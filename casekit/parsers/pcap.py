"""A dependency-free PCAP reader for network forensics triage.

Decodes classic libpcap captures (micro- and nanosecond, either byte order)
with Ethernet, Linux SLL or raw-IP link layers, then IPv4 -> TCP/UDP, and
from there:

* DNS queries and A/AAAA answers (with RFC 1035 name compression)
* HTTP request lines, Host and User-Agent headers
* TLS ClientHello Server Name Indication (SNI) - who the client *said* it was
  talking to, readable even though the session itself is encrypted
* per-flow packet and byte counters, used for exfiltration analytics

It is deliberately a triage parser, not a replacement for Wireshark or Zeek:
no TCP stream reassembly, so an HTTP request or ClientHello split across
segments is missed. pcapng and IPv6 are reported and skipped, not guessed at.
"""
from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

from casekit.models import Event

PCAP_MAGIC = {
    b"\xa1\xb2\xc3\xd4": (">", 1e-6), b"\xd4\xc3\xb2\xa1": ("<", 1e-6),
    b"\xa1\xb2\x3c\x4d": (">", 1e-9), b"\x4d\x3c\xb2\xa1": ("<", 1e-9),
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
LINKTYPE_ETHERNET, LINKTYPE_RAW, LINKTYPE_SLL = 1, 101, 113
HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"PATCH ")
QTYPES = {1: "A", 2: "NS", 5: "CNAME", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS"}


class PcapError(ValueError):
    pass


@dataclass
class Packet:
    ts: datetime
    number: int
    src: str
    dst: str
    proto: str                # TCP | UDP
    sport: int
    dport: int
    payload: bytes
    length: int               # IP total length (what crossed the wire at L3)
    tcp_flags: int = 0


@dataclass
class Flow:
    src: str
    dst: str
    sport: int
    dport: int
    proto: str
    first: datetime
    last: datetime
    packets: int = 0
    bytes: int = 0
    first_packet: int = 0


# ---------------------------------------------------------------- packet layer

def read_packets(path: Path) -> Iterator[Packet]:
    data = path.read_bytes()
    if data[:4] == PCAPNG_MAGIC:
        raise PcapError(f"{path.name} is pcapng; convert with: editcap -F libpcap in.pcapng out.pcap")
    if data[:4] not in PCAP_MAGIC:
        raise PcapError(f"{path.name}: not a libpcap file")
    endian, resolution = PCAP_MAGIC[data[:4]]
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    off, number = 24, 0
    while off + 16 <= len(data):
        sec, frac, incl, _orig = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        frame = data[off:off + incl]
        off += incl
        number += 1
        ts = datetime.fromtimestamp(sec + frac * resolution, tz=timezone.utc)
        pkt = _decode_frame(frame, linktype, ts, number)
        if pkt:
            yield pkt


def _decode_frame(frame: bytes, linktype: int, ts: datetime, number: int) -> Optional[Packet]:
    if linktype == LINKTYPE_ETHERNET:
        if len(frame) < 14:
            return None
        ethertype, off = struct.unpack("!H", frame[12:14])[0], 14
        while ethertype == 0x8100 and len(frame) >= off + 4:        # 802.1Q VLAN tags
            ethertype, off = struct.unpack("!H", frame[off + 2:off + 4])[0], off + 4
        if ethertype != 0x0800:
            return None
        ip = frame[off:]
    elif linktype == LINKTYPE_SLL:
        if len(frame) < 16 or struct.unpack("!H", frame[14:16])[0] != 0x0800:
            return None
        ip = frame[16:]
    elif linktype == LINKTYPE_RAW:
        ip = frame
    else:
        return None
    return _decode_ipv4(ip, ts, number)


def _decode_ipv4(ip: bytes, ts: datetime, number: int) -> Optional[Packet]:
    if len(ip) < 20 or ip[0] >> 4 != 4:
        return None
    ihl = (ip[0] & 0x0F) * 4
    total_len = struct.unpack("!H", ip[2:4])[0]
    proto = ip[9]
    src, dst = str(ipaddress.IPv4Address(ip[12:16])), str(ipaddress.IPv4Address(ip[16:20]))
    seg = ip[ihl:total_len] if total_len >= ihl else ip[ihl:]
    if proto == 6 and len(seg) >= 20:
        sport, dport = struct.unpack("!HH", seg[:4])
        data_off = (seg[12] >> 4) * 4
        return Packet(ts, number, src, dst, "TCP", sport, dport, seg[data_off:], total_len, seg[13])
    if proto == 17 and len(seg) >= 8:
        sport, dport = struct.unpack("!HH", seg[:4])
        return Packet(ts, number, src, dst, "UDP", sport, dport, seg[8:], total_len)
    return None


# ----------------------------------------------------------------- app layer

def _read_name(msg: bytes, off: int, depth: int = 0) -> Tuple[str, int]:
    """Read a (possibly compressed) DNS name; return (name, offset after it)."""
    labels, jumped, end = [], False, off
    while True:
        if off >= len(msg) or depth > 20:
            raise ValueError("bad DNS name")
        n = msg[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0 == 0xC0:                       # compression pointer
            ptr = struct.unpack("!H", msg[off:off + 2])[0] & 0x3FFF
            if not jumped:
                end = off + 2
            jumped, off, depth = True, ptr, depth + 1
            continue
        labels.append(msg[off + 1:off + 1 + n].decode("ascii", "replace"))
        off += 1 + n
    return ".".join(labels), (end if jumped else off)


def parse_dns(msg: bytes) -> Optional[dict]:
    if len(msg) < 12:
        return None
    tid, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", msg[:12])
    off, questions, answers = 12, [], []
    try:
        for _ in range(qd):
            name, off = _read_name(msg, off)
            qtype = struct.unpack("!H", msg[off:off + 2])[0]
            off += 4
            questions.append((name, QTYPES.get(qtype, str(qtype))))
        for _ in range(an):
            _name, off = _read_name(msg, off)
            rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", msg[off:off + 10])
            off += 10
            rdata = msg[off:off + rdlen]
            off += rdlen
            if rtype == 1 and rdlen == 4:
                answers.append(str(ipaddress.IPv4Address(rdata)))
            elif rtype == 28 and rdlen == 16:
                answers.append(str(ipaddress.IPv6Address(rdata)))
    except (ValueError, struct.error, IndexError):
        if not questions:
            return None
    return {"id": tid, "response": bool(flags & 0x8000), "rcode": flags & 0x000F,
            "questions": questions, "answers": answers}


def parse_http_request(payload: bytes) -> Optional[dict]:
    if not payload.startswith(HTTP_METHODS):
        return None
    head = payload.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace")
    lines = head.split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) < 2:
        return None
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return {"method": parts[0], "uri": parts[1], "host": headers.get("host", ""),
            "user_agent": headers.get("user-agent", "")}


def parse_tls_sni(payload: bytes) -> Optional[str]:
    """Extract SNI from a TLS ClientHello carried in a single segment."""
    try:
        if len(payload) < 43 or payload[0] != 0x16 or payload[5] != 0x01:
            return None
        off = 5 + 4 + 2 + 32                         # record hdr, hs hdr, version, random
        off += 1 + payload[off]                      # session id
        off += 2 + struct.unpack("!H", payload[off:off + 2])[0]   # cipher suites
        off += 1 + payload[off]                      # compression methods
        ext_end = off + 2 + struct.unpack("!H", payload[off:off + 2])[0]
        off += 2
        while off + 4 <= ext_end:
            etype, elen = struct.unpack("!HH", payload[off:off + 4])
            off += 4
            if etype == 0:                           # server_name
                name_len = struct.unpack("!H", payload[off + 3:off + 5])[0]
                return payload[off + 5:off + 5 + name_len].decode("ascii", "replace")
            off += elen
    except (struct.error, IndexError):
        return None
    return None


# ------------------------------------------------------------------- events

def iter_pcap(path: Path, hostmap: Optional[Dict[str, str]] = None) -> Iterator[Event]:
    hostmap = hostmap or {}
    flows: Dict[tuple, Flow] = {}
    ev_path = str(path)

    def host(ip: str) -> str:
        return hostmap.get(ip, ip)

    for p in read_packets(path):
        key = (p.src, p.sport, p.dst, p.dport, p.proto)
        fl = flows.get(key)
        if fl is None:
            fl = flows[key] = Flow(p.src, p.dst, p.sport, p.dport, p.proto, p.ts, p.ts, first_packet=p.number)
        fl.packets += 1
        fl.bytes += p.length
        fl.last = p.ts

        base = {"src_ip": p.src, "dst_ip": p.dst, "src_port": p.sport, "dst_port": p.dport, "proto": p.proto}
        if p.proto == "UDP" and p.dport == 53:
            dns = parse_dns(p.payload)
            if dns and not dns["response"]:
                for qname, qtype in dns["questions"]:
                    yield Event(p.ts, "pcap", host(p.src), None,
                                {**base, "type": "dns", "query": qname.lower(), "qtype": qtype,
                                 "summary": f"DNS {qtype} {qname} ({p.src} -> {p.dst})"},
                                ev_path, p.number)
        elif p.proto == "UDP" and p.sport == 53:
            dns = parse_dns(p.payload)
            if dns and dns["response"] and dns["questions"] and dns["answers"]:
                qname = dns["questions"][0][0].lower()
                yield Event(p.ts, "pcap", host(p.dst), None,
                            {**base, "type": "dns_answer", "query": qname, "answers": dns["answers"],
                             "summary": f"DNS answer {qname} -> {', '.join(dns['answers'])}"},
                            ev_path, p.number)
        elif p.proto == "TCP" and p.payload:
            http = parse_http_request(p.payload)
            if http:
                url = f"http://{http['host'] or p.dst}{http['uri']}"
                yield Event(p.ts, "pcap", host(p.src), None,
                            {**base, "type": "http", **http, "url": url,
                             "summary": f"HTTP {http['method']} {url} UA='{http['user_agent']}'"},
                            ev_path, p.number)
                continue
            sni = parse_tls_sni(p.payload)
            if sni:
                yield Event(p.ts, "pcap", host(p.src), None,
                            {**base, "type": "tls", "sni": sni.lower(),
                             "summary": f"TLS ClientHello SNI={sni} ({p.src} -> {p.dst}:{p.dport})"},
                            ev_path, p.number)

    for fl in flows.values():
        yield Event(fl.first, "pcap", host(fl.src), None,
                    {"type": "flow", "src_ip": fl.src, "dst_ip": fl.dst, "src_port": fl.sport,
                     "dst_port": fl.dport, "proto": fl.proto, "packets": fl.packets, "bytes": fl.bytes,
                     "duration_s": round((fl.last - fl.first).total_seconds(), 3),
                     "summary": f"Flow {fl.proto} {fl.src}:{fl.sport} -> {fl.dst}:{fl.dport} "
                                f"{fl.packets} pkts / {fl.bytes:,} bytes"},
                    ev_path, fl.first_packet)
