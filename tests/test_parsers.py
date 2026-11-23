import base64
import struct
from datetime import datetime, timezone

import pytest

from casekit.enrich import decode_powershell
from casekit.parsers import authlog, pcap, winevt


def test_timestamp_variants():
    assert winevt.parse_ts("2026-11-18T09:31:10.1234567Z") == datetime(2026, 11, 18, 9, 31, 10, 123456, tzinfo=timezone.utc)
    assert winevt.parse_ts("2026-11-18 09:31:10").tzinfo is not None
    assert winevt.parse_ts("2026-11-18T15:31:10+06:00").hour == 9


def test_xml_and_winlogbeat_records(tmp_path):
    xml = tmp_path / "sec.xml"
    xml.write_text('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
                   '<EventID>4624</EventID><TimeCreated SystemTime="2026-11-18T09:31:10.0000000Z"/>'
                   '<EventRecordID>7</EventRecordID><Channel>Security</Channel><Computer>DC01.corp.local</Computer>'
                   '</System><EventData><Data Name="TargetUserName">bob</Data><Data Name="LogonType">3</Data>'
                   '</EventData></Event>\n')
    (e,) = list(winevt.iter_xml(xml))
    assert (e.source, e.host, e.event_id, e.record, e.get("TargetUserName")) == ("security", "DC01", 4624, 7, "bob")

    rec = {"@timestamp": "2026-11-18T09:31:11.000Z", "winlog": {"channel": "System", "computer_name": "dc01",
           "event_id": 7045, "record_id": 9, "event_data": {"ServiceName": "PSEXESVC"}}}
    e2 = winevt.record_to_event(rec, "x.jsonl")
    assert (e2.source, e2.host, e2.event_id, e2.get("ServiceName")) == ("system", "DC01", 7045, "PSEXESVC")


def test_authlog_classic_and_rfc3339():
    a = authlog.parse_line("Nov 18 07:40:04 web01 sshd[3101]: Failed password for invalid user oracle from 198.51.100.23 port 30295 ssh2", 2026)
    assert (a["action"], a["user"], a["ip"], a["ts"].year) == ("ssh_failed", "oracle", "198.51.100.23", 2026)
    b = authlog.parse_line("2026-11-18T07:03:11.000000+00:00 web01 sshd[2210]: Accepted publickey for deploy from 10.0.0.1 port 5 ssh2", 2026)
    assert (b["action"], b["user"]) == ("ssh_accepted", "deploy")
    c = authlog.parse_line("Nov 18 07:03:40 web01 sudo:   deploy : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/bash", 2026)
    assert (c["action"], c["command"]) == ("sudo", "/bin/bash")


def test_dns_name_compression_and_answers(make_case):
    msg = make_case.dns_answer(0x1234, "api.example.net", "203.0.113.5")
    d = pcap.parse_dns(msg)
    assert d["response"] and d["questions"] == [("api.example.net", "A")] and d["answers"] == ["203.0.113.5"]


def test_dns_pointer_loop_is_rejected():
    loop = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\xc0\x0c"
    assert pcap.parse_dns(loop) is None


def test_tls_sni_and_http(make_case):
    assert pcap.parse_tls_sni(make_case.client_hello("files.example.org")) == "files.example.org"
    assert pcap.parse_tls_sni(b"\x17\x03\x03\x00\x05hello") is None
    h = pcap.parse_http_request(b"GET /a.ps1 HTTP/1.1\r\nHost: x.example\r\nUser-Agent: curl/8\r\n\r\n")
    assert h == {"method": "GET", "uri": "/a.ps1", "host": "x.example", "user_agent": "curl/8"}


def test_pcap_roundtrip(tmp_path, make_case):
    p = make_case.Pcap()
    ts = datetime(2026, 11, 18, 8, 0, tzinfo=timezone.utc)
    p.udp(ts, "10.0.0.2", 5555, "10.0.0.1", 53, make_case.dns_query(1, "evil.example"))
    p.handshake(ts, "10.0.0.2", 4444, "203.0.113.7", 443)
    p.tcp(ts, "10.0.0.2", 4444, "203.0.113.7", 443, make_case.client_hello("evil.example"))
    f = tmp_path / "t.pcap"
    p.write(f)
    events = list(pcap.iter_pcap(f, {"10.0.0.2": "WS1"}))
    kinds = {e.get("type") for e in events}
    assert {"dns", "tls", "flow"} <= kinds
    assert all(e.host in ("WS1", "203.0.113.7") for e in events)
    assert next(e for e in events if e.get("type") == "dns").get("query") == "evil.example"


def test_pcapng_is_refused(tmp_path):
    f = tmp_path / "x.pcap"
    f.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\0" * 40)
    with pytest.raises(pcap.PcapError):
        list(pcap.read_packets(f))


def test_decode_encoded_powershell():
    blob = base64.b64encode("Write-Host hi".encode("utf-16-le")).decode()
    assert decode_powershell(f"powershell.exe -NoP -EncodedCommand {blob}") == "Write-Host hi"
    assert decode_powershell(f"powershell -e {blob}") == "Write-Host hi"
    assert decode_powershell("powershell -File x.ps1") is None
