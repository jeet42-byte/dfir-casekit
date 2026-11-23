"""Indicator of Compromise extraction, scoped to the evidence behind findings.

IOCs are pulled only from events that a detection fired on - not from the
whole dataset - so the list stays short enough to act on (block, hunt,
share) and every indicator can be traced to the finding that produced it.
"""
from __future__ import annotations

import csv
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Tuple

from casekit.analytics import is_public, registrable
from casekit.models import Finding

URL_RX = re.compile(r"https?://[^\s'\"<>()]+", re.IGNORECASE)
IP_RX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HASH_RX = re.compile(r"(MD5|SHA1|SHA256|IMPHASH)=([A-Fa-f0-9]{32,64})")
SUSPICIOUS_DIRS = ("\\users\\public\\", "\\appdata\\", "\\temp\\", "\\programdata\\", "\\perflogs\\")
TRUSTED_DIRS = ("c:\\windows\\", "c:\\program files\\", "c:\\program files (x86)\\")


@dataclass
class IOC:
    type: str
    value: str
    context: str
    first_seen: str

    @property
    def defanged(self) -> str:
        """Defang so the indicator can't be clicked or auto-resolved when shared."""
        if self.type in ("domain", "ipv4"):
            return self.value.replace(".", "[.]")
        if self.type == "url":
            m = re.match(r"(https?)://([^/]+)(.*)", self.value, re.I)
            if m:
                return m.group(1).lower().replace("t", "x", 2) + "://" + m.group(2).replace(".", "[.]") + m.group(3)
        return self.value


def extract(findings: List[Finding]) -> List[IOC]:
    seen: Dict[Tuple[str, str], IOC] = {}

    def add(kind: str, value: str, context: str, ts) -> None:
        value = value.strip().rstrip(".,;'\"")
        if not value:
            return
        key = (kind, value.lower())
        if key not in seen:
            seen[key] = IOC(kind, value, context, ts.isoformat(timespec="seconds"))

    for f in findings:
        for e in f.events:
            fl = e.fields
            text = " ".join(str(fl.get(k, "")) for k in ("CommandLine", "DecodedCommand", "ImagePath", "url"))
            for u in URL_RX.findall(text):
                add("url", u, f.title, e.ts)
                host = re.sub(r"^https?://", "", u, flags=re.I).split("/")[0].split(":")[0]
                if not IP_RX.fullmatch(host):
                    add("domain", host.lower(), f.title, e.ts)
            for key in ("DestinationIp", "IpAddress", "dst_ip", "src_ip", "ip"):
                ip = str(fl.get(key, ""))
                if IP_RX.fullmatch(ip) and is_public(ip):
                    add("ipv4", ip, f.title, e.ts)
            for ip in IP_RX.findall(text):
                if is_public(ip):
                    add("ipv4", ip, f.title, e.ts)
            if fl.get("type") == "dns":
                q = fl.get("query", "")
                add("domain", registrable(q) if f.rule_id == "analytic.dns_tunnel" else q, f.title, e.ts)
            for key in ("sni", "host"):
                if fl.get(key) and not IP_RX.fullmatch(str(fl[key])):
                    add("domain", str(fl[key]).lower(), f.title, e.ts)
            # Hash IOCs only for binaries outside trusted system paths: the hash of
            # the real cmd.exe or powershell.exe is not an indicator, and blocking
            # it would break every host in the estate (LOLBin abuse is caught by
            # behaviour, not by hash).
            image = str(fl.get("Image", "")).lower()
            trusted = image.startswith(TRUSTED_DIRS) and not any(d in image for d in SUSPICIOUS_DIRS)
            for algo, digest in ([] if trusted else HASH_RX.findall(str(fl.get("Hashes", "")))):
                if algo in ("SHA256", "MD5"):
                    add(algo.lower(), digest.lower(), f"{fl.get('Image', '')} ({f.title})", e.ts)
            for key in ("Image", "TargetFilename"):
                path = str(fl.get(key, ""))
                if path and any(d in path.lower() for d in SUSPICIOUS_DIRS):
                    add("file", path, f.title, e.ts)
            if e.source == "security" and e.event_id == 4720:
                add("account", str(fl.get("TargetUserName")), f.title, e.ts)
    order = ["ipv4", "domain", "url", "sha256", "md5", "file", "account"]
    return sorted(seen.values(), key=lambda i: (order.index(i.type) if i.type in order else 99, i.first_seen))


def write(iocs: List[IOC], out_dir: Path) -> None:
    with open(out_dir / "iocs.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["type", "value", "defanged", "first_seen_utc", "context"])
        for i in iocs:
            w.writerow([i.type, i.value, i.defanged, i.first_seen, i.context])
    (out_dir / "iocs.json").write_text(json.dumps([asdict(i) for i in iocs], indent=2))
