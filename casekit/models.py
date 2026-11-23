"""Core data structures shared by every parser, detector and reporter.

Every artefact - a Sysmon record, a DNS packet, an auth.log line - is
normalised into one ``Event``. Detections produce ``Finding`` objects that
point back at the events that justify them, so every claim in the final
report can be traced to a specific line of evidence.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}


@dataclass
class Event:
    ts: datetime                      # always timezone-aware UTC
    source: str                       # sysmon | security | system | powershell | pcap | authlog
    host: str
    event_id: Optional[int]
    fields: Dict[str, Any]
    evidence: str                     # file the event came from
    record: Optional[int] = None      # record / packet / line number inside that file

    @property
    def ref(self) -> str:
        """Short pointer back into the evidence, e.g. ``Sysmon.jsonl#42``."""
        name = self.evidence.rsplit("/", 1)[-1]
        return f"{name}#{self.record}" if self.record is not None else name

    def get(self, key: str, default: Any = "") -> Any:
        return self.fields.get(key, default)

    def summary(self) -> str:
        f = self.fields
        if self.source == "sysmon" and self.event_id == 1:
            return f"Process: {f.get('Image')} | {f.get('CommandLine')}"
        if self.source == "sysmon" and self.event_id == 10:
            return f"ProcessAccess: {f.get('SourceImage')} -> {f.get('TargetImage')} ({f.get('GrantedAccess')})"
        if self.source == "sysmon" and self.event_id in (12, 13):
            return f"Registry: {f.get('TargetObject')} = {f.get('Details', '')}"
        if self.source == "sysmon" and self.event_id == 11:
            return f"FileCreate: {f.get('TargetFilename')} by {f.get('Image')}"
        if self.source == "sysmon" and self.event_id == 3:
            return f"NetConn: {f.get('Image')} -> {f.get('DestinationIp')}:{f.get('DestinationPort')}"
        if self.source == "security" and self.event_id in (4624, 4625):
            verb = "Logon" if self.event_id == 4624 else "Failed logon"
            return (f"{verb}: {f.get('TargetDomainName', '')}\\{f.get('TargetUserName')} "
                    f"type {f.get('LogonType')} from {f.get('IpAddress')} ({f.get('AuthenticationPackageName', '')})")
        if self.source == "pcap":
            return f.get("summary", "")
        if self.source == "authlog":
            return f.get("message", "")
        msg = f.get("message") or ", ".join(f"{k}={v}" for k, v in list(f.items())[:4])
        return f"EID {self.event_id}: {msg}"


@dataclass
class Finding:
    title: str
    severity: str
    techniques: List[str]
    description: str
    events: List[Event] = field(default_factory=list)
    rule_id: str = ""
    detector: str = "sigma"           # sigma | analytic

    @property
    def first_seen(self) -> datetime:
        return min((e.ts for e in self.events), default=datetime.max.replace(tzinfo=timezone.utc))

    @property
    def hosts(self) -> List[str]:
        return sorted({e.host for e in self.events})

    def sort_key(self):
        return (-SEVERITY_ORDER.get(self.severity, 0), self.first_seen)
