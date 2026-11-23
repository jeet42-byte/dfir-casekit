"""Windows event log parsing: Sysmon, Security, System, PowerShell.

Accepted inputs
---------------
* ``.jsonl`` / ``.json`` - one record per line, in either of the two shapes
  analysts usually end up with:
    - flat:        {"TimeCreated", "Channel", "Computer", "EventID", "EventData": {...}}
    - Winlogbeat:  {"@timestamp", "winlog": {"channel", "computer_name", "event_id", "event_data"}}
* ``.xml`` - ``wevtutil qe Security /f:xml`` output (no extra libraries needed)
* ``.evtx`` - native logs, if the optional ``python-evtx`` package is installed

Everything becomes a ``casekit.models.Event`` with the EventData fields flattened
into ``Event.fields``, which is what the Sigma engine matches against.
"""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterator, Optional

from casekit.models import Event

CHANNEL_SOURCE = {
    "microsoft-windows-sysmon/operational": "sysmon",
    "security": "security",
    "system": "system",
    "microsoft-windows-powershell/operational": "powershell",
    "windows powershell": "powershell",
}

NS = re.compile(r"^\{[^}]+\}")


def parse_ts(value: str) -> datetime:
    """Parse the timestamp variants Windows tooling emits into aware UTC."""
    v = value.strip().replace(" ", "T", 1)
    if v.endswith("Z"):
        v = v[:-1] + "+00:00"
    # Trim sub-microsecond precision (EVTX carries 100ns ticks: 7 digits).
    v = re.sub(r"(\.\d{6})\d+", r"\1", v)
    dt = datetime.fromisoformat(v)
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def source_for(channel: str) -> str:
    return CHANNEL_SOURCE.get(channel.strip().lower(), channel.strip().lower() or "unknown")


def _short_host(computer: str) -> str:
    return computer.split(".")[0].upper() if computer else "UNKNOWN"


def record_to_event(rec: Dict, evidence: str, line: Optional[int] = None) -> Optional[Event]:
    """Normalise one JSON record (flat or Winlogbeat shape)."""
    if "winlog" in rec:
        w = rec["winlog"]
        channel, computer = w.get("channel", ""), w.get("computer_name", "")
        eid, record = w.get("event_id"), w.get("record_id", line)
        data = dict(w.get("event_data") or {})
        ts = rec.get("@timestamp")
    else:
        channel, computer = rec.get("Channel", ""), rec.get("Computer", "")
        eid = rec.get("EventID", rec.get("EventId"))
        record = rec.get("EventRecordID", rec.get("EventRecordId", line))
        data = dict(rec.get("EventData") or {})
        ts = rec.get("TimeCreated") or rec.get("SystemTime")
    if ts is None or eid is None:
        return None
    if "message" in rec and "message" not in data:
        data["message"] = rec["message"]
    return Event(ts=parse_ts(str(ts)), source=source_for(channel), host=_short_host(computer),
                 event_id=int(eid), fields=data, evidence=evidence, record=int(record) if record else line)


def iter_jsonl(path: Path) -> Iterator[Event]:
    with open(path, encoding="utf-8-sig") as fh:
        for n, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            ev = record_to_event(json.loads(line), str(path), n)
            if ev:
                yield ev


def xml_record_to_event(elem: ET.Element, evidence: str) -> Optional[Event]:
    """Convert one <Event> element (wevtutil / EVTX rendering) to an Event."""
    def child(parent, name):
        for c in parent:
            if NS.sub("", c.tag) == name:
                return c
        return None

    system = child(elem, "System")
    if system is None:
        return None
    eid_el, time_el = child(system, "EventID"), child(system, "TimeCreated")
    if eid_el is None or time_el is None:
        return None
    chan_el, comp_el, rec_el = child(system, "Channel"), child(system, "Computer"), child(system, "EventRecordID")
    data: Dict[str, str] = {}
    for section in ("EventData", "UserData"):
        sec = child(elem, section)
        if sec is None:
            continue
        for d in sec.iter():
            if d is sec:
                continue
            name = d.get("Name") or NS.sub("", d.tag)
            if d.text and d.text.strip():
                data[name] = d.text.strip()
    return Event(
        ts=parse_ts(time_el.get("SystemTime", "")),
        source=source_for(chan_el.text if chan_el is not None and chan_el.text else ""),
        host=_short_host(comp_el.text if comp_el is not None and comp_el.text else ""),
        event_id=int(eid_el.text),
        fields=data,
        evidence=evidence,
        record=int(rec_el.text) if rec_el is not None and rec_el.text else None,
    )


def iter_xml(path: Path) -> Iterator[Event]:
    text = path.read_text(encoding="utf-8-sig")
    # wevtutil emits bare <Event> siblings without a root element.
    body = re.sub(r"<\?xml[^>]*\?>", "", text)
    root = ET.fromstring("<Events>" + body + "</Events>")
    for elem in root:
        if NS.sub("", elem.tag) == "Event":
            ev = xml_record_to_event(elem, str(path))
            if ev:
                yield ev
        elif NS.sub("", elem.tag) == "Events":   # already wrapped
            for inner in elem:
                ev = xml_record_to_event(inner, str(path))
                if ev:
                    yield ev


def iter_evtx(path: Path) -> Iterator[Event]:
    try:
        from Evtx.Evtx import Evtx  # type: ignore
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise RuntimeError(
            f"{path.name}: native .evtx needs the optional 'python-evtx' package "
            "(pip install python-evtx), or export the log with "
            "'wevtutil qe <log> /f:xml' / EvtxECmd --json first."
        ) from exc
    with Evtx(str(path)) as log:  # pragma: no cover - exercised only with the optional lib
        for rec in log.records():
            ev = xml_record_to_event(ET.fromstring(rec.xml()), str(path))
            if ev:
                yield ev
