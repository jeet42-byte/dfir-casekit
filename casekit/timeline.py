"""Super-timeline output: every event, in UTC order, tagged with its findings."""
from __future__ import annotations

import csv
from collections import defaultdict
from pathlib import Path
from typing import Dict, List

from casekit.models import SEVERITY_ORDER, Event, Finding


def tag_events(findings: List[Finding]) -> Dict[int, List[Finding]]:
    tags: Dict[int, List[Finding]] = defaultdict(list)
    for f in findings:
        for e in f.events:
            tags[id(e)].append(f)
    return tags


def write_csv(events: List[Event], findings: List[Finding], path: Path) -> int:
    tags = tag_events(findings)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["timestamp_utc", "host", "source", "event_id", "evidence", "summary",
                    "severity", "findings", "techniques"])
        for e in events:
            fs = tags.get(id(e), [])
            sev = max((f.severity for f in fs), key=lambda s: SEVERITY_ORDER.get(s, 0), default="")
            w.writerow([e.ts.isoformat(timespec="milliseconds"), e.host, e.source,
                        e.event_id if e.event_id is not None else "", e.ref, e.summary(), sev,
                        " | ".join(f.title for f in fs),
                        " ".join(sorted({t for f in fs for t in f.techniques}))])
    return len(events)


def key_events(events: List[Event], findings: List[Finding]) -> List[tuple]:
    """(event, findings) for every event that at least one finding cites, in time order."""
    tags = tag_events(findings)
    return [(e, tags[id(e)]) for e in events if id(e) in tags]
