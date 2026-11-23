"""Evidence loading: pick a parser by file type and return normalised events."""
from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional, Tuple

from casekit.models import Event
from casekit.parsers import authlog, pcap, winevt


def load_file(path: Path, hostmap: Optional[Dict[str, str]] = None, year: Optional[int] = None) -> List[Event]:
    name = path.name.lower()
    if name.endswith((".pcap", ".cap")):
        return list(pcap.iter_pcap(path, hostmap))
    if name.endswith((".jsonl", ".json", ".ndjson")):
        return list(winevt.iter_jsonl(path))
    if name.endswith(".xml"):
        return list(winevt.iter_xml(path))
    if name.endswith(".evtx"):
        return list(winevt.iter_evtx(path))
    if name.startswith(("auth.log", "secure")) or name.endswith(".log"):
        return list(authlog.iter_authlog(path, year))
    return []


def load_case(evidence_dir: Path, hostmap: Optional[Dict[str, str]] = None,
              year: Optional[int] = None) -> Tuple[List[Event], List[str]]:
    """Load every supported file. Returns (events sorted by time, warnings)."""
    events: List[Event] = []
    warnings: List[str] = []
    for path in sorted(p for p in evidence_dir.rglob("*") if p.is_file()):
        try:
            loaded = load_file(path, hostmap, year)
        except Exception as exc:  # one bad file must not sink the whole case
            warnings.append(f"{path.name}: {exc}")
            continue
        if not loaded:
            warnings.append(f"{path.name}: no supported records (skipped)")
        events.extend(loaded)
    events.sort(key=lambda e: e.ts)
    return events, warnings
