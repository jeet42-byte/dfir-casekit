"""Linux auth.log / secure parsing (sshd and sudo).

Handles both classic syslog timestamps (``Nov 18 07:12:01``, which carry no
year - supplied from the case config) and RFC 3339 timestamps written by
modern rsyslog / journald exports.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional

from casekit.models import Event

CLASSIC = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s(?P<host>\S+)\s(?P<proc>[\w\-/.]+)(?:\[(?P<pid>\d+)\])?:\s(?P<msg>.*)$")
RFC3339 = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}T\S+)\s(?P<host>\S+)\s(?P<proc>[\w\-/.]+)(?:\[(?P<pid>\d+)\])?:\s(?P<msg>.*)$")

SSH_PATTERNS = [
    ("ssh_failed", re.compile(r"Failed (?P<method>\S+) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)")),
    ("ssh_accepted", re.compile(r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)")),
    ("ssh_invalid_user", re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>[\d.]+)")),
    ("sudo", re.compile(r"^\s*(?P<user>\S+) : .*COMMAND=(?P<command>.*)$")),
]


def parse_line(line: str, year: int) -> Optional[dict]:
    m = RFC3339.match(line)
    if m:
        ts = datetime.fromisoformat(m["ts"].replace("Z", "+00:00"))
        ts = ts.replace(tzinfo=timezone.utc) if ts.tzinfo is None else ts.astimezone(timezone.utc)
    else:
        m = CLASSIC.match(line)
        if not m:
            return None
        ts = datetime.strptime(f"{year} {m['ts']}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
    out = {"ts": ts, "host": m["host"].upper(), "process": m["proc"], "message": m["msg"], "action": "other"}
    for action, pat in SSH_PATTERNS:
        hit = pat.search(m["msg"])
        if hit and (action != "sudo" or m["proc"] == "sudo"):
            out["action"] = action
            out.update({k: v for k, v in hit.groupdict().items() if v is not None})
            break
    return out


def iter_authlog(path: Path, year: Optional[int] = None) -> Iterator[Event]:
    year = year or datetime.now(timezone.utc).year
    with open(path, encoding="utf-8", errors="replace") as fh:
        for n, line in enumerate(fh, 1):
            rec = parse_line(line.rstrip("\n"), year)
            if rec is None:
                continue
            ts, host = rec.pop("ts"), rec.pop("host")
            yield Event(ts, "authlog", host, None, rec, str(path), n)
