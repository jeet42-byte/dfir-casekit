"""Evidence intake and a tamper-evident chain of custody.

Each evidence file is hashed (MD5, SHA-1, SHA-256) on intake. Every custody
action is appended to ``custody.jsonl`` as one JSON line that also carries the
SHA-256 of the previous line, so the log is a hash chain: editing, deleting or
reordering any past entry breaks every link after it, and ``verify`` says
exactly where.

This does not make the log impossible to forge - someone with write access
can rebuild the whole chain - but it turns silent edits into detectable ones,
which is the property a custody record needs. Anchor the head hash somewhere
outside the examiner's control (a ticket, an email) to close the gap.
"""
from __future__ import annotations

import getpass
import hashlib
import json
import os
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List

CUSTODY_FILE = "custody.jsonl"
GENESIS = "0" * 64
CHUNK = 1024 * 1024


def hash_file(path: Path) -> Dict[str, str]:
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(CHUNK), b""):
            md5.update(block)
            sha1.update(block)
            sha256.update(block)
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}


def _entry_hash(entry: dict) -> str:
    body = {k: v for k, v in entry.items() if k != "entry_hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()


def read_log(case_dir: Path) -> List[dict]:
    path = case_dir / CUSTODY_FILE
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def append(case_dir: Path, action: str, item: str, hashes: Dict[str, str], note: str = "",
           examiner: str | None = None) -> dict:
    log = read_log(case_dir)
    entry = {
        "seq": len(log) + 1,
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "examiner": examiner or os.environ.get("CASEKIT_EXAMINER") or getpass.getuser(),
        "action": action,
        "item": item,
        "size": hashes.get("size"),
        "md5": hashes.get("md5"),
        "sha1": hashes.get("sha1"),
        "sha256": hashes.get("sha256"),
        "note": note,
        "prev_hash": log[-1]["entry_hash"] if log else GENESIS,
    }
    entry["entry_hash"] = _entry_hash(entry)
    with open(case_dir / CUSTODY_FILE, "a") as fh:
        fh.write(json.dumps(entry, sort_keys=True) + "\n")
    return entry


def evidence_files(case_dir: Path) -> Iterable[Path]:
    root = case_dir / "evidence"
    return sorted(p for p in root.rglob("*") if p.is_file()) if root.exists() else []


def intake(case_dir: Path, note: str = "", lock: bool = True, examiner: str | None = None) -> List[dict]:
    """Hash every evidence file not yet logged, record it, and make it read-only."""
    logged = {e["item"] for e in read_log(case_dir) if e["action"] == "intake"}
    entries = []
    for path in evidence_files(case_dir):
        rel = path.relative_to(case_dir).as_posix()
        if rel in logged:
            continue
        hashes = hash_file(path)
        hashes["size"] = path.stat().st_size
        entries.append(append(case_dir, "intake", rel, hashes, note, examiner))
        if lock:
            path.chmod(path.stat().st_mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))
    return entries


@dataclass
class VerifyResult:
    chain_ok: bool
    broken_at: int | None
    files: List[dict]                 # {item, expected, actual, status}

    @property
    def ok(self) -> bool:
        return self.chain_ok and all(f["status"] == "match" for f in self.files)


def verify(case_dir: Path) -> VerifyResult:
    log = read_log(case_dir)
    prev, broken_at = GENESIS, None
    for entry in log:
        if entry.get("prev_hash") != prev or _entry_hash(entry) != entry.get("entry_hash"):
            broken_at = entry.get("seq")
            break
        prev = entry["entry_hash"]

    files = []
    for entry in (e for e in log if e["action"] == "intake"):
        path = case_dir / entry["item"]
        if not path.exists():
            files.append({"item": entry["item"], "expected": entry["sha256"], "actual": None, "status": "missing"})
            continue
        actual = hash_file(path)["sha256"]
        files.append({"item": entry["item"], "expected": entry["sha256"], "actual": actual,
                      "status": "match" if actual == entry["sha256"] else "MODIFIED"})
    return VerifyResult(chain_ok=broken_at is None, broken_at=broken_at, files=files)
