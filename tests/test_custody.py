import hashlib
import json
import os

from casekit import custody


def _case(tmp_path):
    (tmp_path / "evidence").mkdir()
    (tmp_path / "evidence" / "a.log").write_text("alpha\n")
    (tmp_path / "evidence" / "b.log").write_text("bravo\n")
    return tmp_path


def test_intake_hashes_and_locks(tmp_path):
    case = _case(tmp_path)
    entries = custody.intake(case, examiner="tester")
    assert [e["item"] for e in entries] == ["evidence/a.log", "evidence/b.log"]
    assert entries[0]["sha256"] == hashlib.sha256(b"alpha\n").hexdigest()
    assert entries[0]["md5"] == hashlib.md5(b"alpha\n").hexdigest()
    mode = (case / "evidence" / "a.log").stat().st_mode
    assert not mode & 0o222                       # write bits cleared
    assert custody.intake(case) == []           # idempotent: nothing new to log
    assert custody.verify(case).ok


def test_modified_evidence_is_detected(tmp_path):
    case = _case(tmp_path)
    custody.intake(case, lock=False)
    (case / "evidence" / "b.log").write_text("tampered\n")
    res = custody.verify(case)
    assert res.chain_ok and not res.ok
    assert {f["item"]: f["status"] for f in res.files}["evidence/b.log"] == "MODIFIED"


def test_edited_custody_log_breaks_chain(tmp_path):
    case = _case(tmp_path)
    custody.intake(case, lock=False)
    custody.append(case, "note", "-", {}, "second entry")
    lines = (case / custody.CUSTODY_FILE).read_text().splitlines()
    first = json.loads(lines[0])
    first["examiner"] = "someone-else"           # silent edit of history
    lines[0] = json.dumps(first, sort_keys=True)
    (case / custody.CUSTODY_FILE).write_text("\n".join(lines) + "\n")
    res = custody.verify(case)
    assert not res.chain_ok and res.broken_at == 1


def test_deleted_custody_entry_breaks_chain(tmp_path):
    case = _case(tmp_path)
    custody.intake(case, lock=False)
    lines = (case / custody.CUSTODY_FILE).read_text().splitlines()
    (case / custody.CUSTODY_FILE).write_text(lines[1] + "\n")   # drop entry 1
    assert custody.verify(case).broken_at == 2
