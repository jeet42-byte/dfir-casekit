"""Run the full pipeline on the synthetic case and pin the expected verdicts."""
import csv
import json

import pytest

from casekit.cli import DEFAULT_RULES, analyze, main

EXPECTED = {
    "ck-win-001", "ck-win-002", "ck-win-003", "ck-win-004", "ck-win-005", "ck-win-006", "ck-win-007",
    "ck-win-008", "ck-win-009", "ck-win-010", "ck-win-011", "ck-win-012", "ck-win-013", "ck-win-014",
    "ck-win-015", "ck-win-016", "ck-win-019", "ck-win-020", "ck-win-021", "ck-net-001",
    "analytic.dns_beacon", "analytic.dns_tunnel", "analytic.large_outbound", "analytic.bruteforce.ssh",
}


@pytest.fixture(scope="module")
def result(tmp_path_factory, make_case):
    case = tmp_path_factory.mktemp("case") / "CASE"
    make_case.main(case)
    assert main(["intake", str(case), "--examiner", "pytest", "--no-lock"]) == 0
    res = analyze(case, DEFAULT_RULES, case / "output", quiet=True)
    return case, res


def test_every_stage_detected_and_nothing_else(result):
    _, res = result
    assert {f.rule_id for f in res["findings"]} == EXPECTED


def test_noise_is_not_flagged(result):
    _, res = result
    titles = " ".join(f.title for f in res["findings"])
    assert "time.windows.com" not in titles                 # periodic but allow-listed
    assert "Windows brute force" not in titles              # three typos on the DC are not an attack
    ssh = next(f for f in res["findings"] if f.rule_id == "analytic.bruteforce.ssh")
    assert ssh.severity == "medium"                          # failed only


def test_evidence_integrity_and_custody(result):
    case, res = result
    assert res["verify"].ok
    assert main(["verify", str(case)]) == 0


def test_iocs(result):
    case, res = result
    values = {(i.type, i.value) for i in res["iocs"]}
    assert ("domain", "api.cdn-sync.example") in values
    assert ("ipv4", "203.0.113.50") in values
    assert ("account", "svc_backup") in values
    assert ("url", "http://update.cdn-sync.example/assets/stage2.ps1") in values   # recovered from -enc payload
    assert not any(v.startswith("10.") for _, v in values)                         # no internal IPs
    hashed = {i.context.split(" (")[0].lower() for i in res["iocs"] if i.type == "sha256"}
    assert hashed == {r"c:\users\public\libraries\svchost.exe", r"c:\users\public\libraries\7za.exe"}
    rows = list(csv.DictReader(open(case / "output" / "iocs.csv")))
    assert all("[.]" in r["defanged"] for r in rows if r["type"] in ("ipv4", "domain", "url"))


def test_outputs_written(result):
    case, res = result
    out = case / "output"
    md = (out / "report.md").read_text()
    for section in ("Executive summary", "MITRE ATT&CK mapping", "Process lineage", "Indicators of compromise"):
        assert section in md
    assert "<table>" in (out / "report.html").read_text()
    assert len(json.loads((out / "findings.json").read_text())) == len(EXPECTED)
    with open(out / "timeline.csv") as fh:
        assert sum(1 for _ in fh) == len(res["events"]) + 1
