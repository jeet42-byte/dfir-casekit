"""Command-line interface.

    casekit new      CASE_DIR            scaffold a case (evidence/, case.yml)
    casekit intake   CASE_DIR            hash + log + write-protect new evidence
    casekit verify   CASE_DIR            re-hash evidence, validate custody chain
    casekit analyze  CASE_DIR            parse, detect, and write the report
    casekit triage   CASE_DIR            intake + analyze in one step
    casekit rules                        list the loaded Sigma rules
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Dict

import yaml

from casekit import __version__, custody, ioc, lineage, report, sigma, timeline
from casekit.analytics import Thresholds, run_analytics
from casekit.enrich import enrich
from casekit.parsers import load_case

DEFAULT_RULES = Path(__file__).parent / "rules"

CASE_TEMPLATE = """\
case_id: CASE-0001
title: Describe the incident
organisation: Client name
examiner: Your name
classification: CONFIDENTIAL
year: 2026            # year for syslog timestamps that omit it
hosts: {}             # optional IP -> hostname map, e.g. {10.0.0.5: WS-01}
summary: |
  Analyst-written executive summary goes here.
recommendations: []
conclusion: ""
"""


def load_case_config(case_dir: Path) -> Dict:
    path = case_dir / "case.yml"
    cfg = yaml.safe_load(path.read_text()) if path.exists() else {}
    cfg = cfg or {}
    cfg["hosts"] = {str(k): str(v) for k, v in (cfg.get("hosts") or {}).items()}
    return cfg


def cmd_new(args) -> int:
    d = Path(args.case_dir)
    (d / "evidence").mkdir(parents=True, exist_ok=True)
    if not (d / "case.yml").exists():
        (d / "case.yml").write_text(CASE_TEMPLATE)
    print(f"Case scaffolded at {d}. Copy evidence into {d / 'evidence'} then run: casekit triage {d}")
    return 0


def cmd_intake(args) -> int:
    d = Path(args.case_dir)
    entries = custody.intake(d, note=args.note, lock=not args.no_lock, examiner=args.examiner)
    for e in entries:
        print(f"[+] {e['item']}  sha256={e['sha256']}")
    print(f"{len(entries)} new item(s) logged to {d / custody.CUSTODY_FILE}")
    return 0


def cmd_verify(args) -> int:
    res = custody.verify(Path(args.case_dir))
    print(f"custody chain: {'OK' if res.chain_ok else f'BROKEN at entry {res.broken_at}'}")
    for f in res.files:
        print(f"  {f['status']:>8}  {f['item']}")
    print("RESULT:", "PASS" if res.ok else "FAIL")
    return 0 if res.ok else 1


def analyze(case_dir: Path, rules_dir: Path, out_dir: Path, quiet: bool = False) -> Dict:
    cfg = load_case_config(case_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    log = (lambda *a: None) if quiet else print

    events, warnings = load_case(case_dir / "evidence", cfg["hosts"], cfg.get("year"))
    enrich(events)
    log(f"[*] parsed {len(events):,} events")
    rules = sigma.load_rules(rules_dir)
    findings = sigma.run_rules(rules, events) + run_analytics(events, Thresholds())
    findings.sort(key=lambda f: f.sort_key())
    log(f"[*] {len(rules)} rules + analytics -> {len(findings)} findings")

    iocs = ioc.extract(findings)
    ioc.write(iocs, out_dir)
    timeline.write_csv(events, findings, out_dir / "timeline.csv")
    trees = lineage.build_trees(events, findings)
    ver = custody.verify(case_dir)
    log_entries = custody.read_log(case_dir)
    logged = {e["item"] for e in log_entries if e["action"] == "intake"}
    for p in custody.evidence_files(case_dir):
        rel = p.relative_to(case_dir).as_posix()
        if rel not in logged:
            warnings.append(f"{rel}: not in the chain-of-custody log (run 'casekit intake')")

    md = report.build_markdown(cfg, events, findings, iocs, ver, log_entries,
                               timeline.key_events(events, findings), trees, warnings)
    (out_dir / "report.md").write_text(md, encoding="utf-8")
    (out_dir / "report.html").write_text(report.markdown_to_html(md, cfg.get("title", "Incident report")),
                                         encoding="utf-8")
    (out_dir / "findings.json").write_text(json.dumps([
        {"title": f.title, "severity": f.severity, "techniques": f.techniques, "rule_id": f.rule_id,
         "hosts": f.hosts, "first_seen": f.first_seen.isoformat(), "event_refs": [e.ref for e in f.events]}
        for f in findings], indent=2))
    custody.append(case_dir, "analysis", out_dir.name, {}, f"CaseKit v{__version__}: {len(findings)} findings")

    if not quiet:
        for f in findings:
            print(f"  [{f.severity.upper():>8}] {f.title}  ({', '.join(f.techniques)})")
        print(f"[+] report: {out_dir / 'report.html'}")
    return {"events": events, "findings": findings, "iocs": iocs, "verify": ver, "warnings": warnings}


def cmd_analyze(args) -> int:
    d = Path(args.case_dir)
    analyze(d, Path(args.rules), Path(args.out) if args.out else d / "output")
    return 0


def cmd_triage(args) -> int:
    cmd_intake(args)
    return cmd_analyze(args)


def cmd_rules(args) -> int:
    for r in sigma.load_rules(Path(args.rules)):
        print(f"{r.level:>9}  {r.title}  [{', '.join(r.techniques)}]")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="casekit", description="DFIR CaseKit - evidence to report.")
    p.add_argument("--version", action="version", version=f"casekit {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def case_cmd(name, fn, help_):
        sp = sub.add_parser(name, help=help_)
        sp.add_argument("case_dir")
        sp.set_defaults(fn=fn)
        return sp

    case_cmd("new", cmd_new, "scaffold a case directory")
    for name, fn, h in (("intake", cmd_intake, "hash and log evidence"),
                        ("triage", cmd_triage, "intake + analyze")):
        sp = case_cmd(name, fn, h)
        sp.add_argument("--note", default="")
        sp.add_argument("--examiner")
        sp.add_argument("--no-lock", action="store_true", help="don't make evidence read-only")
        if name == "triage":
            sp.add_argument("--rules", default=str(DEFAULT_RULES))
            sp.add_argument("--out")
    case_cmd("verify", cmd_verify, "verify evidence integrity")
    sp = case_cmd("analyze", cmd_analyze, "run detections and write the report")
    sp.add_argument("--rules", default=str(DEFAULT_RULES))
    sp.add_argument("--out")
    sp = sub.add_parser("rules", help="list Sigma rules")
    sp.add_argument("--rules", default=str(DEFAULT_RULES))
    sp.set_defaults(fn=cmd_rules)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
