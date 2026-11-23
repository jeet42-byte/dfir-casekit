"""Incident report generation: Markdown, plus a self-contained HTML rendering.

The structure follows a conventional DFIR deliverable: executive summary,
scope and evidence integrity, findings ranked by severity, ATT&CK mapping,
attack timeline, process lineage, IOCs, and recommendations. Analyst-written
narrative (summary, conclusions, recommendations) is taken from ``case.yml``;
everything else is generated from the evidence and is reproducible.
"""
from __future__ import annotations

import html
import re
from collections import Counter
from datetime import datetime, timezone
from typing import Dict, List

from casekit import __version__, attack
from casekit.custody import VerifyResult
from casekit.ioc import IOC
from casekit.models import SEVERITY_ORDER, Event, Finding

SEV_ICON = {"critical": "🟥", "high": "🟧", "medium": "🟨", "low": "🟦", "informational": "⬜"}

# Containment / eradication guidance keyed by technique - used when the
# analyst has not written recommendations for a technique themselves.
PLAYBOOK = {
    "T1566.001": "Block the sender and attachment hash at the mail gateway; purge the message from all mailboxes.",
    "T1204.002": "Disable macros from the internet via Group Policy (Block macros in Office files from the Internet).",
    "T1059.001": "Enable PowerShell Script Block Logging (EID 4104) and Constrained Language Mode; alert on -EncodedCommand.",
    "T1547.001": "Remove the Run-key value and the dropped binary; hunt the same value name across the estate.",
    "T1003.001": "Treat every credential used on the host as compromised: reset passwords, reset krbtgt twice, enable LSA Protection (RunAsPPL) and Credential Guard.",
    "T1550.002": "Reset the affected privileged account; restrict NTLM, add admins to Protected Users, deploy LAPS for local admin passwords.",
    "T1021.002": "Block workstation-to-workstation/server SMB (445) at the host firewall except from admin jump hosts.",
    "T1569.002": "Alert on EID 7045 service installs on servers; remove PsExec-style services (PSEXESVC).",
    "T1136.002": "Disable and remove the rogue account; review all accounts created during the intrusion window.",
    "T1098": "Audit privileged group membership (Domain Admins, Administrators) and alert on EID 4728/4732/4756.",
    "T1070.001": "Forward logs to a SIEM in real time so local clearing cannot destroy evidence; alert on EID 1102/104.",
    "T1490": "Protect backups offline/immutable; alert on vssadmin/wmic shadowcopy deletion.",
    "T1071.004": "Sinkhole/block the C2 domain at DNS; force all DNS through internal resolvers and monitor query entropy.",
    "T1048": "Block the tunnelling domain; alert on long, high-entropy DNS labels and per-host DNS volume.",
    "T1041": "Block the destination IP at the perimeter; quantify the data exposed and assess notification duties.",
    "T1105": "Block the staging URL/domain at the web proxy; restrict PowerShell's outbound web access.",
    "T1110.001": "Rate-limit and lock out after repeated failures; enforce MFA; remove internet exposure of SSH/RDP where possible.",
    "T1560.001": "Alert on archivers (7z, rar, makecab) writing to staging directories on workstations.",
}


def _md_escape(s: str) -> str:
    return str(s).replace("|", "\\|").replace("\n", " ")


def _fmt(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%d %H:%M:%S")


def build_markdown(case: Dict, events: List[Event], findings: List[Finding], iocs: List[IOC],
                   verify: VerifyResult, custody: List[dict], key_events: List[tuple],
                   trees: Dict[str, List[str]], warnings: List[str]) -> str:
    findings = sorted(findings, key=lambda f: f.sort_key())
    sev_counts = Counter(f.severity for f in findings)
    techniques = sorted({t for f in findings for t in f.techniques})
    hosts = sorted({h for f in findings for h in f.hosts})
    first = min((f.first_seen for f in findings), default=None)
    last = max((e.ts for f in findings for e in f.events), default=None)
    L: List[str] = []
    add = L.append

    add(f"# Incident Report — {case.get('title', 'Untitled case')}")
    add("")
    add("| | |\n|---|---|")
    add(f"| **Case ID** | {case.get('case_id', '—')} |")
    add(f"| **Organisation** | {case.get('organisation', '—')} |")
    add(f"| **Examiner** | {case.get('examiner', '—')} |")
    add(f"| **Classification** | {case.get('classification', 'CONFIDENTIAL')} |")
    add(f"| **Report generated** | {_fmt(datetime.now(timezone.utc))} UTC by DFIR CaseKit v{__version__} |")
    add("")
    if case.get("disclaimer"):
        add(f"> {case['disclaimer']}")
        add("")

    add("## 1. Executive summary")
    add("")
    if case.get("summary"):
        add(case["summary"].strip())
        add("")
    counts = ", ".join(f"{sev_counts[s]} {s}" for s in SEVERITY_ORDER if sev_counts.get(s))
    add(f"**At a glance:** {len(findings)} findings ({counts or 'none'}) across "
        f"{len(hosts)} host(s): {', '.join(hosts) or '—'}. "
        f"{len(techniques)} distinct MITRE ATT&CK techniques. "
        + (f"Malicious activity spans {_fmt(first)} → {_fmt(last)} UTC." if first and last else ""))
    add("")

    add("## 2. Scope and evidence integrity")
    add("")
    status = "✅ intact" if verify.ok else "❌ **INTEGRITY FAILURE**"
    chain = "valid" if verify.chain_ok else f"**broken at entry {verify.broken_at}**"
    add(f"Chain of custody: {len(custody)} entries, hash chain {chain}; evidence re-hashed at report time: {status}.")
    add("")
    add("| Evidence item | Size | SHA-256 | Verified |\n|---|---:|---|---|")
    by_item = {f["item"]: f for f in verify.files}
    for c in (c for c in custody if c["action"] == "intake"):
        v = by_item.get(c["item"], {})
        add(f"| `{c['item']}` | {c.get('size') or 0:,} | `{c['sha256']}` | {v.get('status', '—')} |")
    src_counts = Counter(e.source for e in events)
    add("")
    add("Events parsed: " + ", ".join(f"{n:,} {s}" for s, n in src_counts.most_common()) + f" ({len(events):,} total).")
    add("")

    add("## 3. Findings summary")
    add("")
    add("| # | Severity | Finding | Host(s) | First seen (UTC) | ATT&CK |\n|---|---|---|---|---|---|")
    for i, f in enumerate(findings, 1):
        add(f"| {i} | {SEV_ICON.get(f.severity, '')} {f.severity.title()} | {_md_escape(f.title)} | "
            f"{', '.join(f.hosts)} | {_fmt(f.first_seen)} | {' '.join(f.techniques)} |")
    add("")

    add("## 4. MITRE ATT&CK mapping")
    add("")
    add("| Tactic | Technique |\n|---|---|")
    for tac, tids in attack.matrix(techniques).items():
        cells = "<br>".join(f"[{t}]({attack.url(t)}) {attack.name(t)}" for t in tids)
        add(f"| **{tac}** | {cells} |")
    add("")

    add("## 5. Attack timeline")
    add("")
    add("Events cited by at least one finding, in UTC order. The full super-timeline "
        "(every parsed event) is in `timeline.csv`.")
    add("")
    add("| Time (UTC) | Host | Source | Event | Finding |\n|---|---|---|---|---|")
    # Bulk analytic evidence (40 failed logons, 30 beacon queries) is shown as
    # first + last occurrence with a count, so the table stays a narrative.
    bulk_first, bulk_last, bulk_n = {}, {}, {}
    for f in findings:
        if f.detector == "analytic" and len(f.events) > 3:
            evs = sorted(f.events, key=lambda e: e.ts)
            bulk_first[id(evs[0])], bulk_last[id(evs[-1])] = f, f
            bulk_n[f.rule_id + f.title] = len(evs)
    bulk_members = {id(e) for f in findings if f.detector == "analytic" and len(f.events) > 3 for e in f.events}
    for e, fs in key_events:
        is_bulk_only = id(e) in bulk_members and all(
            f.detector == "analytic" and len(f.events) > 3 for f in fs)
        if is_bulk_only and id(e) not in bulk_first and id(e) not in bulk_last:
            continue
        label = fs[0].title
        if id(e) in bulk_first:
            f = bulk_first[id(e)]
            label = f"{f.title} — first of {bulk_n[f.rule_id + f.title]} events"
        elif id(e) in bulk_last:
            label = f"{bulk_last[id(e)].title} — last event"
        add(f"| {e.ts:%H:%M:%S} | {e.host} | {e.source}{' ' + str(e.event_id) if e.event_id else ''} | "
            f"{_md_escape(e.summary())[:160]} | {_md_escape(label)} |")
    add("")

    if trees:
        add("## 6. Process lineage")
        add("")
        add("Reconstructed from Sysmon EID 1 using ProcessGuid/ParentProcessGuid. Processes a detection fired on are marked.")
        add("")
        for host, lines in trees.items():
            add(f"**{host}**")
            add("")
            add("```text")
            L.extend(lines)
            add("```")
            add("")

    add("## 7. Detailed findings")
    add("")
    for i, f in enumerate(findings, 1):
        add(f"### 7.{i} {SEV_ICON.get(f.severity, '')} {f.title}")
        add("")
        add(f"**Severity:** {f.severity.title()} · **Detector:** {f.detector} (`{f.rule_id}`) · "
            f"**Hosts:** {', '.join(f.hosts)} · **Events:** {len(f.events)}")
        add("")
        add("**ATT&CK:** " + ", ".join(f"[{t} {attack.name(t)}]({attack.url(t)})" for t in f.techniques))
        add("")
        if f.description:
            add(f.description)
            add("")
        add("**Evidence:**")
        add("")
        for e in f.events[:8]:
            add(f"- `{e.ref}` {_fmt(e.ts)} {e.host} — {_md_escape(e.summary())[:220]}")
            if e.get("DecodedCommand"):
                add(f"  - Decoded PowerShell: `{_md_escape(e.get('DecodedCommand'))[:220]}`")
        if len(f.events) > 8:
            add(f"- … and {len(f.events) - 8} more events (see `timeline.csv`).")
        add("")

    add("## 8. Indicators of compromise")
    add("")
    add("Defanged for safe sharing. Machine-readable copies: `iocs.csv`, `iocs.json`.")
    add("")
    add("| Type | Indicator | First seen (UTC) | Context |\n|---|---|---|---|")
    for i in iocs:
        add(f"| {i.type} | `{_md_escape(i.defanged)}` | {i.first_seen.replace('T', ' ')[:19]} | {_md_escape(i.context)} |")
    add("")

    add("## 9. Recommendations")
    add("")
    if case.get("recommendations"):
        for r in case["recommendations"]:
            add(f"- {r}")
        add("")
        add("**Technique-specific controls**")
        add("")
    for t in techniques:
        if t in PLAYBOOK:
            add(f"- **{t} {attack.name(t)}:** {PLAYBOOK[t]}")
    add("")

    if case.get("conclusion"):
        add("## 10. Conclusion")
        add("")
        add(case["conclusion"].strip())
        add("")

    add("## Appendix A — Chain of custody log")
    add("")
    add("| # | Time (UTC) | Examiner | Action | Item | Entry hash |\n|---|---|---|---|---|---|")
    for c in custody:
        add(f"| {c['seq']} | {c['ts'].replace('T', ' ')[:19]} | {c['examiner']} | {c['action']} | "
            f"`{c['item']}` | `{c['entry_hash'][:16]}…` |")
    add("")
    add("## Appendix B — Methodology and limitations")
    add("")
    add("- Evidence was hashed (MD5/SHA-1/SHA-256) on intake, set read-only, and re-verified when this report was produced.")
    add("- Windows logs were matched against Sigma rules (`rules/`); cross-event behaviour (brute force, beaconing, "
        "DNS tunnelling, bulk transfer) was detected by threshold analytics whose numbers are stated in each finding.")
    add("- PCAP analysis is per-packet with no TCP reassembly; payloads split across segments are not inspected. "
        "Encrypted content was not decrypted — TLS findings rely on SNI and flow metadata.")
    add("- Absence of a detection is not evidence of absence: coverage is limited to the log sources supplied.")
    if warnings:
        add("")
        add("**Parser warnings:**")
        for w in warnings:
            add(f"- {w}")
    add("")
    return "\n".join(L)


# ------------------------------------------------------------- md -> html

CSS = """
:root{--bg:#f7f8fa;--fg:#1b1f24;--muted:#5b6472;--card:#fff;--line:#e3e6eb;--accent:#0b5cad;--code:#f0f2f5}
@media (prefers-color-scheme:dark){:root{--bg:#0f1216;--fg:#e6e8eb;--muted:#9aa3ad;--card:#171b21;--line:#2a3038;--accent:#6cb0ff;--code:#1f252c}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 -apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:1100px;margin:0 auto;padding:32px 20px}h1{font-size:26px;margin:0 0 16px}h2{font-size:20px;margin:36px 0 12px;padding-bottom:6px;border-bottom:2px solid var(--line)}
h3{font-size:16px;margin:26px 0 8px}a{color:var(--accent)}table{border-collapse:collapse;width:100%;margin:8px 0;background:var(--card);font-size:13.5px}
th,td{border:1px solid var(--line);padding:6px 9px;text-align:left;vertical-align:top}th{background:var(--code)}
code{background:var(--code);padding:1px 5px;border-radius:4px;font:12.5px ui-monospace,Menlo,Consolas,monospace;word-break:break-all}
pre{background:var(--code);padding:12px 14px;border-radius:6px;overflow-x:auto}pre code{padding:0;word-break:normal;white-space:pre}
blockquote{margin:0;padding:8px 14px;border-left:4px solid var(--accent);background:var(--card);color:var(--muted)}ul{padding-left:22px}
"""


def _inline(s: str) -> str:
    s = html.escape(s, quote=False)
    s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
    s = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", s)
    s = re.sub(r"\[([^\]]+)\]\((https?://[^)\s]+)\)", r'<a href="\2">\1</a>', s)
    return s.replace("&lt;br&gt;", "<br>")


def markdown_to_html(md: str, title: str) -> str:
    out, lines, i = [], md.split("\n"), 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("```"):
            j = i + 1
            while j < len(lines) and not lines[j].startswith("```"):
                j += 1
            out.append("<pre><code>" + html.escape("\n".join(lines[i + 1:j])) + "</code></pre>")
            i = j + 1
            continue
        if line.startswith("|"):
            rows = []
            while i < len(lines) and lines[i].startswith("|"):
                rows.append(lines[i])
                i += 1
            rows = "\n".join(rows).split("\n")
            cells = lambda r: [c.strip().replace("\\|", "|") for c in re.split(r"(?<!\\)\|", r.strip())[1:-1]]
            head, body = cells(rows[0]), [cells(r) for r in rows[2:]]
            out.append("<table><thead><tr>" + "".join(f"<th>{_inline(c)}</th>" for c in head) + "</tr></thead><tbody>"
                       + "".join("<tr>" + "".join(f"<td>{_inline(c)}</td>" for c in r) + "</tr>" for r in body)
                       + "</tbody></table>")
            continue
        m = re.match(r"^(#{1,4}) (.*)", line)
        if m:
            n = len(m.group(1))
            out.append(f"<h{n}>{_inline(m.group(2))}</h{n}>")
        elif line.startswith("- ") or line.startswith("  - "):
            items = []
            while i < len(lines) and (lines[i].startswith("- ") or lines[i].startswith("  - ")):
                items.append(("    " if lines[i].startswith("  ") else "") + _inline(lines[i].strip()[2:]))
                i += 1
            out.append("<ul>" + "".join(f"<li>{it.strip()}</li>" for it in items) + "</ul>")
            continue
        elif line.startswith("> "):
            out.append(f"<blockquote>{_inline(line[2:])}</blockquote>")
        elif line.strip():
            para = [line]
            while (i + 1 < len(lines) and lines[i + 1].strip()
                   and not re.match(r"^(#{1,4} |\||- |  - |> |```)", lines[i + 1])):
                i += 1
                para.append(lines[i])
            out.append(f"<p>{_inline(' '.join(p.strip() for p in para))}</p>")
        i += 1
    return (f"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" "
            f"content=\"width=device-width,initial-scale=1\"><title>{html.escape(title)}</title><style>{CSS}</style>"
            f"</head><body><main>{''.join(out)}</main></body></html>")
