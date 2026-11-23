"""Process lineage reconstruction from Sysmon EID 1.

A single suspicious process is a data point; the chain that produced it is
the story. Given the processes a detection fired on, this rebuilds every
ancestor (up to the first process the logs don't cover) and every
descendant, using ProcessGuid / ParentProcessGuid - which, unlike PIDs, are
never reused - and renders the result as an indented tree.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Set

from casekit.models import Event, Finding


def _name(path: str) -> str:
    return str(path).replace("/", "\\").rsplit("\\", 1)[-1]


def build_trees(events: List[Event], findings: List[Finding], max_cmd: int = 110) -> Dict[str, List[str]]:
    procs = {e.get("ProcessGuid"): e for e in events
             if e.source == "sysmon" and e.event_id == 1 and e.get("ProcessGuid")}
    children: Dict[str, List[str]] = defaultdict(list)
    for guid, e in procs.items():
        children[e.get("ParentProcessGuid")].append(guid)

    flagged: Set[str] = set()
    for f in findings:
        for e in f.events:
            if e.source == "sysmon" and e.get("ProcessGuid") in procs:
                flagged.add(e.get("ProcessGuid"))
            if e.source == "sysmon" and e.get("SourceProcessGUID") in procs:
                flagged.add(e.get("SourceProcessGUID"))
    if not flagged:
        return {}

    keep: Set[str] = set()
    for g in flagged:                       # ancestors
        cur = g
        while cur in procs and cur not in keep:
            keep.add(cur)
            cur = procs[cur].get("ParentProcessGuid")
    stack = list(flagged)                   # descendants
    while stack:
        g = stack.pop()
        for c in children.get(g, []):
            if c not in keep:
                keep.add(c)
                stack.append(c)

    roots = [g for g in keep if procs[g].get("ParentProcessGuid") not in keep]
    trees: Dict[str, List[str]] = defaultdict(list)

    def render(g: str, depth: int) -> None:
        e = procs[g]
        cmd = str(e.get("CommandLine"))
        cmd = cmd if len(cmd) <= max_cmd else cmd[: max_cmd - 3] + "..."
        mark = "  <-- flagged" if g in flagged else ""
        lines = trees[e.host]
        if depth == 0:
            parent = _name(e.get("ParentImage")) or "?"
            lines.append(f"[{parent}] (parent not in logs)")
        lines.append(f"{'    ' * depth}└─ {_name(e.get('Image'))} (PID {e.get('ProcessId')}, "
                     f"{e.ts:%H:%M:%S}) {e.get('User', '')}{mark}")
        lines.append(f"{'    ' * depth}     {cmd}")
        for c in sorted((c for c in children.get(g, []) if c in keep), key=lambda c: procs[c].ts):
            render(c, depth + 1)

    for r in sorted(roots, key=lambda g: procs[g].ts):
        render(r, 0)
    return dict(trees)
