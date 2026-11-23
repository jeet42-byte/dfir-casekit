"""A compact Sigma rule engine.

Implements the subset of the Sigma specification that covers the large
majority of community Windows rules:

* detection maps (fields AND-ed), lists of maps (OR-ed), keyword lists
* value lists (OR-ed), ``*`` / ``?`` wildcards, ``null`` for an absent field
* modifiers: ``contains``, ``startswith``, ``endswith``, ``re``, ``all``, ``cidr``
* conditions: ``and``, ``or``, ``not``, parentheses, ``1 of sel_*``,
  ``all of sel_*``, ``1 of them``, ``all of them``

Logsources are mapped onto CaseKit's normalised events - ``category:
process_creation`` matches Sysmon EID 1 *and* Security EID 4688 (with 4688's
field names aliased to Sysmon's), so one rule covers hosts with or without
Sysmon. Network rules use ``product: network`` with ``service: dns|http|tls``.
"""
from __future__ import annotations

import fnmatch
import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional

import yaml

from casekit.models import Event, Finding

# category -> list of (source, event ids or None for any)
CATEGORY_MAP = {
    "process_creation": [("sysmon", {1}), ("security", {4688})],
    "network_connection": [("sysmon", {3})],
    "process_access": [("sysmon", {10})],
    "file_event": [("sysmon", {11})],
    "registry_set": [("sysmon", {13})],
    "registry_event": [("sysmon", {12, 13, 14})],
    "dns_query": [("sysmon", {22})],
    "ps_script": [("powershell", {4104})],
}
# Security 4688 uses different names for the same facts.
FIELD_ALIASES = {"Image": ["NewProcessName"], "ParentImage": ["ParentProcessName"],
                 "User": ["SubjectUserName"]}


class SigmaError(ValueError):
    pass


# ------------------------------------------------------------------ matching

def _field_value(event: Event, name: str) -> Any:
    if name == "EventID":
        return event.event_id
    f = event.fields
    if name in f:
        return f[name]
    for alias in FIELD_ALIASES.get(name, []):
        if alias in f:
            return f[alias]
    lower = name.lower()
    for k, v in f.items():
        if k.lower() == lower:
            return v
    return None


def _glob_to_regex(pattern: str) -> re.Pattern:
    return re.compile(fnmatch.translate(pattern), re.IGNORECASE | re.DOTALL)


def _compile_value(value: Any, modifiers: List[str]) -> Callable[[Any], bool]:
    if value is None:
        return lambda v: v is None or v == ""
    if "re" in modifiers:
        rx = re.compile(str(value), re.IGNORECASE)
        return lambda v: v is not None and rx.search(str(v)) is not None
    if "cidr" in modifiers:
        net = ipaddress.ip_network(str(value), strict=False)

        def in_net(v):
            try:
                return v is not None and ipaddress.ip_address(str(v)) in net
            except ValueError:
                return False
        return in_net
    s = str(value)
    if "contains" in modifiers:
        s = f"*{s}*"
    elif "startswith" in modifiers:
        s = f"{s}*"
    elif "endswith" in modifiers:
        s = f"*{s}"
    if "*" in s or "?" in s:
        rx = _glob_to_regex(s.replace("[", "[[]"))
        return lambda v: v is not None and rx.match(str(v)) is not None
    low = s.lower()
    return lambda v: v is not None and str(v).lower() == low


def _compile_field(key: str, value: Any) -> Callable[[Event], bool]:
    name, *mods = key.split("|")
    values = value if isinstance(value, list) else [value]
    tests = [_compile_value(v, mods) for v in values]
    combine = all if "all" in mods else any

    def check(event: Event) -> bool:
        actual = _field_value(event, name)
        return combine(t(actual) for t in tests)
    return check


def _compile_map(mapping: Dict[str, Any]) -> Callable[[Event], bool]:
    checks = [_compile_field(k, v) for k, v in mapping.items()]
    return lambda e: all(c(e) for c in checks)


def _compile_keywords(words: List[Any]) -> Callable[[Event], bool]:
    rxs = [_glob_to_regex(f"*{w}*".replace("[", "[[]")) for w in words]
    return lambda e: any(rx.match(str(v)) for v in e.fields.values() for rx in rxs)


def compile_detection_item(item: Any) -> Callable[[Event], bool]:
    if isinstance(item, dict):
        return _compile_map(item)
    if isinstance(item, list) and all(isinstance(i, dict) for i in item):
        maps = [_compile_map(i) for i in item]
        return lambda e: any(m(e) for m in maps)
    if isinstance(item, list):
        return _compile_keywords(item)
    raise SigmaError(f"unsupported detection item: {item!r}")


# ----------------------------------------------------------------- condition

TOKEN = re.compile(r"\s*(\(|\)|[\w*]+)")


def _tokenize(cond: str) -> List[str]:
    pos, out = 0, []
    while pos < len(cond):
        m = TOKEN.match(cond, pos)
        if not m:
            if cond[pos:].strip() == "":
                break
            raise SigmaError(f"cannot parse condition near: {cond[pos:]!r}")
        out.append(m.group(1))
        pos = m.end()
    return out


class _CondParser:
    def __init__(self, tokens: List[str], selections: Dict[str, Callable[[Event], bool]]):
        self.t, self.i, self.sel = tokens, 0, selections

    def peek(self) -> Optional[str]:
        return self.t[self.i] if self.i < len(self.t) else None

    def take(self) -> str:
        tok = self.peek()
        if tok is None:
            raise SigmaError("unexpected end of condition")
        self.i += 1
        return tok

    def parse(self) -> Callable[[Event], bool]:
        node = self.expr()
        if self.peek() is not None:
            raise SigmaError(f"unexpected token {self.peek()!r}")
        return node

    def expr(self):
        left = self.term()
        while self.peek() == "or":
            self.take()
            right, l = self.term(), left
            left = lambda e, l=l, r=right: l(e) or r(e)
        return left

    def term(self):
        left = self.factor()
        while self.peek() == "and":
            self.take()
            right, l = self.factor(), left
            left = lambda e, l=l, r=right: l(e) and r(e)
        return left

    def factor(self):
        tok = self.take()
        if tok == "not":
            inner = self.factor()
            return lambda e: not inner(e)
        if tok == "(":
            node = self.expr()
            if self.take() != ")":
                raise SigmaError("missing ')'")
            return node
        if tok in ("1", "any", "all") and self.peek() == "of":
            self.take()
            target = self.take()
            names = list(self.sel) if target == "them" else [n for n in self.sel if fnmatch.fnmatchcase(n, target)]
            if not names:
                raise SigmaError(f"'{target}' matches no selection")
            funcs = [self.sel[n] for n in names]
            if tok == "all":
                return lambda e: all(f(e) for f in funcs)
            return lambda e: any(f(e) for f in funcs)
        if tok in self.sel:
            return self.sel[tok]
        raise SigmaError(f"unknown selection '{tok}'")


# ---------------------------------------------------------------------- rules

@dataclass
class SigmaRule:
    id: str
    title: str
    level: str
    description: str
    techniques: List[str]
    logsource: Dict[str, str]
    path: str
    _match: Callable[[Event], bool]

    def applies_to(self, event: Event) -> bool:
        ls = self.logsource
        product = ls.get("product", "windows")
        if product == "network":
            return event.source == "pcap" and event.fields.get("type") == ls.get("service")
        if product == "linux":
            return event.source == "authlog"
        if "category" in ls:
            return any(event.source == src and (eids is None or event.event_id in eids)
                       for src, eids in CATEGORY_MAP.get(ls["category"], []))
        if "service" in ls:
            return event.source == ls["service"]
        return event.source != "pcap"

    def matches(self, event: Event) -> bool:
        return self.applies_to(event) and self._match(event)


def techniques_from_tags(tags: Iterable[str]) -> List[str]:
    out = []
    for tag in tags or []:
        m = re.fullmatch(r"attack\.(t\d{4}(?:\.\d{3})?)", tag.lower())
        if m:
            out.append(m.group(1).upper())
    return out


def compile_rule(doc: Dict[str, Any], path: str = "") -> SigmaRule:
    det = dict(doc.get("detection") or {})
    if "condition" not in det:
        raise SigmaError(f"{path}: detection has no condition")
    cond = det.pop("condition")
    selections = {name: compile_detection_item(item) for name, item in det.items() if name != "timeframe"}
    conds = cond if isinstance(cond, list) else [cond]
    funcs = [_CondParser(_tokenize(c), selections).parse() for c in conds]
    return SigmaRule(
        id=str(doc.get("id", Path(path).stem)), title=doc.get("title", Path(path).stem),
        level=str(doc.get("level", "medium")).lower(), description=doc.get("description", "").strip(),
        techniques=techniques_from_tags(doc.get("tags")), logsource=doc.get("logsource") or {},
        path=path, _match=lambda e: any(f(e) for f in funcs),
    )


def load_rules(rule_dir: Path) -> List[SigmaRule]:
    rules = []
    for path in sorted(rule_dir.rglob("*.yml")) + sorted(rule_dir.rglob("*.yaml")):
        for doc in yaml.safe_load_all(path.read_text()):
            if doc and "detection" in doc:
                rules.append(compile_rule(doc, str(path)))
    return rules


def run_rules(rules: List[SigmaRule], events: List[Event]) -> List[Finding]:
    findings = []
    for rule in rules:
        hits = [e for e in events if rule.matches(e)]
        if hits:
            findings.append(Finding(title=rule.title, severity=rule.level, techniques=rule.techniques,
                                    description=rule.description, events=hits, rule_id=rule.id,
                                    detector="sigma"))
    return findings
