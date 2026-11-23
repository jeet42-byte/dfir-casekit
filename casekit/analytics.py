"""Stateful detections that a single-event Sigma rule cannot express.

Each analytic looks across many events - counting, timing, measuring - and
explains its own verdict in the finding description, with the numbers that
drove it, so an analyst can check the reasoning rather than trust a score.
"""
from __future__ import annotations

import ipaddress
import math
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Dict, List, Sequence

from casekit.models import Event, Finding

SECOND_LEVEL = {"co", "com", "net", "org", "gov", "ac", "edu", "mil"}


@dataclass
class Thresholds:
    bruteforce_failures: int = 10
    bruteforce_window: timedelta = timedelta(minutes=10)
    success_after: timedelta = timedelta(minutes=30)
    beacon_min_queries: int = 8
    beacon_max_cv: float = 0.30            # stdev / mean of inter-arrival times
    beacon_min_interval_s: float = 5.0
    tunnel_min_label: int = 25
    tunnel_min_entropy: float = 3.5
    tunnel_min_queries: int = 5
    exfil_bytes: int = 1_000_000
    allow_domains: Sequence[str] = field(default_factory=lambda: (
        "microsoft.com", "windowsupdate.com", "msftncsi.com", "windows.com", "office.com",
        "office365.com", "google.com", "gstatic.com", "digicert.com"))


# ------------------------------------------------------------------- helpers

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


def registrable(domain: str) -> str:
    labels = domain.strip(".").lower().split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def is_public(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    # RFC 5737 documentation ranges are "global" for analysis purposes: the
    # sample case uses them to stand in for internet hosts.
    doc_nets = ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
    if any(a in ipaddress.ip_network(n) for n in doc_nets):
        return True
    return not (a.is_private or a.is_loopback or a.is_multicast or a.is_link_local or a.is_reserved)


def _allowed(domain: str, th: Thresholds) -> bool:
    d = domain.lower().strip(".")
    return any(d == a or d.endswith("." + a) for a in th.allow_domains)


# ------------------------------------------------------------- brute force

def _bruteforce(failures: List[Event], successes: List[Event], key_fail, key_ok, user_key: str,
                th: Thresholds, label: str, technique: str) -> List[Finding]:
    groups: Dict[tuple, List[Event]] = defaultdict(list)
    for e in failures:
        groups[key_fail(e)].append(e)
    ok_by_key: Dict[tuple, List[Event]] = defaultdict(list)
    for e in successes:
        ok_by_key[key_ok(e)].append(e)

    findings = []
    for (host, ip), evs in groups.items():
        evs.sort(key=lambda e: e.ts)
        # sliding window: the densest burst of failures
        best, start = 0, 0
        for end in range(len(evs)):
            while evs[end].ts - evs[start].ts > th.bruteforce_window:
                start += 1
            best = max(best, end - start + 1)
        if best < th.bruteforce_failures:
            continue
        users = Counter(str(e.get(user_key)) for e in evs)
        last_fail = evs[-1].ts
        wins = [s for s in ok_by_key.get((host, ip), [])
                if evs[0].ts <= s.ts <= last_fail + th.success_after]
        top_users = ", ".join(f"{u} ({n})" for u, n in users.most_common(5))
        desc = (f"{len(evs)} failed {label} logons to {host} from {ip} between "
                f"{evs[0].ts:%H:%M:%S} and {last_fail:%H:%M:%S} UTC (peak {best} within "
                f"{int(th.bruteforce_window.total_seconds() // 60)} min); {len(users)} distinct "
                f"usernames tried, most frequent: {top_users}.")
        if wins:
            desc += (f" A SUCCESSFUL logon from the same source followed at {wins[0].ts:%H:%M:%S} UTC "
                     f"as '{wins[0].get(user_key)}' - treat the account as compromised.")
            sev, title = "critical", f"{label} brute force followed by successful logon"
        else:
            desc += " No successful logon from this source was observed in the evidence."
            sev, title = "medium", f"{label} brute force (no success observed)"
        findings.append(Finding(title=title, severity=sev, techniques=[technique], description=desc,
                                events=evs + wins, rule_id=f"analytic.bruteforce.{label.lower()}",
                                detector="analytic"))
    return findings


def windows_bruteforce(events: List[Event], th: Thresholds) -> List[Finding]:
    fails = [e for e in events if e.source == "security" and e.event_id == 4625]
    oks = [e for e in events if e.source == "security" and e.event_id == 4624
           and str(e.get("LogonType")) in ("3", "10")]
    key = lambda e: (e.host, str(e.get("IpAddress")))
    return _bruteforce(fails, oks, key, key, "TargetUserName", th, "Windows", "T1110.001")


def ssh_bruteforce(events: List[Event], th: Thresholds) -> List[Finding]:
    fails = [e for e in events if e.source == "authlog" and e.get("action") == "ssh_failed"]
    oks = [e for e in events if e.source == "authlog" and e.get("action") == "ssh_accepted"]
    key = lambda e: (e.host, str(e.get("ip")))
    return _bruteforce(fails, oks, key, key, "user", th, "SSH", "T1110.001")


# -------------------------------------------------------------- DNS / network

def dns_beaconing(events: List[Event], th: Thresholds) -> List[Finding]:
    groups: Dict[tuple, List[Event]] = defaultdict(list)
    for e in events:
        if e.source == "pcap" and e.get("type") == "dns" and not _allowed(e.get("query"), th):
            groups[(e.get("src_ip"), e.get("query"))].append(e)
    findings = []
    for (src, q), evs in groups.items():
        if len(evs) < th.beacon_min_queries:
            continue
        evs.sort(key=lambda e: e.ts)
        gaps = [(b.ts - a.ts).total_seconds() for a, b in zip(evs, evs[1:])]
        gaps = [g for g in gaps if g > 0.5]                 # ignore retransmits
        if len(gaps) < th.beacon_min_queries - 1:
            continue
        mean = statistics.mean(gaps)
        cv = statistics.pstdev(gaps) / mean if mean else 1.0
        if mean < th.beacon_min_interval_s or cv > th.beacon_max_cv:
            continue
        findings.append(Finding(
            title=f"Periodic DNS beaconing to {q}",
            severity="high", techniques=["T1071.004"],
            description=(f"{src} ({evs[0].host}) resolved {q} {len(evs)} times at a regular interval: "
                         f"mean {mean:.1f}s, jitter (coefficient of variation) {cv:.2f}. Human-driven "
                         "lookups are bursty; a near-constant interval is characteristic of an implant "
                         "checking in with command-and-control."),
            events=evs, rule_id="analytic.dns_beacon", detector="analytic"))
    return findings


def dns_tunneling(events: List[Event], th: Thresholds) -> List[Finding]:
    groups: Dict[str, List[Event]] = defaultdict(list)
    for e in events:
        if e.source != "pcap" or e.get("type") != "dns":
            continue
        q = e.get("query")
        parent = registrable(q)
        sub = q[: -len(parent)].strip(".")
        longest = max((len(l) for l in sub.split(".")), default=0)
        if longest >= th.tunnel_min_label and shannon_entropy(sub.replace(".", "")) >= th.tunnel_min_entropy:
            groups[parent].append(e)
    findings = []
    for parent, evs in groups.items():
        uniq = {e.get("query") for e in evs}
        if len(uniq) < th.tunnel_min_queries:
            continue
        encoded = sum(len(q) - len(parent) - 1 for q in uniq)
        ent = statistics.mean(shannon_entropy(q[: -len(parent)].replace(".", "")) for q in uniq)
        srcs = sorted({f"{e.get('src_ip')} ({e.host})" for e in evs})
        findings.append(Finding(
            title=f"DNS tunnelling / exfiltration via {parent}",
            severity="high", techniques=["T1048", "T1071.004"],
            description=(f"{len(uniq)} unique queries under {parent} carried long, high-entropy subdomains "
                         f"(mean entropy {ent:.2f} bits/char, ~{encoded:,} bytes of encoded labels) from "
                         f"{', '.join(srcs)}. Legitimate hostnames are short and pronounceable; this pattern "
                         "matches data being smuggled out inside DNS queries."),
            events=evs, rule_id="analytic.dns_tunnel", detector="analytic"))
    return findings


def large_outbound(events: List[Event], th: Thresholds) -> List[Finding]:
    sni_by_dst = defaultdict(set)
    for e in events:
        if e.source == "pcap" and e.get("type") == "tls":
            sni_by_dst[e.get("dst_ip")].add(e.get("sni"))
    findings = []
    for e in events:
        if (e.source == "pcap" and e.get("type") == "flow" and e.get("bytes", 0) >= th.exfil_bytes
                and not is_public(e.get("src_ip")) and is_public(e.get("dst_ip"))):
            names = ", ".join(sorted(sni_by_dst.get(e.get("dst_ip"), []))) or "no SNI observed"
            findings.append(Finding(
                title=f"Large outbound transfer to {e.get('dst_ip')}:{e.get('dst_port')}",
                severity="high", techniques=["T1041"],
                description=(f"{e.get('src_ip')} ({e.host}) sent {e.get('bytes'):,} bytes in {e.get('packets')} "
                             f"packets over {e.get('duration_s')}s to {e.get('dst_ip')}:{e.get('dst_port')} "
                             f"(TLS names: {names}). Outbound volume from a workstation at this scale, to a "
                             "host with no business purpose, is the network signature of exfiltration."),
                events=[e], rule_id="analytic.large_outbound", detector="analytic"))
    return findings


ALL = [windows_bruteforce, ssh_bruteforce, dns_beaconing, dns_tunneling, large_outbound]


def run_analytics(events: List[Event], th: Thresholds | None = None) -> List[Finding]:
    th = th or Thresholds()
    out: List[Finding] = []
    for fn in ALL:
        out.extend(fn(events, th))
    return out
