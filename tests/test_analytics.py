import random
from datetime import datetime, timedelta, timezone

from casekit.analytics import (Thresholds, dns_beaconing, dns_tunneling, registrable, shannon_entropy,
                               ssh_bruteforce, windows_bruteforce)
from casekit.models import Event

T0 = datetime(2026, 11, 18, 8, 0, tzinfo=timezone.utc)


def dns(ts, q, src="10.0.0.5"):
    return Event(ts, "pcap", "WS", None, {"type": "dns", "query": q, "src_ip": src}, "c.pcap", 1)


def test_regular_beacon_detected_and_bursty_ignored():
    rng = random.Random(1)
    beacon = [dns(T0 + timedelta(seconds=30 * i + rng.uniform(-2, 2)), "c2.bad.example") for i in range(20)]
    human, t = [], T0
    for _ in range(20):
        t += timedelta(seconds=rng.expovariate(1 / 40))
        human.append(dns(t, "news.example"))
    out = dns_beaconing(beacon + human, Thresholds())
    assert [f.title for f in out] == ["Periodic DNS beaconing to c2.bad.example"]


def test_allow_listed_periodic_domain_not_flagged():
    evs = [dns(T0 + timedelta(seconds=60 * i), "time.windows.com") for i in range(30)]
    assert dns_beaconing(evs, Thresholds()) == []


def test_tunnel_detection():
    rng = random.Random(2)
    alpha = "abcdefghijklmnopqrstuvwxyz234567"
    evs = [dns(T0 + timedelta(seconds=i), "".join(rng.choice(alpha) for _ in range(48)) + f".{i}.t.exfil.example")
           for i in range(10)]
    evs += [dns(T0, "www.example.com"), dns(T0, "mail.example.com")]
    (f,) = dns_tunneling(evs, Thresholds())
    assert "exfil.example" in f.title and len(f.events) == 10


def test_helpers():
    assert registrable("a.b.example.co.uk") == "example.co.uk"
    assert registrable("x.cdn-sync.example") == "cdn-sync.example"
    assert shannon_entropy("aaaa") == 0 and shannon_entropy("abcd") == 2


def _logon(eid, ts, ip, user, ltype=3):
    return Event(ts, "security", "SRV", eid, {"IpAddress": ip, "TargetUserName": user, "LogonType": str(ltype)}, "s", 1)


def test_windows_bruteforce_then_success_is_critical():
    evs = [_logon(4625, T0 + timedelta(seconds=5 * i), "198.51.100.9", f"u{i % 3}") for i in range(15)]
    evs.append(_logon(4624, T0 + timedelta(minutes=3), "198.51.100.9", "u1"))
    (f,) = windows_bruteforce(evs, Thresholds())
    assert f.severity == "critical" and "SUCCESSFUL" in f.description


def test_bruteforce_below_threshold_or_spread_out_ignored():
    few = [_logon(4625, T0 + timedelta(seconds=i), "198.51.100.9", "a") for i in range(5)]
    slow = [_logon(4625, T0 + timedelta(minutes=5 * i), "198.51.100.9", "a") for i in range(15)]
    assert windows_bruteforce(few, Thresholds()) == [] and windows_bruteforce(slow, Thresholds()) == []


def test_ssh_bruteforce_without_success_is_medium():
    evs = [Event(T0 + timedelta(seconds=4 * i), "authlog", "WEB", None,
                 {"action": "ssh_failed", "ip": "198.51.100.23", "user": "root"}, "auth.log", i) for i in range(12)]
    (f,) = ssh_bruteforce(evs, Thresholds())
    assert f.severity == "medium"
