from datetime import datetime, timezone

import pytest

from casekit.models import Event
from casekit.sigma import SigmaError, compile_rule, techniques_from_tags

TS = datetime(2026, 1, 1, tzinfo=timezone.utc)


def ev(source="sysmon", eid=1, **fields):
    return Event(TS, source, "HOST", eid, fields, "test.jsonl", 1)


def rule(detection, logsource=None, **kw):
    return compile_rule({"title": "t", "logsource": logsource or {"product": "windows", "category": "process_creation"},
                         "detection": detection, **kw})


def test_modifiers_and_case_insensitivity():
    r = rule({"sel": {"Image|endswith": "\\powershell.exe", "CommandLine|contains": "-ENC"}, "condition": "sel"})
    assert r.matches(ev(Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\PowerShell.EXE", CommandLine="powershell -enc AAA"))
    assert not r.matches(ev(Image="C:\\x\\pwsh.exe", CommandLine="-enc"))


def test_value_list_is_or_and_all_modifier_is_and():
    any_r = rule({"sel": {"CommandLine|contains": ["foo", "bar"]}, "condition": "sel"})
    all_r = rule({"sel": {"CommandLine|contains|all": ["foo", "bar"]}, "condition": "sel"})
    assert any_r.matches(ev(CommandLine="x bar"))
    assert not all_r.matches(ev(CommandLine="x bar"))
    assert all_r.matches(ev(CommandLine="foo bar"))


def test_wildcards_regex_null_and_brackets():
    assert rule({"s": {"Image": "C:\\*\\cmd.exe"}, "condition": "s"}).matches(ev(Image="C:\\Windows\\cmd.exe"))
    assert rule({"s": {"CommandLine|re": r"\d{3}-\d{4}"}, "condition": "s"}).matches(ev(CommandLine="call 555-1234"))
    assert rule({"s": {"ParentImage": None}, "condition": "s"}).matches(ev(Image="a"))
    assert rule({"s": {"CommandLine|contains": "[x]"}, "condition": "s"}).matches(ev(CommandLine="a [x] b"))


def test_condition_grammar():
    det = {"sel_a": {"Image|endswith": "a.exe"}, "sel_b": {"Image|endswith": "b.exe"},
           "filter": {"User": "SYSTEM"}}
    r = rule({**det, "condition": "1 of sel_* and not filter"})
    assert r.matches(ev(Image="x\\b.exe", User="alice"))
    assert not r.matches(ev(Image="x\\b.exe", User="SYSTEM"))
    r2 = rule({**det, "condition": "(sel_a or sel_b) and not (filter)"})
    assert r2.matches(ev(Image="x\\a.exe", User="bob"))
    r3 = rule({"s1": {"Image|contains": "a"}, "s2": {"Image|contains": "b"}, "condition": "all of them"})
    assert r3.matches(ev(Image="ab")) and not r3.matches(ev(Image="a"))


def test_bad_conditions_raise():
    with pytest.raises(SigmaError):
        rule({"sel": {"Image": "x"}, "condition": "sel and missing"})
    with pytest.raises(SigmaError):
        rule({"sel": {"Image": "x"}, "condition": "(sel"})


def test_process_creation_covers_security_4688_with_aliases():
    r = rule({"sel": {"Image|endswith": "\\cmd.exe", "ParentImage|endswith": "\\WINWORD.EXE"}, "condition": "sel"})
    e = ev("security", 4688, NewProcessName="C:\\Windows\\System32\\cmd.exe",
           ParentProcessName="C:\\Program Files\\Office\\WINWORD.EXE")
    assert r.matches(e)
    assert not r.matches(ev("security", 4624, NewProcessName="cmd.exe"))


def test_service_logsource_and_eventid():
    r = rule({"sel": {"EventID": [1102, 104]}, "condition": "sel"}, {"product": "windows", "service": "security"})
    assert r.matches(ev("security", 1102))
    assert not r.matches(ev("system", 1102))


def test_cidr_and_network_logsource():
    r = rule({"sel": {"dst_ip|cidr": "203.0.113.0/24"}, "condition": "sel"}, {"product": "network", "service": "http"})
    assert r.matches(ev("pcap", None, type="http", dst_ip="203.0.113.9"))
    assert not r.matches(ev("pcap", None, type="dns", dst_ip="203.0.113.9"))


def test_attack_tags():
    assert techniques_from_tags(["attack.execution", "attack.t1059.001", "attack.T1027"]) == ["T1059.001", "T1027"]
