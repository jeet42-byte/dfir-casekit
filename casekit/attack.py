"""MITRE ATT&CK (Enterprise) reference data for the techniques CaseKit detects.

Only the techniques the bundled rules and analytics can emit are listed; an
unknown ID still renders, just without a name. Tactic order follows the
ATT&CK matrix, left to right, so the report's matrix reads as a kill chain.
"""
from __future__ import annotations

from collections import OrderedDict
from typing import Dict, Iterable, List

TACTICS = [
    "Reconnaissance", "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection",
    "Command and Control", "Exfiltration", "Impact",
]

# technique -> (name, primary tactic)
TECHNIQUES: Dict[str, tuple] = {
    "T1566.001": ("Phishing: Spearphishing Attachment", "Initial Access"),
    "T1204.002": ("User Execution: Malicious File", "Execution"),
    "T1059.001": ("Command and Scripting Interpreter: PowerShell", "Execution"),
    "T1059.003": ("Command and Scripting Interpreter: Windows Command Shell", "Execution"),
    "T1569.002": ("System Services: Service Execution", "Execution"),
    "T1547.001": ("Boot or Logon Autostart: Registry Run Keys", "Persistence"),
    "T1053.005": ("Scheduled Task/Job: Scheduled Task", "Persistence"),
    "T1136.002": ("Create Account: Domain Account", "Persistence"),
    "T1098": ("Account Manipulation", "Persistence"),
    "T1027": ("Obfuscated Files or Information", "Defense Evasion"),
    "T1036.005": ("Masquerading: Match Legitimate Name or Location", "Defense Evasion"),
    "T1218.011": ("System Binary Proxy Execution: Rundll32", "Defense Evasion"),
    "T1070.001": ("Indicator Removal: Clear Windows Event Logs", "Defense Evasion"),
    "T1550.002": ("Use Alternate Authentication Material: Pass the Hash", "Lateral Movement"),
    "T1003.001": ("OS Credential Dumping: LSASS Memory", "Credential Access"),
    "T1110.001": ("Brute Force: Password Guessing", "Credential Access"),
    "T1033": ("System Owner/User Discovery", "Discovery"),
    "T1087.002": ("Account Discovery: Domain Account", "Discovery"),
    "T1482": ("Domain Trust Discovery", "Discovery"),
    "T1021.002": ("Remote Services: SMB/Windows Admin Shares", "Lateral Movement"),
    "T1560.001": ("Archive Collected Data: Archive via Utility", "Collection"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1071.001": ("Application Layer Protocol: Web Protocols", "Command and Control"),
    "T1071.004": ("Application Layer Protocol: DNS", "Command and Control"),
    "T1573": ("Encrypted Channel", "Command and Control"),
    "T1041": ("Exfiltration Over C2 Channel", "Exfiltration"),
    "T1048": ("Exfiltration Over Alternative Protocol", "Exfiltration"),
    "T1490": ("Inhibit System Recovery", "Impact"),
}


def name(tid: str) -> str:
    return TECHNIQUES.get(tid, (tid, ""))[0]


def tactic(tid: str) -> str:
    return TECHNIQUES.get(tid, ("", "Unmapped"))[1] or "Unmapped"


def url(tid: str) -> str:
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"


def matrix(techniques: Iterable[str]) -> "OrderedDict[str, List[str]]":
    """Group technique IDs by tactic, in kill-chain order."""
    out: "OrderedDict[str, List[str]]" = OrderedDict()
    seen = sorted(set(techniques))
    for t in TACTICS + ["Unmapped"]:
        hits = [tid for tid in seen if tactic(tid) == t]
        if hits:
            out[t] = hits
    return out
