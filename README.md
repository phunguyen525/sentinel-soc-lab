# Sentinel SOC Detection Lab

A working Microsoft Sentinel deployment built to answer one question: what does
the platform already detect, and what has to be written by hand?

A live tenant was stood up, an endpoint onboarded to Defender for Endpoint, and
a multi-stage attack run against both the identity and the endpoint. Five
analytics rules were authored in KQL, deployed, and confirmed firing against
that traffic. Each was then checked against Microsoft's own detections for the
same activity, using alert output and incident evidence rather than assumption.

Two of the five turned out to duplicate native coverage and were retired. The
attack was investigated end to end and written up as an incident report, and a
Conditional Access policy was deployed and tested to close the path the attacker
used.

---

## Environment

```
Browser + VPN ───────────→ Microsoft Entra ID ──────┐
(identity attack source)                            │
                                                    ├──→ Log Analytics
win11-target VM ─────────→ Defender for Endpoint ───┘    (law-soc-lab)
(VirtualBox, Atomic Red Team)                                  │
                                                        Microsoft Sentinel
```

Single tenant, two identities, one Windows 11 workstation, deployed in Canada
Central. Endpoint telemetry comes from a local hypervisor.

| Source | Mechanism | Tables |
|---|---|---|
| Microsoft Entra ID | Diagnostic setting | `SigninLogs`, `AuditLogs`, `AADNonInteractiveUserSignInLogs` |
| Defender for Endpoint | Defender XDR connector | `DeviceProcessEvents`, `DeviceRegistryEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceLogonEvents`, `DeviceImageLoadEvents`, `DeviceEvents`, `DeviceInfo` |
| Defender alerts | Defender XDR connector | `AlertInfo`, `AlertEvidence` |
| Entra ID Protection | Connector | `SecurityAlert` |

---

## Attack simulated

Two phases against one test account and the workstation it used. Identity
activity was driven from a browser over a commercial VPN; endpoint activity came
from Atomic Red Team.

| Stage | Technique | Method |
|---|---|---|
| Credential Access | T1110.001 Password guessing | Six failed sign-ins, then success from the same address |
| Initial Access | T1078 Valid accounts | Sign-in from an unfamiliar country via VPN |
| Persistence | T1556.006 MFA method | Passkey enrolled from an address never seen before |
| Execution | T1059.001 PowerShell | Encoded command, hidden window |
| Persistence | T1547.001 Registry Run keys | Autorun value written by `cmd.exe` |
| Discovery | T1016, T1049, T1087.001 | Eleven distinct utilities across nine minutes |
| Command and Control | T1105 Ingress tool transfer | `bitsadmin` succeeded, `certutil` blocked |

The full sequence, with timestamps, indicators and the queries used to
investigate it, is in `docs/incident-report-001.md`.

---

## Detection coverage

Each rule was verified by running the attack and confirming the alert fired. The
last column records whether Microsoft's built-in detections already covered the
same activity, measured against alert output and the evidence attached to the
correlated incident.

| # | Rule | MITRE | Verified | Native coverage |
|---|---|---|---|---|
| 1 | Credential guessing followed by successful sign-in | T1110.001, T1078 | Yes | None |
| 2 | Encoded or obfuscated PowerShell execution | T1059.001 | Yes | Duplicate, retired |
| 3 | Registry Run key written by non-standard process | T1547.001 | Yes | Duplicate, retired |
| 4 | MFA method registered from an unfamiliar address | T1556.006 | Yes | None |
| 5 | Discovery utility burst on a single host | T1016, T1049, T1087.001, T1082 | Yes | None |

The split fell along domain lines. Defender for Endpoint covered the endpoint
techniques completely, correlating them into a single multi-stage incident and
invoking automated disruption; Entra ID Protection raised nothing for the
credential guessing or the MFA enrolment. Rules 2 and 3 therefore added nothing
and were withdrawn, and remain here with their export template because the
measurement that retired them is part of the work.

---

## What's in here

| Path | What it is |
|---|---|
| `docs/incident-report-001.md` | Investigation write-up following NIST SP 800-61, with timeline, indicators, containment and recommendations |
| `kql/analytics-rules/` | The five rules as deployed, and the ARM template they export to |
