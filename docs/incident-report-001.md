# INC-2026-001, account compromise and post-access activity on workstation PHU

Classification: Internal
Distribution: Security Operations Manager; IT Operations
Prepared by: Phú Nguyễn, Security Operations
Date of report: 2026-09-23

Source addresses have been replaced with RFC 5737 documentation ranges and the
account identifier truncated. The substitution is consistent throughout, so the
distinction between the workstation's own address and the unfamiliar address
used for the authentication-method registration is preserved.

---

## Case summary

| | |
|---|---|
| Case ID | INC-2026-001 |
| Severity | High |
| Status | Closed, contained, with one open remediation item |
| Framework | NIST SP 800-61r2 |
| Activity window | 2026-09-23 17:30 to 18:54 UTC |
| First detection | 17:33:27 UTC, Defender for Endpoint |
| First identity detection | 18:17:34 UTC, Sentinel analytics |
| Containment complete | 20:51:53 UTC |
| Time to detect, endpoint | 3m 15s |
| Time to detect, identity | 40m 21s |
| Time to contain | 3h 16m from first alert |
| Accounts affected | 1 |
| Hosts affected | 1 |
| Data exfiltration observed | None |

All timestamps UTC. Local time is UTC minus 3.

---

## 1. Executive summary

An attacker obtained the password of a standard user account by guessing, and
signed in successfully on the sixth attempt. They then registered their own
authentication method on the account, an action that would have preserved their
access through a password reset, and ran a sequence of commands on the user's
workstation to establish persistence and survey the environment.

Every technique observed produced an alert. Coverage came from two independent
sources working over different ground. Endpoint protection detected the
workstation activity within minutes of each action. The identity activity,
meaning the password guessing and the addition of an attacker-controlled
authentication method, was detected only by analytics rules maintained in-house,
and the platform's own identity protection raised nothing.

No evidence of data access or exfiltration was found. The account has been
restricted to phishing-resistant authentication and re-tested, and a password
alone no longer grants access.

One remediation item remains open and is rated High. The authentication method
registered by the attacker is still present on the account, and until it is
removed, containment is incomplete.

---

## 2. Preparation

### 2.1 Affected assets

| Attribute | Value |
|---|---|
| Hostname | `PHU` |
| Type | Workstation |
| Operating system | Windows 11, build 26200 |
| Public address | `198.51.100.24` |
| EDR onboarding status | Onboarded |
| EDR sensor health | Active |
| Logged-on user | `phu1` (`S-1-5-21-…-1001`) |

| Attribute | Value |
|---|---|
| Account | Standard user, Microsoft 365 E5 licensed |
| Privileges | No administrative roles assigned |
| Authentication methods at time of incident | Password, Microsoft Authenticator |

### 2.2 Controls in place

Detection was provided by Defender for Endpoint covering endpoint behaviour,
Entra ID Protection covering sign-in risk, and four scheduled Sentinel analytics
rules covering credential guessing, MFA enrolment, encoded PowerShell and
autorun registry keys.

Preventive controls amounted to password authentication only. No Conditional
Access policy was configured, and this is the condition that permitted the first
phase of the attack to succeed.

---

## 3. Detection and analysis

### 3.1 Timeline

| Time (UTC) | Activity | Source |
|---|---|---|
| 17:30:12 | Autorun registry key written by `cmd.exe` | `DeviceRegistryEvents` |
| 17:31:22 | Encoded PowerShell executed with `-nop -w hidden -enc` | `DeviceProcessEvents` |
| 17:33:27 | Alert, anomaly detected in ASEP registry | Defender for Endpoint |
| 17:33:52 | First failed sign-in, result 50126 | `SigninLogs` |
| 17:35:11 | Alert, registry Run key written by non-standard process | Sentinel |
| 17:35:11 to 17:36:22 | Five further authentication failures, same source | `SigninLogs` |
| 17:36:26 | Alert, suspicious PowerShell download or encoded command | Defender for Endpoint |
| 17:36:30 | Result 50140, "keep me signed in" interrupt | `SigninLogs` |
| 17:37:13 | Successful sign-in, same source address | `SigninLogs` |
| 17:42 | Sign-in from commercial VPN egress address | `SigninLogs` |
| 17:44 | Authentication method registered from `203.0.113.47` | `AuditLogs` |
| 18:17:34 | Alert, credential guessing followed by successful sign-in, High | Sentinel |
| 18:32:48 | Alert, encoded or obfuscated PowerShell execution | Sentinel |
| 18:47:32 to 18:47:34 | `ipconfig`, `netsh`, `arp`, `nbtstat`, `net`, `netstat`, `route` | `DeviceProcessEvents` |
| 18:53:37 | `certutil` download attempt, blocked by antivirus | `DeviceProcessEvents` |
| 18:53:40 | `bitsadmin` download, completed successfully | `DeviceProcessEvents` |
| 18:53:45 to 18:53:52 | `net user`, `net localgroup`, `cmdkey /list`, `query user` | `DeviceProcessEvents` |
| 18:54:24 | Alert, malware in command line prevented from executing | Defender for Endpoint |
| 18:57:25 | Alert, suspicious bitsadmin activity | Defender for Endpoint |
| 18:57:26 | Alert, compromised account conducting hands-on-keyboard attack, High | Defender for Endpoint |
| 19:00:24 | Alert, possible theft of passwords and browser information | Defender for Endpoint |
| 19:28:31 | Alert, discovery utility burst on a single host | Sentinel |
| 20:14:33 | Alert, MFA method registered from an unfamiliar address | Sentinel |
| 20:24:25 | Conditional Access policy created, report-only | `AuditLogs` |
| 20:51:53 | Conditional Access policy enforced | `AuditLogs` |

### 3.2 Investigation

The first question was whether the failures and the eventual success originated
from the same source, and whether the success followed the failures rather than
preceding them.

```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where UserPrincipalName startswith "testuser"
| project TimeGenerated, IPAddress, ResultType, ResultDescription
| order by TimeGenerated desc
```

Six results of 50126, meaning invalid username or password, occurred between
17:33:52 and 17:36:22 from a single address, followed by result 0 at 17:37:13
from that same address. One result of 50140 at 17:36:30 is a "keep me signed in"
interrupt rather than an authentication failure, and is excluded from the count.

Attempt timing required a second column. `TimeGenerated` records the time a
record reached the workspace, not the time of the sign-in itself, while
`CreatedDateTime` carries the latter. Measured across a controlled sequence of
ten attempts spaced at fifteen-second intervals, ingestion delay ranged from
1m 12s to 6m 26s. Any analysis of attempt rate must use `CreatedDateTime`.

Identifying the registered authentication method required extraction from a
nested structure.

```kql
AuditLogs
| where TimeGenerated > ago(6h)
| where OperationName has "security info"
| extend Actor    = tostring(InitiatedBy.user.userPrincipalName)
| extend SourceIP = tostring(InitiatedBy.user.ipAddress)
| project TimeGenerated, OperationName, Actor, SourceIP, Result
```

One record returned, `User registered security info`, successful, from
`203.0.113.47`.

The source address was then checked against sign-in history.

```kql
SigninLogs
| where TimeGenerated > ago(30d)
| where IPAddress == "203.0.113.47"
```

No results. The address had never been used to authenticate against this tenant
in the retained period, which is what makes the enrolment significant rather
than routine account maintenance.

### 3.3 Indicators of compromise

| Type | Value | Context |
|---|---|---|
| SHA256 | `ef37663b44ac66920c6f33694deea01acb78ae3f3012884819373fa04c3eb5f0` | `reg.exe`, autorun key write |
| SHA256 | `8bb6fa8c283b4d92120b1ef249a9b311b0f804d4cabbe9981159976c8be76a5e` | `powershell.exe` |
| SHA256 | `4125cd7966810cdfafb18157c276a88e6ac443c7c98d42593c70247045815028` | `cmdkey.exe` |
| Registry | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, value `Atomic Red Team`, data `C:\Path\AtomicRedTeam.exe` | Persistence |
| Authentication method | Passkey registered under the name `hacker` | Persistence |
| Source address | `203.0.113.47` | Authentication method registration, no prior history |
| Command line | `powershell.exe -nop -w hidden -enc VwByAGkAdABlAC0ASABvAHMAdAAgACIAdABlAHMAdAAiAA==` | Obfuscated execution |
| Command line | `Import-Module "…\Invoke-Mimikatz.ps1"; Invoke-Mimikatz -DumpCreds` | Credential access attempt |

The credential-dumping attempt failed because the payload file was not present
on disk, but the command line was recorded in full. Telemetry captures intent
independently of outcome, so a failed attempt is as visible as a successful one
and is equally indicative of operator intent.

### 3.4 MITRE ATT&CK mapping

| Tactic | Technique | Observed | Detection source |
|---|---|---|---|
| Credential Access | T1110.001 Password Guessing | Six failures followed by success | Sentinel |
| Initial Access | T1078 Valid Accounts | Successful sign-in 17:37:13 | Sentinel |
| Execution | T1059.001 PowerShell | Encoded command, hidden window | Defender, Sentinel |
| Persistence | T1547.001 Registry Run Keys | Autorun value written | Defender, Sentinel |
| Persistence | T1556.006 Multi-Factor Authentication | Passkey registered | Sentinel |
| Discovery | T1016, T1049, T1087.001, T1082 | Eleven distinct utilities across nine minutes | Sentinel |
| Command and Control | T1105 Ingress Tool Transfer | `bitsadmin` succeeded, `certutil` blocked | Defender |

---

## 4. Containment, eradication and recovery

At 20:24:25 a Conditional Access policy was created in report-only mode. The
policy requires phishing-resistant authentication strength for the affected
account across all resources. In report-only mode the sign-in log recorded
`reportOnlyInterrupted` with all three conditions satisfied, confirming the
policy would apply as intended before enforcement.

This action was taken first because it closes the access path. The attacker
holds a valid password, and removing the password's sufficiency is more
immediate and more complete than revoking any individual session.

At 20:51:53 the policy was enforced. Time to contain from first alert was
3h 16m.

The control was verified in both directions. With the policy enforced, signing
in with the password produced an interrupt offering only "Face, fingerprint, PIN
or security key", with no push notification and no one-time code offered.
Signing in with a registered passkey completed normally. A control that blocks
all access is not a working control, so both the deny path and the permit path
were tested before the case was closed.

One item remains outstanding. The autorun registry value and the
attacker-registered passkey remain in place at the time of writing. Removal is
tracked as recommendation 1 below and is rated High.

Defender XDR invoked attack disruption during the endpoint phase without
operator intervention, so no manual endpoint containment was required.

---

## 5. Recommendations
| # | Recommendation | Priority | Owner | Target |
|---|---|---|---|---|
| 1 | Audit authentication methods on the affected account and remove the passkey registered at 17:44 | High | Identity Operations | 24 hours |
| 2 | Extend Conditional Access requiring phishing-resistant authentication to all accounts | High | Identity Operations | 7 days |
| 3 | Configure alert suppression on all scheduled rules, duration matching lookback window | Medium | Security Operations | 14 days |
| 4 | Review analytics rule coverage against native detections, per the post-incident review | Medium | Security Operations | 30 days |

Recommendation 1 is rated High and given the shortest target because an
attacker-registered authentication method survives a password reset. Until it is
removed, the containment described in section 4 is incomplete.

Recommendation 2 is rated High because the Conditional Access policy currently
scopes a single account. Every other identity in the tenant retains
password-only access and remains exposed to the same technique.

