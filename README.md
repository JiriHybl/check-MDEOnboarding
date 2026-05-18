# MDE Onboarding Detection

A PowerShell detection script for **Microsoft Intune** that validates whether Microsoft Defender for Endpoint (MDE) is correctly onboarded and healthy on a Windows device.

Designed to be used as **Proactive Remediation** detection script.

---

## Overview

The script checks the following MDE components and reports a structured, single-line output that Intune captures as detection result:

| Check | Source | Description |
|---|---|---|
| StatusKey | Registry | MDE status registry key presence |
| SenseService | SCM | Sense service state |
| Onboarding | Registry | OnboardingState value |
| OrgId | Registry | Tenant OrgId populated |
| Health | Registry | Sensor health state |
| LastSeen | Registry | Last successful MDE cloud connection |
| LastSeenAgeHours | Calculated | Hours since last connection |
| AVEnabled | WMI | Microsoft Defender Antivirus active |
| RTP | WMI | Real-time protection enabled |
| AMRunningMode | WMI | AV running mode (Normal / Passive) |
| Tamper | WMI | Tamper Protection state |

---

## Output Format

The script produces a **single line** on stdout, structured as:

```
RESULT=<COMPLIANT|NONCOMPLIANT> | [SEV]Name=Value | [SEV]Name=Value | ...
```

Each part uses one of three severity prefixes:

| Prefix | Meaning |
|---|---|
| `[OK]` | Check passed |
| `[WARN]` | Degraded or uncertain state; does not trigger NONCOMPLIANT |
| `[ERR]` | Critical failure; triggers NONCOMPLIANT and exit code 1 |

### Example – healthy device

```
RESULT=COMPLIANT | [OK]StatusKey=Present | [OK]SenseService=Running | [OK]Onboarding=OK | [OK]OrgId=Present | [OK]Health=Healthy | [OK]LastSeen=2025-05-17 08:32:11 | [OK]LastSeenAgeHours=4.2 | [OK]AVEnabled=True | [OK]RTP=True | [OK]AMRunningMode=Normal | [OK]Tamper=Enabled
```

### Example – not onboarded

```
RESULT=NONCOMPLIANT | [ERR]StatusKey=Missing | [ERR]SenseService=Missing | [ERR]Onboarding=Unknown | [WARN]HintOnboarding=StateMissing | [ERR]OrgId=Missing | [WARN]HintOrgId=OnboardingIncompleteOrRegistrationIssue | ...
```

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | All ERR-level checks passed → Intune marks device **Compliant** |
| `1` | One or more ERR-level checks failed → Intune marks device **Non-compliant** |

WARN-level findings are informational only and do not affect the exit code.

---

## Checks Detail

### 1. StatusKey
Reads `HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status`.  
If missing, the MDE sensor components are not present or onboarding never started.

### 2. SenseService
Checks the `Sense` Windows service via SCM.  
- `Running` → OK  
- Any other state (e.g. `Stopped`, `StartPending`) → ERR + `HintSense=ServiceNotRunning`  
- Service missing entirely → ERR (unsupported OS or onboarding package not applied)

### 3. Onboarding
Reads `OnboardingState` from the MDE status registry key.

| Value | Meaning | Severity |
|---|---|---|
| `1` | Onboarded | OK |
| `0` | Offboarded | ERR |
| `null` / missing | State not populated | ERR |
| other | Unexpected / partial | ERR |

### 4. OrgId
Checks that `OrgId` is populated in the MDE registry key.  
A missing OrgId after successful onboarding indicates a sensor registration problem.

### 5. Health (HealthState)
Reads the `HealthState` value from the MDE registry key.

| Value | Label | Severity |
|---|---|---|
| `0` | Healthy | OK |
| `1` | NoData | ERR |
| `2` | Pending | ERR |
| `3` | ImpairedCommunications | ERR |
| null | Unknown | WARN |
| other | UnexpectedHealthState | WARN |

**HealthState=3 (ImpairedCommunications)** typically indicates network, proxy, or TLS inspection issues blocking MDE telemetry URLs.

### 6. LastSeen / LastSeenAgeHours
Reads `LastConnected` (Windows FILETIME format) and converts to a human-readable local timestamp.  
Additionally calculates age in hours. Devices not seen for more than **24 hours** generate a WARN.

### 7. AVEnabled / RTP
Read from `Get-MpComputerStatus`.  
Both `False` states generate WARN (not ERR) — MDE EDR can function without Defender AV being primary, e.g. when a third-party AV is installed and Defender runs in passive mode.

### 8. AMRunningMode
Passive mode is flagged as WARN. This is expected when a third-party AV is active but should be noted for compliance visibility.

### 9. Tamper Protection
Read from `Get-MpComputerStatus.IsTamperProtected`.  
Disabled tamper protection generates WARN — it does not block onboarding but reduces local protection resilience against tampering with MDE components.

---

## Hint Codes

Hint entries (`[WARN]HintXxx=...`) provide machine-readable remediation context alongside the failed check. They always carry WARN severity and never affect compliance result independently.

| Hint Code | Associated Check | Suggested Action |
|---|---|---|
| `ServiceNotRunning` | SenseService | Check service status and event log: `Microsoft-Windows-SENSE` |
| `DeviceOffboarded` | Onboarding | Re-apply MDE onboarding policy in Intune |
| `StateMissing` | Onboarding | Verify EDR onboarding policy assignment and device sync |
| `PolicyOrRegistrationIssue` | Onboarding | Check Intune policy delivery and MDE portal registration |
| `OnboardingIncompleteOrRegistrationIssue` | OrgId | Re-check onboarding package and tenant binding |
| `OnboardedButNoSensorHealthOrTelemetryDelay` | Health | Wait for telemetry initialization; re-check after 30–60 min |
| `CheckTelemetryConnectivityProxy` | Health | Verify access to MDE service URLs; check proxy/TLS inspection |
| `OnboardingNotFullyInitialized` | Health | Wait for onboarding to complete; check Sense event log |
| `CheckNetworkProxyOrTLSInspection` | Health | ImpairedCommunications — review network path to MDE endpoints |
| `UnexpectedHealthState` | Health | Run `mdatp health` and review MDE diagnostics |
| `OlderThan24Hours` | LastSeen | Device may be offline, sleeping, or connectivity is degraded |
| `NoSuccessfulConnectionRecorded` | LastSeen | Onboarding may be incomplete or device never reached MDE cloud |
| `DefenderAVNotPrimary` | AVEnabled | Informational — third-party AV may be active |
| `RealTimeProtectionDisabled` | RTP | Review AV policy or passive mode configuration |
| `PassiveMode` | AMRunningMode | Expected with third-party AV; verify intentional |
| `TamperProtectionDisabled` | Tamper | Enable via Intune Security Baseline or MDE portal |
| `GetMpComputerStatusUnavailable` | DefenderStatus | Defender WMI provider unavailable; verify AV components |

---

## Deployment – Intune

### As a Proactive Remediation

1. Go to **Devices → Scripts and remediations**.
2. Upload `MDE-Readiness-Detection.ps1` as the **detection script**.
3. Optionally pair with a remediation script (e.g. restart Sense service).
4. Set schedule (e.g. every 1 hour).

> **Note:** The script must run in **System context** to access the MDE registry key and WMI providers.

---

## Requirements

| Requirement | Detail |
|---|---|
| OS | Windows 10 1903+ / Windows 11 / Windows Server 2019+ |
| PowerShell | 5.1 or later |
| Context | SYSTEM (required for registry and WMI access) |
| MDE | Microsoft Defender for Endpoint onboarding via Intune EDR policy |

---

## Output Length

Intune detection script output is capped at **2048 characters**. On a fully healthy device the output is well within this limit (~350 characters). On a device with multiple failures and hints, output may approach the limit. If truncation is a concern, consider filtering output to non-OK parts only.

---

## License

MIT
