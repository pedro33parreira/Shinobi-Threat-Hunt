# 🕵️ Threat Hunt Report — Azuki Import/Export Espionage Case
## Cyber Range Incident Investigation | November 2025

---

# 📌 Executive Summary

This investigation simulated a real-world corporate espionage incident involving the compromise of a logistics company workstation through exposed Remote Desktop Protocol (RDP) access.

The attacker successfully gained unauthorized access to the IT administrator workstation `AZUKI-SL`, established persistence, executed PowerShell-based activity, and exfiltrated sensitive supplier contracts and pricing documentation over encrypted outbound channels.

The incident demonstrated multiple stages of the cyber kill chain including:

- initial access
- execution
- persistence
- discovery
- data exfiltration

Using Microsoft Defender for Endpoint telemetry and Kusto Query Language (KQL), the investigation reconstructed attacker activity, identified indicators of compromise (IOCs), and determined the root causes that enabled the breach.

---

# 🏢 Organisation Overview

<p align="center">
  <img width="350" alt="Azuki Import Export" src="https://github.com/user-attachments/assets/5c1ac1d3-0a5e-4e13-91bd-3831aacbdced">
</p>

| Attribute | Details |
|---|---|
| Company | Azuki Import / Export Trading Co. |
| Industry | Shipping Logistics & International Trade |
| Employees | 23 |
| Region | Japan & Southeast Asia |

---

# ⚠️ Incident Background

Azuki Import / Export Trading Co. unexpectedly lost a long-standing six-year shipping contract after a competitor undercut their pricing strategy by exactly **3%**.

Shortly afterward, confidential supplier agreements and internal pricing documents were discovered circulating on underground forums.

The precision of the competitor’s pricing strongly suggested prior access to confidential commercial intelligence.

An internal investigation was initiated to determine:

- how the compromise occurred
- which systems were affected
- what information was stolen
- whether persistence mechanisms remained active

---

# 🎯 Investigation Objectives

The investigation aimed to:

- Identify the initial access vector
- Determine compromised accounts
- Identify attacker activity
- Confirm persistence mechanisms
- Determine the exfiltration method
- Assess business impact
- Recommend containment and remediation actions

---

# 💻 Compromised Asset

| Attribute | Value |
|---|---|
| Hostname | `AZUKI-SL` |
| Asset Role | IT Administrator Workstation |
| Operating System | Windows |
| Telemetry Source | Microsoft Defender for Endpoint |

---

# 🚨 IOC Summary

| Indicator | Value |
|---|---|
| Host | `AZUKI-SL` |
| Compromised Account | `Administrator` |
| Access Vector | RDP |
| Persistence Mechanism | Registry Run Key |
| Exfiltration Method | HTTPS Outbound Traffic |
| Threat Classification | Corporate Espionage |
| Severity | 🔴 HIGH |

---

# 🧪 Investigation Methodology

The investigation leveraged:

- Microsoft Defender for Endpoint telemetry
- KQL-based threat hunting
- process analysis
- registry analysis
- network telemetry correlation
- authentication investigation

### Telemetry Sources

- `DeviceProcessEvents`
- `DeviceNetworkEvents`
- `DeviceRegistryEvents`
- `DeviceLogonEvents`

---

# 🔍 Investigation Findings

---

# 1️⃣ Initial Access Detection

## KQL Query

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where FileName == "mstsc.exe"
    or ProcessCommandLine has "3389"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
```

## Findings

Analysis revealed successful RDP-related activity associated with the `Administrator` account originating outside normal business hours.

### Indicators Observed

- Remote Desktop process execution
- RDP port usage (`3389`)
- administrative authentication activity
- anomalous login timing

### Assessment

The attacker likely leveraged exposed RDP services combined with compromised or weak administrative credentials to gain initial access.

---

# 2️⃣ Malicious Execution Activity

## KQL Query

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where InitiatingProcessAccountName == "Administrator"
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessParentFileName
| order by Timestamp desc
```

## Findings

Multiple suspicious processes were executed using:

- `cmd.exe`
- `powershell.exe`

### Indicators Observed

- abnormal PowerShell execution
- unrecognized binaries
- suspicious command-line activity
- administrative process chaining

### Assessment

The attacker executed post-compromise tooling to:

- establish control
- perform reconnaissance
- prepare data collection and exfiltration activities

---

# 3️⃣ Persistence Mechanism Identification

## KQL Query

```kql
DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where ActionType == "RegistryValueSet"
| project Timestamp, RegistryKey, RegistryValueName, RegistryValueData
| order by Timestamp desc
```

## Findings

Registry Run keys were modified to ensure malicious code execution after system reboot.

### Persistence Technique

- Registry Run Keys
- Auto-start execution

### Assessment

The attacker implemented persistence to maintain long-term access and survive endpoint restarts.

---

# 4️⃣ Data Exfiltration Analysis

## KQL Query

```kql
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where RemotePort in (443,8080)
| project Timestamp, RemoteIP, RemotePort, InitiatingProcessFileName, SentBytes
| order by Timestamp desc
```

## Findings

Significant outbound HTTPS traffic was observed outside normal operational baselines.

### Indicators Observed

- elevated outbound transfer volume
- encrypted communications
- external network destinations
- abnormal traffic timing

### Assessment

Sensitive internal documents were likely compressed and exfiltrated through encrypted outbound HTTPS channels to attacker-controlled infrastructure.

---

# 🕒 Attack Timeline (UTC)

| Time | Event |
|---|---|
| 2025-11-19 22:41 | RDP login using Administrator credentials |
| 2025-11-19 23:05 | Suspicious PowerShell activity initiated |
| 2025-11-20 00:10 | Registry persistence modifications observed |
| 2025-11-20 01:30 | Large outbound HTTPS transfers detected |
| 2025-11-20 04:05 | Malicious activity ceased |

---

# ⚔️ MITRE ATT&CK Mapping

| Tactic | Technique |
|---|---|
| Initial Access | T1133 — External Remote Services |
| Credential Access | T1110 — Brute Force |
| Execution | T1059.001 — PowerShell |
| Persistence | T1547.001 — Registry Run Keys |
| Discovery | T1082 — System Information Discovery |
| Exfiltration | T1041 — Exfiltration Over C2 Channel |

---

# 🧠 What Happened

The investigation concluded that an external threat actor gained unauthorized access to the workstation `AZUKI-SL` via exposed Remote Desktop Protocol (RDP) services using compromised administrative credentials.

Following successful access, the attacker:

- executed malicious PowerShell commands
- launched unauthorized binaries
- established registry-based persistence
- accessed confidential supplier and pricing documentation
- exfiltrated sensitive business data through encrypted outbound HTTPS communications

The compromised documents were later identified on underground forums, confirming successful data theft.

---

# 📉 Impact Assessment

## Business Impact

- Loss of strategic commercial advantage
- Exposure of confidential pricing structures
- Supplier contract compromise
- Competitive intelligence theft
- Reputational risk

---

## Security Impact

| Category | Assessment |
|---|---|
| Confidentiality | 🔴 Severely Impacted |
| Integrity | 🟠 Potentially Impacted |
| Availability | 🟢 Not Significantly Affected |

---

# 🔴 Overall Risk Level

# HIGH

Sensitive business intelligence and proprietary commercial data were successfully exfiltrated outside the organization.

---

# 🔬 Root Cause Analysis

| Security Area | Root Cause |
|---|---|
| Access Control | No MFA enforced on RDP |
| Exposure Management | Public-facing RDP exposure |
| Credential Hygiene | Administrative credential reuse |
| Monitoring | No anomaly-based alerting |
| Network Security | Unrestricted outbound traffic |
| Endpoint Security | Insufficient PowerShell monitoring |

---

# 🛡️ Recommendations

---

# Immediate Actions

- Disable external RDP exposure
- Reset all privileged credentials
- Isolate `AZUKI-SL`
- Preserve forensic evidence
- Reimage compromised systems

---

# Short-Term Improvements

- Enforce MFA for remote access
- Restrict administrative privileges
- Enable RDP anomaly alerting
- Harden PowerShell policies
- Implement outbound traffic restrictions

---

# Long-Term Security Improvements

- Deploy centralized SIEM monitoring
- Implement Zero Trust architecture
- Segment critical business systems
- Harden EDR policies
- Implement privileged access management (PAM)
- Deploy centralized logging and alert correlation

---

# 🚨 Detection Engineering Improvements

| Category | Recommendation |
|---|---|
| Process Monitoring | Alert on administrative PowerShell execution |
| Authentication | Detect anomalous RDP logons |
| Network Monitoring | Identify abnormal HTTPS transfers |
| Persistence Detection | Monitor registry auto-run modifications |
| Threat Hunting | Correlate administrative process chains |

---

# 🧠 Lessons Learned

This incident highlighted several important cybersecurity lessons:

- exposed RDP remains a high-risk attack vector
- administrative credential hygiene is critical
- PowerShell abuse remains common in post-exploitation activity
- outbound encrypted traffic can conceal data exfiltration
- persistence mechanisms often leverage simple registry modifications
- lack of anomaly detection significantly delays incident discovery

The investigation also demonstrated the importance of:

- endpoint telemetry
- detection engineering
- authentication monitoring
- threat hunting workflows
- layered security controls

---

# ✅ Final Verdict

This investigation determined that the incident was a deliberate cyber-espionage operation rather than accidental exposure or insider misuse.

The attacker successfully:

- exploited exposed remote access
- leveraged privileged credentials
- established persistence
- exfiltrated sensitive commercial intelligence
- avoided detection during active operations

---

# 📌 Incident Status

| Status | Result |
|---|---|
| Investigation | ✅ Completed |
| Management Notification | ✅ Completed |
| Forensic Preservation | ✅ Completed |
| Containment Actions | ✅ Initiated |
| Remediation | ✅ Underway |

---

# 🚀 Skills Demonstrated

- Threat Hunting
- Microsoft Defender for Endpoint
- KQL Querying
- Endpoint Investigation
- Incident Response
- Network Traffic Analysis
- PowerShell Detection
- Persistence Analysis
- MITRE ATT&CK Mapping
- SOC Operations
- Detection Engineering
- Root Cause Analysis

---

# 👨‍💻 Author

## Pedro Fernandes Parreira

Cyber Threat Hunter | SOC Analyst | Detection Engineering | Vulnerability Management

### 🔗 LinkedIn
https://www.linkedin.com/in/pedro-parreira-85902a5a/

### 🔗 GitHub
https://github.com/pedro33parreira
Cyber Threat Hunter / SOC Analyst Portfolio
