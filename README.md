# Threat Hunt Report — Azuki Import/Export Espionage Case
### Cyber Range Incident Investigation | November 2025

---

## Incident Brief

### Organisation

<img width="597" height="902" alt="image" src="https://github.com/user-attachments/assets/5c1ac1d3-0a5e-4e13-91bd-3831aacbdced" />

Azuki Import / Export Trading Co.  
23 employees | Shipping logistics (Japan & Southeast Asia)

### Situation
A competitor undercut Azuki’s 6-year shipping contract by exactly 3%.  
Soon after, **internal supplier contracts and pricing documents appeared on underground forums**.

### Compromised System
- Hostname: AZUKI-SL  
- Role: IT Administrator Workstation  

### Evidence Available
- Microsoft Defender for Endpoint telemetry

---

## Investigation Objectives

- Identify initial access method  
- Identify compromised account(s)  
- Determine what data was stolen  
- Identify exfiltration method  
- Confirm persistence mechanisms  

---

## IOC Summary

| Indicator | Value |
|-----------|------|
| Host | AZUKI-SL |
| Compromised Account | Administrator |
| Access Vector | RDP |
| Persistence | Registry Run Key |
| Exfiltration | HTTPS outbound |
| Impact | Confidential data leak |
| Threat Type | Corporate espionage |

---

## Investigation Queries

### Initial Access Detection

```kql
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where FileName == "mstsc.exe"
| or ProcessCommandLine has "3389"

Finding:
RDP activity detected from an external location using Administrator credentials outside business hours.

Malicious Execution
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where InitiatingProcessAccountName == "Administrator"


Finding:
Unrecognized executables launched via cmd.exe and powershell.exe.

Persistence Validation
DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where ActionType == "RegistryValueSet"


Finding:
Registry Run keys modified to allow persistence after reboot.

Data Exfiltration
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where RemotePort in (443, 8080)


Finding:
Outbound HTTPS transfers exceeding baseline volume.

Timeline (UTC)
Time	Event
2025-11-19 22:41	RDP login as Administrator
2025-11-19 23:05	Suspicious PowerShell usage
2025-11-20 01:30	Large outbound transfer
2025-11-20 04:05	Attacker activity ceased


MITRE ATT&CK Mapping
Tactic	Technique
Initial Access	T1110 – Brute Force
Execution	T1059 – PowerShell
Persistence	T1547 – Registry Run
Exfiltration	T1041 – C2 Channel
What Happened

An external attacker accessed AZUKI-SL via exposed RDP using Administrator credentials.
They executed malicious binaries, installed persistence, and navigated internal systems.
Sensitive supply contracts and pricing documentation were compressed and exfiltrated.

The stolen documents were later observed on underground forums.

Impact Assessment
Business Impact

Contract loss

Pricing strategy exposed

Commercial intelligence compromise

Risk Level

HIGH

Business confidential data was leaked externally.

Root Cause Analysis
Category	Root
Access Control	No MFA on RDP
Exposure	Public RDP
Credential Hygiene	Admin reuse
Monitoring	No anomaly alert
Network	Unrestricted egress
Recommendations
Immediate

Disable external RDP

Reset Admin credentials

Isolate AZUKI-SL

Reimage the device

Short Term

Enforce MFA

Enable RDP alerts

Lock down admin privileges

Reduce outbound access

Long Term

SIEM deployment

Zero Trust architecture

Network segmentation

EDR policy hardening

Detection Improvements
Category	Improvement
Process Monitoring	Alert on Admin powershell
Network	Monitor abnormal HTTPS
Persistence	Registry alerts
Login	Geo anomaly detection
Final Verdict

This was a deliberate cyber-espionage incident, not user error or accidental exposure.

The attacker:

Exploited exposed access

Stole high-value documents

Enabled persistence

Exfiltrated data

Left without triggering alarms

Incident Status

✅ Closed
✅ Management notified
✅ Forensics preserved
✅ Remediation underway

Author

Pedro Fernandes Parreira
Cyber Threat Hunter / SOC Analyst Portfolio
