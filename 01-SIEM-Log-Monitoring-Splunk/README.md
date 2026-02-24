# 01 – SIEM Log Monitoring & Threat Detection (Splunk Lab)

##  Overview
This lab simulates a real-world SOC environment using Splunk Enterprise and Sysmon to detect credential-based attacks and PowerShell misuse activity.

The project includes:
- Log ingestion validation
- Brute force attack simulation
- RDP compromise scenario
- PowerShell misuse detection
- Detection engineering and alert configuration
- MITRE ATT&CK mapping

---

## Lab Architecture

- Windows 11 Endpoint (Sysmon enabled)
- Ubuntu Server (Splunk Enterprise – 10GB Dev License)
- Kali Linux (Attacker machine)
- Splunk Universal Forwarder

---

##  Attack Scenarios Simulated

### 1️⃣ Brute Force Attack
- Multiple failed logins (Event ID 4625)
- Successful login (Event ID 4624)
- Privileged session (Event ID 4672)

### 2️⃣ PowerShell Misuse
- Baseline execution
- EncodedCommand execution
- DownloadString + IEX remote script execution
- Post-compromise reconnaissance

---

## Detection Engineering

Detection logic built using:

- Sysmon Event ID 1 (Process Creation)
- Command-line indicator matching
- Correlation logic
- Scheduled Alert configuration

MITRE ATT&CK Techniques:
- T1110 – Brute Force
- T1078 – Valid Accounts
- T1059.001 – PowerShell
- T1027 – Obfuscation
- T1105 – Ingress Tool Transfer

---

##  Skills Demonstrated

- SIEM deployment & configuration
- Log analysis (Windows & Sysmon)
- Attack simulation in lab environment
- Detection rule development
- Alert validation
- SOC documentation methodology

---


---

##  Outcome

This lab demonstrates practical Tier 1–Tier 2 SOC analyst capabilities including:

- Attack simulation in a controlled environment
- Behavioral log analysis
- Correlation-based detection development
- Automated alert monitoring
- Structured incident documentation

The project reflects real-world SOC workflows from initial access detection to post-compromise behavioral analysis.
