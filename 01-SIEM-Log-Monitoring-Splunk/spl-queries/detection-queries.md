# Detection Queries – Lab 01 (Splunk SIEM)

## 1) Authentication Timeline View (Target Account: Yazan)
**Purpose:** Reconstruct the exact sequence of failed → successful authentication events for the targeted account during the brute-force window.

index=wineventlog (EventCode=4624 OR EventCode=4625) Account_Name=Yazan
| table _time EventCode Source_Network_Address Logon_Type
| sort _time

## 2) Authentication Outcome Labeling (Failed vs Success)

**Purpose:** Tag authentication events as failed or success to support quick triage and timeline readability.

index=wineventlog (EventCode=4624 OR EventCode=4625)
| eval outcome=if(EventCode=4625,"failed","success")
| table _time Account_Name Source_Network_Address EventCode outcome
| sort _time
ط

## 3) Brute Force Correlation (5 Failures + 1 Success in 5 Minutes)

**Purpose:** Detect likely brute-force compromise patterns by correlating failed attempts with a subsequent success in a short time window.

index=wineventlog (EventCode=4624 OR EventCode=4625)
| bucket span=5m _time
| stats 
    count(eval(EventCode=4625)) as failed_count,
    count(eval(EventCode=4624)) as success_count
    by Account_Name, Source_Network_Address, _time
| where failed_count >= 5 AND success_count >= 1


## 4) PowerShell Execution Visibility (Sysmon EID 1)

**Purpose:** Provide full visibility into PowerShell executions (baseline vs suspicious) using Sysmon process creation telemetry.

index=wineventlog source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
(Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
| table _time User Image ParentImage CommandLine
| sort _time


## 5) PowerShell Suspicious Indicator Filtering (Encoded / DownloadString / IEX)

**Purpose:** Narrow hunting scope by filtering PowerShell command-lines for common misuse indicators.

index=wineventlog source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
(CommandLine="*DownloadString*" OR CommandLine="*IEX*" OR CommandLine="*-EncodedCommand*")
| table _time User ParentImage CommandLine


## 6) PowerShell Misuse Detection Rule (Correlation / Alert Query)

**Purpose:** Detection logic used for scheduled alerting; flags PowerShell executions with high-risk indicators and aggregates evidence by host.

index=wineventlog source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
(Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
| eval suspicious=if(match(lower(CommandLine),"(-encodedcommand|downloadstring|iex)"),"yes","no")
| where suspicious="yes"
| stats count values(CommandLine) as CommandLine values(User) as User values(ParentImage) as ParentImage by ComputerName
