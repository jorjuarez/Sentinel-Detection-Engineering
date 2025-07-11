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
| where TimeGenerated between (datetime(2025-06-06T04:49:00Z) .. datetime(2025-06-07T04:38:00Z)) //The times shown are for the integrety of the report, otherwise we would set this line to look data >= ago(24h)
| where (FileName contains "powershell.exe" or FileName contains "pwsh.exe") 
  and (ProcessCommandLine contains "Invoke-WebRequest" or ProcessCommandLine contains "iwr" or ProcessCommandLine contains "wget")
| project TimeGenerated, AccountName, DeviceName, FileName, InitiatingProcessCommandLine, ProcessCommandLine
| sort by TimeGenerated desc

```

**Sentinel Configuration**
In Microsoft Sentinel, this KQL query was used to create a new Scheduled Analytics Rule.

* Run query every: 4 hours
* Lookup data from the last: 24 hours

### 3. Simulating the Attack & Triggering the Alert
To validate the rule, a command was executed on a test virtual machine to simulate an attacker downloading a payload. This command downloads the harmless EICAR test file and then executes it.
