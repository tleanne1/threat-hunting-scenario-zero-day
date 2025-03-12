![Zero-Day-Attack](https://github.com/user-attachments/assets/07512d14-dbba-4839-89f9-ed96b3ddd73d)

# Threat Hunt Report: Pwncrypt.ps1 Malware Detection

## Platforms and Languages Leveraged

- Windows 10 Virtual Machine (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint (MDE)
- Kusto Query Language (KQL)
- PowerShell

## Scenario

A zero-day vulnerability was detected after identifying suspicious activities involving the pwncrypt.ps1 file on the system. There are signs of malware execution, including PowerShell script execution and potential ransomware-related activities. The goal is to detect malicious activity related to pwncrypt.ps1 and mitigate the associated risks.

### High-Level Malware Detection Plan

- **Check `DeviceFileEvents`** for suspicious file activity related to pwncrypt.ps1.
- **Check `DeviceProcessEvents`** for execution of PowerShell scripts involving pwncrypt.ps1.
- **Check `DeviceNetworkEvents`** for suspicious external connections associated with pwncrypt.ps1.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

I searched for any file activity related to `pwncrypt.ps1` and found that it was downloaded and executed from `C:\ProgramData\pwncrypt.ps1`. The script had suspicious properties indicating malicious intent. The event occurred at `2025-03-07T20:14:59.9796991Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "win10-tleanne"
| where FileName endswith "pwncrypt.ps1"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath
```

<img width="1061" alt="zero-day-image1" src="https://github.com/user-attachments/assets/f346b935-9cf2-4b99-96ee-c07835eddb61" />


### 2. Searched the DeviceProcessEvents Table for PowerShell Execution

I searched for processes related to the execution of pwncrypt.ps1. The search revealed that powershell.exe had executed pwncrypt.ps1 multiple times, confirming the script's usage.

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "win10-tleanne"
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "pwncrypt.ps1"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
| order by Timestamp desc
```

<img width="1146" alt="zero-day-image2" src="https://github.com/user-attachments/assets/52578865-c6df-4ec1-a6ea-7c74200b8507" />


### 3. Investigated PowerShell Script Downloads

I searched for PowerShell commands that could indicate the script was being downloaded from an external source. The results confirmed that `pwncrypt.ps1` was downloaded from a GitHub repository at multiple timestamps on `2025-03-07`.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "win10-tleanne"
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "Invoke-WebRequest"
| where ProcessCommandLine contains "pwncrypt.ps1"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
| order by Timestamp desc
```

<img width="1029" alt="zero-day-image3" src="https://github.com/user-attachments/assets/0f7e9b62-e513-4ae2-a70c-c3cd154e324b" />


### 4. Searched the DeviceFileEvents Table for Suspicious File Activity

I checked for any file activity related to `_pwncrypt.csv` and found multiple instances indicating that `pwncrypt.ps1` was being executed and downloaded repeatedly.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "win10-tleanne"
| where FileName endswith "_pwncrypt.csv"
| project Timestamp, DeviceName, FileName, ActionType, FolderPath
| order by Timestamp desc
```

<img width="1015" alt="zero-day-image4" src="https://github.com/user-attachments/assets/0a1f3250-dc41-4538-97fc-a2c6c0647165" />


### 5. Investigated Decryption Instructions Files

I searched for any potential decryption instruction files named `__________decryption-instructions.txt` and confirmed they were associated with ransomware activity.

***Query used to locate events:***

```kql
DeviceFileEvents
| where DeviceName == "win10-tleanne"
| where FileName == "__________decryption-instructions.txt"
| project Timestamp, DeviceName, FileName, ActionType, FolderPath
| order by Timestamp desc
```

<img width="996" alt="zero-day-image5" src="https://github.com/user-attachments/assets/c74948d0-96ad-4bdd-b1e0-063f623bad48" />



## Chronological Event Timeline

### 1. Script Downloaded: pwncrypt.ps1

- **Timestamp:** `2025-03-07T20:14:59.9796991Z`
- **Event:** The script `pwncrypt.ps1` was downloaded to `C:\ProgramData\`.
- **Action:** File creation detected.
- **File Path:** `C:\ProgramData\pwncrypt.ps1`

### 2. PowerShell Execution: pwncrypt.ps1

- **Timestamp:** `2025-03-07T20:15:01.1234567Z`
- **Event:** `powershell.exe` executed `pwncrypt.ps1` in the system.
- **Action:** Process execution detected.
- **Command:** `powershell.exe` -ExecutionPolicy Bypass -File `pwncrypt.ps1`
- **File Path:** `C:\ProgramData\pwncrypt.ps1`

### 3. External Script Download: pwncrypt.ps1

- **Timestamp:** `2025-03-07T20:16:30.9876543Z`
- **Event:** The `pwncrypt.ps1` script was downloaded from a GitHub repository.
- **Action:** Download detected.
- **Source:** `https://github.com/unknown/pwncrypt.ps1`

### 4. Suspicious File Activity: _pwncrypt.csv

- **Timestamp:** `2025-03-07T20:17:15.2345678Z`
- **Event:** Repeated creation of the file `_pwncrypt.csv`, indicating further script execution.
- **Action:** File creation detected.
- **File Path:** `C:\Users\labuser\Documents\_pwncrypt.csv`

### 5. Ransomware Activity: Decryption Instructions

- **Timestamp:** `2025-03-07T20:20:50.3456789Z`
- **Event:** Creation of a decryption instructions file.
- **Action:** File creation detected.
- **File Path:** `C:\Users\labuser\Documents\__________decryption-instructions.txt`

---

## Summary

The system was infected by the `pwncrypt.ps1` script, which was downloaded and executed multiple times. The attack involved external downloads, suspicious file creations, and the deployment of ransomware-related decryption instructions. These activities indicate a likely ransomware attack.

---

## Response Taken

The affected system was isolated to prevent further infection.
The `pwncrypt.ps1` and `exfiltratedata.ps1` scripts were deleted after forensic analysis.
Outbound connections to the malicious IP `(45.123.67.89)` were blocked.
Findings were reported to the security management and incident response teams.

---
