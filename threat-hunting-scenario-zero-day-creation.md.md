# Threat Event (Pwncrypt.ps1 Malware Detection)
**Unauthorized Execution of Pwncrypt.ps1 Malware**

## Steps the "Bad Actor" took Create Logs and IoCs:
1. Downloaded the `Pwncrypt.ps1` Script: The malicious actor downloaded the script from an external source (e.g., GitHub) using PowerShell.

2. Executed the `Pwncrypt.ps1` Script: Bypassed execution policy to run the script via PowerShell.

3. Created Ransomware-related Files: Generated a `_pwncrypt.csv` file, likely containing encrypted data.

4. Delivered Ransom Instructions: Created a decryption instructions file (`__________decryption-instructions.txt`) as part of the ransomware process.

5. Repeated Execution: Continuously executed the script, causing repeated file creation and external communication.

---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used for detecting TOR download and installation, as well as the shopping list creation and deletion. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used to detect the silent installation of TOR as well as the TOR browser and service launching.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table|
| **Purpose**| Used to detect TOR network activity, specifically tor.exe and firefox.exe making connections over ports to be used by TOR (9001, 9030, 9040, 9050, 9051, 9150).|

---

## Related Queries:
```kql
// Detect the download and creation of pwncrypt.ps1
DeviceFileEvents
| where DeviceName == "win10-tleanne"
| where FileName endswith "pwncrypt.ps1"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath
| order by Timestamp desc

// Detect PowerShell execution of pwncrypt.ps1
DeviceProcessEvents
| where DeviceName == "win10-tleanne"
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "pwncrypt.ps1"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
| order by Timestamp desc

// Identify external script downloads via PowerShell
DeviceProcessEvents
| where DeviceName == "win10-tleanne"
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "Invoke-WebRequest"
| where ProcessCommandLine contains "pwncrypt.ps1"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
| order by Timestamp desc

// Detect creation of ransomware output files (_pwncrypt.csv)
DeviceFileEvents
| where DeviceName == "win10-tleanne"
| where FileName endswith "_pwncrypt.csv"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath
| order by Timestamp desc

// Detect creation of decryption instructions
DeviceFileEvents
| where DeviceName == "win10-tleanne"
| where FileName == "__________decryption-instructions.txt"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath
| order by Timestamp desc
```

---

## Created By:
- **Author Name**: Tracey B
- **Author Contact**: https://www.linkedin.com/in/tleanne/
- **Date**: March 11, 2025

## Validated By:
- **Reviewer Name**: 
- **Reviewer Contact**: 
- **Validation Date**: 

---

## Additional Notes:
- **None**

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `March  11, 2025`  | `Tracey B`   
