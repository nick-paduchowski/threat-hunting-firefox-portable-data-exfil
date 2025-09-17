# Threat Hunt Report: Firefox Portable Data Exfiltration
- [Scenario Creation](https://github.com/nick-paduchowski/threat-hunting-firefox-portable-data-exfil/blob/main/scenario-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Firefox Portable Browser
- PowerShell Compress-Archive

##  Scenario

Management is worried an employee who recently met with competitors may have shared company files. There are reports the employee used an uncommon browser (FireFox Portable) to hide activity. The goal is to see if the portable browser was used to copy or upload sensitive data — and, if so, contain the situation and tell management.

### High-Level Firefox Portable IoC Discovery Plan

- **Check `DeviceFileEvents`** for any Firefox, or Zip file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of connection to known file storage sites such as Dropbox or Filebin.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table


Searched for any file that had the string of 'firefox' in it and discovered what looks like the user "nicklabuser" downloaded an executable called FirefoxPortable_143.0_English.paf.exe, ran the executable which resulted in the creation of the FirefoxPortable.exe
 file on the desktop at `2025-09-17T08:25:01.5662875Z`. These events began at `2025-09-17T08:23:06.5248324Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "nick-test-vm-md"
| where InitiatingProcessAccountName == "nicklabuser"
| where FileName contains "Firefox"
| sort by TimeGenerated desc
```

Searched for any file that had the file type of Zip and discovered what looks like the user "nicklabuser" created a Zip called confidential_q3_report.zip. These events began at `2025-09-14T14:24:48.8426211Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "nick-test-vm-md"
| where InitiatingProcessAccountName == "nicklabuser"
| where tostring(parse_json(AdditionalFields.FileType)) == "Zip"
| sort by TimeGenerated desc
```
<img width="1212" alt="image" src="https://github.com/nick-paduchowski/threat-hunting-firefox-portable-data-exfil/blob/4a6b42e56c85b96915fef9e52499707a2bfeb7e9/threat-hunt-1.png">

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "firefox". Based on the logs returned, at `2025-09-17T08:23:06.5248324Z`, a user on the "nick-test-vm-md" device ran the file `FirefoxPortable_143.0_English.paf.exe /S` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "nick-test-vm-md"
| where AccountName != "system"
| where ProcessCommandLine contains "firefox"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
| sort by TimeGenerated desc

```
<img width="1212" alt="image" src="https://github.com/nick-paduchowski/threat-hunting-firefox-portable-data-exfil/blob/9a2c31d85988571a2af7ab07dbc368efa520e9ed/threat-hunt-2.png">

---

### 3. Searched the `DeviceProcessEvents` Table for Firefox Portable Execution

Searched for any indication that user "nicklabuser" actually opened the Firefox portable There was evidence that they did open it at `2025-09-17T08:25:40.4004815Z`. There were several other instances of `firefox.exe` as well as `firefox.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "nick-test-vm-md"
| where AccountName != "system"
| where ProcessCommandLine contains "firefox"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
| sort by TimeGenerated desc
```
<img width="1212" alt="image" src="https://github.com/nick-paduchowski/threat-hunting-firefox-portable-data-exfil/blob/9a2c31d85988571a2af7ab07dbc368efa520e9ed/threat-hunt-2.png">

---

### 4. Searched the `DeviceNetworkEvents` Table for File Upload Service Connections

Searched for any indication the Firefox Portable browser was used to establish a connection to file upload sites that could be used to exfiltrate the data. At `2025-09-17T08:28:00.7515181Z`, a user on the "nick-test-vm-md" device successfully established a connection to the remote IP address `162.125.248.18` at RemoteURL `dropbox.com` on port `443`. The connection was initiated by the process `firefox.exe`, located in the folder `c:\users\nicklabuser\downloads\firefoxportable\app\firefox64\firefox.exe`. There were a couple of other connections to sites over port `443`. The user also established a connection at `2025-09-17T08:31:08.4489788Z` to Remote IP `88.99.137.18` at Remote URL `filebin.net` on port `443` using the same process as above.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "nick-test-vm-md"
| where RemoteUrl has_any ("filebin", "dropbox", "mega.nz")
| project TimeGenerated, DeviceName, Account = InitiatingProcessAccountName, Browser = InitiatingProcessFileName, RemoteIP, RemoteUrl
| sort by TimeGenerated desc
```
<img width="1212" alt="image" src="https://github.com/nick-paduchowski/threat-hunting-firefox-portable-data-exfil/blob/697622dc49005346af2cc3f330c865ecf44cc916/threat-hunt-3.png">

---

## Chronological Event Timeline 

### 1. File Creation - Confidential ZIP
- **Timestamp:** `2025-09-14T14:24:48.8426211Z`
- **Event:** The user "nicklabuser" created a file named `confidential_q3_report.zip`.
- **Action:** Archive (Zip) creation detected.
- **File Path:** (recorded in `DeviceFileEvents`)

### 2. Process Execution - Firefox Portable Installer Run
- **Timestamp:** `2025-09-17T08:23:06.5248324Z`
- **Event:** The user "nicklabuser" executed `FirefoxPortable_143.0_English.paf.exe` from the Downloads folder, using a command that triggered a silent installation.
- **Action:** Process creation detected.
- **Command:** `FirefoxPortable_143.0_English.paf.exe /S`
- **File Path:** `C:\Users\nicklabuser\Downloads\FirefoxPortable_143.0_English.paf.exe`

### 3. File Creation - Firefox Portable Extracted/Installed
- **Timestamp:** `2025-09-17T08:25:01.5662875Z`
- **Event:** The Firefox Portable runtime (`FirefoxPortable.exe` / `firefox.exe`) appeared in the user's Downloads/Desktop folder as part of the portable installation/extraction.
- **Action:** File creation detected.
- **File Path:** `C:\Users\nicklabuser\Downloads\FirefoxPortable\App\Firefox64\firefox.exe` (and desktop shortcut created)

### 4. Process Execution - Firefox Portable Launch
- **Timestamp:** `2025-09-17T08:25:40.4004815Z`
- **Event:** The user "nicklabuser" launched the portable Firefox (`firefox.exe`), indicating interactive use of the portable browser.
- **Action:** Process creation detected.
- **Process:** `firefox.exe`
- **File Path:** `c:\users\nicklabuser\downloads\firefoxportable\app\firefox64\firefox.exe`

### 5. Network Connection - Dropbox Upload (Suspected)
- **Timestamp:** `2025-09-17T08:28:00.7515181Z`
- **Event:** A network connection to `162.125.248.18` (RemoteURL: `dropbox.com`) on port `443` was established by the portable Firefox process.
- **Action:** Outbound HTTPS connection detected.
- **Process:** `firefox.exe`
- **File Path:** `c:\users\nicklabuser\downloads\firefoxportable\app\firefox64\firefox.exe`

### 6. Network Connection - Filebin Upload (Suspected)
- **Timestamp:** `2025-09-17T08:31:08.4489788Z`
- **Event:** A network connection to `88.99.137.18` (RemoteURL: `filebin.net`) on port `443` was established by the same portable Firefox process.
- **Action:** Outbound HTTPS connection detected.
- **Process:** `firefox.exe`
- **File Path:** `c:\users\nicklabuser\downloads\firefoxportable\app\firefox64\firefox.exe`

---

## Summary

The timeline shows that a confidential ZIP (`confidential_q3_report.zip`) existed on the user's machine on **2025-09-14**. On **2025-09-17**, the user `nicklabuser` ran a Firefox Portable installer (`FirefoxPortable_143.0_English.paf.exe`) which resulted in portable Firefox files appearing on the system. The portable browser was launched shortly after and established HTTPS connections to cloud/file-sharing services (Dropbox and Filebin) within minutes. 

This sequence — archive creation followed by the use of a portable browser and then outbound connections to file sharing services — is consistent with possible data exfiltration using Firefox Portable. Recommend preserving the endpoint, collecting full logs, and escalating to management if uploads can be confirmed.

---

## Response Taken

Data exfiltration was confirmed on the endpoint `nick-test-vm-md` by the user `nicklabuser`. The device was isolated, and the user's direct manager was notified.

---
