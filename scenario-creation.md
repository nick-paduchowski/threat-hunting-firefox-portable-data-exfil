# ⚠️ Threat Event: Suspicious Firefox Portable Usage for Data Exfiltration

## Scenario Summary:
An internal user downloaded **Firefox Portable** and used it to **access unauthorized cloud storage services** (like Mega.nz or Dropbox), bypassing company proxies or firewall inspection. A **sensitive internal document** was prepared, zipped, and potentially uploaded via the browser.

---

## 🧑‍💻 Steps the “Bad Actor” Took to Create Logs and IoCs:

1. **Download Firefox Portable**:
   - URL: https://portableapps.com/apps/internet/firefox_portable

2. **Extract Firefox Portable**:
   - Run the downloaded installer: `FirefoxPortable_x.x_English.paf.exe`
   - Extract to `C:\Users\<username>\Desktop\FirefoxPortable`

3. **Launch Firefox Portable**:
   - Execute `FirefoxPortable.exe`

4. **Browse to Mega.nz or Dropbox**:
   - Open: https://mega.nz or https://www.dropbox.com

5. **Create a fake confidential document**:
   - File: `confidential-q3-plans.docx` with placeholder sensitive content.

6. **Compress the document**:
   - File: `confidential-q3-plans.zip` using built-in Windows compression or 7-Zip.

7. **Upload via Firefox Portable**

8. **Delete local copies** of both the zip and the original document.

---

## 📊 Tables Used to Detect IoCs:

### DeviceFileEvents
- **Info**: [DeviceFileEvents docs](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table)
- **Purpose**: Detect download and creation of Firefox Portable files and sensitive docs.

### DeviceProcessEvents
- **Info**: [DeviceProcessEvents docs](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table)
- **Purpose**: Detect running of portable Firefox process, including from unusual locations.

### DeviceNetworkEvents
- **Info**: [DeviceNetworkEvents docs](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table)
- **Purpose**: Detect Firefox making connections to suspicious domains (mega.nz, etc.)

---

## 🔍 Related Queries:

```kusto
// Detect the Firefox Portable installer being downloaded
DeviceFileEvents
| where FileName startswith "FirefoxPortable"
| project TimeGenerated, DeviceName, FileName, FolderPath, InitiatingProcessFileName

// Firefox Portable process executed
DeviceProcessEvents
| where ProcessCommandLine has "FirefoxPortable.exe"
| project TimeGenerated, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine

// Suspicious Firefox browsing to exfil domains
DeviceNetworkEvents
| where InitiatingProcessFileName == "FirefoxPortable.exe"
| where RemoteUrl has_any ("mega.nz", "dropbox.com", "anonfiles.com", "wetransfer.com")
| project TimeGenerated, DeviceName, RemoteUrl, RemotePort, InitiatingProcessAccountName

// Sensitive file created or accessed
DeviceFileEvents
| where FileName has "confidential-q3-plans"
| project TimeGenerated, ActionType, FileName, FolderPath, DeviceName

// ZIP archive created
DeviceFileEvents
| where FileName endswith ".zip"
| where FolderPath contains "Desktop"
| project TimeGenerated, ActionType, FileName, FolderPath, InitiatingProcessAccountName

// File deletion (covering tracks)
DeviceFileEvents
| where ActionType == "FileDeleted"
| where FileName has_any ("confidential-q3-plans", ".zip")
| project TimeGenerated, FileName, FolderPath, DeviceName, InitiatingProcessAccountName

✍️ Created By:

Author Name: Nicholas Paduchowski

Author Contact: https://www.linkedin.com/in/nick-paduchowski-111129203/

Date: September 16, 2025
