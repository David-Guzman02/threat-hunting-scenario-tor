<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/David-Guzman02/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md).

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-05-26T04:54:49.8849544Z`. These events began at `2025-05-26T04:39:41.4170503Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "dg-win10"
| where InitiatingProcessAccountName == "dgsec"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-05-26T04:39:41.4170503Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
![image](https://github.com/user-attachments/assets/e17852cb-4a2e-4ec6-925d-9f18b0c33c03)

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.1.exe". Based on the logs returned, at `2025-05-26T04:42:59.054862Z`, an employee on the "dg-win10" device ran the file `tor-browser-windows-x86_64-portable-14.0.1.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "dg-win10"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.2.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
![image](https://github.com/user-attachments/assets/4765a4d5-996c-4548-bec3-0d69b7a16f56)


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee" actually opened the TOR browser. There was evidence that they did open it at `2025-05-26T04:43:37.5235068Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "dg-win10"
| where FileName has_any ("tor.exe", "torbrowser-install-win64-*.exe", "tor-browser-windows-x86_64-portable-*.exe", "firefox.exe", "obfs4proxy.exe", "meek-client.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/ab46e9d1-3a54-490b-9983-03ff2abafa3a)


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-05-26T04:44:25.2192272Z`, an employee on the "dg-win10" device successfully established a connection to the remote IP address `176.198.159.33` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "dg-win10"
| where InitiatingProcessAccountName == "dgsec"
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150","80","443")
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/9924c5d4-e43c-42cc-9a9b-56fd93d020c1)


---

## Chronological Event Timeline 

## 📅 Tor Browser Activity Timeline

---

### 📥 Download & Execution of Tor Installer

**🕒 May 26, 2025 – 12:39:41 AM (UTC-4)**  
- `tor-browser-windows-x86_64-portable-14.5.2.exe` was renamed in the Downloads folder.  
- This likely indicates a completed download or manual/system rename.

**🕒 May 26, 2025 – 12:42:59 AM**  
- User `dgsec` executed the file `tor-browser-windows-x86_64-portable-14.5.2.exe` from `Downloads`.  
- ✅ This confirmed the launch of the Tor Browser's portable installer.  
- **Command:** `tor-browser-windows-x86_64-portable-14.5.2.exe /S`

---

### 📁 Installation Artifacts Appeared

**🕒 May 26, 2025 – 12:43:14 AM**  
- Files such as `tor.exe`, `tor.txt`, and `Torbutton.txt` appeared in the Tor Browser directory.  
- ✅ This indicates the application was successfully decompressed or extracted.

---

### 🧪 Tor Browser Process Activity

**🕒 May 26, 2025 – 12:44:11 AM to 12:45:00 AM**  
- Multiple `firefox.exe` processes were spawned from within the Tor Browser folder.  
- ✅ These processes suggest the browser was actively opened, and tabs or background processes were launched.

---

### 🌐 Network Activity Suggesting Tor Usage

**🕒 May 26, 2025 – 12:44:25 AM**  
- `tor.exe` established an outbound connection to `116.255.1.163` over **TCP port 9001**, a known Tor relay port.  

**🔗 Other Notable Connections:**  
- `tor.exe` also connected to:
  - `135.148.100.233` over port **443**
  - `51.83.132.103` over port **9001**
- `firefox.exe` initiated a **loopback connection to 127.0.0.1:9150**, commonly used for Tor SOCKS proxy traffic.

---

### 📄 User File Creation

**🕒 May 26, 2025 – 12:54:49 AM**  
- User `dgsec` created a file named `tor-shopping-list.txt` on the desktop.  
- 📌 This may indicate they were collecting or organizing sensitive information.

**🕒 May 26, 2025 – 12:54:50 AM**  
- A `.lnk` shortcut to `tor-shopping-list.txt` was created in the AppData Recent Items folder.  
- 📁 This likely resulted from the user opening or pinning the file.

---


## Summary

On May 26, 2025, between 12:39 AM and 12:55 AM (UTC-4), the user dgsec on the device dg-win10 downloaded and executed the Tor Browser portable installer. The file tor-browser-windows-x86_64-portable-14.5.2.exe appeared in the Downloads folder and was launched at 12:42:59 AM. Shortly after execution, multiple Tor-related files—including tor.exe and Torbutton.txt—were extracted to the desktop, indicating the browser had been installed or unpacked.
At approximately 12:44 AM, the user began interacting with the Tor Browser, as evidenced by the creation of multiple firefox.exe processes (used by Tor) and the spawning of tor.exe. Around this same time, the system established several outbound connections to known Tor network relays, including IP addresses 116.255.1.163 and 135.148.100.233 over ports 9001 and 443, confirming that Tor was actively used to anonymize traffic.
Later, at 12:54:49 AM, the user created a file named tor-shopping-list.txt on the desktop, followed immediately by the creation of a shortcut to that file, suggesting it may have been accessed or referenced multiple times. These events collectively confirm that the Tor Browser was not only installed but also used within the session, including active network communication and content generation by the user.

---

## Response Taken

TOR usage was confirmed on the endpoint dg-win10 by the user dgsec. The device was isolated and the user's direct manager was notified.

---
