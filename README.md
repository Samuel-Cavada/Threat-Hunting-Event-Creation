# 🛡️ Threat Hunt Event: TOR Usage

## 🧠 Executive Summary

**Objective:**  
Detect and confirm unauthorized installation or use of the TOR browser by an endpoint user in order to bypass corporate security policies.

**Scenario Overview:**  
Suspicious encrypted network activity and anonymous reports suggest potential TOR usage. This hunt aims to identify file, process, and network evidence related to TOR execution on a managed endpoint.

---

## 🔍 Hunt Metadata

| Field                | Details                                  |
|---------------------|------------------------------------------|
| **Date Performed**   | `YYYY-MM-DD`                             |
| **VM Hostname**      | `REDACTED`                               |
| **User Account**     | `REDACTED`                               |
| **Tools Used**       | Microsoft Defender for Endpoint, KQL     |

---

## 🔐 Threat Overview: TOR Browser Activity

### Indicators of Compromise (IoCs)
| Indicator Type     | Value / Notes                             |
|--------------------|-------------------------------------------|
| File Executed       | `tor.exe`, `firefox.exe`                 |
| Network Port        | `9050`, `9001`, `9030`                   |
| Known IP Addresses  | Verified TOR exit nodes (see references) |

---

## 🧪 Data Sources (Tables Used)

- `DeviceFileEvents`  
- `DeviceProcessEvents`  
- `DeviceNetworkEvents`  
- `DeviceInfo`

---

## 🔍 Related Queries

### TOR Binary Detection
```kql
DeviceFileEvents
| where FileName has_any ("tor.exe", "firefox.exe")
```

### TOR Process Execution
```kql
DeviceProcessEvents
| where FileName in ("tor.exe", "firefox.exe")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine
```

### Network Traffic to TOR Ports
```kql
DeviceNetworkEvents
| where RemotePort in (9001, 9030, 9050)
| project Timestamp, DeviceName, RemoteIP, RemotePort
```

---

## 🗂️ Steps Taken by Threat Actor (Recreated)

1. Downloaded TOR browser installer to local machine  
2. Executed `tor.exe` from `Downloads` folder  
3. Connected to known TOR port 9050  
4. Maintained outbound TOR network traffic for 10–15 minutes  

---

## ⏱️ Timeline of Events

| Timestamp (UTC)       | Event Type     | Description |
|------------------------|----------------|-------------|
| `YYYY-MM-DD HH:MM:SS`  | File Created   | `tor.exe` added to `Downloads` |
| `YYYY-MM-DD HH:MM:SS`  | Process Start  | TOR process execution initiated |
| `YYYY-MM-DD HH:MM:SS`  | Network Event  | Connection to TOR entry node on port 9050 |

---

## ✅ Conclusion

TOR usage was **confirmed** on the analyzed endpoint. Logs showed execution of `tor.exe` and verified network traffic to TOR nodes.

---

## 🚨 Response

- Device was isolated using Microsoft Defender for Endpoint  
- Evidence logs were archived for review  
- Relevant team notified for policy review and user follow-up  
- No persistent malware or lateral movement observed

---

## 🔄 Recommendations

- Implement application allow-listing  
- Monitor `DeviceNetworkEvents` for TOR port activity  
- Block known TOR IP ranges at the firewall  
- Conduct user awareness training on acceptable internet usage

---

## 📎 References

- [TOR Exit Node List](https://check.torproject.org/torbulkexitlist)
- [MDE: DeviceProcessEvents Table](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-deviceprocessevents-table)
- [MITRE ATT&CK: T1090.003 – Multi-hop Proxy (TOR)](https://attack.mitre.org/techniques/T1090/003)

---

**Status:** ✅ Hunt Completed  
**Next Steps:** Begin formal reporting and documentation
