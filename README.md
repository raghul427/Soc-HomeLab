# Soc-HomeLab
# Enterprise SOC Telemetry & Threat Detection Home Lab

An isolated Security Operations Center (SOC) home lab environment built to simulate real-world enterprise logging, endpoint telemetry pipelines, and adversary behavior detection using Splunk Enterprise and Sysinternals Sysmon.

---

## 📐 Network Architecture & Topology

The lab operates on an isolated VirtualBox NAT Network (`10.0.2.0/24`):

| Node | Role | OS | IP Address | Ingestion / Port |
| :--- | :--- | :--- | :--- | :--- |
| **SIEM Server** | Central Log Indexer & Search Head | Ubuntu Server 22.04 | `10.0.2.10` | Web: `8000/8888`, Splunk TCP: `9997` |
| **Endpoint (Victim)** | Monitored Workstation | Windows 10 | `10.0.2.20` | Sysmon + Splunk Universal Forwarder |
| **Attacker Node** | Adversary Simulation | Kali Linux | `10.0.2.30` | Network scanning, reconnaissance, testing |

---

## ⚙️ Telemetry Pipeline Implementation

### 1. Endpoint Instrumentation (Windows Victim)
* **Sysinternals Sysmon Deployment:** Installed and tuned with a modular configuration to capture high-fidelity host events:
  * Event ID 1: Process Creation (CommandLine, ParentImage, Hashes)
  * Event ID 3: Network Connection detection
  * Event ID 8/10: Process tampering & thread injection
* **Splunk Universal Forwarder:** Configured local inputs (`etc\system\local\inputs.conf`) to monitor security channels:
  * `WinEventLog://Security`
  * `WinEventLog://System`
  * `WinEventLog://Application`
  * `WinEventLog://Microsoft-Windows-Sysmon/Operational`

### 2. SIEM Indexer Configuration (Ubuntu Server)
* Deployed **Splunk Enterprise** on an Ubuntu headless instance.
* Activated dedicated TCP receiver on port **9997** to listen for incoming forwarder streams.
* Established host port forwarding (`8888 -> 8000`) for secure web dashboard management from the host workstation.

---

## 🛠️ Engineering & Troubleshooting Highlights

* **Static Subnetting & Routing:** Configured static IP allocations and default gateways across three guest operating systems on a private `10.0.2.0/24` subnet.
* **Service Recovery & Port Verification:** Diagnosed and resolved Universal Forwarder service lockups during restart cycles; verified TCP handshake state between Windows and Ubuntu via PowerShell (`Test-NetConnection -ComputerName 10.0.2.10 -Port 9997`).
* **Authentication Pipeline:** Resolved credential seed mismatches by provisioning a clean `user-seed.conf` to reset admin access without losing indexed telemetry.

---

## 🎯 Attack Scenarios & Detection Engineering

### Scenario 1: LOLBins Discovery & Reconnaissance (MITRE T1033 / T1087)
* **Adversary Behavior:** Execution of built-in system administration utilities (`whoami /priv`, `net user`, `net localgroup administrators`, `ipconfig /all`) to map local privileges.
* **Detection Logic (SPL):**
```spl
index=main sourcetype="*sysmon*" EventCode=1 
| search Image="*\\whoami.exe" OR Image="*\\net.exe" OR Image="*\\ipconfig.exe"
| table _time, host, User, ParentImage, Image, CommandLine
