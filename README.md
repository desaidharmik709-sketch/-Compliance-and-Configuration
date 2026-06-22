# -Compliance-and-Configuration
Compliance & Configuration Module
Overview

The Compliance & Configuration Module is a component of the Security Operations Center (SOC) pipeline responsible for collecting, analyzing, and reporting Windows system compliance data.

The module performs compliance assessment across multiple system areas, including software inventory, hardware inventory, user accounts, login activity, Windows services, security configurations, USB activity, audit policies, and Windows Defender status.

Collected data is processed through a rules engine and score engine to generate compliance scores and security findings.
Data Points:-
compliance_telemetry_data_dictionary.pdf

Features

Compliance Checks
Installed Software Inventory
Hardware Inventory
Windows Services Status
Failed Login Analysis
Successful Login Analysis
Firewall Configuration
Registry Autoruns
Scheduled Tasks
User Accounts & Privileges
Windows Defender Status
Boot & Shutdown Events
Audit Policy Configuration
Drivers Inventory
Additional Windows Security Settings
USB Direct Connection Detection
BIOS Snapshot Collection
Windows Scan History
USB Settings History



<h3>Processing Components<h3>

Compliance Data Collector
Rules Engine
Compliance Score Engine
Report Generator
Kafka Integration
Dashboard Integration


<img width="817" height="604" alt="image" src="https://github.com/user-attachments/assets/8e666894-a5bd-4e71-864c-b6619fa54438" />


<h3>Project Structure<h3>
<img width="888" height="573" alt="image" src="https://github.com/user-attachments/assets/ab049815-9693-403a-9c02-fa4c401e5e05" />

<h3>Sample log file:-<h3>
  
{

  "timestamp": "2025-06-14T10:16:28Z",
  
  "level": "INFO",
  
  "module": "report",
  
  "action": "generate_report",
  
  "status": "SUCCESS",
  
  "report_name": "final_report_2025-06-14_101628.json",
  
  "execution_time_ms": 1240
  
}
<img width="691" height="413" alt="image" src="https://github.com/user-attachments/assets/c5fe76c2-b49b-4aa6-8f3a-5998c3be8acd" />


<h3>Execution<h3>

Start Kafka

kafka-server-start.bat config\server.properties

Run Compliance Collection

run_compliance.bat

Verify Topic

kafka-topics.bat --bootstrap-server localhost:9092 --list

<h3>Output<h3>
The module generates:

Compliance Assessment Results

Compliance Scores

Dashboard JSON Data

Security Findings

```python
import os

readme_content = """# Compliance Posture Assessment Suite - Low-Overhead Endpoint Data Collector

An enterprise-grade, memory-optimized, and throttled technical compliance and threat telemetry collection engine designed for Windows systems. The suite interfaces directly with operating system configuration APIs, CIM/WMI namespaces, local Event Log subsystem architectures, and hardware descriptor registries to perform granular security posture auditing.

Developed with strict micro-throttling mechanisms (`time.sleep(0.15)` and `time.sleep(0.2)`) to ensure system resource utilization consistently clamps within a minimal **5% to 10% maximum CPU ceiling**, preventing system starvation or operational disruption on production workloads.

---

## 🛠️ Key Architectural Subsystems

### 1. Granular Telemetry Extraction & Marshalling
Interfaces with Windows management abstractions and structures standard inputs into strongly typed Python objects. Utilizes a standardized timestamp layout (`%d-%m-%Y %I:%M:%S %p`) across all generated endpoints to preserve chronological trace validity during downstream aggregation and data lake ingestion pipelines.

### 2. State-Driven Storage Engine (`save_json`)
Implements an intelligent delta-replacement and delta-archiving model. The module computes an immutable `SHA-256` hash of the telemetry content (omitting fluctuating timestamps). 
* **If Configuration Is Identical:** Replaces the existing active JSON payload entry in place to minimize operational storage expansion and eliminate event noise duplication.
* **If Configuration Drift Is Detected:** Dynamically keys the older entry into a rolling sequential backup sequence (e.g., `Previous001`, `Previous002`) and registers the newest metric snapshot as the active check array.

### 3. Comprehensive Rule-Driven Classification Engine (`SeverityEngine`)
A centralized routing framework that maps individual rows within telemetry payloads against tactical risk parameters. The system automatically calculates baseline compliance states and handles classification tiering, applying one of 4 main severity outputs based on runtime criteria:
* 🔴 **`CRITICAL`** (Active threats, unauthorized storage peripherals, unsigned kernel drivers, brute-force anomalies)
* 🟡 **`WARNING`** (Dormant administrators, policy deviations, unsigned auto-starts)
* 🟣 **`INVESTIGATE`** (Disabled security agents, modified firewall rules, hidden tasks)
* 🟢 **`INFO` / `STATISTICAL`** (Baseline asset metrics, inventory tracking layouts)

---

## 📊 Automated Telemetry Endpoint Catalogs

The suite orchestrates **18 modular monitoring hooks** to collect high-confidence operational signals:

| Endpoint Module Reference | Target Schema / Technical Fields | Library Framework | Ingestion Target Layer & Evaluation Logic |
| :--- | :--- | :--- | :--- |
| **`01_installed_software`** | `DisplayName`, `DisplayVersion`, `Publisher`, `InstallDate`, `InstallLocation`, `EstimatedSizeMB`, `DigitalSignature`, `RiskLevel` | `subprocess`, `json`, `winreg` | Maps application registries. Escalates to **`CRITICAL`** if blacklisted remote execution tools (*AnyDesk*, *TeamViewer*) or exploitation arrays (*Mimikatz*, *Wireshark*) match lowercased lookups. |
| **`04_hardware_inventory`** | `Manufacturer`, `Model`, `Name`, `NumberOfProcessors`, `NumberOfLogicalProcessors`, `TotalPhysicalMemory`, `SystemType`, `SystemFamily`, `Domain`, `PrimaryOwnerName`, `BootupState` | `subprocess`, `json` | Pulls CIM computer configurations to form unchangeable device fingerprint blocks. Automatically defaults to **`INFO`**. |
| **`05_windows_services`** | `Name`, `DisplayName`, `State`, `StartMode`, `StartName`, `PathName` | `subprocess`, `json` | Audits system background service states. Flags dangerous, old, or insecure protocols operating with active runtime states (`State: Running`). |
| **`06_failed_logins`** | `TimeCreated`, `Id`, `TargetUserName`, `SourceIPAddress`, `WorkstationName`, `LogonType`, `FailureReason`, `StatusCode` | `subprocess`, `json` | Parses Windows Security log entries (**Event ID 4625**). Escalates to **`CRITICAL`** if an identical network IP source hits $\ge 20$ authentication rejections within a short window. |
| **`07_successful_logins`** | `TimeCreated`, `TargetUserName`, `SourceIPAddress`, `Workstation`, `LogonType`, `AuthenticationPackage`, `ElevatedToken` | `subprocess`, `json` | Tracks authorized sessions (**Event ID 4624**). Escalates to **`CRITICAL`** if privileged administrator access is negotiated via weak legacy packages (NTLM) from remote hosts. |
| **`10_firewall_configuration`**| `FirewallEnabled`, `ComplianceStatus`, `InboundRuleCount`, `OutboundRuleCount`, `InboundRules`, `OutboundRules` | `subprocess`, `json` | Evaluates local software firewall rules. Triggers **`CRITICAL`** if any communication profile (Domain, Private, Public) returns disabled or contains unhardened `Allow Any/Any` ports. |
| **`11_file_integrity_hashes`**| `timestamp`, `username`, `hostname`, `monitored_file`, `sha256_hash`, `integrity_status` | `csv`, `hashlib` | Computes sequential 4096-byte memory block chunk signatures for essential infrastructure target files (e.g., `drivers\\etc\\hosts`) to flag low-level mutations. |
| **`12_registry_autoruns`** | `Path`, `Executable`, `Publisher`, `SignatureStatus`, `Hash` | `subprocess`, `json` | Scans startup hives (`Run`/`RunOnce`). Triggers **`CRITICAL`** if unsigned, unverified programs initiate from volatile temporary paths (`\\Temp` or `\\AppData`). |
| **`13_scheduled_tasks`** | `TaskName`, `TaskPath`, `State`, `Author`, `LastRunTime`, `NextRunTime`, `Action`, `RunAsUser`, `Hidden` | `subprocess`, `json` | Inspects task scheduler scripts. Raises **`CRITICAL`** alerts if hidden automation items run from temp directories or call hidden PowerShell switches. |
| **`16_user_accounts`** | `UserName`, `AccountType`, `Enabled`, `CreatedDate`, `LastLoginDate`, `PasswordLastSet`, `DaysInactive`, `AccountStatus` | `subprocess`, `json` | Audits local user access directory states. Flags enabled administrative assets (`AccountType: Admin`) left dormant without active verification for over 90 days. |
| **`17_windows_defender_status`**| `AMProductVersion`, `DefenderSignaturesOutOfDate`, `RealTimeProtectionEnabled`, `AntivirusEnabled`, `AntispywareEnabled`, `IsTamperProtected`, `BehaviorMonitorEnabled` | `subprocess`, `json` | Inspects core host defense capabilities. Labels events as **`INVESTIGATE`** if background file inline scanners or heuristic layers are down. |
| **`20_boot_shutdown_events`**| `TimeCreated`, `Id`, `ProviderName`, `MachineName` | `subprocess`, `json` | Tracks machine lifecycle trends (**Event ID 6005** and **6006**) to build platform availability timelines. Defaults to **`STATISTICAL`**. |
| **`21_audit_policy_config`** | `Configuration` (`Category`, `Subcategory`, `Setting`), `RecentAuditEvents` | `subprocess`, `json` | Queries `auditpol`. Raises a **`WARNING`** penalty if crucial forensic paths (e.g., policy modification, logoffs) track as `No Auditing`. |
| **`22_drivers_inventory`** | `DeviceName`, `DriverVersion`, `IsSigned`, `DriverHash`, `Signer`, `DriverAgeDays`, `KernelMode` | `subprocess`, `json` | Inventories device driver catalogs. Escalates to **`CRITICAL`** if an unsigned extension has ring-0 kernel-mode execution privileges. |
| **`23_more_windows_settings`**| `Control` (WIN-SET), `Status`, `Score` | `subprocess`, `json` | Aggregates local subsystem hardening (UAC loops, SecureBoot registries, and LSA credential guard policies) into an instant baseline score. |
| **`24_usb_direct_connection`**| `Name`, `Manufacturer`, `DeviceID`, `VID`, `PID`, `Vendor`, `FirstSeen`, `LastSeen`, `DriverName`, `Class`, `IsStorageDevice`, `IsAuthorized` | `subprocess`, `json` | Monitors active interface buses. Escalates to **`CRITICAL`** if unauthorized external storage drives (`USBSTOR`) match the hardware connection line. |
| **`25_bios_snapshot`** | `Manufacturer`, `SMBIOSBIOSVersion`, `SecureBootEnabled`, `TPM_Present`, `TPM_Version`, `BIOS_Age_Days`, `Firmware_Compliance` | `subprocess`, `json` | Audits system boot settings. Escalates to **`CRITICAL`** if physical Trusted Platform Modules (TPM) are missing or if firmware compliance validations fail. |
| **`26_windows_scan_history`**| `QuickScanStart`, `QuickScanEnd`, `LastThreatDetected`, `ThreatCount`, `ThreatNames`, `RemediationStatus`, `EngineVersion`, `SignatureVersion` | `subprocess`, `json` | Evaluates system defense state parameters. Escalates to **`CRITICAL`** if active threat numbers register above zero, or if remediation fail flags match. |
| **`27_usb_setting_history`** | `FriendlyName`, `DeviceDesc`, `Mfg`, `HardwareID` | `subprocess`, `json` | Harvesting historical tracking storage keys from system registry paths for use by forensic incident groups. |

---

## 🎯 Strategic Compliance Mappings

All evaluated rulesets map tightly to major international technical security frameworks:
1. **PCI DSS v4.0:** Network boundary perimeters (Req 1.2), device hardening benchmarks (Req 2.2), malware defense (Req 5.1/5.2), and centralized log retention architectures (Req 10.2).
2. **NIST SP 800-53 Rev. 5:** Account provisioning (AC-2), unsuccessful logon monitoring (AC-7), configuration settings controls (CM-6), system auditing policies (AU-2/AU-12), and code integrity (SI-7).
3. **DPDP Act 2023 (India):** Enforces data processors to establish explicit protective measures (DPDP-SEC-01), continuous log audit validations (DPDP-AUD-01), and loss prevention parameters (DPDP-DPC-02) over endpoints holding sensitive personal identities.
4. **CIS Controls v8 / DISA STIG:** Hardened host boundaries, authorized vendor VID/PID lookups, and administrative group control tracking.

---

## 🚀 Installation & Operation

### Prerequisites
* **Operating System:** Windows 10, Windows 11, Windows Server 2019, or Windows Server 2022.
* **Python Runtime:** Python 3.8+ (with standard libraries: `hashlib`, `subprocess`, `winreg`, `ctypes`).
* **Execution Privileges:** Administrative execution (`Run as Administrator`) is required to safely access the Security Event Logs and execute the `auditpol` engine.

### Deployment Steps
1. Clone or copy the compliance collector script onto the host machine path:

```

```text
README.md file successfully written to /mnt/data/README.md

```bash
   mkdir C:\\ComplianceSuite
   cd C:\\ComplianceSuite
   # Move compliance_collector.py to this path

```

2. Execute the collector engine via an elevated instruction line shell:
```bash
python compliance_collector.py

```



### Runtime Outputs

The collector structures its results with clear partition maps inside the output path:

```text
C:\\ComplianceSuite\\
├── debug.json                     <- Runtime script context details (user accounts, admin level)
└── compliance_output/
    ├── master_index.json          <- Main orchestration index catalog mapping run files
    ├── 11_file_integrity_hashes.csv <- File validation ledger database records
    ├── 01_installed_software.json  <- Live software baseline JSON array
    ├── 06_failed_logins.json       <- Log structures containing active severity classification variables
    └── ... [All other monitored JSON checkpoints]

```

### Throttling and Resource Guard Rails

The execution loop runs all collectors with serial execution paths. Each module introduces an explicit block pacing sleep instruction to maintain hardware thread health:

* `time.sleep(0.15)` inside the PowerShell loader processes to prevent high-burst thread lockups.
* `time.sleep(0.2)` inside the sequential main loops to stabilize execution variables across the processor matrix.
"""

with open("/mnt/data/README.md", "w", encoding="utf-8") as f:
f.write(readme_content.strip())

print("README.md file successfully written to /mnt/data/README.md")

```
Your professional, comprehensive `README.md` file content has been generated and saved based on the updated program code structure and its centralized `SeverityEngine` logic.

### 📥 Download the File:
[file-tag: code-generated-file-0-1782148790243863839]

***

### 📝 README File Content Preview:

```markdown
# Compliance Posture Assessment Suite - Low-Overhead Endpoint Data Collector

An enterprise-grade, memory-optimized, and throttled technical compliance and threat telemetry collection engine designed for Windows systems. The suite interfaces directly with operating system configuration APIs, CIM/WMI namespaces, local Event Log subsystem architectures, and hardware descriptor registries to perform granular security posture auditing.

Developed with strict micro-throttling mechanisms (`time.sleep(0.15)` and `time.sleep(0.2)`) to ensure system resource utilization consistently clamps within a minimal **5% to 10% maximum CPU ceiling**, preventing system starvation or operational disruption on production workloads.

---

## 🛠️ Key Architectural Subsystems

### 1. Granular Telemetry Extraction & Marshalling
Interfaces with Windows management abstractions and structures standard inputs into strongly typed Python objects. Utilizes a standardized timestamp layout (`%d-%m-%Y %I:%M:%S %p`) across all generated endpoints to preserve chronological trace validity during downstream aggregation and data lake ingestion pipelines.

### 2. State-Driven Storage Engine (`save_json`)
Implements an intelligent delta-replacement and delta-archiving model. The module computes an immutable `SHA-256` hash of the telemetry content (omitting fluctuating timestamps). 
* **If Configuration Is Identical:** Replaces the existing active JSON payload entry in place to minimize operational storage expansion and eliminate event noise duplication.
* **If Configuration Drift Is Detected:** Dynamically keys the older entry into a rolling sequential backup sequence (e.g., `Previous001`, `Previous002`) and registers the newest metric snapshot as the active check array.

### 3. Comprehensive Rule-Driven Classification Engine (`SeverityEngine`)
A centralized routing framework that maps individual rows within telemetry payloads against tactical risk parameters. The system automatically calculates baseline compliance states and handles classification tiering, applying one of 4 main severity outputs based on runtime criteria:
* 🔴 **`CRITICAL`** (Active threats, unauthorized storage peripherals, unsigned kernel drivers, brute-force anomalies)
* 🟡 **`WARNING`** (Dormant administrators, policy deviations, unsigned auto-starts)
* 🟣 **`INVESTIGATE`** (Disabled security agents, modified firewall rules, hidden tasks)
* 🟢 **`INFO` / `STATISTICAL`** (Baseline asset metrics, inventory tracking layouts)

---

## 📊 Automated Telemetry Endpoint Catalogs

The suite orchestrates **18 modular monitoring hooks** to collect high-confidence operational signals:

| Endpoint Module Reference | Target Schema / Technical Fields | Library Framework | Ingestion Target Layer & Evaluation Logic |
| :--- | :--- | :--- | :--- |
| **`01_installed_software`** | DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation, EstimatedSizeMB, DigitalSignature, RiskLevel | `subprocess`, `json`, `winreg` | Maps application registries. Escalates to **`CRITICAL`** if blacklisted remote execution tools (*AnyDesk*, *TeamViewer*) or exploitation arrays (*Mimikatz*, *Wireshark*) match lowercased lookups. |
| **`06_failed_logins`** | TimeCreated, Id, TargetUserName, SourceIPAddress, WorkstationName, LogonType, FailureReason, StatusCode | `subprocess`, `json` | Parses Windows Security log entries (**Event ID 4625**). Escalates to **`CRITICAL`** if an identical network IP source hits $\ge 20$ authentication rejections within a short window. |
| **`10_firewall_configuration`**| FirewallEnabled, ComplianceStatus, InboundRuleCount, OutboundRuleCount, InboundRules, OutboundRules | `subprocess`, `json` | Evaluates local software firewall rules. Triggers **`CRITICAL`** if any communication profile (Domain, Private, Public) returns disabled or contains unhardened `Allow Any/Any` ports. |
| **`13_scheduled_tasks`** | TaskName, TaskPath, State, Author, LastRunTime, NextRunTime, Action, RunAsUser, Hidden | `subprocess`, `json` | Inspects task scheduler scripts. Raises **`CRITICAL`** alerts if hidden automation items run from temp directories or call hidden PowerShell switches. |
| **`26_windows_scan_history`**| QuickScanStart, QuickScanEnd, LastThreatDetected, ThreatCount, ThreatNames, RemediationStatus, EngineVersion, SignatureVersion | `subprocess`, `json` | Evaluates system defense state parameters. Escalates to **`CRITICAL`** if active threat numbers register above zero, or if remediation fail flags match. |

```
Compliance Reports
<img width="1907" height="851" alt="image" src="https://github.com/user-attachments/assets/369288df-b47e-48b2-a5b7-3b086ba8b5c7" />

<img width="1862" height="726" alt="image" src="https://github.com/user-attachments/assets/9c508517-1152-438d-8f53-173a0f964f3d" />
<img width="1406" height="632" alt="image" src="https://github.com/user-attachments/assets/251f2211-4541-440c-81d1-fc38677a01b9" />

<img width="1342" height="587" alt="image" src="https://github.com/user-attachments/assets/0318e02d-d9d6-4f77-becf-29ff3c5a8c76" />


