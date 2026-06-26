# 🛡️ Compliance Posture Assessment Suite

> **Windows endpoint compliance pipeline** — collects 18 security datapoints, classifies severity, streams via Apache Kafka 4.3.0, and renders a live SOC dashboard.

Built as part of the **Deepcytes Cyber Labs UK Summer Fellowship** by **Team 8**.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Modules](#modules)
- [18 Datapoints](#18-datapoints)
- [Severity Levels](#severity-levels)
- [Compliance Frameworks](#compliance-frameworks)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Running the Pipeline](#running-the-pipeline)
- [Project Structure](#project-structure)
- [Team](#team)

---

## Overview

The suite runs a three-stage Python pipeline on a Windows endpoint:

1. **Collect** — 18 PowerShell/WMI/Registry collectors gather endpoint security data with CPU throttling (5–10% overhead)
2. **Stream** — A Kafka producer normalises, deduplicates, and priority-sorts events before sending to topic `compliance-data`
3. **Visualise** — A Kafka consumer renders a live HTML dashboard updated every 2 seconds

Targets **NIST SP 800-53**, **PCI DSS v4.0**, and internal Deepcytes controls.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│              compliance_collector.py  (Module 1)                │
│                                                                 │
│  get_device_fingerprint()  →  hostname / IP / MAC / OS          │
│         │                                                       │
│         ▼                                                       │
│  18 Collector Functions  (run_ps / run_cmd)                     │
│    └─ throttled: time.sleep(0.15) per collector                 │
│         │                                                       │
│         ▼                                                       │
│  SeverityEngine.process_*()                                     │
│    └─ adds Severity / SeverityReason / DetectionParameters      │
│         │                                                       │
│         ▼                                                       │
│  generate_data_hash()  →  SHA-256 dedup check                  │
│         │                                                       │
│         ▼                                                       │
│  save_json()  →  compliance_output/<name>.json                  │
└─────────────────────────────────────────────────────────────────┘
                          │
                          │  JSON files on disk
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│               kafka_producer.py  (Module 2)                     │
│                                                                 │
│  Read all *.json from compliance_output/                        │
│         │                                                       │
│         ▼                                                       │
│  normalize_stdout()  →  flatten to list of records             │
│         │                                                       │
│         ▼                                                       │
│  Deduplication  →  SHA-256 of {file + event_id + record}       │
│         │                                                       │
│         ▼                                                       │
│  Priority Sort  →  CRITICAL → WARNING → STATISTICAL → INFO     │
│         │                                                       │
│         ▼                                                       │
│  producer.send("compliance-data", value=payload)               │
└─────────────────────────────────────────────────────────────────┘
                          │
                          │  Kafka topic: compliance-data
                          │  Bootstrap:   localhost:9092 (KRaft)
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│          kafka_consumer_dashboard.py  (Module 3)                │
│                                                                 │
│  KafkaConsumer("compliance-data", auto_offset_reset="latest")  │
│         │                                                       │
│         ▼                                                       │
│  Per message: dedup → append to JSONL history → update state   │
│         │                                                       │
│         ▼                                                       │
│  render_dashboard_data()  every 2 s                            │
│    └─ writes dashboard_data.js  ←  polled by dashboard.html    │
└─────────────────────────────────────────────────────────────────┘
```

---

## Modules

### `compliance_collector.py` — Data Collection Engine

- Runs on the **Windows endpoint** (admin privileges recommended)
- Collects a **device fingerprint** (hostname, IP, MAC, manufacturer, OS version)
- Executes **18 collector functions** via PowerShell, WMI, and Registry queries
- Each collector is throttled with `time.sleep(0.15)` to keep CPU at 5–10%
- Records are classified by `SeverityEngine` and SHA-256 hashed for deduplication
- Outputs structured JSON files to `compliance_output/`

### `kafka_producer.py` — Event Streaming

- Reads all `*.json` files from `compliance_output/`
- Normalises heterogeneous collector outputs into a flat list of records via `normalize_stdout()`
- Deduplicates using a SHA-256 hash of `{file_name + event_id + timestamp + record}`
- Priority-sorts by severity before sending: `CRITICAL=1 → WARNING=2 → STATISTICAL=3 → INFO=5`
- Streams to Apache Kafka 4.3.0 (KRaft mode) on topic `compliance-data`
- Includes a **Python 3.12+ selector patch** for invalid file descriptor handling

### `kafka_consumer_dashboard.py` — Live SOC Dashboard

- Consumes from `compliance-data` topic (`auto_offset_reset=latest`)
- Maintains in-memory state: per-file logs, latest events, severity bucket counts
- Writes `dashboard_data.js` every 2 seconds (polled by `dashboard.html`)
- Tracks `producer_active` flag: green ACTIVE if last message < 15 s ago
- Appends all events to `reports/dashboard_history.jsonl` for persistence

---

## 18 Datapoints

| # | Datapoint | Collection Method | Framework |
|---|-----------|-------------------|-----------|
| 01 | Installed Software | Registry Uninstall + Authenticode sig | NIST CM-7, PCI DSS 6.3 |
| 04 | Hardware Inventory | WMI Win32_ComputerSystem | NIST CM-8 |
| 05 | Windows Services | WMI Win32_Service | NIST AC-3 |
| 06 | Failed Logins | Security Event Log ID 4625 (last 50) | NIST AC-7, PCI DSS 8.3 |
| 07 | Successful Logins | Security Event Log ID 4624 (last 50) | NIST AU-2, PCI DSS 8.3 |
| 10 | Firewall Configuration | Get-NetFirewallProfile + Get-NetFirewallRule | NIST SC-7, PCI DSS 1.3 |
| 11 | File Integrity Hashes | SHA-256 of hosts + pci.sys (CSV) | NIST SI-7, PCI DSS 11.5 |
| 12 | Registry Autoruns | HKLM/HKCU Run keys + Authenticode + SHA-256 | NIST SI-3, PCI DSS 5.1 |
| 13 | Scheduled Tasks | Get-ScheduledTask (Ready/Running, first 100) | NIST SI-3 |
| 16 | User Accounts & Privileges | Get-LocalUser + LastLogon + PasswordLastSet | NIST AC-2, PCI DSS 8.1 |
| 17 | Windows Defender Status | Get-MpComputerStatus | NIST SI-3, PCI DSS 5.1 |
| 20 | Boot / Shutdown Events | System Event Log IDs 6005/6006/1074/6008/41 | NIST AU-2 |
| 21 | Audit Policy Configuration | auditpol /get /category:* + Security Log | NIST AU-2, PCI DSS 10.2 |
| 22 | Drivers Inventory | WMI Win32_PnPSignedDriver (first 200) + SHA-256 | NIST SI-7 |
| 23 | Windows Settings (17 sub-checks) | PowerShell — BitLocker, SMB1, PS policy, etc. | NIST multiple, PCI DSS multiple |
| 24 | USB Direct Connection | WMI Win32_PnPEntity filter USBSTOR/USB | NIST MP-7, PCI DSS 9.9 |
| 25 | BIOS Snapshot | Win32_BIOS + Get-Tpm + SecureBoot + DeviceGuard | NIST SI-7 |
| 26 | Windows Scan History | Get-MpThreat + Get-MpThreatDetection | NIST SI-3, PCI DSS 5.1 |

> Datapoint 23 (`more_windows_settings`) runs 17 independent sub-checks including BitLocker encryption status, SMB1 enablement, PowerShell execution policy, account lockout policies, event log config, Wi-Fi security, and LSA protection.

---

## Severity Levels

| Level | Colour | Trigger Examples |
|-------|--------|-----------------|
| 🔴 `CRITICAL` | Red | TPM missing · Firewall disabled · BitLocker off · SMB1 enabled · Unsigned kernel driver |
| 🟡 `WARNING` | Amber | Admin inactive >30 days · PS ExecutionPolicy Bypass · Any/Any firewall rule |
| 🟣 `INVESTIGATE` | Purple | SecureBoot disabled · Unsigned autorun · Remote access tool detected · USB device |
| 🔵 `STATISTICAL` | Blue | Routine boot/shutdown events · Baseline telemetry |
| 🟢 `INFO` | Green | Signed driver · Clean AV scan · Active compliant user account |

Each record receives three additional fields from `SeverityEngine`:
- `Severity` — one of the five levels above
- `SeverityReason` — human-readable explanation
- `DetectionParameters` — raw inputs used to derive the decision

---

## Compliance Frameworks

| Framework | Coverage |
|-----------|----------|
| **NIST SP 800-53** | CM-7/8, AC-2/3/7/17, AU-2, SC-7/28, SI-3/7, MP-7, CP-10 |
| **PCI DSS v4.0** | 1.3, 5.1/5.2, 6.3, 8.1/8.3, 9.9, 10.2/10.3, 11.5, 12.8 |
| **Internal (Deepcytes)** | ENDPOINT, HARDWARE, SYSTEM categories |

---

## Prerequisites

```
Python        3.10+  (3.12+ recommended — selector patch included)
Apache Kafka  4.3.0  (KRaft mode, no ZooKeeper)
kafka-python  2.x
psutil
Windows       10/11  (collector must run on Windows endpoint)
```

Optional:
```
Wazuh agent   (Windows 11 Home confirmed Active)
Docker        (for Wazuh on Kali Linux)
```

---

## Installation

```bash
# 1. Clone the repo
git clone https://github.com/team8-deepcytes/compliance-suite.git
cd compliance-suite

# 2. Install Python dependencies
pip install kafka-python psutil

# 3. Start Kafka 4.3.0 in KRaft mode
# (adjust path to your Kafka installation)
./bin/kafka-server-start.sh config/kraft/server.properties

# 4. Create the topic
./bin/kafka-topics.sh --create \
  --topic compliance-data \
  --bootstrap-server localhost:9092 \
  --partitions 1 \
  --replication-factor 1
```

---

## Running the Pipeline

Open three separate terminals:

```bash
# Terminal 1 — Windows endpoint (run as Administrator for full access)
python compliance_collector.py

# Terminal 2 — after collector finishes
python kafka_producer.py

# Terminal 3 — start any time (before or after producer)
python kafka_consumer_dashboard.py
```

Then open `dashboard.html` in your browser. It auto-updates every 2 seconds.

> **Note:** The producer includes a Python 3.12+ patch for `selectors.py` `ValueError`/`KeyError` on `fd=-1` sockets. No action needed — it applies automatically on import.

---

## Project Structure

```
compliance-suite/
├── compliance_collector.py          # Module 1 — collection + severity engine
├── kafka_producer.py                # Module 2 — normalise + deduplicate + stream
├── kafka_consumer_dashboard.py      # Module 3 — consume + live dashboard
│
├── compliance_output/               # Generated by Module 1
│   ├── 01_installed_software.json
│   ├── 04_hardware_inventory.json
│   ├── 05_windows_services.json
│   ├── 06_failed_logins.json
│   ├── 07_successful_logins.json
│   ├── 10_firewall_configuration.json
│   ├── 11_file_integrity_hashes.csv
│   ├── 12_registry_autoruns.json
│   ├── 13_scheduled_tasks.json
│   ├── 16_user_accounts_and_privileges.json
│   ├── 17_windows_defender_status.json
│   ├── 20_boot_shutdown_events.json
│   ├── 21_audit_policy_configuration.json
│   ├── 22_drivers_inventory.json
│   ├── 23_more_windows_settings.json
│   ├── 24_usb_direct_connection.json
│   ├── 25_bios_snapshot.json
│   ├── 26_windows_scan_history.json
│   ├── 27_usb_setting_history.json
│   └── master_index.json
│
├── reports/
│   ├── dashboard_history.jsonl      # Append-only consumer event log
│   └── final_report_*.json         # Compliance engine output
│
├── dashboard.html                   # Static SOC dashboard shell
├── dashboard_data.js                # Live data file (polled every 2 s)
└── debug.json                       # Startup diagnostics (user, admin, cwd)
```




---

## ⚠️ Known Considerations

- `Win32_PnPSignedDriver` WMI query can spike CPU to 25–40% — capped at 200 drivers with `time.sleep(0.15)` throttle
- `consumer_timeout_ms=1000` is intentional — allows idle render loop without blocking on empty topic
- Each consumer run uses a unique `group_id` (`dashboard-group-<epoch>`) to prevent rebalance hangs on restart
- `compliance_output/` accumulates previous scan entries under `PreviousNNN` event IDs — safe to delete between runs

---

*Deepcytes Cyber Labs UK · Team 8 · 2025*
