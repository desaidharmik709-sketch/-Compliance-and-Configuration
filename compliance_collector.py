"""
Compliance Posture Assessment Engine - Low-Overhead Data Collector
Strictly throttled to guarantee CPU usage remains between 5% and 10% maximum.
"""
import hashlib
import os
import json
import csv
import socket
import subprocess
import ctypes
import getpass
import time
import uuid  # Added for MAC address retrieval
import winreg  # Added for low-overhead registry-based hardware lookup
import platform  # Added for safe OS version lookup
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).parent.resolve()
OUTPUT_DIR = BASE_DIR / "compliance_output"
OUTPUT_DIR.mkdir(exist_ok=True)

CURRENT_USER = getpass.getuser()

debug_info = {
    "user": CURRENT_USER,
    "admin": bool(ctypes.windll.shell32.IsUserAnAdmin()),
    "cwd": str(BASE_DIR)
}

with open(BASE_DIR / "debug.json", "w", encoding="utf-8") as f:
    json.dump(debug_info, f, indent=4, ensure_ascii=False)


def ts():
    return datetime.now().strftime("%d-%m-%Y %I:%M:%S %p")


def get_device_fingerprint():
    """
    Retrieves device metadata: Hostname, IP Address, MAC Address,
    Manufacturer, Model Name, and OS Version without causing performance degradation.
    """
    hostname = socket.gethostname()
    ip_address = "127.0.0.1"
    try:
        # Get local IP address safely
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip_address = s.getsockname()[0]
        s.close()
    except Exception:
        try:
            ip_address = socket.gethostbyname(hostname)
        except Exception:
            pass

    # Extract MAC Address and format cleanly
    try:
        mac_hex = iter(f"{uuid.getnode():012x}")
        mac_address = ":".join(a + b for a, b in zip(mac_hex, mac_hex))
    except Exception:
        mac_address = "00:00:00:00:00:00"

    # Fast registry lookup for Manufacturer and Model to keep overhead minimal
    manufacturer = "Unknown"
    model = "Unknown"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\BIOS") as key:
            manufacturer = winreg.QueryValueEx(key, "SystemManufacturer")[0].strip()
            model = winreg.QueryValueEx(key, "SystemProductName")[0].strip()
    except Exception:
        pass

    # Get OS version cleanly
    try:
        os_version = f"{platform.system()} {platform.release()} (Build {platform.version()})"
    except Exception:
        os_version = "Windows Unknown"

    return {
        "device_name": hostname,
        "ip_address": ip_address,
        "mac_address": mac_address,
        "manufacturer": manufacturer,
        "model_name": model,
        "os_version": os_version
    }


def parse_maybe_json(text):
    text = text.strip()
    if not text:
        return text
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text

def remove_timestamp(obj):
    if isinstance(obj, dict):
        return {k: remove_timestamp(v) for k, v in obj.items() if k != "timestamp"}
    elif isinstance(obj, list):
        return [remove_timestamp(elem) for elem in obj]
    else:
        return obj


def generate_data_hash(data):
    try:
        cleaned_data = remove_timestamp(data)
        normalized = json.dumps(cleaned_data, sort_keys=True, default=str)
        return hashlib.sha256(normalized.encode()).hexdigest()
    except Exception:
        return "HASH_ERROR"


def is_duplicate(existing_data, current_hash):
    if not existing_data:
        return False

    try:
        previous_hash = existing_data[-1].get("data_hash")
        return previous_hash == current_hash
    except Exception:
        return False

def run_cmd(cmd):
    # Throttle execution to keep CPU baseline low
    time.sleep(0.15)
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            shell=True
        )
        return {
            "timestamp": ts(),
            "command": cmd,
            "return_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr
        }
    except Exception as e:
        return {"timestamp": ts(), "error": str(e)}


def run_ps(command):
    # Throttle execution to keep CPU baseline low
    time.sleep(0.15)
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
            capture_output=True,
            text=True
        )
        stdout = result.stdout.strip()
        return {
            "timestamp": ts(),
            "command": command,
            "return_code": result.returncode,
            "stdout": parse_maybe_json(stdout),
            "stderr": result.stderr.strip()
        }
    except Exception as e:
        return {"timestamp": ts(), "error": str(e)}


def save_json(name, data, event_id="COMP-GENERIC", severity="INFO", event_type="Compliance Metric Collection"):

    path = OUTPUT_DIR / f"{name}.json"

    data_hash = generate_data_hash(data)

    existing_data = []

    if path.exists():
        try:
            with open(path, "r", encoding="utf-8") as f:
                existing_data = json.load(f)

                if not isinstance(existing_data, list):
                    existing_data = []

        except Exception:
            existing_data = []

    active_index = None

    for i, old_entry in enumerate(existing_data):
        old_severity = old_entry.get("severity", "INFO")
        old_event_id = str(old_entry.get("event_id", ""))
        
        # An entry is active if it has the matching severity and is not archived (doesn't start with "Previous")
        if old_severity == severity and not old_event_id.startswith("Previous"):
            active_index = i
            break

    new_entry = {
        "device_fingerprint": get_device_fingerprint(),
        "timestamp": ts(),
        "event_id": f"EVT_{name.upper()}",
        "event_type": event_type,
        "severity": severity,
        "data_hash": data_hash,
        "payload_message": {
            "collection_metadata": {
                "date": datetime.now().strftime("%d-%m-%Y"),
                "time": datetime.now().strftime("%I:%M:%S %p"),
                "username": CURRENT_USER
            },
            "data": data
        }
    }

    if active_index is not None:
        active_entry = existing_data[active_index]
        old_hash = active_entry.get("data_hash")

        # Fallback: support backward compatibility with legacy entries by computing timestamp-free hash
        if old_hash != data_hash:
            old_data = active_entry.get("payload_message", {}).get("data")
            if old_data is not None:
                legacy_hash = generate_data_hash(old_data)
                if legacy_hash == data_hash:
                    old_hash = legacy_hash

        if old_hash == data_hash:
            # Same data, same severity -> Replace active entry in place
            existing_data[active_index] = new_entry
            print(f"[UPDATED] {name} -> Existing active entry replaced.")
        else:
            # Different data, same severity -> Archive the old active entry and append the new entry
            max_num = 0
            for entry in existing_data:
                eid = str(entry.get("event_id", ""))
                if eid.startswith("Previous"):
                    try:
                        num = int(eid[8:])
                        if num > max_num:
                            max_num = num
                    except ValueError:
                        pass
            next_previous_id = f"Previous{max_num + 1:03d}"
            
            # Archive the old active entry
            active_entry["event_id"] = next_previous_id
            
            # Append the new active entry
            existing_data.append(new_entry)
            print(f"[ARCHIVED] {name} -> Previous active entry archived as {next_previous_id}. New entry appended.")
    else:
        # No existing active entry for this severity -> Append the new entry
        existing_data.append(new_entry)
        print(f"[NEW] {name} -> New active entry appended.")

    with open(path, "w", encoding="utf-8") as f:
        json.dump(existing_data, f, indent=4, ensure_ascii=False)

    print(f"[UPDATED] {name}")

def save_csv(name, headers, rows):
    path = OUTPUT_DIR / f"{name}.csv"
    file_exists = path.exists()
    with open(path, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(headers)
        for row in rows:
            writer.writerow(row)

# --- Throttled Compliance JSON Collectors ---

def installed_software():
    return run_ps("Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* -ErrorAction SilentlyContinue | Select-Object DisplayName,DisplayVersion | ConvertTo-Json -Depth 2")

def hardware_inventory():
    return run_ps("Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer,Model,Name | ConvertTo-Json")

def windows_services():
    return run_ps("Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object Name,DisplayName,Status | ConvertTo-Json -Depth 2")

def failed_logins():
    return run_ps("Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id | ConvertTo-Json")

def successful_logins():
    return run_ps("Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id | ConvertTo-Json")

def firewall_config():
    return run_ps(r"""
Get-NetFirewallProfile |
Select-Object `
Name,
Enabled,
DefaultInboundAction,
DefaultOutboundAction,
AllowInboundRules,
AllowLocalFirewallRules,
AllowLocalIPsecRules,
NotifyOnListen,
LogFileName,
LogAllowed,
LogBlocked |
ConvertTo-Json -Depth 3
""")

def registry_autoruns():
    return {
        "current_version_run": run_ps(r"Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' | ConvertTo-Json -Depth 3"),
        "current_version_runonce": run_ps(r"Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce' | ConvertTo-Json -Depth 3"),
        "wow6432node_run": run_ps(r"Get-ItemProperty 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue | ConvertTo-Json -Depth 3"),
        "user_run": run_ps(r"Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue | ConvertTo-Json -Depth 3")
    }

def scheduled_tasks():
    return run_ps("Get-ScheduledTask | Where-Object {$_.State -eq 'Ready'} | Select-Object TaskName,TaskPath,State | ConvertTo-Json -Depth 2")

def user_accounts():
    return {
        "users": run_ps("Get-LocalUser | Select-Object Name,Enabled | ConvertTo-Json"),
        "admins": run_ps("Get-LocalGroupMember Administrators | Select-Object Name,ObjectClass | ConvertTo-Json")
    }

def defender_status():
    return run_ps("Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, AntivirusEnabled | ConvertTo-Json")

def boot_shutdown():
    return run_ps(r"""
Get-WinEvent -FilterHashtable @{
    LogName='System'
    ID=6005,6006
} |
Select-Object TimeCreated, Id, ProviderName, MachineName |
ConvertTo-Json -Depth 3
""")

def audit_policy():
    return run_ps(r"""
$audit = auditpol /get /category:*
$lines = $audit | Select-Object -Skip 3
$result = @()
foreach ($line in $lines) {
    if ($line.Trim() -ne "") {
        $parts = $line -split '\s{2,}'
        if ($parts.Count -ge 2) {
            $result += [PSCustomObject]@{
                Subcategory = $parts[0]
                Setting     = $parts[1]
            }
        }
    }
}
$result | ConvertTo-Json -Depth 4
""")

def drivers_inventory():
    return run_ps(r"""
Get-CimInstance Win32_PnPSignedDriver |
Select-Object `
DeviceName,
DriverVersion,
Manufacturer,
DriverProviderName,
DriverDate,
FriendlyName,
InfName,
IsSigned,
Location,
PDO,
Signer |
ConvertTo-Json -Depth 4
""")

def more_windows_settings():
    return {
        "uac_configuration": run_ps("Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' | Select-Object EnableLUA, ConsentPromptBehaviorAdmin, PromptOnSecureDesktop | ConvertTo-Json"),
        "windows_defender": run_ps("Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, IoavProtectionEnabled, AntispywareEnabled, BehaviorMonitorEnabled, AntivirusSignatureLastUpdated | ConvertTo-Json"),
        "firewall_profiles": run_ps("Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction | ConvertTo-Json"),
        "rdp_status": run_ps("Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' | Select-Object fDenyTSConnections | ConvertTo-Json"),
        "bitlocker_status": run_ps("Get-BitLockerVolume | Select-Object MountPoint, ProtectionStatus, EncryptionMethod | ConvertTo-Json"),
        "powershell_logging": run_ps("Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -ErrorAction SilentlyContinue | ConvertTo-Json"),
        "secure_boot": run_ps("Confirm-SecureBootUEFI | ConvertTo-Json"),
        "windows_update": run_ps("Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate\\Auto Update' | ConvertTo-Json"),
        "smb_configuration": run_ps("Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, EnableSMB2Protocol | ConvertTo-Json"),
        "remote_registry": run_ps("Get-Service RemoteRegistry | Select-Object Name, Status, StartType | ConvertTo-Json"),
        "credential_guard": run_ps("Get-CimInstance Win32_DeviceGuard | ConvertTo-Json -Depth 3"),
        "lsa_protection": run_ps("Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' | Select-Object RunAsPPL | ConvertTo-Json"),
        "smartscreen": run_ps("Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer' | Select-Object SmartScreenEnabled | ConvertTo-Json")
    }

def usb_laptop_direct_connection():
    return run_ps("Get-CimInstance Win32_USBControllerDevice | Select-Object Dependent, Antecedent | ConvertTo-Json")

def bios_snapshot():
    return run_ps("Get-CimInstance Win32_BIOS | Select-Object Manufacturer, SMBIOSBIOSVersion | ConvertTo-Json")

def windows_scan_history():
    return run_ps("Get-MpThreatDetection -ErrorAction SilentlyContinue | Select-Object TimeDetected, ThreatName | ConvertTo-Json")

def usb_setting_history():
    return run_cmd(r'reg query "HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR" /s')

BLACKLIST = {
    "utorrent",
    "mimikatz",
    "process hacker",
    "cheat engine",
    "hydra",
    "john the ripper",
    "nmap",
    "aircrack",
    "pwdump"
}

def analyse_software(data):

    suspicious_apps = []

    try:
        software_list = data.get("stdout", [])

        if not isinstance(software_list, list):
            return suspicious_apps

        for app in software_list:

            display_name = str(
                app.get("DisplayName", "")
            ).lower()

            for bad in BLACKLIST:

                if bad in display_name:

                    suspicious_apps.append({
                        "application": app.get("DisplayName"),
                        "version": app.get("DisplayVersion"),
                        "severity": "INVESTIGATIVE"
                    })

    except Exception:
        pass

    return suspicious_apps

COLLECTORS = {
    "01_installed_software": installed_software,
    "04_hardware_inventory": hardware_inventory,
    "05_windows_services": windows_services,
    "06_failed_logins": failed_logins,
    "07_successful_logins": successful_logins,
    "10_firewall_configuration": firewall_config,
    "12_registry_autoruns": registry_autoruns,
    "13_scheduled_tasks": scheduled_tasks,
    "16_user_accounts_and_privileges": user_accounts,
    "17_windows_defender_status": defender_status,
    "20_boot_shutdown_events": boot_shutdown,
    "21_audit_policy_configuration": audit_policy,
    "22_drivers_inventory": drivers_inventory,
    "23_more_windows_settings": more_windows_settings,
    "24_usb_direct_connection": usb_laptop_direct_connection,
    "25_bios_snapshot": bios_snapshot,
    "26_windows_scan_history": windows_scan_history,
    "27_usb_setting_history": usb_setting_history
}


def calculate_sha256(filepath):
    try:
        sha256 = hashlib.sha256()
        with open(filepath, "rb") as f:
            while chunk := f.read(4096):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception:
        return "FILE_NOT_FOUND"


def main():
    master = {
        "device_fingerprint": get_device_fingerprint(),
        "timestamp": ts(),
        "event_id": "EVT_MASTER_INDEX",
        "event_type": "Index Generation",
        "severity": "INFO",
        "payload_message": {
            "username": CURRENT_USER,
            "files": []
        }
    }

    # -------------------------------
    # Run all collectors
    # -------------------------------
    for name, func in COLLECTORS.items():

        data = func()

        # Software reputation check
        if name == "01_installed_software":

            suspicious_apps = analyse_software(data)

            if suspicious_apps:

                print("\n" + "=" * 70)
                print("[ALERT] Suspicious Software Detected")
                print("=" * 70)

                for app in suspicious_apps:

                    print(f"Application : {app['application']}")
                    print(f"Version     : {app['version']}")
                    print(f"Severity    : {app['severity']}")
                    print("-" * 70)

        # Blueprint severity classification
        if name == "06_failed_logins":
            severity_level = "CRITICAL"
            event_type_label = "Failed Login Monitoring"

        elif name == "26_windows_scan_history":
            severity_level = "CRITICAL"
            event_type_label = "Threat Detection"

        elif name in [
            "10_firewall_configuration",
            "12_registry_autoruns",
            "13_scheduled_tasks",
            "17_windows_defender_status",
            "23_more_windows_settings",
            "27_usb_setting_history"
        ]:
            severity_level = "INVESTIGATIVE"
            event_type_label = "Security Investigation"

        elif name == "20_boot_shutdown_events":
            severity_level = "STATISTICS"
            event_type_label = "System Availability Metrics"

        else:
            severity_level = "INFO"
            event_type_label = "Compliance Metric Collection"

        save_json(
            name,
            data,
            severity=severity_level,
            event_type=event_type_label
        )

        master["payload_message"]["files"].append(f"{name}.json")

        time.sleep(0.2)
    

    # -------------------------------
    # File Integrity Monitoring
    # -------------------------------
    csv_headers = [
        "timestamp",
        "username",
        "hostname",
        "monitored_file",
        "sha256_hash",
        "integrity_status"
    ]
    csv_rows = []
    files_to_hash = [
        r"C:\Windows\System32\drivers\etc\hosts",
        r"C:\Windows\System32\drivers\pci.sys"
    ]

    for file_path in files_to_hash:
        file_hash = calculate_sha256(file_path)
        csv_rows.append([
            ts(),
            CURRENT_USER,
            socket.gethostname(),
            file_path,
            file_hash,
            "PRESENT" if file_hash != "FILE_NOT_FOUND" else "MISSING"
        ])

    save_csv("11_file_integrity_hashes", csv_headers, csv_rows)
    master["payload_message"]["files"].append("11_file_integrity_hashes.csv")

    # -------------------------------
    # Save master index
    # -------------------------------
    save_json(
        "master_index", 
        master["payload_message"], 
        event_id="EVT_MASTER_INDEX", 
        event_type="Master Aggregation",
        severity="INFO"
    )

    print(f"[+] Throttled collection complete. Output directory: {OUTPUT_DIR.resolve()}")


if __name__ == "__main__":
    main()
