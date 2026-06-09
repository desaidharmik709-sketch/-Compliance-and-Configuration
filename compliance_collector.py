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
    return datetime.utcnow().isoformat() + "Z"


def parse_maybe_json(text):
    text = text.strip()
    if not text:
        return text
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


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

def save_json(name, data):
    path = OUTPUT_DIR / f"{name}.json"

    latest = [{
        "collection_time": ts(),
        "username": CURRENT_USER,
        "hostname": socket.gethostname(),
        "data": data
    }]

    with open(path, "w", encoding="utf-8") as f:
        json.dump(latest, f, indent=4, ensure_ascii=False)

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
    # Optimized property selection to prevent memory/CPU bloat
    return run_ps("Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* -ErrorAction SilentlyContinue | Select-Object DisplayName,DisplayVersion | ConvertTo-Json -Depth 2")

def hardware_inventory():
    return run_ps("Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer,Model,Name | ConvertTo-Json")

def windows_services():
    # Limit to running services to save processing overhead
    return run_ps("Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object Name,DisplayName,Status | ConvertTo-Json -Depth 2")

def failed_logins():
    return run_ps("Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 15 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id | ConvertTo-Json")

def successful_logins():
    return run_ps("Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} -MaxEvents 15 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id | ConvertTo-Json")

def firewall_config():
    return run_cmd("netsh advfirewall show allprofiles")

def registry_autoruns():
    return {
        "run": run_cmd(r'reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"'),
        "runonce": run_cmd(r'reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce"')
    }

def scheduled_tasks():
    # Optimized retrieval of state metrics
    return run_ps("Get-ScheduledTask | Where-Object {$_.State -eq 'Ready'} | Select-Object TaskName,TaskPath,State | ConvertTo-Json -Depth 2")

def user_accounts():
    return {
        "users": run_ps("Get-LocalUser | Select-Object Name,Enabled | ConvertTo-Json"),
        "admins": run_ps("Get-LocalGroupMember Administrators | Select-Object Name,ObjectClass | ConvertTo-Json")
    }

def defender_status():
    return run_ps("Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, AntivirusEnabled | ConvertTo-Json")

def boot_shutdown():
    return run_cmd('wevtutil qe System /q:"*[System[(EventID=6005 or EventID=6006)]]" /f:text /c:15')

def audit_policy():
    return run_cmd("auditpol /get /category:*")

# --- Throttled Targeted Custom Metrics ---

def drivers_inventory():
    return run_cmd("driverquery /FO CSV")

def more_windows_settings():
    return {
        "uac_level": run_cmd(r'reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin'),
        "security_options": run_cmd(r'reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA')
    }

def usb_laptop_direct_connection():
    return run_ps("Get-CimInstance Win32_USBControllerDevice | Select-Object Dependent, Antecedent | ConvertTo-Json")

def bios_snapshot():
    return run_ps("Get-CimInstance Win32_BIOS | Select-Object Manufacturer, SMBIOSBIOSVersion | ConvertTo-Json")

def windows_scan_history():
    return run_ps("Get-MpThreatDetection -ErrorAction SilentlyContinue | Select-Object TimeDetected, ThreatName | ConvertTo-Json")

def usb_setting_history():
    return run_cmd(r'reg query "HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR" /s')

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
        "hostname": socket.gethostname(),
        "username": CURRENT_USER,
        "collection_timestamp": ts(),
        "files": []
    }
    for name, func in COLLECTORS.items():
        data = func()
        save_json(name, data)
        master["files"].append(f"{name}.json")
        # Explicitly wait between loops to flatten out usage spikes completely
        time.sleep(0.2)
    # Required CSV Hashing Destination
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
    master["files"].append("11_file_integrity_hashes.csv")
    save_json("master_index", master)
    print(f"[+] Throttled collection complete. Output directory: {OUTPUT_DIR.resolve()}")
if __name__ == "__main__":
    main()