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
import uuid
import winreg
import platform
import sys
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
    hostname = socket.gethostname()
    ip_address = "127.0.0.1"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip_address = s.getsockname()[0]
        s.close()
    except Exception:
        try:
            ip_address = socket.gethostbyname(hostname)
        except Exception:
            pass

    try:
        mac_hex = iter(f"{uuid.getnode():012x}")
        mac_address = ":".join(a + b for a, b in zip(mac_hex, mac_hex))
    except Exception:
        mac_address = "00:00:00:00:00:00"

    manufacturer = "Unknown"
    model = "Unknown"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\BIOS") as key:
            manufacturer = winreg.QueryValueEx(key, "SystemManufacturer")[0].strip()
            model = winreg.QueryValueEx(key, "SystemProductName")[0].strip()
    except Exception:
        pass

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
    time.sleep(0.15)
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            shell=True
        )
        stdout = result.stdout.strip()
        if not stdout:
            return []
        return {"raw_output": stdout}
    except Exception as e:
        return {"error": str(e)}


def run_ps(command):
    time.sleep(0.15)
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
            capture_output=True,
            text=True
        )
        stdout = result.stdout.strip()
        if not stdout:
            return []
        parsed = parse_maybe_json(stdout)
        if isinstance(parsed, (list, dict)):
            return parsed
        return {"raw_output": parsed}
    except Exception as e:
        return {"error": str(e)}


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

        if old_hash != data_hash:
            old_data = active_entry.get("payload_message", {}).get("data")
            if old_data is not None:
                legacy_hash = generate_data_hash(old_data)
                if legacy_hash == data_hash:
                    old_hash = legacy_hash

        if old_hash == data_hash:
            existing_data[active_index] = new_entry
            print(f"[UPDATED] {name} -> Existing active entry replaced.")
        else:
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
            
            active_entry["event_id"] = next_previous_id
            existing_data.append(new_entry)
            print(f"[ARCHIVED] {name} -> Previous active entry archived as {next_previous_id}. New entry appended.")
    else:
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

# --- Standard Severity Engine ---

class SeverityEngine:
    AUTHORIZED_USB_VIDS = ["0951", "046d"] # Placeholders for whitelisted VIDs

    @staticmethod
    def get_highest_severity(data):
        levels = {"INFO": 0, "STATISTICAL": 1, "INVESTIGATE": 2, "CRITICAL": 3}
        highest = "INFO"
        if isinstance(data, dict):
            highest = data.get("Severity", "INFO")
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    sev = item.get("Severity", "INFO")
                    if levels.get(sev, 0) > levels.get(highest, 0):
                        highest = sev
        return highest

    @staticmethod
    def process_scan_history(data):
        if not isinstance(data, dict): return data
        count = data.get("ThreatCount", 0)
        remediation = str(data.get("RemediationStatus", ""))
        
        if count > 0 and remediation == "Failed":
            sev, reason = "CRITICAL", "Active malware not remediated"
        elif count > 0:
            sev, reason = "INVESTIGATE", f"Detected {count} threats"
        else:
            sev, reason = "INFO", "No threats detected"
            
        data["DetectionParameters"] = {"ThreatCount": count, "RemediationStatus": remediation}
        data["Severity"] = sev
        data["SeverityReason"] = reason
        return data

    @staticmethod
    def process_bios_snapshot(data):
        if not isinstance(data, dict): return data
        sb = data.get("SecureBootEnabled", False)
        tpm = data.get("TPM_Present", False)
        comp = data.get("Firmware_Compliance", False)
        age = data.get("BIOS_Age_Days", 0)
        
        if not tpm:
            sev, reason = "CRITICAL", "TPM Missing"
        elif not comp:
            sev, reason = "CRITICAL", "Firmware Compliance Failed"
        elif not sb:
            sev, reason = "INVESTIGATE", "SecureBoot Disabled"
        elif age > 730:
            sev, reason = "INVESTIGATE", "BIOS Age > 730 Days"
        else:
            sev, reason = "INFO", "BIOS Compliant"
            
        data["DetectionParameters"] = {"SecureBootEnabled": sb, "TPM_Present": tpm, "Firmware_Compliance": comp, "BIOS_Age_Days": age}
        data["Severity"] = sev
        data["SeverityReason"] = reason
        return data

    @staticmethod
    def process_usb(data):
        if not isinstance(data, list): return data
        for r in data:
            if not isinstance(r, dict): continue
            is_storage = r.get("IsStorageDevice", False)
            vid = str(r.get("VID", ""))
            
            r["IsAuthorized"] = vid in SeverityEngine.AUTHORIZED_USB_VIDS
            
            if r["IsAuthorized"]:
                sev, reason = "INFO", "Approved Device"
            elif is_storage:
                sev, reason = "CRITICAL", "Unauthorized Storage Device"
            else:
                sev, reason = "INVESTIGATE", "Unauthorized HID Device"
                
            r["DetectionParameters"] = {"IsStorageDevice": is_storage, "IsAuthorized": r["IsAuthorized"]}
            r["Severity"] = sev
            r["SeverityReason"] = reason
        return data

    @staticmethod
    def process_windows_settings(data):
        if not isinstance(data, dict): return data
        score = data.get("Score", 100)
        if score >= 90:
            sev, reason = "INFO", "Compliant Settings"
        elif score >= 70:
            sev, reason = "INVESTIGATE", "Minor Compliance Deviations"
        else:
            sev, reason = "CRITICAL", "Major Compliance Deviations"
            
        data["DetectionParameters"] = {"Score": score}
        data["Severity"] = sev
        data["SeverityReason"] = reason
        return data

    @staticmethod
    def process_software(data):
        if not isinstance(data, list): return data
        remote_tools = ["anydesk", "teamviewer", "rustdesk", "logmein", "vnc"]
        dump_tools = ["mimikatz", "psexec", "netcat", "nc.exe", "wireshark", "cain"]
        
        for r in data:
            if not isinstance(r, dict): continue
            name = str(r.get("DisplayName", "")).lower()
            is_remote = any(t in name for t in remote_tools)
            is_dump = any(t in name for t in dump_tools)
            
            if is_dump:
                sev, reason, risk = "CRITICAL", "Credential Dumping / Hack Tool Detected", "HIGH"
            elif is_remote:
                sev, reason, risk = "INVESTIGATE", "Remote Access Software Detected", "MEDIUM"
            else:
                sev, reason, risk = "INFO", "Legitimate Software", "LOW"
                
            r["RiskLevel"] = risk
            r["DetectionParameters"] = {"IsRemoteTool": is_remote, "IsHackTool": is_dump}
            r["Severity"] = sev
            r["SeverityReason"] = reason
        return data

    @staticmethod
    def process_failed_logins(data):
        if not isinstance(data, list): return data
        ip_counts = {}
        for r in data:
            if not isinstance(r, dict): continue
            ip = r.get("SourceIPAddress", "Unknown")
            if ip and ip != "Unknown" and ip != "-":
                ip_counts[ip] = ip_counts.get(ip, 0) + 1
            
        for r in data:
            if not isinstance(r, dict): continue
            ip = r.get("SourceIPAddress", "Unknown")
            count = ip_counts.get(ip, 1) if (ip != "Unknown" and ip != "-") else 1
            
            if count >= 20:
                sev, reason = "CRITICAL", ">= 20 failures from same source in 15 mins"
            elif count >= 5:
                sev, reason = "INVESTIGATE", ">= 5 failures from same source in 15 mins"
            else:
                sev, reason = "INFO", "Single or few login failures"
                
            r["DetectionParameters"] = {"FailureCount": count, "SourceIPAddress": ip}
            r["Severity"] = sev
            r["SeverityReason"] = reason
        return data

    @staticmethod
    def process_successful_logins(data):
        if not isinstance(data, list): return data
        for r in data:
            if not isinstance(r, dict): continue
            elevated = r.get("ElevatedToken", False)
            ip = str(r.get("SourceIPAddress", "-"))
            is_unusual = ip not in ["-", "127.0.0.1", "::1"]
            
            if elevated and is_unusual:
                sev, reason = "CRITICAL", "Administrative login from unusual host"
            elif elevated:
                sev, reason = "INVESTIGATE", "Elevated login"
            else:
                sev, reason = "INFO", "Normal login"
                
            r["DetectionParameters"] = {"ElevatedToken": elevated, "IsUnusualHost": is_unusual}
            r["Severity"] = sev
            r["SeverityReason"] = reason
        return data

    @staticmethod
    def process_drivers(data):
        if not isinstance(data, list): return data
        for r in data:
            if not isinstance(r, dict): continue
            signed = r.get("IsSigned", False)
            kernel = r.get("KernelMode", False)
            
            if not signed and kernel:
                sev, reason, risk = "CRITICAL", "Unsigned Kernel Driver", "HIGH"
            elif not signed:
                sev, reason, risk = "INVESTIGATE", "Unsigned User Driver", "MEDIUM"
            else:
                sev, reason, risk = "INFO", "Signed Driver", "LOW"
                
            r["RiskLevel"] = risk
            r["DetectionParameters"] = {"IsSigned": signed, "KernelMode": kernel}
            r["Severity"] = sev
            r["SeverityReason"] = reason
        return data

    @staticmethod
    def process_tasks(data):
        if not isinstance(data, list): return data
        for r in data:
            if not isinstance(r, dict): continue
            hidden = r.get("Hidden", False)
            action = str(r.get("Action", "")).lower()
            in_temp = "appdata" in action or "temp" in action
            
            if hidden and in_temp:
                sev, reason = "CRITICAL", "Hidden Task running from Temp/AppData"
            elif hidden:
                sev, reason = "INVESTIGATE", "Hidden Task"
            else:
                sev, reason = "INFO", "Normal Task"
                
            r["DetectionParameters"] = {"Hidden": hidden, "InTemp": in_temp}
            r["Severity"] = sev
            r["SeverityReason"] = reason
        return data

    @staticmethod
    def process_autoruns(data):
        if not isinstance(data, list): return data
        for r in data:
            if not isinstance(r, dict): continue
            sig = str(r.get("SignatureStatus", "Unknown"))
            exe = str(r.get("Executable", "")).lower()
            in_temp = "appdata" in exe or "temp" in exe
            unsigned = (sig != "Signed" and sig != "Valid")
            
            if unsigned and in_temp:
                sev, reason = "CRITICAL", "Unsigned Autorun in Temp/AppData"
            elif unsigned:
                sev, reason = "INVESTIGATE", "Unsigned Autorun"
            else:
                sev, reason = "INFO", "Signed Autorun"
                
            r["DetectionParameters"] = {"Unsigned": unsigned, "InTemp": in_temp}
            r["Severity"] = sev
            r["SeverityReason"] = reason
        return data

    @staticmethod
    def process_accounts(data):
        if not isinstance(data, list): return data
        for r in data:
            if not isinstance(r, dict): continue
            days = r.get("DaysInactive", 0)
            is_admin = r.get("AccountType", "") == "Admin"
            enabled = r.get("Enabled", False)
            
            if enabled and days <= 30:
                r["AccountStatus"] = "ACTIVE"
            else:
                r["AccountStatus"] = "INACTIVE"
                
            if enabled and is_admin and days > 90:
                sev, reason = "CRITICAL", "Dormant Admin Account >90 Days"
            elif enabled and not is_admin and days > 180:
                sev, reason = "INVESTIGATE", "Dormant Standard User >180 Days"
            else:
                sev, reason = "INFO", "Normal Account Status"
                
            r["DetectionParameters"] = {"DaysInactive": days, "IsAdmin": is_admin, "Enabled": enabled}
            r["Severity"] = sev
            r["SeverityReason"] = reason
        return data

    @staticmethod
    def process_firewall(data):
        if not isinstance(data, dict): return data
        enabled = data.get("FirewallEnabled", False)
        inbound = data.get("InboundRules", [])
        
        any_any = False
        if isinstance(inbound, list):
            for r in inbound:
                if isinstance(r, dict) and r.get("Action") == "Allow" and str(r.get("RemotePort")).lower() == "any":
                    any_any = True
                    break
                
        if not enabled:
            sev, reason = "CRITICAL", "Firewall Disabled"
        elif any_any:
            sev, reason = "CRITICAL", "Allow Any/Any Rule Found"
        elif isinstance(inbound, list) and len(inbound) > 20:
            sev, reason = "INVESTIGATE", "Excessive Open Ports"
        else:
            sev, reason = "INFO", "Fully Compliant"
            
        data["DetectionParameters"] = {"FirewallEnabled": enabled, "HasAnyAnyRule": any_any}
        data["Severity"] = sev
        data["SeverityReason"] = reason
        return data


# --- Throttled Compliance JSON Collectors ---

def installed_software():
    return run_ps(r"""
    Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue | 
    Where-Object { $_.DisplayName } | 
    Select-Object DisplayName, DisplayVersion, Publisher, @{Name='InstallDate';Expression={$_.InstallDate}}, InstallLocation, 
    @{Name='EstimatedSizeMB';Expression={if ($_.EstimatedSize) {[math]::Round($_.EstimatedSize / 1024, 2)} else {0}}}, 
    @{Name='DigitalSignature';Expression={'Unknown'}} |
    ConvertTo-Json -Depth 3
    """)

def hardware_inventory():
    return run_ps("Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer, Model, Name, NumberOfProcessors, NumberOfLogicalProcessors, TotalPhysicalMemory, SystemType, SystemFamily, Domain, PrimaryOwnerName, BootupState | ConvertTo-Json -Depth 2")

def windows_services():
    return run_ps("Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,StartName,PathName | ConvertTo-Json -Depth 2")

def failed_logins():
    return run_ps(r"""
    Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 50 -ErrorAction SilentlyContinue |
    ForEach-Object {
        $xml = [xml]$_.ToXml()
        $data = @{}
        $xml.Event.EventData.Data | ForEach-Object { $data[$_.Name] = $_.'#text' }
        @{
            TimeCreated = $_.TimeCreated.ToString("o")
            Id = $_.Id
            TargetUserName = $data['TargetUserName']
            SourceIPAddress = $data['IpAddress']
            WorkstationName = $data['WorkstationName']
            LogonType = $data['LogonType']
            FailureReason = $data['FailureReason']
            StatusCode = $data['Status']
        }
    } | ConvertTo-Json -Depth 3
    """)

def successful_logins():
    return run_ps(r"""
    Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} -MaxEvents 50 -ErrorAction SilentlyContinue |
    ForEach-Object {
        $xml = [xml]$_.ToXml()
        $data = @{}
        $xml.Event.EventData.Data | ForEach-Object { $data[$_.Name] = $_.'#text' }
        @{
            TimeCreated = $_.TimeCreated.ToString("o")
            TargetUserName = $data['TargetUserName']
            SourceIPAddress = $data['IpAddress']
            Workstation = $data['WorkstationName']
            LogonType = $data['LogonType']
            AuthenticationPackage = $data['AuthenticationPackageName']
            ElevatedToken = if ($data['ElevatedToken'] -eq '%%1842') { $true } else { $false }
        }
    } | ConvertTo-Json -Depth 3
    """)

def firewall_config():
    return run_ps(r"""
    $profile = Get-NetFirewallProfile -Name Domain,Private,Public -ErrorAction SilentlyContinue | Where-Object Enabled -eq $true
    $rules = Get-NetFirewallRule -Enabled True -ErrorAction SilentlyContinue | Select-Object -First 50
    $inbound = @()
    $outbound = @()
    foreach ($r in $rules) {
        $obj = @{
            RuleName = $r.DisplayName
            Direction = $r.Direction.ToString()
            Action = $r.Action.ToString()
            Protocol = "Any"
            LocalPort = "Any"
            RemotePort = "Any"
            Enabled = $true
        }
        if ($r.Direction -eq "Inbound") { $inbound += $obj } else { $outbound += $obj }
    }
    
    @{
        FirewallEnabled = if ($profile) { $true } else { $false }
        ComplianceStatus = if ($profile) { "PASS" } else { "FAIL" }
        InboundRuleCount = $inbound.Count
        OutboundRuleCount = $outbound.Count
        InboundRules = $inbound
        OutboundRules = $outbound
    } | ConvertTo-Json -Depth 4
    """)

def registry_autoruns():
    return run_ps(r"""
    $autoruns = @()
    $paths = @('HKLM:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run')
    foreach ($p in $paths) {
        $items = Get-ItemProperty $p -ErrorAction SilentlyContinue
        if ($items) {
            foreach ($prop in $items.psobject.properties) {
                if ($prop.Name -notmatch "^PS[A-Z]") {
                    $autoruns += @{
                        Path = $p
                        Executable = $prop.Value
                        Publisher = "Unknown"
                        SignatureStatus = "Unknown"
                        Hash = "Unknown"
                    }
                }
            }
        }
    }
    $autoruns | ConvertTo-Json -Depth 3
    """)

def scheduled_tasks():
    return run_ps(r"""
    Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {$_.State -eq 'Ready' -or $_.State -eq 'Running'} | Select-Object -First 100 |
    Select-Object TaskName, TaskPath, State, Author, 
    @{Name='LastRunTime';Expression={$_.LastRunTime}}, 
    @{Name='NextRunTime';Expression={$_.NextRunTime}}, 
    @{Name='Action';Expression={($_.Actions | Select-Object -ExpandProperty Execute -ErrorAction SilentlyContinue) -join ','}}, 
    @{Name='RunAsUser';Expression={$_.Principal.UserId}}, 
    @{Name='Hidden';Expression={$_.Settings.Hidden}} |
    ConvertTo-Json -Depth 3
    """)

def user_accounts():
    return run_ps(r"""
    Get-LocalUser -ErrorAction SilentlyContinue | Select-Object @{Name='UserName';Expression={$_.Name}}, 
    @{Name='AccountType';Expression={if ($_.Description -match "Admin") {"Admin"} else {"Standard"}}},
    Enabled, 
    @{Name='CreatedDate';Expression={""}}, 
    @{Name='LastLoginDate';Expression={if ($_.LastLogon) { $_.LastLogon.ToString("yyyy-MM-dd HH:mm:ss") } else { "" }}}, 
    @{Name='PasswordLastSet';Expression={if ($_.PasswordLastSet) { $_.PasswordLastSet.ToString("yyyy-MM-dd HH:mm:ss") } else { "" }}},
    @{Name='DaysInactive';Expression={if ($_.LastLogon) { (New-TimeSpan -Start $_.LastLogon -End (Get-Date)).Days } else { 999 }}} |
    ConvertTo-Json -Depth 3
    """)

def defender_status():
    return run_ps("Get-MpComputerStatus | Select-Object AMProductVersion,DefenderSignaturesOutOfDate,RealTimeProtectionEnabled,AntivirusEnabled,AntispywareEnabled,IsTamperProtected,BehaviorMonitorEnabled | ConvertTo-Json -Depth 2")

def boot_shutdown():
    return run_ps(r"""
    Get-WinEvent -FilterHashtable @{LogName='System';ID=6005,6006} -ErrorAction SilentlyContinue |
    Select-Object TimeCreated, Id, ProviderName, MachineName | ConvertTo-Json -Depth 3
    """)

def audit_policy():
    return run_ps(r"""
    $result = @{
        Configuration = @()
        RecentAuditEvents = @()
    }

    $audit = auditpol /get /category:* 2>&1
    if ($audit -match "privilege is not held") {
        $result.Configuration += @{ Error = "Requires Administrator Privileges" }
    } else {
        $lines = $audit | Select-Object -Skip 3
        $category = "Unknown"
        foreach ($line in $lines) {
            $trimmed = $line.Trim()
            if ($trimmed -ne "") {
                if ($line -match "^\S") {
                    $category = $trimmed
                } else {
                    $parts = $trimmed -split '\s{2,}'
                    if ($parts.Count -ge 2) {
                        $result.Configuration += @{
                            Category = $category
                            Subcategory = $parts[0]
                            Setting = $parts[1]
                        }
                    }
                }
            }
        }
    }

    $events = Get-WinEvent -FilterHashtable @{LogName='Security'} -MaxEvents 20 -ErrorAction SilentlyContinue
    if ($events) {
        foreach ($e in $events) {
            $result.RecentAuditEvents += @{
                LogName = $e.LogName
                Source = $e.ProviderName
                EventID = $e.Id
                TaskCategory = $e.TaskDisplayName
                Level = $e.LevelDisplayName
                Keywords = if ($e.KeywordsDisplayNames) { $e.KeywordsDisplayNames -join ", " } else { "N/A" }
                User = if ($e.UserId) { $e.UserId.Value } else { "N/A" }
                OpCode = $e.OpcodeDisplayName
                Computer = $e.MachineName
            }
        }
    } else {
        $result.RecentAuditEvents += @{ Error = "Requires Administrator Privileges or No Events Found" }
    }

    $result | ConvertTo-Json -Depth 4
    """)

def drivers_inventory():
    return run_ps(r"""
    Get-CimInstance Win32_PnPSignedDriver -ErrorAction SilentlyContinue | Where-Object { $_.DeviceName } | Select-Object -First 200 |
    Select-Object DeviceName, DriverVersion, @{Name='IsSigned';Expression={$_.IsSigned}}, 
    @{Name='DriverHash';Expression={'Unknown'}}, Signer, 
    @{Name='DriverAgeDays';Expression={if ($_.DriverDate) { (New-TimeSpan -Start $_.DriverDate -End (Get-Date)).Days } else { 0 }}},
    @{Name='KernelMode';Expression={$true}} | ConvertTo-Json -Depth 3
    """)

def more_windows_settings():
    return run_ps(r"""
    $uac = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue
    $lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
    $rdp = Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -ErrorAction SilentlyContinue
    
    $score = 100
    if ($uac.EnableLUA -ne 1) { $score -= 20 }
    if ($rdp.fDenyTSConnections -ne 1) { $score -= 20 }
    if ($lsa.RunAsPPL -ne 1) { $score -= 10 }
    
    @{
        Control = "WIN-SET"
        Status = if ($score -ge 90) { "PASS" } else { "FAIL" }
        Score = $score
    } | ConvertTo-Json -Depth 2
    """)

def usb_laptop_direct_connection():
    return run_ps(r"""
    $usb = Get-CimInstance Win32_PnPEntity -ErrorAction SilentlyContinue | Where-Object { $_.DeviceID -match 'USBSTOR' -or $_.DeviceID -match 'USB' } | Select-Object -First 50
    $res = @()
    foreach ($u in $usb) {
        $isStorage = ($u.DeviceID -match 'USBSTOR')
        $res += @{
            Name = $u.Name
            Manufacturer = $u.Manufacturer
            DeviceID = $u.DeviceID
            VID = if ($u.DeviceID -match 'VID_([0-9A-F]{4})') { $matches[1] } else { "" }
            PID = if ($u.DeviceID -match 'PID_([0-9A-F]{4})') { $matches[1] } else { "" }
            Vendor = $u.Manufacturer
            FirstSeen = "Unknown"
            LastSeen = "Unknown"
            DriverName = $u.Service
            Class = $u.PNPClass
            IsStorageDevice = $isStorage
            IsAuthorized = $false
        }
    }
    $res | ConvertTo-Json -Depth 3
    """)

def bios_snapshot():
    return run_ps(r"""
    $bios = Get-CimInstance Win32_BIOS -ErrorAction SilentlyContinue
    $tpm = Get-Tpm -ErrorAction SilentlyContinue
    $sb = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
    
    $biosDate = $bios.ReleaseDate
    $age = 0
    if ($biosDate) { $age = (New-TimeSpan -Start $biosDate -End (Get-Date)).Days }
    
    @{
        Manufacturer = $bios.Manufacturer
        SMBIOSBIOSVersion = $bios.SMBIOSBIOSVersion
        SecureBootEnabled = if ($sb -eq $true) { $true } else { $false }
        TPM_Present = if ($tpm -and $tpm.TpmPresent) { $true } else { $false }
        TPM_Version = if ($tpm -and $tpm.TpmPresent) { "2.0" } else { "None" }
        BIOS_Age_Days = $age
        Firmware_Compliance = if (($sb -eq $true) -and ($tpm -and $tpm.TpmPresent) -and ($age -le 730)) { $true } else { $false }
    } | ConvertTo-Json -Depth 2
    """)

def windows_scan_history():
    return run_ps(r"""
    $status = Get-MpComputerStatus -ErrorAction SilentlyContinue
    $threats = Get-MpThreat -ErrorAction SilentlyContinue | Select-Object -Property ThreatName, ActionSuccess
    $threatNames = @()
    $remediation = "None"
    if ($threats) {
        foreach ($t in $threats) {
            $threatNames += $t.ThreatName
            if ($t.ActionSuccess -eq $false) { $remediation = "Failed" }
            elseif ($remediation -ne "Failed") { $remediation = "Success" }
        }
    }
    @{
        QuickScanStart = if ($status.QuickScanStartTime) { '{0:yyyy-MM-dd HH:mm:ss}' -f $status.QuickScanStartTime } else { "" }
        QuickScanEnd = if ($status.QuickScanEndTime) { '{0:yyyy-MM-dd HH:mm:ss}' -f $status.QuickScanEndTime } else { "" }
        LastThreatDetected = $status.AMThreatLastDetectTime
        ThreatCount = if ($threats) { @($threats).Count } else { 0 }
        ThreatNames = $threatNames
        RemediationStatus = $remediation
        EngineVersion = $status.AMEngineVersion
        SignatureVersion = $status.AMProductVersion
    } | ConvertTo-Json -Depth 3
    """)

def usb_setting_history():
    return run_ps("Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\\*\\*' -ErrorAction SilentlyContinue | Select-Object FriendlyName, DeviceDesc, Mfg, HardwareID | ConvertTo-Json -Depth 2")


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

        event_type_label = "Compliance Metric Collection"

        if name == "01_installed_software":
            data = SeverityEngine.process_software(data)
            event_type_label = "Installed Software Assessment"
        elif name == "06_failed_logins":
            data = SeverityEngine.process_failed_logins(data)
            event_type_label = "Failed Login Monitoring"
        elif name == "07_successful_logins":
            data = SeverityEngine.process_successful_logins(data)
            event_type_label = "Successful Login Monitoring"
        elif name == "10_firewall_configuration":
            data = SeverityEngine.process_firewall(data)
            event_type_label = "Firewall Assessment"
        elif name == "12_registry_autoruns":
            data = SeverityEngine.process_autoruns(data)
            event_type_label = "Autoruns Assessment"
        elif name == "13_scheduled_tasks":
            data = SeverityEngine.process_tasks(data)
            event_type_label = "Scheduled Tasks Assessment"
        elif name == "16_user_accounts_and_privileges":
            data = SeverityEngine.process_accounts(data)
            event_type_label = "User Account Assessment"
        elif name == "22_drivers_inventory":
            data = SeverityEngine.process_drivers(data)
            event_type_label = "Drivers Assessment"
        elif name == "23_more_windows_settings":
            data = SeverityEngine.process_windows_settings(data)
            event_type_label = "Windows Settings Assessment"
        elif name == "24_usb_direct_connection":
            data = SeverityEngine.process_usb(data)
            event_type_label = "USB Connection Assessment"
        elif name == "25_bios_snapshot":
            data = SeverityEngine.process_bios_snapshot(data)
            event_type_label = "BIOS Security Assessment"
        elif name == "26_windows_scan_history":
            data = SeverityEngine.process_scan_history(data)
            event_type_label = "Threat Detection"
        elif name == "20_boot_shutdown_events":
            event_type_label = "System Availability Metrics"

        severity_level = SeverityEngine.get_highest_severity(data)

        # Fallbacks for non-enhanced schemas
        if severity_level == "INFO" and name not in [
            "01_installed_software", "06_failed_logins", "07_successful_logins", 
            "10_firewall_configuration", "12_registry_autoruns", "13_scheduled_tasks",
            "16_user_accounts_and_privileges", "22_drivers_inventory", "23_more_windows_settings",
            "24_usb_direct_connection", "25_bios_snapshot", "26_windows_scan_history"
        ]:
            if name == "20_boot_shutdown_events": severity_level = "STATISTICAL"
            elif name in ["17_windows_defender_status", "27_usb_setting_history"]: severity_level = "INVESTIGATE"

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
