import json
from pathlib import Path

DATA_DIR = Path("compliance_output")

def load_latest(name):
    path = DATA_DIR / f"{name}.json"
    if not path.exists():
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = json.load(f)
        if isinstance(content, list) and len(content) > 0:
            latest = content[-1]
            data = latest.get("payload_message", {}).get("data", [])
            # Some collectors nest the data inside another dict (like audit policy Configuration)
            if isinstance(data, dict):
                return [data]
            return data
        return []
    except Exception:
        return []

def extract_severity_category(item):
    if not isinstance(item, dict):
        return "Info"
    sev = item.get("Severity", "INFO").upper()
    if sev == "CRITICAL": return "Critical"
    if sev == "INVESTIGATE": return "Investigative"
    if sev == "STATISTICAL": return "Info"
    if sev == "WARNING": return "Warning"
    return "Info"

def extract_evidence(item):
    if not isinstance(item, dict):
        return str(item)
    reason = item.get("SeverityReason")
    if reason:
        return reason
    # Fallback to DetectionParameters or whole item
    params = item.get("DetectionParameters")
    if params:
        return json.dumps(params)
    return json.dumps(item)

def generate_findings(datapoint_name, data_list, controls):
    findings = []
    if not isinstance(data_list, list):
        if isinstance(data_list, dict):
            data_list = [data_list]
        else:
            data_list = []
            
    if not data_list:
        for fw, ctrl, desc in controls:
            findings.append({
                "datapoint": datapoint_name,
                "framework": fw,
                "control_id": ctrl,
                "control_description": desc,
                "status": "FAIL",
                "evidence": "Telemetry missing or empty",
                "risk_category": "Warning",
                "remediation": "Ensure collector is running and outputting data."
            })
        return findings

    for item in data_list:
        if not isinstance(item, dict):
            continue
        category = extract_severity_category(item)
        
        risk = str(item.get("RiskLevel", "LOW")).upper()
        if category == "Info" and risk in ["MEDIUM", "HIGH"]:
            category = "Warning"
            
        status = "FAIL" if category in ["Critical", "Warning"] else "PASS"
        evidence = extract_evidence(item)
        
        for fw, ctrl, desc in controls:
            findings.append({
                "id": datapoint_name,
                "datapoint": datapoint_name,
                "framework": fw,
                "control_id": ctrl,
                "control_description": desc,
                "status": status,
                "evidence": evidence,
                "risk_category": category,
                "remediation": f"Review {evidence} and apply proper configuration" if status == "FAIL" else "N/A"
            })
            
    return findings

# --- Datapoint Checks ---

def installed_software_check():
    return generate_findings("01_installed_software", load_latest("01_installed_software"), [
        ("PCI DSS v4.0", "PCI-6.2", "Malware Protection and Asset Inventory"),
        ("NIST SP 800-53 Rev. 5", "CM-8", "System Component Inventory"),
        ("DPDP Act 2023", "DPDP-SEC-01", "Security Safeguards")
    ])

def hardware_inventory_check():
    return generate_findings("04_hardware_inventory", load_latest("04_hardware_inventory"), [
        ("PCI DSS v4.0", "PCI-9.1", "Asset Inventory"),
        ("NIST SP 800-53 Rev. 5", "CM-8", "System Component Inventory"),
        ("DPDP Act 2023", "DPDP-SEC-01", "Security Safeguards")
    ])

def windows_services_check():
    return generate_findings("05_windows_services", load_latest("05_windows_services"), [
        ("PCI DSS v4.0", "PCI-2.2", "System Hardening"),
        ("NIST SP 800-53 Rev. 5", "CM-7", "Least Functionality"),
        ("DPDP Act 2023", "DPDP-MON-01", "Monitoring Controls")
    ])

def failed_logins_check():
    return generate_findings("06_failed_logins", load_latest("06_failed_logins"), [
        ("PCI DSS v4.0", "PCI-10.2", "Logging and Monitoring"),
        ("NIST SP 800-53 Rev. 5", "AC-7", "Unsuccessful Logon Attempts"),
        ("DPDP Act 2023", "DPDP-AUD-01", "Auditability")
    ])

def successful_logins_check():
    return generate_findings("07_successful_logins", load_latest("07_successful_logins"), [
        ("PCI DSS v4.0", "PCI-8.1", "Account Management"),
        ("NIST SP 800-53 Rev. 5", "AC-2", "Account Management"),
        ("DPDP Act 2023", "DPDP-ACC-01", "Access Governance")
    ])

def firewall_enabled():
    return generate_findings("10_firewall_configuration", load_latest("10_firewall_configuration"), [
        ("PCI DSS v4.0", "PCI-1.2", "Secure Configuration Management"),
        ("NIST SP 800-53 Rev. 5", "SC-7", "Boundary Protection"),
        ("DPDP Act 2023", "DPDP-SEC-02", "Security Safeguards")
    ])

def registry_autoruns_check():
    return generate_findings("12_registry_autoruns", load_latest("12_registry_autoruns"), [
        ("PCI DSS v4.0", "PCI-11.5", "Change Detection"),
        ("NIST SP 800-53 Rev. 5", "SI-7", "Software, Firmware, and Information Integrity"),
        ("DPDP Act 2023", "DPDP-MON-02", "Monitoring Controls")
    ])

def scheduled_tasks_check():
    return generate_findings("13_scheduled_tasks", load_latest("13_scheduled_tasks"), [
        ("PCI DSS v4.0", "PCI-11.5", "Change Detection"),
        ("NIST SP 800-53 Rev. 5", "SI-7", "Software, Firmware, and Information Integrity"),
        ("DPDP Act 2023", "DPDP-MON-02", "Monitoring Controls")
    ])

def admin_accounts_check():
    return generate_findings("16_user_accounts_and_privileges", load_latest("16_user_accounts_and_privileges"), [
        ("PCI DSS v4.0", "PCI-7.1", "Access Control"),
        ("NIST SP 800-53 Rev. 5", "AC-6", "Least Privilege"),
        ("DPDP Act 2023", "DPDP-ACC-02", "Access Governance")
    ])

def defender_enabled():
    return generate_findings("17_windows_defender_status", load_latest("17_windows_defender_status"), [
        ("PCI DSS v4.0", "PCI-5.1", "Malware Protection"),
        ("NIST SP 800-53 Rev. 5", "SI-3", "Malicious Code Protection"),
        ("DPDP Act 2023", "DPDP-DPC-01", "Data Protection Controls")
    ])

def boot_shutdown_check():
    return generate_findings("20_boot_shutdown_events", load_latest("20_boot_shutdown_events"), [
        ("PCI DSS v4.0", "PCI-10.6", "Logging and Monitoring"),
        ("NIST SP 800-53 Rev. 5", "AU-5", "Response to Audit Processing Failures"),
        ("DPDP Act 2023", "DPDP-AUD-02", "Auditability")
    ])

def audit_policy_check():
    return generate_findings("21_audit_policy_configuration", load_latest("21_audit_policy_configuration"), [
        ("PCI DSS v4.0", "PCI-10.1", "Logging and Monitoring"),
        ("NIST SP 800-53 Rev. 5", "AU-6", "Audit Review, Analysis, and Reporting"),
        ("DPDP Act 2023", "DPDP-AUD-03", "Auditability")
    ])

def drivers_inventory_check():
    return generate_findings("22_drivers_inventory", load_latest("22_drivers_inventory"), [
        ("PCI DSS v4.0", "PCI-2.2", "System Hardening"),
        ("NIST SP 800-53 Rev. 5", "SI-4", "Information System Monitoring"),
        ("DPDP Act 2023", "DPDP-MON-03", "Monitoring Controls")
    ])

def more_windows_settings_check():
    return generate_findings("23_more_windows_settings", load_latest("23_more_windows_settings"), [
        ("PCI DSS v4.0", "PCI-2.2", "Secure Configuration Management"),
        ("NIST SP 800-53 Rev. 5", "CM-6", "Configuration Settings"),
        ("DPDP Act 2023", "DPDP-SEC-03", "Security Safeguards")
    ])

def usb_direct_connection_check():
    return generate_findings("24_usb_direct_connection", load_latest("24_usb_direct_connection"), [
        ("PCI DSS v4.0", "PCI-3.4", "System Hardening"),
        ("NIST SP 800-53 Rev. 5", "MP-7", "Media Use"),
        ("DPDP Act 2023", "DPDP-DPC-02", "Data Protection Controls")
    ])

def bios_snapshot_check():
    return generate_findings("25_bios_snapshot", load_latest("25_bios_snapshot"), [
        ("PCI DSS v4.0", "PCI-2.2", "System Hardening"),
        ("NIST SP 800-53 Rev. 5", "CM-8", "System Component Inventory"),
        ("DPDP Act 2023", "DPDP-SEC-04", "Security Safeguards")
    ])

def windows_scan_history_check():
    return generate_findings("26_windows_scan_history", load_latest("26_windows_scan_history"), [
        ("PCI DSS v4.0", "PCI-5.2", "Malware Protection"),
        ("NIST SP 800-53 Rev. 5", "SI-3", "Malicious Code Protection"),
        ("DPDP Act 2023", "DPDP-MON-04", "Monitoring Controls")
    ])

def usb_setting_history_check():
    return generate_findings("27_usb_setting_history", load_latest("27_usb_setting_history"), [
        ("PCI DSS v4.0", "PCI-3.4", "System Hardening"),
        ("NIST SP 800-53 Rev. 5", "MP-7", "Media Use"),
        ("DPDP Act 2023", "DPDP-DPC-03", "Data Protection Controls")
    ])
