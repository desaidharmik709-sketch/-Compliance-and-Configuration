"""
Throttled Assessment Core Router
Maintains strict low-overhead consumption limits (<10% CPU, minimal active RAM footprint)
"""

import time
import gc

from rules import (
    installed_software_check,
    hardware_inventory_check,
    windows_services_check,
    failed_logins_check,
    successful_logins_check,
    firewall_enabled,
    registry_autoruns_check,
    scheduled_tasks_check,
    admin_accounts_check,
    defender_enabled,
    boot_shutdown_check,
    audit_policy_check,
    drivers_inventory_check,
    more_windows_settings_check,
    usb_direct_connection_check,
    bios_snapshot_check,
    windows_scan_history_check,
    usb_setting_history_check
)

CHECKS = [
    installed_software_check,
    hardware_inventory_check,
    windows_services_check,
    failed_logins_check,
    successful_logins_check,
    firewall_enabled,
    registry_autoruns_check,
    scheduled_tasks_check,
    admin_accounts_check,
    defender_enabled,
    boot_shutdown_check,
    audit_policy_check,
    drivers_inventory_check,
    more_windows_settings_check,
    usb_direct_connection_check,
    bios_snapshot_check,
    windows_scan_history_check,
    usb_setting_history_check
]

def evaluate():
    findings = []
    
    for check_func in CHECKS:
        # Pacing delay ensures execution remains inside the 5-10% CPU baseline
        time.sleep(0.3)
        
        try:
            results = check_func()
            findings.extend(results)
        except Exception as e:
            findings.append({
                "datapoint": check_func.__name__,
                "framework": "SYSTEM",
                "control_id": "ERR-01",
                "control_description": "Execution Error",
                "status": "ERROR",
                "evidence": f"Failed to execute check: {str(e)}",
                "risk_category": "Critical",
                "remediation": "Investigate collector script logic."
            })
            
        # Free memory variables inside iteration loop to avoid allocation build-ups
        gc.collect()

    print(f"[*] Evaluation completed generating {len(findings)} detailed technical findings.")
    return findings

if __name__ == "__main__":
    evaluate()
