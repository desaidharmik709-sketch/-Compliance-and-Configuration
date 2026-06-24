import selectors
from selectors import SelectorKey

# Workaround for selectors.py raising ValueError instead of KeyError on Python 3.12+ (e.g. invalid file descriptors)
# We apply the patch to both BaseSelector and _BaseSelectorImpl to handle subclasses overriding unregister.
for selector_cls in [selectors.BaseSelector, getattr(selectors, "_BaseSelectorImpl", None)]:
    if selector_cls is not None and hasattr(selector_cls, "unregister"):
        _orig_unregister = selector_cls.unregister
        def make_safe_unregister(orig_unreg):
            def _safe_unregister(self, fileobj):
                try:
                    return orig_unreg(self, fileobj)
                except (ValueError, KeyError):
                    # If it failed (e.g., closed socket with fd=-1), search for it by object identity in registered keys
                    found_fd = None
                    if hasattr(self, "_fd_to_key"):
                        for fd, key in list(self._fd_to_key.items()):
                            if key.fileobj is fileobj:
                                found_fd = fd
                                break
                    if found_fd is not None:
                        try:
                            return orig_unreg(self, found_fd)
                        except (ValueError, KeyError):
                            pass
                    # Fallback if not found: return a dummy SelectorKey to prevent unhandled KeyError crashes in kafka-python
                    return SelectorKey(fileobj, -1, 0, None)
            return _safe_unregister
        selector_cls.unregister = make_safe_unregister(_orig_unregister)

import json
import time
from pathlib import Path
from kafka import KafkaProducer

producer = KafkaProducer(
    bootstrap_servers="localhost:9092",
    value_serializer=lambda v: json.dumps(v).encode("utf-8")
)

OUTPUT_DIR = Path("compliance_output")


def normalize_stdout(stdout):

    if stdout is None:
        return []

    if isinstance(stdout, list):
        return stdout

    if isinstance(stdout, dict):
        exploded = []
        # Explode firewall rules
        if "InboundRules" in stdout or "OutboundRules" in stdout:
            overall_severity = stdout.get("Severity", "INFO")
            for rule in stdout.get("InboundRules", []):
                rule["RuleType"] = "Inbound"
                rule["OverallSeverity"] = overall_severity
                exploded.append(rule)
            for rule in stdout.get("OutboundRules", []):
                rule["RuleType"] = "Outbound"
                rule["OverallSeverity"] = overall_severity
                exploded.append(rule)
            if not exploded:
                exploded.append(stdout)
            return exploded
            
        # Explode Audit Policy
        if "Configuration" in stdout or "RecentAuditEvents" in stdout:
            for conf in stdout.get("Configuration", []):
                conf["Type"] = "Audit Configuration"
                exploded.append(conf)
            for evt in stdout.get("RecentAuditEvents", []):
                if isinstance(evt, dict):
                    evt["Type"] = "Recent Audit Event"
                    exploded.append(evt)
            if not exploded:
                exploded.append(stdout)
            return exploded

        # Explode generic flat dictionaries into key-value pairs for better rendering, except if it's already a clean event
        if "DetectionParameters" in stdout:
            return [stdout]
            
        return [stdout]

    if isinstance(stdout, str):
        return [{
            "raw_output": stdout
        }]

    return []


def get_severity_priority(severity):
    s = str(severity).upper()
    if s == "CRITICAL": return 1
    if s == "WARNING": return 2
    if s == "STATISTICAL": return 3
    if s == "INVESTIGATIVE": return 4
    return 5

all_payloads = []

for file in sorted(OUTPUT_DIR.glob("*.json")):

    try:

        with open(file, "r", encoding="utf-8") as f:
            content = json.load(f)

        if not isinstance(content, list):
            content = [content]

        for obj in content:

            fingerprint = obj.get(
                "device_fingerprint",
                {}
            )

            payload_message = obj.get(
                "payload_message",
                {}
            )

            collection_metadata = payload_message.get(
                "collection_metadata",
                {}
            )

            telemetry = payload_message.get(
                "data",
                {}
            )

            username = collection_metadata.get(
                "username",
                "unknown"
            )

            hostname = fingerprint.get(
                "device_name",
                "unknown"
            )

            timestamp = obj.get(
                "timestamp",
                ""
            )

            telemetry = payload_message.get("data", {})

            # If telemetry is already a list, it's the new flattened format!
            if isinstance(telemetry, list):
                normalized_records = telemetry
            else:
                if isinstance(telemetry, dict) and "stdout" in telemetry:
                    stdout = telemetry.get("stdout", [])
                else:
                    stdout = telemetry
                normalized_records = normalize_stdout(stdout)

            if not normalized_records:

                normalized_records = [{
                    "message": "No stdout records"
                }]

            total = len(normalized_records)

            for idx, record in enumerate(
                normalized_records,
                start=1
            ):

                individual_severity = obj.get("severity", "INFO")
                if isinstance(record, dict):
                    if "Severity" in record:
                        individual_severity = record["Severity"]
                    elif "OverallSeverity" in record:
                        individual_severity = record["OverallSeverity"]

                kafka_payload = {
                    "file_name": file.name,
                    "event_id": obj.get("event_id", ""),
                    "event_type": obj.get("event_type", ""),
                    "severity": individual_severity,
                    "timestamp": timestamp,
                    "username": username,
                    "hostname": hostname,
                    "device_fingerprint": fingerprint,
                    "record": record
                }

                all_payloads.append(kafka_payload)

    except Exception as e:
        print(f"[ERROR] {file.name}: {e}")

# Phase 2: Deduplication
seen_hashes = set()
unique_payloads = []

for payload in all_payloads:
    unique_id = {
        "file_name": payload.get("file_name", ""),
        "event_id": payload.get("event_id", ""),
        "timestamp": payload.get("timestamp", ""),
        "record": payload.get("record", {})
    }
    unique_hash = json.dumps(unique_id, sort_keys=True, default=str)
    
    if unique_hash not in seen_hashes:
        seen_hashes.add(unique_hash)
        unique_payloads.append(payload)

# Phase 3: Priority Sorting (Severity)
unique_payloads.sort(key=lambda x: get_severity_priority(x.get("severity", "")))

# Phase 4: Efficient Sending
total = len(unique_payloads)
for idx, payload in enumerate(unique_payloads, start=1):
    producer.send("compliance-data", value=payload)
    
    print(f"[SENT] {payload['file_name']} {idx}/{total} - {payload['severity']}")
    
    # Tiny sleep every 50 messages to not completely choke the network, but much faster than before
    if idx % 50 == 0:
        time.sleep(0.01)

# Single flush at the end for maximum efficiency
producer.flush()

print("\nALL LOGS SENT")
