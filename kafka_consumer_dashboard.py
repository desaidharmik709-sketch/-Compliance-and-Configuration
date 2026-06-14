import json
import time
from kafka import KafkaConsumer
from collections import defaultdict
from pathlib import Path
from datetime import datetime

# =========================
# KAFKA CONSUMER
# =========================
consumer = KafkaConsumer(
    "compliance-data",
    bootstrap_servers="localhost:9092",
    auto_offset_reset="earliest",
    value_deserializer=lambda x: json.loads(x.decode("utf-8"))
)

dashboard_file = Path("dashboard.html")

file_logs = defaultdict(list)
latest_events = []

MAX_FILE_LOGS = 50
MAX_LATEST_EVENTS = 500

print("Listening for Kafka messages...")

# =========================
# EVENT SUMMARY
# =========================
def event_summary(record):
    if not isinstance(record, dict):
        return str(record)

    priority_fields = [
        "task_name",
        "service_name",
        "process_name",
        "ProcessName",
        "name",
        "Name",
        "status",
        "message"
    ]

    for field in priority_fields:
        if field in record:
            return str(record[field])

    return json.dumps(record)[:120]

# =========================
# DASHBOARD GENERATOR
# =========================
def render_dashboard():
    total_logs = sum(len(v) for v in file_logs.values())
    total_files = len(file_logs)

    # Base HTML template structure matching your original dashboard layout styling
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Compliance Kafka Dashboard</title>
    <style>
        body {{ font-family: sans-serif; background-color: #0d1117; color: #c9d1d9; margin: 20px; }}
        h1 {{ text-align: center; color: #ffffff; }}
        .metrics-container {{ display: flex; gap: 20px; margin-bottom: 30px; }}
        .metric-card {{ background: #161b22; padding: 20px; border-radius: 6px; min-width: 150px; border: 1px solid #30363d; }}
        .metric-card h3 {{ margin: 0; color: #8b949e; font-size: 14px; }}
        .metric-card p {{ margin: 10px 0 0 0; font-size: 28px; font-weight: bold; color: #ffffff; }}
        .main-layout {{ display: flex; gap: 30px; }}
        .sidebar {{ flex: 1; max-width: 400px; background: #161b22; padding: 15px; border-radius: 6px; border: 1px solid #30363d; }}
        .content {{ flex: 2; background: #161b22; padding: 15px; border-radius: 6px; border: 1px solid #30363d; }}
        details {{ margin-bottom: 10px; background: #21262d; border-radius: 4px; padding: 10px; }}
        summary {{ font-weight: bold; cursor: pointer; color: #58a6ff; }}
        .logcard {{ background: #0d1117; padding: 10px; margin-top: 5px; border-radius: 4px; border: 1px solid #30363d; }}
        pre {{ margin: 0; font-size: 12px; overflow-x: auto; color: #e6edf3; }}
        table {{ width: 100%; border-collapse: collapse; text-align: left; }}
        th, td {{ padding: 10px; border-bottom: 1px solid #30363d; font-size: 13px; }}
        th {{ background-color: #1f6feb; color: #ffffff; }}
        tr:hover {{ background-color: #21262d; }}
    </style>
</head>
<body>

    <h1>Compliance Kafka Dashboard</h1>
    
    <div class="metrics-container">
        <div class="metric-card">
            <h3>Total Events</h3>
            <p>{total_logs}</p>
        </div>
        <div class="metric-card">
            <h3>Files</h3>
            <p>{total_files}</p>
        </div>
    </div>

    <div class="main-layout">
        <div class="sidebar">
            <h2>File Wise Logs</h2>
    """

    # =========================
    # FILE GROUPS
    # =========================
    for fname in sorted(file_logs.keys()):
        logs = file_logs[fname]
        html += f"""
            <details>
                <summary>{fname} ({len(logs)} logs)</summary>
        """
        for log in logs:
            pretty = json.dumps(log, indent=2, ensure_ascii=False)
            html += f"""
                <div class="logcard">
                    <pre>{pretty}</pre>
                </div>
            """
        html += "            </details>"

    # =========================
    # LATEST EVENTS TABLE
    # =========================
    html += """
        </div>
        <div class="content">
            <h2>Latest Events (Newest First)</h2>
            <table>
                <thead>
                    <tr>
                        <th>File</th>
                        <th>Date & Time</th>
                        <th>Host</th>
                        <th>Event</th>
                    </tr>
                </thead>
                <tbody>
    """

    for log in latest_events:
        summary = event_summary(log.get("record", {}))
        
        html += f"""
                    <tr>
                        <td>{log.get('file_name', 'unknown')}</td>
                        <td>{log.get('timestamp', 'N/A')}</td>
                        <td>{log.get('hostname', 'None')}</td>
                        <td>{summary}</td>
                    </tr>
        """

    html += """
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
    """

    dashboard_file.write_text(html, encoding="utf-8")

# =========================
# CONSUME LOOP
# =========================
for message in consumer:
    data = message.value

    file_name = data.get("file_name", "unknown")
    
    # Try parsing internal timestamp metrics, default to runtime generation if missing
    inner_record = data.get("record", {})
    if isinstance(inner_record, dict) and "TimeCreated" in inner_record:
        raw_time = inner_record.get("TimeCreated") or ""
        data["timestamp"] = raw_time.replace("T", " ").split(".")[0]
    elif isinstance(inner_record, dict) and "TimeDetected" in inner_record and inner_record.get("TimeDetected"):
        data["timestamp"] = str(inner_record.get("TimeDetected"))
    elif "timestamp" not in data:
        data["timestamp"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Insert log history payload arrays
    file_logs[file_name].insert(0, data)
    if len(file_logs[file_name]) > MAX_FILE_LOGS:
        file_logs[file_name].pop()

    latest_events.insert(0, data)
    if len(latest_events) > MAX_LATEST_EVENTS:
        latest_events.pop()

    render_dashboard()
    print(f"[RECEIVED] {file_name}")
