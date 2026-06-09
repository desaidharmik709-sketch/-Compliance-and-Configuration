import json
from kafka import KafkaConsumer
from collections import defaultdict
from pathlib import Path

consumer = KafkaConsumer(
    "compliance-data",
    bootstrap_servers="localhost:9092",
    auto_offset_reset="earliest",
    value_deserializer=lambda x: json.loads(x.decode("utf-8"))
)

dashboard_file = Path("dashboard.html")

# file wise storage
file_logs = defaultdict(list)

print("Listening for Kafka messages...")

for message in consumer:

    data = message.value

    file_name = data["file_name"]

    file_logs[file_name].insert(0, data)

    html = f"""
    <html>
    <head>
    <title>Compliance Dashboard</title>

    <style>

    body {{
        background:#0f172a;
        color:white;
        font-family:Arial;
        padding:20px;
    }}

    h1 {{
        text-align:center;
    }}

    .container {{
        display:flex;
        gap:20px;
    }}

    .left {{
        width:40%;
        overflow:auto;
        max-height:90vh;
    }}

    .right {{
        width:60%;
        overflow:auto;
        max-height:90vh;
    }}

    details {{
        background:#1e293b;
        margin-bottom:10px;
        padding:10px;
        border-radius:8px;
    }}

    summary {{
        cursor:pointer;
        font-weight:bold;
    }}

    .logcard {{
        background:#334155;
        padding:10px;
        margin-top:10px;
        border-radius:6px;
    }}

    pre {{
        white-space:pre-wrap;
        word-wrap:break-word;
    }}

    table {{
        width:100%;
        border-collapse:collapse;
    }}

    th {{
        background:#1e40af;
        padding:10px;
        border:1px solid #444;
    }}

    td {{
        border:1px solid #444;
        padding:8px;
    }}

    tr:nth-child(even) {{
        background:#1e293b;
    }}

    </style>

    </head>

    <body>

    <h1>Compliance Kafka Dashboard</h1>

    <div class="container">

        <div class="left">

            <h2>File Wise Logs</h2>
    """

    # LEFT SIDE
    for fname, logs in file_logs.items():

        html += f"""
        <details>

            <summary>
                {fname} ({len(logs)} logs)
            </summary>
        """

        for log in logs:

            pretty = json.dumps(
                log,
                indent=2
            )

            html += f"""
            <div class="logcard">

                <pre>{pretty}</pre>

            </div>
            """

        html += "</details>"

    html += """
        </div>

        <div class="right">

            <h2>Latest Logs (Newest First)</h2>

            <table>

                <tr>

                    <th>File</th>
                    <th>Collection Time</th>

                </tr>
    """

    # ALL LOGS MERGE
    all_logs = []

    for fname, logs in file_logs.items():

        for log in logs:

            all_logs.append(
                (fname, log)
            )

    # latest top
    all_logs.sort(
        key=lambda x: x[1].get(
            "collection_time",
            ""
        ),
        reverse=True
    )

    for fname, log in all_logs:

        html += f"""
        <tr>

            <td>{fname}</td>

            <td>
                {log.get("collection_time","")}
            </td>

        </tr>
        """

    html += """

            </table>

        </div>

    </div>

    </body>

    </html>
    """

    dashboard_file.write_text(
        html,
        encoding="utf-8"
    )

    print(
        f"[RECEIVED] {file_name}"
    )