
import json

from kafka import KafkaConsumer

from collections import defaultdict

from pathlib import Path

from datetime import datetime


consumer = KafkaConsumer(

    "compliance-data",

    bootstrap_servers="localhost:9092",

    auto_offset_reset="earliest",

    value_deserializer=lambda x: json.loads(
        x.decode("utf-8")
    )
)


dashboard_file = Path("dashboard.html")


file_logs = defaultdict(list)


print("Listening for Kafka messages...")


def extract_timestamp(log):

    collection = log.get(
        "collection_time",
        {}
    )

    if isinstance(collection, dict):

        return collection.get(
            "full",
            "01-01-1970 12:00:00 AM"
        )

    return str(collection)


for message in consumer:

    data = message.value

    file_name = data.get(
        "file_name",
        "unknown"
    )

    file_logs[file_name].insert(
        0,
        data
    )

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
                indent=2,
                ensure_ascii=False
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

    <th>Username</th>

    <th>Hostname</th>

    </tr>

    """

    all_logs = []

    for fname, logs in file_logs.items():

        for log in logs:

            all_logs.append(
                (fname, log)
            )

    all_logs.sort(

        key=lambda x: datetime.strptime(

            extract_timestamp(x[1]),

            "%d-%m-%Y %I:%M:%S %p"

        ),

        reverse=True
    )

    for fname, log in all_logs:

        timestamp = extract_timestamp(log)

        username = log.get(
            "username",
            "unknown"
        )

        hostname = log.get(
            "hostname",
            "unknown"
        )

        html += f"""

        <tr>

        <td>{fname}</td>

        <td>{timestamp}</td>

        <td>{username}</td>

        <td>{hostname}</td>

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
