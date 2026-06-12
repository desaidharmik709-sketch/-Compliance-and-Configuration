
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
        return [stdout]

    if isinstance(stdout, str):
        return [{
            "raw_output": stdout
        }]

    return []


for file in sorted(OUTPUT_DIR.glob("*.json")):

    try:

        with open(file, "r", encoding="utf-8") as f:
            content = json.load(f)

        if not isinstance(content, list):
            content = [content]

        for obj in content:

            collection_time = obj.get(
                "collection_time",
                {}
            )

            username = obj.get(
                "username",
                "unknown"
            )

            hostname = obj.get(
                "hostname",
                "unknown"
            )

            telemetry = obj.get(
                "data",
                {}
            )

            stdout = telemetry.get(
                "stdout",
                []
            )

            normalized_records = normalize_stdout(stdout)

            if not normalized_records:

                normalized_records = [{
                    "message": "No stdout records"
                }]

            total = len(normalized_records)

            for idx, record in enumerate(normalized_records, start=1):

                payload = {

                    "file_name": file.name,

                    "collection_time": collection_time,

                    "username": username,

                    "hostname": hostname,

                    "record": record
                }

                producer.send(
                    "compliance-data",
                    value=payload
                )

                print(
                    f"[SENT] "
                    f"{file.name} "
                    f"{idx}/{total}"
                )

                producer.flush()

                time.sleep(0.03)

    except Exception as e:

        print(
            f"[ERROR] "
            f"{file.name}: {e}"
        )

print("\nALL LOGS SENT")
