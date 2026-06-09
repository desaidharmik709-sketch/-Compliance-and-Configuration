import json
import time
from pathlib import Path
from kafka import KafkaProducer

producer = KafkaProducer(
    bootstrap_servers='localhost:9092',
    value_serializer=lambda v: json.dumps(v).encode('utf-8')
)

OUTPUT_DIR = Path("compliance_output")

for file in sorted(OUTPUT_DIR.glob("*.json")):

    try:

        with open(file, "r", encoding="utf-8") as f:
            content = json.load(f)

        if not isinstance(content, list):
            content = [content]

        for obj in content:

            collection_time = obj.get(
                "collection_time",
                ""
            )

            payloads = []

            if (
                isinstance(
                    obj.get("data", {}).get("stdout"),
                    list
                )
            ):

                for record in obj["data"]["stdout"]:

                    payloads.append({
                        "file_name": file.name,
                        "collection_time": collection_time,
                        "record": record
                    })

            else:

                payloads.append({
                    "file_name": file.name,
                    "collection_time": collection_time,
                    "record": obj
                })

            total = len(payloads)

            for idx, payload in enumerate(payloads, start=1):

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

                time.sleep(0.05)

    except Exception as e:

        print(
            f"[ERROR] "
            f"{file.name}: {e}"
        )

print("\nALL LOGS SENT")