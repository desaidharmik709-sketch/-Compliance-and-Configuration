import json
import socket

from datetime import datetime
from pathlib import Path

from compliance_engine import evaluate
from score_engine import calculate_scores

findings = evaluate()

scores = calculate_scores(findings)

passed = len([x for x in findings if x["status"] == "PASS"])
failed = len([x for x in findings if x["status"] == "FAIL"])
errors = len([x for x in findings if x["status"] == "ERROR"])

report = {
    "hostname": socket.gethostname(),
    "generated_at": datetime.utcnow().isoformat() + "Z",

    "summary": {
        "total_controls": len(findings),
        "passed": passed,
        "failed": failed,
        "errors": errors
    },

    "scores": scores,

    "findings": findings
}

REPORTS_DIR = Path("reports")

REPORTS_DIR.mkdir(exist_ok=True)

timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

report_file = REPORTS_DIR / f"final_report_{timestamp}.json"

with open(report_file, "w", encoding="utf-8") as f:
    json.dump(
        report,
        f,
        indent=4,
        ensure_ascii=False
    )

print(f"[+] Report written: {report_file}")