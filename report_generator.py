import json
import socket
from datetime import datetime
from pathlib import Path
from collections import defaultdict

from compliance_engine import evaluate
from score_engine import calculate_scores

findings = evaluate()
scores = calculate_scores(findings)

passed = len([x for x in findings if x.get("status") == "PASS"])
failed = len([x for x in findings if x.get("status") == "FAIL"])
errors = len([x for x in findings if x.get("status") == "ERROR"])

enrichment = {}
metrics_file = Path("reports/team10_enrichment_metrics.json")
if metrics_file.exists():
    try:
        with open(metrics_file, "r", encoding="utf-8") as f:
            enrichment = json.load(f)
    except Exception as e:
        enrichment = {"error": str(e)}

detailed_findings = defaultdict(lambda: defaultdict(list))
for f in findings:
    dp = f.get("datapoint", "Unknown")
    risk = f.get("risk_category", "Info")
    detailed_findings[dp][risk].append(f)

report = {
    "hostname": socket.gethostname(),
    "generated_at": datetime.utcnow().isoformat() + "Z",
    "summary": {
        "total_controls_evaluated": len(findings),
        "passed": passed,
        "failed": failed,
        "errors": errors
    },
    "scores": scores.get("framework_scores", {}),
    "advanced_scores": {
        "overall_score": scores.get("overall_score", 0),
        "risk_impact": scores.get("risk_impact", {}),
        "evidence_confidence": scores.get("evidence_confidence", "0/18")
    },
    "team10_enrichment": enrichment,
    "findings": findings,
    "detailed_findings": detailed_findings
}

REPORTS_DIR = Path("reports")
REPORTS_DIR.mkdir(exist_ok=True)
timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
report_file = REPORTS_DIR / f"final_report_{timestamp}.json"

with open(report_file, "w", encoding="utf-8") as f:
    json.dump(report, f, indent=4, ensure_ascii=False)

print(f"[+] Report written: {report_file}")
