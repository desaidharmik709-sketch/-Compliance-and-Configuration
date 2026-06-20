def calculate_scores(findings):
    frameworks = {"PCI DSS v4.0": 0, "NIST SP 800-53 Rev. 5": 0, "DPDP Act 2023": 0}
    
    # Calculate pass rates per framework
    scores = {}
    for fw in frameworks.keys():
        controls = [x for x in findings if x.get("framework") == fw]
        passed = len([x for x in controls if x.get("status") == "PASS"])
        total = len(controls)
        scores[fw] = round((passed / total) * 100, 2) if total > 0 else 0.0

    # Risk impact
    risk_impact = {
        "Critical": len([x for x in findings if x.get("risk_category") == "Critical"]),
        "Warning": len([x for x in findings if x.get("risk_category") == "Warning"]),
        "Investigative": len([x for x in findings if x.get("risk_category") == "Investigative"]),
        "Info": len([x for x in findings if x.get("risk_category") == "Info"])
    }
    
    # Base score
    total_findings = len(findings)
    total_passed = len([x for x in findings if x.get("status") == "PASS"])
    base_score = (total_passed / total_findings * 100) if total_findings > 0 else 0
    
    # Penalties
    if total_findings > 0:
        penalty = ((risk_impact["Critical"] * 5) + (risk_impact["Warning"] * 2) + (risk_impact["Investigative"] * 0.5)) / total_findings * 10
    else:
        penalty = 0
    overall_score = max(0.0, round(base_score - penalty, 2))
    
    # Datapoint coverage
    datapoints = set(x.get("datapoint") for x in findings if x.get("evidence") != "Telemetry missing or empty")
    evidence_confidence = f"{len(datapoints)}/18 datapoints securely evaluated"

    return {
        "overall_score": overall_score,
        "framework_scores": scores,
        "risk_impact": risk_impact,
        "evidence_confidence": evidence_confidence,
        "total_datapoints_evaluated": len(datapoints)
    }
