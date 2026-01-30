from collections import Counter
import json

def correlate(static_results, logcat_results, network_results):
    categories = Counter([f["category"] for f in static_results])

    if static_results and (logcat_results or network_results):
        risk = "CRITICAL"
    elif static_results:
        risk = "HIGH"
    elif logcat_results or network_results:
        risk = "HIGH"
    else:
        risk = "LOW"

    report = {
        "overall_risk": risk,
        "static_summary": dict(categories),
        "static_findings_count": len(static_results),
        "dynamic_logcat_findings_count": len(logcat_results),
        "dynamic_network_findings_count": len(network_results),
        "risk_reasoning": [
            f"{count} finding(s) in category '{cat}'"
            for cat, count in categories.items()
        ]
    }

    return json.dumps(report, indent=2)
