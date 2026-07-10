from collections import Counter
import json
from typing import List, Dict, Any, Tuple

def get_severity_weight(severity: str) -> float:
    """Returns the weight for a given severity level."""
    sev = severity.upper()
    if sev == "CRITICAL":
        return 10.0
    elif sev == "HIGH":
        return 7.0
    elif sev == "MEDIUM":
        return 4.0
    elif sev == "LOW":
        return 2.0
    return 1.0  # INFO / Default

def get_rating(score: float) -> str:
    """Maps a 0-100 score to a qualitative rating."""
    if score >= 75.0:
        return "CRITICAL"
    elif score >= 50.0:
        return "HIGH"
    elif score >= 25.0:
        return "MEDIUM"
    elif score > 0.0:
        return "LOW"
    return "INFO"

def correlate(static_results: List[Dict[str, Any]], 
              logcat_results: List[Dict[str, Any]], 
              network_results: List[Dict[str, Any]]) -> str:
    """
    Correlates static findings with dynamic logcat/network findings.
    Computes a weighted risk score (0-100) using:
        Risk = Severity Weight * Confidence * Dynamic Evidence Bonus
    Groups findings, generates recommendations, risk reasoning, and executive summary.
    """
    processed_findings: List[Dict[str, Any]] = []
    
    # 1. Determine if dynamic evidence is present in any category
    has_logcat = len(logcat_results) > 0
    has_network = len(network_results) > 0
    has_dynamic = has_logcat or has_network

    # Dynamic findings mapping for correlation
    # We standardise dynamic findings to be structured like static ones
    for item in logcat_results:
        evidence = item.get("evidence", "")
        processed_findings.append({
            "category": "Runtime Credential Leakage (Logcat)",
            "severity": item.get("severity", "HIGH"),
            "confidence": 0.95,
            "owasp": "M1",
            "cwe": "CWE-532",
            "description": "Sensitive credentials or information were exposed in the application runtime logcat logs.",
            "recommendation": "Remove debugging logs and system printing of credentials or authentication states.",
            "reference": "https://owasp.org/www-project-mobile-top-10/2024/M1-Improper-Credential-Usage/",
            "location": "logcat logs",
            "evidence": evidence,
            "is_dynamic": True,
            "dynamic_bonus": 1.5
        })

    for item in network_results:
        evidence = item.get("evidence", "")
        processed_findings.append({
            "category": "Runtime Credential Leakage (Network)",
            "severity": item.get("severity", "CRITICAL"),
            "confidence": 1.0,
            "owasp": "M5",
            "cwe": "CWE-319",
            "description": "Sensitive tokens or passwords were transmitted over unencrypted HTTP protocol at runtime.",
            "recommendation": "Enforce TLS/HTTPS communication and encrypt all network transmission headers and bodies.",
            "reference": "https://owasp.org/www-project-mobile-top-10/2024/M5-Insecure-Communication/",
            "location": "pcap network capture",
            "evidence": evidence,
            "is_dynamic": True,
            "dynamic_bonus": 1.5
        })

    # 2. Process static results
    for item in static_results:
        cat = item.get("category", "Unknown")
        owasp = item.get("owasp", "")
        
        # Correlate static with dynamic: If static finding has a corresponding dynamic leak, apply 1.5 bonus
        # Hardcoded Credentials / API Keys correspond to Logcat leakage
        # Insecure Network corresponds to Network leakage
        bonus = 1.0
        if has_logcat and cat in ["Hardcoded Credentials", "API Keys & Tokens"]:
            bonus = 1.5
        elif has_network and cat in ["Insecure Network Configuration"]:
            bonus = 1.5

        processed_findings.append({
            "category": cat,
            "severity": item.get("severity", "LOW"),
            "confidence": item.get("confidence", 0.5),
            "owasp": owasp,
            "cwe": item.get("cwe", ""),
            "description": item.get("description", ""),
            "recommendation": item.get("recommendation", ""),
            "reference": item.get("reference", ""),
            "location": item.get("location", ""),
            "evidence": item.get("evidence", ""),
            "is_dynamic": False,
            "dynamic_bonus": bonus
        })

    # 3. Calculate finding scores and sum them
    total_finding_score = 0.0
    for f in processed_findings:
        weight = get_severity_weight(f["severity"])
        conf = f["confidence"]
        bonus = f["dynamic_bonus"]
        
        # Scoring: Score = Weight * Confidence * Dynamic Evidence Bonus
        finding_score = weight * conf * bonus
        f["finding_risk_score"] = round(finding_score, 2)
        total_finding_score += finding_score

    # Normalize overall score to 0-100
    overall_score = min(100.0, total_finding_score)
    overall_score = round(overall_score, 2)
    overall_rating = get_rating(overall_score)

    # 4. Groupings for reporting
    categories_counts = Counter([f["category"] for f in processed_findings])
    owasp_counts = Counter([f"OWASP {f['owasp']}" if f['owasp'] else "OWASP Unmapped" for f in processed_findings])
    severity_counts = Counter([f["severity"].upper() for f in processed_findings])

    # Recommendations aggregation (unique recommendations)
    recs = []
    seen_recs = set()
    for f in processed_findings:
        rec = f.get("recommendation", "")
        cat = f.get("category", "")
        owasp = f.get("owasp", "")
        if rec and rec not in seen_recs:
            seen_recs.add(rec)
            recs.append({
                "category": cat,
                "owasp": owasp,
                "recommendation": rec
            })

    # 5. Generate reasoning and executive summary
    reasoning = []
    if overall_score > 0:
        reasoning.append(f"The overall risk score is calculated as {overall_score}/100, yielding a {overall_rating} rating.")
        reasoning.append(f"A total of {len(processed_findings)} security findings were identified.")
        for sev, count in severity_counts.items():
            reasoning.append(f"Detected {count} finding(s) with {sev} severity.")
        if has_dynamic:
            reasoning.append("Dynamic analysis confirmed real-time leakage of credentials or sensitive headers, elevating risk via the Dynamic Evidence Bonus.")
    else:
        reasoning.append("No security vulnerabilities were identified in the static or dynamic analysis phases.")

    summary = (
        f"The security analysis of the application reveals a {overall_rating} risk profile "
        f"with a score of {overall_score} out of 100. "
    )
    if has_dynamic:
        summary += "The presence of verified runtime credential leaks represents a direct threat to the application ecosystem. "
    elif len(static_results) > 0:
        summary += "Static analysis revealed code-level exposures that could be leveraged if decompiled. "
    else:
        summary += "No credentials or storage vulnerabilities were detected."

    report = {
        "overall_risk": overall_rating,
        "overall_risk_score": overall_score,
        "static_findings_count": len(static_results),
        "dynamic_logcat_findings_count": len(logcat_results),
        "dynamic_network_findings_count": len(network_results),
        "static_summary": dict(Counter([f["category"] for f in static_results])),
        "category_summary": dict(categories_counts),
        "owasp_summary": dict(owasp_counts),
        "severity_summary": dict(severity_counts),
        "findings": processed_findings,
        "recommendations": recs,
        "risk_reasoning": reasoning,
        "executive_summary": summary
    }

    return json.dumps(report, indent=2)

def compare_reports(old_report: Dict[str, Any], new_report: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compares two APK analysis reports and identifies removed/added vulnerabilities,
    risk score improvements, and changes in severity/OWASP distribution.
    """
    old_findings = old_report.get("findings", [])
    new_findings = new_report.get("findings", [])
    
    # Uniquely identify findings by category and evidence to track removals/additions
    old_set = {(f.get("category"), f.get("evidence")): f for f in old_findings}
    new_set = {(f.get("category"), f.get("evidence")): f for f in new_findings}
    
    removed = []
    for key, f in old_set.items():
        if key not in new_set:
            removed.append({
                "category": f.get("category"),
                "severity": f.get("severity"),
                "evidence": f.get("evidence"),
                "location": f.get("location")
            })
            
    added = []
    for key, f in new_set.items():
        if key not in old_set:
            added.append({
                "category": f.get("category"),
                "severity": f.get("severity"),
                "evidence": f.get("evidence"),
                "location": f.get("location")
            })
            
    old_score = old_report.get("overall_risk_score", 0.0)
    new_score = new_report.get("overall_risk_score", 0.0)
    score_diff = old_score - new_score
    
    improvement_pct = 0.0
    if old_score > 0.0:
        improvement_pct = (score_diff / old_score) * 100.0
    improvement_pct = round(improvement_pct, 2)
    
    old_sevs = old_report.get("severity_summary", {})
    new_sevs = new_report.get("severity_summary", {})
    
    old_owasp = old_report.get("owasp_summary", {})
    new_owasp = new_report.get("owasp_summary", {})
    
    summary = (
        f"Compared old APK (Risk: {old_report.get('overall_risk')} - Score: {old_score}) "
        f"with new APK (Risk: {new_report.get('overall_risk')} - Score: {new_score}). "
    )
    if score_diff > 0:
        summary += f"Risk improved by {round(score_diff, 2)} points ({improvement_pct}% reduction)."
    elif score_diff < 0:
        summary += f"Risk increased by {round(abs(score_diff), 2)} points ({round(abs(improvement_pct), 2)}% increase)."
    else:
        summary += "No change in security risk score."
        
    return {
        "old_apk_risk_score": old_score,
        "new_apk_risk_score": new_score,
        "risk_difference": round(score_diff, 2),
        "risk_improvement_percentage": improvement_pct,
        "removed_vulnerabilities": removed,
        "new_vulnerabilities": added,
        "severity_comparison": {
            "old": old_sevs,
            "new": new_sevs
        },
        "owasp_comparison": {
            "old": old_owasp,
            "new": new_owasp
        },
        "comparison_summary": summary
    }


