import json
import re

def parse_logcat(logcat_file):
    findings = []

    with open(logcat_file, errors="ignore") as f:
        for line in f:
            if re.search(r"(password|passwd|token|username)=\w+", line, re.IGNORECASE):
                findings.append({
                    "type": "Runtime Credential Leakage (Logcat)",
                    "severity": "HIGH",
                    "evidence": line.strip()
                })

    return findings
