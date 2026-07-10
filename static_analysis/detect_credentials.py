import re
import json
import os
from typing import List, Dict, Any
from vuln_definitions import VULN_CLASSES

INPUT_FILE = "reports/strings.txt"
OUTPUT_FILE = "reports/static_findings.json"
OWASP_MAP_FILE = "owasp_mapping.json"

def load_owasp_mapping() -> Dict[str, Any]:
    """Loads OWASP Mobile Top 10 mappings from owasp_mapping.json."""
    possible_paths = [
        OWASP_MAP_FILE,
        os.path.join(os.path.dirname(__file__), "..", OWASP_MAP_FILE),
        os.path.join(os.path.dirname(__file__), OWASP_MAP_FILE),
        "/home/veera_bhadhra/Documents/android_credential_leakage_detector/owasp_mapping.json"
    ]
    for path in possible_paths:
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
    return {}

owasp_mapping = load_owasp_mapping()
findings: List[Dict[str, Any]] = []
seen_findings = set()

if os.path.exists(INPUT_FILE):
    with open(INPUT_FILE, errors="ignore") as f:
        lines = f.readlines()
else:
    print(f"[!] Input file {INPUT_FILE} not found. Skipping static credential detection.")
    lines = []

for idx, line in enumerate(lines):
    line_stripped = line.strip()
    if not line_stripped:
        continue

    for vuln in VULN_CLASSES:
        # Quick keyword gate (performance + accuracy)
        if not any(k.lower() in line_stripped.lower() for k in vuln.get("keywords", [])):
            continue

        matched = False
        for pattern in vuln.get("patterns", []):
            try:
                if re.search(pattern, line_stripped, re.IGNORECASE):
                    matched = True
                    break
            except re.error:
                # Handle invalid regex pattern configurations gracefully
                pass

        if matched:
            category = vuln.get("category", "Unknown")
            # Deduplicate by category + evidence content
            dup_key = (category, line_stripped)
            if dup_key not in seen_findings:
                seen_findings.add(dup_key)
                
                owasp_key = vuln.get("owasp", "")
                owasp_info = owasp_mapping.get(owasp_key, {})
                
                findings.append({
                    "category": category,
                    "severity": vuln.get("severity", "LOW"),
                    "confidence": vuln.get("confidence", 0.5),
                    "owasp": owasp_key,
                    "cwe": vuln.get("cwe", ""),
                    "description": vuln.get("description") or owasp_info.get("Description", ""),
                    "recommendation": vuln.get("recommendation") or owasp_info.get("Recommendation", ""),
                    "reference": owasp_info.get("Reference", ""),
                    "location": f"strings.txt:line {idx+1}",
                    "evidence": line_stripped
                })
            # STOP after first match -> no double counting for this line
            break

# Ensure output directory exists
os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

with open(OUTPUT_FILE, "w", encoding="utf-8") as out:
    json.dump(findings, out, indent=2)

print(f"[+] Static findings written to {OUTPUT_FILE}")

