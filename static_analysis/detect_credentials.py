import re
import json
from vuln_definitions import VULN_CLASSES

INPUT_FILE = "reports/strings.txt"
OUTPUT_FILE = "reports/static_findings.json"

findings = []

with open(INPUT_FILE, errors="ignore") as f:
    lines = f.readlines()

for idx, line in enumerate(lines):
    for vuln in VULN_CLASSES:
        # quick keyword gate (performance + accuracy)
        if not any(k.lower() in line.lower() for k in vuln["keywords"]):
            continue

        for pattern in vuln["patterns"]:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append({
                    "category": vuln["category"],
                    "severity": vuln["severity"],
                    "location": f"strings.txt:line {idx+1}",
                    "evidence": line.strip()
                })
                # STOP after first match → no double counting
                break
        else:
            continue
        break

with open(OUTPUT_FILE, "w") as out:
    json.dump(findings, out, indent=2)

print(f"[+] Static findings written to {OUTPUT_FILE}")
