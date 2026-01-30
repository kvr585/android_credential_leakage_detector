import subprocess
import json
import os

def run_static(apk_path):
    os.makedirs("reports", exist_ok=True)

    # Step 1: Extract strings (also decompiles APK)
    subprocess.run(
        ["python3", "static_analysis/extract_strings.py", apk_path],
        check=True
    )

    # Step 2: Detect credentials from extracted strings
    subprocess.run(
        ["python3", "static_analysis/detect_credentials.py"],
        check=True
    )

    findings_file = "reports/static_findings.json"

    if not os.path.exists(findings_file):
        with open(findings_file, "w") as f:
            json.dump([], f)

    with open(findings_file) as f:
        return json.load(f)
