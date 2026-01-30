# Android Credential Leakage Detection System

## Overview
This project implements an **Android Credential Leakage Detection System** that analyzes Android applications (APKs) to identify potential exposure of sensitive information such as usernames, passwords, tokens, and insecure configurations.

The system primarily performs **static analysis** on APK files and optionally supports **dynamic analysis** using runtime artifacts when available. It is designed as a **command-line security analysis tool** for academic, research, and learning purposes.

---

## Features

### Static Analysis (Primary)
- Decompiles Android APKs using apktool
- Extracts strings from:
  - `strings.xml`
  - Smali bytecode
- Detects:
  - Hardcoded credentials
  - Insecure storage patterns
  - Insecure network configurations
  - API keys and sensitive tokens
- Categorizes findings with severity levels
- Generates structured JSON reports

### Dynamic Analysis (Optional)
- Supports runtime analysis if evidence is provided:
  - Android logcat output
  - Decoded network traffic
- Detects potential runtime credential leakage
- Automatically skipped if runtime files are not present

### Correlation Engine
- Correlates static and dynamic findings
- Produces a final application risk summary
- Avoids false or assumed results

---

## Project Structure

```
android-credential-leakage-detector/
├── main.py
├── static_analysis/
│   ├── analyze_apk.py
│   ├── extract_strings.py
│   ├── detect_credentials.py
│   ├── vuln_definitions.py
│   └── __init__.py
├── dynamic_analysis/
│   ├── parse_logcat.py
│   └── parse_pcap.py
├── correlation/
│   └── correlation.py
├── samples/
│   └── sample_apk.apk
├── reports/
├── requirements.txt
└── README.md
```

---

## Requirements
- Python 3.10 or higher
- apktool
- Linux (Kali Linux recommended)

---

## Installation

### Clone the Repository
```bash
git clone https://github.com/<your-username>/android-credential-leakage-detector.git
cd android-credential-leakage-detector
```

### Create and Activate Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
```

### Install Dependencies
```bash
pip install -r requirements.txt
```

---

## Usage

### Static Analysis (Default)
```bash
python main.py <apk_path> <reports_directory>
```

### Example
```bash
python main.py samples/app-debug.apk reports/
```

---

### Dynamic Analysis (Optional)

If runtime artifacts are available, place them in the `reports/` directory:

```
reports/
├── logcat_runtime.txt
├── runtime_http.txt
```

Then run the same command again:
```bash
python main.py samples/app-debug.apk reports/
```

If runtime files are missing, the tool safely skips dynamic analysis.

---

## Output

### Static Findings
- `reports/static_findings.json`

### Final Risk Report
- `reports/final_risk_report.json`

#### Example Output
```json
{
  "overall_risk": "HIGH",
  "static_summary": {
    "Hardcoded Credentials": 2,
    "Insecure Storage": 1
  },
  "dynamic_logcat_findings_count": 0,
  "dynamic_network_findings_count": 0
}
```

---

## Design Decisions
- Static analysis is the primary detection method
- Dynamic analysis is optional and evidence-based
- No assumptions or artificial findings are generated
- The tool fails safely and reports limitations clearly

---

## Limitations
- Dynamic analysis depends on externally captured runtime artifacts
- Modern Android versions restrict insecure logging and cleartext traffic
- Encrypted network traffic is not analyzed
- Intended for academic and learning use only

---

## Future Enhancements
- Automated runtime execution
- Proxy-based traffic interception (e.g., Burp Suite)
- Support for additional vulnerability classes
- Severity scoring models
- HTML or PDF report generation

---

## Intended Users
- Android security students
- Cybersecurity researchers
- Developers performing pre-release security checks

---

## Disclaimer
This tool is developed strictly for **educational and research purposes** and is not intended to replace commercial mobile security scanners.
