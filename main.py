import os
import sys
from static_analysis.analyze_apk import run_static
from dynamic_analysis.parse_logcat import parse_logcat
from dynamic_analysis.parse_pcap import parse_pcap
from correlation.correlation import correlate

if len(sys.argv) < 3:
    print("Usage: python main.py <apk_path> <runtime_dir>")
    sys.exit(1)

apk_path = sys.argv[1]
runtime_dir = sys.argv[2]

logcat_path = f"{runtime_dir}/logcat_runtime.txt"
pcap_path = f"{runtime_dir}/runtime_http.txt"

# --- Static analysis ---
static_results = run_static(apk_path)

# --- Dynamic analysis (DEFENSIVE) ---
if os.path.exists(logcat_path):
    logcat_results = parse_logcat(logcat_path)
else:
    print("[!] logcat file not found – dynamic log analysis skipped")
    logcat_results = []

if os.path.exists(pcap_path):
    network_results = parse_pcap(pcap_path)
else:
    print("[!] pcap file not found – dynamic network analysis skipped")
    network_results = []

# --- Correlation ---
final_report = correlate(static_results, logcat_results, network_results)

with open("reports/final_risk_report.json", "w") as f:
    f.write(final_report)

print("[+] Analysis complete. Report generated.")
