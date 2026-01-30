import os
import re

def parse_pcap(pcap_file):
    findings = []

    if not os.path.exists(pcap_file):
        return findings

    with open(pcap_file, errors="ignore") as f:
        content = f.read()

        # Match common credential patterns in HTTP bodies
        if re.search(r"(username|user)\s*=\s*\w+.*(password|passwd)\s*=\s*\w+",
                     content, re.IGNORECASE | re.DOTALL):
            findings.append({
                "type": "Runtime Credential Leakage (Network)",
                "severity": "CRITICAL",
                "evidence": "Plaintext credentials observed in HTTP traffic"
            })

    return findings
