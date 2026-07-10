import os
import re
from typing import List, Dict, Any

# Regex patterns for detecting credentials, tokens, and cookies inside network captures.
NETWORK_PATTERNS: Dict[str, str] = {
    "Plaintext Password": r"(password|passwd|pwd)\s*=\s*[a-zA-Z0-9_\-\.\@\%\+\/\=]+",
    "Plaintext Username": r"(username|user)\s*=\s*[a-zA-Z0-9_\-\.\@\+]+",
    "Authorization Header": r"(Authorization|authorization)\s*:\s*[a-zA-Z0-9_\-\.\/\+\=\s]+",
    "Bearer Token": r"Bearer\s+[a-zA-Z0-9_\-\.\/\+\=]+",
    "Cookie Header": r"(Cookie|cookie)\s*:\s*[^\r\n]+",
    "Session ID Exposure": r"(session|sessionid|session_id|sess_id)\s*=\s*[a-zA-Z0-9_\-\+\=\/]+",
    "JWT Leak": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*",
    "OAuth Token Exposure": r"(oauth_token|access_token|refresh_token)\s*=\s*[a-zA-Z0-9_\-\+\=\/]+",
    "API Key Exposure": r"(apikey|api_key)\s*=\s*[a-zA-Z0-9_\-\+\=\/]+|AIza[0-9A-Za-z\-_]{35}",
    "Secret Exposure": r"(client_secret|app_secret|secret_key)\s*=\s*[a-zA-Z0-9_\-\+\=\/]+",
    "Basic Authentication": r"Basic\s+[A-Za-z0-9+/=]{10,}"
}

def parse_pcap(pcap_file: str) -> List[Dict[str, Any]]:
    """
    Parses network packet dumps or raw HTTP captures.
    Scans for cleartext credential transmission or token leaks.
    """
    findings: List[Dict[str, Any]] = []

    if not os.path.exists(pcap_file):
        return findings

    seen_evidence = set()

    try:
        with open(pcap_file, "r", errors="ignore", encoding="utf-8") as f:
            content = f.read()

        # Check line by line to locate precise evidence lines
        lines = content.splitlines()
        for line in lines:
            line_stripped = line.strip()
            if not line_stripped:
                continue

            for label, pattern in NETWORK_PATTERNS.items():
                if re.search(pattern, line_stripped, re.IGNORECASE):
                    if line_stripped not in seen_evidence:
                        seen_evidence.add(line_stripped)
                        findings.append({
                            "type": f"Runtime Credential Leakage (Network - {label})",
                            "severity": "CRITICAL" if "Password" in label or "Basic" in label or "Bearer" in label else "HIGH",
                            "evidence": f"Cleartext transmission: {line_stripped}"
                        })
                    break

        # Fallback to general capture matching to maintain V1 compatibility
        if not findings:
            if re.search(r"(username|user)\s*=\s*\w+.*(password|passwd)\s*=\s*\w+",
                         content, re.IGNORECASE | re.DOTALL):
                findings.append({
                    "type": "Runtime Credential Leakage (Network - Credentials Combo)",
                    "severity": "CRITICAL",
                    "evidence": "Plaintext username and password parameters observed in HTTP request body."
                })

    except Exception as e:
        print(f"[!] Error parsing network capture {pcap_file}: {e}")

    return findings

