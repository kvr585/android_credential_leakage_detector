import re
from typing import List, Dict, Any

# Regex patterns for detecting sensitive data exposure in dynamic analysis logs.
DYNAMIC_PATTERNS: Dict[str, str] = {
    "Password Leak": r"(password|passwd|pwd)\s*=\s*[a-zA-Z0-9_\-\.\@\%\+\/\=]+",
    "Username Leak": r"(username|user)\s*=\s*[a-zA-Z0-9_\-\.\@\+]+",
    "Authorization Header": r"(Authorization|authorization)\s*:\s*[a-zA-Z0-9_\-\.\/\+\=\s]+",
    "Bearer Token": r"Bearer\s+[a-zA-Z0-9_\-\.\/\+\=]+",
    "Session Cookie": r"Cookie:\s*[^\r\n]+",
    "Session ID Leak": r"(session|sessionid|session_id|sess_id)\s*=\s*[a-zA-Z0-9_\-\+\=\/]+",
    "JWT Exposure": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*",
    "OAuth Token": r"(oauth_token|access_token|refresh_token)\s*=\s*[a-zA-Z0-9_\-\+\=\/]+",
    "API Key Leak": r"(apikey|api_key)\s*=\s*[a-zA-Z0-9_\-\+\=\/]+|AIza[0-9A-Za-z\-_]{35}",
    "Secret Key Leak": r"(client_secret|app_secret|secret_key)\s*=\s*[a-zA-Z0-9_\-\+\=\/]+",
    "Basic Authentication": r"Basic\s+[A-Za-z0-9+/=]{10,}"
}

def parse_logcat(logcat_file: str) -> List[Dict[str, Any]]:
    """
    Scans a logcat file for sensitive credentials or keys leaked in dynamic execution logs.
    Deduplicates findings to prevent false counts.
    """
    findings: List[Dict[str, Any]] = []
    seen_evidence = set()

    try:
        with open(logcat_file, "r", errors="ignore", encoding="utf-8") as f:
            for line in f:
                line_stripped = line.strip()
                if not line_stripped:
                    continue

                for label, pattern in DYNAMIC_PATTERNS.items():
                    if re.search(pattern, line_stripped, re.IGNORECASE):
                        if line_stripped not in seen_evidence:
                            seen_evidence.add(line_stripped)
                            findings.append({
                                "type": f"Runtime Credential Leakage (Logcat - {label})",
                                "severity": "HIGH",
                                "evidence": line_stripped
                            })
                        # Stop scanning this line after first match to avoid multiple reports for one log entry
                        break
    except Exception as e:
        print(f"[!] Error reading logcat file {logcat_file}: {e}")

    return findings

