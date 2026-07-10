import os
import json
from typing import List, Dict, Any

# Hardcoded fallback rules to preserve V1 compatibility if rules.json is missing or corrupt.
FALLBACK_VULN_CLASSES: List[Dict[str, Any]] = [
    {
        "category": "Hardcoded Credentials",
        "severity": "HIGH",
        "confidence": 0.90,
        "owasp": "M9",
        "cwe": "CWE-798",
        "description": "Sensitive credentials such as passwords, credentials, or usernames were found hardcoded in source strings or Smali code.",
        "recommendation": "Do not store secrets in source code. Retrieve credentials dynamically at runtime using secure APIs or utilize the Android Keystore system to protect keys.",
        "keywords": ["password", "passwd", "pwd", "username", "user="],
        "patterns": [
            r"INSERT INTO.*(password|passwd)",
            r"(password|passwd)\s*=\s*['\"].+['\"]"
        ]
    },
    {
        "category": "API Keys & Tokens",
        "severity": "HIGH",
        "confidence": 0.95,
        "owasp": "M9",
        "cwe": "CWE-798",
        "description": "Exposed API keys or token signatures (e.g., Google API keys, JWT signatures) were identified in resource strings or code.",
        "recommendation": "Use API key restriction capabilities in backend consoles and obfuscate keys. Avoid placing static keys in APK files.",
        "keywords": ["apikey", "api_key", "token", "secret", "bearer"],
        "patterns": [
            r"AIza[0-9A-Za-z\-_]{35}",
            r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
        ]
    },
    {
        "category": "Insecure Storage",
        "severity": "MEDIUM",
        "confidence": 0.80,
        "owasp": "M9",
        "cwe": "CWE-922",
        "description": "Detection of local storage models (SQLite, SharedPreferences) being constructed or queried to store unencrypted passwords or token references.",
        "recommendation": "Store highly sensitive user data securely using SQLCipher or Android's EncryptedSharedPreferences.",
        "keywords": ["SharedPreferences", "sqlite", "CREATE TABLE"],
        "patterns": [
            r"CREATE TABLE.*(password|passwd)",
            r"SharedPreferences.*(password|token)"
        ]
    },
    {
        "category": "Debug Configuration",
        "severity": "LOW",
        "confidence": 0.85,
        "owasp": "M7",
        "cwe": "CWE-489",
        "description": "Debugging is enabled in the Android Manifest or verbose logs are left active in the bytecode.",
        "recommendation": "Set android:debuggable to false in production manifest and strip verbose/debug logging prior to compilation.",
        "keywords": ["debug", "Log.d", "Log.v"],
        "patterns": [
            r"android:debuggable\s*=\s*\"true\"",
            r"Log\.(d|v)\("
        ]
    },
    {
        "category": "Insecure Network Configuration",
        "severity": "MEDIUM",
        "confidence": 0.90,
        "owasp": "M5",
        "cwe": "CWE-319",
        "description": "Cleartext HTTP endpoints or network configuration allowing cleartext traffic are defined.",
        "recommendation": "Force HTTPS usage across the application and disallow cleartext traffic by setting android:usesCleartextTraffic to false.",
        "keywords": ["http://", "cleartext"],
        "patterns": [
            r"http://",
            r"cleartextTrafficPermitted\s*=\s*true"
        ]
    }
]

def load_rules() -> List[Dict[str, Any]]:
    """
    Attempts to load vulnerability detection rules from rules.json.
    Searches in multiple possible paths and falls back to hardcoded rules on failure.
    """
    possible_paths = [
        "rules.json",
        os.path.join(os.path.dirname(__file__), "../rules.json"),
        os.path.join(os.path.dirname(__file__), "rules.json"),
        "/home/veera_bhadhra/Documents/android_credential_leakage_detector/rules.json"
    ]

    for path in possible_paths:
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    rules = json.load(f)
                    if isinstance(rules, list) and len(rules) > 0:
                        return rules
            except Exception as e:
                # Silently try next path or fallback
                pass

    return FALLBACK_VULN_CLASSES

# Define VULN_CLASSES at module level for import compatibility
VULN_CLASSES: List[Dict[str, Any]] = load_rules()

