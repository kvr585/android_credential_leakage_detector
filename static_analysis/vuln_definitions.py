VULN_CLASSES = [
    {
        "category": "Hardcoded Credentials",
        "severity": "HIGH",
        "keywords": ["password", "passwd", "pwd", "username", "user="],
        "patterns": [
            r"INSERT INTO.*(password|passwd)",
            r"(password|passwd)\s*=\s*['\"].+['\"]"
        ]
    },
    {
        "category": "API Keys & Tokens",
        "severity": "HIGH",
        "keywords": ["apikey", "api_key", "token", "secret", "bearer"],
        "patterns": [
            r"AIza[0-9A-Za-z\-_]{35}",        # Google API key
            r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"  # JWT
        ]
    },
    {
        "category": "Insecure Storage",
        "severity": "MEDIUM",
        "keywords": ["SharedPreferences", "sqlite", "CREATE TABLE"],
        "patterns": [
            r"CREATE TABLE.*(password|passwd)",
            r"SharedPreferences.*(password|token)"
        ]
    },
    {
        "category": "Debug Configuration",
        "severity": "LOW",
        "keywords": ["debug", "Log.d", "Log.v"],
        "patterns": [
            r"android:debuggable\s*=\s*\"true\"",
            r"Log\.(d|v)\("
        ]
    },
    {
        "category": "Insecure Network Configuration",
        "severity": "MEDIUM",
        "keywords": ["http://", "cleartext"],
        "patterns": [
            r"http://",
            r"cleartextTrafficPermitted\s*=\s*true"
        ]
    }
]
