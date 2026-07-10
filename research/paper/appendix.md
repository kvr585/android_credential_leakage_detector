# Appendix: Supplementary Technical Details (ACLDS V2.0)

This appendix provides configuration extracts from the Android Credential Leakage Detection System (ACLDS) V2.0 rule definitions and mapping databases.

## 1. Vulnerability Rule Definition Sample (`rules.json`)
The following JSON block represents the standard structure of an ACLDS intelligence rule. Rules are evaluated sequentially by compiling the list of regular expression patterns and walking Smali bytecode blocks.

```json
[
  {
    "id": "RULE_001",
    "name": "Hardcoded AWS Access Key",
    "category": "Hardcoded Credentials",
    "severity": "CRITICAL",
    "confidence": "HIGH",
    "owasp_mapping": "M9",
    "cwe": "CWE-798",
    "description": "Plaintext Amazon Web Services (AWS) Access Key ID detected in code assets.",
    "recommendation": "Remove AWS keys from Smali bytecode. Transition authorization to AWS Identity and Access Management (IAM) temporary role credentials.",
    "keywords": ["aws", "key", "access"],
    "patterns": [
      "(?i)(?:aws|amazon|access_key)[\'"]?\s*[:=]\s*[\'"](AKIA[0-9A-Z]{16})[\'"]"
    ]
  },
  {
    "id": "RULE_013",
    "name": "Cleartext Network Traffic",
    "category": "Insecure Network Configuration",
    "severity": "HIGH",
    "confidence": "HIGH",
    "owasp_mapping": "M5",
    "cwe": "CWE-319",
    "description": "Cleartext HTTP request patterns identified, exposing packets to eavesdropping.",
    "recommendation": "Configure Android Network Security Config file (network_security_config.xml) to enforce cleartextTrafficPermitted="false". Force TLS/HTTPS connections.",
    "keywords": ["http://"],
    "patterns": [
      "http://[a-zA-Z0-9\.\-]+(?:/.*)?"
    ]
  }
]
```

## 2. OWASP Mobile Top 10 Mapping Schema (`owasp_mapping.json`)
The mapping registry aligns vulnerability identifiers to the OWASP Mobile security framework, providing descriptions and remediation advice.

```json
{
  "OWASP_M5": {
    "title": "Insecure Communication",
    "risk": "HIGH",
    "remediation": "Configure TLS/SSL across all network requests. Prevent cleartext HTTP parameters, enforce pinning, and reject invalid certificates."
  },
  "OWASP_M9": {
    "title": "Reverse Engineering",
    "risk": "MEDIUM",
    "remediation": "Do not store secrets, private API tokens, or user passwords in static files. Use ProGuard/DexGuard to obfuscate smali code."
  }
}
```
