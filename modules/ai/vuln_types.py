# modules/ai/vuln_types.py
"""
Comprehensive vulnerability type definitions and mappings for the AI classifier.
"""

# Multi-class vulnerability types with descriptions
VULNERABILITY_TYPES = {
    "xss-reflected": {
        "description": "Reflected Cross-Site Scripting",
        "severity": 3,
        "examples": [
            "Reflected script tag <script>alert(1)</script> in query parameter",
            "JavaScript injection in response body",
            "HTML injection with script execution"
        ]
    },
    "xss-stored": {
        "description": "Stored Cross-Site Scripting",
        "severity": 4,
        "examples": [
            "Persistent script injection in user profile",
            "Stored XSS in comment section",
            "Malicious script stored in database"
        ]
    },
    "xss-dom": {
        "description": "DOM-based Cross-Site Scripting",
        "severity": 3,
        "examples": [
            "Client-side script execution via DOM manipulation",
            "Unsafe innerHTML assignment",
            "Document.location used in eval"
        ]
    },
    "sqli": {
        "description": "SQL Injection",
        "severity": 4,
        "examples": [
            "Boolean-based SQL injection detected via ' OR 1=1--",
            "Union select statements in parameter",
            "Error-based SQL injection with database errors"
        ]
    },
    "sqli-blind": {
        "description": "Blind SQL Injection",
        "severity": 3,
        "examples": [
            "Time-based SQL injection with sleep functions",
            "Boolean-based blind SQL injection",
            "Content-based blind SQL injection"
        ]
    },
    "rce": {
        "description": "Remote Code Execution",
        "severity": 5,
        "examples": [
            "Remote code execution via eval(payload)",
            "Command injection in system calls",
            "Code execution through unsafe deserialization"
        ]
    },
    "lfi": {
        "description": "Local File Inclusion",
        "severity": 4,
        "examples": [
            "File inclusion via ../../etc/passwd",
            "Directory traversal to access system files",
            "Path traversal in include parameter"
        ]
    },
    "rfi": {
        "description": "Remote File Inclusion",
        "severity": 5,
        "examples": [
            "Remote file inclusion from external URLs",
            "Inclusion of remote PHP files",
            "Remote code execution via file inclusion"
        ]
    },
    "csrf": {
        "description": "Cross-Site Request Forgery",
        "severity": 3,
        "examples": [
            "CSRF vulnerability in admin panel",
            "State-changing requests without CSRF tokens",
            "Unauthorized actions via forged requests"
        ]
    },
    "info-disclosure": {
        "description": "Information Disclosure",
        "severity": 2,
        "examples": [
            "Stack trace disclosure on /debug",
            "Verbose error messages revealing system info",
            "Server headers exposing technology stack"
        ]
    },
    "auth-bypass": {
        "description": "Authentication Bypass",
        "severity": 4,
        "examples": [
            "Authentication bypass via parameter manipulation",
            "Session fixation vulnerabilities",
            "Login bypass through direct object references"
        ]
    },
    "auth-weak": {
        "description": "Weak Authentication",
        "severity": 2,
        "examples": [
            "Weak password policies",
            "Account lockout mechanism missing",
            "Session management vulnerabilities"
        ]
    },
    "ssrf": {
        "description": "Server-Side Request Forgery",
        "severity": 4,
        "examples": [
            "SSRF allowing internal network access",
            "Cloud metadata service exposure",
            "Internal service enumeration via SSRF"
        ]
    },
    "idor": {
        "description": "Insecure Direct Object Reference",
        "severity": 3,
        "examples": [
            "IDOR allowing access to other users' data",
            "Direct reference to database records",
            "Predictable resource identifiers"
        ]
    },
    "xxe": {
        "description": "XML External Entity",
        "severity": 4,
        "examples": [
            "XXE allowing file disclosure",
            "External entity processing in XML parsers",
            "SSRF via XML external entities"
        ]
    },
    "open-redirect": {
        "description": "Open Redirect",
        "severity": 2,
        "examples": [
            "Unvalidated redirects to external sites",
            "Parameter-based URL redirection",
            "Phishing attacks via open redirects"
        ]
    },
    "overflow": {
        "description": "Buffer Overflow",
        "severity": 5,
        "examples": [
            "Buffer overflow in input processing",
            "Memory corruption vulnerabilities",
            "Stack-based buffer overflows"
        ]
    },
    "insecure-crypto": {
        "description": "Insecure Cryptographic Practices",
        "severity": 3,
        "examples": [
            "Weak encryption algorithms",
            "Hardcoded cryptographic keys",
            "Insufficient key length"
        ]
    },
    "other": {
        "description": "Other Vulnerabilities",
        "severity": 1,
        "examples": [
            "Unclassified security issues",
            "Generic vulnerability reports",
            "Miscellaneous security findings"
        ]
    }
}

# Mapping from simple types to enhanced types
TYPE_MAPPING = {
    "xss": ["xss-reflected", "xss-stored", "xss-dom"],
    "sqli": ["sqli", "sqli-blind"],
    "rce": ["rce"],
    "lfi": ["lfi", "rfi"],
    "csrf": ["csrf"],
    "info": ["info-disclosure"],
    "auth": ["auth-bypass", "auth-weak"],
    "overflow": ["overflow"],
    "xxe": ["xxe"],
    "other": ["other"]
}

# Keywords for classifying vulnerability types
TYPE_KEYWORDS = {
    "xss-reflected": ["cross site scripting", "xss", "script tag", "javascript injection", "reflected", "html injection"],
    "xss-stored": ["stored xss", "persistent xss", "stored script", "persistent script"],
    "xss-dom": ["dom xss", "dom-based", "document.location", "innerhtml"],
    "sqli": ["sql injection", "sql command", "database query", "boolean-based", "union select", "error-based"],
    "sqli-blind": ["blind sql", "time-based sql", "content-based sql"],
    "rce": ["remote code execution", "rce", "code injection", "command injection", "eval(", "exec(", "system("],
    "lfi": ["path traversal", "directory traversal", "file inclusion", "../../", "lfi"],
    "rfi": ["remote file inclusion", "rfi", "remote inclusion"],
    "csrf": ["csrf", "cross-site request forgery", "forged request"],
    "info-disclosure": ["information disclosure", "sensitive information", "data exposure", "stack trace", "debug info", "server header"],
    "auth-bypass": ["authentication bypass", "login bypass", "session", "auth"],
    "auth-weak": ["weak authentication", "password policy", "session management"],
    "ssrf": ["ssrf", "server-side request forgery"],
    "idor": ["idor", "insecure direct object reference"],
    "xxe": ["xxe", "xml external entity"],
    "open-redirect": ["open redirect", "unvalidated redirect"],
    "overflow": ["buffer overflow", "memory corruption"],
    "insecure-crypto": ["weak encryption", "hardcoded key", "insecure crypto"]
}