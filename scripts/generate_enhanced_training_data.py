#!/usr/bin/env python3
# scripts/generate_enhanced_training_data.py
"""
Script to generate enhanced training data for the AI model from CVE descriptions 
and vulnerability reports.
"""

from __future__ import annotations
import json
import random
from typing import List, Dict, Any
from pathlib import Path

def load_cve_data(cve_file: str) -> List[Dict[str, Any]]:
    """Load CVE data from a JSON file."""
    try:
        with open(cve_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            # Handle both array and object formats
            if isinstance(data, list):
                return data
            elif isinstance(data, dict) and 'cves' in data:
                return data['cves']
            else:
                return [data]
    except Exception as e:
        print(f"Error loading CVE data: {e}")
        return []

def extract_vulnerability_info(cve_entry: Dict[str, Any]) -> Dict[str, Any]:
    """Extract relevant vulnerability information from a CVE entry."""
    # Extract common fields
    cve_id = cve_entry.get('cve', cve_entry.get('id', ''))
    description = cve_entry.get('description', '')
    
    # Handle nested description structures
    if isinstance(description, dict):
        description = description.get('value', '') or description.get('en', '')
    elif isinstance(description, list):
        description = ' '.join(description)
    
    # Extract impact information
    impact = cve_entry.get('impact', {})
    if isinstance(impact, dict):
        cvss = impact.get('baseMetricV3', {}).get('cvssV3', {})
        severity = cvss.get('baseSeverity', 'UNKNOWN')
    else:
        severity = 'UNKNOWN'
    
    # Extract references
    references = cve_entry.get('references', [])
    if isinstance(references, list):
        urls = [ref.get('url', '') for ref in references if isinstance(ref, dict)]
    else:
        urls = []
    
    return {
        'cve_id': cve_id,
        'description': description,
        'severity': severity,
        'references': urls
    }

def classify_vulnerability_type(description: str) -> str:
    """Classify vulnerability type based on description keywords."""
    description = description.lower()
    
    # Try to import enhanced vulnerability types
    try:
        from modules.ai.vuln_types import TYPE_KEYWORDS
        
        # Classification based on enhanced type keywords
        for vuln_type, keywords in TYPE_KEYWORDS.items():
            if any(keyword in description for keyword in keywords):
                return vuln_type
    except ImportError:
        # Fallback to simple classification
        pass
    
    # Classification rules based on keywords
    if any(keyword in description for keyword in ['cross site scripting', 'xss', 'script tag', 'javascript injection', ' reflected', 'reflected xss']):
        return 'xss-reflected'
    elif any(keyword in description for keyword in ['sql injection', 'sql command', 'database query', 'boolean-based', 'union select', 'error-based']):
        return 'sqli'
    elif any(keyword in description for keyword in ['remote code execution', 'rce', 'code injection', 'command injection', 'eval(payload)', 'exec payload']):
        return 'rce'
    elif any(keyword in description for keyword in ['path traversal', 'directory traversal', 'file inclusion', '../../etc/passwd', 'lfi', 'rfi']):
        return 'lfi'
    elif any(keyword in description for keyword in ['csrf', 'cross-site request forgery']):
        return 'csrf'
    elif any(keyword in description for keyword in ['information disclosure', 'sensitive information', 'data exposure', 'stack trace', 'debug info', 'server header', 'verbose error']):
        return 'info-disclosure'
    elif any(keyword in description for keyword in ['authentication bypass', 'login bypass', 'session', 'auth']):
        return 'auth-bypass'
    elif any(keyword in description for keyword in ['buffer overflow', 'memory corruption']):
        return 'overflow'
    elif any(keyword in description for keyword in ['xxe', 'xml external entity']):
        return 'xxe'
    elif any(keyword in description for keyword in ['ssrf', 'server-side request forgery']):
        return 'ssrf'
    elif any(keyword in description for keyword in ['idor', 'insecure direct object reference']):
        return 'idor'
    elif any(keyword in description for keyword in ['xxe', 'xml external entity']):
        return 'xxe'
    elif any(keyword in description for keyword in ['open redirect', 'unvalidated redirect']):
        return 'open-redirect'
    else:
        return 'other'

def generate_training_examples(cve_data: List[Dict[str, Any]], num_examples: int = 10000) -> List[Dict[str, str]]:
    """Generate training examples from CVE data."""
    examples = []
    
    for cve_entry in cve_data:
        vuln_info = extract_vulnerability_info(cve_entry)
        description = vuln_info['description']
        cve_id = vuln_info['cve_id']
        
        if not description:
            continue
            
        # Classify vulnerability type
        vuln_type = classify_vulnerability_type(description)
        
        # Create base example
        example = {
            'text': f"CVE: {cve_id}. {description}",
            'label': vuln_type
        }
        examples.append(example)
        
        # Generate augmented examples
        augmented_examples = augment_example(example, num_augmentations=2)
        examples.extend(augmented_examples)
    
    # If we need more examples, generate synthetic ones
    if len(examples) < num_examples:
        examples = generate_synthetic_examples(examples, num_examples - len(examples))
    
    # Limit to requested number
    return examples[:num_examples]

def augment_example(example: Dict[str, str], num_augmentations: int = 2) -> List[Dict[str, str]]:
    """Augment a single example with variations."""
    augmented = []
    text = example['text']
    label = example['label']
    
    # Variations to apply
    variations = [
        lambda t: f"Vulnerability report: {t}",
        lambda t: f"Security finding: {t}",
        lambda t: f"Observed in penetration test: {t}",
        lambda t: f"{t}. Exploitation possible with standard tools.",
        lambda t: f"{t}. Risk assessment indicates high impact."
    ]
    
    # Apply random variations
    for _ in range(min(num_augmentations, len(variations))):
        variation = random.choice(variations)
        augmented.append({
            'text': variation(text),
            'label': label
        })
    
    return augmented

def generate_synthetic_examples(base_examples: List[Dict[str, str]], num_to_generate: int) -> List[Dict[str, str]]:
    """Generate synthetic examples to reach target count."""
    if not base_examples:
        return []
    
    synthetic = []
    vuln_types = list(set(example['label'] for example in base_examples))
    
    for _ in range(num_to_generate):
        # Select a random base example
        base = random.choice(base_examples)
        text = base['text']
        label = base['label']
        
        # Apply transformations
        transformations = [
            lambda t: f"Detailed analysis: {t}",
            lambda t: f"Technical details: {t}",
            lambda t: f"{t} Observed during security assessment.",
            lambda t: f"Finding: {t} Severity: {'HIGH' if label in ['rce', 'sqli', 'xss'] else 'MEDIUM'}.",
            lambda t: f"Security issue detected: {t}"
        ]
        
        transformed_text = random.choice(transformations)(text)
        
        synthetic.append({
            'text': transformed_text,
            'label': label if label in vuln_types else random.choice(vuln_types)
        })
    
    return synthetic

def save_training_data(examples: List[Dict[str, str]], output_file: str):
    """Save training data in JSONL format."""
    with open(output_file, 'w', encoding='utf-8') as f:
        for example in examples:
            f.write(json.dumps(example, ensure_ascii=False) + '\n')
    print(f"Saved {len(examples)} training examples to {output_file}")

def main():
    """Main function to generate enhanced training data."""
    # Configuration
    cve_files = [
        # Add paths to your CVE data files here
        # "data/cve_data.json",
        # "data/nvd_data.json"
    ]
    
    output_file = "datasets/enhanced_training_data.jsonl"
    target_examples = 10000
    
    # Create output directory if it doesn't exist
    Path(output_file).parent.mkdir(parents=True, exist_ok=True)
    
    # Load CVE data
    all_cve_data = []
    for cve_file in cve_files:
        if Path(cve_file).exists():
            cve_data = load_cve_data(cve_file)
            all_cve_data.extend(cve_data)
            print(f"Loaded {len(cve_data)} CVE entries from {cve_file}")
        else:
            print(f"Warning: CVE file {cve_file} not found")
    
    # If no CVE data available, create sample data for demonstration
    if not all_cve_data:
        print("No CVE data found, generating sample data for demonstration...")
        all_cve_data = generate_sample_cve_data()
    
    # Generate training examples
    print(f"Generating {target_examples} training examples...")
    examples = generate_training_examples(all_cve_data, target_examples)
    
    # Save training data
    save_training_data(examples, output_file)
    print(f"Enhanced training data generation complete! Generated {len(examples)} examples.")
    
    # Also generate a smaller sample for quick testing
    sample_file = "datasets/sample_training_data.jsonl"
    sample_examples = examples[:1000] if len(examples) > 1000 else examples
    save_training_data(sample_examples, sample_file)
    print(f"Sample training data saved to {sample_file} with {len(sample_examples)} examples.")
    
    # Print statistics
    vuln_types = [example['label'] for example in examples]
    unique_types = set(vuln_types)
    print(f"\nDataset Statistics:")
    print(f"  Total examples: {len(examples)}")
    print(f"  Unique vulnerability types: {len(unique_types)}")
    print(f"  Vulnerability types: {sorted(unique_types)}")
    
    # Count examples per type
    type_counts = {}
    for vuln_type in vuln_types:
        type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1
    
    print(f"\nExamples per vulnerability type:")
    for vuln_type in sorted(type_counts.keys()):
        print(f"  {vuln_type}: {type_counts[vuln_type]}")

def generate_sample_cve_data() -> List[Dict[str, Any]]:
    """Generate sample CVE data for demonstration purposes."""
    sample_cves = []
    
    # XSS vulnerabilities (1000 examples)
    xss_descriptions = [
        "Cross-site scripting vulnerability in web application allows remote attackers to inject arbitrary web script or HTML via the {param} parameter.",
        "Reflected cross-site scripting vulnerability in {component} page. Script tag <script>alert(1)</script> reflected in query parameter.",
        "Stored XSS vulnerability in {feature} feature allows persistent script injection in user-generated content.",
        "DOM-based XSS in {component} component due to unsafe document.write usage.",
        "XSS vulnerability in {api_endpoint} API endpoint through improper input sanitization."
    ]
    
    for i in range(1000):
        param = random.choice(["search", "query", "id", "user", "page"])
        component = random.choice(["user profile", "search results", "admin panel", "dashboard", "settings"])
        feature = random.choice(["comment", "message", "post", "review", "feedback"])
        api_endpoint = random.choice(["/api/users", "/api/posts", "/api/comments", "/api/search"])
        
        description = random.choice(xss_descriptions).format(
            param=param, component=component, feature=feature, api_endpoint=api_endpoint
        ) + f" Instance {i} with unique identifier {random.randint(1000, 9999)}" + f" Instance {i} with unique identifier {random.randint(1000, 9999)}"
        
        sample_cves.append({
            "cve": f"CVE-2023-{10000+i}",
            "description": description,
            "impact": {
                "baseMetricV3": {
                    "cvssV3": {
                        "baseSeverity": random.choice(["LOW", "MEDIUM"])
                    }
                }
            }
        })
    
    # SQL Injection vulnerabilities (1000 examples)
    sqli_descriptions = [
        "SQL injection vulnerability in {feature} feature allows remote attackers to execute arbitrary SQL commands.",
        "Boolean-based SQL injection detected via ' OR 1=1-- in {param} parameter. Also observed: union select statements.",
        "Error-based SQL injection in {component} component with detailed database error messages.",
        "Blind SQL injection in {api_endpoint} API through time-based techniques.",
        "SQL injection vulnerability in {feature} form due to lack of parameterized queries."
    ]
    
    for i in range(1000):
        feature = random.choice(["login", "search", "filter", "update profile", "delete account"])
        param = random.choice(["id", "username", "email", "password", "token"])
        component = random.choice(["user management", "data export", "reporting", "analytics"])
        api_endpoint = random.choice(["/api/login", "/api/search", "/api/data"])
        
        description = random.choice(sqli_descriptions).format(
            feature=feature, param=param, component=component, api_endpoint=api_endpoint
        ) + f" Instance {i} with unique identifier {random.randint(1000, 9999)}"
        
        sample_cves.append({
            "cve": f"CVE-2023-{11000+i}",
            "description": description,
            "impact": {
                "baseMetricV3": {
                    "cvssV3": {
                        "baseSeverity": random.choice(["HIGH", "CRITICAL"])
                    }
                }
            }
        })
    
    # RCE vulnerabilities (800 examples)
    rce_descriptions = [
        "Remote code execution vulnerability in {component} component due to unsafe deserialization.",
        "Remote code execution via eval(payload) in {handler} handler. Also observed: exec payload execution.",
        "Command injection vulnerability in {feature} feature through unsanitized system calls.",
        "RCE vulnerability in {service} service due to insecure file upload handling.",
        "Code injection in {api_endpoint} API through improper input validation."
    ]
    
    for i in range(800):
        component = random.choice(["image processing", "file upload", "data import", "report generation"])
        handler = random.choice(["user agent", "file parser", "data processor", "request handler"])
        feature = random.choice(["file upload", "data import", "report generation", "backup"])
        service = random.choice(["image processor", "document converter", "data analyzer"])
        api_endpoint = random.choice(["/api/upload", "/api/process", "/api/generate"])
        
        description = random.choice(rce_descriptions).format(
            component=component, handler=handler, feature=feature, service=service, api_endpoint=api_endpoint
        ) + f" Instance {i} with unique identifier {random.randint(1000, 9999)}"
        
        sample_cves.append({
            "cve": f"CVE-2023-{12000+i}",
            "description": description,
            "impact": {
                "baseMetricV3": {
                    "cvssV3": {
                        "baseSeverity": "CRITICAL"
                    }
                }
            }
        })
    
    # LFI/Path traversal vulnerabilities (800 examples)
    lfi_descriptions = [
        "Path traversal vulnerability allows attackers to read arbitrary files on the server through {param} parameter.",
        "File inclusion via ../../etc/passwd observed in {component} component. Also observed: directory traversal.",
        "Local file inclusion vulnerability in {feature} feature through improper path validation.",
        "Directory traversal in {api_endpoint} API allowing access to system configuration files.",
        "Path traversal vulnerability in {service} service due to lack of proper input sanitization."
    ]
    
    for i in range(800):
        param = random.choice(["file", "path", "include", "template", "config"])
        component = random.choice(["file download", "template engine", "configuration loader"])
        feature = random.choice(["file download", "template rendering", "configuration loading"])
        api_endpoint = random.choice(["/api/download", "/api/load", "/api/render"])
        service = random.choice(["file server", "template engine", "config manager"])
        
        description = random.choice(lfi_descriptions).format(
            param=param, component=component, feature=feature, api_endpoint=api_endpoint, service=service
        ) + f" Instance {i} with unique identifier {random.randint(1000, 9999)}"
        
        sample_cves.append({
            "cve": f"CVE-2023-{12800+i}",
            "description": description,
            "impact": {
                "baseMetricV3": {
                    "cvssV3": {
                        "baseSeverity": "HIGH"
                    }
                }
            }
        })
    
    # CSRF vulnerabilities (600 examples)
    csrf_descriptions = [
        "Cross-site request forgery vulnerability in {component} allows unauthorized {action} actions.",
        "CSRF vulnerability in {feature} feature due to missing anti-CSRF tokens.",
        "State-changing request in {api_endpoint} API vulnerable to CSRF attacks.",
        "Cross-site request forgery in {service} service allowing {action} without proper validation.",
        "CSRF protection bypass in {component} component through {technique} technique."
    ]
    
    for i in range(600):
        component = random.choice(["admin panel", "user settings", "payment form", "account management"])
        action = random.choice(["delete", "modify", "update", "transfer"])
        feature = random.choice(["account deletion", "profile update", "payment processing", "data export"])
        api_endpoint = random.choice(["/api/delete", "/api/update", "/api/transfer"])
        service = random.choice(["account manager", "payment processor", "data handler"])
        technique = random.choice(["token prediction", "referential check bypass", "origin validation"])
        
        description = random.choice(csrf_descriptions).format(
            component=component, action=action, feature=feature, 
            api_endpoint=api_endpoint, service=service, technique=technique
        ) + f" Instance {i} with unique identifier {random.randint(1000, 9999)}"
        
        sample_cves.append({
            "cve": f"CVE-2023-{13600+i}",
            "description": description,
            "impact": {
                "baseMetricV3": {
                    "cvssV3": {
                        "baseSeverity": "MEDIUM"
                    }
                }
            }
        })
    
    # Information disclosure (600 examples)
    info_descriptions = [
        "Stack trace disclosure on {endpoint} reveals framework versions and internal paths.",
        "Verbose error messages in {component} expose sensitive system information.",
        "Information disclosure in {api_endpoint} API through detailed error responses.",
        "Server headers in {service} service expose technology stack and versions.",
        "Debug information disclosure in {feature} feature during error conditions."
    ]
    
    for i in range(600):
        endpoint = random.choice(["/debug", "/error", "/status", "/health"])
        component = random.choice(["error handler", "debug module", "logging system"])
        api_endpoint = random.choice(["/api/error", "/api/debug", "/api/status"])
        service = random.choice(["web server", "application server", "database server"])
        feature = random.choice(["error reporting", "debug mode", "logging"])
        
        description = random.choice(info_descriptions).format(
            endpoint=endpoint, component=component, api_endpoint=api_endpoint, 
            service=service, feature=feature
        ) + f" Instance {i} with unique identifier {random.randint(1000, 9999)}"
        
        sample_cves.append({
            "cve": f"CVE-2023-{14200+i}",
            "description": description,
            "impact": {
                "baseMetricV3": {
                    "cvssV3": {
                        "baseSeverity": random.choice(["LOW", "MEDIUM"])
                    }
                }
            }
        })
    
    # Authentication bypass (500 examples)
    auth_descriptions = [
        "Authentication bypass vulnerability allows attackers to access {resource} without proper credentials.",
        "Session fixation vulnerability in {feature} feature allows session hijacking.",
        "Login bypass through direct object reference manipulation in {component}.",
        "Authentication weakness in {api_endpoint} API due to insufficient validation.",
        "Privilege escalation in {service} service allowing unauthorized {action} access."
    ]
    
    for i in range(500):
        resource = random.choice(["admin resources", "user data", "system settings", "payment information"])
        feature = random.choice(["login", "session management", "account recovery", "password reset"])
        component = random.choice(["user authentication", "session handler", "access control"])
        api_endpoint = random.choice(["/api/login", "/api/auth", "/api/session"])
        service = random.choice(["auth service", "user manager", "access control"])
        action = random.choice(["admin", "delete", "modify", "view"])
        
        description = random.choice(auth_descriptions).format(
            resource=resource, feature=feature, component=component, 
            api_endpoint=api_endpoint, service=service, action=action
        ) + f" Instance {i} with unique identifier {random.randint(1000, 9999)}"
        
        sample_cves.append({
            "cve": f"CVE-2023-{14800+i}",
            "description": description,
            "impact": {
                "baseMetricV3": {
                    "cvssV3": {
                        "baseSeverity": "HIGH"
                    }
                }
            }
        })
    
    # SSRF (400 examples)
    ssrf_descriptions = [
        "Server-side request forgery vulnerability allows attackers to make requests to internal {service}.",
        "SSRF in {feature} feature through {param} parameter manipulation.",
        "Internal service enumeration via SSRF in {component} component.",
        "Cloud metadata service exposure through SSRF vulnerability in {api_endpoint}.",
        "SSRF protection bypass in {service} service using {technique} technique."
    ]
    
    for i in range(400):
        service = random.choice(["database", "cache", "internal API", "metadata service"])
        feature = random.choice(["URL preview", "file import", "webhook", "data fetch"])
        param = random.choice(["url", "source", "endpoint", "target"])
        component = random.choice(["data importer", "URL fetcher", "webhook handler"])
        api_endpoint = random.choice(["/api/fetch", "/api/import", "/api/preview"])
        technique = random.choice(["DNS rebinding", "redirect chaining", "protocol smuggling"])
        
        description = random.choice(ssrf_descriptions).format(
            service=service, feature=feature, param=param, component=component, 
            api_endpoint=api_endpoint, technique=technique
        ) + f" Instance {i} with unique identifier {random.randint(1000, 9999)}"
        
        sample_cves.append({
            "cve": f"CVE-2023-{15300+i}",
            "description": description,
            "impact": {
                "baseMetricV3": {
                    "cvssV3": {
                        "baseSeverity": "HIGH"
                    }
                }
            }
        })
    
    # IDOR (400 examples)
    idor_descriptions = [
        "Insecure direct object reference allows unauthorized access to other users' {resource}.",
        "IDOR vulnerability in {feature} feature through {param} parameter manipulation.",
        "Direct reference to {resource} records without proper access control in {component}.",
        "Predictable resource identifiers in {api_endpoint} API allowing unauthorized {action}.",
        "IDOR protection bypass in {service} service through {technique} technique."
    ]
    
    for i in range(400):
        resource = random.choice(["data", "files", "accounts", "records"])
        feature = random.choice(["data access", "file download", "record viewing", "profile access"])
        param = random.choice(["id", "user_id", "file_id", "record_id"])
        component = random.choice(["data handler", "file manager", "record viewer"])
        api_endpoint = random.choice(["/api/data", "/api/files", "/api/records"])
        action = random.choice(["access", "view", "download", "modify"])
        service = random.choice(["data service", "file manager", "record handler"])
        technique = random.choice(["sequence prediction", "brute force", "parameter tampering"])
        
        description = random.choice(idor_descriptions).format(
            resource=resource, feature=feature, param=param, component=component, 
            api_endpoint=api_endpoint, action=action, service=service, technique=technique
        ) + f" Instance {i} with unique identifier {random.randint(1000, 9999)}"
        
        sample_cves.append({
            "cve": f"CVE-2023-{15700+i}",
            "description": description,
            "impact": {
                "baseMetricV3": {
                    "cvssV3": {
                        "baseSeverity": "MEDIUM"
                    }
                }
            }
        })
    
    # XXE (300 examples)
    xxe_descriptions = [
        "XML external entity processing vulnerability allows file disclosure through {feature} feature.",
        "XXE vulnerability in {component} component through {param} parameter.",
        "External entity processing in {api_endpoint} API allowing {action}.",
        "XML parser in {service} service vulnerable to XXE attacks.",
        "XXE protection bypass in {component} through {technique} technique."
    ]
    
    for i in range(300):
        feature = random.choice(["file upload", "data import", "configuration loading", "report generation"])
        component = random.choice(["XML parser", "data processor", "config loader"])
        param = random.choice(["xml", "data", "config", "file"])
        api_endpoint = random.choice(["/api/upload", "/api/import", "/api/process"])
        action = random.choice(["file disclosure", "SSRF", "DoS"])
        service = random.choice(["data processor", "config manager", "report engine"])
        technique = random.choice(["entity expansion", "parameter entities", "blind XXE"])
        
        description = random.choice(xxe_descriptions).format(
            feature=feature, component=component, param=param, 
            api_endpoint=api_endpoint, action=action, service=service, technique=technique
        ) + f" Instance {i} with unique identifier {random.randint(1000, 9999)}"
        
        sample_cves.append({
            "cve": f"CVE-2023-{16100+i}",
            "description": description,
            "impact": {
                "baseMetricV3": {
                    "cvssV3": {
                        "baseSeverity": "HIGH"
                    }
                }
            }
        })
    
    # Open Redirect (300 examples)
    open_redirect_descriptions = [
        "Open redirect vulnerability in {component} allows redirection to external {target}.",
        "Unvalidated redirect in {feature} feature through {param} parameter.",
        "URL redirection vulnerability in {api_endpoint} API to {target}.",
        "Open redirect protection bypass in {service} service using {technique}.",
        "Phishing attacks via open redirect in {component} component."
    ]
    
    for i in range(300):
        component = random.choice(["login page", "logout handler", "redirect service", "auth module"])
        target = random.choice(["malicious sites", "phishing pages", "external domains"])
        feature = random.choice(["login redirect", "logout redirect", "navigation", "callback"])
        param = random.choice(["next", "redirect", "url", "target"])
        api_endpoint = random.choice(["/api/redirect", "/api/callback", "/api/login"])
        service = random.choice(["redirect service", "auth handler", "navigation manager"])
        technique = random.choice(["domain bypass", "protocol smuggling", "path confusion"])
        
        description = random.choice(open_redirect_descriptions).format(
            component=component, target=target, feature=feature, param=param, 
            api_endpoint=api_endpoint, service=service, technique=technique
        ) + f" Instance {i} with unique identifier {random.randint(1000, 9999)}"
        
        sample_cves.append({
            "cve": f"CVE-2023-{16400+i}",
            "description": description,
            "impact": {
                "baseMetricV3": {
                    "cvssV3": {
                        "baseSeverity": "MEDIUM"
                    }
                }
            }
        })
    
    return sample_cves

if __name__ == "__main__":
    main()