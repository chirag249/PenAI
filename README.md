# PenAI - Penetration Testing Automation with AI

PenAI is an advanced penetration testing automation framework enhanced with AI-powered analysis capabilities. It orchestrates security tools, normalizes findings, and applies intelligent analysis to identify and prioritize vulnerabilities.

## Key Features

- **Modular Architecture**: Organized into reconnaissance, scanning, parsing, exploitation, and reporting modules
- **AI Integration**: Google Gemini and Transformer models for vulnerability prediction and risk assessment
- **Comprehensive Tool Support**: Parsers for 40+ security tools including nmap, nuclei, sqlmap, and more
- **Safety Controls**: Destructive testing safeguards with proof-of-control mechanisms
- **Extensible Design**: Easy to add new tools, parsers, and analysis modules

## Security and Compliance Enhancements

### Cryptographic Proof of Control
Enhanced proof-of-control mechanisms with stronger cryptographic tokens and multiple validation methods.

### Comprehensive Audit Logging
Full audit trail of all system activities, user actions, and security events with JSON-formatted logs.

### Role-Based Access Control (RBAC) and MFA
Complete access control system with role management and multi-factor authentication support.

### Compliance Reporting
Automated compliance reporting for PCI DSS, HIPAA, GDPR, and SOC 2 standards.

### Data Protection
Encryption at rest and in transit, data masking, and secure data disposal capabilities.

### Privacy-Preserving Scanning
Configurable privacy settings to minimize data collection and protect sensitive information.

## Installation

```bash
# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install base dependencies
pip install -r requirements.txt

# Optional: Install AI-enhanced dependencies
pip install -r requirements-ai-enhanced.txt
```

## Usage

### Basic Non-Destructive Scan
```bash
python3 agent.py --targets https://example.com --run-id demo1
```

### Destructive Scan (with proper authorization)
```bash
# Set environment variables
export PENTEST_DESTRUCTIVE=1
export PENTEST_PROOF=your_proof_token

# Create proof file
python3 modules/tools/create_proof.py runs/example.com/demo1

# Run destructive scan
python3 agent.py --targets https://example.com --run-id demo1 --force-destructive
```

### Privacy-Preserving Scan
```bash
python3 agent.py --targets https://example.com --run-id demo1 --privacy-level enhanced
```

### With Audit Logging
```bash
python3 agent.py --targets https://example.com --run-id demo1 --enable-audit
```

## Module Structure

- `recon/` - Passive and active reconnaissance
- `scanner/` - Vulnerability scanners (XSS, SQLi, RCE)
- `parsers/` - Parsers for 40+ security tools
- `destructive/` - Exploitation modules (RCE, SQL injection)
- `ai/` - AI integration with Google Gemini and Transformer models
- `poc/` - Proof of concept generation
- `reporter/` - Reporting functionality
- `compliance/` - Security and compliance modules
- `tools/` - Tool adapters and management

## Safety Features

PenAI implements multiple safety controls for destructive testing:

1. **Environment Flag**: `PENTEST_DESTRUCTIVE=1` required
2. **Proof of Control**: Either file-based or environment token required
3. **Interactive Approval**: Manual confirmation for destructive tests
4. **Audit Logging**: Comprehensive tracking of all activities

## Security and Compliance Features

### Audit Logging
All system activities are logged with detailed metadata for compliance and security monitoring.

### Access Control
Role-based access control with multi-factor authentication options.

### Compliance Reporting
Automated generation of compliance reports for major industry standards.

### Data Protection
Encryption, masking, and secure disposal of sensitive data.

### Privacy Controls
Configurable privacy settings to minimize data collection.

## Requirements

- Python 3.8+
- Virtual environment (recommended)
- API key for Google Gemini (for AI features)
- Docker (for some tools)

## Environment Variables

- `GEMINI_API_KEY`: For AI-powered vulnerability analysis
- `PENTEST_DESTRUCTIVE=1`: Enables destructive testing
- `PENTEST_PROOF`: Token for destructive mode authorization
- `SCAN_PROFILE`: Profile to use (quick, normal, thorough, stealth)

## Output Structure

Results are organized under `runs/<target_domain>/<run_id>/`:
- `tools/`: Raw tool outputs
- `logs/`: Agent and tool logs
- `pocs/`: Proof of concept files
- `reports/`: Generated reports
- `audit/`: Audit logs (when enabled)
- `compliance/`: Compliance reports (when generated)

## Contributing

Contributions are welcome! Please see our contributing guidelines for details on how to submit patches, suggest features, or report issues.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
