# PenAI - Penetration Testing Automation Scaffold

PenAI is a comprehensive penetration testing automation framework that integrates multiple security tools with AI-powered analysis capabilities. It provides a structured approach to reconnaissance, scanning, exploitation, and reporting while maintaining strict safety controls.

## Features

- **Modular Architecture**: Organized modules for reconnaissance, scanning, exploitation, and reporting
- **AI Integration**: Uses Google Gemini for vulnerability prediction and reasoning
- **Tool Integration**: Supports over 40 security tools through dedicated adapters and parsers
- **Safety Controls**: Built-in safeguards for destructive testing with explicit operator approval
- **Comprehensive Reporting**: Generates detailed findings and summary reports in multiple formats
- **Extensible Design**: Easy to add new tools, parsers, and scanners
- **CI/CD Integration**: Professional-grade GitHub Actions and GitLab CI/CD pipelines
- **Real-time Notifications**: Slack and Microsoft Teams integration for immediate alerts
- **Vulnerability Intelligence**: NVD/CVE integration for up-to-date vulnerability data
- **Threat Intelligence**: Integration with threat feeds for enhanced detection capabilities

## Prerequisites

- Python 3.7 or higher
- Virtual environment (recommended)
- Target system(s) for testing with proper authorization

## Setup

1. **Clone the repository** (if not already done):
   ```bash
   git clone <repository-url>
   cd PENTEST_AI
   ```

2. **Create and activate a virtual environment**:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

## Dependencies

The main dependencies include:
- `httpx` - For HTTP requests
- `fastapi` - For API interface
- `uvicorn` - ASGI server
- `jinja2` - Templating engine
- `beautifulsoup4` and `lxml` - HTML parsing
- `pydantic` - Data validation
- `weasyprint` - PDF generation
- `python-dotenv` - Environment variable management
- `requests` - HTTP library for intelligence and notification integrations

## Basic Usage

### Non-Destructive Scan (Default)

Run a basic non-destructive scan against a target:

```bash
python3 agent.py --targets https://testphp.vulnweb.com --run-id demo1
```

This will:
1. Perform passive and active reconnaissance
2. Crawl the target website
3. Fingerprint technologies in use
4. Discover parameters and endpoints
5. Test for common vulnerabilities (XSS, SQLi)
6. Generate reports in the `runs/<domain>/<run-id>/reports/` directory

### Scan Options

- `--targets`: One or more target URLs (required)
- `--run-id`: Unique identifier for this scan run (default: "run01")
- `--config-dir`: Path to directory containing custom tool configuration files
- `--scan-profile`: Scan profile to use (choices: "quick", "normal", "thorough", "stealth")
- `--clear-logs`: Remove previous runs for this domain before starting

### Output Structure

Results are stored in the `runs/` directory, organized by target domain and run ID:
```
runs/
└── <target_domain>/
    └── <run_id>/
        ├── generated/
        │   ├── tools/           # Raw tool outputs
        │   └── ...              # Generated artifacts
        ├── logs/                # Execution logs
        ├── pocs/                # Proof of concepts
        ├── reports/             # Final reports
        │   ├── final_report.json # Detailed findings
        │   ├── summary_report.json # Summary report
        │   └── ...              # Additional report formats
        └── run_meta.json        # Run metadata
```

## Destructive Testing

For advanced testing that may modify or exploit target systems:

### Safety Requirements

Destructive testing requires explicit operator approval through two mechanisms:
1. Environment variable: `PENTEST_DESTRUCTIVE=1`
2. Proof of control: Either a proof file or environment token

### Creating Proof of Control

Generate a proof file for destructive testing:

```bash
python3 modules/tools/create_proof.py runs/<target_domain>/<run_id>
```

This creates a `proof_of_control.txt` file and provides export instructions.

### Running Destructive Tests

After setting up proof of control:

```bash
export PENTEST_DESTRUCTIVE=1
export PENTEST_PROOF=<token_from_create_proof>
python3 agent.py --targets <target> --run-id <id> --force-destructive
```

### Destructive Options

- `--force-destructive`: Skip interactive confirmation and force destructive phase
- `--skip-destructive`: Skip destructive phase entirely

## AI Integration

PenAI integrates with Google Gemini for enhanced vulnerability analysis:
- Vulnerability prediction based on findings
- AI-powered reasoning for correlation and triage
- Automated report enhancement

To use AI features, configure your Gemini API key in the environment:
```bash
export GEMINI_API_KEY=your_api_key_here
```

## Module Structure

```
modules/
├── ai/           # AI integration (predictor, reasoner, trainer)
├── destructive/  # Exploitation modules (sqlmap, RCE tester)
├── parsers/      # Tool output parsers (40+ security tools)
├── poc/          # Proof of concept generation and management
├── recon/        # Reconnaissance modules (passive, active)
├── reporter/     # Reporting functionality
├── scanner/      # Vulnerability scanners (XSS, SQLi, RCE)
├── tools/        # Tool adapters and configuration
└── ...           # Core modules (logger, scope, etc.)
```

## Continuous Integration & Deployment

PenAI now includes professional-grade CI/CD integration for automated security testing:

### GitHub Actions

- Multi-Python version testing (3.8, 3.9, 3.10, 3.11)
- Automated security scans on push, pull request, and scheduled events
- Artifact archiving for 1 week
- Failure notifications to Slack and Teams

### GitLab CI/CD

- Multi-stage pipeline (security-scan, report, notify)
- Enhanced scanning with AI capabilities
- Comprehensive notifications
- Artifact management with expiration policies

To enable CI/CD integration, configure the appropriate webhook URLs in your repository/CI settings.

## Notifications

PenAI supports real-time notifications via popular collaboration platforms:

- **Slack**: Configure `SLACK_WEBHOOK_URL` environment variable
- **Microsoft Teams**: Configure `TEAMS_WEBHOOK_URL` environment variable

Notifications include scan status, findings count, and duration information.

## Vulnerability Intelligence

PenAI integrates with external intelligence sources to enhance vulnerability detection:

- **NVD/CVE Integration**: Automatic correlation of findings with CVE data
- **Threat Intelligence**: Integration with threat feeds for emerging threats
- **Exploit Correlation**: Cross-referencing with exploit databases

To enable intelligence features, set your `NVD_API_KEY` environment variable.

## Customization

### Adding New Tools

1. Create an adapter in `modules/tools/` following existing patterns
2. Create a parser in `modules/parsers/` to process tool output
3. The agent will automatically discover and use the new tool

### Configuration Profiles

Tools support multiple configuration profiles:
- `quick`: Fast scanning with minimal tests
- `normal`: Standard scanning with balanced coverage
- `thorough`: Comprehensive scanning with extensive tests
- `stealth`: Low-and-slow scanning to avoid detection

Select a profile using `--scan-profile` or set `PENAI_SCAN_PROFILE` environment variable.

## Docker Deployment

The framework can be containerized for easier deployment (planned feature).

## Security Best Practices

1. **Authorization**: Only scan systems you have explicit permission to test
2. **Scope**: Clearly define and adhere to testing scope boundaries
3. **Proof of Control**: Always use proof files or tokens for destructive testing
4. **Environment Isolation**: Use virtual environments to prevent dependency conflicts
5. **Logging**: Review logs regularly for unexpected behavior
6. **Updates**: Keep dependencies updated with security patches

## Troubleshooting

- If tools are not being discovered, check that adapter files end with `_adapter.py`
- For AI features, ensure `GEMINI_API_KEY` is properly set
- For PDF generation issues, verify WeasyPrint dependencies are installed
- For destructive testing, verify both environment variables are set correctly

## Contributing

1. Fork the repository
2. Create a feature branch
3. Implement your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is intended for authorized security testing only. Unauthorized use is prohibited.

## Testing Sites

For practicing and testing the PenAI framework, here are some legitimate vulnerable web applications that are specifically designed for security testing:

### Deliberately Vulnerable Applications

1. **DVWA (Damn Vulnerable Web Application)**
   - URL: http://www.dvwa.co.uk/ or set up locally
   - Description: PHP/MySQL web application that is extremely vulnerable to various attacks

2. **WebGoat**
   - URL: https://owasp.org/www-project-webgoat/
   - Description: Intentionally insecure application maintained by OWASP for security education

3. **Juice Shop**
   - URL: https://owasp.org/www-project-juice-shop/
   - Description: Modern and sophisticated insecure web application by OWASP

4. **bWAPP (Beebox Web Application)**
   - URL: http://www.itsecgames.com/
   - Description: Contains over 100 vulnerabilities for testing

5. **Mutillidae**
   - URL: https://sourceforge.net/projects/mutillidae/
   - Description: Free, open source, deliberately vulnerable web application

6. **VulnHub**
   - URL: https://www.vulnhub.com/
   - Description: Collection of vulnerable VMs for practicing penetration testing

7. **OWASP Broken Web Applications Project**
   - URL: https://owasp.org/www-project-broken-web-applications/
   - Description: Collection of broken web applications for testing

### Public Testing Targets

1. **Vulnweb.com**
   - URL: http://testphp.vulnweb.com/
   - Description: Test site provided by Acunetix for security testing

2. **Httpbin.org**
   - URL: https://httpbin.org/
   - Description: HTTP Request & Response Service for testing HTTP requests

3. **JSONPlaceholder**
   - URL: https://jsonplaceholder.typicode.com/
   - Description: Fake Online REST API for testing and prototyping

### Setting Up Local Test Environments

For local testing, consider using:
- Docker containers with vulnerable applications
- Virtual machines with deliberately insecure distributions like Metasploitable
- Local installations of testing applications like DVWA or WebGoat

### Important Notes

- Only test systems you own or have explicit written permission to test
- Many of these applications should be run in isolated environments
- Some testing sites may have terms of service that restrict automated testing
- Always follow responsible disclosure practices if you find issues on public sites
- Use these resources ethically and for educational purposes only
