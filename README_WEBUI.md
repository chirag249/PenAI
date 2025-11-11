# PenAI Web UI

This is an interactive web interface for the PenAI penetration testing automation framework.

## Features

1. **Interactive Target Input**: Enter the website you want to test
2. **Mode Selection**: Choose between non-destructive (safe) and destructive (aggressive) scanning modes
3. **Real-time Progress Monitoring**: Visual feedback during the scanning process
4. **AI-Summarized Reports**: Easy-to-understand security findings with actionable recommendations
5. **Data Visualization**: Charts and graphs showing vulnerability distribution
6. **Multiple Report Formats**: Download reports in Markdown, HTML, PDF, JSON, and TXT formats

## Getting Started

1. Activate the virtual environment:
   ```bash
   source venv/bin/activate
   ```

2. Run the web UI:
   ```bash
   python webui.py
   ```

3. Open your browser and navigate to `http://localhost:5000`

## Usage

1. Enter the target website URL (include the scheme, e.g., `https://example.com`)
2. Select the scan mode:
   - **Non-Destructive (Safe)**: Runs passive reconnaissance and non-intrusive scans
   - **Destructive (Aggressive)**: Runs all tests including potentially disruptive ones
3. Provide a Run ID (optional, will be auto-generated if left blank)
4. Click "Start Scan"
5. Monitor progress in real-time
6. Once complete, view the AI-summarized report with visualizations
7. Download reports in your preferred format

## Report Features

- **Severity Distribution Chart**: Visual breakdown of findings by severity level
- **Vulnerability Type Chart**: Top vulnerability types found
- **AI-Generated Recommendations**: Actionable security advice based on findings
- **Top Vulnerabilities**: Critical findings with evidence and confidence levels

## Technical Details

The web UI is built with:
- Flask (backend)
- Plotly.js (charts and visualizations)
- Custom CSS styling with dark/light theme support
- Real-time AJAX polling for progress updates