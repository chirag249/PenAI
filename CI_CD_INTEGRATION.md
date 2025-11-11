# CI/CD Integration for PenAI Security Testing Framework

This document describes the professional-level CI/CD integration capabilities added to the PenAI framework.

## GitHub Actions Integration

The framework now includes a GitHub Actions workflow that automatically runs security scans on:
- Push events to main/master branches
- Pull request events to main/master branches
- Scheduled weekly scans

### Configuration

The workflow is defined in `.github/workflows/security-scan.yml` and includes:

1. **Multi-Python Version Testing**: Runs scans on Python 3.8, 3.9, 3.10, and 3.11
2. **Basic and Enhanced Scans**: Runs both standard and AI-enhanced security scans
3. **Artifact Archiving**: Preserves scan results for 1 week
4. **Failure Notifications**: Sends alerts to Slack and Microsoft Teams when scans fail

### Setup

To enable GitHub Actions integration:

1. Add your `GEMINI_API_KEY` as a repository secret
2. (Optional) Add `SLACK_WEBHOOK` and `TEAMS_WEBHOOK` secrets for notifications

## GitLab CI/CD Integration

The framework includes a GitLab CI/CD pipeline configuration in `.gitlab-ci.yml` that provides:

1. **Multi-Stage Pipeline**: Security scanning, reporting, and notification stages
2. **Enhanced Scanning**: Runs both standard and AI-powered security scans
3. **Comprehensive Notifications**: Slack and Teams notifications for success and failure events
4. **Artifact Management**: Preserves scan results and reports

### Setup

To enable GitLab CI/CD integration:

1. Set the `GEMINI_API_KEY` variable in your GitLab CI/CD settings
2. (Optional) Set `SLACK_WEBHOOK_URL` and `TEAMS_WEBHOOK_URL` variables for notifications

## Notification Systems

The framework now supports real-time notifications to popular collaboration platforms:

### Slack Integration

- Configure `SLACK_WEBHOOK_URL` environment variable
- Notifications include scan status, findings count, and duration

### Microsoft Teams Integration

- Configure `TEAMS_WEBHOOK_URL` environment variable
- Rich notifications with detailed scan information

## Usage Examples

### Running in GitHub Actions

The workflow automatically triggers on the configured events. To manually trigger:

```bash
# In GitHub CLI
gh workflow run "Security Testing Pipeline"
```

### Running in GitLab CI/CD

The pipeline automatically triggers on push events. To manually trigger:

```bash
# In GitLab CI/CD
# Go to CI/CD > Pipelines > Run Pipeline
```

### Local Testing with Notifications

```bash
# Set environment variables
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK"
export TEAMS_WEBHOOK_URL="https://outlook.office.com/webhook/YOUR/TEAMS/WEBHOOK"

# Run scan with notifications
python agent.py --targets https://example.com --run-id test-scan
```

## Security Considerations

1. **API Keys**: Never commit API keys to version control
2. **Webhook URLs**: Use repository/organization level secrets for webhook URLs
3. **Scan Targets**: Be cautious with destructive scan profiles in CI/CD environments

## Customization

The CI/CD workflows can be customized by modifying:
- `.github/workflows/security-scan.yml` for GitHub Actions
- `.gitlab-ci.yml` for GitLab CI/CD

Common customizations include:
- Adding additional scan targets
- Changing scan schedules
- Modifying notification channels
- Adding custom scan profiles