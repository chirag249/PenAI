#!/usr/bin/env python3
"""
Notification system for security testing framework.
Supports Slack and Microsoft Teams notifications.
"""

import os
import json
import requests
import logging
from typing import Dict, Any, Optional
from pathlib import Path

logger = logging.getLogger(__name__)

class NotificationManager:
    """Manages notifications to various platforms."""
    
    def __init__(self):
        self.slack_webhook_url = os.environ.get("SLACK_WEBHOOK_URL")
        self.teams_webhook_url = os.environ.get("TEAMS_WEBHOOK_URL")
        
    def send_slack_notification(self, message: str, attachments: Optional[Dict[str, Any]] = None) -> bool:
        """
        Send a notification to Slack.
        
        Args:
            message: The message to send
            attachments: Optional attachments to include
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.slack_webhook_url:
            logger.warning("Slack webhook URL not configured")
            return False
            
        payload = {
            "text": message,
            "attachments": attachments or []
        }
        
        try:
            response = requests.post(
                self.slack_webhook_url,
                json=payload,
                timeout=30
            )
            response.raise_for_status()
            logger.info("Slack notification sent successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to send Slack notification: {e}")
            return False
    
    def send_teams_notification(self, message: str, summary: Optional[str] = None) -> bool:
        """
        Send a notification to Microsoft Teams.
        
        Args:
            message: The message to send
            summary: Optional summary for the notification
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.teams_webhook_url:
            logger.warning("Teams webhook URL not configured")
            return False
            
        payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": "0076D7",
            "summary": summary or "Security Scan Notification",
            "sections": [{
                "activityTitle": "Security Scan Results",
                "activitySubtitle": "Automated Security Testing Framework",
                "activityImage": "https://upload.wikimedia.org/wikipedia/commons/thumb/f/f8/Python_logo_and_wordmark.svg/1200px-Python_logo_and_wordmark.svg.png",
                "text": message,
                "markdown": True
            }]
        }
        
        try:
            response = requests.post(
                self.teams_webhook_url,
                json=payload,
                timeout=30
            )
            response.raise_for_status()
            logger.info("Teams notification sent successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to send Teams notification: {e}")
            return False
    
    def send_scan_results_notification(self, run_dir: str, target: str, success: bool = True) -> None:
        """
        Send a comprehensive notification about scan results.
        
        Args:
            run_dir: The directory containing scan results
            target: The target that was scanned
            success: Whether the scan was successful
        """
        # Read scan metadata
        meta_file = Path(run_dir) / "run_meta.json"
        scan_metadata = {}
        if meta_file.exists():
            try:
                with open(meta_file, "r") as f:
                    scan_metadata = json.load(f)
            except Exception as e:
                logger.warning(f"Failed to read scan metadata: {e}")
        
        # Count findings if available
        findings_count = 0
        findings_file = Path(run_dir) / "findings.json"
        if findings_file.exists():
            try:
                with open(findings_file, "r") as f:
                    findings = json.load(f)
                    findings_count = len(findings) if isinstance(findings, list) else 0
            except Exception as e:
                logger.warning(f"Failed to read findings: {e}")
        
        # Create message
        if success:
            message = f"✅ Security scan completed successfully for {target}\n"
            message += f"📊 Findings detected: {findings_count}\n"
            if scan_metadata:
                duration = scan_metadata.get("duration", "N/A")
                message += f"⏱️ Scan duration: {duration}\n"
            message += f"📁 Results saved to: {run_dir}"
        else:
            message = f"❌ Security scan failed for {target}\n"
            message += "Please check the logs for more details."
        
        # Send notifications
        self.send_slack_notification(message)
        self.send_teams_notification(message, "Security Scan Results")

# Global instance
notification_manager = NotificationManager()

def send_slack_notification(message: str, attachments: Optional[Dict[str, Any]] = None) -> bool:
    """Send a Slack notification."""
    return notification_manager.send_slack_notification(message, attachments)

def send_teams_notification(message: str, summary: Optional[str] = None) -> bool:
    """Send a Teams notification."""
    return notification_manager.send_teams_notification(message, summary)

def send_scan_results_notification(run_dir: str, target: str, success: bool = True) -> None:
    """Send a comprehensive scan results notification."""
    notification_manager.send_scan_results_notification(run_dir, target, success)