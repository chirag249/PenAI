"""
Audit Logger Module for PenAI

This module provides comprehensive audit logging capabilities for tracking
all system activities, user actions, and security events.
"""

import os
import json
import logging
import hashlib
import time
from typing import Dict, Any, Optional
from datetime import datetime
from pathlib import Path

class AuditLogger:
    def __init__(self, outdir: str, tenant_id: Optional[str] = None):
        """
        Initialize the audit logger.
        
        Args:
            outdir: Output directory for audit logs
            tenant_id: Optional tenant identifier for multi-tenant environments
        """
        self.outdir = outdir
        self.tenant_id = tenant_id
        self.audit_dir = os.path.join(outdir, "audit")
        os.makedirs(self.audit_dir, exist_ok=True)
        
        # Set up audit logger
        self.logger = logging.getLogger("penai_audit")
        self.logger.setLevel(logging.INFO)
        
        # Prevent duplicate handlers
        if not self.logger.handlers:
            audit_log_path = os.path.join(self.audit_dir, "audit.log")
            fh = logging.FileHandler(audit_log_path)
            fh.setLevel(logging.INFO)
            
            # Create formatter and add it to the handler
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            fh.setFormatter(formatter)
            
            # Add handler to logger
            self.logger.addHandler(fh)

    def log_event(self, event_type: str, user: str, resource: str, 
                  action: str, details: Optional[Dict[str, Any]] = None,
                  severity: str = "INFO") -> str:
        """
        Log a security event.
        
        Args:
            event_type: Type of event (e.g., "ACCESS", "MODIFICATION", "AUTHENTICATION")
            user: User identifier
            resource: Resource being accessed/modified
            action: Action performed
            details: Additional details about the event
            severity: Severity level (INFO, WARNING, ERROR, CRITICAL)
            
        Returns:
            Event ID for tracking
        """
        event_id = self._generate_event_id(event_type, user, resource, action)
        
        event = {
            "event_id": event_id,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event_type": event_type,
            "user": user,
            "resource": resource,
            "action": action,
            "severity": severity,
            "details": details or {},
            "tenant_id": self.tenant_id
        }
        
        # Log to file
        if severity == "CRITICAL":
            getattr(self.logger, "critical")(json.dumps(event))
        elif severity == "ERROR":
            getattr(self.logger, "error")(json.dumps(event))
        elif severity == "WARNING":
            getattr(self.logger, "warning")(json.dumps(event))
        else:
            getattr(self.logger, "info")(json.dumps(event))
        
        return event_id

    def log_authentication(self, user: str, success: bool, method: str = "password",
                          ip_address: Optional[str] = None, details: Optional[Dict[str, Any]] = None) -> str:
        """
        Log an authentication event.
        
        Args:
            user: User identifier
            success: Whether authentication was successful
            method: Authentication method used
            ip_address: IP address of the client
            details: Additional authentication details
            
        Returns:
            Event ID for tracking
        """
        return self.log_event(
            event_type="AUTHENTICATION",
            user=user,
            resource="system",
            action="login_success" if success else "login_failure",
            details={
                "method": method,
                "ip_address": ip_address,
                "additional_details": details or {}
            },
            severity="CRITICAL" if not success else "INFO"
        )

    def log_access(self, user: str, resource: str, action: str, 
                   success: bool, details: Optional[Dict[str, Any]] = None) -> str:
        """
        Log a resource access event.
        
        Args:
            user: User identifier
            resource: Resource being accessed
            action: Action performed (read, write, delete, etc.)
            success: Whether access was successful
            details: Additional access details
            
        Returns:
            Event ID for tracking
        """
        return self.log_event(
            event_type="ACCESS",
            user=user,
            resource=resource,
            action=f"{action}_success" if success else f"{action}_failure",
            details=details or {},
            severity="WARNING" if not success else "INFO"
        )

    def log_modification(self, user: str, resource: str, action: str,
                         changes: Dict[str, Any], details: Optional[Dict[str, Any]] = None) -> str:
        """
        Log a resource modification event.
        
        Args:
            user: User identifier
            resource: Resource being modified
            action: Modification action (create, update, delete)
            changes: Description of changes made
            details: Additional modification details
            
        Returns:
            Event ID for tracking
        """
        return self.log_event(
            event_type="MODIFICATION",
            user=user,
            resource=resource,
            action=action,
            details={
                "changes": changes,
                "additional_details": details or {}
            },
            severity="WARNING"
        )

    def log_destructive_action(self, user: str, target: str, tool: str,
                              action: str, details: Optional[Dict[str, Any]] = None) -> str:
        """
        Log a destructive action event.
        
        Args:
            user: User identifier
            target: Target of the destructive action
            tool: Tool used for the action
            action: Specific action performed
            details: Additional details about the action
            
        Returns:
            Event ID for tracking
        """
        return self.log_event(
            event_type="DESTRUCTIVE_ACTION",
            user=user,
            resource=target,
            action=action,
            details={
                "tool": tool,
                "additional_details": details or {}
            },
            severity="CRITICAL"
        )

    def log_compliance_event(self, event_type: str, standard: str, 
                            requirement: str, status: str, details: Optional[Dict[str, Any]] = None) -> str:
        """
        Log a compliance-related event.
        
        Args:
            event_type: Type of compliance event
            standard: Compliance standard (e.g., "PCI DSS", "HIPAA")
            requirement: Specific requirement within the standard
            status: Status of compliance (compliant, non-compliant, pending)
            details: Additional compliance details
            
        Returns:
            Event ID for tracking
        """
        return self.log_event(
            event_type=f"COMPLIANCE_{event_type}",
            user="system",
            resource=standard,
            action=f"{requirement}_{status}",
            details={
                "standard": standard,
                "requirement": requirement,
                "status": status,
                "additional_details": details or {}
            },
            severity="INFO" if status == "compliant" else "WARNING"
        )

    def _generate_event_id(self, event_type: str, user: str, resource: str, action: str) -> str:
        """Generate a unique event ID based on event details."""
        seed = f"{event_type}:{user}:{resource}:{action}:{time.time()}"
        return hashlib.sha256(seed.encode()).hexdigest()[:16]

    def get_audit_log_path(self) -> str:
        """Get the path to the audit log file."""
        return os.path.join(self.audit_dir, "audit.log")

    def search_events(self, event_type: Optional[str] = None, user: Optional[str] = None,
                     start_time: Optional[str] = None, end_time: Optional[str] = None) -> list:
        """
        Search audit events based on criteria.
        
        Args:
            event_type: Filter by event type
            user: Filter by user
            start_time: Filter by start time (ISO format)
            end_time: Filter by end time (ISO format)
            
        Returns:
            List of matching events
        """
        events = []
        try:
            with open(self.get_audit_log_path(), "r") as f:
                for line in f:
                    try:
                        event = json.loads(line)
                        # Apply filters
                        if event_type and event.get("event_type") != event_type:
                            continue
                        if user and event.get("user") != user:
                            continue
                        # Time filtering would require parsing timestamps
                        events.append(event)
                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            pass
        
        return events

# Global audit logger instance
_audit_logger: Optional[AuditLogger] = None

def initialize_audit_logger(outdir: str, tenant_id: Optional[str] = None) -> AuditLogger:
    """Initialize and return the global audit logger."""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger(outdir, tenant_id)
    return _audit_logger

def get_audit_logger() -> Optional[AuditLogger]:
    """Get the global audit logger instance."""
    return _audit_logger