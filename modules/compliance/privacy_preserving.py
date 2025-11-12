#!/usr/bin/env python3
"""
Privacy-Preserving Scanning Module for PenAI

This module provides privacy-preserving scanning options that minimize data collection
and provide configurable privacy settings.
"""

import os
import json
from typing import Dict, Any, List, Optional
from pathlib import Path

class PrivacyPreservingScanner:
    def __init__(self, outdir: str, privacy_level: str = "standard"):
        """
        Initialize the privacy-preserving scanner.
        
        Args:
            outdir: Output directory for scan results
            privacy_level: Privacy level (minimal, standard, enhanced, maximum)
        """
        self.outdir = outdir
        self.privacy_level = privacy_level
        self.privacy_config = self._load_privacy_config()
        
    def _load_privacy_config(self) -> Dict[str, Any]:
        """Load privacy configuration based on privacy level."""
        config = {
            "minimal": {
                "collect_evidence": True,
                "collect_full_response": False,
                "mask_sensitive_data": True,
                "limit_findings_detail": True,
                "exclude_pii": True,
                "anonymize_targets": True,
                "disable_exploitation": True
            },
            "standard": {
                "collect_evidence": True,
                "collect_full_response": True,
                "mask_sensitive_data": True,
                "limit_findings_detail": False,
                "exclude_pii": True,
                "anonymize_targets": False,
                "disable_exploitation": False
            },
            "enhanced": {
                "collect_evidence": True,
                "collect_full_response": True,
                "mask_sensitive_data": True,
                "limit_findings_detail": False,
                "exclude_pii": True,
                "anonymize_targets": True,
                "disable_exploitation": False
            },
            "maximum": {
                "collect_evidence": False,
                "collect_full_response": False,
                "mask_sensitive_data": True,
                "limit_findings_detail": True,
                "exclude_pii": True,
                "anonymize_targets": True,
                "disable_exploitation": True
            }
        }
        
        return config.get(self.privacy_level, config["standard"])

    def apply_privacy_filters(self, findings: List[Dict[str, Any]], meta: Dict[str, Any]) -> Dict[str, Any]:
        """
        Apply privacy filters to scan findings and metadata.
        
        Args:
            findings: List of security findings
            meta: Scan metadata
            
        Returns:
            Privacy-filtered scan data
        """
        # Filter findings based on privacy configuration
        filtered_findings = []
        
        for finding in findings:
            # Skip if exploitation is disabled and this is an exploitation finding
            if self.privacy_config["disable_exploitation"] and finding.get("type", "").startswith("exploit"):
                continue
                
            filtered_finding = finding.copy()
            
            # Limit finding detail if configured
            if self.privacy_config["limit_findings_detail"]:
                # Reduce detail in evidence
                if "evidence" in filtered_finding:
                    evidence = str(filtered_finding["evidence"])
                    if len(evidence) > 200:
                        filtered_finding["evidence"] = evidence[:200] + "... (truncated for privacy)"
                
                # Remove raw data if present
                if "raw" in filtered_finding:
                    del filtered_finding["raw"]
                    
            # Mask sensitive data if configured
            if self.privacy_config["mask_sensitive_data"]:
                if "evidence" in filtered_finding:
                    filtered_finding["evidence"] = self._mask_sensitive_data(filtered_finding["evidence"])
                    
            filtered_findings.append(filtered_finding)
            
        # Filter metadata
        filtered_meta = meta.copy()
        
        # Anonymize targets if configured
        if self.privacy_config["anonymize_targets"] and "targets" in filtered_meta:
            filtered_meta["targets"] = ["[REDACTED]" for _ in filtered_meta["targets"]]
            if "primary_domain" in filtered_meta:
                filtered_meta["primary_domain"] = "[REDACTED]"
                
        # Exclude PII if configured
        if self.privacy_config["exclude_pii"]:
            pii_fields = ["user", "operator", "contact", "email", "phone"]
            for field in pii_fields:
                if field in filtered_meta:
                    filtered_meta[field] = "[REDACTED]"
                    
        return {
            "findings": filtered_findings,
            "metadata": filtered_meta
        }

    def _mask_sensitive_data(self, data: str) -> str:
        """Mask sensitive data in text."""
        import re
        
        # Patterns for sensitive data
        patterns = {
            r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b': '****-****-****-****',  # Credit card
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b': '***@***.***',  # Email
            r'\b\d{3}-\d{2}-\d{4}\b': '***-**-****',  # SSN
            r'\b\d{16}\b': '****************',  # 16-digit numbers
            r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b': '***-***-****',  # Phone number
            r'\b(?:\d{1,3}\.){3}\d{1,3}\b': '*.*.*.*',  # IP address
        }
        
        masked_data = str(data)
        for pattern, replacement in patterns.items():
            masked_data = re.sub(pattern, replacement, masked_data)
            
        return masked_data

    def get_privacy_report(self) -> Dict[str, Any]:
        """Generate a privacy compliance report."""
        return {
            "privacy_level": self.privacy_level,
            "configuration": self.privacy_config,
            "applied_filters": [
                "evidence_truncation" if self.privacy_config["limit_findings_detail"] else None,
                "sensitive_data_masking" if self.privacy_config["mask_sensitive_data"] else None,
                "target_anonymization" if self.privacy_config["anonymize_targets"] else None,
                "pii_exclusion" if self.privacy_config["exclude_pii"] else None,
                "exploitation_disabled" if self.privacy_config["disable_exploitation"] else None
            ]
        }

    def should_collect_evidence(self) -> bool:
        """Check if evidence collection is allowed."""
        return self.privacy_config["collect_evidence"]

    def should_collect_full_response(self) -> bool:
        """Check if full response collection is allowed."""
        return self.privacy_config["collect_full_response"]

    def should_perform_exploitation(self) -> bool:
        """Check if exploitation tests are allowed."""
        return not self.privacy_config["disable_exploitation"]

    def configure_privacy_settings(self, settings: Dict[str, Any]) -> None:
        """
        Configure custom privacy settings.
        
        Args:
            settings: Dictionary of privacy settings to override
        """
        for key, value in settings.items():
            if key in self.privacy_config:
                self.privacy_config[key] = value

# Global privacy-preserving scanner instance
_privacy_scanner: Optional[PrivacyPreservingScanner] = None

def initialize_privacy_scanner(outdir: str, privacy_level: str = "standard") -> PrivacyPreservingScanner:
    """Initialize and return the global privacy-preserving scanner."""
    global _privacy_scanner
    if _privacy_scanner is None:
        _privacy_scanner = PrivacyPreservingScanner(outdir, privacy_level)
    return _privacy_scanner

def get_privacy_scanner() -> Optional[PrivacyPreservingScanner]:
    """Get the global privacy-preserving scanner instance."""
    return _privacy_scanner