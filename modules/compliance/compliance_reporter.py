#!/usr/bin/env python3
"""
Compliance Reporter Module for PenAI

This module provides compliance reporting capabilities for industry standards
including PCI DSS, HIPAA, GDPR, and SOC 2.
"""

import os
import json
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path

class ComplianceReporter:
    def __init__(self, outdir: str):
        """
        Initialize the compliance reporter.
        
        Args:
            outdir: Output directory for compliance reports
        """
        self.outdir = outdir
        self.compliance_dir = os.path.join(outdir, "compliance")
        os.makedirs(self.compliance_dir, exist_ok=True)
        
        # Compliance standards mapping
        self.standards = {
            "PCI_DSS": {
                "name": "Payment Card Industry Data Security Standard",
                "version": "4.0",
                "requirements": self._get_pci_dss_requirements()
            },
            "HIPAA": {
                "name": "Health Insurance Portability and Accountability Act",
                "version": "2023",
                "requirements": self._get_hipaa_requirements()
            },
            "GDPR": {
                "name": "General Data Protection Regulation",
                "version": "2018",
                "requirements": self._get_gdpr_requirements()
            },
            "SOC2": {
                "name": "Service Organization Control 2",
                "version": "2022",
                "requirements": self._get_soc2_requirements()
            }
        }

    def generate_compliance_report(self, standard: str, findings: List[Dict[str, Any]], 
                                 meta: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a compliance report for a specific standard.
        
        Args:
            standard: Compliance standard to report on
            findings: Security findings from the scan
            meta: Scan metadata
            
        Returns:
            Compliance report dictionary
        """
        if standard not in self.standards:
            raise ValueError(f"Unsupported compliance standard: {standard}")
            
        standard_info = self.standards[standard]
        requirements = standard_info["requirements"]
        
        # Evaluate compliance for each requirement
        compliance_status = {}
        for req_id, req_info in requirements.items():
            compliance_status[req_id] = self._evaluate_requirement(
                req_id, req_info, findings, meta
            )
        
        # Generate overall compliance score
        total_requirements = len(compliance_status)
        compliant_requirements = sum(1 for status in compliance_status.values() 
                                   if status["status"] == "compliant")
        
        compliance_score = (compliant_requirements / total_requirements * 100) if total_requirements > 0 else 0
        
        report = {
            "report_id": self._generate_report_id(standard),
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "standard": {
                "name": standard_info["name"],
                "version": standard_info["version"],
                "id": standard
            },
            "scan_metadata": meta,
            "compliance_score": round(compliance_score, 2),
            "summary": {
                "total_requirements": total_requirements,
                "compliant_requirements": compliant_requirements,
                "non_compliant_requirements": total_requirements - compliant_requirements
            },
            "requirements": compliance_status,
            "findings_summary": self._summarize_findings(findings, standard)
        }
        
        # Write report to file
        self._write_compliance_report(report, standard)
        
        return report

    def generate_multi_standard_report(self, standards: List[str], findings: List[Dict[str, Any]], 
                                     meta: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a compliance report covering multiple standards.
        
        Args:
            standards: List of compliance standards to report on
            findings: Security findings from the scan
            meta: Scan metadata
            
        Returns:
            Multi-standard compliance report dictionary
        """
        reports = {}
        for standard in standards:
            try:
                reports[standard] = self.generate_compliance_report(standard, findings, meta)
            except Exception as e:
                reports[standard] = {
                    "error": f"Failed to generate {standard} report: {str(e)}"
                }
        
        multi_report = {
            "report_id": self._generate_report_id("MULTI_STANDARD"),
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "reports": reports
        }
        
        # Write multi-standard report to file
        self._write_compliance_report(multi_report, "MULTI_STANDARD")
        
        return multi_report

    def _evaluate_requirement(self, req_id: str, req_info: Dict[str, Any], 
                            findings: List[Dict[str, Any]], meta: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate compliance with a specific requirement.
        
        Args:
            req_id: Requirement ID
            req_info: Requirement information
            findings: Security findings
            meta: Scan metadata
            
        Returns:
            Compliance evaluation result
        """
        # Check if requirement is applicable based on scan metadata
        if not self._is_requirement_applicable(req_info, meta):
            return {
                "status": "not_applicable",
                "description": req_info["description"],
                "reason": "Requirement not applicable to this environment"
            }
        
        # Check for violations in findings
        violations = self._find_violations(req_info, findings)
        
        if violations:
            return {
                "status": "non_compliant",
                "description": req_info["description"],
                "violations": violations,
                "remediation": req_info.get("remediation", "No remediation guidance available")
            }
        else:
            return {
                "status": "compliant",
                "description": req_info["description"]
            }

    def _is_requirement_applicable(self, req_info: Dict[str, Any], meta: Dict[str, Any]) -> bool:
        """
        Check if a requirement is applicable based on scan metadata.
        
        Args:
            req_info: Requirement information
            meta: Scan metadata
            
        Returns:
            Whether the requirement is applicable
        """
        # Check environment type
        env_type = meta.get("environment", "unknown")
        applicable_envs = req_info.get("applicable_environments", ["all"])
        
        if "all" not in applicable_envs and env_type not in applicable_envs:
            return False
            
        # Check target types
        target_types = meta.get("target_types", [])
        applicable_targets = req_info.get("applicable_targets", ["all"])
        
        if "all" not in applicable_targets and not any(t in applicable_targets for t in target_types):
            return False
            
        return True

    def _find_violations(self, req_info: Dict[str, Any], findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Find violations of a specific requirement in the findings.
        
        Args:
            req_info: Requirement information
            findings: Security findings
            
        Returns:
            List of violations
        """
        violations = []
        violation_patterns = req_info.get("violation_patterns", [])
        
        for finding in findings:
            # Check if finding violates this requirement
            for pattern in violation_patterns:
                if self._matches_pattern(finding, pattern):
                    violations.append({
                        "finding_id": finding.get("id", "unknown"),
                        "type": finding.get("type", "unknown"),
                        "severity": finding.get("severity", 1),
                        "evidence": finding.get("evidence", ""),
                        "pattern_matched": pattern
                    })
                    break  # Don't add the same finding multiple times
                    
        return violations

    def _matches_pattern(self, finding: Dict[str, Any], pattern: Dict[str, Any]) -> bool:
        """
        Check if a finding matches a violation pattern.
        
        Args:
            finding: Security finding
            pattern: Violation pattern
            
        Returns:
            Whether the finding matches the pattern
        """
        # Check finding type
        if "type" in pattern:
            if isinstance(pattern["type"], str):
                if finding.get("type") != pattern["type"]:
                    return False
            elif isinstance(pattern["type"], list):
                if finding.get("type") not in pattern["type"]:
                    return False
                    
        # Check severity
        if "min_severity" in pattern:
            if finding.get("severity", 0) < pattern["min_severity"]:
                return False
                
        # Check evidence keywords
        if "evidence_keywords" in pattern:
            evidence = str(finding.get("evidence", "")).lower()
            keywords = [kw.lower() for kw in pattern["evidence_keywords"]]
            if not any(kw in evidence for kw in keywords):
                return False
                
        return True

    def _summarize_findings(self, findings: List[Dict[str, Any]], standard: str) -> Dict[str, Any]:
        """
        Summarize findings relevant to a compliance standard.
        
        Args:
            findings: Security findings
            standard: Compliance standard
            
        Returns:
            Findings summary
        """
        # Filter findings relevant to the standard
        relevant_findings = []
        standard_info = self.standards.get(standard, {})
        requirements = standard_info.get("requirements", {})
        
        for finding in findings:
            # Check if finding is relevant to any requirement in the standard
            for req_info in requirements.values():
                violation_patterns = req_info.get("violation_patterns", [])
                for pattern in violation_patterns:
                    if self._matches_pattern(finding, pattern):
                        relevant_findings.append(finding)
                        break
        
        # Summarize by severity
        severity_counts = {}
        for finding in relevant_findings:
            severity = finding.get("severity", 1)
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
        return {
            "total_relevant_findings": len(relevant_findings),
            "severity_breakdown": severity_counts,
            "sample_findings": relevant_findings[:5]  # Include first 5 as samples
        }

    def _write_compliance_report(self, report: Dict[str, Any], standard: str) -> None:
        """
        Write compliance report to file.
        
        Args:
            report: Compliance report dictionary
            standard: Compliance standard
        """
        filename = f"{standard.lower()}_compliance_report.json"
        filepath = os.path.join(self.compliance_dir, filename)
        
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

    def _generate_report_id(self, standard: str) -> str:
        """Generate a unique report ID."""
        import hashlib
        import time
        seed = f"{standard}:{time.time()}"
        return hashlib.sha256(seed.encode()).hexdigest()[:16]

    def _get_pci_dss_requirements(self) -> Dict[str, Any]:
        """Get PCI DSS requirements."""
        return {
            "REQ_1.1": {
                "description": "Establish and implement firewall and router configuration standards",
                "violation_patterns": [
                    {"type": "open_port", "min_severity": 4},
                    {"type": ["misconfigured_firewall", "unprotected_service"], "min_severity": 3}
                ],
                "remediation": "Implement proper firewall rules and close unnecessary ports"
            },
            "REQ_2.2": {
                "description": "Develop configuration standards for all system components",
                "violation_patterns": [
                    {"type": "default_account", "min_severity": 3},
                    {"type": "weak_configuration", "min_severity": 3}
                ],
                "remediation": "Remove default accounts and implement secure configurations"
            },
            "REQ_6.1": {
                "description": "Establish a process to identify security vulnerabilities",
                "violation_patterns": [
                    {"type": ["sqli", "xss", "rce"], "min_severity": 4}
                ],
                "remediation": "Implement regular vulnerability scanning and patch management"
            },
            "REQ_7.1": {
                "description": "Restrict access to cardholder data by business need to know",
                "violation_patterns": [
                    {"type": "excessive_permissions", "min_severity": 3}
                ],
                "remediation": "Implement principle of least privilege access controls"
            },
            "REQ_8.1": {
                "description": "Identify and authenticate access to system components",
                "violation_patterns": [
                    {"type": "weak_authentication", "min_severity": 3},
                    {"type": "plaintext_credentials", "min_severity": 4}
                ],
                "remediation": "Implement strong authentication mechanisms"
            }
        }

    def _get_hipaa_requirements(self) -> Dict[str, Any]:
        """Get HIPAA requirements."""
        return {
            "ADMIN_1": {
                "description": "Implement security management process",
                "violation_patterns": [
                    {"type": ["sqli", "xss", "rce"], "min_severity": 4},
                    {"type": "weak_authentication", "min_severity": 3}
                ],
                "remediation": "Conduct regular risk assessments and implement security measures"
            },
            "ADMIN_2": {
                "description": "Implement assigned security responsibility",
                "violation_patterns": [
                    {"type": "unauthorized_access", "min_severity": 3}
                ],
                "remediation": "Assign security responsibilities and implement access controls"
            },
            "ADMIN_3": {
                "description": "Implement information access management policies",
                "violation_patterns": [
                    {"type": "excessive_permissions", "min_severity": 3}
                ],
                "remediation": "Implement role-based access controls and need-to-know principles"
            },
            "PHY_1": {
                "description": "Implement policies for workstation use and security",
                "violation_patterns": [
                    {"type": "insecure_workstation", "min_severity": 3}
                ],
                "remediation": "Implement workstation security policies and controls"
            },
            "TECH_1": {
                "description": "Implement access controls for electronic protected health information",
                "violation_patterns": [
                    {"type": "weak_authentication", "min_severity": 3},
                    {"type": "plaintext_credentials", "min_severity": 4}
                ],
                "remediation": "Implement strong authentication and access controls"
            }
        }

    def _get_gdpr_requirements(self) -> Dict[str, Any]:
        """Get GDPR requirements."""
        return {
            "ART_5": {
                "description": "Principles relating to processing of personal data",
                "violation_patterns": [
                    {"type": "data_exposure", "min_severity": 4},
                    {"type": "insecure_data_storage", "min_severity": 3}
                ],
                "remediation": "Implement data protection by design and by default"
            },
            "ART_25": {
                "description": "Data protection by design and by default",
                "violation_patterns": [
                    {"type": "weak_encryption", "min_severity": 3},
                    {"type": "insecure_data_transmission", "min_severity": 3}
                ],
                "remediation": "Implement privacy by design principles in system architecture"
            },
            "ART_32": {
                "description": "Security of processing",
                "violation_patterns": [
                    {"type": ["sqli", "xss", "rce"], "min_severity": 4},
                    {"type": "weak_authentication", "min_severity": 3}
                ],
                "remediation": "Implement appropriate technical and organizational security measures"
            },
            "ART_33": {
                "description": "Notification of personal data breach to supervisory authority",
                "violation_patterns": [
                    {"type": "data_breach", "min_severity": 4}
                ],
                "remediation": "Implement breach detection and notification procedures"
            }
        }

    def _get_soc2_requirements(self) -> Dict[str, Any]:
        """Get SOC 2 requirements."""
        return {
            "CC_1": {
                "description": "Security - The system is protected against unauthorized access",
                "violation_patterns": [
                    {"type": ["sqli", "xss", "rce"], "min_severity": 4},
                    {"type": "weak_authentication", "min_severity": 3},
                    {"type": "unauthorized_access", "min_severity": 3}
                ],
                "remediation": "Implement comprehensive security controls and access management"
            },
            "CC_2": {
                "description": "Availability - The system is available for operation and use",
                "violation_patterns": [
                    {"type": "denial_of_service", "min_severity": 4}
                ],
                "remediation": "Implement availability monitoring and redundancy measures"
            },
            "CC_3": {
                "description": "Processing Integrity - System processing is complete, accurate, timely, and authorized",
                "violation_patterns": [
                    {"type": "data_corruption", "min_severity": 3}
                ],
                "remediation": "Implement data integrity controls and validation mechanisms"
            },
            "CC_4": {
                "description": "Confidentiality - Information designated as confidential is protected",
                "violation_patterns": [
                    {"type": "data_exposure", "min_severity": 4},
                    {"type": "insecure_data_storage", "min_severity": 3}
                ],
                "remediation": "Implement encryption and confidentiality controls"
            },
            "CC_5": {
                "description": "Privacy - Personal information is collected, used, retained, disclosed, and disposed of to meet the entity's objectives",
                "violation_patterns": [
                    {"type": "privacy_violation", "min_severity": 3}
                ],
                "remediation": "Implement privacy controls and data lifecycle management"
            }
        }

# Global compliance reporter instance
_compliance_reporter: Optional[ComplianceReporter] = None

def initialize_compliance_reporter(outdir: str) -> ComplianceReporter:
    """Initialize and return the global compliance reporter."""
    global _compliance_reporter
    if _compliance_reporter is None:
        _compliance_reporter = ComplianceReporter(outdir)
    return _compliance_reporter

def get_compliance_reporter() -> Optional[ComplianceReporter]:
    """Get the global compliance reporter instance."""
    return _compliance_reporter