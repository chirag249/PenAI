#!/usr/bin/env python3
"""
Vulnerability intelligence integration for security testing framework.
Integrates with NVD, CVE, and threat intelligence feeds.
"""

import os
import json
import requests
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)

class VulnerabilityIntel:
    """Manages vulnerability intelligence from various sources."""
    
    def __init__(self):
        self.nvd_api_key = os.environ.get("NVD_API_KEY")
        self.cve_base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.cache_dir = Path("intel_cache")
        self.cache_dir.mkdir(exist_ok=True)
        
    def get_nvd_vulnerabilities(self, cve_id: Optional[str] = None, 
                               keyword: Optional[str] = None,
                               days_back: int = 7) -> List[Dict[str, Any]]:
        """
        Fetch vulnerabilities from NVD database.
        
        Args:
            cve_id: Specific CVE ID to fetch
            keyword: Keyword to search for
            days_back: Number of days back to search (default: 7)
            
        Returns:
            List of vulnerability records
        """
        params = {}
        
        if cve_id:
            params["cveId"] = cve_id
        else:
            # For general searches, limit by date
            end_date = datetime.now()
            start_date = end_date - timedelta(days=days_back)
            params["pubStartDate"] = start_date.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            params["pubEndDate"] = end_date.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            
            if keyword:
                params["keywordSearch"] = keyword
        
        headers = {}
        if self.nvd_api_key:
            headers["apiKey"] = self.nvd_api_key
            
        try:
            response = requests.get(
                self.cve_base_url,
                params=params,
                headers=headers,
                timeout=30
            )
            response.raise_for_status()
            
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            
            # Cache the results
            cache_file = self.cache_dir / f"nvd_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(cache_file, "w") as f:
                json.dump(data, f, indent=2)
                
            return vulnerabilities
        except Exception as e:
            logger.error(f"Failed to fetch NVD vulnerabilities: {e}")
            # Try to return cached data if available
            return self._get_cached_nvd_data()
    
    def _get_cached_nvd_data(self) -> List[Dict[str, Any]]:
        """Get cached NVD data if available."""
        try:
            # Get the most recent cache file
            cache_files = list(self.cache_dir.glob("nvd_*.json"))
            if not cache_files:
                return []
                
            latest_cache = max(cache_files, key=lambda f: f.stat().st_mtime)
            with open(latest_cache, "r") as f:
                data = json.load(f)
            return data.get("vulnerabilities", [])
        except Exception as e:
            logger.warning(f"Failed to read cached NVD data: {e}")
            return []
    
    def correlate_findings_with_cve(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Correlate security findings with CVE data.
        
        Args:
            findings: List of security findings from tools
            
        Returns:
            List of findings with CVE correlation data
        """
        correlated_findings = []
        
        for finding in findings:
            # Extract potential CVE identifiers from the finding
            cve_ids = self._extract_cve_ids(finding)
            
            # Get CVE details for each identified CVE
            cve_details = []
            for cve_id in cve_ids:
                try:
                    cve_data = self.get_nvd_vulnerabilities(cve_id=cve_id)
                    if cve_data:
                        cve_details.extend(cve_data)
                except Exception as e:
                    logger.warning(f"Failed to get details for {cve_id}: {e}")
            
            # Add CVE details to the finding
            finding_with_cve = finding.copy()
            finding_with_cve["cve_correlation"] = cve_details
            correlated_findings.append(finding_with_cve)
            
        return correlated_findings
    
    def _extract_cve_ids(self, finding: Dict[str, Any]) -> List[str]:
        """Extract CVE IDs from a finding."""
        cve_ids = []
        
        # Check common fields where CVE IDs might be present
        fields_to_check = ["description", "evidence", "details", "title", "name"]
        
        for field in fields_to_check:
            value = finding.get(field, "")
            if isinstance(value, str):
                # Simple regex pattern for CVE IDs
                import re
                cve_matches = re.findall(r"CVE-\d{4}-\d{4,7}", value)
                cve_ids.extend(cve_matches)
        
        return list(set(cve_ids))  # Remove duplicates
    
    def get_threat_intel_feeds(self) -> Dict[str, Any]:
        """
        Fetch threat intelligence feeds.
        This is a placeholder implementation - in a real system, you would
        integrate with actual threat intelligence providers.
        
        Returns:
            Dictionary containing threat intelligence data
        """
        # This would typically integrate with services like:
        # - AlienVault OTX
        # - VirusTotal
        # - IBM X-Force
        # - ThreatConnect
        # - MISP
        
        # For now, we'll return a basic structure
        return {
            "timestamp": datetime.now().isoformat(),
            "feeds": {
                "emerging_threats": self._get_emerging_threats(),
                "malware_indicators": self._get_malware_indicators(),
                "ip_blacklists": self._get_ip_blacklists()
            }
        }
    
    def _get_emerging_threats(self) -> List[Dict[str, Any]]:
        """Get emerging threat intelligence (placeholder)."""
        # In a real implementation, this would fetch from threat intel feeds
        return [
            {
                "type": "emerging_threat",
                "description": "New exploitation technique targeting web applications",
                "severity": "high",
                "date": datetime.now().isoformat()
            }
        ]
    
    def _get_malware_indicators(self) -> List[Dict[str, Any]]:
        """Get malware indicators (placeholder)."""
        return [
            {
                "type": "malware_ioc",
                "indicator": "suspicious_domain.com",
                "indicator_type": "domain",
                "threat_level": "medium"
            }
        ]
    
    def _get_ip_blacklists(self) -> List[Dict[str, Any]]:
        """Get IP blacklists (placeholder)."""
        return [
            {
                "type": "blacklisted_ip",
                "ip": "192.168.1.100",
                "reason": "Known malicious IP",
                "last_seen": datetime.now().isoformat()
            }
        ]
    
    def correlate_with_exploit_db(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Correlate vulnerabilities with known exploits in exploit databases.
        
        Args:
            vulnerabilities: List of vulnerabilities
            
        Returns:
            List of vulnerabilities with exploit correlation data
        """
        # This would integrate with exploit databases like:
        # - ExploitDB
        # - Metasploit
        # - PacketStorm
        
        correlated_vulns = []
        for vuln in vulnerabilities:
            # Extract CVE ID
            cve_id = None
            if "cve" in vuln:
                cve_id = vuln["cve"].get("id")
            elif "id" in vuln:
                cve_id = vuln["id"]
            
            # In a real implementation, we would query exploit databases here
            exploit_info = []
            if cve_id:
                # Placeholder for actual exploit database query
                exploit_info = self._query_exploit_db(cve_id)
            
            vuln_with_exploits = vuln.copy()
            vuln_with_exploits["exploit_correlation"] = exploit_info
            correlated_vulns.append(vuln_with_exploits)
            
        return correlated_vulns
    
    def _query_exploit_db(self, cve_id: str) -> List[Dict[str, Any]]:
        """
        Query exploit database for a CVE (placeholder implementation).
        
        Args:
            cve_id: CVE identifier
            
        Returns:
            List of exploit information
        """
        # In a real implementation, this would query actual exploit databases
        # For now, we'll return sample data
        return [
            {
                "cve_id": cve_id,
                "exploit_available": False,
                "exploit_sources": [],
                "exploit_status": "not_found"
            }
        ]

# Global instance
vuln_intel = VulnerabilityIntel()

def get_nvd_vulnerabilities(cve_id: Optional[str] = None, 
                           keyword: Optional[str] = None,
                           days_back: int = 7) -> List[Dict[str, Any]]:
    """Get vulnerabilities from NVD."""
    return vuln_intel.get_nvd_vulnerabilities(cve_id, keyword, days_back)

def correlate_findings_with_cve(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Correlate findings with CVE data."""
    return vuln_intel.correlate_findings_with_cve(findings)

def get_threat_intel_feeds() -> Dict[str, Any]:
    """Get threat intelligence feeds."""
    return vuln_intel.get_threat_intel_feeds()

def correlate_with_exploit_db(vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Correlate vulnerabilities with exploit database."""
    return vuln_intel.correlate_with_exploit_db(vulnerabilities)