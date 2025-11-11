#!/usr/bin/env python3
"""
Trend Analysis Module for PenAI
Compares findings across multiple scan iterations over time.
"""

import json
import os
from typing import List, Dict, Any
from collections import defaultdict
import datetime

def load_historical_runs(base_dir: str, domain: str) -> List[Dict[str, Any]]:
    """Load historical scan runs for trend analysis."""
    historical_runs = []
    
    domain_dir = os.path.join(base_dir, "runs", domain)
    if not os.path.exists(domain_dir):
        return historical_runs
    
    # Get all run directories
    run_dirs = [d for d in os.listdir(domain_dir) 
                if os.path.isdir(os.path.join(domain_dir, d))]
    
    # Sort by modification time (newest first)
    run_dirs.sort(key=lambda x: os.path.getmtime(os.path.join(domain_dir, x)), reverse=True)
    
    # Load data from each run
    for run_dir in run_dirs:
        try:
            run_path = os.path.join(domain_dir, run_dir)
            meta_path = os.path.join(run_path, "run_meta.json")
            report_path = os.path.join(run_path, "reports", "final_report.json")
            
            # Load metadata
            meta = {}
            if os.path.exists(meta_path):
                with open(meta_path, 'r') as f:
                    meta = json.load(f)
            
            # Load findings
            findings = []
            if os.path.exists(report_path):
                with open(report_path, 'r') as f:
                    report_data = json.load(f)
                    findings = report_data.get("findings", [])
            
            # Create run data
            run_data = {
                "run_id": run_dir,
                "date": datetime.datetime.fromtimestamp(
                    os.path.getmtime(run_path)
                ).isoformat(),
                "meta": meta,
                "findings": findings,
                "total_findings": len(findings),
                "critical_findings": len([f for f in findings if f.get("severity", 0) >= 5]),
                "high_findings": len([f for f in findings if f.get("severity", 0) == 4]),
                "medium_findings": len([f for f in findings if f.get("severity", 0) == 3])
            }
            
            historical_runs.append(run_data)
        except Exception as e:
            print(f"Warning: Failed to load run {run_dir}: {e}")
            continue
    
    return historical_runs

def identify_recurring_vulnerabilities(historical_runs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Identify recurring vulnerabilities across scan runs."""
    # Group findings by type and target
    finding_groups = defaultdict(list)
    
    for run in historical_runs:
        run_id = run.get("run_id", "unknown")
        findings = run.get("findings", [])
        
        for finding in findings:
            # Create a key based on vulnerability type and target
            vuln_type = finding.get("type", "unknown")
            target = finding.get("target", "unknown")
            key = f"{vuln_type}::{target}"
            
            finding_groups[key].append({
                "run_id": run_id,
                "finding": finding,
                "date": run.get("date", "")
            })
    
    # Identify recurring vulnerabilities (appear in multiple runs)
    recurring = []
    for key, occurrences in finding_groups.items():
        if len(occurrences) > 1:
            # Sort by date
            occurrences.sort(key=lambda x: x["date"])
            
            vuln_type, target = key.split("::", 1) if "::" in key else (key, "unknown")
            
            recurring_vuln = {
                "type": vuln_type,
                "target": target,
                "occurrences": len(occurrences),
                "first_seen": occurrences[0]["date"],
                "last_seen": occurrences[-1]["date"],
                "runs": [occ["run_id"] for occ in occurrences],
                "severity_trend": [occ["finding"].get("severity", 1) for occ in occurrences]
            }
            
            recurring.append(recurring_vuln)
    
    # Sort by occurrences (most frequent first)
    recurring.sort(key=lambda x: x["occurrences"], reverse=True)
    
    return recurring

def calculate_improvement_metrics(historical_runs: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Calculate security improvement metrics over time."""
    if len(historical_runs) < 2:
        return {}
    
    # Sort runs chronologically
    sorted_runs = sorted(historical_runs, key=lambda x: x["date"])
    
    first_run = sorted_runs[0]
    latest_run = sorted_runs[-1]
    
    # Calculate improvements
    total_change = first_run["total_findings"] - latest_run["total_findings"]
    critical_change = first_run["critical_findings"] - latest_run["critical_findings"]
    high_change = first_run["high_findings"] - latest_run["high_findings"]
    
    # Calculate percentages
    total_pct_change = (total_change / first_run["total_findings"] * 100) if first_run["total_findings"] > 0 else 0
    critical_pct_change = (critical_change / first_run["critical_findings"] * 100) if first_run["critical_findings"] > 0 else 0
    
    return {
        "total_findings_improvement": {
            "absolute_change": total_change,
            "percentage_change": round(total_pct_change, 2),
            "improvement": total_change > 0
        },
        "critical_findings_improvement": {
            "absolute_change": critical_change,
            "percentage_change": round(critical_pct_change, 2),
            "improvement": critical_change > 0
        },
        "high_findings_improvement": {
            "absolute_change": high_change,
            "percentage_change": round((high_change / first_run["high_findings"] * 100) if first_run["high_findings"] > 0 else 0, 2),
            "improvement": high_change > 0
        },
        "scan_count": len(historical_runs),
        "time_span_days": (
            datetime.datetime.fromisoformat(latest_run["date"]) - 
            datetime.datetime.fromisoformat(first_run["date"])
        ).days if first_run["date"] and latest_run["date"] else 0
    }

def generate_trend_analysis_report(domain: str, base_dir: str = ".") -> Dict[str, Any]:
    """Generate a comprehensive trend analysis report."""
    # Load historical runs
    historical_runs = load_historical_runs(base_dir, domain)
    
    if not historical_runs:
        return {"error": "No historical runs found for domain: " + domain}
    
    # Identify recurring vulnerabilities
    recurring_vulns = identify_recurring_vulnerabilities(historical_runs)
    
    # Calculate improvement metrics
    improvement_metrics = calculate_improvement_metrics(historical_runs)
    
    # Create trend report
    trend_report = {
        "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
        "domain": domain,
        "analysis_period": {
            "start_date": historical_runs[-1].get("date", "") if historical_runs else "",
            "end_date": historical_runs[0].get("date", "") if historical_runs else "",
            "total_runs_analyzed": len(historical_runs)
        },
        "recurring_vulnerabilities": recurring_vulns[:20],  # Top 20 recurring
        "improvement_metrics": improvement_metrics,
        "scan_history": [
            {
                "run_id": run.get("run_id", ""),
                "date": run.get("date", ""),
                "total_findings": run.get("total_findings", 0),
                "critical_findings": run.get("critical_findings", 0),
                "high_findings": run.get("high_findings", 0)
            }
            for run in historical_runs[:10]  # Last 10 runs
        ]
    }
    
    return trend_report

def save_trend_report(trend_report: Dict[str, Any], outdir: str) -> str:
    """Save trend analysis report to file."""
    try:
        os.makedirs(os.path.join(outdir, "reports"), exist_ok=True)
        report_path = os.path.join(outdir, "reports", "trend_analysis.json")
        
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(trend_report, f, indent=2, ensure_ascii=False)
        
        return report_path
    except Exception as e:
        print(f"Warning: Failed to save trend report: {e}")
        return ""

# Integration with enhanced reporter
def integrate_with_enhanced_reporter():
    """Integrate trend analysis with the enhanced reporter."""
    try:
        # We would modify the enhanced reporter to include trend analysis
        pass
    except ImportError:
        pass

# Run integration when module is imported
integrate_with_enhanced_reporter()