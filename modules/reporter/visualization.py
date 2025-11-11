#!/usr/bin/env python3
"""
Visualization Module for PenAI
Generates charts and graphs for security findings using matplotlib and seaborn.
"""

import os
import json
from typing import List, Dict, Any
import datetime

# Check if visualization libraries are available
try:
    import matplotlib.pyplot as plt
    import seaborn as sns
    import numpy as np
    import pandas as pd
    VISUALIZATION_AVAILABLE = True
except ImportError:
    VISUALIZATION_AVAILABLE = False
    plt = None
    sns = None
    np = None
    pd = None

def ensure_visualization_dir(outdir: str) -> str:
    """Ensure the visualization directory exists."""
    viz_dir = os.path.join(outdir, "reports", "visualizations")
    os.makedirs(viz_dir, exist_ok=True)
    return viz_dir

def create_severity_distribution_chart(findings: List[Dict[str, Any]], outdir: str) -> str:
    """Create a severity distribution chart."""
    if not VISUALIZATION_AVAILABLE:
        return ""
    
    try:
        # Count severities
        severity_counts = {1: 0, 2: 0, 3: 0, 4: 0, 5: 0}
        for finding in findings:
            severity = finding.get("severity", 1)
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Create chart
        plt.figure(figsize=(10, 6))
        severities = list(severity_counts.keys())
        counts = list(severity_counts.values())
        colors = ['#90EE90', '#98FB98', '#FFD700', '#FF8C00', '#DC143C']  # Info to Critical
        
        bars = plt.bar(severities, counts, color=colors)
        plt.xlabel('Severity Level')
        plt.ylabel('Number of Findings')
        plt.title('Vulnerability Distribution by Severity')
        plt.xticks(severities)
        
        # Add value labels on bars
        for bar, count in zip(bars, counts):
            plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.1, 
                    str(count), ha='center', va='bottom')
        
        # Save chart
        viz_dir = ensure_visualization_dir(outdir)
        chart_path = os.path.join(viz_dir, "severity_distribution.png")
        plt.tight_layout()
        plt.savefig(chart_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        return chart_path
    except Exception as e:
        print(f"Warning: Failed to create severity distribution chart: {e}")
        return ""

def create_vulnerability_type_chart(findings: List[Dict[str, Any]], outdir: str) -> str:
    """Create a vulnerability type distribution chart."""
    if not VISUALIZATION_AVAILABLE:
        return ""
    
    try:
        # Count vulnerability types
        vuln_types = {}
        for finding in findings:
            vuln_type = finding.get("type", "unknown")
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
        
        # Top 10 vulnerability types
        sorted_vulns = sorted(vuln_types.items(), key=lambda x: x[1], reverse=True)[:10]
        types = [item[0] for item in sorted_vulns]
        counts = [item[1] for item in sorted_vulns]
        
        # Create chart
        plt.figure(figsize=(12, 8))
        y_pos = range(len(types))
        bars = plt.barh(y_pos, counts, color='skyblue')
        plt.xlabel('Number of Findings')
        plt.ylabel('Vulnerability Type')
        plt.title('Top 10 Vulnerability Types')
        plt.yticks(y_pos, types)
        
        # Add value labels on bars
        for i, (bar, count) in enumerate(zip(bars, counts)):
            plt.text(bar.get_width() + 0.1, bar.get_y() + bar.get_height()/2, 
                    str(count), ha='left', va='center')
        
        # Save chart
        viz_dir = ensure_visualization_dir(outdir)
        chart_path = os.path.join(viz_dir, "vulnerability_types.png")
        plt.tight_layout()
        plt.savefig(chart_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        return chart_path
    except Exception as e:
        print(f"Warning: Failed to create vulnerability type chart: {e}")
        return ""

def create_risk_heatmap(findings: List[Dict[str, Any]], outdir: str) -> str:
    """Create a risk heatmap based on severity and asset criticality."""
    if not VISUALIZATION_AVAILABLE:
        return ""
    
    try:
        # Prepare data
        data = []
        for finding in findings:
            severity = finding.get("severity", 1)
            criticality = finding.get("asset_criticality", 1.0)
            data.append([severity, criticality])
        
        if not data:
            return ""
        
        # Create DataFrame
        df = pd.DataFrame(data, columns=['Severity', 'Criticality'])
        
        # Create pivot table for heatmap
        pivot = df.pivot_table(index='Severity', columns='Criticality', aggfunc='size', fill_value=0)
        
        # Create heatmap
        plt.figure(figsize=(10, 6))
        sns.heatmap(pivot, annot=True, fmt="d", cmap="YlOrRd", cbar_kws={'label': 'Number of Findings'})
        plt.title('Risk Heatmap (Severity vs Asset Criticality)')
        plt.xlabel('Asset Criticality')
        plt.ylabel('Severity')
        
        # Save chart
        viz_dir = ensure_visualization_dir(outdir)
        chart_path = os.path.join(viz_dir, "risk_heatmap.png")
        plt.tight_layout()
        plt.savefig(chart_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        return chart_path
    except Exception as e:
        print(f"Warning: Failed to create risk heatmap: {e}")
        return ""

def create_trend_analysis_chart(runs_data: List[Dict[str, Any]], outdir: str) -> str:
    """Create a trend analysis chart showing findings over time."""
    if not VISUALIZATION_AVAILABLE:
        return ""
    
    try:
        # Prepare data
        dates = []
        total_findings = []
        critical_findings = []
        
        for run in runs_data:
            dates.append(run.get("date", ""))
            findings = run.get("findings", [])
            total_findings.append(len(findings))
            critical_findings.append(len([f for f in findings if f.get("severity", 0) >= 5]))
        
        if not dates:
            return ""
        
        # Create chart
        plt.figure(figsize=(12, 6))
        plt.plot(dates, total_findings, marker='o', label='Total Findings', linewidth=2)
        plt.plot(dates, critical_findings, marker='s', label='Critical Findings', linewidth=2)
        plt.xlabel('Scan Date')
        plt.ylabel('Number of Findings')
        plt.title('Vulnerability Trend Analysis')
        plt.legend()
        plt.xticks(rotation=45)
        plt.grid(True, alpha=0.3)
        
        # Save chart
        viz_dir = ensure_visualization_dir(outdir)
        chart_path = os.path.join(viz_dir, "trend_analysis.png")
        plt.tight_layout()
        plt.savefig(chart_path, dpi=300, bbox_inches='tight')
        plt.close()
        
        return chart_path
    except Exception as e:
        print(f"Warning: Failed to create trend analysis chart: {e}")
        return ""

def generate_visualization_report(findings: List[Dict[str, Any]], meta: Dict[str, Any], outdir: str) -> Dict[str, Any]:
    """Generate a visualization report with all charts."""
    if not VISUALIZATION_AVAILABLE:
        return {"message": "Visualization libraries not available. Install matplotlib and seaborn for charts."}
    
    # Create charts
    severity_chart = create_severity_distribution_chart(findings, outdir)
    vuln_type_chart = create_vulnerability_type_chart(findings, outdir)
    risk_heatmap = create_risk_heatmap(findings, outdir)
    
    # Create visualization report
    viz_report = {
        "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
        "charts": {
            "severity_distribution": severity_chart,
            "vulnerability_types": vuln_type_chart,
            "risk_heatmap": risk_heatmap
        }
    }
    
    # Write to file
    viz_dir = ensure_visualization_dir(outdir)
    report_path = os.path.join(viz_dir, "visualization_report.json")
    
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(viz_report, f, indent=2, ensure_ascii=False)
    
    return viz_report

# Integration with enhanced reporter
def integrate_with_enhanced_reporter():
    """Integrate visualization with the enhanced reporter."""
    try:
        from modules.reporter.enhanced_reporter import generate_enhanced_report
        
        # We'll add visualization generation to the enhanced report
        # This is a simplified integration - in practice, you might want to modify
        # the enhanced report generation to include visualization
        pass
    except ImportError:
        pass

# Run integration when module is imported
integrate_with_enhanced_reporter()