#!/usr/bin/env python3
"""
Advanced Analytics Orchestrator for PenAI
Integrates all enhanced reporting and analysis capabilities.
"""

import json
import os
from typing import List, Dict, Any

# Import all the enhanced reporting modules
MODULES_AVAILABLE = True

try:
    import modules.reporter.enhanced_reporter as enhanced_reporter
    import modules.reporter.visualization as visualization
    import modules.reporter.export_formats as export_formats
    import modules.reporter.false_positive_reduction as false_positive_reduction
    import modules.reporter.trend_analysis as trend_analysis
    import modules.reporter.threat_modeling as threat_modeling
    import modules.reporter.root_cause_analysis as root_cause_analysis
except ImportError as e:
    print(f"Warning: Some modules not available: {e}")
    MODULES_AVAILABLE = False

def run_comprehensive_analysis(findings: List[Dict[str, Any]], meta: Dict[str, Any], outdir: str) -> Dict[str, Any]:
    """Run all advanced analytics on the findings."""
    if not MODULES_AVAILABLE:
        return {"error": "Advanced analytics modules not available"}
    
    try:
        # 1. Reduce false positives
        print("Reducing false positives...")
        filtered_findings = findings
        if 'false_positive_reduction' in globals() and false_positive_reduction:
            filtered_findings = false_positive_reduction.reduce_false_positives(findings)
        
        # 2. Enhance findings with threat modeling
        print("Enhancing findings with threat modeling...")
        threat_enhanced_findings = filtered_findings
        if 'threat_modeling' in globals() and threat_modeling:
            threat_enhanced_findings = threat_modeling.enhance_report_with_threat_modeling(filtered_findings)
        
        # 3. Generate enhanced report
        print("Generating enhanced report...")
        enhanced_report = {}
        if 'enhanced_reporter' in globals() and enhanced_reporter:
            enhanced_report = enhanced_reporter.generate_enhanced_report(threat_enhanced_findings, meta, outdir)
        
        # 4. Add root cause analysis
        print("Performing root cause analysis...")
        if 'root_cause_analysis' in globals() and root_cause_analysis:
            root_cause_analysis_result = root_cause_analysis.perform_root_cause_analysis(threat_enhanced_findings)
            enhanced_report["root_cause_analysis"] = root_cause_analysis_result
        
        # 5. Add threat modeling
        print("Generating threat model...")
        if 'threat_modeling' in globals() and threat_modeling:
            threat_model = threat_modeling.generate_threat_model(threat_enhanced_findings)
            enhanced_report["threat_model"] = threat_model
        
        # 6. Generate visualizations
        print("Creating visualizations...")
        if 'visualization' in globals() and visualization:
            visualization_report = visualization.generate_visualization_report(threat_enhanced_findings, meta, outdir)
            enhanced_report["visualizations"] = visualization_report
        
        # 7. Export in multiple formats
        print("Exporting reports in multiple formats...")
        if 'export_formats' in globals() and export_formats:
            export_results = export_formats.export_all_formats(enhanced_report, outdir)
            enhanced_report["exported_formats"] = export_results
        
        # 8. Generate trend analysis (if domain is available)
        domain = meta.get("primary_domain", "unknown")
        if domain != "unknown" and 'trend_analysis' in globals() and trend_analysis:
            print("Generating trend analysis...")
            trend_report = trend_analysis.generate_trend_analysis_report(domain, ".")
            if trend_report and "error" not in trend_report:
                trend_path = trend_analysis.save_trend_report(trend_report, outdir)
                enhanced_report["trend_analysis"] = {
                    "report": trend_report,
                    "report_path": trend_path
                }
        
        # Save the comprehensive report
        comprehensive_path = os.path.join(outdir, "reports", "comprehensive_analysis.json")
        with open(comprehensive_path, "w", encoding="utf-8") as f:
            json.dump(enhanced_report, f, indent=2, ensure_ascii=False)
        
        print("Comprehensive analysis complete!")
        return enhanced_report
        
    except Exception as e:
        print(f"Error during comprehensive analysis: {e}")
        return {"error": f"Analysis failed: {str(e)}"}

def integrate_with_agent():
    """Integrate advanced analytics with the main agent."""
    try:
        from modules import reporter as ReporterModule
        Reporter = getattr(ReporterModule, 'Reporter', None)
        
        # Only integrate if Reporter is available and has write_reports method
        if Reporter is not None and hasattr(Reporter, 'write_reports'):
            # Save original method
            original_write_reports = Reporter.write_reports
            
            def advanced_write_reports(outdir, meta, findings):
                # Call original method
                original_write_reports(outdir, meta, findings)
                
                # Run advanced analytics
                try:
                    run_comprehensive_analysis(findings, meta, outdir)
                except Exception as e:
                    print(f"Warning: Failed to run comprehensive analysis: {e}")
            
            # Replace the method
            Reporter.write_reports = staticmethod(advanced_write_reports)
        
    except ImportError:
        print("Warning: Could not integrate with agent - modules not available")

# Run integration when module is imported
integrate_with_agent()

if __name__ == "__main__":
    # This module is primarily meant to be imported, but we can include a simple test
    print("Advanced Analytics Module for PenAI")
    print("Import this module to use its functions")