#!/usr/bin/env python3
"""
Orchestrator agent (robust, tolerant, integrates adapters/tools).

Behavior changes from original:
 - Always runs non-destructive phase first.
 - After non-destructive completes, interactively prompt operator (y/N)
   to confirm running destructive phase. If confirmed, destructive-capable
   adapters and exploit modules will run. Interactive approval overrides
   scope.is_destructive_allowed (treats operator answer as explicit permission).
 - --force-destructive skips interactive prompt (still forces destructive run).
 - --clear-logs will remove previous runs for the same primary domain before starting.
"""

from __future__ import annotations
import asyncio
import argparse
import os
import sys
import importlib.util
import importlib
import json
import logging
import shutil
from typing import List, Dict, Any, Tuple, Optional
from pathlib import Path

# tolerant imports
try:
    from modules.scope import ScopeManager
except Exception:
    ScopeManager = None  # type: ignore

try:
    from modules.logger import init_logger
except Exception:
    init_logger = None  # type: ignore

try:
    from modules.reporter import Reporter  # type: ignore
except Exception:
    Reporter = None  # type: ignore

try:
    from modules.tools.parsers import parse_tool_envelope  # type: ignore
except Exception:
    parse_tool_envelope = None  # type: ignore

try:
    from modules.notifications import send_scan_results_notification  # type: ignore
except Exception:
    send_scan_results_notification = None  # type: ignore

try:
    from modules.vuln_intel import correlate_findings_with_cve, get_threat_intel_feeds  # type: ignore
except Exception:
    correlate_findings_with_cve = None  # type: ignore
    get_threat_intel_feeds = None  # type: ignore

try:
    from modules.tools.manager import run_tool  # type: ignore
except Exception:
    run_tool = None  # type: ignore

try:
    from modules.distributed_scanner import initiate_distributed_scan, get_distributed_scan_results  # type: ignore
except Exception:
    initiate_distributed_scan = None  # type: ignore
    get_distributed_scan_results = None  # type: ignore

try:
    from modules.resource_monitor import get_resource_monitor, start_resource_monitoring, stop_resource_monitoring  # type: ignore
except Exception:
    get_resource_monitor = None  # type: ignore
    start_resource_monitoring = None  # type: ignore
    stop_resource_monitoring = None  # type: ignore

try:
    from modules.cache_manager import get_cached_results, cache_results  # type: ignore
except Exception:
    get_cached_results = None  # type: ignore
    cache_results = None  # type: ignore

try:
    from modules.tenant_manager import validate_tenant_scan, get_tenant  # type: ignore
except Exception:
    validate_tenant_scan = None  # type: ignore
    get_tenant = None  # type: ignore

# dynamic curated generator if present
_gen_path = os.path.join(os.path.dirname(__file__), "modules", "reporter", "generate_curated.py")
gen_mod = None
if os.path.exists(_gen_path):
    try:
        spec = importlib.util.spec_from_file_location("generate_curated", _gen_path)
        if spec is not None:
            gen_mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(gen_mod)  # type: ignore
    except Exception:
        gen_mod = None

# ---------------- adapters discovery ----------------
def _discover_tool_adapters(base_dir: Optional[str] = None) -> List[Tuple[str, bool]]:
    if base_dir is None:
        base_dir = os.path.join(os.path.dirname(__file__), "modules", "tools")
    base = Path(base_dir)
    adapters = set()

    search_dirs = [base]
    if (base / "adapters").is_dir():
        search_dirs.append(base / "adapters")

    # Files that should not be treated as adapters
    excluded_files = {
        "create_proof",
        "__init__",
        "adapter_base"
    }

    for d in search_dirs:
        try:
            for p in d.iterdir():
                if p.is_file() and p.suffix == ".py":
                    name = p.stem
                    # Skip excluded files
                    if name in excluded_files:
                        continue
                    if name.endswith("_adapter"):
                        adapters.add(name[:-8])
                    else:
                        adapters.add(name)
        except Exception:
            continue

    destructive_suspects = {
        "sqlmap", "wpscan", "hydra", "medusa", "john", "hashcat", "msfconsole", "msf", "commix",
        "crowbar", "ncrack", "crackmapexec", "crack", "ldapdomaindump", "beef", "metasploit",
    }

    return [(a, a in destructive_suspects) for a in sorted(adapters)]

TOOL_ADAPTERS: List[Tuple[str, bool]] = _discover_tool_adapters()

# ---------------- helpers ----------------
def safe_call_module_fn(module, possible_names: List[str], *args, **kwargs):
    if module is None:
        return None
    for name in possible_names:
        fn = getattr(module, name, None)
        if callable(fn):
            try:
                return fn(*args, **kwargs)
            except TypeError:
                # fallback: try calling with zero args (some adapters expose main() without params)
                try:
                    return fn()
                except Exception:
                    raise
    return None


def write_json(path: str, obj: Any) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, ensure_ascii=False)

def parse_tool_outputs(run_dir: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    gen_dir = os.path.join(run_dir, "generated", "tools")
    if not os.path.isdir(gen_dir):
        return findings

    for fname in os.listdir(gen_dir):
        if not fname.endswith(".json"):
            continue
        path = os.path.join(gen_dir, fname)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                envelope = json.load(fh)
        except Exception:
            findings.append({
                "type": f"external-tool-{fname}",
                "target": "<unknown>",
                "severity": 1,
                "evidence": f"failed to read {fname}",
                "source": {"file": path}
            })
            continue

        tool_name = fname.rsplit(".", 1)[0]
        parsed: Optional[List[Dict[str, Any]]] = None
        if parse_tool_envelope:
            try:
                parsed = parse_tool_envelope(tool_name, envelope, run_dir)
            except Exception:
                parsed = None

        if not parsed and isinstance(envelope, dict):
            pf = envelope.get("parsed_findings") or (envelope.get("result") or {}).get("parsed_findings")
            if isinstance(pf, list):
                parsed = pf

        if parsed:
            for p in parsed:
                if isinstance(p, dict):
                    p.setdefault("source", {}).setdefault("tool", tool_name)
            findings.extend(parsed)
        else:
            findings.append({
                "type": f"external-tool-{tool_name}",
                "target": envelope.get("result", {}).get("target") if isinstance(envelope, dict) else "<unknown>",
                "severity": 2,
                "evidence": json.dumps(envelope)[:1500],
                "source": {"tool": tool_name, "file": os.path.relpath(path, run_dir)},
                "raw_tool_output": envelope,
            })
    return findings

def run_external_tools(scope, outdir: str, logger, only_non_destructive: bool = True) -> List[str]:
    """
    Run adapters; if only_non_destructive==False then destructive-suspect adapters are executed.
    """
    written = []
    gen_dir = os.path.join(outdir, "generated", "tools")
    os.makedirs(gen_dir, exist_ok=True)

    meta = {}
    try:
        with open(os.path.join(outdir, "run_meta.json"), "r", encoding="utf-8") as fh:
            meta = json.load(fh)
    except Exception:
        meta = {}

    for tool_name, is_destructive in TOOL_ADAPTERS:
        if is_destructive and only_non_destructive:
            logger.info("Skipping destructive-capable adapter %s (safety gate)", tool_name)
            out_path = os.path.join(gen_dir, f"{tool_name}.json")
            write_json(out_path, {"status": "skipped_by_safety", "tool": tool_name})
            written.append(out_path)
            continue

        logger.info("Running adapter: %s (destructive=%s)", tool_name, is_destructive)

        adapter_module = None
        candidate_paths = [
            os.path.join(os.path.dirname(__file__), "modules", "tools", f"{tool_name}_adapter.py"),
            os.path.join(os.path.dirname(__file__), "modules", "tools", f"{tool_name}.py"),
            os.path.join(os.path.dirname(__file__), "modules", "tools", "adapters", f"{tool_name}_adapter.py"),
            os.path.join(os.path.dirname(__file__), "modules", "tools", "adapters", f"{tool_name}.py"),
        ]
        for adapter_path in candidate_paths:
            try:
                if os.path.exists(adapter_path):
                    spec = importlib.util.spec_from_file_location(f"modules.tools.{tool_name}_adapter", adapter_path)
                    if spec is not None:
                        adapter_module = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(adapter_module)  # type: ignore
                    break
            except Exception as e:
                logger.debug("Adapter module import failed for %s at %s: %s", tool_name, adapter_path, e)
                adapter_module = None

        result = None
        try:
            if adapter_module:
                targets = meta.get("targets") or meta.get("target") or []
                t0 = targets[1] if False else (targets[0] if isinstance(targets, list) and targets else (targets if isinstance(targets, str) else None))
                result = safe_call_module_fn(adapter_module, ["run", "main", "run_adapter"], outdir, t0)
            elif run_tool:
                try:
                    result = run_tool(tool_name, outdir)
                except TypeError:
                    try:
                        result = run_tool(tool_name, outdir, None, None)
                    except Exception:
                        raise
            else:
                result = {"status": "not_available", "tool": tool_name, "note": "no adapter/module and no run_tool"}
        except Exception as e:
            logger.exception("Adapter %s execution failed: %s", tool_name, e)
            result = {"status": "error", "tool": tool_name, "error": str(e)}

        out_path = os.path.join(gen_dir, f"{tool_name}.json")
        try:
            write_json(out_path, result)
        except Exception:
            try:
                with open(out_path, "w", encoding="utf-8") as fh:
                    fh.write(str(result))
            except Exception:
                pass
        written.append(out_path)
        logger.info("Adapter %s: wrote %s", tool_name, out_path)
    return written

# ---------------- non-destructive phase ----------------
async def run_non_destructive_phase(scope, outdir: str,
                                    poc_best_only: bool = True, poc_threshold: float = 0.5,
                                    export_html: bool = True, export_pdf: bool = True) -> dict:
    if init_logger:
        logger = init_logger(outdir)
    else:
        logging.basicConfig(level=logging.INFO)
        logger = logging.getLogger("agent")

    logger.info("Starting non-destructive phase")

    # lazy imports
    try:
        from modules.recon.passive import passive_recon
    except Exception:
        passive_recon = None  # type: ignore
    try:
        from modules.recon.active import active_recon
    except Exception:
        active_recon = None  # type: ignore
    try:
        from modules.crawler import crawl
    except Exception:
        crawl = None  # type: ignore
    try:
        from modules.fingerprint import fingerprint
    except Exception:
        fingerprint = None  # type: ignore
    try:
        from modules.scanner.param_discovery import discover_params
    except Exception:
        discover_params = None  # type: ignore
    try:
        from modules.scanner.form_tester import test_all_params
    except Exception:
        test_all_params = None  # type: ignore
    try:
        from modules.triage import triage_all
    except Exception:
        triage_all = None  # type: ignore

    passive = []
    if passive_recon:
        try:
            passive = await passive_recon(scope, outdir)
        except Exception:
            logger.exception("passive_recon failed")
    logger.info("Passive recon done")

    active = []
    if active_recon:
        try:
            active = await active_recon(scope, outdir)
        except Exception:
            logger.exception("active_recon failed")
    logger.info("Active recon done")

    urls = []
    if crawl:
        try:
            urls = await crawl(scope, outdir)
        except Exception:
            logger.exception("crawl failed")
    logger.info("Crawl done, found %s pages", len(urls))

    fp = {}
    if fingerprint:
        try:
            fp = await fingerprint(scope, outdir)
        except Exception:
            logger.exception("fingerprint failed")
    logger.info("Fingerprint done")

    params = []
    if discover_params:
        try:
            params = await discover_params(scope, outdir)
        except Exception:
            logger.exception("discover_params failed")
    logger.info("Discovered %s parameterized endpoints", len(params))

    form_findings = []
    if test_all_params:
        try:
            form_findings = await test_all_params(outdir)
        except Exception:
            logger.exception("test_all_params failed")
    logger.info("Form testing done, results: %s", len(form_findings))

    try:
        only_non_destructive = not scope.is_destructive_allowed(outdir)
        logger.info("Running external adapters (only_non_destructive=%s)", only_non_destructive)
        run_external_tools(scope, outdir, logger, only_non_destructive)
    except Exception as e:
        logger.exception("external adapters step failed: %s", e)

    targets_to_scan: List[str] = list(scope.targets or [])
    for p in params:
        if p.get("type") in ("query", "form"):
            targets_to_scan.append(p["url"])

    # Use enhanced adaptive scanning to prioritize targets and determine scan strategy
    try:
        from modules.scanner.adaptive_scanner import get_adaptive_scanner
        adaptive_scanner = get_adaptive_scanner(outdir, scope)
        
        # Get dynamic scheduling strategy with comprehensive risk assessment
        scan_strategy = adaptive_scanner.get_dynamic_scheduling_strategy(targets_to_scan)
        logger.info("Enhanced adaptive scan strategy: %s targets, %s parallel scans", 
                   len(scan_strategy["scan_order"]), scan_strategy["parallel_scans"])
        
        # Log any scheduling adjustments
        if scan_strategy.get("schedule_adjustments"):
            for adjustment in scan_strategy["schedule_adjustments"]:
                logger.info("Scheduling adjustment: %s", adjustment)
        
        # Prioritize targets based on enhanced adaptive strategy
        prioritized_targets = scan_strategy["scan_order"]
        
        # Filter targets based on adaptive scanning decisions
        filtered_targets = [
            url for url in prioritized_targets 
            if adaptive_scanner.should_scan_target(url, "general")
        ]
        
        targets_to_scan = filtered_targets if filtered_targets else targets_to_scan
        
        # Log timing recommendations
        if scan_strategy.get("timing_recommendations"):
            for recommendation in scan_strategy["timing_recommendations"]:
                logger.info("Timing recommendation: %s", recommendation)
                
    except Exception as e:
        logger.debug("Enhanced adaptive scanning not available, using default target list: %s", e)

    findings: List[Dict[str, Any]] = []
    try:
        from modules.scanner.xss import xss_check
    except Exception:
        xss_check = None  # type: ignore
    try:
        from modules.scanner.sqli import sqli_check
    except Exception:
        sqli_check = None  # type: ignore

    logger.info("Targets to scan: %s", len(targets_to_scan))
    
    # Apply enhanced adaptive scanning rate limiting if needed
    parallel_limit = 5  # Default
    try:
        from modules.scanner.adaptive_scanner import get_adaptive_scanner
        adaptive_scanner = get_adaptive_scanner(outdir, scope)
        scan_strategy = adaptive_scanner.get_dynamic_scheduling_strategy(targets_to_scan)
        parallel_limit = scan_strategy["parallel_scans"]
        
        # Apply system load updates
        import psutil
        try:
            system_load = psutil.cpu_percent(interval=1) / 100.0
            adaptive_scanner.update_system_load(system_load)
        except Exception:
            pass
            
    except Exception:
        pass

    # Scan targets with adaptive parallelization
    import asyncio
    semaphore = asyncio.Semaphore(parallel_limit)
    
    async def scan_target_with_limit(url):
        async with semaphore:
            results = []
            
            # Get real-time adaptive configuration
            try:
                from modules.scanner.adaptive_scanner import get_adaptive_scanner
                adaptive_scanner = get_adaptive_scanner(outdir, scope)
                
                # Get current findings for context
                current_findings = findings.copy()
                
                # Check if we should scan this target
                if xss_check and adaptive_scanner.should_scan_target_realtime(url, "xss", current_findings):
                    try:
                        results.extend(await xss_check(url, outdir))
                    except Exception:
                        logger.exception("xss_check failed for %s", url)
                        
                if sqli_check and adaptive_scanner.should_scan_target_realtime(url, "sqli", current_findings):
                    try:
                        results.extend(await sqli_check(url, outdir))
                    except Exception:
                        logger.exception("sqli_check failed for %s", url)
            except Exception as e:
                logger.debug("Real-time adaptive configuration failed, using default scanning: %s", e)
                
                # Fallback to original scanning
                if xss_check:
                    try:
                        results.extend(await xss_check(url, outdir))
                    except Exception:
                        logger.exception("xss_check failed for %s", url)
                if sqli_check:
                    try:
                        results.extend(await sqli_check(url, outdir))
                    except Exception:
                        logger.exception("sqli_check failed for %s", url)
            
            return results
    
    # Execute scans with adaptive parallelization
    scan_tasks = [scan_target_with_limit(url) for url in targets_to_scan]
    scan_results = await asyncio.gather(*scan_tasks, return_exceptions=True)
    
    # Collect findings from all scans
    for result in scan_results:
        if isinstance(result, Exception):
            logger.exception("Scan task failed: %s", result)
        elif isinstance(result, list):
            findings.extend(result)

    findings.extend(form_findings)

    try:
        parsed_tools = parse_tool_outputs(outdir)
        if parsed_tools:
            findings.extend(parsed_tools)
            logger.info("Tool parsers: added %s findings from generated/tools", len(parsed_tools))
    except Exception:
        logger.exception("tool parsing failed")

    if triage_all:
        try:
            findings = triage_all(findings)
        except Exception:
            logger.exception("triage_all failed, continuing with untriaged findings")

    # Integrate with vulnerability intelligence sources
    if correlate_findings_with_cve:
        try:
            findings = correlate_findings_with_cve(findings)
            logger.info("CVE correlation completed for %s findings", len(findings))
        except Exception:
            logger.exception("CVE correlation failed")
    
    # Get threat intelligence feeds
    # Threat intelligence will be added to meta after meta is defined

    try:
        from modules.ai.predictor import predict_findings  # type: ignore
        try:
            findings = predict_findings(findings, run_dir=outdir)
            logger.info("AI predictions attached to findings (count=%s)", len(findings))
        except Exception:
            logger.exception("predictor failed to run")
    except Exception:
        logger.debug("No AI predictor available", exc_info=True)

    # generate PoCs (non-destructive)
    pocs: List[Dict[str, Any]] = []
    try:
        runner_mod = None
        runner_path = os.path.join(os.path.dirname(__file__), "modules", "poc", "runner.py")
        if os.path.exists(runner_path):
            spec = importlib.util.spec_from_file_location("modules.poc.runner", runner_path)
            if spec is not None:
                runner_mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(runner_mod)  # type: ignore
        if runner_mod:
            gen_fn = getattr(runner_mod, "generate_pocs_for_findings", None)
            if gen_fn and callable(gen_fn):
                maybe = gen_fn(outdir, findings)
                if asyncio.iscoroutine(maybe):
                    pocs = await maybe
                else:
                    pocs = maybe or []  # type: ignore
    except Exception:
        logger.exception("generate_pocs_for_findings failed")
    logger.info("PoCs generated: %s", len(pocs))

    meta = {
        "passive": passive,
        "active": active,
        "crawl_count": len(urls),
        "fingerprint": fp,
        "pocs_summary": {"count": len(pocs)},
        "pocs_file": "reports/pocs.json",
    }

    # Add threat intelligence to meta
    if get_threat_intel_feeds:
        try:
            threat_intel = get_threat_intel_feeds()
            meta["threat_intel"] = threat_intel
            logger.info("Threat intelligence feeds retrieved")
        except Exception:
            logger.exception("Threat intelligence retrieval failed")

    # Enhanced AI reasoning for correlation and triage (after meta is defined)
    try:
        from modules.ai.reasoner import enhance_findings_with_ai_reasoning
        try:
            # Prepare context for AI reasoning
            context = {
                "targets": list(scope.targets or []),
                "critical_assets": meta.get("critical_assets", []),
                "primary_domain": scope.primary_domain
            }
            findings = enhance_findings_with_ai_reasoning(findings, context)
            logger.info("Enhanced AI reasoning applied to findings (count=%s)", len(findings))
        except Exception:
            logger.exception("enhanced AI reasoning failed to run")
    except Exception:
        logger.debug("No enhanced AI reasoning available", exc_info=True)

    if Reporter:
        try:
            Reporter.write_reports(outdir, meta, findings)
            logger.info("Reports written")
        except Exception:
            logger.exception("Reporter.write_reports failed")
    else:
        try:
            reports_dir = os.path.join(outdir, "reports")
            os.makedirs(reports_dir, exist_ok=True)
            with open(os.path.join(reports_dir, "final_report.json"), "w", encoding="utf-8") as fh:
                json.dump({"findings": findings, "meta": meta}, fh, indent=2)
            logger.info("Wrote minimal final_report.json (Reporter missing)")
        except Exception:
            logger.exception("Failed to write fallback report")

    # Send notifications about scan completion
    if send_scan_results_notification:
        try:
            send_scan_results_notification(outdir, ', '.join(scope.targets or []), success=True)
            logger.info("Scan completion notification sent")
        except Exception:
            logger.exception("Failed to send scan completion notification")

    # post-processing pipeline (normalize/map/attach/curated)
    try:
        normalize_mod = None
        try:
            from modules.poc import normalize_pocs as normalize_pocs_module  # type: ignore
        except Exception:
            normalize_pocs_module = None  # type: ignore
        if normalize_pocs_module:
            try:
                safe_call_module_fn(normalize_pocs_module, ["normalize_pocs", "normalize", "main"], outdir)
                logger.info("normalize_pocs executed")
            except Exception:
                logger.exception("normalize_pocs invocation failed")
    except Exception:
        logger.exception("normalize step failed")

    try:
        try:
            from modules.poc import map_pocs_to_findings as map_pocs_module  # type: ignore
        except Exception:
            map_pocs_module = None  # type: ignore
        if map_pocs_module:
            try:
                safe_call_module_fn(map_pocs_module, ["map_pocs", "main"], outdir)
                logger.info("map_pocs executed")
            except Exception:
                logger.exception("map_pocs invocation failed")
    except Exception:
        logger.exception("map pocs step failed")

    try:
        try:
            from modules.poc import attach_pocs as attach_pocs_module  # type: ignore
        except Exception:
            attach_pocs_module = None  # type: ignore
        if attach_pocs_module:
            try:
                safe_call_module_fn(attach_pocs_module, ["attach_pocs_to_report", "attach_pocs"], outdir, best_only=poc_best_only, threshold=poc_threshold)
                logger.info("attach_pocs executed")
            except Exception:
                logger.exception("attach_pocs invocation failed")
    except Exception:
        logger.exception("attach pocs step failed")

    # Generate summary report
    try:
        summary_report_path = os.path.join(os.path.dirname(__file__), "modules", "reporter", "summary_report.py")
        if os.path.exists(summary_report_path):
            spec = importlib.util.spec_from_file_location("modules.reporter.summary_report", summary_report_path)
            if spec is not None and spec.loader is not None:
                summary_report_module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(summary_report_module)
                if hasattr(summary_report_module, "generate_summary_report"):
                    summary_report = summary_report_module.generate_summary_report(findings, meta, outdir)
                    logger.info("Summary report generated: %s", os.path.join(outdir, "reports", "summary_report.json"))
    except Exception as e:
        logger.debug("Failed to generate summary report: %s", e)

    def _call_generate_curated_module(gen_mod, outdir, export_html=True, export_pdf=True, logger=None):
        if logger is None:
            logger = logging.getLogger(__name__)
        argv_backup = sys.argv[:]
        try:
            sys.argv = ["generate_curated.py", outdir]
            if export_html:
                sys.argv.append("--html")
            if export_pdf:
                sys.argv.append("--pdf")
            for candidate in ("main", "generate", "run"):
                fn = getattr(gen_mod, candidate, None)
                if callable(fn):
                    try:
                        try:
                            res = fn()
                        except TypeError:
                            res = fn(outdir)
                        logger.info("Called generate_curated.%s successfully", candidate)
                        return res
                    except Exception as e:
                        logger.debug("generate_curated.%s raised, trying next: %s", candidate, e)
            if hasattr(gen_mod, "main") and callable(getattr(gen_mod, "main")):
                try:
                    return gen_mod.main()
                except Exception:
                    pass
            logger.warning("generate_curated did not expose a usable entrypoint; skipping curated export.")
        finally:
            sys.argv = argv_backup

    try:
        if gen_mod:
            _call_generate_curated_module(gen_mod, outdir, export_html=export_html, export_pdf=export_pdf, logger=logger)
        else:
            logger.info("generate_curated module not available; skipping curated export.")
    except Exception as e:
        logger.exception("generate_curated failed: %s", e)

    logger.info("Non-destructive phase complete")
    return {
        "pocs_generated": len(pocs),
        "reports_dir": os.path.join(outdir, "reports"),
        "findings_count": len(findings),
    }

# ---------------- destructive phase ----------------
async def run_destructive_phase(scope, outdir: str, logger=None, force: bool = False) -> dict:
    if init_logger and logger is None:
        logger = init_logger(outdir)
    if logger is None:
        logging.basicConfig(level=logging.INFO)
        logger = logging.getLogger("agent")

    logger.warning("Starting DESTRUCTIVE phase — verifying safeguards")

    # if not force and not scope.is_destructive_allowed(outdir):
    #     # normally we'd block here, but interactive approval will call with force=True
    #     logger.error("Destructive safeguards not satisfied. Aborting destructive phase.")
    #     return {"destructive_results": [], "merged_report": None, "skipped": True}

    results: List[Dict[str, Any]] = []

    # run sqlmap exploit wrapper (if present)
    try:
        mod = importlib.import_module("modules.destructive.sqlmap_exploit")
        if hasattr(mod, "run_sqlmap_exploit"):
            s = await mod.run_sqlmap_exploit(scope, outdir)  # type: ignore
            results.append({"module": "sqlmap_exploit", "results": s})
            logger.info("sqlmap_exploit returned %s items", len(s))
    except Exception as e:
        logger.exception("sqlmap_exploit error: %s", e)
        results.append({"module": "sqlmap_exploit", "error": str(e)})

    # optional RCE tester
    try:
        mod = importlib.import_module("modules.destructive.rce_tester")
        if hasattr(mod, "run_rce_tests"):
            rce_findings = await mod.run_rce_tests(scope, outdir)  # type: ignore
            if rce_findings:
                results.append({"module": "rce_tester", "results": rce_findings})
                logger.info("rce_tester returned %s findings", len(rce_findings))
                genp = os.path.join(outdir, "generated", "rce_tester.json")
                write_json(genp, {"result": rce_findings})
    except Exception as e:
        logger.exception("rce_tester invocation failed: %s", e)
        results.append({"module": "rce_tester", "error": str(e)})

    # Merge destructive findings into an existing final report (create if needed)
    out_path = None
    try:
        rpt_candidates = [
            os.path.join(outdir, "reports", "final_report_with_pocs_map.json"),
            os.path.join(outdir, "reports", "final_report_with_pocs.json"),
            os.path.join(outdir, "reports", "final_report.json"),
        ]
        final = None
        base_report_path = None
        for c in rpt_candidates:
            if os.path.isfile(c):
                try:
                    with open(c, "r", encoding="utf-8") as fh:
                        final = json.load(fh)
                    base_report_path = c
                    break
                except Exception:
                    final = None
        if final is None:
            final = {"findings": [], "meta": {}}
            base_report_path = os.path.join(outdir, "reports", "final_report.json")

        existing_evidence = {
            (f.get("type"), f.get("target"), str(f.get("evidence"))[:200]) for f in final.get("findings", [])
        }
        appended = 0
        for f in results:
            key = (f.get("module"), None, str(f)[:200])
            if key not in existing_evidence:
                final.setdefault("findings", []).append(f)
                appended += 1

        final_meta = final.get("meta", {})
        final_meta.setdefault("destructive", {})["appended_count"] = appended
        final_meta["destructive"]["source_report"] = os.path.relpath(base_report_path, outdir) if base_report_path else "unknown"
        final["meta"] = final_meta

        out_path = os.path.join(outdir, "reports", "final_report_with_destructive.json")
        write_json(out_path, final)
        logger.info("Wrote merged destructive report: %s (appended=%s)", out_path, appended)
    except Exception as e:
        logger.exception("Failed to merge destructive findings into report: %s", e)

    logger.warning("Destructive phase complete")
    return {"destructive_results": results, "merged_report": out_path if out_path else None}

# ---------------- interactive helper ----------------
async def _ask_interactive_confirmation(prompt: str) -> bool:
    loop = asyncio.get_running_loop()
    try:
        resp = await loop.run_in_executor(None, input, prompt)
    except Exception:
        return False
    return str(resp).strip().lower() == "y"

# ---------------- cleanup helper ----------------
def clear_old_runs_for_domain(primary_domain: str, keep_run_dir: Optional[str] = None):
    """
    Remove previously created runs for this domain to "clear logs".
    If keep_run_dir is provided, that specific run subdir will be preserved.
    """
    base = os.path.join("runs", primary_domain)
    if not os.path.isdir(base):
        return
    for name in os.listdir(base):
        path = os.path.join(base, name)
        if keep_run_dir and os.path.abspath(path) == os.path.abspath(keep_run_dir):
            continue
        try:
            if os.path.isdir(path):
                shutil.rmtree(path)
            else:
                os.remove(path)
        except Exception:
            # swallow errors - not critical
            pass

# ---------------- orchestration entry ----------------
async def run(scope, outdir: str,
              poc_best_only: bool = True, poc_threshold: float = 0.5,
              export_html: bool = True, export_pdf: bool = True,
              force_destructive: bool = False, clear_logs: bool = False,
              skip_destructive: bool = False):
    logger = logging.getLogger("agent")

    if clear_logs:
        try:
            clear_old_runs_for_domain(scope.primary_domain, keep_run_dir=outdir)
            logger.info("Cleared old runs for domain %s", scope.primary_domain)
        except Exception:
            logger.exception("Failed clearing old runs")

    nd_summary = await run_non_destructive_phase(scope, outdir,
                                                 poc_best_only=poc_best_only,
                                                 poc_threshold=poc_threshold,
                                                 export_html=export_html,
                                                 export_pdf=export_pdf)

    # interactive decision for destructive
    do_destructive = False
    if skip_destructive:
        logger.info("Skip-destructive flag provided; skipping destructive phase.")
        do_destructive = False
    elif force_destructive:
        logger.warning("Force-destructive provided; skipping interactive confirmation.")
        do_destructive = True
    else:
        prompt = (
            "\n*** DESTRUCTIVE TESTS CONFIRMATION REQUIRED ***\n"
            f"Targets: {', '.join(scope.targets or [])}\n"
            f"Run dir: {outdir}\n"
            "Do you have explicit permission to run destructive tests? (y/N): "
        )
        approved = await _ask_interactive_confirmation(prompt)
        if approved:
            logger.warning("Operator approved destructive tests interactively.")
            do_destructive = True
        else:
            logger.info("Operator denied destructive tests. Skipping destructive phase.")

    if do_destructive:
        try:
            logger.info("Re-running external adapters to include destructive-capable adapters (this may invoke exploit tools).")
            # allow destructive adapters to actually run
            run_external_tools(scope, outdir, logger, only_non_destructive=False)
        except Exception:
            logger.exception("Failed while re-running destructive-capable adapters")

        try:
            # pass force=True to destructive phase to bypass scope checks in this implementation
            d_summary = await run_destructive_phase(scope, outdir, logger=logger, force=True)
            logger.info("Destructive summary: %s", d_summary)
        except Exception:
            logger.exception("run_destructive_phase raised an exception")
    else:
        logger.info("Destructive phase skipped; not running destructive adapters/exploits.")

    logger.info("Run orchestration complete")
    return {"non_destructive": nd_summary}

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--targets", nargs="+", required=False,
                   default=["https://testphp.vulnweb.com"])
    p.add_argument("--run-id", default="run01")
    p.add_argument("--poc-multi", action="store_true")
    p.add_argument("--poc-threshold", type=float, default=0.5)
    p.add_argument("--no-html", action="store_true")
    p.add_argument("--no-pdf", action="store_true")
    p.add_argument("--force-destructive", action="store_true",
                   help="Skip interactive confirmation and force destructive phase.")
    p.add_argument("--skip-destructive", action="store_true",
                   help="Skip destructive phase entirely.")
    p.add_argument("--clear-logs", action="store_true",
                   help="Remove previous runs for this domain before starting (clears old logs/artifacts).")
    p.add_argument("--config-dir", default=None,
                   help="Path to directory containing custom tool configuration files.")
    p.add_argument("--scan-profile", choices=["quick", "normal", "thorough", "stealth"],
                   default=None,
                   help="Scan profile to use for tool configurations.")
    p.add_argument("--distributed", action="store_true",
                   help="Enable distributed scanning across multiple nodes.")
    p.add_argument("--tenant-id", default=None,
                   help="Tenant ID for multi-tenant environments.")
    p.add_argument("--redis-host", default="localhost",
                   help="Redis host for distributed scanning.")
    p.add_argument("--redis-port", type=int, default=6379,
                   help="Redis port for distributed scanning.")
    p.add_argument("--enable-caching", action="store_true",
                   help="Enable intelligent caching of scan results.")
    p.add_argument("--monitor-resources", action="store_true",
                   help="Enable resource monitoring during scans.")
    args = p.parse_args()

    if ScopeManager is None:
        print("Error: modules.scope.ScopeManager missing. Ensure modules/scope.py is present.", file=sys.stderr)
        sys.exit(2)

    # Set environment variables for tool configuration
    if args.config_dir:
        os.environ["PENAI_CONFIG_DIR"] = args.config_dir
    if args.scan_profile:
        os.environ["PENAI_SCAN_PROFILE"] = args.scan_profile
    
    # Set Redis configuration for distributed scanning
    if args.redis_host:
        os.environ["REDIS_HOST"] = args.redis_host
    if args.redis_port:
        os.environ["REDIS_PORT"] = str(args.redis_port)

    scope = ScopeManager(args.targets, mode="non-destructive")
    
    # Validate tenant access if tenant ID is provided
    if args.tenant_id and validate_tenant_scan:
        if not validate_tenant_scan(args.tenant_id, args.targets):
            print(f"Error: Tenant {args.tenant_id} is not authorized to scan these targets", file=sys.stderr)
            sys.exit(3)
        
        # Use tenant-specific output directory
        from modules.tenant_manager import get_tenant_manager
        tenant_manager = get_tenant_manager()
        try:
            outdir = tenant_manager.get_tenant_scan_dir(args.tenant_id, args.run_id)
        except Exception as e:
            print(f"Error: Failed to create tenant scan directory: {e}", file=sys.stderr)
            sys.exit(4)
    else:
        outdir = f"runs/{scope.primary_domain}/{args.run_id}"

    # prepare workspace (scope method may create run_meta etc)
    scope.prepare_workspace(outdir)
    
    # Start resource monitoring if enabled
    if args.monitor_resources and start_resource_monitoring:
        start_resource_monitoring()

    try:
        asyncio.run(run(scope, outdir,
                        poc_best_only=not args.poc_multi,
                        poc_threshold=args.poc_threshold,
                        export_html=not args.no_html,
                        export_pdf=not args.no_pdf,
                        force_destructive=args.force_destructive,
                        clear_logs=args.clear_logs,
                        skip_destructive=args.skip_destructive))
        print(f"Run complete. Reports at {outdir}/reports")
        
        # Send success notification
        if send_scan_results_notification:
            try:
                send_scan_results_notification(outdir, ', '.join(args.targets or []), success=True)
            except Exception:
                pass  # Don't fail the whole process if notification fails
    except KeyboardInterrupt:
        print("Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Scan failed with error: {e}", file=sys.stderr)
        # Send failure notification
        if send_scan_results_notification:
            try:
                send_scan_results_notification(outdir, ', '.join(args.targets or []), success=False)
            except Exception:
                pass  # Don't fail the whole process if notification fails
        sys.exit(1)

if __name__ == "__main__":
    main()
