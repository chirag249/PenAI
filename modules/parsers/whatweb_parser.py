#!/usr/bin/env python3
"""Parser stub for whatweb.

Implement `parse_whatweb_output` or similar functions. The top-level parse_tool_envelope dispatcher
will try several function names. This stub provides a simple normalizer.

Returns list of normalized findings:
  { type, target, severity, evidence, source }
"""
def parse_whatweb_output(envelope, run_dir=None):
    out = []
    # prefer adapter-provided parsed_findings
    pf = envelope.get("parsed_findings") or (envelope.get("result") or {}).get("parsed_findings")
    if isinstance(pf, list) and pf:
        for p in pf:
            out.append({
                "type": p.get("type") or "whatweb-vuln",
                "target": p.get("target") or envelope.get("result",{}).get("target") or "<unknown>",
                "severity": int(p.get("severity") or 3),
                "evidence": p.get("evidence") or str(p)[:500],
                "source": {"tool": "whatweb", "raw": p}
            })
        return out

    # fallback: look at stdout text
    res = envelope.get("result") or envelope
    stdout = (res.get("stdout") if isinstance(res, dict) else None) or ""
    if isinstance(stdout, str) and ("vulnerable" in stdout.lower() or "cve" in stdout.lower()):
        out.append({
            "type": "whatweb-inferred",
            "target": envelope.get("result",{}).get("target") or "<unknown>",
            "severity": 3,
            "evidence": stdout[:1000],
            "source": {"tool": "whatweb", "raw": stdout},
        })
    return out
