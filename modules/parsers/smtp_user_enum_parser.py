
#!/usr/bin/env python3
"""Parser for smtp-user-enum outputs (normalized)."""

def parse_smtp_user_enum_output(envelope, run_dir=None):
    out = []
    pf = envelope.get("parsed_findings") or (envelope.get("result") or {}).get("parsed_findings")
    if isinstance(pf, list) and pf:
        for p in pf:
            out.append({
                "type": p.get("type") or "smtp-user-enum-vuln",
                "target": p.get("target") or envelope.get("result", {}).get("target") or "<unknown>",
                "severity": int(p.get("severity") or 3),
                "evidence": p.get("evidence") or str(p)[:500],
                "source": {"tool": "smtp-user-enum", "raw": p}
            })
        return out

    res = envelope.get("result") or envelope
    stdout = (res.get("stdout") if isinstance(res, dict) else "") or ""
    if isinstance(stdout, str) and ("vulnerable" in stdout.lower() or "cve" in stdout.lower() or "username" in stdout.lower()):
        out.append({
            "type": "smtp-user-enum-inferred",
            "target": envelope.get("result", {}).get("target") or "<unknown>",
            "severity": 3,
            "evidence": stdout[:1000],
            "source": {"tool": "smtp-user-enum", "raw": stdout},
        })
    return out
