#!/usr/bin/env python3
"""
Generate a consolidated, human-friendly curated report (Markdown) from the
scanner output with attached PoCs.

Usage:
  python3 modules/reporter/generate_curated.py <run_dir> [--html] [--pdf]

Exports:
  - final_report_curated.md
  - optionally final_report_curated.html (inlined assets)
  - optionally final_report_curated.pdf (via pandoc or weasyprint)
"""
from __future__ import annotations
import json
import os
import sys
import argparse
import subprocess
import base64
import mimetypes
from typing import Any, Dict, List, Optional, Tuple

# Optional imports (used as fallback)
try:
    from bs4 import BeautifulSoup
except Exception:
    BeautifulSoup = None  # type: ignore

try:
    import markdown as _pymarkdown  # pip package name 'markdown'
except Exception:
    _pymarkdown = None  # type: ignore

# ------------------ I/O helpers ------------------
def load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def safe_str(x):
    if x is None:
        return ""
    return str(x)


def write_text(path: str, content: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def write_json(path: str, obj: Any) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


def find_report_file(run_dir: str) -> Optional[str]:
    rpt = os.path.join(run_dir, "reports")
    candidates = [
        os.path.join(rpt, "final_report_with_pocs_map.json"),
        os.path.join(rpt, "final_report_with_pocs.json"),
        os.path.join(rpt, "final_report.json"),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None


def find_pocs_file(run_dir: str) -> Optional[str]:
    rpt = os.path.join(run_dir, "reports")
    candidates = [
        os.path.join(rpt, "pocs_compact_unique.json"),
        os.path.join(rpt, "pocs_compact.json"),
        os.path.join(rpt, "pocs.json"),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None


# ------------------ Snippet inlining helpers ------------------
def inline_snippet_assets(snippet_path: str) -> str:
    """
    Read snippet HTML file and inline local CSS/JS/images so the snippet becomes
    self-contained HTML string. Returns the HTML string (or a simple message).
    Requires BeautifulSoup to be installed; if missing, returns raw file content.
    """
    if not os.path.isfile(snippet_path):
        return f"<pre>Snippet missing: {snippet_path}</pre>"

    try:
        with open(snippet_path, "r", encoding="utf-8", errors="ignore") as fh:
            html = fh.read()
    except Exception as e:
        return f"<pre>Failed to read snippet: {e}</pre>"

    if BeautifulSoup is None:
        # No BS4 available — return raw HTML wrapped
        return f"<!-- BeautifulSoup not installed; returning raw snippet -->\n\n{html}"

    soup = BeautifulSoup(html, "html.parser")
    base_dir = os.path.dirname(snippet_path)

    # inline <link rel="stylesheet" href="...">
    for link in list(soup.find_all("link", rel="stylesheet", href=True)):
        href = link["href"]
        local_path = os.path.normpath(os.path.join(base_dir, href))
        if os.path.isfile(local_path):
            try:
                with open(local_path, "r", encoding="utf-8", errors="ignore") as fh:
                    css = fh.read()
                style_tag = soup.new_tag("style")
                style_tag.string = css
                link.replace_with(style_tag)
            except Exception:
                # leave link as-is
                pass

    # inline <script src="...">
    for script in list(soup.find_all("script", src=True)):
        src = script["src"]
        local_path = os.path.normpath(os.path.join(base_dir, src))
        if os.path.isfile(local_path):
            try:
                with open(local_path, "r", encoding="utf-8", errors="ignore") as fh:
                    js = fh.read()
                script_tag = soup.new_tag("script")
                script_tag.string = js
                script.replace_with(script_tag)
            except Exception:
                pass

    # inline <img src="...">
    for img in list(soup.find_all("img", src=True)):
        src = img["src"]
        local_path = os.path.normpath(os.path.join(base_dir, src))
        if os.path.isfile(local_path):
            try:
                mime, _ = mimetypes.guess_type(local_path)
                if not mime:
                    mime = "application/octet-stream"
                with open(local_path, "rb") as fh:
                    b64 = base64.b64encode(fh.read()).decode("ascii")
                img["src"] = f"data:{mime};base64,{b64}"
            except Exception:
                pass

    # Return pretty html
    return str(soup)


# ------------------ Consolidation logic ------------------
def consolidate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Consolidate findings by (type, used_url||target), merging pocs and keeping highest severity.
    Returns list of consolidated findings.
    """
    idx: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for f in findings:
        ftype = f.get("type", "<unknown>")
        furl = (f.get("used_url") or f.get("target") or "").strip()
        key = (ftype, furl)
        if key not in idx:
            idx[key] = {
                "type": ftype,
                "target": furl,
                "severity": f.get("severity", 0),
                "count": 1,
                "examples": [f],
                "pocs": list(f.get("pocs", []) or []),
                "extra": {k: v for k, v in f.items() if k not in ("pocs", "type", "used_url", "target", "severity")},
            }
        else:
            entry = idx[key]
            entry["severity"] = max(entry["severity"], f.get("severity", 0))
            entry["count"] += 1
            entry["examples"].append(f)
            existing_proofs = {p.get("proof_url") for p in entry["pocs"] if p.get("proof_url")}
            for p in (f.get("pocs") or []):
                if p.get("proof_url") not in existing_proofs:
                    entry["pocs"].append(p)
                    existing_proofs.add(p.get("proof_url"))
    out = sorted(idx.values(), key=lambda e: (-e["severity"], -e["count"], e["target"]))
    return out


# ------------------ Markdown builder ------------------
def snippet_link_for_proof(run_dir: str, proof_url: str) -> Optional[str]:
    """
    Return relative snippet path (pocs/snippets/filename) if a snippet file matches the proof_url.
    This is used for linking in the Markdown. The HTML post-process step will inline content.
    """
    snippets_dir = os.path.join(run_dir, "pocs", "snippets")
    if not os.path.isdir(snippets_dir):
        return None
    # coarse normalization
    key = proof_url.replace("://", "_").replace("/", "_").replace("?", "_").replace("&", "_").replace("=", "_")
    for name in os.listdir(snippets_dir):
        if key in name:
            return os.path.join("pocs", "snippets", name)
    # fallback: substring in filename
    proof_naked = proof_url.replace("http://", "").replace("https://", "")
    for name in os.listdir(snippets_dir):
        if proof_naked in name or proof_url in name:
            return os.path.join("pocs", "snippets", name)
    return None


def build_markdown(run_dir: str, consolidated: List[Dict[str, Any]], report_meta: Dict[str, Any]) -> str:
    md_lines: List[str] = []
    md_lines.append(f"# Curated Scan Report\n")
    md_lines.append(f"- Run: `{os.path.basename(os.path.abspath(run_dir))}`")
    md_lines.append(f"- Reports dir: `reports/`")
    md_lines.append("")
    md_lines.append("## Summary")
    md_lines.append("")
    total_findings = sum(1 for _ in consolidated)
    total_pocs = report_meta.get("pocs", {}).get("count") if isinstance(report_meta.get("pocs"), dict) else None
    md_lines.append(f"- Consolidated findings: **{total_findings}**")
    if total_pocs is not None:
        md_lines.append(f"- PoCs discovered (compact): **{total_pocs}**")
    md_lines.append("")
    md_lines.append("---\n")

    for f in consolidated:
        sev = f["severity"]
        md_lines.append(f"### {f['type']} — `{f['target'] or '<no-target>'}`")
        md_lines.append(f"- **Severity:** {sev}")
        md_lines.append(f"- **Occurrences merged:** {f['count']}")
        if f["pocs"]:
            md_lines.append(f"- **PoCs ({len(f['pocs'])}):**")
            for p in f["pocs"]:
                proof_url = p.get("proof_url") or p.get("target") or "<no-proof-url>"
                status = p.get("status")
                snippet = snippet_link_for_proof(run_dir, proof_url)
                if snippet:
                    # link to relative snippet path; HTML post-process will inline
                    md_lines.append(f"  - [{proof_url}]({snippet}) — status: `{status}`")
                else:
                    md_lines.append(f"  - `{proof_url}` — status: `{status}`")
        else:
            md_lines.append("- **PoCs:** _none attached_")
        md_lines.append("- **Examples / notes:**")
        first_example = f["examples"][0] if f["examples"] else {}
        excerpt_fields = []
        for k in ("parameter", "evidence", "used_payload", "vector", "proof"):
            if first_example.get(k):
                excerpt_fields.append(f"{k}: {first_example.get(k)}")
        if not excerpt_fields:
            for k in ("response", "request", "raw", "description"):
                v = safe_str(first_example.get(k))
                if v:
                    excerpt_fields.append(f"{k}: {v}")
        if excerpt_fields:
            md_lines.append("  - " + " | ".join(excerpt_fields))
        else:
            md_lines.append("  - (no compact excerpt available)")

        # -- AI suggestion block: added here (after Examples / notes, before remediation)
        # It reads the 'ai' field on the first example (or on the consolidated entry) and prints it.
        ai = None
        if first_example:
            ai = first_example.get("ai")
        if not ai:
            # sometimes the 'ai' annotation may be on the consolidated examples[0] or entry-level
            try:
                ai = f.get("examples", [])[0].get("ai")
            except Exception:
                ai = None
        if ai:
            try:
                vuln_type = ai.get("vuln_type", "unknown")
                confidence = float(ai.get("confidence", 0.0))
                explanation = ai.get("explanation", "") or ""
                md_lines.append("- **AI suggestion:**")
                md_lines.append(f"  - predicted type: `{vuln_type}` (confidence: {confidence:.2f})")
                if explanation:
                    md_lines.append(f"  - explanation: {explanation}")
            except Exception:
                # fallback safe rendering
                md_lines.append("- **AI suggestion:** (unavailable due to formatting)")

        md_lines.append("- **Recommended remediation (high level):**")
        if "xss" in f["type"].lower():
            md_lines.append("  - Sanitize and encode untrusted input before rendering. Use context-specific encoding (HTML, JS, attribute). Implement CSP.")
        elif "sqli" in f["type"].lower():
            md_lines.append("  - Use parameterized queries / prepared statements. Validate and escape inputs. Review DB permissions.")
        else:
            md_lines.append("  - Review input validation, encoding, and access controls for this endpoint.")
        md_lines.append("\n---\n")

    unmapped = report_meta.get("pocs", {}).get("unmapped") if isinstance(report_meta.get("pocs"), dict) else None
    diag_file = os.path.join(run_dir, "reports", "pocs_mapping_debug.json")
    if unmapped:
        md_lines.append("## Unmapped PoCs / Suggestions")
        md_lines.append("")
        for u in unmapped:
            proof = u.get("proof_url") or "<no-proof>"
            md_lines.append(f"- `{proof}` — status: `{u.get('status')}`")
            sm = u.get("suggested_match")
            if sm:
                md_lines.append(f"  - suggested: `{sm.get('suggested_finding_target')}` (score {sm.get('score')})")
                topN = sm.get("topN", [])
                if topN:
                    md_lines.append("  - top candidates:")
                    for c in topN:
                        md_lines.append(f"    - {c.get('finding_target')} ({c.get('finding_type')}): score {c.get('score')}")
        md_lines.append("")
    elif os.path.isfile(diag_file):
        try:
            dbg = load_json(diag_file)
            matches = dbg.get("matches", [])
            unm = dbg.get("unmapped", [])
            md_lines.append("## Mapping diagnostics (auto-generated)")
            md_lines.append("")
            md_lines.append(f"- mapping candidates processed: {len(matches)}")
            md_lines.append(f"- unmapped PoCs: {len(unm)}")
            md_lines.append("")
        except Exception:
            pass

    md_lines.append("\n---\n")
    md_lines.append("Generated by pentest pipeline — curated output.\n")
    return "\n".join(md_lines)


# ------------------ Export helpers ------------------
def convert_md_to_html(md_path: str, out_html_path: str) -> None:
    """
    Convert Markdown to HTML. Try pandoc; otherwise use python-markdown.
    After conversion, post-process to inline snippet assets for any links that
    point to pocs/snippets/* (requires BeautifulSoup).
    """
    # try pandoc first
    try:
        subprocess.run(["pandoc", md_path, "-o", out_html_path], check=True)
        print(f"wrote {out_html_path} (pandoc)")
    except Exception as e:
        # fallback to python-markdown if available
        if _pymarkdown is None:
            print(f"pandoc not available and python-markdown not installed ({e}). HTML export skipped.")
            return
        with open(md_path, "r", encoding="utf-8") as fh:
            md = fh.read()
        try:
            html_body = _pymarkdown.markdown(md, extensions=["extra", "tables", "fenced_code"])
            # wrap in minimal HTML shell
            html = "<!doctype html>\n<html>\n<head>\n<meta charset='utf-8'/>\n"
            html += "<meta name='viewport' content='width=device-width,initial-scale=1'/>\n"
            html += "<title>Curated Report</title>\n</head>\n<body>\n"
            html += html_body
            html += "\n</body>\n</html>"
            with open(out_html_path, "w", encoding="utf-8") as fh:
                fh.write(html)
            print(f"wrote {out_html_path} (python-markdown)")
        except Exception as e2:
            print(f"markdown conversion failed: {e2}")
            return

    # post-process HTML to inline snippet assets if possible
    try:
        if BeautifulSoup is None:
            # nothing to do
            return
        with open(out_html_path, "r", encoding="utf-8", errors="ignore") as fh:
            soup = BeautifulSoup(fh.read(), "html.parser")

        # find <a href="pocs/snippets/..."> and replace with a details block containing inlined snippet
        anchors = soup.find_all("a", href=True)
        changed = False
        for a in list(anchors):
            href = a["href"]
            if href.startswith("pocs/snippets/") or "/pocs/snippets/" in href:
                # build absolute path to snippet file (assume relative to markdown parent dir)
                md_dir = os.path.dirname(md_path)
                snippet_abs = os.path.normpath(os.path.join(md_dir, href))
                if not os.path.isfile(snippet_abs):
                    # try relative to run_dir
                    snippet_abs = os.path.normpath(href)
                if os.path.isfile(snippet_abs):
                    inlined = inline_snippet_assets(snippet_abs)
                    # create <details> block
                    details = soup.new_tag("details")
                    summary = soup.new_tag("summary")
                    summary.string = f"Embedded PoC: {os.path.basename(snippet_abs)}"
                    details.append(summary)
                    # insert the inlined snippet (as HTML)
                    try:
                        fragment = BeautifulSoup(inlined, "html.parser")
                        details.append(fragment)
                    except Exception:
                        # fallback: raw pre
                        pre = soup.new_tag("pre")
                        pre.string = inlined
                        details.append(pre)
                    a.replace_with(details)
                    changed = True

        if changed:
            with open(out_html_path, "w", encoding="utf-8") as fh:
                fh.write(str(soup))
            print(f"inlined snippet assets into {out_html_path}")
    except Exception as e:
        print(f"post-process HTML inlining failed: {e}")


def convert_md_to_pdf(md_path: str, out_pdf_path: str) -> None:
    """
    Convert Markdown -> PDF. Try pandoc first; if that fails, try weasyprint
    by converting to HTML (using our convert_md_to_html) then HTML->PDF.
    """
    # try pandoc
    try:
        subprocess.run(["pandoc", md_path, "-o", out_pdf_path], check=True)
        print(f"wrote {out_pdf_path} (pandoc)")
        return
    except Exception as e:
        print(f"pandoc not available or failed for PDF: {e}")

    # fallback: weasyprint (requires weasyprint installed)
    try:
        from weasyprint import HTML  # type: ignore
    except Exception as e:
        print(f"weasyprint not available: {e}. PDF export skipped.")
        return

    # ensure HTML exists
    html_path = md_path.replace(".md", ".html")
    convert_md_to_html(md_path, html_path)
    if not os.path.isfile(html_path):
        print("HTML conversion failed; cannot produce PDF.")
        return
    try:
        HTML(html_path).write_pdf(out_pdf_path)
        print(f"wrote {out_pdf_path} (weasyprint)")
    except Exception as e:
        print(f"weasyprint PDF conversion failed: {e}")


# ------------------ CLI / Main ------------------
def main():
    ap = argparse.ArgumentParser(prog="generate_curated.py")
    ap.add_argument("run_dir", help="run directory (e.g. runs/example.com/run01)")
    ap.add_argument("--html", action="store_true", help="export HTML (inlines PoC snippets)")
    ap.add_argument("--pdf", action="store_true", help="export PDF (tries pandoc then weasyprint)")
    args = ap.parse_args()

    run_dir = args.run_dir.rstrip("/")
    report_file = find_report_file(run_dir)
    if not report_file:
        print("no report found in", run_dir)
        sys.exit(1)

    final = load_json(report_file)
    findings = final.get("findings", []) or []
    consolidated = consolidate_findings(findings)
    meta = final.get("meta", {}) or {}

    out_md = build_markdown(run_dir, consolidated, meta)
    out_path = os.path.join(run_dir, "reports", "final_report_curated.md")
    write_text(out_path, out_md)
    print("wrote", out_path)

    # optionally export HTML and PDF
    if args.html:
        out_html = out_path.replace(".md", ".html")
        convert_md_to_html(out_path, out_html)
    if args.pdf:
        out_pdf = out_path.replace(".md", ".pdf")
        convert_md_to_pdf(out_path, out_pdf)


if __name__ == "__main__":
    main()
