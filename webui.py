#!/usr/bin/env python3
import os
import subprocess
import threading
import urllib.parse
import json
from flask import Flask, request, send_from_directory, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Enable CORS for API endpoints

RUNS_DIR = "runs"

# ---------- API Routes ----------
@app.route("/api/start", methods=["POST"])
def start_scan():
    target = request.form.get("target")
    mode = request.form.get("mode", "non-destructive")
    run_id = request.form.get("run_id") or "ui-run"
    parsed = urllib.parse.urlparse(target)
    if not parsed.scheme and target:
        target = "https://" + target
    threading.Thread(target=run_scan, args=(target or "", run_id, mode), daemon=True).start()
    return ("", 204)  # no content (AJAX friendly)

@app.route("/api/latest")
def latest():
    latest, ready = find_latest_run()
    return jsonify({"latest": latest, "ready": ready})

@app.route("/api/summary/<path:run_path>")
def summary_report(run_path):
    safe_run_path = os.path.normpath(run_path)
    if safe_run_path.startswith(".."):
        return "Invalid run", 400
    
    summary_path = os.path.join(RUNS_DIR, safe_run_path, "reports", "summary_report.json")
    if not os.path.exists(summary_path):
        return "Summary report not found", 404
    
    try:
        with open(summary_path, "r") as f:
            summary_data = json.load(f)
        return jsonify(summary_data)
    except Exception as e:
        return f"Error reading summary report: {e}", 500

@app.route("/api/download/<path:run_path>/<path:filename>")
def download_file(run_path, filename):
    safe_run_path = os.path.normpath(run_path)
    if safe_run_path.startswith(".."):
        return "Invalid run", 400
    
    # Handle both cases: files in reports directory and files in run directory
    if filename.startswith("reports/"):
        # For summary reports and other files in the reports subdirectory
        reports_dir = os.path.join(RUNS_DIR, safe_run_path, "reports")
        file_path = os.path.join(reports_dir, filename[8:])  # Remove "reports/" prefix
    else:
        # For curated reports and other files directly in the run directory
        reports_dir = os.path.join(RUNS_DIR, safe_run_path, "reports")
        file_path = os.path.join(reports_dir, filename)
    
    # Check if file exists in reports directory
    if not os.path.exists(file_path):
        # Try in the run directory directly (for backwards compatibility)
        file_path = os.path.join(RUNS_DIR, safe_run_path, filename)
        if not os.path.exists(file_path):
            return "File not found", 404
    
    return send_from_directory(os.path.dirname(file_path), os.path.basename(file_path), as_attachment=True)

# ---------- Background scan runner ----------
def run_scan(target, run_id, mode):
    env = os.environ.copy()
    env["PYTHONPATH"] = env.get("PYTHONPATH", "") + (":" + os.getcwd() if env.get("PYTHONPATH") else os.getcwd())
    
    # Build command based on mode
    cmd = [
        "python3", "agent.py",
        "--targets", target,
        "--run-id", run_id,
    ]
    
    # Add appropriate flags based on mode
    if mode == "destructive":
        cmd.append("--force-destructive")
    elif mode == "non-destructive":
        cmd.append("--skip-destructive")
    
    subprocess.run(cmd, env=env)

# ---------- Helper to find latest run and 'ready' state ----------
def find_latest_run():
    runs_path = os.path.join(RUNS_DIR)
    if not os.path.isdir(runs_path):
        return None, False
    candidates = []
    for root, dirs, files in os.walk(runs_path):
        if "final_report_curated.md" in files:
            rel = os.path.relpath(root, runs_path)  # domain/runid
            candidates.append(rel)
    if not candidates:
        return None, False
    latest = sorted(candidates)[-1]
    reports_dir = os.path.join(RUNS_DIR, latest, "reports")

    # Require md at minimum
    md_ok = os.path.exists(os.path.join(reports_dir, "final_report_curated.md"))
    html_ok = os.path.exists(os.path.join(reports_dir, "final_report_curated.html"))
    pdf_ok = os.path.exists(os.path.join(reports_dir, "final_report_curated.pdf"))

    ready = md_ok  # mark as ready as soon as md exists
    return latest, ready

# Serve React frontend (must be after API routes)
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_frontend(path):
    frontend_dir = os.path.join(os.path.dirname(__file__), 'frontend', 'dist')
    if path != "" and os.path.exists(os.path.join(frontend_dir, path)):
        return send_from_directory(frontend_dir, path)
    else:
        return send_from_directory(frontend_dir, 'index.html')

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)