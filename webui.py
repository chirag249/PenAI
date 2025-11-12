#!/usr/bin/env python3
import os
import subprocess
import threading
import urllib.parse
import json
import uuid
from datetime import datetime
from flask import Flask, request, send_from_directory, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Enable CORS for API endpoints

RUNS_DIR = "runs"
# Data storage for profiles, policies, templates, and rules
SCANNING_PROFILES = {}
SCANNING_POLICIES = {}
REPORT_TEMPLATES = {}
CUSTOM_RULES = {}
USERS = {}
WORKSPACES = {}

# Load data from files if they exist
def load_persistent_data():
    global SCANNING_PROFILES, SCANNING_POLICIES, REPORT_TEMPLATES, CUSTOM_RULES, USERS, WORKSPACES
    
    # Load scanning profiles
    profiles_path = os.path.join(RUNS_DIR, "scanning_profiles.json")
    if os.path.exists(profiles_path):
        try:
            with open(profiles_path, "r") as f:
                SCANNING_PROFILES = json.load(f)
        except:
            SCANNING_PROFILES = {}
    
    # Load scanning policies
    policies_path = os.path.join(RUNS_DIR, "scanning_policies.json")
    if os.path.exists(policies_path):
        try:
            with open(policies_path, "r") as f:
                SCANNING_POLICIES = json.load(f)
        except:
            SCANNING_POLICIES = {}
    
    # Load report templates
    templates_path = os.path.join(RUNS_DIR, "report_templates.json")
    if os.path.exists(templates_path):
        try:
            with open(templates_path, "r") as f:
                REPORT_TEMPLATES = json.load(f)
        except:
            REPORT_TEMPLATES = {}
    
    # Load custom rules
    rules_path = os.path.join(RUNS_DIR, "custom_rules.json")
    if os.path.exists(rules_path):
        try:
            with open(rules_path, "r") as f:
                CUSTOM_RULES = json.load(f)
        except:
            CUSTOM_RULES = {}
    
    # Load users
    users_path = os.path.join(RUNS_DIR, "users.json")
    if os.path.exists(users_path):
        try:
            with open(users_path, "r") as f:
                USERS = json.load(f)
        except:
            USERS = {}
    
    # Load workspaces
    workspaces_path = os.path.join(RUNS_DIR, "workspaces.json")
    if os.path.exists(workspaces_path):
        try:
            with open(workspaces_path, "r") as f:
                WORKSPACES = json.load(f)
        except:
            WORKSPACES = {}

# Save data to files
def save_persistent_data():
    # Save scanning profiles
    profiles_path = os.path.join(RUNS_DIR, "scanning_profiles.json")
    os.makedirs(os.path.dirname(profiles_path), exist_ok=True)
    with open(profiles_path, "w") as f:
        json.dump(SCANNING_PROFILES, f, indent=2)
    
    # Save scanning policies
    policies_path = os.path.join(RUNS_DIR, "scanning_policies.json")
    with open(policies_path, "w") as f:
        json.dump(SCANNING_POLICIES, f, indent=2)
    
    # Save report templates
    templates_path = os.path.join(RUNS_DIR, "report_templates.json")
    with open(templates_path, "w") as f:
        json.dump(REPORT_TEMPLATES, f, indent=2)
    
    # Save custom rules
    rules_path = os.path.join(RUNS_DIR, "custom_rules.json")
    with open(rules_path, "w") as f:
        json.dump(CUSTOM_RULES, f, indent=2)
    
    # Save users
    users_path = os.path.join(RUNS_DIR, "users.json")
    with open(users_path, "w") as f:
        json.dump(USERS, f, indent=2)
    
    # Save workspaces
    workspaces_path = os.path.join(RUNS_DIR, "workspaces.json")
    with open(workspaces_path, "w") as f:
        json.dump(WORKSPACES, f, indent=2)

# Load data on startup
load_persistent_data()

# ---------- API Routes ----------
@app.route("/api/start", methods=["POST"])
def start_scan():
    target = request.form.get("target")
    mode = request.form.get("mode", "non-destructive")
    run_id = request.form.get("run_id") or f"ui-run-{uuid.uuid4().hex[:8]}"
    profile_id = request.form.get("profile_id")
    
    # Apply profile settings if provided
    profile_settings = {}
    if profile_id and profile_id in SCANNING_PROFILES:
        profile_settings = SCANNING_PROFILES[profile_id].get("settings", {})
    
    parsed = urllib.parse.urlparse(target)
    if not parsed.scheme and target:
        target = "https://" + target
    
    # Create scan metadata
    scan_metadata = {
        "target": target,
        "mode": mode,
        "run_id": run_id,
        "profile_id": profile_id,
        "start_time": datetime.now().isoformat(),
        "status": "running"
    }
    
    # Save scan metadata
    metadata_path = os.path.join(RUNS_DIR, urllib.parse.quote(target, safe=''), run_id, "scan_metadata.json")
    os.makedirs(os.path.dirname(metadata_path), exist_ok=True)
    with open(metadata_path, "w") as f:
        json.dump(scan_metadata, f, indent=2)
    
    threading.Thread(target=run_scan, args=(target or "", run_id, mode, profile_settings), daemon=True).start()
    return jsonify({"run_id": run_id}), 200

@app.route("/api/latest")
def latest():
    latest, ready = find_latest_run()
    return jsonify({"latest": latest, "ready": ready})

@app.route("/api/summary/<path:run_path>")
def summary_report(run_path):
    safe_run_path = os.path.normpath(run_path)
    if safe_run_path.startswith(".."):
        return "Invalid run", 400
    
    # Try multiple possible locations for summary report
    possible_paths = [
        os.path.join(RUNS_DIR, safe_run_path, "reports", "summary_report.json"),
        os.path.join(RUNS_DIR, safe_run_path, "summary_report.json"),
        os.path.join(RUNS_DIR, safe_run_path, "final_report.json")
    ]
    
    summary_path = None
    for path in possible_paths:
        if os.path.exists(path):
            summary_path = path
            break
    
    if not summary_path:
        return "Summary report not found", 404
    
    try:
        with open(summary_path, "r") as f:
            summary_data = json.load(f)
        return jsonify(summary_data)
    except Exception as e:
        return f"Error reading summary report: {e}", 500

@app.route("/api/report/<path:run_path>/<format>")
def get_report(run_path, format):
    """Get report in specified format"""
    safe_run_path = os.path.normpath(run_path)
    if safe_run_path.startswith(".."):
        return "Invalid run", 400
    
    # Map format to file extension
    format_map = {
        "json": "final_report.json",
        "html": "final_report_curated.html",
        "pdf": "final_report_curated.pdf",
        "md": "final_report_curated.md",
        "txt": "final_report.txt"
    }
    
    if format not in format_map:
        return "Unsupported format", 400
    
    filename = format_map[format]
    
    # Try multiple possible locations
    possible_paths = [
        os.path.join(RUNS_DIR, safe_run_path, "reports", filename),
        os.path.join(RUNS_DIR, safe_run_path, filename)
    ]
    
    report_path = None
    for path in possible_paths:
        if os.path.exists(path):
            report_path = path
            break
    
    if not report_path:
        return "Report not found", 404
    
    return send_from_directory(os.path.dirname(report_path), os.path.basename(report_path))

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

# ---------- Enhanced UI/UX Features ----------

# Dashboard metrics API
@app.route("/api/dashboard/metrics")
def dashboard_metrics():
    """Return real-time scanning metrics and vulnerability analytics"""
    metrics = {
        "total_scans": 0,
        "active_scans": 0,
        "completed_scans": 0,
        "vulnerabilities_found": 0,
        "critical_vulns": 0,
        "high_vulns": 0,
        "medium_vulns": 0,
        "recent_scans": []
    }
    
    # Walk through runs directory to collect metrics
    if os.path.isdir(RUNS_DIR):
        for root, dirs, files in os.walk(RUNS_DIR):
            if "final_report.json" in files or "summary_report.json" in files:
                metrics["total_scans"] += 1
                
                # Check if scan is completed
                if "final_report_curated.html" in files or "final_report.json" in files:
                    metrics["completed_scans"] += 1
                
                # Try to read report data for vulnerability counts
                report_files = ["final_report.json", "summary_report.json"]
                for report_file in report_files:
                    report_path = os.path.join(root, report_file)
                    if os.path.exists(report_path):
                        try:
                            with open(report_path, "r") as f:
                                data = json.load(f)
                                # Extract vulnerability counts from report
                                if "scan_summary" in data:
                                    summary = data["scan_summary"]
                                    metrics["vulnerabilities_found"] += summary.get("vulnerabilities_found", 0)
                                    metrics["critical_vulns"] += summary.get("critical_findings", 0)
                                    metrics["high_vulns"] += summary.get("high_severity", 0)
                                    metrics["medium_vulns"] += summary.get("medium_severity", 0)
                                elif "vulnerabilities" in data:
                                    vulns = data["vulnerabilities"]
                                    metrics["vulnerabilities_found"] += len(vulns)
                                    for vuln in vulns:
                                        severity = vuln.get("severity", 1)
                                        if severity == 5:
                                            metrics["critical_vulns"] += 1
                                        elif severity == 4:
                                            metrics["high_vulns"] += 1
                                        elif severity == 3:
                                            metrics["medium_vulns"] += 1
                                break
                        except:
                            pass
                
                # Add to recent scans (last 5)
                if len(metrics["recent_scans"]) < 5:
                    rel_path = os.path.relpath(root, RUNS_DIR)
                    metrics["recent_scans"].append({
                        "path": rel_path,
                        "timestamp": os.path.getmtime(root)
                    })
    
    # Sort recent scans by timestamp
    metrics["recent_scans"].sort(key=lambda x: x["timestamp"], reverse=True)
    
    return jsonify(metrics)

# Scanning profiles API
@app.route("/api/profiles", methods=["GET"])
def get_profiles():
    """Get all scanning profiles"""
    return jsonify(SCANNING_PROFILES)

@app.route("/api/profiles", methods=["POST"])
def create_profile():
    """Create a new scanning profile"""
    data = request.get_json()
    profile_id = f"profile-{uuid.uuid4().hex[:8]}"
    
    SCANNING_PROFILES[profile_id] = {
        "id": profile_id,
        "name": data.get("name", "Untitled Profile"),
        "description": data.get("description", ""),
        "settings": data.get("settings", {}),
        "created_at": datetime.now().isoformat()
    }
    
    save_persistent_data()
    return jsonify(SCANNING_PROFILES[profile_id]), 201

@app.route("/api/profiles/<profile_id>", methods=["PUT"])
def update_profile(profile_id):
    """Update an existing scanning profile"""
    if profile_id not in SCANNING_PROFILES:
        return "Profile not found", 404
    
    data = request.get_json()
    SCANNING_PROFILES[profile_id].update({
        "name": data.get("name", SCANNING_PROFILES[profile_id]["name"]),
        "description": data.get("description", SCANNING_PROFILES[profile_id]["description"]),
        "settings": data.get("settings", SCANNING_PROFILES[profile_id]["settings"])
    })
    
    save_persistent_data()
    return jsonify(SCANNING_PROFILES[profile_id])

@app.route("/api/profiles/<profile_id>", methods=["DELETE"])
def delete_profile(profile_id):
    """Delete a scanning profile"""
    if profile_id not in SCANNING_PROFILES:
        return "Profile not found", 404
    
    del SCANNING_PROFILES[profile_id]
    save_persistent_data()
    return "", 204

# Scanning policies API
@app.route("/api/policies", methods=["GET"])
def get_policies():
    """Get all scanning policies"""
    return jsonify(SCANNING_POLICIES)

@app.route("/api/policies", methods=["POST"])
def create_policy():
    """Create a new scanning policy"""
    data = request.get_json()
    policy_id = f"policy-{uuid.uuid4().hex[:8]}"
    
    SCANNING_POLICIES[policy_id] = {
        "id": policy_id,
        "name": data.get("name", "Untitled Policy"),
        "description": data.get("description", ""),
        "rules": data.get("rules", []),
        "compliance": data.get("compliance", []),
        "created_at": datetime.now().isoformat()
    }
    
    save_persistent_data()
    return jsonify(SCANNING_POLICIES[policy_id]), 201

@app.route("/api/policies/<policy_id>", methods=["PUT"])
def update_policy(policy_id):
    """Update an existing scanning policy"""
    if policy_id not in SCANNING_POLICIES:
        return "Policy not found", 404
    
    data = request.get_json()
    SCANNING_POLICIES[policy_id].update({
        "name": data.get("name", SCANNING_POLICIES[policy_id]["name"]),
        "description": data.get("description", SCANNING_POLICIES[policy_id]["description"]),
        "rules": data.get("rules", SCANNING_POLICIES[policy_id]["rules"]),
        "compliance": data.get("compliance", SCANNING_POLICIES[policy_id]["compliance"])
    })
    
    save_persistent_data()
    return jsonify(SCANNING_POLICIES[policy_id])

@app.route("/api/policies/<policy_id>", methods=["DELETE"])
def delete_policy(policy_id):
    """Delete a scanning policy"""
    if policy_id not in SCANNING_POLICIES:
        return "Policy not found", 404
    
    del SCANNING_POLICIES[policy_id]
    save_persistent_data()
    return "", 204

# Report templates API
@app.route("/api/templates", methods=["GET"])
def get_templates():
    """Get all report templates"""
    return jsonify(REPORT_TEMPLATES)

@app.route("/api/templates", methods=["POST"])
def create_template():
    """Create a new report template"""
    data = request.get_json()
    template_id = f"template-{uuid.uuid4().hex[:8]}"
    
    REPORT_TEMPLATES[template_id] = {
        "id": template_id,
        "name": data.get("name", "Untitled Template"),
        "description": data.get("description", ""),
        "sections": data.get("sections", []),
        "format": data.get("format", "html"),
        "created_at": datetime.now().isoformat()
    }
    
    save_persistent_data()
    return jsonify(REPORT_TEMPLATES[template_id]), 201

@app.route("/api/templates/<template_id>", methods=["PUT"])
def update_template(template_id):
    """Update an existing report template"""
    if template_id not in REPORT_TEMPLATES:
        return "Template not found", 404
    
    data = request.get_json()
    REPORT_TEMPLATES[template_id].update({
        "name": data.get("name", REPORT_TEMPLATES[template_id]["name"]),
        "description": data.get("description", REPORT_TEMPLATES[template_id]["description"]),
        "sections": data.get("sections", REPORT_TEMPLATES[template_id]["sections"]),
        "format": data.get("format", REPORT_TEMPLATES[template_id]["format"])
    })
    
    save_persistent_data()
    return jsonify(REPORT_TEMPLATES[template_id])

@app.route("/api/templates/<template_id>", methods=["DELETE"])
def delete_template(template_id):
    """Delete a report template"""
    if template_id not in REPORT_TEMPLATES:
        return "Template not found", 404
    
    del REPORT_TEMPLATES[template_id]
    save_persistent_data()
    return "", 204

# Custom rules API
@app.route("/api/rules", methods=["GET"])
def get_rules():
    """Get all custom rules"""
    return jsonify(CUSTOM_RULES)

@app.route("/api/rules", methods=["POST"])
def create_rule():
    """Create a new custom rule"""
    data = request.get_json()
    rule_id = f"rule-{uuid.uuid4().hex[:8]}"
    
    CUSTOM_RULES[rule_id] = {
        "id": rule_id,
        "name": data.get("name", "Untitled Rule"),
        "description": data.get("description", ""),
        "category": data.get("category", "general"),
        "pattern": data.get("pattern", ""),
        "severity": data.get("severity", 3),
        "enabled": data.get("enabled", True),
        "created_at": datetime.now().isoformat()
    }
    
    save_persistent_data()
    return jsonify(CUSTOM_RULES[rule_id]), 201

@app.route("/api/rules/<rule_id>", methods=["PUT"])
def update_rule(rule_id):
    """Update an existing custom rule"""
    if rule_id not in CUSTOM_RULES:
        return "Rule not found", 404
    
    data = request.get_json()
    CUSTOM_RULES[rule_id].update({
        "name": data.get("name", CUSTOM_RULES[rule_id]["name"]),
        "description": data.get("description", CUSTOM_RULES[rule_id]["description"]),
        "category": data.get("category", CUSTOM_RULES[rule_id]["category"]),
        "pattern": data.get("pattern", CUSTOM_RULES[rule_id]["pattern"]),
        "severity": data.get("severity", CUSTOM_RULES[rule_id]["severity"]),
        "enabled": data.get("enabled", CUSTOM_RULES[rule_id]["enabled"])
    })
    
    save_persistent_data()
    return jsonify(CUSTOM_RULES[rule_id])

@app.route("/api/rules/<rule_id>", methods=["DELETE"])
def delete_rule(rule_id):
    """Delete a custom rule"""
    if rule_id not in CUSTOM_RULES:
        return "Rule not found", 404
    
    del CUSTOM_RULES[rule_id]
    save_persistent_data()
    return "", 204

# User management API
@app.route("/api/users", methods=["GET"])
def get_users():
    """Get all users"""
    # Don't return sensitive information like passwords
    users_safe = {}
    for user_id, user_data in USERS.items():
        users_safe[user_id] = {
            "id": user_data["id"],
            "username": user_data["username"],
            "role": user_data["role"],
            "email": user_data.get("email", ""),
            "created_at": user_data["created_at"]
        }
    return jsonify(users_safe)

@app.route("/api/users", methods=["POST"])
def create_user():
    """Create a new user"""
    data = request.get_json()
    user_id = f"user-{uuid.uuid4().hex[:8]}"
    
    USERS[user_id] = {
        "id": user_id,
        "username": data.get("username", ""),
        "password": data.get("password", ""),  # In production, this should be hashed
        "role": data.get("role", "standard"),  # admin, standard, viewer
        "email": data.get("email", ""),
        "created_at": datetime.now().isoformat()
    }
    
    save_persistent_data()
    return jsonify({"id": user_id, "username": USERS[user_id]["username"], "role": USERS[user_id]["role"]}), 201

@app.route("/api/users/<user_id>", methods=["PUT"])
def update_user(user_id):
    """Update an existing user"""
    if user_id not in USERS:
        return "User not found", 404
    
    data = request.get_json()
    USERS[user_id].update({
        "username": data.get("username", USERS[user_id]["username"]),
        "role": data.get("role", USERS[user_id]["role"]),
        "email": data.get("email", USERS[user_id].get("email", ""))
    })
    
    # Update password only if provided
    if "password" in data and data["password"]:
        USERS[user_id]["password"] = data["password"]  # In production, this should be hashed
    
    save_persistent_data()
    return jsonify({"id": user_id, "username": USERS[user_id]["username"], "role": USERS[user_id]["role"]})

@app.route("/api/users/<user_id>", methods=["DELETE"])
def delete_user(user_id):
    """Delete a user"""
    if user_id not in USERS:
        return "User not found", 404
    
    del USERS[user_id]
    save_persistent_data()
    return "", 204

# Workspace management API
@app.route("/api/workspaces", methods=["GET"])
def get_workspaces():
    """Get all workspaces"""
    return jsonify(WORKSPACES)

@app.route("/api/workspaces", methods=["POST"])
def create_workspace():
    """Create a new workspace"""
    data = request.get_json()
    workspace_id = f"workspace-{uuid.uuid4().hex[:8]}"
    
    WORKSPACES[workspace_id] = {
        "id": workspace_id,
        "name": data.get("name", "Untitled Workspace"),
        "description": data.get("description", ""),
        "members": data.get("members", []),
        "created_at": datetime.now().isoformat()
    }
    
    save_persistent_data()
    return jsonify(WORKSPACES[workspace_id]), 201

@app.route("/api/workspaces/<workspace_id>", methods=["PUT"])
def update_workspace(workspace_id):
    """Update an existing workspace"""
    if workspace_id not in WORKSPACES:
        return "Workspace not found", 404
    
    data = request.get_json()
    WORKSPACES[workspace_id].update({
        "name": data.get("name", WORKSPACES[workspace_id]["name"]),
        "description": data.get("description", WORKSPACES[workspace_id]["description"]),
        "members": data.get("members", WORKSPACES[workspace_id]["members"])
    })
    
    save_persistent_data()
    return jsonify(WORKSPACES[workspace_id])

@app.route("/api/workspaces/<workspace_id>", methods=["DELETE"])
def delete_workspace(workspace_id):
    """Delete a workspace"""
    if workspace_id not in WORKSPACES:
        return "Workspace not found", 404
    
    del WORKSPACES[workspace_id]
    save_persistent_data()
    return "", 204

# ---------- Background scan runner ----------
def run_scan(target, run_id, mode, profile_settings=None):
    env = os.environ.copy()
    env["PYTHONPATH"] = env.get("PYTHONPATH", "") + (":" + os.getcwd() if env.get("PYTHONPATH") else os.getcwd())
    
    # Build command based on mode
    cmd = [
        "python3", "agent.py",
        "--targets", target,
        "--run-id", run_id,
    ]
    
    # Add profile settings if provided
    if profile_settings:
        # Add concurrency setting
        if "concurrency" in profile_settings:
            cmd.extend(["--concurrency", str(profile_settings["concurrency"])])
        
        # Add timeout setting
        if "timeout" in profile_settings:
            cmd.extend(["--timeout", str(profile_settings["timeout"])])
        
        # Add scan profile setting
        if "scan_profile" in profile_settings:
            cmd.extend(["--scan-profile", profile_settings["scan_profile"]])
    
    # Add appropriate flags based on mode
    if mode == "destructive":
        cmd.append("--force-destructive")
    elif mode == "non-destructive":
        cmd.append("--skip-destructive")
    
    # Update scan metadata status
    metadata_path = os.path.join(RUNS_DIR, urllib.parse.quote(target, safe=''), run_id, "scan_metadata.json")
    if os.path.exists(metadata_path):
        try:
            with open(metadata_path, "r") as f:
                metadata = json.load(f)
            metadata["status"] = "running"
            with open(metadata_path, "w") as f:
                json.dump(metadata, f, indent=2)
        except:
            pass
    
    result = subprocess.run(cmd, env=env)
    
    # Update scan metadata status
    if os.path.exists(metadata_path):
        try:
            with open(metadata_path, "r") as f:
                metadata = json.load(f)
            metadata["status"] = "completed" if result.returncode == 0 else "failed"
            metadata["end_time"] = datetime.now().isoformat()
            with open(metadata_path, "w") as f:
                json.dump(metadata, f, indent=2)
        except:
            pass

# ---------- Helper to find latest run and 'ready' state ----------
def find_latest_run():
    runs_path = os.path.join(RUNS_DIR)
    if not os.path.isdir(runs_path):
        return None, False
    candidates = []
    for root, dirs, files in os.walk(runs_path):
        if "final_report_curated.md" in files or "final_report.json" in files:
            rel = os.path.relpath(root, runs_path)  # domain/runid
            candidates.append(rel)
    if not candidates:
        return None, False
    latest = sorted(candidates)[-1]
    reports_dir = os.path.join(RUNS_DIR, latest, "reports")

    # Require md at minimum
    md_ok = os.path.exists(os.path.join(reports_dir, "final_report_curated.md")) or os.path.exists(os.path.join(RUNS_DIR, latest, "final_report_curated.md"))
    html_ok = os.path.exists(os.path.join(reports_dir, "final_report_curated.html")) or os.path.exists(os.path.join(RUNS_DIR, latest, "final_report_curated.html"))
    pdf_ok = os.path.exists(os.path.join(reports_dir, "final_report_curated.pdf")) or os.path.exists(os.path.join(RUNS_DIR, latest, "final_report_curated.pdf"))

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
    app.run(host="0.0.0.0", port=5001, debug=True)