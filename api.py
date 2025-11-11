from fastapi import FastAPI
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
import os, json

app = FastAPI()

@app.get("/", response_class=HTMLResponse)
async def index():
    path = os.path.join("web","templates","index.html")
    if os.path.exists(path):
        return open(path).read()
    return "<h1>PenAI Dashboard</h1>"

@app.get("/runs")
async def list_runs():
    runs_dir = "runs"
    data = {}
    if os.path.exists(runs_dir):
        for domain in os.listdir(runs_dir):
            dompath = os.path.join(runs_dir, domain)
            if not os.path.isdir(dompath): continue
            data[domain] = {}
            for run_id in os.listdir(dompath):
                runpath = os.path.join(dompath, run_id, "reports", "final_report.json")
                if os.path.exists(runpath):
                    try:
                        with open(runpath) as f:
                            report = json.load(f)
                        data[domain][run_id] = {
                            "findings": len(report.get("findings", []))
                        }
                    except Exception:
                        data[domain][run_id] = {"error": "could not parse"}
    return JSONResponse(data)

@app.get("/runs/{domain}/{run_id}/report")
async def get_report(domain: str, run_id: str):
    p = f"runs/{domain}/{run_id}/reports/final_report.json"
    if os.path.exists(p):
        return FileResponse(p, media_type="application/json", filename="final_report.json")
    return {"error":"report not found"}
