import os, json, shutil
from modules.tools import sqlmap_adapter
from pathlib import Path

def test_sqlmap_adapter_mock(tmp_path):
    outdir = str(tmp_path)
    res = sqlmap_adapter.run(outdir=outdir, target="http://example.local")
    assert isinstance(res, dict)
    # ensure file written
    gen = Path(outdir) / "generated" / "sqlmap.json"
    assert gen.exists()
    # mock path should contain 'mock' when binary not installed
    assert "mock" in res.get("status") or res.get("status") in ("ran","timeout","adapter_error")
