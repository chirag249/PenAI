# tests/conftest.py
import os
import sys
import tempfile
import shutil
import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

@pytest.fixture
def tmp_run_dir(tmp_path):
    d = tmp_path / "run"
    d.mkdir()
    (d / "reports").mkdir()
    (d / "generated").mkdir()
    (d / "generated" / "tools").mkdir(parents=True)
    # create an example final_report.json
    final = {
        "meta": {"title": "unit-test", "domain": "example.test", "generated": "now"},
        "findings": [
            {"type": "xss", "target": "http://example.test/a", "severity": 3, "evidence": "<script>alert(1)</script>"},
            {"type": "sqli", "target": "http://example.test/b", "severity": 4, "evidence": None}
        ]
    }
    with open(str(d / "reports" / "final_report.json"), "w", encoding="utf-8") as fh:
        import json
        json.dump(final, fh)
    yield str(d)
    # cleanup done by tmp_path
