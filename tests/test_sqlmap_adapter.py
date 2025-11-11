
import json
import os
import subprocess
from types import SimpleNamespace

import pytest

from modules.tools import sqlmap_adapter


class DummyProc:
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def test_sqlmap_adapter_mock(tmp_path, monkeypatch):
    outdir = str(tmp_path / "run")
    # ensure no sqlmap on PATH by monkeypatching shutil.which
    monkeypatch.setattr("shutil.which", lambda name: None)
    res = sqlmap_adapter.run(outdir, target="https://example.local")
    assert res["meta"]["status"] == "mocked_no_binary"
    assert "parsed_findings" in res
    assert os.path.exists(res["output_file"])
    with open(res["output_file"], "r", encoding="utf-8") as fh:
        d = json.load(fh)
    assert d["meta"]["status"] == "mocked_no_binary"


def test_sqlmap_adapter_parsing_from_subprocess(tmp_path, monkeypatch):
    outdir = str(tmp_path / "run2")
    # Simulate sqlmap binary present by patching shutil.which
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/sqlmap")

    # Prepare fake stdout that looks like sqlmap output
    fake_stdout = "Parameter: q (POST) \nweb application is vulnerable\nPayload: ' OR '1'='1\n"
    def fake_run(cmd, stdout, stderr, timeout, text, **kwargs):
        return SimpleNamespace(stdout=fake_stdout, stderr="", returncode=0)

    monkeypatch.setattr("subprocess.run", fake_run)

    res = sqlmap_adapter.run(outdir, target="https://example.local")
    assert res["meta"]["status"] == "ran"
    assert isinstance(res.get("parsed_findings"), list)
    assert any("sqli" in f.get("type", "") for f in res["parsed_findings"])
    assert os.path.exists(res["output_file"])

