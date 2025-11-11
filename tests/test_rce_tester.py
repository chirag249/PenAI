import os
import json
import asyncio
import tempfile
import pytest

from modules.destructive import rce_tester

class DummyScope:
    def __init__(self, allowed=False):
        self._allowed = allowed

    def is_destructive_allowed(self, outdir: str) -> bool:
        return self._allowed

@pytest.mark.asyncio
async def test_run_rce_tests_skipped_when_not_allowed(tmp_path):
    scope = DummyScope(allowed=False)
    outdir = str(tmp_path)
    # create run_meta.json (should be ignored)
    meta = {"targets": ["https://example.com"], "simulate_vuln": True}
    with open(os.path.join(outdir, "run_meta.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f)
    res = await rce_tester.run_rce_tests(scope, outdir)
    assert isinstance(res, list)
    assert res == []  # should be skipped when destructive not allowed

@pytest.mark.asyncio
async def test_run_rce_tests_returns_findings_when_allowed(tmp_path):
    scope = DummyScope(allowed=True)
    outdir = str(tmp_path)
    meta = {"targets": ["https://vuln.example.com"], "simulate_vuln": True}
    with open(os.path.join(outdir, "run_meta.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f)
    res = await rce_tester.run_rce_tests(scope, outdir)
    assert isinstance(res, list)
    # should include at least one informational finding and one simulated candidate
    types = [r["type"] for r in res]
    assert "rce-check-info" in types
    assert "rce-candidate" in types

@pytest.mark.asyncio
async def test_run_rce_tests_handles_missing_meta(tmp_path):
    scope = DummyScope(allowed=True)
    outdir = str(tmp_path)
    # no run_meta.json present
    res = await rce_tester.run_rce_tests(scope, outdir)
    assert isinstance(res, list)
    # with no targets, only empty list expected
    assert res == []
