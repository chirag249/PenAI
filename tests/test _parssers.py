import json
from modules.tools.parsers import parse_nikto_envelope, parse_nuclei_envelope, parse_tool_envelope

def test_parse_nikto_simple():
    env = {
        "result": {
            "stdout": "/admin - Directory indexing enabled\nOSVDB-12345: sample issue\n"
        },
        "target": "https://example.com"
    }
    findings = parse_nikto_envelope(env, "/tmp")
    assert isinstance(findings, list)
    assert any(f["type"].startswith("nikto") for f in findings)
    assert any("admin" in (f["evidence"].lower() or "") for f in findings)

def test_parse_nuclei_json_lines():
    # nuclei JSON-lines sample
    j1 = {"host": "https://example.com", "info": {"name": "CVE-XXXX", "severity": "high"}}
    env = {"result": {"stdout": json.dumps(j1) + "\n"}}
    findings = parse_nuclei_envelope(env, "/tmp")
    assert isinstance(findings, list)
    assert len(findings) >= 1
    assert findings[0]["severity"] >= 3

def test_dispatcher_parse_tool_envelope_fallback():
    env = {"result": {"stdout": "some unknown output"}, "target": "https://example.com"}
    parsed = parse_tool_envelope("unknown_tool", env, "/tmp")
    assert isinstance(parsed, list)
    assert parsed and parsed[0]["type"].startswith("external-tool-")
