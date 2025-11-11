from modules.tools.parsers import sqlmap_parser

def test_parser_with_simple_vuln():
    data = {"result": {"vulnerabilities": [{"url":"http://a/x","parameter":"q","payload":"' OR 1=1"}]}}
    out = sqlmap_parser.parse_sqlmap_output(data)
    assert isinstance(out, list)
    assert out and out[0]["type"].startswith("sqli-")
