# Curated Scan Report

- Run: `ui-run-ab165561`
- Reports dir: `reports/`

## Summary

- Consolidated findings: **50**
- PoCs discovered (compact): **4**

---

### sqli-error — `http://testphp.vulnweb.com/search.php?test=query`
- **Severity:** 5
- **Occurrences merged:** 3
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: SQL syntax
- **AI suggestion:**
  - predicted type: `sqli` (confidence: 0.50)
  - explanation: heuristic
- **Recommended remediation (high level):**
  - Use parameterized queries / prepared statements. Validate and escape inputs. Review DB permissions.

---

### sqli-error — `http://testphp.vulnweb.com/secured/newuser.php`
- **Severity:** 5
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: SQL syntax
- **AI suggestion:**
  - predicted type: `sqli` (confidence: 0.50)
  - explanation: heuristic
- **Recommended remediation (high level):**
  - Use parameterized queries / prepared statements. Validate and escape inputs. Review DB permissions.

---

### xss-reflected — `http://testphp.vulnweb.com/guestbook.php`
- **Severity:** 4
- **Occurrences merged:** 3
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
- **AI suggestion:**
  - predicted type: `xss` (confidence: 0.50)
  - explanation: heuristic
- **Recommended remediation (high level):**
  - Sanitize and encode untrusted input before rendering. Use context-specific encoding (HTML, JS, attribute). Implement CSP.

---

### xss-reflected — `http://testphp.vulnweb.com/search.php?test=query`
- **Severity:** 4
- **Occurrences merged:** 2
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
- **AI suggestion:**
  - predicted type: `xss` (confidence: 0.50)
  - explanation: heuristic
- **Recommended remediation (high level):**
  - Sanitize and encode untrusted input before rendering. Use context-specific encoding (HTML, JS, attribute). Implement CSP.

---

### xss-reflected — `http://testphp.vulnweb.com/secured/newuser.php`
- **Severity:** 4
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
- **AI suggestion:**
  - predicted type: `xss` (confidence: 0.50)
  - explanation: heuristic
- **Recommended remediation (high level):**
  - Sanitize and encode untrusted input before rendering. Use context-specific encoding (HTML, JS, attribute). Implement CSP.

---

### sqli-error — `https://testphp.vulnweb.com`
- **Severity:** 4
- **Occurrences merged:** 1
- **PoCs (1):**
  - `https://testphp.vulnweb.com` — status: `error`
- **Examples / notes:**
  - (no compact excerpt available)
- **AI suggestion:**
  - predicted type: `sqli` (confidence: 0.50)
  - explanation: heuristic
- **Recommended remediation (high level):**
  - Use parameterized queries / prepared statements. Validate and escape inputs. Review DB permissions.

---

### xss-none — `http://testphp.vulnweb.com/hpp/params.php?p=valid&pp=12`
- **Severity:** 2
- **Occurrences merged:** 3
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
- **AI suggestion:**
  - predicted type: `xss` (confidence: 0.50)
  - explanation: heuristic
- **Recommended remediation (high level):**
  - Sanitize and encode untrusted input before rendering. Use context-specific encoding (HTML, JS, attribute). Implement CSP.

---

### sqli-none — `http://testphp.vulnweb.com/hpp/params.php?p=valid&pp=12`
- **Severity:** 2
- **Occurrences merged:** 3
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
- **AI suggestion:**
  - predicted type: `sqli` (confidence: 0.50)
  - explanation: heuristic
- **Recommended remediation (high level):**
  - Use parameterized queries / prepared statements. Validate and escape inputs. Review DB permissions.

---

### external-tool-commix — `<no-target>`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: {"status": "skipped_by_safety", "tool": "commix"}
- **AI suggestion:**
  - predicted type: `unknown` (confidence: 0.00)
  - explanation: no-model
- **Recommended remediation (high level):**
  - Review input validation, encoding, and access controls for this endpoint.

---

### external-tool-hashcat — `<no-target>`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: {"status": "skipped_by_safety", "tool": "hashcat"}
- **AI suggestion:**
  - predicted type: `unknown` (confidence: 0.00)
  - explanation: no-model
- **Recommended remediation (high level):**
  - Review input validation, encoding, and access controls for this endpoint.

---

### external-tool-hydra — `<no-target>`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: {"status": "skipped_by_safety", "tool": "hydra"}
- **AI suggestion:**
  - predicted type: `unknown` (confidence: 0.00)
  - explanation: no-model
- **Recommended remediation (high level):**
  - Review input validation, encoding, and access controls for this endpoint.

---

### external-tool-john — `<no-target>`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: {"status": "skipped_by_safety", "tool": "john"}
- **AI suggestion:**
  - predicted type: `unknown` (confidence: 0.00)
  - explanation: no-model
- **Recommended remediation (high level):**
  - Review input validation, encoding, and access controls for this endpoint.

---

### external-tool-medusa — `<no-target>`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: {"status": "skipped_by_safety", "tool": "medusa"}
- **AI suggestion:**
  - predicted type: `unknown` (confidence: 0.00)
  - explanation: no-model
- **Recommended remediation (high level):**
  - Review input validation, encoding, and access controls for this endpoint.

---

### external-tool-msfconsole — `<no-target>`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: {"status": "skipped_by_safety", "tool": "msfconsole"}
- **AI suggestion:**
  - predicted type: `unknown` (confidence: 0.00)
  - explanation: no-model
- **Recommended remediation (high level):**
  - Review input validation, encoding, and access controls for this endpoint.

---

### external-tool-nikto_adapter — `<no-target>`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: {"tool": "nikto", "status": "ran", "rc": 0, "findings": ["+ 0 host(s) tested"], "stdout": "- Nikto v2.5.0\n---------------------------------------------------------------------------\n---------------------------------------------------------------------------\n+ 0 host(s) tested\n", "stderr": ""}
- **AI suggestion:**
  - predicted type: `unknown` (confidence: 0.00)
  - explanation: no-model
- **Recommended remediation (high level):**
  - Review input validation, encoding, and access controls for this endpoint.

---

### external-tool-nikto — `<no-target>`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: {"tool": "nikto", "status": "ran", "rc": 0, "findings": ["+ 0 host(s) tested"], "stdout": "- Nikto v2.5.0\n---------------------------------------------------------------------------\n---------------------------------------------------------------------------\n+ 0 host(s) tested\n", "stderr": "", "output_file": "runs/testphp.vulnweb.com/ui-run-ab165561/generated/tools/nikto_adapter.json"}
- **AI suggestion:**
  - predicted type: `unknown` (confidence: 0.00)
  - explanation: no-model
- **Recommended remediation (high level):**
  - Review input validation, encoding, and access controls for this endpoint.

---

### external-tool-nuclei — `<no-target>`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: {"tool": "nuclei", "status": "adapter_missing_binary", "note": "nuclei not found on PATH"}
- **AI suggestion:**
  - predicted type: `unknown` (confidence: 0.00)
  - explanation: no-model
- **Recommended remediation (high level):**
  - Review input validation, encoding, and access controls for this endpoint.

---

### external-tool-sqlmap — `<no-target>`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: {"status": "skipped_by_safety", "tool": "sqlmap"}
- **AI suggestion:**
  - predicted type: `sqli` (confidence: 0.50)
  - explanation: heuristic
- **Recommended remediation (high level):**
  - Review input validation, encoding, and access controls for this endpoint.

---

### external-tool-sslyze — `<no-target>`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: {"meta": {"tool": "sslyze", "status": "mocked_no_binary"}, "result": {"stdout": "mock output for sslyze"}, "parsed_findings": []}
- **AI suggestion:**
  - predicted type: `unknown` (confidence: 0.00)
  - explanation: no-model
- **Recommended remediation (high level):**
  - Review input validation, encoding, and access controls for this endpoint.

---

### external-tool-wappalyzer — `<no-target>`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: {"meta": {"tool": "wappalyzer", "status": "mocked_no_binary"}, "result": {"stdout": "mock output for wappalyzer"}, "parsed_findings": []}
- **AI suggestion:**
  - predicted type: `unknown` (confidence: 0.00)
  - explanation: no-model
- **Recommended remediation (high level):**
  - Review input validation, encoding, and access controls for this endpoint.

---

### external-tool-wpscan — `<no-target>`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: {"status": "skipped_by_safety", "tool": "wpscan"}
- **AI suggestion:**
  - predicted type: `unknown` (confidence: 0.00)
  - explanation: no-model
- **Recommended remediation (high level):**
  - Review input validation, encoding, and access controls for this endpoint.

---

### external-tool-manager — `<unknown>`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: null
- **AI suggestion:**
  - predicted type: `unknown` (confidence: 0.00)
  - explanation: no-model
- **Recommended remediation (high level):**
  - Review input validation, encoding, and access controls for this endpoint.

---

### external-tool-nmap — `<unknown>`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: null
- **AI suggestion:**
  - predicted type: `unknown` (confidence: 0.00)
  - explanation: no-model
- **Recommended remediation (high level):**
  - Review input validation, encoding, and access controls for this endpoint.

---

### external-tool-parsers — `<unknown>`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: null
- **AI suggestion:**
  - predicted type: `unknown` (confidence: 0.00)
  - explanation: no-model
- **Recommended remediation (high level):**
  - Review input validation, encoding, and access controls for this endpoint.

---

### external-tool-tool_config — `<unknown>`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: null
- **AI suggestion:**
  - predicted type: `unknown` (confidence: 0.00)
  - explanation: no-model
- **Recommended remediation (high level):**
  - Review input validation, encoding, and access controls for this endpoint.

---

### xss-none — `http://testphp.vulnweb.com/`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
- **AI suggestion:**
  - predicted type: `xss` (confidence: 0.50)
  - explanation: heuristic
- **Recommended remediation (high level):**
  - Sanitize and encode untrusted input before rendering. Use context-specific encoding (HTML, JS, attribute). Implement CSP.

---

### xss-none — `http://testphp.vulnweb.com/artists.php?artist=1`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
- **AI suggestion:**
  - predicted type: `xss` (confidence: 0.50)
  - explanation: heuristic
- **Recommended remediation (high level):**
  - Sanitize and encode untrusted input before rendering. Use context-specific encoding (HTML, JS, attribute). Implement CSP.

---

### sqli-none — `http://testphp.vulnweb.com/artists.php?artist=1`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
- **AI suggestion:**
  - predicted type: `sqli` (confidence: 0.50)
  - explanation: heuristic
- **Recommended remediation (high level):**
  - Use parameterized queries / prepared statements. Validate and escape inputs. Review DB permissions.

---

### xss-none — `http://testphp.vulnweb.com/artists.php?artist=2`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
- **AI suggestion:**
  - predicted type: `xss` (confidence: 0.50)
  - explanation: heuristic
- **Recommended remediation (high level):**
  - Sanitize and encode untrusted input before rendering. Use context-specific encoding (HTML, JS, attribute). Implement CSP.

---

### sqli-none — `http://testphp.vulnweb.com/artists.php?artist=2`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
- **AI suggestion:**
  - predicted type: `sqli` (confidence: 0.50)
  - explanation: heuristic
- **Recommended remediation (high level):**
  - Use parameterized queries / prepared statements. Validate and escape inputs. Review DB permissions.

---

### xss-none — `http://testphp.vulnweb.com/artists.php?artist=3`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
- **AI suggestion:**
  - predicted type: `xss` (confidence: 0.50)
  - explanation: heuristic
- **Recommended remediation (high level):**
  - Sanitize and encode untrusted input before rendering. Use context-specific encoding (HTML, JS, attribute). Implement CSP.

---

### sqli-none — `http://testphp.vulnweb.com/artists.php?artist=3`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
- **AI suggestion:**
  - predicted type: `sqli` (confidence: 0.50)
  - explanation: heuristic
- **Recommended remediation (high level):**
  - Use parameterized queries / prepared statements. Validate and escape inputs. Review DB permissions.

---

### xss-none — `http://testphp.vulnweb.com/guestbook.php`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs (1):**
  - `http://testphp.vulnweb.com/guestbook.php` — status: `error`
- **Examples / notes:**
  - (no compact excerpt available)
- **AI suggestion:**
  - predicted type: `xss` (confidence: 0.50)
  - explanation: heuristic
- **Recommended remediation (high level):**
  - Sanitize and encode untrusted input before rendering. Use context-specific encoding (HTML, JS, attribute). Implement CSP.

---

### sqli-none — `http://testphp.vulnweb.com/guestbook.php`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
- **AI suggestion:**
  - predicted type: `sqli` (confidence: 0.50)
  - explanation: heuristic
- **Recommended remediation (high level):**
  - Use parameterized queries / prepared statements. Validate and escape inputs. Review DB permissions.

---

### xss-none — `http://testphp.vulnweb.com/hpp/?pp=12`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
- **AI suggestion:**
  - predicted type: `xss` (confidence: 0.50)
  - explanation: heuristic
- **Recommended remediation (high level):**
  - Sanitize and encode untrusted input before rendering. Use context-specific encoding (HTML, JS, attribute). Implement CSP.

---

### sqli-none — `http://testphp.vulnweb.com/hpp/?pp=12`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
- **AI suggestion:**
  - predicted type: `sqli` (confidence: 0.50)
  - explanation: heuristic
- **Recommended remediation (high level):**
  - Use parameterized queries / prepared statements. Validate and escape inputs. Review DB permissions.

---

### xss-none — `http://testphp.vulnweb.com/listproducts.php?cat=1`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
- **AI suggestion:**
  - predicted type: `xss` (confidence: 0.50)
  - explanation: heuristic
- **Recommended remediation (high level):**
  - Sanitize and encode untrusted input before rendering. Use context-specific encoding (HTML, JS, attribute). Implement CSP.

---

### sqli-none — `http://testphp.vulnweb.com/listproducts.php?cat=1`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
- **AI suggestion:**
  - predicted type: `sqli` (confidence: 0.50)
  - explanation: heuristic
- **Recommended remediation (high level):**
  - Use parameterized queries / prepared statements. Validate and escape inputs. Review DB permissions.

---

### xss-none — `http://testphp.vulnweb.com/listproducts.php?cat=2`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
- **AI suggestion:**
  - predicted type: `xss` (confidence: 0.50)
  - explanation: heuristic
- **Recommended remediation (high level):**
  - Sanitize and encode untrusted input before rendering. Use context-specific encoding (HTML, JS, attribute). Implement CSP.

---

### sqli-none — `http://testphp.vulnweb.com/listproducts.php?cat=2`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
- **AI suggestion:**
  - predicted type: `sqli` (confidence: 0.50)
  - explanation: heuristic
- **Recommended remediation (high level):**
  - Use parameterized queries / prepared statements. Validate and escape inputs. Review DB permissions.

---

### xss-none — `http://testphp.vulnweb.com/listproducts.php?cat=3`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
- **AI suggestion:**
  - predicted type: `xss` (confidence: 0.50)
  - explanation: heuristic
- **Recommended remediation (high level):**
  - Sanitize and encode untrusted input before rendering. Use context-specific encoding (HTML, JS, attribute). Implement CSP.

---

### sqli-none — `http://testphp.vulnweb.com/listproducts.php?cat=3`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
- **AI suggestion:**
  - predicted type: `sqli` (confidence: 0.50)
  - explanation: heuristic
- **Recommended remediation (high level):**
  - Use parameterized queries / prepared statements. Validate and escape inputs. Review DB permissions.

---

### xss-none — `http://testphp.vulnweb.com/listproducts.php?cat=4`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
- **AI suggestion:**
  - predicted type: `xss` (confidence: 0.50)
  - explanation: heuristic
- **Recommended remediation (high level):**
  - Sanitize and encode untrusted input before rendering. Use context-specific encoding (HTML, JS, attribute). Implement CSP.

---

### sqli-none — `http://testphp.vulnweb.com/listproducts.php?cat=4`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
- **AI suggestion:**
  - predicted type: `sqli` (confidence: 0.50)
  - explanation: heuristic
- **Recommended remediation (high level):**
  - Use parameterized queries / prepared statements. Validate and escape inputs. Review DB permissions.

---

### xss-none — `http://testphp.vulnweb.com/search.php?test=query`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs (1):**
  - `http://testphp.vulnweb.com/search.php?test=query` — status: `error`
- **Examples / notes:**
  - (no compact excerpt available)
- **AI suggestion:**
  - predicted type: `xss` (confidence: 0.50)
  - explanation: heuristic
- **Recommended remediation (high level):**
  - Sanitize and encode untrusted input before rendering. Use context-specific encoding (HTML, JS, attribute). Implement CSP.

---

### sqli-none — `http://testphp.vulnweb.com/search.php?test=query`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
- **AI suggestion:**
  - predicted type: `sqli` (confidence: 0.50)
  - explanation: heuristic
- **Recommended remediation (high level):**
  - Use parameterized queries / prepared statements. Validate and escape inputs. Review DB permissions.

---

### xss-none — `http://testphp.vulnweb.com/secured/newuser.php`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs (1):**
  - `http://testphp.vulnweb.com/secured/newuser.php` — status: `error`
- **Examples / notes:**
  - (no compact excerpt available)
- **AI suggestion:**
  - predicted type: `xss` (confidence: 0.50)
  - explanation: heuristic
- **Recommended remediation (high level):**
  - Sanitize and encode untrusted input before rendering. Use context-specific encoding (HTML, JS, attribute). Implement CSP.

---

### sqli-none — `http://testphp.vulnweb.com/secured/newuser.php`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
- **AI suggestion:**
  - predicted type: `sqli` (confidence: 0.50)
  - explanation: heuristic
- **Recommended remediation (high level):**
  - Use parameterized queries / prepared statements. Validate and escape inputs. Review DB permissions.

---

### xss-none — `http://testphp.vulnweb.com/userinfo.php`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
- **AI suggestion:**
  - predicted type: `xss` (confidence: 0.50)
  - explanation: heuristic
- **Recommended remediation (high level):**
  - Sanitize and encode untrusted input before rendering. Use context-specific encoding (HTML, JS, attribute). Implement CSP.

---

### sqli-none — `http://testphp.vulnweb.com/userinfo.php`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
- **AI suggestion:**
  - predicted type: `sqli` (confidence: 0.50)
  - explanation: heuristic
- **Recommended remediation (high level):**
  - Use parameterized queries / prepared statements. Validate and escape inputs. Review DB permissions.

---

## Mapping diagnostics (auto-generated)

- mapping candidates processed: 4
- unmapped PoCs: 0


---

Generated by pentest pipeline — curated output.
