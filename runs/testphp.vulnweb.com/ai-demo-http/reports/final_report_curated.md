# Curated Scan Report

- Run: `ai-demo-http`
- Reports dir: `reports/`

## Summary

- Consolidated findings: **25**
- PoCs discovered (compact): **2**

---

### sqli-error — `http://testphp.vulnweb.com/search.php?test=query`
- **Severity:** 5
- **Occurrences merged:** 3
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: SQL syntax
- **AI suggestion:**
  - predicted type: `sqli` (confidence: 0.92)
  - explanation: keyword-map
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
  - predicted type: `sqli` (confidence: 0.92)
  - explanation: keyword-map
- **Recommended remediation (high level):**
  - Use parameterized queries / prepared statements. Validate and escape inputs. Review DB permissions.

---

### xss-reflected — `http://testphp.vulnweb.com/search.php?test=query`
- **Severity:** 4
- **Occurrences merged:** 2
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
- **AI suggestion:**
  - predicted type: `xss` (confidence: 1.00)
  - explanation: keyword-map
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
  - predicted type: `xss` (confidence: 1.00)
  - explanation: keyword-map
- **Recommended remediation (high level):**
  - Sanitize and encode untrusted input before rendering. Use context-specific encoding (HTML, JS, attribute). Implement CSP.

---

### xss-none — `http://testphp.vulnweb.com/hpp/params.php?p=valid&pp=12`
- **Severity:** 2
- **Occurrences merged:** 3
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
- **AI suggestion:**
  - predicted type: `xss` (confidence: 0.92)
  - explanation: keyword-map
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
  - predicted type: `sqli` (confidence: 0.94)
  - explanation: keyword-map
- **Recommended remediation (high level):**
  - Use parameterized queries / prepared statements. Validate and escape inputs. Review DB permissions.

---

### external-tool-sqlmap — `<no-target>`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: {"meta": {"tool": "sqlmap", "status": "ran"}, "result": {"cmd": ["/usr/bin/sqlmap", "-u", "http://testphp.vulnweb.com", "--batch", "--risk=1", "--level=1", "--random-agent", "--timeout=10"], "rc": 0, "stdout": "        ___\n       __H__\n ___ ___[']_____ ___ ___  {1.8.12#stable}\n|_ -| . [']     | .'| . |\n|___|_  [,]_|_|_|__,|  _|\n      |_|V...       |_|   https://sqlmap.org\n\n[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program\n\n[*] starting @ 22:12:19 /2025-10-04/\n\n[22:12:19] [INFO] fetched random HTTP User-Agent header value 'Mozilla/5.0 (Windows; U; Windows NT 6.0; it; rv:1.9.1b2) Gecko/20081201 Firefox/3.1b2' from file '/usr/share/sqlmap/data/txt/user-agents.txt'\n[22:12:24] [INFO] testing connection to the target URL\n[22:12:25] [INFO] checking if the target is protected by some kind of WAF/IPS\n[22:12:25] [INFO] testing if the target URL content is stable\n[22:12:26] [INFO] target URL content is stable\n[22:12:26] [CRITICAL] no parameter(s) found for testing in the provided data (e.g. GET parameter 'id' in 'www.site.com/index.php?id=1'). You are advised to rerun with '--forms --crawl=2'\n[22:12:26] [WARNING] your sqlmap version is outdated\n\n[*] ending @ 22:12:26 /2025-10-04/\n\n", "stderr": ""}, "parsed_findings": [], "outp
- **AI suggestion:**
  - predicted type: `sqli` (confidence: 0.50)
  - explanation: heuristic
- **Recommended remediation (high level):**
  - Review input validation, encoding, and access controls for this endpoint.

---

### external-tool-wpscan_adapter — `<no-target>`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: {"tool": "wpscan", "status": "ran", "rc": 1, "vulnerabilities": [], "stdout": "", "stderr": "/usr/share/rubygems-integration/all/gems/activesupport-6.1.7.10/lib/active_support/logger_thread_safe_level.rb:16:in `<module:LoggerThreadSafeLevel>': uninitialized constant ActiveSupport::LoggerThreadSafeLevel::Logger (NameError)\n\n    Logger::Severity.constants.each do |severity|\n    ^^^^^^\n\tfrom /usr/share/rubygems-integration/all/gems/activesupport-6.1.7.10/lib/active_support/logger_thread_safe_level.rb:9:in `<module:ActiveSupport>'\n\tfrom /usr/share/rubygems-integration/all/gems/activesupport-6.1.7.10/lib/active_support/logger_thread_safe_level.rb:8:in `<top (required)>'\n\tfrom <internal:/usr/lib/ruby/vendor_ruby/rubygems/core_ext/kernel_require.rb>:85:in `require'\n\tfrom <internal:/usr/lib/ruby/vendor_ruby/rubygems/core_ext/kernel_require.rb>:85:in `require'\n\tfrom /usr/share/rubygems-integration/all/gems/activesupport-6.1.7.10/lib/active_support/logger_silence.rb:5:in `<top (required)>'\n\tfrom <internal:/usr/lib/ruby/vendor_ruby/rubygems/core_ext/kernel_require.rb>:85:in `require'\n\tfrom <internal:/usr/lib/ruby/vendor_ruby/rubygems/core_ext/kernel_require.rb>:85:in `require'\n\tfrom /usr/share/rubygems-integration/all/gems/activesupport-6.1.7.10/lib/active_support/logger.rb:3:in `<top (required)>'\n\tfrom <internal:/usr/lib/ruby/vendor_ruby/rubygems/core_ext/kernel_require.rb>:85:in `require'\n\tfrom <internal:/usr/lib/ruby/vendor_ruby/rubygems/core_ext/kernel_require
- **AI suggestion:**
  - predicted type: `unknown` (confidence: 0.97)
  - explanation: keyword-map
- **Recommended remediation (high level):**
  - Review input validation, encoding, and access controls for this endpoint.

---

### external-tool-wpscan — `<no-target>`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: {"tool": "wpscan", "status": "ran", "rc": 1, "vulnerabilities": [], "stdout": "", "stderr": "/usr/share/rubygems-integration/all/gems/activesupport-6.1.7.10/lib/active_support/logger_thread_safe_level.rb:16:in `<module:LoggerThreadSafeLevel>': uninitialized constant ActiveSupport::LoggerThreadSafeLevel::Logger (NameError)\n\n    Logger::Severity.constants.each do |severity|\n    ^^^^^^\n\tfrom /usr/share/rubygems-integration/all/gems/activesupport-6.1.7.10/lib/active_support/logger_thread_safe_level.rb:9:in `<module:ActiveSupport>'\n\tfrom /usr/share/rubygems-integration/all/gems/activesupport-6.1.7.10/lib/active_support/logger_thread_safe_level.rb:8:in `<top (required)>'\n\tfrom <internal:/usr/lib/ruby/vendor_ruby/rubygems/core_ext/kernel_require.rb>:85:in `require'\n\tfrom <internal:/usr/lib/ruby/vendor_ruby/rubygems/core_ext/kernel_require.rb>:85:in `require'\n\tfrom /usr/share/rubygems-integration/all/gems/activesupport-6.1.7.10/lib/active_support/logger_silence.rb:5:in `<top (required)>'\n\tfrom <internal:/usr/lib/ruby/vendor_ruby/rubygems/core_ext/kernel_require.rb>:85:in `require'\n\tfrom <internal:/usr/lib/ruby/vendor_ruby/rubygems/core_ext/kernel_require.rb>:85:in `require'\n\tfrom /usr/share/rubygems-integration/all/gems/activesupport-6.1.7.10/lib/active_support/logger.rb:3:in `<top (required)>'\n\tfrom <internal:/usr/lib/ruby/vendor_ruby/rubygems/core_ext/kernel_require.rb>:85:in `require'\n\tfrom <internal:/usr/lib/ruby/vendor_ruby/rubygems/core_ext/kernel_require
- **AI suggestion:**
  - predicted type: `unknown` (confidence: 0.97)
  - explanation: keyword-map
- **Recommended remediation (high level):**
  - Review input validation, encoding, and access controls for this endpoint.

---

### external-tool-nikto_adapter — `<no-target>`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: {"tool": "nikto", "status": "ran", "rc": null, "findings": [], "stdout": "", "stderr": "timeout"}
- **AI suggestion:**
  - predicted type: `unknown` (confidence: 0.98)
  - explanation: keyword-map
- **Recommended remediation (high level):**
  - Review input validation, encoding, and access controls for this endpoint.

---

### external-tool-nikto — `<no-target>`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: {"tool": "nikto", "status": "ran", "rc": null, "findings": [], "stdout": "", "stderr": "timeout", "output_file": "runs/testphp.vulnweb.com/ai-demo-http/generated/tools/nikto_adapter.json"}
- **AI suggestion:**
  - predicted type: `unknown` (confidence: 0.98)
  - explanation: keyword-map
- **Recommended remediation (high level):**
  - Review input validation, encoding, and access controls for this endpoint.

---

### external-tool-nuclei_adapter — `<no-target>`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: {"tool": "nuclei", "status": "ran", "rc": null, "findings": [], "stdout": "", "stderr": "timeout"}
- **AI suggestion:**
  - predicted type: `unknown` (confidence: 0.98)
  - explanation: keyword-map
- **Recommended remediation (high level):**
  - Review input validation, encoding, and access controls for this endpoint.

---

### external-tool-nuclei — `<no-target>`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: {"tool": "nuclei", "status": "ran", "rc": null, "findings": [], "stdout": "", "stderr": "timeout", "output_file": "runs/testphp.vulnweb.com/ai-demo-http/generated/tools/nuclei_adapter.json"}
- **AI suggestion:**
  - predicted type: `unknown` (confidence: 0.98)
  - explanation: keyword-map
- **Recommended remediation (high level):**
  - Review input validation, encoding, and access controls for this endpoint.

---

### external-tool-wapiti — `<no-target>`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: {"status": "error", "tool": "wapiti", "error": "[Errno 2] No such file or directory: 'wapiti'"}
- **AI suggestion:**
  - predicted type: `unknown` (confidence: 0.91)
  - explanation: keyword-map
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
  - predicted type: `unknown` (confidence: 1.00)
  - explanation: keyword-map
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
  - predicted type: `xss` (confidence: 0.92)
  - explanation: keyword-map
- **Recommended remediation (high level):**
  - Sanitize and encode untrusted input before rendering. Use context-specific encoding (HTML, JS, attribute). Implement CSP.

---

### sqli-none — `http://testphp.vulnweb.com/`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
- **AI suggestion:**
  - predicted type: `sqli` (confidence: 0.94)
  - explanation: keyword-map
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
  - predicted type: `xss` (confidence: 0.92)
  - explanation: keyword-map
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
  - predicted type: `sqli` (confidence: 0.94)
  - explanation: keyword-map
- **Recommended remediation (high level):**
  - Use parameterized queries / prepared statements. Validate and escape inputs. Review DB permissions.

---

### xss-none — `http://testphp.vulnweb.com/search.php?test=query`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs (1):**
  - [http://testphp.vulnweb.com/search.php?test=query](pocs/snippets/http_testphp.vulnweb.com_search.php_test_query_fc4c1079cd.html) — status: `200`
- **Examples / notes:**
  - (no compact excerpt available)
- **AI suggestion:**
  - predicted type: `xss` (confidence: 0.92)
  - explanation: keyword-map
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
  - predicted type: `sqli` (confidence: 0.94)
  - explanation: keyword-map
- **Recommended remediation (high level):**
  - Use parameterized queries / prepared statements. Validate and escape inputs. Review DB permissions.

---

### xss-none — `http://testphp.vulnweb.com/secured/newuser.php`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs (1):**
  - [http://testphp.vulnweb.com/secured/newuser.php](pocs/snippets/http_testphp.vulnweb.com_secured_newuser.php_2e10db35d2.html) — status: `200`
- **Examples / notes:**
  - (no compact excerpt available)
- **AI suggestion:**
  - predicted type: `xss` (confidence: 0.92)
  - explanation: keyword-map
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
  - predicted type: `sqli` (confidence: 0.94)
  - explanation: keyword-map
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
  - predicted type: `xss` (confidence: 0.92)
  - explanation: keyword-map
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
  - predicted type: `sqli` (confidence: 0.94)
  - explanation: keyword-map
- **Recommended remediation (high level):**
  - Use parameterized queries / prepared statements. Validate and escape inputs. Review DB permissions.

---

## Mapping diagnostics (auto-generated)

- mapping candidates processed: 2
- unmapped PoCs: 0


---

Generated by pentest pipeline — curated output.
