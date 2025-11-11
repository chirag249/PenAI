# Curated Scan Report

- Run: `smoke-test`
- Reports dir: `reports/`

## Summary

- Consolidated findings: **42**
- PoCs discovered (compact): **3**

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

### external-tool-sqlmap — `<no-target>`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: {"meta": {"tool": "sqlmap", "status": "ran"}, "result": {"cmd": ["/usr/bin/sqlmap", "-u", "https://testphp.vulnweb.com", "--batch", "--risk=1", "--level=1", "--random-agent", "--timeout=10"], "rc": 0, "stdout": "        ___\n       __H__\n ___ ___[(]_____ ___ ___  {1.8.12#stable}\n|_ -| . [.]     | .'| . |\n|___|_  [.]_|_|_|__,|  _|\n      |_|V...       |_|   https://sqlmap.org\n\n[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program\n\n[*] starting @ 12:38:25 /2025-10-07/\n\n\u001b[?1049h\u001b[22;0;0t\u001b[1;24r\u001b(B\u001b[m\u001b[4l\u001b[?7h\u001b[24;1H\u001b[?1049l\u001b[23;0;0t\n\u001b[?1l\u001b>[12:38:25] [INFO] fetched random HTTP User-Agent header value 'Mozilla/5.0 (Macintosh; U; PPC Mac OS X 10_5_6; fr-fr) AppleWebKit/525.27.1 (KHTML, like Gecko) Version/3.2.1 Safari/525.27.1' from file '/usr/share/sqlmap/data/txt/user-agents.txt'\n[1/1] URL:\nGET https://testphp.vulnweb.com\ndo you want to test this URL? [Y/n/q]\n> Y\n[12:38:25] [INFO] testing URL 'https://testphp.vulnweb.com'\n[12:38:25] [INFO] using '/home/asd/.local/share/sqlmap/output/results-10072025_1238pm.csv' as the CSV results file in multiple targets mode\n[12:38:25] [INFO] testing connection to the target URL\n[12:39:05] [ERROR] can't establish SSL connection, ski
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
  - predicted type: `unknown` (confidence: 0.00)
  - explanation: model-error
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
  - predicted type: `unknown` (confidence: 0.00)
  - explanation: model-error
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
  - explanation: model-error
- **Recommended remediation (high level):**
  - Review input validation, encoding, and access controls for this endpoint.

---

### external-tool-nikto — `<no-target>`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: {"tool": "nikto", "status": "ran", "rc": 0, "findings": ["+ 0 host(s) tested"], "stdout": "- Nikto v2.5.0\n---------------------------------------------------------------------------\n---------------------------------------------------------------------------\n+ 0 host(s) tested\n", "stderr": "", "output_file": "runs/smoke-test/generated/tools/nikto_adapter.json"}
- **AI suggestion:**
  - predicted type: `unknown` (confidence: 0.00)
  - explanation: model-error
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
  - predicted type: `unknown` (confidence: 0.00)
  - explanation: model-error
- **Recommended remediation (high level):**
  - Review input validation, encoding, and access controls for this endpoint.

---

### external-tool-nuclei — `<no-target>`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: {"tool": "nuclei", "status": "ran", "rc": null, "findings": [], "stdout": "", "stderr": "timeout", "output_file": "runs/smoke-test/generated/tools/nuclei_adapter.json"}
- **AI suggestion:**
  - predicted type: `unknown` (confidence: 0.00)
  - explanation: model-error
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
  - predicted type: `unknown` (confidence: 0.00)
  - explanation: model-error
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
  - explanation: model-error
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

### sqli-none — `http://testphp.vulnweb.com/`
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
  - [http://testphp.vulnweb.com/guestbook.php](pocs/snippets/http_testphp.vulnweb.com_guestbook.php_5304e0614c.html) — status: `200`
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
  - [http://testphp.vulnweb.com/search.php?test=query](pocs/snippets/http_testphp.vulnweb.com_search.php_test_query_fc4c1079cd.html) — status: `200`
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
  - [http://testphp.vulnweb.com/secured/newuser.php](pocs/snippets/http_testphp.vulnweb.com_secured_newuser.php_2e10db35d2.html) — status: `200`
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

- mapping candidates processed: 3
- unmapped PoCs: 0


---

Generated by pentest pipeline — curated output.
