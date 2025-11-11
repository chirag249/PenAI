# Curated Scan Report

- Run: `run-mhs3s7ut-8ok79`
- Reports dir: `reports/`

## Summary

- Consolidated findings: **46**
- PoCs discovered (compact): **0**

---

### external-tool-amass — `<no-target>`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: {"meta": {"tool": "amass", "status": "mocked_no_binary"}, "result": {"stdout": "mock output for amass"}, "parsed_findings": []}
- **AI suggestion:**
  - predicted type: `unknown` (confidence: 0.00)
  - explanation: no-model
- **Recommended remediation (high level):**
  - Review input validation, encoding, and access controls for this endpoint.

---

### external-tool-arachni — `<no-target>`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: {"meta": {"tool": "arachni", "status": "mocked_no_binary"}, "result": {"stdout": "mock output for arachni"}, "parsed_findings": []}
- **AI suggestion:**
  - predicted type: `unknown` (confidence: 0.00)
  - explanation: no-model
- **Recommended remediation (high level):**
  - Review input validation, encoding, and access controls for this endpoint.

---

### external-tool-boofuzz — `<no-target>`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: {"meta": {"tool": "boofuzz", "status": "mocked_no_binary"}, "result": {"stdout": "mock output for boofuzz"}, "parsed_findings": []}
- **AI suggestion:**
  - predicted type: `unknown` (confidence: 0.00)
  - explanation: no-model
- **Recommended remediation (high level):**
  - Review input validation, encoding, and access controls for this endpoint.

---

### external-tool-certspotter — `<no-target>`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: {"meta": {"tool": "certspotter", "status": "mocked_no_binary"}, "result": {"stdout": "mock output for certspotter"}, "parsed_findings": []}
- **AI suggestion:**
  - predicted type: `unknown` (confidence: 0.00)
  - explanation: no-model
- **Recommended remediation (high level):**
  - Review input validation, encoding, and access controls for this endpoint.

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

### external-tool-crtsh — `<no-target>`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: {"meta": {"tool": "crtsh", "status": "mocked_no_binary"}, "result": {"stdout": "mock output for crtsh"}, "parsed_findings": []}
- **AI suggestion:**
  - predicted type: `unknown` (confidence: 0.00)
  - explanation: no-model
- **Recommended remediation (high level):**
  - Review input validation, encoding, and access controls for this endpoint.

---

### external-tool-dalfox — `<no-target>`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: {"meta": {"tool": "dalfox", "status": "mocked_no_binary"}, "result": {"stdout": "mock output for dalfox"}, "parsed_findings": []}
- **AI suggestion:**
  - predicted type: `unknown` (confidence: 0.00)
  - explanation: no-model
- **Recommended remediation (high level):**
  - Review input validation, encoding, and access controls for this endpoint.

---

### external-tool-dirb — `<no-target>`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: {"meta": {"tool": "dirb", "status": "ran"}, "result": {"cmd": ["/usr/bin/dirb", "http://www.dvwa.co.uk/"], "rc": 0, "stdout": "\n-----------------\nDIRB v2.22    \nBy The Dark Raver\n-----------------\n\nSTART_TIME: Mon Nov 10 00:55:42 2025\nURL_BASE: http://www.dvwa.co.uk/\nWORDLIST_FILES: /usr/share/dirb/wordlists/common.txt\n\n-----------------\n\n*** Generating Wordlist...\n                                                                               \nGENERATED WORDS: 4612\n\n---- Scanning URL: http://www.dvwa.co.uk/ ----\n*** Calculating NOT_FOUND code...\n(!) WARNING: NOT_FOUND[] not stable, unable to determine correct URLs {30X}.\n    (Try using FineTunning: '-f')\n                                                                               \n                                                                               \n-----------------\nEND_TIME: Mon Nov 10 00:55:42 2025\nDOWNLOADED: 0 - FOUND: 0\n", "stderr": ""}, "parsed_findings": []}
- **AI suggestion:**
  - predicted type: `unknown` (confidence: 0.00)
  - explanation: no-model
- **Recommended remediation (high level):**
  - Review input validation, encoding, and access controls for this endpoint.

---

### external-tool-enum4linux — `<no-target>`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: {"meta": {"tool": "enum4linux", "status": "ran"}, "result": {"cmd": ["/usr/bin/enum4linux", "http://www.dvwa.co.uk/"], "rc": 1, "stdout": "ERROR: Target hostname \"http://www.dvwa.co.uk/\" contains some illegal characters\n", "stderr": ""}, "parsed_findings": []}
- **AI suggestion:**
  - predicted type: `unknown` (confidence: 0.00)
  - explanation: no-model
- **Recommended remediation (high level):**
  - Review input validation, encoding, and access controls for this endpoint.

---

### external-tool-ffuf — `<no-target>`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: {"meta": {"tool": "ffuf", "status": "ran"}, "result": {"cmd": ["/usr/bin/ffuf", "http://www.dvwa.co.uk/"], "rc": 1, "stdout": "Fuzz Faster U Fool - v2.1.0-dev\n\nHTTP OPTIONS:\n  -H                  Header `\"Name: Value\"`, separated by colon. Multiple -H flags are accepted.\n  -X                  HTTP method to use\n  -b                  Cookie data `\"NAME1=VALUE1; NAME2=VALUE2\"` for copy as curl functionality.\n  -cc                 Client cert for authentication. Client key needs to be defined as well for this to work\n  -ck                 Client key for authentication. Client certificate needs to be defined as well for this to work\n  -d                  POST data\n  -http2              Use HTTP2 protocol (default: false)\n  -ignore-body        Do not fetch the response content. (default: false)\n  -r                  Follow redirects (default: false)\n  -raw                Do not encode URI (default: false)\n  -recursion          Scan recursively. Only FUZZ keyword is supported, and URL (-u) has to end in it. (default: false)\n  -recursion-depth    Maximum recursion depth. (default: 0)\n  -recursion-strategy Recursion strategy: \"default\" for a redirect based, and \"greedy\" to recurse on all matches (default: default)\n  -replay-proxy       Replay matched requests using this proxy.\n  -sni                Target TLS SNI, does not support FUZZ keyword\n  -timeout            HTTP request timeout in seconds. (default: 10)\n  -u                  Target URL\n  -x        
- **AI suggestion:**
  - predicted type: `unknown` (confidence: 0.00)
  - explanation: no-model
- **Recommended remediation (high level):**
  - Review input validation, encoding, and access controls for this endpoint.

---

### external-tool-gitleaks — `<no-target>`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: {"meta": {"tool": "gitleaks", "status": "mocked_no_binary"}, "result": {"stdout": "mock output for gitleaks"}, "parsed_findings": []}
- **AI suggestion:**
  - predicted type: `unknown` (confidence: 0.00)
  - explanation: no-model
- **Recommended remediation (high level):**
  - Review input validation, encoding, and access controls for this endpoint.

---

### external-tool-gitrob — `<no-target>`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: {"meta": {"tool": "gitrob", "status": "mocked_no_binary"}, "result": {"stdout": "mock output for gitrob"}, "parsed_findings": []}
- **AI suggestion:**
  - predicted type: `unknown` (confidence: 0.00)
  - explanation: no-model
- **Recommended remediation (high level):**
  - Review input validation, encoding, and access controls for this endpoint.

---

### external-tool-gobuster — `<no-target>`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: {"meta": {"tool": "gobuster", "status": "ran"}, "result": {"cmd": ["/usr/bin/gobuster", "http://www.dvwa.co.uk/"], "rc": 1, "stdout": "", "stderr": "Error: unknown command \"http://www.dvwa.co.uk/\" for \"gobuster\"\nRun 'gobuster --help' for usage.\n"}, "parsed_findings": []}
- **AI suggestion:**
  - predicted type: `unknown` (confidence: 0.00)
  - explanation: no-model
- **Recommended remediation (high level):**
  - Review input validation, encoding, and access controls for this endpoint.

---

### external-tool-graphql-fuzzer — `<no-target>`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: {"meta": {"tool": "graphql-fuzzer", "status": "mocked_no_binary"}, "result": {"stdout": "mock output for graphql-fuzzer"}, "parsed_findings": []}
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

### external-tool-httprobe — `<no-target>`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: {"meta": {"tool": "httprobe", "status": "mocked_no_binary"}, "result": {"stdout": "mock output for httprobe"}, "parsed_findings": []}
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

### external-tool-masscan — `<no-target>`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: {"meta": {"tool": "masscan", "status": "ran"}, "result": {"cmd": ["/usr/bin/masscan", "http://www.dvwa.co.uk/"], "rc": 1, "stdout": "", "stderr": "FAIL: unknown command-line parameter \"http://www.dvwa.co.uk/\"\n [hint] did you want \"--http://www.dvwa.co.uk/\"?\n"}, "parsed_findings": []}
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

### external-tool-newman — `<no-target>`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: {"meta": {"tool": "newman", "status": "mocked_no_binary"}, "result": {"stdout": "mock output for newman"}, "parsed_findings": []}
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
  - evidence: {"tool": "nikto", "status": "ran", "rc": null, "findings": [], "stdout": "", "stderr": "timeout"}
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
  - evidence: {"tool": "nikto", "status": "ran", "rc": null, "findings": [], "stdout": "", "stderr": "timeout", "output_file": "runs/www.dvwa.co.uk/run-mhs3s7ut-8ok79/generated/tools/nikto_adapter.json"}
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

### external-tool-radamsa — `<no-target>`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: {"meta": {"tool": "radamsa", "status": "mocked_no_binary"}, "result": {"stdout": "mock output for radamsa"}, "parsed_findings": []}
- **AI suggestion:**
  - predicted type: `unknown` (confidence: 0.00)
  - explanation: no-model
- **Recommended remediation (high level):**
  - Review input validation, encoding, and access controls for this endpoint.

---

### external-tool-searchsploit — `<no-target>`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: {"meta": {"tool": "searchsploit", "status": "mocked_no_binary"}, "result": {"stdout": "mock output for searchsploit"}, "parsed_findings": []}
- **AI suggestion:**
  - predicted type: `unknown` (confidence: 0.00)
  - explanation: no-model
- **Recommended remediation (high level):**
  - Review input validation, encoding, and access controls for this endpoint.

---

### external-tool-smbclient — `<no-target>`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: {"meta": {"tool": "smbclient", "status": "ran"}, "result": {"cmd": ["/usr/bin/smbclient", "http://www.dvwa.co.uk/"], "rc": 1, "stdout": "", "stderr": ""}, "parsed_findings": []}
- **AI suggestion:**
  - predicted type: `unknown` (confidence: 0.00)
  - explanation: no-model
- **Recommended remediation (high level):**
  - Review input validation, encoding, and access controls for this endpoint.

---

### external-tool-smtp-user-enum — `<no-target>`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: {"meta": {"tool": "smtp-user-enum", "status": "ran"}, "result": {"cmd": ["/usr/bin/smtp-user-enum", "http://www.dvwa.co.uk/"], "rc": 1, "stdout": "smtp-user-enum v1.2 ( http://pentestmonkey.net/tools/smtp-user-enum )\n\nUsage: smtp-user-enum [options] ( -u username | -U file-of-usernames ) ( -t host | -T file-of-targets )\n\noptions are:\n        -m n     Maximum number of processes (default: 5)\n\t-M mode  Method to use for username guessing EXPN, VRFY or RCPT (default: VRFY)\n\t-u user  Check if user exists on remote system\n\t-f addr  MAIL FROM email address.  Used only in \"RCPT TO\" mode (default: user@example.com)\n        -D dom   Domain to append to supplied user list to make email addresses (Default: none)\n                 Use this option when you want to guess valid email addresses instead of just usernames\n                 e.g. \"-D example.com\" would guess foo@example.com, bar@example.com, etc.  Instead of \n                      simply the usernames foo and bar.\n\t-U file  File of usernames to check via smtp service\n\t-t host  Server host running smtp service\n\t-T file  File of hostnames running the smtp service\n\t-p port  TCP port on which smtp service runs (default: 25)\n\t-d       Debugging output\n\t-w n     Wait a maximum of n seconds for reply (default: 5)\n\t-v       Verbose\n\t-h       This help message\n\nAlso see smtp-user-enum-user-docs.pdf from the smtp-user-enum tar ball.\n\nExamples:\n\n$ smtp-user-enum -M VRFY -U users.txt -t 10.0.0.1\n$ smt
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

### external-tool-subfinder — `<no-target>`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: {"meta": {"tool": "subfinder", "status": "mocked_no_binary"}, "result": {"stdout": "mock output for subfinder"}, "parsed_findings": []}
- **AI suggestion:**
  - predicted type: `unknown` (confidence: 0.00)
  - explanation: no-model
- **Recommended remediation (high level):**
  - Review input validation, encoding, and access controls for this endpoint.

---

### external-tool-trufflehog — `<no-target>`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: {"meta": {"tool": "trufflehog", "status": "mocked_no_binary"}, "result": {"stdout": "mock output for trufflehog"}, "parsed_findings": []}
- **AI suggestion:**
  - predicted type: `unknown` (confidence: 0.00)
  - explanation: no-model
- **Recommended remediation (high level):**
  - Review input validation, encoding, and access controls for this endpoint.

---

### external-tool-unicornscan — `<no-target>`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: {"meta": {"tool": "unicornscan", "status": "ran"}, "result": {"cmd": ["/usr/bin/unicornscan", "http://www.dvwa.co.uk/"], "rc": 0, "stdout": "what host(s) should i scan?, ive got nothing to do\n", "stderr": "Main [Error   cidr.c:263] dns lookup fails for `http': Unknown host\nMain [Error   getconfig.c:434] cant add workunit for argument `http://www.dvwa.co.uk/': dont understand address `//www.dvwa.co.uk/'\n"}, "parsed_findings": []}
- **AI suggestion:**
  - predicted type: `unknown` (confidence: 0.00)
  - explanation: no-model
- **Recommended remediation (high level):**
  - Review input validation, encoding, and access controls for this endpoint.

---

### external-tool-w3af — `<no-target>`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: {"meta": {"tool": "w3af", "status": "mocked_no_binary"}, "result": {"stdout": "mock output for w3af"}, "parsed_findings": []}
- **AI suggestion:**
  - predicted type: `unknown` (confidence: 0.00)
  - explanation: no-model
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

### external-tool-wfuzz — `<no-target>`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: {"meta": {"tool": "wfuzz", "status": "ran"}, "result": {"cmd": ["/usr/bin/wfuzz", "http://www.dvwa.co.uk/"], "rc": 0, "stdout": "", "stderr": " /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.\n /usr/lib/python3/dist-packages/wfuzz/wfuzz.py:78: UserWarning:Fatal exception: Bad usage: You must specify a payload.\n"}, "parsed_findings": []}
- **AI suggestion:**
  - predicted type: `unknown` (confidence: 0.00)
  - explanation: no-model
- **Recommended remediation (high level):**
  - Review input validation, encoding, and access controls for this endpoint.

---

### external-tool-whatweb — `<no-target>`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: {"meta": {"tool": "whatweb", "status": "ran"}, "result": {"cmd": ["/usr/bin/whatweb", "http://www.dvwa.co.uk/"], "rc": 0, "stdout": "\u001b[1m\u001b[34mhttp://www.dvwa.co.uk/\u001b[0m [403 Forbidden] \u001b[1mCountry\u001b[0m[\u001b[0m\u001b[22mUNITED STATES\u001b[0m][\u001b[1m\u001b[31mUS\u001b[0m], \u001b[1mHTML5\u001b[0m, \u001b[1mHTTPServer\u001b[0m[\u001b[1m\u001b[36mcloudflare\u001b[0m], \u001b[1mIP\u001b[0m[\u001b[0m\u001b[22m104.21.32.202\u001b[0m], \u001b[1mScript\u001b[0m, \u001b[1mTitle\u001b[0m[\u001b[1m\u001b[33mAttention Required! | Cloudflare\u001b[0m], \u001b[1mUncommonHeaders\u001b[0m[\u001b[0m\u001b[22mreferrer-policy,report-to,nel,cf-ray,alt-svc\u001b[0m], \u001b[1mX-Frame-Options\u001b[0m[\u001b[0m\u001b[22mSAMEORIGIN\u001b[0m], \u001b[1mX-UA-Compatible\u001b[0m[\u001b[0m\u001b[22mIE=Edge\u001b[0m]\n", "stderr": ""}, "parsed_findings": []}
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

### external-tool-xsstrike — `<no-target>`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: {"meta": {"tool": "xsstrike", "status": "mocked_no_binary"}, "result": {"stdout": "mock output for xsstrike"}, "parsed_findings": []}
- **AI suggestion:**
  - predicted type: `xss` (confidence: 0.50)
  - explanation: heuristic
- **Recommended remediation (high level):**
  - Sanitize and encode untrusted input before rendering. Use context-specific encoding (HTML, JS, attribute). Implement CSP.

---

### external-tool-zmap — `<no-target>`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: {"meta": {"tool": "zmap", "status": "mocked_no_binary"}, "result": {"stdout": "mock output for zmap"}, "parsed_findings": []}
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

## Mapping diagnostics (auto-generated)

- mapping candidates processed: 0
- unmapped PoCs: 0


---

Generated by pentest pipeline — curated output.
