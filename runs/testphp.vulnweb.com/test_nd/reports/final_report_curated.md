# Curated Scan Report

- Run: `test_nd`
- Reports dir: `reports/`

## Summary

- Consolidated findings: **33**
- PoCs discovered (compact): **3**

---

### sqli-error — `http://testphp.vulnweb.com/search.php?test=query`
- **Severity:** 5
- **Occurrences merged:** 3
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: SQL syntax
- **Recommended remediation (high level):**
  - Use parameterized queries / prepared statements. Validate and escape inputs. Review DB permissions.

---

### sqli-error — `http://testphp.vulnweb.com/secured/newuser.php`
- **Severity:** 5
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - evidence: SQL syntax
- **Recommended remediation (high level):**
  - Use parameterized queries / prepared statements. Validate and escape inputs. Review DB permissions.

---

### xss-reflected — `http://testphp.vulnweb.com/guestbook.php`
- **Severity:** 4
- **Occurrences merged:** 3
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
- **Recommended remediation (high level):**
  - Sanitize and encode untrusted input before rendering. Use context-specific encoding (HTML, JS, attribute). Implement CSP.

---

### xss-reflected — `http://testphp.vulnweb.com/search.php?test=query`
- **Severity:** 4
- **Occurrences merged:** 2
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
- **Recommended remediation (high level):**
  - Sanitize and encode untrusted input before rendering. Use context-specific encoding (HTML, JS, attribute). Implement CSP.

---

### xss-reflected — `http://testphp.vulnweb.com/secured/newuser.php`
- **Severity:** 4
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
- **Recommended remediation (high level):**
  - Sanitize and encode untrusted input before rendering. Use context-specific encoding (HTML, JS, attribute). Implement CSP.

---

### xss-none — `http://testphp.vulnweb.com/hpp/params.php?p=valid&pp=12`
- **Severity:** 2
- **Occurrences merged:** 3
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
- **Recommended remediation (high level):**
  - Sanitize and encode untrusted input before rendering. Use context-specific encoding (HTML, JS, attribute). Implement CSP.

---

### sqli-none — `http://testphp.vulnweb.com/hpp/params.php?p=valid&pp=12`
- **Severity:** 2
- **Occurrences merged:** 3
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
- **Recommended remediation (high level):**
  - Use parameterized queries / prepared statements. Validate and escape inputs. Review DB permissions.

---

### xss-none — `http://testphp.vulnweb.com/`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
- **Recommended remediation (high level):**
  - Sanitize and encode untrusted input before rendering. Use context-specific encoding (HTML, JS, attribute). Implement CSP.

---

### sqli-none — `http://testphp.vulnweb.com/`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
- **Recommended remediation (high level):**
  - Use parameterized queries / prepared statements. Validate and escape inputs. Review DB permissions.

---

### xss-none — `http://testphp.vulnweb.com/artists.php?artist=1`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
- **Recommended remediation (high level):**
  - Sanitize and encode untrusted input before rendering. Use context-specific encoding (HTML, JS, attribute). Implement CSP.

---

### sqli-none — `http://testphp.vulnweb.com/artists.php?artist=1`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
- **Recommended remediation (high level):**
  - Use parameterized queries / prepared statements. Validate and escape inputs. Review DB permissions.

---

### xss-none — `http://testphp.vulnweb.com/artists.php?artist=2`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
- **Recommended remediation (high level):**
  - Sanitize and encode untrusted input before rendering. Use context-specific encoding (HTML, JS, attribute). Implement CSP.

---

### sqli-none — `http://testphp.vulnweb.com/artists.php?artist=2`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
- **Recommended remediation (high level):**
  - Use parameterized queries / prepared statements. Validate and escape inputs. Review DB permissions.

---

### xss-none — `http://testphp.vulnweb.com/artists.php?artist=3`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
- **Recommended remediation (high level):**
  - Sanitize and encode untrusted input before rendering. Use context-specific encoding (HTML, JS, attribute). Implement CSP.

---

### sqli-none — `http://testphp.vulnweb.com/artists.php?artist=3`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
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
- **Recommended remediation (high level):**
  - Sanitize and encode untrusted input before rendering. Use context-specific encoding (HTML, JS, attribute). Implement CSP.

---

### sqli-none — `http://testphp.vulnweb.com/guestbook.php`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
- **Recommended remediation (high level):**
  - Use parameterized queries / prepared statements. Validate and escape inputs. Review DB permissions.

---

### xss-none — `http://testphp.vulnweb.com/hpp/?pp=12`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
- **Recommended remediation (high level):**
  - Sanitize and encode untrusted input before rendering. Use context-specific encoding (HTML, JS, attribute). Implement CSP.

---

### sqli-none — `http://testphp.vulnweb.com/hpp/?pp=12`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
- **Recommended remediation (high level):**
  - Use parameterized queries / prepared statements. Validate and escape inputs. Review DB permissions.

---

### xss-none — `http://testphp.vulnweb.com/listproducts.php?cat=1`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
- **Recommended remediation (high level):**
  - Sanitize and encode untrusted input before rendering. Use context-specific encoding (HTML, JS, attribute). Implement CSP.

---

### sqli-none — `http://testphp.vulnweb.com/listproducts.php?cat=1`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
- **Recommended remediation (high level):**
  - Use parameterized queries / prepared statements. Validate and escape inputs. Review DB permissions.

---

### xss-none — `http://testphp.vulnweb.com/listproducts.php?cat=2`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
- **Recommended remediation (high level):**
  - Sanitize and encode untrusted input before rendering. Use context-specific encoding (HTML, JS, attribute). Implement CSP.

---

### sqli-none — `http://testphp.vulnweb.com/listproducts.php?cat=2`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
- **Recommended remediation (high level):**
  - Use parameterized queries / prepared statements. Validate and escape inputs. Review DB permissions.

---

### xss-none — `http://testphp.vulnweb.com/listproducts.php?cat=3`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
- **Recommended remediation (high level):**
  - Sanitize and encode untrusted input before rendering. Use context-specific encoding (HTML, JS, attribute). Implement CSP.

---

### sqli-none — `http://testphp.vulnweb.com/listproducts.php?cat=3`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
- **Recommended remediation (high level):**
  - Use parameterized queries / prepared statements. Validate and escape inputs. Review DB permissions.

---

### xss-none — `http://testphp.vulnweb.com/listproducts.php?cat=4`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
- **Recommended remediation (high level):**
  - Sanitize and encode untrusted input before rendering. Use context-specific encoding (HTML, JS, attribute). Implement CSP.

---

### sqli-none — `http://testphp.vulnweb.com/listproducts.php?cat=4`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
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
- **Recommended remediation (high level):**
  - Sanitize and encode untrusted input before rendering. Use context-specific encoding (HTML, JS, attribute). Implement CSP.

---

### sqli-none — `http://testphp.vulnweb.com/search.php?test=query`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
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
- **Recommended remediation (high level):**
  - Sanitize and encode untrusted input before rendering. Use context-specific encoding (HTML, JS, attribute). Implement CSP.

---

### sqli-none — `http://testphp.vulnweb.com/secured/newuser.php`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
- **Recommended remediation (high level):**
  - Use parameterized queries / prepared statements. Validate and escape inputs. Review DB permissions.

---

### xss-none — `http://testphp.vulnweb.com/userinfo.php`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
- **Recommended remediation (high level):**
  - Sanitize and encode untrusted input before rendering. Use context-specific encoding (HTML, JS, attribute). Implement CSP.

---

### sqli-none — `http://testphp.vulnweb.com/userinfo.php`
- **Severity:** 2
- **Occurrences merged:** 1
- **PoCs:** _none attached_
- **Examples / notes:**
  - (no compact excerpt available)
- **Recommended remediation (high level):**
  - Use parameterized queries / prepared statements. Validate and escape inputs. Review DB permissions.

---

## Mapping diagnostics (auto-generated)

- mapping candidates processed: 3
- unmapped PoCs: 0


---

Generated by pentest pipeline — curated output.
