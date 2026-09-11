# Metasploitable2-security-audit
Vulnerability assessment, network enumeration, and defensive remediation report for Metasploitable 2
# Metasploitable 2 Security Assessment & Defensive Remediation Report

An end-to-end vulnerability assessment, source code security audit, and defensive engineering remediation report conducted against the Damn Vulnerable Web Application (DVWA) running on Metasploitable 2.

---

## Executive Summary & Vulnerability Matrix

| Vulnerability | Target Module | CWE | OWASP Top 10 | CVSS v3.1 | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **SQL Injection** | `/dvwa/vulnerabilities/sqli/` | CWE-89 | A03:2021 - Injection | **9.8** (Critical) | Remediated |
| **OS Command Injection** | `/dvwa/vulnerabilities/exec/` | CWE-78 | A03:2021 - Injection | **9.8** (Critical) | Remediated |
| **Reflected XSS** | `/dvwa/vulnerabilities/xss_r/` | CWE-79 | A03:2021 - Injection | **6.1** (Medium) | Remediated |
| **Stored XSS** | `/dvwa/vulnerabilities/xss_s/` | CWE-79 | A03:2021 - Injection | **7.2** (High) | Remediated |

---

## Detailed Vulnerability Reports

* **[SQL Injection Audit & Patch](docs/vulnerability_sqli.md)**
  * *Root Cause:* Dynamic SQL statement assembly via concatenation without parameter binding.
  * *Remediation:* PDO prepared statements with bound parameters (`PDO::prepare()`).
* **[OS Command Injection Audit & Patch](docs/vulnerability_command_injection.md)**
  * *Root Cause:* Passing untrusted input directly to `shell_exec()`.
  * *Remediation:* Strict IP whitelisting with `filter_var(FILTER_VALIDATE_IP)` and `escapeshellarg()`.
* **[Reflected Cross-Site Scripting Audit & Patch](docs/vulnerability_xss_reflected.md)**
  * *Root Cause:* Unescaped reflection of GET parameters directly into HTML context.
  * *Remediation:* Context-aware encoding via `htmlspecialchars(ENT_QUOTES, 'UTF-8')` and Content Security Policy (CSP).
* **[Stored Cross-Site Scripting Audit & Patch](docs/vulnerability_xss_stored.md)**
  * *Root Cause:* Unfiltered database persistence and unencoded guestbook output rendering.
  * *Remediation:* Dual-layer defense using `strip_tags()` and render-time `htmlspecialchars()` encoding.

---

## Repository Structure

```text
Metasploitable2-security-audit/
├── docs/
│   ├── vulnerability_sqli.md
│   ├── vulnerability_command_injection.md
│   ├── vulnerability_xss_reflected.md
│   └── vulnerability_xss_stored.md
├── evidence/
│   ├── nmap_initial_scan.txt
│   └── screenshots/
│       ├── sqli_finding.png
│       ├── sqli_dump.png
│       ├── command_exec_poc.png
│       ├── xss_reflected_poc.png
│       └── xss_stored_poc.png
├── remediation/
│   ├── secure_sqli_patch.php
│   ├── secure_command_exec_patch.php
│   ├── secure_xss_patch.php
│   └── secure_xss_stored_patch.php
└── README.md
