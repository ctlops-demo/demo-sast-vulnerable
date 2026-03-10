# Demo SAST Vulnerable App

This is a multi-language application with **intentionally vulnerable code** for testing Brigs SAST scanner integration (Opengrep, CodeQL, Deep Code Analysis).

## Languages & Files

| File | Language | Purpose |
|------|----------|---------|
| `src/server.js` | JavaScript | Express web server with injection, XSS, SSRF, path traversal |
| `src/utils.py` | Python | Utility module with SQLi, command injection, pickle, SSTI, XXE |
| `src/handlers.go` | Go | HTTP handlers with SQLi, XSS, command injection, SSRF |

## Intentional Vulnerabilities

| Vulnerability | Language | OWASP | CWE |
|---|---|---|---|
| SQL Injection (string concat) | JS, Python, Go | A03:2021 | CWE-89 |
| Cross-Site Scripting (reflected + stored) | JS, Go | A03:2021 | CWE-79 |
| Command Injection (exec/system) | JS, Python, Go | A03:2021 | CWE-78 |
| Path Traversal | JS, Python, Go | A01:2021 | CWE-22 |
| SSRF (user-controlled URL) | JS, Python, Go | A10:2021 | CWE-918 |
| Insecure Deserialization (eval/pickle/yaml.load) | JS, Python | A08:2021 | CWE-502 |
| Weak Cryptography (MD5/SHA1 for passwords) | JS, Python | A02:2021 | CWE-327 |
| Hardcoded Credentials | JS, Python | A07:2021 | CWE-798 |
| Open Redirect | JS, Go | A01:2021 | CWE-601 |
| Server-Side Template Injection | Python | A03:2021 | CWE-94 |
| XXE (XML External Entities) | Python | A05:2021 | CWE-611 |
| Information Disclosure (stack traces) | JS, Go | A01:2021 | CWE-209 |

## Expected Brigs Behavior

1. **Detection**: `SAST_COVERAGE` control should flag multiple CRITICAL + HIGH findings via Opengrep/CodeQL
2. **Deep Code Analysis**: LLM-powered analysis should identify additional semantic issues beyond regex-based rules
3. **Remediation**: Findings link to source lines with suggested fixes

## Controls Triggered

| Control | Expected Finding |
|---|---|
| `SAST_COVERAGE` | Multiple CRITICAL + HIGH findings from Opengrep/CodeQL |
| `SECRETS_IN_CODE` | Hardcoded API keys and database passwords |

## DO NOT USE IN PRODUCTION

This app exists solely for testing purposes. All vulnerabilities are intentional.
