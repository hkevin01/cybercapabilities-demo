# Vulnerable Web App (for training only)

Implements common OWASP Top 10 issues for demonstration:
- A01:2021-Broken Access Control — admin-only route without proper checks
- A03:2021-Injection — SQL injection in login/search
- A05:2021-Security Misconfiguration — debug endpoints, verbose errors
- A07:2021-Identification and Authentication Failures — weak session mgmt
- A08:2021-Software and Data Integrity Failures — unsafe deserialization
- A09:2021-Security Logging and Monitoring Failures — minimal logging
- A03 (Command Injection) — user-supplied command in utility
- A06:2021-Vulnerable and Outdated Components — documented in SCA
- XSS (Stored/Reflected) — comments feature
- SSRF — URL fetcher endpoint without allowlist
- Insecure file upload — missing content/type checks

Endpoints to implement (intentionally flawed) in `src/app.js`:
- `POST /login` (SQLi)
- `GET /search?q=` (reflected XSS + SQLi)
- `POST /comment` and `GET /comments` (stored XSS)
- `POST /upload` (insecure file upload to ./uploads)
- `POST /exec` (command injection via `ls`/`cat`)
- `GET /fetch?url=` (SSRF to arbitrary URL)
- `GET /admin` (no auth check)
- `GET /debug/config` (leaks env)

Warning: Do not deploy publicly.
