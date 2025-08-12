# Threat Model: Vulnerable Web App

Scope:
- Application: apps/vulnerable-webapp (training-only)
- Assets: credentials, comments data, uploaded files

Method: STRIDE per component
- Spoofing: Missing auth on /admin
- Tampering: SQL injection in /login, /search
- Repudiation: Insufficient logging
- Information Disclosure: /debug/config leaks env
- Denial of Service: No rate limits
- Elevation of Privilege: Broken access control on admin routes

Controls (missing by design in vulnerable app):
- AuthN/Z (role-based)
- Input validation and parameterized queries
- Output encoding and CSP
- SSRF allowlist
- Secure upload handling
- Rate limiting, HPP, security headers

Risk Rating:
- Use OWASP Risk Rating Methodology.
