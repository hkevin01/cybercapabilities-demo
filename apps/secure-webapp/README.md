# Secure Web App

Implements secure counterparts for the vulnerable app:
- Parameterized queries, ORM or prepared statements
- Input validation (Zod), output encoding
- CSRF strategy (token or same-site), session cookies secure/HttpOnly
- Helmet, HPP, rate limiting, CORS hardening
- SSRF allowlist, file upload validation, size/type restrictions
- Least-privilege access control, authZ guard on /admin
- Centralized error handling with safe messages
- Security headers and CSP

See comments in `src/app.js` for callouts to OWASP ASVS/Top 10.
