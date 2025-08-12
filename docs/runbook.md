# Demo Runbook

Checklist (10–15 minutes):
1. make re-build (build RE binaries)
2. docker compose up -d (start both apps)
3. Open http://localhost:3000 and demonstrate:
   - SQLi with ' OR '1'='1
   - Reflected/Stored XSS
   - Insecure upload and command injection
   - SSRF /fetch to http://localhost:3000
4. Run make dast and show ZAP report in analysis/dast
5. Open http://localhost:3001 and contrast:
   - Login (rate limit), safe search and comments
   - Validated upload
   - Safe exec (list/read), SSRF allowlist
   - /admin requires auth
6. Run make sast and make sca; correlate findings with code
7. Close with docs/briefings and docs/reports templates
