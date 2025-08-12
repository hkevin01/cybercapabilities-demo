# Cybersecurity Capabilities Demo

This repository demonstrates end-to-end security engineering capabilities:
- Software assurance (SAST, SCA, DAST) with reports
- Secure web development and OWASP Top 10 countermeasures
- Reverse engineering (static/dynamic) of a benign C challenge binary
- Risk reporting, briefings, knowledge transfer

Contents:
- `apps/vulnerable-webapp` — intentionally vulnerable Node/Express app
- `apps/secure-webapp` — hardened equivalent with best practices
- `apps/reverse-engineering` — C challenge and analysis artifacts
- `analysis/` — outputs from SAST/DAST/SCA
- `docs/` — threat models, report templates, briefings
- `tooling/` — configs and helper scripts
- `.github/workflows` — CI: CodeQL, Semgrep, ZAP, Trivy, Gitleaks

Quick start:
1. Prereqs: Docker, Docker Compose, Node 20+, Python 3.11+ (optional), Git
2. Install tooling: `make setup`
3. Run SAST locally: `make sast`
4. Launch vulnerable app: `make up` then browse http://localhost:3000
5. Run DAST locally (ZAP baseline): `make dast`
6. Build and analyze RE challenge: `make re-build`

Notes:
- For training only. Do not expose the vulnerable app to the internet.
- Map to OWASP Top 10 is documented in `apps/vulnerable-webapp/README.md`.
