# Static Application Security Testing (SAST)

This repository demonstrates comprehensive SAST capabilities using multiple industry-standard tools to identify security vulnerabilities in source code.

## 🔍 Tools Implemented

### CodeQL (GitHub Advanced Security)
- **Language Support**: JavaScript, Python, C/C++
- **Workflow**: `.github/workflows/codeql.yml`
- **Features**: 
  - Advanced semantic analysis
  - Custom query development capability
  - Integration with GitHub Security tab
  - Automated vulnerability detection

### Semgrep
- **Configuration**: `tooling/configs/semgrep.yml`
- **Rulesets**: OWASP Top 10, JavaScript security, secrets detection
- **Output**: JSON format to `analysis/sast/semgrep.json`
- **Custom Rules**: Extensible rule framework

### ESLint with Security Plugin
- **Configuration**: `tooling/configs/.eslintrc.cjs`
- **Plugin**: `eslint-plugin-security`
- **Scope**: Node.js applications in both vulnerable and secure apps

## 🎯 Vulnerability Detection

### Vulnerable Code Examples
The `apps/vulnerable-webapp/` contains intentional vulnerabilities for SAST detection:

- **SQL Injection**: Unparameterized queries in login/search endpoints
- **Command Injection**: Direct shell execution in `/exec` endpoint
- **XSS**: Unescaped output in search and comments
- **Path Traversal**: Unsafe file operations
- **Hardcoded Secrets**: Example credentials and tokens

### Python Security Issues
`apps/vulnerable-webapp/src/util_insecure.py` demonstrates:
- Shell injection via `subprocess.call` with `shell=True`
- Hardcoded secrets in environment variables
- Unsafe deserialization patterns

## 🚀 Running SAST Analysis

### Local Execution
```bash
# Run all SAST tools
make sast

# Individual tools
semgrep --config tooling/configs/semgrep.yml --error --json
npx eslint apps/vulnerable-webapp/src/
npx eslint apps/secure-webapp/src/
```

### CI/CD Integration
SAST runs automatically on:
- Every push to main branch
- Pull requests
- Scheduled weekly scans

### Results Location
- **Semgrep**: `analysis/sast/semgrep.json`
- **CodeQL**: GitHub Security tab (SARIF upload)
- **ESLint**: Console output and CI logs

## 📊 Expected Findings

### High Severity
- SQL Injection in login endpoint
- Command Injection in exec endpoint
- SSRF in fetch endpoint

### Medium Severity
- Stored XSS in comments
- Reflected XSS in search
- Insecure file upload

### Low/Info
- Missing security headers
- Weak session management
- Information disclosure

## 🛠️ Remediation Examples

Compare findings between:
- `apps/vulnerable-webapp/` (vulnerable implementation)
- `apps/secure-webapp/` (secure implementation with fixes)

The secure app demonstrates:
- Parameterized queries
- Input validation with Zod
- Output encoding
- Security headers with Helmet
- Rate limiting

## 📈 Metrics & Reporting

Track security improvements with:
- Vulnerability count trends
- Fix rates and timelines
- Coverage of security rules
- False positive rates

## 🔗 Related Documentation

- [Dynamic Analysis (DAST)](DAST-ANALYSIS.md)
- [Software Composition Analysis (SCA)](SCA-ANALYSIS.md)
- [Secure Development Guide](SECURE-DEVELOPMENT.md)
