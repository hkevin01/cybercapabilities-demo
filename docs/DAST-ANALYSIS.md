# Dynamic Application Security Testing (DAST)

This repository demonstrates comprehensive DAST capabilities using industry-standard tools to identify runtime security vulnerabilities through automated penetration testing.

## 🎯 OWASP ZAP Integration

### ZAP Baseline Scan
- **Tool**: OWASP ZAP (Zed Attack Proxy)
- **Workflow**: `.github/workflows/zap-baseline.yml`
- **Configuration**: `tooling/configs/zap-baseline.conf`
- **Target**: Vulnerable web application on localhost:3000

### Scan Coverage
- **Authentication Testing**: Login bypass attempts
- **Input Validation**: SQL injection, XSS, command injection
- **Session Management**: Cookie security, session fixation
- **Authorization**: Privilege escalation, access control bypass
- **Information Disclosure**: Error handling, debug endpoints

## 🚀 Running DAST Analysis

### Local Execution
```bash
# Complete DAST workflow
make dast

# Manual ZAP scan
docker run --rm --network host \
  -v $(pwd)/tooling/configs:/zap/wrk/:rw \
  -v $(pwd)/analysis/dast:/zap/reports:rw \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://localhost:3000 \
  -r /zap/reports/zap-baseline.html \
  -J /zap/reports/zap-baseline.json
```

### CI/CD Integration
DAST runs on:
- Workflow dispatch (manual trigger)
- Pull requests (optional)
- Scheduled security testing

## 🔍 Vulnerability Detection

### Expected Findings

#### High Risk
- **SQL Injection**: POST /login endpoint
- **Command Injection**: POST /exec endpoint
- **SSRF**: GET /fetch endpoint

#### Medium Risk
- **Stored XSS**: POST /comment endpoint
- **Reflected XSS**: GET /search endpoint
- **Insecure File Upload**: POST /upload endpoint

#### Low Risk
- **Information Disclosure**: GET /debug/config
- **Missing Security Headers**: Various endpoints
- **Weak Session Management**: Cookie configuration

### Test Scenarios

#### Authentication Bypass
```bash
# SQL injection in login
curl -X POST http://localhost:3000/login \
  -d "username=admin' OR '1'='1' --&password=any"
```

#### Cross-Site Scripting
```bash
# Reflected XSS
curl "http://localhost:3000/search?q=<script>alert('XSS')</script>"

# Stored XSS
curl -X POST http://localhost:3000/comment \
  -d "content=<script>alert('Stored XSS')</script>"
```

#### Server-Side Request Forgery
```bash
# Internal network access
curl "http://localhost:3000/fetch?url=http://localhost:3000/admin"
```

## 📊 Results Analysis

### Report Formats
- **HTML Report**: `analysis/dast/zap-baseline.html`
- **JSON Report**: `analysis/dast/zap-baseline.json`
- **CI Artifacts**: Uploaded to GitHub Actions

### Risk Assessment
ZAP categorizes findings by:
- **Risk Level**: High, Medium, Low, Informational
- **Confidence**: High, Medium, Low
- **CWE Mapping**: Common Weakness Enumeration
- **OWASP Category**: Top 10 classification

## 🛡️ Remediation Validation

### Before vs After Testing
1. **Vulnerable App**: Full DAST scan reveals multiple issues
2. **Secure App**: Comparison scan shows mitigations working
3. **Diff Analysis**: Quantify security improvements

### Secure App Validation
The secure application (`apps/secure-webapp/`) demonstrates:
- Input validation preventing injection
- Output encoding preventing XSS
- Rate limiting preventing automated attacks
- SSRF protection with URL allowlists

## 🔧 Configuration Management

### ZAP Rules Configuration
```ini
# tooling/configs/zap-baseline.conf
# Ignore certain rules for demo purposes
10096 IGNORE  # Example: timestamp disclosure
```

### Custom Test Scripts
- **Authentication**: Automated login sequences
- **Session Handling**: Cookie management
- **Custom Payloads**: Application-specific tests

## 📈 Continuous Security Testing

### Integration Strategy
- **Feature Branches**: DAST on new code
- **Staging Environment**: Full security testing
- **Production**: Non-invasive monitoring

### Metrics Tracking
- Vulnerability trends over time
- Mean time to detection (MTTD)
- Mean time to remediation (MTTR)
- Security test coverage

## 🔗 Related Documentation

- [Static Analysis (SAST)](SAST-ANALYSIS.md)
- [Software Composition Analysis (SCA)](SCA-ANALYSIS.md)
- [Threat Modeling](threat-models/vulnerable-app-threat-model.md)
