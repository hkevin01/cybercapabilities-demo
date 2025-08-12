# Secure Development Guide

This repository demonstrates secure development practices through a comparison of vulnerable vs. secure implementations, showing how to mitigate common security issues.

## 🔒 Security-First Development

### OWASP Top 10 Mitigations

#### A01: Broken Access Control
**Vulnerable Implementation:**
```javascript
// No authentication check
app.get('/admin', (req, res) => {
  // Direct access to sensitive data
  res.send(sensitive_data);
});
```

**Secure Implementation:**
```javascript
// Authentication middleware
function requireAuth(req, res, next) {
  const sessionId = req.cookies.sessionId;
  // Validate session and check permissions
}

app.get('/admin', requireAuth, requireRole('admin'), (req, res) => {
  // Protected access with proper authorization
});
```

#### A03: Injection
**Vulnerable Implementation:**
```javascript
// Direct string concatenation - SQL injection
const query = `SELECT * FROM users WHERE username = '${username}'`;
db.query(query);
```

**Secure Implementation:**
```javascript
// Parameterized queries
const query = 'SELECT * FROM users WHERE username = ?';
db.query(query, [username]);
```

### Input Validation Framework

#### Validation Strategy
```javascript
const { z } = require('zod');

// Schema-based validation
const loginSchema = z.object({
  username: z.string().min(1).max(50).regex(/^[a-zA-Z0-9_]+$/),
  password: z.string().min(8).max(100)
});

// Validation middleware
function validateInput(schema) {
  return (req, res, next) => {
    try {
      req.validated = schema.parse(req.body);
      next();
    } catch (error) {
      return res.status(400).json({ error: error.errors });
    }
  };
}
```

#### Sanitization and Encoding
```javascript
// Output encoding for XSS prevention
function htmlEncode(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

// Safe template rendering
res.send(`<h1>Welcome ${htmlEncode(username)}</h1>`);
```

## 🛡️ Security Controls Implementation

### Security Headers
```javascript
const helmet = require('helmet');

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"]
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));
```

### Rate Limiting
```javascript
const { RateLimiterMemory } = require('rate-limiter-flexible');

const rateLimiter = new RateLimiterMemory({
  keyPrefix: 'middleware',
  points: 100, // requests
  duration: 60, // per 60 seconds
});

const loginRateLimiter = new RateLimiterMemory({
  keyPrefix: 'login_fail',
  points: 5, // attempts
  duration: 300, // per 5 minutes
});
```

### Session Management
```javascript
// Secure session configuration
app.use((req, res, next) => {
  res.cookie = ((originalCookie) => {
    return function(name, value, options = {}) {
      options.httpOnly = true;
      options.secure = process.env.NODE_ENV === 'production';
      options.sameSite = 'Lax';
      options.maxAge = options.maxAge || 3600000; // 1 hour
      return originalCookie.call(this, name, value, options);
    };
  })(res.cookie);
  next();
});
```

## 🔐 Cryptographic Best Practices

### Password Hashing
```javascript
const crypto = require('crypto');

function hashPassword(password, salt = crypto.randomBytes(32).toString('hex')) {
  const hash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
  return { hash, salt };
}

function verifyPassword(password, hash, salt) {
  const verifyHash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(verifyHash));
}
```

### Secure Random Generation
```javascript
// Session ID generation
const sessionId = crypto.randomBytes(32).toString('hex');

// CSRF token generation
const csrfToken = crypto.randomBytes(16).toString('base64');

// API key generation
const apiKey = crypto.randomBytes(32).toString('base64url');
```

## 🔍 Security Testing Integration

### Unit Tests for Security
```javascript
describe('Authentication', () => {
  test('should reject SQL injection attempts', async () => {
    const maliciousInput = "admin' OR '1'='1' --";
    const response = await request(app)
      .post('/login')
      .send({ username: maliciousInput, password: 'test' });
    
    expect(response.status).toBe(401);
  });

  test('should sanitize XSS in output', async () => {
    const xssPayload = '<script>alert("xss")</script>';
    const response = await request(app)
      .get('/search')
      .query({ q: xssPayload });
    
    expect(response.text).not.toContain('<script>');
    expect(response.text).toContain('&lt;script&gt;');
  });
});
```

### Security Linting
```javascript
// .eslintrc.js security rules
module.exports = {
  extends: ['eslint:recommended', 'plugin:security/recommended'],
  plugins: ['security'],
  rules: {
    'security/detect-object-injection': 'error',
    'security/detect-non-literal-regexp': 'error',
    'security/detect-unsafe-regex': 'error',
    'security/detect-buffer-noassert': 'error',
    'security/detect-child-process': 'error',
    'security/detect-disable-mustache-escape': 'error',
    'security/detect-eval-with-expression': 'error',
    'security/detect-no-csrf-before-method-override': 'error',
    'security/detect-non-literal-fs-filename': 'error',
    'security/detect-non-literal-require': 'error',
    'security/detect-possible-timing-attacks': 'error',
    'security/detect-pseudoRandomBytes': 'error'
  }
};
```

## 📋 Secure Code Review Checklist

### Authentication & Authorization
- [ ] All sensitive endpoints require authentication
- [ ] Role-based access control implemented
- [ ] Session management follows best practices
- [ ] Password policies enforced
- [ ] Multi-factor authentication considered

### Input Validation
- [ ] All user inputs validated and sanitized
- [ ] Schema-based validation implemented
- [ ] File upload restrictions in place
- [ ] SQL injection prevention measures
- [ ] Command injection protections

### Output Encoding
- [ ] XSS prevention through encoding
- [ ] Content Security Policy configured
- [ ] Safe templating practices
- [ ] JSON responses properly escaped

### Data Protection
- [ ] Sensitive data encrypted at rest
- [ ] HTTPS enforced for data in transit
- [ ] Database credentials secured
- [ ] API keys properly managed
- [ ] PII handling compliance

### Error Handling
- [ ] Generic error messages for users
- [ ] Detailed logging for security events
- [ ] Stack traces not exposed
- [ ] Failed login attempt monitoring

## 🚀 Development Workflow

### Pre-commit Security Checks
```bash
#!/bin/bash
# pre-commit hook

# Run security linting
npm run lint:security

# Check for secrets
git diff --cached --name-only | xargs grep -l "password\|key\|secret" && exit 1

# Run security tests
npm run test:security
```

### CI/CD Security Gates
```yaml
# Security pipeline stage
security:
  stage: test
  script:
    - npm run lint:security
    - npm audit --audit-level high
    - npm run test:security
  allow_failure: false
```

## 📊 Security Metrics

### Code Quality Metrics
- Security linting violations
- Test coverage for security functions
- Dependency vulnerability count
- Code review security findings

### Runtime Metrics
- Failed authentication attempts
- Rate limiting triggers
- Input validation failures
- Security header compliance

## 🔗 Related Documentation

- [Static Analysis (SAST)](SAST-ANALYSIS.md)
- [Dynamic Analysis (DAST)](DAST-ANALYSIS.md)
- [Software Composition Analysis (SCA)](SCA-ANALYSIS.md)
- [Threat Modeling](threat-models/vulnerable-app-threat-model.md)
