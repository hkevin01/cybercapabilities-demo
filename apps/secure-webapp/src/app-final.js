/**
 Secure Express app: mitigations for each vulnerable feature.
 References: OWASP Top 10 (2021), OWASP ASVS controls.

 Highlights:
 - Security headers (Helmet + CSP), HPP, basic rate limiting.
 - sqlite3 with prepared statements (changed from better-sqlite3 for compatibility).
 - Input validation with Zod; output encoding via EJS (auto-escapes).
 - SSRF allowlist; safe "exec" via allowlisted operations (no shell).
 - Robust upload validation (type/size), randomized filenames.
 - AuthN/Z: signed cookie gate for /admin.
*/
const express = require('express');
const path = require('path');
const fs = require('fs');
const sqlite3 = require('sqlite3').verbose();
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const hpp = require('hpp');
const crypto = require('crypto');
const multer = require('multer');
const { RateLimiterMemory } = require('rate-limiter-flexible');
const { z } = require('zod');
const http = require('http');
const https = require('https');

const app = express();

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      "default-src": ["'self'"],
      "img-src": ["'self'", "data:"],
      "script-src": ["'self'"],
      "style-src": ["'self'", "'unsafe-inline'"]
    }
  }
}));
app.use(hpp());
app.disable('x-powered-by');
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

const COOKIE_SECRET = process.env.COOKIE_SECRET || 'dev-only-secret';
app.use(cookieParser(COOKIE_SECRET));

// Rate limiting (login)
const loginLimiter = new RateLimiterMemory({ points: 5, duration: 60 });

// Views
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// DB - using sqlite3 for compatibility
const DB_PATH = path.join(__dirname, '..', 'db.secure.sqlite');
const db = new sqlite3.Database(DB_PATH);

// Initialize database
db.serialize(() => {
  db.run('CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT)');
  db.run('CREATE TABLE IF NOT EXISTS comments (id INTEGER PRIMARY KEY, content TEXT)');
  db.get('SELECT COUNT(*) as c FROM users', (err, row) => {
    if (!row || row.c === 0) {
      db.run('INSERT INTO users(username, password) VALUES (?, ?)', ['admin', 'admin123']);
    }
  });
});

// Auth helpers
function setAuth(res, username) {
  res.cookie('auth', username, {
    httpOnly: true,
    sameSite: 'lax',
    secure: !!process.env.SECURE_COOKIES,
    signed: true,
    maxAge: 60 * 60 * 1000
  });
}
function requireAuth(req, res, next) {
  if (req.signedCookies && req.signedCookies.auth) return next();
  return res.status(401).send('Unauthorized');
}

// Index
app.get('/', (req, res) => {
  res.send(`<h1>Secure App</h1>
    <ul>
      <li>POST /login (rate-limited, parameterized)</li>
      <li>GET /search?q= (encoded output)</li>
      <li>POST /comment + GET /comments (encoded)</li>
      <li>POST /upload (validated)</li>
      <li>POST /exec (safe ops only)</li>
      <li>GET /fetch?url= (allowlist)</li>
      <li>GET /admin (auth required)</li>
    </ul>`);
});

// Login (parameterized + rate limit)
app.post('/login', async (req, res) => {
  try {
    await loginLimiter.consume(req.ip);
  } catch {
    return res.status(429).send('Too many attempts');
  }
  const schema = z.object({
    username: z.string().min(1).max(50),
    password: z.string().min(1).max(200)
  });
  const parsed = schema.safeParse(req.body || {});
  if (!parsed.success) return res.status(400).send('Invalid input');
  const { username, password } = parsed.data;
  
  db.get('SELECT username FROM users WHERE username = ? AND password = ?', [username, password], (err, row) => {
    if (err) return res.status(500).send('Database error');
    if (!row) return res.status(401).send('Invalid credentials');
    setAuth(res, username);
    res.send(`Welcome ${username}`);
  });
});

// Search (validated, safely rendered)
app.get('/search', (req, res) => {
  const schema = z.object({ q: z.string().max(200).optional().default('') });
  const { q } = schema.parse(req.query);
  res.render('search.ejs', { q });
});

// Comments (stored safe rendering)
app.post('/comment', (req, res) => {
  const schema = z.object({ content: z.string().min(1).max(2000) });
  const parsed = schema.safeParse(req.body || {});
  if (!parsed.success) return res.status(400).send('Invalid input');
  
  db.run('INSERT INTO comments(content) VALUES (?)', [parsed.data.content], (err) => {
    if (err) return res.status(500).send('Database error');
    res.redirect('/comments');
  });
});

app.get('/comments', (req, res) => {
  db.all('SELECT id, content FROM comments ORDER BY id DESC', (err, rows) => {
    if (err) return res.status(500).send('Database error');
    res.render('comments.ejs', { rows });
  });
});

// Upload (validate mime/size, randomize filename)
const uploadsDir = path.join(__dirname, '..', 'uploads-secure');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
const storage = multer.diskStorage({
  destination: uploadsDir,
  filename: (req, file, cb) => cb(null, crypto.randomBytes(12).toString('hex') + path.extname(file.originalname))
});
const allowed = new Set(['image/png', 'image/jpeg', 'text/plain']);
const upload = multer({
  storage,
  limits: { fileSize: 1 * 1024 * 1024 }, // 1MB
  fileFilter: (req, file, cb) => cb(null, allowed.has(file.mimetype))
});
app.post('/upload', upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).send('Invalid file');
  res.send(`Uploaded safely: ${req.file.filename}`);
});

// Safe exec emulation (no shell)
const OPS = {
  list: () => fs.readdirSync(uploadsDir).slice(0, 50),
  read: (f) => {
    const name = path.basename(f);
    const target = path.join(uploadsDir, name);
    if (!fs.existsSync(target)) return '(not found)';
    return fs.readFileSync(target, 'utf8').slice(0, 2000);
  }
};
app.post('/exec', (req, res) => {
  const schema = z.object({ op: z.enum(['list', 'read']), arg: z.string().optional() });
  const parsed = schema.safeParse(req.body || {});
  if (!parsed.success) return res.status(400).send('Invalid input');
  const { op, arg } = parsed.data;
  const out = op === 'list' ? OPS.list() : OPS.read(arg || '');
  res.json({ ok: true, result: out });
});

// SSRF allowlist (host + scheme)
const ALLOW_HOSTS = new Set((process.env.ALLOW_HOSTS || 'httpbin.org').split(',').map((s) => s.trim()));
app.get('/fetch', (req, res) => {
  const schema = z.object({ url: z.string().url() });
  const parsed = schema.safeParse(req.query);
  if (!parsed.success) return res.status(400).send('Invalid URL');
  try {
    const u = new URL(parsed.data.url);
    if (!['https:', 'http:'].includes(u.protocol) || !ALLOW_HOSTS.has(u.hostname)) {
      return res.status(400).send('Host not allowed');
    }
    const lib = u.protocol === 'https:' ? https : http;
    const req2 = lib.request(u, (r) => {
      res.status(r.statusCode || 200);
      r.pipe(res);
    });
    req2.on('error', (e) => res.status(502).send(String(e)));
    req2.end();
  } catch {
    res.status(400).send('Invalid URL');
  }
});

// Admin (requires auth)
app.get('/admin', requireAuth, (req, res) => {
  res.json({ secret: 'Only for authenticated users', user: req.signedCookies.auth });
});

const port = process.env.PORT || 3001;
app.listen(port, () => console.log(`Secure app on http://localhost:${port}`));

module.exports = app; // for tests
