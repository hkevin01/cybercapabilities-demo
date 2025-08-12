/**
 Intentionally vulnerable Express app for training purposes.
 DO NOT DEPLOY.

 Vulnerabilities demonstrated (OWASP Top 10):
 - A01 Broken Access Control: /admin has no auth checks.
 - A03 Injection (SQLi): /login and /search use unparameterized queries.
 - XSS (Reflected/Stored): /search reflects, /comments stores unsanitized content.
 - A05 Security Misconfiguration: debug endpoint leaking env.
 - Command Injection: /exec executes user-supplied shell.
 - SSRF: /fetch retrieves arbitrary URLs without allowlist.
 - Insecure File Upload: /upload accepts any file, no validation.

 Each route includes a brief "how to fix" note in comments.
*/
const express = require('express');
const path = require('path');
const fs = require('fs');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const { exec } = require('child_process');
const multer = require('multer');

// Use built-in fetch (Node 18+) or require node-fetch
const fetch = globalThis.fetch || require('node-fetch');

const app = express();
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));

// DB setup
const DB_PATH = path.join(__dirname, '..', 'db.sqlite');
const db = new sqlite3.Database(DB_PATH);
db.serialize(() => {
  db.run('CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT)');
  db.run('CREATE TABLE IF NOT EXISTS comments (id INTEGER PRIMARY KEY, content TEXT)');
  db.get('SELECT COUNT(*) as c FROM users', (err, row) => {
    if (!row || row.c === 0) {
      db.run("INSERT INTO users(username, password) VALUES ('admin','admin123')");
      db.run("INSERT INTO users(username, password) VALUES ('user','password')");
    }
  });
});

const uploadsDir = path.join(__dirname, '..', 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
const upload = multer({ dest: uploadsDir });

// Index: simple forms to exercise endpoints
app.get('/', (req, res) => {
  res.send(`
    <h1>Vulnerable App (Training Only)</h1>
    <ul>
      <li><form method="POST" action="/login">
        <input name="username" placeholder="username">
        <input name="password" placeholder="password" type="password">
        <button type="submit">Login (SQLi)</button>
      </form></li>
      <li><form method="GET" action="/search">
        <input name="q" placeholder="Search term (XSS/SQLi)">
        <button type="submit">Search</button>
      </form></li>
      <li><form method="POST" action="/comment">
        <textarea name="content" placeholder="Comment (Stored XSS)"></textarea>
        <button type="submit">Post</button>
      </form> <a href="/comments">View comments</a></li>
      <li><form method="POST" action="/upload" enctype="multipart/form-data">
        <input type="file" name="file"><button>Upload (insecure)</button>
      </form></li>
      <li><form method="POST" action="/exec">
        <input name="cmd" placeholder="e.g., ls -la"><button>Exec (danger!)</button>
      </form></li>
      <li><form method="GET" action="/fetch">
        <input name="url" placeholder="http://127.0.0.1:3000"><button>Fetch (SSRF)</button>
      </form></li>
      <li><a href="/admin">/admin (no auth)</a></li>
      <li><a href="/debug/config">/debug/config (leaks env)</a></li>
    </ul>
  `);
});

// SQLi: unparameterized query
// Fix: use parameterized queries/prepared statements.
app.post('/login', (req, res) => {
  const { username = '', password = '' } = req.body || {};
  const q = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;
  db.get(q, (err, row) => {
    if (row) return res.send(`Welcome ${row.username}`);
    return res.status(401).send('Invalid credentials');
  });
});

// Reflected XSS + SQLi-like search (for demo: no real table)
// Fix: encode output, validate input, parameterize queries.
app.get('/search', (req, res) => {
  const q = req.query.q || '';
  // Intentionally reflect unsanitized 'q'
  res.send(`<h2>Results for: ${q}</h2><p>(No real search; this demonstrates reflected XSS.)</p>`);
});

// Stored XSS
// Fix: encode on output, validate/strip tags, use templating that escapes.
app.post('/comment', (req, res) => {
  const { content = '' } = req.body || {};
  db.run('INSERT INTO comments(content) VALUES (?)', [content], () => res.redirect('/comments'));
});
app.get('/comments', (req, res) => {
  db.all('SELECT id, content FROM comments ORDER BY id DESC', (e, rows) => {
    const html = rows
      .map((r) => `<li>#${r.id}: ${r.content}</li>`)
      .join('');
    res.send(`<h2>Comments (Stored XSS)</h2><ul>${html}</ul><a href="/">Back</a>`);
  });
});

// Insecure upload
// Fix: restrict types, scan, randomize names, store out of web root.
app.post('/upload', upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).send('No file');
  res.send(`Uploaded to ${req.file.path}`);
});

// Command injection
// Fix: never pass user input to shell; use safe APIs/allowlist.
app.post('/exec', (req, res) => {
  const { cmd = '' } = req.body || {};
  exec(cmd, { timeout: 3000 }, (err, stdout, stderr) => {
    if (err) return res.status(500).send(`Error: ${stderr || err.message}`);
    res.type('text/plain').send(stdout || '(no output)');
  });
});

// SSRF
// Fix: enforce allowlist and scheme checks; fetch server-side only to trusted hosts.
app.get('/fetch', async (req, res) => {
  const url = req.query.url;
  if (!url) return res.status(400).send('Missing url');
  try {
    const r = await fetch(url);
    const text = await r.text();
    res.type('text/plain').send(text.slice(0, 2000));
  } catch (e) {
    res.status(500).send(String(e));
  }
});

// Broken access control
// Fix: require authN/Z guard.
app.get('/admin', (req, res) => {
  db.all('SELECT username, password FROM users', (e, rows) => {
    res.json({ secret: 'This should be protected', users: rows });
  });
});

// Health check endpoint for monitoring
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    service: 'vulnerable-webapp',
    version: '1.0.0'
  });
});

// Debug config leak
// Fix: disable in prod; never return env values.
app.get('/debug/config', (req, res) => {
  res.json(process.env);
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Vulnerable app on http://localhost:${port}`));

module.exports = app; // for tests
