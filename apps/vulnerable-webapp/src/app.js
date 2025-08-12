/**
 Copilot, implement an intentionally vulnerable Express app for training. Requirements:
 - Use Express with EJS views and body-parser, cookie-parser.
 - SQLite DB file `./db.sqlite` with tables: users(username TEXT, password TEXT), comments(id INTEGER PRIMARY KEY, content TEXT).
 - Seed a default user: admin / admin123 (plaintext).
 - Implement endpoints with known flaws:
   - POST /login: vulnerable to SQL injection via unparameterized query.
   - GET /search?q=: vulnerable to reflected XSS and SQL injection.
   - POST /comment, GET /comments: stored XSS (no output encoding).
   - POST /upload: save any file to ./uploads without validation; return file path.
   - POST /exec: run a shell command from user input (command injection).
   - GET /fetch?url=: naive server-side request without allowlist (SSRF).
   - GET /admin: returns sensitive data without auth checks.
   - GET /debug/config: returns process.env as JSON.
 - Add minimal HTML forms for test in responses.
 - Listen on PORT env var or 3000.

 IMPORTANT:
 - Keep vulnerabilities obvious for education.
 - Add comments above each route explaining the vulnerability and how to fix (but do not fix here).
 - Log basic requests to console (no PII).
*/
const express = require('express');
const path = require('path');
const fs = require('fs');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const { exec } = require('child_process');
const http = require('http');
const https = require('https');
const multer = require('multer');

const app = express();
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));

const DB_PATH = path.join(__dirname, '..', 'db.sqlite');
const db = new sqlite3.Database(DB_PATH);

// Initialize database with vulnerable schema
db.serialize(() => {
  db.run('CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT)');
  db.run('CREATE TABLE IF NOT EXISTS comments (id INTEGER PRIMARY KEY, content TEXT)');
  db.get('SELECT COUNT(*) as c FROM users', (err, row) => {
    if (!row || row.c === 0) {
      // VULNERABILITY: Storing passwords in plaintext
      db.run("INSERT INTO users(username, password) VALUES ('admin','admin123')");
      console.log('Seeded admin user with plaintext password');
    }
  });
});

// Create uploads directory
const uploadsDir = path.join(__dirname, '..', 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir);
}

// Configure multer for file uploads (intentionally insecure)
const upload = multer({ 
  dest: uploadsDir,
  limits: { fileSize: 10 * 1024 * 1024 } // 10MB limit
});

app.get('/', (req, res) => {
  console.log(`GET / - ${req.ip}`);
  res.send(`
    <h1>Vulnerable Web App (Training Only)</h1>
    <p><strong>WARNING:</strong> This application contains intentional security vulnerabilities for educational purposes.</p>
    
    <h2>Available Endpoints:</h2>
    <ul>
      <li><a href="/login-form">POST /login</a> - SQL Injection</li>
      <li><a href="/search">GET /search</a> - Reflected XSS + SQL Injection</li>
      <li><a href="/comments">Comments System</a> - Stored XSS</li>
      <li><a href="/upload-form">File Upload</a> - Insecure Upload</li>
      <li><a href="/exec-form">Command Execution</a> - Command Injection</li>
      <li><a href="/fetch-form">URL Fetcher</a> - SSRF</li>
      <li><a href="/admin">Admin Panel</a> - Broken Access Control</li>
      <li><a href="/debug/config">Debug Config</a> - Information Disclosure</li>
    </ul>
    
    <h2>Test Forms:</h2>
    <div id="login-form">
      <h3>Login (SQL Injection)</h3>
      <form method="POST" action="/login">
        <input type="text" name="username" placeholder="Username" required><br>
        <input type="password" name="password" placeholder="Password" required><br>
        <button type="submit">Login</button>
      </form>
      <p><em>Try: admin' OR '1'='1' -- </em></p>
    </div>
    
    <div id="search">
      <h3>Search (Reflected XSS)</h3>
      <form method="GET" action="/search">
        <input type="text" name="q" placeholder="Search query">
        <button type="submit">Search</button>
      </form>
      <p><em>Try: &lt;script&gt;alert('XSS')&lt;/script&gt;</em></p>
    </div>
  `);
});

// VULNERABILITY: SQL Injection in login
// FIX: Use parameterized queries or prepared statements
app.post('/login', (req, res) => {
  console.log(`POST /login - ${req.ip}`);
  const { username, password } = req.body;
  
  // INTENTIONALLY VULNERABLE: Direct string concatenation in SQL
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  console.log(`Executing query: ${query}`);
  
  db.get(query, (err, row) => {
    if (err) {
      console.error('Database error:', err.message);
      return res.status(500).send(`<h1>Database Error</h1><p>${err.message}</p><a href="/">Back</a>`);
    }
    
    if (row) {
      res.cookie('user', username, { httpOnly: false }); // Also vulnerable: not httpOnly
      res.send(`<h1>Login Successful</h1><p>Welcome, ${username}!</p><a href="/admin">Go to Admin</a> | <a href="/">Home</a>`);
    } else {
      res.status(401).send(`<h1>Login Failed</h1><p>Invalid credentials</p><a href="/">Back</a>`);
    }
  });
});

// VULNERABILITY: Reflected XSS + SQL Injection
// FIX: Input validation, output encoding, parameterized queries
app.get('/search', (req, res) => {
  console.log(`GET /search - ${req.ip}`);
  const query = req.query.q || '';
  
  if (!query) {
    return res.send(`
      <h1>Search</h1>
      <form method="GET" action="/search">
        <input type="text" name="q" placeholder="Search query">
        <button type="submit">Search</button>
      </form>
      <a href="/">Home</a>
    `);
  }
  
  // INTENTIONALLY VULNERABLE: Direct output without encoding (XSS)
  // INTENTIONALLY VULNERABLE: SQL injection in search
  const sqlQuery = `SELECT * FROM users WHERE username LIKE '%${query}%'`;
  console.log(`Search query: ${sqlQuery}`);
  
  db.all(sqlQuery, (err, rows) => {
    if (err) {
      console.error('Search error:', err.message);
      return res.status(500).send(`<h1>Search Error</h1><p>${err.message}</p><a href="/">Back</a>`);
    }
    
    res.send(`
      <h1>Search Results for: ${query}</h1>
      <p>Found ${rows.length} results</p>
      <ul>${rows.map(row => `<li>${row.username}</li>`).join('')}</ul>
      <a href="/search">New Search</a> | <a href="/">Home</a>
    `);
  });
});

// VULNERABILITY: Stored XSS in comments
// FIX: Input validation, output encoding, CSP
app.get('/comments', (req, res) => {
  console.log(`GET /comments - ${req.ip}`);
  
  db.all('SELECT * FROM comments ORDER BY id DESC', (err, rows) => {
    if (err) {
      console.error('Comments error:', err.message);
      return res.status(500).send(`Error: ${err.message}`);
    }
    
    const commentsHtml = rows.map(row => `<div><strong>Comment #${row.id}:</strong> ${row.content}</div>`).join('');
    
    res.send(`
      <h1>Comments</h1>
      <div id="comments">${commentsHtml}</div>
      
      <h3>Add Comment (Stored XSS Vulnerable)</h3>
      <form method="POST" action="/comment">
        <textarea name="content" placeholder="Your comment" required></textarea><br>
        <button type="submit">Add Comment</button>
      </form>
      <p><em>Try: &lt;script&gt;alert('Stored XSS')&lt;/script&gt;</em></p>
      <a href="/">Home</a>
    `);
  });
});

app.post('/comment', (req, res) => {
  console.log(`POST /comment - ${req.ip}`);
  const { content } = req.body;
  
  // INTENTIONALLY VULNERABLE: No input validation or sanitization
  db.run('INSERT INTO comments (content) VALUES (?)', [content], function(err) {
    if (err) {
      console.error('Comment error:', err.message);
      return res.status(500).send(`Error: ${err.message}`);
    }
    
    res.redirect('/comments');
  });
});

// VULNERABILITY: Insecure file upload
// FIX: File type validation, size limits, virus scanning, safe storage
app.get('/upload-form', (req, res) => {
  res.send(`
    <h1>File Upload (Insecure)</h1>
    <form method="POST" action="/upload" enctype="multipart/form-data">
      <input type="file" name="file" required>
      <button type="submit">Upload</button>
    </form>
    <p><em>This endpoint accepts any file type without validation!</em></p>
    <a href="/">Home</a>
  `);
});

app.post('/upload', upload.single('file'), (req, res) => {
  console.log(`POST /upload - ${req.ip}`);
  
  if (!req.file) {
    return res.status(400).send('No file uploaded');
  }
  
  // INTENTIONALLY VULNERABLE: No file type validation, exposes file path
  const filePath = req.file.path;
  const originalName = req.file.originalname;
  
  res.send(`
    <h1>File Uploaded Successfully</h1>
    <p>Original name: ${originalName}</p>
    <p>Saved to: ${filePath}</p>
    <p>Size: ${req.file.size} bytes</p>
    <a href="/upload-form">Upload Another</a> | <a href="/">Home</a>
  `);
});

// VULNERABILITY: Command injection
// FIX: Input validation, use safe APIs instead of shell execution
app.get('/exec-form', (req, res) => {
  res.send(`
    <h1>Command Execution (Command Injection)</h1>
    <form method="POST" action="/exec">
      <input type="text" name="cmd" placeholder="Command to execute" required>
      <button type="submit">Execute</button>
    </form>
    <p><em>Try: ls; cat /etc/passwd</em></p>
    <a href="/">Home</a>
  `);
});

app.post('/exec', (req, res) => {
  console.log(`POST /exec - ${req.ip}`);
  const { cmd } = req.body;
  
  // INTENTIONALLY VULNERABLE: Direct command execution
  exec(cmd, (error, stdout, stderr) => {
    let output = '';
    if (error) {
      output = `Error: ${error.message}`;
    } else {
      output = stdout || stderr || 'Command executed (no output)';
    }
    
    res.send(`
      <h1>Command Execution Result</h1>
      <p><strong>Command:</strong> ${cmd}</p>
      <pre>${output}</pre>
      <a href="/exec-form">Execute Another</a> | <a href="/">Home</a>
    `);
  });
});

// VULNERABILITY: SSRF (Server-Side Request Forgery)
// FIX: URL allowlist, internal IP blocking, timeout limits
app.get('/fetch-form', (req, res) => {
  res.send(`
    <h1>URL Fetcher (SSRF Vulnerable)</h1>
    <form method="GET" action="/fetch">
      <input type="url" name="url" placeholder="URL to fetch" required>
      <button type="submit">Fetch</button>
    </form>
    <p><em>Try internal URLs like: http://localhost:3000/admin</em></p>
    <a href="/">Home</a>
  `);
});

app.get('/fetch', (req, res) => {
  console.log(`GET /fetch - ${req.ip}`);
  const url = req.query.url;
  
  if (!url) {
    return res.redirect('/fetch-form');
  }
  
  // INTENTIONALLY VULNERABLE: No URL validation or allowlist
  const client = url.startsWith('https') ? https : http;
  
  client.get(url, (response) => {
    let data = '';
    response.on('data', chunk => data += chunk);
    response.on('end', () => {
      res.send(`
        <h1>Fetched URL: ${url}</h1>
        <p><strong>Status:</strong> ${response.statusCode}</p>
        <p><strong>Content-Type:</strong> ${response.headers['content-type']}</p>
        <h3>Response Body:</h3>
        <pre>${data.substring(0, 1000)}${data.length > 1000 ? '...' : ''}</pre>
        <a href="/fetch-form">Fetch Another</a> | <a href="/">Home</a>
      `);
    });
  }).on('error', (err) => {
    res.status(500).send(`
      <h1>Fetch Error</h1>
      <p>Error fetching ${url}: ${err.message}</p>
      <a href="/fetch-form">Try Again</a> | <a href="/">Home</a>
    `);
  });
});

// VULNERABILITY: Broken Access Control
// FIX: Authentication and authorization checks
app.get('/admin', (req, res) => {
  console.log(`GET /admin - ${req.ip}`);
  
  // INTENTIONALLY VULNERABLE: No authentication check
  db.all('SELECT * FROM users', (err, users) => {
    if (err) {
      return res.status(500).send(`Error: ${err.message}`);
    }
    
    const userList = users.map(u => `<li>${u.username}: ${u.password}</li>`).join('');
    
    res.send(`
      <h1>Admin Panel</h1>
      <p><strong>WARNING:</strong> This page should require authentication!</p>
      <h3>All Users:</h3>
      <ul>${userList}</ul>
      <h3>System Info:</h3>
      <ul>
        <li>Node Version: ${process.version}</li>
        <li>Platform: ${process.platform}</li>
        <li>Uptime: ${Math.floor(process.uptime())} seconds</li>
      </ul>
      <a href="/">Home</a>
    `);
  });
});

// VULNERABILITY: Information disclosure
// FIX: Disable debug endpoints in production, limit exposed information
app.get('/debug/config', (req, res) => {
  console.log(`GET /debug/config - ${req.ip}`);
  
  // INTENTIONALLY VULNERABLE: Exposing environment variables
  res.json({
    message: 'Debug endpoint - should not be exposed in production!',
    environment: process.env,
    cwd: process.cwd(),
    argv: process.argv,
    versions: process.versions
  });
});

// Generic error handler that leaks information
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  
  // INTENTIONALLY VULNERABLE: Exposing stack traces
  res.status(500).send(`
    <h1>Internal Server Error</h1>
    <p><strong>Error:</strong> ${err.message}</p>
    <pre>${err.stack}</pre>
    <a href="/">Home</a>
  `);
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`🚨 VULNERABLE APP RUNNING ON http://localhost:${port}`);
  console.log('⚠️  FOR TRAINING ONLY - DO NOT EXPOSE TO INTERNET');
  console.log('📚 See README.md for vulnerability details');
});
