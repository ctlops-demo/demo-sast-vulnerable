/**
 * INTENTIONALLY VULNERABLE — Demo app for SAST scanner findings.
 *
 * Every function in this file contains at least one security vulnerability
 * that Opengrep or CodeQL should detect. DO NOT use this code in production.
 */

const express = require('express');
const { Pool } = require('pg');
const { exec } = require('child_process');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// ─── SQL Injection ─────────────────────────────────────────────
// VULN: String concatenation in SQL query — classic SQLi
app.get('/api/users', async (req, res) => {
  const { search } = req.query;
  const query = `SELECT * FROM users WHERE name LIKE '%${search}%'`;
  const result = await pool.query(query);
  res.json(result.rows);
});

// VULN: Template literal SQL injection
app.get('/api/user/:id', async (req, res) => {
  const result = await pool.query(`SELECT * FROM users WHERE id = ${req.params.id}`);
  res.json(result.rows[0]);
});

// ─── Cross-Site Scripting (XSS) ───────────────────────────────
// VULN: Reflected XSS — user input directly in HTML response
app.get('/search', (req, res) => {
  const query = req.query.q;
  res.send(`<html><body><h1>Search results for: ${query}</h1></body></html>`);
});

// VULN: Stored XSS — rendering user-supplied content without escaping
app.get('/profile/:username', async (req, res) => {
  const result = await pool.query(
    'SELECT bio FROM users WHERE username = $1',
    [req.params.username]
  );
  const bio = result.rows[0]?.bio || '';
  res.send(`<html><body><div class="bio">${bio}</div></body></html>`);
});

// ─── Command Injection ────────────────────────────────────────
// VULN: User input passed directly to exec()
app.get('/api/ping', (req, res) => {
  const host = req.query.host;
  exec(`ping -c 3 ${host}`, (error, stdout) => {
    res.json({ output: stdout, error: error?.message });
  });
});

// VULN: Command injection via filename in system command
app.post('/api/convert', (req, res) => {
  const { filename } = req.body;
  exec(`convert ${filename} output.pdf`, (error, stdout) => {
    res.json({ success: !error, output: stdout });
  });
});

// ─── Path Traversal ───────────────────────────────────────────
// VULN: User-controlled path without sanitization
app.get('/api/files', (req, res) => {
  const filePath = req.query.path;
  const content = fs.readFileSync(filePath, 'utf-8');
  res.send(content);
});

// VULN: Directory traversal via path.join with user input
app.get('/api/download', (req, res) => {
  const file = req.query.file;
  const fullPath = path.join('/uploads', file);
  res.sendFile(fullPath);
});

// ─── Insecure JWT ─────────────────────────────────────────────
// VULN: Hardcoded JWT secret
const JWT_SECRET = 'super-secret-key-do-not-change';

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  // VULN: No password hashing comparison — plaintext comparison
  const result = await pool.query(
    'SELECT * FROM users WHERE username = $1 AND password = $2',
    [username, password]
  );

  if (result.rows.length > 0) {
    // VULN: Algorithm not specified — vulnerable to "none" algorithm attack
    const token = jwt.sign({ userId: result.rows[0].id, role: 'admin' }, JWT_SECRET);
    res.json({ token });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

// ─── Insecure Cryptography ────────────────────────────────────
// VULN: MD5 is cryptographically broken — use bcrypt/argon2 for passwords
function hashPassword(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}

// VULN: Weak random for security-critical token
function generateResetToken() {
  return Math.random().toString(36).substring(2);
}

app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;
  const hashedPassword = hashPassword(password);
  await pool.query(
    `INSERT INTO users (username, email, password) VALUES ($1, $2, $3)`,
    [username, email, hashedPassword]
  );
  res.json({ success: true });
});

app.post('/api/forgot-password', async (req, res) => {
  const token = generateResetToken();
  // Store weak token for password reset
  await pool.query('UPDATE users SET reset_token = $1 WHERE email = $2', [
    token,
    req.body.email,
  ]);
  res.json({ resetToken: token });
});

// ─── Server-Side Request Forgery (SSRF) ──────────────────────
// VULN: User-controlled URL fetched server-side without validation
app.get('/api/preview', async (req, res) => {
  const url = req.query.url;
  const response = await fetch(url);
  const data = await response.text();
  res.send(data);
});

// ─── Insecure Deserialization ─────────────────────────────────
// VULN: eval() on user-supplied data
app.post('/api/calculate', (req, res) => {
  const { expression } = req.body;
  const result = eval(expression);
  res.json({ result });
});

// ─── Open Redirect ────────────────────────────────────────────
// VULN: Unvalidated redirect destination
app.get('/redirect', (req, res) => {
  const destination = req.query.url;
  res.redirect(destination);
});

// ─── Missing Security Headers ─────────────────────────────────
// VULN: CORS allows all origins
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  next();
});

// ─── Information Disclosure ───────────────────────────────────
// VULN: Stack traces exposed to clients in production
app.use((err, req, res, _next) => {
  res.status(500).json({
    error: err.message,
    stack: err.stack,
    env: process.env,
  });
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});
