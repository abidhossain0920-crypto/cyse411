// sqli-lab.js
// SQLi teaching lab (safe simulation). Run only on localhost.
// npm init -y
// npm i express body-parser
// node sqli-lab.js

const express = require('express');
const bodyParser = require('body-parser');
const app = express();
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

/*
 A tiny in-memory dataset to simulate DB rows.
 We intentionally use a mock DB layer that optionally accepts
 raw SQL strings (vulnerable simulation) or parameter arrays (safe).
*/
const users = [
  { id: 1, username: 'admin', password: 'secret', email: 'admin@example.com' },
  { id: 2, username: 'alice', password: 'alicepwd', email: 'alice@example.com' },
];
// test change
const posts = [
  { id: 1, title: 'Hello', body: 'First post' },
  { id: 2, title: 'Bye', body: 'Second post' },
];

const mockDb = {
  // query(sql)  -> vulnerable style (string interpreted)
  // query(sql, params) -> safe style (params treated as data)
  async query(sql, params) {
    // Simple logger
    console.log('[DB] SQL:', sql, 'PARAMS:', params || 'none');

    // If params provided, do a safe match (simulate parameter binding)
    if (Array.isArray(params)) {
      // very small set of supported queries simulated by pattern
      if (/from users where username = \? and password = \?/i.test(sql)) {
        const [username, password] = params;
        return users.filter(u => u.username === username && u.password === password);
      }
      if (/from posts where id = \?/i.test(sql)) {
        const [id] = params;
        return posts.filter(p => p.id === Number(id));
      }
      return [];
    }

    // --- Vulnerable interpretation (VERY naive simulation) ---
    const s = String(sql).toLowerCase();

    // login simulation: if injection like "or '1'='1'" present, return admin
    if (s.includes("username") && s.includes("password")) {
      if (s.includes("or '1'='1'") || s.includes("or 1=1")) {
        return [users[0]]; // return admin
      }
      // crude parse for username/password values in quotes
      const u = (sql.match(/username\s*=\s*'([^']*)'/i) || [])[1];
      const p = (sql.match(/password\s*=\s*'([^']*)'/i) || [])[1];
      return users.filter(x => x.username === u && x.password === p);
    }

    // posts by id (vulnerable)
    if (s.includes("from posts where id =")) {
      if (s.includes("union")) {
        // union-based simulated return: combine posts + users (safely simulated)
        return posts.concat(users.map(u => ({ id: u.id, title: u.username, body: u.email })));
      }
      const match = sql.match(/from posts where id =\s*([0-9]+)/i);
      if (match) {
        return posts.filter(p => p.id === Number(match[1]));
      }
      return [];
    }

    // dynamic order by vulnerable simulation: if ORDER BY contains arbitrary user input, return full list
    if (s.includes('order by')) {
      return posts; // just return posts
    }

    // default empty
    return [];
  }
};

/* ------------------------------------------------------------------
   Endpoints with assorted vulnerabilities (each demonstrates a different pattern)
   These are intentionally insecure and labeled. Students should find and fix them.
   ------------------------------------------------------------------ */

/* 1) /vuln-login - raw concatenation -> classic authentication bypass (UNSAFE) */
app.post('/vuln-login', async (req, res) => {
  const { username = '', password = '' } = req.body;
  // VULNERABLE: concatenates values into SQL string.
  const sql = "SELECT id, username FROM users WHERE username = '" + username +
              "' AND password = '" + password + "'";
  const rows = await mockDb.query(sql); // vulnerable path
  if (rows.length) return res.json({ ok: true, user: rows[0] });
  return res.status(401).json({ ok: false });
});

/* 2) /vuln-post-union - raw concatenation showing UNION problem */
app.get('/vuln-post', async (req, res) => {
  const id = req.query.id || '';
  const sql = "SELECT id, title, body FROM posts WHERE id = " + id; // vulnerable
  const rows = await mockDb.query(sql);
  res.json({ rows });
});

/* 3) /vuln-orderby - dynamic ORDER BY built from user input (whitelist needed) */
app.get('/vuln-orderby', async (req, res) => {
  const col = req.query.col || 'id'; // attacker can pass "id; DROP TABLE ..." in real DBs
  // vulnerable: directly inject col into SQL fragment
  const sql = "SELECT id, title, body FROM posts ORDER BY " + col;
  const rows = await mockDb.query(sql);
  res.json({ rows });
});

/* 4) /vuln-in-list - building IN() clauses from comma lists */
app.get('/vuln-in', async (req, res) => {
  // ex: ids=1,2,3  -> untrusted input concatenated into IN(...)
  const ids = req.query.ids || ''; // user controlled
  const sql = "SELECT id, title FROM posts WHERE id IN (" + ids + ")";
  const rows = await mockDb.query(sql);
  res.json({ rows });
});

/* 5) /vuln-orm-raw - ORM misuse / raw SQL string interpolation */
app.post('/vuln-orm-raw', async (req, res) => {
  const name = req.body.name || '';
  // many ORMs allow raw SQL execution and are still vulnerable if you interpolate.
  const sql = `SELECT * FROM users WHERE username = '${name}'`; // vulnerable
  const rows = await mockDb.query(sql);
  res.json({ rows });
});

/* 6) /vuln-error-leak - shows DB error messages to client (exposes info) */
app.get('/vuln-error-leak', async (req, res) => {
  const id = req.query.id || '';
  try {
    // vulnerable: simulate DB error when a specific token is present
    if (String(id).includes('TRIGGER_ERROR')) throw new Error('Simulated DB error: syntax near ... secret=DBNAME');
    const sql = "SELECT id FROM posts WHERE id = " + id;
    const rows = await mockDb.query(sql);
    res.json({ rows });
  } catch (err) {
    // vulnerable behavior: returning raw error message to client
    return res.status(500).send(err.message);
  }
});

/* 7) /vuln-second-order - second-order scenario: store unsafe data then used unsafely */
let storage = {};
app.post('/vuln-store', (req, res) => {
  // simulate storing untrusted input in DB; later used unsafely
  storage.key = req.body.payload || '';
  res.json({ stored: true });
});
app.get('/vuln-second-order', async (req, res) => {
  // later use of stored value without parameterization
  const payload = storage.key || '1';
  const sql = "SELECT id, title FROM posts WHERE id = " + payload; // unsafe use
  const rows = await mockDb.query(sql);
  res.json({ rows });
});

/* 8) /safe-login - correct parameterized example for comparison */
app.post('/safe-login', async (req, res) => {
  const { username = '', password = '' } = req.body;
  const sql = "SELECT id, username FROM users WHERE username = ? AND password = ?";
  const rows = await mockDb.query(sql, [username, password]); // safe path
  if (rows.length) return res.json({ ok: true, user: rows[0] });
  return res.status(401).json({ ok: false });
});

/* 9) helper: simple home page listing endpoints and short hints */
app.get('/', (req, res) => {
  res.send(`
  <h2>SQLi Lab (safe simulation)</h2>
  <ul>
    <li>POST /vuln-login {username,password} — vulnerable string concat login</li>
    <li>POST /safe-login {username,password} — parameterized (safe)</li>
    <li>GET  /vuln-post?id=... — UNION demo if ID contains 'UNION'</li>
    <li>GET  /vuln-orderby?col=... — dynamic ORDER BY injection (whitelist needed)</li>
    <li>GET  /vuln-in?ids=1,2 — unsafe IN() assembly</li>
    <li>POST /vuln-orm-raw {name} — ORM raw SQL interpolation</li>
    <li>GET  /vuln-error-leak?id=TRIGGER_ERROR — shows error leak</li>
    <li>POST /vuln-store {payload} then GET /vuln-second-order — second-order SQLi</li>
  </ul>
  <p>Run only on localhost in a lab VM. See lab tasks and instructions in README.</p>
  `);
});

/* Start server */
const port = 3000;
app.listen(port, () => console.log(`SQLi lab running on http://localhost:${port}`));
