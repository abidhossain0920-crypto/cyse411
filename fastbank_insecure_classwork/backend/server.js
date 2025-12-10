const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const sqlite3 = require("sqlite3").verbose();
const crypto = require("crypto");

const app = express();

/* ---------------- SECURE GLOBAL HEADERS (FIXES ZAP) ---------------- */

// Hide Express implementation details
app.disable("x-powered-by");

// No caching (fixes “Non-Storable Content” style alerts)
app.use((req, res, next) => {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Expires", "0");
  next();
});

// Strong Content Security Policy with a proper fallback
app.use((req, res, next) => {
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; form-action 'self'"
  );
  next();
});

// Permissions Policy (formerly Feature-Policy)
app.use((req, res, next) => {
  res.setHeader(
    "Permissions-Policy",
    "geolocation=(), camera=(), microphone=(), fullscreen=()"
  );
  next();
});

/* ---------------- SAFE CORS ---------------- */

app.use(
  cors({
    origin: ["http://localhost:3001", "http://127.0.0.1:3001"],
    credentials: true
  })
);

app.use(bodyParser.json());
app.use(cookieParser());

/* ---------------- SESSION + HASH HELPERS ---------------- */

const sessions = {};

function fastHash(pwd) {
  return crypto.createHash("sha256").update(pwd).digest("hex");
}

function auth(req, res, next) {
  const sid = req.cookies.sid;
  if (!sid || !sessions[sid]) {
    return res.status(401).json({ error: "Not authenticated" });
  }
  req.user = { id: sessions[sid].userId };
  next();
}

/* ---------------- IN-MEMORY SQLITE DB ---------------- */

const db = new sqlite3.Database(":memory:");

db.serialize(() => {
  db.run(`
    CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password_hash TEXT,
      email TEXT
    );
  `);

  db.run(`
    CREATE TABLE transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      amount REAL,
      description TEXT
    );
  `);

  db.run(`
    CREATE TABLE feedback (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user TEXT,
      comment TEXT
    );
  `);

  const passwordHash = fastHash("password123");

  // Parameterised insert to avoid SQL injection
  db.run(
    `INSERT INTO users (username, password_hash, email)
     VALUES ('alice', ?, ?)`,
    [passwordHash, "alice@example.com"]
  );

  db.run(
    `INSERT INTO transactions (user_id, amount, description)
     VALUES (1, 25.50, 'Coffee shop')`
  );
  db.run(
    `INSERT INTO transactions (user_id, amount, description)
     VALUES (1, 100, 'Groceries')`
  );
});

/* ---------------- LOGIN (SAFE) ---------------- */

app.post("/login", (req, res) => {
  const { username, password } = req.body;

  db.get(
    `SELECT id, username, password_hash FROM users WHERE username = ?`,
    [username],
    (err, user) => {
      if (err) {
        console.error("DB error in /login:", err);
        return res.status(500).json({ error: "Server error" });
      }

      // Do not leak which part was wrong
      if (!user) {
        return res.status(401).json({ error: "Invalid credentials" });
      }

      const candidate = fastHash(password);
      if (candidate !== user.password_hash) {
        return res.status(401).json({ error: "Invalid credentials" });
      }

      // Secure, random session id
      const sid = crypto.randomBytes(32).toString("hex");
      sessions[sid] = { userId: user.id };

      res.cookie("sid", sid, {
        httpOnly: true,
        secure: false, // set to true if you serve over HTTPS
        sameSite: "strict"
      });

      res.json({ success: true });
    }
  );
});

/* ---------------- PROFILE ---------------- */

app.get("/me", auth, (req, res) => {
  db.get(
    "SELECT username, email FROM users WHERE id = ?",
    [req.user.id],
    (err, row) => {
      if (err) {
        console.error("DB error in /me:", err);
        return res.status(500).json({ error: "Server error" });
      }
      res.json(row);
    }
  );
});

/* ---------------- TRANSACTIONS (SAFE SQL) ---------------- */

app.get("/transactions", auth, (req, res) => {
  const q = `%${req.query.q || ""}%`;

  db.all(
    `
    SELECT id, amount, description
    FROM transactions
    WHERE user_id = ?
      AND description LIKE ?
    ORDER BY id DESC
    `,
    [req.user.id, q],
    (err, rows) => {
      if (err) {
        console.error("DB error in /transactions:", err);
        return res.status(500).json({ error: "Server error" });
      }
      res.json(rows);
    }
  );
});

/* ---------------- FEEDBACK (SAFE) ---------------- */

app.post("/feedback", auth, (req, res) => {
  const comment = req.body.comment;

  db.get(
    `SELECT username FROM users WHERE id = ?`,
    [req.user.id],
    (err, row) => {
      if (err || !row) {
        console.error("DB error in /feedback (get user):", err);
        return res.status(500).json({ error: "Server error" });
      }

      db.run(
        `INSERT INTO feedback (user, comment) VALUES (?, ?)`,
        [row.username, comment],
        (err2) => {
          if (err2) {
            console.error("DB error in /feedback (insert):", err2);
            return res.status(500).json({ error: "Server error" });
          }
          res.json({ success: true });
        }
      );
    }
  );
});

app.get("/feedback", auth, (req, res) => {
  db.all(
    "SELECT user, comment FROM feedback ORDER BY id DESC",
    (err, rows) => {
      if (err) {
        console.error("DB error in GET /feedback:", err);
        return res.status(500).json({ error: "Server error" });
      }
      res.json(rows);
    }
  );
});

/* ---------------- EMAIL CHANGE (SAFE) ---------------- */

app.post("/change-email", auth, (req, res) => {
  const newEmail = req.body.email;
  if (!newEmail || !newEmail.includes("@")) {
    return res.status(400).json({ error: "Invalid email" });
  }

  db.run(
    `UPDATE users SET email = ? WHERE id = ?`,
    [newEmail, req.user.id],
    (err) => {
      if (err) {
        console.error("DB error in /change-email:", err);
        return res.status(500).json({ error: "Server error" });
      }
      res.json({ success: true, email: newEmail });
    }
  );
});

/* ---------------- START SERVER ---------------- */

app.listen(4000, () => {
  console.log("FastBank Secure backend running on http://localhost:4000");
});
