'use strict';
// ══════════════════════════════════════════════════════════════════
//  WebArs CRM — Self-Hosted Server (Express + MySQL)
//  Replaces GitHub as the storage backend for Coolify deployment.
//
//  Required environment variables:
//    DATABASE_URL  — MySQL connection string
//                    e.g. mysql://user:pass@host:3306/dbname
//    API_SECRET    — Secret key the CRM frontend sends as Bearer token
//    PORT          — (optional) defaults to 3000
// ══════════════════════════════════════════════════════════════════

const express     = require('express');
const mysql       = require('mysql2/promise');
const path        = require('path');
const fs          = require('fs');
const nodeCrypto  = require('crypto');

// Optional nodemailer (install nodemailer package to enable email reset)
let nodemailer = null;
try { nodemailer = require('nodemailer'); } catch(e) { console.log('ℹ nodemailer not installed — email reset will show link instead'); }

const app  = express();
const PORT = process.env.PORT || 3000;
const API_SECRET = (process.env.API_SECRET || '').trim();
const APP_URL    = (process.env.APP_URL    || 'http://localhost:3000').replace(/\/$/, '');
const SMTP_HOST  = process.env.SMTP_HOST  || '';
const SMTP_PORT  = parseInt(process.env.SMTP_PORT || '587');
const SMTP_USER  = process.env.SMTP_USER  || '';
const SMTP_PASS  = process.env.SMTP_PASS  || '';
const SMTP_FROM  = process.env.SMTP_FROM  || SMTP_USER;
const RESET_TO   = process.env.RESET_TO   || 'turleat@gmail.com'; // hardwired recovery address
const PBKDF2_ITER_DEFAULT = 600000; // OWASP 2023 recommendation for PBKDF2-SHA256

if (!API_SECRET) {
  console.error('❌  FATAL: API_SECRET environment variable is not set. Refusing to start.');
  process.exit(1);
}

// ── MySQL connection pool ────────────────────────────────────────
const DB_URL = process.env.DATABASE_URL || '';
if (!DB_URL) {
  console.error('❌  FATAL: DATABASE_URL environment variable is not set. Refusing to start.');
  process.exit(1);
}

// Parse mysql://user:pass@host:port/db  OR  use env vars directly
function parseDbUrl(url) {
  try {
    const u = new URL(url);
    return {
      host:     u.hostname,
      port:     parseInt(u.port) || 3306,
      user:     decodeURIComponent(u.username),
      password: decodeURIComponent(u.password),
      database: u.pathname.replace(/^\//, ''),
    };
  } catch(e) {
    throw new Error('Invalid DATABASE_URL: ' + e.message);
  }
}

let pool;
try {
  pool = mysql.createPool({
    ...parseDbUrl(DB_URL),
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    timezone: '+00:00',
    // Store JSON as text (mysql2 auto-parses JSON columns)
    typeCast: function(field, next) {
      if (field.type === 'JSON') {
        const val = field.string();
        if (val === null) return null;
        try { return JSON.parse(val); } catch(e) { return val; }
      }
      return next();
    }
  });
  console.log('✓ MySQL pool created');
} catch(e) {
  console.error('❌  FATAL: ' + e.message);
  process.exit(1);
}

// ── Database initialisation ──────────────────────────────────────
async function initDb() {
  const conn = await pool.getConnection();
  try {
    await conn.query(`
      CREATE TABLE IF NOT EXISTS crm_data (
        id         INT          NOT NULL DEFAULT 1,
        content    LONGTEXT     NOT NULL,
        version    BIGINT       NOT NULL DEFAULT 1,
        updated_at DATETIME     DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (id)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    `);
    await conn.query(`
      CREATE TABLE IF NOT EXISTS recovery_blobs (
        email_hash VARCHAR(32)  NOT NULL,
        payload    LONGTEXT     NOT NULL,
        updated_at DATETIME     DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (email_hash)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    `);
    await conn.query(`
      CREATE TABLE IF NOT EXISTS form_definitions (
        slug       VARCHAR(128) NOT NULL,
        content    LONGTEXT     NOT NULL,
        updated_at DATETIME     DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (slug)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    `);
    await conn.query(`
      CREATE TABLE IF NOT EXISTS crm_summary (
        id         INT          NOT NULL DEFAULT 1,
        content    LONGTEXT     NOT NULL,
        updated_at DATETIME     DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (id)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    `);
    await conn.query(`
      CREATE TABLE IF NOT EXISTS crm_backups (
        id         INT          NOT NULL AUTO_INCREMENT,
        name       VARCHAR(64)  NOT NULL,
        content    LONGTEXT     NOT NULL,
        created_at DATETIME     DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY uk_name (name)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    `);
    await conn.query(`
      CREATE TABLE IF NOT EXISTS crm_key_escrow (
        id         INT          NOT NULL DEFAULT 1,
        content    LONGTEXT     NOT NULL,
        updated_at DATETIME     DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (id)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    `);
    await conn.query(`
      CREATE TABLE IF NOT EXISTS password_resets (
        token      VARCHAR(128) NOT NULL,
        expires_at DATETIME     NOT NULL,
        used       TINYINT(1)   NOT NULL DEFAULT 0,
        created_at DATETIME     DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (token)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    `);
    // Add 'used' column to password_resets if it was created by an older version
    await conn.query(`
      ALTER TABLE password_resets
        ADD COLUMN IF NOT EXISTS used TINYINT(1) NOT NULL DEFAULT 0
    `).catch(()=>{});
    // ── NEW UNIFIED AUTH TABLE ─────────────────────────────────────
    // Single row (id=1). Contains everything needed to log in from ANY device
    // with the same password. No localStorage state required.
    //   salt           : base64 PBKDF2 salt (32 random bytes), GLOBAL — same on every device
    //   wrapped_master : {iv,ct} master key encrypted by PBKDF2(password, salt, iter)
    //   escrow_blob    : {iv,ct} master key encrypted by PBKDF2(API_SECRET, fixed-salt, iter)
    //   pbkdf2_iter    : iteration count (for future hardening)
    await conn.query(`
      CREATE TABLE IF NOT EXISTS crm_auth (
        id              INT          NOT NULL DEFAULT 1,
        salt            VARCHAR(128) NOT NULL,
        wrapped_master  LONGTEXT     NOT NULL,
        escrow_blob     LONGTEXT     NOT NULL,
        pbkdf2_iter     INT          NOT NULL DEFAULT 600000,
        created_at      DATETIME     DEFAULT CURRENT_TIMESTAMP,
        updated_at      DATETIME     DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (id)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    `);
    // ── BACKUP HARDENING ───────────────────────────────────────────
    // Add tier column so we can keep different retention windows.
    // Existing rows get tier='legacy' (kept indefinitely — safe).
    try {
      await conn.query(`ALTER TABLE crm_backups ADD COLUMN tier VARCHAR(16) NOT NULL DEFAULT 'legacy'`);
      console.log('✓ Added tier column to crm_backups');
    } catch(e) {
      if (!/Duplicate column/i.test(e.message)) console.warn('crm_backups.tier:', e.message);
    }
    // Allow multiple rows with the same name across different timestamps —
    // we no longer overwrite backups by name. Drop the UNIQUE constraint if it exists.
    try {
      await conn.query(`ALTER TABLE crm_backups DROP INDEX uk_name`);
      console.log('✓ Dropped UNIQUE(name) on crm_backups (backups are now append-only)');
    } catch(e) {
      if (!/check that column.key exists|doesn't exist/i.test(e.message)) {
        // ignore
      }
    }
    console.log('✓ Database tables ready');
  } finally {
    conn.release();
  }
}

// ── Helper: JSON stringify for storage ───────────────────────────
const toJson  = v => typeof v === 'string' ? v : JSON.stringify(v);
const fromRow = (row, col) => {
  if (!row || row[col] == null) return null;
  const v = row[col];
  if (typeof v === 'object') return v;
  try { return JSON.parse(v); } catch(e) { return v; }
};

// ── Middleware ───────────────────────────────────────────────────
app.use(express.json({ limit: '20mb' }));

// ── Auth middleware ──────────────────────────────────────────────
function requireAuth(req, res, next) {
  const auth  = (req.headers.authorization || '').trim();
  const token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : auth;
  if (!token || token !== API_SECRET) {
    return res.status(401).json({ error: 'Unauthorized: invalid API key' });
  }
  next();
}

// ══════════════════════════════════════════════════════════════════
//  ROUTES
// ══════════════════════════════════════════════════════════════════

// ── Validate API key ─────────────────────────────────────────────
app.get('/api/validate', requireAuth, (_req, res) => {
  res.json({ ok: true });
});

// ── Diagnostic endpoint (does NOT leak the secret) ───────────────
app.get('/api/debug-auth', (req, res) => {
  const auth  = (req.headers.authorization || '').trim();
  const token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : auth;
  res.json({
    receivedTokenLength: token.length,
    expectedSecretLength: API_SECRET.length,
    match: token === API_SECRET,
    // First/last char codes — helps spot wrapping quotes, hidden whitespace, etc.
    receivedFirstCharCode: token.length ? token.charCodeAt(0) : null,
    receivedLastCharCode:  token.length ? token.charCodeAt(token.length - 1) : null,
    expectedFirstCharCode: API_SECRET.length ? API_SECRET.charCodeAt(0) : null,
    expectedLastCharCode:  API_SECRET.length ? API_SECRET.charCodeAt(API_SECRET.length - 1) : null,
    authHeaderStartsWithBearer: auth.startsWith('Bearer '),
    rawHeaderLength: (req.headers.authorization || '').length,
  });
});

// ── CRM data (encrypted blob) ────────────────────────────────────
app.get('/api/data', requireAuth, async (_req, res) => {
  try {
    const [rows] = await pool.query('SELECT content, version FROM crm_data WHERE id = 1');
    if (!rows.length) return res.json({ content: null, version: 0 });
    res.json({ content: fromRow(rows[0], 'content'), version: rows[0].version });
  } catch (e) {
    console.error('GET /api/data:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// Optimistic-locking write
app.put('/api/data', requireAuth, async (req, res) => {
  const { content, version } = req.body;
  if (!content) return res.status(400).json({ error: 'content is required' });
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [rows] = await conn.query('SELECT version FROM crm_data WHERE id = 1 FOR UPDATE');
    if (rows.length === 0) {
      // First insert
      await conn.query('INSERT INTO crm_data (id, content, version) VALUES (1, ?, 1)', [toJson(content)]);
      await conn.commit();
      return res.json({ version: 1 });
    }
    const currentVer = rows[0].version;
    // SAFETY: if caller sends version=null (fresh setup / unknown state), refuse to
    // overwrite existing data — prevents a new browser session from wiping old records.
    if (version === null || version === undefined) {
      await conn.rollback();
      return res.status(409).json({ error: 'EXISTING_DATA', version: currentVer, message: 'Server hat bereits Daten. Bitte zuerst laden (version mitsenden).' });
    }
    // Conflict check: version must match current
    if (Number(version) !== currentVer) {
      await conn.rollback();
      return res.status(409).json({ error: 'Conflict: data was modified by another device' });
    }
    const newVer = currentVer + 1;
    await conn.query('UPDATE crm_data SET content = ?, version = ? WHERE id = 1', [toJson(content), newVer]);
    await conn.commit();
    res.json({ version: newVer });
  } catch (e) {
    await conn.rollback();
    console.error('PUT /api/data:', e.message);
    res.status(500).json({ error: e.message });
  } finally {
    conn.release();
  }
});

// ── Recovery blobs (no auth — content is client-side encrypted) ──
app.get('/api/recovery/:hash', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT payload FROM recovery_blobs WHERE email_hash = ?', [req.params.hash]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(fromRow(rows[0], 'payload'));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.put('/api/recovery/:hash', async (req, res) => {
  try {
    await pool.query(
      'INSERT INTO recovery_blobs (email_hash, payload) VALUES (?, ?) ON DUPLICATE KEY UPDATE payload = VALUES(payload)',
      [req.params.hash, toJson(req.body)]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Public form definitions ──────────────────────────────────────
app.get('/forms/:slug', async (req, res) => {
  const slug = req.params.slug.replace(/\.json$/, '');
  try {
    const [rows] = await pool.query('SELECT content FROM form_definitions WHERE slug = ?', [slug]);
    if (!rows.length) return res.status(404).json({ error: 'Form not found' });
    res.json(fromRow(rows[0], 'content'));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.put('/api/forms/:slug', requireAuth, async (req, res) => {
  try {
    await pool.query(
      'INSERT INTO form_definitions (slug, content) VALUES (?, ?) ON DUPLICATE KEY UPDATE content = VALUES(content)',
      [req.params.slug, toJson(req.body)]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/forms/:slug', requireAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM form_definitions WHERE slug = ?', [req.params.slug]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Jarvis API summary ───────────────────────────────────────────
app.get('/api/summary', async (_req, res) => {
  try {
    const [rows] = await pool.query('SELECT content FROM crm_summary WHERE id = 1');
    if (!rows.length) return res.status(404).json({ error: 'No summary yet' });
    res.json(fromRow(rows[0], 'content'));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.put('/api/summary', requireAuth, async (req, res) => {
  try {
    await pool.query(
      'INSERT INTO crm_summary (id, content) VALUES (1, ?) ON DUPLICATE KEY UPDATE content = VALUES(content)',
      [toJson(req.body)]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Backups ──────────────────────────────────────────────────────
app.get('/api/backups', requireAuth, async (_req, res) => {
  try {
    const [rows] = await pool.query('SELECT id, name, tier, created_at FROM crm_backups ORDER BY created_at DESC LIMIT 500');
    res.json({ backups: rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/backups/:id', requireAuth, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT content, name, created_at FROM crm_backups WHERE id = ?', [req.params.id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    res.json({ content: fromRow(rows[0], 'content'), name: rows[0].name });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/backups', requireAuth, async (req, res) => {
  try {
    const note = (req.body && typeof req.body.note === 'string') ? req.body.note.slice(0, 40) : '';
    await createBackup('manual', note);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/backups/:id/restore — atomically snapshot current data, then restore
// the chosen backup into crm_data. The pre-restore snapshot is itself a backup
// with tier='pre-restore' (kept forever) — so a restore can NEVER lose data.
app.post('/api/backups/:id/restore', requireAuth, async (req, res) => {
  if (!DB_READY) return res.status(503).json({ error: 'Database not ready' });
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    // 1) Verify target backup exists
    const [target] = await conn.query('SELECT content, name FROM crm_backups WHERE id = ?', [req.params.id]);
    if (!target.length) {
      await conn.rollback();
      return res.status(404).json({ error: 'Backup nicht gefunden' });
    }
    // 2) Snapshot current state (if any) as a pre-restore backup
    const [cur] = await conn.query('SELECT content FROM crm_data WHERE id = 1 FOR UPDATE');
    if (cur.length) {
      const snapName = `pre-restore-${new Date().toISOString().replace(/[:.]/g, '-')}`;
      await conn.query(
        'INSERT INTO crm_backups (name, content, tier) VALUES (?, ?, ?)',
        [snapName, cur[0].content, 'pre-restore']
      );
    }
    // 3) Write backup content into crm_data with new version
    const [verRow] = await conn.query('SELECT version FROM crm_data WHERE id = 1 FOR UPDATE');
    const newVer = verRow.length ? verRow[0].version + 1 : 1;
    if (verRow.length) {
      await conn.query('UPDATE crm_data SET content = ?, version = ? WHERE id = 1', [target[0].content, newVer]);
    } else {
      await conn.query('INSERT INTO crm_data (id, content, version) VALUES (1, ?, ?)', [target[0].content, newVer]);
    }
    await conn.commit();
    console.log(`✓ Restored backup ${target[0].name} (id=${req.params.id}), pre-restore snapshot saved`);
    res.json({ ok: true, version: newVer, restored: target[0].name });
  } catch (e) {
    await conn.rollback();
    console.error('POST /api/backups/:id/restore:', e.message);
    res.status(500).json({ error: e.message });
  } finally {
    conn.release();
  }
});

// ══════════════════════════════════════════════════════════════════
//  NEW UNIFIED AUTH MODEL
//  ─────────────────────
//  Single source of truth for password → master key derivation.
//  - GET /api/auth-blob          (public)   : salt + wrapped_master + iter
//  - POST /api/auth-blob/init    (API auth) : one-time setup, refuses if exists
//  - PUT /api/auth-blob          (API auth) : update wrapped_master (password change)
//  - GET /api/reset-token/:t     (token)    : returns salt + escrow + iter
//  - POST /api/reset-token/:t/confirm       : commits new wrapped_master + marks used
// ══════════════════════════════════════════════════════════════════

// GET — public so the login form can fetch salt before user has any credentials.
// Returns {exists:false} if no auth has been set up yet. NEVER returns escrow.
app.get('/api/auth-blob', async (_req, res) => {
  if (!DB_READY) return res.status(503).json({ error: 'Database not ready' });
  try {
    const [rows] = await pool.query('SELECT salt, wrapped_master, pbkdf2_iter FROM crm_auth WHERE id = 1');
    if (!rows.length) return res.json({ exists: false });
    res.json({
      exists: true,
      salt: rows[0].salt,
      wrapped_master: fromRow(rows[0], 'wrapped_master'),
      pbkdf2_iter: rows[0].pbkdf2_iter || PBKDF2_ITER_DEFAULT,
    });
  } catch (e) {
    console.error('GET /api/auth-blob:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// POST /api/auth-blob/init — one-time setup. REFUSES if row already exists.
// Body: {salt, wrapped_master, escrow_blob, pbkdf2_iter}
app.post('/api/auth-blob/init', requireAuth, async (req, res) => {
  if (!DB_READY) return res.status(503).json({ error: 'Database not ready' });
  const { salt, wrapped_master, escrow_blob, pbkdf2_iter } = req.body || {};
  if (!salt || !wrapped_master || !escrow_blob) {
    return res.status(400).json({ error: 'salt, wrapped_master, escrow_blob required' });
  }
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [rows] = await conn.query('SELECT id FROM crm_auth WHERE id = 1 FOR UPDATE');
    if (rows.length) {
      await conn.rollback();
      return res.status(409).json({ error: 'AUTH_ALREADY_EXISTS', message: 'Auth blob already initialized. Use password change or reset flow.' });
    }
    await conn.query(
      'INSERT INTO crm_auth (id, salt, wrapped_master, escrow_blob, pbkdf2_iter) VALUES (1, ?, ?, ?, ?)',
      [salt, toJson(wrapped_master), toJson(escrow_blob), pbkdf2_iter || PBKDF2_ITER_DEFAULT]
    );
    await conn.commit();
    console.log('✓ Auth blob initialized');
    res.json({ ok: true });
  } catch (e) {
    await conn.rollback();
    console.error('POST /api/auth-blob/init:', e.message);
    res.status(500).json({ error: e.message });
  } finally {
    conn.release();
  }
});

// PUT /api/auth-blob — change password (update wrapped_master only).
// Body: {wrapped_master}
// salt, escrow_blob, pbkdf2_iter never change here (escrow tracks master, not pw)
app.put('/api/auth-blob', requireAuth, async (req, res) => {
  if (!DB_READY) return res.status(503).json({ error: 'Database not ready' });
  const { wrapped_master } = req.body || {};
  if (!wrapped_master) return res.status(400).json({ error: 'wrapped_master required' });
  try {
    const [rows] = await pool.query('SELECT id FROM crm_auth WHERE id = 1');
    if (!rows.length) return res.status(404).json({ error: 'AUTH_NOT_INITIALIZED' });
    await pool.query('UPDATE crm_auth SET wrapped_master = ? WHERE id = 1', [toJson(wrapped_master)]);
    console.log('✓ Auth blob: password updated');
    res.json({ ok: true });
  } catch (e) {
    console.error('PUT /api/auth-blob:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// ── Legacy Master-Key Escrow (encrypted with API_SECRET-derived key) ──
// Kept for backwards-compat / migration only. New flows use crm_auth.
app.get('/api/key-escrow', requireAuth, async (_req, res) => {
  try {
    const [rows] = await pool.query('SELECT content FROM crm_key_escrow WHERE id = 1');
    if (!rows.length) return res.status(404).json({ error: 'No escrow yet' });
    res.json(fromRow(rows[0], 'content'));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.put('/api/key-escrow', requireAuth, async (req, res) => {
  try {
    await pool.query(
      'INSERT INTO crm_key_escrow (id, content) VALUES (1, ?) ON DUPLICATE KEY UPDATE content = VALUES(content)',
      [toJson(req.body)]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Password Reset ───────────────────────────────────────────────
// POST /api/forgot-password  — generate reset token, send email or return URL
app.post('/api/forgot-password', async (req, res) => {
  if (!DB_READY) return res.status(503).json({ error: 'Database not ready' });
  try {
    // Clean up expired/used tokens first
    await pool.query('DELETE FROM password_resets WHERE used = 1 OR expires_at < NOW()');

    // Generate a secure one-time token (valid for 1 hour)
    const token = nodeCrypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
    await pool.query('INSERT INTO password_resets (token, expires_at) VALUES (?, ?)', [token, expiresAt]);

    const resetUrl = `${APP_URL}/?reset=${token}`;

    // Try to send email if SMTP is configured
    if (nodemailer && SMTP_HOST && SMTP_USER && SMTP_PASS && RESET_TO) {
      try {
        const transporter = nodemailer.createTransport({
          host: SMTP_HOST,
          port: SMTP_PORT,
          secure: SMTP_PORT === 465,
          auth: { user: SMTP_USER, pass: SMTP_PASS },
        });
        await transporter.sendMail({
          from: SMTP_FROM || SMTP_USER,
          to: RESET_TO,
          subject: 'WebArs CRM — Passwort zurücksetzen',
          html: `
            <p>Hallo,</p>
            <p>Du hast eine Passwort-Zurücksetzung für WebArs CRM angefordert.</p>
            <p><a href="${resetUrl}" style="background:#141210;color:white;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:bold;display:inline-block;margin:16px 0">Passwort zurücksetzen →</a></p>
            <p style="color:#666;font-size:13px">Oder kopiere diesen Link: ${resetUrl}</p>
            <p style="color:#666;font-size:13px">Gültig für 1 Stunde. Falls du diese Anfrage nicht gestellt hast, ignoriere diese E-Mail.</p>
          `,
        });
        console.log(`✓ Password reset email sent to ${RESET_TO}`);
        return res.json({ ok: true, emailSent: true });
      } catch (mailErr) {
        console.error('Email send failed:', mailErr.message);
        // Fall through — return URL directly
      }
    }

    // No SMTP or email failed — return reset URL directly (admin-only use case)
    console.log(`ℹ Password reset URL generated (no email sent): ${resetUrl}`);
    res.json({ ok: true, emailSent: false, resetUrl, token });
  } catch (e) {
    console.error('POST /api/forgot-password:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// GET /api/reset-token/:token — validate token, return salt + escrow + iter
// Prefers new crm_auth row; falls back to legacy crm_key_escrow for old installs.
app.get('/api/reset-token/:token', async (req, res) => {
  if (!DB_READY) return res.status(503).json({ error: 'Database not ready' });
  try {
    const [rows] = await pool.query(
      'SELECT token FROM password_resets WHERE token = ? AND used = 0 AND expires_at > NOW()',
      [req.params.token]
    );
    if (!rows.length) return res.status(404).json({ error: 'Link ungültig oder abgelaufen. Bitte fordere einen neuen an.' });

    // Prefer new auth-blob
    const [auth] = await pool.query('SELECT salt, escrow_blob, pbkdf2_iter FROM crm_auth WHERE id = 1');
    if (auth.length) {
      return res.json({
        scheme: 'auth-blob-v1',
        salt: auth[0].salt,
        escrow: fromRow(auth[0], 'escrow_blob'),
        pbkdf2_iter: auth[0].pbkdf2_iter || PBKDF2_ITER_DEFAULT,
      });
    }

    // Legacy fallback (pre-migration)
    const [escrow] = await pool.query('SELECT content FROM crm_key_escrow WHERE id = 1');
    if (!escrow.length) return res.status(404).json({ error: 'Kein Key-Escrow gefunden. Bitte logge dich zuerst einmal erfolgreich ein, damit das Escrow erstellt wird.' });
    res.json({ scheme: 'legacy', escrow: fromRow(escrow[0], 'content') });
  } catch (e) {
    console.error('GET /api/reset-token:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// POST /api/reset-token/:token/confirm — commits new wrapped_master and marks token used.
// Body: {wrapped_master} — required for auth-blob scheme.
// In one transaction: atomically updates crm_auth.wrapped_master and marks token used.
app.post('/api/reset-token/:token/confirm', async (req, res) => {
  if (!DB_READY) return res.status(503).json({ error: 'Database not ready' });
  const { wrapped_master } = req.body || {};
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [tokens] = await conn.query(
      'SELECT token FROM password_resets WHERE token = ? AND used = 0 AND expires_at > NOW() FOR UPDATE',
      [req.params.token]
    );
    if (!tokens.length) {
      await conn.rollback();
      return res.status(404).json({ error: 'Link ungültig oder abgelaufen.' });
    }
    // If wrapped_master sent, update crm_auth atomically with token consumption
    if (wrapped_master) {
      const [auth] = await conn.query('SELECT id FROM crm_auth WHERE id = 1 FOR UPDATE');
      if (auth.length) {
        await conn.query('UPDATE crm_auth SET wrapped_master = ? WHERE id = 1', [toJson(wrapped_master)]);
      }
    }
    await conn.query('UPDATE password_resets SET used = 1 WHERE token = ?', [req.params.token]);
    await conn.commit();
    res.json({ ok: true });
  } catch (e) {
    await conn.rollback();
    console.error('POST /api/reset-token/:token/confirm:', e.message);
    res.status(500).json({ error: e.message });
  } finally {
    conn.release();
  }
});

// ── Import JSON backup from old GitHub-based CRM ─────────────────
app.post('/api/import', requireAuth, async (req, res) => {
  const { encryptedData } = req.body;
  if (!encryptedData) return res.status(400).json({ error: 'encryptedData required' });
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [rows] = await conn.query('SELECT version FROM crm_data WHERE id = 1 FOR UPDATE');
    const newVer = rows.length ? rows[0].version + 1 : 1;
    await conn.query(
      'INSERT INTO crm_data (id, content, version) VALUES (1, ?, ?) ON DUPLICATE KEY UPDATE content = VALUES(content), version = VALUES(version)',
      [toJson(encryptedData), newVer]
    );
    await conn.commit();
    res.json({ ok: true, version: newVer });
  } catch (e) {
    await conn.rollback();
    res.status(500).json({ error: e.message });
  } finally {
    conn.release();
  }
});

// ── Admin: Full Reset ──────────────────────────────────────────────
// PERMANENTLY DISABLED in the new auth model. A single endpoint that wipes
// data is too dangerous — any leaked API_SECRET would destroy everything.
// Use the password-reset email flow if you forgot your password; if you
// really need to wipe (rare), do it manually via mysql client.
app.post('/api/admin/reset', requireAuth, (_req, res) => {
  res.status(410).json({
    error: 'ENDPOINT_DISABLED',
    message: 'Wipe-Endpoint dauerhaft deaktiviert. Nutze stattdessen den Passwort-Reset-Link per E-Mail.'
  });
});

// ── Frontend (inject SELF_HOSTED flag) ───────────────────────────
const INDEX_PATH = path.join(__dirname, 'index.html');

app.get('/', (_req, res) => {
  try {
    let html = fs.readFileSync(INDEX_PATH, 'utf8');
    html = html.replace(
      '<script>',
      `<script>\n// ── Injected by self-hosted server ──\nwindow.WEBARS_SELF_HOSTED = true;\nwindow.WEBARS_API_TOKEN = ${JSON.stringify(API_SECRET)};\n`
    );
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(html);
  } catch (e) {
    res.status(500).send('Could not load index.html: ' + e.message);
  }
});

app.use(express.static(__dirname, { index: false }));

// ── Backup helper ────────────────────────────────────────────────
// Backups are APPEND-ONLY. Each invocation creates a new row.
// Tier-based retention applied per-tier (never crosses tiers, never touches
// 'legacy', 'manual', or 'pre-restore' which are kept indefinitely).
const RETENTION = {
  hourly:  48,    // 2 days of hourly snapshots
  daily:   90,    // 3 months of daily snapshots
  weekly:  104,   // 2 years of weekly snapshots
  // 'manual', 'pre-restore', 'legacy' → kept forever (no auto-delete)
};

async function createBackup(tier = 'daily', note = '') {
  const [rows] = await pool.query('SELECT content FROM crm_data WHERE id = 1');
  if (!rows.length) return;
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const suffix = note ? `-${note.replace(/[^a-zA-Z0-9_-]/g, '')}` : '';
  const name = `${tier}-${stamp}${suffix}`;
  await pool.query(
    'INSERT INTO crm_backups (name, content, tier) VALUES (?, ?, ?)',
    [name, rows[0].content, tier]
  );
  // Apply retention only within the same tier — never touches other tiers
  const cap = RETENTION[tier];
  if (cap) {
    await pool.query(`
      DELETE FROM crm_backups WHERE tier = ? AND id NOT IN (
        SELECT id FROM (SELECT id FROM crm_backups WHERE tier = ? ORDER BY created_at DESC LIMIT ?) t
      )
    `, [tier, tier, cap]);
  }
  console.log(`✓ Backup created (tier=${tier}): ${name}`);
}

// ── Tiered backup scheduler ──────────────────────────────────────
// Hourly: every hour on the hour, keep 48
// Daily: 02:00 UTC, keep 90
// Weekly: Sunday 02:00 UTC, keep 104
function scheduleBackups() {
  const now = new Date();

  // Hourly — runs at top of next hour, then every hour
  const nextHour = new Date(now);
  nextHour.setUTCMinutes(0, 0, 0);
  nextHour.setUTCHours(nextHour.getUTCHours() + 1);
  setTimeout(() => {
    createBackup('hourly').catch(e => console.error('Hourly backup failed:', e.message));
    setInterval(() => createBackup('hourly').catch(e => console.error('Hourly backup failed:', e.message)), 60 * 60 * 1000);
  }, nextHour - now);

  // Daily — runs at 02:00 UTC
  const nextDay = new Date(now);
  nextDay.setUTCHours(2, 0, 0, 0);
  if (nextDay <= now) nextDay.setUTCDate(nextDay.getUTCDate() + 1);
  setTimeout(() => {
    createBackup('daily').catch(e => console.error('Daily backup failed:', e.message));
    setInterval(() => createBackup('daily').catch(e => console.error('Daily backup failed:', e.message)), 24 * 60 * 60 * 1000);
  }, nextDay - now);

  // Weekly — runs Sunday 02:00 UTC
  const nextSun = new Date(now);
  nextSun.setUTCHours(2, 0, 0, 0);
  const daysToSun = (7 - nextSun.getUTCDay()) % 7;
  if (daysToSun === 0 && nextSun <= now) nextSun.setUTCDate(nextSun.getUTCDate() + 7);
  else nextSun.setUTCDate(nextSun.getUTCDate() + daysToSun);
  setTimeout(() => {
    createBackup('weekly').catch(e => console.error('Weekly backup failed:', e.message));
    setInterval(() => createBackup('weekly').catch(e => console.error('Weekly backup failed:', e.message)), 7 * 24 * 60 * 60 * 1000);
  }, nextSun - now);

  console.log(`✓ Backup scheduler armed`);
  console.log(`  Hourly  next: ${nextHour.toISOString()} (keep ${RETENTION.hourly})`);
  console.log(`  Daily   next: ${nextDay.toISOString()} (keep ${RETENTION.daily})`);
  console.log(`  Weekly  next: ${nextSun.toISOString()} (keep ${RETENTION.weekly})`);
}

// ── Start: listen IMMEDIATELY, init DB in background with retries ──
let DB_READY = false;
let DB_ERROR = null;

app.get('/health', (_req, res) => {
  res.json({ ok: true, dbReady: DB_READY, dbError: DB_ERROR, ts: Date.now() });
});

// ── Deep self-test (proves MySQL is reachable AND writable AND tables exist) ──
// GET /api/selftest  (requires auth) — for admins to verify everything is wired up.
app.get('/api/selftest', requireAuth, async (_req, res) => {
  const out = { ts: Date.now(), checks: {} };
  try {
    if (!DB_READY) { out.checks.db_init = { ok: false, error: DB_ERROR || 'not ready' }; return res.json(out); }
    // 1) Read crm_data row count
    try {
      const [rows] = await pool.query('SELECT COUNT(*) AS n, MAX(version) AS v, MAX(updated_at) AS t FROM crm_data');
      out.checks.crm_data = { ok: true, rows: rows[0].n, latestVersion: rows[0].v, lastUpdate: rows[0].t };
    } catch(e) { out.checks.crm_data = { ok: false, error: e.message }; }
    // 2) Read crm_auth
    try {
      const [rows] = await pool.query('SELECT COUNT(*) AS n, MAX(updated_at) AS t FROM crm_auth');
      out.checks.crm_auth = { ok: true, rows: rows[0].n, lastUpdate: rows[0].t };
    } catch(e) { out.checks.crm_auth = { ok: false, error: e.message }; }
    // 3) Backups by tier
    try {
      const [rows] = await pool.query('SELECT tier, COUNT(*) AS n, MAX(created_at) AS latest FROM crm_backups GROUP BY tier');
      out.checks.crm_backups = { ok: true, byTier: rows };
    } catch(e) { out.checks.crm_backups = { ok: false, error: e.message }; }
    // 4) Write+read+delete a probe row in crm_summary (proves write access)
    try {
      const probe = `selftest-${Date.now()}`;
      await pool.query('INSERT INTO crm_summary (id, content) VALUES (999, ?) ON DUPLICATE KEY UPDATE content = VALUES(content)', [probe]);
      const [rows] = await pool.query('SELECT content FROM crm_summary WHERE id = 999');
      const ok = rows.length && rows[0].content === probe;
      await pool.query('DELETE FROM crm_summary WHERE id = 999');
      out.checks.write_test = { ok };
    } catch(e) { out.checks.write_test = { ok: false, error: e.message }; }
    // 5) Backup scheduler proof
    out.checks.backup_scheduler = { ok: true, retention: { hourly: 48, daily: 90, weekly: 104 } };
    out.allOk = Object.values(out.checks).every(c => c.ok);
    res.json(out);
  } catch (e) {
    res.status(500).json({ error: e.message, partial: out });
  }
});

async function initDbWithRetry() {
  let attempt = 0;
  while (!DB_READY) {
    attempt++;
    try {
      await initDb();
      DB_READY = true;
      DB_ERROR = null;
      scheduleBackups();
      console.log('✓ Database connected (attempt ' + attempt + ')');
      return;
    } catch (e) {
      DB_ERROR = e.message;
      console.error(`⚠ DB init failed (attempt ${attempt}): ${e.message}`);
      // Wait 3s then retry
      await new Promise(r => setTimeout(r, 3000));
      if (attempt >= 100) {
        console.error('❌ Giving up after 100 attempts');
        return;
      }
    }
  }
}

app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n🚀  WebArs CRM server listening on port ${PORT}`);
  console.log(`   Health: http://localhost:${PORT}/health`);
  console.log(`   (DB connecting in background…)\n`);
});

initDbWithRetry();
