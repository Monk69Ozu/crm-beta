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

const express    = require('express');
const mysql      = require('mysql2/promise');
const path       = require('path');
const fs         = require('fs');
const nodeCrypto = require('crypto');

// Nodemailer is optional — if missing, reset links are logged to console instead
let nodemailer = null;
try { nodemailer = require('nodemailer'); } catch(e) {
  console.warn('⚠ nodemailer not installed — password reset links will be logged to console');
}

const app  = express();
const PORT = process.env.PORT || 3000;
const API_SECRET = (process.env.API_SECRET || '').trim();

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
        token      VARCHAR(64)  NOT NULL,
        email_hash VARCHAR(32)  NOT NULL,
        expires_at DATETIME     NOT NULL,
        PRIMARY KEY (token)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    `);
    // Add email-reset columns to recovery_blobs (idempotent — ignore if already exist)
    for (const ddl of [
      'ALTER TABLE recovery_blobs ADD COLUMN email_reset_key VARCHAR(256) DEFAULT NULL',
      'ALTER TABLE recovery_blobs ADD COLUMN email_reset_enc LONGTEXT DEFAULT NULL',
    ]) {
      try { await conn.query(ddl); } catch(e) { /* column already exists — ignore */ }
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
    // Conflict check: if caller sent a version and it doesn't match → 409
    if (version !== null && version !== undefined && Number(version) !== currentVer) {
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
    const [rows] = await pool.query('SELECT id, name, created_at FROM crm_backups ORDER BY created_at DESC LIMIT 30');
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

app.post('/api/backups', requireAuth, async (_req, res) => {
  try {
    await createBackup();
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Master-Key Escrow (encrypted with API_SECRET-derived key) ────
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

// ── Email-reset data (no auth — stored by client after login) ────
// Check if reset data exists for a given email hash
app.get('/api/recovery/:hash/email-reset', async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT (email_reset_key IS NOT NULL) AS has_reset FROM recovery_blobs WHERE email_hash = ?',
      [req.params.hash]
    );
    res.json({ has_reset: rows.length > 0 && rows[0].has_reset === 1 });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// Store reset data (client pushes after login; never overwrites existing data)
app.put('/api/recovery/:hash/email-reset', async (req, res) => {
  const { email_reset_key, email_reset_enc } = req.body;
  if (!email_reset_key || !email_reset_enc) {
    return res.status(400).json({ error: 'email_reset_key and email_reset_enc required' });
  }
  try {
    // MySQL: only set if currently NULL (don't overwrite once established)
    await pool.query(
      `INSERT INTO recovery_blobs (email_hash, payload, email_reset_key, email_reset_enc)
       VALUES (?, '{}', ?, ?)
       ON DUPLICATE KEY UPDATE
         email_reset_key = IF(email_reset_key IS NULL, VALUES(email_reset_key), email_reset_key),
         email_reset_enc = IF(email_reset_enc IS NULL, VALUES(email_reset_enc), email_reset_enc)`,
      [req.params.hash, email_reset_key, email_reset_enc]
    );
    res.json({ ok: true });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// Trigger a password-reset email for a given email hash
app.post('/api/forgot-password', async (req, res) => {
  const { email, emailHash } = req.body;
  if (!emailHash) return res.status(400).json({ error: 'emailHash required' });
  try {
    // Look up reset data (don't reveal if hash exists)
    const [rows] = await pool.query(
      'SELECT email_reset_key FROM recovery_blobs WHERE email_hash = ? AND email_reset_key IS NOT NULL',
      [emailHash]
    );
    if (!rows.length) {
      return res.json({ ok: true, hint: 'no_reset_data' });
    }

    // Generate a one-time token (64 hex chars, valid 1 hour)
    const token     = nodeCrypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000);
    await pool.query(
      'INSERT INTO password_resets (token, email_hash, expires_at) VALUES (?, ?, ?)',
      [token, emailHash, expiresAt.toISOString().slice(0, 19).replace('T', ' ')]
    );
    // Clean up expired tokens
    await pool.query('DELETE FROM password_resets WHERE expires_at < NOW()');

    // Build reset URL — prefer SMTP_RESET_BASE_URL env var, then Origin header, then fallback
    const baseUrl   = (process.env.SMTP_RESET_BASE_URL || '').replace(/\/$/, '')
                      || (req.headers.origin || 'https://crm.webars.at');
    const resetUrl  = `${baseUrl}/?reset=${token}`;
    const recipient = email || 'CRM-Administrator';

    // Try to send email; fall back to console logging
    let emailSent = false;
    if (nodemailer && process.env.SMTP_HOST) {
      try {
        const transporter = nodemailer.createTransport({
          host:   process.env.SMTP_HOST,
          port:   parseInt(process.env.SMTP_PORT) || 587,
          secure: parseInt(process.env.SMTP_PORT) === 465,
          auth:   { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
        });
        await transporter.sendMail({
          from:    process.env.SMTP_FROM || process.env.SMTP_USER,
          to:      email || process.env.SMTP_FROM || process.env.SMTP_USER,
          subject: 'WebArs CRM – Passwort zurücksetzen',
          html: `
            <p>Hallo,</p>
            <p>Du hast eine Passwort-Zurücksetzung für dein WebArs CRM angefordert.</p>
            <p><a href="${resetUrl}" style="font-size:16px;font-weight:bold">→ Passwort zurücksetzen</a></p>
            <p style="color:#888;font-size:12px">Dieser Link ist 1 Stunde gültig und kann nur einmal verwendet werden.<br>
            URL: ${resetUrl}</p>
          `,
          text: `WebArs CRM – Passwort zurücksetzen\n\nLink: ${resetUrl}\n\n(Gültig 1 Stunde, einmalig verwendbar)`
        });
        emailSent = true;
        console.log(`✓ Password reset email sent to ${email || 'configured SMTP recipient'}`);
      } catch(e) {
        console.error('❌ Email send failed:', e.message);
      }
    }

    if (!emailSent) {
      console.log(`\n${'═'.repeat(60)}`);
      console.log(`  PASSWORT-RESET LINK (kein SMTP konfiguriert)`);
      console.log(`  Empfänger: ${recipient}`);
      console.log(`  Link: ${resetUrl}`);
      console.log(`  Gültig bis: ${expiresAt.toISOString()}`);
      console.log(`${'═'.repeat(60)}\n`);
    }

    res.json({ ok: true, emailSent });
  } catch(e) {
    console.error('POST /api/forgot-password:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// Validate a reset token and return the email-reset key + enc (one-time)
app.get('/api/reset-token/:token', async (req, res) => {
  try {
    const [tokenRows] = await pool.query(
      'SELECT email_hash, expires_at FROM password_resets WHERE token = ?',
      [req.params.token]
    );
    if (!tokenRows.length) {
      return res.status(404).json({ error: 'Token ungültig oder bereits verwendet.' });
    }
    if (new Date(tokenRows[0].expires_at) < new Date()) {
      await pool.query('DELETE FROM password_resets WHERE token = ?', [req.params.token]);
      return res.status(410).json({ error: 'Token abgelaufen. Bitte neuen Reset anfordern.' });
    }
    const [resetRows] = await pool.query(
      'SELECT email_reset_key, email_reset_enc FROM recovery_blobs WHERE email_hash = ?',
      [tokenRows[0].email_hash]
    );
    if (!resetRows.length || !resetRows[0].email_reset_key) {
      return res.status(404).json({ error: 'Keine Reset-Daten gefunden. Bitte zuerst einloggen.' });
    }
    // Invalidate token immediately (one-time use)
    await pool.query('DELETE FROM password_resets WHERE token = ?', [req.params.token]);

    res.json({
      email_reset_key: resetRows[0].email_reset_key,
      email_reset_enc: resetRows[0].email_reset_enc,
    });
  } catch(e) {
    console.error('GET /api/reset-token:', e.message);
    res.status(500).json({ error: e.message });
  }
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
async function createBackup() {
  const [rows] = await pool.query('SELECT content FROM crm_data WHERE id = 1');
  if (!rows.length) return;
  const name = `backup-${new Date().toISOString().slice(0, 10)}`;
  await pool.query(
    'INSERT INTO crm_backups (name, content) VALUES (?, ?) ON DUPLICATE KEY UPDATE content = VALUES(content), created_at = NOW()',
    [name, rows[0].content]
  );
  // Keep only last 30 backups
  await pool.query(`
    DELETE FROM crm_backups WHERE id NOT IN (
      SELECT id FROM (SELECT id FROM crm_backups ORDER BY created_at DESC LIMIT 30) t
    )
  `);
  console.log(`✓ Daily backup created: ${name}`);
}

// ── Daily backup cron (runs at 02:00 UTC each day) ───────────────
function scheduleDailyBackup() {
  const now  = new Date();
  const next = new Date(now);
  next.setUTCHours(2, 0, 0, 0);
  if (next <= now) next.setUTCDate(next.getUTCDate() + 1);
  setTimeout(() => {
    createBackup().catch(e => console.error('Daily backup failed:', e.message));
    setInterval(
      () => createBackup().catch(e => console.error('Daily backup failed:', e.message)),
      24 * 60 * 60 * 1000
    );
  }, next - now);
  console.log(`✓ Daily backup scheduled (next: ${next.toISOString()})`);
}

// ── Start: listen IMMEDIATELY, init DB in background with retries ──
let DB_READY = false;
let DB_ERROR = null;

app.get('/health', (_req, res) => {
  res.json({ ok: true, dbReady: DB_READY, dbError: DB_ERROR, ts: Date.now() });
});

async function initDbWithRetry() {
  let attempt = 0;
  while (!DB_READY) {
    attempt++;
    try {
      await initDb();
      DB_READY = true;
      DB_ERROR = null;
      scheduleDailyBackup();
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
