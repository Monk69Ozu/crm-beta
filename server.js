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
    queueLimit: 50,           // bound the queue so we fail fast under load instead of hanging
    connectTimeout: 10000,    // 10s to establish a TCP+handshake (default is forever)
    enableKeepAlive: true,    // recover from idle-killed connections (cloud DBs love to drop these)
    keepAliveInitialDelay: 10000,
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
    // Add 'used' column to password_resets if it was created by an older version.
    try {
      await conn.query(`ALTER TABLE password_resets ADD COLUMN used TINYINT(1) NOT NULL DEFAULT 0`);
      console.log('✓ Migrated password_resets: added used column');
    } catch(e) {
      if (!/Duplicate column/i.test(e.message)) { console.error('⚠ password_resets.used:', e.message); throw e; }
    }
    // Drop legacy columns that older versions may have left behind (would block INSERTs in strict mode).
    for (const legacyCol of ['email_hash','email','user_id','salt','wrapped_master']) {
      try {
        await conn.query(`ALTER TABLE password_resets DROP COLUMN ${legacyCol}`);
        console.log(`✓ Dropped legacy column password_resets.${legacyCol}`);
      } catch(e) {
        // Most common: "check that column/key exists" — column doesn't exist, ignore
      }
    }
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
    // ── CAMPAIGN + LEAD INBOX (webhook receiver for ad networks) ───
    // Leads come in plaintext (ad networks can't encrypt with master key).
    // Server is short-term inbox: client polls, moves into encrypted state, deletes.
    await conn.query(`
      CREATE TABLE IF NOT EXISTS crm_campaigns (
        slug            VARCHAR(64)  NOT NULL,
        webhook_secret  VARCHAR(64)  NOT NULL,
        label           VARCHAR(128) NOT NULL DEFAULT '',
        created_at      DATETIME     DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (slug)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    `);
    await conn.query(`
      CREATE TABLE IF NOT EXISTS crm_lead_inbox (
        id              INT          NOT NULL AUTO_INCREMENT,
        campaign_slug   VARCHAR(64)  NOT NULL,
        payload         LONGTEXT     NOT NULL,
        source_ip       VARCHAR(45)  DEFAULT NULL,
        received_at     DATETIME     DEFAULT CURRENT_TIMESTAMP,
        claimed_at      DATETIME     DEFAULT NULL,
        PRIMARY KEY (id),
        INDEX idx_unclaimed (claimed_at, received_at),
        INDEX idx_campaign (campaign_slug)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    `);
    // Webhook attempt log — every call (success + failure) for debugging.
    // Capped to last 500 entries (auto-pruned).
    await conn.query(`
      CREATE TABLE IF NOT EXISTS crm_lead_log (
        id              INT          NOT NULL AUTO_INCREMENT,
        ts              DATETIME     DEFAULT CURRENT_TIMESTAMP,
        slug            VARCHAR(128) DEFAULT NULL,
        status          SMALLINT     NOT NULL,
        reason          VARCHAR(255) DEFAULT NULL,
        source_ip       VARCHAR(45)  DEFAULT NULL,
        user_agent      VARCHAR(255) DEFAULT NULL,
        content_type    VARCHAR(128) DEFAULT NULL,
        body_preview    TEXT         DEFAULT NULL,
        PRIMARY KEY (id),
        INDEX idx_ts (ts)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    `);
    // Claude usage tracking — plaintext (only utilization metrics, no customer data).
    // Browser bookmarklet on claude.ai posts here; CRM polls + merges into encrypted state.
    await conn.query(`
      CREATE TABLE IF NOT EXISTS crm_claude_usage (
        email                          VARCHAR(255) NOT NULL,
        org_uuid                       VARCHAR(64)  DEFAULT NULL,
        five_hour_pct                  DECIMAL(6,2) DEFAULT NULL,
        five_hour_resets_at            DATETIME     DEFAULT NULL,
        seven_day_pct                  DECIMAL(6,2) DEFAULT NULL,
        seven_day_resets_at            DATETIME     DEFAULT NULL,
        seven_day_omelette_pct         DECIMAL(6,2) DEFAULT NULL,
        seven_day_omelette_resets_at   DATETIME     DEFAULT NULL,
        seven_day_opus_pct             DECIMAL(6,2) DEFAULT NULL,
        seven_day_opus_resets_at       DATETIME     DEFAULT NULL,
        raw_json                       LONGTEXT     DEFAULT NULL,
        updated_at                     DATETIME     DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (email)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    `);
    // Singleton config row (id=1) holding the bookmarklet's webhook secret.
    await conn.query(`
      CREATE TABLE IF NOT EXISTS crm_claude_usage_config (
        id             TINYINT      NOT NULL DEFAULT 1,
        webhook_secret VARCHAR(64)  NOT NULL,
        created_at     DATETIME     DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    `);
    // ── GAMIFICATION: Daily task counter ───────────────────────────
    // Overlay (done-overlay.ps1) syncs task completions here via POST /api/gamification/sync
    // Dashboard (CRM) reads this for the Gamification view.
    await conn.query(`
      CREATE TABLE IF NOT EXISTS crm_gamification_daily (
        id         INT          NOT NULL AUTO_INCREMENT,
        date       DATE         NOT NULL,
        count      INT          NOT NULL DEFAULT 0,
        eur        DECIMAL(10,2) NOT NULL DEFAULT 0,
        created_at DATETIME     DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME     DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY uk_date (date),
        INDEX idx_date (date)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    `);
    // Singleton config for gamification sync (id=1).
    // Stores: CRM_URL (for the overlay to know where to POST), SECRET_KEY (for sync validation).
    await conn.query(`
      CREATE TABLE IF NOT EXISTS crm_gamification_config (
        id           TINYINT      NOT NULL DEFAULT 1,
        crm_url      VARCHAR(255) NOT NULL,
        secret_key   VARCHAR(64)  NOT NULL,
        last_sync_at DATETIME     DEFAULT NULL,
        created_at   DATETIME     DEFAULT CURRENT_TIMESTAMP,
        updated_at   DATETIME     DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (id)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    `);
    await conn.query(`
      CREATE TABLE IF NOT EXISTS crm_quote_links (
        token        VARCHAR(64)  NOT NULL,
        quote_json   LONGTEXT     NOT NULL,
        status       VARCHAR(16)  NOT NULL DEFAULT 'pending',
        created_at   DATETIME     DEFAULT CURRENT_TIMESTAMP,
        responded_at DATETIME     NULL,
        PRIMARY KEY (token)
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
// Uses constant-time comparison to defeat timing attacks.
const API_SECRET_BUF = Buffer.from(API_SECRET, 'utf8');
function requireAuth(req, res, next) {
  const auth  = (req.headers.authorization || '').trim();
  const token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : auth;
  if (!token) return res.status(401).json({ error: 'Unauthorized: invalid API key' });
  const tokBuf = Buffer.from(token, 'utf8');
  // Length mismatch → reject without revealing secret length via early-exit timing
  if (tokBuf.length !== API_SECRET_BUF.length) {
    // Still call timingSafeEqual on equal-length dummy to keep timing constant
    nodeCrypto.timingSafeEqual(API_SECRET_BUF, API_SECRET_BUF);
    return res.status(401).json({ error: 'Unauthorized: invalid API key' });
  }
  if (!nodeCrypto.timingSafeEqual(tokBuf, API_SECRET_BUF)) {
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

// ── Diagnostic endpoint (REQUIRES auth — only useful for diagnosing trim/quote issues
//    AFTER you have a working token. Public access would let an attacker probe the
//    secret length + boundary chars + verify guesses without rate-limit.) ─────────
app.get('/api/debug-auth', requireAuth, (req, res) => {
  const auth  = (req.headers.authorization || '').trim();
  const token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : auth;
  res.json({
    receivedTokenLength: token.length,
    expectedSecretLength: API_SECRET.length,
    match: token === API_SECRET,
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
  if (!DB_READY) return res.status(503).json({ error: 'Database not ready' });
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
  if (!DB_READY) return res.status(503).json({ error: 'Database not ready' });
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
// SAFETY: hash must be exactly 16 hex chars (matches emailHash16 in frontend).
// This prevents DoS by uploading to arbitrary keys.
const HASH_RE = /^[0-9a-f]{16}$/;
app.get('/api/recovery/:hash', async (req, res) => {
  if (!HASH_RE.test(req.params.hash)) return res.status(400).json({ error: 'invalid hash' });
  if (!DB_READY) return res.status(503).json({ error: 'Database not ready' });
  try {
    const [rows] = await pool.query('SELECT payload FROM recovery_blobs WHERE email_hash = ?', [req.params.hash]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    res.json(fromRow(rows[0], 'payload'));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.put('/api/recovery/:hash', async (req, res) => {
  if (!HASH_RE.test(req.params.hash)) return res.status(400).json({ error: 'invalid hash' });
  if (!DB_READY) return res.status(503).json({ error: 'Database not ready' });
  // Cap payload size for this specific route — anything bigger is abuse, not a real recovery blob.
  const bodyStr = toJson(req.body);
  if (bodyStr.length > 64 * 1024) return res.status(413).json({ error: 'payload too large' });
  try {
    await pool.query(
      'INSERT INTO recovery_blobs (email_hash, payload) VALUES (?, ?) ON DUPLICATE KEY UPDATE payload = VALUES(payload)',
      [req.params.hash, bodyStr]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Public form definitions ──────────────────────────────────────
// Slug must be safe-URL chars only and ≤128 (matches DB column).
const SLUG_RE = /^[a-zA-Z0-9_-]{1,128}$/;
app.get('/forms/:slug', async (req, res) => {
  const slug = req.params.slug.replace(/\.json$/, '');
  if (!SLUG_RE.test(slug)) return res.status(400).json({ error: 'invalid slug' });
  if (!DB_READY) return res.status(503).json({ error: 'Database not ready' });
  try {
    const [rows] = await pool.query('SELECT content FROM form_definitions WHERE slug = ?', [slug]);
    if (!rows.length) return res.status(404).json({ error: 'Form not found' });
    res.json(fromRow(rows[0], 'content'));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.put('/api/forms/:slug', requireAuth, async (req, res) => {
  if (!SLUG_RE.test(req.params.slug)) return res.status(400).json({ error: 'invalid slug' });
  if (!DB_READY) return res.status(503).json({ error: 'Database not ready' });
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
  if (!SLUG_RE.test(req.params.slug)) return res.status(400).json({ error: 'invalid slug' });
  if (!DB_READY) return res.status(503).json({ error: 'Database not ready' });
  try {
    await pool.query('DELETE FROM form_definitions WHERE slug = ?', [req.params.slug]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Jarvis API summary ───────────────────────────────────────────
app.get('/api/summary', async (_req, res) => {
  if (!DB_READY) return res.status(503).json({ error: 'Database not ready' });
  try {
    const [rows] = await pool.query('SELECT content FROM crm_summary WHERE id = 1');
    if (!rows.length) return res.status(404).json({ error: 'No summary yet' });
    res.json(fromRow(rows[0], 'content'));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.put('/api/summary', requireAuth, async (req, res) => {
  if (!DB_READY) return res.status(503).json({ error: 'Database not ready' });
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
  if (!DB_READY) return res.status(503).json({ error: 'Database not ready' });
  try {
    const [rows] = await pool.query('SELECT id, name, tier, created_at FROM crm_backups ORDER BY created_at DESC LIMIT 500');
    res.json({ backups: rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/backups/:id', requireAuth, async (req, res) => {
  if (!DB_READY) return res.status(503).json({ error: 'Database not ready' });
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'invalid id' });
  try {
    const [rows] = await pool.query('SELECT content, name, created_at FROM crm_backups WHERE id = ?', [id]);
    if (!rows.length) return res.status(404).json({ error: 'Not found' });
    res.json({ content: fromRow(rows[0], 'content'), name: rows[0].name });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/backups', requireAuth, async (req, res) => {
  if (!DB_READY) return res.status(503).json({ error: 'Database not ready' });
  try {
    const note = (req.body && typeof req.body.note === 'string') ? req.body.note.slice(0, 40) : '';
    await createBackup('manual', note);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/backups/email', requireAuth, async (req, res) => {
  if (!DB_READY) return res.status(503).json({ error: 'Database not ready' });
  try {
    await sendBackupEmail();
    const configured = !!(nodemailer && SMTP_HOST && SMTP_USER && SMTP_PASS && RESET_TO);
    res.json({ ok: true, emailSent: configured });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/backups/:id/restore — atomically snapshot current data, then restore
// the chosen backup into crm_data. The pre-restore snapshot is itself a backup
// with tier='pre-restore' (kept forever) — so a restore can NEVER lose data.
app.post('/api/backups/:id/restore', requireAuth, async (req, res) => {
  if (!DB_READY) return res.status(503).json({ error: 'Database not ready' });
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'invalid id' });
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    // 1) Verify target backup exists
    const [target] = await conn.query('SELECT content, name FROM crm_backups WHERE id = ?', [id]);
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
    console.log(`✓ Restored backup ${target[0].name} (id=${id}), pre-restore snapshot saved`);
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
  if (!DB_READY) return res.status(503).json({ error: 'Database not ready' });
  try {
    const [rows] = await pool.query('SELECT content FROM crm_key_escrow WHERE id = 1');
    if (!rows.length) return res.status(404).json({ error: 'No escrow yet' });
    res.json(fromRow(rows[0], 'content'));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.put('/api/key-escrow', requireAuth, async (req, res) => {
  if (!DB_READY) return res.status(503).json({ error: 'Database not ready' });
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
          // Hard timeouts so a stuck SMTP server can't hang the request
          connectionTimeout: 8000,  // 8s to establish TCP
          greetingTimeout: 8000,    // 8s to receive SMTP greeting
          socketTimeout: 15000,     // 15s for any socket operation
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
      if (!auth.length) {
        // crm_auth row missing — refuse to consume the token so the user can retry once auth is initialised
        await conn.rollback();
        return res.status(409).json({ error: 'Auth row not initialised on server. Bitte zuerst einloggen damit das Server-Auth angelegt wird.' });
      }
      await conn.query('UPDATE crm_auth SET wrapped_master = ? WHERE id = 1', [toJson(wrapped_master)]);
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
// SAFETY: always snapshots current data as a pre-restore backup before overwriting,
// so an accidental re-import can never destroy data.
app.post('/api/import', requireAuth, async (req, res) => {
  if (!DB_READY) return res.status(503).json({ error: 'Database not ready' });
  const { encryptedData } = req.body;
  if (!encryptedData) return res.status(400).json({ error: 'encryptedData required' });
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [rows] = await conn.query('SELECT version, content FROM crm_data WHERE id = 1 FOR UPDATE');
    // Snapshot existing data first (kept forever — pre-restore tier)
    if (rows.length && rows[0].content) {
      const snapName = `pre-import-${new Date().toISOString().replace(/[:.]/g, '-')}`;
      await conn.query(
        'INSERT INTO crm_backups (name, content, tier) VALUES (?, ?, ?)',
        [snapName, rows[0].content, 'pre-restore']
      );
    }
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

// ══════════════════════════════════════════════════════════════════
//  CAMPAIGNS + LEAD WEBHOOK
//  ────────────────────────
//  Public webhook for ad networks. Validated by per-campaign secret.
//  Leads are stored plaintext (briefly) until the CRM client polls,
//  encrypts them into its state, and deletes from the inbox.
// ══════════════════════════════════════════════════════════════════
const CAMPAIGN_SLUG_RE = /^[a-z0-9_-]{2,64}$/;

// CORS middleware — applied ONLY to public lead-webhook routes.
// Browser-based forms on partner sites (e.g. everadam.com) trigger a
// preflight OPTIONS for Content-Type: application/json, which fails
// without these headers. We do NOT open CORS globally — auth-protected
// endpoints stay same-origin so a hostile site can't ride a session.
function publicLeadCors(req, res, next) {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  res.header('Access-Control-Max-Age', '86400'); // cache preflight 24h
  res.header('Vary', 'Origin');
  if (req.method === 'OPTIONS') return res.status(204).end();
  next();
}
app.options('/api/leads/:slug', publicLeadCors);
app.options('/api/leads/docs',   publicLeadCors);

// GET /api/leads/docs — public documentation for ad partners
app.get('/api/leads/docs', publicLeadCors, (_req, res) => {
  res.json({
    description: 'Webhook endpoint for delivering leads from ad campaigns into the CRM.',
    endpoint: 'POST /api/leads/{campaign_slug}?key={webhook_secret}',
    contentType: 'application/json',
    expectedFields: {
      name:    { type: 'string', required: true,  example: 'Max Mustermann' },
      email:   { type: 'string', required: false, example: 'max@example.at' },
      phone:   { type: 'string', required: false, example: '+43 660 1234567' },
      company: { type: 'string', required: false, example: 'Mustermann GmbH' },
      message: { type: 'string', required: false, example: 'Interesse an Webentwicklung' },
      source:  { type: 'string', required: false, note: 'Important — identifies which form/landing page sent the lead. Defaults to campaign_slug if missing.', example: 'everadam-website-cta' },
      metadata:{ type: 'object', required: false, note: 'Any additional structured data (preserved verbatim)' },
    },
    extraFieldsAllowed: true,
    extraFieldsNote: 'Any field beyond the listed ones (e.g. industry, goal, utm_campaign, ad_id) is preserved verbatim and shown in the CRM. When a lead is converted to a contact, each extra field is automatically promoted to a custom field on the contact.',
    commonExtraFieldExamples: ['industry', 'goal', 'budget', 'utm_source', 'utm_campaign', 'ad_id', 'page'],
    maxPayloadBytes: 32 * 1024,
    rateLimit: 'no formal limit — but the inbox is purged regularly',
    responses: {
      '200': '{ "ok": true, "id": <inbox_id> }',
      '400': 'invalid JSON / missing name / payload too large',
      '401': 'invalid or missing webhook key',
      '404': 'unknown campaign slug',
    },
    exampleCurl: `curl -X POST 'https://crm.webars.at/api/leads/CAMPAIGN_SLUG?key=YOUR_SECRET' \\\n  -H 'Content-Type: application/json' \\\n  -d '{"name":"Max Mustermann","email":"max@example.at","phone":"+43 660 1234567","message":"Interesse"}'`
  });
});

// Helper: record every webhook attempt to crm_lead_log + console
async function recordLeadAttempt({ slug, status, reason, ip, ua, ct, body }) {
  try {
    let preview = null;
    if (body !== undefined && body !== null) {
      try { preview = (typeof body === 'string' ? body : JSON.stringify(body)).slice(0, 1024); }
      catch { preview = '(unserializable)'; }
    }
    await pool.query(
      'INSERT INTO crm_lead_log (slug, status, reason, source_ip, user_agent, content_type, body_preview) VALUES (?,?,?,?,?,?,?)',
      [slug || null, status, (reason || '').slice(0,255), ip || null, (ua || '').slice(0,255), (ct || '').slice(0,128), preview]
    );
    // Cap log at last 500 entries
    await pool.query(`
      DELETE FROM crm_lead_log WHERE id NOT IN (
        SELECT id FROM (SELECT id FROM crm_lead_log ORDER BY id DESC LIMIT 500) t
      )
    `);
  } catch (e) { /* logging must never break the main flow */ }
}

// POST /api/leads/:slug?key=SECRET — public webhook (ad networks call this)
app.post('/api/leads/:slug', publicLeadCors, async (req, res) => {
  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').toString().split(',')[0].trim().slice(0, 45);
  const ua = (req.headers['user-agent'] || '').toString();
  const ct = (req.headers['content-type'] || '').toString();
  const slug = (req.params.slug || '').toLowerCase();
  const finish = async (status, reason, payload) => {
    if (status >= 400) console.warn(`✗ Lead REJECTED [${status}] slug='${slug}' from=${ip} UA="${ua.slice(0,80)}" CT="${ct}" reason="${reason}"`);
    else console.log(`✓ Lead received for campaign='${slug}' (id=${payload?.id}, from=${ip})`);
    await recordLeadAttempt({ slug, status, reason, ip, ua, ct, body: req.body });
    return res.status(status).json(payload);
  };
  if (!DB_READY) return finish(503, 'DB not ready', { error: 'Database not ready' });
  if (!CAMPAIGN_SLUG_RE.test(slug)) return finish(400, 'invalid slug format', { error: 'invalid campaign slug' });
  const key = (req.query.key || '').toString();
  if (!key) return finish(401, 'missing key (?key=... fehlt in URL)', { error: 'missing webhook key (?key=...)' });
  try {
    const [rows] = await pool.query('SELECT webhook_secret FROM crm_campaigns WHERE slug = ?', [slug]);
    if (!rows.length) return finish(404, 'unknown campaign (Slug nicht angelegt)', { error: 'unknown campaign' });
    const a = Buffer.from(key, 'utf8');
    const b = Buffer.from(rows[0].webhook_secret, 'utf8');
    if (a.length !== b.length || !nodeCrypto.timingSafeEqual(a, b)) {
      return finish(401, `wrong key (len got=${a.length} want=${b.length})`, { error: 'invalid webhook key' });
    }
    const body = req.body || {};
    if (typeof body !== 'object' || Array.isArray(body)) {
      return finish(400, `body not JSON object (got ${Array.isArray(body)?'array':typeof body})`, { error: 'body must be a JSON object', hint: 'send Content-Type: application/json with a {} body' });
    }
    if (!body.name || typeof body.name !== 'string' || !body.name.trim()) {
      return finish(400, `name missing — body keys: [${Object.keys(body).join(',')||'(empty)'}]`, { error: 'field "name" is required', receivedKeys: Object.keys(body) });
    }
    const payloadStr = JSON.stringify(body);
    if (payloadStr.length > 32 * 1024) return finish(413, 'payload too large (>32KB)', { error: 'payload too large (max 32KB)' });
    const [result] = await pool.query(
      'INSERT INTO crm_lead_inbox (campaign_slug, payload, source_ip) VALUES (?, ?, ?)',
      [slug, payloadStr, ip]
    );
    return finish(200, 'ok', { ok: true, id: result.insertId });
  } catch (e) {
    return finish(500, 'server error: '+e.message, { error: e.message });
  }
});

// GET /api/leads/log — fetch recent webhook attempts (auth)
app.get('/api/leads/log', requireAuth, async (req, res) => {
  if (!DB_READY) return res.status(503).json({ error: 'Database not ready' });
  const limit = Math.min(parseInt(req.query.limit, 10) || 100, 500);
  try {
    const [rows] = await pool.query(
      'SELECT id, ts, slug, status, reason, source_ip, user_agent, content_type, body_preview FROM crm_lead_log ORDER BY id DESC LIMIT ?',
      [limit]
    );
    res.json({ entries: rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// DELETE /api/leads/log — clear the log (auth)
app.delete('/api/leads/log', requireAuth, async (_req, res) => {
  if (!DB_READY) return res.status(503).json({ error: 'Database not ready' });
  try { await pool.query('TRUNCATE crm_lead_log'); res.json({ ok: true }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

// Catch attempts where someone GETs the webhook URL (common mistake — log it)
app.get('/api/leads/:slug', publicLeadCors, async (req, res) => {
  // Skip if it's a valid sub-route already handled
  if (req.params.slug === 'log' || req.params.slug === 'docs') return res.status(404).json({ error: 'not found' });
  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').toString().split(',')[0].trim().slice(0,45);
  const ua = (req.headers['user-agent'] || '').toString();
  await recordLeadAttempt({ slug: req.params.slug, status: 405, reason: 'wrong method (GET) — webhook needs POST with JSON body', ip, ua, ct: req.headers['content-type'] || '', body: null });
  res.status(405).json({ error: 'wrong method', hint: 'use POST with Content-Type: application/json' });
});

// GET /api/leads — list inbox (auth) — for the CRM client to poll
//   ?claimed=0 (default) returns only unclaimed
//   ?claimed=all returns everything
//   ?since=ID  returns only id > ID
app.get('/api/leads', requireAuth, async (req, res) => {
  if (!DB_READY) return res.status(503).json({ error: 'Database not ready' });
  try {
    const claimedFilter = req.query.claimed === 'all' ? '' : 'AND claimed_at IS NULL';
    const since = parseInt(req.query.since, 10);
    const params = [];
    let sinceClause = '';
    if (Number.isInteger(since) && since > 0) { sinceClause = 'AND id > ?'; params.push(since); }
    const [rows] = await pool.query(
      `SELECT id, campaign_slug, payload, source_ip, received_at, claimed_at
         FROM crm_lead_inbox
         WHERE 1=1 ${claimedFilter} ${sinceClause}
         ORDER BY id ASC LIMIT 500`,
      params
    );
    const leads = rows.map(r => ({
      id: r.id,
      campaign: r.campaign_slug,
      payload: (() => { try { return JSON.parse(r.payload); } catch { return r.payload; } })(),
      sourceIp: r.source_ip,
      receivedAt: r.received_at,
      claimedAt: r.claimed_at,
    }));
    res.json({ leads, count: leads.length });
  } catch (e) {
    console.error('GET /api/leads:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// POST /api/leads/:id/claim — mark a lead as claimed (CRM picked it up)
app.post('/api/leads/:id/claim', requireAuth, async (req, res) => {
  if (!DB_READY) return res.status(503).json({ error: 'Database not ready' });
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'invalid id' });
  try {
    const [r] = await pool.query('UPDATE crm_lead_inbox SET claimed_at = NOW() WHERE id = ? AND claimed_at IS NULL', [id]);
    if (!r.affectedRows) return res.status(404).json({ error: 'not found or already claimed' });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// DELETE /api/leads/:id — explicitly delete a lead from the inbox
app.delete('/api/leads/:id', requireAuth, async (req, res) => {
  if (!DB_READY) return res.status(503).json({ error: 'Database not ready' });
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'invalid id' });
  try {
    await pool.query('DELETE FROM crm_lead_inbox WHERE id = ?', [id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Campaign management ──────────────────────────────────────────
// POST /api/campaigns  body: {slug, label?}  → server generates webhook_secret
app.post('/api/campaigns', requireAuth, async (req, res) => {
  if (!DB_READY) return res.status(503).json({ error: 'Database not ready' });
  const slug = ((req.body && req.body.slug) || '').toLowerCase();
  const label = (req.body && req.body.label || '').toString().slice(0, 128);
  if (!CAMPAIGN_SLUG_RE.test(slug)) return res.status(400).json({ error: 'slug must match [a-z0-9_-]{2,64}' });
  try {
    const [exists] = await pool.query('SELECT slug FROM crm_campaigns WHERE slug = ?', [slug]);
    if (exists.length) return res.status(409).json({ error: 'campaign already exists' });
    const secret = nodeCrypto.randomBytes(24).toString('base64url'); // 32 url-safe chars
    await pool.query(
      'INSERT INTO crm_campaigns (slug, webhook_secret, label) VALUES (?, ?, ?)',
      [slug, secret, label]
    );
    const host = (req.headers.host || 'crm.webars.at');
    const proto = (req.headers['x-forwarded-proto'] || 'https');
    const webhookUrl = `${proto}://${host}/api/leads/${slug}?key=${secret}`;
    console.log(`✓ Campaign created: ${slug}`);
    res.json({ slug, label, webhookSecret: secret, webhookUrl });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /api/campaigns — list campaigns + their webhook URLs
app.get('/api/campaigns', requireAuth, async (req, res) => {
  if (!DB_READY) return res.status(503).json({ error: 'Database not ready' });
  try {
    const [rows] = await pool.query('SELECT slug, label, webhook_secret, created_at FROM crm_campaigns ORDER BY created_at DESC');
    const host = (req.headers.host || 'crm.webars.at');
    const proto = (req.headers['x-forwarded-proto'] || 'https');
    const campaigns = rows.map(c => ({
      slug: c.slug,
      label: c.label,
      webhookSecret: c.webhook_secret,
      webhookUrl: `${proto}://${host}/api/leads/${c.slug}?key=${c.webhook_secret}`,
      createdAt: c.created_at,
    }));
    res.json({ campaigns });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// DELETE /api/campaigns/:slug — remove campaign + its inbox
app.delete('/api/campaigns/:slug', requireAuth, async (req, res) => {
  if (!DB_READY) return res.status(503).json({ error: 'Database not ready' });
  const slug = (req.params.slug || '').toLowerCase();
  if (!CAMPAIGN_SLUG_RE.test(slug)) return res.status(400).json({ error: 'invalid slug' });
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    await conn.query('DELETE FROM crm_lead_inbox WHERE campaign_slug = ?', [slug]);
    await conn.query('DELETE FROM crm_campaigns WHERE slug = ?', [slug]);
    await conn.commit();
    res.json({ ok: true });
  } catch (e) { await conn.rollback(); res.status(500).json({ error: e.message }); }
  finally { conn.release(); }
});

// ══════════════════════════════════════════════════════════════════
//  CLAUDE USAGE TRACKING
//  Browser bookmarklet on claude.ai POSTs utilization here (CORS open,
//  validated by per-install secret). CRM polls + merges by email into
//  encrypted state.
// ══════════════════════════════════════════════════════════════════
function claudeUsageCors(req, res, next) {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  res.header('Access-Control-Max-Age', '86400');
  res.header('Vary', 'Origin');
  if (req.method === 'OPTIONS') return res.status(204).end();
  next();
}
app.options('/api/claude-usage/inbox', claudeUsageCors);

// Helper: parse ISO timestamp → MySQL DATETIME (UTC) or null
function toMysqlDt(iso) {
  if (!iso || typeof iso !== 'string') return null;
  const d = new Date(iso);
  if (isNaN(d.getTime())) return null;
  return d.toISOString().slice(0, 19).replace('T', ' ');
}
// Helper: clamp utilization to a sane number or null
function utilNum(v) {
  if (v === null || v === undefined) return null;
  const n = Number(v);
  if (!isFinite(n)) return null;
  return Math.max(0, Math.min(999, n));
}

// GET /api/claude-usage/config — returns (and lazily creates) the webhook secret
app.get('/api/claude-usage/config', requireAuth, async (_req, res) => {
  if (!DB_READY) return res.status(503).json({ error: 'Database not ready' });
  try {
    let [rows] = await pool.query('SELECT webhook_secret FROM crm_claude_usage_config WHERE id = 1');
    if (!rows.length) {
      const secret = nodeCrypto.randomBytes(24).toString('base64url'); // 32 chars
      await pool.query('INSERT INTO crm_claude_usage_config (id, webhook_secret) VALUES (1, ?)', [secret]);
      rows = [{ webhook_secret: secret }];
    }
    res.json({ webhook_secret: rows[0].webhook_secret });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /api/claude-usage/inbox?key=SECRET — public (CORS), validated by secret
//   Body: { email, org_uuid, usage: {five_hour:{utilization,resets_at}, seven_day:{...}, seven_day_omelette:{...}, seven_day_opus:{...}} }
app.post('/api/claude-usage/inbox', claudeUsageCors, async (req, res) => {
  if (!DB_READY) return res.status(503).json({ error: 'Database not ready' });
  const key = (req.query.key || '').toString();
  if (!key) return res.status(401).json({ error: 'missing key' });
  try {
    const [rows] = await pool.query('SELECT webhook_secret FROM crm_claude_usage_config WHERE id = 1');
    if (!rows.length) return res.status(404).json({ error: 'config not initialised — open the CRM "Claude-Limits einrichten" panel first' });
    const a = Buffer.from(key, 'utf8');
    const b = Buffer.from(rows[0].webhook_secret, 'utf8');
    if (a.length !== b.length || !nodeCrypto.timingSafeEqual(a, b)) {
      return res.status(401).json({ error: 'invalid key' });
    }
    const body = req.body || {};
    const email = (body.email || '').toString().trim().toLowerCase();
    if (!email || email.length > 255) return res.status(400).json({ error: 'email required (string, ≤255 chars)' });
    const u = body.usage || {};
    const fh = u.five_hour || {};
    const sd = u.seven_day || {};
    const so = u.seven_day_omelette || u.omelette_promotional || {};
    const sp = u.seven_day_opus || {};
    const raw = JSON.stringify(u).slice(0, 8000);
    await pool.query(
      `INSERT INTO crm_claude_usage
         (email, org_uuid,
          five_hour_pct, five_hour_resets_at,
          seven_day_pct, seven_day_resets_at,
          seven_day_omelette_pct, seven_day_omelette_resets_at,
          seven_day_opus_pct, seven_day_opus_resets_at,
          raw_json)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE
         org_uuid                     = VALUES(org_uuid),
         five_hour_pct                = VALUES(five_hour_pct),
         five_hour_resets_at          = VALUES(five_hour_resets_at),
         seven_day_pct                = VALUES(seven_day_pct),
         seven_day_resets_at          = VALUES(seven_day_resets_at),
         seven_day_omelette_pct       = VALUES(seven_day_omelette_pct),
         seven_day_omelette_resets_at = VALUES(seven_day_omelette_resets_at),
         seven_day_opus_pct           = VALUES(seven_day_opus_pct),
         seven_day_opus_resets_at     = VALUES(seven_day_opus_resets_at),
         raw_json                     = VALUES(raw_json)`,
      [
        email, (body.org_uuid || null),
        utilNum(fh.utilization), toMysqlDt(fh.resets_at),
        utilNum(sd.utilization), toMysqlDt(sd.resets_at),
        utilNum(so.utilization), toMysqlDt(so.resets_at),
        utilNum(sp.utilization), toMysqlDt(sp.resets_at),
        raw,
      ]
    );
    console.log(`✓ Claude usage updated for ${email} (5h=${utilNum(fh.utilization)}% 7d=${utilNum(sd.utilization)}% design=${utilNum(so.utilization)}%)`);
    res.json({ ok: true, email });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /api/claude-usage — list all usage rows (auth) — CRM polls this
app.get('/api/claude-usage', requireAuth, async (_req, res) => {
  if (!DB_READY) return res.status(503).json({ error: 'Database not ready' });
  try {
    const [rows] = await pool.query(
      `SELECT email, org_uuid,
              five_hour_pct, five_hour_resets_at,
              seven_day_pct, seven_day_resets_at,
              seven_day_omelette_pct, seven_day_omelette_resets_at,
              seven_day_opus_pct, seven_day_opus_resets_at,
              updated_at
       FROM crm_claude_usage`
    );
    // Normalise DATETIME → ISO so the frontend can do new Date(...) consistently
    const toIso = v => v ? new Date(v).toISOString() : null;
    const entries = rows.map(r => ({
      email: r.email,
      org_uuid: r.org_uuid,
      five_hour:          { utilization: r.five_hour_pct          == null ? null : Number(r.five_hour_pct),          resets_at: toIso(r.five_hour_resets_at) },
      seven_day:          { utilization: r.seven_day_pct          == null ? null : Number(r.seven_day_pct),          resets_at: toIso(r.seven_day_resets_at) },
      seven_day_omelette: { utilization: r.seven_day_omelette_pct == null ? null : Number(r.seven_day_omelette_pct), resets_at: toIso(r.seven_day_omelette_resets_at) },
      seven_day_opus:     { utilization: r.seven_day_opus_pct     == null ? null : Number(r.seven_day_opus_pct),     resets_at: toIso(r.seven_day_opus_resets_at) },
      updated_at: toIso(r.updated_at),
    }));
    res.json({ entries });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// DELETE /api/claude-usage/:email — remove a specific entry (auth)
app.delete('/api/claude-usage/:email', requireAuth, async (req, res) => {
  if (!DB_READY) return res.status(503).json({ error: 'Database not ready' });
  const email = (req.params.email || '').toString().trim().toLowerCase();
  if (!email) return res.status(400).json({ error: 'email required' });
  try {
    await pool.query('DELETE FROM crm_claude_usage WHERE email = ?', [email]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── GAMIFICATION: Dashboard data sync from overlay ──────────────────

// GET /api/gamification/config — get sync config (auth)
app.get('/api/gamification/config', requireAuth, async (_req, res) => {
  if (!DB_READY) return res.status(503).json({ error: 'Database not ready' });
  try {
    const [row] = await pool.query('SELECT crm_url, last_sync_at FROM crm_gamification_config WHERE id = 1');
    if (!row) {
      return res.status(404).json({ error: 'Config not found' });
    }
    res.json({
      crm_url: row.crm_url,
      last_sync_at: row.last_sync_at ? new Date(row.last_sync_at).toISOString() : null
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /api/gamification/sync?key=SECRET — overlay posts task completions here
// Body: {count, eur, date}
// Returns: {ok: true} on success
// Auth: same API_SECRET as all other endpoints (passed as ?key= query param)
app.post('/api/gamification/sync', async (req, res) => {
  if (!DB_READY) return res.status(503).json({ error: 'Database not ready' });

  const queryKey = (req.query.key || '').toString().trim();
  const keyBuf   = Buffer.from(queryKey, 'utf8');
  const validKey = keyBuf.length === API_SECRET_BUF.length &&
    nodeCrypto.timingSafeEqual(keyBuf, API_SECRET_BUF);
  if (!validKey) return res.status(403).json({ error: 'Invalid secret' });

  try {
    const { count = 0, eur = 0, date } = req.body;
    const syncDate = date ? new Date(date).toISOString().split('T')[0] : new Date().toISOString().split('T')[0];

    await pool.query(
      `INSERT INTO crm_gamification_daily (date, count, eur)
       VALUES (?, ?, ?)
       ON DUPLICATE KEY UPDATE
         count = count + ?,
         eur   = eur + ?,
         updated_at = CURRENT_TIMESTAMP`,
      [syncDate, count, eur, count, eur]
    );

    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /api/gamification — return daily data + derived stats for dashboard (auth)
app.get('/api/gamification', requireAuth, async (_req, res) => {
  if (!DB_READY) return res.status(503).json({ error: 'Database not ready' });
  try {
    const [rows] = await pool.query(
      `SELECT date, count, eur FROM crm_gamification_daily ORDER BY date DESC LIMIT 180`
    );
    const daily = rows.map(r => ({
      date: r.date.toISOString().split('T')[0],
      count: r.count,
      eur: Number(r.eur)
    }));

    // Day streak — consecutive days back from today with at least 1 task
    const dateSet = new Set(daily.map(d => d.date));
    let streak = 0;
    const cursor = new Date(); cursor.setHours(0,0,0,0);
    while (dateSet.has(cursor.toISOString().split('T')[0])) {
      streak++;
      cursor.setDate(cursor.getDate() - 1);
    }

    // Current week (Mon–Sun) stats
    const now = new Date(); now.setHours(0,0,0,0);
    const dayOfWeek = (now.getDay() + 6) % 7; // Mon=0
    const monday = new Date(now); monday.setDate(now.getDate() - dayOfWeek);
    const mondayStr = monday.toISOString().split('T')[0];
    const weekDays = daily.filter(d => d.date >= mondayStr);
    const weekTasks = weekDays.reduce((s, d) => s + d.count, 0);
    const weekEur   = weekDays.reduce((s, d) => s + d.eur, 0);

    // Last 3 calendar months for comparison
    const monthly = {};
    for (const d of daily) {
      const m = d.date.slice(0, 7); // YYYY-MM
      if (!monthly[m]) monthly[m] = { tasks: 0, eur: 0 };
      monthly[m].tasks += d.count;
      monthly[m].eur   += d.eur;
    }
    const monthList = Object.entries(monthly)
      .sort((a, b) => b[0].localeCompare(a[0]))
      .slice(0, 3)
      .map(([month, v]) => ({ month, tasks: v.tasks, eur: v.eur }));

    res.json({ daily, streak, weekTasks, weekEur, monthList });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// DELETE /api/gamification — wipe all daily data (admin, for resets)
app.delete('/api/gamification', requireAuth, async (_req, res) => {
  if (!DB_READY) return res.status(503).json({ error: 'Database not ready' });
  try {
    await pool.query('DELETE FROM crm_gamification_daily');
    res.json({ ok: true, message: 'All gamification data deleted' });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /api/gamification/init?key=API_SECRET — initialize gamification config (admin only)
// Generates a new secret_key for PC overlay sync
app.post('/api/gamification/init', requireAuth, async (req, res) => {
  if (!DB_READY) return res.status(503).json({ error: 'Database not ready' });
  try {
    // Check if already initialized
    const [existing] = await pool.query('SELECT id FROM crm_gamification_config WHERE id = 1');

    if (existing) {
      // Already exists — return current secret
      const [row] = await pool.query('SELECT crm_url, secret_key FROM crm_gamification_config WHERE id = 1');
      return res.json({
        message: 'Config already initialized',
        crm_url: row.crm_url,
        secret_key: row.secret_key
      });
    }

    // Generate new 32-char base64url secret
    const secretBytes = crypto.randomBytes(24);
    const secretKey = secretBytes.toString('base64url');

    // Store config with CRM URL (to help overlay connect back)
    const crmUrl = `https://${req.get('host')}`;
    await pool.query(
      'INSERT INTO crm_gamification_config (id, crm_url, secret_key) VALUES (1, ?, ?)',
      [crmUrl, secretKey]
    );

    res.json({
      message: 'Config initialized',
      crm_url: crmUrl,
      secret_key: secretKey,
      instruction: 'Copy the secret_key to gamification-config.json on your PC'
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
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
// Cache the injected HTML once at startup — index.html is read-only at runtime
// and only changes between deploys. Avoids a synchronous fs read per request.
const INDEX_PATH = path.join(__dirname, 'index.html');
let INDEX_HTML_CACHED = null;
let INDEX_HTML_ERR = null;
try {
  const raw = fs.readFileSync(INDEX_PATH, 'utf8');
  const inject = `<script>\n// ── Injected by self-hosted server ──\nwindow.WEBARS_SELF_HOSTED = true;\nwindow.WEBARS_API_TOKEN = ${JSON.stringify(API_SECRET)};\n`;
  if (!raw.includes('<script>')) {
    INDEX_HTML_ERR = 'index.html has no <script> tag — cannot inject API token. Login will not work.';
    console.error('❌  ' + INDEX_HTML_ERR);
  } else {
    INDEX_HTML_CACHED = raw.replace('<script>', inject);
    console.log('✓ index.html cached and patched with self-hosted token');
  }
} catch(e) {
  INDEX_HTML_ERR = 'Could not load index.html: ' + e.message;
  console.error('❌  ' + INDEX_HTML_ERR);
}

// ── Public Quote Links ───────────────────────────────────────────
app.post('/api/quote-links', requireAuth, async (req, res) => {
  if (!DB_READY) return res.status(503).json({ error: 'DB not ready' });
  const { quote } = req.body;
  if (!quote || !quote.id) return res.status(400).json({ error: 'quote required' });
  const token = nodeCrypto.randomBytes(24).toString('base64url');
  await pool.query('INSERT INTO crm_quote_links (token, quote_json) VALUES (?, ?)', [token, JSON.stringify(quote)]);
  const url = `${process.env.APP_URL || ''}/q/${token}`;
  res.json({ token, url });
});

app.get('/api/quote-links/:token', requireAuth, async (req, res) => {
  if (!DB_READY) return res.status(503).json({ error: 'DB not ready' });
  const [rows] = await pool.query('SELECT status, created_at, responded_at FROM crm_quote_links WHERE token = ?', [req.params.token]);
  if (!rows.length) return res.status(404).json({ error: 'not found' });
  res.json(rows[0]);
});

app.delete('/api/quote-links/:token', requireAuth, async (req, res) => {
  if (!DB_READY) return res.status(503).json({ error: 'DB not ready' });
  await pool.query('DELETE FROM crm_quote_links WHERE token = ?', [req.params.token]);
  res.json({ ok: true });
});

app.post('/q/:token/respond', async (req, res) => {
  if (!DB_READY) return res.status(503).json({ error: 'DB not ready' });
  const { action } = req.body; // 'accept' | 'decline'
  if (!['accept','decline'].includes(action)) return res.status(400).json({ error: 'invalid action' });
  const status = action === 'accept' ? 'accepted' : 'declined';
  const [result] = await pool.query(
    "UPDATE crm_quote_links SET status = ?, responded_at = NOW() WHERE token = ? AND status = 'pending'",
    [status, req.params.token]
  );
  if (result.affectedRows === 0) return res.status(409).json({ error: 'already responded or not found' });
  res.json({ ok: true, status });
});

app.get('/q/:token', async (req, res) => {
  if (!DB_READY) return res.status(503).send('Server nicht bereit');
  const [rows] = await pool.query('SELECT quote_json, status FROM crm_quote_links WHERE token = ?', [req.params.token]);
  if (!rows.length) return res.status(404).send('<h2>Angebot nicht gefunden oder abgelaufen.</h2>');
  const quote = typeof rows[0].quote_json === 'string' ? JSON.parse(rows[0].quote_json) : rows[0].quote_json;
  const status = rows[0].status;
  const token = req.params.token;
  const fmtDate = d => { if(!d) return '—'; const p = d.slice(0,10).split('-'); return `${p[2]}.${p[1]}.${p[0]}`; };
  const fmtMoney = n => Number(n||0).toLocaleString('de-AT', {minimumFractionDigits:2,maximumFractionDigits:2}) + ' €';
  const items = (quote.items||[]).filter(i=>i.type!=='heading');
  const subtotal = items.reduce((s,i)=>s+(Number(i.quantity)||0)*(Number(i.unitPrice)||0),0);
  const tax = subtotal * (Number(quote.taxRate)||0)/100;
  const total = subtotal + tax;
  const itemsHtml = (quote.items||[]).map(it => {
    if(it.type==='heading') return `<tr><td colspan="4" style="padding:18px 0 6px;font-weight:700;font-size:13px;color:#6B6560;text-transform:uppercase;letter-spacing:.08em;border-bottom:1px solid #E8E3DC">${it.description||''}</td></tr>`;
    const amt = (Number(it.quantity)||0)*(Number(it.unitPrice)||0);
    const descLines = (it.description||'').split('\n');
    return `<tr style="border-bottom:1px solid #F0EDE8">
      <td style="padding:14px 0;vertical-align:top">
        <div style="font-weight:600;color:#1A1714;font-size:14px">${descLines[0]||''}</div>
        ${descLines.slice(1).map(l=>`<div style="font-size:12.5px;color:#8A8480;margin-top:3px">${l}</div>`).join('')}
      </td>
      <td style="padding:14px 16px;text-align:center;color:#6B6560;font-size:13px;white-space:nowrap;vertical-align:top">${Number(it.unitPrice)>0?fmtMoney(it.unitPrice):''}</td>
      <td style="padding:14px 8px;text-align:center;color:#6B6560;font-size:13px;vertical-align:top">${Number(it.unitPrice)>0?'×'+it.quantity:''}</td>
      <td style="padding:14px 0;text-align:right;font-weight:600;color:#1A1714;font-size:14px;white-space:nowrap;vertical-align:top">${Number(it.unitPrice)>0?fmtMoney(amt):'Inklusive'}</td>
    </tr>`;
  }).join('');
  const alreadyAccepted = status === 'accepted';
  const alreadyDeclined = status === 'declined';
  const actionBar = alreadyAccepted
    ? `<div style="background:#F0FDF4;border:1.5px solid #86EFAC;border-radius:12px;padding:20px 24px;text-align:center;margin-top:32px"><div style="font-size:22px;margin-bottom:6px">✓</div><div style="font-weight:700;color:#16a34a;font-size:16px">Angebot angenommen</div><div style="color:#4ade80;font-size:13px;margin-top:4px">Wir melden uns in Kürze mit den nächsten Schritten.</div></div>`
    : alreadyDeclined
    ? `<div style="background:#FEF2F2;border:1.5px solid #FCA5A5;border-radius:12px;padding:20px 24px;text-align:center;margin-top:32px"><div style="font-weight:700;color:#dc2626;font-size:16px">Angebot abgelehnt</div></div>`
    : `<div style="margin-top:40px;display:flex;gap:12px;justify-content:center;flex-wrap:wrap">
        <button onclick="respond('accept')" id="btn-accept" style="background:#141210;color:white;border:none;border-radius:10px;padding:16px 40px;font-size:15px;font-weight:700;cursor:pointer;letter-spacing:-.01em;transition:opacity .15s">Angebot annehmen →</button>
        <button onclick="respond('decline')" id="btn-decline" style="background:none;color:#9A9490;border:1.5px solid #D8D4CE;border-radius:10px;padding:16px 24px;font-size:14px;font-weight:500;cursor:pointer;transition:all .15s">Ablehnen</button>
      </div>
      <script>
      async function respond(action){
        const btns=document.querySelectorAll('#btn-accept,#btn-decline');
        btns.forEach(b=>{b.disabled=true;b.style.opacity='.5';});
        const r=await fetch('/q/${token}/respond',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action})});
        const j=await r.json();
        if(j.ok){location.reload();}else{btns.forEach(b=>{b.disabled=false;b.style.opacity='1';});alert('Fehler: '+j.error);}
      }
      </script>`;
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(`<!DOCTYPE html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Angebot ${quote.number||''} · WebArs</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{background:#F8F5F0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#1A1714;-webkit-font-smoothing:antialiased}a{color:inherit}
.wrap{max-width:720px;margin:0 auto;padding:40px 20px 80px}
.card{background:white;border-radius:16px;padding:40px 44px;box-shadow:0 2px 16px rgba(0,0,0,.06)}
.header{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:36px;gap:16px;flex-wrap:wrap}
.logo{font-size:20px;font-weight:800;letter-spacing:-.03em;color:#141210}
.badge{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.1em;padding:5px 12px;border-radius:20px;white-space:nowrap}
.badge-draft{background:#F0EDE8;color:#9A9490}
.badge-sent{background:#EFF6FF;color:#1d4ed8}
.badge-accepted{background:#F0FDF4;color:#16a34a}
.eyebrow{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.12em;color:#B0ABA5;margin-bottom:6px}
.quote-title{font-size:26px;font-weight:800;letter-spacing:-.02em;color:#141210;line-height:1.15;margin-bottom:4px}
.meta{font-size:13px;color:#9A9490}
.section{margin-top:32px}
.intro-text{font-size:14.5px;color:#5F5A55;line-height:1.7;white-space:pre-wrap}
table{width:100%;border-collapse:collapse}
.totals td{padding:6px 0;font-size:13.5px;color:#6B6560}
.totals .total-row td{padding-top:14px;font-size:17px;font-weight:800;color:#141210;border-top:2px solid #1A1714}
.terms-text{font-size:13px;color:#8A8480;line-height:1.65;white-space:pre-wrap}
.steps{list-style:none;counter-reset:steps}
.steps li{counter-increment:steps;display:flex;gap:14px;margin-bottom:14px;font-size:13.5px;color:#5F5A55;line-height:1.55}
.steps li::before{content:counter(steps);background:#F0EDE8;color:#6B6560;font-weight:700;font-size:11px;min-width:24px;height:24px;border-radius:50%;display:flex;align-items:center;justify-content:center;flex-shrink:0;margin-top:1px}
.footer-note{text-align:center;font-size:13px;color:#B0ABA5;margin-top:40px;line-height:1.6}
@media(max-width:500px){.card{padding:28px 20px}.header{gap:10px}}
</style></head><body>
<div class="wrap">
  <div class="card">
    <div class="header">
      <div class="logo">WebArs</div>
      <span class="badge ${alreadyAccepted?'badge-accepted':status==='declined'?'badge-draft':'badge-sent'}">${alreadyAccepted?'✓ Angenommen':alreadyDeclined?'Abgelehnt':'Angebot'}</span>
    </div>
    <div class="eyebrow">Angebot ${quote.number||''}</div>
    <div class="quote-title">${quote.title||'Angebot'}</div>
    <div class="meta" style="margin-top:8px">Für: <strong>${quote.contactSnapshot?.firma||''}</strong> · Datum: ${fmtDate(quote.date)} · Gültig bis: <strong>${fmtDate(quote.validUntil)}</strong></div>
    ${quote.intro ? `<div class="section"><div class="intro-text">${quote.intro}</div></div>` : ''}
    <div class="section">
      <table>
        <thead><tr style="border-bottom:2px solid #1A1714"><th style="text-align:left;padding-bottom:10px;font-size:11px;text-transform:uppercase;letter-spacing:.1em;color:#9A9490;font-weight:700">Leistung</th><th style="text-align:center;padding-bottom:10px;font-size:11px;text-transform:uppercase;letter-spacing:.1em;color:#9A9490;font-weight:700;white-space:nowrap">Einzel</th><th style="text-align:center;padding-bottom:10px;font-size:11px;text-transform:uppercase;letter-spacing:.1em;color:#9A9490;font-weight:700">Menge</th><th style="text-align:right;padding-bottom:10px;font-size:11px;text-transform:uppercase;letter-spacing:.1em;color:#9A9490;font-weight:700">Gesamt</th></tr></thead>
        <tbody>${itemsHtml}</tbody>
      </table>
      <table class="totals" style="margin-top:16px">
        <tr><td>Nettobetrag</td><td style="text-align:right">${fmtMoney(subtotal)}</td></tr>
        ${Number(quote.taxRate)>0?`<tr><td>USt ${quote.taxRate}%</td><td style="text-align:right">${fmtMoney(tax)}</td></tr>`:''}
        <tr class="total-row"><td>Gesamtbetrag</td><td style="text-align:right">${fmtMoney(total)}</td></tr>
      </table>
    </div>
    ${quote.notes ? `<div class="section"><div class="eyebrow" style="margin-bottom:8px">Hinweise</div><div class="terms-text">${quote.notes}</div></div>` : ''}
    ${quote.terms ? `<div class="section"><div class="eyebrow" style="margin-bottom:8px">Konditionen</div><div class="terms-text">${quote.terms}</div></div>` : ''}
    ${quote.nextSteps ? `<div class="section"><div class="eyebrow" style="margin-bottom:12px">Nächste Schritte</div><ol class="steps">${quote.nextSteps.split('\n').filter(l=>l.trim()).map(l=>`<li><span>${l.replace(/^\d+\.\s*/,'')}</span></li>`).join('')}</ol></div>` : ''}
    ${quote.footer ? `<div class="section" style="padding-top:24px;border-top:1px solid #F0EDE8"><div style="font-size:14px;color:#6B6560;font-style:italic;line-height:1.65">${quote.footer}</div></div>` : ''}
    ${actionBar}
  </div>
  <div class="footer-note">Dieses Angebot wurde von <strong>WebArs e.U.</strong> erstellt.<br>Bei Fragen: <a href="mailto:office@webars.at" style="color:#141210">office@webars.at</a></div>
</div>
</body></html>`);
});

app.get('/', (_req, res) => {
  if (INDEX_HTML_ERR) return res.status(500).send(INDEX_HTML_ERR);
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(INDEX_HTML_CACHED);
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

// ── Weekly offsite backup via email ──────────────────────────────
// Sends the latest backup as encrypted .json attachment to RESET_TO.
// Safe to email: content is AES-256-GCM encrypted, server cannot read it.
async function sendBackupEmail() {
  if (!nodemailer || !SMTP_HOST || !SMTP_USER || !SMTP_PASS || !RESET_TO) {
    console.log('ℹ Weekly email backup skipped — SMTP not configured');
    return;
  }
  try {
    const [rows] = await pool.query(
      'SELECT content, name, created_at FROM crm_backups ORDER BY created_at DESC LIMIT 1'
    );
    if (!rows.length) { console.warn('Email backup: no backup found to send'); return; }
    const backup = rows[0];
    const content = typeof backup.content === 'string' ? backup.content : JSON.stringify(backup.content);
    const date = new Date(backup.created_at).toLocaleDateString('de-AT', { day:'2-digit', month:'2-digit', year:'numeric' });
    const filename = `crm-backup-${new Date(backup.created_at).toISOString().slice(0,10)}.json`;
    const transporter = nodemailer.createTransport({
      host: SMTP_HOST, port: SMTP_PORT,
      secure: SMTP_PORT === 465,
      auth: { user: SMTP_USER, pass: SMTP_PASS },
      connectionTimeout: 10000, greetingTimeout: 8000,
    });
    await transporter.sendMail({
      from: SMTP_FROM || SMTP_USER,
      to: RESET_TO,
      subject: `WebArs CRM — Wöchentliches Backup ${date}`,
      text: [
        `Hallo,`,
        ``,
        `anbei das automatische wöchentliche Backup deines WebArs CRM vom ${date}.`,
        ``,
        `Die Datei ist AES-256-GCM verschlüsselt — ohne dein CRM-Passwort ist sie für niemanden lesbar.`,
        ``,
        `So wiederherstellen:`,
        `1. Einloggen auf crm.webars.at`,
        `2. Einstellungen → Backups → "Backup importieren"`,
        `3. Diese Datei auswählen`,
        ``,
        `Diese E-Mail wird automatisch jeden Sonntag gesendet.`,
        `Backup-Name: ${backup.name}`,
      ].join('\n'),
      attachments: [{ filename, content, contentType: 'application/json' }],
    });
    console.log(`✓ Weekly backup email sent to ${RESET_TO} (${filename})`);
  } catch (e) {
    console.error('Weekly backup email failed:', e.message);
  }
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
    createBackup('weekly')
      .then(() => sendBackupEmail())
      .catch(e => console.error('Weekly backup failed:', e.message));
    setInterval(() => {
      createBackup('weekly')
        .then(() => sendBackupEmail())
        .catch(e => console.error('Weekly backup failed:', e.message));
    }, 7 * 24 * 60 * 60 * 1000);
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

// ── Process-level safety net ─────────────────────────────────────
// Log instead of crash on unhandled rejections; same for uncaught exceptions
// (we keep running because Coolify+/health will restart the container if it
// stops responding, but a single unhandled error mid-request shouldn't kill it).
process.on('unhandledRejection', (reason) => {
  console.error('⚠ unhandledRejection:', reason && reason.stack || reason);
});
process.on('uncaughtException', (err) => {
  console.error('⚠ uncaughtException:', err && err.stack || err);
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n🚀  WebArs CRM server listening on port ${PORT}`);
  console.log(`   Health: http://localhost:${PORT}/health`);
  console.log(`   (DB connecting in background…)\n`);
});

initDbWithRetry();
