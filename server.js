'use strict';
// ══════════════════════════════════════════════════════════════════
//  WebArs CRM — Self-Hosted Server (Express + PostgreSQL)
//  Replaces GitHub as the storage backend for Coolify deployment.
//
//  Required environment variables:
//    DATABASE_URL  — PostgreSQL connection string
//                    e.g. postgresql://user:pass@host:5432/dbname
//    API_SECRET    — Secret key the CRM frontend sends as Bearer token
//    PORT          — (optional) defaults to 3000
// ══════════════════════════════════════════════════════════════════

const express = require('express');
const { Pool } = require('pg');
const path    = require('path');
const fs      = require('fs');
const crypto  = require('crypto');

const app  = express();
const PORT = process.env.PORT || 3000;
const API_SECRET = (process.env.API_SECRET || '').trim();

if (!API_SECRET) {
  console.error('❌  FATAL: API_SECRET environment variable is not set. Refusing to start.');
  process.exit(1);
}

// ── PostgreSQL ───────────────────────────────────────────────────
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

pool.on('error', (err) => {
  console.error('Unexpected PostgreSQL error:', err.message);
});

// ── Database initialisation ──────────────────────────────────────
async function initDb() {
  const client = await pool.connect();
  try {
    await client.query(`
      -- Main CRM data blob (single encrypted row)
      CREATE TABLE IF NOT EXISTS crm_data (
        id         INTEGER PRIMARY KEY DEFAULT 1,
        content    JSONB    NOT NULL,
        version    BIGINT   NOT NULL DEFAULT 1,
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );

      -- Password-recovery blobs keyed by hashed email
      CREATE TABLE IF NOT EXISTS recovery_blobs (
        email_hash VARCHAR(32) PRIMARY KEY,
        blob       JSONB       NOT NULL,
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );

      -- Published public form definitions
      CREATE TABLE IF NOT EXISTS form_definitions (
        slug       VARCHAR(128) PRIMARY KEY,
        content    JSONB        NOT NULL,
        updated_at TIMESTAMPTZ  DEFAULT NOW()
      );

      -- Jarvis API summary (single row, updated on every CRM save)
      CREATE TABLE IF NOT EXISTS crm_summary (
        id         INTEGER PRIMARY KEY DEFAULT 1,
        content    JSONB    NOT NULL,
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );

      -- Daily automatic backups (encrypted blobs)
      CREATE TABLE IF NOT EXISTS crm_backups (
        id         SERIAL       PRIMARY KEY,
        name       VARCHAR(64)  NOT NULL UNIQUE,
        content    JSONB        NOT NULL,
        created_at TIMESTAMPTZ  DEFAULT NOW()
      );
    `);
    console.log('✓ Database tables ready');
  } finally {
    client.release();
  }
}

// ── Middleware ───────────────────────────────────────────────────
app.use(express.json({ limit: '20mb' }));

// Serve static files (forms/*.json legacy compat handled by route below)
// We intentionally do NOT use express.static for / so we can inject SELF_HOSTED flag

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

// ── Health / validate ────────────────────────────────────────────
app.get('/api/validate', requireAuth, (_req, res) => {
  res.json({ ok: true });
});

// ── CRM data (encrypted blob) ────────────────────────────────────
app.get('/api/data', requireAuth, async (_req, res) => {
  try {
    const r = await pool.query(
      'SELECT content, version FROM crm_data WHERE id = 1'
    );
    if (r.rows.length === 0) return res.json({ content: null, version: 0 });
    res.json({ content: r.rows[0].content, version: r.rows[0].version });
  } catch (e) {
    console.error('GET /api/data:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// Optimistic-locking write: pass current version to prevent conflicts.
// If version is null the client doesn't care → always overwrite.
app.put('/api/data', requireAuth, async (req, res) => {
  const { content, version } = req.body;
  if (!content) return res.status(400).json({ error: 'content is required' });
  try {
    // INSERT or UPDATE with version check
    const r = await pool.query(`
      INSERT INTO crm_data (id, content, version) VALUES (1, $1, 1)
      ON CONFLICT (id) DO UPDATE
        SET content    = EXCLUDED.content,
            version    = crm_data.version + 1,
            updated_at = NOW()
        WHERE ($2::bigint IS NULL OR crm_data.version = $2::bigint)
      RETURNING version
    `, [content, version ?? null]);

    if (r.rows.length === 0) {
      // Another client saved in the meantime
      return res.status(409).json({ error: 'Conflict: data was modified by another device' });
    }
    res.json({ version: r.rows[0].version });
  } catch (e) {
    console.error('PUT /api/data:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// Lightweight version-only poll (used by background sync)
app.get('/api/data/version', requireAuth, async (_req, res) => {
  try {
    const r = await pool.query('SELECT version FROM crm_data WHERE id = 1');
    res.json({ version: r.rows.length ? r.rows[0].version : 0 });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Recovery blobs (no auth — content is client-side encrypted) ──
app.get('/api/recovery/:hash', async (req, res) => {
  try {
    const r = await pool.query(
      'SELECT blob FROM recovery_blobs WHERE email_hash = $1',
      [req.params.hash]
    );
    if (r.rows.length === 0) return res.status(404).json({ error: 'Not found' });
    res.json(r.rows[0].blob);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.put('/api/recovery/:hash', async (req, res) => {
  try {
    await pool.query(`
      INSERT INTO recovery_blobs (email_hash, blob) VALUES ($1, $2)
      ON CONFLICT (email_hash) DO UPDATE SET blob = EXCLUDED.blob, updated_at = NOW()
    `, [req.params.hash, req.body]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Public form definitions ──────────────────────────────────────
// Accessible without auth so external visitors can fill out forms
app.get('/forms/:slug', async (req, res) => {
  const slug = req.params.slug.replace(/\.json$/, ''); // accept /forms/x.json too
  try {
    const r = await pool.query(
      'SELECT content FROM form_definitions WHERE slug = $1', [slug]
    );
    if (r.rows.length === 0) return res.status(404).json({ error: 'Form not found' });
    res.json(r.rows[0].content);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.put('/api/forms/:slug', requireAuth, async (req, res) => {
  try {
    await pool.query(`
      INSERT INTO form_definitions (slug, content) VALUES ($1, $2)
      ON CONFLICT (slug) DO UPDATE SET content = EXCLUDED.content, updated_at = NOW()
    `, [req.params.slug, req.body]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/forms/:slug', requireAuth, async (req, res) => {
  try {
    await pool.query('DELETE FROM form_definitions WHERE slug = $1', [req.params.slug]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Jarvis API summary ───────────────────────────────────────────
// GET is intentionally open (summary is read by Jarvis with its own token)
app.get('/api/summary', async (_req, res) => {
  try {
    const r = await pool.query('SELECT content FROM crm_summary WHERE id = 1');
    if (r.rows.length === 0) return res.status(404).json({ error: 'No summary yet' });
    res.json(r.rows[0].content);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.put('/api/summary', requireAuth, async (req, res) => {
  try {
    await pool.query(`
      INSERT INTO crm_summary (id, content) VALUES (1, $1)
      ON CONFLICT (id) DO UPDATE SET content = EXCLUDED.content, updated_at = NOW()
    `, [req.body]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Backups ──────────────────────────────────────────────────────
app.get('/api/backups', requireAuth, async (_req, res) => {
  try {
    const r = await pool.query(
      'SELECT id, name, created_at FROM crm_backups ORDER BY created_at DESC LIMIT 30'
    );
    res.json({ backups: r.rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/backups/:id', requireAuth, async (req, res) => {
  try {
    const r = await pool.query(
      'SELECT content, name, created_at FROM crm_backups WHERE id = $1',
      [req.params.id]
    );
    if (r.rows.length === 0) return res.status(404).json({ error: 'Not found' });
    res.json({ content: r.rows[0].content, name: r.rows[0].name });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Manual backup trigger (also called by the daily cron inside this server)
app.post('/api/backups', requireAuth, async (_req, res) => {
  try {
    await createBackup();
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Import JSON backup from old GitHub-based CRM ─────────────────
// POST /api/import  body: { encryptedData: <the raw encrypted JSON object> }
app.post('/api/import', requireAuth, async (req, res) => {
  const { encryptedData } = req.body;
  if (!encryptedData) return res.status(400).json({ error: 'encryptedData required' });
  try {
    // Just store it as the current CRM data (user will decrypt in browser)
    const r = await pool.query(`
      INSERT INTO crm_data (id, content, version) VALUES (1, $1, 1)
      ON CONFLICT (id) DO UPDATE SET content = EXCLUDED.content,
        version = crm_data.version + 1, updated_at = NOW()
      RETURNING version
    `, [encryptedData]);
    res.json({ ok: true, version: r.rows[0].version });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Frontend (inject SELF_HOSTED flag) ───────────────────────────
const INDEX_PATH = path.join(__dirname, 'index.html');

app.get('/', (_req, res) => {
  try {
    let html = fs.readFileSync(INDEX_PATH, 'utf8');
    // Inject self-hosted flag BEFORE the main script runs
    html = html.replace(
      '<script>',
      '<script>\n// ── Injected by self-hosted server ──\nwindow.WEBARS_SELF_HOSTED = true;\n'
    );
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(html);
  } catch (e) {
    res.status(500).send('Could not load index.html: ' + e.message);
  }
});

// Serve other static assets (CSS, JS, images) if any
app.use(express.static(__dirname, {
  index: false, // we handle / ourselves above
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.html')) res.setHeader('Cache-Control', 'no-store');
  }
}));

// ── Backup helper ────────────────────────────────────────────────
async function createBackup() {
  const r = await pool.query('SELECT content FROM crm_data WHERE id = 1');
  if (r.rows.length === 0) return; // nothing to back up yet
  const name = `backup-${new Date().toISOString().slice(0, 10)}`;
  await pool.query(`
    INSERT INTO crm_backups (name, content) VALUES ($1, $2)
    ON CONFLICT (name) DO UPDATE SET content = EXCLUDED.content, created_at = NOW()
  `, [name, r.rows[0].content]);
  // Keep only last 30 backups
  await pool.query(`
    DELETE FROM crm_backups WHERE id NOT IN (
      SELECT id FROM crm_backups ORDER BY created_at DESC LIMIT 30
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
  const msUntilFirst = next - now;
  setTimeout(() => {
    createBackup().catch(e => console.error('Daily backup failed:', e.message));
    setInterval(
      () => createBackup().catch(e => console.error('Daily backup failed:', e.message)),
      24 * 60 * 60 * 1000
    );
  }, msUntilFirst);
  console.log(`✓ Daily backup scheduled (next: ${next.toISOString()})`);
}

// ── Start ────────────────────────────────────────────────────────
async function start() {
  try {
    await initDb();
    scheduleDailyBackup();
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`\n🚀  WebArs CRM server running on port ${PORT}`);
      console.log(`   Open: http://localhost:${PORT}`);
      console.log(`   API:  http://localhost:${PORT}/api/validate\n`);
    });
  } catch (e) {
    console.error('Startup failed:', e.message);
    process.exit(1);
  }
}

start();
