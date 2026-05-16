# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Running the server

```bash
node server.js          # production
node --watch server.js  # dev (auto-restart on file change)
```

Required env vars (see `.env.example`):
- `DATABASE_URL` — `mysql://user:pass@host:3306/dbname`
- `API_SECRET` — bearer token the frontend sends on every API call (user never types this)
- `PORT` — defaults to 3000

Optional for email password-reset:
- `APP_URL`, `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM`, `RESET_TO`

## Deployment

Push to `main` → Coolify auto-builds the Docker image and deploys to **crm.webars.at**.
No manual steps needed. Health check: `GET /health` (no auth).

The Dockerfile is a two-stage `node:20-alpine` build. Only `server.js`, `index.html`, `package.json`, `jarvis_crm_tools.js`, and `logo.png` are copied into the image. `curl` is installed for the Coolify healthcheck.

### Required Coolify env vars
- `DATABASE_URL` — MySQL connection string
- `API_SECRET` — bearer token (≥32 random chars). **DO NOT CHANGE after first init** — it is the only key that can decrypt `crm_auth.escrow_blob` for password recovery.
- `APP_URL=https://crm.webars.at` — used in password reset emails (without this the link points to localhost, but the frontend reconstructs it from `window.location.origin` as a fallback).

### Lock-out recovery paths (defence in depth)
1. **Forgot password** (UI) → email link → re-wrap escrow with new password
2. **No email?** → POST `/api/forgot-password` returns the link in the response when SMTP isn't configured
3. **Lost everything?** → SSH into server → query `crm_auth.escrow_blob` → decrypt with `PBKDF2(API_SECRET, 'webars-key-escrow-v1', 100000)` → master key recovered

### Self-test
`GET /api/selftest` (auth required) verifies:
- `crm_data` row count + version
- `crm_auth` row exists
- backups by tier + last update
- write/read probe on `crm_summary`
Returns `allOk: true` only when everything passes.

## Architecture

### Two-file application
- **`server.js`** (~1000 lines) — Express + mysql2. All business logic and API routes.
- **`index.html`** (~8000 lines) — Entire React frontend in a single file. No build step; React 18 + Babel Standalone are loaded via CDN. UI language is **German**.

### Self-hosted injection (cached at startup)
When the server boots it reads `index.html` once, injects into the first `<script>` tag:
```js
window.WEBARS_SELF_HOSTED = true;
window.WEBARS_API_TOKEN = "<API_SECRET>";
```
…and serves the cached patched HTML on every `GET /`. If `<script>` tag is missing the server logs a fatal warning at startup (silent login breakage prevented). Frontend code checks `const SELF_HOSTED = !!window.WEBARS_SELF_HOSTED` to branch between self-hosted (MySQL via API) and the legacy GitHub Pages mode.

### Client-side encryption (AES-256-GCM) — auth-blob model
All CRM data is encrypted in the browser. Server only sees opaque blobs.

**Single source of truth: `crm_auth` table (one row, id=1) on the server.**
Same password works on every device, forever — no per-device localStorage salt.

Columns:
- `salt` — base64 PBKDF2 salt (32 random bytes), GLOBAL
- `wrapped_master` — `{iv, data}` master key encrypted with `PBKDF2(password, salt, 600k)`
- `escrow_blob` — `{iv, data}` master key encrypted with `PBKDF2(API_SECRET, 'webars-key-escrow-v1', 100k)` — used only by the password-reset email flow
- `pbkdf2_iter` — iteration count (default 600 000)

**Login flow (self-hosted):**
1. `GET /api/auth-blob` → `{salt, wrapped_master, pbkdf2_iter}`
2. `wrap_key = PBKDF2(password, salt, iter)`
3. `master_key = AES-decrypt(wrap_key, wrapped_master)`

**Password change:** re-wrap master with new password → `PUT /api/auth-blob` with new `wrapped_master`. Salt + escrow stay (master key never changes).

**Forgot password:** `POST /api/forgot-password` → email link with token → frontend gets `{salt, escrow_blob, pbkdf2_iter}` → derives escrow key from `WEBARS_API_TOKEN` → decrypts escrow → re-wraps with new password → `POST /api/reset-token/:t/confirm` with new `wrapped_master`. The confirm endpoint **refuses to consume the token** if `crm_auth` row is missing (prevents silent lock-out where the user thinks reset succeeded but auth wasn't initialised).

**Auto-migration:** if a device has local `MASTER_KEY_STORE`+`SALT_KEY` but server `crm_auth` is empty, `ensureServerAuthMigrated()` pushes the local master key + a fresh salt to the server on next successful `verifyPassword`.

**Local cache** — `SALT_KEY`, `VERIFY_KEY`, `MASTER_KEY_STORE` are kept in `localStorage` purely for offline reads after a successful online login. Server is always source of truth.

**Auto-login** — raw master key still stored in `sessionStorage` (`DEVICE_KEY_STORE`) for fast unlock on the same device.

**Legacy:** `crm_key_escrow` table + `/api/key-escrow` endpoints are kept for read-only fallback (old reset tokens). New code never writes to them.

### State management
`CRMApp` holds a single `state` object. The `upd(patch)` helper shallow-merges a patch and triggers an auto-save via `useEffect → saveEncrypted`. The encrypted blob is written to `localStorage` and synced to `PUT /api/data` with optimistic locking (`version` field).

**Important — `version=null` guard:** `PUT /api/data` returns `409 EXISTING_DATA` when the client sends `version=null` (fresh browser). The frontend must call `GET /api/data` first to retrieve the current version before writing.

**Important — `loadEncrypted` safeguards:**
1. Throws `KEY_MISMATCH` (not just `null`) when the wrap key can't decrypt server data — prevents silent fall-through to `DEFAULT_STATE` that would then overwrite the cloud blob.
2. Updates `_ghSha` *only* after successful decrypt — prevents wrong-key sessions from advancing the version pointer.
3. Compares `_savedAt` timestamps before overwriting local with cloud — if local is newer (e.g. previous PUT 409'd), keeps local edits and bumps `_ghSha` so the next save wins.

`LockOverlay.submit` and `AuthScreen.submit` both catch `KEY_MISMATCH` explicitly and show a user-readable error instead of hanging.

### Adding new top-level state fields
When adding a new collection to `state`, update it in **5 places** inside `index.html`:
1. `DEFAULT_STATE` constant
2. `useState` initialisation in `CRMApp`
3. `refreshFromCloud` setState callback
4. `GithubSyncModal` / `onSaved` setState callback
5. `SnapshotRestoreModal` `onRestore` setState callback

All five must hydrate the new field with a safe default (`|| []`, `|| {}`, etc.).

### Sidebar views
String constants (`TODOS_VIEW`, `AI_VIEW`, `CLAUDE_VIEW`, `QUOTES_VIEW`, `INVOICES_VIEW`, `TOKENS_VIEW`, `FORMS_VIEW`, `CAMPAIGNS_VIEW`, `LEADS_VIEW`) control which panel is active. The `activeId` state is compared against these strings in a chain of ternary renderers at the bottom of `CRMApp`.

### Modal pattern
`setModal('someName')` opens a modal. Render site checks `modal === 'someName' && <SomeModal onClose={()=>setModal(null)}/>`.

### MySQL tables
| Table | Purpose |
|---|---|
| `crm_auth` | Source-of-truth auth row (id=1): salt + wrapped_master + escrow_blob + iter |
| `crm_data` | Single encrypted blob (id=1), optimistic lock via `version BIGINT` |
| `crm_key_escrow` | LEGACY — read-only fallback for old reset tokens (id=1) |
| `password_resets` | One-time tokens for the "Passwort vergessen" flow (expire after 1 h). `used` column auto-migrated via `ALTER TABLE ADD COLUMN` if missing from older schemas |
| `recovery_blobs` | Legacy recovery by email hash (no auth — content is client-encrypted; hash must match `^[0-9a-f]{16}$`; payload capped at 64 KB) |
| `form_definitions` | Public intake forms (slug → content) |
| `crm_summary` | Plain-text summary for the Jarvis API (id=1) |
| `crm_backups` | **APPEND-ONLY** snapshots with `tier` column. Tiers: `hourly` (48), `daily` (90), `weekly` (104), `manual` (∞), `pre-restore` (∞), `legacy` (∞). Per-tier retention only |
| `crm_campaigns` | Lead-webhook campaigns. `slug` (PK) + `webhook_secret` (32-char base64url, server-generated) + `label`. Plaintext — needed for webhook validation |
| `crm_lead_inbox` | Short-term inbox for incoming leads (plaintext until CRM client polls + encrypts into `state.leads` + claims/deletes server-side) |
| `crm_lead_log` | Webhook attempt audit log — capped at 500 entries (auto-pruned). Records every POST + helpful 405 GET attempts with status, reason, IP, UA, content-type, body preview |

### API routes (all require `Authorization: Bearer <API_SECRET>` unless noted)
| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | `/health` | none | dbReady flag |
| GET | `/api/debug-auth` | **yes** | Diagnose token mismatches (auth-protected to avoid secret-probing attacks) |
| GET | `/api/auth-blob` | none | Returns `{exists, salt, wrapped_master, pbkdf2_iter}` — public so login form can fetch salt |
| POST | `/api/auth-blob/init` | yes | One-time setup. Refuses 409 if row exists |
| PUT | `/api/auth-blob` | yes | Update `wrapped_master` (password change) |
| GET/PUT | `/api/data` | yes | Encrypted CRM blob |
| GET/PUT | `/api/recovery/:hash` | none | Recovery blob. Hash must be 16 hex chars, payload ≤64 KB |
| GET | `/forms/:slug` | none | Public form (slug regex `^[a-zA-Z0-9_-]{1,128}$`) |
| PUT/DELETE | `/api/forms/:slug` | yes | Manage forms |
| GET/PUT | `/api/summary` | none/yes | Jarvis summary |
| GET/POST | `/api/backups` | yes | List (up to 500) / trigger manual backup |
| GET | `/api/backups/:id` | yes | Download backup |
| POST | `/api/backups/:id/restore` | yes | **Atomic snapshot-then-restore**. Always creates a `pre-restore` backup of current state first |
| GET/PUT | `/api/key-escrow` | yes | LEGACY — kept for old reset tokens only |
| POST | `/api/forgot-password` | none | Generate reset token, email link |
| GET | `/api/reset-token/:token` | none | Returns `{scheme:'auth-blob-v1', salt, escrow, pbkdf2_iter}` (or `scheme:'legacy'`) |
| POST | `/api/reset-token/:token/confirm` | none | Body: `{wrapped_master}`. Atomically updates `crm_auth` + marks token used. Refuses with 409 if `crm_auth` row missing |
| POST | `/api/import` | yes | Import encrypted blob. **Always snapshots existing data as `pre-restore` first** (symmetric with `/restore`) |
| POST | `/api/admin/reset` | yes | ⛔ **PERMANENTLY DISABLED** — returns 410 |
| GET | `/api/selftest` | yes | Deep DB health check |
| **GET** | **`/api/leads/docs`** | **none** | Public JSON docs for ad partners (CORS-enabled) |
| **POST** | **`/api/leads/:slug`** | **secret** | Public webhook — validates `?key=<secret>` against `crm_campaigns.webhook_secret` (constant-time compare). Body must be JSON with `name` field. 32 KB cap. CORS-enabled. Every attempt logged to `crm_lead_log` (incl. failures with diagnostic context) |
| GET | `/api/leads/:slug` | none | Returns 405 + hint (catches the common "colleague tried GET" mistake) — also logged |
| GET | `/api/leads` | yes | List inbox (`?claimed=0` default, `?since=ID`, `?claimed=all`) |
| POST | `/api/leads/:id/claim` | yes | Mark inbox entry as claimed (CRM polled it) |
| DELETE | `/api/leads/:id` | yes | Hard-delete from inbox |
| POST/GET/DELETE | `/api/campaigns` (`:slug`) | yes | Manage campaigns. POST auto-generates 32-char `base64url` secret. DELETE also wipes the campaign's inbox |
| GET | `/api/leads/log` | yes | Recent webhook attempts (default 100, max 500) |
| DELETE | `/api/leads/log` | yes | Clear the log |

### CORS policy
CORS is **NOT** globally enabled. It is opened only for the public lead-webhook routes:
- `POST /api/leads/:slug` (+ OPTIONS preflight)
- `GET /api/leads/:slug` (the 405-with-hint catcher)
- `GET /api/leads/docs`

Everything else stays same-origin — prevents hostile sites from riding an authenticated user's session.

### Security hardening
- `requireAuth` uses `crypto.timingSafeEqual` with length-padding (no early-exit timing leak)
- Webhook secrets compared with `crypto.timingSafeEqual` likewise
- MySQL pool: `connectTimeout: 10s`, `queueLimit: 50` (bounded — fail fast under load), `enableKeepAlive: true` (cloud DBs idle-kill connections)
- Process-level `unhandledRejection` + `uncaughtException` handlers log instead of crash
- Every DB-touching endpoint guards with `if (!DB_READY) return 503` — no 500-on-startup-race

### Lead pipeline data flow (Werbekampagnen)
1. User creates campaign in CRM → `POST /api/campaigns` → server generates secret → row in `crm_campaigns`
2. CRM displays `https://crm.webars.at/api/leads/<slug>?key=<secret>` — user gives this to ad partner
3. Ad partner / landing page POSTs JSON → CORS preflight → validated against `crm_campaigns.webhook_secret` → inserted into `crm_lead_inbox` (plaintext) + logged to `crm_lead_log`
4. `LeadsView` in browser polls `GET /api/leads` every 30 s while user is logged in
5. Unknown inbox IDs are imported into `state.leads` (now inside the encrypted blob) and immediately claimed via `POST /api/leads/:id/claim`
6. User clicks "→ Kontakt" → all extra fields (e.g. `industry`, `goal`) are auto-promoted to `customFields` definitions on the contact (case-insensitive label match to avoid duplicates) + full audit block written to `notizen`

The server schema for leads is **future-proof**: `crm_lead_inbox.payload` is `LONGTEXT` holding the full JSON, no migration needed for new fields. The `LeadsView` shows ALL extras visibly (not behind a `<details>` toggle).

### BlockEditor (Notizen & Ideen)
Critical performance note for `function BlockEditor`:
- Textarea `ref` callbacks must only **store** the element (`blockRefs.current[id] = el`), never resize
- Auto-resize for individual textareas happens in `onChange` (only the active one)
- Bulk-resize for all textareas happens in `useLayoutEffect` keyed on `[file.id, blocks.length]` — NOT on every render
- This prevents scroll-position jumping while typing in long notes (was the bug — every keystroke resized every textarea, causing layout reflow that pushed scroll to top)

### Styles
- CSS variables defined in `:root` — dark sidebar `#0F0E0C`, warm background `#F3F0EB`.
- Utility classes: `.btn`, `.btn-primary`, `.btn-ghost`, `.btn-danger`, `.btn-sm`, `.btn-icon`.
- Modal wrapper: `.modal-overlay > .modal-box`.
- Status colours use `_STATUS` constant objects `{key, label, color, bg, dot}`.

### Static assets
- `logo.png` — used on all 4 auth screens (Login, Setup, ForgotPassword, Reset) at `/logo.png`. Also serves as favicon via `<link rel="icon">` in `<head>`.
- Served via `express.static(__dirname)` — must be copied in the Dockerfile or browsers see broken icons.
