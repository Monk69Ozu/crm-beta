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

The Dockerfile is a two-stage node:20-alpine build. Only `server.js`, `index.html`, `package.json`, and `jarvis_crm_tools.js` are copied into the image.

## Architecture

### Two-file application
- **`server.js`** (~600 lines) — Express + mysql2. All business logic and API routes.
- **`index.html`** (~7200 lines) — Entire React frontend in a single file. No build step; React 18 + Babel Standalone are loaded via CDN. UI language is **German**.

### Self-hosted injection
When the server serves `index.html` it injects into the first `<script>` tag:
```js
window.WEBARS_SELF_HOSTED = true;
window.WEBARS_API_TOKEN = "<API_SECRET>";
```
Frontend code checks `const SELF_HOSTED = !!window.WEBARS_SELF_HOSTED` to branch between self-hosted (MySQL via API) and the legacy GitHub Pages mode.

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

**Forgot password:** `POST /api/forgot-password` → email link with token → frontend gets `{salt, escrow_blob, pbkdf2_iter}` → derives escrow key from `WEBARS_API_TOKEN` → decrypts escrow → re-wraps with new password → `POST /api/reset-token/:t/confirm` with new `wrapped_master` (atomic update + token consumption).

**Auto-migration:** if a device has local `MASTER_KEY_STORE`+`SALT_KEY` but server `crm_auth` is empty, `ensureServerAuthMigrated()` pushes the local master key + a fresh salt to the server on next successful `verifyPassword`.

**Local cache** — `SALT_KEY`, `VERIFY_KEY`, `MASTER_KEY_STORE` are kept in `localStorage` purely for offline reads after a successful online login. Server is always source of truth.

**Auto-login** — raw master key still stored in `sessionStorage` (`DEVICE_KEY_STORE`) for fast unlock on the same device.

**Legacy:** `crm_key_escrow` table + `/api/key-escrow` endpoints are kept for read-only fallback (old reset tokens). New code never writes to them.

### State management
`CRMApp` holds a single `state` object. The `upd(patch)` helper shallow-merges a patch and triggers an auto-save via `useEffect → saveEncrypted`. The encrypted blob is written to `localStorage` and synced to `PUT /api/data` with optimistic locking (`version` field).

**Important — `version=null` guard:** `PUT /api/data` returns `409 EXISTING_DATA` when the client sends `version=null` (fresh browser). The frontend must call `GET /api/data` first to retrieve the current version before writing.

### Adding new top-level state fields
When adding a new collection to `state`, update it in **4 places** inside `index.html`:
1. `DEFAULT_STATE` constant
2. `useState` initialisation in `CRMApp`
3. `refreshFromCloud` setState callback
4. `GithubSyncModal` / `onSaved` setState callback

### Sidebar views
String constants (`TODOS_VIEW`, `AI_VIEW`, `CLAUDE_VIEW`, `QUOTES_VIEW`, `INVOICES_VIEW`, `TOKENS_VIEW`, `FORMS_VIEW`, `CAMPAIGNS_VIEW`) control which panel is active. The `activeId` state is compared against these strings in a chain of ternary renderers at the bottom of `CRMApp`.

### Modal pattern
`setModal('someName')` opens a modal. Render site checks `modal === 'someName' && <SomeModal onClose={()=>setModal(null)}/>`.

### MySQL tables
| Table | Purpose |
|---|---|
| `crm_auth` | **NEW** Source-of-truth auth row (id=1): salt + wrapped_master + escrow_blob + iter |
| `crm_data` | Single encrypted blob (id=1), optimistic lock via `version BIGINT` |
| `crm_key_escrow` | LEGACY — read-only fallback for old reset tokens (id=1) |
| `password_resets` | One-time tokens for the "Passwort vergessen" flow (expire after 1 h) |
| `recovery_blobs` | Legacy recovery by email hash (no auth — content is client-encrypted) |
| `form_definitions` | Public intake forms (slug → content) |
| `crm_summary` | Plain-text summary for the Jarvis API (id=1) |
| `crm_backups` | **APPEND-ONLY** snapshots with `tier` column. Tiers: `hourly` (48), `daily` (90), `weekly` (104), `manual` (∞), `pre-restore` (∞), `legacy` (∞). Per-tier retention only. |

### API routes (all require `Authorization: Bearer <API_SECRET>` unless noted)
| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | `/health` | none | dbReady flag |
| GET | `/api/debug-auth` | none | Diagnose token mismatches |
| GET | `/api/auth-blob` | none | Returns `{exists, salt, wrapped_master, pbkdf2_iter}` — public so login form can fetch salt |
| POST | `/api/auth-blob/init` | yes | One-time setup. Refuses 409 if row exists |
| PUT | `/api/auth-blob` | yes | Update `wrapped_master` (password change) |
| GET/PUT | `/api/data` | yes | Encrypted CRM blob |
| GET/PUT | `/api/recovery/:hash` | none | Recovery blob |
| GET | `/forms/:slug` | none | Public form |
| PUT/DELETE | `/api/forms/:slug` | yes | Manage forms |
| GET/PUT | `/api/summary` | none/yes | Jarvis summary |
| GET/POST | `/api/backups` | yes | List (up to 500) / trigger manual backup |
| GET | `/api/backups/:id` | yes | Download backup |
| POST | `/api/backups/:id/restore` | yes | **Atomic snapshot-then-restore**. Always creates a `pre-restore` backup of current state first |
| GET/PUT | `/api/key-escrow` | yes | LEGACY — kept for old reset tokens only |
| POST | `/api/forgot-password` | none | Generate reset token, email link |
| GET | `/api/reset-token/:token` | none | Returns `{scheme:'auth-blob-v1', salt, escrow, pbkdf2_iter}` (or `scheme:'legacy'`) |
| POST | `/api/reset-token/:token/confirm` | none | Body: `{wrapped_master}`. Atomically updates `crm_auth` + marks token used |
| POST | `/api/import` | yes | Import encrypted blob (legacy migration) |
| POST | `/api/admin/reset` | yes | ⛔ **PERMANENTLY DISABLED** — returns 410 |

### Styles
- CSS variables defined in `:root` — dark sidebar `#0F0E0C`, warm background `#F3F0EB`.
- Utility classes: `.btn`, `.btn-primary`, `.btn-ghost`, `.btn-danger`, `.btn-sm`, `.btn-icon`.
- Modal wrapper: `.modal-overlay > .modal-box`.
- Status colours use `_STATUS` constant objects `{key, label, color, bg, dot}`.
