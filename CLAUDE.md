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

### Client-side encryption (AES-256-GCM)
All CRM data is encrypted in the browser before being sent to or stored on the server. The server only ever sees opaque encrypted blobs.

Key hierarchy:
1. **Master key** — random AES-256-GCM key, never leaves the browser unencrypted.
2. **Wrap key** — derived from the user's password via PBKDF2 (210 000 iterations, SHA-256, per-device random salt stored in `localStorage`).
3. The master key is stored in `localStorage` encrypted by the wrap key (`MASTER_KEY_STORE`). A `VERIFY_KEY` blob lets `verifyPassword()` confirm the correct password without decrypting data.

**Key escrow** — on every successful login `escrowMasterKey()` encrypts the master key with a key derived from `window.WEBARS_API_TOKEN` (PBKDF2, salt `'webars-key-escrow-v1'`, 100 000 iterations) and stores it at `PUT /api/key-escrow`. The "Passwort vergessen" flow fetches this blob and re-wraps it with the new password — no data loss even after a forgotten password.

**Auto-login** — the raw master key is stored in `sessionStorage` as base64 (`DEVICE_KEY_STORE`). It is imported as `extractable: true` so it can be re-exported for escrow/rewrap operations.

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
| `crm_data` | Single encrypted blob (id=1), optimistic lock via `version BIGINT` |
| `crm_key_escrow` | Master key encrypted with API_SECRET-derived key (id=1) |
| `password_resets` | One-time tokens for the "Passwort vergessen" flow (expire after 1 h) |
| `recovery_blobs` | Legacy recovery by email hash (no auth — content is client-encrypted) |
| `form_definitions` | Public intake forms (slug → content) |
| `crm_summary` | Plain-text summary for the Jarvis API (id=1) |
| `crm_backups` | Daily snapshots at 02:00 UTC, max 30 kept |

### API routes (all require `Authorization: Bearer <API_SECRET>` unless noted)
| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | `/health` | none | dbReady flag |
| GET | `/api/debug-auth` | none | Diagnose token mismatches |
| GET/PUT | `/api/data` | yes | Encrypted CRM blob |
| GET/PUT | `/api/recovery/:hash` | none | Recovery blob |
| GET | `/forms/:slug` | none | Public form |
| PUT/DELETE | `/api/forms/:slug` | yes | Manage forms |
| GET/PUT | `/api/summary` | none/yes | Jarvis summary |
| GET/POST | `/api/backups` | yes | List / trigger backup |
| GET | `/api/backups/:id` | yes | Download backup |
| GET/PUT | `/api/key-escrow` | yes | Password-reset escrow |
| POST | `/api/forgot-password` | none | Generate reset token |
| GET | `/api/reset-token/:token` | none | Validate token, return escrow blob |
| POST | `/api/reset-token/:token/confirm` | none | Mark token used |
| POST | `/api/import` | yes | Import encrypted blob |
| POST | `/api/admin/reset` | yes | ⚠ Wipe all CRM data |

### Styles
- CSS variables defined in `:root` — dark sidebar `#0F0E0C`, warm background `#F3F0EB`.
- Utility classes: `.btn`, `.btn-primary`, `.btn-ghost`, `.btn-danger`, `.btn-sm`, `.btn-icon`.
- Modal wrapper: `.modal-overlay > .modal-box`.
- Status colours use `_STATUS` constant objects `{key, label, color, bg, dot}`.
