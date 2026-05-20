// Backend-API-Wrapper fuer das WebArs CRM.
//
// Verantwortung dieser Datei:
//   - Self-hosted vs. GitHub-Pages-Modus erkennen
//   - Auth-Header an autorisierte Requests anhaengen
//   - Die ROHEN Auth-Blob-Endpoints (fetch/init/update) wrappen
//
// Hoehere Auth-Flows (verifyPassword, setupPassword, changePassword) liegen in
// lib/auth.js — die kombinieren Crypto + Storage + diesen API-Layer.

// ── Self-hosted / Token-Detection ─────────────────────────────────────────
export const SELF_HOSTED = !!(
  typeof window !== 'undefined' && window.WEBARS_SELF_HOSTED
);

export function apiToken() {
  return (typeof window !== 'undefined' && window.WEBARS_API_TOKEN) || '';
}

export function authHeaders(extra = {}) {
  return {
    Authorization: `Bearer ${apiToken()}`,
    'Content-Type': 'application/json',
    ...extra,
  };
}

// ── Generischer authentifizierter Fetch-Wrapper ───────────────────────────
// Wird in spaeteren Sessions von den meisten View-Komponenten genutzt.
export async function apiFetch(path, opts = {}) {
  const headers = opts.skipAuth
    ? opts.headers || { 'Content-Type': 'application/json' }
    : authHeaders(opts.headers);
  const res = await fetch(path, { ...opts, headers });
  return res;
}

// ── Auth-Blob-Endpoints ───────────────────────────────────────────────────
// GET /api/auth-blob ist OEFFENTLICH (kein Auth-Header) — das Login-Formular
// braucht den Salt zum Ableiten des Wrap-Keys, bevor der User authentifiziert
// ist. Server-seitig schuetzt ein 5-Versuche-pro-15-Minuten-Limit.
export async function fetchServerAuthBlob() {
  if (!SELF_HOSTED) return null;
  try {
    const r = await fetch('/api/auth-blob', { cache: 'no-store' });
    if (r.status === 429) {
      const j = await r.json().catch(() => ({}));
      const mins = j.retryAfter ? Math.ceil(j.retryAfter / 60) : 15;
      throw new Error(
        'RATE_LIMITED:Zu viele Login-Versuche. Bitte ' +
          mins +
          ' Minuten warten.',
      );
    }
    if (!r.ok) return null;
    const j = await r.json();
    return j && j.exists ? j : { exists: false };
  } catch (e) {
    console.warn('fetchServerAuthBlob:', e.message);
    throw e;
  }
}

export async function serverHasAuth() {
  const ab = await fetchServerAuthBlob();
  return !!(ab && ab.exists);
}

// POST /api/auth-blob/init — einmaliges Setup. Server antwortet 409
// (AUTH_ALREADY_EXISTS) wenn schon eine Auth-Row existiert.
export async function apiInitAuthBlob({
  salt,
  wrapped_master,
  escrow_blob,
  pbkdf2_iter,
}) {
  const r = await fetch('/api/auth-blob/init', {
    method: 'POST',
    headers: authHeaders(),
    body: JSON.stringify({ salt, wrapped_master, escrow_blob, pbkdf2_iter }),
  });
  if (!r.ok) {
    const j = await r.json().catch(() => ({}));
    if (j.error === 'AUTH_ALREADY_EXISTS') throw new Error('AUTH_ALREADY_EXISTS');
    throw new Error('Setup failed: ' + (j.error || r.status));
  }
  return r;
}

// PUT /api/auth-blob — Passwort-Aenderung (nur wrapped_master wird ersetzt).
export async function apiUpdateAuthBlob({ wrapped_master }) {
  const r = await fetch('/api/auth-blob', {
    method: 'PUT',
    headers: authHeaders(),
    body: JSON.stringify({ wrapped_master }),
  });
  if (!r.ok) {
    const j = await r.json().catch(() => ({}));
    throw new Error('Passwort-Update fehlgeschlagen: ' + (j.error || r.status));
  }
  return r;
}
