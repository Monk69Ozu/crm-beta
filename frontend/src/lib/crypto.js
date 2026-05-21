// Reine Crypto-Helper fuer WebArs CRM.
// Bewusste 1:1-Uebernahme aus legacy/index.html (Zeilen 86-548) — KEINE
// Verhaltensaenderungen, sonst werden alte verschluesselte Blobs unlesbar.
//
// Verboten in dieser Datei:
//   - localStorage-Zugriffe (siehe storage.js)
//   - fetch / API-Calls (siehe api.js)
//   - Module-level mutable state
//
// Erlaubt:
//   - Lesen von `window.WEBARS_API_TOKEN` in deriveEscrowKey() — der Token wird
//     vom Server beim Page-Load in den HTML-<script>-Platzhalter injiziert.

// ── Base64-Helpers ────────────────────────────────────────────────────────
// WICHTIG: String.fromCharCode(...array) sprengt bei grossen Buffern den
// Call-Stack ("Maximum call stack size exceeded" ab ~100 KB). Daher in
// 8-KB-Chunks verarbeiten — verschluesselte CRM-Blobs sind 150 KB+.
export const toB64 = (buf) => {
  const bytes = new Uint8Array(buf);
  let bin = '';
  const CHUNK = 8192;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
  }
  return btoa(bin);
};

export const fromB64 = (b64) =>
  Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));

// UTF-8-sichere base64-Variante fuer Strings (Invite-Tokens, GitHub-Blobs).
// Bewusst mit den deprecated escape/unescape — exakt wie im Original. Aenderung
// hier wuerde alte Tokens unbrauchbar machen.
export const b64encode = (str) => btoa(unescape(encodeURIComponent(str)));
export const b64decode = (b64) =>
  decodeURIComponent(escape(atob(b64.replace(/\s/g, ''))));

// ── Hashing ───────────────────────────────────────────────────────────────
export async function sha256b64(str) {
  const buf = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(str),
  );
  return toB64(buf);
}

// 16-stelliger Hex-Hash der E-Mail (lowercase) — fuer Recovery-Blob-Dateinamen.
export async function emailHash16(email) {
  const buf = new TextEncoder().encode(email.trim().toLowerCase());
  const h = await crypto.subtle.digest('SHA-256', buf);
  return [...new Uint8Array(h)]
    .slice(0, 8)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

// ── Key-Derivation (PBKDF2 → AES-GCM) ─────────────────────────────────────
// `iterations` darf 0/undefined sein — Default 210000 entspricht dem alten
// (Legacy) Wert. Server-Auth verwendet 600000 (PBKDF2_ITER_NEW in storage.js).
export async function deriveKey(password, salt, iterations) {
  const enc = new TextEncoder();
  const raw = await crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    'PBKDF2',
    false,
    ['deriveKey'],
  );
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations: iterations || 210000,
      hash: 'SHA-256',
    },
    raw,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

// PBKDF2-Variante fuer Recovery-Code-Verschluesselung (kombiniert Geheimnis
// mit der E-Mail-Adresse als zusaetzlicher Seperator).
export async function deriveStrongKey(secret, email, salt) {
  const enc = new TextEncoder();
  const raw = await crypto.subtle.importKey(
    'raw',
    enc.encode(secret + ':' + email.trim().toLowerCase()),
    'PBKDF2',
    false,
    ['deriveKey'],
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' },
    raw,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

// Escrow-Schluessel = PBKDF2(API_SECRET, 'webars-key-escrow-v1', 100000).
// Erlaubt Master-Key-Recovery via Server (nach Passwort-Vergessen-Flow).
export async function deriveEscrowKey() {
  const enc = new TextEncoder();
  const token =
    (typeof window !== 'undefined' && window.WEBARS_API_TOKEN) || '';
  const raw = await crypto.subtle.importKey(
    'raw',
    enc.encode(token),
    'PBKDF2',
    false,
    ['deriveKey'],
  );
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: enc.encode('webars-key-escrow-v1'),
      iterations: 100000,
      hash: 'SHA-256',
    },
    raw,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

// ── AES-GCM-Verschluesselung von beliebigen JSON-serialisierbaren Werten ──
export async function aesEncrypt(key, obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    new TextEncoder().encode(JSON.stringify(obj)),
  );
  return { iv: toB64(iv), data: toB64(ct) };
}

export async function aesDecrypt(key, { iv, data }) {
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fromB64(iv) },
    key,
    fromB64(data),
  );
  return JSON.parse(new TextDecoder().decode(pt));
}

// ── Master-Key (Team-Encryption-Key) ──────────────────────────────────────
export async function generateMasterKey() {
  return crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt'],
  );
}

export async function exportMasterKeyB64(masterKey) {
  const raw = await crypto.subtle.exportKey('raw', masterKey);
  return toB64(raw);
}

export async function importMasterKeyFromB64(b64) {
  return crypto.subtle.importKey(
    'raw',
    fromB64(b64),
    { name: 'AES-GCM' },
    true,
    ['encrypt', 'decrypt'],
  );
}

// Konvenienz-Export — alter Code (legacy) verwendet diesen Namen.
export async function getMasterKeyB64(masterKey) {
  return exportMasterKeyB64(masterKey);
}

// ── Recovery-Code-Generator (10 Bytes → 16 Zeichen, 4er-Gruppen) ──────────
export function generateRecoveryCode() {
  const bytes = crypto.getRandomValues(new Uint8Array(10));
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // ohne 0,1,O,I
  return [...bytes]
    .map((b) => alphabet[b % 32])
    .join('')
    .match(/.{1,4}/g)
    .join('-');
}

// ── Recovery-Blob: doppelt-verschluesselt (Passwort + Recovery-Code) ──────
export async function buildRecoveryBlob(
  email,
  password,
  recoveryCode,
  masterKey,
  ghSettings,
) {
  const masterB64 = await exportMasterKeyB64(masterKey);
  const payload = { masterKeyB64: masterB64, ghSettings: ghSettings || null };

  const pwSalt = crypto.getRandomValues(new Uint8Array(32));
  const pwKey = await deriveStrongKey(password, email, pwSalt);
  const pwEnc = await aesEncrypt(pwKey, payload);

  const codeSalt = crypto.getRandomValues(new Uint8Array(32));
  const codeKey = await deriveStrongKey(recoveryCode, email, codeSalt);
  const codeEnc = await aesEncrypt(codeKey, payload);

  return {
    v: 1,
    pwSalt: toB64(pwSalt),
    pwEnc,
    codeSalt: toB64(codeSalt),
    codeEnc,
    updatedAt: new Date().toISOString(),
  };
}

export async function decryptRecoveryWithPassword(blob, email, password) {
  const salt = fromB64(blob.pwSalt);
  const key = await deriveStrongKey(password, email, salt);
  return aesDecrypt(key, blob.pwEnc);
}

export async function decryptRecoveryWithCode(blob, email, code) {
  if (!blob.codeSalt || !blob.codeEnc)
    throw new Error('Kein Recovery-Code fuer dieses Konto hinterlegt.');
  const salt = fromB64(blob.codeSalt);
  const key = await deriveStrongKey(
    code.replace(/-/g, '').toUpperCase(),
    email,
    salt,
  );
  return aesDecrypt(key, blob.codeEnc);
}

// ── Invite-Token: base64url-codiertes JSON mit Master-Key + GH-Settings ──
export async function createInviteToken(masterKey, ghSettings, label) {
  const masterB64 = await exportMasterKeyB64(masterKey);
  const payload = {
    v: 1,
    mk: masterB64,
    gh: ghSettings || null,
    label: label || '',
    created: new Date().toISOString(),
  };
  return b64encode(JSON.stringify(payload))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

export function parseInviteToken(token) {
  try {
    if (!token) return null;
    let s = token.trim().replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    const payload = JSON.parse(b64decode(s));
    if (payload.v !== 1 || !payload.mk) return null;
    return {
      masterKeyB64: payload.mk,
      ghSettings: payload.gh || null,
      label: payload.label || '',
      created: payload.created,
    };
  } catch {
    return null;
  }
}
