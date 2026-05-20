// AUTO-GENERATED: legacy-bundle.jsx
// Bulk-Import aller noch nicht-extrahierten Helper + React-Komponenten aus
// legacy/index.html (Zeilen 86-9892). Wird in spaeteren Sessions schritt-
// weise in kleinere Module aufgesplittet (Modals, Views, CRMApp Root).
//
// Wichtige Eigenschaften dieses Bundles:
//   - Alle Module-Globals (_ghSettings, _ghSha, _isSaving, _lastSnapAt etc.)
//     leben hier im Datei-Scope — alle internen Funktionen sehen sie.
//   - Definiert eine zweite Kopie von Crypto/Auth-Helpers (sha256b64,
//     setupPassword, etc.). Funktional identisch zu frontend/src/lib/*.js,
//     aber unabhaengig — Doppel-Bundle in Kauf genommen fuer Migration.
//   - Exportiert NUR CRMApp. Andere Komponenten (incl. AuthScreen-Duplikate
//     aus dem Original) sind file-private und unbenutzt.

import { useState, useEffect, useLayoutEffect, useRef, useCallback } from 'react';

// ── Self-hosted mode (injected by server.js at runtime) ─────────
// When served from the Express server, window.WEBARS_SELF_HOSTED is set
// to true BEFORE this script runs. On GitHub Pages it stays undefined.
const SELF_HOSTED = !!(typeof window !== 'undefined' && window.WEBARS_SELF_HOSTED);

// ═══════════════════════════════════════════════════════════════
//  CRYPTO + TOTP  (plain JS, no framework)
// ═══════════════════════════════════════════════════════════════
const RECOVERY_EMAIL  = 'turleat@gmail.com';
const OWNER_EMAIL     = 'turlea@webars.at';
const SALT_KEY        = 'webars_salt_v1';
const VERIFY_KEY      = 'webars_verify_v1';
const TOTP_KEY        = 'webars_totp_v1';
const DATA_KEY        = 'webars_data_v1';
const INVITES_KEY     = 'webars_invites_v1';
const EMAIL_HASH_KEY  = 'webars_email_v1';
const VERIFY_STR      = 'WEBARS_AUTH_OK_2026';
const IDLE_TIMEOUT_MS = 15 * 60 * 1000;
// Device-key store for TOTP-only login
const DEVICE_KEY_STORE = 'webars_dkey_v1';
const TOTP_ENC_STORE   = 'webars_totp_denc_v1';
const PKEY_ENC_STORE   = 'webars_pkey_denc_v1';

// ─── Invite helpers ─────────────────────────────────────────────
async function sha256b64(str) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return toB64(buf);
}

// Invite token = base64url-encoded JSON containing master key + GitHub creds.
// Sharing this token with a member gives them access to the same team data.
async function createInviteToken(masterKey, ghSettings, label) {
  const masterB64 = await exportMasterKeyB64(masterKey);
  const payload = {
    v: 1,
    mk: masterB64,
    gh: ghSettings || null,
    label: label || '',
    created: new Date().toISOString()
  };
  // base64url so it's URL-safe
  return b64encode(JSON.stringify(payload)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}

function parseInviteToken(token) {
  try {
    if (!token) return null;
    let s = token.trim().replace(/-/g,'+').replace(/_/g,'/');
    while (s.length % 4) s += '=';
    const payload = JSON.parse(b64decode(s));
    if (payload.v !== 1 || !payload.mk) return null;
    return {
      masterKeyB64: payload.mk,
      ghSettings: payload.gh || null,
      label: payload.label || '',
      created: payload.created
    };
  } catch (e) { return null; }
}

// ─── AES helpers ────────────────────────────────────────────────
const toB64  = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
const fromB64 = b64 => Uint8Array.from(atob(b64), c => c.charCodeAt(0));
// UTF-8 safe base64 for strings (used by invite tokens and GitHub blobs)
const b64encode = str => btoa(unescape(encodeURIComponent(str)));
const b64decode = b64 => decodeURIComponent(escape(atob(b64.replace(/\s/g,''))));

async function deriveKey(password, salt, iterations) {
  const enc = new TextEncoder();
  const raw = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name:'PBKDF2', salt, iterations: iterations || 210000, hash:'SHA-256' },
    raw, { name:'AES-GCM', length:256 }, false, ['encrypt','decrypt']
  );
}

// ─── NEW SERVER-BACKED AUTH (auth-blob model) ───────────────────
// Source of truth is the server's crm_auth row. Same password works on EVERY
// device because salt+wrapped_master live on the server, not in localStorage.
const PBKDF2_ITER_NEW = 600000;

async function fetchServerAuthBlob() {
  if (!SELF_HOSTED) return null;
  try {
    const r = await fetch('/api/auth-blob', { cache: 'no-store' });
    if (r.status === 429) {
      const j = await r.json().catch(() => ({}));
      const mins = j.retryAfter ? Math.ceil(j.retryAfter / 60) : 15;
      throw new Error('RATE_LIMITED:Zu viele Login-Versuche. Bitte ' + mins + ' Minuten warten.');
    }
    if (!r.ok) return null;
    const j = await r.json();
    return j && j.exists ? j : { exists: false };
  } catch(e) { console.warn('fetchServerAuthBlob:', e.message); throw e; }
}

async function serverHasAuth() {
  const ab = await fetchServerAuthBlob();
  return !!(ab && ab.exists);
}

async function setupPasswordServer(password, providedMasterKeyB64 = null) {
  // 1) Generate fresh salt + master key
  const saltBytes = crypto.getRandomValues(new Uint8Array(32));
  const saltB64 = toB64(saltBytes);
  const masterKey = providedMasterKeyB64
    ? await importMasterKeyFromB64(providedMasterKeyB64)
    : await generateMasterKey();
  const masterB64 = await exportMasterKeyB64(masterKey);
  // 2) Wrap master with PBKDF2(password, salt, 600k)
  const wrapKey = await deriveKey(password, saltBytes, PBKDF2_ITER_NEW);
  const wrapped_master = await aesEncrypt(wrapKey, masterB64);
  // 3) Build escrow blob (master encrypted with API_SECRET-derived key)
  const escrowKey = await deriveEscrowKey();
  const escrow_blob = await aesEncrypt(escrowKey, masterB64);
  // 4) POST to /api/auth-blob/init — refuses if already exists (safety)
  const r = await fetch('/api/auth-blob/init', {
    method: 'POST',
    headers: { 'Authorization': `Bearer ${window.WEBARS_API_TOKEN}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ salt: saltB64, wrapped_master, escrow_blob, pbkdf2_iter: PBKDF2_ITER_NEW })
  });
  if (!r.ok) {
    const j = await r.json().catch(()=>({}));
    if (j.error === 'AUTH_ALREADY_EXISTS') throw new Error('AUTH_ALREADY_EXISTS');
    throw new Error('Setup failed: ' + (j.error || r.status));
  }
  // 5) Cache locally (useful for offline reads only; server remains source of truth)
  localStorage.setItem(SALT_KEY, saltB64);
  localStorage.setItem(VERIFY_KEY, JSON.stringify(await aesEncrypt(wrapKey, VERIFY_STR)));
  localStorage.setItem(MASTER_KEY_STORE, JSON.stringify(wrapped_master));
  return masterKey;
}

async function verifyPasswordServer(password) {
  const ab = await fetchServerAuthBlob();
  if (!ab || !ab.exists) return { status: 'no-server-auth' };
  try {
    const saltBytes = fromB64(ab.salt);
    const wrapKey = await deriveKey(password, saltBytes, ab.pbkdf2_iter || PBKDF2_ITER_NEW);
    const masterB64 = await aesDecrypt(wrapKey, ab.wrapped_master);
    const masterKey = await importMasterKeyFromB64(masterB64);
    // Refresh local cache
    localStorage.setItem(SALT_KEY, ab.salt);
    localStorage.setItem(VERIFY_KEY, JSON.stringify(await aesEncrypt(wrapKey, VERIFY_STR)));
    localStorage.setItem(MASTER_KEY_STORE, JSON.stringify(ab.wrapped_master));
    return { status: 'ok', masterKey };
  } catch(e) {
    return { status: 'wrong-password' };
  }
}

// Change password by re-wrapping master and PUTing new wrapped_master to server.
// Salt + escrow stay the same — master key itself never changes.
async function changePasswordServer(masterKey, newPassword) {
  const ab = await fetchServerAuthBlob();
  if (!ab || !ab.exists) throw new Error('Kein Server-Auth — bitte zuerst Setup machen');
  const saltBytes = fromB64(ab.salt);
  const iter = ab.pbkdf2_iter || PBKDF2_ITER_NEW;
  const wrapKey = await deriveKey(newPassword, saltBytes, iter);
  const masterB64 = await exportMasterKeyB64(masterKey);
  const wrapped_master = await aesEncrypt(wrapKey, masterB64);
  const r = await fetch('/api/auth-blob', {
    method: 'PUT',
    headers: { 'Authorization': `Bearer ${window.WEBARS_API_TOKEN}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ wrapped_master })
  });
  if (!r.ok) { const j = await r.json().catch(()=>({})); throw new Error('Passwort-Update fehlgeschlagen: ' + (j.error || r.status)); }
  // Refresh local cache so offline reads still work
  localStorage.setItem(SALT_KEY, ab.salt);
  localStorage.setItem(VERIFY_KEY, JSON.stringify(await aesEncrypt(wrapKey, VERIFY_STR)));
  localStorage.setItem(MASTER_KEY_STORE, JSON.stringify(wrapped_master));
}

// Auto-migrate: if local password works but no server auth-blob exists, push it up.
async function ensureServerAuthMigrated(password, masterKey) {
  if (!SELF_HOSTED || !window.WEBARS_API_TOKEN) return;
  try {
    const ab = await fetchServerAuthBlob();
    if (ab && ab.exists) return; // already migrated
    // Build new auth blob from current master key + this password
    const saltBytes = crypto.getRandomValues(new Uint8Array(32));
    const saltB64 = toB64(saltBytes);
    const wrapKey = await deriveKey(password, saltBytes, PBKDF2_ITER_NEW);
    const masterB64 = await exportMasterKeyB64(masterKey);
    const wrapped_master = await aesEncrypt(wrapKey, masterB64);
    const escrowKey = await deriveEscrowKey();
    const escrow_blob = await aesEncrypt(escrowKey, masterB64);
    const r = await fetch('/api/auth-blob/init', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${window.WEBARS_API_TOKEN}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ salt: saltB64, wrapped_master, escrow_blob, pbkdf2_iter: PBKDF2_ITER_NEW })
    });
    if (r.ok) {
      console.log('[migration] Pushed local auth → server auth-blob');
      localStorage.setItem(SALT_KEY, saltB64);
      localStorage.setItem(VERIFY_KEY, JSON.stringify(await aesEncrypt(wrapKey, VERIFY_STR)));
      localStorage.setItem(MASTER_KEY_STORE, JSON.stringify(wrapped_master));
    }
  } catch(e) { console.warn('[migration] failed:', e.message); }
}
async function aesEncrypt(key, obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({name:'AES-GCM',iv}, key, new TextEncoder().encode(JSON.stringify(obj)));
  return { iv: toB64(iv), data: toB64(ct) };
}
async function aesDecrypt(key, {iv, data}) {
  const pt = await crypto.subtle.decrypt({name:'AES-GCM',iv:fromB64(iv)}, key, fromB64(data));
  return JSON.parse(new TextDecoder().decode(pt));
}
function getSalt() {
  const s = localStorage.getItem(SALT_KEY);
  if (s) return fromB64(s);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  localStorage.setItem(SALT_KEY, toB64(salt));
  return salt;
}
function hasSetup()  { return !!localStorage.getItem(VERIFY_KEY) && !!localStorage.getItem(MASTER_KEY_STORE); }
function hasTOTP()   { return !!localStorage.getItem(TOTP_KEY); }

async function storeEmailHash(email) {
  const hash = await sha256b64('WEBARS_EMAIL_' + email.trim().toLowerCase());
  localStorage.setItem(EMAIL_HASH_KEY, hash);
}
async function checkEmailHash(email) {
  const stored = localStorage.getItem(EMAIL_HASH_KEY);
  if (!stored) return true; // legacy: no hash stored yet, allow
  const hash = await sha256b64('WEBARS_EMAIL_' + email.trim().toLowerCase());
  return hash === stored;
}
function hasEmailHash() { return !!localStorage.getItem(EMAIL_HASH_KEY); }

// ─── CLOUD RECOVERY ─────────────────────────────────────────────
// Encrypted master-key blob stored in public repo at recovery/<emailhash>.json
// Allows login on any device with email+password, no invite needed.
const RECOVERY_REPO = 'Tatstast/crm-system';
const LOGIN_ATTEMPTS_KEY = 'webars_login_attempts_v1';

async function emailHash16(email){
  const buf = new TextEncoder().encode(email.trim().toLowerCase());
  const h = await crypto.subtle.digest('SHA-256', buf);
  return [...new Uint8Array(h)].slice(0,8).map(b=>b.toString(16).padStart(2,'0')).join('');
}

async function deriveStrongKey(secret, email, salt){
  const enc = new TextEncoder();
  const raw = await crypto.subtle.importKey('raw', enc.encode(secret+':'+email.trim().toLowerCase()), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    {name:'PBKDF2', salt, iterations:600000, hash:'SHA-256'},
    raw, {name:'AES-GCM', length:256}, false, ['encrypt','decrypt']
  );
}

function generateRecoveryCode(){
  const bytes = crypto.getRandomValues(new Uint8Array(10));
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no 0,1,O,I (lookalikes)
  return [...bytes].map(b=>alphabet[b%32]).join('').match(/.{1,4}/g).join('-');
}

async function buildRecoveryBlob(email, password, recoveryCode, masterKey, ghSettings){
  const masterB64 = await exportMasterKeyB64(masterKey);
  const payload = {masterKeyB64: masterB64, ghSettings: ghSettings || null};

  const pwSalt = crypto.getRandomValues(new Uint8Array(32));
  const pwKey = await deriveStrongKey(password, email, pwSalt);
  const pwEnc = await aesEncrypt(pwKey, payload);

  const codeSalt = crypto.getRandomValues(new Uint8Array(32));
  const codeKey = await deriveStrongKey(recoveryCode, email, codeSalt);
  const codeEnc = await aesEncrypt(codeKey, payload);

  return {v:1, pwSalt:toB64(pwSalt), pwEnc, codeSalt:toB64(codeSalt), codeEnc, updatedAt:new Date().toISOString()};
}

async function decryptRecoveryWithPassword(blob, email, password){
  const salt = fromB64(blob.pwSalt);
  const key = await deriveStrongKey(password, email, salt);
  return aesDecrypt(key, blob.pwEnc);
}

async function decryptRecoveryWithCode(blob, email, code){
  if(!blob.codeSalt||!blob.codeEnc) throw new Error('Kein Recovery-Code für dieses Konto hinterlegt.');
  const salt = fromB64(blob.codeSalt);
  const key = await deriveStrongKey(code.replace(/-/g,'').toUpperCase(), email, salt);
  return aesDecrypt(key, blob.codeEnc);
}

async function pushRecoveryBlob(email, blob, ghToken, ghRepo){
  if (SELF_HOSTED) {
    const hash = await emailHash16(email);
    const r = await fetch(`/api/recovery/${hash}`, {
      method: 'PUT',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(blob)
    });
    if (!r.ok) throw new Error('Recovery push failed: ' + r.status);
    return;
  }
  const filename = await emailHash16(email);
  const path = `recovery/${filename}.json`;
  let sha = null;
  try{
    const r = await fetch(`https://api.github.com/repos/${ghRepo}/contents/${path}`, {headers:{Authorization:`Bearer ${ghToken}`,Accept:'application/vnd.github+json'}});
    if(r.ok) sha = (await r.json()).sha;
  }catch(e){}
  const body = {message:'Update recovery blob', content: btoa(unescape(encodeURIComponent(JSON.stringify(blob, null, 2))))};
  if(sha) body.sha = sha;
  const r = await fetch(`https://api.github.com/repos/${ghRepo}/contents/${path}`, {
    method:'PUT',
    headers:{Authorization:`Bearer ${ghToken}`,'Content-Type':'application/json',Accept:'application/vnd.github+json'},
    body: JSON.stringify(body)
  });
  if(!r.ok){const t=await r.text();throw new Error('Recovery push failed: '+r.status+' '+t.slice(0,100));}
}

async function fetchRecoveryBlob(email, ghRepo){
  if (SELF_HOSTED) {
    const hash = await emailHash16(email);
    try {
      const r = await fetch(`/api/recovery/${hash}`, {cache: 'no-store'});
      if (!r.ok) return null;
      return await r.json();
    } catch(e) { return null; }
  }
  const repo = ghRepo || RECOVERY_REPO;
  const filename = await emailHash16(email);
  const url = `https://raw.githubusercontent.com/${repo}/main/recovery/${filename}.json?t=${Date.now()}`;
  try{
    const r = await fetch(url, {cache:'no-store'});
    if(!r.ok) return null;
    return await r.json();
  }catch(e){ return null; }
}

// ─── LOGIN LOCKOUT ──────────────────────────────────────────────
function getLoginLockout(){
  try{
    const a = JSON.parse(localStorage.getItem(LOGIN_ATTEMPTS_KEY)||'{}');
    if(a.until && a.until > Date.now()) return Math.ceil((a.until-Date.now())/1000);
    return 0;
  }catch(e){return 0;}
}

function recordLoginFailure(){
  let a = {count:0};
  try{ a = JSON.parse(localStorage.getItem(LOGIN_ATTEMPTS_KEY)||'{}'); }catch(e){}
  a.count = (a.count||0)+1;
  if(a.count >= 3){
    const tier = Math.floor((a.count-3)/3);
    const lockMin = [5, 60, 60*24][Math.min(tier,2)] || 60*24;
    a.until = Date.now() + lockMin*60*1000;
    a.lockMin = lockMin;
  }
  localStorage.setItem(LOGIN_ATTEMPTS_KEY, JSON.stringify(a));
  return {count:a.count, lockSeconds: a.until?Math.ceil((a.until-Date.now())/1000):0, lockMin:a.lockMin||0};
}

function clearLoginAttempts(){ localStorage.removeItem(LOGIN_ATTEMPTS_KEY); }

// ─── Master Key (shared team encryption key, wrapped per-user) ──
const MASTER_KEY_STORE = 'webars_master_v1';

async function generateMasterKey() {
  return crypto.subtle.generateKey({name:'AES-GCM',length:256}, true, ['encrypt','decrypt']);
}
async function exportMasterKeyB64(masterKey) {
  const raw = await crypto.subtle.exportKey('raw', masterKey);
  return toB64(raw);
}
async function importMasterKeyFromB64(b64) {
  return crypto.subtle.importKey('raw', fromB64(b64), {name:'AES-GCM'}, true, ['encrypt','decrypt']);
}

async function setupPassword(password, providedMasterKeyB64 = null) {
  // ── Self-hosted: server auth-blob is source of truth ──
  if (SELF_HOSTED && window.WEBARS_API_TOKEN) {
    return setupPasswordServer(password, providedMasterKeyB64);
  }
  // ── Legacy local-only path (GitHub Pages mode) ──
  localStorage.removeItem(SALT_KEY);
  const salt = getSalt();
  const wrapKey = await deriveKey(password, salt);
  localStorage.setItem(VERIFY_KEY, JSON.stringify(await aesEncrypt(wrapKey, VERIFY_STR)));
  const masterKey = providedMasterKeyB64
    ? await importMasterKeyFromB64(providedMasterKeyB64)
    : await generateMasterKey();
  const masterB64 = await exportMasterKeyB64(masterKey);
  localStorage.setItem(MASTER_KEY_STORE, JSON.stringify(await aesEncrypt(wrapKey, masterB64)));
  return masterKey;
}

// Re-encrypt master key with NEW password (for password change / reset)
async function rewrapMasterKey(masterKey, newPassword){
  localStorage.removeItem(SALT_KEY);
  const salt = getSalt();
  const wrapKey = await deriveKey(newPassword, salt);
  localStorage.setItem(VERIFY_KEY, JSON.stringify(await aesEncrypt(wrapKey, VERIFY_STR)));
  const masterB64 = await exportMasterKeyB64(masterKey);
  localStorage.setItem(MASTER_KEY_STORE, JSON.stringify(await aesEncrypt(wrapKey, masterB64)));
}

// ─── Key Escrow (enables password reset without losing data) ────────
// Master key is encrypted with an API_SECRET-derived key and stored on the server.
// This lets us recover the master key after a forgotten password.
async function deriveEscrowKey() {
  const enc = new TextEncoder();
  const raw = await crypto.subtle.importKey(
    'raw', enc.encode(window.WEBARS_API_TOKEN || ''), 'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    {name:'PBKDF2', salt: enc.encode('webars-key-escrow-v1'), iterations:100000, hash:'SHA-256'},
    raw, {name:'AES-GCM', length:256}, false, ['encrypt','decrypt']
  );
}
async function escrowMasterKey(masterKey) {
  if (!SELF_HOSTED || !window.WEBARS_API_TOKEN) return;
  try {
    const escrowKey = await deriveEscrowKey();
    const rawMk = await crypto.subtle.exportKey('raw', masterKey);
    const newMkB64 = toB64(rawMk);

    // SAFETY: refuse to overwrite an existing escrow whose key currently
    // decrypts the server data. This prevents a fresh-setup/reset session
    // from destroying the canonical key and losing access to old data.
    try {
      const checkR = await fetch('/api/key-escrow', {headers:{Authorization:`Bearer ${window.WEBARS_API_TOKEN}`}});
      if (checkR.ok) {
        const existing = await checkR.json();
        let existingMkB64 = null;
        try { existingMkB64 = await aesDecrypt(escrowKey, existing); } catch {}
        if (existingMkB64 && existingMkB64 !== newMkB64) {
          // Different key already in escrow — check if it still matches server data
          try {
            const dr = await fetch('/api/data', {headers:{Authorization:`Bearer ${window.WEBARS_API_TOKEN}`}});
            if (dr.ok) {
              const dj = await dr.json();
              if (dj.content) {
                const existingMk = await importMasterKeyFromB64(existingMkB64);
                try {
                  await aesDecrypt(existingMk, dj.content);
                  console.warn('[escrow] Refusing to overwrite — existing escrow key still decrypts server data');
                  return; // DON'T overwrite
                } catch {}
              }
            }
          } catch {}
        }
      }
    } catch {}

    const encrypted = await aesEncrypt(escrowKey, newMkB64);
    await fetch('/api/key-escrow', {
      method:'PUT',
      headers:{Authorization:`Bearer ${window.WEBARS_API_TOKEN}`,'Content-Type':'application/json'},
      body: JSON.stringify(encrypted)
    });
  } catch(e) { console.warn('Key escrow update failed:', e); }
}
async function unescrowMasterKey(escrowBlob) {
  const escrowKey = await deriveEscrowKey();
  const mkB64 = await aesDecrypt(escrowKey, escrowBlob);
  return importMasterKeyFromB64(mkB64);
}

// Save recovery blob to cloud (called whenever password OR ghSettings change)
async function saveCloudRecovery(email, password, recoveryCode, masterKey, ghSettings){
  if(!email||!password||!recoveryCode||!masterKey||!ghSettings||!ghSettings.token||!ghSettings.repo)return false;
  try{
    const blob = await buildRecoveryBlob(email, password, recoveryCode, masterKey, ghSettings);
    await pushRecoveryBlob(email, blob, ghSettings.token, ghSettings.repo);
    return true;
  }catch(e){console.warn('Cloud recovery save failed:', e);return false;}
}

async function verifyPassword(password) {
  // ── Self-hosted: try server auth-blob first (source of truth) ──
  if (SELF_HOSTED && window.WEBARS_API_TOKEN) {
    const r = await verifyPasswordServer(password);
    if (r.status === 'ok') {
      // No legacy-escrow update here: the new crm_auth row already contains
      // an escrow_blob and the master key never changes after init.
      return r.masterKey;
    }
    if (r.status === 'wrong-password') return null;
    // status === 'no-server-auth' → fall through to local + auto-migrate
  }
  // ── Legacy local path (also used for migration from pre-auth-blob installs) ──
  const localSaltB64 = localStorage.getItem(SALT_KEY);
  if (!localSaltB64) { console.error('[auth] No salt in localStorage'); return null; }
  const salt = fromB64(localSaltB64);
  const wrapKey = await deriveKey(password, salt);
  try {
    const verifyRaw = localStorage.getItem(VERIFY_KEY);
    if (!verifyRaw) { console.error('[auth] VERIFY_KEY missing'); return null; }
    let verifyBlob;
    try { verifyBlob = JSON.parse(verifyRaw); } catch(e) { console.error('[auth] VERIFY_KEY not valid JSON'); return null; }
    const v = await aesDecrypt(wrapKey, verifyBlob);
    if (v !== VERIFY_STR) { console.error('[auth] Verify string mismatch — wrong password'); return null; }
    const mkRaw = localStorage.getItem(MASTER_KEY_STORE);
    if (!mkRaw) { console.error('[auth] MASTER_KEY_STORE missing'); return null; }
    const mkB64 = await aesDecrypt(wrapKey, JSON.parse(mkRaw));
    const masterKey = await importMasterKeyFromB64(mkB64);
    // Auto-migrate to server auth-blob (one-shot, idempotent)
    if (SELF_HOSTED && window.WEBARS_API_TOKEN) {
      ensureServerAuthMigrated(password, masterKey).catch(()=>{});
    }
    return masterKey;
  } catch(e) { console.error('[auth] verifyPassword failed:', e.message); return null; }
}

async function getMasterKeyB64(masterKey) {
  return exportMasterKeyB64(masterKey);
}
async function saveTOTPSecret(key, secret) {
  localStorage.setItem(TOTP_KEY, JSON.stringify(await aesEncrypt(key, secret)));
}
async function loadTOTPSecret(key) {
  const raw = localStorage.getItem(TOTP_KEY);
  if (!raw) return null;
  try { return await aesDecrypt(key, JSON.parse(raw)); } catch(e) { return null; }
}
async function saveEncrypted(key, data) {
  _isSaving = true;
  try {
  const dataWithTs = {...data, _savedAt: Date.now()};
  const encrypted = await aesEncrypt(key, dataWithTs);
  try { localStorage.setItem(DATA_KEY, JSON.stringify(encrypted)); } catch(e) { console.warn('[save] localStorage voll:', e); }
  // Auto-snapshot every 4 hours (no internet needed)
  const now = Date.now();
  if(now - _lastSnapAt > 4*3600*1000){ saveLocalSnapshot(encrypted); _lastSnapAt = now; }
  // Push to cloud
  if (_ghSettings) {
    let attempt = 0;
    while (attempt < 2) {
      attempt++;
      try {
        const newSha = await ghPushFile(_ghSettings.token, _ghSettings.repo, _ghSettings.path, encrypted, _ghSha);
        _ghSha = newSha;
        localStorage.setItem(GH_SHA_KEY, newSha);
        _ghSyncState = {state:'ok', at:Date.now()};
        _notifySync && _notifySync();
        pushCrmSummary(data, _ghSettings).catch(()=>{});
        return;
      } catch(e) {
        if (e.message === 'CONFLICT' && attempt === 1) {
          // 409 — version changed on server. Refetch to compare timestamps.
          try {
            const fetched = await ghFetchFile(_ghSettings.token, _ghSettings.repo, _ghSettings.path);
            if (fetched.content) {
              const cloudDec = await aesDecrypt(key, fetched.content);
              const cloudTs = cloudDec._savedAt || 0;
              if (cloudTs > dataWithTs._savedAt) {
                // Server has NEWER data than what we're saving — refuse, keep local
                // until user resolves manually. Local edits are still in DATA_KEY.
                _ghSyncState = {state:'conflict_newer_on_server', message:'Server hat neuere Daten (anderes Gerät). Bitte Seite neu laden.', at:Date.now()};
                _notifySync && _notifySync();
                return;
              }
              // Our edits are newer (or equal) — bump our version pointer and retry
              _ghSha = fetched.sha;
              localStorage.setItem(GH_SHA_KEY, fetched.sha);
              continue;
            }
          } catch(refetchErr) { /* fall through to error */ }
        }
        _ghSyncState = {state:'error', message:e.message, at:Date.now()};
        _notifySync && _notifySync();
        return;
      }
    }
  }
  } finally { _isSaving = false; }
}
async function loadEncrypted(key) {
  // Try cloud/server first if configured
  if (_ghSettings) {
    try {
      const fetched = await ghFetchFile(_ghSettings.token, _ghSettings.repo, _ghSettings.path);
      if (fetched.content) {
        // CRITICAL: decrypt BEFORE updating _ghSha. If the key doesn't match the
        // cloud blob, we MUST NOT update version state.
        let decrypted;
        try {
          decrypted = await aesDecrypt(key, fetched.content);
        } catch(decErr) {
          _ghSyncState = {state:'key_mismatch', message:'Server-Daten konnten mit deinem aktuellen Schlüssel nicht entschlüsselt werden. Anmeldung mit falschem Passwort? Bitte ausloggen.', at:Date.now()};
          _notifySync && _notifySync();
          throw new Error('KEY_MISMATCH');
        }
        // BUG #4 FIX: compare timestamps before overwriting local with server data.
        // If local has newer unsaved edits (e.g. a previous PUT failed with 409),
        // we must NOT overwrite them with the older server version.
        const cloudTs = decrypted._savedAt || 0;
        let useLocal = false;
        const localRaw = localStorage.getItem(DATA_KEY);
        if (localRaw && cloudTs > 0) {
          try {
            const localBlob = JSON.parse(localRaw);
            const localDec = await aesDecrypt(key, localBlob);
            const localTs = localDec._savedAt || 0;
            if (localTs > cloudTs) {
              // Local is newer — keep local data, but DO update _ghSha so the next
              // save uses the correct version (the upcoming PUT will then overwrite
              // the older server version). This propagates pending local edits.
              useLocal = true;
              _ghSha = fetched.sha;
              localStorage.setItem(GH_SHA_KEY, fetched.sha);
              _ghSyncState = {state:'pending_push', message:'Lokale Änderungen warten auf Sync.', at:Date.now()};
              _notifySync && _notifySync();
              console.log('[loadEncrypted] local is newer than cloud — keeping local edits');
              return localDec;
            }
          } catch(e) { /* local unreadable — fall through to use cloud */ }
        }
        // Cloud is newer or no local — backup current local then commit cloud
        if (localRaw) {
          try { localStorage.setItem(DATA_BACKUP_KEY, localRaw); } catch(e){}
        }
        _ghSha = fetched.sha;
        localStorage.setItem(GH_SHA_KEY, fetched.sha);
        localStorage.setItem(DATA_KEY, JSON.stringify(fetched.content));
        saveLocalSnapshot(fetched.content); _lastSnapAt = Date.now();
        _ghSyncState = {state:'ok', at:Date.now()};
        _notifySync && _notifySync();
        return decrypted;
      } else {
        _ghSha = fetched.sha;
        localStorage.setItem(GH_SHA_KEY, fetched.sha);
      }
    } catch(e) {
      if (e.message === 'KEY_MISMATCH') throw e;
      _ghSyncState = {state:'error', message:e.message, at:Date.now()};
      _notifySync && _notifySync();
    }
  }
  const raw = localStorage.getItem(DATA_KEY);
  if (!raw) return null;
  try { return await aesDecrypt(key, JSON.parse(raw)); } catch(e) { return null; }
}

// ─── GitHub Sync ────────────────────────────────────────────────
const GH_SETTINGS_KEY = 'webars_gh_settings_v1';
const GH_SHA_KEY = 'webars_gh_sha_v1';
const GH_GIST_KEY = 'webars_jarvis_gist_v1';
const DATA_BACKUP_KEY = 'webars_data_backup_v1';
const SNAP_PREFIX = 'webars_snap_v2_';
const SNAP_SLOTS = 5;
let _lastSnapAt = 0;

function saveLocalSnapshot(encBlob) {
  try {
    let oi=0, ot=Infinity;
    for(let i=0;i<SNAP_SLOTS;i++){
      const r=localStorage.getItem(SNAP_PREFIX+i);
      if(!r){oi=i;ot=0;break;}
      try{const p=JSON.parse(r);if(p.t<ot){ot=p.t;oi=i;}}catch(e){}
    }
    localStorage.setItem(SNAP_PREFIX+oi, JSON.stringify({t:Date.now(),d:encBlob}));
  } catch(e){}
}
function getLocalSnapshots(){
  const r=[];
  for(let i=0;i<SNAP_SLOTS;i++){
    const raw=localStorage.getItem(SNAP_PREFIX+i);
    if(raw){try{const p=JSON.parse(raw);r.push({i,t:p.t,d:p.d});}catch(e){}}
  }
  return r.sort((a,b)=>b.t-a.t);
}

let _ghSettings = null;       // {token, repo, path}
let _ghSha = localStorage.getItem(GH_SHA_KEY) || null; // persisted across reloads
let _gistId = localStorage.getItem(GH_GIST_KEY) || null; // private Gist ID for Jarvis
let _ghSyncState = {state:'idle'}; // {state: 'idle'|'ok'|'error', message, at}
let _isSaving = false;        // true while saveEncrypted is running — blocks cloud polling
let _notifySync = null;       // hook for UI updates

function setSyncListener(fn) { _notifySync = fn; }
function getSyncState() { return _ghSyncState; }
function hasGithubSettings() {
  if (SELF_HOSTED && window.WEBARS_API_TOKEN) return true;
  return !!localStorage.getItem(GH_SETTINGS_KEY);
}

async function saveGithubSettings(key, settings) {
  const enc = await aesEncrypt(key, settings);
  localStorage.setItem(GH_SETTINGS_KEY, JSON.stringify(enc));
  _ghSettings = settings;
}
async function loadGithubSettings(key) {
  // In self-hosted mode the server injects the API token — no manual setup needed
  if (SELF_HOSTED && window.WEBARS_API_TOKEN) {
    _ghSettings = {token: window.WEBARS_API_TOKEN, repo: 'self-hosted', path: 'crm_data'};
    return _ghSettings;
  }
  const raw = localStorage.getItem(GH_SETTINGS_KEY);
  if (!raw) return null;
  try {
    const settings = await aesDecrypt(key, JSON.parse(raw));
    _ghSettings = settings;
    return settings;
  } catch(e) { return null; }
}
function clearGithubSettings() {
  localStorage.removeItem(GH_SETTINGS_KEY);
  _ghSettings = null;
  _ghSha = null;
  _ghSyncState = {state:'idle'};
}
function getJarvisGistId(){ return _gistId; }

function buildCrmSummary(state) {
  return {
    updatedAt: new Date().toISOString(),
    contacts: (state.contacts||[]).map(c=>({
      id:      c.id,
      name:    c.ansprechpartner||'',
      company: c.firma||'',
      email:   c.email||'',
      phone:   c.telefon||'',
      status:  c.status||'',
      address: [c.address,c.zip,c.city,c.country].filter(Boolean).join(', '),
      taxId:   c.taxId||'',
      umsatz:  c.umsatz||'',
      notizen: c.notizen||'',
    })),
    invoices: (state.invoices||[]).map(inv=>({
      id:          inv.id,
      number:      inv.number,
      status:      inv.status,
      contactName: inv.contactSnapshot?.firma||'',
      email:       inv.contactSnapshot?.email||'',
      total:       quoteTotals(inv).total,
      date:        inv.date,
      dueDate:     inv.dueDate,
    })),
    quotes: (state.quotes||[]).map(q=>({
      id:          q.id,
      number:      q.number,
      status:      q.status,
      contactName: q.contactSnapshot?.firma||'',
      email:       q.contactSnapshot?.email||'',
      total:       quoteTotals(q).total,
      date:        q.date,
    })),
    tasks: (state.todos||[]).map(t=>({
      id:          t.id,
      title:       t.text||'',
      description: t.description||'',
      status:      t.done?'erledigt':'offen',
      priority:    t.priority||'',
      dueDate:     t.dueDate||'',
      assignedTo:  '',
      contactName: '',
      createdAt:   t.createdAt||'',
      doneAt:      t.doneAt||'',
    })),
    campaigns: (state.campaigns||[]).map(c=>({
      id:        c.id,
      name:      c.name||'',
      color:     c.color||'',
      fileCount: (c.files||[]).length,
      files:     (c.files||[]).map(f=>({id:f.id,name:f.name,updatedAt:f.updatedAt||''})),
    })),
    employees: (state.aiEmployees||[]).map(e=>({
      id:      e.id,
      name:    e.name||'',
      role:    e.plan||e.role||'',
    })),
    forms: (state.forms||[]).map(f=>({
      id:            f.id,
      title:         f.title||'',
      slug:          f.slug||'',
      published:     !!f.published,
      responseCount: (state.formResponses||[]).filter(r=>r.formId===f.id).length,
    })),
    formResponses: (state.formResponses||[]).map(r=>({
      id:           r.id,
      formId:       r.formId,
      formTitle:    r.formTitle||'',
      contactName:  r.contactName||'',
      submittedAt:  r.submittedAt||'',
      read:         !!r.read,
    })),
  };
}
async function pushCrmSummary(state, ghSettings) {
  if (SELF_HOSTED) {
    try {
      await fetch('/api/summary', {
        method: 'PUT',
        headers: {Authorization: `Bearer ${ghSettings.token}`, 'Content-Type': 'application/json'},
        body: JSON.stringify(buildCrmSummary(state))
      });
    } catch(e) {}
    return;
  }
  try {
    const content = JSON.stringify(buildCrmSummary(state), null, 2);
    const headers = {Authorization:`Bearer ${ghSettings.token}`,'Content-Type':'application/json'};
    if (!_gistId) {
      // Erstmalig: neuen privaten Gist anlegen
      const r = await fetch('https://api.github.com/gists', {
        method:'POST', headers,
        body: JSON.stringify({
          description: 'CRM Summary — Jarvis API (privat, nicht löschen)',
          public: false,
          files: {'crm_summary.json': {content}}
        })
      });
      if (r.ok) {
        const j = await r.json();
        _gistId = j.id;
        localStorage.setItem(GH_GIST_KEY, _gistId);
      }
    } else {
      // Bestehenden Gist aktualisieren
      const r = await fetch(`https://api.github.com/gists/${_gistId}`, {
        method:'PATCH', headers,
        body: JSON.stringify({files: {'crm_summary.json': {content}}})
      });
      if (!r.ok) { _gistId = null; localStorage.removeItem(GH_GIST_KEY); }
    }
  } catch(e) {}
}

async function ghValidateAccess(token, repo) {
  if (SELF_HOSTED) {
    const r = await fetch('/api/validate', {
      headers: {Authorization: `Bearer ${token}`}
    });
    if (r.status === 401) throw new Error('API Key ungültig — stimmt der eingegebene Schlüssel?');
    if (!r.ok) throw new Error(`Server-Fehler ${r.status}`);
    return true;
  }
  const r = await fetch(`https://api.github.com/repos/${repo}`, {
    headers: {Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json'}
  });
  if (r.status === 401) throw new Error('Token ungültig oder abgelaufen.');
  if (r.status === 404) throw new Error('Repository nicht gefunden oder Token hat keinen Zugriff.');
  if (!r.ok) throw new Error(`GitHub-Fehler ${r.status}`);
  const j = await r.json();
  if (!j.permissions || !j.permissions.push) throw new Error('Token hat keine Schreibrechte für dieses Repo.');
  return true;
}

async function ghFetchFile(token, repo, path) {
  if (SELF_HOSTED) {
    const r = await fetch('/api/data', {
      headers: {Authorization: `Bearer ${token}`}
    });
    if (r.status === 401) {
      _ghSyncState = {state:'token_invalid', at:Date.now()};
      _notifySync && _notifySync();
      throw new Error('TOKEN_INVALID');
    }
    if (!r.ok) return {content: null, sha: null};
    const j = await r.json();
    if (!j.content) return {content: null, sha: null};
    return {content: j.content, sha: String(j.version)};
  }
  const r = await fetch(`https://api.github.com/repos/${repo}/contents/${path}?ref=main`, {
    headers: {Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json'}
  });
  if (r.status === 404) return {content: null, sha: null};
  if (r.status === 401 || r.status === 403) {
    _ghSyncState = {state:'token_invalid', at:Date.now()};
    _notifySync && _notifySync();
    throw new Error('TOKEN_INVALID');
  }
  if (!r.ok) throw new Error(`Sync-Fehler ${r.status}`);
  const j = await r.json();
  let content = null;
  try { content = JSON.parse(b64decode(j.content)); } catch(e) { throw new Error('Datei konnte nicht gelesen werden.'); }
  return {content, sha: j.sha};
}

async function ghPushFile(token, repo, path, content, sha = null, message = 'Update CRM') {
  if (SELF_HOSTED) {
    const r = await fetch('/api/data', {
      method: 'PUT',
      headers: {Authorization: `Bearer ${token}`, 'Content-Type': 'application/json'},
      body: JSON.stringify({content, version: sha ? Number(sha) : null})
    });
    if (r.status === 409) throw new Error('CONFLICT');
    if (r.status === 401) {
      _ghSyncState = {state:'token_invalid', at:Date.now()};
      _notifySync && _notifySync();
      throw new Error('TOKEN_INVALID');
    }
    if (!r.ok) {
      const e = await r.json().catch(()=>({}));
      throw new Error(`Sync fehlgeschlagen: ${e.error || r.status}`);
    }
    const j = await r.json();
    return String(j.version);
  }
  const body = {
    message: `${message} · ${new Date().toISOString().slice(0,16).replace('T',' ')}`,
    content: b64encode(JSON.stringify(content)),
    branch: 'main',
    ...(sha ? {sha} : {})
  };
  const r = await fetch(`https://api.github.com/repos/${repo}/contents/${path}`, {
    method: 'PUT',
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github+json',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(body)
  });
  if (r.status === 409) {
    // SHA conflict — someone else pushed. Refetch and retry once.
    const {sha: latestSha} = await ghFetchFile(token, repo, path);
    if (latestSha && latestSha !== sha) {
      throw new Error('CONFLICT'); // caller can decide how to handle
    }
  }
  if (r.status === 401 || r.status === 403) {
    _ghSyncState = {state:'token_invalid', at:Date.now()};
    _notifySync && _notifySync();
    throw new Error('TOKEN_INVALID');
  }
  if (!r.ok) {
    const err = await r.json().catch(()=>({}));
    throw new Error(`Sync fehlgeschlagen: ${err.message || r.status}`);
  }
  const j = await r.json();
  return j.content.sha;
}

// Poll for updates from other team members
async function ghCheckForUpdates(key) {
  if (!_ghSettings) return null;
  if (_isSaving) return null; // Nicht während eines laufenden Speichervorgangs überschreiben
  if (SELF_HOSTED) {
    try {
      const r = await fetch('/api/data', {
        headers: {Authorization: `Bearer ${_ghSettings.token}`}
      });
      if (!r.ok) return null;
      const j = await r.json();
      if (!j.content) return null;
      const newVer = String(j.version);
      if (newVer === _ghSha) return null; // nothing changed
      const content = j.content;
      const decrypted = await aesDecrypt(key, content);
      const cloudTs = decrypted._savedAt || 0;
      const localRaw = localStorage.getItem(DATA_KEY);
      let localTs = 0;
      if (localRaw) { try { const ld = await aesDecrypt(key, JSON.parse(localRaw)); localTs = ld?._savedAt||0; } catch(e){} }
      if (cloudTs > 0 && cloudTs <= localTs) {
        _ghSha = newVer; localStorage.setItem(GH_SHA_KEY, newVer); return null;
      }
      if (localRaw) localStorage.setItem(DATA_BACKUP_KEY, localRaw);
      _ghSha = newVer; localStorage.setItem(GH_SHA_KEY, newVer);
      localStorage.setItem(DATA_KEY, JSON.stringify(content));
      return decrypted;
    } catch(e) { return null; }
  }
  try {
    const r = await fetch(`https://api.github.com/repos/${_ghSettings.repo}/contents/${_ghSettings.path}?ref=main`, {
      headers: {Authorization: `Bearer ${_ghSettings.token}`, Accept: 'application/vnd.github+json'}
    });
    if (!r.ok) return null;
    const j = await r.json();
    if (j.sha === _ghSha) return null; // no changes
    // SHA changed — decrypt and compare timestamps before overwriting
    const content = JSON.parse(b64decode(j.content));
    const decrypted = await aesDecrypt(key, content);
    const cloudTs = decrypted._savedAt || 0;
    // Read local timestamp to avoid overwriting newer local data with older cloud data
    const localRaw = localStorage.getItem(DATA_KEY);
    let localTs = 0;
    if (localRaw) { try { const ld = await aesDecrypt(key, JSON.parse(localRaw)); localTs = ld?._savedAt||0; } catch(e){} }
    if (cloudTs > 0 && cloudTs <= localTs) {
      // Cloud version is older — update SHA so we stop re-checking, but don't overwrite state
      _ghSha = j.sha;
      localStorage.setItem(GH_SHA_KEY, j.sha);
      return null;
    }
    // Cloud is newer (or no timestamp yet) — backup current local data first, then apply
    if (localRaw) localStorage.setItem(DATA_BACKUP_KEY, localRaw);
    _ghSha = j.sha;
    localStorage.setItem(GH_SHA_KEY, j.sha);
    localStorage.setItem(DATA_KEY, JSON.stringify(content));
    return decrypted;
  } catch(e) { return null; }
}

// ─── Device-key helpers (TOTP-only login) ───────────────────────
async function getOrCreateDeviceKey() {
  const stored = localStorage.getItem(DEVICE_KEY_STORE);
  if (stored) {
    return crypto.subtle.importKey('raw', fromB64(stored), 'AES-GCM', false, ['encrypt','decrypt']);
  }
  const key = await crypto.subtle.generateKey({name:'AES-GCM',length:256}, true, ['encrypt','decrypt']);
  const exp = await crypto.subtle.exportKey('raw', key);
  localStorage.setItem(DEVICE_KEY_STORE, toB64(exp));
  return key;
}
async function storeKeyForDevice(cryptoKey) {
  const dk = await getOrCreateDeviceKey();
  const rawKey = await crypto.subtle.exportKey('raw', cryptoKey);
  localStorage.setItem(PKEY_ENC_STORE, JSON.stringify(await aesEncrypt(dk, toB64(rawKey))));
}
async function storeTOTPAndKeyForDevice(totpSecret, cryptoKey) {
  const dk = await getOrCreateDeviceKey();
  localStorage.setItem(TOTP_ENC_STORE, JSON.stringify(await aesEncrypt(dk, totpSecret)));
  const rawKey = await crypto.subtle.exportKey('raw', cryptoKey);
  localStorage.setItem(PKEY_ENC_STORE, JSON.stringify(await aesEncrypt(dk, toB64(rawKey))));
}
async function loginWithTOTPCode(code) {
  const totpRaw = localStorage.getItem(TOTP_ENC_STORE);
  const pkeyRaw = localStorage.getItem(PKEY_ENC_STORE);
  if (!totpRaw || !pkeyRaw) return null; // not set up on this device
  const dk = await getOrCreateDeviceKey();
  try {
    const totpSecret = await aesDecrypt(dk, JSON.parse(totpRaw));
    const ok = await verifyTOTP(totpSecret, code);
    if (!ok) return false; // wrong code
    const b64key = await aesDecrypt(dk, JSON.parse(pkeyRaw));
    return crypto.subtle.importKey('raw', fromB64(b64key), {name:'AES-GCM',length:256}, false, ['encrypt','decrypt']);
  } catch(e) { return null; }
}
function hasDeviceKeySetup() { return !!localStorage.getItem(TOTP_ENC_STORE) && !!localStorage.getItem(PKEY_ENC_STORE); }

// ─── TOTP ───────────────────────────────────────────────────────
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function base32Encode(bytes) {
  let bits=0,val=0,out='';
  for(const b of bytes){val=(val<<8)|b;bits+=8;while(bits>=5){out+=B32[(val>>>(bits-5))&31];bits-=5;}}
  if(bits>0) out+=B32[(val<<(5-bits))&31];
  return out;
}
function base32Decode(s) {
  s=s.toUpperCase().replace(/=+$/,'');
  let bits=0,val=0;const out=[];
  for(const c of s){const i=B32.indexOf(c);if(i<0)continue;val=(val<<5)|i;bits+=5;if(bits>=8){out.push((val>>>(bits-8))&255);bits-=8;}}
  return new Uint8Array(out);
}
function generateTOTPSecret() {
  return base32Encode(crypto.getRandomValues(new Uint8Array(20)));
}
async function computeTOTP(secretB32, timeCounter) {
  const key = await crypto.subtle.importKey('raw', base32Decode(secretB32), {name:'HMAC',hash:'SHA-1'}, false, ['sign']);
  const buf = new ArrayBuffer(8);
  new DataView(buf).setUint32(4, timeCounter>>>0, false);
  const hmac = new Uint8Array(await crypto.subtle.sign('HMAC', key, buf));
  const off = hmac[19]&0xf;
  const code=((hmac[off]&0x7f)<<24|hmac[off+1]<<16|hmac[off+2]<<8|hmac[off+3])%1000000;
  return code.toString().padStart(6,'0');
}
async function verifyTOTP(secretB32, userCode) {
  const clean = userCode.replace(/\s/g,'');
  if(clean.length!==6) return false;
  const t = Math.floor(Date.now()/1000/30);
  for(let d=-1;d<=1;d++){
    if(await computeTOTP(secretB32,t+d)===clean) return true;
  }
  return false;
}
function makeOTPAuthURL(secret, email='WebArs CRM') {
  return `otpauth://totp/${encodeURIComponent('WebArs CRM')}:${encodeURIComponent(email)}?secret=${secret}&issuer=${encodeURIComponent('WebArs CRM')}&algorithm=SHA1&digits=6&period=30`;
}

// ════════════════════════════════════════════════════════════════════
// REACT-KOMPONENTEN (Original Zeilen 1153-9892 aus legacy/index.html)
// ════════════════════════════════════════════════════════════════════


// ── HELPERS ─────────────────────────────────────────────────────
const uid     = () => Math.random().toString(36).slice(2,10);
const fmt     = n  => (n!=null&&n!=='') ? `€\u00a0${Number(n).toLocaleString('de-AT')}` : null;
const fmtDate = iso=> iso ? new Date(iso).toLocaleDateString('de-AT',{day:'2-digit',month:'short',year:'numeric'}) : '–';

const STATUS_META = {
  'Aktiv':         {dot:'#22c55e',bg:'#F0FDF4',color:'#15803d'},
  'Lead':          {dot:'#3b82f6',bg:'#EFF6FF',color:'#1d4ed8'},
  'Kalt':          {dot:'#94a3b8',bg:'#F8FAFC',color:'#64748b'},
  'In Gespräch':   {dot:'#f59e0b',bg:'#FFFBEB',color:'#b45309'},
  'Abgeschlossen': {dot:'#8b5cf6',bg:'#F5F3FF',color:'#6d28d9'},
  'Inaktiv':       {dot:'#ef4444',bg:'#FEF2F2',color:'#b91c1c'},
};
const STATUSES = Object.keys(STATUS_META);
const AVATAR_COLORS = ['#C8943A','#4A7FA5','#6B9E6B','#9B6B9B','#C8643A','#3A8F8F','#B8734A','#5A7FA0','#7A9B5A','#A06B7A'];
const avatarColor = str => { let h=0;for(let c of str)h=(h*31+c.charCodeAt(0))%AVATAR_COLORS.length;return AVATAR_COLORS[Math.abs(h)]; };

const DEFAULT_SECTIONS = [
  {id:'hauptkunden',name:'Hauptkunden',icon:'◆'},
  {id:'leads',name:'Leads',icon:'◎'},
  {id:'kaltkontakte',name:'Kaltkontakte',icon:'❄'},
];
const DEFAULT_SUBSECTIONS = [
  {id:'hk-aktiv',  sectionId:'hauptkunden',name:'Aktive Kunden',  order:0},
  {id:'hk-fertig', sectionId:'hauptkunden',name:'Projekt fertig', order:1},
  {id:'hk-pause',  sectionId:'hauptkunden',name:'Pausiert',       order:2},
  {id:'leads-neu', sectionId:'leads',       name:'Neue Leads',    order:0},
  {id:'leads-qual',sectionId:'leads',       name:'Qualifiziert',  order:1},
];
const SAMPLE_CONTACTS = [
  {id:uid(),sectionId:'hauptkunden',subsectionId:'hk-aktiv', firma:'Muster GmbH',email:'office@muster.at',telefon:'+43 1 234 5678',status:'Aktiv',notizen:'Langjähriger Stammkunde.',umsatz:24500,reminders:[],activities:[{id:uid(),text:'Erstgespräch geführt',date:'2025-03-10'}],customValues:{}},
  {id:uid(),sectionId:'hauptkunden',subsectionId:'hk-aktiv', firma:'Alpen Tech AG',email:'info@alpentech.at',telefon:'+43 512 88 44 00',status:'Aktiv',notizen:'Jahresvertrag bis Dezember.',umsatz:87000,reminders:[{id:uid(),text:'Verlängerung besprechen',date:'2026-11-15'}],activities:[],customValues:{}},
  {id:uid(),sectionId:'hauptkunden',subsectionId:'hk-fertig',firma:'Wiener Manufaktur KG',email:'kontakt@wm-kg.at',telefon:'+43 1 987 6543',status:'Abgeschlossen',notizen:'',umsatz:14200,reminders:[],activities:[],customValues:{}},
  {id:uid(),sectionId:'leads',      subsectionId:'leads-neu', firma:'Digital Minds KG',email:'hallo@digitalminds.at',telefon:'+43 699 1234 567',status:'Lead',notizen:'Interesse an Website-Relaunch.',umsatz:'',reminders:[],activities:[],customValues:{}},
  {id:uid(),sectionId:'leads',      subsectionId:'leads-qual',firma:'Sonnleitner & Partner',email:'s.sonnleitner@partner.at',telefon:'+43 676 555 22 11',status:'In Gespräch',notizen:'Zweites Meeting nächste Woche.',umsatz:12000,reminders:[],activities:[],customValues:{}},
  {id:uid(),sectionId:'kaltkontakte',subsectionId:null,       firma:'Bergkristall GmbH',email:'info@bergkristall.at',telefon:'+43 732 55 66 77',status:'Kalt',notizen:'Auf Messe getroffen.',umsatz:'',reminders:[],activities:[],customValues:{}},
];
const DEFAULT_QUOTE_SETTINGS = {
  companyName:'WebArs',
  companyAddress:'',
  companyEmail:'',
  companyPhone:'',
  companyWebsite:'',
  taxId:'', // USt-IdNr / UID
  iban:'',
  bic:'',
  bankName:'',
  defaultIntro:'vielen Dank für das angenehme Gespräch und Ihr Interesse an einer Zusammenarbeit. Auf Basis Ihrer Anforderungen haben wir folgendes Angebot für Sie zusammengestellt.',
  defaultTerms:'Dieses Angebot ist 30 Tage gültig.\nAnzahlung 50 % erst nach gemeinsam vereinbartem Projektstart — nicht bei Angebotsannahme.\nRestbetrag nach Fertigstellung, 14 Tage netto.\nAlle Preise zzgl. der gesetzlichen USt.',
  defaultFooter:'Wir freuen uns auf eine erfolgreiche Zusammenarbeit.',
  defaultNextSteps:'1. Sie nehmen das Angebot an — kein Zahlungseingang nötig.\n2. Wir legen gemeinsam einen Starttermin fest.\n3. Anzahlung 50 % nach Starttermin-Bestätigung.\n4. Fertigstellung: 1 Woche nach Projektstart.',
  accentColor:'#141210',
  taxRate:20,
  currency:'EUR',
  quoteCounter:1,
  quotePrefix:'AN',
  logoUrl:'',
  bannerUrl:''
};
const DEFAULT_INVOICE_SETTINGS = {
  numberPrefix:'RE',
  invoiceCounter:1,
  defaultDueDays:14,
  paymentNote:'Bitte überweisen Sie den Betrag unter Angabe der Rechnungsnummer auf folgendes Konto.',
};
const ONBOARDING_FORM_FIELDS = [
  {id:'f_name', type:'text', label:'Ihr Name', required:true, help:'Damit ich Ihre Antworten richtig zuordnen kann.'},

  {id:'f_section_1', type:'section', label:'Über Sie & Ihr Angebot'},
  {id:'f_about', type:'textarea', label:'Was bieten Sie an, und was soll auf der Website vorgestellt werden?', required:true, help:'Bitte kurz in 2–3 Sätzen: Was machen Sie, für wen, und was macht Sie besonders?'},

  {id:'f_section_2', type:'section', label:'Ziele & Zielgruppe'},
  {id:'f_goal', type:'multiselect', label:'Was soll Ihre Website hauptsächlich erreichen?', required:true, options:['Neue Kunden gewinnen','Mein Unternehmen vorstellen','Vertrauen aufbauen','Terminbuchungen ermöglichen','Produkte oder Leistungen präsentieren','Online besser gefunden werden','Etwas anderes']},
  {id:'f_priority', type:'multiselect', label:'Was ist Ihnen bei der neuen Website am wichtigsten?', required:true, options:['Professioneller Auftritt','Modernes Design','Klare Struktur & Übersicht','Schnell online gehen','Günstig umsetzen','Etwas anderes']},
  {id:'f_audience', type:'text', label:'Wer soll die Website hauptsächlich besuchen?', required:false, help:'Zum Beispiel: Privatkunden, Firmenkunden, Patienten, Gäste, Bewerber …'},

  {id:'f_section_3', type:'section', label:'Aufbau & Design'},
  {id:'f_pages', type:'multiselect', label:'Welche Seiten soll Ihre Website ungefähr haben?', required:true, options:['Startseite','Über uns / Über mich','Leistungen / Angebote','Preise','Galerie / Referenzen','Kontakt','Häufige Fragen','Impressum / Datenschutz','Andere']},
  {id:'f_contact_methods', type:'multiselect', label:'Wie sollen Besucher Sie kontaktieren können?', required:true, options:['Telefon','E-Mail','Kontaktformular','WhatsApp','Terminbuchung','Adresse / Anfahrt','Social Media']},
  {id:'f_likes', type:'textarea', label:'Gibt es Websites, die Ihnen gefallen?', required:false, help:'Links einfügen — es reicht wenn Ihnen nur bestimmte Bereiche gefallen.'},
  {id:'f_style', type:'textarea', label:'Haben Sie Vorstellungen zu Farben, Schriften oder Stil?', required:false, help:'Zum Beispiel: modern, schlicht, elegant, freundlich, luxuriös, seriös …'},

  {id:'f_section_4', type:'section', label:'Inhalte & Materialien'},
  {id:'f_texts', type:'select', label:'Haben Sie bereits Texte für die Website?', required:true, options:['Ja, vollständig','Teilweise','Nein, ich brauche Unterstützung']},
  {id:'f_show_prices', type:'select', label:'Sollen Preise oder Pakete auf der Website stehen?', required:true, options:['Ja','Nein','Lieber persönlich besprechen']},
  {id:'f_pw_notice', type:'info', label:'Bitte senden Sie keine Passwörter über dieses Formular. Falls ich Zugriff benötige, klären wir das sicher separat.'},
  {id:'f_files', type:'file', label:'Logo, Bilder oder sonstige Dateien hochladen', required:false, multiple:true, help:'Alles auf einmal — Logo, Fotos, bestehende Unterlagen usw.'},

  {id:'f_section_5', type:'section', label:'Abschluss'},
  {id:'f_has_domain', type:'select', label:'Haben Sie bereits eine Domain?', required:true, help:'Eine Domain ist Ihre Webadresse, z. B. www.ihrefirma.at.', options:['Ja','Nein','Ich bin mir nicht sicher']},
  {id:'f_legal', type:'select', label:'Haben Sie bereits Impressum & Datenschutzerklärung?', required:true, options:['Ja','Nein','Ich bin mir nicht sicher']},
  {id:'f_deadline', type:'text', label:'Gibt es einen gewünschten Fertigstellungstermin?', required:false},
  {id:'f_other', type:'textarea', label:'Gibt es sonst noch etwas, das ich wissen sollte?', required:false},
];

const DEFAULT_ONBOARDING_FORM = {
  id:'form_onboarding',
  slug:'website-onboarding',
  title:'Website-Onboarding',
  intro:'Damit ich Ihre Website optimal planen und gestalten kann, beantworten Sie mir bitte die folgenden Fragen. Dauert ca. 5–10 Minuten — Sie können jederzeit pausieren.',
  thanks:'Vielen Dank! Ihre Antworten sind angekommen. Ich melde mich in den nächsten Tagen bei Ihnen.',
  submitEmail:'',
  fields: ONBOARDING_FORM_FIELDS,
  createdAt: null,
  published: false,
};

const DEFAULT_STATE = {sections:DEFAULT_SECTIONS,subsections:DEFAULT_SUBSECTIONS,contacts:SAMPLE_CONTACTS,customFields:[],members:[],todos:[],aiEmployees:[],claudeAccounts:[],claudeTasks:[],quotes:[],quoteSettings:DEFAULT_QUOTE_SETTINGS,invoices:[],invoiceSettings:DEFAULT_INVOICE_SETTINGS,tokens:[],forms:[DEFAULT_ONBOARDING_FORM],formResponses:[],campaigns:[],leads:[],coldCampaigns:[],visualizations:[]};

const lbl = {display:'block',fontSize:11,fontWeight:600,color:'#A8A39D',marginBottom:6,textTransform:'uppercase',letterSpacing:'0.06em'};

// ── ICONS ────────────────────────────────────────────────────────
const Icons = {
  Plus:    ()=><svg width="13" height="13" viewBox="0 0 13 13" fill="none"><path d="M6.5 1v11M1 6.5h11" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round"/></svg>,
  Edit:    ()=><svg width="13" height="13" viewBox="0 0 13 13" fill="none"><path d="M9 2l2 2-6 6H3v-2l6-6z" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round"/></svg>,
  Trash:   ()=><svg width="13" height="13" viewBox="0 0 13 13" fill="none"><path d="M2 4h9M5 4V2.5h3V4M4 4l.5 6.5h4L9 4" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round"/></svg>,
  Search:  ()=><svg width="14" height="14" viewBox="0 0 14 14" fill="none"><circle cx="6" cy="6" r="4.5" stroke="currentColor" strokeWidth="1.5"/><path d="M10 10l2.5 2.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/></svg>,
  Move:    ()=><svg width="13" height="13" viewBox="0 0 13 13" fill="none"><path d="M2 6.5h9M8 4l3 2.5L8 9" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round"/></svg>,
  Bell:    ()=><svg width="12" height="12" viewBox="0 0 12 12" fill="none"><path d="M6 1a3 3 0 013 3c0 2.5 1 3 1 3H2s1-.5 1-3a3 3 0 013-3zM5 10a1 1 0 002 0" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round"/></svg>,
  Export:  ()=><svg width="13" height="13" viewBox="0 0 13 13" fill="none"><path d="M6.5 1v7M4 5l2.5 3L9 5M2 11h9" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/></svg>,
  Close:   ()=><svg width="11" height="11" viewBox="0 0 11 11" fill="none"><path d="M1 1l9 9M10 1l-9 9" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round"/></svg>,
  Field:   ()=><svg width="13" height="13" viewBox="0 0 13 13" fill="none"><rect x="1" y="2.5" width="11" height="2.5" rx="1" stroke="currentColor" strokeWidth="1.3"/><rect x="1" y="8" width="7" height="2.5" rx="1" stroke="currentColor" strokeWidth="1.3"/></svg>,
  Lock:    ()=><svg width="13" height="13" viewBox="0 0 13 13" fill="none"><rect x="2" y="5.5" width="9" height="6.5" rx="2" stroke="currentColor" strokeWidth="1.4"/><path d="M4.5 5.5V4a2 2 0 014 0v1.5" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round"/><circle cx="6.5" cy="8.5" r="1" fill="currentColor"/></svg>,
  Invite:  ()=><svg width="13" height="13" viewBox="0 0 13 13" fill="none"><circle cx="5" cy="4.5" r="2.5" stroke="currentColor" strokeWidth="1.3"/><path d="M1 11c0-2.2 1.8-4 4-4" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round"/><path d="M10 8v4M8 10h4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/></svg>,
  Members: ()=><svg width="13" height="13" viewBox="0 0 13 13" fill="none"><circle cx="4.5" cy="4" r="2" stroke="currentColor" strokeWidth="1.3"/><path d="M1 11c0-2 1.6-3.5 3.5-3.5S8 9 8 11" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round"/><circle cx="9.5" cy="4.5" r="1.5" stroke="currentColor" strokeWidth="1.2"/><path d="M11 11c0-1.4-1-2.5-2-2.8" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round"/></svg>,
  Import:  ()=><svg width="13" height="13" viewBox="0 0 13 13" fill="none"><path d="M6.5 8V1M4 5.5l2.5 3 2.5-3" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/><path d="M2 10h9" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/></svg>,
  Tab:     ()=><svg width="13" height="13" viewBox="0 0 13 13" fill="none"><rect x="1" y="3" width="11" height="8" rx="1.5" stroke="currentColor" strokeWidth="1.3"/><path d="M1 6h11" stroke="currentColor" strokeWidth="1.3"/></svg>,
  Eye:     ()=><svg width="14" height="14" viewBox="0 0 14 14" fill="none"><path d="M1 7s2.5-4.5 6-4.5S13 7 13 7s-2.5 4.5-6 4.5S1 7 1 7z" stroke="currentColor" strokeWidth="1.4"/><circle cx="7" cy="7" r="1.8" stroke="currentColor" strokeWidth="1.4"/></svg>,
  EyeOff:  ()=><svg width="14" height="14" viewBox="0 0 14 14" fill="none"><path d="M1 1l12 12M5.5 5.7A2 2 0 009.3 9M3 3.6C1.8 4.7 1 6 1 7s2.5 4.5 6 4.5c1.2 0 2.3-.3 3.2-.8M5 2.6C5.6 2.5 6.3 2.5 7 2.5c3.5 0 6 4.5 6 4.5s-.5 1-1.5 2" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round"/></svg>,
  Activity:()=><svg width="12" height="12" viewBox="0 0 12 12" fill="none"><path d="M1 6h2l2-4 2 8 1.5-4.5L10 6h1" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round"/></svg>,
  Reminder:()=><svg width="12" height="12" viewBox="0 0 12 12" fill="none"><circle cx="6" cy="6" r="5" stroke="currentColor" strokeWidth="1.3"/><path d="M6 3.5v3l2 1" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round"/></svg>,
  Check:   ()=><svg width="13" height="13" viewBox="0 0 13 13" fill="none"><rect x="1.5" y="1.5" width="10" height="10" rx="2.5" stroke="currentColor" strokeWidth="1.4"/><path d="M4 6.5l2 2 3-3" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round"/></svg>,
  Shield:  ()=><svg width="14" height="14" viewBox="0 0 14 14" fill="none"><path d="M7 1.5L2 4v4c0 3 2.2 5.8 5 6.5 2.8-.7 5-3.5 5-6.5V4L7 1.5z" stroke="rgba(255,255,255,0.3)" strokeWidth="1.3" strokeLinejoin="round"/></svg>,
  Auth:    ()=><svg width="14" height="14" viewBox="0 0 14 14" fill="none"><rect x="1" y="6" width="12" height="7" rx="2" stroke="rgba(255,255,255,0.3)" strokeWidth="1.3"/><path d="M4 6V4.5a3 3 0 016 0V6" stroke="rgba(255,255,255,0.3)" strokeWidth="1.3" strokeLinecap="round"/><circle cx="7" cy="9.5" r="1.2" fill="rgba(255,255,255,0.3)"/></svg>,
  Bot:     ()=><svg width="13" height="13" viewBox="0 0 13 13" fill="none"><rect x="2" y="4" width="9" height="7" rx="1.8" stroke="currentColor" strokeWidth="1.3"/><circle cx="5" cy="7.5" r="0.9" fill="currentColor"/><circle cx="8" cy="7.5" r="0.9" fill="currentColor"/><path d="M6.5 1.5v2.5M5 2.5h3" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round"/></svg>,
  Doc:     ()=><svg width="12" height="12" viewBox="0 0 12 12" fill="none"><path d="M2.5 1.5h5L9.5 3.5v7a1 1 0 01-1 1h-6a1 1 0 01-1-1v-8a1 1 0 011-1z" stroke="currentColor" strokeWidth="1.3" strokeLinejoin="round"/><path d="M7 1.5v2.5h2.5M3.5 6.5h5M3.5 8.5h3" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round"/></svg>,
  Logout:  ()=><svg width="13" height="13" viewBox="0 0 13 13" fill="none"><path d="M5.5 1.5h-3a1 1 0 00-1 1v8a1 1 0 001 1h3" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round"/><path d="M8.5 4l2.5 2.5L8.5 9M11 6.5H5" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round"/></svg>,
  Cloud:   ()=><svg width="13" height="13" viewBox="0 0 13 13" fill="none"><path d="M3.5 9.5a2.5 2.5 0 010-5 3.5 3.5 0 016.6-1A2.5 2.5 0 1110 9.5h-6.5z" stroke="currentColor" strokeWidth="1.3" strokeLinejoin="round"/></svg>,
  Quote:   ()=><svg width="13" height="13" viewBox="0 0 13 13" fill="none"><rect x="2" y="1.5" width="9" height="10" rx="1.4" stroke="currentColor" strokeWidth="1.3"/><path d="M4 4.5h5M4 6.5h5M4 8.5h3" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round"/></svg>,
  Invoice: ()=><svg width="13" height="13" viewBox="0 0 13 13" fill="none"><rect x="1.5" y="1.5" width="10" height="10" rx="1.4" stroke="currentColor" strokeWidth="1.3"/><path d="M4 4.5h5M4 6.5h3.5" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round"/><path d="M7.5 8.5h2" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round"/><circle cx="4.5" cy="8.5" r=".8" fill="currentColor"/></svg>,
  Print:   ()=><svg width="13" height="13" viewBox="0 0 13 13" fill="none"><path d="M3 5V2h7v3M3 9.5H2a1 1 0 01-1-1v-3a1 1 0 011-1h9a1 1 0 011 1v3a1 1 0 01-1 1h-1M3 8h7v3.5H3z" stroke="currentColor" strokeWidth="1.3" strokeLinejoin="round"/></svg>,
  Mail:    ()=><svg width="13" height="13" viewBox="0 0 13 13" fill="none"><rect x="1.5" y="3" width="10" height="7" rx="1.3" stroke="currentColor" strokeWidth="1.3"/><path d="M2 4l4.5 3 4.5-3" stroke="currentColor" strokeWidth="1.3" strokeLinejoin="round"/></svg>,
};

// ── STATUS DOT ───────────────────────────────────────────────────
function StatusDot({status}){
  const m=STATUS_META[status]||{dot:'#94a3b8',bg:'#F8FAFC',color:'#64748b'};
  return <span style={{display:'inline-flex',alignItems:'center',gap:5,padding:'3px 9px 3px 7px',borderRadius:99,background:m.bg,fontSize:11.5,fontWeight:600,color:m.color}}>
    <span style={{width:5,height:5,borderRadius:'50%',background:m.dot,flexShrink:0}}></span>{status}
  </span>;
}

// ── QR CODE COMPONENT ────────────────────────────────────────────
function QRCodeImage({url}) {
  // Uses Google Chart API to render QR code client-side via img
  const encoded = encodeURIComponent(url);
  const src = `https://chart.googleapis.com/chart?cht=qr&chs=256x256&chld=M|1&chl=${encoded}`;
  const [loaded, setLoaded] = useState(false);
  const [error,  setError]  = useState(false);
  return (
    <div style={{width:200,height:200,background:'white',borderRadius:12,display:'flex',alignItems:'center',justifyContent:'center',overflow:'hidden',position:'relative'}}>
      {!loaded && !error && <div style={{position:'absolute',inset:0,display:'flex',alignItems:'center',justifyContent:'center',background:'white',borderRadius:12}}><span style={{color:'#C8C3BD',fontSize:13}}>Lade…</span></div>}
      {error && <div style={{padding:12,textAlign:'center',fontSize:12,color:'#888',lineHeight:1.5}}>QR-Code konnte nicht geladen werden. Bitte den Code manuell eingeben.</div>}
      <img
        src={src}
        onLoad={()=>setLoaded(true)}
        onError={()=>setError(true)}
        style={{width:200,height:200,display:loaded?'block':'none',borderRadius:12}}
        alt="QR Code"
      />
    </div>
  );
}

// ── TOTP TIMER ───────────────────────────────────────────────────
// (TOTPTimer entfernt — Authenticator-Login nicht mehr verwendet)

// ── PASSWORD INPUT ───────────────────────────────────────────────
function PasswordInput({value,onChange,placeholder,autoFocus,onKeyDown,className}){
  const [show,setShow]=useState(false);
  return(
    <div style={{position:'relative'}}>
      <input type={show?'text':'password'} value={value} onChange={onChange} placeholder={placeholder||'Passwort'} autoFocus={autoFocus} onKeyDown={onKeyDown} className={`auth-input ${className||''}`} style={{paddingRight:44}}/>
      <button onClick={()=>setShow(s=>!s)} style={{position:'absolute',right:12,top:'50%',transform:'translateY(-50%)',background:'none',border:'none',color:'rgba(255,255,255,0.35)',lineHeight:0,padding:4,cursor:'pointer'}}>
        {show?<Icons.EyeOff/>:<Icons.Eye/>}
      </button>
    </div>
  );
}



// ══════════════════════════════════════════════════════════════════
//  AUTH SCREEN  — WordPress-Style: nur Passwort, fertig
// ══════════════════════════════════════════════════════════════════
function AuthScreen({mode, onDone, onSwitchMode, onForgotPassword}) {
  const isSetup = mode === 'setup';
  const [email, setEmail] = useState(OWNER_EMAIL || '');
  const [pw,    setPw]    = useState('');
  const [pw2,   setPw2]   = useState('');
  const [err,   setErr]   = useState('');
  const [busy,  setBusy]  = useState(false);

  const submit = async () => {
    if (isSetup) {
      if (!email.trim().includes('@')) { setErr('Bitte gültige E-Mail-Adresse eingeben.'); return; }
      if (pw.length < 8)              { setErr('Passwort: mindestens 8 Zeichen.'); return; }
      if (pw !== pw2)                 { setErr('Passwörter stimmen nicht überein.'); return; }
    }
    setBusy(true); setErr('');
    try {
      if (isSetup) {
        const trimmed = email.trim().toLowerCase();
        await storeEmailHash(trimmed);
        const masterKey = await setupPassword(pw);
        await saveEncrypted(masterKey, DEFAULT_STATE);
        try { await storeKeyForDevice(masterKey); } catch(e) {}
        onDone(masterKey, DEFAULT_STATE, trimmed);
      } else {
        const key = await verifyPassword(pw);
        if (!key) { setErr('Falsches Passwort.'); setBusy(false); return; }
        let data;
        try {
          data = await loadEncrypted(key);
        } catch(loadErr) {
          if (loadErr && loadErr.message === 'KEY_MISMATCH') {
            // Password unlocked the wrap key but resulting master key cannot
            // decrypt server data → auth-blob and crm_data are out of sync.
            setErr('Anmeldung erfolgreich, aber Server-Daten passen nicht zum Schlüssel. Bitte Admin kontaktieren oder ein Backup wiederherstellen.');
            setBusy(false);
            return;
          }
          throw loadErr;
        }
        try { await storeKeyForDevice(key); } catch(e) {}
        onDone(key, data || DEFAULT_STATE, OWNER_EMAIL);
      }
    } catch(e) {
      const msg = e?.message || '';
      if (/AUTH_ALREADY_EXISTS/.test(msg)) {
        setErr('Es existiert bereits ein Konto am Server. Bitte stattdessen anmelden.');
        if (onSwitchMode) setTimeout(onSwitchMode, 1500);
      } else if (msg.startsWith('RATE_LIMITED:')) {
        setErr(msg.replace('RATE_LIMITED:', ''));
      } else {
        setErr('Fehler. Bitte erneut versuchen.');
      }
    }
    setBusy(false);
  };

  const S = {background:'rgba(255,255,255,0.07)',border:'1.5px solid rgba(255,255,255,0.1)',borderRadius:10,padding:'13px 14px',color:'white',fontSize:14,outline:'none',width:'100%',boxSizing:'border-box'};

  return (
    <div className="auth-screen">
      <div className="auth-card">
        <div style={{textAlign:'center',marginBottom:28}}>
          <img src="/logo.png" alt="WebArs" style={{width:60,height:60,borderRadius:'50%',marginBottom:14,boxShadow:'0 8px 24px rgba(0,0,0,0.4)'}}/>
          <div style={{fontWeight:800,fontSize:22,color:'white',letterSpacing:'-0.02em'}}>WebArs CRM</div>
          <div style={{fontSize:13,color:'rgba(255,255,255,0.35)',marginTop:4}}>{isSetup?'Konto einrichten':'Anmelden'}</div>
        </div>
        <div className="auth-panel" style={{display:'grid',gap:14}}>
          {isSetup && (
            <input type="email" value={email} onChange={e=>setEmail(e.target.value)}
              placeholder="E-Mail-Adresse" autoFocus style={S}
              onKeyDown={e=>e.key==='Enter'&&!busy&&submit()}/>
          )}
          <PasswordInput value={pw} onChange={e=>setPw(e.target.value)}
            placeholder="Passwort" autoFocus={!isSetup}
            onKeyDown={e=>e.key==='Enter'&&!busy&&submit()}/>
          {isSetup && (
            <PasswordInput value={pw2} onChange={e=>setPw2(e.target.value)}
              placeholder="Passwort bestätigen"
              onKeyDown={e=>e.key==='Enter'&&!busy&&submit()}/>
          )}
          {err && <div style={{fontSize:12.5,color:'#F87171',padding:'8px 12px',background:'rgba(248,113,113,0.1)',borderRadius:8,textAlign:'center'}}>{err}</div>}
          <button className="btn auth-btn" onClick={submit} disabled={busy||!pw}>
            {busy?<><span className="spinner" style={{borderTopColor:'#555',borderColor:'rgba(0,0,0,0.1)'}}></span> …</>:isSetup?'Konto erstellen →':'Anmelden →'}
          </button>
        </div>
        {!isSetup && (
          <div style={{textAlign:'center',marginTop:14,display:'flex',justifyContent:'center',gap:18,flexWrap:'wrap'}}>
            {onForgotPassword && SELF_HOSTED && (
              <button onClick={onForgotPassword} style={{background:'none',border:'none',color:'rgba(255,255,255,0.35)',fontSize:12.5,cursor:'pointer',padding:0,transition:'color .15s'}}
                onMouseEnter={e=>e.target.style.color='rgba(255,255,255,0.7)'}
                onMouseLeave={e=>e.target.style.color='rgba(255,255,255,0.35)'}>
                Passwort vergessen?
              </button>
            )}
            <button onClick={()=>{
              const hasVerify = !!localStorage.getItem('webars_verify_v1');
              const hasSalt   = !!localStorage.getItem('webars_salt_v1');
              const hasMk     = !!localStorage.getItem('webars_master_v1');
              let msg = `Diagnose:\nVERIFY_KEY: ${hasVerify}\nSALT_KEY: ${hasSalt}\nMASTER_KEY: ${hasMk}\n\n`;
              if (!hasSalt && hasVerify) {
                msg += '⚠️ SALT fehlt aber VERIFY vorhanden — Browser-Daten unvollständig.\nPasswörter können NICHT funktionieren ohne Salt.\n→ Nutze "Passwort vergessen?" um über den Server-Escrow wieder Zugang zu bekommen.';
              } else if (!hasSalt && !hasVerify && !hasMk) {
                msg += 'Keine lokalen Daten. Wähle "Einrichten" für ein neues Konto, oder stelle zuerst ein Backup wieder her.';
              } else if (hasSalt && hasVerify && hasMk) {
                msg += 'Alle Keys vorhanden — Passwort wird geprüft. Falls falsch: genau dieses Passwort wurde zum Einrichten verwendet.';
              } else {
                msg += 'Teilweise Daten vorhanden — ungewöhnlicher Zustand. "Passwort vergessen?" empfohlen.';
              }
              alert(msg);
            }} style={{background:'none',border:'none',color:'rgba(255,255,255,0.2)',fontSize:11.5,cursor:'pointer',padding:0}}>
              Diagnose
            </button>
          </div>
        )}
        {onSwitchMode && (
          <div style={{textAlign:'center',marginTop:14,fontSize:12.5,color:'rgba(255,255,255,0.3)'}}>
            {isSetup
              ? <><span>Schon ein Konto? </span><button onClick={onSwitchMode} style={{background:'none',border:'none',color:'rgba(255,255,255,0.7)',fontSize:12.5,cursor:'pointer',padding:0,fontWeight:600}}>Anmelden</button></>
              : <><span>Noch kein Konto? </span><button onClick={onSwitchMode} style={{background:'none',border:'none',color:'rgba(255,255,255,0.7)',fontSize:12.5,cursor:'pointer',padding:0,fontWeight:600}}>Einrichten</button></>
            }
          </div>
        )}
      </div>
    </div>
  );
}

// ── LOCK OVERLAY ─────────────────────────────────────────────────
function LockOverlay({onUnlock}) {
  const [pw,  setPw]  = useState('');
  const [err, setErr] = useState('');
  const [busy,setBusy]= useState(false);

  const submit = async () => {
    setBusy(true); setErr('');
    try {
      const key = await verifyPassword(pw);
      if (!key) { setErr('Falsches Passwort.'); setBusy(false); return; }
      let data;
      try { data = await loadEncrypted(key); }
      catch(loadErr) {
        if (loadErr && loadErr.message === 'KEY_MISMATCH') {
          setErr('Schlüssel passt nicht zu den Server-Daten. Bitte neu anmelden.');
          setBusy(false); return;
        }
        throw loadErr;
      }
      try { await storeKeyForDevice(key); } catch(e) {}
      onUnlock(key, data || DEFAULT_STATE);
    } catch(e) {
      setErr('Fehler beim Entsperren: ' + (e && e.message || ''));
      setBusy(false);
    }
  };

  return(
    <div style={{position:'fixed',inset:0,background:'rgba(10,9,7,0.95)',backdropFilter:'blur(20px)',zIndex:9999,display:'flex',alignItems:'center',justifyContent:'center',padding:20}}>
      <div style={{width:360,display:'grid',gap:20}}>
        <div style={{textAlign:'center'}}>
          <img src="/logo.png" alt="WebArs" style={{width:52,height:52,borderRadius:'50%',marginBottom:14,boxShadow:'0 8px 24px rgba(0,0,0,0.4)'}}/>
          <div style={{fontWeight:800,fontSize:20,color:'white'}}>WebArs CRM</div>
          <div style={{fontSize:13,color:'rgba(255,255,255,0.3)',marginTop:4}}>Gesperrt — Passwort eingeben</div>
        </div>
        <div className="auth-panel" style={{display:'grid',gap:14}}>
          <PasswordInput value={pw} onChange={e=>setPw(e.target.value)} placeholder="Passwort" autoFocus
            onKeyDown={e=>e.key==='Enter'&&!busy&&pw&&submit()}/>
          {err && <div style={{fontSize:12.5,color:'#F87171',textAlign:'center'}}>{err}</div>}
          <button className="btn auth-btn" onClick={submit} disabled={busy||!pw}>
            {busy?<><span className="spinner" style={{borderTopColor:'#555',borderColor:'rgba(0,0,0,0.1)'}}></span> …</>:'Entsperren →'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── FORGOT PASSWORD SCREEN ───────────────────────────────────────
function ForgotPasswordScreen({onBack}) {
  const [busy,setBusy]=useState(false);
  const [done,setDone]=useState(false);
  const [resetUrl,setResetUrl]=useState('');
  const [err,setErr]=useState('');

  const send=async()=>{
    setBusy(true);setErr('');
    try{
      const r=await fetch('/api/forgot-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({})});
      if(!r.ok){setErr('Server-Fehler. Bitte versuche es erneut.');setBusy(false);return;}
      const j=await r.json();
      // Reconstruct URL using actual hostname (server APP_URL may be wrong/localhost)
      if(j.resetUrl){
        try{
          const token=new URL(j.resetUrl).searchParams.get('reset')||j.resetUrl.split('reset=')[1];
          setResetUrl(window.location.origin+'/?reset='+token);
        }catch{setResetUrl(j.resetUrl);}
      } else if(j.token){
        setResetUrl(window.location.origin+'/?reset='+j.token);
      }
      setDone(true);
    }catch(e){setErr('Fehler: '+e.message);}
    setBusy(false);
  };

  return(
    <div className="auth-screen">
      <div className="auth-card">
        <div style={{textAlign:'center',marginBottom:28}}>
          <img src="/logo.png" alt="WebArs" style={{width:60,height:60,borderRadius:'50%',marginBottom:14,boxShadow:'0 8px 24px rgba(0,0,0,0.4)'}}/>
          <div style={{fontWeight:800,fontSize:22,color:'white',letterSpacing:'-0.02em'}}>WebArs CRM</div>
          <div style={{fontSize:13,color:'rgba(255,255,255,0.35)',marginTop:4}}>Passwort zurücksetzen</div>
        </div>
        <div className="auth-panel" style={{display:'grid',gap:14}}>
          {!done?(
            <>
              <div style={{fontSize:13.5,color:'rgba(255,255,255,0.55)',lineHeight:1.65,textAlign:'center'}}>
                Ein Zurücksetz-Link wird für dich generiert.<br/>
                <span style={{fontSize:12,color:'rgba(255,255,255,0.3)'}}>Falls SMTP konfiguriert ist, wird er per E-Mail gesendet. Sonst wird er hier angezeigt.</span>
              </div>
              {err&&<div style={{fontSize:12.5,color:'#F87171',padding:'8px 12px',background:'rgba(248,113,113,0.1)',borderRadius:8,textAlign:'center'}}>{err}</div>}
              <button className="btn auth-btn" onClick={send} disabled={busy}>
                {busy?<><span className="spinner" style={{borderTopColor:'#555',borderColor:'rgba(0,0,0,0.1)'}}></span> …</>:'Link anfordern →'}
              </button>
            </>
          ):(
            <>
              {resetUrl?(
                <>
                  <div style={{fontSize:13,color:'rgba(255,255,255,0.5)',lineHeight:1.6,textAlign:'center'}}>
                    Kein SMTP konfiguriert. Hier ist dein Zurücksetz-Link:
                  </div>
                  <div style={{background:'rgba(255,255,255,0.07)',border:'1px solid rgba(255,255,255,0.12)',borderRadius:10,padding:'12px 14px',wordBreak:'break-all',userSelect:'all'}}>
                    <a href={resetUrl} style={{color:'#60A5FA',fontSize:12.5,textDecoration:'none',lineHeight:1.5}}>{resetUrl}</a>
                  </div>
                  <button className="btn auth-btn" onClick={()=>window.location.href=resetUrl}>Jetzt zurücksetzen →</button>
                </>
              ):(
                <div style={{fontSize:14,color:'rgba(255,255,255,0.65)',lineHeight:1.7,textAlign:'center',padding:'8px 0'}}>
                  ✓ E-Mail wurde gesendet!<br/>
                  <span style={{fontSize:12.5,color:'rgba(255,255,255,0.35)'}}>Überprüfe dein Postfach und klicke den Link.</span>
                </div>
              )}
            </>
          )}
        </div>
        <div style={{textAlign:'center',marginTop:18}}>
          <button onClick={onBack} style={{background:'none',border:'none',color:'rgba(255,255,255,0.3)',fontSize:12.5,cursor:'pointer',padding:0,transition:'color .15s'}}
            onMouseEnter={e=>e.target.style.color='rgba(255,255,255,0.7)'}
            onMouseLeave={e=>e.target.style.color='rgba(255,255,255,0.3)'}>← Zurück zum Login</button>
        </div>
      </div>
    </div>
  );
}

// ── RESET PASSWORD SCREEN (via ?reset=TOKEN in URL) ──────────────
function ResetPasswordScreen({token}) {
  const [pw,setPw]=useState('');
  const [pw2,setPw2]=useState('');
  const [busy,setBusy]=useState(false);
  const [done,setDone]=useState(false);
  const [err,setErr]=useState('');

  const reset=async()=>{
    if(pw.length<8){setErr('Mindestens 8 Zeichen.');return;}
    if(pw!==pw2){setErr('Passwörter stimmen nicht überein.');return;}
    setBusy(true);setErr('');
    try{
      const r=await fetch(`/api/reset-token/${encodeURIComponent(token)}`);
      if(!r.ok){const j=await r.json();setErr(j.error||'Token ungültig oder abgelaufen.');setBusy(false);return;}
      const j=await r.json();

      // Decrypt the escrow blob with API_SECRET-derived key → master key (b64)
      const escrowKey = await deriveEscrowKey();
      const masterB64 = await aesDecrypt(escrowKey, j.escrow);
      const masterKey = await importMasterKeyFromB64(masterB64);

      if (j.scheme === 'auth-blob-v1') {
        // NEW model: re-wrap with new password using SERVER salt + iter, send back atomically
        const saltBytes = fromB64(j.salt);
        const iter = j.pbkdf2_iter || 600000;
        const wrapKey = await deriveKey(pw, saltBytes, iter);
        const wrapped_master = await aesEncrypt(wrapKey, masterB64);
        const cr = await fetch(`/api/reset-token/${encodeURIComponent(token)}/confirm`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ wrapped_master })
        });
        if (!cr.ok) { const cj = await cr.json().catch(()=>({})); throw new Error(cj.error || 'Confirm fehlgeschlagen'); }
        // Refresh local cache
        localStorage.setItem(SALT_KEY, j.salt);
        localStorage.setItem(VERIFY_KEY, JSON.stringify(await aesEncrypt(wrapKey, VERIFY_STR)));
        localStorage.setItem(MASTER_KEY_STORE, JSON.stringify(wrapped_master));
      } else {
        // LEGACY scheme: re-wrap locally and confirm (will trigger auto-migrate on next login)
        await rewrapMasterKey(masterKey, pw);
        await fetch(`/api/reset-token/${encodeURIComponent(token)}/confirm`, { method: 'POST' });
      }
      try{await storeKeyForDevice(masterKey);}catch(e){}
      window.history.replaceState({},'','/');
      setDone(true);
    }catch(e){setErr('Fehler: '+e.message);}
    setBusy(false);
  };

  return(
    <div className="auth-screen">
      <div className="auth-card">
        <div style={{textAlign:'center',marginBottom:28}}>
          <img src="/logo.png" alt="WebArs" style={{width:60,height:60,borderRadius:'50%',marginBottom:14,boxShadow:'0 8px 24px rgba(0,0,0,0.4)'}}/>
          <div style={{fontWeight:800,fontSize:22,color:'white',letterSpacing:'-0.02em'}}>WebArs CRM</div>
          <div style={{fontSize:13,color:'rgba(255,255,255,0.35)',marginTop:4}}>Neues Passwort festlegen</div>
        </div>
        <div className="auth-panel" style={{display:'grid',gap:14}}>
          {done?(
            <>
              <div style={{fontSize:14,color:'rgba(255,255,255,0.65)',textAlign:'center',lineHeight:1.7,padding:'8px 0'}}>
                ✓ Passwort erfolgreich geändert!<br/>
                <span style={{fontSize:12.5,color:'rgba(255,255,255,0.35)'}}>Du kannst dich jetzt einloggen.</span>
              </div>
              <button className="btn auth-btn" onClick={()=>window.location.href='/'}>Zum Login →</button>
            </>
          ):(
            <>
              <PasswordInput value={pw} onChange={e=>setPw(e.target.value)} placeholder="Neues Passwort (min. 8 Zeichen)" autoFocus onKeyDown={e=>e.key==='Enter'&&!busy&&reset()}/>
              <PasswordInput value={pw2} onChange={e=>setPw2(e.target.value)} placeholder="Passwort bestätigen" onKeyDown={e=>e.key==='Enter'&&!busy&&reset()}/>
              {err&&<div style={{fontSize:12.5,color:'#F87171',padding:'8px 12px',background:'rgba(248,113,113,0.1)',borderRadius:8,textAlign:'center'}}>{err}</div>}
              <button className="btn auth-btn" onClick={reset} disabled={busy||!pw||!pw2}>
                {busy?<><span className="spinner" style={{borderTopColor:'#555',borderColor:'rgba(0,0,0,0.1)'}}></span> …</>:'Passwort speichern →'}
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

// ── CHANGE PASSWORD MODAL (in-app) ───────────────────────────────
function ChangePasswordModal({cryptoKey,onClose}){
  const [curPw,setCurPw]=useState('');
  const [newPw,setNewPw]=useState('');
  const [newPw2,setNewPw2]=useState('');
  const [busy,setBusy]=useState(false);
  const [done,setDone]=useState(false);
  const [err,setErr]=useState('');
  // noServerAuth: crm_auth table empty → first-time setup, no old password needed
  const [noServerAuth,setNoServerAuth]=useState(null); // null=loading, true/false

  useEffect(()=>{
    if(!SELF_HOSTED){setNoServerAuth(false);return;}
    serverHasAuth().then(has=>setNoServerAuth(!has)).catch(()=>setNoServerAuth(false));
  },[]);

  const submit=async()=>{
    if(newPw.length<8){setErr('Neues Passwort: mindestens 8 Zeichen.');return;}
    if(newPw!==newPw2){setErr('Passwörter stimmen nicht überein.');return;}
    setBusy(true);setErr('');
    try{
      if(SELF_HOSTED && noServerAuth){
        // No crm_auth yet — initialize with current master key + new password.
        // SAFETY: verify cryptoKey actually decrypts current server data before
        // locking it in as the canonical master key. Otherwise we'd save a key
        // that can't decrypt the user's own data.
        try {
          const r = await fetch('/api/data', {headers:{Authorization:`Bearer ${window.WEBARS_API_TOKEN}`}});
          if (r.ok) {
            const j = await r.json();
            if (j && j.content) {
              try { await aesDecrypt(cryptoKey, j.content); }
              catch(decErr) {
                setErr('Dein aktueller Sitzungs-Schlüssel passt nicht zu den Server-Daten. Bitte ausloggen und mit dem korrekten Passwort neu anmelden, bevor du das Passwort am Server festlegst.');
                setBusy(false);
                return;
              }
            }
          }
        } catch(e) { /* fetch failure → proceed (offline-friendly) */ }
        const masterB64 = await exportMasterKeyB64(cryptoKey);
        await setupPasswordServer(newPw, masterB64);
        try{await storeKeyForDevice(cryptoKey);}catch(e){}
      } else {
        const verifiedKey=await verifyPassword(curPw);
        if(!verifiedKey){setErr('Aktuelles Passwort ist falsch.');setBusy(false);return;}
        if(SELF_HOSTED && window.WEBARS_API_TOKEN){
          await changePasswordServer(verifiedKey,newPw);
        } else {
          await rewrapMasterKey(verifiedKey,newPw);
        }
        try{await storeKeyForDevice(verifiedKey);}catch(e){}
      }
      setDone(true);
    }catch(e){setErr('Fehler: '+e.message);}
    setBusy(false);
  };

  const inputStyle={width:'100%',padding:'11px 14px',borderRadius:9,border:'1.5px solid rgba(0,0,0,0.12)',fontSize:14,fontFamily:'inherit',outline:'none',boxSizing:'border-box'};

  return(
    <div className="modal-overlay" onClick={e=>e.target===e.currentTarget&&onClose()}>
      <div className="modal-box" style={{width:400}}>
        <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:24}}>
          <div style={{fontWeight:700,fontSize:17}}>🔑 {noServerAuth?'Passwort festlegen':'Passwort ändern'}</div>
          <button className="btn btn-ghost btn-sm btn-icon" onClick={onClose}>✕</button>
        </div>
        {noServerAuth===null?(
          <div style={{textAlign:'center',padding:20,color:'#6B6560'}}>Prüfe Server…</div>
        ):done?(
          <>
            <div style={{textAlign:'center',padding:'20px 0',color:'#166534',background:'#F0FDF4',border:'1px solid #BBF7D0',borderRadius:12,marginBottom:18,fontSize:14,fontWeight:600}}>
              ✓ Passwort erfolgreich {noServerAuth?'festgelegt':'geändert'}
            </div>
            <button className="btn btn-primary" style={{width:'100%'}} onClick={onClose}>Schließen</button>
          </>
        ):(
          <>
            {noServerAuth&&(
              <div style={{fontSize:13,color:'#92400E',background:'#FFFBEB',border:'1px solid #FDE68A',borderRadius:8,padding:'10px 13px',marginBottom:16,lineHeight:1.5}}>
                Noch kein Passwort am Server eingerichtet. Lege jetzt dein Passwort fest — danach funktioniert die Anmeldung auf jedem Gerät.
              </div>
            )}
            <div style={{display:'grid',gap:12,marginBottom:16}}>
              {!noServerAuth&&(
                <div>
                  <div style={{fontSize:11.5,fontWeight:600,color:'#6B6560',marginBottom:5,textTransform:'uppercase',letterSpacing:'0.04em'}}>Aktuelles Passwort</div>
                  <input type="password" value={curPw} onChange={e=>setCurPw(e.target.value)} placeholder="••••••••" autoFocus style={inputStyle}/>
                </div>
              )}
              <div>
                <div style={{fontSize:11.5,fontWeight:600,color:'#6B6560',marginBottom:5,textTransform:'uppercase',letterSpacing:'0.04em'}}>Neues Passwort</div>
                <input type="password" value={newPw} onChange={e=>setNewPw(e.target.value)} placeholder="Mindestens 8 Zeichen" autoFocus={!!noServerAuth} style={inputStyle}/>
              </div>
              <div>
                <div style={{fontSize:11.5,fontWeight:600,color:'#6B6560',marginBottom:5,textTransform:'uppercase',letterSpacing:'0.04em'}}>Passwort bestätigen</div>
                <input type="password" value={newPw2} onChange={e=>setNewPw2(e.target.value)} placeholder="••••••••"
                  style={inputStyle} onKeyDown={e=>e.key==='Enter'&&!busy&&submit()}/>
              </div>
            </div>
            {err&&<div style={{fontSize:12.5,color:'#C0392B',background:'#FEF2F2',border:'1px solid #FECACA',borderRadius:8,padding:'9px 12px',marginBottom:14,textAlign:'center'}}>{err}</div>}
            <div style={{display:'flex',gap:10,justifyContent:'flex-end'}}>
              <button className="btn btn-ghost" onClick={onClose}>Abbrechen</button>
              <button className="btn btn-primary" onClick={submit} disabled={busy||(!noServerAuth&&!curPw)||!newPw||!newPw2}>
                {busy?<><span className="spinner"></span> …</>:noServerAuth?'Passwort festlegen':'Passwort ändern'}
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

// ── INVITE MANAGER MODAL ─────────────────────────────────────────
// ── GitHub Sync Setup Modal ─────────────────────────────────────
function GithubSyncModal({cryptoKey, currentSettings, onSaved, onClose, onCleared}) {
  const [token, setToken] = useState(currentSettings?.token || '');
  const [repo, setRepo]   = useState(currentSettings?.repo || 'Tatstast/crm-system');
  const [path, setPath]   = useState(currentSettings?.path || 'data/crm-data.json');
  const [busy, setBusy]   = useState(false);
  const [err, setErr]     = useState('');
  const [info, setInfo]   = useState('');
  const [step, setStep]   = useState('form'); // form | conflict
  const [conflictData, setConflictData] = useState(null);

  const isUpdate = !!currentSettings;

  const test = async () => {
    setErr(''); setInfo(''); setBusy(true);
    try {
      await ghValidateAccess(token.trim(), repo.trim());
      setInfo(SELF_HOSTED ? '✓ API Key gültig — Server erreichbar.' : '✓ Verbindung OK — Token und Repo gültig.');
    } catch(e) { setErr(e.message); }
    setBusy(false);
  };

  const save = async (forceOverwrite = false) => {
    setErr(''); setInfo(''); setBusy(true);
    try {
      await ghValidateAccess(token.trim(), repo.trim());
      const settings = SELF_HOSTED
        ? {token: token.trim(), selfhosted: true}
        : {token: token.trim(), repo: repo.trim(), path: path.trim()};
      // Check if remote file exists with data
      const fetched = await ghFetchFile(settings.token, settings.repo || '', settings.path || '');
      if (fetched.content) {
        try {
          const decrypted = await aesDecrypt(cryptoKey, fetched.content);
          await saveGithubSettings(cryptoKey, settings);
          _ghSha = fetched.sha;
          setInfo('✓ Verbunden — vorhandene Daten geladen.');
          onSaved && onSaved(decrypted);
          return;
        } catch(e) {
          if (forceOverwrite) {
            // User chose to overwrite — connect anyway, old blob will be replaced on next save/import
            await saveGithubSettings(cryptoKey, settings);
            _ghSha = String(fetched.sha || '');
            setInfo('✓ Verbunden — alte Server-Daten werden beim nächsten Speichern überschrieben.');
            onSaved && onSaved(null);
            return;
          }
          setErr('Daten auf dem Server können mit deinem Passwort nicht entschlüsselt werden. Falls die alten Server-Daten verloren sind und du sie überschreiben willst, klick unten "Trotzdem verbinden".');
          setStep('decryptFail');
          setBusy(false); return;
        }
      } else {
        await saveGithubSettings(cryptoKey, settings);
        onSaved && onSaved(null);
        return;
      }
    } catch(e) { setErr(e.message); }
    setBusy(false);
  };

  const disconnect = () => {
    if(!window.confirm('Cloud-Sync trennen? Lokale Daten bleiben erhalten.'))return;
    clearGithubSettings();
    onCleared && onCleared();
  };

  // ── Backup helpers ────────────────────────────────────────────
  const [backups, setBackups] = useState([]);
  const [backupBusy, setBackupBusy] = useState(false);
  const [backupErr, setBackupErr] = useState('');
  const [backupInfo, setBackupInfo] = useState('');
  const [migratePending, setMigratePending] = useState(null); // {encryptedData, exportSalt?, encryptedMasterKey?}
  const [migrateOldPw, setMigrateOldPw] = useState('');
  const [migrateOldData, setMigrateOldData] = useState('');
  const [migrateBusy, setMigrateBusy] = useState(false);
  // Migration export (old CRM → new CRM)
  const [showMigExport, setShowMigExport] = useState(false);
  const [migExportPw, setMigExportPw] = useState('');
  const [migExportBusy, setMigExportBusy] = useState(false);
  // Recovery: detect when current key doesn't match server data + try escrow / manual key
  const [showRecovery, setShowRecovery] = useState(false);
  const [recoveryBusy, setRecoveryBusy] = useState(false);
  const [recoveryStatus, setRecoveryStatus] = useState(null); // {currentKeyFp,escrowKeyFp,keysMatch,escrowMasterKey,backupStatus:[{id,name,decryptable:'current'|'escrow'|'manual'|'none'}],dataDecryptable}
  const [manualKeyB64, setManualKeyB64] = useState('');

  const keyFingerprint = async (k) => {
    try { const b64 = await exportMasterKeyB64(k); return b64.slice(0,12)+'…'+b64.slice(-4); }
    catch(e) { return '?'; }
  };

  const runRecoveryAnalysis = async () => {
    setRecoveryBusy(true); setBackupErr(''); setBackupInfo('');
    try {
      const s = currentSettings;
      if (!s || !s.token) throw new Error('Keine Server-Verbindung. Trage zuerst dein API_SECRET ein.');

      // Step 1: fingerprint current login key
      const currentFp = await keyFingerprint(cryptoKey);

      // Step 2: try to fetch & decrypt escrow
      let escrowMasterKey = null;
      let escrowFp = null;
      try {
        const r = await fetch('/api/key-escrow', {headers:{Authorization:`Bearer ${s.token}`}});
        if (r.ok) {
          const blob = await r.json();
          escrowMasterKey = await unescrowMasterKey(blob);
          escrowFp = await keyFingerprint(escrowMasterKey);
        }
      } catch(e) { console.warn('Escrow fetch/decrypt failed:', e.message); }

      // Step 3: check current /api/data
      let dataDecryptable = 'none';
      try {
        const r = await fetch('/api/data', {headers:{Authorization:`Bearer ${s.token}`}});
        if (r.ok) {
          const j = await r.json();
          if (j.content) {
            try { await aesDecrypt(cryptoKey, j.content); dataDecryptable = 'current'; }
            catch {
              if (escrowMasterKey) {
                try { await aesDecrypt(escrowMasterKey, j.content); dataDecryptable = 'escrow'; } catch {}
              }
            }
          } else { dataDecryptable = 'empty'; }
        }
      } catch(e) { console.warn('Data check failed:', e.message); }

      // Step 4: list backups & test each
      let backupList = [];
      try {
        const rl = await fetch('/api/backups', {headers:{Authorization:`Bearer ${s.token}`}});
        if (rl.ok) {
          const lj = await rl.json();
          backupList = lj.backups || [];
        }
      } catch(e) {}

      const backupStatus = [];
      for (const b of backupList) {
        try {
          const rb = await fetch(`/api/backups/${b.id}`, {headers:{Authorization:`Bearer ${s.token}`}});
          if (!rb.ok) { backupStatus.push({id:b.id,name:b.name,decryptable:'error'}); continue; }
          const bj = await rb.json();
          const content = bj.content;
          let dec = 'none';
          try { await aesDecrypt(cryptoKey, content); dec = 'current'; }
          catch {
            if (escrowMasterKey) {
              try { await aesDecrypt(escrowMasterKey, content); dec = 'escrow'; } catch {}
            }
          }
          backupStatus.push({id:b.id,name:b.name,decryptable:dec});
        } catch(e) { backupStatus.push({id:b.id,name:b.name,decryptable:'error'}); }
      }

      setRecoveryStatus({
        currentFp,
        escrowFp,
        keysMatch: escrowFp && currentFp === escrowFp,
        escrowMasterKey,
        backupStatus,
        dataDecryptable,
      });
    } catch(e) { setBackupErr('Recovery-Analyse fehlgeschlagen: ' + e.message); }
    setRecoveryBusy(false);
  };

  const restoreWithKey = async (backupId, useKey) => {
    setRecoveryBusy(true); setBackupErr(''); setBackupInfo('');
    try {
      const s = currentSettings;
      const r = await fetch(`/api/backups/${backupId}`, {headers:{Authorization:`Bearer ${s.token}`}});
      if (!r.ok) throw new Error('Backup nicht ladbar (' + r.status + ')');
      const j = await r.json();
      const decrypted = await aesDecrypt(useKey, j.content);
      const reEncrypted = await aesEncrypt(cryptoKey, decrypted);
      const ri = await fetch('/api/import', {
        method:'POST',
        headers:{Authorization:`Bearer ${s.token}`,'Content-Type':'application/json'},
        body: JSON.stringify({encryptedData: reEncrypted}),
      });
      if (!ri.ok) { const e = await ri.json().catch(()=>({})); throw new Error('Import: ' + (e.error||ri.status)); }
      const ij = await ri.json();
      _ghSha = String(ij.version);
      localStorage.setItem(GH_SHA_KEY, _ghSha);
      setBackupInfo('✓ Backup wiederhergestellt — bitte Seite neu laden, um die Daten zu sehen.');
    } catch(e) { setBackupErr('Restore fehlgeschlagen: ' + e.message); }
    setRecoveryBusy(false);
  };

  // Smart key parser: accepts
  //   (1) raw 44-char base64 master key
  //   (2) JSON {master_raw, master_wrapped, salt}  → from F12 console
  //   (3) JSON {s, m}                                → legacy migration-extract
  // If only wrapped key + salt are present, asks for old password.
  const [manualOldPw, setManualOldPw] = useState('');
  const [manualNeedsPw, setManualNeedsPw] = useState(false);
  const [manualParsed, setManualParsed] = useState(null); // {salt, wrapped} when needsPw

  const tryManualKey = async () => {
    setRecoveryBusy(true); setBackupErr(''); setManualNeedsPw(false); setManualParsed(null);
    try {
      const raw = manualKeyB64.trim();
      let masterKey = null;

      // Try JSON first
      let parsed = null;
      try { parsed = JSON.parse(raw); } catch {}

      if (parsed && typeof parsed === 'object') {
        // Variant: master_raw is the unwrapped base64 master key
        if (parsed.master_raw && typeof parsed.master_raw === 'string') {
          masterKey = await importMasterKeyFromB64(parsed.master_raw);
        }
        // Variant: master_wrapped + salt — need old password
        else if ((parsed.master_wrapped || parsed.m) && (parsed.salt || parsed.s)) {
          const wrapped = parsed.master_wrapped || parsed.m;
          const salt    = parsed.salt           || parsed.s;
          setManualParsed({wrapped: typeof wrapped === 'string' ? JSON.parse(wrapped) : wrapped, salt});
          setManualNeedsPw(true);
          setBackupErr('');
          setBackupInfo('Salt + wrapped Key erkannt — bitte altes Passwort eingeben (siehe Feld unten).');
          setRecoveryBusy(false);
          return;
        }
      }

      if (!masterKey) {
        // Treat as raw base64 master key (44 chars typical)
        masterKey = await importMasterKeyFromB64(raw);
      }

      await testKeyAgainstBackups(masterKey, 'manual');
      setBackupInfo('Manueller Schlüssel akzeptiert und gegen alle Backups getestet.');
    } catch(e) { setBackupErr('Schlüssel ungültig: ' + e.message); }
    setRecoveryBusy(false);
  };

  const tryManualWithPassword = async () => {
    setRecoveryBusy(true); setBackupErr('');
    try {
      if (!manualParsed) throw new Error('Keine Daten zum Entpacken.');
      const saltBytes = fromB64(manualParsed.salt);
      const wrapKey = await deriveKey(manualOldPw, saltBytes);
      let masterB64;
      try { masterB64 = await aesDecrypt(wrapKey, manualParsed.wrapped); }
      catch { throw new Error('Altes Passwort falsch (oder Daten passen nicht zum Salt).'); }
      const masterKey = await importMasterKeyFromB64(masterB64);
      await testKeyAgainstBackups(masterKey, 'manual');
      setBackupInfo('✓ Alter Schlüssel rekonstruiert und gegen Backups getestet.');
      setManualNeedsPw(false);
    } catch(e) { setBackupErr(e.message); }
    setRecoveryBusy(false);
  };

  const testKeyAgainstBackups = async (key, label) => {
    const updated = [...(recoveryStatus?.backupStatus || [])];
    const s = currentSettings;
    for (let i = 0; i < updated.length; i++) {
      const rb = await fetch(`/api/backups/${updated[i].id}`, {headers:{Authorization:`Bearer ${s.token}`}});
      if (!rb.ok) continue;
      const bj = await rb.json();
      try { await aesDecrypt(key, bj.content); updated[i] = {...updated[i], decryptable: label}; } catch {}
    }
    // Also check current /api/data
    let dataDecryptable = recoveryStatus?.dataDecryptable;
    try {
      const r = await fetch('/api/data', {headers:{Authorization:`Bearer ${s.token}`}});
      if (r.ok) {
        const j = await r.json();
        if (j.content) { try { await aesDecrypt(key, j.content); dataDecryptable = label; } catch {} }
      }
    } catch {}
    setRecoveryStatus(prev => ({...prev, manualMasterKey:key, backupStatus:updated, dataDecryptable}));
  };

  const doMigrationExport = async () => {
    setBackupErr(''); setMigExportBusy(true);
    try {
      const key = await verifyPassword(migExportPw);
      if(!key){ setBackupErr('Falsches Passwort.'); setMigExportBusy(false); return; }
      const masterKeyB64 = await exportMasterKeyB64(key);
      const exportSalt = crypto.getRandomValues(new Uint8Array(16));
      const exportWrapKey = await deriveKey(migExportPw, exportSalt);
      const encryptedMasterKey = await aesEncrypt(exportWrapKey, masterKeyB64);
      // Get raw encrypted data blob
      let encryptedData = null;
      if(SELF_HOSTED && currentSettings && currentSettings.token){
        try{
          const r = await fetch('/api/data',{headers:{Authorization:`Bearer ${currentSettings.token}`}});
          if(r.ok){ const j=await r.json(); if(j.content) encryptedData=j.content; }
        }catch(e){}
      }
      if(!encryptedData && _ghSettings){
        try{
          const fetched = await ghFetchFile(_ghSettings.token, _ghSettings.repo, _ghSettings.path);
          encryptedData = fetched.content;
        }catch(e){}
      }
      if(!encryptedData){
        const raw = localStorage.getItem(DATA_KEY);
        if(raw) encryptedData = JSON.parse(raw);
      }
      if(!encryptedData) throw new Error('Keine Daten gefunden. Bitte zuerst Daten speichern.');
      const payload = {
        version:2, migrationExport:true, savedAt:new Date().toISOString(),
        exportSalt:toB64(exportSalt), encryptedMasterKey, encryptedData
      };
      const blob = new Blob([JSON.stringify(payload,null,2)],{type:'application/json'});
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href=url; a.download=`webars-crm-migration-${new Date().toISOString().slice(0,10)}.json`; a.click();
      URL.revokeObjectURL(url);
      setShowMigExport(false); setMigExportPw('');
      setBackupInfo('✓ Migration-Export heruntergeladen.');
    }catch(e){ setBackupErr(e.message); }
    setMigExportBusy(false);
  };

  const doMigrateImport = async () => {
    setBackupErr(''); setMigrateBusy(true);
    try {
      const isV2 = !!(migratePending.exportSalt && migratePending.encryptedMasterKey);
      const isV3 = !!(migratePending.localSalt && migratePending.localMasterEncKey);
      let oldMasterKey;
      if(isV2){
        // V2: derive key directly from password + exportSalt embedded in file
        const exportSalt = fromB64(migratePending.exportSalt);
        const exportWrapKey = await deriveKey(migrateOldPw, exportSalt);
        let oldMasterKeyB64;
        try { oldMasterKeyB64 = await aesDecrypt(exportWrapKey, migratePending.encryptedMasterKey); }
        catch(e){ throw new Error('Altes Passwort falsch.'); }
        oldMasterKey = await importMasterKeyFromB64(oldMasterKeyB64);
      } else if(isV3){
        // V3: salt + wrapped master key still in localStorage — just need old password
        const oldWrapKey = await deriveKey(migrateOldPw, fromB64(migratePending.localSalt));
        let oldMasterKeyB64;
        try { oldMasterKeyB64 = await aesDecrypt(oldWrapKey, migratePending.localMasterEncKey); }
        catch(e){ throw new Error('Altes Passwort falsch.'); }
        oldMasterKey = await importMasterKeyFromB64(oldMasterKeyB64);
      } else {
        // V1 fallback: user provides localStorage data manually
        let parsed;
        try { parsed = JSON.parse(migrateOldData.trim()); } catch(e) { throw new Error('Ungültiges JSON — bitte exakt so einfügen wie aus der Konsole.'); }
        const { s, m } = parsed;
        if(!s || !m) throw new Error('Fehlende Felder: "s" (salt) oder "m" (master key) nicht gefunden.');
        const oldWrapKey = await deriveKey(migrateOldPw, fromB64(s));
        let oldMasterKeyB64;
        try { oldMasterKeyB64 = await aesDecrypt(oldWrapKey, JSON.parse(m)); }
        catch(e){ throw new Error('Altes Passwort falsch oder Daten ungültig.'); }
        oldMasterKey = await importMasterKeyFromB64(oldMasterKeyB64);
      }
      let data;
      try { data = await aesDecrypt(oldMasterKey, migratePending.encryptedData); }
      catch(e){ throw new Error('Entschlüsselung fehlgeschlagen — stimmt das Passwort?'); }
      const newEncryptedData = await aesEncrypt(cryptoKey, data);
      const r = await fetch('/api/import', {
        method:'POST',
        headers:{Authorization:`Bearer ${currentSettings.token}`,'Content-Type':'application/json'},
        body: JSON.stringify({encryptedData: newEncryptedData})
      });
      if(!r.ok){ const e=await r.json().catch(()=>({})); throw new Error(`Import fehlgeschlagen: ${e.error||r.status}`); }
      const j = await r.json();
      _ghSha = String(j.version);
      localStorage.setItem(GH_SHA_KEY, _ghSha);
      setMigratePending(null); setMigrateOldPw(''); setMigrateOldData('');
      setBackupInfo('✓ Import erfolgreich — bitte Seite neu laden.');
    } catch(e){ setBackupErr(e.message); }
    setMigrateBusy(false);
  };

  const downloadCurrentBackup = async () => {
    setBackupErr(''); setBackupInfo(''); setBackupBusy(true);
    try {
      const s = currentSettings;
      if (!s) throw new Error('Erst Verbindung herstellen.');
      const fetched = await ghFetchFile(s.token, s.repo || '', s.path || '');
      if (!fetched.content) throw new Error('Noch keine Daten in der Cloud.');
      const payload = {
        version: 1,
        savedAt: new Date().toISOString(),
        selfhosted: SELF_HOSTED,
        encryptedData: fetched.content,
      };
      const blob = new Blob([JSON.stringify(payload, null, 2)], {type:'application/json'});
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `webars-crm-backup-${new Date().toISOString().slice(0,10)}.json`;
      a.click();
      URL.revokeObjectURL(url);
      setBackupInfo('✓ Backup heruntergeladen.');
    } catch(e) { setBackupErr(e.message); }
    setBackupBusy(false);
  };

  const loadServerBackups = async () => {
    setBackupErr(''); setBackupBusy(true);
    try {
      const s = currentSettings;
      if (!s) throw new Error('Erst Verbindung herstellen.');
      if (SELF_HOSTED) {
        const r = await fetch('/api/backups', {headers:{Authorization:`Bearer ${s.token}`}});
        if (!r.ok) throw new Error(`Konnte Backups nicht laden (${r.status})`);
        const j = await r.json();
        if (!j.backups || j.backups.length === 0) {
          setBackups([]);
          setBackupErr('Noch keine automatischen Backups — werden täglich um 02:00 UTC erstellt.');
        } else {
          setBackups(j.backups.map(b => ({...b, sha: String(b.id)})));
        }
        setBackupBusy(false); return;
      }
      // GitHub mode
      const dir = (s.path || 'data/crm-data.json').split('/').slice(0,-1).join('/') + '/backups';
      const r = await fetch(`https://api.github.com/repos/${s.repo}/contents/${dir}`, {
        headers:{Authorization:`Bearer ${s.token}`, Accept:'application/vnd.github+json'}
      });
      if (r.status === 404) { setBackups([]); setBackupErr('Noch keine täglichen Backups vorhanden — werden ab dem ersten Tag (UTC 02:00) automatisch erstellt.'); setBackupBusy(false); return; }
      if (!r.ok) throw new Error(`Konnte Backups nicht laden (${r.status})`);
      const items = await r.json();
      const sorted = items.filter(i=>i.type==='file' && i.name.endsWith('.json')).sort((a,b)=>b.name.localeCompare(a.name));
      setBackups(sorted);
    } catch(e) { setBackupErr(e.message); }
    setBackupBusy(false);
  };

  const restoreFromBackup = async (backup) => {
    const label = backup.name ? backup.name.replace(/.*(\d{4}-\d{2}-\d{2}).*/,'$1') : String(backup.id);
    if (!window.confirm(`Wirklich auf Backup vom ${label} zurücksetzen?\n\nDie aktuelle Datei wird überschrieben. (Backup bleibt erhalten.)`)) return;
    setBackupErr(''); setBackupInfo(''); setBackupBusy(true);
    try {
      const s = currentSettings;
      let content;
      if (SELF_HOSTED) {
        const r = await fetch(`/api/backups/${backup.id}`, {headers:{Authorization:`Bearer ${s.token}`}});
        if (!r.ok) throw new Error(`Backup konnte nicht gelesen werden (${r.status})`);
        const j = await r.json();
        content = j.content;
      } else {
        const r = await fetch(`https://api.github.com/repos/${s.repo}/contents/${backup.path}`, {
          headers:{Authorization:`Bearer ${s.token}`, Accept:'application/vnd.github+json'}
        });
        if (!r.ok) throw new Error(`Backup konnte nicht gelesen werden (${r.status})`);
        const j = await r.json();
        content = JSON.parse(b64decode(j.content));
      }
      // Sanity-check: must be decryptable with current key
      let canDecrypt = false;
      try { await aesDecrypt(cryptoKey, content); canDecrypt = true; } catch(e){}
      if (!canDecrypt) {
        // Key mismatch — ask for old password instead of hard-failing.
        // Auto-read local salt+masterKey if still in localStorage (password-only flow).
        // Read existing salt directly — do NOT call getSalt() which auto-generates
        // a new random salt when missing, making every password attempt fail.
        const localSaltB64 = localStorage.getItem(SALT_KEY);
        const localMasterEncRaw = localStorage.getItem(MASTER_KEY_STORE);
        if (localSaltB64 && localMasterEncRaw) {
          // Salt is already b64 as stored — pass directly
          setMigratePending({encryptedData: content, localSalt: localSaltB64, localMasterEncKey: JSON.parse(localMasterEncRaw), fromServerBackup: true});
        } else {
          // localStorage cleared — fall back to manual console-extract flow
          setMigratePending({encryptedData: content, fromServerBackup: true});
        }
        setBackupBusy(false);
        return;
      }
      if (SELF_HOSTED) {
        // Use server-side restore endpoint: atomically snapshots current data
        // (as tier='pre-restore' backup, kept forever) before overwriting crm_data.
        const r = await fetch(`/api/backups/${backup.id}/restore`, {
          method:'POST',
          headers:{Authorization:`Bearer ${s.token}`,'Content-Type':'application/json'}
        });
        if (!r.ok){ const e=await r.json().catch(()=>({})); throw new Error(`Restore fehlgeschlagen: ${e.error||r.status}`); }
        const j = await r.json();
        _ghSha = String(j.version);
        localStorage.setItem(GH_SHA_KEY, _ghSha);
      } else {
        const fetched = await ghFetchFile(s.token, s.repo||'', s.path||'');
        const newSha = await ghPushFile(s.token, s.repo||'', s.path||'', content, fetched.sha, `Restore from backup ${backup.name||backup.id}`);
        _ghSha = newSha;
      }
      setBackupInfo('✓ Wiederhergestellt (Vorzustand als Pre-Restore-Snapshot gesichert) — bitte Seite neu laden.');
    } catch(e) { setBackupErr(e.message); }
    setBackupBusy(false);
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-box" onClick={e=>e.stopPropagation()} style={{width:520}}>
        <div style={{display:'flex',justifyContent:'space-between',alignItems:'flex-start',marginBottom:18}}>
          <div>
            <h2 style={{fontSize:17,fontWeight:700}}>{SELF_HOSTED ? '🖥 Server-Sync' : '☁ Cloud-Sync (GitHub)'}</h2>
            <p style={{fontSize:12.5,color:'#A8A39D',marginTop:3,lineHeight:1.5}}>
              {SELF_HOSTED
                ? 'Daten verschlüsselt auf dem eigenen Server (Coolify) speichern — kein GitHub benötigt.'
                : 'Daten verschlüsselt in einem GitHub-Repo speichern, damit Team-Mitglieder Zugriff haben.'}
            </p>
          </div>
          <button onClick={onClose} style={{background:'#F5F3F0',border:'none',borderRadius:8,padding:8,color:'#999',lineHeight:0}}><Icons.Close/></button>
        </div>

        {SELF_HOSTED ? (
          <div style={{background:'#EFF6FF',border:'1px solid #BFDBFE',borderRadius:10,padding:'10px 14px',marginBottom:18,fontSize:12.5,color:'#1e40af',lineHeight:1.55}}>
            <strong>Self-Hosted Modus:</strong> Das CRM läuft auf deinem eigenen Server. Trage den <strong>API_SECRET</strong> aus deiner Coolify-Konfiguration ein — kein GitHub-Token nötig.
          </div>
        ) : (
          <div style={{background:'#FFF7ED',border:'1px solid #FED7AA',borderRadius:10,padding:'10px 14px',marginBottom:18,fontSize:12.5,color:'#9A3412',lineHeight:1.55}}>
            <strong>Wichtig:</strong> Alle Team-Mitglieder brauchen <strong>denselben Token, dasselbe Repo</strong> und das <strong>gleiche Passwort</strong> wie du, um die Daten zu entschlüsseln. Teile diese drei Dinge sicher (z.B. via Passwort-Manager).
          </div>
        )}

        <div style={{marginBottom:SELF_HOSTED?18:14}}>
          <div style={{fontSize:11,fontWeight:600,color:'#6B6560',marginBottom:6,textTransform:'uppercase',letterSpacing:'0.05em'}}>{SELF_HOSTED ? 'API Secret (aus Coolify-Einstellungen)' : 'GitHub Personal Access Token'}</div>
          <input value={token} onChange={e=>setToken(e.target.value)} type="password" placeholder={SELF_HOSTED ? 'API_SECRET…' : 'github_pat_…'} style={{fontFamily:'monospace',fontSize:12.5}}/>
          {!SELF_HOSTED && <div style={{fontSize:11.5,color:'#A8A39D',marginTop:4,lineHeight:1.5}}>
            Erstellen unter <a href="https://github.com/settings/personal-access-tokens/new" target="_blank" rel="noopener" style={{color:'#3F3A35',fontWeight:600}}>github.com/settings/personal-access-tokens</a> · Berechtigungen: <em>Contents: Read and write</em>
          </div>}
        </div>
        {!SELF_HOSTED && <div style={{marginBottom:14}}>
          <div style={{fontSize:11,fontWeight:600,color:'#6B6560',marginBottom:6,textTransform:'uppercase',letterSpacing:'0.05em'}}>Repository (user/repo)</div>
          <input value={repo} onChange={e=>setRepo(e.target.value)} placeholder="Tatstast/crm-system" style={{fontFamily:'monospace'}}/>
        </div>}
        {!SELF_HOSTED && <div style={{marginBottom:18}}>
          <div style={{fontSize:11,fontWeight:600,color:'#6B6560',marginBottom:6,textTransform:'uppercase',letterSpacing:'0.05em'}}>Datei-Pfad im Repo</div>
          <input value={path} onChange={e=>setPath(e.target.value)} placeholder="data/crm-data.json" style={{fontFamily:'monospace'}}/>
        </div>}

        {info && <div style={{fontSize:12.5,color:'#16a34a',padding:'8px 12px',background:'#F0FDF4',borderRadius:8,marginBottom:12,border:'1px solid #BBF7D0'}}>{info}</div>}
        {err && <div style={{fontSize:12.5,color:'#C0392B',padding:'8px 12px',background:'#FEF2F2',borderRadius:8,marginBottom:12,border:'1px solid #FECACA'}}>{err}</div>}

        <div style={{display:'flex',gap:8,justifyContent:'space-between'}}>
          {isUpdate ? (
            <button className="btn btn-danger btn-sm" onClick={disconnect} disabled={busy}>Sync trennen</button>
          ) : <div></div>}
          <div style={{display:'flex',gap:8}}>
            <button className="btn btn-ghost" onClick={test} disabled={busy||!token||(SELF_HOSTED?false:!repo)}>Verbindung testen</button>
            {step==='decryptFail' ? (
              <button className="btn btn-primary" onClick={()=>{setStep('form');save(true);}} disabled={busy} style={{background:'#DC2626'}}>
                {busy?'…':'⚠ Trotzdem verbinden (überschreiben)'}
              </button>
            ) : (
              <button className="btn btn-primary" onClick={()=>save(false)} disabled={busy||!token||(SELF_HOSTED?false:!repo||!path)}>
                {busy?'…':isUpdate?'Speichern':'Verbinden'}
              </button>
            )}
          </div>
        </div>

        {isUpdate && (
          <div style={{marginTop:14,paddingTop:14,borderTop:'1px solid #F0EDE8',fontSize:11.5,color:'#A8A39D'}}>
            Sync-Status: <span style={{fontWeight:600,color:getSyncState().state==='ok'?'#16a34a':getSyncState().state==='error'?'#C0392B':'#6B6560'}}>{getSyncState().state==='ok'?'OK · live':getSyncState().state==='error'?`Fehler: ${getSyncState().message||'unbekannt'}`:'wartet'}</span>
            {getSyncState().at && <span> · zuletzt {new Date(getSyncState().at).toLocaleTimeString('de-DE',{hour:'2-digit',minute:'2-digit'})}</span>}
          </div>
        )}

        {isUpdate && (
          <div style={{marginTop:18,paddingTop:18,borderTop:'1px solid #F0EDE8'}}>
            <div style={{fontSize:13,fontWeight:700,color:'#141210',marginBottom:6}}>🤖 Jarvis API</div>
            {SELF_HOSTED ? (
              <div style={{fontSize:12,color:'#3F3A35',lineHeight:1.6}}>
                <div style={{marginBottom:4}}>Im Self-Hosted Modus liest Jarvis die CRM-Zusammenfassung direkt vom Server.</div>
                <div style={{display:'flex',gap:6,alignItems:'center'}}>
                  <code style={{background:'#FAFAF8',padding:'4px 8px',borderRadius:6,fontSize:11,border:'1px solid #E8E4DF',flex:1,wordBreak:'break-all'}}>{window.location.origin}/api/summary</code>
                  <button className="btn btn-ghost btn-sm" onClick={()=>navigator.clipboard?.writeText(window.location.origin+'/api/summary')} style={{flexShrink:0,fontSize:11}}>Kopieren</button>
                </div>
                <div style={{fontSize:11,color:'#A8A39D',marginTop:4}}>→ In <code>jarvis_crm_tools.js</code>: <code>SELF_HOSTED_URL</code> auf diese Basis-URL setzen</div>
              </div>
            ) : (()=>{
              const gid = getJarvisGistId();
              return gid ? (
                <div style={{fontSize:12,color:'#3F3A35',lineHeight:1.6}}>
                  <div style={{marginBottom:4}}>Privater Gist wird automatisch bei jedem Speichern aktualisiert.</div>
                  <div style={{display:'flex',gap:6,alignItems:'center'}}>
                    <code style={{background:'#FAFAF8',padding:'4px 8px',borderRadius:6,fontSize:11,border:'1px solid #E8E4DF',flex:1,wordBreak:'break-all'}}>{gid}</code>
                    <button className="btn btn-ghost btn-sm" onClick={()=>navigator.clipboard?.writeText(gid)} style={{flexShrink:0,fontSize:11}}>Kopieren</button>
                  </div>
                  <div style={{fontSize:11,color:'#A8A39D',marginTop:4}}>→ Als <code>JARVIS_GIST_ID</code> in Jarvis-Konfiguration eintragen</div>
                </div>
              ) : (
                <div style={{fontSize:12,color:'#A8A39D',lineHeight:1.5}}>Gist wird beim nächsten Speichern automatisch erstellt und erscheint dann hier.</div>
              );
            })()}
          </div>
        )}

        {isUpdate && (
          <div style={{marginTop:18,paddingTop:18,borderTop:'1px solid #F0EDE8'}}>
            <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',marginBottom:10}}>
              <div>
                <div style={{fontSize:13,fontWeight:700,color:'#141210'}}>🛡 Backups</div>
                <div style={{fontSize:11.5,color:'#A8A39D',marginTop:2,lineHeight:1.5}}>
                  {SELF_HOSTED
                    ? 'Täglich um 02:00 UTC automatisch erstellt (PostgreSQL). Letzte 30 Snapshots werden behalten.'
                    : <>Tägliche Snapshots werden automatisch in <code style={{background:'#FAFAF8',padding:'1px 5px',borderRadius:4,fontSize:11}}>data/backups/</code> erstellt. Letzte 30 Tage werden behalten.</>}
                </div>
              </div>
            </div>
            <div style={{display:'flex',gap:8,marginBottom:10,flexWrap:'wrap'}}>
              <button className="btn btn-ghost btn-sm" onClick={downloadCurrentBackup} disabled={backupBusy}>↓ Backup jetzt herunterladen</button>
              <button className="btn btn-ghost btn-sm" onClick={loadServerBackups} disabled={backupBusy}>{backupBusy?'…':'Verlauf anzeigen'}</button>
              {SELF_HOSTED&&<button className="btn btn-ghost btn-sm" onClick={async()=>{setBackupBusy(true);setBackupErr('');setBackupInfo('');try{const r=await fetch('/api/backups/email',{method:'POST',headers:{Authorization:`Bearer ${window.WEBARS_API_TOKEN}`}});const j=await r.json();if(!r.ok)throw new Error(j.error||r.status);setBackupInfo(j.emailSent?'✓ Backup-E-Mail wurde gesendet.':'⚠ SMTP nicht konfiguriert — E-Mail konnte nicht gesendet werden.');}catch(e){setBackupErr('Fehler: '+e.message);}setBackupBusy(false);}} disabled={backupBusy}>📧 Backup per E-Mail senden</button>}
              <button className="btn btn-ghost btn-sm" onClick={()=>{setShowMigExport(v=>!v);setMigExportPw('');setBackupErr('');}} disabled={backupBusy}>📦 Migration-Export</button>
              <button className="btn btn-sm" style={{background:'#FEF3C7',color:'#92400E',border:'1.5px solid #FCD34D'}} onClick={()=>{setShowRecovery(v=>!v);}} disabled={backupBusy}>🔧 Schlüssel-Recovery</button>
              {SELF_HOSTED && (
                <label className="btn btn-ghost btn-sm" style={{cursor:'pointer'}}>
                  ↑ Backup-Datei importieren
                  <input type="file" accept=".json,application/json" style={{display:'none'}} onChange={async (ev)=>{
                    const file = ev.target.files && ev.target.files[0];
                    if(!file) return;
                    setBackupErr(''); setBackupInfo(''); setBackupBusy(true);
                    try {
                      const text = await file.text();
                      let parsed;
                      try { parsed = JSON.parse(text); } catch(e){ throw new Error('Ungültiges JSON-Format.'); }
                      // V2 migration export (has embedded key info)
                      if(parsed.migrationExport && parsed.exportSalt && parsed.encryptedMasterKey && parsed.encryptedData){
                        setMigratePending({
                          encryptedData: parsed.encryptedData,
                          exportSalt: parsed.exportSalt,
                          encryptedMasterKey: parsed.encryptedMasterKey
                        });
                        setBackupErr(''); setBackupBusy(false); ev.target.value=''; return;
                      }
                      const encryptedData = parsed.encryptedData || parsed; // accept raw or wrapped
                      if(!encryptedData || typeof encryptedData !== 'object') throw new Error('Datei enthält kein "encryptedData" Feld.');
                      // Sanity check: try to decrypt with current key
                      let canDecrypt = false;
                      try { await aesDecrypt(cryptoKey, encryptedData); canDecrypt = true; } catch(e){}
                      if(!canDecrypt){
                        // Key mismatch — trigger v1 migration flow
                        setMigratePending({encryptedData});
                        setBackupErr('');
                        setBackupBusy(false);
                        ev.target.value = '';
                        return;
                      }
                      // Push directly to /api/import
                      const r = await fetch('/api/import', {
                        method: 'POST',
                        headers: {Authorization:`Bearer ${currentSettings.token}`,'Content-Type':'application/json'},
                        body: JSON.stringify({encryptedData})
                      });
                      if(!r.ok){ const e=await r.json().catch(()=>({})); throw new Error(`Import fehlgeschlagen: ${e.error||r.status}`); }
                      const j = await r.json();
                      _ghSha = String(j.version);
                      localStorage.setItem(GH_SHA_KEY, _ghSha);
                      setBackupInfo('✓ Import erfolgreich — bitte Seite neu laden.');
                    } catch(e){ setBackupErr(e.message); }
                    setBackupBusy(false);
                    ev.target.value = '';
                  }} disabled={backupBusy}/>
                </label>
              )}
            </div>
            {showMigExport && (
              <div style={{background:'#F0F9FF',border:'1px solid #BAE6FD',borderRadius:10,padding:14,marginBottom:10}}>
                <div style={{fontWeight:700,fontSize:13,color:'#0C4A6E',marginBottom:6}}>📦 Migration-Export erstellen</div>
                <div style={{fontSize:12,color:'#075985',marginBottom:10,lineHeight:1.6}}>
                  Erstellt eine Backup-Datei mit eingebettetem Schlüssel. Im neuen Self-Hosted CRM kannst du diese Datei importieren — du brauchst nur dein altes Passwort.
                </div>
                <input type="password" placeholder="Dein aktuelles Passwort" value={migExportPw} onChange={e=>setMigExportPw(e.target.value)}
                  style={{width:'100%',fontSize:13,padding:'8px 10px',borderRadius:7,border:'1px solid #BAE6FD',background:'#F8FBFF',marginBottom:10,boxSizing:'border-box'}}
                  autoFocus onKeyDown={e=>e.key==='Enter'&&doMigrationExport()}
                />
                <div style={{display:'flex',gap:8}}>
                  <button className="btn btn-primary btn-sm" onClick={doMigrationExport} disabled={migExportBusy||!migExportPw}>
                    {migExportBusy?'Erstelle…':'↓ Export herunterladen'}
                  </button>
                  <button className="btn btn-ghost btn-sm" onClick={()=>{setShowMigExport(false);setMigExportPw('');setBackupErr('');}}>Abbrechen</button>
                </div>
              </div>
            )}
            {backupInfo && <div style={{fontSize:12,color:'#16a34a',padding:'7px 11px',background:'#F0FDF4',borderRadius:7,marginBottom:8,border:'1px solid #BBF7D0'}}>{backupInfo}</div>}
            {backupErr && <div style={{fontSize:12,color:'#9A3412',padding:'7px 11px',background:'#FFF7ED',borderRadius:7,marginBottom:8,border:'1px solid #FED7AA'}}>{backupErr}</div>}
            {showRecovery && (
              <div style={{background:'#FFFBEB',border:'1px solid #FCD34D',borderRadius:10,padding:14,marginBottom:10}}>
                <div style={{fontWeight:700,fontSize:13,color:'#92400E',marginBottom:6}}>🔧 Schlüssel-Recovery (Daten-Wiederherstellung)</div>
                <div style={{fontSize:12,color:'#78350F',marginBottom:10,lineHeight:1.6}}>
                  Prüft welche Schlüssel deine Daten entschlüsseln können — aktueller Login, Server-Escrow, oder ein manuell eingegebener Master Key.
                </div>
                <div style={{display:'flex',gap:8,marginBottom:10,flexWrap:'wrap'}}>
                  <button className="btn btn-primary btn-sm" onClick={runRecoveryAnalysis} disabled={recoveryBusy}>
                    {recoveryBusy ? 'Analysiere…' : '🔍 Schlüssel-Status prüfen'}
                  </button>
                  <button className="btn btn-ghost btn-sm" onClick={()=>{setShowRecovery(false);setRecoveryStatus(null);setManualKeyB64('');}}>Schließen</button>
                </div>

                {recoveryStatus && (
                  <div style={{fontSize:12.5,color:'#3F2E13',background:'#FFFEF7',border:'1px solid #FDE68A',borderRadius:8,padding:10,marginBottom:10}}>
                    <div style={{fontFamily:'monospace',fontSize:11.5,lineHeight:1.7}}>
                      <div>Aktueller Login: <strong>{recoveryStatus.currentFp}</strong></div>
                      <div>Server-Escrow:  <strong>{recoveryStatus.escrowFp || '— nicht verfügbar —'}</strong></div>
                      <div style={{marginTop:4,color:recoveryStatus.keysMatch?'#15803D':'#B45309'}}>
                        {recoveryStatus.keysMatch ? '✓ Beide Schlüssel identisch — Escrow bringt keinen anderen Zugriff.' : (recoveryStatus.escrowFp ? '⚠ Schlüssel verschieden — Escrow kann zusätzliche Daten entsperren!' : '⚠ Kein Escrow verfügbar.')}
                      </div>
                      <div style={{marginTop:4}}>Aktuelle Daten (/api/data): {recoveryStatus.dataDecryptable==='current'?'✓ mit Login lesbar':recoveryStatus.dataDecryptable==='escrow'?'⚠ NUR mit Escrow lesbar':recoveryStatus.dataDecryptable==='empty'?'leer':'✗ keiner der Schlüssel passt'}</div>
                    </div>

                    {recoveryStatus.dataDecryptable==='escrow' && recoveryStatus.escrowMasterKey && (
                      <div style={{marginTop:8,padding:'8px 10px',background:'#FEF3C7',border:'1px solid #FCD34D',borderRadius:6}}>
                        <div style={{fontSize:12,marginBottom:6}}>Deine aktuellen Daten sind mit dem Escrow-Schlüssel verschlüsselt, nicht mit deinem Login.</div>
                        <button className="btn btn-primary btn-sm" disabled={recoveryBusy} onClick={async()=>{
                          setRecoveryBusy(true);setBackupErr('');setBackupInfo('');
                          try{
                            const s=currentSettings;
                            const r=await fetch('/api/data',{headers:{Authorization:`Bearer ${s.token}`}});
                            const j=await r.json();
                            const data=await aesDecrypt(recoveryStatus.escrowMasterKey,j.content);
                            const re=await aesEncrypt(cryptoKey,data);
                            const ri=await fetch('/api/import',{method:'POST',headers:{Authorization:`Bearer ${s.token}`,'Content-Type':'application/json'},body:JSON.stringify({encryptedData:re})});
                            if(!ri.ok)throw new Error((await ri.json().catch(()=>({}))).error||ri.status);
                            setBackupInfo('✓ Daten neu verschlüsselt mit deinem Login — bitte Seite neu laden.');
                          }catch(e){setBackupErr(e.message);}
                          setRecoveryBusy(false);
                        }}>↻ Aktuelle Daten mit Login-Schlüssel neu verschlüsseln</button>
                      </div>
                    )}

                    {recoveryStatus.backupStatus.length > 0 && (
                      <div style={{marginTop:10}}>
                        <div style={{fontWeight:600,marginBottom:4}}>Server-Backups:</div>
                        {recoveryStatus.backupStatus.map(b=>(
                          <div key={b.id} style={{display:'flex',justifyContent:'space-between',alignItems:'center',padding:'5px 0',borderTop:'1px dashed #FDE68A',fontSize:11.5}}>
                            <span style={{fontFamily:'monospace'}}>{b.name}</span>
                            <span>
                              {b.decryptable==='current' && <button className="btn btn-primary btn-sm" style={{fontSize:11}} disabled={recoveryBusy} onClick={()=>restoreWithKey(b.id,cryptoKey)}>↻ Wiederherstellen</button>}
                              {b.decryptable==='escrow' && <button className="btn btn-primary btn-sm" style={{fontSize:11}} disabled={recoveryBusy} onClick={()=>restoreWithKey(b.id,recoveryStatus.escrowMasterKey)}>↻ Mit Escrow wiederherstellen</button>}
                              {b.decryptable==='manual' && recoveryStatus.manualMasterKey && <button className="btn btn-primary btn-sm" style={{fontSize:11}} disabled={recoveryBusy} onClick={()=>restoreWithKey(b.id,recoveryStatus.manualMasterKey)}>↻ Mit Schlüssel wiederherstellen</button>}
                              {b.decryptable==='none' && <span style={{color:'#9A3412'}}>✗ kein passender Schlüssel</span>}
                              {b.decryptable==='error' && <span style={{color:'#9A3412'}}>Fehler</span>}
                            </span>
                          </div>
                        ))}
                      </div>
                    )}

                    <div style={{marginTop:12,padding:'10px 12px',background:'#FFFEF7',border:'1px dashed #FDE68A',borderRadius:6}}>
                      <div style={{fontSize:12,marginBottom:6,color:'#78350F',fontWeight:600}}>🔑 Alten Schlüssel von einem anderen Gerät einfügen</div>
                      <div style={{fontSize:11.5,marginBottom:8,color:'#78350F',lineHeight:1.55}}>
                        Geh auf einem Gerät/Browser wo du <em>früher</em> eingeloggt warst auf crm.webars.at, drücke <code style={{background:'rgba(0,0,0,0.08)',padding:'1px 4px',borderRadius:3}}>F12</code> → Console und führe aus:
                      </div>
                      <div style={{background:'#1E1B18',color:'#E2DDD8',fontFamily:'monospace',fontSize:10.5,padding:'8px 10px',borderRadius:6,marginBottom:8,userSelect:'all',wordBreak:'break-all',lineHeight:1.5}}>
                        JSON.stringify(&#123;master_raw:sessionStorage.getItem('webars_device_key_v1'),master_wrapped:localStorage.getItem('webars_master_v1'),salt:localStorage.getItem('webars_salt_v1')&#125;)
                      </div>
                      <div style={{fontSize:11,marginBottom:8,color:'#78350F',lineHeight:1.5}}>Das Ergebnis hier einfügen (geht auch direkt als 44-Zeichen base64 Master Key):</div>
                      <textarea placeholder='{"master_raw":"…","master_wrapped":"…","salt":"…"}' value={manualKeyB64} onChange={e=>setManualKeyB64(e.target.value)}
                        rows={3} style={{width:'100%',fontSize:11.5,fontFamily:'monospace',padding:'6px 8px',borderRadius:6,border:'1px solid #FDE68A',background:'#FFFEF0',marginBottom:6,boxSizing:'border-box',resize:'vertical'}}/>
                      <button className="btn btn-ghost btn-sm" style={{fontSize:11.5}} onClick={tryManualKey} disabled={recoveryBusy||!manualKeyB64.trim()}>Schlüssel testen</button>

                      {manualNeedsPw && (
                        <div style={{marginTop:10,padding:'8px 10px',background:'#FEF3C7',border:'1px solid #FCD34D',borderRadius:6}}>
                          <div style={{fontSize:11.5,marginBottom:6,color:'#78350F'}}>Nur Salt + wrapped Key gefunden — gib das <strong>alte Passwort</strong> ein, das damals für dieses Gerät verwendet wurde:</div>
                          <input type="password" placeholder="Altes Passwort" value={manualOldPw} onChange={e=>setManualOldPw(e.target.value)}
                            style={{width:'100%',fontSize:12,padding:'6px 8px',borderRadius:6,border:'1px solid #FCD34D',background:'#FFFEF0',marginBottom:6,boxSizing:'border-box'}}
                            autoFocus onKeyDown={e=>e.key==='Enter'&&!recoveryBusy&&manualOldPw&&tryManualWithPassword()}/>
                          <button className="btn btn-primary btn-sm" style={{fontSize:11.5}} onClick={tryManualWithPassword} disabled={recoveryBusy||!manualOldPw}>Mit altem Passwort entsperren</button>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            )}
            {migratePending && (
              <div style={{background:'#FFFBEB',border:'1px solid #FDE68A',borderRadius:10,padding:16,marginBottom:10}}>
                <div style={{fontWeight:700,fontSize:13,color:'#92400E',marginBottom:8}}>🔑 Altes Passwort erforderlich</div>
                {migratePending.exportSalt ? (
                  // V2: simple password-only flow (migration export file)
                  <>
                    <div style={{fontSize:12,color:'#78350F',marginBottom:10,lineHeight:1.6}}>
                      Migration-Export erkannt. Gib dein <strong>altes CRM-Passwort</strong> ein — die Daten werden automatisch in dein neues Konto übernommen.
                    </div>
                    <input type="password" placeholder="Altes Passwort" value={migrateOldPw} onChange={e=>setMigrateOldPw(e.target.value)}
                      style={{width:'100%',fontSize:13,padding:'8px 10px',borderRadius:7,border:'1px solid #FCD34D',background:'#FFFEF0',marginBottom:10,boxSizing:'border-box'}}
                      autoFocus onKeyDown={e=>e.key==='Enter'&&doMigrateImport()}
                    />
                    <div style={{display:'flex',gap:8}}>
                      <button className="btn btn-primary btn-sm" onClick={doMigrateImport} disabled={migrateBusy||!migrateOldPw}>
                        {migrateBusy?'Importiere…':'✓ Importieren'}
                      </button>
                      <button className="btn btn-ghost btn-sm" onClick={()=>{setMigratePending(null);setMigrateOldPw('');setBackupErr('');}}>Abbrechen</button>
                    </div>
                  </>
                ) : migratePending.localSalt ? (
                  // V3: server backup, salt still in localStorage — password only
                  <>
                    <div style={{fontSize:12,color:'#78350F',marginBottom:10,lineHeight:1.6}}>
                      Dieses Backup wurde mit einem anderen Schlüssel verschlüsselt. Gib das <strong>Passwort ein, das du damals verwendet hast</strong> — die Daten werden automatisch mit deinem aktuellen Schlüssel neu verschlüsselt.
                    </div>
                    <input type="password" placeholder="Altes Passwort" value={migrateOldPw} onChange={e=>setMigrateOldPw(e.target.value)}
                      style={{width:'100%',fontSize:13,padding:'8px 10px',borderRadius:7,border:'1px solid #FCD34D',background:'#FFFEF0',marginBottom:10,boxSizing:'border-box'}}
                      autoFocus onKeyDown={e=>e.key==='Enter'&&doMigrateImport()}
                    />
                    <div style={{display:'flex',gap:8}}>
                      <button className="btn btn-primary btn-sm" onClick={doMigrateImport} disabled={migrateBusy||!migrateOldPw}>
                        {migrateBusy?'Importiere…':'✓ Importieren'}
                      </button>
                      <button className="btn btn-ghost btn-sm" onClick={()=>{setMigratePending(null);setMigrateOldPw('');setBackupErr('');}}>Abbrechen</button>
                    </div>
                  </>
                ) : (
                  // V1 fallback: localStorage cleared, need manual console data
                  <>
                    <div style={{fontSize:12,color:'#78350F',marginBottom:10,lineHeight:1.6}}>
                      Dieses Backup wurde mit einem anderen Schlüssel verschlüsselt. Bitte erstelle im alten CRM einen <strong>Migration-Export</strong> (Einstellungen → Backup → 📦 Migration-Export). Falls das nicht möglich ist:<br/><br/>
                      Öffne das alte CRM, drücke <code style={{background:'rgba(0,0,0,0.08)',padding:'1px 4px',borderRadius:3}}>F12</code> → Konsole → ausführen:
                    </div>
                    <div style={{background:'#1E1B18',color:'#E2DDD8',fontFamily:'monospace',fontSize:11.5,padding:'10px 13px',borderRadius:8,marginBottom:10,userSelect:'all',wordBreak:'break-all'}}>
                      JSON.stringify(&#123;s:localStorage.getItem('webars_salt'),m:localStorage.getItem('webars_master_v1')&#125;)
                    </div>
                    <textarea placeholder='Ergebnis hier einfügen…' value={migrateOldData} onChange={e=>setMigrateOldData(e.target.value)}
                      rows={3} style={{width:'100%',fontSize:12,fontFamily:'monospace',padding:'8px 10px',borderRadius:7,border:'1px solid #FCD34D',background:'#FFFEF0',marginBottom:8,boxSizing:'border-box',resize:'vertical'}}
                    />
                    <input type="password" placeholder="Altes Passwort" value={migrateOldPw} onChange={e=>setMigrateOldPw(e.target.value)}
                      style={{width:'100%',fontSize:13,padding:'8px 10px',borderRadius:7,border:'1px solid #FCD34D',background:'#FFFEF0',marginBottom:10,boxSizing:'border-box'}}
                      onKeyDown={e=>e.key==='Enter'&&doMigrateImport()}
                    />
                    <div style={{display:'flex',gap:8}}>
                      <button className="btn btn-primary btn-sm" onClick={doMigrateImport} disabled={migrateBusy||!migrateOldPw||!migrateOldData.trim()}>
                        {migrateBusy?'Importiere…':'✓ Importieren'}
                      </button>
                      <button className="btn btn-ghost btn-sm" onClick={()=>{setMigratePending(null);setMigrateOldPw('');setMigrateOldData('');setBackupErr('');}}>Abbrechen</button>
                    </div>
                  </>
                )}
              </div>
            )}
            {backups.length > 0 && (
              <div style={{maxHeight:200,overflowY:'auto',border:'1px solid #F0EDE8',borderRadius:8}}>
                {backups.map(b=>{
                  const dateMatch = (b.name||'').match(/(\d{4}-\d{2}-\d{2})/);
                  const date = dateMatch ? dateMatch[1] : (b.created_at ? b.created_at.slice(0,10) : b.name||String(b.id));
                  return(
                    <div key={b.sha||b.id} style={{display:'flex',alignItems:'center',justifyContent:'space-between',padding:'8px 12px',borderBottom:'1px solid #F5F3F0',fontSize:12.5}}>
                      <div>
                        <div style={{fontWeight:600,color:'#141210'}}>{date}</div>
                        <div style={{fontSize:10.5,color:'#A8A39D',fontFamily:'monospace',marginTop:1}}>{b.name}</div>
                      </div>
                      <button className="btn btn-ghost btn-sm" style={{fontSize:11}} onClick={()=>restoreFromBackup(b)} disabled={backupBusy}>Wiederherstellen</button>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function InviteManagerModal({masterKey, onClose}) {
  const [token, setToken]   = useState('');
  const [busy, setBusy]     = useState(false);
  const [copiedLink, setCopiedLink]   = useState(false);
  const [copiedToken, setCopiedToken] = useState(false);
  const [err, setErr]       = useState('');
  const cloudReady = !!_ghSettings;

  const buildInviteLink = (tok) => {
    const base = window.location.origin + window.location.pathname.replace(/\/$/,'');
    return `${base}/?invite=${encodeURIComponent(tok)}`;
  };

  const generate = async () => {
    setErr(''); setBusy(true);
    try {
      if (!_ghSettings) {
        setErr('Cloud-Sync muss aktiv sein, bevor du jemanden einladen kannst. Klick links unten auf "Cloud-Sync".');
        setBusy(false); return;
      }
      const tok = await createInviteToken(masterKey, _ghSettings);
      setToken(tok);
    } catch(e) { setErr('Fehler beim Erstellen.'); }
    setBusy(false);
  };

  const copyLink = () => {
    navigator.clipboard?.writeText(buildInviteLink(token)).then(()=>{setCopiedLink(true);setTimeout(()=>setCopiedLink(false),2000);});
  };
  const copyToken = () => {
    navigator.clipboard?.writeText(token).then(()=>{setCopiedToken(true);setTimeout(()=>setCopiedToken(false),2000);});
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-box" style={{width:520,padding:28}} onClick={e=>e.stopPropagation()}>
        <div style={{display:'flex',justifyContent:'space-between',alignItems:'flex-start',marginBottom:18}}>
          <div>
            <h2 style={{fontSize:17,fontWeight:700}}>📱 Gerät verbinden oder Mitglied einladen</h2>
            <p style={{fontSize:12.5,color:'#A8A39D',marginTop:3,lineHeight:1.5}}>Erstelle einen Verbindungs-Link. Damit kann <strong>dein eigenes neues Gerät</strong> oder ein <strong>Team-Mitglied</strong> auf <strong>genau dieselben Daten</strong> zugreifen wie hier.</p>
          </div>
          <button onClick={onClose} style={{background:'#F5F3F0',border:'none',borderRadius:8,padding:8,color:'#999',lineHeight:0}}><Icons.Close/></button>
        </div>

        <div style={{background:'#F0F9FF',border:'1px solid #BAE6FD',borderRadius:10,padding:'12px 14px',marginBottom:16,fontSize:12.5,color:'#0C4A6E',lineHeight:1.55}}>
          <strong>So einfach geht's:</strong>
          <ol style={{marginTop:6,marginLeft:18,padding:0,lineHeight:1.7}}>
            <li>Hier unten <strong>Verbindungs-Link erstellen</strong></li>
            <li>Link kopieren und auf dem neuen Gerät (oder bei Team-Mitglied) öffnen</li>
            <li>Dort eigene Email + Passwort wählen → fertig, alle Daten sind da</li>
          </ol>
        </div>

        {!cloudReady && (
          <div style={{background:'#FFF7ED',border:'1px solid #FED7AA',borderRadius:10,padding:'12px 14px',marginBottom:16,fontSize:12.5,color:'#9A3412',lineHeight:1.55}}>
            <strong>Cloud-Sync nicht aktiv.</strong> Aktiviere zuerst Cloud-Sync (links unten in der Sidebar), sonst können Mitglieder die Daten nicht sehen.
          </div>
        )}

        {!token && (
          <button className="btn btn-primary" onClick={generate} disabled={busy||!cloudReady} style={{width:'100%',justifyContent:'center'}}>
            {busy?'…':<><Icons.Plus/>Verbindungs-Link erstellen</>}
          </button>
        )}

        {err && <div style={{fontSize:12.5,color:'#C0392B',padding:'8px 12px',background:'#FEF2F2',borderRadius:8,marginTop:12,border:'1px solid #FECACA'}}>{err}</div>}

        {token && (<>
          <div style={{padding:'14px 16px',background:'white',borderRadius:11,border:'1.5px solid #E8E4DF',marginBottom:14}}>
            <div style={{fontSize:11,color:'#A8A39D',marginBottom:8,textTransform:'uppercase',letterSpacing:'0.05em',fontWeight:600,display:'flex',alignItems:'center',gap:6}}>
              <span style={{color:'#16a34a'}}>✦</span> Verbindungs-Link (empfohlen)
            </div>
            <div style={{fontSize:12,color:'#3F3A35',wordBreak:'break-all',padding:'8px 10px',background:'#FAFAF8',borderRadius:7,fontFamily:'monospace',lineHeight:1.4,marginBottom:8,maxHeight:80,overflow:'auto'}}>{buildInviteLink(token)}</div>
            <button className="btn btn-primary btn-sm" onClick={copyLink} style={{width:'100%',justifyContent:'center'}}>
              {copiedLink?'✓ Link kopiert':'Link kopieren'}
            </button>
            <div style={{fontSize:12,color:'#6B6560',marginTop:10,lineHeight:1.5}}>
              Sende den Link sicher (z.B. via Bitwarden, Signal). Mitglied wählt nur noch <strong>eigene Email + eigenes Passwort</strong>.
            </div>
          </div>

          <div style={{padding:'12px 14px',background:'#FAFAF8',borderRadius:10,border:'1px solid #E8E4DF',marginBottom:14}}>
            <div style={{fontSize:10.5,color:'#B0ABA5',marginBottom:6,textTransform:'uppercase',letterSpacing:'0.05em',fontWeight:600}}>Nur der Token (manuelle Eingabe)</div>
            <div style={{fontFamily:'monospace',fontSize:11,color:'#3F3A35',background:'white',padding:'8px 10px',borderRadius:6,wordBreak:'break-all',maxHeight:70,overflow:'auto',marginBottom:6,lineHeight:1.4}}>{token}</div>
            <button className="btn btn-ghost btn-sm" onClick={copyToken}>{copiedToken?'✓ Kopiert':'Token kopieren'}</button>
          </div>

          <div style={{padding:'10px 14px',background:'#FEF2F2',borderRadius:10,border:'1px solid #FECACA',fontSize:12,color:'#9A1F1F',lineHeight:1.5,marginBottom:14}}>
            <strong>Wichtig:</strong> Der Token enthält Master-Schlüssel + Cloud-Zugang. Behandle ihn wie ein Passwort.
          </div>

          <div style={{display:'flex',gap:8,justifyContent:'space-between'}}>
            <button className="btn btn-ghost btn-sm" onClick={()=>setToken('')}>Neuen erstellen</button>
            <button className="btn btn-primary btn-sm" onClick={onClose}>Fertig</button>
          </div>
        </>)}
      </div>
    </div>
  );
}

// ── CONFIRM MODAL ─────────────────────────────────────────────────
function ConfirmModal({text,onConfirm,onCancel}){
  return(<div className="modal-overlay" onClick={onCancel}><div className="modal-box" style={{width:380,padding:28}} onClick={e=>e.stopPropagation()}><p style={{fontSize:15,color:'#333',lineHeight:1.6,marginBottom:24}}>{text}</p><div style={{display:'flex',gap:10,justifyContent:'flex-end'}}><button className="btn btn-ghost" onClick={onCancel}>Abbrechen</button><button className="btn btn-danger" onClick={onConfirm}>Löschen</button></div></div></div>);
}

function ContactModal({contact,sections,customFields,onSave,onClose}){
  const isEdit=!!contact;
  const [form,setForm]=useState(contact?{...contact}:{firma:'',ansprechpartner:'',email:'',telefon:'',address:'',zip:'',city:'',country:'',taxId:'',status:'Aktiv',notizen:'',umsatz:'',sectionId:sections[0]?.id||'',reminders:[],activities:[],customValues:{}});
  const set=(k,v)=>setForm(f=>({...f,[k]:v}));
  const setCV=(k,v)=>setForm(f=>({...f,customValues:{...f.customValues,[k]:v}}));
  const relevant=customFields.filter(cf=>!cf.sectionId||cf.sectionId===form.sectionId);
  return(<div className="modal-overlay" onClick={onClose}><div className="modal-box" onClick={e=>e.stopPropagation()}>
    <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:26}}>
      <div><h2 style={{fontSize:18,fontWeight:700}}>{isEdit?'Kontakt bearbeiten':'Neuer Kontakt'}</h2><p style={{fontSize:13,color:'#A8A39D',marginTop:3}}>{isEdit?form.firma:'Felder nach Bedarf ausfüllen'}</p></div>
      <button onClick={onClose} style={{background:'#F5F3F0',border:'none',borderRadius:8,padding:8,color:'#999',lineHeight:0}}><Icons.Close/></button>
    </div>
    <div style={{display:'grid',gap:16}}>
      <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:12}}>
        <div><label style={lbl}>Bereich</label><select value={form.sectionId} onChange={e=>set('sectionId',e.target.value)}>{sections.map(s=><option key={s.id} value={s.id}>{s.name}</option>)}</select></div>
        <div><label style={lbl}>Status</label><select value={form.status} onChange={e=>set('status',e.target.value)}>{STATUSES.map(s=><option key={s}>{s}</option>)}</select></div>
      </div>
      <div><label style={lbl}>Firma / Unternehmen *</label><input value={form.firma} onChange={e=>set('firma',e.target.value)} placeholder="Musterfirma GmbH"/></div>
      <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:12}}>
        <div><label style={lbl}>E-Mail</label><input type="email" value={form.email} onChange={e=>set('email',e.target.value)} placeholder="office@firma.at"/></div>
        <div><label style={lbl}>Telefon</label><input value={form.telefon} onChange={e=>set('telefon',e.target.value)} placeholder="+43 1 234 5678"/></div>
      </div>
      <div><label style={lbl}>Umsatz / Auftragswert (€)</label><input type="number" value={form.umsatz} onChange={e=>set('umsatz',e.target.value)} placeholder="0"/></div>
      <div><label style={lbl}>Notizen</label><textarea value={form.notizen} onChange={e=>set('notizen',e.target.value)} placeholder="Interne Notizen..."/></div>
      {relevant.map(cf=>(<div key={cf.id}><label style={lbl}>{cf.label}</label>{cf.type==='textarea'?<textarea value={form.customValues?.[cf.id]||''} onChange={e=>setCV(cf.id,e.target.value)}/>:<input type={cf.type||'text'} value={form.customValues?.[cf.id]||''} onChange={e=>setCV(cf.id,e.target.value)}/>}</div>))}
    </div>
    <div style={{display:'flex',gap:10,justifyContent:'flex-end',marginTop:28}}>
      <button className="btn btn-ghost" onClick={onClose}>Abbrechen</button>
      <button className="btn btn-primary" onClick={()=>{if(!form.firma.trim())return alert('Bitte Firma angeben.');onSave({...form,id:form.id||uid()});}}>Speichern</button>
    </div>
  </div></div>);
}

function ContactDetail({contact,sections,quotes,settings,onClose,onUpdate,onEdit,onCreateQuote,onOpenQuote}){
  const [tab,setTab]=useState('aktivitäten');
  const [newAct,setNewAct]=useState('');
  const [remText,setRemText]=useState('');
  const [remDate,setRemDate]=useState('');
  const today=new Date().toISOString().slice(0,10);
  const section=sections.find(s=>s.id===contact.sectionId);
  const initials=contact.firma.split(' ').slice(0,2).map(w=>w[0]).join('').toUpperCase();
  const aColor=avatarColor(contact.firma);
  const addAct=()=>{if(!newAct.trim())return;onUpdate({...contact,activities:[...(contact.activities||[]),{id:uid(),text:newAct,date:today}]});setNewAct('');};
  const delAct=id=>onUpdate({...contact,activities:(contact.activities||[]).filter(a=>a.id!==id)});
  const addRem=()=>{if(!remText.trim()||!remDate)return;onUpdate({...contact,reminders:[...(contact.reminders||[]),{id:uid(),text:remText,date:remDate}]});setRemText('');setRemDate('');};
  const delRem=id=>onUpdate({...contact,reminders:(contact.reminders||[]).filter(r=>r.id!==id)});
  return(<div style={{position:'fixed',inset:0,zIndex:900,display:'flex',justifyContent:'flex-end'}} onClick={onClose}>
    <div onClick={e=>e.stopPropagation()} style={{width:460,background:'white',height:'100%',display:'flex',flexDirection:'column',boxShadow:'-2px 0 60px rgba(0,0,0,.12)',animation:'slideInRight .22s cubic-bezier(.34,1.1,.64,1)'}}>
      <div style={{padding:'28px 28px 22px',borderBottom:'1px solid #F0EDE9'}}>
        <div style={{display:'flex',justifyContent:'space-between',alignItems:'flex-start',marginBottom:18}}>
          <div style={{display:'flex',alignItems:'center',gap:14}}>
            <div style={{width:48,height:48,borderRadius:13,background:aColor,color:'white',display:'flex',alignItems:'center',justifyContent:'center',fontWeight:700,fontSize:16,flexShrink:0}}>{initials}</div>
            <div><div style={{fontWeight:700,fontSize:17,letterSpacing:'-0.01em',lineHeight:1.2}}>{contact.firma}</div><div style={{marginTop:6}}><StatusDot status={contact.status}/></div></div>
          </div>
          <div style={{display:'flex',gap:8}}><button className="btn btn-ghost btn-sm" onClick={onEdit}><Icons.Edit/>Bearbeiten</button><button onClick={onClose} style={{background:'#F5F3F0',border:'none',borderRadius:8,padding:8,color:'#999',lineHeight:0}}><Icons.Close/></button></div>
        </div>
        <div style={{display:'grid',gap:6}}>
          {contact.email&&<a href={`mailto:${contact.email}`} style={{fontSize:13,color:'#6B6560',textDecoration:'none',display:'flex',alignItems:'center',gap:8}}><span style={{fontSize:11}}>✉</span>{contact.email}</a>}
          {contact.telefon&&<div style={{fontSize:13,color:'#6B6560',display:'flex',alignItems:'center',gap:8}}><span style={{fontSize:11}}>✆</span>{contact.telefon}</div>}
          {fmt(contact.umsatz)&&<div style={{fontSize:14,fontWeight:700,color:'oklch(62% 0.14 65)',marginTop:2}}>{fmt(contact.umsatz)}</div>}
          {contact.notizen&&<p style={{fontSize:13,color:'#888',lineHeight:1.6,marginTop:4,borderTop:'1px solid #F5F3F0',paddingTop:10}}>{contact.notizen}</p>}
        </div>
        {section&&<div style={{marginTop:10,fontSize:11.5,color:'#C0BBB5',fontWeight:500,display:'flex',alignItems:'center',gap:5}}><span>{section.icon}</span>{section.name}</div>}
      </div>
      <div style={{display:'flex',borderBottom:'1px solid #F0EDE9',padding:'0 28px',flexShrink:0}}>
        {[{id:'aktivitäten',icon:<Icons.Activity/>},{id:'erinnerungen',icon:<Icons.Reminder/>},{id:'angebote',icon:<Icons.Quote/>}].map(t=>(
          <button key={t.id} onClick={()=>setTab(t.id)} style={{background:'none',padding:'13px 0',marginRight:22,fontSize:12.5,fontWeight:600,color:tab===t.id?'#141210':'#B0ABA5',borderBottom:tab===t.id?'2px solid #141210':'2px solid transparent',display:'flex',alignItems:'center',gap:6,transition:'all .15s',textTransform:'capitalize'}}>{t.icon}{t.id}</button>
        ))}
      </div>
      <div style={{flex:1,overflowY:'auto',padding:28}}>
        {tab==='aktivitäten'&&(<>
          <div style={{display:'flex',gap:8,marginBottom:20}}><input value={newAct} onChange={e=>setNewAct(e.target.value)} placeholder="Neue Aktivität..." onKeyDown={e=>e.key==='Enter'&&addAct()}/><button className="btn btn-primary btn-sm" style={{flexShrink:0}} onClick={addAct}><Icons.Plus/></button></div>
          {(contact.activities||[]).length===0?<div style={{fontSize:13,color:'#C8C3BD',textAlign:'center',paddingTop:20}}>Noch keine Aktivitäten.</div>
          :[...(contact.activities||[])].reverse().map(a=>(<div key={a.id} style={{display:'flex',justifyContent:'space-between',alignItems:'flex-start',padding:'12px 0',borderBottom:'1px solid #F8F6F3'}}>
            <div><div style={{fontSize:13.5,lineHeight:1.5}}>{a.text}</div><div style={{fontSize:11.5,color:'#C0BBB5',marginTop:3}}>{fmtDate(a.date)}</div></div>
            <button onClick={()=>delAct(a.id)} style={{background:'none',border:'none',color:'#D4CFC9',fontSize:16,cursor:'pointer',padding:'0 4px'}}>×</button>
          </div>))}
        </>)}
        {tab==='erinnerungen'&&(<>
          <div style={{display:'grid',gap:8,marginBottom:20,padding:16,background:'#FAF9F7',borderRadius:12}}>
            <input value={remText} onChange={e=>setRemText(e.target.value)} placeholder="Erinnerung..."/>
            <input type="date" value={remDate} onChange={e=>setRemDate(e.target.value)}/>
            <button className="btn btn-primary btn-sm" onClick={addRem}>Erinnerung hinzufügen</button>
          </div>
          {(contact.reminders||[]).length===0?<div style={{fontSize:13,color:'#C8C3BD',textAlign:'center',paddingTop:10}}>Keine Erinnerungen gesetzt.</div>
          :[...(contact.reminders||[])].sort((a,b)=>a.date.localeCompare(b.date)).map(r=>{
            const ov=r.date<today;
            return(<div key={r.id} style={{display:'flex',justifyContent:'space-between',alignItems:'center',padding:'11px 14px',borderRadius:10,background:ov?'#FFF7ED':'#FAF9F7',marginBottom:8,border:ov?'1px solid #FED7AA':'1px solid transparent'}}>
              <div><div style={{fontSize:13.5}}>{r.text}</div><div style={{fontSize:11.5,marginTop:3,color:ov?'#B45309':'#C0BBB5',fontWeight:ov?600:400}}>{fmtDate(r.date)}{ov?' · Überfällig':''}</div></div>
              <button onClick={()=>delRem(r.id)} style={{background:'none',border:'none',color:'#D4CFC9',fontSize:16,cursor:'pointer',padding:'0 4px'}}>×</button>
            </div>);
          })}
        </>)}
        {tab==='angebote'&&(()=>{
          const cQuotes = (quotes||[]).filter(q=>q.contactId===contact.id).sort((a,b)=>(b.createdAt||'').localeCompare(a.createdAt||''));
          const cur = settings?.currency || 'EUR';
          return(<>
            <button className="btn btn-primary" style={{width:'100%',marginBottom:14,justifyContent:'center'}} onClick={onCreateQuote}><Icons.Plus/>Neues Angebot für {contact.firma}</button>
            {cQuotes.length===0?(
              <div style={{fontSize:13,color:'#C8C3BD',textAlign:'center',paddingTop:20}}>Noch keine Angebote für diesen Kunden.</div>
            ):cQuotes.map(q=>{
              const totals = quoteTotals(q);
              const status = QUOTE_STATUSES.find(s=>s.key===q.status) || QUOTE_STATUSES[0];
              return(
                <div key={q.id} onClick={()=>onOpenQuote(q)} style={{padding:'12px 14px',borderRadius:10,background:'#FAF9F7',marginBottom:8,cursor:'pointer',border:'1px solid transparent',transition:'all 0.15s'}}
                  onMouseEnter={e=>e.currentTarget.style.borderColor='#E8E4DF'}
                  onMouseLeave={e=>e.currentTarget.style.borderColor='transparent'}>
                  <div style={{display:'flex',justifyContent:'space-between',alignItems:'flex-start',gap:10}}>
                    <div style={{flex:1,minWidth:0}}>
                      <div style={{display:'flex',alignItems:'center',gap:8,marginBottom:4}}>
                        <span style={{fontFamily:'monospace',fontSize:11,color:'#6B6560',fontWeight:600}}>{q.number}</span>
                        <span style={{display:'inline-flex',alignItems:'center',gap:4,padding:'1px 6px',borderRadius:99,background:status.bg,fontSize:10,fontWeight:600,color:status.color}}>
                          <span style={{width:4,height:4,borderRadius:'50%',background:status.dot}}></span>{status.label}
                        </span>
                      </div>
                      <div style={{fontSize:13,fontWeight:600,whiteSpace:'nowrap',overflow:'hidden',textOverflow:'ellipsis'}}>{q.title || '(ohne Titel)'}</div>
                      <div style={{fontSize:11.5,color:'#A8A39D',marginTop:2}}>{fmtDate(q.date)}</div>
                    </div>
                    <div style={{fontSize:14,fontWeight:700,fontVariantNumeric:'tabular-nums',whiteSpace:'nowrap'}}>{fmtMoney(totals.total,cur)}</div>
                  </div>
                </div>
              );
            })}
          </>);
        })()}
      </div>
    </div>
  </div>);
}

function ContactCard({contact,sections,onEdit,onDelete,onDetail,onMove,animDelay}){
  const initials=(contact.firma||'?').split(' ').slice(0,2).map(w=>w[0]||'').join('').toUpperCase()||'?';
  const aColor=avatarColor(contact.firma);
  const overdueRem=(contact.reminders||[]).filter(r=>r.date<new Date().toISOString().slice(0,10));
  const [hover,setHover]=useState(false);
  return(<div onClick={()=>onDetail(contact)} onMouseEnter={()=>setHover(true)} onMouseLeave={()=>setHover(false)}
    style={{background:'white',borderRadius:14,padding:'20px 22px',border:'1px solid rgba(0,0,0,.07)',boxShadow:hover?'0 4px 24px rgba(0,0,0,.10)':'0 1px 4px rgba(0,0,0,.05)',transform:hover?'translateY(-2px)':'translateY(0)',transition:'box-shadow .2s,transform .2s',cursor:'pointer',display:'flex',flexDirection:'column',gap:14,animation:`cardIn .3s ${animDelay||0}s both ease`}}>
    <div style={{display:'flex',alignItems:'flex-start',gap:13}}>
      <div style={{width:40,height:40,borderRadius:11,background:aColor,color:'white',display:'flex',alignItems:'center',justifyContent:'center',fontWeight:700,fontSize:14,flexShrink:0}}>{initials}</div>
      <div style={{flex:1,minWidth:0}}>
        <div style={{fontWeight:700,fontSize:15,letterSpacing:'-0.01em',lineHeight:1.2,marginBottom:7,whiteSpace:'nowrap',overflow:'hidden',textOverflow:'ellipsis'}}>{contact.firma}</div>
        <StatusDot status={contact.status}/>
      </div>
      {overdueRem.length>0&&<div title="Überfällige Erinnerung" style={{color:'#f59e0b',flexShrink:0}}><Icons.Bell/></div>}
    </div>
    <div style={{display:'grid',gap:5}}>
      {contact.email&&<div style={{fontSize:12.5,color:'#8A857F',display:'flex',alignItems:'center',gap:7,overflow:'hidden'}}><span style={{fontSize:10}}>✉</span><span style={{overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{contact.email}</span></div>}
      {contact.telefon&&<div style={{fontSize:12.5,color:'#8A857F',display:'flex',alignItems:'center',gap:7}}><span style={{fontSize:10}}>✆</span>{contact.telefon}</div>}
      {fmt(contact.umsatz)&&<div style={{fontSize:14,fontWeight:700,color:'oklch(62% 0.14 65)',marginTop:2}}>{fmt(contact.umsatz)}</div>}
    </div>
    <div style={{display:'flex',gap:6,marginTop:'auto'}} onClick={e=>e.stopPropagation()}>
      <button className="btn btn-ghost btn-sm" onClick={()=>onEdit(contact)} style={{flex:1,justifyContent:'center'}}><Icons.Edit/>Bearbeiten</button>
      <button className="btn btn-ghost btn-sm btn-icon" title="Verschieben" onClick={()=>onMove(contact)}><Icons.Move/></button>
      <button onClick={()=>onDelete(contact)} style={{background:'none',border:'none',color:'#DDD',padding:'7px 9px',borderRadius:8,transition:'color .15s,background .15s'}}
        onMouseEnter={e=>{e.currentTarget.style.color='#C0392B';e.currentTarget.style.background='#FEF2F2';}}
        onMouseLeave={e=>{e.currentTarget.style.color='#DDD';e.currentTarget.style.background='none';}}><Icons.Trash/></button>
    </div>
  </div>);
}

function MoveModal({contact,sections,onMove,onClose}){return(<div className="modal-overlay" onClick={onClose}><div className="modal-box" style={{width:360,padding:28}} onClick={e=>e.stopPropagation()}><h3 style={{fontSize:16,fontWeight:700,marginBottom:6}}>Kontakt verschieben</h3><p style={{fontSize:13,color:'#A8A39D',marginBottom:20}}>{contact.firma}</p><div style={{display:'grid',gap:8}}>{sections.filter(s=>s.id!==contact.sectionId).map(s=>(<button key={s.id} onClick={()=>onMove(contact.id,s.id)} className="btn btn-ghost" style={{justifyContent:'flex-start',padding:'12px 16px',fontSize:14}}><span style={{marginRight:10}}>{s.icon}</span>{s.name}</button>))}</div><button className="btn btn-ghost" style={{width:'100%',marginTop:12}} onClick={onClose}>Abbrechen</button></div></div>);}

function AddSectionModal({onAdd,onClose}){
  const [name,setName]=useState('');
  const icons=['◆','◎','❋','▲','⊕','⬡','✦','⊞','◉','∞'];
  const [icon,setIcon]=useState(icons[0]);
  return(<div className="modal-overlay" onClick={onClose}><div className="modal-box" style={{width:380,padding:28}} onClick={e=>e.stopPropagation()}><h3 style={{fontSize:16,fontWeight:700,marginBottom:22}}>Neuer Bereich</h3><div style={{display:'grid',gap:16}}><div><label style={lbl}>Name</label><input value={name} onChange={e=>setName(e.target.value)} placeholder="z.B. Partner, Lieferanten…" autoFocus/></div><div><label style={lbl}>Symbol</label><div style={{display:'flex',gap:8,flexWrap:'wrap'}}>{icons.map(ic=><button key={ic} onClick={()=>setIcon(ic)} style={{width:38,height:38,borderRadius:9,border:icon===ic?'none':'1.5px solid #E8E4DF',background:icon===ic?'#141210':'white',color:icon===ic?'white':'#6B6560',fontSize:16,cursor:'pointer',transition:'all .12s'}}>{ic}</button>)}</div></div></div><div style={{display:'flex',gap:10,justifyContent:'flex-end',marginTop:24}}><button className="btn btn-ghost" onClick={onClose}>Abbrechen</button><button className="btn btn-primary" onClick={()=>{if(!name.trim())return;onAdd({id:uid(),name:name.trim(),icon});}}>Erstellen</button></div></div></div>);
}

function AddFieldModal({sections,customFields,onAdd,onDelete,onClose}){
  const [label,setLabel]=useState('');const [type,setType]=useState('text');const [sectionId,setSectionId]=useState('');
  return(<div className="modal-overlay" onClick={onClose}><div className="modal-box" style={{width:420,padding:28}} onClick={e=>e.stopPropagation()}>
    <h3 style={{fontSize:16,fontWeight:700,marginBottom:6}}>Felder verwalten</h3><p style={{fontSize:13,color:'#A8A39D',marginBottom:22}}>Eigene Felder hinzufügen oder entfernen.</p>
    {customFields.length>0&&(<div style={{marginBottom:22}}><label style={lbl}>Vorhandene Felder</label><div style={{display:'grid',gap:6}}>{customFields.map(cf=>(<div key={cf.id} style={{display:'flex',justifyContent:'space-between',alignItems:'center',padding:'8px 12px',background:'#FAF9F7',borderRadius:8}}><div><span style={{fontSize:13.5,fontWeight:500}}>{cf.label}</span><span style={{fontSize:11.5,color:'#B0ABA5',marginLeft:8}}>{cf.type}{cf.sectionId?` · ${sections.find(s=>s.id===cf.sectionId)?.name}`:' · Global'}</span></div><button onClick={()=>onDelete(cf.id)} style={{background:'none',border:'none',color:'#DDD',cursor:'pointer',fontSize:16,padding:'0 4px'}} onMouseEnter={e=>e.currentTarget.style.color='#C0392B'} onMouseLeave={e=>e.currentTarget.style.color='#DDD'}>×</button></div>))}</div></div>)}
    <label style={lbl}>Neues Feld</label>
    <div style={{display:'grid',gap:12}}><input value={label} onChange={e=>setLabel(e.target.value)} placeholder="Feldname, z.B. Website, Branche…"/><div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:10}}><div><label style={lbl}>Typ</label><select value={type} onChange={e=>setType(e.target.value)}><option value="text">Text</option><option value="number">Zahl</option><option value="date">Datum</option><option value="url">URL</option><option value="textarea">Mehrzeilig</option></select></div><div><label style={lbl}>Bereich (optional)</label><select value={sectionId} onChange={e=>setSectionId(e.target.value)}><option value="">Alle Bereiche</option>{sections.map(s=><option key={s.id} value={s.id}>{s.name}</option>)}</select></div></div></div>
    <div style={{display:'flex',gap:10,justifyContent:'flex-end',marginTop:22}}><button className="btn btn-ghost" onClick={onClose}>Schließen</button><button className="btn btn-primary" onClick={()=>{if(!label.trim())return;onAdd({id:uid(),label:label.trim(),type,sectionId});setLabel('');}}>Feld hinzufügen</button></div>
  </div></div>);
}

// ══════════════════════════════════════════════════════════════════
//  TODO VIEW
// ══════════════════════════════════════════════════════════════════
const TODO_PRIORITIES = [{key:'hoch',label:'Hoch',color:'#ef4444',bg:'#FEF2F2'},{key:'mittel',label:'Mittel',color:'#f59e0b',bg:'#FFFBEB'},{key:'niedrig',label:'Niedrig',color:'#6B6560',bg:'#F5F3F0'}];

function TodoView({todos, onUpdate}) {
  const [newText, setNewText] = useState('');
  const [newDesc, setNewDesc] = useState('');
  const [newDate, setNewDate] = useState('');
  const [newPriority, setNewPriority] = useState('');
  const [showDone, setShowDone] = useState(false);
  const [filterPriority, setFilterPriority] = useState('');
  const [expandedId, setExpandedId] = useState(null);
  const today = new Date().toISOString().slice(0,10);

  const sortByPriority = (a,b) => {
    const pi=['hoch','mittel','niedrig'];
    const pa=pi.indexOf(a.priority),pb=pi.indexOf(b.priority);
    if(pa!==pb)return(pa===-1?99:pa)-(pb===-1?99:pb);
    return (a.dueDate||'9999').localeCompare(b.dueDate||'9999');
  };
  const open = todos.filter(t=>!t.done).sort(sortByPriority);
  const done = todos.filter(t=>t.done);

  const filteredOpen = filterPriority ? open.filter(t=>t.priority===filterPriority) : open;

  const counts = {
    hoch: open.filter(t=>t.priority==='hoch').length,
    mittel: open.filter(t=>t.priority==='mittel').length,
    niedrig: open.filter(t=>t.priority==='niedrig').length,
    keine: open.filter(t=>!t.priority).length,
  };

  const addTodo = () => {
    if(!newText.trim()) return;
    onUpdate([...todos,{id:uid(),text:newText.trim(),description:newDesc.trim(),done:false,priority:newPriority,dueDate:newDate,createdAt:today}]);
    setNewText(''); setNewDesc(''); setNewDate(''); setNewPriority('');
  };
  const toggle = id => onUpdate(todos.map(t=>t.id===id?{...t,done:!t.done,doneAt:!t.done?today:null}:t));
  const remove = id => onUpdate(todos.filter(t=>t.id!==id));
  const updateDesc = (id, description) => onUpdate(todos.map(t=>t.id===id?{...t,description}:t));

  const pMeta = key => TODO_PRIORITIES.find(p=>p.key===key);

  const TodoItem = ({t}) => {
    const overdue = !t.done && t.dueDate && t.dueDate < today;
    const expanded = expandedId === t.id;
    const [editingDesc, setEditingDesc] = useState(false);
    const [draftDesc, setDraftDesc] = useState(t.description||'');
    const priColor = t.priority ? pMeta(t.priority)?.color : '#E5E1DC';

    return(
      <div style={{background:'white',borderRadius:12,border:'1px solid rgba(0,0,0,0.07)',boxShadow:'0 1px 4px rgba(0,0,0,0.05)',marginBottom:8,transition:'opacity 0.15s, box-shadow 0.15s',opacity:t.done?0.55:1,borderLeft:`3px solid ${priColor}`,overflow:'hidden'}}>
        <div style={{display:'flex',alignItems:'flex-start',gap:12,padding:'12px 16px'}}>
          <button onClick={()=>toggle(t.id)} style={{marginTop:1,flexShrink:0,width:20,height:20,borderRadius:6,border:t.done?'none':'1.5px solid #D4CFC9',background:t.done?'#141210':'white',display:'flex',alignItems:'center',justifyContent:'center',cursor:'pointer',transition:'all 0.15s'}}>
            {t.done&&<svg width="11" height="11" viewBox="0 0 11 11" fill="none"><path d="M2 5.5l2.5 2.5 4.5-4.5" stroke="white" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"/></svg>}
          </button>
          <div style={{flex:1,minWidth:0,cursor:'pointer'}} onClick={()=>setExpandedId(expanded?null:t.id)}>
            <div style={{fontSize:14,fontWeight:500,color:'#141210',lineHeight:1.4,textDecoration:t.done?'line-through':'none'}}>{t.text}</div>
            <div style={{display:'flex',alignItems:'center',gap:8,marginTop:4,flexWrap:'wrap'}}>
              {t.priority&&pMeta(t.priority)&&<span style={{fontSize:11,fontWeight:600,padding:'1px 7px',borderRadius:99,background:pMeta(t.priority).bg,color:pMeta(t.priority).color}}>{pMeta(t.priority).label}</span>}
              {t.dueDate&&<span style={{fontSize:11.5,color:overdue?'#B45309':'#A8A39D',fontWeight:overdue?600:400}}>{overdue?'⚠ ':''}{fmtDate(t.dueDate)}</span>}
              {t.description&&!expanded&&<span style={{fontSize:11.5,color:'#A8A39D',display:'flex',alignItems:'center',gap:4}}><Icons.Doc/>Beschreibung</span>}
            </div>
          </div>
          <button onClick={()=>setExpandedId(expanded?null:t.id)} style={{background:'none',border:'none',color:'#C8C3BD',cursor:'pointer',padding:'2px 6px',lineHeight:1,flexShrink:0,fontSize:12,transition:'transform 0.2s, color 0.15s',transform:expanded?'rotate(180deg)':'rotate(0)'}} onMouseEnter={e=>e.currentTarget.style.color='#6B6560'} onMouseLeave={e=>e.currentTarget.style.color='#C8C3BD'}>▾</button>
          <button onClick={()=>remove(t.id)} style={{background:'none',border:'none',color:'#DDD',cursor:'pointer',fontSize:16,padding:'0 4px',lineHeight:1,flexShrink:0,transition:'color 0.15s'}}
            onMouseEnter={e=>e.currentTarget.style.color='#C0392B'} onMouseLeave={e=>e.currentTarget.style.color='#DDD'}>×</button>
        </div>
        {expanded&&(
          <div style={{padding:'4px 16px 14px 48px',borderTop:'1px solid rgba(0,0,0,0.05)',background:'#FAFAF8'}}>
            <div style={{fontSize:11,fontWeight:600,color:'#A8A39D',textTransform:'uppercase',letterSpacing:'0.06em',marginTop:10,marginBottom:6}}>Beschreibung</div>
            {editingDesc?(
              <div>
                <textarea value={draftDesc} onChange={e=>setDraftDesc(e.target.value)} placeholder="Mehr Details zur Aufgabe…" style={{minHeight:80,fontSize:13}} autoFocus/>
                <div style={{display:'flex',gap:8,marginTop:8}}>
                  <button className="btn btn-primary btn-sm" onClick={()=>{updateDesc(t.id,draftDesc.trim());setEditingDesc(false);}}>Speichern</button>
                  <button className="btn btn-ghost btn-sm" onClick={()=>{setDraftDesc(t.description||'');setEditingDesc(false);}}>Abbrechen</button>
                </div>
              </div>
            ):(
              <div onClick={()=>setEditingDesc(true)} style={{fontSize:13,color:t.description?'#3F3A35':'#B0ABA5',lineHeight:1.5,whiteSpace:'pre-wrap',cursor:'text',padding:'6px 0',fontStyle:t.description?'normal':'italic'}}>{t.description||'Klick zum Hinzufügen einer Beschreibung…'}</div>
            )}
          </div>
        )}
      </div>
    );
  };

  return(
    <div style={{flex:1,overflowY:'auto',padding:28}}>
      {/* Add new todo */}
      <div style={{background:'white',borderRadius:14,padding:20,marginBottom:20,border:'1px solid rgba(0,0,0,0.07)',boxShadow:'0 1px 4px rgba(0,0,0,0.05)'}}>
        <div style={{display:'flex',gap:10,marginBottom:10}}>
          <input value={newText} onChange={e=>setNewText(e.target.value)} placeholder="Neue Aufgabe hinzufügen…"
            onKeyDown={e=>e.key==='Enter'&&addTodo()} style={{flex:1}}/>
          <button className="btn btn-primary" onClick={addTodo} disabled={!newText.trim()}><Icons.Plus/>Hinzufügen</button>
        </div>
        <textarea value={newDesc} onChange={e=>setNewDesc(e.target.value)} placeholder="Beschreibung (optional) — Details, Notizen, Kontext…" style={{marginBottom:10,minHeight:60,fontSize:13}}/>
        <div style={{display:'flex',gap:10,alignItems:'center',flexWrap:'wrap'}}>
          <div style={{fontSize:11.5,fontWeight:600,color:'#A8A39D',textTransform:'uppercase',letterSpacing:'0.06em',marginRight:4}}>Priorität:</div>
          <div style={{display:'flex',gap:6}}>
            {TODO_PRIORITIES.map(p=>{
              const active = newPriority === p.key;
              return(
                <button key={p.key} onClick={()=>setNewPriority(active?'':p.key)} style={{padding:'6px 12px',borderRadius:99,fontSize:12,fontWeight:600,border:`1.5px solid ${active?p.color:'transparent'}`,background:active?p.bg:'#F5F3F0',color:active?p.color:'#6B6560',cursor:'pointer',transition:'all 0.15s'}}>
                  {p.label}
                </button>
              );
            })}
          </div>
          <input type="date" value={newDate} onChange={e=>setNewDate(e.target.value)} style={{flex:1,minWidth:140,padding:'6px 12px',fontSize:12.5,background:'#F5F3F0',border:'1.5px solid transparent'}}/>
        </div>
      </div>

      {/* Priority overview */}
      {open.length > 0 && (
        <div style={{marginBottom:18}}>
          <div style={{fontSize:11,fontWeight:600,color:'#A8A39D',textTransform:'uppercase',letterSpacing:'0.06em',marginBottom:8,padding:'0 4px'}}>Prioritäten</div>
          <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fit,minmax(140px,1fr))',gap:10}}>
            {[
              {key:'hoch',label:'Hoch',count:counts.hoch,color:'#ef4444',bg:'#FEF2F2'},
              {key:'mittel',label:'Mittel',count:counts.mittel,color:'#f59e0b',bg:'#FFFBEB'},
              {key:'niedrig',label:'Niedrig',count:counts.niedrig,color:'#6B6560',bg:'#F5F3F0'},
              {key:'',label:'Alle',count:open.length,color:'#141210',bg:'#FAFAF8'},
            ].map(p=>{
              const active = filterPriority === p.key;
              return(
                <button key={p.key||'all'} onClick={()=>setFilterPriority(active && p.key ? '' : p.key)} style={{textAlign:'left',padding:'12px 14px',borderRadius:11,border:`1.5px solid ${active?p.color:'rgba(0,0,0,0.07)'}`,background:active?p.bg:'white',cursor:'pointer',transition:'all 0.15s',boxShadow:active?'none':'0 1px 4px rgba(0,0,0,0.04)'}}>
                  <div style={{fontSize:11.5,fontWeight:600,color:p.color,letterSpacing:'0.02em',marginBottom:2}}>{p.label}</div>
                  <div style={{fontSize:22,fontWeight:700,color:'#141210',letterSpacing:'-0.02em'}}>{p.count}</div>
                </button>
              );
            })}
          </div>
        </div>
      )}

      {/* Open tasks */}
      {open.length === 0 && done.length === 0 && (
        <div style={{textAlign:'center',padding:'80px 20px',color:'#C8C3BD'}}>
          <div style={{fontSize:44,marginBottom:16,opacity:.5}}>✓</div>
          <div style={{fontSize:16,fontWeight:600,color:'#C0BBB5'}}>Keine Aufgaben — alles erledigt!</div>
        </div>
      )}
      {open.length === 0 && done.length > 0 && (
        <div style={{textAlign:'center',padding:'40px 20px',color:'#C8C3BD'}}>
          <div style={{fontSize:32,marginBottom:12,opacity:.5}}>✓</div>
          <div style={{fontSize:15,fontWeight:600,color:'#C0BBB5'}}>Alle Aufgaben erledigt!</div>
        </div>
      )}
      {filteredOpen.length === 0 && open.length > 0 && filterPriority && (
        <div style={{textAlign:'center',padding:'40px 20px',color:'#C8C3BD',fontSize:14}}>Keine Aufgaben mit dieser Priorität.</div>
      )}
      {filteredOpen.map(t=><TodoItem key={t.id} t={t}/>)}

      {/* Done tasks */}
      {done.length > 0 && (
        <div style={{marginTop:16}}>
          <button onClick={()=>setShowDone(s=>!s)} style={{background:'none',border:'none',cursor:'pointer',display:'flex',alignItems:'center',gap:6,fontSize:12.5,color:'#A8A39D',fontWeight:600,padding:'4px 0',marginBottom:10}}>
            <span style={{transition:'transform 0.2s',display:'inline-block',transform:showDone?'rotate(90deg)':'rotate(0)'}}>&rsaquo;</span>
            Erledigt ({done.length})
          </button>
          {showDone && done.map(t=><TodoItem key={t.id} t={t}/>)}
        </div>
      )}
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════
//  AI EMPLOYEES VIEW
// ══════════════════════════════════════════════════════════════════
const AI_STATUS = [
  {key:'aktiv',label:'Aktiv',color:'#16a34a',bg:'#F0FDF4',dot:'#22c55e'},
  {key:'pausiert',label:'Pausiert',color:'#d97706',bg:'#FFFBEB',dot:'#f59e0b'},
  {key:'inaktiv',label:'Inaktiv',color:'#6B6560',bg:'#F5F3F0',dot:'#A8A39D'},
];

const COMMON_MODELS = ['Claude Opus 4.7','Claude Sonnet 4.6','Claude Haiku 4.5','GPT-4o','GPT-4 Turbo','GPT-3.5','Gemini 2.0 Pro','Gemini 1.5 Flash','Llama 3.1 70B','Mistral Large','Anderes…'];

const AI_AVATARS = ['🤖','🦾','🧠','⚡','🔮','💡','🎯','📊','📝','🔍','💼','🛠️','🎨','📞','📧'];

const CLAUDE_PLANS = ['Pro', 'Max 5x', 'Max 20x', 'Team', 'Enterprise', 'API', 'Anderes…'];
const CLAUDE_AVATARS = ['🤖','🧠','✨','💡','🎯','📊','📝','🔍','💼','🛠️','🎨','📞','📧','🚀','⚡','🦾','🔮','🎭','🌟','💫'];
const TASK_STATUS = [
  {key:'offen',label:'Offen',color:'#6B6560',bg:'#F5F3F0',dot:'#A8A39D'},
  {key:'arbeit',label:'In Arbeit',color:'#0369a1',bg:'#EFF6FF',dot:'#3B82F6'},
  {key:'erledigt',label:'Erledigt',color:'#16a34a',bg:'#F0FDF4',dot:'#22c55e'},
  {key:'blockiert',label:'Blockiert',color:'#dc2626',bg:'#FEF2F2',dot:'#ef4444'},
];
const TASK_PRIORITY = [
  {key:'niedrig',label:'Niedrig',color:'#6B6560',bg:'#F5F3F0'},
  {key:'normal',label:'Normal',color:'#0369a1',bg:'#EFF6FF'},
  {key:'hoch',label:'Hoch',color:'#dc2626',bg:'#FEF2F2'},
];

function fmtRelativeTime(ts){
  const diff = Date.now() - new Date(ts).getTime();
  const m = Math.floor(diff/60000);
  if(m<1) return 'gerade eben';
  if(m<60) return `vor ${m} Min`;
  const h = Math.floor(m/60);
  if(h<24) return `vor ${h} Std`;
  const d = Math.floor(h/24);
  if(d<7) return `vor ${d} ${d===1?'Tag':'Tagen'}`;
  return new Date(ts).toLocaleDateString('de-DE',{day:'2-digit',month:'2-digit',year:'numeric'});
}

function AIEmployeeModal({employee, onSave, onClose, onDelete}){
  const isNew = !employee;
  const [form, setForm] = useState(employee || {
    id: uid(),
    name: '',
    avatar: '🤖',
    model: 'Claude Opus 4.7',
    customModel: '',
    account: '',
    responsibilities: '',
    status: 'aktiv',
    activities: [],
    createdAt: new Date().toISOString(),
  });
  const updField = (k,v) => setForm(f=>({...f,[k]:v}));
  const submit = () => {
    if(!form.name.trim()) return;
    const finalModel = form.model === 'Anderes…' ? form.customModel.trim() : form.model;
    onSave({...form, name:form.name.trim(), model:finalModel || form.model, account:form.account.trim(), responsibilities:form.responsibilities.trim()});
  };

  return(
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-box" onClick={e=>e.stopPropagation()} style={{width:560}}>
        <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',marginBottom:20}}>
          <div>
            <h2 style={{fontSize:18,fontWeight:700,letterSpacing:'-0.01em'}}>{isNew?'Neuen KI Mitarbeiter hinzufügen':'KI Mitarbeiter bearbeiten'}</h2>
            <div style={{fontSize:12,color:'#A8A39D',marginTop:2}}>Verwalte deine KI-Helfer an einem Ort.</div>
          </div>
          <button onClick={onClose} style={{background:'#F5F3F0',border:'none',borderRadius:8,padding:8,color:'#999',lineHeight:0}}><Icons.Close/></button>
        </div>

        <div style={{display:'flex',gap:14,marginBottom:14}}>
          <div style={{flexShrink:0}}>
            <div style={{fontSize:11,fontWeight:600,color:'#A8A39D',textTransform:'uppercase',letterSpacing:'0.06em',marginBottom:6}}>Avatar</div>
            <div style={{display:'grid',gridTemplateColumns:'repeat(5,32px)',gap:4,maxWidth:172}}>
              {AI_AVATARS.map(a=>(
                <button key={a} onClick={()=>updField('avatar',a)} style={{width:32,height:32,borderRadius:8,fontSize:18,border:form.avatar===a?'2px solid #141210':'1.5px solid rgba(0,0,0,0.08)',background:form.avatar===a?'#FAFAF8':'white',cursor:'pointer',transition:'all 0.15s'}}>{a}</button>
              ))}
            </div>
          </div>
          <div style={{flex:1,minWidth:0}}>
            <div style={{marginBottom:12}}>
              <div style={{fontSize:11,fontWeight:600,color:'#A8A39D',textTransform:'uppercase',letterSpacing:'0.06em',marginBottom:6}}>Name</div>
              <input value={form.name} onChange={e=>updField('name',e.target.value)} placeholder="z.B. Bertha, Max, Sales-Bot…" autoFocus/>
            </div>
            <div>
              <div style={{fontSize:11,fontWeight:600,color:'#A8A39D',textTransform:'uppercase',letterSpacing:'0.06em',marginBottom:6}}>Status</div>
              <div style={{display:'flex',gap:6}}>
                {AI_STATUS.map(s=>{
                  const active = form.status === s.key;
                  return(
                    <button key={s.key} onClick={()=>updField('status',s.key)} style={{flex:1,padding:'7px 10px',borderRadius:9,fontSize:12,fontWeight:600,border:`1.5px solid ${active?s.color:'transparent'}`,background:active?s.bg:'#F5F3F0',color:active?s.color:'#6B6560',cursor:'pointer',transition:'all 0.15s'}}>{s.label}</button>
                  );
                })}
              </div>
            </div>
          </div>
        </div>

        <div style={{marginBottom:12}}>
          <div style={{fontSize:11,fontWeight:600,color:'#A8A39D',textTransform:'uppercase',letterSpacing:'0.06em',marginBottom:6}}>Modell</div>
          <select value={form.model} onChange={e=>updField('model',e.target.value)}>
            {COMMON_MODELS.map(m=><option key={m} value={m}>{m}</option>)}
          </select>
          {form.model === 'Anderes…' && (
            <input style={{marginTop:8}} value={form.customModel} onChange={e=>updField('customModel',e.target.value)} placeholder="Modell-Name eingeben…"/>
          )}
        </div>

        <div style={{marginBottom:12}}>
          <div style={{fontSize:11,fontWeight:600,color:'#A8A39D',textTransform:'uppercase',letterSpacing:'0.06em',marginBottom:6}}>Account / Plattform</div>
          <input value={form.account} onChange={e=>updField('account',e.target.value)} placeholder="z.B. webars-main, openai-pro, anthropic-team…"/>
        </div>

        <div style={{marginBottom:18}}>
          <div style={{fontSize:11,fontWeight:600,color:'#A8A39D',textTransform:'uppercase',letterSpacing:'0.06em',marginBottom:6}}>Zuständigkeit</div>
          <textarea value={form.responsibilities} onChange={e=>updField('responsibilities',e.target.value)} placeholder="Wofür ist diese KI zuständig? z.B. Email-Antworten, Lead-Recherche, Content erstellen…" style={{minHeight:70}}/>
        </div>

        <div style={{display:'flex',gap:10,justifyContent:'space-between'}}>
          {!isNew && onDelete ? (
            <button className="btn btn-danger" onClick={()=>{if(confirm('KI Mitarbeiter wirklich löschen?'))onDelete(form.id);}}><Icons.Trash/>Löschen</button>
          ) : <div></div>}
          <div style={{display:'flex',gap:10}}>
            <button className="btn btn-ghost" onClick={onClose}>Abbrechen</button>
            <button className="btn btn-primary" onClick={submit} disabled={!form.name.trim()}>{isNew?'Hinzufügen':'Speichern'}</button>
          </div>
        </div>
      </div>
    </div>
  );
}

function AIEmployeeDetail({employee, onBack, onUpdate, onEdit}){
  const [newActivity, setNewActivity] = useState('');
  const statusMeta = AI_STATUS.find(s=>s.key===employee.status) || AI_STATUS[0];
  const activities = (employee.activities||[]).slice().sort((a,b)=>new Date(b.timestamp)-new Date(a.timestamp));

  const addActivity = () => {
    if(!newActivity.trim()) return;
    const updated = {...employee, activities:[...(employee.activities||[]),{id:uid(),timestamp:new Date().toISOString(),text:newActivity.trim()}]};
    onUpdate(updated);
    setNewActivity('');
  };
  const removeActivity = (aid) => {
    const updated = {...employee, activities:(employee.activities||[]).filter(a=>a.id!==aid)};
    onUpdate(updated);
  };

  // Group activities by date
  const grouped = activities.reduce((acc,a)=>{
    const d = new Date(a.timestamp).toLocaleDateString('de-DE',{weekday:'long',day:'2-digit',month:'long',year:'numeric'});
    if(!acc[d]) acc[d]=[];
    acc[d].push(a);
    return acc;
  },{});

  return(
    <div style={{flex:1,overflowY:'auto',padding:28}}>
      <button onClick={onBack} style={{background:'none',border:'none',color:'#6B6560',fontSize:13,cursor:'pointer',padding:'4px 0',marginBottom:16,display:'flex',alignItems:'center',gap:6,fontWeight:500}}>← Zurück zur Übersicht</button>

      {/* Header card */}
      <div style={{background:'white',borderRadius:14,padding:24,marginBottom:20,border:'1px solid rgba(0,0,0,0.07)',boxShadow:'0 1px 4px rgba(0,0,0,0.05)'}}>
        <div style={{display:'flex',alignItems:'flex-start',gap:18}}>
          <div style={{width:64,height:64,borderRadius:14,background:'#F5F3F0',display:'flex',alignItems:'center',justifyContent:'center',fontSize:32,flexShrink:0}}>{employee.avatar||'🤖'}</div>
          <div style={{flex:1,minWidth:0}}>
            <div style={{display:'flex',alignItems:'center',gap:10,marginBottom:6,flexWrap:'wrap'}}>
              <h1 style={{fontSize:22,fontWeight:800,letterSpacing:'-0.02em'}}>{employee.name}</h1>
              <span style={{display:'inline-flex',alignItems:'center',gap:5,padding:'3px 9px 3px 7px',borderRadius:99,background:statusMeta.bg,fontSize:11.5,fontWeight:600,color:statusMeta.color}}>
                <span style={{width:5,height:5,borderRadius:'50%',background:statusMeta.dot}}></span>{statusMeta.label}
              </span>
            </div>
            <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fit,minmax(180px,1fr))',gap:12,marginTop:14}}>
              <div>
                <div style={{fontSize:10.5,fontWeight:600,color:'#A8A39D',textTransform:'uppercase',letterSpacing:'0.06em',marginBottom:3}}>Modell</div>
                <div style={{fontSize:13,color:'#141210',fontWeight:500}}>{employee.model||'—'}</div>
              </div>
              <div>
                <div style={{fontSize:10.5,fontWeight:600,color:'#A8A39D',textTransform:'uppercase',letterSpacing:'0.06em',marginBottom:3}}>Account</div>
                <div style={{fontSize:13,color:'#141210',fontWeight:500}}>{employee.account||'—'}</div>
              </div>
              <div>
                <div style={{fontSize:10.5,fontWeight:600,color:'#A8A39D',textTransform:'uppercase',letterSpacing:'0.06em',marginBottom:3}}>Aktivitäten</div>
                <div style={{fontSize:13,color:'#141210',fontWeight:500}}>{activities.length}</div>
              </div>
            </div>
            {employee.responsibilities && (
              <div style={{marginTop:16,padding:'12px 14px',background:'#FAFAF8',borderRadius:10,borderLeft:'3px solid #141210'}}>
                <div style={{fontSize:10.5,fontWeight:600,color:'#A8A39D',textTransform:'uppercase',letterSpacing:'0.06em',marginBottom:4}}>Zuständigkeit</div>
                <div style={{fontSize:13.5,color:'#3F3A35',lineHeight:1.5,whiteSpace:'pre-wrap'}}>{employee.responsibilities}</div>
              </div>
            )}
          </div>
          <button className="btn btn-ghost btn-sm" onClick={onEdit}><Icons.Edit/>Bearbeiten</button>
        </div>
      </div>

      {/* Activity log */}
      <div style={{background:'white',borderRadius:14,padding:20,border:'1px solid rgba(0,0,0,0.07)',boxShadow:'0 1px 4px rgba(0,0,0,0.05)'}}>
        <div style={{display:'flex',alignItems:'center',gap:10,marginBottom:14}}>
          <Icons.Activity/>
          <h2 style={{fontSize:14.5,fontWeight:700,letterSpacing:'-0.01em'}}>Aktivitäts-Log</h2>
          <div style={{fontSize:12,color:'#A8A39D',marginLeft:'auto'}}>Was hat {employee.name} gemacht?</div>
        </div>

        <div style={{display:'flex',gap:8,marginBottom:18}}>
          <input value={newActivity} onChange={e=>setNewActivity(e.target.value)} placeholder="Was wurde erledigt? z.B. 10 Leads recherchiert, Newsletter geschrieben…"
            onKeyDown={e=>e.key==='Enter'&&addActivity()} style={{flex:1}}/>
          <button className="btn btn-primary" onClick={addActivity} disabled={!newActivity.trim()}><Icons.Plus/>Eintragen</button>
        </div>

        {activities.length === 0 ? (
          <div style={{textAlign:'center',padding:'40px 20px',color:'#C8C3BD'}}>
            <div style={{fontSize:32,marginBottom:8,opacity:.4}}>📋</div>
            <div style={{fontSize:14,fontWeight:600,color:'#C0BBB5'}}>Noch keine Einträge.</div>
            <div style={{fontSize:12.5,color:'#C0BBB5',marginTop:4}}>Halte fest, woran {employee.name} arbeitet.</div>
          </div>
        ) : (
          <div>
            {Object.entries(grouped).map(([date,items])=>(
              <div key={date} style={{marginBottom:18}}>
                <div style={{fontSize:11,fontWeight:600,color:'#A8A39D',textTransform:'uppercase',letterSpacing:'0.06em',marginBottom:8,paddingLeft:4}}>{date}</div>
                {items.map(a=>(
                  <div key={a.id} style={{display:'flex',gap:12,padding:'10px 14px',borderRadius:10,background:'#FAFAF8',marginBottom:6,alignItems:'flex-start'}}>
                    <div style={{width:6,height:6,borderRadius:'50%',background:'#141210',marginTop:7,flexShrink:0}}></div>
                    <div style={{flex:1,minWidth:0}}>
                      <div style={{fontSize:13.5,color:'#141210',lineHeight:1.45,whiteSpace:'pre-wrap'}}>{a.text}</div>
                      <div style={{fontSize:11.5,color:'#A8A39D',marginTop:3}}>{new Date(a.timestamp).toLocaleTimeString('de-DE',{hour:'2-digit',minute:'2-digit'})} · {fmtRelativeTime(a.timestamp)}</div>
                    </div>
                    <button onClick={()=>removeActivity(a.id)} style={{background:'none',border:'none',color:'#DDD',cursor:'pointer',fontSize:16,padding:'0 4px',lineHeight:1,flexShrink:0,transition:'color 0.15s'}}
                      onMouseEnter={e=>e.currentTarget.style.color='#C0392B'} onMouseLeave={e=>e.currentTarget.style.color='#DDD'}>×</button>
                  </div>
                ))}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function AIEmployeesView({employees, onUpdate, externalNewTrigger, onExternalNewHandled}){
  const [modal, setModal] = useState(null); // null | 'new' | {edit: emp}
  const [selectedId, setSelectedId] = useState(null);

  useEffect(()=>{
    if(externalNewTrigger){
      setSelectedId(null);
      setModal('new');
      onExternalNewHandled && onExternalNewHandled();
    }
  },[externalNewTrigger]);

  const selected = selectedId ? employees.find(e=>e.id===selectedId) : null;

  const saveEmployee = (emp) => {
    const exists = employees.find(e=>e.id===emp.id);
    onUpdate(exists ? employees.map(e=>e.id===emp.id?emp:e) : [...employees, emp]);
    setModal(null);
  };
  const removeEmployee = (id) => {
    onUpdate(employees.filter(e=>e.id!==id));
    setModal(null);
    setSelectedId(null);
  };
  const updateOne = (emp) => {
    onUpdate(employees.map(e=>e.id===emp.id?emp:e));
  };

  if(selected){
    return(<>
      <AIEmployeeDetail employee={selected} onBack={()=>setSelectedId(null)} onUpdate={updateOne} onEdit={()=>setModal({edit:selected})}/>
      {modal && modal.edit && <AIEmployeeModal employee={modal.edit} onSave={emp=>{saveEmployee(emp);}} onClose={()=>setModal(null)} onDelete={removeEmployee}/>}
    </>);
  }

  return(<>
    <div style={{flex:1,overflowY:'auto',padding:28}}>
      {employees.length === 0 ? (
        <div style={{textAlign:'center',padding:'80px 20px',color:'#C8C3BD'}}>
          <div style={{fontSize:48,marginBottom:16,opacity:.6}}>🤖</div>
          <div style={{fontSize:17,fontWeight:700,color:'#3F3A35',marginBottom:6}}>Noch keine KI Mitarbeiter</div>
          <div style={{fontSize:13,color:'#A8A39D',marginBottom:20,maxWidth:380,margin:'0 auto 20px'}}>Behalte den Überblick über alle deine KI-Helfer: welches Modell, welcher Account, wofür sie zuständig sind und was sie erledigt haben.</div>
          <button className="btn btn-primary" onClick={()=>setModal('new')}><Icons.Plus/>Ersten KI Mitarbeiter hinzufügen</button>
        </div>
      ) : (
        <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fill,minmax(280px,1fr))',gap:14}}>
          {employees.map(e=>{
            const statusMeta = AI_STATUS.find(s=>s.key===e.status) || AI_STATUS[0];
            const lastActivity = (e.activities||[]).slice().sort((a,b)=>new Date(b.timestamp)-new Date(a.timestamp))[0];
            return(
              <button key={e.id} onClick={()=>setSelectedId(e.id)} style={{textAlign:'left',background:'white',borderRadius:14,padding:18,border:'1px solid rgba(0,0,0,0.07)',boxShadow:'0 1px 4px rgba(0,0,0,0.05)',cursor:'pointer',transition:'all 0.15s',display:'flex',flexDirection:'column',gap:12}}
                onMouseEnter={ev=>{ev.currentTarget.style.transform='translateY(-2px)';ev.currentTarget.style.boxShadow='0 6px 16px rgba(0,0,0,0.08)';}}
                onMouseLeave={ev=>{ev.currentTarget.style.transform='translateY(0)';ev.currentTarget.style.boxShadow='0 1px 4px rgba(0,0,0,0.05)';}}>
                <div style={{display:'flex',alignItems:'center',gap:12}}>
                  <div style={{width:46,height:46,borderRadius:11,background:'#F5F3F0',display:'flex',alignItems:'center',justifyContent:'center',fontSize:22,flexShrink:0}}>{e.avatar||'🤖'}</div>
                  <div style={{flex:1,minWidth:0}}>
                    <div style={{fontSize:15,fontWeight:700,color:'#141210',letterSpacing:'-0.01em',whiteSpace:'nowrap',overflow:'hidden',textOverflow:'ellipsis'}}>{e.name}</div>
                    <div style={{fontSize:11.5,color:'#6B6560',marginTop:2,whiteSpace:'nowrap',overflow:'hidden',textOverflow:'ellipsis'}}>{e.model||'—'}</div>
                  </div>
                  <span style={{display:'inline-flex',alignItems:'center',gap:4,padding:'2px 7px 2px 6px',borderRadius:99,background:statusMeta.bg,fontSize:10.5,fontWeight:600,color:statusMeta.color,flexShrink:0}}>
                    <span style={{width:4,height:4,borderRadius:'50%',background:statusMeta.dot}}></span>{statusMeta.label}
                  </span>
                </div>
                {e.account && <div style={{fontSize:11.5,color:'#A8A39D',padding:'4px 8px',background:'#FAFAF8',borderRadius:6,fontFamily:'monospace',whiteSpace:'nowrap',overflow:'hidden',textOverflow:'ellipsis'}}>{e.account}</div>}
                {e.responsibilities && (
                  <div style={{fontSize:12.5,color:'#3F3A35',lineHeight:1.45,display:'-webkit-box',WebkitLineClamp:2,WebkitBoxOrient:'vertical',overflow:'hidden'}}>{e.responsibilities}</div>
                )}
                <div style={{borderTop:'1px solid rgba(0,0,0,0.05)',paddingTop:10,marginTop:'auto',display:'flex',alignItems:'center',gap:8,fontSize:11.5,color:'#A8A39D'}}>
                  <Icons.Activity/>
                  {lastActivity ? (
                    <span style={{flex:1,whiteSpace:'nowrap',overflow:'hidden',textOverflow:'ellipsis'}}>Zuletzt {fmtRelativeTime(lastActivity.timestamp)}</span>
                  ) : (
                    <span style={{flex:1,fontStyle:'italic'}}>Noch keine Aktivität</span>
                  )}
                  <span style={{fontWeight:600,color:'#6B6560'}}>{(e.activities||[]).length}</span>
                </div>
              </button>
            );
          })}
        </div>
      )}
    </div>
    {modal === 'new' && <AIEmployeeModal onSave={saveEmployee} onClose={()=>setModal(null)}/>}
    {modal && modal.edit && <AIEmployeeModal employee={modal.edit} onSave={saveEmployee} onClose={()=>setModal(null)} onDelete={removeEmployee}/>}
  </>);
}

// ══════════════════════════════════════════════════════════════════
//  CLAUDE KONTEN (mit Aufgaben-Zuweisung)
// ══════════════════════════════════════════════════════════════════
// ── Claude Usage helpers (5h / 7d / Design limits) ──────────────────────
function claudeFmtCountdown(resetsAt, nowMs){
  if(!resetsAt) return '';
  const t = new Date(resetsAt).getTime();
  if(!isFinite(t)) return '';
  let s = Math.floor((t - nowMs)/1000);
  if(s <= 0) return 'jetzt';
  const d = Math.floor(s/86400); s -= d*86400;
  const h = Math.floor(s/3600);  s -= h*3600;
  const m = Math.floor(s/60);
  if(d > 0) return `${d}d ${h}h`;
  if(h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}
function claudePctColor(p){ if(p==null) return '#A8A39D'; if(p>=90) return '#dc2626'; if(p>=70) return '#d97706'; return '#16a34a'; }
function claudePctBg(p){    if(p==null) return '#F5F3F0'; if(p>=90) return '#FEE2E2'; if(p>=70) return '#FEF3C7'; return '#DCFCE7'; }
// If reset moment has passed, treat utilization as 0 (it auto-resets server-side too)
function claudeEffPct(p, resetsAt, nowMs){
  if(p == null) return null;
  if(resetsAt){
    const t = new Date(resetsAt).getTime();
    if(isFinite(t) && nowMs >= t) return 0;
  }
  return p;
}
function ClaudeUsageBar({code, label, pct, resetsAt, nowMs}){
  const eff = claudeEffPct(pct, resetsAt, nowMs);
  if(eff == null && !resetsAt) return null;
  const color = claudePctColor(eff);
  const bg = claudePctBg(eff);
  const w = eff == null ? 0 : Math.min(100, Math.max(0, eff));
  return(
    <div style={{display:'flex',alignItems:'center',gap:7,fontSize:11}} title={label+(resetsAt?(' · Reset: '+new Date(resetsAt).toLocaleString('de-DE')):'')}>
      <span style={{display:'inline-block',width:11,fontWeight:700,color:'#6B6560',textAlign:'center',fontSize:10}}>{code}</span>
      <div style={{flex:1,height:6,background:bg,borderRadius:99,overflow:'hidden'}}>
        <div style={{width:w+'%',height:'100%',background:color,transition:'width .4s'}}/>
      </div>
      <span style={{minWidth:34,textAlign:'right',color:color,fontWeight:700}}>{eff==null?'—':Math.round(eff)+'%'}</span>
      {resetsAt && <span style={{minWidth:46,textAlign:'right',color:'#A8A39D',fontSize:10}}>{claudeFmtCountdown(resetsAt, nowMs)}</span>}
    </div>
  );
}
function ClaudeUsageBars({usage, compact}){
  const [now, setNow] = useState(Date.now());
  useEffect(()=>{ const t=setInterval(()=>setNow(Date.now()), 30000); return ()=>clearInterval(t); }, []);
  const u = usage || {};
  const hasAny = ['five_hour','seven_day','seven_day_omelette'].some(k => u[k] && (u[k].utilization != null || u[k].resets_at));
  if(!hasAny) return null;
  return(
    <div style={{display:'flex',flexDirection:'column',gap:compact?3:5,marginTop:compact?2:4}}>
      <ClaudeUsageBar code="S" label="Session 5 Stunden" pct={u.five_hour&&u.five_hour.utilization} resetsAt={u.five_hour&&u.five_hour.resets_at} nowMs={now}/>
      <ClaudeUsageBar code="W" label="Woche 7 Tage"      pct={u.seven_day&&u.seven_day.utilization} resetsAt={u.seven_day&&u.seven_day.resets_at} nowMs={now}/>
      <ClaudeUsageBar code="D" label="Claude Design"      pct={u.seven_day_omelette&&u.seven_day_omelette.utilization} resetsAt={u.seven_day_omelette&&u.seven_day_omelette.resets_at} nowMs={now}/>
    </div>
  );
}
// Build bookmarklet JS with the user's webhook secret baked in.
function buildClaudeBookmarklet(secret){
  const origin = (typeof window !== 'undefined' && window.location && window.location.origin) || 'https://crm.webars.at';
  const js = `(async()=>{const S=${JSON.stringify(secret)};const C=${JSON.stringify(origin)}+'/api/claude-usage/inbox?key='+S;try{const b=await fetch('/api/bootstrap',{credentials:'include'}).then(r=>r.json());const em=b&&b.account&&b.account.email_address;const memberships=(b&&b.account&&b.account.memberships)||[];if(!em||!memberships.length)throw new Error('Konto nicht gefunden – bist du auf claude.ai eingeloggt?');let ou=null,u=null;const candidates=[];for(const m of memberships){const id=m&&m.organization&&m.organization.uuid;if(!id)continue;const resp=await fetch('/api/organizations/'+id+'/usage',{credentials:'include'}).then(r=>r.json());if(resp&&!resp.error&&!resp.type&&resp.five_hour!==undefined)candidates.push({id,resp});}const best=candidates.find(c=>c.resp.five_hour?.utilization!=null||c.resp.seven_day?.utilization!=null)||candidates[candidates.length-1];if(!best)throw new Error('Keine Nutzungsdaten gefunden – kein passendes Konto auf claude.ai?');ou=best.id;u=best.resp;const r=await fetch(C,{method:'POST',mode:'cors',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:em,org_uuid:ou,usage:u})});if(!r.ok)throw new Error('CRM antwortete '+r.status);const f=x=>x&&x.utilization!=null?Math.round(x.utilization)+'%':'-';const design=u.seven_day_omelette||u.omelette_promotional||null;alert('✅ WebArs CRM aktualisiert\\n\\nKonto: '+em+'\\nSession (5h): '+f(u.five_hour)+'\\nWoche (7d):  '+f(u.seven_day)+'\\nDesign:       '+f(design));}catch(e){alert('❌ WebArs CRM:\\n\\n'+e.message);}})();`;
  return 'javascript:' + js;
}

function ClaudeUsageSetupModal({onClose}){
  const [secret, setSecret] = useState(null);
  const [err, setErr] = useState('');
  const auth = {Authorization:`Bearer ${window.WEBARS_API_TOKEN}`};
  useEffect(()=>{
    fetch('/api/claude-usage/config', {headers: auth})
      .then(r => r.ok ? r.json() : Promise.reject(new Error('HTTP '+r.status)))
      .then(j => setSecret(j.webhook_secret))
      .catch(e => setErr(e.message));
  }, []);
  const href = secret ? buildClaudeBookmarklet(secret) : '#';
  return(
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-box" onClick={e=>e.stopPropagation()} style={{width:620,maxHeight:'85vh',overflowY:'auto'}}>
        <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',marginBottom:18}}>
          <div>
            <h2 style={{fontSize:18,fontWeight:700,letterSpacing:'-0.01em'}}>🚀 Claude-Limits einrichten</h2>
            <div style={{fontSize:12,color:'#A8A39D',marginTop:2}}>1-Klick-Update direkt von claude.ai ins CRM.</div>
          </div>
          <button onClick={onClose} style={{background:'#F5F3F0',border:'none',borderRadius:8,padding:8,color:'#999',lineHeight:0}}><Icons.Close/></button>
        </div>

        {err && <div style={{padding:12,background:'#FEE2E2',color:'#991B1B',borderRadius:8,marginBottom:12,fontSize:13}}>Fehler: {err}</div>}

        <div style={{background:'#FAFAF8',padding:14,borderRadius:10,marginBottom:14,fontSize:13,lineHeight:1.55,color:'#3F3A35'}}>
          So funktioniert's: Du ziehst den grünen Knopf <b>einmalig</b> in deine Browser-Lesezeichen-Leiste. Danach reicht <b>1 Klick</b> während du auf <code style={{background:'#F5F3F0',padding:'1px 5px',borderRadius:4}}>claude.ai</code> eingeloggt bist — die Werte fliegen automatisch ins richtige Konto (über die E-Mail-Adresse).
        </div>

        <div style={{padding:'18px 16px',background:'white',border:'2px dashed #d4d4d4',borderRadius:10,textAlign:'center',marginBottom:14}}>
          <div style={{fontSize:11,fontWeight:700,color:'#A8A39D',textTransform:'uppercase',letterSpacing:'0.06em',marginBottom:10}}>Schritt 1 — Knopf in Lesezeichen-Leiste ziehen</div>
          {secret ? (
            <a href={href} draggable="true" onClick={e=>e.preventDefault()} style={{display:'inline-block',background:'#16a34a',color:'white',textDecoration:'none',padding:'12px 22px',borderRadius:10,fontWeight:700,fontSize:14,cursor:'grab'}}>📊 Claude → WebArs CRM</a>
          ) : (
            <span style={{color:'#A8A39D',fontSize:13}}>Lade Webhook-Schlüssel…</span>
          )}
          <div style={{fontSize:11,color:'#A8A39D',marginTop:10}}>Maus über den Knopf drücken, festhalten und nach oben in die Lesezeichen-Leiste ziehen (Strg+Umschalt+B blendet sie ein).</div>
        </div>

        <div style={{fontSize:13,lineHeight:1.7,color:'#3F3A35'}}>
          <div style={{fontSize:11,fontWeight:700,color:'#A8A39D',textTransform:'uppercase',letterSpacing:'0.06em',marginBottom:8}}>Schritt 2 — Auf claude.ai benutzen</div>
          <ol style={{paddingLeft:20,margin:0}}>
            <li>Auf <code style={{background:'#F5F3F0',padding:'1px 5px',borderRadius:4}}>claude.ai</code> gehen, bei einem Konto einloggen.</li>
            <li>Oben in der Lesezeichen-Leiste auf <b>„Claude → WebArs CRM"</b> klicken.</li>
            <li>Bestätigung-Popup erscheint → fertig, Werte sind im CRM. Für andere Konten: dort einloggen und Knopf nochmal klicken.</li>
          </ol>
        </div>

        <div style={{background:'#FFF8E1',borderLeft:'4px solid #F5C518',padding:'10px 14px',borderRadius:6,marginTop:14,fontSize:12,color:'#6B5800'}}>
          <b>Wichtig:</b> Bei jedem Claude-Konto im CRM muss die <b>E-Mail-Adresse</b> eingetragen sein (Feld „E-Mail / Account") — sonst kann der Knopf das richtige Konto nicht finden.
        </div>

        <div style={{display:'flex',justifyContent:'flex-end',marginTop:18}}>
          <button className="btn btn-primary" onClick={onClose}>Verstanden</button>
        </div>
      </div>
    </div>
  );
}

function ClaudeAccountModal({account, onSave, onClose, onDelete}){
  const isNew = !account;
  // datetime-local needs local-time "YYYY-MM-DDTHH:MM"
  const _dtToLocal = iso => {
    if(!iso) return '';
    const d = new Date(iso); if(isNaN(d)) return '';
    const p = n => String(n).padStart(2,'0');
    return d.getFullYear()+'-'+p(d.getMonth()+1)+'-'+p(d.getDate())+'T'+p(d.getHours())+':'+p(d.getMinutes());
  };
  const _initUsage = (account && account.usage) || {};
  const _seed = account ? {
    ...account,
    m_session_pct:   (_initUsage.five_hour && _initUsage.five_hour.utilization != null) ? _initUsage.five_hour.utilization : '',
    m_session_reset: _dtToLocal(_initUsage.five_hour && _initUsage.five_hour.resets_at),
    m_weekly_pct:    (_initUsage.seven_day && _initUsage.seven_day.utilization != null) ? _initUsage.seven_day.utilization : '',
    m_weekly_reset:  _dtToLocal(_initUsage.seven_day && _initUsage.seven_day.resets_at),
    m_design_pct:    (_initUsage.seven_day_omelette && _initUsage.seven_day_omelette.utilization != null) ? _initUsage.seven_day_omelette.utilization : '',
    m_design_reset:  _dtToLocal(_initUsage.seven_day_omelette && _initUsage.seven_day_omelette.resets_at),
  } : {
    id: uid(),
    avatar: CLAUDE_AVATARS[0],
    name: '',
    plan: CLAUDE_PLANS[0],
    customPlan: '',
    account: '',
    notes: '',
    status: 'aktiv',
    createdAt: new Date().toISOString(),
    m_session_pct: '', m_session_reset: '',
    m_weekly_pct: '',  m_weekly_reset: '',
    m_design_pct: '',  m_design_reset: '',
  };
  const [form, setForm] = useState(_seed);
  const updField = (k,v) => setForm(f=>({...f,[k]:v}));
  const submit = () => {
    if(!form.name.trim()) return;
    const finalPlan = form.plan === 'Anderes…' ? form.customPlan.trim() : form.plan;
    // Build usage from manual fields (only overwrites limits the user actually touched)
    const mkLimit = (p, r) => {
      const hasP = p !== '' && p != null;
      const hasR = r && String(r).length > 0;
      if(!hasP && !hasR) return null;
      return {
        utilization: hasP ? Number(p) : null,
        resets_at:   hasR ? new Date(r).toISOString() : null,
      };
    };
    const fh = mkLimit(form.m_session_pct, form.m_session_reset);
    const sd = mkLimit(form.m_weekly_pct,  form.m_weekly_reset);
    const so = mkLimit(form.m_design_pct,  form.m_design_reset);
    const prevUsage = (account && account.usage) || {};
    const nextUsage = {
      ...prevUsage,
      five_hour:          fh,
      seven_day:          sd,
      seven_day_omelette: so,
    };
    // Strip the helper m_* fields before saving
    const {m_session_pct, m_session_reset, m_weekly_pct, m_weekly_reset, m_design_pct, m_design_reset, ...rest} = form;
    onSave({
      ...rest,
      name: form.name.trim(),
      plan: finalPlan || form.plan,
      account: form.account.trim(),
      notes: form.notes.trim(),
      usage: nextUsage,
    });
  };

  return(
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-box" onClick={e=>e.stopPropagation()} style={{width:560}}>
        <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',marginBottom:20}}>
          <div>
            <h2 style={{fontSize:18,fontWeight:700,letterSpacing:'-0.01em'}}>{isNew?'Neues Claude Konto':'Claude Konto bearbeiten'}</h2>
            <div style={{fontSize:12,color:'#A8A39D',marginTop:2}}>Verwalte deine Claude-Accounts an einem Ort.</div>
          </div>
          <button onClick={onClose} style={{background:'#F5F3F0',border:'none',borderRadius:8,padding:8,color:'#999',lineHeight:0}}><Icons.Close/></button>
        </div>

        <div style={{display:'flex',gap:14,marginBottom:14}}>
          <div style={{flexShrink:0}}>
            <div style={{fontSize:11,fontWeight:600,color:'#A8A39D',textTransform:'uppercase',letterSpacing:'0.06em',marginBottom:6}}>Avatar</div>
            <div style={{display:'grid',gridTemplateColumns:'repeat(5,32px)',gap:4,maxWidth:172}}>
              {CLAUDE_AVATARS.map(a=>(
                <button key={a} onClick={()=>updField('avatar',a)} style={{width:32,height:32,borderRadius:8,fontSize:18,border:form.avatar===a?'2px solid #141210':'1.5px solid rgba(0,0,0,0.08)',background:form.avatar===a?'#FAFAF8':'white',cursor:'pointer',transition:'all 0.15s'}}>{a}</button>
              ))}
            </div>
          </div>
          <div style={{flex:1,minWidth:0}}>
            <div style={{marginBottom:12}}>
              <div style={{fontSize:11,fontWeight:600,color:'#A8A39D',textTransform:'uppercase',letterSpacing:'0.06em',marginBottom:6}}>Name</div>
              <input value={form.name} onChange={e=>updField('name',e.target.value)} placeholder="z.B. Haupt-Account, Marketing-Claude…" autoFocus/>
            </div>
            <div>
              <div style={{fontSize:11,fontWeight:600,color:'#A8A39D',textTransform:'uppercase',letterSpacing:'0.06em',marginBottom:6}}>Status</div>
              <div style={{display:'flex',gap:6}}>
                {AI_STATUS.map(s=>{
                  const active = form.status === s.key;
                  return(
                    <button key={s.key} onClick={()=>updField('status',s.key)} style={{flex:1,padding:'7px 10px',borderRadius:9,fontSize:12,fontWeight:600,border:`1.5px solid ${active?s.color:'transparent'}`,background:active?s.bg:'#F5F3F0',color:active?s.color:'#6B6560',cursor:'pointer',transition:'all 0.15s'}}>{s.label}</button>
                  );
                })}
              </div>
            </div>
          </div>
        </div>

        <div style={{marginBottom:12}}>
          <div style={{fontSize:11,fontWeight:600,color:'#A8A39D',textTransform:'uppercase',letterSpacing:'0.06em',marginBottom:6}}>Plan</div>
          <select value={form.plan} onChange={e=>updField('plan',e.target.value)}>
            {CLAUDE_PLANS.map(p=><option key={p} value={p}>{p}</option>)}
          </select>
          {form.plan === 'Anderes…' && (
            <input style={{marginTop:8}} value={form.customPlan} onChange={e=>updField('customPlan',e.target.value)} placeholder="Plan-Name eingeben…"/>
          )}
        </div>

        <div style={{marginBottom:12}}>
          <div style={{fontSize:11,fontWeight:600,color:'#A8A39D',textTransform:'uppercase',letterSpacing:'0.06em',marginBottom:6}}>E-Mail / Account</div>
          <input value={form.account} onChange={e=>updField('account',e.target.value)} placeholder="z.B. claude@webars.at"/>
        </div>

        <div style={{marginBottom:14}}>
          <div style={{fontSize:11,fontWeight:600,color:'#A8A39D',textTransform:'uppercase',letterSpacing:'0.06em',marginBottom:6}}>Notizen</div>
          <textarea value={form.notes} onChange={e=>updField('notes',e.target.value)} placeholder="Wofür wird dieser Account genutzt?" style={{minHeight:60}}/>
        </div>

        <div style={{marginBottom:18,padding:14,background:'#FAFAF8',borderRadius:10,border:'1px solid rgba(0,0,0,0.05)'}}>
          <div style={{display:'flex',alignItems:'center',gap:6,marginBottom:4}}>
            <div style={{fontSize:11,fontWeight:600,color:'#A8A39D',textTransform:'uppercase',letterSpacing:'0.06em'}}>Aktuelle Limits (manuell)</div>
          </div>
          <div style={{fontSize:11,color:'#A8A39D',marginBottom:10,lineHeight:1.5}}>Werte von <code style={{background:'#F5F3F0',padding:'1px 5px',borderRadius:4,fontSize:10.5}}>claude.ai</code> hier eintragen. Der 1-Klick-Knopf füllt das auch automatisch (siehe „Limits einrichten").</div>
          {[
            {key:'session', label:'Session-Limit (5 Std.)'},
            {key:'weekly',  label:'Wochen-Limit (7 Tage)'},
            {key:'design',  label:'Claude Design (Woche)'},
          ].map(row => (
            <div key={row.key} style={{display:'grid',gridTemplateColumns:'1fr 80px 1fr',gap:8,alignItems:'center',marginBottom:6}}>
              <div style={{fontSize:12,color:'#6B6560',fontWeight:500}}>{row.label}</div>
              <input
                type="number" min="0" max="200" step="1"
                placeholder="%"
                value={form['m_'+row.key+'_pct']}
                onChange={e=>updField('m_'+row.key+'_pct', e.target.value)}
                style={{padding:'6px 8px',fontSize:12,textAlign:'right'}}
              />
              <input
                type="datetime-local"
                value={form['m_'+row.key+'_reset']}
                onChange={e=>updField('m_'+row.key+'_reset', e.target.value)}
                style={{padding:'6px 8px',fontSize:12}}
                title="Reset-Zeitpunkt"
              />
            </div>
          ))}
          <div style={{fontSize:10.5,color:'#C0BBB5',marginTop:6}}>Leer lassen = Limit nicht anzeigen. Wenn der Reset-Zeitpunkt erreicht ist, springt der Balken automatisch auf 0 %.</div>
        </div>

        <div style={{display:'flex',gap:10,justifyContent:'space-between'}}>
          {!isNew && onDelete ? (
            <button className="btn btn-danger" onClick={()=>{if(confirm('Claude Konto wirklich löschen? Aufgaben bleiben erhalten.'))onDelete(form.id);}}><Icons.Trash/>Löschen</button>
          ) : <div></div>}
          <div style={{display:'flex',gap:10}}>
            <button className="btn btn-ghost" onClick={onClose}>Abbrechen</button>
            <button className="btn btn-primary" onClick={submit} disabled={!form.name.trim()}>{isNew?'Hinzufügen':'Speichern'}</button>
          </div>
        </div>
      </div>
    </div>
  );
}

function ClaudeTaskModal({task, accounts, onSave, onClose, onDelete}){
  const isNew = !task || !task.title;
  const [form, setForm] = useState(task || {
    id: uid(),
    title: '',
    description: '',
    status: 'offen',
    priority: 'normal',
    dueDate: '',
    assignedAccountIds: [],
    createdAt: new Date().toISOString(),
    completedAt: null,
  });
  const updField = (k,v) => setForm(f=>({...f,[k]:v}));
  const toggleAccount = (id) => {
    const ids = form.assignedAccountIds || [];
    if(ids.includes(id)) updField('assignedAccountIds', ids.filter(x=>x!==id));
    else updField('assignedAccountIds', [...ids, id]);
  };
  const submit = () => {
    if(!form.title.trim()) return;
    const wasErledigt = task && task.status === 'erledigt';
    const isErledigt = form.status === 'erledigt';
    const completedAt = isErledigt && !wasErledigt ? new Date().toISOString() : (isErledigt ? form.completedAt : null);
    onSave({...form, title:form.title.trim(), description:(form.description||'').trim(), completedAt});
  };

  return(
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-box" onClick={e=>e.stopPropagation()} style={{width:600}}>
        <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',marginBottom:20}}>
          <div>
            <h2 style={{fontSize:18,fontWeight:700,letterSpacing:'-0.01em'}}>{isNew?'Neue Aufgabe':'Aufgabe bearbeiten'}</h2>
            <div style={{fontSize:12,color:'#A8A39D',marginTop:2}}>Aufgabe einem oder mehreren Claude-Konten zuweisen.</div>
          </div>
          <button onClick={onClose} style={{background:'#F5F3F0',border:'none',borderRadius:8,padding:8,color:'#999',lineHeight:0}}><Icons.Close/></button>
        </div>

        <div style={{marginBottom:12}}>
          <div style={{fontSize:11,fontWeight:600,color:'#A8A39D',textTransform:'uppercase',letterSpacing:'0.06em',marginBottom:6}}>Titel</div>
          <input value={form.title} onChange={e=>updField('title',e.target.value)} placeholder="z.B. Newsletter texten, Lead-Recherche…" autoFocus/>
        </div>

        <div style={{marginBottom:12}}>
          <div style={{fontSize:11,fontWeight:600,color:'#A8A39D',textTransform:'uppercase',letterSpacing:'0.06em',marginBottom:6}}>Beschreibung</div>
          <textarea value={form.description||''} onChange={e=>updField('description',e.target.value)} placeholder="Details zur Aufgabe…" style={{minHeight:70}}/>
        </div>

        <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:12,marginBottom:12}}>
          <div>
            <div style={{fontSize:11,fontWeight:600,color:'#A8A39D',textTransform:'uppercase',letterSpacing:'0.06em',marginBottom:6}}>Status</div>
            <div style={{display:'flex',gap:4,flexWrap:'wrap'}}>
              {TASK_STATUS.map(s=>{
                const active = form.status === s.key;
                return(<button key={s.key} onClick={()=>updField('status',s.key)} style={{padding:'7px 10px',borderRadius:9,fontSize:11.5,fontWeight:600,border:`1.5px solid ${active?s.color:'transparent'}`,background:active?s.bg:'#F5F3F0',color:active?s.color:'#6B6560',cursor:'pointer',transition:'all 0.15s'}}>{s.label}</button>);
              })}
            </div>
          </div>
          <div>
            <div style={{fontSize:11,fontWeight:600,color:'#A8A39D',textTransform:'uppercase',letterSpacing:'0.06em',marginBottom:6}}>Priorität</div>
            <div style={{display:'flex',gap:4}}>
              {TASK_PRIORITY.map(p=>{
                const active = form.priority === p.key;
                return(<button key={p.key} onClick={()=>updField('priority',p.key)} style={{flex:1,padding:'7px 10px',borderRadius:9,fontSize:11.5,fontWeight:600,border:`1.5px solid ${active?p.color:'transparent'}`,background:active?p.bg:'#F5F3F0',color:active?p.color:'#6B6560',cursor:'pointer',transition:'all 0.15s'}}>{p.label}</button>);
              })}
            </div>
          </div>
        </div>

        <div style={{marginBottom:14}}>
          <div style={{fontSize:11,fontWeight:600,color:'#A8A39D',textTransform:'uppercase',letterSpacing:'0.06em',marginBottom:6}}>Fällig am (optional)</div>
          <input type="date" value={form.dueDate||''} onChange={e=>updField('dueDate',e.target.value)}/>
        </div>

        <div style={{marginBottom:18}}>
          <div style={{fontSize:11,fontWeight:600,color:'#A8A39D',textTransform:'uppercase',letterSpacing:'0.06em',marginBottom:6}}>Zugewiesene Konten ({(form.assignedAccountIds||[]).length})</div>
          {accounts.length === 0 ? (
            <div style={{padding:14,background:'#FAFAF8',borderRadius:10,fontSize:12.5,color:'#A8A39D'}}>Noch keine Claude-Konten vorhanden. Lege erst ein Konto an.</div>
          ) : (
            <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fill,minmax(180px,1fr))',gap:6,maxHeight:200,overflowY:'auto',padding:6,background:'#FAFAF8',borderRadius:10}}>
              {accounts.map(a=>{
                const checked = (form.assignedAccountIds||[]).includes(a.id);
                return(
                  <button key={a.id} onClick={()=>toggleAccount(a.id)} style={{display:'flex',alignItems:'center',gap:8,padding:'8px 10px',borderRadius:8,border:checked?'1.5px solid #141210':'1.5px solid transparent',background:checked?'white':'transparent',cursor:'pointer',textAlign:'left',transition:'all 0.15s'}}>
                    <div style={{width:26,height:26,borderRadius:6,background:'#F5F3F0',display:'flex',alignItems:'center',justifyContent:'center',fontSize:14,flexShrink:0}}>{a.avatar||'🤖'}</div>
                    <div style={{flex:1,minWidth:0}}>
                      <div style={{fontSize:12.5,fontWeight:600,color:'#141210',whiteSpace:'nowrap',overflow:'hidden',textOverflow:'ellipsis'}}>{a.name}</div>
                      <div style={{fontSize:10.5,color:'#A8A39D',whiteSpace:'nowrap',overflow:'hidden',textOverflow:'ellipsis'}}>{a.plan}</div>
                    </div>
                    {checked && <span style={{color:'#141210',fontSize:14,fontWeight:700}}>✓</span>}
                  </button>
                );
              })}
            </div>
          )}
        </div>

        <div style={{display:'flex',gap:10,justifyContent:'space-between'}}>
          {!isNew && onDelete ? (
            <button className="btn btn-danger" onClick={()=>{if(confirm('Aufgabe wirklich löschen?'))onDelete(form.id);}}><Icons.Trash/>Löschen</button>
          ) : <div></div>}
          <div style={{display:'flex',gap:10}}>
            <button className="btn btn-ghost" onClick={onClose}>Abbrechen</button>
            <button className="btn btn-primary" onClick={submit} disabled={!form.title.trim()}>{isNew?'Erstellen':'Speichern'}</button>
          </div>
        </div>
      </div>
    </div>
  );
}

function ClaudeAccountDetail({account, tasks, accounts, onBack, onUpdateTasks, onEdit}){
  const [taskModal, setTaskModal] = useState(null);
  const statusMeta = AI_STATUS.find(s=>s.key===account.status) || AI_STATUS[0];

  const accountTasks = tasks.filter(t => (t.assignedAccountIds||[]).includes(account.id));
  const groupedByStatus = TASK_STATUS.map(s => ({
    ...s,
    tasks: accountTasks.filter(t => t.status === s.key)
  }));

  const saveTask = (task) => {
    const exists = tasks.find(t=>t.id===task.id);
    onUpdateTasks(exists ? tasks.map(t=>t.id===task.id?task:t) : [...tasks, task]);
    setTaskModal(null);
  };
  const deleteTask = (id) => {
    onUpdateTasks(tasks.filter(t=>t.id!==id));
    setTaskModal(null);
  };

  return(
    <div style={{flex:1,overflowY:'auto',padding:28}}>
      <button onClick={onBack} style={{background:'none',border:'none',color:'#6B6560',fontSize:13,cursor:'pointer',padding:'4px 0',marginBottom:16,display:'flex',alignItems:'center',gap:6,fontWeight:500}}>← Zurück zur Übersicht</button>

      <div style={{background:'white',borderRadius:14,padding:24,marginBottom:20,border:'1px solid rgba(0,0,0,0.07)',boxShadow:'0 1px 4px rgba(0,0,0,0.05)'}}>
        <div style={{display:'flex',alignItems:'flex-start',gap:18}}>
          <div style={{width:64,height:64,borderRadius:14,background:'#F5F3F0',display:'flex',alignItems:'center',justifyContent:'center',fontSize:32,flexShrink:0}}>{account.avatar||'🤖'}</div>
          <div style={{flex:1,minWidth:0}}>
            <div style={{display:'flex',alignItems:'center',gap:10,marginBottom:6,flexWrap:'wrap'}}>
              <h1 style={{fontSize:22,fontWeight:800,letterSpacing:'-0.02em'}}>{account.name}</h1>
              <span style={{display:'inline-flex',alignItems:'center',gap:5,padding:'3px 9px 3px 7px',borderRadius:99,background:statusMeta.bg,fontSize:11.5,fontWeight:600,color:statusMeta.color}}>
                <span style={{width:5,height:5,borderRadius:'50%',background:statusMeta.dot}}></span>{statusMeta.label}
              </span>
            </div>
            <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fit,minmax(180px,1fr))',gap:12,marginTop:14}}>
              <div>
                <div style={{fontSize:10.5,fontWeight:600,color:'#A8A39D',textTransform:'uppercase',letterSpacing:'0.06em',marginBottom:3}}>Plan</div>
                <div style={{fontSize:13,color:'#141210',fontWeight:500}}>{account.plan||'—'}</div>
              </div>
              <div>
                <div style={{fontSize:10.5,fontWeight:600,color:'#A8A39D',textTransform:'uppercase',letterSpacing:'0.06em',marginBottom:3}}>Account</div>
                <div style={{fontSize:13,color:'#141210',fontWeight:500}}>{account.account||'—'}</div>
              </div>
              <div>
                <div style={{fontSize:10.5,fontWeight:600,color:'#A8A39D',textTransform:'uppercase',letterSpacing:'0.06em',marginBottom:3}}>Aufgaben</div>
                <div style={{fontSize:13,color:'#141210',fontWeight:500}}>{accountTasks.length} ({accountTasks.filter(t=>t.status!=='erledigt').length} offen)</div>
              </div>
            </div>
            {account.notes && (
              <div style={{marginTop:16,padding:'12px 14px',background:'#FAFAF8',borderRadius:10,borderLeft:'3px solid #141210'}}>
                <div style={{fontSize:10.5,fontWeight:600,color:'#A8A39D',textTransform:'uppercase',letterSpacing:'0.06em',marginBottom:4}}>Notizen</div>
                <div style={{fontSize:13.5,color:'#3F3A35',lineHeight:1.5,whiteSpace:'pre-wrap'}}>{account.notes}</div>
              </div>
            )}
            {(account.usage && (['five_hour','seven_day','seven_day_omelette'].some(k => account.usage[k] && (account.usage[k].utilization != null || account.usage[k].resets_at)))) && (
              <div style={{marginTop:16,padding:'14px 16px',background:'#FAFAF8',borderRadius:10,border:'1px solid rgba(0,0,0,0.05)'}}>
                <div style={{display:'flex',alignItems:'center',gap:8,marginBottom:10}}>
                  <div style={{fontSize:10.5,fontWeight:600,color:'#A8A39D',textTransform:'uppercase',letterSpacing:'0.06em'}}>Nutzungs-Limits</div>
                  {account.usage.last_synced && <span style={{fontSize:10.5,color:'#A8A39D'}}>· zuletzt synchronisiert: {new Date(account.usage.last_synced).toLocaleString('de-DE')}</span>}
                  <button onClick={()=>{window.open('https://claude.ai','_blank','noopener');setTimeout(()=>{alert('Auf claude.ai eingeloggt sein → in der Lesezeichen-Leiste auf „Claude → WebArs CRM" klicken.');},120);}} style={{marginLeft:'auto',fontSize:11,color:'#16a34a',cursor:'pointer',fontWeight:600,padding:'3px 9px',borderRadius:6,background:'#DCFCE7',border:'1px solid #86efac'}}>↻ Aktualisieren</button>
                </div>
                <ClaudeUsageBars usage={account.usage}/>
              </div>
            )}
          </div>
          <button className="btn btn-ghost btn-sm" onClick={onEdit}><Icons.Edit/>Bearbeiten</button>
        </div>
      </div>

      <div style={{background:'white',borderRadius:14,padding:20,border:'1px solid rgba(0,0,0,0.07)',boxShadow:'0 1px 4px rgba(0,0,0,0.05)'}}>
        <div style={{display:'flex',alignItems:'center',gap:10,marginBottom:14}}>
          <Icons.Check/>
          <h2 style={{fontSize:14.5,fontWeight:700,letterSpacing:'-0.01em'}}>Aufgaben Dashboard</h2>
          <button className="btn btn-primary btn-sm" style={{marginLeft:'auto'}} onClick={()=>setTaskModal({mode:'new',prefilledAccountIds:[account.id]})}><Icons.Plus/>Neue Aufgabe</button>
        </div>

        {accountTasks.length === 0 ? (
          <div style={{textAlign:'center',padding:'40px 20px',color:'#C8C3BD'}}>
            <div style={{fontSize:32,marginBottom:8,opacity:.4}}>📋</div>
            <div style={{fontSize:14,fontWeight:600,color:'#C0BBB5'}}>Keine Aufgaben zugewiesen.</div>
            <div style={{fontSize:12.5,color:'#C0BBB5',marginTop:4}}>Erstelle eine Aufgabe und weise sie diesem Konto zu.</div>
          </div>
        ) : (
          <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fill,minmax(240px,1fr))',gap:12}}>
            {groupedByStatus.filter(g=>g.tasks.length>0).map(g => (
              <div key={g.key} style={{background:'#FAFAF8',borderRadius:10,padding:12}}>
                <div style={{display:'flex',alignItems:'center',gap:6,marginBottom:8}}>
                  <span style={{width:6,height:6,borderRadius:'50%',background:g.dot}}></span>
                  <span style={{fontSize:11,fontWeight:700,color:g.color,textTransform:'uppercase',letterSpacing:'0.06em'}}>{g.label}</span>
                  <span style={{fontSize:11,color:'#A8A39D',marginLeft:'auto'}}>{g.tasks.length}</span>
                </div>
                {g.tasks.map(t => {
                  const prio = TASK_PRIORITY.find(p=>p.key===t.priority) || TASK_PRIORITY[1];
                  return(
                    <button key={t.id} onClick={()=>setTaskModal({mode:'edit',task:t})} style={{display:'block',width:'100%',textAlign:'left',background:'white',border:'1px solid rgba(0,0,0,0.05)',borderRadius:8,padding:10,marginBottom:6,cursor:'pointer',transition:'all 0.15s'}}
                      onMouseEnter={e=>e.currentTarget.style.borderColor='rgba(0,0,0,0.15)'} onMouseLeave={e=>e.currentTarget.style.borderColor='rgba(0,0,0,0.05)'}>
                      <div style={{fontSize:13,fontWeight:600,color:'#141210',marginBottom:4}}>{t.title}</div>
                      <div style={{display:'flex',gap:6,alignItems:'center',flexWrap:'wrap'}}>
                        {t.priority !== 'normal' && <span style={{fontSize:10,padding:'1px 6px',borderRadius:99,background:prio.bg,color:prio.color,fontWeight:600}}>{prio.label}</span>}
                        {t.dueDate && <span style={{fontSize:10.5,color:'#A8A39D'}}>📅 {new Date(t.dueDate).toLocaleDateString('de-DE')}</span>}
                      </div>
                    </button>
                  );
                })}
              </div>
            ))}
          </div>
        )}
      </div>

      {taskModal && taskModal.mode==='new' && (
        <ClaudeTaskModal task={{
          id: uid(), title: '', description: '', status: 'offen', priority: 'normal',
          dueDate: '', assignedAccountIds: taskModal.prefilledAccountIds || [],
          createdAt: new Date().toISOString(), completedAt: null,
        }} accounts={accounts} onSave={saveTask} onClose={()=>setTaskModal(null)}/>
      )}
      {taskModal && taskModal.mode==='edit' && (
        <ClaudeTaskModal task={taskModal.task} accounts={accounts} onSave={saveTask} onClose={()=>setTaskModal(null)} onDelete={deleteTask}/>
      )}
    </div>
  );
}

function ClaudeAccountsView({accounts, tasks, onUpdateAccounts, onUpdateTasks, externalNewTrigger, onExternalNewHandled, externalNewTaskTrigger, onExternalNewTaskHandled}){
  const [tab, setTab] = useState('konten');
  const [accountModal, setAccountModal] = useState(null);
  const [taskModal, setTaskModal] = useState(null);
  const [selectedId, setSelectedId] = useState(null);
  const [usageSetupOpen, setUsageSetupOpen] = useState(false);

  // ── Claude-Usage polling: server stores plaintext from bookmarklet,
  // we merge into encrypted state by email match (case-insensitive).
  const accountsRef = useRef(accounts);
  useEffect(()=>{ accountsRef.current = accounts; }, [accounts]);
  useEffect(()=>{
    const auth = {Authorization:`Bearer ${window.WEBARS_API_TOKEN}`};
    const poll = async () => {
      try{
        const r = await fetch('/api/claude-usage', {headers: auth});
        if(!r.ok) return;
        const j = await r.json();
        const map = {};
        for(const e of (j.entries||[])){ if(e.email) map[e.email.toLowerCase()] = e; }
        const accs = accountsRef.current || [];
        let changed = false;
        const next = accs.map(a => {
          const em = (a.account||'').trim().toLowerCase();
          if(!em || !map[em]) return a;
          const fresh = map[em];
          const newUsage = {
            five_hour:          fresh.five_hour,
            seven_day:          fresh.seven_day,
            seven_day_omelette: fresh.seven_day_omelette,
            seven_day_opus:     fresh.seven_day_opus,
            last_synced:        fresh.updated_at,
          };
          if(JSON.stringify(a.usage||null) === JSON.stringify(newUsage)) return a;
          changed = true;
          return {...a, usage: newUsage};
        });
        if(changed) onUpdateAccounts(next);
      }catch(e){/* network blip — silent */}
    };
    poll();
    const t = setInterval(poll, 60000);
    return ()=>clearInterval(t);
  }, []);

  useEffect(()=>{
    if(externalNewTrigger){
      setSelectedId(null);
      setTab('konten');
      setAccountModal('new');
      onExternalNewHandled && onExternalNewHandled();
    }
  },[externalNewTrigger]);

  useEffect(()=>{
    if(externalNewTaskTrigger){
      setSelectedId(null);
      setTab('aufgaben');
      setTaskModal({mode:'new'});
      onExternalNewTaskHandled && onExternalNewTaskHandled();
    }
  },[externalNewTaskTrigger]);

  const selected = selectedId ? accounts.find(a=>a.id===selectedId) : null;

  const saveAccount = (acc) => {
    const exists = accounts.find(a=>a.id===acc.id);
    onUpdateAccounts(exists ? accounts.map(a=>a.id===acc.id?acc:a) : [...accounts, acc]);
    setAccountModal(null);
  };
  const removeAccount = (id) => {
    onUpdateAccounts(accounts.filter(a=>a.id!==id));
    onUpdateTasks(tasks.map(t => ({...t, assignedAccountIds: (t.assignedAccountIds||[]).filter(x=>x!==id)})));
    setAccountModal(null);
    setSelectedId(null);
  };

  const saveTask = (task) => {
    const exists = tasks.find(t=>t.id===task.id);
    onUpdateTasks(exists ? tasks.map(t=>t.id===task.id?task:t) : [...tasks, task]);
    setTaskModal(null);
  };
  const deleteTask = (id) => {
    onUpdateTasks(tasks.filter(t=>t.id!==id));
    setTaskModal(null);
  };

  if(selected){
    return(<>
      <ClaudeAccountDetail
        account={selected}
        tasks={tasks}
        accounts={accounts}
        onBack={()=>setSelectedId(null)}
        onUpdateTasks={onUpdateTasks}
        onEdit={()=>setAccountModal({edit:selected})}
      />
      {accountModal && accountModal.edit && <ClaudeAccountModal account={accountModal.edit} onSave={(acc)=>{saveAccount(acc);}} onClose={()=>setAccountModal(null)} onDelete={removeAccount}/>}
    </>);
  }

  return(<>
    <div style={{flex:1,overflowY:'auto',padding:28}}>
      <div style={{display:'flex',alignItems:'center',gap:10,marginBottom:20}}>
        <div style={{display:'flex',gap:6,padding:4,background:'#F5F3F0',borderRadius:10,width:'fit-content'}}>
          {[{key:'konten',label:`Konten (${accounts.length})`},{key:'aufgaben',label:`Aufgaben (${tasks.length})`}].map(t=>(
            <button key={t.key} onClick={()=>setTab(t.key)} style={{padding:'7px 14px',borderRadius:7,border:'none',background:tab===t.key?'white':'transparent',color:tab===t.key?'#141210':'#6B6560',fontWeight:600,fontSize:13,cursor:'pointer',transition:'all 0.15s',boxShadow:tab===t.key?'0 1px 3px rgba(0,0,0,0.06)':'none'}}>{t.label}</button>
          ))}
        </div>
        {tab==='konten' && <button className="btn btn-ghost btn-sm" onClick={()=>setUsageSetupOpen(true)} style={{marginLeft:'auto'}}>🚀 Limits einrichten</button>}
      </div>

      {tab === 'konten' && (
        accounts.length === 0 ? (
          <div style={{textAlign:'center',padding:'80px 20px',color:'#C8C3BD'}}>
            <div style={{fontSize:48,marginBottom:16,opacity:.6}}>✨</div>
            <div style={{fontSize:17,fontWeight:700,color:'#3F3A35',marginBottom:6}}>Noch keine Claude Konten</div>
            <div style={{fontSize:13,color:'#A8A39D',marginBottom:20,maxWidth:380,margin:'0 auto 20px'}}>Lege deine Claude-Accounts an und weise ihnen Aufgaben zu.</div>
            <button className="btn btn-primary" onClick={()=>setAccountModal('new')}><Icons.Plus/>Erstes Konto hinzufügen</button>
          </div>
        ) : (
          <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fill,minmax(280px,1fr))',gap:14}}>
            {accounts.map(a=>{
              const statusMeta = AI_STATUS.find(s=>s.key===a.status) || AI_STATUS[0];
              const accTasks = tasks.filter(t=>(t.assignedAccountIds||[]).includes(a.id));
              const openCount = accTasks.filter(t=>t.status!=='erledigt').length;
              return(
                <button key={a.id} onClick={()=>setSelectedId(a.id)} style={{textAlign:'left',background:'white',borderRadius:14,padding:18,border:'1px solid rgba(0,0,0,0.07)',boxShadow:'0 1px 4px rgba(0,0,0,0.05)',cursor:'pointer',transition:'all 0.15s',display:'flex',flexDirection:'column',gap:12}}
                  onMouseEnter={ev=>{ev.currentTarget.style.transform='translateY(-2px)';ev.currentTarget.style.boxShadow='0 6px 16px rgba(0,0,0,0.08)';}}
                  onMouseLeave={ev=>{ev.currentTarget.style.transform='translateY(0)';ev.currentTarget.style.boxShadow='0 1px 4px rgba(0,0,0,0.05)';}}>
                  <div style={{display:'flex',alignItems:'center',gap:12}}>
                    <div style={{width:46,height:46,borderRadius:11,background:'#F5F3F0',display:'flex',alignItems:'center',justifyContent:'center',fontSize:22,flexShrink:0}}>{a.avatar||'🤖'}</div>
                    <div style={{flex:1,minWidth:0}}>
                      <div style={{fontSize:15,fontWeight:700,color:'#141210',letterSpacing:'-0.01em',whiteSpace:'nowrap',overflow:'hidden',textOverflow:'ellipsis'}}>{a.name}</div>
                      <div style={{fontSize:11.5,color:'#6B6560',marginTop:2,whiteSpace:'nowrap',overflow:'hidden',textOverflow:'ellipsis'}}>{a.plan||'—'}</div>
                    </div>
                    <span style={{display:'inline-flex',alignItems:'center',gap:4,padding:'2px 7px 2px 6px',borderRadius:99,background:statusMeta.bg,fontSize:10.5,fontWeight:600,color:statusMeta.color,flexShrink:0}}>
                      <span style={{width:4,height:4,borderRadius:'50%',background:statusMeta.dot}}></span>{statusMeta.label}
                    </span>
                  </div>
                  {a.account && <div style={{fontSize:11.5,color:'#A8A39D',padding:'4px 8px',background:'#FAFAF8',borderRadius:6,fontFamily:'monospace',whiteSpace:'nowrap',overflow:'hidden',textOverflow:'ellipsis'}}>{a.account}</div>}
                  <ClaudeUsageBars usage={a.usage} compact={true}/>
                  <div style={{display:'flex',gap:8,fontSize:11.5,color:'#6B6560',paddingTop:8,borderTop:'1px solid rgba(0,0,0,0.05)',marginTop:'auto',alignItems:'center'}}>
                    <span><strong style={{color:'#141210'}}>{accTasks.length}</strong> Aufgaben</span>
                    {openCount>0 && <span>· <strong style={{color:'#0369a1'}}>{openCount}</strong> offen</span>}
                    <span title="Auf claude.ai aktualisieren" onClick={ev=>{ev.preventDefault();ev.stopPropagation();window.open('https://claude.ai','_blank','noopener');setTimeout(()=>{alert('Auf claude.ai eingeloggt sein → in der Lesezeichen-Leiste auf „Claude → WebArs CRM" klicken.\n\n(Falls noch nicht eingerichtet: „Limits einrichten"-Knopf oben.)');},120);}} style={{marginLeft:'auto',fontSize:10.5,color:'#16a34a',cursor:'pointer',fontWeight:600,padding:'2px 6px',borderRadius:5}}>↻ aktualisieren</span>
                  </div>
                </button>
              );
            })}
          </div>
        )
      )}

      {tab === 'aufgaben' && (
        tasks.length === 0 ? (
          <div style={{textAlign:'center',padding:'80px 20px',color:'#C8C3BD'}}>
            <div style={{fontSize:48,marginBottom:16,opacity:.6}}>📋</div>
            <div style={{fontSize:17,fontWeight:700,color:'#3F3A35',marginBottom:6}}>Noch keine Aufgaben</div>
            <div style={{fontSize:13,color:'#A8A39D',marginBottom:20,maxWidth:380,margin:'0 auto 20px'}}>Erstelle Aufgaben und weise sie deinen Claude-Konten zu.</div>
            <button className="btn btn-primary" onClick={()=>setTaskModal({mode:'new'})} disabled={accounts.length===0}><Icons.Plus/>Erste Aufgabe</button>
            {accounts.length===0 && <div style={{fontSize:11.5,color:'#A8A39D',marginTop:8}}>Lege zuerst ein Claude-Konto an.</div>}
          </div>
        ) : (
          <div style={{display:'flex',flexDirection:'column',gap:8}}>
            {[...tasks].sort((a,b)=>{
              if(a.status==='erledigt' && b.status!=='erledigt') return 1;
              if(b.status==='erledigt' && a.status!=='erledigt') return -1;
              const prioOrder = {hoch:0, normal:1, niedrig:2};
              const ap = prioOrder[a.priority]||1, bp = prioOrder[b.priority]||1;
              if(ap !== bp) return ap - bp;
              return new Date(b.createdAt) - new Date(a.createdAt);
            }).map(t=>{
              const status = TASK_STATUS.find(s=>s.key===t.status) || TASK_STATUS[0];
              const prio = TASK_PRIORITY.find(p=>p.key===t.priority) || TASK_PRIORITY[1];
              const assigned = (t.assignedAccountIds||[]).map(id=>accounts.find(a=>a.id===id)).filter(Boolean);
              const overdue = t.dueDate && t.status!=='erledigt' && t.dueDate < new Date().toISOString().slice(0,10);
              return(
                <button key={t.id} onClick={()=>setTaskModal({mode:'edit',task:t})} style={{display:'flex',alignItems:'center',gap:14,padding:'14px 18px',background:'white',borderRadius:12,border:'1px solid rgba(0,0,0,0.07)',cursor:'pointer',textAlign:'left',transition:'all 0.15s',opacity:t.status==='erledigt'?0.6:1}}
                  onMouseEnter={e=>e.currentTarget.style.boxShadow='0 4px 12px rgba(0,0,0,0.06)'} onMouseLeave={e=>e.currentTarget.style.boxShadow='none'}>
                  <span style={{display:'inline-flex',alignItems:'center',gap:5,padding:'3px 9px 3px 7px',borderRadius:99,background:status.bg,fontSize:11,fontWeight:600,color:status.color,flexShrink:0}}>
                    <span style={{width:5,height:5,borderRadius:'50%',background:status.dot}}></span>{status.label}
                  </span>
                  <div style={{flex:1,minWidth:0}}>
                    <div style={{fontSize:14,fontWeight:600,color:'#141210',textDecoration:t.status==='erledigt'?'line-through':'none'}}>{t.title}</div>
                    <div style={{display:'flex',gap:10,fontSize:11.5,color:'#A8A39D',marginTop:4,alignItems:'center',flexWrap:'wrap'}}>
                      {t.priority !== 'normal' && <span style={{padding:'1px 7px',borderRadius:99,background:prio.bg,color:prio.color,fontWeight:600}}>{prio.label}</span>}
                      {t.dueDate && <span style={{color:overdue?'#dc2626':'#A8A39D',fontWeight:overdue?600:400}}>📅 {new Date(t.dueDate).toLocaleDateString('de-DE')}</span>}
                      {t.description && <span style={{whiteSpace:'nowrap',overflow:'hidden',textOverflow:'ellipsis',maxWidth:240}}>{t.description}</span>}
                    </div>
                  </div>
                  <div style={{display:'flex',flexShrink:0,alignItems:'center'}}>
                    {assigned.slice(0,4).map((a,i)=>(
                      <div key={a.id} title={a.name} style={{width:30,height:30,borderRadius:8,background:'#F5F3F0',display:'flex',alignItems:'center',justifyContent:'center',fontSize:14,border:'2px solid white',marginLeft:i===0?0:-8}}>{a.avatar||'🤖'}</div>
                    ))}
                    {assigned.length > 4 && <div style={{width:30,height:30,borderRadius:8,background:'#141210',color:'white',display:'flex',alignItems:'center',justifyContent:'center',fontSize:11,fontWeight:700,border:'2px solid white',marginLeft:-8}}>+{assigned.length-4}</div>}
                    {assigned.length === 0 && <span style={{fontSize:11,color:'#C0BBB5',fontStyle:'italic'}}>nicht zugewiesen</span>}
                  </div>
                </button>
              );
            })}
          </div>
        )
      )}
    </div>

    {accountModal === 'new' && <ClaudeAccountModal onSave={saveAccount} onClose={()=>setAccountModal(null)}/>}
    {accountModal && accountModal.edit && <ClaudeAccountModal account={accountModal.edit} onSave={saveAccount} onClose={()=>setAccountModal(null)} onDelete={removeAccount}/>}
    {usageSetupOpen && <ClaudeUsageSetupModal onClose={()=>setUsageSetupOpen(false)}/>}
    {taskModal && taskModal.mode==='new' && (
      <ClaudeTaskModal task={{
        id: uid(), title: '', description: '', status: 'offen', priority: 'normal',
        dueDate: '', assignedAccountIds: [], createdAt: new Date().toISOString(), completedAt: null,
      }} accounts={accounts} onSave={saveTask} onClose={()=>setTaskModal(null)}/>
    )}
    {taskModal && taskModal.mode==='edit' && <ClaudeTaskModal task={taskModal.task} accounts={accounts} onSave={saveTask} onClose={()=>setTaskModal(null)} onDelete={deleteTask}/>}
  </>);
}

// ══════════════════════════════════════════════════════════════════
//  QUOTES (Angebote)
// ══════════════════════════════════════════════════════════════════
const QUOTE_STATUSES = [
  {key:'entwurf',label:'Entwurf',color:'#6B6560',bg:'#F5F3F0',dot:'#A8A39D'},
  {key:'gesendet',label:'Gesendet',color:'#1d4ed8',bg:'#EFF6FF',dot:'#3b82f6'},
  {key:'akzeptiert',label:'Akzeptiert',color:'#16a34a',bg:'#F0FDF4',dot:'#22c55e'},
  {key:'abgelehnt',label:'Abgelehnt',color:'#C0392B',bg:'#FEF2F2',dot:'#ef4444'},
];

function fmtMoney(amount, currency='EUR') {
  const n = Number(amount) || 0;
  return new Intl.NumberFormat('de-DE',{style:'currency',currency,minimumFractionDigits:2}).format(n);
}

function nextQuoteNumber(settings) {
  const year = new Date().getFullYear();
  const num = String(settings.quoteCounter || 1).padStart(3,'0');
  return `${settings.quotePrefix || 'AN'}-${year}-${num}`;
}

function blankQuote(contact, settings) {
  return {
    id: uid(),
    number: nextQuoteNumber(settings),
    contactId: contact?.id || null,
    contactSnapshot: contact ? {
      firma: contact.firma || '',
      ansprechpartner: contact.ansprechpartner || '',
      email: contact.email || '',
      telefon: contact.telefon || '',
      adresse: contact.adresse || ''
    } : {firma:'',ansprechpartner:'',email:'',telefon:'',adresse:''},
    title: '',
    date: new Date().toISOString().slice(0,10),
    validUntil: new Date(Date.now()+30*86400000).toISOString().slice(0,10),
    intro: settings.defaultIntro,
    items: [{id:uid(),type:'item',description:'',quantity:1,unitPrice:0}],
    taxRate: settings.taxRate || 20,
    discount: 0,
    notes: '',
    terms: settings.defaultTerms,
    footer: settings.defaultFooter,
    nextSteps: settings.defaultNextSteps || '',
    status: 'entwurf',
    sentAt: null,
    createdAt: new Date().toISOString(),
  };
}

function quoteTotals(quote) {
  const subtotal = (quote.items||[]).filter(i=>i.type!=='heading').reduce((s,i)=>s+(Number(i.quantity)||0)*(Number(i.unitPrice)||0), 0);
  const discount = Number(quote.discount)||0;
  const afterDiscount = Math.max(0, subtotal - discount);
  const tax = afterDiscount * (Number(quote.taxRate)||0) / 100;
  const total = afterDiscount + tax;
  return {subtotal, discount, afterDiscount, tax, total};
}

// ══════════════════════════════════════════════════════════════════
//  INVOICE HELPERS
// ══════════════════════════════════════════════════════════════════
const INVOICE_STATUSES = [
  {key:'entwurf',      label:'Entwurf',     color:'#6B6560',bg:'#F5F3F0',dot:'#A8A39D'},
  {key:'gesendet',     label:'Gesendet',    color:'#1d4ed8',bg:'#EFF6FF',dot:'#3b82f6'},
  {key:'offen',        label:'Offen',       color:'#b45309',bg:'#FFFBEB',dot:'#f59e0b'},
  {key:'bezahlt',      label:'Bezahlt',     color:'#15803d',bg:'#F0FDF4',dot:'#22c55e'},
  {key:'ueberfaellig', label:'Überfällig',  color:'#b91c1c',bg:'#FEF2F2',dot:'#ef4444'},
  {key:'storniert',    label:'Storniert',   color:'#6d28d9',bg:'#F5F3FF',dot:'#8b5cf6'},
];
function nextInvoiceNumber(settings) {
  const year = new Date().getFullYear();
  const num = String(settings.invoiceCounter||1).padStart(3,'0');
  return `${settings.numberPrefix||'RE'}-${year}-${num}`;
}
function contactToSnapshot(c){
  if(!c)return {};
  return {firma:c.firma||'',ansprechpartner:c.ansprechpartner||'',email:c.email||'',telefon:c.telefon||'',address:c.address||'',zip:c.zip||'',city:c.city||'',country:c.country||'',taxId:c.taxId||''};
}
function blankInvoice(contact, quoteSettings, invoiceSettings, fromQuote) {
  const today = new Date().toISOString().slice(0,10);
  const dueDays = invoiceSettings?.defaultDueDays||14;
  const due = new Date(Date.now()+dueDays*86400000).toISOString().slice(0,10);
  const snap = contact ? contactToSnapshot(contact) : (fromQuote?.contactSnapshot||{});
  return {
    id:uid(), number:nextInvoiceNumber(invoiceSettings||{}), status:'entwurf',
    contactId:contact?.id||fromQuote?.contactId||'',
    contactSnapshot:snap,
    items:fromQuote ? (fromQuote.items||[]).map(i=>({...i,id:uid()})) : [{id:uid(),type:'item',description:'',quantity:1,unitPrice:0}],
    date:today, dueDate:due, serviceDate:today, serviceEndDate:'',
    taxRate:fromQuote?.taxRate||(quoteSettings?.taxRate||20),
    discount:fromQuote?.discount||0,
    title:fromQuote?.title||'',
    notes:'', paymentNote:invoiceSettings?.paymentNote||'',
    fromQuoteId:fromQuote?.id||'',
    paidAt:null, createdAt:new Date().toISOString(),
  };
}

// ── Quote Settings Modal ─────────────────────────────────────────
function TokenUpdateModal({cryptoKey, currentState, onSaved, onClose}){
  const current = _ghSettings;
  const [token, setToken] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const [ok, setOk] = useState(false);

  const save = async () => {
    if(!token.trim()){setErr('Bitte neuen Token eingeben.');return;}
    setBusy(true); setErr('');
    try {
      await ghValidateAccess(token.trim(), current.repo);
      // CRITICAL: push current local state with new token FIRST before saving settings
      // This prevents the old GitHub state from overwriting newer local data on next sync
      if(currentState){
        try{
          const enc = await aesEncrypt(cryptoKey, {...currentState, _savedAt:Date.now()});
          const newSha = await ghPushFile(token.trim(), current.repo, current.path, enc, _ghSha);
          _ghSha = newSha;
          localStorage.setItem(GH_SHA_KEY, newSha);
          localStorage.setItem(DATA_KEY, JSON.stringify(enc));
          saveLocalSnapshot(enc); _lastSnapAt = Date.now();
        }catch(pushErr){}
      }
      const newSettings = {...current, token: token.trim()};
      await saveGithubSettings(cryptoKey, newSettings);
      _ghSyncState = {state:'idle'};
      setOk(true);
      setTimeout(()=>{onSaved&&onSaved();onClose();}, 1200);
    } catch(e) { setErr(e.message); }
    setBusy(false);
  };

  return(
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-box" onClick={e=>e.stopPropagation()} style={{width:460}}>
        <div style={{display:'flex',justifyContent:'space-between',alignItems:'flex-start',marginBottom:18}}>
          <div>
            <h2 style={{fontSize:17,fontWeight:700}}>🔑 Token aktualisieren</h2>
            <p style={{fontSize:12.5,color:'#A8A39D',marginTop:3}}>Neuen GitHub Token eingeben — Repo und Daten bleiben unverändert.</p>
          </div>
          <button onClick={onClose} style={{background:'#F5F3F0',border:'none',borderRadius:8,padding:8,color:'#999',lineHeight:0}}><Icons.Close/></button>
        </div>
        <div style={{background:'#F5F3F0',borderRadius:8,padding:'10px 14px',marginBottom:16,fontSize:12.5,color:'#5F5A55'}}>
          <div style={{marginBottom:2}}><strong>Repo:</strong> {current?.repo}</div>
          <div><strong>Pfad:</strong> {current?.path}</div>
        </div>
        <div style={{marginBottom:14}}>
          <label style={{display:'block',fontSize:11,fontWeight:600,color:'#A8A39D',marginBottom:6,textTransform:'uppercase',letterSpacing:'0.06em'}}>Neuer Token</label>
          <input value={token} onChange={e=>setToken(e.target.value)} placeholder="github_pat_… oder ghp_…" style={{fontFamily:'monospace',fontSize:12}} autoFocus/>
          <div style={{fontSize:11.5,color:'#A8A39D',marginTop:6}}>Erstellen unter github.com/settings/tokens · Berechtigungen: Contents + Actions read/write</div>
        </div>
        {err&&<div style={{fontSize:12.5,color:'#C0392B',padding:'8px 12px',background:'#FEF2F2',borderRadius:8,marginBottom:12,border:'1px solid #FECACA'}}>{err}</div>}
        {ok&&<div style={{fontSize:12.5,color:'#16a34a',padding:'8px 12px',background:'#F0FDF4',borderRadius:8,marginBottom:12,border:'1px solid #BBF7D0'}}>✓ Token gespeichert — Sync wird fortgesetzt.</div>}
        <div style={{display:'flex',gap:10,justifyContent:'flex-end'}}>
          <button className="btn btn-ghost" onClick={onClose}>Abbrechen</button>
          <button className="btn btn-primary" onClick={save} disabled={busy||!token.trim()||ok}>{busy?'Prüfe…':'Speichern'}</button>
        </div>
      </div>
    </div>
  );
}

function QuoteSettingsModal({settings, onSave, onClose}){
  const [s, setS] = useState(settings || DEFAULT_QUOTE_SETTINGS);
  const u = (k,v)=>setS(p=>({...p,[k]:v}));
  return(
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-box" onClick={e=>e.stopPropagation()} style={{width:580}}>
        <div style={{display:'flex',justifyContent:'space-between',alignItems:'flex-start',marginBottom:18}}>
          <div>
            <h2 style={{fontSize:17,fontWeight:700}}>Angebots-Vorlage</h2>
            <p style={{fontSize:12.5,color:'#A8A39D',marginTop:3}}>Diese Daten werden in jedem Angebot verwendet.</p>
          </div>
          <button onClick={onClose} style={{background:'#F5F3F0',border:'none',borderRadius:8,padding:8,color:'#999',lineHeight:0}}><Icons.Close/></button>
        </div>

        <div style={{fontSize:11,fontWeight:600,color:'#A8A39D',textTransform:'uppercase',letterSpacing:'0.06em',marginBottom:8}}>Firma</div>
        <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:10,marginBottom:14}}>
          <input value={s.companyName} onChange={e=>u('companyName',e.target.value)} placeholder="Firmenname"/>
          <input value={s.taxId} onChange={e=>u('taxId',e.target.value)} placeholder="UID / USt-IdNr"/>
        </div>
        <textarea value={s.companyAddress} onChange={e=>u('companyAddress',e.target.value)} placeholder="Adresse (mehrzeilig)" style={{minHeight:60,marginBottom:10}}/>
        <div style={{display:'grid',gridTemplateColumns:'1fr 1fr 1fr',gap:10,marginBottom:18}}>
          <input value={s.companyEmail} onChange={e=>u('companyEmail',e.target.value)} placeholder="Email"/>
          <input value={s.companyPhone} onChange={e=>u('companyPhone',e.target.value)} placeholder="Telefon"/>
          <input value={s.companyWebsite} onChange={e=>u('companyWebsite',e.target.value)} placeholder="Website"/>
        </div>

        <div style={{fontSize:11,fontWeight:600,color:'#A8A39D',textTransform:'uppercase',letterSpacing:'0.06em',marginBottom:8}}>Bankverbindung</div>
        <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:10,marginBottom:10}}>
          <input value={s.bankName} onChange={e=>u('bankName',e.target.value)} placeholder="Bank"/>
          <input value={s.bic} onChange={e=>u('bic',e.target.value)} placeholder="BIC"/>
        </div>
        <input value={s.iban} onChange={e=>u('iban',e.target.value)} placeholder="IBAN" style={{marginBottom:18,fontFamily:'monospace'}}/>

        <div style={{fontSize:11,fontWeight:600,color:'#A8A39D',textTransform:'uppercase',letterSpacing:'0.06em',marginBottom:8}}>Standardtexte</div>
        <div style={{fontSize:11.5,color:'#6B6560',marginBottom:4}}>Einleitung (nach „Sehr geehrte/r …,")</div>
        <textarea value={s.defaultIntro} onChange={e=>u('defaultIntro',e.target.value)} placeholder="z.B. vielen Dank für das Gespräch …" style={{minHeight:70,marginBottom:10}}/>
        <div style={{fontSize:11.5,color:'#6B6560',marginBottom:4}}>Nächste Schritte</div>
        <textarea value={s.defaultNextSteps} onChange={e=>u('defaultNextSteps',e.target.value)} placeholder="z.B. So geht's nach Ihrer Zusage weiter …" style={{minHeight:70,marginBottom:10}}/>
        <div style={{fontSize:11.5,color:'#6B6560',marginBottom:4}}>Bedingungen</div>
        <textarea value={s.defaultTerms} onChange={e=>u('defaultTerms',e.target.value)} placeholder="Gültigkeit, Zahlungsziel …" style={{minHeight:70,marginBottom:10}}/>
        <input value={s.defaultFooter} onChange={e=>u('defaultFooter',e.target.value)} placeholder="Schluss-Satz (z.B. Wir freuen uns auf …)" style={{marginBottom:18}}/>

        <div style={{fontSize:11,fontWeight:600,color:'#A8A39D',textTransform:'uppercase',letterSpacing:'0.06em',marginBottom:8}}>Design</div>
        <div style={{display:'flex',alignItems:'center',gap:10,marginBottom:14}}>
          <div style={{fontSize:12.5,color:'#6B6560',flex:1}}>Akzent-Farbe (Titel + Linien im Angebot)</div>
          <input type="color" value={s.accentColor||'#141210'} onChange={e=>u('accentColor',e.target.value)} style={{width:48,height:36,padding:2,cursor:'pointer'}}/>
          <input value={s.accentColor||'#141210'} onChange={e=>u('accentColor',e.target.value)} style={{width:100,fontFamily:'monospace',fontSize:12}}/>
        </div>
        {/* Logo upload */}
        <div style={{marginBottom:14}}>
          <div style={{fontSize:12.5,color:'#6B6560',marginBottom:8}}>Firmen-Logo (wird auf dem Angebot angezeigt)</div>
          <div style={{display:'flex',alignItems:'center',gap:10}}>
            {s.logoUrl ? (
              <div style={{position:'relative',display:'inline-flex'}}>
                <img src={s.logoUrl} style={{height:44,maxWidth:160,objectFit:'contain',border:'1.5px solid #E5E1DC',borderRadius:8,padding:'4px 8px',background:'white'}} alt="Logo"/>
                <button onClick={()=>u('logoUrl','')} style={{position:'absolute',top:-6,right:-6,width:18,height:18,borderRadius:'50%',background:'#C0392B',border:'none',color:'white',cursor:'pointer',fontSize:11,lineHeight:'18px',textAlign:'center',padding:0}}>×</button>
              </div>
            ) : (
              <div style={{width:160,height:44,border:'1.5px dashed #D8D3CE',borderRadius:8,display:'flex',alignItems:'center',justifyContent:'center',color:'#C8C3BD',fontSize:12}}>Kein Logo</div>
            )}
            <label style={{cursor:'pointer'}}>
              <span className="btn btn-ghost btn-sm" style={{pointerEvents:'none'}}>Logo hochladen</span>
              <input type="file" accept="image/*" style={{display:'none'}} onChange={e=>{const f=e.target.files[0];if(!f)return;const r=new FileReader();r.onload=ev=>u('logoUrl',ev.target.result);r.readAsDataURL(f);}}/>
            </label>
          </div>
        </div>
        {/* Banner upload */}
        <div style={{marginBottom:18}}>
          <div style={{fontSize:12.5,color:'#6B6560',marginBottom:8}}>Cover-Banner (großes Hintergrundbild auf der Titelseite)</div>
          <div style={{display:'flex',alignItems:'center',gap:10}}>
            {s.bannerUrl ? (
              <div style={{position:'relative',display:'inline-flex'}}>
                <img src={s.bannerUrl} style={{height:56,width:180,objectFit:'cover',border:'1.5px solid #E5E1DC',borderRadius:8}} alt="Banner"/>
                <button onClick={()=>u('bannerUrl','')} style={{position:'absolute',top:-6,right:-6,width:18,height:18,borderRadius:'50%',background:'#C0392B',border:'none',color:'white',cursor:'pointer',fontSize:11,lineHeight:'18px',textAlign:'center',padding:0}}>×</button>
              </div>
            ) : (
              <div style={{width:180,height:56,border:'1.5px dashed #D8D3CE',borderRadius:8,display:'flex',alignItems:'center',justifyContent:'center',color:'#C8C3BD',fontSize:12}}>Kein Banner</div>
            )}
            <label style={{cursor:'pointer'}}>
              <span className="btn btn-ghost btn-sm" style={{pointerEvents:'none'}}>Banner hochladen</span>
              <input type="file" accept="image/*" style={{display:'none'}} onChange={e=>{const f=e.target.files[0];if(!f)return;const r=new FileReader();r.onload=ev=>u('bannerUrl',ev.target.result);r.readAsDataURL(f);}}/>
            </label>
          </div>
        </div>

        <div style={{fontSize:11,fontWeight:600,color:'#A8A39D',textTransform:'uppercase',letterSpacing:'0.06em',marginBottom:8}}>Standard-Werte</div>
        <div style={{display:'grid',gridTemplateColumns:'1fr 1fr 1fr',gap:10,marginBottom:10}}>
          <div>
            <div style={{fontSize:11.5,color:'#6B6560',marginBottom:4}}>USt-Satz %</div>
            <input type="number" value={s.taxRate} onChange={e=>u('taxRate',Number(e.target.value)||0)}/>
          </div>
          <div>
            <div style={{fontSize:11.5,color:'#6B6560',marginBottom:4}}>Währung</div>
            <select value={s.currency} onChange={e=>u('currency',e.target.value)}>
              <option value="EUR">EUR €</option><option value="CHF">CHF</option><option value="USD">USD $</option><option value="GBP">GBP £</option>
            </select>
          </div>
          <div>
            <div style={{fontSize:11.5,color:'#6B6560',marginBottom:4}}>Nummer-Präfix</div>
            <input value={s.quotePrefix} onChange={e=>u('quotePrefix',e.target.value)}/>
          </div>
        </div>
        <div style={{background:'#FFFBEB',borderRadius:8,padding:'10px 12px',border:'1px solid #FDE68A',marginBottom:18}}>
          <div style={{fontSize:11.5,color:'#92400E',marginBottom:4,fontWeight:600}}>Nächste Angebotsnummer (frei wählbar)</div>
          <div style={{display:'flex',alignItems:'center',gap:10}}>
            <input type="number" value={s.quoteCounter||1} onChange={e=>u('quoteCounter',Math.max(1,Number(e.target.value)||1))} min={1} style={{width:120,fontFamily:'monospace'}}/>
            <span style={{fontSize:12,color:'#92400E'}}>→ Nächstes Angebot: <strong style={{fontFamily:'monospace'}}>{s.quotePrefix||'AN'}-{new Date().getFullYear()}-{String(s.quoteCounter||1).padStart(3,'0')}</strong></span>
          </div>
          <div style={{fontSize:11,color:'#A88A4F',marginTop:5,lineHeight:1.5}}>Setze hier jede beliebige Startzahl (z.B. 158). Bestehende Angebote werden nicht verändert.</div>
        </div>

        <div style={{display:'flex',gap:10,justifyContent:'flex-end'}}>
          <button className="btn btn-ghost" onClick={onClose}>Abbrechen</button>
          <button className="btn btn-primary" onClick={()=>{onSave(s);onClose();}}>Speichern</button>
        </div>
      </div>
    </div>
  );
}

// ── Quote Editor ─────────────────────────────────────────────────
function QuoteEditor({quote, contacts, settings, onSave, onClose, onPreview}){
  const [q, setQ] = useState(quote);
  const u = (k,v)=>setQ(p=>({...p,[k]:v}));
  const totals = quoteTotals(q);
  const cur = settings.currency || 'EUR';

  const updateItem = (id, field, value) => {
    setQ(p=>({...p, items:p.items.map(it=>it.id===id?{...it,[field]:value}:it)}));
  };
  const addItem = () => setQ(p=>({...p,items:[...p.items,{id:uid(),type:'item',description:'',quantity:1,unitPrice:0}]}));
  const addHeading = () => setQ(p=>({...p,items:[...p.items,{id:uid(),type:'heading',description:''}]}));
  const removeItem = (id) => setQ(p=>({...p,items:p.items.filter(it=>it.id!==id)}));
  const moveItem = (id, dir) => {
    setQ(p=>{
      const idx = p.items.findIndex(i=>i.id===id);
      if(idx<0) return p;
      const target = idx+dir;
      if(target<0 || target>=p.items.length) return p;
      const items = [...p.items];
      [items[idx], items[target]] = [items[target], items[idx]];
      return {...p, items};
    });
  };

  const updContact = (k,v) => setQ(p=>({...p, contactSnapshot:{...p.contactSnapshot,[k]:v}}));

  return(
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-box" onClick={e=>e.stopPropagation()} style={{width:760,maxHeight:'92vh'}}>
        <div style={{display:'flex',justifyContent:'space-between',alignItems:'flex-start',marginBottom:18}}>
          <div style={{flex:1}}>
            <div style={{display:'flex',alignItems:'center',gap:10,marginBottom:4}}>
              <input value={q.number} onChange={e=>u('number',e.target.value)} style={{fontSize:18,fontWeight:700,letterSpacing:'-0.01em',fontFamily:'monospace',border:'none',borderBottom:'2px solid transparent',borderRadius:0,padding:'0 2px',background:'transparent',width:160,outline:'none',transition:'border-color .15s'}} onFocus={e=>e.target.style.borderBottomColor='#141210'} onBlur={e=>e.target.style.borderBottomColor='transparent'} title="Nummer bearbeiten"/>
              <select value={q.status} onChange={e=>{const s=e.target.value;setQ(p=>({...p,status:s,sentAt:s==='gesendet'&&!p.sentAt?new Date().toISOString():p.sentAt}));}} style={{width:'auto',padding:'4px 8px',fontSize:11.5,fontWeight:600,background:'#F5F3F0',border:'1.5px solid transparent'}}>
                {QUOTE_STATUSES.map(st=><option key={st.key} value={st.key}>{st.label}</option>)}
              </select>
            </div>
            <p style={{fontSize:12.5,color:'#A8A39D'}}>Erstelle und passe dein Angebot an.</p>
          </div>
          <button onClick={onClose} style={{background:'#F5F3F0',border:'none',borderRadius:8,padding:8,color:'#999',lineHeight:0}}><Icons.Close/></button>
        </div>

        <div style={{display:'grid',gridTemplateColumns:'2fr 1fr 1fr',gap:10,marginBottom:14}}>
          <input value={q.title} onChange={e=>u('title',e.target.value)} placeholder="Betreff (z.B. Webseite Relaunch)"/>
          <div><div style={{fontSize:11,color:'#A8A39D',marginBottom:4,fontWeight:600,textTransform:'uppercase',letterSpacing:'0.05em'}}>Datum</div><input type="date" value={q.date} onChange={e=>u('date',e.target.value)}/></div>
          <div><div style={{fontSize:11,color:'#A8A39D',marginBottom:4,fontWeight:600,textTransform:'uppercase',letterSpacing:'0.05em'}}>Gültig bis</div><input type="date" value={q.validUntil} onChange={e=>u('validUntil',e.target.value)}/></div>
        </div>

        <div style={{fontSize:11,fontWeight:600,color:'#A8A39D',textTransform:'uppercase',letterSpacing:'0.06em',marginBottom:8}}>Kunde</div>
        <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:10,marginBottom:10}}>
          <input value={q.contactSnapshot.firma} onChange={e=>updContact('firma',e.target.value)} placeholder="Firma"/>
          <input value={q.contactSnapshot.ansprechpartner} onChange={e=>updContact('ansprechpartner',e.target.value)} placeholder="Ansprechpartner"/>
        </div>
        <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:10,marginBottom:10}}>
          <input value={q.contactSnapshot.email} onChange={e=>updContact('email',e.target.value)} placeholder="Email" type="email"/>
          <input value={q.contactSnapshot.telefon} onChange={e=>updContact('telefon',e.target.value)} placeholder="Telefon"/>
        </div>
        <textarea value={q.contactSnapshot.adresse} onChange={e=>updContact('adresse',e.target.value)} placeholder="Adresse (mehrzeilig)" style={{minHeight:50,marginBottom:18}}/>

        <div style={{fontSize:11,fontWeight:600,color:'#A8A39D',textTransform:'uppercase',letterSpacing:'0.06em',marginBottom:8}}>Einleitung</div>
        <textarea value={q.intro} onChange={e=>u('intro',e.target.value)} style={{minHeight:60,marginBottom:18}}/>

        <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:8}}>
          <div style={{fontSize:11,fontWeight:600,color:'#A8A39D',textTransform:'uppercase',letterSpacing:'0.06em'}}>Leistungen</div>
          <div style={{display:'flex',gap:6}}>
            <button className="btn btn-ghost btn-sm" onClick={addHeading}><Icons.Plus/>Phase / Überschrift</button>
            <button className="btn btn-ghost btn-sm" onClick={addItem}><Icons.Plus/>Leistung</button>
          </div>
        </div>
        <div style={{border:'1px solid #EAE6E0',borderRadius:10,overflow:'hidden',marginBottom:14}}>
          {q.items.map((it,idx)=>{
            if (it.type === 'heading') {
              return(
                <div key={it.id} style={{display:'flex',alignItems:'center',gap:8,padding:'10px 12px',borderTop:idx>0?'1px solid #F0EDE8':'none',background:'#FAFAF8'}}>
                  <span style={{fontSize:10,fontWeight:700,color:'#A8A39D',textTransform:'uppercase',letterSpacing:'0.08em',padding:'3px 8px',background:'#EAE6E0',borderRadius:6}}>Phase</span>
                  <input value={it.description} onChange={e=>updateItem(it.id,'description',e.target.value)} placeholder="z.B. Phase 1: Konzept &amp; Design" style={{flex:1,padding:'6px 10px',fontSize:13.5,fontWeight:700,background:'white'}}/>
                  <button onClick={()=>moveItem(it.id,-1)} disabled={idx===0} style={{background:'none',border:'none',color:'#C8C3BD',cursor:'pointer',padding:'2px 4px',fontSize:13,opacity:idx===0?0.3:1}}>↑</button>
                  <button onClick={()=>moveItem(it.id,1)} disabled={idx===q.items.length-1} style={{background:'none',border:'none',color:'#C8C3BD',cursor:'pointer',padding:'2px 4px',fontSize:13,opacity:idx===q.items.length-1?0.3:1}}>↓</button>
                  <button onClick={()=>removeItem(it.id)} style={{background:'none',border:'none',color:'#DDD',cursor:'pointer',fontSize:18,padding:'2px 4px',lineHeight:1}} onMouseEnter={e=>e.currentTarget.style.color='#C0392B'} onMouseLeave={e=>e.currentTarget.style.color='#DDD'}>×</button>
                </div>
              );
            }
            const lineTotal = (Number(it.quantity)||0)*(Number(it.unitPrice)||0);
            return(
              <div key={it.id} style={{display:'grid',gridTemplateColumns:'1fr 70px 100px 100px 56px',gap:8,padding:'8px 12px',borderTop:idx>0?'1px solid #F0EDE8':'none',alignItems:'flex-start'}}>
                <textarea value={it.description} onChange={e=>updateItem(it.id,'description',e.target.value)} placeholder="Was wird geliefert? Mehrere Zeilen ok." style={{minHeight:42,padding:'6px 8px',fontSize:12.5,resize:'vertical'}}/>
                <input type="number" step="0.01" value={it.quantity} onChange={e=>updateItem(it.id,'quantity',e.target.value)} style={{padding:'6px 8px',fontSize:12.5,textAlign:'right'}}/>
                <input type="number" step="0.01" value={it.unitPrice} onChange={e=>updateItem(it.id,'unitPrice',e.target.value)} style={{padding:'6px 8px',fontSize:12.5,textAlign:'right'}}/>
                <div style={{padding:'8px 8px',fontSize:13,fontWeight:600,textAlign:'right',fontVariantNumeric:'tabular-nums'}}>{fmtMoney(lineTotal,cur)}</div>
                <div style={{display:'flex',alignItems:'flex-start',gap:0}}>
                  <button onClick={()=>moveItem(it.id,-1)} disabled={idx===0} style={{background:'none',border:'none',color:'#C8C3BD',cursor:'pointer',padding:'2px 3px',fontSize:13,opacity:idx===0?0.3:1}}>↑</button>
                  <button onClick={()=>moveItem(it.id,1)} disabled={idx===q.items.length-1} style={{background:'none',border:'none',color:'#C8C3BD',cursor:'pointer',padding:'2px 3px',fontSize:13,opacity:idx===q.items.length-1?0.3:1}}>↓</button>
                  <button onClick={()=>removeItem(it.id)} style={{background:'none',border:'none',color:'#DDD',cursor:'pointer',fontSize:16,padding:'2px 3px',lineHeight:1}} onMouseEnter={e=>e.currentTarget.style.color='#C0392B'} onMouseLeave={e=>e.currentTarget.style.color='#DDD'}>×</button>
                </div>
              </div>
            );
          })}
        </div>

        <div style={{display:'grid',gridTemplateColumns:'1fr 280px',gap:14,marginBottom:18}}>
          <div>
            <div style={{fontSize:11,fontWeight:600,color:'#A8A39D',textTransform:'uppercase',letterSpacing:'0.06em',marginBottom:8}}>Notizen / interne Hinweise</div>
            <textarea value={q.notes} onChange={e=>u('notes',e.target.value)} placeholder="Werden NICHT im Angebot angezeigt — nur für dich" style={{minHeight:70}}/>
          </div>
          <div style={{background:'#FAFAF8',padding:14,borderRadius:10,border:'1px solid #EAE6E0'}}>
            <div style={{display:'flex',justifyContent:'space-between',fontSize:13,padding:'4px 0'}}><span>Zwischensumme</span><span style={{fontVariantNumeric:'tabular-nums',fontWeight:500}}>{fmtMoney(totals.subtotal,cur)}</span></div>
            <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',fontSize:13,padding:'4px 0'}}>
              <span>Rabatt</span>
              <input type="number" step="0.01" value={q.discount} onChange={e=>u('discount',Number(e.target.value)||0)} style={{width:90,padding:'4px 8px',fontSize:12,textAlign:'right'}}/>
            </div>
            <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',fontSize:13,padding:'4px 0'}}>
              <span>USt</span>
              <span style={{display:'flex',alignItems:'center',gap:4}}>
                <input type="number" value={q.taxRate} onChange={e=>u('taxRate',Number(e.target.value)||0)} style={{width:50,padding:'4px 6px',fontSize:12,textAlign:'right'}}/>
                <span style={{fontSize:12,color:'#6B6560'}}>%</span>
                <span style={{fontVariantNumeric:'tabular-nums',fontWeight:500,minWidth:80,textAlign:'right'}}>{fmtMoney(totals.tax,cur)}</span>
              </span>
            </div>
            <div style={{borderTop:'2px solid #141210',marginTop:8,paddingTop:8,display:'flex',justifyContent:'space-between',fontSize:15,fontWeight:700}}><span>Gesamt</span><span style={{fontVariantNumeric:'tabular-nums'}}>{fmtMoney(totals.total,cur)}</span></div>
          </div>
        </div>

        <div style={{fontSize:11,fontWeight:600,color:'#A8A39D',textTransform:'uppercase',letterSpacing:'0.06em',marginBottom:8}}>So geht's weiter</div>
        <textarea value={q.nextSteps||''} onChange={e=>u('nextSteps',e.target.value)} placeholder="Was passiert nach Zusage? z.B. Kick-off, Briefing, Start" style={{minHeight:70,marginBottom:18}}/>

        <div style={{fontSize:11,fontWeight:600,color:'#A8A39D',textTransform:'uppercase',letterSpacing:'0.06em',marginBottom:8}}>Bedingungen / Kleingedrucktes</div>
        <textarea value={q.terms} onChange={e=>u('terms',e.target.value)} style={{minHeight:60,marginBottom:18}}/>

        <div style={{display:'flex',gap:10,justifyContent:'space-between',paddingTop:14,borderTop:'1px solid #EAE6E0'}}>
          <button className="btn btn-ghost" onClick={onClose}>Abbrechen</button>
          <div style={{display:'flex',gap:8}}>
            <button className="btn btn-ghost" onClick={()=>{onSave(q);onPreview && onPreview(q);}}><Icons.Print/>Vorschau</button>
            <button className="btn btn-primary" onClick={()=>onSave(q)}>Speichern</button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Quote Preview / Print View (Pitch-style) ─────────────────────
function QuotePreview({quote, settings, onClose, onMarkSent}){
  const totals = quoteTotals(quote);
  const cur = settings.currency || 'EUR';
  const accent = settings.accentColor || '#141210';
  const fmtD = iso => iso ? new Date(iso).toLocaleDateString('de-AT',{day:'2-digit',month:'long',year:'numeric'}) : '';
  const status = QUOTE_STATUSES.find(s=>s.key===quote.status) || QUOTE_STATUSES[0];
  const greeting = quote.contactSnapshot?.ansprechpartner ? `Sehr geehrte/r ${quote.contactSnapshot.ansprechpartner},` : 'Sehr geehrte Damen und Herren,';
  const [linkPopup, setLinkPopup] = React.useState(null); // null | {url, copied}
  const [linkBusy, setLinkBusy] = React.useState(false);
  const generateLink = async () => {
    setLinkBusy(true);
    try {
      const r = await fetch('/api/quote-links', {method:'POST', headers:{Authorization:`Bearer ${window.WEBARS_API_TOKEN}`,'Content-Type':'application/json'}, body:JSON.stringify({quote})});
      const j = await r.json();
      if(!r.ok) throw new Error(j.error||r.status);
      setLinkPopup({url:j.url, copied:false});
      if(quote.status==='entwurf') onMarkSent && onMarkSent();
    } catch(e) { alert('Fehler: '+e.message); }
    setLinkBusy(false);
  };

  // Group items by heading for sectioned display
  const sections = [];
  let current = {heading:null, items:[]};
  (quote.items||[]).forEach(it=>{
    if (it.type === 'heading') {
      if (current.items.length || current.heading) sections.push(current);
      current = {heading:it.description, items:[]};
    } else {
      current.items.push(it);
    }
  });
  if (current.items.length || current.heading) sections.push(current);

  const handlePrint = () => { window.print(); };
  const handleEmail = () => {
    const c = quote.contactSnapshot;
    const subject = `Angebot ${quote.number}${quote.title?' — '+quote.title:''}`;
    const body = `${c.ansprechpartner?'Sehr geehrte/r '+c.ansprechpartner+',':'Sehr geehrte Damen und Herren,'}

anbei finden Sie unser Angebot ${quote.number}${quote.title?' für '+quote.title:''}.

Gesamtinvestition: ${fmtMoney(totals.total,cur)}
Gültig bis: ${fmtD(quote.validUntil)}

Wir freuen uns auf Ihre Rückmeldung.

${settings.defaultFooter || 'Mit freundlichen Grüßen'}
${settings.companyName || ''}`;
    const mailto = `mailto:${encodeURIComponent(c.email||'')}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
    window.location.href = mailto;
    if (quote.status === 'entwurf') onMarkSent && onMarkSent();
  };

  return(
    <div className="quote-print-page" style={{position:'fixed',inset:0,zIndex:1000,overflow:'auto'}}>
      {/* Floating action bar */}
      <div className="quote-no-print" style={{position:'sticky',top:0,zIndex:10,background:'rgba(15,14,12,0.92)',backdropFilter:'blur(8px)',padding:'12px 20px',display:'flex',gap:10,alignItems:'center',marginLeft:-20,marginRight:-20,marginTop:-40,marginBottom:24,boxShadow:'0 4px 20px rgba(0,0,0,0.2)'}}>
        <div style={{color:'rgba(255,255,255,0.5)',fontSize:12.5,marginRight:'auto',display:'flex',alignItems:'center',gap:10}}>
          <span>Vorschau</span>
          <span style={{color:'rgba(255,255,255,0.3)'}}>·</span>
          <span style={{color:'white',fontFamily:'monospace'}}>{quote.number}</span>
          <span style={{color:status.color,fontWeight:600,padding:'2px 8px',background:'rgba(255,255,255,0.1)',borderRadius:99,fontSize:11}}>{status.label}</span>
        </div>
        <button className="btn btn-ghost btn-sm" onClick={handleEmail} style={{color:'white',borderColor:'rgba(255,255,255,0.2)'}}><Icons.Mail/>Per Email senden</button>
        <button className="btn btn-ghost btn-sm" onClick={generateLink} disabled={linkBusy} style={{color:'#4ade80',borderColor:'rgba(74,222,128,0.3)',fontWeight:700}}>🔗 {linkBusy?'…':'Annehmen-Link'}</button>
        <button className="btn btn-primary btn-sm" onClick={handlePrint}><Icons.Print/>Drucken / PDF</button>
        <button onClick={onClose} style={{background:'rgba(255,255,255,0.1)',border:'none',borderRadius:8,padding:8,color:'white',lineHeight:0,cursor:'pointer'}}><Icons.Close/></button>
      </div>

      {linkPopup && (
        <div style={{position:'fixed',inset:0,zIndex:2000,background:'rgba(0,0,0,0.6)',display:'flex',alignItems:'center',justifyContent:'center',padding:20}} onClick={()=>setLinkPopup(null)}>
          <div style={{background:'white',borderRadius:16,padding:32,maxWidth:480,width:'100%',boxShadow:'0 20px 60px rgba(0,0,0,0.3)'}} onClick={e=>e.stopPropagation()}>
            <div style={{fontWeight:800,fontSize:17,color:'#141210',marginBottom:6}}>🔗 Annehmen-Link generiert</div>
            <div style={{fontSize:13,color:'#6B6560',marginBottom:16,lineHeight:1.5}}>Schick diesen Link an deine Kundin. Sie kann das Angebot direkt online annehmen — ohne Login.</div>
            <div style={{background:'#F8F5F0',borderRadius:10,padding:'12px 16px',fontFamily:'monospace',fontSize:12,color:'#3F3A35',wordBreak:'break-all',marginBottom:16,border:'1px solid #E8E3DC'}}>{linkPopup.url}</div>
            <div style={{display:'flex',gap:10}}>
              <button onClick={()=>{navigator.clipboard.writeText(linkPopup.url).then(()=>setLinkPopup(p=>({...p,copied:true})));}} style={{flex:1,background:linkPopup.copied?'#16a34a':'#141210',color:'white',border:'none',borderRadius:10,padding:'12px 20px',fontWeight:700,fontSize:14,cursor:'pointer',transition:'background .2s'}}>{linkPopup.copied?'✓ Kopiert!':'Link kopieren'}</button>
              <button onClick={()=>setLinkPopup(null)} style={{background:'#F0EDE8',color:'#6B6560',border:'none',borderRadius:10,padding:'12px 16px',fontWeight:600,fontSize:13,cursor:'pointer'}}>Schließen</button>
            </div>
          </div>
        </div>
      )}

      <div className="quote-paper">
        {/* === COVER === */}
        <div>

          {/* ── BANNER (full-bleed, escapes paper padding) ── */}
          {settings.bannerUrl ? (
            <div style={{
              marginTop:'-22mm', marginLeft:'-20mm', marginRight:'-20mm',
              height:'78mm', position:'relative', marginBottom:'8mm',
              overflow:'hidden', printColorAdjust:'exact', WebkitPrintColorAdjust:'exact'
            }}>
              {/* Banner as <img> so it prints correctly */}
              <img src={settings.bannerUrl} alt="" style={{position:'absolute',inset:0,width:'100%',height:'100%',objectFit:'cover',display:'block'}}/>
              {/* gradient overlay */}
              <div style={{position:'absolute',inset:0,background:'linear-gradient(to bottom, rgba(0,0,0,0) 55%, rgba(0,0,0,0.38) 100%)',printColorAdjust:'exact',WebkitPrintColorAdjust:'exact'}}/>
              {/* Logo top-right on banner */}
              {settings.logoUrl && (
                <img src={settings.logoUrl} alt="Logo" style={{position:'absolute',top:'6mm',right:'8mm',height:'13mm',maxWidth:'55mm',objectFit:'contain',filter:'drop-shadow(0 1px 4px rgba(0,0,0,0.35))'}}/>
              )}
              {/* Quote number + label bottom-left */}
              <div style={{position:'absolute',bottom:'6mm',left:'8mm'}}>
                <div style={{fontSize:'7pt',color:'rgba(255,255,255,0.75)',textTransform:'uppercase',letterSpacing:'0.18em',fontWeight:700,marginBottom:'0.5mm'}}>Angebot</div>
                <div style={{fontSize:'8.5pt',color:'white',fontFamily:'monospace',fontWeight:600,letterSpacing:'0.04em'}}>{quote.number}</div>
              </div>
              {/* Status badge bottom-right */}
              <div style={{position:'absolute',bottom:'6mm',right:'8mm',fontSize:'7.5pt',fontWeight:700,color:'white',background:'rgba(255,255,255,0.18)',backdropFilter:'blur(4px)',padding:'2px 7px',borderRadius:99,letterSpacing:'0.06em'}}>{status.label}</div>
            </div>
          ) : (
            /* ── NO BANNER: classic header row ── */
            <div style={{display:'flex',justifyContent:'space-between',alignItems:'flex-start',marginBottom:'8mm'}}>
              <div>
                <div style={{fontSize:'8pt',color:'#9A9590',textTransform:'uppercase',letterSpacing:'0.16em',fontWeight:600,marginBottom:'1mm'}}>Angebot</div>
                <div style={{fontSize:'9pt',color:'#3F3A35',fontFamily:'monospace',letterSpacing:'0.05em'}}>{quote.number}</div>
              </div>
              <div style={{textAlign:'right'}}>
                {settings.logoUrl ? (
                  <img src={settings.logoUrl} alt="Logo" style={{height:'12mm',maxWidth:'55mm',objectFit:'contain'}}/>
                ) : (
                  <>
                    <div style={{fontWeight:700,fontSize:'12pt',color:accent,letterSpacing:'-0.01em'}}>{settings.companyName || 'Firma'}</div>
                    {settings.companyWebsite && <div style={{fontSize:'9pt',color:'#7A7570',marginTop:'1mm'}}>{settings.companyWebsite}</div>}
                  </>
                )}
              </div>
            </div>
          )}

          {/* ── BRAND ROW (only when banner is shown — pairs with banner) ── */}
          {settings.bannerUrl && (
            <div style={{display:'flex',justifyContent:'space-between',alignItems:'baseline',paddingBottom:'2mm',borderBottom:'0.5pt solid #E5E1DC',marginBottom:'7mm'}}>
              <div style={{fontWeight:700,fontSize:'11pt',color:accent,letterSpacing:'-0.01em'}}>{settings.companyName || 'Firma'}</div>
              {settings.companyWebsite && (
                <div style={{fontSize:'8.5pt',color:'#9A9590',letterSpacing:'0.02em'}}>{settings.companyWebsite}</div>
              )}
            </div>
          )}

          {/* ── HERO: client name + project (top-aligned, fixed rhythm) ── */}
          <div>
            <div style={{fontSize:'8pt',color:'#9A9590',textTransform:'uppercase',letterSpacing:'0.18em',fontWeight:700,marginBottom:'2mm'}}>Für</div>
            <h1 style={{fontSize:'28pt',fontWeight:800,color:accent,letterSpacing:'-0.03em',lineHeight:1.0,margin:'0 0 5mm 0'}}>{quote.contactSnapshot.firma || '—'}</h1>
            {quote.title && (
              <div style={{borderTop:`2pt solid ${accent}`,paddingTop:'3mm',maxWidth:'88%'}}>
                <div style={{fontSize:'8pt',color:'#9A9590',textTransform:'uppercase',letterSpacing:'0.14em',fontWeight:700,marginBottom:'2mm'}}>Projekt</div>
                <div style={{fontSize:'17pt',fontWeight:700,color:'#141210',lineHeight:1.3,letterSpacing:'-0.01em'}}>{quote.title}</div>
              </div>
            )}
          </div>

          {/* ── BOTTOM META STRIP ── */}
          <div style={{display:'flex',gap:0,borderRadius:'2mm',overflow:'hidden',border:`1.5pt solid ${accent}`}}>
            <div style={{flex:1,padding:'3mm 5mm',borderRight:`1pt solid ${accent}`}}>
              <div style={{fontSize:'7pt',color:'#9A9590',textTransform:'uppercase',letterSpacing:'0.14em',fontWeight:700,marginBottom:'1.5mm'}}>Datum</div>
              <div style={{fontSize:'10pt',fontWeight:700,color:'#141210'}}>{fmtD(quote.date)}</div>
            </div>
            <div style={{flex:1,padding:'3mm 5mm',borderRight:`1pt solid ${accent}`}}>
              <div style={{fontSize:'7pt',color:'#9A9590',textTransform:'uppercase',letterSpacing:'0.14em',fontWeight:700,marginBottom:'1.5mm'}}>Gültig bis</div>
              <div style={{fontSize:'10pt',fontWeight:700,color:'#141210'}}>{fmtD(quote.validUntil)}</div>
            </div>
            <div style={{flex:1.5,padding:'3mm 5mm',background:accent}}>
              <div style={{fontSize:'7pt',color:'rgba(255,255,255,0.65)',textTransform:'uppercase',letterSpacing:'0.14em',fontWeight:700,marginBottom:'1.5mm'}}>Investition</div>
              <div style={{fontSize:'14pt',fontWeight:800,color:'white',fontVariantNumeric:'tabular-nums',letterSpacing:'-0.02em'}}>{fmtMoney(totals.total,cur)}</div>
            </div>
          </div>
        </div>

        {/* Page break after cover — only active in print */}
        <div className="quote-cover-break"/>

        {/* === GREETING + INTRO === */}
        <div className="quote-section" style={{marginTop:'10mm',marginBottom:'6mm'}}>
          <div style={{fontSize:'10.5pt',marginBottom:'2mm',fontWeight:500}}>{greeting}</div>
          {quote.intro && <div style={{fontSize:'10.5pt',whiteSpace:'pre-line',lineHeight:1.65,color:'#2F2A25'}}>{quote.intro}</div>}
        </div>

        {/* === LEISTUNGEN (Sectioned) === */}
        <div className="quote-section" style={{marginBottom:'7mm'}}>
          <div style={{display:'flex',alignItems:'baseline',gap:'3mm',marginBottom:'4mm'}}>
            <span style={{fontSize:'8pt',color:accent,textTransform:'uppercase',letterSpacing:'0.16em',fontWeight:700}}>01</span>
            <h2 style={{fontSize:'13pt',fontWeight:700,color:accent,letterSpacing:'-0.01em'}}>Was wir leisten</h2>
          </div>
          {sections.map((section, sIdx) => (
            <div key={sIdx} style={{marginBottom: sIdx < sections.length-1 ? '4mm' : 0}}>
              {section.heading && (
                <div style={{fontSize:'10pt',fontWeight:700,color:'#141210',marginBottom:'2mm',paddingBottom:'1mm',borderBottom:`1pt solid ${accent}`,letterSpacing:'-0.005em'}}>{section.heading}</div>
              )}
              {section.items.map((it, idx) => {
                const lineTotal = (Number(it.quantity)||0)*(Number(it.unitPrice)||0);
                return(
                  <div key={it.id} style={{display:'flex',gap:'5mm',padding:'2.5mm 0',borderTop:idx>0?'0.4pt solid #EFEBE6':'none',alignItems:'flex-start'}}>
                    <div style={{flex:1,minWidth:0}}>
                      <div style={{fontSize:'10.5pt',whiteSpace:'pre-line',color:'#1F1B17',lineHeight:1.5,fontWeight:500}}>{it.description}</div>
                      {Number(it.quantity) > 1 && (
                        <div style={{fontSize:'9pt',color:'#7A7570',marginTop:'1.5mm'}}>{it.quantity} × {fmtMoney(it.unitPrice,cur)}</div>
                      )}
                    </div>
                    <div style={{fontSize:'10.5pt',fontWeight:600,fontVariantNumeric:'tabular-nums',color:'#1F1B17',whiteSpace:'nowrap',minWidth:'30mm',textAlign:'right'}}>{fmtMoney(lineTotal,cur)}</div>
                  </div>
                );
              })}
            </div>
          ))}
        </div>

        {/* === INVESTITION (highlighted) === */}
        <div className="quote-section" style={{marginBottom:'7mm',padding:'4mm 6mm',background:'#FAF9F7',borderRadius:'2mm',borderLeft:`3pt solid ${accent}`}}>
          <div style={{display:'flex',alignItems:'baseline',gap:'3mm',marginBottom:'3mm'}}>
            <span style={{fontSize:'8pt',color:accent,textTransform:'uppercase',letterSpacing:'0.16em',fontWeight:700}}>02</span>
            <h2 style={{fontSize:'13pt',fontWeight:700,color:accent,letterSpacing:'-0.01em'}}>Investition</h2>
          </div>
          <div style={{display:'grid',gridTemplateColumns:'1fr auto',gap:'2mm 5mm',fontSize:'9.5pt'}}>
            <div style={{color:'#5F5A55'}}>Zwischensumme (netto)</div>
            <div style={{fontVariantNumeric:'tabular-nums',textAlign:'right'}}>{fmtMoney(totals.subtotal,cur)}</div>
            {totals.discount>0 && <>
              <div style={{color:'#5F5A55'}}>Rabatt</div>
              <div style={{fontVariantNumeric:'tabular-nums',textAlign:'right'}}>−{fmtMoney(totals.discount,cur)}</div>
            </>}
            <div style={{color:'#5F5A55'}}>USt {quote.taxRate}%</div>
            <div style={{fontVariantNumeric:'tabular-nums',textAlign:'right'}}>{fmtMoney(totals.tax,cur)}</div>
          </div>
          <div style={{borderTop:`1.5pt solid ${accent}`,marginTop:'2.5mm',paddingTop:'2.5mm',display:'flex',justifyContent:'space-between',alignItems:'baseline'}}>
            <div style={{fontSize:'11pt',fontWeight:700,color:accent}}>Gesamt</div>
            <div style={{fontSize:'18pt',fontWeight:800,fontVariantNumeric:'tabular-nums',color:accent,letterSpacing:'-0.02em'}}>{fmtMoney(totals.total,cur)}</div>
          </div>
        </div>

        {/* === NÄCHSTE SCHRITTE === */}
        {quote.nextSteps && (
          <div className="quote-section" style={{marginBottom:'6mm'}}>
            <div style={{display:'flex',alignItems:'baseline',gap:'3mm',marginBottom:'3mm'}}>
              <span style={{fontSize:'8pt',color:accent,textTransform:'uppercase',letterSpacing:'0.16em',fontWeight:700}}>03</span>
              <h2 style={{fontSize:'13pt',fontWeight:700,color:accent,letterSpacing:'-0.01em'}}>So geht's weiter</h2>
            </div>
            <div style={{fontSize:'10.5pt',whiteSpace:'pre-line',lineHeight:1.65,color:'#2F2A25'}}>{quote.nextSteps}</div>
          </div>
        )}

        {/* === SCHLUSSWORTE === */}
        <div style={{marginBottom:'5mm'}}>
          <div style={{fontSize:'10pt',color:'#2F2A25',lineHeight:1.55,marginBottom:'3mm'}}>{quote.footer || settings.defaultFooter || 'Wir freuen uns auf Ihre Rückmeldung.'}</div>
          <div style={{fontSize:'10pt',fontWeight:700,color:accent}}>{settings.companyName}</div>
          {quote.contactSnapshot?.ansprechpartner && <div style={{fontSize:'9pt',color:'#7A7570',marginTop:'1.5mm'}}>Ihr Ansprechpartner: {quote.contactSnapshot.ansprechpartner}</div>}
        </div>

        {/* === FOOTER (bedingungen + meta) === */}
        {quote.terms && (
          <div style={{marginBottom:'4mm',padding:'3mm 4mm',background:'#FAFAF8',borderRadius:'2mm',fontSize:'8pt',color:'#5F5A55',whiteSpace:'pre-line',lineHeight:1.5}}>
            {quote.terms}
          </div>
        )}

        {/* === COMPANY FOOTER STRIP === */}
        <div style={{paddingTop:'3mm',borderTop:'0.5pt solid #E5E1DC',display:'flex',gap:'6mm',fontSize:'7pt',color:'#9A9590',lineHeight:1.5}}>
          <div style={{flex:1,display:'flex',flexDirection:'column',gap:'0.5mm'}}>
            <div style={{fontWeight:600,color:'#5F5A55',marginBottom:'0.5mm'}}>{settings.companyName}</div>
            {settings.companyAddress && <div style={{whiteSpace:'pre-line'}}>{settings.companyAddress}</div>}
          </div>
          <div style={{flex:1,display:'flex',flexDirection:'column',gap:'0.5mm'}}>
            <div style={{fontWeight:600,color:'#5F5A55',marginBottom:'0.5mm'}}>Kontakt</div>
            {settings.companyEmail && <div>{settings.companyEmail}</div>}
            {settings.companyPhone && <div>{settings.companyPhone}</div>}
            {settings.taxId && <div style={{marginTop:'1mm'}}>UID: {settings.taxId}</div>}
          </div>
          {(settings.iban || settings.bankName) && (
            <div style={{flex:1,display:'flex',flexDirection:'column',gap:'0.5mm'}}>
              <div style={{fontWeight:600,color:'#5F5A55',marginBottom:'0.5mm'}}>Bankverbindung</div>
              {settings.bankName && <div>{settings.bankName}</div>}
              {settings.iban && <div style={{fontFamily:'monospace'}}>{settings.iban}</div>}
              {settings.bic && <div style={{fontFamily:'monospace'}}>{settings.bic}</div>}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Quotes List View (Sidebar Section) ───────────────────────────
function QuotesView({quotes, contacts, settings, onCreate, onOpen, onDelete, onDuplicate, onSettings}){
  const [statusFilter, setStatusFilter] = useState('');
  const [search, setSearch] = useState('');

  const filtered = quotes.filter(q=>{
    if(statusFilter && q.status !== statusFilter) return false;
    if(search){
      const s = search.toLowerCase();
      return [q.number,q.title,q.contactSnapshot?.firma,q.contactSnapshot?.ansprechpartner].some(f=>f && f.toLowerCase().includes(s));
    }
    return true;
  }).sort((a,b)=>(b.createdAt||'').localeCompare(a.createdAt||''));

  const totalValue = filtered.reduce((s,q)=>s+quoteTotals(q).total,0);
  const cur = settings.currency || 'EUR';

  return(
    <div style={{flex:1,display:'flex',flexDirection:'column',overflow:'hidden'}}>
      <div style={{padding:'14px 28px',background:'white',borderBottom:'1px solid rgba(0,0,0,0.07)',display:'flex',gap:12,alignItems:'center',flexShrink:0}}>
        <div style={{position:'relative',flex:1,maxWidth:280}}>
          <div style={{position:'absolute',left:11,top:'50%',transform:'translateY(-50%)',color:'#C8C3BD',lineHeight:0}}><Icons.Search/></div>
          <input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Angebote durchsuchen…" style={{paddingLeft:34,background:'#F5F3F0',border:'1.5px solid transparent'}}/>
        </div>
        <select value={statusFilter} onChange={e=>setStatusFilter(e.target.value)} style={{width:'auto',padding:'9px 12px',fontSize:13,background:'#F5F3F0',border:'1.5px solid transparent',color:statusFilter?'#141210':'#A8A39D'}}>
          <option value="">Alle Status</option>{QUOTE_STATUSES.map(s=><option key={s.key} value={s.key}>{s.label}</option>)}
        </select>
        <div style={{flex:1}}></div>
        <button className="btn btn-ghost btn-sm" onClick={onSettings}><Icons.Field/>Vorlage</button>
        <button className="btn btn-primary" onClick={()=>onCreate(null)}><Icons.Plus/>Neues Angebot</button>
      </div>

      <div style={{flex:1,overflowY:'auto',padding:28}}>
        {filtered.length === 0 ? (
          <div style={{textAlign:'center',padding:'80px 20px',color:'#C8C3BD'}}>
            <div style={{fontSize:46,marginBottom:16,opacity:.5}}>📄</div>
            <div style={{fontSize:16,fontWeight:600,color:'#C0BBB5'}}>{quotes.length===0?'Noch keine Angebote.':'Keine Treffer.'}</div>
            {quotes.length===0 && <button className="btn btn-primary" style={{marginTop:20}} onClick={()=>onCreate(null)}><Icons.Plus/>Erstes Angebot erstellen</button>}
          </div>
        ) : (<>
          <div style={{fontSize:12.5,color:'#A8A39D',marginBottom:14}}>{filtered.length} {filtered.length===1?'Angebot':'Angebote'} · Gesamt {fmtMoney(totalValue,cur)}</div>
          <div style={{display:'grid',gap:8}}>
            {filtered.map(q=>{
              const totals = quoteTotals(q);
              const status = QUOTE_STATUSES.find(s=>s.key===q.status) || QUOTE_STATUSES[0];
              return(
                <div key={q.id} style={{background:'white',borderRadius:12,padding:'14px 18px',border:'1px solid rgba(0,0,0,0.07)',boxShadow:'0 1px 4px rgba(0,0,0,0.04)',display:'flex',alignItems:'center',gap:14,cursor:'pointer',transition:'all 0.15s'}}
                  onMouseEnter={e=>{e.currentTarget.style.transform='translateY(-1px)';e.currentTarget.style.boxShadow='0 4px 12px rgba(0,0,0,0.06)';}}
                  onMouseLeave={e=>{e.currentTarget.style.transform='translateY(0)';e.currentTarget.style.boxShadow='0 1px 4px rgba(0,0,0,0.04)';}}
                  onClick={()=>onOpen(q)}>
                  <div style={{flexShrink:0,width:44,height:44,borderRadius:10,background:'#FAFAF8',display:'flex',alignItems:'center',justifyContent:'center',color:'#6B6560'}}><Icons.Quote/></div>
                  <div style={{flex:1,minWidth:0}}>
                    <div style={{display:'flex',alignItems:'center',gap:8,marginBottom:3}}>
                      <span style={{fontFamily:'monospace',fontSize:11.5,fontWeight:600,color:'#6B6560'}}>{q.number}</span>
                      <span style={{display:'inline-flex',alignItems:'center',gap:4,padding:'2px 7px',borderRadius:99,background:status.bg,fontSize:10.5,fontWeight:600,color:status.color}}>
                        <span style={{width:4,height:4,borderRadius:'50%',background:status.dot}}></span>{status.label}
                      </span>
                    </div>
                    <div style={{fontSize:14,fontWeight:600,color:'#141210',whiteSpace:'nowrap',overflow:'hidden',textOverflow:'ellipsis'}}>{q.title || '(ohne Titel)'}</div>
                    <div style={{fontSize:12,color:'#A8A39D',whiteSpace:'nowrap',overflow:'hidden',textOverflow:'ellipsis',marginTop:2}}>
                      {q.contactSnapshot?.firma || '—'} · {fmtDate(q.date)}
                    </div>
                  </div>
                  <div style={{textAlign:'right',flexShrink:0}}>
                    <div style={{fontSize:15,fontWeight:700,fontVariantNumeric:'tabular-nums'}}>{fmtMoney(totals.total,cur)}</div>
                  </div>
                  <div style={{display:'flex',flexDirection:'column',gap:4,flexShrink:0}}>
                    <button onClick={ev=>{ev.stopPropagation();onDuplicate(q);}} title="Duplizieren" style={{background:'none',border:'none',color:'#C8C3BD',cursor:'pointer',fontSize:14,padding:'3px 6px',lineHeight:1,borderRadius:6,transition:'color .15s,background .15s'}} onMouseEnter={e=>{e.currentTarget.style.color='#2563EB';e.currentTarget.style.background='#EFF6FF';}} onMouseLeave={e=>{e.currentTarget.style.color='#C8C3BD';e.currentTarget.style.background='none';}}>⧉</button>
                    <button onClick={ev=>{ev.stopPropagation();if(confirm('Angebot wirklich löschen?'))onDelete(q.id);}} style={{background:'none',border:'none',color:'#C8C3BD',cursor:'pointer',fontSize:18,padding:'3px 6px',lineHeight:1,borderRadius:6,transition:'color .15s'}} onMouseEnter={e=>e.currentTarget.style.color='#C0392B'} onMouseLeave={e=>e.currentTarget.style.color='#C8C3BD'}>×</button>
                  </div>
                </div>
              );
            })}
          </div>
        </>)}
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════
//  INVOICES (Rechnungen)
// ══════════════════════════════════════════════════════════════════
function InvoiceSettingsModal({quoteSettings, invoiceSettings, onSave, onClose}){
  const [qs, setQs] = useState({...DEFAULT_QUOTE_SETTINGS,...(quoteSettings||{})});
  const [is_, setIs] = useState({...DEFAULT_INVOICE_SETTINGS,...(invoiceSettings||{})});
  const uq=(k,v)=>setQs(p=>({...p,[k]:v}));
  const ui=(k,v)=>setIs(p=>({...p,[k]:v}));
  const SectionLabel = ({children}) => <div style={{fontSize:11,fontWeight:700,color:'#A8A39D',textTransform:'uppercase',letterSpacing:'0.07em',marginBottom:8,marginTop:4}}>{children}</div>;
  const uploadImg = (field, setter) => e => {
    const f=e.target.files[0]; if(!f)return;
    const r=new FileReader(); r.onload=ev=>setter(p=>({...p,[field]:ev.target.result})); r.readAsDataURL(f);
  };
  return(
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-box" onClick={e=>e.stopPropagation()} style={{width:640,maxHeight:'88vh',overflowY:'auto'}}>
        <div style={{display:'flex',justifyContent:'space-between',alignItems:'flex-start',marginBottom:20}}>
          <div>
            <h2 style={{fontSize:17,fontWeight:700}}>Rechnungs-Vorlage</h2>
            <p style={{fontSize:12.5,color:'#A8A39D',marginTop:3}}>Firma, Design und Standard-Werte für alle Rechnungen.</p>
          </div>
          <button onClick={onClose} style={{background:'#F5F3F0',border:'none',borderRadius:8,padding:8,color:'#999',lineHeight:0,cursor:'pointer'}}><Icons.Close/></button>
        </div>

        <SectionLabel>Firmeninformationen</SectionLabel>
        <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:10,marginBottom:10}}>
          <input value={qs.companyName} onChange={e=>uq('companyName',e.target.value)} placeholder="Firmenname *"/>
          <input value={qs.taxId} onChange={e=>uq('taxId',e.target.value)} placeholder="UID / USt-IdNr"/>
        </div>
        <textarea value={qs.companyAddress} onChange={e=>uq('companyAddress',e.target.value)} placeholder="Adresse (mehrzeilig — erscheint im Rechnungsfooter)" style={{minHeight:64,marginBottom:10,width:'100%',boxSizing:'border-box'}}/>
        <div style={{display:'grid',gridTemplateColumns:'1fr 1fr 1fr',gap:10,marginBottom:18}}>
          <input value={qs.companyEmail} onChange={e=>uq('companyEmail',e.target.value)} placeholder="E-Mail"/>
          <input value={qs.companyPhone} onChange={e=>uq('companyPhone',e.target.value)} placeholder="Telefon"/>
          <input value={qs.companyWebsite} onChange={e=>uq('companyWebsite',e.target.value)} placeholder="Website"/>
        </div>

        <SectionLabel>Bankverbindung</SectionLabel>
        <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:10,marginBottom:10}}>
          <input value={qs.bankName} onChange={e=>uq('bankName',e.target.value)} placeholder="Bank"/>
          <input value={qs.bic} onChange={e=>uq('bic',e.target.value)} placeholder="BIC / SWIFT"/>
        </div>
        <input value={qs.iban} onChange={e=>uq('iban',e.target.value)} placeholder="IBAN" style={{marginBottom:18,fontFamily:'monospace'}}/>

        <SectionLabel>Rechnungs-Einstellungen</SectionLabel>
        <div style={{display:'grid',gridTemplateColumns:'1fr 1fr 1fr',gap:10,marginBottom:10}}>
          <div>
            <div style={{fontSize:11.5,color:'#6B6560',marginBottom:4}}>Nummern-Präfix</div>
            <input value={is_.numberPrefix} onChange={e=>ui('numberPrefix',e.target.value)} placeholder="RE"/>
          </div>
          <div>
            <div style={{fontSize:11.5,color:'#6B6560',marginBottom:4}}>Zahlungsziel (Tage)</div>
            <input type="number" value={is_.defaultDueDays} onChange={e=>ui('defaultDueDays',Number(e.target.value))} min={1}/>
          </div>
          <div>
            <div style={{fontSize:11.5,color:'#6B6560',marginBottom:4}}>Standard USt %</div>
            <input type="number" value={qs.taxRate} onChange={e=>uq('taxRate',Number(e.target.value))} min={0} max={100}/>
          </div>
        </div>
        <div style={{background:'#FFFBEB',borderRadius:8,padding:'10px 12px',border:'1px solid #FDE68A',marginBottom:10}}>
          <div style={{fontSize:11.5,color:'#92400E',marginBottom:4,fontWeight:600}}>Nächste Rechnungsnummer (frei wählbar)</div>
          <div style={{display:'flex',alignItems:'center',gap:10}}>
            <input type="number" value={is_.invoiceCounter} onChange={e=>ui('invoiceCounter',Math.max(1,Number(e.target.value)||1))} min={1} style={{width:120,fontFamily:'monospace'}}/>
            <span style={{fontSize:12,color:'#92400E'}}>→ Nächste Rechnung: <strong style={{fontFamily:'monospace'}}>{is_.numberPrefix||'RE'}-{new Date().getFullYear()}-{String(is_.invoiceCounter||1).padStart(3,'0')}</strong></span>
          </div>
          <div style={{fontSize:11,color:'#A88A4F',marginTop:5,lineHeight:1.5}}>Du kannst hier jede beliebige Startzahl eintragen (z.B. 247) — die Nummerierung läuft dann fortlaufend weiter. <strong>Wichtig:</strong> Bestehende Rechnungen werden nicht verändert.</div>
        </div>
        <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:10,marginBottom:10}}>
          <div>
            <div style={{fontSize:11.5,color:'#6B6560',marginBottom:4}}>Währung</div>
            <select value={qs.currency} onChange={e=>uq('currency',e.target.value)}>
              <option value="EUR">EUR €</option><option value="CHF">CHF</option><option value="USD">USD $</option><option value="GBP">GBP £</option>
            </select>
          </div>
        </div>
        <div style={{fontSize:11.5,color:'#6B6560',marginBottom:4}}>Standard-Zahlungshinweis (erscheint auf jeder Rechnung)</div>
        <textarea value={is_.paymentNote} onChange={e=>ui('paymentNote',e.target.value)} placeholder="z.B. Bitte überweisen Sie den Betrag unter Angabe der Rechnungsnummer auf folgendes Konto." style={{minHeight:60,marginBottom:18,width:'100%',boxSizing:'border-box'}}/>

        <SectionLabel>Design</SectionLabel>
        <div style={{display:'flex',alignItems:'center',gap:10,marginBottom:14}}>
          <div style={{fontSize:12.5,color:'#6B6560',flex:1}}>Akzentfarbe (Titelzeile, Tabellenkopf, Gesamtbalken)</div>
          <input type="color" value={qs.accentColor||'#141210'} onChange={e=>uq('accentColor',e.target.value)} style={{width:48,height:36,padding:2,cursor:'pointer',borderRadius:6}}/>
          <input value={qs.accentColor||'#141210'} onChange={e=>uq('accentColor',e.target.value)} style={{width:90,fontFamily:'monospace',fontSize:12}}/>
        </div>
        {/* Logo */}
        <div style={{marginBottom:14}}>
          <div style={{fontSize:12.5,color:'#6B6560',marginBottom:8}}>Firmen-Logo (erscheint oben links auf der Rechnung)</div>
          <div style={{display:'flex',alignItems:'center',gap:10}}>
            {qs.logoUrl
              ? <div style={{position:'relative',display:'inline-flex'}}>
                  <img src={qs.logoUrl} style={{height:44,maxWidth:160,objectFit:'contain',border:'1.5px solid #E5E1DC',borderRadius:8,padding:'4px 8px',background:'white'}} alt="Logo"/>
                  <button onClick={()=>uq('logoUrl','')} style={{position:'absolute',top:-6,right:-6,width:18,height:18,borderRadius:'50%',background:'#C0392B',border:'none',color:'white',cursor:'pointer',fontSize:11,lineHeight:'18px',textAlign:'center',padding:0}}>×</button>
                </div>
              : <div style={{width:160,height:44,border:'1.5px dashed #D8D3CE',borderRadius:8,display:'flex',alignItems:'center',justifyContent:'center',color:'#C8C3BD',fontSize:12}}>Kein Logo</div>
            }
            <label style={{cursor:'pointer'}}>
              <span className="btn btn-ghost btn-sm" style={{pointerEvents:'none'}}>Logo hochladen</span>
              <input type="file" accept="image/*" style={{display:'none'}} onChange={uploadImg('logoUrl',setQs)}/>
            </label>
          </div>
        </div>

        <div style={{display:'flex',gap:10,justifyContent:'flex-end',marginTop:8}}>
          <button className="btn btn-ghost" onClick={onClose}>Abbrechen</button>
          <button className="btn btn-primary" onClick={()=>{onSave(qs,is_);onClose();}}>Speichern</button>
        </div>
      </div>
    </div>
  );
}
function InvoiceEditor({invoice, contacts, quoteSettings, invoiceSettings, quotes, onSave, onClose, onPreview, onCreateContact}){
  const [inv,setInv]=useState(invoice);
  const [newCust,setNewCust]=useState(false);
  const [nc,setNc]=useState({firma:'',ansprechpartner:'',email:'',telefon:'',address:'',zip:'',city:'',country:'Österreich',taxId:''});
  const us=(k,v)=>setInv(p=>({...p,contactSnapshot:{...(p.contactSnapshot||{}),[k]:v}}));
  const u=(k,v)=>setInv(p=>({...p,[k]:v}));
  const totals=quoteTotals(inv);
  const cur=quoteSettings?.currency||'EUR';
  const accent=quoteSettings?.accentColor||'#141210';
  const updateItem=(id,f,v)=>u('items',inv.items.map(it=>it.id===id?{...it,[f]:v}:it));
  const addItem=()=>u('items',[...inv.items,{id:uid(),type:'item',description:'',quantity:1,unitPrice:0}]);
  const addHeading=()=>u('items',[...inv.items,{id:uid(),type:'heading',description:''}]);
  const removeItem=id=>u('items',inv.items.filter(it=>it.id!==id));
  const fromQuote=q=>setInv(p=>({...p,contactId:q.contactId,contactSnapshot:q.contactSnapshot,items:(q.items||[]).map(i=>({...i,id:uid()})),taxRate:q.taxRate,discount:q.discount,title:q.title,fromQuoteId:q.id}));
  const acceptedQ=(quotes||[]).filter(q=>q.status==='akzeptiert'||q.status==='gesendet');
  const submitNewCust=()=>{
    if(!nc.firma.trim())return;
    const c={id:uid(),firma:nc.firma.trim(),ansprechpartner:nc.ansprechpartner.trim(),email:nc.email.trim(),telefon:nc.telefon.trim(),address:nc.address.trim(),zip:nc.zip.trim(),city:nc.city.trim(),country:nc.country.trim(),taxId:nc.taxId.trim(),sectionId:(contacts[0]?.sectionId||'hauptkunden'),subsectionId:null,status:'Aktiv',notizen:'',umsatz:'',reminders:[],activities:[],customValues:{}};
    onCreateContact(c);
    u('contactId',c.id);
    u('contactSnapshot',contactToSnapshot(c));
    setNc({firma:'',ansprechpartner:'',email:'',telefon:'',address:'',zip:'',city:'',country:'Österreich',taxId:''});
    setNewCust(false);
  };
  return(
    <div style={{position:'fixed',inset:0,zIndex:1000,background:'rgba(0,0,0,0.5)',display:'flex',alignItems:'center',justifyContent:'center'}}>
      <div style={{background:'white',borderRadius:18,width:'90vw',maxWidth:880,maxHeight:'93vh',overflow:'auto',display:'flex',flexDirection:'column'}}>
        <div style={{padding:'20px 28px 16px',borderBottom:'1px solid rgba(0,0,0,0.07)',display:'flex',alignItems:'flex-start',gap:12,flexShrink:0}}>
          <div style={{flex:1}}>
            <div style={{display:'flex',alignItems:'center',gap:10,marginBottom:6}}>
              <h2 style={{fontSize:18,fontWeight:700,letterSpacing:'-0.01em'}}>Rechnung {inv.number}</h2>
              <select value={inv.status} onChange={e=>u('status',e.target.value)} style={{width:'auto',padding:'4px 8px',fontSize:11.5,fontWeight:600,background:'#F5F3F0',border:'1.5px solid transparent',borderRadius:8}}>
                {INVOICE_STATUSES.map(s=><option key={s.key} value={s.key}>{s.label}</option>)}
              </select>
            </div>
            {acceptedQ.length>0&&(
              <select onChange={e=>{if(e.target.value){const q=(quotes||[]).find(x=>x.id===e.target.value);if(q)fromQuote(q);}e.target.value='';}} style={{fontSize:12,color:'#3b82f6',background:'none',border:'1px solid #BFDBFE',borderRadius:7,padding:'3px 8px',cursor:'pointer'}} defaultValue="">
                <option value="" disabled>↑ Aus Angebot übernehmen…</option>
                {acceptedQ.map(q=><option key={q.id} value={q.id}>{q.number} – {q.contactSnapshot?.firma||'?'} – {fmtMoney(quoteTotals(q).total,cur)}</option>)}
              </select>
            )}
          </div>
          <button onClick={()=>onPreview(inv)} className="btn btn-ghost btn-sm"><Icons.Eye/>Vorschau</button>
          <button onClick={()=>onSave(inv)} className="btn btn-primary btn-sm"><Icons.Check/>Speichern</button>
          <button onClick={()=>{const hasContent=inv.contactId||(inv.title&&inv.title.trim())||(inv.items||[]).some(i=>i.type!=='heading'&&i.description&&i.description.trim());if(hasContent)onSave({...inv,status:inv.status==='bezahlt'||inv.status==='storniert'?inv.status:'entwurf'});else onClose();}} style={{background:'rgba(0,0,0,0.06)',border:'none',borderRadius:8,padding:8,cursor:'pointer',lineHeight:0}} title="Schließen (als Entwurf speichern)"><Icons.Close/></button>
        </div>
        <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:20,padding:28,overflowY:'auto',flex:1}}>
          <div style={{display:'flex',flexDirection:'column',gap:16}}>
            <div>
              <div style={{display:'flex',alignItems:'center',marginBottom:6}}>
                <label style={{...lbl,marginBottom:0,flex:1}}>Kunde</label>
                <button onClick={()=>setNewCust(v=>!v)} style={{fontSize:11.5,color:'#3b82f6',background:'none',border:'1px solid #BFDBFE',borderRadius:6,padding:'2px 8px',cursor:'pointer',fontWeight:600}}>{newCust?'× Abbrechen':'+ Neuer Kunde'}</button>
              </div>
              {newCust ? (
                <div style={{background:'#F0F7FF',borderRadius:10,padding:'12px 14px',border:'1.5px solid #BFDBFE',display:'flex',flexDirection:'column',gap:8}}>
                  <div style={{fontSize:12,fontWeight:600,color:'#1d4ed8',marginBottom:2}}>Neuen Kunden anlegen</div>
                  <input value={nc.firma} onChange={e=>setNc(p=>({...p,firma:e.target.value}))} placeholder="Firmenname *" style={{fontSize:13}}/>
                  <input value={nc.ansprechpartner} onChange={e=>setNc(p=>({...p,ansprechpartner:e.target.value}))} placeholder="Ansprechpartner" style={{fontSize:13}}/>
                  <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:8}}>
                    <input value={nc.email} onChange={e=>setNc(p=>({...p,email:e.target.value}))} placeholder="E-Mail" style={{fontSize:13}}/>
                    <input value={nc.telefon} onChange={e=>setNc(p=>({...p,telefon:e.target.value}))} placeholder="Telefon" style={{fontSize:13}}/>
                  </div>
                  <input value={nc.address} onChange={e=>setNc(p=>({...p,address:e.target.value}))} placeholder="Straße + Hausnummer" style={{fontSize:13}}/>
                  <div style={{display:'grid',gridTemplateColumns:'80px 1fr 1fr',gap:8}}>
                    <input value={nc.zip} onChange={e=>setNc(p=>({...p,zip:e.target.value}))} placeholder="PLZ" style={{fontSize:13}}/>
                    <input value={nc.city} onChange={e=>setNc(p=>({...p,city:e.target.value}))} placeholder="Ort" style={{fontSize:13}}/>
                    <input value={nc.country} onChange={e=>setNc(p=>({...p,country:e.target.value}))} placeholder="Land" style={{fontSize:13}}/>
                  </div>
                  <input value={nc.taxId} onChange={e=>setNc(p=>({...p,taxId:e.target.value}))} placeholder="UID / USt-IdNr (optional)" style={{fontSize:13,fontFamily:'monospace'}}/>
                  <button onClick={submitNewCust} className="btn btn-primary btn-sm" style={{alignSelf:'flex-start',marginTop:2}} disabled={!nc.firma.trim()}>Anlegen &amp; auswählen</button>
                </div>
              ) : (
              <select value={inv.contactId} onChange={e=>{const c=contacts.find(x=>x.id===e.target.value);u('contactId',e.target.value);if(c)u('contactSnapshot',contactToSnapshot(c));}} style={{width:'100%'}}>
                <option value="">— Kunden wählen —</option>
                {contacts.map(c=><option key={c.id} value={c.id}>{c.firma}</option>)}
              </select>
              )}
            </div>
            {(inv.contactSnapshot?.firma||inv.contactId)&&(
              <div style={{background:'#FAFAF8',borderRadius:10,padding:'12px 14px',border:'1px solid #EEEAE5',display:'flex',flexDirection:'column',gap:6}}>
                <div style={{fontSize:10.5,fontWeight:700,color:'#A8A39D',textTransform:'uppercase',letterSpacing:'0.06em',marginBottom:2}}>Empfänger-Daten (auf Rechnung)</div>
                <input value={inv.contactSnapshot?.firma||''} onChange={e=>us('firma',e.target.value)} placeholder="Firmenname *" style={{fontSize:13,fontWeight:600}}/>
                <input value={inv.contactSnapshot?.ansprechpartner||''} onChange={e=>us('ansprechpartner',e.target.value)} placeholder="Ansprechpartner" style={{fontSize:13}}/>
                <input value={inv.contactSnapshot?.address||''} onChange={e=>us('address',e.target.value)} placeholder="Straße + Hausnummer" style={{fontSize:13}}/>
                <div style={{display:'grid',gridTemplateColumns:'80px 1fr 1fr',gap:6}}>
                  <input value={inv.contactSnapshot?.zip||''} onChange={e=>us('zip',e.target.value)} placeholder="PLZ" style={{fontSize:13}}/>
                  <input value={inv.contactSnapshot?.city||''} onChange={e=>us('city',e.target.value)} placeholder="Ort" style={{fontSize:13}}/>
                  <input value={inv.contactSnapshot?.country||''} onChange={e=>us('country',e.target.value)} placeholder="Land" style={{fontSize:13}}/>
                </div>
                <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:6}}>
                  <input value={inv.contactSnapshot?.email||''} onChange={e=>us('email',e.target.value)} placeholder="E-Mail" style={{fontSize:13}}/>
                  <input value={inv.contactSnapshot?.telefon||''} onChange={e=>us('telefon',e.target.value)} placeholder="Telefon" style={{fontSize:13}}/>
                </div>
                <input value={inv.contactSnapshot?.taxId||''} onChange={e=>us('taxId',e.target.value)} placeholder="UID / USt-IdNr (Pflicht ab netto €10.000)" style={{fontSize:13,fontFamily:'monospace'}}/>
              </div>
            )}
            <div><label style={lbl}>Projekttitel</label><input value={inv.title||''} onChange={e=>u('title',e.target.value)} placeholder="z.B. Website-Relaunch"/></div>
            <div><label style={lbl}>Interne Notiz</label><textarea value={inv.notes||''} onChange={e=>u('notes',e.target.value)} rows={2} placeholder="Nur intern sichtbar…" style={{width:'100%',boxSizing:'border-box',resize:'vertical',minHeight:58}}/></div>
          </div>
          <div style={{display:'flex',flexDirection:'column',gap:16}}>
            <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:12}}>
              <div><label style={lbl}>Rechnungsdatum</label><input type="date" value={inv.date} onChange={e=>u('date',e.target.value)}/></div>
              <div><label style={lbl}>Fällig am</label><input type="date" value={inv.dueDate} onChange={e=>u('dueDate',e.target.value)}/></div>
            </div>
            <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:12}}>
              <div><label style={lbl}>Leistungsdatum *</label><input type="date" value={inv.serviceDate||inv.date} onChange={e=>u('serviceDate',e.target.value)} title="Datum der Leistungserbringung — gesetzlich erforderlich"/></div>
              <div><label style={lbl}>Leistung bis (optional)</label><input type="date" value={inv.serviceEndDate||''} onChange={e=>u('serviceEndDate',e.target.value)} title="Bei Zeitraum-Leistungen — sonst leer lassen"/></div>
            </div>
            <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:12}}>
              <div><label style={lbl}>USt %</label><input type="number" value={inv.taxRate} onChange={e=>u('taxRate',Number(e.target.value))} min={0} max={100}/></div>
              <div><label style={lbl}>Rabatt (€)</label><input type="number" value={inv.discount||0} onChange={e=>u('discount',Number(e.target.value))} min={0}/></div>
            </div>
            <div><label style={lbl}>Zahlungshinweis (auf Rechnung)</label><textarea value={inv.paymentNote||''} onChange={e=>u('paymentNote',e.target.value)} rows={2} placeholder="z.B. Bitte überweisen Sie…" style={{width:'100%',boxSizing:'border-box',resize:'vertical',minHeight:58}}/></div>
            <div style={{background:'#FAF9F7',borderRadius:10,padding:'12px 14px',fontSize:13,border:'1px solid #EEEAE5'}}>
              <div style={{display:'flex',justifyContent:'space-between',marginBottom:4,color:'#6B6560'}}><span>Netto</span><span>{fmtMoney(totals.subtotal,cur)}</span></div>
              {totals.discount>0&&<div style={{display:'flex',justifyContent:'space-between',marginBottom:4,color:'#6B6560'}}><span>Rabatt</span><span>−{fmtMoney(totals.discount,cur)}</span></div>}
              <div style={{display:'flex',justifyContent:'space-between',marginBottom:6,color:'#6B6560'}}><span>USt {inv.taxRate}%</span><span>{fmtMoney(totals.tax,cur)}</span></div>
              <div style={{display:'flex',justifyContent:'space-between',fontWeight:700,fontSize:15,color:accent,borderTop:'1px solid #E5E1DC',paddingTop:6}}><span>Gesamt</span><span>{fmtMoney(totals.total,cur)}</span></div>
            </div>
          </div>
          <div style={{gridColumn:'1/-1'}}>
            <div style={{display:'flex',alignItems:'center',marginBottom:10}}>
              <label style={{...lbl,marginBottom:0,flex:1}}>Positionen</label>
              <div style={{display:'flex',gap:6}}>
                <button className="btn btn-ghost btn-sm" onClick={addHeading} style={{fontSize:12}}>+ Abschnitt</button>
                <button className="btn btn-ghost btn-sm" onClick={addItem} style={{fontSize:12}}>+ Position</button>
              </div>
            </div>
            <div style={{border:'1px solid #EEEAE5',borderRadius:10,overflow:'hidden'}}>
              {(inv.items||[]).map((it,idx)=>
                it.type==='heading'?(
                  <div key={it.id} style={{display:'flex',gap:8,alignItems:'center',padding:'8px 12px',background:'#F7F5F2',borderBottom:idx<inv.items.length-1?'1px solid #EEEAE5':'none'}}>
                    <span style={{fontSize:10,color:'#A8A39D',fontWeight:600,textTransform:'uppercase',letterSpacing:'0.06em',minWidth:60}}>Abschnitt</span>
                    <input value={it.description} onChange={e=>updateItem(it.id,'description',e.target.value)} placeholder="Bezeichnung…" style={{flex:1,fontWeight:400,background:'transparent',border:'none',fontSize:13}}/>
                    <button onClick={()=>removeItem(it.id)} style={{background:'none',border:'none',color:'#DDD',cursor:'pointer',fontSize:16,lineHeight:1}} onMouseEnter={e=>e.currentTarget.style.color='#C0392B'} onMouseLeave={e=>e.currentTarget.style.color='#DDD'}>×</button>
                  </div>
                ):(
                  <div key={it.id} style={{display:'grid',gridTemplateColumns:'24px 1fr 64px 88px 88px 28px',gap:8,alignItems:'center',padding:'8px 12px',borderBottom:idx<inv.items.length-1?'1px solid #EEEAE5':'none'}}>
                    <span style={{fontSize:11,color:'#C8C3BD',textAlign:'center',fontVariantNumeric:'tabular-nums'}}>{(inv.items||[]).filter((x,i)=>x.type!=='heading'&&i<=idx).length}</span>
                    <input value={it.description} onChange={e=>updateItem(it.id,'description',e.target.value)} placeholder="Leistungsbeschreibung…" style={{fontSize:13}}/>
                    <input type="number" value={it.quantity} onChange={e=>updateItem(it.id,'quantity',e.target.value)} placeholder="Mge" style={{textAlign:'center',fontSize:12}} min={0}/>
                    <input type="number" value={it.unitPrice} onChange={e=>updateItem(it.id,'unitPrice',e.target.value)} placeholder="EP" style={{textAlign:'right',fontSize:12}} min={0}/>
                    <span style={{textAlign:'right',fontSize:12,fontWeight:600,fontVariantNumeric:'tabular-nums',color:'#141210'}}>{fmtMoney((Number(it.quantity)||0)*(Number(it.unitPrice)||0),cur)}</span>
                    <button onClick={()=>removeItem(it.id)} style={{background:'none',border:'none',color:'#DDD',cursor:'pointer',fontSize:16,lineHeight:1}} onMouseEnter={e=>e.currentTarget.style.color='#C0392B'} onMouseLeave={e=>e.currentTarget.style.color='#DDD'}>×</button>
                  </div>
                )
              )}
              {(inv.items||[]).length===0&&<div style={{padding:'20px',textAlign:'center',color:'#C8C3BD',fontSize:13}}>Noch keine Positionen.</div>}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function InvoicePreview({invoice, settings, invoiceSettings, onClose}){
  const totals=quoteTotals(invoice);
  const cur=settings?.currency||'EUR';
  const accent=settings?.accentColor||'#141210';
  const fmtD=iso=>iso?new Date(iso).toLocaleDateString('de-AT',{day:'2-digit',month:'long',year:'numeric'}):'';
  const status=INVOICE_STATUSES.find(s=>s.key===invoice.status)||INVOICE_STATUSES[0];
  const isOverdue=invoice.dueDate&&invoice.status!=='bezahlt'&&invoice.status!=='storniert'&&new Date(invoice.dueDate)<new Date();
  const sections=[];let cur2={heading:null,items:[]};
  (invoice.items||[]).forEach(it=>{if(it.type==='heading'){if(cur2.items.length||cur2.heading)sections.push(cur2);cur2={heading:it.description,items:[]};}else cur2.items.push(it);});
  if(cur2.items.length||cur2.heading)sections.push(cur2);
  const allItems=(invoice.items||[]).filter(it=>it.type!=='heading');
  return(
    <div className="quote-print-page" style={{position:'fixed',inset:0,zIndex:1001,overflow:'auto'}}>
      <div className="quote-no-print" style={{position:'sticky',top:0,zIndex:10,background:'rgba(15,14,12,0.92)',backdropFilter:'blur(8px)',padding:'12px 20px',display:'flex',gap:10,alignItems:'center',boxShadow:'0 4px 20px rgba(0,0,0,0.2)'}}>
        <div style={{color:'rgba(255,255,255,0.5)',fontSize:12.5,marginRight:'auto',display:'flex',alignItems:'center',gap:10}}>
          <span style={{color:'white',fontFamily:'monospace'}}>{invoice.number}</span>
          <span style={{color:status.color,fontWeight:600,padding:'2px 8px',background:'rgba(255,255,255,0.1)',borderRadius:99,fontSize:11}}>{status.label}</span>
          {isOverdue&&<span style={{color:'#ef4444',fontWeight:600,fontSize:11}}>⚠ Überfällig</span>}
        </div>
        <button className="btn btn-ghost btn-sm" onClick={()=>{
          const paper=document.querySelector('.quote-paper');
          if(!paper)return;
          const html='<!DOCTYPE html><html><head><meta charset="utf-8"><title>'+invoice.number+'</title></head><body style="margin:0;padding:20px;font-family:sans-serif">'+paper.outerHTML+'</body></html>';
          const a=document.createElement('a');
          a.href=URL.createObjectURL(new Blob([html],{type:'text/html'}));
          a.download=(invoice.number||'rechnung')+'.html';
          a.click();URL.revokeObjectURL(a.href);
        }} style={{color:'rgba(255,255,255,0.7)',borderColor:'rgba(255,255,255,0.2)'}}>💾 Als HTML speichern</button>
        <button className="btn btn-primary btn-sm" onClick={()=>window.print()}><Icons.Print/>Drucken / PDF</button>
        <button onClick={onClose} style={{background:'rgba(255,255,255,0.1)',border:'none',borderRadius:8,padding:8,color:'white',lineHeight:0,cursor:'pointer'}}><Icons.Close/></button>
      </div>
      <div className="quote-paper">
        {/* HEADER */}
        <div style={{display:'flex',justifyContent:'space-between',alignItems:'flex-start',marginBottom:'7mm'}}>
          <div>
            {settings?.logoUrl
              ?<><img src={settings.logoUrl} alt="Logo" style={{height:'13mm',maxWidth:'55mm',objectFit:'contain',marginBottom:'2mm',display:'block'}}/><div style={{fontSize:'10pt',fontWeight:700,color:accent}}>{settings?.companyName}</div></>
              :<div style={{fontSize:'15pt',fontWeight:800,color:accent,letterSpacing:'-0.02em'}}>{settings?.companyName||'Firma'}</div>
            }
            {settings?.companyAddress&&<div style={{fontSize:'7.5pt',color:'#7A7570',whiteSpace:'pre-line',lineHeight:1.5,marginTop:'1mm'}}>{settings.companyAddress}</div>}
            {settings?.companyEmail&&<div style={{fontSize:'7.5pt',color:'#7A7570'}}>{settings.companyEmail}</div>}
            {settings?.companyPhone&&<div style={{fontSize:'7.5pt',color:'#7A7570'}}>{settings.companyPhone}</div>}
            {settings?.taxId&&<div style={{fontSize:'7pt',color:'#9A9590',marginTop:'1mm'}}>UID: {settings.taxId}</div>}
          </div>
          <div style={{textAlign:'right'}}>
            <div style={{fontSize:'26pt',fontWeight:900,color:accent,letterSpacing:'-0.03em',lineHeight:1}}>RECHNUNG</div>
            <div style={{fontSize:'11pt',fontFamily:'monospace',fontWeight:600,color:'#6B6560',marginTop:'1.5mm'}}>{invoice.number}</div>
            {invoice.title&&<div style={{fontSize:'8.5pt',color:'#9A9590',marginTop:'1mm',maxWidth:'65mm',textAlign:'right'}}>{invoice.title}</div>}
          </div>
        </div>
        {/* META STRIP */}
        <div style={{borderTop:`2pt solid ${accent}`,paddingTop:'3mm',marginBottom:'5mm',display:'flex',gap:'3mm'}}>
          {[
            {label:'Rechnungsdatum',value:fmtD(invoice.date)},
            {label:invoice.serviceEndDate?'Leistungszeitraum':'Leistungsdatum',value:invoice.serviceEndDate?`${fmtD(invoice.serviceDate||invoice.date)} – ${fmtD(invoice.serviceEndDate)}`:fmtD(invoice.serviceDate||invoice.date)},
            {label:'Fällig am',value:fmtD(invoice.dueDate),warn:isOverdue},
            {label:'Rechnungs-Nr.',value:invoice.number},
          ].map(m=>(
            <div key={m.label} style={{flex:1,background:m.warn?'#FEF2F2':'#FAFAF8',borderRadius:'2mm',padding:'2.5mm 3.5mm',border:m.warn?'1pt solid #FECACA':'1pt solid #EEEAE5'}}>
              <div style={{fontSize:'6pt',color:m.warn?'#b91c1c':'#9A9590',textTransform:'uppercase',letterSpacing:'0.14em',fontWeight:700,marginBottom:'1mm'}}>{m.label}</div>
              <div style={{fontSize:'8.5pt',fontWeight:700,color:m.warn?'#b91c1c':'#141210'}}>{m.value}</div>
            </div>
          ))}
        </div>
        {/* ADDRESSES */}
        <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:'6mm',marginBottom:'6mm'}}>
          <div style={{padding:'3.5mm 4mm',background:'#FAFAF8',borderRadius:'2mm',border:'0.5pt solid #E5E1DC'}}>
            <div style={{fontSize:'6.5pt',color:'#9A9590',textTransform:'uppercase',letterSpacing:'0.14em',fontWeight:700,marginBottom:'1.5mm'}}>Rechnungsempfänger</div>
            <div style={{fontSize:'10.5pt',fontWeight:700,color:'#141210'}}>{invoice.contactSnapshot?.firma||'—'}</div>
            {invoice.contactSnapshot?.ansprechpartner&&<div style={{fontSize:'8.5pt',color:'#6B6560',marginTop:'0.5mm'}}>z.Hd. {invoice.contactSnapshot.ansprechpartner}</div>}
            {invoice.contactSnapshot?.address&&<div style={{fontSize:'8.5pt',color:'#3F3A35',marginTop:'1mm'}}>{invoice.contactSnapshot.address}</div>}
            {(invoice.contactSnapshot?.zip||invoice.contactSnapshot?.city)&&<div style={{fontSize:'8.5pt',color:'#3F3A35'}}>{[invoice.contactSnapshot.zip,invoice.contactSnapshot.city].filter(Boolean).join(' ')}</div>}
            {invoice.contactSnapshot?.country&&<div style={{fontSize:'8.5pt',color:'#3F3A35'}}>{invoice.contactSnapshot.country}</div>}
            {invoice.contactSnapshot?.taxId&&<div style={{fontSize:'7.5pt',color:'#6B6560',marginTop:'1.5mm',fontFamily:'monospace'}}>UID: {invoice.contactSnapshot.taxId}</div>}
            {invoice.contactSnapshot?.email&&<div style={{fontSize:'7.5pt',color:'#9A9590',marginTop:'1mm'}}>{invoice.contactSnapshot.email}</div>}
          </div>
          <div style={{padding:'3.5mm 4mm',background:'#FAFAF8',borderRadius:'2mm',border:'0.5pt solid #E5E1DC'}}>
            <div style={{fontSize:'6.5pt',color:'#9A9590',textTransform:'uppercase',letterSpacing:'0.14em',fontWeight:700,marginBottom:'1.5mm'}}>Rechnungssteller</div>
            <div style={{fontSize:'10.5pt',fontWeight:700,color:'#141210'}}>{settings?.companyName||'—'}</div>
            {settings?.companyAddress&&<div style={{fontSize:'8.5pt',color:'#3F3A35',whiteSpace:'pre-line',lineHeight:1.4,marginTop:'1mm'}}>{settings.companyAddress}</div>}
            {settings?.taxId&&<div style={{fontSize:'7.5pt',color:'#6B6560',marginTop:'1.5mm',fontFamily:'monospace'}}>UID: {settings.taxId}</div>}
            {settings?.companyEmail&&<div style={{fontSize:'7.5pt',color:'#9A9590',marginTop:'1mm'}}>{settings.companyEmail}</div>}
          </div>
        </div>
        {/* ITEMS TABLE */}
        <div className="quote-section" style={{marginBottom:'5mm'}}>
          <div style={{display:'grid',gridTemplateColumns:'28px 1fr 40px 62px 62px',gap:0,background:accent,borderRadius:'2mm 2mm 0 0',padding:'3mm 4mm'}}>
            {['Nr.','Beschreibung','Mge','EP','GP'].map((h,i)=>(
              <div key={h} style={{fontSize:'6.5pt',fontWeight:700,color:'rgba(255,255,255,0.85)',textTransform:'uppercase',letterSpacing:'0.1em',textAlign:i>=2?'right':'left'}}>{h}</div>
            ))}
          </div>
          <div style={{border:`1pt solid ${accent}`,borderTop:'none',borderRadius:'0 0 2mm 2mm',overflow:'hidden'}}>
            {sections.map((sec,sIdx)=>(
              <React.Fragment key={sIdx}>
                {sec.heading&&<div style={{background:'#F3F0EB',padding:'2mm 4mm',fontSize:'9pt',fontWeight:700,color:'#141210',borderBottom:'0.5pt solid #E5E1DC'}}>{sec.heading}</div>}
                {sec.items.map((it,iIdx)=>{
                  const pos=allItems.indexOf(it)+1;
                  const lineTotal=(Number(it.quantity)||0)*(Number(it.unitPrice)||0);
                  return(
                    <div key={it.id} style={{display:'grid',gridTemplateColumns:'28px 1fr 40px 62px 62px',gap:0,padding:'3mm 4mm',background:iIdx%2===0?'white':'#FAFAF8',borderBottom:(sIdx<sections.length-1||iIdx<sec.items.length-1)?'0.4pt solid #EFEBE6':'none',alignItems:'start'}}>
                      <div style={{fontSize:'8.5pt',color:'#9A9590',fontVariantNumeric:'tabular-nums'}}>{pos}</div>
                      <div style={{fontSize:'9.5pt',color:'#1F1B17',lineHeight:1.4,whiteSpace:'pre-line'}}>{it.description}</div>
                      <div style={{fontSize:'9pt',color:'#6B6560',textAlign:'right'}}>{it.quantity}</div>
                      <div style={{fontSize:'9pt',color:'#6B6560',textAlign:'right',fontVariantNumeric:'tabular-nums'}}>{fmtMoney(it.unitPrice,cur)}</div>
                      <div style={{fontSize:'9.5pt',fontWeight:600,color:'#141210',textAlign:'right',fontVariantNumeric:'tabular-nums'}}>{fmtMoney(lineTotal,cur)}</div>
                    </div>
                  );
                })}
              </React.Fragment>
            ))}
          </div>
        </div>
        {/* TOTALS */}
        <div style={{display:'flex',justifyContent:'flex-end',marginBottom:'5mm'}}>
          <div style={{minWidth:'58mm',border:`1pt solid ${accent}`,borderRadius:'2mm',overflow:'hidden'}}>
            <div style={{padding:'3mm 4mm',display:'grid',gridTemplateColumns:'1fr auto',gap:'1.5mm 6mm',fontSize:'9pt'}}>
              <div style={{color:'#6B6560'}}>Zwischensumme</div><div style={{textAlign:'right',fontVariantNumeric:'tabular-nums'}}>{fmtMoney(totals.subtotal,cur)}</div>
              {totals.discount>0&&<><div style={{color:'#6B6560'}}>Rabatt</div><div style={{textAlign:'right',fontVariantNumeric:'tabular-nums'}}>−{fmtMoney(totals.discount,cur)}</div></>}
              <div style={{color:'#6B6560'}}>USt {invoice.taxRate}%</div><div style={{textAlign:'right',fontVariantNumeric:'tabular-nums'}}>{fmtMoney(totals.tax,cur)}</div>
            </div>
            <div style={{background:accent,padding:'3mm 4mm',display:'flex',justifyContent:'space-between',alignItems:'baseline'}}>
              <div style={{fontSize:'8.5pt',fontWeight:700,color:'white',textTransform:'uppercase',letterSpacing:'0.08em'}}>Gesamt</div>
              <div style={{fontSize:'13pt',fontWeight:800,color:'white',fontVariantNumeric:'tabular-nums',letterSpacing:'-0.02em'}}>{fmtMoney(totals.total,cur)}</div>
            </div>
          </div>
        </div>
        {/* PAYMENT INFO */}
        {(settings?.iban||settings?.bankName||invoice.paymentNote)&&(
          <div className="quote-section" style={{marginBottom:'5mm',padding:'3.5mm 5mm',background:'#F3F0EB',borderRadius:'2mm',borderLeft:`3pt solid ${accent}`}}>
            <div style={{fontSize:'6.5pt',color:'#9A9590',textTransform:'uppercase',letterSpacing:'0.14em',fontWeight:700,marginBottom:'1.5mm'}}>Zahlungsinformationen</div>
            {invoice.paymentNote&&<div style={{fontSize:'8.5pt',color:'#3F3A35',marginBottom:'1.5mm',lineHeight:1.5}}>{invoice.paymentNote}</div>}
            <div style={{display:'flex',gap:'5mm',flexWrap:'wrap',fontSize:'8pt'}}>
              {settings?.bankName&&<div><span style={{color:'#9A9590'}}>Bank: </span><span style={{fontWeight:600}}>{settings.bankName}</span></div>}
              {settings?.iban&&<div><span style={{color:'#9A9590'}}>IBAN: </span><span style={{fontFamily:'monospace',fontWeight:600}}>{settings.iban}</span></div>}
              {settings?.bic&&<div><span style={{color:'#9A9590'}}>BIC: </span><span style={{fontFamily:'monospace',fontWeight:600}}>{settings.bic}</span></div>}
            </div>
            <div style={{marginTop:'1.5mm',fontSize:'7.5pt',color:'#9A9590'}}>Zahlungsziel: {fmtD(invoice.dueDate)}</div>
          </div>
        )}
        {/* hidden data island for HTML re-import */}
        <div id="crm-invoice-data" style={{display:'none'}} data-json={btoa(unescape(encodeURIComponent(JSON.stringify(invoice))))}></div>
        {/* LEGAL NOTE */}
        <div style={{marginBottom:'3mm',fontSize:'7.5pt',color:'#6B6560',lineHeight:1.5,fontStyle:'italic'}}>
          Diese Rechnung wurde elektronisch erstellt und ist auch ohne Unterschrift gültig.
        </div>
        {/* FOOTER */}
        <div style={{paddingTop:'3mm',borderTop:'0.5pt solid #E5E1DC',display:'flex',gap:'6mm',fontSize:'7pt',color:'#9A9590',lineHeight:1.5}}>
          <div style={{flex:1}}><div style={{fontWeight:600,color:'#5F5A55',marginBottom:'0.5mm'}}>{settings?.companyName}</div>{settings?.companyAddress&&<div style={{whiteSpace:'pre-line'}}>{settings.companyAddress}</div>}</div>
          <div style={{flex:1}}><div style={{fontWeight:600,color:'#5F5A55',marginBottom:'0.5mm'}}>Kontakt</div>{settings?.companyEmail&&<div>{settings.companyEmail}</div>}{settings?.companyPhone&&<div>{settings.companyPhone}</div>}{settings?.taxId&&<div>UID: {settings.taxId}</div>}</div>
          {(settings?.iban||settings?.bankName)&&<div style={{flex:1}}><div style={{fontWeight:600,color:'#5F5A55',marginBottom:'0.5mm'}}>Bankverbindung</div>{settings?.bankName&&<div>{settings.bankName}</div>}{settings?.iban&&<div style={{fontFamily:'monospace'}}>{settings.iban}</div>}</div>}
        </div>
      </div>
    </div>
  );
}

// ── Mahnung Preview ─────────────────────────────────────────────
function MahnungPreview({invoice, settings, onSave, onClose}){
  const totals=quoteTotals(invoice);
  const cur=settings?.currency||'EUR';
  const accent=settings?.accentColor||'#141210';
  const mahnLevel=(invoice.mahnungen?.length||0)+1;
  const levelLabel=mahnLevel===1?'1. Mahnung':mahnLevel===2?'2. Mahnung':`${mahnLevel}. Mahnung`;
  const fmtD=iso=>iso?new Date(iso).toLocaleDateString('de-AT',{day:'2-digit',month:'long',year:'numeric'}):'';
  const today=new Date().toISOString().slice(0,10);
  const [newDueDate,setNewDueDate]=useState(new Date(Date.now()+14*86400000).toISOString().slice(0,10));
  const [note,setNote]=useState('');
  const [saved,setSaved]=useState(false);
  const doSave=()=>{
    const m={id:uid(),level:mahnLevel,date:today,newDueDate,note};
    onSave({...invoice,mahnungen:[...(invoice.mahnungen||[]),m]});
    setSaved(true);
  };
  return(
    <div className="quote-print-page" style={{position:'fixed',inset:0,zIndex:1001,overflow:'auto'}}>
      <div className="quote-no-print" style={{position:'sticky',top:0,zIndex:10,background:'rgba(15,14,12,0.92)',backdropFilter:'blur(8px)',padding:'12px 20px',display:'flex',gap:10,alignItems:'center',flexWrap:'wrap',boxShadow:'0 4px 20px rgba(0,0,0,0.2)'}}>
        <div style={{color:'rgba(255,255,255,0.5)',fontSize:12.5,display:'flex',alignItems:'center',gap:10}}>
          <span style={{color:'white',fontFamily:'monospace'}}>{invoice.number}</span>
          <span style={{color:'#fbbf24',fontWeight:600,padding:'2px 8px',background:'rgba(255,255,255,0.1)',borderRadius:99,fontSize:11}}>🔔 {levelLabel}</span>
        </div>
        <div style={{display:'flex',alignItems:'center',gap:8,flexWrap:'wrap'}}>
          <label style={{color:'rgba(255,255,255,0.6)',fontSize:12}}>Neues Zahlungsziel:</label>
          <input type="date" value={newDueDate} onChange={e=>setNewDueDate(e.target.value)} style={{fontSize:12,padding:'5px 8px',borderRadius:6,border:'1px solid rgba(255,255,255,0.2)',background:'rgba(255,255,255,0.1)',color:'white'}}/>
        </div>
        <div style={{display:'flex',alignItems:'center',gap:8}}>
          <label style={{color:'rgba(255,255,255,0.6)',fontSize:12}}>Zusatz-Text:</label>
          <input value={note} onChange={e=>setNote(e.target.value)} placeholder="Optionaler Hinweis…" style={{fontSize:12,padding:'5px 8px',borderRadius:6,border:'1px solid rgba(255,255,255,0.2)',background:'rgba(255,255,255,0.1)',color:'white',width:200}}/>
        </div>
        <div style={{flex:1}}/>
        <button className="btn btn-ghost btn-sm" onClick={()=>{const paper=document.querySelector('.mahnung-paper');if(!paper)return;const html='<!DOCTYPE html><html><head><meta charset="utf-8"><title>Mahnung '+invoice.number+'</title></head><body style="margin:0;padding:20px;font-family:sans-serif">'+paper.outerHTML+'</body></html>';const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([html],{type:'text/html'}));a.download='mahnung-'+invoice.number+'.html';a.click();URL.revokeObjectURL(a.href);}} style={{color:'rgba(255,255,255,0.7)',borderColor:'rgba(255,255,255,0.2)'}}>💾 Als HTML</button>
        <button className="btn btn-primary btn-sm" onClick={()=>window.print()}><Icons.Print/>Drucken / PDF</button>
        {saved
          ?<span style={{color:'#4ade80',fontWeight:600,fontSize:12.5}}>✓ Gespeichert</span>
          :<button onClick={doSave} style={{background:'#f59e0b',border:'none',borderRadius:8,padding:'6px 14px',cursor:'pointer',color:'white',fontSize:12.5,fontWeight:600}}>✓ Als gesendet markieren</button>
        }
        <button onClick={onClose} style={{background:'rgba(255,255,255,0.1)',border:'none',borderRadius:8,padding:8,color:'white',lineHeight:0,cursor:'pointer'}}><Icons.Close/></button>
      </div>
      <div className="mahnung-paper quote-paper">
        <div style={{display:'flex',justifyContent:'space-between',alignItems:'flex-start',marginBottom:'7mm'}}>
          <div>
            {settings?.logoUrl
              ?<><img src={settings.logoUrl} alt="Logo" style={{height:'13mm',maxWidth:'55mm',objectFit:'contain',marginBottom:'2mm',display:'block'}}/><div style={{fontSize:'10pt',fontWeight:700,color:accent}}>{settings?.companyName}</div></>
              :<div style={{fontSize:'15pt',fontWeight:800,color:accent,letterSpacing:'-0.02em'}}>{settings?.companyName||'Firma'}</div>
            }
            {settings?.companyAddress&&<div style={{fontSize:'7.5pt',color:'#7A7570',whiteSpace:'pre-line',lineHeight:1.5,marginTop:'1mm'}}>{settings.companyAddress}</div>}
            {settings?.companyEmail&&<div style={{fontSize:'7.5pt',color:'#7A7570'}}>{settings.companyEmail}</div>}
            {settings?.companyPhone&&<div style={{fontSize:'7.5pt',color:'#7A7570'}}>{settings.companyPhone}</div>}
            {settings?.taxId&&<div style={{fontSize:'7pt',color:'#9A9590',marginTop:'1mm'}}>UID: {settings.taxId}</div>}
          </div>
          <div style={{textAlign:'right'}}>
            <div style={{fontSize:'26pt',fontWeight:900,color:'#b91c1c',letterSpacing:'-0.03em',lineHeight:1}}>{levelLabel.toUpperCase()}</div>
            <div style={{fontSize:'9pt',color:'#6B6560',marginTop:'1.5mm'}}>zu Rechnung <span style={{fontFamily:'monospace',fontWeight:600}}>{invoice.number}</span></div>
            <div style={{fontSize:'8pt',color:'#9A9590',marginTop:'1mm'}}>{fmtD(today)}</div>
          </div>
        </div>
        <div style={{marginBottom:'8mm',padding:'3.5mm 4mm',background:'#FAFAF8',borderRadius:'2mm',border:'0.5pt solid #E5E1DC',display:'inline-block',minWidth:'60mm'}}>
          <div style={{fontSize:'10.5pt',fontWeight:700,color:'#141210'}}>{invoice.contactSnapshot?.firma||'—'}</div>
          {invoice.contactSnapshot?.ansprechpartner&&<div style={{fontSize:'8.5pt',color:'#6B6560',marginTop:'0.5mm'}}>z.Hd. {invoice.contactSnapshot.ansprechpartner}</div>}
          {invoice.contactSnapshot?.address&&<div style={{fontSize:'8.5pt',color:'#3F3A35',marginTop:'1mm'}}>{invoice.contactSnapshot.address}</div>}
          {(invoice.contactSnapshot?.zip||invoice.contactSnapshot?.city)&&<div style={{fontSize:'8.5pt',color:'#3F3A35'}}>{[invoice.contactSnapshot.zip,invoice.contactSnapshot.city].filter(Boolean).join(' ')}</div>}
          {invoice.contactSnapshot?.country&&<div style={{fontSize:'8.5pt',color:'#3F3A35'}}>{invoice.contactSnapshot.country}</div>}
        </div>
        <div style={{marginBottom:'4mm'}}><div style={{fontSize:'11pt',fontWeight:700,color:'#141210'}}>Betreff: {levelLabel} zu Rechnung {invoice.number}{invoice.title?` — ${invoice.title}`:''}</div></div>
        <div style={{fontSize:'10pt',color:'#1F1B17',lineHeight:1.7,marginBottom:'5mm'}}>
          <p style={{marginBottom:'3mm'}}>Sehr geehrte Damen und Herren,</p>
          <p style={{marginBottom:'3mm'}}>{mahnLevel===1?'trotz des bereits abgelaufenen Zahlungsziels haben wir bis heute keinen Zahlungseingang für die nachstehende Rechnung feststellen können. Wir bitten Sie, dies auf eine Unachtsamkeit zurückzuführen und ersuchen um umgehende Begleichung des offenen Betrages.':`wir haben Ihnen bereits ${mahnLevel-1}. Mahnung${mahnLevel-1>1?'en':''} zugesandt, jedoch ist der ausstehende Betrag nach wie vor nicht eingegangen. Wir ersuchen Sie dringend, den offenen Betrag umgehend zu begleichen.`}</p>
        </div>
        <div style={{marginBottom:'5mm',border:`1pt solid ${accent}`,borderRadius:'2mm',overflow:'hidden'}}>
          <div style={{background:accent,padding:'3mm 4mm',display:'grid',gridTemplateColumns:'1fr 90px 90px',gap:'2mm'}}>
            {['Beschreibung','Fällig am','Betrag'].map((h,i)=>(
              <div key={h} style={{fontSize:'6.5pt',fontWeight:700,color:'rgba(255,255,255,0.85)',textTransform:'uppercase',letterSpacing:'0.1em',textAlign:i>0?'right':'left'}}>{h}</div>
            ))}
          </div>
          <div style={{background:'white',padding:'3mm 4mm',display:'grid',gridTemplateColumns:'1fr 90px 90px',gap:'2mm',alignItems:'center'}}>
            <div>
              <div style={{fontSize:'9.5pt',fontWeight:600,color:'#141210'}}>Rechnung {invoice.number}</div>
              {invoice.title&&<div style={{fontSize:'8pt',color:'#6B6560'}}>{invoice.title}</div>}
              <div style={{fontSize:'8pt',color:'#9A9590',marginTop:'0.5mm'}}>Rechnungsdatum: {fmtD(invoice.date)}</div>
            </div>
            <div style={{textAlign:'right',fontSize:'9pt',color:'#b91c1c',fontWeight:600}}>{fmtD(invoice.dueDate)}</div>
            <div style={{textAlign:'right',fontSize:'11pt',fontWeight:700,color:'#b91c1c',fontVariantNumeric:'tabular-nums'}}>{fmtMoney(totals.total,cur)}</div>
          </div>
          <div style={{background:'#FEF2F2',padding:'3mm 4mm',display:'flex',justifyContent:'space-between',alignItems:'center',borderTop:'0.5pt solid #FECACA'}}>
            <div style={{fontSize:'9pt',fontWeight:700,color:'#b91c1c'}}>Offener Betrag</div>
            <div style={{fontSize:'13pt',fontWeight:800,color:'#b91c1c',fontVariantNumeric:'tabular-nums'}}>{fmtMoney(totals.total,cur)}</div>
          </div>
        </div>
        <div style={{marginBottom:'5mm',padding:'3.5mm 5mm',background:'#FEF2F2',borderRadius:'2mm',borderLeft:'3pt solid #b91c1c'}}>
          <div style={{fontSize:'9.5pt',color:'#141210',lineHeight:1.6}}>Wir ersuchen Sie, den Betrag von <strong>{fmtMoney(totals.total,cur)}</strong> bis spätestens <strong>{fmtD(newDueDate)}</strong> auf das unten angegebene Konto zu überweisen. Bitte geben Sie als Verwendungszweck die Rechnungsnummer <strong>{invoice.number}</strong> an.</div>
        </div>
        {note&&<div style={{marginBottom:'5mm',fontSize:'9.5pt',color:'#1F1B17',lineHeight:1.6,whiteSpace:'pre-line'}}>{note}</div>}
        <div style={{fontSize:'10pt',color:'#1F1B17',lineHeight:1.7,marginBottom:'8mm'}}>
          <p style={{marginBottom:'3mm'}}>Bei bereits erfolgter Zahlung bitten wir Sie, dieses Schreiben als gegenstandslos zu betrachten. Bei Fragen stehen wir Ihnen gerne zur Verfügung.</p>
          <p>Mit freundlichen Grüßen,</p>
          <p style={{marginTop:'6mm',fontWeight:700}}>{settings?.companyName||''}</p>
        </div>
        {(settings?.iban||settings?.bankName||invoice.paymentNote)&&(
          <div style={{marginBottom:'5mm',padding:'3.5mm 5mm',background:'#F3F0EB',borderRadius:'2mm',borderLeft:`3pt solid ${accent}`}}>
            <div style={{fontSize:'6.5pt',color:'#9A9590',textTransform:'uppercase',letterSpacing:'0.14em',fontWeight:700,marginBottom:'1.5mm'}}>Zahlungsinformationen</div>
            {invoice.paymentNote&&<div style={{fontSize:'8.5pt',color:'#3F3A35',marginBottom:'1.5mm',lineHeight:1.5}}>{invoice.paymentNote}</div>}
            <div style={{display:'flex',gap:'5mm',flexWrap:'wrap',fontSize:'8pt'}}>
              {settings?.bankName&&<div><span style={{color:'#9A9590'}}>Bank: </span><span style={{fontWeight:600}}>{settings.bankName}</span></div>}
              {settings?.iban&&<div><span style={{color:'#9A9590'}}>IBAN: </span><span style={{fontFamily:'monospace',fontWeight:600}}>{settings.iban}</span></div>}
              {settings?.bic&&<div><span style={{color:'#9A9590'}}>BIC: </span><span style={{fontFamily:'monospace',fontWeight:600}}>{settings.bic}</span></div>}
            </div>
          </div>
        )}
        <div style={{paddingTop:'3mm',borderTop:'0.5pt solid #E5E1DC',display:'flex',gap:'6mm',fontSize:'7pt',color:'#9A9590',lineHeight:1.5}}>
          <div style={{flex:1}}><div style={{fontWeight:600,color:'#5F5A55',marginBottom:'0.5mm'}}>{settings?.companyName}</div>{settings?.companyAddress&&<div style={{whiteSpace:'pre-line'}}>{settings.companyAddress}</div>}</div>
          <div style={{flex:1}}><div style={{fontWeight:600,color:'#5F5A55',marginBottom:'0.5mm'}}>Kontakt</div>{settings?.companyEmail&&<div>{settings.companyEmail}</div>}{settings?.companyPhone&&<div>{settings.companyPhone}</div>}{settings?.taxId&&<div>UID: {settings.taxId}</div>}</div>
          {(settings?.iban||settings?.bankName)&&<div style={{flex:1}}><div style={{fontWeight:600,color:'#5F5A55',marginBottom:'0.5mm'}}>Bankverbindung</div>{settings?.bankName&&<div>{settings.bankName}</div>}{settings?.iban&&<div style={{fontFamily:'monospace'}}>{settings.iban}</div>}</div>}
        </div>
      </div>
    </div>
  );
}

// ── Snapshot Restore Modal ───────────────────────────────────────
function SnapshotRestoreModal({cryptoKey, onRestore, onClose}){
  const [snaps] = useState(()=>getLocalSnapshots());
  const [busy,setBusy]=useState(false);
  const [err,setErr]=useState('');
  const fmt=t=>new Date(t).toLocaleString('de-DE',{day:'2-digit',month:'2-digit',year:'numeric',hour:'2-digit',minute:'2-digit'});
  const restore=async(snap)=>{
    setBusy(true);setErr('');
    try{
      const data=await aesDecrypt(cryptoKey,snap.d);
      if(!data){setErr('Entschlüsselung fehlgeschlagen — falsches Passwort?');setBusy(false);return;}
      onRestore(data);onClose();
    }catch(e){setErr(e.message);}
    setBusy(false);
  };
  return(
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-box" onClick={e=>e.stopPropagation()} style={{width:500}}>
        <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:20}}>
          <div><h2 style={{fontSize:17,fontWeight:700}}>🕐 Snapshots wiederherstellen</h2>
          <p style={{fontSize:12.5,color:'#A8A39D',marginTop:3}}>Automatisch gespeicherte lokale Sicherungen. Keine Internetverbindung nötig.</p></div>
          <button onClick={onClose} style={{background:'#F5F3F0',border:'none',borderRadius:8,padding:8,color:'#999',lineHeight:0,flexShrink:0}}><Icons.Close/></button>
        </div>
        {snaps.length===0?(
          <div style={{textAlign:'center',padding:'32px 0',color:'#C8C3BD'}}>
            <div style={{fontSize:36,marginBottom:10}}>🗄</div>
            <div style={{fontSize:14,fontWeight:600,color:'#C0BBB5'}}>Noch keine Snapshots vorhanden.</div>
            <div style={{fontSize:12.5,marginTop:6,color:'#C8C3BD'}}>Die ersten werden automatisch beim nächsten Speichern angelegt.</div>
          </div>
        ):(
          <div style={{display:'flex',flexDirection:'column',gap:8}}>
            {snaps.map((s,idx)=>(
              <div key={s.i} style={{display:'flex',alignItems:'center',justifyContent:'space-between',background:'#F8F7F5',borderRadius:10,padding:'13px 16px',border:'1px solid rgba(0,0,0,0.06)'}}>
                <div>
                  <div style={{fontWeight:600,fontSize:13.5}}>{fmt(s.t)}</div>
                  <div style={{fontSize:11.5,color:'#A8A39D',marginTop:2}}>{idx===0?'Neuester Snapshot':'Älterer Snapshot'}</div>
                </div>
                <button className="btn btn-primary btn-sm" onClick={()=>restore(s)} disabled={busy} style={{fontSize:12}}>
                  {busy?'…':'Wiederherstellen'}
                </button>
              </div>
            ))}
          </div>
        )}
        {err&&<div style={{marginTop:12,padding:'10px 14px',background:'#FEF2F2',borderRadius:8,color:'#C0392B',fontSize:13}}>{err}</div>}
        <div style={{marginTop:16,padding:'10px 14px',background:'#F0FDF4',borderRadius:8,fontSize:12,color:'#15803d'}}>
          ✓ Snapshots werden alle 4 Stunden automatisch gespeichert — auch ohne Internet und ohne GitHub-Token.
        </div>
      </div>
    </div>
  );
}

// ── Invoice File Parsing ─────────────────────────────────────────
async function loadTesseract(){
  if(window.Tesseract)return window.Tesseract;
  return new Promise((resolve,reject)=>{
    const s=document.createElement('script');
    s.src='https://cdn.jsdelivr.net/npm/tesseract.js@5/dist/tesseract.min.js';
    s.onload=()=>resolve(window.Tesseract);
    s.onerror=()=>reject(new Error('Tesseract.js konnte nicht geladen werden.'));
    document.head.appendChild(s);
  });
}
async function extractPdfDataOcr(file,onProgress){
  const lib=await loadPdfJs();
  const buf=await file.arrayBuffer();
  const pdf=await lib.getDocument({data:buf}).promise;
  if(onProgress)onProgress('Tesseract wird geladen…');
  const Tess=await loadTesseract();
  const worker=await Tess.createWorker('deu');
  let fullText='';
  for(let p=1;p<=pdf.numPages;p++){
    if(onProgress)onProgress('OCR Seite '+p+'/'+pdf.numPages+'…');
    const page=await pdf.getPage(p);
    const vp=page.getViewport({scale:2.5});
    const canvas=document.createElement('canvas');
    canvas.width=vp.width;canvas.height=vp.height;
    await page.render({canvasContext:canvas.getContext('2d'),viewport:vp}).promise;
    const {data:{text}}=await worker.recognize(canvas);
    fullText+=text+'\n';
  }
  await worker.terminate();
  return{full:fullText,leftCol:''};
}
async function loadPdfJs(){
  if(window.pdfjsLib)return window.pdfjsLib;
  return new Promise((resolve,reject)=>{
    const s=document.createElement('script');
    s.src='https://cdn.jsdelivr.net/npm/pdfjs-dist@3.4.120/legacy/build/pdf.min.js';
    s.onload=()=>{window.pdfjsLib.GlobalWorkerOptions.workerSrc='https://cdn.jsdelivr.net/npm/pdfjs-dist@3.4.120/legacy/build/pdf.worker.min.js';resolve(window.pdfjsLib);};
    s.onerror=()=>reject(new Error('PDF.js konnte nicht geladen werden.'));
    document.head.appendChild(s);
  });
}
async function extractPdfData(file){
  const lib=await loadPdfJs();
  const buf=await file.arrayBuffer();
  const pdf=await lib.getDocument({data:buf}).promise;
  let fullLines=[],leftLines=[];
  for(let p=1;p<=pdf.numPages;p++){
    const page=await pdf.getPage(p);
    const vp=page.getViewport({scale:1});
    const midX=vp.width/2;
    const content=await page.getTextContent();
    const raw=content.items.filter(i=>i.str&&i.str.trim());
    // Group into rows by y-position (4pt tolerance)
    const rows=[];
    for(const item of raw){
      const y=item.transform[5];
      let row=rows.find(r=>Math.abs(r.y-y)<=4);
      if(!row){row={y,items:[]};rows.push(row);}
      row.items.push(item);
    }
    rows.sort((a,b)=>b.y-a.y);
    for(const row of rows){
      row.items.sort((a,b)=>a.transform[4]-b.transform[4]);
      fullLines.push(row.items.map(i=>i.str).join(' '));
      leftLines.push(row.items.filter(i=>i.transform[4]<midX).map(i=>i.str).join(' '));
    }
  }
  return {full:fullLines.join('\n'),leftCol:leftLines.join('\n')};
}
const _DE_MONTHS={januar:1,februar:2,märz:3,april:4,mai:5,juni:6,juli:7,august:8,september:9,oktober:10,november:11,dezember:12};
function parseDEDate(s){
  if(!s)return'';
  let m=s.match(/(\d{1,2})\.\s*([A-Za-zäöüÄÖÜ]+)\s+(\d{4})/);
  if(m){const mo=_DE_MONTHS[m[2].toLowerCase()];if(mo)return`${m[3]}-${String(mo).padStart(2,'0')}-${m[1].padStart(2,'0')}`;}
  m=s.match(/(\d{1,2})\.(\d{1,2})\.(\d{4})/);
  if(m)return`${m[3]}-${m[2].padStart(2,'0')}-${m[1].padStart(2,'0')}`;
  return'';
}
function parseInvoiceText(full,leftCol,existingContacts){
  const nfull=full.replace(/[–—]/g,'-');
  const nleft=(leftCol||'').replace(/[–—]/g,'-');
  const res={number:'',date:'',dueDate:'',serviceDate:'',taxRate:20,discount:0,firma:'',ansprechpartner:'',email:'',telefon:'',address:'',zip:'',city:'',country:'',taxId:'',items:[]};
  const fullLines=nfull.split('\n').map(s=>s.trim()).filter(s=>s);
  const leftLines=nleft.split('\n').map(s=>s.trim()).filter(s=>s);
  const dateRx=/\d{1,2}\.\s*(?:[A-Za-zäöüÄÖÜ]+\s+\d{4}|\d{1,2}\.\d{4})/g;
  // Normalize: collapse whitespace + uppercase → tolerant to letter-spacing artifacts
  const norm=s=>(s||'').replace(/\s+/g,'').toUpperCase();

  // Meta strip: row containing all 4 labels, values on next row
  for(let i=0;i<fullLines.length;i++){
    if(norm(fullLines[i]).includes('RECHNUNGSDATUM')){
      // values may be on i+1, sometimes split across i+1+i+2
      const val=(fullLines[i+1]||'')+' '+(fullLines[i+2]||'');
      const dates=[...val.matchAll(dateRx)].map(m=>parseDEDate(m[0])).filter(d=>d);
      if(dates[0])res.date=dates[0];
      if(dates[1])res.serviceDate=dates[1];
      if(dates[2])res.dueDate=dates[2];
      const inv=val.match(/([A-Z]{1,6}-\d{4}-\d{2,6})/);
      if(inv&&!res.number)res.number=inv[1];
      break;
    }
  }
  // Find the meta strip VALUES line (multiple dates on same line) — used for OCR fallback
  let metaValLineIdx=-1;
  for(let i=0;i<fullLines.length;i++){
    const dm=[...fullLines[i].matchAll(new RegExp(dateRx.source,'g'))];
    if(dm.length>=2){metaValLineIdx=i;break;}
  }
  // Invoice number: prefer from meta strip values line (avoids OCR header noise), then anywhere
  if(!res.number&&metaValLineIdx>=0){
    const m=fullLines[metaValLineIdx].match(/\b([A-Z]{1,4}-\d{4}-\d{2,6})\b/);
    if(m)res.number=m[1];
  }
  if(!res.number){const m=nfull.match(/\b([A-Z]{1,4}-\d{4}-\d{2,6})\b/);if(m)res.number=m[1];}
  // Date fallback: use meta strip values line or first 30 lines
  if(!res.date){
    const srcIdx=metaValLineIdx>=0?metaValLineIdx:0;
    for(let i=srcIdx;i<Math.min(srcIdx+5,fullLines.length);i++){
      const dm=[...fullLines[i].matchAll(new RegExp(dateRx.source,'g'))];
      if(dm.length>=2){
        const dates=dm.map(x=>parseDEDate(x[0])).filter(d=>d);
        if(dates[0])res.date=dates[0];
        if(dates[1])res.serviceDate=dates[1];
        if(dates[2])res.dueDate=dates[2];
        break;
      }
    }
  }
  if(!res.date){
    for(let i=0;i<Math.min(30,fullLines.length);i++){
      const dm=fullLines[i].match(dateRx);
      if(dm){res.date=parseDEDate(dm[0]);break;}
    }
  }
  // Due date fallback by label
  if(!res.dueDate){
    for(let i=0;i<fullLines.length;i++){
      if(/F.LLIG/i.test(fullLines[i])||norm(fullLines[i]).includes('FÄLLIGAM')||norm(fullLines[i]).includes('FALLIGAM')){
        const c=(fullLines[i]||'')+' '+(fullLines[i+1]||'')+' '+(fullLines[i+2]||'');
        const dm=c.match(dateRx);if(dm)res.dueDate=parseDEDate(dm[dm.length-1]);break;
      }
    }
  }
  // Tax rate
  const txM=nfull.match(/USt\s*(\d+)\s*%/i)||nfull.match(/MwSt[^%\d]*?(\d+)\s*%/i)||nfull.match(/(\d+)\s*%\s*(?:MwSt|USt)/i);
  if(txM)res.taxRate=parseInt(txM[1]);
  // Recipient — try left column first, fall back to full text (OCR mode)
  const parseRecipientBlock=(lines,startIdx,stopFn)=>{
    for(let i=startIdx+1;i<Math.min(startIdx+15,lines.length);i++){
      const l=lines[i];const nl=norm(l);
      if(!l||stopFn(nl))break;
      if(!res.firma&&!/^UID/i.test(l)&&!/@/.test(l)&&!/^\+?\d/.test(l)&&l.length>2&&!/^z\.?Hd/i.test(l))res.firma=l;
      else if(!res.ansprechpartner&&/^z\.?Hd/i.test(l))res.ansprechpartner=l.replace(/^z\.?Hd\.?\s*/i,'').trim();
      else if(!res.zip&&/^\d{4,5}\s+\S/.test(l)){const zm=l.match(/^(\d{4,5})\s+(.+)/);if(zm){res.zip=zm[1];res.city=zm[2].replace(/\s*(Österreich|Deutschland|Schweiz|Austria|Germany).*/i,'').trim();}}
      else if(!res.address&&/[a-zäöüA-ZÄÖÜ].*\s\d+[a-z]?\s*$/i.test(l))res.address=l;
      else if(!res.country&&/^(Österreich|Deutschland|Schweiz|Austria|Germany)/i.test(l))res.country=l;
      else if(!res.taxId&&/^UID:/i.test(l))res.taxId=l.replace(/^UID:\s*/i,'').trim();
      else if(!res.email&&/@/.test(l))res.email=l.trim();
      else if(!res.telefon&&/^\+?\d[\d\s()-]{5,}$/.test(l))res.telefon=l.trim();
    }
  };
  let ei=-1;
  for(let i=0;i<leftLines.length;i++){if(norm(leftLines[i]).includes('RECHNUNGSEMPF')){ei=i;break;}}
  if(ei>=0){
    parseRecipientBlock(leftLines,ei,nl=>nl.includes('RECHNUNGSSTELLER')||nl.includes('BESCHREIBUNG')||nl.includes('ZAHLUNGS')||nl.startsWith('NR.'));
  } else {
    for(let i=0;i<fullLines.length;i++){if(norm(fullLines[i]).includes('RECHNUNGSEMPF')){ei=i;break;}}
    if(ei>=0){
      parseRecipientBlock(fullLines,ei,nl=>nl.includes('RECHNUNGSSTELL')||nl.includes('BESCHREIBUNG')||nl.includes('ZAHLUNGS')||nl.startsWith('NR.'));
    } else if(metaValLineIdx>=0){
      // OCR mode: no label found — extract recipient from lines between meta strip and items table
      let itemsHdrIdx=fullLines.length;
      for(let i=metaValLineIdx+1;i<fullLines.length;i++){const nl=norm(fullLines[i]);if(nl.includes('BESCHREIBUNG')&&(nl.includes('EP')||nl.includes('GP')||nl.includes('MGE'))){itemsHdrIdx=i;break;}}
      // Detect sender company + sender UID from header (before meta strip values line)
      let senderCompany='',senderUid='';
      for(let i=0;i<metaValLineIdx;i++){
        const l=fullLines[i];
        if(!senderUid){const um=l.match(/^UID:\s*([A-Z]{2}\w+)/i);if(um)senderUid=um[1];}
        if(!senderCompany&&l.length>2&&l.length<60&&/^[A-ZÄÖÜa-zäöü]/.test(l)&&!/@/.test(l)&&!/^\+?\d/.test(l)&&!/^UID/i.test(l)&&![...l.matchAll(new RegExp(dateRx.source,'g'))].length){
          senderCompany=l;
        }
      }
      for(let i=metaValLineIdx+1;i<itemsHdrIdx;i++){
        const l=fullLines[i];
        if(!l)continue;
        if(!res.firma){
          // Strip sender company merged from right side
          let firm=l;
          if(senderCompany&&firm.includes(senderCompany))firm=firm.slice(0,firm.lastIndexOf(senderCompany)).trim();
          // Also strip anything after multiple spaces (right column artefact)
          firm=firm.split(/\s{3,}/)[0].trim();
          if(firm.length>1&&!/^UID/i.test(firm)&&!/@/.test(firm)&&!/^\+?\d/.test(firm))res.firma=firm;
        } else if(!res.address){
          // Take FIRST street+number pattern in line (not greedy — no spaces in street-name char class)
          const am=l.match(/([A-ZÄÖÜa-zäöü][\wäöüÄÖÜß-]+(?:\s[\wäöüÄÖÜß-]+)?\s\d+[a-zA-Z]?(?:\/\d+)?)/);
          if(am)res.address=am[1].trim();
        } else if(!res.zip){
          // Left part before "UID:" = recipient zip+city
          const zipPart=l.split(/\s{2,}|\s*UID:/i)[0].trim();
          const zm=zipPart.match(/^(\d{4,5})\s+(.+)/);
          if(zm){res.zip=zm[1];res.city=zm[2].trim();}
        } else if(!res.country&&/^(Österreich|Deutschland|Schweiz|Austria|Germany)/i.test(l)){
          res.country=l.match(/^(Österreich|Deutschland|Schweiz|Austria|Germany\w*)/i)[0];
        } else if(!res.taxId&&/^UID:/i.test(l)){
          const uid=l.replace(/^UID:\s*/i,'').split(/\s+/)[0].trim();
          if(uid&&uid!==senderUid)res.taxId=uid;
        } else if(!res.email&&/@/.test(l)){
          res.email=(l.match(/[\w.+-]+@[\w-]+\.[\w.]+/)||[])[0]||'';
        } else if(!res.telefon&&/^\+?\d[\d\s()-]{5,}/.test(l)){
          res.telefon=(l.match(/^\+?[\d\s()-]+/)||[''])[0].trim();
        }
      }
    }
  }
  if(!res.email){const m=nfull.match(/\b[\w.+-]+@[\w-]+\.[\w.]{2,}\b/);if(m)res.email=m[0];}
  // Match existing contact
  if(res.firma&&existingContacts){
    for(const c of existingContacts){
      if(c.firma&&c.firma.length>2&&(res.firma.toLowerCase().includes(c.firma.toLowerCase())||c.firma.toLowerCase().includes(res.firma.toLowerCase()))){res.firma=c.firma;break;}
    }
  }
  // Line items
  const parseDec=s=>parseFloat((s||'0').replace(/€/g,'').replace(/\./g,'').replace(',','.'))||0;
  const itemRx=/^(?:\d+\s+)?(.+?)\s+(\d+(?:[.,]\d+)?)\s+([\d.,]+)\s*€?\s+([\d.,]+)\s*€?\s*$/;
  const isStopLine=l=>/^(Zwischensumme|Nettobetrag|GESAMT|Gesamt|USt\s*\d|MwSt\s*\d|Summe|Rabatt\s+\d)/i.test(l);
  let inItems=false;
  for(let i=0;i<fullLines.length;i++){
    const l=fullLines[i];const nl=norm(l);
    if(nl.includes('BESCHREIBUNG')&&(nl.includes('EP')||nl.includes('GP')||nl.includes('MGE'))){inItems=true;continue;}
    if(inItems&&isStopLine(l))break;
    if(!inItems)continue;
    const m=l.match(itemRx);
    if(m){
      const desc=m[1].trim(),qty=parseDec(m[2]),ep=parseDec(m[3]);
      if(desc.length>=2&&qty>0&&ep>0&&!/^(Zwischensumme|Netto|Gesamt|MwSt|USt|Summe|Rabatt)/i.test(desc)){
        res.items.push({id:uid(),type:'item',description:desc,quantity:qty,unitPrice:ep});
        // Skip continuation description lines (formatting text, not item data)
        while(i+1<fullLines.length&&!isStopLine(fullLines[i+1])&&!fullLines[i+1].match(itemRx))i++;
      }
    }
  }
  if(res.items.length===0)res.items=[{id:uid(),type:'item',description:'',quantity:1,unitPrice:0}];
  return res;
}
function parseInvoiceHtml(html,existingContacts){
  const doc=new DOMParser().parseFromString(html,'text/html');
  const island=doc.getElementById('crm-invoice-data');
  if(island&&island.dataset.json){
    try{
      const inv=JSON.parse(decodeURIComponent(escape(atob(island.dataset.json))));
      return {number:inv.number||'',date:inv.date||'',dueDate:inv.dueDate||'',serviceDate:inv.serviceDate||'',taxRate:inv.taxRate||20,discount:inv.discount||0,firma:inv.contactSnapshot?.firma||'',ansprechpartner:inv.contactSnapshot?.ansprechpartner||'',email:inv.contactSnapshot?.email||'',telefon:inv.contactSnapshot?.telefon||'',address:inv.contactSnapshot?.address||'',zip:inv.contactSnapshot?.zip||'',city:inv.contactSnapshot?.city||'',country:inv.contactSnapshot?.country||'',taxId:inv.contactSnapshot?.taxId||'',items:inv.items||[{id:uid(),type:'item',description:'',quantity:1,unitPrice:0}],notes:inv.notes||'',paymentNote:inv.paymentNote||''};
    }catch(e){}
  }
  return parseInvoiceText(doc.body?.textContent||'','',existingContacts);
}

// ── Invoice Import Modal ─────────────────────────────────────────
function InvoiceImportModal({contacts, invoiceSettings, quoteSettings, onImport, onClose, initialData}){
  const cur=quoteSettings?.currency||'EUR';
  const blank={number:'',date:new Date().toISOString().slice(0,10),dueDate:'',serviceDate:'',status:'entwurf',firma:'',ansprechpartner:'',email:'',telefon:'',address:'',zip:'',city:'',country:'Österreich',taxId:'',items:[{id:uid(),type:'item',description:'',quantity:1,unitPrice:0}],taxRate:quoteSettings?.taxRate||20,discount:0,notes:'',paymentNote:invoiceSettings?.paymentNote||''};
  const fromJarvis=!!initialData;
  const [form,setForm]=useState(()=>fromJarvis?{...blank,firma:initialData.firma||'',email:initialData.email||'',address:initialData.address||'',zip:initialData.zip||'',city:initialData.city||'',country:initialData.country||'Österreich',taxId:initialData.taxId||'',items:(initialData.items||[]).length?initialData.items.map(it=>({id:uid(),type:'item',description:it.description||'',quantity:it.quantity??1,unitPrice:it.unitPrice??0})):[{id:uid(),type:'item',description:'',quantity:1,unitPrice:0}],date:initialData.date||new Date().toISOString().slice(0,10),dueDate:initialData.dueDate||'',taxRate:initialData.taxRate??20,notes:initialData.notes||''}:blank);
  const [parsing,setParsing]=useState(false);
  const [parseErr,setParseErr]=useState('');
  const [parsed,setParsed]=useState(fromJarvis);
  const [dragOver,setDragOver]=useState(false);
  const [contactMatch,setContactMatch]=useState(null);
  const [createContact,setCreateContact]=useState(true);
  const [rawText,setRawText]=useState('');
  const [showRaw,setShowRaw]=useState(false);
  const fileInputRef=React.useRef(null);
  const upd=p=>setForm(f=>({...f,...p}));
  const updItem=(idx,p)=>setForm(f=>({...f,items:f.items.map((it,i)=>i===idx?{...it,...p}:it)}));
  const addItem=()=>setForm(f=>({...f,items:[...f.items,{id:uid(),type:'item',description:'',quantity:1,unitPrice:0}]}));
  const addHeading=()=>setForm(f=>({...f,items:[...f.items,{id:uid(),type:'heading',description:''}]}));
  const removeItem=idx=>setForm(f=>({...f,items:f.items.filter((_,i)=>i!==idx)}));

  const handleFile=async(file)=>{
    if(!file){setParseErr('Keine Datei ausgewählt.');return;}
    setParsing(true);setParseErr('');setParsed(false);setRawText('');setShowRaw(false);
    const isPdf=file.type==='application/pdf'||/\.pdf$/i.test(file.name);
    const isHtml=file.type==='text/html'||/\.html?$/i.test(file.name);
    try{
      let parsedData;
      if(isPdf){
        let full='',leftCol='';
        try{const res=await extractPdfData(file);full=res.full;leftCol=res.leftCol;}
        catch(pdfErr){setRawText('[PDF.js Fehler] '+pdfErr.message);throw pdfErr;}
        if(!full.trim()){
          setParseErr('Kein Textlayer gefunden — OCR wird gestartet (10–20 Sek.)…');
          try{
            const res=await extractPdfDataOcr(file,msg=>setParseErr(msg));
            full=res.full;leftCol=res.leftCol;
          }catch(ocrErr){
            setRawText('[OCR Fehler] '+ocrErr.message);
            throw ocrErr;
          }
        }
        setParseErr('');
        const debugLines=full.split('\n').slice(0,60).join('\n');
        setRawText('=== DATEI ===\n'+file.name+'\n\n=== TEXT (erste 60 Zeilen) ===\n'+(debugLines||'(leer)'));
        parsedData=parseInvoiceText(full,leftCol,contacts);
      } else if(isHtml){
        const text=await file.text();
        setRawText('=== HTML (erste 800 Zeichen) ===\n'+text.slice(0,800));
        parsedData=parseInvoiceHtml(text,contacts);
      } else {
        setRawText('[Unbekannter Dateityp]\nName: '+file.name+'\nTyp: '+(file.type||'(unbekannt)')+'\nGröße: '+file.size+' bytes');
        setParseErr('Bitte eine PDF- oder HTML-Datei hochladen. Erkannt: '+(file.type||file.name));
        setParsing(false);return;
      }
      setForm(f=>({...blank,...parsedData,status:f.status}));
      setParsed(true);
    }catch(e){
      setParseErr('Fehler: '+(e.message||e.toString()));
      setRawText(rt=>rt||(('[Fehler]\n'+e.message)));
    }
    setParsing(false);
  };
  const onDrop=e=>{e.preventDefault();setDragOver(false);handleFile(e.dataTransfer.files[0]);};
  const onFileInput=e=>handleFile(e.target.files[0]);

  React.useEffect(()=>{
    if(!form.firma){setContactMatch(null);return;}
    const m=contacts.find(c=>c.firma.toLowerCase().trim()===form.firma.toLowerCase().trim());
    setContactMatch(m||null);
    if(m){
      const sn=contactToSnapshot(m);
      upd({ansprechpartner:form.ansprechpartner||sn.ansprechpartner||'',email:form.email||sn.email||'',telefon:form.telefon||sn.telefon||'',address:form.address||sn.address||'',zip:form.zip||sn.zip||'',city:form.city||sn.city||''});
    }
  },[form.firma]);

  const totals=quoteTotals(form);
  const doImport=()=>{
    if(!form.number.trim()&&!form.firma.trim()&&form.items.every(i=>!i.description.trim())){return;}
    const snap={firma:form.firma,ansprechpartner:form.ansprechpartner,email:form.email,telefon:form.telefon,address:form.address,zip:form.zip,city:form.city,country:form.country,taxId:form.taxId};
    let contactId=contactMatch?.id||'';
    let newContact=null;
    if(!contactMatch&&createContact&&form.firma.trim()){
      newContact={id:uid(),firma:form.firma,ansprechpartner:form.ansprechpartner,email:form.email,telefon:form.telefon,address:form.address,zip:form.zip,city:form.city,country:form.country||'Österreich',taxId:form.taxId,sectionId:(contacts[0]?.sectionId||'hauptkunden'),subsectionId:null,status:'Aktiv',notizen:'',umsatz:'',reminders:[],activities:[],customValues:{}};
      contactId=newContact.id;
    }
    const inv={id:uid(),number:form.number||nextInvoiceNumber(invoiceSettings||{}),status:form.status,contactId,contactSnapshot:snap,items:form.items,date:form.date,dueDate:form.dueDate,serviceDate:form.serviceDate,serviceEndDate:'',taxRate:form.taxRate,discount:form.discount,title:'',notes:form.notes,paymentNote:form.paymentNote,createdAt:new Date().toISOString(),paidAt:form.status==='bezahlt'?form.date:null,fromQuoteId:''};
    onImport(inv,newContact);
    onClose();
  };
  const lbl={fontSize:12,fontWeight:600,color:'#5F5A55',marginBottom:4,display:'block'};
  return(
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-box" onClick={e=>e.stopPropagation()} style={{width:660,maxHeight:'92vh',overflowY:'auto'}}>
        <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:20}}>
          <div><h2 style={{fontSize:17,fontWeight:700}}>📥 Rechnung importieren</h2>
          <p style={{fontSize:12.5,color:'#A8A39D',marginTop:3}}>PDF oder HTML hochladen — Daten werden automatisch erkannt.</p></div>
          <button onClick={onClose} style={{background:'#F5F3F0',border:'none',borderRadius:8,padding:8,color:'#999',lineHeight:0,flexShrink:0}}><Icons.Close/></button>
        </div>

        {/* FILE UPLOAD ZONE */}
        <input ref={fileInputRef} type="file" accept=".pdf,.html,.htm" onChange={onFileInput} style={{display:'none'}}/>
        <div
          onDragEnter={e=>{e.preventDefault();e.stopPropagation();setDragOver(true);}}
          onDragOver={e=>{e.preventDefault();e.stopPropagation();setDragOver(true);}}
          onDragLeave={e=>{e.preventDefault();e.stopPropagation();setDragOver(false);}}
          onDrop={e=>{e.preventDefault();e.stopPropagation();setDragOver(false);handleFile(e.dataTransfer.files[0]);}}
          style={{border:`2px dashed ${dragOver?'#141210':'#D5D0CB'}`,borderRadius:12,padding:'22px 20px',textAlign:'center',marginBottom:16,background:dragOver?'#F5F3F0':'#FAFAF9',transition:'all .15s'}}>
          {parsing?(
            <div style={{color:'#A8A39D',fontSize:13.5}}>
              <div style={{fontSize:24,marginBottom:8}}>⏳</div>
              Rechnung wird eingelesen…
            </div>
          ):parsed?(
            fromJarvis?(
              <div style={{color:'#7c3aed',fontSize:13.5,fontWeight:600}}>
                <div style={{fontSize:22,marginBottom:6}}>🤖</div>
                Jarvis-Entwurf{form.firma?` · ${form.firma}`:''}
                {form.items.filter(i=>i.description).length>0&&<span> · {form.items.filter(i=>i.description).length} Position(en)</span>}
                <div style={{fontSize:12,fontWeight:400,color:'#A8A39D',marginTop:6}}>Felder prüfen und unten importieren</div>
              </div>
            ):(
            <div style={{color:'#16a34a',fontSize:13.5,fontWeight:600}}>
              <div style={{fontSize:22,marginBottom:6}}>✓</div>
              {form.firma?`Kunde: ${form.firma}`:'Datei gelesen'}{form.number?` · ${form.number}`:''}
              {form.items.filter(i=>i.description).length>0&&<span> · {form.items.filter(i=>i.description).length} Position(en)</span>}
              <div style={{fontSize:12,fontWeight:400,color:'#A8A39D',marginTop:6}}>Prüfe die Felder unten und korrigiere falls nötig</div>
              <button className="btn btn-ghost btn-sm" onClick={()=>fileInputRef.current?.click()} style={{marginTop:10}}>Andere Datei wählen</button>
            </div>
            )
          ):(
            <div style={{color:'#A8A39D',fontSize:13.5}}>
              <div style={{fontSize:28,marginBottom:8}}>📄</div>
              <div style={{marginBottom:10}}><span style={{color:'#141210',fontWeight:600}}>PDF oder HTML</span> hier reinziehen</div>
              <button className="btn btn-primary btn-sm" onClick={()=>fileInputRef.current?.click()}>Datei auswählen</button>
              <div style={{fontSize:12,marginTop:10}}>Rechnungen die mit diesem CRM erstellt wurden werden automatisch erkannt</div>
            </div>
          )}
        </div>
        {parseErr&&<div style={{marginBottom:14,padding:'10px 14px',background:'#FEF2F2',borderRadius:8,color:'#C0392B',fontSize:13}}>{parseErr}</div>}
        {rawText&&<div style={{marginBottom:14}}>
          <button className="btn btn-ghost btn-sm" onClick={()=>setShowRaw(v=>!v)} style={{marginBottom:6,fontSize:11}}>
            {showRaw?'▲ Debug-Text ausblenden':'▼ Extrahierter Text (Debug)'}
          </button>
          {showRaw&&<textarea readOnly value={rawText} style={{width:'100%',height:160,fontSize:10.5,fontFamily:'monospace',background:'#F5F3F0',border:'1px solid #D5D0CB',borderRadius:8,padding:'8px 10px',resize:'vertical',boxSizing:'border-box',color:'#3a3530'}}/>}
        </div>}

        <div style={{display:'grid',gridTemplateColumns:'1fr 1fr 1fr',gap:12,marginBottom:14}}>
          <div><label style={lbl}>Rechnungsnummer</label><input value={form.number} onChange={e=>upd({number:e.target.value})} placeholder={nextInvoiceNumber(invoiceSettings||{})}/></div>
          <div><label style={lbl}>Datum</label><input type="date" value={form.date} onChange={e=>upd({date:e.target.value})}/></div>
          <div><label style={lbl}>Fällig am</label><input type="date" value={form.dueDate} onChange={e=>upd({dueDate:e.target.value})}/></div>
        </div>
        <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:12,marginBottom:16}}>
          <div><label style={lbl}>Leistungsdatum</label><input type="date" value={form.serviceDate} onChange={e=>upd({serviceDate:e.target.value})}/></div>
          <div><label style={lbl}>Status</label><select value={form.status} onChange={e=>upd({status:e.target.value})} style={{width:'100%'}}>{INVOICE_STATUSES.map(s=><option key={s.key} value={s.key}>{s.label}</option>)}</select></div>
        </div>
        <div style={{background:'#F8F7F5',borderRadius:10,padding:'14px 16px',marginBottom:14}}>
          <div style={{fontWeight:600,fontSize:13,marginBottom:12,color:'#141210'}}>Kunde</div>
          <div style={{marginBottom:10}}>
            <label style={lbl}>Firma / Name *</label>
            <input value={form.firma} onChange={e=>upd({firma:e.target.value})} placeholder="Firmenname des Kunden"/>
            {contactMatch&&<div style={{fontSize:12,color:'#16a34a',marginTop:4,fontWeight:500}}>✓ Kontakt gefunden: {contactMatch.firma} — Daten werden automatisch übernommen</div>}
            {!contactMatch&&form.firma.trim()&&<div style={{fontSize:12,color:'#b45309',marginTop:4}}>Kein bestehender Kontakt — {createContact?'wird neu angelegt':''}</div>}
          </div>
          <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:10,marginBottom:10}}>
            <div><label style={lbl}>Ansprechpartner</label><input value={form.ansprechpartner} onChange={e=>upd({ansprechpartner:e.target.value})}/></div>
            <div><label style={lbl}>Email</label><input value={form.email} onChange={e=>upd({email:e.target.value})}/></div>
            <div><label style={lbl}>Telefon</label><input value={form.telefon} onChange={e=>upd({telefon:e.target.value})}/></div>
            <div><label style={lbl}>UID / Steuer-Nr.</label><input value={form.taxId} onChange={e=>upd({taxId:e.target.value})}/></div>
            <div><label style={lbl}>Straße + Nr.</label><input value={form.address} onChange={e=>upd({address:e.target.value})}/></div>
            <div style={{display:'grid',gridTemplateColumns:'90px 1fr',gap:8}}>
              <div><label style={lbl}>PLZ</label><input value={form.zip} onChange={e=>upd({zip:e.target.value})}/></div>
              <div><label style={lbl}>Ort</label><input value={form.city} onChange={e=>upd({city:e.target.value})}/></div>
            </div>
          </div>
          {!contactMatch&&form.firma.trim()&&(
            <label style={{display:'flex',alignItems:'center',gap:8,fontSize:13,cursor:'pointer',color:'#5F5A55'}}>
              <input type="checkbox" checked={createContact} onChange={e=>setCreateContact(e.target.checked)} style={{width:'auto',accentColor:'#141210'}}/>
              Automatisch als neuen Kontakt speichern
            </label>
          )}
        </div>
        <div style={{marginBottom:14}}>
          <div style={{fontWeight:600,fontSize:13,marginBottom:10,color:'#141210'}}>Positionen</div>
          <div style={{display:'grid',gridTemplateColumns:'1fr 80px 110px 32px',gap:8,marginBottom:6}}>
            <div style={{fontSize:11,color:'#A8A39D',fontWeight:600}}>BESCHREIBUNG</div>
            <div style={{fontSize:11,color:'#A8A39D',fontWeight:600,textAlign:'right'}}>MENGE</div>
            <div style={{fontSize:11,color:'#A8A39D',fontWeight:600,textAlign:'right'}}>EINZELPREIS</div>
            <div/>
          </div>
          {form.items.map((it,idx)=>(
            it.type==='heading'?(
              <div key={it.id} style={{display:'grid',gridTemplateColumns:'1fr 32px',gap:8,marginBottom:6,alignItems:'center'}}>
                <input value={it.description} onChange={e=>updItem(idx,{description:e.target.value})} placeholder="Abschnitt / Überschrift" style={{fontWeight:700,background:'#F0EDE9',borderColor:'transparent',fontSize:13}}/>
                <button onClick={()=>removeItem(idx)} style={{background:'none',border:'none',color:'#DDD',fontSize:18,cursor:'pointer',padding:0,lineHeight:1}} onMouseEnter={e=>e.currentTarget.style.color='#C0392B'} onMouseLeave={e=>e.currentTarget.style.color='#DDD'}>×</button>
              </div>
            ):(
              <div key={it.id} style={{display:'grid',gridTemplateColumns:'1fr 80px 110px 32px',gap:8,marginBottom:8,alignItems:'center'}}>
                <input value={it.description} onChange={e=>updItem(idx,{description:e.target.value})} placeholder="Beschreibung der Leistung"/>
                <input type="number" min="0" step="0.01" value={it.quantity} onChange={e=>updItem(idx,{quantity:parseFloat(e.target.value)||0})} style={{textAlign:'right'}}/>
                <input type="number" min="0" step="0.01" value={it.unitPrice} onChange={e=>updItem(idx,{unitPrice:parseFloat(e.target.value)||0})} style={{textAlign:'right'}}/>
                {form.items.length>1?<button onClick={()=>removeItem(idx)} style={{background:'none',border:'none',color:'#DDD',fontSize:18,cursor:'pointer',padding:0,lineHeight:1}} onMouseEnter={e=>e.currentTarget.style.color='#C0392B'} onMouseLeave={e=>e.currentTarget.style.color='#DDD'}>×</button>:<div/>}
              </div>
            )
          ))}
          <div style={{display:'flex',gap:8,marginTop:4}}>
            <button className="btn btn-ghost btn-sm" onClick={addItem}><Icons.Plus/>Position hinzufügen</button>
            <button className="btn btn-ghost btn-sm" onClick={addHeading} style={{color:'#8B5CF6'}}>§ Abschnitt hinzufügen</button>
          </div>
        </div>
        <div style={{display:'grid',gridTemplateColumns:'1fr 1fr 1fr',gap:12,marginBottom:16}}>
          <div><label style={lbl}>MwSt (%)</label><input type="number" min="0" step="1" value={form.taxRate} onChange={e=>upd({taxRate:parseFloat(e.target.value)||0})} style={{textAlign:'right'}}/></div>
          <div><label style={lbl}>Rabatt (%)</label><input type="number" min="0" step="1" value={form.discount} onChange={e=>upd({discount:parseFloat(e.target.value)||0})} style={{textAlign:'right'}}/></div>
          <div style={{display:'flex',alignItems:'flex-end',justifyContent:'flex-end'}}><div style={{textAlign:'right'}}><div style={{fontSize:11,color:'#A8A39D',fontWeight:600,marginBottom:4}}>GESAMT</div><div style={{fontSize:18,fontWeight:700}}>{fmtMoney(totals.total,cur)}</div></div></div>
        </div>
        <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',paddingTop:16,borderTop:'1px solid rgba(0,0,0,0.07)'}}>
          <button className="btn btn-ghost" onClick={onClose}>Abbrechen</button>
          <button className="btn btn-primary" onClick={doImport} disabled={!form.number.trim()&&!form.firma.trim()}>📥 Rechnung importieren</button>
        </div>
      </div>
    </div>
  );
}

function InvoicesView({invoices, contacts, quoteSettings, invoiceSettings, quotes, onCreate, onOpen, onDelete, onMarkPaid, onDuplicate, onImport, onMahnung}){
  const [statusFilter,setStatusFilter]=useState('');
  const [search,setSearch]=useState('');
  const cur=quoteSettings?.currency||'EUR';
  const today=new Date().toISOString().slice(0,10);
  const enriched=(invoices||[]).map(inv=>(inv.dueDate&&inv.dueDate<today&&(inv.status==='offen'||inv.status==='gesendet'))?{...inv,status:'ueberfaellig'}:inv);
  const filtered=enriched.filter(inv=>{
    if(statusFilter&&inv.status!==statusFilter)return false;
    if(search){const s=search.toLowerCase();return[inv.number,inv.title,inv.contactSnapshot?.firma].some(f=>f&&f.toLowerCase().includes(s));}
    return true;
  }).sort((a,b)=>(b.createdAt||'').localeCompare(a.createdAt||''));
  const totalOpen=enriched.filter(i=>['offen','gesendet','ueberfaellig'].includes(i.status)).reduce((s,i)=>s+quoteTotals(i).total,0);
  const totalPaid=enriched.filter(i=>i.status==='bezahlt').reduce((s,i)=>s+quoteTotals(i).total,0);
  return(
    <div style={{flex:1,display:'flex',flexDirection:'column',overflow:'hidden'}}>
      <div style={{padding:'7px 28px',background:'#FAFAF8',borderBottom:'1px solid rgba(0,0,0,0.07)',display:'flex',gap:16,fontSize:12.5,alignItems:'center',flexShrink:0}}>
        <span style={{fontWeight:600,color:'#141210'}}>{enriched.length} Rechnungen</span>
        {totalOpen>0&&<span style={{color:'#b45309'}}>Offen: <strong>{fmtMoney(totalOpen,cur)}</strong></span>}
        {totalPaid>0&&<span style={{color:'#16a34a'}}>Bezahlt: <strong>{fmtMoney(totalPaid,cur)}</strong></span>}
        <div style={{flex:1}}/>
        <span style={{color:'#A8A39D',fontSize:12}}>Gesamt: <strong style={{color:'#141210'}}>{fmtMoney(enriched.reduce((s,i)=>s+quoteTotals(i).total,0),cur)}</strong></span>
      </div>
      <div style={{padding:'10px 28px',background:'white',borderBottom:'1px solid rgba(0,0,0,0.07)',display:'flex',gap:10,alignItems:'center',flexShrink:0}}>
        <div style={{position:'relative',flex:1,maxWidth:280}}>
          <div style={{position:'absolute',left:11,top:'50%',transform:'translateY(-50%)',color:'#C8C3BD',lineHeight:0}}><Icons.Search/></div>
          <input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Rechnungen suchen…" style={{paddingLeft:34,background:'#F5F3F0',border:'1.5px solid transparent'}}/>
        </div>
        <select value={statusFilter} onChange={e=>setStatusFilter(e.target.value)} style={{width:'auto',padding:'9px 12px',fontSize:13,background:'#F5F3F0',border:'1.5px solid transparent',color:statusFilter?'#141210':'#A8A39D'}}>
          <option value="">Alle Status</option>{INVOICE_STATUSES.map(s=><option key={s.key} value={s.key}>{s.label}</option>)}
        </select>
        <div style={{flex:1}}/>
        {onImport&&<button className="btn btn-ghost" onClick={onImport} style={{fontSize:13}}>📥 Importieren</button>}
        <button className="btn btn-primary" onClick={()=>onCreate(null)}><Icons.Plus/>Neue Rechnung</button>
      </div>
      <div style={{flex:1,overflowY:'auto',padding:28}}>
        {filtered.length===0?(
          <div style={{textAlign:'center',padding:'80px 20px',color:'#C8C3BD'}}>
            <div style={{fontSize:46,marginBottom:16,opacity:.5}}>🧾</div>
            <div style={{fontSize:16,fontWeight:600,color:'#C0BBB5'}}>{(invoices||[]).length===0?'Noch keine Rechnungen.':'Keine Treffer.'}</div>
            {(invoices||[]).length===0&&<button className="btn btn-primary" style={{marginTop:20}} onClick={()=>onCreate(null)}><Icons.Plus/>Erste Rechnung erstellen</button>}
          </div>
        ):(
          <div style={{display:'grid',gap:8}}>
            {filtered.map(inv=>{
              const totals=quoteTotals(inv);
              const status=INVOICE_STATUSES.find(s=>s.key===inv.status)||INVOICE_STATUSES[0];
              const overdue=inv.status==='ueberfaellig';
              return(
                <div key={inv.id} style={{background:'white',borderRadius:12,padding:'14px 18px',border:`1px solid ${overdue?'#FECACA':'rgba(0,0,0,0.07)'}`,boxShadow:'0 1px 4px rgba(0,0,0,0.04)',display:'flex',alignItems:'center',gap:14,cursor:'pointer',transition:'all 0.15s'}}
                  onMouseEnter={e=>{e.currentTarget.style.transform='translateY(-1px)';e.currentTarget.style.boxShadow='0 4px 12px rgba(0,0,0,0.08)';}}
                  onMouseLeave={e=>{e.currentTarget.style.transform='translateY(0)';e.currentTarget.style.boxShadow='0 1px 4px rgba(0,0,0,0.04)';}}
                  onClick={()=>onOpen(inv)}>
                  <div style={{flexShrink:0,width:44,height:44,borderRadius:10,background:overdue?'#FEF2F2':'#FAFAF8',display:'flex',alignItems:'center',justifyContent:'center',fontSize:20}}>{overdue?'⚠':'🧾'}</div>
                  <div style={{flex:1,minWidth:0}}>
                    <div style={{display:'flex',alignItems:'center',gap:8,marginBottom:3}}>
                      <span style={{fontFamily:'monospace',fontSize:11.5,fontWeight:600,color:'#6B6560'}}>{inv.number}</span>
                      <span style={{display:'inline-flex',alignItems:'center',gap:4,padding:'2px 7px',borderRadius:99,background:status.bg,fontSize:10.5,fontWeight:600,color:status.color}}>
                        <span style={{width:4,height:4,borderRadius:'50%',background:status.dot}}></span>{status.label}
                      </span>
                    </div>
                    <div style={{fontSize:14,fontWeight:600,color:'#141210',whiteSpace:'nowrap',overflow:'hidden',textOverflow:'ellipsis'}}>{inv.contactSnapshot?.firma||'—'}{inv.title?` · ${inv.title}`:''}</div>
                    <div style={{fontSize:12,color:'#A8A39D',marginTop:2}}>
                      Ausgestellt {fmtDate(inv.date)} · Fällig {fmtDate(inv.dueDate)}
                      {inv.paidAt&&<span style={{color:'#16a34a',marginLeft:8}}>✓ Bezahlt {fmtDate(inv.paidAt)}</span>}
                    </div>
                  </div>
                  <div style={{textAlign:'right',flexShrink:0,display:'flex',flexDirection:'column',alignItems:'flex-end',gap:5}}>
                    <div style={{fontSize:16,fontWeight:700,fontVariantNumeric:'tabular-nums',color:overdue?'#b91c1c':'#141210'}}>{fmtMoney(totals.total,cur)}</div>
                    {inv.status!=='bezahlt'&&inv.status!=='storniert'&&(
                      <button onClick={ev=>{ev.stopPropagation();onMarkPaid(inv.id);}} className="btn btn-ghost btn-sm" style={{fontSize:11,padding:'3px 8px',color:'#16a34a',borderColor:'#BBF7D0'}}>✓ Bezahlt</button>
                    )}
                    {overdue&&onMahnung&&(
                      <button onClick={ev=>{ev.stopPropagation();onMahnung(inv);}} className="btn btn-ghost btn-sm" style={{fontSize:11,padding:'3px 8px',color:'#b45309',borderColor:'#FDE68A'}}>🔔 Mahnung{(inv.mahnungen?.length||0)>0?` (${inv.mahnungen.length})`:''}</button>
                    )}
                  </div>
                  <div style={{display:'flex',flexDirection:'column',gap:4,flexShrink:0}}>
                    <button onClick={ev=>{ev.stopPropagation();onDuplicate(inv);}} title="Duplizieren" style={{background:'none',border:'none',color:'#C8C3BD',cursor:'pointer',fontSize:14,padding:'3px 6px',lineHeight:1,borderRadius:6,transition:'color .15s,background .15s'}} onMouseEnter={e=>{e.currentTarget.style.color='#2563EB';e.currentTarget.style.background='#EFF6FF';}} onMouseLeave={e=>{e.currentTarget.style.color='#C8C3BD';e.currentTarget.style.background='none';}}>⧉</button>
                    <button onClick={ev=>{ev.stopPropagation();if(confirm('Rechnung wirklich löschen?'))onDelete(inv.id);}} title="Löschen" style={{background:'none',border:'none',color:'#DDD',cursor:'pointer',fontSize:18,padding:'3px 6px',lineHeight:1,borderRadius:6,transition:'color .15s,background .15s'}} onMouseEnter={e=>{e.currentTarget.style.color='#C0392B';e.currentTarget.style.background='#FEF2F2';}} onMouseLeave={e=>{e.currentTarget.style.color='#DDD';e.currentTarget.style.background='none';}}>×</button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════
//  KAMPAGNEN & IDEEN
// ══════════════════════════════════════════════════════════════════
const CAMPAIGN_COLORS=['#6366f1','#ec4899','#f59e0b','#10b981','#3b82f6','#8b5cf6','#ef4444','#14b8a6'];
const CAMPAIGN_EMOJIS=['💡','📢','🚀','🎯','📌','⚡','🔥','🌟','📝','🎨','💼','📊'];
const BLOCK_DEFS=[
  {type:'text',   icon:'¶',   label:'Text',          desc:'Normaler Absatz'},
  {type:'h1',     icon:'H1',  label:'Überschrift 1', desc:'Große Überschrift'},
  {type:'h2',     icon:'H2',  label:'Überschrift 2', desc:'Mittlere Überschrift'},
  {type:'h3',     icon:'H3',  label:'Überschrift 3', desc:'Kleine Überschrift'},
  {type:'bullet', icon:'•',   label:'Aufzählung',    desc:'Aufzählungspunkt'},
  {type:'numbered',icon:'1.', label:'Nummeriert',    desc:'Nummerierte Liste'},
  {type:'code',   icon:'</>',label:'Code-Snippet',   desc:'Code mit Syntax-Highlighting'},
  {type:'image',  icon:'🖼',  label:'Bild',          desc:'Bild hochladen oder URL'},
  {type:'divider',icon:'—',   label:'Trennlinie',    desc:'Horizontaler Strich'},
];
function newBlock(type='text'){return{id:uid(),type,content:'',language:'js',caption:''};}
function parseBlocks(raw){
  if(!raw)return[newBlock()];
  try{const p=JSON.parse(raw);if(Array.isArray(p)&&p.length)return p;}catch{}
  return[{id:uid(),type:'text',content:raw,language:'js',caption:''}];
}

function BlockEditor({file,campColor,onSaveContent,onRenameFile}){
  const accent=campColor||'#6366f1';
  const [blocks,setBlocks]=useState(()=>parseBlocks(file.content));
  const [editingName,setEditingName]=useState(false);
  const [fileName,setFileName]=useState(file.name);
  const [slashMenu,setSlashMenu]=useState(null);
  const [addMenu,setAddMenu]=useState(null);
  const [rowHover,setRowHover]=useState(null);
  const timerRef=useRef(null);
  const blockRefs=useRef({});
  const scrollRef=useRef(null);
  const [tocOpen,setTocOpen]=useState(false);

  useEffect(()=>{setBlocks(parseBlocks(file.content));setFileName(file.name);setEditingName(false);},[file.id]);

  // Resize ALL textareas once when the file (or blocks added/removed) changes.
  // Crucially: NOT on every render — that's what caused the scroll-jump while typing.
  useLayoutEffect(()=>{
    Object.values(blockRefs.current).forEach(el=>{
      if(el){el.style.height='auto';el.style.height=el.scrollHeight+'px';}
    });
  },[file.id, blocks.length]);

  const headings=blocks.filter(b=>['h1','h2','h3'].includes(b.type)&&b.content.trim());
  const scrollToHeading=(blockId)=>{
    const el=blockRefs.current[blockId];
    if(!el)return;
    const c=scrollRef.current;
    if(!c){el.scrollIntoView({behavior:'smooth',block:'start'});return;}
    const offset=el.getBoundingClientRect().top-c.getBoundingClientRect().top-24;
    c.scrollBy({top:offset,behavior:'smooth'});
  };

  const persist=useCallback(bl=>{clearTimeout(timerRef.current);timerRef.current=setTimeout(()=>onSaveContent(JSON.stringify(bl)),600);},[onSaveContent]);
  const setB=bl=>{setBlocks(bl);persist(bl);};
  const updB=(id,p)=>setB(blocks.map(b=>b.id===id?{...b,...p}:b));

  const insertB=(afterId,type='text')=>{
    const nb=newBlock(type);
    const i=afterId===null?blocks.length:blocks.findIndex(b=>b.id===afterId)+1;
    setB([...blocks.slice(0,i),nb,...blocks.slice(i)]);
    setSlashMenu(null);setAddMenu(null);
    setTimeout(()=>blockRefs.current[nb.id]?.focus(),40);
  };
  const delB=id=>{
    if(blocks.length===1){updB(id,{content:''});return;}
    const i=blocks.findIndex(b=>b.id===id);
    const bl=blocks.filter(b=>b.id!==id);
    setB(bl);
    setTimeout(()=>blockRefs.current[bl[Math.max(0,i-1)]?.id]?.focus(),40);
  };
  const handleKey=(e,block)=>{
    if(e.key==='Enter'&&!e.shiftKey&&block.type!=='code'){
      e.preventDefault();
      if(!block.content.trim()&&['bullet','numbered'].includes(block.type)){updB(block.id,{type:'text'});return;}
      insertB(block.id,['bullet','numbered'].includes(block.type)?block.type:'text');
    }
    if(e.key==='Backspace'&&!block.content){
      e.preventDefault();
      if(block.type!=='text')updB(block.id,{type:'text'});else delB(block.id);
    }
    if(e.key==='Escape'){setSlashMenu(null);setAddMenu(null);}
  };
  const handleChange=(id,val)=>{
    if(val.startsWith('/')&&!val.slice(1).includes(' '))setSlashMenu({blockId:id,query:val.slice(1)});
    else if(slashMenu?.blockId===id)setSlashMenu(null);
    updB(id,{content:val});
    const el=blockRefs.current[id];if(el){el.style.height='auto';el.style.height=el.scrollHeight+'px';}
  };
  const applySlash=(blockId,type)=>{
    setB(blocks.map(b=>b.id!==blockId?b:{...b,type,content:'',language:'js'}));
    setSlashMenu(null);setTimeout(()=>blockRefs.current[blockId]?.focus(),40);
  };
  const filteredDefs=slashMenu?BLOCK_DEFS.filter(d=>!slashMenu.query||d.label.toLowerCase().includes(slashMenu.query.toLowerCase())||d.type.startsWith(slashMenu.query.toLowerCase())):[];
  const baseTA={width:'100%',boxSizing:'border-box',border:'none',outline:'none',resize:'none',background:'transparent',fontFamily:'inherit',overflow:'hidden',display:'block',padding:0};
  const ts={text:{fontSize:15,lineHeight:1.85,color:'#1F1B17'},h1:{fontSize:28,fontWeight:800,lineHeight:1.25,color:'#141210',letterSpacing:'-0.025em'},h2:{fontSize:21,fontWeight:700,lineHeight:1.3,color:'#141210',letterSpacing:'-0.01em'},h3:{fontSize:17,fontWeight:700,lineHeight:1.4,color:'#141210'},bullet:{fontSize:15,lineHeight:1.85,color:'#1F1B17'},numbered:{fontSize:15,lineHeight:1.85,color:'#1F1B17'}};
  const fmtDate=iso=>iso?new Date(iso).toLocaleDateString('de-AT',{day:'2-digit',month:'2-digit',year:'numeric'}):'';

  const renderBlock=(block,idx)=>{
    const numIdx=(()=>{if(block.type!=='numbered')return 0;let n=1;for(let i=idx-1;i>=0;i--){if(blocks[i].type==='numbered')n++;else break;}return n;})();
    return(
      <div key={block.id} style={{position:'relative',marginBottom:block.type==='divider'?6:0}}>
        <div style={{display:'flex',alignItems:'flex-start',gap:6,padding:'1px 0'}}
          onMouseEnter={()=>setRowHover(block.id)} onMouseLeave={()=>{setRowHover(null);}}>
          {/* Delete handle */}
          <div style={{width:22,flexShrink:0,display:'flex',alignItems:'center',justifyContent:'center',paddingTop:block.type==='h1'?8:block.type==='h2'?5:3,opacity:rowHover===block.id?1:0,transition:'opacity .12s'}}>
            <button onMouseDown={e=>{e.preventDefault();delB(block.id);}} style={{background:'none',border:'none',cursor:'pointer',color:'#C8C3BD',fontSize:13,width:20,height:20,borderRadius:4,display:'flex',alignItems:'center',justifyContent:'center',transition:'all .1s',padding:0}} onMouseEnter={e=>{e.currentTarget.style.background='#FEF2F2';e.currentTarget.style.color='#C0392B';}} onMouseLeave={e=>{e.currentTarget.style.background='none';e.currentTarget.style.color='#C8C3BD';}}>×</button>
          </div>
          <div style={{flex:1,minWidth:0,position:'relative'}}>
            {/* DIVIDER */}
            {block.type==='divider'&&<hr style={{border:'none',borderTop:'2px solid rgba(0,0,0,0.1)',margin:'10px 0',cursor:'pointer'}} onClick={()=>delB(block.id)} title="Klicken zum Löschen"/>}
            {/* IMAGE */}
            {block.type==='image'&&(
              <div style={{marginBottom:4}}>
                {block.content
                  ?<div style={{position:'relative',display:'inline-block',maxWidth:'100%'}}>
                      <img src={block.content} alt={block.caption||''} style={{maxWidth:'100%',borderRadius:10,display:'block'}}/>
                      <button onMouseDown={e=>{e.preventDefault();updB(block.id,{content:'',caption:'',});}} style={{position:'absolute',top:8,right:8,background:'rgba(0,0,0,0.55)',border:'none',borderRadius:6,color:'white',fontSize:12,padding:'3px 10px',cursor:'pointer',backdropFilter:'blur(4px)'}}>✕ Entfernen</button>
                      <textarea value={block.caption||''} onChange={e=>updB(block.id,{caption:e.target.value})} placeholder="Bildunterschrift…" style={{...baseTA,fontSize:12.5,color:'#9A9590',marginTop:6,fontStyle:'italic'}} rows={1}/>
                    </div>
                  :<label style={{display:'flex',flexDirection:'column',alignItems:'center',justifyContent:'center',border:`2px dashed ${accent}44`,borderRadius:12,padding:'32px 20px',cursor:'pointer',gap:10,color:'#A8A39D',background:'#FAFAF8',transition:'all .15s'}}
                      onMouseEnter={e=>{e.currentTarget.style.borderColor=accent;e.currentTarget.style.background='white';}}
                      onMouseLeave={e=>{e.currentTarget.style.borderColor=accent+'44';e.currentTarget.style.background='#FAFAF8';}}
                      onDragOver={e=>{e.preventDefault();e.currentTarget.style.borderColor=accent;}}
                      onDragLeave={e=>{e.currentTarget.style.borderColor=accent+'44';}}
                      onDrop={e=>{e.preventDefault();const f=e.dataTransfer.files[0];if(f&&f.type.startsWith('image/')){if(f.size>2*1024*1024){alert('Bild ist zu groß (max. 2 MB).');return;}const r=new FileReader();r.onload=ev=>updB(block.id,{content:ev.target.result});r.readAsDataURL(f);}}}>
                      <input type="file" accept="image/*" style={{display:'none'}} onChange={e=>{const f=e.target.files[0];if(f){if(f.size>2*1024*1024){alert('Bild ist zu groß (max. 2 MB). Bitte ein kleineres Bild verwenden.');return;}const r=new FileReader();r.onload=ev=>updB(block.id,{content:ev.target.result});r.readAsDataURL(f);}}}/>
                      <span style={{fontSize:36,lineHeight:1}}>🖼</span>
                      <div style={{fontSize:14,fontWeight:600,color:'#6B6560'}}>Bild hochladen oder hierher ziehen</div>
                      <div style={{fontSize:12,color:'#C8C3BD'}}>JPG, PNG, GIF, WebP · max. 2 MB</div>
                      <div style={{display:'flex',gap:6,alignItems:'center'}} onClick={e=>e.stopPropagation()}>
                        <input placeholder="https://… Bild-URL" style={{fontSize:13,padding:'7px 12px',borderRadius:8,border:'1.5px solid #E5E1DC',width:250}} onKeyDown={e=>{if(e.key==='Enter'&&e.target.value.trim()){updB(block.id,{content:e.target.value.trim()});}}}/>
                        <span style={{fontSize:11,color:'#C8C3BD'}}>↵ Enter</span>
                      </div>
                    </label>
                }
              </div>
            )}
            {/* CODE */}
            {block.type==='code'&&(
              <div style={{background:'#1a1a2e',borderRadius:12,overflow:'hidden',marginBottom:2}}>
                <div style={{display:'flex',alignItems:'center',gap:8,padding:'8px 14px',background:'rgba(255,255,255,0.04)',borderBottom:'1px solid rgba(255,255,255,0.06)'}}>
                  <div style={{display:'flex',gap:5}}>{['#ff5f56','#ffbd2e','#27c93f'].map(c=><div key={c} style={{width:10,height:10,borderRadius:'50%',background:c}}/>)}</div>
                  <select value={block.language||'js'} onChange={e=>updB(block.id,{language:e.target.value})} style={{fontSize:11.5,background:'rgba(255,255,255,0.08)',color:'#8892b0',border:'none',borderRadius:5,padding:'3px 8px',cursor:'pointer',marginLeft:4}}>
                    {['js','ts','python','html','css','json','sql','bash','php','java','go','rust','c','cpp'].map(l=><option key={l} value={l}>{l}</option>)}
                  </select>
                  <div style={{flex:1}}/>
                  <button onMouseDown={e=>{e.preventDefault();navigator.clipboard?.writeText(block.content||'');}} style={{fontSize:11.5,background:'rgba(255,255,255,0.06)',color:'#8892b0',border:'1px solid rgba(255,255,255,0.1)',borderRadius:6,padding:'3px 10px',cursor:'pointer'}}>📋 Kopieren</button>
                </div>
                <textarea ref={el=>{if(el)blockRefs.current[block.id]=el;}}
                  value={block.content||''}
                  onChange={e=>{updB(block.id,{content:e.target.value});const el=e.target;el.style.height='auto';el.style.height=el.scrollHeight+'px';}}
                  onKeyDown={e=>{if(e.key==='Tab'){e.preventDefault();const s=e.target.selectionStart;const v=e.target.value;updB(block.id,{content:v.slice(0,s)+'  '+v.slice(e.target.selectionEnd)});setTimeout(()=>{const el=blockRefs.current[block.id];if(el){el.selectionStart=el.selectionEnd=s+2;}},0);}if(e.key==='Escape'){setSlashMenu(null);setAddMenu(null);}}}
                  placeholder="// Code hier eingeben…"
                  style={{...baseTA,fontFamily:'"Fira Code","Cascadia Code",Consolas,monospace',fontSize:13.5,lineHeight:1.65,color:'#cdd6f4',padding:'14px 16px',minHeight:56,background:'transparent'}}
                  rows={3}/>
              </div>
            )}
            {/* TEXT / HEADINGS / LISTS */}
            {!['divider','image','code'].includes(block.type)&&(
              <div style={{display:'flex',alignItems:'flex-start',gap:8}}>
                {block.type==='bullet'&&<span style={{color:accent,fontSize:18,lineHeight:1.5,flexShrink:0,marginTop:1,userSelect:'none'}}>•</span>}
                {block.type==='numbered'&&<span style={{color:accent,fontSize:15,lineHeight:1.85,flexShrink:0,minWidth:22,textAlign:'right',userSelect:'none'}}>{numIdx}.</span>}
                <textarea
                  ref={el=>{if(el)blockRefs.current[block.id]=el;}}
                  value={block.content||''}
                  onChange={e=>handleChange(block.id,e.target.value)}
                  onKeyDown={e=>handleKey(e,block)}
                  onFocus={()=>setAddMenu(null)}
                  placeholder={block.type==='text'?'Tippe / für Blöcke…':block.type==='h1'?'Überschrift 1':block.type==='h2'?'Überschrift 2':block.type==='h3'?'Überschrift 3':'Listenpunkt…'}
                  style={{...baseTA,...(ts[block.type]||ts.text),flex:1,minHeight:28,paddingTop:block.type==='h1'?8:block.type==='h2'?5:block.type==='h3'?3:0}}
                  rows={1}/>
              </div>
            )}
            {/* Slash menu */}
            {slashMenu?.blockId===block.id&&filteredDefs.length>0&&(
              <div style={{position:'absolute',left:0,top:'100%',zIndex:300,background:'white',borderRadius:12,boxShadow:'0 8px 32px rgba(0,0,0,0.16)',border:'1px solid rgba(0,0,0,0.07)',padding:'6px',minWidth:230,maxHeight:300,overflowY:'auto'}}>
                {filteredDefs.map(d=>(
                  <button key={d.type} onMouseDown={e=>{e.preventDefault();applySlash(block.id,d.type);}}
                    style={{display:'flex',alignItems:'center',gap:10,width:'100%',padding:'8px 10px',borderRadius:8,border:'none',background:'none',cursor:'pointer',textAlign:'left'}}
                    onMouseEnter={e=>e.currentTarget.style.background='#F5F3F0'} onMouseLeave={e=>e.currentTarget.style.background='none'}>
                    <span style={{fontSize:11.5,fontFamily:'monospace',fontWeight:700,color:accent,width:28,textAlign:'center',flexShrink:0}}>{d.icon}</span>
                    <div><div style={{fontSize:13,fontWeight:600,color:'#141210'}}>{d.label}</div><div style={{fontSize:11,color:'#A8A39D'}}>{d.desc}</div></div>
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>
        {/* Between-block add button */}
        <div style={{height:14,display:'flex',alignItems:'center',opacity:rowHover===block.id?1:0,transition:'opacity .12s',gap:0}}
          onMouseEnter={()=>setRowHover(block.id)} onMouseLeave={()=>setRowHover(null)}>
          <div style={{flex:1,height:1,background:'rgba(0,0,0,0.07)'}}/>
          <button onMouseDown={e=>{e.preventDefault();setAddMenu(addMenu===block.id?null:block.id);}}
            style={{width:20,height:20,borderRadius:'50%',background:'white',border:`1.5px solid ${addMenu===block.id?accent:'#D5D0CA'}`,display:'flex',alignItems:'center',justifyContent:'center',fontSize:13,cursor:'pointer',color:addMenu===block.id?accent:'#A8A39D',boxShadow:'0 1px 4px rgba(0,0,0,0.08)',transition:'all .12s',padding:0,lineHeight:1,flexShrink:0}}>+</button>
          <div style={{flex:1,height:1,background:'rgba(0,0,0,0.07)'}}/>
        </div>
        {addMenu===block.id&&(
          <div style={{position:'absolute',left:28,zIndex:200,background:'white',borderRadius:12,boxShadow:'0 8px 32px rgba(0,0,0,0.15)',border:'1px solid rgba(0,0,0,0.07)',padding:'8px',display:'flex',flexWrap:'wrap',gap:5,maxWidth:400}}>
            {BLOCK_DEFS.map(d=>(
              <button key={d.type} onMouseDown={e=>{e.preventDefault();insertB(block.id,d.type);}}
                style={{display:'flex',alignItems:'center',gap:6,padding:'6px 10px',borderRadius:7,border:'1px solid rgba(0,0,0,0.06)',background:'#FAFAF8',cursor:'pointer',fontSize:12.5,transition:'all .1s'}}
                onMouseEnter={e=>{e.currentTarget.style.background=accent+'18';e.currentTarget.style.borderColor=accent+'50';}}
                onMouseLeave={e=>{e.currentTarget.style.background='#FAFAF8';e.currentTarget.style.borderColor='rgba(0,0,0,0.06)';}}>
                <span style={{fontFamily:'monospace',fontWeight:700,color:accent,fontSize:11,minWidth:18,textAlign:'center'}}>{d.icon}</span>
                <span style={{color:'#3F3A35'}}>{d.label}</span>
              </button>
            ))}
          </div>
        )}
      </div>
    );
  };

  return(
    <div style={{flex:1,display:'flex',flexDirection:'column',overflow:'hidden',background:'white'}} onClick={e=>{if(e.target===e.currentTarget){setAddMenu(null);setSlashMenu(null);}}}>
      {/* Header mit Inline-Umbenennung */}
      <div style={{padding:'12px 22px',borderBottom:'1px solid rgba(0,0,0,0.06)',display:'flex',alignItems:'center',gap:10,flexShrink:0}}>
        <div style={{width:8,height:8,borderRadius:'50%',background:accent,flexShrink:0}}/>
        <div style={{flex:1,minWidth:0}}>
          {editingName
            ?<input value={fileName} onChange={e=>setFileName(e.target.value)} autoFocus
                onBlur={()=>{const n=fileName.trim()||file.name;onRenameFile(n);setEditingName(false);}}
                onKeyDown={e=>{if(e.key==='Enter'||e.key==='Escape'){const n=fileName.trim()||file.name;onRenameFile(n);setEditingName(false);}}}
                style={{fontSize:14,fontWeight:700,border:'none',borderBottom:`2px solid ${accent}`,outline:'none',background:'transparent',width:'100%',padding:'1px 0'}}/>
            :<div style={{display:'inline-flex',alignItems:'center',gap:5,cursor:'text'}} onClick={()=>{setFileName(file.name);setEditingName(true);}}>
                <span style={{fontWeight:700,fontSize:14,color:'#141210'}}>{file.name}</span>
                <span style={{fontSize:12,color:'#C8C3BD'}}>✎</span>
              </div>
          }
          <div style={{fontSize:11,color:'#B0ABA5',marginTop:1}}>Gespeichert {fmtDate(file.updatedAt||file.createdAt)}</div>
        </div>
        <div style={{fontSize:11,color:'#D5D0CA',flexShrink:0}}>Auto-Speicherung</div>
        {headings.length>0&&(
          <button onClick={()=>setTocOpen(v=>!v)} title="Inhaltsverzeichnis"
            style={{marginLeft:8,padding:'4px 9px',borderRadius:7,border:`1.5px solid ${tocOpen?accent:'rgba(0,0,0,0.1)'}`,background:tocOpen?accent+'15':'transparent',color:tocOpen?accent:'#A8A39D',fontSize:12.5,cursor:'pointer',fontWeight:600,transition:'all .15s',flexShrink:0}}>≡</button>
        )}
      </div>
      {/* Blöcke + ToC */}
      <div style={{flex:1,display:'flex',overflow:'hidden'}}>
        <div ref={scrollRef} style={{flex:1,overflowY:'auto',padding:'24px 32px 80px'}} onClick={e=>{if(e.target===e.currentTarget){setAddMenu(null);setSlashMenu(null);}}}>
          <div style={{maxWidth:740,margin:'0 auto'}}>
            {blocks.map((b,i)=>renderBlock(b,i))}
            <div style={{paddingTop:16}}>
              <button onMouseDown={e=>{e.preventDefault();insertB(blocks[blocks.length-1]?.id||null,'text');}}
                style={{background:'none',border:`1.5px dashed ${accent}33`,borderRadius:9,padding:'7px 20px',fontSize:13,color:'#C8C3BD',cursor:'pointer',transition:'all .12s',width:'100%',textAlign:'left'}}
                onMouseEnter={e=>{e.currentTarget.style.borderColor=accent;e.currentTarget.style.color=accent;e.currentTarget.style.background=accent+'0a';}}
                onMouseLeave={e=>{e.currentTarget.style.borderColor=accent+'33';e.currentTarget.style.color='#C8C3BD';e.currentTarget.style.background='none';}}>+ Block hinzufügen</button>
            </div>
          </div>
        </div>
        {tocOpen&&headings.length>0&&(
          <div style={{width:210,flexShrink:0,borderLeft:'1px solid rgba(0,0,0,0.07)',overflowY:'auto',padding:'18px 12px 32px',background:'#FAFAF8'}}>
            <div style={{fontSize:10.5,fontWeight:700,color:'#A8A39D',textTransform:'uppercase',letterSpacing:'0.07em',marginBottom:10,paddingLeft:6}}>Inhalt</div>
            {headings.map(h=>(
              <button key={h.id} onClick={()=>scrollToHeading(h.id)}
                style={{display:'block',width:'100%',textAlign:'left',paddingTop:5,paddingBottom:5,paddingRight:6,paddingLeft:h.type==='h1'?6:h.type==='h2'?16:26,background:'none',border:'none',borderRadius:7,cursor:'pointer',fontSize:h.type==='h1'?13:12,fontWeight:h.type==='h1'?700:h.type==='h2'?600:500,color:'#3F3A35',lineHeight:1.35,transition:'all .1s'}}
                onMouseEnter={e=>{e.currentTarget.style.background=accent+'18';e.currentTarget.style.color=accent;}}
                onMouseLeave={e=>{e.currentTarget.style.background='none';e.currentTarget.style.color='#3F3A35';}}>
                {h.type==='h2'&&<span style={{color:accent,marginRight:5,fontSize:10}}>›</span>}
                {h.type==='h3'&&<span style={{color:'#C8C3BD',marginRight:5,fontSize:10}}>·</span>}
                {h.content}
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// ─── COLD OUTREACH VIEW ─────────────────────────────────────────────────────
const COLD_STATUS = [
  {id:'aktiv',    label:'Aktiv',        color:'#f59e0b', bg:'rgba(245,158,11,.1)'},
  {id:'pausiert', label:'Pausiert',     color:'#6B6560', bg:'rgba(107,101,96,.1)'},
  {id:'fertig',   label:'Abgeschlossen',color:'#22c55e', bg:'rgba(34,197,94,.1)'},
];

function ColdOutreachView({campaigns, onUpdate}){
  const [showNew, setShowNew] = React.useState(false);
  const [form, setForm] = React.useState({name:'',zielgruppe:'',notizen:''});
  const [detail, setDetail] = React.useState(null);
  const fileInputRef = React.useRef(null);
  const dropInputRef = React.useRef(null);

  const fmtDate = iso => iso ? new Date(iso).toLocaleDateString('de-AT',{day:'2-digit',month:'2-digit',year:'numeric'}) : '';
  const fmtSize = b => b < 1024*1024 ? (b/1024).toFixed(0)+' KB' : (b/1024/1024).toFixed(1)+' MB';

  const save = () => {
    if(!form.name.trim()) return;
    const c = {id:uid(), name:form.name.trim(), zielgruppe:form.zielgruppe.trim(), notizen:form.notizen.trim(), status:'aktiv', createdAt:new Date().toISOString(), csvFiles:[]};
    onUpdate([...(campaigns||[]), c]);
    setForm({name:'',zielgruppe:'',notizen:''});
    setShowNew(false);
    setDetail(c.id);
  };

  const updateCampStatus = (id, status) => onUpdate((campaigns||[]).map(c=>c.id===id?{...c,status}:c));
  const deleteCamp = (id) => { if(!confirm('Kampagne löschen?'))return; onUpdate((campaigns||[]).filter(c=>c.id!==id)); if(detail===id)setDetail(null); };

  const handleFile = (campId, file) => {
    if(!file) return;
    if(file.size > 10*1024*1024){ alert('CSV darf maximal 10 MB groß sein.'); return; }
    const reader = new FileReader();
    reader.onload = e => {
      const content = e.target.result;
      const lines = content.split('\n').filter(l=>l.trim());
      const count = Math.max(0, lines.length - 1);
      const newFile = {id:uid(), name:file.name, size:file.size, count, uploadedAt:new Date().toISOString(), content};
      onUpdate((campaigns||[]).map(c=>c.id===campId?{...c,csvFiles:[...(c.csvFiles||[]),newFile]}:c));
    };
    reader.readAsText(file, 'UTF-8');
  };

  const deleteCSV = (campId, fileId) => {
    if(!confirm('CSV-Datei entfernen?'))return;
    onUpdate((campaigns||[]).map(c=>c.id===campId?{...c,csvFiles:(c.csvFiles||[]).filter(f=>f.id!==fileId)}:c));
  };

  const downloadCSV = (f) => {
    const blob = new Blob(['﻿'+(f.content||'')], {type:'text/csv;charset=utf-8'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = f.name; a.click();
    setTimeout(()=>URL.revokeObjectURL(url), 1000);
  };

  const activeCamp = detail ? (campaigns||[]).find(c=>c.id===detail) : null;

  if(activeCamp) return (
    <div style={{flex:1,display:'flex',flexDirection:'column',overflow:'hidden'}}>
      <div style={{padding:'10px 24px',background:'white',borderBottom:'1px solid rgba(0,0,0,.07)',display:'flex',gap:12,alignItems:'center',flexShrink:0}}>
        <button className="btn btn-ghost btn-sm" onClick={()=>setDetail(null)}>← Zurück</button>
        <div style={{flex:1}}>
          <span style={{fontWeight:700,fontSize:15}}>{activeCamp.name}</span>
          {activeCamp.zielgruppe&&<span style={{fontSize:12,color:'#A8A39D',marginLeft:10}}>{activeCamp.zielgruppe}</span>}
        </div>
        <select value={activeCamp.status} onChange={e=>updateCampStatus(activeCamp.id,e.target.value)}
          style={{fontSize:12,padding:'5px 10px',borderRadius:7,border:'1.5px solid rgba(0,0,0,.12)',background:'white',cursor:'pointer',width:'auto'}}>
          {COLD_STATUS.map(s=><option key={s.id} value={s.id}>{s.label}</option>)}
        </select>
        <button className="btn btn-danger btn-sm" onClick={()=>deleteCamp(activeCamp.id)}>Löschen</button>
      </div>
      <div style={{flex:1,overflowY:'auto',padding:28,display:'flex',flexDirection:'column',gap:20}}>
        {(activeCamp.notizen||'').trim()&&(
          <div style={{background:'white',borderRadius:12,border:'1px solid rgba(0,0,0,.08)',padding:'16px 20px'}}>
            <div style={{fontSize:11,fontWeight:600,color:'#A8A39D',textTransform:'uppercase',letterSpacing:'.06em',marginBottom:8}}>Notizen</div>
            <div style={{fontSize:13.5,color:'#3F3A35',lineHeight:1.6,whiteSpace:'pre-wrap'}}>{activeCamp.notizen}</div>
          </div>
        )}
        <div style={{background:'white',borderRadius:12,border:'1px solid rgba(0,0,0,.08)',padding:'16px 20px'}}>
          <div style={{display:'flex',alignItems:'center',gap:12,marginBottom:16}}>
            <div style={{fontSize:11,fontWeight:600,color:'#A8A39D',textTransform:'uppercase',letterSpacing:'.06em',flex:1}}>CSV-Dateien</div>
            <input ref={fileInputRef} type="file" accept=".csv" style={{display:'none'}}
              onChange={e=>{handleFile(activeCamp.id,e.target.files[0]);e.target.value='';}}/>
            <button className="btn btn-primary btn-sm" onClick={()=>fileInputRef.current?.click()}>+ CSV hochladen</button>
          </div>
          {(activeCamp.csvFiles||[]).length===0?(
            <div onClick={()=>dropInputRef.current?.click()}
              style={{border:'2px dashed rgba(0,0,0,.12)',borderRadius:10,padding:'32px',textAlign:'center',cursor:'pointer',color:'#B0ABA5'}}
              onDragOver={e=>e.preventDefault()}
              onDrop={e=>{e.preventDefault();handleFile(activeCamp.id,e.dataTransfer.files[0]);}}>
              <input ref={dropInputRef} type="file" accept=".csv" style={{display:'none'}}
                onChange={e=>{handleFile(activeCamp.id,e.target.files[0]);e.target.value='';}}/>
              <div style={{fontSize:28,marginBottom:8,opacity:.4}}>📄</div>
              <div style={{fontSize:13,fontWeight:500}}>CSV hier ablegen oder klicken</div>
              <div style={{fontSize:12,marginTop:4}}>Bereinigte Lead-Liste — max. 10 MB</div>
            </div>
          ):(
            <div style={{display:'flex',flexDirection:'column',gap:8}}>
              {(activeCamp.csvFiles||[]).map(f=>(
                <div key={f.id} style={{display:'flex',alignItems:'center',gap:12,padding:'10px 14px',background:'#F8F7F5',borderRadius:9}}>
                  <span style={{fontSize:16}}>📄</span>
                  <div style={{flex:1,minWidth:0}}>
                    <div style={{fontSize:13,fontWeight:600,whiteSpace:'nowrap',overflow:'hidden',textOverflow:'ellipsis'}}>{f.name}</div>
                    <div style={{fontSize:11,color:'#A8A39D',marginTop:2}}>{(f.count||0).toLocaleString('de-AT')} Leads · {fmtSize(f.size)} · {fmtDate(f.uploadedAt)}</div>
                  </div>
                  <button className="btn btn-ghost btn-sm" onClick={()=>downloadCSV(f)}>⬇ Download</button>
                  <button className="btn btn-ghost btn-sm" style={{color:'#ef4444'}} onClick={()=>deleteCSV(activeCamp.id,f.id)}>✕</button>
                </div>
              ))}
            </div>
          )}
        </div>
        <div style={{display:'grid',gridTemplateColumns:'repeat(3,1fr)',gap:12}}>
          {[
            {label:'Leads gesamt', value:(activeCamp.csvFiles||[]).reduce((s,f)=>s+(f.count||0),0).toLocaleString('de-AT'), icon:'👥'},
            {label:'CSV-Dateien',  value:(activeCamp.csvFiles||[]).length, icon:'📂'},
            {label:'Erstellt',     value:fmtDate(activeCamp.createdAt), icon:'📅'},
          ].map(s=>(
            <div key={s.label} style={{background:'white',borderRadius:12,border:'1px solid rgba(0,0,0,.08)',padding:'14px 16px'}}>
              <div style={{fontSize:20,marginBottom:6}}>{s.icon}</div>
              <div style={{fontSize:18,fontWeight:800,letterSpacing:'-0.02em'}}>{s.value}</div>
              <div style={{fontSize:11,color:'#A8A39D',marginTop:2}}>{s.label}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );

  return (
    <div style={{flex:1,display:'flex',flexDirection:'column',overflow:'hidden'}}>
      <div style={{padding:'10px 24px',background:'white',borderBottom:'1px solid rgba(0,0,0,.07)',display:'flex',gap:12,alignItems:'center',flexShrink:0}}>
        <div style={{flex:1}}/>
        <button className="btn btn-primary" onClick={()=>setShowNew(v=>!v)}>+ Neue Kampagne</button>
      </div>
      {showNew&&(
        <div style={{padding:'20px 24px',background:'#FAFAF8',borderBottom:'1px solid rgba(0,0,0,.07)'}}>
          <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:12,marginBottom:12,maxWidth:680}}>
            <div>
              <label style={{fontSize:12,fontWeight:600,color:'#6B6560',display:'block',marginBottom:5}}>Kampagnen-Name *</label>
              <input value={form.name} onChange={e=>setForm(f=>({...f,name:e.target.value}))} placeholder="z.B. USA Cleaning — Welle 1" autoFocus
                onKeyDown={e=>e.key==='Enter'&&save()}/>
            </div>
            <div>
              <label style={{fontSize:12,fontWeight:600,color:'#6B6560',display:'block',marginBottom:5}}>Zielgruppe</label>
              <input value={form.zielgruppe} onChange={e=>setForm(f=>({...f,zielgruppe:e.target.value}))} placeholder="z.B. Reinigungsfirmen USA, 1–10 MA"/>
            </div>
          </div>
          <div style={{maxWidth:680,marginBottom:12}}>
            <label style={{fontSize:12,fontWeight:600,color:'#6B6560',display:'block',marginBottom:5}}>Notizen (optional)</label>
            <textarea value={form.notizen} onChange={e=>setForm(f=>({...f,notizen:e.target.value}))} placeholder="Sequenz-Tool, Domain-Rotation, Besonderheiten…" style={{minHeight:60}}/>
          </div>
          <div style={{display:'flex',gap:8}}>
            <button className="btn btn-primary" onClick={save}>Erstellen</button>
            <button className="btn btn-ghost" onClick={()=>setShowNew(false)}>Abbrechen</button>
          </div>
        </div>
      )}
      <div style={{flex:1,overflowY:'auto',padding:28}}>
        {(campaigns||[]).length===0&&!showNew?(
          <div style={{textAlign:'center',padding:'80px 20px',color:'#C8C3BD'}}>
            <div style={{fontSize:52,marginBottom:16,opacity:.4}}>📨</div>
            <div style={{fontSize:16,fontWeight:600,color:'#C0BBB5',marginBottom:8}}>Noch keine Kampagne</div>
            <div style={{fontSize:13,lineHeight:1.6,marginBottom:24}}>Erstelle eine Kampagne und lade die bereinigte CSV-Datei hoch.<br/>Jede Kampagne hat ihren eigenen Status und ihre eigenen Leads.</div>
            <button className="btn btn-primary" onClick={()=>setShowNew(true)}>+ Erste Kampagne erstellen</button>
          </div>
        ):(
          <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fill,minmax(280px,1fr))',gap:16}}>
            {(campaigns||[]).map(c=>{
              const st = COLD_STATUS.find(s=>s.id===c.status)||COLD_STATUS[0];
              const totalLeads = (c.csvFiles||[]).reduce((s,f)=>s+(f.count||0),0);
              return(
                <div key={c.id} onClick={()=>setDetail(c.id)}
                  style={{background:'white',borderRadius:14,border:'1px solid rgba(0,0,0,.08)',boxShadow:'0 1px 4px rgba(0,0,0,.05)',cursor:'pointer',overflow:'hidden',transition:'all .15s'}}
                  onMouseEnter={e=>{e.currentTarget.style.transform='translateY(-2px)';e.currentTarget.style.boxShadow='0 6px 20px rgba(0,0,0,.1)';}}
                  onMouseLeave={e=>{e.currentTarget.style.transform='translateY(0)';e.currentTarget.style.boxShadow='0 1px 4px rgba(0,0,0,.05)';}}>
                  <div style={{height:4,background:st.color}}/>
                  <div style={{padding:'16px 18px 14px'}}>
                    <div style={{display:'flex',alignItems:'flex-start',gap:10,marginBottom:10}}>
                      <div style={{flex:1}}>
                        <div style={{fontSize:14,fontWeight:700,color:'#141210',lineHeight:1.3}}>{c.name}</div>
                        {c.zielgruppe&&<div style={{fontSize:11.5,color:'#A8A39D',marginTop:3}}>{c.zielgruppe}</div>}
                      </div>
                      <span style={{fontSize:11,fontWeight:600,color:st.color,background:st.bg,borderRadius:99,padding:'3px 8px',whiteSpace:'nowrap',flexShrink:0}}>{st.label}</span>
                    </div>
                    <div style={{display:'flex',gap:16,fontSize:12,color:'#6B6560'}}>
                      <span>👥 {totalLeads>0?totalLeads.toLocaleString('de-AT')+' Leads':'Keine Leads'}</span>
                      <span>📂 {(c.csvFiles||[]).length} CSV</span>
                    </div>
                    <div style={{marginTop:8,fontSize:11,color:'#C0BBB5'}}>Erstellt {fmtDate(c.createdAt)}</div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

// ─── LINKEDIN MULTI-SESSION ───────────────────────────────────────────────────
function LinkedInOutreachBot(){
  const AUTH = {'Authorization': `Bearer ${window.WEBARS_API_TOKEN}`, 'Content-Type': 'application/json'};
  const [openSession, setOpenSession] = React.useState(null); // null = Übersicht
  if(openSession) return <LinkedInSessionDetail id={openSession} onBack={()=>setOpenSession(null)} AUTH={AUTH}/>;
  return <LinkedInSessionOverview onOpen={setOpenSession} AUTH={AUTH}/>;
}

// ── Übersicht: alle Sessions als Karten ───────────────────────────────────────
function LinkedInSessionOverview({ onOpen, AUTH }){
  const [sessions, setSessions] = React.useState([]);
  const [loading, setLoading] = React.useState(true);
  const [creating, setCreating] = React.useState(false);
  const [err, setErr] = React.useState('');

  async function load(){
    try{
      const r = await fetch('/api/linkedin/sessions',{headers:AUTH});
      const d = await r.json();
      if(Array.isArray(d)) setSessions(d);
    }catch{}
    setLoading(false);
  }

  React.useEffect(()=>{ load(); const iv=setInterval(load,8000); return()=>clearInterval(iv); },[]);

  async function createSession(){
    setCreating(true); setErr('');
    try{
      const r = await fetch('/api/linkedin/sessions',{method:'POST',headers:AUTH,body:JSON.stringify({name:'Neue Session'})});
      const d = await r.json();
      if(d.error) throw new Error(d.error);
      setSessions(s=>[...s,d]);
      onOpen(d.id);
    }catch(e){ setErr(e.message); }
    setCreating(false);
  }

  async function deleteSession(id, e){
    e.stopPropagation();
    if(!confirm('Session löschen?')) return;
    try{
      const r = await fetch(`/api/linkedin/sessions/${id}`,{method:'DELETE',headers:AUTH});
      const d = await r.json();
      if(d.error) throw new Error(d.error);
      setSessions(s=>s.filter(x=>x.id!==id));
    }catch(ex){ setErr(ex.message); }
  }

  const dotColor = st => st==='running'?'#22c55e':st==='error'?'#ef4444':'#d1d5db';
  const statusLabel = st => st==='running'?'Läuft':st==='error'?'Fehler':'Gestoppt';

  return(
    <div style={{flex:1,overflowY:'auto',padding:28,display:'flex',flexDirection:'column',gap:20}}>
      <div style={{display:'flex',alignItems:'center',gap:12}}>
        <div style={{flex:1}}>
          <div style={{fontSize:18,fontWeight:800,letterSpacing:'-0.02em'}}>LinkedIn Outreach</div>
          <div style={{fontSize:12,color:'#B0ABA5',marginTop:2}}>Tages-Limit: max. 15 Anfragen gesamt über alle Sessions</div>
        </div>
        <button className="btn btn-primary btn-sm" onClick={createSession} disabled={creating}>{creating?'…':'+ Neue Session'}</button>
      </div>

      {err&&<div style={{background:'rgba(239,68,68,.08)',border:'1px solid rgba(239,68,68,.2)',borderRadius:10,padding:'10px 14px',fontSize:12,color:'#ef4444'}}>{err}</div>}

      {loading?(
        <div style={{textAlign:'center',padding:'60px 20px',color:'#C8C3BD',fontSize:13}}>Lädt…</div>
      ):sessions.length===0?(
        <div style={{textAlign:'center',padding:'60px 20px',color:'#C8C3BD'}}>
          <div style={{fontSize:40,marginBottom:12,opacity:.3}}>💼</div>
          <div style={{fontSize:14,fontWeight:600,marginBottom:6}}>Noch keine Sessions</div>
          <div style={{fontSize:12,marginBottom:20}}>Erstelle eine Session um LinkedIn-Outreach zu starten</div>
          <button className="btn btn-primary btn-sm" onClick={createSession} disabled={creating}>{creating?'…':'+ Erste Session erstellen'}</button>
        </div>
      ):(
        <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fill,minmax(280px,1fr))',gap:16}}>
          {sessions.map(s=>{
            const st = s.status?.status||'stopped';
            const isRunning = st==='running';
            return(
              <div key={s.id} onClick={()=>onOpen(s.id)}
                style={{background:'white',borderRadius:14,border:`1px solid ${isRunning?'rgba(34,197,94,.25)':'rgba(0,0,0,.08)'}`,padding:'18px 20px',cursor:'pointer',transition:'box-shadow .15s',boxShadow:'0 1px 4px rgba(0,0,0,.05)'}}
                onMouseEnter={e=>e.currentTarget.style.boxShadow='0 4px 16px rgba(0,0,0,.1)'}
                onMouseLeave={e=>e.currentTarget.style.boxShadow='0 1px 4px rgba(0,0,0,.05)'}>
                <div style={{display:'flex',alignItems:'flex-start',gap:10,marginBottom:12}}>
                  <div style={{width:10,height:10,borderRadius:'50%',background:dotColor(st),marginTop:4,flexShrink:0,boxShadow:isRunning?'0 0 0 3px rgba(34,197,94,.2)':'none'}}/>
                  <div style={{flex:1,fontWeight:700,fontSize:14,color:'#141210',lineHeight:1.3}}>{s.name}</div>
                  <button onClick={e=>deleteSession(s.id,e)} className="btn btn-ghost btn-sm btn-icon" style={{flexShrink:0,opacity:.5,fontSize:14}} title="Löschen">✕</button>
                </div>
                <div style={{display:'flex',gap:8,flexWrap:'wrap',marginBottom:12}}>
                  <span style={{fontSize:11,fontWeight:600,color:dotColor(st),background:isRunning?'rgba(34,197,94,.1)':st==='error'?'rgba(239,68,68,.08)':'rgba(0,0,0,.04)',borderRadius:99,padding:'2px 8px'}}>{statusLabel(st)}</span>
                  {s.hasCookies&&<span style={{fontSize:11,color:'#22c55e',background:'rgba(34,197,94,.08)',borderRadius:99,padding:'2px 8px',fontWeight:600}}>Cookies ✓</span>}
                  {s.hasProxy&&<span style={{fontSize:11,color:'#2563eb',background:'rgba(37,99,235,.08)',borderRadius:99,padding:'2px 8px',fontWeight:600}}>Proxy ✓</span>}
                </div>
                <div style={{fontSize:12,color:'#A8A39D'}}>
                  {s.status?.sentToday||0} heute gesendet · {s.status?.totalSent||0} gesamt
                </div>
                {s.status?.lastError&&st==='error'&&(
                  <div style={{fontSize:11,color:'#ef4444',marginTop:8,lineHeight:1.4}}>{s.status.lastError.slice(0,100)}</div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ── Detail-View: eine Session konfigurieren + starten ─────────────────────────
function LinkedInSessionDetail({ id, onBack, AUTH }){

  const [name, setName] = React.useState('');
  const [botStatus, setBotStatus] = React.useState({status:'stopped',sentToday:0,totalSent:0,dailyMax:15,remainingToday:15});
  const [log, setLog] = React.useState([]);
  const [config, setConfig] = React.useState({ zielgruppe:'', tagLimit:15, message:'', cookies:'', anthropicKey:'', proxy:'' });
  const [serverHasCookies, setServerHasCookies] = React.useState(false);
  const [serverHasKey, setServerHasKey] = React.useState(false);
  const [serverHasProxy, setServerHasProxy] = React.useState(false);
  const [saving, setSaving] = React.useState(false);
  const [saveMsg, setSaveMsg] = React.useState('');
  const [actionBusy, setActionBusy] = React.useState(false);
  const [err, setErr] = React.useState('');

  const cookiesValid = React.useMemo(()=>{ try{ const p=JSON.parse(config.cookies); return Array.isArray(p)&&p.length>0; }catch{ return false; } },[config.cookies]);

  React.useEffect(()=>{
    fetch(`/api/linkedin/sessions/${id}/config`,{headers:AUTH}).then(r=>r.json()).then(d=>{
      if(d.error) return;
      setConfig(c=>({...c,zielgruppe:d.zielgruppe||c.zielgruppe,tagLimit:d.tagLimit||c.tagLimit,message:d.message||c.message}));
      if(d.name) setName(d.name);
      setServerHasCookies(!!d.hasCookies); setServerHasKey(!!d.hasApiKey); setServerHasProxy(!!d.hasProxy);
    }).catch(()=>{});
    fetchStatus(); fetchLog();
  },[id]);

  React.useEffect(()=>{
    if(botStatus.status!=='running') return;
    const iv=setInterval(()=>{ fetchStatus(); fetchLog(); },6000);
    return()=>clearInterval(iv);
  },[botStatus.status]);

  function fetchStatus(){ fetch(`/api/linkedin/sessions/${id}/status`,{headers:AUTH}).then(r=>r.json()).then(d=>{ if(!d.error) setBotStatus(d); }).catch(()=>{}); }
  function fetchLog(){ fetch(`/api/linkedin/sessions/${id}/log?limit=100`,{headers:AUTH}).then(r=>r.json()).then(d=>{ if(d.log) setLog(d.log); }).catch(()=>{}); }

  async function saveConfig(){
    setSaving(true); setSaveMsg(''); setErr('');
    try{
      const body = {zielgruppe:config.zielgruppe,tagLimit:config.tagLimit,message:config.message};
      if(name.trim()) body.name=name.trim();
      if(config.cookies.trim()) body.cookies=config.cookies;
      if(config.anthropicKey.trim()) body.anthropicKey=config.anthropicKey;
      if(config.proxy.trim()) body.proxy=config.proxy;
      const r = await fetch(`/api/linkedin/sessions/${id}/config`,{method:'PUT',headers:AUTH,body:JSON.stringify(body)});
      const ct=r.headers.get('content-type')||'';
      if(!ct.includes('json')) throw new Error('Server noch nicht bereit — Seite neu laden.');
      const d=await r.json(); if(d.error) throw new Error(d.error);
      setServerHasCookies(!!d.hasCookies); setServerHasKey(!!d.hasApiKey); setServerHasProxy(!!d.hasProxy);
      setSaveMsg('✓ Gespeichert'); setTimeout(()=>setSaveMsg(''),2000);
      setConfig(c=>({...c,cookies:'',anthropicKey:'',proxy:''})); setName('');
    }catch(e){ setErr(e.message); }
    setSaving(false);
  }

  async function handleStart(){
    setActionBusy(true); setErr('');
    try{
      await saveConfig();
      const r=await fetch(`/api/linkedin/sessions/${id}/start`,{method:'POST',headers:AUTH,body:JSON.stringify({})});
      const d=await r.json(); if(d.error) throw new Error(d.error);
      setBotStatus(s=>({...s,status:'running'})); fetchLog();
    }catch(e){ setErr(e.message); }
    setActionBusy(false);
  }

  async function handleStop(){
    setActionBusy(true);
    try{ await fetch(`/api/linkedin/sessions/${id}/stop`,{method:'POST',headers:AUTH}); setBotStatus(s=>({...s,status:'stopped'})); fetchStatus(); }
    catch(e){ setErr(e.message); }
    setActionBusy(false);
  }

  const isRunning = botStatus.status==='running';
  const dotColor = isRunning?'#22c55e':botStatus.status==='error'?'#ef4444':'#d1d5db';
  const levelColor = lvl => lvl==='success'?'#16a34a':lvl==='error'?'#ef4444':lvl==='warn'?'#d97706':'#A8A39D';

  return(
    <div style={{flex:1,overflowY:'auto',padding:28,display:'flex',flexDirection:'column',gap:20}}>

      {/* Header mit Zurück-Button */}
      <div style={{display:'flex',alignItems:'center',gap:12}}>
        <button className="btn btn-ghost btn-sm" onClick={onBack} style={{flexShrink:0}}>← Zurück</button>
        <div style={{flex:1,fontSize:15,fontWeight:700,color:'#141210'}}>Session konfigurieren</div>
        <div style={{fontSize:12,color:'#A8A39D'}}>Tages-Limit: {botStatus.sentToday||0}/{botStatus.dailyMax||15}</div>
      </div>

      {/* Status-Bar */}
      <div style={{background:'white',borderRadius:14,border:'1px solid rgba(0,0,0,.08)',padding:'18px 22px',display:'flex',alignItems:'center',gap:16}}>
        <div style={{width:12,height:12,borderRadius:'50%',background:dotColor,flexShrink:0,boxShadow:isRunning?'0 0 0 4px rgba(34,197,94,.2)':'none',transition:'all .3s'}}/>
        <div style={{flex:1}}>
          <div style={{fontSize:14,fontWeight:700,color:'#141210'}}>{isRunning?`Läuft — ${botStatus.sentToday} heute gesendet`:botStatus.status==='error'?'Fehler':'Gestoppt'}</div>
          <div style={{fontSize:12,color:'#A8A39D',marginTop:2}}>{isRunning?'LinkedIn-Outreach aktiv':botStatus.lastError||`Gesamt: ${botStatus.totalSent||0} gesendet`}</div>
        </div>
        <button onClick={isRunning?handleStop:handleStart} disabled={actionBusy||(!serverHasCookies&&!cookiesValid)} className={'btn btn-sm '+(isRunning?'btn-danger':'btn-primary')}>
          {actionBusy?'…':isRunning?'Stop':'Start'}
        </button>
      </div>

      {err&&<div style={{background:'rgba(239,68,68,.08)',border:'1px solid rgba(239,68,68,.2)',borderRadius:10,padding:'10px 14px',fontSize:12,color:'#ef4444'}}>{err}</div>}

      {/* Konfiguration */}
      <div style={{background:'white',borderRadius:14,border:'1px solid rgba(0,0,0,.08)',padding:'18px 22px'}}>
        <div style={{fontSize:11,fontWeight:600,color:'#A8A39D',textTransform:'uppercase',letterSpacing:'.06em',marginBottom:14}}>Konfiguration</div>
        <div style={{display:'flex',flexDirection:'column',gap:12}}>
          <div>
            <label style={{fontSize:12,fontWeight:600,color:'#6B6560',display:'block',marginBottom:5}}>Session-Name</label>
            <input value={name} onChange={e=>setName(e.target.value)} placeholder="z.B. HVAC USA, Plumbers Wien …"/>
          </div>
          <div>
            <label style={{fontSize:12,fontWeight:600,color:'#6B6560',display:'block',marginBottom:5}}>Zielgruppe (Suchbegriff)</label>
            <input value={config.zielgruppe} onChange={e=>setConfig(c=>({...c,zielgruppe:e.target.value}))} placeholder="z.B. HVAC Owner USA"/>
          </div>
          <div>
            <label style={{fontSize:12,fontWeight:600,color:'#6B6560',display:'block',marginBottom:5}}>Max. Anfragen pro Session (Hard-Limit: 15/Tag gesamt)</label>
            <input type="number" value={config.tagLimit} min={1} max={15} onChange={e=>setConfig(c=>({...c,tagLimit:parseInt(e.target.value)||15}))} style={{maxWidth:100}}/>
          </div>
          <div>
            <label style={{fontSize:12,fontWeight:600,color:'#6B6560',display:'block',marginBottom:5}}>Connection-Nachricht (max. 300 Zeichen)</label>
            <textarea value={config.message} onChange={e=>setConfig(c=>({...c,message:e.target.value.slice(0,300)}))} style={{minHeight:80,fontFamily:'inherit',resize:'vertical'}}/>
            <div style={{fontSize:11,color:config.message.length>280?'#ef4444':'#C0BBB5',marginTop:4,textAlign:'right'}}>{config.message.length}/300</div>
          </div>
          <div>
            <label style={{fontSize:12,fontWeight:600,color:'#6B6560',display:'block',marginBottom:5}}>Anthropic API-Key {serverHasKey&&<span style={{color:'#22c55e',fontWeight:400}}>✓ gespeichert</span>}</label>
            <input type="password" value={config.anthropicKey} onChange={e=>setConfig(c=>({...c,anthropicKey:e.target.value}))} placeholder={serverHasKey?'(gespeichert — neu eingeben zum Ändern)':'sk-ant-api03-...'}/>
            <div style={{fontSize:11,color:'#C0BBB5',marginTop:4}}>Optional — für Haiku-Personalisierung</div>
          </div>
          <div>
            <label style={{fontSize:12,fontWeight:600,color:'#6B6560',display:'block',marginBottom:5}}>Residential Proxy {serverHasProxy&&<span style={{color:'#22c55e',fontWeight:400}}>✓ aktiv</span>}</label>
            <input type="password" value={config.proxy} onChange={e=>setConfig(c=>({...c,proxy:e.target.value}))} placeholder={serverHasProxy?'(gespeichert — neu eingeben zum Ändern)':'http://user:pass@proxy.smartproxy.net:3120'}/>
            <div style={{fontSize:11,color:'#C0BBB5',marginTop:4}}>Pflicht — ohne Proxy startet der Bot nicht</div>
          </div>
        </div>
      </div>

      {/* LinkedIn Session (Cookies) */}
      <div style={{background:'white',borderRadius:14,border:`1px solid ${(cookiesValid||serverHasCookies)?'rgba(34,197,94,.3)':'rgba(0,0,0,.08)'}`,padding:'18px 22px'}}>
        <div style={{display:'flex',alignItems:'center',gap:10,marginBottom:6}}>
          <div style={{fontSize:11,fontWeight:600,color:'#A8A39D',textTransform:'uppercase',letterSpacing:'.06em',flex:1}}>LinkedIn Session (Cookies)</div>
          {serverHasCookies&&<span style={{fontSize:11,fontWeight:600,color:'#22c55e',background:'rgba(34,197,94,.1)',borderRadius:99,padding:'2px 8px'}}>✓ gespeichert</span>}
        </div>
        <div style={{fontSize:12,color:'#A8A39D',marginBottom:12,lineHeight:1.6}}>linkedin.com → Cookie-Editor → Export as JSON → hier einfügen</div>
        <textarea value={config.cookies} onChange={e=>setConfig(c=>({...c,cookies:e.target.value}))}
          placeholder='[{"name":"li_at","value":"...","domain":".linkedin.com",...}]'
          style={{minHeight:80,fontFamily:'monospace',fontSize:11,resize:'vertical',color:cookiesValid?'#16a34a':'inherit'}}/>
        {config.cookies.trim()&&!cookiesValid&&<div style={{fontSize:11,color:'#ef4444',marginTop:4}}>⚠ Ungültiges JSON</div>}
      </div>

      {/* Speichern */}
      <div style={{display:'flex',justifyContent:'flex-end',gap:10,alignItems:'center'}}>
        {saveMsg&&<span style={{fontSize:12,color:'#22c55e',fontWeight:600}}>{saveMsg}</span>}
        <button className="btn btn-primary btn-sm" onClick={saveConfig} disabled={saving}>{saving?'Speichert…':'Einstellungen speichern'}</button>
      </div>

      {/* Log */}
      <div style={{background:'white',borderRadius:14,border:'1px solid rgba(0,0,0,.08)',padding:'18px 22px'}}>
        <div style={{display:'flex',alignItems:'center',gap:10,marginBottom:14}}>
          <div style={{fontSize:11,fontWeight:600,color:'#A8A39D',textTransform:'uppercase',letterSpacing:'.06em',flex:1}}>Aktivitäts-Log</div>
          {isRunning&&<div style={{fontSize:11,color:'#22c55e',fontWeight:600}}>● Live</div>}
          {log.length>0&&<button className="btn btn-ghost btn-sm" onClick={fetchLog}>Aktualisieren</button>}
        </div>
        {log.length===0?(
          <div style={{textAlign:'center',padding:'40px 20px',color:'#C8C3BD'}}>
            <div style={{fontSize:13,fontWeight:500}}>Noch keine Aktivität</div>
            <div style={{fontSize:12,marginTop:4}}>Gesendete Connection Requests erscheinen hier</div>
          </div>
        ):(
          <div style={{display:'flex',flexDirection:'column',gap:4,maxHeight:400,overflowY:'auto'}}>
            {log.map((entry,i)=>(
              <div key={i} style={{display:'flex',gap:10,padding:'7px 10px',background:'#F8F7F5',borderRadius:8,fontSize:12,alignItems:'flex-start'}}>
                <span style={{color:'#C0BBB5',flexShrink:0,fontFamily:'monospace',fontSize:11}}>{entry.ts?entry.ts.slice(11,19):''}</span>
                <span style={{color:levelColor(entry.level),flexShrink:0,fontWeight:600,width:48}}>{entry.level}</span>
                <span style={{color:'#3F3A35',flex:1,lineHeight:1.5}}>{entry.msg}{entry.company?` · ${entry.company}`:''}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// ─── AUTOMATISIERUNG AUSWAHL ──────────────────────────────────────────────────
function AutomatisierungView(){
  const [subView, setSubView] = React.useState(null);

  if(subView==='linkedin') return <LinkedInOutreachBot/>;

  const cards = [
    {id:'linkedin', icon:'💼', title:'LinkedIn Outreach', desc:'Automatisch Verbindungsanfragen\nund Follow-ups versenden', badge:null},
    {id:'email',    icon:'📧', title:'Email Sequenz',     desc:'Cold-Email Kampagnen\nautomatisch versenden',          badge:'Demnächst'},
    {id:'followup', icon:'🔔', title:'Follow-up Bot',     desc:'Offene Leads automatisch\nnachfassen',                  badge:'Demnächst'},
  ];

  return (
    <div style={{flex:1,display:'flex',flexDirection:'column',overflow:'hidden'}}>
      <div style={{background:'white',borderBottom:'1px solid rgba(0,0,0,.07)',padding:'14px 28px',flexShrink:0}}>
        <h1 style={{fontSize:18,fontWeight:800,letterSpacing:'-0.02em'}}>⚡ Automatisierungen</h1>
        <div style={{fontSize:12,color:'#B0ABA5',marginTop:2}}>Wähle eine Automatisierung</div>
      </div>
      <div style={{flex:1,display:'flex',alignItems:'center',justifyContent:'center',padding:40,gap:20,background:'#F8F7F5',flexWrap:'wrap'}}>
        {cards.map(card=>(
          <div key={card.id}
            onClick={()=>{if(!card.badge)setSubView(card.id);}}
            style={{background:'white',borderRadius:16,border:'1px solid rgba(0,0,0,.08)',boxShadow:'0 2px 8px rgba(0,0,0,.06)',cursor:card.badge?'default':'pointer',padding:'36px 28px',width:220,textAlign:'center',transition:'all .15s',opacity:card.badge?.9:1,position:'relative'}}
            onMouseEnter={e=>{if(!card.badge){e.currentTarget.style.transform='translateY(-3px)';e.currentTarget.style.boxShadow='0 10px 28px rgba(0,0,0,.12)';}}}
            onMouseLeave={e=>{e.currentTarget.style.transform='translateY(0)';e.currentTarget.style.boxShadow='0 2px 8px rgba(0,0,0,.06)';}}>
            {card.badge&&<div style={{position:'absolute',top:14,right:14,fontSize:10,fontWeight:700,color:'#A8A39D',background:'#F0EDE8',borderRadius:99,padding:'2px 8px'}}>{card.badge}</div>}
            <div style={{fontSize:40,marginBottom:14}}>{card.icon}</div>
            <div style={{fontSize:15,fontWeight:700,color:'#141210',marginBottom:8}}>{card.title}</div>
            <div style={{fontSize:13,color:'#A8A39D',lineHeight:1.6,whiteSpace:'pre-line'}}>{card.desc}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── COLD OUTREACH CONTAINER ──────────────────────────────────────────────────
function ColdOutreachContainer({campaigns, onUpdate}){
  const [subView, setSubView] = React.useState(null); // null | 'kampagnen' | 'automatisierung'

  if(!subView) return (
    <div style={{flex:1,display:'flex',flexDirection:'column',overflow:'hidden'}}>
      <div style={{background:'white',borderBottom:'1px solid rgba(0,0,0,.07)',padding:'14px 28px',flexShrink:0}}>
        <h1 style={{fontSize:18,fontWeight:800,letterSpacing:'-0.02em'}}>📨 Cold Outreach</h1>
        <div style={{fontSize:12,color:'#B0ABA5',marginTop:2}}>Wähle einen Bereich</div>
      </div>
      <div style={{flex:1,display:'flex',alignItems:'center',justifyContent:'center',padding:40,gap:24,background:'#F8F7F5'}}>
        {[
          {id:'kampagnen',      icon:'📋', title:'Kampagnen',      desc:'CSV-Leads verwalten und\nKampagnen-Status tracken'},
          {id:'automatisierung',icon:'🤖', title:'Automatisierung',desc:'LinkedIn-Outreach automatisch\nversenden und tracken'},
        ].map(card=>(
          <div key={card.id} onClick={()=>setSubView(card.id)}
            style={{background:'white',borderRadius:16,border:'1px solid rgba(0,0,0,.08)',boxShadow:'0 2px 8px rgba(0,0,0,.06)',cursor:'pointer',padding:'36px 32px',width:240,textAlign:'center',transition:'all .15s'}}
            onMouseEnter={e=>{e.currentTarget.style.transform='translateY(-3px)';e.currentTarget.style.boxShadow='0 10px 28px rgba(0,0,0,.12)';}}
            onMouseLeave={e=>{e.currentTarget.style.transform='translateY(0)';e.currentTarget.style.boxShadow='0 2px 8px rgba(0,0,0,.06)';}}>
            <div style={{fontSize:44,marginBottom:14}}>{card.icon}</div>
            <div style={{fontSize:16,fontWeight:700,color:'#141210',marginBottom:8}}>{card.title}</div>
            <div style={{fontSize:13,color:'#A8A39D',lineHeight:1.6,whiteSpace:'pre-line'}}>{card.desc}</div>
          </div>
        ))}
      </div>
    </div>
  );

  if(subView==='kampagnen') return (
    <div style={{flex:1,display:'flex',flexDirection:'column',overflow:'hidden'}}>
      <div style={{background:'white',borderBottom:'1px solid rgba(0,0,0,.07)',padding:'10px 24px',display:'flex',alignItems:'center',gap:14,flexShrink:0}}>
        <button className="btn btn-ghost btn-sm" onClick={()=>setSubView(null)}>← Zurück</button>
        <div style={{flex:1}}>
          <h1 style={{fontSize:18,fontWeight:800,letterSpacing:'-0.02em'}}>📋 Kampagnen</h1>
          <div style={{fontSize:12,color:'#B0ABA5',marginTop:2}}>
            {(campaigns||[]).filter(c=>c.status==='aktiv').length} aktiv · {(campaigns||[]).reduce((s,c)=>s+(c.csvFiles||[]).reduce((a,f)=>a+f.count,0),0).toLocaleString('de-AT')} Leads gesamt
          </div>
        </div>
      </div>
      <ColdOutreachView campaigns={campaigns} onUpdate={onUpdate}/>
    </div>
  );

  return (
    <div style={{flex:1,display:'flex',flexDirection:'column',overflow:'hidden'}}>
      <div style={{background:'white',borderBottom:'1px solid rgba(0,0,0,.07)',padding:'10px 24px',display:'flex',alignItems:'center',gap:14,flexShrink:0}}>
        <button className="btn btn-ghost btn-sm" onClick={()=>setSubView(null)}>← Zurück</button>
        <div style={{flex:1}}>
          <h1 style={{fontSize:18,fontWeight:800,letterSpacing:'-0.02em'}}>⚡ Automatisierungen</h1>
          <div style={{fontSize:12,color:'#B0ABA5',marginTop:2}}>Automatisierte Outreach-Tools</div>
        </div>
      </div>
      <AutomatisierungView/>
    </div>
  );
}

function CampaignsView({campaigns, onUpdate}){
  const [view,setView]=useState('overview'); // 'overview' | 'campaign'
  const [selCamp,setSelCamp]=useState(null);
  const [selFile,setSelFile]=useState(null);
  const [addingCamp,setAddingCamp]=useState(false);
  const [newCampName,setNewCampName]=useState('');
  const [newCampEmoji,setNewCampEmoji]=useState('💡');
  const [addingFile,setAddingFile]=useState(false);
  const [newFileName,setNewFileName]=useState('');
  const [renamingCamp,setRenamingCamp]=useState(null);
  const [renamingFile,setRenamingFile]=useState(null);
  const [renameVal,setRenameVal]=useState('');

  const openCamp=c=>{setSelCamp(c.id);setSelFile(null);setView('campaign');};
  const goBack=()=>{setView('overview');setSelCamp(null);setSelFile(null);};

  const createCamp=()=>{
    if(!newCampName.trim())return;
    const c={id:uid(),name:newCampName.trim(),emoji:newCampEmoji,color:CAMPAIGN_COLORS[Math.floor(Math.random()*CAMPAIGN_COLORS.length)],createdAt:new Date().toISOString(),files:[]};
    onUpdate([...(campaigns||[]),c]);
    setAddingCamp(false);setNewCampName('');setNewCampEmoji('💡');
    openCamp(c);
  };
  const deleteCamp=id=>{
    if(!confirm('Mappe und alle Dateien darin löschen?'))return;
    onUpdate((campaigns||[]).filter(c=>c.id!==id));
    if(selCamp===id)goBack();
  };
  const createFile=()=>{
    if(!newFileName.trim()||!selCamp)return;
    const f={id:uid(),name:newFileName.trim(),content:'',createdAt:new Date().toISOString(),updatedAt:new Date().toISOString()};
    onUpdate((campaigns||[]).map(c=>c.id!==selCamp?c:{...c,files:[...(c.files||[]),f]}));
    setSelFile(f.id);setAddingFile(false);setNewFileName('');
  };
  const deleteFile=(campId,fileId)=>{
    if(!confirm('Datei löschen?'))return;
    onUpdate((campaigns||[]).map(c=>c.id!==campId?c:{...c,files:(c.files||[]).filter(f=>f.id!==fileId)}));
    if(selFile===fileId)setSelFile(null);
  };
  const doRenameCamp=()=>{
    if(!renameVal.trim())return;
    onUpdate((campaigns||[]).map(c=>c.id!==renamingCamp?c:{...c,name:renameVal.trim()}));
    setRenamingCamp(null);setRenameVal('');
  };
  const doRenameFile=()=>{
    if(!renameVal.trim()||!selCamp)return;
    onUpdate((campaigns||[]).map(c=>c.id!==selCamp?c:{...c,files:(c.files||[]).map(f=>f.id!==renamingFile?f:{...f,name:renameVal.trim()})}));
    setRenamingFile(null);setRenameVal('');
  };

  const activeCamp=(campaigns||[]).find(c=>c.id===selCamp);
  const activeFile=activeCamp&&selFile?(activeCamp.files||[]).find(f=>f.id===selFile):null;
  const fmtDate=iso=>iso?new Date(iso).toLocaleDateString('de-AT',{day:'2-digit',month:'2-digit',year:'numeric'}):'';
  const lastUpdated=c=>{const dates=(c.files||[]).map(f=>f.updatedAt||f.createdAt).filter(Boolean).sort();return dates[dates.length-1]||c.createdAt;};

  // ── ÜBERSICHT ──────────────────────────────────────────────────
  if(view==='overview') return(
    <div style={{flex:1,display:'flex',flexDirection:'column',overflow:'hidden'}}>
      <div style={{padding:'10px 28px',background:'white',borderBottom:'1px solid rgba(0,0,0,0.07)',display:'flex',gap:10,alignItems:'center',flexShrink:0}}>
        <div style={{flex:1}}/>
        <button className="btn btn-primary" onClick={()=>{setAddingCamp(true);setNewCampName('');setNewCampEmoji('📁');}}><Icons.Plus/>Neue Mappe</button>
      </div>

      {addingCamp&&(
        <div style={{padding:'18px 28px',background:'#FAFAF8',borderBottom:'1px solid rgba(0,0,0,0.07)',display:'flex',gap:16,alignItems:'flex-start'}}>
          <div style={{flex:1,maxWidth:480}}>
            <div style={{fontSize:12,fontWeight:600,color:'#6B6560',marginBottom:8}}>Emoji wählen</div>
            <div style={{display:'flex',flexWrap:'wrap',gap:5,marginBottom:12}}>
              {CAMPAIGN_EMOJIS.map(e=>(
                <button key={e} onClick={()=>setNewCampEmoji(e)} style={{fontSize:18,padding:'5px 8px',borderRadius:8,border:`2px solid ${newCampEmoji===e?'#141210':'transparent'}`,background:newCampEmoji===e?'#F0EDE8':'white',cursor:'pointer',lineHeight:1,boxShadow:'0 1px 3px rgba(0,0,0,0.06)'}}>{e}</button>
              ))}
            </div>
            <input value={newCampName} onChange={e=>setNewCampName(e.target.value)} autoFocus placeholder="Name der Kampagne oder Idee…"
              onKeyDown={e=>{if(e.key==='Enter')createCamp();if(e.key==='Escape')setAddingCamp(false);}}
              style={{width:'100%',boxSizing:'border-box',fontSize:14,marginBottom:10}}/>
            <div style={{display:'flex',gap:8}}>
              <button className="btn btn-primary" onClick={createCamp}>Erstellen & öffnen</button>
              <button className="btn btn-ghost" onClick={()=>setAddingCamp(false)}>Abbrechen</button>
            </div>
          </div>
        </div>
      )}

      <div style={{flex:1,overflowY:'auto',padding:28}}>
        {(campaigns||[]).length===0&&!addingCamp?(
          <div style={{textAlign:'center',padding:'80px 20px',color:'#C8C3BD'}}>
            <div style={{fontSize:52,marginBottom:16,opacity:.4}}>💡</div>
            <div style={{fontSize:16,fontWeight:600,color:'#C0BBB5',marginBottom:8}}>Noch keine Notizen</div>
            <div style={{fontSize:13,lineHeight:1.6,marginBottom:24}}>Erstelle deine erste Mappe für Notizen, Ideen oder Dokumente.<br/>Jede Mappe enthält beliebig viele Seiten mit Block-Editor.</div>
            <button className="btn btn-primary" onClick={()=>{setAddingCamp(true);setNewCampName('');setNewCampEmoji('📁');}}><Icons.Plus/>Erste Mappe erstellen</button>
          </div>
        ):(
          <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fill,minmax(260px,1fr))',gap:16}}>
            {(campaigns||[]).map(c=>(
              <div key={c.id} onClick={()=>openCamp(c)}
                style={{background:'white',borderRadius:14,border:'1px solid rgba(0,0,0,0.08)',boxShadow:'0 1px 4px rgba(0,0,0,0.05)',cursor:'pointer',overflow:'hidden',transition:'all .15s',display:'flex',flexDirection:'column'}}
                onMouseEnter={e=>{e.currentTarget.style.transform='translateY(-2px)';e.currentTarget.style.boxShadow='0 6px 20px rgba(0,0,0,0.1)';}}
                onMouseLeave={e=>{e.currentTarget.style.transform='translateY(0)';e.currentTarget.style.boxShadow='0 1px 4px rgba(0,0,0,0.05)';}}>
                {/* Farbstreifen oben */}
                <div style={{height:6,background:c.color||'#6366f1'}}/>
                <div style={{padding:'16px 18px 14px',flex:1}}>
                  <div style={{display:'flex',alignItems:'flex-start',gap:12,marginBottom:12}}>
                    <div style={{width:44,height:44,borderRadius:12,background:c.color+'22'||'#6366f122',display:'flex',alignItems:'center',justifyContent:'center',fontSize:22,flexShrink:0}}>{c.emoji||'💡'}</div>
                    <div style={{flex:1,minWidth:0}}>
                      {renamingCamp===c.id
                        ?<input value={renameVal} onChange={e=>setRenameVal(e.target.value)} autoFocus onClick={e=>e.stopPropagation()}
                            onKeyDown={e=>{if(e.key==='Enter')doRenameCamp();if(e.key==='Escape'){setRenamingCamp(null);setRenameVal('');}}}
                            onBlur={doRenameCamp} style={{fontSize:15,width:'100%',fontWeight:700}}/>
                        :<div style={{fontSize:15,fontWeight:700,color:'#141210',lineHeight:1.3}}>{c.name}</div>
                      }
                      <div style={{fontSize:11.5,color:'#A8A39D',marginTop:3}}>Erstellt {fmtDate(c.createdAt)}</div>
                    </div>
                  </div>
                  {/* Datei-Vorschau */}
                  {(c.files||[]).length>0?(
                    <div style={{display:'flex',flexDirection:'column',gap:4}}>
                      {(c.files||[]).slice(0,3).map(f=>(
                        <div key={f.id} style={{display:'flex',alignItems:'center',gap:7,padding:'5px 8px',background:'#F8F7F5',borderRadius:7}}>
                          <span style={{fontSize:12,color:c.color||'#6366f1'}}>📄</span>
                          <span style={{fontSize:12.5,color:'#3F3A35',flex:1,whiteSpace:'nowrap',overflow:'hidden',textOverflow:'ellipsis'}}>{f.name}</span>
                          {f.content&&<span style={{fontSize:10.5,color:'#C8C3BD'}}>{(()=>{try{const bs=JSON.parse(f.content);return Array.isArray(bs)?bs.reduce((s,b)=>s+(b.content?.length||0),0):f.content.length;}catch{return f.content.length;}})()}{' '}Z.</span>}
                        </div>
                      ))}
                      {(c.files||[]).length>3&&<div style={{fontSize:11.5,color:'#A8A39D',textAlign:'center',paddingTop:2}}>+{(c.files||[]).length-3} weitere Dateien</div>}
                    </div>
                  ):(
                    <div style={{padding:'10px 8px',background:'#F8F7F5',borderRadius:7,textAlign:'center',fontSize:12.5,color:'#C8C3BD'}}>Noch keine Dateien</div>
                  )}
                </div>
                {/* Footer */}
                <div style={{padding:'10px 18px',borderTop:'1px solid rgba(0,0,0,0.05)',display:'flex',alignItems:'center',gap:8,background:'#FAFAF8'}}>
                  <span style={{fontSize:11.5,color:'#A8A39D',flex:1}}>{(c.files||[]).length} {(c.files||[]).length===1?'Datei':'Dateien'} · {fmtDate(lastUpdated(c))}</span>
                  <div onClick={e=>e.stopPropagation()} style={{display:'flex',gap:4}}>
                    <button onClick={()=>{setRenamingCamp(c.id);setRenameVal(c.name);}} title="Umbenennen" style={{background:'none',border:'none',color:'#C8C3BD',cursor:'pointer',fontSize:12,padding:'3px 6px',borderRadius:5,lineHeight:1,transition:'color .12s'}} onMouseEnter={e=>e.currentTarget.style.color='#6B6560'} onMouseLeave={e=>e.currentTarget.style.color='#C8C3BD'}>✎</button>
                    <button onClick={()=>deleteCamp(c.id)} title="Löschen" style={{background:'none',border:'none',color:'#C8C3BD',cursor:'pointer',fontSize:15,padding:'3px 6px',borderRadius:5,lineHeight:1,transition:'color .12s'}} onMouseEnter={e=>e.currentTarget.style.color='#C0392B'} onMouseLeave={e=>e.currentTarget.style.color='#C8C3BD'}>×</button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );

  // ── KAMPAGNE INNEN ─────────────────────────────────────────────
  return(
    <div style={{display:'flex',flex:1,overflow:'hidden',flexDirection:'column'}}>
      {/* Breadcrumb-Header */}
      <div style={{padding:'10px 20px',background:'white',borderBottom:'1px solid rgba(0,0,0,0.07)',display:'flex',alignItems:'center',gap:12,flexShrink:0}}>
        <button onClick={goBack} style={{display:'flex',alignItems:'center',gap:6,background:'none',border:'none',cursor:'pointer',color:'#A8A39D',fontSize:13,padding:'4px 8px',borderRadius:7,transition:'all .12s'}} onMouseEnter={e=>{e.currentTarget.style.background='#F5F3F0';e.currentTarget.style.color='#141210';}} onMouseLeave={e=>{e.currentTarget.style.background='none';e.currentTarget.style.color='#A8A39D';}}>← Übersicht</button>
        <span style={{color:'#D5D0CA',fontSize:14}}>/</span>
        <div style={{width:24,height:24,borderRadius:7,background:activeCamp?.color||'#6366f1',display:'flex',alignItems:'center',justifyContent:'center',fontSize:13}}>{activeCamp?.emoji||'💡'}</div>
        <span style={{fontWeight:700,fontSize:14,color:'#141210'}}>{activeCamp?.name}</span>
        <div style={{flex:1}}/>
        <button onClick={()=>{setAddingFile(true);setNewFileName('');}} className="btn btn-primary btn-sm"><Icons.Plus/>Neue Datei</button>
      </div>

      <div style={{display:'flex',flex:1,overflow:'hidden'}}>
        {/* Datei-Liste */}
        <div style={{width:230,flexShrink:0,background:'#FAFAF8',borderRight:'1px solid rgba(0,0,0,0.07)',display:'flex',flexDirection:'column',overflow:'hidden'}}>
          {addingFile&&(
            <div style={{padding:'10px 12px',background:'white',borderBottom:'1px solid rgba(0,0,0,0.07)'}}>
              <input value={newFileName} onChange={e=>setNewFileName(e.target.value)} autoFocus placeholder="Dateiname…"
                onKeyDown={e=>{if(e.key==='Enter')createFile();if(e.key==='Escape')setAddingFile(false);}}
                style={{width:'100%',boxSizing:'border-box',fontSize:13,marginBottom:6}}/>
              <div style={{display:'flex',gap:5}}>
                <button className="btn btn-primary btn-sm" onClick={createFile} style={{flex:1}}>OK</button>
                <button className="btn btn-ghost btn-sm" onClick={()=>setAddingFile(false)}>✕</button>
              </div>
            </div>
          )}
          <div style={{flex:1,overflowY:'auto',padding:'8px 8px'}}>
            {(activeCamp?.files||[]).length===0&&!addingFile&&(
              <div style={{textAlign:'center',padding:'40px 14px',color:'#C8C3BD'}}>
                <div style={{fontSize:28,marginBottom:8}}>📄</div>
                <div style={{fontSize:12.5,color:'#C0BBB5',lineHeight:1.5}}>Noch keine Dateien.<br/>Klicke auf „+ Neue Datei".</div>
              </div>
            )}
            {(activeCamp?.files||[]).map(f=>(
              <div key={f.id} onClick={()=>setSelFile(f.id)}
                style={{display:'flex',alignItems:'center',gap:9,padding:'9px 10px',borderRadius:9,marginBottom:2,cursor:'pointer',background:selFile===f.id?'white':'transparent',border:`1px solid ${selFile===f.id?'rgba(0,0,0,0.08)':'transparent'}`,boxShadow:selFile===f.id?'0 1px 4px rgba(0,0,0,0.06)':'none',transition:'all .12s'}}
                onMouseEnter={e=>{if(selFile!==f.id)e.currentTarget.style.background='rgba(0,0,0,0.03)';}}
                onMouseLeave={e=>{if(selFile!==f.id)e.currentTarget.style.background='transparent';}}>
                <span style={{fontSize:14,flexShrink:0,color:selFile===f.id?activeCamp?.color||'#6366f1':'#B0ABA5'}}>📄</span>
                <div style={{flex:1,minWidth:0}}>
                  {renamingFile===f.id
                    ?<input value={renameVal} onChange={e=>setRenameVal(e.target.value)} autoFocus onClick={e=>e.stopPropagation()}
                        onKeyDown={e=>{if(e.key==='Enter')doRenameFile();if(e.key==='Escape'){setRenamingFile(null);setRenameVal('');}}}
                        onBlur={doRenameFile} style={{fontSize:12.5,width:'100%'}}/>
                    :<div style={{fontSize:13,fontWeight:selFile===f.id?600:400,color:selFile===f.id?'#141210':'#3F3A35',whiteSpace:'nowrap',overflow:'hidden',textOverflow:'ellipsis'}}>{f.name}</div>
                  }
                  <div style={{fontSize:10.5,color:'#C0BBB5',marginTop:1}}>{fmtDate(f.updatedAt||f.createdAt)}</div>
                </div>
                <div style={{display:'flex',flexDirection:'column',gap:1,flexShrink:0}} onClick={e=>e.stopPropagation()}>
                  <button onClick={()=>{setRenamingFile(f.id);setRenameVal(f.name);}} style={{background:'none',border:'none',color:'transparent',cursor:'pointer',fontSize:11,padding:'2px 4px',borderRadius:4,lineHeight:1,transition:'color .1s'}} onMouseEnter={e=>e.currentTarget.style.color='#A8A39D'} onMouseLeave={e=>e.currentTarget.style.color='transparent'}>✎</button>
                  <button onClick={()=>deleteFile(selCamp,f.id)} style={{background:'none',border:'none',color:'transparent',cursor:'pointer',fontSize:13,padding:'2px 4px',borderRadius:4,lineHeight:1,transition:'color .1s'}} onMouseEnter={e=>e.currentTarget.style.color='#C0392B'} onMouseLeave={e=>e.currentTarget.style.color='transparent'}>×</button>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Editor */}
        {!selFile?(
          <div style={{flex:1,display:'flex',alignItems:'center',justifyContent:'center',background:'#F8F7F5'}}>
            <div style={{textAlign:'center',color:'#C8C3BD'}}>
              <div style={{fontSize:40,marginBottom:10,opacity:.4}}>📝</div>
              <div style={{fontSize:14,fontWeight:600,color:'#C0BBB5'}}>Datei auswählen</div>
              <div style={{fontSize:12.5,marginTop:6}}>Wähle eine Datei links oder erstelle eine neue.</div>
            </div>
          </div>
        ):(
          <BlockEditor
            key={selFile}
            file={activeFile}
            campColor={activeCamp?.color}
            onSaveContent={content=>{
              const now=new Date().toISOString();
              onUpdate((campaigns||[]).map(c=>c.id!==selCamp?c:{...c,files:(c.files||[]).map(f=>f.id!==selFile?f:{...f,content,updatedAt:now})}));
            }}
            onRenameFile={name=>{
              if(!name.trim()||!selCamp)return;
              onUpdate((campaigns||[]).map(c=>c.id!==selCamp?c:{...c,files:(c.files||[]).map(f=>f.id!==selFile?f:{...f,name:name.trim()})}));
            }}
          />
        )}
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════
//  CRM APP
// ══════════════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════════
//  SUBSECTION BAR
// ═══════════════════════════════════════════════════════════════
function SubsectionBar({sectionId,subsections,activeSubId,onSelect,onAdd,onDelete}){
  const [adding,setAdding]=useState(false);
  const [newName,setNewName]=useState('');
  const subs=subsections.filter(s=>s.sectionId===sectionId).sort((a,b)=>a.order-b.order);
  const submit=()=>{if(!newName.trim())return;onAdd(newName.trim());setNewName('');setAdding(false);};
  return(
    <div style={{background:'white',borderBottom:'1px solid rgba(0,0,0,0.07)',padding:'0 28px',display:'flex',alignItems:'center',gap:0,overflowX:'auto',flexShrink:0}}>
      <button onClick={()=>onSelect(null)} style={{background:'none',border:'none',padding:'11px 14px 11px 0',fontSize:13,fontWeight:activeSubId===null?700:400,color:activeSubId===null?'#141210':'#A8A39D',borderBottom:activeSubId===null?'2px solid #141210':'2px solid transparent',cursor:'pointer',whiteSpace:'nowrap',transition:'all 0.15s'}}>Alle</button>
      {subs.map(s=>(
        <div key={s.id} style={{display:'flex',alignItems:'center'}}>
          <button onClick={()=>onSelect(s.id)} style={{background:'none',border:'none',padding:'11px 14px',fontSize:13,fontWeight:activeSubId===s.id?700:400,color:activeSubId===s.id?'#141210':'#A8A39D',borderBottom:activeSubId===s.id?'2px solid #141210':'2px solid transparent',cursor:'pointer',whiteSpace:'nowrap',transition:'all 0.15s'}}>{s.name}</button>
          <button onClick={()=>onDelete(s.id)} style={{background:'none',border:'none',color:'transparent',padding:'0 2px',fontSize:14,cursor:'pointer',lineHeight:1,transition:'color 0.15s'}}
            onMouseEnter={e=>e.currentTarget.style.color='#ccc'}
            onMouseLeave={e=>e.currentTarget.style.color='transparent'}>×</button>
        </div>
      ))}
      {adding
        ?<div style={{display:'flex',alignItems:'center',gap:6,marginLeft:8}}>
          <input value={newName} onChange={e=>setNewName(e.target.value)} placeholder="Abteilung…" autoFocus
            onKeyDown={e=>{if(e.key==='Enter')submit();if(e.key==='Escape'){setAdding(false);setNewName('');}}}
            style={{padding:'5px 10px',fontSize:12.5,width:140,borderRadius:7}}/>
          <button className="btn btn-primary btn-sm" onClick={submit}>OK</button>
          <button className="btn btn-ghost btn-sm" onClick={()=>{setAdding(false);setNewName('');}}>✕</button>
        </div>
        :<button onClick={()=>setAdding(true)} style={{background:'none',border:'none',padding:'11px 12px',fontSize:12,color:'#C8C3BD',cursor:'pointer',display:'flex',alignItems:'center',gap:4,transition:'color 0.15s',whiteSpace:'nowrap'}}
          onMouseEnter={e=>e.currentTarget.style.color='#888'}
          onMouseLeave={e=>e.currentTarget.style.color='#C8C3BD'}><Icons.Plus/> Abteilung</button>
      }
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
//  MEMBERS MODAL
// ═══════════════════════════════════════════════════════════════
function MembersModal({members,onSave,onClose}){
  const [list,setList]=useState(members||[]);
  const [form,setForm]=useState({name:'',email:'',role:'Mitglied',notes:''});
  const [editing,setEditing]=useState(null);
  const [inviteFor,setInviteFor]=useState(null);
  const [generatedCode,setGeneratedCode]=useState('');
  const [copied,setCopied]=useState(false);
  const roles=['Admin','Mitglied','Gast'];
  const save=()=>{
    if(!form.name.trim()||!form.email.trim())return;
    if(editing){setList(l=>l.map(m=>m.id===editing?{...m,...form}:m));setEditing(null);}
    else setList(l=>[...l,{id:uid(),...form,addedAt:new Date().toISOString().slice(0,10)}]);
    setForm({name:'',email:'',role:'Mitglied',notes:''});
  };
  const remove=id=>setList(l=>l.filter(m=>m.id!==id));
  const startEdit=m=>{setEditing(m.id);setForm({name:m.name,email:m.email,role:m.role,notes:m.notes||''});};
  const genInvite=async m=>{alert('Bitte nutze in der Sidebar links unten den Eintrag "Einladungen" um einen Einladungs-Token zu erstellen.');};
  const copyCode=()=>{navigator.clipboard?.writeText(generatedCode);setCopied(true);setTimeout(()=>setCopied(false),2000);};
  const roleBadge=r=>{const c=r==='Admin'?{bg:'#EFF6FF',color:'#1d4ed8'}:r==='Mitglied'?{bg:'#F0FDF4',color:'#15803d'}:{bg:'#F8FAFC',color:'#64748b'};return<span style={{padding:'2px 8px',borderRadius:99,fontSize:11,fontWeight:600,background:c.bg,color:c.color}}>{r}</span>;};
  return(
    <div className="modal-overlay" onClick={()=>{onSave(list);onClose();}}>
      <div className="modal-box" style={{width:560,padding:28}} onClick={e=>e.stopPropagation()}>
        <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:22}}>
          <div><h2 style={{fontSize:17,fontWeight:700}}>Mitglieder</h2><p style={{fontSize:12.5,color:'#A8A39D',marginTop:3}}>Übersicht aller Personen mit Zugang.</p></div>
          <button onClick={()=>{onSave(list);onClose();}} style={{background:'#F5F3F0',border:'none',borderRadius:8,padding:8,color:'#999',lineHeight:0}}><Icons.Close/></button>
        </div>
        {list.length===0
          ?<div style={{fontSize:13,color:'#C8C3BD',padding:'16px 0',textAlign:'center'}}>Noch keine Mitglieder eingetragen.</div>
          :<div style={{display:'grid',gap:8,marginBottom:20}}>
            {list.map(m=>(
              <div key={m.id} style={{display:'flex',alignItems:'center',gap:12,padding:'12px 14px',borderRadius:10,background:'#FAF9F7',border:'1px solid #F0EDE9'}}>
                <div style={{width:36,height:36,borderRadius:10,background:avatarColor(m.name),color:'white',display:'flex',alignItems:'center',justifyContent:'center',fontWeight:700,fontSize:13,flexShrink:0}}>{m.name.split(' ').slice(0,2).map(w=>w[0]).join('').toUpperCase()}</div>
                <div style={{flex:1,minWidth:0}}>
                  <div style={{display:'flex',alignItems:'center',gap:8,marginBottom:3}}><span style={{fontWeight:600,fontSize:13.5}}>{m.name}</span>{roleBadge(m.role)}</div>
                  <div style={{fontSize:12,color:'#A8A39D'}}>{m.email}{m.addedAt?' · seit '+m.addedAt:''}</div>
                </div>
                <div style={{display:'flex',gap:6,flexShrink:0}}>
                  <button className="btn btn-ghost btn-sm" onClick={()=>genInvite(m)} title="Einladungscode generieren"><Icons.Invite/></button>
                  <button className="btn btn-ghost btn-sm" onClick={()=>startEdit(m)}><Icons.Edit/></button>
                  <button onClick={()=>remove(m.id)} style={{background:'none',border:'none',color:'#DDD',cursor:'pointer',padding:'4px 6px',borderRadius:6,fontSize:16}}
                    onMouseEnter={e=>{e.currentTarget.style.color='#C0392B';e.currentTarget.style.background='#FEF2F2';}}
                    onMouseLeave={e=>{e.currentTarget.style.color='#DDD';e.currentTarget.style.background='none';}}>×</button>
                </div>
              </div>
            ))}
          </div>
        }
        {generatedCode&&(
          <div style={{padding:'12px 14px',background:'#F0FDF4',border:'1px solid #BBF7D0',borderRadius:10,marginBottom:16}}>
            <div style={{fontSize:11.5,color:'#15803d',fontWeight:600,marginBottom:6}}>Einladungscode für {inviteFor}:</div>
            <div style={{display:'flex',alignItems:'center',gap:10}}>
              <div style={{fontFamily:'monospace',fontSize:16,fontWeight:700,letterSpacing:'2px',color:'#141210',flex:1}}>{generatedCode}</div>
              <button className="btn btn-ghost btn-sm" onClick={copyCode}>{copied?'✓ Kopiert':'Kopieren'}</button>
            </div>
          </div>
        )}
        <div style={{background:'#FAF9F7',borderRadius:12,padding:16}}>
          <label style={lbl}>{editing?'Mitglied bearbeiten':'Neues Mitglied'}</label>
          <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:10,marginTop:8}}>
            <input value={form.name} onChange={e=>setForm(f=>({...f,name:e.target.value}))} placeholder="Name"/>
            <input value={form.email} onChange={e=>setForm(f=>({...f,email:e.target.value}))} placeholder="E-Mail" type="email"/>
          </div>
          <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:10,marginTop:10}}>
            <select value={form.role} onChange={e=>setForm(f=>({...f,role:e.target.value}))}>{roles.map(r=><option key={r}>{r}</option>)}</select>
            <input value={form.notes} onChange={e=>setForm(f=>({...f,notes:e.target.value}))} placeholder="Notizen (optional)"/>
          </div>
          <div style={{display:'flex',gap:8,marginTop:10,justifyContent:'flex-end'}}>
            {editing&&<button className="btn btn-ghost btn-sm" onClick={()=>{setEditing(null);setForm({name:'',email:'',role:'Mitglied',notes:''});}}>Abbrechen</button>}
            <button className="btn btn-primary btn-sm" onClick={save}>{editing?'Speichern':'+ Mitglied hinzufügen'}</button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
//  CSV IMPORT MODAL
// ═══════════════════════════════════════════════════════════════
function CSVImportModal({sections,onImport,onClose}){
  const [step,setStep]=useState('upload');
  const [rows,setRows]=useState([]);
  const [headers,setHeaders]=useState([]);
  const [targetSection,setTargetSection]=useState(sections.find(s=>s.id==='leads')?.id||sections[0]?.id);
  const [mapping,setMapping]=useState({firma:'',email:'',telefon:'',umsatz:'',notizen:''});
  const [error,setError]=useState('');
  const CRM_FIELDS=[{key:'firma',label:'Firma / Unternehmen'},{key:'email',label:'E-Mail'},{key:'telefon',label:'Telefon'},{key:'umsatz',label:'Umsatz'},{key:'notizen',label:'Notizen'}];
  const parseCSV=text=>{
    const lines=text.split(/\r?\n/).filter(l=>l.trim());
    if(lines.length<2)return null;
    const sep=lines[0].includes(';')?';':',';
    const parseRow=l=>{const res=[];let cur='',inQ=false;for(const c of l){if(c==='"'){inQ=!inQ;continue;}if(c===sep&&!inQ){res.push(cur.trim());cur='';}else cur+=c;}res.push(cur.trim());return res;};
    const hdrs=parseRow(lines[0]);
    const data=lines.slice(1).map(l=>parseRow(l)).filter(r=>r.some(c=>c));
    return{hdrs,data};
  };
  const handleFile=e=>{
    const file=e.target.files?.[0];if(!file)return;
    const reader=new FileReader();
    reader.onload=ev=>{
      const result=parseCSV(ev.target.result);
      if(!result){setError('CSV konnte nicht gelesen werden.');return;}
      setHeaders(result.hdrs);setRows(result.data);
      const autoMap={};
      const aliases={firma:['firma','company','unternehmen','name'],email:['email','e-mail','mail'],telefon:['tel','telefon','phone'],umsatz:['umsatz','value','revenue'],notizen:['notiz','note','notes','kommentar']};
      for(const[field,als]of Object.entries(aliases)){const match=result.hdrs.find(h=>als.some(a=>h.toLowerCase().includes(a)));autoMap[field]=match||'';}
      setMapping(autoMap);setError('');setStep('map');
    };
    reader.readAsText(file,'UTF-8');
  };
  const doImport=()=>{
    const contacts=rows.map(row=>{
      const get=col=>col?(row[headers.indexOf(col)]||''):'';
      return{id:uid(),sectionId:targetSection,subsectionId:null,firma:get(mapping.firma)||'Unbekannt',email:get(mapping.email),telefon:get(mapping.telefon),umsatz:get(mapping.umsatz),notizen:get(mapping.notizen),status:'Lead',reminders:[],activities:[],customValues:{}};
    }).filter(c=>c.firma!=='Unbekannt'||c.email);
    onImport(contacts);onClose();
  };
  return(
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-box" style={{width:560,padding:28}} onClick={e=>e.stopPropagation()}>
        <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:22}}>
          <div><h2 style={{fontSize:17,fontWeight:700}}>CSV importieren</h2><p style={{fontSize:12.5,color:'#A8A39D',marginTop:3}}>{step==='upload'?'CSV-Datei hochladen':`${rows.length} Zeilen – Spalten zuordnen`}</p></div>
          <button onClick={onClose} style={{background:'#F5F3F0',border:'none',borderRadius:8,padding:8,color:'#999',lineHeight:0}}><Icons.Close/></button>
        </div>
        {step==='upload'&&(
          <div>
            <label style={{display:'block',border:'2px dashed #E8E4DF',borderRadius:12,padding:'36px 20px',textAlign:'center',cursor:'pointer',background:'#FAF9F7'}}
              onMouseEnter={e=>e.currentTarget.style.borderColor='#141210'}
              onMouseLeave={e=>e.currentTarget.style.borderColor='#E8E4DF'}>
              <div style={{fontSize:32,marginBottom:10}}>📂</div>
              <div style={{fontWeight:600,fontSize:14,color:'#141210',marginBottom:4}}>CSV-Datei auswählen</div>
              <div style={{fontSize:12.5,color:'#A8A39D'}}>Komma oder Semikolon · UTF-8</div>
              <input type="file" accept=".csv,text/csv" onChange={handleFile} style={{display:'none'}}/>
            </label>
            {error&&<div style={{fontSize:12.5,color:'#C0392B',marginTop:10,padding:'8px 12px',background:'#FEF2F2',borderRadius:8}}>{error}</div>}
          </div>
        )}
        {step==='map'&&(
          <div style={{display:'grid',gap:14}}>
            <div><label style={lbl}>Importieren in Bereich</label><select value={targetSection} onChange={e=>setTargetSection(e.target.value)}>{sections.map(s=><option key={s.id} value={s.id}>{s.name}</option>)}</select></div>
            <div>
              <label style={lbl}>Spalten zuordnen</label>
              <div style={{display:'grid',gap:8}}>
                {CRM_FIELDS.map(f=>(
                  <div key={f.key} style={{display:'grid',gridTemplateColumns:'1fr 1fr',alignItems:'center',gap:10}}>
                    <span style={{fontSize:13,fontWeight:500,color:'#6B6560'}}>{f.label}</span>
                    <select value={mapping[f.key]} onChange={e=>setMapping(m=>({...m,[f.key]:e.target.value}))}>
                      <option value="">– nicht importieren –</option>
                      {headers.map(h=><option key={h} value={h}>{h}</option>)}
                    </select>
                  </div>
                ))}
              </div>
            </div>
            <div style={{background:'#FAF9F7',borderRadius:10,padding:12,maxHeight:140,overflowY:'auto'}}>
              <div style={{fontSize:11,color:'#A8A39D',fontWeight:600,textTransform:'uppercase',letterSpacing:'0.05em',marginBottom:8}}>Vorschau (3 Zeilen)</div>
              {rows.slice(0,3).map((row,i)=>(
                <div key={i} style={{fontSize:12.5,color:'#6B6560',padding:'4px 0',borderBottom:'1px solid #F0EDE9'}}>
                  <strong>{mapping.firma?row[headers.indexOf(mapping.firma)]||'?':'?'}</strong>
                  {mapping.email&&` · ${row[headers.indexOf(mapping.email)]}`}
                </div>
              ))}
            </div>
            <div style={{display:'flex',gap:10,justifyContent:'flex-end'}}>
              <button className="btn btn-ghost" onClick={()=>setStep('upload')}>← Zurück</button>
              <button className="btn btn-primary" onClick={doImport}>{rows.length} Kontakte importieren →</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function TokenEditModal({token, onSave, onClose}){
  const SERVICES=['GitHub','Anthropic','OpenAI','Google','AWS','Azure','Stripe','Twilio','SendGrid','Custom'];
  const [form,setForm]=React.useState({service:token?.service||'GitHub',account:token?.account||'',token:token?.token||'',notes:token?.notes||'',refreshUrl:token?.refreshUrl||''});
  const [showTok,setShowTok]=React.useState(!token);
  const f=(k,v)=>setForm(p=>({...p,[k]:v}));
  return(
    <div className="modal-overlay" onClick={e=>{if(e.target===e.currentTarget)onClose();}}>
      <div className="modal-box" style={{width:480}}>
        <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:22}}>
          <h2 style={{fontSize:17,fontWeight:800}}>{token?'Token bearbeiten':'Neuer Token'}</h2>
          <button onClick={onClose} style={{background:'#F5F3F0',border:'none',borderRadius:8,padding:8,cursor:'pointer',color:'#999',lineHeight:0}}><Icons.Close/></button>
        </div>
        <div style={{display:'grid',gap:14}}>
          <div>
            <label style={{fontSize:12,fontWeight:600,color:'#6B6560',display:'block',marginBottom:5}}>Service</label>
            <select value={form.service} onChange={e=>f('service',e.target.value)}>
              {SERVICES.map(s=><option key={s} value={s}>{s}</option>)}
            </select>
          </div>
          <div>
            <label style={{fontSize:12,fontWeight:600,color:'#6B6560',display:'block',marginBottom:5}}>Konto / E-Mail</label>
            <input value={form.account} onChange={e=>f('account',e.target.value)} placeholder="z.B. mateo@webars.at"/>
          </div>
          <div>
            <label style={{fontSize:12,fontWeight:600,color:'#6B6560',display:'block',marginBottom:5}}>API Token / Key</label>
            <div style={{position:'relative'}}>
              <input type={showTok?'text':'password'} value={form.token} onChange={e=>f('token',e.target.value)} placeholder="Token einfügen..." style={{paddingRight:44,fontFamily:'monospace',fontSize:13}}/>
              <button type="button" onClick={()=>setShowTok(v=>!v)} style={{position:'absolute',right:10,top:'50%',transform:'translateY(-50%)',background:'none',border:'none',cursor:'pointer',color:'#9CA3AF',fontSize:14}}>{showTok?'🙈':'👁'}</button>
            </div>
          </div>
          <div>
            <label style={{fontSize:12,fontWeight:600,color:'#6B6560',display:'block',marginBottom:5}}>Notizen (optional)</label>
            <input value={form.notes} onChange={e=>f('notes',e.target.value)} placeholder="z.B. Ablaufdatum, Berechtigungen..."/>
          </div>
          <div>
            <label style={{fontSize:12,fontWeight:600,color:'#6B6560',display:'block',marginBottom:5}}>Aktualisierungs-URL (optional)</label>
            <input value={form.refreshUrl} onChange={e=>f('refreshUrl',e.target.value)} placeholder="z.B. https://github.com/settings/tokens"/>
            <div style={{fontSize:11,color:'#A8A39D',marginTop:4}}>Die Seite, die beim Klick auf ↻ Aktualisieren geöffnet wird.</div>
          </div>
        </div>
        <div style={{display:'flex',justifyContent:'flex-end',gap:10,marginTop:24}}>
          <button className="btn btn-ghost" onClick={onClose}>Abbrechen</button>
          <button className="btn btn-primary" onClick={()=>onSave(form)} disabled={!form.token.trim()}>{token?'Speichern':'Hinzufügen'}</button>
        </div>
      </div>
    </div>
  );
}

function TokensView({tokens,onUpdate}){
  const [modal,setModal]=React.useState(null);
  const [visible,setVisible]=React.useState({});
  const [copied,setCopied]=React.useState(null);
  const SERVICE_COLOR={GitHub:'#24292e',Anthropic:'#d97706',OpenAI:'#10a37f',Google:'#4285F4',AWS:'#FF9900',Azure:'#0078D4',Stripe:'#635BFF',Twilio:'#F22F46',SendGrid:'#1A82E2',Custom:'#6B6560'};
  const save=(form)=>{
    if(modal==='add') onUpdate([...tokens,{...form,id:uid(),createdAt:new Date().toISOString()}]);
    else onUpdate(tokens.map(t=>t.id===modal.id?{...modal,...form}:t));
    setModal(null);
  };
  const del=(id)=>{if(window.confirm('Token wirklich löschen?'))onUpdate(tokens.filter(t=>t.id!==id));};
  const copy=(id,val)=>{navigator.clipboard.writeText(val).catch(()=>{});setCopied(id);setTimeout(()=>setCopied(null),1500);};
  const handleRefresh=(t)=>{
    localStorage.setItem('crm_pending_token_target',JSON.stringify({tokenId:t.id,label:t.service+(t.account?' / '+t.account:'')}));
    window.open(t.refreshUrl,'_blank','noopener');
    setTimeout(()=>alert('Seite geöffnet.\n\nKopiere dort den neuen Token, dann klicke auf das Lesezeichen „↻ Token → CRM" in deiner Browser-Lesezeichen-Leiste.'),150);
  };
  const bookmarkletCode=`javascript:(function(){var v=prompt('Neuen Token-Wert einfügen:');if(!v||!v.trim())return;try{localStorage.setItem('crm_pending_token_value',JSON.stringify({value:v.trim(),setAt:Date.now()}));}catch(e){}window.open('${window.location.origin}/?crm_pending_token=1','_blank');})()`;
  return(
    <div style={{flex:1,overflowY:'auto',padding:'28px'}}>
      <div style={{background:'#F0F9FF',border:'1px solid #BAE6FD',borderRadius:12,padding:'14px 18px',marginBottom:20,display:'flex',alignItems:'center',gap:14}}>
        <div style={{fontSize:22}}>🔖</div>
        <div style={{flex:1}}>
          <div style={{fontSize:13,fontWeight:700,color:'#0369A1',marginBottom:3}}>Lesezeichen einrichten (einmalig)</div>
          <div style={{fontSize:12,color:'#0369A1',opacity:.8}}>Ziehe diesen Link in deine Browser-Lesezeichen-Leiste — danach kannst du Tokens mit einem Klick aktualisieren:</div>
        </div>
        <a href={bookmarkletCode} onClick={e=>e.preventDefault()} onDragStart={()=>{}} style={{display:'inline-flex',alignItems:'center',gap:6,padding:'8px 14px',borderRadius:8,background:'#0369A1',color:'white',fontSize:12.5,fontWeight:700,cursor:'grab',textDecoration:'none',flexShrink:0,userSelect:'none'}} draggable="true">↻ Token → CRM</a>
      </div>
      <div style={{display:'flex',justifyContent:'flex-end',marginBottom:20}}>
        <button className="btn btn-primary" onClick={()=>setModal('add')}><Icons.Plus/>Neuer Token</button>
      </div>
      {tokens.length===0?(
        <div style={{textAlign:'center',padding:'60px 0',color:'#B0ABA5'}}>
          <div style={{fontSize:40,marginBottom:12}}>🔑</div>
          <div style={{fontWeight:600,fontSize:15,color:'#6B6560',marginBottom:6}}>Keine API-Tokens gespeichert</div>
          <div style={{fontSize:13}}>Speichere GitHub-, OpenAI- oder andere API-Keys sicher im CRM.</div>
        </div>
      ):(
        <div style={{display:'grid',gap:8}}>
          {tokens.map(t=>{
            const isVis=visible[t.id];const isCopied=copied===t.id;
            const color=SERVICE_COLOR[t.service]||SERVICE_COLOR.Custom;
            const initials=(t.service||'?').slice(0,2).toUpperCase();
            return(
              <div key={t.id} style={{background:'white',borderRadius:12,padding:'16px 20px',border:'1px solid rgba(0,0,0,.07)',display:'flex',alignItems:'center',gap:16}}>
                <div style={{width:38,height:38,borderRadius:9,background:color,display:'flex',alignItems:'center',justifyContent:'center',flexShrink:0}}>
                  <span style={{fontSize:11,fontWeight:800,color:'white',letterSpacing:'-0.01em'}}>{initials}</span>
                </div>
                <div style={{flex:1,minWidth:0}}>
                  <div style={{display:'flex',alignItems:'center',gap:8,marginBottom:4}}>
                    <span style={{fontWeight:700,fontSize:14}}>{t.service}</span>
                    {t.account&&<span style={{fontSize:12,color:'#9CA3AF'}}>{t.account}</span>}
                  </div>
                  <div style={{display:'flex',alignItems:'center',gap:6}}>
                    <code style={{fontSize:12,color:'#374151',background:'#F3F4F6',borderRadius:6,padding:'3px 8px',fontFamily:'monospace',flex:1,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap',maxWidth:340}}>
                      {isVis?t.token:'••••••••••••••••••••••••••'}
                    </code>
                    <button onClick={()=>setVisible(v=>({...v,[t.id]:!isVis}))} style={{background:'none',border:'none',cursor:'pointer',padding:'3px 6px',borderRadius:5,color:'#9CA3AF',fontSize:13}} title={isVis?'Verstecken':'Anzeigen'}>{isVis?'🙈':'👁'}</button>
                    <button onClick={()=>copy(t.id,t.token)} style={{background:isCopied?'#DCFCE7':'#F3F4F6',border:'none',cursor:'pointer',padding:'4px 10px',borderRadius:6,color:isCopied?'#16a34a':'#374151',fontSize:11.5,fontWeight:600,transition:'all .15s',flexShrink:0}}>{isCopied?'✓ Kopiert':'📋 Kopieren'}</button>
                  </div>
                  {t.notes&&<div style={{fontSize:11.5,color:'#9CA3AF',marginTop:5}}>{t.notes}</div>}
                </div>
                <div style={{display:'flex',gap:6,flexShrink:0}}>
                  {t.refreshUrl&&<button className="btn btn-ghost btn-sm" onClick={()=>handleRefresh(t)} style={{color:'#16a34a',borderColor:'#86efac',background:'#F0FDF4'}} title="Token aktualisieren">↻ Aktualisieren</button>}
                  <button className="btn btn-ghost btn-sm" onClick={()=>setModal(t)}>Bearbeiten</button>
                  <button className="btn btn-danger btn-sm" onClick={()=>del(t.id)}>Löschen</button>
                </div>
              </div>
            );
          })}
        </div>
      )}
      {modal&&<TokenEditModal token={modal==='add'?null:modal} onSave={save} onClose={()=>setModal(null)}/>}
    </div>
  );
}

// ── PUBLIC FORM PAGE ─────────────────────────────────────────────
function PublicFormPage({slug}){
  const [form,setForm]=useState(null);
  const [loadErr,setLoadErr]=useState('');
  const [submitErr,setSubmitErr]=useState('');
  const [values,setValues]=useState({});
  const [submitted,setSubmitted]=useState(false);
  const [submitting,setSubmitting]=useState(false);
  const [errors,setErrors]=useState({});

  useEffect(()=>{
    if(!document.getElementById('inter-font')){
      const l=document.createElement('link');
      l.id='inter-font';
      l.rel='stylesheet';
      l.href='https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap';
      document.head.appendChild(l);
    }
  },[]);

  const FF="'Inter',system-ui,sans-serif";
  const NAVY='#1B2A3B';
  const BG='#F3F0EB';
  const CARD={background:'#fff',borderRadius:14,padding:'20px 22px',border:'1px solid rgba(0,0,0,.06)',boxShadow:'0 1px 8px rgba(0,0,0,.05)'};
  const INPUT_BASE={width:'100%',padding:'10px 13px',border:'1.5px solid #E0DCD6',borderRadius:9,fontSize:14,fontFamily:FF,background:'#FAFAF8',outline:'none',boxSizing:'border-box'};
  const PILL_BASE={display:'flex',alignItems:'center',gap:10,padding:'11px 14px',borderRadius:9,border:'1.5px solid #E0DCD6',background:'#FAFAF8',cursor:'pointer',fontSize:13.5,fontWeight:500,fontFamily:FF,color:'#3F3A35',transition:'all .12s',userSelect:'none'};
  const PILL_ON={...PILL_BASE,background:NAVY,borderColor:NAVY,color:'#fff'};

  const HEADER_JSX=(
    <div style={{background:NAVY,padding:'16px 24px',display:'flex',alignItems:'center',gap:12,flexShrink:0}}>
      <img src="/logo.png" alt="WebArs" style={{height:36,width:'auto'}}
        onError={e=>{e.target.style.display='none';e.target.nextSibling.style.display='flex';}}/>
      <div style={{display:'none',alignItems:'center',gap:8,color:'#fff',fontWeight:800,fontSize:15,fontFamily:FF}}>WebArs</div>
      <div style={{width:1,height:20,background:'rgba(255,255,255,.2)',margin:'0 4px'}}/>
      <span style={{color:'rgba(255,255,255,.55)',fontSize:12.5,fontWeight:500,fontFamily:FF}}>Kunden-Formular</span>
    </div>
  );
  const FOOTER_JSX=(
    <div style={{background:NAVY,padding:'14px 24px',textAlign:'center',fontSize:11.5,color:'rgba(255,255,255,.35)',fontFamily:FF,flexShrink:0}}>
      Erstellt mit WebArs · webars.at
    </div>
  );
  const PAGE={minHeight:'100vh',fontFamily:FF,display:'flex',flexDirection:'column',background:NAVY};

  useEffect(()=>{
    (async()=>{
      try{
        const dir=window.location.pathname+(window.location.pathname.endsWith('/')?'':'/');
        const url=SELF_HOSTED
          ? `/forms/${encodeURIComponent(slug)}?t=${Date.now()}`
          : `${window.location.origin}${dir}forms/${slug}.json?t=${Date.now()}`;
        const r=await fetch(url,{cache:'no-store'});
        if(!r.ok){setLoadErr('Dieses Formular wurde nicht gefunden oder ist nicht mehr verfügbar.');return;}
        const def=await r.json();
        setForm(def);
        const v={};(def.fields||[]).forEach(fld=>{if(fld.type==='multiselect')v[fld.id]=[];else v[fld.id]='';});
        setValues(v);
      }catch(e){setLoadErr('Formular konnte nicht geladen werden.');}
    })();
  },[slug]);

  const setVal=(id,v)=>setValues(s=>({...s,[id]:v}));
  const toggleMulti=(id,opt)=>setValues(s=>{const arr=s[id]||[];return{...s,[id]:arr.includes(opt)?arr.filter(x=>x!==opt):[...arr,opt]};});

  const validate=()=>{
    const e={};
    (form.fields||[]).forEach(fld=>{
      if(!fld.required||fld.type==='section'||fld.type==='info'||fld.type==='file')return;
      const v=values[fld.id];
      if(fld.type==='multiselect'){if(!v||v.length===0)e[fld.id]='Bitte mindestens eine Option auswählen.';}
      else if(!v||(typeof v==='string'&&!v.trim()))e[fld.id]='Pflichtfeld.';
    });
    return e;
  };

  const handleSubmit=async(ev)=>{
    ev.preventDefault();
    const e=validate();
    setErrors(e);
    if(Object.keys(e).length>0){
      const firstErr=document.querySelector('[data-field-err="true"]');
      if(firstErr)firstErr.scrollIntoView({behavior:'smooth',block:'center'});
      return;
    }
    if(!form.submitEmail){setSubmitErr('Diesem Formular fehlt eine Empfänger-Email — bitte den Betreiber informieren.');return;}
    setSubmitting(true);
    setSubmitErr('');
    try{
      const fd=new FormData();
      const nameField=(form.fields||[]).find(f=>/name/i.test(f.label||''))||form.fields[0];
      const senderName=nameField?values[nameField.id]:'Unbekannt';
      fd.append('_subject',`Neue Antwort: ${form.title} — ${senderName||'Anonym'}`);
      fd.append('_template','table');
      fd.append('_captcha','false');
      (form.fields||[]).forEach(fld=>{
        if(fld.type==='section'||fld.type==='info')return;
        const v=values[fld.id];
        if(fld.type==='file'){
          if(v&&v.length){for(let i=0;i<v.length;i++)fd.append(`${fld.label||fld.id} (Datei ${i+1})`,v[i]);}
        }else{
          fd.append(fld.label||fld.id,Array.isArray(v)?v.join(', '):(v||''));
        }
      });
      const exportData={};
      (form.fields||[]).forEach(fld=>{if(fld.type!=='section'&&fld.type!=='info'&&fld.type!=='file')exportData[fld.id]=values[fld.id];});
      const importPayload={formSlug:form.slug,formTitle:form.title,contactName:senderName||'Anonym',data:exportData,submittedAt:new Date().toISOString()};
      const b64=btoa(unescape(encodeURIComponent(JSON.stringify(importPayload))));
      const importLink=`${window.location.origin}${window.location.pathname.replace(/\/$/,'')}/?formresponse=${b64}`;
      fd.append('🔗 In CRM importieren',importLink);

      const r=await fetch(`https://formsubmit.co/${encodeURIComponent(form.submitEmail)}`,{method:'POST',body:fd});
      if(!r.ok)throw new Error('HTTP '+r.status);
      setSubmitted(true);
      window.scrollTo(0,0);
    }catch(err){
      const msg=err.message==='Failed to fetch'
        ?'Verbindung zu FormSubmit.co fehlgeschlagen. Mögliche Ursachen: 1) Erste Nutzung — bitte Bestätigungs-E-Mail von FormSubmit.co prüfen und Link klicken. 2) Netzwerkproblem — bitte kurz warten und erneut versuchen.'
        :'Fehler beim Senden: '+err.message;
      setSubmitErr(msg);
    }
    setSubmitting(false);
  };

  if(loadErr)return(
    <div style={PAGE}>
      {HEADER_JSX}
      <div style={{flex:1,background:BG,display:'flex',alignItems:'center',justifyContent:'center',padding:24}}>
        <div style={{maxWidth:500,background:'#fff',borderRadius:16,padding:'36px 30px',textAlign:'center',boxShadow:'0 2px 12px rgba(0,0,0,.07)'}}>
          <div style={{fontSize:42,marginBottom:14}}>📭</div>
          <div style={{fontSize:17,fontWeight:800,color:'#141210',marginBottom:8,fontFamily:FF}}>Formular nicht verfügbar</div>
          <div style={{fontSize:13.5,color:'#6B6560',lineHeight:1.6,fontFamily:FF}}>{loadErr}</div>
        </div>
      </div>
      {FOOTER_JSX}
    </div>
  );
  if(!form)return(
    <div style={PAGE}>
      {HEADER_JSX}
      <div style={{flex:1,background:BG,display:'flex',alignItems:'center',justifyContent:'center'}}>
        <span style={{width:28,height:28,border:'2.5px solid rgba(0,0,0,.1)',borderTopColor:NAVY,borderRadius:'50%',animation:'spin .7s linear infinite',display:'block'}}></span>
      </div>
      {FOOTER_JSX}
    </div>
  );
  if(submitted)return(
    <div style={PAGE}>
      {HEADER_JSX}
      <div style={{flex:1,background:BG,display:'flex',alignItems:'center',justifyContent:'center',padding:24}}>
        <div style={{maxWidth:540,background:'#fff',borderRadius:16,padding:'44px 32px',textAlign:'center',boxShadow:'0 2px 12px rgba(0,0,0,.07)'}}>
          <div style={{width:56,height:56,borderRadius:'50%',background:NAVY,color:'#fff',fontSize:26,display:'flex',alignItems:'center',justifyContent:'center',margin:'0 auto 18px'}}>✓</div>
          <div style={{fontSize:20,fontWeight:800,color:'#141210',marginBottom:12,fontFamily:FF,letterSpacing:'-0.02em'}}>Erfolgreich gesendet!</div>
          <div style={{fontSize:14,color:'#6B6560',lineHeight:1.65,whiteSpace:'pre-wrap',fontFamily:FF}}>{form.thanks||'Vielen Dank für Ihre Antworten!'}</div>
        </div>
      </div>
      {FOOTER_JSX}
    </div>
  );

  return(
    <div style={PAGE}>
      {HEADER_JSX}
      <div style={{flex:1,background:BG,padding:'36px 16px 60px'}}>
        <div style={{maxWidth:660,margin:'0 auto',display:'flex',flexDirection:'column',gap:18}}>

          {/* Intro-Card */}
          <div style={{...CARD,borderRadius:16,padding:'26px 28px'}}>
            <h1 style={{fontSize:22,fontWeight:800,color:'#141210',marginBottom:8,letterSpacing:'-0.03em',fontFamily:FF,margin:'0 0 8px'}}>{form.title}</h1>
            {form.intro&&<p style={{fontSize:14,color:'#6B6560',lineHeight:1.65,margin:'8px 0 0',fontFamily:FF,whiteSpace:'pre-wrap'}}>{form.intro}</p>}
          </div>

          <form onSubmit={handleSubmit} style={{display:'contents'}}>
            {(form.fields||[]).map(fld=>{
              const err=errors[fld.id];
              const errMark=err?{'data-field-err':'true'}:{};

              if(fld.type==='section')return(
                <div key={fld.id} style={{display:'flex',alignItems:'center',gap:12,margin:'4px 0'}}>
                  <div style={{flex:1,height:1.5,background:NAVY}}/>
                  <div style={{fontSize:11,fontWeight:800,color:NAVY,textTransform:'uppercase',letterSpacing:'0.1em',whiteSpace:'nowrap',fontFamily:FF}}>{fld.label}</div>
                  <div style={{flex:1,height:1.5,background:NAVY}}/>
                </div>
              );

              if(fld.type==='info')return(
                <div key={fld.id} style={{background:'#EFF6FF',border:'1px solid #BFDBFE',borderRadius:10,padding:'13px 16px',fontSize:13,color:'#1E40AF',lineHeight:1.55,fontFamily:FF}}>
                  {fld.label}
                </div>
              );

              return(
                <div key={fld.id} style={CARD} {...errMark}>
                  <label style={{display:'block',fontSize:13,fontWeight:700,color:'#141210',marginBottom:4,fontFamily:FF}}>
                    {fld.label}{fld.required&&<span style={{color:NAVY,marginLeft:3}}>*</span>}
                  </label>
                  {fld.help&&<div style={{fontSize:12,color:'#A8A39D',marginBottom:10,lineHeight:1.5,fontFamily:FF}}>{fld.help}</div>}

                  {fld.type==='text'&&(
                    <input type="text" value={values[fld.id]||''} onChange={e=>setVal(fld.id,e.target.value)}
                      placeholder={fld.placeholder||''}
                      style={{...INPUT_BASE,borderColor:err?'#dc2626':values[fld.id]?NAVY:'#E0DCD6'}}/>
                  )}
                  {fld.type==='textarea'&&(
                    <textarea value={values[fld.id]||''} onChange={e=>setVal(fld.id,e.target.value)} rows={4}
                      style={{...INPUT_BASE,borderColor:err?'#dc2626':values[fld.id]?NAVY:'#E0DCD6',resize:'vertical'}}/>
                  )}
                  {fld.type==='select'&&(
                    <div style={{display:'grid',gap:7,marginTop:2}}>
                      {(fld.options||[]).map(opt=>(
                        <div key={opt} style={values[fld.id]===opt?PILL_ON:PILL_BASE} onClick={()=>setVal(fld.id,opt)}>
                          <div style={{width:16,height:16,borderRadius:'50%',border:'2px solid currentColor',flexShrink:0,display:'flex',alignItems:'center',justifyContent:'center'}}>
                            {values[fld.id]===opt&&<div style={{width:7,height:7,borderRadius:'50%',background:'currentColor'}}/>}
                          </div>
                          <span>{opt}</span>
                        </div>
                      ))}
                    </div>
                  )}
                  {fld.type==='multiselect'&&(
                    <div style={{display:'grid',gap:7,marginTop:2}}>
                      {(fld.options||[]).map(opt=>{
                        const on=(values[fld.id]||[]).includes(opt);
                        return(
                          <div key={opt} style={on?PILL_ON:PILL_BASE} onClick={()=>toggleMulti(fld.id,opt)}>
                            <div style={{width:16,height:16,borderRadius:4,border:'2px solid currentColor',flexShrink:0,display:'flex',alignItems:'center',justifyContent:'center',fontSize:11,fontWeight:700}}>
                              {on&&'✓'}
                            </div>
                            <span>{opt}</span>
                          </div>
                        );
                      })}
                    </div>
                  )}
                  {fld.type==='file'&&(
                    <label style={{display:'block',border:'2px dashed '+(values[fld.id]&&values[fld.id].length?NAVY:'#D4CEC8'),borderRadius:10,padding:'18px',textAlign:'center',fontSize:13,color:values[fld.id]&&values[fld.id].length?NAVY:'#A8A39D',background:'#FAFAF8',cursor:'pointer',fontFamily:FF,transition:'all .15s'}}>
                      <input type="file" multiple={fld.multiple} onChange={e=>setVal(fld.id,e.target.files)} style={{display:'none'}}/>
                      {values[fld.id]&&values[fld.id].length
                        ?<span>✓ {values[fld.id].length} {values[fld.id].length===1?'Datei':'Dateien'} ausgewählt: {Array.from(values[fld.id]).map(f=>f.name).join(', ')}</span>
                        :<span>📎 Dateien hier ablegen oder klicken zum Auswählen</span>
                      }
                    </label>
                  )}
                  {err&&<div style={{fontSize:12,color:'#dc2626',marginTop:6,fontFamily:FF}}>{err}</div>}
                </div>
              );
            })}

            {/* Submit-Card */}
            <div style={CARD}>
              {submitErr&&<div style={{background:'#FEF2F2',border:'1px solid #FECACA',borderRadius:9,padding:'12px 14px',marginBottom:14,fontSize:13,color:'#991B1B',lineHeight:1.6,fontFamily:FF}}>{submitErr}</div>}
              <button type="submit" disabled={submitting}
                style={{width:'100%',padding:'14px',background:NAVY,color:'#fff',border:'none',borderRadius:10,fontSize:15,fontWeight:700,cursor:submitting?'wait':'pointer',fontFamily:FF,letterSpacing:'-0.01em',opacity:submitting?.65:1,transition:'opacity .15s'}}>
                {submitting?'Wird gesendet…':'Absenden →'}
              </button>
              <div style={{textAlign:'center',marginTop:12,fontSize:12,color:'#B0ABA5',fontFamily:FF,display:'flex',alignItems:'center',justifyContent:'center',gap:5}}>
                🔒 Ihre Antworten werden sicher übertragen
              </div>
            </div>

          </form>
        </div>
      </div>
      {FOOTER_JSX}
    </div>
  );
}

// ── FORMS ────────────────────────────────────────────────────────
async function publishFormToGithub(form, ghSettings){
  if(!ghSettings)throw new Error('Server/Cloud-Sync muss verbunden sein, um Formulare zu veröffentlichen.');
  const publicForm={slug:form.slug,title:form.title,intro:form.intro||'',thanks:form.thanks||'',submitEmail:form.submitEmail||'',fields:form.fields||[]};
  if (SELF_HOSTED) {
    const r=await fetch(`/api/forms/${form.slug}`,{method:'PUT',headers:{Authorization:`Bearer ${ghSettings.token}`,'Content-Type':'application/json'},body:JSON.stringify(publicForm)});
    if(!r.ok){const t=await r.text();throw new Error(`Server Fehler ${r.status}: ${t.slice(0,120)}`);}
    return;
  }
  const path=`forms/${form.slug}.json`;
  const content=JSON.stringify(publicForm,null,2);
  let sha=null;
  try{
    const r=await fetch(`https://api.github.com/repos/${ghSettings.repo}/contents/${path}`,{headers:{Authorization:`Bearer ${ghSettings.token}`,Accept:'application/vnd.github+json'}});
    if(r.ok){const j=await r.json();sha=j.sha;}
  }catch(e){}
  const body={message:`Update form: ${form.slug}`,content:btoa(unescape(encodeURIComponent(content)))};
  if(sha)body.sha=sha;
  const r=await fetch(`https://api.github.com/repos/${ghSettings.repo}/contents/${path}`,{method:'PUT',headers:{Authorization:`Bearer ${ghSettings.token}`,'Content-Type':'application/json',Accept:'application/vnd.github+json'},body:JSON.stringify(body)});
  if(!r.ok){const t=await r.text();throw new Error(`GitHub Fehler ${r.status}: ${t.slice(0,120)}`);}
}

async function unpublishFormFromGithub(form, ghSettings){
  if(!ghSettings)return;
  if (SELF_HOSTED) {
    try{await fetch(`/api/forms/${form.slug}`,{method:'DELETE',headers:{Authorization:`Bearer ${ghSettings.token||''}`}});}catch(e){}
    return;
  }
  const path=`forms/${form.slug}.json`;
  try{
    const r=await fetch(`https://api.github.com/repos/${ghSettings.repo}/contents/${path}`,{headers:{Authorization:`Bearer ${ghSettings.token}`,Accept:'application/vnd.github+json'}});
    if(!r.ok)return;
    const j=await r.json();
    await fetch(`https://api.github.com/repos/${ghSettings.repo}/contents/${path}`,{method:'DELETE',headers:{Authorization:`Bearer ${ghSettings.token}`,'Content-Type':'application/json',Accept:'application/vnd.github+json'},body:JSON.stringify({message:`Unpublish form: ${form.slug}`,sha:j.sha})});
  }catch(e){}
}

function formPublicUrl(slug){
  const base=window.location.origin+window.location.pathname.replace(/\/$/,'');
  return `${base}/?form=${encodeURIComponent(slug)}`;
}

function FormsView({forms, responses, ghSettings, onUpdateForms, onUpdateResponses}){
  const [tab,setTab]=useState('forms');
  const [editingForm,setEditingForm]=useState(null);
  const [viewingResponse,setViewingResponse]=useState(null);
  const [busy,setBusy]=useState(null);
  const [msg,setMsg]=useState('');

  const newForm=()=>{
    setEditingForm({id:'form_'+uid(),slug:'neues-formular-'+uid().slice(0,4),title:'Neues Formular',intro:'',thanks:'Vielen Dank für Ihre Antworten!',submitEmail:'',fields:[],createdAt:new Date().toISOString(),published:false});
  };
  const saveForm=async(form,doPublish)=>{
    const exists=forms.some(f=>f.id===form.id);
    let updated={...form};
    if(doPublish){
      try{
        setBusy('publish');setMsg('');
        await publishFormToGithub(form,ghSettings);
        updated={...updated,published:true,publishedAt:new Date().toISOString()};
        setMsg('✓ Formular veröffentlicht.');
      }catch(e){setMsg('Fehler: '+e.message);setBusy(null);return;}
      setBusy(null);
    }
    onUpdateForms(exists?forms.map(f=>f.id===form.id?updated:f):[...forms,updated]);
    setEditingForm(null);
  };
  const deleteForm=async(form)=>{
    if(!window.confirm(`Formular "${form.title}" wirklich löschen?`))return;
    if(form.published&&ghSettings){try{await unpublishFormFromGithub(form,ghSettings);}catch(e){}}
    onUpdateForms(forms.filter(f=>f.id!==form.id));
  };
  const togglePublish=async(form)=>{
    if(form.published){
      if(!window.confirm('Formular vom Internet entfernen? Bestehende Antworten bleiben erhalten.'))return;
      try{setBusy('publish');await unpublishFormFromGithub(form,ghSettings);onUpdateForms(forms.map(f=>f.id===form.id?{...f,published:false}:f));setMsg('Formular ist nicht mehr öffentlich.');}
      catch(e){setMsg('Fehler: '+e.message);}
      setBusy(null);
    }else{
      if(!form.submitEmail){setMsg('Bitte zuerst Empfänger-Email im Formular eintragen.');return;}
      try{setBusy('publish');await publishFormToGithub(form,ghSettings);onUpdateForms(forms.map(f=>f.id===form.id?{...f,published:true,publishedAt:new Date().toISOString()}:f));setMsg('✓ Formular ist jetzt öffentlich.');}
      catch(e){setMsg('Fehler: '+e.message);}
      setBusy(null);
    }
  };
  const copyLink=(slug)=>{
    navigator.clipboard?.writeText(formPublicUrl(slug));
    setMsg('Link kopiert.');setTimeout(()=>setMsg(''),2000);
  };
  const markRead=(r)=>{onUpdateResponses(responses.map(x=>x.id===r.id?{...x,read:true}:x));};
  const deleteResponse=(r)=>{if(window.confirm('Antwort wirklich löschen?'))onUpdateResponses(responses.filter(x=>x.id!==r.id));};

  return(<>
    <div style={{background:'white',borderBottom:'1px solid rgba(0,0,0,.07)',padding:'14px 28px',display:'flex',alignItems:'center',gap:14,flexShrink:0}}>
      <div style={{flex:1}}>
        <h1 style={{fontSize:18,fontWeight:800,letterSpacing:'-0.02em'}}>Formulare</h1>
        <div style={{fontSize:12,color:'#B0ABA5',marginTop:2,display:'flex',gap:12}}>
          <span>{forms.length} {forms.length===1?'Formular':'Formulare'}</span>
          <span>· {responses.length} {responses.length===1?'Antwort':'Antworten'}</span>
          {responses.filter(r=>!r.read).length>0&&<span style={{color:'#16a34a',fontWeight:600}}>· {responses.filter(r=>!r.read).length} neu</span>}
        </div>
      </div>
      <div style={{display:'inline-flex',background:'#F5F3F0',borderRadius:10,padding:3}}>
        <button onClick={()=>setTab('forms')} style={{padding:'7px 14px',borderRadius:8,fontSize:12.5,fontWeight:600,border:'none',cursor:'pointer',background:tab==='forms'?'white':'transparent',color:tab==='forms'?'#141210':'#A8A39D',boxShadow:tab==='forms'?'0 1px 2px rgba(0,0,0,.05)':'none'}}>Formulare</button>
        <button onClick={()=>setTab('responses')} style={{padding:'7px 14px',borderRadius:8,fontSize:12.5,fontWeight:600,border:'none',cursor:'pointer',background:tab==='responses'?'white':'transparent',color:tab==='responses'?'#141210':'#A8A39D',boxShadow:tab==='responses'?'0 1px 2px rgba(0,0,0,.05)':'none'}}>Antworten {responses.filter(r=>!r.read).length>0&&`(${responses.filter(r=>!r.read).length})`}</button>
      </div>
      {tab==='forms'&&<button className="btn btn-primary btn-sm" onClick={newForm}><Icons.Plus/>Neues Formular</button>}
    </div>
    {msg&&<div style={{padding:'10px 28px',fontSize:12.5,color:msg.startsWith('Fehler')?'#C0392B':'#16a34a',background:msg.startsWith('Fehler')?'#FEF2F2':'#F0FDF4',borderBottom:'1px solid rgba(0,0,0,.05)'}}>{msg}</div>}

    <div style={{flex:1,overflowY:'auto',padding:'24px 28px'}}>
      {tab==='forms'?(
        forms.length===0?(
          <div style={{textAlign:'center',padding:'60px 20px',color:'#A8A39D'}}>
            <div style={{fontSize:42,marginBottom:14}}>📋</div>
            <div style={{fontWeight:600,fontSize:15,color:'#6B6560',marginBottom:6}}>Noch kein Formular</div>
            <div style={{fontSize:13,marginBottom:18}}>Erstelle ein Formular, das du an Kunden zum Ausfüllen weitergeben kannst.</div>
            <button className="btn btn-primary" onClick={newForm}><Icons.Plus/>Erstes Formular erstellen</button>
          </div>
        ):(
          <div style={{display:'grid',gap:12}}>
            {forms.map(f=>{
              const responseCount=responses.filter(r=>r.formId===f.id).length;
              return(
                <div key={f.id} style={{background:'white',border:'1px solid rgba(0,0,0,.07)',borderRadius:12,padding:'16px 18px'}}>
                  <div style={{display:'flex',alignItems:'flex-start',gap:14}}>
                    <div style={{flex:1,minWidth:0}}>
                      <div style={{display:'flex',alignItems:'center',gap:8,marginBottom:4,flexWrap:'wrap'}}>
                        <div style={{fontWeight:700,fontSize:15,color:'#141210'}}>{f.title}</div>
                        {f.published?(
                          <span style={{fontSize:10.5,fontWeight:700,color:'#16a34a',background:'#F0FDF4',padding:'2px 8px',borderRadius:99,border:'1px solid #BBF7D0'}}>● ÖFFENTLICH</span>
                        ):(
                          <span style={{fontSize:10.5,fontWeight:700,color:'#A8A39D',background:'#F5F3F0',padding:'2px 8px',borderRadius:99}}>ENTWURF</span>
                        )}
                      </div>
                      <div style={{fontSize:12,color:'#A8A39D',marginBottom:8}}>{(f.fields||[]).filter(x=>x.type!=='section'&&x.type!=='info').length} Felder · {responseCount} {responseCount===1?'Antwort':'Antworten'}{f.submitEmail&&` · → ${f.submitEmail}`}</div>
                      {f.published&&(
                        <div style={{display:'flex',alignItems:'center',gap:6,marginTop:6}}>
                          <code style={{flex:1,background:'#FAFAF8',padding:'5px 9px',borderRadius:6,fontSize:11,border:'1px solid #E8E4DF',wordBreak:'break-all',color:'#3F3A35'}}>{formPublicUrl(f.slug)}</code>
                          <button className="btn btn-ghost btn-sm" onClick={()=>copyLink(f.slug)} style={{flexShrink:0,fontSize:11}}>Kopieren</button>
                          <a className="btn btn-ghost btn-sm" href={formPublicUrl(f.slug)} target="_blank" rel="noopener" style={{flexShrink:0,fontSize:11,textDecoration:'none'}}>Öffnen</a>
                        </div>
                      )}
                    </div>
                    <div style={{display:'flex',gap:6,flexShrink:0}}>
                      <button className="btn btn-ghost btn-sm" onClick={()=>setEditingForm(f)} disabled={busy}>Bearbeiten</button>
                      <button className="btn btn-ghost btn-sm" onClick={()=>togglePublish(f)} disabled={busy} style={f.published?{}:{color:'#16a34a',fontWeight:600}}>{busy==='publish'?'…':f.published?'Offline nehmen':'Veröffentlichen'}</button>
                      <button className="btn btn-danger btn-sm" onClick={()=>deleteForm(f)} disabled={busy}>Löschen</button>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )
      ):(
        responses.length===0?(
          <div style={{textAlign:'center',padding:'60px 20px',color:'#A8A39D'}}>
            <div style={{fontSize:42,marginBottom:14}}>📭</div>
            <div style={{fontWeight:600,fontSize:15,color:'#6B6560',marginBottom:6}}>Noch keine Antworten</div>
            <div style={{fontSize:13}}>Sobald jemand dein Formular ausfüllt, erscheinen die Antworten hier.</div>
          </div>
        ):(
          <div style={{display:'grid',gap:8}}>
            {[...responses].sort((a,b)=>(b.submittedAt||'').localeCompare(a.submittedAt||'')).map(r=>{
              const form=forms.find(f=>f.id===r.formId);
              const date=r.submittedAt?new Date(r.submittedAt).toLocaleDateString('de-DE',{day:'2-digit',month:'2-digit',year:'numeric',hour:'2-digit',minute:'2-digit'}):'';
              return(
                <div key={r.id} onClick={()=>{setViewingResponse(r);if(!r.read)markRead(r);}} style={{background:'white',border:'1px solid rgba(0,0,0,.07)',borderRadius:10,padding:'12px 16px',cursor:'pointer',display:'flex',alignItems:'center',gap:14,transition:'border-color .12s'}}
                  onMouseEnter={e=>e.currentTarget.style.borderColor='#D4CEC8'}
                  onMouseLeave={e=>e.currentTarget.style.borderColor='rgba(0,0,0,.07)'}>
                  {!r.read&&<span style={{width:8,height:8,borderRadius:'50%',background:'#22c55e',flexShrink:0}}/>}
                  <div style={{flex:1,minWidth:0}}>
                    <div style={{fontWeight:600,fontSize:14,color:'#141210'}}>{r.contactName||'Anonym'}</div>
                    <div style={{fontSize:11.5,color:'#A8A39D',marginTop:2}}>{form?.title||r.formTitle||'Formular'} · {date}</div>
                  </div>
                  <button className="btn btn-danger btn-sm" onClick={e=>{e.stopPropagation();deleteResponse(r);}}>Löschen</button>
                </div>
              );
            })}
          </div>
        )
      )}
    </div>
    {editingForm&&<FormEditorModal form={editingForm} ghSettings={ghSettings} onSave={saveForm} onClose={()=>setEditingForm(null)}/>}
    {viewingResponse&&<ResponseViewerModal response={viewingResponse} form={forms.find(f=>f.id===viewingResponse.formId)} onClose={()=>setViewingResponse(null)}/>}
  </>);
}

function FormEditorModal({form, ghSettings, onSave, onClose}){
  const [f,setF]=useState({...form,fields:[...(form.fields||[])]});
  const [saving,setSaving]=useState(false);
  const fieldTypes=[
    {v:'text',l:'Kurzer Text'},
    {v:'textarea',l:'Langer Text'},
    {v:'select',l:'Einzelauswahl'},
    {v:'multiselect',l:'Mehrfachauswahl'},
    {v:'file',l:'Datei-Upload'},
    {v:'section',l:'Abschnittsüberschrift'},
    {v:'info',l:'Hinweis-Text'},
  ];
  const updField=(idx,patch)=>setF(s=>({...s,fields:s.fields.map((x,i)=>i===idx?{...x,...patch}:x)}));
  const removeField=idx=>setF(s=>({...s,fields:s.fields.filter((_,i)=>i!==idx)}));
  const addField=t=>setF(s=>({...s,fields:[...s.fields,{id:'fld_'+uid(),type:t,label:'',required:false,...(t==='select'||t==='multiselect'?{options:['Option 1']}:{})}]}));
  const moveField=(idx,dir)=>{const j=idx+dir;if(j<0||j>=f.fields.length)return;const a=[...f.fields];[a[idx],a[j]]=[a[j],a[idx]];setF({...f,fields:a});};
  const slugify=s=>s.toLowerCase().replace(/[äöü]/g,m=>({ä:'ae',ö:'oe',ü:'ue'}[m])).replace(/ß/g,'ss').replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'').slice(0,60);
  const handleSave=async(publish)=>{
    if(!f.title.trim()){alert('Titel fehlt');return;}
    if(!f.slug.trim()){alert('Slug fehlt');return;}
    if(publish&&!f.submitEmail.trim()){alert('Empfänger-Email fehlt — wird benötigt für die Antworten.');return;}
    setSaving(true);
    await onSave(f,publish);
    setSaving(false);
  };
  return(
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-box" onClick={e=>e.stopPropagation()} style={{width:780,maxHeight:'90vh',display:'flex',flexDirection:'column'}}>
        <div style={{display:'flex',justifyContent:'space-between',alignItems:'flex-start',marginBottom:16,flexShrink:0}}>
          <div>
            <h2 style={{fontSize:17,fontWeight:700}}>Formular bearbeiten</h2>
            <p style={{fontSize:12.5,color:'#A8A39D',marginTop:3}}>Felder hinzufügen, anordnen, dann veröffentlichen.</p>
          </div>
          <button onClick={onClose} style={{background:'#F5F3F0',border:'none',borderRadius:8,padding:8,color:'#999',lineHeight:0}}><Icons.Close/></button>
        </div>

        <div style={{overflowY:'auto',flex:1,paddingRight:6}}>
          <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:12,marginBottom:14}}>
            <div>
              <div style={lbl}>Titel</div>
              <input value={f.title} onChange={e=>setF({...f,title:e.target.value,slug:f.slug||slugify(e.target.value)})}/>
            </div>
            <div>
              <div style={lbl}>URL-Slug</div>
              <input value={f.slug} onChange={e=>setF({...f,slug:slugify(e.target.value)})} style={{fontFamily:'monospace',fontSize:12.5}}/>
            </div>
          </div>
          <div style={{marginBottom:14}}>
            <div style={lbl}>Empfänger-Email (wohin Antworten geschickt werden) *</div>
            <input value={f.submitEmail} onChange={e=>setF({...f,submitEmail:e.target.value})} placeholder="deine-email@beispiel.at" type="email"/>
            <div style={{fontSize:11,color:'#A8A39D',marginTop:4,lineHeight:1.5}}>Antworten kommen via FormSubmit.co an diese Email. Beim ersten Eingang musst du die Email einmal bestätigen.</div>
          </div>
          <div style={{marginBottom:14}}>
            <div style={lbl}>Einleitungstext (oben im Formular)</div>
            <textarea value={f.intro||''} onChange={e=>setF({...f,intro:e.target.value})} rows={2}/>
          </div>
          <div style={{marginBottom:14}}>
            <div style={lbl}>Danke-Text (nach dem Absenden)</div>
            <textarea value={f.thanks||''} onChange={e=>setF({...f,thanks:e.target.value})} rows={2}/>
          </div>

          <div style={{borderTop:'1px solid #F0EDE8',paddingTop:14,marginBottom:10}}>
            <div style={{fontSize:13,fontWeight:700,marginBottom:10}}>Felder ({f.fields.length})</div>
            {f.fields.map((fld,idx)=>(
              <div key={fld.id} style={{background:fld.type==='section'?'#F0EDE8':'#FAFAF8',border:'1px solid #E8E4DF',borderRadius:9,padding:10,marginBottom:8}}>
                <div style={{display:'flex',gap:8,alignItems:'center',marginBottom:6}}>
                  <select value={fld.type} onChange={e=>updField(idx,{type:e.target.value})} style={{width:160,fontSize:12}}>
                    {fieldTypes.map(t=><option key={t.v} value={t.v}>{t.l}</option>)}
                  </select>
                  <input value={fld.label||''} onChange={e=>updField(idx,{label:e.target.value})} placeholder={fld.type==='section'?'Abschnittstitel':fld.type==='info'?'Hinweistext':'Feldbezeichnung'} style={{flex:1,fontSize:12.5}}/>
                  <button className="btn btn-ghost btn-sm" onClick={()=>moveField(idx,-1)} disabled={idx===0} style={{padding:'4px 8px'}}>↑</button>
                  <button className="btn btn-ghost btn-sm" onClick={()=>moveField(idx,1)} disabled={idx===f.fields.length-1} style={{padding:'4px 8px'}}>↓</button>
                  <button className="btn btn-danger btn-sm" onClick={()=>removeField(idx)} style={{padding:'4px 8px'}}>×</button>
                </div>
                {fld.type!=='section'&&fld.type!=='info'&&(
                  <div style={{display:'flex',gap:8,alignItems:'center',flexWrap:'wrap'}}>
                    <label style={{fontSize:11.5,display:'flex',alignItems:'center',gap:5,cursor:'pointer'}}>
                      <input type="checkbox" checked={!!fld.required} onChange={e=>updField(idx,{required:e.target.checked})}/>
                      Pflichtfeld
                    </label>
                    {(fld.type==='text'||fld.type==='textarea')&&(
                      <input value={fld.help||''} onChange={e=>updField(idx,{help:e.target.value})} placeholder="Hilfetext (optional)" style={{flex:1,minWidth:200,fontSize:11.5}}/>
                    )}
                  </div>
                )}
                {(fld.type==='select'||fld.type==='multiselect')&&(
                  <div style={{marginTop:6}}>
                    <div style={{fontSize:10.5,color:'#A8A39D',marginBottom:4,textTransform:'uppercase',letterSpacing:'0.05em'}}>Optionen (eine pro Zeile)</div>
                    <textarea value={(fld.options||[]).join('\n')} onChange={e=>updField(idx,{options:e.target.value.split('\n').map(s=>s.trim()).filter(Boolean)})} rows={Math.min(6,(fld.options||[]).length+1)} style={{fontSize:12,fontFamily:'monospace'}}/>
                  </div>
                )}
                {fld.help&&fld.type!=='section'&&fld.type!=='info'&&(fld.type==='select'||fld.type==='multiselect'||fld.type==='file')&&(
                  <input value={fld.help||''} onChange={e=>updField(idx,{help:e.target.value})} placeholder="Hilfetext" style={{marginTop:6,fontSize:11.5}}/>
                )}
              </div>
            ))}
            <div style={{display:'flex',gap:6,flexWrap:'wrap',marginTop:10}}>
              {fieldTypes.map(t=>(
                <button key={t.v} className="btn btn-ghost btn-sm" onClick={()=>addField(t.v)} style={{fontSize:11.5}}>+ {t.l}</button>
              ))}
            </div>
          </div>
        </div>

        <div style={{display:'flex',gap:8,justifyContent:'flex-end',paddingTop:14,borderTop:'1px solid #F0EDE8',flexShrink:0}}>
          <button className="btn btn-ghost" onClick={onClose} disabled={saving}>Abbrechen</button>
          <button className="btn btn-ghost" onClick={()=>handleSave(false)} disabled={saving}>Nur speichern</button>
          <button className="btn btn-primary" onClick={()=>handleSave(true)} disabled={saving||!ghSettings}>{saving?'…':form.published?'Speichern & neu veröffentlichen':'Speichern & veröffentlichen'}</button>
        </div>
        {!ghSettings&&<div style={{fontSize:11.5,color:'#9A3412',marginTop:8,textAlign:'right'}}>Cloud-Sync muss verbunden sein, um zu veröffentlichen.</div>}
      </div>
    </div>
  );
}

function ResponseViewerModal({response, form, onClose}){
  const fields=form?.fields||[];
  const data=response.data||{};
  return(
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-box" onClick={e=>e.stopPropagation()} style={{width:680,maxHeight:'85vh',display:'flex',flexDirection:'column'}}>
        <div style={{display:'flex',justifyContent:'space-between',alignItems:'flex-start',marginBottom:14,flexShrink:0}}>
          <div>
            <h2 style={{fontSize:17,fontWeight:700}}>{response.contactName||'Antwort'}</h2>
            <p style={{fontSize:12.5,color:'#A8A39D',marginTop:3}}>
              {form?.title||response.formTitle} · {response.submittedAt?new Date(response.submittedAt).toLocaleString('de-DE'):''}
            </p>
          </div>
          <button onClick={onClose} style={{background:'#F5F3F0',border:'none',borderRadius:8,padding:8,color:'#999',lineHeight:0}}><Icons.Close/></button>
        </div>
        <div style={{overflowY:'auto',flex:1,paddingRight:6}}>
          {fields.length>0?fields.filter(fld=>fld.type!=='info').map(fld=>{
            if(fld.type==='section')return(<div key={fld.id} style={{fontSize:11,fontWeight:700,color:'#A8A39D',textTransform:'uppercase',letterSpacing:'0.06em',marginTop:18,marginBottom:8,paddingBottom:6,borderBottom:'1px solid #F0EDE8'}}>{fld.label}</div>);
            const v=data[fld.id];
            const display=Array.isArray(v)?v.join(', '):(v||'—');
            return(
              <div key={fld.id} style={{marginBottom:14}}>
                <div style={{fontSize:11.5,fontWeight:600,color:'#6B6560',marginBottom:3}}>{fld.label}</div>
                <div style={{fontSize:13.5,color:'#141210',whiteSpace:'pre-wrap',wordBreak:'break-word'}}>{display||'—'}</div>
              </div>
            );
          }):Object.entries(data).map(([k,v])=>(
            <div key={k} style={{marginBottom:12}}>
              <div style={{fontSize:11.5,fontWeight:600,color:'#6B6560',marginBottom:3}}>{k}</div>
              <div style={{fontSize:13.5,color:'#141210',whiteSpace:'pre-wrap'}}>{Array.isArray(v)?v.join(', '):(v||'—')}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── LEADS VIEW (Werbe-Webhook Inbox + Kampagnen-Verwaltung) ────────
function LeadsView({leads, sections, onUpdateLeads, onConvertLead}){
  const [serverCampaigns,setServerCampaigns]=useState(null); // null=loading
  const [pendingLeads,setPendingLeads]=useState([]);
  const [busy,setBusy]=useState(false);
  const [err,setErr]=useState('');
  const [showNew,setShowNew]=useState(false);
  const [newSlug,setNewSlug]=useState('');
  const [newLabel,setNewLabel]=useState('');
  const [reveal,setReveal]=useState({}); // {slug: bool} — show secret in URL
  const [tab,setTab]=useState('inbox'); // 'inbox' | 'campaigns' | 'log' | 'archive'
  const [convert,setConvert]=useState(null); // lead being converted
  const [logEntries,setLogEntries]=useState(null);
  const [expandedLog,setExpandedLog]=useState({});

  const auth={Authorization:`Bearer ${window.WEBARS_API_TOKEN}`};

  const loadCampaigns=async()=>{
    try{const r=await fetch('/api/campaigns',{headers:auth});if(r.ok){const j=await r.json();setServerCampaigns(j.campaigns||[]);}else setServerCampaigns([]);}
    catch(e){setServerCampaigns([]);}
  };

  const pollInbox=async()=>{
    try{
      const r=await fetch('/api/leads',{headers:auth});
      if(!r.ok)return;
      const j=await r.json();
      const fresh=j.leads||[];
      setPendingLeads(fresh);
      // Auto-import: pull each into encrypted state, then claim
      if(fresh.length){
        const known=new Set((leads||[]).map(l=>l.serverId));
        const newOnes=fresh.filter(l=>!known.has(l.id));
        if(newOnes.length){
          const STD_KEYS=['name','email','phone','company','message','source','metadata'];
          const imported=newOnes.map(l=>{
            const p=l.payload||{};
            // Preserve EVERYTHING the partner sent — known fields go into named slots,
            // anything else lands in `extras` and is displayed as-is in the UI.
            return {
              id:'lead_'+(l.id)+'_'+Date.now().toString(36),
              serverId:l.id,
              campaign:l.campaign,
              name:(p.name||'').toString(),
              email:(p.email||'').toString(),
              phone:(p.phone||'').toString(),
              company:(p.company||'').toString(),
              message:(p.message||'').toString(),
              source:(p.source||l.campaign||'').toString(),
              metadata:p.metadata&&typeof p.metadata==='object'?p.metadata:{},
              extras:Object.fromEntries(Object.entries(p).filter(([k])=>!STD_KEYS.includes(k))),
              rawPayload:p, // keep the full original payload too for audit / future migrations
              receivedAt:l.receivedAt,
              sourceIp:l.sourceIp,
              status:'new',
              importedAt:new Date().toISOString(),
            };
          });
          onUpdateLeads([...(leads||[]), ...imported]);
          // Claim each on server (best effort)
          for(const l of newOnes){
            fetch(`/api/leads/${l.id}/claim`,{method:'POST',headers:auth}).catch(()=>{});
          }
        }
      }
    }catch(e){/* network blip — silent */}
  };

  const loadLog=async()=>{
    try{const r=await fetch('/api/leads/log?limit=200',{headers:auth});if(r.ok){const j=await r.json();setLogEntries(j.entries||[]);}else setLogEntries([]);}
    catch(e){setLogEntries([]);}
  };
  const clearLog=async()=>{
    if(!window.confirm('Alle Log-Einträge löschen?'))return;
    await fetch('/api/leads/log',{method:'DELETE',headers:auth});
    loadLog();
  };

  useEffect(()=>{loadCampaigns();pollInbox();const t=setInterval(pollInbox,30000);return()=>clearInterval(t);},[]);
  useEffect(()=>{
    if(tab!=='log')return;
    loadLog();
    const t=setInterval(loadLog,5000); // refresh log every 5s while tab open
    return()=>clearInterval(t);
  },[tab]);

  const createCampaign=async()=>{
    if(!/^[a-z0-9_-]{2,64}$/.test(newSlug)){setErr('Slug: nur a-z, 0-9, _ oder - (2-64 Zeichen)');return;}
    setBusy(true);setErr('');
    try{
      const r=await fetch('/api/campaigns',{method:'POST',headers:{...auth,'Content-Type':'application/json'},body:JSON.stringify({slug:newSlug,label:newLabel})});
      if(!r.ok){const j=await r.json().catch(()=>({}));setErr(j.error||'Fehler ('+r.status+')');setBusy(false);return;}
      setNewSlug('');setNewLabel('');setShowNew(false);
      await loadCampaigns();
    }catch(e){setErr('Netzwerkfehler');}
    setBusy(false);
  };

  const deleteCampaign=async(slug)=>{
    if(!window.confirm(`Kampagne "${slug}" löschen?\nDamit erlischt auch der Webhook — laufende Werbeanzeigen können dann keine Leads mehr senden.`))return;
    await fetch('/api/campaigns/'+encodeURIComponent(slug),{method:'DELETE',headers:auth});
    await loadCampaigns();
  };

  const copyToClip=(t,note='Kopiert!')=>{
    if(navigator.clipboard?.writeText)navigator.clipboard.writeText(t).then(()=>alert(note),()=>alert('Kopieren fehlgeschlagen.'));
    else{const ta=document.createElement('textarea');ta.value=t;document.body.appendChild(ta);ta.select();document.execCommand('copy');document.body.removeChild(ta);alert(note);}
  };

  const newLeads=(leads||[]).filter(l=>l.status==='new');
  const archivedLeads=(leads||[]).filter(l=>l.status!=='new');

  return (
    <div style={{flex:1,overflow:'auto',padding:'24px 28px',background:'#F3F0EB'}}>
      {/* Tabs */}
      <div style={{display:'flex',gap:6,marginBottom:20}}>
        {[{k:'inbox',l:'Posteingang',n:newLeads.length},{k:'campaigns',l:'Kampagnen',n:(serverCampaigns||[]).length},{k:'log',l:'Webhook-Log',n:null},{k:'archive',l:'Archiv',n:archivedLeads.length}].map(t=>(
          <button key={t.k} onClick={()=>setTab(t.k)} className="btn btn-sm" style={{background:tab===t.k?'#141210':'white',color:tab===t.k?'white':'#6B6560',border:tab===t.k?'none':'1px solid rgba(0,0,0,.08)'}}>
            {t.l}{t.n>0?` · ${t.n}`:''}
          </button>
        ))}
      </div>

      {tab==='inbox'&&(
        <div>
          {newLeads.length===0?(
            <div style={{background:'white',padding:'40px 24px',borderRadius:14,textAlign:'center',color:'#6B6560'}}>
              <div style={{fontSize:34,marginBottom:8}}>📭</div>
              <div style={{fontWeight:600,marginBottom:4}}>Keine neuen Leads</div>
              <div style={{fontSize:13}}>Sobald deine Werbeanzeigen Daten an den Webhook senden, erscheinen sie hier.</div>
            </div>
          ):(
            <div style={{display:'grid',gap:12}}>
              {newLeads.map(l=>{
                const extraEntries=Object.entries(l.extras||{}).filter(([,v])=>v!==null&&v!==undefined&&v!=='');
                return (
                <div key={l.id} style={{background:'white',borderRadius:14,padding:'16px 18px',border:'1px solid rgba(0,0,0,.06)'}}>
                  <div style={{display:'flex',alignItems:'flex-start',justifyContent:'space-between',gap:12,marginBottom:10}}>
                    <div style={{flex:1,minWidth:0}}>
                      <div style={{display:'flex',alignItems:'center',gap:8,marginBottom:4,flexWrap:'wrap'}}>
                        <span style={{fontSize:10,fontWeight:700,color:'#22c55e',background:'rgba(34,197,94,.12)',borderRadius:99,padding:'2px 8px'}}>NEU</span>
                        <span style={{fontSize:11,color:'#A8A39D'}}>Kampagne <code style={{background:'#F5F3F0',padding:'1px 6px',borderRadius:4,fontSize:11}}>{l.campaign}</code> · {new Date(l.receivedAt||l.importedAt).toLocaleString('de-AT')}</span>
                      </div>
                      <div style={{fontWeight:700,fontSize:15.5}}>{l.name||'(ohne Namen)'}</div>
                      <div style={{display:'flex',gap:14,flexWrap:'wrap',fontSize:13,color:'#5A554F',marginTop:4}}>
                        {l.email&&<span>📧 {l.email}</span>}
                        {l.phone&&<span>📞 {l.phone}</span>}
                        {l.company&&<span>🏢 {l.company}</span>}
                      </div>
                      {/* Source — ALWAYS shown if present, important for tracking which form/page sent the lead */}
                      {l.source&&l.source!==l.campaign&&(
                        <div style={{marginTop:6,fontSize:12.5,color:'#5A554F'}}>
                          <span style={{color:'#A8A39D'}}>Quelle:</span> <span style={{background:'#FEF3C7',padding:'2px 8px',borderRadius:6,fontWeight:600,fontSize:12}}>{l.source}</span>
                        </div>
                      )}
                      {l.message&&<div style={{marginTop:8,padding:'8px 10px',background:'#F5F3F0',borderRadius:8,fontSize:13,color:'#5A554F',whiteSpace:'pre-wrap'}}>{l.message}</div>}
                      {/* Extras — show ALL non-empty fields directly visible (not hidden behind details) */}
                      {extraEntries.length>0&&(
                        <div style={{marginTop:10,padding:'10px 12px',background:'#FAFAF8',border:'1px solid rgba(0,0,0,.05)',borderRadius:8}}>
                          <div style={{fontSize:11,fontWeight:600,color:'#A8A39D',textTransform:'uppercase',letterSpacing:'0.04em',marginBottom:6}}>Zusatzfelder</div>
                          <div style={{display:'grid',gridTemplateColumns:'auto 1fr',gap:'4px 12px',fontSize:13}}>
                            {extraEntries.map(([k,v])=>(
                              <React.Fragment key={k}>
                                <div style={{color:'#A8A39D',fontWeight:500,fontFamily:'ui-monospace,Menlo,monospace',fontSize:12.5}}>{k}:</div>
                                <div style={{color:'#5A554F',wordBreak:'break-word'}}>{typeof v==='object'?JSON.stringify(v):String(v)}</div>
                              </React.Fragment>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                    <div style={{display:'flex',flexDirection:'column',gap:6}}>
                      <button className="btn btn-primary btn-sm" onClick={()=>setConvert(l)}>→ Kontakt</button>
                      <button className="btn btn-ghost btn-sm" onClick={()=>onUpdateLeads((leads||[]).map(x=>x.id===l.id?{...x,status:'dismissed'}:x))}>Verwerfen</button>
                    </div>
                  </div>
                </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {tab==='campaigns'&&(
        <div>
          <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',marginBottom:14}}>
            <div style={{fontSize:13,color:'#6B6560'}}>Erstelle eine Kampagne pro Werbekanal. Den Webhook-URL gibst du deinem Werbepartner.</div>
            <button className="btn btn-primary btn-sm" onClick={()=>setShowNew(v=>!v)}><Icons.Plus/>Neue Kampagne</button>
          </div>
          {showNew&&(
            <div style={{background:'white',padding:18,borderRadius:14,marginBottom:14,border:'1px solid rgba(0,0,0,.06)'}}>
              <div style={{display:'grid',gap:10}}>
                <div>
                  <label style={{fontSize:12,color:'#6B6560',fontWeight:600}}>Slug (URL-Teil) — z.B. "facebook-mai-2026"</label>
                  <input value={newSlug} onChange={e=>setNewSlug(e.target.value.toLowerCase())} placeholder="nur a-z, 0-9, _ oder -" style={{width:'100%',marginTop:4}} autoFocus/>
                </div>
                <div>
                  <label style={{fontSize:12,color:'#6B6560',fontWeight:600}}>Label (für deine Übersicht)</label>
                  <input value={newLabel} onChange={e=>setNewLabel(e.target.value)} placeholder="z.B. Facebook Ads — Mai 2026" style={{width:'100%',marginTop:4}}/>
                </div>
                {err&&<div style={{fontSize:12,color:'#dc2626'}}>{err}</div>}
                <div style={{display:'flex',gap:8,justifyContent:'flex-end'}}>
                  <button className="btn btn-ghost btn-sm" onClick={()=>{setShowNew(false);setErr('');}}>Abbrechen</button>
                  <button className="btn btn-primary btn-sm" onClick={createCampaign} disabled={busy||!newSlug}>Erstellen</button>
                </div>
              </div>
            </div>
          )}
          {serverCampaigns===null?(
            <div style={{textAlign:'center',padding:40,color:'#A8A39D'}}>Lade…</div>
          ):serverCampaigns.length===0?(
            <div style={{background:'white',padding:'40px 24px',borderRadius:14,textAlign:'center',color:'#6B6560'}}>
              <div style={{fontSize:34,marginBottom:8}}>🎯</div>
              <div style={{fontWeight:600,marginBottom:4}}>Noch keine Kampagne</div>
              <div style={{fontSize:13}}>Lege eine Kampagne an um den Webhook-URL zu bekommen.</div>
            </div>
          ):(
            <div style={{display:'grid',gap:12}}>
              {serverCampaigns.map(c=>(
                <div key={c.slug} style={{background:'white',padding:'16px 18px',borderRadius:14,border:'1px solid rgba(0,0,0,.06)'}}>
                  <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',gap:12,marginBottom:10}}>
                    <div>
                      <div style={{fontWeight:700,fontSize:15}}>{c.label||c.slug}</div>
                      <div style={{fontSize:12,color:'#A8A39D'}}>Slug: <code>{c.slug}</code> · seit {new Date(c.createdAt).toLocaleDateString('de-AT')}</div>
                    </div>
                    <button className="btn btn-ghost btn-sm" onClick={()=>deleteCampaign(c.slug)} style={{color:'#dc2626'}}>Löschen</button>
                  </div>
                  <div style={{background:'#F5F3F0',padding:'10px 12px',borderRadius:8,fontSize:12,wordBreak:'break-all',fontFamily:'ui-monospace,Menlo,monospace'}}>
                    {reveal[c.slug]?c.webhookUrl:c.webhookUrl.replace(/key=[^&]+/,'key=••••••••••••••••••••')}
                  </div>
                  <div style={{display:'flex',gap:8,marginTop:8}}>
                    <button className="btn btn-ghost btn-sm" onClick={()=>setReveal(r=>({...r,[c.slug]:!r[c.slug]}))}>{reveal[c.slug]?'Verbergen':'Anzeigen'}</button>
                    <button className="btn btn-ghost btn-sm" onClick={()=>copyToClip(c.webhookUrl,'Webhook-URL kopiert!')}>URL kopieren</button>
                    <button className="btn btn-ghost btn-sm" onClick={()=>copyToClip(c.webhookSecret,'Secret kopiert!')}>Nur Secret kopieren</button>
                  </div>
                </div>
              ))}
            </div>
          )}
          {/* API Docs */}
          <div style={{marginTop:24,background:'white',padding:18,borderRadius:14,border:'1px solid rgba(0,0,0,.06)'}}>
            <div style={{fontWeight:700,fontSize:14,marginBottom:8}}>📘 Für deinen Werbepartner</div>
            <div style={{fontSize:13,color:'#5A554F',lineHeight:1.6}}>
              <p style={{margin:'4px 0'}}>Der Partner sendet ein <strong>HTTP POST</strong> an die Webhook-URL mit JSON-Body:</p>
              <pre style={{background:'#F5F3F0',padding:12,borderRadius:8,fontSize:12,overflow:'auto'}}>{`{
  "name":    "Max Mustermann",   // PFLICHT
  "email":   "max@example.at",
  "phone":   "+43 660 1234567",
  "company": "Mustermann GmbH",
  "message": "Interesse an Webentwicklung",
  "source":  "facebook-leadform"  // optional
}`}</pre>
              <p style={{margin:'8px 0 4px'}}>Beliebige Zusatzfelder werden auch gespeichert.</p>
              <p style={{margin:'4px 0'}}>Antworten: <code>200 {`{ok:true, id:N}`}</code> · <code>401</code> falsches Secret · <code>404</code> unbekannte Kampagne · <code>413</code> &gt;32KB.</p>
              <p style={{margin:'8px 0 0'}}>Volle Doku als JSON: <a href="/api/leads/docs" target="_blank" style={{color:'#0F0E0C'}}>GET /api/leads/docs</a></p>
            </div>
          </div>
        </div>
      )}

      {tab==='log'&&(
        <div>
          <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',marginBottom:14}}>
            <div style={{fontSize:13,color:'#6B6560'}}>Jeder Webhook-Versuch (Erfolg + Fehler) — aktualisiert sich alle 5 Sek. Letzte 500 Einträge.</div>
            <div style={{display:'flex',gap:6}}>
              <button className="btn btn-ghost btn-sm" onClick={loadLog}>↻ Aktualisieren</button>
              <button className="btn btn-ghost btn-sm" style={{color:'#dc2626'}} onClick={clearLog}>Leeren</button>
            </div>
          </div>
          {logEntries===null?(
            <div style={{textAlign:'center',padding:40,color:'#A8A39D'}}>Lade…</div>
          ):logEntries.length===0?(
            <div style={{background:'white',padding:'40px 24px',borderRadius:14,textAlign:'center',color:'#6B6560'}}>
              <div style={{fontSize:34,marginBottom:8}}>📋</div>
              <div style={{fontWeight:600,marginBottom:4}}>Noch keine Webhook-Versuche</div>
              <div style={{fontSize:13}}>Sobald jemand den Webhook aufruft erscheint hier ein Eintrag — auch fehlgeschlagene Versuche.</div>
            </div>
          ):(
            <div style={{background:'white',borderRadius:14,border:'1px solid rgba(0,0,0,.06)',overflow:'hidden'}}>
              {logEntries.map(e=>{
                const ok = e.status>=200 && e.status<300;
                const expanded = !!expandedLog[e.id];
                return (
                  <div key={e.id} style={{borderBottom:'1px solid rgba(0,0,0,.05)'}}>
                    <button onClick={()=>setExpandedLog(s=>({...s,[e.id]:!s[e.id]}))} style={{width:'100%',background:'none',border:'none',padding:'12px 16px',cursor:'pointer',textAlign:'left',display:'flex',alignItems:'center',gap:14}}>
                      <span style={{fontSize:11,fontWeight:700,padding:'2px 8px',borderRadius:99,background:ok?'rgba(34,197,94,.12)':'rgba(220,38,38,.12)',color:ok?'#16a34a':'#dc2626',minWidth:42,textAlign:'center'}}>{e.status}</span>
                      <span style={{fontSize:11.5,color:'#A8A39D',fontFamily:'ui-monospace,Menlo,monospace',minWidth:140}}>{new Date(e.ts).toLocaleString('de-AT')}</span>
                      <span style={{fontSize:13,fontWeight:500,color:'#5A554F',minWidth:140,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{e.slug||'(kein slug)'}</span>
                      <span style={{fontSize:12.5,color:ok?'#16a34a':'#dc2626',flex:1,minWidth:0,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{e.reason||(ok?'ok':'')}</span>
                      <span style={{fontSize:11,color:'#A8A39D'}}>{expanded?'▼':'▶'}</span>
                    </button>
                    {expanded&&(
                      <div style={{padding:'4px 16px 16px',background:'#FAFAF8',fontSize:12,color:'#5A554F',display:'grid',gap:6}}>
                        <div><strong>IP:</strong> <code>{e.source_ip||'?'}</code></div>
                        <div><strong>User-Agent:</strong> <code style={{wordBreak:'break-all'}}>{e.user_agent||'?'}</code></div>
                        <div><strong>Content-Type:</strong> <code>{e.content_type||'(leer)'}</code></div>
                        {e.body_preview&&(
                          <div>
                            <strong>Body (erste 1KB):</strong>
                            <pre style={{marginTop:4,padding:8,background:'#F5F3F0',borderRadius:6,fontSize:11.5,whiteSpace:'pre-wrap',wordBreak:'break-all',maxHeight:200,overflow:'auto'}}>{e.body_preview}</pre>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {tab==='archive'&&(
        <div>
          {archivedLeads.length===0?(
            <div style={{background:'white',padding:'40px 24px',borderRadius:14,textAlign:'center',color:'#6B6560'}}>Noch keine archivierten Leads.</div>
          ):(
            <div style={{display:'grid',gap:8}}>
              {archivedLeads.slice().reverse().map(l=>(
                <div key={l.id} style={{background:'white',padding:'12px 14px',borderRadius:10,border:'1px solid rgba(0,0,0,.06)',display:'flex',justifyContent:'space-between',alignItems:'center',gap:12}}>
                  <div style={{flex:1,minWidth:0}}>
                    <div style={{fontWeight:600,fontSize:14}}>{l.name||'(ohne Namen)'}</div>
                    <div style={{fontSize:12,color:'#A8A39D'}}>{l.campaign} · {l.status==='converted'?'→ als Kontakt übernommen':'verworfen'} · {new Date(l.importedAt).toLocaleDateString('de-AT')}</div>
                  </div>
                  <button className="btn btn-ghost btn-sm" style={{color:'#dc2626'}} onClick={()=>{if(window.confirm('Lead endgültig löschen?'))onUpdateLeads((leads||[]).filter(x=>x.id!==l.id));}}>Löschen</button>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Convert lead → contact modal */}
      {convert&&(
        <div className="modal-overlay" onClick={e=>e.target===e.currentTarget&&setConvert(null)}>
          <div className="modal-box" style={{width:460}}>
            <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:18}}>
              <div style={{fontWeight:700,fontSize:16}}>Lead → Kontakt</div>
              <button className="btn btn-ghost btn-sm btn-icon" onClick={()=>setConvert(null)}>✕</button>
            </div>
            <div style={{fontSize:13,color:'#6B6560',marginBottom:14}}>In welchen Bereich soll <strong>{convert.name||'(ohne Namen)'}</strong> übernommen werden?</div>
            <div style={{display:'grid',gap:8}}>
              {(sections||[]).map(s=>(
                <button key={s.id} className="btn btn-ghost" style={{justifyContent:'flex-start',padding:'12px 14px'}} onClick={()=>{onConvertLead(convert,s.id);setConvert(null);}}>
                  <span style={{marginRight:10}}>{s.icon}</span>{s.name}
                </button>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function VisualizationsView({items, onUpdate}) {
  const [showAdd, setShowAdd] = React.useState(false);
  const [form, setForm] = React.useState({name:'', url:'', note:''});
  const uid = () => Math.random().toString(36).slice(2,10);

  const save = () => {
    if (!form.name.trim() || !form.url.trim()) return;
    onUpdate([...items, {id: uid(), name: form.name.trim(), url: form.url.trim(), note: form.note.trim(), createdAt: new Date().toISOString()}]);
    setForm({name:'', url:'', note:''});
    setShowAdd(false);
  };

  return (
    <div style={{flex:1, overflow:'auto', background:'#F3F0EB'}}>
      <div style={{background:'white', borderBottom:'1px solid rgba(0,0,0,.07)', padding:'14px 28px', display:'flex', alignItems:'center', gap:14, flexShrink:0}}>
        <div style={{flex:1}}>
          <h1 style={{fontSize:18, fontWeight:800, letterSpacing:'-0.02em'}}>🖼️ Visualisierungen</h1>
          <div style={{fontSize:12, color:'#B0ABA5', marginTop:2}}>{items.length} {items.length===1?'Board':'Boards'} verlinkt</div>
        </div>
        <button className="btn btn-primary btn-sm" onClick={()=>setShowAdd(true)}>+ Hinzufügen</button>
      </div>

      <div style={{padding:'24px 28px'}}>
        {items.length === 0 && !showAdd && (
          <div style={{textAlign:'center', padding:'60px 0', color:'#B0ABA5'}}>
            <div style={{fontSize:40, marginBottom:12}}>🖼️</div>
            <div style={{fontSize:15, fontWeight:600, color:'#6B6560', marginBottom:6}}>Noch keine Visualisierungen</div>
            <div style={{fontSize:13, marginBottom:20}}>Figma-Boards, FigJam-Links oder andere URLs hier verlinken.</div>
            <button className="btn btn-primary btn-sm" onClick={()=>setShowAdd(true)}>Ersten Link hinzufügen</button>
          </div>
        )}

        <div style={{display:'grid', gridTemplateColumns:'repeat(auto-fill, minmax(300px, 1fr))', gap:16, marginBottom: showAdd?20:0}}>
          {items.map(item => (
            <div key={item.id} style={{background:'white', borderRadius:12, border:'1px solid rgba(0,0,0,.08)', padding:'18px 20px', display:'flex', flexDirection:'column', gap:10, position:'relative'}}>
              <div style={{display:'flex', alignItems:'flex-start', gap:12}}>
                <div style={{width:36, height:36, borderRadius:8, background:'#F3F0EB', display:'flex', alignItems:'center', justifyContent:'center', flexShrink:0, fontSize:18}}>
                  {item.url.includes('figma.com/board') ? '🗂️' : item.url.includes('figma.com') ? '🎨' : '🔗'}
                </div>
                <div style={{flex:1, minWidth:0}}>
                  <div style={{fontWeight:700, fontSize:14, color:'#141210', marginBottom:2, whiteSpace:'nowrap', overflow:'hidden', textOverflow:'ellipsis'}}>{item.name}</div>
                  <div style={{fontSize:11, color:'#B0ABA5', whiteSpace:'nowrap', overflow:'hidden', textOverflow:'ellipsis'}}>{item.url}</div>
                </div>
              </div>
              {item.note && <div style={{fontSize:12, color:'#6B6560', borderTop:'1px solid rgba(0,0,0,.06)', paddingTop:8}}>{item.note}</div>}
              <div style={{display:'flex', gap:8, marginTop:4}}>
                <a href={item.url} target="_blank" rel="noopener noreferrer" style={{flex:1, background:'#141210', color:'white', border:'none', borderRadius:8, padding:'8px 12px', fontSize:12, fontWeight:600, cursor:'pointer', textAlign:'center', textDecoration:'none', display:'block'}}>Öffnen →</a>
                <button onClick={()=>onUpdate(items.filter(x=>x.id!==item.id))} style={{background:'transparent', border:'1px solid #FECACA', color:'#C0392B', borderRadius:8, padding:'8px 10px', fontSize:12, cursor:'pointer'}}>✕</button>
              </div>
            </div>
          ))}
        </div>

        {showAdd && (
          <div style={{background:'white', borderRadius:12, border:'1px solid rgba(0,0,0,.08)', padding:'20px 22px', maxWidth:480}}>
            <div style={{fontWeight:700, fontSize:14, marginBottom:14}}>Neuen Link hinzufügen</div>
            <div style={{display:'flex', flexDirection:'column', gap:10}}>
              <input placeholder="Name (z.B. Cold Email Maschine)" value={form.name} onChange={e=>setForm(f=>({...f, name:e.target.value}))} style={{padding:'8px 12px', fontSize:13, border:'1.5px solid #E5E0DA', borderRadius:8, outline:'none'}}/>
              <input placeholder="URL (Figma, FigJam, ...)" value={form.url} onChange={e=>setForm(f=>({...f, url:e.target.value}))} style={{padding:'8px 12px', fontSize:13, border:'1.5px solid #E5E0DA', borderRadius:8, outline:'none'}}/>
              <input placeholder="Notiz (optional)" value={form.note} onChange={e=>setForm(f=>({...f, note:e.target.value}))} style={{padding:'8px 12px', fontSize:13, border:'1.5px solid #E5E0DA', borderRadius:8, outline:'none'}}/>
              <div style={{display:'flex', gap:8}}>
                <button className="btn btn-primary btn-sm" onClick={save} style={{flex:1}}>Speichern</button>
                <button className="btn btn-ghost btn-sm" onClick={()=>{setShowAdd(false);setForm({name:'',url:'',note:''});}}>Abbrechen</button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function GamificationView({onLoadData, onReset, onRescale}) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [showRanks, setShowRanks] = useState(false);
  const [weekGoal, setWeekGoal] = useState(() => parseInt(localStorage.getItem('gami_weekGoal')||'50'));
  const [editGoal, setEditGoal] = useState(false);
  const [goalInput, setGoalInput] = useState('50');
  const [resetting, setResetting] = useState(false);

  const load = async () => {
    try {
      const result = await onLoadData();
      setData(result || {daily:[], streak:0, weekTasks:0, weekEur:0, monthList:[]});
      setError('');
    } catch(e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, [onLoadData]);

  // Auto-refresh every 60s
  useEffect(() => {
    const t = setInterval(() => { onLoadData().then(r => { if(r) setData(r); }).catch(()=>{}); }, 60000);
    return () => clearInterval(t);
  }, [onLoadData]);

  if (loading) return <div style={{padding:'60px 28px',textAlign:'center',color:'#B0ABA5',fontSize:14}}>Laden...</div>;
  if (loading) return <div style={{padding:'60px 28px',textAlign:'center',color:'#B0ABA5',fontSize:14}}>Laden...</div>;
  if (error)   return <div style={{padding:'40px 28px',color:'#B45309'}}>Fehler: {error}</div>;

  const LEVELS = [
    {min:0,    num:1,  name:'Einsteiger',    icon:'🌱', color:'#6B7280'},
    {min:25,   num:2,  name:'Lehrling',      icon:'📚', color:'#10B981'},
    {min:75,   num:3,  name:'Geselle',       icon:'🔧', color:'#14B8A6'},
    {min:150,  num:4,  name:'Freelancer',    icon:'💻', color:'#3B82F6'},
    {min:300,  num:5,  name:'Profi',         icon:'⚡', color:'#6366F1'},
    {min:500,  num:6,  name:'Spezialist',    icon:'🎯', color:'#8B5CF6'},
    {min:750,  num:7,  name:'Expert',        icon:'🏆', color:'#A855F7'},
    {min:1000, num:8,  name:'Senior',        icon:'⭐', color:'#F59E0B'},
    {min:1500, num:9,  name:'Meister',       icon:'👑', color:'#EAB308'},
    {min:2000, num:10, name:'Unternehmer',   icon:'🚀', color:'#06B6D4'},
    {min:3000, num:11, name:'Stratege',      icon:'🧠', color:'#0891B2'},
    {min:5000, num:12, name:'Visionaer',     icon:'💎', color:'#059669'},
    {min:7500, num:13, name:'Innovator',     icon:'🌟', color:'#10B981'},
    {min:10000,num:14, name:'Marktfuehrer',  icon:'🔥', color:'#F97316'},
    {min:15000,num:15, name:'Legende',       icon:'🌈', color:'#EC4899'},
  ];

  const daily      = (data?.daily || []).slice().sort((a,b) => new Date(b.date)-new Date(a.date));
  const totalTasks = daily.reduce((s,d) => s+d.count, 0);
  const totalEur   = daily.reduce((s,d) => s+Number(d.eur), 0);
  const bestDay    = daily.reduce((best,d) => d.count > best.count ? d : best, {count:0,eur:0,date:''});
  const streak     = data?.streak || 0;
  const weekTasks  = data?.weekTasks || 0;
  const weekEur    = data?.weekEur || 0;
  const monthList  = data?.monthList || [];

  const now        = new Date();
  const todayStr   = now.toISOString().split('T')[0];
  const todayEntry = daily.find(d => d.date === todayStr) || {count:0,eur:0};
  const curMonth   = todayStr.slice(0,7);
  const monthDays  = daily.filter(d => d.date?.startsWith(curMonth));
  const monthTasks = monthDays.reduce((s,d) => s+d.count, 0);
  const monthEur   = monthDays.reduce((s,d) => s+Number(d.eur), 0);

  let curLevel = LEVELS[0];
  for (const l of LEVELS) { if (totalTasks >= l.min) curLevel = l; }
  const nextLevel = LEVELS.find(l => l.num === curLevel.num + 1);
  const levelPct  = nextLevel ? Math.min(100,Math.round(((totalTasks-curLevel.min)/(nextLevel.min-curLevel.min))*100)) : 100;

  const last7 = [];
  for (let i=6; i>=0; i--) {
    const d = new Date(now); d.setDate(d.getDate()-i);
    const key = d.toISOString().split('T')[0];
    last7.push({...(daily.find(x=>x.date===key)||{count:0,eur:0,date:key}), label:['So','Mo','Di','Mi','Do','Fr','Sa'][d.getDay()]});
  }
  const maxCount = Math.max(...last7.map(d=>d.count), 1);

  const weekPct   = Math.min(100, Math.round((weekTasks/weekGoal)*100));
  const monthName = ['Januar','Februar','März','April','Mai','Juni','Juli','August','September','Oktober','November','Dezember'][now.getMonth()];
  const MONTH_NAMES = ['Jan','Feb','Mär','Apr','Mai','Jun','Jul','Aug','Sep','Okt','Nov','Dez'];

  const motivations = [
    [0,  "Leg los — jeder Task bringt dich weiter!"],
    [1,  "Guter Start! Der Momentum baut sich auf."],
    [3,  "3 Tage am Stück — du bleibst dran!"],
    [7,  "Eine Woche Streak — beeindruckend!"],
    [14, "2 Wochen täglich — das ist echte Disziplin!"],
    [30, "30-Tage-Streak — Legende am Werk!"],
  ];
  const motivText = motivations.slice().reverse().find(([d]) => streak >= d)?.[1] || '';

  const Card = ({label, value, sub, color, accent, extra}) => (
    <div style={{background:'white',borderRadius:12,padding:'16px 20px',border:`1.5px solid ${accent||'rgba(0,0,0,.07)'}`,flex:1,minWidth:130,position:'relative',overflow:'hidden'}}>
      <div style={{position:'absolute',top:0,left:0,right:0,height:3,background:color||'#10B981',borderRadius:'12px 12px 0 0'}}/>
      <div style={{fontSize:10,fontWeight:600,color:'#A8A39D',letterSpacing:'.05em',textTransform:'uppercase',marginBottom:5}}>{label}</div>
      <div style={{fontSize:24,fontWeight:800,color:color||'#141210',letterSpacing:'-0.03em',lineHeight:1}}>{value}</div>
      {sub   && <div style={{fontSize:11,color:'#6B7280',marginTop:4,fontWeight:500}}>{sub}</div>}
      {extra && extra}
    </div>
  );

  return (
    <div style={{flex:1,overflow:'auto',padding:'20px 28px',background:'#F0FDF4'}}>

      {/* Rang-Modal */}
      {showRanks && (
        <div style={{position:'fixed',inset:0,background:'rgba(0,0,0,.5)',zIndex:1000,display:'flex',alignItems:'center',justifyContent:'center'}} onClick={()=>setShowRanks(false)}>
          <div style={{background:'white',borderRadius:18,padding:'24px 28px',width:480,maxWidth:'92vw',maxHeight:'88vh',overflow:'auto',boxShadow:'0 24px 80px rgba(0,0,0,.3)'}} onClick={e=>e.stopPropagation()}>
            <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',marginBottom:20}}>
              <div style={{fontSize:16,fontWeight:800,color:'#141210'}}>Alle 15 Ränge</div>
              <button onClick={()=>setShowRanks(false)} style={{background:'#F3F4F6',border:'none',borderRadius:8,width:28,height:28,cursor:'pointer',fontSize:15,color:'#6B7280'}}>×</button>
            </div>
            {LEVELS.map(l => {
              const isActive = l.num === curLevel.num;
              const isDone   = totalTasks >= l.min;
              const nxt      = LEVELS.find(x=>x.num===l.num+1);
              const pct      = (isActive && nxt) ? Math.min(100,Math.round(((totalTasks-l.min)/(nxt.min-l.min))*100)) : 0;
              return (
                <div key={l.num} style={{display:'flex',alignItems:'center',gap:12,padding:'10px 14px',borderRadius:10,marginBottom:4,background:isActive?`${l.color}12`:'transparent',border:isActive?`1.5px solid ${l.color}35`:'1.5px solid transparent'}}>
                  <div style={{width:40,height:40,borderRadius:'50%',background:isDone?`linear-gradient(135deg,${l.color},${l.color}bb)`:'#E5E7EB',display:'flex',alignItems:'center',justifyContent:'center',fontSize:18,flexShrink:0,boxShadow:isDone?`0 2px 10px ${l.color}40`:'none'}}>
                    {isDone ? l.icon : '🔒'}
                  </div>
                  <div style={{flex:1,minWidth:0}}>
                    <div style={{display:'flex',alignItems:'center',gap:7,marginBottom:2}}>
                      <span style={{fontSize:10,fontWeight:700,color:isDone?l.color:'#9CA3AF',letterSpacing:'.05em',textTransform:'uppercase'}}>Lvl {l.num}</span>
                      <span style={{fontSize:13,fontWeight:700,color:isDone?'#141210':'#9CA3AF'}}>{l.name}</span>
                      {isActive && <span style={{fontSize:9,fontWeight:700,background:l.color,color:'white',padding:'1px 6px',borderRadius:99}}>JETZT</span>}
                    </div>
                    <div style={{fontSize:10,color:'#9CA3AF'}}>{l.min===0?'Start':(`ab ${l.min.toLocaleString()} Tasks`)}{nxt?` · bis ${nxt.min.toLocaleString()}`:'· Maximalstufe'}</div>
                    {isActive && nxt && <div style={{height:3,background:'#E5E7EB',borderRadius:99,overflow:'hidden',marginTop:4}}><div style={{height:'100%',width:`${pct}%`,background:`linear-gradient(90deg,${l.color},${nxt.color})`,borderRadius:99}}/></div>}
                  </div>
                  <div style={{fontSize:12,fontWeight:800,color:isDone?l.color:'#D1D5DB',flexShrink:0,minWidth:36,textAlign:'right'}}>
                    {isDone ? (isActive&&nxt?`${pct}%`:'✓') : l.min.toLocaleString()}
                  </div>
                </div>
              );
            })}
            <div style={{marginTop:16,padding:'12px 14px',background:'#F0FDF4',borderRadius:10,fontSize:11,color:'#6B7280',textAlign:'center'}}>
              Du hast <strong style={{color:'#059669'}}>{totalTasks.toLocaleString()}</strong> Tasks insgesamt · {nextLevel ? `noch ${(nextLevel.min-totalTasks).toLocaleString()} bis ${nextLevel.icon} ${nextLevel.name}` : 'Maximalstufe erreicht!'}
            </div>
          </div>
        </div>
      )}

      {/* Level Hero */}
      <div onClick={()=>setShowRanks(true)} style={{background:`linear-gradient(135deg,${curLevel.color}1a 0%,${curLevel.color}08 100%)`,border:`1.5px solid ${curLevel.color}40`,borderRadius:16,padding:'18px 22px',marginBottom:16,display:'flex',alignItems:'center',gap:18,cursor:'pointer',transition:'transform .12s,box-shadow .12s'}}
        onMouseEnter={e=>{e.currentTarget.style.transform='translateY(-2px)';e.currentTarget.style.boxShadow=`0 10px 32px ${curLevel.color}25`;}}
        onMouseLeave={e=>{e.currentTarget.style.transform='';e.currentTarget.style.boxShadow='';}}>
        <div style={{width:64,height:64,borderRadius:'50%',background:`linear-gradient(135deg,${curLevel.color},${curLevel.color}cc)`,display:'flex',alignItems:'center',justifyContent:'center',fontSize:26,flexShrink:0,boxShadow:`0 6px 22px ${curLevel.color}55`}}>
          {curLevel.icon}
        </div>
        <div style={{flex:1}}>
          <div style={{display:'flex',alignItems:'center',gap:10,marginBottom:4}}>
            <span style={{fontSize:10,fontWeight:700,color:curLevel.color,letterSpacing:'.08em',textTransform:'uppercase',background:`${curLevel.color}18`,padding:'2px 8px',borderRadius:99}}>Level {curLevel.num} / 15</span>
            <span style={{fontSize:18,fontWeight:800,color:'#141210'}}>{curLevel.name}</span>
          </div>
          {nextLevel ? (
            <>
              <div style={{height:7,background:'rgba(0,0,0,.08)',borderRadius:99,overflow:'hidden',marginBottom:4}}>
                <div style={{height:'100%',width:`${levelPct}%`,background:`linear-gradient(90deg,${curLevel.color},${nextLevel.color})`,borderRadius:99,transition:'width .5s'}}/>
              </div>
              <div style={{fontSize:11,color:'#6B7280'}}>{totalTasks.toLocaleString()} / {nextLevel.min.toLocaleString()} · noch <strong style={{color:nextLevel.color}}>{(nextLevel.min-totalTasks).toLocaleString()} Tasks</strong> bis {nextLevel.icon} {nextLevel.name} <span style={{color:'#B0ABA5',fontSize:10}}>· klicken für alle Ränge</span></div>
            </>
          ) : <div style={{fontSize:12,color:curLevel.color,fontWeight:700}}>Maximalstufe erreicht!</div>}
        </div>
        <div style={{textAlign:'right',flexShrink:0}}>
          <div style={{fontSize:28,fontWeight:900,color:curLevel.color,letterSpacing:'-0.03em',lineHeight:1}}>€ {totalEur.toFixed(0)}</div>
          <div style={{fontSize:10,color:'#6B7280',marginTop:2}}>gesamt verdient</div>
        </div>
      </div>

      {/* Streak + Motivationstext */}
      {(streak > 0 || motivText) && (
        <div style={{background:`linear-gradient(135deg,#FFF7ED,#FFFBEB)`,border:'1.5px solid #FED7AA',borderRadius:12,padding:'12px 18px',marginBottom:16,display:'flex',alignItems:'center',gap:14}}>
          <div style={{fontSize:28,lineHeight:1}}>{streak>=7?'🔥':streak>=3?'✨':'⚡'}</div>
          <div>
            <div style={{fontSize:13,fontWeight:700,color:'#92400E'}}>{streak} Tag{streak!==1?'e':''} Streak{streak>=7?' — absolut heiss!':streak>=3?' — du bist auf Kurs!':''}</div>
            {motivText && <div style={{fontSize:11,color:'#B45309',marginTop:2}}>{motivText}</div>}
          </div>
          <div style={{marginLeft:'auto',textAlign:'right'}}>
            <div style={{fontSize:22,fontWeight:900,color:'#F59E0B'}}>{streak}</div>
            <div style={{fontSize:10,color:'#B45309'}}>Tage</div>
          </div>
        </div>
      )}

      {/* Stat Cards */}
      <div style={{display:'flex',gap:10,marginBottom:16,flexWrap:'wrap'}}>
        <Card label="Heute" value={todayEntry.count} sub={`€ ${Number(todayEntry.eur).toFixed(2)}`} color="#10B981" accent="rgba(16,185,129,.2)"/>
        <Card label={monthName} value={monthTasks} sub={`€ ${monthEur.toFixed(2)}`} color="#3B82F6" accent="rgba(59,130,246,.15)"/>
        <Card label="Rekordtag" value={bestDay.count||'–'} sub={bestDay.date?new Date(bestDay.date).toLocaleDateString('de-AT',{day:'2-digit',month:'2-digit'}):'–'} color="#F59E0B" accent="rgba(245,158,11,.15)"/>
        <Card label="Gesamt" value={totalTasks.toLocaleString()} sub={`${curLevel.icon} ${curLevel.name}`} color={curLevel.color} accent={`${curLevel.color}25`}/>
      </div>

      {/* Wochenziel */}
      <div style={{background:'white',borderRadius:12,padding:'16px 20px',marginBottom:16,border:'1px solid rgba(16,185,129,.15)'}}>
        <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',marginBottom:10}}>
          <div style={{fontSize:13,fontWeight:700,color:'#141210'}}>Wochenziel</div>
          <div style={{display:'flex',alignItems:'center',gap:8}}>
            {editGoal ? (
              <>
                <input type="number" value={goalInput} onChange={e=>setGoalInput(e.target.value)} style={{width:70,padding:'4px 8px',fontSize:12,border:'1.5px solid #10B981',borderRadius:6,outline:'none'}} onKeyDown={e=>{if(e.key==='Enter'){const v=Math.max(1,parseInt(goalInput)||50);setWeekGoal(v);localStorage.setItem('gami_weekGoal',v);setEditGoal(false);}}}/>
                <button onClick={()=>{const v=Math.max(1,parseInt(goalInput)||50);setWeekGoal(v);localStorage.setItem('gami_weekGoal',v);setEditGoal(false);}} style={{background:'#10B981',color:'white',border:'none',borderRadius:6,padding:'4px 10px',fontSize:12,cursor:'pointer',fontWeight:600}}>OK</button>
              </>
            ) : (
              <button onClick={()=>{setGoalInput(String(weekGoal));setEditGoal(true);}} style={{background:'transparent',border:'1px solid #D1FAE5',color:'#6B7280',borderRadius:6,padding:'3px 9px',fontSize:11,cursor:'pointer'}}>Ziel: {weekGoal} Tasks</button>
            )}
          </div>
        </div>
        <div style={{display:'flex',alignItems:'center',gap:12}}>
          <div style={{flex:1}}>
            <div style={{height:10,background:'#D1FAE5',borderRadius:99,overflow:'hidden'}}>
              <div style={{height:'100%',width:`${weekPct}%`,background:weekPct>=100?`linear-gradient(90deg,#10B981,#059669)`:`linear-gradient(90deg,#34D399,#10B981)`,borderRadius:99,transition:'width .4s'}}/>
            </div>
          </div>
          <div style={{fontSize:13,fontWeight:700,color:weekPct>=100?'#059669':'#141210',flexShrink:0}}>
            {weekTasks} / {weekGoal}
            {weekPct>=100 && <span style={{marginLeft:6,fontSize:11,background:'#ECFDF5',color:'#059669',padding:'1px 7px',borderRadius:99,border:'1px solid #6EE7B7'}}>ZIEL ERREICHT!</span>}
          </div>
        </div>
        <div style={{fontSize:11,color:'#6B7280',marginTop:6}}>€ {weekEur.toFixed(2)} diese Woche · {weekPct<100?`noch ${weekGoal-weekTasks} Tasks bis zum Ziel`:'Wochenziel geschafft!'}</div>
      </div>

      {/* 7-Tage Balken */}
      <div style={{background:'white',borderRadius:12,padding:'16px 20px',marginBottom:16,border:'1px solid rgba(16,185,129,.15)'}}>
        <div style={{fontSize:13,fontWeight:700,color:'#141210',marginBottom:14}}>Letzte 7 Tage</div>
        <div style={{display:'flex',gap:6,alignItems:'flex-end',height:110}}>
          {last7.map(d => {
            const isToday = d.date === todayStr;
            const barH = Math.max((d.count/maxCount)*88, d.count>0?10:3);
            return (
              <div key={d.date} style={{flex:1,display:'flex',flexDirection:'column',alignItems:'center',gap:3}}>
                {d.count>0 && <div style={{fontSize:10,fontWeight:700,color:isToday?'#059669':'#6B7280'}}>{d.count}</div>}
                <div style={{width:'100%',height:88,display:'flex',alignItems:'flex-end'}}>
                  <div style={{width:'100%',height:barH,background:isToday?'linear-gradient(180deg,#10B981,#059669)':d.count>0?'#6EE7B7':'#D1FAE5',borderRadius:'4px 4px 2px 2px',transition:'height .3s',boxShadow:isToday?'0 2px 8px rgba(16,185,129,.5)':'none'}}/>
                </div>
                <div style={{fontSize:11,fontWeight:isToday?700:400,color:isToday?'#059669':'#9CA3AF'}}>{d.label}</div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Monatsvergleich */}
      {monthList.length > 1 && (
        <div style={{background:'white',borderRadius:12,padding:'16px 20px',marginBottom:16,border:'1px solid rgba(16,185,129,.15)'}}>
          <div style={{fontSize:13,fontWeight:700,color:'#141210',marginBottom:14}}>Monatsvergleich</div>
          <div style={{display:'flex',gap:16,alignItems:'flex-end'}}>
            {monthList.map((m,i) => {
              const maxT = Math.max(...monthList.map(x=>x.tasks),1);
              const barH = Math.max((m.tasks/maxT)*80,m.tasks>0?8:3);
              const isThis = m.month===curMonth;
              const [yr,mo] = m.month.split('-');
              return (
                <div key={m.month} style={{flex:1,display:'flex',flexDirection:'column',alignItems:'center',gap:4}}>
                  {m.tasks>0 && <div style={{fontSize:11,fontWeight:700,color:isThis?'#059669':'#6B7280'}}>{m.tasks}</div>}
                  <div style={{width:'100%',height:80,display:'flex',alignItems:'flex-end'}}>
                    <div style={{width:'100%',height:barH,background:isThis?'linear-gradient(180deg,#10B981,#059669)':'#A7F3D0',borderRadius:'5px 5px 2px 2px'}}/>
                  </div>
                  <div style={{fontSize:11,fontWeight:isThis?700:400,color:isThis?'#059669':'#6B7280'}}>{MONTH_NAMES[parseInt(mo,10)-1]}</div>
                  <div style={{fontSize:10,color:'#9CA3AF'}}>€ {m.eur.toFixed(0)}</div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Verlaufstabelle + Reset */}
      <div style={{background:'white',borderRadius:12,overflow:'hidden',border:'1px solid rgba(16,185,129,.15)'}}>
        <div style={{padding:'12px 20px',borderBottom:'1px solid rgba(0,0,0,.06)',display:'flex',alignItems:'center',justifyContent:'space-between'}}>
          <span style={{fontSize:13,fontWeight:700,color:'#141210'}}>Verlauf</span>
        </div>
        {daily.length === 0 ? (
          <div style={{padding:'28px 20px',textAlign:'center',color:'#B0ABA5',fontSize:13}}>Noch keine Daten — der nächste Task füllt das hier.</div>
        ) : (
          <table style={{width:'100%',borderCollapse:'collapse'}}>
            <thead>
              <tr style={{background:'#F0FDF4'}}>
                <th style={{padding:'9px 20px',textAlign:'left',fontSize:10,fontWeight:600,color:'#6B7280',letterSpacing:'.05em',textTransform:'uppercase'}}>Datum</th>
                <th style={{padding:'9px 20px',textAlign:'right',fontSize:10,fontWeight:600,color:'#6B7280',letterSpacing:'.05em',textTransform:'uppercase'}}>Tasks</th>
                <th style={{padding:'9px 20px',textAlign:'right',fontSize:10,fontWeight:600,color:'#6B7280',letterSpacing:'.05em',textTransform:'uppercase'}}>EUR</th>
                <th style={{padding:'9px 20px',width:100}}/>
              </tr>
            </thead>
            <tbody>
              {daily.map(entry => {
                const isToday = entry.date===todayStr;
                const isBest  = entry.count>0 && entry.count===bestDay.count;
                const pct     = Math.min(100,Math.round((entry.count/(bestDay.count||1))*100));
                return (
                  <tr key={entry.date} style={{borderTop:'1px solid rgba(0,0,0,.04)',background:isToday?'#F0FDF4':'white'}}>
                    <td style={{padding:'11px 20px',fontSize:13,color:'#141210',fontWeight:isToday?700:400}}>
                      {isToday?'Heute':new Date(entry.date).toLocaleDateString('de-AT',{weekday:'short',day:'2-digit',month:'2-digit'})}
                      {isBest&&<span style={{marginLeft:7,fontSize:10,background:'#ECFDF5',color:'#059669',padding:'2px 7px',borderRadius:99,fontWeight:700,border:'1px solid #6EE7B7'}}>REKORD</span>}
                    </td>
                    <td style={{padding:'11px 20px',textAlign:'right',fontSize:13,fontWeight:700,color:isToday?'#059669':'#141210'}}>{entry.count}</td>
                    <td style={{padding:'11px 20px',textAlign:'right',fontSize:13,fontWeight:600,color:'#10B981'}}>€ {Number(entry.eur).toFixed(2)}</td>
                    <td style={{padding:'11px 20px'}}>
                      <div style={{height:5,background:'#D1FAE5',borderRadius:99,overflow:'hidden'}}>
                        <div style={{height:'100%',width:`${pct}%`,background:isToday?'#10B981':'#34D399',borderRadius:99}}/>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

function CRMApp({cryptoKey, initialData, onLock, onLogout}) {
  const [state,setState]=useState(()=>({
    ...initialData,
    sections: initialData.sections || DEFAULT_SECTIONS,
    subsections: initialData.subsections || DEFAULT_SUBSECTIONS,
    customFields: initialData.customFields || [],
    members: initialData.members || [],
    todos: initialData.todos || [],
    aiEmployees: initialData.aiEmployees || [],
    claudeAccounts: initialData.claudeAccounts || [],
    claudeTasks: initialData.claudeTasks || [],
    quotes: (()=>{
      const existing=(initialData.quotes||[]).filter(q=>q.id!=='seed-constanze-quote-v1');
      if(existing.some(q=>q.id==='seed-constanze-quote-v2'))return existing;
      const qItems=[
        {id:'sq-h1',type:'heading',description:'Website fotostube.at',quantity:1,unitPrice:0},
        {id:'sq-i1',type:'item',description:'One Pager — Design & Entwicklung\nHauptseite mit vollständigem Layout, Animationen, mobiloptimiert, Next.js',quantity:1,unitPrice:700},
        {id:'sq-i2',type:'item',description:'6 Projekt-Unterseiten\nJe eine Seite pro Projekt — einheitliches Design, Galerie, Projektbeschreibung',quantity:6,unitPrice:100},
        {id:'sq-i3',type:'item',description:'Grundlegende SEO\nMeta-Tags, Sitemap, Google Search Console, Alt-Texte, Ladegeschwindigkeit',quantity:1,unitPrice:100},
        {id:'sq-i4',type:'item',description:'Zufriedenheitsgarantie\nWir überarbeiten so lange bis du zu 100% zufrieden bist — ohne Aufpreis',quantity:1,unitPrice:0},
      ];
      return [...existing,{
        id:'seed-constanze-quote-v2',
        number:'AN-2026-001',
        status:'entwurf',
        contactId:null,
        contactSnapshot:{firma:'Constanze Trzebin',ansprechpartner:'Constanze Trzebin',email:'',telefon:'',adresse:'Wien'},
        title:'Neue Website fotostube.at',
        date:'2026-05-18',
        validUntil:'2026-06-01',
        intro:'Liebe Constanze,\n\nvielen Dank für unser angenehmes Gespräch heute. Es hat mich gefreut, dich besser kennenzulernen — und ich bin überzeugt, dass wir zusammen etwas wirklich Besonderes für fotostube.at schaffen können.\n\nHier ist mein Angebot für deine neue Website.',
        items:qItems,
        taxRate:20,
        discount:0,
        notes:'Zufriedenheitsgarantie: Überarbeitungen bis zur vollständigen Zufriedenheit inklusive.\nHosting & Domain nicht inkludiert (auf Wunsch Empfehlung möglich).',
        terms:'Angebot gültig bis 01.06.2026 — damit ich die Planung fixieren kann.\nZahlung: 50% bei Auftragserteilung, 50% bei Projektabschluss.\nAlle Preise zzgl. 20% USt.',
        footer:'Ich freue mich auf eine erfolgreiche Zusammenarbeit und bin überzeugt, dass deine neue Website genauso hochwertig wird wie deine Fotos.',
        nextSteps:'1. Angebot bis 01.06.2026 annehmen — damit ich die Planung fixieren kann.\n2. Nach deiner Zusage: Anzahlung (50%) + kurzes Kick-off-Gespräch (30 min).\n3. Projektstart nach Absprache — Fertigstellung in ca. 3–4 Wochen.',
        sentAt:null,
        createdAt:'2026-05-18T08:00:00.000Z',
      }];
    })(),
    quoteSettings: {...DEFAULT_QUOTE_SETTINGS, ...(initialData.quoteSettings||{})},
    invoices: initialData.invoices || [],
    invoiceSettings: {...DEFAULT_INVOICE_SETTINGS,...(initialData.invoiceSettings||{})},
    tokens: initialData.tokens || [],
    forms: initialData.forms && initialData.forms.length ? initialData.forms : [DEFAULT_ONBOARDING_FORM],
    formResponses: initialData.formResponses || [],
    campaigns: (()=>{
      const base=(initialData.campaigns||[]).filter(c=>c.id!=='seed-verkauf-v1');
      if(base.some(c=>c.id==='seed-verkauf-v2'))return base;
      const blocks=[
        {id:'sv2-b1',type:'h1',content:'Constanze Trzebin — Verkaufsskript',language:'js',caption:''},
        {id:'sv2-b2',type:'text',content:'BNI-Kontakt · fotostube.at · Fotografin (Family/Portrait) · WordPress\nZiel: Auftrag direkt im Call abschließen. Rahmen: Schmerz → Kosten → Dringlichkeit → Lösung → Abschluss.',language:'js',caption:''},
        {id:'sv2-b3',type:'divider',content:'',language:'js',caption:''},
        {id:'sv2-b4',type:'h2',content:'Vor dem Call',language:'js',caption:''},
        {id:'sv2-b5',type:'bullet',content:'Rebranding-Tool bereit: webars-rebranding-tool.vercel.app',language:'js',caption:''},
        {id:'sv2-b6',type:'bullet',content:'Ihre Instagram/Website kurz anschauen — 1 konkretes Detail merken',language:'js',caption:''},
        {id:'sv2-b7',type:'bullet',content:'Konkretes Startdatum im Kopf haben',language:'js',caption:''},
        {id:'sv2-b8',type:'divider',content:'',language:'js',caption:''},
        {id:'sv2-b9',type:'h2',content:'Phase 1 — Aufwärmen & Sympathie (2–3 min)',language:'js',caption:''},
        {id:'sv2-b10',type:'text',content:'»Constanze, schön dass wir uns Zeit nehmen. Ich hab mir vorher nochmal deine Website angesehen — deine Bilder sind wirklich außergewöhnlich, das [konkretes Detail] hat mich sofort angesprochen.«\n→ kurze Reaktion, dann: »Wie läuft\'s bei dir gerade — viel zu tun mit dem Frühjahr?«',language:'js',caption:''},
        {id:'sv2-b11',type:'h2',content:'Phase 2 — Übergang (erstes kleines Ja holen)',language:'js',caption:''},
        {id:'sv2-b12',type:'text',content:'»Ich hab übrigens kurz nachgedacht bevor wir telefoniert haben — ich glaube ich weiß schon ungefähr wo der Schuh drückt, aber ich will das lieber von dir hören. Darf ich dir ein paar Fragen stellen?«\n→ Sie sagt Ja. Erstes Commitment.',language:'js',caption:''},
        {id:'sv2-b13',type:'h2',content:'Phase 3 — Discovery (Was fehlt?)',language:'js',caption:''},
        {id:'sv2-b14',type:'bullet',content:'»Was nervt dich am meisten an deiner Online-Präsenz?« → »Was noch?«',language:'js',caption:''},
        {id:'sv2-b15',type:'bullet',content:'»Zeigt deine Website wirklich wer du bist — oder ist es ein Kompromiss?«',language:'js',caption:''},
        {id:'sv2-b16',type:'bullet',content:'»Was hat dich bisher davon abgehalten, das zu ändern?«',language:'js',caption:''},
        {id:'sv2-b17',type:'h2',content:'Phase 4 — SCHMERZ VERTIEFEN (entscheidend)',language:'js',caption:''},
        {id:'sv2-b18',type:'text',content:'»Wenn du dir vorstellst, eine Wunschkundin kommt auf deine Website — jemand der genau zu dir passt und auch das Budget hat. Was glaubst du, was passiert wenn der erste Eindruck nicht stimmt?«\n→ Pause. Sie antwortet.',language:'js',caption:''},
        {id:'sv2-b19',type:'text',content:'»Und wie oft passiert das deiner Meinung nach gerade — pro Monat?«\n→ Sie schätzt eine Zahl.',language:'js',caption:''},
        {id:'sv2-b20',type:'text',content:'»Also wenn wir sagen [ihre Zahl] Anfragen gehen verloren — was wäre das ungefähr in Euro pro Monat?«\n→ Sie rechnet selbst. Dann: »Seit wann ist das so?« → sie multipliziert selbst.',language:'js',caption:''},
        {id:'sv2-b21',type:'h2',content:'Phase 5 — DRINGLICHKEIT',language:'js',caption:''},
        {id:'sv2-b22',type:'text',content:'»Was passiert wenn du das noch 6 Monate so lässt — ändert sich irgendetwas von selbst?«\n→ Sie sagt Nein.\n»Genau. Andere Fotografinnen in Wien investieren gerade massiv in ihre Online-Präsenz.«',language:'js',caption:''},
        {id:'sv2-b23',type:'text',content:'»Ich arbeite übrigens gerade mit [Anzahl] Projekten — ich nehme bewusst nicht zu viele auf einmal, weil ich lieber wirklich gute Arbeit abliefere. Deshalb wollte ich heute auch schauen ob wir zusammenpassen.«\n→ Knappheit ohne Druck.',language:'js',caption:''},
        {id:'sv2-b24',type:'h2',content:'Phase 6 — Budget (Anchoring)',language:'js',caption:''},
        {id:'sv2-b25',type:'text',content:'»Für Websites auf diesem Level — hochwertige Fotografie-Websites die auch konvertieren — liegt man oft bei 3.000–5.000 €. Ich arbeite etwas darunter, weil mir BNI-Kontakte wichtig sind. Wo fühlst du dich wohl?«\n→ Sie hört 3.000–5.000, dein Preis wirkt günstig.',language:'js',caption:''},
        {id:'sv2-b26',type:'h2',content:'Phase 7 — Tool zeigen',language:'js',caption:''},
        {id:'sv2-b27',type:'text',content:'webars-rebranding-tool.vercel.app teilen\n»Welche Richtung spricht dich sofort an?« → »Warum genau diese?« (Wortwahl merken für Angebot!)',language:'js',caption:''},
        {id:'sv2-b28',type:'h2',content:'Phase 8 — Angebot (ihre eigenen Worte)',language:'js',caption:''},
        {id:'sv2-b29',type:'text',content:'»Basierend auf allem was du mir erzählt hast — du verlierst [Zahl] Kundinnen/Monat, du willst dass die Website genauso hochwertig wirkt wie deine Fotos, und die Richtung die dich angesprochen hat ist [Richtung].\nNeue Website, komplett neu designed. Investition: [Betrag]. 50% jetzt, 50% wenn du zufrieden bist. Start [Datum], fertig in 3–4 Wochen.«',language:'js',caption:''},
        {id:'sv2-b30',type:'h2',content:'Phase 9 — STILLE AUSHALTEN',language:'js',caption:''},
        {id:'sv2-b31',type:'text',content:'Nach dem Angebot: MUND HALTEN. Nicht erklären. Nicht rechtfertigen.\nWer zuerst redet, verliert.',language:'js',caption:''},
        {id:'sv2-b32',type:'h2',content:'Phase 10 — Abschluss & Einwände',language:'js',caption:''},
        {id:'sv2-b33',type:'bullet',content:'Ja → »Ich schick dir heute noch die Anzahlung (50%) + Projektplan. Start wäre [Datum] — passt das?«',language:'js',caption:''},
        {id:'sv2-b34',type:'bullet',content:'»Ich muss drüber nachdenken« → »Was genau ist noch unklar für dich?«',language:'js',caption:''},
        {id:'sv2-b35',type:'bullet',content:'»Zu teuer« → »Was wäre ein Betrag der sich für dich richtig anfühlt?«',language:'js',caption:''},
        {id:'sv2-b36',type:'bullet',content:'»Muss Partner fragen« → »Was braucht er noch um Ja sagen zu können? Ich schick dir kurz eine Zusammenfassung.«',language:'js',caption:''},
        {id:'sv2-b37',type:'bullet',content:'»Andere Angebote« → »Was ist dir dabei am wichtigsten — Preis, Tempo, oder dass jemand wirklich Fotografinnen versteht?«',language:'js',caption:''},
        {id:'sv2-b38',type:'divider',content:'',language:'js',caption:''},
        {id:'sv2-b39',type:'h2',content:'Notizen nach dem Call',language:'js',caption:''},
        {id:'sv2-b40',type:'text',content:'Datum: \nBudget-Rahmen: \nRichtung gewählt: \nGeschätzte verlorene Anfragen/Monat: \nEinwände: \nNächster Step: \nAnzahlung gesendet: ☐',language:'js',caption:''},
      ];
      return [{id:'seed-verkauf-v2',name:'Verkauf',emoji:'💼',color:'#10b981',createdAt:'2026-05-18T00:00:00.000Z',files:[{id:'seed-constanze-v2',name:'Constanze Trzebin — Verkaufsskript',content:JSON.stringify(blocks),updatedAt:'2026-05-18T00:00:00.000Z'}]},...base];
    })(),
    leads: initialData.leads || [],
    coldCampaigns: initialData.coldCampaigns || [],
    visualizations: initialData.visualizations || [],
  }));
  const TODOS_VIEW = '__todos__';
  const AI_VIEW = '__ai__';
  const CLAUDE_VIEW = '__claude__';
  const QUOTES_VIEW = '__quotes__';
  const INVOICES_VIEW = '__invoices__';
  const TOKENS_VIEW = '__tokens__';
  const FORMS_VIEW = '__forms__';
  const CAMPAIGNS_VIEW = '__campaigns__';
  const LEADS_VIEW = '__leads__';
  const COLD_OUTREACH_VIEW = '__cold_outreach__';
  const GAMIFICATION_VIEW = '__gamification__';
  const VISUALIZATIONS_VIEW = '__visualizations__';
  const [activeId,setActiveId]=useState((initialData.sections||DEFAULT_SECTIONS)[0]?.id);
  const [activeSubId,setActiveSubId]=useState(null);
  const [search,setSearch]=useState('');
  const [statusFilter,setStatusFilter]=useState('');
  const [modal,setModal]=useState(null);
  const [selected,setSelected]=useState(null);
  const [locked,setLocked]=useState(false);
  const [syncTick,setSyncTick]=useState(0);
  const [cloudConnected,setCloudConnected]=useState(hasGithubSettings());
  const lastActivityRef=useRef(Date.now());
  const skipNextSaveRef=useRef(false);
  const [editingQuote,setEditingQuote]=useState(null);
  const [previewQuote,setPreviewQuote]=useState(null);
  const [editingInvoice,setEditingInvoice]=useState(null);
  const [previewInvoice,setPreviewInvoice]=useState(null);
  const [mahnungInvoice,setMahnungInvoice]=useState(null);
  const [jarvisDraft,setJarvisDraft]=useState(null);

  // Deep-link handler: ?formresponse=BASE64 (from public form submission)
  useEffect(()=>{
    try{
      const params=new URLSearchParams(window.location.search);
      const fr=params.get('formresponse');
      if(!fr)return;
      window.history.replaceState({},'',window.location.pathname);
      const payload=JSON.parse(decodeURIComponent(escape(atob(fr))));
      const matchingForm=(state.forms||[]).find(f=>f.slug===payload.formSlug);
      const exists=(state.formResponses||[]).some(r=>r.submittedAt===payload.submittedAt&&r.contactName===payload.contactName);
      if(!exists){
        const response={id:'resp_'+uid(),formId:matchingForm?.id||null,formSlug:payload.formSlug,formTitle:payload.formTitle,contactName:payload.contactName,data:payload.data,submittedAt:payload.submittedAt,read:false};
        upd({formResponses:[...(state.formResponses||[]),response]});
        setActiveId(FORMS_VIEW);
        setTimeout(()=>alert(`Antwort von "${payload.contactName}" wurde importiert.`),100);
      }else{
        setActiveId(FORMS_VIEW);
        setTimeout(()=>alert('Diese Antwort wurde bereits importiert.'),100);
      }
    }catch(e){console.warn('formresponse import failed:',e);}
  },[]);

  // Deep-link handler: ?crm_pending_token=1 (from token-refresh bookmarklet)
  useEffect(()=>{
    try{
      const params=new URLSearchParams(window.location.search);
      if(!params.get('crm_pending_token'))return;
      window.history.replaceState({},'',window.location.pathname);
      const targetStr=localStorage.getItem('crm_pending_token_target');
      const valueStr=localStorage.getItem('crm_pending_token_value');
      if(!targetStr||!valueStr)return;
      const target=JSON.parse(targetStr);
      const valueData=JSON.parse(valueStr);
      localStorage.removeItem('crm_pending_token_target');
      localStorage.removeItem('crm_pending_token_value');
      if(Date.now()-valueData.setAt>5*60*1000){setTimeout(()=>alert('Token-Aktualisierung abgelaufen (>5 Min). Bitte erneut versuchen.'),100);return;}
      if(!target.tokenId||!valueData.value)return;
      const updated=(state.tokens||[]).map(tok=>tok.id===target.tokenId?{...tok,token:valueData.value}:tok);
      upd({tokens:updated});
      setActiveId(TOKENS_VIEW);
      setTimeout(()=>alert(`✓ Token "${target.label}" wurde erfolgreich aktualisiert!`),200);
    }catch(e){console.warn('crm_pending_token import failed:',e);}
  },[]);

  // Deep-link handler: ?draft=BASE64JSON (from Jarvis)
  useEffect(()=>{
    try{
      const params=new URLSearchParams(window.location.search);
      const b64=params.get('draft');
      if(!b64)return;
      window.history.replaceState({},'',window.location.pathname);
      const draft=JSON.parse(decodeURIComponent(escape(atob(b64))));
      if(draft.type==='invoice'){
        setJarvisDraft(draft);
        setActiveId(INVOICES_VIEW);
        setModal('importInvoice');
      } else if(draft.type==='quote'){
        setActiveId(QUOTES_VIEW);
        const items=(draft.items||[]).map(it=>({id:uid(),type:'item',description:it.description||'',quantity:it.quantity??1,unitPrice:it.unitPrice??0}));
        const q={id:uid(),number:nextQuoteNumber(state.quoteSettings),contactId:null,contactSnapshot:{firma:draft.firma||'',ansprechpartner:'',email:draft.email||'',telefon:'',adresse:''},title:'',date:new Date().toISOString().slice(0,10),validUntil:new Date(Date.now()+30*86400000).toISOString().slice(0,10),items:items.length?items:[{id:uid(),type:'item',description:'',quantity:1,unitPrice:0}],taxRate:draft.taxRate??20,discount:0,notes:draft.notes||'',status:'entwurf',createdAt:new Date().toISOString()};
        setEditingQuote(q);
        upd({quoteSettings:{...state.quoteSettings,quoteCounter:(state.quoteSettings.quoteCounter||1)+1}});
      }
    }catch(e){}
  },[]);

  useEffect(()=>{
    if(skipNextSaveRef.current){skipNextSaveRef.current=false;return;}
    saveEncrypted(cryptoKey,state).catch(console.error);
  },[state]);

  // Subscribe to sync status updates
  useEffect(()=>{
    setSyncListener(()=>setSyncTick(t=>t+1));
    return ()=>setSyncListener(null);
  },[]);

  // Poll for updates + refresh on tab focus (cloud is the source of truth)
  const refreshFromCloud = async () => {
    if(!cloudConnected) return false;
    const fresh=await ghCheckForUpdates(cryptoKey);
    if(fresh){
      skipNextSaveRef.current=true;
      setState(s=>({...fresh, sections:fresh.sections||DEFAULT_SECTIONS, subsections:fresh.subsections||DEFAULT_SUBSECTIONS, customFields:fresh.customFields||[], members:fresh.members||[], todos:fresh.todos||[], aiEmployees:fresh.aiEmployees||[], claudeAccounts:fresh.claudeAccounts||[], claudeTasks:fresh.claudeTasks||[], quotes:fresh.quotes||[], quoteSettings:{...DEFAULT_QUOTE_SETTINGS, ...(fresh.quoteSettings||{})}, invoices:fresh.invoices||[], invoiceSettings:{...DEFAULT_INVOICE_SETTINGS,...(fresh.invoiceSettings||{})}, tokens:fresh.tokens||[], forms:fresh.forms&&fresh.forms.length?fresh.forms:[DEFAULT_ONBOARDING_FORM], formResponses:fresh.formResponses||[], campaigns:fresh.campaigns||[], leads:fresh.leads||[], coldCampaigns:fresh.coldCampaigns||[], visualizations:fresh.visualizations||[]}));
      return true;
    }
    return false;
  };
  useEffect(()=>{
    if(!cloudConnected)return;
    const iv=setInterval(refreshFromCloud,30000);
    const onFocus = () => { refreshFromCloud(); };
    const onVisibility = () => { if(!document.hidden) refreshFromCloud(); };
    window.addEventListener('focus', onFocus);
    document.addEventListener('visibilitychange', onVisibility);
    return ()=>{
      clearInterval(iv);
      window.removeEventListener('focus', onFocus);
      document.removeEventListener('visibilitychange', onVisibility);
    };
  },[cloudConnected,cryptoKey]);

  useEffect(()=>{
    const bump=()=>{lastActivityRef.current=Date.now();};
    window.addEventListener('mousemove',bump);window.addEventListener('keydown',bump);window.addEventListener('click',bump);
    const iv=setInterval(()=>{ if(Date.now()-lastActivityRef.current>IDLE_TIMEOUT_MS) setLocked(true); },30000);
    return()=>{window.removeEventListener('mousemove',bump);window.removeEventListener('keydown',bump);window.removeEventListener('click',bump);clearInterval(iv);};
  },[]);

  // Auto-open Cloud-Sync modal once on first load if not connected
  useEffect(()=>{
    if(!hasGithubSettings()) setTimeout(()=>setModal('githubSync'), 600);
  },[]);

  const upd=patch=>setState(s=>({...s,...patch}));
  const section=state.sections.find(s=>s.id===activeId)||state.sections[0];

  const contacts=state.contacts.filter(c=>{
    if(c.sectionId!==activeId)return false;
    if(activeSubId && c.subsectionId!==activeSubId)return false;
    if(statusFilter&&c.status!==statusFilter)return false;
    if(search){const q=search.toLowerCase();return[c.firma,c.email,c.telefon,c.notizen].some(f=>f&&f.toLowerCase().includes(q));}
    return true;
  });

  const addSubsection=(name)=>{
    const subs=state.subsections||[];
    const order=subs.filter(s=>s.sectionId===activeId).length;
    upd({subsections:[...subs,{id:uid(),sectionId:activeId,name,order}]});
  };
  const deleteSubsection=(id)=>{
    upd({
      subsections:(state.subsections||[]).filter(s=>s.id!==id),
      contacts:state.contacts.map(c=>c.subsectionId===id?{...c,subsectionId:null}:c),
    });
    if(activeSubId===id)setActiveSubId(null);
  };

  const totalUmsatz=state.contacts.filter(c=>c.sectionId===activeId).reduce((a,c)=>a+(Number(c.umsatz)||0),0);
  const overdueCount=state.contacts.filter(c=>c.sectionId===activeId).reduce((a,c)=>a+(c.reminders||[]).filter(r=>r.date<new Date().toISOString().slice(0,10)).length,0);

  const saveContact=contact=>{const ex=state.contacts.find(c=>c.id===contact.id);upd({contacts:ex?state.contacts.map(c=>c.id===contact.id?contact:c):[...state.contacts,contact]});if(selected?.id===contact.id)setSelected(contact);setModal(null);};
  const deleteContact=()=>{upd({contacts:state.contacts.filter(c=>c.id!==selected.id)});setModal(null);setSelected(null);};
  const moveContact=(cId,toId)=>{upd({contacts:state.contacts.map(c=>c.id===cId?{...c,sectionId:toId,subsectionId:null}:c)});setModal(null);setSelected(null);};
  const exportCSV=()=>{const sectionCFs=(state.customFields||[]).filter(cf=>!cf.sectionId||cf.sectionId===activeId);const cols=['Firma','E-Mail','Telefon','Status','Umsatz','Notizen',...sectionCFs.map(cf=>cf.label)];const esc=v=>`"${String(v||'').replace(/"/g,'""')}"`;const rows=state.contacts.filter(c=>c.sectionId===activeId).map(c=>[c.firma,c.email,c.telefon,c.status,c.umsatz,c.notizen,...sectionCFs.map(cf=>c.customValues?.[cf.id]||'')].map(esc).join(','));const csv=[cols.join(','),...rows].join('\n');const a=document.createElement('a');a.href=URL.createObjectURL(new Blob(['﻿'+csv],{type:'text/csv;charset=utf-8'}));a.download=`${section?.name||'export'}.csv`;a.click();};

  return(<>
    {locked&&<LockOverlay onUnlock={(key,data)=>{setState(data);setLocked(false);lastActivityRef.current=Date.now();}}/>}
    <div style={{display:'flex',flexDirection:'column',height:'100vh',filter:locked?'blur(8px)':'none',pointerEvents:locked?'none':'auto',transition:'filter .3s'}}>
    {!cloudConnected&&<div style={{flexShrink:0,background:'#B91C1C',color:'white',padding:'9px 20px',display:'flex',alignItems:'center',gap:12,fontSize:13,fontWeight:500,zIndex:200}}>
      <span style={{fontSize:16}}>⚠️</span>
      <span style={{flex:1}}><strong>Cloud-Sync nicht eingerichtet</strong> — deine Daten liegen nur im Browser. Wenn du den Browser wechselst oder Cache leerst, sind sie weg.</span>
      <button onClick={()=>setModal('githubSync')} style={{background:'white',color:'#B91C1C',border:'none',borderRadius:6,padding:'5px 14px',fontWeight:700,fontSize:12.5,cursor:'pointer',flexShrink:0}}>Jetzt verbinden</button>
    </div>}
    {cloudConnected&&getSyncState().state==='token_invalid'&&<div style={{flexShrink:0,background:'#C05621',color:'white',padding:'9px 20px',display:'flex',alignItems:'center',gap:12,fontSize:13,fontWeight:500,zIndex:200}}>
      <span style={{fontSize:16}}>🔑</span>
      <span style={{flex:1}}><strong>GitHub Token ungültig oder abgelaufen</strong> — Cloud-Sync pausiert. Daten werden nur noch lokal gespeichert bis du den Token aktualisierst.</span>
      <button onClick={()=>setModal('tokenUpdate')} style={{background:'white',color:'#C05621',border:'none',borderRadius:6,padding:'5px 14px',fontWeight:700,fontSize:12.5,cursor:'pointer',flexShrink:0}}>Token aktualisieren</button>
    </div>}
    <div style={{display:'flex',flex:1,overflow:'hidden'}}>
      {/* SIDEBAR */}
      <aside style={{width:230,background:'#0F0E0C',display:'flex',flexDirection:'column',flexShrink:0}}>
        <div style={{padding:'22px 20px 20px',borderBottom:'1px solid rgba(255,255,255,.06)',display:'flex',alignItems:'center',gap:12}}>
          <img src="/logo.png" alt="WebArs" style={{width:34,height:34,borderRadius:'50%'}}/>
          <div><div style={{fontWeight:700,fontSize:14.5,color:'white',letterSpacing:'-0.01em'}}>WebArs</div><div style={{fontSize:10.5,color:'rgba(255,255,255,.3)',marginTop:1,letterSpacing:'0.04em',textTransform:'uppercase',fontWeight:500}}>CRM</div></div>
        </div>
        <nav style={{flex:1,overflowY:'auto',padding:'14px 12px'}}>
          <div style={{fontSize:10,color:'rgba(255,255,255,.25)',fontWeight:600,textTransform:'uppercase',letterSpacing:'0.08em',padding:'2px 8px 10px'}}>Bereiche</div>
          {/* Aufgaben (To-Do) */}
          {(()=>{const isActive=activeId===TODOS_VIEW;const open=(state.todos||[]).filter(t=>!t.done).length;return(
            <button onClick={()=>setActiveId(TODOS_VIEW)} style={{display:'flex',alignItems:'center',width:'100%',padding:'9px 10px',borderRadius:9,background:isActive?'rgba(255,255,255,.1)':'transparent',border:'none',cursor:'pointer',gap:10,marginBottom:2,transition:'background .12s'}}
              onMouseEnter={e=>{if(!isActive)e.currentTarget.style.background='rgba(255,255,255,.05)';}}
              onMouseLeave={e=>{if(!isActive)e.currentTarget.style.background='transparent';}}>
              <span style={{fontSize:13,width:18,textAlign:'center',flexShrink:0,opacity:isActive?1:.5}}><Icons.Check/></span>
              <span style={{flex:1,fontSize:13.5,fontWeight:isActive?600:400,color:isActive?'white':'rgba(255,255,255,.5)',textAlign:'left',letterSpacing:'-0.01em'}}>Aufgaben</span>
              {open>0&&<span style={{fontSize:11,color:'rgba(255,255,255,.25)',fontWeight:500}}>{open}</span>}
            </button>
          );})()}
          {/* Notizen & Ideen (Block-Editor) */}
          {(()=>{const isActive=activeId===CAMPAIGNS_VIEW;const count=(state.campaigns||[]).length;return(
            <button onClick={()=>setActiveId(CAMPAIGNS_VIEW)} style={{display:'flex',alignItems:'center',width:'100%',padding:'9px 10px',borderRadius:9,background:isActive?'rgba(255,255,255,.1)':'transparent',border:'none',cursor:'pointer',gap:10,marginBottom:2,transition:'background .12s'}}
              onMouseEnter={e=>{if(!isActive)e.currentTarget.style.background='rgba(255,255,255,.05)';}}
              onMouseLeave={e=>{if(!isActive)e.currentTarget.style.background='transparent';}}>
              <span style={{fontSize:13,width:18,textAlign:'center',flexShrink:0,opacity:isActive?1:.5}}>📝</span>
              <span style={{flex:1,fontSize:13.5,fontWeight:isActive?600:400,color:isActive?'white':'rgba(255,255,255,.5)',textAlign:'left',letterSpacing:'-0.01em'}}>Notizen & Ideen</span>
              {count>0&&<span style={{fontSize:11,color:'rgba(255,255,255,.25)',fontWeight:500}}>{count}</span>}
            </button>
          );})()}
          {/* KI Mitarbeiter */}
          {(()=>{const isActive=activeId===AI_VIEW;const count=(state.aiEmployees||[]).length;return(
            <button onClick={()=>setActiveId(AI_VIEW)} style={{display:'flex',alignItems:'center',width:'100%',padding:'9px 10px',borderRadius:9,background:isActive?'rgba(255,255,255,.1)':'transparent',border:'none',cursor:'pointer',gap:10,marginBottom:2,transition:'background .12s'}}
              onMouseEnter={e=>{if(!isActive)e.currentTarget.style.background='rgba(255,255,255,.05)';}}
              onMouseLeave={e=>{if(!isActive)e.currentTarget.style.background='transparent';}}>
              <span style={{fontSize:13,width:18,textAlign:'center',flexShrink:0,opacity:isActive?1:.5}}><Icons.Bot/></span>
              <span style={{flex:1,fontSize:13.5,fontWeight:isActive?600:400,color:isActive?'white':'rgba(255,255,255,.5)',textAlign:'left',letterSpacing:'-0.01em'}}>KI Mitarbeiter</span>
              {count>0&&<span style={{fontSize:11,color:'rgba(255,255,255,.25)',fontWeight:500}}>{count}</span>}
            </button>
          );})()}
          {/* Claude Konten */}
          {(()=>{const isActive=activeId===CLAUDE_VIEW;const count=(state.claudeAccounts||[]).length;const openTasks=(state.claudeTasks||[]).filter(t=>t.status!=='erledigt').length;return(
            <button onClick={()=>setActiveId(CLAUDE_VIEW)} style={{display:'flex',alignItems:'center',width:'100%',padding:'9px 10px',borderRadius:9,background:isActive?'rgba(255,255,255,.1)':'transparent',border:'none',cursor:'pointer',gap:10,marginBottom:2,transition:'background .12s'}}
              onMouseEnter={e=>{if(!isActive)e.currentTarget.style.background='rgba(255,255,255,.05)';}}
              onMouseLeave={e=>{if(!isActive)e.currentTarget.style.background='transparent';}}>
              <span style={{fontSize:13,width:18,textAlign:'center',flexShrink:0,opacity:isActive?1:.5}}>✨</span>
              <span style={{flex:1,fontSize:13.5,fontWeight:isActive?600:400,color:isActive?'white':'rgba(255,255,255,.5)',textAlign:'left',letterSpacing:'-0.01em'}}>Claude Konten</span>
              {count>0&&<span style={{fontSize:11,color:'rgba(255,255,255,.25)',fontWeight:500}}>{count}{openTasks>0?` · ${openTasks}`:''}</span>}
            </button>
          );})()}
          {/* Angebote */}
          {(()=>{const isActive=activeId===QUOTES_VIEW;const count=(state.quotes||[]).length;return(
            <button onClick={()=>setActiveId(QUOTES_VIEW)} style={{display:'flex',alignItems:'center',width:'100%',padding:'9px 10px',borderRadius:9,background:isActive?'rgba(255,255,255,.1)':'transparent',border:'none',cursor:'pointer',gap:10,marginBottom:2,transition:'background .12s'}}
              onMouseEnter={e=>{if(!isActive)e.currentTarget.style.background='rgba(255,255,255,.05)';}}
              onMouseLeave={e=>{if(!isActive)e.currentTarget.style.background='transparent';}}>
              <span style={{fontSize:13,width:18,textAlign:'center',flexShrink:0,opacity:isActive?1:.5}}><Icons.Quote/></span>
              <span style={{flex:1,fontSize:13.5,fontWeight:isActive?600:400,color:isActive?'white':'rgba(255,255,255,.5)',textAlign:'left',letterSpacing:'-0.01em'}}>Angebote</span>
              {count>0&&<span style={{fontSize:11,color:'rgba(255,255,255,.25)',fontWeight:500}}>{count}</span>}
            </button>
          );})()}
          {/* Rechnungen */}
          {(()=>{const isActive=activeId===INVOICES_VIEW;const invs=state.invoices||[];const count=invs.length;const overdue=invs.filter(i=>i.dueDate&&i.dueDate<new Date().toISOString().slice(0,10)&&(i.status==='offen'||i.status==='gesendet')).length;return(
            <button onClick={()=>setActiveId(INVOICES_VIEW)} style={{display:'flex',alignItems:'center',width:'100%',padding:'9px 10px',borderRadius:9,background:isActive?'rgba(255,255,255,.1)':'transparent',border:'none',cursor:'pointer',gap:10,marginBottom:2,transition:'background .12s'}}
              onMouseEnter={e=>{if(!isActive)e.currentTarget.style.background='rgba(255,255,255,.05)';}}
              onMouseLeave={e=>{if(!isActive)e.currentTarget.style.background='transparent';}}>
              <span style={{fontSize:13,width:18,textAlign:'center',flexShrink:0,opacity:isActive?1:.5}}><Icons.Invoice/></span>
              <span style={{flex:1,fontSize:13.5,fontWeight:isActive?600:400,color:isActive?'white':'rgba(255,255,255,.5)',textAlign:'left',letterSpacing:'-0.01em'}}>Rechnungen</span>
              {overdue>0&&<span style={{fontSize:10,fontWeight:700,color:'#ef4444',background:'rgba(239,68,68,0.15)',borderRadius:99,padding:'1px 6px'}}>{overdue}</span>}
              {count>0&&!overdue&&<span style={{fontSize:11,color:'rgba(255,255,255,.25)',fontWeight:500}}>{count}</span>}
            </button>
          );})()}
          {/* Leads (Werbe-Webhooks) */}
          {(()=>{const isActive=activeId===LEADS_VIEW;const newCount=(state.leads||[]).filter(l=>l.status==='new').length;const total=(state.leads||[]).length;return(
            <button onClick={()=>setActiveId(LEADS_VIEW)} style={{display:'flex',alignItems:'center',width:'100%',padding:'9px 10px',borderRadius:9,background:isActive?'rgba(255,255,255,.1)':'transparent',border:'none',cursor:'pointer',gap:10,marginBottom:2,transition:'background .12s'}}
              onMouseEnter={e=>{if(!isActive)e.currentTarget.style.background='rgba(255,255,255,.05)';}}
              onMouseLeave={e=>{if(!isActive)e.currentTarget.style.background='transparent';}}>
              <span style={{fontSize:13,width:18,textAlign:'center',flexShrink:0,opacity:isActive?1:.5}}>🎯</span>
              <span style={{flex:1,fontSize:13.5,fontWeight:isActive?600:400,color:isActive?'white':'rgba(255,255,255,.5)',textAlign:'left',letterSpacing:'-0.01em'}}>Leads</span>
              {newCount>0&&<span style={{fontSize:10,fontWeight:700,color:'#22c55e',background:'rgba(34,197,94,.15)',borderRadius:99,padding:'1px 6px'}}>{newCount}</span>}
              {total>0&&!newCount&&<span style={{fontSize:11,color:'rgba(255,255,255,.25)',fontWeight:500}}>{total}</span>}
            </button>
          );})()}
          {/* Cold Outreach */}
          {(()=>{const isActive=activeId===COLD_OUTREACH_VIEW;const count=(state.coldCampaigns||[]).length;const active=(state.coldCampaigns||[]).filter(c=>c.status==='aktiv').length;return(
            <button onClick={()=>setActiveId(COLD_OUTREACH_VIEW)} style={{display:'flex',alignItems:'center',width:'100%',padding:'9px 10px',borderRadius:9,background:isActive?'rgba(255,255,255,.1)':'transparent',border:'none',cursor:'pointer',gap:10,marginBottom:2,transition:'background .12s'}}
              onMouseEnter={e=>{if(!isActive)e.currentTarget.style.background='rgba(255,255,255,.05)';}}
              onMouseLeave={e=>{if(!isActive)e.currentTarget.style.background='transparent';}}>
              <span style={{fontSize:13,width:18,textAlign:'center',flexShrink:0,opacity:isActive?1:.5}}>📨</span>
              <span style={{flex:1,fontSize:13.5,fontWeight:isActive?600:400,color:isActive?'white':'rgba(255,255,255,.5)',textAlign:'left',letterSpacing:'-0.01em'}}>Cold Outreach</span>
              {active>0&&<span style={{fontSize:10,fontWeight:700,color:'#f59e0b',background:'rgba(245,158,11,.15)',borderRadius:99,padding:'1px 6px'}}>{active}</span>}
              {count>0&&!active&&<span style={{fontSize:11,color:'rgba(255,255,255,.25)',fontWeight:500}}>{count}</span>}
            </button>
          );})()}
          {/* Formulare */}
          {(()=>{const isActive=activeId===FORMS_VIEW;const fcount=(state.forms||[]).length;const rcount=(state.formResponses||[]).filter(r=>!r.read).length;return(
            <button onClick={()=>setActiveId(FORMS_VIEW)} style={{display:'flex',alignItems:'center',width:'100%',padding:'9px 10px',borderRadius:9,background:isActive?'rgba(255,255,255,.1)':'transparent',border:'none',cursor:'pointer',gap:10,marginBottom:2,transition:'background .12s'}}
              onMouseEnter={e=>{if(!isActive)e.currentTarget.style.background='rgba(255,255,255,.05)';}}
              onMouseLeave={e=>{if(!isActive)e.currentTarget.style.background='transparent';}}>
              <span style={{fontSize:13,width:18,textAlign:'center',flexShrink:0,opacity:isActive?1:.5}}>📋</span>
              <span style={{flex:1,fontSize:13.5,fontWeight:isActive?600:400,color:isActive?'white':'rgba(255,255,255,.5)',textAlign:'left',letterSpacing:'-0.01em'}}>Formulare</span>
              {rcount>0&&<span style={{fontSize:10,fontWeight:700,color:'#22c55e',background:'rgba(34,197,94,.15)',borderRadius:99,padding:'1px 6px'}}>{rcount}</span>}
              {fcount>0&&!rcount&&<span style={{fontSize:11,color:'rgba(255,255,255,.25)',fontWeight:500}}>{fcount}</span>}
            </button>
          );})()}
          {/* Tokens */}
          {(()=>{const isActive=activeId===TOKENS_VIEW;const count=(state.tokens||[]).length;return(
            <button onClick={()=>setActiveId(TOKENS_VIEW)} style={{display:'flex',alignItems:'center',width:'100%',padding:'9px 10px',borderRadius:9,background:isActive?'rgba(255,255,255,.1)':'transparent',border:'none',cursor:'pointer',gap:10,marginBottom:2,transition:'background .12s'}}
              onMouseEnter={e=>{if(!isActive)e.currentTarget.style.background='rgba(255,255,255,.05)';}}
              onMouseLeave={e=>{if(!isActive)e.currentTarget.style.background='transparent';}}>
              <span style={{fontSize:13,width:18,textAlign:'center',flexShrink:0,opacity:isActive?1:.5}}>🔑</span>
              <span style={{flex:1,fontSize:13.5,fontWeight:isActive?600:400,color:isActive?'white':'rgba(255,255,255,.5)',textAlign:'left',letterSpacing:'-0.01em'}}>Tokens</span>
              {count>0&&<span style={{fontSize:11,color:'rgba(255,255,255,.25)',fontWeight:500}}>{count}</span>}
            </button>
          );})()}
          {/* Gamification */}
          {(()=>{const isActive=activeId===GAMIFICATION_VIEW;return(
            <button onClick={()=>setActiveId(GAMIFICATION_VIEW)} style={{display:'flex',alignItems:'center',width:'100%',padding:'9px 10px',borderRadius:9,background:isActive?'rgba(255,255,255,.1)':'transparent',border:'none',cursor:'pointer',gap:10,marginBottom:2,transition:'background .12s'}}
              onMouseEnter={e=>{if(!isActive)e.currentTarget.style.background='rgba(255,255,255,.05)';}}
              onMouseLeave={e=>{if(!isActive)e.currentTarget.style.background='transparent';}}>
              <span style={{fontSize:13,width:18,textAlign:'center',flexShrink:0,opacity:isActive?1:.5}}>🎮</span>
              <span style={{flex:1,fontSize:13.5,fontWeight:isActive?600:400,color:isActive?'white':'rgba(255,255,255,.5)',textAlign:'left',letterSpacing:'-0.01em'}}>Gamifikation</span>
            </button>
          );})()}
          {(()=>{const isActive=activeId===VISUALIZATIONS_VIEW;const count=(state.visualizations||[]).length;return(
            <button onClick={()=>setActiveId(VISUALIZATIONS_VIEW)} style={{display:'flex',alignItems:'center',width:'100%',padding:'9px 10px',borderRadius:9,background:isActive?'rgba(255,255,255,.1)':'transparent',border:'none',cursor:'pointer',gap:10,marginBottom:2,transition:'background .12s'}}
              onMouseEnter={e=>{if(!isActive)e.currentTarget.style.background='rgba(255,255,255,.05)';}}
              onMouseLeave={e=>{if(!isActive)e.currentTarget.style.background='transparent';}}>
              <span style={{fontSize:13,width:18,textAlign:'center',flexShrink:0,opacity:isActive?1:.5}}>🖼️</span>
              <span style={{flex:1,fontSize:13.5,fontWeight:isActive?600:400,color:isActive?'white':'rgba(255,255,255,.5)',textAlign:'left',letterSpacing:'-0.01em'}}>Visualisierungen</span>
              {count>0&&<span style={{fontSize:11,color:'rgba(255,255,255,.25)',fontWeight:500}}>{count}</span>}
            </button>
          );})()}
          {(()=>{const inSales=state.sections.some(s=>s.id===activeId);const totalContacts=state.contacts.length;return(
            <button onClick={()=>setActiveId(state.sections[0]?.id||activeId)} style={{display:'flex',alignItems:'center',width:'100%',padding:'9px 10px',borderRadius:9,background:inSales?'rgba(255,255,255,.1)':'transparent',border:'none',cursor:'pointer',gap:10,marginBottom:2,transition:'background .12s'}}
              onMouseEnter={e=>{if(!inSales)e.currentTarget.style.background='rgba(255,255,255,.05)';}}
              onMouseLeave={e=>{if(!inSales)e.currentTarget.style.background='transparent';}}>
              <span style={{fontSize:13,width:18,textAlign:'center',flexShrink:0,opacity:inSales?1:.5}}>💼</span>
              <span style={{flex:1,fontSize:13.5,fontWeight:inSales?600:400,color:inSales?'white':'rgba(255,255,255,.5)',textAlign:'left',letterSpacing:'-0.01em'}}>Sales Management</span>
              {totalContacts>0&&<span style={{fontSize:11,color:'rgba(255,255,255,.25)',fontWeight:500}}>{totalContacts}</span>}
            </button>
          );})()}
        </nav>
        <div style={{padding:'12px 12px 16px',borderTop:'1px solid rgba(255,255,255,.06)',display:'grid',gap:2}}>
          {[
            {icon:<span style={{fontSize:13}}>🕐</span>,label:'Snapshots',action:()=>setModal('snapshots')},
            {icon:<Icons.Field/>,label:'Felder verwalten',action:()=>setModal('addField')},
            {icon:<span style={{fontSize:13}}>🔑</span>,label:'Passwort',action:()=>setModal('changePassword')},
            {icon:<span style={{fontSize:13}}>⚙</span>,label:'Einstellungen',action:()=>setModal('githubSync')},
            (()=>{
              const sync=getSyncState();
              const dot = !cloudConnected?'#A8A39D':sync.state==='ok'?'#22c55e':sync.state==='token_invalid'?'#f97316':sync.state==='error'?'#ef4444':'#f59e0b';
              const status = !cloudConnected?'Cloud-Sync einrichten':sync.state==='ok'?'Cloud-Sync · live':sync.state==='token_invalid'?'Token abgelaufen!':sync.state==='error'?'Cloud-Sync · Fehler':'Cloud-Sync · verbunden';
              const action = sync.state==='token_invalid'?()=>setModal('tokenUpdate'):()=>setModal('githubSync');
              const isAlert = sync.state==='error'||sync.state==='token_invalid';
              return {icon:<span style={{position:'relative',display:'inline-flex'}}><Icons.Cloud/><span style={{position:'absolute',right:-2,bottom:-2,width:6,height:6,borderRadius:'50%',background:dot,border:'1.5px solid #0F0E0C'}}></span></span>,label:status,action,alert:isAlert};
            })(),
            {icon:<Icons.Lock/>,label:'Sperren',action:()=>setLocked(true)},
            {icon:<Icons.Logout/>,label:'Abmelden',action:()=>{if(window.confirm('Wirklich abmelden? Du musst dich danach neu einloggen.'))onLogout&&onLogout();},danger:true},
          ].map(({icon,label,action,danger,alert})=>(
            <button key={label} onClick={action} style={{display:'flex',alignItems:'center',width:'100%',padding:'8px 10px',borderRadius:9,border:'none',background:alert?'rgba(239,68,68,0.15)':'transparent',cursor:'pointer',gap:10,color:alert?'rgba(255,150,150,0.9)':'rgba(255,255,255,.25)',fontSize:12.5,transition:'color .15s,background .15s'}}
              onMouseEnter={e=>{e.currentTarget.style.color=danger?'rgba(255,140,140,.85)':alert?'rgba(255,180,180,1)':'rgba(255,255,255,.5)';}}
              onMouseLeave={e=>{e.currentTarget.style.color=alert?'rgba(255,150,150,0.9)':'rgba(255,255,255,.25)';e.currentTarget.style.background=alert?'rgba(239,68,68,0.15)':'transparent';}}>
              {icon}<span>{label}</span>
            </button>
          ))}
        </div>
      </aside>

      {/* MAIN */}
      <main style={{flex:1,display:'flex',flexDirection:'column',overflow:'hidden'}}>
        {activeId === TODOS_VIEW ? (<>
          <div style={{background:'white',borderBottom:'1px solid rgba(0,0,0,.07)',padding:'14px 28px',display:'flex',alignItems:'center',gap:14,flexShrink:0}}>
            <div style={{flex:1}}>
              <h1 style={{fontSize:18,fontWeight:800,letterSpacing:'-0.02em'}}>Aufgaben</h1>
              <div style={{fontSize:12,color:'#B0ABA5',marginTop:2,display:'flex',gap:12,alignItems:'center'}}>
                <span>{(state.todos||[]).filter(t=>!t.done).length} offen</span>
                {(state.todos||[]).filter(t=>t.done).length>0&&<span>· {(state.todos||[]).filter(t=>t.done).length} erledigt</span>}
                {(state.todos||[]).filter(t=>!t.done&&t.dueDate&&t.dueDate<new Date().toISOString().slice(0,10)).length>0&&<span style={{color:'#B45309',fontWeight:600}}>· {(state.todos||[]).filter(t=>!t.done&&t.dueDate&&t.dueDate<new Date().toISOString().slice(0,10)).length} überfällig</span>}
              </div>
            </div>
          </div>
          <TodoView todos={state.todos||[]} onUpdate={todos=>upd({todos})}/>
        </>) : activeId === AI_VIEW ? (<>
          <div style={{background:'white',borderBottom:'1px solid rgba(0,0,0,.07)',padding:'14px 28px',display:'flex',alignItems:'center',gap:14,flexShrink:0}}>
            <div style={{flex:1}}>
              <h1 style={{fontSize:18,fontWeight:800,letterSpacing:'-0.02em'}}>KI Mitarbeiter</h1>
              <div style={{fontSize:12,color:'#B0ABA5',marginTop:2,display:'flex',gap:12,alignItems:'center'}}>
                <span>{(state.aiEmployees||[]).length} {(state.aiEmployees||[]).length===1?'Mitarbeiter':'Mitarbeiter'}</span>
                {(state.aiEmployees||[]).filter(e=>e.status==='aktiv').length>0&&<span>· {(state.aiEmployees||[]).filter(e=>e.status==='aktiv').length} aktiv</span>}
              </div>
            </div>
            {(state.aiEmployees||[]).length>0 && (
              <button className="btn btn-primary" onClick={()=>setModal('addAI')}><Icons.Plus/>Neuer KI Mitarbeiter</button>
            )}
          </div>
          <AIEmployeesView employees={state.aiEmployees||[]} onUpdate={aiEmployees=>upd({aiEmployees})} externalNewTrigger={modal==='addAI'} onExternalNewHandled={()=>setModal(null)}/>
        </>) : activeId === CLAUDE_VIEW ? (<>
          <div style={{background:'white',borderBottom:'1px solid rgba(0,0,0,.07)',padding:'14px 28px',display:'flex',alignItems:'center',gap:14,flexShrink:0}}>
            <div style={{flex:1}}>
              <h1 style={{fontSize:18,fontWeight:800,letterSpacing:'-0.02em'}}>Claude Konten</h1>
              <div style={{fontSize:12,color:'#B0ABA5',marginTop:2,display:'flex',gap:12,alignItems:'center'}}>
                <span>{(state.claudeAccounts||[]).length} {(state.claudeAccounts||[]).length===1?'Konto':'Konten'}</span>
                {(state.claudeTasks||[]).length>0&&<span>· {(state.claudeTasks||[]).length} Aufgaben</span>}
                {(state.claudeTasks||[]).filter(t=>t.status!=='erledigt').length>0&&<span style={{color:'#0369a1',fontWeight:600}}>· {(state.claudeTasks||[]).filter(t=>t.status!=='erledigt').length} offen</span>}
              </div>
            </div>
            <div style={{display:'flex',gap:8}}>
              <button className="btn btn-ghost" onClick={()=>setModal('addClaudeTask')} disabled={(state.claudeAccounts||[]).length===0}><Icons.Plus/>Aufgabe</button>
              <button className="btn btn-primary" onClick={()=>setModal('addClaude')}><Icons.Plus/>Neues Konto</button>
            </div>
          </div>
          <ClaudeAccountsView
            accounts={state.claudeAccounts||[]}
            tasks={state.claudeTasks||[]}
            onUpdateAccounts={claudeAccounts=>upd({claudeAccounts})}
            onUpdateTasks={claudeTasks=>upd({claudeTasks})}
            externalNewTrigger={modal==='addClaude'}
            onExternalNewHandled={()=>setModal(null)}
            externalNewTaskTrigger={modal==='addClaudeTask'}
            onExternalNewTaskHandled={()=>setModal(null)}
          />
        </>) : activeId === QUOTES_VIEW ? (<>
          <div style={{background:'white',borderBottom:'1px solid rgba(0,0,0,.07)',padding:'14px 28px',display:'flex',alignItems:'center',gap:14,flexShrink:0}}>
            <div style={{flex:1}}>
              <h1 style={{fontSize:18,fontWeight:800,letterSpacing:'-0.02em'}}>Angebote</h1>
              <div style={{fontSize:12,color:'#B0ABA5',marginTop:2,display:'flex',gap:12,alignItems:'center'}}>
                <span>{(state.quotes||[]).length} {(state.quotes||[]).length===1?'Angebot':'Angebote'}</span>
                {(state.quotes||[]).filter(q=>q.status==='entwurf').length>0&&<span>· {(state.quotes||[]).filter(q=>q.status==='entwurf').length} Entwurf</span>}
                {(state.quotes||[]).filter(q=>q.status==='gesendet').length>0&&<span>· {(state.quotes||[]).filter(q=>q.status==='gesendet').length} gesendet</span>}
              </div>
            </div>
          </div>
          <QuotesView
            quotes={state.quotes||[]}
            contacts={state.contacts}
            settings={state.quoteSettings}
            onCreate={(contact)=>{
              const q = blankQuote(contact, state.quoteSettings);
              setEditingQuote(q);
              upd({quoteSettings:{...state.quoteSettings, quoteCounter:(state.quoteSettings.quoteCounter||1)+1}});
            }}
            onOpen={(q)=>setEditingQuote(q)}
            onDelete={(id)=>upd({quotes:(state.quotes||[]).filter(q=>q.id!==id)})}
            onDuplicate={async q=>{const settings=state.quoteSettings||DEFAULT_QUOTE_SETTINGS;const duped={...q,id:uid(),number:nextQuoteNumber(settings),createdAt:new Date().toISOString(),status:'entwurf'};const patch={quotes:[...(state.quotes||[]),duped],quoteSettings:{...settings,quoteCounter:(settings.quoteCounter||1)+1}};skipNextSaveRef.current=true;upd(patch);await saveEncrypted(cryptoKey,{...state,...patch}).catch(console.error);}}
            onSettings={()=>setModal('quoteSettings')}
          />
        </>) : activeId === FORMS_VIEW ? (<>
          <FormsView
            forms={state.forms||[]}
            responses={state.formResponses||[]}
            ghSettings={cloudConnected?_ghSettings:null}
            onUpdateForms={forms=>upd({forms})}
            onUpdateResponses={formResponses=>upd({formResponses})}
          />
        </>) : activeId === COLD_OUTREACH_VIEW ? (
          <ColdOutreachContainer campaigns={state.coldCampaigns||[]} onUpdate={coldCampaigns=>upd({coldCampaigns})}/>
        ) : activeId === TOKENS_VIEW ? (<>
          <div style={{background:'white',borderBottom:'1px solid rgba(0,0,0,.07)',padding:'14px 28px',display:'flex',alignItems:'center',gap:14,flexShrink:0}}>
            <div style={{flex:1}}>
              <h1 style={{fontSize:18,fontWeight:800,letterSpacing:'-0.02em'}}>Tokens & API Keys</h1>
              <div style={{fontSize:12,color:'#B0ABA5',marginTop:2}}>
                <span>{(state.tokens||[]).length} {(state.tokens||[]).length===1?'Token':'Tokens'} gespeichert</span>
              </div>
            </div>
          </div>
          <TokensView tokens={state.tokens||[]} onUpdate={tokens=>upd({tokens})}/>
        </>) : activeId === CAMPAIGNS_VIEW ? (<>
          <div style={{background:'white',borderBottom:'1px solid rgba(0,0,0,.07)',padding:'14px 28px',display:'flex',alignItems:'center',gap:14,flexShrink:0}}>
            <div style={{flex:1}}>
              <h1 style={{fontSize:18,fontWeight:800,letterSpacing:'-0.02em'}}>📝 Notizen & Ideen</h1>
              <div style={{fontSize:12,color:'#B0ABA5',marginTop:2}}>{(state.campaigns||[]).length} Mappen · {(state.campaigns||[]).reduce((s,c)=>s+(c.files||[]).length,0)} Seiten</div>
            </div>
          </div>
          <CampaignsView
            campaigns={state.campaigns||[]}
            onUpdate={campaigns=>upd({campaigns})}
          />
        </>) : activeId === LEADS_VIEW ? (<>
          <div style={{background:'white',borderBottom:'1px solid rgba(0,0,0,.07)',padding:'14px 28px',display:'flex',alignItems:'center',gap:14,flexShrink:0}}>
            <div style={{flex:1}}>
              <h1 style={{fontSize:18,fontWeight:800,letterSpacing:'-0.02em'}}>🎯 Leads</h1>
              <div style={{fontSize:12,color:'#B0ABA5',marginTop:2}}>{(state.leads||[]).filter(l=>l.status==='new').length} neue · {(state.leads||[]).filter(l=>l.status==='converted').length} übernommen · {(state.leads||[]).filter(l=>l.status==='dismissed').length} verworfen</div>
            </div>
          </div>
          <LeadsView
            leads={state.leads||[]}
            sections={state.sections||[]}
            onUpdateLeads={leads=>upd({leads})}
            onConvertLead={(lead, sectionId)=>{
              // Auto-create customField definitions for any extras so they appear
              // as structured (editable) fields in the contact, not just in notes.
              const STD=['name','email','phone','company','message','source','metadata'];
              const extraEntries=Object.entries(lead.extras||{}).filter(([k,v])=>!STD.includes(k)&&v!==null&&v!==undefined&&v!=='');
              // Always also include source as a field (so it's queryable on the contact)
              if (lead.source) extraEntries.unshift(['source', lead.source]);
              const existingDefs=state.customFields||[];
              const defByKey=Object.fromEntries(existingDefs.map(cf=>[cf.label.toLowerCase(),cf]));
              const newDefs=[];
              const customValues={};
              for (const [k,v] of extraEntries) {
                const labelLc=k.toLowerCase();
                let def=defByKey[labelLc];
                if (!def) {
                  def={id:'cf_'+uid(),label:k,type:'text',sectionId:null};
                  newDefs.push(def);
                  defByKey[labelLc]=def;
                }
                customValues[def.id]=typeof v==='object'?JSON.stringify(v):String(v);
              }
              // Build a complete notes block as a human-readable audit trail too.
              const notesLines=[
                `📨 Lead aus Kampagne "${lead.campaign}"`,
                `Empfangen: ${new Date(lead.receivedAt||lead.importedAt).toLocaleString('de-AT')}`,
                lead.source?`Quelle: ${lead.source}`:'',
                lead.message?`\nNachricht:\n${lead.message}`:'',
                extraEntries.length?`\nZusatzfelder:\n${extraEntries.map(([k,v])=>`  • ${k}: ${typeof v==='object'?JSON.stringify(v):v}`).join('\n')}`:'',
              ].filter(Boolean).join('\n');
              const newContact={
                id:'c_'+uid(),
                sectionId,
                firma:lead.company||lead.name||'',
                ansprechpartner:lead.name||'',
                email:lead.email||'',
                telefon:lead.phone||'',
                address:'', zip:'', city:'', country:'', taxId:'',
                status:'Aktiv',
                umsatz:'',
                notizen:notesLines,
                customValues,
                reminders:[],
                activities:[{id:'a_'+uid(),timestamp:new Date().toISOString(),text:`Lead automatisch aus Kampagne "${lead.campaign}" übernommen${lead.source?` (Quelle: ${lead.source})`:''}.`}],
                createdAt:new Date().toISOString(),
              };
              upd({
                contacts:[...state.contacts, newContact],
                customFields:[...existingDefs, ...newDefs],
                leads:(state.leads||[]).map(l=>l.id===lead.id?{...l,status:'converted',contactId:newContact.id}:l),
              });
              alert(`Kontakt "${newContact.ansprechpartner||newContact.firma}" angelegt${newDefs.length?` (${newDefs.length} neue Custom-Felder erstellt)`:''}.`);
            }}
          />
        </>) : activeId === GAMIFICATION_VIEW ? (<>
          <div style={{background:'white',borderBottom:'1px solid rgba(0,0,0,.07)',padding:'14px 28px',display:'flex',alignItems:'center',gap:14,flexShrink:0}}>
            <div style={{flex:1}}>
              <h1 style={{fontSize:18,fontWeight:800,letterSpacing:'-0.02em'}}>🎮 Gamifikation</h1>
              <div style={{fontSize:12,color:'#B0ABA5',marginTop:2}}>Tägliche Task-Übersicht aus dem Overlay</div>
            </div>
          </div>
          <GamificationView
            onLoadData={async ()=>{
              const resp=await fetch('/api/gamification',{headers:{'Authorization':`Bearer ${window.WEBARS_API_TOKEN}`}});
              if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
              return await resp.json();
            }}
            onReset={async ()=>{
              const resp=await fetch('/api/gamification',{method:'DELETE',headers:{'Authorization':`Bearer ${window.WEBARS_API_TOKEN}`}});
              if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
            }}
            onRescale={async (factor)=>{
              const resp=await fetch(`/api/gamification/rescale?factor=${factor}`,{method:'POST',headers:{'Authorization':`Bearer ${window.WEBARS_API_TOKEN}`}});
              if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
            }}
          />
        </>) : activeId === VISUALIZATIONS_VIEW ? (<>
          <VisualizationsView
            items={state.visualizations||[]}
            onUpdate={visualizations=>upd({visualizations})}
          />
        </>) : activeId === INVOICES_VIEW ? (<>
          <div style={{background:'white',borderBottom:'1px solid rgba(0,0,0,.07)',padding:'14px 28px',display:'flex',alignItems:'center',gap:14,flexShrink:0}}>
            <div style={{flex:1}}>
              <h1 style={{fontSize:18,fontWeight:800,letterSpacing:'-0.02em'}}>Rechnungen</h1>
              <div style={{fontSize:12,color:'#B0ABA5',marginTop:2,display:'flex',gap:12,alignItems:'center'}}>
                <span>{(state.invoices||[]).length} {(state.invoices||[]).length===1?'Rechnung':'Rechnungen'}</span>
                {(state.invoices||[]).filter(i=>i.status==='offen'||i.status==='ueberfaellig').length>0&&<span style={{color:'#b45309',fontWeight:600}}>· {(state.invoices||[]).filter(i=>i.status==='offen'||i.status==='ueberfaellig').length} offen</span>}
                {(state.invoices||[]).filter(i=>i.status==='bezahlt').length>0&&<span style={{color:'#16a34a',fontWeight:600}}>· {(state.invoices||[]).filter(i=>i.status==='bezahlt').length} bezahlt</span>}
              </div>
            </div>
            <button className="btn btn-ghost btn-sm" onClick={()=>setModal('invoiceSettings')}><Icons.Field/>Vorlage</button>
          </div>
          <InvoicesView
            invoices={state.invoices||[]}
            contacts={state.contacts}
            quoteSettings={state.quoteSettings}
            invoiceSettings={state.invoiceSettings||DEFAULT_INVOICE_SETTINGS}
            quotes={state.quotes||[]}
            onCreate={()=>{
              const inv=blankInvoice(null,state.quoteSettings,state.invoiceSettings||DEFAULT_INVOICE_SETTINGS,null);
              setEditingInvoice(inv);
              upd({invoiceSettings:{...(state.invoiceSettings||DEFAULT_INVOICE_SETTINGS),invoiceCounter:((state.invoiceSettings||DEFAULT_INVOICE_SETTINGS).invoiceCounter||1)+1}});
            }}
            onOpen={inv=>setEditingInvoice(inv.status==='ueberfaellig'?{...inv,status:'offen'}:inv)}
            onDelete={id=>upd({invoices:(state.invoices||[]).filter(i=>i.id!==id)})}
            onMarkPaid={id=>upd({invoices:(state.invoices||[]).map(i=>i.id===id?{...i,status:'bezahlt',paidAt:new Date().toISOString().slice(0,10)}:i)})}
            onDuplicate={inv=>{const settings=state.invoiceSettings||DEFAULT_INVOICE_SETTINGS;const duped={...inv,id:uid(),number:nextInvoiceNumber(settings),createdAt:new Date().toISOString(),status:'entwurf',paidAt:null,mahnungen:[]};upd({invoices:[...(state.invoices||[]),duped],invoiceSettings:{...settings,invoiceCounter:(settings.invoiceCounter||1)+1}});}}
            onImport={()=>setModal('importInvoice')}
            onMahnung={inv=>setMahnungInvoice(inv.status==='ueberfaellig'?{...inv,status:'offen'}:inv)}
          />
        </>) : (<>
        <div style={{background:'white',borderBottom:'1px solid rgba(0,0,0,.07)',padding:'14px 28px',display:'flex',alignItems:'center',gap:14,flexShrink:0}}>
          <div style={{flex:1}}>
            <h1 style={{fontSize:18,fontWeight:800,letterSpacing:'-0.02em'}}>💼 Sales Management</h1>
            <div style={{fontSize:12,color:'#B0ABA5',marginTop:2,display:'flex',gap:12,alignItems:'center'}}>
              <span>{state.contacts.filter(c=>c.sectionId===activeId).length} Kontakte</span>
              {totalUmsatz>0&&<span>· Gesamt {fmt(totalUmsatz)}</span>}
              {overdueCount>0&&<span style={{color:'#B45309',fontWeight:600}}>· {overdueCount} überfällig</span>}
            </div>
          </div>
          <div style={{position:'relative',width:260}}>
            <div style={{position:'absolute',left:11,top:'50%',transform:'translateY(-50%)',color:'#C8C3BD',lineHeight:0}}><Icons.Search/></div>
            <input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Suchen…" style={{paddingLeft:34,background:'#F5F3F0',border:'1.5px solid transparent'}}/>
          </div>
          <select value={statusFilter} onChange={e=>setStatusFilter(e.target.value)} style={{width:'auto',padding:'9px 12px',fontSize:13,background:'#F5F3F0',border:'1.5px solid transparent',color:statusFilter?'#141210':'#A8A39D'}}>
            <option value="">Alle Status</option>{STATUSES.map(s=><option key={s}>{s}</option>)}
          </select>
          <button className="btn btn-ghost btn-sm" onClick={exportCSV}><Icons.Export/>CSV</button>
          <button className="btn btn-ghost btn-sm" onClick={()=>setModal('csvImport')}><Icons.Import/>CSV Import</button>
          <button className="btn btn-primary" onClick={()=>{setSelected(null);setModal('add');}}><Icons.Plus/>Neuer Kontakt</button>
        </div>
        {/* Section-Tabs */}
        <div style={{background:'white',borderBottom:'1px solid rgba(0,0,0,.06)',padding:'0 28px',display:'flex',alignItems:'center',gap:0,flexShrink:0,overflowX:'auto'}}>
          {state.sections.map(s=>(
            <button key={s.id} onClick={()=>setActiveId(s.id)}
              style={{display:'flex',alignItems:'center',gap:7,padding:'10px 16px',background:'none',border:'none',borderBottom:s.id===activeId?'2px solid #141210':'2px solid transparent',cursor:'pointer',fontSize:13,fontWeight:s.id===activeId?700:400,color:s.id===activeId?'#141210':'#A8A39D',whiteSpace:'nowrap',transition:'all .15s',marginBottom:-1}}>
              <span>{s.icon}</span>{s.name}
              <span style={{fontSize:11,color:s.id===activeId?'#6B6560':'#C8C3BD',marginLeft:4}}>{state.contacts.filter(c=>c.sectionId===s.id).length}</span>
            </button>
          ))}
          <button onClick={()=>setModal('addSection')}
            style={{display:'flex',alignItems:'center',gap:5,padding:'10px 14px',background:'none',border:'none',borderBottom:'2px solid transparent',cursor:'pointer',fontSize:12,color:'#C8C3BD',whiteSpace:'nowrap',transition:'color .15s',marginBottom:-1}}
            onMouseEnter={e=>e.currentTarget.style.color='#6B6560'}
            onMouseLeave={e=>e.currentTarget.style.color='#C8C3BD'}>
            <Icons.Plus/>Bereich hinzufügen
          </button>
        </div>
        <SubsectionBar
          sectionId={activeId}
          subsections={state.subsections||[]}
          activeSubId={activeSubId}
          onSelect={id=>{setActiveSubId(id);}}
          onAdd={addSubsection}
          onDelete={deleteSubsection}
        />
        <div style={{flex:1,overflowY:'auto',padding:28}}>
          {contacts.length===0?(
            <div style={{textAlign:'center',padding:'100px 20px',color:'#C8C3BD'}}>
              <div style={{fontSize:44,marginBottom:16,opacity:.5}}>{section?.icon}</div>
              <div style={{fontSize:16,fontWeight:600,color:'#C0BBB5'}}>{search||statusFilter?'Keine Treffer.':'Noch keine Kontakte in diesem Bereich.'}</div>
              {!search&&!statusFilter&&<button className="btn btn-primary" style={{marginTop:20}} onClick={()=>setModal('add')}><Icons.Plus/>Ersten Kontakt hinzufügen</button>}
            </div>
          ):(
            <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fill,minmax(280px,1fr))',gap:14}}>
              {contacts.map((c,i)=>(<ContactCard key={c.id} contact={c} sections={state.sections} animDelay={i*.04}
                onEdit={()=>{setSelected(c);setModal('edit');}} onDelete={()=>{setSelected(c);setModal('delete');}}
                onDetail={()=>{setSelected(c);setModal('detail');}} onMove={()=>{setSelected(c);setModal('move');}}/>))}
            </div>
          )}
        </div>
        </>)}
      </main>
    </div>
    </div>
    {(modal==='add'||modal==='edit')&&<ContactModal contact={modal==='edit'?selected:null} sections={state.sections} customFields={state.customFields} onSave={saveContact} onClose={()=>setModal(null)}/>}
    {modal==='delete'&&selected&&<ConfirmModal text={`"${selected.firma}" wirklich löschen?`} onConfirm={deleteContact} onCancel={()=>setModal(null)}/>}
    {modal==='move'&&selected&&<MoveModal contact={selected} sections={state.sections} onMove={moveContact} onClose={()=>setModal(null)}/>}
    {modal==='addSection'&&<AddSectionModal onAdd={s=>{upd({sections:[...state.sections,s]});setActiveId(s.id);setModal(null);}} onClose={()=>setModal(null)}/>}
    {modal==='members'&&<MembersModal members={state.members||[]} onSave={m=>upd({members:m})} onClose={()=>setModal(null)}/>}
    {modal==='csvImport'&&<CSVImportModal sections={state.sections} onImport={newContacts=>upd({contacts:[...state.contacts,...newContacts]})} onClose={()=>setModal(null)}/>}
    {modal==='invites'&&<InviteManagerModal masterKey={cryptoKey} onClose={()=>setModal(null)}/>}
    {modal==='addField'&&<AddFieldModal sections={state.sections} customFields={state.customFields} onAdd={f=>upd({customFields:[...state.customFields,f]})} onDelete={id=>upd({customFields:state.customFields.filter(f=>f.id!==id)})} onClose={()=>setModal(null)}/>}
    {modal==='githubSync'&&<GithubSyncModal
      cryptoKey={cryptoKey}
      currentSettings={cloudConnected?_ghSettings:null}
      onSaved={async (existingData)=>{
        setCloudConnected(true);
        setModal(null);
        if (existingData) {
          // Loaded from GitHub — overwrite local state
          skipNextSaveRef.current=true;
          setState({...existingData, sections:existingData.sections||DEFAULT_SECTIONS, subsections:existingData.subsections||DEFAULT_SUBSECTIONS, customFields:existingData.customFields||[], members:existingData.members||[], todos:existingData.todos||[], aiEmployees:existingData.aiEmployees||[], claudeAccounts:existingData.claudeAccounts||[], claudeTasks:existingData.claudeTasks||[], quotes:existingData.quotes||[], quoteSettings:{...DEFAULT_QUOTE_SETTINGS, ...(existingData.quoteSettings||{})}, invoices:existingData.invoices||[], invoiceSettings:{...DEFAULT_INVOICE_SETTINGS,...(existingData.invoiceSettings||{})}, tokens:existingData.tokens||[], forms:existingData.forms&&existingData.forms.length?existingData.forms:[DEFAULT_ONBOARDING_FORM], formResponses:existingData.formResponses||[], campaigns:existingData.campaigns||[], leads:existingData.leads||[]});
        } else {
          // No remote yet — push current local state
          await saveEncrypted(cryptoKey, state);
        }
      }}
      onCleared={()=>{setCloudConnected(false);setModal(null);}}
      onClose={()=>setModal(null)}
    />}
    {modal==='detail'&&selected&&<ContactDetail contact={selected} sections={state.sections} quotes={state.quotes||[]} settings={state.quoteSettings} onClose={()=>setModal(null)} onEdit={()=>setModal('edit')} onUpdate={u2=>{upd({contacts:state.contacts.map(c=>c.id===u2.id?u2:c)});setSelected(u2);}}
      onCreateQuote={()=>{
        const q = blankQuote(selected, state.quoteSettings);
        setEditingQuote(q);
        upd({quoteSettings:{...state.quoteSettings, quoteCounter:(state.quoteSettings.quoteCounter||1)+1}});
        setModal(null);
      }}
      onOpenQuote={(q)=>{setEditingQuote(q);setModal(null);}}
    />}
    {modal==='quoteSettings'&&<QuoteSettingsModal settings={state.quoteSettings} onSave={s=>upd({quoteSettings:s})} onClose={()=>setModal(null)}/>}
    {modal==='invoiceSettings'&&<InvoiceSettingsModal quoteSettings={state.quoteSettings} invoiceSettings={state.invoiceSettings||DEFAULT_INVOICE_SETTINGS} onSave={(qs,is_)=>upd({quoteSettings:{...state.quoteSettings,...qs},invoiceSettings:{...state.invoiceSettings,...is_}})} onClose={()=>setModal(null)}/>}
    {modal==='tokenUpdate'&&<TokenUpdateModal cryptoKey={cryptoKey} currentState={state} onSaved={()=>setModal(null)} onClose={()=>setModal(null)}/>}
    {modal==='changePassword'&&<ChangePasswordModal cryptoKey={cryptoKey} onClose={()=>setModal(null)}/>}
    {modal==='snapshots'&&<SnapshotRestoreModal cryptoKey={cryptoKey} onRestore={data=>{skipNextSaveRef.current=true;setState(s=>({...s,...data,subsections:data.subsections||DEFAULT_SUBSECTIONS,members:data.members||[],todos:data.todos||[],aiEmployees:data.aiEmployees||[],claudeAccounts:data.claudeAccounts||[],claudeTasks:data.claudeTasks||[],quotes:data.quotes||[],quoteSettings:{...DEFAULT_QUOTE_SETTINGS,...(data.quoteSettings||{})},invoices:data.invoices||[],invoiceSettings:{...DEFAULT_INVOICE_SETTINGS,...(data.invoiceSettings||{})},tokens:data.tokens||[],forms:data.forms&&data.forms.length?data.forms:[DEFAULT_ONBOARDING_FORM],formResponses:data.formResponses||[],campaigns:data.campaigns||[],leads:data.leads||[],coldCampaigns:data.coldCampaigns||[],visualizations:data.visualizations||[]}));}} onClose={()=>setModal(null)}/>}
    {modal==='importInvoice'&&<InvoiceImportModal contacts={state.contacts} invoiceSettings={state.invoiceSettings||DEFAULT_INVOICE_SETTINGS} quoteSettings={state.quoteSettings} initialData={jarvisDraft} onImport={(inv,newContact)=>{const invs=[...(state.invoices||[]),inv];const ctcts=newContact?[...state.contacts,newContact]:state.contacts;const newInvSettings=newContact?state.invoiceSettings:{...state.invoiceSettings||DEFAULT_INVOICE_SETTINGS,invoiceCounter:((state.invoiceSettings||DEFAULT_INVOICE_SETTINGS).invoiceCounter||1)+1};upd({invoices:invs,contacts:ctcts,invoiceSettings:newInvSettings});setJarvisDraft(null);}} onClose={()=>{setModal(null);setJarvisDraft(null);}}/>}
    {editingQuote && <QuoteEditor
      quote={editingQuote}
      contacts={state.contacts}
      settings={state.quoteSettings}
      onSave={(q)=>{
        const exists = (state.quotes||[]).some(x=>x.id===q.id);
        upd({quotes: exists ? state.quotes.map(x=>x.id===q.id?q:x) : [...(state.quotes||[]), q]});
        setEditingQuote(null);
      }}
      onPreview={(q)=>{setEditingQuote(null);setPreviewQuote(q);}}
      onClose={()=>setEditingQuote(null)}
    />}
    {previewQuote && <QuotePreview
      quote={previewQuote}
      settings={state.quoteSettings}
      onMarkSent={()=>{
        const updated = {...previewQuote, status:'gesendet', sentAt:new Date().toISOString()};
        upd({quotes:(state.quotes||[]).map(q=>q.id===updated.id?updated:q)});
        setPreviewQuote(updated);
      }}
      onClose={()=>setPreviewQuote(null)}
    />}
    {editingInvoice && <InvoiceEditor
      invoice={editingInvoice}
      contacts={state.contacts}
      quoteSettings={state.quoteSettings}
      invoiceSettings={state.invoiceSettings||DEFAULT_INVOICE_SETTINGS}
      quotes={state.quotes||[]}
      onCreateContact={c=>upd({contacts:[...state.contacts,c]})}
      onSave={inv=>{
        const exists=(state.invoices||[]).find(i=>i.id===inv.id);
        const saved={...inv, paidAt: inv.status==='bezahlt' ? (inv.paidAt||new Date().toISOString().slice(0,10)) : (inv.status==='storniert'?inv.paidAt:null)};
        upd({invoices:exists?(state.invoices||[]).map(i=>i.id===inv.id?saved:i):[...(state.invoices||[]),saved]});
        setEditingInvoice(null);
      }}
      onPreview={inv=>{setEditingInvoice(null);setPreviewInvoice(inv);}}
      onClose={()=>setEditingInvoice(null)}
    />}
    {previewInvoice && <InvoicePreview
      invoice={previewInvoice}
      settings={state.quoteSettings}
      invoiceSettings={state.invoiceSettings||DEFAULT_INVOICE_SETTINGS}
      onClose={()=>setPreviewInvoice(null)}
    />}
    {mahnungInvoice && <MahnungPreview
      invoice={mahnungInvoice}
      settings={state.quoteSettings}
      onSave={inv=>{upd({invoices:(state.invoices||[]).map(i=>i.id===inv.id?inv:i)});}}
      onClose={()=>setMahnungInvoice(null)}
    />}
  </>);
}

// ══════════════════════════════════════════════════════════════════
//  AUTH WRAPPER
// ══════════════════════════════════════════════════════════════════
function AuthWrapper(){
  const [phase,setPhase]=useState('loading');
  const [cryptoKey,setCryptoKey]=useState(null);
  const [crmData,setCrmData]=useState(null);
  const [prefilledInvite,setPrefilledInvite]=useState('');

  // Public form mode: ?form=<slug> renders the public form without login
  const publicFormSlug=(()=>{try{return new URLSearchParams(window.location.search).get('form');}catch(e){return null;}})();
  if(publicFormSlug)return <PublicFormPage slug={publicFormSlug}/>;

  // Password reset mode: ?reset=TOKEN
  const resetToken=(()=>{try{return new URLSearchParams(window.location.search).get('reset');}catch(e){return null;}})();
  if(resetToken&&SELF_HOSTED)return <ResetPasswordScreen token={resetToken}/>;

  useEffect(()=>{
    // Read ?invite=CODE from URL
    try{
      const params=new URLSearchParams(window.location.search);
      const inv=params.get('invite');
      if(inv) setPrefilledInvite(inv.trim());
    }catch(e){}
    // Try auto-login with stored device key (no password needed on same device)
    (async()=>{
      // Determine if any auth exists (server is source of truth in self-hosted mode)
      let serverAuth = false;
      if (SELF_HOSTED && window.WEBARS_API_TOKEN) {
        try { serverAuth = await serverHasAuth(); } catch(e) {}
      }
      const anyAuth = serverAuth || hasSetup();

      if(anyAuth && localStorage.getItem(PKEY_ENC_STORE)){
        try{
          const dk = await getOrCreateDeviceKey();
          const b64key = await aesDecrypt(dk, JSON.parse(localStorage.getItem(PKEY_ENC_STORE)));
          const key = await crypto.subtle.importKey('raw',fromB64(b64key),{name:'AES-GCM',length:256},true,['encrypt','decrypt']);
          if(key){
            if(hasGithubSettings()){
              try{ await loadGithubSettings(key); }catch(e){}
            }
            let data;
            try {
              data = await loadEncrypted(key);
            } catch(loadErr) {
              if (loadErr && loadErr.message === 'KEY_MISMATCH') {
                // Stored device-key cannot decrypt server data → force fresh password login
                console.warn('[auto-login] key mismatch — clearing device key, going to login');
                localStorage.removeItem(PKEY_ENC_STORE);
                localStorage.removeItem(DEVICE_KEY_STORE);
                setPhase('login');
                return;
              }
              throw loadErr;
            }
            console.log('[auto-login] success');
            setCryptoKey(key); setCrmData(data || DEFAULT_STATE); setPhase('app'); return;
          }
        }catch(e){ console.warn('[auto-login] failed:', e); }
      }
      setPhase(anyAuth?'login':'setup');
    })();
  },[]);

  const handleReset=()=>{
    // In self-hosted mode the server holds the canonical auth + data.
    // This button only clears the LOCAL CACHE — it no longer destroys server data.
    // The user can always log back in with their password.
    if(SELF_HOSTED){
      if(!window.confirm('Lokalen Cache leeren?\n\nDeine Daten am Server bleiben sicher. Du musst dich danach mit deinem Passwort neu anmelden.'))return;
    } else {
      if(!window.confirm(`Alle lokalen Daten löschen?\n\nWiederherstellungskontakt: ${RECOVERY_EMAIL}`))return;
    }
    [SALT_KEY,VERIFY_KEY,TOTP_KEY,DATA_KEY,EMAIL_HASH_KEY,INVITES_KEY,DEVICE_KEY_STORE,TOTP_ENC_STORE,PKEY_ENC_STORE,GH_SETTINGS_KEY,MASTER_KEY_STORE].forEach(k=>localStorage.removeItem(k));
    clearGithubSettings();
    // In self-hosted mode, server auth-blob still exists → go to login, NOT setup
    if(SELF_HOSTED) { setPhase('login'); }
    else { setPhase('setup'); }
  };

  const handleLogout=()=>{
    clearGithubSettings();
    localStorage.removeItem(PKEY_ENC_STORE);
    setCryptoKey(null);
    setCrmData(null);
    setPhase('login');
  };

  if(phase==='loading')return(
    <div style={{height:'100vh',background:'#0F0E0C',display:'flex',alignItems:'center',justifyContent:'center'}}>
      <span style={{width:28,height:28,border:'2.5px solid rgba(255,255,255,.1)',borderTopColor:'white',borderRadius:'50%',animation:'spin .7s linear infinite',display:'block'}}></span>
    </div>
  );

  const completeAuth = async (key, data, email) => {
    // Load GitHub settings if configured, then refresh data from GitHub
    if (hasGithubSettings()) {
      try {
        await loadGithubSettings(key);
        const fresh = await loadEncrypted(key);
        if (fresh) data = fresh;
      } catch(e) { console.warn('GitHub sync init failed', e); }
    }
    // Silently update key escrow so password reset works in the future
    escrowMasterKey(key).catch(()=>{});
    setCryptoKey(key);
    setCrmData(data);
    setPhase('app');
  };

  if(phase==='setup')return <AuthScreen mode="setup" onDone={completeAuth} onSwitchMode={()=>setPhase('login')}/>;
  if(phase==='login')return <AuthScreen mode="login" onDone={completeAuth} onSwitchMode={()=>setPhase('setup')} onForgotPassword={SELF_HOSTED?()=>setPhase('forgot'):null}/>;
  if(phase==='forgot')return <ForgotPasswordScreen onBack={()=>setPhase('login')}/>;
  if(phase==='app'&&cryptoKey&&crmData)return <CRMApp cryptoKey={cryptoKey} initialData={crmData} onLock={()=>setPhase('login')} onLogout={handleLogout}/>;
  return null;
}

export { CRMApp, DEFAULT_STATE };
