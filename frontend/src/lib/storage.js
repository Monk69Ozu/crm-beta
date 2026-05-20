// localStorage-Schluessel und einfache Wrapper fuer das WebArs CRM.
// WICHTIG: Alle Key-Strings sind 1:1 aus legacy/index.html uebernommen — bei
// einer Aenderung wuerden bestehende User ausgesperrt (kein Master-Key mehr
// auffindbar). Die "_v1"-Suffixe sind absichtlich konserviert.

import {
  toB64,
  fromB64,
  sha256b64,
  aesEncrypt,
  aesDecrypt,
} from './crypto.js';

// ── E-Mails (Konfiguration) ───────────────────────────────────────────────
export const RECOVERY_EMAIL = 'turleat@gmail.com';
export const OWNER_EMAIL = 'turlea@webars.at';

// ── localStorage-Keys ─────────────────────────────────────────────────────
export const SALT_KEY = 'webars_salt_v1';
export const VERIFY_KEY = 'webars_verify_v1';
export const TOTP_KEY = 'webars_totp_v1';
export const DATA_KEY = 'webars_data_v1';
export const INVITES_KEY = 'webars_invites_v1';
export const EMAIL_HASH_KEY = 'webars_email_v1';
export const MASTER_KEY_STORE = 'webars_master_v1';
export const DEVICE_KEY_STORE = 'webars_dkey_v1';
export const TOTP_ENC_STORE = 'webars_totp_denc_v1';
export const PKEY_ENC_STORE = 'webars_pkey_denc_v1';
export const LOGIN_ATTEMPTS_KEY = 'webars_login_attempts_v1';

// GitHub-Sync (Legacy / GitHub-Pages-Modus)
export const GH_SETTINGS_KEY = 'webars_gh_settings_v1';
export const GH_SHA_KEY = 'webars_gh_sha_v1';
export const GH_GIST_KEY = 'webars_jarvis_gist_v1';
export const DATA_BACKUP_KEY = 'webars_data_backup_v1';
export const SNAP_PREFIX = 'webars_snap_v2_';
export const SNAP_SLOTS = 5;

// ── Konstanten ────────────────────────────────────────────────────────────
export const VERIFY_STR = 'WEBARS_AUTH_OK_2026';
export const IDLE_TIMEOUT_MS = 15 * 60 * 1000;
export const PBKDF2_ITER_NEW = 600000;
export const RECOVERY_REPO = 'Tatstast/crm-system';

// ── Salt-Handling ─────────────────────────────────────────────────────────
// Liest den lokalen Salt, oder erzeugt einen frischen 16-Byte-Salt und
// persistiert ihn. Nur fuer den Legacy-Pfad relevant — der Server-Auth-Pfad
// (auth-blob) benutzt einen global-on-server Salt von 32 Byte.
export function getSalt() {
  const s = localStorage.getItem(SALT_KEY);
  if (s) return fromB64(s);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  localStorage.setItem(SALT_KEY, toB64(salt));
  return salt;
}

// ── Setup-Status-Checks ───────────────────────────────────────────────────
export function hasSetup() {
  return (
    !!localStorage.getItem(VERIFY_KEY) &&
    !!localStorage.getItem(MASTER_KEY_STORE)
  );
}

export function hasTOTP() {
  return !!localStorage.getItem(TOTP_KEY);
}

export function hasEmailHash() {
  return !!localStorage.getItem(EMAIL_HASH_KEY);
}

export function hasDeviceKeySetup() {
  return (
    !!localStorage.getItem(TOTP_ENC_STORE) &&
    !!localStorage.getItem(PKEY_ENC_STORE)
  );
}

// ── E-Mail-Hash (verhindert Login-Versuche mit falscher Mail) ─────────────
export async function storeEmailHash(email) {
  const hash = await sha256b64('WEBARS_EMAIL_' + email.trim().toLowerCase());
  localStorage.setItem(EMAIL_HASH_KEY, hash);
}

export async function checkEmailHash(email) {
  const stored = localStorage.getItem(EMAIL_HASH_KEY);
  if (!stored) return true; // legacy: kein Hash gespeichert, durchlassen
  const hash = await sha256b64('WEBARS_EMAIL_' + email.trim().toLowerCase());
  return hash === stored;
}

// ── Login-Lockout (3 Fehlversuche → 5 min, dann 1 h, dann 24 h) ──────────
export function getLoginLockout() {
  try {
    const a = JSON.parse(localStorage.getItem(LOGIN_ATTEMPTS_KEY) || '{}');
    if (a.until && a.until > Date.now())
      return Math.ceil((a.until - Date.now()) / 1000);
    return 0;
  } catch {
    return 0;
  }
}

export function recordLoginFailure() {
  let a = { count: 0 };
  try {
    a = JSON.parse(localStorage.getItem(LOGIN_ATTEMPTS_KEY) || '{}');
  } catch {}
  a.count = (a.count || 0) + 1;
  if (a.count >= 3) {
    const tier = Math.floor((a.count - 3) / 3);
    const lockMin = [5, 60, 60 * 24][Math.min(tier, 2)] || 60 * 24;
    a.until = Date.now() + lockMin * 60 * 1000;
    a.lockMin = lockMin;
  }
  localStorage.setItem(LOGIN_ATTEMPTS_KEY, JSON.stringify(a));
  return {
    count: a.count,
    lockSeconds: a.until ? Math.ceil((a.until - Date.now()) / 1000) : 0,
    lockMin: a.lockMin || 0,
  };
}

export function clearLoginAttempts() {
  localStorage.removeItem(LOGIN_ATTEMPTS_KEY);
}

// ── TOTP-Secret (verschluesselt mit dem wrap-key) ─────────────────────────
export async function saveTOTPSecret(key, secret) {
  localStorage.setItem(TOTP_KEY, JSON.stringify(await aesEncrypt(key, secret)));
}

export async function loadTOTPSecret(key) {
  const raw = localStorage.getItem(TOTP_KEY);
  if (!raw) return null;
  try {
    return await aesDecrypt(key, JSON.parse(raw));
  } catch {
    return null;
  }
}
