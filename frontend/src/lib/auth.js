// High-Level-Auth-Flows fuer das WebArs CRM.
//
// Diese Datei kombiniert crypto + storage + api zu den Top-Level-Operationen,
// die direkt von den Auth-Screens aufgerufen werden:
//
//   - setupPassword       — Erst-Setup mit Passwort
//   - verifyPassword      — Login mit Passwort, gibt MasterKey zurueck
//   - changePassword      — Passwort aendern (Master-Key bleibt erhalten)
//   - escrowMasterKey     — Legacy-Escrow auf Server (Read-Only-Fallback)
//   - unescrowMasterKey   — Master-Key aus Escrow-Blob recovern
//   - rewrapMasterKey     — Lokales Re-Wrap mit neuem Passwort (Legacy)
//
// 1:1-Logik aus legacy/index.html — siehe Zeilen 163-594 dort. Verhalten
// MUSS identisch bleiben, sonst werden bestehende User ausgesperrt.

import {
  toB64,
  fromB64,
  aesEncrypt,
  aesDecrypt,
  deriveKey,
  deriveEscrowKey,
  generateMasterKey,
  exportMasterKeyB64,
  importMasterKeyFromB64,
} from './crypto.js';
import {
  SALT_KEY,
  VERIFY_KEY,
  MASTER_KEY_STORE,
  VERIFY_STR,
  PBKDF2_ITER_NEW,
  getSalt,
} from './storage.js';
import {
  SELF_HOSTED,
  apiToken,
  authHeaders,
  fetchServerAuthBlob,
  apiInitAuthBlob,
  apiUpdateAuthBlob,
} from './api.js';

// ─────────────────────────────────────────────────────────────────────────
//  SERVER-BACKED AUTH (auth-blob model)
// ─────────────────────────────────────────────────────────────────────────
// Server-Row crm_auth (id=1) ist Source-of-Truth. Selber Passwort + selber
// Master-Key auf jedem Geraet — kein per-Device-Salt mehr in localStorage.

export async function setupPasswordServer(password, providedMasterKeyB64 = null) {
  // 1) Frischer Salt + Master-Key
  const saltBytes = crypto.getRandomValues(new Uint8Array(32));
  const saltB64 = toB64(saltBytes);
  const masterKey = providedMasterKeyB64
    ? await importMasterKeyFromB64(providedMasterKeyB64)
    : await generateMasterKey();
  const masterB64 = await exportMasterKeyB64(masterKey);

  // 2) Master mit PBKDF2(password, salt, 600k) wrappen
  const wrapKey = await deriveKey(password, saltBytes, PBKDF2_ITER_NEW);
  const wrapped_master = await aesEncrypt(wrapKey, masterB64);

  // 3) Escrow-Blob (Master verschluesselt mit API_SECRET-derivierter Key)
  const escrowKey = await deriveEscrowKey();
  const escrow_blob = await aesEncrypt(escrowKey, masterB64);

  // 4) POST /api/auth-blob/init — Server antwortet 409 bei vorhandener Row
  await apiInitAuthBlob({
    salt: saltB64,
    wrapped_master,
    escrow_blob,
    pbkdf2_iter: PBKDF2_ITER_NEW,
  });

  // 5) Offline-Cache (Server bleibt Source-of-Truth)
  localStorage.setItem(SALT_KEY, saltB64);
  localStorage.setItem(
    VERIFY_KEY,
    JSON.stringify(await aesEncrypt(wrapKey, VERIFY_STR)),
  );
  localStorage.setItem(MASTER_KEY_STORE, JSON.stringify(wrapped_master));
  return masterKey;
}

export async function verifyPasswordServer(password) {
  const ab = await fetchServerAuthBlob();
  if (!ab || !ab.exists) return { status: 'no-server-auth' };
  try {
    const saltBytes = fromB64(ab.salt);
    const wrapKey = await deriveKey(
      password,
      saltBytes,
      ab.pbkdf2_iter || PBKDF2_ITER_NEW,
    );
    const masterB64 = await aesDecrypt(wrapKey, ab.wrapped_master);
    const masterKey = await importMasterKeyFromB64(masterB64);
    // Lokalen Cache aktualisieren
    localStorage.setItem(SALT_KEY, ab.salt);
    localStorage.setItem(
      VERIFY_KEY,
      JSON.stringify(await aesEncrypt(wrapKey, VERIFY_STR)),
    );
    localStorage.setItem(MASTER_KEY_STORE, JSON.stringify(ab.wrapped_master));
    return { status: 'ok', masterKey };
  } catch {
    return { status: 'wrong-password' };
  }
}

// Passwort aendern: nur wrapped_master wird ersetzt. Salt + Escrow bleiben.
export async function changePasswordServer(masterKey, newPassword) {
  const ab = await fetchServerAuthBlob();
  if (!ab || !ab.exists)
    throw new Error('Kein Server-Auth — bitte zuerst Setup machen');
  const saltBytes = fromB64(ab.salt);
  const iter = ab.pbkdf2_iter || PBKDF2_ITER_NEW;
  const wrapKey = await deriveKey(newPassword, saltBytes, iter);
  const masterB64 = await exportMasterKeyB64(masterKey);
  const wrapped_master = await aesEncrypt(wrapKey, masterB64);
  await apiUpdateAuthBlob({ wrapped_master });
  // Cache aktualisieren
  localStorage.setItem(SALT_KEY, ab.salt);
  localStorage.setItem(
    VERIFY_KEY,
    JSON.stringify(await aesEncrypt(wrapKey, VERIFY_STR)),
  );
  localStorage.setItem(MASTER_KEY_STORE, JSON.stringify(wrapped_master));
}

// Auto-Migration: lokales Setup vorhanden, aber Server-Auth-Blob noch nicht.
// Push lokal abgeleiteten Auth-Blob auf Server (idempotent — wenn Server schon
// initialisiert ist, bricht der Call mit AUTH_ALREADY_EXISTS ab).
export async function ensureServerAuthMigrated(password, masterKey) {
  if (!SELF_HOSTED || !apiToken()) return;
  try {
    const ab = await fetchServerAuthBlob();
    if (ab && ab.exists) return; // schon migriert
    const saltBytes = crypto.getRandomValues(new Uint8Array(32));
    const saltB64 = toB64(saltBytes);
    const wrapKey = await deriveKey(password, saltBytes, PBKDF2_ITER_NEW);
    const masterB64 = await exportMasterKeyB64(masterKey);
    const wrapped_master = await aesEncrypt(wrapKey, masterB64);
    const escrowKey = await deriveEscrowKey();
    const escrow_blob = await aesEncrypt(escrowKey, masterB64);
    await apiInitAuthBlob({
      salt: saltB64,
      wrapped_master,
      escrow_blob,
      pbkdf2_iter: PBKDF2_ITER_NEW,
    });
    console.log('[migration] Pushed local auth -> server auth-blob');
    localStorage.setItem(SALT_KEY, saltB64);
    localStorage.setItem(
      VERIFY_KEY,
      JSON.stringify(await aesEncrypt(wrapKey, VERIFY_STR)),
    );
    localStorage.setItem(MASTER_KEY_STORE, JSON.stringify(wrapped_master));
  } catch (e) {
    console.warn('[migration] failed:', e.message);
  }
}

// ─────────────────────────────────────────────────────────────────────────
//  LEGACY ESCROW (kept for read-only Fallback alter Reset-Tokens)
// ─────────────────────────────────────────────────────────────────────────
// Neuer Code schreibt NIE in /api/key-escrow — die `escrowMasterKey`-
// Funktion bleibt nur, weil aelter erzeugte Reset-Tokens auf diesem Pfad
// zurueckgreifen koennten. Sie hat eine Schutzklausel die das Ueberschreiben
// existierender Escrow-Schluessel verhindert (verhindert Datenverlust).
export async function escrowMasterKey(masterKey) {
  if (!SELF_HOSTED || !apiToken()) return;
  try {
    const escrowKey = await deriveEscrowKey();
    const rawMk = await crypto.subtle.exportKey('raw', masterKey);
    const newMkB64 = toB64(rawMk);

    // SAFETY: Existierenden Escrow nur ueberschreiben, wenn der dort
    // hinterlegte Key NICHT mehr die Server-Daten entschluesselt.
    try {
      const checkR = await fetch('/api/key-escrow', {
        headers: { Authorization: `Bearer ${apiToken()}` },
      });
      if (checkR.ok) {
        const existing = await checkR.json();
        let existingMkB64 = null;
        try {
          existingMkB64 = await aesDecrypt(escrowKey, existing);
        } catch {}
        if (existingMkB64 && existingMkB64 !== newMkB64) {
          try {
            const dr = await fetch('/api/data', {
              headers: { Authorization: `Bearer ${apiToken()}` },
            });
            if (dr.ok) {
              const dj = await dr.json();
              if (dj.content) {
                const existingMk = await importMasterKeyFromB64(existingMkB64);
                try {
                  await aesDecrypt(existingMk, dj.content);
                  console.warn(
                    '[escrow] Refusing to overwrite — existing escrow key still decrypts server data',
                  );
                  return; // NICHT ueberschreiben
                } catch {}
              }
            }
          } catch {}
        }
      }
    } catch {}

    const encrypted = await aesEncrypt(escrowKey, newMkB64);
    await fetch('/api/key-escrow', {
      method: 'PUT',
      headers: authHeaders(),
      body: JSON.stringify(encrypted),
    });
  } catch (e) {
    console.warn('Key escrow update failed:', e);
  }
}

export async function unescrowMasterKey(escrowBlob) {
  const escrowKey = await deriveEscrowKey();
  const mkB64 = await aesDecrypt(escrowKey, escrowBlob);
  return importMasterKeyFromB64(mkB64);
}

// ─────────────────────────────────────────────────────────────────────────
//  LEGACY LOCAL PATH (GitHub-Pages / pre-auth-blob installs)
// ─────────────────────────────────────────────────────────────────────────
// Wird auch von Auto-Migration genutzt — wenn ein User von einer aelteren
// Installation kommt und der Server-Auth-Blob noch nicht existiert.

export async function rewrapMasterKey(masterKey, newPassword) {
  localStorage.removeItem(SALT_KEY);
  const salt = getSalt();
  const wrapKey = await deriveKey(newPassword, salt);
  localStorage.setItem(
    VERIFY_KEY,
    JSON.stringify(await aesEncrypt(wrapKey, VERIFY_STR)),
  );
  const masterB64 = await exportMasterKeyB64(masterKey);
  localStorage.setItem(
    MASTER_KEY_STORE,
    JSON.stringify(await aesEncrypt(wrapKey, masterB64)),
  );
}

// ─────────────────────────────────────────────────────────────────────────
//  TOP-LEVEL WRAPPER (selbe Signaturen wie im Original)
// ─────────────────────────────────────────────────────────────────────────

export async function setupPassword(password, providedMasterKeyB64 = null) {
  // Self-hosted: Server-Auth-Blob ist Source-of-Truth
  if (SELF_HOSTED && apiToken()) {
    return setupPasswordServer(password, providedMasterKeyB64);
  }
  // Legacy local-only (GitHub-Pages-Modus)
  localStorage.removeItem(SALT_KEY);
  const salt = getSalt();
  const wrapKey = await deriveKey(password, salt);
  localStorage.setItem(
    VERIFY_KEY,
    JSON.stringify(await aesEncrypt(wrapKey, VERIFY_STR)),
  );
  const masterKey = providedMasterKeyB64
    ? await importMasterKeyFromB64(providedMasterKeyB64)
    : await generateMasterKey();
  const masterB64 = await exportMasterKeyB64(masterKey);
  localStorage.setItem(
    MASTER_KEY_STORE,
    JSON.stringify(await aesEncrypt(wrapKey, masterB64)),
  );
  return masterKey;
}

export async function verifyPassword(password) {
  // Self-hosted: erst Server-Auth-Blob probieren (Source-of-Truth)
  if (SELF_HOSTED && apiToken()) {
    const r = await verifyPasswordServer(password);
    if (r.status === 'ok') return r.masterKey;
    if (r.status === 'wrong-password') return null;
    // 'no-server-auth' -> faellt durch zum Legacy-Pfad + Auto-Migration
  }
  // Legacy local path (auch fuer Migration genutzt)
  const localSaltB64 = localStorage.getItem(SALT_KEY);
  if (!localSaltB64) {
    console.error('[auth] No salt in localStorage');
    return null;
  }
  const salt = fromB64(localSaltB64);
  const wrapKey = await deriveKey(password, salt);
  try {
    const verifyRaw = localStorage.getItem(VERIFY_KEY);
    if (!verifyRaw) {
      console.error('[auth] VERIFY_KEY missing');
      return null;
    }
    let verifyBlob;
    try {
      verifyBlob = JSON.parse(verifyRaw);
    } catch {
      console.error('[auth] VERIFY_KEY not valid JSON');
      return null;
    }
    const v = await aesDecrypt(wrapKey, verifyBlob);
    if (v !== VERIFY_STR) {
      console.error('[auth] Verify string mismatch — wrong password');
      return null;
    }
    const mkRaw = localStorage.getItem(MASTER_KEY_STORE);
    if (!mkRaw) {
      console.error('[auth] MASTER_KEY_STORE missing');
      return null;
    }
    const mkB64 = await aesDecrypt(wrapKey, JSON.parse(mkRaw));
    const masterKey = await importMasterKeyFromB64(mkB64);
    // One-shot Auto-Migration zum Server-Auth-Blob
    if (SELF_HOSTED && apiToken()) {
      ensureServerAuthMigrated(password, masterKey).catch(() => {});
    }
    return masterKey;
  } catch (e) {
    console.error('[auth] verifyPassword failed:', e.message);
    return null;
  }
}

// Convenience-Wrapper, einige Komponenten verwenden diesen Namen.
export async function changePassword(masterKey, newPassword) {
  if (SELF_HOSTED && apiToken()) {
    return changePasswordServer(masterKey, newPassword);
  }
  return rewrapMasterKey(masterKey, newPassword);
}
