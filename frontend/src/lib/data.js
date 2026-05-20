// Server-Daten-Layer (lightweight) fuer das WebArs CRM.
//
// In Session 2 brauchen wir nur loadEncrypted — Login + Lock-Overlay rufen es
// auf, um nach erfolgreichem verifyPassword die Server-Daten zu lesen und zu
// pruefen ob der Master-Key sie auch wirklich entschluesseln kann
// (KEY_MISMATCH-Detection).
//
// saveEncrypted (Versioning + GitHub-Sync) kommt in Session 3 mit dem
// vollstaendigen CRMApp-State-Management.

import { aesDecrypt } from './crypto.js';
import { authHeaders } from './api.js';

// Holt verschluesselten Daten-Blob vom Server und entschluesselt mit
// master-key. Bei "Wrong key" wirft eine Exception mit message='KEY_MISMATCH'
// — die UI muss das explizit fangen (siehe AuthScreen/LockOverlay).
export async function loadEncryptedFromServer(masterKey) {
  const r = await fetch('/api/data', { headers: authHeaders() });
  if (!r.ok) {
    if (r.status === 404) return null; // noch keine Daten
    throw new Error('Server-Fehler beim Daten-Laden: ' + r.status);
  }
  const j = await r.json();
  if (!j || !j.content) return null;
  try {
    return await aesDecrypt(masterKey, j.content);
  } catch {
    const err = new Error('KEY_MISMATCH');
    err.code = 'KEY_MISMATCH';
    throw err;
  }
}
