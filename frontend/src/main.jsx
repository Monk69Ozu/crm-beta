// Vite-Entry-Point fuer das WebArs CRM Frontend.
//
// Session 1 (heute): Skeleton + lib/-Smoke-Test. Keine echten UI-Komponenten.
// Spaetere Sessions ersetzen den Smoke-Test durch <AuthWrapper /> und CRMApp.

import {
  sha256b64,
  emailHash16,
  generateRecoveryCode,
} from './lib/crypto.js';
import {
  SALT_KEY,
  VERIFY_KEY,
  MASTER_KEY_STORE,
  PBKDF2_ITER_NEW,
  hasSetup,
  hasTOTP,
} from './lib/storage.js';
import { SELF_HOSTED, apiToken, fetchServerAuthBlob } from './lib/api.js';

const root = document.getElementById('root');

async function smokeTest() {
  if (!root) return;
  const lines = [];
  lines.push(`SELF_HOSTED=${SELF_HOSTED}`);
  lines.push(`HAS_TOKEN=${apiToken() ? 'yes' : 'no'}`);
  lines.push(`PBKDF2_ITER_NEW=${PBKDF2_ITER_NEW}`);
  lines.push(`STORAGE_KEYS=${[SALT_KEY, VERIFY_KEY, MASTER_KEY_STORE].join(', ')}`);
  lines.push(`hasSetup()=${hasSetup()}`);
  lines.push(`hasTOTP()=${hasTOTP()}`);
  try {
    const h = await sha256b64('vite-skeleton-check');
    lines.push(`sha256b64('vite-skeleton-check')=${h.slice(0, 12)}...`);
    const e = await emailHash16('test@example.com');
    lines.push(`emailHash16('test@example.com')=${e}`);
    lines.push(`generateRecoveryCode()=${generateRecoveryCode()}`);
  } catch (err) {
    lines.push(`CRYPTO_ERROR: ${err.message}`);
  }
  if (SELF_HOSTED) {
    try {
      const ab = await fetchServerAuthBlob();
      lines.push(`server.auth-blob.exists=${ab && ab.exists}`);
    } catch (err) {
      lines.push(`server.auth-blob.ERROR=${err.message}`);
    }
  }
  root.innerHTML =
    '<pre style="font-family:monospace;padding:24px;line-height:1.6">' +
    lines.map((l) => l.replace(/</g, '&lt;')).join('\n') +
    '</pre>';
}

smokeTest();
