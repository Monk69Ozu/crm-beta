// Device-Key-Helper fuer schnelles Re-Unlock auf demselben Geraet.
// 1:1 aus legacy/index.html (Zeilen 1076-1111).
//
// Ein zufaelliger 256-Bit-Schluessel wird pro Geraet einmal generiert und in
// localStorage abgelegt. Damit wird der Master-Key (oder TOTP-Secret) im
// SessionStore verschluesselt, sodass die App nach einem Tab-Wechsel ohne
// Passwort entsperren kann, aber ein anderer User am gleichen Computer
// ohne API_SECRET nichts damit anfangen kann (Master-Key bleibt zudem
// optional an einen TOTP-Code gekoppelt).

import { toB64, fromB64, aesEncrypt, aesDecrypt } from './crypto.js';
import {
  DEVICE_KEY_STORE,
  PKEY_ENC_STORE,
  TOTP_ENC_STORE,
} from './storage.js';
import { verifyTOTP } from './totp.js';

export async function getOrCreateDeviceKey() {
  const stored = localStorage.getItem(DEVICE_KEY_STORE);
  if (stored) {
    return crypto.subtle.importKey(
      'raw',
      fromB64(stored),
      'AES-GCM',
      false,
      ['encrypt', 'decrypt'],
    );
  }
  const key = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt'],
  );
  const exp = await crypto.subtle.exportKey('raw', key);
  localStorage.setItem(DEVICE_KEY_STORE, toB64(exp));
  return key;
}

export async function storeKeyForDevice(cryptoKey) {
  const dk = await getOrCreateDeviceKey();
  const rawKey = await crypto.subtle.exportKey('raw', cryptoKey);
  localStorage.setItem(
    PKEY_ENC_STORE,
    JSON.stringify(await aesEncrypt(dk, toB64(rawKey))),
  );
}

export async function storeTOTPAndKeyForDevice(totpSecret, cryptoKey) {
  const dk = await getOrCreateDeviceKey();
  localStorage.setItem(
    TOTP_ENC_STORE,
    JSON.stringify(await aesEncrypt(dk, totpSecret)),
  );
  const rawKey = await crypto.subtle.exportKey('raw', cryptoKey);
  localStorage.setItem(
    PKEY_ENC_STORE,
    JSON.stringify(await aesEncrypt(dk, toB64(rawKey))),
  );
}

export async function loginWithTOTPCode(code) {
  const totpRaw = localStorage.getItem(TOTP_ENC_STORE);
  const pkeyRaw = localStorage.getItem(PKEY_ENC_STORE);
  if (!totpRaw || !pkeyRaw) return null;
  const dk = await getOrCreateDeviceKey();
  try {
    const totpSecret = await aesDecrypt(dk, JSON.parse(totpRaw));
    const ok = await verifyTOTP(totpSecret, code);
    if (!ok) return false;
    const b64key = await aesDecrypt(dk, JSON.parse(pkeyRaw));
    return crypto.subtle.importKey(
      'raw',
      fromB64(b64key),
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
  } catch {
    return null;
  }
}
