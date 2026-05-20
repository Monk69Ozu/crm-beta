// TOTP (RFC 6238) — Base32, Secret-Generator, HMAC-SHA-1-Berechnung,
// otpauth://-URL fuer QR-Code. 1:1 aus legacy/index.html (Z. 1113-1150).

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(bytes) {
  let bits = 0,
    val = 0,
    out = '';
  for (const b of bytes) {
    val = (val << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += B32[(val >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(val << (5 - bits)) & 31];
  return out;
}

export function base32Decode(s) {
  s = s.toUpperCase().replace(/=+$/, '');
  let bits = 0,
    val = 0;
  const out = [];
  for (const c of s) {
    const i = B32.indexOf(c);
    if (i < 0) continue;
    val = (val << 5) | i;
    bits += 5;
    if (bits >= 8) {
      out.push((val >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

export function generateTOTPSecret() {
  return base32Encode(crypto.getRandomValues(new Uint8Array(20)));
}

// Berechnet TOTP-Code (6 Stellen) fuer einen gegebenen 30-s-Counter.
export async function computeTOTP(secretB32, timeCounter) {
  const key = await crypto.subtle.importKey(
    'raw',
    base32Decode(secretB32),
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign'],
  );
  const buf = new ArrayBuffer(8);
  new DataView(buf).setUint32(4, timeCounter >>> 0, false);
  const hmac = new Uint8Array(await crypto.subtle.sign('HMAC', key, buf));
  const off = hmac[19] & 0xf;
  const code =
    ((hmac[off] & 0x7f) << 24 |
      hmac[off + 1] << 16 |
      hmac[off + 2] << 8 |
      hmac[off + 3]) %
    1000000;
  return code.toString().padStart(6, '0');
}

// Akzeptiert den aktuellen und beide Nachbar-Counter (±30 s Clock-Skew).
export async function verifyTOTP(secretB32, userCode) {
  const clean = userCode.replace(/\s/g, '');
  if (clean.length !== 6) return false;
  const t = Math.floor(Date.now() / 1000 / 30);
  for (let d = -1; d <= 1; d++) {
    if ((await computeTOTP(secretB32, t + d)) === clean) return true;
  }
  return false;
}

// otpauth://-URL fuer Google Authenticator / Authy / 1Password.
export function makeOTPAuthURL(secret, email = 'WebArs CRM') {
  return (
    `otpauth://totp/${encodeURIComponent('WebArs CRM')}:${encodeURIComponent(email)}` +
    `?secret=${secret}&issuer=${encodeURIComponent('WebArs CRM')}` +
    `&algorithm=SHA1&digits=6&period=30`
  );
}
