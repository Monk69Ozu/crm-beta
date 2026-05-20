import { useState } from 'react';
import {
  fromB64,
  deriveKey,
  deriveEscrowKey,
  aesEncrypt,
  aesDecrypt,
  importMasterKeyFromB64,
} from '../lib/crypto.js';
import {
  SALT_KEY,
  VERIFY_KEY,
  MASTER_KEY_STORE,
  VERIFY_STR,
} from '../lib/storage.js';
import { rewrapMasterKey } from '../lib/auth.js';
import { storeKeyForDevice } from '../lib/device.js';
import PasswordInput from '../components/PasswordInput.jsx';

// 1:1 aus legacy/index.html (Zeilen 1605-1686).
// Aufgerufen wenn URL ?reset=<token> enthaelt. Holt Reset-Token vom Server,
// entschluesselt Escrow-Blob mit API_SECRET-derived Key, re-wrapped Master-Key
// mit neuem Passwort, sendet wrapped_master atomic ans Server.
export default function ResetPasswordScreen({ token }) {
  const [pw, setPw] = useState('');
  const [pw2, setPw2] = useState('');
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);
  const [err, setErr] = useState('');

  const reset = async () => {
    if (pw.length < 8) {
      setErr('Mindestens 8 Zeichen.');
      return;
    }
    if (pw !== pw2) {
      setErr('Passwörter stimmen nicht überein.');
      return;
    }
    setBusy(true);
    setErr('');
    try {
      const r = await fetch(`/api/reset-token/${encodeURIComponent(token)}`);
      if (!r.ok) {
        const j = await r.json().catch(() => ({}));
        setErr(j.error || 'Token ungültig oder abgelaufen.');
        setBusy(false);
        return;
      }
      const j = await r.json();

      // Escrow-Blob mit API_SECRET-derived Key entschluesseln -> Master-Key
      const escrowKey = await deriveEscrowKey();
      const masterB64 = await aesDecrypt(escrowKey, j.escrow);
      const masterKey = await importMasterKeyFromB64(masterB64);

      if (j.scheme === 'auth-blob-v1') {
        // NEW model: re-wrap mit SERVER salt + iter, atomic confirm
        const saltBytes = fromB64(j.salt);
        const iter = j.pbkdf2_iter || 600000;
        const wrapKey = await deriveKey(pw, saltBytes, iter);
        const wrapped_master = await aesEncrypt(wrapKey, masterB64);
        const cr = await fetch(
          `/api/reset-token/${encodeURIComponent(token)}/confirm`,
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ wrapped_master }),
          },
        );
        if (!cr.ok) {
          const cj = await cr.json().catch(() => ({}));
          throw new Error(cj.error || 'Confirm fehlgeschlagen');
        }
        // Lokalen Cache aktualisieren
        localStorage.setItem(SALT_KEY, j.salt);
        localStorage.setItem(
          VERIFY_KEY,
          JSON.stringify(await aesEncrypt(wrapKey, VERIFY_STR)),
        );
        localStorage.setItem(MASTER_KEY_STORE, JSON.stringify(wrapped_master));
      } else {
        // LEGACY scheme: lokal re-wrap, dann confirm (Auto-Migrate beim
        // naechsten Login)
        await rewrapMasterKey(masterKey, pw);
        await fetch(
          `/api/reset-token/${encodeURIComponent(token)}/confirm`,
          { method: 'POST' },
        );
      }
      try {
        await storeKeyForDevice(masterKey);
      } catch {}
      window.history.replaceState({}, '', '/');
      setDone(true);
    } catch (e) {
      setErr('Fehler: ' + e.message);
    }
    setBusy(false);
  };

  return (
    <div className="auth-screen">
      <div className="auth-card">
        <div style={{ textAlign: 'center', marginBottom: 28 }}>
          <img
            src="/logo.png"
            alt="WebArs"
            style={{
              width: 60,
              height: 60,
              borderRadius: '50%',
              marginBottom: 14,
              boxShadow: '0 8px 24px rgba(0,0,0,0.4)',
            }}
          />
          <div
            style={{
              fontWeight: 800,
              fontSize: 22,
              color: 'white',
              letterSpacing: '-0.02em',
            }}
          >
            WebArs CRM
          </div>
          <div
            style={{
              fontSize: 13,
              color: 'rgba(255,255,255,0.35)',
              marginTop: 4,
            }}
          >
            Neues Passwort festlegen
          </div>
        </div>
        <div className="auth-panel" style={{ display: 'grid', gap: 14 }}>
          {done ? (
            <>
              <div
                style={{
                  fontSize: 14,
                  color: 'rgba(255,255,255,0.65)',
                  textAlign: 'center',
                  lineHeight: 1.7,
                  padding: '8px 0',
                }}
              >
                ✓ Passwort erfolgreich geändert!
                <br />
                <span
                  style={{
                    fontSize: 12.5,
                    color: 'rgba(255,255,255,0.35)',
                  }}
                >
                  Du kannst dich jetzt einloggen.
                </span>
              </div>
              <button
                className="btn auth-btn"
                onClick={() => (window.location.href = '/')}
              >
                Zum Login →
              </button>
            </>
          ) : (
            <>
              <PasswordInput
                value={pw}
                onChange={(e) => setPw(e.target.value)}
                placeholder="Neues Passwort (min. 8 Zeichen)"
                autoFocus
                onKeyDown={(e) => e.key === 'Enter' && !busy && reset()}
              />
              <PasswordInput
                value={pw2}
                onChange={(e) => setPw2(e.target.value)}
                placeholder="Passwort bestätigen"
                onKeyDown={(e) => e.key === 'Enter' && !busy && reset()}
              />
              {err && (
                <div
                  style={{
                    fontSize: 12.5,
                    color: '#F87171',
                    padding: '8px 12px',
                    background: 'rgba(248,113,113,0.1)',
                    borderRadius: 8,
                    textAlign: 'center',
                  }}
                >
                  {err}
                </div>
              )}
              <button
                className="btn auth-btn"
                onClick={reset}
                disabled={busy || !pw || !pw2}
              >
                {busy ? (
                  <>
                    <span
                      className="spinner"
                      style={{
                        borderTopColor: '#555',
                        borderColor: 'rgba(0,0,0,0.1)',
                      }}
                    ></span>{' '}
                    …
                  </>
                ) : (
                  'Passwort speichern →'
                )}
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
