import { useState } from 'react';
import { verifyPassword } from '../lib/auth.js';
import { storeKeyForDevice } from '../lib/device.js';
import { loadEncryptedFromServer } from '../lib/data.js';
import PasswordInput from '../components/PasswordInput.jsx';

// Lock-Overlay nach Idle-Timeout. 1:1 aus legacy/index.html (Zeilen 1479-1525)
// mit derselben loadEncryptedFromServer-Vereinfachung wie AuthScreen.
export default function LockOverlay({ onUnlock }) {
  const [pw, setPw] = useState('');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    setBusy(true);
    setErr('');
    try {
      const key = await verifyPassword(pw);
      if (!key) {
        setErr('Falsches Passwort.');
        setBusy(false);
        return;
      }
      let data = null;
      try {
        data = await loadEncryptedFromServer(key);
      } catch (loadErr) {
        if (loadErr && loadErr.code === 'KEY_MISMATCH') {
          setErr(
            'Schlüssel passt nicht zu den Server-Daten. Bitte neu anmelden.',
          );
          setBusy(false);
          return;
        }
        throw loadErr;
      }
      try {
        await storeKeyForDevice(key);
      } catch {}
      onUnlock(key, data);
    } catch (e) {
      setErr('Fehler beim Entsperren: ' + (e?.message || ''));
      setBusy(false);
    }
  };

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(10,9,7,0.95)',
        backdropFilter: 'blur(20px)',
        zIndex: 9999,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: 20,
      }}
    >
      <div style={{ width: 360, display: 'grid', gap: 20 }}>
        <div style={{ textAlign: 'center' }}>
          <img
            src="/logo.png"
            alt="WebArs"
            style={{
              width: 52,
              height: 52,
              borderRadius: '50%',
              marginBottom: 14,
              boxShadow: '0 8px 24px rgba(0,0,0,0.4)',
            }}
          />
          <div style={{ fontWeight: 800, fontSize: 20, color: 'white' }}>
            WebArs CRM
          </div>
          <div
            style={{
              fontSize: 13,
              color: 'rgba(255,255,255,0.3)',
              marginTop: 4,
            }}
          >
            Gesperrt — Passwort eingeben
          </div>
        </div>
        <div className="auth-panel" style={{ display: 'grid', gap: 14 }}>
          <PasswordInput
            value={pw}
            onChange={(e) => setPw(e.target.value)}
            placeholder="Passwort"
            autoFocus
            onKeyDown={(e) => e.key === 'Enter' && !busy && pw && submit()}
          />
          {err && (
            <div
              style={{
                fontSize: 12.5,
                color: '#F87171',
                textAlign: 'center',
              }}
            >
              {err}
            </div>
          )}
          <button
            className="btn auth-btn"
            onClick={submit}
            disabled={busy || !pw}
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
              'Entsperren →'
            )}
          </button>
        </div>
      </div>
    </div>
  );
}
