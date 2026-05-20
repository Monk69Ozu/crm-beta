import { useState } from 'react';
import { setupPassword, verifyPassword } from '../lib/auth.js';
import { storeEmailHash, OWNER_EMAIL } from '../lib/storage.js';
import { storeKeyForDevice } from '../lib/device.js';
import { SELF_HOSTED } from '../lib/api.js';
import PasswordInput from '../components/PasswordInput.jsx';

// AuthScreen — Setup ("Konto einrichten") + Login ("Anmelden").
// Funktionsgleich zu legacy/index.html (Zeilen 1351-1476), mit folgenden
// bewussten Abweichungen fuer die Migration:
//
//   - Setup-Flow ruft KEIN saveEncrypted(masterKey, DEFAULT_STATE) — die
//     Initialisierung von crm_data uebernimmt die CRMApp in Session 3.
//   - Login-Flow nutzt loadEncryptedFromServer (lightweight) statt das alte
//     loadEncrypted mit GitHub-Sync.
//
// Props:
//   mode               — 'login' | 'setup'
//   onDone(key, data, email) — wird nach erfolgreichem Login/Setup aufgerufen
//   onSwitchMode       — toggle login <-> setup (optional)
//   onForgotPassword   — fuehrt zum ForgotPasswordScreen (optional)
export default function AuthScreen({
  mode,
  onDone,
  onSwitchMode,
  onForgotPassword,
}) {
  const isSetup = mode === 'setup';
  const [email, setEmail] = useState(OWNER_EMAIL || '');
  const [pw, setPw] = useState('');
  const [pw2, setPw2] = useState('');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    if (isSetup) {
      if (!email.trim().includes('@')) {
        setErr('Bitte gültige E-Mail-Adresse eingeben.');
        return;
      }
      if (pw.length < 8) {
        setErr('Passwort: mindestens 8 Zeichen.');
        return;
      }
      if (pw !== pw2) {
        setErr('Passwörter stimmen nicht überein.');
        return;
      }
    }
    setBusy(true);
    setErr('');
    try {
      if (isSetup) {
        const trimmed = email.trim().toLowerCase();
        await storeEmailHash(trimmed);
        const masterKey = await setupPassword(pw);
        try {
          await storeKeyForDevice(masterKey);
        } catch {}
        // isSetup=true → completeAuth initialisiert die DB mit DEFAULT_STATE.
        onDone(masterKey, null, true);
      } else {
        const key = await verifyPassword(pw);
        if (!key) {
          setErr('Falsches Passwort.');
          setBusy(false);
          return;
        }
        try {
          await storeKeyForDevice(key);
        } catch {}
        // completeAuth laedt die aktuellen Server-Daten (inkl. KEY_MISMATCH-
        // Behandlung).
        onDone(key, null, false);
      }
    } catch (e) {
      const msg = e?.message || '';
      if (/AUTH_ALREADY_EXISTS/.test(msg)) {
        setErr(
          'Es existiert bereits ein Konto am Server. Bitte stattdessen anmelden.',
        );
        if (onSwitchMode) setTimeout(onSwitchMode, 1500);
      } else if (msg.startsWith('RATE_LIMITED:')) {
        setErr(msg.replace('RATE_LIMITED:', ''));
      } else {
        setErr('Fehler. Bitte erneut versuchen.');
      }
    }
    setBusy(false);
  };

  const S = {
    background: 'rgba(255,255,255,0.07)',
    border: '1.5px solid rgba(255,255,255,0.1)',
    borderRadius: 10,
    padding: '13px 14px',
    color: 'white',
    fontSize: 14,
    outline: 'none',
    width: '100%',
    boxSizing: 'border-box',
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
            {isSetup ? 'Konto einrichten' : 'Anmelden'}
          </div>
        </div>
        <div className="auth-panel" style={{ display: 'grid', gap: 14 }}>
          {isSetup && (
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="E-Mail-Adresse"
              autoFocus
              style={S}
              onKeyDown={(e) => e.key === 'Enter' && !busy && submit()}
            />
          )}
          <PasswordInput
            value={pw}
            onChange={(e) => setPw(e.target.value)}
            placeholder="Passwort"
            autoFocus={!isSetup}
            onKeyDown={(e) => e.key === 'Enter' && !busy && submit()}
          />
          {isSetup && (
            <PasswordInput
              value={pw2}
              onChange={(e) => setPw2(e.target.value)}
              placeholder="Passwort bestätigen"
              onKeyDown={(e) => e.key === 'Enter' && !busy && submit()}
            />
          )}
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
            ) : isSetup ? (
              'Konto erstellen →'
            ) : (
              'Anmelden →'
            )}
          </button>
        </div>
        {!isSetup && (
          <div
            style={{
              textAlign: 'center',
              marginTop: 14,
              display: 'flex',
              justifyContent: 'center',
              gap: 18,
              flexWrap: 'wrap',
            }}
          >
            {onForgotPassword && SELF_HOSTED && (
              <button
                onClick={onForgotPassword}
                style={{
                  background: 'none',
                  border: 'none',
                  color: 'rgba(255,255,255,0.35)',
                  fontSize: 12.5,
                  cursor: 'pointer',
                  padding: 0,
                  transition: 'color .15s',
                }}
                onMouseEnter={(e) =>
                  (e.target.style.color = 'rgba(255,255,255,0.7)')
                }
                onMouseLeave={(e) =>
                  (e.target.style.color = 'rgba(255,255,255,0.35)')
                }
              >
                Passwort vergessen?
              </button>
            )}
            <button
              onClick={() => {
                const hasVerify = !!localStorage.getItem('webars_verify_v1');
                const hasSalt = !!localStorage.getItem('webars_salt_v1');
                const hasMk = !!localStorage.getItem('webars_master_v1');
                let msg =
                  `Diagnose:\nVERIFY_KEY: ${hasVerify}\nSALT_KEY: ${hasSalt}\nMASTER_KEY: ${hasMk}\n\n`;
                if (!hasSalt && hasVerify) {
                  msg +=
                    '⚠️ SALT fehlt aber VERIFY vorhanden — Browser-Daten unvollständig.\nPasswörter können NICHT funktionieren ohne Salt.\n→ Nutze "Passwort vergessen?" um über den Server-Escrow wieder Zugang zu bekommen.';
                } else if (!hasSalt && !hasVerify && !hasMk) {
                  msg +=
                    'Keine lokalen Daten. Wähle "Einrichten" für ein neues Konto, oder stelle zuerst ein Backup wieder her.';
                } else if (hasSalt && hasVerify && hasMk) {
                  msg +=
                    'Alle Keys vorhanden — Passwort wird geprüft. Falls falsch: genau dieses Passwort wurde zum Einrichten verwendet.';
                } else {
                  msg +=
                    'Teilweise Daten vorhanden — ungewöhnlicher Zustand. "Passwort vergessen?" empfohlen.';
                }
                alert(msg);
              }}
              style={{
                background: 'none',
                border: 'none',
                color: 'rgba(255,255,255,0.2)',
                fontSize: 11.5,
                cursor: 'pointer',
                padding: 0,
              }}
            >
              Diagnose
            </button>
          </div>
        )}
        {onSwitchMode && (
          <div
            style={{
              textAlign: 'center',
              marginTop: 14,
              fontSize: 12.5,
              color: 'rgba(255,255,255,0.3)',
            }}
          >
            {isSetup ? (
              <>
                <span>Schon ein Konto? </span>
                <button
                  onClick={onSwitchMode}
                  style={{
                    background: 'none',
                    border: 'none',
                    color: 'rgba(255,255,255,0.7)',
                    fontSize: 12.5,
                    cursor: 'pointer',
                    padding: 0,
                    fontWeight: 600,
                  }}
                >
                  Anmelden
                </button>
              </>
            ) : (
              <>
                <span>Noch kein Konto? </span>
                <button
                  onClick={onSwitchMode}
                  style={{
                    background: 'none',
                    border: 'none',
                    color: 'rgba(255,255,255,0.7)',
                    fontSize: 12.5,
                    cursor: 'pointer',
                    padding: 0,
                    fontWeight: 600,
                  }}
                >
                  Einrichten
                </button>
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
