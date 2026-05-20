import { useEffect, useState } from 'react';
import { fromB64, aesDecrypt } from '../lib/crypto.js';
import {
  SALT_KEY,
  VERIFY_KEY,
  TOTP_KEY,
  DATA_KEY,
  INVITES_KEY,
  EMAIL_HASH_KEY,
  MASTER_KEY_STORE,
  DEVICE_KEY_STORE,
  TOTP_ENC_STORE,
  PKEY_ENC_STORE,
  GH_SETTINGS_KEY,
  RECOVERY_EMAIL,
  hasSetup,
} from '../lib/storage.js';
import { escrowMasterKey } from '../lib/auth.js';
import { SELF_HOSTED, apiToken, serverHasAuth } from '../lib/api.js';
import { getOrCreateDeviceKey } from '../lib/device.js';
import { loadEncryptedFromServer } from '../lib/data.js';
import AuthScreen from './AuthScreen.jsx';
import ForgotPasswordScreen from './ForgotPasswordScreen.jsx';
import ResetPasswordScreen from './ResetPasswordScreen.jsx';

// AuthWrapper — orchestriert alle Auth-Phasen.
// 1:1 nach legacy/index.html (Zeilen 9779-9892), mit den fuer die Migration
// noetigen Vereinfachungen:
//   - hasGithubSettings/loadGithubSettings/clearGithubSettings entfaellt
//     (Self-hosted braucht keine GH-Settings — Server ist Source-of-Truth)
//   - PublicFormPage kommt in Session 4
//   - CRMApp kommt in Session 6 — bis dahin steht ein Placeholder hier
export default function AuthWrapper() {
  const [phase, setPhase] = useState('loading');
  const [cryptoKey, setCryptoKey] = useState(null);
  const [crmData, setCrmData] = useState(null);

  // Public form mode: ?form=<slug> rendert oeffentliches Formular ohne Login.
  const publicFormSlug = (() => {
    try {
      return new URLSearchParams(window.location.search).get('form');
    } catch {
      return null;
    }
  })();
  if (publicFormSlug) {
    // TODO Session 4: <PublicFormPage slug={publicFormSlug} />
    return (
      <div style={{ padding: 40, fontFamily: 'monospace' }}>
        Public Form: <b>{publicFormSlug}</b>
        <br />
        <span style={{ color: '#888' }}>
          (PublicFormPage kommt in Session 4 — bitte bis dahin die alte
          index.html verwenden.)
        </span>
      </div>
    );
  }

  // Password reset mode: ?reset=TOKEN
  const resetToken = (() => {
    try {
      return new URLSearchParams(window.location.search).get('reset');
    } catch {
      return null;
    }
  })();
  if (resetToken && SELF_HOSTED) {
    return <ResetPasswordScreen token={resetToken} />;
  }

  useEffect(() => {
    // Auto-Login mit Device-Key, falls vorhanden.
    (async () => {
      let serverAuth = false;
      if (SELF_HOSTED && apiToken()) {
        try {
          serverAuth = await serverHasAuth();
        } catch {}
      }
      const anyAuth = serverAuth || hasSetup();

      if (anyAuth && localStorage.getItem(PKEY_ENC_STORE)) {
        try {
          const dk = await getOrCreateDeviceKey();
          const b64key = await aesDecrypt(
            dk,
            JSON.parse(localStorage.getItem(PKEY_ENC_STORE)),
          );
          const key = await crypto.subtle.importKey(
            'raw',
            fromB64(b64key),
            { name: 'AES-GCM', length: 256 },
            true,
            ['encrypt', 'decrypt'],
          );
          if (key) {
            let data = null;
            try {
              data = await loadEncryptedFromServer(key);
            } catch (loadErr) {
              if (loadErr && loadErr.code === 'KEY_MISMATCH') {
                console.warn(
                  '[auto-login] key mismatch — clearing device key, going to login',
                );
                localStorage.removeItem(PKEY_ENC_STORE);
                localStorage.removeItem(DEVICE_KEY_STORE);
                setPhase('login');
                return;
              }
              throw loadErr;
            }
            console.log('[auto-login] success');
            setCryptoKey(key);
            setCrmData(data);
            setPhase('app');
            return;
          }
        } catch (e) {
          console.warn('[auto-login] failed:', e);
        }
      }
      setPhase(anyAuth ? 'login' : 'setup');
    })();
  }, []);

  const handleReset = () => {
    if (SELF_HOSTED) {
      if (
        !window.confirm(
          'Lokalen Cache leeren?\n\nDeine Daten am Server bleiben sicher. Du musst dich danach mit deinem Passwort neu anmelden.',
        )
      )
        return;
    } else {
      if (
        !window.confirm(
          `Alle lokalen Daten löschen?\n\nWiederherstellungskontakt: ${RECOVERY_EMAIL}`,
        )
      )
        return;
    }
    [
      SALT_KEY,
      VERIFY_KEY,
      TOTP_KEY,
      DATA_KEY,
      EMAIL_HASH_KEY,
      INVITES_KEY,
      DEVICE_KEY_STORE,
      TOTP_ENC_STORE,
      PKEY_ENC_STORE,
      GH_SETTINGS_KEY,
      MASTER_KEY_STORE,
    ].forEach((k) => localStorage.removeItem(k));
    setPhase(SELF_HOSTED ? 'login' : 'setup');
  };

  const handleLogout = () => {
    localStorage.removeItem(PKEY_ENC_STORE);
    setCryptoKey(null);
    setCrmData(null);
    setPhase('login');
  };

  const completeAuth = async (key, data /* , email */) => {
    // Escrow aktualisieren, damit Passwort-Reset zukuenftig funktioniert.
    escrowMasterKey(key).catch(() => {});
    setCryptoKey(key);
    setCrmData(data);
    setPhase('app');
  };

  if (phase === 'loading')
    return (
      <div
        style={{
          height: '100vh',
          background: '#0F0E0C',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
        }}
      >
        <span
          style={{
            width: 28,
            height: 28,
            border: '2.5px solid rgba(255,255,255,.1)',
            borderTopColor: 'white',
            borderRadius: '50%',
            animation: 'spin .7s linear infinite',
            display: 'block',
          }}
        ></span>
      </div>
    );

  if (phase === 'setup')
    return (
      <AuthScreen
        mode="setup"
        onDone={completeAuth}
        onSwitchMode={() => setPhase('login')}
      />
    );

  if (phase === 'login')
    return (
      <AuthScreen
        mode="login"
        onDone={completeAuth}
        onSwitchMode={() => setPhase('setup')}
        onForgotPassword={SELF_HOSTED ? () => setPhase('forgot') : null}
      />
    );

  if (phase === 'forgot')
    return <ForgotPasswordScreen onBack={() => setPhase('login')} />;

  if (phase === 'app' && cryptoKey) {
    return (
      <CRMPlaceholder
        cryptoKey={cryptoKey}
        crmData={crmData}
        onReset={handleReset}
        onLogout={handleLogout}
      />
    );
  }

  return null;
}

// Temporaerer Placeholder bis CRMApp in Session 6 vollstaendig migriert ist.
// Zeigt nur an dass Login funktioniert + erste Datenzeile vom Server.
function CRMPlaceholder({ cryptoKey, crmData, onReset, onLogout }) {
  const dataInfo = crmData
    ? `geladen (${Object.keys(crmData).length} Top-Level-Felder)`
    : 'leer / nicht gefunden';
  const fields = crmData ? Object.keys(crmData).sort().join(', ') : '–';
  return (
    <div
      style={{
        padding: 40,
        fontFamily: "'Plus Jakarta Sans', sans-serif",
        background: '#F3F0EB',
        minHeight: '100vh',
      }}
    >
      <h1 style={{ marginBottom: 18 }}>WebArs CRM — Migration in Arbeit</h1>
      <div
        style={{
          background: 'white',
          borderRadius: 14,
          padding: 28,
          maxWidth: 720,
          lineHeight: 1.65,
          boxShadow: '0 4px 16px rgba(0,0,0,.06)',
        }}
      >
        <p style={{ marginBottom: 14 }}>
          ✓ Login erfolgreich. Master-Key im Speicher, Server-Daten erreichbar.
        </p>
        <div
          style={{
            fontFamily: 'monospace',
            fontSize: 13,
            background: '#F5F2EE',
            padding: 14,
            borderRadius: 8,
            marginBottom: 18,
          }}
        >
          cryptoKey: {cryptoKey ? '<CryptoKey vorhanden>' : '–'}
          <br />
          Daten vom Server: {dataInfo}
          <br />
          Felder: {fields}
        </div>
        <p style={{ marginBottom: 18, fontSize: 13.5, color: '#6B6560' }}>
          Die volle CRMApp-Oberflaeche wird in Session 6 hier eingehaengt.
          Bis dahin ist dieser Placeholder die Bestaetigung dass Auth +
          Server-Anbindung sauber laufen.
        </p>
        <div style={{ display: 'flex', gap: 10 }}>
          <button className="btn btn-ghost" onClick={onReset}>
            Lokalen Cache leeren
          </button>
          <button className="btn btn-primary" onClick={onLogout}>
            Abmelden
          </button>
        </div>
      </div>
    </div>
  );
}
