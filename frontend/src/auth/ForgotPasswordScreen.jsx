import { useState } from 'react';

// 1:1 aus legacy/index.html (Zeilen 1528-1603).
// Loest POST /api/forgot-password aus — wenn SMTP konfiguriert ist, geht eine
// E-Mail raus; sonst zeigt der Server den Reset-Link direkt im Response, den
// wir hier anzeigen.
export default function ForgotPasswordScreen({ onBack }) {
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);
  const [resetUrl, setResetUrl] = useState('');
  const [err, setErr] = useState('');

  const send = async () => {
    setBusy(true);
    setErr('');
    try {
      const r = await fetch('/api/forgot-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      if (!r.ok) {
        setErr('Server-Fehler. Bitte versuche es erneut.');
        setBusy(false);
        return;
      }
      const j = await r.json();
      // URL ueber tatsaechlichen Hostname rekonstruieren — server.APP_URL
      // kann falsch konfiguriert (z.B. localhost) sein.
      if (j.resetUrl) {
        try {
          const token =
            new URL(j.resetUrl).searchParams.get('reset') ||
            j.resetUrl.split('reset=')[1];
          setResetUrl(window.location.origin + '/?reset=' + token);
        } catch {
          setResetUrl(j.resetUrl);
        }
      } else if (j.token) {
        setResetUrl(window.location.origin + '/?reset=' + j.token);
      }
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
            Passwort zurücksetzen
          </div>
        </div>
        <div className="auth-panel" style={{ display: 'grid', gap: 14 }}>
          {!done ? (
            <>
              <div
                style={{
                  fontSize: 13.5,
                  color: 'rgba(255,255,255,0.55)',
                  lineHeight: 1.65,
                  textAlign: 'center',
                }}
              >
                Ein Zurücksetz-Link wird für dich generiert.
                <br />
                <span
                  style={{
                    fontSize: 12,
                    color: 'rgba(255,255,255,0.3)',
                  }}
                >
                  Falls SMTP konfiguriert ist, wird er per E-Mail gesendet.
                  Sonst wird er hier angezeigt.
                </span>
              </div>
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
                onClick={send}
                disabled={busy}
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
                  'Link anfordern →'
                )}
              </button>
            </>
          ) : (
            <>
              {resetUrl ? (
                <>
                  <div
                    style={{
                      fontSize: 13,
                      color: 'rgba(255,255,255,0.5)',
                      lineHeight: 1.6,
                      textAlign: 'center',
                    }}
                  >
                    Kein SMTP konfiguriert. Hier ist dein Zurücksetz-Link:
                  </div>
                  <div
                    style={{
                      background: 'rgba(255,255,255,0.07)',
                      border: '1px solid rgba(255,255,255,0.12)',
                      borderRadius: 10,
                      padding: '12px 14px',
                      wordBreak: 'break-all',
                      userSelect: 'all',
                    }}
                  >
                    <a
                      href={resetUrl}
                      style={{
                        color: '#60A5FA',
                        fontSize: 12.5,
                        textDecoration: 'none',
                        lineHeight: 1.5,
                      }}
                    >
                      {resetUrl}
                    </a>
                  </div>
                  <button
                    className="btn auth-btn"
                    onClick={() => (window.location.href = resetUrl)}
                  >
                    Jetzt zurücksetzen →
                  </button>
                </>
              ) : (
                <div
                  style={{
                    fontSize: 14,
                    color: 'rgba(255,255,255,0.65)',
                    lineHeight: 1.7,
                    textAlign: 'center',
                    padding: '8px 0',
                  }}
                >
                  ✓ E-Mail wurde gesendet!
                  <br />
                  <span
                    style={{
                      fontSize: 12.5,
                      color: 'rgba(255,255,255,0.35)',
                    }}
                  >
                    Überprüfe dein Postfach und klicke den Link.
                  </span>
                </div>
              )}
            </>
          )}
        </div>
        <div style={{ textAlign: 'center', marginTop: 18 }}>
          <button
            onClick={onBack}
            style={{
              background: 'none',
              border: 'none',
              color: 'rgba(255,255,255,0.3)',
              fontSize: 12.5,
              cursor: 'pointer',
              padding: 0,
              transition: 'color .15s',
            }}
            onMouseEnter={(e) =>
              (e.target.style.color = 'rgba(255,255,255,0.7)')
            }
            onMouseLeave={(e) =>
              (e.target.style.color = 'rgba(255,255,255,0.3)')
            }
          >
            ← Zurück zum Login
          </button>
        </div>
      </div>
    </div>
  );
}
