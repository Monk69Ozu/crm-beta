import { useState } from 'react';

// QR-Code-Rendering via Google Charts API (kein npm-Dep noetig).
// 1:1 aus legacy/index.html (Zeilen 1309-1328).
export default function QRCodeImage({ url }) {
  const encoded = encodeURIComponent(url);
  const src = `https://chart.googleapis.com/chart?cht=qr&chs=256x256&chld=M|1&chl=${encoded}`;
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState(false);
  return (
    <div
      style={{
        width: 200,
        height: 200,
        background: 'white',
        borderRadius: 12,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        overflow: 'hidden',
        position: 'relative',
      }}
    >
      {!loaded && !error && (
        <div
          style={{
            position: 'absolute',
            inset: 0,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            background: 'white',
            borderRadius: 12,
          }}
        >
          <span style={{ color: '#C8C3BD', fontSize: 13 }}>Lade…</span>
        </div>
      )}
      {error && (
        <div
          style={{
            padding: 12,
            textAlign: 'center',
            fontSize: 12,
            color: '#888',
            lineHeight: 1.5,
          }}
        >
          QR-Code konnte nicht geladen werden. Bitte den Code manuell
          eingeben.
        </div>
      )}
      <img
        src={src}
        onLoad={() => setLoaded(true)}
        onError={() => setError(true)}
        style={{
          width: 200,
          height: 200,
          display: loaded ? 'block' : 'none',
          borderRadius: 12,
        }}
        alt="QR Code"
      />
    </div>
  );
}
