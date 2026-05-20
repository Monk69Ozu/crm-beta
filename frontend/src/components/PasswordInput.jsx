import { useState } from 'react';
import { Eye, EyeOff } from './Icons.jsx';

// Passwort-Input mit Eye-Toggle. 1:1 aus legacy/index.html (Zeilen 1334-1344).
export default function PasswordInput({
  value,
  onChange,
  placeholder,
  autoFocus,
  onKeyDown,
  className,
}) {
  const [show, setShow] = useState(false);
  return (
    <div style={{ position: 'relative' }}>
      <input
        type={show ? 'text' : 'password'}
        value={value}
        onChange={onChange}
        placeholder={placeholder || 'Passwort'}
        autoFocus={autoFocus}
        onKeyDown={onKeyDown}
        className={`auth-input ${className || ''}`}
        style={{ paddingRight: 44 }}
      />
      <button
        type="button"
        onClick={() => setShow((s) => !s)}
        style={{
          position: 'absolute',
          right: 12,
          top: '50%',
          transform: 'translateY(-50%)',
          background: 'none',
          border: 'none',
          color: 'rgba(255,255,255,0.35)',
          lineHeight: 0,
          padding: 4,
          cursor: 'pointer',
        }}
      >
        {show ? <EyeOff /> : <Eye />}
      </button>
    </div>
  );
}
