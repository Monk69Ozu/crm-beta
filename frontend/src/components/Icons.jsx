// Inline-SVG-Icon-Bibliothek. 1:1 aus legacy/index.html (Zeilen 1268-1298).
// Alle Icons stroke="currentColor" — die Farbe wird vom umgebenden Element
// vererbt. Shield + Auth nutzen explizit rgba(255,255,255,0.3) fuer den
// schwachen weissen Hintergrund auf dunkler Auth-Card.

export const Plus = () => (
  <svg width="13" height="13" viewBox="0 0 13 13" fill="none">
    <path d="M6.5 1v11M1 6.5h11" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
  </svg>
);

export const Edit = () => (
  <svg width="13" height="13" viewBox="0 0 13 13" fill="none">
    <path d="M9 2l2 2-6 6H3v-2l6-6z" stroke="currentColor" strokeWidth="1.4" strokeLinejoin="round" />
  </svg>
);

export const Trash = () => (
  <svg width="13" height="13" viewBox="0 0 13 13" fill="none">
    <path d="M2 4h9M5 4V2.5h3V4M4 4l.5 6.5h4L9 4" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);

export const Search = () => (
  <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
    <circle cx="6" cy="6" r="4.5" stroke="currentColor" strokeWidth="1.5" />
    <path d="M10 10l2.5 2.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
  </svg>
);

export const Move = () => (
  <svg width="13" height="13" viewBox="0 0 13 13" fill="none">
    <path d="M2 6.5h9M8 4l3 2.5L8 9" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);

export const Bell = () => (
  <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
    <path d="M6 1a3 3 0 013 3c0 2.5 1 3 1 3H2s1-.5 1-3a3 3 0 013-3zM5 10a1 1 0 002 0" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);

export const Export = () => (
  <svg width="13" height="13" viewBox="0 0 13 13" fill="none">
    <path d="M6.5 1v7M4 5l2.5 3L9 5M2 11h9" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);

export const Close = () => (
  <svg width="11" height="11" viewBox="0 0 11 11" fill="none">
    <path d="M1 1l9 9M10 1l-9 9" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
  </svg>
);

export const Field = () => (
  <svg width="13" height="13" viewBox="0 0 13 13" fill="none">
    <rect x="1" y="2.5" width="11" height="2.5" rx="1" stroke="currentColor" strokeWidth="1.3" />
    <rect x="1" y="8" width="7" height="2.5" rx="1" stroke="currentColor" strokeWidth="1.3" />
  </svg>
);

export const Lock = () => (
  <svg width="13" height="13" viewBox="0 0 13 13" fill="none">
    <rect x="2" y="5.5" width="9" height="6.5" rx="2" stroke="currentColor" strokeWidth="1.4" />
    <path d="M4.5 5.5V4a2 2 0 014 0v1.5" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
    <circle cx="6.5" cy="8.5" r="1" fill="currentColor" />
  </svg>
);

export const Invite = () => (
  <svg width="13" height="13" viewBox="0 0 13 13" fill="none">
    <circle cx="5" cy="4.5" r="2.5" stroke="currentColor" strokeWidth="1.3" />
    <path d="M1 11c0-2.2 1.8-4 4-4" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" />
    <path d="M10 8v4M8 10h4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
  </svg>
);

export const Members = () => (
  <svg width="13" height="13" viewBox="0 0 13 13" fill="none">
    <circle cx="4.5" cy="4" r="2" stroke="currentColor" strokeWidth="1.3" />
    <path d="M1 11c0-2 1.6-3.5 3.5-3.5S8 9 8 11" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" />
    <circle cx="9.5" cy="4.5" r="1.5" stroke="currentColor" strokeWidth="1.2" />
    <path d="M11 11c0-1.4-1-2.5-2-2.8" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
  </svg>
);

export const Import = () => (
  <svg width="13" height="13" viewBox="0 0 13 13" fill="none">
    <path d="M6.5 8V1M4 5.5l2.5 3 2.5-3" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    <path d="M2 10h9" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
  </svg>
);

export const Tab = () => (
  <svg width="13" height="13" viewBox="0 0 13 13" fill="none">
    <rect x="1" y="3" width="11" height="8" rx="1.5" stroke="currentColor" strokeWidth="1.3" />
    <path d="M1 6h11" stroke="currentColor" strokeWidth="1.3" />
  </svg>
);

export const Eye = () => (
  <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
    <path d="M1 7s2.5-4.5 6-4.5S13 7 13 7s-2.5 4.5-6 4.5S1 7 1 7z" stroke="currentColor" strokeWidth="1.4" />
    <circle cx="7" cy="7" r="1.8" stroke="currentColor" strokeWidth="1.4" />
  </svg>
);

export const EyeOff = () => (
  <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
    <path d="M1 1l12 12M5.5 5.7A2 2 0 009.3 9M3 3.6C1.8 4.7 1 6 1 7s2.5 4.5 6 4.5c1.2 0 2.3-.3 3.2-.8M5 2.6C5.6 2.5 6.3 2.5 7 2.5c3.5 0 6 4.5 6 4.5s-.5 1-1.5 2" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
  </svg>
);

export const Activity = () => (
  <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
    <path d="M1 6h2l2-4 2 8 1.5-4.5L10 6h1" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);

export const Reminder = () => (
  <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
    <circle cx="6" cy="6" r="5" stroke="currentColor" strokeWidth="1.3" />
    <path d="M6 3.5v3l2 1" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" />
  </svg>
);

export const Check = () => (
  <svg width="13" height="13" viewBox="0 0 13 13" fill="none">
    <rect x="1.5" y="1.5" width="10" height="10" rx="2.5" stroke="currentColor" strokeWidth="1.4" />
    <path d="M4 6.5l2 2 3-3" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);

export const Shield = () => (
  <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
    <path d="M7 1.5L2 4v4c0 3 2.2 5.8 5 6.5 2.8-.7 5-3.5 5-6.5V4L7 1.5z" stroke="rgba(255,255,255,0.3)" strokeWidth="1.3" strokeLinejoin="round" />
  </svg>
);

export const Auth = () => (
  <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
    <rect x="1" y="6" width="12" height="7" rx="2" stroke="rgba(255,255,255,0.3)" strokeWidth="1.3" />
    <path d="M4 6V4.5a3 3 0 016 0V6" stroke="rgba(255,255,255,0.3)" strokeWidth="1.3" strokeLinecap="round" />
    <circle cx="7" cy="9.5" r="1.2" fill="rgba(255,255,255,0.3)" />
  </svg>
);

export const Bot = () => (
  <svg width="13" height="13" viewBox="0 0 13 13" fill="none">
    <rect x="2" y="4" width="9" height="7" rx="1.8" stroke="currentColor" strokeWidth="1.3" />
    <circle cx="5" cy="7.5" r="0.9" fill="currentColor" />
    <circle cx="8" cy="7.5" r="0.9" fill="currentColor" />
    <path d="M6.5 1.5v2.5M5 2.5h3" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" />
  </svg>
);

export const Doc = () => (
  <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
    <path d="M2.5 1.5h5L9.5 3.5v7a1 1 0 01-1 1h-6a1 1 0 01-1-1v-8a1 1 0 011-1z" stroke="currentColor" strokeWidth="1.3" strokeLinejoin="round" />
    <path d="M7 1.5v2.5h2.5M3.5 6.5h5M3.5 8.5h3" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);

export const Logout = () => (
  <svg width="13" height="13" viewBox="0 0 13 13" fill="none">
    <path d="M5.5 1.5h-3a1 1 0 00-1 1v8a1 1 0 001 1h3" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" />
    <path d="M8.5 4l2.5 2.5L8.5 9M11 6.5H5" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);

export const Cloud = () => (
  <svg width="13" height="13" viewBox="0 0 13 13" fill="none">
    <path d="M3.5 9.5a2.5 2.5 0 010-5 3.5 3.5 0 016.6-1A2.5 2.5 0 1110 9.5h-6.5z" stroke="currentColor" strokeWidth="1.3" strokeLinejoin="round" />
  </svg>
);

export const Quote = () => (
  <svg width="13" height="13" viewBox="0 0 13 13" fill="none">
    <rect x="2" y="1.5" width="9" height="10" rx="1.4" stroke="currentColor" strokeWidth="1.3" />
    <path d="M4 4.5h5M4 6.5h5M4 8.5h3" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" />
  </svg>
);

export const Invoice = () => (
  <svg width="13" height="13" viewBox="0 0 13 13" fill="none">
    <rect x="1.5" y="1.5" width="10" height="10" rx="1.4" stroke="currentColor" strokeWidth="1.3" />
    <path d="M4 4.5h5M4 6.5h3.5" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" />
    <path d="M7.5 8.5h2" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" />
    <circle cx="4.5" cy="8.5" r=".8" fill="currentColor" />
  </svg>
);

export const Print = () => (
  <svg width="13" height="13" viewBox="0 0 13 13" fill="none">
    <path d="M3 5V2h7v3M3 9.5H2a1 1 0 01-1-1v-3a1 1 0 011-1h9a1 1 0 011 1v3a1 1 0 01-1 1h-1M3 8h7v3.5H3z" stroke="currentColor" strokeWidth="1.3" strokeLinejoin="round" />
  </svg>
);

export const Mail = () => (
  <svg width="13" height="13" viewBox="0 0 13 13" fill="none">
    <rect x="1.5" y="3" width="10" height="7" rx="1.3" stroke="currentColor" strokeWidth="1.3" />
    <path d="M2 4l4.5 3 4.5-3" stroke="currentColor" strokeWidth="1.3" strokeLinejoin="round" />
  </svg>
);

// Konvenienz-Namespace, damit Komponenten <Icons.Eye /> statt <Eye /> schreiben
// koennen — exakt wie im Original-Code.
export const Icons = {
  Plus, Edit, Trash, Search, Move, Bell, Export, Close, Field, Lock,
  Invite, Members, Import, Tab, Eye, EyeOff, Activity, Reminder, Check,
  Shield, Auth, Bot, Doc, Logout, Cloud, Quote, Invoice, Print, Mail,
};
