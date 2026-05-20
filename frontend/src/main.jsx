// Vite-Entry-Point fuer das WebArs CRM Frontend.
//
// AuthWrapper kuemmert sich um Auto-Login, Login-Screen, Forgot/Reset-Flows
// und wird in Session 6 die CRMApp-Komponente einhaengen.

import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import AuthWrapper from './auth/AuthWrapper.jsx';
import './styles.css';

const root = document.getElementById('root');
if (root) {
  createRoot(root).render(
    <StrictMode>
      <AuthWrapper />
    </StrictMode>,
  );
}
