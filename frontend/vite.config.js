import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Vite-Build fuer das WebArs CRM Frontend.
// Output landet in `dist/` (relativ zu /frontend). server.js liest spaeter
// `frontend/dist/index.html` und injiziert WEBARS_API_TOKEN, identisch zur
// bisherigen Logik mit der monolithischen index.html.
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: false,
    // Single-File-Output ist nicht noetig - der Express-Server kann
    // ausreichend statische Assets liefern. Wir behalten den default
    // Code-Split, da React/ReactDOM dann seperate Chunks sind und sich
    // browser-cachen lassen.
  },
  server: {
    port: 5173,
    // Lokales Dev: API-Calls an Express weiterleiten (laeuft auf Port 3000)
    proxy: {
      '/api':    'http://localhost:3000',
      '/health': 'http://localhost:3000',
      '/forms':  'http://localhost:3000',
      '/q':      'http://localhost:3000',
    },
  },
});
