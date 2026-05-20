// Cloud-Sync-Layer (self-hosted + GitHub-Pages-Fallback).
// 1:1 aus legacy/index.html (Zeilen 607-1075). Module-Globals (_ghSettings,
// _ghSha, _isSaving etc.) bleiben hier intern. saveEncrypted / loadEncrypted
// sind die Top-Level-Funktionen die CRMApp im State-Hook ruft.

import { toB64, fromB64, aesEncrypt, aesDecrypt, b64encode, b64decode } from './crypto.js';
import {
  DATA_KEY,
  GH_SETTINGS_KEY,
  GH_SHA_KEY,
  GH_GIST_KEY,
  DATA_BACKUP_KEY,
  SNAP_PREFIX,
  SNAP_SLOTS,
} from './storage.js';
import { SELF_HOSTED, apiToken } from './api.js';

// ── Modul-Globals ────────────────────────────────────────────────────────
let _ghSettings = null;
let _ghSha = localStorage.getItem(GH_SHA_KEY) || null;
let _gistId = localStorage.getItem(GH_GIST_KEY) || null;
let _ghSyncState = { state: 'idle' };
let _isSaving = false;
let _notifySync = null;
let _lastSnapAt = 0;

export function setSyncListener(fn) { _notifySync = fn; }
export function getSyncState() { return _ghSyncState; }
export function getJarvisGistId() { return _gistId; }
export function getGhSettings() { return _ghSettings; }

// ── Snapshots (5 Slots, LRU) ─────────────────────────────────────────────
export function saveLocalSnapshot(encBlob) {
  try {
    let oi = 0, ot = Infinity;
    for (let i = 0; i < SNAP_SLOTS; i++) {
      const r = localStorage.getItem(SNAP_PREFIX + i);
      if (!r) { oi = i; ot = 0; break; }
      try { const p = JSON.parse(r); if (p.t < ot) { ot = p.t; oi = i; } } catch {}
    }
    localStorage.setItem(SNAP_PREFIX + oi, JSON.stringify({ t: Date.now(), d: encBlob }));
  } catch {}
}

export function getLocalSnapshots() {
  const r = [];
  for (let i = 0; i < SNAP_SLOTS; i++) {
    const raw = localStorage.getItem(SNAP_PREFIX + i);
    if (raw) { try { const p = JSON.parse(raw); r.push({ i, t: p.t, d: p.d }); } catch {} }
  }
  return r.sort((a, b) => b.t - a.t);
}

// ── GH-Settings (im self-hosted-Modus ein Pseudo-Wert) ───────────────────
export function hasGithubSettings() {
  if (SELF_HOSTED && apiToken()) return true;
  return !!localStorage.getItem(GH_SETTINGS_KEY);
}

export async function saveGithubSettings(key, settings) {
  const enc = await aesEncrypt(key, settings);
  localStorage.setItem(GH_SETTINGS_KEY, JSON.stringify(enc));
  _ghSettings = settings;
}

export async function loadGithubSettings(key) {
  if (SELF_HOSTED && apiToken()) {
    _ghSettings = { token: apiToken(), repo: 'self-hosted', path: 'crm_data' };
    return _ghSettings;
  }
  const raw = localStorage.getItem(GH_SETTINGS_KEY);
  if (!raw) return null;
  try {
    const settings = await aesDecrypt(key, JSON.parse(raw));
    _ghSettings = settings;
    return settings;
  } catch { return null; }
}

export function clearGithubSettings() {
  localStorage.removeItem(GH_SETTINGS_KEY);
  _ghSettings = null;
  _ghSha = null;
  _ghSyncState = { state: 'idle' };
}

// ── Validate (UI-Pruefung) ───────────────────────────────────────────────
export async function ghValidateAccess(token, repo) {
  if (SELF_HOSTED) {
    const r = await fetch('/api/validate', { headers: { Authorization: `Bearer ${token}` } });
    if (r.status === 401) throw new Error('API Key ungueltig - stimmt der eingegebene Schluessel?');
    if (!r.ok) throw new Error(`Server-Fehler ${r.status}`);
    return true;
  }
  const r = await fetch(`https://api.github.com/repos/${repo}`, {
    headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json' },
  });
  if (r.status === 401) throw new Error('Token ungueltig oder abgelaufen.');
  if (r.status === 404) throw new Error('Repository nicht gefunden oder Token hat keinen Zugriff.');
  if (!r.ok) throw new Error(`GitHub-Fehler ${r.status}`);
  const j = await r.json();
  if (!j.permissions || !j.permissions.push) throw new Error('Token hat keine Schreibrechte fuer dieses Repo.');
  return true;
}

// ── Fetch + Push Datei (zweigleisig self-hosted / GitHub) ────────────────
export async function ghFetchFile(token, repo, path) {
  if (SELF_HOSTED) {
    const r = await fetch('/api/data', { headers: { Authorization: `Bearer ${token}` } });
    if (r.status === 401) {
      _ghSyncState = { state: 'token_invalid', at: Date.now() };
      _notifySync && _notifySync();
      throw new Error('TOKEN_INVALID');
    }
    if (!r.ok) return { content: null, sha: null };
    const j = await r.json();
    if (!j.content) return { content: null, sha: null };
    return { content: j.content, sha: String(j.version) };
  }
  const r = await fetch(`https://api.github.com/repos/${repo}/contents/${path}?ref=main`, {
    headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json' },
  });
  if (r.status === 404) return { content: null, sha: null };
  if (r.status === 401 || r.status === 403) {
    _ghSyncState = { state: 'token_invalid', at: Date.now() };
    _notifySync && _notifySync();
    throw new Error('TOKEN_INVALID');
  }
  if (!r.ok) throw new Error(`Sync-Fehler ${r.status}`);
  const j = await r.json();
  let content = null;
  try { content = JSON.parse(b64decode(j.content)); } catch { throw new Error('Datei konnte nicht gelesen werden.'); }
  return { content, sha: j.sha };
}

export async function ghPushFile(token, repo, path, content, sha = null, message = 'Update CRM') {
  if (SELF_HOSTED) {
    const r = await fetch('/api/data', {
      method: 'PUT',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ content, version: sha ? Number(sha) : null }),
    });
    if (r.status === 409) throw new Error('CONFLICT');
    if (r.status === 401) {
      _ghSyncState = { state: 'token_invalid', at: Date.now() };
      _notifySync && _notifySync();
      throw new Error('TOKEN_INVALID');
    }
    if (!r.ok) {
      const e = await r.json().catch(() => ({}));
      throw new Error(`Sync fehlgeschlagen: ${e.error || r.status}`);
    }
    const j = await r.json();
    return String(j.version);
  }
  const body = {
    message: `${message} - ${new Date().toISOString().slice(0, 16).replace('T', ' ')}`,
    content: b64encode(JSON.stringify(content)),
    branch: 'main',
    ...(sha ? { sha } : {}),
  };
  const r = await fetch(`https://api.github.com/repos/${repo}/contents/${path}`, {
    method: 'PUT',
    headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (r.status === 409) {
    const { sha: latestSha } = await ghFetchFile(token, repo, path);
    if (latestSha && latestSha !== sha) throw new Error('CONFLICT');
  }
  if (r.status === 401 || r.status === 403) {
    _ghSyncState = { state: 'token_invalid', at: Date.now() };
    _notifySync && _notifySync();
    throw new Error('TOKEN_INVALID');
  }
  if (!r.ok) {
    const err = await r.json().catch(() => ({}));
    throw new Error(`Sync fehlgeschlagen: ${err.message || r.status}`);
  }
  const j = await r.json();
  return j.content.sha;
}

// ── Polling fuer Team-Updates ────────────────────────────────────────────
export async function ghCheckForUpdates(key) {
  if (!_ghSettings) return null;
  if (_isSaving) return null;
  if (SELF_HOSTED) {
    try {
      const r = await fetch('/api/data', { headers: { Authorization: `Bearer ${_ghSettings.token}` } });
      if (!r.ok) return null;
      const j = await r.json();
      if (!j.content) return null;
      const newVer = String(j.version);
      if (newVer === _ghSha) return null;
      const content = j.content;
      const decrypted = await aesDecrypt(key, content);
      const cloudTs = decrypted._savedAt || 0;
      const localRaw = localStorage.getItem(DATA_KEY);
      let localTs = 0;
      if (localRaw) { try { const ld = await aesDecrypt(key, JSON.parse(localRaw)); localTs = ld?._savedAt || 0; } catch {} }
      if (cloudTs > 0 && cloudTs <= localTs) {
        _ghSha = newVer; localStorage.setItem(GH_SHA_KEY, newVer); return null;
      }
      if (localRaw) localStorage.setItem(DATA_BACKUP_KEY, localRaw);
      _ghSha = newVer; localStorage.setItem(GH_SHA_KEY, newVer);
      localStorage.setItem(DATA_KEY, JSON.stringify(content));
      return decrypted;
    } catch { return null; }
  }
  try {
    const r = await fetch(`https://api.github.com/repos/${_ghSettings.repo}/contents/${_ghSettings.path}?ref=main`, {
      headers: { Authorization: `Bearer ${_ghSettings.token}`, Accept: 'application/vnd.github+json' },
    });
    if (!r.ok) return null;
    const j = await r.json();
    if (j.sha === _ghSha) return null;
    let content;
    try { content = JSON.parse(b64decode(j.content)); } catch { return null; }
    const decrypted = await aesDecrypt(key, content);
    const cloudTs = decrypted._savedAt || 0;
    const localRaw = localStorage.getItem(DATA_KEY);
    let localTs = 0;
    if (localRaw) { try { const ld = await aesDecrypt(key, JSON.parse(localRaw)); localTs = ld?._savedAt || 0; } catch {} }
    if (cloudTs > 0 && cloudTs <= localTs) {
      _ghSha = j.sha; localStorage.setItem(GH_SHA_KEY, j.sha); return null;
    }
    if (localRaw) localStorage.setItem(DATA_BACKUP_KEY, localRaw);
    _ghSha = j.sha; localStorage.setItem(GH_SHA_KEY, j.sha);
    localStorage.setItem(DATA_KEY, JSON.stringify(content));
    return decrypted;
  } catch { return null; }
}

// ── CRM-Summary (Plaintext fuer Jarvis-API) ──────────────────────────────
function quoteTotalsSimple(q) {
  // CRMApp definiert eine vollstaendige quoteTotals — die brauchen wir hier
  // nur fuer die Summary. Berechne minimal: sum der line-items.
  if (!q || !q.items) return { total: 0 };
  const sub = q.items.reduce((s, it) => s + (Number(it.amount) || 0) * (Number(it.qty || 1)), 0);
  const tax = q.taxRate ? sub * (Number(q.taxRate) / 100) : 0;
  return { total: sub + tax };
}

export function buildCrmSummary(state) {
  return {
    updatedAt: new Date().toISOString(),
    contacts: (state.contacts || []).map((c) => ({
      id: c.id, name: c.ansprechpartner || '', company: c.firma || '',
      email: c.email || '', phone: c.telefon || '', status: c.status || '',
      address: [c.address, c.zip, c.city, c.country].filter(Boolean).join(', '),
      taxId: c.taxId || '', umsatz: c.umsatz || '', notizen: c.notizen || '',
    })),
    invoices: (state.invoices || []).map((inv) => ({
      id: inv.id, number: inv.number, status: inv.status,
      contactName: inv.contactSnapshot?.firma || '', email: inv.contactSnapshot?.email || '',
      total: quoteTotalsSimple(inv).total, date: inv.date, dueDate: inv.dueDate,
    })),
    quotes: (state.quotes || []).map((q) => ({
      id: q.id, number: q.number, status: q.status,
      contactName: q.contactSnapshot?.firma || '', email: q.contactSnapshot?.email || '',
      total: quoteTotalsSimple(q).total, date: q.date,
    })),
    tasks: (state.todos || []).map((t) => ({
      id: t.id, title: t.text || '', description: t.description || '',
      status: t.done ? 'erledigt' : 'offen', priority: t.priority || '',
      dueDate: t.dueDate || '', assignedTo: '', contactName: '',
      createdAt: t.createdAt || '', doneAt: t.doneAt || '',
    })),
    campaigns: (state.campaigns || []).map((c) => ({
      id: c.id, name: c.name || '', color: c.color || '',
      fileCount: (c.files || []).length,
      files: (c.files || []).map((f) => ({ id: f.id, name: f.name, updatedAt: f.updatedAt || '' })),
    })),
    employees: (state.aiEmployees || []).map((e) => ({
      id: e.id, name: e.name || '', role: e.plan || e.role || '',
    })),
    forms: (state.forms || []).map((f) => ({
      id: f.id, title: f.title || '', slug: f.slug || '', published: !!f.published,
      responseCount: (state.formResponses || []).filter((r) => r.formId === f.id).length,
    })),
    formResponses: (state.formResponses || []).map((r) => ({
      id: r.id, formId: r.formId, formTitle: r.formTitle || '',
      contactName: r.contactName || '', submittedAt: r.submittedAt || '', read: !!r.read,
    })),
  };
}

export async function pushCrmSummary(state, ghSettings) {
  if (SELF_HOSTED) {
    try {
      await fetch('/api/summary', {
        method: 'PUT',
        headers: { Authorization: `Bearer ${ghSettings.token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(buildCrmSummary(state)),
      });
    } catch {}
    return;
  }
  try {
    const content = JSON.stringify(buildCrmSummary(state), null, 2);
    const headers = { Authorization: `Bearer ${ghSettings.token}`, 'Content-Type': 'application/json' };
    if (!_gistId) {
      const r = await fetch('https://api.github.com/gists', {
        method: 'POST', headers,
        body: JSON.stringify({
          description: 'CRM Summary - Jarvis API (privat, nicht loeschen)',
          public: false,
          files: { 'crm_summary.json': { content } },
        }),
      });
      if (r.ok) { const j = await r.json(); _gistId = j.id; localStorage.setItem(GH_GIST_KEY, _gistId); }
    } else {
      const r = await fetch(`https://api.github.com/gists/${_gistId}`, {
        method: 'PATCH', headers,
        body: JSON.stringify({ files: { 'crm_summary.json': { content } } }),
      });
      if (!r.ok) { _gistId = null; localStorage.removeItem(GH_GIST_KEY); }
    }
  } catch {}
}

// ── saveEncrypted / loadEncrypted (Top-Level Daten-Sync) ─────────────────
export async function saveEncrypted(key, data) {
  _isSaving = true;
  try {
    const dataWithTs = { ...data, _savedAt: Date.now() };
    const encrypted = await aesEncrypt(key, dataWithTs);
    try { localStorage.setItem(DATA_KEY, JSON.stringify(encrypted)); } catch (e) { console.warn('[save] localStorage voll:', e); }
    const now = Date.now();
    if (now - _lastSnapAt > 4 * 3600 * 1000) { saveLocalSnapshot(encrypted); _lastSnapAt = now; }
    if (_ghSettings) {
      let attempt = 0;
      while (attempt < 2) {
        attempt++;
        try {
          const newSha = await ghPushFile(_ghSettings.token, _ghSettings.repo, _ghSettings.path, encrypted, _ghSha);
          _ghSha = newSha;
          localStorage.setItem(GH_SHA_KEY, newSha);
          _ghSyncState = { state: 'ok', at: Date.now() };
          _notifySync && _notifySync();
          pushCrmSummary(data, _ghSettings).catch(() => {});
          return;
        } catch (e) {
          if (e.message === 'CONFLICT' && attempt === 1) {
            try {
              const fetched = await ghFetchFile(_ghSettings.token, _ghSettings.repo, _ghSettings.path);
              if (fetched.content) {
                const cloudDec = await aesDecrypt(key, fetched.content);
                const cloudTs = cloudDec._savedAt || 0;
                if (cloudTs > dataWithTs._savedAt) {
                  _ghSyncState = { state: 'conflict_newer_on_server', message: 'Server hat neuere Daten (anderes Geraet). Bitte Seite neu laden.', at: Date.now() };
                  _notifySync && _notifySync();
                  return;
                }
                _ghSha = fetched.sha;
                localStorage.setItem(GH_SHA_KEY, fetched.sha);
                continue;
              }
            } catch {}
          }
          _ghSyncState = { state: 'error', message: e.message, at: Date.now() };
          _notifySync && _notifySync();
          return;
        }
      }
    }
  } finally { _isSaving = false; }
}

export async function loadEncrypted(key) {
  if (_ghSettings) {
    try {
      const fetched = await ghFetchFile(_ghSettings.token, _ghSettings.repo, _ghSettings.path);
      if (fetched.content) {
        let decrypted;
        try { decrypted = await aesDecrypt(key, fetched.content); }
        catch {
          _ghSyncState = { state: 'key_mismatch', message: 'Server-Daten konnten mit deinem aktuellen Schluessel nicht entschluesselt werden. Anmeldung mit falschem Passwort? Bitte ausloggen.', at: Date.now() };
          _notifySync && _notifySync();
          throw new Error('KEY_MISMATCH');
        }
        const cloudTs = decrypted._savedAt || 0;
        const localRaw = localStorage.getItem(DATA_KEY);
        if (localRaw && cloudTs > 0) {
          try {
            const localBlob = JSON.parse(localRaw);
            const localDec = await aesDecrypt(key, localBlob);
            const localTs = localDec._savedAt || 0;
            if (localTs > cloudTs) {
              _ghSha = fetched.sha;
              localStorage.setItem(GH_SHA_KEY, fetched.sha);
              _ghSyncState = { state: 'pending_push', message: 'Lokale Aenderungen warten auf Sync.', at: Date.now() };
              _notifySync && _notifySync();
              console.log('[loadEncrypted] local is newer than cloud - keeping local edits');
              return localDec;
            }
          } catch {}
        }
        if (localRaw) { try { localStorage.setItem(DATA_BACKUP_KEY, localRaw); } catch {} }
        _ghSha = fetched.sha;
        localStorage.setItem(GH_SHA_KEY, fetched.sha);
        localStorage.setItem(DATA_KEY, JSON.stringify(fetched.content));
        saveLocalSnapshot(fetched.content); _lastSnapAt = Date.now();
        _ghSyncState = { state: 'ok', at: Date.now() };
        _notifySync && _notifySync();
        return decrypted;
      } else {
        _ghSha = fetched.sha;
        localStorage.setItem(GH_SHA_KEY, fetched.sha);
      }
    } catch (e) {
      if (e.message === 'KEY_MISMATCH') throw e;
      _ghSyncState = { state: 'error', message: e.message, at: Date.now() };
      _notifySync && _notifySync();
    }
  }
  const raw = localStorage.getItem(DATA_KEY);
  if (!raw) return null;
  try { return await aesDecrypt(key, JSON.parse(raw)); } catch { return null; }
}
