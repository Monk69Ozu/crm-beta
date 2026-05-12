/**
 * jarvis_crm_tools.js
 * CRM-Integration für Jarvis
 *
 * Setup in Jarvis (config.json oder .env):
 *   GITHUB_TOKEN=ghp_...
 *   GITHUB_REPO=tatstast/crm-system
 *   CRM_URL=https://tatstast.github.io/crm-system
 *
 * Einbinden in Jarvis:
 *   const { CRM_TOOLS, handleCrmTool } = require('./jarvis_crm_tools');
 *
 *   // Tools zu Claude API hinzufügen:
 *   const response = await anthropic.messages.create({
 *     model: 'claude-opus-4-7',
 *     tools: [...andereTools, ...CRM_TOOLS],
 *     messages: [...]
 *   });
 *
 *   // Tool-Aufruf verarbeiten:
 *   if (response.stop_reason === 'tool_use') {
 *     for (const block of response.content) {
 *       if (block.type === 'tool_use' && block.name.startsWith('crm_')) {
 *         const result = await handleCrmTool(block.name, block.input);
 *         // result zurück an Claude senden
 *       }
 *     }
 *   }
 */

const GITHUB_TOKEN      = process.env.GITHUB_TOKEN;
const GIST_ID           = process.env.JARVIS_GIST_ID || process.env.GIST_ID || null;
const CRM_URL           = process.env.CRM_URL        || 'https://tatstast.github.io/crm-system';

// Self-hosted mode: set SELF_HOSTED_URL to your Coolify server URL
// e.g.  SELF_HOSTED_URL=https://crm.webars.at
// When set, Jarvis reads the summary from GET <SELF_HOSTED_URL>/api/summary
// and ignores GITHUB_TOKEN / GIST_ID entirely.
const SELF_HOSTED_URL   = (process.env.SELF_HOSTED_URL || '').replace(/\/$/, '');

// ── Tool-Definitionen für Claude API ─────────────────────────────

const CRM_TOOLS = [
  {
    name: 'crm_get_contacts',
    description: 'Liest alle Kontakte aus dem CRM. Gibt Firma, Email, Telefon, Adresse und UID-Nummer zurück. Nützlich bevor ein Entwurf erstellt wird um Kundendaten zu holen.',
    input_schema: {
      type: 'object',
      properties: {
        search: {
          type: 'string',
          description: 'Optional: Suchbegriff (Firmenname oder Email)'
        }
      }
    }
  },
  {
    name: 'crm_get_open_invoices',
    description: 'Gibt alle offenen, gesendeten und überfälligen Rechnungen zurück mit Betrag und Fälligkeitsdatum.',
    input_schema: {
      type: 'object',
      properties: {}
    }
  },
  {
    name: 'crm_get_quotes',
    description: 'Gibt alle Angebote aus dem CRM zurück.',
    input_schema: {
      type: 'object',
      properties: {
        status: {
          type: 'string',
          description: 'Optional: Filter nach Status — entwurf | gesendet | akzeptiert | abgelehnt'
        }
      }
    }
  },
  {
    name: 'crm_create_invoice_draft',
    description: 'Erstellt einen Rechnungsentwurf und gibt einen Link zurück. Der Benutzer klickt den Link → CRM öffnet sich mit vorausgefülltem Formular. Felder können noch korrigiert werden bevor gespeichert wird.',
    input_schema: {
      type: 'object',
      required: ['firma', 'items'],
      properties: {
        firma:   { type: 'string', description: 'Firmenname des Kunden' },
        email:   { type: 'string' },
        address: { type: 'string', description: 'Straße + Hausnummer' },
        zip:     { type: 'string', description: 'PLZ' },
        city:    { type: 'string', description: 'Ort' },
        country: { type: 'string', default: 'Österreich' },
        taxId:   { type: 'string', description: 'UID-Nummer des Kunden z.B. ATU12345678' },
        items: {
          type: 'array',
          description: 'Positionen der Rechnung',
          items: {
            type: 'object',
            required: ['description', 'unitPrice'],
            properties: {
              description: { type: 'string', description: 'Bezeichnung der Leistung' },
              quantity:    { type: 'number', default: 1 },
              unitPrice:   { type: 'number', description: 'Einzelpreis in EUR (ohne MwSt)' }
            }
          }
        },
        date:    { type: 'string', description: 'Rechnungsdatum YYYY-MM-DD, Standard: heute' },
        dueDate: { type: 'string', description: 'Fälligkeitsdatum YYYY-MM-DD' },
        taxRate: { type: 'number', default: 20, description: 'MwSt in Prozent' },
        notes:   { type: 'string', description: 'Interne Notizen' }
      }
    }
  },
  {
    name: 'crm_create_quote_draft',
    description: 'Erstellt einen Angebotsentwurf und gibt einen Link zurück. Der Benutzer klickt den Link → CRM öffnet sich mit vorausgefülltem Angebot.',
    input_schema: {
      type: 'object',
      required: ['firma', 'items'],
      properties: {
        firma:   { type: 'string' },
        email:   { type: 'string' },
        address: { type: 'string' },
        zip:     { type: 'string' },
        city:    { type: 'string' },
        country: { type: 'string', default: 'Österreich' },
        taxId:   { type: 'string' },
        items: {
          type: 'array',
          items: {
            type: 'object',
            required: ['description', 'unitPrice'],
            properties: {
              description: { type: 'string' },
              quantity:    { type: 'number', default: 1 },
              unitPrice:   { type: 'number' }
            }
          }
        },
        taxRate: { type: 'number', default: 20 },
        notes:   { type: 'string' }
      }
    }
  }
];

// ── Hilfsfunktionen ───────────────────────────────────────────────

async function fetchCrmSummary() {
  // ── Self-hosted mode ──────────────────────────────────────────
  if (SELF_HOSTED_URL) {
    const r = await fetch(`${SELF_HOSTED_URL}/api/summary`);
    if (r.status === 404) throw new Error('Noch kein CRM-Summary auf dem Server — einmal im CRM speichern.');
    if (!r.ok) throw new Error(`Server Fehler ${r.status}`);
    return await r.json();
  }
  // ── GitHub Gist mode ──────────────────────────────────────────
  if (!GITHUB_TOKEN) throw new Error('GITHUB_TOKEN nicht gesetzt (oder SELF_HOSTED_URL für Self-Hosted-Modus).');
  if (!GIST_ID) throw new Error('JARVIS_GIST_ID nicht gesetzt — Gist-ID aus dem CRM (Cloud-Sync → Jarvis API) kopieren und als Umgebungsvariable setzen.');
  const r = await fetch(
    `https://api.github.com/gists/${GIST_ID}`,
    { headers: { Authorization: `Bearer ${GITHUB_TOKEN}`, Accept: 'application/vnd.github+json' } }
  );
  if (r.status === 404) throw new Error('Gist nicht gefunden — stimmt die JARVIS_GIST_ID? Gist-ID im CRM unter Cloud-Sync → Jarvis API prüfen.');
  if (!r.ok) throw new Error(`GitHub Fehler ${r.status}`);
  const j = await r.json();
  const file = j.files && j.files['crm_summary.json'];
  if (!file) throw new Error('crm_summary.json nicht im Gist gefunden — einmal im CRM speichern damit die Datei erstellt wird.');
  return JSON.parse(file.content);
}

function uid() {
  return Math.random().toString(36).slice(2, 10);
}

function generateDraftUrl(type, data) {
  const draft = { type, ...data };
  const encoded = Buffer.from(JSON.stringify(draft), 'utf8').toString('base64');
  const base = SELF_HOSTED_URL || CRM_URL;
  return `${base}?draft=${encodeURIComponent(encoded)}`;
}

// ── Tool Handler ──────────────────────────────────────────────────

async function handleCrmTool(toolName, input) {
  switch (toolName) {

    case 'crm_get_contacts': {
      const summary = await fetchCrmSummary();
      let contacts = summary.contacts || [];
      if (input.search) {
        const q = input.search.toLowerCase();
        contacts = contacts.filter(c =>
          c.firma?.toLowerCase().includes(q) ||
          c.email?.toLowerCase().includes(q)
        );
      }
      return { contacts, total: contacts.length };
    }

    case 'crm_get_open_invoices': {
      const summary = await fetchCrmSummary();
      const today = new Date().toISOString().slice(0, 10);
      const open = (summary.invoices || []).filter(inv =>
        ['offen', 'gesendet', 'ueberfaellig'].includes(inv.status) ||
        (inv.status === 'offen' && inv.dueDate && inv.dueDate < today)
      ).map(inv => ({
        ...inv,
        ueberfaellig: inv.dueDate && inv.dueDate < today && inv.status !== 'bezahlt'
      }));
      const gesamtOffen = open.reduce((s, i) => s + (i.total || 0), 0);
      return { invoices: open, anzahl: open.length, gesamtOffen };
    }

    case 'crm_get_quotes': {
      const summary = await fetchCrmSummary();
      let quotes = summary.quotes || [];
      if (input.status) quotes = quotes.filter(q => q.status === input.status);
      return { quotes, anzahl: quotes.length };
    }

    case 'crm_create_invoice_draft': {
      const items = (input.items || []).map(it => ({
        id: uid(),
        type: 'item',
        description: it.description || '',
        quantity: it.quantity ?? 1,
        unitPrice: it.unitPrice ?? 0
      }));
      const url = generateDraftUrl('invoice', {
        firma:   input.firma,
        email:   input.email   || '',
        address: input.address || '',
        zip:     input.zip     || '',
        city:    input.city    || '',
        country: input.country || 'Österreich',
        taxId:   input.taxId   || '',
        items,
        date:    input.date    || new Date().toISOString().slice(0, 10),
        dueDate: input.dueDate || '',
        taxRate: input.taxRate ?? 20,
        notes:   input.notes   || ''
      });
      const netto = items.reduce((s, i) => s + i.quantity * i.unitPrice, 0);
      const brutto = netto * (1 + (input.taxRate ?? 20) / 100);
      return {
        url,
        meldung: `Rechnungsentwurf für ${input.firma} erstellt (${brutto.toFixed(2)} € brutto). Link öffnen um zu finalisieren.`,
        netto, brutto
      };
    }

    case 'crm_create_quote_draft': {
      const items = (input.items || []).map(it => ({
        id: uid(),
        type: 'item',
        description: it.description || '',
        quantity: it.quantity ?? 1,
        unitPrice: it.unitPrice ?? 0
      }));
      const url = generateDraftUrl('quote', {
        firma:   input.firma,
        email:   input.email   || '',
        address: input.address || '',
        zip:     input.zip     || '',
        city:    input.city    || '',
        country: input.country || 'Österreich',
        taxId:   input.taxId   || '',
        items,
        taxRate: input.taxRate ?? 20,
        notes:   input.notes   || ''
      });
      const netto = items.reduce((s, i) => s + i.quantity * i.unitPrice, 0);
      const brutto = netto * (1 + (input.taxRate ?? 20) / 100);
      return {
        url,
        meldung: `Angebotsentwurf für ${input.firma} erstellt (${brutto.toFixed(2)} € brutto). Link öffnen um zu finalisieren.`,
        netto, brutto
      };
    }

    default:
      throw new Error(`Unbekanntes CRM-Tool: ${toolName}`);
  }
}

module.exports = { CRM_TOOLS, handleCrmTool };
