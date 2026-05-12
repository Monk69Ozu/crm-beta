# Jarvis × CRM — Briefing für Claude

## Was ist das CRM?

Ein privates, browserseitiges CRM-System unter **https://tatstast.github.io/crm-system** — gebaut als einzelne HTML-Datei (React via CDN, kein Backend). Alle Daten sind AES-verschlüsselt und werden in einem privaten GitHub-Repo gespeichert. Der Nutzer heißt Mateo (WebArs).

---

## Was kann Jarvis damit machen?

Jarvis hat Zugriff auf fünf CRM-Tools (definiert in `jarvis_crm_tools.js`):

| Tool | Funktion |
|---|---|
| `crm_get_contacts` | Alle Kontakte lesen (Firma, Email, Telefon, Adresse, UID-Nummer). Optional `search` zum Filtern. |
| `crm_get_open_invoices` | Alle offenen/überfälligen Rechnungen mit Betrag und Fälligkeitsdatum. |
| `crm_get_quotes` | Alle Angebote. Optional `status`-Filter: `entwurf | gesendet | akzeptiert | abgelehnt`. |
| `crm_create_invoice_draft` | Rechnungsentwurf erstellen → gibt einen Link zurück, den Mateo klickt → CRM öffnet sich mit vorausgefülltem Formular. |
| `crm_create_quote_draft` | Angebotsentwurf erstellen → gleiches Prinzip wie Rechnung. |

### Wichtig zum Workflow bei Entwürfen

Jarvis erstellt **keinen** finalen Datensatz im CRM — er erstellt einen **Link**. Mateo klickt den Link, das CRM öffnet sich mit dem vorausgefüllten Formular, er kann Korrekturen vornehmen und dann speichern. Das ist Absicht (Vier-Augen-Prinzip).

---

## Wie liest Jarvis die CRM-Daten?

Das CRM schreibt bei jedem Speichern automatisch eine Zusammenfassung (`crm_summary.json`) in einen **privaten GitHub Gist**. Jarvis liest diesen Gist.

### Konfiguration — Self-Hosted (Coolify) ✓ empfohlen

```
SELF_HOSTED_URL=https://crm.webars.at   # Basis-URL des Coolify-Servers
CRM_URL=https://crm.webars.at           # Für Deep-Links (Entwürfe)
```

Die Summary-URL ist dann: `https://crm.webars.at/api/summary` — kein Token nötig, der Endpunkt ist öffentlich lesbar.

### Konfiguration — GitHub Pages (alte Methode)

```
GITHUB_TOKEN=ghp_...          # GitHub Personal Access Token (gists: read/write)
JARVIS_GIST_ID=<id>           # Gist-ID — im CRM unter Cloud-Sync → Jarvis API sichtbar
CRM_URL=https://tatstast.github.io/crm-system
```

Die Gist-ID findet Mateo im CRM: **Einstellungen → Cloud-Sync → Jarvis API** — dort steht sie mit einem Kopieren-Button.

---

## Struktur von `crm_summary.json`

```json
{
  "updatedAt": "2026-05-04T10:00:00.000Z",
  "contacts": [
    {
      "id": "abc123",
      "name": "Max Mustermann",
      "company": "Musterfirma GmbH",
      "email": "max@musterfirma.at",
      "phone": "+43 123 456789",
      "address": "Musterstraße 1, 1010 Wien, Österreich",
      "taxId": "ATU12345678"
    }
  ],
  "invoices": [
    {
      "id": "inv1",
      "number": "RE-2026-001",
      "status": "offen",
      "contactName": "Musterfirma GmbH",
      "email": "max@musterfirma.at",
      "total": 1200.00,
      "date": "2026-04-01",
      "dueDate": "2026-04-15"
    }
  ],
  "quotes": [
    {
      "id": "q1",
      "number": "AN-2026-001",
      "status": "gesendet",
      "contactName": "Musterfirma GmbH",
      "email": "max@musterfirma.at",
      "total": 950.00,
      "date": "2026-04-20"
    }
  ]
}
```

**Rechnungsstatus-Werte:** `entwurf | offen | gesendet | bezahlt | ueberfaellig | storniert`  
**Angebotsstatus-Werte:** `entwurf | gesendet | akzeptiert | abgelehnt`

---

## Parameter für Rechnungs-/Angebotsentwürfe

### `crm_create_invoice_draft` — Pflichtfelder

```json
{
  "firma": "Musterfirma GmbH",
  "items": [
    {
      "description": "Webdesign Startseite",
      "quantity": 1,
      "unitPrice": 800
    }
  ]
}
```

### Alle optionalen Felder

| Feld | Typ | Beschreibung |
|---|---|---|
| `email` | string | E-Mail-Adresse |
| `address` | string | Straße + Hausnummer |
| `zip` | string | PLZ |
| `city` | string | Ort |
| `country` | string | Standard: `Österreich` |
| `taxId` | string | UID-Nummer z.B. `ATU12345678` |
| `date` | string | Rechnungsdatum `YYYY-MM-DD`, Standard: heute |
| `dueDate` | string | Fälligkeitsdatum `YYYY-MM-DD` |
| `taxRate` | number | MwSt in Prozent, Standard: `20` |
| `notes` | string | Interne Notizen |

### Angebote (`crm_create_quote_draft`)

Gleiche Felder, nur ohne `date`, `dueDate`. `taxRate` und `notes` vorhanden.

---

## Typische Anfragen von Mateo — wie reagieren

**"Erstell eine Rechnung für [Firma]"**  
→ Zuerst `crm_get_contacts` mit Firmenname als `search` aufrufen, um die gespeicherten Kontaktdaten zu holen. Dann `crm_create_invoice_draft` mit den Kundendaten + gefragten Positionen. Den zurückgegebenen Link präsentieren.

**"Welche Rechnungen sind noch offen?"**  
→ `crm_get_open_invoices` aufrufen, Ergebnis zusammenfassen.

**"Erstell ein Angebot für [Firma] über [Leistung]"**  
→ Kontakt holen, dann `crm_create_quote_draft`. Link präsentieren.

**"Wie viel habe ich insgesamt offen?"**  
→ `crm_get_open_invoices`, `gesamtOffen` aus dem Ergebnis ausgeben.

---

## Einbindung in Jarvis (Node.js)

```js
const { CRM_TOOLS, handleCrmTool } = require('./jarvis_crm_tools');

// Tools zu Claude API hinzufügen:
const response = await anthropic.messages.create({
  model: 'claude-opus-4-7',
  tools: [...andereTools, ...CRM_TOOLS],
  messages: [...]
});

// Tool-Aufrufe verarbeiten:
if (response.stop_reason === 'tool_use') {
  for (const block of response.content) {
    if (block.type === 'tool_use' && block.name.startsWith('crm_')) {
      const result = await handleCrmTool(block.name, block.input);
      // result als tool_result zurück an Claude senden
    }
  }
}
```

---

## Technische Details

- **Deep-Link-Format:** `https://tatstast.github.io/crm-system?draft=BASE64` — die `generateDraftUrl()`-Funktion in `jarvis_crm_tools.js` erzeugt diese Links automatisch.
- **Gist-Update:** Wird bei jedem CRM-Speichervorgang automatisch aktualisiert (PATCH). Beim ersten Mal wird der Gist automatisch erstellt.
- **Keine Echtzeit:** Der Gist ist ein Snapshot des letzten Speicherstands — nicht live. Für aktuelle Daten Mateo bitten, kurz im CRM zu speichern.
- **Nur Lesen + Entwürfe:** Jarvis kann keine Daten direkt im CRM ändern oder löschen — nur lesen und Entwurfslinks erzeugen.
