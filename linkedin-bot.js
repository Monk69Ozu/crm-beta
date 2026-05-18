/**
 * LinkedIn Outreach Bot
 * Playwright + Claude Haiku für personalisierte Verbindungsanfragen
 */

const { chromium } = require('playwright-core');
const Anthropic = require('@anthropic-ai/sdk');

const CHROMIUM_PATH = process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH || undefined;

// ── State (wird vom server.js verwaltet) ───────────────────────────────────────
let botState = {
  status: 'stopped',    // stopped | running | paused | error
  sessionId: null,
  sentToday: 0,
  totalSent: 0,
  log: [],              // max 200 Einträge
  lastError: null,
  startedAt: null,
  browser: null,
  page: null,
  stopRequested: false,
};

// ── Logging ────────────────────────────────────────────────────────────────────
function addLog(level, msg, extra = {}) {
  const entry = { ts: new Date().toISOString(), level, msg, ...extra };
  botState.log.unshift(entry);
  if (botState.log.length > 200) botState.log.length = 200;
  console.log(`[LinkedIn Bot] [${level}] ${msg}`);
  return entry;
}

// ── Haiku Personalisierung ─────────────────────────────────────────────────────
async function personalizeMessage(profile, templateMsg, anthropicKey) {
  // Immer {name} ersetzen — auch ohne Haiku-Key
  const firstName = (profile.name || '').split(' ')[0];
  const resolved = templateMsg.replace(/\{name\}/gi, firstName || 'there');
  if (!anthropicKey) return resolved;
  try {
    const client = new Anthropic({ apiKey: anthropicKey });
    const prompt = `You are writing a short, casual LinkedIn connection request opener (1 sentence max, no emojis, very natural).

Profile info:
- Name: ${profile.name || 'there'}
- Title: ${profile.title || ''}
- Company: ${profile.company || ''}

Base message (use as reference, do NOT copy verbatim):
"${templateMsg}"

Write ONE short opener line that feels personal and genuine. Just the opener sentence, nothing else.`;

    const msg = await client.messages.create({
      model: 'claude-haiku-4-5-20251001',
      max_tokens: 100,
      messages: [{ role: 'user', content: prompt }],
    });
    const text = msg.content[0]?.text?.trim();
    return text || templateMsg;
  } catch (e) {
    addLog('warn', `Haiku-Fehler: ${e.message}`);
    return templateMsg;
  }
}

// ── Cookie-Setup ───────────────────────────────────────────────────────────────
async function setupCookies(context, cookiesJson) {
  let cookies;
  try {
    cookies = typeof cookiesJson === 'string' ? JSON.parse(cookiesJson) : cookiesJson;
  } catch {
    throw new Error('Ungültiges Cookie-JSON');
  }
  if (!Array.isArray(cookies)) throw new Error('Cookies müssen ein Array sein');

  const normSameSite = v => {
    if (!v) return 'None';
    const s = String(v).toLowerCase();
    if (s === 'strict') return 'Strict';
    if (s === 'lax') return 'Lax';
    return 'None'; // 'no_restriction', 'none', anything else
  };

  const mapped = cookies.map(c => ({
    name: c.name,
    value: c.value,
    domain: c.domain || '.linkedin.com',
    path: c.path || '/',
    httpOnly: c.httpOnly ?? true,
    secure: c.secure ?? true,
    sameSite: normSameSite(c.sameSite),
  })).filter(c => c.name && c.value);

  await context.addCookies(mapped);
  addLog('info', `${mapped.length} Cookies gesetzt`);
}

// ── Login-Check ────────────────────────────────────────────────────────────────
async function checkLoggedIn(page) {
  await page.goto('https://www.linkedin.com/feed/', { waitUntil: 'domcontentloaded', timeout: 30000 });
  await page.waitForTimeout(2000);
  const url = page.url();
  if (url.includes('/login') || url.includes('/checkpoint')) {
    throw new Error('LinkedIn nicht eingeloggt — Cookies ungültig oder abgelaufen');
  }
  addLog('info', 'LinkedIn eingeloggt ✓');
}

// ── Profil-Infos aus Suchresultat extrahieren ──────────────────────────────────
async function extractProfileInfo(card) {
  try {
    const name = await card.$eval('.entity-result__title-text', el => el.innerText.trim()).catch(() => '');
    const title = await card.$eval('.entity-result__primary-subtitle', el => el.innerText.trim()).catch(() => '');
    const company = await card.$eval('.entity-result__secondary-subtitle', el => el.innerText.trim()).catch(() => '');
    const profileUrl = await card.$eval('a.app-aware-link', el => el.href).catch(() => '');
    return { name: name.split('\n')[0].trim(), title, company, profileUrl };
  } catch {
    return { name: '', title: '', company: '', profileUrl: '' };
  }
}

// ── Verbindungsanfrage senden ──────────────────────────────────────────────────
async function sendConnectionRequest(page, profile, message) {
  // Auf Profil navigieren
  if (profile.profileUrl) {
    await page.goto(profile.profileUrl, { waitUntil: 'domcontentloaded', timeout: 30000 });
    await page.waitForTimeout(1500 + Math.random() * 1500);
  }

  // "Vernetzen" Button finden
  const connectBtn = await page.$('button[aria-label*="Vernetzen"], button[aria-label*="Connect"]');
  if (!connectBtn) {
    // Manchmal hinter "Mehr"
    const moreBtn = await page.$('button[aria-label*="Mehr"], button[aria-label*="More"]');
    if (moreBtn) {
      await moreBtn.click();
      await page.waitForTimeout(800);
    } else {
      return { success: false, reason: 'Kein Vernetzen-Button gefunden' };
    }
  }

  const finalConnectBtn = await page.$('button[aria-label*="Vernetzen"], button[aria-label*="Connect"]');
  if (!finalConnectBtn) return { success: false, reason: 'Connect-Button nicht gefunden nach More-Klick' };

  await finalConnectBtn.click();
  await page.waitForTimeout(1000);

  // "Notiz hinzufügen" klicken
  const addNoteBtn = await page.$('button[aria-label*="Notiz"], button[aria-label*="note"], button[aria-label*="Add a note"]');
  if (addNoteBtn) {
    await addNoteBtn.click();
    await page.waitForTimeout(800);
    const textarea = await page.$('textarea[name="message"]');
    if (textarea) {
      await textarea.fill(message);
      await page.waitForTimeout(500);
    }
  }

  // Senden
  const sendBtn = await page.$('button[aria-label*="Senden"], button[aria-label*="Send invitation"]');
  if (!sendBtn) return { success: false, reason: 'Send-Button nicht gefunden' };

  await sendBtn.click();
  await page.waitForTimeout(1000);

  return { success: true };
}

// ── Hauptschleife ──────────────────────────────────────────────────────────────
async function runBot(config) {
  const { zielgruppe, tagLimit, message, cookies, anthropicKey } = config;

  botState.status = 'running';
  botState.startedAt = new Date().toISOString();
  botState.stopRequested = false;
  botState.sentToday = 0;

  addLog('info', 'Bot startet...', { zielgruppe, tagLimit });

  let browser, context, page;
  try {
    browser = await chromium.launch({
      executablePath: CHROMIUM_PATH,
      headless: true,
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-blink-features=AutomationControlled',
      ],
    });
    botState.browser = browser;

    context = await browser.newContext({
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
      viewport: { width: 1280, height: 900 },
      locale: 'en-US',
    });

    page = await context.newPage();

    // navigator.webdriver entfernen (LinkedIn prüft das aktiv)
    await page.addInitScript(() => {
      Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
    });
    botState.page = page;

    await setupCookies(context, cookies);
    await checkLoggedIn(page);

    // Suchanfrage aus Zielgruppe bauen
    const searchQuery = encodeURIComponent(zielgruppe);
    let searchPage = 1;
    let sent = 0;

    while (sent < tagLimit && !botState.stopRequested) {
      const searchUrl = `https://www.linkedin.com/search/results/people/?keywords=${searchQuery}&page=${searchPage}&network=%5B%22S%22%2C%22O%22%5D`;
      await page.goto(searchUrl, { waitUntil: 'domcontentloaded', timeout: 30000 });
      await page.waitForTimeout(2000 + Math.random() * 2000);

      const cards = await page.$$('.entity-result__item, .search-results__result-item');
      if (cards.length === 0) {
        addLog('info', `Seite ${searchPage}: keine Ergebnisse mehr`);
        break;
      }

      addLog('info', `Seite ${searchPage}: ${cards.length} Profile gefunden`);

      for (const card of cards) {
        if (botState.stopRequested || sent >= tagLimit) break;

        const profile = await extractProfileInfo(card);
        if (!profile.profileUrl) continue;

        // Bereits verbunden? Überspringen
        const connectLabel = await card.$eval(
          'button[aria-label*="Vernetzen"], button[aria-label*="Connect"]',
          () => true
        ).catch(() => false);
        if (!connectLabel) {
          addLog('debug', `Übersprungen (bereits verbunden?): ${profile.name}`);
          continue;
        }

        const personalMsg = await personalizeMessage(profile, message, anthropicKey);
        const result = await sendConnectionRequest(page, profile, personalMsg);

        if (result.success) {
          sent++;
          botState.sentToday++;
          botState.totalSent++;
          addLog('success', `Anfrage gesendet: ${profile.name}`, { title: profile.title, company: profile.company, msg: personalMsg });
        } else {
          addLog('warn', `Fehlgeschlagen: ${profile.name} — ${result.reason}`);
        }

        // Menschliche Pause (15–45 Sekunden zwischen Anfragen)
        const pause = 15000 + Math.random() * 30000;
        addLog('debug', `Pause ${Math.round(pause / 1000)}s...`);
        await new Promise(r => setTimeout(r, pause));
      }

      searchPage++;
      // Kurze Pause zwischen Seiten
      await page.waitForTimeout(3000 + Math.random() * 3000);
    }

    addLog('info', `Bot fertig. ${sent} Anfragen gesendet.`);
    botState.status = 'stopped';
  } catch (err) {
    botState.lastError = err.message;
    botState.status = 'error';
    addLog('error', err.message);
  } finally {
    try { await browser?.close(); } catch {}
    botState.browser = null;
    botState.page = null;
  }
}

// ── Exports für server.js ──────────────────────────────────────────────────────
module.exports = {
  getStatus() {
    return {
      status: botState.status,
      sentToday: botState.sentToday,
      totalSent: botState.totalSent,
      lastError: botState.lastError,
      startedAt: botState.startedAt,
    };
  },

  getLog() {
    return botState.log;
  },

  async start(config) {
    if (botState.status === 'running') throw new Error('Bot läuft bereits');
    // Async starten — nicht awaiten, damit der HTTP-Request sofort antwortet
    runBot(config).catch(err => {
      botState.status = 'error';
      botState.lastError = err.message;
    });
    return { started: true };
  },

  stop() {
    botState.stopRequested = true;
    addLog('info', 'Stop angefordert...');
    return { stopping: true };
  },
};
