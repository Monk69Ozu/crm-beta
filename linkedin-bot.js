/**
 * LinkedIn Outreach Bot
 * Playwright + Claude Haiku für personalisierte Verbindungsanfragen
 */

const { chromium } = require('playwright-core');
const Anthropic = require('@anthropic-ai/sdk');
const fs = require('fs');
const path = require('path');

const CHROMIUM_PATH = process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH || undefined;
const STATS_FILE = path.join(__dirname, 'data', 'linkedin-stats.json');

// Tages-Maximum — LinkedIn sperrt ab ~20/Tag, wir bleiben bei 15 als hartes Limit
const HARD_DAILY_MAX = 15;

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

// ── Persistentes Daily-Limit ───────────────────────────────────────────────────
function loadStats() {
  try {
    if (fs.existsSync(STATS_FILE)) {
      const raw = JSON.parse(fs.readFileSync(STATS_FILE, 'utf8'));
      const today = new Date().toISOString().slice(0, 10);
      if (raw.date === today) return raw;
    }
  } catch {}
  return { date: new Date().toISOString().slice(0, 10), sentToday: 0, totalSent: 0 };
}

function saveStats(stats) {
  try {
    const dir = path.dirname(STATS_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(STATS_FILE, JSON.stringify(stats, null, 2));
  } catch (e) {
    addLog('warn', `Stats speichern fehlgeschlagen: ${e.message}`);
  }
}

function getSentToday() {
  return loadStats().sentToday;
}

function incrementSentToday() {
  const stats = loadStats();
  stats.sentToday++;
  stats.totalSent = (stats.totalSent || 0) + 1;
  saveStats(stats);
  botState.sentToday = stats.sentToday;
  botState.totalSent = stats.totalSent;
}

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
    return text || resolved;
  } catch (e) {
    addLog('warn', `Haiku-Fehler: ${e.message}`);
    return resolved;
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
    return 'None';
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

// ── Checkpoint/CAPTCHA-Detection ───────────────────────────────────────────────
async function checkForCheckpoint(page) {
  const url = page.url();
  if (
    url.includes('/checkpoint/') ||
    url.includes('/challenge/') ||
    url.includes('/captcha/') ||
    url.includes('security/verify')
  ) {
    throw new Error(`CHECKPOINT ERKANNT — LinkedIn verlangt manuelle Verifizierung. Bot gestoppt. URL: ${url}`);
  }
}

// ── Login-Check ────────────────────────────────────────────────────────────────
async function checkLoggedIn(page) {
  await page.goto('https://www.linkedin.com/feed/', { waitUntil: 'domcontentloaded', timeout: 30000 });
  await page.waitForTimeout(2000 + Math.random() * 1500);
  await checkForCheckpoint(page);
  const url = page.url();
  if (url.includes('/login') || url.includes('/checkpoint')) {
    throw new Error('LinkedIn nicht eingeloggt — Cookies ungültig oder abgelaufen');
  }
  addLog('info', 'LinkedIn eingeloggt ✓');
}

// ── Human-Behavior: zufälliges Scrollen ───────────────────────────────────────
async function humanScroll(page) {
  const scrolls = 2 + Math.floor(Math.random() * 3);
  for (let i = 0; i < scrolls; i++) {
    const amount = 200 + Math.floor(Math.random() * 400);
    await page.evaluate(y => window.scrollBy(0, y), amount);
    await page.waitForTimeout(400 + Math.random() * 600);
  }
  // Kurz wieder nach oben
  await page.evaluate(() => window.scrollBy(0, -(100 + Math.random() * 200)));
  await page.waitForTimeout(300 + Math.random() * 400);
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
  if (profile.profileUrl) {
    await page.goto(profile.profileUrl, { waitUntil: 'domcontentloaded', timeout: 30000 });
    // Human-Delay nach Seitenload
    await page.waitForTimeout(2000 + Math.random() * 2000);
    await checkForCheckpoint(page);
    // Kurz scrollen wie ein Mensch
    await humanScroll(page);
  }

  // "Vernetzen" Button finden
  let connectBtn = await page.$('button[aria-label*="Vernetzen"], button[aria-label*="Connect"]');
  if (!connectBtn) {
    const moreBtn = await page.$('button[aria-label*="Mehr"], button[aria-label*="More"]');
    if (moreBtn) {
      await moreBtn.click();
      await page.waitForTimeout(800 + Math.random() * 500);
    } else {
      return { success: false, reason: 'Kein Vernetzen-Button gefunden' };
    }
  }

  const finalConnectBtn = await page.$('button[aria-label*="Vernetzen"], button[aria-label*="Connect"]');
  if (!finalConnectBtn) return { success: false, reason: 'Connect-Button nicht gefunden nach More-Klick' };

  await finalConnectBtn.click();
  await page.waitForTimeout(1000 + Math.random() * 800);

  // "Notiz hinzufügen" klicken
  const addNoteBtn = await page.$('button[aria-label*="Notiz"], button[aria-label*="note"], button[aria-label*="Add a note"]');
  if (addNoteBtn) {
    await addNoteBtn.click();
    await page.waitForTimeout(800 + Math.random() * 500);
    const textarea = await page.$('textarea[name="message"]');
    if (textarea) {
      // Menschliches Tippen: nicht alles auf einmal
      await textarea.click();
      await page.waitForTimeout(300 + Math.random() * 300);
      await textarea.fill(message);
      await page.waitForTimeout(500 + Math.random() * 400);
    }
  }

  // Senden
  const sendBtn = await page.$('button[aria-label*="Senden"], button[aria-label*="Send invitation"]');
  if (!sendBtn) return { success: false, reason: 'Send-Button nicht gefunden' };

  await sendBtn.click();
  await page.waitForTimeout(1000 + Math.random() * 500);
  await checkForCheckpoint(page);

  return { success: true };
}

// ── Hauptschleife ──────────────────────────────────────────────────────────────
async function runBot(config) {
  const { zielgruppe, tagLimit, message, cookies, anthropicKey, proxy } = config;

  // Proxy-Zwang: kein Start ohne Proxy (Datacenter-IP = sofortige Erkennung)
  if (!proxy || proxy.trim() === '') {
    throw new Error('Kein Proxy konfiguriert — Bot läuft nicht ohne Proxy (Konto-Schutz). Bitte im CRM einen Proxy eintragen.');
  }

  // Hartes Tages-Limit prüfen
  const alreadySentToday = getSentToday();
  if (alreadySentToday >= HARD_DAILY_MAX) {
    throw new Error(`Tages-Limit erreicht: ${alreadySentToday}/${HARD_DAILY_MAX} bereits heute gesendet. Morgen wieder verfügbar.`);
  }
  const remainingToday = Math.min(tagLimit, HARD_DAILY_MAX - alreadySentToday);

  botState.status = 'running';
  botState.startedAt = new Date().toISOString();
  botState.stopRequested = false;
  botState.sentToday = alreadySentToday;

  addLog('info', `Bot startet... (${alreadySentToday} heute bereits gesendet, noch ${remainingToday} erlaubt)`, { zielgruppe, tagLimit: remainingToday });

  let browser;
  try {
    // Session-ID: sticky Proxy-Session (keine IP-Sprünge innerhalb einer Session)
    const sessionId = Math.random().toString(36).slice(2, 10);
    const proxyServer = proxy.replace(/^(https?:\/\/)([^:]+):([^@]+)@/, (_, proto, user, pass) =>
      `${proto}${user}-session-${sessionId}:${pass}@`);

    // Viewport leicht randomisieren
    const vpWidth = 1260 + Math.floor(Math.random() * 80);
    const vpHeight = 880 + Math.floor(Math.random() * 60);

    browser = await chromium.launch({
      executablePath: CHROMIUM_PATH,
      headless: 'new', // Neue Headless-Variante — weniger erkennbar als headless: true
      args: [
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-blink-features=AutomationControlled',
      ],
      proxy: { server: proxyServer },
    });
    botState.browser = browser;

    const context = await browser.newContext({
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
      viewport: { width: vpWidth, height: vpHeight },
      locale: 'de-DE',
    });

    const page = await context.newPage();

    // navigator.webdriver entfernen (LinkedIn prüft das aktiv)
    await page.addInitScript(() => {
      Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
      delete Object.getPrototypeOf(navigator).webdriver;
    });
    botState.page = page;

    await setupCookies(context, cookies);
    await checkLoggedIn(page);

    const searchQuery = encodeURIComponent(zielgruppe);
    let searchPage = 1;
    let sent = 0;

    while (sent < remainingToday && !botState.stopRequested) {
      const searchUrl = `https://www.linkedin.com/search/results/people/?keywords=${searchQuery}&page=${searchPage}&network=%5B%22S%22%2C%22O%22%5D`;
      await page.goto(searchUrl, { waitUntil: 'domcontentloaded', timeout: 30000 });
      await page.waitForTimeout(2500 + Math.random() * 2000);
      await checkForCheckpoint(page);
      await humanScroll(page);

      const cards = await page.$$('.entity-result__item, .search-results__result-item');
      if (cards.length === 0) {
        addLog('info', `Seite ${searchPage}: keine Ergebnisse mehr`);
        break;
      }

      addLog('info', `Seite ${searchPage}: ${cards.length} Profile gefunden`);

      for (const card of cards) {
        if (botState.stopRequested || sent >= remainingToday) break;

        const profile = await extractProfileInfo(card);
        if (!profile.profileUrl) continue;

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
          incrementSentToday();
          addLog('success', `Anfrage gesendet: ${profile.name}`, { title: profile.title, company: profile.company, msg: personalMsg });
        } else {
          addLog('warn', `Fehlgeschlagen: ${profile.name} — ${result.reason}`);
        }

        // Menschliche Pause zwischen Anfragen (20–50 Sek)
        const pause = 20000 + Math.random() * 30000;
        addLog('debug', `Pause ${Math.round(pause / 1000)}s...`);
        await new Promise(r => setTimeout(r, pause));
      }

      searchPage++;
      await page.waitForTimeout(4000 + Math.random() * 3000);
    }

    addLog('info', `Bot fertig. ${sent} Anfragen gesendet (${getSentToday()}/${HARD_DAILY_MAX} heute gesamt).`);
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
    const stats = loadStats();
    return {
      status: botState.status,
      sentToday: stats.sentToday,
      dailyMax: HARD_DAILY_MAX,
      remainingToday: Math.max(0, HARD_DAILY_MAX - stats.sentToday),
      totalSent: stats.totalSent,
      lastError: botState.lastError,
      startedAt: botState.startedAt,
    };
  },

  getLog() {
    return botState.log;
  },

  async start(config) {
    if (botState.status === 'running') throw new Error('Bot läuft bereits');
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
