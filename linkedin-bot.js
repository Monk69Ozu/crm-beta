/**
 * LinkedIn Outreach Bot
 * Playwright + Claude Haiku für personalisierte Verbindungsanfragen
 * Factory-Pattern: createBot() gibt unabhängige Instanz zurück
 */

const { chromium } = require('playwright-core');
const Anthropic = require('@anthropic-ai/sdk');
const fs = require('fs');
const path = require('path');

const CHROMIUM_PATH = process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH || undefined;

// Tages-Maximum pro Session — LinkedIn sperrt ab ~20/Tag
const HARD_DAILY_MAX = 15;

// ── Haiku Personalisierung ─────────────────────────────────────────────────────
async function personalizeMessage(profile, templateMsg, anthropicKey, logFn) {
  const firstName = (profile.name || '').split(' ')[0];
  const resolved = templateMsg.replace(/\{name\}/gi, firstName || 'there');
  if (!anthropicKey) return resolved;
  try {
    const client = new Anthropic({ apiKey: anthropicKey });
    const msg = await client.messages.create({
      model: 'claude-haiku-4-5-20251001',
      max_tokens: 100,
      messages: [{ role: 'user', content: `Write ONE short, casual LinkedIn connection request opener (1 sentence, no emojis). Profile: ${profile.name}, ${profile.title}, ${profile.company}. Base: "${templateMsg}". Just the sentence.` }],
    });
    return msg.content[0]?.text?.trim() || resolved;
  } catch (e) {
    logFn('warn', `Haiku-Fehler: ${e.message}`);
    return resolved;
  }
}

// ── Cookie-Setup ───────────────────────────────────────────────────────────────
async function setupCookies(context, cookiesJson) {
  let cookies;
  try { cookies = typeof cookiesJson === 'string' ? JSON.parse(cookiesJson) : cookiesJson; }
  catch { throw new Error('Ungültiges Cookie-JSON'); }
  if (!Array.isArray(cookies)) throw new Error('Cookies müssen ein Array sein');
  const normSameSite = v => { const s = String(v||'').toLowerCase(); return s==='strict'?'Strict':s==='lax'?'Lax':'None'; };
  const mapped = cookies.map(c => ({ name:c.name, value:c.value, domain:c.domain||'.linkedin.com', path:c.path||'/', httpOnly:c.httpOnly??true, secure:c.secure??true, sameSite:normSameSite(c.sameSite) })).filter(c=>c.name&&c.value);
  await context.addCookies(mapped);
  return mapped.length;
}

// ── Checkpoint-Detection ───────────────────────────────────────────────────────
function checkUrlForCheckpoint(url) {
  if (url.includes('/checkpoint/')||url.includes('/challenge/')||url.includes('/captcha/')||url.includes('security/verify')) {
    throw new Error(`CHECKPOINT erkannt — LinkedIn verlangt manuelle Verifizierung. Bot gestoppt. URL: ${url}`);
  }
}

// ── Human-Behavior ─────────────────────────────────────────────────────────────
async function humanScroll(page) {
  const n = 2 + Math.floor(Math.random() * 3);
  for (let i = 0; i < n; i++) {
    await page.evaluate(y => window.scrollBy(0, y), 200 + Math.floor(Math.random() * 400));
    await page.waitForTimeout(400 + Math.random() * 600);
  }
  await page.evaluate(() => window.scrollBy(0, -(100 + Math.random() * 200)));
  await page.waitForTimeout(300 + Math.random() * 400);
}

// ── Factory ────────────────────────────────────────────────────────────────────
function createBot(sessionId) {
  const statsFile = sessionId
    ? path.join(__dirname, 'data', `linkedin-stats-${sessionId}.json`)
    : path.join(__dirname, 'data', 'linkedin-stats.json');

  function loadStats() {
    try {
      if (fs.existsSync(statsFile)) {
        const raw = JSON.parse(fs.readFileSync(statsFile, 'utf8'));
        const today = new Date().toISOString().slice(0, 10);
        if (raw.date === today) return raw;
      }
    } catch {}
    return { date: new Date().toISOString().slice(0, 10), sentToday: 0, totalSent: 0 };
  }

  function saveStats(stats) {
    try {
      const dir = path.dirname(statsFile);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(statsFile, JSON.stringify(stats, null, 2));
    } catch {}
  }

  function getSentToday() { return loadStats().sentToday; }

  function incrementSentToday() {
    const stats = loadStats();
    stats.sentToday++;
    stats.totalSent = (stats.totalSent || 0) + 1;
    saveStats(stats);
    return stats;
  }

  let state = {
    status: 'stopped',
    sentToday: 0,
    totalSent: 0,
    log: [],
    lastError: null,
    startedAt: null,
    stopRequested: false,
    browser: null,
  };

  function addLog(level, msg, extra = {}) {
    const entry = { ts: new Date().toISOString(), level, msg, ...extra };
    state.log.unshift(entry);
    if (state.log.length > 200) state.log.length = 200;
    console.log(`[LinkedIn Bot] [${level}] ${msg}`);
  }

  async function sendConnectionRequest(page, profile, message) {
    if (profile.profileUrl) {
      await page.goto(profile.profileUrl, { waitUntil: 'domcontentloaded', timeout: 30000 });
      await page.waitForTimeout(2000 + Math.random() * 2000);
      checkUrlForCheckpoint(page.url());
      await humanScroll(page);
    }
    let connectBtn = await page.$('button[aria-label*="Vernetzen"], button[aria-label*="Connect"]');
    if (!connectBtn) {
      const moreBtn = await page.$('button[aria-label*="Mehr"], button[aria-label*="More"]');
      if (moreBtn) { await moreBtn.click(); await page.waitForTimeout(800 + Math.random() * 500); }
      else return { success: false, reason: 'Kein Vernetzen-Button' };
    }
    const finalBtn = await page.$('button[aria-label*="Vernetzen"], button[aria-label*="Connect"]');
    if (!finalBtn) return { success: false, reason: 'Connect-Button nicht gefunden' };
    await finalBtn.click();
    await page.waitForTimeout(1000 + Math.random() * 800);
    const addNoteBtn = await page.$('button[aria-label*="Notiz"], button[aria-label*="note"], button[aria-label*="Add a note"]');
    if (addNoteBtn) {
      await addNoteBtn.click();
      await page.waitForTimeout(800 + Math.random() * 500);
      const textarea = await page.$('textarea[name="message"]');
      if (textarea) { await textarea.click(); await page.waitForTimeout(300); await textarea.fill(message); await page.waitForTimeout(500); }
    }
    const sendBtn = await page.$('button[aria-label*="Senden"], button[aria-label*="Send invitation"]');
    if (!sendBtn) return { success: false, reason: 'Send-Button nicht gefunden' };
    await sendBtn.click();
    await page.waitForTimeout(1000 + Math.random() * 500);
    checkUrlForCheckpoint(page.url());
    return { success: true };
  }

  async function runBot(config) {
    const { zielgruppe, tagLimit, message, cookies, anthropicKey, proxy } = config;

    if (!proxy || !proxy.trim()) {
      throw new Error('Kein Proxy konfiguriert — bitte Residential Proxy eintragen (Konto-Schutz).');
    }

    const alreadyToday = getSentToday();
    if (alreadyToday >= HARD_DAILY_MAX) {
      throw new Error(`Tages-Limit erreicht: ${alreadyToday}/${HARD_DAILY_MAX} heute gesendet. Morgen wieder verfügbar.`);
    }
    const remaining = Math.min(tagLimit, HARD_DAILY_MAX - alreadyToday);

    state.status = 'running';
    state.startedAt = new Date().toISOString();
    state.stopRequested = false;
    addLog('info', `Bot startet (${alreadyToday} heute bereits gesendet, noch ${remaining} erlaubt)`, { zielgruppe });

    let browser;
    try {
      const sid = Math.random().toString(36).slice(2, 10);
      const proxyServer = proxy.replace(/^(https?:\/\/)([^:]+):([^@]+)@/, (_, p, u, pw) => `${p}${u}-session-${sid}:${pw}@`);
      const vpW = 1260 + Math.floor(Math.random() * 80);
      const vpH = 880 + Math.floor(Math.random() * 60);

      browser = await chromium.launch({
        executablePath: CHROMIUM_PATH,
        headless: 'new',
        args: ['--no-sandbox','--disable-setuid-sandbox','--disable-dev-shm-usage','--disable-blink-features=AutomationControlled'],
        proxy: { server: proxyServer },
      });
      state.browser = browser;

      const context = await browser.newContext({
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
        viewport: { width: vpW, height: vpH },
        locale: 'de-DE',
      });
      const page = await context.newPage();
      await page.addInitScript(() => {
        Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
        try { delete Object.getPrototypeOf(navigator).webdriver; } catch {}
      });

      const cookieCount = await setupCookies(context, cookies);
      addLog('info', `${cookieCount} Cookies gesetzt`);

      await page.goto('https://www.linkedin.com/feed/', { waitUntil: 'domcontentloaded', timeout: 30000 });
      await page.waitForTimeout(2000 + Math.random() * 1500);
      checkUrlForCheckpoint(page.url());
      if (page.url().includes('/login') || page.url().includes('/checkpoint')) {
        throw new Error('LinkedIn nicht eingeloggt — Cookies ungültig oder abgelaufen');
      }
      addLog('info', 'LinkedIn eingeloggt ✓');

      let searchPage = 1, sent = 0;
      while (sent < remaining && !state.stopRequested) {
        const url = `https://www.linkedin.com/search/results/people/?keywords=${encodeURIComponent(zielgruppe)}&page=${searchPage}&network=%5B%22S%22%2C%22O%22%5D`;
        await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
        await page.waitForTimeout(2500 + Math.random() * 2000);
        checkUrlForCheckpoint(page.url());
        await humanScroll(page);

        const cards = await page.$$('.entity-result__item, .search-results__result-item');
        if (!cards.length) { addLog('info', `Seite ${searchPage}: keine Ergebnisse mehr`); break; }
        addLog('info', `Seite ${searchPage}: ${cards.length} Profile`);

        for (const card of cards) {
          if (state.stopRequested || sent >= remaining) break;
          let profile = { name:'', title:'', company:'', profileUrl:'' };
          try {
            profile.name = (await card.$eval('.entity-result__title-text', el=>el.innerText.trim()).catch(()=>'')).split('\n')[0].trim();
            profile.title = await card.$eval('.entity-result__primary-subtitle', el=>el.innerText.trim()).catch(()=>'');
            profile.company = await card.$eval('.entity-result__secondary-subtitle', el=>el.innerText.trim()).catch(()=>'');
            profile.profileUrl = await card.$eval('a.app-aware-link', el=>el.href).catch(()=>'');
          } catch {}
          if (!profile.profileUrl) continue;
          const hasConnect = await card.$eval('button[aria-label*="Vernetzen"], button[aria-label*="Connect"]', ()=>true).catch(()=>false);
          if (!hasConnect) { addLog('debug', `Übersprungen: ${profile.name}`); continue; }

          const msg = await personalizeMessage(profile, message, anthropicKey, addLog);
          const result = await sendConnectionRequest(page, profile, msg);
          if (result.success) {
            sent++;
            const stats = incrementSentToday();
            state.sentToday = stats.sentToday;
            state.totalSent = stats.totalSent;
            addLog('success', `Anfrage gesendet: ${profile.name}`, { title: profile.title, company: profile.company });
          } else {
            addLog('warn', `Fehlgeschlagen: ${profile.name} — ${result.reason}`);
          }
          const pause = 20000 + Math.random() * 30000;
          addLog('debug', `Pause ${Math.round(pause/1000)}s...`);
          await new Promise(r => setTimeout(r, pause));
        }
        searchPage++;
        await page.waitForTimeout(4000 + Math.random() * 3000);
      }

      addLog('info', `Fertig. ${sent} Anfragen gesendet (${getSentToday()}/${HARD_DAILY_MAX} heute gesamt).`);
      state.status = 'stopped';
    } catch (err) {
      state.lastError = err.message;
      state.status = 'error';
      addLog('error', err.message);
    } finally {
      try { await browser?.close(); } catch {}
      state.browser = null;
    }
  }

  return {
    getStatus() {
      const stats = loadStats();
      return { status: state.status, sentToday: stats.sentToday, dailyMax: HARD_DAILY_MAX, remainingToday: Math.max(0, HARD_DAILY_MAX - stats.sentToday), totalSent: stats.totalSent, lastError: state.lastError, startedAt: state.startedAt };
    },
    getLog() { return state.log; },
    async start(config) {
      if (state.status === 'running') throw new Error('Bot läuft bereits');
      runBot(config).catch(err => { state.status = 'error'; state.lastError = err.message; });
      return { started: true };
    },
    stop() { state.stopRequested = true; addLog('info', 'Stop angefordert...'); return { stopping: true }; },
    isRunning() { return state.status === 'running'; },
  };
}

module.exports = { createBot };
