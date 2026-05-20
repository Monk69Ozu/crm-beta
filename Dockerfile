# ── Frontend build stage (only used when USE_VITE_BUILD=true) ────
FROM node:20-alpine AS frontend
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm install --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

# ── Server deps stage ────────────────────────────────────────────
FROM node:20-alpine AS deps
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev --no-audit --no-fund

# ── Runtime stage ─────────────────────────────────────────────────
FROM node:20-alpine
WORKDIR /app

# Chromium for Playwright (LinkedIn bot) + curl for healthcheck
RUN apk add --no-cache curl chromium chromium-chromedriver \
    && addgroup -S crm && adduser -S crm -G crm

# Tell playwright-core where the system Chromium lives
ENV PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/usr/bin/chromium-browser

COPY --from=deps /app/node_modules ./node_modules
COPY package.json ./
COPY server.js    ./
COPY index.html   ./
COPY logo.png     ./

# Optional: jarvis tools (not needed at runtime, but nice to have)
COPY jarvis_crm_tools.js ./
COPY linkedin-bot.js     ./

# Vite-Build: production dist (wird nur verwendet wenn USE_VITE_BUILD=true).
COPY --from=frontend /app/frontend/dist ./frontend/dist

RUN chown -R crm:crm /app
USER crm

EXPOSE 3000
ENV NODE_ENV=production

# Healthcheck removed — Coolify can configure this in the UI if needed.
# The /health endpoint is available at GET /health (no auth required).

CMD ["node", "server.js"]
