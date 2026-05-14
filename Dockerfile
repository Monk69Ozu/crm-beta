# ── Build stage ──────────────────────────────────────────────────
FROM node:20-alpine AS deps
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev --no-audit --no-fund

# ── Runtime stage ─────────────────────────────────────────────────
FROM node:20-alpine
WORKDIR /app

# Non-root user for security
RUN addgroup -S crm && adduser -S crm -G crm && apk add --no-cache curl

COPY --from=deps /app/node_modules ./node_modules
COPY package.json ./
COPY server.js    ./
COPY index.html   ./

# Optional: jarvis tools (not needed at runtime, but nice to have)
COPY jarvis_crm_tools.js ./

RUN chown -R crm:crm /app
USER crm

EXPOSE 3000
ENV NODE_ENV=production

# Healthcheck removed — Coolify can configure this in the UI if needed.
# The /health endpoint is available at GET /health (no auth required).

CMD ["node", "server.js"]
