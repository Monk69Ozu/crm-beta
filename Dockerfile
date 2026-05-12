# ── Build stage ──────────────────────────────────────────────────
FROM node:20-alpine AS deps
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev

# ── Runtime stage ─────────────────────────────────────────────────
FROM node:20-alpine
WORKDIR /app

# Non-root user for security
RUN addgroup -S crm && adduser -S crm -G crm

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

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:3000/api/validate || exit 1

CMD ["node", "server.js"]
