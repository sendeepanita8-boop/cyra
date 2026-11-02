# =====================================================================
# CYRA Security Scanner — Docker Image
# Multi-stage build for minimal, secure production image
# =====================================================================
# Build:   docker build -t cyra:latest .
# Run:     docker run -p 3000:3000 cyra:latest
# Compose: docker compose up --build
# =====================================================================

# ---------- Stage 1: Dependency installation ----------
FROM node:20-alpine AS deps

# Security: non-root user during build
RUN addgroup --system --gid 1001 nodejs \
 && adduser  --system --uid  1001 nextjs

WORKDIR /app

# Install dependencies (frozen lockfile for reproducibility)
COPY package.json package-lock.json ./
RUN npm ci --only=production --ignore-scripts

# ---------- Stage 2: Builder ----------
FROM node:20-alpine AS builder
WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules
COPY . .

# Build Next.js application in standalone mode
ENV NEXT_TELEMETRY_DISABLED=1
ENV NODE_ENV=production

# Enable standalone output in next.config.ts before building
# (uncomment `output: "standalone"` in next.config.ts)
RUN npm run build

# ---------- Stage 3: Production runner ----------
FROM node:20-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=3000
ENV HOSTNAME=0.0.0.0

# Security hardening
RUN addgroup --system --gid 1001 nodejs \
 && adduser  --system --uid  1001 nextjs \
 && apk add --no-cache dumb-init

# Copy built artifacts from standalone output
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static
COPY --from=builder --chown=nextjs:nodejs /app/public ./public

# Drop to non-root
USER nextjs

EXPOSE 3000

# Graceful shutdown via dumb-init
ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "server.js"]

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD wget -qO- http://localhost:3000/api/health || exit 1
