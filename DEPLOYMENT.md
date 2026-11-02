# CYRA Security Scanner — Deployment Guide

A complete reference for deploying CYRA to production.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Environment Variables](#environment-variables)
3. [Deploy to Vercel (Recommended)](#deploy-to-vercel)
4. [Deploy with Docker](#deploy-with-docker)
5. [Self-hosted Node.js](#self-hosted-nodejs)
6. [Health Check](#health-check)
7. [Rate Limiting at Scale](#rate-limiting-at-scale)
8. [Security Checklist](#security-checklist)

---

## Prerequisites

| Requirement | Version |
|---|---|
| Node.js | ≥ 20.x LTS |
| npm | ≥ 10.x |
| Docker (optional) | ≥ 24.x |

---

## Environment Variables

Copy `.env.example` to `.env.local` before running locally:

```bash
cp .env.example .env.local
```

| Variable | Default | Description |
|---|---|---|
| `NEXT_PUBLIC_APP_URL` | `https://cyra.app` | Canonical URL for sitemap & OG |
| `NODE_ENV` | `production` | Node environment |
| `NEXT_TELEMETRY_DISABLED` | `1` | Disables Next.js telemetry |
| `PORT` | `3000` | HTTP port (Docker / self-hosted) |

---

## Deploy to Vercel

### One-click

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new)

### Manual

```bash
# Install Vercel CLI
npm i -g vercel

# Inside the cyra/ directory
cd cyra
vercel --prod
```

**Important:** The scan API (`/api/scan`) makes outbound TLS and DNS connections. Vercel's Edge Functions **do not** have access to Node.js `tls` or `dns` modules. CYRA's API uses **Node.js runtime** (the default for App Router API routes), so it works correctly on Vercel's standard serverless functions.

The `vercel.json` already sets `maxDuration: 30` for the scan function to accommodate slow domains.

---

## Deploy with Docker

### Build & Run

```bash
# Build the image
docker build -t cyra:latest .

# Run in production mode
docker run \
  --name cyra \
  --restart unless-stopped \
  -p 3000:3000 \
  -e NODE_ENV=production \
  -e NEXT_TELEMETRY_DISABLED=1 \
  cyra:latest
```

### Using Docker Compose

```bash
docker compose up --build -d
docker compose logs -f
```

### Enabling Standalone Output

For the Docker build to work, uncomment `output: "standalone"` in `next.config.ts` before building:

```ts
// next.config.ts
const nextConfig: NextConfig = {
  output: "standalone",  // ← uncomment this
  // ...
};
```

---

## Self-hosted Node.js

```bash
cd cyra

# Install dependencies
npm ci

# Build production bundle
npm run build

# Start production server
npm start
```

To run behind a reverse proxy (nginx/Caddy), set `PORT=3000` and proxy `:80`/`:443` → `:3000`.

### nginx example

```nginx
server {
    listen 443 ssl http2;
    server_name cyra.example.com;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_cache_bypass $http_upgrade;
    }
}
```

---

## Health Check

The `/api/health` endpoint is always available and suitable for load-balancer probes:

```bash
curl https://cyra.app/api/health
# {"status":"ok","service":"cyra-security-scanner","version":"0.1.0","timestamp":"..."}
```

Docker and Compose health checks are pre-configured in `Dockerfile` and `docker-compose.yml`.

---

## Rate Limiting at Scale

The default in-memory rate limiter (10 req / 60 s per IP) works for single-process deployments. For multi-instance or serverless deployments:

1. Replace the `rateLimitStore` Map in `lib/security/guard.ts` with a Redis client (e.g. `ioredis` or Upstash).
2. Set `REDIS_URL` as an environment variable and read it in `guard.ts`.

Example with Upstash:
```ts
import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";
```

---

## Security Checklist

Before going live:

- [ ] Set `NEXT_PUBLIC_APP_URL` to your real domain
- [ ] Ensure TLS certificate is valid and auto-renewing
- [ ] Verify security headers via `https://securityheaders.com`
- [ ] Check `https://hstspreload.org` if targeting preload list
- [ ] Configure uptime monitoring against `/api/health`
- [ ] Review rate limit values for your expected traffic
- [ ] Set up error alerting (e.g., Sentry, Datadog)
- [ ] Verify Docker container runs as non-root (`whoami` inside container = `nextjs`)
- [ ] Run `npm audit` and resolve any critical CVEs
- [ ] Confirm `X-Powered-By` header is absent in production responses
