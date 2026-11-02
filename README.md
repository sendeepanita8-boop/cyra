# CYRA — Website Security Intelligence 🛡️

[![Next.js](https://img.shields.io/badge/Next.js-16.3-black?logo=next.js)](https://nextjs.org/)
[![React](https://img.shields.io/badge/React-19-blue?logo=react)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5-blue?logo=typescript)](https://www.typescriptlang.org/)
[![TailwindCSS](https://img.shields.io/badge/TailwindCSS-v4-38bdf8?logo=tailwindcss)](https://tailwindcss.com/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ed?logo=docker)](https://www.docker.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-emerald.svg)](LICENSE)

**CYRA** is a modern, high-precision security intelligence scanner and posture evaluator for authorized public web domains. It performs passive, non-intrusive perimeter audits across HTTPS/TLS, HTTP security headers, DNS records (SPF, DMARC, CAA), cookie configurations, and exposure indicators to generate actionable, executive-ready security reports.

---

## ✨ Features

- **🔒 Real Socket TLS / SSL Analysis**
  - Live inspection of certificate expiration, issuer, subject CN, and SANs.
  - Verification of negotiated protocol (`TLSv1.3` / `TLSv1.2`) and modern cipher suites.
  - Certificate SHA-256 fingerprint tracking.

- **🛡️ HTTP Security Headers Audit**
  - Comprehensive inspection of `Strict-Transport-Security` (HSTS) with `preload` & `includeSubDomains`.
  - Full directive analysis for `Content-Security-Policy` (CSP) and `frame-ancestors`.
  - Clickjacking defense (`X-Frame-Options: DENY / SAMEORIGIN`).
  - MIME-type sniffing protection (`X-Content-Type-Options: nosniff`).
  - Privacy protections (`Referrer-Policy` and `Permissions-Policy`).

- **🌐 DNS & Mail Security Audits**
  - Resilient DNS queries with public fallback resolvers (`1.1.1.1`, `8.8.8.8`).
  - Email spoofing defense audits: SPF (`v=spf1`) and DMARC (`v=DMARC1; p=reject|quarantine`).
  - Authoritative nameservers (`NS`) and IPv4/IPv6 (`A`/`AAAA`) records.
  - Certificate Authority Authorization (`CAA`) validation.

- **🍪 Cookie Security Standards**
  - Audit of session cookies for `Secure`, `HttpOnly`, and `SameSite` flags.

- **⚡ Live Response Telemetry & Health**
  - Precise latency SLA benchmarking (< 500 ms SLA indicator) and HTTP status code tracking.

- **📊 Scoring Algorithm & Actionable Roadmap**
  - Context-aware 0–100 security scoring engine and Letter Grade (A+ to F).
  - Clear explanations ("What was detected" & "Why it matters").
  - Step-by-step remediation snippets with copyable technical evidence.
  - Built-in PDF report generator, JSON export, and executive summary sharing.

---

## 🚀 Getting Started

### Prerequisites
- Node.js 18.18+ or 20+
- npm, yarn, pnpm, or bun

### Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/cyra.git
cd cyra

# Install dependencies
npm install

# Start the local development server
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

---

## 🐳 Docker Deployment

A hardened, multi-stage Alpine Dockerfile is included:

```bash
# Build the production image
docker build -t cyra-scanner .

# Run the container
docker run -p 3000:3000 --rm cyra-scanner
```

Or using Docker Compose:

```bash
docker compose up -d
```

---

## ☁️ Deploy to Vercel

The fastest way to deploy CYRA in production:

1. Push your repository to GitHub.
2. Import the project into [Vercel](https://vercel.com/new).
3. The included `vercel.json` automatically configures function timeouts (30s) and static caching.
4. Deploy! 🚀

---

## 🔒 Security & Responsible Use Policy

- **Passive Only:** CYRA exclusively analyzes publicly available HTTP headers, TLS handshakes, and public DNS records.
- **Non-Destructive:** No active injection, denial-of-service, brute force, or payload execution is conducted.
- **SSRF Safeguarded:** Target resolution blocks private CIDRs (RFC 1918), loopback, link-local, and AWS/cloud metadata addresses (`169.254.169.254`).
- **Rate Limited:** Built-in IP rate limiter protects backend resources.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
