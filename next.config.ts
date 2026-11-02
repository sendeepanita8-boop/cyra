import type { NextConfig } from "next";

/* ============================================================
   SECURITY RESPONSE HEADERS
   Applied to all routes including the API.
   ============================================================ */

const securityHeaders = [
  // Prevent MIME-type sniffing
  { key: "X-Content-Type-Options", value: "nosniff" },
  // Deny framing to block clickjacking
  { key: "X-Frame-Options", value: "DENY" },
  // Force HTTPS for 2 years, include subdomains, preload-eligible
  {
    key: "Strict-Transport-Security",
    value: "max-age=63072000; includeSubDomains; preload",
  },
  // Safe referrer policy
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  // Restrict browser features
  {
    key: "Permissions-Policy",
    value: "camera=(), microphone=(), geolocation=(), interest-cohort=()",
  },
  // Content Security Policy
  {
    key: "Content-Security-Policy",
    value: [
      "default-src 'self'",
      // Next.js needs inline scripts for hydration; nonces are preferable
      // in production if you can generate them at the edge.
      "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "font-src 'self' data: https://fonts.gstatic.com",
      "img-src 'self' data: blob:",
      "connect-src 'self'",
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self'",
      "object-src 'none'",
      "upgrade-insecure-requests",
    ].join("; "),
  },
  // Prevent cross-origin data leakage
  { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
  { key: "Cross-Origin-Resource-Policy", value: "same-origin" },
  // X-DNS-Prefetch-Control
  { key: "X-DNS-Prefetch-Control", value: "on" },
];

/* ============================================================
   NEXT.JS CONFIGURATION
   ============================================================ */

const nextConfig: NextConfig = {
  // Remove the X-Powered-By: Next.js response header
  poweredByHeader: false,

  // Enable React strict mode for better development-time checks
  reactStrictMode: true,

  // Compress responses (enable for self-hosted; Vercel handles this automatically)
  compress: true,

  // Output standalone bundle — required for Docker deployment
  // Comment this out when deploying to Vercel (Vercel prefers default output)
  // output: "standalone",

  // Turbopack configuration (Next.js 16+)
  turbopack: {
    root: __dirname,
  },

  // Security headers on all routes
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: securityHeaders,
      },
    ];
  },

  // Redirect HTTP to HTTPS (handled by hosting platform, but guard here too)
  async redirects() {
    return [
      // Canonical trailing-slash redirect
      {
        source: "/:path+/",
        destination: "/:path+",
        permanent: true,
      },
    ];
  },

  // Image optimisation configuration
  images: {
    formats: ["image/avif", "image/webp"],
    dangerouslyAllowSVG: false,
    contentSecurityPolicy: "default-src 'self'; script-src 'none'; sandbox;",
  },

  // Logging (Next 16+)
  logging: {
    fetches: {
      fullUrl: process.env.NODE_ENV === "development",
    },
  },

  // Experimental features (enable as needed)
  experimental: {
    // optimizeCss: true,   // requires critters — enable once installed
    // ppr: true,           // partial prerendering — enable when GA
  },
};

export default nextConfig;
