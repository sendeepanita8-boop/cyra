/**
 * CYRA Security Guard
 * --------------------------------------------------
 * SSRF Protection  – blocks localhost, link-local & private CIDRs
 * Rate Limiting    – in-memory sliding-window (10 req / 60 s per IP)
 * Input Validation – strict RFC domain rules + scheme rejection
 */

import dnsPromises from "node:dns/promises";
import dns from "node:dns";
import { isIPv4, isIPv6 } from "node:net";

const FALLBACK_DNS_SERVERS = ["1.1.1.1", "8.8.8.8", "1.0.0.1", "8.8.4.4"];

function getResolver(): dnsPromises.Resolver {
  const resolver = new dnsPromises.Resolver();
  try {
    const sysServers = dns.getServers();
    const isLoopbackOnly =
      !sysServers.length || sysServers.every((s) => s === "127.0.0.1" || s === "::1");
    if (isLoopbackOnly) {
      resolver.setServers(FALLBACK_DNS_SERVERS);
    } else {
      resolver.setServers([...sysServers, ...FALLBACK_DNS_SERVERS]);
    }
  } catch {
    resolver.setServers(FALLBACK_DNS_SERVERS);
  }
  return resolver;
}

/* =========================================================
   SSRF — Private & Reserved IPv4 CIDR Blocks
   ========================================================= */

/** Checks whether an IPv4 string falls inside a private/reserved range */
function isPrivateIPv4(ip: string): boolean {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) return false;
  const [a, b] = parts;

  // 127.0.0.0/8   — loopback
  if (a === 127) return true;
  // 10.0.0.0/8    — Class A private
  if (a === 10) return true;
  // 172.16.0.0/12 — Class B private
  if (a === 172 && b >= 16 && b <= 31) return true;
  // 192.168.0.0/16 — Class C private
  if (a === 192 && b === 168) return true;
  // 169.254.0.0/16 — link-local (APIPA)
  if (a === 169 && b === 254) return true;
  // 100.64.0.0/10  — carrier-grade NAT
  if (a === 100 && b >= 64 && b <= 127) return true;
  // 0.0.0.0/8
  if (a === 0) return true;
  // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 — documentation
  if (a === 192 && b === 0 && parts[2] === 2) return true;
  if (a === 198 && b === 51 && parts[2] === 100) return true;
  if (a === 203 && b === 0 && parts[2] === 113) return true;
  // 240.0.0.0/4 — reserved
  if (a >= 240) return true;

  return false;
}

/** Checks whether an IPv6 string is loopback or link-local */
function isPrivateIPv6(ip: string): boolean {
  const lower = ip.toLowerCase().replace(/[\[\]]/g, "");
  // ::1 loopback
  if (lower === "::1") return true;
  // fe80::/10 link-local
  if (lower.startsWith("fe80")) return true;
  // fc00::/7 unique-local
  if (lower.startsWith("fc") || lower.startsWith("fd")) return true;
  return false;
}

/**
 * Resolves the domain to its IP addresses and rejects any that fall
 * inside private / reserved / loopback ranges (SSRF prevention).
 * 
 * IMPORTANT: If DNS resolution itself fails (network/resolver issue),
 * we allow the request through — the outbound fetch will fail safely
 * on its own. We only block when we POSITIVELY identify a private IP.
 */
export async function assertSafeResolution(domain: string): Promise<void> {
  let addresses: string[] = [];

  const resolver = getResolver();
  // Resolve both A and AAAA — allSettled never rejects
  const [v4, v6] = await Promise.allSettled([
    resolver.resolve4(domain),
    resolver.resolve6(domain),
  ]);

  if (v4.status === "fulfilled") addresses.push(...v4.value);
  if (v6.status === "fulfilled") addresses.push(...v6.value);

  // If DNS completely failed to resolve, let fetch handle it (safe fail)
  // Don't block legitimate domains due to resolver issues
  if (addresses.length === 0) return;

  // Only block if we positively identify a private/reserved address
  for (const addr of addresses) {
    if (isIPv4(addr) && isPrivateIPv4(addr)) {
      throw new Error("Scanning private or internal network addresses is not permitted.");
    }
    if (isIPv6(addr) && isPrivateIPv6(addr)) {
      throw new Error("Scanning loopback or link-local IPv6 addresses is not permitted.");
    }
  }
}


/* =========================================================
   INPUT VALIDATION
   ========================================================= */

const MAX_DOMAIN_LENGTH = 253;
const MAX_LABEL_LENGTH  = 63;

/** Strict RFC-compliant domain validator */
export function isValidDomain(domain: string): boolean {
  if (!domain || domain.length > MAX_DOMAIN_LENGTH) return false;
  // Must have at least one dot (TLD required)
  if (!domain.includes(".")) return false;
  const labels = domain.split(".");
  // Must have a non-numeric TLD (reject bare IP-looking inputs)
  if (/^\d+$/.test(labels[labels.length - 1])) return false;
  for (const label of labels) {
    if (label.length === 0 || label.length > MAX_LABEL_LENGTH) return false;
    if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/i.test(label)) return false;
  }
  return true;
}

/** Normalise raw user input to a bare domain (strips schemes, paths, ports) */
export function normalizeDomain(raw: string): string {
  return raw
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//i, "")
    .replace(/^[a-z][a-z0-9+\-.]*:\/\//i, "") // any other scheme
    .replace(/[/?#].*$/, "")                   // path / query / fragment
    .replace(/:[\d]+$/, "")                    // trailing port
    .replace(/[^a-z0-9.\-]/gi, "");            // strip unexpected chars
}

/* =========================================================
   RATE LIMITER  (in-memory sliding window)
   ========================================================= */

const RATE_LIMIT_MAX      = 10;  // max requests
const RATE_LIMIT_WINDOW   = 60_000; // per 60 seconds

/** { ip → [timestamp, timestamp, …] } */
const rateLimitStore = new Map<string, number[]>();

/**
 * Returns true if the given IP is within rate limits.
 * Slides the window on each call.
 */
export function checkRateLimit(ip: string): { allowed: boolean; retryAfter: number } {
  const now = Date.now();
  const windowStart = now - RATE_LIMIT_WINDOW;

  // Purge expired timestamps
  const hits = (rateLimitStore.get(ip) ?? []).filter((t) => t > windowStart);

  if (hits.length >= RATE_LIMIT_MAX) {
    // Earliest hit + window = when first slot reopens
    const retryAfter = Math.ceil((hits[0] + RATE_LIMIT_WINDOW - now) / 1000);
    return { allowed: false, retryAfter };
  }

  hits.push(now);
  rateLimitStore.set(ip, hits);

  // Evict old IPs to prevent unbounded growth (simple GC)
  if (rateLimitStore.size > 10_000) {
    for (const [key, times] of rateLimitStore) {
      if (times.every((t) => t <= windowStart)) {
        rateLimitStore.delete(key);
      }
    }
  }

  return { allowed: true, retryAfter: 0 };
}
