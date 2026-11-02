/**
 * CYRA — X-Frame-Options Scanner
 * -----------------------------------------------
 * Dedicated module for clickjacking defense header.
 * Kept separate from headers.ts for modularity.
 */

import type { Finding } from "../types";

/**
 * Inspects the X-Frame-Options header to detect clickjacking exposure.
 * Modern alternative: `frame-ancestors` directive in CSP — checked here too.
 */
export function scanFrameOptions(headers: Headers): Finding[] {
  const findings: Finding[] = [];

  const xfo = headers.get("x-frame-options");
  const csp = headers.get("content-security-policy") ?? "";
  const hasFrameAncestors = csp.toLowerCase().includes("frame-ancestors");

  if (xfo) {
    const value = xfo.toUpperCase().trim();
    const isValid = value === "DENY" || value === "SAMEORIGIN";

    if (isValid) {
      findings.push({
        id: "x-frame-options",
        title: "Clickjacking Defense (X-Frame-Options)",
        category: "HTTP Headers",
        severity: "PASS",
        status: "PASS",
        description: `X-Frame-Options is set to "${xfo}", preventing malicious iframes from embedding this page.`,
        recommendation:
          "Keep X-Frame-Options enforced. Consider migrating to CSP frame-ancestors for finer-grained control.",
        evidence: `X-Frame-Options: ${xfo}`,
      });
    } else {
      findings.push({
        id: "x-frame-options",
        title: "Clickjacking Defense (X-Frame-Options)",
        category: "HTTP Headers",
        severity: "LOW",
        status: "WARN",
        description: `X-Frame-Options is set to an unrecognised value: "${xfo}". Only DENY and SAMEORIGIN are effective.`,
        recommendation:
          'Set X-Frame-Options to DENY or SAMEORIGIN. Alternatively, use Content-Security-Policy: frame-ancestors \'self\'.',
        evidence: `X-Frame-Options: ${xfo}`,
      });
    }
  } else if (hasFrameAncestors) {
    // CSP frame-ancestors is the modern, preferred approach
    findings.push({
      id: "x-frame-options",
      title: "Clickjacking Defense (frame-ancestors CSP)",
      category: "HTTP Headers",
      severity: "PASS",
      status: "PASS",
      description:
        "X-Frame-Options is absent but the Content-Security-Policy header includes a frame-ancestors directive — the modern standard for clickjacking protection.",
      recommendation:
        "Continue enforcing frame-ancestors in your CSP. You may optionally add X-Frame-Options for legacy browser support.",
      evidence: "CSP frame-ancestors directive detected",
    });
  } else {
    findings.push({
      id: "x-frame-options",
      title: "Clickjacking Defense (X-Frame-Options)",
      category: "HTTP Headers",
      severity: "MEDIUM",
      status: "WARN",
      description:
        "Neither X-Frame-Options nor a CSP frame-ancestors directive was detected. The page may be embeddable in third-party iframes.",
      recommendation:
        "Add X-Frame-Options: DENY or Content-Security-Policy: frame-ancestors 'none' to prevent clickjacking attacks.",
    });
  }

  return findings;
}
