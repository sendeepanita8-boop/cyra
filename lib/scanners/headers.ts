import type { Finding } from "../types";

export function scanHeaders(headers: Headers): Finding[] {
  const findings: Finding[] = [];

  const hsts = headers.get("strict-transport-security");
  if (hsts) {
    findings.push({
      id: "hsts",
      title: "HTTP Strict Transport Security",
      category: "HTTP Headers",
      severity: "PASS",
      status: "PASS",
      description: "The website sends an HSTS policy.",
      recommendation: "Keep HSTS enabled and review the max-age and includeSubDomains settings.",
      evidence: hsts,
    });
  } else {
    findings.push({
      id: "hsts",
      title: "HTTP Strict Transport Security",
      category: "HTTP Headers",
      severity: "MEDIUM",
      status: "WARN",
      description: "No Strict-Transport-Security header was detected.",
      recommendation: "Consider enabling HSTS after confirming that the site is correctly served over HTTPS.",
    });
  }

  const csp = headers.get("content-security-policy");
  if (csp) {
    findings.push({
      id: "csp",
      title: "Content Security Policy",
      category: "HTTP Headers",
      severity: "PASS",
      status: "PASS",
      description: "A Content-Security-Policy header was detected.",
      recommendation: "Review and maintain a restrictive policy that matches the application.",
      evidence: csp,
    });
  } else {
    findings.push({
      id: "csp",
      title: "Content Security Policy",
      category: "HTTP Headers",
      severity: "MEDIUM",
      status: "WARN",
      description: "No Content-Security-Policy header was detected.",
      recommendation: "Consider implementing a CSP appropriate for the site's resources.",
    });
  }

  const xcto = headers.get("x-content-type-options");
  if (xcto?.toLowerCase() === "nosniff") {
    findings.push({
      id: "x-content-type-options",
      title: "MIME Type Protection",
      category: "HTTP Headers",
      severity: "PASS",
      status: "PASS",
      description: "X-Content-Type-Options is set to nosniff.",
      recommendation: "Keep this protection enabled.",
      evidence: xcto,
    });
  } else {
    findings.push({
      id: "x-content-type-options",
      title: "MIME Type Protection",
      category: "HTTP Headers",
      severity: "LOW",
      status: "WARN",
      description: "The expected X-Content-Type-Options: nosniff header was not detected.",
      recommendation: "Consider setting X-Content-Type-Options to nosniff.",
    });
  }

  const referrerPolicy = headers.get("referrer-policy");
  if (referrerPolicy) {
    findings.push({
      id: "referrer-policy",
      title: "Referrer Policy",
      category: "HTTP Headers",
      severity: "PASS",
      status: "PASS",
      description: "A Referrer-Policy header was detected.",
      recommendation: "Review the policy to ensure it matches the site's privacy requirements.",
      evidence: referrerPolicy,
    });
  } else {
    findings.push({
      id: "referrer-policy",
      title: "Referrer Policy",
      category: "HTTP Headers",
      severity: "LOW",
      status: "WARN",
      description: "No Referrer-Policy header was detected.",
      recommendation: "Consider configuring a suitable Referrer-Policy.",
    });
  }

  const permissionsPolicy = headers.get("permissions-policy");
  if (permissionsPolicy) {
    findings.push({
      id: "permissions-policy",
      title: "Permissions Policy",
      category: "HTTP Headers",
      severity: "PASS",
      status: "PASS",
      description: "A Permissions-Policy header was detected.",
      recommendation: "Keep unnecessary browser capabilities disabled.",
      evidence: permissionsPolicy,
    });
  } else {
    findings.push({
      id: "permissions-policy",
      title: "Permissions Policy",
      category: "HTTP Headers",
      severity: "INFO",
      status: "WARN",
      description: "No Permissions-Policy header was detected.",
      recommendation: "Consider configuring Permissions-Policy based on the website's real feature needs.",
    });
  }

  return findings;
}
