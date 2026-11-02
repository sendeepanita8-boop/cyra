import { NextRequest, NextResponse } from "next/server";
import {
  calculateContextAwareScore,
  calculateOverallRisk,
  prioritizeFindings,
} from "@/lib/security/scoring";
import type { Finding } from "@/lib/types";
import {
  assertSafeResolution,
  checkRateLimit,
  isValidDomain,
  normalizeDomain,
} from "@/lib/security/guard";

// Dedicated scanner modules
import { scanHeaders }      from "@/lib/scanners/headers";
import { scanFrameOptions } from "@/lib/scanners/header";
import { scanCookies }      from "@/lib/scanners/cookies";
import { scanDNS }          from "@/lib/scanners/dns";
import { scanSSL }          from "@/lib/scanners/ssl";
import { scanRedirects }    from "@/lib/scanners/redirects";

/* =========================================================
   HELPERS
   ========================================================= */

function getClientIP(req: NextRequest): string {
  return (
    req.headers.get("x-forwarded-for")?.split(",")[0].trim() ??
    req.headers.get("x-real-ip") ??
    "unknown"
  );
}

/** Read at most maxBytes from a Response body to free the socket cleanly */
async function drainBody(response: Response, maxBytes = 2_097_152): Promise<void> {
  const reader = response.body?.getReader();
  if (!reader) return;
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done || !value) break;
      total += value.byteLength;
      if (total >= maxBytes) break;
    }
  } finally {
    reader.cancel().catch(() => {});
  }
}

/* =========================================================
   SERVER / TECHNOLOGY DISCLOSURE  (inline — header-based)
   ========================================================= */

function scanDisclosure(headers: Headers): Finding[] {
  const findings: Finding[] = [];

  const server = headers.get("server");
  if (server) {
    const hasVersion = /[\d.]{2,}/.test(server);
    findings.push({
      id: "server-disclosure",
      title: "Server Version Disclosure",
      category: "Server Information",
      severity: hasVersion ? "MEDIUM" : "LOW",
      status: "WARN",
      description: hasVersion
        ? `Server header exposes software version: "${server}".`
        : `Server header is present: "${server}".`,
      recommendation:
        "Remove or suppress the Server header to prevent version fingerprinting.",
      evidence: server,
    });
  } else {
    findings.push({
      id: "server-disclosure",
      title: "Server Version Disclosure",
      category: "Server Information",
      severity: "PASS",
      status: "PASS",
      description: "No Server response header was detected.",
      recommendation: "Continue minimising unnecessary technology disclosure.",
    });
  }

  const poweredBy = headers.get("x-powered-by");
  if (poweredBy) {
    findings.push({
      id: "x-powered-by",
      title: "Technology Disclosure (X-Powered-By)",
      category: "Server Information",
      severity: "LOW",
      status: "WARN",
      description: `X-Powered-By header reveals framework: "${poweredBy}".`,
      recommendation:
        "Remove the X-Powered-By header to prevent technology fingerprinting.",
      evidence: poweredBy,
    });
  } else {
    findings.push({
      id: "x-powered-by",
      title: "Technology Disclosure (X-Powered-By)",
      category: "Server Information",
      severity: "PASS",
      status: "PASS",
      description: "No X-Powered-By header was detected.",
      recommendation: "Continue minimising unnecessary technology disclosure.",
    });
  }

  // X-AspNet-Version / X-AspNetMvc-Version
  const aspVersion = headers.get("x-aspnet-version") ?? headers.get("x-aspnetmvc-version");
  if (aspVersion) {
    findings.push({
      id: "aspnet-version",
      title: "ASP.NET Version Disclosure",
      category: "Server Information",
      severity: "LOW",
      status: "WARN",
      description: `ASP.NET version header detected: "${aspVersion}".`,
      recommendation:
        "Remove X-AspNet-Version and X-AspNetMvc-Version response headers.",
      evidence: aspVersion,
    });
  }

  return findings;
}

/* =========================================================
   WEBSITE HEALTH CHECK  (inline — response telemetry)
   ========================================================= */

function scanHealth(statusCode: number, responseTime: number): Finding[] {
  const findings: Finding[] = [];

  // HTTP Status
  if (statusCode >= 200 && statusCode < 300) {
    findings.push({
      id: "health-status",
      title: "HTTP Status Code",
      category: "Website Health",
      severity: "PASS",
      status: "PASS",
      description: `The server returned HTTP ${statusCode} — website is reachable.`,
      recommendation: "Continue monitoring endpoint availability.",
      evidence: String(statusCode),
    });
  } else if (statusCode >= 400 && statusCode < 500) {
    findings.push({
      id: "health-status",
      title: "HTTP Status Code",
      category: "Website Health",
      severity: "HIGH",
      status: "FAIL",
      description: `The server returned HTTP ${statusCode} — client error response.`,
      recommendation: "Investigate and resolve the HTTP error response.",
      evidence: String(statusCode),
    });
  } else if (statusCode >= 500) {
    findings.push({
      id: "health-status",
      title: "HTTP Status Code",
      category: "Website Health",
      severity: "HIGH",
      status: "FAIL",
      description: `The server returned HTTP ${statusCode} — server error response.`,
      recommendation: "Investigate the server error and ensure reliable availability.",
      evidence: String(statusCode),
    });
  } else {
    findings.push({
      id: "health-status",
      title: "HTTP Status Code",
      category: "Website Health",
      severity: "INFO",
      status: "WARN",
      description: `The server returned HTTP ${statusCode}.`,
      recommendation: "Verify this response code is expected.",
      evidence: String(statusCode),
    });
  }

  // Response Time (latency SLA)
  if (responseTime <= 500) {
    findings.push({
      id: "health-latency",
      title: "Response Latency",
      category: "Website Health",
      severity: "PASS",
      status: "PASS",
      description: `Excellent response time of ${responseTime}ms — well within the 500ms SLA.`,
      recommendation: "Continue monitoring latency over time.",
      evidence: `${responseTime}ms`,
    });
  } else if (responseTime <= 1500) {
    findings.push({
      id: "health-latency",
      title: "Response Latency",
      category: "Website Health",
      severity: "INFO",
      status: "WARN",
      description: `Response time of ${responseTime}ms is acceptable but could be improved.`,
      recommendation: "Consider CDN caching, compression, or performance optimisation.",
      evidence: `${responseTime}ms`,
    });
  } else {
    findings.push({
      id: "health-latency",
      title: "Response Latency",
      category: "Website Health",
      severity: "MEDIUM",
      status: "WARN",
      description: `Slow response time of ${responseTime}ms detected — this may affect user experience.`,
      recommendation: "Investigate server performance, caching configuration, and network routing.",
      evidence: `${responseTime}ms`,
    });
  }

  return findings;
}

/* =========================================================
   ROUTE HANDLER
   ========================================================= */

export async function POST(request: NextRequest) {

  /* --------------------------------------------------
     1. RATE LIMITING
     -------------------------------------------------- */
  const clientIP = getClientIP(request);
  const { allowed, retryAfter } = checkRateLimit(clientIP);

  if (!allowed) {
    return NextResponse.json(
      {
        success: false,
        error: `Rate limit exceeded. Please wait ${retryAfter} second${retryAfter !== 1 ? "s" : ""} before trying again.`,
      },
      {
        status: 429,
        headers: {
          "Retry-After": String(retryAfter),
          "X-RateLimit-Limit": "10",
          "X-RateLimit-Window": "60",
        },
      }
    );
  }

  try {
    /* --------------------------------------------------
       2. INPUT PARSING & VALIDATION
       -------------------------------------------------- */
    let body: unknown;
    try {
      body = await request.json();
    } catch {
      return NextResponse.json(
        { success: false, error: "Invalid request body." },
        { status: 400 }
      );
    }

    const rawDomain = (body as Record<string, unknown>)?.domain;

    if (typeof rawDomain !== "string" || rawDomain.trim().length === 0) {
      return NextResponse.json(
        { success: false, error: "Domain is required." },
        { status: 400 }
      );
    }

    // Reject dangerous URI schemes before normalization
    const trimmed = rawDomain.trim().toLowerCase();
    const dangerousSchemes = ["file://", "ftp://", "gopher://", "dict://", "ldap://", "data:"];
    if (dangerousSchemes.some((s) => trimmed.startsWith(s))) {
      return NextResponse.json(
        { success: false, error: "Unsupported URL scheme." },
        { status: 400 }
      );
    }

    const domain = normalizeDomain(rawDomain);

    if (!isValidDomain(domain)) {
      return NextResponse.json(
        {
          success: false,
          error: "Please enter a valid public domain name (e.g. example.com).",
        },
        { status: 400 }
      );
    }

    /* --------------------------------------------------
       3. SSRF — DNS RESOLUTION CHECK
       -------------------------------------------------- */
    try {
      await assertSafeResolution(domain);
    } catch (ssrfError) {
      return NextResponse.json(
        { success: false, error: (ssrfError as Error).message },
        { status: 400 }
      );
    }

    /* --------------------------------------------------
       4. OUTBOUND HTTP REQUEST  (hardened)
       -------------------------------------------------- */
    const targetUrl = `https://${domain}`;
    const startTime = Date.now();
    let response: Response;

    try {
      response = await fetch(targetUrl, {
        method: "GET",
        redirect: "follow",
        cache: "no-store",
        headers: {
          "User-Agent": "CYRA-Security-Scanner/1.0 (+https://cyra.app/bot)",
          Accept: "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
          "Accept-Language": "en-US,en;q=0.5",
        },
        signal: AbortSignal.timeout(8_000),
      });
    } catch (err) {
      const isTimeout = err instanceof Error && err.name === "TimeoutError";
      return NextResponse.json(
        {
          success: false,
          error: isTimeout
            ? "The target website took too long to respond (8 s timeout)."
            : "CYRA could not connect to this website. Verify the domain and try again.",
        },
        { status: 502 }
      );
    }

    const responseTime = Date.now() - startTime;
    const finalUrl     = response.url;
    const statusCode   = response.status;
    const headers      = response.headers;

    // Drain body to free socket (2 MB cap)
    await drainBody(response);

    /* --------------------------------------------------
       5. RUN ALL SCANNERS IN PARALLEL
          – HTTP-based scanners use response data we already have
          – DNS and SSL scanners run concurrently with no extra fetch
       -------------------------------------------------- */
    const [dnsFindings, sslFindings] = await Promise.all([
      scanDNS(domain),
      scanSSL(domain),
    ]);

    const headerFindings      = scanHeaders(headers);
    const frameFindings       = scanFrameOptions(headers);
    const cookieFindings      = scanCookies(headers);
    const redirectFindings    = scanRedirects(targetUrl, finalUrl, statusCode);
    const disclosureFindings  = scanDisclosure(headers);
    const healthFindings      = scanHealth(statusCode, responseTime);

    // One consolidated HTTPS pass finding (SSL scanner covers TLS details)
    const httpsPassFinding: Finding = {
      id: "https-reachable",
      title: "HTTPS Connection",
      category: "HTTPS / SSL",
      severity: "PASS",
      status: "PASS",
      description: "The website is reachable over an HTTPS connection.",
      recommendation: "Continue using HTTPS across the entire website.",
      evidence: finalUrl,
    };

    const allFindings: Finding[] = [
      httpsPassFinding,
      ...headerFindings,
      ...frameFindings,
      ...cookieFindings,
      ...redirectFindings,
      ...disclosureFindings,
      ...healthFindings,
      ...dnsFindings,
      ...sslFindings,
    ];

    /* --------------------------------------------------
       6. SCORING & RESPONSE
       -------------------------------------------------- */
    const prioritizedFindings = prioritizeFindings(allFindings);
    const overallRisk         = calculateOverallRisk(allFindings);
    const intelligence        = calculateContextAwareScore(allFindings);

    return NextResponse.json({
      success: true,
      data: {
        domain,
        finalUrl,
        statusCode,
        responseTime,
        scannedAt: new Date().toISOString(),
        findings: prioritizedFindings,
        risk: {
          level:       overallRisk.level,
          priority:    overallRisk.priority,
          explanation: overallRisk.explanation,
          context:     overallRisk.context,
          area:        overallRisk.area,
        },
        intelligence: {
          score:           intelligence.score,
          status:          intelligence.status,
          riskLevel:       intelligence.riskLevel,
          posture:         intelligence.posture,
          topRisks:        intelligence.topRisks,
          recommendations: intelligence.recommendations,
          areas:           intelligence.areas,
          context:         intelligence.context,
          summary:         intelligence.summary,
        },
      },
    });

  } catch (error) {
    console.error("CYRA scan error:", error);
    return NextResponse.json(
      { success: false, error: "CYRA encountered an unexpected error. Please try again." },
      { status: 500 }
    );
  }
}
