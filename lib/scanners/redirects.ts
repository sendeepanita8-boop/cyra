import type { Finding } from "../types";

function normalizeUrl(url: string): string {
  return url.trim().replace(/\/+$/, "");
}

export function scanRedirects(
  originalUrl: string,
  finalUrl: string,
  statusCode: number
): Finding[] {
  const findings: Finding[] = [];

  const original = normalizeUrl(originalUrl);
  const final = normalizeUrl(finalUrl);

  const originalIsHttps = original.startsWith("https://");
  const finalIsHttps = final.startsWith("https://");

  /*
   * Final HTTPS check
   */
  if (finalIsHttps) {
    findings.push({
      id: "redirect-https",
      title: "HTTPS Final Destination",
      category: "Redirects",
      severity: "PASS",
      status: "PASS",
      description:
        "The scanned URL ultimately resolves to an HTTPS destination.",
      recommendation:
        "Continue serving the website over HTTPS.",
      evidence: final,
    });
  } else {
    findings.push({
      id: "redirect-https",
      title: "HTTPS Final Destination",
      category: "Redirects",
      severity: "HIGH",
      status: "FAIL",
      description:
        "The final destination of the scan is not using HTTPS.",
      recommendation:
        "Configure the website so normal public traffic ends at an HTTPS URL.",
      evidence: final,
    });
  }

  /*
   * HTTP → HTTPS behavior
   */
  if (!originalIsHttps) {
    if (statusCode >= 300 && statusCode < 400) {
      if (finalIsHttps) {
        findings.push({
          id: "redirect-http-to-https",
          title: "HTTP to HTTPS Redirect",
          category: "Redirects",
          severity: "PASS",
          status: "PASS",
          description:
            "The HTTP request returned a redirect and the final destination uses HTTPS.",
          recommendation:
            "Keep the HTTP-to-HTTPS redirect enabled.",
          evidence:
            `${statusCode} → ${final}`,
        });
      } else {
        findings.push({
          id: "redirect-http-to-https",
          title: "HTTP to HTTPS Redirect",
          category: "Redirects",
          severity: "HIGH",
          status: "FAIL",
          description:
            "The HTTP request redirects, but the final destination is not HTTPS.",
          recommendation:
            "Redirect HTTP traffic directly to the HTTPS version of the website.",
          evidence:
            `${statusCode} → ${final}`,
        });
      }
    } else if (finalIsHttps) {
      findings.push({
        id: "redirect-http-to-https",
        title: "HTTP to HTTPS Redirect",
        category: "Redirects",
        severity: "INFO",
        status: "PASS",
        description:
          "The final scanned destination is HTTPS, but the current response did not expose a redirect status.",
        recommendation:
          "Verify separately that direct HTTP requests consistently redirect to HTTPS.",
        evidence:
          `HTTP response: ${statusCode}`,
      });
    } else {
      findings.push({
        id: "redirect-http-to-https",
        title: "HTTP to HTTPS Redirect",
        category: "Redirects",
        severity: "HIGH",
        status: "FAIL",
        description:
          "The scanned HTTP request did not result in an HTTPS final destination.",
        recommendation:
          "Configure a permanent HTTP-to-HTTPS redirect.",
        evidence:
          `HTTP response: ${statusCode}`,
      });
    }
  } else {
    findings.push({
      id: "redirect-http-to-https",
      title: "HTTP to HTTPS Redirect",
      category: "Redirects",
      severity: "INFO",
      status: "PASS",
      description:
        "The scanner started directly from an HTTPS URL, so HTTP redirect behavior was not tested by this check.",
      recommendation:
        "Test the HTTP endpoint separately to verify that it redirects to HTTPS.",
      evidence:
        "Scan started with HTTPS",
    });
  }

  /*
   * Redirect destination consistency
   */
  try {
    const originalParsed = new URL(original);
    const finalParsed = new URL(final);

    if (
      originalParsed.hostname !== finalParsed.hostname &&
      finalParsed.hostname !== `www.${originalParsed.hostname}` &&
      originalParsed.hostname !== `www.${finalParsed.hostname}`
    ) {
      findings.push({
        id: "redirect-cross-domain",
        title: "Cross-Domain Redirect",
        category: "Redirects",
        severity: "MEDIUM",
        status: "WARN",
        description:
          "The scan ended on a different hostname from the original domain.",
        recommendation:
          "Verify that the cross-domain redirect is intentional and points to a trusted destination.",
        evidence:
          `${originalParsed.hostname} → ${finalParsed.hostname}`,
      });
    } else {
      findings.push({
        id: "redirect-cross-domain",
        title: "Redirect Destination",
        category: "Redirects",
        severity: "PASS",
        status: "PASS",
        description:
          "The final redirect destination remains on the same domain or its www variant.",
        recommendation:
          "Continue reviewing redirect destinations when website infrastructure changes.",
        evidence:
          finalParsed.hostname,
      });
    }
  } catch {
    findings.push({
      id: "redirect-destination",
      title: "Redirect Destination",
      category: "Redirects",
      severity: "INFO",
      status: "WARN",
      description:
        "CYRA could not parse the final redirect destination.",
      recommendation:
        "Verify the website's redirect configuration manually.",
      evidence: final,
    });
  }

  return findings;
}
