import type { Finding } from "../types";

function parseSetCookieHeaders(headers: Headers): string[] {
  // Headers.getSetCookie() is available in modern Node.js runtimes.
  // The fallback keeps the scanner compatible with environments where
  // it is not available.
  if (typeof headers.getSetCookie === "function") {
    return headers.getSetCookie();
  }

  const combined = headers.get("set-cookie");

  if (!combined) {
    return [];
  }

  return combined
    .split(/,(?=\s*[^;,=\s]+=[^;,]+)/)
    .map((cookie) => cookie.trim())
    .filter(Boolean);
}

function getCookieName(cookie: string): string {
  return cookie.split("=")[0]?.trim() || "Unknown";
}

function hasAttribute(
  cookie: string,
  attribute: string
): boolean {
  const regex = new RegExp(
    `(?:^|;)\\s*${attribute}(?:=|;|$)`,
    "i"
  );

  return regex.test(cookie);
}

function getSameSiteValue(
  cookie: string
): string | null {
  const match = cookie.match(
    /(?:^|;)\s*SameSite\s*=\s*([^;]+)/i
  );

  return match?.[1]?.trim().toLowerCase() ?? null;
}

export function scanCookies(
  headers: Headers
): Finding[] {
  const findings: Finding[] = [];

  const cookies = parseSetCookieHeaders(headers);

  if (cookies.length === 0) {
    findings.push({
      id: "cookies-detected",
      title: "Set-Cookie Headers",
      category: "Cookies",
      severity: "INFO",
      status: "PASS",
      description:
        "No Set-Cookie response headers were detected.",
      recommendation:
        "If the website does not require cookies, no action is necessary.",
    });

    return findings;
  }

  findings.push({
    id: "cookies-detected",
    title: "Set-Cookie Headers",
    category: "Cookies",
    severity: "INFO",
    status: "PASS",
    description:
      `${cookies.length} Set-Cookie header${
        cookies.length === 1 ? "" : "s"
      } were detected.`,
    recommendation:
      "Review cookies periodically and remove cookies that are no longer required.",
    evidence: cookies
      .map((cookie) => getCookieName(cookie))
      .join(", "),
  });

  let missingSecure = 0;
  let missingHttpOnly = 0;
  let missingSameSite = 0;

  const cookieNames: string[] = [];

  for (const cookie of cookies) {
    const name = getCookieName(cookie);

    cookieNames.push(name);

    const secure = hasAttribute(cookie, "Secure");
    const httpOnly = hasAttribute(cookie, "HttpOnly");
    const sameSite = getSameSiteValue(cookie);

    if (!secure) {
      missingSecure++;
    }

    if (!httpOnly) {
      missingHttpOnly++;
    }

    if (!sameSite) {
      missingSameSite++;
    }
  }

  /*
   * SECURE
   */
  if (missingSecure === 0) {
    findings.push({
      id: "cookies-secure",
      title: "Secure Cookie Attribute",
      category: "Cookies",
      severity: "PASS",
      status: "PASS",
      description:
        "All detected cookies include the Secure attribute.",
      recommendation:
        "Keep the Secure attribute enabled for cookies that should only travel over HTTPS.",
    });
  } else {
    findings.push({
      id: "cookies-secure",
      title: "Secure Cookie Attribute",
      category: "Cookies",
      severity: "MEDIUM",
      status: "WARN",
      description:
        `${missingSecure} of ${cookies.length} detected cookie${
          cookies.length === 1 ? "" : "s"
        } do not include the Secure attribute.`,
      recommendation:
        "Add the Secure attribute to cookies that contain sensitive or session-related data.",
      evidence: cookieNames.join(", "),
    });
  }

  /*
   * HTTPONLY
   */
  if (missingHttpOnly === 0) {
    findings.push({
      id: "cookies-httponly",
      title: "HttpOnly Cookie Attribute",
      category: "Cookies",
      severity: "PASS",
      status: "PASS",
      description:
        "All detected cookies include the HttpOnly attribute.",
      recommendation:
        "Keep HttpOnly enabled for cookies that do not need JavaScript access.",
    });
  } else {
    findings.push({
      id: "cookies-httponly",
      title: "HttpOnly Cookie Attribute",
      category: "Cookies",
      severity: "LOW",
      status: "WARN",
      description:
        `${missingHttpOnly} of ${cookies.length} detected cookie${
          cookies.length === 1 ? "" : "s"
        } do not include the HttpOnly attribute.`,
      recommendation:
        "Use HttpOnly for session and other sensitive cookies that do not need client-side JavaScript access.",
      evidence: cookieNames.join(", "),
    });
  }

  /*
   * SAMESITE
   */
  if (missingSameSite === 0) {
    findings.push({
      id: "cookies-samesite",
      title: "SameSite Cookie Attribute",
      category: "Cookies",
      severity: "PASS",
      status: "PASS",
      description:
        "All detected cookies specify a SameSite attribute.",
      recommendation:
        "Keep SameSite configured according to the application's cross-site requirements.",
    });
  } else {
    findings.push({
      id: "cookies-samesite",
      title: "SameSite Cookie Attribute",
      category: "Cookies",
      severity: "LOW",
      status: "WARN",
      description:
        `${missingSameSite} of ${cookies.length} detected cookie${
          cookies.length === 1 ? "" : "s"
        } do not specify SameSite.`,
      recommendation:
        "Consider setting SameSite explicitly to Lax or Strict based on the application's needs.",
      evidence: cookieNames.join(", "),
    });
  }

  return findings;
}
