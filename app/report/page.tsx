"use client";

import { useEffect, useState, useMemo } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import ScanBox from "@/components/ScanBox";

/* =========================================
   TYPES
========================================= */

type Severity = "PASS" | "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
type Status = "PASS" | "WARN" | "FAIL";

type Finding = {
  id: string;
  title: string;
  category: string;
  severity: Severity;
  status: Status;
  description: string;
  whyItMatters?: string;
  recommendation: string;
  evidence?: string;
};

type RiskInfo = {
  level: string;
  priority: number;
  explanation: string;
  context?: string;
  area?: string;
};

type AttackSurface = {
  name: string;
  value: string;
  severity: "Low" | "Moderate" | "High" | "Critical";
};

type Intelligence = {
  score: number;
  status: string;
  riskLevel: string;
  posture: {
    score: number;
    status: string;
    riskLevel: string;
    areas: string[];
    attackSurface: AttackSurface[];
    summary: string;
  };
  topRisks: Finding[];
  recommendations: string[];
  areas: string[];
  context: string;
  summary: string;
};

type ScanResult = {
  domain: string;
  finalUrl: string;
  statusCode: number;
  responseTime: number;
  scannedAt: string;
  findings: Finding[];
  risk?: RiskInfo;
  intelligence?: Intelligence;
};

/* =========================================
   CANONICAL CATEGORIES
========================================= */

const CANONICAL_CATEGORIES = [
  "Security Headers",
  "HTTPS / SSL",
  "Cookies",
  "DNS",
  "Redirects",
  "Server Information",
  "Content Security",
  "Website Health",
] as const;

function normalizeCategory(category: string): string {
  const c = category.toLowerCase();
  if (c.includes("ssl") || c.includes("tls") || c.includes("https")) return "HTTPS / SSL";
  if (c.includes("cookie")) return "Cookies";
  if (c.includes("dns") || c.includes("email") || c.includes("spf") || c.includes("dmarc")) return "DNS";
  if (c.includes("redirect")) return "Redirects";
  if (c.includes("server") || c.includes("exposure") || c.includes("disclosure")) return "Server Information";
  if (c.includes("csp") || c.includes("content security")) return "Content Security";
  if (c.includes("health") || c.includes("availability") || c.includes("performance")) return "Website Health";
  return "Security Headers";
}

function resolveWhyItMatters(finding: Finding): string {
  if (finding.whyItMatters && finding.whyItMatters.trim()) {
    return finding.whyItMatters;
  }
  const id = finding.id.toLowerCase();
  const title = finding.title.toLowerCase();

  if (id.includes("csp") || title.includes("content security policy")) {
    return "Without a Content Security Policy, browsers will execute any injected code, leaving users exposed to Cross-Site Scripting (XSS) and data exfiltration.";
  }
  if (id.includes("hsts") || title.includes("strict-transport-security")) {
    return "HSTS prevents downgrade attacks and ensures browsers never communicate over insecure HTTP channels, preventing cookie theft on public networks.";
  }
  if (id.includes("xcto") || title.includes("mime") || title.includes("content-type")) {
    return "Enforcing 'nosniff' blocks MIME confusion attacks where untrusted uploads are masqueraded and executed as executable scripts.";
  }
  if (id.includes("xfo") || title.includes("frame")) {
    return "Framing restrictions prevent clickjacking attacks where transparent overlay frames trick authenticated users into unauthorized actions.";
  }
  if (id.includes("referrer") || title.includes("referrer-policy")) {
    return "Restricting referrer data prevents internal paths, session tokens, and navigation history from leaking to external websites.";
  }
  if (id.includes("permission") || title.includes("permissions-policy")) {
    return "Permissions policy blocks unauthorized browser access to camera, microphone, and geolocation sensors by third-party scripts.";
  }
  if (id.includes("cookie") || title.includes("cookie")) {
    return "Missing Secure, HttpOnly, or SameSite attributes allows scripts or network attackers to hijack user authentication sessions.";
  }
  if (id.includes("server") || id.includes("powered") || title.includes("exposure")) {
    return "Publishing exact server versions lets attackers target known public CVE exploits matching that specific distribution.";
  }
  if (id.includes("spf") || id.includes("dmarc") || title.includes("dns")) {
    return "Incomplete DNS and mail protection enables malicious actors to forge emails from your domain, driving phishing campaigns.";
  }
  if (id.includes("https") || title.includes("ssl")) {
    return "Transport layer encryption guarantees data privacy and prevents in-transit payload tampering.";
  }
  if (id.includes("redirect")) {
    return "Automatic HTTP-to-HTTPS redirects protect visitors who enter unencrypted URLs from initial cleartext transmission.";
  }
  return "Hardening this setting mitigates external attack vectors and aligns with OWASP defense-in-depth security standards.";
}

/* =========================================
   SAMPLE AUDIT DEMO DATA
========================================= */

const DEMO_REPORT: ScanResult = {
  domain: "fintech-corp.example.com",
  finalUrl: "https://fintech-corp.example.com",
  statusCode: 200,
  responseTime: 142,
  scannedAt: new Date().toISOString(),
  risk: {
    level: "Moderate",
    priority: 52,
    explanation: "Solid TLS encryption and DNS defenses. Remediation needed for Content Security Policy and server banner disclosure.",
    context: "Website",
    area: "Configuration",
  },
  intelligence: {
    score: 82,
    status: "Stable",
    riskLevel: "Moderate",
    posture: {
      score: 82,
      status: "Stable",
      riskLevel: "Moderate",
      areas: ["TLS", "HTTP Headers", "DNS", "Cookies", "Configuration"],
      attackSurface: [
        { name: "TLS Version", value: "TLS 1.3 Active & Enforced", severity: "Low" },
        { name: "HSTS Policy", value: "max-age=31536000; includeSubDomains", severity: "Low" },
        { name: "Content-Security-Policy", value: "Missing directive", severity: "High" },
        { name: "Server Header", value: "nginx/1.24.0 disclosed", severity: "Moderate" },
        { name: "Cookie Security", value: "Missing Secure flag on 1 cookie", severity: "Moderate" },
        { name: "DNSSEC", value: "Validated & Active", severity: "Low" },
      ],
      summary: "CYRA evaluated the target perimeter. The host demonstrates robust transport encryption and DNS configuration, but lacks advanced browser defenses (CSP) and exposes server version signatures.",
    },
    topRisks: [
      {
        id: "csp-missing",
        title: "Content Security Policy (CSP) Missing",
        category: "Content Security",
        severity: "HIGH",
        status: "FAIL",
        description: "No Content-Security-Policy header was detected. Without CSP, the browser has no origin enforcement against malicious scripts.",
        whyItMatters: "CSP is the foremost defense against Cross-Site Scripting (XSS), clickjacking, and unauthorized third-party script injection.",
        recommendation: "Implement a restrictive Content-Security-Policy defining default-src 'self', script-src, and frame-ancestors.",
        evidence: "Content-Security-Policy: null",
      },
      {
        id: "server-tokens",
        title: "Server Software Version Disclosed",
        category: "Server Information",
        severity: "MEDIUM",
        status: "WARN",
        description: "The HTTP response exposes explicit server banner 'nginx/1.24.0', facilitating targeted exploit discovery.",
        whyItMatters: "Detailed version numbers allow attackers to match public CVE vulnerabilities to your exact operating system and web server build.",
        recommendation: "Configure server_tokens off in nginx.conf or suppress banner headers at the reverse proxy layer.",
        evidence: "Server: nginx/1.24.0 (Ubuntu)",
      },
      {
        id: "cookie-samesite",
        title: "Cookie Missing SameSite & Secure Attributes",
        category: "Cookies",
        severity: "MEDIUM",
        status: "WARN",
        description: "Session cookie 'session_token' was set without SameSite=Lax/Strict and lacks explicit Secure transmission enforcement.",
        whyItMatters: "Missing cookie flags enable Cross-Site Request Forgery (CSRF) attacks and risk session leakage over unencrypted links.",
        recommendation: "Ensure all set-cookie directives include 'Secure; HttpOnly; SameSite=Lax' to prevent CSRF and session hijacking.",
        evidence: "Set-Cookie: session_token=ab7f920c; Path=/",
      },
    ],
    recommendations: [
      "Deploy a restrictive Content Security Policy (CSP) with report-to endpoints.",
      "Disable server version identification banners in web server configuration.",
      "Enforce HttpOnly, Secure, and SameSite attributes on all application cookies.",
      "Add Permissions-Policy to explicitly restrict camera, geolocation, and microphone access.",
      "Configure CAA (Certificate Authority Authorization) records in DNS.",
    ],
    areas: ["TLS", "HTTP Headers", "DNS", "Cookies", "Configuration"],
    context: "Website",
    summary: "Perimeter assessment complete. 11 of 15 security checks passed. Implement recommended header protections to achieve an A+ security posture.",
  },
  findings: [
    {
      id: "https",
      title: "HTTPS Connection & TLS 1.3",
      category: "HTTPS / SSL",
      severity: "PASS",
      status: "PASS",
      description: "The website enforces valid HTTPS and establishes connection using modern cipher suites.",
      whyItMatters: "Guarantees confidentiality and data integrity between website visitors and your servers.",
      recommendation: "Maintain certificate auto-renewal and ensure legacy TLS 1.0/1.1 remain permanently disabled.",
      evidence: "Protocol: TLSv1.3 | Cipher: TLS_AES_256_GCM_SHA384",
    },
    {
      id: "hsts",
      title: "HTTP Strict Transport Security (HSTS)",
      category: "Security Headers",
      severity: "PASS",
      status: "PASS",
      description: "HSTS header is enabled with high max-age (31,536,000 seconds), protecting users against SSL-stripping attacks.",
      whyItMatters: "Prevents attackers from downgrading HTTPS connections to unencrypted HTTP.",
      recommendation: "Ensure includeSubDomains and preload directives are audited before submitting to the HSTS preload list.",
      evidence: "Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    {
      id: "csp-missing",
      title: "Content Security Policy (CSP)",
      category: "Content Security",
      severity: "HIGH",
      status: "FAIL",
      description: "No Content-Security-Policy header was detected. Without CSP, the browser has no origin enforcement against malicious scripts.",
      whyItMatters: "CSP is the foremost web standard for neutralizing Cross-Site Scripting (XSS) and malicious data injection.",
      recommendation: "Define a Content-Security-Policy with default-src 'self' and disallow unsafe-inline scripts.",
      evidence: "Content-Security-Policy header missing from response headers",
    },
    {
      id: "xcto",
      title: "MIME Type Sniffing Defense (XCTO)",
      category: "Security Headers",
      severity: "PASS",
      status: "PASS",
      description: "X-Content-Type-Options is set to 'nosniff', instructing browsers to strictly adhere to declared content types.",
      whyItMatters: "Blocks browser MIME-type sniffing which attackers exploit to execute scripts masquerading as harmless images.",
      recommendation: "Keep this protection permanently enabled across all static and dynamic responses.",
      evidence: "X-Content-Type-Options: nosniff",
    },
    {
      id: "xfo",
      title: "Clickjacking Defense (X-Frame-Options)",
      category: "Security Headers",
      severity: "PASS",
      status: "PASS",
      description: "X-Frame-Options is set to 'DENY' or 'SAMEORIGIN', preventing malicious websites from framing this application.",
      whyItMatters: "Stops clickjacking attacks where a transparent iframe tricks users into clicking disguised malicious buttons.",
      recommendation: "Continue enforcing frame restrictions across all authenticated routes.",
      evidence: "X-Frame-Options: SAMEORIGIN",
    },
    {
      id: "referrer-policy",
      title: "Referrer Policy Protection",
      category: "Security Headers",
      severity: "PASS",
      status: "PASS",
      description: "Referrer-Policy header is configured to 'strict-origin-when-cross-origin', safeguarding private URL paths.",
      whyItMatters: "Prevents leakage of sensitive query parameters, tokens, and navigation history to third-party endpoints.",
      recommendation: "Ensure no confidential query parameters are transmitted via GET requests.",
      evidence: "Referrer-Policy: strict-origin-when-cross-origin",
    },
    {
      id: "permissions-policy",
      title: "Hardware Permissions Policy",
      category: "Security Headers",
      severity: "MEDIUM",
      status: "WARN",
      description: "No Permissions-Policy header was detected. Modern browsers permit access to sensitive device APIs unless restricted.",
      whyItMatters: "Prevents embedded scripts or rogue ads from accessing webcam, microphone, and geolocation hardware.",
      recommendation: "Add Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=() to block unauthorized API usage.",
      evidence: "Permissions-Policy header missing",
    },
    {
      id: "server-tokens",
      title: "Server Software Disclosure",
      category: "Server Information",
      severity: "MEDIUM",
      status: "WARN",
      description: "The server returns detailed software and version identifiers in response headers, giving attackers exact version fingerprints.",
      whyItMatters: "Allows adversaries to look up specific unpatched vulnerabilities in CVE databases.",
      recommendation: "Suppress or redact Server and X-Powered-By response headers in server reverse proxy configs.",
      evidence: "Server: nginx/1.24.0 (Ubuntu)",
    },
    {
      id: "x-powered-by",
      title: "Application Framework Masking",
      category: "Server Information",
      severity: "PASS",
      status: "PASS",
      description: "No X-Powered-By or runtime identity headers were observed in the response.",
      whyItMatters: "Reduces information disclosure and slows down targeted automated vulnerability scanners.",
      recommendation: "Maintain suppression of runtime framework banners in production environments.",
      evidence: "X-Powered-By: [REDACTED / NOT PRESENT]",
    },
    {
      id: "dns-a",
      title: "DNS A / IPv4 Addressing",
      category: "DNS",
      severity: "INFO",
      status: "PASS",
      description: "Valid public IPv4 address records resolved successfully.",
      whyItMatters: "Proper DNS resolution and redundant nameservers guarantee domain availability and resilience.",
      recommendation: "Audit authoritative nameservers regularly and utilize DDoS mitigation proxies.",
      evidence: "A: 104.21.48.112, 172.67.182.204",
    },
    {
      id: "dns-spf",
      title: "Sender Policy Framework (SPF)",
      category: "DNS",
      severity: "PASS",
      status: "PASS",
      description: "SPF TXT record is published, restricting unauthorized mail servers from forging email sender identity for this domain.",
      whyItMatters: "Stops spammers and phishers from using your domain to send deceptive emails.",
      recommendation: "Audit SPF include mechanisms and transition to hard fail -all when authorized mailers are finalized.",
      evidence: "v=spf1 include:_spf.google.com ~all",
    },
    {
      id: "dns-dmarc",
      title: "DMARC Spoofing Defense",
      category: "DNS",
      severity: "MEDIUM",
      status: "WARN",
      description: "DMARC policy is set to p=none (monitoring mode only). Inactive enforcement does not instruct receivers to reject fraudulent spoofed mail.",
      whyItMatters: "Without quarantine or reject policies, fraudulent emails using your domain still land in victim inboxes.",
      recommendation: "Upgrade DMARC policy from p=none to p=quarantine or p=reject once mail flows are validated.",
      evidence: "v=DMARC1; p=none; rua=mailto:dmarc-reports@example.com",
    },
    {
      id: "cookie-security",
      title: "Session Cookie Flags",
      category: "Cookies",
      severity: "MEDIUM",
      status: "WARN",
      description: "Application sets cookie without comprehensive security flags, exposing it to potential cross-site script access or insecure transport.",
      whyItMatters: "Exposes session tokens to credential theft via Cross-Site Scripting (XSS) and network eavesdropping.",
      recommendation: "Add Secure; HttpOnly; SameSite=Strict to all sensitive session and state cookies.",
      evidence: "Set-Cookie: session_token=ab7f920c; Path=/",
    },
    {
      id: "redirect-https",
      title: "HTTP to HTTPS Redirection",
      category: "Redirects",
      severity: "PASS",
      status: "PASS",
      description: "Insecure port 80 HTTP requests are automatically upgraded with a 301 Permanent Redirect to HTTPS.",
      whyItMatters: "Guarantees users who type 'domain.com' without https:// are immediately upgraded before sending cookies or data.",
      recommendation: "Ensure 301 redirects preserve exact path and query string parameters.",
      evidence: "HTTP 301 Moved Permanently -> https://fintech-corp.example.com/",
    },
    {
      id: "health-latency",
      title: "Perimeter Response Latency",
      category: "Website Health",
      severity: "PASS",
      status: "PASS",
      description: "Server responded in 142 ms, well within the recommended 500 ms SLA threshold for high availability.",
      whyItMatters: "Rapid response times indicate healthy load balancers and prevent timeout-induced availability denial.",
      recommendation: "Continue caching static assets and utilizing CDN edge endpoints.",
      evidence: "HTTP 200 OK | Round-Trip: 142ms",
    },
  ],
};

/* =========================================
   REPORT PAGE COMPONENT (WHITE THEME)
========================================= */

export default function ReportPage() {
  const router = useRouter();
  const [result, setResult] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [rescanLoading, setRescanLoading] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedStatus, setSelectedStatus] = useState<string>("ALL");
  const [selectedSeverity, setSelectedSeverity] = useState<string>("ALL");
  const [selectedCategory, setSelectedCategory] = useState<string>("ALL");
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  useEffect(() => {
    try {
      const stored = sessionStorage.getItem("cyra-scan-result");
      if (stored) {
        setResult(JSON.parse(stored));
      }
    } catch {
      setResult(null);
    }
  }, []);

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => {
      setToastMessage(null);
    }, 2800);
  };

  const handleRescan = async (domainToScan?: string) => {
    const target = domainToScan || result?.domain;
    if (!target) return;

    setRescanLoading(true);

    try {
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: target }),
      });

      const res = await response.json();
      if (!response.ok || !res.success) {
        throw new Error(res.error || "Re-scan failed.");
      }

      sessionStorage.setItem("cyra-scan-result", JSON.stringify(res.data));
      setResult(res.data);
      showToast(`Scan complete for ${res.data.domain}`);
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : "Failed to scan domain";
      showToast(`Error: ${message}`);
    } finally {
      setRescanLoading(false);
    }
  };

  const handleLoadDemo = () => {
    sessionStorage.setItem("cyra-scan-result", JSON.stringify(DEMO_REPORT));
    setResult(DEMO_REPORT);
    showToast("Loaded interactive demo report");
  };

  const copyToClipboard = (text: string, id: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    showToast(`${label} copied to clipboard`);
    setTimeout(() => {
      setCopiedId(null);
    }, 2000);
  };

  const handlePrint = () => {
    window.print();
  };

  const handleExportJSON = () => {
    if (!result) return;
    const blob = new Blob([JSON.stringify(result, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `CYRA-Report-${result.domain}-${new Date().toISOString().slice(0, 10)}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showToast("Downloaded JSON audit report");
  };

  const handleShareSummary = () => {
    if (!result) return;
    const summaryText = `CYRA Security Assessment Report
Target: ${result.domain}
Audit URL: ${result.finalUrl}
Health Score: ${score}/100 (Grade: ${grade})
Status: ${gradeExplanation.title}
Total Checks: ${total} | Passed: ${passed} | Warnings: ${warnings} | Failed: ${failed} | Critical/High: ${criticalAndHighCount}
Scanned: ${new Date(result.scannedAt).toUTCString()}
Report verified by CYRA Security Intelligence`;

    copyToClipboard(summaryText, "share-summary", "Executive summary");
  };

  /* Metrics */
  const findings = result?.findings ?? [];
  const passed = findings.filter((f) => f.status === "PASS").length;
  const warnings = findings.filter((f) => f.status === "WARN").length;
  const failed = findings.filter((f) => f.status === "FAIL").length;
  const criticalCount = findings.filter((f) => f.severity === "CRITICAL").length;
  const highCount = findings.filter((f) => f.severity === "HIGH").length;
  const criticalAndHighCount = criticalCount + highCount;
  const total = findings.length;

  const score =
    result?.intelligence?.score ??
    (total === 0 ? 0 : Math.round((passed / total) * 100));

  const grade = useMemo(() => {
    if (score >= 95) return "A+";
    if (score >= 85) return "A";
    if (score >= 75) return "B";
    if (score >= 65) return "C";
    if (score >= 50) return "D";
    return "F";
  }, [score]);

  const gradeExplanation = useMemo(() => {
    if (grade === "A+") {
      return {
        title: "Exceptional Security Posture",
        desc: "All critical safeguards and modern perimeter controls are fully verified. Zero critical or high-severity vulnerabilities observed.",
        color: "text-emerald-700",
        badge: "bg-emerald-50 text-emerald-800 border-emerald-300 font-bold",
        stroke: "stroke-emerald-600",
      };
    }
    if (grade === "A") {
      return {
        title: "Robust Security Standards",
        desc: "Core transport encryption and primary browser defenses are active. Minor low-impact configuration improvements recommended.",
        color: "text-emerald-700",
        badge: "bg-emerald-50 text-emerald-800 border-emerald-300 font-bold",
        stroke: "stroke-emerald-600",
      };
    }
    if (grade === "B") {
      return {
        title: "Satisfactory with Moderate Gaps",
        desc: "Baseline defenses are functional, but configuration gaps in Content Security Policy or cookie flags require attention.",
        color: "text-lime-700",
        badge: "bg-lime-50 text-lime-800 border-lime-300 font-bold",
        stroke: "stroke-lime-600",
      };
    }
    if (grade === "C") {
      return {
        title: "Elevated Risk - Action Needed",
        desc: "Multiple perimeter safeguards are missing. Website has elevated exposure to Cross-Site Scripting (XSS) or spoofing vectors.",
        color: "text-amber-700",
        badge: "bg-amber-50 text-amber-800 border-amber-300 font-bold",
        stroke: "stroke-amber-500",
      };
    }
    if (grade === "D") {
      return {
        title: "High Risk Profile",
        desc: "Critical web defense headers and configurations are absent, significantly weakening the perimeter defense.",
        color: "text-orange-700",
        badge: "bg-orange-50 text-orange-800 border-orange-300 font-bold",
        stroke: "stroke-orange-500",
      };
    }
    return {
      title: "Severe Vulnerability Exposure",
      desc: "Immediate remediation required. Essential transport security or core safeguards are failing, creating acute security vulnerabilities.",
      color: "text-rose-700",
      badge: "bg-rose-50 text-rose-800 border-rose-300 font-bold",
      stroke: "stroke-rose-600",
    };
  }, [grade]);

  const riskLevel = result?.risk?.level ?? (score >= 80 ? "Minimal" : score >= 60 ? "Moderate" : "High");
  const riskPriority = result?.risk?.priority ?? Math.max(0, 100 - score);

  const recommendations =
    result?.intelligence?.recommendations ??
    findings
      .filter((f) => f.status !== "PASS")
      .map((f) => f.recommendation)
      .slice(0, 5);

  const attackSurface = result?.intelligence?.posture?.attackSurface ?? [];

  const categoryBreakdown = useMemo(() => {
    const map: Record<string, { total: number; passed: number; percent: number }> = {};
    CANONICAL_CATEGORIES.forEach((cat) => {
      map[cat] = { total: 0, passed: 0, percent: 100 };
    });

    findings.forEach((f) => {
      const norm = normalizeCategory(f.category);
      if (!map[norm]) {
        map[norm] = { total: 0, passed: 0, percent: 100 };
      }
      map[norm].total += 1;
      if (f.status === "PASS") {
        map[norm].passed += 1;
      }
    });

    Object.keys(map).forEach((k) => {
      const item = map[k];
      item.percent = item.total > 0 ? Math.round((item.passed / item.total) * 100) : 100;
    });

    return map;
  }, [findings]);

  const filteredFindings = useMemo(() => {
    return findings.filter((item) => {
      if (selectedStatus === "PASS" && item.status !== "PASS") return false;
      if (selectedStatus === "WARN" && item.status !== "WARN") return false;
      if (selectedStatus === "FAIL" && item.status !== "FAIL") return false;
      if (selectedStatus === "ACTION" && item.status === "PASS") return false;

      if (selectedSeverity !== "ALL") {
        if (selectedSeverity === "CRITICAL" && item.severity !== "CRITICAL") return false;
        if (selectedSeverity === "HIGH" && item.severity !== "HIGH") return false;
        if (selectedSeverity === "MEDIUM" && item.severity !== "MEDIUM") return false;
        if (selectedSeverity === "LOW" && item.severity !== "LOW") return false;
        if (selectedSeverity === "INFO" && item.severity !== "INFO") return false;
        if (selectedSeverity === "PASS" && item.severity !== "PASS") return false;
      }

      if (selectedCategory !== "ALL") {
        const norm = normalizeCategory(item.category);
        if (norm !== selectedCategory && item.category !== selectedCategory) return false;
      }

      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchTitle = item.title.toLowerCase().includes(q);
        const matchDesc = item.description.toLowerCase().includes(q);
        const matchRec = item.recommendation.toLowerCase().includes(q);
        const matchCat = item.category.toLowerCase().includes(q);
        const matchEv = (item.evidence ?? "").toLowerCase().includes(q);
        const matchWhy = resolveWhyItMatters(item).toLowerCase().includes(q);
        return matchTitle || matchDesc || matchRec || matchCat || matchEv || matchWhy;
      }

      return true;
    });
  }, [findings, selectedStatus, selectedSeverity, selectedCategory, searchQuery]);

  /* Fallback Empty State (White Theme) */
  if (!result) {
    return (
      <main className="relative flex min-h-screen flex-col items-center justify-center bg-[#f8fafc] px-6 py-16 text-slate-900">
        <div className="pointer-events-none fixed inset-0">
          <div className="absolute left-1/3 top-1/4 h-80 w-80 rounded-full bg-emerald-500/10 blur-[140px]" />
          <div className="cyra-grid absolute inset-0" />
        </div>

        <div className="relative z-10 mx-auto flex w-full max-w-4xl flex-col items-center text-center">
          <div className="flex h-14 w-14 items-center justify-center rounded-2xl border border-emerald-200 bg-emerald-50 text-2xl font-black text-emerald-700 shadow-md">
            C
          </div>
          
          <h1 className="mt-5 text-4xl sm:text-5xl font-black text-slate-950 tracking-tight">
            CYRA Security Scanner
          </h1>
          
          <p className="mt-3 text-base sm:text-lg font-medium text-slate-600 max-w-xl">
            Analyze any public website to inspect SSL/TLS, security headers, DNS records, and vulnerability exposure.
          </p>

          {/* PROMINENT CENTERED ANALYZER BOX */}
          <div className="mt-10 w-full flex justify-center">
            <ScanBox />
          </div>

          {/* Secondary Actions */}
          <div className="mt-8 flex flex-wrap items-center justify-center gap-3.5">
            <button
              onClick={handleLoadDemo}
              className="rounded-xl bg-emerald-600 px-6 py-3 text-sm font-bold text-white shadow-md shadow-emerald-600/25 transition hover:bg-emerald-500"
            >
              📊 Load Interactive Demo Report
            </button>
            <Link
              href="/"
              className="rounded-xl border border-slate-200 bg-white px-6 py-3 text-sm font-bold text-slate-700 shadow-xs transition hover:bg-slate-50 hover:text-slate-950"
            >
              Back to Home
            </Link>
          </div>
        </div>
      </main>
    );
  }

  /* Active Dashboard (White Theme) */
  return (
    <main className="min-h-screen bg-[#f8fafc] text-slate-900 antialiased">
      {/* Toast Feedback */}
      {toastMessage && (
        <div className="fixed right-6 top-6 z-50 flex items-center gap-3 rounded-xl border border-emerald-300 bg-white px-5 py-3 text-sm font-bold text-emerald-900 shadow-xl backdrop-blur-xl">
          <span className="text-emerald-600 font-extrabold text-base">✓</span>
          <span>{toastMessage}</span>
        </div>
      )}

      {/* Atmospheric Background */}
      <div className="pointer-events-none fixed inset-0">
        <div className="absolute left-[10%] top-[8%] h-72 w-72 rounded-full bg-emerald-500/5 blur-[130px]" />
        <div className="cyra-grid absolute inset-0" />
      </div>

      {/* 1. TOP HEADER & NAVIGATION */}
      <header className="no-print relative z-20 border-b border-slate-200 bg-white/95 backdrop-blur-xl shadow-xs">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-4 lg:px-8">
          <Link href="/" className="group flex items-center gap-3.5">
            <div className="flex h-11 w-11 items-center justify-center rounded-xl border border-emerald-300 bg-emerald-50 text-emerald-700 font-extrabold text-xl shadow-xs transition group-hover:border-emerald-500">
              C
            </div>
            <div>
              <div className="flex items-center gap-2.5">
                <span className="font-extrabold tracking-[0.2em] text-slate-950 text-base sm:text-lg">CYRA</span>
                <span className="rounded-md bg-emerald-100 px-2 py-0.5 text-xs font-bold tracking-wider text-emerald-800 border border-emerald-300 uppercase">
                  Audit Report
                </span>
              </div>
              <p className="text-xs text-slate-500 tracking-wider font-semibold">WEBSITE HEALTH & SECURITY</p>
            </div>
          </Link>

          {/* Action Buttons */}
          <div className="flex items-center gap-2.5">
            <button
              onClick={() => handleRescan()}
              disabled={rescanLoading}
              className="flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 py-2 text-sm font-bold text-slate-700 shadow-xs transition hover:bg-slate-50 hover:text-slate-950 disabled:opacity-50"
            >
              <span className={rescanLoading ? "animate-spin" : ""}>🔄</span>
              <span className="hidden sm:inline">{rescanLoading ? "Scanning..." : "Rescan"}</span>
            </button>

            <button
              onClick={handlePrint}
              className="flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 py-2 text-sm font-bold text-slate-700 shadow-xs transition hover:bg-slate-50 hover:text-slate-950"
            >
              <span>🖨️</span>
              <span className="hidden sm:inline">PDF</span>
            </button>

            <button
              onClick={handleExportJSON}
              className="flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 py-2 text-sm font-bold text-slate-700 shadow-xs transition hover:bg-slate-50 hover:text-slate-950"
            >
              <span>💾</span>
              <span className="hidden md:inline">JSON</span>
            </button>

            <button
              onClick={handleShareSummary}
              className="flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-4 py-2 text-sm font-bold text-slate-700 shadow-xs transition hover:bg-slate-50 hover:text-slate-950"
            >
              <span>📋</span>
              <span className="hidden md:inline">Share</span>
            </button>

            <Link
              href="/"
              className="flex items-center gap-1.5 rounded-xl bg-emerald-600 px-4 py-2 text-sm font-bold text-white shadow-md shadow-emerald-600/25 transition hover:bg-emerald-500"
            >
              <span>+</span>
              <span>New Scan</span>
            </Link>
          </div>
        </div>
      </header>

      {/* MAIN CONTAINER */}
      <div className="relative z-10 mx-auto max-w-7xl px-6 py-8 lg:px-8">

        {/* 2. TARGET DOMAIN SUMMARY CARD */}
        <div className="mb-8 rounded-2xl border-2 border-slate-200 bg-white p-6 sm:p-8 lg:p-9 shadow-md">
          <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <div className="space-y-1.5">
              <div className="flex flex-wrap items-center gap-2.5 text-sm sm:text-base font-bold text-slate-600 mb-1">
                <span className="h-3 w-3 rounded-full bg-emerald-600 animate-pulse shadow-[0_0_8px_rgba(5,150,105,0.8)]" />
                <span className="uppercase tracking-wider text-xs sm:text-sm font-extrabold text-slate-500">Audited Host</span>
                <span className="text-slate-300">•</span>
                <span className="font-mono text-sm sm:text-base text-emerald-800 font-extrabold bg-emerald-50 px-3 py-1 rounded-lg border border-emerald-300 shadow-2xs">
                  {result.finalUrl}
                </span>
              </div>
              <h1 className="text-4xl font-black tracking-tight text-slate-950 sm:text-5xl lg:text-6xl">
                {result.domain}
              </h1>
            </div>

            {/* Target Telemetry Badges */}
            <div className="flex flex-wrap items-center gap-3">
              <span className="rounded-xl border border-emerald-300 bg-emerald-50 px-4 py-2 text-sm sm:text-base font-extrabold text-emerald-900 shadow-xs">
                HTTP {result.statusCode} OK
              </span>
              <span className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-2 text-sm sm:text-base font-bold text-slate-800">
                ⚡ {result.responseTime} ms latency
              </span>
              <span className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-2 text-sm sm:text-base font-semibold text-slate-600">
                🕒 {new Date(result.scannedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
              </span>
            </div>
          </div>
        </div>

        {/* 3. EXECUTIVE SCORECARD & KPI METRICS */}
        <div className="grid gap-6 lg:grid-cols-[340px_1fr]">

          {/* Left Score Gauge Card */}
          <div className="flex flex-col justify-between rounded-2xl border-2 border-slate-200 bg-white p-6 sm:p-7 shadow-md">
            <div>
              <div className="flex items-center justify-between">
                <span className="text-xs sm:text-sm font-extrabold uppercase tracking-wider text-emerald-800">
                  Security Health Score
                </span>
                <span className={`rounded-xl border px-3.5 py-1.5 text-sm sm:text-base font-black ${gradeExplanation.badge}`}>
                  Grade {grade}
                </span>
              </div>

              {/* Radial SVG Gauge */}
              <div className="my-5 flex items-center justify-center">
                <div className="relative flex h-48 w-48 items-center justify-center">
                  <svg className="h-full w-full -rotate-90" viewBox="0 0 100 100">
                    <circle cx="50" cy="50" r="40" className="stroke-slate-200" strokeWidth="8" fill="transparent" />
                    <circle
                      cx="50" cy="50" r="40"
                      className={gradeExplanation.stroke}
                      strokeWidth="8"
                      strokeDasharray={251.2}
                      strokeDashoffset={251.2 - (251.2 * score) / 100}
                      strokeLinecap="round"
                      fill="transparent"
                      style={{ transition: "stroke-dashoffset 0.8s ease-in-out" }}
                    />
                  </svg>
                  <div className="absolute flex flex-col items-center justify-center text-center">
                    <span className="text-6xl font-black text-slate-950 tracking-tight">{score}</span>
                    <span className="text-xs font-extrabold uppercase tracking-widest text-slate-500 mt-1">/ 100</span>
                    <span className={`text-lg font-black mt-1 ${gradeExplanation.color}`}>Grade {grade}</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Verdict Box */}
            <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
              <div className="flex items-center gap-2 text-base font-bold text-slate-950">
                <span className={gradeExplanation.color}>●</span>
                <span>{gradeExplanation.title}</span>
              </div>
              <p className="mt-2 text-sm sm:text-base text-slate-700 leading-relaxed font-medium">{gradeExplanation.desc}</p>
              <div className="mt-3 pt-2.5 border-t border-slate-200 text-sm font-bold text-slate-700 flex items-center justify-between">
                <span>Risk Exposure:</span>
                <span className="rounded-md bg-white border border-slate-300 px-2.5 py-0.5 text-slate-950 font-black">
                  {riskLevel} · Priority {riskPriority}/100
                </span>
              </div>
            </div>
          </div>

          {/* Right — Compact Bar Visualization Panel */}
          <div className="rounded-2xl border-2 border-slate-200 bg-white p-6 sm:p-7 shadow-md">
            <div className="mb-5 flex items-center justify-between">
              <h3 className="text-sm sm:text-base font-extrabold uppercase tracking-wider text-slate-800">Check Breakdown</h3>
              <span className="text-xs sm:text-sm font-bold text-slate-500">{total} rules evaluated</span>
            </div>

            <div className="space-y-4">
              {/* Passed */}
              <div className="flex items-center gap-3.5">
                <span className="w-24 shrink-0 text-right text-xs sm:text-sm font-extrabold uppercase tracking-wider text-emerald-800">Passed</span>
                <div className="relative flex-1 h-7 rounded-full bg-emerald-100 overflow-hidden">
                  <div
                    className="h-full rounded-full bg-emerald-500 transition-all duration-700"
                    style={{ width: total > 0 ? `${(passed / total) * 100}%` : "0%" }}
                  />
                </div>
                <span className="w-14 shrink-0 text-base sm:text-lg font-black text-emerald-800">{passed}</span>
                <span className="w-12 shrink-0 text-xs sm:text-sm font-bold text-slate-500">{total > 0 ? Math.round((passed / total) * 100) : 0}%</span>
              </div>

              {/* Warnings */}
              <div className="flex items-center gap-3.5">
                <span className="w-24 shrink-0 text-right text-xs sm:text-sm font-extrabold uppercase tracking-wider text-amber-700">Warnings</span>
                <div className="relative flex-1 h-7 rounded-full bg-amber-100 overflow-hidden">
                  <div
                    className="h-full rounded-full bg-amber-500 transition-all duration-700"
                    style={{ width: total > 0 ? `${(warnings / total) * 100}%` : "0%" }}
                  />
                </div>
                <span className="w-14 shrink-0 text-base sm:text-lg font-black text-amber-700">{warnings}</span>
                <span className="w-12 shrink-0 text-xs sm:text-sm font-bold text-slate-500">{total > 0 ? Math.round((warnings / total) * 100) : 0}%</span>
              </div>

              {/* Failed */}
              <div className="flex items-center gap-3.5">
                <span className="w-24 shrink-0 text-right text-xs sm:text-sm font-extrabold uppercase tracking-wider text-rose-700">Failed</span>
                <div className="relative flex-1 h-7 rounded-full bg-rose-100 overflow-hidden">
                  <div
                    className="h-full rounded-full bg-rose-500 transition-all duration-700"
                    style={{ width: total > 0 ? `${(failed / total) * 100}%` : "0%" }}
                  />
                </div>
                <span className="w-14 shrink-0 text-base sm:text-lg font-black text-rose-700">{failed}</span>
                <span className="w-12 shrink-0 text-xs sm:text-sm font-bold text-slate-500">{total > 0 ? Math.round((failed / total) * 100) : 0}%</span>
              </div>

              {/* Critical & High */}
              <div className="flex items-center gap-3.5">
                <span className="w-24 shrink-0 text-right text-xs sm:text-sm font-extrabold uppercase tracking-wider text-orange-700">Critical</span>
                <div className="relative flex-1 h-7 rounded-full bg-orange-100 overflow-hidden">
                  <div
                    className="h-full rounded-full bg-orange-500 transition-all duration-700"
                    style={{ width: total > 0 ? `${(criticalAndHighCount / total) * 100}%` : "0%" }}
                  />
                </div>
                <span className="w-14 shrink-0 text-base sm:text-lg font-black text-orange-700">{criticalAndHighCount}</span>
                <span className="w-12 shrink-0 text-xs sm:text-sm font-bold text-slate-500">{total > 0 ? Math.round((criticalAndHighCount / total) * 100) : 0}%</span>
              </div>
            </div>

            {/* Stacked proportion bar */}
            <div className="mt-6 pt-5 border-t border-slate-100">
              <p className="mb-2.5 text-xs sm:text-sm font-extrabold uppercase tracking-wider text-slate-700">Overall Distribution</p>
              <div className="flex h-4 w-full overflow-hidden rounded-full bg-slate-100">
                <div className="h-full bg-emerald-500 transition-all duration-700" style={{ width: total > 0 ? `${(passed / total) * 100}%` : "0%" }} title={`Passed: ${passed}`} />
                <div className="h-full bg-amber-400 transition-all duration-700" style={{ width: total > 0 ? `${(warnings / total) * 100}%` : "0%" }} title={`Warnings: ${warnings}`} />
                <div className="h-full bg-rose-500 transition-all duration-700" style={{ width: total > 0 ? `${(failed / total) * 100}%` : "0%" }} title={`Failed: ${failed}`} />
              </div>
              <div className="mt-3 flex flex-wrap gap-x-5 gap-y-1.5">
                <span className="flex items-center gap-2 text-xs sm:text-sm font-bold text-slate-700"><span className="inline-block h-3 w-3 rounded-full bg-emerald-500" />Passed ({passed})</span>
                <span className="flex items-center gap-2 text-xs sm:text-sm font-bold text-slate-700"><span className="inline-block h-3 w-3 rounded-full bg-amber-400" />Warnings ({warnings})</span>
                <span className="flex items-center gap-2 text-xs sm:text-sm font-bold text-slate-700"><span className="inline-block h-3 w-3 rounded-full bg-rose-500" />Failed ({failed})</span>
              </div>
            </div>
          </div>

        </div>

        {/* 4. SECURITY CATEGORIES (8 CANONICAL DOMAINS) */}
        <section className="mt-8 rounded-2xl border-2 border-slate-200 bg-white p-6 sm:p-8 shadow-md">
          <div className="flex items-center justify-between mb-6">
            <div>
              <h2 className="text-2xl sm:text-3xl font-black text-slate-950">Security Categories</h2>
              <p className="text-base font-medium text-slate-600 mt-1">Posture evaluation across 8 standard security domains</p>
            </div>
            {selectedCategory !== "ALL" && (
              <button
                onClick={() => setSelectedCategory("ALL")}
                className="text-sm sm:text-base font-extrabold text-emerald-700 hover:underline"
              >
                Clear Category Filter
              </button>
            )}
          </div>

          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {CANONICAL_CATEGORIES.map((cat) => {
              const stat = categoryBreakdown[cat] || { total: 0, passed: 0, percent: 100 };
              const isSelected = selectedCategory === cat;

              return (
                <div
                  key={cat}
                  onClick={() => setSelectedCategory(isSelected ? "ALL" : cat)}
                  className={`cursor-pointer rounded-xl border-2 p-4 sm:p-5 transition ${
                    isSelected
                      ? "border-emerald-600 bg-emerald-50/70 shadow-md ring-4 ring-emerald-500/20"
                      : "border-slate-200 bg-slate-50/70 hover:border-slate-300 hover:bg-white hover:shadow-xs"
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-base sm:text-lg font-extrabold text-slate-950 truncate pr-2">{cat}</span>
                    <span className="text-lg sm:text-xl font-black text-slate-950">{stat.percent}%</span>
                  </div>

                  {/* Progress bar */}
                  <div className="mt-3.5 h-2.5 w-full overflow-hidden rounded-full bg-slate-200">
                    <div
                      className={`h-full rounded-full transition-all duration-500 ${
                        stat.percent >= 80
                          ? "bg-emerald-600"
                          : stat.percent >= 60
                            ? "bg-amber-500"
                            : "bg-rose-600"
                      }`}
                      style={{ width: `${stat.percent}%` }}
                    />
                  </div>

                  <div className="mt-3 flex items-center justify-between text-xs sm:text-sm font-bold text-slate-700">
                    <span>{stat.passed} / {stat.total} pass</span>
                    <span className="text-xs sm:text-sm font-extrabold text-emerald-700">{isSelected ? "Filtering" : "Click to view"}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </section>

        {/* 5. ATTACK SURFACE & ACTIONABLE REMEDIATION */}
        <section className="mt-8 grid gap-6 lg:grid-cols-2">
          
          {/* Attack Surface Telemetry */}
          <div className="rounded-2xl border-2 border-slate-200 bg-white p-6 sm:p-8 shadow-md">
            <div className="flex items-center justify-between mb-5">
              <div>
                <h3 className="text-lg sm:text-xl font-black text-slate-950">Attack Surface & Exposure</h3>
                <p className="text-sm sm:text-base font-medium text-slate-600">Passive endpoint signals and protocol posture</p>
              </div>
              <span className="text-xs sm:text-sm font-extrabold text-emerald-900 bg-emerald-50 border border-emerald-300 px-2.5 py-1 rounded-lg uppercase tracking-wider">Live Telemetry</span>
            </div>

            <div className="space-y-3.5">
              {attackSurface.length > 0 ? (
                attackSurface.map((item, idx) => (
                  <div
                    key={`${item.name}-${idx}`}
                    className="flex items-center justify-between rounded-xl border border-slate-200 bg-slate-50/90 p-4"
                  >
                    <div className="min-w-0 pr-3">
                      <p className="text-base font-bold text-slate-950">{item.name}</p>
                      <p className="mt-1 truncate font-mono text-sm sm:text-base text-slate-700 font-semibold">{item.value}</p>
                    </div>

                    <span
                      className={`shrink-0 rounded-lg border-2 px-3.5 py-1 text-xs sm:text-sm font-black uppercase tracking-wider ${
                        item.severity === "Low"
                          ? "border-emerald-300 bg-emerald-50 text-emerald-900"
                          : item.severity === "Moderate"
                            ? "border-amber-300 bg-amber-50 text-amber-900"
                            : "border-rose-300 bg-rose-50 text-rose-900"
                      }`}
                    >
                      {item.severity}
                    </span>
                  </div>
                ))
              ) : (
                <div className="rounded-xl border border-slate-200 p-6 text-center text-base font-medium text-slate-600">
                  No public exposure indicators observed.
                </div>
              )}
            </div>
          </div>

          {/* Actionable Executive Recommendations */}
          <div className="rounded-2xl border-2 border-slate-200 bg-white p-6 sm:p-8 shadow-md">
            <div className="flex items-center justify-between mb-5">
              <div>
                <h3 className="text-lg sm:text-xl font-black text-slate-950">Recommended Action Plan</h3>
                <p className="text-sm sm:text-base font-medium text-slate-600">Priority steps to harden perimeter configurations</p>
              </div>
              <span className="text-xs sm:text-sm font-extrabold text-amber-900 bg-amber-50 border border-amber-300 px-2.5 py-1 rounded-lg uppercase tracking-wider">Roadmap</span>
            </div>

            <div className="space-y-3.5">
              {recommendations.length > 0 ? (
                recommendations.map((item, idx) => (
                  <div
                    key={`rec-${idx}`}
                    className="flex items-start gap-4 rounded-xl border border-slate-200 bg-slate-50/90 p-4"
                  >
                    <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-xl bg-emerald-100 border border-emerald-300 font-mono text-sm font-black text-emerald-900 shadow-2xs">
                      {idx + 1}
                    </span>
                    <p className="text-base sm:text-lg text-slate-900 leading-relaxed font-semibold">
                      {item}
                    </p>
                  </div>
                ))
              ) : (
                <p className="text-base text-slate-600 font-medium p-4">
                  System conforms to baseline security best practices.
                </p>
              )}
            </div>
          </div>

        </section>

        {/* 6. FINDINGS EXPLORER (SEARCH + FILTER TABS) */}
        <section className="mt-12">
          <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between mb-6">
            <div>
              <h2 className="text-2xl sm:text-3xl font-black text-slate-950">Security Findings</h2>
              <p className="text-base font-semibold text-slate-600 mt-1">Inspect full descriptions, threat impact, and remediations</p>
            </div>

            {/* Severity Filter Tabs */}
            <div className="flex flex-wrap items-center gap-2">
              {[
                { label: "All", value: "ALL", count: total },
                { label: "Critical", value: "CRITICAL", count: criticalCount },
                { label: "High", value: "HIGH", count: highCount },
                { label: "Medium", value: "MEDIUM", count: findings.filter((f) => f.severity === "MEDIUM").length },
                { label: "Low", value: "LOW", count: findings.filter((f) => f.severity === "LOW").length },
                { label: "Passed", value: "PASS", count: passed },
              ].map((tab) => (
                <button
                  key={tab.value}
                  onClick={() => setSelectedSeverity(tab.value)}
                  className={`rounded-xl px-4 py-2 text-xs sm:text-sm font-extrabold transition shadow-xs ${
                    selectedSeverity === tab.value
                      ? "bg-slate-950 text-white shadow-md"
                      : "border border-slate-200 bg-white text-slate-800 hover:bg-slate-50 hover:border-slate-300"
                  }`}
                >
                  {tab.label} ({tab.count})
                </button>
              ))}
            </div>
          </div>

          {/* Search Bar + Secondary Status Filter */}
          <div className="flex flex-col gap-3.5 sm:flex-row sm:items-center mb-6">
            <div className="relative flex-1">
              <span className="absolute left-4 top-1/2 -translate-y-1/2 text-base text-slate-400">
                🔍
              </span>
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search findings by title, description, or payload..."
                className="h-13 w-full rounded-xl border border-slate-300 bg-white pl-12 pr-4 text-base font-medium text-slate-950 placeholder-slate-400 focus:border-emerald-600 focus:outline-none focus:ring-4 focus:ring-emerald-500/10 shadow-xs"
              />
              {searchQuery && (
                <button
                  onClick={() => setSearchQuery("")}
                  className="absolute right-4 top-1/2 -translate-y-1/2 text-base font-black text-slate-400 hover:text-slate-800"
                >
                  ✕
                </button>
              )}
            </div>

            <select
              value={selectedStatus}
              onChange={(e) => setSelectedStatus(e.target.value)}
              aria-label="Filter by status"
              className="h-13 rounded-xl border border-slate-300 bg-white px-4 text-base font-extrabold text-slate-800 focus:border-emerald-600 focus:outline-none shadow-xs"
            >
              <option value="ALL">All Statuses ({total})</option>
              <option value="ACTION">Action Needed ({warnings + failed})</option>
              <option value="FAIL">Failed ({failed})</option>
              <option value="WARN">Warnings ({warnings})</option>
              <option value="PASS">Passed ({passed})</option>
            </select>
          </div>

          {/* Active Filter Counter & Reset */}
          {(selectedStatus !== "ALL" || selectedSeverity !== "ALL" || selectedCategory !== "ALL" || searchQuery) && (
            <div className="mb-6 flex items-center justify-between text-base text-slate-700 font-bold">
              <span>
                Showing <strong className="text-slate-950 font-black">{filteredFindings.length}</strong> of {total} findings
              </span>
              <button
                onClick={() => {
                  setSelectedStatus("ALL");
                  setSelectedSeverity("ALL");
                  setSelectedCategory("ALL");
                  setSearchQuery("");
                }}
                className="text-emerald-700 font-extrabold hover:underline"
              >
                Reset Filters
              </button>
            </div>
          )}

          {/* 7. CLEAN FINDING CARDS (WHITE THEME) */}
          <div className="space-y-4">
            {filteredFindings.length > 0 ? (
              filteredFindings.map((finding) => (
                <FindingDetailCard
                  key={finding.id}
                  finding={finding}
                  whyItMatters={resolveWhyItMatters(finding)}
                  onCopyEvidence={(ev) =>
                    copyToClipboard(ev, finding.id, `Payload for "${finding.title}"`)
                  }
                  isCopied={copiedId === finding.id}
                />
              ))
            ) : (
              <div className="rounded-2xl border-2 border-slate-200 bg-white p-12 text-center shadow-sm">
                <p className="text-lg font-bold text-slate-950">No matching findings</p>
                <p className="mt-2 text-base text-slate-600">Adjust your search keyword or reset active filters.</p>
                <button
                  onClick={() => {
                    setSelectedStatus("ALL");
                    setSelectedSeverity("ALL");
                    setSelectedCategory("ALL");
                    setSearchQuery("");
                  }}
                  className="mt-5 rounded-xl border-2 border-slate-300 bg-white px-6 py-2.5 text-base font-bold text-slate-800 shadow-xs hover:bg-slate-50"
                >
                  Clear Filters
                </button>
              </div>
            )}
          </div>
        </section>

        {/* 8. REPORT FOOTER & DISCLAIMER */}
        <footer className="mt-14 rounded-2xl border-2 border-slate-200 bg-white p-6 lg:p-8 text-slate-600 text-sm shadow-sm">
          <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between border-b border-slate-200 pb-4 mb-4">
            <span className="font-black text-slate-950 text-base sm:text-lg">CYRA Security Intelligence</span>
            <span className="text-xs sm:text-sm font-bold text-slate-600">Audit Reference: {result.domain}</span>
          </div>
          <p className="text-xs sm:text-sm leading-relaxed text-slate-600 font-medium">
            <strong>Disclaimer:</strong> CYRA performs non-intrusive passive perimeter testing against public HTTP responses, TLS configurations, and DNS records. It does not perform active intrusion, denial of service, or destructive testing.
          </p>
        </footer>

      </div>
    </main>
  );
}

/* =========================================
   FINDING CARD COMPONENT (WHITE THEME)
========================================= */

function FindingDetailCard({
  finding,
  whyItMatters,
  onCopyEvidence,
  isCopied,
}: {
  finding: Finding;
  whyItMatters: string;
  onCopyEvidence: (evidence: string) => void;
  isCopied: boolean;
}) {
  const isPass = finding.status === "PASS";
  const isWarn = finding.status === "WARN";

  const statusBadge = isPass
    ? "border-emerald-300 bg-emerald-100 text-emerald-900"
    : isWarn
      ? "border-amber-300 bg-amber-100 text-amber-900"
      : "border-rose-300 bg-rose-100 text-rose-900";

  const statusIcon = isPass ? "✓" : isWarn ? "!" : "✕";

  const severityBadge =
    finding.severity === "CRITICAL"
      ? "border-rose-300 bg-rose-50 text-rose-900 font-black"
      : finding.severity === "HIGH"
        ? "border-orange-300 bg-orange-50 text-orange-900 font-bold"
        : finding.severity === "MEDIUM"
          ? "border-amber-300 bg-amber-50 text-amber-900 font-bold"
          : finding.severity === "LOW"
            ? "border-sky-300 bg-sky-50 text-sky-900 font-bold"
            : finding.severity === "INFO"
              ? "border-slate-300 bg-slate-100 text-slate-800 font-bold"
              : "border-emerald-300 bg-emerald-50 text-emerald-900 font-bold";

  return (
    <article className="rounded-2xl border-2 border-slate-200/90 bg-white p-6 sm:p-7 shadow-sm transition hover:shadow-md hover:border-slate-300">
      
      {/* Header Row */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-3.5">
          <span className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-xl border-2 text-base font-black ${statusBadge}`}>
            {statusIcon}
          </span>
          <h3 className="text-lg sm:text-xl font-black text-slate-950">
            {finding.title}
          </h3>
        </div>

        <div className="flex items-center gap-2.5">
          <span className="rounded-lg border border-slate-200 bg-slate-100 px-3 py-1 text-slate-800 font-bold text-xs sm:text-sm">
            {normalizeCategory(finding.category)}
          </span>
          <span className={`rounded-lg border px-3 py-1 text-xs sm:text-sm uppercase tracking-wider ${severityBadge}`}>
            {finding.severity}
          </span>
        </div>
      </div>

      {/* Body Flow */}
      <div className="mt-4 space-y-3.5 pl-0 sm:pl-12 text-base leading-relaxed">
        {/* Description */}
        <p className="text-slate-800 text-base sm:text-lg font-normal leading-relaxed">
          {finding.description}
        </p>

        {/* Why It Matters */}
        <p className="text-slate-800 text-base sm:text-lg leading-relaxed">
          <strong className="text-slate-950 font-extrabold bg-amber-50/90 border border-amber-300/80 px-2 py-0.5 rounded-md inline-block mr-1">
            Why it matters:
          </strong>{" "}
          {whyItMatters}
        </p>

        {/* Remediation Banner */}
        <div className="rounded-xl border border-emerald-200 bg-emerald-50/90 p-4 sm:p-5 text-emerald-950 text-base sm:text-lg">
          <strong className="font-black text-emerald-900 bg-emerald-100 border border-emerald-300 px-2.5 py-0.5 rounded-md inline-block mr-1.5">
            Remediation:
          </strong>
          <span>{finding.recommendation}</span>
        </div>

        {/* Technical Evidence */}
        {finding.evidence && (
          <div className="rounded-xl border border-slate-800 bg-[#090d16] p-4 sm:p-5 shadow-inner">
            <div className="flex items-center justify-between mb-2.5">
              <span className="text-xs sm:text-sm font-extrabold uppercase tracking-wider text-slate-400">
                Technical Evidence
              </span>
              <button
                onClick={() => onCopyEvidence(finding.evidence!)}
                className="text-xs sm:text-sm font-bold text-emerald-400 hover:text-white transition px-2 py-1 rounded bg-slate-800/80 hover:bg-slate-700"
              >
                {isCopied ? "✓ Copied" : "Copy Payload"}
              </button>
            </div>
            <pre className="font-mono text-sm sm:text-base text-emerald-400 whitespace-pre-wrap break-all leading-relaxed">
              {finding.evidence}
            </pre>
          </div>
        )}
      </div>

    </article>
  );
}