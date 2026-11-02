import type {
  AttackSurfaceIndicator,
  Finding,
  SecurityArea,
  SecurityContext,
  SecurityPosture,
  SecurityScore,
  SecurityStatus,
} from "../types";

export type RiskLevel =
  | "Minimal"
  | "Low"
  | "Moderate"
  | "High"
  | "Critical";

export function determineRiskLevel(score: number): RiskLevel {
  if (score >= 85) return "Critical";
  if (score >= 70) return "High";
  if (score >= 50) return "Moderate";
  if (score >= 30) return "Low";
  return "Minimal";
}

export function mapScoreToStatus(score: number): SecurityStatus {
  if (score >= 80) return "Healthy";
  if (score >= 60) return "Stable";
  if (score >= 40) return "Monitor";
  return "Attention";
}

export function deriveSecurityAreas(
  findings: Finding[]
): SecurityArea[] {
  const areas = new Set<SecurityArea>();

  for (const finding of findings) {
    const category = finding.category;

    if (category === "SSL / TLS") areas.add("TLS");
    if (category === "DNS Security") areas.add("DNS");
    if (category === "Cookies") areas.add("Cookies");
    if (category === "HTTP Headers") areas.add("Website");
    if (category === "Information Exposure") areas.add("Website");
    if (category === "Security Configuration") areas.add("Configuration");
    if (category === "Email Security" || category === "Email") areas.add("Email");
  }

  return [...areas];
}

export function deriveAttackSurfaceIndicators(
  findings: Finding[]
): AttackSurfaceIndicator[] {
  const indicators: AttackSurfaceIndicator[] = [];

  for (const finding of findings) {
    const normalized = finding.title.toLowerCase();

    if (normalized.includes("hsts") || normalized.includes("https")) {
      indicators.push({
        name: "TLS exposure",
        value: "HTTPS surface",
        severity: finding.severity === "HIGH" ? "High" : "Moderate",
      });
    }

    if (normalized.includes("cookie") || normalized.includes("header")) {
      indicators.push({
        name: "Client-side exposure",
        value: "Browser surface",
        severity: finding.severity === "HIGH" ? "High" : "Low",
      });
    }

    if (normalized.includes("dns") || normalized.includes("spf") || normalized.includes("dmarc")) {
      indicators.push({
        name: "DNS surface",
        value: "Domain exposure",
        severity: finding.severity === "HIGH" ? "High" : "Moderate",
      });
    }
  }

  return indicators.length > 0 ? indicators : [{
    name: "No major indicators",
    value: "No active risks observed",
    severity: "Low",
  }];
}

export function deriveOverallPosture(
  findings: Finding[],
  score: number
): SecurityPosture {
  const areas = deriveSecurityAreas(findings);
  const riskLevel = determineRiskLevel(score);

  return {
    score,
    status: mapScoreToStatus(score),
    riskLevel,
    areas,
    attackSurface: deriveAttackSurfaceIndicators(findings),
    summary:
      score >= 80
        ? "This website shows a strong baseline security posture with only minor follow-up work."
        : score >= 60
          ? "This website has a generally stable posture with a few items worth review."
          : score >= 40
            ? "This website needs focused hardening to reduce avoidable exposure."
            : "This website shows a weaker posture and should prioritize immediate remediation.",
  };
}

export function buildSecurityScore(
  findings: Finding[]
): SecurityScore {
  const score = findings.reduce((total, finding) => {
    switch (finding.severity) {
      case "PASS":
        return total + 10;
      case "INFO":
        return total + 5;
      case "LOW":
        return total - 8;
      case "MEDIUM":
        return total - 16;
      case "HIGH":
        return total - 28;
      case "CRITICAL":
        return total - 42;
      default:
        return total;
    }
  }, 100);

  const clamped = Math.max(0, Math.min(100, score));
  const posture = deriveOverallPosture(findings, clamped);
  const topRisks = getTopRisks(findings);
  const recommendations = getRecommendations(findings);
  const areas = deriveSecurityAreas(findings);
  const context = classifyContext(
    findings[0]?.category ?? "Security Configuration"
  );

  return {
    score: clamped,
    status: mapScoreToStatus(clamped),
    riskLevel: determineRiskLevel(clamped),
    posture,
    topRisks,
    recommendations,
    areas,
    context,
    summary:
      clamped >= 80
        ? "Strong baseline posture."
        : clamped >= 60
          ? "Stable with targeted improvements."
          : clamped >= 40
            ? "Moderate exposure requiring attention."
            : "High-risk posture requiring remediation.",
  };
}

export function getTopRisks(findings: Finding[]): Finding[] {
  return [...findings]
    .filter((finding) => finding.status !== "PASS")
    .sort((a, b) => {
      const order = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFO: 1, PASS: 0 };
      return order[b.severity] - order[a.severity];
    })
    .slice(0, 3);
}

export function getRecommendations(findings: Finding[]): string[] {
  const recommendations = new Set<string>();

  for (const finding of findings) {
    if (finding.recommendation && finding.status !== "PASS") {
      recommendations.add(finding.recommendation);
    }
  }

  return [...recommendations].slice(0, 5);
}

export function classifyContext(
  category: string
): SecurityContext {
  if (category === "DNS Security") return "DNS";
  if (category === "SSL / TLS") return "TLS";
  if (category === "Cookies") return "Configuration";
  if (category === "Email Security" || category === "Email") return "Email";
  if (category === "Information Exposure") return "Privacy";
  if (category === "HTTP Headers" || category === "Redirects") return "Website";
  return "Configuration";
}
