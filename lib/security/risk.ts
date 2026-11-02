import type {
  Finding,
  RiskAssessment,
  RiskLevel,
  SecurityArea,
  SecurityContext,
  SecurityScore,
} from "../types";

const SEVERITY_WEIGHT: Record<Finding["severity"], number> = {
  PASS: 0,
  INFO: 5,
  LOW: 12,
  MEDIUM: 28,
  HIGH: 56,
  CRITICAL: 90,
};

const CONTEXT_WEIGHT: Record<SecurityContext, number> = {
  Website: 1.0,
  Email: 1.15,
  DNS: 1.2,
  TLS: 1.25,
  Privacy: 1.3,
  Configuration: 1.1,
};

const AREA_WEIGHT: Record<SecurityArea, number> = {
  TLS: 1.2,
  Email: 1.15,
  Cookies: 1.1,
  Website: 1.05,
  DNS: 1.25,
  Configuration: 1.1,
};

const LEVEL_LABELS: Record<number, RiskLevel> = {
  0: "Minimal",
  1: "Low",
  2: "Moderate",
  3: "High",
  4: "Critical",
};

function mapRiskToSurfaceSeverity(level: RiskLevel) {
  switch (level) {
    case "Critical":
      return "Critical";
    case "High":
      return "High";
    case "Moderate":
      return "Moderate";
    case "Low":
      return "Low";
    default:
      return "Low";
  }
}

function determineLevel(score: number): RiskLevel {
  if (score >= 85) return "Critical";
  if (score >= 70) return "High";
  if (score >= 50) return "Moderate";
  if (score >= 30) return "Low";
  return "Minimal";
}

function getContext(category: string): SecurityContext {
  switch (category) {
    case "SSL / TLS":
      return "TLS";
    case "DNS Security":
      return "DNS";
    case "Email Security":
    case "Email":
      return "Email";
    case "Information Exposure":
      return "Privacy";
    case "HTTP Headers":
    case "Redirects":
      return "Website";
    default:
      return "Configuration";
  }
}

function getArea(category: string): SecurityArea {
  switch (category) {
    case "SSL / TLS":
      return "TLS";
    case "DNS Security":
      return "DNS";
    case "Cookies":
      return "Cookies";
    case "Email Security":
    case "Email":
      return "Email";
    case "HTTP Headers":
    case "Redirects":
    case "Information Exposure":
    case "Availability":
      return "Website";
    default:
      return "Configuration";
  }
}

export function assessFindingRisk(finding: Finding): RiskAssessment {
  if (finding.status === "PASS") {
    return {
      level: "Minimal",
      priority: 0,
      explanation:
        "This check passed and did not indicate a current security concern.",
      context: getContext(finding.category),
      area: getArea(finding.category),
    };
  }

  const context = getContext(finding.category);
  const area = getArea(finding.category);
  const weightedScore =
    SEVERITY_WEIGHT[finding.severity] *
    CONTEXT_WEIGHT[context] *
    AREA_WEIGHT[area] *
    (finding.status === "FAIL" ? 1.35 : 1.05);

  const priority = Math.min(100, Math.round(weightedScore));
  const level = determineLevel(priority);

  let explanation =
    "This configuration item should be reviewed to reduce exposure.";

  if (level === "Critical") {
    explanation =
      "This issue may represent a significant security exposure and should be addressed promptly.";
  } else if (level === "High") {
    explanation =
      "This issue represents a meaningful risk and should be reviewed soon.";
  } else if (level === "Moderate") {
    explanation =
      "This issue indicates a moderate security weakness that deserves attention.";
  } else if (level === "Low") {
    explanation =
      "This issue is lower impact but still worth remediation.";
  }

  return {
    level,
    priority,
    explanation,
    context,
    area,
  };
}

export function prioritizeFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const left = assessFindingRisk(a).priority;
    const right = assessFindingRisk(b).priority;
    return right - left;
  });
}

export function calculateOverallRisk(findings: Finding[]): RiskAssessment {
  const withoutPass = findings.filter((finding) => finding.status !== "PASS");

  if (withoutPass.length === 0) {
    return {
      level: "Minimal",
      priority: 0,
      explanation: "No actionable findings were identified.",
      context: "Configuration",
      area: "Configuration",
    };
  }

  const highest = withoutPass.reduce((max, finding) => {
    return Math.max(max, assessFindingRisk(finding).priority);
  }, 0);

  const average =
    withoutPass.reduce((sum, finding) => {
      return sum + assessFindingRisk(finding).priority;
    }, 0) / withoutPass.length;

  const priority = Math.min(100, Math.round(highest * 0.65 + average * 0.35));

  return {
    level: determineLevel(priority),
    priority,
    explanation:
      "Overall risk balances the most severe findings with the average impact of the current exposure profile.",
    context: "Configuration",
    area: "Configuration",
  };
}

export function calculateIntelligentScore(findings: Finding[]): SecurityScore {
  if (findings.length === 0) {
    return {
      score: 100,
      status: "Healthy",
      riskLevel: "Minimal",
      posture: {
        score: 100,
        status: "Healthy",
        riskLevel: "Minimal",
        areas: ["Configuration"],
        attackSurface: [
          {
            name: "No major indicators",
            value: "No active risks observed",
            severity: "Low",
          },
        ],
        summary: "No findings were available for evaluation.",
      },
      topRisks: [],
      recommendations: [],
      areas: ["Configuration"],
      context: "Configuration",
      summary: "No findings were available for evaluation.",
    };
  }

  const riskAssessments = findings.map(assessFindingRisk);
  const actionable = riskAssessments.filter((item) => item.priority > 0);

  if (actionable.length === 0) {
    return {
      score: 100,
      status: "Healthy",
      riskLevel: "Minimal",
      posture: {
        score: 100,
        status: "Healthy",
        riskLevel: "Minimal",
        areas: ["Configuration"],
        attackSurface: [
          {
            name: "No major indicators",
            value: "No active risks observed",
            severity: "Low",
          },
        ],
        summary: "All checks passed and no actionable issues were found.",
      },
      topRisks: [],
      recommendations: [],
      areas: ["Configuration"],
      context: "Configuration",
      summary: "All checks passed and no actionable issues were found.",
    };
  }

  const highest = Math.max(...actionable.map((item) => item.priority));
  const average =
    actionable.reduce((sum, item) => sum + item.priority, 0) / actionable.length;
  const score = Math.max(
    0,
    Math.min(100, Math.round(100 - (highest * 0.55 + average * 0.45)))
  );

  const topRisks = [...findings]
    .filter((finding) => finding.status !== "PASS")
    .sort((a, b) => {
      const order = {
        CRITICAL: 5,
        HIGH: 4,
        MEDIUM: 3,
        LOW: 2,
        INFO: 1,
        PASS: 0,
      } as const;

      return order[b.severity] - order[a.severity];
    })
    .slice(0, 3);

  const recommendations = [...new Set(
    findings
      .filter((finding) => finding.status !== "PASS")
      .map((finding) => finding.recommendation)
      .filter(Boolean)
  )].slice(0, 5);

  const context = findings.reduce<SecurityContext>((current, finding) => {
    const candidate = getContext(finding.category);
    return current === "Configuration" ? candidate : current;
  }, "Configuration");

  const areas = [...new Set(findings.map((finding) => getArea(finding.category)))];

  return {
    score,
    status: score >= 80 ? "Healthy" : score >= 60 ? "Stable" : score >= 40 ? "Monitor" : "Attention",
    riskLevel: determineLevel(score),
    posture: {
      score,
      status: score >= 80 ? "Healthy" : score >= 60 ? "Stable" : score >= 40 ? "Monitor" : "Attention",
      riskLevel: determineLevel(score),
      areas,
      attackSurface: [
        {
          name: "Detected exposure",
          value: `${actionable.length} actionable findings`,
          severity: mapRiskToSurfaceSeverity(determineLevel(highest)),
        },
      ],
      summary:
        score >= 80
          ? "This website shows a strong baseline posture with only minor follow-up work."
          : score >= 60
            ? "This website is generally stable but should still be reviewed for targeted remediation."
            : score >= 40
              ? "This website has a moderate exposure profile and should be prioritized for remediation."
              : "This website shows a weak baseline and needs immediate hardening work.",
    },
    topRisks: topRisks.map((finding) => ({
      ...finding,
      severity: finding.severity,
    })),
    recommendations,
    areas,
    context,
    summary:
      score >= 80
        ? "Strong baseline posture."
        : score >= 60
          ? "Stable with targeted improvements."
          : score >= 40
            ? "Moderate exposure requiring attention."
            : "High-risk posture requiring remediation.",
  };
}

export function getRiskLevelLabel(index: number): RiskLevel {
  return LEVEL_LABELS[index] ?? "Minimal";
}
