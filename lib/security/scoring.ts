import type {
  Finding,
  RiskAssessment,
  RiskLevel,
  SecurityArea,
  SecurityContext,
  SecurityPosture,
  SecurityScore,
  Severity,
} from "../types";

const severityWeight: Record<Severity, number> = {
  PASS: 0,
  INFO: 10,
  LOW: 25,
  MEDIUM: 50,
  HIGH: 80,
  CRITICAL: 100,
};

const contextWeight: Record<SecurityContext, number> = {
  Website: 1,
  Email: 1.15,
  DNS: 1.2,
  TLS: 1.25,
  Privacy: 1.3,
  Configuration: 1.1,
};

const areaWeight: Record<SecurityArea, number> = {
  TLS: 1.2,
  Email: 1.15,
  Cookies: 1.1,
  Website: 1.05,
  DNS: 1.25,
  Configuration: 1.1,
};

function getRiskLevel(score: number): RiskLevel {
  if (score >= 85) return "Critical";
  if (score >= 70) return "High";
  if (score >= 50) return "Moderate";
  if (score >= 30) return "Low";
  return "Minimal";
}

function getSecurityContext(category: string): SecurityContext {
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

function getSecurityArea(category: string): SecurityArea {
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
      explanation: "This check passed and did not identify a current concern.",
      context: getSecurityContext(finding.category),
      area: getSecurityArea(finding.category),
    };
  }

  const context = getSecurityContext(finding.category);
  const area = getSecurityArea(finding.category);
  const statusMultiplier = finding.status === "FAIL" ? 1.35 : 1.05;
  const priority = Math.min(
    100,
    Math.round(
      severityWeight[finding.severity] *
        contextWeight[context] *
        areaWeight[area] *
        statusMultiplier
    )
  );

  const level = getRiskLevel(priority);

  let explanation = "This configuration item should be reviewed to reduce exposure.";

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
    explanation = "This issue is lower impact but still worth remediation.";
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
    return assessFindingRisk(b).priority - assessFindingRisk(a).priority;
  });
}

export function calculateOverallRisk(findings: Finding[]): RiskAssessment {
  const actionable = findings.filter((finding) => finding.status !== "PASS");

  if (actionable.length === 0) {
    return {
      level: "Minimal",
      priority: 0,
      explanation: "No actionable findings were identified.",
      context: "Configuration",
      area: "Configuration",
    };
  }

  const highest = Math.max(
    ...actionable.map((finding) => assessFindingRisk(finding).priority)
  );
  const average =
    actionable.reduce(
      (sum, finding) => sum + assessFindingRisk(finding).priority,
      0
    ) / actionable.length;

  const priority = Math.min(100, Math.round(highest * 0.65 + average * 0.35));

  return {
    level: getRiskLevel(priority),
    priority,
    explanation:
      "Overall risk balances the most severe findings with the average impact of the current exposure profile.",
    context: "Configuration",
    area: "Configuration",
  };
}

export function calculateContextAwareScore(findings: Finding[]): SecurityScore {
  if (!findings.length) {
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

  const assessments = findings.map(assessFindingRisk);
  const actionable = assessments.filter((assessment) => assessment.priority > 0);

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

  const highest = Math.max(...actionable.map((assessment) => assessment.priority));
  const average =
    actionable.reduce((sum, assessment) => sum + assessment.priority, 0) /
    actionable.length;
  const score = Math.max(
    0,
    Math.min(100, Math.round(100 - (highest * 0.55 + average * 0.45)))
  );

  const context = actionable.reduce<SecurityContext>(
    (current, assessment) => current === "Configuration" ? assessment.context : current,
    "Configuration"
  );

  const areas = [...new Set(actionable.map((assessment) => assessment.area))];
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

  const posture: SecurityPosture = {
    score,
    status: score >= 80 ? "Healthy" : score >= 60 ? "Stable" : score >= 40 ? "Monitor" : "Attention",
    riskLevel: getRiskLevel(score),
    areas,
    attackSurface: [
      {
        name: "Detected exposure",
        value: `${actionable.length} actionable findings`,
        severity: getRiskLevel(highest) === "Critical" ? "Critical" : getRiskLevel(highest) === "High" ? "High" : getRiskLevel(highest) === "Moderate" ? "Moderate" : "Low",
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
  };

  return {
    score,
    status: posture.status,
    riskLevel: posture.riskLevel,
    posture,
    topRisks,
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

export function calculateScore(findings: Finding[]): number {
  if (!findings.length) return 100;

  const totalPenalty = findings.reduce((sum, finding) => {
    return sum + severityWeight[finding.severity];
  }, 0);

  const normalized = 100 - Math.min(totalPenalty, 100);
  return Math.max(0, Math.round(normalized));
}

export function calculateSummary(findings: Finding[]) {
  const pass = findings.filter((finding) => finding.status === "PASS").length;
  const warn = findings.filter((finding) => finding.status === "WARN").length;
  const fail = findings.filter((finding) => finding.status === "FAIL").length;

  const score = calculateScore(findings);

  return {
    pass,
    warn,
    fail,
    score,
    level:
      fail > 0 || warn > 0
        ? fail > 0
          ? "Needs attention"
          : "Monitor closely"
        : "Healthy",
    riskLevel: getRiskLevel(score),
    posture: calculateContextAwareScore(findings).posture,
  };
}
