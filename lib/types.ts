export type Severity =
  | "PASS"
  | "INFO"
  | "LOW"
  | "MEDIUM"
  | "HIGH"
  | "CRITICAL";

export type Status = "PASS" | "WARN" | "FAIL";

export type RiskLevel =
  | "Minimal"
  | "Low"
  | "Moderate"
  | "High"
  | "Critical";

export type SecurityStatus =
  | "Healthy"
  | "Stable"
  | "Monitor"
  | "Attention";

export type SecurityContext =
  | "Website"
  | "Email"
  | "DNS"
  | "TLS"
  | "Privacy"
  | "Configuration";

export type SecurityArea =
  | "TLS"
  | "Email"
  | "Cookies"
  | "Website"
  | "DNS"
  | "Configuration";

export type AttackSurfaceSeverity =
  | "Low"
  | "Moderate"
  | "High"
  | "Critical";

export type AttackSurfaceIndicator = {
  name: string;
  value: string;
  severity: AttackSurfaceSeverity;
};

export type SecurityPosture = {
  score: number;
  status: SecurityStatus;
  riskLevel: RiskLevel;
  areas: SecurityArea[];
  attackSurface: AttackSurfaceIndicator[];
  summary: string;
};

export type RiskAssessment = {
  level: RiskLevel;
  priority: number;
  explanation: string;
  context: SecurityContext;
  area: SecurityArea;
};

export type SecurityScore = {
  score: number;
  status: SecurityStatus;
  riskLevel: RiskLevel;
  posture: SecurityPosture;
  topRisks: Finding[];
  recommendations: string[];
  areas: SecurityArea[];
  context: SecurityContext;
  summary: string;
};

export type Finding = {
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

