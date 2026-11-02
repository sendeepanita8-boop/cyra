import type {
  Finding,
  SecurityArea,
  SecurityContext,
} from "../types";

const CATEGORY_CONTEXT: Record<string, SecurityContext> = {
  "SSL / TLS": "TLS",
  "HTTP Headers": "Website",
  "Cookies": "Website",
  "Redirects": "Website",
  "DNS Security": "DNS",
  "Information Exposure": "Privacy",
  "Availability": "Website",
  "Security Configuration": "Configuration",
  "Email Security": "Email",
  "Email": "Email",
};

const CATEGORY_AREA: Record<string, SecurityArea> = {
  "SSL / TLS": "TLS",
  "HTTP Headers": "Website",
  "Cookies": "Cookies",
  "Redirects": "Website",
  "DNS Security": "DNS",
  "Information Exposure": "Website",
  "Availability": "Website",
  "Security Configuration": "Configuration",
  "Email Security": "Email",
  "Email": "Email",
};

export function classifyFindingContext(
  category: string
): SecurityContext {
  return CATEGORY_CONTEXT[category] ?? "Configuration";
}

export function classifySecurityArea(
  category: string
): SecurityArea {
  return CATEGORY_AREA[category] ?? "Configuration";
}

export function classifyFinding(
  finding: Pick<Finding, "category" | "title">
): {
  context: SecurityContext;
  area: SecurityArea;
} {
  const category = finding.category || "Security Configuration";

  return {
    context: classifyFindingContext(category),
    area: classifySecurityArea(category),
  };
}

export function normalizeFindingContext(
  finding: Finding
): SecurityContext {
  const context = classifyFindingContext(finding.category);

  if (finding.title.toLowerCase().includes("email")) {
    return "Email";
  }

  if (
    context === "Privacy" &&
    finding.title.toLowerCase().includes("header")
  ) {
    return "Website";
  }

  return context;
}
