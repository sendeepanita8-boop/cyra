import dnsPromises from "node:dns/promises";
import dns from "node:dns";
import type { Finding } from "../types";

// Fallback public DNS resolvers (Cloudflare, Google) used when local system
// resolvers (e.g. Windows loopback stub 127.0.0.1) fail or refuse UDP queries
const FALLBACK_DNS_SERVERS = ["1.1.1.1", "8.8.8.8", "1.0.0.1", "8.8.4.4"];

function getResolver(): dnsPromises.Resolver {
  const resolver = new dnsPromises.Resolver();
  try {
    const sysServers = dns.getServers();
    const isLoopbackOnly =
      !sysServers.length || sysServers.every((s) => s === "127.0.0.1" || s === "::1");
    if (isLoopbackOnly) {
      resolver.setServers(FALLBACK_DNS_SERVERS);
    } else {
      resolver.setServers([...sysServers, ...FALLBACK_DNS_SERVERS]);
    }
  } catch {
    resolver.setServers(FALLBACK_DNS_SERVERS);
  }
  return resolver;
}

async function getRecords(
  type:
    | "A"
    | "AAAA"
    | "MX"
    | "NS"
    | "TXT"
    | "CAA",
  domain: string
): Promise<any[]> {
  const resolver = getResolver();
  try {
    switch (type) {
      case "A":
        return await resolver.resolve4(domain);

      case "AAAA":
        return await resolver.resolve6(domain);

      case "MX":
        return await resolver.resolveMx(domain);

      case "NS":
        return await resolver.resolveNs(domain);

      case "TXT":
        return await resolver.resolveTxt(domain);

      case "CAA":
        return await resolver.resolveCaa(domain);

      default:
        return [];
    }
  } catch {
    return [];
  }
}

function flattenTXT(records: string[][]): string[] {
  return records.map((record) => record.join(""));
}

export async function scanDNS(
  domain: string
): Promise<Finding[]> {
  const findings: Finding[] = [];

  /*
   * ==========================================
   * A RECORD
   * ==========================================
   */

  const aRecords = await getRecords("A", domain);

  if (aRecords.length > 0) {
    findings.push({
      id: "dns-a",
      title: "IPv4 DNS Record",
      category: "DNS Security",
      severity: "INFO",
      status: "PASS",
      description:
        "The domain has one or more public IPv4 DNS records.",
      recommendation:
        "Review DNS records periodically and remove obsolete addresses.",
      evidence: aRecords.join(", "),
    });
  } else {
    findings.push({
      id: "dns-a",
      title: "IPv4 DNS Record",
      category: "DNS Security",
      severity: "INFO",
      status: "WARN",
      description:
        "No IPv4 A record was detected.",
      recommendation:
        "Verify that the domain's DNS configuration is intentional.",
    });
  }

  /*
   * ==========================================
   * AAAA RECORD
   * ==========================================
   */

  const aaaaRecords = await getRecords(
    "AAAA",
    domain
  );

  if (aaaaRecords.length > 0) {
    findings.push({
      id: "dns-aaaa",
      title: "IPv6 DNS Record",
      category: "DNS Security",
      severity: "INFO",
      status: "PASS",
      description:
        "The domain publishes an IPv6 address.",
      recommendation:
        "Ensure IPv6 services receive the same security controls as IPv4 services.",
      evidence: aaaaRecords.join(", "),
    });
  } else {
    findings.push({
      id: "dns-aaaa",
      title: "IPv6 DNS Record",
      category: "DNS Security",
      severity: "INFO",
      status: "PASS",
      description:
        "No IPv6 AAAA record was detected.",
      recommendation:
        "If IPv6 is not required, no action is necessary.",
    });
  }

  /*
   * ==========================================
   * MX
   * ==========================================
   */

  const mxRecords = await getRecords(
    "MX",
    domain
  );

  if (mxRecords.length > 0) {
    const mxEvidence = mxRecords
      .map(
        (record) =>
          `${record.priority} ${record.exchange}`
      )
      .join(", ");

    findings.push({
      id: "dns-mx",
      title: "Mail Exchange Records",
      category: "DNS Security",
      severity: "INFO",
      status: "PASS",
      description:
        "Mail exchange records were detected for the domain.",
      recommendation:
        "Ensure all listed mail providers are expected and properly secured.",
      evidence: mxEvidence,
    });
  } else {
    findings.push({
      id: "dns-mx",
      title: "Mail Exchange Records",
      category: "DNS Security",
      severity: "INFO",
      status: "PASS",
      description:
        "No MX records were detected.",
      recommendation:
        "If the domain does not receive email, this may be intentional.",
    });
  }

  /*
   * ==========================================
   * NAMESERVERS
   * ==========================================
   */

  const nsRecords = await getRecords(
    "NS",
    domain
  );

  if (nsRecords.length > 0) {
    findings.push({
      id: "dns-ns",
      title: "Authoritative Nameservers",
      category: "DNS Security",
      severity: "INFO",
      status: "PASS",
      description:
        "Authoritative nameserver records were detected.",
      recommendation:
        "Review nameservers and ensure only trusted DNS providers are configured.",
      evidence: nsRecords.join(", "),
    });
  } else {
    findings.push({
      id: "dns-ns",
      title: "Authoritative Nameservers",
      category: "DNS Security",
      severity: "MEDIUM",
      status: "WARN",
      description:
        "CYRA could not retrieve authoritative nameserver records.",
      recommendation:
        "Verify that the domain's DNS delegation is configured correctly.",
    });
  }

  /*
   * ==========================================
   * TXT RECORDS
   * ==========================================
   */

  const rawTXT = await getRecords(
    "TXT",
    domain
  );

  const txtRecords = flattenTXT(
    rawTXT as string[][]
  );

  const spfRecord = txtRecords.find(
    (record) =>
      record.toLowerCase().startsWith(
        "v=spf1"
      )
  );

  /*
   * SPF
   */

  if (spfRecord) {
    findings.push({
      id: "dns-spf",
      title: "SPF Email Protection",
      category: "DNS Security",
      severity: "PASS",
      status: "PASS",
      description:
        "An SPF record was detected.",
      recommendation:
        "Review the SPF policy and ensure only authorized mail servers are included.",
      evidence: spfRecord,
    });
  } else {
    findings.push({
      id: "dns-spf",
      title: "SPF Email Protection",
      category: "DNS Security",
      severity: "MEDIUM",
      status: "WARN",
      description:
        "No SPF record was detected.",
      recommendation:
        "If the domain sends email, configure SPF to identify authorized sending servers.",
    });
  }

  /*
   * ==========================================
   * DMARC
   * ==========================================
   */

  let dmarcRecords: string[][] = [];

  try {
    const resolver = getResolver();
    dmarcRecords =
      await resolver.resolveTxt(
        `_dmarc.${domain}`
      );
  } catch {
    dmarcRecords = [];
  }

  const dmarcTXT = flattenTXT(
    dmarcRecords
  );

  const dmarcRecord = dmarcTXT.find(
    (record) =>
      record
        .toLowerCase()
        .startsWith("v=dmarc1")
  );

  if (dmarcRecord) {
    const policyMatch =
      dmarcRecord.match(
        /(?:^|;)\s*p=([^;]+)/i
      );

    const policy =
      policyMatch?.[1]?.trim().toLowerCase();

    if (
      policy === "reject" ||
      policy === "quarantine"
    ) {
      findings.push({
        id: "dns-dmarc",
        title: "DMARC Email Protection",
        category: "DNS Security",
        severity: "PASS",
        status: "PASS",
        description:
          `A DMARC policy of ${policy} was detected.`,
        recommendation:
          "Continue monitoring DMARC reports and maintain the intended policy.",
        evidence: dmarcRecord,
      });
    } else {
      findings.push({
        id: "dns-dmarc",
        title: "DMARC Email Protection",
        category: "DNS Security",
        severity: "MEDIUM",
        status: "WARN",
        description:
          `A DMARC record was found with policy ${
            policy ?? "not specified"
          }.`,
        recommendation:
          "Review the DMARC policy and consider moving from monitoring to enforcement when appropriate.",
        evidence: dmarcRecord,
      });
    }
  } else {
    findings.push({
      id: "dns-dmarc",
      title: "DMARC Email Protection",
      category: "DNS Security",
      severity: "MEDIUM",
      status: "WARN",
      description:
        "No DMARC record was detected.",
      recommendation:
        "If the domain sends email, consider implementing DMARC to reduce domain spoofing risks.",
    });
  }

  /*
   * ==========================================
   * CAA
   * ==========================================
   */

  const caaRecords = await getRecords(
    "CAA",
    domain
  );

  if (caaRecords.length > 0) {
    const caaEvidence = caaRecords
      .map(
        (record) =>
          `${record.issue ?? ""} ${
            record.value ?? ""
          }`.trim()
      )
      .join(", ");

    findings.push({
      id: "dns-caa",
      title: "Certificate Authority Authorization",
      category: "DNS Security",
      severity: "PASS",
      status: "PASS",
      description:
        "CAA DNS records were detected.",
      recommendation:
        "Review CAA records and allow only intended certificate authorities.",
      evidence: caaEvidence,
    });
  } else {
    findings.push({
      id: "dns-caa",
      title: "Certificate Authority Authorization",
      category: "DNS Security",
      severity: "LOW",
      status: "WARN",
      description:
        "No CAA record was detected.",
      recommendation:
        "Consider configuring CAA records to restrict which certificate authorities may issue certificates for the domain.",
    });
  }

  /*
   * ==========================================
   * DNSSEC INDICATOR
   * ==========================================
   *
   * Node's standard DNS resolver does not expose
   * a simple portable DNSSEC validation result.
   *
   * Therefore CYRA reports this as an
   * informational limitation instead of pretending
   * that DNSSEC was verified.
   */

  findings.push({
    id: "dns-dnssec",
    title: "DNSSEC Validation",
    category: "DNS Security",
    severity: "INFO",
    status: "WARN",
    description:
      "DNSSEC validation was not independently verified by the current scanner.",
    recommendation:
      "Use a DNSSEC-aware resolver or specialized DNS analysis service when DNSSEC verification is required.",
    evidence:
      "Verification unavailable through the current DNS resolver.",
  });

  return findings;
}
