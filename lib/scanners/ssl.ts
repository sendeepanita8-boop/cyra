import tls from "node:tls";
import type { Finding } from "../types";

type CertificateInfo = {
  subject?: {
    CN?: string;
  };

  issuer?: {
    CN?: string;
    O?: string;
  };

  valid_from?: string;
  valid_to?: string;

  fingerprint256?: string;

  subjectaltname?: string;
};

type TLSConnection = tls.TLSSocket;

function connectTLS(
  domain: string
): Promise<TLSConnection> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      host: domain,
      port: 443,
      rejectUnauthorized: false,
      servername: domain,
      minVersion: "TLSv1.2",
      timeout: 10000,
    });

    socket.once("secureConnect", () => {
      resolve(socket);
    });

    socket.once("error", (error) => {
      socket.destroy();
      reject(error);
    });

    socket.once("timeout", () => {
      socket.destroy();
      reject(
        new Error("TLS connection timed out.")
      );
    });
  });
}

function daysUntil(
  dateString: string
): number {
  const target = new Date(dateString).getTime();
  const now = Date.now();

  return Math.ceil(
    (target - now) /
      (1000 * 60 * 60 * 24)
  );
}

export async function scanSSL(
  domain: string
): Promise<Finding[]> {
  const findings: Finding[] = [];

  let socket: TLSConnection | null = null;

  try {
    socket = await connectTLS(domain);

    /*
     * ==========================================
     * TLS PROTOCOL
     * ==========================================
     */

    const protocol =
      socket.getProtocol();

    if (
      protocol === "TLSv1.3" ||
      protocol === "TLSv1.2"
    ) {
      findings.push({
        id: "ssl-protocol",
        title: "Modern TLS Protocol",
        category: "SSL / TLS",
        severity: "PASS",
        status: "PASS",
        description:
          `The server negotiated ${protocol}.`,
        recommendation:
          "Continue supporting modern TLS versions and disable obsolete protocols.",
        evidence:
          protocol ?? undefined,
      });
    } else {
      findings.push({
        id: "ssl-protocol",
        title: "TLS Protocol",
        category: "SSL / TLS",
        severity: "HIGH",
        status: "WARN",
        description:
          `The negotiated TLS protocol is ${
            protocol ?? "unknown"
          }.`,
        recommendation:
          "Use TLS 1.2 or TLS 1.3 and disable obsolete protocols.",
        evidence:
          protocol ?? undefined,
      });
    }

    /*
     * ==========================================
     * CERTIFICATE
     * ==========================================
     */

    const certificate =
      socket.getPeerCertificate(
        true
      ) as CertificateInfo;

    if (
      !certificate ||
      !certificate.valid_to
    ) {
      findings.push({
        id: "ssl-certificate",
        title: "TLS Certificate",
        category: "SSL / TLS",
        severity: "HIGH",
        status: "FAIL",
        description:
          "CYRA could not obtain a usable TLS certificate from the server.",
        recommendation:
          "Install a valid certificate for the domain and verify the complete certificate chain.",
      });

      return findings;
    }

    /*
     * ==========================================
     * CERTIFICATE EXPIRATION
     * ==========================================
     */

    const remainingDays =
      daysUntil(certificate.valid_to);

    if (remainingDays < 0) {
      findings.push({
        id: "ssl-expiration",
        title: "Certificate Expired",
        category: "SSL / TLS",
        severity: "HIGH",
        status: "FAIL",
        description:
          "The TLS certificate appears to have expired.",
        recommendation:
          "Renew the certificate and verify that the renewed certificate is deployed.",
        evidence:
          certificate.valid_to,
      });
    } else if (remainingDays <= 14) {
      findings.push({
        id: "ssl-expiration",
        title: "Certificate Expiring Soon",
        category: "SSL / TLS",
        severity: "HIGH",
        status: "WARN",
        description:
          `The certificate expires in approximately ${remainingDays} days.`,
        recommendation:
          "Renew the certificate before it expires.",
        evidence:
          certificate.valid_to,
      });
    } else if (remainingDays <= 30) {
      findings.push({
        id: "ssl-expiration",
        title: "Certificate Expiration",
        category: "SSL / TLS",
        severity: "MEDIUM",
        status: "WARN",
        description:
          `The certificate expires in approximately ${remainingDays} days.`,
        recommendation:
          "Plan certificate renewal before the expiration date.",
        evidence:
          certificate.valid_to,
      });
    } else {
      findings.push({
        id: "ssl-expiration",
        title: "Certificate Validity",
        category: "SSL / TLS",
        severity: "PASS",
        status: "PASS",
        description:
          `The certificate has approximately ${remainingDays} days remaining.`,
        recommendation:
          "Continue monitoring certificate expiration.",
        evidence:
          certificate.valid_to,
      });
    }

    /*
     * ==========================================
     * CERTIFICATE SUBJECT
     * ==========================================
     */

    if (certificate.subject?.CN) {
      findings.push({
        id: "ssl-subject",
        title: "Certificate Identity",
        category: "SSL / TLS",
        severity: "INFO",
        status: "PASS",
        description:
          "The certificate provides a subject identity.",
        recommendation:
          "Ensure the certificate identity matches the intended website.",
        evidence:
          certificate.subject.CN,
      });
    }

    /*
     * ==========================================
     * CERTIFICATE ISSUER
     * ==========================================
     */

    if (
      certificate.issuer?.CN ||
      certificate.issuer?.O
    ) {
      findings.push({
        id: "ssl-issuer",
        title: "Certificate Issuer",
        category: "SSL / TLS",
        severity: "INFO",
        status: "PASS",
        description:
          "The TLS certificate provides issuer information.",
        recommendation:
          "Use a trusted certificate authority and monitor certificate changes.",
        evidence:
          certificate.issuer.CN ??
          certificate.issuer.O,
      });
    }

    /*
     * ==========================================
     * SAN
     * ==========================================
     */

    if (certificate.subjectaltname) {
      findings.push({
        id: "ssl-san",
        title: "Certificate SAN",
        category: "SSL / TLS",
        severity: "PASS",
        status: "PASS",
        description:
          "The certificate contains Subject Alternative Name information.",
        recommendation:
          "Ensure the required domain names are covered by the certificate.",
        evidence:
          certificate.subjectaltname,
      });
    } else {
      findings.push({
        id: "ssl-san",
        title: "Certificate SAN",
        category: "SSL / TLS",
        severity: "LOW",
        status: "WARN",
        description:
          "No Subject Alternative Name information was detected.",
        recommendation:
          "Use certificates with appropriate SAN entries for modern TLS deployments.",
      });
    }

    /*
     * ==========================================
     * CERTIFICATE FINGERPRINT
     * ==========================================
     */

    if (certificate.fingerprint256) {
      findings.push({
        id: "ssl-fingerprint",
        title: "Certificate Fingerprint",
        category: "SSL / TLS",
        severity: "INFO",
        status: "PASS",
        description:
          "CYRA obtained the certificate SHA-256 fingerprint.",
        recommendation:
          "Certificate fingerprints can be used to monitor unexpected certificate changes.",
        evidence:
          certificate.fingerprint256,
      });
    }

  } catch (error) {
    findings.push({
      id: "ssl-connection",
      title: "TLS Connection",
      category: "SSL / TLS",
      severity: "HIGH",
      status: "FAIL",
      description:
        "CYRA could not establish a TLS connection to the domain.",
      recommendation:
        "Verify that the domain supports HTTPS on port 443 and that its certificate configuration is correct.",
      evidence:
        error instanceof Error
          ? error.message
          : "Unknown TLS error",
    });
  } finally {
    if (socket) {
      socket.destroy();
    }
  }

  return findings;
}