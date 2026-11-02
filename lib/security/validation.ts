import dns from "node:dns/promises";

export function normalizeDomain(value: string): string {
  return value
    .trim()
    .replace(/^https?:\/\//i, "")
    .replace(/\/.*$/, "")
    .replace(/\.$/, "")
    .toLowerCase();
}

export function validatePublicDomain(domain: string): Promise<{
  valid: boolean;
  reason?: string;
}> {
  return (async () => {
    if (!domain || domain.length > 253) {
      return { valid: false, reason: "Domain is invalid." };
    }

    const isValid = /^(?!-)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i.test(domain);

    if (!isValid) {
      return { valid: false, reason: "Please enter a valid domain." };
    }

    try {
      await dns.lookup(domain, { all: false });
      return { valid: true };
    } catch {
      return { valid: false, reason: "The domain does not resolve publicly." };
    }
  })();
}
