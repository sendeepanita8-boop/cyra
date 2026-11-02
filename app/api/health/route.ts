import { NextResponse } from "next/server";

/**
 * GET /api/health
 *
 * Lightweight liveness probe for load-balancers, uptime monitors,
 * and Kubernetes/Docker health-check endpoints.
 *
 * Returns HTTP 200 with a minimal JSON payload when the app is running.
 * Deliberately performs no database or external I/O so it is always fast.
 */
export async function GET() {
  return NextResponse.json(
    {
      status: "ok",
      service: "cyra-security-scanner",
      version: process.env.npm_package_version ?? "0.1.0",
      timestamp: new Date().toISOString(),
      environment: process.env.NODE_ENV ?? "production",
    },
    {
      status: 200,
      headers: {
        "Cache-Control": "no-store, no-cache, must-revalidate",
        "Content-Type": "application/json",
      },
    }
  );
}
