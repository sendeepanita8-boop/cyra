"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";

export default function ScanBox() {
  const router = useRouter();

  const [domain, setDomain] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  function cleanDomain(value: string) {
    return value
      .replace(/^https?:\/\//i, "")
      .replace(/\/.*$/, "")
      .trim()
      .toLowerCase();
  }

  async function handleScan(targetDomain?: string) {
    setError("");
    const raw = targetDomain || domain;
    const clean = cleanDomain(raw);

    if (!clean) {
      setError("Please enter a target domain name.");
      return;
    }

    if (!clean.includes(".") || clean.includes(" ")) {
      setError("Please enter a valid domain (e.g. example.com).");
      return;
    }

    try {
      setLoading(true);

      const response = await fetch("/api/scan", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          domain: clean,
        }),
      });

      const result = await response.json();

      if (!response.ok || !result.success) {
        throw new Error(result.error || "Unable to complete scan for this domain.");
      }

      sessionStorage.setItem("cyra-scan-result", JSON.stringify(result.data));
      router.push("/report");
    } catch (err: unknown) {
      const message =
        err instanceof Error ? err.message : "Something went wrong while scanning.";
      setError(message);
    } finally {
      setLoading(false);
    }
  }

  const sampleDomains = ["github.com", "cloudflare.com", "stripe.com"];

  return (
    <div className="mx-auto w-full max-w-3xl px-4 sm:px-0">
      
      {/* Outer Card Container */}
      <div className="group relative">
        <div
          className={`absolute -inset-1 rounded-3xl bg-emerald-500/15 blur-xl transition duration-500 ${
            loading ? "opacity-100" : "opacity-30 group-hover:opacity-60"
          }`}
        />

        <div className="relative rounded-2xl sm:rounded-3xl border-2 border-slate-200 bg-white p-2.5 sm:p-3.5 shadow-xl transition group-hover:border-emerald-500/40">
          <div className="flex flex-col gap-2.5 sm:flex-row sm:items-center">
            
            {/* Input Wrapper with Crisp High Contrast */}
            <div className="flex flex-1 items-center rounded-xl sm:rounded-2xl border-2 border-slate-200 bg-slate-50/90 px-4 py-1.5 focus-within:border-emerald-600 focus-within:bg-white focus-within:ring-4 focus-within:ring-emerald-500/15 transition">
              <span className="mr-3 text-base sm:text-lg font-mono font-black text-emerald-700 select-none">
                https://
              </span>

              <input
                type="text"
                value={domain}
                disabled={loading}
                onChange={(e) => {
                  setDomain(e.target.value);
                  setError("");
                }}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && !loading) {
                    handleScan();
                  }
                }}
                placeholder="Enter domain — e.g. yoursite.com"
                className="h-14 sm:h-16 w-full bg-transparent text-lg sm:text-xl font-bold text-slate-950 outline-none placeholder:text-slate-400 placeholder:font-medium disabled:cursor-not-allowed disabled:opacity-50"
              />

              {domain && !loading && (
                <button
                  type="button"
                  onClick={() => {
                    setDomain("");
                    setError("");
                  }}
                  className="ml-2 text-slate-400 hover:text-slate-800 p-1.5 text-base font-black transition"
                >
                  ✕
                </button>
              )}
            </div>

            {/* Prominent Analyze Button */}
            <button
              onClick={() => handleScan()}
              disabled={loading}
              className="flex h-14 sm:h-16 items-center justify-center rounded-xl sm:rounded-2xl bg-gradient-to-r from-emerald-600 to-teal-600 px-8 sm:px-10 text-base sm:text-lg font-black text-white shadow-lg shadow-emerald-600/30 transition hover:from-emerald-500 hover:to-teal-500 hover:shadow-xl hover:shadow-emerald-600/40 active:scale-[0.98] disabled:cursor-not-allowed disabled:opacity-60"
            >
              {loading ? (
                <span className="flex items-center gap-3">
                  <span className="h-5 w-5 animate-spin rounded-full border-2 border-white/30 border-t-white" />
                  <span className="font-extrabold">Analyzing...</span>
                </span>
              ) : (
                <span className="flex items-center gap-2.5">
                  <span>Analyze Website</span>
                  <span className="text-2xl leading-none font-bold">→</span>
                </span>
              )}
            </button>

          </div>
        </div>
      </div>

      {/* Quick Sample Domain Chips */}
      <div className="mt-4 flex flex-wrap items-center justify-center gap-2.5 text-xs sm:text-sm">
        <span className="font-extrabold text-slate-500 uppercase tracking-wider text-xs">Quick Test:</span>
        {sampleDomains.map((sample) => (
          <button
            key={sample}
            type="button"
            disabled={loading}
            onClick={() => {
              setDomain(sample);
              setError("");
              handleScan(sample);
            }}
            className="rounded-xl border border-slate-300 bg-white px-3.5 py-1.5 text-xs sm:text-sm font-bold text-slate-800 shadow-xs transition hover:border-emerald-600 hover:bg-emerald-50 hover:text-emerald-900 active:scale-95"
          >
            {sample}
          </button>
        ))}
      </div>

      {/* Error Message */}
      {error && (
        <div className="mt-4 rounded-xl border-2 border-rose-300 bg-rose-50 p-4 text-center text-sm sm:text-base font-extrabold text-rose-900 animate-in fade-in shadow-xs">
          ⚠️ {error}
        </div>
      )}

      {/* Trust & Methodology Badges */}
      {!error && (
        <div className="mt-6 flex flex-wrap items-center justify-center gap-x-7 gap-y-2.5 text-xs sm:text-sm font-bold text-slate-700">
          <span className="flex items-center gap-2 rounded-full bg-slate-100/90 border border-slate-200 px-3 py-1">
            <span className="text-emerald-700 font-extrabold">🔒</span>
            <span>Passive Public Audit</span>
          </span>
          <span className="flex items-center gap-2 rounded-full bg-emerald-50 border border-emerald-200 px-3 py-1 text-emerald-900">
            <span className="text-emerald-600 font-extrabold">⚡</span>
            <span>Instant Health & Score</span>
          </span>
          <span className="flex items-center gap-2 rounded-full bg-slate-100/90 border border-slate-200 px-3 py-1">
            <span className="text-emerald-700 font-extrabold">🛡️</span>
            <span>Non-Intrusive & Safe</span>
          </span>
        </div>
      )}

    </div>
  );
}