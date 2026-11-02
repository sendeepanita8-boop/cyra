import Link from "next/link";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Page Not Found — CYRA Security",
  description: "The page you are looking for does not exist.",
  robots: { index: false, follow: false },
};

export default function NotFound() {
  return (
    <main className="relative flex min-h-screen flex-col items-center justify-center bg-[#f8fafc] px-6 py-16 text-slate-900">
      {/* Ambient background */}
      <div className="pointer-events-none fixed inset-0 overflow-hidden">
        <div className="absolute left-1/3 top-1/4 h-80 w-80 rounded-full bg-emerald-500/8 blur-[140px]" />
        <div className="cyra-grid absolute inset-0" />
      </div>

      <div className="relative z-10 mx-auto flex w-full max-w-lg flex-col items-center text-center animate-fade-in">
        {/* Logo */}
        <Link href="/" className="group flex items-center gap-3 mb-8">
          <div className="flex h-12 w-12 items-center justify-center rounded-2xl border border-emerald-200 bg-emerald-50 text-emerald-700 font-black text-xl shadow-md transition group-hover:border-emerald-500">
            C
          </div>
          <span className="font-extrabold tracking-[0.2em] text-slate-950 text-lg">CYRA</span>
        </Link>

        {/* 404 Badge */}
        <div className="mb-6 inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-4 py-1.5 text-xs font-bold uppercase tracking-wider text-slate-600 shadow-sm">
          <span className="text-rose-500">404</span>
          <span className="text-slate-300">•</span>
          <span>Page Not Found</span>
        </div>

        <h1 className="text-4xl font-black tracking-tight text-slate-950 sm:text-5xl">
          This page doesn&apos;t exist.
        </h1>

        <p className="mt-4 text-base font-medium text-slate-600 max-w-sm leading-relaxed">
          The URL you followed may be broken, or the page may have been removed.
          Head back and run a new security scan.
        </p>

        <div className="mt-10 flex flex-wrap items-center justify-center gap-3">
          <Link
            href="/"
            className="rounded-xl bg-emerald-600 px-6 py-3 text-sm font-bold text-white shadow-md shadow-emerald-600/25 transition hover:bg-emerald-500"
          >
            ← Back to CYRA
          </Link>
          <Link
            href="/report"
            className="rounded-xl border border-slate-200 bg-white px-6 py-3 text-sm font-bold text-slate-700 shadow-xs transition hover:bg-slate-50 hover:text-slate-950"
          >
            View Report
          </Link>
        </div>
      </div>
    </main>
  );
}
