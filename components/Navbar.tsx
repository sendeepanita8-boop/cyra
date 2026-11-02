import Link from "next/link";

export default function Navbar() {
  return (
    <nav className="relative z-50 mx-auto flex w-full max-w-7xl items-center justify-between px-6 py-5 lg:px-10">

      {/* Logo */}
      <Link href="/" className="group flex items-center gap-3.5">
        <div className="flex h-12 w-12 items-center justify-center rounded-2xl border-2 border-emerald-500/40 bg-emerald-50 text-emerald-700 shadow-md transition group-hover:border-emerald-600 group-hover:scale-105">
          <span className="text-2xl font-black">
            C
          </span>
        </div>

        <div>
          <div className="text-xl font-black tracking-[0.22em] text-slate-950">
            CYRA
          </div>

          <div className="text-xs font-extrabold tracking-[0.2em] text-emerald-800">
            SECURITY INTELLIGENCE
          </div>
        </div>
      </Link>

      {/* Navigation */}
      <div className="hidden items-center gap-9 text-base font-bold text-slate-700 md:flex">
        <Link href="#checks" className="transition hover:text-emerald-700">
          Security Checks
        </Link>

        <Link href="#how" className="transition hover:text-emerald-700">
          How It Works
        </Link>

        <Link href="#about" className="transition hover:text-emerald-700">
          About
        </Link>
      </div>

      {/* Scanner status */}
      <div className="hidden items-center gap-2.5 rounded-full border border-emerald-300 bg-emerald-50/90 px-4 py-2 text-xs sm:text-sm font-extrabold text-emerald-900 sm:flex shadow-xs">
        <span className="h-2.5 w-2.5 rounded-full bg-emerald-600 animate-pulse shadow-[0_0_10px_rgba(5,150,105,0.9)]" />
        Scanner Active & Online
      </div>

    </nav>
  );
}