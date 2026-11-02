import Link from "next/link";

export default function Footer() {
  const year = new Date().getFullYear();

  return (
    <footer className="border-t border-slate-200 bg-white">
      <div className="mx-auto max-w-7xl px-6 py-10 lg:px-10">
        
        {/* Top Row */}
        <div className="flex flex-col gap-6 sm:flex-row sm:items-start sm:justify-between">
          
          {/* Brand */}
          <div className="space-y-2">
            <Link href="/" className="group flex items-center gap-3">
              <div className="flex h-9 w-9 items-center justify-center rounded-xl border border-emerald-200 bg-emerald-50 text-emerald-700 font-black text-base transition group-hover:border-emerald-500">
                C
              </div>
              <div>
                <div className="text-base font-extrabold tracking-[0.2em] text-slate-900">CYRA</div>
                <div className="text-[10px] font-bold tracking-widest text-slate-500 uppercase">Security Intelligence</div>
              </div>
            </Link>
            <p className="max-w-xs text-xs font-medium leading-relaxed text-slate-500">
              Automated security posture and passive configuration analysis for authorized public domains.
            </p>
          </div>

          {/* Links */}
          <div className="flex flex-wrap gap-x-10 gap-y-4">
            <div className="space-y-2">
              <p className="text-xs font-extrabold uppercase tracking-widest text-slate-400">Product</p>
              <ul className="space-y-1.5">
                <li>
                  <Link href="/#checks" className="text-sm font-medium text-slate-600 hover:text-emerald-700 transition">
                    Security Checks
                  </Link>
                </li>
                <li>
                  <Link href="/#how" className="text-sm font-medium text-slate-600 hover:text-emerald-700 transition">
                    How It Works
                  </Link>
                </li>
                <li>
                  <Link href="/report" className="text-sm font-medium text-slate-600 hover:text-emerald-700 transition">
                    Demo Report
                  </Link>
                </li>
              </ul>
            </div>

            <div className="space-y-2">
              <p className="text-xs font-extrabold uppercase tracking-widest text-slate-400">Legal</p>
              <ul className="space-y-1.5">
                <li>
                  <span className="text-sm font-medium text-slate-500 cursor-default">
                    Privacy Policy
                  </span>
                </li>
                <li>
                  <span className="text-sm font-medium text-slate-500 cursor-default">
                    Terms of Use
                  </span>
                </li>
                <li>
                  <span className="text-sm font-medium text-slate-500 cursor-default">
                    Responsible Use
                  </span>
                </li>
              </ul>
            </div>
          </div>
        </div>

        {/* Divider */}
        <div className="mt-8 border-t border-slate-100 pt-6">
          <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
            <p className="text-xs font-medium text-slate-500">
              © {year} CYRA Security Intelligence. All rights reserved.
            </p>
            <div className="flex items-center gap-2 text-xs font-medium text-slate-500">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-500 animate-pulse" />
              <span>Passive scanning only — no intrusive testing</span>
            </div>
          </div>
        </div>
      </div>
    </footer>
  );
}