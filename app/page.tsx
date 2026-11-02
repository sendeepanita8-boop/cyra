import Navbar from "../components/Navbar";
import ScanBox from "../components/ScanBox";
import FeatureCard from "../components/FeatureCard";
import Footer from "../components/Footer";

export default function Home() {
  return (
    <main className="relative min-h-screen overflow-hidden bg-[#f8fafc] text-slate-900">
      {/* Subtle light background ambient glow */}
      <div className="pointer-events-none absolute inset-0 overflow-hidden">
        <div className="cyra-orb left-[10%] top-[8%] h-80 w-80 bg-emerald-500/10" />
        <div className="cyra-orb right-[10%] top-[25%] h-96 w-96 bg-teal-500/5" />
        <div className="cyra-grid absolute inset-0" />
      </div>

      <Navbar />

      {/* HERO SECTION */}
      <section className="relative z-10 mx-auto flex max-w-7xl flex-col items-center px-6 pb-24 pt-12 text-center lg:px-10 lg:pt-16">
        
        {/* Top Tag Badge */}
        <div className="mb-6 inline-flex items-center gap-2.5 rounded-full border border-emerald-300 bg-emerald-50/90 px-5 py-2 text-xs sm:text-sm font-extrabold uppercase tracking-wider text-emerald-900 shadow-xs">
          <span className="h-2.5 w-2.5 animate-pulse rounded-full bg-emerald-600 shadow-[0_0_10px_rgba(5,150,105,0.9)]" />
          <span>WEBSITE SECURITY & POSTURE VISIBILITY</span>
        </div>

        {/* Main Headline */}
        <h1 className="max-w-5xl text-5xl font-black leading-[1.05] tracking-tight sm:text-6xl lg:text-7xl">
          <span className="text-slate-950">Know what your</span>
          <br />
          <span className="bg-gradient-to-r from-emerald-500 via-teal-500 to-cyan-500 bg-clip-text text-transparent">
            website exposes.
          </span>
        </h1>

        {/* Subtitle with highlighted key signals */}
        <p className="mt-6 max-w-3xl text-lg sm:text-xl leading-relaxed text-slate-700 font-medium">
          CYRA examines <strong className="text-slate-950 font-bold bg-emerald-50/80 px-2 py-0.5 rounded-md border border-emerald-200/60">HTTPS posture</strong>,{" "}
          <strong className="text-slate-950 font-bold bg-teal-50/80 px-2 py-0.5 rounded-md border border-teal-200/60">security headers</strong>,{" "}
          <strong className="text-slate-950 font-bold bg-cyan-50/80 px-2 py-0.5 rounded-md border border-cyan-200/60">DNS health</strong>, and configuration disclosures to generate a clear, professional security audit report.
        </p>

        {/* PROMINENT CENTERED ANALYZER BOX */}
        <div className="mt-11 w-full flex justify-center">
          <ScanBox />
        </div>

        {/* 3 High-Impact Stat Badges */}
        <div className="mt-14 grid w-full max-w-3xl grid-cols-3 gap-4 sm:gap-6">
          <div className="cyra-stat-card">
            <span className="text-4xl sm:text-5xl font-black text-slate-950 tracking-tight">99.9%</span>
            <span className="mt-2 text-xs sm:text-sm font-extrabold uppercase tracking-wider text-slate-600">signal clarity</span>
          </div>
          <div className="cyra-stat-card">
            <span className="text-4xl sm:text-5xl font-black text-slate-950 tracking-tight">8</span>
            <span className="mt-2 text-xs sm:text-sm font-extrabold uppercase tracking-wider text-slate-600">security layers</span>
          </div>
          <div className="cyra-stat-card">
            <span className="text-4xl sm:text-5xl font-black text-emerald-600 tracking-tight">Live</span>
            <span className="mt-2 text-xs sm:text-sm font-extrabold uppercase tracking-wider text-emerald-800">domain checks</span>
          </div>
        </div>

        {/* 4 Process Steps */}
        <div
          id="how"
          className="mt-16 grid w-full max-w-5xl grid-cols-2 overflow-hidden rounded-2xl border border-slate-200 bg-white p-4 shadow-md md:grid-cols-4"
        >
          <ProcessStep number="01" title="Enter domain" description="Specify the public domain you want to evaluate." />
          <ProcessStep number="02" title="Passive scan" description="CYRA inspects live HTTPS, DNS, and header signals." />
          <ProcessStep number="03" title="Analyze risk" description="Findings are classified by impact and OWASP standards." />
          <ProcessStep number="04" title="Get report" description="Review score, grade, and actionable remediations." />
        </div>
      </section>

      {/* SECURITY COVERAGE GRID */}
      <section id="checks" className="relative z-10 mx-auto max-w-7xl px-6 pb-24 lg:px-10">
        <div className="mb-12 text-center">
          <p className="text-xs sm:text-sm font-black uppercase tracking-widest text-emerald-700">SECURITY COVERAGE</p>
          <h2 className="mt-2.5 text-3xl font-black tracking-tight sm:text-4xl lg:text-5xl">
            <span className="bg-gradient-to-r from-emerald-500 via-teal-500 to-cyan-500 bg-clip-text text-transparent">
              Multiple defense layers.
            </span>{" "}
            <span className="text-slate-950">One clear report.</span>
          </h2>
        </div>

        <div className="grid gap-6 md:grid-cols-3">
          <FeatureCard number="01" title="SSL / TLS" description="Inspect HTTPS enforcement, certificate expiration, TLS versions, and modern cipher configuration." />
          <FeatureCard number="02" title="HTTP Headers" description="Audit critical browser security controls including HSTS, CSP, X-Frame-Options, and Referrer policies." />
          <FeatureCard number="03" title="DNS Security" description="Review DNS records, IPv4/IPv6 resolution, and anti-spoofing controls such as SPF, DMARC, and CAA." />
          <FeatureCard number="04" title="Exposure" description="Detect unnecessary server identity banners, framework footprints, and header leakages." />
          <FeatureCard number="05" title="Cookies" description="Inspect session cookie security attributes including Secure, HttpOnly, and SameSite enforcement." />
          <FeatureCard number="06" title="Website Health" description="Benchmark endpoint availability, HTTP status consistency, and response latency SLAs." />
        </div>
      </section>

      {/* ABOUT BANNER */}
      <section id="about" className="relative z-10 mx-auto max-w-7xl px-6 pb-24 lg:px-10">
        <div className="rounded-3xl border border-emerald-200 bg-gradient-to-br from-emerald-50/90 via-teal-50/80 to-cyan-50/60 p-8 sm:p-14 shadow-lg text-center">
          <span className="text-xs sm:text-sm font-black uppercase tracking-widest text-emerald-700">
            SECURITY AUDIT INTELLIGENCE
          </span>
          <h2 className="mt-3.5 text-3xl font-black leading-tight sm:text-4xl lg:text-5xl">
            <span className="bg-gradient-to-r from-emerald-600 via-teal-600 to-cyan-600 bg-clip-text text-transparent">
              Security clarity
            </span>{" "}
            <span className="text-slate-950">for every stakeholder.</span>
          </h2>
          <p className="mt-5 text-base sm:text-lg leading-relaxed text-slate-700 font-medium max-w-3xl mx-auto">
            CYRA is designed to make perimeter security posture simple to comprehend. Each finding clearly explains <strong className="text-slate-950 font-bold">what was detected</strong>, <strong className="text-slate-950 font-bold">why it matters</strong>, <strong className="text-slate-950 font-bold">how severe it is</strong>, and the exact steps needed to fix it.
          </p>
        </div>
      </section>

      {/* TRUST PILLARS */}
      <section className="relative z-10 mx-auto max-w-7xl px-6 pb-24 lg:px-10">
        <div className="mb-10 text-center">
          <h2 className="text-2xl font-black sm:text-3xl lg:text-4xl">
            <span className="bg-gradient-to-r from-emerald-500 via-teal-500 to-cyan-500 bg-clip-text text-transparent">Built on trust.</span>{" "}
            <span className="text-slate-950">Backed by evidence.</span>
          </h2>
        </div>
        <div className="grid gap-6 md:grid-cols-3">
          <TrustCard title="Clear Findings" description="Every security issue is explained in plain language with concrete remediation steps." />
          <TrustCard title="Evidence Based" description="Reports display the exact header payload and observable technical evidence detected." />
          <TrustCard title="Security First" description="Strict passive scanning ensures no denial of service, injection, or destructive testing is performed." />
        </div>
      </section>

      {/* AUDIT NOTE */}
      <section className="relative z-10 mx-auto max-w-4xl px-6 pb-20 text-center">
        <div className="rounded-2xl border border-slate-200 bg-white p-6 sm:p-7 shadow-xs">
          <p className="text-xs sm:text-sm leading-relaxed text-slate-600 font-medium">
            CYRA evaluates publicly visible security configuration and exposure indicators. A security score is benchmark telemetry and does not replace an internal penetration test or regulatory audit.
          </p>
        </div>
      </section>

      <Footer />
    </main>
  );
}

function ProcessStep({ number, title, description }: { number: string; title: string; description: string }) {
  return (
    <div className="p-5 sm:p-6 text-left border-b md:border-b-0 md:border-l border-slate-100 first:border-l-0">
      <span className="text-xs sm:text-sm font-extrabold tracking-widest text-emerald-800 bg-emerald-50 border border-emerald-200 px-2 py-0.5 rounded-md inline-block">
        {number}
      </span>
      <div className="mt-3 text-base sm:text-lg font-bold text-slate-950">{title}</div>
      <div className="mt-1.5 text-sm sm:text-base leading-relaxed text-slate-600 font-medium">{description}</div>
    </div>
  );
}

function TrustCard({ title, description }: { title: string; description: string }) {
  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-7 sm:p-8 shadow-sm transition hover:shadow-md hover:border-emerald-500/50">
      <div className="mb-4 flex h-11 w-11 items-center justify-center rounded-xl border border-emerald-300 bg-emerald-50 text-emerald-700 font-black text-xl">
        ✓
      </div>
      <h3 className="text-xl font-bold text-slate-950">{title}</h3>
      <p className="mt-2.5 text-base leading-relaxed text-slate-600 font-medium">{description}</p>
    </div>
  );
}
