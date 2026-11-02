type FeatureCardProps = {
  number: string;
  title: string;
  description: string;
};

export default function FeatureCard({
  number,
  title,
  description,
}: FeatureCardProps) {
  return (
    <div className="group relative overflow-hidden rounded-2xl border border-slate-200 bg-white p-7 sm:p-8 shadow-sm transition duration-300 hover:-translate-y-1 hover:border-emerald-500/50 hover:shadow-xl">

      {/* Subtle ambient light glow */}
      <div className="absolute -right-16 -top-16 h-36 w-36 rounded-full bg-emerald-500/10 blur-3xl transition group-hover:bg-emerald-500/20" />

      <div className="relative">

        {/* Number + arrow */}
        <div className="flex items-center justify-between">
          <span className="text-xs sm:text-sm font-extrabold tracking-widest text-emerald-800 bg-emerald-50 border border-emerald-300 px-3 py-1 rounded-lg shadow-2xs">
            {number}
          </span>

          <span className="text-base sm:text-lg text-slate-400 font-bold transition group-hover:text-emerald-600 group-hover:translate-x-0.5 group-hover:-translate-y-0.5">
            ↗
          </span>
        </div>

        {/* Title */}
        <h3 className="mt-7 text-xl sm:text-2xl font-black text-slate-950 tracking-tight">
          {title}
        </h3>

        {/* Description */}
        <p className="mt-3 text-base text-slate-600 leading-relaxed font-medium">
          {description}
        </p>

      </div>
    </div>
  );
}