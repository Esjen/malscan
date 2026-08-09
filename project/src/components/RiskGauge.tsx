interface RiskGaugeProps {
  score: number;
  level: "low" | "medium" | "high" | "critical";
}

const LEVEL_COLORS: Record<string, { stroke: string; glow: string; text: string; bg: string }> = {
  low: { stroke: "#22c55e", glow: "rgba(34,197,94,0.3)", text: "text-emerald-400", bg: "bg-emerald-500/10" },
  medium: { stroke: "#eab308", glow: "rgba(234,179,8,0.3)", text: "text-yellow-400", bg: "bg-yellow-500/10" },
  high: { stroke: "#f97316", glow: "rgba(249,115,22,0.3)", text: "text-orange-400", bg: "bg-orange-500/10" },
  critical: { stroke: "#ef4444", glow: "rgba(239,68,68,0.35)", text: "text-red-400", bg: "bg-red-500/10" },
};

export function RiskGauge({ score, level }: RiskGaugeProps) {
  const radius = 80;
  const circumference = Math.PI * radius;
  const dashOffset = circumference - (score / 100) * circumference;
  const colors = LEVEL_COLORS[level];

  return (
    <div className="flex flex-col items-center">
      <div className="relative">
        <svg width="200" height="110" viewBox="0 0 200 110">
          <path
            d={`M 20 100 A ${radius} ${radius} 0 0 1 180 100`}
            fill="none"
            stroke="#1e293b"
            strokeWidth="12"
            strokeLinecap="round"
          />
          <path
            d={`M 20 100 A ${radius} ${radius} 0 0 1 180 100`}
            fill="none"
            stroke={colors.stroke}
            strokeWidth="12"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={dashOffset}
            style={{
              transition: "stroke-dashoffset 1s ease-out, stroke 0.5s",
              filter: `drop-shadow(0 0 6px ${colors.glow})`,
            }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-end pb-1">
          <span className={`text-4xl font-bold ${colors.text}`}>{score}</span>
          <span className="text-xs text-slate-500">/ 100</span>
        </div>
      </div>
      <div className={`mt-2 rounded-full px-4 py-1 text-sm font-semibold uppercase tracking-wide ${colors.bg} ${colors.text}`}>
        {level}
      </div>
    </div>
  );
}
