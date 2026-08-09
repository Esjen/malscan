import { useEffect, useState } from "react";
import { supabase } from "@/lib/supabase";
import type { AnalysisSummary, RiskLevel } from "@/lib/types";
import { History, Trash2, FileWarning, FileCheck, ShieldAlert, ShieldX } from "lucide-react";

interface HistorySidebarProps {
  selectedId: string | null;
  onSelect: (id: string) => void;
  refreshKey: number;
}

const LEVEL_ICON: Record<RiskLevel, typeof FileCheck> = {
  low: FileCheck,
  medium: FileWarning,
  high: ShieldAlert,
  critical: ShieldX,
};

const LEVEL_COLOR: Record<RiskLevel, string> = {
  low: "text-emerald-400",
  medium: "text-yellow-400",
  high: "text-orange-400",
  critical: "text-red-400",
};

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

export function HistorySidebar({ selectedId, onSelect, refreshKey }: HistorySidebarProps) {
  const [items, setItems] = useState<AnalysisSummary[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    supabase
      .from("analyses")
      .select("id, file_name, file_size, risk_score, risk_level, created_at")
      .order("created_at", { ascending: false })
      .limit(50)
      .then(({ data }) => {
        if (cancelled) return;
        setItems((data as AnalysisSummary[]) || []);
        setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [refreshKey]);

  const handleDelete = async (id: string) => {
    await supabase.from("analyses").delete().eq("id", id);
    setItems((prev) => prev.filter((i) => i.id !== id));
    if (selectedId === id) onSelect("");
  };

  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center gap-2 border-b border-slate-800 px-4 py-3">
        <History className="h-4 w-4 text-slate-500" />
        <h2 className="text-sm font-semibold text-slate-300">Analysis History</h2>
        <span className="ml-auto text-xs text-slate-600">{items.length}</span>
      </div>

      <div className="flex-1 overflow-y-auto">
        {loading && (
          <div className="px-4 py-8 text-center text-sm text-slate-500">Loading…</div>
        )}
        {!loading && items.length === 0 && (
          <div className="px-4 py-8 text-center text-sm text-slate-500">
            No analyses yet. Upload a binary to begin.
          </div>
        )}
        {!loading &&
          items.map((item) => {
            const Icon = LEVEL_ICON[item.risk_level];
            const isActive = selectedId === item.id;
            return (
              <div
                key={item.id}
                onClick={() => onSelect(item.id)}
                className={[
                  "group flex cursor-pointer items-start gap-3 border-b border-slate-800/50 px-4 py-3 transition-colors",
                  isActive ? "bg-slate-800/60" : "hover:bg-slate-800/30",
                ].join(" ")}
              >
                <Icon className={`mt-0.5 h-4 w-4 shrink-0 ${LEVEL_COLOR[item.risk_level]}`} />
                <div className="min-w-0 flex-1">
                  <p className="truncate text-sm font-medium text-slate-200">{item.file_name}</p>
                  <div className="mt-0.5 flex items-center gap-2 text-xs text-slate-500">
                    <span className={LEVEL_COLOR[item.risk_level]}>{item.risk_score}/100</span>
                    <span>{formatBytes(item.file_size)}</span>
                  </div>
                </div>
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    handleDelete(item.id);
                  }}
                  className="opacity-0 transition-opacity group-hover:opacity-100"
                  title="Delete report"
                >
                  <Trash2 className="h-4 w-4 text-slate-600 hover:text-red-400" />
                </button>
              </div>
            );
          })}
      </div>
    </div>
  );
}
