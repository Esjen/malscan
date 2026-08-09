import { useState } from "react";
import type { AnalysisResult } from "@/lib/types";
import { RiskGauge } from "./RiskGauge";
import { CfgVisualizer } from "./CfgVisualizer";
import {
  Shield,
  Binary,
  Download,
  Layers,
  Terminal,
  GitBranch,
  Cpu,
  AlertTriangle,
  Copy,
  Check,
  Sparkles,
  ChevronDown,
  ChevronRight,
} from "lucide-react";

interface AnalysisDashboardProps {
  result: AnalysisResult;
  onNewScan: () => void;
}

type Tab = "overview" | "imports" | "strings" | "sections" | "cfg" | "explanation";

const ENTROPY_COLOR = (e: number) => {
  if (e >= 7.2) return "text-red-400";
  if (e >= 6.5) return "text-orange-400";
  if (e >= 4) return "text-yellow-400";
  return "text-emerald-400";
};

function hex(n: number): string {
  return "0x" + n.toString(16).toUpperCase().padStart(8, "0");
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

function truncateHash(h: string): string {
  return h.length > 20 ? `${h.slice(0, 18)}…${h.slice(-8)}` : h;
}

export function AnalysisDashboard({ result, onNewScan }: AnalysisDashboardProps) {
  const [tab, setTab] = useState<Tab>("overview");
  const [copied, setCopied] = useState(false);
  const [expandedDll, setExpandedDll] = useState<string | null>(null);

  const tabs: { id: Tab; label: string; icon: typeof Shield }[] = [
    { id: "overview", label: "Overview", icon: Shield },
    { id: "imports", label: `Imports (${result.imports.length})`, icon: Download },
    { id: "strings", label: `Strings (${result.strings.length})`, icon: Terminal },
    { id: "sections", label: `Sections (${result.sections.length})`, icon: Layers },
    { id: "cfg", label: "Control Flow", icon: GitBranch },
    { id: "explanation", label: "AI Explanation", icon: Sparkles },
  ];

  const suspiciousByCategory = result.suspicious_apis.reduce<Record<string, typeof result.suspicious_apis>>((acc, api) => {
    (acc[api.category] ||= []).push(api);
    return acc;
  }, {});

  const downloadReport = () => {
    const report = {
      file_name: result.file_name,
      file_size: result.file_size,
      file_hash: result.file_hash,
      analyzed_at: result.created_at,
      risk_score: result.risk_score,
      risk_level: result.risk_level,
      metadata: result.metadata,
      imports: result.imports,
      suspicious_apis: result.suspicious_apis,
      strings: result.strings,
      sections: result.sections,
      cfg: result.cfg,
      ai_explanation: result.ai_explanation,
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `report-${result.file_name.replace(/\.[^.]+$/, "")}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const copyHash = () => {
    navigator.clipboard.writeText(result.file_hash);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header bar */}
      <div className="flex flex-col gap-4 rounded-2xl border border-slate-800 bg-slate-900/60 p-5 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-start gap-4">
          <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-500/20 ring-1 ring-cyan-500/30">
            <Binary className="h-6 w-6 text-cyan-400" />
          </div>
          <div className="min-w-0">
            <h2 className="truncate text-lg font-semibold text-slate-100">{result.file_name}</h2>
            <div className="mt-1 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-400">
              <span>{formatBytes(result.file_size)}</span>
              <button
                onClick={copyHash}
                className="flex items-center gap-1 font-mono text-slate-500 transition-colors hover:text-cyan-400"
                title="Copy full SHA-256"
              >
                SHA-256: {truncateHash(result.file_hash)}
                {copied ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
              </button>
              <span>{new Date(result.created_at).toLocaleString()}</span>
            </div>
          </div>
        </div>
        <div className="flex gap-2">
          <button
            onClick={downloadReport}
            className="flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-800/50 px-4 py-2 text-sm font-medium text-slate-200 transition-colors hover:border-slate-600 hover:bg-slate-800"
          >
            <Download className="h-4 w-4" />
            Export Report
          </button>
          <button
            onClick={onNewScan}
            className="flex items-center gap-2 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 px-4 py-2 text-sm font-medium text-white transition-all hover:from-cyan-500 hover:to-blue-500"
          >
            <Shield className="h-4 w-4" />
            New Scan
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex flex-wrap gap-1 rounded-xl border border-slate-800 bg-slate-900/40 p-1">
        {tabs.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={[
              "flex items-center gap-2 rounded-lg px-3 py-2 text-sm font-medium transition-all",
              tab === t.id
                ? "bg-slate-800 text-cyan-400 shadow-sm"
                : "text-slate-400 hover:bg-slate-800/50 hover:text-slate-200",
            ].join(" ")}
          >
            <t.icon className="h-4 w-4" />
            {t.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {tab === "overview" && (
        <div className="grid gap-6 lg:grid-cols-3">
          {/* Risk gauge */}
          <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6 lg:col-span-1">
            <h3 className="mb-4 flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-slate-400">
              <Shield className="h-4 w-4" /> Risk Assessment
            </h3>
            <RiskGauge score={result.risk_score} level={result.risk_level} />
            <div className="mt-5 space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-slate-400">Suspicious APIs</span>
                <span className="font-medium text-slate-200">{result.suspicious_apis.length}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Total Imports</span>
                <span className="font-medium text-slate-200">
                  {result.imports.reduce((s, i) => s + i.functions.length, 0)}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Sections</span>
                <span className="font-medium text-slate-200">{result.sections.length}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Extracted Strings</span>
                <span className="font-medium text-slate-200">{result.strings.length}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">CFG Nodes</span>
                <span className="font-medium text-slate-200">{result.cfg.node_count}</span>
              </div>
            </div>
          </div>

          {/* Metadata */}
          <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6 lg:col-span-2">
            <h3 className="mb-4 flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-slate-400">
              <Cpu className="h-4 w-4" /> PE Metadata
            </h3>
            <div className="grid grid-cols-1 gap-x-6 gap-y-3 sm:grid-cols-2">
              <MetaRow label="Architecture" value={result.metadata.machine} />
              <MetaRow label="Subsystem" value={result.metadata.subsystem} />
              <MetaRow label="Image Type" value={result.metadata.is_dll ? "DLL" : "Executable"} />
              <MetaRow label="Entry Point" value={hex(result.metadata.entry_point)} />
              <MetaRow label="Image Base" value={hex(result.metadata.image_base)} />
              <MetaRow label="Build Timestamp" value={result.metadata.timestamp_human || "N/A"} />
              <MetaRow label="Size of Image" value={formatBytes(result.metadata.size_of_image)} />
              <MetaRow label="Size of Headers" value={formatBytes(result.metadata.size_of_headers)} />
            </div>

            <div className="mt-4 space-y-3">
              <div>
                <p className="mb-1.5 text-xs font-medium uppercase tracking-wide text-slate-500">Characteristics</p>
                <div className="flex flex-wrap gap-1.5">
                  {result.metadata.characteristics.map((c) => (
                    <span key={c} className="rounded-md bg-slate-800 px-2 py-0.5 text-xs text-slate-300">
                      {c}
                    </span>
                  ))}
                </div>
              </div>
              <div>
                <p className="mb-1.5 text-xs font-medium uppercase tracking-wide text-slate-500">DLL Characteristics</p>
                <div className="flex flex-wrap gap-1.5">
                  {result.metadata.dll_characteristics.length > 0 ? (
                    result.metadata.dll_characteristics.map((c) => (
                      <span
                        key={c}
                        className={[
                          "rounded-md px-2 py-0.5 text-xs",
                          c.includes("GUARD_CF") || c.includes("ASLR") || c.includes("DEP")
                            ? "bg-emerald-500/10 text-emerald-400"
                            : "bg-slate-800 text-slate-300",
                        ].join(" ")}
                      >
                        {c}
                      </span>
                    ))
                  ) : (
                    <span className="text-xs text-slate-500">None</span>
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* Suspicious APIs summary */}
          <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6 lg:col-span-3">
            <h3 className="mb-4 flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-slate-400">
              <AlertTriangle className="h-4 w-4 text-orange-400" /> Suspicious API Calls
            </h3>
            {result.suspicious_apis.length === 0 ? (
              <p className="text-sm text-slate-500">No suspicious API calls detected.</p>
            ) : (
              <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
                {Object.entries(suspiciousByCategory).map(([cat, apis]) => (
                  <div key={cat} className="rounded-xl border border-slate-800 bg-slate-950/40 p-4">
                    <div className="mb-2 flex items-center justify-between">
                      <span className="text-sm font-medium text-orange-400">{cat}</span>
                      <span className="text-xs text-slate-500">{apis.length}</span>
                    </div>
                    <div className="flex flex-wrap gap-1">
                      {apis.map((a) => (
                        <span
                          key={`${a.dll}:${a.name}`}
                          title={a.description}
                          className="rounded bg-red-500/10 px-1.5 py-0.5 font-mono text-xs text-red-300"
                        >
                          {a.name}
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {tab === "imports" && (
        <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6">
          <div className="space-y-2">
            {result.imports.map((imp) => (
              <div key={imp.dll} className="rounded-xl border border-slate-800 bg-slate-950/40">
                <button
                  onClick={() => setExpandedDll(expandedDll === imp.dll ? null : imp.dll)}
                  className="flex w-full items-center justify-between px-4 py-3 text-left"
                >
                  <div className="flex items-center gap-2">
                    {expandedDll === imp.dll ? (
                      <ChevronDown className="h-4 w-4 text-slate-500" />
                    ) : (
                      <ChevronRight className="h-4 w-4 text-slate-500" />
                    )}
                    <span className="font-mono text-sm text-slate-200">{imp.dll}</span>
                  </div>
                  <span className="text-xs text-slate-500">{imp.functions.length} functions</span>
                </button>
                {expandedDll === imp.dll && (
                  <div className="border-t border-slate-800 px-4 py-3">
                    <div className="flex flex-wrap gap-1.5">
                      {imp.functions.map((fn) => {
                        const isSusp = result.suspicious_apis.some((s) => s.name === fn && s.dll === imp.dll);
                        return (
                          <span
                            key={fn}
                            title={isSusp ? "Flagged as suspicious" : undefined}
                            className={[
                              "rounded px-2 py-0.5 font-mono text-xs",
                              isSusp
                                ? "bg-red-500/15 text-red-300 ring-1 ring-red-500/30"
                                : "bg-slate-800 text-slate-300",
                            ].join(" ")}
                          >
                            {fn}
                          </span>
                        );
                      })}
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {tab === "strings" && (
        <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6">
          <div className="mb-4 flex flex-wrap gap-2">
            {["URL", "File Path", "Command", "Registry Path", "IP Address", "Email", "File Reference", "Symbol", "Text"].map(
              (cat) => {
                const count = result.strings.filter((s) => s.category === cat).length;
                if (count === 0) return null;
                return (
                  <span key={cat} className="rounded-md bg-slate-800 px-2.5 py-1 text-xs text-slate-300">
                    {cat} ({count})
                  </span>
                );
              },
            )}
          </div>
          <div className="max-h-[600px] space-y-1 overflow-y-auto">
            {result.strings.map((s, i) => (
              <div
                key={i}
                className="flex items-center gap-3 rounded-lg px-3 py-2 transition-colors hover:bg-slate-800/40"
              >
                <span className="w-24 shrink-0 rounded bg-slate-800 px-2 py-0.5 text-center text-xs text-slate-400">
                  {s.category}
                </span>
                <span className="truncate font-mono text-sm text-slate-200" title={s.value}>
                  {s.value}
                </span>
                <span className="ml-auto shrink-0 text-xs text-slate-600">{s.length}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {tab === "sections" && (
        <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-800 text-left text-xs uppercase tracking-wide text-slate-500">
                  <th className="pb-3 pr-4 font-medium">Name</th>
                  <th className="pb-3 pr-4 font-medium">VAddr</th>
                  <th className="pb-3 pr-4 font-medium">VSize</th>
                  <th className="pb-3 pr-4 font-medium">Raw Size</th>
                  <th className="pb-3 pr-4 font-medium">Entropy</th>
                  <th className="pb-3 font-medium">Flags</th>
                </tr>
              </thead>
              <tbody>
                {result.sections.map((s) => (
                  <tr key={s.name} className="border-b border-slate-800/50">
                    <td className="py-3 pr-4 font-mono font-medium text-slate-200">{s.name}</td>
                    <td className="py-3 pr-4 font-mono text-slate-400">{hex(s.virtual_address)}</td>
                    <td className="py-3 pr-4 font-mono text-slate-400">{formatBytes(s.virtual_size)}</td>
                    <td className="py-3 pr-4 font-mono text-slate-400">{formatBytes(s.raw_size)}</td>
                    <td className="py-3 pr-4">
                      <span className={`font-mono font-medium ${ENTROPY_COLOR(s.entropy)}`}>{s.entropy.toFixed(2)}</span>
                    </td>
                    <td className="py-3">
                      <div className="flex flex-wrap gap-1">
                        {s.flags.map((f) => (
                          <span key={f} className="rounded bg-slate-800 px-1.5 py-0.5 text-xs text-slate-400">
                            {f}
                          </span>
                        ))}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="mt-4 flex items-center gap-4 text-xs text-slate-500">
            <span>Entropy scale:</span>
            <span className="text-emerald-400">&lt; 4.0 normal</span>
            <span className="text-yellow-400">4.0–6.5 moderate</span>
            <span className="text-orange-400">6.5–7.2 elevated</span>
            <span className="text-red-400">&ge; 7.2 likely packed</span>
          </div>
        </div>
      )}

      {tab === "cfg" && (
        <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6">
          <div className="mb-4 flex flex-wrap gap-4 text-sm">
            <span className="text-slate-400">
              Nodes: <span className="font-medium text-slate-200">{result.cfg.node_count}</span>
            </span>
            <span className="text-slate-400">
              Edges: <span className="font-medium text-slate-200">{result.cfg.edge_count}</span>
            </span>
            <span className="text-slate-400">
              Density: <span className="font-medium text-slate-200">{result.cfg.density}</span>
            </span>
            <span className="text-slate-400">
              Entry section: <span className="font-medium text-slate-200">{result.cfg.entry || "N/A"}</span>
            </span>
          </div>
          <CfgVisualizer cfg={result.cfg} />
        </div>
      )}

      {tab === "explanation" && (
        <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6">
          <div className="mb-4 flex items-center gap-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-gradient-to-br from-cyan-500/20 to-blue-500/20 ring-1 ring-cyan-500/30">
              <Sparkles className="h-4 w-4 text-cyan-400" />
            </div>
            <h3 className="text-sm font-semibold uppercase tracking-wide text-slate-400">
              AI-Generated Analysis
            </h3>
          </div>
          <div className="prose prose-invert max-w-none">
            {result.ai_explanation.split("\n\n").map((para, i) => (
              <p key={i} className="mb-3 text-sm leading-relaxed text-slate-300">
                {para}
              </p>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function MetaRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-2 border-b border-slate-800/50 py-1.5">
      <span className="text-sm text-slate-400">{label}</span>
      <span className="text-right font-mono text-sm text-slate-200">{value}</span>
    </div>
  );
}
