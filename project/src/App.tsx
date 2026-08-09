import { useEffect, useState } from "react";
import { Shield, Menu, X, Zap } from "lucide-react";
import { supabase } from "@/lib/supabase";
import type { AnalysisResult } from "@/lib/types";
import { UploadZone } from "@/components/UploadZone";
import { AnalysisDashboard } from "@/components/AnalysisDashboard";
import { HistorySidebar } from "@/components/HistorySidebar";

type View = "upload" | "report";

export default function App() {
  const [view, setView] = useState<View>("upload");
  const [currentId, setCurrentId] = useState<string | null>(null);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [loadingReport, setLoadingReport] = useState(false);
  const [historyRefresh, setHistoryRefresh] = useState(0);
  const [sidebarOpen, setSidebarOpen] = useState(false);

  const loadReport = async (id: string) => {
    if (!id) {
      setView("upload");
      setCurrentId(null);
      setResult(null);
      return;
    }
    setLoadingReport(true);
    const { data } = await supabase.from("analyses").select("*").eq("id", id).maybeSingle();
    setLoadingReport(false);
    if (data) {
      setResult(data as AnalysisResult);
      setCurrentId(id);
      setView("report");
    }
  };

  const handleAnalyzed = (id: string) => {
    setHistoryRefresh((k) => k + 1);
    loadReport(id);
  };

  const handleNewScan = () => {
    setView("upload");
    setCurrentId(null);
    setResult(null);
  };

  const handleSelect = (id: string) => {
    setSidebarOpen(false);
    loadReport(id);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      {/* Header */}
      <header className="sticky top-0 z-30 border-b border-slate-800 bg-slate-950/90 backdrop-blur">
        <div className="flex items-center justify-between px-4 py-3 sm:px-6">
          <div className="flex items-center gap-3">
            <button
              onClick={() => setSidebarOpen((o) => !o)}
              className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-800 hover:text-slate-200 lg:hidden"
            >
              {sidebarOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
            </button>
            <div className="flex items-center gap-2.5">
              <div className="relative flex h-9 w-9 items-center justify-center rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600">
                <Shield className="h-5 w-5 text-white" />
                <div className="absolute -bottom-0.5 -right-0.5 h-3 w-3 rounded-full bg-emerald-400 ring-2 ring-slate-950" />
              </div>
              <div>
                <h1 className="text-base font-bold tracking-tight">MalScan</h1>
                <p className="text-xs text-slate-500">Static PE Analysis Engine</p>
              </div>
            </div>
          </div>
          <a
            href="https://bolt.new"
            target="_blank"
            rel="noreferrer"
            className="hidden items-center gap-1.5 rounded-lg border border-slate-800 px-3 py-1.5 text-xs text-slate-400 transition-colors hover:border-slate-700 hover:text-slate-200 sm:flex"
          >
            <Zap className="h-3.5 w-3.5" />
            Powered by Bolt
          </a>
        </div>
      </header>

      <div className="flex">
        {/* Sidebar */}
        <aside
          className={[
            "fixed inset-y-0 left-0 top-[57px] z-20 w-72 border-r border-slate-800 bg-slate-900/95 transition-transform duration-200 lg:sticky lg:top-[57px] lg:translate-x-0",
            sidebarOpen ? "translate-x-0" : "-translate-x-full",
          ].join(" ")}
          style={{ height: "calc(100vh - 57px)" }}
        >
          <HistorySidebar
            selectedId={currentId}
            onSelect={handleSelect}
            refreshKey={historyRefresh}
          />
        </aside>

        {sidebarOpen && (
          <div
            onClick={() => setSidebarOpen(false)}
            className="fixed inset-0 top-[57px] z-10 bg-black/50 lg:hidden"
          />
        )}

        {/* Main */}
        <main className="min-w-0 flex-1">
          {view === "upload" && (
            <div className="mx-auto max-w-3xl px-4 py-12 sm:px-6">
              <div className="mb-10 text-center">
                <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-cyan-500/20 bg-cyan-500/5 px-3 py-1 text-xs font-medium text-cyan-400">
                  <Shield className="h-3.5 w-3.5" />
                  Static Malware Analysis
                </div>
                <h2 className="text-3xl font-bold tracking-tight sm:text-4xl">
                  Analyze suspicious binaries
                </h2>
                <p className="mx-auto mt-3 max-w-xl text-slate-400">
                  Upload a Windows executable and get an instant breakdown of its imports, strings,
                  PE structure, entropy, and a heuristic risk score — all processed in a secure
                  sandbox.
                </p>
              </div>
              <UploadZone onAnalyzed={handleAnalyzed} />
            </div>
          )}

          {view === "report" && loadingReport && (
            <div className="flex h-96 items-center justify-center">
              <div className="flex flex-col items-center gap-3">
                <div className="h-8 w-8 animate-spin rounded-full border-2 border-slate-700 border-t-cyan-400" />
                <p className="text-sm text-slate-400">Loading report…</p>
              </div>
            </div>
          )}

          {view === "report" && !loadingReport && result && (
            <div className="mx-auto max-w-6xl px-4 py-6 sm:px-6">
              <AnalysisDashboard result={result} onNewScan={handleNewScan} />
            </div>
          )}

          {view === "report" && !loadingReport && !result && (
            <div className="flex h-96 items-center justify-center">
              <p className="text-sm text-slate-400">Report not found.</p>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}
