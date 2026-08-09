import { useCallback, useRef, useState } from "react";
import { UploadCloud, Binary, Loader2, AlertTriangle } from "lucide-react";

interface UploadZoneProps {
  onAnalyzed: (id: string) => void;
}

export function UploadZone({ onAnalyzed }: UploadZoneProps) {
  const [dragging, setDragging] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  const handleFile = useCallback(
    async (file: File) => {
      setError(null);
      setUploading(true);
      setProgress(0);

      const formData = new FormData();
      formData.append("file", file);

      try {
        const xhr = new XMLHttpRequest();
        xhr.open("POST", import.meta.env.VITE_SUPABASE_URL + "/functions/v1/analyze-pe");

        xhr.upload.onprogress = (e) => {
          if (e.lengthComputable) {
            setProgress(Math.round((e.loaded / e.total) * 100));
          }
        };

        xhr.onload = () => {
          setUploading(false);
          if (xhr.status >= 200 && xhr.status < 300) {
            try {
              const data = JSON.parse(xhr.responseText);
              if (data.id) {
                onAnalyzed(data.id);
              } else if (data.error) {
                setError(data.error);
              } else {
                setError("Unexpected response from server.");
              }
            } catch {
              setError("Failed to parse server response.");
            }
          } else {
            try {
              const data = JSON.parse(xhr.responseText);
              setError(data.error || `Upload failed (${xhr.status}).`);
            } catch {
              setError(`Upload failed (${xhr.status}).`);
            }
          }
        };

        xhr.onerror = () => {
          setUploading(false);
          setError("Network error during upload.");
        };

        xhr.send(formData);
      } catch (err) {
        setUploading(false);
        setError(err instanceof Error ? err.message : "Upload failed.");
      }
    },
    [onAnalyzed],
  );

  return (
    <div className="w-full">
      <div
        onClick={() => !uploading && inputRef.current?.click()}
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragging(false);
          const f = e.dataTransfer.files[0];
          if (f) handleFile(f);
        }}
        className={[
          "relative flex flex-col items-center justify-center gap-4 rounded-2xl border-2 border-dashed px-6 py-16 cursor-pointer transition-all duration-300",
          dragging
            ? "border-cyan-400 bg-cyan-500/5 scale-[1.01]"
            : "border-slate-700 hover:border-slate-600 hover:bg-slate-900/40",
          uploading ? "pointer-events-none opacity-70" : "",
        ].join(" ")}
      >
        <input
          ref={inputRef}
          type="file"
          accept=".exe,.dll,.sys,.ocx,.cpl,.scr"
          className="hidden"
          onChange={(e) => {
            const f = e.target.files?.[0];
            if (f) handleFile(f);
            e.target.value = "";
          }}
        />

        {!uploading && (
          <>
            <div className="flex h-16 w-16 items-center justify-center rounded-2xl bg-gradient-to-br from-cyan-500/20 to-blue-500/20 ring-1 ring-cyan-500/30">
              <UploadCloud className="h-8 w-8 text-cyan-400" />
            </div>
            <div className="text-center">
              <p className="text-lg font-semibold text-slate-100">Drop a binary here</p>
              <p className="mt-1 text-sm text-slate-400">
                or click to browse — .exe, .dll, .sys supported (max 16 MB)
              </p>
            </div>
          </>
        )}

        {uploading && (
          <>
            <Loader2 className="h-10 w-10 animate-spin text-cyan-400" />
            <div className="text-center">
              <p className="font-semibold text-slate-100">Analyzing binary…</p>
              <p className="mt-1 text-sm text-slate-400">{progress}% uploaded</p>
            </div>
            <div className="mt-2 h-1.5 w-64 overflow-hidden rounded-full bg-slate-700">
              <div
                className="h-full rounded-full bg-gradient-to-r from-cyan-500 to-blue-500 transition-all duration-200"
                style={{ width: `${progress}%` }}
              />
            </div>
          </>
        )}
      </div>

      {error && (
        <div className="mt-4 flex items-start gap-3 rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3">
          <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-red-400" />
          <div>
            <p className="text-sm font-medium text-red-300">Analysis failed</p>
            <p className="mt-0.5 text-sm text-red-200/80">{error}</p>
          </div>
        </div>
      )}

      {!uploading && !error && (
        <div className="mt-6 grid grid-cols-1 gap-3 sm:grid-cols-3">
          {[
            { icon: Binary, title: "PE Structure", desc: "Sections, headers & metadata" },
            { icon: UploadCloud, title: "Static Analysis", desc: "Imports, strings & entropy" },
            { icon: AlertTriangle, title: "Risk Scoring", desc: "Heuristic threat assessment" },
          ].map((f) => (
            <div
              key={f.title}
              className="flex items-start gap-3 rounded-xl border border-slate-800 bg-slate-900/40 p-4"
            >
              <f.icon className="mt-0.5 h-5 w-5 shrink-0 text-slate-400" />
              <div>
                <p className="text-sm font-medium text-slate-200">{f.title}</p>
                <p className="mt-0.5 text-xs text-slate-500">{f.desc}</p>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
