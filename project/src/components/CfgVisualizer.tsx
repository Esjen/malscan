import { useMemo } from "react";
import type { CfgData } from "@/lib/types";

interface CfgVisualizerProps {
  cfg: CfgData;
}

const NODE_STYLE: Record<string, { fill: string; stroke: string; text: string }> = {
  entry: { fill: "rgba(6,182,212,0.15)", stroke: "#06b6d4", text: "#67e8f9" },
  section: { fill: "rgba(59,130,246,0.12)", stroke: "#3b82f6", text: "#93c5fd" },
  dll: { fill: "rgba(168,85,247,0.10)", stroke: "#a855f7", text: "#c4b5fd" },
  suspicious: { fill: "rgba(239,68,68,0.15)", stroke: "#ef4444", text: "#fca5a5" },
};

export function CfgVisualizer({ cfg }: CfgVisualizerProps) {
  const layout = useMemo(() => {
    const w = 880;
    const h = Math.max(360, cfg.nodes.length * 28);
    const nodes = cfg.nodes.map((node, i) => {
      // Group by type into columns
      let col = 0;
      if (node.type === "entry") col = 0;
      else if (node.type === "section") col = 1;
      else if (node.type === "dll") col = 2;
      else col = 3;

      const colCount = [1, 0, 0, 0];
      // count per column
      const counts: Record<number, number> = { 0: 0, 1: 0, 2: 0, 3: 0 };
      for (const n of cfg.nodes) {
        let c = 0;
        if (n.type === "entry") c = 0;
        else if (n.type === "section") c = 1;
        else if (n.type === "dll") c = 2;
        else c = 3;
        counts[c]++;
      }

      const colWidth = w / 4;
      const x = col * colWidth + colWidth / 2;
      const itemsInCol = counts[col];
      const spacing = Math.min(60, (h - 40) / Math.max(itemsInCol, 1));
      const y = 30 + (i % itemsInCol) * spacing + 20;
      void colCount;
      return { ...node, x, y };
    });

    const nodeMap = new Map(nodes.map((n) => [n.id, n]));
    const edges = cfg.edges
      .map((e) => {
        const from = nodeMap.get(e.from);
        const to = nodeMap.get(e.to);
        if (!from || !to) return null;
        return { ...e, x1: from.x, y1: from.y, x2: to.x, y2: to.y };
      })
      .filter(Boolean);

    return { nodes, edges, w, h };
  }, [cfg]);

  return (
    <div className="overflow-x-auto">
      <svg width={layout.w} height={layout.h} className="mx-auto">
        <defs>
          <marker
            id="cfg-arrow"
            markerWidth="8"
            markerHeight="6"
            refX="8"
            refY="3"
            orient="auto"
          >
            <path d="M0,0 L8,3 L0,6 Z" fill="#475569" />
          </marker>
        </defs>

        {layout.edges.map((edge, i) => {
          if (!edge) return null;
          const dx = edge.x2 - edge.x1;
          const dy = edge.y2 - edge.y1;
          const len = Math.sqrt(dx * dx + dy * dy) || 1;
          const offset = 22;
          const x1 = edge.x1 + (dx / len) * offset;
          const y1 = edge.y1 + (dy / len) * offset;
          const x2 = edge.x2 - (dx / len) * offset;
          const y2 = edge.y2 - (dy / len) * offset;
          const isSuspicious = edge.to.startsWith("api:");
          return (
            <path
              key={i}
              d={`M ${x1} ${y1} Q ${(x1 + x2) / 2} ${Math.min(y1, y2) - 20} ${x2} ${y2}`}
              fill="none"
              stroke={isSuspicious ? "#ef444460" : "#334155"}
              strokeWidth={isSuspicious ? 1.5 : 1}
              markerEnd="url(#cfg-arrow)"
              opacity={0.6}
            />
          );
        })}

        {layout.nodes.map((node) => {
          const style = NODE_STYLE[node.type] || NODE_STYLE.section;
          const labelW = Math.max(node.label.length * 6.5 + 16, 70);
          return (
            <g key={node.id} transform={`translate(${node.x}, ${node.y})`}>
              <rect
                x={-labelW / 2}
                y={-13}
                width={labelW}
                height={26}
                rx={6}
                fill={style.fill}
                stroke={style.stroke}
                strokeWidth={1.5}
              />
              <text
                x={0}
                y={4}
                textAnchor="middle"
                fontSize={11}
                fill={style.text}
                fontFamily="monospace"
              >
                {node.label.length > 22 ? node.label.slice(0, 21) + "…" : node.label}
              </text>
            </g>
          );
        })}
      </svg>

      <div className="mt-3 flex flex-wrap justify-center gap-4 text-xs">
        {[
          { label: "Entry", color: "#06b6d4" },
          { label: "Section", color: "#3b82f6" },
          { label: "Imported DLL", color: "#a855f7" },
          { label: "Suspicious API", color: "#ef4444" },
        ].map((l) => (
          <div key={l.label} className="flex items-center gap-1.5">
            <span className="h-2.5 w-2.5 rounded-sm" style={{ background: l.color }} />
            <span className="text-slate-400">{l.label}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
