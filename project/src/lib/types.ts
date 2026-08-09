export interface PeMetadata {
  machine: string;
  machine_raw: number;
  number_of_sections: number;
  timestamp: number;
  timestamp_human: string | null;
  entry_point: number;
  image_base: number;
  subsystem: string;
  subsystem_raw: number;
  characteristics: string[];
  dll_characteristics: string[];
  is_dll: boolean;
  is_64bit: boolean;
  size_of_image: number;
  size_of_headers: number;
}

export interface ParsedImport {
  dll: string;
  functions: string[];
}

export interface SuspiciousApi {
  name: string;
  dll: string;
  category: string;
  description: string;
  weight: number;
}

export interface ExtractedString {
  value: string;
  length: number;
  category: string;
}

export interface PeSection {
  name: string;
  virtual_size: number;
  virtual_address: number;
  raw_size: number;
  raw_offset: number;
  entropy: number;
  flags: string[];
}

export interface CfgNode {
  id: string;
  label: string;
  type: "entry" | "section" | "dll" | "suspicious";
}

export interface CfgEdge {
  from: string;
  to: string;
}

export interface CfgData {
  nodes: CfgNode[];
  edges: CfgEdge[];
  node_count: number;
  edge_count: number;
  density: number;
  entry: string | null;
}

export type RiskLevel = "low" | "medium" | "high" | "critical";

export interface AnalysisResult {
  id: string;
  created_at: string;
  file_name: string;
  file_size: number;
  file_hash: string;
  risk_score: number;
  risk_level: RiskLevel;
  metadata: PeMetadata;
  imports: ParsedImport[];
  suspicious_apis: SuspiciousApi[];
  strings: ExtractedString[];
  sections: PeSection[];
  cfg: CfgData;
  ai_explanation: string;
}

export interface AnalysisSummary {
  id: string;
  file_name: string;
  file_size: number;
  risk_score: number;
  risk_level: RiskLevel;
  created_at: string;
}
