/*
# Create analyses table (single-tenant, no auth)

1. New Tables
- `analyses` — stores each binary analysis report.
  - `id` (uuid, primary key)
  - `file_name` (text, not null) — original uploaded file name
  - `file_size` (bigint, not null) — size in bytes
  - `file_hash` (text, not null) — SHA-256 of the binary for dedup
  - `risk_score` (int, not null) — 0-100 aggregate risk score
  - `risk_level` (text, not null) — low | medium | high | critical
  - `metadata` (jsonb) — PE header metadata (machine, subsystem, timestamp, entry point, etc.)
  - `imports` (jsonb) — array of imported DLLs and their functions
  - `suspicious_apis` (jsonb) — array of flagged API calls with category and description
  - `strings` (jsonb) — array of extracted strings (value, length, category)
  - `sections` (jsonb) — array of PE sections (name, vaddr, vsize, raw size, entropy, flags)
  - `cfg` (jsonb) — control flow graph data (nodes, edges, summary)
  - `ai_explanation` (text) — AI-generated plain-language explanation
  - `created_at` (timestamptz, default now())
2. Security
- Enable RLS on `analyses`.
- Single-tenant app (no sign-in) → allow anon + authenticated CRUD because data is intentionally shared/public.
3. Indexes
- Index on `file_hash` for dedup lookups.
- Index on `created_at` desc for history listing.
*/

CREATE TABLE IF NOT EXISTS analyses (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  file_name text NOT NULL,
  file_size bigint NOT NULL,
  file_hash text NOT NULL,
  risk_score int NOT NULL DEFAULT 0,
  risk_level text NOT NULL DEFAULT 'low',
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  imports jsonb NOT NULL DEFAULT '[]'::jsonb,
  suspicious_apis jsonb NOT NULL DEFAULT '[]'::jsonb,
  strings jsonb NOT NULL DEFAULT '[]'::jsonb,
  sections jsonb NOT NULL DEFAULT '[]'::jsonb,
  cfg jsonb NOT NULL DEFAULT '{}'::jsonb,
  ai_explanation text,
  created_at timestamptz DEFAULT now()
);

ALTER TABLE analyses ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "anon_select_analyses" ON analyses;
CREATE POLICY "anon_select_analyses" ON analyses FOR SELECT
  TO anon, authenticated USING (true);

DROP POLICY IF EXISTS "anon_insert_analyses" ON analyses;
CREATE POLICY "anon_insert_analyses" ON analyses FOR INSERT
  TO anon, authenticated WITH CHECK (true);

DROP POLICY IF EXISTS "anon_update_analyses" ON analyses;
CREATE POLICY "anon_update_analyses" ON analyses FOR UPDATE
  TO anon, authenticated USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS "anon_delete_analyses" ON analyses;
CREATE POLICY "anon_delete_analyses" ON analyses FOR DELETE
  TO anon, authenticated USING (true);

CREATE INDEX IF NOT EXISTS idx_analyses_file_hash ON analyses (file_hash);
CREATE INDEX IF NOT EXISTS idx_analyses_created_at ON analyses (created_at DESC);