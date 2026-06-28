CREATE TABLE users (
  id uuid PRIMARY KEY,
  email text NOT NULL UNIQUE,
  password_hash text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE runs (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  workflow_id text NOT NULL UNIQUE,
  apk_filename text NOT NULL,
  apk_sha256 text NOT NULL,
  apk_size_bytes bigint NOT NULL,
  artifact_root text NOT NULL,
  status text NOT NULL,
  message text,
  started_at timestamptz,
  finished_at timestamptz,
  duration_ms bigint,
  report_html_key text,
  report_sarif_key text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE run_nodes (
  run_id uuid NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  node_id text NOT NULL,
  label text NOT NULL,
  kind text NOT NULL,
  state text NOT NULL,
  message text,
  queued_at timestamptz,
  started_at timestamptz,
  finished_at timestamptz,
  duration_ms bigint,
  finding_count integer NOT NULL DEFAULT 0,
  severity_counts jsonb NOT NULL DEFAULT '{}'::jsonb,
  metrics jsonb NOT NULL DEFAULT '{}'::jsonb,
  diagnostics jsonb NOT NULL DEFAULT '[]'::jsonb,
  artifacts jsonb NOT NULL DEFAULT '[]'::jsonb,
  error jsonb,
  findings_keys jsonb NOT NULL DEFAULT '[]'::jsonb,
  findings_ingested boolean NOT NULL DEFAULT false,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (run_id, node_id)
);

CREATE TABLE findings (
  id uuid PRIMARY KEY,
  run_id uuid NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
  node_id text,
  analyzer text NOT NULL,
  rule_id text,
  vulnerability_class text,
  severity text NOT NULL,
  message text NOT NULL,
  cwe text,
  owasp_mobile text,
  source_file text,
  source_line integer,
  sink_file text,
  sink_line integer,
  raw_json jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (run_id, node_id) REFERENCES run_nodes(run_id, node_id) ON DELETE CASCADE
);

CREATE INDEX idx_runs_user_created_at ON runs(user_id, created_at DESC);
CREATE INDEX idx_runs_status_updated_at ON runs(status, updated_at DESC);
CREATE INDEX idx_run_nodes_state ON run_nodes(state);
CREATE INDEX idx_run_nodes_run_state ON run_nodes(run_id, state);
CREATE INDEX idx_findings_run ON findings(run_id);
CREATE INDEX idx_findings_run_severity ON findings(run_id, severity);
