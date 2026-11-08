-- Pending OAuth handshakes (the API Indonesia key is held here, encrypted, until the OAuth callback finishes)
CREATE TABLE IF NOT EXISTS pending (
  state TEXT PRIMARY KEY,
  kind TEXT NOT NULL,            -- 'notion' | 'linear'
  api_key_enc TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS notion_installs (
  id TEXT PRIMARY KEY,           -- Notion bot_id
  workspace_id TEXT,
  workspace_name TEXT,
  access_token_enc TEXT NOT NULL,
  api_key_enc TEXT NOT NULL,
  page_id TEXT,
  database_id TEXT,
  backlog INTEGER NOT NULL DEFAULT 1,
  last_sync INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS notion_rows (
  install_id TEXT NOT NULL,
  holiday_id TEXT NOT NULL,
  page_id TEXT,
  PRIMARY KEY (install_id, holiday_id)
);

CREATE TABLE IF NOT EXISTS linear_installs (
  id TEXT PRIMARY KEY,           -- Linear organization id
  org_name TEXT,
  org_key TEXT,
  access_token_enc TEXT NOT NULL,
  refresh_token_enc TEXT,
  expires_at INTEGER,
  api_key_enc TEXT NOT NULL,
  team_id TEXT,
  team_name TEXT,
  label_id TEXT,
  days_ahead INTEGER NOT NULL DEFAULT 14,
  backlog INTEGER NOT NULL DEFAULT 1,
  last_sync INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS linear_issues (
  install_id TEXT NOT NULL,
  holiday_id TEXT NOT NULL,
  issue_id TEXT,
  issue_identifier TEXT,
  PRIMARY KEY (install_id, holiday_id)
);
