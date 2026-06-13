CREATE TABLE programs (
  program_hash TEXT PRIMARY KEY,
  github_repository TEXT,
  github_verified_by TEXT,
  github_verified_at TEXT,
  wasm_bytes INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX programs_github_repository_idx ON programs(github_repository);
