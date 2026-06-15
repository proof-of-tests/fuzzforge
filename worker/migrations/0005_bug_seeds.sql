CREATE TABLE bug_seeds (
  program_hash TEXT NOT NULL,
  seed_hex TEXT NOT NULL,
  verifier_version INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (program_hash, seed_hex)
);

CREATE INDEX bug_seeds_program_created_idx ON bug_seeds(program_hash, created_at DESC);
