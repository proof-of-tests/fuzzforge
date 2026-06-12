CREATE TABLE hll_buckets (
  program_hash TEXT NOT NULL,
  bucket_index INTEGER NOT NULL,
  verifier_version INTEGER NOT NULL,
  observation_hash TEXT NOT NULL,
  seed_hex TEXT NOT NULL,
  PRIMARY KEY (program_hash, bucket_index)
);

CREATE INDEX hll_buckets_program_hash_idx ON hll_buckets(program_hash);
