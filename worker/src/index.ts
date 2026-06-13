import verifierModule from "../generated/verifier.wasm";

export interface Env {
  DB: D1Database;
  WASM_BUCKET: R2Bucket;
  GITHUB_APP_CLIENT_ID?: string;
  GITHUB_API_BASE_URL?: string;
}

interface HllRecord {
  schema_version: number;
  program_hash: string;
  precision: number;
  buckets: Array<StoredObservation | null>;
}

interface StoredObservation {
  seed_hex: string;
  observation_hash: string;
  verifier_version: number;
}

interface BucketRow {
  program_hash: string;
  bucket_index: number;
  verifier_version: number;
  observation_hash: string;
  seed_hex: string;
}

interface ProgramRow {
  program_hash: string;
  github_repository: string | null;
  component_name: string | null;
  version: string | null;
  github_verified_by: string | null;
  github_verified_at: string | null;
  wasm_bytes: number;
  average_fuel_consumed: number | null;
  fuel_samples: number;
  created_at: string;
  updated_at: string;
}

interface ProgramListResponse {
  programs: ProgramRow[];
  next_cursor: string | null;
}

interface GitHubUser {
  login?: unknown;
}

interface GitHubRepository {
  permissions?: {
    admin?: unknown;
    push?: unknown;
  };
}

interface WasmMetadata {
  github_repository: string | null;
  component_name: string | null;
  version: string | null;
}

interface ProofVerificationReport {
  fuel_consumed: number;
}

const HASH_RE = /^[0-9a-f]{64}$/;
const SEED_RE = /^(?:[0-9a-f]{2})+$/;
const GITHUB_REPO_RE = /^[a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?\/[a-z0-9._-]{1,100}$/;
const SEMVER_RE =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/;
const HLL_PRECISION = 6;
const HLL_BUCKETS = 1 << HLL_PRECISION;
const MAX_STREAM_INTERVAL_MS = 10_000;
const CURRENT_VERIFIER_VERSION = 1;
const VERIFY_CODES: Record<number, string> = {
  1: "invalid_verifier_input",
  2: "invalid_proof",
  3: "wasm_hash_mismatch",
  4: "observation_verification_failed",
  5: "unsupported_wasm",
  9: "observation_hash_mismatch",
};

type VerifierExports = {
  memory: WebAssembly.Memory;
  ff_alloc(len: number): number;
  ff_dealloc(ptr: number, len: number): void;
  ff_hash_hex(wasmPtr: number, wasmLen: number, outPtr: number, outLen: number): number;
  ff_metadata(wasmPtr: number, wasmLen: number, outPtr: number, outLen: number): number;
  ff_estimate_fuel(wasmPtr: number, wasmLen: number, outPtr: number, outLen: number): number;
  ff_verify(
    wasmPtr: number,
    wasmLen: number,
    observationPtr: number,
    observationLen: number,
    outPtr: number,
    outLen: number,
  ): number;
};

let verifierPromise: Promise<VerifierExports> | undefined;

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (request.method === "OPTIONS") {
      return cors(new Response(null, { status: 204 }));
    }

    const url = new URL(request.url);
    const parts = url.pathname.split("/").filter(Boolean);

    try {
      if (request.method === "GET" && url.pathname === "/health") {
        return json({ ok: true });
      }

      if (request.method === "GET" && url.pathname === "/api/auth/github") {
        return json({ client_id: env.GITHUB_APP_CLIENT_ID ?? null });
      }

      if (parts[0] === "api" && parts[1] === "programs" && parts.length === 2) {
        if (request.method === "GET") {
          return await listPrograms(url, env);
        }
      }

      if (parts[0] === "api" && parts[1] === "programs" && parts.length === 3) {
        const programHash = normalizeProgramHash(parts[2]);
        if (request.method === "GET") {
          return await getProgram(env, programHash);
        }
      }

      if (parts[0] === "api" && parts[1] === "programs" && parts.length === 4) {
        const programHash = normalizeProgramHash(parts[2]);
        if (parts[3] === "wasm") {
          if (request.method === "PUT") {
            return await putWasm(request, env, programHash);
          }
          if (request.method === "GET") {
            return await getWasm(env, programHash);
          }
        }
        if (parts[3] === "proof") {
          if (request.method === "POST" || request.method === "PUT") {
            return await putProof(request, env, programHash);
          }
          if (request.method === "GET") {
            return await getProof(env, programHash);
          }
        }
        if (parts[3] === "stats" && request.method === "GET") {
          return await getStats(env, programHash);
        }
      }

      if (parts[0] === "api" && parts[1] === "hash-results" && parts.length === 2) {
        if (request.method === "GET") {
          return await listHashResults(url, env);
        }
      }

      if (
        parts[0] === "api" &&
        parts[1] === "hash-results" &&
        parts[2] === "stream" &&
        parts.length === 3 &&
        request.method === "GET"
      ) {
        return streamHashResults(request, url, env);
      }

      return json({ error: "not_found" }, { status: 404 });
    } catch (error) {
      if (error instanceof HttpError) {
        return json({ error: error.message }, { status: error.status });
      }
      console.error(error);
      return json({ error: "internal_error" }, { status: 500 });
    }
  },
};

async function putWasm(request: Request, env: Env, programHash: string): Promise<Response> {
  const bytes = await request.arrayBuffer();
  if (bytes.byteLength === 0) {
    throw new HttpError(400, "empty_wasm");
  }
  const actualHash = await hashWasm(bytes);
  if (actualHash !== programHash) {
    throw new HttpError(400, "wasm_hash_mismatch");
  }
  const metadata = await queryWasmMetadata(bytes);
  const fuelConsumed = await estimateInitialFuel(bytes);
  const githubRepository = metadata.github_repository;
  const githubVerifiedBy =
    githubRepository === null
      ? null
      : await verifyGitHubRepositoryAccess(request, env, githubRepository);

  await env.WASM_BUCKET.put(wasmKey(programHash), bytes, {
    httpMetadata: { contentType: "application/wasm" },
    customMetadata: wasmCustomMetadata(programHash, metadata),
  });

  const now = new Date().toISOString();
  await env.DB.prepare(
    `INSERT INTO programs (
      program_hash,
      github_repository,
      component_name,
      version,
      github_verified_by,
      github_verified_at,
      wasm_bytes,
      average_fuel_consumed,
      fuel_samples,
      created_at,
      updated_at
    )
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(program_hash) DO UPDATE SET
      github_repository = excluded.github_repository,
      component_name = excluded.component_name,
      version = excluded.version,
      github_verified_by = excluded.github_verified_by,
      github_verified_at = excluded.github_verified_at,
      wasm_bytes = excluded.wasm_bytes,
      average_fuel_consumed = CASE
        WHEN programs.fuel_samples = 0 THEN excluded.average_fuel_consumed
        ELSE programs.average_fuel_consumed
      END,
      fuel_samples = CASE
        WHEN programs.fuel_samples = 0 THEN excluded.fuel_samples
        ELSE programs.fuel_samples
      END,
      updated_at = excluded.updated_at`,
  )
    .bind(
      programHash,
      githubRepository,
      metadata.component_name,
      metadata.version,
      githubVerifiedBy,
      githubRepository === null ? null : now,
      bytes.byteLength,
      fuelConsumed,
      1,
      now,
      now,
    )
    .run();

  const row = await loadProgramRow(env, programHash);
  if (!row) {
    throw new HttpError(500, "program_not_stored");
  }
  return json({
    program_hash: programHash,
    bytes: bytes.byteLength,
    github_repository: row.github_repository,
    component_name: row.component_name,
    version: row.version,
    github_verified_by: row.github_verified_by,
    average_fuel_consumed: row.average_fuel_consumed,
    fuel_samples: row.fuel_samples,
  });
}

async function getWasm(env: Env, programHash: string): Promise<Response> {
  const object = await env.WASM_BUCKET.get(wasmKey(programHash));
  if (object === null) {
    throw new HttpError(404, "wasm_not_found");
  }

  const headers = new Headers();
  object.writeHttpMetadata(headers);
  headers.set("etag", object.httpEtag);
  headers.set("cache-control", "public, max-age=31536000, immutable");
  return cors(new Response(object.body, { headers }));
}

async function getProgram(env: Env, programHash: string): Promise<Response> {
  const row = await loadProgramRow(env, programHash);
  if (!row) {
    throw new HttpError(404, "program_not_found");
  }
  return json(row);
}

async function loadProgramRow(env: Env, programHash: string): Promise<ProgramRow | null> {
  return env.DB.prepare(
    `SELECT
      program_hash,
      github_repository,
      component_name,
      version,
      github_verified_by,
      github_verified_at,
      wasm_bytes,
      average_fuel_consumed,
      fuel_samples,
      created_at,
      updated_at
     FROM programs
     WHERE program_hash = ?`,
  )
    .bind(programHash)
    .first<ProgramRow>();
}

async function listPrograms(url: URL, env: Env): Promise<Response> {
  const limit = Math.min(parseNonNegativeInt(url.searchParams.get("limit"), 100), 1000);
  const associatedOnly = url.searchParams.get("associated") === "true";
  const cursor = url.searchParams.get("cursor");
  if (cursor !== null) {
    normalizeProgramHash(cursor);
  }

  const where: string[] = [];
  const binds: string[] = [];
  if (associatedOnly) {
    where.push("github_repository IS NOT NULL");
  }
  if (cursor !== null) {
    where.push("program_hash > ?");
    binds.push(cursor.toLowerCase());
  }

  const whereSql = where.length === 0 ? "" : `WHERE ${where.join(" AND ")}`;
  const result = await env.DB.prepare(
    `SELECT
      program_hash,
      github_repository,
      component_name,
      version,
      github_verified_by,
      github_verified_at,
      wasm_bytes,
      average_fuel_consumed,
      fuel_samples,
      created_at,
      updated_at
     FROM programs
     ${whereSql}
     ORDER BY program_hash ASC
     LIMIT ?`,
  )
    .bind(...binds, limit + 1)
    .all<ProgramRow>();

  const programs = result.results.slice(0, limit);
  const response: ProgramListResponse = {
    programs,
    next_cursor:
      result.results.length > limit ? programs[programs.length - 1]?.program_hash ?? null : null,
  };
  return json(response);
}

async function putProof(request: Request, env: Env, programHash: string): Promise<Response> {
  const observation = validateProofObservation(await request.json());
  const wasmObject = await env.WASM_BUCKET.get(wasmKey(programHash));
  if (wasmObject === null) {
    throw new HttpError(404, "wasm_not_found");
  }
  const wasm = await wasmObject.arrayBuffer();
  const verification = await verifyProof(wasm, observation);

  const statements: D1PreparedStatement[] = [
    fuelEstimateUpdateStatement(env, programHash, verification),
  ];
  const bucket = observationBucket(observation.observation_hash);
  statements.push(
    env.DB.prepare(
      `INSERT INTO hll_buckets (
        program_hash,
        bucket_index,
        verifier_version,
        observation_hash,
        seed_hex
      )
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(program_hash, bucket_index) DO UPDATE SET
        verifier_version = excluded.verifier_version,
        observation_hash = excluded.observation_hash,
        seed_hex = excluded.seed_hex
       WHERE excluded.observation_hash < hll_buckets.observation_hash`,
    ).bind(
      programHash,
      bucket.index,
      CURRENT_VERIFIER_VERSION,
      observation.observation_hash,
      observation.seed_hex,
    ),
  );

  await env.DB.batch(statements);
  const proof = await loadProof(env, programHash);
  const bucketWitnesses = proof.buckets.filter((bucket) => bucket !== null).length;
  return json({
    program_hash: programHash,
    bucket_witnesses: bucketWitnesses,
    estimated_observations: estimate(bucketsToRegisters(proof.buckets)),
    verified_observations: 1,
  });
}

function fuelEstimateUpdateStatement(
  env: Env,
  programHash: string,
  verification: ProofVerificationReport,
): D1PreparedStatement {
  return env.DB.prepare(
    `UPDATE programs
     SET
      average_fuel_consumed =
        ((COALESCE(average_fuel_consumed, 0) * fuel_samples) + ?) /
        (fuel_samples + 1),
      fuel_samples = fuel_samples + 1,
      updated_at = ?
     WHERE program_hash = ?`,
  )
    .bind(
      verification.fuel_consumed,
      new Date().toISOString(),
      programHash,
    );
}

async function getProof(env: Env, programHash: string): Promise<Response> {
  return json(await loadProof(env, programHash));
}

async function getStats(env: Env, programHash: string): Promise<Response> {
  const proof = await loadProof(env, programHash);
  return json({
    program_hash: proof.program_hash,
    schema_version: proof.schema_version,
    precision: proof.precision,
    buckets: HLL_BUCKETS,
    bucket_witnesses: proof.buckets.filter((bucket) => bucket !== null).length,
    estimated_observations: estimate(bucketsToRegisters(proof.buckets)),
  });
}

async function listHashResults(url: URL, env: Env): Promise<Response> {
  const limit = Math.min(parseNonNegativeInt(url.searchParams.get("limit"), 100), 1000);
  const rows = await env.DB.prepare(
    `SELECT program_hash, bucket_index, observation_hash, seed_hex
     FROM hll_buckets
     ORDER BY program_hash ASC, bucket_index ASC
     LIMIT ?`,
  )
    .bind(limit)
    .all();
  const total = await totalHllEstimate(env);
  return json({ total_tests: total, bucket_witnesses: rows.results });
}

function streamHashResults(request: Request, url: URL, env: Env): Response {
  const encoder = new TextEncoder();
  const intervalMs = Math.min(
    parseNonNegativeInt(url.searchParams.get("interval_ms"), 1000),
    MAX_STREAM_INTERVAL_MS,
  );

  const body = new ReadableStream({
    async start(controller) {
      let closed = false;
      request.signal.addEventListener("abort", () => {
        closed = true;
        try {
          controller.close();
        } catch {
          // The client may have already closed the stream.
        }
      });

      while (!closed) {
        const total = await totalHllEstimate(env);
        controller.enqueue(
          encoder.encode(
            sse("counter", { total_tests: total, timestamp_ms: Date.now() }),
          ),
        );

        await sleep(intervalMs);
      }
    },
  });

  return cors(
    new Response(body, {
      headers: {
        "content-type": "text/event-stream; charset=utf-8",
        "cache-control": "no-store",
        connection: "keep-alive",
      },
    }),
  );
}

function validateProofObservation(value: unknown): StoredObservation {
  if (!isRecord(value)) {
    throw new HttpError(400, "invalid_observation");
  }
  if (
    typeof value.seed_hex !== "string" ||
    typeof value.observation_hash !== "string" ||
    !SEED_RE.test(value.seed_hex) ||
    !HASH_RE.test(value.observation_hash) ||
    value.verifier_version !== CURRENT_VERIFIER_VERSION
  ) {
    throw new HttpError(400, "invalid_observation");
  }
  return {
    seed_hex: value.seed_hex,
    verifier_version: CURRENT_VERIFIER_VERSION,
    observation_hash: value.observation_hash,
  };
}

async function verifyGitHubRepositoryAccess(
  request: Request,
  env: Env,
  repository: string,
): Promise<string> {
  const token = bearerToken(request);
  if (token === null) {
    throw new HttpError(401, "github_auth_required");
  }

  const base = (env.GITHUB_API_BASE_URL ?? "https://api.github.com").replace(/\/+$/, "");
  const userResponse = await fetch(`${base}/user`, {
    headers: githubHeaders(token),
  });
  if (userResponse.status === 401 || userResponse.status === 403) {
    throw new HttpError(401, "github_auth_invalid");
  }
  if (!userResponse.ok) {
    throw new HttpError(401, "github_auth_invalid");
  }
  const user = (await userResponse.json()) as GitHubUser;
  if (typeof user.login !== "string" || user.login.length === 0) {
    throw new HttpError(401, "github_auth_invalid");
  }

  const [owner, repo] = repository.split("/");
  const repositoryResponse = await fetch(
    `${base}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`,
    { headers: githubHeaders(token) },
  );
  if (repositoryResponse.status === 401) {
    throw new HttpError(401, "github_auth_invalid");
  }
  if (repositoryResponse.status === 404) {
    throw new HttpError(403, "repository_access_denied");
  }
  if (!repositoryResponse.ok) {
    throw new HttpError(403, "repository_access_denied");
  }
  const githubRepository = (await repositoryResponse.json()) as GitHubRepository;
  if (
    githubRepository.permissions?.admin !== true &&
    githubRepository.permissions?.push !== true
  ) {
    throw new HttpError(403, "repository_access_denied");
  }

  return user.login;
}

async function queryWasmMetadata(wasm: ArrayBuffer): Promise<WasmMetadata> {
  const exports = await verifierExports();
  const wasmBytes = new Uint8Array(wasm);
  const wasmPtr = copyIntoVerifier(exports, wasmBytes);
  const outLen = 4096;
  const outPtr = exports.ff_alloc(outLen);
  try {
    const len = exports.ff_metadata(wasmPtr, wasmBytes.byteLength, outPtr, outLen);
    if (len < 0) {
      throw new HttpError(400, VERIFY_CODES[-len] ?? "metadata_query_failed");
    }
    if (len === 0) {
      return { github_repository: null, component_name: null, version: null };
    }
    const metadata = new TextDecoder().decode(
      new Uint8Array(exports.memory.buffer, outPtr, len),
    );
    return parseWasmMetadata(metadata);
  } finally {
    exports.ff_dealloc(wasmPtr, wasmBytes.byteLength);
    exports.ff_dealloc(outPtr, outLen);
  }
}

async function estimateInitialFuel(wasm: ArrayBuffer): Promise<number> {
  const exports = await verifierExports();
  const wasmBytes = new Uint8Array(wasm);
  const wasmPtr = copyIntoVerifier(exports, wasmBytes);
  const outLen = 8;
  const outPtr = exports.ff_alloc(outLen);
  try {
    const code = exports.ff_estimate_fuel(wasmPtr, wasmBytes.byteLength, outPtr, outLen);
    if (code !== 0) {
      throw new HttpError(400, VERIFY_CODES[code] ?? "fuel_estimate_failed");
    }
    const fuelConsumed = new DataView(exports.memory.buffer, outPtr, outLen).getBigUint64(
      0,
      true,
    );
    if (fuelConsumed > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new HttpError(400, "fuel_estimate_too_large");
    }
    return Number(fuelConsumed);
  } finally {
    exports.ff_dealloc(wasmPtr, wasmBytes.byteLength);
    exports.ff_dealloc(outPtr, outLen);
  }
}

function parseWasmMetadata(value: string): WasmMetadata {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new HttpError(400, "invalid_wasm_metadata");
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new HttpError(400, "invalid_wasm_metadata");
  }

  const raw = parsed as Record<string, unknown>;
  const githubRepository = optionalString(raw.github_repository, "invalid_wasm_repository");
  const componentName = optionalString(raw.component_name, "invalid_wasm_component_name");
  const version = optionalString(raw.version, "invalid_wasm_version");
  if (version !== null && !SEMVER_RE.test(version)) {
    throw new HttpError(400, "invalid_wasm_version");
  }

  return {
    github_repository:
      githubRepository === null || githubRepository.trim() === ""
        ? null
        : normalizeGitHubRepository(githubRepository),
    component_name: componentName,
    version,
  };
}

function optionalString(value: unknown, error: string): string | null {
  if (value === undefined || value === null) {
    return null;
  }
  if (typeof value !== "string") {
    throw new HttpError(400, error);
  }
  return value;
}

function wasmCustomMetadata(programHash: string, metadata: WasmMetadata): Record<string, string> {
  return Object.fromEntries(
    Object.entries({
      programHash,
      githubRepository: metadata.github_repository,
      componentName: metadata.component_name,
      version: metadata.version,
    }).filter((entry): entry is [string, string] => entry[1] !== null),
  );
}

function githubHeaders(token: string): HeadersInit {
  return {
    accept: "application/vnd.github+json",
    authorization: `Bearer ${token}`,
    "user-agent": "fuzzforge-worker",
    "x-github-api-version": "2026-03-10",
  };
}

function bearerToken(request: Request): string | null {
  const authorization = request.headers.get("authorization");
  const match = authorization?.match(/^Bearer\s+(.+)$/i);
  return match ? match[1].trim() : null;
}

function normalizeGitHubRepository(value: string): string {
  const repository = value.trim().toLowerCase();
  const repo = repository.split("/")[1] ?? "";
  if (!GITHUB_REPO_RE.test(repository) || repo === "." || repo === "..") {
    throw new HttpError(400, "invalid_wasm_repository");
  }
  return repository;
}

async function hashWasm(wasm: ArrayBuffer): Promise<string> {
  const exports = await verifierExports();
  const wasmBytes = new Uint8Array(wasm);
  const wasmPtr = copyIntoVerifier(exports, wasmBytes);
  const outPtr = exports.ff_alloc(64);
  try {
    const code = exports.ff_hash_hex(wasmPtr, wasmBytes.byteLength, outPtr, 64);
    if (code !== 0) {
      throw new HttpError(400, VERIFY_CODES[code] ?? "verifier_error");
    }
    return new TextDecoder().decode(
      new Uint8Array(exports.memory.buffer, outPtr, 64),
    );
  } finally {
    exports.ff_dealloc(wasmPtr, wasmBytes.byteLength);
    exports.ff_dealloc(outPtr, 64);
  }
}

async function verifyProof(
  wasm: ArrayBuffer,
  observation: StoredObservation,
): Promise<ProofVerificationReport> {
  const exports = await verifierExports();
  const wasmBytes = new Uint8Array(wasm);
  const observationBytes = new TextEncoder().encode(JSON.stringify(observation));
  const wasmPtr = copyIntoVerifier(exports, wasmBytes);
  const observationPtr = copyIntoVerifier(exports, observationBytes);
  const outLen = 8;
  const outPtr = exports.ff_alloc(outLen);
  try {
    const code = exports.ff_verify(
      wasmPtr,
      wasmBytes.byteLength,
      observationPtr,
      observationBytes.byteLength,
      outPtr,
      outLen,
    );
    if (code !== 0) {
      throw new HttpError(400, VERIFY_CODES[code] ?? "verifier_error");
    }
    const view = new DataView(exports.memory.buffer, outPtr, outLen);
    const fuelConsumed = view.getBigUint64(0, true);
    if (fuelConsumed > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new HttpError(400, "proof_fuel_too_large");
    }
    return {
      fuel_consumed: Number(fuelConsumed),
    };
  } finally {
    exports.ff_dealloc(wasmPtr, wasmBytes.byteLength);
    exports.ff_dealloc(observationPtr, observationBytes.byteLength);
    exports.ff_dealloc(outPtr, outLen);
  }
}

function copyIntoVerifier(exports: VerifierExports, bytes: Uint8Array): number {
  const ptr = exports.ff_alloc(bytes.byteLength);
  new Uint8Array(exports.memory.buffer, ptr, bytes.byteLength).set(bytes);
  return ptr;
}

async function verifierExports(): Promise<VerifierExports> {
  verifierPromise ??= WebAssembly.instantiate(verifierModule).then(
    (instance) => instance.exports as VerifierExports,
  );
  return verifierPromise;
}

async function loadProof(env: Env, programHash: string): Promise<HllRecord> {
  const rows = await env.DB.prepare(
    `SELECT
      program_hash,
      bucket_index,
      verifier_version,
      observation_hash,
      seed_hex
     FROM hll_buckets
     WHERE program_hash = ?
     ORDER BY bucket_index ASC`,
  )
    .bind(programHash)
    .all<BucketRow>();
  if (rows.results.length === 0) {
    throw new HttpError(404, "proof_not_found");
  }
  const buckets: Array<StoredObservation | null> = Array.from(
    { length: HLL_BUCKETS },
    () => null,
  );
  for (const row of rows.results) {
    buckets[row.bucket_index] = {
      seed_hex: row.seed_hex,
      verifier_version: row.verifier_version,
      observation_hash: row.observation_hash,
    };
  }
  return {
    schema_version: 2,
    program_hash: programHash,
    precision: HLL_PRECISION,
    buckets,
  };
}

function observationBucket(observationHash: string): { index: number; rank: number } {
  const value = BigInt(`0x${observationHash.slice(0, 16)}`);
  const index = Number(value >> BigInt(64 - HLL_PRECISION));
  const remaining = (value << BigInt(HLL_PRECISION)) & ((1n << 64n) - 1n);
  const maxRank = 64 - HLL_PRECISION + 1;
  const rank =
    remaining === 0n
      ? maxRank
      : Math.min(64 - remaining.toString(2).length + 1, maxRank);
  return { index, rank };
}

function estimate(registers: number[]): number {
  const m = HLL_BUCKETS;
  const sum = registers.reduce((total, rank) => total + 2 ** -rank, 0);
  const raw = alpha(m) * m * m / sum;
  const zeros = registers.filter((rank) => rank === 0).length;
  if (raw <= 2.5 * m && zeros > 0) {
    return m * Math.log(m / zeros);
  }
  return raw;
}

function bucketsToRegisters(buckets: Array<StoredObservation | null>): number[] {
  const registers = Array.from({ length: HLL_BUCKETS }, () => 0);
  for (const observation of buckets) {
    if (observation === null) {
      continue;
    }
    const bucket = observationBucket(observation.observation_hash);
    registers[bucket.index] = bucket.rank;
  }
  return registers;
}

function alpha(bucketCount: number): number {
  switch (bucketCount) {
    case 16:
      return 0.673;
    case 32:
      return 0.697;
    case 64:
      return 0.709;
    default:
      return 0.7213 / (1 + 1.079 / bucketCount);
  }
}

async function totalHllEstimate(env: Env): Promise<number> {
  const rows = await env.DB.prepare(
    "SELECT program_hash, observation_hash FROM hll_buckets ORDER BY program_hash ASC",
  ).all<{ program_hash: string; observation_hash: string }>();
  const registersByProgram = new Map<string, number[]>();
  for (const row of rows.results) {
    let registers = registersByProgram.get(row.program_hash);
    if (!registers) {
      registers = Array.from({ length: HLL_BUCKETS }, () => 0);
      registersByProgram.set(row.program_hash, registers);
    }
    const bucket = observationBucket(row.observation_hash);
    registers[bucket.index] = bucket.rank;
  }
  let total = 0;
  for (const registers of registersByProgram.values()) {
    total += estimate(registers);
  }
  return total;
}

function normalizeProgramHash(value: string): string {
  const programHash = value.toLowerCase();
  if (!HASH_RE.test(programHash)) {
    throw new HttpError(400, "invalid_program_hash");
  }
  return programHash;
}

function wasmKey(programHash: string): string {
  return `wasm/${programHash}.wasm`;
}

function parseNonNegativeInt(value: string | null, fallback: number): number {
  if (value === null) {
    return fallback;
  }
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : fallback;
}

function sse(event: string, data: unknown, id?: number): string {
  const fields = [];
  if (id !== undefined) {
    fields.push(`id: ${id}`);
  }
  fields.push(`event: ${event}`);
  fields.push(`data: ${JSON.stringify(data)}`);
  return `${fields.join("\n")}\n\n`;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function json(value: unknown, init: ResponseInit = {}): Response {
  const headers = new Headers(init.headers);
  headers.set("content-type", "application/json; charset=utf-8");
  return cors(new Response(JSON.stringify(value), { ...init, headers }));
}

function cors(response: Response): Response {
  response.headers.set("access-control-allow-origin", "*");
  response.headers.set("access-control-allow-methods", "GET, PUT, POST, OPTIONS");
  response.headers.set("access-control-allow-headers", "authorization, content-type");
  return response;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

class HttpError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}
