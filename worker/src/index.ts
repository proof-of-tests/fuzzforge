import verifierModule from "../generated/verifier.wasm";

export interface Env {
  DB: D1Database;
  WASM_BUCKET: R2Bucket;
}

interface HllRecord {
  schema_version: number;
  program_hash: string;
  precision: number;
  sketch: { registers: number[] };
  observations: StoredObservation[];
}

interface StoredObservation {
  seed_hex: string;
  observation_hash: string;
  verifier_version?: number;
}

interface BucketRow {
  program_hash: string;
  bucket_index: number;
  verifier_version: number;
  observation_hash: string;
  seed_hex: string;
}

const HASH_RE = /^[0-9a-f]{64}$/;
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
  ff_verify(wasmPtr: number, wasmLen: number, recordPtr: number, recordLen: number): number;
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

  await env.WASM_BUCKET.put(wasmKey(programHash), bytes, {
    httpMetadata: { contentType: "application/wasm" },
    customMetadata: { programHash },
  });

  return json({ program_hash: programHash, bytes: bytes.byteLength });
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

async function putProof(request: Request, env: Env, programHash: string): Promise<Response> {
  const record = validateHllRecord(await request.json(), programHash);
  const wasmObject = await env.WASM_BUCKET.get(wasmKey(programHash));
  if (wasmObject === null) {
    throw new HttpError(404, "wasm_not_found");
  }
  const wasm = await wasmObject.arrayBuffer();
  await verifyProof(wasm, record);

  const statements: D1PreparedStatement[] = [];

  for (const observation of record.observations) {
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
  }

  await env.DB.batch(statements);
  const proof = await loadProof(env, programHash);
  return json({
    program_hash: programHash,
    bucket_witnesses: proof.observations.length,
    estimated_observations: estimate(proof.sketch.registers),
    verified_observations: record.observations.length,
  });
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
    bucket_witnesses: proof.observations.length,
    estimated_observations: estimate(proof.sketch.registers),
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

function validateHllRecord(value: unknown, programHash: string): HllRecord {
  if (!isRecord(value)) {
    throw new HttpError(400, "invalid_proof");
  }
  const record = value as Partial<HllRecord>;
  if (record.program_hash !== programHash) {
    throw new HttpError(400, "program_hash_mismatch");
  }
  if (record.schema_version !== 2 || record.precision !== HLL_PRECISION) {
    throw new HttpError(400, "unsupported_hll_schema");
  }
  if (!isRecord(record.sketch) || !Array.isArray(record.sketch.registers)) {
    throw new HttpError(400, "invalid_hll_sketch");
  }
  if (record.sketch.registers.length !== HLL_BUCKETS) {
    throw new HttpError(400, "invalid_hll_bucket_count");
  }
  if (
    !record.sketch.registers.every(
      (rank) => Number.isInteger(rank) && rank >= 0 && rank <= 64,
    )
  ) {
    throw new HttpError(400, "invalid_hll_register");
  }
  if (!Array.isArray(record.observations)) {
    throw new HttpError(400, "invalid_observations");
  }
  for (const observation of record.observations) {
    if (!isRecord(observation)) {
      throw new HttpError(400, "invalid_observation");
    }
    if (
      typeof observation.seed_hex !== "string" ||
      typeof observation.observation_hash !== "string" ||
      !HASH_RE.test(observation.observation_hash)
    ) {
      throw new HttpError(400, "invalid_observation");
    }
  }
  return record as HllRecord;
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

async function verifyProof(wasm: ArrayBuffer, record: HllRecord): Promise<void> {
  const exports = await verifierExports();
  const wasmBytes = new Uint8Array(wasm);
  const recordBytes = new TextEncoder().encode(JSON.stringify(record));
  const wasmPtr = copyIntoVerifier(exports, wasmBytes);
  const recordPtr = copyIntoVerifier(exports, recordBytes);
  try {
    const code = exports.ff_verify(
      wasmPtr,
      wasmBytes.byteLength,
      recordPtr,
      recordBytes.byteLength,
    );
    if (code !== 0) {
      throw new HttpError(400, VERIFY_CODES[code] ?? "verifier_error");
    }
  } finally {
    exports.ff_dealloc(wasmPtr, wasmBytes.byteLength);
    exports.ff_dealloc(recordPtr, recordBytes.byteLength);
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
  const registers = Array.from({ length: HLL_BUCKETS }, () => 0);
  const observations: StoredObservation[] = [];
  for (const row of rows.results) {
    registers[row.bucket_index] = observationBucket(row.observation_hash).rank;
    observations.push({
      seed_hex: row.seed_hex,
      verifier_version: row.verifier_version,
      observation_hash: row.observation_hash,
    });
  }
  return {
    schema_version: 2,
    program_hash: programHash,
    precision: HLL_PRECISION,
    sketch: { registers },
    observations,
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
  response.headers.set("access-control-allow-headers", "content-type");
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
