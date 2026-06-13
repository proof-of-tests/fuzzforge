import { SELF, env, fetchMock } from "cloudflare:test";
import { afterEach, beforeAll, beforeEach, describe, expect, test } from "vitest";

const PROGRAM_HASH = "a2840b47184016de26d91be9d95955d962509723404cf60907961399ccfdf29f";
const WASM_HEX =
  "0061736d0100000001040160000003020100070a01065f737461727400000a040102000b";
const WASM = hexToBytes(WASM_HEX);
const ASSOCIATED_PROGRAM_HASH =
  "dd4ffef9a099126e58677d9f1a695d3072512cadedb5625441e8459d473fd1ef";
const ASSOCIATED_WASM_HEX =
  "0061736d0100000001040160000003020100070a01065f737461727400000a040102000b00351266757a7a666f7267652e6d657461646174617b226769746875625f7265706f7369746f7279223a226f776e65722f7265706f227d";
const ASSOCIATED_WASM = hexToBytes(ASSOCIATED_WASM_HEX);
const OBSERVATIONS = [
  {
    seed_hex: "00",
    stdout_hash: "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
    status: "Success",
    fuel_consumed: 16,
    config: {
      fuel: 100,
      memory_bytes: 65536,
      invoke: null,
    },
    observation_hash: "bd1879579ace4829d2edd6542a21894f79408e18d874f5e58eff3f0c0fe860a1",
  },
  {
    seed_hex: "01",
    stdout_hash: "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
    status: "Success",
    fuel_consumed: 16,
    config: {
      fuel: 100,
      memory_bytes: 65536,
      invoke: null,
    },
    observation_hash: "a25fe64ecb5ea49bc2319da08cdb696e53a2bc64b7d034f34442badc78fcfc18",
  },
];
const SAME_BUCKET_LOW_RANK = {
  seed_hex: "00000006",
  observation_hash: "ab2cfe5f1a881a0ec45d99951e0a2bb365a447eee4de03261a1306517c132fdf",
};
const SAME_BUCKET_HIGH_RANK = {
  seed_hex: "00000002",
  observation_hash: "a8a888e5f36a182596943198be5f71264244acf1ab70b443d62a2f13ebd8c869",
};

describe("fuzzforge worker api", () => {
  beforeAll(() => {
    fetchMock.activate();
    fetchMock.disableNetConnect();
  });

  beforeEach(async () => {
    await env.DB.prepare("DELETE FROM hll_buckets").run();
    await env.DB.prepare("DELETE FROM programs").run();
    await env.WASM_BUCKET.delete(`wasm/${PROGRAM_HASH}.wasm`);
    await env.WASM_BUCKET.delete(`wasm/${ASSOCIATED_PROGRAM_HASH}.wasm`);
  });

  afterEach(() => {
    fetchMock.assertNoPendingInterceptors();
  });

  test("stores and fetches wasm from r2 after verifying its hash", async () => {
    await uploadWasm();

    const get = await SELF.fetch(`https://example.com/api/programs/${PROGRAM_HASH}/wasm`);
    expect(get.status).toBe(200);
    expect(new Uint8Array(await get.arrayBuffer())).toEqual(WASM);
    expect(get.headers.get("content-type")).toBe("application/wasm");
  });

  test("returns program metadata for stored wasm", async () => {
    await uploadWasm();

    const get = await SELF.fetch(`https://example.com/api/programs/${PROGRAM_HASH}`);
    expect(get.status).toBe(200);
    await expect(get.json()).resolves.toMatchObject({
      program_hash: PROGRAM_HASH,
      github_repository: null,
      github_verified_by: null,
      wasm_bytes: WASM.byteLength,
    });
  });

  test("returns github app client id for cli login", async () => {
    const get = await SELF.fetch("https://example.com/api/auth/github");
    expect(get.status).toBe(200);
    await expect(get.json()).resolves.toEqual({ client_id: "test-client-id" });
  });

  test("rejects wasm uploaded under the wrong hash", async () => {
    const put = await SELF.fetch(`https://example.com/api/programs/${"a".repeat(64)}/wasm`, {
      method: "PUT",
      body: WASM,
    });
    expect(put.status).toBe(400);
    await expect(put.json()).resolves.toEqual({ error: "wasm_hash_mismatch" });
  });

  test("does not call github when associated wasm hash mismatches", async () => {
    const put = await SELF.fetch(`https://example.com/api/programs/${"a".repeat(64)}/wasm`, {
      method: "PUT",
      body: ASSOCIATED_WASM,
    });
    expect(put.status).toBe(400);
    await expect(put.json()).resolves.toEqual({ error: "wasm_hash_mismatch" });
  });

  test("rejects associated wasm without github auth", async () => {
    const put = await SELF.fetch(
      `https://example.com/api/programs/${ASSOCIATED_PROGRAM_HASH}/wasm`,
      {
        method: "PUT",
        body: ASSOCIATED_WASM,
      },
    );
    expect(put.status).toBe(401);
    await expect(put.json()).resolves.toEqual({ error: "github_auth_required" });
  });

  test("rejects associated wasm with invalid github token", async () => {
    mockGitHubUser(401, { message: "Bad credentials" });

    const put = await SELF.fetch(
      `https://example.com/api/programs/${ASSOCIATED_PROGRAM_HASH}/wasm`,
      {
        method: "PUT",
        headers: { authorization: "Bearer bad-token" },
        body: ASSOCIATED_WASM,
      },
    );
    expect(put.status).toBe(401);
    await expect(put.json()).resolves.toEqual({ error: "github_auth_invalid" });
  });

  test("rejects associated wasm when github permission is read", async () => {
    mockGitHubPermission("read");

    const put = await SELF.fetch(
      `https://example.com/api/programs/${ASSOCIATED_PROGRAM_HASH}/wasm`,
      {
        method: "PUT",
        headers: { authorization: "Bearer read-token" },
        body: ASSOCIATED_WASM,
      },
    );
    expect(put.status).toBe(403);
    await expect(put.json()).resolves.toEqual({ error: "repository_access_denied" });
  });

  test("rejects associated wasm when github permission lookup returns 404", async () => {
    mockGitHubUser(200, { login: "alice" });
    mockGitHubPermissionResponse(404, { message: "Not Found" });

    const put = await SELF.fetch(
      `https://example.com/api/programs/${ASSOCIATED_PROGRAM_HASH}/wasm`,
      {
        method: "PUT",
        headers: { authorization: "Bearer denied-token" },
        body: ASSOCIATED_WASM,
      },
    );
    expect(put.status).toBe(403);
    await expect(put.json()).resolves.toEqual({ error: "repository_access_denied" });
  });

  test("stores associated wasm after verifying github write permission", async () => {
    mockGitHubPermission("write");

    const put = await SELF.fetch(
      `https://example.com/api/programs/${ASSOCIATED_PROGRAM_HASH}/wasm`,
      {
        method: "PUT",
        headers: { authorization: "Bearer write-token" },
        body: ASSOCIATED_WASM,
      },
    );
    expect(put.status, await put.clone().text()).toBe(200);
    await expect(put.json()).resolves.toMatchObject({
      program_hash: ASSOCIATED_PROGRAM_HASH,
      bytes: ASSOCIATED_WASM.byteLength,
      github_repository: "owner/repo",
      github_verified_by: "alice",
    });

    const row = await env.DB.prepare(
      "SELECT github_repository, github_verified_by, wasm_bytes FROM programs WHERE program_hash = ?",
    )
      .bind(ASSOCIATED_PROGRAM_HASH)
      .first<{ github_repository: string; github_verified_by: string; wasm_bytes: number }>();
    expect(row).toEqual({
      github_repository: "owner/repo",
      github_verified_by: "alice",
      wasm_bytes: ASSOCIATED_WASM.byteLength,
    });
  });

  test("rejects malformed wasm metadata", async () => {
    const invalid = withMetadata(WASM, new Uint8Array([0xff]));
    const put = await SELF.fetch(
      "https://example.com/api/programs/70420d3bec5c2e28dc02689b899f36c7ac8c3889f0c2a9ea336eb9e898566000/wasm",
      {
        method: "PUT",
        body: invalid,
      },
    );
    expect(put.status).toBe(400);
    await expect(put.json()).resolves.toEqual({ error: "invalid_wasm_metadata" });
  });

  test("allows authorization header in cors preflight", async () => {
    const response = await SELF.fetch("https://example.com/api/programs", {
      method: "OPTIONS",
    });
    expect(response.status).toBe(204);
    expect(response.headers.get("access-control-allow-headers")).toContain("authorization");
  });

  test("verifies observations before merging them into the server proof", async () => {
    await uploadWasm();

    const first = await submitProof(proofRecord([OBSERVATIONS[0]]));
    expect(first.status, await first.clone().text()).toBe(200);
    await expect(first.json()).resolves.toMatchObject({
      bucket_witnesses: 1,
      verified_observations: 1,
    });

    const second = await submitProof(proofRecord([OBSERVATIONS[1]]));
    expect(second.status, await second.clone().text()).toBe(200);
    await expect(second.json()).resolves.toMatchObject({
      bucket_witnesses: 2,
      verified_observations: 1,
    });

    const duplicate = await submitProof(proofRecord([OBSERVATIONS[0]]));
    expect(duplicate.status, await duplicate.clone().text()).toBe(200);
    await expect(duplicate.json()).resolves.toMatchObject({
      bucket_witnesses: 2,
      verified_observations: 1,
    });

    const fetched = await SELF.fetch(`https://example.com/api/programs/${PROGRAM_HASH}/proof`);
    expect(fetched.status).toBe(200);
    const proof = (await fetched.json()) as { program_hash: string; observations: unknown[] };
    expect(proof.program_hash).toBe(PROGRAM_HASH);
    expect(proof.observations).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ observation_hash: OBSERVATIONS[0].observation_hash }),
        expect.objectContaining({ observation_hash: OBSERVATIONS[1].observation_hash }),
      ]),
    );
    expect(proof.observations).toHaveLength(2);

    const results = await SELF.fetch("https://example.com/api/hash-results");
    expect(results.status).toBe(200);
    const body = (await results.json()) as { total_tests: number; bucket_witnesses: unknown[] };
    expect(body.total_tests).toBeCloseTo(2.032, 3);
    expect(body.bucket_witnesses).toHaveLength(2);
  });

  test("preserves concurrent writes to different hll buckets", async () => {
    await uploadWasm();

    const [first, second] = await Promise.all([
      submitProof(proofRecord([OBSERVATIONS[0]])),
      submitProof(proofRecord([OBSERVATIONS[1]])),
    ]);
    expect(first.status, await first.clone().text()).toBe(200);
    expect(second.status, await second.clone().text()).toBe(200);

    const proof = (await (
      await SELF.fetch(`https://example.com/api/programs/${PROGRAM_HASH}/proof`)
    ).json()) as { observations: Array<{ observation_hash: string }> };
    expect(proof.observations.map((observation) => observation.observation_hash)).toEqual(
      expect.arrayContaining([
        OBSERVATIONS[0].observation_hash,
        OBSERVATIONS[1].observation_hash,
      ]),
    );
    expect(proof.observations).toHaveLength(2);

    const row = await env.DB.prepare(
      "SELECT COUNT(*) AS count FROM hll_buckets WHERE program_hash = ?",
    )
      .bind(PROGRAM_HASH)
      .first<{ count: number }>();
    expect(row?.count).toBe(2);
  });

  test("same-bucket writes keep the highest-rank witness without storing rank", async () => {
    await uploadWasm();

    const first = await submitProof(proofRecord([SAME_BUCKET_LOW_RANK]));
    expect(first.status, await first.clone().text()).toBe(200);
    const second = await submitProof(proofRecord([SAME_BUCKET_HIGH_RANK]));
    expect(second.status, await second.clone().text()).toBe(200);

    const proof = (await (
      await SELF.fetch(`https://example.com/api/programs/${PROGRAM_HASH}/proof`)
    ).json()) as { observations: Array<{ observation_hash: string }> };
    expect(proof.observations).toHaveLength(1);
    expect(proof.observations[0].observation_hash).toBe(
      SAME_BUCKET_HIGH_RANK.observation_hash,
    );
  });

  test("rejects tampered observations before writing hash results", async () => {
    await uploadWasm();
    const tampered = {
      ...OBSERVATIONS[0],
      observation_hash: "e".repeat(64),
    };

    const response = await submitProof(proofRecord([tampered]));
    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({
      error: "observation_hash_mismatch",
    });

    const results = await SELF.fetch("https://example.com/api/hash-results");
    expect(results.status).toBe(200);
    await expect(results.json()).resolves.toMatchObject({
      total_tests: 0,
      bucket_witnesses: [],
    });
  });

  test("rejects malformed proof records", async () => {
    const response = await SELF.fetch(`https://example.com/api/programs/${PROGRAM_HASH}/proof`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ program_hash: "d".repeat(64) }),
    });
    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({ error: "program_hash_mismatch" });
  });

  test("streams live counter events after verified writes", async () => {
    await uploadWasm();
    await submitProof(proofRecord([OBSERVATIONS[0]]));

    const response = await SELF.fetch(
      "https://example.com/api/hash-results/stream?interval_ms=1",
    );
    expect(response.status).toBe(200);

    const reader = response.body!.getReader();
    const chunk = await reader.read();
    await reader.cancel();
    const text = new TextDecoder().decode(chunk.value);
    expect(text).toContain("event: ");
    expect(text).toContain("total_tests");
  });
});

async function uploadWasm() {
  const put = await SELF.fetch(`https://example.com/api/programs/${PROGRAM_HASH}/wasm`, {
    method: "PUT",
    body: WASM,
  });
  expect(put.status).toBe(200);
  await expect(put.json()).resolves.toMatchObject({
    program_hash: PROGRAM_HASH,
    bytes: WASM.byteLength,
  });
}

function submitProof(record: unknown): Promise<Response> {
  return SELF.fetch(`https://example.com/api/programs/${PROGRAM_HASH}/proof`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(record),
  });
}

function proofRecord(observations: unknown[]) {
  return {
    schema_version: 2,
    program_hash: PROGRAM_HASH,
    precision: 6,
    sketch: {
      registers: Array.from({ length: 64 }, () => 0),
    },
    observations,
  };
}

function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(hex.match(/.{2}/g)!.map((byte) => Number.parseInt(byte, 16)));
}

function mockGitHubPermission(permission: string) {
  mockGitHubUser(200, { login: "alice" });
  mockGitHubPermissionResponse(200, { permission });
}

function mockGitHubUser(status: number, body: object) {
  fetchMock.get("https://api.github.com").intercept({ method: "GET", path: "/user" }).reply(
    status,
    body,
    { headers: { "content-type": "application/json" } },
  );
}

function mockGitHubPermissionResponse(status: number, body: object) {
  fetchMock
    .get("https://api.github.com")
    .intercept({
      method: "GET",
      path: "/repos/owner/repo/collaborators/alice/permission",
    })
    .reply(status, body, { headers: { "content-type": "application/json" } });
}

function withMetadata(wasm: Uint8Array, metadata: Uint8Array): Uint8Array {
  const name = new TextEncoder().encode("fuzzforge.metadata");
  const payload = concat([encodeLebU32(name.byteLength), name, metadata]);
  return concat([wasm, new Uint8Array([0]), encodeLebU32(payload.byteLength), payload]);
}

function encodeLebU32(value: number): Uint8Array {
  const bytes = [];
  do {
    let byte = value & 0x7f;
    value >>>= 7;
    if (value !== 0) {
      byte |= 0x80;
    }
    bytes.push(byte);
  } while (value !== 0);
  return new Uint8Array(bytes);
}

function concat(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.byteLength, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.byteLength;
  }
  return out;
}
