import { SELF, env, fetchMock } from "cloudflare:test";
import { afterEach, beforeAll, beforeEach, describe, expect, test } from "vitest";

const PROGRAM_HASH = "a2840b47184016de26d91be9d95955d962509723404cf60907961399ccfdf29f";
const WASM_HEX =
  "0061736d0100000001040160000003020100070a01065f737461727400000a040102000b";
const WASM = hexToBytes(WASM_HEX);
const ASSOCIATED_PROGRAM_HASH =
  "c0e8436f1426c3ba7ab7171ef77c462526910735ef11e091b9044b476c9fbd45";
const ASSOCIATED_WASM_HEX =
  "0061736d0100000001120360047f7f7f7f017f60027f7f017f600000026c0316776173695f736e617073686f745f70726576696577310766645f72656164000016776173695f736e617073686f745f70726576696577310866645f7772697465000016776173695f736e617073686f745f70726576696577310e617267735f73697a65735f6765740001030201020503010001071302066d656d6f72790200065f737461727400030a6f016d0041dc0041e00010021a41dc0028020041014b04404100418001360200410441cb0036020041014100410141e40010011a0541004110360200410441c00036020041004100410141d40010001a41084110360200410c41d40028020036020041014108410141d80010011a0b0b0b5201004180010b4b7b226769746875625f7265706f7369746f7279223a226f776e65722f7265706f222c22636f6d706f6e656e745f6e616d65223a22617069222c2276657273696f6e223a22312e322e33227d002b046e616d65012403000766645f72656164010866645f7772697465020e617267735f73697a65735f676574";
const ASSOCIATED_WASM = hexToBytes(ASSOCIATED_WASM_HEX);
const OBSERVATIONS = [
  {
    seed_hex: "00",
    observation_hash: "aeb47a6b97e7b4c3291bc0e379cfe9f65b2185c797c40c581375b6c770df9ff9",
  },
  {
    seed_hex: "01",
    observation_hash: "a5fd96b85a17d6709fa02775e296c4e853d709bd7bbd6926463ee3154d3e29c1",
  },
];
const SAME_BUCKET_HIGH_HASH = {
  seed_hex: "00000006",
  observation_hash: "2bd1ebda0e82a323eef9073b3e0ec316102a8c62b0ecfc9649e71111bed10b5e",
};
const SAME_BUCKET_LOW_HASH = {
  seed_hex: "00000004",
  observation_hash: "2b4eabbaa058ea77931c0180a3980e3b6d0cc9e12dc5caf15354b4e6de084a1e",
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
      component_name: null,
      version: null,
      github_verified_by: null,
      wasm_bytes: WASM.byteLength,
      average_fuel_consumed: expect.any(Number),
      fuel_samples: 1,
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

  test("does not query repository when wasm hash mismatches", async () => {
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

  test("rejects associated wasm when github repository permissions are read-only", async () => {
    mockGitHubRepositoryPermissions({ pull: true, push: false, admin: false });

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

  test("rejects associated wasm when github repository lookup returns 404", async () => {
    mockGitHubUser(200, { login: "alice" });
    mockGitHubRepositoryResponse(404, { message: "Not Found" });

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

  test("stores associated wasm after verifying github push permission", async () => {
    mockGitHubRepositoryPermissions({ pull: true, push: true, admin: false });

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
      component_name: "api",
      version: "1.2.3",
      github_verified_by: "alice",
    });

    const row = await env.DB.prepare(
      "SELECT github_repository, component_name, version, github_verified_by, wasm_bytes, average_fuel_consumed, fuel_samples FROM programs WHERE program_hash = ?",
    )
      .bind(ASSOCIATED_PROGRAM_HASH)
      .first<{
        github_repository: string;
        component_name: string | null;
        version: string | null;
        github_verified_by: string;
        wasm_bytes: number;
        average_fuel_consumed: number;
        fuel_samples: number;
      }>();
    expect(row).toMatchObject({
      github_repository: "owner/repo",
      component_name: "api",
      version: "1.2.3",
      github_verified_by: "alice",
      wasm_bytes: ASSOCIATED_WASM.byteLength,
      average_fuel_consumed: expect.any(Number),
      fuel_samples: 1,
    });
    expect(row!.average_fuel_consumed).toBeGreaterThan(0);
  });

  test("records one initial fuel sample for uploaded wasm", async () => {
    const put = await uploadWasm();
    const body = (await put.json()) as {
      average_fuel_consumed: number;
      fuel_samples: number;
    };
    expect(body.average_fuel_consumed).toBeGreaterThan(0);
    expect(body.fuel_samples).toBe(1);

    const row = await env.DB.prepare(
      "SELECT average_fuel_consumed, fuel_samples FROM programs WHERE program_hash = ?",
    )
      .bind(PROGRAM_HASH)
      .first<{ average_fuel_consumed: number; fuel_samples: number }>();
    expect(row).toEqual({
      average_fuel_consumed: body.average_fuel_consumed,
      fuel_samples: body.fuel_samples,
    });
  });

  test("does not reset existing fuel estimates when wasm is uploaded again", async () => {
    await uploadWasm();
    await env.DB.prepare(
      "UPDATE programs SET average_fuel_consumed = ?, fuel_samples = ? WHERE program_hash = ?",
    )
      .bind(123.5, 2, PROGRAM_HASH)
      .run();

    const put = await SELF.fetch(`https://example.com/api/programs/${PROGRAM_HASH}/wasm`, {
      method: "PUT",
      body: WASM,
    });
    expect(put.status, await put.clone().text()).toBe(200);
    await expect(put.json()).resolves.toMatchObject({
      average_fuel_consumed: 123.5,
      fuel_samples: 2,
    });
  });

  test("updates fuel estimates from a submitted proof observation", async () => {
    await uploadWasm();
    await env.DB.prepare(
      "UPDATE programs SET average_fuel_consumed = ?, fuel_samples = ? WHERE program_hash = ?",
    )
      .bind(1_000_000_000, 2, PROGRAM_HASH)
      .run();

    const response = await submitProof(proofObservation(OBSERVATIONS[0]));
    expect(response.status, await response.clone().text()).toBe(200);

    const row = await env.DB.prepare(
      "SELECT average_fuel_consumed, fuel_samples FROM programs WHERE program_hash = ?",
    )
      .bind(PROGRAM_HASH)
      .first<{ average_fuel_consumed: number; fuel_samples: number }>();
    expect(row?.fuel_samples).toBe(3);
    expect(row?.average_fuel_consumed).toBeGreaterThan(0);
    expect(row?.average_fuel_consumed).toBeLessThan(1_000_000_000);
  });

  test("rejects proof submissions with multiple observations", async () => {
    await uploadWasm();

    const response = await submitProof(OBSERVATIONS.map(proofObservation));
    expect(response.status, await response.clone().text()).toBe(400);
    await expect(response.json()).resolves.toEqual({ error: "invalid_observation" });
  });

  test("lists stored programs and filters to associated programs", async () => {
    await uploadWasm();
    mockGitHubRepositoryPermissions({ pull: true, push: true, admin: false });
    const associatedPut = await SELF.fetch(
      `https://example.com/api/programs/${ASSOCIATED_PROGRAM_HASH}/wasm`,
      {
        method: "PUT",
        headers: { authorization: "Bearer write-token" },
        body: ASSOCIATED_WASM,
      },
    );
    expect(associatedPut.status, await associatedPut.clone().text()).toBe(200);

    const firstPage = await SELF.fetch("https://example.com/api/programs?limit=1");
    expect(firstPage.status).toBe(200);
    await expect(firstPage.json()).resolves.toMatchObject({
      programs: [{ program_hash: PROGRAM_HASH, github_repository: null }],
      next_cursor: PROGRAM_HASH,
    });

    const associated = await SELF.fetch("https://example.com/api/programs?associated=true");
    expect(associated.status).toBe(200);
    await expect(associated.json()).resolves.toMatchObject({
      programs: [
        {
          program_hash: ASSOCIATED_PROGRAM_HASH,
          github_repository: "owner/repo",
          component_name: "api",
          version: "1.2.3",
        },
      ],
      next_cursor: null,
    });
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

    const first = await submitProof(proofObservation(OBSERVATIONS[0]));
    expect(first.status, await first.clone().text()).toBe(200);
    await expect(first.json()).resolves.toMatchObject({
      bucket_witnesses: 1,
      verified_observations: 1,
    });

    const second = await submitProof(proofObservation(OBSERVATIONS[1]));
    expect(second.status, await second.clone().text()).toBe(200);
    await expect(second.json()).resolves.toMatchObject({
      bucket_witnesses: 2,
      verified_observations: 1,
    });

    const duplicate = await submitProof(proofObservation(OBSERVATIONS[0]));
    expect(duplicate.status, await duplicate.clone().text()).toBe(200);
    await expect(duplicate.json()).resolves.toMatchObject({
      bucket_witnesses: 2,
      verified_observations: 1,
    });

    const fetched = await SELF.fetch(`https://example.com/api/programs/${PROGRAM_HASH}/proof`);
    expect(fetched.status).toBe(200);
    const proof = (await fetched.json()) as {
      program_hash: string;
      buckets: Array<{ observation_hash: string } | null>;
    };
    expect(proof.program_hash).toBe(PROGRAM_HASH);
    const witnesses = proof.buckets.filter((bucket) => bucket !== null);
    expect(witnesses).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ observation_hash: OBSERVATIONS[0].observation_hash }),
        expect.objectContaining({ observation_hash: OBSERVATIONS[1].observation_hash }),
      ]),
    );
    expect(witnesses).toHaveLength(2);

    const results = await SELF.fetch("https://example.com/api/hash-results");
    expect(results.status).toBe(200);
    const body = (await results.json()) as { total_tests: number; bucket_witnesses: unknown[] };
    expect(body.total_tests).toBeCloseTo(2.032, 3);
    expect(body.bucket_witnesses).toHaveLength(2);
  });

  test("preserves concurrent writes to different hll buckets", async () => {
    await uploadWasm();

    const [first, second] = await Promise.all([
      submitProof(proofObservation(OBSERVATIONS[0])),
      submitProof(proofObservation(OBSERVATIONS[1])),
    ]);
    expect(first.status, await first.clone().text()).toBe(200);
    expect(second.status, await second.clone().text()).toBe(200);

    const proof = (await (
      await SELF.fetch(`https://example.com/api/programs/${PROGRAM_HASH}/proof`)
    ).json()) as { buckets: Array<{ observation_hash: string } | null> };
    const witnesses = proof.buckets.filter((bucket) => bucket !== null);
    expect(witnesses.map((observation) => observation.observation_hash)).toEqual(
      expect.arrayContaining([
        OBSERVATIONS[0].observation_hash,
        OBSERVATIONS[1].observation_hash,
      ]),
    );
    expect(witnesses).toHaveLength(2);

    const row = await env.DB.prepare(
      "SELECT COUNT(*) AS count FROM hll_buckets WHERE program_hash = ?",
    )
      .bind(PROGRAM_HASH)
      .first<{ count: number }>();
    expect(row?.count).toBe(2);
  });

  test("same-bucket writes keep the lower observation hash witness", async () => {
    await uploadWasm();

    const first = await submitProof(proofObservation(SAME_BUCKET_HIGH_HASH));
    expect(first.status, await first.clone().text()).toBe(200);
    const second = await submitProof(proofObservation(SAME_BUCKET_LOW_HASH));
    expect(second.status, await second.clone().text()).toBe(200);

    const proof = (await (
      await SELF.fetch(`https://example.com/api/programs/${PROGRAM_HASH}/proof`)
    ).json()) as { buckets: Array<{ observation_hash: string } | null> };
    const witnesses = proof.buckets.filter((bucket) => bucket !== null);
    expect(witnesses).toHaveLength(1);
    expect(witnesses[0].observation_hash).toBe(SAME_BUCKET_LOW_HASH.observation_hash);
  });

  test("rejects tampered observations before writing hash results", async () => {
    await uploadWasm();
    const tampered = {
      ...OBSERVATIONS[0],
      observation_hash: "e".repeat(64),
    };

    const response = await submitProof(proofObservation(tampered));
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

  test("rejects malformed proof observations", async () => {
    const response = await SELF.fetch(`https://example.com/api/programs/${PROGRAM_HASH}/proof`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ program_hash: "d".repeat(64) }),
    });
    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({ error: "invalid_observation" });
  });

  test("rejects malformed observation witnesses", async () => {
    await uploadWasm();
    const malformed = {
      seed_hex: "0",
      verifier_version: 1,
      observation_hash: OBSERVATIONS[0].observation_hash,
    };

    const response = await submitProof(malformed);
    expect(response.status).toBe(400);
    await expect(response.json()).resolves.toEqual({ error: "invalid_observation" });
  });

  test("streams live counter events after verified writes", async () => {
    await uploadWasm();
    await submitProof(proofObservation(OBSERVATIONS[0]));

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
  const clone = put.clone();
  await expect(clone.json()).resolves.toMatchObject({
    program_hash: PROGRAM_HASH,
    bytes: WASM.byteLength,
    average_fuel_consumed: expect.any(Number),
    fuel_samples: 1,
  });
  return put;
}

function submitProof(record: unknown): Promise<Response> {
  return SELF.fetch(`https://example.com/api/programs/${PROGRAM_HASH}/proof`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(record),
  });
}

function proofObservation(observation: { seed_hex: string; observation_hash: string }) {
  return {
    seed_hex: observation.seed_hex,
    verifier_version: 1,
    observation_hash: observation.observation_hash,
  };
}

function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(hex.match(/.{2}/g)!.map((byte) => Number.parseInt(byte, 16)));
}

function mockGitHubRepositoryPermissions(permissions: object) {
  mockGitHubUser(200, { login: "alice" });
  mockGitHubRepositoryResponse(200, { permissions });
}

function mockGitHubUser(status: number, body: object) {
  fetchMock.get("https://api.github.com").intercept({ method: "GET", path: "/user" }).reply(
    status,
    body,
    { headers: { "content-type": "application/json" } },
  );
}

function mockGitHubRepositoryResponse(status: number, body: object) {
  fetchMock
    .get("https://api.github.com")
    .intercept({
      method: "GET",
      path: "/repos/owner/repo",
    })
    .reply(status, body, { headers: { "content-type": "application/json" } });
}
