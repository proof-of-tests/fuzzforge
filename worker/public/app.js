const HLL_PRECISION = 6;
const HLL_BUCKETS = 1 << HLL_PRECISION;
const RATE_WINDOW_MS = 10_000;
const SPARKLINE_POINTS = 80;
const SEED_BYTES = 32;

const state = {
  metric: "tests",
  programs: new Map(),
  buckets: new Map(),
  samples: [],
  sparkline: [],
  submitted: 0,
  runner: {
    active: false,
    queue: [],
    current: null,
    verifier: null,
  },
};

const els = {
  connection: document.querySelector(".status"),
  connectionStatus: document.getElementById("connectionStatus"),
  totalValue: document.getElementById("totalValue"),
  rateValue: document.getElementById("rateValue"),
  programCount: document.getElementById("programCount"),
  witnessCount: document.getElementById("witnessCount"),
  sparkline: document.getElementById("sparkline"),
  runnerState: document.getElementById("runnerState"),
  runnerProgram: document.getElementById("runnerProgram"),
  submittedCount: document.getElementById("submittedCount"),
  queueCount: document.getElementById("queueCount"),
  startRunner: document.getElementById("startRunner"),
  stopRunner: document.getElementById("stopRunner"),
  lastUpdate: document.getElementById("lastUpdate"),
  programList: document.getElementById("programList"),
  segments: document.querySelectorAll(".segment"),
};

for (const segment of els.segments) {
  segment.addEventListener("click", () => {
    state.metric = segment.dataset.metric;
    for (const item of els.segments) {
      item.classList.toggle("active", item === segment);
    }
    recordSample(Date.now());
    render();
  });
}

els.startRunner.addEventListener("click", () => {
  void startRunner();
});
els.stopRunner.addEventListener("click", stopRunner);

connectProofStream();
render();

function connectProofStream() {
  setConnection("connecting", "Connecting");
  const source = new EventSource("/api/proofs/stream?interval_ms=1000");

  source.addEventListener("open", () => {
    setConnection("live", "Live");
  });

  source.addEventListener("snapshot", (event) => {
    applySnapshot(JSON.parse(event.data));
  });

  source.addEventListener("proof", (event) => {
    applyProofEvent(JSON.parse(event.data));
  });

  source.addEventListener("heartbeat", (event) => {
    const payload = JSON.parse(event.data);
    recordSample(payload.timestamp_ms);
    render();
  });

  source.addEventListener("error", () => {
    setConnection("offline", "Reconnecting");
  });
}

function applySnapshot(payload) {
  state.programs.clear();
  state.buckets.clear();
  applyPrograms(payload.programs);
  applyBuckets(payload.buckets);
  recordSample(payload.timestamp_ms);
  render();
}

function applyProofEvent(payload) {
  applyPrograms(payload.programs);
  applyBuckets(payload.buckets);
  recordSample(payload.timestamp_ms);
  render();
}

function applyPrograms(programs) {
  for (const program of programs ?? []) {
    state.programs.set(program.program_hash, {
      program_hash: program.program_hash,
      average_fuel_consumed: Number(program.average_fuel_consumed ?? 0),
    });
  }
}

function applyBuckets(buckets) {
  for (const bucket of buckets ?? []) {
    state.buckets.set(bucketKey(bucket.program_hash, bucket.bucket_index), bucket);
  }
}

function recordSample(timestampMs) {
  const total = selectedTotal();
  state.samples.push({ timestampMs, total });
  while (
    state.samples.length > 0 &&
    timestampMs - state.samples[0].timestampMs > RATE_WINDOW_MS
  ) {
    state.samples.shift();
  }

  const rate = currentRate();
  state.sparkline.push(rate);
  if (state.sparkline.length > SPARKLINE_POINTS) {
    state.sparkline.shift();
  }
}

function selectedTotal() {
  const totals = totalsByProgram();
  if (state.metric === "fuel") {
    let total = 0;
    for (const [programHash, tests] of totals.entries()) {
      total += tests * (state.programs.get(programHash)?.average_fuel_consumed ?? 0);
    }
    return total;
  }

  let total = 0;
  for (const tests of totals.values()) {
    total += tests;
  }
  return total;
}

function totalsByProgram() {
  const registersByProgram = new Map();
  for (const bucket of state.buckets.values()) {
    let registers = registersByProgram.get(bucket.program_hash);
    if (!registers) {
      registers = Array.from({ length: HLL_BUCKETS }, () => 0);
      registersByProgram.set(bucket.program_hash, registers);
    }
    registers[bucket.bucket_index] = observationRank(bucket.observation_hash);
  }

  const totals = new Map();
  for (const [programHash, registers] of registersByProgram.entries()) {
    totals.set(programHash, estimate(registers));
  }
  return totals;
}

function currentRate() {
  if (state.samples.length < 2) {
    return 0;
  }
  const first = state.samples[0];
  const last = state.samples[state.samples.length - 1];
  const elapsedMs = Math.max(0, last.timestampMs - first.timestampMs);
  if (elapsedMs === 0) {
    return 0;
  }
  return Math.max(0, last.total - first.total) / (elapsedMs / 1000);
}

function render() {
  const total = selectedTotal();
  const rate = currentRate();
  const totals = totalsByProgram();

  els.totalValue.textContent = formatMetric(total, state.metric);
  els.rateValue.textContent = `${formatMetric(rate, state.metric)}/sec`;
  els.programCount.textContent = `${state.programs.size} programs`;
  els.witnessCount.textContent = `${state.buckets.size} witnesses`;
  els.submittedCount.textContent = String(state.submitted);
  els.queueCount.textContent = String(state.runner.queue.length);
  els.runnerProgram.textContent = state.runner.current ?? "-";
  els.runnerState.textContent = state.runner.active ? "Running" : "Idle";
  els.startRunner.disabled = state.runner.active;
  els.stopRunner.disabled = !state.runner.active;
  els.lastUpdate.textContent =
    state.samples.length === 0
      ? "No events yet"
      : new Date(state.samples[state.samples.length - 1].timestampMs).toLocaleTimeString();

  renderProgramList(totals);
  renderSparkline();
}

function renderProgramList(totals) {
  if (totals.size === 0) {
    els.programList.innerHTML = '<div class="empty">Waiting for proofs</div>';
    return;
  }

  const rows = [...totals.entries()]
    .sort((left, right) => right[1] - left[1])
    .slice(0, 12)
    .map(([programHash, tests]) => {
      const averageFuel = state.programs.get(programHash)?.average_fuel_consumed ?? 0;
      return `
        <div class="program-row">
          <div class="hash" title="${programHash}">${programHash}</div>
          <div class="program-stat">${formatMetric(tests, "tests")} tests</div>
          <div class="program-stat">${formatMetric(tests * averageFuel, "fuel")} fuel</div>
        </div>
      `;
    });
  els.programList.innerHTML = rows.join("");
}

function renderSparkline() {
  const canvas = els.sparkline;
  const ctx = canvas.getContext("2d");
  const width = canvas.width;
  const height = canvas.height;
  ctx.clearRect(0, 0, width, height);

  ctx.strokeStyle = "rgba(167, 173, 159, 0.18)";
  ctx.lineWidth = 1;
  for (let line = 1; line < 4; line += 1) {
    const y = Math.round((height / 4) * line);
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(width, y);
    ctx.stroke();
  }

  const points = state.sparkline;
  if (points.length < 2) {
    return;
  }

  const max = Math.max(...points, 1);
  ctx.strokeStyle = state.metric === "fuel" ? "#f2bd67" : "#7fd77e";
  ctx.lineWidth = 3;
  ctx.beginPath();
  points.forEach((point, index) => {
    const x = (index / (SPARKLINE_POINTS - 1)) * width;
    const y = height - (point / max) * (height - 16) - 8;
    if (index === 0) {
      ctx.moveTo(x, y);
    } else {
      ctx.lineTo(x, y);
    }
  });
  ctx.stroke();
}

async function startRunner() {
  state.runner.active = true;
  state.runner.queue = [];
  render();

  try {
    state.runner.verifier ??= await loadVerifier();
    const programs = await loadAssociatedPrograms();
    state.runner.queue = programs;
    render();

    for (const program of programs) {
      if (!state.runner.active) {
        break;
      }
      await runProgram(program);
    }
  } catch (error) {
    console.error(error);
  } finally {
    state.runner.active = false;
    state.runner.current = null;
    state.runner.queue = [];
    render();
  }
}

function stopRunner() {
  state.runner.active = false;
  render();
}

async function loadAssociatedPrograms() {
  const response = await fetch("/api/programs?associated=true&limit=100");
  if (!response.ok) {
    throw new Error(`program list failed: ${response.status}`);
  }
  const body = await response.json();
  return body.programs ?? [];
}

async function runProgram(program) {
  state.runner.current = program.program_hash;
  state.runner.queue = state.runner.queue.filter(
    (queued) => queued.program_hash !== program.program_hash,
  );
  render();

  const wasmResponse = await fetch(`/api/programs/${program.program_hash}/wasm`);
  if (!wasmResponse.ok) {
    throw new Error(`wasm fetch failed: ${wasmResponse.status}`);
  }

  const wasm = new Uint8Array(await wasmResponse.arrayBuffer());
  const verifier = state.runner.verifier;
  const programPtr = verifier.createProgram(wasm);
  try {
    while (state.runner.active) {
      const seed = new Uint8Array(SEED_BYTES);
      crypto.getRandomValues(seed);
      const observation = verifier.runProgram(programPtr, seed);
      if (improvesLocalBucket(program.program_hash, observation)) {
        await submitObservation(program.program_hash, observation);
        state.submitted += 1;
        render();
      }
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
  } finally {
    verifier.freeProgram(programPtr);
  }
}

async function submitObservation(programHash, observation) {
  const response = await fetch(`/api/programs/${programHash}/proof`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      seed_hex: observation.seed_hex,
      verifier_version: observation.verifier_version,
      observation_hash: observation.observation_hash,
    }),
  });
  if (!response.ok) {
    throw new Error(`proof submission failed: ${response.status}`);
  }
}

function improvesLocalBucket(programHash, observation) {
  const existing = state.buckets.get(bucketKey(programHash, observation.bucket_index));
  return !existing || observation.observation_hash < existing.observation_hash;
}

async function loadVerifier() {
  const { instance } = await WebAssembly.instantiateStreaming(fetch("/verifier.wasm"));
  const exports = instance.exports;
  const decoder = new TextDecoder();

  function copy(bytes) {
    const ptr = exports.ff_alloc(bytes.byteLength);
    new Uint8Array(exports.memory.buffer, ptr, bytes.byteLength).set(bytes);
    return ptr;
  }

  return {
    createProgram(wasm) {
      const wasmPtr = copy(wasm);
      try {
        const programPtr = exports.ff_program_new(wasmPtr, wasm.byteLength);
        if (programPtr === 0) {
          throw new Error("unsupported wasm");
        }
        return programPtr;
      } finally {
        exports.ff_dealloc(wasmPtr, wasm.byteLength);
      }
    },
    freeProgram(programPtr) {
      exports.ff_program_free(programPtr);
    },
    runProgram(programPtr, seed) {
      const seedPtr = copy(seed);
      const outLen = 1024;
      const outPtr = exports.ff_alloc(outLen);
      try {
        const len = exports.ff_program_run(
          programPtr,
          seedPtr,
          seed.byteLength,
          outPtr,
          outLen,
        );
        if (len <= 0) {
          throw new Error(`verifier run failed: ${len}`);
        }
        const json = decoder.decode(new Uint8Array(exports.memory.buffer, outPtr, len));
        return JSON.parse(json);
      } finally {
        exports.ff_dealloc(seedPtr, seed.byteLength);
        exports.ff_dealloc(outPtr, outLen);
      }
    },
  };
}

function observationRank(observationHash) {
  const value = BigInt(`0x${observationHash.slice(0, 16)}`);
  const remaining = (value << BigInt(HLL_PRECISION)) & ((1n << 64n) - 1n);
  const maxRank = 64 - HLL_PRECISION + 1;
  if (remaining === 0n) {
    return maxRank;
  }
  return Math.min(64 - remaining.toString(2).length + 1, maxRank);
}

function estimate(registers) {
  const m = HLL_BUCKETS;
  const sum = registers.reduce((total, rank) => total + 2 ** -rank, 0);
  const raw = alpha(m) * m * m / sum;
  const zeros = registers.filter((rank) => rank === 0).length;
  if (raw <= 2.5 * m && zeros > 0) {
    return m * Math.log(m / zeros);
  }
  return raw;
}

function alpha(bucketCount) {
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

function bucketKey(programHash, bucketIndex) {
  return `${programHash}:${bucketIndex}`;
}

function formatMetric(value, metric) {
  if (!Number.isFinite(value)) {
    return "0";
  }
  if (metric === "fuel" && value >= 1_000_000_000) {
    return `${(value / 1_000_000_000).toFixed(2)}B`;
  }
  if (value >= 1_000_000) {
    return `${(value / 1_000_000).toFixed(2)}M`;
  }
  if (value >= 10_000) {
    return `${(value / 1_000).toFixed(1)}K`;
  }
  if (value >= 100) {
    return value.toFixed(0);
  }
  return value.toFixed(2);
}

function setConnection(status, label) {
  els.connection.dataset.status = status;
  els.connectionStatus.textContent = label;
}
