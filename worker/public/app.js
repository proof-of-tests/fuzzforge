const HLL_PRECISION = 6;
const HLL_BUCKETS = 1 << HLL_PRECISION;
const COUNTER_UPDATE_INTERVAL_MS = 1000;
const COUNTER_ANIMATION_MS = 1000;
const SEED_BYTES = 32;

const state = {
  metric: "tests",
  theme: localStorage.getItem("theme") ?? "dark",
  programs: new Map(),
  buckets: new Map(),
  displayedTotal: 0,
  pendingDelta: 0,
  counterTimer: null,
  counterFrame: null,
  lastCounterUpdateAt: -COUNTER_UPDATE_INTERVAL_MS,
  lastProofAt: null,
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
  metricLabel: document.getElementById("metricLabel"),
  totalValue: document.getElementById("totalValue"),
  counterDelta: document.getElementById("counterDelta"),
  updateState: document.getElementById("updateState"),
  programCount: document.getElementById("programCount"),
  witnessCount: document.getElementById("witnessCount"),
  runnerState: document.getElementById("runnerState"),
  runnerProgram: document.getElementById("runnerProgram"),
  submittedCount: document.getElementById("submittedCount"),
  queueCount: document.getElementById("queueCount"),
  startRunner: document.getElementById("startRunner"),
  stopRunner: document.getElementById("stopRunner"),
  lastUpdate: document.getElementById("lastUpdate"),
  programList: document.getElementById("programList"),
  settingsOpen: document.getElementById("settingsOpen"),
  settingsDialog: document.getElementById("settingsDialog"),
  themeToggle: document.getElementById("themeToggle"),
  segments: document.querySelectorAll(".segment"),
};

for (const segment of els.segments) {
  segment.addEventListener("click", () => {
    state.metric = segment.dataset.metric;
    for (const item of els.segments) {
      item.classList.toggle("active", item === segment);
    }
    resetDisplayedTotal(selectedTotal());
    render();
  });
}

els.settingsOpen.addEventListener("click", () => {
  els.settingsDialog.showModal();
});
els.themeToggle.addEventListener("change", () => {
  state.theme = els.themeToggle.checked ? "light" : "dark";
  localStorage.setItem("theme", state.theme);
  applyTheme();
});
els.startRunner.addEventListener("click", () => {
  void startRunner();
});
els.stopRunner.addEventListener("click", stopRunner);

applyTheme();
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

  source.addEventListener("heartbeat", () => {
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
  resetDisplayedTotal(selectedTotal());
  state.lastProofAt = state.buckets.size === 0 ? null : (payload.timestamp_ms ?? Date.now());
  render();
}

function applyProofEvent(payload) {
  const previousTotal = selectedTotal();
  applyPrograms(payload.programs);
  applyBuckets(payload.buckets);
  const nextTotal = selectedTotal();
  queueCounterDelta(Math.max(0, nextTotal - previousTotal));
  state.lastProofAt = payload.timestamp_ms ?? Date.now();
  render();
}

function applyPrograms(programs) {
  for (const program of programs ?? []) {
    state.programs.set(program.program_hash, {
      program_hash: program.program_hash,
      github_repository: program.github_repository ?? null,
      component_name: program.component_name ?? null,
      version: program.version ?? null,
      average_fuel_consumed: Number(program.average_fuel_consumed ?? 0),
    });
  }
}

function applyBuckets(buckets) {
  for (const bucket of buckets ?? []) {
    state.buckets.set(bucketKey(bucket.program_hash, bucket.bucket_index), bucket);
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

function render() {
  const totals = totalsByProgram();

  els.metricLabel.textContent = state.metric === "fuel" ? "Instructions" : "Tests";
  els.totalValue.textContent = formatMetric(state.displayedTotal, state.metric);
  els.updateState.textContent =
    state.pendingDelta > 0
      ? `+${formatMetric(state.pendingDelta, state.metric)} queued`
      : "Updates on new proofs";
  els.programCount.textContent = `${state.programs.size} programs`;
  els.witnessCount.textContent = `${state.buckets.size} witnesses`;
  els.submittedCount.textContent = String(state.submitted);
  els.queueCount.textContent = String(state.runner.queue.length);
  els.runnerProgram.textContent = state.runner.current ?? "-";
  els.runnerState.textContent = state.runner.active ? "Running" : "Idle";
  els.startRunner.disabled = state.runner.active;
  els.stopRunner.disabled = !state.runner.active;
  els.lastUpdate.textContent =
    state.lastProofAt === null
      ? "No events yet"
      : new Date(state.lastProofAt).toLocaleTimeString();

  renderProgramList(totals);
}

function queueCounterDelta(delta) {
  if (delta <= 0) {
    return;
  }
  state.pendingDelta += delta;

  if (state.counterTimer !== null) {
    return;
  }

  const now = performance.now();
  const elapsed = now - state.lastCounterUpdateAt;
  const delay = Math.max(0, COUNTER_UPDATE_INTERVAL_MS - elapsed);
  state.counterTimer = window.setTimeout(flushCounterDelta, delay);
}

function flushCounterDelta() {
  state.counterTimer = null;
  if (state.pendingDelta <= 0) {
    return;
  }

  const delta = state.pendingDelta;
  state.pendingDelta = 0;
  state.lastCounterUpdateAt = performance.now();
  animateCounter(state.displayedTotal, state.displayedTotal + delta);
  flashCounterDelta(delta);
  render();
}

function animateCounter(from, to) {
  if (state.counterFrame !== null) {
    cancelAnimationFrame(state.counterFrame);
  }

  const startedAt = performance.now();
  const step = (now) => {
    const elapsed = Math.min(1, (now - startedAt) / COUNTER_ANIMATION_MS);
    state.displayedTotal = from + (to - from) * sigmoidProgress(elapsed);
    els.totalValue.textContent = formatMetric(state.displayedTotal, state.metric);

    if (elapsed < 1) {
      state.counterFrame = requestAnimationFrame(step);
    } else {
      state.counterFrame = null;
      state.displayedTotal = to;
      render();
    }
  };

  state.counterFrame = requestAnimationFrame(step);
}

function resetDisplayedTotal(total) {
  if (state.counterTimer !== null) {
    clearTimeout(state.counterTimer);
    state.counterTimer = null;
  }
  if (state.counterFrame !== null) {
    cancelAnimationFrame(state.counterFrame);
    state.counterFrame = null;
  }
  state.pendingDelta = 0;
  state.displayedTotal = total;
}

function sigmoidProgress(progress) {
  const slope = 12;
  const min = 1 / (1 + Math.exp(slope / 2));
  const max = 1 / (1 + Math.exp(-slope / 2));
  const value = 1 / (1 + Math.exp(-slope * (progress - 0.5)));
  return (value - min) / (max - min);
}

function flashCounterDelta(delta) {
  els.counterDelta.textContent = `+${formatMetric(delta, state.metric)}`;
  els.counterDelta.classList.remove("flash");
  void els.counterDelta.offsetWidth;
  els.counterDelta.classList.add("flash");
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
      const program = state.programs.get(programHash);
      const averageFuel = program?.average_fuel_consumed ?? 0;
      const repository = program?.github_repository ?? "Unassociated";
      const component = program?.component_name ?? "Unknown component";
      const version = program?.version ?? "No version";
      return `
        <div class="program-row">
          <div class="program-main">
            <div class="program-title">
              <span title="${escapeHtml(repository)}">${escapeHtml(repository)}</span>
              <span class="program-version">${escapeHtml(version)}</span>
            </div>
            <div class="program-meta">
              <span>${escapeHtml(component)}</span>
              <span class="hash" title="${programHash}">${programHash}</span>
            </div>
          </div>
          <div class="program-stat">${formatMetric(tests, "tests")} tests</div>
          <div class="program-stat">${formatMetric(tests * averageFuel, "fuel")} instructions</div>
        </div>
      `;
    });
  els.programList.innerHTML = rows.join("");
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
  if (!Number.isFinite(value) || value === 0) {
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

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function applyTheme() {
  document.documentElement.dataset.theme = state.theme;
  els.themeToggle.checked = state.theme === "light";
}

function setConnection(status, label) {
  els.connection.dataset.status = status;
  els.connectionStatus.textContent = label;
}
