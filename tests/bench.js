/**
 * Throughput benchmark for 100 KB, 1 MB, and 5 MB inputs.
 * Run with: node tests/bench.js
 */

import { runSanitization } from "../js/pipeline.js";
import { SAMPLE_NOISY_TEXT } from "../js/samples.js";

function buildPayload(bytes) {
  const repeats = Math.ceil(bytes / SAMPLE_NOISY_TEXT.length);
  return SAMPLE_NOISY_TEXT.repeat(repeats).slice(0, bytes);
}

const sizes = [
  ["100 KB", 100 * 1024],
  ["1 MB", 1024 * 1024],
  ["5 MB", 5 * 1024 * 1024],
];

for (const [label, bytes] of sizes) {
  const payload = buildPayload(bytes);
  const t0 = performance.now();
  const res = runSanitization(payload, { format: "text", mode: "pseudonym" });
  const ms = performance.now() - t0;
  const mbPerSec = (bytes / (1024 * 1024) / (ms / 1000)).toFixed(1);
  console.log(
    `Bench [${label}]: ${ms.toFixed(1)} ms | ${res.entities.length} entities | ${mbPerSec} MB/s`
  );
}
