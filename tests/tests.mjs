import { runTestSuite } from "./suite.js";

const summary = runTestSuite();
for (const item of summary.results) {
  const icon = item.ok ? "PASS" : "FAIL";
  console.log(`[${icon}] ${item.name} (${item.durationMs.toFixed(1)} ms)`);
  if (!item.ok) {
    console.error(`       ${item.error}`);
  }
}
console.log(`\nSummary: ${summary.passed}/${summary.total} passed, ${summary.failed} failed.`);
if (summary.failed > 0) {
  process.exitCode = 1;
}
