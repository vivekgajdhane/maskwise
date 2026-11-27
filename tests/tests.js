import { runTestSuite } from "./suite.js";

function renderBrowserTests() {
  const summaryEl = document.getElementById("test-summary");
  const listEl = document.getElementById("test-results");
  if (!summaryEl || !listEl) return;

  const summary = runTestSuite();
  summaryEl.textContent = `${summary.passed}/${summary.total} tests passed (${summary.failed} failed)`;
  listEl.replaceChildren();

  for (const item of summary.results) {
    const li = document.createElement("li");
    li.className = "detector-chip";

    const name = document.createElement("span");
    name.className = "chip-name";
    name.textContent = `${item.ok ? "PASS" : "FAIL"} — ${item.name}${item.error ? `: ${item.error}` : ""}`;

    const badge = document.createElement("span");
    badge.className = "chip-count";
    badge.textContent = `${item.durationMs.toFixed(1)} ms`;

    li.append(name, badge);
    listEl.appendChild(li);
  }
}

document.addEventListener("DOMContentLoaded", renderBrowserTests);
