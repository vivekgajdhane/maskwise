/**
 * CloakText UI controller — coordinates input, pipeline execution, XSS-safe
 * diff rendering, synchronized scrolling, summary metrics, mapping table,
 * sample loading, and local copy/download export.
 */

import { ENTITY_TYPES } from "./detectors.js";
import { runSanitization } from "./pipeline.js";
import { createPseudonymMapper } from "./redactors.js";
import { SAMPLE_NOISY_CSV, SAMPLE_NOISY_TEXT } from "./samples.js";

const MAX_FILE_BYTES = 5 * 1024 * 1024;
const ALLOWED_EXTENSIONS = new Set(["txt", "csv"]);

const TYPE_TAGS = {
  credit_card: "CARD",
  aadhaar: "AADHAAR",
  pan: "PAN",
  phone: "PHONE",
  ip: "IP",
  email: "EMAIL",
};

const TYPE_LABELS = {
  credit_card: "Credit Card",
  aadhaar: "Aadhaar",
  pan: "Indian PAN",
  phone: "Phone",
  ip: "IP Address",
  email: "Email",
};

const state = {
  theme: "light",
  mode: "full",
  format: "text",
  typedFullMask: false,
  persistMapping: false,
  mappingOpen: false,
  fileName: null,
  fileExt: "txt",
  enabledTypes: new Set(ENTITY_TYPES),
  mapper: createPseudonymMapper(),
  lastResult: null,
  debounceTimer: null,
  copyTimer: null,
  syncLock: null,
};

function getFileExtension(name) {
  const idx = name.lastIndexOf(".");
  if (idx === -1) return "";
  return name.slice(idx + 1).toLowerCase();
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function countLines(text) {
  if (!text) return 0;
  return text.split(/\r\n|\n|\r/).length;
}

function setFileStatus(message, isError = false) {
  const statusEl = document.getElementById("file-status");
  if (!statusEl) return;
  statusEl.textContent = message;
  statusEl.classList.toggle("is-error", isError);
}

function syncFormatButtons() {
  const buttons = document.querySelectorAll(".format-btn[data-format]");
  buttons.forEach((btn) => {
    const active = btn.dataset.format === state.format;
    btn.classList.toggle("is-active", active);
    btn.setAttribute("aria-checked", String(active));
  });
  const downloadLabel = document.getElementById("download-label");
  if (downloadLabel) {
    downloadLabel.textContent = `Download sanitized .${state.format === "csv" ? "csv" : "txt"}`;
  }
}

/**
 * Render diff panes strictly via Text nodes and element.textContent (XSS-safe).
 */
function renderDiffPane(container, text, spans, isSanitized, emptyMessage) {
  if (!container) return;
  container.replaceChildren();

  if (!text) {
    const empty = document.createElement("span");
    empty.className = "empty-state";
    empty.textContent = emptyMessage;
    container.appendChild(empty);
    return;
  }

  const fragment = document.createDocumentFragment();
  let cursor = 0;

  for (const span of spans) {
    const start = isSanitized ? span.sanitizedStart : span.start;
    const end = isSanitized ? span.sanitizedEnd : span.end;
    if (start < cursor || start > text.length || end > text.length) {
      continue;
    }

    if (start > cursor) {
      fragment.appendChild(document.createTextNode(text.slice(cursor, start)));
    }

    const mark = document.createElement("mark");
    const tag = TYPE_TAGS[span.type] || span.type.toUpperCase();
    const label = TYPE_LABELS[span.type] || span.type;
    mark.textContent = text.slice(start, end);

    if (isSanitized) {
      mark.className = "redacted-mark";
      mark.title = `Redacted ${label}`;
      mark.setAttribute("aria-label", `Redacted ${label}: ${mark.textContent}`);
    } else {
      mark.className = `pii-mark pii-${span.type}`;
      mark.dataset.tag = tag;
      const issuerNote = span.meta?.issuer ? ` (${span.meta.issuer})` : "";
      mark.title = `${label}${issuerNote}`;
      mark.setAttribute("aria-label", `${label}${issuerNote}: ${mark.textContent}`);
    }

    fragment.appendChild(mark);
    cursor = end;
  }

  if (cursor < text.length) {
    fragment.appendChild(document.createTextNode(text.slice(cursor)));
  }

  container.appendChild(fragment);
}

function updateSummaryBadges(result) {
  const counts = {
    credit_card: 0,
    aadhaar: 0,
    pan: 0,
    phone: 0,
    ip: 0,
    email: 0,
  };

  for (const ent of result.entities) {
    if (Object.prototype.hasOwnProperty.call(counts, ent.type)) {
      counts[ent.type] += 1;
    }
  }

  for (const type of ENTITY_TYPES) {
    const badge = document.querySelector(`[data-count="${type}"]`);
    if (badge) {
      badge.textContent = String(counts[type]);
    }
    const chip = document.querySelector(`.detector-chip[data-type="${type}"]`);
    if (chip) {
      chip.classList.toggle("is-disabled", !state.enabledTypes.has(type));
    }
  }

  const totalEl = document.getElementById("total-detected-badge");
  if (totalEl) {
    const total = result.entities.length;
    totalEl.textContent = `${total} ${total === 1 ? "entity" : "entities"} detected`;
  }

  const rejectedEl = document.getElementById("rejected-summary-badge");
  if (rejectedEl) {
    const r = result.rejected;
    const parts = [];
    if (r.luhn) parts.push(`${r.luhn} Luhn-failed`);
    if (r.verhoeff) parts.push(`${r.verhoeff} Verhoeff-failed`);
    if (r.ipv4) parts.push(`${r.ipv4} invalid IP`);
    if (r.pan) parts.push(`${r.pan} invalid PAN`);
    if (r.phone) parts.push(`${r.phone} invalid phone`);
    const totalRejected = r.luhn + r.verhoeff + r.ipv4 + r.pan + r.phone;
    rejectedEl.textContent =
      totalRejected === 0
        ? "0 invalid candidates ignored"
        : `${totalRejected} invalid ignored (${parts.join(", ")})`;
  }

  const perfEl = document.getElementById("perf-badge");
  if (perfEl) {
    if (!result.originalText) {
      perfEl.textContent = "Ready";
    } else if (result.csvStats) {
      perfEl.textContent = `${result.csvStats.dataRows} CSV rows · ${result.csvStats.formulasGuarded} formula-guarded · ${result.durationMs.toFixed(1)} ms`;
    } else {
      perfEl.textContent = `Processed in ${result.durationMs.toFixed(1)} ms`;
    }
  }
}

function renderMappingTable(result) {
  const tbody = document.getElementById("mapping-tbody");
  const countEl = document.getElementById("mapping-count");
  if (!tbody) return;

  tbody.replaceChildren();
  const entries =
    state.mode === "pseudonym"
      ? result.mapper.entries().filter((e) => e.count > 0)
      : [];

  if (countEl) {
    countEl.textContent = `${entries.length} unique ${entries.length === 1 ? "entity" : "entities"} mapped`;
  }

  if (entries.length === 0) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 4;
    td.className = "empty-cell";
    td.textContent =
      state.mode === "pseudonym"
        ? "No matching PII found to pseudonymize in the current input."
        : "Switch to Pseudonymize mode to view placeholder mappings.";
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }

  const fragment = document.createDocumentFragment();
  for (const entry of entries) {
    const tr = document.createElement("tr");

    const tdToken = document.createElement("td");
    const code = document.createElement("code");
    code.textContent = entry.token;
    tdToken.appendChild(code);

    const tdType = document.createElement("td");
    tdType.textContent = TYPE_LABELS[entry.type] || entry.type;

    const tdNorm = document.createElement("td");
    tdNorm.textContent = entry.normalized;

    const tdCount = document.createElement("td");
    tdCount.textContent = String(entry.count);

    tr.append(tdToken, tdType, tdNorm, tdCount);
    fragment.appendChild(tr);
  }
  tbody.appendChild(fragment);
}

function processInput() {
  const rawInput = document.getElementById("raw-input");
  const text = rawInput ? rawInput.value : "";

  if (!state.persistMapping) {
    state.mapper.reset();
  } else {
    state.mapper.beginRun();
  }

  const result = runSanitization(text, {
    format: state.format,
    enabledTypes: state.enabledTypes,
    mode: state.mode,
    typedFullMask: state.typedFullMask,
    mapper: state.mapper,
  });

  state.lastResult = result;

  const inputMeta = document.getElementById("input-meta");
  if (inputMeta) {
    inputMeta.textContent = `${text.length.toLocaleString()} chars · ${countLines(text).toLocaleString()} lines`;
  }

  const origLineEl = document.getElementById("original-line-count");
  const sanLineEl = document.getElementById("sanitized-line-count");
  if (origLineEl) {
    const n = countLines(result.originalText);
    origLineEl.textContent = `${n} ${n === 1 ? "line" : "lines"}`;
  }
  if (sanLineEl) {
    const n = countLines(result.sanitizedText);
    sanLineEl.textContent = `${n} ${n === 1 ? "line" : "lines"}`;
  }

  renderDiffPane(
    document.getElementById("original-diff"),
    result.originalText,
    result.entities,
    false,
    "Paste text, upload a .txt/.csv file, or load sample noisy data to inspect detected PII."
  );

  renderDiffPane(
    document.getElementById("sanitized-diff"),
    result.sanitizedText,
    result.replacements,
    true,
    "Sanitized output will appear here in real time."
  );

  updateSummaryBadges(result);
  renderMappingTable(result);

  const hasOutput = result.sanitizedText.length > 0;
  const copyBtn = document.getElementById("copy-output");
  const downloadBtn = document.getElementById("download-output");
  if (copyBtn) copyBtn.disabled = !hasOutput;
  if (downloadBtn) downloadBtn.disabled = !hasOutput;
}

function scheduleProcess() {
  if (state.debounceTimer) {
    clearTimeout(state.debounceTimer);
  }
  state.debounceTimer = setTimeout(processInput, 120);
}

function syncPaneScroll(source, target) {
  if (!source || !target) return;
  if (state.syncLock && state.syncLock !== source) return;
  state.syncLock = source;

  const maxSourceY = Math.max(1, source.scrollHeight - source.clientHeight);
  const maxTargetY = Math.max(0, target.scrollHeight - target.clientHeight);
  const ratioY = source.scrollTop / maxSourceY;
  target.scrollTop = Math.round(ratioY * maxTargetY);
  target.scrollLeft = source.scrollLeft;

  requestAnimationFrame(() => {
    if (state.syncLock === source) {
      state.syncLock = null;
    }
  });
}

function buildDownloadFilename() {
  const ext = state.format === "csv" ? "csv" : "txt";
  if (!state.fileName) {
    return `sanitized-output.${ext}`;
  }
  const dotIdx = state.fileName.lastIndexOf(".");
  const stem = dotIdx > 0 ? state.fileName.slice(0, dotIdx) : state.fileName;
  return `${stem}.sanitized.${ext}`;
}

function downloadSanitized() {
  const text = state.lastResult?.sanitizedText;
  if (!text) return;

  const mimeType =
    state.format === "csv"
      ? "text/csv;charset=utf-8"
      : "text/plain;charset=utf-8";
  const blob = new Blob([text], { type: mimeType });
  const url = URL.createObjectURL(blob);

  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = buildDownloadFilename();
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);

  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function copySanitized() {
  const text = state.lastResult?.sanitizedText;
  const copyLabel = document.getElementById("copy-label");
  if (!text) return;

  let copied = false;
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(text);
      copied = true;
    } catch {
      copied = false;
    }
  }

  if (!copied) {
    const temp = document.createElement("textarea");
    temp.value = text;
    temp.className = "sr-only";
    document.body.appendChild(temp);
    temp.select();
    try {
      copied = document.execCommand("copy");
    } catch {
      copied = false;
    }
    document.body.removeChild(temp);
  }

  if (copyLabel) {
    copyLabel.textContent = copied ? "Copied!" : "Copy failed";
    if (state.copyTimer) clearTimeout(state.copyTimer);
    state.copyTimer = setTimeout(() => {
      copyLabel.textContent = "Copy sanitized";
    }, 1800);
  }
}

function handleSelectedFile(file) {
  if (!file) return;
  const ext = getFileExtension(file.name);

  if (!ALLOWED_EXTENSIONS.has(ext)) {
    setFileStatus(
      `Unsupported file "${file.name}". Only .txt and .csv files are accepted.`,
      true
    );
    return;
  }

  if (file.size > MAX_FILE_BYTES) {
    setFileStatus(
      `File too large: "${file.name}" is ${formatBytes(file.size)} (max 5 MB).`,
      true
    );
    return;
  }

  const reader = new FileReader();
  reader.onload = () => {
    const rawInput = document.getElementById("raw-input");
    if (!rawInput) return;
    rawInput.value = typeof reader.result === "string" ? reader.result : "";
    state.fileName = file.name;
    state.fileExt = ext;
    state.format = ext === "csv" ? "csv" : "text";
    if (!state.persistMapping) {
      state.mapper.reset();
    }
    syncFormatButtons();
    setFileStatus(`Loaded "${file.name}" (${formatBytes(file.size)}) locally`);
    processInput();
  };
  reader.onerror = () => {
    setFileStatus(`Failed to read "${file.name}" locally.`, true);
  };
  reader.readAsText(file, "UTF-8");
}

function loadSample(kind) {
  const rawInput = document.getElementById("raw-input");
  if (!rawInput) return;

  if (kind === "csv") {
    rawInput.value = SAMPLE_NOISY_CSV;
    state.fileName = "sample-records.csv";
    state.fileExt = "csv";
    state.format = "csv";
    setFileStatus("Loaded sample noisy CSV (4 data rows + header)");
  } else {
    rawInput.value = SAMPLE_NOISY_TEXT;
    state.fileName = "sample-noisy-log.txt";
    state.fileExt = "txt";
    state.format = "text";
    setFileStatus("Loaded sample noisy text (ticket, resume, clinical note, server log)");
  }

  if (!state.persistMapping) {
    state.mapper.reset();
  }
  syncFormatButtons();
  processInput();
}

function bindEvents() {
  const themeBtn = document.getElementById("theme-toggle");
  const themeLabel = themeBtn?.querySelector(".theme-label");
  const modeButtons = document.querySelectorAll(".seg-btn[data-mode]");
  const formatButtons = document.querySelectorAll(".format-btn[data-format]");
  const tabButtons = document.querySelectorAll(".tab-btn[data-tab]");
  const paneOriginal = document.getElementById("pane-original");
  const paneSanitized = document.getElementById("pane-sanitized");
  const originalDiff = document.getElementById("original-diff");
  const sanitizedDiff = document.getElementById("sanitized-diff");
  const rawInput = document.getElementById("raw-input");
  const dropzone = document.getElementById("dropzone");
  const fileInput = document.getElementById("file-input");
  const clearBtn = document.getElementById("clear-input");
  const sampleTextBtn = document.getElementById("load-sample-text");
  const sampleCsvBtn = document.getElementById("load-sample-csv");
  const typedToggle = document.getElementById("typed-mask-toggle");
  const persistToggle = document.getElementById("persist-mapping-toggle");
  const toggleMappingBtn = document.getElementById("toggle-mapping-btn");
  const resetMappingBtn = document.getElementById("reset-mapping-btn");
  const mappingPanel = document.getElementById("mapping-panel");
  const detectorCheckboxes = document.querySelectorAll("[data-detector]");
  const copyBtn = document.getElementById("copy-output");
  const downloadBtn = document.getElementById("download-output");

  themeBtn?.addEventListener("click", () => {
    state.theme = state.theme === "light" ? "dark" : "light";
    document.documentElement.setAttribute("data-theme", state.theme);
    themeBtn.setAttribute("aria-pressed", String(state.theme === "dark"));
    if (themeLabel) {
      themeLabel.textContent = state.theme === "light" ? "Dark" : "Light";
    }
  });

  modeButtons.forEach((btn) => {
    btn.addEventListener("click", () => {
      state.mode = btn.dataset.mode || "full";
      modeButtons.forEach((b) => {
        const active = b === btn;
        b.classList.toggle("is-active", active);
        b.setAttribute("aria-checked", String(active));
      });
      const typedOption = document.getElementById("typed-mask-option");
      const pseudoActions = document.getElementById("pseudonym-actions");
      if (typedOption) typedOption.hidden = state.mode !== "full";
      if (pseudoActions) pseudoActions.hidden = state.mode !== "pseudonym";
      if (state.mode !== "pseudonym" && mappingPanel) {
        state.mappingOpen = false;
        mappingPanel.hidden = true;
        if (toggleMappingBtn) {
          toggleMappingBtn.setAttribute("aria-expanded", "false");
          toggleMappingBtn.textContent = "Show mapping table";
        }
      }
      processInput();
    });
  });

  formatButtons.forEach((btn) => {
    btn.addEventListener("click", () => {
      state.format = btn.dataset.format === "csv" ? "csv" : "text";
      state.fileExt = state.format === "csv" ? "csv" : "txt";
      syncFormatButtons();
      processInput();
    });
  });

  tabButtons.forEach((btn) => {
    btn.addEventListener("click", () => {
      const target = btn.dataset.tab;
      tabButtons.forEach((b) => {
        const active = b === btn;
        b.classList.toggle("is-active", active);
        b.setAttribute("aria-selected", String(active));
      });
      paneOriginal?.classList.toggle("is-active", target === "original");
      paneSanitized?.classList.toggle("is-active", target === "sanitized");
    });
  });

  detectorCheckboxes.forEach((cb) => {
    cb.addEventListener("change", () => {
      const type = cb.dataset.detector;
      if (!type) return;
      if (cb.checked) {
        state.enabledTypes.add(type);
      } else {
        state.enabledTypes.delete(type);
      }
      scheduleProcess();
    });
  });

  rawInput?.addEventListener("input", scheduleProcess);

  typedToggle?.addEventListener("change", () => {
    state.typedFullMask = Boolean(typedToggle.checked);
    processInput();
  });

  persistToggle?.addEventListener("change", () => {
    state.persistMapping = Boolean(persistToggle.checked);
    processInput();
  });

  toggleMappingBtn?.addEventListener("click", () => {
    state.mappingOpen = !state.mappingOpen;
    if (mappingPanel) mappingPanel.hidden = !state.mappingOpen;
    toggleMappingBtn.setAttribute("aria-expanded", String(state.mappingOpen));
    toggleMappingBtn.textContent = state.mappingOpen
      ? "Hide mapping table"
      : "Show mapping table";
  });

  resetMappingBtn?.addEventListener("click", () => {
    state.mapper.reset();
    processInput();
  });

  sampleTextBtn?.addEventListener("click", () => loadSample("text"));
  sampleCsvBtn?.addEventListener("click", () => loadSample("csv"));

  clearBtn?.addEventListener("click", () => {
    if (rawInput) rawInput.value = "";
    state.fileName = null;
    if (fileInput) fileInput.value = "";
    state.mapper.reset();
    setFileStatus("No file loaded");
    processInput();
  });

  dropzone?.addEventListener("click", () => fileInput?.click());
  dropzone?.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      fileInput?.click();
    }
  });
  dropzone?.addEventListener("dragover", (event) => {
    event.preventDefault();
    dropzone.classList.add("is-dragover");
  });
  dropzone?.addEventListener("dragleave", () => {
    dropzone.classList.remove("is-dragover");
  });
  dropzone?.addEventListener("drop", (event) => {
    event.preventDefault();
    dropzone.classList.remove("is-dragover");
    handleSelectedFile(event.dataTransfer?.files?.[0]);
  });

  fileInput?.addEventListener("change", () => {
    handleSelectedFile(fileInput.files?.[0]);
  });

  originalDiff?.addEventListener("scroll", () => syncPaneScroll(originalDiff, sanitizedDiff));
  sanitizedDiff?.addEventListener("scroll", () => syncPaneScroll(sanitizedDiff, originalDiff));

  copyBtn?.addEventListener("click", copySanitized);
  downloadBtn?.addEventListener("click", downloadSanitized);

  syncFormatButtons();
  processInput();
}

document.addEventListener("DOMContentLoaded", bindEvents);
