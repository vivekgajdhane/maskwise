/**
 * Maskwise UI controller — coordinates input, pipeline execution, XSS-safe
 * diff rendering, synchronized scrolling, summary metrics, mapping table,
 * sample loading, and local copy/download export.
 */

import {
  ALLOWED_EXTENSIONS,
  ALLOWED_MIME_TYPES,
  APP_CONFIG,
  ENTITY_TYPES,
  FULL_MASK_LABELS,
  TYPE_LABELS,
} from "./config.js";
import { runSanitization } from "./pipeline.js";
import { createPseudonymMapper } from "./redactors.js";
import { SAMPLE_NOISY_CSV, SAMPLE_NOISY_TEXT } from "./samples.js";

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
  worker: null,
  requestSeq: 0,
  renderSeq: 0,
  themeOverridden: false,
  announceCountsOnNextResult: false,
};

function getFileExtension(name) {
  const idx = name.lastIndexOf(".");
  return idx === -1 ? "" : name.slice(idx + 1).toLowerCase();
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function countLines(text) {
  return text ? text.split(/\r\n|\n|\r/).length : 0;
}

function setFileStatus(message, isError = false) {
  const statusEl = document.getElementById("file-status");
  if (!statusEl) return;
  statusEl.textContent = message;
  statusEl.classList.toggle("is-error", isError);
}

function announce(message) {
  const announcer = document.getElementById("status-announcer");
  if (!announcer) return;
  announcer.textContent = "";
  requestAnimationFrame(() => {
    announcer.textContent = message;
  });
}

function wireRovingGroup(buttons, onActivate) {
  const list = Array.from(buttons);
  list.forEach((btn, idx) => {
    btn.addEventListener("keydown", (event) => {
      const keyMap = { ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1 };
      let nextIdx = -1;
      if (keyMap[event.key] !== undefined) nextIdx = (idx + keyMap[event.key] + list.length) % list.length;
      else if (event.key === "Home") nextIdx = 0;
      else if (event.key === "End") nextIdx = list.length - 1;
      if (nextIdx !== -1) {
        event.preventDefault();
        list[nextIdx].focus();
        onActivate(list[nextIdx]);
      }
    });
  });
}

function syncFormatButtons() {
  document.querySelectorAll(".format-btn[data-format]").forEach((btn) => {
    const active = btn.dataset.format === state.format;
    btn.classList.toggle("is-active", active);
    btn.setAttribute("aria-checked", String(active));
    btn.setAttribute("tabindex", active ? "0" : "-1");
  });
  const downloadLabel = document.getElementById("download-label");
  if (downloadLabel) {
    downloadLabel.textContent = `Download sanitized .${state.format === "csv" ? "csv" : "txt"}`;
  }
}

function createDiffMark(text, span, isSanitized) {
  const mark = document.createElement("mark");
  const tag = FULL_MASK_LABELS[span.type] || span.type.toUpperCase();
  const label = TYPE_LABELS[span.type] || span.type;
  mark.textContent = text;
  if (isSanitized) {
    mark.className = "redacted-mark";
    mark.title = `Redacted ${label}`;
    mark.setAttribute("aria-label", `Redacted ${label}: ${text}`);
  } else {
    mark.className = `pii-mark pii-${span.type}`;
    mark.dataset.tag = tag;
    const issuerNote = span.meta?.issuer ? ` (${span.meta.issuer})` : "";
    mark.title = `${label}${issuerNote}`;
    mark.setAttribute("aria-label", `${label}${issuerNote}: ${text}`);
  }
  return mark;
}

function appendChunkedNodes(container, text, spans, isSanitized, renderToken, noteText) {
  const limit = Math.min(text.length, APP_CONFIG.PREVIEW_CHAR_CAP);
  let idx = 0;
  let cursor = 0;

  function step() {
    if (state.renderSeq !== renderToken) return;
    const fragment = document.createDocumentFragment();
    let count = 0;

    while (idx < spans.length && count < APP_CONFIG.DIFF_CHUNK_SIZE) {
      const span = spans[idx];
      const start = isSanitized ? span.sanitizedStart : span.start;
      const end = isSanitized ? span.sanitizedEnd : span.end;
      idx += 1;
      if (start < cursor || start >= limit) continue;
      const clampedEnd = Math.min(end, limit);
      if (start > cursor) fragment.appendChild(document.createTextNode(text.slice(cursor, start)));
      fragment.appendChild(createDiffMark(text.slice(start, clampedEnd), span, isSanitized));
      cursor = clampedEnd;
      count += 1;
    }

    if (idx < spans.length && cursor < limit) {
      container.appendChild(fragment);
      requestAnimationFrame(step);
      return;
    }

    if (cursor < limit) fragment.appendChild(document.createTextNode(text.slice(cursor, limit)));
    if (text.length > limit) {
      const note = document.createElement("span");
      note.className = "empty-state";
      note.textContent = `\n\n${noteText}`;
      fragment.appendChild(note);
    }
    container.appendChild(fragment);
  }

  step();
}

function renderDiffPane(container, text, spans, isSanitized, emptyMessage, renderToken) {
  if (!container) return;
  container.replaceChildren();
  if (!text) {
    const empty = document.createElement("span");
    empty.className = "empty-state";
    empty.textContent = emptyMessage;
    container.appendChild(empty);
    return;
  }

  if (text.length <= APP_CONFIG.LARGE_TEXT_THRESHOLD && spans.length <= APP_CONFIG.DIFF_CHUNK_SIZE) {
    const fragment = document.createDocumentFragment();
    let cursor = 0;
    for (const span of spans) {
      const start = isSanitized ? span.sanitizedStart : span.start;
      const end = isSanitized ? span.sanitizedEnd : span.end;
      if (start < cursor || start > text.length || end > text.length) continue;
      if (start > cursor) fragment.appendChild(document.createTextNode(text.slice(cursor, start)));
      fragment.appendChild(createDiffMark(text.slice(start, end), span, isSanitized));
      cursor = end;
    }
    if (cursor < text.length) fragment.appendChild(document.createTextNode(text.slice(cursor)));
    container.appendChild(fragment);
    return;
  }

  appendChunkedNodes(
    container,
    text,
    spans,
    isSanitized,
    renderToken,
    `[Preview truncated at ${formatBytes(APP_CONFIG.PREVIEW_CHAR_CAP)} to keep scrolling smooth — full ${formatBytes(text.length)} output is ready for Copy / Download.]`
  );
}

function formatRejectedSummary(rejected) {
  const labels = [
    ["luhn", "Luhn-failed"],
    ["verhoeff", "Verhoeff-failed"],
    ["ipv4", "invalid IP"],
    ["pan", "invalid PAN"],
    ["phone", "invalid phone"],
  ];
  const parts = labels.filter(([k]) => rejected[k] > 0).map(([k, lbl]) => `${rejected[k]} ${lbl}`);
  const total = labels.reduce((sum, [k]) => sum + (rejected[k] || 0), 0);
  return total === 0 ? "0 invalid candidates ignored" : `${total} invalid ignored (${parts.join(", ")})`;
}

function updateSummaryBadges(result) {
  const counts = Object.fromEntries(ENTITY_TYPES.map((t) => [t, 0]));
  for (const ent of result.entities) {
    if (Object.prototype.hasOwnProperty.call(counts, ent.type)) counts[ent.type] += 1;
  }
  for (const type of ENTITY_TYPES) {
    const badge = document.querySelector(`[data-count="${type}"]`);
    if (badge) badge.textContent = String(counts[type]);
    document.querySelector(`.detector-chip[data-type="${type}"]`)?.classList.toggle("is-disabled", !state.enabledTypes.has(type));
  }
  const totalEl = document.getElementById("total-detected-badge");
  if (totalEl) {
    const n = result.entities.length;
    totalEl.textContent = `${n} ${n === 1 ? "entity" : "entities"} detected`;
  }
  const rejectedEl = document.getElementById("rejected-summary-badge");
  if (rejectedEl) rejectedEl.textContent = formatRejectedSummary(result.rejected);

  const perfEl = document.getElementById("perf-badge");
  if (perfEl) {
    if (!result.originalText) perfEl.textContent = "Ready";
    else if (result.csvStats) {
      perfEl.textContent = `${result.csvStats.dataRows} CSV rows · ${result.csvStats.formulasGuarded} formula-guarded · ${result.durationMs.toFixed(1)} ms`;
    } else {
      perfEl.textContent = `Processed in ${result.durationMs.toFixed(1)} ms`;
    }
  }
}

function createMappingRow(entry) {
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
  return tr;
}

function renderMappingTable(result) {
  const tbody = document.getElementById("mapping-tbody");
  const countEl = document.getElementById("mapping-count");
  if (!tbody) return;
  tbody.replaceChildren();

  const entries = state.mode === "pseudonym" ? result.mapper.entries().filter((e) => e.count > 0) : [];
  if (countEl) countEl.textContent = `${entries.length} unique ${entries.length === 1 ? "entity" : "entities"} mapped`;

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
  for (const entry of entries) fragment.appendChild(createMappingRow(entry));
  tbody.appendChild(fragment);
}

function updateLineCounters(origText, sanText) {
  const origLines = countLines(origText);
  const sanLines = countLines(sanText);
  const inputMeta = document.getElementById("input-meta");
  const origLineEl = document.getElementById("original-line-count");
  const sanLineEl = document.getElementById("sanitized-line-count");
  if (inputMeta) inputMeta.textContent = `${origText.length.toLocaleString()} chars · ${origLines.toLocaleString()} lines`;
  if (origLineEl) origLineEl.textContent = `${origLines} ${origLines === 1 ? "line" : "lines"}`;
  if (sanLineEl) sanLineEl.textContent = `${sanLines} ${sanLines === 1 ? "line" : "lines"}`;
}

function applySanitizationResult(result) {
  state.lastResult = result;
  state.renderSeq += 1;
  const renderToken = state.renderSeq;

  updateLineCounters(result.originalText, result.sanitizedText);
  renderDiffPane(
    document.getElementById("original-diff"),
    result.originalText,
    result.entities,
    false,
    "Paste text, upload a .txt/.csv file, or load sample noisy data to inspect detected PII.",
    renderToken
  );
  renderDiffPane(
    document.getElementById("sanitized-diff"),
    result.sanitizedText,
    result.replacements,
    true,
    "Sanitized output will appear here in real time.",
    renderToken
  );
  updateSummaryBadges(result);
  renderMappingTable(result);

  const hasOutput = result.sanitizedText.length > 0;
  const copyBtn = document.getElementById("copy-output");
  const downloadBtn = document.getElementById("download-output");
  const aiReviewBtn = document.getElementById("ai-review-btn");
  if (copyBtn) copyBtn.disabled = !hasOutput;
  if (downloadBtn) downloadBtn.disabled = !hasOutput;
  if (aiReviewBtn) aiReviewBtn.disabled = !hasOutput;

  if (state.announceCountsOnNextResult) {
    state.announceCountsOnNextResult = false;
    announce(`${result.entities.length} PII entities detected. ${formatRejectedSummary(result.rejected)}.`);
  }
}

function getOrCreateWorker() {
  if (state.worker || typeof Worker === "undefined") return state.worker;
  try {
    state.worker = new Worker(new URL("./worker.js", import.meta.url), { type: "module" });
    state.worker.addEventListener("message", (event) => {
      const { requestId, ok, result, error } = event.data || {};
      if (requestId !== state.requestSeq) return;
      if (!ok) {
        setFileStatus(`Processing error: ${error || "Worker failed."}`, true);
        return;
      }
      state.mapper = createPseudonymMapper(result.mapperEntries || []);
      applySanitizationResult({ ...result, mapper: state.mapper });
    });
    state.worker.addEventListener("error", () => {
      state.worker?.terminate();
      state.worker = null;
      processInputOnMainThread();
    });
  } catch {
    state.worker = null;
  }
  return state.worker;
}

function processInputOnMainThread() {
  try {
    const text = document.getElementById("raw-input")?.value || "";
    if (!state.persistMapping) state.mapper.reset();
    else state.mapper.beginRun();

    const result = runSanitization(text, {
      format: state.format,
      enabledTypes: state.enabledTypes,
      mode: state.mode,
      typedFullMask: state.typedFullMask,
      mapper: state.mapper,
    });
    applySanitizationResult(result);
  } catch (err) {
    setFileStatus(`Processing error: ${err?.message || "Unable to sanitize input."}`, true);
    announce("An error occurred while processing input.");
  }
}

function processInput() {
  const text = document.getElementById("raw-input")?.value || "";
  const worker = getOrCreateWorker();
  if (!worker || text.length === 0) {
    processInputOnMainThread();
    return;
  }

  state.requestSeq += 1;
  if (!state.persistMapping) state.mapper.reset();
  worker.postMessage({
    requestId: state.requestSeq,
    text,
    format: state.format,
    enabledTypes: Array.from(state.enabledTypes),
    mode: state.mode,
    typedFullMask: state.typedFullMask,
    persistMapping: state.persistMapping,
    mapperEntries: state.persistMapping ? state.mapper.entries() : [],
  });
}

function scheduleProcess() {
  if (state.debounceTimer) clearTimeout(state.debounceTimer);
  state.debounceTimer = setTimeout(processInput, APP_CONFIG.DEBOUNCE_MS);
}

function syncPaneScroll(source, target) {
  if (!source || !target || (state.syncLock && state.syncLock !== source)) return;
  state.syncLock = source;
  const maxSourceY = Math.max(1, source.scrollHeight - source.clientHeight);
  const maxTargetY = Math.max(0, target.scrollHeight - target.clientHeight);
  target.scrollTop = Math.round((source.scrollTop / maxSourceY) * maxTargetY);
  target.scrollLeft = source.scrollLeft;
  requestAnimationFrame(() => {
    if (state.syncLock === source) state.syncLock = null;
  });
}

function downloadSanitized() {
  const text = state.lastResult?.sanitizedText;
  if (!text) return;
  const ext = state.format === "csv" ? "csv" : "txt";
  const dotIdx = state.fileName ? state.fileName.lastIndexOf(".") : -1;
  const filename = state.fileName
    ? `${dotIdx > 0 ? state.fileName.slice(0, dotIdx) : state.fileName}.maskwise-sanitized.${ext}`
    : `maskwise-sanitized.${ext}`;
  const blob = new Blob([text], { type: state.format === "csv" ? "text/csv;charset=utf-8" : "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  announce(`Downloaded ${filename}`);
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
    } catch (err) {
      announce(`Clipboard API unavailable (${err?.name || "permission"}); trying fallback.`);
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
    } catch (err) {
      announce(`Copy failed: ${err?.message || "select output manually."}`);
    }
    document.body.removeChild(temp);
  }
  if (copyLabel) {
    copyLabel.textContent = copied ? "Copied!" : "Copy failed";
    if (state.copyTimer) clearTimeout(state.copyTimer);
    state.copyTimer = setTimeout(() => {
      copyLabel.textContent = "Copy sanitized";
    }, APP_CONFIG.COPY_FEEDBACK_MS);
  }
}

function isAllowedFileType(file, ext) {
  if (!ALLOWED_EXTENSIONS.has(ext)) return false;
  const mime = (file.type || "").split(";")[0].trim().toLowerCase();
  return mime === "" || ALLOWED_MIME_TYPES.has(mime);
}

function handleSelectedFile(file) {
  if (!file) return;
  const ext = getFileExtension(file.name);
  if (!isAllowedFileType(file, ext)) {
    setFileStatus(
      `Unsupported file "${file.name}" (${file.type || "unknown MIME"}). Only .txt and .csv files are accepted.`,
      true
    );
    return;
  }
  if (file.size > APP_CONFIG.MAX_FILE_BYTES) {
    setFileStatus(`File too large: "${file.name}" is ${formatBytes(file.size)} (max 5 MB).`, true);
    return;
  }
  const reader = new FileReader();
  reader.onload = () => {
    const rawInput = document.getElementById("raw-input");
    if (!rawInput || !(reader.result instanceof ArrayBuffer)) return;
    try {
      const decoder = new TextDecoder("utf-8", { fatal: true });
      rawInput.value = decoder.decode(reader.result);
    } catch {
      setFileStatus(`Encoding error: "${file.name}" is not valid UTF-8 text.`, true);
      announce("File rejected due to invalid UTF-8 encoding.");
      return;
    }
    state.fileName = file.name;
    state.fileExt = ext;
    state.format = ext === "csv" ? "csv" : "text";
    if (!state.persistMapping) state.mapper.reset();
    syncFormatButtons();
    setFileStatus(`Loaded "${file.name}" (${formatBytes(file.size)}) locally`);
    state.announceCountsOnNextResult = true;
    processInput();
  };
  reader.onerror = () => {
    setFileStatus(`Failed to read "${file.name}" locally.`, true);
    announce(`Failed to read ${file.name}`);
  };
  reader.readAsArrayBuffer(file);
}

function wipeSensitiveState() {
  const rawInput = document.getElementById("raw-input");
  const fileInput = document.getElementById("file-input");
  if (rawInput) rawInput.value = "";
  if (fileInput) fileInput.value = "";
  state.fileName = null;
  state.lastResult = null;
  state.mapper.reset();
  document.getElementById("original-diff")?.replaceChildren();
  document.getElementById("sanitized-diff")?.replaceChildren();
  const aiNote = document.getElementById("ai-review-note");
  if (aiNote) {
    aiNote.textContent = "";
    aiNote.hidden = true;
  }
}

function loadSample(kind) {
  const rawInput = document.getElementById("raw-input");
  if (!rawInput) return;
  const isCsv = kind === "csv";
  rawInput.value = isCsv ? SAMPLE_NOISY_CSV : SAMPLE_NOISY_TEXT;
  state.fileName = isCsv ? "sample-records.csv" : "sample-noisy-log.txt";
  state.fileExt = isCsv ? "csv" : "txt";
  state.format = isCsv ? "csv" : "text";
  setFileStatus(
    isCsv ? "Loaded sample noisy CSV (4 data rows + header)" : "Loaded sample noisy text (ticket, resume, clinical note, server log)"
  );
  if (!state.persistMapping) state.mapper.reset();
  syncFormatButtons();
  state.announceCountsOnNextResult = true;
  processInput();
}

const THEME_STORAGE_KEY = "maskwise-theme"; // Theme preference only; never stores user text or PII
const LEGACY_THEME_KEY = "cloaktext-theme"; // Intentional one-time fallback for users switching from old key

function readStoredTheme() {
  try {
    const saved = window.localStorage?.getItem(THEME_STORAGE_KEY);
    if (saved === "light" || saved === "dark") return saved;
    const legacy = window.localStorage?.getItem(LEGACY_THEME_KEY);
    if (legacy === "light" || legacy === "dark") {
      window.localStorage?.setItem(THEME_STORAGE_KEY, legacy);
      window.localStorage?.removeItem(LEGACY_THEME_KEY);
      return legacy;
    }
  } catch {
    return null;
  }
  return null;
}

function saveThemePreference(theme) {
  try {
    window.localStorage?.setItem(THEME_STORAGE_KEY, theme);
  } catch {
    // Ignore storage denial in restricted browser contexts
  }
}

function applyTheme(theme) {
  state.theme = theme;
  document.documentElement.setAttribute("data-theme", theme);
  const themeBtn = document.getElementById("theme-toggle");
  const themeLabel = themeBtn?.querySelector(".theme-label");
  themeBtn?.setAttribute("aria-pressed", String(theme === "dark"));
  if (themeLabel) themeLabel.textContent = theme === "light" ? "Dark" : "Light";
}

function bindModeAndThemeEvents() {
  // Force light theme — dark mode disabled
  document.documentElement.setAttribute("data-theme", "light");

  const modeButtons = document.querySelectorAll(".seg-btn[data-mode]");
  const activateMode = (btn) => {
    state.mode = btn.dataset.mode || "full";
    modeButtons.forEach((b) => {
      const active = b === btn;
      b.classList.toggle("is-active", active);
      b.setAttribute("aria-checked", String(active));
      b.setAttribute("tabindex", active ? "0" : "-1");
    });
    const typedOption = document.getElementById("typed-mask-option");
    const pseudoActions = document.getElementById("pseudonym-actions");
    if (typedOption) typedOption.hidden = state.mode !== "full";
    if (pseudoActions) pseudoActions.hidden = state.mode !== "pseudonym";
    if (state.mode !== "pseudonym") {
      state.mappingOpen = false;
      const mappingPanel = document.getElementById("mapping-panel");
      const toggleMappingBtn = document.getElementById("toggle-mapping-btn");
      if (mappingPanel) mappingPanel.hidden = true;
      if (toggleMappingBtn) {
        toggleMappingBtn.setAttribute("aria-expanded", "false");
        toggleMappingBtn.textContent = "Show mapping table";
      }
    }
    processInput();
    announce(`Redaction mode set to ${btn.textContent?.trim() || state.mode}`);
  };
  modeButtons.forEach((btn) => btn.addEventListener("click", () => activateMode(btn)));
  wireRovingGroup(modeButtons, activateMode);
}

function bindFormatAndDetectorEvents() {
  const formatButtons = document.querySelectorAll(".format-btn[data-format]");
  const activateFormat = (btn) => {
    state.format = btn.dataset.format === "csv" ? "csv" : "text";
    state.fileExt = state.format === "csv" ? "csv" : "txt";
    syncFormatButtons();
    processInput();
    announce(`Input format set to ${state.format === "csv" ? "CSV" : "Plain Text"}`);
  };
  formatButtons.forEach((btn) => btn.addEventListener("click", () => activateFormat(btn)));
  wireRovingGroup(formatButtons, activateFormat);

  document.querySelectorAll("[data-detector]").forEach((cb) => {
    cb.addEventListener("change", () => {
      const type = cb.dataset.detector;
      if (!type) return;
      if (cb.checked) state.enabledTypes.add(type);
      else state.enabledTypes.delete(type);
      scheduleProcess();
    });
  });

  document.getElementById("typed-mask-toggle")?.addEventListener("change", (e) => {
    state.typedFullMask = Boolean(e.target.checked);
    processInput();
  });
  document.getElementById("persist-mapping-toggle")?.addEventListener("change", (e) => {
    state.persistMapping = Boolean(e.target.checked);
    processInput();
  });
  document.getElementById("toggle-mapping-btn")?.addEventListener("click", (e) => {
    state.mappingOpen = !state.mappingOpen;
    const panel = document.getElementById("mapping-panel");
    if (panel) panel.hidden = !state.mappingOpen;
    e.currentTarget.setAttribute("aria-expanded", String(state.mappingOpen));
    e.currentTarget.textContent = state.mappingOpen ? "Hide mapping table" : "Show mapping table";
  });
  document.getElementById("reset-mapping-btn")?.addEventListener("click", () => {
    state.mapper.reset();
    processInput();
    announce("Pseudonym mapping table reset");
  });
}

function bindInputAndExportEvents() {
  const rawInput = document.getElementById("raw-input");
  const dropzone = document.getElementById("dropzone");
  const fileInput = document.getElementById("file-input");

  rawInput?.addEventListener("input", scheduleProcess);
  document.getElementById("load-sample-text")?.addEventListener("click", () => loadSample("text"));
  document.getElementById("load-sample-csv")?.addEventListener("click", () => loadSample("csv"));
  document.getElementById("clear-input")?.addEventListener("click", () => {
    wipeSensitiveState();
    setFileStatus("No file loaded");
    processInput();
  });

  window.addEventListener("pagehide", wipeSensitiveState);
  window.addEventListener("beforeunload", wipeSensitiveState);

  document.getElementById("browse-files-btn")?.addEventListener("click", () => fileInput?.click());
  dropzone?.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropzone.classList.add("is-dragover");
  });
  dropzone?.addEventListener("dragleave", () => dropzone.classList.remove("is-dragover"));
  dropzone?.addEventListener("drop", (e) => {
    e.preventDefault();
    dropzone.classList.remove("is-dragover");
    handleSelectedFile(e.dataTransfer?.files?.[0]);
  });
  fileInput?.addEventListener("change", () => handleSelectedFile(fileInput.files?.[0]));

  const tabButtons = document.querySelectorAll(".tab-btn[data-tab]");
  const activateTab = (btn) => {
    const target = btn.dataset.tab;
    tabButtons.forEach((b) => {
      const active = b === btn;
      b.classList.toggle("is-active", active);
      b.setAttribute("aria-selected", String(active));
      b.setAttribute("tabindex", active ? "0" : "-1");
    });
    document.getElementById("pane-original")?.classList.toggle("is-active", target === "original");
    document.getElementById("pane-sanitized")?.classList.toggle("is-active", target === "sanitized");
  };
  tabButtons.forEach((btn) => btn.addEventListener("click", () => activateTab(btn)));
  wireRovingGroup(tabButtons, activateTab);

  const originalDiff = document.getElementById("original-diff");
  const sanitizedDiff = document.getElementById("sanitized-diff");
  originalDiff?.addEventListener("scroll", () => syncPaneScroll(originalDiff, sanitizedDiff));
  sanitizedDiff?.addEventListener("scroll", () => syncPaneScroll(sanitizedDiff, originalDiff));
  document.getElementById("copy-output")?.addEventListener("click", copySanitized);
  document.getElementById("download-output")?.addEventListener("click", downloadSanitized);
  document.getElementById("ai-review-btn")?.addEventListener("click", runOnDeviceAIReview);
}

async function runOnDeviceAIReview() {
  const noteEl = document.getElementById("ai-review-note");
  const sanitizedText = state.lastResult?.sanitizedText;
  if (!noteEl || !sanitizedText) return;

  noteEl.hidden = false;
  const promptApi = globalThis.LanguageModel || window.ai?.languageModel;
  if (!promptApi) {
    noteEl.textContent =
      "On-device Gemini Nano is unavailable in this browser. Deterministic local regex + checksum redaction remains 100% active with zero network calls.";
    announce("On-device AI is unavailable in this browser.");
    return;
  }

  try {
    const availability = promptApi.availability
      ? await promptApi.availability()
      : (await promptApi.capabilities?.())?.available;
    if (availability === "no" || availability === "unavailable") {
      noteEl.textContent =
        "On-device Gemini Nano model is not downloaded on this device. No external request was made.";
      return;
    }
    noteEl.textContent = "Running local on-device Gemini Nano review...";
    const session = await promptApi.create({
      systemPrompt:
        "You review already-redacted text locally. Briefly list any remaining unstructured PII hints (person names, street addresses) or say 'No obvious missed PII found.'",
    });
    const reply = await session.prompt(sanitizedText.slice(0, 4000));
    session.destroy?.();
    noteEl.textContent = `On-device AI review: ${String(reply || "").trim()}`;
    announce("On-device AI review completed.");
  } catch (err) {
    noteEl.textContent = `On-device AI review skipped (${err?.message || "unavailable"}). Zero network calls were made.`;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  bindModeAndThemeEvents();
  bindFormatAndDetectorEvents();
  bindInputAndExportEvents();
  syncFormatButtons();
  processInput();
});
