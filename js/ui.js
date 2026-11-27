/**
 * CloakText UI controller — Phase 4 input handling, file validation,
 * FileReader local loading, format toggling, and debounced pipeline execution.
 */

import { createPseudonymMapper } from "./redactors.js";
import { runSanitization } from "./pipeline.js";

const MAX_FILE_BYTES = 5 * 1024 * 1024; // 5 MB client-side cap
const ALLOWED_EXTENSIONS = new Set(["txt", "csv"]);

const state = {
  theme: "light",
  mode: "full",
  format: "text",
  typedFullMask: false,
  persistMapping: false,
  fileName: null,
  fileExt: "txt",
  enabledTypes: new Set(["credit_card", "aadhaar", "pan", "phone", "ip", "email"]),
  mapper: createPseudonymMapper(),
  lastResult: null,
  debounceTimer: null,
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

function setFileStatus(message, isError = false) {
  const statusEl = document.getElementById("file-status");
  if (!statusEl) return;
  statusEl.textContent = message;
  statusEl.classList.toggle("is-error", isError);
}

function updateInputMeta(text) {
  const metaEl = document.getElementById("input-meta");
  if (!metaEl) return;
  const lineCount = text.length === 0 ? 0 : text.split(/\r\n|\n|\r/).length;
  metaEl.textContent = `${text.length.toLocaleString()} chars · ${lineCount.toLocaleString()} lines`;
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
  updateInputMeta(text);

  // Temporary Phase 4 text-only preview until Phase 5 side-by-side highlight renderer
  const originalDiff = document.getElementById("original-diff");
  const sanitizedDiff = document.getElementById("sanitized-diff");
  const copyBtn = document.getElementById("copy-output");
  const downloadBtn = document.getElementById("download-output");

  if (originalDiff) {
    originalDiff.textContent = text || "Paste text, upload a .txt/.csv file, or load sample noisy data to inspect detected PII.";
  }
  if (sanitizedDiff) {
    sanitizedDiff.textContent = result.sanitizedText || "Sanitized output will appear here in real time.";
  }
  if (copyBtn) copyBtn.disabled = result.sanitizedText.length === 0;
  if (downloadBtn) downloadBtn.disabled = result.sanitizedText.length === 0;
}

function scheduleProcess() {
  if (state.debounceTimer) {
    clearTimeout(state.debounceTimer);
  }
  state.debounceTimer = setTimeout(processInput, 120);
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
    const content = typeof reader.result === "string" ? reader.result : "";
    rawInput.value = content;
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

function bindEvents() {
  const themeBtn = document.getElementById("theme-toggle");
  const themeLabel = themeBtn?.querySelector(".theme-label");
  const modeButtons = document.querySelectorAll(".seg-btn[data-mode]");
  const formatButtons = document.querySelectorAll(".format-btn[data-format]");
  const tabButtons = document.querySelectorAll(".tab-btn[data-tab]");
  const paneOriginal = document.getElementById("pane-original");
  const paneSanitized = document.getElementById("pane-sanitized");
  const rawInput = document.getElementById("raw-input");
  const dropzone = document.getElementById("dropzone");
  const fileInput = document.getElementById("file-input");
  const clearBtn = document.getElementById("clear-input");
  const typedToggle = document.getElementById("typed-mask-toggle");
  const persistToggle = document.getElementById("persist-mapping-toggle");

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

  rawInput?.addEventListener("input", scheduleProcess);

  typedToggle?.addEventListener("change", () => {
    state.typedFullMask = Boolean(typedToggle.checked);
    processInput();
  });

  persistToggle?.addEventListener("change", () => {
    state.persistMapping = Boolean(persistToggle.checked);
    processInput();
  });

  clearBtn?.addEventListener("click", () => {
    if (rawInput) rawInput.value = "";
    state.fileName = null;
    if (fileInput) fileInput.value = "";
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
    const file = event.dataTransfer?.files?.[0];
    handleSelectedFile(file);
  });

  fileInput?.addEventListener("change", () => {
    const file = fileInput.files?.[0];
    handleSelectedFile(file);
  });

  syncFormatButtons();
  processInput();
}

document.addEventListener("DOMContentLoaded", bindEvents);
