/**
 * CloakText UI controller — Phase 1 base interactions (theme toggle, mode UI, mobile tabs).
 */

import { runSanitization } from "./pipeline.js";

const state = {
  theme: "light",
  mode: "full",
};

function initPhase1Shell() {
  const themeBtn = document.getElementById("theme-toggle");
  const themeLabel = themeBtn?.querySelector(".theme-label");
  const modeButtons = document.querySelectorAll(".seg-btn[data-mode]");
  const tabButtons = document.querySelectorAll(".tab-btn[data-tab]");
  const paneOriginal = document.getElementById("pane-original");
  const paneSanitized = document.getElementById("pane-sanitized");
  const rawInput = document.getElementById("raw-input");
  const inputMeta = document.getElementById("input-meta");

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

  rawInput?.addEventListener("input", () => {
    const len = rawInput.value.length;
    if (inputMeta) {
      inputMeta.textContent = `${len} chars · plain text`;
    }
    runSanitization(rawInput.value, { mode: state.mode });
  });
}

document.addEventListener("DOMContentLoaded", initPhase1Shell);
