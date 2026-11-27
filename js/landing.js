/**
 * Minimal landing page controller — handles theme persistence and OS color-scheme sync.
 * Intentionally avoids loading detection/redaction modules to keep "/" lightweight.
 */

const THEME_STORAGE_KEY = "maskwise-theme"; // Theme preference only; never stores user text or PII
const LEGACY_THEME_KEY = "cloaktext-theme"; // Intentional one-time fallback for users switching from old key

function applyTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  const toggleBtn = document.getElementById("theme-toggle");
  const labelEl = toggleBtn?.querySelector(".theme-label");
  toggleBtn?.setAttribute("aria-pressed", String(theme === "dark"));
  if (labelEl) {
    labelEl.textContent = theme === "light" ? "Dark" : "Light";
  }
}

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

/**
 * Initialize landing page theme toggle and prefers-color-scheme listener.
 *
 * @returns {void}
 */
export function initLandingTheme() {
  const mediaQuery = window.matchMedia?.("(prefers-color-scheme: dark)");
  const stored = readStoredTheme();
  let activeTheme = stored || (mediaQuery?.matches ? "dark" : "light");
  applyTheme(activeTheme);

  mediaQuery?.addEventListener("change", (event) => {
    if (!readStoredTheme()) {
      activeTheme = event.matches ? "dark" : "light";
      applyTheme(activeTheme);
    }
  });

  document.getElementById("theme-toggle")?.addEventListener("click", () => {
    activeTheme = activeTheme === "light" ? "dark" : "light";
    saveThemePreference(activeTheme);
    applyTheme(activeTheme);
  });
}

document.addEventListener("DOMContentLoaded", initLandingTheme);
