/**
 * Mobbin-Inspired Landing Page Controller for Maskwise.
 * Handles theme persistence, mobile drawer navigation, interactive tab filters,
 * and client-side agent preview simulations.
 * Intentionally isolates detection/redaction modules to keep "/" lightweight and instantaneous.
 */

import { initHeadlineRotator } from "./landing-rotator.js";

/**
 * Force light theme on the landing page (dark mode disabled).
 *
 * @returns {void}
 */
export function initLandingTheme() {
  document.documentElement.setAttribute("data-theme", "light");
}

/**
 * Initialize mobile navigation drawer toggle.
 *
 * @returns {void}
 */
export function initMobileNav() {
  const toggleBtn = document.getElementById("mobile-menu-toggle");
  const mobileNav = document.getElementById("mobile-nav");
  if (!toggleBtn || !mobileNav) return;

  toggleBtn.addEventListener("click", () => {
    const isExpanded = toggleBtn.getAttribute("aria-expanded") === "true";
    toggleBtn.setAttribute("aria-expanded", String(!isExpanded));
    mobileNav.hidden = isExpanded;
  });

  // Close mobile nav when clicking any link inside it
  mobileNav.querySelectorAll("a").forEach((link) => {
    link.addEventListener("click", () => {
      toggleBtn.setAttribute("aria-expanded", "false");
      mobileNav.hidden = true;
    });
  });
}

/**
 * Workflow scenarios dataset for the interactive problem-to-solution tab switcher.
 */
const WORKFLOW_SCENARIOS = {
  support: {
    old: `Customer: rahul.sharma@enterprise.com
Phone: +91 98765 12345
Issue: Card ending in 4532 0151 1283 0366 charged twice.
Aadhaar verified: 9999 9999 0019
Server IP: 10.0.4.15`,
    new: `Customer: USER_01
Phone: PHONE_01
Issue: Card ending in CARD_01 charged twice.
Aadhaar verified: AADHAAR_01
Server IP: IP_01`
  },
  ai: {
    old: `Prompt: "Analyze high-risk refund request for client demo.user@example.test (Mobile +91 98765 43210).
Tax ID attached: ABCPE1234F.
Visa token: 4532-0151-1283-0366 from gateway 192.168.1.100."`,
    new: `Prompt: "Analyze high-risk refund request for client USER_01 (Mobile PHONE_01).
Tax ID attached: PAN_01.
Visa token: CARD_01 from gateway IP_01."`
  },
  dev: {
    old: `[ERROR] 2026-11-27 10:42:19 client 192.168.1.50 auth failure for admin@internal.net:
Payload: { pan: "ABCPE1234F", uid: "9999 9999 0019", card: "4532-0151-1283-0366" }
Exception trace logged at /var/log/auth.log`,
    new: `[ERROR] 2026-11-27 10:42:19 client IP_01 auth failure for USER_01:
Payload: { pan: "PAN_01", uid: "AADHAAR_01", card: "CARD_01" }
Exception trace logged at /var/log/auth.log`
  },
  hr: {
    old: `Employee: ananya.deshmukh@corp.in
Official PAN: ABCDE5678K
UIDAI Aadhaar: 9999 9999 0019
Direct Deposit Account Card: 4532 0151 1283 0366
Emergency Contact: +91 91234 56789`,
    new: `Employee: USER_01
Official PAN: PAN_01
UIDAI Aadhaar: AADHAAR_01
Direct Deposit Account Card: CARD_01
Emergency Contact: PHONE_01`
  }
};

/**
 * Initialize interactive problem-to-solution pill tabs.
 *
 * @returns {void}
 */
export function initWorkflowTabs() {
  const tabs = Array.from(document.querySelectorAll(".tab-pill"));
  const panelEl = document.getElementById("workflow-panel");
  const oldCodeEl = document.getElementById("workflow-old-code");
  const newCodeEl = document.getElementById("workflow-new-code");
  if (!tabs.length || !oldCodeEl || !newCodeEl) return;

  const activateTab = (tab) => {
    tabs.forEach((t) => {
      const isSelected = t === tab;
      t.classList.toggle("active", isSelected);
      t.setAttribute("aria-selected", String(isSelected));
      t.setAttribute("tabindex", isSelected ? "0" : "-1");
    });

    if (panelEl && tab.id) panelEl.setAttribute("aria-labelledby", tab.id);

    const scenarioKey = tab.getAttribute("data-scenario") || "support";
    const scenario = WORKFLOW_SCENARIOS[scenarioKey] || WORKFLOW_SCENARIOS.support;

    oldCodeEl.textContent = scenario.old;
    newCodeEl.textContent = scenario.new;
  };

  tabs.forEach((tab, idx) => {
    tab.addEventListener("click", () => activateTab(tab));
    tab.addEventListener("keydown", (event) => {
      let nextIdx = -1;
      if (event.key === "ArrowRight" || event.key === "ArrowDown") nextIdx = (idx + 1) % tabs.length;
      else if (event.key === "ArrowLeft" || event.key === "ArrowUp") nextIdx = (idx - 1 + tabs.length) % tabs.length;
      else if (event.key === "Home") nextIdx = 0;
      else if (event.key === "End") nextIdx = tabs.length - 1;
      if (nextIdx !== -1) {
        event.preventDefault();
        tabs[nextIdx].focus();
        activateTab(tabs[nextIdx]);
      }
    });
  });
}

/**
 * Initialize simulated interactive agent scan filter.
 *
 * @returns {void}
 */
export function initAgentPreview() {
  const runBtn = document.getElementById("run-agent-preview");
  if (!runBtn) return;

  const steps = [
    document.getElementById("agent-step-1"),
    document.getElementById("agent-step-2"),
    document.getElementById("agent-step-3"),
    document.getElementById("agent-step-4")
  ].filter(Boolean);

  let isRunning = false;

  runBtn.addEventListener("click", () => {
    if (isRunning) return;
    isRunning = true;
    runBtn.disabled = true;

    // Reset status steps
    steps.forEach((step, index) => {
      if (index === 0) {
        step.classList.add("active");
      } else {
        step.classList.remove("active");
      }
    });

    // Animate through sequence
    let current = 1;
    const interval = setInterval(() => {
      if (current < steps.length) {
        steps[current]?.classList.add("active");
        current++;
      } else {
        clearInterval(interval);
        isRunning = false;
        runBtn.disabled = false;
      }
    }, 400);
  });
}

/**
 * Root bootstrap for landing page
 */
export function initLandingPage() {
  initLandingTheme();
  initMobileNav();
  initWorkflowTabs();
  initAgentPreview();
  initHeadlineRotator();
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initLandingPage);
} else {
  initLandingPage();
}
