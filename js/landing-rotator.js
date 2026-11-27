/**
 * Headline Rotator Module for Maskwise.
 * Rotates 3 keywords with 150ms stagger and 2000ms loop interval.
 * Accessible: pauses on hover, focus, visibilitychange, and explicit toggle button.
 * Respects prefers-reduced-motion; transform and opacity only.
 */

export function createRotatorState(options = {}) {
  const variantCount = options.variantCount || 3;
  const loopInterval = options.interval || 2000;
  const staggerDelay = options.stagger || 150;
  let currentIndex = 0;
  let isPaused = false;

  return {
    get currentIndex() {
      return currentIndex;
    },
    get isPaused() {
      return isPaused;
    },
    variantCount,
    loopInterval,
    staggerDelay,
    next() {
      currentIndex = (currentIndex + 1) % variantCount;
      return currentIndex;
    },
    tick() {
      return isPaused ? currentIndex : this.next();
    },
    pause() {
      isPaused = true;
    },
    resume() {
      isPaused = false;
    },
    togglePause() {
      isPaused = !isPaused;
      return isPaused;
    }
  };
}

/**
 * Initialize rotating headline keyword pills in the DOM.
 *
 * @returns {(() => void) | null} Cleanup function
 */
export function initHeadlineRotator() {
  if (typeof window === "undefined" || window.matchMedia?.("(prefers-reduced-motion: reduce)")?.matches) {
    return null;
  }

  const headlineEl = document.querySelector(".hero-title");
  const slots = Array.from(document.querySelectorAll(".rotator-slot"));
  const toggleBtn = document.getElementById("headline-rotator-toggle");

  if (!headlineEl || slots.length === 0) return null;

  const state = createRotatorState();
  let timerId = null;
  let staggerTimeouts = [];
  let userPaused = false;

  function setSlot(slot, nextIdx) {
    const active = slot.querySelector('.rotator-item[data-active="true"]');
    const nextItem = slot.querySelector(`.rotator-item[data-variant="${nextIdx}"]`);
    if (!nextItem || active === nextItem) return;

    if (active) {
      active.setAttribute("data-active", "false");
      active.setAttribute("data-exiting", "true");
      active.setAttribute("aria-hidden", "true");
      setTimeout(() => active.removeAttribute("data-exiting"), 350);
    }
    nextItem.setAttribute("data-active", "true");
    nextItem.removeAttribute("data-exiting");
    nextItem.setAttribute("aria-hidden", "false");
  }

  function advance() {
    if (state.isPaused || userPaused) return;
    const nextIdx = state.next();
    slots.forEach((slot, i) => {
      staggerTimeouts.push(setTimeout(() => setSlot(slot, nextIdx), i * state.staggerDelay));
    });
  }

  function start() {
    stop();
    timerId = setInterval(advance, state.loopInterval);
  }

  function stop() {
    if (timerId) clearInterval(timerId);
    timerId = null;
    staggerTimeouts.forEach(clearTimeout);
    staggerTimeouts = [];
  }

  function updateBtn(paused) {
    if (!toggleBtn) return;
    toggleBtn.setAttribute("aria-pressed", String(paused));
    const label = toggleBtn.querySelector(".rotator-toggle-label");
    if (label) label.textContent = paused ? "Resume animation" : "Pause animation";
  }

  toggleBtn?.addEventListener("click", () => {
    userPaused = !userPaused;
    if (userPaused) {
      state.pause();
      stop();
    } else {
      state.resume();
      start();
    }
    updateBtn(userPaused);
  });

  const pauseTemp = () => {
    if (!userPaused) {
      state.pause();
      stop();
    }
  };

  const resumeTemp = () => {
    if (!userPaused) {
      state.resume();
      start();
    }
  };

  headlineEl.addEventListener("mouseenter", pauseTemp);
  headlineEl.addEventListener("mouseleave", resumeTemp);
  headlineEl.addEventListener("focusin", pauseTemp);
  headlineEl.addEventListener("focusout", resumeTemp);

  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "hidden") stop();
    else if (!userPaused) resumeTemp();
  });

  start();

  const cleanup = () => {
    stop();
    window.removeEventListener("pagehide", cleanup);
  };
  window.addEventListener("pagehide", cleanup, { once: true });
  return cleanup;
}
