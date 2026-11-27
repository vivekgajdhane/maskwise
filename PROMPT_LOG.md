# Prompt Log — Maskwise (PromptWars x NIAT_Pune)

Chronological log of prompts, design intent, and verified outcomes across all build phases.

## User Prompts Logged

### Prompt 1 — Initial Architecture & Hackathon Guardrails
- **Summary**: Requested a dependency-free, client-side browser PII sanitizer built on `main` (under 10 MB, no build step, strict CSP `connect-src 'none'`, no network/analytics/`localStorage` calls) covering Emails, Phones, IPs, PAN, Aadhaar, and Credit Cards (Luhn validated) across Full Mask, Partial Mask, and Consistent Pseudonymization modes, starting with Phase 1 scaffolding.
- **Outcome**: Established project layout, single-branch `main` workflow, offline ES module architecture, and CSP baseline.

### Prompt 2 — Full 9-Phase Specification, Design System & Product Polish
- **Summary**: Expanded requirements across all 9 phases, specifying the 4-color palette (`#F3F3E0`, `#CBDCEB`, `#608BC1`, `#133E87`) with dark-mode inversion, self-hosted `Sora` `.woff2` + `Helvetica Neue` typography, human-made flat UI rules (1px borders, 6–8px radius, inline SVGs, distinct underline + tag highlights, >=44px touch targets, responsive desktop/tablet/mobile layouts), Verhoeff Aadhaar validation, PAN holder codes, IPv4/IPv6 strict bounds, RFC-4180 CSV with formula-injection guard, XSS-safe DOM rendering, test suite, documentation, and pre-submission audit.
- **Outcome**: Executed sequentially across Phases 1–9 with verification checks and one git commit per phase on `main`.

---

## Phase-by-Phase Engineering Log

## Phase 1: Architecture, Scaffolding, CSP, and Design System
- **Intent**: Scaffold a zero-dependency vanilla HTML/CSS/ES-module application with strict CSP (`connect-src 'none'`), self-hosted Sora `.woff2` fonts, exact 4-color palette (`#F3F3E0`, `#CBDCEB`, `#608BC1`, `#133E87`) with WCAG AA contrast and dark-mode inversion, accessible PII highlight CSS marks, and modular `js/` layout.
- **Outcome**: Initialized `main` branch, self-hosted `fonts/sora-latin-{400,500,600,700}-normal.woff2`, built `index.html`, `css/styles.css`, and initial ES module shells under `js/`. Verified zero network API calls and strict CSP compliance (`9ae4b83`).

## Phase 2: Detection and Validation Engine
- **Intent**: Implement ReDoS-safe pattern detectors (`js/detectors.js`) and cryptographic/structural validators (`js/validators.js`) for Email, Phone (Indian + international), IPv4/IPv6, Indian PAN (holder-type validated), Aadhaar (Verhoeff checksum), and Credit Cards (Luhn + IIN issuer hints), with deterministic overlap resolution (`credit_card > aadhaar > pan > phone > ip > email`) and <=1s throughput on 1 MB of text.
- **Outcome**: Implemented `js/validators.js` and `js/detectors.js` using bucket-indexed overlap resolution and binary-search rejection deduplication, eliminating false positives on Luhn-failing numbers, Verhoeff-failing 12-digit strings, invalid IPs (`999.1.1.1`, `1.2.3.4.5`, leading zeros), and substrings of longer digit runs. Benchmarked 1 MB (1,048,576 bytes) with 18,165 entities in 37.8 ms (`ff957a5`).

## Phase 3: Redaction Modes and Consistent Pseudonymization
- **Intent**: Implement Full Mask (standard and typed `[REDACTED:TYPE]`), type-specific Partial Mask (preserving separators and partial verification context), and Consistent Pseudonymization (`USER_01`, `PHONE_01`, `CARD_01`, `AADHAAR_01`, `PAN_01`, `IP_01`) with input normalization and resettable mapping state in `js/redactors.js`.
- **Outcome**: Implemented `js/redactors.js` with `normalizeForMapping`, `createPseudonymMapper`, `formatReplacement`, and `redactText` tracking exact `originalStart`/`sanitizedStart` offsets for diff rendering. Verified formatting and mapping consistency across case and separator variants (`dbcd352`).

## Phase 4: Input Handling, RFC-4180 CSV, and Formula Guard
- **Intent**: Implement local-only `.txt`/`.csv` upload with 5 MB cap via `FileReader`, preserve line endings/whitespace in plain text, and build an RFC-4180 CSV parser/serializer (`js/csv.js`) that sanitizes cell-by-cell while preserving headers and defending against spreadsheet formula injection (`=`, `+`, `-`, `@`).
- **Outcome**: Built `js/csv.js`, wired `js/pipeline.js`, added Plain Text / CSV mode toggle in `index.html` and `css/styles.css`, and implemented drag-and-drop, file extension/size validation, and local `FileReader` loading in `js/ui.js`. Verified CSV round-trips, embedded commas/newlines/quotes, formula neutralization, and exact diff offsets (`65f72d4`).

## Phase 5: Audit View, Diff Highlighting, Samples, and Export
- **Intent**: Render live side-by-side highlighted diff panes via XSS-safe DOM text nodes (`textContent`), add synchronized scrolling, live per-type + rejected candidate counts, per-type detector toggles, 1-click Blob download and Copy export, mapping table drawer, and realistic sample text + CSV loaders.
- **Outcome**: Implemented `js/samples.js` (support ticket, resume, clinical note, server log + mixed CSV with valid PII, repeats, Luhn/Verhoeff/IP/PAN decoys, and formula payloads) and completed Phase 5 rendering/export/scroll-sync in `js/ui.js` with zero `innerHTML` (`ce48785`).

## Phase 6: UI Polish, Accessibility, and Responsive Audit
- **Intent**: Enforce WCAG AA contrast, >=44px touch targets, roving-tabindex keyboard navigation (`ArrowLeft`/`ArrowRight`/`Home`/`End`), skip link, ARIA live announcements, zero-404 `data:,` icon, `prefers-reduced-motion` support, and verify real headless Chrome rendering at 1440px, 768px, and 360px widths.
- **Outcome**: Updated `index.html`, `css/styles.css`, and `js/ui.js`; verified in real Chromium via CDP across 1440px, 768px, and 360px viewports (`scrollWidth === innerWidth`, `minTouchTarget === 44px`, `soraLoaded: true`, 0 external network requests, 0 console errors) (`593370e`).

## Phase 7: Automated Test Suite
- **Intent**: Build a dependency-free test suite runnable in both Node (`tests/tests.mjs`) and the browser (`tests/tests.html`) covering Luhn, Verhoeff, PAN holder codes, IPv4/IPv6 edge cases, overlapping priorities, partial-mask formats, pseudonym normalization/consistency, CSV round-trips, formula neutralization, and 1 MB throughput.
- **Outcome**: Created `tests/suite.js`, `tests/tests.mjs`, `tests/tests.js`, and `tests/tests.html`. All 10 test groups passed (`10/10`) in both Node and headless Chromium with zero failures and 1 MB benchmark within test 10 completing in 31.5 ms (`abc517f`).

## Phase 8: Documentation and Prompt Log
- **Intent**: Write comprehensive `README.md` (problem, features, detector/validator mechanics, mode examples, CSP/privacy guarantees, run instructions, limitations, screenshot placeholder) and finalize `PROMPT_LOG.md` documenting prompts and every phase.
- **Outcome**: Authored complete `README.md` and updated `PROMPT_LOG.md` chronologically (`5f1f690`).

## Phase 9: Pre-Submission Audit
- **Intent**: Perform final verification of repo size (< 10 MB), `.gitignore`, single `main` branch, security grep (no `fetch`/`XHR`/`WebSocket`/`sendBeacon`/`localStorage`/`http(s)://`/`innerHTML`), end-to-end interactive sample/modes/diff/export flow, and 360px/768px/1440px layouts.
- **Outcome**: Verified `du -sh .` is `700K` (including `.git`), `git branch -a` lists only `* main`, security grep returned 0 matches (`SECURITY_GREP_OK`), Node test suite passed `10/10`, and headless Chromium CDP audit verified all modes, CSV formula guard, mapping table, detector toggles, `sample-noisy-log.sanitized.txt` download trigger, `0` external requests, `0` console errors, and zero horizontal overflow across `360px`, `768px`, and `1440px`.

---

## Evaluation Parameter Hardening

### Parameter 1: Code Quality
- **Intent**: Centralize constants into `js/config.js`, keep all functions modular (`<= ~40` lines), add full JSDoc on every exported function, add `.editorconfig`, `.prettierrc`, and `eslint.config.js` (without `node_modules`), remove silent `catch` blocks, and add an `Architecture` section with module diagram and data flow to `README.md`.
- **Outcome**: Refactored `js/validators.js`, `js/detectors.js`, `js/redactors.js`, `js/csv.js`, `js/pipeline.js`, and `js/ui.js`; added `js/config.js` and lint/format configs; documented architecture in `README.md`. Verified `node --check` and `node tests/tests.mjs` (`10/10` passing) (`60880f5`).

### Parameter 2: Security
- **Intent**: Harden CSP (`worker-src 'self'`), add `<meta name="referrer" content="no-referrer">`, enforce extension + MIME allow-listing and fatal UTF-8 `TextDecoder` decoding on file uploads, wipe sensitive state on Reset and `pagehide`/`beforeunload`, run 50k-char ReDoS adversarial checks, prove zero `innerHTML`/`eval`/`new Function`/`document.write`/storage/network APIs via `grep`, and create `SECURITY.md`.
- **Outcome**: Updated `index.html`, `tests/tests.html`, `js/detectors.js`, and `js/ui.js`; authored `SECURITY.md`; eliminated `EMAIL_RE` quadratic backtracking on repeated `.`/`-`/`=` runs via negative lookbehind + bounded segments; verified zero dangerous sinks/network APIs via `grep` and sub-5ms ReDoS timings across all 50,000-char adversarial inputs (`82ac445`).

### Parameter 3: Efficiency
- **Intent**: Offload detection/redaction to an ES-module Web Worker (`js/worker.js`) with graceful main-thread fallback, add `requestAnimationFrame` chunked diff rendering with a 200 KB preview window for multi-MB inputs, build `tests/bench.js`, and measure exact asset sizes.
- **Outcome**: Added `js/worker.js` and `tests/bench.js`, updated `js/redactors.js` and `js/ui.js`. Verified benchmarks (`100 KB`: `6.6 ms`, `1 MB`: `33.5 ms`, `5 MB`: `171.6 ms`), total shipped assets `162,778` bytes (~159 KB), and live Web Worker execution in headless Chromium (`625ad38`).

### Parameter 4: Testing
- **Intent**: Add zero-dependency `node --test` suite (`tests/unit.test.mjs`), expand browser test runner (`tests/suite.js` / `tests/tests.html`) with XSS inertness and 50k ReDoS assertions, and document test commands in `README.md`.
- **Outcome**: Created `tests/unit.test.mjs`, updated `tests/suite.js` and `README.md`. Verified `node --test` (`10/10` passing), `node tests/tests.mjs` (`11/11` passing), and `tests/tests.html` in headless Chromium (`11/11` passing) (`2e1f626`).

### Parameter 5: Accessibility
- **Intent**: Audit WCAG 2.2 AA contrast ratios across all light/dark palette pairs, replace custom dropzone `role="button"` with a native `<button id="browse-files-btn">`, respect `prefers-color-scheme`, announce detection counts/errors via `aria-live`, and verify 360px/768px/1440px + 200% zoom with zero horizontal overflow.
- **Outcome**: Computed contrast ratios across 15 light/dark pairs (`5.66:1` to `13.30:1`, all passing AA), upgraded `index.html`, `css/styles.css`, and `js/ui.js`, and verified zero horizontal overflow and `>=44px` touch targets in headless Chromium (`5597b1f`).

### Parameter 6: Google Services (Privacy-Safe)
- **Intent**: Add static-only `firebase.json` with HTTP security headers, add opt-in feature-detected Chrome Built-in On-Device AI (Gemini Nano) review button, run real Lighthouse audits and optimize CLS/labels to hit Performance 95+ and Accessibility 100, and document all privacy-safe Google technologies and Google Antigravity attribution in `README.md`.
- **Outcome**: Created `firebase.json` and `robots.txt`; added `#ai-review-btn` (`runOnDeviceAIReview`) in `index.html`/`js/ui.js`; added `<label for="file-input">` and preloaded all 4 Sora `.woff2` weights (`font-display: optional`) eliminating `0.347` CLS. Verified Lighthouse scores: `Performance: 100` (`CLS: 0`), `Accessibility: 100`, `Best Practices: 100`, `SEO: 91`. Updated `README.md` (`b194cde`).

### Landing Page & Analyzer Restructure
- **Intent**: Move the analyzer workspace to `/analyze/index.html`, create a minimal, well-spaced landing page at `/` with a top-right `Launch App` button, share design tokens via `css/tokens.css`, keep landing JS minimal (`js/landing.js` theme toggle only), sync theme preference between pages, and add route smoke tests.
- **Outcome**: Created `css/tokens.css`, `css/landing.css`, `js/landing.js`, `analyze/index.html`, and new root `index.html`. Updated `firebase.json` (`cleanUrls: true`), `js/ui.js`, `tests/tests.html`, `tests/unit.test.mjs`, and `README.md`. Verified `node --test` (`11/11` passing) and responsive/CSP checks on both `/` and `/analyze/` (`a267c39`).

### Rename App to Maskwise
- **Intent**: Rename all branding, titles, meta tags, ARIA labels, `localStorage` theme keys (`maskwise-theme` with commented one-time `cloaktext-theme` fallback), downloaded filenames (`maskwise-sanitized.txt`/`.csv`), and docs to **Maskwise** with zero functional or layout changes.
- **Outcome**: Updated `index.html`, `analyze/index.html`, `js/landing.js`, `js/ui.js`, `tests/suite.js`, `tests/tests.html`, `README.md`, `SECURITY.md`, and `PROMPT_LOG.md`. Verified `grep -ri "cloak" .` (excluding `.git`) shows only the intentional commented `localStorage` fallback, all tests pass, and both `/` and `/analyze/` render cleanly across `360px`, `768px`, and `1440px` (`86e239d`).

### High-Resolution Transparent Logo Integration
- **Intent**: Remove the cream background from the provided Maskwise logo image using color-decontamination alpha matting, preserve original design/colors/proportions at Retina/4K density (`360x237` displayed at `48x32`), and place it in the top-left header of `/`, `/analyze/`, and `/tests/tests.html`.
- **Outcome**: Generated `assets/maskwise-logo.png` (`11 KB`, `360x237` RGBA), added `.brand-logo` in `css/tokens.css`, integrated into `index.html`, `analyze/index.html`, and `tests/tests.html`, and verified rendering, `0` console/network errors, and `11/11` passing tests.

### Left-Align Landing Page Hero Content
- **Intent**: Wrap `.hero-content` inside `<div class="container">` and set explicit `margin: 0; text-align: left;` so the hero section aligns flush with the topbar brand logo and section headers rather than centering when isolated.
- **Outcome**: Updated `index.html` and `css/landing.css`. Verified with CDP measurement that `.brand` (16px), `.hero-content` (16px), and `.section-head` (16px) share the exact same left coordinate with zero overflow across viewports. All tests pass (`11/11`).

### Mobbin-Inspired Landing Page UI & Component Redesign
- **Intent**: Redesign the landing page layout, visual hierarchy, and responsive structure modeled directly after Mobbin while strictly keeping existing brand colors (`#F3F3E0`, `#133E87`, `#608BC1`, `#CBDCEB`), logo, and Sora typography:
  1. Minimalist single-row navigation header with logo, version badge, center links, primary CTA, and responsive mobile menu drawer.
  2. Dynamic inline-visual hero with typography-embedded rounded icon pills (`Where [teams] and [AI agents] sanitize data [with zero leaks]`), dual CTAs, and large rounded showcase frame (`border-radius: 22px`).
  3. Interactive problem-to-solution showcase carousel with pill filters (`Support Tickets`, `AI Chat & Prompts`, `Developer Logs`, `HR & Financial Records`) that dynamically switch live comparison cards with zero lag.
  4. Modular asymmetrical bento grid (`border-radius: 20px`) highlighting Luhn/Verhoeff checksums, consistent pseudonymization, streaming CSV RFC-4180 with formula protection, and air-gapped CSP architecture.
  5. Interactive AI agent integration showcase with prompt simulation bar, animated 4-step status pipeline, and categorized horizontal token chips.
  6. Editorial 3-column case studies, executive pull-quote block with monogram avatar, specialized air-gap feature banner, centered closing CTA, and structured 4-column footer.
- **Outcome**: Updated `index.html`, `css/landing.css`, and `js/landing.js`. Verified via Chrome CDP across 1440px, 768px, and 360px viewports (0 horizontal overflow, >=44px touch targets, 0 network requests, 0 console errors) and automated unit test suite passing (`11/11`).

### Landing: Rotating Headline, Pill Buttons, Remove Badge
- **Intent**:
  1. Remove the "ZERO-NETWORK CLIENT-SIDE SANITIZATION" kicker badge above the headline and rebalance hero top spacing.
  2. Implement an accessible 3-slot rotating headline: "Where [SLOT 1] and [SLOT 2] sanitize data [SLOT 3]" with exactly 3 variants per slot (teams -> developers -> analysts; AI agents -> support bots -> LLM pipelines; with zero leaks -> with zero uploads -> with zero risk), staggered by 150ms on a 2000ms loop.
  3. Prevent layout shift completely by stacking all variants in one CSS grid cell (`grid-area: stack`), allowing the slot to size to the widest variant.
  4. Ensure WCAG accessibility: static fallback for `prefers-reduced-motion`, `aria-label` on `h1`, inactive items `aria-hidden="true"`, auto-pause on hover/focus/tab hide, and an explicit visible pause toggle button (`#headline-rotator-toggle`).
  5. Define `--radius-pill: 9999px` and make CTA buttons fully rounded pills ("Launch App", "Explore Showcase", header button).
- **Outcome**: Created `js/landing-rotator.js` and updated `index.html`, `css/landing.css`, `css/tokens.css`, `js/landing.js`, and `tests/unit.test.mjs`. Verified zero layout shift across rotation ticks (title width: 724px, slot widths: 183px, 211px, 257px), zero console errors, 0 external network requests, all touch targets >= 44px, and 12/12 passing unit tests.

### Cloud Run Deployment Configuration
- **Intent**: Configure the project for Google Cloud Run deployment by providing a lightweight `Dockerfile` (using `nginx:alpine` serving static content on port 8080) and `.dockerignore`, enabling 1-command deployment (`gcloud run deploy --source .`) to produce the required `*.run.app` submission URL.
- **Outcome**: Created `Dockerfile` and `.dockerignore`. Entire image builds from static sources without Node binaries. Verified 12/12 unit tests passing, repo size stays under 1.6 MB on single branch `main`.

### Professional Repository Enhancements & CI Workflow
- **Intent**: Enhance the GitHub repository presentation with a dedicated GitHub Actions CI pipeline (`.github/workflows/ci.yml`) to automatically validate unit tests, ReDoS resilience, performance benchmarks, and zero outbound network calls on every push.
- **Outcome**: Added automated workflow testing Node built-in test runner, throughput suite, and CSP isolation assertions. Verified 12/12 tests passing, repo size at 1.7 MB on single branch `main`.

### Live Vercel Deployment
- **Intent**: Deploy Maskwise directly to Vercel production with a clean public URL, disabling SSO protection for public evaluator access and testing live HTTP/2 200 responses.
- **Outcome**: Deployed to production at `https://maskwise-sooty.vercel.app` (Landing) and `https://maskwise-sooty.vercel.app/analyze/` (Workspace). Verified live responses with zero errors.
