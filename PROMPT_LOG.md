# Prompt Log — CloakText (PromptWars x NIAT_Pune)

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
- **Outcome**: Refactored `js/validators.js`, `js/detectors.js`, `js/redactors.js`, `js/csv.js`, `js/pipeline.js`, and `js/ui.js`; added `js/config.js` and lint/format configs; documented architecture in `README.md`. Verified `node --check` and `node tests/tests.mjs` (`10/10` passing).
