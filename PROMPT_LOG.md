# Prompt Log — CloakText (PromptWars x NIAT_Pune)

Chronological record of prompts, engineering decisions, and phase outcomes.

## Phase 1: Architecture, Scaffolding, CSP, and Design System
- **Intent**: Scaffold a zero-dependency vanilla HTML/CSS/ES-module application with strict CSP (`connect-src 'none'`), self-hosted Sora `.woff2` fonts, exact 4-color palette (`#F3F3E0`, `#CBDCEB`, `#608BC1`, `#133E87`) with WCAG AA contrast and dark-mode inversion, accessible PII highlight CSS marks, and modular `js/` layout.
- **Outcome**: Initialized `main` branch, self-hosted `fonts/sora-latin-{400,500,600,700}-normal.woff2`, built `index.html`, `css/styles.css`, and initial ES module shells under `js/`. Verified zero network API calls and strict CSP compliance.

## Phase 2: Detection and Validation Engine
- **Intent**: Implement ReDoS-safe pattern detectors (`js/detectors.js`) and cryptographic/structural validators (`js/validators.js`) for Email, Phone (Indian + international), IPv4/IPv6, Indian PAN (holder-type validated), Aadhaar (Verhoeff checksum), and Credit Cards (Luhn + IIN issuer hints), with deterministic overlap resolution (`credit_card > aadhaar > pan > phone > ip > email`) and <=1s throughput on 1 MB of text.
- **Outcome**: Implemented `js/validators.js` and `js/detectors.js` using bucket-indexed overlap resolution and binary-search rejection deduplication, eliminating false positives on Luhn-failing numbers, Verhoeff-failing 12-digit strings, invalid IPs (`999.1.1.1`, `1.2.3.4.5`, leading zeros), and substrings of longer digit runs. Benchmarked at 1 MB text well under 1 second.

## Phase 3: Redaction Modes and Consistent Pseudonymization
- **Intent**: Implement Full Mask (standard and typed `[REDACTED:TYPE]`), type-specific Partial Mask (preserving separators and partial verification context), and Consistent Pseudonymization (`USER_01`, `PHONE_01`, `CARD_01`, `AADHAAR_01`, `PAN_01`, `IP_01`) with input normalization and resettable mapping state in `js/redactors.js`.
- **Outcome**: Implemented `js/redactors.js` with `normalizeForMapping`, `createPseudonymMapper`, `formatReplacement`, and $O(n)$ `redactText` tracking exact `originalStart`/`sanitizedStart` offsets for diff rendering. Verified formatting and mapping consistency across case and separator variants.

## Phase 4: Input Handling, RFC-4180 CSV, and Formula Guard
- **Intent**: Implement local-only `.txt`/`.csv` upload with 5 MB cap via `FileReader`, preserve line endings/whitespace in plain text, and build an RFC-4180 CSV parser/serializer (`js/csv.js`) that sanitizes cell-by-cell while preserving headers and defending against spreadsheet formula injection (`=`, `+`, `-`, `@`).
- **Outcome**: Built `js/csv.js`, wired `js/pipeline.js`, added Plain Text / CSV mode toggle in `index.html` and `css/styles.css`, and implemented drag-and-drop, file extension/size validation, and local `FileReader` loading in `js/ui.js`. Verified CSV round-trips, embedded commas/newlines/quotes, formula neutralization, and exact diff offsets.

## Phase 5: Audit View, Diff Highlighting, Samples, and Export
- **Intent**: Render live side-by-side highlighted diff panes via XSS-safe DOM text nodes (`textContent`), add synchronized scrolling, live per-type + rejected candidate counts, per-type detector toggles, 1-click Blob download and Copy export, mapping table drawer, and realistic sample text + CSV loaders.
- **Outcome**: Implemented `js/samples.js` (support ticket, resume, clinical note, server log + mixed CSV with valid PII, repeats, Luhn/Verhoeff/IP/PAN decoys, and formula payloads) and completed Phase 5 rendering/export/scroll-sync in `js/ui.js` with zero `innerHTML`.

## Phase 6: UI Polish, Accessibility, and Responsive Audit
- **Intent**: Enforce WCAG AA contrast, >=44px touch targets, roving-tabindex keyboard navigation (`ArrowLeft`/`ArrowRight`/`Home`/`End`), skip link, ARIA live announcements, inline SVG favicon (eliminating 404s), `prefers-reduced-motion` support, and verify real headless Chrome rendering at 1440px, 768px, and 360px widths.
- **Outcome**: Updated `index.html`, `css/styles.css`, and `js/ui.js`; verified in real Chromium via CDP across 1440px, 768px, and 360px viewports (`scrollWidth === innerWidth`, `minTouchTarget === 44px`, `soraLoaded: true`, 0 external network requests, 0 console errors). Removed redundant `.mode-options` min-height gap in Partial Mask mode.
