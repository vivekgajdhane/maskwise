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
