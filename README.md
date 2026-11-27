# CloakText — Client-Side PII Sanitizer

CloakText is a dependency-free, 100% browser-based Personally Identifiable Information (PII) sanitizer built for **PromptWars x NIAT_Pune** (Google x NIAT Hackathon). Users can paste raw logs, support tickets, resumes, clinical notes, or upload `.txt`/`.csv` files (up to 5 MB) to detect, validate, highlight, redact, and export sanitized data **entirely inside the browser** without any server communication.

---

## Problem Statement

Organizations and individuals routinely paste or share application logs, support tickets, CSV exports, resumes, and clinical notes containing raw emails, phone numbers, IP addresses, Indian PANs, Aadhaar numbers, and payment card numbers. Uploading sensitive raw data to third-party web tools introduces severe privacy, compliance, and breach risks. CloakText eliminates server-side exposure by executing every detection, validation, redaction, and export step locally on the client.

---

## Features

- **Six PII Detectors with Validation**: Email, Phone (Indian + international), IPv4/IPv6, Indian PAN, Aadhaar, and Credit Cards.

---

## Architecture

CloakText uses a strict unidirectional client-side pipeline with zero external network calls:

```text
[ index.html + css/styles.css + fonts/sora-*.woff2 ]
                         │
                         ▼
                    [ js/ui.js ]  ◄──  [ js/samples.js ]
                    (DOM, FileReader,
                     Blob export, state)
                         │
                         ▼
                 [ js/pipeline.js ]
                   /            \
      Plain Text  /              \  RFC-4180 CSV
                 ▼                ▼
      [ js/detectors.js ]    [ js/csv.js ]
      (Regex + Overlap)      (Per-cell + Formula Guard)
                 │                │
                 └───────┬────────┘
                         ▼
                [ js/validators.js ]
                (Luhn, Verhoeff, PAN, IP)
                         │
                         ▼
                [ js/redactors.js ]
                (Full / Partial / Pseudonym)
                         │
                         ▼
                 [ js/config.js ]
                 (Shared constants & limits)
```

### Data Flow
1. **Input**: User pastes text, clicks a 1-click sample loader (`js/samples.js`), or drops/selects a `.txt`/`.csv` file read locally via `FileReader`.
2. **Orchestration**: `js/pipeline.js` routes plain text directly to `js/detectors.js` + `js/redactors.js`, or routes CSV through `js/csv.js` for RFC-4180 cell parsing and per-cell sanitization.
3. **Detection & Validation**: `js/detectors.js` runs precompiled patterns and validates candidates via `js/validators.js`, resolving overlaps deterministically (`credit_card > aadhaar > pan > phone > ip > email`).
4. **Redaction & Audit**: `js/redactors.js` applies Full Mask, Partial Mask, or normalized Consistent Pseudonymization while recording exact character offsets so `js/ui.js` can render both diff panes via `Text` nodes (`textContent` only) and export via `Blob`.

---

## Features

- **Six PII Detectors with Validation**: Email, Phone (Indian + international), IPv4/IPv6, Indian PAN, Aadhaar, and Credit Cards.
- **False-Positive Rejection**: Luhn checksum filtering for cards, Verhoeff dihedral checksum filtering for Aadhaar, strict IPv4 octet/leading-zero validation, PAN 4th-character entity-type validation, and digit-run boundary checks.
- **Three Redaction Modes**: Full Mask (standard & typed), type-specific Partial Mask, and Consistent Pseudonymization with a live Mapping Table and Reset control.
- **RFC-4180 CSV Sanitization**: Parses quoted fields, embedded commas, escaped quotes, and multiline cells; preserves Row 0 headers; neutralizes spreadsheet formula injection (`=`, `+`, `-`, `@`) with a leading apostrophe `'`.
- **Live Side-by-Side Audit Diff**: Highlights original PII (distinct palette tints, underline styles, and inline tags) alongside redacted replacements with synchronized scrolling, per-type counters, rejected-candidate counts, and per-type detector toggles.
- **1-Click Demo Loaders & Export**: Sample noisy text loader (support ticket, resume, clinical note, server log), sample noisy CSV loader, Clipboard Copy, and 1-click `Blob` file download preserving `.txt`/`.csv` extensions.
- **Accessible Hand-Crafted UI**: Self-hosted `Sora` typography + `Helvetica Neue` body stack, strict 4-color palette (`#F3F3E0`, `#CBDCEB`, `#608BC1`, `#133E87`) with dark mode inversion, >=44px touch targets, roving-tabindex keyboard navigation, and responsive desktop/tablet/mobile layouts.

---

## How Detection & Validation Work

Implemented in [`js/validators.js`](js/validators.js) and [`js/detectors.js`](js/detectors.js) using linear-time, ReDoS-safe patterns:

| Entity Type | Detection Rules | Validation & False-Positive Guards |
| :--- | :--- | :--- |
| **Credit Card** | 13–19 digits with consistent space/hyphen grouping or contiguous digits | **Luhn (`mod 10`) checksum** (`isValidLuhn`), rejects all-zero/repeated digits and digit-chain substrings; adds BIN issuer hint (`Visa`, `Mastercard`, `Amex`, `RuPay`, `Discover`, `Card`) |
| **Aadhaar** | 12 digits starting with `2–9` (`XXXX XXXX XXXX`, `XXXX-XXXX-XXXX`, or 12 contiguous digits) | **Verhoeff dihedral D5 checksum** (`isValidVerhoeff`), rejects digits inside longer card/ID chains |
| **Indian PAN** | `[A-Z]{5}[0-9]{4}[A-Z]` with strict alphanumeric word boundaries | Validates 4th character holder code against `{P, C, H, F, A, T, B, L, J, G}` (`isValidPan`) |
| **Phone** | Indian (`+91`, `0091`, `91`, `0` prefix + 10 digits `[6–9]`) and E.164 / NANP international formats | Digit-count bounds (`7–15` digits for `+` E.164) and boundary checks rejecting substrings of longer IDs or hyphenated dates |
| **IP Address** | Dotted IPv4 and full/compressed IPv6 (including `::1` and IPv4-mapped `::ffff:...`) | Strict `0–255` octets, rejects leading zeros (`192.168.01.1`) and 5-octet runs (`1.2.3.4.5`); rejects C++ `std::vector` and timestamps |
| **Email** | Pragmatic RFC local-part (`+` tags, dots) + subdomain-aware domain + alphabetic TLD | Length bounds (`<= 254` total, `<= 64` local) and boundary guards against malformed leading/trailing dots |

**Deterministic Overlap Resolution**: Overlapping matches resolve by priority `credit_card > aadhaar > pan > phone > ip > email`, breaking ties by longest span.

---

## Redaction Mode Examples

| Input | Full Mask | Partial Mask | Consistent Pseudonymization |
| :--- | :--- | :--- | :--- |
| `Priya.Sharma@Acme.in` | `[REDACTED]` (or `[REDACTED:EMAIL]`) | `P***@Acme.in` | `USER_01` (case-folded match with `priya.sharma@acme.in`) |
| `+91-98765-43210` | `[REDACTED]` (or `[REDACTED:PHONE]`) | `+91-XXXXX-X3210` | `PHONE_01` (normalized with `+91 98765 43210` & `09876543210`) |
| `192.168.14.22` | `[REDACTED]` (or `[REDACTED:IP]`) | `192.168.XXX.XXX` | `IP_01` |
| `ABCPE1234F` | `[REDACTED]` (or `[REDACTED:PAN]`) | `ABXXXXXX4F` | `PAN_01` |
| `4521 8890 3129` | `[REDACTED]` (or `[REDACTED:AADHAAR]`) | `XXXX XXXX 3129` | `AADHAAR_01` |
| `4532-0151-1283-0366` | `[REDACTED]` (or `[REDACTED:CARD]`) | `XXXX-XXXX-XXXX-0366` | `CARD_01` |

---

## Privacy & Security Guarantees

1. **Browser-Enforced CSP**: `index.html` and `tests/tests.html` ship with:
   ```text
   default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data: blob:; connect-src 'none'; form-action 'none'; base-uri 'none'; object-src 'none';
   ```
   Any outbound XHR/Fetch/WebSocket/beacon attempt is blocked by the browser itself.
2. **Zero Network APIs or Persistence**: Code contains no `fetch`, `XMLHttpRequest`, `WebSocket`, `sendBeacon`, analytics, or `localStorage` calls. All file uploads use local `FileReader`, and exports use in-memory `Blob` URLs.
3. **Zero External Dependencies**: Fonts (`fonts/sora-latin-*.woff2`) are self-hosted; no CDNs, npm packages, or build steps are used.
4. **XSS-Safe Rendering**: Diff panes and mapping rows render user content strictly via `document.createTextNode` and `element.textContent`—never `innerHTML`.

---

## Running Locally

Because browsers enforce CORS on native ES modules (`<script type="module">`) when opened over `file://`, serve the folder over any local static HTTP server (or open via GitHub Pages):

```bash
# 1. Start a lightweight static server from the repository root
python3 -m http.server 8000 --bind 127.0.0.1

# 2. Open index.html in your browser
open http://127.0.0.1:8000/index.html
```

### Running the Test Suite

- **CLI (Node)**:
  ```bash
  node tests/tests.mjs
  ```
- **Browser**: Visit `http://127.0.0.1:8000/tests/tests.html` (or click **Open browser test suite** in the app footer).

---

## Screenshot

> _Screenshot Placeholder_: Capture the live Desktop (`1440px`) side-by-side diff after clicking **Load sample noisy data** and switching to **Pseudonymize** with **Show mapping table** expanded, and save here if desired.
>
> ```text
> [ CloakText Desktop Diff & Pseudonym Mapping Preview ]
> ```

---

## Limitations

- **No Named-Entity Recognition (NER)**: CloakText intentionally uses deterministic pattern + checksum algorithms offline without downloading heavy ML models. Unstructured person names (e.g., `Rohan Kulkarni`), street addresses, or free-text medical diagnoses are not automatically detected unless matched by structured identifiers (email, phone, PAN, Aadhaar, card, IP).
- **File Cap**: Local file uploads are capped at **5 MB** per `.txt`/`.csv` file to keep interactive UI diff rendering responsive in single-threaded browser tabs.
