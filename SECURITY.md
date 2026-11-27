# Security Policy & Threat Model — CloakText

## Threat Model
CloakText processes sensitive Personally Identifiable Information (PII)—emails, phone numbers, IP addresses, Indian PANs, Aadhaar numbers, and payment card numbers—inside a static web application. Primary threats considered:
1. **Data Exfiltration**: Accidental or malicious outbound transmission of raw PII to external servers, analytics, or third-party CDNs.
2. **Stored/Reflected XSS via Untrusted Input**: Malicious HTML/JS payloads embedded inside pasted logs or uploaded `.txt`/`.csv` files executing in the browser.
3. **ReDoS (Regular Expression Denial of Service)**: Adversarial input (e.g., 50,000 repeated digits, `@`, `.`, or `:`) freezing the UI thread via catastrophic backtracking.
4. **CSV Formula Injection**: Untrusted spreadsheet formulas (`=`, `+`, `-`, `@`) surviving sanitization and executing when opened in Excel or Google Sheets.
5. **Malicious or Binary File Uploads**: Non-text payloads or corrupted encodings disguised as `.txt`/`.csv`.
6. **Residual State Persistence**: Sensitive input or pseudonym mappings lingering in browser storage or memory after clearing or leaving the page.

## Implemented Mitigations
- **Strict Content Security Policy (CSP)**:
  ```text
  default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data: blob:; worker-src 'self'; connect-src 'none'; form-action 'none'; base-uri 'none'; object-src 'none';
  ```
  `connect-src 'none'` blocks all `fetch`, `XMLHttpRequest`, `WebSocket`, and `sendBeacon` requests at the browser layer. `Referrer-Policy` is set via `<meta name="referrer" content="no-referrer">` and HTTP headers in `firebase.json` (alongside `X-Content-Type-Options: nosniff`).
- **Zero Persistence & Unload Wipe**: No `localStorage`, `sessionStorage`, cookies, or `IndexedDB` are used. Clicking **Clear** or navigating away (`pagehide`/`beforeunload`) clears the textarea, pseudonym dictionary, cached result, and diff DOM nodes.
- **XSS-Safe Rendering**: Diff highlights and mapping table cells are constructed strictly with `document.createTextNode()` and `element.textContent`. `innerHTML`, `eval`, `new Function`, and `document.write` are never used.
- **ReDoS-Safe Regexes**: All detector patterns avoid nested ambiguous quantifiers and are audited against 50,000-character adversarial inputs.
- **File Allow-Listing & Fatal UTF-8 Decoding**: Uploads validate both extension (`.txt`/`.csv`) and MIME type, enforce a 5 MB cap, and decode `ArrayBuffer` bytes with `new TextDecoder("utf-8", { fatal: true })`.
- **CSV Formula Neutralization**: Every output cell starting with `=`, `+`, `-`, or `@` is prefixed with `'` during serialization.

## Known Limits
- **HTTP-Only Headers**: `X-Content-Type-Options: nosniff` cannot be enforced via `<meta http-equiv>` in HTML5; it is configured as an HTTP response header in `firebase.json` for static hosting.
- **Browser Tab Memory**: While active in the browser tab, input text resides in JS/DOM memory until cleared or the tab closes.
- **Structured PII Scope**: Unstructured free-text entities (person names, street addresses) are outside deterministic pattern matching.
