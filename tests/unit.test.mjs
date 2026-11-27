/**
 * Built-in Node test runner suite (`node --test`).
 * Zero external dependencies; covers unit, negative, integration, XSS, and ReDoS checks.
 */

import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { parseCSV, serializeCSV } from "../js/csv.js";
import { detectPII, detectPIIWithStats } from "../js/detectors.js";
import { runSanitization } from "../js/pipeline.js";
import { createPseudonymMapper, formatReplacement, redactText } from "../js/redactors.js";
import { SAMPLE_NOISY_CSV, SAMPLE_NOISY_TEXT } from "../js/samples.js";
import {
  detectCardIssuer,
  isValidAadhaar,
  isValidIPv4,
  isValidIPv6,
  isValidLuhn,
  isValidPan,
  isValidVerhoeff,
} from "../js/validators.js";

test("Unit: Luhn validator & issuer prefixes", () => {
  assert.equal(isValidLuhn("4532015112830366"), true);
  assert.equal(isValidLuhn("5425233430109903"), true);
  assert.equal(isValidLuhn("378282246310005"), true);
  assert.equal(isValidLuhn("6070930000123455"), true);
  assert.equal(isValidLuhn("6011111111111117"), true);

  assert.equal(detectCardIssuer("4532015112830366"), "Visa");
  assert.equal(detectCardIssuer("5425233430109903"), "Mastercard");
  assert.equal(detectCardIssuer("378282246310005"), "Amex");
  assert.equal(detectCardIssuer("6070930000123455"), "RuPay");
  assert.equal(detectCardIssuer("6011111111111117"), "Discover");
});

test("Negative: Luhn-failing 16-digit numbers and repeated digits are NOT flagged", () => {
  assert.equal(isValidLuhn("4532015112830367"), false);
  assert.equal(isValidLuhn("1234567890123456"), false);
  assert.equal(isValidLuhn("0000000000000000"), false);
  assert.equal(isValidLuhn("1111111111111111"), false);
  const res = detectPIIWithStats("Decoys: 4532-0151-1283-0367 and 1234567890123456");
  assert.equal(res.entities.length, 0);
  assert.equal(res.rejected.luhn, 2);
});

test("Unit & Negative: Verhoeff checksum & Aadhaar rules", () => {
  assert.equal(isValidAadhaar("452188903129"), true);
  assert.equal(isValidAadhaar("781234569018"), true);
  assert.equal(isValidVerhoeff("452188903120"), false);
  assert.equal(isValidVerhoeff("452188903192"), false);
  assert.equal(isValidAadhaar("052188903129"), false);
  assert.equal(isValidAadhaar("152188903129"), false);

  const res = detectPIIWithStats("Valid 4521 8890 3129; Bad 4521 8890 3120; Lookalike 0521 8890 3129");
  assert.equal(res.entities.length, 1);
  assert.equal(res.entities[0].type, "aadhaar");
  assert.equal(res.rejected.verhoeff, 1);
});

test("Unit & Negative: PAN holder types and word boundaries", () => {
  for (const code of ["P", "C", "H", "F", "A", "T", "B", "L", "J", "G"]) {
    assert.equal(isValidPan(`ABC${code}E1234F`), true);
  }
  assert.equal(isValidPan("ABCXE1234F"), false);
  const res = detectPIIWithStats("Good ABCPE1234F, bad ABCXE1234F, glued XABCPE1234FY");
  assert.equal(res.entities.length, 1);
  assert.equal(res.rejected.pan, 1);
});

test("Unit & Negative: IPv4/IPv6 edge cases (256, leading zeros, 1.2.3.4.5, ::1)", () => {
  assert.equal(isValidIPv4("0.0.0.0"), true);
  assert.equal(isValidIPv4("192.168.1.45"), true);
  assert.equal(isValidIPv4("256.1.1.1"), false);
  assert.equal(isValidIPv4("192.168.01.1"), false);
  assert.equal(isValidIPv4("1.2.3.4.5"), false);

  assert.equal(isValidIPv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334"), true);
  assert.equal(isValidIPv6("2001:db8::1"), true);
  assert.equal(isValidIPv6("::1"), true);
  assert.equal(isValidIPv6("::ffff:192.0.2.128"), true);
  assert.equal(isValidIPv6("std::vector"), false);

  const res = detectPIIWithStats("10.0.0.1 ::1 256.1.1.1 1.2.3.4.5 192.168.01.1 std::vector");
  assert.equal(res.entities.length, 2);
  assert.equal(res.rejected.ipv4, 3);
});

test("Unit: Phone formats, email variants, and overlap resolution", () => {
  const text = "Mail: Alice.Smith+tag@sub.acme.co.in. Call +91 98765 43210, 09876543210, +1 (415) 555-0199. Ignore 987654321012345.";
  const entities = detectPII(text);
  assert.equal(entities.filter((e) => e.type === "email").length, 1);
  assert.equal(entities.filter((e) => e.type === "phone").length, 3);
  assert.equal(detectPII("4532-0151-1283-0366").map((e) => e.type).join(","), "credit_card");
});

test("Unit: All 3 redaction modes and pseudonym normalization", () => {
  assert.equal(formatReplacement({ type: "email", value: "john.doe@example.com" }, "full"), "[REDACTED]");
  assert.equal(formatReplacement({ type: "email", value: "john.doe@example.com" }, "full", { typedFullMask: true }), "[REDACTED:EMAIL]");
  assert.equal(formatReplacement({ type: "credit_card", value: "4532-0151-1283-0366" }, "partial"), "XXXX-XXXX-XXXX-0366");
  assert.equal(formatReplacement({ type: "aadhaar", value: "4521 8890 3129" }, "partial"), "XXXX XXXX 3129");
  assert.equal(formatReplacement({ type: "pan", value: "ABCPE1234F" }, "partial"), "ABXXXXXX4F");
  assert.equal(formatReplacement({ type: "phone", value: "+91-98765-43210" }, "partial"), "+91-XXXXX-X3210");
  assert.equal(formatReplacement({ type: "email", value: "john.doe@example.com" }, "partial"), "j***@example.com");
  assert.equal(formatReplacement({ type: "ip", value: "192.168.1.45" }, "partial"), "192.168.XXX.XXX");

  const mapper = createPseudonymMapper();
  const sample = "A@acme.in a@acme.in +91 98765 43210 +91-98765-43210";
  const res = redactText(sample, detectPII(sample), "pseudonym", { mapper });
  assert.equal(res.sanitizedText, "USER_01 USER_01 PHONE_01 PHONE_01");
});

test("Unit: CSV RFC-4180 round-trip and formula-injection guard", () => {
  const csv = 'id,name,notes,formula\r\n1,"Doe, Jane","Priya@Acme.in\n+91-98765-43210",=CMD|calc\r\n2,"He said ""hi""",priya@acme.in,@SUM(1)\r\n';
  const rows = parseCSV(csv);
  assert.equal(rows.length, 3);
  assert.equal(serializeCSV(rows, { lineEnding: "\r\n", hadTrailingNewline: true, guardFormula: false }), csv);

  const sanitized = runSanitization(csv, { format: "csv", mode: "pseudonym" });
  const outRows = parseCSV(sanitized.sanitizedText);
  assert.equal(outRows[0][0], "id");
  assert.equal(outRows[1][2], "USER_01\nPHONE_01");
  assert.equal(outRows[2][2], "USER_01");
  assert.equal(outRows[1][3], "'=CMD|calc");
  assert.equal(outRows[2][3], "'@SUM(1)");
});

test("Integration: sample-loader text and CSV produce exact expected counts", () => {
  const txtRes = runSanitization(SAMPLE_NOISY_TEXT, { format: "text", mode: "pseudonym" });
  assert.equal(txtRes.entities.length, 21);
  assert.deepEqual(txtRes.rejected, { luhn: 3, verhoeff: 1, ipv4: 3, pan: 1, phone: 0 });

  const csvRes = runSanitization(SAMPLE_NOISY_CSV, { format: "csv", mode: "partial" });
  assert.equal(csvRes.entities.length, 14);
  assert.equal(csvRes.csvStats.dataRows, 4);
  assert.equal(csvRes.csvStats.formulasGuarded, 3);
});

test("Security: XSS payloads remain inert and 50k ReDoS inputs finish under 50 ms", () => {
  const xss = '<img src=x onerror=alert(1)> <script>alert(1)</script> user@example.com';
  const res = runSanitization(xss, { format: "text", mode: "full" });
  assert.equal(res.sanitizedText, '<img src=x onerror=alert(1)> <script>alert(1)</script> [REDACTED]');

  for (const input of ["9".repeat(50000), "@.".repeat(25000), "a.".repeat(25000) + "com", "9-".repeat(25000), "9=".repeat(25000)]) {
    const t0 = performance.now();
    const out = detectPIIWithStats(input);
    const ms = performance.now() - t0;
    assert.equal(out.entities.length, 0);
    assert.ok(ms < 50, `ReDoS check took ${ms.toFixed(2)} ms`);
  }
});

test("Smoke: landing page and /analyze/ routes exist with proper script isolation", () => {
  assert.equal(fs.existsSync("index.html"), true);
  assert.equal(fs.existsSync("analyze/index.html"), true);
  assert.equal(fs.existsSync("css/tokens.css"), true);
  assert.equal(fs.existsSync("css/landing.css"), true);

  const landingHtml = fs.readFileSync("index.html", "utf8");
  const analyzerHtml = fs.readFileSync("analyze/index.html", "utf8");

  assert.match(landingHtml, /href="analyze\/"/);
  assert.match(landingHtml, /src="js\/landing\.js"/);
  assert.doesNotMatch(landingHtml, /detectors\.js|redactors\.js|pipeline\.js|ui\.js/);

  assert.match(analyzerHtml, /src="\.\.\/js\/ui\.js"/);
  assert.match(analyzerHtml, /href="\.\.\/"/);
});
