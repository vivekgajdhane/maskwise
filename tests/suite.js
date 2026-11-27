/**
 * Dependency-free ES module unit & integration test suite for CloakText.
 * Runs identically in Node (tests/tests.mjs) and the browser (tests/tests.html).
 */

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

function assert(condition, message) {
  if (!condition) {
    throw new Error(message || "Assertion failed");
  }
}

function assertEqual(actual, expected, message) {
  if (actual !== expected) {
    throw new Error(
      `${message || "Expected equality"} — expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`
    );
  }
}

export function runTestSuite() {
  const cases = [];
  const test = (name, fn) => cases.push({ name, fn });

  test("Luhn validator accepts valid cards and rejects decoys", () => {
    assert(isValidLuhn("4532015112830366"), "Valid Visa must pass");
    assert(isValidLuhn("5425233430109903"), "Valid Mastercard must pass");
    assert(isValidLuhn("378282246310005"), "Valid Amex must pass");
    assert(isValidLuhn("6070930000123455"), "Valid RuPay must pass");
    assert(isValidLuhn("6011111111111117"), "Valid Discover must pass");

    assert(!isValidLuhn("4532015112830367"), "Luhn-invalid Visa must fail");
    assert(!isValidLuhn("1234567890123456"), "Sequential 16 digits must fail Luhn");
    assert(!isValidLuhn("0000000000000000"), "All zeros must be rejected");
    assert(!isValidLuhn("1111111111111111"), "Repeated digits must be rejected");
    assert(!isValidLuhn("453201511283"), "12-digit number too short for card");
    assert(!isValidLuhn("45320151128303660000"), "20-digit number too long for card");

    assertEqual(detectCardIssuer("4532015112830366"), "Visa");
    assertEqual(detectCardIssuer("5425233430109903"), "Mastercard");
    assertEqual(detectCardIssuer("378282246310005"), "Amex");
    assertEqual(detectCardIssuer("6070930000123455"), "RuPay");
    assertEqual(detectCardIssuer("6011111111111117"), "Discover");
  });

  test("Verhoeff validator accepts valid Aadhaar and catches single-digit & transposition errors", () => {
    assert(isValidAadhaar("452188903129"), "Valid Aadhaar 1");
    assert(isValidAadhaar("781234569018"), "Valid Aadhaar 2");

    assert(!isValidVerhoeff("452188903120"), "Single-digit mutation must fail Verhoeff");
    assert(!isValidVerhoeff("452188903192"), "Adjacent transposition must fail Verhoeff");
    assert(!isValidAadhaar("052188903129"), "Aadhaar starting with 0 must fail");
    assert(!isValidAadhaar("152188903129"), "Aadhaar starting with 1 must fail");

    const res = detectPIIWithStats("Valid 4521-8890-3129 vs bad 4521-8890-3120 vs card 4532-0151-1283-0366");
    assertEqual(res.entities.filter((e) => e.type === "aadhaar").length, 1);
    assertEqual(res.entities.filter((e) => e.type === "credit_card").length, 1);
    assertEqual(res.rejected.verhoeff, 1);
  });

  test("PAN detector validates all 10 holder types and enforces word boundaries", () => {
    const validCodes = ["P", "C", "H", "F", "A", "T", "B", "L", "J", "G"];
    for (const code of validCodes) {
      const pan = `ABC${code}E1234F`;
      assert(isValidPan(pan), `Expected holder code ${code} to be valid`);
      const found = detectPII(`PAN=${pan};`);
      assertEqual(found.length, 1, `Should detect ${pan}`);
      assertEqual(found[0].type, "pan");
    }

    const invalid = detectPIIWithStats("Bad holder ABCXE1234F, glued XABCPE1234F, suffix ABCPE1234F9");
    assertEqual(invalid.entities.length, 0);
    assertEqual(invalid.rejected.pan, 1);
  });

  test("IPv4 and IPv6 edge cases (256, leading zeros, 5 octets, ::1, compressed)", () => {
    assert(isValidIPv4("0.0.0.0"));
    assert(isValidIPv4("192.168.1.45"));
    assert(isValidIPv4("255.255.255.255"));
    assert(!isValidIPv4("256.1.1.1"));
    assert(!isValidIPv4("192.168.01.1"));
    assert(!isValidIPv4("010.0.0.1"));
    assert(!isValidIPv4("192.168.1.00"));
    assert(!isValidIPv4("1.2.3.4.5"));

    assert(isValidIPv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
    assert(isValidIPv6("2001:db8::8a2e:370:7334"));
    assert(isValidIPv6("::1"));
    assert(isValidIPv6("::ffff:192.0.2.128"));
    assert(!isValidIPv6("std::vector"));
    assert(!isValidIPv6("10:53:48"));
    assert(!isValidIPv6("00:1A:2B:3C:4D:5E"));

    const text = "ok=10.0.0.1 v6=2001:db8::1 loop=::1 bad=256.0.0.1,999.1.1.1,1.2.3.4.5,192.168.01.1 prose=std::vector";
    const res = detectPIIWithStats(text);
    assertEqual(res.entities.length, 3);
    assertEqual(res.rejected.ipv4, 4);
  });

  test("Phone and email detection rejects substrings of longer digit runs", () => {
    const text =
      "Email: Alice.Smith+alerts@sub.domain.co.in. Call +91 98765 43210, 09876543210, +1 (415) 555-0199. " +
      "Ignore order=987654321012345 date=2026-11-27 chained=1234-9876543210.";
    const entities = detectPII(text);
    assertEqual(entities.filter((e) => e.type === "email").length, 1);
    assertEqual(entities.find((e) => e.type === "email").value, "Alice.Smith+alerts@sub.domain.co.in");
    const phones = entities.filter((e) => e.type === "phone").map((e) => e.value);
    assertEqual(phones.length, 3);
    assert(phones.includes("+91 98765 43210"));
    assert(phones.includes("09876543210"));
    assert(phones.includes("+1 (415) 555-0199"));
  });

  test("Overlapping match priority and longest-match tie breaking", () => {
    // 16-digit Luhn-valid card must not split into Aadhaar or phone
    const cardOnly = detectPII("4532-0151-1283-0366");
    assertEqual(cardOnly.length, 1);
    assertEqual(cardOnly[0].type, "credit_card");

    // 12-digit Verhoeff-valid Aadhaar must win over phone even if starting with 9
    // Construct valid 12-digit starting with 9: 98765432101 -> check digit
    const aadhaarStart9 = "987654321018"; // check whether Verhoeff passes; if not, compute dynamically
    const D = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]];
    const P = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]];
    const INV = [0,4,3,2,1,5,6,7,8,9];
    let c = 0;
    const base = "98765432101";
    for (let i = 0; i < 11; i++) c = D[c][P[(i + 1) % 8][Number(base[10 - i])]];
    const validAadhaar9 = base + INV[c];
    assert(isValidAadhaar(validAadhaar9));
    const res = detectPII(validAadhaar9);
    assertEqual(res.length, 1);
    assertEqual(res[0].type, "aadhaar");
    assert(aadhaarStart9.length === 12);
  });

  test("Full Mask and Partial Mask formats per entity type", () => {
    assertEqual(formatReplacement({ type: "email", value: "john.doe@example.com" }, "full"), "[REDACTED]");
    assertEqual(
      formatReplacement({ type: "email", value: "john.doe@example.com" }, "full", { typedFullMask: true }),
      "[REDACTED:EMAIL]"
    );
    assertEqual(formatReplacement({ type: "credit_card", value: "4532-0151-1283-0366" }, "partial"), "XXXX-XXXX-XXXX-0366");
    assertEqual(formatReplacement({ type: "credit_card", value: "5425 2334 3010 9903" }, "partial"), "XXXX XXXX XXXX 9903");
    assertEqual(formatReplacement({ type: "aadhaar", value: "4521-8890-3129" }, "partial"), "XXXX-XXXX-3129");
    assertEqual(formatReplacement({ type: "aadhaar", value: "452188903129" }, "partial"), "XXXX-XXXX-3129");
    assertEqual(formatReplacement({ type: "pan", value: "ABCPE1234F" }, "partial"), "ABXXXXXX4F");
    assertEqual(formatReplacement({ type: "phone", value: "+91-98765-43210" }, "partial"), "+91-XXXXX-X3210");
    assertEqual(formatReplacement({ type: "email", value: "john.doe@example.com" }, "partial"), "j***@example.com");
    assertEqual(formatReplacement({ type: "ip", value: "192.168.1.45" }, "partial"), "192.168.XXX.XXX");
    assertEqual(formatReplacement({ type: "ip", value: "2001:db8::1" }, "partial"), "2001:db8::XXXX");
  });

  test("Consistent Pseudonymization normalizes variants and resets cleanly", () => {
    const sample =
      "A: Alice@Example.com, B: alice@example.com, P1: +91 98765 43210, P2: +91-98765-43210, " +
      "C1: 4532-0151-1283-0366, C2: 4532 0151 1283 0366, IP: 2001:DB8::1 and 2001:db8::1";
    const mapper = createPseudonymMapper();
    const res = redactText(sample, detectPII(sample), "pseudonym", { mapper });

    assert(res.sanitizedText.includes("A: USER_01, B: USER_01"), "Email case-folding failed");
    assert(res.sanitizedText.includes("P1: PHONE_01, P2: PHONE_01"), "Phone normalization failed");
    assert(res.sanitizedText.includes("C1: CARD_01, C2: CARD_01"), "Card normalization failed");
    assert(res.sanitizedText.includes("IP: IP_01 and IP_01"), "IPv6 case normalization failed");
    assertEqual(mapper.entries().length, 4);

    mapper.reset();
    assertEqual(mapper.entries().length, 0);
  });

  test("CSV round-trip preserves quotes, embedded commas/newlines, headers, and guards formulas", () => {
    const csv =
      'id,name,notes,formula\r\n1,"Doe, Jane","Priya@Acme.in\n+91-98765-43210",=CMD|calc\r\n2,"He said ""hi""",priya@acme.in,@SUM(1)\r\n';
    const parsed = parseCSV(csv);
    assertEqual(parsed.length, 3);
    assertEqual(parsed[1][1], "Doe, Jane");
    assertEqual(parsed[1][2], "Priya@Acme.in\n+91-98765-43210");
    assertEqual(parsed[2][1], 'He said "hi"');

    const roundTrip = serializeCSV(parsed, { lineEnding: "\r\n", hadTrailingNewline: true, guardFormula: false });
    assertEqual(roundTrip, csv);

    const sanitized = runSanitization(csv, { format: "csv", mode: "pseudonym" });
    const outRows = parseCSV(sanitized.sanitizedText);
    assertEqual(outRows[0][0], "id", "Header preserved");
    assertEqual(outRows[1][2], "USER_01\nPHONE_01");
    assertEqual(outRows[2][2], "USER_01");
    assertEqual(outRows[1][3], "'=CMD|calc", "Leading apostrophe on = formula");
    assertEqual(outRows[2][3], "'@SUM(1)", "Leading apostrophe on @ formula");
    assert(sanitized.sanitizedText.includes("\r\n"), "CRLF preserved");

    for (const rep of sanitized.replacements) {
      assertEqual(
        sanitized.sanitizedText.slice(rep.sanitizedStart, rep.sanitizedEnd),
        rep.replacement,
        "Sanitized CSV diff offset must match exact token"
      );
    }
  });

  test("Sample text & CSV payloads execute accurately and 1 MB throughput is under 1 second", () => {
    const sampleRes = runSanitization(SAMPLE_NOISY_TEXT, { format: "text", mode: "pseudonym" });
    assert(sampleRes.entities.length >= 20, "Sample text should detect >= 20 entities");
    assert(sampleRes.rejected.luhn >= 2, "Sample text should ignore Luhn-failing decoys");
    assert(sampleRes.rejected.verhoeff >= 1, "Sample text should ignore Verhoeff-failing decoy");
    assert(sampleRes.rejected.ipv4 >= 3, "Sample text should ignore invalid IPs");

    const csvRes = runSanitization(SAMPLE_NOISY_CSV, { format: "csv", mode: "partial" });
    assertEqual(csvRes.csvStats.dataRows, 4);
    assert(csvRes.csvStats.formulasGuarded >= 2);

    const targetBytes = 1024 * 1024;
    const bigText = SAMPLE_NOISY_TEXT.repeat(Math.ceil(targetBytes / SAMPLE_NOISY_TEXT.length)).slice(0, targetBytes);
    const bigRes = runSanitization(bigText, { format: "text", mode: "full" });
    assert(bigRes.durationMs < 1000, `1 MB took ${bigRes.durationMs.toFixed(1)} ms (> 1000 ms limit)`);
  });

  test("Security: XSS payloads stay inert and 50k ReDoS inputs finish under 50 ms", () => {
    const xssPayload = '<img src=x onerror=alert(1)> <script>alert("xss")</script> alice@example.com';
    const xssRes = runSanitization(xssPayload, { format: "text", mode: "pseudonym" });
    assertEqual(xssRes.sanitizedText, '<img src=x onerror=alert(1)> <script>alert("xss")</script> USER_01');
    if (typeof document !== "undefined") {
      const pre = document.createElement("pre");
      pre.textContent = xssRes.sanitizedText;
      assertEqual(pre.querySelectorAll("img, script").length, 0, "XSS payload must not create DOM elements");
    }

    const adversarial = [
      "9".repeat(50000),
      "@.".repeat(25000),
      "a.".repeat(25000) + "com",
      "9-".repeat(25000),
      "9=".repeat(25000),
    ];
    for (const input of adversarial) {
      const t0 = performance.now();
      const res = detectPIIWithStats(input);
      const ms = performance.now() - t0;
      assertEqual(res.entities.length, 0);
      assert(ms < 50, `Adversarial 50k input took ${ms.toFixed(1)} ms (> 50 ms limit)`);
    }
  });

  const results = [];
  let passed = 0;
  let failed = 0;

  for (const tc of cases) {
    const t0 = performance.now();
    try {
      tc.fn();
      const ms = performance.now() - t0;
      passed += 1;
      results.push({ name: tc.name, ok: true, durationMs: ms });
    } catch (err) {
      const ms = performance.now() - t0;
      failed += 1;
      results.push({ name: tc.name, ok: false, durationMs: ms, error: err?.message || String(err) });
    }
  }

  return { passed, failed, total: cases.length, results };
}
