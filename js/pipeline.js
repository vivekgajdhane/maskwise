/**
 * Sanitization pipeline coordinating plain text and RFC-4180 CSV workflows.
 */

import { sanitizeCSV } from "./csv.js";
import { detectPIIWithStats } from "./detectors.js";
import { createPseudonymMapper, redactText } from "./redactors.js";

/**
 * Execute detection and redaction over plain text or CSV input.
 * Edge cases: returns empty result structure for empty or non-string input.
 *
 * @param {string} text - Raw text or CSV payload.
 * @param {object} [options={}] - Pipeline options (format, enabledTypes, mode, typedFullMask, mapper, guardFormula).
 * @returns {{ format: string, originalText: string, sanitizedText: string, entities: Array<object>, replacements: Array<object>, rejected: object, mapper: object, csvStats: object|null, durationMs: number }}
 */
export function runSanitization(text, options = {}) {
  const {
    format = "text",
    enabledTypes,
    mode = "full",
    typedFullMask = false,
    mapper = createPseudonymMapper(),
    guardFormula = true,
  } = options;

  if (typeof text !== "string" || text.length === 0) {
    return {
      format,
      originalText: "",
      sanitizedText: "",
      entities: [],
      replacements: [],
      rejected: { luhn: 0, verhoeff: 0, ipv4: 0, pan: 0, phone: 0 },
      mapper,
      csvStats: null,
      durationMs: 0,
    };
  }

  const t0 = performance.now();

  if (format === "csv") {
    const result = sanitizeCSV(text, { enabledTypes, mode, typedFullMask, mapper, guardFormula });
    return { format: "csv", ...result, durationMs: performance.now() - t0 };
  }

  const { entities, rejected } = detectPIIWithStats(text, enabledTypes);
  const redaction = redactText(text, entities, mode, { typedFullMask, mapper });
  return {
    format: "text",
    originalText: text,
    sanitizedText: redaction.sanitizedText,
    entities,
    replacements: redaction.replacements,
    rejected,
    mapper: redaction.mapper,
    csvStats: null,
    durationMs: performance.now() - t0,
  };
}
