/**
 * Sanitization pipeline coordinating plain text and CSV workflows.
 * Phase 1 scaffold — wired completely across Phases 2–5.
 */

import { detectPIIWithStats } from "./detectors.js";
import { redactText } from "./redactors.js";

export function runSanitization(text, options = {}) {
  const {
    enabledTypes,
    mode = "full",
    typedFullMask = false,
    mapper,
  } = options;

  const { entities, rejected } = detectPIIWithStats(text, enabledTypes);
  const redaction = redactText(text, entities, mode, { typedFullMask, mapper });

  return {
    originalText: text,
    sanitizedText: redaction.sanitizedText,
    entities,
    replacements: redaction.replacements,
    rejected,
    mapper: redaction.mapper,
  };
}
