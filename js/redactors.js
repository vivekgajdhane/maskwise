/**
 * Redaction strategies: Full Mask, Partial Mask, Consistent Pseudonymization.
 * Phase 1 scaffold — full redaction logic implemented in Phase 3.
 */

export function createPseudonymMapper() {
  return {
    entries() {
      return [];
    },
    reset() {},
    resolve(_type, value) {
      return value;
    },
  };
}

export function redactText(text, _entities, _mode, _options) {
  return {
    sanitizedText: text,
    replacements: [],
    mapper: createPseudonymMapper(),
  };
}
