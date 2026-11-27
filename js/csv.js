/**
 * RFC-4180 CSV parser, per-cell sanitizer, and formula-injection-safe serializer.
 * Phase 1 scaffold — full parser and serializer implemented in Phase 4.
 */

export function parseCSV(text) {
  return text ? [[text]] : [];
}

export function serializeCSV(rows) {
  return rows.map((row) => row.join(",")).join("\n");
}
