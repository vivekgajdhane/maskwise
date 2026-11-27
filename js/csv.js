/**
 * RFC-4180 CSV parser, formula-injection guard, and offset-aware serializer.
 * Why: Plain-text redaction across raw CSV lines can break quoted fields or
 * miss multiline records; parsing per cell preserves structure and lets us
 * neutralize spreadsheet formula payloads (=, +, -, @) safely.
 */

import { detectPIIWithStats } from "./detectors.js";
import { createPseudonymMapper, redactText } from "./redactors.js";

const FORMULA_TRIGGER_RE = /^[=+\-@]/;

/**
 * Parse RFC-4180 CSV text into rows while retaining line-ending metadata
 * and raw index mappings for each unescaped character in every cell.
 */
export function parseCSVWithMeta(text) {
  if (typeof text !== "string" || text.length === 0) {
    return { rows: [], lineEnding: "\n", hadTrailingNewline: false };
  }

  const lineEnding = text.includes("\r\n") ? "\r\n" : "\n";
  const hadTrailingNewline = text.endsWith("\n") || text.endsWith("\r");

  const rows = [];
  let currentRow = [];
  let i = 0;
  const len = text.length;

  while (i <= len) {
    // Parse one field
    let value = "";
    const charOffsets = [];
    let quoted = false;

    if (i < len && text[i] === '"') {
      quoted = true;
      i += 1; // skip opening quote
      while (i < len) {
        if (text[i] === '"') {
          if (i + 1 < len && text[i + 1] === '"') {
            value += '"';
            charOffsets.push(i);
            i += 2;
          } else {
            i += 1; // skip closing quote
            break;
          }
        } else {
          value += text[i];
          charOffsets.push(i);
          i += 1;
        }
      }
      // Consume any trailing non-delimiter characters before comma/newline gracefully
      while (i < len && text[i] !== "," && text[i] !== "\r" && text[i] !== "\n") {
        value += text[i];
        charOffsets.push(i);
        i += 1;
      }
    } else {
      while (i < len && text[i] !== "," && text[i] !== "\r" && text[i] !== "\n") {
        value += text[i];
        charOffsets.push(i);
        i += 1;
      }
    }

    currentRow.push({ value, charOffsets, quoted });

    if (i < len && text[i] === ",") {
      i += 1;
      // Handle trailing comma at end of input ("a,b,")
      if (i === len) {
        currentRow.push({ value: "", charOffsets: [], quoted: false });
        rows.push(currentRow);
        break;
      }
      continue;
    }

    if (i < len && (text[i] === "\r" || text[i] === "\n")) {
      if (text[i] === "\r" && i + 1 < len && text[i + 1] === "\n") {
        i += 2;
      } else {
        i += 1;
      }
      rows.push(currentRow);
      currentRow = [];
      if (i === len) {
        break;
      }
      continue;
    }

    // End of input
    rows.push(currentRow);
    break;
  }

  return { rows, lineEnding, hadTrailingNewline };
}

/**
 * Simple RFC-4180 parser returning a 2D array of unescaped string cells.
 */
export function parseCSV(text) {
  return parseCSVWithMeta(text).rows.map((row) => row.map((cell) => cell.value));
}

/**
 * Guard a CSV cell against spreadsheet formula injection (=, +, -, @)
 * and escape quotes/newlines/commas according to RFC-4180.
 */
export function escapeCSVCell(value, guardFormula = true) {
  let cell = String(value ?? "");
  let formulaPrefixLen = 0;

  if (guardFormula && FORMULA_TRIGGER_RE.test(cell)) {
    cell = `'${cell}`;
    formulaPrefixLen = 1;
  }

  const needsQuotes =
    cell.includes(",") || cell.includes('"') || cell.includes("\n") || cell.includes("\r");

  if (!needsQuotes) {
    return { serialized: cell, isQuoted: false, formulaPrefixLen, innerText: cell };
  }

  const escaped = cell.replace(/"/g, '""');
  return {
    serialized: `"${escaped}"`,
    isQuoted: true,
    formulaPrefixLen,
    innerText: cell,
  };
}

/**
 * Serialize a 2D array of cells back to RFC-4180 CSV.
 */
export function serializeCSV(rows, options = {}) {
  const {
    lineEnding = "\n",
    hadTrailingNewline = false,
    guardFormula = true,
  } = options;

  if (!rows || rows.length === 0) {
    return "";
  }

  const lines = rows.map((row) =>
    row.map((cell) => escapeCSVCell(cell, guardFormula).serialized).join(",")
  );
  const body = lines.join(lineEnding);
  return hadTrailingNewline ? `${body}${lineEnding}` : body;
}

/**
 * Map a character offset inside a raw unescaped cell string to its index inside
 * the serialized CSV cell (accounting for leading apostrophe, opening quote, and "" escaping).
 */
function mapCellOffsetToSerialized(innerText, indexInOriginalCell, formulaPrefixLen, isQuoted) {
  let outOffset = isQuoted ? 1 : 0;
  const targetIdx = indexInOriginalCell + formulaPrefixLen;
  for (let i = 0; i < targetIdx && i < innerText.length; i++) {
    outOffset += innerText[i] === '"' ? 2 : 1;
  }
  return outOffset;
}

/**
 * Sanitize CSV text cell-by-cell while preserving row 0 headers and RFC-4180 structure.
 * Tracks exact entity offsets in both the original CSV and sanitized CSV for diffing.
 */
export function sanitizeCSV(text, options = {}) {
  const {
    enabledTypes,
    mode = "full",
    typedFullMask = false,
    mapper = createPseudonymMapper(),
    guardFormula = true,
  } = options;

  const { rows, lineEnding, hadTrailingNewline } = parseCSVWithMeta(text);
  const rejected = { luhn: 0, verhoeff: 0, ipv4: 0, pan: 0, phone: 0 };

  if (rows.length === 0) {
    return {
      originalText: text,
      sanitizedText: "",
      entities: [],
      replacements: [],
      rejected,
      mapper,
      csvStats: { rows: 0, dataRows: 0, cellsSanitized: 0, formulasGuarded: 0 },
    };
  }

  const originalEntities = [];
  const sanitizedReplacements = [];
  const sanitizedLines = [];
  let runningSanitizedOffset = 0;
  let cellsSanitized = 0;
  let formulasGuarded = 0;

  for (let r = 0; r < rows.length; r++) {
    const row = rows[r];
    const isHeader = r === 0;
    const serializedCells = [];

    for (let c = 0; c < row.length; c++) {
      if (c > 0) {
        runningSanitizedOffset += 1; // comma delimiter
      }

      const cell = row[c];
      let cellSanitizedValue = cell.value;
      let cellReplacements = [];

      if (!isHeader && cell.value.length > 0) {
        const detection = detectPIIWithStats(cell.value, enabledTypes);
        for (const key of Object.keys(rejected)) {
          rejected[key] += detection.rejected[key] || 0;
        }

        if (detection.entities.length > 0) {
          cellsSanitized += 1;
          for (const ent of detection.entities) {
            const origStart = cell.charOffsets[ent.start];
            const origEnd = cell.charOffsets[ent.end - 1] + 1;
            if (origStart !== undefined && origEnd !== undefined) {
              originalEntities.push({
                ...ent,
                start: origStart,
                end: origEnd,
              });
            }
          }

          const redaction = redactText(cell.value, detection.entities, mode, {
            typedFullMask,
            mapper,
          });
          cellSanitizedValue = redaction.sanitizedText;
          cellReplacements = redaction.replacements;
        }
      }

      const escaped = escapeCSVCell(cellSanitizedValue, guardFormula);
      if (escaped.formulaPrefixLen > 0) {
        formulasGuarded += 1;
      }

      for (const rep of cellReplacements) {
        const relStart = mapCellOffsetToSerialized(
          escaped.innerText,
          rep.sanitizedStart,
          escaped.formulaPrefixLen,
          escaped.isQuoted
        );
        const relEnd = mapCellOffsetToSerialized(
          escaped.innerText,
          rep.sanitizedEnd,
          escaped.formulaPrefixLen,
          escaped.isQuoted
        );
        sanitizedReplacements.push({
          ...rep,
          sanitizedStart: runningSanitizedOffset + relStart,
          sanitizedEnd: runningSanitizedOffset + relEnd,
        });
      }

      serializedCells.push(escaped.serialized);
      runningSanitizedOffset += escaped.serialized.length;
    }

    sanitizedLines.push(serializedCells.join(","));
    if (r < rows.length - 1 || hadTrailingNewline) {
      runningSanitizedOffset += lineEnding.length;
    }
  }

  const sanitizedBody = sanitizedLines.join(lineEnding);
  const sanitizedText = hadTrailingNewline ? `${sanitizedBody}${lineEnding}` : sanitizedBody;

  return {
    originalText: text,
    sanitizedText,
    entities: originalEntities,
    replacements: sanitizedReplacements,
    rejected,
    mapper,
    csvStats: {
      rows: rows.length,
      dataRows: Math.max(0, rows.length - 1),
      cellsSanitized,
      formulasGuarded,
    },
  };
}
