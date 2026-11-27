/**
 * RFC-4180 CSV parser, formula-injection guard, and offset-aware serializer.
 */

import { detectPIIWithStats } from "./detectors.js";
import { createPseudonymMapper, redactText } from "./redactors.js";

const FORMULA_TRIGGER_RE = /^[=+\-@]/;

function readQuotedField(text, startIdx) {
  let i = startIdx + 1;
  let chunkStart = i;
  let parts = null;
  let charOffsets = null;
  let unescapedLen = 0;

  while (i < text.length) {
    const nextQuote = text.indexOf('"', i);
    if (nextQuote === -1) {
      i = text.length;
      break;
    }
    if (nextQuote + 1 < text.length && text[nextQuote + 1] === '"') {
      if (!parts) {
        parts = [];
        charOffsets = [];
      }
      if (nextQuote > chunkStart) {
        const seg = text.slice(chunkStart, nextQuote);
        parts.push(seg);
        for (let k = chunkStart; k < nextQuote; k++) charOffsets.push(k);
        unescapedLen += seg.length;
      }
      parts.push('"');
      charOffsets.push(nextQuote);
      unescapedLen += 1;
      i = nextQuote + 2;
      chunkStart = i;
    } else {
      const valueEnd = nextQuote;
      let tailEnd = valueEnd + 1;
      while (tailEnd < text.length && text[tailEnd] !== "," && text[tailEnd] !== "\r" && text[tailEnd] !== "\n") {
        tailEnd += 1;
      }
      if (!parts && tailEnd === valueEnd + 1) {
        return {
          field: {
            value: text.slice(chunkStart, valueEnd),
            baseOffset: chunkStart,
            charOffsets: null,
            quoted: true,
          },
          nextIdx: tailEnd,
        };
      }
      if (!parts) {
        parts = [];
        charOffsets = [];
      }
      if (valueEnd > chunkStart) {
        parts.push(text.slice(chunkStart, valueEnd));
        for (let k = chunkStart; k < valueEnd; k++) charOffsets.push(k);
      }
      for (let k = valueEnd + 1; k < tailEnd; k++) {
        parts.push(text[k]);
        charOffsets.push(k);
      }
      return {
        field: { value: parts.join(""), baseOffset: chunkStart, charOffsets, quoted: true },
        nextIdx: tailEnd,
      };
    }
  }

  if (!parts) {
    return {
      field: { value: text.slice(chunkStart, i), baseOffset: chunkStart, charOffsets: null, quoted: true },
      nextIdx: i,
    };
  }
  if (i > chunkStart) {
    parts.push(text.slice(chunkStart, i));
    for (let k = chunkStart; k < i; k++) charOffsets.push(k);
  }
  return {
    field: { value: parts.join(""), baseOffset: startIdx + 1, charOffsets, quoted: true, length: unescapedLen },
    nextIdx: i,
  };
}

function readPlainField(text, startIdx) {
  let i = startIdx;
  while (i < text.length) {
    const code = text.charCodeAt(i);
    if (code === 44 || code === 13 || code === 10) break;
    i += 1;
  }
  return {
    field: { value: text.slice(startIdx, i), baseOffset: startIdx, charOffsets: null, quoted: false },
    nextIdx: i,
  };
}

/**
 * Parse RFC-4180 CSV text into rows with line-ending metadata and zero-allocation raw offsets.
 * Edge cases: handles quoted commas/newlines, escaped "" quotes, unclosed quotes, and trailing commas.
 *
 * @param {string} text - Raw CSV input.
 * @returns {{ rows: Array<Array<{ value: string, baseOffset: number, charOffsets: number[]|null, quoted: boolean }>>, lineEnding: string, hadTrailingNewline: boolean }}
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

  while (i <= text.length) {
    const parsed = i < text.length && text[i] === '"' ? readQuotedField(text, i) : readPlainField(text, i);
    currentRow.push(parsed.field);
    i = parsed.nextIdx;

    if (i < text.length && text[i] === ",") {
      i += 1;
      if (i === text.length) {
        currentRow.push({ value: "", baseOffset: i, charOffsets: null, quoted: false });
        rows.push(currentRow);
        break;
      }
      continue;
    }
    if (i < text.length && (text[i] === "\r" || text[i] === "\n")) {
      i += text[i] === "\r" && text[i + 1] === "\n" ? 2 : 1;
      rows.push(currentRow);
      currentRow = [];
      if (i === text.length) break;
      continue;
    }
    rows.push(currentRow);
    break;
  }
  return { rows, lineEnding, hadTrailingNewline };
}

/**
 * Parse RFC-4180 CSV text into a 2D array of unescaped string cells.
 *
 * @param {string} text - Raw CSV string.
 * @returns {string[][]} Parsed rows of string values.
 */
export function parseCSV(text) {
  return parseCSVWithMeta(text).rows.map((row) => row.map((cell) => cell.value));
}

/**
 * Neutralize spreadsheet formula triggers (=, +, -, @) and RFC-4180-escape a CSV cell.
 *
 * @param {unknown} value - Cell value.
 * @param {boolean} [guardFormula=true] - Whether to prepend "'" to formula-triggering cells.
 * @returns {{ serialized: string, isQuoted: boolean, formulaPrefixLen: number, innerText: string }}
 */
export function escapeCSVCell(value, guardFormula = true) {
  let cell = String(value ?? "");
  let formulaPrefixLen = 0;
  if (guardFormula && FORMULA_TRIGGER_RE.test(cell)) {
    cell = `'${cell}`;
    formulaPrefixLen = 1;
  }
  const needsQuotes = cell.includes(",") || cell.includes('"') || cell.includes("\n") || cell.includes("\r");
  if (!needsQuotes) {
    return { serialized: cell, isQuoted: false, formulaPrefixLen, innerText: cell };
  }
  return { serialized: `"${cell.replace(/"/g, '""')}"`, isQuoted: true, formulaPrefixLen, innerText: cell };
}

/**
 * Serialize a 2D array of cells back into RFC-4180 CSV text.
 *
 * @param {string[][]} rows - Rows of unescaped string cells.
 * @param {{ lineEnding?: string, hadTrailingNewline?: boolean, guardFormula?: boolean }} [options={}]
 * @returns {string} Serialized CSV text.
 */
export function serializeCSV(rows, options = {}) {
  const { lineEnding = "\n", hadTrailingNewline = false, guardFormula = true } = options;
  if (!Array.isArray(rows) || rows.length === 0) return "";
  const body = rows.map((row) => row.map((cell) => escapeCSVCell(cell, guardFormula).serialized).join(",")).join(lineEnding);
  return hadTrailingNewline ? `${body}${lineEnding}` : body;
}

function mapCellOffsetToSerialized(innerText, indexInCell, formulaPrefixLen, isQuoted) {
  const targetIdx = Math.min(indexInCell + formulaPrefixLen, innerText.length);
  let extraQuotes = 0;
  if (isQuoted && innerText.includes('"')) {
    let pos = 0;
    while (pos < targetIdx) {
      const q = innerText.indexOf('"', pos);
      if (q === -1 || q >= targetIdx) break;
      extraQuotes += 1;
      pos = q + 1;
    }
  }
  return (isQuoted ? 1 : 0) + targetIdx + extraQuotes;
}

function getRawSpan(cell, start, end) {
  if (!cell.charOffsets) {
    return { origStart: cell.baseOffset + start, origEnd: cell.baseOffset + end };
  }
  return { origStart: cell.charOffsets[start], origEnd: cell.charOffsets[end - 1] + 1 };
}

function processCSVCell(cell, isHeader, ctx) {
  let cellSanitizedValue = cell.value;
  let cellReplacements = [];

  if (!isHeader && cell.value.length > 0) {
    const detection = detectPIIWithStats(cell.value, ctx.enabledTypes);
    for (const key of Object.keys(ctx.rejected)) {
      ctx.rejected[key] += detection.rejected[key] || 0;
    }
    if (detection.entities.length > 0) {
      ctx.cellsSanitized += 1;
      for (const ent of detection.entities) {
        const { origStart, origEnd } = getRawSpan(cell, ent.start, ent.end);
        if (origStart !== undefined && origEnd !== undefined) {
          ctx.originalEntities.push({ ...ent, start: origStart, end: origEnd });
        }
      }
      const redaction = redactText(cell.value, detection.entities, ctx.mode, {
        typedFullMask: ctx.typedFullMask,
        mapper: ctx.mapper,
      });
      cellSanitizedValue = redaction.sanitizedText;
      cellReplacements = redaction.replacements;
    }
  }

  const escaped = escapeCSVCell(cellSanitizedValue, ctx.guardFormula);
  if (escaped.formulaPrefixLen > 0) ctx.formulasGuarded += 1;

  for (const rep of cellReplacements) {
    const relStart = mapCellOffsetToSerialized(escaped.innerText, rep.sanitizedStart, escaped.formulaPrefixLen, escaped.isQuoted);
    const relEnd = mapCellOffsetToSerialized(escaped.innerText, rep.sanitizedEnd, escaped.formulaPrefixLen, escaped.isQuoted);
    ctx.sanitizedReplacements.push({
      ...rep,
      sanitizedStart: ctx.runningOffset + relStart,
      sanitizedEnd: ctx.runningOffset + relEnd,
    });
  }
  return escaped.serialized;
}

/**
 * Sanitize CSV text cell-by-cell while preserving row 0 headers and RFC-4180 structure.
 *
 * @param {string} text - Raw CSV text.
 * @param {object} [options={}] - Sanitization options (enabledTypes, mode, typedFullMask, mapper, guardFormula).
 * @returns {{ originalText: string, sanitizedText: string, entities: Array<object>, replacements: Array<object>, rejected: object, mapper: object, csvStats: object }}
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
  const ctx = {
    enabledTypes,
    mode,
    typedFullMask,
    mapper,
    guardFormula,
    rejected: { luhn: 0, verhoeff: 0, ipv4: 0, pan: 0, phone: 0 },
    originalEntities: [],
    sanitizedReplacements: [],
    runningOffset: 0,
    cellsSanitized: 0,
    formulasGuarded: 0,
  };

  if (rows.length === 0) {
    return {
      originalText: text,
      sanitizedText: "",
      entities: [],
      replacements: [],
      rejected: ctx.rejected,
      mapper,
      csvStats: { rows: 0, dataRows: 0, cellsSanitized: 0, formulasGuarded: 0 },
    };
  }

  const sanitizedLines = rows.map((row, r) => {
    const serializedRow = row
      .map((cell, c) => {
        if (c > 0) ctx.runningOffset += 1;
        const serialized = processCSVCell(cell, r === 0, ctx);
        ctx.runningOffset += serialized.length;
        return serialized;
      })
      .join(",");
    if (r < rows.length - 1 || hadTrailingNewline) ctx.runningOffset += lineEnding.length;
    return serializedRow;
  });

  const body = sanitizedLines.join(lineEnding);
  return {
    originalText: text,
    sanitizedText: hadTrailingNewline ? `${body}${lineEnding}` : body,
    entities: ctx.originalEntities,
    replacements: ctx.sanitizedReplacements,
    rejected: ctx.rejected,
    mapper,
    csvStats: {
      rows: rows.length,
      dataRows: Math.max(0, rows.length - 1),
      cellsSanitized: ctx.cellsSanitized,
      formulasGuarded: ctx.formulasGuarded,
    },
  };
}
