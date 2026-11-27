/**
 * Redaction strategies: Full Mask, Partial Mask, and Consistent Pseudonymization.
 */

import { FULL_MASK_LABELS, PSEUDONYM_PREFIX } from "./config.js";

/**
 * Normalize an entity value prior to pseudonym dictionary lookup so case and
 * formatting variants map to the exact same placeholder.
 *
 * @param {string} type - Entity type identifier.
 * @param {string} value - Raw matched substring.
 * @returns {string} Canonical lookup key.
 */
export function normalizeForMapping(type, value) {
  const trimmed = String(value || "").trim();
  switch (type) {
    case "email":
      return trimmed.toLowerCase();
    case "pan":
      return trimmed.toUpperCase();
    case "credit_card":
    case "aadhaar":
      return trimmed.replace(/\D/g, "");
    case "phone": {
      const compact = trimmed.replace(/[\s().-]/g, "");
      if (compact.startsWith("+")) {
        return /^\+0091[6-9]\d{9}$/.test(compact) ? `+91${compact.slice(5)}` : compact;
      }
      if (!trimmed.includes("(") && /^(?:0091|91|0)?[6-9]\d{9}$/.test(compact)) {
        return `+91${compact.slice(-10)}`;
      }
      return compact;
    }
    case "ip":
      return trimmed.toLowerCase();
    default:
      return trimmed;
  }
}

/**
 * Create a stateful pseudonym mapper maintaining consistent numbered tokens per type.
 *
 * @param {Array<{ token: string, type: string, normalized: string, count?: number, variants?: string[] }>} [initialEntries]
 * @returns {{ resolve: Function, beginRun: Function, entries: Function, reset: Function }}
 */
export function createPseudonymMapper(initialEntries = []) {
  const keyToEntry = new Map();
  const typeCounters = new Map();

  for (const item of initialEntries) {
    const mapKey = `${item.type}:${item.normalized}`;
    keyToEntry.set(mapKey, {
      token: item.token,
      type: item.type,
      normalized: item.normalized,
      count: item.count || 0,
      variants: new Set(item.variants || []),
    });
    const suffixNum = Number(item.token.split("_").pop()) || 0;
    typeCounters.set(item.type, Math.max(typeCounters.get(item.type) || 0, suffixNum));
  }

  return {
    resolve(type, rawValue) {
      const normalized = normalizeForMapping(type, rawValue);
      const mapKey = `${type}:${normalized}`;
      let entry = keyToEntry.get(mapKey);

      if (!entry) {
        const nextNum = (typeCounters.get(type) || 0) + 1;
        typeCounters.set(type, nextNum);
        const prefix = PSEUDONYM_PREFIX[type] || "ENTITY";
        entry = {
          token: `${prefix}_${String(nextNum).padStart(2, "0")}`,
          type,
          normalized,
          count: 0,
          variants: new Set(),
        };
        keyToEntry.set(mapKey, entry);
      }

      entry.count += 1;
      entry.variants.add(rawValue);
      return entry.token;
    },

    beginRun() {
      for (const entry of keyToEntry.values()) {
        entry.count = 0;
      }
    },

    entries() {
      return Array.from(keyToEntry.values()).map((entry) => ({
        token: entry.token,
        type: entry.type,
        normalized: entry.normalized,
        count: entry.count,
        variants: Array.from(entry.variants),
      }));
    },

    reset() {
      keyToEntry.clear();
      typeCounters.clear();
    },
  };
}

function maskDigitsKeepLast4(raw, defaultFormattedMask) {
  const digits = raw.replace(/\D/g, "");
  if (!raw.includes(" ") && !raw.includes("-") && defaultFormattedMask) {
    return defaultFormattedMask(digits);
  }
  const keepFrom = Math.max(0, digits.length - 4);
  const chars = new Array(raw.length);
  let digitIndex = 0;
  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i];
    if (ch >= "0" && ch <= "9") {
      chars[i] = digitIndex < keepFrom ? "X" : ch;
      digitIndex += 1;
    } else {
      chars[i] = ch;
    }
  }
  return chars.join("");
}

function partialMaskCard(raw) {
  return maskDigitsKeepLast4(raw, (digits) => {
    const last4 = digits.slice(-4);
    return digits.length === 16 ? `XXXX-XXXX-XXXX-${last4}` : `${"X".repeat(Math.max(0, digits.length - 4))}${last4}`;
  });
}

function partialMaskAadhaar(raw) {
  return maskDigitsKeepLast4(raw, (digits) => `XXXX-XXXX-${digits.slice(-4)}`);
}

function partialMaskPhone(raw) {
  const digits = raw.replace(/\D/g, "");
  const keepFrom = Math.max(0, digits.length - 4);
  if (!/[\s()-]/.test(raw)) {
    const last4 = digits.slice(-4);
    if (raw.startsWith("+91") && digits.length === 12) return `+91-XXXXX-X${last4}`;
    return `${"X".repeat(Math.max(0, digits.length - 4))}${last4}`;
  }
  const prefixMatch = raw.startsWith("+") ? raw.match(/^\+\d{1,3}[\s-]+/) : null;
  const prefixDigits = prefixMatch ? prefixMatch[0].replace(/\D/g, "").length : 0;
  const chars = new Array(raw.length);
  let digitIndex = 0;
  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i];
    if (ch >= "0" && ch <= "9") {
      chars[i] = digitIndex < prefixDigits || digitIndex >= keepFrom ? ch : "X";
      digitIndex += 1;
    } else {
      chars[i] = ch;
    }
  }
  return chars.join("");
}

function partialMaskIP(raw) {
  if (!raw.includes(":")) {
    const parts = raw.split(".");
    return parts.length === 4 ? `${parts[0]}.${parts[1]}.XXX.XXX` : "XXX.XXX.XXX.XXX";
  }
  if (raw.includes(".")) {
    const lastColon = raw.lastIndexOf(":");
    const v4Parts = raw.slice(lastColon + 1).split(".");
    if (v4Parts.length === 4) return `${raw.slice(0, lastColon + 1)}${v4Parts[0]}.${v4Parts[1]}.XXX.XXX`;
  }
  if (raw.includes("::")) {
    const [left] = raw.split("::");
    return left ? `${left.split(":").slice(0, 2).join(":")}::XXXX` : "::XXXX";
  }
  const groups = raw.split(":");
  return `${groups.slice(0, 2).join(":")}:${Array(Math.max(1, groups.length - 2)).fill("XXXX").join(":")}`;
}

/**
 * Format a single entity replacement string for the requested redaction mode.
 *
 * @param {{ type: string, value: string }} entity - Detected PII entity.
 * @param {"full"|"partial"|"pseudonym"} mode - Active redaction strategy.
 * @param {{ typedFullMask?: boolean, mapper?: object }} [options] - Redaction options.
 * @returns {string} Replacement string.
 */
export function formatReplacement(entity, mode, options = {}) {
  const { typedFullMask = false, mapper } = options;

  if (mode === "full") {
    return typedFullMask ? `[REDACTED:${FULL_MASK_LABELS[entity.type] || entity.type.toUpperCase()}]` : "[REDACTED]";
  }

  if (mode === "partial") {
    switch (entity.type) {
      case "credit_card": return partialMaskCard(entity.value);
      case "aadhaar": return partialMaskAadhaar(entity.value);
      case "pan": return entity.value.length === 10 ? `${entity.value.slice(0, 2)}XXXXXX${entity.value.slice(-2)}` : "[REDACTED:PAN]";
      case "phone": return partialMaskPhone(entity.value);
      case "email": {
        const at = entity.value.indexOf("@");
        return at >= 1 ? `${entity.value[0]}***${entity.value.slice(at)}` : "***";
      }
      case "ip": return partialMaskIP(entity.value);
      default: return "[REDACTED]";
    }
  }

  if (mode === "pseudonym") {
    if (!mapper) throw new Error("Pseudonym mode requires a mapper instance.");
    return mapper.resolve(entity.type, entity.value);
  }

  return "[REDACTED]";
}

/**
 * Redact detected entities in text while tracking exact replacement offsets.
 *
 * @param {string} text - Source plain text.
 * @param {Array<object>} entities - Sorted non-overlapping detected entities.
 * @param {"full"|"partial"|"pseudonym"} [mode="full"] - Redaction strategy.
 * @param {{ typedFullMask?: boolean, mapper?: object }} [options={}] - Redaction options.
 * @returns {{ sanitizedText: string, replacements: Array<object>, mapper: object }}
 */
export function redactText(text, entities, mode = "full", options = {}) {
  const activeMapper = options.mapper || createPseudonymMapper();
  if (!text || !Array.isArray(entities) || entities.length === 0) {
    return { sanitizedText: text || "", replacements: [], mapper: activeMapper };
  }

  const parts = [];
  const replacements = [];
  let cursor = 0;
  let sanitizedLength = 0;

  for (const entity of entities) {
    if (entity.start > cursor) {
      const unchanged = text.slice(cursor, entity.start);
      parts.push(unchanged);
      sanitizedLength += unchanged.length;
    }
    const replacement = formatReplacement(entity, mode, {
      typedFullMask: Boolean(options.typedFullMask),
      mapper: activeMapper,
    });
    const sanitizedStart = sanitizedLength;
    parts.push(replacement);
    sanitizedLength += replacement.length;
    replacements.push({
      type: entity.type,
      originalStart: entity.start,
      originalEnd: entity.end,
      sanitizedStart,
      sanitizedEnd: sanitizedLength,
      original: entity.value,
      replacement,
    });
    cursor = entity.end;
  }

  if (cursor < text.length) parts.push(text.slice(cursor));
  return { sanitizedText: parts.join(""), replacements, mapper: activeMapper };
}
