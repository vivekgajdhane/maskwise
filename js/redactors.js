/**
 * Redaction strategies: Full Mask, Partial Mask, and Consistent Pseudonymization.
 */

const FULL_MASK_LABELS = {
  email: "EMAIL",
  phone: "PHONE",
  ip: "IP",
  pan: "PAN",
  aadhaar: "AADHAAR",
  credit_card: "CARD",
};

const PSEUDONYM_PREFIX = {
  email: "USER",
  phone: "PHONE",
  credit_card: "CARD",
  aadhaar: "AADHAAR",
  pan: "PAN",
  ip: "IP",
};

/**
 * Normalize an entity value prior to pseudonym dictionary lookup so
 * case and formatting variants map to the exact same placeholder.
 */
export function normalizeForMapping(type, value) {
  const trimmed = value.trim();
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
        if (/^\+0091[6-9]\d{9}$/.test(compact)) {
          return `+91${compact.slice(5)}`;
        }
        return compact;
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
 * Stateful mapper maintaining consistent deterministic placeholders per entity type.
 */
export function createPseudonymMapper() {
  const keyToEntry = new Map();
  const typeCounters = new Map();

  return {
    resolve(type, rawValue) {
      const normalized = normalizeForMapping(type, rawValue);
      const mapKey = `${type}:${normalized}`;
      let entry = keyToEntry.get(mapKey);

      if (!entry) {
        const nextNum = (typeCounters.get(type) || 0) + 1;
        typeCounters.set(type, nextNum);
        const prefix = PSEUDONYM_PREFIX[type] || "ENTITY";
        const token = `${prefix}_${String(nextNum).padStart(2, "0")}`;
        entry = {
          token,
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
  let digitIndex = 0;
  let out = "";
  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i];
    if (ch >= "0" && ch <= "9") {
      out += digitIndex < keepFrom ? "X" : ch;
      digitIndex += 1;
    } else {
      out += ch;
    }
  }
  return out;
}

function partialMaskCard(raw) {
  return maskDigitsKeepLast4(raw, (digits) => {
    const last4 = digits.slice(-4);
    if (digits.length === 16) {
      return `XXXX-XXXX-XXXX-${last4}`;
    }
    return `${"X".repeat(Math.max(0, digits.length - 4))}${last4}`;
  });
}

function partialMaskAadhaar(raw) {
  return maskDigitsKeepLast4(raw, (digits) => `XXXX-XXXX-${digits.slice(-4)}`);
}

function partialMaskPan(raw) {
  if (raw.length !== 10) {
    return "[REDACTED:PAN]";
  }
  return `${raw.slice(0, 2)}XXXXXX${raw.slice(-2)}`;
}

function partialMaskPhone(raw) {
  const digits = raw.replace(/\D/g, "");
  const keepFrom = Math.max(0, digits.length - 4);

  // If unseparated Indian number (e.g. +919876543210 or 9876543210)
  if (!/[\s()-]/.test(raw)) {
    const last4 = digits.slice(-4);
    if (raw.startsWith("+91") && digits.length === 12) {
      return `+91-XXXXX-X${last4}`;
    }
    return `${"X".repeat(Math.max(0, digits.length - 4))}${last4}`;
  }

  // Preserve country prefix (+CC) if separated, mask subscriber digits except last 4
  let prefixEnd = 0;
  if (raw.startsWith("+")) {
    const prefixMatch = raw.match(/^\+\d{1,3}[\s-]+/);
    if (prefixMatch) {
      prefixEnd = prefixMatch[0].length;
    }
  }

  const prefixDigitCount = raw.slice(0, prefixEnd).replace(/\D/g, "").length;
  let digitIndex = 0;
  let out = "";
  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i];
    if (ch >= "0" && ch <= "9") {
      if (digitIndex < prefixDigitCount || digitIndex >= keepFrom) {
        out += ch;
      } else {
        out += "X";
      }
      digitIndex += 1;
    } else {
      out += ch;
    }
  }
  return out;
}

function partialMaskEmail(raw) {
  const atIndex = raw.indexOf("@");
  if (atIndex < 1) {
    return "***";
  }
  const firstChar = raw[0];
  const domain = raw.slice(atIndex);
  return `${firstChar}***${domain}`;
}

function partialMaskIP(raw) {
  if (!raw.includes(":")) {
    const parts = raw.split(".");
    if (parts.length === 4) {
      return `${parts[0]}.${parts[1]}.XXX.XXX`;
    }
    return "XXX.XXX.XXX.XXX";
  }

  // IPv6 (with optional IPv4-mapped tail)
  if (raw.includes(".")) {
    const lastColon = raw.lastIndexOf(":");
    const prefix = raw.slice(0, lastColon + 1);
    const v4Parts = raw.slice(lastColon + 1).split(".");
    if (v4Parts.length === 4) {
      return `${prefix}${v4Parts[0]}.${v4Parts[1]}.XXX.XXX`;
    }
  }

  if (raw.includes("::")) {
    const [left] = raw.split("::");
    if (!left) {
      return "::XXXX";
    }
    const leftGroups = left.split(":").slice(0, 2);
    return `${leftGroups.join(":")}::XXXX`;
  }

  const groups = raw.split(":");
  const head = groups.slice(0, 2).join(":");
  const tail = Array(Math.max(1, groups.length - 2)).fill("XXXX").join(":");
  return `${head}:${tail}`;
}

/**
 * Format a single entity replacement according to the selected mode.
 */
export function formatReplacement(entity, mode, options = {}) {
  const { typedFullMask = false, mapper } = options;

  if (mode === "full") {
    if (typedFullMask) {
      const label = FULL_MASK_LABELS[entity.type] || entity.type.toUpperCase();
      return `[REDACTED:${label}]`;
    }
    return "[REDACTED]";
  }

  if (mode === "partial") {
    switch (entity.type) {
      case "credit_card":
        return partialMaskCard(entity.value);
      case "aadhaar":
        return partialMaskAadhaar(entity.value);
      case "pan":
        return partialMaskPan(entity.value);
      case "phone":
        return partialMaskPhone(entity.value);
      case "email":
        return partialMaskEmail(entity.value);
      case "ip":
        return partialMaskIP(entity.value);
      default:
        return "[REDACTED]";
    }
  }

  if (mode === "pseudonym") {
    if (!mapper) {
      throw new Error("Pseudonym mode requires a mapper instance.");
    }
    return mapper.resolve(entity.type, entity.value);
  }

  return "[REDACTED]";
}

/**
 * Redact detected entities in text while tracking exact replacement offsets
 * for side-by-side diff highlighting.
 */
export function redactText(text, entities, mode = "full", options = {}) {
  const activeMapper = options.mapper || createPseudonymMapper();
  if (!text || !Array.isArray(entities) || entities.length === 0) {
    return {
      sanitizedText: text || "",
      replacements: [],
      mapper: activeMapper,
    };
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

  if (cursor < text.length) {
    parts.push(text.slice(cursor));
  }

  return {
    sanitizedText: parts.join(""),
    replacements,
    mapper: activeMapper,
  };
}
