/**
 * Cryptographic & structural validators for PII candidates.
 * Why: Regex alone creates high false-positive rates on random numeric IDs,
 * version numbers, and malformed addresses; checksums filter out decoys.
 */

export const PAN_HOLDER_TYPES = new Set([
  "P", // Individual
  "C", // Company
  "H", // Hindu Undivided Family (HUF)
  "F", // Firm / Partnership
  "A", // Association of Persons (AOP)
  "T", // Trust
  "B", // Body of Individuals (BOI)
  "L", // Local Authority
  "J", // Artificial Juridical Person
  "G", // Government
]);

const VERHOEFF_D = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
  [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
  [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
  [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
  [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
  [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
  [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
  [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
  [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];

const VERHOEFF_P = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
  [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
  [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
  [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
  [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
  [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
  [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

const ASCII_DIGITS_RE = /^\d+$/;
const ALL_SAME_DIGIT_RE = /^(\d)\1+$/;
const HEX_GROUP_RE = /^[0-9A-Fa-f]{1,4}$/;
const PAN_FORMAT_RE = /^[A-Z]{5}[0-9]{4}[A-Z]$/;

/**
 * Validate a numeric string (13-19 digits) using the Luhn checksum.
 */
export function isValidLuhn(digits) {
  if (typeof digits !== "string" || !ASCII_DIGITS_RE.test(digits)) {
    return false;
  }
  if (digits.length < 13 || digits.length > 19) {
    return false;
  }
  if (digits.startsWith("0") || ALL_SAME_DIGIT_RE.test(digits)) {
    return false;
  }

  let sum = 0;
  let shouldDouble = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let digit = digits.charCodeAt(i) - 48;
    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) {
        digit -= 9;
      }
    }
    sum += digit;
    shouldDouble = !shouldDouble;
  }
  return sum % 10 === 0;
}

/**
 * Return the probable card network hint from IIN/BIN prefixes.
 */
export function detectCardIssuer(digits) {
  if (typeof digits !== "string" || !ASCII_DIGITS_RE.test(digits)) {
    return "Card";
  }
  const len = digits.length;

  if (digits.startsWith("4") && (len === 13 || len === 16 || len === 19)) {
    return "Visa";
  }
  if ((digits.startsWith("34") || digits.startsWith("37")) && len === 15) {
    return "Amex";
  }

  const prefix2 = Number(digits.slice(0, 2));
  const prefix4 = Number(digits.slice(0, 4));
  if (len === 16 && ((prefix2 >= 51 && prefix2 <= 55) || (prefix4 >= 2221 && prefix4 <= 2720))) {
    return "Mastercard";
  }

  // RuPay ranges (check 6521/6522 before general Discover 65)
  if (
    len === 16 &&
    (digits.startsWith("6521") ||
      digits.startsWith("6522") ||
      digits.startsWith("508") ||
      digits.startsWith("60") ||
      digits.startsWith("81") ||
      digits.startsWith("82"))
  ) {
    // 6011 belongs to Discover
    if (!digits.startsWith("6011")) {
      return "RuPay";
    }
  }

  const prefix3 = Number(digits.slice(0, 3));
  if (
    (len === 16 || len === 19) &&
    (digits.startsWith("6011") || (prefix3 >= 644 && prefix3 <= 649) || digits.startsWith("65"))
  ) {
    return "Discover";
  }

  return "Card";
}

/**
 * Validate a 12-digit string using the Verhoeff dihedral group D5 checksum.
 */
export function isValidVerhoeff(digits) {
  if (typeof digits !== "string" || !ASCII_DIGITS_RE.test(digits) || digits.length === 0) {
    return false;
  }
  if (ALL_SAME_DIGIT_RE.test(digits)) {
    return false;
  }

  let checksum = 0;
  for (let i = 0; i < digits.length; i++) {
    const digit = digits.charCodeAt(digits.length - 1 - i) - 48;
    checksum = VERHOEFF_D[checksum][VERHOEFF_P[i % 8][digit]];
  }
  return checksum === 0;
}

/**
 * Validate an Indian Aadhaar number (12 digits, starts with 2-9, passes Verhoeff).
 */
export function isValidAadhaar(digits) {
  if (typeof digits !== "string" || digits.length !== 12 || !ASCII_DIGITS_RE.test(digits)) {
    return false;
  }
  const firstDigit = digits.charCodeAt(0) - 48;
  if (firstDigit < 2 || firstDigit > 9) {
    return false;
  }
  return isValidVerhoeff(digits);
}

/**
 * Validate an Indian PAN string including the 4th character entity type code.
 */
export function isValidPan(pan) {
  if (typeof pan !== "string" || !PAN_FORMAT_RE.test(pan)) {
    return false;
  }
  return PAN_HOLDER_TYPES.has(pan[3]);
}

/**
 * Strictly validate an IPv4 address: 4 octets in [0, 255] with no leading zeros.
 */
export function isValidIPv4(ip) {
  if (typeof ip !== "string") {
    return false;
  }
  const parts = ip.split(".");
  if (parts.length !== 4) {
    return false;
  }
  for (const part of parts) {
    if (part.length === 0 || part.length > 3 || !ASCII_DIGITS_RE.test(part)) {
      return false;
    }
    if (part.length > 1 && part.startsWith("0")) {
      return false;
    }
    const num = Number(part);
    if (num < 0 || num > 255) {
      return false;
    }
  }
  return true;
}

/**
 * Validate full and compressed IPv6 addresses (including IPv4-mapped tails).
 */
export function isValidIPv6(ip) {
  if (typeof ip !== "string" || !ip.includes(":")) {
    return false;
  }
  if (ip.includes(":::")) {
    return false;
  }

  const doubleColonParts = ip.split("::");
  if (doubleColonParts.length > 2) {
    return false;
  }

  const hasCompression = doubleColonParts.length === 2;
  const leftGroups = doubleColonParts[0] ? doubleColonParts[0].split(":") : [];
  const rightRaw = hasCompression ? doubleColonParts[1] : "";
  const rightGroups = rightRaw ? rightRaw.split(":") : [];

  let ipv4TailUsed = false;
  const checkGroups = (groups, allowTrailingIPv4) => {
    for (let i = 0; i < groups.length; i++) {
      const group = groups[i];
      if (allowTrailingIPv4 && i === groups.length - 1 && group.includes(".")) {
        if (!isValidIPv4(group)) {
          return false;
        }
        ipv4TailUsed = true;
      } else if (!HEX_GROUP_RE.test(group)) {
        return false;
      }
    }
    return true;
  };

  if (hasCompression) {
    if (!checkGroups(leftGroups, false) || !checkGroups(rightGroups, true)) {
      return false;
    }
    const totalHextets = leftGroups.length + rightGroups.length + (ipv4TailUsed ? 1 : 0);
    // Compressed form omits at least one 16-bit group; avoid prose false positives like "cafe::babe"
    if (totalHextets >= 8) {
      return false;
    }
    const colonCount = (ip.match(/:/g) || []).length;
    if (colonCount === 2 && !(ip === "::1" || (leftGroups.length === 0 && rightGroups.length === 1 && /^\d+$/.test(rightGroups[0])))) {
      return false;
    }
    return totalHextets >= 1;
  }

  if (!checkGroups(leftGroups, true)) {
    return false;
  }
  const expectedCount = ipv4TailUsed ? 7 : 8;
  return leftGroups.length === expectedCount;
}
