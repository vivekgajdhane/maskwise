/**
 * Cryptographic & structural validators for PII candidates.
 */

import { PAN_HOLDER_TYPES } from "./config.js";

export { PAN_HOLDER_TYPES };

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
 * Validate a 13–19 digit payment card string using the Luhn (mod 10) checksum.
 * Edge cases: rejects leading zero, non-digits, lengths outside 13–19, and all-identical digits.
 *
 * @param {string} digits - Digit-only card candidate.
 * @returns {boolean} True when Luhn checksum passes.
 */
export function isValidLuhn(digits) {
  if (typeof digits !== "string" || !ASCII_DIGITS_RE.test(digits)) return false;
  if (digits.length < 13 || digits.length > 19) return false;
  if (digits.startsWith("0") || ALL_SAME_DIGIT_RE.test(digits)) return false;

  let sum = 0;
  let shouldDouble = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let digit = digits.charCodeAt(i) - 48;
    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    shouldDouble = !shouldDouble;
  }
  return sum % 10 === 0;
}

/**
 * Identify probable payment card network from IIN/BIN prefixes and length.
 * Edge cases: checks RuPay 6521/6522 before Discover 65, and 6011 as Discover before RuPay 60.
 *
 * @param {string} digits - Digit-only card number.
 * @returns {string} Issuer name ("Visa", "Amex", "Mastercard", "RuPay", "Discover", or "Card").
 */
export function detectCardIssuer(digits) {
  if (typeof digits !== "string" || !ASCII_DIGITS_RE.test(digits)) return "Card";
  const len = digits.length;

  if (digits.startsWith("4") && (len === 13 || len === 16 || len === 19)) return "Visa";
  if ((digits.startsWith("34") || digits.startsWith("37")) && len === 15) return "Amex";

  const prefix2 = Number(digits.slice(0, 2));
  const prefix4 = Number(digits.slice(0, 4));
  if (len === 16 && ((prefix2 >= 51 && prefix2 <= 55) || (prefix4 >= 2221 && prefix4 <= 2720))) {
    return "Mastercard";
  }

  const isRuPayPrefix =
    digits.startsWith("6521") ||
    digits.startsWith("6522") ||
    digits.startsWith("508") ||
    digits.startsWith("60") ||
    digits.startsWith("81") ||
    digits.startsWith("82");
  if (len === 16 && isRuPayPrefix && !digits.startsWith("6011")) return "RuPay";

  const prefix3 = Number(digits.slice(0, 3));
  const isDiscover =
    digits.startsWith("6011") || (prefix3 >= 644 && prefix3 <= 649) || digits.startsWith("65");
  if ((len === 16 || len === 19) && isDiscover) return "Discover";

  return "Card";
}

/**
 * Validate a numeric string using the Verhoeff dihedral group D5 checksum.
 * Edge cases: rejects empty strings, non-digits, and all-identical digits.
 *
 * @param {string} digits - Digit-only string.
 * @returns {boolean} True when Verhoeff checksum equals 0.
 */
export function isValidVerhoeff(digits) {
  if (typeof digits !== "string" || digits.length === 0 || !ASCII_DIGITS_RE.test(digits)) {
    return false;
  }
  if (ALL_SAME_DIGIT_RE.test(digits)) return false;

  let checksum = 0;
  for (let i = 0; i < digits.length; i++) {
    const digit = digits.charCodeAt(digits.length - 1 - i) - 48;
    checksum = VERHOEFF_D[checksum][VERHOEFF_P[i % 8][digit]];
  }
  return checksum === 0;
}

/**
 * Validate an Indian Aadhaar number (12 digits, first digit 2–9, Verhoeff valid).
 *
 * @param {string} digits - Digit-only 12-char Aadhaar candidate.
 * @returns {boolean} True when UIDAI structural and Verhoeff checks pass.
 */
export function isValidAadhaar(digits) {
  if (typeof digits !== "string" || digits.length !== 12 || !ASCII_DIGITS_RE.test(digits)) {
    return false;
  }
  const firstDigit = digits.charCodeAt(0) - 48;
  if (firstDigit < 2 || firstDigit > 9) return false;
  return isValidVerhoeff(digits);
}

/**
 * Validate an Indian PAN string including the 4th-character holder code.
 *
 * @param {string} pan - 10-character uppercase PAN candidate.
 * @returns {boolean} True when format and holder type code are valid.
 */
export function isValidPan(pan) {
  if (typeof pan !== "string" || !PAN_FORMAT_RE.test(pan)) return false;
  return PAN_HOLDER_TYPES.has(pan[3]);
}

/**
 * Validate an IPv4 address strictly (4 octets in 0–255, no leading zeros).
 * Edge cases: "0.0.0.0" is valid; "192.168.01.1" and "256.0.0.1" return false.
 *
 * @param {string} ip - Dotted IPv4 candidate.
 * @returns {boolean} True when strictly valid IPv4.
 */
export function isValidIPv4(ip) {
  if (typeof ip !== "string") return false;
  const parts = ip.split(".");
  if (parts.length !== 4) return false;
  for (const part of parts) {
    if (part.length === 0 || part.length > 3 || !ASCII_DIGITS_RE.test(part)) return false;
    if (part.length > 1 && part.startsWith("0")) return false;
    const num = Number(part);
    if (num < 0 || num > 255) return false;
  }
  return true;
}

function validateIPv6GroupList(groups, allowTrailingIPv4) {
  let ipv4TailUsed = false;
  for (let i = 0; i < groups.length; i++) {
    const group = groups[i];
    if (allowTrailingIPv4 && i === groups.length - 1 && group.includes(".")) {
      if (!isValidIPv4(group)) return { valid: false, ipv4TailUsed: false };
      ipv4TailUsed = true;
    } else if (!HEX_GROUP_RE.test(group)) {
      return { valid: false, ipv4TailUsed: false };
    }
  }
  return { valid: true, ipv4TailUsed };
}

/**
 * Validate full and compressed IPv6 addresses, including IPv4-mapped tails.
 * Edge cases: rejects triple colons, multiple "::", and C++ scope tokens like "std::vector".
 *
 * @param {string} ip - IPv6 candidate string.
 * @returns {boolean} True when valid IPv6.
 */
export function isValidIPv6(ip) {
  if (typeof ip !== "string" || !ip.includes(":") || ip.includes(":::")) return false;
  const parts = ip.split("::");
  if (parts.length > 2) return false;

  const hasCompression = parts.length === 2;
  const leftGroups = parts[0] ? parts[0].split(":") : [];
  const rightGroups = hasCompression && parts[1] ? parts[1].split(":") : [];

  const leftCheck = validateIPv6GroupList(leftGroups, !hasCompression);
  if (!leftCheck.valid) return false;

  if (!hasCompression) {
    return leftGroups.length === (leftCheck.ipv4TailUsed ? 7 : 8);
  }

  const rightCheck = validateIPv6GroupList(rightGroups, true);
  if (!rightCheck.valid) return false;

  const totalHextets = leftGroups.length + rightGroups.length + (rightCheck.ipv4TailUsed ? 1 : 0);
  if (totalHextets >= 8 || totalHextets < 1) return false;

  const colonCount = (ip.match(/:/g) || []).length;
  const isLoopbackLike = leftGroups.length === 0 && rightGroups.length === 1 && /^\d+$/.test(rightGroups[0]);
  return !(colonCount === 2 && ip !== "::1" && !isLoopbackLike);
}
