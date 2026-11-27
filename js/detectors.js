/**
 * PII detection engine: email, phone, IPv4/IPv6, Indian PAN, Aadhaar, and credit cards.
 * Uses linear-time ReDoS-safe regular expressions, strict boundary guards,
 * cryptographic/structural validation, and deterministic overlap resolution.
 */

import {
  detectCardIssuer,
  isValidAadhaar,
  isValidIPv4,
  isValidIPv6,
  isValidLuhn,
  isValidPan,
} from "./validators.js";

export const ENTITY_TYPES = ["credit_card", "aadhaar", "pan", "phone", "ip", "email"];

const TYPE_PRIORITY = {
  credit_card: 0,
  aadhaar: 1,
  pan: 2,
  phone: 3,
  ip: 4,
  email: 5,
};

// Flat, ReDoS-safe patterns (no nested ambiguous quantifiers)
const EMAIL_RE =
  /\b[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}\b/g;

const PAN_RE = /(?<![A-Za-z0-9])[A-Z]{5}[0-9]{4}[A-Z](?![A-Za-z0-9])/g;

const AADHAAR_RE =
  /(?<![0-9A-Za-z])(?:[2-9]\d{3}(?:[ -]\d{4}){2}|[2-9]\d{11})(?![0-9A-Za-z])/g;

const CARD_RE = /(?<![0-9A-Za-z])(?:\d[ -]?){12,18}\d(?![0-9A-Za-z])/g;

const PHONE_RE =
  /(?<![0-9A-Za-z+])(?:(?:(?:\+91|0091|91|0)[\s-]?)?[6-9](?:\d{9}|\d{4}[\s-]\d{5}|\d{2}[\s-]\d{3}[\s-]\d{4})|\+[1-9]\d{0,2}(?:[\s-]?\(\d{1,4}\)[\s-]?|[\s-]?)(?:\d[\s-]?){6,14}\d|\(\d{3}\)[\s-]?\d{3}[\s-]?\d{4}|[2-9]\d{2}[\s-][2-9]\d{2}[\s-]\d{4})(?![0-9A-Za-z])/g;

const IPV4_CANDIDATE_RE = /(?<![0-9A-Za-z.])\d{1,3}(?:\.\d{1,3}){3,}(?![0-9A-Za-z.])/g;

const IPV6_CANDIDATE_RE =
  /(?<![0-9A-Za-z:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?:\.\d{1,3}){0,3}(?![0-9A-Za-z:])/g;

const DIGIT_RE = /\d/;
const EMAIL_LOCAL_BOUNDARY_RE = /[A-Za-z0-9._%+-]/;

function hasNumericChainBoundaryConflict(text, start, end) {
  if (start >= 2 && (text[start - 1] === "-" || text[start - 1] === ".") && DIGIT_RE.test(text[start - 2])) {
    return true;
  }
  if (end + 1 < text.length && (text[end] === "-" || text[end] === ".") && DIGIT_RE.test(text[end + 1])) {
    return true;
  }
  return false;
}

function hasConsistentCardSeparators(raw) {
  const hasSpace = raw.includes(" ");
  const hasHyphen = raw.includes("-");
  if (hasSpace && hasHyphen) {
    return false;
  }
  if (!hasSpace && !hasHyphen) {
    return true;
  }
  const sep = hasSpace ? " " : "-";
  const groups = raw.split(sep);
  // Prevent accidentally merging unrelated 2-digit tokens like timestamps ("20 26 11 27 10 53 48")
  for (let i = 0; i < groups.length; i++) {
    if (groups[i].length === 0) {
      return false;
    }
    if (i < groups.length - 1 && groups[i].length < 3) {
      return false;
    }
  }
  return true;
}

function isConsistentAadhaarGrouping(raw) {
  if (!raw.includes(" ") && !raw.includes("-")) {
    return true;
  }
  return !(raw.includes(" ") && raw.includes("-"));
}

function isValidEmailCandidate(text, value, start, end) {
  if (value.length > 254) {
    return false;
  }
  const atIndex = value.indexOf("@");
  if (atIndex < 1 || atIndex > 64) {
    return false;
  }
  if (start > 0 && text[start - 1] === ".") {
    // Reject malformed ".user@domain.com" while allowing ellipsis "...user@domain.com"
    if (start < 2 || text[start - 2] !== ".") {
      return false;
    }
  }
  if (start > 0 && EMAIL_LOCAL_BOUNDARY_RE.test(text[start - 1]) && text[start - 1] !== ".") {
    return false;
  }
  if (end + 1 < text.length && text[end] === "." && /[A-Za-z0-9]/.test(text[end + 1])) {
    return false;
  }
  return true;
}

function detectCards(text, candidates, rejected) {
  CARD_RE.lastIndex = 0;
  let match;
  while ((match = CARD_RE.exec(text)) !== null) {
    const value = match[0];
    const start = match.index;
    const end = start + value.length;
    if (hasNumericChainBoundaryConflict(text, start, end)) {
      continue;
    }
    if (!hasConsistentCardSeparators(value)) {
      continue;
    }
    const digits = value.replace(/\D/g, "");
    if (digits.length < 13 || digits.length > 19) {
      continue;
    }
    if (isValidLuhn(digits)) {
      const issuer = detectCardIssuer(digits);
      candidates.push({
        type: "credit_card",
        start,
        end,
        value,
        confidence: issuer === "Card" ? 0.88 : 0.99,
        meta: { issuer },
      });
    } else {
      rejected.push({ type: "luhn", start, end });
    }
  }
}

function detectAadhaars(text, candidates, rejected) {
  AADHAAR_RE.lastIndex = 0;
  let match;
  while ((match = AADHAAR_RE.exec(text)) !== null) {
    const value = match[0];
    const start = match.index;
    const end = start + value.length;
    if (hasNumericChainBoundaryConflict(text, start, end)) {
      continue;
    }
    if (!isConsistentAadhaarGrouping(value)) {
      continue;
    }
    const digits = value.replace(/\D/g, "");
    if (isValidAadhaar(digits)) {
      candidates.push({
        type: "aadhaar",
        start,
        end,
        value,
        confidence: value.length > 12 ? 0.99 : 0.95,
      });
    } else {
      rejected.push({ type: "verhoeff", start, end });
    }
  }
}

function detectPans(text, candidates, rejected) {
  PAN_RE.lastIndex = 0;
  let match;
  while ((match = PAN_RE.exec(text)) !== null) {
    const value = match[0];
    const start = match.index;
    const end = start + value.length;
    if (isValidPan(value)) {
      candidates.push({
        type: "pan",
        start,
        end,
        value,
        confidence: 0.98,
        meta: { holderType: value[3] },
      });
    } else {
      rejected.push({ type: "pan", start, end });
    }
  }
}

function detectPhones(text, candidates, rejected) {
  PHONE_RE.lastIndex = 0;
  let match;
  while ((match = PHONE_RE.exec(text)) !== null) {
    const value = match[0];
    const start = match.index;
    const end = start + value.length;

    if (hasNumericChainBoundaryConflict(text, start, end)) {
      continue;
    }
    if (value.includes("  ") || value.includes("--")) {
      continue;
    }

    const digits = value.replace(/\D/g, "");
    const hasPlus = value.startsWith("+");
    if (hasPlus) {
      if (digits.length < 7 || digits.length > 15) {
        rejected.push({ type: "phone", start, end });
        continue;
      }
      // Reject E.164 matches made of tiny space-separated chunks like "+1 23 45 67"
      const parts = value.slice(1).trim().split(/[\s-]+/);
      if (parts.length > 5) {
        rejected.push({ type: "phone", start, end });
        continue;
      }
    }

    candidates.push({
      type: "phone",
      start,
      end,
      value,
      confidence: hasPlus || value.includes("(") ? 0.96 : 0.9,
    });
  }
}

function detectIPs(text, candidates, rejected) {
  IPV4_CANDIDATE_RE.lastIndex = 0;
  let match;
  while ((match = IPV4_CANDIDATE_RE.exec(text)) !== null) {
    const value = match[0];
    const start = match.index;
    const end = start + value.length;
    if (isValidIPv4(value)) {
      candidates.push({
        type: "ip",
        start,
        end,
        value,
        confidence: 0.98,
        meta: { version: 4 },
      });
    } else {
      rejected.push({ type: "ipv4", start, end });
    }
  }

  IPV6_CANDIDATE_RE.lastIndex = 0;
  while ((match = IPV6_CANDIDATE_RE.exec(text)) !== null) {
    const value = match[0];
    const start = match.index;
    const end = start + value.length;
    if (isValidIPv6(value)) {
      candidates.push({
        type: "ip",
        start,
        end,
        value,
        confidence: 0.97,
        meta: { version: 6 },
      });
    }
  }
}

function detectEmails(text, candidates) {
  EMAIL_RE.lastIndex = 0;
  let match;
  while ((match = EMAIL_RE.exec(text)) !== null) {
    const value = match[0];
    const start = match.index;
    const end = start + value.length;
    if (!isValidEmailCandidate(text, value, start, end)) {
      continue;
    }
    candidates.push({
      type: "email",
      start,
      end,
      value,
      confidence: 0.98,
    });
  }
}

function intervalsOverlap(a, b) {
  return a.start < b.end && b.start < a.end;
}

const BUCKET_SIZE = 128;

/**
 * Resolve overlapping detections deterministically in near-linear time:
 * credit_card > aadhaar > pan > phone > ip > email; longest match breaks ties.
 */
function resolveOverlaps(candidates) {
  const sorted = [...candidates].sort((a, b) => {
    const priorityDiff = TYPE_PRIORITY[a.type] - TYPE_PRIORITY[b.type];
    if (priorityDiff !== 0) {
      return priorityDiff;
    }
    const lenDiff = b.end - b.start - (a.end - a.start);
    if (lenDiff !== 0) {
      return lenDiff;
    }
    return a.start - b.start;
  });

  const accepted = [];
  const buckets = new Map();

  for (const cand of sorted) {
    const startBucket = Math.floor(cand.start / BUCKET_SIZE);
    const endBucket = Math.floor(Math.max(cand.start, cand.end - 1) / BUCKET_SIZE);
    let overlaps = false;

    for (let b = startBucket; b <= endBucket && !overlaps; b++) {
      const list = buckets.get(b);
      if (!list) continue;
      for (const existing of list) {
        if (intervalsOverlap(cand, existing)) {
          overlaps = true;
          break;
        }
      }
    }

    if (!overlaps) {
      accepted.push(cand);
      for (let b = startBucket; b <= endBucket; b++) {
        let list = buckets.get(b);
        if (!list) {
          list = [];
          buckets.set(b, list);
        }
        list.push(cand);
      }
    }
  }

  accepted.sort((a, b) => a.start - b.start);
  return accepted;
}

function isCoveredBySortedEntities(rec, entities) {
  let lo = 0;
  let hi = entities.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const ent = entities[mid];
    if (ent.end <= rec.start) {
      lo = mid + 1;
    } else if (ent.start >= rec.end) {
      hi = mid - 1;
    } else {
      return true;
    }
  }
  return false;
}

/**
 * Detect PII entities and report validation rejections.
 * @param {string} text
 * @param {Set<string>|string[]|undefined} enabledTypes
 */
export function detectPIIWithStats(text, enabledTypes) {
  const emptyStats = { luhn: 0, verhoeff: 0, ipv4: 0, pan: 0, phone: 0 };
  if (typeof text !== "string" || text.length === 0) {
    return { entities: [], rejected: emptyStats };
  }

  const activeSet =
    enabledTypes instanceof Set
      ? enabledTypes
      : Array.isArray(enabledTypes)
      ? new Set(enabledTypes)
      : new Set(ENTITY_TYPES);

  const candidates = [];
  const rejectedRecords = [];

  if (activeSet.has("credit_card")) detectCards(text, candidates, rejectedRecords);
  if (activeSet.has("aadhaar")) detectAadhaars(text, candidates, rejectedRecords);
  if (activeSet.has("pan")) detectPans(text, candidates, rejectedRecords);
  if (activeSet.has("phone")) detectPhones(text, candidates, rejectedRecords);
  if (activeSet.has("ip")) detectIPs(text, candidates, rejectedRecords);
  if (activeSet.has("email")) detectEmails(text, candidates);

  const entities = resolveOverlaps(candidates);

  // Do not double-count a rejected candidate if an accepted higher/valid entity covers that span
  const rejected = { ...emptyStats };
  for (const rec of rejectedRecords) {
    if (!isCoveredBySortedEntities(rec, entities)) {
      rejected[rec.type] += 1;
    }
  }

  return { entities, rejected };
}

/**
 * Convenience detector returning only resolved entities.
 */
export function detectPII(text, enabledTypes) {
  return detectPIIWithStats(text, enabledTypes).entities;
}
