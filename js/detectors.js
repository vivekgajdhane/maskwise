/**
 * PII detection engine: email, phone, IPv4/IPv6, Indian PAN, Aadhaar, and credit cards.
 * Uses precompiled linear-time regexes, strict boundary guards, and deterministic
 * bucket-indexed overlap resolution.
 */

import { APP_CONFIG, ENTITY_TYPES, TYPE_PRIORITY } from "./config.js";
import {
  detectCardIssuer,
  isValidAadhaar,
  isValidIPv4,
  isValidIPv6,
  isValidLuhn,
  isValidPan,
} from "./validators.js";

export { ENTITY_TYPES };

const EMAIL_RE =
  /(?<![A-Za-z0-9!#$%&'*+/=?^_`{|}~.-])[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+){0,32}@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}\b/g;

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
  if (hasSpace && hasHyphen) return false;
  if (!hasSpace && !hasHyphen) return true;

  const groups = raw.split(hasSpace ? " " : "-");
  for (let i = 0; i < groups.length; i++) {
    if (groups[i].length === 0) return false;
    if (i < groups.length - 1 && groups[i].length < 3) return false;
  }
  return true;
}

function isValidEmailCandidate(text, value, start, end) {
  if (value.length > 254) return false;
  const atIndex = value.indexOf("@");
  if (atIndex < 1 || atIndex > 64) return false;
  if (start > 0 && text[start - 1] === "." && (start < 2 || text[start - 2] !== ".")) return false;
  if (start > 0 && EMAIL_LOCAL_BOUNDARY_RE.test(text[start - 1]) && text[start - 1] !== ".") return false;
  if (end + 1 < text.length && text[end] === "." && /[A-Za-z0-9]/.test(text[end + 1])) return false;
  return true;
}

function detectCards(text, candidates, rejected) {
  CARD_RE.lastIndex = 0;
  let match;
  while ((match = CARD_RE.exec(text)) !== null) {
    const value = match[0];
    const start = match.index;
    const end = start + value.length;
    if (hasNumericChainBoundaryConflict(text, start, end) || !hasConsistentCardSeparators(value)) {
      continue;
    }
    const digits = value.replace(/\D/g, "");
    if (digits.length < 13 || digits.length > 19) continue;
    if (isValidLuhn(digits)) {
      const issuer = detectCardIssuer(digits);
      candidates.push({ type: "credit_card", start, end, value, confidence: issuer === "Card" ? 0.88 : 0.99, meta: { issuer } });
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
    if (hasNumericChainBoundaryConflict(text, start, end) || (value.includes(" ") && value.includes("-"))) {
      continue;
    }
    if (isValidAadhaar(value.replace(/\D/g, ""))) {
      candidates.push({ type: "aadhaar", start, end, value, confidence: value.length > 12 ? 0.99 : 0.95 });
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
      candidates.push({ type: "pan", start, end, value, confidence: 0.98, meta: { holderType: value[3] } });
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
    if (hasNumericChainBoundaryConflict(text, start, end) || value.includes("  ") || value.includes("--")) {
      continue;
    }
    const digits = value.replace(/\D/g, "");
    const hasPlus = value.startsWith("+");
    if (hasPlus && (digits.length < 7 || digits.length > 15 || value.slice(1).trim().split(/[\s-]+/).length > 5)) {
      rejected.push({ type: "phone", start, end });
      continue;
    }
    candidates.push({ type: "phone", start, end, value, confidence: hasPlus || value.includes("(") ? 0.96 : 0.9 });
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
      candidates.push({ type: "ip", start, end, value, confidence: 0.98, meta: { version: 4 } });
    } else {
      rejected.push({ type: "ipv4", start, end });
    }
  }

  IPV6_CANDIDATE_RE.lastIndex = 0;
  while ((match = IPV6_CANDIDATE_RE.exec(text)) !== null) {
    const value = match[0];
    if (isValidIPv6(value)) {
      candidates.push({ type: "ip", start: match.index, end: match.index + value.length, value, confidence: 0.97, meta: { version: 6 } });
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
    if (isValidEmailCandidate(text, value, start, end)) {
      candidates.push({ type: "email", start, end, value, confidence: 0.98 });
    }
  }
}

function intervalsOverlap(a, b) {
  return a.start < b.end && b.start < a.end;
}

function bucketHasOverlap(cand, buckets) {
  const startBucket = Math.floor(cand.start / APP_CONFIG.BUCKET_SIZE);
  const endBucket = Math.floor(Math.max(cand.start, cand.end - 1) / APP_CONFIG.BUCKET_SIZE);
  for (let b = startBucket; b <= endBucket; b++) {
    const list = buckets.get(b);
    if (list && list.some((existing) => intervalsOverlap(cand, existing))) return true;
  }
  return false;
}

function addToBuckets(cand, buckets) {
  const startBucket = Math.floor(cand.start / APP_CONFIG.BUCKET_SIZE);
  const endBucket = Math.floor(Math.max(cand.start, cand.end - 1) / APP_CONFIG.BUCKET_SIZE);
  for (let b = startBucket; b <= endBucket; b++) {
    let list = buckets.get(b);
    if (!list) {
      list = [];
      buckets.set(b, list);
    }
    list.push(cand);
  }
}

function resolveOverlaps(candidates) {
  const sorted = [...candidates].sort((a, b) => {
    const priorityDiff = TYPE_PRIORITY[a.type] - TYPE_PRIORITY[b.type];
    if (priorityDiff !== 0) return priorityDiff;
    const lenDiff = b.end - b.start - (a.end - a.start);
    return lenDiff !== 0 ? lenDiff : a.start - b.start;
  });

  const accepted = [];
  const buckets = new Map();
  for (const cand of sorted) {
    if (!bucketHasOverlap(cand, buckets)) {
      accepted.push(cand);
      addToBuckets(cand, buckets);
    }
  }
  return accepted.sort((a, b) => a.start - b.start);
}

function isCoveredBySortedEntities(rec, entities) {
  let lo = 0;
  let hi = entities.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (entities[mid].end <= rec.start) lo = mid + 1;
    else if (entities[mid].start >= rec.end) hi = mid - 1;
    else return true;
  }
  return false;
}

/**
 * Detect PII entities in text and return both resolved matches and validation rejections.
 * Edge cases: returns empty arrays/zero stats for empty or non-string input; never double-counts
 * a rejected span if an accepted higher-priority entity covers it.
 *
 * @param {string} text - Input text to scan.
 * @param {Set<string>|string[]|undefined} enabledTypes - Optional active entity type filter.
 * @returns {{ entities: Array<object>, rejected: { luhn: number, verhoeff: number, ipv4: number, pan: number, phone: number } }}
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
  const rejected = { ...emptyStats };
  for (const rec of rejectedRecords) {
    if (!isCoveredBySortedEntities(rec, entities)) {
      rejected[rec.type] += 1;
    }
  }

  return { entities, rejected };
}

/**
 * Detect and resolve PII entities in text.
 *
 * @param {string} text - Input text to scan.
 * @param {Set<string>|string[]|undefined} enabledTypes - Optional active entity type filter.
 * @returns {Array<{ type: string, start: number, end: number, value: string, confidence: number, meta?: object }>}
 */
export function detectPII(text, enabledTypes) {
  return detectPIIWithStats(text, enabledTypes).entities;
}
