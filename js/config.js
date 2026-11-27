/**
 * Centralized configuration constants, validation sets, and UI metadata.
 */

export const APP_CONFIG = Object.freeze({
  MAX_FILE_BYTES: 5 * 1024 * 1024,
  DEBOUNCE_MS: 120,
  COPY_FEEDBACK_MS: 1800,
  BUCKET_SIZE: 128,
  DIFF_CHUNK_SIZE: 250,
  LARGE_TEXT_THRESHOLD: 120000,
});

export const ALLOWED_EXTENSIONS = new Set(["txt", "csv"]);

export const ALLOWED_MIME_TYPES = new Set([
  "text/plain",
  "text/csv",
  "application/csv",
  "application/vnd.ms-excel",
]);

export const ENTITY_TYPES = Object.freeze([
  "credit_card",
  "aadhaar",
  "pan",
  "phone",
  "ip",
  "email",
]);

export const TYPE_PRIORITY = Object.freeze({
  credit_card: 0,
  aadhaar: 1,
  pan: 2,
  phone: 3,
  ip: 4,
  email: 5,
});

export const PAN_HOLDER_TYPES = new Set([
  "P",
  "C",
  "H",
  "F",
  "A",
  "T",
  "B",
  "L",
  "J",
  "G",
]);

export const FULL_MASK_LABELS = Object.freeze({
  email: "EMAIL",
  phone: "PHONE",
  ip: "IP",
  pan: "PAN",
  aadhaar: "AADHAAR",
  credit_card: "CARD",
});

export const PSEUDONYM_PREFIX = Object.freeze({
  email: "USER",
  phone: "PHONE",
  credit_card: "CARD",
  aadhaar: "AADHAAR",
  pan: "PAN",
  ip: "IP",
});

export const TYPE_LABELS = Object.freeze({
  credit_card: "Credit Card",
  aadhaar: "Aadhaar",
  pan: "Indian PAN",
  phone: "Phone",
  ip: "IP Address",
  email: "Email",
});
