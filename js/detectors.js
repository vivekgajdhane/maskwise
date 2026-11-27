/**
 * PII Detection Engine (email, phone, IP, PAN, Aadhaar, credit card).
 * Phase 1 scaffold — full detectors and overlap resolution implemented in Phase 2.
 */

export const ENTITY_TYPES = ["credit_card", "aadhaar", "pan", "phone", "ip", "email"];

export function detectPIIWithStats(_text, _enabledTypes) {
  return {
    entities: [],
    rejected: {
      luhn: 0,
      verhoeff: 0,
      ipv4: 0,
      pan: 0,
      phone: 0,
    },
  };
}

export function detectPII(text, enabledTypes) {
  return detectPIIWithStats(text, enabledTypes).entities;
}
