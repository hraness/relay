/** Wire envelope shapes. The relay stores ciphertext as opaque strings and
 * never learns plaintext: payload envelopes are AES-256-GCM under the
 * account key, signed by the writing device; key-wrap envelopes deliver a
 * key version to one device over ECDH-P256 + HKDF-SHA-256 + AES-256-GCM.
 * Validation here is shape/bounds only — `crypto/` opens them. */

import { exactKeys, isBase64Url, isSafePositiveInteger } from "./encoding";
import { isDeviceId, isWireNamespace } from "./ids";

export const RELAY_ENVELOPE_CONTRACT = "relay.envelope.v1" as const;
export const RELAY_KEYWRAP_CONTRACT = "relay.keywrap.v1" as const;
export const RELAY_ENVELOPE_ALGORITHM = "A256GCM" as const;
export const RELAY_KEYWRAP_ALGORITHM = "P256-HKDF-SHA256+A256GCM" as const;

export const ENVELOPE_FIELDS = Object.freeze({
  ivChars: 16,           // 96-bit AES-GCM nonce
  signatureChars: 86,    // 64-byte ECDSA signature, base64url
  maxCiphertextChars: 65_536,
  maxWrappedChars: 4_096,
} as const);

export type EncryptedEnvelope = Readonly<{
  algorithm: typeof RELAY_ENVELOPE_ALGORITHM;
  ciphertext: string;
  keyVersion: number;
  nonce: string;
}>;

export function isEncryptedEnvelope(value: unknown, maxCiphertextChars: number): value is EncryptedEnvelope {
  return exactKeys(value, ["algorithm", "ciphertext", "keyVersion", "nonce"])
    && value.algorithm === RELAY_ENVELOPE_ALGORITHM
    && isBase64Url(value.ciphertext, maxCiphertextChars)
    && isSafePositiveInteger(value.keyVersion)
    && isBase64Url(value.nonce, ENVELOPE_FIELDS.ivChars);
}

/** A signed envelope header — the fields a sender signs over canonical
 * JSON. The signature covers every field except itself, and the contract
 * string pins the interpretation of `scope` for all time. */
export type SignedEnvelopeHeader = Readonly<{
  contract: string;
  sender: string;
  recipient: string;
  scope: string;
  keyVersion: number;
  iv: string;
  ciphertext: string;
}>;

export const SIGNED_ENVELOPE_KEYS = Object.freeze([
  "contract",
  "sender",
  "recipient",
  "scope",
  "keyVersion",
  "iv",
  "ciphertext",
] as const);

export type SignedEnvelope = SignedEnvelopeHeader & Readonly<{ signature: string }>;

export function isSignedEnvelope(value: unknown, maxCiphertextChars: number): value is SignedEnvelope {
  return exactKeys(value, [...SIGNED_ENVELOPE_KEYS, "signature"])
    && isWireNamespace(value.contract)
    && isDeviceId(value.sender)
    && (isDeviceId(value.recipient) || value.recipient === "account")
    && typeof value.scope === "string" && value.scope.length >= 1 && value.scope.length <= 128
    && isSafePositiveInteger(value.keyVersion)
    && isBase64Url(value.iv, ENVELOPE_FIELDS.ivChars)
    && isBase64Url(value.ciphertext, maxCiphertextChars)
    && isBase64Url(value.signature, ENVELOPE_FIELDS.signatureChars);
}

/** A signed key-wrap envelope — delivers one account key version to one
 * device over ECDH-P256 + HKDF-SHA-256 + AES-256-GCM. The signature covers
 * every field except itself. */
export type KeyWrapEnvelope = Readonly<{
  contract: string;
  sender: string;
  recipient: string;
  keyVersion: number;
  iv: string;
  wrapped: string;
  signature: string;
}>;

export const KEYWRAP_ENVELOPE_KEYS = Object.freeze([
  "contract",
  "sender",
  "recipient",
  "keyVersion",
  "iv",
  "wrapped",
  "signature",
] as const);

export function isKeyWrapEnvelope(value: unknown): value is KeyWrapEnvelope {
  return exactKeys(value, [...KEYWRAP_ENVELOPE_KEYS])
    && value.contract === RELAY_KEYWRAP_CONTRACT
    && isDeviceId(value.sender)
    && isDeviceId(value.recipient)
    && value.sender !== value.recipient
    && isSafePositiveInteger(value.keyVersion)
    && isBase64Url(value.iv, ENVELOPE_FIELDS.ivChars)
    && isBase64Url(value.wrapped, ENVELOPE_FIELDS.maxWrappedChars)
    && isBase64Url(value.signature, ENVELOPE_FIELDS.signatureChars);
}
