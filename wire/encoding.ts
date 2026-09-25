/** Canonical encodings and strict structural parsing shared by every wire
 * value. The codec accepts exactly one encoding per byte string: unpadded
 * base64url whose unused low bits are zero. Dependency-free so the Convex
 * backend, the TypeScript client, and a Rust port all enforce the same
 * rules. */

export type Bytes = Uint8Array<ArrayBuffer>;

const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const alphabetPattern = /^[A-Za-z0-9_-]+$/;
const sextets = new Map<string, number>([...alphabet].map((char, index) => [char, index]));

/** True for a non-empty, unpadded, canonical base64url string of at most
 * `maxChars` characters. */
export function isBase64Url(value: unknown, maxChars: number): value is string {
  if (typeof value !== "string" || value.length === 0 || value.length > maxChars) return false;
  if (value.length % 4 === 1 || !alphabetPattern.test(value)) return false;
  const last = sextets.get(value[value.length - 1] ?? "") ?? 0;
  if (value.length % 4 === 2) return (last & 0x0f) === 0;
  if (value.length % 4 === 3) return (last & 0x03) === 0;
  return true;
}

/** Decode a canonical unpadded base64url string of at most `maxChars`
 * characters, or return null. */
export function decodeBase64Url(value: string, maxChars: number): Bytes | null {
  if (!isBase64Url(value, maxChars)) return null;
  const bytes = new Uint8Array(Math.floor((value.length * 3) / 4));
  let buffer = 0, bits = 0, offset = 0;
  for (const char of value) {
    buffer = (buffer << 6) | (sextets.get(char) ?? 0);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes[offset++] = (buffer >> bits) & 0xff;
      buffer &= (1 << bits) - 1;
    }
  }
  return bytes;
}

export function encodeBase64Url(bytes: Uint8Array): string {
  let out = "", buffer = 0, bits = 0;
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 6) {
      bits -= 6;
      out += alphabet[(buffer >> bits) & 0x3f];
    }
    buffer &= (1 << bits) - 1;
  }
  if (bits > 0) out += alphabet[(buffer << (6 - bits)) & 0x3f];
  return out;
}

const hexPattern = /^[0-9a-f]+$/;

export function isHex(value: unknown, chars: number): value is string {
  return typeof value === "string" && value.length === chars && hexPattern.test(value);
}

export function encodeHex(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
}

export function decodeHex(value: string): Bytes | null {
  if (value.length % 2 !== 0 || (value.length !== 0 && !hexPattern.test(value))) return null;
  const bytes = new Uint8Array(value.length / 2);
  for (let index = 0; index < value.length; index += 2) {
    bytes[index / 2] = Number.parseInt(value.slice(index, index + 2), 16);
  }
  return bytes;
}

export function utf8Encode(text: string): Bytes {
  return new TextEncoder().encode(text);
}

export function utf8Decode(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

// Strict structural parsing ---------------------------------------------------

/** A plain `Record`: a non-null non-array object whose prototype is exactly
 * `Object.prototype` or null (a JSON.parse product). */
export function isRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype: unknown = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

/** A record whose own keys are exactly `keys` — no missing, no extras. */
export function exactKeys(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  if (!isRecord(value)) return false;
  return Object.keys(value).sort().join("\0") === [...keys].sort().join("\0");
}

export function isSafeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value);
}

export function isSafePositiveInteger(value: unknown): value is number {
  return isSafeInteger(value) && value >= 1;
}

export function isSafeNonNegativeInteger(value: unknown): value is number {
  return isSafeInteger(value) && value >= 0;
}
