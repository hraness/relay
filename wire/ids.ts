/** Identifier formats on the wire. Every identifier is a bounded ASCII
 * string that survives JSON, URLs, and log lines unmodified. */

import { isHex, isSafePositiveInteger } from "./encoding";

const deviceIdPattern = /^[0-9a-f]{32}$/;
const namePattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/;
const digestPattern = /^sha256:[0-9a-f]{64}$/;
const opaqueIdentifierPattern = /^[A-Za-z0-9][A-Za-z0-9_-]{21,127}$/;
const uuidV7Pattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const publicIdPattern = /^[0-9a-f]{16,64}$/;
const namespacePattern = /^[a-z][a-z0-9]*(\.[a-z][a-z0-9]*)*\.v[1-9][0-9]*$/;

/** A device id: the first 128 bits of SHA-256 over the device's ECDSA P-256
 * signing key in SPKI form, as 32 lowercase hex characters. */
export function isDeviceId(value: unknown): value is string {
  return typeof value === "string" && deviceIdPattern.test(value);
}

/** A bounded object name — workspace, projection scope, route segment —
 * 1 to 64 characters from `[A-Za-z0-9._:-]`, starting with a letter or
 * digit. */
export function isRelayName(value: unknown): value is string {
  return typeof value === "string" && namePattern.test(value);
}

/** A content digest: `sha256:` followed by 64 lowercase hex characters. */
export function isDigest(value: unknown): value is string {
  return typeof value === "string" && digestPattern.test(value);
}

/** An opaque generated identifier: 22–128 URL-safe characters. */
export function isOpaqueIdentifier(value: unknown): value is string {
  return typeof value === "string" && opaqueIdentifierPattern.test(value);
}

/** A UUIDv7 (lowercase, version/variant bits set). The first 48 bits are a
 * millisecond timestamp, which is why idempotency keys are uuids: the relay
 * can expire receipts from the key alone. */
export function isUuidV7(value: unknown): value is string {
  return typeof value === "string" && uuidV7Pattern.test(value);
}

export function uuidV7Timestamp(value: string): number | null {
  if (!uuidV7Pattern.test(value)) return null;
  const prefix = value.replaceAll("-", "").slice(0, 12);
  const timestamp = Number.parseInt(prefix, 16);
  return Number.isSafeInteger(timestamp) ? timestamp : null;
}

/** Mint a fresh UUIDv7. Millisecond timestamp in the first 48 bits, random
 * remainder; returns lowercase canonical form. */
export function uuidV7(now = Date.now()): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  const ms = BigInt(Math.trunc(now)) & 0xffffffffffffn;
  for (let index = 0; index < 6; index++) {
    bytes[index] = Number((ms >> BigInt(8 * (5 - index))) & 0xffn);
  }
  bytes[6] = ((bytes[6] ?? 0) & 0x0f) | 0x70;
  bytes[8] = ((bytes[8] ?? 0) & 0x3f) | 0x80;
  const hex = [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/** A public id for devices, commands, and projections: lowercase hex. */
export function isPublicId(value: unknown): value is string {
  return typeof value === "string" && publicIdPattern.test(value);
}

/** A wire namespace such as `xcb.relay.v1` or `relay.dev.v1`: dotted
 * lowercase segments ending in a `v<n>` version. */
export function isWireNamespace(value: unknown): value is string {
  return typeof value === "string" && namespacePattern.test(value) && value.length <= 64;
}

/** A command kind or wire contract member of the product's closed union:
 * lowercase snake_case. */
const kindPattern = /^[a-z][a-z0-9_]{0,63}$/;
export function isWireKind(value: unknown): value is string {
  return typeof value === "string" && kindPattern.test(value);
}

const unsafeLabelCharacters = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u;
const loneSurrogate = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

/** A device label shown in listings: 1 to 64 UTF-16 units, trimmed, with no
 * control, format, or line-separator characters. It is the only free text
 * the relay stores in plaintext — products should pass opaque labels when
 * names are sensitive. */
export function isDeviceLabel(value: unknown): value is string {
  return typeof value === "string"
    && value.length >= 1
    && value.length <= 64
    && value.trim() === value
    && !unsafeLabelCharacters.test(value)
    && !loneSurrogate.test(value);
}

/** An email address for auth subjects: syntactically plausible, bounded,
 * normalized lowercase before hashing. The relay stores only its digest. */
const emailPattern = /^[^@\s]{1,64}@[^@\s]{1,255}$/;
export function isEmailAddress(value: unknown): value is string {
  return typeof value === "string" && value.length <= 320 && emailPattern.test(value);
}

export function normalizeEmail(value: string): string {
  return value.trim().toLowerCase();
}

export { isHex, isSafePositiveInteger };
