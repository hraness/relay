/** WebCrypto building blocks: canonical-JSON ECDSA P-256 signatures
 * normalized to low S, ECDH-P256 → HKDF-SHA-256 → AES-GCM-256 derivation,
 * and key shape checks. Every operation runs identically in Bun, browsers,
 * and Node through `crypto.subtle`, and ports to Rust via `p256` +
 * `aes-gcm` + `hkdf`. */

import { canonicalize, type JsonValue } from "./canonical";
import { encodeBase64Url, utf8Encode, type Bytes } from "../wire/encoding";

export const ECDSA_P256 = Object.freeze({ name: "ECDSA", namedCurve: "P-256" } as const);
export const ECDH_P256 = Object.freeze({ name: "ECDH", namedCurve: "P-256" } as const);
const SIGNATURE = Object.freeze({ name: "ECDSA", hash: "SHA-256" } as const);
const AES_256 = Object.freeze({ name: "AES-GCM", length: 256 } as const);

export const SIGNATURE_BYTES = 64;
export const IV_BYTES = 12;

/** The group order of P-256 and half of it. A signature (r, s) and
 * (r, n − s) both verify, so signing keeps the low one and verification
 * rejects the high one: every signed record then has exactly one valid
 * encoding. */
const P256_ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const HALF_ORDER = P256_ORDER >> 1n;

export function subtle(): SubtleCrypto {
  const api = globalThis.crypto?.subtle;
  if (api === undefined) throw new Error("WebCrypto is unavailable; relay needs a secure context");
  return api;
}

export function randomBytes(length: number): Bytes {
  return crypto.getRandomValues(new Uint8Array(length)) as Bytes;
}

export async function sha256(bytes: Bytes): Promise<Bytes> {
  return new Uint8Array(await subtle().digest("SHA-256", bytes)) as Bytes;
}

/** AES-GCM with a 128-bit tag and UTF-8 additional data. */
export function gcm(iv: Bytes, additionalData: string): AesGcmParams {
  return { name: "AES-GCM", iv, additionalData: utf8Encode(additionalData), tagLength: 128 };
}

function readScalar(signature: Uint8Array, offset: number): bigint {
  let value = 0n;
  for (let index = offset; index < offset + 32; index++) value = (value << 8n) | BigInt(signature[index]!);
  return value;
}

function lowS(signature: Bytes): Bytes {
  const s = readScalar(signature, 32);
  if (s <= HALF_ORDER) return signature;
  const out = new Uint8Array(signature);
  let flipped = P256_ORDER - s;
  for (let index = 63; index >= 32; index--) { out[index] = Number(flipped & 0xffn); flipped >>= 8n; }
  return out;
}

/** Sign the canonical JSON of `value` with ECDSA P-256 and SHA-256; returns
 * the low-S signature as raw bytes. */
export async function signCanonical(privateKey: CryptoKey, value: JsonValue): Promise<Bytes> {
  const signature = new Uint8Array(await subtle().sign(SIGNATURE, privateKey, utf8Encode(canonicalize(value)))) as Bytes;
  if (signature.length !== SIGNATURE_BYTES) throw new Error("Unexpected ECDSA signature size");
  return lowS(signature);
}

export async function signCanonicalBase64(privateKey: CryptoKey, value: JsonValue): Promise<string> {
  return encodeBase64Url(await signCanonical(privateKey, value));
}

/** Verify a low-S ECDSA P-256 signature over the canonical JSON of `value`.
 * Any failure, including an unusable key, is `false`. */
export async function verifyCanonical(publicKey: CryptoKey, value: JsonValue, signature: Bytes): Promise<boolean> {
  if (signature.length !== SIGNATURE_BYTES || readScalar(signature, 32) > HALF_ORDER) return false;
  try {
    return await subtle().verify(SIGNATURE, publicKey, signature, utf8Encode(canonicalize(value)));
  } catch {
    return false;
  }
}

type KeyAlgorithmName = "ECDSA" | "ECDH" | "AES-GCM";

/** A `CryptoKey` of exactly this type, algorithm (P-256 or 256-bit AES),
 * usage set, and, when given, extractability. */
export function isKey(value: unknown, type: KeyType, algorithm: KeyAlgorithmName, usages: readonly KeyUsage[], extractable?: boolean): value is CryptoKey {
  if (typeof CryptoKey === "undefined" || !(value instanceof CryptoKey)) return false;
  if (value.type !== type || (extractable !== undefined && value.extractable !== extractable)) return false;
  const described = value.algorithm as { name?: unknown; namedCurve?: unknown; length?: unknown };
  if (described.name !== algorithm) return false;
  if (algorithm === "AES-GCM" ? described.length !== 256 : described.namedCurve !== "P-256") return false;
  return [...value.usages].sort().join(",") === [...usages].sort().join(",");
}

/** The account payload key encrypts and decrypts envelope bodies. It is
 * extractable solely so `crypto/envelope` can wrap it for a new device;
 * nothing exports it raw. */
export const ACCOUNT_KEY_USAGES: readonly KeyUsage[] = Object.freeze(["encrypt", "decrypt", "wrapKey", "unwrapKey"]);

export async function generateAccountKey(): Promise<CryptoKey> {
  return subtle().generateKey(AES_256, true, [...ACCOUNT_KEY_USAGES]);
}

export function isAccountKey(value: unknown): value is CryptoKey {
  return isKey(value, "secret", "AES-GCM", ACCOUNT_KEY_USAGES, true);
}

export async function importAccountKey(raw: Bytes): Promise<CryptoKey> {
  if (raw.length !== 32) throw new Error("Account key must be 32 bytes");
  const key = await subtle().importKey("raw", raw, AES_256, true, [...ACCOUNT_KEY_USAGES]);
  if (!isAccountKey(key)) throw new Error("Imported key is not an account key");
  return key;
}

export async function exportAccountKey(key: CryptoKey): Promise<Bytes> {
  if (!isAccountKey(key)) throw new TypeError("Invalid account key");
  return new Uint8Array(await subtle().exportKey("raw", key)) as Bytes;
}

/** AES-GCM-256 encrypt under an account or derived key. */
export async function sealBytes(key: CryptoKey, iv: Bytes, additionalData: string, plaintext: Bytes): Promise<Bytes> {
  return new Uint8Array(await subtle().encrypt(gcm(iv, additionalData), key, plaintext)) as Bytes;
}

export async function openBytes(key: CryptoKey, iv: Bytes, additionalData: string, ciphertext: Bytes): Promise<Bytes> {
  return new Uint8Array(await subtle().decrypt(gcm(iv, additionalData), key, ciphertext)) as Bytes;
}

/** The AES-GCM-256 wrapping key two devices share via static ECDH, bound to
 * `purpose` through HKDF info and to direction through additional data at
 * the call site. */
export async function deriveWrapKey(
  privateKey: CryptoKey,
  publicKey: CryptoKey,
  salt: string,
  info: string,
  usage: "wrapKey" | "unwrapKey",
): Promise<CryptoKey> {
  const secret = await subtle().deriveBits({ name: "ECDH", public: publicKey }, privateKey, 256);
  const material = await subtle().importKey("raw", secret, "HKDF", false, ["deriveKey"]);
  return subtle().deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: utf8Encode(salt), info: utf8Encode(info) },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    [usage],
  );
}

// P-256 SPKI import/export ------------------------------------------------------

/** DER prefix of an uncompressed P-256 public key in SPKI form, through the
 * 0x04 point marker. WebCrypto exports ECDSA and ECDH P-256 keys this way. */
const P256_SPKI_PREFIX = Object.freeze([
  0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
  0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
]);
export const P256_SPKI_BYTES = 91;
export const P256_SPKI_CHARS = 122;

export function isP256Spki(bytes: Uint8Array): boolean {
  return bytes.length === P256_SPKI_BYTES && P256_SPKI_PREFIX.every((byte, index) => bytes[index] === byte);
}

export async function importP256SigningKey(spki: Bytes): Promise<CryptoKey> {
  if (!isP256Spki(spki)) throw new Error("Not a P-256 SPKI public key");
  return subtle().importKey("spki", spki, ECDSA_P256, true, ["verify"]);
}

export async function importP256AgreementKey(spki: Bytes): Promise<CryptoKey> {
  if (!isP256Spki(spki)) throw new Error("Not a P-256 SPKI public key");
  return subtle().importKey("spki", spki, ECDH_P256, true, []);
}
