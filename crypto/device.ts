/** Device identity: an ECDSA P-256 signing pair and an ECDH P-256 agreement
 * pair, both with non-extractable private keys. The device id is the first
 * 128 bits of SHA-256 over the signing public key in SPKI form, as 32
 * lowercase hex characters. Public keys travel as base64url SPKI. */

import { decodeBase64Url, encodeBase64Url, encodeHex, exactKeys, isRecord, type Bytes } from "../wire/encoding";
import { isDeviceId } from "../wire/ids";
import {
  ECDH_P256,
  ECDSA_P256,
  isKey,
  isP256Spki,
  P256_SPKI_CHARS,
  sha256,
  subtle,
  randomBytes,
} from "./primitives";

/** A device's public keys as they travel between devices and the relay. */
export type DevicePublicKeys = Readonly<{ device: string; signing: string; agreement: string }>;

/** This device's own keys. The object is structured-cloneable, so it can be
 * stored in IndexedDB or serialized as JWK by the host; `restoreDeviceIdentity`
 * checks it on the way back. */
export type DeviceIdentity = Readonly<{
  device: string;
  publicKeys: DevicePublicKeys;
  signing: Readonly<CryptoKeyPair>;
  agreement: Readonly<CryptoKeyPair>;
}>;

/** Another device, or this one, as a verifier and key-agreement peer. */
export type PeerDevice = Readonly<{
  device: string;
  publicKeys: DevicePublicKeys;
  verifyKey: CryptoKey;
  agreementKey: CryptoKey;
}>;

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index++) difference |= left[index]! ^ right[index]!;
  return difference === 0;
}

function checkSpki(bytes: Uint8Array, what: string): Bytes {
  if (!isP256Spki(bytes)) throw new Error(`Invalid ${what}`);
  return new Uint8Array(bytes) as Bytes;
}

function spkiField(value: unknown, what: string): Bytes {
  if (typeof value !== "string") throw new Error(`Invalid ${what}`);
  const bytes = decodeBase64Url(value, P256_SPKI_CHARS);
  if (bytes === null) throw new Error(`Invalid ${what}`);
  return checkSpki(bytes, what);
}

/** The device id of an ECDSA P-256 public key given in SPKI form. */
export async function deviceIdOf(signingSpki: Uint8Array): Promise<string> {
  return encodeHex((await sha256(checkSpki(signingSpki, "signing public key"))).subarray(0, 16));
}

async function exportSpki(publicKey: CryptoKey): Promise<Bytes> {
  return new Uint8Array(await subtle().exportKey("spki", publicKey)) as Bytes;
}

function hasIdentityKeys(signing: CryptoKeyPair, agreement: CryptoKeyPair): boolean {
  return isKey(signing.privateKey, "private", "ECDSA", ["sign"], false)
    && isKey(signing.publicKey, "public", "ECDSA", ["verify"], true)
    && isKey(agreement.privateKey, "private", "ECDH", ["deriveBits"], false)
    && isKey(agreement.publicKey, "public", "ECDH", [], true);
}

/** Build an identity from key pairs of the required shape. Throws unless
 * both private keys are non-extractable with exactly the expected usages. */
export async function assembleDeviceIdentity(signing: CryptoKeyPair, agreement: CryptoKeyPair): Promise<DeviceIdentity> {
  if (!hasIdentityKeys(signing, agreement)) throw new Error("Device keys have the wrong algorithm, usages, or extractability");
  const signingSpki = await exportSpki(signing.publicKey), agreementSpki = await exportSpki(agreement.publicKey);
  if (equalBytes(signingSpki, agreementSpki)) throw new Error("Device keys must differ");
  const device = await deviceIdOf(signingSpki);
  checkSpki(agreementSpki, "agreement public key");
  const publicKeys: DevicePublicKeys = Object.freeze({ device, signing: encodeBase64Url(signingSpki), agreement: encodeBase64Url(agreementSpki) });
  return Object.freeze({
    device,
    publicKeys,
    signing: Object.freeze({ privateKey: signing.privateKey, publicKey: signing.publicKey }),
    agreement: Object.freeze({ privateKey: agreement.privateKey, publicKey: agreement.publicKey }),
  });
}

export async function createDeviceIdentity(): Promise<DeviceIdentity> {
  const signing = await subtle().generateKey(ECDSA_P256, false, ["sign", "verify"]);
  const agreement = await subtle().generateKey(ECDH_P256, false, ["deriveBits"]);
  return assembleDeviceIdentity(signing, agreement);
}

function keyPair(value: unknown, what: string): CryptoKeyPair {
  if (!exactKeys(value, ["privateKey", "publicKey"])) throw new Error(`Invalid ${what}`);
  return { privateKey: value.privateKey as CryptoKey, publicKey: value.publicKey as CryptoKey };
}

/** Prove that each private key belongs to its public key: a signature over
 * a random challenge verifies, and ECDH with a fresh probe agrees both
 * ways. */
async function proveKeyPairs(identity: DeviceIdentity): Promise<void> {
  const challenge = randomBytes(32);
  const signed = await subtle().sign({ name: "ECDSA", hash: "SHA-256" }, identity.signing.privateKey, challenge);
  if (!(await subtle().verify({ name: "ECDSA", hash: "SHA-256" }, identity.signing.publicKey, signed, challenge))) throw new Error("Device signing keys do not form a pair");
  const probe = await subtle().generateKey(ECDH_P256, false, ["deriveBits"]);
  const mine = new Uint8Array(await subtle().deriveBits({ name: "ECDH", public: probe.publicKey }, identity.agreement.privateKey, 256));
  const theirs = new Uint8Array(await subtle().deriveBits({ name: "ECDH", public: identity.agreement.publicKey }, probe.privateKey, 256));
  if (!equalBytes(mine, theirs)) throw new Error("Device agreement keys do not form a pair");
}

/** Check an identity read back from storage: exact keys, key shapes,
 * non-extractable private keys, and private keys that match their public
 * keys. */
export async function restoreDeviceIdentity(value: unknown): Promise<DeviceIdentity> {
  if (!exactKeys(value, ["device", "publicKeys", "signing", "agreement"])) throw new Error("Invalid device identity");
  const storedDevice = value.device, storedPublicKeys = value.publicKeys;
  const identity = await assembleDeviceIdentity(keyPair(value.signing, "device signing keys"), keyPair(value.agreement, "device agreement keys"));
  if (!exactKeys(storedPublicKeys, ["device", "signing", "agreement"])) throw new Error("Invalid device public keys");
  const publicKeys = storedPublicKeys;
  if (storedDevice !== identity.device || publicKeys.device !== identity.device
    || publicKeys.signing !== identity.publicKeys.signing || publicKeys.agreement !== identity.publicKeys.agreement) {
    throw new Error("Stored device identity does not match its keys");
  }
  await proveKeyPairs(identity);
  return identity;
}

/** Whether `value` has the key shapes a signing or agreement call needs. */
export function isDeviceIdentity(value: unknown): value is DeviceIdentity {
  if (!isRecord(value)) return false;
  const { device, signing, agreement } = value;
  const isPair = (pair: unknown): pair is CryptoKeyPair => isRecord(pair);
  return isDeviceId(device) && isPair(signing) && isPair(agreement) && hasIdentityKeys(signing, agreement);
}

/** Whether `value` has the key shapes of a peer device. */
export function isPeerDevice(value: unknown): value is PeerDevice {
  if (!isRecord(value)) return false;
  const { device, publicKeys, verifyKey, agreementKey } = value;
  return isDeviceId(device) && isRecord(publicKeys)
    && isKey(verifyKey, "public", "ECDSA", ["verify"]) && isKey(agreementKey, "public", "ECDH", []);
}

/** This device as a peer, for verifying its own envelopes. */
export function peerOf(identity: DeviceIdentity): PeerDevice {
  return Object.freeze({ device: identity.device, publicKeys: identity.publicKeys, verifyKey: identity.signing.publicKey, agreementKey: identity.agreement.publicKey });
}

/** Parse foreign public keys: exact fields, distinct canonical P-256 SPKI,
 * and a device id equal to the hash of the signing key. */
export async function checkDevicePublicKeys(value: unknown): Promise<{ keys: DevicePublicKeys; signing: Bytes; agreement: Bytes }> {
  if (!exactKeys(value, ["device", "signing", "agreement"])) throw new Error("Invalid device public keys");
  const device = value.device;
  if (!isDeviceId(device)) throw new Error("Invalid device id");
  const signingText = value.signing, agreementText = value.agreement;
  const signing = spkiField(signingText, "signing public key"), agreement = spkiField(agreementText, "agreement public key");
  if (equalBytes(signing, agreement)) throw new Error("Device keys must differ");
  if ((await deviceIdOf(signing)) !== device) throw new Error("Device id does not match its signing key");
  return { keys: Object.freeze({ device, signing: signingText as string, agreement: agreementText as string }), signing, agreement };
}

/** Import another device's public keys. Import rejects points off the
 * curve. */
export async function importPeerDevice(value: unknown): Promise<PeerDevice> {
  const { keys, signing, agreement } = await checkDevicePublicKeys(value);
  let verifyKey: CryptoKey, agreementKey: CryptoKey;
  try {
    verifyKey = await subtle().importKey("spki", signing, ECDSA_P256, true, ["verify"]);
    agreementKey = await subtle().importKey("spki", agreement, ECDH_P256, true, []);
  } catch {
    throw new Error("Invalid device public key");
  }
  return Object.freeze({ device: keys.device, publicKeys: keys, verifyKey, agreementKey });
}
