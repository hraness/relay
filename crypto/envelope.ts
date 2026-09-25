/** The two envelope contracts.

 * `relay.envelope.v1` seals a payload under the account AES-GCM-256 key and
 * signs the canonical JSON of every field except `signature` with the
 * sender's device key. `recipient` is the literal `account`: every enrolled
 * device holds the same wrapped account key, and the signature is what
 * proves which device wrote it. Additional data binds
 * `contract|scope|sender|recipient|keyVersion`, so a ciphertext moved
 * between scopes or key versions fails to open.

 * `relay.keywrap.v1` delivers the account key to one device: static
 * ECDH-P256 between sender and recipient agreement keys, HKDF-SHA-256 with
 * the recipient device id as salt and the contract as info, AES-GCM-256
 * wrap with `contract|sender|recipient|keyVersion` as additional data, and
 * the sender's signature over the canonical fields. */

import { decodeBase64Url, encodeBase64Url, exactKeys, isBase64Url, type Bytes } from "../wire/encoding";
import {
  ENVELOPE_FIELDS,
  RELAY_ENVELOPE_CONTRACT,
  RELAY_KEYWRAP_CONTRACT,
  type KeyWrapEnvelope,
  type SignedEnvelope,
} from "../wire/envelope";
import { isDeviceId } from "../wire/ids";
import {
  deriveWrapKey,
  isAccountKey,
  openBytes,
  randomBytes,
  sealBytes,
  signCanonicalBase64,
  subtle,
  verifyCanonical,
  IV_BYTES,
  isKey,
} from "./primitives";
import { isDeviceIdentity, isPeerDevice, peerOf, type DeviceIdentity, type PeerDevice } from "./device";
import { canonicalize, type JsonObject, type JsonValue } from "./canonical";

export { RELAY_ENVELOPE_CONTRACT, RELAY_KEYWRAP_CONTRACT };

export type RelayEnvelope = SignedEnvelope;
export type EnvelopeRejection =
  | "malformed-envelope"
  | "recipient-mismatch"
  | "sender-mismatch"
  | "bad-signature"
  | "decrypt-failed";

export type OpenedEnvelope =
  | Readonly<{ status: "opened"; envelope: RelayEnvelope; plaintext: Bytes }>
  | Readonly<{ status: "rejected"; reason: EnvelopeRejection }>;

const ENVELOPE_KEYS = ["contract", "sender", "recipient", "scope", "keyVersion", "iv", "ciphertext", "signature"] as const;

type ParsedEnvelope = Readonly<{ envelope: RelayEnvelope; iv: Bytes; ciphertext: Bytes; signature: Bytes }>;

const rejected = (reason: EnvelopeRejection): OpenedEnvelope => ({ status: "rejected", reason });

function bytesField(value: unknown, min: number, max: number, what: string): Bytes {
  if (typeof value !== "string") throw new Error(`Invalid ${what}`);
  const bytes = decodeBase64Url(value, Math.max(min * 2, max * 2));
  if (bytes === null || bytes.length < min || bytes.length > max) throw new Error(`Invalid ${what}`);
  return bytes;
}

function readEnvelope(value: unknown): ParsedEnvelope {
  if (!exactKeys(value, [...ENVELOPE_KEYS])) throw new Error("Invalid envelope fields");
  if (value.contract !== RELAY_ENVELOPE_CONTRACT) throw new Error("Invalid envelope contract");
  const sender = value.sender, recipient = value.recipient, scope = value.scope;
  if (!isDeviceId(sender)) throw new Error("Invalid envelope sender");
  if (recipient !== "account" && !isDeviceId(recipient)) throw new Error("Invalid envelope recipient");
  if (typeof scope !== "string" || scope.length < 1 || scope.length > 128) throw new Error("Invalid envelope scope");
  const keyVersion = value.keyVersion;
  if (typeof keyVersion !== "number" || !Number.isSafeInteger(keyVersion) || keyVersion < 1) throw new Error("Invalid envelope key version");
  const ivText = value.iv, ciphertextText = value.ciphertext, signatureText = value.signature;
  if (typeof ivText !== "string" || typeof ciphertextText !== "string" || typeof signatureText !== "string") {
    throw new Error("Invalid envelope body");
  }
  const iv = bytesField(ivText, IV_BYTES, IV_BYTES, "envelope iv");
  const ciphertext = bytesField(ciphertextText, 1, 48 * 1024 + 16, "envelope ciphertext");
  const signature = bytesField(signatureText, 64, 64, "envelope signature");
  const envelope: RelayEnvelope = Object.freeze({
    contract: RELAY_ENVELOPE_CONTRACT,
    sender,
    recipient,
    scope,
    keyVersion,
    iv: ivText,
    ciphertext: ciphertextText,
    signature: signatureText,
  });
  return { envelope, iv, ciphertext, signature };
}

/** Parse an envelope without checking its signature. */
export function parseRelayEnvelope(value: unknown): RelayEnvelope {
  return readEnvelope(value).envelope;
}

function signedFields(envelope: Omit<RelayEnvelope, "signature">): JsonObject {
  return {
    contract: envelope.contract,
    sender: envelope.sender,
    recipient: envelope.recipient,
    scope: envelope.scope,
    keyVersion: envelope.keyVersion,
    iv: envelope.iv,
    ciphertext: envelope.ciphertext,
  };
}

export function envelopeAdditionalData(scope: string, sender: string, recipient: string, keyVersion: number): string {
  return `${RELAY_ENVELOPE_CONTRACT}|${scope}|${sender}|${recipient}|${keyVersion}`;
}

/** Sign arbitrary envelope fields. Exported for tests that build
 * deliberately inconsistent envelopes; use `sealEnvelope` instead. */
export async function signEnvelope(sender: DeviceIdentity, unsigned: Omit<RelayEnvelope, "signature">): Promise<RelayEnvelope> {
  return Object.freeze({ ...unsigned, signature: await signCanonicalBase64(sender.signing.privateKey, signedFields(unsigned)) });
}

/** Seal `plaintext` under `accountKey`, addressed to `recipient`
 * (`"account"` for fleet-visible content) within `scope`. */
export async function sealEnvelope(input: {
  sender: DeviceIdentity;
  accountKey: CryptoKey;
  scope: string;
  keyVersion: number;
  plaintext: Bytes;
  recipient?: string;
}): Promise<RelayEnvelope> {
  const { sender, accountKey, scope, keyVersion, plaintext } = input;
  const recipient = input.recipient ?? "account";
  if (!isDeviceIdentity(sender)) throw new TypeError("Invalid sender identity");
  if (!isAccountKey(accountKey)) throw new TypeError("Invalid account key");
  if (scope.length < 1 || scope.length > 128) throw new Error("Invalid envelope scope");
  if (recipient !== "account" && !isDeviceId(recipient)) throw new Error("Invalid envelope recipient");
  if (!Number.isSafeInteger(keyVersion) || keyVersion < 1) throw new Error("Invalid envelope key version");
  const iv = randomBytes(IV_BYTES);
  const ciphertext = await sealBytes(accountKey, iv, envelopeAdditionalData(scope, sender.device, recipient, keyVersion), plaintext);
  return signEnvelope(sender, {
    contract: RELAY_ENVELOPE_CONTRACT,
    sender: sender.device,
    recipient,
    scope,
    keyVersion,
    iv: encodeBase64Url(iv),
    ciphertext: encodeBase64Url(ciphertext),
  });
}

/** Open an envelope: check the sender's signature, then decrypt under the
 * account key with the full bound additional data. */
export async function openEnvelope(input: {
  envelope: unknown;
  recipient: DeviceIdentity;
  sender: PeerDevice;
  accountKey: CryptoKey;
}): Promise<OpenedEnvelope> {
  const { recipient, sender, accountKey } = input;
  if (!isDeviceIdentity(recipient)) throw new TypeError("Invalid recipient identity");
  if (!isPeerDevice(sender)) throw new TypeError("Invalid sender device");
  if (!isAccountKey(accountKey)) throw new TypeError("Invalid account key");
  let parsed: ParsedEnvelope;
  try { parsed = readEnvelope(input.envelope); } catch { return rejected("malformed-envelope"); }
  const { envelope } = parsed;
  if (envelope.recipient !== "account" && envelope.recipient !== recipient.device) return rejected("recipient-mismatch");
  if (envelope.sender !== sender.device) return rejected("sender-mismatch");
  if (!(await verifyCanonical(sender.verifyKey, signedFields(envelope), parsed.signature))) return rejected("bad-signature");
  try {
    const plaintext = await openBytes(
      accountKey,
      parsed.iv,
      envelopeAdditionalData(envelope.scope, envelope.sender, envelope.recipient, envelope.keyVersion),
      parsed.ciphertext,
    );
    return { status: "opened", envelope, plaintext };
  } catch {
    return rejected("decrypt-failed");
  }
}

// Key wrap: account-key delivery to a device ------------------------------------

export type { KeyWrapEnvelope };

export type KeyWrapRejection =
  | "malformed-envelope"
  | "recipient-mismatch"
  | "sender-mismatch"
  | "bad-signature"
  | "unwrap-failed";

export type OpenedKeyWrap =
  | Readonly<{ status: "opened"; envelope: KeyWrapEnvelope; accountKey: CryptoKey }>
  | Readonly<{ status: "rejected"; reason: KeyWrapRejection }>;

const KEYWRAP_KEYS = ["contract", "sender", "recipient", "keyVersion", "iv", "wrapped", "signature"] as const;

type ParsedKeyWrap = Readonly<{ envelope: KeyWrapEnvelope; iv: Bytes; wrapped: Bytes; signature: Bytes }>;

const wrapRejected = (reason: KeyWrapRejection): OpenedKeyWrap => ({ status: "rejected", reason });

function readKeyWrap(value: unknown): ParsedKeyWrap {
  if (!exactKeys(value, [...KEYWRAP_KEYS])) throw new Error("Invalid key-wrap fields");
  if (value.contract !== RELAY_KEYWRAP_CONTRACT) throw new Error("Invalid key-wrap contract");
  const sender = value.sender, recipient = value.recipient;
  if (!isDeviceId(sender) || !isDeviceId(recipient) || sender === recipient) {
    throw new Error("Invalid key-wrap parties");
  }
  const keyVersion = value.keyVersion;
  if (typeof keyVersion !== "number" || !Number.isSafeInteger(keyVersion) || keyVersion < 1) throw new Error("Invalid key version");
  const ivText = value.iv, wrappedText = value.wrapped, signatureText = value.signature;
  if (typeof ivText !== "string" || typeof wrappedText !== "string" || typeof signatureText !== "string") {
    throw new Error("Invalid key-wrap body");
  }
  const iv = bytesField(ivText, IV_BYTES, IV_BYTES, "key-wrap iv");
  const wrapped = bytesField(wrappedText, 32, ENVELOPE_FIELDS.maxWrappedChars, "key-wrap payload");
  const signature = bytesField(signatureText, 64, 64, "key-wrap signature");
  const envelope: KeyWrapEnvelope = Object.freeze({
    contract: RELAY_KEYWRAP_CONTRACT,
    sender,
    recipient,
    keyVersion,
    iv: ivText,
    wrapped: wrappedText,
    signature: signatureText,
  });
  return { envelope, iv, wrapped, signature };
}

function keyWrapSignedFields(envelope: Omit<KeyWrapEnvelope, "signature">): JsonObject {
  return {
    contract: envelope.contract,
    sender: envelope.sender,
    recipient: envelope.recipient,
    keyVersion: envelope.keyVersion,
    iv: envelope.iv,
    wrapped: envelope.wrapped,
  };
}

export function keyWrapAdditionalData(sender: string, recipient: string, keyVersion: number): string {
  return `${RELAY_KEYWRAP_CONTRACT}|${sender}|${recipient}|${keyVersion}`;
}

/** Wrap `accountKey` for `recipient` — a device already enrolled and whose
 * public keys this device trusts. */
export async function sealKeyWrap(input: {
  sender: DeviceIdentity;
  recipient: PeerDevice;
  accountKey: CryptoKey;
  keyVersion: number;
}): Promise<KeyWrapEnvelope> {
  const { sender, recipient, accountKey, keyVersion } = input;
  if (!isDeviceIdentity(sender)) throw new TypeError("Invalid sender identity");
  if (!isPeerDevice(recipient)) throw new TypeError("Invalid recipient device");
  if (!isAccountKey(accountKey)) throw new TypeError("Invalid account key");
  if (recipient.device === sender.device) throw new Error("A device does not wrap the account key for itself");
  if (!Number.isSafeInteger(keyVersion) || keyVersion < 1) throw new Error("Invalid key version");
  const sealing = await deriveWrapKey(sender.agreement.privateKey, recipient.agreementKey, recipient.device, RELAY_KEYWRAP_CONTRACT, "wrapKey");
  const iv = randomBytes(IV_BYTES);
  const wrapped = new Uint8Array(await subtle().wrapKey(
    "raw",
    accountKey,
    sealing,
    { name: "AES-GCM", iv, additionalData: new TextEncoder().encode(keyWrapAdditionalData(sender.device, recipient.device, keyVersion)), tagLength: 128 },
  )) as Bytes;
  const signature = await signCanonicalBase64(sender.signing.privateKey, keyWrapSignedFields({
    contract: RELAY_KEYWRAP_CONTRACT,
    sender: sender.device,
    recipient: recipient.device,
    keyVersion,
    iv: encodeBase64Url(iv),
    wrapped: encodeBase64Url(wrapped),
  }));
  return Object.freeze({
    contract: RELAY_KEYWRAP_CONTRACT,
    sender: sender.device,
    recipient: recipient.device,
    keyVersion,
    iv: encodeBase64Url(iv),
    wrapped: encodeBase64Url(wrapped),
    signature,
  });
}

/** Open a key-wrap addressed to `recipient` from `sender`. The signature is
 * checked before the key is derived, and the account key comes back
 * extractable so it can be re-wrapped when enrolling another device. */
export async function openKeyWrap(input: {
  envelope: unknown;
  recipient: DeviceIdentity;
  sender: PeerDevice;
}): Promise<OpenedKeyWrap> {
  const { recipient, sender } = input;
  if (!isDeviceIdentity(recipient)) throw new TypeError("Invalid recipient identity");
  if (!isPeerDevice(sender)) throw new TypeError("Invalid sender device");
  let parsed: ParsedKeyWrap;
  try { parsed = readKeyWrap(input.envelope); } catch { return wrapRejected("malformed-envelope"); }
  const { envelope } = parsed;
  if (envelope.recipient !== recipient.device) return wrapRejected("recipient-mismatch");
  if (envelope.sender !== sender.device) return wrapRejected("sender-mismatch");
  if (!(await verifyCanonical(sender.verifyKey, keyWrapSignedFields(envelope), parsed.signature))) return wrapRejected("bad-signature");
  try {
    const sealing = await deriveWrapKey(recipient.agreement.privateKey, sender.agreementKey, recipient.device, RELAY_KEYWRAP_CONTRACT, "unwrapKey");
    const raw = await subtle().unwrapKey(
      "raw",
      parsed.wrapped,
      sealing,
      { name: "AES-GCM", iv: parsed.iv, additionalData: new TextEncoder().encode(keyWrapAdditionalData(envelope.sender, envelope.recipient, envelope.keyVersion)), tagLength: 128 },
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
    );
    if (!isKey(raw, "secret", "AES-GCM", ["encrypt", "decrypt", "wrapKey", "unwrapKey"], true)) return wrapRejected("unwrap-failed");
    return { status: "opened", envelope, accountKey: raw };
  } catch {
    return wrapRejected("unwrap-failed");
  }
}

// Re-export identity helpers envelope callers need --------------------------------
export { peerOf };
export type { DeviceIdentity, PeerDevice };
export type { JsonValue };
export { canonicalize };
