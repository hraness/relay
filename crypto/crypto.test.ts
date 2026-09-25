import { describe, expect, test } from "bun:test";

import {
  canonicalDigest,
  canonicalize,
  createDeviceIdentity,
  deviceIdOf,
  generateAccountKey,
  importP256SigningKey,
  isDeviceIdentity,
  openBytes,
  openEnvelope,
  openKeyWrap,
  peerOf,
  restoreDeviceIdentity,
  sealBytes,
  sealEnvelope,
  sealKeyWrap,
  signCanonical,
  signCanonicalBase64,
  verifyCanonical,
  IV_BYTES,
} from "./index";
import { decodeBase64Url, encodeBase64Url, utf8Encode } from "../wire/encoding";

/** Golden vector: the canonicalization + device-id + signature a Rust
 * implementation must reproduce byte-for-byte. */
const GOLDEN = {
  device: "368562786cf06ebcd49e59c1bdfbde21",
  signingSpki: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAm80JBvKwoJdhq25y3Qv9AmIOtDK-MgbqIurIdxv480djpLrvL70yZr84Uk0W1kfYp4a_4y4Twc4TB-rW1p61A",
  message: { challengeId: "vec", contract: "relay.dev.v1:device-bind", nonce: "AA" },
  canonical: "{\"challengeId\":\"vec\",\"contract\":\"relay.dev.v1:device-bind\",\"nonce\":\"AA\"}",
  signature: "-pW0MyxSaapcDLVlg6VN0oVtxchDThC_eaFIE5fliaA2M686A5NSb7XngFYyhn4pgbv1U93mE1Of6X4ubQUFeA",
} as const;

describe("canonical JSON", () => {
  test("sorts object keys and removes whitespace", () => {
    expect(canonicalize({ b: 2, a: { d: [3, "x"], c: true }, z: null })).toBe(
      "{\"a\":{\"c\":true,\"d\":[3,\"x\"]},\"b\":2,\"z\":null}",
    );
  });

  test("matches the golden vector byte-for-byte", () => {
    expect(canonicalize(GOLDEN.message)).toBe(GOLDEN.canonical);
  });

  test("rejects non-finite numbers", () => {
    expect(() => canonicalize(Number.NaN)).toThrow();
    expect(() => canonicalize({ x: Number.POSITIVE_INFINITY })).toThrow();
  });

  test("digest renders sha256:<64 hex>", async () => {
    const digest = await canonicalDigest(GOLDEN.message);
    expect(digest).toMatch(/^sha256:[0-9a-f]{64}$/);
  });
});

describe("device identity", () => {
  test("derives the golden device id from SPKI", async () => {
    const spki = decodeBase64Url(GOLDEN.signingSpki, 122);
    expect(spki).not.toBeNull();
    expect(await deviceIdOf(spki!)).toBe(GOLDEN.device);
  });

  test("creates non-extractable private keys and matching id", async () => {
    const identity = await createDeviceIdentity();
    expect(identity.device).toMatch(/^[0-9a-f]{32}$/);
    expect(identity.signing.privateKey.extractable).toBe(false);
    expect(identity.agreement.privateKey.extractable).toBe(false);
    const spki = decodeBase64Url(identity.publicKeys.signing, 122)!;
    expect(await deviceIdOf(spki)).toBe(identity.device);
  });

  test("restores a live identity and rejects mismatched storage", async () => {
    const identity = await createDeviceIdentity();
    expect(await restoreDeviceIdentity(identity)).toBeTruthy();
    const other = await createDeviceIdentity();
    await expect(restoreDeviceIdentity({ ...identity, publicKeys: other.publicKeys })).rejects.toThrow();
  });
});

describe("signatures", () => {
  test("the golden signature verifies under the golden key", async () => {
    const verifyKey = await importP256SigningKey(decodeBase64Url(GOLDEN.signingSpki, 122)!);
    const signature = decodeBase64Url(GOLDEN.signature, 86)!;
    expect(await verifyCanonical(verifyKey, GOLDEN.message, signature)).toBe(true);
  });

  test("produces low-S signatures only", async () => {
    const identity = await createDeviceIdentity();
    for (let index = 0; index < 8; index++) {
      const signature = await signCanonical(identity.signing.privateKey, { index });
      const s = BigInt(`0x${encodeHex(signature.subarray(32))}`);
      expect(s <= 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n / 2n).toBe(true);
    }
  });

  test("rejects a high-S variant of a valid signature", async () => {
    const identity = await createDeviceIdentity();
    const signature = await signCanonical(identity.signing.privateKey, GOLDEN.message);
    const order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
    const r = signature.subarray(0, 32);
    const s = BigInt(`0x${encodeHex(signature.subarray(32))}`);
    const flipped = order - s;
    const high = new Uint8Array(64);
    high.set(r);
    high.set(new Uint8Array(flipped.toString(16).padStart(64, "0").match(/../g)!.map((b) => Number.parseInt(b, 16))), 32);
    expect(await verifyCanonical(identity.signing.publicKey, GOLDEN.message, high)).toBe(false);
  });

  test("rejects signatures over other messages and other keys", async () => {
    const identity = await createDeviceIdentity();
    const other = await createDeviceIdentity();
    const signature = await signCanonical(identity.signing.privateKey, { a: 1 });
    expect(await verifyCanonical(identity.signing.publicKey, { a: 2 }, signature)).toBe(false);
    expect(await verifyCanonical(other.signing.publicKey, { a: 1 }, signature)).toBe(false);
  });
});

function encodeHex(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
}

describe("AES-GCM", () => {
  test("round-trips under the account key", async () => {
    const key = await generateAccountKey();
    const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
    const sealed = await sealBytes(key, iv, "ad", utf8Encode("hello relay"));
    expect(new TextDecoder().decode(await openBytes(key, iv, "ad", sealed))).toBe("hello relay");
  });

  test("rejects wrong additional data and wrong iv", async () => {
    const key = await generateAccountKey();
    const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
    const sealed = await sealBytes(key, iv, "ad", utf8Encode("x"));
    await expect(openBytes(key, iv, "other", sealed)).rejects.toThrow();
    await expect(openBytes(key, crypto.getRandomValues(new Uint8Array(IV_BYTES)), "ad", sealed)).rejects.toThrow();
  });
});

describe("relay envelopes", () => {
  test("seal → open round trip, account-addressed", async () => {
    const sender = await createDeviceIdentity();
    const reader = await createDeviceIdentity();
    const accountKey = await generateAccountKey();
    const envelope = await sealEnvelope({
      accountKey,
      keyVersion: 1,
      plaintext: utf8Encode(JSON.stringify({ ok: true })),
      scope: "projections.v1",
      sender,
    });
    expect(envelope.sender).toBe(sender.device);
    const opened = await openEnvelope({ accountKey, envelope, recipient: reader, sender: peerOf(sender) });
    expect(opened.status).toBe("opened");
    if (opened.status === "opened") expect(new TextDecoder().decode(opened.plaintext)).toBe("{\"ok\":true}");
  });

  test("rejects wrong sender, tampered scope, and foreign recipients", async () => {
    const sender = await createDeviceIdentity();
    const other = await createDeviceIdentity();
    const reader = await createDeviceIdentity();
    const accountKey = await generateAccountKey();
    const envelope = await sealEnvelope({ accountKey, keyVersion: 1, plaintext: utf8Encode("x"), scope: "s", sender });

    const wrongSender = await openEnvelope({ accountKey, envelope, recipient: reader, sender: peerOf(other) });
    expect(wrongSender.status).toBe("rejected");

    const tampered = { ...envelope, scope: "other" };
    const tamperedOpen = await openEnvelope({ accountKey, envelope: tampered, recipient: reader, sender: peerOf(sender) });
    expect(tamperedOpen.status).toBe("rejected");

    const targeted = await sealEnvelope({
      accountKey,
      keyVersion: 1,
      plaintext: utf8Encode("x"),
      recipient: reader.device,
      scope: "s",
      sender,
    });
    const wrongRecipient = await openEnvelope({ accountKey, envelope: targeted, recipient: other, sender: peerOf(sender) });
    expect(wrongRecipient.status).toBe("rejected");
    expect(wrongRecipient.status === "rejected" ? wrongRecipient.reason : "").toBe("recipient-mismatch");
  });
});

describe("key-wrap envelopes", () => {
  test("delivers the account key to the named device only", async () => {
    const sender = await createDeviceIdentity();
    const recipient = await createDeviceIdentity();
    const recipientPeer = peerOf(recipient);
    const accountKey = await generateAccountKey();
    const envelope = await sealKeyWrap({ accountKey, keyVersion: 3, recipient: recipientPeer, sender });
    const opened = await openKeyWrap({ envelope, recipient, sender: peerOf(sender) });
    expect(opened.status).toBe("opened");
    if (opened.status === "opened") {
      const roundTrip = await sealBytes(opened.accountKey, new Uint8Array(IV_BYTES), "ad", utf8Encode("k"));
      expect(new TextDecoder().decode(await openBytes(accountKey, new Uint8Array(IV_BYTES), "ad", roundTrip))).toBe("k");
    }
  });

  test("rejects the wrong recipient and a forged sender", async () => {
    const sender = await createDeviceIdentity();
    const recipient = await createDeviceIdentity();
    const outsider = await createDeviceIdentity();
    const accountKey = await generateAccountKey();
    const envelope = await sealKeyWrap({ accountKey, keyVersion: 1, recipient: peerOf(recipient), sender });

    const wrongRecipient = await openKeyWrap({ envelope, recipient: outsider, sender: peerOf(sender) });
    expect(wrongRecipient.status).toBe("rejected");
    if (wrongRecipient.status === "rejected") expect(wrongRecipient.reason).toBe("recipient-mismatch");

    const wrongSender = await openKeyWrap({ envelope, recipient, sender: peerOf(outsider) });
    expect(wrongSender.status).toBe("rejected");
    if (wrongSender.status === "rejected") expect(wrongSender.reason).toBe("sender-mismatch");
  });
});
