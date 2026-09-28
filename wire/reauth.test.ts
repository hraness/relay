import { expect, test } from "bun:test";
import { canonicalize, deviceIdOf, importP256SigningKey, verifyCanonical } from "../crypto";
import { decodeBase64Url } from "./encoding";
import { parseDeviceReauthChallenge } from "./reauth";
import vector from "./device-reauth.vector.json";

test("reauth cross-language vector validates canonical bytes, device key and low-S signature", async () => {
  const message = parseDeviceReauthChallenge(vector.message, "relay.dev.v1");
  expect(message).toEqual(vector.message);
  expect(canonicalize(message!)).toBe(vector.canonical);
  const spki = decodeBase64Url(vector.signingPublicKey, 200)!;
  expect(await deviceIdOf(spki)).toBe(vector.deviceId);
  const key = await importP256SigningKey(spki);
  expect(await verifyCanonical(key, message!, decodeBase64Url(vector.signature, 86)!)).toBe(true);
  expect(await verifyCanonical(key, { ...message!, authSessionId: "other_session" }, decodeBase64Url(vector.signature, 86)!)).toBe(false);
});

test("reauth challenge parser rejects unknown fields, malformed IDs and unsafe authority numbers", () => {
  for (const patch of [
    { unknown: true }, { contract: "relay.dev.v1:device-bind" }, { authEpoch: 0 }, { keyVersion: 0 },
    { bindingRevision: -1 }, { bindingRevision: Number.MAX_SAFE_INTEGER }, { bindingRevision: 0.5 },
    { expiresAt: Number.MAX_SAFE_INTEGER + 1 }, { nonce: "bad" }, { challengeId: "bad" },
    { authSessionId: "bad|session" }, { userId: "bad/user" }, { deviceClass: "unknown class" }, { deviceId: "bad" },
  ]) expect(parseDeviceReauthChallenge({ ...vector.message, ...patch }, "relay.dev.v1")).toBeNull();
  expect(parseDeviceReauthChallenge(vector.message, "other.relay.v1")).toBeNull();
});
