/** Emit cross-language golden vectors as JSON on stdout. The Rust consumer
 * embeds this output; every field is base64url or plain text. Device
 * scalars are exported once from an extractable copy and re-imported
 * non-extractable so the identity matches the custody contract.
 *
 * Run: `bun scripts/emit-vectors.ts` */

import { assembleDeviceIdentity, importPeerDevice } from "../crypto/device";
import { canonicalize } from "../crypto/canonical";
import { sealEnvelope, sealKeyWrap, RELAY_ENVELOPE_CONTRACT } from "../crypto/envelope";
import {
  ECDH_P256,
  ECDSA_P256,
  generateAccountKey,
  exportAccountKey,
  signCanonical,
  subtle,
} from "../crypto/primitives";
import { decodeBase64Url, encodeBase64Url, utf8Encode } from "../wire/encoding";

async function exportableDevice() {
  const signing = await subtle().generateKey(ECDSA_P256, true, ["sign", "verify"]);
  const agreement = await subtle().generateKey(ECDH_P256, true, ["deriveBits"]);
  // Record scalars, then re-import non-extractable for the live identity.
  const signingJwk = (await subtle().exportKey("jwk", signing.privateKey)) as { d?: string; x?: string; y?: string };
  const agreementJwk = (await subtle().exportKey("jwk", agreement.privateKey)) as { d?: string; x?: string; y?: string };
  const sealedSigning = {
    privateKey: await subtle().importKey("jwk", signingJwk, ECDSA_P256, false, ["sign"]),
    publicKey: signing.publicKey,
  };
  const sealedAgreement = {
    privateKey: await subtle().importKey("jwk", agreementJwk, ECDH_P256, false, ["deriveBits"]),
    publicKey: agreement.publicKey,
  };
  const identity = await assembleDeviceIdentity(sealedSigning, sealedAgreement);
  return { identity, signingScalar: signingJwk.d!, agreementScalar: agreementJwk.d! };
}

const sender = await exportableDevice();
const receiver = await exportableDevice();
const accountKey = await generateAccountKey();

const message = { challengeId: "vec", contract: "relay.dev.v1:device-bind", nonce: "AA" };
const signature = await signCanonical(sender.identity.signing.privateKey, message);

const plaintext = utf8Encode("bounded projection ciphertext across languages");
const envelope = await sealEnvelope({
  sender: sender.identity,
  accountKey,
  scope: "workspace.demo",
  keyVersion: 1,
  plaintext,
});

const wrap = await sealKeyWrap({
  sender: sender.identity,
  recipient: await importPeerDevice(receiver.identity.publicKeys),
  accountKey,
  keyVersion: 1,
});

console.log(JSON.stringify({
  accountKey: encodeBase64Url(await exportAccountKey(accountKey)),
  canonical: canonicalize(message),
  contract: RELAY_ENVELOPE_CONTRACT,
  envelope,
  keyWrap: wrap,
  message,
  plaintext: encodeBase64Url(plaintext),
  receiver: {
    agreementScalar: receiver.agreementScalar,
    device: receiver.identity.device,
    publicKeys: receiver.identity.publicKeys,
    signingScalar: receiver.signingScalar,
  },
  sender: {
    agreementScalar: sender.agreementScalar,
    device: sender.identity.device,
    publicKeys: sender.identity.publicKeys,
    signingScalar: sender.signingScalar,
  },
  signature: encodeBase64Url(signature),
}));
