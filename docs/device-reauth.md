# Device reauthentication

A product re-exports `relay.devices.beginReauth`, `finishReauth`, and
`reauthStatus`. This additive protocol restores an **active** device's
session after interactive verified-email authentication. It preserves the
device ID, signing/agreement keys, class, key version, auth epoch, wrapped
account keys, presence, projections, commands, and boot-authority fences.
It cannot activate pending devices or resurrect revoked devices.

`relay.auth.queries.currentSubject` uses the verified provider subject and
returns `{ userId, authEpoch, status: "active", verifiedAt }`. `verifiedAt`
is a timestamp or null. Missing or inactive authority is rejected. The
stable `userId` is distinct from the JWT's `userId|sessionId` subject.
Existing `devices.list` output is unchanged.

## Wire contract

All calls use the newly authenticated session for the device's existing
user and existing relay deployment. The old token is not required.

- Mutation `beginReauth({ deviceId })` returns `DeviceReauthChallenge` in
  [wire/reauth.ts](../wire/reauth.ts).
- Sign the **entire returned object**, with no extra fields, using canonical
  JSON UTF-8 and the retained device ECDSA P-256 key. Signatures are SHA-256,
  raw 64-byte `r || s`, low-S, unpadded canonical base64url. The contract is
  `${namespace}:device-reauth`, distinct from device enrollment.
- Mutation `finishReauth({ deviceId, challengeId, signature })` returns
  `DeviceReauthResult`, including the new session ID, challenge ID, stable
  user, unchanged device/class/keyVersion/authEpoch, and incremented
  `bindingRevision`.
- Query `reauthStatus({ deviceId, challengeId })` returns
  `{ status: "committed", result }` or `{ status: "pending" | "expired" |
  "superseded" | "unknown" }`. Only `committed` authorizes publication of
  the journal's new session locally. A receipt is visible only to the exact
  authenticated session that committed it.

The signed challenge includes `userId`, `authSessionId`, `deviceId`,
`deviceClass`, `authEpoch`, `keyVersion`, `bindingRevision`, `challengeId`,
`nonce`, `expiresAt`, and `contract`. It expires after five minutes.
`bindingRevision` is independent of presence or projection changes. Legacy
rows start at revision zero; a successful transition increments it once.
Unknown fields and unsafe integer authority values are rejected.

The committed mapping retains the operation ID, proof digest, and device
metadata needed to reconcile an exact retry **after challenge cleanup**.
Successful replay does not mutate the device again. It still requires the
same authenticated session and exact proof, and fails after another reauth,
revocation, epoch change, or key/class change. A client whose journal session
expires obtains a fresh OTP, begins a new challenge against the current
revision, and proves its retained device key again.

## Atomicity and lifecycle

Finish rechecks the current verified user/session, active device, auth epoch,
unchanged keys/class/key version and binding revision in one transaction.
A session already bound to another device cannot begin or finish. Competing
ceremonies based on the same revision have one winner. The old device mapping
is deleted and replaced atomically; old tokens lose device authority. Device
mappings remain bounded to one. Corrupt multiple legacy mappings fail closed
without partial deletion.

Challenges reuse `relayBindChallenges`; optional purpose/metadata preserve
legacy enrollment rows. Untagged challenges mean bind, and `finishBind`
rejects reauth challenges. Existing expiry sweep, account lifecycle and
device revocation coverage apply unchanged. Auth mutation rate limits apply
to begin, finish, and committed retries.

The client must stop its healthy local relay at a complete pump boundary
before finish, durably journal ambiguous outcomes, validate the exact result,
and publish the new local session atomically. This protocol does not drain
or reset pending or started commands. Truly abandoned claims use the existing
strictly later-authority recovery path; an unobserved started effect remains
`ambiguous`, never `applied`.

[wire/device-reauth.vector.json](../wire/device-reauth.vector.json) is a
fixed cross-language signing vector. Its private scalar is synthetic test
material only. `scripts/emit-vectors.ts` also emits a `reauth` vector alongside
the existing enrollment/envelope vectors.
