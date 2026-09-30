<!-- browser-automation:start -->
- Ordinary owned automated browser runs use versioned Chrome for Testing or the browser provisioned for the pinned Playwright version. Reject the installed auto-updating Chrome application, including explicit executable overrides and symlinks; never fall back to it when provisioning is missing. Report the resolved executable and browser version, and close owned contexts and browsers gracefully in cleanup. Attaching to an explicitly authorized user-owned browser is a separate operation: preserve its profile and lifetime. Keep regression checks for browser selection in the existing required checks; see [browser automation](https://github.com/hraness/.github/blob/main/BROWSER_AUTOMATION.md).
- Never start the system Chrome app directly from an agent shell; use the repository's browser tooling and respect its scheduler and browser custody controls. For owned launches, pass `--mute-audio` and merge `PaintHolding,MacAppCodeSignClone` into any existing `--disable-features` value instead of adding a second switch. Finish owned process, context, and profile cleanup before releasing the browser lane. Never signal another holder or manipulate its lease to obtain a slot.
- The sole native-runtime exception is Slopcamera’s documented signature-verified, version-bound, immutable task-owned Chrome snapshot, never a direct launch of the installed application. Its current integrity-bound launch contract must disable `MacAppCodeSignClone`; retain vendor identity verification, browser custody, graceful cleanup, and regression checks. Qualify the native fix with live clone-growth and cleanup evidence before activating this exception. It is not an executable override or fallback for ordinary automation; see [the native-runtime exception](https://github.com/hraness/.github/blob/main/BROWSER_AUTOMATION.md#slopcamera-native-runtime-exception).
<!-- browser-automation:end -->

# Contents

- `backend/` contains the backend factories each product instantiates with
  its own wire namespace and bounds: verified-email auth subjects and OTP
  challenges, the device registry, capability-bound enrollment invites,
  the device-command lifecycle reducer, the envelope store, rate buckets,
  and retention crons.
- `convex/` contains the relay's own dev instantiation and the
  `convex-test` harness that exercises the factories end to end.
- `wire/` contains the versioned contract specification and validators:
  envelope shapes, authority tuples (user + device + auth epoch + boot
  generation), idempotency keys, and every bound. Non-TypeScript clients
  implement `wire/` directly; it is the portability surface.
- `crypto/` contains the pinned envelope scheme — ECDSA P-256 low-S
  signatures over canonical JSON, ECDH-P256 device pairing, AES-GCM-256
  payloads — implemented only on WebCrypto primitives so Rust can match
  with `p256` and `aes-gcm`.
- `client-ts/` contains the typed TypeScript client over `wire/` and
  `crypto/`.
- `docs/plans/` contains the frozen contracts for each delivery phase.

# Guidelines

- Parse every foreign value from `unknown`. Reject unknown fields, stale
  revisions, stale authority, and replayed idempotency keys.
- The relay stores ciphertext plus opaque metadata only. Never accept
  plaintext session content, provider credentials, raw reasoning,
  approval secrets, arbitrary tool output, environment values, or
  unbounded paths.
- Commands follow the closed lifecycle `pending → prepared →
  effect_started → applied | failed | ambiguous | cancelled | expired`.
  Daemon-addressed commands are fenced by the target's boot authority
  generation; every protected write revalidates user, device, auth epoch
  and authority. An effect that may already have begun closes as
  `ambiguous`, never `applied`.
- Bound everything: payload bytes, pending commands per device, devices
  per user, invite lifetime, OTP rate buckets, retained records.
- A new table joins every exhaustive map: lifecycle policy, quota
  genesis, account deletion, device revocation, and the maintenance
  categories that sweep it.
- Crypto changes ship with cross-implementation vectors in `wire/` and
  round-trip tests in both consumers.
