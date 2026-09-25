# relay

Shared Convex relay foundation for Hraness products: verified-email device
enrollment, a fenced device-command lifecycle, and end-to-end encrypted
projections between machines.

relay is the store, not the product. It holds ciphertext envelopes and
opaque metadata — device ids, revisions, command states, bounded
timestamps — and never sees plaintext session content, credentials, or
workspace bodies.

## Layout

- `convex/` — backend factories: auth subjects and OTP challenges, the
  device registry, capability-bound enrollment invites, the command
  lifecycle reducer, the envelope store, rate buckets, retention crons.
- `wire/` — the versioned contract specification and validators every
  client speaks.
- `crypto/` — the pinned envelope scheme: ECDSA P-256 low-S signatures
  over canonical JSON, ECDH-P256 pairing, AES-GCM-256 payloads.
- `client-ts/` — the typed TypeScript client.

Products instantiate the backend with their own wire namespace
(`xcb.relay.*.v1`, …) and bounds. Wire compatibility is the contract;
other-language clients (Rust) implement `wire/` directly.

## Status

Foundation extraction in progress. xcb is the first consumer; hra and alt
can adopt it later. See `docs/plans/`.
