# relay

Shared Convex relay foundation for Hraness products: verified-email device
enrollment, a fenced device-command lifecycle, and end-to-end encrypted
projections between machines.

relay is the store, not the product. It holds ciphertext envelopes and
opaque metadata — device ids, revisions, command states, bounded
timestamps — and never sees plaintext session content, credentials, or
workspace bodies.

## Layout

- `backend/` — backend factories: auth subjects and OTP challenges, the
  device registry, capability-bound enrollment invites, the command
  lifecycle reducer, the envelope store, rate buckets, retention crons.
- `convex/` — the relay's own dev instantiation and `convex-test` harness.
- `wire/` — the versioned contract specification and validators every
  client speaks.
- `crypto/` — the pinned envelope scheme: ECDSA P-256 low-S signatures
  over canonical JSON, ECDH-P256 pairing, AES-GCM-256 payloads.
- `client-ts/` — the typed TypeScript client.

Products instantiate the backend with their own wire namespace
(`xcb.relay.*.v1`, …) and bounds. Wire compatibility is the contract;
other-language clients (Rust) implement `wire/` directly.

## Instantiating a product relay

A product deployment is a thin `convex/` directory over `defineRelay`:

```ts
// convex/relay.ts
import { defineRelay } from "@hraness/relay/backend";

export const relay = defineRelay({
  namespace: "xcb.relay.v1",
  commandKinds: ["task_dispatch", "task_steer"],
  deviceClasses: ["daemon", "controller"],
  executorClass: "daemon",
  email: { mode: "log" },
  openSignup: false,
  authProviderId: "xcb-otp-v1",
});
```

The product then re-exports the pieces Convex must register:

- `convex/schema.ts` — `export default relaySchema()`.
- `convex/auth.config.ts` — the single credentials provider.
- `convex/relayInternal.ts` — re-export `relayAuthInternal` under the path
  the auth internals resolve through (default `relayInternal`).
- One module per surface (`relayDevices`, `relayCommands`,
  `relayProjections`, `relayEnvelopes`, `relayInvites`,
  `relayMaintenance`, `relayAuth`), spreading the corresponding backend
  factory result.
- `convex/crons.ts` — schedule `relayMaintenance:sweep`.

This repository's own `convex/` directory is the reference instantiation.

## Developing

```
bun install
bun run check            # typecheck + unit/convex tests
bun run convex:init      # select the anonymous local deployment
bun run convex:dev       # live-push the dev instantiation locally
```

Local development only ever targets the anonymous deployment chosen by
`scripts/convex-local.ts`; deploy credentials are scrubbed before launch.

## Status

Foundation. xcb is the first consumer; hra and alt can adopt it later.
