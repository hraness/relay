# relay

Shared Convex relay foundation for Hraness products: verified-email device
enrollment, a fenced device-command lifecycle, and end-to-end encrypted
projections between machines.

relay stores encrypted payloads with device IDs, revisions, command states,
and bounded timestamps. Products encrypt session content and workspace bodies
before sending them to the relay. Authentication handles email addresses and
one-time sign-in codes separately.

## Choose a package entry point

The package exports TypeScript source and has no root import. Use the subpath for your task:

| Import | Task |
| --- | --- |
| `@hraness/relay/backend` | Instantiate a product's Convex functions with `defineRelay`. |
| `@hraness/relay/wire` | Validate the versioned messages shared by clients and backend. |
| `@hraness/relay/crypto` | Encrypt and sign payloads using the shared envelope scheme. |
| `@hraness/relay/client` | Connect a TypeScript client to the relay. |

Your toolchain must handle TypeScript source. The backend uses Convex with a peer range of `>=1.44.0`; the repository tests against its pinned Convex version. Start with [the reference instantiation](#instantiating-a-product-relay), and use [device reauthentication](docs/device-reauth.md) when an active device needs a new session without replacing its keys.

## Layout

- `backend/`: backend factories for auth subjects and OTP challenges, the
  device registry, capability-bound enrollment invites, the command
  lifecycle reducer, the envelope store, rate buckets, retention crons.
- `convex/`: the relay's own dev instantiation and `convex-test` harness.
- `wire/`: the versioned contract specification and validators every
  client speaks.
- `crypto/`: the pinned envelope scheme, with ECDSA P-256 low-S signatures
  over canonical JSON, ECDH-P256 pairing, and AES-GCM-256 payloads.
- `client-ts/`: the typed TypeScript client.

Products instantiate the backend with their own wire namespace
(`xcb.relay.*.v1`, …) and bounds. Wire compatibility is the contract;
other-language clients (Rust) implement `wire/` directly.

## Instantiating a product relay

A product deployment is a thin `convex/` directory over `defineRelay`. This
example uses local log delivery, which prints sign-in codes to the backend
log. Production deployments use the `webhook` or `resend` email transport:

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
  productName: "xcb",
});
```

The product then re-exports the pieces Convex must register:

- `convex/schema.ts`: `export default relaySchema()`.
- `convex/auth.config.ts`: the single credentials provider.
- `convex/relayInternal.ts`: re-export `relayAuthInternal` under the path
  the auth internals resolve through (default `relayInternal`).
- One module per surface (`relayDevices`, `relayCommands`,
  `relayProjections`, `relayEnvelopes`, `relayInvites`,
  `relayMaintenance`, `relayAuth`), spreading the corresponding backend
  factory result.
- `convex/crons.ts`: schedule `relayMaintenance:sweep`.

This repository's own `convex/` directory is the reference instantiation.
See [device reauthentication](docs/device-reauth.md) for the additive protocol
that restores an active device's session while preserving its keys and work.

## Developing

```
bun install
bun run check            # typecheck + unit/convex tests
bun run convex:init      # select the anonymous local deployment
bun run convex:dev       # live-push the dev instantiation locally
```

Local development only ever targets the anonymous deployment chosen by
`scripts/convex-local.ts`; deploy credentials are scrubbed before launch.
