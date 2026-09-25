# Contents

- `convex/` is the relay's own dev instantiation and test harness:
  `relay.ts` instantiates `defineRelay` with namespace `relay.dev.v1`,
  open sign-up, and log-mode email; the per-module re-export files expose
  the factory functions to Convex; `fixture.ts` plus the colocated
  `*.test.ts` files exercise the backend end to end with `convex-test`.

# Guidelines

- Local development only ever targets the anonymous deployment selected
  by `scripts/convex-local.ts`. Never point this directory at a production
  deployment or commit deploy credentials.
- The dev instantiation stays permissive on purpose (`openSignup`, log
  email). Product deployments set their own policy.
- Test auth identities follow `userId|authSessionId`; never fake a device
  authority the bind ceremony would not produce.
