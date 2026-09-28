/** Test-only instantiation wired to the resend transport so tests can
 * drive the real `auth:signIn` action with a stubbed `fetch`. The key and
 * sender come from `RELAY_TEST_RESEND_*` env vars. `@convex-dev/auth`
 * hardcodes the `auth:store` path, so `test.setup.ts` maps this module to
 * `./auth.ts`; it shares the dev instantiation's internal mutations and
 * provider id so only the transport differs. Never deployed. */

import { defineRelay } from "../backend";

const resend = defineRelay({
  namespace: "relay.dev.v1",
  commandKinds: ["task_dispatch"],
  deviceClasses: ["daemon", "controller"],
  executorClass: "daemon",
  email: { mode: "resend", keyEnv: "RELAY_TEST_RESEND_KEY", fromEnv: "RELAY_TEST_RESEND_FROM" },
  openSignup: true,
  authProviderId: "relay-dev-otp-v1",
  productName: "Relay Dev",
});

export const auth = resend.auth.auth;
export const isAuthenticated = resend.auth.isAuthenticated;
export const signIn = resend.auth.signIn;
export const signOut = resend.auth.signOut;
export const store = resend.auth.store;
