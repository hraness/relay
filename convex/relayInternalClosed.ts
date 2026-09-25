/** Test-only second instantiation: closed sign-up plus a bootstrap invite
 * capability read from `RELAY_TEST_BOOTSTRAP_TOKEN`. Exists so tests can
 * exercise the invite/bootstrap admission path the permissive dev
 * instantiation intentionally skips. Never deployed to a real backend —
 * the module registers only under `convex-test`. */

import { defineRelay } from "../backend";

const closed = defineRelay({
  namespace: "relay.dev.v1",
  commandKinds: ["task_dispatch"],
  deviceClasses: ["daemon", "controller"],
  executorClass: "daemon",
  email: { mode: "log" },
  openSignup: false,
  bootstrapInviteEnv: "RELAY_TEST_BOOTSTRAP_TOKEN",
  authProviderId: "relay-dev-otp-v1",
});

export const reserveEmailAttempt = closed.internal.reserveEmailAttempt;
export const storeOtpChallenge = closed.internal.storeOtpChallenge;
export const recordOtpDelivery = closed.internal.recordOtpDelivery;
export const consumeOtpChallenge = closed.internal.consumeOtpChallenge;
