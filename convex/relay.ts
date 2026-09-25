/** The relay's own dev instantiation: namespace `relay.dev.v1`, daemon +
 * controller device classes, log-mode email (the only mode an anonymous
 * local backend supports), and open sign-up for local development. */

import { defineRelay } from "../backend";

export const relay = defineRelay({
  namespace: "relay.dev.v1",
  commandKinds: [
    "task_dispatch",
    "task_steer",
    "task_cancel",
    "attention_answer",
    "daemon_send",
    "projection_refresh",
  ],
  deviceClasses: ["daemon", "controller"],
  executorClass: "daemon",
  email: { mode: "log" },
  openSignup: true,
  authProviderId: "relay-dev-otp-v1",
});
