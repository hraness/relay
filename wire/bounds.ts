/** Relay bounds and the product configuration every backend instantiation
 * supplies. Bounds are compile-time constants: a product tightening a bound
 * is a deploy-safe change, and loosening one is a deliberate contract bump. */

import { isWireKind, isWireNamespace } from "./ids";

export type RelayBounds = Readonly<{
  /** Items per write call and rows per page. */
  batch: number;
  /** Ciphertext characters on a signed envelope body. */
  ciphertextChars: number;
  /** Command plaintext ceiling enforced by products before sealing. */
  commandPayloadChars: number;
  /** Projection plaintext ceiling enforced by products before sealing. */
  projectionPayloadChars: number;
  /** Pending (non-terminal) commands per target device. */
  pendingCommandsPerDevice: number;
  /** Enrolled device rows per user, revoked rows included. */
  devicesPerUser: number;
  /** Active (non-revoked) devices per user. */
  activeDevicesPerUser: number;
  /** Key-delivery envelopes stored for one recipient device. */
  keyEnvelopesPerRecipient: number;
  /** Projection scopes per device. */
  projectionScopesPerDevice: number;
  /** How long a queued command may sit before it expires. */
  commandLifetimeMs: number;
  /** Terminal command rows are retained this long after the requester
   * acknowledged them. */
  terminalCommandRetentionMs: number;
  /** Idempotency receipts outlive their command by this much. */
  idempotencyReceiptLifetimeMs: number;
  /** Invite codes live this long once issued. */
  inviteLifetimeMs: number;
  /** OTP codes live this long once issued. */
  otpLifetimeMs: number;
  /** Live OTP challenges per email address. */
  liveOtpChallenges: number;
  /** Presence TTL for one heartbeat. */
  presenceTtlMs: number;
  /** Security/audit events retained per user. */
  securityEventsPerUser: number;
}>;

export const DEFAULT_RELAY_BOUNDS: RelayBounds = Object.freeze({
  batch: 50,
  ciphertextChars: 65_536,
  commandPayloadChars: 8_192,
  projectionPayloadChars: 32_768,
  pendingCommandsPerDevice: 64,
  devicesPerUser: 64,
  activeDevicesPerUser: 32,
  keyEnvelopesPerRecipient: 256,
  projectionScopesPerDevice: 64,
  commandLifetimeMs: 24 * 60 * 60 * 1_000,
  terminalCommandRetentionMs: 7 * 24 * 60 * 60 * 1_000,
  idempotencyReceiptLifetimeMs: 7 * 24 * 60 * 60 * 1_000,
  inviteLifetimeMs: 7 * 24 * 60 * 60 * 1_000,
  otpLifetimeMs: 10 * 60 * 1_000,
  liveOtpChallenges: 3,
  presenceTtlMs: 45_000,
  securityEventsPerUser: 1_000,
});

export type RelayRateBucket = "sync" | "commands" | "devices" | "auth";
export const RELAY_RATE_BUCKETS = Object.freeze(["sync", "commands", "devices", "auth"] as const);

export type RelayRateLimits = Readonly<Record<RelayRateBucket, Readonly<{ capacity: number; periodMs: number }>>>;

export const DEFAULT_RELAY_RATE_LIMITS: RelayRateLimits = Object.freeze({
  sync: Object.freeze({ capacity: 2_000, periodMs: 60 * 60 * 1_000 }),
  commands: Object.freeze({ capacity: 500, periodMs: 60 * 60 * 1_000 }),
  devices: Object.freeze({ capacity: 64, periodMs: 24 * 60 * 60 * 1_000 }),
  auth: Object.freeze({ capacity: 120, periodMs: 60 * 60 * 1_000 }),
});

/** OTP attempt policy: per-address and global windows for sends, plus a
 * lifetime cap on codes sent to an address that never verifies. */
export const OTP_ATTEMPT_POLICY = Object.freeze({
  sendPerEmail: Object.freeze([
    Object.freeze({ limit: 3, windowMs: 15 * 60 * 1_000 }),
    Object.freeze({ limit: 5, windowMs: 24 * 60 * 60 * 1_000 }),
  ]),
  sendGlobal: Object.freeze([
    Object.freeze({ limit: 200, windowMs: 60 * 60 * 1_000 }),
    Object.freeze({ limit: 1_000, windowMs: 24 * 60 * 60 * 1_000 }),
  ]),
  verifyPerEmail: Object.freeze([Object.freeze({ limit: 10, windowMs: 15 * 60 * 1_000 })]),
  verifyGlobal: Object.freeze([Object.freeze({ limit: 100, windowMs: 60 * 60 * 1_000 })]),
  sendRetentionMs: 24 * 60 * 60 * 1_000,
  verifyRetentionMs: 60 * 60 * 1_000,
  unverifiedLifetimeSendLimit: 10,
} as const);

/** How the deployment delivers OTP codes. `log` writes the code to the
 * backend log and is the only mode an anonymous local backend supports;
 * `webhook` POSTs `{to, code, expiresAt}` with a bearer token; `resend`
 * calls the Resend email API; `sendgrid` calls the SendGrid v3 mail-send
 * API. Non-log modes read their endpoint and secrets from environment
 * variables named here — the values never appear in configuration or
 * code. */
export type EmailTransport =
  | Readonly<{ mode: "log" }>
  | Readonly<{ mode: "webhook"; urlEnv: string; tokenEnv: string }>
  | Readonly<{ mode: "resend"; keyEnv: string; fromEnv: string }>
  | Readonly<{ mode: "sendgrid"; keyEnv: string; fromEnv: string }>;

export type RelayConfig = Readonly<{
  /** Wire namespace stamping envelope contracts, e.g. `xcb.relay.v1`. */
  namespace: string;
  /** The closed union of device-command kinds this product admits. */
  commandKinds: readonly string[];
  /** Device classes the registry admits. The first listed is the executor
   * class — the only one that may claim commands addressed to it. */
  deviceClasses: readonly [string, ...string[]];
  /** Executor device class name, e.g. `daemon`. */
  executorClass: string;
  /** How OTP codes leave the deployment. */
  email: EmailTransport;
  /** Whether a never-seen email may self-admit by OTP. When false, first
   * admission requires an identity invite issued by an active subject. */
  openSignup: boolean;
  /** Names the environment variable holding a one-shot bootstrap invite
   * token: while no subject has ever verified, a request may present
   * `digestInviteCapability(namespace, token)` and be admitted as if it
   * held an issued identity invite. Once the first subject verifies, the
   * token is dead. Never set on a deployment that leaves open sign-up on. */
  bootstrapInviteEnv?: string;
  /** Convex Auth credentials provider id — pinned per product. */
  authProviderId: string;
  bounds?: Partial<RelayBounds>;
  rateLimits?: Partial<RelayRateLimits>;
}>;

export function resolveRelayBounds(config: Pick<RelayConfig, "bounds">): RelayBounds {
  return Object.freeze({ ...DEFAULT_RELAY_BOUNDS, ...(config.bounds ?? {}) });
}

export function resolveRateLimits(config: Pick<RelayConfig, "rateLimits">): RelayRateLimits {
  return Object.freeze({ ...DEFAULT_RELAY_RATE_LIMITS, ...(config.rateLimits ?? {}) }) as RelayRateLimits;
}

/** Validate a product configuration once, at module scope, so a malformed
 * relay refuses every call instead of drifting. */
export function checkRelayConfig(config: RelayConfig): RelayConfig {
  if (!isWireNamespace(config.namespace)) {
    throw new Error(`relay config: invalid namespace ${JSON.stringify(config.namespace)}`);
  }
  if (config.commandKinds.length === 0 || config.commandKinds.length > 64) {
    throw new Error("relay config: commandKinds must name 1–64 kinds");
  }
  const seen = new Set<string>();
  for (const kind of config.commandKinds) {
    if (!isWireKind(kind)) throw new Error(`relay config: invalid command kind ${JSON.stringify(kind)}`);
    if (seen.has(kind)) throw new Error(`relay config: duplicate command kind ${JSON.stringify(kind)}`);
    seen.add(kind);
  }
  if (config.deviceClasses.length === 0 || config.deviceClasses.length > 8) {
    throw new Error("relay config: deviceClasses must name 1–8 classes");
  }
  for (const deviceClass of config.deviceClasses) {
    if (!isWireKind(deviceClass)) throw new Error(`relay config: invalid device class ${JSON.stringify(deviceClass)}`);
  }
  if (!config.deviceClasses.includes(config.executorClass)) {
    throw new Error("relay config: executorClass must be one of deviceClasses");
  }
  if (!isWireKind(config.authProviderId) && !/^[-a-z0-9_]{1,64}$/u.test(config.authProviderId)) {
    throw new Error("relay config: invalid authProviderId");
  }
  if (config.bootstrapInviteEnv !== undefined) {
    if (!/^[A-Z][A-Z0-9_]{0,63}$/u.test(config.bootstrapInviteEnv)) {
      throw new Error("relay config: invalid env name for bootstrapInviteEnv");
    }
    if (config.openSignup) {
      throw new Error("relay config: bootstrapInviteEnv is meaningless with open sign-up");
    }
  }
  const email = config.email;
  if (email.mode === "webhook") {
    for (const name of [email.urlEnv, email.tokenEnv]) {
      if (!/^[A-Z][A-Z0-9_]{0,63}$/u.test(name)) throw new Error(`relay config: invalid env name ${name}`);
    }
  }
  if (email.mode === "resend" || email.mode === "sendgrid") {
    for (const name of [email.keyEnv, email.fromEnv]) {
      if (!/^[A-Z][A-Z0-9_]{0,63}$/u.test(name)) throw new Error(`relay config: invalid env name ${name}`);
    }
  }
  const bounds = resolveRelayBounds(config);
  for (const [key, value] of Object.entries(bounds)) {
    if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
      throw new Error(`relay config: bound ${key} must be a positive number`);
    }
  }
  return config;
}
