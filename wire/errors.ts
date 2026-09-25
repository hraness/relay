/** The closed error vocabulary crossing the relay boundary. Convex errors
 * carry a `data` payload; only these shapes are produced, and a client
 * parses anything it receives through `parseRelayErrorData` before trusting
 * a code. */

import { exactKeys, isSafeNonNegativeInteger } from "./encoding";
import { isDeviceId, isPublicId } from "./ids";
import { RELAY_RATE_BUCKETS, type RelayRateBucket } from "./bounds";

export type RelayQuota =
  | "devices"
  | "active-devices"
  | "pending-commands"
  | "key-envelopes"
  | "projection-scopes"
  | "security-events";

export const RELAY_QUOTAS = Object.freeze([
  "devices",
  "active-devices",
  "pending-commands",
  "key-envelopes",
  "projection-scopes",
  "security-events",
] as const satisfies readonly RelayQuota[]);

export type RelayErrorData =
  | Readonly<{ code: "unauthenticated" }>
  | Readonly<{ code: "invalid-argument"; field: string }>
  | Readonly<{ code: "rate-limited"; bucket: RelayRateBucket; retryAfterMs: number }>
  | Readonly<{ code: "quota-exceeded"; quota: RelayQuota }>
  | Readonly<{ code: "unknown-device"; device: string }>
  | Readonly<{ code: "revoked-device"; device: string }>
  | Readonly<{ code: "unknown-command"; command: string }>
  | Readonly<{ code: "conflict"; field: string }>
  | Readonly<{ code: "authority-stale" }>
  | Readonly<{ code: "forbidden-device-class"; device: string }>;

export type RelayErrorCode = RelayErrorData["code"];
export const RELAY_ERROR_CODES = Object.freeze([
  "unauthenticated",
  "invalid-argument",
  "rate-limited",
  "quota-exceeded",
  "unknown-device",
  "revoked-device",
  "unknown-command",
  "conflict",
  "authority-stale",
  "forbidden-device-class",
] as const satisfies readonly RelayErrorCode[]);

const fieldPattern = /^[a-z][a-zA-Z0-9.]{0,63}$/;

/** Parse `ConvexError.data` from the relay, or return null for anything
 * outside the closed vocabulary. */
export function parseRelayErrorData(value: unknown): RelayErrorData | null {
  if (value === null || typeof value !== "object") return null;
  const code = (value as { code?: unknown }).code;
  switch (code) {
    case "unauthenticated":
      return exactKeys(value, ["code"]) ? { code: "unauthenticated" } : null;
    case "authority-stale":
      return exactKeys(value, ["code"]) ? { code: "authority-stale" } : null;
    case "invalid-argument":
    case "conflict":
      return exactKeys(value, ["code", "field"])
        && typeof value.field === "string" && fieldPattern.test(value.field)
        ? { code, field: value.field }
        : null;
    case "rate-limited":
      return exactKeys(value, ["code", "bucket", "retryAfterMs"])
        && (RELAY_RATE_BUCKETS as readonly unknown[]).includes(value.bucket)
        && isSafeNonNegativeInteger(value.retryAfterMs) && value.retryAfterMs <= 86_400_000
        ? { code, bucket: value.bucket as RelayRateBucket, retryAfterMs: value.retryAfterMs }
        : null;
    case "quota-exceeded":
      return exactKeys(value, ["code", "quota"]) && (RELAY_QUOTAS as readonly unknown[]).includes(value.quota)
        ? { code, quota: value.quota as RelayQuota }
        : null;
    case "unknown-device":
    case "revoked-device":
    case "forbidden-device-class":
      return exactKeys(value, ["code", "device"]) && isDeviceId(value.device)
        ? { code, device: value.device }
        : null;
    case "unknown-command":
      return exactKeys(value, ["code", "command"]) && isPublicId(value.command)
        ? { code, command: value.command }
        : null;
    default:
      return null;
  }
}
