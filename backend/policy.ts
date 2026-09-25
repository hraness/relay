/** Shared backend policy: typed errors, the caller's auth subject and
 * bound device, per-user token buckets, and quota ceilings. Every public
 * function calls `requireSubject` or `requireDevice` first and scopes
 * every read and write to its result. */

import { getAuthSessionId, getAuthUserId } from "@convex-dev/auth/server";
import { ConvexError } from "convex/values";

import type { RelayRateBucket, RelayBounds, RelayRateLimits, RelayConfig } from "../wire/bounds";
import { resolveRateLimits } from "../wire/bounds";
import type { RelayErrorData, RelayQuota } from "../wire/errors";
import { isDeviceId } from "../wire/ids";

import type {
  AuthSubjectRow,
  DeviceRow,
  DeviceSessionRow,
  RateLimitRow,
  RelayMutationCtx,
  RelayQueryCtx,
  Row,
  RowId,
} from "./db";

export function relayError(data: RelayErrorData): ConvexError<RelayErrorData> {
  return new ConvexError(data);
}

/** Reject a malformed argument. `field` names the argument path only. */
export function check(condition: boolean, field: string): asserts condition {
  if (!condition) throw relayError({ code: "invalid-argument", field });
}

export function quotaExceeded(quota: RelayQuota): ConvexError<RelayErrorData> {
  return relayError({ code: "quota-exceeded", quota });
}

// Identity ----------------------------------------------------------------------

/** The Convex Auth identity of the caller, or null. The library has
 * already validated the session JWT; user and session ids come from the
 * auth provider's claims. */
async function authIdentity(ctx: RelayQueryCtx): Promise<{ userId: RowId; sessionId: RowId } | null> {
  const [userId, sessionId] = await Promise.all([
    getAuthUserId(ctx as never),
    getAuthSessionId(ctx as never),
  ]);
  if (userId === null || sessionId === null) return null;
  return { userId: userId as unknown as RowId, sessionId: sessionId as unknown as RowId };
}

export type SubjectAuthority = Readonly<{
  authSessionId: RowId;
  subject: Row<AuthSubjectRow>;
  userId: RowId;
}>;

/** The caller's verified subject. Session expiry is enforced by Convex
 * Auth; here we require that the session's user has exactly one active
 * subject row. */
export async function requireSubject(ctx: RelayQueryCtx): Promise<SubjectAuthority> {
  const identity = await authIdentity(ctx);
  if (identity === null) throw relayError({ code: "unauthenticated" });
  const subjects = await ctx.db
    .query<AuthSubjectRow>("relaySubjects")
    .withIndex("by_user", (q) => q.eq("userId", identity.userId))
    .take(2);
  const subject = subjects[0];
  if (subjects.length !== 1 || subject === undefined || subject.status !== "active") {
    throw relayError({ code: "unauthenticated" });
  }
  if (subject.userId !== identity.userId) throw relayError({ code: "unauthenticated" });
  return { authSessionId: identity.sessionId, subject, userId: identity.userId };
}

export type DeviceAuthority = SubjectAuthority & Readonly<{
  binding: Row<DeviceSessionRow>;
  device: Row<DeviceRow>;
  deviceId: RowId;
}>;

/** The caller's subject plus the device bound to this auth session: one
 * active device session, same user, same auth epoch, and an active device
 * row. */
export async function requireDevice(ctx: RelayQueryCtx): Promise<DeviceAuthority> {
  const authority = await requireSubject(ctx);
  const bindings = await ctx.db
    .query<DeviceSessionRow>("relayDeviceSessions")
    .withIndex("by_auth_session", (q) => q.eq("authSessionId", authority.authSessionId))
    .take(2);
  const binding = bindings[0];
  if (bindings.length !== 1 || binding === undefined) throw relayError({ code: "unauthenticated" });
  if (binding.revokedAt !== undefined || binding.userId !== authority.userId
    || binding.authEpoch !== authority.subject.authEpoch) {
    throw relayError({ code: "unauthenticated" });
  }
  const device = await ctx.db.get<DeviceRow>(binding.deviceId);
  if (device === null || device.userId !== authority.userId
    || device.authEpoch !== authority.subject.authEpoch
    || device.status !== "active") {
    throw relayError({ code: "unauthenticated" });
  }
  return { ...authority, binding, device, deviceId: device._id };
}

/** The executor class is the only device class that may claim commands. */
export async function requireExecutor(ctx: RelayQueryCtx, config: RelayConfig): Promise<DeviceAuthority> {
  const authority = await requireDevice(ctx);
  if (authority.device.deviceClass !== config.executorClass) {
    throw relayError({ code: "forbidden-device-class", device: authority.device.deviceId });
  }
  return authority;
}

export async function findDevice(ctx: RelayQueryCtx, userId: RowId, deviceId: string): Promise<Row<DeviceRow> | null> {
  return await ctx.db
    .query<DeviceRow>("relayDevices")
    .withIndex("by_user_and_device_id", (q) => q.eq("userId", userId).eq("deviceId", deviceId))
    .unique();
}

export async function requireActiveDevice(ctx: RelayQueryCtx, userId: RowId, deviceId: string): Promise<Row<DeviceRow>> {
  const device = await findDevice(ctx, userId, deviceId);
  if (device === null) throw relayError({ code: "unknown-device", device: deviceId });
  if (device.status === "revoked") throw relayError({ code: "revoked-device", device: deviceId });
  return device;
}

// Rate buckets ----------------------------------------------------------------------

/** Spend `units` from the user's bucket or throw `rate-limited`. Zero
 * units neither reads nor writes, so no-op repeats stay free. */
export async function consumeRate(ctx: RelayMutationCtx, config: RelayConfig, userId: RowId, bucket: RelayRateBucket, units: number): Promise<void> {
  if (units <= 0) return;
  const limits = resolveRateLimits(config);
  const { capacity, periodMs } = limits[bucket];
  const perMs = capacity / periodMs;
  const now = Date.now();
  const row = await ctx.db
    .query<RateLimitRow>("relayRateLimits")
    .withIndex("by_user_and_bucket", (q) => q.eq("userId", userId).eq("bucket", bucket))
    .unique();
  const available = row === null ? capacity : Math.min(capacity, row.tokens + Math.max(0, now - row.updatedAt) * perMs);
  if (available < units) {
    throw relayError({ code: "rate-limited", bucket, retryAfterMs: Math.min(periodMs, Math.ceil((units - available) / perMs)) });
  }
  if (row === null) await ctx.db.insert("relayRateLimits", { userId, bucket, tokens: available - units, updatedAt: now });
  else await ctx.db.patch(row._id, { tokens: available - units, updatedAt: now });
}

/** Check a batch's size before any per-item work. */
export function checkBatch(items: readonly unknown[], bounds: RelayBounds, field: string): void {
  check(items.length >= 1 && items.length <= bounds.batch, field);
}

export function isPageLimit(value: number, bounds: RelayBounds): boolean {
  return Number.isSafeInteger(value) && value >= 1 && value <= bounds.batch;
}

export function isDeviceIdChecked(value: unknown, field: string): asserts value is string {
  check(isDeviceId(value), field);
}
