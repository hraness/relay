/** Device registry: registration is a signed-challenge ceremony so a device
 * id (derived from its signing key) can never be bound to a different key.
 * Activation is self-service under a verified session — the account key
 * travels separately through key-wrap envelopes posted by an existing
 * device, so the relay never sees key material.

 * Presence is a freshness signal only: a device's revocation or a session's
 * death makes every write fail before presence is consulted. */

import { mutationGeneric as mutation, queryGeneric as query } from "convex/server";
import { v } from "convex/values";

import { decodeBase64Url, encodeBase64Url, isBase64Url } from "../wire/encoding";
import { isDeviceId, isDeviceLabel } from "../wire/ids";
import { resolveRelayBounds, type RelayConfig } from "../wire/bounds";
import { deviceIdOf } from "../crypto/device";
import { importP256SigningKey, randomBytes, verifyCanonical } from "../crypto/primitives";

import type { BindChallengeRow, DeviceRow, PresenceRow, Row } from "./db";
import { relayMutationCtx, relayCtx } from "./db";
import { check, consumeRate, quotaExceeded, relayError, requireDevice, requireSubject } from "./policy";

const BIND_CHALLENGE_TTL_MS = 5 * 60 * 1_000;
/** Rows the revocation drain touches per call; per-device live commands are
 * bounded well below this. */
const DRAIN_LIMIT = 512;

export function isDeviceClass(value: unknown): boolean {
  return typeof value === "string" && /^[a-z][a-z0-9-]{1,32}$/u.test(value);
}

function rejectDevice(): never {
  throw relayError({ code: "invalid-argument", field: "device" });
}

function newOpaqueId(): string {
  return encodeBase64Url(randomBytes(24));
}

export function relayDevicesBackend(config: RelayConfig) {
  const bounds = resolveRelayBounds(config);

  const register = mutation({
    args: {
      agreementPublicKey: v.string(),
      deviceClass: v.string(),
      deviceId: v.string(),
      label: v.string(),
      signingPublicKey: v.string(),
    },
    handler: async (rawCtx, args) => {
      const ctx = relayMutationCtx(rawCtx);
      const subject = await requireSubject(ctx);
      await consumeRate(ctx, config, subject.userId, "devices", 1);
      check(isDeviceId(args.deviceId), "deviceId");
      check(isDeviceClass(args.deviceClass) && config.deviceClasses.includes(args.deviceClass), "deviceClass");
      check(isDeviceLabel(args.label), "label");
      check(isBase64Url(args.signingPublicKey, 200), "signingPublicKey");
      check(isBase64Url(args.agreementPublicKey, 200), "agreementPublicKey");
      const signingSpki = decodeBase64Url(args.signingPublicKey, 200);
      const agreementSpki = decodeBase64Url(args.agreementPublicKey, 200);
      check(signingSpki !== null && agreementSpki !== null, "keys");
      if (await deviceIdOf(signingSpki) !== args.deviceId) rejectDevice();
      const existing = await ctx.db
        .query<DeviceRow>("relayDevices")
        .withIndex("by_user_and_device_id", (q) => q.eq("userId", subject.userId).eq("deviceId", args.deviceId))
        .unique();
      if (existing !== null) {
        if (existing.status !== "pending"
          || existing.signingPublicKey !== args.signingPublicKey
          || existing.agreementPublicKey !== args.agreementPublicKey
          || existing.deviceClass !== args.deviceClass) rejectDevice();
        return { deviceId: args.deviceId };
      }
      const enrolled = await ctx.db
        .query<DeviceRow>("relayDevices")
        .withIndex("by_user_and_status", (q) => q.eq("userId", subject.userId).eq("status", "revoked"))
        .take(bounds.devicesPerUser + 1);
      const live = await ctx.db
        .query<DeviceRow>("relayDevices")
        .withIndex("by_user_and_status", (q) => q.eq("userId", subject.userId).eq("status", "active"))
        .take(bounds.activeDevicesPerUser + 1);
      const pending = await ctx.db
        .query<DeviceRow>("relayDevices")
        .withIndex("by_user_and_status", (q) => q.eq("userId", subject.userId).eq("status", "pending"))
        .take(bounds.devicesPerUser + 1);
      if (enrolled.length + live.length + pending.length >= bounds.devicesPerUser) throw quotaExceeded("devices");
      if (live.length + pending.length >= bounds.activeDevicesPerUser) throw quotaExceeded("devices");
      const now = Date.now();
      await ctx.db.insert("relayDevices", {
        agreementPublicKey: args.agreementPublicKey,
        authEpoch: subject.subject.authEpoch,
        createdAt: now,
        deviceClass: args.deviceClass,
        deviceId: args.deviceId,
        keyVersion: 1,
        label: args.label,
        revision: 1,
        signingPublicKey: args.signingPublicKey,
        status: "pending",
        updatedAt: now,
        userId: subject.userId,
      });
      return { deviceId: args.deviceId };
    },
  });

  const beginBind = mutation({
    args: { deviceId: v.string() },
    handler: async (rawCtx, args) => {
      const ctx = relayMutationCtx(rawCtx);
      const subject = await requireSubject(ctx);
      await consumeRate(ctx, config, subject.userId, "auth", 1);
      check(isDeviceId(args.deviceId), "deviceId");
      const device = await ctx.db
        .query<DeviceRow>("relayDevices")
        .withIndex("by_user_and_device_id", (q) => q.eq("userId", subject.userId).eq("deviceId", args.deviceId))
        .unique();
      if (device === null || device.status !== "pending" || device.authEpoch !== subject.subject.authEpoch) rejectDevice();
      const challengeId = newOpaqueId();
      const nonce = encodeBase64Url(randomBytes(32));
      const now = Date.now();
      await ctx.db.insert("relayBindChallenges", {
        authSessionId: subject.authSessionId,
        challengeId,
        createdAt: now,
        deviceId: device._id,
        expiresAt: now + BIND_CHALLENGE_TTL_MS,
        nonce,
        userId: subject.userId,
      });
      return { challengeId, nonce };
    },
  });

  const finishBind = mutation({
    args: { challengeId: v.string(), deviceId: v.string(), signature: v.string() },
    handler: async (rawCtx, args) => {
      const ctx = relayMutationCtx(rawCtx);
      const subject = await requireSubject(ctx);
      await consumeRate(ctx, config, subject.userId, "auth", 1);
      check(isDeviceId(args.deviceId), "deviceId");
      check(isBase64Url(args.signature, 200), "signature");
      const challenges = await ctx.db
        .query<BindChallengeRow>("relayBindChallenges")
        .withIndex("by_challenge", (q) => q.eq("challengeId", args.challengeId))
        .take(2);
      const challenge = challenges[0];
      const now = Date.now();
      if (challenges.length !== 1 || challenge === undefined
        || challenge.userId !== subject.userId
        || challenge.authSessionId !== subject.authSessionId
        || challenge.consumedAt !== undefined
        || challenge.expiresAt <= now) rejectDevice();
      const device = await ctx.db.get<DeviceRow>(challenge.deviceId);
      if (device === null || device.userId !== subject.userId
        || device.status !== "pending"
        || device.deviceId !== args.deviceId
        || device.authEpoch !== subject.subject.authEpoch) rejectDevice();
      const verifyKey = await importP256SigningKey(decodeBase64Url(device.signingPublicKey, 200)!);
      const message = { challengeId: challenge.challengeId, contract: `${config.namespace}:device-bind`, nonce: challenge.nonce };
      const signature = decodeBase64Url(args.signature, 200);
      if (signature === null || !(await verifyCanonical(verifyKey, message, signature))) rejectDevice();
      await ctx.db.patch(device._id, { revision: device.revision + 1, status: "active", updatedAt: now });
      await ctx.db.patch(challenge._id, { consumedAt: now });
      await ctx.db.insert("relayDeviceSessions", {
        authEpoch: subject.subject.authEpoch,
        authSessionId: subject.authSessionId,
        boundAt: now,
        deviceId: device._id,
        userId: subject.userId,
      });
      return { deviceId: device.deviceId, keyVersion: device.keyVersion };
    },
  });

  const list = query({
    args: {},
    handler: async (rawCtx) => {
      const ctx = relayCtx(rawCtx);
      const subject = await requireSubject(ctx);
      const now = Date.now();
      const devices: Row<DeviceRow>[] = [];
      for (const status of ["active", "pending"] as const) {
        devices.push(...await ctx.db
          .query<DeviceRow>("relayDevices")
          .withIndex("by_user_and_status", (q) => q.eq("userId", subject.userId).eq("status", status))
          .take(bounds.devicesPerUser));
      }
      const presence = await ctx.db
        .query<PresenceRow>("relayPresence")
        .withIndex("by_user", (q) => q.eq("userId", subject.userId))
        .take(bounds.devicesPerUser + 1);
      const online = new Set(presence.filter((row) => row.presenceUntil > now).map((row) => row.deviceId));
      return devices.map((device) => ({
        deviceClass: device.deviceClass,
        deviceId: device.deviceId,
        keyVersion: device.keyVersion,
        label: device.label,
        online: online.has(device._id),
        status: device.status,
      }));
    },
  });

  const connect = mutation({
    args: { connectionId: v.string(), deviceId: v.string(), fingerprint: v.string() },
    handler: async (rawCtx, args) => {
      const ctx = relayMutationCtx(rawCtx);
      const authority = await requireDevice(ctx);
      check(isDeviceId(args.deviceId) && args.deviceId === authority.device.deviceId, "deviceId");
      check(args.connectionId.length >= 8 && args.connectionId.length <= 128, "connectionId");
      check(args.fingerprint.length >= 8 && args.fingerprint.length <= 128, "fingerprint");
      const now = Date.now();
      const rows = await ctx.db
        .query<PresenceRow>("relayPresence")
        .withIndex("by_device", (q) => q.eq("deviceId", authority.deviceId))
        .take(4);
      const existing = rows.find((row) => row.connectionId === args.connectionId);
      if (existing !== undefined) {
        await ctx.db.patch(existing._id, {
          authEpoch: authority.subject.authEpoch,
          fingerprint: args.fingerprint,
          observedAt: now,
          presenceUntil: now + bounds.presenceTtlMs,
        });
      } else {
        await ctx.db.insert("relayPresence", {
          authEpoch: authority.subject.authEpoch,
          connectionId: args.connectionId,
          connectionSequence: 1,
          deviceId: authority.deviceId,
          fingerprint: args.fingerprint,
          observedAt: now,
          presenceUntil: now + bounds.presenceTtlMs,
          userId: authority.userId,
        });
      }
      return { presenceUntil: now + bounds.presenceTtlMs };
    },
  });

  const heartbeat = mutation({
    args: { connectionId: v.string(), deviceId: v.string() },
    handler: async (rawCtx, args) => {
      const ctx = relayMutationCtx(rawCtx);
      const authority = await requireDevice(ctx);
      check(args.deviceId === authority.device.deviceId, "deviceId");
      const now = Date.now();
      const rows = await ctx.db
        .query<PresenceRow>("relayPresence")
        .withIndex("by_device", (q) => q.eq("deviceId", authority.deviceId))
        .take(4);
      const presence = rows.find((row) => row.connectionId === args.connectionId);
      if (presence === undefined || presence.presenceUntil <= now) rejectDevice();
      await ctx.db.patch(presence._id, {
        connectionSequence: presence.connectionSequence + 1,
        observedAt: now,
        presenceUntil: now + bounds.presenceTtlMs,
      });
      return { presenceUntil: now + bounds.presenceTtlMs };
    },
  });

  const disconnect = mutation({
    args: { connectionId: v.string(), deviceId: v.string() },
    handler: async (rawCtx, args) => {
      const ctx = relayMutationCtx(rawCtx);
      const authority = await requireDevice(ctx);
      check(args.deviceId === authority.device.deviceId, "deviceId");
      const rows = await ctx.db
        .query<PresenceRow>("relayPresence")
        .withIndex("by_device", (q) => q.eq("deviceId", authority.deviceId))
        .take(8);
      for (const row of rows) {
        if (row.connectionId === args.connectionId) await ctx.db.delete(row._id);
      }
      return null;
    },
  });

  const revoke = mutation({
    args: { deviceId: v.string() },
    handler: async (rawCtx, args) => {
      const ctx = relayMutationCtx(rawCtx);
      const subject = await requireSubject(ctx);
      await consumeRate(ctx, config, subject.userId, "devices", 1);
      const device = await ctx.db
        .query<DeviceRow>("relayDevices")
        .withIndex("by_user_and_device_id", (q) => q.eq("userId", subject.userId).eq("deviceId", args.deviceId))
        .unique();
      if (device === null) rejectDevice();
      if (device.status === "revoked") return null;
      const now = Date.now();
      await ctx.db.patch(device._id, { revision: device.revision + 1, revokedAt: now, status: "revoked", updatedAt: now });
      for (const [table, index, field] of [
        ["relayPresence", "by_device", "deviceId"],
        ["relayDeviceSessions", "by_device", "deviceId"],
        ["relayBindChallenges", "by_device", "deviceId"],
        ["relayKeyEnvelopes", "by_device_and_version", "deviceId"],
        ["relayProjections", "by_device_and_scope", "deviceId"],
      ] as const) {
        const rows = await ctx.db
          .query<{ _id: unknown }>(table)
          .withIndex(index, (q) => q.eq(field, device._id))
          .take(DRAIN_LIMIT);
        for (const row of rows) await ctx.db.delete(row._id as never);
      }
      // Drain the revoked device's command lane: pending and prepared
      // commands expire; anything that may have started goes ambiguous —
      // never applied.
      for (const [state, result] of [
        ["pending", "expired"],
        ["prepared", "ambiguous"],
        ["effect_started", "ambiguous"],
      ] as const) {
        const rows = await ctx.db
          .query<{ _id: unknown }>("relayCommands")
          .withIndex("by_target_state_and_created_at", (q) => q.eq("targetDeviceId", device._id).eq("state", state))
          .take(DRAIN_LIMIT);
        for (const row of rows) {
          await ctx.db.patch(row._id as never, {
            nonterminal: false,
            resultCode: `revoked-${result}`,
            state: result,
            updatedAt: now,
          } as never);
        }
      }
      await ctx.db.insert("relaySecurityEvents", {
        actorDeviceId: undefined,
        createdAt: now,
        entityId: device.deviceId,
        event: "device-revoked",
        userId: subject.userId,
      });
      return null;
    },
  });

  return { beginBind, connect, disconnect, finishBind, heartbeat, list, register, revoke };
}
