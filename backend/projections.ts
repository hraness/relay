/** Encrypted projections: one current signed envelope per (device, scope).
 * The publisher is always the bound device itself, the envelope's `sender`
 * must equal it, and `recipient` is `account` — projections are fleet-
 * visible to every enrolled device that holds the account key.
 *
 * Revisions fence stale writes: a caller presents `expectedRevision`, and
 * a mismatch is a conflict, not a silent overwrite. */

import { mutationGeneric as mutation, queryGeneric as query } from "convex/server";
import { v } from "convex/values";

import { isSignedEnvelope, type SignedEnvelope } from "../wire/envelope";
import { isDeviceId, isPublicId, isRelayName } from "../wire/ids";
import { isSafeNonNegativeInteger } from "../wire/encoding";
import { encodeHex } from "../wire/encoding";
import { resolveRelayBounds, type RelayConfig } from "../wire/bounds";
import { randomBytes } from "../crypto/primitives";

import type { DeviceRow, ProjectionRow, Row, RowId } from "./db";
import { relayMutationCtx, relayCtx } from "./db";
import { check, consumeRate, quotaExceeded, relayError, requireDevice, requireSubject } from "./policy";

const signedEnvelopeArg = v.object({
  contract: v.string(),
  sender: v.string(),
  recipient: v.string(),
  scope: v.string(),
  keyVersion: v.number(),
  iv: v.string(),
  ciphertext: v.string(),
  signature: v.string(),
});

export type ProjectionView = Readonly<{
  deviceId: string;
  envelope: SignedEnvelope;
  publicId: string;
  revision: number;
  scope: string;
  updatedAt: number;
}>;

function viewOf(row: Row<ProjectionRow>, device: Row<DeviceRow> | null): ProjectionView {
  return {
    deviceId: device?.deviceId ?? "",
    envelope: row.envelope,
    publicId: row.publicId,
    revision: row.revision,
    scope: row.scope,
    updatedAt: row.updatedAt,
  };
}

export function relayProjectionsBackend(config: RelayConfig) {
  const bounds = resolveRelayBounds(config);

  const publish = mutation({
    args: {
      deviceId: v.string(),
      envelope: signedEnvelopeArg,
      expectedRevision: v.number(),
      scope: v.string(),
    },
    handler: async (rawCtx, args) => {
      const ctx = relayMutationCtx(rawCtx);
      const authority = await requireDevice(ctx);
      await consumeRate(ctx, config, authority.userId, "sync", 1);
      check(args.deviceId === authority.device.deviceId, "deviceId");
      check(isRelayName(args.scope), "scope");
      check(isSafeNonNegativeInteger(args.expectedRevision), "expectedRevision");
      if (!isSignedEnvelope(args.envelope, bounds.ciphertextChars)) {
        throw relayError({ code: "invalid-argument", field: "envelope" });
      }
      // The envelope must be exactly the one this device claims: signed by
      // the bound device, addressed to the account, and named by the scope
      // argument so the row's index and the signed content can't diverge.
      if (
        args.envelope.sender !== authority.device.deviceId
        || args.envelope.recipient !== "account"
        || args.envelope.scope !== args.scope
        || args.envelope.keyVersion !== authority.device.keyVersion
      ) throw relayError({ code: "invalid-argument", field: "envelope.parties" });

      const existing = await ctx.db
        .query<ProjectionRow>("relayProjections")
        .withIndex("by_device_and_scope", (q) => q.eq("deviceId", authority.deviceId).eq("scope", args.scope))
        .unique();
      const now = Date.now();
      if (existing !== null) {
        if (existing.revision !== args.expectedRevision) {
          throw relayError({ code: "conflict", field: "expectedRevision" });
        }
        await ctx.db.patch(existing._id, {
          envelope: args.envelope,
          revision: existing.revision + 1,
          updatedAt: now,
        } as Partial<ProjectionRow>);
        return { publicId: existing.publicId, revision: existing.revision + 1, scope: args.scope };
      }
      if (args.expectedRevision !== 0) throw relayError({ code: "conflict", field: "expectedRevision" });
      const scopes = await ctx.db
        .query<ProjectionRow>("relayProjections")
        .withIndex("by_device_and_scope", (q) => q.eq("deviceId", authority.deviceId))
        .take(bounds.projectionScopesPerDevice + 1);
      if (scopes.length >= bounds.projectionScopesPerDevice) throw quotaExceeded("projection-scopes");
      const publicId = encodeHex(randomBytes(16));
      await ctx.db.insert("relayProjections", {
        deviceId: authority.deviceId,
        envelope: args.envelope,
        publicId,
        revision: 1,
        scope: args.scope,
        updatedAt: now,
        userId: authority.userId,
      });
      return { publicId, revision: 1, scope: args.scope };
    },
  });

  const remove = mutation({
    args: { deviceId: v.string(), scope: v.string() },
    handler: async (rawCtx, args) => {
      const ctx = relayMutationCtx(rawCtx);
      const authority = await requireDevice(ctx);
      check(args.deviceId === authority.device.deviceId, "deviceId");
      const existing = await ctx.db
        .query<ProjectionRow>("relayProjections")
        .withIndex("by_device_and_scope", (q) => q.eq("deviceId", authority.deviceId).eq("scope", args.scope))
        .unique();
      if (existing !== null) await ctx.db.delete(existing._id);
      return null;
    },
  });

  const get = query({
    args: { deviceId: v.string(), scope: v.string() },
    handler: async (rawCtx, args) => {
      const ctx = relayCtx(rawCtx);
      const subject = await requireSubject(ctx);
      check(isDeviceId(args.deviceId), "deviceId");
      const device = await ctx.db
        .query<DeviceRow>("relayDevices")
        .withIndex("by_user_and_device_id", (q) => q.eq("userId", subject.userId).eq("deviceId", args.deviceId))
        .unique();
      if (device === null) throw relayError({ code: "unknown-device", device: args.deviceId });
      const row = await ctx.db
        .query<ProjectionRow>("relayProjections")
        .withIndex("by_device_and_scope", (q) => q.eq("deviceId", device._id).eq("scope", args.scope))
        .unique();
      return row === null ? null : viewOf(row, device);
    },
  });

  const list = query({
    args: { deviceId: v.optional(v.string()) },
    handler: async (rawCtx, args) => {
      const ctx = relayCtx(rawCtx);
      const subject = await requireSubject(ctx);
      const rows = args.deviceId === undefined
        ? await ctx.db
          .query<ProjectionRow>("relayProjections")
          .withIndex("by_user", (q) => q.eq("userId", subject.userId))
          .take(bounds.projectionScopesPerDevice * bounds.activeDevicesPerUser)
        : await (async () => {
          check(isDeviceId(args.deviceId), "deviceId");
          const device = await ctx.db
            .query<DeviceRow>("relayDevices")
            .withIndex("by_user_and_device_id", (q) => q.eq("userId", subject.userId).eq("deviceId", args.deviceId!))
            .unique();
          if (device === null) throw relayError({ code: "unknown-device", device: args.deviceId! });
          return await ctx.db
            .query<ProjectionRow>("relayProjections")
            .withIndex("by_device_and_scope", (q) => q.eq("deviceId", device._id))
            .take(bounds.projectionScopesPerDevice);
        })();
      const devices = new Map<RowId, Row<DeviceRow>>();
      const views: ProjectionView[] = [];
      for (const row of rows) {
        let device = devices.get(row.deviceId);
        if (device === undefined) {
          const found = await ctx.db.get<DeviceRow>(row.deviceId);
          if (found !== null) devices.set(row.deviceId, found);
          device = found ?? undefined;
        }
        views.push(viewOf(row, device ?? null));
      }
      return views;
    },
  });

  return { get, list, publish, remove };
}
