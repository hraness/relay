/** Key-envelope storage: how an enrolled device delivers the account key
 * to a newly activated one. The envelope is a signed key-wrap — the relay
 * validates shape and parties, never contents. One row per (recipient,
 * keyVersion); posting the same version again replaces it. */

import { mutationGeneric as mutation, queryGeneric as query } from "convex/server";
import { v } from "convex/values";

import { isKeyWrapEnvelope, type KeyWrapEnvelope } from "../wire/envelope";
import { isDeviceId } from "../wire/ids";
import { resolveRelayBounds, type RelayConfig } from "../wire/bounds";

import type { DeviceRow, KeyEnvelopeRow } from "./db";
import { relayMutationCtx, relayCtx } from "./db";
import { check, consumeRate, quotaExceeded, relayError, requireDevice, requireSubject } from "./policy";

const keyWrapArg = v.object({
  contract: v.string(),
  sender: v.string(),
  recipient: v.string(),
  keyVersion: v.number(),
  iv: v.string(),
  wrapped: v.string(),
  signature: v.string(),
});

export function relayEnvelopesBackend(config: RelayConfig) {
  const bounds = resolveRelayBounds(config);

  const postKeyEnvelope = mutation({
    args: { envelope: keyWrapArg },
    handler: async (rawCtx, args) => {
      const ctx = relayMutationCtx(rawCtx);
      const authority = await requireDevice(ctx);
      await consumeRate(ctx, config, authority.userId, "devices", 1);
      if (!isKeyWrapEnvelope(args.envelope)) {
        throw relayError({ code: "invalid-argument", field: "envelope" });
      }
      const envelope = args.envelope as KeyWrapEnvelope;
      // The sender is always the bound device; a device can never post a
      // wrap that claims another sender.
      if (envelope.sender !== authority.device.deviceId) {
        throw relayError({ code: "invalid-argument", field: "envelope.sender" });
      }
      const recipient = await ctx.db
        .query<DeviceRow>("relayDevices")
        .withIndex("by_user_and_device_id", (q) => q.eq("userId", authority.userId).eq("deviceId", envelope.recipient))
        .unique();
      if (recipient === null) throw relayError({ code: "unknown-device", device: envelope.recipient });
      if (recipient.status !== "active" || recipient.authEpoch !== authority.subject.authEpoch) {
        throw relayError({ code: "revoked-device", device: envelope.recipient });
      }
      const existing = await ctx.db
        .query<KeyEnvelopeRow>("relayKeyEnvelopes")
        .withIndex("by_device_and_version", (q) => q.eq("deviceId", recipient._id).eq("envelope.keyVersion", envelope.keyVersion))
        .take(bounds.keyEnvelopesPerRecipient + 1);
      const now = Date.now();
      for (const row of existing) await ctx.db.delete(row._id);
      const count = await ctx.db
        .query<KeyEnvelopeRow>("relayKeyEnvelopes")
        .withIndex("by_device_and_version", (q) => q.eq("deviceId", recipient._id))
        .take(bounds.keyEnvelopesPerRecipient + 1);
      if (count.length >= bounds.keyEnvelopesPerRecipient) throw quotaExceeded("key-envelopes");
      await ctx.db.insert("relayKeyEnvelopes", {
        createdAt: now,
        deviceId: recipient._id,
        envelope,
        userId: authority.userId,
      });
      return { delivered: true };
    },
  });

  /** Key envelopes addressed to the bound device. A newly enrolled device
   * calls this once to collect its account-key wraps. */
  const myKeyEnvelopes = query({
    args: {},
    handler: async (rawCtx) => {
      const ctx = relayCtx(rawCtx);
      const authority = await requireDevice(ctx);
      const rows = await ctx.db
        .query<KeyEnvelopeRow>("relayKeyEnvelopes")
        .withIndex("by_device_and_version", (q) => q.eq("deviceId", authority.deviceId))
        .take(bounds.keyEnvelopesPerRecipient);
      return rows.map((row) => row.envelope);
    },
  });

  const dropKeyEnvelope = mutation({
    args: { envelope: keyWrapArg },
    handler: async (rawCtx, args) => {
      const ctx = relayMutationCtx(rawCtx);
      const authority = await requireDevice(ctx);
      const envelope = args.envelope;
      const recipient = await ctx.db
        .query<DeviceRow>("relayDevices")
        .withIndex("by_user_and_device_id", (q) => q.eq("userId", authority.userId).eq("deviceId", envelope.recipient))
        .unique();
      if (recipient === null) return null;
      const rows = await ctx.db
        .query<KeyEnvelopeRow>("relayKeyEnvelopes")
        .withIndex("by_device_and_version", (q) => q.eq("deviceId", recipient._id).eq("envelope.keyVersion", envelope.keyVersion))
        .take(bounds.keyEnvelopesPerRecipient);
      // Either the sender or the recipient may drop the wrap.
      const isParty = envelope.sender === authority.device.deviceId || envelope.recipient === authority.device.deviceId;
      check(isParty, "envelope");
      for (const row of rows) {
        if (row.envelope.signature === envelope.signature) await ctx.db.delete(row._id);
      }
      return null;
    },
  });

  return { dropKeyEnvelope, myKeyEnvelopes, postKeyEnvelope };
}
