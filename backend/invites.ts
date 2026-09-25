/** Capability-bound invites. An `identity` invite admits a new email
 * subject when open sign-up is closed: the invite token (returned once, in
 * plaintext, to the issuing device) is what the new subject presents at
 * `request_code`. The relay stores only its digest. */

import { mutationGeneric as mutation, queryGeneric as query } from "convex/server";
import { v } from "convex/values";

import { encodeBase64Url } from "../wire/encoding";
import { isEmailAddress } from "../wire/ids";
import { resolveRelayBounds, type RelayConfig } from "../wire/bounds";
import { randomBytes } from "../crypto/primitives";

import type { InviteRow } from "./db";
import { relayMutationCtx, relayCtx } from "./db";
import { check, consumeRate, quotaExceeded, relayError, requireSubject } from "./policy";
import { digestAuthEmail, digestInviteCapability } from "./auth";

const LIVE_INVITE_LIMIT = 32;

export function relayInvitesBackend(config: RelayConfig) {
  const bounds = resolveRelayBounds(config);

  const issue = mutation({
    args: {
      boundEmail: v.optional(v.string()),
      purpose: v.union(v.literal("identity"), v.literal("device")),
    },
    handler: async (rawCtx, args) => {
      const ctx = relayMutationCtx(rawCtx);
      const subject = await requireSubject(ctx);
      await consumeRate(ctx, config, subject.userId, "auth", 1);
      let boundEmailDigest: string | undefined;
      if (args.boundEmail !== undefined) {
        check(isEmailAddress(args.boundEmail), "boundEmail");
        boundEmailDigest = await digestAuthEmail(config.namespace, args.boundEmail);
      }
      const live = await ctx.db
        .query<InviteRow>("relayInvites")
        .withIndex("by_user", (q) => q.eq("issuedByUserId", subject.userId))
        .take(LIVE_INVITE_LIMIT + 1);
      const now = Date.now();
      const liveCount = live.filter((row) => row.state === "issued" && row.expiresAt > now && row.revokedAt === undefined).length;
      if (liveCount >= LIVE_INVITE_LIMIT) throw quotaExceeded("devices");
      const token = encodeBase64Url(randomBytes(32));
      await ctx.db.insert("relayInvites", {
        ...(boundEmailDigest !== undefined ? { boundEmailDigest } : {}),
        capabilityDigest: await digestInviteCapability(config.namespace, token),
        createdAt: now,
        expiresAt: now + bounds.inviteLifetimeMs,
        issuedByUserId: subject.userId,
        publicId: encodeBase64Url(randomBytes(12)),
        purpose: args.purpose,
        state: "issued",
        updatedAt: now,
      });
      return { expiresAt: now + bounds.inviteLifetimeMs, token };
    },
  });

  const list = query({
    args: {},
    handler: async (rawCtx) => {
      const ctx = relayCtx(rawCtx);
      const subject = await requireSubject(ctx);
      const now = Date.now();
      const rows = await ctx.db
        .query<InviteRow>("relayInvites")
        .withIndex("by_user", (q) => q.eq("issuedByUserId", subject.userId))
        .take(LIVE_INVITE_LIMIT);
      return rows
        .filter((row) => row.expiresAt > now)
        .map((row) => ({
          expiresAt: row.expiresAt,
          publicId: row.publicId,
          purpose: row.purpose,
          state: row.revokedAt !== undefined ? "revoked" : row.state,
        }));
    },
  });

  const revoke = mutation({
    args: { publicId: v.string() },
    handler: async (rawCtx, args) => {
      const ctx = relayMutationCtx(rawCtx);
      const subject = await requireSubject(ctx);
      const rows = await ctx.db
        .query<InviteRow>("relayInvites")
        .withIndex("by_user", (q) => q.eq("issuedByUserId", subject.userId))
        .take(LIVE_INVITE_LIMIT + 1);
      const invite = rows.find((row) => row.publicId === args.publicId);
      if (invite === undefined) throw relayError({ code: "invalid-argument", field: "publicId" });
      if (invite.revokedAt === undefined && invite.state !== "consumed") {
        await ctx.db.patch(invite._id, { revokedAt: Date.now(), state: "revoked", updatedAt: Date.now() });
      }
      return null;
    },
  });

  return { issue, list, revoke };
}
