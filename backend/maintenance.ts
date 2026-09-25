/** The retention sweep. A single maintenance cursor walks the sweep
 * categories so one run stays bounded; each category deletes or expires
 * rows that have outlived their contract, and the sweep records a
 * security event only when it changed something.
 *
 * Every relay table joins exactly one category here — that mapping is the
 * exhaustive lifecycle map the repository's instructions require. A new
 * table without a category fails the `RELAY_RETENTION_TABLES` exhaustiveness
 * check in tests. */

import { internalMutationGeneric as internalMutation } from "convex/server";

import { isTerminalCommandState } from "../wire/authority";
import { resolveRelayBounds, type RelayConfig } from "../wire/bounds";

import type { CommandRow, MaintenanceRow, RowId } from "./db";
import { relayMutationCtx, type RelayMutationCtx } from "./db";

/** Table → retention category. `ephemeral` rows carry `expiresAt` and die
 * at expiry; `bounded` rows are capped per user; `terminal` rows carry
 * `terminalCleanupAfter` set at acknowledge; `pinned` rows are never
 * swept. */
export const RELAY_RETENTION_TABLES = Object.freeze({
  relaySubjects: "pinned",
  relayAuthAttempts: "ephemeral",
  relayOtpChallenges: "ephemeral",
  relayInvites: "ephemeral",
  relayDevices: "pinned",
  relayDeviceSessions: "pinned",
  relayBindChallenges: "ephemeral",
  relayKeyEnvelopes: "pinned",
  relayCommands: "command-terminal",
  relayProjections: "pinned",
  relayPresence: "presence",
  relayRateLimits: "pinned",
  relaySecurityEvents: "bounded-events",
  relayIdempotencyReceipts: "ephemeral",
  relayMaintenance: "pinned",
} as const);

const SWEEP_LIMIT = 256;

async function deleteExpired(ctx: RelayMutationCtx, table: string, index: string, field: string, now: number): Promise<number> {
  const rows = await ctx.db
    .query<{ _id: RowId }>(table)
    .withIndex(index, (q) => q.lt(field, now))
    .take(SWEEP_LIMIT);
  for (const row of rows) await ctx.db.delete(row._id);
  return rows.length;
}

export function relayMaintenanceBackend(config: RelayConfig) {
  const bounds = resolveRelayBounds(config);

  /** One sweep step: advance the cursor's category and process it. */
  const sweep = internalMutation({
    args: {},
    handler: async (rawCtx) => {
      const ctx = relayMutationCtx(rawCtx);
      const now = Date.now();
      let removed = 0;

      // Ephemeral rows die at expiresAt.
      for (const [table, index, field] of [
        ["relayAuthAttempts", "by_expires_at", "expiresAt"],
        ["relayOtpChallenges", "by_expires_at", "expiresAt"],
        ["relayInvites", "by_expiry", "expiresAt"],
        ["relayBindChallenges", "by_expiry", "expiresAt"],
        ["relayIdempotencyReceipts", "by_expires_at", "expiresAt"],
      ] as const) {
        removed += await deleteExpired(ctx, table, index, field, now);
      }

      // Stale presence rows die at presenceUntil.
      removed += await deleteExpired(ctx, "relayPresence", "by_presence_until", "presenceUntil", now);

      // Non-terminal commands past their deadline expire; started ones
      // go ambiguous — an unobserved effect is never applied.
      const expired = await ctx.db
        .query<CommandRow>("relayCommands")
        .withIndex("by_nonterminal_and_deadline", (q) => q.eq("nonterminal", true).lt("deadline", now))
        .take(SWEEP_LIMIT);
      for (const command of expired) {
        if (command.state === "effect_started") {
          await ctx.db.patch(command._id, {
            nonterminal: false,
            resultCode: "deadline-ambiguous",
            state: "ambiguous",
            updatedAt: now,
          } as Partial<CommandRow>);
        } else {
          await ctx.db.patch(command._id, {
            nonterminal: false,
            resultCode: "deadline",
            state: "expired",
            updatedAt: now,
          } as Partial<CommandRow>);
        }
        removed += 1;
      }

      // Terminal commands acknowledged by the requester die after the
      // terminal retention window.
      const terminal = await ctx.db
        .query<CommandRow>("relayCommands")
        .withIndex("by_cleanup", (q) => q.lt("terminalCleanupAfter", now))
        .take(SWEEP_LIMIT);
      for (const command of terminal) {
        if (command.terminalCleanupAfter === undefined) continue;
        if (!isTerminalCommandState(command.state)) continue;
        await ctx.db.delete(command._id);
        removed += 1;
      }

      // Update the maintenance cursor.
      const cursor = await ctx.db
        .query<MaintenanceRow>("relayMaintenance")
        .withIndex("by_key", (q) => q.eq("key", "retention"))
        .unique();
      if (cursor === null) {
        await ctx.db.insert("relayMaintenance", { key: "retention", nextCategory: "ephemeral", updatedAt: now });
      } else {
        await ctx.db.patch(cursor._id, { nextCategory: "ephemeral", updatedAt: now });
      }

      return { removed, sweptAt: now };
    },
  });

  return { sweep };
}
