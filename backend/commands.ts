/** The device-command lifecycle. A requester (any active device, typically
 * a controller) enqueues an encrypted command addressed to an executor
 * device. The executor claims it under its boot authority, reports effect
 * start, and settles with an encrypted result. A strictly later authority
 * may reclaim a command that never started, and may only close a started
 * one as `ambiguous`.

 * Idempotency: (user, target, requester, kind, key) pins one command. A
 * replay with the same request digest returns the existing command; a
 * different digest under the same key is a conflict, never a second
 * effect. */

import { mutationGeneric as mutation, queryGeneric as query } from "convex/server";
import { v } from "convex/values";

import {
  commandTransitionDisposition,
  deviceCommandAuthorityTransitionDisposition,
  deviceCommandRecoveryAdmitted,
  deviceCommandRecoveryReplayAdmitted,
  isTerminalCommandState,
  parseAuthorityTuple,
  type AuthorityTuple,
  type CommandState,
} from "../wire/authority";
import { isSignedEnvelope, type SignedEnvelope } from "../wire/envelope";
import { isDigest, isDeviceId, isPublicId, isUuidV7, isWireKind, uuidV7Timestamp } from "../wire/ids";
import { encodeHex } from "../wire/encoding";
import { resolveRelayBounds, type RelayConfig } from "../wire/bounds";
import { randomBytes } from "../crypto/primitives";

import type { CommandRow, DeviceRow, Row, RowId } from "./db";
import { relayMutationCtx, relayCtx, type RelayMutationCtx } from "./db";
import {
  check,
  consumeRate,
  quotaExceeded,
  relayError,
  requireDevice,
  requireExecutor,
} from "./policy";

/** An idempotency key stays a valid replay reference for this long after
 * its embedded timestamp, matching the command lifetime bound. */
const FUTURE_SKEW_MS = 5 * 60 * 1_000;

const authorityArg = v.object({
  bootGeneration: v.number(),
  bootId: v.string(),
  fence: v.number(),
});

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

function newPublicId(): string {
  return encodeHex(randomBytes(16));
}

function rejectCommand(): never {
  throw relayError({ code: "invalid-argument", field: "command" });
}

export type CommandView = Readonly<{
  boundAuthority: AuthorityTuple | null;
  createdAt: number;
  deadline: number;
  kind: string;
  payload: SignedEnvelope;
  publicId: string;
  requestingDeviceId: string;
  result: SignedEnvelope | null;
  resultCode: string | null;
  state: CommandState;
  targetDeviceId: string;
  updatedAt: number;
}>;

function viewOf(command: Row<CommandRow>, target: Row<DeviceRow>, requester: Row<DeviceRow> | null): CommandView {
  return {
    boundAuthority: command.boundAuthority ?? null,
    createdAt: command.createdAt,
    deadline: command.deadline,
    kind: command.kind,
    payload: command.payload as SignedEnvelope,
    publicId: command.publicId,
    requestingDeviceId: requester?.deviceId ?? "",
    result: (command.result ?? null) as SignedEnvelope | null,
    resultCode: command.resultCode ?? null,
    state: command.state,
    targetDeviceId: target.deviceId,
    updatedAt: command.updatedAt,
  };
}

async function deviceByRowId(ctx: RelayMutationCtx | ReturnType<typeof relayCtx>, id: RowId): Promise<Row<DeviceRow> | null> {
  return await ctx.db.get<DeviceRow>(id);
}

/** The command row a wire `publicId` names, scoped to the caller's user —
 * an id from another account is indistinguishable from one that never
 * existed. */
async function commandByPublicId(ctx: RelayMutationCtx | ReturnType<typeof relayCtx>, userId: RowId, publicId: string) {
  const rows = await ctx.db
    .query<CommandRow>("relayCommands")
    .withIndex("by_public_id", (q) => q.eq("publicId", publicId))
    .take(2);
  const command = rows[0];
  if (command === undefined || rows.length !== 1 || command.userId !== userId) {
    throw relayError({ code: "unknown-command", command: publicId });
  }
  return command;
}

function checkAuthorityArg(value: unknown): asserts value is AuthorityTuple {
  if (parseAuthorityTuple(value) === null) throw relayError({ code: "invalid-argument", field: "authority" });
}

function checkEnvelopeArg(value: unknown, maxCiphertextChars: number): asserts value is SignedEnvelope {
  if (!isSignedEnvelope(value, maxCiphertextChars)) {
    throw relayError({ code: "invalid-argument", field: "envelope" });
  }
}

function applyTransition(ctx: RelayMutationCtx, command: Row<CommandRow>, next: CommandState, patch: Record<string, unknown>, now: number): Promise<void> {
  return ctx.db.patch(command._id, {
    ...patch,
    nonterminal: !isTerminalCommandState(next),
    state: next,
    updatedAt: now,
  } as Partial<CommandRow>);
}

export function relayCommandsBackend(config: RelayConfig) {
  const bounds = resolveRelayBounds(config);

  const enqueue = mutation({
    args: {
      deadlineMs: v.optional(v.number()),
      idempotencyKey: v.string(),
      kind: v.string(),
      payload: signedEnvelopeArg,
      requestDigest: v.string(),
      targetDeviceId: v.string(),
    },
    handler: async (rawCtx, args) => {
      const ctx = relayMutationCtx(rawCtx);
      const caller = await requireDevice(ctx);
      await consumeRate(ctx, config, caller.userId, "commands", 1);
      check(isDeviceId(args.targetDeviceId), "targetDeviceId");
      check(isWireKind(args.kind) && config.commandKinds.includes(args.kind), "kind");
      check(isUuidV7(args.idempotencyKey), "idempotencyKey");
      check(isDigest(args.requestDigest), "requestDigest");
      checkEnvelopeArg(args.payload, bounds.ciphertextChars);
      if (args.payload.sender !== caller.device.deviceId || args.payload.recipient !== args.targetDeviceId) {
        throw relayError({ code: "invalid-argument", field: "payload.parties" });
      }
      const now = Date.now();
      const keyTime = uuidV7Timestamp(args.idempotencyKey);
      check(keyTime !== null && keyTime <= now + FUTURE_SKEW_MS, "idempotencyKey");

      const target = await ctx.db
        .query<DeviceRow>("relayDevices")
        .withIndex("by_user_and_device_id", (q) => q.eq("userId", caller.userId).eq("deviceId", args.targetDeviceId))
        .unique();
      if (target === null) throw relayError({ code: "unknown-device", device: args.targetDeviceId });
      if (target.status === "revoked") throw relayError({ code: "revoked-device", device: args.targetDeviceId });
      if (target.status !== "active" || target.deviceClass !== config.executorClass || target.authEpoch !== caller.subject.authEpoch) {
        rejectCommand();
      }

      const existing = await ctx.db
        .query<CommandRow>("relayCommands")
        .withIndex("by_idempotency", (q) =>
          q.eq("userId", caller.userId)
            .eq("targetDeviceId", target._id)
            .eq("requestingDeviceId", caller.deviceId)
            .eq("kind", args.kind)
            .eq("idempotencyKey", args.idempotencyKey))
        .take(2);
      if (existing.length > 0) {
        const command = existing[0]!;
        if (command.requestDigest !== args.requestDigest) {
          throw relayError({ code: "conflict", field: "idempotencyKey" });
        }
        const requester = await deviceByRowId(ctx, command.requestingDeviceId);
        return { command: viewOf(command, target, requester), replayed: true };
      }

      const pending = await ctx.db
        .query<CommandRow>("relayCommands")
        .withIndex("by_target_nonterminal_and_created_at", (q) => q.eq("targetDeviceId", target._id).eq("nonterminal", true))
        .take(bounds.pendingCommandsPerDevice + 1);
      if (pending.length >= bounds.pendingCommandsPerDevice) throw quotaExceeded("pending-commands");

      const deadline = args.deadlineMs === undefined
        ? now + bounds.commandLifetimeMs
        : (check(Number.isSafeInteger(args.deadlineMs), "deadlineMs"),
          Math.min(args.deadlineMs, now + bounds.commandLifetimeMs));
      const commandId = await ctx.db.insert("relayCommands", {
        createdAt: now,
        deadline,
        idempotencyKey: args.idempotencyKey,
        kind: args.kind,
        nonterminal: true,
        payload: args.payload,
        publicId: newPublicId(),
        requestingDeviceId: caller.deviceId,
        requestDigest: args.requestDigest,
        state: "pending",
        targetDeviceId: target._id,
        updatedAt: now,
        userId: caller.userId,
      });
      const command = await ctx.db.get<CommandRow>(commandId);
      if (command === null) rejectCommand();
      return { command: viewOf(command, target, caller.device), replayed: false };
    },
  });

  const listForTarget = query({
    args: { deviceId: v.string(), limit: v.optional(v.number()) },
    handler: async (rawCtx, args) => {
      const ctx = relayCtx(rawCtx);
      const authority = await requireDevice(ctx);
      check(args.deviceId === authority.device.deviceId, "deviceId");
      const limit = Math.min(args.limit ?? bounds.batch, bounds.batch);
      const rows = await ctx.db
        .query<CommandRow>("relayCommands")
        .withIndex("by_target_nonterminal_and_created_at", (q) => q.eq("targetDeviceId", authority.deviceId).eq("nonterminal", true))
        .take(limit);
      const requesters = new Map<RowId, string>();
      const views: CommandView[] = [];
      for (const row of rows) {
        let requesterId = requesters.get(row.requestingDeviceId);
        if (requesterId === undefined) {
          const requester = await deviceByRowId(ctx, row.requestingDeviceId);
          requesterId = requester?.deviceId ?? "";
          requesters.set(row.requestingDeviceId, requesterId);
        }
        views.push({ ...viewOf(row, authority.device, null), requestingDeviceId: requesterId });
      }
      return views;
    },
  });

  const claim = mutation({
    args: {
      authority: authorityArg,
      deviceId: v.string(),
      publicId: v.string(),
    },
    handler: async (rawCtx, args) => {
      const ctx = relayMutationCtx(rawCtx);
      const executor = await requireExecutor(ctx, config);
      check(args.deviceId === executor.device.deviceId, "deviceId");
      check(isPublicId(args.publicId), "publicId");
      checkAuthorityArg(args.authority);
      const command = await commandByPublicId(ctx, executor.userId, args.publicId);
      if (command.targetDeviceId !== executor.deviceId) rejectCommand();
      const now = Date.now();
      if (command.deadline <= now && command.state !== "effect_started") {
        const disposition = commandTransitionDisposition(command.state, "expired");
        if (disposition.kind === "applied") {
          await applyTransition(ctx, command, "expired", { resultCode: "deadline" }, now);
        }
        return {
          command: { publicId: command.publicId, state: "expired" },
          outcome: "expired",
        };
      }
      if (command.deadline <= now) {
        return { command: { publicId: command.publicId, state: command.state }, outcome: "started-past-deadline" };
      }
      const disposition = deviceCommandAuthorityTransitionDisposition({
        boundAuthority: command.boundAuthority ?? null,
        next: "prepared",
        requestedAuthority: args.authority,
        state: command.state,
      });
      if (disposition.kind === "rejected") {
        throw relayError(
          disposition.reason === "stale_authority"
            ? { code: "authority-stale" }
            : { code: "conflict", field: `command.${disposition.reason}` },
        );
      }
      if (disposition.kind === "applied" || disposition.kind === "rebound") {
        await applyTransition(ctx, command, "prepared", { boundAuthority: disposition.boundAuthority }, now);
      }
      return {
        command: {
          boundAuthority: disposition.boundAuthority,
          publicId: command.publicId,
          state: "prepared",
        },
        outcome: disposition.kind === "rebound" ? "rebound" : disposition.kind,
      };
    },
  });

  const markEffectStarted = mutation({
    args: {
      authority: authorityArg,
      deviceId: v.string(),
      publicId: v.string(),
    },
    handler: async (rawCtx, args) => {
      const ctx = relayMutationCtx(rawCtx);
      const executor = await requireExecutor(ctx, config);
      check(args.deviceId === executor.device.deviceId, "deviceId");
      checkAuthorityArg(args.authority);
      const command = await commandByPublicId(ctx, executor.userId, args.publicId);
      if (command.targetDeviceId !== executor.deviceId) rejectCommand();
      const disposition = deviceCommandAuthorityTransitionDisposition({
        boundAuthority: command.boundAuthority ?? null,
        next: "effect_started",
        requestedAuthority: args.authority,
        state: command.state,
      });
      if (disposition.kind === "rejected") {
        throw relayError(
          disposition.reason === "stale_authority" || disposition.reason === "bound_authority"
            ? { code: "authority-stale" }
            : { code: "conflict", field: "command.transition" },
        );
      }
      const now = Date.now();
      if (disposition.kind === "applied") {
        await applyTransition(ctx, command, "effect_started", {}, now);
      }
      return { publicId: command.publicId, state: "effect_started" };
    },
  });

  const settle = mutation({
    args: {
      authority: authorityArg,
      deviceId: v.string(),
      publicId: v.string(),
      result: signedEnvelopeArg,
      resultCode: v.string(),
      resultDigest: v.string(),
      state: v.union(v.literal("applied"), v.literal("failed")),
    },
    handler: async (rawCtx, args) => {
      const ctx = relayMutationCtx(rawCtx);
      const executor = await requireExecutor(ctx, config);
      check(args.deviceId === executor.device.deviceId, "deviceId");
      checkAuthorityArg(args.authority);
      checkEnvelopeArg(args.result, bounds.ciphertextChars);
      check(/^[a-z][a-z0-9_.-]{0,63}$/u.test(args.resultCode), "resultCode");
      check(isDigest(args.resultDigest), "resultDigest");
      const command = await commandByPublicId(ctx, executor.userId, args.publicId);
      if (command.targetDeviceId !== executor.deviceId) rejectCommand();
      const disposition = deviceCommandAuthorityTransitionDisposition({
        boundAuthority: command.boundAuthority ?? null,
        next: args.state,
        requestedAuthority: args.authority,
        state: command.state,
      });
      if (disposition.kind === "rejected") {
        throw relayError(
          disposition.reason === "stale_authority" || disposition.reason === "bound_authority"
            ? { code: "authority-stale" }
            : { code: "conflict", field: "command.transition" },
        );
      }
      if (disposition.kind === "replay") {
        // Same authority restating a terminal: only byte-identical results
        // replay, everything else is a conflict.
        if (command.resultCode !== args.resultCode || command.resultDigest !== args.resultDigest) {
          throw relayError({ code: "conflict", field: "command.result" });
        }
        return { publicId: command.publicId, state: command.state };
      }
      const now = Date.now();
      await applyTransition(ctx, command, args.state, {
        result: args.result,
        resultCode: args.resultCode,
        resultDigest: args.resultDigest,
      }, now);
      return { publicId: command.publicId, state: args.state };
    },
  });

  const recover = mutation({
    args: {
      authority: authorityArg,
      deviceId: v.string(),
      publicId: v.string(),
      result: v.optional(signedEnvelopeArg),
      resultCode: v.string(),
      resultDigest: v.optional(v.string()),
      state: v.union(v.literal("failed"), v.literal("ambiguous")),
    },
    handler: async (rawCtx, args) => {
      const ctx = relayMutationCtx(rawCtx);
      const executor = await requireExecutor(ctx, config);
      check(args.deviceId === executor.device.deviceId, "deviceId");
      checkAuthorityArg(args.authority);
      check(/^[a-z][a-z0-9_.-]{0,63}$/u.test(args.resultCode), "resultCode");
      if (args.result !== undefined) checkEnvelopeArg(args.result, bounds.ciphertextChars);
      if (args.resultDigest !== undefined) check(isDigest(args.resultDigest), "resultDigest");
      const command = await commandByPublicId(ctx, executor.userId, args.publicId);
      if (command.targetDeviceId !== executor.deviceId) rejectCommand();
      const staleAuthority = command.boundAuthority;
      if (staleAuthority === undefined) rejectCommand();
      const now = Date.now();
      // A replay of a recovery already committed returns the stored
      // terminal only when the presented result is byte-identical. The
      // authority that wrote the terminal is the recovery authority when
      // one is recorded, else the original binding.
      if (isTerminalCommandState(command.state)) {
        const writtenAuthority = command.recoveryAuthority ?? staleAuthority;
        if (
          deviceCommandRecoveryReplayAdmitted({
            boundAuthority: writtenAuthority,
            recoveryAuthority: args.authority,
            staleAuthority,
          })
          && command.resultCode === args.resultCode
          && (command.resultDigest ?? undefined) === args.resultDigest
        ) return { publicId: command.publicId, state: command.state };
        throw relayError({ code: "conflict", field: "command.state" });
      }
      if (!deviceCommandRecoveryAdmitted({
        recoveryAuthority: args.authority,
        staleAuthority,
        state: command.state,
        terminalState: args.state,
      })) {
        throw relayError({ code: "authority-stale" });
      }
      await applyTransition(ctx, command, args.state, {
        recoveryAuthority: args.authority,
        ...(args.result !== undefined ? { result: args.result } : {}),
        resultCode: args.resultCode,
        ...(args.resultDigest !== undefined ? { resultDigest: args.resultDigest } : {}),
      }, now);
      return { publicId: command.publicId, state: args.state };
    },
  });

  const cancel = mutation({
    args: { deviceId: v.string(), publicId: v.string() },
    handler: async (rawCtx, args) => {
      const ctx = relayMutationCtx(rawCtx);
      const caller = await requireDevice(ctx);
      check(isPublicId(args.publicId), "publicId");
      const command = await commandByPublicId(ctx, caller.userId, args.publicId);
      if (command.requestingDeviceId !== caller.deviceId) rejectCommand();
      const disposition = commandTransitionDisposition(command.state, "cancelled");
      if (disposition.kind === "rejected") {
        if (disposition.reason === "terminal") {
          return { publicId: command.publicId, state: command.state };
        }
        throw relayError({ code: "conflict", field: "command.state" });
      }
      const now = Date.now();
      await applyTransition(ctx, command, "cancelled", { resultCode: "requester-cancel" }, now);
      return { publicId: command.publicId, state: "cancelled" };
    },
  });

  const acknowledge = mutation({
    args: { deviceId: v.string(), publicId: v.string() },
    handler: async (rawCtx, args) => {
      const ctx = relayMutationCtx(rawCtx);
      const caller = await requireDevice(ctx);
      const command = await commandByPublicId(ctx, caller.userId, args.publicId);
      if (command.requestingDeviceId !== caller.deviceId) rejectCommand();
      if (!isTerminalCommandState(command.state)) rejectCommand();
      if (command.requesterAcknowledgedAt === undefined) {
        await ctx.db.patch(command._id, {
          requesterAcknowledgedAt: Date.now(),
          terminalCleanupAfter: Date.now() + bounds.terminalCommandRetentionMs,
        } as Partial<CommandRow>);
      }
      return { publicId: command.publicId, state: command.state };
    },
  });

  const get = query({
    args: { publicId: v.string() },
    handler: async (rawCtx, args) => {
      const ctx = relayCtx(rawCtx);
      const caller = await requireDevice(ctx);
      const command = await commandByPublicId(ctx, caller.userId, args.publicId);
      const target = await deviceByRowId(ctx, command.targetDeviceId);
      const requester = await deviceByRowId(ctx, command.requestingDeviceId);
      if (target === null) rejectCommand();
      return viewOf(command, target, requester);
    },
  });

  const listForRequester = query({
    args: { deviceId: v.string(), limit: v.optional(v.number()) },
    handler: async (rawCtx, args) => {
      const ctx = relayCtx(rawCtx);
      const caller = await requireDevice(ctx);
      check(args.deviceId === caller.device.deviceId, "deviceId");
      const limit = Math.min(args.limit ?? bounds.batch, bounds.batch);
      const rows = await ctx.db
        .query<CommandRow>("relayCommands")
        .withIndex("by_requesting_device_and_nonterminal", (q) => q.eq("requestingDeviceId", caller.deviceId))
        .take(limit + bounds.batch);
      const views: CommandView[] = [];
      for (const row of rows.filter((row) => row.nonterminal).slice(0, limit)) {
        const target = await deviceByRowId(ctx, row.targetDeviceId);
        if (target !== null) views.push(viewOf(row, target, caller.device));
      }
      return views;
    },
  });

  return {
    acknowledge,
    cancel,
    claim,
    enqueue,
    get,
    listForRequester,
    listForTarget,
    markEffectStarted,
    recover,
    settle,
  };
}
