/** Verified-email auth: one Convex Auth credentials provider issuing 8-digit
 * OTP challenges. Subjects are keyed by a purpose-separated email digest; the
 * code travels only through the configured email transport; challenges are
 * one-time, expiring, and rate-limited by rolling attempt windows.

 * The returned internal mutations are invoked by the credentials provider
 * through `ctx.runMutation` with string function references, so the product
 * must re-export them from a module named `relayInternal.ts` in its convex
 * directory (or set `paths.internal` in the config to match). */

import { ConvexCredentials } from "@convex-dev/auth/providers/ConvexCredentials";
import { convexAuth, createAccount } from "@convex-dev/auth/server";
import { internalMutationGeneric as internalMutation, makeFunctionReference, queryGeneric as query } from "convex/server";
import { v } from "convex/values";

import { isEmailAddress, normalizeEmail } from "../wire/ids";
import { isHex } from "../wire/encoding";
import type { GenericId } from "convex/values";
import { OTP_ATTEMPT_POLICY, resolveRelayBounds, type RelayConfig } from "../wire/bounds";

import type { AuthAttemptRow, AuthSubjectRow, InviteRow, OtpChallengeRow, Row, RowId } from "./db";
import { relayCtx, relayMutationCtx, type RelayMutationCtx } from "./db";

export type RelayAuthPaths = Readonly<{ internal: string }>;

function digestHex(bytes: ArrayBuffer): string {
  let hex = "";
  for (const byte of new Uint8Array(bytes)) hex += byte.toString(16).padStart(2, "0");
  return hex;
}

async function sha256Hex(text: string): Promise<string> {
  return digestHex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
}

/** Purpose-separated digests — an email digest can never be replayed as a
 * code digest, and digests are namespaced per product. */
export function digestAuthEmail(namespace: string, email: string): Promise<string> {
  return sha256Hex(`${namespace}:email|${normalizeEmail(email)}`);
}

export function digestAuthOtp(namespace: string, email: string, code: string): Promise<string> {
  return sha256Hex(`${namespace}:otp|${normalizeEmail(email)}|${code}`);
}

export function digestInviteCapability(namespace: string, invite: string): Promise<string> {
  return sha256Hex(`${namespace}:invite|${invite}`);
}

function isAuthDigest(value: unknown): value is string {
  return isHex(value, 64);
}

function rejectAuth(): never {
  // One flat refusal for every auth path: the client must not learn which
  // invariant failed, matching hra's behavior.
  throw new Error("Authentication is unavailable.");
}

function timingSafeEqualHex(left: string, right: string): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index++) difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  return difference === 0;
}

export function generateOtp(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(4));
  const value = ((bytes[0]! << 24) | (bytes[1]! << 16) | (bytes[2]! << 8) | bytes[3]!) >>> 0;
  return String(value % 100_000_000).padStart(8, "0");
}

type Credentials = Readonly<Record<string, unknown>>;

type ParsedCredentials =
  | Readonly<{ kind: "request_code"; email: string; invite?: string }>
  | Readonly<{ kind: "verify_code"; email: string; code: string }>
  | Readonly<{ kind: "rejected" }>;

export function parseAuthCredentials(credentials: Credentials): ParsedCredentials {
  const flow = credentials.flow;
  const email = credentials.email;
  if (typeof email !== "string" || !isEmailAddress(email)) return { kind: "rejected" };
  if (flow === "request_code") {
    const invite = credentials.invite;
    if (invite !== undefined && (typeof invite !== "string" || invite.length < 32 || invite.length > 128)) {
      return { kind: "rejected" };
    }
    return invite === undefined
      ? { kind: "request_code", email }
      : { kind: "request_code", email, invite };
  }
  if (flow === "verify_code") {
    const code = credentials.code;
    if (typeof code !== "string" || !/^[0-9]{8}$/u.test(code)) return { kind: "rejected" };
    return { kind: "verify_code", email, code };
  }
  return { kind: "rejected" };
}

// Email transport ------------------------------------------------------------------

async function sendOtpEmail(config: RelayConfig, input: Readonly<{ email: string; code: string; expiresAt: number }>): Promise<void> {
  const transport = config.email;
  if (transport.mode === "log") {
    console.log(`[relay] OTP for ${input.email}: ${input.code} (expires ${new Date(input.expiresAt).toISOString()})`);
    return;
  }
  if (transport.mode === "resend") {
    const key = process.env[transport.keyEnv];
    const from = process.env[transport.fromEnv];
    if (key === undefined || from === undefined) throw new Error("Email delivery is unavailable.");
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8_000);
    try {
      const response = await fetch("https://api.resend.com/emails", {
        body: JSON.stringify({
          from,
          subject: "Your sign-in code",
          text: `Your sign-in code is ${input.code}.\n\nIt expires in 10 minutes. If you did not request it, you can ignore this email.`,
          to: [input.email],
        }),
        headers: {
          Authorization: `Bearer ${key}`,
          "Content-Type": "application/json",
          "Idempotency-Key": await sha256Hex(`${config.namespace}:otp-send|${input.email}|${input.code}|${String(input.expiresAt)}`),
        },
        method: "POST",
        redirect: "error",
        signal: controller.signal,
      });
      await response.body?.cancel().catch(() => undefined);
      if (!response.ok) throw new Error("Email delivery is unavailable.");
      return;
    } finally {
      clearTimeout(timeout);
    }
  }
  const url = process.env[transport.urlEnv];
  const token = process.env[transport.tokenEnv];
  if (url === undefined || token === undefined) throw new Error("Email delivery is unavailable.");
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 8_000);
  try {
    const response = await fetch(url, {
      body: JSON.stringify({ code: input.code, expiresAt: input.expiresAt, to: input.email }),
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      method: "POST",
      redirect: "error",
      signal: controller.signal,
    });
    await response.body?.cancel().catch(() => undefined);
    if (!response.ok) throw new Error("Email delivery is unavailable.");
  } finally {
    clearTimeout(timeout);
  }
}

// Internal mutations ---------------------------------------------------------

type InternalCtx = RelayMutationCtx;

async function subjectByEmail(ctx: InternalCtx, emailDigest: string): Promise<Row<AuthSubjectRow> | null> {
  const matches = await ctx.db
    .query<AuthSubjectRow>("relaySubjects")
    .withIndex("by_email_digest", (q) => q.eq("emailDigest", emailDigest))
    .take(2);
  if (matches.length > 1) rejectAuth();
  return matches[0] ?? null;
}

async function countAttempts(
  ctx: InternalCtx,
  input: Readonly<{ cutoff: number; emailDigest: string; kind: "send" | "verify"; limit: number }>,
): Promise<number> {
  const matches = await ctx.db
    .query<AuthAttemptRow>("relayAuthAttempts")
    .withIndex("by_email_kind_and_created_at", (q) =>
      q.eq("emailDigest", input.emailDigest).eq("kind", input.kind).gte("createdAt", input.cutoff))
    .take(input.limit);
  return matches.length;
}

async function countGlobalAttempts(
  ctx: InternalCtx,
  input: Readonly<{ cutoff: number; kind: "send" | "verify"; limit: number }>,
): Promise<number> {
  const rows = await ctx.db
    .query<AuthAttemptRow>("relayAuthAttempts")
    .withIndex("by_expires_at", (q) => q.gte("expiresAt", input.cutoff))
    .take(input.limit + 1024);
  return rows.filter((row) => row.kind === input.kind && row.createdAt >= input.cutoff).length;
}

export function relayAuthInternal(config: RelayConfig) {
  const bounds = resolveRelayBounds(config);

  const reserveEmailAttempt = internalMutation({
    args: {
      emailDigest: v.string(),
      inviteCapabilityDigest: v.optional(v.string()),
      kind: v.union(v.literal("send"), v.literal("verify")),
    },
    handler: async (rawCtx, args) => {
      const ctx = relayMutationCtx(rawCtx);
      if (!isAuthDigest(args.emailDigest)) rejectAuth();
      if (args.inviteCapabilityDigest !== undefined && !isAuthDigest(args.inviteCapabilityDigest)) rejectAuth();
      const now = Date.now();
      let subject = await subjectByEmail(ctx, args.emailDigest);
      let inviteBinding: "bound" | "not_required" | "replay" = "not_required";

      if (args.kind === "verify") {
        if (subject?.status !== "active" || args.inviteCapabilityDigest !== undefined) rejectAuth();
      } else if (subject?.status === "active" && subject.userId !== undefined && subject.verifiedAt !== undefined) {
        if (args.inviteCapabilityDigest !== undefined) rejectAuth();
      } else if (args.inviteCapabilityDigest === undefined) {
        // Open sign-up: admitted without an invite only when the product
        // declared open enrollment, or the subject was already admitted
        // through an invite and is re-sending.
        if (subject === null && !config.openSignup) rejectAuth();
        if (subject !== null && (subject.status !== "active" || (!config.openSignup && subject.admittedWithInvite !== true && subject.userId === undefined))) {
          rejectAuth();
        }
        if (subject === null) {
          const subjectId = await ctx.db.insert("relaySubjects", {
            authEpoch: 1,
            createdAt: now,
            emailDigest: args.emailDigest,
            status: "active",
            updatedAt: now,
          });
          subject = await ctx.db.get<AuthSubjectRow>(subjectId);
          if (subject === null) rejectAuth();
        }
      } else {
        if (subject !== null && subject.status !== "active") rejectAuth();
        const invites = await ctx.db
          .query<InviteRow>("relayInvites")
          .withIndex("by_capability_digest", (q) => q.eq("capabilityDigest", args.inviteCapabilityDigest!))
          .take(2);
        const invite = invites[0];
        if (
          invites.length !== 1
          || invite === undefined
          || invite.purpose !== "identity"
          || invite.state !== "issued"
          || invite.revokedAt !== undefined
          || invite.expiresAt <= now
        ) rejectAuth();
        if (invite.boundEmailDigest !== undefined && invite.boundEmailDigest !== args.emailDigest) rejectAuth();
        if (subject === null) {
          const subjectId = await ctx.db.insert("relaySubjects", {
            admittedWithInvite: true,
            authEpoch: 1,
            createdAt: now,
            emailDigest: args.emailDigest,
            status: "active",
            updatedAt: now,
          });
          subject = await ctx.db.get<AuthSubjectRow>(subjectId);
          if (subject === null) rejectAuth();
        } else if (subject.admittedWithInvite !== true) {
          await ctx.db.patch(subject._id, { admittedWithInvite: true, updatedAt: now });
        }
        // The capability is one-shot: it binds to this email and dies at
        // the first send. A never-completed OTP leaves the subject marked
        // invite-admitted so resends still work.
        await ctx.db.patch(invite._id, {
          boundEmailDigest: args.emailDigest,
          consumedAt: now,
          state: "consumed",
          updatedAt: now,
        });
        inviteBinding = "bound";
      }
      if (subject?.status !== "active") rejectAuth();

      const unverifiedSends = args.kind === "send" && !(subject.userId !== undefined && subject.verifiedAt !== undefined)
        ? subject.unverifiedSendCount ?? 0
        : null;
      if (unverifiedSends !== null && (!Number.isSafeInteger(unverifiedSends) || unverifiedSends >= OTP_ATTEMPT_POLICY.unverifiedLifetimeSendLimit)) {
        rejectAuth();
      }

      const policy = OTP_ATTEMPT_POLICY;
      if (args.kind === "send") {
        for (const window of policy.sendPerEmail) {
          if (await countAttempts(ctx, { cutoff: now - window.windowMs, emailDigest: args.emailDigest, kind: "send", limit: window.limit }) >= window.limit) rejectAuth();
        }
        for (const window of policy.sendGlobal) {
          if (await countGlobalAttempts(ctx, { cutoff: now - window.windowMs, kind: "send", limit: window.limit }) >= window.limit) rejectAuth();
        }
      } else {
        for (const window of policy.verifyPerEmail) {
          if (await countAttempts(ctx, { cutoff: now - window.windowMs, emailDigest: args.emailDigest, kind: "verify", limit: window.limit }) >= window.limit) rejectAuth();
        }
        for (const window of policy.verifyGlobal) {
          if (await countGlobalAttempts(ctx, { cutoff: now - window.windowMs, kind: "verify", limit: window.limit }) >= window.limit) rejectAuth();
        }
      }
      if (unverifiedSends !== null) {
        await ctx.db.patch(subject._id, { unverifiedSendCount: unverifiedSends + 1, updatedAt: now });
      }
      await ctx.db.insert("relayAuthAttempts", {
        authEpoch: subject.authEpoch,
        createdAt: now,
        emailDigest: args.emailDigest,
        expiresAt: now + (args.kind === "send" ? policy.sendRetentionMs : policy.verifyRetentionMs),
        kind: args.kind,
      });
      return { authEpoch: subject.authEpoch, inviteBinding };
    },
  });

  const storeOtpChallenge = internalMutation({
    args: {
      accountId: v.id("authAccounts"),
      authEpoch: v.number(),
      codeDigest: v.string(),
      emailDigest: v.string(),
      expiresAt: v.number(),
      userId: v.id("users"),
    },
    handler: async (rawCtx, args) => {
      const ctx = relayMutationCtx(rawCtx);
      if (!isAuthDigest(args.emailDigest) || !isAuthDigest(args.codeDigest)) rejectAuth();
      const now = Date.now();
      const subject = await subjectByEmail(ctx, args.emailDigest);
      const account = await ctx.db.get<{ provider?: string; userId?: RowId }>(args.accountId as unknown as RowId);
      const user = await ctx.db.get(args.userId as unknown as RowId);
      if (
        subject?.status !== "active"
        || subject.authEpoch !== args.authEpoch
        || (subject.userId !== undefined && subject.userId !== (args.userId as unknown as RowId))
        || account?.provider !== config.authProviderId
        || (account.userId as unknown) !== args.userId
        || user === null
        || !Number.isFinite(args.expiresAt)
        || args.expiresAt <= now
        || args.expiresAt > now + bounds.otpLifetimeMs
      ) rejectAuth();
      if (subject.userId === undefined) {
        await ctx.db.patch(subject._id, { updatedAt: now, userId: args.userId as unknown as RowId });
      }
      const challenges = await ctx.db
        .query<OtpChallengeRow>("relayOtpChallenges")
        .withIndex("by_email", (q) => q.eq("emailDigest", args.emailDigest))
        .take(bounds.liveOtpChallenges + 1);
      const live: Row<OtpChallengeRow>[] = [];
      for (const challenge of challenges) {
        if (challenge.expiresAt <= now || challenge.authEpoch !== args.authEpoch) {
          await ctx.db.delete(challenge._id);
        } else {
          live.push(challenge);
        }
      }
      if (live.some((challenge) => (challenge.accountId as unknown) !== args.accountId || (challenge.userId as unknown) !== args.userId)) rejectAuth();
      const duplicate = live.find((challenge) => timingSafeEqualHex(challenge.codeDigest, args.codeDigest));
      if (duplicate !== undefined) return duplicate._id;
      if (live.length >= bounds.liveOtpChallenges) rejectAuth();
      return await ctx.db.insert("relayOtpChallenges", {
        accountId: args.accountId,
        authEpoch: args.authEpoch,
        codeDigest: args.codeDigest,
        createdAt: now,
        deliveryState: "reserved",
        emailDigest: args.emailDigest,
        expiresAt: args.expiresAt,
        updatedAt: now,
        userId: args.userId,
      });
    },
  });

  const recordOtpDelivery = internalMutation({
    args: {
      challengeId: v.id("relayOtpChallenges"),
      state: v.union(v.literal("accepted"), v.literal("ambiguous")),
    },
    handler: async (rawCtx, args) => {
      const ctx = relayMutationCtx(rawCtx);
      const challenge = await ctx.db.get<OtpChallengeRow>(args.challengeId as unknown as RowId);
      if (challenge === null) return null;
      if (challenge.deliveryState === args.state) return challenge._id;
      if (challenge.deliveryState !== "reserved") rejectAuth();
      await ctx.db.patch(challenge._id, { deliveryState: args.state, updatedAt: Date.now() });
      return challenge._id;
    },
  });

  const consumeOtpChallenge = internalMutation({
    args: {
      authEpoch: v.number(),
      codeDigest: v.string(),
      emailDigest: v.string(),
    },
    handler: async (rawCtx, args): Promise<RowId> => {
      const ctx = relayMutationCtx(rawCtx);
      if (!isAuthDigest(args.emailDigest) || !isAuthDigest(args.codeDigest)) rejectAuth();
      const now = Date.now();
      const subject = await subjectByEmail(ctx, args.emailDigest);
      if (subject?.status !== "active" || subject.authEpoch !== args.authEpoch || subject.userId === undefined) rejectAuth();
      const challenges = await ctx.db
        .query<OtpChallengeRow>("relayOtpChallenges")
        .withIndex("by_email", (q) => q.eq("emailDigest", args.emailDigest))
        .take(bounds.liveOtpChallenges + 1);
      const matches = challenges.filter((challenge) =>
        timingSafeEqualHex(challenge.codeDigest, args.codeDigest)
        && challenge.authEpoch === args.authEpoch
        && challenge.expiresAt > now);
      const challenge = matches[0];
      if (matches.length !== 1 || challenge === undefined) rejectAuth();
      const account = await ctx.db.get<{ provider?: string; userId?: RowId }>(challenge.accountId);
      const user = await ctx.db.get<{ emailVerificationTime?: number }>(challenge.userId);
      if (account?.provider !== config.authProviderId || user === null) rejectAuth();
      if (subject.userId !== user._id || (account.userId as unknown) !== user._id
        || challenges.some((stored) => (stored.accountId as unknown) !== challenge.accountId || (stored.userId as unknown) !== user._id)) rejectAuth();

      // Consume: one-time codes die with the successful verify.
      for (const stored of challenges) await ctx.db.delete(stored._id);
      await ctx.db.patch(user._id, { emailVerificationTime: now });
      await ctx.db.patch(subject._id, { updatedAt: now, verifiedAt: now });
      return user._id;
    },
  });

  return { consumeOtpChallenge, recordOtpDelivery, reserveEmailAttempt, storeOtpChallenge };
}

// The provider + session surface --------------------------------------------------

export function relayAuth(config: RelayConfig, paths: RelayAuthPaths = { internal: "relayInternal" }) {
  const bounds = resolveRelayBounds(config);
  const internal = relayAuthInternal(config);

  const ref = (name: string) => makeFunctionReference<"mutation", Record<string, unknown>, unknown>(`${paths.internal}:${name}`);

  const otpProvider = ConvexCredentials({
    id: config.authProviderId,
    authorize: async (credentials, ctx) => {
      try {
        const parsed = parseAuthCredentials(credentials as Credentials);
        if (parsed.kind === "rejected") return null;
        const emailDigest = await digestAuthEmail(config.namespace, parsed.email);
        const reservation = await ctx.runMutation(ref("reserveEmailAttempt"), {
          emailDigest,
          kind: parsed.kind === "request_code" ? "send" : "verify",
          ...(parsed.kind === "request_code" && parsed.invite !== undefined
            ? { inviteCapabilityDigest: await digestInviteCapability(config.namespace, parsed.invite) }
            : {}),
        }) as unknown as { authEpoch: number; inviteBinding: string };
        if (parsed.kind === "verify_code") {
          return {
            userId: (await ctx.runMutation(ref("consumeOtpChallenge"), {
              authEpoch: reservation.authEpoch,
              codeDigest: await digestAuthOtp(config.namespace, parsed.email, parsed.code),
              emailDigest,
            })) as GenericId<"users">,
          };
        }
        const code = generateOtp();
        const expiresAt = Date.now() + bounds.otpLifetimeMs;
        const { account, user } = await createAccount(ctx, {
          account: { id: parsed.email },
          profile: { email: parsed.email },
          provider: config.authProviderId,
          shouldLinkViaEmail: true,
        });
        const challengeId = await ctx.runMutation(ref("storeOtpChallenge"), {
          accountId: account._id,
          authEpoch: reservation.authEpoch,
          codeDigest: await digestAuthOtp(config.namespace, parsed.email, code),
          emailDigest,
          expiresAt,
          userId: user._id,
        });
        try {
          await sendOtpEmail(config, { email: parsed.email, code, expiresAt });
          await ctx.runMutation(ref("recordOtpDelivery"), { challengeId, state: "accepted" });
        } catch {
          await ctx.runMutation(ref("recordOtpDelivery"), { challengeId, state: "ambiguous" });
        }
        return null;
      } catch {
        return null;
      }
    },
  });

  const configured = convexAuth({
    jwt: { durationMs: 15 * 60 * 1_000 },
    providers: [otpProvider],
    session: {
      inactiveDurationMs: 24 * 60 * 60 * 1_000,
      totalDurationMs: 7 * 24 * 60 * 60 * 1_000,
    },
    signIn: { maxFailedAttempsPerHour: 12 },
  });

  return {
    auth: configured.auth,
    isAuthenticated: configured.isAuthenticated,
    signIn: configured.signIn,
    signOut: configured.signOut,
    /** Must be exported as `internalMutation` from the module at
     * `paths.internal` (conventionally `convex/relayInternal.ts`). */
    internal,
    /** The library's auth store handler — the product's convex directory
     * re-exports it so session refresh and cleanup run. */
    store: configured.store,
  };
}

/** The subject row the caller authenticates as — public query for
 * `whoami`-style reads. */
export function relayAuthQueries() {
  return {
    currentSubject: query({
      args: {},
      handler: async (ctx) => {
        const relay = relayCtx(ctx);
        const identity = await relay.auth.getUserIdentity();
        if (identity === null) return null;
        const subjects = await relay.db
          .query<AuthSubjectRow>("relaySubjects")
          .withIndex("by_user", (q) => q.eq("userId", identity.subject as RowId))
          .take(2);
        const subject = subjects[0];
        if (subject === undefined) return null;
        return { authEpoch: subject.authEpoch, status: subject.status, verifiedAt: subject.verifiedAt ?? null };
      },
    }),
  };
}
