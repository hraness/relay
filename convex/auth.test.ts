import { describe, expect, test } from "bun:test";
import { makeFunctionReference } from "convex/server";
import type { GenericId } from "convex/values";
import { convexTest } from "convex-test";

import {
  digestAuthEmail,
  digestAuthOtp,
  digestInviteCapability,
  generateOtp,
  parseAuthCredentials,
} from "../backend/auth";

import { relayWorld } from "./fixture";
import schema from "./schema";
import { modules } from "./test.setup";

const reserveEmailAttempt = makeFunctionReference<"mutation", Record<string, unknown>, { authEpoch: number; inviteBinding: string }>("relayInternal:reserveEmailAttempt");
const storeOtpChallenge = makeFunctionReference<"mutation", Record<string, unknown>, string>("relayInternal:storeOtpChallenge");
const consumeOtpChallenge = makeFunctionReference<"mutation", Record<string, unknown>, string>("relayInternal:consumeOtpChallenge");
const recordOtpDelivery = makeFunctionReference<"mutation", Record<string, unknown>, unknown>("relayInternal:recordOtpDelivery");

const emailDigest = (email: string) => digestAuthEmail("relay.dev.v1", email);

describe("auth credentials", () => {
  test("parses request_code and verify_code shapes only", () => {
    expect(parseAuthCredentials({ flow: "request_code", email: "a@b.c" })).toEqual({ kind: "request_code", email: "a@b.c" });
    expect(parseAuthCredentials({ flow: "request_code", email: "a@b.c", invite: "t".repeat(32) })).toMatchObject({ kind: "request_code" });
    expect(parseAuthCredentials({ flow: "verify_code", email: "a@b.c", code: "12345678" })).toEqual({ code: "12345678", email: "a@b.c", kind: "verify_code" });
    expect(parseAuthCredentials({ flow: "verify_code", email: "a@b.c", code: "1234" })).toEqual({ kind: "rejected" });
    expect(parseAuthCredentials({ flow: "other", email: "a@b.c" })).toEqual({ kind: "rejected" });
    expect(parseAuthCredentials({ flow: "request_code", email: "not-an-email" })).toEqual({ kind: "rejected" });
    expect(parseAuthCredentials({})).toEqual({ kind: "rejected" });
  });

  test("digests are purpose-separated", async () => {
    const email = await emailDigest("x@example.test");
    const otp = await digestAuthOtp("relay.dev.v1", "x@example.test", "12345678");
    const invite = await digestInviteCapability("relay.dev.v1", "tok");
    expect(email).toMatch(/^[0-9a-f]{64}$/);
    expect(new Set([email, otp, invite]).size).toBe(3);
    // Normalization: case and whitespace fold into the same digest.
    expect(await emailDigest("  X@EXAMPLE.test ")).toBe(email);
  });

  test("OTPs are eight digits", () => {
    for (let index = 0; index < 20; index++) {
      expect(generateOtp()).toMatch(/^[0-9]{8}$/);
    }
  });
});

describe("otp internals", () => {
  test("a fresh email can reserve a send attempt under open sign-up", async () => {
    const world = await relayWorld();
    const digest = await emailDigest("new@example.test");
    const reserved = await world.t.mutation(reserveEmailAttempt, { emailDigest: digest, kind: "send" });
    expect(reserved.authEpoch).toBe(1);
    expect(reserved.inviteBinding).toBe("not_required");
  });

  test("verify is refused without a live challenge and codes are one-time", async () => {
    const world = await relayWorld();
    const email = "verify@example.test";
    const digest = await emailDigest(email);

    // Store a challenge the way the provider path does.
    const { accountId, userId } = await world.t.run(async (ctx) => {
      const userId = await ctx.db.insert("users", { email, emailVerificationTime: undefined });
      const accountId = await ctx.db.insert("authAccounts", {
        provider: "relay-dev-otp-v1",
        providerAccountId: email,
        secret: undefined,
        userId,
      } as never);
      return { accountId, userId };
    });

    await world.t.mutation(reserveEmailAttempt, { emailDigest: digest, kind: "send" });
    const code = "12345678";
    const codeDigest = await digestAuthOtp("relay.dev.v1", email, code);
    const challengeId = await world.t.mutation(storeOtpChallenge, {
      accountId,
      authEpoch: 1,
      codeDigest,
      emailDigest: digest,
      expiresAt: Date.now() + 10 * 60 * 1_000,
      userId,
    });
    expect(typeof challengeId).toBe("string");
    await world.t.mutation(recordOtpDelivery, { challengeId, state: "accepted" });

    // Wrong code → refused; verify attempt must be rate-reserved first.
    const wrong = await digestAuthOtp("relay.dev.v1", email, "00000000");
    await world.t.mutation(reserveEmailAttempt, { emailDigest: digest, kind: "verify" });
    await expect(world.t.mutation(consumeOtpChallenge, {
      authEpoch: 1,
      codeDigest: wrong,
      emailDigest: digest,
    })).rejects.toThrow();

    // Right code consumes once.
    const consumed = await world.t.mutation(consumeOtpChallenge, {
      authEpoch: 1,
      codeDigest,
      emailDigest: digest,
    }) as GenericId<"users">;
    expect(consumed).toBe(userId);

    // Second consume: the challenge is gone.
    await expect(world.t.mutation(consumeOtpChallenge, {
      authEpoch: 1,
      codeDigest,
      emailDigest: digest,
    })).rejects.toThrow();
  });

  test("closed sign-up admits the bootstrap token once, then never again", async () => {
    const closed = makeFunctionReference<"mutation", Record<string, unknown>, { authEpoch: number; inviteBinding: string }>("relayInternalClosed:reserveEmailAttempt");
    const t = convexTest(schema, modules);
    process.env.RELAY_TEST_BOOTSTRAP_TOKEN = "bootstrap-secret-token-0001";
    try {
      const digest = await emailDigest("founder@example.test");
      const capability = await digestInviteCapability("relay.dev.v1", "bootstrap-secret-token-0001");

      // Without the capability, a fresh email is refused outright.
      const stranger = await emailDigest("stranger@example.test");
      await expect(t.mutation(closed, { emailDigest: stranger, kind: "send" })).rejects.toThrow();

      // With it, the founder is admitted as invite-bound.
      const admitted = await t.mutation(closed, {
        emailDigest: digest,
        inviteCapabilityDigest: capability,
        kind: "send",
      });
      expect(admitted.inviteBinding).toBe("bound");

      // Resend works for the admitted-but-unverified subject.
      const resend = await t.mutation(closed, {
        emailDigest: digest,
        inviteCapabilityDigest: capability,
        kind: "send",
      });
      expect(resend.inviteBinding).toBe("bound");
    } finally {
      delete process.env.RELAY_TEST_BOOTSTRAP_TOKEN;
    }
  });

  test("the bootstrap token dies once a subject has verified", async () => {
    const closed = makeFunctionReference<"mutation", Record<string, unknown>, { authEpoch: number; inviteBinding: string }>("relayInternalClosed:reserveEmailAttempt");
    const storeClosed = makeFunctionReference<"mutation", Record<string, unknown>, string>("relayInternalClosed:storeOtpChallenge");
    const consumeClosed = makeFunctionReference<"mutation", Record<string, unknown>, string>("relayInternalClosed:consumeOtpChallenge");
    const t = convexTest(schema, modules);
    process.env.RELAY_TEST_BOOTSTRAP_TOKEN = "bootstrap-secret-token-0002";
    try {
      const email = "founder@example.test";
      const digest = await emailDigest(email);
      const capability = await digestInviteCapability("relay.dev.v1", "bootstrap-secret-token-0002");
      await t.mutation(closed, { emailDigest: digest, inviteCapabilityDigest: capability, kind: "send" });

      // Complete verification through the challenge path.
      const { accountId, userId } = await t.run(async (ctx) => {
        const userId = await ctx.db.insert("users", { email, emailVerificationTime: undefined });
        const accountId = await ctx.db.insert("authAccounts", {
          provider: "relay-dev-otp-v1",
          providerAccountId: email,
          secret: undefined,
          userId,
        } as never);
        return { accountId, userId };
      });
      const code = "12345678";
      const codeDigest = await digestAuthOtp("relay.dev.v1", email, code);
      await t.mutation(storeClosed, {
        accountId,
        authEpoch: 1,
        codeDigest,
        emailDigest: digest,
        expiresAt: Date.now() + 10 * 60 * 1_000,
        userId,
      });
      await t.mutation(consumeClosed, { authEpoch: 1, codeDigest, emailDigest: digest });

      // A second email holding the same token is now refused.
      const late = await emailDigest("late@example.test");
      await expect(t.mutation(closed, {
        emailDigest: late,
        inviteCapabilityDigest: capability,
        kind: "send",
      })).rejects.toThrow();
    } finally {
      delete process.env.RELAY_TEST_BOOTSTRAP_TOKEN;
    }
  });

  test("send attempts rate-limit per address", async () => {
    const world = await relayWorld();
    const digest = await emailDigest("spam@example.test");
    for (let index = 0; index < 3; index++) {
      await world.t.mutation(reserveEmailAttempt, { emailDigest: digest, kind: "send" });
    }
    await expect(world.t.mutation(reserveEmailAttempt, { emailDigest: digest, kind: "send" })).rejects.toThrow();
  });
});
