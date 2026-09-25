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

  test("send attempts rate-limit per address", async () => {
    const world = await relayWorld();
    const digest = await emailDigest("spam@example.test");
    for (let index = 0; index < 3; index++) {
      await world.t.mutation(reserveEmailAttempt, { emailDigest: digest, kind: "send" });
    }
    await expect(world.t.mutation(reserveEmailAttempt, { emailDigest: digest, kind: "send" })).rejects.toThrow();
  });
});
