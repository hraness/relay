/** Test fixtures: mint users, auth sessions, and enrolled devices directly
 * against the relay schema, bypassing the OTP path (which is covered by its
 * own focused tests). */

import { convexTest } from "convex-test";
import { makeFunctionReference } from "convex/server";
import type { GenericId } from "convex/values";

import { createDeviceIdentity, signCanonicalBase64, type DeviceIdentity } from "../crypto";
import { encodeBase64Url } from "../wire/encoding";
import type { RowId } from "../backend/db";

import schema from "./schema";
import { modules } from "./test.setup";

export type TestRuntime = ReturnType<ReturnType<typeof convexTest>["withIdentity"]>;
export type DeviceHandle = Readonly<{
  authSessionId: GenericId<"authSessions">;
  device: DeviceIdentity;
  deviceId: string;
  runtime: TestRuntime;
  userId: GenericId<"users">;
}>;

const registerRef = makeFunctionReference<"mutation", Record<string, unknown>, unknown>("relayDevices:register");
const beginBindRef = makeFunctionReference<"mutation", Record<string, unknown>, unknown>("relayDevices:beginBind");
const finishBindRef = makeFunctionReference<"mutation", Record<string, unknown>, unknown>("relayDevices:finishBind");

export async function relayWorld() {
  const t = convexTest(schema, modules);
  const now = Date.now();

  const enrollUser = async (label: string): Promise<GenericId<"users">> =>
    await t.run(async (ctx) => {
      const userId = await ctx.db.insert("users", {
        email: `${label}@example.test`,
        emailVerificationTime: now,
      });
      await ctx.db.insert("relaySubjects", {
        authEpoch: 1,
        createdAt: now,
        emailDigest: `${label.padEnd(64, "0")}`.slice(0, 64),
        status: "active",
        updatedAt: now,
        userId,
        verifiedAt: now,
      });
      return userId;
    });

  const asSession = (userId: GenericId<"users">, authSessionId: GenericId<"authSessions">): TestRuntime =>
    t.withIdentity({
      issuer: "https://test.example",
      subject: `${userId}|${authSessionId}`,
      tokenIdentifier: `test|${authSessionId}`,
    });

  /** Register + bind a device through the real mutations. */
  const enrollDevice = async (
    userId: GenericId<"users">,
    deviceClass: "daemon" | "controller",
    label: string,
  ): Promise<DeviceHandle> => {
    const device = await createDeviceIdentity();
    const authSessionId = await t.run(async (ctx) =>
      await ctx.db.insert("authSessions", { expirationTime: now + 3_600_000, userId }));
    const runtime = asSession(userId, authSessionId);
    await runtime.mutation(registerRef, {
      agreementPublicKey: device.publicKeys.agreement,
      deviceClass,
      deviceId: device.device,
      label,
      signingPublicKey: device.publicKeys.signing,
    });
    const begin = await runtime.mutation(beginBindRef, { deviceId: device.device }) as { challengeId: string; nonce: string };
    const signature = await signCanonicalBase64(device.signing.privateKey, {
      challengeId: begin.challengeId,
      contract: "relay.dev.v1:device-bind",
      nonce: begin.nonce,
    });
    await runtime.mutation(finishBindRef, {
      challengeId: begin.challengeId,
      deviceId: device.device,
      signature,
    });
    return { authSessionId, device, deviceId: device.device, runtime, userId };
  };

  return { asSession, enrollDevice, enrollUser, t };
}

export function uuidV7(seed: number): string {
  const now = BigInt(Date.now());
  const hex = now.toString(16).padStart(12, "0");
  const rand = encodeBase64Url(crypto.getRandomValues(new Uint8Array(10)))
    .replace(/[^0-9a-f]/g, "a").padEnd(20, "b");
  return `${hex.slice(0, 8)}-${hex.slice(8)}-7${rand.slice(0, 3)}-8${rand.slice(3, 6)}-${(seed.toString(16) + rand.slice(6)).slice(0, 12)}`;
}

export const sampleEnvelope = (sender: string, recipient: string, scope = "commands.v1") => ({
  ciphertext: "A".repeat(48),
  contract: "relay.dev.v1",
  iv: "B".repeat(16),
  keyVersion: 1,
  recipient,
  scope,
  sender,
  signature: "A".repeat(86),
});

export const sampleAuthority = (generation = 1, fence = 0, bootId?: string) => ({
  bootGeneration: generation,
  bootId: bootId ?? `b${"0".repeat(31)}`,
  fence,
});
