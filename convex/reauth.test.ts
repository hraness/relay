import { describe, expect, test } from "bun:test";
import { makeFunctionReference } from "convex/server";
import { createDeviceIdentity, signCanonicalBase64 } from "../crypto";
import type { DeviceReauthChallenge, DeviceReauthResult } from "../wire/reauth";
import { relayWorld, sampleAuthority, sampleEnvelope, uuidV7 } from "./fixture";

const mutation = (name: string) => makeFunctionReference<"mutation">(name);
const query = (name: string) => makeFunctionReference<"query">(name);
const begin = mutation("relayDevices:beginReauth");
const finish = mutation("relayDevices:finishReauth");
const status = query("relayDevices:reauthStatus");
const list = query("relayDevices:list");
const myEnvelopes = query("relayEnvelopes:myKeyEnvelopes");
const currentSubject = query("relayAuth:currentSubject");

async function fixture() {
  const world = await relayWorld();
  const userId = await world.enrollUser("reauth-owner");
  const device = await world.enrollDevice(userId, "daemon", "existing-device");
  const newSession = async (owner = userId) => {
    const sessionId = await world.t.run(async (ctx) => await ctx.db.insert("authSessions", {
      expirationTime: Date.now() + 3_600_000, userId: owner,
    }));
    return { runtime: world.asSession(owner, sessionId), sessionId };
  };
  const next = await newSession();
  const prepare = async (runtime = next.runtime) => {
    const challenge = await runtime.mutation(begin, { deviceId: device.deviceId }) as DeviceReauthChallenge;
    const signature = await signCanonicalBase64(device.device.signing.privateKey, challenge);
    return { challenge, args: { deviceId: device.deviceId, challengeId: challenge.challengeId, signature } };
  };
  const deviceRow = async () => await world.t.run(async (ctx) =>
    (await ctx.db.query("relayDevices").filter((q) => q.eq(q.field("deviceId"), device.deviceId)).unique())!);
  return { world, userId, device, next, newSession, prepare, deviceRow };
}

describe("key-preserving reauthentication", () => {
  test("replaces the session, preserving device, live effects, presence, projections and wrapped keys", async () => {
    const f = await fixture();
    const peer = await f.world.enrollDevice(f.userId, "controller", "controller");
    await f.device.runtime.mutation(mutation("relayDevices:connect"), {
      connectionId: "existing-connection", deviceId: f.device.deviceId, fingerprint: "existing-fingerprint",
    });
    await f.device.runtime.mutation(mutation("relayProjections:publish"), {
      deviceId: f.device.deviceId, envelope: sampleEnvelope(f.device.deviceId, "account", "tasks.v1"),
      expectedRevision: 0, scope: "tasks.v1",
    });
    await peer.runtime.mutation(mutation("relayEnvelopes:postKeyEnvelope"), { envelope: {
      contract: "relay.keywrap.v1", sender: peer.deviceId, recipient: f.device.deviceId,
      keyVersion: 1, iv: "B".repeat(16), wrapped: "C".repeat(48), signature: "A".repeat(86),
    } });
    const commandIds: string[] = [];
    for (let index = 0; index < 3; index++) {
      const { command } = await peer.runtime.mutation(mutation("relayCommands:enqueue"), {
        idempotencyKey: uuidV7(index + 1), kind: "task_dispatch", payload: sampleEnvelope(peer.deviceId, f.device.deviceId),
        requestDigest: `sha256:${"a".repeat(64)}`, targetDeviceId: f.device.deviceId,
      }) as { command: { publicId: string } };
      commandIds.push(command.publicId);
      if (index > 0) await f.device.runtime.mutation(mutation("relayCommands:claim"), {
        authority: sampleAuthority(), deviceId: f.device.deviceId, publicId: command.publicId,
      });
      if (index > 1) await f.device.runtime.mutation(mutation("relayCommands:markEffectStarted"), {
        authority: sampleAuthority(), deviceId: f.device.deviceId, publicId: command.publicId,
      });
    }
    const before = await f.deviceRow();
    const unchanged = async () => await f.world.t.run(async (ctx) => ({
      commands: await ctx.db.query("relayCommands").collect(),
      presence: await ctx.db.query("relayPresence").collect(),
      projections: await ctx.db.query("relayProjections").collect(),
      keys: await ctx.db.query("relayKeyEnvelopes").collect(),
    }));
    const retained = await unchanged();
    const { args } = await f.prepare();
    const result = await f.next.runtime.mutation(finish, args) as DeviceReauthResult;
    expect(result).toMatchObject({ deviceId: f.device.deviceId, authSessionId: f.next.sessionId,
      userId: f.userId, authEpoch: 1, keyVersion: 1, bindingRevision: 1, deviceClass: "daemon", challengeId: args.challengeId });
    expect(await unchanged()).toEqual(retained);
    const after = await f.deviceRow();
    expect(after).toEqual({ ...before, bindingRevision: 1, revision: before.revision + 1, updatedAt: after.updatedAt });
    const bindings = await f.world.t.run(async (ctx) => await ctx.db.query("relayDeviceSessions")
      .filter((q) => q.eq(q.field("deviceId"), before._id)).collect());
    expect(bindings).toHaveLength(1);
    expect(bindings[0]?.authSessionId).toBe(f.next.sessionId);
    await expect(f.device.runtime.query(myEnvelopes, {})).rejects.toThrow();
    expect(await f.next.runtime.query(myEnvelopes, {})).toHaveLength(1);
    // Recovery remains strictly later-authority and ambiguous; reauth did not
    // claim that old effects completed or reset their generation fences.
    await expect(f.next.runtime.mutation(mutation("relayCommands:recover"), {
      authority: sampleAuthority(), deviceId: f.device.deviceId, publicId: commandIds[2],
      resultCode: "reauth", state: "ambiguous",
    })).rejects.toThrow();
    expect(await f.next.runtime.mutation(mutation("relayCommands:recover"), {
      authority: sampleAuthority(2), deviceId: f.device.deviceId, publicId: commandIds[2],
      resultCode: "reauth", state: "ambiguous",
    })).toMatchObject({ state: "ambiguous" });
  });

  test("lost successful response reconciles and retries after challenge GC, but only exact proof/session", async () => {
    const f = await fixture();
    const { args } = await f.prepare();
    const result = await f.next.runtime.mutation(finish, args);
    await f.world.t.run(async (ctx) => {
      const challenge = await ctx.db.query("relayBindChallenges").filter((q) => q.eq(q.field("challengeId"), args.challengeId)).unique();
      await ctx.db.delete(challenge!._id);
    });
    expect(await f.next.runtime.mutation(finish, args)).toEqual(result);
    expect(await f.next.runtime.query(status, { deviceId: args.deviceId, challengeId: args.challengeId }))
      .toEqual({ status: "committed", result });
    await expect(f.next.runtime.mutation(finish, { ...args, signature: "A".repeat(86) })).rejects.toThrow();
    const later = await f.newSession();
    expect(await later.runtime.query(status, { deviceId: args.deviceId, challengeId: args.challengeId })).toEqual({ status: "unknown" });
    await expect(later.runtime.mutation(finish, args)).rejects.toThrow();
    // A fresh OTP can recover even if the previous target session expired.
    const replacement = await f.prepare(later.runtime);
    expect((await later.runtime.mutation(finish, replacement.args) as DeviceReauthResult).bindingRevision).toBe(2);
    await expect(f.next.runtime.mutation(finish, args)).rejects.toThrow();
    expect(await f.next.runtime.query(status, { deviceId: args.deviceId, challengeId: args.challengeId })).toEqual({ status: "unknown" });
  });

  test("two concurrent ceremonies have one winner; stale proof never replaces the winner", async () => {
    const f = await fixture();
    const later = await f.newSession();
    const first = await f.prepare();
    const second = await f.prepare(later.runtime);
    const results = await Promise.allSettled([
      f.next.runtime.mutation(finish, first.args), later.runtime.mutation(finish, second.args),
    ]);
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(results.filter((result) => result.status === "rejected")).toHaveLength(1);
    const firstStatus = await f.next.runtime.query(status, { deviceId: first.args.deviceId, challengeId: first.args.challengeId });
    const secondStatus = await later.runtime.query(status, { deviceId: second.args.deviceId, challengeId: second.args.challengeId });
    expect([firstStatus, secondStatus].map((value) => (value as { status: string }).status).sort())
      .toEqual(["committed", "superseded"]);
  });

  test("pending/expired status is read-only and an expired challenge cannot commit", async () => {
    const f = await fixture();
    const { args } = await f.prepare();
    expect(await f.next.runtime.query(status, { deviceId: args.deviceId, challengeId: args.challengeId })).toEqual({ status: "pending" });
    await f.world.t.run(async (ctx) => {
      const row = await ctx.db.query("relayBindChallenges").filter((q) => q.eq(q.field("challengeId"), args.challengeId)).unique();
      await ctx.db.patch(row!._id, { expiresAt: Date.now() - 1 });
    });
    expect(await f.next.runtime.query(status, { deviceId: args.deviceId, challengeId: args.challengeId })).toEqual({ status: "expired" });
    await expect(f.next.runtime.mutation(finish, args)).rejects.toThrow();
    expect(await f.device.runtime.query(myEnvelopes, {})).toEqual([]);
  });

  test("wrong user, session, signing key, bind domain, and device cannot consume a proof", async () => {
    const f = await fixture();
    const { challenge, args } = await f.prepare();
    const outsider = await f.world.enrollUser("other-owner");
    const foreign = await f.newSession(outsider);
    await expect(foreign.runtime.mutation(begin, { deviceId: f.device.deviceId })).rejects.toThrow();
    await expect(foreign.runtime.mutation(finish, args)).rejects.toThrow();
    const otherSession = await f.newSession();
    await expect(otherSession.runtime.mutation(finish, args)).rejects.toThrow();
    const wrongKey = await createDeviceIdentity();
    await expect(f.next.runtime.mutation(finish, { ...args,
      signature: await signCanonicalBase64(wrongKey.signing.privateKey, challenge),
    })).rejects.toThrow();
    await expect(f.next.runtime.mutation(finish, { ...args,
      signature: await signCanonicalBase64(f.device.device.signing.privateKey, { ...challenge, contract: "relay.dev.v1:device-bind" }),
    })).rejects.toThrow();
    await expect(f.next.runtime.mutation(finish, { ...args, deviceId: wrongKey.device })).rejects.toThrow();
    await expect(f.next.runtime.mutation(mutation("relayDevices:finishBind"), args)).rejects.toThrow();
    expect(await f.next.runtime.mutation(finish, args)).toMatchObject({ bindingRevision: 1 });
  });

  test.each([
    ["revocation", { status: "revoked" as const }],
    ["stale epoch", { authEpoch: 2 }],
    ["key version", { keyVersion: 2 }],
    ["device class", { deviceClass: "controller" }],
    ["binding revision", { bindingRevision: 1 }],
    ["signing key", { signingPublicKey: "A".repeat(122) }],
    ["agreement key", { agreementPublicKey: "A".repeat(122) }],
  ])("rejects %s occurring between begin and finish", async (_label, patch) => {
    const f = await fixture();
    const { args } = await f.prepare();
    const device = await f.deviceRow();
    await f.world.t.run(async (ctx) => await ctx.db.patch(device._id, patch));
    await expect(f.next.runtime.mutation(finish, args)).rejects.toThrow();
  });

  test("rejects new session already bound to another device, including a race after begin", async () => {
    const f = await fixture();
    const peer = await f.world.enrollDevice(f.userId, "controller", "other-device");
    await expect(peer.runtime.mutation(begin, { deviceId: f.device.deviceId })).rejects.toThrow();
    const { args } = await f.prepare();
    await f.world.t.run(async (ctx) => {
      const mapping = (await ctx.db.query("relayDeviceSessions").filter((q) => q.eq(q.field("authSessionId"), peer.authSessionId)).unique())!;
      await ctx.db.patch(mapping._id, { authSessionId: f.next.sessionId });
    });
    await expect(f.next.runtime.mutation(finish, args)).rejects.toThrow();
  });

  test("old pending bind stays compatible and cannot add a second device to a session", async () => {
    const f = await fixture();
    const fresh = await createDeviceIdentity();
    await f.device.runtime.mutation(mutation("relayDevices:register"), {
      agreementPublicKey: fresh.publicKeys.agreement, signingPublicKey: fresh.publicKeys.signing,
      deviceId: fresh.device, deviceClass: "controller", label: "pending",
    });
    const challenge = await f.device.runtime.mutation(mutation("relayDevices:beginBind"), { deviceId: fresh.device }) as { challengeId: string; nonce: string };
    await expect(f.device.runtime.mutation(mutation("relayDevices:finishBind"), {
      deviceId: fresh.device, challengeId: challenge.challengeId,
      signature: await signCanonicalBase64(fresh.signing.privateKey, { ...challenge, contract: "relay.dev.v1:device-bind" }),
    })).rejects.toThrow();
    await expect(f.next.runtime.mutation(begin, { deviceId: fresh.device })).rejects.toThrow();
    const rows = await f.device.runtime.query(list, {}) as Record<string, unknown>[];
    expect(rows).toHaveLength(2);
    for (const row of rows) expect(Object.keys(row).sort()).toEqual([
      "agreementPublicKey", "deviceClass", "deviceId", "keyVersion", "label", "online", "signingPublicKey", "status",
    ]);
  });

  test("stable verified subject uses provider's user/session parsing and disabled subjects fail", async () => {
    const f = await fixture();
    expect(await f.next.runtime.query(currentSubject, {})).toMatchObject({ userId: f.userId, authEpoch: 1, status: "active" });
    await f.world.t.run(async (ctx) => {
      const subject = (await ctx.db.query("relaySubjects").filter((q) => q.eq(q.field("userId"), f.userId)).unique())!;
      await ctx.db.patch(subject._id, { status: "disabled" });
    });
    await expect(f.next.runtime.query(currentSubject, {})).rejects.toThrow();
    await expect(f.next.runtime.mutation(begin, { deviceId: f.device.deviceId })).rejects.toThrow();
  });

  test("heartbeat and unrelated revision updates do not stale a binding challenge", async () => {
    const f = await fixture();
    const { args } = await f.prepare();
    const device = await f.deviceRow();
    await f.world.t.run(async (ctx) => await ctx.db.patch(device._id, { revision: device.revision + 1 }));
    expect(await f.next.runtime.mutation(finish, args)).toMatchObject({ bindingRevision: 1 });
  });

  test.each([
    ["device epoch", { authEpoch: 2 }], ["revoked device", { status: "revoked" as const }],
    ["key version", { keyVersion: 2 }], ["class", { deviceClass: "controller" }],
    ["signing key", { signingPublicKey: "A".repeat(122) }],
    ["agreement key", { agreementPublicKey: "A".repeat(122) }],
  ])("committed replay refuses changed %s without reconstructing old authority", async (_label, patch) => {
    const f = await fixture();
    const { args } = await f.prepare();
    await f.next.runtime.mutation(finish, args);
    const row = await f.deviceRow();
    await f.world.t.run(async (ctx) => await ctx.db.patch(row._id, patch));
    await expect(f.next.runtime.mutation(finish, args)).rejects.toThrow();
    expect(await f.next.runtime.query(status, { deviceId: args.deviceId, challengeId: args.challengeId }))
      .not.toMatchObject({ status: "committed" });
  });

  test("subject epoch rotation rejects both unfinished and committed reauth proofs", async () => {
    const f = await fixture();
    const committed = await f.prepare();
    await f.next.runtime.mutation(finish, committed.args);
    const pending = await f.prepare();
    await f.world.t.run(async (ctx) => {
      const subject = (await ctx.db.query("relaySubjects").filter((q) => q.eq(q.field("userId"), f.userId)).unique())!;
      await ctx.db.patch(subject._id, { authEpoch: 2 });
    });
    await expect(f.next.runtime.mutation(finish, committed.args)).rejects.toThrow();
    await expect(f.next.runtime.mutation(finish, pending.args)).rejects.toThrow();
  });

  test("reauth proof cannot replay across purpose even on a pending device", async () => {
    const f = await fixture();
    const { challenge, args } = await f.prepare();
    const row = await f.deviceRow();
    await f.world.t.run(async (ctx) => await ctx.db.patch(row._id, { status: "pending" }));
    const bindSignature = await signCanonicalBase64(f.device.device.signing.privateKey, {
      challengeId: challenge.challengeId, nonce: challenge.nonce, contract: "relay.dev.v1:device-bind",
    });
    await expect(f.next.runtime.mutation(mutation("relayDevices:finishBind"), { ...args, signature: bindSignature })).rejects.toThrow();
  });

  test("safe integer ceiling never overflows; last successful transition remains reconcilable", async () => {
    const f = await fixture();
    const row = await f.deviceRow();
    await f.world.t.run(async (ctx) => await ctx.db.patch(row._id, {
      bindingRevision: Number.MAX_SAFE_INTEGER - 1, revision: Number.MAX_SAFE_INTEGER - 1,
    }));
    const { args } = await f.prepare();
    const result = await f.next.runtime.mutation(finish, args);
    expect(result).toMatchObject({ bindingRevision: Number.MAX_SAFE_INTEGER });
    expect(await f.next.runtime.mutation(finish, args)).toEqual(result);
    expect(await f.next.runtime.query(status, { deviceId: args.deviceId, challengeId: args.challengeId })).toEqual({ status: "committed", result });
    await expect(f.next.runtime.mutation(begin, { deviceId: f.device.deviceId })).rejects.toThrow();
  });

  test("corrupt multiple legacy mappings fail closed without partial deletion", async () => {
    const f = await fixture();
    const { args } = await f.prepare();
    await f.world.t.run(async (ctx) => {
      const mapping = (await ctx.db.query("relayDeviceSessions").unique())!;
      await ctx.db.insert("relayDeviceSessions", { authEpoch: mapping.authEpoch, authSessionId: f.next.sessionId,
        boundAt: mapping.boundAt, deviceId: mapping.deviceId, userId: mapping.userId });
    });
    await expect(f.next.runtime.mutation(finish, args)).rejects.toThrow();
    expect(await f.world.t.run(async (ctx) => await ctx.db.query("relayDeviceSessions").collect())).toHaveLength(2);
  });

  test("committed receipts refuse a second device mapping even after challenge GC", async () => {
    const f = await fixture();
    const { args } = await f.prepare();
    await f.next.runtime.mutation(finish, args);
    await f.world.t.run(async (ctx) => {
      const mapping = (await ctx.db.query("relayDeviceSessions").unique())!;
      await ctx.db.insert("relayDeviceSessions", {
        authEpoch: mapping.authEpoch, authSessionId: f.device.authSessionId,
        boundAt: mapping.boundAt, deviceId: mapping.deviceId, userId: mapping.userId,
      });
      const challenge = (await ctx.db.query("relayBindChallenges")
        .filter((q) => q.eq(q.field("challengeId"), args.challengeId)).unique())!;
      await ctx.db.delete(challenge._id);
    });
    const before = await f.world.t.run(async (ctx) => await ctx.db.query("relayDeviceSessions").collect());
    await expect(f.next.runtime.mutation(finish, args)).rejects.toThrow();
    expect(await f.next.runtime.query(status, { deviceId: args.deviceId, challengeId: args.challengeId }))
      .toEqual({ status: "unknown" });
    expect(await f.world.t.run(async (ctx) => await ctx.db.query("relayDeviceSessions").collect())).toEqual(before);
  });
});
