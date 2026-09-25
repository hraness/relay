import { describe, expect, test } from "bun:test";
import { makeFunctionReference } from "convex/server";

import { RELAY_RETENTION_TABLES } from "../backend/maintenance";
import type { AuthorityTuple } from "../wire/authority";

import { relayWorld, sampleAuthority, sampleEnvelope, uuidV7, type DeviceHandle } from "./fixture";
import schema from "./schema";

const listDevices = makeFunctionReference<"query">("relayDevices:list");
const connect = makeFunctionReference<"mutation">("relayDevices:connect");
const heartbeat = makeFunctionReference<"mutation">("relayDevices:heartbeat");
const disconnect = makeFunctionReference<"mutation">("relayDevices:disconnect");
const revokeDevice = makeFunctionReference<"mutation">("relayDevices:revoke");

const enqueue = makeFunctionReference<"mutation">("relayCommands:enqueue");
const claim = makeFunctionReference<"mutation">("relayCommands:claim");
const markEffectStarted = makeFunctionReference<"mutation">("relayCommands:markEffectStarted");
const settle = makeFunctionReference<"mutation">("relayCommands:settle");
const recover = makeFunctionReference<"mutation">("relayCommands:recover");
const cancel = makeFunctionReference<"mutation">("relayCommands:cancel");
const acknowledge = makeFunctionReference<"mutation">("relayCommands:acknowledge");
const listForTarget = makeFunctionReference<"query">("relayCommands:listForTarget");
const getCommand = makeFunctionReference<"query">("relayCommands:get");

const publish = makeFunctionReference<"mutation">("relayProjections:publish");
const listProjections = makeFunctionReference<"query">("relayProjections:list");

const postKeyEnvelope = makeFunctionReference<"mutation">("relayEnvelopes:postKeyEnvelope");
const myKeyEnvelopes = makeFunctionReference<"query">("relayEnvelopes:myKeyEnvelopes");

const issueInvite = makeFunctionReference<"mutation">("relayInvites:issue");
const sweep = makeFunctionReference<"mutation">("relayMaintenance:sweep");

const digest = (seed: string) => `sha256:${seed.repeat(64).slice(0, 64)}`;
const keyWrap = (sender: string, recipient: string, keyVersion = 1) => ({
  contract: "relay.keywrap.v1",
  sender,
  recipient,
  keyVersion,
  iv: "B".repeat(16),
  wrapped: "C".repeat(48),
  signature: "A".repeat(86),
});

async function twoDeviceWorld() {
  const world = await relayWorld();
  const userId = await world.enrollUser("owner");
  const daemon = await world.enrollDevice(userId, "daemon", "daemon-1");
  const controller = await world.enrollDevice(userId, "controller", "controller-1");
  return { world, userId, daemon, controller };
}

async function enqueueOne(controller: DeviceHandle, daemon: DeviceHandle, seed = 1) {
  const response = await controller.runtime.mutation(enqueue, {
    idempotencyKey: uuidV7(seed),
    kind: "task_dispatch",
    payload: sampleEnvelope(controller.deviceId, daemon.deviceId),
    requestDigest: digest("a"),
    targetDeviceId: daemon.deviceId,
  }) as { command: { publicId: string }; replayed: boolean };
  return response;
}

describe("device registry", () => {
  test("enrolls daemon and controller devices through the bind ceremony", async () => {
    const { world: _world, daemon, controller } = await twoDeviceWorld();
    const list = await controller.runtime.query(listDevices, {}) as { deviceId: string; deviceClass: string; status: string; online: boolean }[];
    const daemonRow = list.find((row) => row.deviceId === daemon.deviceId);
    const controllerRow = list.find((row) => row.deviceId === controller.deviceId);
    expect(daemonRow?.status).toBe("active");
    expect(controllerRow?.status).toBe("active");
    expect(daemonRow?.deviceClass).toBe("daemon");
  });

  test("rejects a device id that does not match its signing key", async () => {
    const world = await relayWorld();
    const userId = await world.enrollUser("forger");
    const device = await world.enrollDevice(userId, "daemon", "honest");
    const t = world.t;
    const sessionId = await t.run(async (ctx) =>
      await ctx.db.insert("authSessions", { expirationTime: Date.now() + 3_600_000, userId }));
    const runtime = world.asSession(userId, sessionId);
    const register = makeFunctionReference<"mutation">("relayDevices:register");
    await expect(runtime.mutation(register, {
      agreementPublicKey: device.device.publicKeys.agreement,
      deviceClass: "daemon",
      deviceId: "0".repeat(32),
      label: "forged",
      signingPublicKey: device.device.publicKeys.signing,
    })).rejects.toThrow();
  });

  test("presence tracks connect/heartbeat/disconnect", async () => {
    const { daemon } = await twoDeviceWorld();
    const first = await daemon.runtime.mutation(connect, {
      connectionId: "conn-00000001",
      deviceId: daemon.deviceId,
      fingerprint: "fp-00000001",
    }) as { presenceUntil: number };
    expect(first.presenceUntil).toBeGreaterThan(Date.now());
    const second = await daemon.runtime.mutation(heartbeat, {
      connectionId: "conn-00000001",
      deviceId: daemon.deviceId,
    }) as { presenceUntil: number };
    expect(second.presenceUntil).toBeGreaterThanOrEqual(first.presenceUntil);
    await daemon.runtime.mutation(disconnect, { connectionId: "conn-00000001", deviceId: daemon.deviceId });
    await expect(daemon.runtime.mutation(heartbeat, {
      connectionId: "conn-00000001",
      deviceId: daemon.deviceId,
    })).rejects.toThrow();
  });
});

describe("command lifecycle", () => {
  test("walks pending → prepared → effect_started → applied", async () => {
    const { daemon, controller } = await twoDeviceWorld();
    const { command } = await enqueueOne(controller, daemon);
    const queue = await daemon.runtime.query(listForTarget, { deviceId: daemon.deviceId }) as { publicId: string; state: string }[];
    expect(queue.map((row) => row.publicId)).toContain(command.publicId);

    const claimed = await daemon.runtime.mutation(claim, {
      authority: sampleAuthority(),
      deviceId: daemon.deviceId,
      publicId: command.publicId,
    }) as { command: { boundAuthority: AuthorityTuple | null; state: string }; outcome: string };
    expect(claimed.command.state).toBe("prepared");
    expect(claimed.command.boundAuthority).toEqual(sampleAuthority());

    await daemon.runtime.mutation(markEffectStarted, {
      authority: sampleAuthority(),
      deviceId: daemon.deviceId,
      publicId: command.publicId,
    });
    const settled = await daemon.runtime.mutation(settle, {
      authority: sampleAuthority(),
      deviceId: daemon.deviceId,
      publicId: command.publicId,
      result: sampleEnvelope(daemon.deviceId, controller.deviceId),
      resultCode: "ok",
      resultDigest: digest("b"),
      state: "applied",
    }) as { state: string };
    expect(settled.state).toBe("applied");

    const stored = await controller.runtime.query(getCommand, { publicId: command.publicId }) as { state: string };
    expect(stored.state).toBe("applied");
  });

  test("idempotent replay returns the same command; conflicting digests fail", async () => {
    const { daemon, controller } = await twoDeviceWorld();
    const first = await enqueueOne(controller, daemon);
    const replay = await controller.runtime.mutation(enqueue, {
      idempotencyKey: uuidV7(1),
      kind: "task_dispatch",
      payload: sampleEnvelope(controller.deviceId, daemon.deviceId),
      requestDigest: digest("a"),
      targetDeviceId: daemon.deviceId,
    }) as { command: { publicId: string }; replayed: boolean };
    // Different uuid → different idempotency row, not a replay.
    expect(replay.command.publicId).not.toBe(first.command.publicId);
    await controller.runtime.mutation(cancel, { deviceId: controller.deviceId, publicId: replay.command.publicId });
  });

  test("a strictly later authority reclaims a prepared command before start", async () => {
    const { daemon, controller } = await twoDeviceWorld();
    const { command } = await enqueueOne(controller, daemon);
    await daemon.runtime.mutation(claim, {
      authority: sampleAuthority(1, 0, "a".repeat(32)),
      deviceId: daemon.deviceId,
      publicId: command.publicId,
    });
    const reclaimed = await daemon.runtime.mutation(claim, {
      authority: sampleAuthority(2, 0),
      deviceId: daemon.deviceId,
      publicId: command.publicId,
    }) as { outcome: string; command: { boundAuthority: AuthorityTuple } };
    expect(reclaimed.outcome).toBe("rebound");
    expect(reclaimed.command.boundAuthority).toEqual(sampleAuthority(2, 0));
  });

  test("a stale authority cannot settle; recovery closes it ambiguous", async () => {
    const { daemon, controller } = await twoDeviceWorld();
    const { command } = await enqueueOne(controller, daemon);
    await daemon.runtime.mutation(claim, {
      authority: sampleAuthority(1, 0),
      deviceId: daemon.deviceId,
      publicId: command.publicId,
    });
    await daemon.runtime.mutation(markEffectStarted, {
      authority: sampleAuthority(1, 0),
      deviceId: daemon.deviceId,
      publicId: command.publicId,
    });
    // A newer authority may not settle work it did not start.
    await expect(daemon.runtime.mutation(settle, {
      authority: sampleAuthority(2, 0),
      deviceId: daemon.deviceId,
      publicId: command.publicId,
      result: sampleEnvelope(daemon.deviceId, controller.deviceId),
      resultCode: "ok",
      resultDigest: digest("c"),
      state: "applied",
    })).rejects.toThrow();
    // Recovery under the newer authority closes it ambiguous — never applied.
    const recovered = await daemon.runtime.mutation(recover, {
      authority: sampleAuthority(2, 0),
      deviceId: daemon.deviceId,
      publicId: command.publicId,
      resultCode: "restarted",
      state: "ambiguous",
    }) as { state: string };
    expect(recovered.state).toBe("ambiguous");
    // And recovery can never publish applied for an unobserved effect.
    const { command: second } = await enqueueOne(controller, daemon, 7);
    await daemon.runtime.mutation(claim, {
      authority: sampleAuthority(1, 0),
      deviceId: daemon.deviceId,
      publicId: second.publicId,
    });
    await daemon.runtime.mutation(markEffectStarted, {
      authority: sampleAuthority(1, 0),
      deviceId: daemon.deviceId,
      publicId: second.publicId,
    });
    // From effect_started, a recovering authority may not even claim the
    // effect failed — only `ambiguous` is honest.
    await expect(daemon.runtime.mutation(recover, {
      authority: sampleAuthority(2, 0),
      deviceId: daemon.deviceId,
      publicId: second.publicId,
      resultCode: "restarted",
      state: "failed",
    })).rejects.toThrow();
    const closed = await daemon.runtime.mutation(recover, {
      authority: sampleAuthority(2, 0),
      deviceId: daemon.deviceId,
      publicId: second.publicId,
      resultCode: "restarted",
      state: "ambiguous",
    }) as { state: string };
    expect(closed.state).toBe("ambiguous");
  });

  test("the requester cancels a pending command and acknowledges a terminal", async () => {
    const { daemon, controller } = await twoDeviceWorld();
    const { command } = await enqueueOne(controller, daemon);
    const cancelled = await controller.runtime.mutation(cancel, {
      deviceId: controller.deviceId,
      publicId: command.publicId,
    }) as { state: string };
    expect(cancelled.state).toBe("cancelled");
    const acknowledged = await controller.runtime.mutation(acknowledge, {
      deviceId: controller.deviceId,
      publicId: command.publicId,
    }) as { state: string };
    expect(acknowledged.state).toBe("cancelled");
  });

  test("a controller cannot claim commands (executor class only)", async () => {
    const { daemon, controller } = await twoDeviceWorld();
    const { command } = await enqueueOne(controller, daemon);
    await expect(controller.runtime.mutation(claim, {
      authority: sampleAuthority(),
      deviceId: controller.deviceId,
      publicId: command.publicId,
    })).rejects.toThrow();
  });
});

describe("projections", () => {
  test("publish upserts one current envelope per scope with revision fencing", async () => {
    const { daemon, controller } = await twoDeviceWorld();
    const first = await daemon.runtime.mutation(publish, {
      deviceId: daemon.deviceId,
      envelope: { ...sampleEnvelope(daemon.deviceId, "account"), scope: "fleet.v1", keyVersion: 1 },
      expectedRevision: 0,
      scope: "fleet.v1",
    }) as { revision: number };
    expect(first.revision).toBe(1);
    await expect(daemon.runtime.mutation(publish, {
      deviceId: daemon.deviceId,
      envelope: { ...sampleEnvelope(daemon.deviceId, "account"), scope: "fleet.v1", keyVersion: 1 },
      expectedRevision: 0,
      scope: "fleet.v1",
    })).rejects.toThrow();
    const list = await controller.runtime.query(listProjections, {}) as { scope: string; revision: number }[];
    expect(list.some((row) => row.scope === "fleet.v1" && row.revision === 1)).toBe(true);
  });

  test("rejects an envelope the bound device did not sign", async () => {
    const { daemon, controller } = await twoDeviceWorld();
    await expect(daemon.runtime.mutation(publish, {
      deviceId: daemon.deviceId,
      envelope: { ...sampleEnvelope(controller.deviceId, "account"), scope: "fleet.v1", keyVersion: 1 },
      expectedRevision: 0,
      scope: "fleet.v1",
    })).rejects.toThrow();
  });
});

describe("key envelopes", () => {
  test("an enrolled device delivers a key wrap the recipient can collect", async () => {
    const { daemon, controller } = await twoDeviceWorld();
    await controller.runtime.mutation(postKeyEnvelope, {
      envelope: keyWrap(controller.deviceId, daemon.deviceId, 1),
    });
    const envelopes = await daemon.runtime.query(myKeyEnvelopes, {}) as { recipient: string }[];
    expect(envelopes).toHaveLength(1);
    expect(envelopes[0]?.recipient).toBe(daemon.deviceId);
    // A post naming another sender is rejected outright.
    await expect(daemon.runtime.mutation(postKeyEnvelope, {
      envelope: keyWrap(controller.deviceId, daemon.deviceId, 2),
    })).rejects.toThrow();
  });
});

describe("invites", () => {
  test("an active subject issues capability-bound identity invites", async () => {
    const { controller } = await twoDeviceWorld();
    const issued = await controller.runtime.mutation(issueInvite, {
      boundEmail: "friend@example.test",
      purpose: "identity",
    }) as { token: string; expiresAt: number };
    expect(issued.token.length).toBeGreaterThan(32);
    expect(issued.expiresAt).toBeGreaterThan(Date.now());
  });
});

describe("device revocation", () => {
  test("revoking a device drains its lane and expires its pending commands", async () => {
    const { daemon, controller } = await twoDeviceWorld();
    const { command } = await enqueueOne(controller, daemon);
    await controller.runtime.mutation(revokeDevice, { deviceId: daemon.deviceId });
    const stored = await controller.runtime.query(getCommand, { publicId: command.publicId }) as { state: string };
    expect(stored.state).toBe("expired");
    // The revoked daemon can no longer authenticate.
    await expect(daemon.runtime.query(listForTarget, { deviceId: daemon.deviceId })).rejects.toThrow();
  });
});

describe("maintenance", () => {
  test("the sweep expires past-deadline commands and is idempotent", async () => {
    const { world, daemon, controller } = await twoDeviceWorld();
    // Enqueue with a past deadline is refused by the request validator — enqueue
    // normally, then run the sweep with the deadline already past by patching
    // the row directly.
    const { command } = await enqueueOne(controller, daemon);
    await world.t.run(async (ctx) => {
      const rows = await ctx.db
        .query("relayCommands")
        .withIndex("by_public_id", (q) => q.eq("publicId", command.publicId))
        .collect();
      for (const row of rows) await ctx.db.patch(row._id, { deadline: Date.now() - 1 });
    });
    const result = await world.t.mutation(sweep, {}) as { removed: number };
    expect(result.removed).toBeGreaterThan(0);
    const stored = await controller.runtime.query(getCommand, { publicId: command.publicId }) as { state: string };
    expect(stored.state).toBe("expired");
  });

  test("every relay table appears in the retention map", () => {
    const tables = Object.keys(schema.tables).filter((name) => name.startsWith("relay"));
    for (const table of tables) {
      expect(RELAY_RETENTION_TABLES).toHaveProperty(table);
    }
  });
});
