import { describe, expect, test } from "bun:test";

import {
  commandTransitionDisposition,
  compareDeviceAuthority,
  deviceCommandAuthorityTransitionDisposition,
  deviceCommandRecoveryAdmitted,
  deviceCommandRecoveryReplayAdmitted,
  isTerminalCommandState,
  parseAuthorityTuple,
} from "./authority";
import {
  decodeBase64Url,
  encodeBase64Url,
  exactKeys,
  isBase64Url,
} from "./encoding";
import { isKeyWrapEnvelope, isSignedEnvelope } from "./envelope";
import { isDeviceId, isDigest, isPublicId, isUuidV7, isWireKind, isWireNamespace, uuidV7, uuidV7Timestamp } from "./ids";
import { parseRelayErrorData } from "./errors";

const deviceA = "a".repeat(32);
const deviceB = "b".repeat(32);

const authority = (generation: number, fence: number, bootId = "b".repeat(32)) =>
  ({ bootGeneration: generation, bootId, fence });

describe("encoding", () => {
  test("round-trips canonical base64url", () => {
    const bytes = crypto.getRandomValues(new Uint8Array(33));
    const encoded = encodeBase64Url(bytes);
    expect(decodeBase64Url(encoded, 64)).toEqual(bytes);
  });

  test("rejects padding, bad chars, non-canonical trailing bits, and length 4k+1", () => {
    expect(isBase64Url("AAA=", 8)).toBe(false);
    expect(isBase64Url("AA!A", 8)).toBe(false);
    // "AB" is 2 chars: last sextet 'B' has low bits set → non-canonical.
    expect(isBase64Url("AB", 8)).toBe(false);
    expect(isBase64Url("AA", 8)).toBe(true);
    expect(isBase64Url("AAAAA", 8)).toBe(false);
  });

  test("enforces the character bound", () => {
    expect(isBase64Url("AA", 1)).toBe(false);
  });
});

describe("identifiers", () => {
  test("device ids are 32 lowercase hex", () => {
    expect(isDeviceId(deviceA)).toBe(true);
    expect(isDeviceId(deviceA.toUpperCase())).toBe(false);
    expect(isDeviceId("x".repeat(32))).toBe(false);
  });

  test("digests carry the sha256: prefix", () => {
    expect(isDigest(`sha256:${"0".repeat(64)}`)).toBe(true);
    expect(isDigest("0".repeat(64))).toBe(false);
  });

  test("uuid v7 pins version and variant bits", () => {
    const key = "018f3c5a-1a2b-7c3d-8e4f-0123456789ab";
    expect(isUuidV7(key)).toBe(true);
    expect(uuidV7Timestamp(key)).toBe(0x018f3c5a1a2b);
    expect(isUuidV7("018f3c5a-1a2b-4c3d-8e4f-0123456789ab")).toBe(false);
  });

  test("the generator mints parseable uuids carrying the timestamp", () => {
    const key = uuidV7(1_700_000_000_000);
    expect(isUuidV7(key)).toBe(true);
    expect(uuidV7Timestamp(key)).toBe(1_700_000_000_000);
    expect(uuidV7(1_700_000_000_000)).not.toBe(key);
  });

  test("namespaces end in a version segment", () => {
    expect(isWireNamespace("relay.dev.v1")).toBe(true);
    expect(isWireNamespace("xcb.relay.v2")).toBe(true);
    expect(isWireNamespace("relay.dev")).toBe(false);
    expect(isWireNamespace("Relay.dev.v1")).toBe(false);
  });

  test("command kinds are snake_case", () => {
    expect(isWireKind("task_dispatch")).toBe(true);
    expect(isWireKind("task-dispatch")).toBe(false);
  });
});

describe("envelopes", () => {
  const envelope = {
    contract: "relay.dev.v1",
    sender: deviceA,
    recipient: "account",
    scope: "projections.v1",
    keyVersion: 1,
    iv: "B".repeat(16),
    ciphertext: "C".repeat(48),
    signature: "A".repeat(86),
  };

  test("accepts a well-formed signed envelope", () => {
    expect(isSignedEnvelope(envelope, 65_536)).toBe(true);
  });

  test("rejects unknown fields and missing fields", () => {
    expect(isSignedEnvelope({ ...envelope, extra: 1 }, 65_536)).toBe(false);
    const { signature: _dropped, ...unsigned } = envelope;
    expect(isSignedEnvelope(unsigned, 65_536)).toBe(false);
  });

  test("rejects malformed senders and recipients", () => {
    expect(isSignedEnvelope({ ...envelope, sender: "x" }, 65_536)).toBe(false);
    expect(isSignedEnvelope({ ...envelope, recipient: "somebody" }, 65_536)).toBe(false);
    expect(isSignedEnvelope({ ...envelope, recipient: deviceB }, 65_536)).toBe(true);
  });

  const wrap = {
    contract: "relay.keywrap.v1",
    sender: deviceA,
    recipient: deviceB,
    keyVersion: 1,
    iv: "B".repeat(16),
    wrapped: "C".repeat(48),
    signature: "A".repeat(86),
  };

  test("key-wrap envelopes require distinct parties", () => {
    expect(isKeyWrapEnvelope(wrap)).toBe(true);
    expect(isKeyWrapEnvelope({ ...wrap, recipient: deviceA })).toBe(false);
    expect(isKeyWrapEnvelope({ ...wrap, contract: "relay.dev.v1" })).toBe(false);
  });
});

describe("authority tuples", () => {
  test("parse requires exact fields", () => {
    expect(parseAuthorityTuple(authority(1, 0))).toEqual(authority(1, 0));
    expect(parseAuthorityTuple({ ...authority(1, 0), extra: 1 })).toBeNull();
    expect(parseAuthorityTuple({ ...authority(1, 0), bootGeneration: 0 })).toBeNull();
    expect(parseAuthorityTuple({ ...authority(1, 0), bootId: "x" })).toBeNull();
  });

  test("orders by generation, then boot id, then fence", () => {
    expect(compareDeviceAuthority(authority(1, 0), authority(2, 0))).toBe("before");
    expect(compareDeviceAuthority(authority(2, 0), authority(1, 0))).toBe("after");
    expect(compareDeviceAuthority(authority(1, 0), authority(1, 1))).toBe("before");
    expect(compareDeviceAuthority(authority(1, 1), authority(1, 1))).toBe("equal");
    // Distinct boot ids at equal generation: the fence still orders them.
    expect(compareDeviceAuthority(authority(1, 0, "a".repeat(32)), authority(1, 1, "b".repeat(32)))).toBe("before");
    expect(compareDeviceAuthority(authority(1, 0, "b".repeat(32)), authority(1, 0, "a".repeat(32)))).toBe("after");
  });
});

describe("command lifecycle", () => {
  test("follows the closed transition set", () => {
    expect(commandTransitionDisposition("pending", "prepared").kind).toBe("applied");
    expect(commandTransitionDisposition("pending", "applied").kind).toBe("rejected");
    expect(commandTransitionDisposition("prepared", "effect_started").kind).toBe("applied");
    expect(commandTransitionDisposition("effect_started", "applied").kind).toBe("applied");
    expect(commandTransitionDisposition("effect_started", "ambiguous").kind).toBe("applied");
    expect(commandTransitionDisposition("applied", "pending").kind).toBe("rejected");
    expect(commandTransitionDisposition("applied", "applied").kind).toBe("replay");
  });

  test("every terminal state is closed", () => {
    for (const state of ["applied", "failed", "ambiguous", "cancelled", "expired"] as const) {
      expect(isTerminalCommandState(state)).toBe(true);
    }
    expect(isTerminalCommandState("prepared")).toBe(false);
  });

  test("claims bind authority; a strictly later authority reclaims only before start", () => {
    const claimed = deviceCommandAuthorityTransitionDisposition({
      boundAuthority: null,
      next: "prepared",
      requestedAuthority: authority(1, 0),
      state: "pending",
    });
    expect(claimed.kind).toBe("applied");

    const rebound = deviceCommandAuthorityTransitionDisposition({
      boundAuthority: authority(1, 0),
      next: "prepared",
      requestedAuthority: authority(2, 0),
      state: "prepared",
    });
    expect(rebound.kind).toBe("rebound");

    const stale = deviceCommandAuthorityTransitionDisposition({
      boundAuthority: authority(2, 0),
      next: "prepared",
      requestedAuthority: authority(1, 0),
      state: "prepared",
    });
    expect(stale.kind).toBe("rejected");
    if (stale.kind === "rejected") expect(stale.reason).toBe("stale_authority");

    // Once started, only the bound authority may proceed — a newer boot
    // is bound_authority-rejected on the settlement path.
    const settled = deviceCommandAuthorityTransitionDisposition({
      boundAuthority: authority(1, 0),
      next: "applied",
      requestedAuthority: authority(2, 0),
      state: "effect_started",
    });
    expect(settled.kind).toBe("rejected");
  });

  test("recovery admits only later authorities and only honest terminals", () => {
    expect(deviceCommandRecoveryAdmitted({
      recoveryAuthority: authority(2, 0),
      staleAuthority: authority(1, 0),
      state: "effect_started",
      terminalState: "ambiguous",
    })).toBe(true);
    expect(deviceCommandRecoveryAdmitted({
      recoveryAuthority: authority(2, 0),
      staleAuthority: authority(1, 0),
      state: "effect_started",
      terminalState: "applied",
    })).toBe(false);
    expect(deviceCommandRecoveryAdmitted({
      recoveryAuthority: authority(1, 0),
      staleAuthority: authority(1, 0),
      state: "prepared",
      terminalState: "failed",
    })).toBe(false);
    expect(deviceCommandRecoveryAdmitted({
      recoveryAuthority: authority(2, 0),
      staleAuthority: authority(1, 0),
      state: "prepared",
      terminalState: "failed",
    })).toBe(true);
  });

  test("recovery replays only the writing or intervening authority", () => {
    expect(deviceCommandRecoveryReplayAdmitted({
      boundAuthority: authority(2, 0),
      recoveryAuthority: authority(2, 0),
      staleAuthority: authority(1, 0),
    })).toBe(true);
    expect(deviceCommandRecoveryReplayAdmitted({
      boundAuthority: authority(2, 0),
      recoveryAuthority: authority(3, 0),
      staleAuthority: authority(1, 0),
    })).toBe(true);
    expect(deviceCommandRecoveryReplayAdmitted({
      boundAuthority: authority(3, 0),
      recoveryAuthority: authority(2, 0),
      staleAuthority: authority(1, 0),
    })).toBe(false);
  });
});

describe("error vocabulary", () => {
  test("parses only closed shapes", () => {
    expect(parseRelayErrorData({ code: "unauthenticated" })).toEqual({ code: "unauthenticated" });
    expect(parseRelayErrorData({ code: "unknown-command", command: "ab".repeat(8) })).toEqual({ code: "unknown-command", command: "ab".repeat(8) });
    expect(parseRelayErrorData({ code: "unknown-command", command: "not hex!" })).toBeNull();
    expect(parseRelayErrorData({ code: "unauthenticated", extra: 1 })).toBeNull();
    expect(parseRelayErrorData({ code: "arbitrary" })).toBeNull();
    expect(parseRelayErrorData("rate-limited")).toBeNull();
  });
});

describe("exact keys", () => {
  test("rejects extra and missing fields", () => {
    expect(exactKeys({ a: 1, b: 2 }, ["a", "b"])).toBe(true);
    expect(exactKeys({ a: 1, b: 2, c: 3 }, ["a", "b"])).toBe(false);
    expect(exactKeys({ a: 1 }, ["a", "b"])).toBe(false);
    expect(exactKeys([], ["a"])).toBe(false);
    expect(exactKeys(null, [])).toBe(false);
  });
});
