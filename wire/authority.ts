/** Authority tuples and the device-command lifecycle reducer — the pure
 * admission policy every layer enforces. A daemon presents its own boot
 * authority (`bootGeneration`, `bootId`, `fence`); the relay binds a command
 * to exactly one authority at `prepare` and only a strictly later authority
 * may take it over before an effect has begun. An effect that may already
 * have begun is quarantined as `ambiguous`, never `applied`. */

import { exactKeys, isSafeNonNegativeInteger, isSafePositiveInteger } from "./encoding";
import { isOpaqueIdentifier } from "./ids";

export type AuthorityTuple = Readonly<{
  bootGeneration: number;
  bootId: string;
  fence: number;
}>;

export function parseAuthorityTuple(value: unknown): AuthorityTuple | null {
  if (!exactKeys(value, ["bootGeneration", "bootId", "fence"])) return null;
  if (
    !isSafePositiveInteger(value.bootGeneration)
    || !isOpaqueIdentifier(value.bootId)
    || !isSafeNonNegativeInteger(value.fence)
  ) return null;
  return {
    bootGeneration: value.bootGeneration,
    bootId: value.bootId,
    fence: value.fence,
  };
}

export type CommandState =
  | "pending"
  | "prepared"
  | "effect_started"
  | "applied"
  | "failed"
  | "ambiguous"
  | "cancelled"
  | "expired";

export const COMMAND_STATES = Object.freeze([
  "pending",
  "prepared",
  "effect_started",
  "applied",
  "failed",
  "ambiguous",
  "cancelled",
  "expired",
] as const satisfies readonly CommandState[]);

export const TERMINAL_COMMAND_STATES = Object.freeze([
  "applied",
  "failed",
  "ambiguous",
  "cancelled",
  "expired",
] as const satisfies readonly CommandState[]);

export function isTerminalCommandState(state: CommandState): boolean {
  return (TERMINAL_COMMAND_STATES as readonly CommandState[]).includes(state);
}

export type CommandTransitionDisposition =
  | Readonly<{ kind: "applied"; next: CommandState }>
  | Readonly<{ kind: "replay"; next: CommandState }>
  | Readonly<{ kind: "rejected"; reason: "terminal" | "invalid_transition" }>;

const transitions: Readonly<Record<CommandState, readonly CommandState[]>> = {
  ambiguous: [],
  applied: [],
  cancelled: [],
  effect_started: ["applied", "failed", "ambiguous"],
  expired: [],
  failed: [],
  pending: ["prepared", "cancelled", "expired"],
  prepared: ["effect_started", "cancelled", "expired"],
};

export function commandTransitionDisposition(
  current: CommandState,
  next: CommandState,
): CommandTransitionDisposition {
  if (current === next) return { kind: "replay", next };
  const allowed = transitions[current];
  if (allowed.includes(next)) return { kind: "applied", next };
  return {
    kind: "rejected",
    reason: allowed.length === 0 ? "terminal" : "invalid_transition",
  };
}

// Boot authority ordering ------------------------------------------------------

export type DeviceAuthorityOrder = "before" | "equal" | "after";

export function compareDeviceAuthority(
  left: AuthorityTuple,
  right: AuthorityTuple,
): DeviceAuthorityOrder {
  if (left.bootGeneration !== right.bootGeneration) {
    return left.bootGeneration < right.bootGeneration ? "before" : "after";
  }
  if (left.bootId !== right.bootId) {
    // Two distinct boots of the same generation are incomparable in
    // wall-clock terms. The fence still orders them, and an equal fence
    // under a different boot id is treated as a later authority so a
    // restarted daemon can always make progress rather than deadlocking on
    // its own predecessor.
    return left.fence < right.fence ? "before" : "after";
  }
  if (left.fence !== right.fence) return left.fence < right.fence ? "before" : "after";
  return "equal";
}

export function sameDeviceAuthority(left: AuthorityTuple, right: AuthorityTuple): boolean {
  return left.bootGeneration === right.bootGeneration
    && left.bootId === right.bootId
    && left.fence === right.fence;
}

// Device-command admission ------------------------------------------------------

export type DeviceCommandAuthorityTransitionDisposition =
  | Readonly<{
      boundAuthority: AuthorityTuple;
      kind: "applied" | "rebound" | "replay";
      state: CommandState;
    }>
  | Readonly<{
      boundAuthority: AuthorityTuple | null;
      kind: "rejected";
      reason: "bound_authority" | "invalid_transition" | "stale_authority";
      state: CommandState;
    }>;

/**
 * Pure admission policy for effect-bearing device-command transitions.
 *
 * `prepared` may be claimed by a pending command, replayed by the authority
 * that already holds it, or rebound to a strictly later authority (a
 * restarted daemon reclaiming work that never started). Every later
 * transition demands an exact match with the bound authority, so an effect
 * that may have begun is never settled by a different generation on this
 * path; that case goes through the explicit recovery transition instead.
 */
export function deviceCommandAuthorityTransitionDisposition(input: Readonly<{
  boundAuthority: AuthorityTuple | null;
  next: "prepared" | "effect_started" | "applied" | "failed" | "ambiguous";
  requestedAuthority: AuthorityTuple;
  state: CommandState;
}>): DeviceCommandAuthorityTransitionDisposition {
  const rejected = (
    reason: Extract<
      DeviceCommandAuthorityTransitionDisposition,
      { kind: "rejected" }
    >["reason"],
  ): DeviceCommandAuthorityTransitionDisposition => ({
    boundAuthority: input.boundAuthority,
    kind: "rejected",
    reason,
    state: input.state,
  });

  if (input.next === "prepared") {
    if (input.state === "pending") {
      if (input.boundAuthority !== null) return rejected("bound_authority");
      return {
        boundAuthority: input.requestedAuthority,
        kind: "applied",
        state: "prepared",
      };
    }
    if (input.state !== "prepared") return rejected("invalid_transition");
    if (input.boundAuthority === null) return rejected("bound_authority");
    const order = compareDeviceAuthority(input.requestedAuthority, input.boundAuthority);
    if (order === "equal") {
      return { boundAuthority: input.boundAuthority, kind: "replay", state: "prepared" };
    }
    if (order === "before") return rejected("stale_authority");
    return {
      boundAuthority: input.requestedAuthority,
      kind: "rebound",
      state: "prepared",
    };
  }

  if (input.boundAuthority === null) return rejected("bound_authority");
  if (!sameDeviceAuthority(input.boundAuthority, input.requestedAuthority)) {
    return rejected("bound_authority");
  }
  const transition = commandTransitionDisposition(input.state, input.next);
  if (transition.kind === "rejected") return rejected("invalid_transition");
  return {
    boundAuthority: input.boundAuthority,
    kind: transition.kind,
    state: transition.next,
  };
}

/**
 * Whether a stale `effect_started` device command may be closed by a newer
 * authority. The recovering authority must be strictly later than the one
 * that recorded the effect, and the only terminal state it may publish for
 * an effect it did not observe is `ambiguous`.
 */
export function deviceCommandRecoveryAdmitted(input: Readonly<{
  recoveryAuthority: AuthorityTuple;
  staleAuthority: AuthorityTuple;
  state: CommandState;
  terminalState: "applied" | "failed" | "ambiguous";
}>): boolean {
  if (input.state !== "prepared" && input.state !== "effect_started") return false;
  if (compareDeviceAuthority(input.recoveryAuthority, input.staleAuthority) !== "after") {
    return false;
  }
  // A recovering authority never observed the effect, so it may never
  // publish `applied`. From `prepared` nothing started, so `failed` is
  // honest; from `effect_started` the only honest answer is `ambiguous`.
  return input.state === "prepared"
    ? input.terminalState !== "applied"
    : input.terminalState === "ambiguous";
}

/**
 * A recovery terminal may outlive the boot that wrote it when the response
 * is lost. The next boot may accept that exact terminal without rewriting
 * it only when its bound authority is either the current recovery authority
 * or a strictly intervening authority between the journal's stale boot and
 * this one. Result code and keyed digest equality are checked by the hosted
 * mutation.
 */
export function deviceCommandRecoveryReplayAdmitted(input: Readonly<{
  boundAuthority: AuthorityTuple;
  recoveryAuthority: AuthorityTuple;
  staleAuthority: AuthorityTuple;
}>): boolean {
  if (sameDeviceAuthority(input.boundAuthority, input.recoveryAuthority)) return true;
  return compareDeviceAuthority(input.boundAuthority, input.staleAuthority) === "after"
    && compareDeviceAuthority(input.recoveryAuthority, input.boundAuthority) === "after"
    && compareDeviceAuthority(input.recoveryAuthority, input.staleAuthority) === "after";
}
