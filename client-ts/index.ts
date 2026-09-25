/**
 * Typed TypeScript client for the relay contract. The client speaks through a
 * caller-supplied transport — a `ConvexClient`, `ConvexReactClient`, or a
 * test runtime — so it carries no transport dependency of its own.
 *
 * All payloads crossing the wire are validated with the shared `wire/`
 * parsers before arguments are sent and after rows are returned; the client
 * never trusts an unparsed row.
 */

import type { AuthorityTuple } from "../wire/authority";
import { parseAuthorityTuple } from "../wire/authority";
import {
  isKeyWrapEnvelope,
  isSignedEnvelope,
  type KeyWrapEnvelope,
  type SignedEnvelope,
} from "../wire/envelope";
import { isDeviceId, isDigest, isPublicId, uuidV7 } from "../wire/ids";

/** A local contract violation — the row or argument failed wire validation
 * before any server error was involved. */
export class RelayClientError extends Error {
  constructor(readonly reason: string, detail?: string) {
    super(detail ? `${reason}: ${detail}` : reason);
    this.name = "RelayClientError";
  }
}

/** Anything that can run a Convex function reference. */
export interface RelayTransport {
  mutation(reference: { _name: string }, args: Record<string, unknown>): Promise<unknown>;
  query(reference: { _name: string }, args: Record<string, unknown>): Promise<unknown>;
}

/** Module prefixes for the product deployment's re-export files. Defaults to
 * the names the reference `convex/` instantiation uses. */
export interface RelayModules {
  commands?: string;
  devices?: string;
  envelopes?: string;
  invites?: string;
  maintenance?: string;
  projections?: string;
}

const modules = (names?: RelayModules) => ({
  commands: names?.commands ?? "relayCommands",
  devices: names?.devices ?? "relayDevices",
  envelopes: names?.envelopes ?? "relayEnvelopes",
  invites: names?.invites ?? "relayInvites",
  maintenance: names?.maintenance ?? "relayMaintenance",
  projections: names?.projections ?? "relayProjections",
});

const reference = (module: string, name: string) => ({ _name: `${module}:${name}` });

export type CommandState =
  | "pending"
  | "prepared"
  | "effect_started"
  | "applied"
  | "failed"
  | "ambiguous"
  | "cancelled"
  | "expired";

const COMMAND_STATES: ReadonlySet<string> = new Set([
  "pending", "prepared", "effect_started", "applied", "failed", "ambiguous", "cancelled", "expired",
]);

export interface DeviceRow {
  agreementPublicKey: string;
  deviceClass: string;
  deviceId: string;
  keyVersion: number;
  label: string;
  online: boolean;
  signingPublicKey: string;
  status: string;
}

export interface CommandRow {
  boundAuthority: AuthorityTuple | null;
  deadline: number;
  deviceId: string;
  kind: string;
  nonterminal: boolean;
  payload: SignedEnvelope | null;
  publicId: string;
  recoveryAuthority: AuthorityTuple | null;
  result: SignedEnvelope | null;
  resultCode: string | null;
  state: CommandState;
  targetDeviceId: string;
}

export interface ProjectionRow {
  deviceId: string;
  envelope: SignedEnvelope;
  revision: number;
  scope: string;
  updatedAt: number;
}

function assertDeviceId(value: unknown, field: string): asserts value is string {
  if (!isDeviceId(value)) throw new RelayClientError("malformed-envelope", `${field} must be a device id`);
}

function assertPublicId(value: unknown, field: string): asserts value is string {
  if (!isPublicId(value)) throw new RelayClientError("malformed-envelope", `${field} must be a public id`);
}

function parseDeviceRow(row: unknown): DeviceRow {
  if (typeof row !== "object" || row === null) throw new RelayClientError("malformed-envelope", "device row is not an object");
  const record = row as Record<string, unknown>;
  if (!isDeviceId(record.deviceId) || typeof record.deviceClass !== "string" || typeof record.status !== "string"
    || typeof record.label !== "string" || typeof record.online !== "boolean"
    || typeof record.signingPublicKey !== "string" || typeof record.agreementPublicKey !== "string"
    || !Number.isSafeInteger(record.keyVersion) || (record.keyVersion as number) < 1) {
    throw new RelayClientError("malformed-envelope", "device row failed validation");
  }
  return row as DeviceRow;
}

function parseCommandRow(row: unknown): CommandRow {
  if (typeof row !== "object" || row === null) throw new RelayClientError("malformed-envelope", "command row is not an object");
  const record = row as Record<string, unknown>;
  if (typeof record.publicId !== "string" || typeof record.kind !== "string" || typeof record.state !== "string"
    || !COMMAND_STATES.has(record.state)) {
    throw new RelayClientError("malformed-envelope", "command row failed validation");
  }
  return row as CommandRow;
}

/**
 * Typed relay client. Construct once per authenticated session; the
 * transport must already carry the session identity.
 */
export class RelayClient {
  private readonly modules: ReturnType<typeof modules>;
  constructor(private readonly transport: RelayTransport, names?: RelayModules) {
    this.modules = modules(names);
  }

  /** List the caller's enrolled devices. */
  async listDevices(): Promise<DeviceRow[]> {
    const rows = await this.transport.query(reference(this.modules.devices, "list"), {});
    if (!Array.isArray(rows)) throw new RelayClientError("malformed-envelope", "devices list is not an array");
    return rows.map(parseDeviceRow);
  }

  /** Open or refresh a presence session for a bound device. */
  async connect(args: {
    authority: AuthorityTuple;
    connectionId: string;
    deviceId: string;
    fingerprint: string;
  }): Promise<{ presenceUntil: number; previousBootId: string | null }> {
    assertDeviceId(args.deviceId, "deviceId");
    if (!parseAuthorityTuple(args.authority)) throw new RelayClientError("malformed-authority");
    const result = await this.transport.mutation(reference(this.modules.devices, "connect"), {
      authority: args.authority,
      connectionId: args.connectionId,
      deviceId: args.deviceId,
      fingerprint: args.fingerprint,
    });
    return result as { presenceUntil: number; previousBootId: string | null };
  }

  async disconnect(args: { connectionId: string; deviceId: string }): Promise<void> {
    assertDeviceId(args.deviceId, "deviceId");
    await this.transport.mutation(reference(this.modules.devices, "disconnect"), args);
  }

  /** Revoke a device the caller owns. */
  async revokeDevice(deviceId: string): Promise<void> {
    assertDeviceId(deviceId, "deviceId");
    await this.transport.mutation(reference(this.modules.devices, "revoke"), { deviceId });
  }

  /** Enqueue a signed command envelope for a target device. */
  async enqueueCommand(args: {
    deadline?: number;
    kind: string;
    payload: SignedEnvelope;
    requestDigest: string;
    targetDeviceId: string;
  }): Promise<{ command: CommandRow; replayed: boolean }> {
    assertDeviceId(args.targetDeviceId, "targetDeviceId");
    if (!isDigest(args.requestDigest)) throw new RelayClientError("malformed-envelope", "requestDigest must be sha256:<hex>");
    if (!isSignedEnvelope(args.payload, 1 << 20)) throw new RelayClientError("malformed-envelope");
    const result = await this.transport.mutation(reference(this.modules.commands, "enqueue"), {
      ...args,
      idempotencyKey: uuidV7(),
    });
    return result as { command: CommandRow; replayed: boolean };
  }

  /** Re-fetch a command, or `null` when the caller cannot see it. */
  async getCommand(publicId: string): Promise<CommandRow | null> {
    assertPublicId(publicId, "publicId");
    const row = await this.transport.query(reference(this.modules.commands, "get"), { publicId });
    return row === null ? null : parseCommandRow(row);
  }

  /** List nonterminal commands addressed to a device. */
  async listCommandsFor(deviceId: string): Promise<CommandRow[]> {
    assertDeviceId(deviceId, "deviceId");
    const rows = await this.transport.query(reference(this.modules.commands, "listForTarget"), { deviceId });
    if (!Array.isArray(rows)) throw new RelayClientError("malformed-envelope");
    return rows.map(parseCommandRow);
  }

  /** Claim a pending command under the caller's authority. */
  async claimCommand(args: {
    authority: AuthorityTuple;
    deviceId: string;
    publicId: string;
  }): Promise<{ command: CommandRow; outcome: string }> {
    assertDeviceId(args.deviceId, "deviceId");
    assertPublicId(args.publicId, "publicId");
    const result = await this.transport.mutation(reference(this.modules.commands, "claim"), args);
    return result as { command: CommandRow; outcome: string };
  }

  /** Mark a claimed command's effect as started. */
  async markEffectStarted(args: { authority: AuthorityTuple; deviceId: string; publicId: string }): Promise<void> {
    await this.transport.mutation(reference(this.modules.commands, "markEffectStarted"), args);
  }

  /** Settle a started command with an encrypted result. */
  async settleCommand(args: {
    authority: AuthorityTuple;
    deviceId: string;
    publicId: string;
    result: SignedEnvelope | null;
    resultCode: string;
    resultDigest: string;
    state: "applied" | "failed" | "ambiguous";
  }): Promise<void> {
    if (!isDigest(args.resultDigest)) throw new RelayClientError("malformed-envelope", "resultDigest must be sha256:<hex>");
    await this.transport.mutation(reference(this.modules.commands, "settle"), args);
  }

  /** Recover a stale-authority command under the caller's newer authority. */
  async recoverCommand(args: {
    authority: AuthorityTuple;
    deviceId: string;
    publicId: string;
    resultCode: string;
    state: "ambiguous" | "failed";
  }): Promise<void> {
    await this.transport.mutation(reference(this.modules.commands, "recover"), args);
  }

  /** Cancel a pending command the caller enqueued. */
  async cancelCommand(args: { deviceId: string; publicId: string }): Promise<void> {
    await this.transport.mutation(reference(this.modules.commands, "cancel"), args);
  }

  /** Acknowledge a terminal command (starts its result retention clock). */
  async acknowledgeCommand(args: { deviceId: string; publicId: string }): Promise<void> {
    await this.transport.mutation(reference(this.modules.commands, "acknowledge"), args);
  }

  /** Publish a signed projection envelope under a scope. */
  async publishProjection(args: {
    deviceId: string;
    envelope: SignedEnvelope;
    expectedRevision: number;
    scope: string;
  }): Promise<{ revision: number }> {
    assertDeviceId(args.deviceId, "deviceId");
    const result = await this.transport.mutation(reference(this.modules.projections, "publish"), args);
    return result as { revision: number };
  }

  /** List every projection visible to the caller. */
  async listProjections(): Promise<ProjectionRow[]> {
    const rows = await this.transport.query(reference(this.modules.projections, "list"), {});
    if (!Array.isArray(rows)) throw new RelayClientError("malformed-envelope");
    return rows as ProjectionRow[];
  }

  /** Deliver a key-wrap envelope to a recipient device. */
  async postKeyEnvelope(envelope: KeyWrapEnvelope): Promise<void> {
    if (!isKeyWrapEnvelope(envelope)) throw new RelayClientError("malformed-envelope");
    await this.transport.mutation(reference(this.modules.envelopes, "postKeyEnvelope"), { envelope });
  }

  /** Collect key wraps addressed to the caller's device. */
  async myKeyEnvelopes(): Promise<KeyWrapEnvelope[]> {
    const rows = await this.transport.query(reference(this.modules.envelopes, "myKeyEnvelopes"), {});
    if (!Array.isArray(rows)) throw new RelayClientError("malformed-envelope");
    return rows as KeyWrapEnvelope[];
  }

  /** Issue an identity invite. */
  async issueInvite(args: { boundEmail: string; purpose?: string }): Promise<{ token: string; expiresAt: number }> {
    const result = await this.transport.mutation(reference(this.modules.invites, "issue"), args);
    return result as { token: string; expiresAt: number };
  }
}
