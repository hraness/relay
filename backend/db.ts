/** The narrow database surface the relay backend needs, typed over the
 * relay's own schema names. Convex contexts satisfy these interfaces; row
 * values still pass through `wire/` validators before they are trusted. */

import type { CommandState } from "../wire/authority";
import type { KeyWrapEnvelope, SignedEnvelope } from "../wire/envelope";

/** Document ids are opaque strings to the relay: a product deployment's id
 * shape is its own business. */
export type RowId = string & { readonly __rowId: unique symbol };

export type Row<Fields> = Readonly<Fields> & Readonly<{
  _id: RowId;
  _creationTime: number;
}>;

/** Convex index constraints chain on a filter builder — each call returns
 * the builder itself, and the finished chain is what `withIndex` takes. */
export interface FilterBuilder {
  eq(field: string, value: unknown): FilterBuilder;
  gt(field: string, value: unknown): FilterBuilder;
  gte(field: string, value: unknown): FilterBuilder;
  lt(field: string, value: unknown): FilterBuilder;
  lte(field: string, value: unknown): FilterBuilder;
}

export interface DbQuery<Fields> {
  withIndex(name: string, builder: (q: FilterBuilder) => FilterBuilder): DbQuery<Fields>;
  order(direction: "asc" | "desc"): DbQuery<Fields>;
  take(count: number): Promise<Row<Fields>[]>;
  unique(): Promise<Row<Fields> | null>;
  collect(): Promise<Row<Fields>[]>;
  first(): Promise<Row<Fields> | null>;
  paginate(options: { numItems: number; cursor: string | null }): Promise<{
    page: Row<Fields>[];
    continueCursor: string;
    isDone: boolean;
  }>;
}

export interface Db {
  get<Fields>(id: RowId): Promise<Row<Fields> | null>;
  query<Fields>(table: string): DbQuery<Fields>;
  insert<Fields>(table: string, value: Fields): Promise<RowId>;
  patch<Fields>(id: RowId, value: Partial<Fields>): Promise<void>;
  delete(id: RowId): Promise<void>;
  normalizeId(table: string, id: RowId): RowId | null;
}

export interface Scheduler {
  runAfter(delayMs: number, reference: unknown, args: Record<string, unknown>): Promise<unknown>;
  runAt(timestampMs: number, reference: unknown, args: Record<string, unknown>): Promise<unknown>;
  cancel(id: unknown): Promise<void>;
}

export interface Auth {
  getUserIdentity(): Promise<Record<string, unknown> | null>;
}

export type RelayQueryCtx = Readonly<{ db: Db; auth: Auth }>;
export type RelayMutationCtx = Readonly<{ db: Db; auth: Auth; scheduler: Scheduler }>;

/** Cast a Convex context to the relay's narrow surface. The runtime object
 * is the same; only the compile-time view tightens. */
export function relayCtx(ctx: { db: unknown; auth: unknown }): RelayQueryCtx {
  return ctx as unknown as RelayQueryCtx;
}

export function relayMutationCtx(ctx: { db: unknown; auth: unknown; scheduler: unknown }): RelayMutationCtx {
  return ctx as unknown as RelayMutationCtx;
}

// Row shapes --------------------------------------------------------------------

export type AuthSubjectRow = Readonly<{
  admittedWithInvite?: boolean;
  authEpoch: number;
  createdAt: number;
  emailDigest: string;
  status: "active" | "disabled";
  unverifiedSendCount?: number;
  updatedAt: number;
  userId?: RowId;
  verifiedAt?: number;
}>;

export type AuthAttemptRow = Readonly<{
  createdAt: number;
  emailDigest: string;
  expiresAt: number;
  kind: "send" | "verify";
}>;

export type OtpChallengeRow = Readonly<{
  accountId: RowId;
  authEpoch: number;
  codeDigest: string;
  createdAt: number;
  deliveryState: "reserved" | "accepted" | "ambiguous";
  emailDigest: string;
  expiresAt: number;
  updatedAt: number;
  userId: RowId;
}>;

export type DeviceRow = Readonly<{
  agreementPublicKey: string;
  authEpoch: number;
  createdAt: number;
  deviceClass: string;
  deviceId: string;
  keyVersion: number;
  label: string;
  revision: number;
  revokedAt?: number;
  signingPublicKey: string;
  status: "pending" | "active" | "revoked";
  updatedAt: number;
  userId: RowId;
}>;

export type DeviceSessionRow = Readonly<{
  authEpoch: number;
  authSessionId: RowId;
  boundAt: number;
  deviceId: RowId;
  revokedAt?: number;
  userId: RowId;
}>;

export type BindChallengeRow = Readonly<{
  authSessionId: RowId;
  challengeId: string;
  consumedAt?: number;
  createdAt: number;
  deviceId: RowId;
  expiresAt: number;
  nonce: string;
  userId: RowId;
}>;

export type InviteRow = Readonly<{
  boundEmailDigest?: string;
  capabilityDigest: string;
  consumedAt?: number;
  createdAt: number;
  expiresAt: number;
  issuedByUserId?: RowId;
  publicId: string;
  purpose: "identity" | "device";
  revokedAt?: number;
  state: "issued" | "bound_to_email" | "consumed" | "revoked";
  updatedAt: number;
}>;

export type KeyEnvelopeRow = Readonly<{
  createdAt: number;
  deviceId: RowId;
  envelope: KeyWrapEnvelope;
  userId: RowId;
}>;

export type CommandRow = Readonly<{
  boundAuthority?: Readonly<{ bootGeneration: number; bootId: string; fence: number }>;
  createdAt: number;
  deadline: number;
  idempotencyKey: string;
  kind: string;
  nonterminal: boolean;
  payload: SignedEnvelope;
  publicId: string;
  recoveryAuthority?: Readonly<{ bootGeneration: number; bootId: string; fence: number }>;
  requestingDeviceId: RowId;
  requestDigest: string;
  requesterAcknowledgedAt?: number;
  result?: SignedEnvelope;
  resultCode?: string;
  resultDigest?: string;
  state: CommandState;
  targetDeviceId: RowId;
  terminalCleanupAfter?: number;
  updatedAt: number;
  userId: RowId;
}>;

export type ProjectionRow = Readonly<{
  deviceId: RowId;
  envelope: SignedEnvelope;
  publicId: string;
  revision: number;
  scope: string;
  updatedAt: number;
  userId: RowId;
}>;

export type PresenceRow = Readonly<{
  authEpoch: number;
  connectionId: string;
  connectionSequence: number;
  deviceId: RowId;
  fingerprint: string;
  observedAt: number;
  presenceUntil: number;
  userId: RowId;
}>;

export type RateLimitRow = Readonly<{
  bucket: string;
  tokens: number;
  updatedAt: number;
  userId: RowId;
}>;

export type SecurityEventRow = Readonly<{
  actorDeviceId?: RowId;
  createdAt: number;
  entityId: string;
  event: string;
  userId: RowId;
}>;

export type MaintenanceRow = Readonly<{
  key: "retention";
  nextCategory: string;
  updatedAt: number;
}>;
