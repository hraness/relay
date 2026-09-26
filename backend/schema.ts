/** The relay's tables. Product deployments export this schema verbatim
 * (`export { relaySchema as default }`) — table names are fixed so the
 * command lifecycle, retention sweeps, and revocation drains are identical
 * across products. The product's wire namespace and bounds live in
 * configuration, not in the schema. */

import { authTables } from "@convex-dev/auth/server";
import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";

const wrappedKeyEnvelope = v.object({
  contract: v.string(),
  sender: v.string(),
  recipient: v.string(),
  keyVersion: v.number(),
  iv: v.string(),
  wrapped: v.string(),
  signature: v.string(),
});

const signedEnvelope = v.object({
  contract: v.string(),
  sender: v.string(),
  recipient: v.string(),
  scope: v.string(),
  keyVersion: v.number(),
  iv: v.string(),
  ciphertext: v.string(),
  signature: v.string(),
});

const authorityTuple = v.object({
  bootGeneration: v.number(),
  bootId: v.string(),
  fence: v.number(),
});

const commandState = v.union(
  v.literal("pending"),
  v.literal("prepared"),
  v.literal("effect_started"),
  v.literal("applied"),
  v.literal("failed"),
  v.literal("ambiguous"),
  v.literal("cancelled"),
  v.literal("expired"),
);

export function relaySchema() {
  return defineSchema({
    ...authTables,

    /** One verified-email subject per user. `authEpoch` advances when the
     * subject's credentials reset; every device row and session binding
     * carries the epoch it was minted under, and only the current epoch
     * is authoritative. */
    relaySubjects: defineTable({
      admittedWithInvite: v.optional(v.boolean()),
      authEpoch: v.number(),
      createdAt: v.number(),
      emailDigest: v.string(),
      status: v.union(v.literal("active"), v.literal("disabled")),
      unverifiedSendCount: v.optional(v.number()),
      updatedAt: v.number(),
      userId: v.optional(v.id("users")),
      verifiedAt: v.optional(v.number()),
    })
      .index("by_email_digest", ["emailDigest"])
      .index("by_user", ["userId"])
      .index("by_unverified_status_and_updated_at", ["verifiedAt", "status", "updatedAt"]),

    /** OTP send/verify attempts for rate limiting; rows expire. */
    relayAuthAttempts: defineTable({
      authEpoch: v.number(),
      createdAt: v.number(),
      emailDigest: v.string(),
      expiresAt: v.number(),
      kind: v.union(v.literal("send"), v.literal("verify")),
    })
      .index("by_email_kind_and_created_at", ["emailDigest", "kind", "createdAt"])
      .index("by_expires_at", ["expiresAt"]),

    /** Live OTP challenges: digests only, one-time, expiring. */
    relayOtpChallenges: defineTable({
      accountId: v.id("authAccounts"),
      authEpoch: v.number(),
      codeDigest: v.string(),
      createdAt: v.number(),
      deliveryState: v.union(
        v.literal("reserved"),
        v.literal("accepted"),
        v.literal("ambiguous"),
      ),
      emailDigest: v.string(),
      expiresAt: v.number(),
      updatedAt: v.number(),
      userId: v.id("users"),
    })
      .index("by_email", ["emailDigest"])
      .index("by_expires_at", ["expiresAt"])
      .index("by_user", ["userId"]),

    /** Capability-bound invites: `identity` admits a new email subject,
     * `device` lets an existing subject enroll a new device. */
    relayInvites: defineTable({
      boundEmailDigest: v.optional(v.string()),
      capabilityDigest: v.string(),
      consumedAt: v.optional(v.number()),
      createdAt: v.number(),
      expiresAt: v.number(),
      issuedByUserId: v.optional(v.id("users")),
      publicId: v.string(),
      purpose: v.union(v.literal("identity"), v.literal("device")),
      revokedAt: v.optional(v.number()),
      state: v.union(
        v.literal("issued"),
        v.literal("bound_to_email"),
        v.literal("consumed"),
        v.literal("revoked"),
      ),
      updatedAt: v.number(),
    })
      .index("by_capability_digest", ["capabilityDigest"])
      .index("by_expiry", ["expiresAt"])
      .index("by_user", ["issuedByUserId"]),

    /** The device registry. A device owns a signing key, an agreement key,
     * a class, and the account key version it was enrolled under. `deviceId`
     * is derived from the signing key, so a row can never be renamed onto a
     * different key. Revoked rows stay so a revoked id cannot return. */
    relayDevices: defineTable({
      agreementPublicKey: v.string(),
      authEpoch: v.number(),
      createdAt: v.number(),
      deviceClass: v.string(),
      deviceId: v.string(),
      keyVersion: v.number(),
      label: v.string(),
      revision: v.number(),
      revokedAt: v.optional(v.number()),
      signingPublicKey: v.string(),
      status: v.union(v.literal("pending"), v.literal("active"), v.literal("revoked")),
      updatedAt: v.number(),
      userId: v.id("users"),
    })
      .index("by_device_id", ["deviceId"])
      .index("by_user_and_device_id", ["userId", "deviceId"])
      .index("by_user_and_status", ["userId", "status"]),

    /** Binds a Convex Auth session to exactly one device. */
    relayDeviceSessions: defineTable({
      authEpoch: v.number(),
      authSessionId: v.id("authSessions"),
      boundAt: v.number(),
      deviceId: v.id("relayDevices"),
      revokedAt: v.optional(v.number()),
      userId: v.id("users"),
    })
      .index("by_auth_session", ["authSessionId"])
      .index("by_device", ["deviceId"])
      .index("by_user", ["userId"]),

    /** Signed bind challenges prove the enrolling session controls the
     * device's private signing key before activation. */
    relayBindChallenges: defineTable({
      authSessionId: v.id("authSessions"),
      challengeId: v.string(),
      consumedAt: v.optional(v.number()),
      createdAt: v.number(),
      deviceId: v.id("relayDevices"),
      expiresAt: v.number(),
      nonce: v.string(),
      userId: v.id("users"),
    })
      .index("by_challenge", ["challengeId"])
      .index("by_device", ["deviceId"])
      .index("by_expiry", ["expiresAt"])
      .index("by_user", ["userId"]),

    /** Account key versions wrapped for one device each. */
    relayKeyEnvelopes: defineTable({
      createdAt: v.number(),
      deviceId: v.id("relayDevices"),
      envelope: wrappedKeyEnvelope,
      userId: v.id("users"),
    })
      .index("by_device_and_version", ["deviceId", "envelope.keyVersion"])
      .index("by_user", ["userId"]),

    /** Device commands: closed lifecycle, fenced by the target's bound
     * boot authority. Payload and result are opaque ciphertext. */
    relayCommands: defineTable({
      boundAuthority: v.optional(authorityTuple),
      createdAt: v.number(),
      deadline: v.number(),
      idempotencyKey: v.string(),
      kind: v.string(),
      nonterminal: v.boolean(),
      payload: signedEnvelope,
      publicId: v.string(),
      recoveryAuthority: v.optional(authorityTuple),
      requestingDeviceId: v.id("relayDevices"),
      requestDigest: v.string(),
      requesterAcknowledgedAt: v.optional(v.number()),
      result: v.optional(signedEnvelope),
      resultCode: v.optional(v.string()),
      resultDigest: v.optional(v.string()),
      state: commandState,
      targetDeviceId: v.id("relayDevices"),
      terminalCleanupAfter: v.optional(v.number()),
      updatedAt: v.number(),
      userId: v.id("users"),
    })
      .index("by_public_id", ["publicId"])
      .index("by_idempotency", ["userId", "targetDeviceId", "requestingDeviceId", "kind", "idempotencyKey"])
      .index("by_requesting_device_and_nonterminal", ["requestingDeviceId"])
      .index("by_target_state_and_created_at", ["targetDeviceId", "state", "createdAt"])
      .index("by_target_nonterminal_and_created_at", ["targetDeviceId", "nonterminal", "createdAt"])
      .index("by_nonterminal_and_deadline", ["nonterminal", "deadline"])
      .index("by_cleanup", ["terminalCleanupAfter"])
      .index("by_user", ["userId"]),

    /** One current encrypted projection per (device, scope). The envelope
     * carries its own signature and sender. */
    relayProjections: defineTable({
      deviceId: v.id("relayDevices"),
      envelope: signedEnvelope,
      publicId: v.string(),
      revision: v.number(),
      scope: v.string(),
      updatedAt: v.number(),
      userId: v.id("users"),
    })
      .index("by_device_and_scope", ["deviceId", "scope"])
      .index("by_user", ["userId"])
      .index("by_user_and_device", ["userId", "deviceId"]),

    /** Device presence: the latest heartbeat for liveness display. */
    relayPresence: defineTable({
      authEpoch: v.number(),
      connectionId: v.string(),
      connectionSequence: v.number(),
      deviceId: v.id("relayDevices"),
      fingerprint: v.string(),
      observedAt: v.number(),
      presenceUntil: v.number(),
      userId: v.id("users"),
    })
      .index("by_device", ["deviceId"])
      .index("by_device_and_connection", ["deviceId", "connectionId"])
      .index("by_presence_until", ["presenceUntil"])
      .index("by_user", ["userId"]),

    /** Per-user token buckets. */
    relayRateLimits: defineTable({
      bucket: v.string(),
      tokens: v.number(),
      updatedAt: v.number(),
      userId: v.id("users"),
    }).index("by_user_and_bucket", ["userId", "bucket"]),

    /** Bounded audit record: enqueue/settle/revoke landmarks. */
    relaySecurityEvents: defineTable({
      actorDeviceId: v.optional(v.id("relayDevices")),
      createdAt: v.number(),
      entityId: v.string(),
      event: v.string(),
      userId: v.id("users"),
    })
      .index("by_user_and_created_at", ["userId", "createdAt"])
      .index("by_user", ["userId"]),

    /** Idempotency receipts for non-command mutations. */
    relayIdempotencyReceipts: defineTable({
      createdAt: v.number(),
      deviceId: v.optional(v.id("relayDevices")),
      expiresAt: v.number(),
      idempotencyKey: v.string(),
      operation: v.string(),
      requestDigest: v.string(),
      responseJson: v.string(),
      scopeId: v.string(),
      userId: v.id("users"),
    })
      .index("by_scope_and_key", ["userId", "deviceId", "operation", "scopeId", "idempotencyKey"])
      .index("by_expires_at", ["expiresAt"])
      .index("by_user", ["userId"]),

    /** Single-row maintenance cursor for the retention sweep. */
    relayMaintenance: defineTable({
      key: v.literal("retention"),
      nextCategory: v.string(),
      updatedAt: v.number(),
    }).index("by_key", ["key"]),
  });
}
