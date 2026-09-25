/** The relay backend factories. A product instantiates `defineRelay` with
 * its namespace, command union, device classes, and email transport, then
 * re-exports the returned functions from its own `convex/` directory.

 * Internal mutations resolve through `paths.internal` — the product must
 * re-export `internal` from a module of that name (conventionally
 * `convex/relayInternal.ts`) so the auth provider's `runMutation` calls
 * resolve. */

import { checkRelayConfig, type RelayConfig } from "../wire/bounds";

import { relayAuth, relayAuthInternal, relayAuthQueries, type RelayAuthPaths } from "./auth";
import { relayCommandsBackend } from "./commands";
import { relayDevicesBackend } from "./devices";
import { relayEnvelopesBackend } from "./envelopes";
import { relayInvitesBackend } from "./invites";
import { relayMaintenanceBackend, RELAY_RETENTION_TABLES } from "./maintenance";
import { relayProjectionsBackend } from "./projections";
import { relaySchema } from "./schema";

export function defineRelay(config: RelayConfig, paths?: Partial<RelayAuthPaths>) {
  const checked = checkRelayConfig(config);
  const mergedPaths: RelayAuthPaths = { internal: "relayInternal", ...(paths ?? {}) };
  const auth = relayAuth(checked, mergedPaths);
  return {
    auth: {
      auth: auth.auth,
      isAuthenticated: auth.isAuthenticated,
      signIn: auth.signIn,
      signOut: auth.signOut,
      store: auth.store,
      queries: relayAuthQueries(),
    },
    internal: auth.internal,
    commands: relayCommandsBackend(checked),
    devices: relayDevicesBackend(checked),
    envelopes: relayEnvelopesBackend(checked),
    invites: relayInvitesBackend(checked),
    maintenance: relayMaintenanceBackend(checked),
    projections: relayProjectionsBackend(checked),
    retentionTables: RELAY_RETENTION_TABLES,
    schema: relaySchema,
  };
}

export { relayAuth, relayAuthInternal, relayAuthQueries, relayCommandsBackend, relayDevicesBackend };
export { relayEnvelopesBackend, relayInvitesBackend, relayMaintenanceBackend, relaySchema };
export { digestAuthEmail, digestAuthOtp, digestInviteCapability, parseAuthCredentials } from "./auth";
export { RELAY_RETENTION_TABLES };
export type { RelayAuthPaths };
export type { CommandView } from "./commands";
export type { ProjectionView } from "./projections";
export { relayProjectionsBackend } from "./projections";
export { relayCtx, relayMutationCtx } from "./db";
export type { RelayMutationCtx, RelayQueryCtx } from "./db";
export { check, consumeRate, quotaExceeded, relayError, requireDevice, requireExecutor, requireSubject } from "./policy";
