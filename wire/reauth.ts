/** Key-preserving device reauthentication. Sign the entire challenge with
 * canonical JSON and the retained device P-256 key (raw 64-byte low-S).
 * Auth sessions are opaque provider IDs, never bearer tokens. */
import { exactKeys, isBase64Url, isSafeNonNegativeInteger, isSafePositiveInteger } from "./encoding";
import { isDeviceId, isWireNamespace } from "./ids";

export const DEVICE_REAUTH_TTL_MS = 5 * 60 * 1_000;
export type DeviceReauthChallenge = Readonly<{
  authEpoch: number;
  authSessionId: string;
  bindingRevision: number;
  challengeId: string;
  contract: string;
  deviceClass: string;
  deviceId: string;
  expiresAt: number;
  keyVersion: number;
  nonce: string;
  userId: string;
}>;
export type DeviceReauthResult = Readonly<{
  authEpoch: number;
  authSessionId: string;
  bindingRevision: number;
  challengeId: string;
  deviceClass: string;
  deviceId: string;
  keyVersion: number;
  userId: string;
}>;
export type DeviceReauthStatus = Readonly<{ status: "committed"; result: DeviceReauthResult }>
  | Readonly<{ status: "pending" | "expired" | "superseded" | "unknown" }>;

const opaqueId = (value: unknown): value is string => typeof value === "string"
  && /^[A-Za-z0-9_-]{1,128}$/u.test(value);
export function parseDeviceReauthChallenge(value: unknown, namespace: string): DeviceReauthChallenge | null {
  if (!isWireNamespace(namespace) || !exactKeys(value, ["authEpoch", "authSessionId", "bindingRevision",
    "challengeId", "contract", "deviceClass", "deviceId", "expiresAt", "keyVersion", "nonce", "userId"])) return null;
  if (!isSafePositiveInteger(value.authEpoch) || !opaqueId(value.authSessionId)
    || !isSafeNonNegativeInteger(value.bindingRevision) || value.bindingRevision >= Number.MAX_SAFE_INTEGER
    || !isBase64Url(value.challengeId, 32) || value.challengeId.length !== 32
    || value.contract !== `${namespace}:device-reauth`
    || typeof value.deviceClass !== "string" || !/^[a-z][a-z0-9-]{1,32}$/u.test(value.deviceClass)
    || !isDeviceId(value.deviceId) || !isSafePositiveInteger(value.expiresAt)
    || !isSafePositiveInteger(value.keyVersion) || !isBase64Url(value.nonce, 43) || value.nonce.length !== 43
    || !opaqueId(value.userId)) return null;
  return value as DeviceReauthChallenge;
}
