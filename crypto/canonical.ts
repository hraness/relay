/** Canonical JSON: the one byte encoding of a JSON value that signing and
 * digests can rely on. Object keys sort by code point, arrays keep order,
 * numbers use the shortest round-trip form, and there is no whitespace.
 * Any runtime that implements this produces byte-identical output —
 * including the Rust port. */

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | Readonly<{ [key: string]: JsonValue }>;
export type JsonObject = Readonly<{ [key: string]: JsonValue }>;

function escapeString(value: string): string {
  // JSON.stringify is the canonical string escape for the JSON spec; only
  // key order and whitespace are left open, which this module closes.
  return JSON.stringify(value);
}

function numberText(value: number): string {
  if (!Number.isFinite(value)) throw new Error("Non-finite numbers are not JSON values");
  return JSON.stringify(value);
}

export function canonicalize(value: JsonValue): string {
  if (value === null || typeof value === "boolean") return value === null ? "null" : String(value);
  if (typeof value === "string") return escapeString(value);
  if (typeof value === "number") return numberText(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  const record = value as JsonObject;
  const keys = Object.keys(record).sort();
  return `{${keys.map((key) => `${escapeString(key)}:${canonicalize(record[key]!)}`).join(",")}}`;
}

/** SHA-256 over canonical JSON UTF-8, rendered `sha256:<64 lowercase hex>`. */
export async function canonicalDigest(value: JsonValue): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonicalize(value)));
  let hex = "";
  for (const byte of new Uint8Array(digest)) hex += byte.toString(16).padStart(2, "0");
  return `sha256:${hex}`;
}

/** A value that is already canonical JSON — primitives, plain arrays, and
 * plain objects only. Anything else (undefined, functions, class
 * instances, symbols) is rejected rather than silently dropped. */
export function isJsonValue(value: unknown): value is JsonValue {
  if (value === null || typeof value === "boolean" || typeof value === "string") return true;
  if (typeof value === "number") return Number.isFinite(value);
  if (Array.isArray(value)) return value.every(isJsonValue);
  if (typeof value === "object") {
    const prototype: unknown = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) return false;
    return Object.values(value as Record<string, unknown>).every(isJsonValue);
  }
  return false;
}
