import { createHash } from "node:crypto";

/** Byte-stable JSON serialization with sorted object keys */
export function stableJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    if (typeof value === "number" && !Number.isFinite(value)) {
      throw new Error("non-finite number is not canonically serializable");
    }
    if (value === undefined || typeof value === "function") {
      throw new Error("value is not canonically serializable");
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`)
    .join(",")}}`;
}

/** SHA-256 identity with an explicit algorithm prefix */
export function sha256(value: string | Buffer): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

/** Recursive immutable view of a canonical data value */
export function deepFreeze<T>(value: T): T {
  deepFreezeValue(value, new WeakSet<object>());
  return value;
}

function deepFreezeValue(value: unknown, seen: WeakSet<object>): void {
  if (value === null || typeof value !== "object" || seen.has(value)) return;
  seen.add(value);
  if (!Object.isFrozen(value)) Object.freeze(value);
  for (const child of Object.values(value as Record<string, unknown>)) {
    deepFreezeValue(child, seen);
  }
}
