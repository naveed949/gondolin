import { deepFreeze, sha256, stableJson } from "./canonical-json.ts";

export const HTTPS_REQUEST_SCHEMA_VERSION =
  "gondolin.https-request/v1" as const;
export const HTTPS_CEILING_SCHEMA_VERSION =
  "gondolin.https-ceiling/v1" as const;
export const HTTPS_EVIDENCE_SCHEMA_VERSION =
  "gondolin.https-evidence/v1" as const;

export type HttpsAuthority = {
  protocol: "https";
  /** Exact ASCII DNS name with no wildcard or trailing dot */
  host: string;
  port: number;
  methods: ("GET" | "HEAD")[];
  resolution: "public-only";
  redirects: "none";
  /** Maximum decoded response entity size in `bytes` */
  maxResponseBytes: number;
  /** Maximum complete mediated request lifetime in `ms` */
  timeoutMs: number;
};
export type HttpsInvocationRequest = {
  schemaVersion: typeof HTTPS_REQUEST_SCHEMA_VERSION;
  invocationId: string;
  request: { url: string; method: "GET" | "HEAD" };
  authority: HttpsAuthority;
  limits: { outputBytes: number; wallTimeMs: number };
};
export type HttpsInvocationCeiling = {
  schemaVersion: typeof HTTPS_CEILING_SCHEMA_VERSION;
  network: { https: HttpsAuthority[] };
  limits: { maxOutputBytes: number; maxWallTimeMs: number };
};

/** Strict public grammar shared by normalization and evidence verification */
export function exactObject(
  input: unknown,
  keys: string[],
): Record<string, unknown> {
  if (
    !input ||
    typeof input !== "object" ||
    Array.isArray(input) ||
    Object.keys(input).length !== keys.length ||
    keys.some((key) => !Object.hasOwn(input, key))
  )
    throw new TypeError(`expected exactly ${keys.join(", ")}`);
  return input as Record<string, unknown>;
}
function positive(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0)
    throw new TypeError("limit must be a positive safe integer");
  return value;
}
function hostname(input: unknown): string {
  if (
    typeof input !== "string" ||
    input.length > 253 ||
    !/^[A-Za-z0-9.-]+$/.test(input)
  )
    throw new TypeError("exact ASCII DNS hostname required");
  const host = input.toLowerCase(),
    labels = host.split(".");
  if (
    labels.length < 2 ||
    !/[a-z]/.test(labels.at(-1)!) ||
    labels.every((part) => /^(?:[0-9]+|0x[0-9a-f]+)$/.test(part)) ||
    labels.some(
      (part) =>
        part.length > 63 ||
        part.startsWith("xn--") ||
        !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(part),
    )
  )
    throw new TypeError("unsupported or ambiguous DNS hostname");
  return host;
}
function authority(input: unknown): HttpsAuthority {
  const value = exactObject(input, [
    "protocol",
    "host",
    "port",
    "methods",
    "resolution",
    "redirects",
    "maxResponseBytes",
    "timeoutMs",
  ]);
  if (
    value.protocol !== "https" ||
    value.resolution !== "public-only" ||
    value.redirects !== "none"
  )
    throw new TypeError("unsupported HTTPS authority");
  const port = positive(value.port);
  if (
    port > 65535 ||
    !Array.isArray(value.methods) ||
    !value.methods.length ||
    ![...value.methods].every((method) => method === "GET" || method === "HEAD")
  )
    throw new TypeError("unsupported HTTPS port or method");
  return {
    protocol: "https",
    host: hostname(value.host),
    port,
    methods: [...new Set(value.methods)].sort(),
    resolution: "public-only",
    redirects: "none",
    maxResponseBytes: positive(value.maxResponseBytes),
    timeoutMs: positive(value.timeoutMs),
  };
}
export function normalizeHttpsCeiling(input: unknown): HttpsInvocationCeiling {
  const value = exactObject(input, ["schemaVersion", "network", "limits"]);
  if (value.schemaVersion !== HTTPS_CEILING_SCHEMA_VERSION)
    throw new TypeError("unsupported HTTPS ceiling schema");
  const network = exactObject(value.network, ["https"]);
  if (!Array.isArray(network.https) || !network.https.length)
    throw new TypeError("HTTPS ceiling requires explicit grants");
  const rules = [
    ...new Map(
      network.https.map((entry) => {
        const rule = authority(entry);
        return [stableJson(rule), rule];
      }),
    ).entries(),
  ]
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([, rule]) => rule);
  const limits = exactObject(value.limits, ["maxOutputBytes", "maxWallTimeMs"]);
  return deepFreeze({
    schemaVersion: HTTPS_CEILING_SCHEMA_VERSION,
    network: { https: rules },
    limits: {
      maxOutputBytes: positive(limits.maxOutputBytes),
      maxWallTimeMs: positive(limits.maxWallTimeMs),
    },
  });
}
export function canonicalizeHttpsInvocationRequest(input: unknown): {
  request: HttpsInvocationRequest;
  canonical: string;
  digest: string;
} {
  const value = exactObject(input, [
    "schemaVersion",
    "invocationId",
    "request",
    "authority",
    "limits",
  ]);
  if (
    value.schemaVersion !== HTTPS_REQUEST_SCHEMA_VERSION ||
    typeof value.invocationId !== "string" ||
    !/^[A-Za-z0-9._:-]{1,128}$/.test(value.invocationId)
  )
    throw new TypeError("invalid HTTPS schema or invocation identity");
  const target = exactObject(value.request, ["url", "method"]),
    grant = authority(value.authority);
  if (
    typeof target.url !== "string" ||
    !target.url.startsWith("https://") ||
    /[\s\\\x00-\x1f\x7f]/.test(target.url) ||
    target.url.includes("#")
  )
    throw new TypeError("unsupported HTTPS URL");
  const url = new URL(target.url);
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    hostname(url.hostname) !== grant.host ||
    Number(url.port || 443) !== grant.port ||
    (target.method !== "GET" && target.method !== "HEAD") ||
    !grant.methods.includes(target.method)
  )
    throw new TypeError("HTTPS request exceeds its declared authority");
  // Reject authority spellings which URL parsing would silently reinterpret.
  const rawAuthority = target.url.slice(8).split(/[/?]/, 1)[0]!;
  if (
    !new RegExp(
      `^${grant.host.replaceAll(".", "\\.")}(?::${grant.port})?$`,
      "i",
    ).test(rawAuthority)
  )
    throw new TypeError("ambiguous HTTPS URL authority");
  const limits = exactObject(value.limits, ["outputBytes", "wallTimeMs"]);
  const request: HttpsInvocationRequest = deepFreeze({
    schemaVersion: HTTPS_REQUEST_SCHEMA_VERSION,
    invocationId: value.invocationId,
    request: { url: url.href, method: target.method },
    authority: grant,
    limits: {
      outputBytes: positive(limits.outputBytes),
      wallTimeMs: positive(limits.wallTimeMs),
    },
  });
  const canonical = stableJson(request);
  return { request, canonical, digest: sha256(canonical) };
}
export function admitHttpsRequest(
  request: HttpsInvocationRequest,
  ceiling: HttpsInvocationCeiling,
): void {
  const grant = request.authority;
  if (
    !ceiling.network.https.some(
      (rule) =>
        rule.host === grant.host &&
        rule.port === grant.port &&
        grant.methods.every((method) => rule.methods.includes(method)) &&
        rule.maxResponseBytes >= grant.maxResponseBytes &&
        rule.timeoutMs >= grant.timeoutMs,
    ) ||
    request.limits.outputBytes > ceiling.limits.maxOutputBytes ||
    request.limits.wallTimeMs > ceiling.limits.maxWallTimeMs
  )
    throw new TypeError("HTTPS request widens immutable ceiling");
  // Node timers overflow above the signed 32-bit range; do not silently shorten them.
  if (
    request.authority.timeoutMs > 2147483647 ||
    request.limits.wallTimeMs > 2147483647
  )
    throw new TypeError("HTTPS timer exceeds supported runtime range");
}
