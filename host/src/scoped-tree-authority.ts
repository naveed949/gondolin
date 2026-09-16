import { deepFreeze, sha256, stableJson } from "./canonical-json.ts";
import {
  pinHostDirectoryIdentity,
  type HostDirectoryIdentity,
} from "./scoped-tree-vfs.ts";

export const SCOPED_TREE_REQUEST_SCHEMA_VERSION =
  "gondolin.scoped-tree-request/v1" as const;
export const SCOPED_TREE_CEILING_SCHEMA_VERSION =
  "gondolin.scoped-tree-ceiling/v1" as const;
export const SCOPED_TREE_EVIDENCE_SCHEMA_VERSION =
  "gondolin.scoped-tree-evidence/v1" as const;
export const SCOPED_TREE_PROFILE = "scoped-tree-runner/v1" as const;

export const SCOPED_TREE_GUEST_PATHS = deepFreeze({
  repository: "/data/repo",
  cache: "/data/cache",
  temp: "/data/tmp",
});

export const SCOPED_TREE_POLICY_VERSIONS = deepFreeze({
  admission: "scoped-tree-runner/v1",
  filesystem: "pinned-root-openat-vfs/v1",
  process: "exact-mount-landlock-tree/v1",
  resources: "payload-cgroup-wait4/v1",
  lifecycle: "one-shot-qemu/v1",
  /** Payload CPU cross-check allowance versus wait4 in `ms` */
  cpuRoundingAllowanceMs: 5,
  /** Observer polling period in `ms` */
  collectionIntervalMs: 10,
  /** Maximum accepted sample age in `ms` */
  maxSampleAgeMs: 20,
});

const TARGET_ID = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/u;
const INVOCATION_ID = /^[A-Za-z0-9._:-]{1,128}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const GUEST_PATH = /^\/(?:[A-Za-z0-9._-]+\/)*[A-Za-z0-9._-]+$/;

export type ScopedTreeLimits = {
  /** Cumulative payload-subtree CPU bound in `ms` */
  cpuMs: number;
  /** Payload cgroup memory ceiling in `bytes` */
  memoryBytes: number;
  /** Maximum descendants excluding the entrypoint */
  children: number;
  /** Returned UTF-8 payload bound in `bytes` */
  outputBytes: number;
  /** Payload runner interval bound in `ms` */
  wallMs: number;
};

export type ScopedTreeTargetBinding = {
  /** Controller-registered target identifier */
  id: string;
  /** Absolute guest executable path */
  executable: string;
  /** SHA-256 digest of the registered executable image */
  executableDigest: string;
  /** Literal argument vector excluding the executable */
  args: string[];
};

export type ScopedTreeInvocationCeiling = {
  schemaVersion: typeof SCOPED_TREE_CEILING_SCHEMA_VERSION;
  profile: typeof SCOPED_TREE_PROFILE;
  /** Host repository directory pinned at ceiling creation */
  repositoryHostPath: string;
  /** Controller-registered targets; never a public invocation argument */
  targets: ScopedTreeTargetBinding[];
  limits: {
    maxCpuMs: number;
    maxMemoryBytes: number;
    maxChildren: number;
    maxOutputBytes: number;
    maxWallMs: number;
  };
};

export type ScopedTreeInvocationRequest = {
  schemaVersion: typeof SCOPED_TREE_REQUEST_SCHEMA_VERSION;
  invocationId: string;
  profile: typeof SCOPED_TREE_PROFILE;
  /** Registered target identifier selected by AdaptiveSandbox */
  target: string;
  filesystem: {
    /** Fresh invocation-owned cache directory */
    cacheHostPath: string;
    /** Fresh invocation-owned temporary directory */
    tempHostPath: string;
  };
  limits: ScopedTreeLimits;
};

export type CanonicalScopedTreeRequest = {
  request: ScopedTreeInvocationRequest;
  canonical: string;
  digest: string;
};

export type AdmittedScopedTreeRequest = {
  request: ScopedTreeInvocationRequest;
  target: ScopedTreeTargetBinding;
  repository: HostDirectoryIdentity;
  cache: HostDirectoryIdentity;
  temp: HostDirectoryIdentity;
};

/** Strict public grammar shared by normalization and evidence verification */
export function exactObject(
  input: unknown,
  keys: readonly string[],
): Record<string, unknown> {
  if (
    !input ||
    typeof input !== "object" ||
    Array.isArray(input) ||
    Object.keys(input).length !== keys.length ||
    keys.some((key) => !Object.hasOwn(input, key))
  ) {
    throw new TypeError(`expected exactly ${keys.join(", ")}`);
  }
  return input as Record<string, unknown>;
}

function positive(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) {
    throw new TypeError(`${label} must be a positive safe integer`);
  }
  return value;
}

function natural(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new TypeError(`${label} must be a non-negative safe integer`);
  }
  return value;
}

function guestPath(value: unknown, label: string): string {
  if (
    typeof value !== "string" ||
    !GUEST_PATH.test(value) ||
    value.includes("..")
  ) {
    throw new TypeError(`${label} must be a canonical absolute guest path`);
  }
  return value;
}

function hostPath(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0 || value.includes("\0")) {
    throw new TypeError(`${label} must be a non-empty host path`);
  }
  return value;
}

function targetBinding(input: unknown): ScopedTreeTargetBinding {
  const value = exactObject(input, [
    "id",
    "executable",
    "executableDigest",
    "args",
  ]);
  if (typeof value.id !== "string" || !TARGET_ID.test(value.id)) {
    throw new TypeError("target id must be a scoped-test identifier");
  }
  if (
    typeof value.executableDigest !== "string" ||
    !DIGEST.test(value.executableDigest)
  ) {
    throw new TypeError("target executable digest must be sha256-hex");
  }
  if (
    !Array.isArray(value.args) ||
    value.args.some((arg) => typeof arg !== "string")
  ) {
    throw new TypeError("target args must be a literal string vector");
  }
  return {
    id: value.id,
    executable: guestPath(value.executable, "target.executable"),
    executableDigest: value.executableDigest,
    args: [...value.args],
  };
}

function limits(input: unknown): ScopedTreeLimits {
  const value = exactObject(input, [
    "cpuMs",
    "memoryBytes",
    "children",
    "outputBytes",
    "wallMs",
  ]);
  return {
    cpuMs: positive(value.cpuMs, "cpuMs"),
    memoryBytes: positive(value.memoryBytes, "memoryBytes"),
    children: natural(value.children, "children"),
    outputBytes: positive(value.outputBytes, "outputBytes"),
    wallMs: positive(value.wallMs, "wallMs"),
  };
}

export function normalizeScopedTreeCeiling(
  input: unknown,
): ScopedTreeInvocationCeiling {
  const value = exactObject(input, [
    "schemaVersion",
    "profile",
    "repositoryHostPath",
    "targets",
    "limits",
  ]);
  if (
    value.schemaVersion !== SCOPED_TREE_CEILING_SCHEMA_VERSION ||
    value.profile !== SCOPED_TREE_PROFILE
  ) {
    throw new TypeError("unsupported scoped-tree ceiling schema");
  }
  if (!Array.isArray(value.targets) || value.targets.length === 0) {
    throw new TypeError("scoped-tree ceiling requires registered targets");
  }
  const targets = [
    ...new Map(
      value.targets.map((entry) => {
        const target = targetBinding(entry);
        return [target.id, target];
      }),
    ).values(),
  ];
  if (targets.length !== value.targets.length) {
    throw new TypeError("duplicate scoped-tree target registration");
  }
  const bound = exactObject(value.limits, [
    "maxCpuMs",
    "maxMemoryBytes",
    "maxChildren",
    "maxOutputBytes",
    "maxWallMs",
  ]);
  return deepFreeze({
    schemaVersion: SCOPED_TREE_CEILING_SCHEMA_VERSION,
    profile: SCOPED_TREE_PROFILE,
    repositoryHostPath: hostPath(
      value.repositoryHostPath,
      "repositoryHostPath",
    ),
    targets,
    limits: {
      maxCpuMs: positive(bound.maxCpuMs, "maxCpuMs"),
      maxMemoryBytes: positive(bound.maxMemoryBytes, "maxMemoryBytes"),
      maxChildren: natural(bound.maxChildren, "maxChildren"),
      maxOutputBytes: positive(bound.maxOutputBytes, "maxOutputBytes"),
      maxWallMs: positive(bound.maxWallMs, "maxWallMs"),
    },
  });
}

export function canonicalizeScopedTreeInvocationRequest(
  input: unknown,
): CanonicalScopedTreeRequest {
  const value = exactObject(input, [
    "schemaVersion",
    "invocationId",
    "profile",
    "target",
    "filesystem",
    "limits",
  ]);
  if (
    value.schemaVersion !== SCOPED_TREE_REQUEST_SCHEMA_VERSION ||
    value.profile !== SCOPED_TREE_PROFILE ||
    typeof value.invocationId !== "string" ||
    !INVOCATION_ID.test(value.invocationId)
  ) {
    throw new TypeError("invalid scoped-tree schema or invocation identity");
  }
  if (typeof value.target !== "string" || !TARGET_ID.test(value.target)) {
    throw new TypeError("request target must be a registered identifier");
  }
  const filesystem = exactObject(value.filesystem, [
    "cacheHostPath",
    "tempHostPath",
  ]);
  const request: ScopedTreeInvocationRequest = deepFreeze({
    schemaVersion: SCOPED_TREE_REQUEST_SCHEMA_VERSION,
    invocationId: value.invocationId,
    profile: SCOPED_TREE_PROFILE,
    target: value.target,
    filesystem: {
      cacheHostPath: hostPath(filesystem.cacheHostPath, "cacheHostPath"),
      tempHostPath: hostPath(filesystem.tempHostPath, "tempHostPath"),
    },
    limits: limits(value.limits),
  });
  const canonical = stableJson(request);
  return { request, canonical, digest: sha256(canonical) };
}

export function admitScopedTreeRequest(
  request: ScopedTreeInvocationRequest,
  ceiling: ScopedTreeInvocationCeiling,
): AdmittedScopedTreeRequest {
  const target = ceiling.targets.find((entry) => entry.id === request.target);
  if (!target) {
    throw new TypeError(`unregistered scoped-tree target ${request.target}`);
  }
  const { limits: requested, filesystem } = request;
  if (
    requested.cpuMs > ceiling.limits.maxCpuMs ||
    requested.memoryBytes > ceiling.limits.maxMemoryBytes ||
    requested.children > ceiling.limits.maxChildren ||
    requested.outputBytes > ceiling.limits.maxOutputBytes ||
    requested.wallMs > ceiling.limits.maxWallMs
  ) {
    throw new TypeError("scoped-tree request widens the immutable ceiling");
  }
  if (filesystem.cacheHostPath === filesystem.tempHostPath) {
    throw new TypeError("cache and temp roots must be disjoint");
  }
  if (
    filesystem.cacheHostPath === ceiling.repositoryHostPath ||
    filesystem.tempHostPath === ceiling.repositoryHostPath
  ) {
    throw new TypeError("private roots cannot reuse the repository path");
  }
  const repository = pinHostDirectoryIdentity(
    ceiling.repositoryHostPath,
  ).identity;
  const cache = pinHostDirectoryIdentity(filesystem.cacheHostPath).identity;
  const temp = pinHostDirectoryIdentity(filesystem.tempHostPath).identity;
  if (
    sameIdentity(repository, cache) ||
    sameIdentity(repository, temp) ||
    sameIdentity(cache, temp)
  ) {
    throw new TypeError("scoped-tree roots must have disjoint identities");
  }
  return { request, target, repository, cache, temp };
}

function sameIdentity(
  left: HostDirectoryIdentity,
  right: HostDirectoryIdentity,
): boolean {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.birthtimeNs === right.birthtimeNs
  );
}
