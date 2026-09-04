import { createHash, randomUUID } from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { Writable } from "node:stream";
import { domainToASCII } from "node:url";

import { VM, type VmRuntimeIdentity } from "./vm/core.ts";
import type { ImagePath } from "./sandbox/server-options.ts";
import type { HttpHooks, HttpIpAllowInfo } from "./qemu/contracts.ts";
import { extractIPv4Mapped, parseIPv6Hextets } from "./utils/ip.ts";
import { MemoryProvider } from "./vfs/node/index.ts";
import { createErrnoError } from "./vfs/errors.ts";
import { ERRNO, isWriteFlag } from "./vfs/utils.ts";

export const CAPABILITY_CEILING_SCHEMA_VERSION =
  "gondolin.capability-ceiling/v1" as const;
export const CAPABILITY_INVOCATION_SCHEMA_VERSION =
  "gondolin.capability-invocation/v1" as const;
export const CAPABILITY_EVIDENCE_SCHEMA_VERSION =
  "gondolin.capability-evidence/v1" as const;

export const EXACT_READER_GUARANTEES = [
  "canonical-request",
  "immutable-ceiling",
  "exact-file-read",
  "no-network",
  "clean-environment",
  "bounded-output",
  "wall-time",
  "disposable-qemu-vm",
  "host-observed-filesystem",
  "completed-teardown",
] as const;

export const HTTP_TLS_EGRESS_GUARANTEES = [
  "http-tls-egress",
  "checked-resolution",
  "redirect-reauthorization",
  "invocation-network-identity",
  "network-channel-teardown",
] as const;

export type ExactReaderGuarantee =
  | (typeof EXACT_READER_GUARANTEES)[number]
  | (typeof HTTP_TLS_EGRESS_GUARANTEES)[number];

export type CapabilityHttpMethod =
  "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS";

export type CapabilityNetworkRule = {
  /** Content-aware transport, where `tls` means HTTP/1.x over TLS */
  protocol: "http" | "tls";
  /** Exact normalized DNS hostname or IP address */
  destination: string;
  /** Exact destination TCP port */
  port: number;
  /** Uppercase HTTP methods permitted by this rule */
  methods: CapabilityHttpMethod[];
  /** Redirect authority available from requests admitted by this rule */
  redirects: "deny" | "same-origin" | "follow-authorized";
  /** Host-side resolution with policy re-check at connection time */
  resolution: "checked-host";
  /** Handling for loopback, link-local, private, and special-use answers */
  internalRanges: "deny" | "allow";
};

export type CapabilityNetworkAuthority =
  "none" | { /** Exact HTTP/TLS authorities */ rules: CapabilityNetworkRule[] };

export const EXACT_WRITER_GUARANTEES = [
  "canonical-request",
  "immutable-ceiling",
  "exact-file-write",
  "no-ambient-read",
  "no-network",
  "clean-environment",
  "bounded-output",
  "wall-time",
  "disposable-qemu-vm",
  "host-observed-filesystem",
  "completed-teardown",
] as const;

export type ExactWriterGuarantee = (typeof EXACT_WRITER_GUARANTEES)[number];

export type ExactWriterOperation = "create" | "write" | "truncate";

export type ExactReaderCeiling = {
  /** Capability ceiling schema identifier */
  schemaVersion: typeof CAPABILITY_CEILING_SCHEMA_VERSION;
  /** Narrow capability profile */
  profile: "exact-reader";
  /** Absolute guest executables permitted as invocation entrypoints */
  allowedExecutables: string[];
  filesystem: {
    /** Host files from which an invocation may select exactly one */
    sourcePaths: string[];
    /** Guest file paths to which an invocation may bind exactly one source */
    guestPaths: string[];
  };
  /** Maximum invocation network authority; omitted is equivalent to `none` */
  network?: CapabilityNetworkAuthority;
  limits: {
    /** Maximum combined stdout and stderr in `bytes` */
    maxOutputBytes: number;
    /** Maximum command wall time in `ms` */
    maxWallTimeMs: number;
  };
  /** Guarantees the ceiling permits callers to require */
  guarantees: ExactReaderGuarantee[];
};

export type ExactReaderInvocationRequest = {
  /** Capability invocation schema identifier */
  schemaVersion: typeof CAPABILITY_INVOCATION_SCHEMA_VERSION;
  /** Caller-selected replay identity */
  invocationId: string;
  /** Narrow capability profile */
  profile: "exact-reader";
  launch: {
    /** Absolute executable path, invoked directly without a shell */
    executable: string;
    /** Literal argument vector excluding the executable */
    args: string[];
  };
  capabilities: {
    filesystem: {
      /** Exact host file selected beneath the ceiling */
      sourcePath: string;
      /** Exact guest-visible path below `/data` */
      guestPath: string;
      /** Exact supported filesystem operation */
      operations: ["read"];
    };
    /** Declarative invocation-local HTTP/TLS authority */
    network: CapabilityNetworkAuthority;
    /** Explicit environment projection, fixed to empty in this profile */
    environment: Record<string, never>;
  };
  limits: {
    /** Combined stdout and stderr bound in `bytes` */
    outputBytes: number;
    /** Command wall-time bound in `ms` */
    wallTimeMs: number;
  };
  /** Guarantees that must be active or admission fails */
  requiredGuarantees: ExactReaderGuarantee[];
};

export type ExactWriterCeiling = {
  /** Capability ceiling schema identifier */
  schemaVersion: typeof CAPABILITY_CEILING_SCHEMA_VERSION;
  /** Narrow capability profile */
  profile: "exact-writer";
  /** Absolute guest executables permitted as invocation entrypoints */
  allowedExecutables: string[];
  filesystem: {
    /** Exact host paths from which an invocation may select one target */
    targetPaths: string[];
    /** Guest file paths to which an invocation may bind one target */
    guestPaths: string[];
    /** Maximum exact-target mutations permitted by the ceiling */
    operations: ExactWriterOperation[];
  };
  limits: {
    /** Maximum combined stdout and stderr in `bytes` */
    maxOutputBytes: number;
    /** Maximum command wall time in `ms` */
    maxWallTimeMs: number;
  };
  /** Guarantees the ceiling permits callers to require */
  guarantees: ExactWriterGuarantee[];
};

export type ExactWriterInvocationRequest = {
  /** Capability invocation schema identifier */
  schemaVersion: typeof CAPABILITY_INVOCATION_SCHEMA_VERSION;
  /** Caller-selected replay identity */
  invocationId: string;
  /** Narrow capability profile */
  profile: "exact-writer";
  launch: {
    /** Absolute executable path, invoked directly without a shell */
    executable: string;
    /** Literal argument vector excluding the executable */
    args: string[];
  };
  capabilities: {
    filesystem: {
      /** Exact host target selected beneath the ceiling */
      targetPath: string;
      /** Exact guest-visible path below `/data` */
      guestPath: string;
      /** Exact target mutations requested for this invocation */
      operations: ExactWriterOperation[];
    };
    /** Network authority, fixed to no authority in this profile */
    network: "none";
    /** Explicit environment projection, fixed to empty in this profile */
    environment: Record<string, never>;
  };
  limits: {
    /** Combined stdout and stderr bound in `bytes` */
    outputBytes: number;
    /** Command wall-time bound in `ms` */
    wallTimeMs: number;
  };
  /** Guarantees that must be active or admission fails */
  requiredGuarantees: ExactWriterGuarantee[];
};

export type CapabilityCeiling = ExactReaderCeiling | ExactWriterCeiling;
export type CapabilityInvocationRequest =
  ExactReaderInvocationRequest | ExactWriterInvocationRequest;

export type CapabilityInvocationRuntimeOptions = {
  /** QEMU executable path */
  qemuPath?: string;
  /** Guest asset directory, selector, or explicit asset paths */
  imagePath?: ImagePath;
  /** QEMU acceleration backend */
  accel?: string;
  /** QEMU CPU model */
  cpu?: string;
  /** QEMU machine type */
  machineType?: string;
  /** VM console mode */
  console?: "stdio" | "none";
  /** Disposable VM memory size */
  memory?: string;
  /** Disposable VM CPU count */
  cpus?: number;
  /** Guest startup timeout in `ms` */
  startTimeoutMs?: number;
};

export type CapabilityEffectDecision =
  "requested" | "granted" | "attempted" | "denied" | "observed";

export type CapabilityFilesystemEffect = {
  /** Capability domain */
  domain: "filesystem";
  /** Backend-neutral operation */
  operation:
    | "read"
    | "lookup"
    | "create"
    | "write"
    | "truncate"
    | "rename"
    | "delete"
    | "metadata-write"
    | "link"
    | "execute"
    | "other";
  /** SHA-256 resource identity, excluding sensitive host paths */
  resourceId: string;
  /** Guest-visible resource path */
  guestPath: string;
  /** Relationship of this event to enforcement */
  decision: CapabilityEffectDecision;
};

export type CapabilityNetworkEffect = {
  /** Capability domain */
  domain: "network";
  /** Host-observed network operation */
  operation:
    | "flow"
    | "request"
    | "resolution"
    | "connection"
    | "redirect"
    | "completion";
  /** Requested or detected transport */
  protocol: "http" | "tls" | "tcp" | "ssh" | "udp" | "unknown";
  /** Normalized hostname/address, or a SHA-256 flow identity when unavailable */
  destination: string;
  /** Destination port */
  port: number;
  /** Uppercase HTTP method when applicable */
  method?: string;
  /** SHA-256 resolved address identity when applicable */
  addressId?: string;
  /** Relationship of this event to enforcement */
  decision: CapabilityEffectDecision;
};

export type CapabilityEffect =
  CapabilityFilesystemEffect | CapabilityNetworkEffect;

export type CapabilityTeardownEvidence = {
  /** Whether the command transport has stopped */
  commandStopped: boolean;
  /** Whether the disposable VM runner has stopped */
  vmStopped: boolean;
  /** Whether host VFS handles are no longer reachable */
  vfsHandlesRevoked: boolean;
  /** Whether invocation policy has been removed */
  policyRemoved: boolean;
  /** Whether every invocation network channel has been closed */
  networkChannelsClosed?: boolean;
  /** Whether ephemeral VM state has been destroyed */
  ephemeralStateDestroyed: boolean;
  /** Teardown completion timestamp */
  completedAt: string | null;
};

export type CapabilityInvocationOutcome =
  | "success"
  | "command_failed"
  | "timeout"
  | "output_overflow"
  | "transport_failure"
  | "commit_failure"
  | "teardown_failure";

export type CapabilityInvocationEvidence = {
  /** Evidence schema identifier */
  schemaVersion: typeof CAPABILITY_EVIDENCE_SCHEMA_VERSION;
  /** Canonical request SHA-256 */
  requestDigest: string;
  /** Immutable ceiling SHA-256 */
  ceilingDigest: string;
  /** Fresh host execution identity */
  executionId: string;
  /** Disposable VM identity */
  vmId: string;
  /** Backend and guest image identities */
  runtime: VmRuntimeIdentity;
  /** Invocation policy implementation versions */
  policyVersions: {
    admission: "exact-reader/v1" | "exact-writer/v1";
    filesystem: "snapshot-vfs/v1" | "exact-writer-vfs/v1";
    network?: "http-tls-mediator/v1";
    lifecycle: "one-shot-qemu/v1";
  };
  /** SHA-256 of the snapshotted input bytes */
  inputDigest: string | null;
  /** SHA-256 of final exact-target bytes for writer invocations */
  outputDigest: string | null;
  /** Effects expressed by the admitted request */
  requested: CapabilityEffect[];
  /** Effects granted after ceiling intersection */
  granted: CapabilityEffect[];
  /** Host-observed operation attempts */
  attempted: CapabilityEffect[];
  /** Host-denied operation attempts */
  denied: CapabilityEffect[];
  /** Host-observed successful effects */
  observed: CapabilityEffect[];
  /** Invocation start timestamp */
  startedAt: string;
  /** Invocation settlement timestamp */
  settledAt: string;
  /** Resource and lifecycle termination evidence */
  teardown: CapabilityTeardownEvidence;
};

export type CapabilityInvocationResult = {
  /** Post-admission execution outcome */
  outcome: CapabilityInvocationOutcome;
  /** Guest exit code when an exec response was received */
  exitCode: number | null;
  /** Bounded stdout */
  stdout: string;
  /** Bounded stderr */
  stderr: string;
  /** Whether output exceeded the admitted bound */
  outputTruncated: boolean;
  /** Host-authored invocation evidence */
  evidence: CapabilityInvocationEvidence;
  /** Non-sensitive failure description */
  error?: string;
};

export type CanonicalCapabilityRequest = {
  /** Normalized invocation request */
  request: CapabilityInvocationRequest;
  /** Byte-stable UTF-8 JSON representation */
  canonical: string;
  /** SHA-256 of the canonical UTF-8 bytes */
  digest: string;
};

export type CapabilityFeatureStatus = "active" | "unsupported" | "unverified";

export type CapabilityInvocationFeatureManifest = {
  /** Feature manifest schema identifier */
  schemaVersion: "gondolin.capability-features/v1";
  /** Supported request schemas */
  requestSchemas: Record<string, CapabilityFeatureStatus>;
  /** Supported evidence schemas */
  evidenceSchemas: Record<string, CapabilityFeatureStatus>;
  profiles: Record<string, CapabilityFeatureStatus>;
  backends: Record<string, CapabilityFeatureStatus>;
  hosts: Record<string, CapabilityFeatureStatus>;
  guarantees: Record<string, CapabilityFeatureStatus>;
  domains: Record<string, CapabilityFeatureStatus>;
  operations: Record<string, CapabilityFeatureStatus>;
};

const FEATURE_MANIFEST: CapabilityInvocationFeatureManifest = deepFreeze({
  schemaVersion: "gondolin.capability-features/v1",
  requestSchemas: {
    [CAPABILITY_INVOCATION_SCHEMA_VERSION]: "active",
    "future-schema": "unsupported",
  },
  evidenceSchemas: {
    [CAPABILITY_EVIDENCE_SCHEMA_VERSION]: "active",
    "future-schema": "unsupported",
  },
  profiles: {
    "exact-reader": "active",
    "exact-writer": "active",
    "scoped-runner": "active",
    writer: "unsupported",
    runner: "unsupported",
  },
  backends: { qemu: "active", krun: "unverified" },
  hosts: { linux: "unverified", darwin: "unverified", win32: "unsupported" },
  guarantees: {
    ...Object.fromEntries(
      [...EXACT_READER_GUARANTEES, ...HTTP_TLS_EGRESS_GUARANTEES].map(
        (name) => [name, "active"],
      ),
    ),
    ...Object.fromEntries(
      EXACT_WRITER_GUARANTEES.map((name) => [name, "active"]),
    ),
    "declared-repository-read": "active",
    "exact-ephemeral-write": "active",
    "projected-environment": "active",
    "direct-executable": "active",
    "descendant-executable-restriction": "active",
    "scoped-runner.descendant-executable-restriction": "active",
    "explicit-shell": "active",
    "full-process-tree-termination": "active",
    "host-observed-process-lifecycle": "active",
    "per-invocation-cpu": "unsupported",
    "per-invocation-memory": "unsupported",
    "per-invocation-pids": "unsupported",
    "per-invocation-storage": "unsupported",
  },
  domains: {
    filesystem: "active",
    process: "active",
    lifecycle: "active",
    network: "active",
    environment: "unsupported",
    "environment.scoped-runner": "active",
    credentials: "unsupported",
    git: "unsupported",
    ipc: "unsupported",
    devices: "unsupported",
  },
  operations: {
    "filesystem.read.exact": "active",
    "filesystem.write.ephemeral-exact": "active",
    "filesystem.truncate.ephemeral-exact": "active",
    "filesystem.write": "unsupported",
    "filesystem.create": "unsupported",
    "filesystem.truncate": "unsupported",
    "filesystem.write.exact": "active",
    "filesystem.create.exact": "active",
    "filesystem.truncate.exact": "active",
    "filesystem.rename": "unsupported",
    "filesystem.delete": "unsupported",
    "filesystem.metadata-write": "unsupported",
    "filesystem.link": "unsupported",
    "filesystem.execute": "unsupported",
    "network.none": "active",
    "network.http1": "active",
    "network.tls-http1": "active",
    "network.redirect.reauthorized": "active",
    "network.resolution.checked-host": "active",
    "network.internal-ranges.explicit": "active",
    "network.dns.synthetic": "active",
    "network.dns.trusted": "unsupported",
    "network.dns.open": "unsupported",
    "network.raw-tcp": "unsupported",
    "network.ssh": "unsupported",
    "network.websocket": "unsupported",
    "network.http2": "unsupported",
    "network.http3": "unsupported",
    "network.quic": "unsupported",
    "network.any": "unsupported",
    "environment.empty": "active",
    "environment.projected": "active",
    "process.direct-executable": "active",
    "process.descendant-allow-list": "active",
    "process.descendants-denied": "unsupported",
    "shell.explicit": "active",
  },
});

const CEILING_KEYS = [
  "schemaVersion",
  "profile",
  "allowedExecutables",
  "filesystem",
  "limits",
  "guarantees",
] as const;
const CEILING_OPTIONAL_KEYS = ["network"] as const;
const REQUEST_KEYS = [
  "schemaVersion",
  "invocationId",
  "profile",
  "launch",
  "capabilities",
  "limits",
  "requiredGuarantees",
] as const;

/** Admission failure raised before any guest VM is created */
export class CapabilityAdmissionError extends Error {
  readonly code:
    | "invalid_request"
    | "unsupported"
    | "ceiling_widening"
    | "duplicate_invocation";

  constructor(code: CapabilityAdmissionError["code"], message: string) {
    super(message);
    this.name = "CapabilityAdmissionError";
    this.code = code;
  }
}

/** Return the immutable feature manifest for the public capability seam */
export function getCapabilityInvocationFeatureManifest(): CapabilityInvocationFeatureManifest {
  return FEATURE_MANIFEST;
}

/** Normalize, canonically serialize, and digest one capability request */
export function canonicalizeCapabilityInvocationRequest(
  input: unknown,
): CanonicalCapabilityRequest {
  const request = normalizeRequest(input);
  const canonical = stableJson(request);
  return { request, canonical, digest: sha256(canonical) };
}

/** Capability-enabled execution context with a fixed, immutable authority ceiling */
export class CapabilityInvocationContext {
  readonly ceiling: Readonly<CapabilityCeiling>;
  readonly ceilingDigest: string;
  private readonly runtime: Readonly<CapabilityInvocationRuntimeOptions>;
  private readonly sourceIdentities: ReadonlyMap<string, HostFileIdentity>;
  private readonly targetIdentities: ReadonlyMap<
    string,
    HostWriterTargetIdentity
  >;
  private readonly usedInvocationIds = new Set<string>();

  private constructor(
    ceiling: CapabilityCeiling,
    runtime: CapabilityInvocationRuntimeOptions,
  ) {
    this.ceiling = deepFreeze(ceiling);
    this.ceilingDigest = sha256(stableJson(ceiling));
    this.runtime = deepFreeze({ ...runtime });
    this.sourceIdentities = new Map(
      ceiling.profile === "exact-reader"
        ? ceiling.filesystem.sourcePaths.map((sourcePath) => [
            sourcePath,
            getHostFileIdentity(sourcePath),
          ])
        : [],
    );
    this.targetIdentities = new Map(
      ceiling.profile === "exact-writer"
        ? ceiling.filesystem.targetPaths.map((targetPath) => [
            targetPath,
            getHostWriterTargetIdentity(targetPath),
          ])
        : [],
    );
  }

  /** Validate and freeze a maximum capability ceiling */
  static create(
    ceiling: unknown,
    runtime: CapabilityInvocationRuntimeOptions = {},
  ): CapabilityInvocationContext {
    return new CapabilityInvocationContext(normalizeCeiling(ceiling), runtime);
  }

  /** Admit and run one invocation in a fresh, disposable QEMU VM */
  async invoke(input: unknown): Promise<CapabilityInvocationResult> {
    const canonical = canonicalizeCapabilityInvocationRequest(input);
    this.admit(canonical.request);

    if (this.usedInvocationIds.has(canonical.request.invocationId)) {
      throw new CapabilityAdmissionError(
        "duplicate_invocation",
        `invocation identity has already been used: ${canonical.request.invocationId}`,
      );
    }
    this.usedInvocationIds.add(canonical.request.invocationId);

    return canonical.request.profile === "exact-reader"
      ? await this.executeReader(
          canonical as CanonicalCapabilityRequest & {
            request: ExactReaderInvocationRequest;
          },
        )
      : await this.executeWriter(
          canonical as CanonicalCapabilityRequest & {
            request: ExactWriterInvocationRequest;
          },
        );
  }

  private admit(request: CapabilityInvocationRequest): void {
    if (request.profile !== this.ceiling.profile) {
      throw new CapabilityAdmissionError(
        "ceiling_widening",
        "invocation profile is outside the immutable ceiling",
      );
    }
    if (!this.ceiling.allowedExecutables.includes(request.launch.executable)) {
      throw new CapabilityAdmissionError(
        "ceiling_widening",
        "launch executable is outside the immutable ceiling",
      );
    }
    if (request.profile === "exact-reader") {
      const ceiling = this.ceiling as ExactReaderCeiling;
      if (
        !ceiling.filesystem.sourcePaths.includes(
          request.capabilities.filesystem.sourcePath,
        )
      ) {
        throw new CapabilityAdmissionError(
          "ceiling_widening",
          "filesystem source is outside the immutable ceiling",
        );
      }
    } else {
      const ceiling = this.ceiling as ExactWriterCeiling;
      if (
        !ceiling.filesystem.targetPaths.includes(
          request.capabilities.filesystem.targetPath,
        )
      ) {
        throw new CapabilityAdmissionError(
          "ceiling_widening",
          "filesystem target is outside the immutable ceiling",
        );
      }
      for (const operation of request.capabilities.filesystem.operations) {
        if (!ceiling.filesystem.operations.includes(operation)) {
          throw new CapabilityAdmissionError(
            "ceiling_widening",
            `filesystem operation is outside the immutable ceiling: ${operation}`,
          );
        }
      }
      const target = this.targetIdentities.get(
        request.capabilities.filesystem.targetPath,
      );
      if (!target) {
        throw new CapabilityAdmissionError(
          "ceiling_widening",
          "filesystem target has no identity in the immutable ceiling",
        );
      }
      if (
        target.file === null &&
        !request.capabilities.filesystem.operations.includes("create")
      ) {
        throw new CapabilityAdmissionError(
          "invalid_request",
          "a missing exact target requires create authority",
        );
      }
      if (
        target.file !== null &&
        request.capabilities.filesystem.operations.length === 1 &&
        request.capabilities.filesystem.operations[0] === "create"
      ) {
        throw new CapabilityAdmissionError(
          "invalid_request",
          "create-only authority has an empty intersection for an existing target",
        );
      }
    }
    if (
      !this.ceiling.filesystem.guestPaths.includes(
        request.capabilities.filesystem.guestPath,
      )
    ) {
      throw new CapabilityAdmissionError(
        "ceiling_widening",
        "filesystem guest path is outside the immutable ceiling",
      );
    }
    if (
      request.limits.outputBytes > this.ceiling.limits.maxOutputBytes ||
      request.limits.wallTimeMs > this.ceiling.limits.maxWallTimeMs
    ) {
      throw new CapabilityAdmissionError(
        "ceiling_widening",
        "invocation limits exceed the immutable ceiling",
      );
    }
    const ceilingGuarantees = new Set<string>(this.ceiling.guarantees);
    if (request.profile === "exact-reader") {
      admitNetworkAuthority(
        request.capabilities.network,
        (this.ceiling as ExactReaderCeiling).network,
      );
    }
    if (
      request.capabilities.network !== "none" &&
      request.requiredGuarantees.includes("no-network")
    ) {
      throw new CapabilityAdmissionError(
        "invalid_request",
        "a network-enabled invocation cannot require no-network",
      );
    }
    for (const guarantee of request.requiredGuarantees) {
      if (!ceilingGuarantees.has(guarantee)) {
        throw new CapabilityAdmissionError(
          "ceiling_widening",
          `required guarantee is excluded by the immutable ceiling: ${guarantee}`,
        );
      }
      if (FEATURE_MANIFEST.guarantees[guarantee] !== "active") {
        throw new CapabilityAdmissionError(
          "unsupported",
          `required guarantee is not active: ${guarantee}`,
        );
      }
    }
  }

  private async executeReader(
    canonical: CanonicalCapabilityRequest & {
      request: ExactReaderInvocationRequest;
    },
  ): Promise<CapabilityInvocationResult> {
    const request = canonical.request;
    const executionId = randomUUID();
    const startedAt = new Date().toISOString();
    const sourcePath = request.capabilities.filesystem.sourcePath;
    const sourceIdentity = this.sourceIdentities.get(sourcePath);
    if (!sourceIdentity) {
      throw new CapabilityAdmissionError(
        "ceiling_widening",
        "filesystem source has no identity in the immutable ceiling",
      );
    }
    const source = readExactHostFile(sourcePath, sourceIdentity);
    const inputDigest = sha256(source);
    const resourceId = sha256(
      `file:${request.capabilities.filesystem.sourcePath}`,
    );
    const requested = [fileEffect(request, resourceId, "requested")];
    const granted = [fileEffect(request, resourceId, "granted")];
    const attempted: CapabilityEffect[] = [];
    const denied: CapabilityEffect[] = [];
    const observed: CapabilityEffect[] = [];
    const networkEnabled = request.capabilities.network !== "none";
    const abort = new AbortController();
    const output = new BoundedOutput(request.limits.outputBytes, abort);
    const provider = new MemoryProvider();
    const relativeGuestPath = request.capabilities.filesystem.guestPath.slice(
      "/data".length,
    );
    await populateSnapshot(provider, relativeGuestPath, source);

    let vm: VM | null = null;
    let vmId = "not-created";
    let runtime: VmRuntimeIdentity = unavailableRuntimeIdentity();
    let outcome: CapabilityInvocationOutcome = "transport_failure";
    let exitCode: number | null = null;
    let error: string | undefined;
    let timedOut = false;
    let commandStopped = false;
    let closeError: Error | null = null;
    let admissionError: CapabilityAdmissionError | null = null;
    let runnerPid: number | null = null;

    let timer: NodeJS.Timeout | null = null;

    const hooks = createEvidenceHooks({
      exactPath: relativeGuestPath,
      guestPath: request.capabilities.filesystem.guestPath,
      resourceId,
      networkEnabled,
      attempted,
      denied,
      observed,
    });
    const networkAuthority = request.capabilities.network;
    const httpHooks =
      networkAuthority !== "none"
        ? createInvocationHttpHooks({
            authority: networkAuthority,
            requested,
            granted,
            attempted,
            denied,
            observed,
          })
        : undefined;

    try {
      vm = await VM.create({
        autoStart: false,
        startTimeoutMs: this.runtime.startTimeoutMs,
        memory: this.runtime.memory,
        cpus: this.runtime.cpus,
        rootfs: { mode: "readonly" },
        env: undefined,
        httpHooks,
        dns: networkEnabled
          ? { mode: "synthetic", syntheticHostMapping: "per-host" }
          : undefined,
        vfs: { mounts: { "/": provider }, hooks },
        sandbox: {
          vmm: "qemu",
          qemuPath: this.runtime.qemuPath,
          imagePath: this.runtime.imagePath,
          accel: this.runtime.accel,
          cpu: this.runtime.cpu,
          machineType: this.runtime.machineType,
          console: this.runtime.console ?? "none",
          autoRestart: false,
          netEnabled: networkEnabled,
          allowWebSockets: false,
        },
      });
      vmId = vm.id;
      runtime = vm.getRuntimeIdentity();
      if (!runtime.guestFeatures.includes("exec.clear-env/v1")) {
        throw new CapabilityAdmissionError(
          "unsupported",
          "selected guest image does not declare exec.clear-env/v1",
        );
      }

      await vm.start();
      runnerPid = vm.getHostPid();
      timer = setTimeout(() => {
        timedOut = true;
        abort.abort();
      }, request.limits.wallTimeMs);
      timer.unref?.();

      const result = await vm.exec(
        [request.launch.executable, ...request.launch.args],
        {
          clearEnv: true,
          signal: abort.signal,
          stdin: false,
          pty: false,
          stdout: output.stdout,
          stderr: output.stderr,
          windowBytes: Math.min(request.limits.outputBytes + 1, 256 * 1024),
        },
      );
      commandStopped = true;
      exitCode = result.exitCode;
      outcome = result.exitCode === 0 ? "success" : "command_failed";
    } catch (caught) {
      commandStopped = true;
      if (caught instanceof CapabilityAdmissionError) {
        admissionError = caught;
        outcome = "transport_failure";
      } else if (output.overflowed) outcome = "output_overflow";
      else if (timedOut) outcome = "timeout";
      else outcome = "transport_failure";
      error = safeError(caught);
    } finally {
      if (timer) clearTimeout(timer);
      if (vm) {
        runnerPid ??= vm.getHostPid();
        try {
          await vm.close();
        } catch (caught) {
          closeError =
            caught instanceof Error ? caught : new Error(String(caught));
        }
      }
    }

    const runnerStopped =
      vm !== null && (runnerPid === null || !isProcessAlive(runnerPid));
    const teardownComplete =
      vm !== null && closeError === null && runnerStopped;
    if (admissionError && teardownComplete) {
      throw admissionError;
    }
    if (!teardownComplete) {
      outcome = "teardown_failure";
      error = closeError
        ? safeError(closeError)
        : "VM teardown could not be confirmed";
    }

    const settledAt = new Date().toISOString();
    const teardown: CapabilityTeardownEvidence = {
      commandStopped,
      vmStopped: teardownComplete,
      vfsHandlesRevoked: teardownComplete,
      policyRemoved: teardownComplete,
      ...(networkEnabled ? { networkChannelsClosed: teardownComplete } : {}),
      ephemeralStateDestroyed: teardownComplete,
      completedAt: teardownComplete ? settledAt : null,
    };

    return {
      outcome,
      exitCode,
      stdout: output.stdoutText,
      stderr: output.stderrText,
      outputTruncated: output.overflowed,
      evidence: {
        schemaVersion: CAPABILITY_EVIDENCE_SCHEMA_VERSION,
        requestDigest: canonical.digest,
        ceilingDigest: this.ceilingDigest,
        executionId,
        vmId,
        runtime,
        policyVersions: {
          admission: "exact-reader/v1",
          filesystem: "snapshot-vfs/v1",
          ...(networkEnabled
            ? { network: "http-tls-mediator/v1" as const }
            : {}),
          lifecycle: "one-shot-qemu/v1",
        },
        inputDigest,
        outputDigest: inputDigest,
        requested,
        granted,
        attempted,
        denied,
        observed,
        startedAt,
        settledAt,
        teardown,
      },
      ...(error ? { error } : {}),
    };
  }

  private async executeWriter(
    canonical: CanonicalCapabilityRequest & {
      request: ExactWriterInvocationRequest;
    },
  ): Promise<CapabilityInvocationResult> {
    const request = canonical.request;
    const executionId = randomUUID();
    const startedAt = new Date().toISOString();
    const targetPath = request.capabilities.filesystem.targetPath;
    const targetIdentity = this.targetIdentities.get(targetPath);
    if (!targetIdentity) {
      throw new CapabilityAdmissionError(
        "ceiling_widening",
        "filesystem target has no identity in the immutable ceiling",
      );
    }
    const initial = readExactWriterTarget(targetPath, targetIdentity);
    const inputDigest = initial === null ? null : sha256(initial);
    const resourceId = sha256(`file:${targetPath}`);
    const requested = request.capabilities.filesystem.operations.map(
      (operation) => writerEffect(request, resourceId, operation, "requested"),
    );
    const granted = request.capabilities.filesystem.operations.map(
      (operation) => writerEffect(request, resourceId, operation, "granted"),
    );
    const attempted: CapabilityEffect[] = [];
    const denied: CapabilityEffect[] = [];
    const observed: CapabilityEffect[] = [];
    const abort = new AbortController();
    const output = new BoundedOutput(request.limits.outputBytes, abort);
    const provider = new MemoryProvider();
    const relativeGuestPath = request.capabilities.filesystem.guestPath.slice(
      "/data".length,
    );
    await populateWriterSnapshot(provider, relativeGuestPath, initial);

    let vm: VM | null = null;
    let vmId = "not-created";
    let runtime: VmRuntimeIdentity = unavailableRuntimeIdentity();
    let outcome: CapabilityInvocationOutcome = "transport_failure";
    let exitCode: number | null = null;
    let error: string | undefined;
    let timedOut = false;
    let commandStopped = false;
    let closeError: Error | null = null;
    let admissionError: CapabilityAdmissionError | null = null;
    let runnerPid: number | null = null;
    let timer: NodeJS.Timeout | null = null;

    const hooks = createWriterEvidenceHooks({
      exactPath: relativeGuestPath,
      guestPath: request.capabilities.filesystem.guestPath,
      resourceId,
      targetInitiallyExists: initial !== null,
      operations: new Set(request.capabilities.filesystem.operations),
      attempted,
      denied,
      observed,
    });

    try {
      vm = await VM.create({
        autoStart: false,
        startTimeoutMs: this.runtime.startTimeoutMs,
        memory: this.runtime.memory,
        cpus: this.runtime.cpus,
        rootfs: { mode: "readonly" },
        env: undefined,
        vfs: { mounts: { "/": provider }, hooks },
        sandbox: {
          vmm: "qemu",
          qemuPath: this.runtime.qemuPath,
          imagePath: this.runtime.imagePath,
          accel: this.runtime.accel,
          cpu: this.runtime.cpu,
          machineType: this.runtime.machineType,
          console: this.runtime.console ?? "none",
          autoRestart: false,
          netEnabled: false,
          allowWebSockets: false,
        },
      });
      vmId = vm.id;
      runtime = vm.getRuntimeIdentity();
      if (!runtime.guestFeatures.includes("exec.clear-env/v1")) {
        throw new CapabilityAdmissionError(
          "unsupported",
          "selected guest image does not declare exec.clear-env/v1",
        );
      }

      await vm.start();
      runnerPid = vm.getHostPid();
      timer = setTimeout(() => {
        timedOut = true;
        abort.abort();
      }, request.limits.wallTimeMs);
      timer.unref?.();

      const result = await vm.exec(
        [request.launch.executable, ...request.launch.args],
        {
          clearEnv: true,
          signal: abort.signal,
          stdin: false,
          pty: false,
          stdout: output.stdout,
          stderr: output.stderr,
          windowBytes: Math.min(request.limits.outputBytes + 1, 256 * 1024),
        },
      );
      commandStopped = true;
      exitCode = result.exitCode;
      outcome = result.exitCode === 0 ? "success" : "command_failed";
    } catch (caught) {
      commandStopped = true;
      if (caught instanceof CapabilityAdmissionError) {
        admissionError = caught;
        outcome = "transport_failure";
      } else if (output.overflowed) outcome = "output_overflow";
      else if (timedOut) outcome = "timeout";
      else outcome = "transport_failure";
      error = safeError(caught);
    } finally {
      if (timer) clearTimeout(timer);
      if (vm) {
        runnerPid ??= vm.getHostPid();
        try {
          await vm.close();
        } catch (caught) {
          closeError =
            caught instanceof Error ? caught : new Error(String(caught));
        }
      }
    }

    const runnerStopped =
      vm !== null && (runnerPid === null || !isProcessAlive(runnerPid));
    const teardownComplete =
      vm !== null && closeError === null && runnerStopped;
    let finalContents: Buffer | null = initial;
    if (admissionError && teardownComplete) throw admissionError;

    if (teardownComplete && hasObservedMutation(observed)) {
      try {
        finalContents = await readProviderFile(provider, relativeGuestPath);
        commitExactWriterTarget(
          targetPath,
          targetIdentity,
          finalContents,
          new Set(
            observed
              .map((effect) => effect.operation)
              .filter(isExactWriterOperation),
          ),
        );
      } catch (caught) {
        outcome = "commit_failure";
        error = safeError(caught);
        finalContents = null;
      }
    }
    if (!teardownComplete) {
      outcome = "teardown_failure";
      error = closeError
        ? safeError(closeError)
        : "VM teardown could not be confirmed";
    }

    const settledAt = new Date().toISOString();
    const teardown: CapabilityTeardownEvidence = {
      commandStopped,
      vmStopped: teardownComplete,
      vfsHandlesRevoked: teardownComplete,
      policyRemoved: teardownComplete,
      ephemeralStateDestroyed: teardownComplete,
      completedAt: teardownComplete ? settledAt : null,
    };

    return {
      outcome,
      exitCode,
      stdout: output.stdoutText,
      stderr: output.stderrText,
      outputTruncated: output.overflowed,
      evidence: {
        schemaVersion: CAPABILITY_EVIDENCE_SCHEMA_VERSION,
        requestDigest: canonical.digest,
        ceilingDigest: this.ceilingDigest,
        executionId,
        vmId,
        runtime,
        policyVersions: {
          admission: "exact-writer/v1",
          filesystem: "exact-writer-vfs/v1",
          lifecycle: "one-shot-qemu/v1",
        },
        inputDigest,
        outputDigest: finalContents === null ? null : sha256(finalContents),
        requested,
        granted,
        attempted,
        denied,
        observed,
        startedAt,
        settledAt,
        teardown,
      },
      ...(error ? { error } : {}),
    };
  }
}

class CollectingSink extends Writable {
  readonly chunks: Buffer[] = [];
  private readonly owner: BoundedOutput;

  constructor(owner: BoundedOutput) {
    super();
    this.owner = owner;
  }

  override _write(
    chunk: Buffer | string,
    encoding: BufferEncoding,
    callback: (error?: Error | null) => void,
  ): void {
    const data = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, encoding);
    this.owner.accept(this, data);
    callback();
  }
}

class BoundedOutput {
  readonly stdout: CollectingSink;
  readonly stderr: CollectingSink;
  overflowed = false;
  private acceptedBytes = 0;
  private readonly limit: number;
  private readonly abort: AbortController;

  constructor(limit: number, abort: AbortController) {
    this.limit = limit;
    this.abort = abort;
    this.stdout = new CollectingSink(this);
    this.stderr = new CollectingSink(this);
  }

  accept(sink: CollectingSink, data: Buffer): void {
    const remaining = Math.max(0, this.limit - this.acceptedBytes);
    if (remaining > 0) sink.chunks.push(data.subarray(0, remaining));
    this.acceptedBytes += Math.min(remaining, data.length);
    if (data.length > remaining && !this.overflowed) {
      this.overflowed = true;
      this.abort.abort();
    }
  }

  get stdoutText(): string {
    return Buffer.concat(this.stdout.chunks).toString("utf8");
  }

  get stderrText(): string {
    return Buffer.concat(this.stderr.chunks).toString("utf8");
  }
}

function createEvidenceHooks(options: {
  exactPath: string;
  guestPath: string;
  resourceId: string;
  networkEnabled: boolean;
  attempted: CapabilityEffect[];
  denied: CapabilityEffect[];
  observed: CapabilityEffect[];
}) {
  return {
    before(context: {
      op: string;
      path?: string;
      flags?: string | number;
    }): void {
      const guestPath = toGuestPath(context.path ?? "/");
      const providerPath = normalizeProviderPath(context.path ?? "/");
      const isExact = providerPath === options.exactPath;
      const isMountRoot = providerPath === "/";
      const operation = classifyOperation(context.op, context.flags);
      const effect: CapabilityFilesystemEffect = {
        domain: "filesystem",
        operation,
        resourceId: isExact ? options.resourceId : sha256(`guest:${guestPath}`),
        guestPath,
        decision: "attempted",
      };
      options.attempted.push(effect);

      const permittedMountLookup = isMountRoot && operation === "lookup";
      const permittedInfrastructureLookup =
        operation === "lookup" &&
        (providerPath === "/etc" || providerPath === "/etc/gondolin");
      const permittedNetworkTrustRead =
        options.networkEnabled &&
        (operation === "lookup" || operation === "read") &&
        (providerPath === "/etc/gondolin/mitm" ||
          providerPath === "/etc/gondolin/mitm/ca.crt");
      if (
        (!isExact &&
          !permittedMountLookup &&
          !permittedInfrastructureLookup &&
          !permittedNetworkTrustRead) ||
        operation === "write" ||
        operation === "other"
      ) {
        options.denied.push({ ...effect, decision: "denied" });
        throw createErrnoError(ERRNO.EACCES, context.op, context.path);
      }
    },
    after(context: {
      op: string;
      path?: string;
      flags?: string | number;
    }): void {
      const normalized = normalizeProviderPath(context.path ?? "/");
      if (normalized !== options.exactPath) return;
      options.observed.push({
        domain: "filesystem",
        operation: classifyOperation(context.op, context.flags),
        resourceId: options.resourceId,
        guestPath: options.guestPath,
        decision: "observed",
      });
    },
  };
}

type EvidenceHookContext = {
  op: string;
  path?: string;
  oldPath?: string;
  newPath?: string;
  flags?: string | number;
};

function createWriterEvidenceHooks(options: {
  exactPath: string;
  guestPath: string;
  resourceId: string;
  targetInitiallyExists: boolean;
  operations: ReadonlySet<ExactWriterOperation>;
  attempted: CapabilityEffect[];
  denied: CapabilityEffect[];
  observed: CapabilityEffect[];
}) {
  const effects = (
    context: EvidenceHookContext,
  ): Array<{
    operation: CapabilityFilesystemEffect["operation"];
    permitted: boolean;
  }> => {
    if (/^read/i.test(context.op))
      return [{ operation: "read", permitted: false }];
    if (/^(rename)/i.test(context.op))
      return [{ operation: "rename", permitted: false }];
    if (/^(unlink|rmdir)/i.test(context.op))
      return [{ operation: "delete", permitted: false }];
    if (/^(link|symlink)/i.test(context.op))
      return [{ operation: "link", permitted: false }];
    if (/^(chmod|chown|utimes)/i.test(context.op)) {
      return [{ operation: "metadata-write", permitted: false }];
    }
    if (/truncate/i.test(context.op)) {
      return [
        {
          operation: "truncate",
          permitted: options.operations.has("truncate"),
        },
      ];
    }
    if (/write/i.test(context.op)) {
      return [
        { operation: "write", permitted: options.operations.has("write") },
      ];
    }
    if (context.op === "open" && context.flags !== undefined) {
      const result: Array<{
        operation: CapabilityFilesystemEffect["operation"];
        permitted: boolean;
      }> = [];
      if (isWritableOpen(context.flags)) {
        if (!options.targetInitiallyExists && openCreates(context.flags)) {
          result.push({
            operation: "create",
            permitted: options.operations.has("create"),
          });
        }
        if (options.targetInitiallyExists && openTruncates(context.flags)) {
          result.push({
            operation: "truncate",
            permitted: options.operations.has("truncate"),
          });
        }
      }
      return result.length
        ? result
        : [{ operation: "lookup", permitted: true }];
    }
    if (
      /open|stat|access|realpath|release|readdir|readlink/i.test(context.op)
    ) {
      return [{ operation: "lookup", permitted: true }];
    }
    return [{ operation: "other", permitted: false }];
  };

  const pathFor = (context: EvidenceHookContext): string =>
    context.path ?? context.newPath ?? context.oldPath ?? "/";

  return {
    before(context: EvidenceHookContext): void {
      const rawPath = pathFor(context);
      const providerPath = normalizeProviderPath(rawPath);
      const guestPath = toGuestPath(rawPath);
      const isExact = providerPath === options.exactPath;
      const infrastructureLookup =
        providerPath === "/" ||
        providerPath === "/etc" ||
        providerPath === "/etc/gondolin";
      const operationEffects = effects(context);
      for (const item of operationEffects) {
        const effect: CapabilityEffect = {
          domain: "filesystem",
          operation: item.operation,
          resourceId: isExact
            ? options.resourceId
            : sha256(`guest:${guestPath}`),
          guestPath: isExact ? options.guestPath : guestPath,
          decision: "attempted",
        };
        options.attempted.push(effect);
        const allowedLookup =
          item.operation === "lookup" && infrastructureLookup;
        if ((!isExact && !allowedLookup) || !item.permitted) {
          options.denied.push({ ...effect, decision: "denied" });
          throw createErrnoError(ERRNO.EACCES, context.op, rawPath);
        }
      }
    },
    after(context: EvidenceHookContext): void {
      const providerPath = normalizeProviderPath(pathFor(context));
      if (providerPath !== options.exactPath) return;
      for (const item of effects(context)) {
        if (!item.permitted || item.operation === "lookup") continue;
        options.observed.push({
          domain: "filesystem",
          operation: item.operation,
          resourceId: options.resourceId,
          guestPath: options.guestPath,
          decision: "observed",
        });
      }
    },
  };
}

function classifyOperation(
  op: string,
  flags?: string | number,
): CapabilityFilesystemEffect["operation"] {
  if (op === "open" && flags !== undefined && isWritableOpen(flags))
    return "write";
  if (/write|truncate|mkdir|rmdir|unlink|rename|link|symlink/i.test(op))
    return "write";
  if (/read/i.test(op)) return "read";
  if (/open|stat|access|realpath|release|readdir/i.test(op)) return "lookup";
  return "other";
}

function isWritableOpen(flags: string | number): boolean {
  if (typeof flags === "string") return isWriteFlag(flags);
  const writeMask =
    fs.constants.O_WRONLY |
    fs.constants.O_RDWR |
    fs.constants.O_APPEND |
    fs.constants.O_CREAT |
    fs.constants.O_TRUNC;
  return (flags & writeMask) !== 0;
}

function openCreates(flags: string | number): boolean {
  return typeof flags === "string"
    ? /^[wax]/.test(flags)
    : (flags & fs.constants.O_CREAT) !== 0;
}

function openTruncates(flags: string | number): boolean {
  return typeof flags === "string"
    ? flags.startsWith("w")
    : (flags & fs.constants.O_TRUNC) !== 0;
}

async function populateSnapshot(
  provider: InstanceType<typeof MemoryProvider>,
  filePath: string,
  contents: Buffer,
): Promise<void> {
  const directory = path.posix.dirname(filePath);
  if (directory !== "/") {
    await provider.mkdir(directory, { recursive: true });
  }
  const handle = await provider.open(filePath, "w", 0o400);
  await handle.writeFile(contents);
  await handle.close();
  provider.setReadOnly();
}

async function populateWriterSnapshot(
  provider: InstanceType<typeof MemoryProvider>,
  filePath: string,
  contents: Buffer | null,
): Promise<void> {
  const directory = path.posix.dirname(filePath);
  if (directory !== "/") await provider.mkdir(directory, { recursive: true });
  if (contents === null) return;
  const handle = await provider.open(filePath, "w", 0o600);
  await handle.writeFile(contents);
  await handle.close();
}

async function readProviderFile(
  provider: InstanceType<typeof MemoryProvider>,
  filePath: string,
): Promise<Buffer> {
  const handle = await provider.open(filePath, "r");
  try {
    const contents = await handle.readFile();
    return Buffer.isBuffer(contents) ? contents : Buffer.from(contents);
  } finally {
    await handle.close();
  }
}

const CAPABILITY_HTTP_METHODS = [
  "GET",
  "HEAD",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "OPTIONS",
] as const;

function normalizeNetworkAuthority(
  input: unknown,
  label: string,
): CapabilityNetworkAuthority {
  if (input === "none") return "none";
  const root = object(input, label);
  exactKeys(root, ["rules"], label);
  if (!Array.isArray(root.rules)) invalid(`${label}.rules must be an array`);
  if (root.rules.length === 0) invalid(`${label}.rules cannot be empty`);

  const rules = root.rules.map((inputRule, index) => {
    const ruleLabel = `${label}.rules[${index}]`;
    const rule = object(inputRule, ruleLabel);
    exactKeys(
      rule,
      [
        "protocol",
        "destination",
        "port",
        "methods",
        "redirects",
        "resolution",
        "internalRanges",
      ],
      ruleLabel,
    );
    if (rule.protocol !== "http" && rule.protocol !== "tls") {
      unsupported(
        `${ruleLabel}.protocol supports only declarative http or tls`,
      );
    }
    if (
      rule.redirects !== "deny" &&
      rule.redirects !== "same-origin" &&
      rule.redirects !== "follow-authorized"
    ) {
      unsupported(`${ruleLabel}.redirects is unsupported`);
    }
    literal(
      rule.resolution,
      "checked-host",
      `${ruleLabel}.resolution`,
      "unsupported",
    );
    if (rule.internalRanges !== "deny" && rule.internalRanges !== "allow") {
      unsupported(`${ruleLabel}.internalRanges is unsupported`);
    }
    const methods = uniqueSorted(
      stringArray(rule.methods, `${ruleLabel}.methods`).map((method) => {
        if (!(CAPABILITY_HTTP_METHODS as readonly string[]).includes(method)) {
          unsupported(
            `${ruleLabel}.methods contains unsupported method: ${method}`,
          );
        }
        return method as CapabilityHttpMethod;
      }),
    );
    if (methods.length === 0) invalid(`${ruleLabel}.methods cannot be empty`);
    const destination = normalizeNetworkDestination(
      rule.destination,
      `${ruleLabel}.destination`,
    );
    const port = networkPort(rule.port, `${ruleLabel}.port`);
    if (
      rule.internalRanges === "deny" &&
      net.isIP(destination) !== 0 &&
      isInternalAddress(destination)
    ) {
      invalid(
        `${ruleLabel} has an empty intersection because its exact address is internal but internalRanges is deny`,
      );
    }
    return {
      protocol: rule.protocol,
      destination,
      port,
      methods,
      redirects: rule.redirects,
      resolution: "checked-host",
      internalRanges: rule.internalRanges,
    } satisfies CapabilityNetworkRule;
  });

  const origins = new Set<string>();
  for (const rule of rules) {
    const origin = networkOrigin(rule);
    if (origins.has(origin)) {
      invalid(
        `${label}.rules contains ambiguous duplicate authority for ${origin}`,
      );
    }
    origins.add(origin);
  }
  rules.sort((left, right) =>
    stableJson(left).localeCompare(stableJson(right)),
  );
  return { rules };
}

function normalizeNetworkDestination(value: unknown, label: string): string {
  const input = nonEmptyString(value, label);
  if (input !== input.trim() || input.includes("%")) {
    invalid(`${label} must be an unambiguous hostname or address`);
  }
  const unbracketed =
    input.startsWith("[") && input.endsWith("]") ? input.slice(1, -1) : input;
  const family = net.isIP(unbracketed);
  if (family === 4) return unbracketed;
  if (family === 6) {
    const hostname = new URL(`http://[${unbracketed}]/`).hostname;
    return hostname.slice(1, -1).toLowerCase();
  }
  if (input.startsWith("[") || input.endsWith("]")) {
    invalid(`${label} contains malformed address brackets`);
  }
  const withoutDot = input.endsWith(".") ? input.slice(0, -1) : input;
  const ascii = domainToASCII(withoutDot).toLowerCase();
  if (
    !ascii ||
    ascii.length > 253 ||
    ascii.includes("..") ||
    !ascii
      .split(".")
      .every(
        (part) =>
          part.length > 0 &&
          part.length <= 63 &&
          /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(part),
      )
  ) {
    invalid(`${label} must be a valid exact DNS hostname or IP address`);
  }
  const urlHostname = new URL(`http://${ascii}/`).hostname;
  if (net.isIP(urlHostname.replace(/^\[|\]$/g, "")) !== 0) {
    invalid(`${label} contains a non-canonical IP address`);
  }
  return ascii;
}

function networkPort(value: unknown, label: string): number {
  const port = positiveInteger(value, label);
  if (port > 65_535) invalid(`${label} must not exceed 65535`);
  return port;
}

function admitNetworkAuthority(
  request: CapabilityNetworkAuthority,
  ceiling: CapabilityNetworkAuthority | undefined,
): void {
  if (request === "none") return;
  if (!ceiling || ceiling === "none") {
    throw new CapabilityAdmissionError(
      "ceiling_widening",
      "network authority is outside the immutable ceiling",
    );
  }
  for (const requested of request.rules) {
    const permitted = ceiling.rules.find(
      (candidate) => networkOrigin(candidate) === networkOrigin(requested),
    );
    if (
      !permitted ||
      requested.methods.some((method) => !permitted.methods.includes(method)) ||
      redirectRank(requested.redirects) > redirectRank(permitted.redirects) ||
      (requested.internalRanges === "allow" &&
        permitted.internalRanges !== "allow")
    ) {
      throw new CapabilityAdmissionError(
        "ceiling_widening",
        `network authority is outside the immutable ceiling: ${networkOrigin(requested)}`,
      );
    }
  }
}

function redirectRank(value: CapabilityNetworkRule["redirects"]): number {
  if (value === "deny") return 0;
  if (value === "same-origin") return 1;
  return 2;
}

function networkOrigin(rule: CapabilityNetworkRule): string {
  return `${rule.protocol}://${rule.destination}:${rule.port}`;
}

function createInvocationHttpHooks(options: {
  authority: Exclude<CapabilityNetworkAuthority, "none">;
  requested: CapabilityEffect[];
  granted: CapabilityEffect[];
  attempted: CapabilityEffect[];
  denied: CapabilityEffect[];
  observed: CapabilityEffect[];
}): HttpHooks {
  for (const rule of options.authority.rules) {
    for (const method of rule.methods) {
      options.requested.push(
        networkEffect(rule, "request", "requested", method),
      );
      options.granted.push(networkEffect(rule, "request", "granted", method));
    }
  }

  const findRule = (
    protocol: string,
    destination: string,
    port: number,
    method?: string,
  ): CapabilityNetworkRule | undefined =>
    options.authority.rules.find(
      (rule) =>
        rule.protocol === protocol &&
        rule.destination === destination &&
        rule.port === port &&
        (method === undefined ||
          rule.methods.includes(method as CapabilityHttpMethod)),
    );

  return {
    isRequestAllowed(request) {
      const parsed = parseMediatedUrl(request.url);
      const method = request.method.toUpperCase();
      const rule = parsed
        ? findRule(parsed.protocol, parsed.destination, parsed.port, method)
        : undefined;
      const effect = parsed
        ? networkEffect(
            parsed,
            "request",
            rule ? "attempted" : "denied",
            method,
          )
        : unknownNetworkEffect("request", "denied", method);
      options.attempted.push({ ...effect, decision: "attempted" });
      if (!rule) options.denied.push({ ...effect, decision: "denied" });
      return Boolean(rule);
    },
    isIpAllowed(info: HttpIpAllowInfo) {
      const protocol = info.protocol === "https" ? "tls" : "http";
      const destination = normalizeObservedDestination(info.hostname);
      const rule = findRule(protocol, destination, info.port);
      const allowed = Boolean(
        rule &&
        (rule.internalRanges === "allow" || !isInternalAddress(info.ip)),
      );
      const operation =
        info.phase === "connection" ? "connection" : "resolution";
      const effect: CapabilityNetworkEffect = {
        domain: "network",
        operation,
        protocol,
        destination,
        port: info.port,
        addressId: sha256(`address:${info.ip}`),
        decision: "attempted",
      };
      options.attempted.push(effect);
      (allowed ? options.observed : options.denied).push({
        ...effect,
        decision: allowed ? "observed" : "denied",
      });
      return allowed;
    },
    isRedirectAllowed(source, target) {
      const from = parseMediatedUrl(source.url);
      const to = parseMediatedUrl(target.url);
      const sourceMethod = source.method.toUpperCase();
      const targetMethod = target.method.toUpperCase();
      const sourceRule = from
        ? findRule(from.protocol, from.destination, from.port, sourceMethod)
        : undefined;
      const targetRule = to
        ? findRule(to.protocol, to.destination, to.port, targetMethod)
        : undefined;
      const sameOrigin = Boolean(
        from && to && networkOrigin(from) === networkOrigin(to),
      );
      const allowed = Boolean(
        sourceRule &&
        targetRule &&
        (sourceRule.redirects === "follow-authorized" ||
          (sourceRule.redirects === "same-origin" && sameOrigin)),
      );
      const effect = to
        ? networkEffect(
            to,
            "redirect",
            allowed ? "observed" : "denied",
            targetMethod,
          )
        : unknownNetworkEffect("redirect", "denied", targetMethod);
      options.attempted.push({ ...effect, decision: "attempted" });
      (allowed ? options.observed : options.denied).push(effect);
      return allowed;
    },
    onResponse(response, request) {
      const parsed = parseMediatedUrl(request.url);
      if (parsed) {
        options.observed.push(
          networkEffect(
            parsed,
            "completion",
            "observed",
            request.method.toUpperCase(),
          ),
        );
      }
      return response;
    },
    onFlowDecision(info) {
      const protocol =
        info.protocol === "http" ||
        info.protocol === "tls" ||
        info.protocol === "ssh" ||
        info.protocol === "tcp"
          ? info.protocol
          : "unknown";
      const effect: CapabilityNetworkEffect = {
        domain: "network",
        operation: "flow",
        protocol,
        destination: sha256(`guest-flow:${info.destination}`),
        port: info.port,
        decision: "attempted",
      };
      options.attempted.push(effect);
      (info.allowed ? options.observed : options.denied).push({
        ...effect,
        decision: info.allowed ? "observed" : "denied",
      });
    },
  };
}

function parseMediatedUrl(url: string): CapabilityNetworkRule | null {
  try {
    const parsed = new URL(url);
    const protocol =
      parsed.protocol === "http:"
        ? "http"
        : parsed.protocol === "https:"
          ? "tls"
          : null;
    if (!protocol) return null;
    return {
      protocol,
      destination: normalizeObservedDestination(parsed.hostname),
      port: parsed.port ? Number(parsed.port) : protocol === "tls" ? 443 : 80,
      methods: [],
      redirects: "deny",
      resolution: "checked-host",
      internalRanges: "deny",
    };
  } catch {
    return null;
  }
}

function normalizeObservedDestination(value: string): string {
  const unbracketed =
    value.startsWith("[") && value.endsWith("]") ? value.slice(1, -1) : value;
  if (net.isIP(unbracketed) === 6) {
    return new URL(`http://[${unbracketed}]/`).hostname
      .slice(1, -1)
      .toLowerCase();
  }
  return unbracketed.replace(/\.$/, "").toLowerCase();
}

function networkEffect(
  rule: Pick<CapabilityNetworkRule, "protocol" | "destination" | "port">,
  operation: CapabilityNetworkEffect["operation"],
  decision: CapabilityEffectDecision,
  method?: string,
): CapabilityNetworkEffect {
  return {
    domain: "network",
    operation,
    protocol: rule.protocol,
    destination: rule.destination,
    port: rule.port,
    ...(method ? { method } : {}),
    decision,
  };
}

function unknownNetworkEffect(
  operation: CapabilityNetworkEffect["operation"],
  decision: CapabilityEffectDecision,
  method?: string,
): CapabilityNetworkEffect {
  return {
    domain: "network",
    operation,
    protocol: "unknown",
    destination: "unparseable",
    port: 0,
    ...(method ? { method } : {}),
    decision,
  };
}

function isInternalAddress(ip: string): boolean {
  const family = net.isIP(ip);
  if (family === 4) return isPrivateIPv4(ip);
  if (family === 6) return isPrivateIPv6(ip);
  return true;
}

function isPrivateIPv4(ip: string): boolean {
  const octets = ip.split(".").map(Number);
  if (octets.length !== 4 || octets.some((part) => !Number.isInteger(part))) {
    return true;
  }
  const [a, b] = octets;
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 169 && b === 254) ||
    (a === 172 && b! >= 16 && b! <= 31) ||
    (a === 192 && b === 0 && (octets[2] === 0 || octets[2] === 2)) ||
    (a === 192 && b === 168) ||
    (a === 100 && b! >= 64 && b! <= 127) ||
    (a === 198 && (b === 18 || b === 19)) ||
    (a === 198 && b === 51 && octets[2] === 100) ||
    (a === 203 && b === 0 && octets[2] === 113) ||
    a! >= 224
  );
}

function isPrivateIPv6(ip: string): boolean {
  const hextets = parseIPv6Hextets(ip);
  if (!hextets) return true;
  const allZero = hextets.every((value) => value === 0);
  const loopback =
    hextets.slice(0, 7).every((value) => value === 0) && hextets[7] === 1;
  if (allZero || loopback) return true;
  // Deprecated IPv4-compatible addresses can otherwise tunnel internal IPv4.
  if (hextets.slice(0, 6).every((value) => value === 0)) return true;
  // Reject the local-use NAT64 prefix, and inspect embedded IPv4 in WKP NAT64.
  if (hextets[0] === 0x64 && hextets[1] === 0xff9b) {
    if (hextets[2] === 1) return true;
    if (hextets.slice(2, 6).every((value) => value === 0)) {
      const embedded = `${hextets[6]! >> 8}.${hextets[6]! & 0xff}.${hextets[7]! >> 8}.${hextets[7]! & 0xff}`;
      return isPrivateIPv4(embedded);
    }
  }
  if ((hextets[0]! & 0xfe00) === 0xfc00) return true;
  if ((hextets[0]! & 0xffc0) === 0xfe80) return true;
  if ((hextets[0]! & 0xff00) === 0xff00) return true;
  if (hextets[0] === 0x100 && hextets.slice(1, 4).every((v) => v === 0)) {
    return true;
  }
  // Conservatively deny non-global and transition/documentation assignments.
  if (hextets[0] === 0x2001 && (hextets[1]! & 0xfe00) === 0) return true;
  if (hextets[0] === 0x2001 && hextets[1] === 0x0db8) return true;
  if (hextets[0] === 0x2002) return true;
  if (hextets[0] === 0x3fff && (hextets[1]! & 0xf000) === 0) return true;
  if (hextets[0] === 0x5f00) return true;
  const mapped = extractIPv4Mapped(hextets);
  return mapped ? isPrivateIPv4(mapped) : false;
}

function normalizeCeiling(input: unknown): CapabilityCeiling {
  const root = object(input, "ceiling");
  const rawProfile = capabilityProfile(root.profile, "ceiling.profile");
  exactKeys(
    root,
    CEILING_KEYS,
    "ceiling",
    rawProfile === "exact-reader" ? CEILING_OPTIONAL_KEYS : [],
  );
  literal(
    root.schemaVersion,
    CAPABILITY_CEILING_SCHEMA_VERSION,
    "ceiling.schemaVersion",
    "unsupported",
  );
  const profile = rawProfile;
  const filesystem = object(root.filesystem, "ceiling.filesystem");
  exactKeys(
    filesystem,
    profile === "exact-reader"
      ? ["sourcePaths", "guestPaths"]
      : ["targetPaths", "guestPaths", "operations"],
    "ceiling.filesystem",
  );
  const limits = object(root.limits, "ceiling.limits");
  exactKeys(limits, ["maxOutputBytes", "maxWallTimeMs"], "ceiling.limits");

  const guestPaths = stringArray(
    filesystem.guestPaths,
    "ceiling.filesystem.guestPaths",
  ).map((value) =>
    normalizeGuestPath(value, "ceiling.filesystem.guestPaths", profile),
  );
  const allowedExecutables = stringArray(
    root.allowedExecutables,
    "ceiling.allowedExecutables",
  ).map((value) =>
    absoluteGuestExecutable(value, "ceiling.allowedExecutables"),
  );
  const guarantees = guaranteeArray(
    root.guarantees,
    "ceiling.guarantees",
    profile,
  );
  const hostPaths =
    profile === "exact-reader"
      ? stringArray(
          filesystem.sourcePaths,
          "ceiling.filesystem.sourcePaths",
        ).map((value) =>
          canonicalHostFile(value, "ceiling.filesystem.sourcePaths"),
        )
      : stringArray(
          filesystem.targetPaths,
          "ceiling.filesystem.targetPaths",
        ).map((value) =>
          canonicalHostTarget(value, "ceiling.filesystem.targetPaths"),
        );
  const network =
    profile === "exact-reader"
      ? normalizeNetworkAuthority(root.network ?? "none", "ceiling.network")
      : undefined;
  if (
    !hostPaths.length ||
    !guestPaths.length ||
    !allowedExecutables.length ||
    !guarantees.length
  ) {
    invalid("ceiling intersections cannot be empty");
  }

  const common = {
    schemaVersion: CAPABILITY_CEILING_SCHEMA_VERSION,
    allowedExecutables: uniqueSorted(allowedExecutables),
    limits: {
      maxOutputBytes: positiveInteger(
        limits.maxOutputBytes,
        "ceiling.limits.maxOutputBytes",
      ),
      maxWallTimeMs: positiveInteger(
        limits.maxWallTimeMs,
        "ceiling.limits.maxWallTimeMs",
      ),
    },
  };
  if (profile === "exact-reader") {
    return {
      ...common,
      profile,
      filesystem: {
        sourcePaths: uniqueSorted(hostPaths),
        guestPaths: uniqueSorted(guestPaths),
      },
      network,
      guarantees: uniqueSorted(guarantees as ExactReaderGuarantee[]),
    };
  }
  const operations = writerOperationArray(
    filesystem.operations,
    "ceiling.filesystem.operations",
  );
  if (operations.length === 0) invalid("ceiling intersections cannot be empty");
  return {
    ...common,
    profile,
    filesystem: {
      targetPaths: uniqueSorted(hostPaths),
      guestPaths: uniqueSorted(guestPaths),
      operations: uniqueSorted(operations),
    },
    guarantees: uniqueSorted(guarantees as ExactWriterGuarantee[]),
  };
}

function normalizeRequest(input: unknown): CapabilityInvocationRequest {
  const root = object(input, "request");
  exactKeys(root, REQUEST_KEYS, "request");
  literal(
    root.schemaVersion,
    CAPABILITY_INVOCATION_SCHEMA_VERSION,
    "request.schemaVersion",
    "unsupported",
  );
  const profile = capabilityProfile(root.profile, "request.profile");
  const invocationId = nonEmptyString(
    root.invocationId,
    "request.invocationId",
  );
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(invocationId)) {
    invalid("request.invocationId contains unsupported characters");
  }

  const launch = object(root.launch, "request.launch");
  exactKeys(launch, ["executable", "args"], "request.launch");
  const capabilities = object(root.capabilities, "request.capabilities");
  exactKeys(
    capabilities,
    ["filesystem", "network", "environment"],
    "request.capabilities",
  );
  const network = normalizeNetworkAuthority(
    capabilities.network,
    "request.capabilities.network",
  );
  const environment = object(
    capabilities.environment,
    "request.capabilities.environment",
  );
  exactKeys(environment, [], "request.capabilities.environment");

  const filesystem = object(
    capabilities.filesystem,
    "request.capabilities.filesystem",
  );
  exactKeys(
    filesystem,
    profile === "exact-reader"
      ? ["sourcePath", "guestPath", "operations"]
      : ["targetPath", "guestPath", "operations"],
    "request.capabilities.filesystem",
  );
  const operationValues = stringArray(
    filesystem.operations,
    "request.capabilities.filesystem.operations",
  );
  if (
    profile === "exact-reader" &&
    (operationValues.length !== 1 || operationValues[0] !== "read")
  ) {
    unsupported("only the exact reader operation ['read'] is supported");
  }

  const limits = object(root.limits, "request.limits");
  exactKeys(limits, ["outputBytes", "wallTimeMs"], "request.limits");

  const requiredGuarantees = uniqueSorted(
    guaranteeArray(
      root.requiredGuarantees,
      "request.requiredGuarantees",
      profile,
    ),
  );
  if (requiredGuarantees.length === 0) {
    invalid("request.requiredGuarantees cannot be empty");
  }

  const common = {
    schemaVersion: CAPABILITY_INVOCATION_SCHEMA_VERSION,
    invocationId,
    launch: {
      executable: absoluteGuestExecutable(
        launch.executable,
        "request.launch.executable",
      ),
      args: stringArray(launch.args, "request.launch.args"),
    },
    limits: {
      outputBytes: positiveInteger(
        limits.outputBytes,
        "request.limits.outputBytes",
      ),
      wallTimeMs: positiveInteger(
        limits.wallTimeMs,
        "request.limits.wallTimeMs",
      ),
    },
  };
  const guestPath = normalizeGuestPath(
    filesystem.guestPath,
    "request.capabilities.filesystem.guestPath",
    profile,
  );
  if (profile === "exact-reader") {
    return {
      ...common,
      profile,
      capabilities: {
        filesystem: {
          sourcePath: canonicalHostFile(
            filesystem.sourcePath,
            "request.capabilities.filesystem.sourcePath",
          ),
          guestPath,
          operations: ["read"],
        },
        network,
        environment: {},
      },
      requiredGuarantees: requiredGuarantees as ExactReaderGuarantee[],
    };
  }
  const operations = uniqueSorted(
    writerOperationArray(
      filesystem.operations,
      "request.capabilities.filesystem.operations",
    ),
  );
  if (operations.length === 0) {
    invalid("request.capabilities.filesystem.operations cannot be empty");
  }
  if (network !== "none") {
    unsupported("exact-writer supports only capabilities.network = 'none'");
  }
  return {
    ...common,
    profile,
    capabilities: {
      filesystem: {
        targetPath: canonicalHostTarget(
          filesystem.targetPath,
          "request.capabilities.filesystem.targetPath",
        ),
        guestPath,
        operations,
      },
      network: "none",
      environment: {},
    },
    requiredGuarantees: requiredGuarantees as ExactWriterGuarantee[],
  };
}

function canonicalHostFile(value: unknown, label: string): string {
  const input = nonEmptyString(value, label);
  const lexical = path.resolve(input);
  let stats: fs.Stats;
  try {
    stats = fs.lstatSync(lexical);
  } catch {
    invalid(`${label} must identify an existing host file`);
  }
  if (stats!.isSymbolicLink() || !stats!.isFile()) {
    invalid(
      `${label} must identify a regular file without symlink indirection`,
    );
  }
  return fs.realpathSync(lexical);
}

function canonicalHostTarget(value: unknown, label: string): string {
  const input = nonEmptyString(value, label);
  const lexical = path.resolve(input);
  const parent = path.dirname(lexical);
  let canonicalParent: string;
  try {
    canonicalParent = fs.realpathSync(parent);
  } catch {
    invalid(`${label} parent must identify an existing directory`);
  }
  const target = path.join(canonicalParent!, path.basename(lexical));
  if (
    target
      .split(path.sep)
      .some((component) => component.toLowerCase() === ".git")
  ) {
    unsupported(`${label} cannot select Git metadata`);
  }
  try {
    const stats = fs.lstatSync(target, { bigint: true });
    if (stats.isSymbolicLink() || !stats.isFile()) {
      invalid(
        `${label} must identify a regular file or a missing exact target`,
      );
    }
    if (stats.nlink !== 1n) {
      invalid(`${label} cannot select a hard-linked file`);
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  return target;
}

type HostFileIdentity = {
  dev: bigint;
  ino: bigint;
};

type HostWriterTargetIdentity = {
  parent: HostFileIdentity;
  file: HostFileIdentity | null;
};

function getHostWriterTargetIdentity(
  targetPath: string,
): HostWriterTargetIdentity {
  const parent = getHostDirectoryIdentity(path.dirname(targetPath));
  try {
    const stats = fs.lstatSync(targetPath, { bigint: true });
    if (stats.isSymbolicLink() || !stats.isFile() || stats.nlink !== 1n) {
      invalid("filesystem target must remain a uniquely linked regular file");
    }
    return { parent, file: { dev: stats.dev, ino: stats.ino } };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return { parent, file: null };
    }
    throw error;
  }
}

function getHostDirectoryIdentity(directoryPath: string): HostFileIdentity {
  let fd: number;
  try {
    fd = fs.openSync(
      directoryPath,
      fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY ?? 0),
    );
  } catch {
    invalid("filesystem target parent changed or could not be opened");
  }
  try {
    const stats = fs.fstatSync(fd!, { bigint: true });
    if (!stats.isDirectory())
      invalid("filesystem target parent is no longer a directory");
    return { dev: stats.dev, ino: stats.ino };
  } finally {
    fs.closeSync(fd!);
  }
}

function getHostFileIdentity(filePath: string): HostFileIdentity {
  const noFollow = fs.constants.O_NOFOLLOW;
  if (typeof noFollow !== "number") {
    unsupported(
      "host platform cannot open exact files without following links",
    );
  }
  let fd: number;
  try {
    fd = fs.openSync(filePath, fs.constants.O_RDONLY | noFollow);
  } catch {
    invalid(
      "filesystem source changed or could not be opened without symlink traversal",
    );
  }
  try {
    const stats = fs.fstatSync(fd!, { bigint: true });
    if (!stats.isFile())
      invalid("filesystem source is no longer a regular file");
    return { dev: stats.dev, ino: stats.ino };
  } finally {
    fs.closeSync(fd!);
  }
}

function readExactHostFile(
  filePath: string,
  expected: HostFileIdentity,
): Buffer {
  const noFollow = fs.constants.O_NOFOLLOW;
  if (typeof noFollow !== "number") {
    unsupported(
      "host platform cannot open exact files without following links",
    );
  }
  let fd: number;
  try {
    fd = fs.openSync(filePath, fs.constants.O_RDONLY | noFollow);
  } catch {
    invalid(
      "filesystem source changed or could not be opened without symlink traversal",
    );
  }
  try {
    const stats = fs.fstatSync(fd!, { bigint: true });
    if (!stats.isFile())
      invalid("filesystem source is no longer a regular file");
    if (stats.dev !== expected.dev || stats.ino !== expected.ino) {
      invalid("filesystem source identity changed after ceiling creation");
    }
    return fs.readFileSync(fd!);
  } finally {
    fs.closeSync(fd!);
  }
}

function readExactWriterTarget(
  targetPath: string,
  expected: HostWriterTargetIdentity,
): Buffer | null {
  verifyHostDirectoryIdentity(path.dirname(targetPath), expected.parent);
  if (expected.file === null) {
    try {
      fs.lstatSync(targetPath);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw error;
    }
    invalid("filesystem target appeared after ceiling creation");
  }
  const fd = openExactWriterFile(
    targetPath,
    expected.file,
    fs.constants.O_RDONLY,
  );
  try {
    return fs.readFileSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

function openExactWriterFile(
  targetPath: string,
  expected: HostFileIdentity,
  access: number,
): number {
  const noFollow = fs.constants.O_NOFOLLOW;
  if (typeof noFollow !== "number") {
    unsupported(
      "host platform cannot open exact writer targets without following links",
    );
  }
  let fd: number;
  try {
    fd = fs.openSync(targetPath, access | noFollow);
  } catch {
    invalid(
      "filesystem target changed or could not be opened without symlink traversal",
    );
  }
  const stats = fs.fstatSync(fd!, { bigint: true });
  if (
    !stats.isFile() ||
    stats.nlink !== 1n ||
    stats.dev !== expected.dev ||
    stats.ino !== expected.ino
  ) {
    fs.closeSync(fd!);
    invalid("filesystem target identity changed after ceiling creation");
  }
  return fd!;
}

function verifyHostDirectoryIdentity(
  directoryPath: string,
  expected: HostFileIdentity,
): void {
  const actual = getHostDirectoryIdentity(directoryPath);
  if (actual.dev !== expected.dev || actual.ino !== expected.ino) {
    invalid("filesystem target parent identity changed after ceiling creation");
  }
}

function commitExactWriterTarget(
  targetPath: string,
  expected: HostWriterTargetIdentity,
  contents: Buffer,
  observedOperations: ReadonlySet<ExactWriterOperation> = new Set([
    "create",
    "write",
    "truncate",
  ]),
): void {
  verifyHostDirectoryIdentity(path.dirname(targetPath), expected.parent);
  let fd: number;
  if (expected.file === null) {
    if (!observedOperations.has("create")) {
      invalid("writer produced a missing target without an observed create");
    }
    const noFollow = fs.constants.O_NOFOLLOW;
    if (typeof noFollow !== "number") {
      unsupported(
        "host platform cannot create exact writer targets without following links",
      );
    }
    try {
      fd = fs.openSync(
        targetPath,
        fs.constants.O_CREAT |
          fs.constants.O_EXCL |
          fs.constants.O_RDWR |
          noFollow,
        0o600,
      );
    } catch {
      invalid("filesystem target appeared or changed before exact creation");
    }
  } else {
    fd = openExactWriterFile(targetPath, expected.file, fs.constants.O_RDWR);
  }
  try {
    if (expected.file === null || observedOperations.has("truncate")) {
      fs.ftruncateSync(fd!, 0);
      if (contents.length) fs.writeSync(fd!, contents, 0, contents.length, 0);
    } else if (observedOperations.has("write")) {
      const before = fs.readFileSync(fd!);
      writeChangedRanges(fd!, before, contents);
    }
    fs.fsyncSync(fd!);
    const stats = fs.fstatSync(fd!, { bigint: true });
    if (!stats.isFile() || stats.nlink !== 1n) {
      invalid(
        "filesystem target gained an alternate hard-link alias during commit",
      );
    }
  } finally {
    fs.closeSync(fd!);
  }
  verifyHostDirectoryIdentity(path.dirname(targetPath), expected.parent);
}

function writeChangedRanges(fd: number, before: Buffer, after: Buffer): void {
  if (after.length < before.length) {
    invalid("writer shortened the target without truncate authority");
  }
  let offset = 0;
  while (offset < after.length) {
    if (offset < before.length && before[offset] === after[offset]) {
      offset += 1;
      continue;
    }
    const start = offset;
    while (
      offset < after.length &&
      (offset >= before.length || before[offset] !== after[offset])
    ) {
      offset += 1;
    }
    fs.writeSync(fd, after, start, offset - start, start);
  }
}

function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code !== "ESRCH";
  }
}

function normalizeGuestPath(
  value: unknown,
  label: string,
  profile: "exact-reader" | "exact-writer" = "exact-reader",
): string {
  const input = nonEmptyString(value, label);
  if (input.includes("\0") || !input.startsWith("/data/")) {
    invalid(`${label} must be an absolute path below /data`);
  }
  const normalized = path.posix.normalize(input);
  if (normalized !== input || normalized === "/data" || input.endsWith("/")) {
    invalid(`${label} is ambiguous or non-canonical`);
  }
  if (path.posix.dirname(normalized) !== "/data") {
    invalid(`${label} must be a direct child of /data in ${profile}/v1`);
  }
  return normalized;
}

function absoluteGuestExecutable(value: unknown, label: string): string {
  const input = nonEmptyString(value, label);
  if (
    !input.startsWith("/") ||
    input.includes("\0") ||
    path.posix.normalize(input) !== input
  ) {
    invalid(`${label} must be a canonical absolute guest path`);
  }
  return input;
}

function guaranteeArray(
  value: unknown,
  label: string,
  profile: "exact-reader" | "exact-writer",
): Array<ExactReaderGuarantee | ExactWriterGuarantee> {
  const values = stringArray(value, label);
  const supported =
    profile === "exact-reader"
      ? [...EXACT_READER_GUARANTEES, ...HTTP_TLS_EGRESS_GUARANTEES]
      : EXACT_WRITER_GUARANTEES;
  for (const item of values) {
    if (!(supported as readonly string[]).includes(item)) {
      unsupported(`unknown or unsupported critical guarantee: ${item}`);
    }
  }
  return values as Array<ExactReaderGuarantee | ExactWriterGuarantee>;
}

function capabilityProfile(
  value: unknown,
  label: string,
): "exact-reader" | "exact-writer" {
  if (value === "exact-reader" || value === "exact-writer") return value;
  unsupported(`${label} is unknown or unsupported`);
}

function writerOperationArray(
  value: unknown,
  label: string,
): ExactWriterOperation[] {
  const values = stringArray(value, label);
  for (const item of values) {
    if (!isExactWriterOperation(item)) {
      unsupported(`unknown or unsupported exact-writer operation: ${item}`);
    }
  }
  return values as ExactWriterOperation[];
}

function isExactWriterOperation(value: string): value is ExactWriterOperation {
  return value === "create" || value === "write" || value === "truncate";
}

function object(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    invalid(`${label} must be an object`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    invalid(`${label} must be a plain data object`);
  }
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== "string") {
      invalid(`${label} must contain only string-keyed declarative data`);
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || descriptor.get || descriptor.set) {
      invalid(`${label}.${key} must be a plain data property`);
    }
  }
  return value as Record<string, unknown>;
}

function exactKeys(
  value: Record<string, unknown>,
  allowed: readonly string[],
  label: string,
  optional: readonly string[] = [],
): void {
  const known = [...allowed, ...optional];
  const unknown = Object.keys(value).filter((key) => !known.includes(key));
  const missing = allowed.filter((key) => !Object.hasOwn(value, key));
  if (unknown.length)
    invalid(
      `${label} contains unknown critical field(s): ${unknown.sort().join(", ")}`,
    );
  if (missing.length)
    invalid(`${label} is missing required field(s): ${missing.join(", ")}`);
}

function stringArray(value: unknown, label: string): string[] {
  if (!Array.isArray(value)) invalid(`${label} must be an array`);
  return value.map((item, index) => nonEmptyString(item, `${label}[${index}]`));
}

function nonEmptyString(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0 || value.includes("\0")) {
    invalid(`${label} must be a non-empty string without NUL bytes`);
  }
  return value;
}

function positiveInteger(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) {
    invalid(`${label} must be a positive safe integer`);
  }
  return value;
}

function literal(
  value: unknown,
  expected: string,
  label: string,
  code: "invalid_request" | "unsupported",
): void {
  if (value === expected) return;
  throw new CapabilityAdmissionError(
    code,
    `${label} must be ${JSON.stringify(expected)}`,
  );
}

function invalid(message: string): never {
  throw new CapabilityAdmissionError("invalid_request", message);
}

function unsupported(message: string): never {
  throw new CapabilityAdmissionError("unsupported", message);
}

function uniqueSorted<T extends string>(values: T[]): T[] {
  return [...new Set(values)].sort() as T[];
}

function stableJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`)
    .join(",")}}`;
}

function sha256(value: string | Buffer): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function deepFreeze<T>(value: T): T {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    for (const nested of Object.values(value as Record<string, unknown>))
      deepFreeze(nested);
    Object.freeze(value);
  }
  return value;
}

function normalizeProviderPath(value: string): string {
  const normalized = path.posix.normalize(
    value.startsWith("/") ? value : `/${value}`,
  );
  return normalized;
}

function toGuestPath(providerPath: string): string {
  const normalized = normalizeProviderPath(providerPath);
  return normalized === "/" ? "/data" : `/data${normalized}`;
}

function fileEffect(
  request: ExactReaderInvocationRequest,
  resourceId: string,
  decision: "requested" | "granted",
): CapabilityEffect {
  return {
    domain: "filesystem",
    operation: "read",
    resourceId,
    guestPath: request.capabilities.filesystem.guestPath,
    decision,
  };
}

function writerEffect(
  request: ExactWriterInvocationRequest,
  resourceId: string,
  operation: ExactWriterOperation,
  decision: "requested" | "granted",
): CapabilityEffect {
  return {
    domain: "filesystem",
    operation,
    resourceId,
    guestPath: request.capabilities.filesystem.guestPath,
    decision,
  };
}

function hasObservedMutation(effects: readonly CapabilityEffect[]): boolean {
  return effects.some((effect) => isExactWriterOperation(effect.operation));
}

function unavailableRuntimeIdentity(): VmRuntimeIdentity {
  return {
    vmm: "qemu",
    hostPlatform: process.platform,
    hostArchitecture: process.arch,
    imageDigest: "unavailable",
    guestKernelDigest: "unavailable",
    guestControlDigest: "unavailable",
    guestFeatures: [],
  };
}

function safeError(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  return message.slice(0, 512);
}
