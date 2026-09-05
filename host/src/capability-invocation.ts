import { createHash, randomBytes } from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { domainToASCII } from "node:url";

import { VM, type VmRuntimeIdentity } from "./vm/core.ts";
import type { ImagePath } from "./sandbox/server-options.ts";
import {
  ON_REQUEST_EARLY_POLICY_SAFE,
  type HttpHooks,
  type HttpIpAllowInfo,
} from "./qemu/contracts.ts";
import { extractIPv4Mapped, parseIPv6Hextets } from "./utils/ip.ts";
import { HttpRequestBlockedError } from "./http/utils.ts";
import { MemoryProvider } from "./vfs/node/index.ts";
import { createErrnoError } from "./vfs/errors.ts";
import { ERRNO, isWriteFlag } from "./vfs/utils.ts";
import { BoundedOutput } from "./bounded-output.ts";
import {
  CAPABILITY_EVIDENCE_SCHEMA_VERSION,
  CAPABILITY_FEATURE_SCHEMA_VERSION,
  AuthenticatedExecutionIdentity,
  capabilityQualificationId,
  capabilityResultDigest,
  gondolinVersion,
  sealCapabilityEvidence,
  type AuthenticatedEvidenceEvent,
  type CapabilityEvidenceDecision,
  type CapabilityEvidenceIntegrity,
} from "./invocation-evidence.ts";
import {
  canonicalHostFile,
  canonicalHostTarget,
  commitExactWriterTarget,
  getHostFileIdentity,
  getHostWriterTargetIdentity,
  readExactHostFile,
  readExactWriterTarget,
  type CapabilityFilesystemValidation,
  type HostFileIdentity,
  type HostWriterTargetIdentity,
} from "./capability-filesystem.ts";
import { deepFreeze, sha256, stableJson } from "./canonical-json.ts";
import {
  isProcessAlive,
  unavailableRuntimeIdentity,
  uniqueSorted,
} from "./capability-runtime.ts";

export { CAPABILITY_EVIDENCE_SCHEMA_VERSION } from "./invocation-evidence.ts";

export const CAPABILITY_CEILING_SCHEMA_VERSION =
  "gondolin.capability-ceiling/v1" as const;
export const CAPABILITY_INVOCATION_SCHEMA_VERSION =
  "gondolin.capability-invocation/v1" as const;

const capabilityFilesystemValidation: CapabilityFilesystemValidation = {
  invalid,
  unsupported,
  nonEmptyString,
};

export const CAPABILITY_EVIDENCE_GUARANTEES = [
  "authenticated-execution-identity",
  "concurrent-disjoint-authority",
  "tamper-evident-evidence",
  "independent-evidence-verification",
] as const;

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
  ...CAPABILITY_EVIDENCE_GUARANTEES,
] as const;

export const HTTP_TLS_EGRESS_GUARANTEES = [
  "http-tls-egress",
  "checked-resolution",
  "redirect-reauthorization",
  "invocation-network-identity",
  "network-channel-teardown",
] as const;

export const DESTINATION_BOUND_CREDENTIAL_GUARANTEES = [
  "destination-bound-credentials",
  "invocation-credential-identity",
  "credential-redaction",
  "credential-teardown",
] as const;

export type ExactReaderGuarantee =
  | (typeof EXACT_READER_GUARANTEES)[number]
  | (typeof HTTP_TLS_EGRESS_GUARANTEES)[number]
  | (typeof DESTINATION_BOUND_CREDENTIAL_GUARANTEES)[number];

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
  | "none"
  | {
      /** Exact HTTP/TLS authorities */
      rules: CapabilityNetworkRule[];
    };

export type CapabilityCredentialValidity = {
  /** Earliest permitted redemption timestamp */
  notBefore?: string;
  /** Last permitted redemption timestamp */
  expiresAt?: string;
};

export type CapabilityCredentialProjection = {
  /** Opaque trusted-controller credential reference */
  reference: string;
  /** Guest-visible environment variable name */
  projection: string;
  /** Safe identity retained in evidence and logs */
  redactionId: string;
  /** Exact content-aware transport */
  protocol: "http" | "tls";
  /** Exact normalized DNS hostname or IP address */
  destination: string;
  /** Exact destination TCP port */
  port: number;
  /** Uppercase HTTP methods permitted to redeem the placeholder */
  methods: CapabilityHttpMethod[];
  /** Invocation-declared credential validity contraction */
  validity: CapabilityCredentialValidity;
};

export type CapabilityCredentialAuthority =
  | "none"
  | {
      /** Invocation-bound destination credential projections */
      projections: CapabilityCredentialProjection[];
    };

export type TrustedCapabilityCredential = {
  /** Secret value retained only in trusted host state */
  value: string;
  /** Safe identity that must match capability policy */
  redactionId: string;
  /** Exact content-aware transport */
  protocol: "http" | "tls";
  /** Exact normalized DNS hostname or IP address */
  destination: string;
  /** Exact destination TCP port */
  port: number;
  /** Uppercase HTTP methods permitted by trusted configuration */
  methods: CapabilityHttpMethod[];
  /** Host-authoritative earliest redemption timestamp */
  notBefore?: string;
  /** Host-authoritative last redemption timestamp */
  expiresAt?: string;
};

type StoredCapabilityCredential = TrustedCapabilityCredential & {
  reference: string;
  revoked: boolean;
  deleted: boolean;
  revision: number;
};

/** Mutable trusted host credential configuration used by capability invocations */
export class CapabilityCredentialStore {
  private readonly entries = new Map<string, StoredCapabilityCredential>();
  private readonly redactionHistory = new Set<string>();

  constructor(credentials: Record<string, TrustedCapabilityCredential> = {}) {
    for (const [reference, credential] of Object.entries(credentials)) {
      this.set(reference, credential);
    }
  }

  /** Create a trusted credential store without placing values in capability policy */
  static create(
    credentials: Record<string, TrustedCapabilityCredential> = {},
  ): CapabilityCredentialStore {
    return new CapabilityCredentialStore(credentials);
  }

  /** Add or rotate one host-side credential */
  set(reference: string, credential: TrustedCapabilityCredential): void {
    const normalizedReference = credentialIdentifier(
      reference,
      "credential reference",
    );
    const normalized = normalizeTrustedCredential(
      credential,
      `trusted credential ${normalizedReference}`,
    );
    if (normalized.value.includes("GONDOLIN_CREDENTIAL_")) {
      invalid(
        "trusted credential value overlaps the reserved placeholder namespace",
      );
    }
    for (const [otherReference, entry] of this.entries) {
      if (
        otherReference !== normalizedReference &&
        !entry.deleted &&
        entry.value === normalized.value
      ) {
        invalid(
          "trusted credential values must be unambiguous across references",
        );
      }
    }
    const previous = this.entries.get(normalizedReference);
    if (previous) this.redactionHistory.add(previous.value);
    this.redactionHistory.add(normalized.value);
    this.entries.set(normalizedReference, {
      ...normalized,
      reference: normalizedReference,
      revoked: false,
      deleted: false,
      revision: (previous?.revision ?? 0) + 1,
    });
  }

  /** Revoke one reference while retaining its values for redaction */
  revoke(reference: string): void {
    const entry = this.require(reference);
    entry.revoked = true;
    entry.revision += 1;
  }

  /** Delete one reference while retaining its values for redaction */
  delete(reference: string): void {
    const entry = this.require(reference);
    entry.deleted = true;
    entry.revoked = true;
    entry.revision += 1;
  }

  /** Safe metadata for trusted-controller inspection */
  inspect(reference: string): {
    redactionId: string;
    revoked: boolean;
    deleted: boolean;
    revision: number;
  } | null {
    const entry = this.entries.get(reference);
    return entry
      ? {
          redactionId: entry.redactionId,
          revoked: entry.revoked,
          deleted: entry.deleted,
          revision: entry.revision,
        }
      : null;
  }

  /** @internal */
  resolve(reference: string): StoredCapabilityCredential | null {
    return this.entries.get(reference) ?? null;
  }

  /** @internal */
  sensitiveValues(): string[] {
    return [...this.redactionHistory].filter(Boolean);
  }

  private require(reference: string): StoredCapabilityCredential {
    const entry = this.entries.get(reference);
    if (!entry) throw new Error(`unknown credential reference: ${reference}`);
    return entry;
  }
}

export const EXACT_WRITER_GUARANTEES = [
  "canonical-request",
  "immutable-ceiling",
  "exact-file-write",
  "atomic-target-replacement",
  "no-ambient-read",
  "no-network",
  "clean-environment",
  "bounded-output",
  "wall-time",
  "disposable-qemu-vm",
  "host-observed-filesystem",
  "completed-teardown",
  ...CAPABILITY_EVIDENCE_GUARANTEES,
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
  /** Maximum destination-bound credential authority */
  credentials?: CapabilityCredentialAuthority;
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
    /** Invocation-bound host credential projections */
    credentials?: CapabilityCredentialAuthority;
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
  /** Trusted host credential configuration */
  credentialStore?: CapabilityCredentialStore;
};

export type CapabilityEffectDecision =
  "requested" | "granted" | "attempted" | "denied" | "observed";

export type CapabilityFilesystemEffect = AuthenticatedEvidenceEvent & {
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

export type CapabilityNetworkEffect = AuthenticatedEvidenceEvent & {
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

export type CapabilityCredentialEffect = AuthenticatedEvidenceEvent & {
  /** Capability domain */
  domain: "credential";
  /** Host-observed credential lifecycle operation */
  operation: "projection" | "use" | "denial" | "expiry" | "revocation";
  /** SHA-256 opaque-reference identity */
  referenceId: string;
  /** Guest-visible projection name */
  projection: string;
  /** Safe configured redaction identity */
  redactionId: string;
  /** Exact content-aware transport */
  protocol: "http" | "tls";
  /** Exact normalized destination */
  destination: string;
  /** Exact destination TCP port */
  port: number;
  /** Uppercase HTTP method when redemption was attempted */
  method?: string;
  /** Non-sensitive denial classification */
  reason?:
    "missing" | "expired" | "revoked" | "mismatch" | "stale" | "inactive";
  /** Relationship of this event to enforcement */
  decision: CapabilityEffectDecision;
};

export type CapabilityEffect =
  | CapabilityFilesystemEffect
  | CapabilityNetworkEffect
  | CapabilityCredentialEffect;

export type CapabilityTeardownEvidence = {
  /** Host execution identity authenticating teardown */
  executionId: string;
  /** Strictly increasing host-authored event sequence */
  sequence: number;
  /** Command transport stopped state */
  commandStopped: boolean;
  /** Disposable VM runner stopped state */
  vmStopped: boolean;
  /** Host VFS handle revocation state */
  vfsHandlesRevoked: boolean;
  /** Invocation policy removal state */
  policyRemoved: boolean;
  /** Invocation network-channel closure state */
  networkChannelsClosed?: boolean;
  /** Invocation credential-projection revocation state */
  credentialProjectionsRevoked?: boolean;
  /** Ephemeral VM-state destruction state */
  ephemeralStateDestroyed: boolean;
  /** Teardown completion timestamp */
  completedAt: string | null;
};

export type CapabilityInvocationOutcome =
  | "success"
  | "policy_denied"
  | "cancelled"
  | "command_failed"
  | "timeout"
  | "output_overflow"
  | "cpu_exhausted"
  | "memory_exhausted"
  | "pids_exhausted"
  | "storage_exhausted"
  | "guest_crash"
  | "host_controller_failure"
  | "transport_failure"
  | "commit_failure"
  | "teardown_failure";

export type CapabilityLifecycleEvent = AuthenticatedEvidenceEvent & {
  /** Host-observed event domain */
  domain: "process" | "lifecycle";
  /** Host-observed lifecycle transition */
  kind: "start" | "policy" | "signal" | "exit" | "teardown";
  /** Non-sensitive host observation */
  detail: string;
  /** Host observation timestamp */
  observedAt: string;
};

export type CapabilityInvocationEvidence = {
  /** Evidence schema identifier */
  schemaVersion: typeof CAPABILITY_EVIDENCE_SCHEMA_VERSION;
  /** Capability request schema identifier */
  capabilitySchemaVersion: typeof CAPABILITY_INVOCATION_SCHEMA_VERSION;
  /** Gondolin package version producing the evidence */
  gondolinVersion: string;
  /** Host admission decision */
  decision: CapabilityEvidenceDecision;
  /** Final post-teardown outcome */
  outcome: CapabilityInvocationOutcome;
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
  /** Exact feature manifest digest used for admission */
  featureManifestDigest: string;
  /** Exact runtime, policy, schema, and package qualification identity */
  qualificationId: string;
  /** Invocation policy implementation versions */
  policyVersions: {
    admission: "exact-reader/v1" | "exact-writer/v1";
    filesystem: "snapshot-vfs/v1" | "exact-writer-vfs/v1";
    process: "exact-mount-landlock/v1";
    network?: "http-tls-mediator/v1";
    credentials?: "destination-bound-credentials/v1";
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
  /** Authenticated host-observed process and lifecycle transitions */
  processEvents: CapabilityLifecycleEvent[];
  /** Invocation start timestamp */
  startedAt: string;
  /** Invocation settlement timestamp */
  settledAt: string;
  /** Resource and lifecycle termination evidence */
  teardown: CapabilityTeardownEvidence;
  /** SHA-256 binding to the public command result */
  resultDigest: string;
  /** Host signature over every preceding evidence field */
  integrity: CapabilityEvidenceIntegrity;
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
  /** Admitted output-bound overflow state */
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
  schemaVersion: typeof CAPABILITY_FEATURE_SCHEMA_VERSION;
  /** Supported request schemas */
  requestSchemas: Record<string, CapabilityFeatureStatus>;
  /** Supported evidence schemas */
  evidenceSchemas: Record<string, CapabilityFeatureStatus>;
  /** Available invocation profiles */
  profiles: Record<string, CapabilityFeatureStatus>;
  /** Available virtualization backends */
  backends: Record<string, CapabilityFeatureStatus>;
  /** Available host platforms */
  hosts: Record<string, CapabilityFeatureStatus>;
  /** Implemented security guarantees */
  guarantees: Record<string, CapabilityFeatureStatus>;
  /** Implemented authority domains */
  domains: Record<string, CapabilityFeatureStatus>;
  /** Implemented policy operations */
  operations: Record<string, CapabilityFeatureStatus>;
  /** Non-wildcard released runtime/conformance combinations */
  qualifications: Record<string, CapabilityFeatureStatus>;
};

const FEATURE_MANIFEST: CapabilityInvocationFeatureManifest = deepFreeze({
  schemaVersion: CAPABILITY_FEATURE_SCHEMA_VERSION,
  requestSchemas: {
    [CAPABILITY_INVOCATION_SCHEMA_VERSION]: "active",
    "future-schema": "unsupported",
  },
  evidenceSchemas: {
    [CAPABILITY_EVIDENCE_SCHEMA_VERSION]: "active",
    "gondolin.capability-evidence/v1": "unsupported",
    "future-schema": "unsupported",
  },
  profiles: {
    "exact-reader": "active",
    "exact-reader.http-tls-credentials": "active",
    "exact-writer": "active",
    "scoped-runner": "active",
    writer: "unsupported",
    runner: "unsupported",
  },
  backends: { qemu: "active", krun: "unverified" },
  hosts: { linux: "unverified", darwin: "unverified", win32: "unsupported" },
  guarantees: {
    ...Object.fromEntries(
      [
        ...EXACT_READER_GUARANTEES,
        ...HTTP_TLS_EGRESS_GUARANTEES,
        ...DESTINATION_BOUND_CREDENTIAL_GUARANTEES,
      ].map((name) => [name, "active"]),
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
    "per-invocation-cpu": "unverified",
    "per-invocation-memory": "unverified",
    "per-invocation-pids": "unverified",
    "per-invocation-storage": "unverified",
    "host-observed-resource-accounting": "unverified",
    "authenticated-execution-identity": "active",
    "concurrent-disjoint-authority": "active",
    "tamper-evident-evidence": "active",
    "independent-evidence-verification": "active",
  },
  domains: {
    filesystem: "active",
    process: "active",
    lifecycle: "active",
    network: "active",
    environment: "unsupported",
    "environment.scoped-runner": "active",
    credentials: "active",
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
    "credentials.http-header.destination-bound": "active",
    "credentials.tls-header.destination-bound": "active",
    "credentials.query": "unsupported",
    "credentials.body": "unsupported",
    "credentials.raw-tcp": "unsupported",
    "credentials.ssh": "unsupported",
    "credentials.broker": "unsupported",
    "environment.empty": "active",
    "environment.projected": "active",
    "process.direct-executable": "active",
    "process.descendant-allow-list": "active",
    "process.descendants-denied": "active",
    "resource.cpu-time": "unverified",
    "resource.memory": "unverified",
    "resource.pids": "unverified",
    "resource.writable-storage": "unverified",
    "resource.output": "unverified",
    "resource.wall-time": "unverified",
    "shell.explicit": "active",
    "evidence.ed25519": "active",
    "evidence.runtime-policy-binding": "active",
    "evidence.resource-usage.guest-reported": "active",
    "evidence.resource-usage.host-observed": "unverified",
  },
  qualifications: {
    "scoped-runner.resources/qemu/linux/released-image-kernel-arch-bundle":
      "unverified",
    "scoped-runner.resources/qemu/darwin/released-image-kernel-arch-bundle":
      "unsupported",
    "scoped-runner.resources/krun/linux/released-image-kernel-arch-bundle":
      "unverified",
    "scoped-runner.resources/krun/darwin/released-image-kernel-arch-bundle":
      "unverified",
    "scoped-runner.resources/qemu/win32/released-image-kernel-arch-bundle":
      "unsupported",
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
const CEILING_OPTIONAL_KEYS = ["network", "credentials"] as const;
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
  private readonly credentialStore: CapabilityCredentialStore | null;
  private readonly sourceIdentities: ReadonlyMap<string, HostFileIdentity>;
  private readonly targetIdentities: Map<string, HostWriterTargetIdentity>;
  private readonly usedInvocationIds = new Set<string>();

  private constructor(
    ceiling: CapabilityCeiling,
    runtime: CapabilityInvocationRuntimeOptions,
  ) {
    this.ceiling = deepFreeze(ceiling);
    this.ceilingDigest = sha256(stableJson(ceiling));
    this.credentialStore = runtime.credentialStore ?? null;
    if (this.credentialStore && ceiling.profile === "exact-reader") {
      assertCredentialMaterialAbsent(
        stableJson(ceiling),
        "capability ceiling",
        this.credentialStore.sensitiveValues(),
      );
    }
    this.runtime = deepFreeze({ ...runtime, credentialStore: undefined });
    this.sourceIdentities = new Map(
      ceiling.profile === "exact-reader"
        ? ceiling.filesystem.sourcePaths.map((sourcePath) => [
            sourcePath,
            getHostFileIdentity(sourcePath, capabilityFilesystemValidation),
          ])
        : [],
    );
    this.targetIdentities = new Map(
      ceiling.profile === "exact-writer"
        ? ceiling.filesystem.targetPaths.map((targetPath) => [
            targetPath,
            getHostWriterTargetIdentity(
              targetPath,
              capabilityFilesystemValidation,
            ),
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
      admitCredentialAuthority(
        request.capabilities.credentials ?? "none",
        (this.ceiling as ExactReaderCeiling).credentials,
        request.capabilities.network,
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
    if (
      request.profile === "exact-reader" &&
      request.capabilities.credentials !== undefined &&
      request.capabilities.credentials !== "none" &&
      !this.credentialStore
    ) {
      throw new CapabilityAdmissionError(
        "unsupported",
        "destination-bound credentials require trusted host configuration",
      );
    }
    if (
      request.profile === "exact-reader" &&
      request.capabilities.credentials !== undefined &&
      request.capabilities.credentials !== "none"
    ) {
      for (const guarantee of DESTINATION_BOUND_CREDENTIAL_GUARANTEES) {
        if (!request.requiredGuarantees.includes(guarantee)) {
          throw new CapabilityAdmissionError(
            "invalid_request",
            `credential projection requires guarantee: ${guarantee}`,
          );
        }
      }
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
    const identity = AuthenticatedExecutionIdentity.begin(
      canonical.digest,
      this.ceilingDigest,
    );
    const executionId = identity.executionId;
    const startedAt = new Date().toISOString();
    const sourcePath = request.capabilities.filesystem.sourcePath;
    const sourceIdentity = this.sourceIdentities.get(sourcePath);
    if (!sourceIdentity) {
      throw new CapabilityAdmissionError(
        "ceiling_widening",
        "filesystem source has no identity in the immutable ceiling",
      );
    }
    const source = readExactHostFile(
      sourcePath,
      sourceIdentity,
      capabilityFilesystemValidation,
    );
    const inputDigest = sha256(source);
    const resourceId = sha256(
      `file:${request.capabilities.filesystem.sourcePath}`,
    );
    const requested = [fileEffect(identity, request, resourceId, "requested")];
    const granted = [fileEffect(identity, request, resourceId, "granted")];
    const attempted: CapabilityEffect[] = [];
    const denied: CapabilityEffect[] = [];
    const observed: CapabilityEffect[] = [];
    const processEvents: CapabilityLifecycleEvent[] = [];
    const networkEnabled = request.capabilities.network !== "none";
    const abort = new AbortController();
    const credentialAuthority = request.capabilities.credentials ?? "none";
    const credentialMediator =
      credentialAuthority === "none"
        ? null
        : createInvocationCredentialMediator({
            executionId,
            identity,
            authority: credentialAuthority,
            store: this.credentialStore!,
            requested,
            granted,
            attempted,
            denied,
            observed,
          });
    const redact = (value: string): string =>
      redactCredentialText(
        value,
        this.credentialStore?.sensitiveValues() ?? [],
      );
    if (credentialMediator) {
      assertCredentialMaterialAbsent(
        canonical.canonical,
        "capability request",
        this.credentialStore!.sensitiveValues(),
      );
      assertCredentialMaterialAbsent(
        source,
        "guest filesystem snapshot",
        this.credentialStore!.sensitiveValues(),
      );
    }
    const output = new BoundedOutput(request.limits.outputBytes, abort, redact);
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
    let commandDispatched = false;

    let timer: NodeJS.Timeout | null = null;

    const hooks = createEvidenceHooks({
      exactPath: relativeGuestPath,
      guestPath: request.capabilities.filesystem.guestPath,
      resourceId,
      networkEnabled,
      identity,
      attempted,
      denied,
      observed,
    });
    const networkAuthority = request.capabilities.network;
    const httpHooks =
      networkAuthority !== "none"
        ? createInvocationHttpHooks({
            authority: networkAuthority,
            identity,
            requested,
            granted,
            attempted,
            denied,
            observed,
            credentialMediator,
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
      identity.bindVm(vmId);
      runtime = vm.getRuntimeIdentity();
      for (const feature of [
        "exec.clear-env/v1",
        "exec.descendants-denied/v1",
        "exec.executable-mount-policy/v1",
        "exec.exact-path-lsm/v1",
        "exec.payload-confinement/v1",
        "exec.landlock-allowlist/v1",
      ]) {
        if (!runtime.guestFeatures.includes(feature)) {
          throw new CapabilityAdmissionError(
            "unsupported",
            `selected guest image does not declare ${feature}`,
          );
        }
      }

      await vm.start();
      runnerPid = vm.getHostPid();
      timer = setTimeout(() => {
        timedOut = true;
        abort.abort();
      }, request.limits.wallTimeMs);
      timer.unref?.();

      processEvents.push(
        lifecycleEvent(
          identity,
          "policy",
          "exact executable mount and inherited Landlock policy attached to exec request",
        ),
      );
      processEvents.push(
        lifecycleEvent(identity, "start", "entrypoint launch dispatched"),
      );
      commandDispatched = true;
      const result = await vm.exec(
        [request.launch.executable, ...request.launch.args],
        {
          clearEnv: true,
          allowedExecutables: [request.launch.executable],
          denyDescendants: true,
          isolateIpc: true,
          isolateDevices: true,
          env: credentialMediator?.environment,
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
      if (result.resourceUsage?.descendantDenied === true) {
        processEvents.push(
          lifecycleEvent(
            identity,
            "policy",
            "guest process policy denied descendant creation",
          ),
        );
      }
      processEvents.push(
        lifecycleEvent(
          identity,
          "exit",
          `entrypoint exited with code ${result.exitCode}`,
        ),
      );
      outcome =
        denied.length > 0 || result.resourceUsage?.descendantDenied === true
          ? "policy_denied"
          : result.exitCode === 0
            ? "success"
            : "command_failed";
    } catch (caught) {
      commandStopped = true;
      if (caught instanceof CapabilityAdmissionError) {
        admissionError = caught;
        outcome = "transport_failure";
      } else if (isMissingCapabilityPolicyError(caught)) {
        admissionError = new CapabilityAdmissionError(
          "unsupported",
          "required guest process, executable, or namespace policy is unavailable",
        );
        outcome = "transport_failure";
      } else if (output.overflowed) outcome = "output_overflow";
      else if (timedOut) outcome = "timeout";
      else if (!commandDispatched) outcome = "host_controller_failure";
      else if (runnerPid !== null && !isProcessAlive(runnerPid)) {
        outcome = "guest_crash";
      } else outcome = "transport_failure";
      error = safeError(caught, redact);
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
      credentialMediator?.deactivate();
    }

    const runnerStopped =
      vm !== null && (runnerPid === null || !isProcessAlive(runnerPid));
    const teardownComplete =
      vm !== null && closeError === null && runnerStopped;
    if (admissionError && teardownComplete) {
      identity.finish("revoked", true);
      throw admissionError;
    }
    if (!teardownComplete) {
      outcome = "teardown_failure";
      error = closeError
        ? safeError(closeError, redact)
        : "VM teardown could not be confirmed";
    }

    const settledAt = new Date().toISOString();
    processEvents.push(
      lifecycleEvent(
        identity,
        "teardown",
        teardownComplete
          ? "disposable VM stopped and invocation authority revoked"
          : "disposable VM teardown could not be confirmed",
      ),
    );
    const teardown: CapabilityTeardownEvidence = {
      ...identity.authenticate(),
      commandStopped,
      vmStopped: teardownComplete,
      vfsHandlesRevoked: teardownComplete,
      policyRemoved: teardownComplete,
      ...(networkEnabled ? { networkChannelsClosed: teardownComplete } : {}),
      ...(credentialMediator
        ? { credentialProjectionsRevoked: !credentialMediator.active }
        : {}),
      ephemeralStateDestroyed: teardownComplete,
      completedAt: teardownComplete ? settledAt : null,
    };

    const resultWithoutEvidence = {
      outcome,
      exitCode,
      stdout: output.stdoutText,
      stderr: output.stderrText,
      outputTruncated: output.overflowed,
      ...(error ? { error } : {}),
    };
    const featureManifestDigest = sha256(stableJson(FEATURE_MANIFEST));
    const policyVersions = {
      admission: "exact-reader/v1" as const,
      filesystem: "snapshot-vfs/v1" as const,
      process: "exact-mount-landlock/v1" as const,
      ...(networkEnabled ? { network: "http-tls-mediator/v1" as const } : {}),
      ...(credentialMediator
        ? { credentials: "destination-bound-credentials/v1" as const }
        : {}),
      lifecycle: "one-shot-qemu/v1" as const,
    };
    const qualificationId = capabilityQualificationId({
      gondolinVersion: gondolinVersion(),
      capabilitySchemaVersion: CAPABILITY_INVOCATION_SCHEMA_VERSION,
      evidenceSchemaVersion: CAPABILITY_EVIDENCE_SCHEMA_VERSION,
      featureManifestDigest,
      runtime,
      policyVersions,
    });
    identity.finish(
      teardownComplete ? "completed" : "revoked",
      teardownComplete,
    );
    const evidence = sealCapabilityEvidence({
      schemaVersion: CAPABILITY_EVIDENCE_SCHEMA_VERSION,
      capabilitySchemaVersion: CAPABILITY_INVOCATION_SCHEMA_VERSION,
      gondolinVersion: gondolinVersion(),
      decision: "admitted" as const,
      outcome,
      requestDigest: canonical.digest,
      ceilingDigest: this.ceilingDigest,
      executionId,
      vmId,
      runtime,
      featureManifestDigest,
      qualificationId,
      policyVersions,
      inputDigest,
      outputDigest: inputDigest,
      requested,
      granted,
      attempted,
      denied,
      observed,
      processEvents,
      startedAt,
      settledAt,
      teardown,
      resultDigest: capabilityResultDigest(resultWithoutEvidence),
    });
    return {
      ...resultWithoutEvidence,
      evidence,
    };
  }

  private async executeWriter(
    canonical: CanonicalCapabilityRequest & {
      request: ExactWriterInvocationRequest;
    },
  ): Promise<CapabilityInvocationResult> {
    const request = canonical.request;
    const identity = AuthenticatedExecutionIdentity.begin(
      canonical.digest,
      this.ceilingDigest,
    );
    const executionId = identity.executionId;
    const startedAt = new Date().toISOString();
    const targetPath = request.capabilities.filesystem.targetPath;
    const targetIdentity = this.targetIdentities.get(targetPath);
    if (!targetIdentity) {
      throw new CapabilityAdmissionError(
        "ceiling_widening",
        "filesystem target has no identity in the immutable ceiling",
      );
    }
    const initial = readExactWriterTarget(
      targetPath,
      targetIdentity,
      capabilityFilesystemValidation,
    );
    const inputDigest = initial === null ? null : sha256(initial);
    const resourceId = sha256(`file:${targetPath}`);
    const requested = request.capabilities.filesystem.operations.map(
      (operation) =>
        writerEffect(identity, request, resourceId, operation, "requested"),
    );
    const granted = request.capabilities.filesystem.operations.map(
      (operation) =>
        writerEffect(identity, request, resourceId, operation, "granted"),
    );
    const attempted: CapabilityEffect[] = [];
    const denied: CapabilityEffect[] = [];
    const observed: CapabilityEffect[] = [];
    const processEvents: CapabilityLifecycleEvent[] = [];
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
    let commandDispatched = false;
    let timer: NodeJS.Timeout | null = null;

    const hooks = createWriterEvidenceHooks({
      exactPath: relativeGuestPath,
      guestPath: request.capabilities.filesystem.guestPath,
      resourceId,
      targetInitiallyExists: initial !== null,
      operations: new Set(request.capabilities.filesystem.operations),
      identity,
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
      identity.bindVm(vmId);
      runtime = vm.getRuntimeIdentity();
      for (const feature of [
        "exec.clear-env/v1",
        "exec.descendants-denied/v1",
        "exec.executable-mount-policy/v1",
        "exec.exact-path-lsm/v1",
        "exec.payload-confinement/v1",
        "exec.landlock-allowlist/v1",
      ]) {
        if (!runtime.guestFeatures.includes(feature)) {
          throw new CapabilityAdmissionError(
            "unsupported",
            `selected guest image does not declare ${feature}`,
          );
        }
      }

      await vm.start();
      runnerPid = vm.getHostPid();
      timer = setTimeout(() => {
        timedOut = true;
        abort.abort();
      }, request.limits.wallTimeMs);
      timer.unref?.();

      processEvents.push(
        lifecycleEvent(
          identity,
          "policy",
          "exact executable mount and inherited Landlock policy attached to exec request",
        ),
      );
      processEvents.push(
        lifecycleEvent(identity, "start", "entrypoint launch dispatched"),
      );
      commandDispatched = true;
      const result = await vm.exec(
        [request.launch.executable, ...request.launch.args],
        {
          clearEnv: true,
          allowedExecutables: [request.launch.executable],
          denyDescendants: true,
          isolateIpc: true,
          isolateDevices: true,
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
      if (result.resourceUsage?.descendantDenied === true) {
        processEvents.push(
          lifecycleEvent(
            identity,
            "policy",
            "guest process policy denied descendant creation",
          ),
        );
      }
      processEvents.push(
        lifecycleEvent(
          identity,
          "exit",
          `entrypoint exited with code ${result.exitCode}`,
        ),
      );
      outcome =
        denied.length > 0 || result.resourceUsage?.descendantDenied === true
          ? "policy_denied"
          : result.exitCode === 0
            ? "success"
            : "command_failed";
    } catch (caught) {
      commandStopped = true;
      if (caught instanceof CapabilityAdmissionError) {
        admissionError = caught;
        outcome = "transport_failure";
      } else if (isMissingCapabilityPolicyError(caught)) {
        admissionError = new CapabilityAdmissionError(
          "unsupported",
          "required guest process, executable, or namespace policy is unavailable",
        );
        outcome = "transport_failure";
      } else if (output.overflowed) outcome = "output_overflow";
      else if (timedOut) outcome = "timeout";
      else if (!commandDispatched) outcome = "host_controller_failure";
      else if (runnerPid !== null && !isProcessAlive(runnerPid)) {
        outcome = "guest_crash";
      } else outcome = "transport_failure";
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
    if (admissionError && teardownComplete) {
      identity.finish("revoked", true);
      throw admissionError;
    }

    if (teardownComplete && hasObservedMutation(observed)) {
      try {
        finalContents = await readProviderFile(provider, relativeGuestPath);
        const publishedIdentity = commitExactWriterTarget(
          targetPath,
          targetIdentity,
          initial,
          finalContents,
          new Set(
            observed
              .map((effect) => effect.operation)
              .filter(isExactWriterOperation),
          ),
          {},
          capabilityFilesystemValidation,
        );
        this.targetIdentities.set(targetPath, publishedIdentity);
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
    processEvents.push(
      lifecycleEvent(
        identity,
        "teardown",
        teardownComplete
          ? "disposable VM stopped and invocation authority revoked"
          : "disposable VM teardown could not be confirmed",
      ),
    );
    const teardown: CapabilityTeardownEvidence = {
      ...identity.authenticate(),
      commandStopped,
      vmStopped: teardownComplete,
      vfsHandlesRevoked: teardownComplete,
      policyRemoved: teardownComplete,
      ephemeralStateDestroyed: teardownComplete,
      completedAt: teardownComplete ? settledAt : null,
    };

    const resultWithoutEvidence = {
      outcome,
      exitCode,
      stdout: output.stdoutText,
      stderr: output.stderrText,
      outputTruncated: output.overflowed,
      ...(error ? { error } : {}),
    };
    const featureManifestDigest = sha256(stableJson(FEATURE_MANIFEST));
    const policyVersions = {
      admission: "exact-writer/v1" as const,
      filesystem: "exact-writer-vfs/v1" as const,
      process: "exact-mount-landlock/v1" as const,
      lifecycle: "one-shot-qemu/v1" as const,
    };
    const qualificationId = capabilityQualificationId({
      gondolinVersion: gondolinVersion(),
      capabilitySchemaVersion: CAPABILITY_INVOCATION_SCHEMA_VERSION,
      evidenceSchemaVersion: CAPABILITY_EVIDENCE_SCHEMA_VERSION,
      featureManifestDigest,
      runtime,
      policyVersions,
    });
    identity.finish(
      teardownComplete ? "completed" : "revoked",
      teardownComplete,
    );
    const evidence = sealCapabilityEvidence({
      schemaVersion: CAPABILITY_EVIDENCE_SCHEMA_VERSION,
      capabilitySchemaVersion: CAPABILITY_INVOCATION_SCHEMA_VERSION,
      gondolinVersion: gondolinVersion(),
      decision: "admitted" as const,
      outcome,
      requestDigest: canonical.digest,
      ceilingDigest: this.ceilingDigest,
      executionId,
      vmId,
      runtime,
      featureManifestDigest,
      qualificationId,
      policyVersions,
      inputDigest,
      outputDigest: finalContents === null ? null : sha256(finalContents),
      requested,
      granted,
      attempted,
      denied,
      observed,
      processEvents,
      startedAt,
      settledAt,
      teardown,
      resultDigest: capabilityResultDigest(resultWithoutEvidence),
    });
    return {
      ...resultWithoutEvidence,
      evidence,
    };
  }
}

function createEvidenceHooks(options: {
  identity: AuthenticatedExecutionIdentity;
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
      const effect: CapabilityFilesystemEffect = authenticatedEffect(
        options.identity,
        {
          domain: "filesystem",
          operation,
          resourceId: isExact
            ? options.resourceId
            : sha256(`guest:${guestPath}`),
          guestPath,
          decision: "attempted",
        },
      );
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
        options.denied.push(
          authenticatedEffect(options.identity, {
            ...withoutAuthentication(effect),
            decision: "denied" as const,
          }),
        );
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
      options.observed.push(
        authenticatedEffect(options.identity, {
          domain: "filesystem",
          operation: classifyOperation(context.op, context.flags),
          resourceId: options.resourceId,
          guestPath: options.guestPath,
          decision: "observed",
        }),
      );
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
  identity: AuthenticatedExecutionIdentity;
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
        const effect: CapabilityEffect = authenticatedEffect(options.identity, {
          domain: "filesystem",
          operation: item.operation,
          resourceId: isExact
            ? options.resourceId
            : sha256(`guest:${guestPath}`),
          guestPath: isExact ? options.guestPath : guestPath,
          decision: "attempted",
        });
        options.attempted.push(effect);
        const allowedLookup =
          item.operation === "lookup" && infrastructureLookup;
        if ((!isExact && !allowedLookup) || !item.permitted) {
          options.denied.push(
            authenticatedEffect(options.identity, {
              ...withoutAuthentication(effect),
              decision: "denied" as const,
            }),
          );
          throw createErrnoError(ERRNO.EACCES, context.op, rawPath);
        }
      }
    },
    after(context: EvidenceHookContext): void {
      const providerPath = normalizeProviderPath(pathFor(context));
      if (providerPath !== options.exactPath) return;
      for (const item of effects(context)) {
        if (!item.permitted || item.operation === "lookup") continue;
        options.observed.push(
          authenticatedEffect(options.identity, {
            domain: "filesystem",
            operation: item.operation,
            resourceId: options.resourceId,
            guestPath: options.guestPath,
            decision: "observed",
          }),
        );
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

function normalizeCredentialAuthority(
  input: unknown,
  label: string,
): CapabilityCredentialAuthority {
  if (input === "none") return "none";
  const root = object(input, label);
  exactKeys(root, ["projections"], label);
  if (!Array.isArray(root.projections)) {
    invalid(`${label}.projections must be an array`);
  }
  if (root.projections.length === 0) {
    invalid(`${label}.projections cannot be empty`);
  }
  const projections = root.projections.map((inputProjection, index) => {
    const projectionLabel = `${label}.projections[${index}]`;
    const projection = object(inputProjection, projectionLabel);
    exactKeys(
      projection,
      [
        "reference",
        "projection",
        "redactionId",
        "protocol",
        "destination",
        "port",
        "methods",
        "validity",
      ],
      projectionLabel,
    );
    if (projection.protocol !== "http" && projection.protocol !== "tls") {
      unsupported(`${projectionLabel}.protocol supports only http or tls`);
    }
    const validity = normalizeCredentialValidity(
      projection.validity,
      `${projectionLabel}.validity`,
    );
    const methods = normalizeCredentialMethods(
      projection.methods,
      `${projectionLabel}.methods`,
    );
    return {
      reference: credentialIdentifier(
        projection.reference,
        `${projectionLabel}.reference`,
      ),
      projection: credentialProjectionName(
        projection.projection,
        `${projectionLabel}.projection`,
      ),
      redactionId: credentialIdentifier(
        projection.redactionId,
        `${projectionLabel}.redactionId`,
      ),
      protocol: projection.protocol,
      destination: normalizeNetworkDestination(
        projection.destination,
        `${projectionLabel}.destination`,
      ),
      port: networkPort(projection.port, `${projectionLabel}.port`),
      methods,
      validity,
    } satisfies CapabilityCredentialProjection;
  });
  const references = new Set<string>();
  const names = new Set<string>();
  for (const projection of projections) {
    if (
      references.has(projection.reference) ||
      names.has(projection.projection)
    ) {
      invalid(
        `${label}.projections contains ambiguous duplicate references or projection names`,
      );
    }
    references.add(projection.reference);
    names.add(projection.projection);
  }
  projections.sort((left, right) =>
    stableJson(left).localeCompare(stableJson(right)),
  );
  return { projections };
}

function normalizeCredentialValidity(
  input: unknown,
  label: string,
): CapabilityCredentialValidity {
  const validity = object(input, label);
  exactKeys(validity, [], label, ["notBefore", "expiresAt"]);
  const notBefore = Object.hasOwn(validity, "notBefore")
    ? isoTimestamp(validity.notBefore, `${label}.notBefore`)
    : undefined;
  const expiresAt = Object.hasOwn(validity, "expiresAt")
    ? isoTimestamp(validity.expiresAt, `${label}.expiresAt`)
    : undefined;
  if (
    notBefore !== undefined &&
    expiresAt !== undefined &&
    Date.parse(notBefore) >= Date.parse(expiresAt)
  ) {
    invalid(`${label} must have notBefore earlier than expiresAt`);
  }
  return {
    ...(notBefore ? { notBefore } : {}),
    ...(expiresAt ? { expiresAt } : {}),
  };
}

function normalizeCredentialMethods(
  input: unknown,
  label: string,
): CapabilityHttpMethod[] {
  const methods = uniqueSorted(
    stringArray(input, label).map((method) => {
      if (!(CAPABILITY_HTTP_METHODS as readonly string[]).includes(method)) {
        unsupported(`${label} contains unsupported method: ${method}`);
      }
      return method as CapabilityHttpMethod;
    }),
  );
  if (methods.length === 0) invalid(`${label} cannot be empty`);
  return methods;
}

function normalizeTrustedCredential(
  input: unknown,
  label: string,
): TrustedCapabilityCredential {
  const credential = object(input, label);
  exactKeys(
    credential,
    ["value", "redactionId", "protocol", "destination", "port", "methods"],
    label,
    ["notBefore", "expiresAt"],
  );
  const value = nonEmptyString(credential.value, `${label}.value`);
  if (credential.protocol !== "http" && credential.protocol !== "tls") {
    throw new Error(`${label}.protocol supports only http or tls`);
  }
  const validity = normalizeCredentialValidity(
    {
      ...(Object.hasOwn(credential, "notBefore")
        ? { notBefore: credential.notBefore }
        : {}),
      ...(Object.hasOwn(credential, "expiresAt")
        ? { expiresAt: credential.expiresAt }
        : {}),
    },
    `${label}.validity`,
  );
  return {
    value,
    redactionId: credentialIdentifier(
      credential.redactionId,
      `${label}.redactionId`,
    ),
    protocol: credential.protocol,
    destination: normalizeNetworkDestination(
      credential.destination,
      `${label}.destination`,
    ),
    port: networkPort(credential.port, `${label}.port`),
    methods: normalizeCredentialMethods(credential.methods, `${label}.methods`),
    ...validity,
  };
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

function admitCredentialAuthority(
  request: CapabilityCredentialAuthority,
  ceiling: CapabilityCredentialAuthority | undefined,
  network: CapabilityNetworkAuthority,
): void {
  if (request === "none") return;
  if (!ceiling || ceiling === "none") {
    throw new CapabilityAdmissionError(
      "ceiling_widening",
      "credential authority is outside the immutable ceiling",
    );
  }
  if (network === "none") {
    throw new CapabilityAdmissionError(
      "invalid_request",
      "credential projection requires an active HTTP/TLS network grant",
    );
  }
  for (const requested of request.projections) {
    const permitted = ceiling.projections.find(
      (candidate) =>
        candidate.reference === requested.reference &&
        candidate.projection === requested.projection &&
        candidate.redactionId === requested.redactionId &&
        credentialOrigin(candidate) === credentialOrigin(requested),
    );
    if (
      !permitted ||
      requested.methods.some((method) => !permitted.methods.includes(method)) ||
      !validityContracts(requested.validity, permitted.validity)
    ) {
      throw new CapabilityAdmissionError(
        "ceiling_widening",
        `credential authority is outside the immutable ceiling: ${requested.redactionId}`,
      );
    }
    const networkRule = network.rules.find(
      (rule) => networkOrigin(rule) === credentialOrigin(requested),
    );
    if (
      !networkRule ||
      requested.methods.some((method) => !networkRule.methods.includes(method))
    ) {
      throw new CapabilityAdmissionError(
        "invalid_request",
        `credential authority is outside the active network grant: ${requested.redactionId}`,
      );
    }
  }
}

function credentialOrigin(
  credential: Pick<
    CapabilityCredentialProjection,
    "protocol" | "destination" | "port"
  >,
): string {
  return `${credential.protocol}://${credential.destination}:${credential.port}`;
}

function validityContracts(
  requested: CapabilityCredentialValidity,
  ceiling: CapabilityCredentialValidity,
): boolean {
  if (
    ceiling.notBefore &&
    (!requested.notBefore ||
      Date.parse(requested.notBefore) < Date.parse(ceiling.notBefore))
  ) {
    return false;
  }
  if (
    ceiling.expiresAt &&
    (!requested.expiresAt ||
      Date.parse(requested.expiresAt) > Date.parse(ceiling.expiresAt))
  ) {
    return false;
  }
  return true;
}

function redirectRank(value: CapabilityNetworkRule["redirects"]): number {
  if (value === "deny") return 0;
  if (value === "same-origin") return 1;
  return 2;
}

function networkOrigin(rule: CapabilityNetworkRule): string {
  return `${rule.protocol}://${rule.destination}:${rule.port}`;
}

type CredentialDenialReason = NonNullable<CapabilityCredentialEffect["reason"]>;

class InvocationCredentialMediator {
  readonly environment: Readonly<Record<string, string>>;
  active = true;
  private readonly authority: Exclude<CapabilityCredentialAuthority, "none">;
  private readonly store: CapabilityCredentialStore;
  private readonly placeholders = new Map<
    string,
    CapabilityCredentialProjection
  >();
  private readonly attempted: CapabilityEffect[];
  private readonly denied: CapabilityEffect[];
  private readonly observed: CapabilityEffect[];
  private readonly identity: AuthenticatedExecutionIdentity;

  constructor(options: {
    executionId: string;
    identity: AuthenticatedExecutionIdentity;
    authority: Exclude<CapabilityCredentialAuthority, "none">;
    store: CapabilityCredentialStore;
    attempted: CapabilityEffect[];
    denied: CapabilityEffect[];
    observed: CapabilityEffect[];
  }) {
    this.authority = options.authority;
    this.identity = options.identity;
    this.store = options.store;
    this.attempted = options.attempted;
    this.denied = options.denied;
    this.observed = options.observed;
    const environment: Record<string, string> = {};
    const executionTag = createHash("sha256")
      .update(options.executionId)
      .digest("hex")
      .slice(0, 16);
    for (const projection of options.authority.projections) {
      const placeholder = `GONDOLIN_CREDENTIAL_${executionTag}_${randomBytes(24).toString("hex")}`;
      environment[projection.projection] = placeholder;
      this.placeholders.set(placeholder, projection);
    }
    this.environment = Object.freeze(environment);
  }

  apply(request: Request): Request {
    const parsed = parseMediatedUrl(request.url);
    const method = request.method.toUpperCase();
    if (!this.active || !parsed) {
      if (this.requestContainsCredentialMaterial(request)) {
        const projection = this.authority.projections[0]!;
        this.reject(
          projection,
          parsed,
          method,
          this.active ? "mismatch" : "inactive",
        );
      }
      return request;
    }

    this.rejectCredentialMaterialInUrl(request.url, parsed, method);
    const headers = new Headers(request.headers);
    for (const [headerName, original] of request.headers.entries()) {
      let value = original;
      const basic = /^(authorization|proxy-authorization)$/i.test(headerName)
        ? decodeBasicCredential(value)
        : null;
      if (basic) {
        const replaced = this.replaceValue(basic.decoded, parsed, method);
        if (replaced !== basic.decoded) {
          value = `${basic.scheme}${basic.space}${Buffer.from(replaced, "utf8").toString("base64")}${basic.trailing}`;
        }
      }
      value = this.replaceValue(value, parsed, method);
      headers.set(headerName, value);
    }
    for (const name of [...request.headers.keys()])
      request.headers.delete(name);
    for (const [name, value] of headers.entries())
      request.headers.set(name, value);
    return request;
  }

  deactivate(): void {
    this.active = false;
    this.placeholders.clear();
  }

  async redactResponse(response: Response): Promise<Response> {
    const headers = new Headers(response.headers);
    for (const [name, value] of headers.entries()) {
      headers.set(
        name,
        redactCredentialText(value, this.store.sensitiveValues()),
      );
    }
    const body = response.body
      ? redactCredentialBuffer(
          Buffer.from(await response.arrayBuffer()),
          this.store.sensitiveValues(),
        )
      : null;
    headers.delete("content-length");
    return new Response(body ? new Uint8Array(body) : null, {
      status: response.status,
      statusText: response.statusText,
      headers,
    });
  }

  private replaceValue(
    value: string,
    destination: CapabilityNetworkRule,
    method: string,
  ): string {
    let updated = value;
    let redeemed = false;
    for (const [placeholder, projection] of this.placeholders) {
      if (!updated.includes(placeholder)) continue;
      const entry = this.resolve(projection, destination, method);
      updated = updated.split(placeholder).join(entry.value);
      redeemed = true;
      this.observed.push(
        credentialEffect(
          this.identity,
          projection,
          "use",
          "observed",
          destination,
          method,
        ),
      );
    }

    if (/GONDOLIN_CREDENTIAL_[A-Za-z0-9_-]+/.test(updated)) {
      const projection = this.authority.projections[0]!;
      this.reject(projection, destination, method, "stale");
    }

    for (const sensitive of this.store.sensitiveValues()) {
      if (!sensitive || !updated.includes(sensitive)) continue;
      const activeProjection = this.authority.projections.find((projection) => {
        const entry = this.store.resolve(projection.reference);
        return entry?.value === sensitive;
      });
      if (!activeProjection) {
        this.reject(
          this.authority.projections[0]!,
          destination,
          method,
          "revoked",
        );
      }
      this.assertScope(activeProjection, destination, method);
      if (!redeemed) {
        this.observed.push(
          credentialEffect(
            this.identity,
            activeProjection,
            "use",
            "observed",
            destination,
            method,
          ),
        );
      }
    }
    return updated;
  }

  private resolve(
    projection: CapabilityCredentialProjection,
    destination: CapabilityNetworkRule,
    method: string,
  ): StoredCapabilityCredential {
    this.attempted.push(
      credentialEffect(
        this.identity,
        projection,
        "use",
        "attempted",
        destination,
        method,
      ),
    );
    if (!this.active) this.reject(projection, destination, method, "inactive");
    this.assertScope(projection, destination, method);
    const entry = this.store.resolve(projection.reference);
    if (!entry || entry.deleted) {
      this.reject(projection, destination, method, "missing");
    }
    if (entry.revoked) {
      this.reject(projection, destination, method, "revoked");
    }
    const now = Date.now();
    if (
      !credentialStoreMatchesProjection(entry, projection) ||
      !isCredentialTimeValid(projection.validity, now)
    ) {
      const reason = !credentialStoreMatchesProjection(entry, projection)
        ? "mismatch"
        : "expired";
      this.reject(projection, destination, method, reason);
    }
    if (!isCredentialTimeValid(entry, now)) {
      this.reject(projection, destination, method, "expired");
    }
    return entry;
  }

  private assertScope(
    projection: CapabilityCredentialProjection,
    destination: CapabilityNetworkRule,
    method: string,
  ): void {
    if (
      projection.protocol !== destination.protocol ||
      projection.destination !== destination.destination ||
      projection.port !== destination.port ||
      !projection.methods.includes(method as CapabilityHttpMethod)
    ) {
      this.reject(projection, destination, method, "mismatch");
    }
  }

  private rejectCredentialMaterialInUrl(
    url: string,
    destination: CapabilityNetworkRule,
    method: string,
  ): void {
    if (
      /GONDOLIN_CREDENTIAL_[A-Za-z0-9_-]+/.test(url) ||
      this.store.sensitiveValues().some((value) => value && url.includes(value))
    ) {
      this.reject(
        this.authority.projections[0]!,
        destination,
        method,
        "mismatch",
      );
    }
  }

  private requestContainsCredentialMaterial(request: Request): boolean {
    const values = [request.url, ...request.headers.values()];
    return values.some(
      (value) =>
        /GONDOLIN_CREDENTIAL_[A-Za-z0-9_-]+/.test(value) ||
        this.store
          .sensitiveValues()
          .some((sensitive) => sensitive && value.includes(sensitive)),
    );
  }

  private reject(
    projection: CapabilityCredentialProjection,
    destination: CapabilityNetworkRule | null,
    method: string,
    reason: CredentialDenialReason,
  ): never {
    const operation =
      reason === "expired"
        ? "expiry"
        : reason === "revoked" || reason === "missing"
          ? "revocation"
          : "denial";
    const effect = credentialEffect(
      this.identity,
      projection,
      operation,
      "denied",
      destination ?? projection,
      method,
      reason,
    );
    this.denied.push(effect);
    throw new HttpRequestBlockedError(
      `credential ${projection.redactionId} denied: ${reason}`,
    );
  }
}

function createInvocationCredentialMediator(options: {
  executionId: string;
  identity: AuthenticatedExecutionIdentity;
  authority: Exclude<CapabilityCredentialAuthority, "none">;
  store: CapabilityCredentialStore;
  requested: CapabilityEffect[];
  granted: CapabilityEffect[];
  attempted: CapabilityEffect[];
  denied: CapabilityEffect[];
  observed: CapabilityEffect[];
}): InvocationCredentialMediator {
  for (const projection of options.authority.projections) {
    options.requested.push(
      credentialEffect(
        options.identity,
        projection,
        "projection",
        "requested",
        projection,
      ),
    );
    options.granted.push(
      credentialEffect(
        options.identity,
        projection,
        "projection",
        "granted",
        projection,
      ),
    );
    options.observed.push(
      credentialEffect(
        options.identity,
        projection,
        "projection",
        "observed",
        projection,
      ),
    );
  }
  return new InvocationCredentialMediator(options);
}

function credentialEffect(
  identity: AuthenticatedExecutionIdentity,
  projection: CapabilityCredentialProjection,
  operation: CapabilityCredentialEffect["operation"],
  decision: CapabilityEffectDecision,
  destination: Pick<CapabilityNetworkRule, "protocol" | "destination" | "port">,
  method?: string,
  reason?: CredentialDenialReason,
): CapabilityCredentialEffect {
  return authenticatedEffect(identity, {
    domain: "credential",
    operation,
    referenceId: sha256(`credential-reference:${projection.reference}`),
    projection: projection.projection,
    redactionId: projection.redactionId,
    protocol: destination.protocol,
    destination: destination.destination,
    port: destination.port,
    ...(method ? { method } : {}),
    ...(reason ? { reason } : {}),
    decision,
  });
}

function decodeBasicCredential(value: string): {
  scheme: string;
  space: string;
  decoded: string;
  trailing: string;
} | null {
  const match = value.match(/^(Basic)(\s+)(\S+)(\s*)$/i);
  if (!match) return null;
  return {
    scheme: match[1]!,
    space: match[2]!,
    decoded: Buffer.from(match[3]!, "base64").toString("utf8"),
    trailing: match[4] ?? "",
  };
}

function createInvocationHttpHooks(options: {
  identity: AuthenticatedExecutionIdentity;
  authority: Exclude<CapabilityNetworkAuthority, "none">;
  requested: CapabilityEffect[];
  granted: CapabilityEffect[];
  attempted: CapabilityEffect[];
  denied: CapabilityEffect[];
  observed: CapabilityEffect[];
  credentialMediator: InvocationCredentialMediator | null;
}): HttpHooks {
  for (const rule of options.authority.rules) {
    for (const method of rule.methods) {
      options.requested.push(
        networkEffect(options.identity, rule, "request", "requested", method),
      );
      options.granted.push(
        networkEffect(options.identity, rule, "request", "granted", method),
      );
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

  const onRequest: NonNullable<HttpHooks["onRequest"]> | undefined =
    options.credentialMediator
      ? (request) => options.credentialMediator!.apply(request)
      : undefined;
  if (onRequest) onRequest[ON_REQUEST_EARLY_POLICY_SAFE] = true;

  return {
    isRequestAllowed(request) {
      const parsed = parseMediatedUrl(request.url);
      const method = request.method.toUpperCase();
      const rule = parsed
        ? findRule(parsed.protocol, parsed.destination, parsed.port, method)
        : undefined;
      const effect = parsed
        ? networkEffect(
            options.identity,
            parsed,
            "request",
            rule ? "attempted" : "denied",
            method,
          )
        : unknownNetworkEffect(options.identity, "request", "denied", method);
      options.attempted.push(
        authenticatedEffect(options.identity, {
          ...withoutAuthentication(effect),
          decision: "attempted" as const,
        }),
      );
      if (!rule) {
        options.denied.push(
          authenticatedEffect(options.identity, {
            ...withoutAuthentication(effect),
            decision: "denied" as const,
          }),
        );
      }
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
      const effect: CapabilityNetworkEffect = authenticatedEffect(
        options.identity,
        {
          domain: "network",
          operation,
          protocol,
          destination,
          port: info.port,
          addressId: sha256(`address:${info.ip}`),
          decision: "attempted",
        },
      );
      options.attempted.push(effect);
      (allowed ? options.observed : options.denied).push(
        authenticatedEffect(options.identity, {
          ...withoutAuthentication(effect),
          decision: allowed ? "observed" : "denied",
        }),
      );
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
            options.identity,
            to,
            "redirect",
            allowed ? "observed" : "denied",
            targetMethod,
          )
        : unknownNetworkEffect(
            options.identity,
            "redirect",
            "denied",
            targetMethod,
          );
      options.attempted.push(
        authenticatedEffect(options.identity, {
          ...withoutAuthentication(effect),
          decision: "attempted" as const,
        }),
      );
      (allowed ? options.observed : options.denied).push(
        authenticatedEffect(options.identity, withoutAuthentication(effect)),
      );
      return allowed;
    },
    async onResponse(response, request) {
      const parsed = parseMediatedUrl(request.url);
      if (parsed) {
        options.observed.push(
          networkEffect(
            options.identity,
            parsed,
            "completion",
            "observed",
            request.method.toUpperCase(),
          ),
        );
      }
      return options.credentialMediator
        ? await options.credentialMediator.redactResponse(response)
        : response;
    },
    ...(onRequest ? { onRequest } : {}),
    onFlowDecision(info) {
      const protocol =
        info.protocol === "http" ||
        info.protocol === "tls" ||
        info.protocol === "ssh" ||
        info.protocol === "tcp"
          ? info.protocol
          : "unknown";
      const effect: CapabilityNetworkEffect = authenticatedEffect(
        options.identity,
        {
          domain: "network",
          operation: "flow",
          protocol,
          destination: sha256(`guest-flow:${info.destination}`),
          port: info.port,
          decision: "attempted",
        },
      );
      options.attempted.push(effect);
      (info.allowed ? options.observed : options.denied).push(
        authenticatedEffect(options.identity, {
          ...withoutAuthentication(effect),
          decision: info.allowed ? "observed" : "denied",
        }),
      );
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
  identity: AuthenticatedExecutionIdentity,
  rule: Pick<CapabilityNetworkRule, "protocol" | "destination" | "port">,
  operation: CapabilityNetworkEffect["operation"],
  decision: CapabilityEffectDecision,
  method?: string,
): CapabilityNetworkEffect {
  return authenticatedEffect(identity, {
    domain: "network",
    operation,
    protocol: rule.protocol,
    destination: rule.destination,
    port: rule.port,
    ...(method ? { method } : {}),
    decision,
  });
}

function unknownNetworkEffect(
  identity: AuthenticatedExecutionIdentity,
  operation: CapabilityNetworkEffect["operation"],
  decision: CapabilityEffectDecision,
  method?: string,
): CapabilityNetworkEffect {
  return authenticatedEffect(identity, {
    domain: "network",
    operation,
    protocol: "unknown",
    destination: "unparseable",
    port: 0,
    ...(method ? { method } : {}),
    decision,
  });
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
          canonicalHostFile(
            value,
            "ceiling.filesystem.sourcePaths",
            capabilityFilesystemValidation,
          ),
        )
      : stringArray(
          filesystem.targetPaths,
          "ceiling.filesystem.targetPaths",
        ).map((value) =>
          canonicalHostTarget(
            value,
            "ceiling.filesystem.targetPaths",
            capabilityFilesystemValidation,
          ),
        );
  const network =
    profile === "exact-reader"
      ? normalizeNetworkAuthority(root.network ?? "none", "ceiling.network")
      : undefined;
  const credentials =
    profile === "exact-reader" && Object.hasOwn(root, "credentials")
      ? normalizeCredentialAuthority(root.credentials, "ceiling.credentials")
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
      ...(credentials !== undefined ? { credentials } : {}),
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
    profile === "exact-reader" ? ["credentials"] : [],
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
  const credentials =
    profile === "exact-reader" && Object.hasOwn(capabilities, "credentials")
      ? normalizeCredentialAuthority(
          capabilities.credentials,
          "request.capabilities.credentials",
        )
      : undefined;

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
            capabilityFilesystemValidation,
          ),
          guestPath,
          operations: ["read"],
        },
        network,
        environment: {},
        ...(credentials !== undefined ? { credentials } : {}),
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
          capabilityFilesystemValidation,
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
      ? [
          ...EXACT_READER_GUARANTEES,
          ...HTTP_TLS_EGRESS_GUARANTEES,
          ...DESTINATION_BOUND_CREDENTIAL_GUARANTEES,
        ]
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

function credentialIdentifier(value: unknown, label: string): string {
  const identifier = nonEmptyString(value, label);
  if (!/^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$/.test(identifier)) {
    invalid(`${label} contains unsupported characters`);
  }
  return identifier;
}

function credentialProjectionName(value: unknown, label: string): string {
  const name = nonEmptyString(value, label);
  if (!/^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(name)) {
    invalid(`${label} must be a valid environment variable name`);
  }
  return name;
}

function isoTimestamp(value: unknown, label: string): string {
  const timestamp = nonEmptyString(value, label);
  const milliseconds = Date.parse(timestamp);
  if (!Number.isFinite(milliseconds)) invalid(`${label} must be ISO 8601`);
  return new Date(milliseconds).toISOString();
}

function credentialStoreMatchesProjection(
  entry: StoredCapabilityCredential,
  projection: CapabilityCredentialProjection,
): boolean {
  return (
    entry.redactionId === projection.redactionId &&
    entry.protocol === projection.protocol &&
    entry.destination === projection.destination &&
    entry.port === projection.port &&
    projection.methods.every((method) => entry.methods.includes(method))
  );
}

function isCredentialTimeValid(
  validity: CapabilityCredentialValidity,
  now: number,
): boolean {
  return (
    (!validity.notBefore || now >= Date.parse(validity.notBefore)) &&
    (!validity.expiresAt || now < Date.parse(validity.expiresAt))
  );
}

function credentialRedactionVariants(value: string): string[] {
  const buffer = Buffer.from(value, "utf8");
  return uniqueSorted(
    [
      value,
      encodeURIComponent(value),
      buffer.toString("base64"),
      buffer.toString("base64url"),
    ].filter(Boolean),
  );
}

function redactCredentialText(
  value: string,
  sensitiveValues: string[],
): string {
  let redacted = value;
  const variants = sensitiveValues
    .flatMap(credentialRedactionVariants)
    .sort((left, right) => right.length - left.length);
  for (const sensitive of variants) {
    redacted = redacted.split(sensitive).join("[REDACTED_CREDENTIAL]");
  }
  return redacted;
}

function redactCredentialBuffer(
  value: Buffer,
  sensitiveValues: string[],
): Buffer {
  const replacement = Buffer.from("[REDACTED_CREDENTIAL]", "utf8");
  const variants = uniqueSorted(
    sensitiveValues.flatMap(credentialRedactionVariants),
  )
    .map((variant) => Buffer.from(variant, "utf8"))
    .sort((left, right) => right.length - left.length);
  let redacted: Buffer = Buffer.from(value);
  for (const sensitive of variants) {
    redacted = replaceBuffer(redacted, sensitive, replacement);
  }
  return redacted;
}

function replaceBuffer(
  value: Buffer,
  search: Buffer,
  replacement: Buffer,
): Buffer {
  if (search.length === 0) return value;
  const chunks: Buffer[] = [];
  let offset = 0;
  while (offset < value.length) {
    const found = value.indexOf(search, offset);
    if (found < 0) break;
    chunks.push(value.subarray(offset, found), replacement);
    offset = found + search.length;
  }
  if (chunks.length === 0) return value;
  chunks.push(value.subarray(offset));
  return Buffer.concat(chunks);
}

function assertCredentialMaterialAbsent(
  value: string | Buffer,
  label: string,
  sensitiveValues: string[],
): void {
  const text = Buffer.isBuffer(value) ? value.toString("utf8") : value;
  if (
    sensitiveValues.some((sensitive) =>
      credentialRedactionVariants(sensitive).some((variant) =>
        text.includes(variant),
      ),
    )
  ) {
    invalid(`${label} contains trusted credential material`);
  }
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
  identity: AuthenticatedExecutionIdentity,
  request: ExactReaderInvocationRequest,
  resourceId: string,
  decision: "requested" | "granted",
): CapabilityEffect {
  return authenticatedEffect(identity, {
    domain: "filesystem",
    operation: "read",
    resourceId,
    guestPath: request.capabilities.filesystem.guestPath,
    decision,
  });
}

function writerEffect(
  identity: AuthenticatedExecutionIdentity,
  request: ExactWriterInvocationRequest,
  resourceId: string,
  operation: ExactWriterOperation,
  decision: "requested" | "granted",
): CapabilityEffect {
  return authenticatedEffect(identity, {
    domain: "filesystem",
    operation,
    resourceId,
    guestPath: request.capabilities.filesystem.guestPath,
    decision,
  });
}

function authenticatedEffect<T extends object>(
  identity: AuthenticatedExecutionIdentity,
  effect: T,
): T & AuthenticatedEvidenceEvent {
  return { ...identity.authenticate(), ...effect };
}

function withoutAuthentication<T extends AuthenticatedEvidenceEvent>(
  effect: T,
): Omit<T, keyof AuthenticatedEvidenceEvent> {
  const { executionId: _executionId, sequence: _sequence, ...rest } = effect;
  return rest;
}

function lifecycleEvent(
  identity: AuthenticatedExecutionIdentity,
  kind: CapabilityLifecycleEvent["kind"],
  detail: string,
): CapabilityLifecycleEvent {
  return {
    ...identity.authenticate(),
    domain:
      kind === "start" || kind === "policy" || kind === "exit"
        ? "process"
        : "lifecycle",
    kind,
    detail,
    observedAt: new Date().toISOString(),
  };
}

function hasObservedMutation(effects: readonly CapabilityEffect[]): boolean {
  return effects.some((effect) => isExactWriterOperation(effect.operation));
}

function safeError(
  error: unknown,
  redact: (value: string) => string = (value) => value,
): string {
  const message = error instanceof Error ? error.message : String(error);
  return redact(message).slice(0, 512);
}

function isMissingCapabilityPolicyError(error: unknown): boolean {
  return /(capability_policy|namespace_isolation|resource_controller)_unavailable/.test(
    error instanceof Error ? error.message : String(error),
  );
}

/** @internal */
export const __test = { redactCredentialBuffer };
