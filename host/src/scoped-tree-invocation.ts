import { performance } from "node:perf_hooks";

import { BoundedOutput } from "./bounded-output.ts";
import {
  CapabilityAdmissionError,
  getCapabilityInvocationFeatureManifest,
  type CapabilityInvocationRuntimeOptions,
} from "./capability-invocation.ts";
import {
  unavailableRuntimeIdentity,
  isProcessAlive,
} from "./capability-runtime.ts";
import { deepFreeze, sha256, stableJson } from "./canonical-json.ts";
import {
  AuthenticatedExecutionIdentity,
  capabilityQualificationId,
  gondolinVersion,
  sealCapabilityEvidence,
  verifySignedInvocationEvidence,
  type CapabilityEvidenceIntegrity,
  type CapabilityEvidenceVerificationOptions,
} from "./invocation-evidence.ts";
import {
  admitScopedTreeRequest,
  canonicalizeScopedTreeInvocationRequest,
  exactObject,
  normalizeScopedTreeCeiling,
  SCOPED_TREE_CEILING_SCHEMA_VERSION,
  SCOPED_TREE_EVIDENCE_SCHEMA_VERSION,
  SCOPED_TREE_GUEST_PATHS,
  SCOPED_TREE_POLICY_VERSIONS,
  SCOPED_TREE_PROFILE,
  SCOPED_TREE_REQUEST_SCHEMA_VERSION,
  type ScopedTreeInvocationCeiling,
  type ScopedTreeInvocationRequest,
  type ScopedTreeLimits,
} from "./scoped-tree-authority.ts";
import {
  acquirePinnedDirectory,
  identitiesEqual,
  pinHostDirectoryIdentity,
  serializeDirectoryIdentity,
  ScopedTreeProvider,
  type HostDirectoryIdentity,
  type ScopedTreeDecision,
} from "./scoped-tree-vfs.ts";
import { VM, type VmRuntimeIdentity } from "./vm/core.ts";

export {
  SCOPED_TREE_CEILING_SCHEMA_VERSION,
  SCOPED_TREE_EVIDENCE_SCHEMA_VERSION,
  SCOPED_TREE_GUEST_PATHS,
  SCOPED_TREE_POLICY_VERSIONS,
  SCOPED_TREE_PROFILE,
  SCOPED_TREE_REQUEST_SCHEMA_VERSION,
  canonicalizeScopedTreeInvocationRequest,
  normalizeScopedTreeCeiling,
};
export type { ScopedTreeInvocationCeiling, ScopedTreeInvocationRequest };

const MEBIBYTE = 1024 * 1024;
const REQUIRED_FEATURES = [
  "exec.clear-env/v1",
  "exec.executable-mount-policy/v1",
  "exec.exact-path-lsm/v1",
  "exec.payload-confinement/v1",
  "exec.landlock-allowlist/v1",
  "exec.namespace-isolation/v1",
  "exec.resource-limits/v1",
  "exec.resource-observation/v2",
  "exec.scoped-tree-vfs/v1",
];

export type ScopedTreeInvocationRuntimeOptions = Omit<
  CapabilityInvocationRuntimeOptions,
  "credentialStore"
>;

export type ScopedTreeInvocationOutcome =
  | "success"
  | "policy_denied"
  | "command_failed"
  | "timeout"
  | "output_overflow"
  | "transport_failure"
  | "host_controller_failure"
  | "cpu_exhausted"
  | "memory_exhausted"
  | "pids_exhausted"
  | "teardown_failure";

export type ScopedTreeResourceUsage = {
  /** Payload-subtree CPU in `ms`, or `null` when unavailable */
  cpuMs: number | null;
  /** Payload cgroup charged peak in `bytes`, or `null` when unavailable */
  peakMemoryBytes: number | null;
  /** Descendants excluding the entrypoint, or `null` when membership is unavailable */
  peakChildren: number | null;
  /** Returned UTF-8 payload size in `bytes` */
  outputBytes: number;
  /** Payload runner interval in `ms` */
  wallMs: number;
  /** Observation completeness for required payload counters */
  observation: "complete" | "unavailable" | "failed";
};

export type ScopedTreeInvocationEvidence = {
  schemaVersion: typeof SCOPED_TREE_EVIDENCE_SCHEMA_VERSION;
  capabilitySchemaVersion: typeof SCOPED_TREE_REQUEST_SCHEMA_VERSION;
  gondolinVersion: string;
  decision: "admitted";
  outcome: ScopedTreeInvocationOutcome;
  requestDigest: string;
  ceilingDigest: string;
  executionId: string;
  vmId: string;
  runtime: VmRuntimeIdentity;
  featureManifestDigest: string;
  qualificationId: string;
  policyVersions: typeof SCOPED_TREE_POLICY_VERSIONS;
  request: ScopedTreeInvocationRequest;
  target: {
    id: string;
    executable: string;
    executableDigest: string;
    args: string[];
  };
  roots: {
    repository: {
      guestPath: string;
      identity: ReturnType<typeof serializeDirectoryIdentity>;
    };
    cache: {
      guestPath: string;
      identity: ReturnType<typeof serializeDirectoryIdentity>;
    };
    temp: {
      guestPath: string;
      identity: ReturnType<typeof serializeDirectoryIdentity>;
    };
  };
  operations: ScopedTreeDecision[];
  resources: {
    limits: ScopedTreeLimits;
    usage: ScopedTreeResourceUsage;
    cgroupPidsCeiling: number;
  };
  environment: "empty";
  network: "none";
  credentials: "none";
  startedAt: string;
  settledAt: string;
  teardown: {
    executionId: string;
    sequence: number;
    commandStopped: boolean;
    vmStopped: boolean;
    vfsHandlesRevoked: boolean;
    policyRemoved: boolean;
    privateStateDisposed: boolean;
    completedAt: string | null;
  };
  resultDigest: string;
  integrity: CapabilityEvidenceIntegrity;
};

export type ScopedTreeInvocationResult = {
  outcome: ScopedTreeInvocationOutcome;
  exitCode: number | null;
  stdout: string;
  stderr: string;
  outputTruncated: boolean;
  resourceAccounting: ScopedTreeResourceUsage;
  evidence: ScopedTreeInvocationEvidence;
  error?: string;
};

/** A fresh VM and pinned live-tree mounts for one registered payload invocation */
export class ScopedTreeInvocationContext {
  #ceiling: ScopedTreeInvocationCeiling;
  #ceilingDigest: string;
  #runtime: Readonly<ScopedTreeInvocationRuntimeOptions>;
  #used = false;
  #repositoryIdentity: HostDirectoryIdentity;

  get ceiling(): ScopedTreeInvocationCeiling {
    return this.#ceiling;
  }
  get ceilingDigest(): string {
    return this.#ceilingDigest;
  }

  private constructor(
    input: unknown,
    runtime: ScopedTreeInvocationRuntimeOptions,
  ) {
    this.#ceiling = normalizeScopedTreeCeiling(input);
    this.#ceilingDigest = sha256(stableJson(this.#ceiling));
    const allowed = [
      "qemuPath",
      "imagePath",
      "accel",
      "cpu",
      "machineType",
      "console",
      "memory",
      "cpus",
      "startTimeoutMs",
    ];
    if (
      !runtime ||
      typeof runtime !== "object" ||
      Array.isArray(runtime) ||
      Object.keys(runtime).some((key) => !allowed.includes(key))
    ) {
      throw new TypeError("unsupported scoped-tree runtime option");
    }
    if (runtime.console !== undefined && runtime.console !== "none") {
      throw new TypeError("scoped-tree console must be disabled");
    }
    if (
      runtime.startTimeoutMs !== undefined &&
      (!Number.isSafeInteger(runtime.startTimeoutMs) ||
        runtime.startTimeoutMs <= 0 ||
        runtime.startTimeoutMs > 2147483647)
    ) {
      throw new TypeError("scoped-tree startup deadline must be finite");
    }
    this.#runtime = deepFreeze(structuredClone(runtime));
    this.#repositoryIdentity = pinHostDirectoryIdentity(
      this.#ceiling.repositoryHostPath,
    ).identity;
    Object.freeze(this);
  }

  static create(
    ceiling: unknown,
    runtime: ScopedTreeInvocationRuntimeOptions = {},
  ): ScopedTreeInvocationContext {
    return new ScopedTreeInvocationContext(ceiling, runtime);
  }

  async execute(input: unknown): Promise<ScopedTreeInvocationResult> {
    const canonical = canonicalizeScopedTreeInvocationRequest(input);
    const admitted = admitScopedTreeRequest(canonical.request, this.#ceiling);
    if (!identitiesEqual(admitted.repository, this.#repositoryIdentity)) {
      throw new TypeError("repository identity changed after ceiling creation");
    }
    if (this.#used) throw new TypeError("scoped-tree context is single use");
    this.#used = true;

    const identity = AuthenticatedExecutionIdentity.begin(
      canonical.digest,
      this.#ceilingDigest,
    );
    const startedAt = new Date().toISOString();
    const startedMonotonic = performance.now();
    const operations: ScopedTreeDecision[] = [];
    const observe = (decision: ScopedTreeDecision) => operations.push(decision);
    const request = admitted.request;
    const target = admitted.target;
    const abort = new AbortController();
    const output = new BoundedOutput(request.limits.outputBytes, abort);

    let repo: ScopedTreeProvider | undefined;
    let cache: ScopedTreeProvider | undefined;
    let temp: ScopedTreeProvider | undefined;
    try {
      repo = new ScopedTreeProvider(
        "repository",
        acquirePinnedDirectory(
          this.#ceiling.repositoryHostPath,
          admitted.repository,
        ),
        observe,
      );
      cache = new ScopedTreeProvider(
        "private",
        acquirePinnedDirectory(
          request.filesystem.cacheHostPath,
          admitted.cache,
        ),
        observe,
      );
      temp = new ScopedTreeProvider(
        "private",
        acquirePinnedDirectory(request.filesystem.tempHostPath, admitted.temp),
        observe,
      );
    } catch (error) {
      repo?.closeRoot();
      cache?.closeRoot();
      temp?.closeRoot();
      throw error;
    }
    if (!repo || !cache || !temp) {
      throw new TypeError("scoped roots could not be acquired");
    }

    let vm: VM | null = null;
    let vmId = "not-created";
    let runtime = unavailableRuntimeIdentity();
    let outcome: ScopedTreeInvocationOutcome = "transport_failure";
    let exitCode: number | null = null;
    let commandStopped = false;
    let closed = false;
    let guestUsage: import("./exec.ts").ExecResourceUsage | undefined;
    let timer: NodeJS.Timeout | null = null;
    let timedOut = false;
    let commandDispatched = false;
    let error: string | undefined;
    let admissionError: CapabilityAdmissionError | undefined;
    const pidsCeiling = request.limits.children + 1;

    try {
      vm = await VM.create({
        autoStart: false,
        startTimeoutMs: this.#runtime.startTimeoutMs,
        memory: vmProvisioningMemory(
          request.limits.memoryBytes,
          this.#runtime.memory,
        ),
        cpus: this.#runtime.cpus,
        rootfs: { mode: "readonly" },
        env: undefined,
        vfs: {
          mounts: {
            [SCOPED_TREE_GUEST_PATHS.repository]: repo,
            [SCOPED_TREE_GUEST_PATHS.cache]: cache,
            [SCOPED_TREE_GUEST_PATHS.temp]: temp,
          },
        },
        sandbox: {
          vmm: "qemu",
          qemuPath: this.#runtime.qemuPath,
          imagePath: this.#runtime.imagePath,
          accel: this.#runtime.accel,
          cpu: this.#runtime.cpu,
          machineType: this.#runtime.machineType,
          console: this.#runtime.console ?? "none",
          autoRestart: false,
          netEnabled: false,
          allowWebSockets: false,
        },
      });
      vmId = vm.id;
      identity.bindVm(vmId);
      runtime = vm.getRuntimeIdentity();
      for (const feature of REQUIRED_FEATURES) {
        if (!runtime.guestFeatures.includes(feature)) {
          throw new CapabilityAdmissionError(
            "unsupported",
            `selected guest image does not declare ${feature}`,
          );
        }
      }
      await vm.start();
      timer = setTimeout(() => {
        timedOut = true;
        abort.abort();
      }, request.limits.wallMs);
      timer.unref?.();
      commandDispatched = true;
      const result = await vm.exec([target.executable, ...target.args], {
        cwd: SCOPED_TREE_GUEST_PATHS.repository,
        clearEnv: true,
        env: undefined,
        allowedExecutables: [target.executable],
        allowedWritablePaths: [],
        allowedWritableTrees: [
          SCOPED_TREE_GUEST_PATHS.cache,
          SCOPED_TREE_GUEST_PATHS.temp,
        ],
        denyDescendants: false,
        denyFork: true,
        isolateIpc: true,
        isolateDevices: true,
        resourceLimits: {
          cpuTimeMs: request.limits.cpuMs,
          memoryBytes: request.limits.memoryBytes,
          pids: pidsCeiling,
        },
        signal: abort.signal,
        stdin: false,
        pty: false,
        stdout: output.stdout,
        stderr: output.stderr,
        windowBytes: Math.min(request.limits.outputBytes + 1, 256 * 1024),
      });
      commandStopped = true;
      exitCode = result.exitCode;
      guestUsage = result.resourceUsage;
      outcome =
        result.resourceUsage?.descendantDenied === true
          ? "policy_denied"
          : result.exitCode === 0
            ? "success"
            : "command_failed";
    } catch (caught) {
      commandStopped = true;
      error = caught instanceof Error ? caught.message : String(caught);
      if (caught instanceof CapabilityAdmissionError) {
        admissionError = caught;
        outcome = "host_controller_failure";
      } else if (
        !commandDispatched &&
        /does not declare|identity|unsupported scoped-tree/.test(error)
      ) {
        outcome = "host_controller_failure";
      } else if (output.overflowed) outcome = "output_overflow";
      else if (timedOut) outcome = "timeout";
      else if (!commandDispatched) outcome = "host_controller_failure";
      else outcome = "transport_failure";
    } finally {
      if (timer) clearTimeout(timer);
      let runnerPid: number | null = null;
      if (vm) {
        runnerPid = vm.getHostPid();
        try {
          await vm.close();
          closed = runnerPid === null || !isProcessAlive(runnerPid);
        } catch {
          closed = false;
        }
      }
      repo.closeRoot();
      cache.closeRoot();
      temp.closeRoot();
    }

    const handlesRevoked =
      repo.handlesClosed() && cache.handlesClosed() && temp.handlesClosed();
    if (admissionError && closed && handlesRevoked) {
      identity.finish("revoked", true);
      throw admissionError;
    }
    const wallMs = Math.max(
      0,
      Math.round(performance.now() - startedMonotonic),
    );
    const usage = payloadUsage(request.limits, guestUsage, output, wallMs);
    if (usage.observation !== "complete" && outcome === "success") {
      outcome = "host_controller_failure";
    }
    if (guestUsage?.exhausted === "cpu") outcome = "cpu_exhausted";
    if (guestUsage?.exhausted === "memory") outcome = "memory_exhausted";
    if (guestUsage?.exhausted === "pids") outcome = "pids_exhausted";
    if (output.overflowed) outcome = "output_overflow";
    if (timedOut && outcome === "success") outcome = "timeout";
    if (!closed || !handlesRevoked) outcome = "teardown_failure";

    const settledAt = new Date().toISOString();
    const result = {
      outcome,
      exitCode,
      stdout: output.stdoutText,
      stderr: output.stderrText,
      outputTruncated: output.overflowed,
      resourceAccounting: usage,
      ...(error ? { error } : {}),
    };
    const featureManifestDigest = sha256(
      stableJson(getCapabilityInvocationFeatureManifest()),
    );
    const qualificationId = capabilityQualificationId({
      gondolinVersion: gondolinVersion(),
      capabilitySchemaVersion: SCOPED_TREE_REQUEST_SCHEMA_VERSION,
      evidenceSchemaVersion: SCOPED_TREE_EVIDENCE_SCHEMA_VERSION,
      featureManifestDigest,
      runtime,
      policyVersions: SCOPED_TREE_POLICY_VERSIONS,
    });
    const teardown = {
      ...identity.authenticate(),
      commandStopped,
      vmStopped: closed,
      vfsHandlesRevoked: handlesRevoked,
      policyRemoved: closed,
      privateStateDisposed: handlesRevoked,
      completedAt: closed && handlesRevoked ? settledAt : null,
    };
    identity.finish(
      closed && handlesRevoked ? "completed" : "revoked",
      closed && handlesRevoked,
    );
    const evidence = sealCapabilityEvidence({
      schemaVersion: SCOPED_TREE_EVIDENCE_SCHEMA_VERSION,
      capabilitySchemaVersion: SCOPED_TREE_REQUEST_SCHEMA_VERSION,
      gondolinVersion: gondolinVersion(),
      decision: "admitted" as const,
      outcome,
      requestDigest: canonical.digest,
      ceilingDigest: this.#ceilingDigest,
      executionId: identity.executionId,
      vmId,
      runtime,
      featureManifestDigest,
      qualificationId,
      policyVersions: SCOPED_TREE_POLICY_VERSIONS,
      request,
      target: {
        id: target.id,
        executable: target.executable,
        executableDigest: target.executableDigest,
        args: target.args,
      },
      roots: {
        repository: {
          guestPath: SCOPED_TREE_GUEST_PATHS.repository,
          identity: serializeDirectoryIdentity(admitted.repository),
        },
        cache: {
          guestPath: SCOPED_TREE_GUEST_PATHS.cache,
          identity: serializeDirectoryIdentity(admitted.cache),
        },
        temp: {
          guestPath: SCOPED_TREE_GUEST_PATHS.temp,
          identity: serializeDirectoryIdentity(admitted.temp),
        },
      },
      operations,
      resources: {
        limits: request.limits,
        usage,
        cgroupPidsCeiling: pidsCeiling,
      },
      environment: "empty" as const,
      network: "none" as const,
      credentials: "none" as const,
      startedAt,
      settledAt,
      teardown,
      resultDigest: sha256(stableJson(result)),
    });
    return deepFreeze({ ...result, evidence });
  }
}

function vmProvisioningMemory(
  payloadBytes: number,
  runtimeMemory?: string,
): string {
  if (runtimeMemory !== undefined) return runtimeMemory;
  const mebibytes = Math.max(128, Math.ceil(payloadBytes / MEBIBYTE));
  return `${mebibytes}M`;
}

function payloadUsage(
  limits: ScopedTreeLimits,
  guest: import("./exec.ts").ExecResourceUsage | undefined,
  output: BoundedOutput,
  wallMs: number,
): ScopedTreeResourceUsage {
  const outputBytes =
    Buffer.byteLength(output.stdoutText) + Buffer.byteLength(output.stderrText);
  if (!guest || guest.observationFailed) {
    return {
      cpuMs: null,
      peakMemoryBytes: null,
      peakChildren: null,
      outputBytes,
      wallMs,
      observation: guest?.observationFailed ? "failed" : "unavailable",
    };
  }
  const cpuMs = guest.cpuTimeMs;
  const peakMemoryBytes = guest.memoryPeakBytes;
  const pidsPeak = guest.pidsPeak;
  const peakChildren = pidsPeak === null || pidsPeak < 1 ? null : pidsPeak - 1;
  const complete =
    cpuMs !== null &&
    peakMemoryBytes !== null &&
    peakChildren !== null &&
    cpuMs <= limits.cpuMs &&
    peakMemoryBytes <= limits.memoryBytes &&
    peakChildren <= limits.children;
  return {
    cpuMs,
    peakMemoryBytes,
    peakChildren,
    outputBytes,
    wallMs,
    observation: complete ? "complete" : "unavailable",
  };
}

export function verifyScopedTreeInvocationResult(
  input: unknown,
  options: CapabilityEvidenceVerificationOptions & {
    requestDigest: string;
    ceilingDigest: string;
    runtime: unknown;
    qualificationId: string;
  },
) {
  try {
    const value = exactObject(input, [
      "outcome",
      "exitCode",
      "stdout",
      "stderr",
      "outputTruncated",
      "resourceAccounting",
      "evidence",
    ]);
    const evidence = value.evidence as ScopedTreeInvocationEvidence;
    const checked = verifySignedInvocationEvidence(evidence, options);
    const errors = [...checked.errors];
    const expect = (valid: boolean, message: string) => {
      if (!valid) errors.push(message);
    };
    expect(
      evidence.schemaVersion === SCOPED_TREE_EVIDENCE_SCHEMA_VERSION &&
        evidence.capabilitySchemaVersion === SCOPED_TREE_REQUEST_SCHEMA_VERSION,
      "unsupported scoped-tree evidence schema",
    );
    expect(
      evidence.environment === "empty",
      "scoped-tree environment must be empty",
    );
    expect(evidence.network === "none", "scoped-tree network must be denied");
    expect(
      evidence.credentials === "none",
      "scoped-tree credentials must be denied",
    );
    expect(
      evidence.resources.cgroupPidsCeiling ===
        evidence.resources.limits.children + 1,
      "cgroup membership ceiling must be children + 1",
    );
    expect(
      evidence.policyVersions.cpuRoundingAllowanceMs === 5,
      "CPU rounding allowance must remain 5 ms",
    );
    if (evidence.outcome === "success") {
      expect(
        evidence.resources.usage.observation === "complete",
        "success requires complete payload observations",
      );
    }
    return { ...checked, valid: errors.length === 0, errors };
  } catch {
    return {
      valid: false,
      errors: ["malformed scoped-tree result"],
      payloadDigest: null,
      qualificationId: null,
    };
  }
}

export const __test = {
  payloadUsage,
  vmProvisioningMemory,
  REQUIRED_FEATURES,
};
