import fs from "node:fs";
import path from "node:path";
import { performance } from "node:perf_hooks";

import {
  CAPABILITY_CEILING_SCHEMA_VERSION,
  CAPABILITY_EVIDENCE_GUARANTEES,
  CAPABILITY_EVIDENCE_SCHEMA_VERSION,
  CAPABILITY_INVOCATION_SCHEMA_VERSION,
  CapabilityAdmissionError,
  getCapabilityInvocationFeatureManifest,
  type CapabilityInvocationOutcome,
  type CapabilityInvocationRuntimeOptions,
  type CapabilityTeardownEvidence,
} from "./capability-invocation.ts";
import { VM, type VmRuntimeIdentity } from "./vm/core.ts";
import type { ExecResourceUsage } from "./exec.ts";
import { BoundedOutput } from "./bounded-output.ts";
import {
  AuthenticatedExecutionIdentity,
  capabilityQualificationId,
  capabilityResultDigest,
  gondolinVersion,
  sealCapabilityEvidence,
  type AuthenticatedEvidenceEvent,
  type CapabilityEvidenceIntegrity,
} from "./invocation-evidence.ts";
import { deepFreeze, sha256, stableJson } from "./canonical-json.ts";
import {
  isProcessAlive,
  unavailableRuntimeIdentity,
  uniqueSorted,
} from "./capability-runtime.ts";
import {
  formatDirectoryIdentity,
  linuxAtAvailable,
  parseDirectoryIdentity,
  pinDirectory,
  type DirectoryIdentity,
} from "./linux-at.ts";
import {
  ScopedTreeProvider,
  capabilityPath,
  type ScopedTreeDecision,
  type ScopedTreeRole,
  type ScopedTreeRootBinding,
} from "./vfs/scoped-tree.ts";

/** Native wait4/cgroup CPU allowance in `us` */
export const SCOPED_TREE_CPU_WAIT4_ALLOWANCE_USEC = 5000;
/** Guest observer polling period in `ms` */
export const SCOPED_TREE_OBSERVER_INTERVAL_MS = 10;

export const SCOPED_TREE_RUNNER_GUARANTEES = [
  "canonical-request",
  "immutable-ceiling",
  "root-bound-repository-read",
  "private-write-roots",
  "no-network",
  "clean-environment",
  "direct-executable",
  "no-fork",
  "bounded-output",
  "wall-time",
  "payload-cpu",
  "payload-memory",
  "payload-children",
  "disposable-qemu-vm",
  "completed-teardown",
  ...CAPABILITY_EVIDENCE_GUARANTEES,
] as const;

export type ScopedTreeRunnerGuarantee =
  (typeof SCOPED_TREE_RUNNER_GUARANTEES)[number];

export type ScopedTreeRootSpec = {
  /** Absolute host directory for this root */
  hostPath: string;
  /** Absolute guest directory under `/data` */
  guestPath: string;
  /** Controller-retained `dev:ino:birthtimeNs` identity */
  identity: string;
};

export type ScopedTreeRunnerCeiling = {
  /** Capability ceiling schema identifier */
  schemaVersion: typeof CAPABILITY_CEILING_SCHEMA_VERSION;
  /** Scoped tree profile identifier */
  profile: "scoped-tree-runner";
  /** Absolute guest entrypoints permitted by the ceiling */
  allowedExecutables: string[];
  /** Absolute guest working directories permitted by the ceiling */
  allowedWorkingDirectories: string[];
  /** Filesystem authority ceiling */
  filesystem: {
    /** Host repository directories available as live read roots */
    repositoryHostPaths: string[];
    /** Guest repository directories available as live read roots */
    repositoryGuestPaths: string[];
    /** Guest cache directories available as private write roots */
    cacheGuestPaths: string[];
    /** Guest temporary directories available as private write roots */
    tempGuestPaths: string[];
  };
  /** Resource limit ceiling */
  limits: {
    /** Maximum payload-subtree CPU time in `ms` */
    maxCpuMs: number;
    /** Maximum payload cgroup memory in `bytes` */
    maxMemoryBytes: number;
    /** Maximum descendants excluding the entrypoint */
    maxChildren: number;
    /** Maximum combined stdout and stderr in `bytes` */
    maxOutputBytes: number;
    /** Maximum payload runner wall time in `ms` */
    maxWallMs: number;
  };
  /** Guarantees the ceiling permits callers to require */
  guarantees: ScopedTreeRunnerGuarantee[];
};

export type ScopedTreeRunnerInvocationRequest = {
  /** Capability invocation schema identifier */
  schemaVersion: typeof CAPABILITY_INVOCATION_SCHEMA_VERSION;
  /** Caller-selected replay identity */
  invocationId: string;
  /** Scoped tree profile identifier */
  profile: "scoped-tree-runner";
  /** Entrypoint launch description */
  launch: {
    /** Directly invoked absolute executable path */
    executable: string;
    /** Literal argument vector excluding the executable */
    args: string[];
    /** Absolute guest working directory */
    cwd: string;
  };
  /** Complete invocation authority */
  capabilities: {
    /** Live root-bound filesystem authority */
    filesystem: {
      /** Live repository read root */
      repository: ScopedTreeRootSpec;
      /** Fresh private cache write root */
      cache: ScopedTreeRootSpec;
      /** Fresh private temporary write root */
      temp: ScopedTreeRootSpec;
    };
    /** Empty environment, no network, credentials, Git, IPC, or devices */
    network: "none";
    credentials: "none";
    git: "none";
    ipc: "none";
    devices: "none";
  };
  /** Effective `ScopedTestLimits` */
  limits: {
    /** Payload-subtree CPU ceiling in `ms` */
    cpuMs: number;
    /** Payload cgroup memory ceiling in `bytes` */
    memoryBytes: number;
    /** Maximum descendants excluding the entrypoint */
    children: number;
    /** Returned UTF-8 payload byte ceiling */
    outputBytes: number;
    /** Payload runner interval ceiling in `ms` */
    wallMs: number;
  };
  /** Guarantees the caller requires */
  requiredGuarantees: ScopedTreeRunnerGuarantee[];
};

export type ScopedTreeRunnerInvokeOptions = {
  signal?: AbortSignal;
};

export type ScopedTreeRunnerFilesystemEffect = AuthenticatedEvidenceEvent & {
  domain: "filesystem";
  operation: ScopedTreeDecision["operation"];
  resourceId: string;
  guestPath: string;
  decision: "requested" | "granted" | "attempted" | "denied" | "observed";
  capabilityPath?: string;
};

export type ScopedTreeRunnerProcessEvent = AuthenticatedEvidenceEvent & {
  domain: "process" | "lifecycle";
  kind: "start" | "policy" | "denial" | "signal" | "exit" | "teardown";
  executableId?: string;
  detail: string;
  observedAt: string;
};

export type ScopedTreeRunnerResourceAccounting = AuthenticatedEvidenceEvent & {
  limits: ScopedTreeRunnerInvocationRequest["limits"];
  usage: {
    /** Payload cgroup CPU in `ms`, or `null` when unavailable */
    cpuMs: number | null;
    /** Independent wait4 CPU in `ms`, or `null` when unavailable */
    wait4CpuMs: number | null;
    /** Payload cgroup CPU in `us`, or `null` when unavailable */
    cgroupCpuUsec: number | null;
    /** Payload cgroup peak memory in `bytes`, or `null` when unavailable */
    memoryBytes: number | null;
    /** Peak descendants excluding the entrypoint, or `null` when unavailable */
    children: number | null;
    /** Host-observed combined stdout and stderr in `bytes` */
    outputBytes: number;
    /** Payload runner interval in `ms` */
    wallMs: number;
    /** VM/image setup interval in `ms` */
    setupMs: number;
    /** Teardown interval in `ms` */
    teardownMs: number;
  };
  exhausted: "cpu" | "memory" | "children" | "output" | "wall-time" | null;
  exhaustionObservation: "guest-reported" | "host-observed" | null;
  observations: {
    cpu: "payload-cgroup-wait4" | "unavailable";
    memory: "guest-reported-cgroup-v2" | "unavailable";
    children: "guest-reported-cgroup-v2" | "unavailable";
    output: "host-exec-channel";
    wallTime: "host-monotonic-clock";
  };
  guestResourceGroupRemoved: boolean;
  guestObservationFailed: boolean;
};

export type ScopedTreeRunnerInvocationEvidence = {
  schemaVersion: typeof CAPABILITY_EVIDENCE_SCHEMA_VERSION;
  publication: null;
  capabilitySchemaVersion: typeof CAPABILITY_INVOCATION_SCHEMA_VERSION;
  gondolinVersion: string;
  decision: "admitted";
  outcome: ScopedTreeRunnerInvocationResult["outcome"];
  requestDigest: string;
  ceilingDigest: string;
  executionId: string;
  vmId: string;
  runtime: VmRuntimeIdentity;
  featureManifestDigest: string;
  qualificationId: string;
  policyVersions: {
    admission: "scoped-tree-runner/v1";
    filesystem: "root-bound-openat2/v1";
    process: "no-fork-landlock/v1";
    resources: "payload-cgroup-wait4/v1";
    lifecycle: "one-shot-qemu/v1";
  };
  roots: Record<ScopedTreeRole, string>;
  observer: {
    provenance: "sandboxd-cgroup-wait4";
    collectionIntervalMs: number;
    cpuWait4AllowanceUsec: number;
  };
  requested: ScopedTreeRunnerFilesystemEffect[];
  granted: ScopedTreeRunnerFilesystemEffect[];
  attempted: ScopedTreeRunnerFilesystemEffect[];
  denied: ScopedTreeRunnerFilesystemEffect[];
  observed: ScopedTreeRunnerFilesystemEffect[];
  processEvents: ScopedTreeRunnerProcessEvent[];
  resources: ScopedTreeRunnerResourceAccounting;
  startedAt: string;
  settledAt: string;
  teardown: CapabilityTeardownEvidence & {
    processTreeEmpty: boolean;
    transportClosed: boolean;
    privateRootsDestroyed: boolean;
    resourceControllersRemoved: boolean;
  };
  resultDigest: string;
  integrity: CapabilityEvidenceIntegrity;
};

export type ScopedTreeRunnerInvocationResult = {
  outcome:
    | CapabilityInvocationOutcome
    | "policy_denied"
    | "cancelled"
    | "guest_crash"
    | "cpu_exhausted"
    | "memory_exhausted"
    | "children_exhausted";
  exitCode: number | null;
  stdout: string;
  stderr: string;
  outputTruncated: boolean;
  resourceAccounting: ScopedTreeRunnerResourceAccounting;
  evidence: ScopedTreeRunnerInvocationEvidence;
  error?: string;
};

export type CanonicalScopedTreeRunnerRequest = {
  request: ScopedTreeRunnerInvocationRequest;
  canonical: string;
  digest: string;
};

const CEILING_KEYS = [
  "schemaVersion",
  "profile",
  "allowedExecutables",
  "allowedWorkingDirectories",
  "filesystem",
  "limits",
  "guarantees",
] as const;

const REQUEST_KEYS = [
  "schemaVersion",
  "invocationId",
  "profile",
  "launch",
  "capabilities",
  "limits",
  "requiredGuarantees",
] as const;

/** Normalize, canonically serialize, and digest one scoped-tree-runner request */
export function canonicalizeScopedTreeRunnerInvocationRequest(
  input: unknown,
): CanonicalScopedTreeRunnerRequest {
  const request = normalizeRequest(input);
  const canonical = stableJson(request);
  return { request, canonical, digest: sha256(canonical) };
}

/** One-shot scoped-tree-runner context with immutable maximum authority */
export class ScopedTreeRunnerInvocationContext {
  readonly ceiling: Readonly<ScopedTreeRunnerCeiling>;
  readonly ceilingDigest: string;
  private readonly runtime: Readonly<CapabilityInvocationRuntimeOptions>;
  private readonly usedInvocationIds = new Set<string>();

  private constructor(
    ceiling: ScopedTreeRunnerCeiling,
    runtime: CapabilityInvocationRuntimeOptions,
  ) {
    this.ceiling = deepFreeze(ceiling);
    this.ceilingDigest = sha256(stableJson(ceiling));
    this.runtime = deepFreeze({ ...runtime });
  }

  static create(
    ceiling: unknown,
    runtime: CapabilityInvocationRuntimeOptions = {},
  ): ScopedTreeRunnerInvocationContext {
    return new ScopedTreeRunnerInvocationContext(
      normalizeCeiling(ceiling),
      runtime,
    );
  }

  async invoke(
    input: unknown,
    options: ScopedTreeRunnerInvokeOptions = {},
  ): Promise<ScopedTreeRunnerInvocationResult> {
    const canonical = canonicalizeScopedTreeRunnerInvocationRequest(input);
    this.admit(canonical.request);
    if (this.usedInvocationIds.has(canonical.request.invocationId)) {
      throw new CapabilityAdmissionError(
        "duplicate_invocation",
        `invocation identity has already been used: ${canonical.request.invocationId}`,
      );
    }
    this.usedInvocationIds.add(canonical.request.invocationId);
    return await this.execute(canonical, options);
  }

  private admit(request: ScopedTreeRunnerInvocationRequest): void {
    if (!this.ceiling.allowedExecutables.includes(request.launch.executable)) {
      widening("launch executable is outside the immutable ceiling");
    }
    if (!this.ceiling.allowedWorkingDirectories.includes(request.launch.cwd)) {
      widening("working directory is outside the immutable ceiling");
    }
    const fs = request.capabilities.filesystem;
    if (
      !this.ceiling.filesystem.repositoryHostPaths.includes(fs.repository.hostPath) ||
      !this.ceiling.filesystem.repositoryGuestPaths.includes(fs.repository.guestPath)
    ) {
      widening("repository root is outside the immutable ceiling");
    }
    if (!this.ceiling.filesystem.cacheGuestPaths.includes(fs.cache.guestPath)) {
      widening("cache root is outside the immutable ceiling");
    }
    if (!this.ceiling.filesystem.tempGuestPaths.includes(fs.temp.guestPath)) {
      widening("temp root is outside the immutable ceiling");
    }
    if (
      request.limits.cpuMs > this.ceiling.limits.maxCpuMs ||
      request.limits.memoryBytes > this.ceiling.limits.maxMemoryBytes ||
      request.limits.children > this.ceiling.limits.maxChildren ||
      request.limits.outputBytes > this.ceiling.limits.maxOutputBytes ||
      request.limits.wallMs > this.ceiling.limits.maxWallMs
    ) {
      widening("invocation resource limits exceed the immutable ceiling");
    }
    for (const guarantee of request.requiredGuarantees) {
      if (!this.ceiling.guarantees.includes(guarantee)) {
        widening(
          `required guarantee is excluded by the immutable ceiling: ${guarantee}`,
        );
      }
    }
  }

  private async execute(
    canonical: CanonicalScopedTreeRunnerRequest,
    options: ScopedTreeRunnerInvokeOptions,
  ): Promise<ScopedTreeRunnerInvocationResult> {
    const request = canonical.request;
    const identity = AuthenticatedExecutionIdentity.begin(
      canonical.digest,
      this.ceilingDigest,
    );
    const executionId = identity.executionId;
    const startedAt = new Date().toISOString();
    const startedMonotonic = performance.now();
    const attempted: ScopedTreeRunnerFilesystemEffect[] = [];
    const denied: ScopedTreeRunnerFilesystemEffect[] = [];
    const observed: ScopedTreeRunnerFilesystemEffect[] = [];
    const requested = declaredEffects(identity, request, "requested");
    const granted = declaredEffects(identity, request, "granted");
    const processEvents: ScopedTreeRunnerProcessEvent[] = [];
    const abort = new AbortController();
    const output = new BoundedOutput(request.limits.outputBytes, abort);
    let cancelled = options.signal?.aborted ?? false;
    let timedOut = false;
    const onCancel = () => {
      cancelled = true;
      abort.abort();
    };
    options.signal?.addEventListener("abort", onCancel, { once: true });
    if (cancelled) abort.abort();

    let vm: VM | null = null;
    let vmId = "not-created";
    let runtime = unavailableRuntimeIdentity();
    let outcome: ScopedTreeRunnerInvocationResult["outcome"] = "transport_failure";
    let exitCode: number | null = null;
    let error: string | undefined;
    let commandStopped = false;
    let closeError: Error | null = null;
    let runnerPid: number | null = null;
    let runnerAliveAtFailure = true;
    let admissionError: CapabilityAdmissionError | null = null;
    let timer: NodeJS.Timeout | null = null;
    let guestUsage: ExecResourceUsage | undefined;
    let commandDispatched = false;
    let provider: ScopedTreeProvider | null = null;
    let treeDispose: { handlesRevoked: boolean; rootsClosed: boolean } | null =
      null;
    let privateRootsDestroyed = false;
    let setupMs = 0;
    let payloadMs = 0;
    let teardownMs = 0;
    const setupStarted = performance.now();

    try {
      if (!linuxAtAvailable()) {
        throw new CapabilityAdmissionError(
          "unsupported",
          `${capabilityPath("repository", "resolution")}: host platform cannot perform openat2 root-bound resolution`,
        );
      }
      provider = bindScopedTreeProvider(request, (decision) => {
        const effect: ScopedTreeRunnerFilesystemEffect = {
          ...identity.authenticate(vmId === "not-created" ? undefined : vmId),
          domain: "filesystem",
          operation: decision.operation,
          resourceId: sha256(`tree:${decision.guestPath}`),
          guestPath: decision.guestPath,
          decision: decision.decision === "granted" ? "attempted" : "denied",
          ...(decision.capabilityPath
            ? { capabilityPath: decision.capabilityPath }
            : {}),
        };
        if (decision.decision === "denied") {
          denied.push({ ...effect, decision: "denied" });
          processEvents.push({
            ...identity.authenticate(vmId === "not-created" ? undefined : vmId),
            domain: "process",
            kind: "denial",
            detail: `host policy denied ${decision.operation} on ${decision.guestPath} at ${decision.capabilityPath}`,
            observedAt: new Date().toISOString(),
          });
        } else {
          attempted.push(effect);
          observed.push({ ...effect, decision: "observed" });
        }
      });
      provider.verifyPinnedIdentities();

      vm = await VM.create({
        autoStart: false,
        startTimeoutMs: this.runtime.startTimeoutMs,
        memory: this.runtime.memory ?? "512M",
        cpus: this.runtime.cpus,
        rootfs: { mode: "readonly" },
        env: {
          GONDOLIN_SCOPED_TREE_CHALLENGE: "seeded-credential",
        },
        vfs: { mounts: { "/": provider } },
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
        "exec.namespace-isolation/v1",
        "exec.resource-limits/v1",
        "exec.resource-observation/v2",
        "exec.scoped-tree-runner/v1",
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
      setupMs = Math.max(0, Math.ceil(performance.now() - setupStarted));
      timer = setTimeout(() => {
        timedOut = true;
        processEvents.push(
          lifecycleEvent(
            identity,
            "signal",
            "wall-time expiry requested VM teardown",
          ),
        );
        abort.abort();
      }, request.limits.wallMs);
      timer.unref?.();

      const executableId = sha256(`executable:${request.launch.executable}`);
      processEvents.push({
        ...identity.authenticate(vmId),
        domain: "process",
        kind: "policy",
        executableId,
        detail:
          "root-bound Landlock trees, no-fork seccomp, and empty environment installed before start-gate release",
        observedAt: new Date().toISOString(),
      });
      processEvents.push({
        ...identity.authenticate(vmId),
        domain: "process",
        kind: "start",
        executableId,
        detail: `payload entrypoint dispatched under pinned roots ${formatDirectoryIdentity(
          parseDirectoryIdentity(
            request.capabilities.filesystem.repository.identity,
            "repository",
          ),
        )}`,
        observedAt: new Date().toISOString(),
      });

      commandDispatched = true;
      const payloadStarted = performance.now();
      const result = await vm.exec(
        [request.launch.executable, ...request.launch.args],
        {
          cwd: request.launch.cwd,
          env: [],
          clearEnv: true,
          allowedExecutables: [request.launch.executable],
          denyDescendants: true,
          denyFork: true,
          isolateIpc: true,
          isolateDevices: true,
          isolateProc: false,
          allowedReadableDirectories: [
            request.capabilities.filesystem.repository.guestPath,
          ],
          allowedWritableDirectories: [
            request.capabilities.filesystem.cache.guestPath,
            request.capabilities.filesystem.temp.guestPath,
          ],
          resourceLimits: {
            cpuTimeMs: request.limits.cpuMs,
            memoryBytes: request.limits.memoryBytes,
            pids: request.limits.children + 1,
          },
          signal: abort.signal,
          stdin: false,
          pty: false,
          stdout: output.stdout,
          stderr: output.stderr,
          windowBytes: Math.min(request.limits.outputBytes + 1, 256 * 1024),
        },
      );
      payloadMs = Math.max(0, Math.ceil(performance.now() - payloadStarted));
      commandStopped = true;
      exitCode = result.exitCode;
      guestUsage = validPayloadResourceUsage(result.resourceUsage)
        ? result.resourceUsage
        : undefined;
      if (result.signal !== undefined) {
        processEvents.push({
          ...identity.authenticate(vmId),
          domain: "process",
          kind: "signal",
          detail: `guest wait status observed signal ${result.signal}`,
          observedAt: new Date().toISOString(),
        });
      }
      processEvents.push({
        ...identity.authenticate(vmId),
        domain: "process",
        kind: "exit",
        executableId,
        detail: `entrypoint exited with code ${result.exitCode}${result.signal === undefined ? "" : ` and signal ${result.signal}`}`,
        observedAt: new Date().toISOString(),
      });
      outcome =
        denied.length > 0
          ? "policy_denied"
          : (resourceOutcome(guestUsage?.exhausted) ??
            (output.overflowed
              ? "output_overflow"
              : result.exitCode === 0
                ? "success"
                : "command_failed"));
    } catch (caught) {
      commandStopped = true;
      setupMs = Math.max(0, Math.ceil(performance.now() - setupStarted));
      runnerAliveAtFailure = runnerPid === null || isProcessAlive(runnerPid);
      if (caught instanceof CapabilityAdmissionError) {
        admissionError = caught;
        error = safeError(caught);
      } else if (isMissingExecutionIsolationError(caught)) {
        admissionError = new CapabilityAdmissionError(
          "unsupported",
          "required guest resource controllers or namespaces are unavailable or degraded",
        );
        error = safeError(admissionError);
      } else if (output.overflowed) {
        outcome = "output_overflow";
      } else if (cancelled) {
        outcome = "cancelled";
        processEvents.push(
          lifecycleEvent(
            identity,
            "signal",
            "caller cancellation requested VM teardown",
          ),
        );
      } else if (timedOut) {
        outcome = "timeout";
      } else if (!runnerAliveAtFailure) {
        outcome = "guest_crash";
      } else if (!commandDispatched) {
        outcome = "host_controller_failure";
      } else {
        outcome = "transport_failure";
      }
      error ??= safeError(caught);
    } finally {
      const teardownStarted = performance.now();
      if (timer) clearTimeout(timer);
      options.signal?.removeEventListener("abort", onCancel);
      if (provider) {
        treeDispose = provider.dispose();
      }
      privateRootsDestroyed = destroyPrivateRoots(request);
      if (vm) {
        runnerPid ??= vm.getHostPid();
        try {
          await vm.close();
        } catch (caught) {
          closeError =
            caught instanceof Error ? caught : new Error(String(caught));
        }
      }
      teardownMs = Math.max(0, Math.ceil(performance.now() - teardownStarted));
    }

    const runnerStopped =
      vm !== null && (runnerPid === null || !isProcessAlive(runnerPid));
    const handlesRevoked = treeDispose?.handlesRevoked === true;
    const rootsClosed = treeDispose?.rootsClosed === true;
    const vmStopped = vm !== null && closeError === null && runnerStopped;
    const teardownComplete =
      vmStopped && handlesRevoked && rootsClosed && privateRootsDestroyed;
    if (admissionError && teardownComplete) {
      identity.finish("revoked", true);
      throw admissionError;
    }

    const payloadCpuValid =
      guestUsage !== undefined &&
      guestUsage.observationFailed === false &&
      cpuAgreesWithWait4(guestUsage.cgroupCpuUsec, guestUsage.wait4CpuMs) &&
      guestUsage.cpuTimeMs !== null;
    const childrenValue = peakChildren(guestUsage?.pidsPeak ?? null);
    const memoryValid =
      guestUsage?.memoryPeakBytes != null &&
      Number.isSafeInteger(guestUsage.memoryPeakBytes);
    if (
      commandDispatched &&
      (!payloadCpuValid || childrenValue === null || !memoryValid)
    ) {
      const observationError =
        "payload resource accounting unavailable, malformed, or contradictory";
      processEvents.push(lifecycleEvent(identity, "policy", observationError));
      if (outcome === "success") {
        outcome = "host_controller_failure";
        error = observationError;
      }
    }
    if (!teardownComplete) {
      outcome = "teardown_failure";
      error = closeError
        ? safeError(closeError)
        : "private state or handle revocation could not be independently confirmed";
    }

    const settledAt = new Date().toISOString();
    const wallMs =
      payloadMs > 0
        ? payloadMs
        : Math.max(0, Math.ceil(performance.now() - startedMonotonic));
    const exhausted = outcomeToExhausted(outcome);
    const resourceAccounting: ScopedTreeRunnerResourceAccounting = {
      ...identity.authenticate(),
      limits: request.limits,
      usage: {
        cpuMs: payloadCpuValid ? guestUsage!.cpuTimeMs : null,
        wait4CpuMs: payloadCpuValid ? (guestUsage!.wait4CpuMs ?? null) : null,
        cgroupCpuUsec: payloadCpuValid
          ? (guestUsage!.cgroupCpuUsec ?? null)
          : null,
        memoryBytes: memoryValid ? guestUsage!.memoryPeakBytes : null,
        children: childrenValue,
        outputBytes: output.acceptedBytes,
        wallMs,
        setupMs,
        teardownMs,
      },
      exhausted,
      exhaustionObservation:
        exhausted === null
          ? null
          : guestUsage?.exhausted === exhausted ||
              (exhausted === "children" && guestUsage?.exhausted === "pids")
            ? "guest-reported"
            : "host-observed",
      observations: {
        cpu: payloadCpuValid ? "payload-cgroup-wait4" : "unavailable",
        memory: memoryValid ? "guest-reported-cgroup-v2" : "unavailable",
        children:
          childrenValue !== null ? "guest-reported-cgroup-v2" : "unavailable",
        output: "host-exec-channel",
        wallTime: "host-monotonic-clock",
      },
      guestResourceGroupRemoved: guestUsage?.resourceGroupRemoved ?? false,
      guestObservationFailed: guestUsage?.observationFailed !== false,
    };
    processEvents.push(
      lifecycleEvent(
        identity,
        "teardown",
        teardownComplete
          ? "VM stopped; private roots destroyed; handles revoked independently of vm.close"
          : "teardown could not be independently confirmed",
      ),
    );
    const teardown: ScopedTreeRunnerInvocationEvidence["teardown"] = {
      ...identity.authenticate(),
      commandStopped,
      vmStopped,
      vfsHandlesRevoked: handlesRevoked,
      policyRemoved: vmStopped,
      ephemeralStateDestroyed: privateRootsDestroyed,
      processTreeEmpty: vmStopped,
      transportClosed: vmStopped,
      privateRootsDestroyed,
      resourceControllersRemoved:
        vmStopped && (guestUsage?.resourceGroupRemoved ?? false),
      completedAt: teardownComplete ? settledAt : null,
    };

    const resultWithoutEvidence = {
      outcome,
      exitCode,
      stdout: output.stdoutText,
      stderr: output.stderrText,
      outputTruncated: output.overflowed,
      resourceAccounting,
      ...(error ? { error } : {}),
    };
    const featureManifestDigest = sha256(
      stableJson(getCapabilityInvocationFeatureManifest()),
    );
    const policyVersions = {
      admission: "scoped-tree-runner/v1" as const,
      filesystem: "root-bound-openat2/v1" as const,
      process: "no-fork-landlock/v1" as const,
      resources: "payload-cgroup-wait4/v1" as const,
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
      publication: null,
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
      roots: {
        repository: request.capabilities.filesystem.repository.identity,
        cache: request.capabilities.filesystem.cache.identity,
        temp: request.capabilities.filesystem.temp.identity,
      },
      observer: {
        provenance: "sandboxd-cgroup-wait4" as const,
        collectionIntervalMs: SCOPED_TREE_OBSERVER_INTERVAL_MS,
        cpuWait4AllowanceUsec: SCOPED_TREE_CPU_WAIT4_ALLOWANCE_USEC,
      },
      requested,
      granted,
      attempted,
      denied,
      observed,
      processEvents,
      resources: resourceAccounting,
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

/** Pin controller-retained directory identities into a live tree provider */
export function bindScopedTreeProvider(
  request: ScopedTreeRunnerInvocationRequest,
  onDecision?: (decision: ScopedTreeDecision) => void,
): ScopedTreeProvider {
  const roles: ScopedTreeRole[] = ["repository", "cache", "temp"];
  const roots: ScopedTreeRootBinding[] = roles.map((role) => {
    const spec = request.capabilities.filesystem[role];
    try {
      const expected = parseDirectoryIdentity(
        spec.identity,
        `filesystem.${role}.identity`,
      );
      const fd = pinDirectory(spec.hostPath, expected);
      return {
        role,
        guestPath: spec.guestPath,
        fd,
        identity: expected,
      };
    } catch (caught) {
      const message = caught instanceof Error ? caught.message : String(caught);
      throw new CapabilityAdmissionError(
        message.includes("cannot") ? "unsupported" : "invalid_request",
        `${capabilityPath(role, "identity")}: ${message}`,
      );
    }
  });
  return new ScopedTreeProvider(roots, onDecision);
}

/** Create an empty private directory and retain its identity */
export function preparePrivateRoot(parent: string, label: string): ScopedTreeRootSpec {
  const hostPath = fs.mkdtempSync(path.join(parent, `${label}-`));
  fs.chmodSync(hostPath, 0o700);
  const fd = fs.openSync(
    hostPath,
    fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | 0x80000,
  );
  try {
    const stats = fs.fstatSync(fd, { bigint: true });
    const born = stats.birthtimeNs;
    if (typeof born !== "bigint" || born <= 0n) {
      throw new CapabilityAdmissionError(
        "unsupported",
        `${capabilityPath(label === "cache" ? "cache" : "temp", "identity")}: host filesystem omits creation-time identity`,
      );
    }
    return {
      hostPath,
      guestPath: label === "cache" ? "/data/cache" : "/data/tmp",
      identity: formatDirectoryIdentity({
        dev: stats.dev,
        ino: stats.ino,
        birthtimeNs: born,
      }),
    };
  } finally {
    fs.closeSync(fd);
  }
}

/** Observe device/inode/creation-time identity for an existing directory */
export function observeRootIdentity(hostPath: string, role: ScopedTreeRole): string {
  const fd = fs.openSync(
    hostPath,
    fs.constants.O_RDONLY |
      fs.constants.O_DIRECTORY |
      fs.constants.O_NOFOLLOW |
      0x80000,
  );
  try {
    const stats = fs.fstatSync(fd, { bigint: true });
    const born = stats.birthtimeNs;
    if (typeof born !== "bigint" || born <= 0n) {
      throw new CapabilityAdmissionError(
        "unsupported",
        `${capabilityPath(role, "identity")}: host filesystem omits creation-time identity`,
      );
    }
    return formatDirectoryIdentity({
      dev: stats.dev,
      ino: stats.ino,
      birthtimeNs: born,
    });
  } finally {
    fs.closeSync(fd);
  }
}

/** Native wait4/cgroup CPU cross-check with a 5 ms allowance */
export function cpuAgreesWithWait4(
  cgroupUsec: number | null | undefined,
  wait4Ms: number | null | undefined,
): boolean {
  if (
    cgroupUsec == null ||
    wait4Ms == null ||
    !Number.isSafeInteger(cgroupUsec) ||
    !Number.isSafeInteger(wait4Ms) ||
    cgroupUsec < 0 ||
    wait4Ms < 0
  ) {
    return false;
  }
  return wait4Ms * 1000 <= cgroupUsec + SCOPED_TREE_CPU_WAIT4_ALLOWANCE_USEC;
}

/** Peak descendants excluding the entrypoint; unavailable without membership */
export function peakChildren(pidsPeak: number | null | undefined): number | null {
  if (pidsPeak == null || !Number.isSafeInteger(pidsPeak) || pidsPeak < 1) {
    return null;
  }
  return pidsPeak - 1;
}

export function validPayloadResourceUsage(
  value: unknown,
): value is ExecResourceUsage {
  if (value === null || typeof value !== "object") return false;
  const usage = value as ExecResourceUsage;
  return (
    [usage.cpuTimeMs, usage.memoryPeakBytes, usage.pidsPeak].every(
      (measurement) =>
        measurement === null ||
        (typeof measurement === "number" &&
          Number.isSafeInteger(measurement) &&
          measurement >= 0),
    ) &&
    (usage.exhausted === null ||
      usage.exhausted === "cpu" ||
      usage.exhausted === "memory" ||
      usage.exhausted === "pids") &&
    typeof usage.observationFailed === "boolean" &&
    typeof usage.resourceGroupRemoved === "boolean" &&
    (usage.wait4CpuMs === undefined ||
      usage.wait4CpuMs === null ||
      (typeof usage.wait4CpuMs === "number" &&
        Number.isSafeInteger(usage.wait4CpuMs) &&
        usage.wait4CpuMs >= 0)) &&
    (usage.cgroupCpuUsec === undefined ||
      usage.cgroupCpuUsec === null ||
      (typeof usage.cgroupCpuUsec === "number" &&
        Number.isSafeInteger(usage.cgroupCpuUsec) &&
        usage.cgroupCpuUsec >= 0))
  );
}

function destroyPrivateRoots(
  request: ScopedTreeRunnerInvocationRequest,
): boolean {
  let destroyed = true;
  for (const role of ["cache", "temp"] as const) {
    const hostPath = request.capabilities.filesystem[role].hostPath;
    try {
      fs.rmSync(hostPath, { recursive: true, force: true });
      if (fs.existsSync(hostPath)) destroyed = false;
    } catch {
      destroyed = false;
    }
  }
  return destroyed;
}

function declaredEffects(
  identity: AuthenticatedExecutionIdentity,
  request: ScopedTreeRunnerInvocationRequest,
  decision: "requested" | "granted",
): ScopedTreeRunnerFilesystemEffect[] {
  const filesystem = request.capabilities.filesystem;
  return (["repository", "cache", "temp"] as const).map((role) => ({
    ...identity.authenticate(),
    domain: "filesystem" as const,
    operation: role === "repository" ? "read" : "write",
    resourceId: sha256(`root:${filesystem[role].identity}`),
    guestPath: filesystem[role].guestPath,
    decision,
  }));
}

function lifecycleEvent(
  identity: AuthenticatedExecutionIdentity,
  kind: ScopedTreeRunnerProcessEvent["kind"],
  detail: string,
): ScopedTreeRunnerProcessEvent {
  return {
    ...identity.authenticate(),
    domain: "lifecycle",
    kind,
    detail,
    observedAt: new Date().toISOString(),
  };
}

function resourceOutcome(
  exhausted: ExecResourceUsage["exhausted"] | undefined,
): ScopedTreeRunnerInvocationResult["outcome"] | undefined {
  if (exhausted === "cpu") return "cpu_exhausted";
  if (exhausted === "memory") return "memory_exhausted";
  if (exhausted === "pids") return "children_exhausted";
  return undefined;
}

function outcomeToExhausted(
  outcome: ScopedTreeRunnerInvocationResult["outcome"],
): ScopedTreeRunnerResourceAccounting["exhausted"] {
  if (outcome === "cpu_exhausted") return "cpu";
  if (outcome === "memory_exhausted") return "memory";
  if (outcome === "children_exhausted") return "children";
  if (outcome === "output_overflow") return "output";
  if (outcome === "timeout") return "wall-time";
  return null;
}

function isMissingExecutionIsolationError(error: unknown): boolean {
  return /(resource_controller|namespace_isolation|capability_policy)_unavailable/.test(
    safeError(error),
  );
}

function safeError(error: unknown): string {
  return (error instanceof Error ? error.message : String(error)).slice(0, 512);
}

function normalizeCeiling(input: unknown): ScopedTreeRunnerCeiling {
  const root = object(input, "ceiling");
  exactKeys(root, CEILING_KEYS, "ceiling");
  literal(
    root.schemaVersion,
    CAPABILITY_CEILING_SCHEMA_VERSION,
    "ceiling.schemaVersion",
    "unsupported",
  );
  literal(root.profile, "scoped-tree-runner", "ceiling.profile", "unsupported");
  const filesystem = object(root.filesystem, "ceiling.filesystem");
  exactKeys(
    filesystem,
    [
      "repositoryHostPaths",
      "repositoryGuestPaths",
      "cacheGuestPaths",
      "tempGuestPaths",
    ],
    "ceiling.filesystem",
  );
  const limits = object(root.limits, "ceiling.limits");
  exactKeys(
    limits,
    ["maxCpuMs", "maxMemoryBytes", "maxChildren", "maxOutputBytes", "maxWallMs"],
    "ceiling.limits",
  );
  return {
    schemaVersion: CAPABILITY_CEILING_SCHEMA_VERSION,
    profile: "scoped-tree-runner",
    allowedExecutables: normalizeExecutables(
      root.allowedExecutables,
      "ceiling.allowedExecutables",
    ),
    allowedWorkingDirectories: uniqueSorted(
      stringArray(root.allowedWorkingDirectories, "ceiling.allowedWorkingDirectories").map(
        (entry) => guestDirectory(entry, "ceiling.allowedWorkingDirectories"),
      ),
    ),
    filesystem: {
      repositoryHostPaths: uniqueSorted(
        stringArray(
          filesystem.repositoryHostPaths,
          "ceiling.filesystem.repositoryHostPaths",
        ).map((entry) => hostDirectory(entry, "ceiling.filesystem.repositoryHostPaths")),
      ),
      repositoryGuestPaths: uniqueSorted(
        stringArray(
          filesystem.repositoryGuestPaths,
          "ceiling.filesystem.repositoryGuestPaths",
        ).map((entry) => guestDirectory(entry, "ceiling.filesystem.repositoryGuestPaths")),
      ),
      cacheGuestPaths: uniqueSorted(
        stringArray(
          filesystem.cacheGuestPaths,
          "ceiling.filesystem.cacheGuestPaths",
        ).map((entry) => guestDirectory(entry, "ceiling.filesystem.cacheGuestPaths")),
      ),
      tempGuestPaths: uniqueSorted(
        stringArray(
          filesystem.tempGuestPaths,
          "ceiling.filesystem.tempGuestPaths",
        ).map((entry) => guestDirectory(entry, "ceiling.filesystem.tempGuestPaths")),
      ),
    },
    limits: {
      maxCpuMs: positiveInteger(limits.maxCpuMs, "ceiling.limits.maxCpuMs"),
      maxMemoryBytes: positiveInteger(
        limits.maxMemoryBytes,
        "ceiling.limits.maxMemoryBytes",
      ),
      maxChildren: nonNegativeInteger(
        limits.maxChildren,
        "ceiling.limits.maxChildren",
      ),
      maxOutputBytes: positiveInteger(
        limits.maxOutputBytes,
        "ceiling.limits.maxOutputBytes",
      ),
      maxWallMs: positiveInteger(limits.maxWallMs, "ceiling.limits.maxWallMs"),
    },
    guarantees: normalizeGuarantees(root.guarantees, "ceiling.guarantees"),
  };
}

function normalizeRequest(input: unknown): ScopedTreeRunnerInvocationRequest {
  const root = object(input, "request");
  exactKeys(root, REQUEST_KEYS, "request");
  literal(
    root.schemaVersion,
    CAPABILITY_INVOCATION_SCHEMA_VERSION,
    "request.schemaVersion",
    "unsupported",
  );
  literal(root.profile, "scoped-tree-runner", "request.profile", "unsupported");
  const launch = object(root.launch, "request.launch");
  exactKeys(launch, ["executable", "args", "cwd"], "request.launch");
  const capabilities = object(root.capabilities, "request.capabilities");
  exactKeys(
    capabilities,
    ["filesystem", "network", "credentials", "git", "ipc", "devices"],
    "request.capabilities",
  );
  literal(capabilities.network, "none", "request.capabilities.network", "unsupported");
  literal(
    capabilities.credentials,
    "none",
    "request.capabilities.credentials",
    "unsupported",
  );
  literal(capabilities.git, "none", "request.capabilities.git", "unsupported");
  literal(capabilities.ipc, "none", "request.capabilities.ipc", "unsupported");
  literal(capabilities.devices, "none", "request.capabilities.devices", "unsupported");
  const filesystem = object(capabilities.filesystem, "request.capabilities.filesystem");
  exactKeys(
    filesystem,
    ["repository", "cache", "temp"],
    "request.capabilities.filesystem",
  );
  const limits = object(root.limits, "request.limits");
  exactKeys(
    limits,
    ["cpuMs", "memoryBytes", "children", "outputBytes", "wallMs"],
    "request.limits",
  );
  return {
    schemaVersion: CAPABILITY_INVOCATION_SCHEMA_VERSION,
    invocationId: nonEmptyString(root.invocationId, "request.invocationId"),
    profile: "scoped-tree-runner",
    launch: {
      executable: guestExecutable(launch.executable, "request.launch.executable"),
      args: stringArray(launch.args, "request.launch.args").map((entry, index) =>
        nonEmptyString(entry, `request.launch.args[${index}]`),
      ),
      cwd: guestDirectory(launch.cwd, "request.launch.cwd"),
    },
    capabilities: {
      filesystem: {
        repository: normalizeRoot(
          filesystem.repository,
          "repository",
          "request.capabilities.filesystem.repository",
        ),
        cache: normalizeRoot(
          filesystem.cache,
          "cache",
          "request.capabilities.filesystem.cache",
        ),
        temp: normalizeRoot(
          filesystem.temp,
          "temp",
          "request.capabilities.filesystem.temp",
        ),
      },
      network: "none",
      credentials: "none",
      git: "none",
      ipc: "none",
      devices: "none",
    },
    limits: {
      cpuMs: positiveInteger(limits.cpuMs, "request.limits.cpuMs"),
      memoryBytes: positiveInteger(
        limits.memoryBytes,
        "request.limits.memoryBytes",
      ),
      children: nonNegativeInteger(limits.children, "request.limits.children"),
      outputBytes: positiveInteger(
        limits.outputBytes,
        "request.limits.outputBytes",
      ),
      wallMs: positiveInteger(limits.wallMs, "request.limits.wallMs"),
    },
    requiredGuarantees: normalizeGuarantees(
      root.requiredGuarantees,
      "request.requiredGuarantees",
    ),
  };
}

function normalizeRoot(
  input: unknown,
  role: ScopedTreeRole,
  label: string,
): ScopedTreeRootSpec {
  const root = object(input, label);
  exactKeys(root, ["hostPath", "guestPath", "identity"], label);
  parseDirectoryIdentity(nonEmptyString(root.identity, `${label}.identity`), `${label}.identity`);
  const spec = {
    hostPath: hostDirectory(root.hostPath, `${label}.hostPath`),
    guestPath: guestDirectory(root.guestPath, `${label}.guestPath`),
    identity: nonEmptyString(root.identity, `${label}.identity`),
  };
  if (role === "repository" && spec.guestPath === "/data") {
    invalid(`${label}.guestPath must be a directory below /data`);
  }
  return spec;
}

function normalizeExecutables(value: unknown, label: string): string[] {
  return uniqueSorted(
    stringArray(value, label).map((entry) => guestExecutable(entry, label)),
  );
}

function normalizeGuarantees(
  value: unknown,
  label: string,
): ScopedTreeRunnerGuarantee[] {
  const values = stringArray(value, label);
  for (const item of values) {
    if (!(SCOPED_TREE_RUNNER_GUARANTEES as readonly string[]).includes(item))
      unsupported(`unknown or unsupported critical guarantee: ${item}`);
  }
  return uniqueSorted(values as ScopedTreeRunnerGuarantee[]);
}

function guestDirectory(value: unknown, label: string): string {
  const result = canonicalGuestPath(value, label);
  if (result !== "/data" && !result.startsWith("/data/"))
    invalid(`${label} must be /data or below it`);
  return result;
}

function guestExecutable(value: unknown, label: string): string {
  const result = canonicalGuestPath(value, label);
  if (result.endsWith("/")) invalid(`${label} must identify an executable file`);
  return result;
}

function canonicalGuestPath(value: unknown, label: string): string {
  const input = nonEmptyString(value, label);
  if (
    !input.startsWith("/") ||
    path.posix.normalize(input) !== input ||
    input.includes("\0")
  )
    invalid(`${label} must be a canonical absolute guest path`);
  return input;
}

function hostDirectory(value: unknown, label: string): string {
  const input = nonEmptyString(value, label);
  if (!path.isAbsolute(input) || input.includes("\0"))
    invalid(`${label} must be an absolute host directory`);
  return path.resolve(input);
}

function object(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    invalid(`${label} must be an object`);
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null)
    invalid(`${label} must be a plain data object`);
  return value as Record<string, unknown>;
}

function exactKeys(
  value: Record<string, unknown>,
  allowed: readonly string[],
  label: string,
): void {
  const unknown = Object.keys(value).filter((key) => !allowed.includes(key));
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
  return value.map((entry, index) =>
    nonEmptyString(entry, `${label}[${index}]`),
  );
}

function nonEmptyString(value: unknown, label: string): string {
  if (typeof value !== "string" || !value.length || value.includes("\0"))
    invalid(`${label} must be a non-empty string without NUL bytes`);
  return value;
}

function positiveInteger(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0)
    invalid(`${label} must be a positive safe integer`);
  return value;
}

function nonNegativeInteger(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0)
    invalid(`${label} must be a non-negative safe integer`);
  return value;
}

function literal<T extends string>(
  value: unknown,
  expected: T,
  label: string,
  code: CapabilityAdmissionError["code"] = "invalid_request",
): asserts value is T {
  if (value !== expected) {
    const error = new CapabilityAdmissionError(
      code,
      `${label} must be ${JSON.stringify(expected)}`,
    );
    throw error;
  }
}

function invalid(message: string): never {
  throw new CapabilityAdmissionError("invalid_request", message);
}

function widening(message: string): never {
  throw new CapabilityAdmissionError("ceiling_widening", message);
}

function unsupported(message: string): never {
  throw new CapabilityAdmissionError("unsupported", message);
}

/** @internal */
export const __test = {
  cpuAgreesWithWait4,
  peakChildren,
  validPayloadResourceUsage,
  resourceOutcome,
  outcomeToExhausted,
  destroyPrivateRoots,
};
