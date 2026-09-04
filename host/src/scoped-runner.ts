import { createHash, randomUUID } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { Writable } from "node:stream";

import {
  CAPABILITY_CEILING_SCHEMA_VERSION,
  CAPABILITY_EVIDENCE_SCHEMA_VERSION,
  CAPABILITY_INVOCATION_SCHEMA_VERSION,
  CapabilityAdmissionError,
  getCapabilityInvocationFeatureManifest,
  type CapabilityInvocationOutcome,
  type CapabilityInvocationRuntimeOptions,
  type CapabilityTeardownEvidence,
} from "./capability-invocation.ts";
import { VM, type VmRuntimeIdentity } from "./vm/core.ts";
import { MemoryProvider } from "./vfs/node/index.ts";
import { createErrnoError } from "./vfs/errors.ts";
import { ERRNO, isWriteFlag } from "./vfs/utils.ts";

export const SCOPED_RUNNER_GUARANTEES = [
  "canonical-request",
  "immutable-ceiling",
  "declared-repository-read",
  "exact-ephemeral-write",
  "no-network",
  "clean-environment",
  "projected-environment",
  "direct-executable",
  "descendant-executable-restriction",
  "explicit-shell",
  "bounded-output",
  "wall-time",
  "disposable-qemu-vm",
  "full-process-tree-termination",
  "host-observed-process-lifecycle",
  "completed-teardown",
] as const;

export type ScopedRunnerGuarantee = (typeof SCOPED_RUNNER_GUARANTEES)[number];

export type ScopedRunnerCeiling = {
  /** Capability ceiling schema identifier */
  schemaVersion: typeof CAPABILITY_CEILING_SCHEMA_VERSION;
  profile: "scoped-runner";
  /** Absolute guest entrypoints permitted by the ceiling */
  allowedExecutables: string[];
  /** Absolute guest descendant executables permitted by the ceiling */
  allowedDescendantExecutables: string[];
  /** Whether shell-mode launches may be requested */
  allowShell: boolean;
  /** Absolute guest working directories permitted by the ceiling */
  allowedWorkingDirectories: string[];
  filesystem: {
    /** Host repository files available for exact snapshot reads */
    sourcePaths: string[];
    /** Guest paths available for exact repository reads */
    readGuestPaths: string[];
    /** Guest paths available for exact ephemeral writes */
    writeGuestPaths: string[];
  };
  environment: {
    /** Environment variable names which an invocation may project */
    allowedNames: string[];
  };
  lifecycle: {
    /** Maximum combined stdout and stderr in `bytes` */
    maxOutputBytes: number;
    /** Maximum command wall time in `ms` */
    maxWallTimeMs: number;
  };
  /** Guarantees the ceiling permits callers to require */
  guarantees: ScopedRunnerGuarantee[];
};

export type ScopedRunnerInvocationRequest = {
  /** Capability invocation schema identifier */
  schemaVersion: typeof CAPABILITY_INVOCATION_SCHEMA_VERSION;
  /** Caller-selected replay identity */
  invocationId: string;
  profile: "scoped-runner";
  launch: {
    /** Directly invoked absolute executable path */
    executable: string;
    /** Literal argument vector excluding the executable */
    args: string[];
    /** Absolute guest working directory */
    cwd: string;
    /** Explicit direct or shell launch mode */
    mode: "direct" | "shell";
  };
  capabilities: {
    filesystem: {
      reads: Array<{
        /** Exact host repository file */
        sourcePath: string;
        /** Exact guest-visible snapshot path */
        guestPath: string;
        operations: ["read"];
      }>;
      writes: Array<{
        /** Exact guest-visible ephemeral file */
        guestPath: string;
        /** Exact write operations required by the invocation */
        operations: Array<"write" | "truncate">;
      }>;
    };
    /** Explicit clean environment projection */
    environment: Record<string, string>;
    process: {
      /** Additional descendant executable authority is denied or allow-listed */
      descendants: "deny" | "allow-list";
      /** Absolute descendant executables, empty when descendants are denied */
      allowedExecutables: string[];
    };
    network: "none";
    credentials: "none";
    git: "none";
    ipc: "none";
    devices: "none";
  };
  lifecycle: {
    /** Combined stdout and stderr bound in `bytes` */
    outputBytes: number;
    /** Command wall-time bound in `ms` */
    wallTimeMs: number;
  };
  /** Guarantees that must be active or admission fails */
  requiredGuarantees: ScopedRunnerGuarantee[];
};

export type ScopedRunnerInvokeOptions = {
  /** Caller cancellation signal */
  signal?: AbortSignal;
};

export type ScopedRunnerFilesystemEffect = {
  domain: "filesystem";
  operation: "read" | "lookup" | "write" | "truncate" | "other";
  /** SHA-256 identity which does not expose a host path */
  resourceId: string;
  /** Guest-visible resource path */
  guestPath: string;
  decision: "requested" | "granted" | "attempted" | "denied" | "observed";
};

export type ScopedRunnerProcessEvent = {
  domain: "process" | "lifecycle";
  kind: "start" | "policy" | "signal" | "exit" | "teardown";
  /** SHA-256 executable identity when applicable */
  executableId?: string;
  /** Non-sensitive host observation */
  detail: string;
  observedAt: string;
};

export type ScopedRunnerInvocationEvidence = {
  schemaVersion: typeof CAPABILITY_EVIDENCE_SCHEMA_VERSION;
  requestDigest: string;
  ceilingDigest: string;
  executionId: string;
  vmId: string;
  runtime: VmRuntimeIdentity;
  policyVersions: {
    admission: "scoped-runner/v1";
    filesystem: "exact-ephemeral-vfs/v1";
    process: "landlock-exec/v1";
    lifecycle: "one-shot-qemu/v1";
  };
  requested: ScopedRunnerFilesystemEffect[];
  granted: ScopedRunnerFilesystemEffect[];
  attempted: ScopedRunnerFilesystemEffect[];
  denied: ScopedRunnerFilesystemEffect[];
  observed: ScopedRunnerFilesystemEffect[];
  processEvents: ScopedRunnerProcessEvent[];
  /** SHA-256 digests of final ephemeral write bytes */
  writeDigests: Record<string, string>;
  startedAt: string;
  settledAt: string;
  teardown: CapabilityTeardownEvidence & {
    /** Whether the disposable VM boundary proved the tree empty */
    processTreeEmpty: boolean;
    /** Whether the execution transport was closed */
    transportClosed: boolean;
    /** Whether ephemeral writable resources were destroyed */
    writableStateDestroyed: boolean;
  };
};

export type ScopedRunnerInvocationResult = {
  outcome:
    CapabilityInvocationOutcome | "policy_denied" | "cancelled" | "guest_crash";
  exitCode: number | null;
  stdout: string;
  stderr: string;
  outputTruncated: boolean;
  evidence: ScopedRunnerInvocationEvidence;
  error?: string;
};

export type CanonicalScopedRunnerRequest = {
  request: ScopedRunnerInvocationRequest;
  canonical: string;
  digest: string;
};

const CEILING_KEYS = [
  "schemaVersion",
  "profile",
  "allowedExecutables",
  "allowedDescendantExecutables",
  "allowShell",
  "allowedWorkingDirectories",
  "filesystem",
  "environment",
  "lifecycle",
  "guarantees",
] as const;

const REQUEST_KEYS = [
  "schemaVersion",
  "invocationId",
  "profile",
  "launch",
  "capabilities",
  "lifecycle",
  "requiredGuarantees",
] as const;

/** Normalize, canonically serialize, and digest one scoped-runner request */
export function canonicalizeScopedRunnerInvocationRequest(
  input: unknown,
): CanonicalScopedRunnerRequest {
  const request = normalizeRequest(input);
  const canonical = stableJson(request);
  return { request, canonical, digest: sha256(canonical) };
}

/** One-shot scoped-runner context with immutable maximum authority */
export class ScopedRunnerInvocationContext {
  readonly ceiling: Readonly<ScopedRunnerCeiling>;
  readonly ceilingDigest: string;
  private readonly runtime: Readonly<CapabilityInvocationRuntimeOptions>;
  private readonly sourceIdentities: ReadonlyMap<string, HostFileIdentity>;
  private readonly usedInvocationIds = new Set<string>();

  private constructor(
    ceiling: ScopedRunnerCeiling,
    runtime: CapabilityInvocationRuntimeOptions,
  ) {
    this.ceiling = deepFreeze(ceiling);
    this.ceilingDigest = sha256(stableJson(ceiling));
    this.runtime = deepFreeze({ ...runtime });
    this.sourceIdentities = new Map(
      ceiling.filesystem.sourcePaths.map((sourcePath) => [
        sourcePath,
        getHostFileIdentity(sourcePath),
      ]),
    );
  }

  static create(
    ceiling: unknown,
    runtime: CapabilityInvocationRuntimeOptions = {},
  ): ScopedRunnerInvocationContext {
    return new ScopedRunnerInvocationContext(
      normalizeCeiling(ceiling),
      runtime,
    );
  }

  async invoke(
    input: unknown,
    options: ScopedRunnerInvokeOptions = {},
  ): Promise<ScopedRunnerInvocationResult> {
    const canonical = canonicalizeScopedRunnerInvocationRequest(input);
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

  private admit(request: ScopedRunnerInvocationRequest): void {
    if (!this.ceiling.allowedExecutables.includes(request.launch.executable)) {
      widening("launch executable is outside the immutable ceiling");
    }
    if (request.launch.mode === "shell" && !this.ceiling.allowShell) {
      widening("shell execution is excluded by the immutable ceiling");
    }
    if (
      request.launch.mode === "shell" &&
      !isShellExecutable(request.launch.executable)
    ) {
      invalid("shell mode requires an explicit supported shell executable");
    }
    if (!this.ceiling.allowedWorkingDirectories.includes(request.launch.cwd)) {
      widening("working directory is outside the immutable ceiling");
    }
    for (const read of request.capabilities.filesystem.reads) {
      if (
        !this.ceiling.filesystem.sourcePaths.includes(read.sourcePath) ||
        !this.ceiling.filesystem.readGuestPaths.includes(read.guestPath)
      ) {
        widening("repository read is outside the immutable ceiling");
      }
    }
    for (const write of request.capabilities.filesystem.writes) {
      if (!this.ceiling.filesystem.writeGuestPaths.includes(write.guestPath)) {
        widening("ephemeral write is outside the immutable ceiling");
      }
    }
    for (const name of Object.keys(request.capabilities.environment)) {
      if (!this.ceiling.environment.allowedNames.includes(name)) {
        widening(
          `environment variable is outside the immutable ceiling: ${name}`,
        );
      }
    }
    for (const executable of request.capabilities.process.allowedExecutables) {
      if (!this.ceiling.allowedDescendantExecutables.includes(executable)) {
        widening(
          `descendant executable is outside the immutable ceiling: ${executable}`,
        );
      }
    }
    if (
      request.lifecycle.outputBytes > this.ceiling.lifecycle.maxOutputBytes ||
      request.lifecycle.wallTimeMs > this.ceiling.lifecycle.maxWallTimeMs
    ) {
      widening("invocation lifecycle bounds exceed the immutable ceiling");
    }
    for (const guarantee of request.requiredGuarantees) {
      if (!this.ceiling.guarantees.includes(guarantee)) {
        widening(
          `required guarantee is excluded by the immutable ceiling: ${guarantee}`,
        );
      }
      if (
        getCapabilityInvocationFeatureManifest().guarantees[guarantee] !==
        "active"
      ) {
        throw new CapabilityAdmissionError(
          "unsupported",
          `required guarantee is not active: ${guarantee}`,
        );
      }
    }
  }

  private async execute(
    canonical: CanonicalScopedRunnerRequest,
    options: ScopedRunnerInvokeOptions,
  ): Promise<ScopedRunnerInvocationResult> {
    const request = canonical.request;
    const executionId = randomUUID();
    const startedAt = new Date().toISOString();
    const attempted: ScopedRunnerFilesystemEffect[] = [];
    const denied: ScopedRunnerFilesystemEffect[] = [];
    const observed: ScopedRunnerFilesystemEffect[] = [];
    const requested = declaredEffects(request, "requested");
    const granted = declaredEffects(request, "granted");
    const processEvents: ScopedRunnerProcessEvent[] = [];
    const provider = new MemoryProvider();
    const reads = new Map<string, ResourcePolicy>();
    const writes = new Map<string, ResourcePolicy>();

    for (const read of request.capabilities.filesystem.reads) {
      const identity = this.sourceIdentities.get(read.sourcePath);
      if (!identity) widening("repository source has no ceiling identity");
      const contents = readExactHostFile(read.sourcePath, identity!);
      const providerPath = toProviderPath(read.guestPath);
      await populateFile(provider, providerPath, contents, 0o400);
      reads.set(providerPath, {
        resourceId: sha256(`file:${read.sourcePath}`),
        guestPath: read.guestPath,
        operations: new Set(["read"]),
      });
    }
    for (const write of request.capabilities.filesystem.writes) {
      const providerPath = toProviderPath(write.guestPath);
      await populateFile(provider, providerPath, Buffer.alloc(0), 0o600);
      writes.set(providerPath, {
        resourceId: sha256(`ephemeral:${write.guestPath}`),
        guestPath: write.guestPath,
        operations: new Set(write.operations),
      });
    }

    const abort = new AbortController();
    const output = new BoundedOutput(request.lifecycle.outputBytes, abort);
    let cancelled = options.signal?.aborted ?? false;
    let timedOut = false;
    const onCancel = () => {
      cancelled = true;
      abort.abort();
    };
    options.signal?.addEventListener("abort", onCancel, { once: true });
    if (cancelled) abort.abort();

    const hooks = createScopedHooks({
      reads,
      writes,
      attempted,
      denied,
      observed,
    });
    let vm: VM | null = null;
    let vmId = "not-created";
    let runtime = unavailableRuntimeIdentity();
    let outcome: ScopedRunnerInvocationResult["outcome"] = "transport_failure";
    let exitCode: number | null = null;
    let error: string | undefined;
    let commandStopped = false;
    let closeError: Error | null = null;
    let runnerPid: number | null = null;
    let runnerAliveAtFailure = true;
    let admissionError: CapabilityAdmissionError | null = null;
    let timer: NodeJS.Timeout | null = null;

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
      for (const feature of [
        "exec.clear-env/v1",
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
        processEvents.push(
          lifecycleEvent("signal", "wall-time expiry requested VM teardown"),
        );
        abort.abort();
      }, request.lifecycle.wallTimeMs);
      timer.unref?.();

      const executableId = sha256(`executable:${request.launch.executable}`);
      processEvents.push({
        domain: "process",
        kind: "policy",
        executableId,
        detail:
          "exact executable allow-list sent over the invocation exec channel",
        observedAt: new Date().toISOString(),
      });
      processEvents.push({
        domain: "process",
        kind: "start",
        executableId,
        detail: "entrypoint launch dispatched to the guest execution channel",
        observedAt: new Date().toISOString(),
      });

      const allowedExecutables = uniqueSorted([
        request.launch.executable,
        ...request.capabilities.process.allowedExecutables,
      ]);
      const result = await vm.exec(
        [request.launch.executable, ...request.launch.args],
        {
          cwd: request.launch.cwd,
          env: request.capabilities.environment,
          clearEnv: true,
          allowedExecutables,
          signal: abort.signal,
          stdin: false,
          pty: false,
          stdout: output.stdout,
          stderr: output.stderr,
          windowBytes: Math.min(request.lifecycle.outputBytes + 1, 256 * 1024),
        },
      );
      commandStopped = true;
      exitCode = result.exitCode;
      processEvents.push({
        domain: "process",
        kind: "exit",
        executableId,
        detail: `entrypoint exited with code ${result.exitCode}${result.signal === undefined ? "" : ` and signal ${result.signal}`}`,
        observedAt: new Date().toISOString(),
      });
      outcome =
        denied.length > 0
          ? "policy_denied"
          : result.exitCode === 0
            ? "success"
            : "command_failed";
    } catch (caught) {
      commandStopped = true;
      runnerAliveAtFailure = runnerPid === null || isProcessAlive(runnerPid);
      if (caught instanceof CapabilityAdmissionError) {
        admissionError = caught;
        error = safeError(caught);
      } else if (output.overflowed) {
        outcome = "output_overflow";
      } else if (cancelled) {
        outcome = "cancelled";
        processEvents.push(
          lifecycleEvent("signal", "caller cancellation requested VM teardown"),
        );
      } else if (timedOut) {
        outcome = "timeout";
      } else if (!runnerAliveAtFailure) {
        outcome = "guest_crash";
      } else {
        outcome = "transport_failure";
      }
      error ??= safeError(caught);
    } finally {
      if (timer) clearTimeout(timer);
      options.signal?.removeEventListener("abort", onCancel);
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
    if (admissionError && teardownComplete) throw admissionError;
    if (!teardownComplete) {
      outcome = "teardown_failure";
      error = closeError
        ? safeError(closeError)
        : "VM teardown could not be confirmed";
    }
    const writeDigests: Record<string, string> = {};
    for (const [providerPath, policy] of writes) {
      writeDigests[policy.guestPath] = sha256(
        await readProviderFile(provider, providerPath),
      );
    }
    const settledAt = new Date().toISOString();
    processEvents.push(
      lifecycleEvent(
        "teardown",
        teardownComplete
          ? "VM stopped; process tree empty; handles, policy, transport, and writable state revoked"
          : "teardown could not be independently confirmed",
      ),
    );
    const teardown: ScopedRunnerInvocationEvidence["teardown"] = {
      commandStopped,
      vmStopped: teardownComplete,
      vfsHandlesRevoked: teardownComplete,
      policyRemoved: teardownComplete,
      ephemeralStateDestroyed: teardownComplete,
      processTreeEmpty: teardownComplete,
      transportClosed: teardownComplete,
      writableStateDestroyed: teardownComplete,
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
          admission: "scoped-runner/v1",
          filesystem: "exact-ephemeral-vfs/v1",
          process: "landlock-exec/v1",
          lifecycle: "one-shot-qemu/v1",
        },
        requested,
        granted,
        attempted,
        denied,
        observed,
        processEvents,
        writeDigests,
        startedAt,
        settledAt,
        teardown,
      },
      ...(error ? { error } : {}),
    };
  }
}

type ResourcePolicy = {
  resourceId: string;
  guestPath: string;
  operations: Set<string>;
};

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
    this.owner.accept(
      this,
      Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, encoding),
    );
    callback();
  }
}

class BoundedOutput {
  readonly stdout = new CollectingSink(this);
  readonly stderr = new CollectingSink(this);
  overflowed = false;
  private acceptedBytes = 0;
  private readonly limit: number;
  private readonly abort: AbortController;
  constructor(limit: number, abort: AbortController) {
    this.limit = limit;
    this.abort = abort;
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

function normalizeCeiling(input: unknown): ScopedRunnerCeiling {
  const root = object(input, "ceiling");
  exactKeys(root, CEILING_KEYS, "ceiling");
  literal(
    root.schemaVersion,
    CAPABILITY_CEILING_SCHEMA_VERSION,
    "ceiling.schemaVersion",
    "unsupported",
  );
  literal(root.profile, "scoped-runner", "ceiling.profile", "unsupported");
  boolean(root.allowShell, "ceiling.allowShell");
  const filesystem = object(root.filesystem, "ceiling.filesystem");
  exactKeys(
    filesystem,
    ["sourcePaths", "readGuestPaths", "writeGuestPaths"],
    "ceiling.filesystem",
  );
  const environment = object(root.environment, "ceiling.environment");
  exactKeys(environment, ["allowedNames"], "ceiling.environment");
  const lifecycle = object(root.lifecycle, "ceiling.lifecycle");
  exactKeys(
    lifecycle,
    ["maxOutputBytes", "maxWallTimeMs"],
    "ceiling.lifecycle",
  );

  const ceiling: ScopedRunnerCeiling = {
    schemaVersion: CAPABILITY_CEILING_SCHEMA_VERSION,
    profile: "scoped-runner",
    allowedExecutables: normalizeExecutables(
      root.allowedExecutables,
      "ceiling.allowedExecutables",
    ),
    allowedDescendantExecutables: normalizeExecutables(
      root.allowedDescendantExecutables,
      "ceiling.allowedDescendantExecutables",
    ),
    allowShell: root.allowShell as boolean,
    allowedWorkingDirectories: uniqueSorted(
      stringArray(
        root.allowedWorkingDirectories,
        "ceiling.allowedWorkingDirectories",
      ).map((value) =>
        guestDirectory(value, "ceiling.allowedWorkingDirectories"),
      ),
    ),
    filesystem: {
      sourcePaths: uniqueSorted(
        stringArray(
          filesystem.sourcePaths,
          "ceiling.filesystem.sourcePaths",
        ).map((value) =>
          canonicalHostFile(value, "ceiling.filesystem.sourcePaths"),
        ),
      ),
      readGuestPaths: uniqueSorted(
        stringArray(
          filesystem.readGuestPaths,
          "ceiling.filesystem.readGuestPaths",
        ).map((value) =>
          guestDataFile(value, "ceiling.filesystem.readGuestPaths"),
        ),
      ),
      writeGuestPaths: uniqueSorted(
        stringArray(
          filesystem.writeGuestPaths,
          "ceiling.filesystem.writeGuestPaths",
        ).map((value) =>
          guestDataFile(value, "ceiling.filesystem.writeGuestPaths"),
        ),
      ),
    },
    environment: {
      allowedNames: uniqueSorted(
        stringArray(
          environment.allowedNames,
          "ceiling.environment.allowedNames",
        ).map((value) =>
          environmentName(value, "ceiling.environment.allowedNames"),
        ),
      ),
    },
    lifecycle: {
      maxOutputBytes: positiveInteger(
        lifecycle.maxOutputBytes,
        "ceiling.lifecycle.maxOutputBytes",
      ),
      maxWallTimeMs: positiveInteger(
        lifecycle.maxWallTimeMs,
        "ceiling.lifecycle.maxWallTimeMs",
      ),
    },
    guarantees: normalizeGuarantees(root.guarantees, "ceiling.guarantees"),
  };
  if (
    !ceiling.allowedExecutables.length ||
    !ceiling.allowedWorkingDirectories.length ||
    !ceiling.guarantees.length
  ) {
    invalid("ceiling intersections cannot be empty");
  }
  if (
    new Set([
      ...ceiling.filesystem.readGuestPaths,
      ...ceiling.filesystem.writeGuestPaths,
    ]).size !==
    ceiling.filesystem.readGuestPaths.length +
      ceiling.filesystem.writeGuestPaths.length
  ) {
    invalid("read and write guest paths must be disjoint");
  }
  return ceiling;
}

function normalizeRequest(input: unknown): ScopedRunnerInvocationRequest {
  const root = object(input, "request");
  exactKeys(root, REQUEST_KEYS, "request");
  literal(
    root.schemaVersion,
    CAPABILITY_INVOCATION_SCHEMA_VERSION,
    "request.schemaVersion",
    "unsupported",
  );
  literal(root.profile, "scoped-runner", "request.profile", "unsupported");
  const invocationId = nonEmptyString(
    root.invocationId,
    "request.invocationId",
  );
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(invocationId))
    invalid("request.invocationId contains unsupported characters");

  const launch = object(root.launch, "request.launch");
  exactKeys(launch, ["executable", "args", "cwd", "mode"], "request.launch");
  if (launch.mode !== "direct" && launch.mode !== "shell")
    invalid("request.launch.mode must be direct or shell");
  const capabilities = object(root.capabilities, "request.capabilities");
  exactKeys(
    capabilities,
    [
      "filesystem",
      "environment",
      "process",
      "network",
      "credentials",
      "git",
      "ipc",
      "devices",
    ],
    "request.capabilities",
  );
  for (const domain of [
    "network",
    "credentials",
    "git",
    "ipc",
    "devices",
  ] as const) {
    literal(
      capabilities[domain],
      "none",
      `request.capabilities.${domain}`,
      "unsupported",
    );
  }
  const filesystem = object(
    capabilities.filesystem,
    "request.capabilities.filesystem",
  );
  exactKeys(filesystem, ["reads", "writes"], "request.capabilities.filesystem");
  if (!Array.isArray(filesystem.reads) || !Array.isArray(filesystem.writes))
    invalid("filesystem reads and writes must be arrays");
  const reads = (filesystem.reads as unknown[]).map((entry, index) => {
    const value = object(
      entry,
      `request.capabilities.filesystem.reads[${index}]`,
    );
    exactKeys(
      value,
      ["sourcePath", "guestPath", "operations"],
      `request.capabilities.filesystem.reads[${index}]`,
    );
    const operations = stringArray(
      value.operations,
      `request.capabilities.filesystem.reads[${index}].operations`,
    );
    if (operations.length !== 1 || operations[0] !== "read")
      unsupported("repository reads support only the exact operation ['read']");
    return {
      sourcePath: canonicalHostFile(
        value.sourcePath,
        `request.capabilities.filesystem.reads[${index}].sourcePath`,
      ),
      guestPath: guestDataFile(
        value.guestPath,
        `request.capabilities.filesystem.reads[${index}].guestPath`,
      ),
      operations: ["read"] as ["read"],
    };
  });
  const writes = (filesystem.writes as unknown[]).map((entry, index) => {
    const value = object(
      entry,
      `request.capabilities.filesystem.writes[${index}]`,
    );
    exactKeys(
      value,
      ["guestPath", "operations"],
      `request.capabilities.filesystem.writes[${index}]`,
    );
    const operations = uniqueSorted(
      stringArray(
        value.operations,
        `request.capabilities.filesystem.writes[${index}].operations`,
      ),
    );
    if (
      !operations.length ||
      operations.some(
        (operation) => operation !== "write" && operation !== "truncate",
      )
    )
      unsupported("ephemeral writes support only write and truncate");
    return {
      guestPath: guestDataFile(
        value.guestPath,
        `request.capabilities.filesystem.writes[${index}].guestPath`,
      ),
      operations: operations as Array<"write" | "truncate">,
    };
  });
  const allGuestPaths = [
    ...reads.map((entry) => entry.guestPath),
    ...writes.map((entry) => entry.guestPath),
  ];
  if (new Set(allGuestPaths).size !== allGuestPaths.length)
    invalid("declared guest resource paths must be unique and disjoint");

  const environment = object(
    capabilities.environment,
    "request.capabilities.environment",
  );
  const normalizedEnvironment: Record<string, string> = {};
  for (const key of Object.keys(environment).sort()) {
    const name = environmentName(key, "request.capabilities.environment");
    normalizedEnvironment[name] = nonEmptyString(
      environment[key],
      `request.capabilities.environment.${key}`,
    );
  }
  const processPolicy = object(
    capabilities.process,
    "request.capabilities.process",
  );
  exactKeys(
    processPolicy,
    ["descendants", "allowedExecutables"],
    "request.capabilities.process",
  );
  if (
    processPolicy.descendants !== "deny" &&
    processPolicy.descendants !== "allow-list"
  )
    invalid("process descendants must be deny or allow-list");
  const descendantExecutables = normalizeExecutables(
    processPolicy.allowedExecutables,
    "request.capabilities.process.allowedExecutables",
  );
  if (processPolicy.descendants === "deny" && descendantExecutables.length)
    invalid("deny descendant policy requires an empty executable list");
  if (
    processPolicy.descendants === "allow-list" &&
    !descendantExecutables.length
  )
    invalid("allow-list descendant policy requires at least one executable");
  const lifecycle = object(root.lifecycle, "request.lifecycle");
  exactKeys(lifecycle, ["outputBytes", "wallTimeMs"], "request.lifecycle");
  const requiredGuarantees = normalizeGuarantees(
    root.requiredGuarantees,
    "request.requiredGuarantees",
  );
  if (!requiredGuarantees.length)
    invalid("request.requiredGuarantees cannot be empty");

  return {
    schemaVersion: CAPABILITY_INVOCATION_SCHEMA_VERSION,
    invocationId,
    profile: "scoped-runner",
    launch: {
      executable: guestExecutable(
        launch.executable,
        "request.launch.executable",
      ),
      args: stringArray(launch.args, "request.launch.args"),
      cwd: guestDirectory(launch.cwd, "request.launch.cwd"),
      mode: launch.mode,
    },
    capabilities: {
      filesystem: { reads, writes },
      environment: normalizedEnvironment,
      process: {
        descendants: processPolicy.descendants,
        allowedExecutables: descendantExecutables,
      },
      network: "none",
      credentials: "none",
      git: "none",
      ipc: "none",
      devices: "none",
    },
    lifecycle: {
      outputBytes: positiveInteger(
        lifecycle.outputBytes,
        "request.lifecycle.outputBytes",
      ),
      wallTimeMs: positiveInteger(
        lifecycle.wallTimeMs,
        "request.lifecycle.wallTimeMs",
      ),
    },
    requiredGuarantees,
  };
}

function createScopedHooks(options: {
  reads: Map<string, ResourcePolicy>;
  writes: Map<string, ResourcePolicy>;
  attempted: ScopedRunnerFilesystemEffect[];
  denied: ScopedRunnerFilesystemEffect[];
  observed: ScopedRunnerFilesystemEffect[];
}) {
  return {
    before(context: {
      op: string;
      path?: string;
      flags?: string | number;
    }): void {
      const providerPath = normalizeProviderPath(context.path ?? "/");
      const guestPath = toGuestPath(providerPath);
      const operation = classifyOperation(context.op, context.flags);
      const policy =
        options.reads.get(providerPath) ?? options.writes.get(providerPath);
      const effect: ScopedRunnerFilesystemEffect = {
        domain: "filesystem",
        operation,
        resourceId: policy?.resourceId ?? sha256(`guest:${guestPath}`),
        guestPath,
        decision: "attempted",
      };
      options.attempted.push(effect);
      const infrastructure = isInfrastructureLookup(providerPath, operation, [
        ...options.reads.keys(),
        ...options.writes.keys(),
      ]);
      const allowed =
        infrastructure ||
        (policy !== undefined && operationAllowed(policy, operation));
      if (!allowed) {
        options.denied.push({ ...effect, decision: "denied" });
        throw createErrnoError(ERRNO.EACCES, context.op, context.path);
      }
    },
    after(context: {
      op: string;
      path?: string;
      flags?: string | number;
    }): void {
      const providerPath = normalizeProviderPath(context.path ?? "/");
      const policy =
        options.reads.get(providerPath) ?? options.writes.get(providerPath);
      if (!policy) return;
      options.observed.push({
        domain: "filesystem",
        operation: classifyOperation(context.op, context.flags),
        resourceId: policy.resourceId,
        guestPath: policy.guestPath,
        decision: "observed",
      });
    },
  };
}

function operationAllowed(
  policy: ResourcePolicy,
  operation: ScopedRunnerFilesystemEffect["operation"],
): boolean {
  if (operation === "lookup") return true;
  return policy.operations.has(operation);
}

function isInfrastructureLookup(
  providerPath: string,
  operation: string,
  resources: string[],
): boolean {
  if (operation !== "lookup") return false;
  if (
    providerPath === "/" ||
    providerPath === "/etc" ||
    providerPath === "/etc/gondolin"
  )
    return true;
  return resources.some((resource) => resource.startsWith(`${providerPath}/`));
}

function classifyOperation(
  op: string,
  flags?: string | number,
): ScopedRunnerFilesystemEffect["operation"] {
  if (/truncate/i.test(op) || (op === "open" && isTruncatingOpen(flags)))
    return "truncate";
  if (op === "open" && flags !== undefined && isWritableOpen(flags))
    return "write";
  if (/write/i.test(op)) return "write";
  if (/read/i.test(op)) return "read";
  if (/open|stat|access|realpath|release|readdir/i.test(op)) return "lookup";
  return "other";
}

function isWritableOpen(flags: string | number): boolean {
  return typeof flags === "string"
    ? isWriteFlag(flags)
    : (flags &
        (fs.constants.O_WRONLY |
          fs.constants.O_RDWR |
          fs.constants.O_APPEND |
          fs.constants.O_CREAT |
          fs.constants.O_TRUNC)) !==
        0;
}

function isTruncatingOpen(flags: string | number | undefined): boolean {
  if (flags === undefined) return false;
  if (typeof flags === "string") return flags.includes("w");
  return (flags & fs.constants.O_TRUNC) !== 0;
}

function declaredEffects(
  request: ScopedRunnerInvocationRequest,
  decision: "requested" | "granted",
): ScopedRunnerFilesystemEffect[] {
  return [
    ...request.capabilities.filesystem.reads.map((read) => ({
      domain: "filesystem" as const,
      operation: "read" as const,
      resourceId: sha256(`file:${read.sourcePath}`),
      guestPath: read.guestPath,
      decision,
    })),
    ...request.capabilities.filesystem.writes.flatMap((write) =>
      write.operations.map((operation) => ({
        domain: "filesystem" as const,
        operation,
        resourceId: sha256(`ephemeral:${write.guestPath}`),
        guestPath: write.guestPath,
        decision,
      })),
    ),
  ];
}

async function populateFile(
  provider: InstanceType<typeof MemoryProvider>,
  filePath: string,
  contents: Buffer,
  mode: number,
): Promise<void> {
  const directory = path.posix.dirname(filePath);
  if (directory !== "/") await provider.mkdir(directory, { recursive: true });
  const handle = await provider.open(filePath, "w", mode);
  await handle.writeFile(contents);
  await handle.close();
}

async function readProviderFile(
  provider: InstanceType<typeof MemoryProvider>,
  filePath: string,
): Promise<Buffer> {
  const handle = await provider.open(filePath, "r");
  try {
    return Buffer.from(await handle.readFile());
  } finally {
    await handle.close();
  }
}

type HostFileIdentity = { dev: bigint; ino: bigint };

function canonicalHostFile(value: unknown, label: string): string {
  const input = nonEmptyString(value, label);
  const lexical = path.resolve(input);
  let stats: fs.Stats;
  try {
    stats = fs.lstatSync(lexical);
  } catch {
    invalid(`${label} must identify an existing host file`);
  }
  if (stats!.isSymbolicLink() || !stats!.isFile())
    invalid(
      `${label} must identify a regular file without symlink indirection`,
    );
  return fs.realpathSync(lexical);
}

function getHostFileIdentity(filePath: string): HostFileIdentity {
  const noFollow = fs.constants.O_NOFOLLOW;
  if (typeof noFollow !== "number")
    unsupported(
      "host platform cannot open exact files without following links",
    );
  let fd: number;
  try {
    fd = fs.openSync(filePath, fs.constants.O_RDONLY | noFollow);
  } catch {
    invalid(
      "repository source changed or could not be opened without symlink traversal",
    );
  }
  try {
    const stats = fs.fstatSync(fd!, { bigint: true });
    if (!stats.isFile())
      invalid("repository source is no longer a regular file");
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
  if (typeof noFollow !== "number")
    unsupported(
      "host platform cannot open exact files without following links",
    );
  const fd = fs.openSync(filePath, fs.constants.O_RDONLY | noFollow);
  try {
    const stats = fs.fstatSync(fd, { bigint: true });
    if (!stats.isFile())
      invalid("repository source is no longer a regular file");
    if (stats.dev !== expected.dev || stats.ino !== expected.ino)
      invalid("repository source identity changed after ceiling creation");
    return fs.readFileSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

function guestDataFile(value: unknown, label: string): string {
  const result = canonicalGuestPath(value, label);
  if (!result.startsWith("/data/") || result.endsWith("/"))
    invalid(`${label} must be a file below /data`);
  return result;
}

function guestDirectory(value: unknown, label: string): string {
  const result = canonicalGuestPath(value, label);
  if (result !== "/data" && !result.startsWith("/data/"))
    invalid(`${label} must be /data or below it`);
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

function guestExecutable(value: unknown, label: string): string {
  const result = canonicalGuestPath(value, label);
  if (result.endsWith("/"))
    invalid(`${label} must identify an executable file`);
  return result;
}

function normalizeExecutables(value: unknown, label: string): string[] {
  return uniqueSorted(
    stringArray(value, label).map((entry) => guestExecutable(entry, label)),
  );
}

function environmentName(value: unknown, label: string): string {
  const name = nonEmptyString(value, label);
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name))
    invalid(`${label} contains an invalid environment variable name`);
  return name;
}

function normalizeGuarantees(
  value: unknown,
  label: string,
): ScopedRunnerGuarantee[] {
  const values = stringArray(value, label);
  for (const item of values) {
    if (!(SCOPED_RUNNER_GUARANTEES as readonly string[]).includes(item))
      unsupported(`unknown or unsupported critical guarantee: ${item}`);
  }
  return uniqueSorted(values as ScopedRunnerGuarantee[]);
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

function boolean(value: unknown, label: string): asserts value is boolean {
  if (typeof value !== "boolean") invalid(`${label} must be a boolean`);
}

function literal(
  value: unknown,
  expected: string,
  label: string,
  code: "invalid_request" | "unsupported",
): void {
  if (value !== expected)
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

function widening(message: string): never {
  throw new CapabilityAdmissionError("ceiling_widening", message);
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
  return path.posix.normalize(value.startsWith("/") ? value : `/${value}`);
}

function toProviderPath(guestPath: string): string {
  return guestPath.slice("/data".length);
}

function toGuestPath(providerPath: string): string {
  const normalized = normalizeProviderPath(providerPath);
  return normalized === "/" ? "/data" : `/data${normalized}`;
}

function isShellExecutable(executable: string): boolean {
  return ["/bin/sh", "/bin/bash", "/bin/ash", "/usr/bin/bash"].includes(
    executable,
  );
}

function lifecycleEvent(
  kind: ScopedRunnerProcessEvent["kind"],
  detail: string,
): ScopedRunnerProcessEvent {
  return {
    domain: "lifecycle",
    kind,
    detail,
    observedAt: new Date().toISOString(),
  };
}

function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code !== "ESRCH";
  }
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
  return (error instanceof Error ? error.message : String(error)).slice(0, 512);
}
