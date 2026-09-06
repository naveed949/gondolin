import { Writable } from "node:stream";
import { assertDefaultHttpsTrust } from "./http/https-connector.ts";
import fs from "node:fs";
import path from "node:path";
import { VM, type VmRuntimeIdentity } from "./vm/core.ts";
import { CapabilitySnapshotProvider } from "./capability-snapshot.ts";
import { BoundedOutput } from "./bounded-output.ts";
import { HttpsObservation } from "./http/https-observation.ts";
import { isPublicAddress } from "./public-address.ts";
import { deepFreeze, sha256, stableJson } from "./canonical-json.ts";
import {
  isProcessAlive,
  unavailableRuntimeIdentity,
} from "./capability-runtime.ts";
import { createErrnoError } from "./vfs/errors.ts";
import { ERRNO, isWriteFlag } from "./vfs/utils.ts";
import {
  getCapabilityInvocationFeatureManifest,
  type CapabilityInvocationRuntimeOptions,
} from "./capability-invocation.ts";
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
  HTTPS_CEILING_SCHEMA_VERSION,
  HTTPS_EVIDENCE_SCHEMA_VERSION,
  HTTPS_REQUEST_SCHEMA_VERSION,
  admitHttpsRequest,
  canonicalizeHttpsInvocationRequest,
  exactObject,
  normalizeHttpsCeiling,
  type HttpsInvocationCeiling,
  type HttpsInvocationRequest,
} from "./https-authority.ts";

export {
  HTTPS_CEILING_SCHEMA_VERSION,
  HTTPS_EVIDENCE_SCHEMA_VERSION,
  HTTPS_REQUEST_SCHEMA_VERSION,
  canonicalizeHttpsInvocationRequest,
};
export type { HttpsInvocationCeiling, HttpsInvocationRequest };

export const HTTPS_POLICY_VERSIONS = deepFreeze({
  admission: "https-request/v1",
  filesystem: "empty-snapshot-vfs/v1",
  process: "exact-mount-landlock/v1",
  network: "http-tls-mediator/v3",
  lifecycle: "one-shot-qemu/v1",
});
const EXECUTABLE = "/usr/bin/curl";
const REQUIRED_FEATURES = [
  "exec.clear-env/v1",
  "exec.descendants-denied/v1",
  "exec.executable-mount-policy/v1",
  "exec.exact-path-lsm/v1",
  "exec.payload-confinement/v1",
  "exec.landlock-allowlist/v1",
];

type Observation = ReturnType<HttpsObservation["snapshot"]>;
export type HttpsInvocationOutcome =
  | "success"
  | "policy_denied"
  | "command_failed"
  | "timeout"
  | "output_overflow"
  | "transport_failure"
  | "host_controller_failure"
  | "teardown_failure";
export type HttpsInvocationRuntimeOptions = Omit<
  CapabilityInvocationRuntimeOptions,
  "credentialStore"
>;
export type HttpsInvocationResult = {
  outcome: HttpsInvocationOutcome;
  exitCode: number | null;
  /** Bounded guest diagnostics with no HTTP response provenance claim */
  stdout: string;
  stderr: string;
  outputTruncated: boolean;
  /** Host-observed complete upstream response only on accepted success */
  response: Observation["response"];
  evidence: HttpsInvocationEvidence;
};
export type HttpsInvocationEvidence = {
  schemaVersion: typeof HTTPS_EVIDENCE_SCHEMA_VERSION;
  capabilitySchemaVersion: typeof HTTPS_REQUEST_SCHEMA_VERSION;
  gondolinVersion: string;
  decision: "admitted";
  outcome: HttpsInvocationOutcome;
  requestDigest: string;
  ceilingDigest: string;
  executionId: string;
  vmId: string;
  runtime: VmRuntimeIdentity;
  featureManifestDigest: string;
  qualificationId: string;
  policyVersions: typeof HTTPS_POLICY_VERSIONS;
  /** Full canonical request binds URL, authority and limits without guest reinterpretation */
  request: HttpsInvocationRequest;
  /** Authenticated host-mediated observation, distinct from independent external proof */
  network: Observation & { executionId: string; sequence: number };
  /** Caller filesystem authority is absent in this profile */
  filesystem: "none";
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
    networkChannelsClosed: boolean;
    ephemeralStateDestroyed: boolean;
    completedAt: string | null;
  };
  resultDigest: string;
  integrity: CapabilityEvidenceIntegrity;
};

/** A fresh VM and host mediator for exactly one credential-free HTTPS invocation */
export class HttpsInvocationContext {
  #ceiling: HttpsInvocationCeiling;
  #ceilingDigest: string;
  #runtime: Readonly<HttpsInvocationRuntimeOptions>;
  #used = false;
  get ceiling(): HttpsInvocationCeiling {
    return this.#ceiling;
  }
  get ceilingDigest(): string {
    return this.#ceilingDigest;
  }

  private constructor(input: unknown, runtime: HttpsInvocationRuntimeOptions) {
    this.#ceiling = normalizeHttpsCeiling(input);
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
    )
      throw new TypeError("unsupported HTTPS runtime option");
    if (runtime.console !== undefined && runtime.console !== "none")
      throw new TypeError("HTTPS console must be disabled");
    if (
      runtime.startTimeoutMs !== undefined &&
      (!Number.isSafeInteger(runtime.startTimeoutMs) ||
        runtime.startTimeoutMs <= 0 ||
        runtime.startTimeoutMs > 2147483647)
    )
      throw new TypeError("HTTPS startup deadline must be finite");
    this.#runtime = deepFreeze(structuredClone(runtime));
    Object.freeze(this);
  }

  static create(
    ceiling: unknown,
    runtime: HttpsInvocationRuntimeOptions = {},
  ): HttpsInvocationContext {
    return new HttpsInvocationContext(ceiling, runtime);
  }

  async execute(input: unknown): Promise<HttpsInvocationResult> {
    const canonical = canonicalizeHttpsInvocationRequest(input),
      request = canonical.request;
    admitHttpsRequest(request, this.ceiling);
    if (this.#used) throw new TypeError("HTTPS context is single use");
    assertTrustedEnvironment();
    this.#used = true;
    const identity = AuthenticatedExecutionIdentity.begin(
      canonical.digest,
      this.ceilingDigest,
    );
    const startedAt = new Date().toISOString(),
      abort = new AbortController();
    const output = new BoundedOutput(request.limits.outputBytes, abort);
    // Curl stdout carries entity bytes (GET) or response headers (HEAD), never diagnostics.
    // Discard incrementally without retaining a duplicate response or granting device writes.
    const discardLimit =
      request.request.method === "HEAD"
        ? 65536
        : request.authority.maxResponseBytes;
    let discardedBytes = 0,
      discardOverflow = false;
    const discard = new Writable({
      write(chunk, encoding, callback) {
        discardedBytes += Buffer.isBuffer(chunk)
          ? chunk.length
          : Buffer.byteLength(chunk, encoding);
        if (discardedBytes > discardLimit) {
          discardOverflow = true;
          abort.abort();
        }
        callback();
      },
    });
    const observation = new HttpsObservation({
      ...request.request,
      maxResponseBytes: request.authority.maxResponseBytes,
      timeoutMs: request.authority.timeoutMs,
    });
    const provider = new CapabilitySnapshotProvider();
    let vm: VM | null = null,
      vmId = "not-created",
      runtime = unavailableRuntimeIdentity();
    let runnerPid: number | null = null,
      exitCode: number | null = null;
    let outcome: HttpsInvocationOutcome = "host_controller_failure",
      commandStopped = false;
    let closed = false,
      timedOut = false,
      policyDenied = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const deny = () => {
      policyDenied = true;
      observation.fail("request_denied");
      return false;
    };
    try {
      vm = await VM.create({
        autoStart: false,
        startTimeoutMs: this.#runtime.startTimeoutMs ?? 30000,
        memory: this.#runtime.memory,
        cpus: this.#runtime.cpus,
        rootfs: { mode: "readonly" },
        env: undefined,
        httpsObservation: observation,
        maxHttpResponseBodyBytes: request.authority.maxResponseBytes,
        httpHooks: {
          isRequestAllowed(value) {
            return (
              (value.url === request.request.url &&
                value.method === request.request.method) ||
              deny()
            );
          },
          isIpAllowed(value) {
            return (
              (value.protocol === "https" &&
                value.hostname === request.authority.host &&
                value.port === request.authority.port &&
                isPublicAddress(value.ip)) ||
              deny()
            );
          },
          isRedirectAllowed() {
            return deny();
          },
          onFlowDecision(value) {
            if (!value.allowed || value.protocol !== "tls") deny();
          },
        },
        dns: {
          mode: "synthetic",
          syntheticHostMapping: "single",
          syntheticIPv4: "192.0.2.1",
        },
        vfs: {
          mounts: { "/": provider },
          hooks: {
            before(context) {
              const pathname = path.posix.normalize(`/${context.path ?? ""}`);
              const flags = context.flags;
              const write =
                flags === undefined
                  ? false
                  : typeof flags === "string"
                    ? isWriteFlag(flags)
                    : (flags &
                        (fs.constants.O_WRONLY |
                          fs.constants.O_RDWR |
                          fs.constants.O_APPEND |
                          fs.constants.O_CREAT |
                          fs.constants.O_TRUNC)) !==
                      0;
              const lookup = [
                "stat",
                "lstat",
                "realpath",
                "access",
                "release",
              ].includes(context.op);
              const trust = [
                "/etc/gondolin/mitm",
                "/etc/gondolin/mitm/ca.crt",
              ].includes(pathname);
              if (
                !write &&
                ((lookup &&
                  ["/", "/etc", "/etc/gondolin"].includes(pathname)) ||
                  (trust &&
                    (lookup ||
                      ["open", "read", "close", "fstat"].includes(context.op))))
              )
                return;
              policyDenied = true;
              observation.fail("request_denied");
              throw createErrnoError(ERRNO.EACCES, context.op, pathname);
            },
          },
        },
        sandbox: {
          vmm: "qemu",
          qemuPath: this.#runtime.qemuPath,
          imagePath: this.#runtime.imagePath,
          accel: this.#runtime.accel,
          cpu: this.#runtime.cpu,
          machineType: this.#runtime.machineType,
          console: "none",
          autoRestart: false,
          netEnabled: true,
          allowWebSockets: false,
        },
      });
      vmId = vm.id;
      identity.bindVm(vmId);
      runtime = vm.getRuntimeIdentity();
      if (
        REQUIRED_FEATURES.some(
          (feature) => !runtime.guestFeatures.includes(feature),
        )
      )
        throw new Error("HTTPS guest lacks mandatory confinement features");
      await vm.start();
      runnerPid = vm.getHostPid();
      timer = setTimeout(() => {
        timedOut = true;
        observation.fail("timeout");
        abort.abort();
      }, request.limits.wallTimeMs);
      timer.unref();
      const result = await vm.exec(
        [
          EXECUTABLE,
          "--disable",
          "--silent",
          "--show-error",
          "--http1.1",
          "--proto",
          "=https",
          "--noproxy",
          "*",
          "--cacert",
          "/etc/gondolin/mitm/ca.crt",
          "--resolve",
          `${request.authority.host}:${request.authority.port}:192.0.2.1`,
          "--header",
          "Accept-Encoding: identity",
          "--output",
          "-",
          ...(request.request.method === "HEAD" ? ["--head"] : []),
          "--url",
          request.request.url,
        ],
        {
          clearEnv: true,
          allowedExecutables: [EXECUTABLE],
          denyDescendants: true,
          isolateIpc: true,
          isolateDevices: true,
          signal: abort.signal,
          stdin: false,
          pty: false,
          stdout: discard,
          stderr: output.stderr,
          windowBytes: Math.min(request.limits.outputBytes + 1, 256 * 1024),
        },
      );
      commandStopped = true;
      exitCode = result.exitCode;
      policyDenied ||= result.resourceUsage?.descendantDenied === true;
      if (policyDenied) observation.fail("request_denied");
      outcome = policyDenied
        ? "policy_denied"
        : exitCode === 0
          ? "success"
          : "command_failed";
    } catch {
      outcome = output.overflowed
        ? "output_overflow"
        : timedOut
          ? "timeout"
          : "transport_failure";
    } finally {
      clearTimeout(timer);
      if (vm) {
        runnerPid ??= vm.getHostPid();
        try {
          await vm.close();
          closed = runnerPid === null || !isProcessAlive(runnerPid);
        } catch {
          closed = false;
        }
      }
      observation.finish();
    }
    commandStopped ||= closed;
    const snapshot = observation.snapshot();
    const rawDiagnostics = output.stderrText;
    const diagnostics = boundedUtf8(rawDiagnostics, request.limits.outputBytes);
    const diagnosticsOverflow =
      output.overflowed || discardOverflow || diagnostics !== rawDiagnostics;
    if (!closed) outcome = "teardown_failure";
    else if (diagnosticsOverflow) outcome = "output_overflow";
    else if (timedOut || snapshot.settlement === "timeout") outcome = "timeout";
    else if (
      policyDenied ||
      ["request_denied", "redirect_denied"].includes(snapshot.settlement)
    )
      outcome = "policy_denied";
    else if (
      snapshot.settlement !== "complete" ||
      !snapshot.response ||
      !snapshot.connection
    )
      outcome = "transport_failure";
    const settledAt = new Date().toISOString();
    const network = { ...snapshot, ...identity.authenticate() };
    const teardown = {
      ...identity.authenticate(),
      commandStopped,
      vmStopped: closed,
      vfsHandlesRevoked: closed,
      policyRemoved: closed,
      networkChannelsClosed: closed,
      ephemeralStateDestroyed: closed,
      completedAt: closed ? settledAt : null,
    };
    const result = {
      outcome,
      exitCode,
      stdout: "",
      stderr: diagnostics,
      outputTruncated: diagnosticsOverflow,
      response: outcome === "success" ? snapshot.response : null,
    };
    const featureManifestDigest = sha256(
      stableJson(getCapabilityInvocationFeatureManifest()),
    );
    const qualificationId = capabilityQualificationId({
      gondolinVersion: gondolinVersion(),
      capabilitySchemaVersion: HTTPS_REQUEST_SCHEMA_VERSION,
      evidenceSchemaVersion: HTTPS_EVIDENCE_SCHEMA_VERSION,
      featureManifestDigest,
      runtime,
      policyVersions: HTTPS_POLICY_VERSIONS,
    });
    identity.finish(closed ? "completed" : "revoked", closed);
    const evidence = sealCapabilityEvidence({
      schemaVersion: HTTPS_EVIDENCE_SCHEMA_VERSION,
      capabilitySchemaVersion: HTTPS_REQUEST_SCHEMA_VERSION,
      gondolinVersion: gondolinVersion(),
      decision: "admitted" as const,
      outcome,
      requestDigest: canonical.digest,
      ceilingDigest: this.ceilingDigest,
      executionId: identity.executionId,
      vmId,
      runtime,
      featureManifestDigest,
      qualificationId,
      policyVersions: HTTPS_POLICY_VERSIONS,
      request,
      network,
      filesystem: "none" as const,
      credentials: "none" as const,
      startedAt,
      settledAt,
      teardown,
      resultDigest: sha256(stableJson(result)),
    });
    return deepFreeze({ ...result, evidence });
  }
}

function assertTrustedEnvironment(): void {
  assertDefaultHttpsTrust();
  // Arbitrary Node startup instrumentation is not part of this narrow measured profile.
  if (process.env.NODE_OPTIONS)
    throw new TypeError("HTTPS runtime does not admit NODE_OPTIONS");
}

function boundedUtf8(value: string, maximum: number): string {
  if (Buffer.byteLength(value) <= maximum) return value;
  let bytes = 0,
    result = "";
  for (const character of value) {
    bytes += Buffer.byteLength(character);
    if (bytes > maximum) break;
    result += character;
  }
  return result;
}

/** Receipt consumers must pin trusted identity and expected request/runtime outside this result */
export function verifyHttpsInvocationResult(
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
      "response",
      "evidence",
    ]);
    const evidence = value.evidence as HttpsInvocationEvidence;
    const checked = verifySignedInvocationEvidence(evidence, options),
      errors = [...checked.errors];
    const expect = (valid: boolean, message: string) => {
      if (!valid) errors.push(message);
    };
    expect(
      Boolean(
        options.requestDigest &&
        options.ceilingDigest &&
        options.runtime &&
        options.qualificationId,
      ),
      "required expected bindings missing",
    );
    expect(
      evidence.schemaVersion === HTTPS_EVIDENCE_SCHEMA_VERSION &&
        evidence.capabilitySchemaVersion === HTTPS_REQUEST_SCHEMA_VERSION,
      "unsupported HTTPS evidence schema",
    );
    expect(
      evidence.gondolinVersion === gondolinVersion() &&
        evidence.decision === "admitted",
      "invalid HTTPS runtime admission",
    );
    expect(
      evidence.filesystem === "none" && evidence.credentials === "none",
      "HTTPS profile contains unmodeled authority",
    );
    expect(
      stableJson(evidence.policyVersions) === stableJson(HTTPS_POLICY_VERSIONS),
      "HTTPS policy substitution",
    );
    expect(
      evidence.featureManifestDigest ===
        sha256(stableJson(getCapabilityInvocationFeatureManifest())),
      "HTTPS manifest substitution",
    );
    expect(
      evidence.qualificationId ===
        capabilityQualificationId({
          gondolinVersion: evidence.gondolinVersion,
          capabilitySchemaVersion: HTTPS_REQUEST_SCHEMA_VERSION,
          evidenceSchemaVersion: HTTPS_EVIDENCE_SCHEMA_VERSION,
          featureManifestDigest: evidence.featureManifestDigest,
          runtime: evidence.runtime,
          policyVersions: evidence.policyVersions,
        }),
      "HTTPS qualification mismatch",
    );
    const canonical = canonicalizeHttpsInvocationRequest(evidence.request);
    expect(
      canonical.digest === evidence.requestDigest &&
        stableJson(canonical.request) === stableJson(evidence.request),
      "HTTPS request binding mismatch",
    );
    const { evidence: _evidence, ...result } = value;
    expect(
      evidence.resultDigest === sha256(stableJson(result)) &&
        evidence.outcome === value.outcome,
      "HTTPS public result substitution",
    );
    const outcomes = [
      "success",
      "policy_denied",
      "command_failed",
      "timeout",
      "output_overflow",
      "transport_failure",
      "host_controller_failure",
      "teardown_failure",
    ];
    expect(
      typeof value.outcome === "string" && outcomes.includes(value.outcome),
      "invalid HTTPS outcome",
    );
    expect(
      (value.exitCode === null || Number.isInteger(value.exitCode)) &&
        typeof value.stdout === "string" &&
        typeof value.stderr === "string" &&
        typeof value.outputTruncated === "boolean",
      "invalid HTTPS command diagnostics",
    );
    const network = evidence.network,
      request = canonical.request;
    expect(
      network.executionId === evidence.executionId &&
        network.sequence === 1 &&
        evidence.teardown.executionId === evidence.executionId &&
        evidence.teardown.sequence === 2,
      "HTTPS event identity or ordering mismatch",
    );
    expect(
      network.urlDigest === sha256(request.request.url) &&
        network.method === request.request.method &&
        network.maxResponseBytes === request.authority.maxResponseBytes &&
        network.timeoutMs === request.authority.timeoutMs,
      "HTTPS observation request mismatch",
    );
    expect(
      typeof network.requestId === "string" &&
        network.requestId.length > 0 &&
        Number.isSafeInteger(network.receivedBytes) &&
        network.receivedBytes >= 0 &&
        (network.elapsedMs === null ||
          (typeof network.elapsedMs === "number" &&
            Number.isFinite(network.elapsedMs) &&
            network.elapsedMs >= 0)) &&
        [
          "complete",
          "timeout",
          "overflow",
          "transport_failure",
          "redirect_denied",
          "request_denied",
        ].includes(network.settlement),
      "malformed HTTPS settlement observation",
    );
    expect(
      Array.isArray(network.resolutionCandidates) &&
        network.resolutionCandidates.every(
          (entry) =>
            entry &&
            typeof entry.address === "string" &&
            [4, 6].includes(entry.family) &&
            isPublicAddress(entry.address),
        ),
      "malformed HTTPS resolution observations",
    );
    if (network.connection !== null)
      expect(
        typeof network.connection.connectionId === "string" &&
          network.connection.connectionId.length > 0 &&
          network.connection.tlsVerified === true &&
          network.connection.tlsHostname === request.authority.host &&
          network.connection.peerPort === request.authority.port &&
          isPublicAddress(network.connection.peerAddress),
        "malformed HTTPS connected peer",
      );
    expect(
      value.stdout === "" &&
        typeof value.stderr === "string" &&
        Buffer.byteLength(value.stdout) + Buffer.byteLength(value.stderr) <=
          request.limits.outputBytes,
      "HTTPS diagnostics exceed output authority",
    );
    expect(
      (network.settlement === "complete") === (network.response !== null),
      "HTTPS complete settlement requires response provenance",
    );
    if (network.settlement !== "complete")
      expect(
        network.response === null,
        "failed mediation retained complete response",
      );
    if (network.response !== null) {
      const body = Buffer.from(network.response.bodyBase64, "base64");
      expect(
        network.settlement === "complete" &&
          network.connection !== null &&
          body.toString("base64") === network.response.bodyBase64 &&
          network.response.bodyBytes === body.length &&
          network.response.bodyDigest === sha256(body) &&
          body.length === network.receivedBytes &&
          body.length <= request.authority.maxResponseBytes &&
          Number.isInteger(network.response.status) &&
          network.response.status >= 200 &&
          network.response.status <= 599 &&
          ![301, 302, 303, 307, 308].includes(network.response.status) &&
          (!(
            request.request.method === "HEAD" ||
            [204, 205, 304].includes(network.response.status)
          ) ||
            body.length === 0) &&
          network.elapsedMs !== null &&
          network.elapsedMs < network.timeoutMs,
        "malformed completed HTTPS response",
      );
    }
    const gates = [
      evidence.teardown.commandStopped,
      evidence.teardown.vmStopped,
      evidence.teardown.vfsHandlesRevoked,
      evidence.teardown.policyRemoved,
      evidence.teardown.networkChannelsClosed,
      evidence.teardown.ephemeralStateDestroyed,
    ];
    const complete = gates.every((gate) => gate === true);
    expect(
      gates.every((gate) => typeof gate === "boolean") &&
        (value.outcome === "teardown_failure") === !complete,
      "HTTPS teardown outcome mismatch",
    );
    expect(
      complete
        ? evidence.teardown.completedAt === evidence.settledAt &&
            Number.isFinite(Date.parse(evidence.settledAt))
        : evidence.teardown.completedAt === null,
      "HTTPS settlement mismatch",
    );
    if (complete) {
      const allowed =
        value.outputTruncated === true
          ? ["output_overflow"]
          : network.settlement === "timeout"
            ? ["timeout"]
            : ["request_denied", "redirect_denied"].includes(network.settlement)
              ? ["policy_denied"]
              : network.settlement !== "complete"
                ? ["transport_failure"]
                : value.exitCode === 0
                  ? ["success"]
                  : value.exitCode === null
                    ? ["transport_failure"]
                    : ["command_failed"];
      expect(
        allowed.includes(String(value.outcome)),
        "HTTPS outcome conflicts with mediation settlement",
      );
    }
    if (value.outcome === "success") {
      expect(
        value.exitCode === 0 &&
          value.outputTruncated === false &&
          complete &&
          evidence.vmId !== "not-created",
        "HTTPS success without completed execution",
      );
      expect(
        network.settlement === "complete" &&
          Boolean(network.response && network.connection),
        "HTTPS response provenance missing",
      );
      const response = network.response!,
        connection = network.connection!;
      const bytes = Buffer.from(response.bodyBase64, "base64");
      expect(
        stableJson(value.response) === stableJson(response) &&
          bytes.toString("base64") === response.bodyBase64 &&
          response.bodyBytes === bytes.length &&
          response.bodyDigest === sha256(bytes) &&
          bytes.length <= request.authority.maxResponseBytes &&
          network.receivedBytes === bytes.length &&
          Number.isInteger(response.status) &&
          response.status >= 200 &&
          response.status <= 599,
        "HTTPS response status or byte binding mismatch",
      );
      expect(
        network.elapsedMs !== null &&
          network.elapsedMs >= 0 &&
          network.elapsedMs < network.timeoutMs &&
          connection.tlsVerified === true &&
          connection.tlsHostname === request.authority.host &&
          connection.peerPort === request.authority.port &&
          isPublicAddress(connection.peerAddress) &&
          Boolean(connection.connectionId),
        "HTTPS peer, TLS or deadline verification failed",
      );
      expect(
        request.request.method !== "HEAD" || bytes.length === 0,
        "HEAD response contains entity bytes",
      );
    } else
      expect(
        value.response === null,
        "failed HTTPS invocation exposed successful response",
      );
    return { ...checked, valid: errors.length === 0, errors };
  } catch {
    return {
      valid: false,
      errors: ["malformed HTTPS result"],
      payloadDigest: null,
      qualificationId: null,
    };
  }
}
