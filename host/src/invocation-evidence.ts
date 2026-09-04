import {
  createHash,
  generateKeyPairSync,
  randomUUID,
  sign,
  verify,
} from "node:crypto";

import { getAssetVersion } from "./assets.ts";

export const CAPABILITY_EVIDENCE_SCHEMA_VERSION =
  "gondolin.capability-evidence/v2" as const;
export const CAPABILITY_FEATURE_SCHEMA_VERSION =
  "gondolin.capability-features/v2" as const;
export const EXECUTION_IDENTITY_RETENTION_MS = 24 * 60 * 60 * 1000;

export type CapabilityEvidenceDecision = "admitted";

export type AuthenticatedEvidenceEvent = {
  /** Host execution identity authenticating this event */
  executionId: string;
  /** Strictly increasing host-authored sequence within the execution */
  sequence: number;
};

export type CapabilityEvidenceIntegrity = {
  /** Host evidence signature algorithm */
  algorithm: "Ed25519";
  /** SHA-256 identity of the host verifier key */
  signerKeyId: string;
  /** DER SPKI host verifier key encoded as base64 */
  publicKey: string;
  /** SHA-256 digest of the canonical evidence payload */
  payloadDigest: string;
  /** Ed25519 signature of the canonical evidence payload */
  signature: string;
};

export type CapabilityResultBinding = {
  /** SHA-256 digest of the canonical public command result */
  resultDigest: string;
};

export type CapabilityEvidenceVerificationOptions = {
  /** Expected canonical request digest */
  requestDigest?: string;
  /** Expected immutable ceiling digest */
  ceilingDigest?: string;
  /** Expected fresh host execution identity */
  executionId?: string;
  /** Expected disposable VM identity */
  vmId?: string;
  /** Expected exact runtime identity */
  runtime?: unknown;
  /** Expected exact policy version set */
  policyVersions?: unknown;
  /** Expected exact runtime and policy qualification identity */
  qualificationId?: string;
  /** Trusted host verifier key identity */
  signerKeyId?: string;
  /** Trusted DER SPKI host verifier key encoded as base64 */
  publicKey?: string;
};

export type CapabilityEvidenceVerification = {
  valid: boolean;
  errors: string[];
  payloadDigest: string | null;
  qualificationId: string | null;
};

type ExecutionStatus = "active" | "completed" | "revoked";
type ExecutionRecord = {
  status: ExecutionStatus;
  requestDigest: string;
  ceilingDigest: string;
  vmId: string | null;
  teardownVerified: boolean;
  createdAt: number;
  retainedUntil: number;
};

type ExecutionRegistry = Map<string, ExecutionRecord>;

const registryKey = Symbol.for("gondolin.capability-execution-registry/v1");
const globalWithRegistry = globalThis as typeof globalThis & {
  [registryKey]?: ExecutionRegistry;
};
const executionRegistry =
  globalWithRegistry[registryKey] ??
  (globalWithRegistry[registryKey] = new Map<string, ExecutionRecord>());

const signerKey = Symbol.for("gondolin.capability-evidence-signer/v1");
type Signer = {
  privateKey: ReturnType<typeof generateKeyPairSync>["privateKey"];
  publicKey: string;
  signerKeyId: string;
};
const globalWithSigner = globalThis as typeof globalThis & {
  [signerKey]?: Signer;
};

function createSigner(): Signer {
  const pair = generateKeyPairSync("ed25519");
  const publicKey = pair.publicKey
    .export({ type: "spki", format: "der" })
    .toString("base64");
  return {
    privateKey: pair.privateKey,
    publicKey,
    signerKeyId: sha256(Buffer.from(publicKey, "base64")),
  };
}

const signer =
  globalWithSigner[signerKey] ?? (globalWithSigner[signerKey] = createSigner());

/** Trusted verifier identity to pin outside an untrusted invocation result */
export function getCapabilityEvidenceVerifierIdentity(): {
  algorithm: "Ed25519";
  signerKeyId: string;
  publicKey: string;
} {
  return Object.freeze({
    algorithm: "Ed25519" as const,
    signerKeyId: signer.signerKeyId,
    publicKey: signer.publicKey,
  });
}

/** Host-only active execution identity used to authenticate evidence events */
export class AuthenticatedExecutionIdentity {
  readonly executionId: string;
  readonly requestDigest: string;
  readonly ceilingDigest: string;
  private sequence = 0;

  private constructor(requestDigest: string, ceilingDigest: string) {
    this.requestDigest = requestDigest;
    this.ceilingDigest = ceilingDigest;
    pruneExecutionRegistry();
    for (;;) {
      const candidate = randomUUID();
      if (executionRegistry.has(candidate)) continue;
      this.executionId = candidate;
      executionRegistry.set(candidate, {
        status: "active",
        requestDigest,
        ceilingDigest,
        vmId: null,
        teardownVerified: false,
        createdAt: Date.now(),
        retainedUntil: Number.POSITIVE_INFINITY,
      });
      break;
    }
  }

  static begin(
    requestDigest: string,
    ceilingDigest: string,
  ): AuthenticatedExecutionIdentity {
    return new AuthenticatedExecutionIdentity(requestDigest, ceilingDigest);
  }

  bindVm(vmId: string): void {
    const record = this.requireActive();
    if (record.vmId !== null && record.vmId !== vmId) {
      throw new Error("execution identity is already bound to another VM");
    }
    record.vmId = vmId;
  }

  authenticate(vmId?: string): AuthenticatedEvidenceEvent {
    const record = this.requireActive();
    if (vmId !== undefined && record.vmId !== vmId) {
      throw new Error("execution identity is not authenticated for this VM");
    }
    this.sequence += 1;
    return { executionId: this.executionId, sequence: this.sequence };
  }

  finish(
    status: Exclude<ExecutionStatus, "active">,
    teardownVerified = false,
  ): void {
    const record = this.requireActive();
    if (status === "completed" && !teardownVerified) {
      throw new Error("execution identity cannot complete before teardown");
    }
    record.status = status;
    record.teardownVerified = teardownVerified;
    record.retainedUntil = Date.now() + EXECUTION_IDENTITY_RETENTION_MS;
  }

  private requireActive(): ExecutionRecord {
    pruneExecutionRegistry();
    const record = executionRegistry.get(this.executionId);
    if (!record) throw new Error("stale execution identity");
    if (record.status !== "active") {
      throw new Error(`${record.status} execution identity`);
    }
    if (
      record.requestDigest !== this.requestDigest ||
      record.ceilingDigest !== this.ceilingDigest
    ) {
      throw new Error("execution identity binding mismatch");
    }
    return record;
  }
}

/** Independent process-local probe of retained host execution state */
export function probeCapabilityInvocationTeardown(
  executionId: string,
  expected: {
    requestDigest?: string;
    ceilingDigest?: string;
    vmId?: string;
  } = {},
): {
  found: boolean;
  active: boolean;
  completed: boolean;
  revoked: boolean;
  teardownVerified: boolean;
  bindingMatches: boolean;
} {
  pruneExecutionRegistry();
  const record = executionRegistry.get(executionId);
  if (!record) {
    return Object.freeze({
      found: false,
      active: false,
      completed: false,
      revoked: false,
      teardownVerified: false,
      bindingMatches: false,
    });
  }
  const bindingMatches =
    (expected.requestDigest === undefined ||
      expected.requestDigest === record.requestDigest) &&
    (expected.ceilingDigest === undefined ||
      expected.ceilingDigest === record.ceilingDigest) &&
    (expected.vmId === undefined || expected.vmId === record.vmId);
  return Object.freeze({
    found: true,
    active: record.status === "active",
    completed: record.status === "completed",
    revoked: record.status === "revoked",
    teardownVerified: record.teardownVerified,
    bindingMatches,
  });
}

export function capabilityQualificationId(input: {
  gondolinVersion: string;
  capabilitySchemaVersion: string;
  evidenceSchemaVersion: string;
  featureManifestDigest: string;
  runtime: unknown;
  policyVersions: unknown;
}): string {
  return sha256(stableJson(input));
}

export function sealCapabilityEvidence<T extends Record<string, unknown>>(
  evidence: T,
): T & { integrity: CapabilityEvidenceIntegrity } {
  const canonical = stableJson(evidence);
  const payloadDigest = sha256(canonical);
  const signature = sign(
    null,
    Buffer.from(canonical),
    signer.privateKey,
  ).toString("base64");
  return deepFreeze({
    ...evidence,
    integrity: {
      algorithm: "Ed25519" as const,
      signerKeyId: signer.signerKeyId,
      publicKey: signer.publicKey,
      payloadDigest,
      signature,
    },
  });
}

export function capabilityResultDigest(result: {
  outcome: string;
  exitCode: number | null;
  stdout: string;
  stderr: string;
  outputTruncated: boolean;
  error?: string;
}): string {
  return sha256(
    stableJson({
      outcome: result.outcome,
      exitCode: result.exitCode,
      stdoutDigest: sha256(result.stdout),
      stderrDigest: sha256(result.stderr),
      outputTruncated: result.outputTruncated,
      error: result.error ?? null,
    }),
  );
}

/** Verify signature, bindings, event attribution, consistency, and teardown */
export function verifyCapabilityInvocationEvidence(
  input: unknown,
  options: CapabilityEvidenceVerificationOptions = {},
): CapabilityEvidenceVerification {
  try {
    return verifyCapabilityInvocationEvidenceInternal(input, options);
  } catch {
    return {
      valid: false,
      errors: ["evidence verification failed closed on malformed input"],
      payloadDigest: null,
      qualificationId: null,
    };
  }
}

function verifyCapabilityInvocationEvidenceInternal(
  input: unknown,
  options: CapabilityEvidenceVerificationOptions,
): CapabilityEvidenceVerification {
  const errors: string[] = [];
  if (!isRecord(input)) {
    return {
      valid: false,
      errors: ["evidence must be an object"],
      payloadDigest: null,
      qualificationId: null,
    };
  }
  const integrity = input.integrity;
  if (!isRecord(integrity)) {
    return {
      valid: false,
      errors: ["evidence integrity metadata is missing"],
      payloadDigest: null,
      qualificationId: stringValue(input.qualificationId),
    };
  }
  const unsigned = { ...input };
  delete unsigned.integrity;
  let canonical = "";
  try {
    canonical = stableJson(unsigned);
  } catch {
    errors.push("evidence payload is not canonically serializable");
  }
  const payloadDigest = canonical ? sha256(canonical) : null;
  if (integrity.algorithm !== "Ed25519") {
    errors.push("unsupported evidence signature algorithm");
  }
  if (integrity.payloadDigest !== payloadDigest) {
    errors.push("evidence payload digest mismatch");
  }
  const publicKey = stringValue(integrity.publicKey);
  const signature = stringValue(integrity.signature);
  if (!publicKey || !signature || !canonical) {
    errors.push("evidence signature metadata is malformed");
  } else {
    try {
      const verified = verify(
        null,
        Buffer.from(canonical),
        { key: Buffer.from(publicKey, "base64"), type: "spki", format: "der" },
        Buffer.from(signature, "base64"),
      );
      if (!verified) errors.push("evidence signature verification failed");
    } catch {
      errors.push("evidence signature metadata is malformed");
    }
  }
  const computedSignerKeyId = publicKey
    ? sha256(Buffer.from(publicKey, "base64"))
    : null;
  if (integrity.signerKeyId !== computedSignerKeyId) {
    errors.push("evidence signer key identity mismatch");
  }
  expected(
    errors,
    "request digest",
    input.requestDigest,
    options.requestDigest,
  );
  expected(
    errors,
    "ceiling digest",
    input.ceilingDigest,
    options.ceilingDigest,
  );
  expected(
    errors,
    "execution identity",
    input.executionId,
    options.executionId,
  );
  expected(errors, "VM identity", input.vmId, options.vmId);
  expected(errors, "runtime identity", input.runtime, options.runtime);
  expected(
    errors,
    "policy versions",
    input.policyVersions,
    options.policyVersions,
  );
  expected(
    errors,
    "qualification identity",
    input.qualificationId,
    options.qualificationId,
  );
  expected(
    errors,
    "signer key identity",
    integrity.signerKeyId,
    options.signerKeyId ??
      (options.publicKey
        ? sha256(Buffer.from(options.publicKey, "base64"))
        : signer.signerKeyId),
  );
  expected(
    errors,
    "signer public key",
    publicKey,
    options.publicKey ?? signer.publicKey,
  );

  if (input.schemaVersion !== CAPABILITY_EVIDENCE_SCHEMA_VERSION) {
    errors.push("unsupported evidence schema version");
  }
  if (input.gondolinVersion !== gondolinVersion()) {
    errors.push("evidence Gondolin version does not match this verifier");
  }
  if (input.decision !== "admitted")
    errors.push("evidence decision is invalid");
  if (
    typeof input.outcome !== "string" ||
    !CAPABILITY_OUTCOMES.has(input.outcome)
  ) {
    errors.push("evidence outcome is invalid");
  }

  const computedQualification = qualificationForEvidence(input);
  if (input.qualificationId !== computedQualification) {
    errors.push("runtime and policy qualification identity mismatch");
  }
  verifyEffects(input, errors);
  verifyTeardown(input, errors);
  return {
    valid: errors.length === 0,
    errors,
    payloadDigest,
    qualificationId: stringValue(input.qualificationId),
  };
}

/** Verify a complete public invocation result and its signed result binding */
export function verifyCapabilityInvocationResult(
  input: unknown,
  options: CapabilityEvidenceVerificationOptions = {},
): CapabilityEvidenceVerification {
  try {
    return verifyCapabilityInvocationResultInternal(input, options);
  } catch {
    return {
      valid: false,
      errors: [
        "invocation result verification failed closed on malformed input",
      ],
      payloadDigest: null,
      qualificationId: null,
    };
  }
}

function verifyCapabilityInvocationResultInternal(
  input: unknown,
  options: CapabilityEvidenceVerificationOptions,
): CapabilityEvidenceVerification {
  if (!isRecord(input) || !isRecord(input.evidence)) {
    return {
      valid: false,
      errors: ["invocation result and evidence must be objects"],
      payloadDigest: null,
      qualificationId: null,
    };
  }
  const checked = verifyCapabilityInvocationEvidence(input.evidence, options);
  const errors = [...checked.errors];
  if (input.error !== undefined && typeof input.error !== "string") {
    errors.push("invocation result error is malformed");
  }
  if (
    typeof input.outcome !== "string" ||
    !(typeof input.exitCode === "number" || input.exitCode === null) ||
    typeof input.stdout !== "string" ||
    typeof input.stderr !== "string" ||
    typeof input.outputTruncated !== "boolean"
  ) {
    errors.push("invocation result fields are malformed");
  } else {
    const resultDigest = capabilityResultDigest({
      outcome: input.outcome,
      exitCode: input.exitCode,
      stdout: input.stdout,
      stderr: input.stderr,
      outputTruncated: input.outputTruncated,
      ...(typeof input.error === "string" ? { error: input.error } : {}),
    });
    if (input.evidence.resultDigest !== resultDigest) {
      errors.push("invocation result binding mismatch");
    }
    if (input.evidence.outcome !== input.outcome) {
      errors.push("evidence outcome does not match invocation result");
    }
    if (input.outcome === "success" && input.exitCode !== 0) {
      errors.push("successful invocation result has a non-zero exit code");
    }
    if (input.outcome === "success" && input.error !== undefined) {
      errors.push("successful invocation result contains an error");
    }
    if (input.outcome === "command_failed" && input.exitCode === 0) {
      errors.push("failed command result has a zero exit code");
    }
    if (
      input.evidence.resources !== undefined &&
      input.resourceAccounting === undefined
    ) {
      errors.push("resource accounting result is missing");
    }
    if (
      input.resourceAccounting !== undefined &&
      stableJson(input.resourceAccounting) !==
        stableJson(input.evidence.resources)
    ) {
      errors.push("resource accounting result binding mismatch");
    }
  }
  return { ...checked, valid: errors.length === 0, errors };
}

export function gondolinVersion(): string {
  return getAssetVersion().replace(/^v/, "");
}

function qualificationForEvidence(evidence: Record<string, unknown>): string {
  return capabilityQualificationId({
    gondolinVersion: String(evidence.gondolinVersion),
    capabilitySchemaVersion: String(evidence.capabilitySchemaVersion),
    evidenceSchemaVersion: String(evidence.schemaVersion),
    featureManifestDigest: String(evidence.featureManifestDigest),
    runtime: evidence.runtime,
    policyVersions: evidence.policyVersions,
  });
}

function verifyEffects(
  evidence: Record<string, unknown>,
  errors: string[],
): void {
  const executionId = evidence.executionId;
  const sequences = new Set<number>();
  const buckets = ["requested", "granted", "attempted", "denied", "observed"];
  for (const bucket of buckets) {
    const effects = evidence[bucket];
    if (!Array.isArray(effects)) {
      errors.push(`${bucket} effects are missing`);
      continue;
    }
    let previous = 0;
    for (const effect of effects) {
      if (!isRecord(effect)) {
        errors.push(`${bucket} effect is malformed`);
        continue;
      }
      if (effect.executionId !== executionId) {
        errors.push(
          `${bucket} effect has an unauthenticated execution identity`,
        );
      }
      if (effect.decision !== bucket) {
        errors.push(`${bucket} effect has an inconsistent decision`);
      }
      const sequence = effect.sequence;
      if (!Number.isSafeInteger(sequence) || Number(sequence) <= previous) {
        errors.push(`${bucket} effect sequence is invalid or reordered`);
      }
      previous = Number(sequence);
      if (sequences.has(Number(sequence))) {
        errors.push("duplicate evidence event sequence");
      }
      sequences.add(Number(sequence));
    }
  }
  const processEvents = evidence.processEvents;
  if (!Array.isArray(processEvents)) {
    errors.push("process and lifecycle events are missing or malformed");
  } else {
    let previous = 0;
    for (const event of processEvents) {
      if (!isRecord(event) || event.executionId !== executionId) {
        errors.push("process or lifecycle event is unauthenticated");
        continue;
      }
      const sequence = Number(event.sequence);
      if (!Number.isSafeInteger(sequence) || sequence <= previous) {
        errors.push(
          "process or lifecycle event sequence is invalid or reordered",
        );
      }
      previous = sequence;
      if (sequences.has(sequence))
        errors.push("duplicate evidence event sequence");
      sequences.add(sequence);
    }
  }
  const resources = evidence.resources;
  if (isRecord(resources)) {
    if (resources.executionId !== executionId) {
      errors.push(
        "resource accounting has an unauthenticated execution identity",
      );
    }
    const sequence = Number(resources.sequence);
    if (!Number.isSafeInteger(sequence) || sequences.has(sequence)) {
      errors.push(
        "resource accounting event sequence is invalid or duplicated",
      );
    }
    sequences.add(sequence);
  }
  if (
    isRecord(evidence.policyVersions) &&
    evidence.policyVersions.resources !== undefined &&
    !isRecord(resources)
  ) {
    errors.push("qualified resource accounting evidence is missing");
  }
  if (sequences.size === 0) {
    errors.push("authenticated evidence events are missing");
  }
  verifyEffectRelations(evidence, errors);
}

function verifyEffectRelations(
  evidence: Record<string, unknown>,
  errors: string[],
): void {
  const descriptors = (bucket: string): Set<string> =>
    new Set(
      (Array.isArray(evidence[bucket]) ? evidence[bucket] : [])
        .filter(isRecord)
        .map(effectDescriptor),
    );
  const requested = descriptors("requested");
  const attempted = descriptors("attempted");
  for (const descriptor of descriptors("granted")) {
    if (!requested.has(descriptor))
      errors.push("granted effect was not requested");
  }
  for (const descriptor of descriptors("denied")) {
    if (!attempted.has(descriptor)) {
      errors.push("denied effect has no matching attempt");
    }
  }
  const observed = Array.isArray(evidence.observed) ? evidence.observed : [];
  for (const effect of observed.filter(isRecord)) {
    if (
      effect.operation === "completion" ||
      effect.operation === "projection"
    ) {
      continue;
    }
    if (!attempted.has(effectDescriptor(effect))) {
      errors.push("observed effect has no matching attempt");
    }
  }
}

function effectDescriptor(effect: Record<string, unknown>): string {
  const copy = { ...effect };
  delete copy.executionId;
  delete copy.sequence;
  delete copy.decision;
  if (
    copy.domain === "credential" &&
    (copy.operation === "denial" ||
      copy.operation === "expiry" ||
      copy.operation === "revocation")
  ) {
    copy.operation = "use";
    delete copy.reason;
  }
  return stableJson(copy);
}

const CAPABILITY_OUTCOMES = new Set([
  "success",
  "policy_denied",
  "cancelled",
  "command_failed",
  "timeout",
  "output_overflow",
  "cpu_exhausted",
  "memory_exhausted",
  "pids_exhausted",
  "storage_exhausted",
  "guest_crash",
  "host_controller_failure",
  "transport_failure",
  "commit_failure",
  "teardown_failure",
]);

function verifyTeardown(
  evidence: Record<string, unknown>,
  errors: string[],
): void {
  if (!isRecord(evidence.teardown)) {
    errors.push("teardown evidence is missing");
    return;
  }
  const teardown = evidence.teardown;
  if (teardown.executionId !== evidence.executionId) {
    errors.push("teardown evidence has an unauthenticated execution identity");
  }
  const sequence = Number(teardown.sequence);
  const priorSequences = new Set<number>();
  for (const bucket of [
    "requested",
    "granted",
    "attempted",
    "denied",
    "observed",
    "processEvents",
  ]) {
    const events = evidence[bucket];
    if (!Array.isArray(events)) continue;
    for (const event of events) {
      if (isRecord(event)) priorSequences.add(Number(event.sequence));
    }
  }
  if (isRecord(evidence.resources)) {
    priorSequences.add(Number(evidence.resources.sequence));
  }
  if (!Number.isSafeInteger(sequence) || priorSequences.has(sequence)) {
    errors.push("teardown event sequence is invalid or duplicated");
  }
  const validPriorSequences = [...priorSequences].filter((candidate) =>
    Number.isSafeInteger(candidate),
  );
  if (
    Number.isSafeInteger(sequence) &&
    validPriorSequences.some((candidate) => candidate >= sequence)
  ) {
    errors.push("teardown event is not the final authenticated event");
  }
  if (Number.isSafeInteger(sequence) && sequence > 0) {
    const completeSequence = new Set([...validPriorSequences, sequence]);
    for (
      let expectedSequence = 1;
      expectedSequence <= sequence;
      expectedSequence += 1
    ) {
      if (!completeSequence.has(expectedSequence)) {
        errors.push("authenticated evidence event sequence is incomplete");
        break;
      }
    }
  }

  const requiredGates = [
    "commandStopped",
    "vmStopped",
    "vfsHandlesRevoked",
    "policyRemoved",
    "ephemeralStateDestroyed",
  ];
  const policyVersions = evidence.policyVersions;
  if (isRecord(policyVersions) && policyVersions.network !== undefined) {
    requiredGates.push("networkChannelsClosed");
  }
  if (isRecord(policyVersions) && policyVersions.credentials !== undefined) {
    requiredGates.push("credentialProjectionsRevoked");
  }
  if (isRecord(policyVersions) && policyVersions.resources !== undefined) {
    requiredGates.push(
      "processTreeEmpty",
      "transportClosed",
      "writableStateDestroyed",
      "resourceControllersRemoved",
    );
  }
  const teardownComplete = requiredGates.every(
    (gate) => teardown[gate] === true,
  );
  if (!teardownComplete && evidence.outcome !== "teardown_failure") {
    errors.push("incomplete teardown did not determine the final outcome");
  }
  if (teardownComplete && evidence.outcome === "teardown_failure") {
    errors.push("teardown failure outcome conflicts with completed teardown");
  }
  if (evidence.outcome === "success" && !teardownComplete) {
    for (const gate of requiredGates) {
      if (teardown[gate] !== true) {
        errors.push(`successful evidence has incomplete teardown: ${gate}`);
      }
    }
  }
  if (
    teardownComplete &&
    (typeof teardown.completedAt !== "string" ||
      teardown.completedAt !== evidence.settledAt)
  ) {
    errors.push("evidence settled before completed teardown");
  }
}

function expected(
  errors: string[],
  label: string,
  actual: unknown,
  wanted: unknown,
): void {
  if (wanted !== undefined && stableJson(actual) !== stableJson(wanted)) {
    errors.push(`${label} substitution detected`);
  }
}

function pruneExecutionRegistry(now = Date.now()): void {
  for (const [executionId, record] of executionRegistry) {
    if (
      record.status === "active" &&
      record.createdAt + EXECUTION_IDENTITY_RETENTION_MS <= now
    ) {
      record.status = "revoked";
      record.teardownVerified = false;
      record.retainedUntil = now + EXECUTION_IDENTITY_RETENTION_MS;
    } else if (record.status !== "active" && record.retainedUntil <= now) {
      executionRegistry.delete(executionId);
    }
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function stringValue(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

function stableJson(value: unknown): string {
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

function sha256(value: string | Buffer): string {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function deepFreeze<T>(value: T): T {
  if (value && typeof value === "object") {
    Object.freeze(value);
    for (const child of Object.values(value as Record<string, unknown>)) {
      deepFreeze(child);
    }
  }
  return value;
}

/** @internal */
export const __test = { executionRegistry, pruneExecutionRegistry };
