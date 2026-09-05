import { createHash } from "node:crypto";

import {
  CAPABILITY_EVIDENCE_SCHEMA_VERSION,
  CAPABILITY_INVOCATION_SCHEMA_VERSION,
  type CapabilityInvocationResult,
  type CapabilityInvocationFeatureManifest,
  type CapabilityInvocationEvidence,
} from "./capability-invocation.ts";
import {
  verifyCapabilityInvocationResult,
  type CapabilityEvidenceVerificationOptions,
} from "./invocation-evidence.ts";
import type {
  ScopedRunnerInvocationEvidence,
  ScopedRunnerInvocationResult,
} from "./scoped-runner.ts";

export const ADAPTIVESANDBOX_PIN_SCHEMA_VERSION =
  "gondolin.adaptivesandbox-conformance-pin/v1" as const;
export const ADAPTIVESANDBOX_MATRIX_SCHEMA_VERSION =
  "gondolin.adaptivesandbox-compatibility-matrix/v1" as const;
export const ADAPTIVESANDBOX_REPORT_SCHEMA_VERSION =
  "gondolin.adaptivesandbox-qualification-report/v1" as const;

export const REQUIRED_ADAPTIVESANDBOX_FIXTURE_CATEGORIES = [
  "exact-reader",
  "exact-writer",
  "scoped-runner",
  "environment",
  "process",
  "resource",
  "http-tls",
  "credential",
  "effect-evidence",
  "replay-resistance",
  "concurrency",
  "failure",
  "teardown",
  "controlled-execution",
  "dishonest-backend",
] as const;

export const QUALIFICATION_LATENCY_PHASES = [
  "coldBootMs",
  "invocationSetupMs",
  "policyInstallationMs",
  "executionMs",
  "observationMs",
  "verificationMs",
  "teardownMs",
] as const;

export type AdaptiveSandboxFixtureCategory =
  (typeof REQUIRED_ADAPTIVESANDBOX_FIXTURE_CATEGORIES)[number];
export type QualificationLatencyPhase =
  (typeof QUALIFICATION_LATENCY_PHASES)[number];
export type QualificationStatus = "verified" | "unverified" | "unsupported";
/** Validated lowercase SHA-256 identity */
export type Sha256Digest = `sha256:${string}`;

export type AdaptiveSandboxUnavailablePin = {
  /** Pin file schema identifier */
  schemaVersion: typeof ADAPTIVESANDBOX_PIN_SCHEMA_VERSION;
  /** Absence of a released integrity-pinned bundle */
  status: "unavailable";
  /** Exact expected upstream repository */
  repository: "naveed949/AdaptiveSandbox";
  /** Human-readable reason no qualification may run */
  reason: string;
};

export type AdaptiveSandboxReleasedPin = {
  /** Pin file schema identifier */
  schemaVersion: typeof ADAPTIVESANDBOX_PIN_SCHEMA_VERSION;
  /** Presence of a reviewed released bundle pin */
  status: "pinned";
  /** Exact expected upstream repository */
  repository: "naveed949/AdaptiveSandbox";
  /** Immutable GitHub release tag */
  releaseTag: string;
  /** AdaptiveSandbox conformance bundle version */
  bundleVersion: string;
  artifact: {
    /** Release asset URL, never a branch or latest URL */
    url: string;
    /** SHA-256 of the exact release asset bytes */
    sha256: Sha256Digest;
    /** Executable single-file bundle media type */
    mediaType: "text/javascript";
  };
  execution: {
    /** Pinned bundle runtime */
    runtime: "node";
    /** Arguments containing artifact, adapter, and report placeholders */
    arguments: string[];
  };
};

export type AdaptiveSandboxConformancePin =
  AdaptiveSandboxUnavailablePin | AdaptiveSandboxReleasedPin;

export type QemuQualificationIdentity = {
  /** QEMU version output normalized by the conformance bundle */
  version: string;
  /** SHA-256 of the QEMU executable */
  executableDigest: Sha256Digest;
};

export type AdaptiveSandboxQualificationIdentity = {
  /** Gondolin package version */
  gondolinVersion: string;
  /** Capability request schema identifier */
  capabilitySchemaVersion: string;
  /** Capability evidence schema identifier */
  evidenceSchemaVersion: string;
  /** Lowercase SHA-256 feature-manifest identity or unavailable sentinel */
  featureManifestDigest: Sha256Digest | null;
  /** Lowercase SHA-256 policy-version identity or unavailable sentinel */
  policyVersionsDigest: Sha256Digest | null;
  /** Exact AdaptiveSandbox bundle version or unavailable sentinel */
  adaptiveSandboxBundleVersion: string | null;
  /** Lowercase SHA-256 bundle identity or unavailable sentinel */
  adaptiveSandboxBundleDigest: Sha256Digest | null;
  /** Virtual machine monitor family */
  vmm: "qemu" | "krun";
  /** Exact QEMU runtime identity or non-QEMU/unavailable sentinel */
  qemu: QemuQualificationIdentity | null;
  /** Lowercase SHA-256 guest-image identity or unavailable sentinel */
  guestImageDigest: Sha256Digest | null;
  /** Lowercase SHA-256 guest-kernel identity or unavailable sentinel */
  guestKernelDigest: Sha256Digest | null;
  /** Qualification host operating system */
  hostPlatform: "linux" | "darwin" | "win32";
  /** Qualification host architecture */
  hostArchitecture: "x64" | "arm64";
  /** Portable Linux guest architecture */
  guestArchitecture: "x86_64" | "aarch64";
};

export type PercentileSummary = {
  /** Number of measured latency samples */
  samples: number;
  /** Nearest-rank p50 latency in `ms` or no-sample sentinel */
  p50: number | null;
  /** Nearest-rank p95 latency in `ms` or no-sample sentinel */
  p95: number | null;
};

export type WorkloadPerformanceSummary = {
  /** Number of measured workload invocations */
  samples: number;
  /** Per-phase latency distributions in `ms` */
  phases: Record<QualificationLatencyPhase, PercentileSummary>;
};

export type QualificationReportSummary = {
  /** Performance results keyed by public capability profile */
  workloads: Record<
    "exact-reader" | "exact-writer" | "scoped-runner",
    WorkloadPerformanceSummary
  >;
  /** Required fixture outcome counts */
  security: {
    /** Passing security fixture count */
    passed: number;
    /** Failing security fixture count */
    failed: number;
    /** Skipped security fixture count */
    skipped: number;
  };
  /** Allowed-fixture denial measurements */
  falseDenials: {
    /** Executed fixtures expected to be allowed */
    allowedFixtures: number;
    /** Allowed fixtures incorrectly denied */
    denied: number;
    /** Denied-to-allowed ratio or no-fixture sentinel */
    rate: number | null;
  };
};

export type AdaptiveSandboxCompatibilityRow = {
  /** Stable exact-combination row identifier */
  id: string;
  /** Exact runtime and policy qualification identity */
  identity: AdaptiveSandboxQualificationIdentity;
  /** Earned qualification state */
  status: QualificationStatus;
  /** Qualification status for issue #24 procedure-generated operations */
  procedureGeneratedOperations: QualificationStatus;
  /** Human-readable qualification-state explanation */
  reason: string;
  /** Key of the exact security, false-denial, and performance report */
  report: string;
};

export type AdaptiveSandboxCompatibilityMatrix = {
  /** Compatibility matrix schema identifier */
  schemaVersion: typeof ADAPTIVESANDBOX_MATRIX_SCHEMA_VERSION;
  /** Canonical UTC matrix generation timestamp */
  generatedAt: string;
  /** Authoritative PRD, ticket, and pin locations */
  source: {
    /** Parent product requirement */
    prd: "https://github.com/naveed949/gondolin/issues/1";
    /** Conformance qualification ticket */
    ticket: "https://github.com/naveed949/gondolin/issues/9";
    /** Repository-relative release-pin path */
    pin: "conformance/adaptivesandbox-bundle.pin.json";
  };
  /** Reusable security and performance reports keyed by identifier */
  reports: Record<string, QualificationReportSummary>;
  /** Exact runtime-combination compatibility claims */
  rows: AdaptiveSandboxCompatibilityRow[];
};

export type QualificationFixtureResult = {
  /** Unique fixture result identifier */
  id: string;
  /** Required conformance fixture category */
  category: AdaptiveSandboxFixtureCategory;
  /** Fixture execution outcome */
  status: "passed" | "failed" | "skipped";
  /** Principal which produced or executed the requested operation */
  producerPrincipal: string;
  /** Principal which independently verified the operation */
  verifierPrincipal: string;
  /** Lowercase SHA-256 canonical-request identity */
  requestDigest: Sha256Digest;
  /** Lowercase SHA-256 evidence-payload identity */
  evidencePayloadDigest: Sha256Digest;
  /** Fresh host execution identity */
  executionId: string;
  /** Fresh disposable-VM identity */
  vmId: string;
  /** Independent enforcement-domain observations */
  checks: {
    /** Canonical request agreement */
    canonicalRequest: boolean;
    /** Filesystem authority agreement */
    filesystem: boolean;
    /** Process authority agreement */
    process: boolean;
    /** Resource-boundary agreement */
    resource: boolean;
    /** Network authority agreement */
    network: boolean;
    /** Credential authority agreement */
    credential: boolean;
    /** Completed teardown agreement */
    teardown: boolean;
    /** Independent authority-overlap check for controlled execution only */
    disjointAuthority: boolean | null;
  };
};

export type AdaptiveSandboxQualificationReport = {
  /** Qualification report schema identifier */
  schemaVersion: typeof ADAPTIVESANDBOX_REPORT_SCHEMA_VERSION;
  /** Exact runtime and policy qualification identity */
  identity: AdaptiveSandboxQualificationIdentity;
  /** Overall earned qualification state */
  status: QualificationStatus;
  /** Per-fixture independent results */
  fixtures: QualificationFixtureResult[];
  /** Aggregate security and performance results */
  summary: QualificationReportSummary;
};

export type QualificationSample = {
  /** Public capability workload profile */
  profile: "exact-reader" | "exact-writer" | "scoped-runner";
  /** Policy-expected workload decision */
  expected: "allowed" | "denied";
  /** Backend-observed workload decision */
  observed: "allowed" | "denied";
  /** Independent security-check result */
  securityPassed: boolean;
  /** Explicit non-execution marker */
  skipped?: boolean;
  /** Per-phase latency measurements in `ms` */
  phases: Record<QualificationLatencyPhase, number>;
};

type VerifiableInvocationResult =
  CapabilityInvocationResult | ScopedRunnerInvocationResult;
type VerifiableInvocationEvidence =
  CapabilityInvocationEvidence | ScopedRunnerInvocationEvidence;

/** Parse and strictly validate the checked-in AdaptiveSandbox release pin */
export function parseAdaptiveSandboxConformancePin(
  input: unknown,
): AdaptiveSandboxConformancePin {
  const pin = object(input, "AdaptiveSandbox conformance pin");
  exactKeys(
    pin,
    pin.status === "pinned"
      ? [
          "schemaVersion",
          "status",
          "repository",
          "releaseTag",
          "bundleVersion",
          "artifact",
          "execution",
        ]
      : ["schemaVersion", "status", "repository", "reason"],
    "AdaptiveSandbox conformance pin",
  );
  requiredString(
    pin.schemaVersion,
    ADAPTIVESANDBOX_PIN_SCHEMA_VERSION,
    "pin schema version",
  );
  requiredString(pin.repository, "naveed949/AdaptiveSandbox", "pin repository");
  if (pin.status === "unavailable") {
    nonEmptyString(pin.reason, "unavailable pin reason");
    return input as AdaptiveSandboxUnavailablePin;
  }
  requiredString(pin.status, "pinned", "pin status");
  const releaseTag = nonEmptyString(pin.releaseTag, "release tag");
  const bundleVersion = nonEmptyString(pin.bundleVersion, "bundle version");
  if (releaseTag !== `v${bundleVersion}`) {
    invalid("release tag must exactly equal v<bundleVersion>");
  }
  if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(bundleVersion)) {
    invalid("bundle version must be an exact semantic version");
  }
  const artifact = object(pin.artifact, "pin artifact");
  exactKeys(artifact, ["url", "sha256", "mediaType"], "pin artifact");
  const artifactUrl = nonEmptyString(artifact.url, "artifact URL");
  let parsedArtifactUrl: URL;
  try {
    parsedArtifactUrl = new URL(artifactUrl);
  } catch {
    invalid("artifact URL must be an absolute URL");
  }
  const expectedPathPrefix =
    `/naveed949/AdaptiveSandbox/releases/download/` +
    `${encodeURIComponent(releaseTag)}/`;
  const assetName = parsedArtifactUrl.pathname.slice(expectedPathPrefix.length);
  if (
    parsedArtifactUrl.protocol !== "https:" ||
    parsedArtifactUrl.hostname !== "github.com" ||
    parsedArtifactUrl.port !== "" ||
    parsedArtifactUrl.username !== "" ||
    parsedArtifactUrl.password !== "" ||
    parsedArtifactUrl.search !== "" ||
    parsedArtifactUrl.hash !== "" ||
    !parsedArtifactUrl.pathname.startsWith(expectedPathPrefix) ||
    assetName.length === 0 ||
    assetName.includes("/")
  ) {
    invalid("artifact URL must name an exact asset beneath the pinned release");
  }
  digest(artifact.sha256, "artifact SHA-256");
  requiredString(artifact.mediaType, "text/javascript", "artifact media type");
  const execution = object(pin.execution, "pin execution");
  exactKeys(execution, ["runtime", "arguments"], "pin execution");
  requiredString(execution.runtime, "node", "bundle runtime");
  const args = stringArray(execution.arguments, "bundle arguments");
  for (const placeholder of ["{artifact}", "{adapter}", "{report}"]) {
    if (args.filter((argument) => argument === placeholder).length !== 1) {
      invalid(`bundle arguments must include ${placeholder} exactly once`);
    }
  }
  return input as AdaptiveSandboxReleasedPin;
}

/** Verify exact released bundle bytes against their reviewed integrity pin */
export function verifyAdaptiveSandboxBundle(
  bytes: Uint8Array,
  pinInput: unknown,
): AdaptiveSandboxReleasedPin {
  const pin = parseAdaptiveSandboxConformancePin(pinInput);
  if (pin.status !== "pinned") {
    invalid("no released AdaptiveSandbox conformance bundle is pinned");
  }
  const actual = sha256(bytes);
  if (actual !== pin.artifact.sha256) {
    invalid("AdaptiveSandbox conformance bundle integrity mismatch");
  }
  return pin;
}

/** Strictly validate all compatibility claims against the checked-in pin */
export function parseAdaptiveSandboxCompatibilityMatrix(
  input: unknown,
  pinInput: unknown,
): AdaptiveSandboxCompatibilityMatrix {
  const pin = parseAdaptiveSandboxConformancePin(pinInput);
  const matrix = object(input, "AdaptiveSandbox compatibility matrix");
  exactKeys(
    matrix,
    ["schemaVersion", "generatedAt", "source", "reports", "rows"],
    "AdaptiveSandbox compatibility matrix",
  );
  requiredString(
    matrix.schemaVersion,
    ADAPTIVESANDBOX_MATRIX_SCHEMA_VERSION,
    "matrix schema version",
  );
  isoTimestamp(matrix.generatedAt, "matrix generatedAt");
  const source = object(matrix.source, "matrix source");
  exactKeys(source, ["prd", "ticket", "pin"], "matrix source");
  requiredString(
    source.prd,
    "https://github.com/naveed949/gondolin/issues/1",
    "matrix PRD",
  );
  requiredString(
    source.ticket,
    "https://github.com/naveed949/gondolin/issues/9",
    "matrix ticket",
  );
  requiredString(
    source.pin,
    "conformance/adaptivesandbox-bundle.pin.json",
    "matrix pin",
  );
  const reports = object(matrix.reports, "matrix reports");
  if (Object.keys(reports).length === 0) {
    invalid("compatibility matrix must publish at least one report");
  }
  for (const [reportId, report] of Object.entries(reports)) {
    nonEmptyString(reportId, "matrix report id");
    validateReportSummary(report, `matrix report ${reportId}`);
  }
  if (!Array.isArray(matrix.rows) || matrix.rows.length === 0) {
    invalid("compatibility matrix must contain rows");
  }
  const ids = new Set<string>();
  const identities = new Set<string>();
  for (const [index, value] of matrix.rows.entries()) {
    validateCompatibilityRow(value, pin, index, ids, identities, reports);
  }
  return input as AdaptiveSandboxCompatibilityMatrix;
}

/** Validate a released bundle report before any row may become verified */
export function parseAdaptiveSandboxQualificationReport(
  input: unknown,
  pinInput: unknown,
): AdaptiveSandboxQualificationReport {
  const pin = parseAdaptiveSandboxConformancePin(pinInput);
  if (pin.status !== "pinned") {
    invalid("qualification reports require a released integrity-pinned bundle");
  }
  const report = object(input, "AdaptiveSandbox qualification report");
  exactKeys(
    report,
    ["schemaVersion", "identity", "status", "fixtures", "summary"],
    "AdaptiveSandbox qualification report",
  );
  requiredString(
    report.schemaVersion,
    ADAPTIVESANDBOX_REPORT_SCHEMA_VERSION,
    "qualification report schema version",
  );
  const identity = validateIdentity(report.identity, "report identity");
  if (
    identity.adaptiveSandboxBundleVersion !== pin.bundleVersion ||
    identity.adaptiveSandboxBundleDigest !== pin.artifact.sha256
  ) {
    invalid("qualification report does not match the pinned bundle identity");
  }
  const status = qualificationStatus(report.status, "report status");
  if (status === "verified") {
    requireExactVerifiedIdentity(identity);
  }
  if (!Array.isArray(report.fixtures)) {
    invalid("qualification report fixtures must be an array");
  }
  const categories = new Map<AdaptiveSandboxFixtureCategory, number>();
  const fixtureIds = new Set<string>();
  const executions = new Set<string>();
  const vms = new Set<string>();
  for (const [index, fixture] of report.fixtures.entries()) {
    const parsed = validateFixture(fixture, index);
    if (fixtureIds.has(parsed.id)) {
      invalid(`qualification report reused fixture id ${parsed.id}`);
    }
    fixtureIds.add(parsed.id);
    categories.set(parsed.category, (categories.get(parsed.category) ?? 0) + 1);
    if (status === "verified") {
      if (parsed.status !== "passed") {
        invalid(
          "verified qualification cannot contain failed or skipped fixtures",
        );
      }
      if (executions.has(parsed.executionId) || vms.has(parsed.vmId)) {
        invalid("verified qualification reused an execution or VM identity");
      }
      executions.add(parsed.executionId);
      vms.add(parsed.vmId);
    }
  }
  if (status === "verified") {
    for (const category of REQUIRED_ADAPTIVESANDBOX_FIXTURE_CATEGORIES) {
      if (!categories.has(category)) {
        invalid(`verified qualification is missing ${category} fixtures`);
      }
    }
  }
  const summary = validateReportSummary(report.summary, "report summary");
  const fixtureCounts = {
    passed: report.fixtures.filter(
      (fixture) => object(fixture, "fixture").status === "passed",
    ).length,
    failed: report.fixtures.filter(
      (fixture) => object(fixture, "fixture").status === "failed",
    ).length,
    skipped: report.fixtures.filter(
      (fixture) => object(fixture, "fixture").status === "skipped",
    ).length,
  };
  if (stableJson(summary.security) !== stableJson(fixtureCounts)) {
    invalid("qualification security summary does not match fixture outcomes");
  }
  if (
    status === "verified" &&
    (summary.security.failed !== 0 || summary.security.skipped !== 0)
  ) {
    invalid("verified qualification must have zero failures and zero skips");
  }
  if (
    status === "verified" &&
    (Object.values(summary.workloads).some(
      (workload) => workload.samples === 0,
    ) ||
      summary.falseDenials.allowedFixtures === 0 ||
      summary.falseDenials.denied !== 0)
  ) {
    invalid(
      "verified qualification requires measured representative workloads with zero false denials",
    );
  }
  return input as AdaptiveSandboxQualificationReport;
}

/** Verify one public-seam result against externally retained exact bindings */
export function verifyQualificationInvocation(
  result: VerifiableInvocationResult,
  options: CapabilityEvidenceVerificationOptions & {
    producerPrincipal: string;
    verifierPrincipal: string;
    independent: QualificationFixtureResult["checks"];
  },
): void {
  const producer = nonEmptyString(
    options.producerPrincipal,
    "producer principal",
  );
  const verifier = nonEmptyString(
    options.verifierPrincipal,
    "verifier principal",
  );
  if (producer === verifier) {
    invalid("producer and verifier principals must be distinct");
  }
  const independent = object(options.independent, "independent checks");
  const independentKeys = [
    "canonicalRequest",
    "filesystem",
    "process",
    "resource",
    "network",
    "credential",
    "teardown",
  ] as const;
  exactKeys(independent, [...independentKeys], "independent checks");
  if (independentKeys.some((key) => independent[key] !== true)) {
    invalid("independent observation did not confirm every required domain");
  }
  const verification = verifyCapabilityInvocationResult(result, options);
  if (!verification.valid) {
    invalid(
      `invocation evidence is invalid: ${verification.errors.join("; ")}`,
    );
  }
}

/** Link controlled producer and verifier runs without implementing plan policy */
export function verifyControlledExecutionLink(
  producer: VerifiableInvocationEvidence,
  verifier: VerifiableInvocationEvidence,
  principals: {
    producer: string;
    verifier: string;
    /** Result of the independent comparison of both declared authority sets */
    authorityOverlap: false;
  },
): void {
  exactKeys(
    object(principals, "controlled execution principals"),
    ["producer", "verifier", "authorityOverlap"],
    "controlled execution principals",
  );
  const producerPrincipal = nonEmptyString(
    principals.producer,
    "producer principal",
  );
  const verifierPrincipal = nonEmptyString(
    principals.verifier,
    "verifier principal",
  );
  if (producerPrincipal === verifierPrincipal) {
    invalid("controlled execution requires distinct principals");
  }
  if (principals.authorityOverlap !== false) {
    invalid("controlled execution requires disjoint declared authority");
  }
  if (
    producer.executionId === verifier.executionId ||
    producer.vmId === verifier.vmId
  ) {
    invalid(
      "controlled execution requires fresh one-shot execution boundaries",
    );
  }
  if (
    producer.teardown.completedAt === null ||
    verifier.teardown.completedAt === null ||
    !producer.teardown.vmStopped ||
    !verifier.teardown.vmStopped
  ) {
    invalid("controlled execution requires independently completed teardown");
  }
}

/** Aggregate phase latency, security outcomes, and false denials */
export function summarizeQualificationSamples(
  samples: readonly QualificationSample[],
): QualificationReportSummary {
  const profiles = ["exact-reader", "exact-writer", "scoped-runner"] as const;
  const workloads = Object.fromEntries(
    profiles.map((profile) => {
      const matching = samples.filter(
        (sample) => sample.profile === profile && sample.skipped !== true,
      );
      const phases = Object.fromEntries(
        QUALIFICATION_LATENCY_PHASES.map((phase) => [
          phase,
          percentiles(matching.map((sample) => sample.phases[phase])),
        ]),
      ) as Record<QualificationLatencyPhase, PercentileSummary>;
      return [profile, { samples: matching.length, phases }];
    }),
  ) as QualificationReportSummary["workloads"];
  const active = samples.filter((sample) => sample.skipped !== true);
  const allowed = active.filter((sample) => sample.expected === "allowed");
  const falseDenials = allowed.filter(
    (sample) => sample.observed === "denied",
  ).length;
  return {
    workloads,
    security: {
      passed: active.filter((sample) => sample.securityPassed).length,
      failed: active.filter((sample) => !sample.securityPassed).length,
      skipped: samples.length - active.length,
    },
    falseDenials: {
      allowedFixtures: allowed.length,
      denied: falseDenials,
      rate: allowed.length === 0 ? null : falseDenials / allowed.length,
    },
  };
}

/** Digest the exact feature manifest consumed by a qualification run */
export function capabilityFeatureManifestDigest(
  manifest: CapabilityInvocationFeatureManifest,
): Sha256Digest {
  return sha256(Buffer.from(stableJson(manifest)));
}

function validateCompatibilityRow(
  input: unknown,
  pin: AdaptiveSandboxConformancePin,
  index: number,
  ids: Set<string>,
  identities: Set<string>,
  reports: Record<string, unknown>,
): void {
  const row = object(input, `matrix row ${index}`);
  exactKeys(
    row,
    [
      "id",
      "identity",
      "status",
      "procedureGeneratedOperations",
      "reason",
      "report",
    ],
    `matrix row ${index}`,
  );
  const id = nonEmptyString(row.id, `matrix row ${index} id`);
  if (ids.has(id)) invalid(`duplicate matrix row id: ${id}`);
  ids.add(id);
  const identity = validateIdentity(
    row.identity,
    `matrix row ${index} identity`,
  );
  const identityKey = stableJson(identity);
  if (identities.has(identityKey)) invalid(`duplicate matrix identity: ${id}`);
  identities.add(identityKey);
  const status = qualificationStatus(row.status, `matrix row ${index} status`);
  const procedure = qualificationStatus(
    row.procedureGeneratedOperations,
    `matrix row ${index} procedure status`,
  );
  nonEmptyString(row.reason, `matrix row ${index} reason`);
  const reportId = nonEmptyString(row.report, `matrix row ${index} report`);
  if (!(reportId in reports)) {
    invalid(`matrix row ${index} references an unknown report`);
  }
  const report = validateReportSummary(
    reports[reportId],
    `matrix row ${index} report ${reportId}`,
  );
  if (pin.status === "unavailable" && status === "verified") {
    invalid("a matrix row cannot be verified without a pinned released bundle");
  }
  if (status === "verified") {
    requireExactVerifiedIdentity(identity);
    if (
      pin.status !== "pinned" ||
      identity.adaptiveSandboxBundleVersion !== pin.bundleVersion ||
      identity.adaptiveSandboxBundleDigest !== pin.artifact.sha256
    ) {
      invalid("verified matrix row does not match the pinned released bundle");
    }
    if (report.security.failed !== 0 || report.security.skipped !== 0) {
      invalid(
        "verified matrix row contains failures or skipped security fixtures",
      );
    }
    if (
      Object.values(report.workloads).some(
        (workload) => workload.samples === 0,
      ) ||
      report.falseDenials.allowedFixtures === 0 ||
      report.falseDenials.denied !== 0
    ) {
      invalid(
        "verified matrix row requires representative workloads with zero false denials",
      );
    }
  }
  if (
    (identity.vmm === "krun" || identity.hostPlatform === "win32") &&
    status === "verified"
  ) {
    invalid("libkrun and Windows combinations are not currently qualifiable");
  }
  if (procedure === "verified") {
    invalid(
      "procedure-generated operations remain unverified until issue #24 releases fixtures",
    );
  }
}

function validateIdentity(
  input: unknown,
  label: string,
): AdaptiveSandboxQualificationIdentity {
  const identity = object(input, label);
  exactKeys(
    identity,
    [
      "gondolinVersion",
      "capabilitySchemaVersion",
      "evidenceSchemaVersion",
      "featureManifestDigest",
      "policyVersionsDigest",
      "adaptiveSandboxBundleVersion",
      "adaptiveSandboxBundleDigest",
      "vmm",
      "qemu",
      "guestImageDigest",
      "guestKernelDigest",
      "hostPlatform",
      "hostArchitecture",
      "guestArchitecture",
    ],
    label,
  );
  nonEmptyString(identity.gondolinVersion, `${label} Gondolin version`);
  requiredString(
    identity.capabilitySchemaVersion,
    CAPABILITY_INVOCATION_SCHEMA_VERSION,
    `${label} capability schema`,
  );
  requiredString(
    identity.evidenceSchemaVersion,
    CAPABILITY_EVIDENCE_SCHEMA_VERSION,
    `${label} evidence schema`,
  );
  optionalDigest(
    identity.featureManifestDigest,
    `${label} feature manifest digest`,
  );
  optionalDigest(
    identity.policyVersionsDigest,
    `${label} policy versions digest`,
  );
  optionalNonEmptyString(
    identity.adaptiveSandboxBundleVersion,
    `${label} bundle version`,
  );
  optionalDigest(
    identity.adaptiveSandboxBundleDigest,
    `${label} bundle digest`,
  );
  if (identity.vmm !== "qemu" && identity.vmm !== "krun") {
    invalid(`${label} VMM is unsupported`);
  }
  if (identity.vmm === "qemu" && identity.qemu !== null) {
    const qemu = object(identity.qemu, `${label} QEMU identity`);
    exactKeys(qemu, ["version", "executableDigest"], `${label} QEMU identity`);
    nonEmptyString(qemu.version, `${label} QEMU version`);
    digest(qemu.executableDigest, `${label} QEMU executable digest`);
  } else if (identity.qemu !== null) {
    invalid(`${label} must not attach a QEMU identity to a non-QEMU row`);
  }
  optionalDigest(identity.guestImageDigest, `${label} guest image digest`);
  optionalDigest(identity.guestKernelDigest, `${label} guest kernel digest`);
  if (!["linux", "darwin", "win32"].includes(String(identity.hostPlatform))) {
    invalid(`${label} host platform is unsupported`);
  }
  if (!["x64", "arm64"].includes(String(identity.hostArchitecture))) {
    invalid(`${label} host architecture is unsupported`);
  }
  if (!["x86_64", "aarch64"].includes(String(identity.guestArchitecture))) {
    invalid(`${label} guest architecture is unsupported`);
  }
  return input as AdaptiveSandboxQualificationIdentity;
}

function requireExactVerifiedIdentity(
  identity: AdaptiveSandboxQualificationIdentity,
): void {
  if (
    identity.vmm !== "qemu" ||
    identity.qemu === null ||
    identity.featureManifestDigest === null ||
    identity.policyVersionsDigest === null ||
    identity.adaptiveSandboxBundleVersion === null ||
    identity.adaptiveSandboxBundleDigest === null ||
    identity.guestImageDigest === null ||
    identity.guestKernelDigest === null
  ) {
    invalid("verified qualification requires every exact runtime identity");
  }
}

function validateFixture(
  input: unknown,
  index: number,
): QualificationFixtureResult {
  const fixture = object(input, `fixture ${index}`);
  exactKeys(
    fixture,
    [
      "id",
      "category",
      "status",
      "producerPrincipal",
      "verifierPrincipal",
      "requestDigest",
      "evidencePayloadDigest",
      "executionId",
      "vmId",
      "checks",
    ],
    `fixture ${index}`,
  );
  nonEmptyString(fixture.id, `fixture ${index} id`);
  if (
    !REQUIRED_ADAPTIVESANDBOX_FIXTURE_CATEGORIES.includes(
      fixture.category as AdaptiveSandboxFixtureCategory,
    )
  ) {
    invalid(`fixture ${index} category is unknown`);
  }
  if (!["passed", "failed", "skipped"].includes(String(fixture.status))) {
    invalid(`fixture ${index} status is unknown`);
  }
  const producer = nonEmptyString(
    fixture.producerPrincipal,
    `fixture ${index} producer principal`,
  );
  const verifier = nonEmptyString(
    fixture.verifierPrincipal,
    `fixture ${index} verifier principal`,
  );
  if (producer === verifier) {
    invalid(`fixture ${index} collapsed producer and verifier principals`);
  }
  digest(fixture.requestDigest, `fixture ${index} request digest`);
  digest(fixture.evidencePayloadDigest, `fixture ${index} evidence digest`);
  nonEmptyString(fixture.executionId, `fixture ${index} execution id`);
  nonEmptyString(fixture.vmId, `fixture ${index} VM id`);
  const checks = object(fixture.checks, `fixture ${index} checks`);
  const checkKeys = [
    "canonicalRequest",
    "filesystem",
    "process",
    "resource",
    "network",
    "credential",
    "teardown",
    "disjointAuthority",
  ] as const;
  exactKeys(checks, [...checkKeys], `fixture ${index} checks`);
  for (const key of checkKeys.slice(0, -1)) {
    if (typeof checks[key] !== "boolean") {
      invalid(`fixture ${index} check ${key} must be boolean`);
    }
    if (fixture.status === "passed" && checks[key] !== true) {
      invalid(`passed fixture ${index} has an unconfirmed ${key} check`);
    }
  }
  if (fixture.category === "controlled-execution") {
    if (checks.disjointAuthority !== true) {
      invalid(
        `controlled-execution fixture ${index} must confirm disjoint authority`,
      );
    }
  } else if (checks.disjointAuthority !== null) {
    invalid(
      `fixture ${index} must not claim controlled-execution authority separation`,
    );
  }
  return input as QualificationFixtureResult;
}

function validateReportSummary(
  input: unknown,
  label: string,
): QualificationReportSummary {
  const summary = object(input, label);
  exactKeys(summary, ["workloads", "security", "falseDenials"], label);
  const workloads = object(summary.workloads, `${label} workloads`);
  exactKeys(
    workloads,
    ["exact-reader", "exact-writer", "scoped-runner"],
    `${label} workloads`,
  );
  for (const profile of [
    "exact-reader",
    "exact-writer",
    "scoped-runner",
  ] as const) {
    const workload = object(workloads[profile], `${label} ${profile}`);
    exactKeys(workload, ["samples", "phases"], `${label} ${profile}`);
    nonNegativeInteger(workload.samples, `${label} ${profile} samples`);
    const phases = object(workload.phases, `${label} ${profile} phases`);
    exactKeys(
      phases,
      [...QUALIFICATION_LATENCY_PHASES],
      `${label} ${profile} phases`,
    );
    for (const phase of QUALIFICATION_LATENCY_PHASES) {
      const result = object(phases[phase], `${label} ${profile} ${phase}`);
      exactKeys(
        result,
        ["samples", "p50", "p95"],
        `${label} ${profile} ${phase}`,
      );
      const count = nonNegativeInteger(
        result.samples,
        `${label} ${profile} ${phase} samples`,
      );
      optionalNonNegativeNumber(result.p50, `${label} ${profile} ${phase} p50`);
      optionalNonNegativeNumber(result.p95, `${label} ${profile} ${phase} p95`);
      if (
        (count === 0 && (result.p50 !== null || result.p95 !== null)) ||
        (count > 0 && (result.p50 === null || result.p95 === null))
      ) {
        invalid(
          `${label} ${profile} ${phase} percentile count is inconsistent`,
        );
      }
      if (
        typeof result.p50 === "number" &&
        typeof result.p95 === "number" &&
        result.p50 > result.p95
      ) {
        invalid(`${label} ${profile} ${phase} p50 exceeds p95`);
      }
      if (count !== workload.samples) {
        invalid(
          `${label} ${profile} ${phase} samples differ from workload samples`,
        );
      }
    }
  }
  const security = object(summary.security, `${label} security`);
  exactKeys(security, ["passed", "failed", "skipped"], `${label} security`);
  nonNegativeInteger(security.passed, `${label} passed security fixtures`);
  nonNegativeInteger(security.failed, `${label} failed security fixtures`);
  nonNegativeInteger(security.skipped, `${label} skipped security fixtures`);
  const falseDenials = object(summary.falseDenials, `${label} false denials`);
  exactKeys(
    falseDenials,
    ["allowedFixtures", "denied", "rate"],
    `${label} false denials`,
  );
  const allowed = nonNegativeInteger(
    falseDenials.allowedFixtures,
    `${label} allowed fixtures`,
  );
  const denied = nonNegativeInteger(
    falseDenials.denied,
    `${label} false denials`,
  );
  if (denied > allowed)
    invalid(`${label} false denials exceed allowed fixtures`);
  optionalRate(falseDenials.rate, `${label} false-denial rate`);
  const expectedRate = allowed === 0 ? null : denied / allowed;
  if (falseDenials.rate !== expectedRate) {
    invalid(`${label} false-denial rate is inconsistent`);
  }
  return input as QualificationReportSummary;
}

function percentiles(values: readonly number[]): PercentileSummary {
  for (const value of values) {
    if (!Number.isFinite(value) || value < 0) {
      invalid("qualification latency must be a finite non-negative number");
    }
  }
  if (values.length === 0) return { samples: 0, p50: null, p95: null };
  const sorted = [...values].sort((left, right) => left - right);
  const at = (quantile: number) =>
    sorted[Math.max(0, Math.ceil(quantile * sorted.length) - 1)]!;
  return { samples: sorted.length, p50: at(0.5), p95: at(0.95) };
}

function qualificationStatus(
  input: unknown,
  label: string,
): QualificationStatus {
  if (!["verified", "unverified", "unsupported"].includes(String(input))) {
    invalid(`${label} is unknown`);
  }
  return input as QualificationStatus;
}

function object(input: unknown, label: string): Record<string, unknown> {
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    invalid(`${label} must be an object`);
  }
  return input as Record<string, unknown>;
}

function exactKeys(
  input: Record<string, unknown>,
  expected: readonly string[],
  label: string,
): void {
  const actual = Object.keys(input).sort();
  const wanted = [...expected].sort();
  if (stableJson(actual) !== stableJson(wanted)) {
    invalid(`${label} has missing or unknown fields`);
  }
}

function nonEmptyString(input: unknown, label: string): string {
  if (typeof input !== "string" || input.length === 0) {
    invalid(`${label} must be a non-empty string`);
  }
  return input;
}

function optionalNonEmptyString(input: unknown, label: string): void {
  if (input !== null) nonEmptyString(input, label);
}

function requiredString(input: unknown, expected: string, label: string): void {
  if (input !== expected) invalid(`${label} is unsupported`);
}

function stringArray(input: unknown, label: string): string[] {
  if (
    !Array.isArray(input) ||
    input.some((value) => typeof value !== "string")
  ) {
    invalid(`${label} must be an array of strings`);
  }
  return input;
}

function digest(input: unknown, label: string): Sha256Digest {
  if (typeof input !== "string" || !/^sha256:[0-9a-f]{64}$/.test(input)) {
    invalid(`${label} must be a lowercase SHA-256 identity`);
  }
  return input as Sha256Digest;
}

function optionalDigest(input: unknown, label: string): void {
  if (input !== null) digest(input, label);
}

function isoTimestamp(input: unknown, label: string): void {
  const value = nonEmptyString(input, label);
  if (new Date(value).toISOString() !== value)
    invalid(`${label} must be canonical UTC`);
}

function nonNegativeInteger(input: unknown, label: string): number {
  if (!Number.isSafeInteger(input) || Number(input) < 0) {
    invalid(`${label} must be a non-negative integer`);
  }
  return Number(input);
}

function optionalNonNegativeNumber(input: unknown, label: string): void {
  if (
    input !== null &&
    (typeof input !== "number" || !Number.isFinite(input) || input < 0)
  ) {
    invalid(`${label} must be null or a finite non-negative number`);
  }
}

function optionalRate(input: unknown, label: string): void {
  if (input !== null && (typeof input !== "number" || input < 0 || input > 1)) {
    invalid(`${label} must be null or between zero and one`);
  }
}

function sha256(bytes: Uint8Array): Sha256Digest {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

function stableJson(input: unknown): string {
  if (input === null || typeof input !== "object") return JSON.stringify(input);
  if (Array.isArray(input)) return `[${input.map(stableJson).join(",")}]`;
  const record = input as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`)
    .join(",")}}`;
}

function invalid(message: string): never {
  throw new Error(`AdaptiveSandbox conformance rejected: ${message}`);
}
