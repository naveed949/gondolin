import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

import {
  ADAPTIVESANDBOX_MATRIX_SCHEMA_VERSION,
  ADAPTIVESANDBOX_PIN_SCHEMA_VERSION,
  ADAPTIVESANDBOX_REPORT_SCHEMA_VERSION,
  CAPABILITY_EVIDENCE_SCHEMA_VERSION,
  CAPABILITY_INVOCATION_SCHEMA_VERSION,
  QUALIFICATION_LATENCY_PHASES,
  REQUIRED_ADAPTIVESANDBOX_FIXTURE_CATEGORIES,
  parseAdaptiveSandboxCompatibilityMatrix,
  parseAdaptiveSandboxConformancePin,
  parseAdaptiveSandboxQualificationReport,
  summarizeQualificationSamples,
  verifyAdaptiveSandboxBundle,
  verifyControlledExecutionLink,
  type AdaptiveSandboxCompatibilityMatrix,
  type AdaptiveSandboxConformancePin,
  type AdaptiveSandboxQualificationReport,
  type QualificationSample,
} from "../src/index.ts";

const root = path.resolve(import.meta.dirname, "../..");
const checkedPin = JSON.parse(
  fs.readFileSync(
    path.join(root, "conformance/adaptivesandbox-bundle.pin.json"),
    "utf8",
  ),
);
const checkedMatrix = JSON.parse(
  fs.readFileSync(
    path.join(root, "conformance/compatibility-matrix.json"),
    "utf8",
  ),
);

function digest(input: string): string {
  return `sha256:${createHash("sha256").update(input).digest("hex")}`;
}

function pinned(bytes = Buffer.from("released bundle")) {
  return {
    schemaVersion: ADAPTIVESANDBOX_PIN_SCHEMA_VERSION,
    status: "pinned",
    repository: "naveed949/AdaptiveSandbox",
    releaseTag: "v1.2.3",
    bundleVersion: "1.2.3",
    artifact: {
      url: "https://github.com/naveed949/AdaptiveSandbox/releases/download/v1.2.3/conformance.mjs",
      sha256: digest(bytes.toString()),
      mediaType: "text/javascript",
    },
    execution: {
      runtime: "node",
      arguments: [
        "{artifact}",
        "--adapter",
        "{adapter}",
        "--report",
        "{report}",
      ],
    },
  } satisfies AdaptiveSandboxConformancePin;
}

function verifiedReport(pin = pinned()): AdaptiveSandboxQualificationReport {
  const phases = Object.fromEntries(
    QUALIFICATION_LATENCY_PHASES.map((phase, index) => [phase, index + 1]),
  ) as QualificationSample["phases"];
  const summary = summarizeQualificationSamples(
    (["exact-reader", "exact-writer", "scoped-runner"] as const).map(
      (profile) => ({
        profile,
        expected: "allowed" as const,
        observed: "allowed" as const,
        securityPassed: true,
        phases,
      }),
    ),
  );
  return {
    schemaVersion: ADAPTIVESANDBOX_REPORT_SCHEMA_VERSION,
    identity: {
      gondolinVersion: "0.12.0",
      capabilitySchemaVersion: CAPABILITY_INVOCATION_SCHEMA_VERSION,
      evidenceSchemaVersion: CAPABILITY_EVIDENCE_SCHEMA_VERSION,
      featureManifestDigest: digest("features"),
      policyVersionsDigest: digest("policies"),
      adaptiveSandboxBundleVersion: pin.bundleVersion,
      adaptiveSandboxBundleDigest: pin.artifact.sha256,
      vmm: "qemu",
      qemu: {
        version: "QEMU emulator version 10.1.0",
        executableDigest: digest("qemu-system-x86_64"),
      },
      guestImageDigest: digest("image"),
      guestKernelDigest: digest("kernel"),
      hostPlatform: "linux",
      hostArchitecture: "x64",
      guestArchitecture: "x86_64",
    },
    status: "verified",
    fixtures: REQUIRED_ADAPTIVESANDBOX_FIXTURE_CATEGORIES.map(
      (category, index) => ({
        id: `${category}-fixture`,
        category,
        status: "passed",
        producerPrincipal: `producer/${category}`,
        verifierPrincipal: `verifier/${category}`,
        requestDigest: digest(`request-${category}`),
        evidencePayloadDigest: digest(`evidence-${category}`),
        executionId: `execution-${index}`,
        vmId: `vm-${index}`,
        checks: {
          canonicalRequest: true,
          filesystem: true,
          process: true,
          resource: true,
          network: true,
          credential: true,
          teardown: true,
          disjointAuthority: category === "controlled-execution" ? true : null,
        },
      }),
    ),
    summary: {
      ...summary,
      security: {
        passed: REQUIRED_ADAPTIVESANDBOX_FIXTURE_CATEGORIES.length,
        failed: 0,
        skipped: 0,
      },
    },
  };
}

test("checked pin and machine-readable matrix are fail-closed", () => {
  const pin = parseAdaptiveSandboxConformancePin(checkedPin);
  assert.equal(pin.status, "unavailable");
  const matrix = parseAdaptiveSandboxCompatibilityMatrix(checkedMatrix, pin);
  assert.equal(matrix.schemaVersion, ADAPTIVESANDBOX_MATRIX_SCHEMA_VERSION);
  assert.equal(
    matrix.rows.some((row) => row.status === "verified"),
    false,
  );
  assert.equal(
    matrix.rows.find((row) => row.identity.hostPlatform === "win32")?.status,
    "unsupported",
  );
  assert.equal(
    matrix.rows
      .filter((row) => row.identity.vmm === "krun")
      .every((row) => row.status === "unverified"),
    true,
  );
  assert.equal(
    matrix.rows.every(
      (row) => row.procedureGeneratedOperations === "unverified",
    ),
    true,
  );
});

test("release pins reject floating, latest, malformed, and changed artifacts", () => {
  const bytes = Buffer.from("released bundle");
  assert.equal(verifyAdaptiveSandboxBundle(bytes, pinned()).status, "pinned");
  assert.throws(
    () => verifyAdaptiveSandboxBundle(Buffer.from("substituted"), pinned()),
    /integrity mismatch/,
  );
  assert.throws(
    () =>
      parseAdaptiveSandboxConformancePin({
        ...pinned(),
        artifact: {
          ...pinned().artifact,
          url: "https://github.com/naveed949/AdaptiveSandbox/releases/latest/download/conformance.mjs",
        },
      }),
    /exact asset beneath the pinned release/,
  );
  assert.throws(
    () => verifyAdaptiveSandboxBundle(bytes, checkedPin),
    /no released AdaptiveSandbox conformance bundle is pinned/,
  );
});

test("verified reports require every category, exact identities, and no skips", () => {
  const pin = pinned();
  assert.equal(
    parseAdaptiveSandboxQualificationReport(verifiedReport(pin), pin).status,
    "verified",
  );

  const missing = structuredClone(verifiedReport(pin));
  missing.fixtures.pop();
  assert.throws(
    () => parseAdaptiveSandboxQualificationReport(missing, pin),
    /missing dishonest-backend fixtures/,
  );

  const skipped = structuredClone(verifiedReport(pin));
  skipped.fixtures[0]!.status = "skipped";
  assert.throws(
    () => parseAdaptiveSandboxQualificationReport(skipped, pin),
    /failed or skipped fixtures/,
  );

  const unknownSchema = structuredClone(verifiedReport(pin));
  unknownSchema.identity.capabilitySchemaVersion =
    "adaptivesandbox.capability/future";
  assert.throws(
    () => parseAdaptiveSandboxQualificationReport(unknownSchema, pin),
    /capability schema is unsupported/,
  );

  const falseDenial = structuredClone(verifiedReport(pin));
  falseDenial.summary.falseDenials = {
    allowedFixtures: 1,
    denied: 1,
    rate: 1,
  };
  assert.throws(
    () => parseAdaptiveSandboxQualificationReport(falseDenial, pin),
    /zero false denials/,
  );
});

test("dishonest backend reports fail on widening, forged effects, reuse, substitution, and premature teardown", () => {
  const pin = pinned();
  const mutations: Array<{
    change: (report: AdaptiveSandboxQualificationReport) => void;
    expected: RegExp;
  }> = [
    {
      change: (report) => {
        report.fixtures[0]!.checks.canonicalRequest = false;
      },
      expected: /unconfirmed canonicalRequest/,
    },
    {
      change: (report) => {
        report.fixtures[0]!.checks.filesystem = false;
      },
      expected: /unconfirmed filesystem/,
    },
    {
      change: (report) => {
        report.fixtures[1]!.executionId = report.fixtures[0]!.executionId;
      },
      expected: /reused an execution or VM identity/,
    },
    {
      change: (report) => {
        report.identity.adaptiveSandboxBundleDigest = digest("stale bundle");
      },
      expected: /does not match the pinned bundle identity/,
    },
    {
      change: (report) => {
        report.fixtures[0]!.checks.teardown = false;
      },
      expected: /unconfirmed teardown/,
    },
    {
      change: (report) => {
        report.fixtures[0]!.verifierPrincipal =
          report.fixtures[0]!.producerPrincipal;
      },
      expected: /collapsed producer and verifier principals/,
    },
  ];
  for (const mutation of mutations) {
    const report = structuredClone(verifiedReport(pin));
    mutation.change(report);
    assert.throws(
      () => parseAdaptiveSandboxQualificationReport(report, pin),
      mutation.expected,
    );
  }
});

test("matrix cannot turn absent or unsupported qualifications into claims", () => {
  const claimed = structuredClone(
    checkedMatrix,
  ) as AdaptiveSandboxCompatibilityMatrix;
  claimed.rows[0]!.status = "verified";
  assert.throws(
    () => parseAdaptiveSandboxCompatibilityMatrix(claimed, checkedPin),
    /cannot be verified without a pinned released bundle/,
  );

  const procedure = structuredClone(
    checkedMatrix,
  ) as AdaptiveSandboxCompatibilityMatrix;
  procedure.rows[0]!.procedureGeneratedOperations = "verified";
  assert.throws(
    () => parseAdaptiveSandboxCompatibilityMatrix(procedure, checkedPin),
    /procedure-generated operations remain unverified/,
  );
});

test("performance reports publish separate p50/p95 phases and false denials", () => {
  const phases = (base: number) =>
    Object.fromEntries(
      QUALIFICATION_LATENCY_PHASES.map((phase, index) => [phase, base + index]),
    ) as QualificationSample["phases"];
  const summary = summarizeQualificationSamples([
    {
      profile: "exact-reader",
      expected: "allowed",
      observed: "allowed",
      securityPassed: true,
      phases: phases(1),
    },
    {
      profile: "exact-reader",
      expected: "allowed",
      observed: "denied",
      securityPassed: false,
      phases: phases(10),
    },
    {
      profile: "exact-writer",
      expected: "denied",
      observed: "denied",
      securityPassed: true,
      phases: phases(20),
    },
    {
      profile: "scoped-runner",
      expected: "allowed",
      observed: "allowed",
      securityPassed: true,
      skipped: true,
      phases: phases(30),
    },
  ]);
  assert.deepEqual(summary.workloads["exact-reader"].phases.coldBootMs, {
    samples: 2,
    p50: 1,
    p95: 10,
  });
  assert.deepEqual(summary.security, { passed: 2, failed: 1, skipped: 1 });
  assert.deepEqual(summary.falseDenials, {
    allowedFixtures: 2,
    denied: 1,
    rate: 0.5,
  });
});

test("controlled execution links distinct principals and fresh sandboxes only", () => {
  const evidence = (executionId: string, vmId: string) =>
    ({
      executionId,
      vmId,
      teardown: {
        vmStopped: true,
        completedAt: "2026-09-04T00:00:00.000Z",
      },
    }) as never;
  assert.doesNotThrow(() =>
    verifyControlledExecutionLink(
      evidence("producer-execution", "producer-vm"),
      evidence("verifier-execution", "verifier-vm"),
      {
        producer: "plan-producer",
        verifier: "independent-verifier",
        authorityOverlap: false,
      },
    ),
  );
  assert.throws(
    () =>
      verifyControlledExecutionLink(
        evidence("same", "producer-vm"),
        evidence("same", "verifier-vm"),
        {
          producer: "plan-producer",
          verifier: "independent-verifier",
          authorityOverlap: false,
        },
      ),
    /fresh one-shot execution boundaries/,
  );
  assert.throws(
    () =>
      verifyControlledExecutionLink(
        evidence("producer-execution", "producer-vm"),
        evidence("verifier-execution", "verifier-vm"),
        {
          producer: "same-principal",
          verifier: "same-principal",
          authorityOverlap: false,
        },
      ),
    /distinct principals/,
  );
  assert.throws(
    () =>
      verifyControlledExecutionLink(
        evidence("producer-execution", "producer-vm"),
        evidence("verifier-execution", "verifier-vm"),
        {
          producer: "plan-producer",
          verifier: "independent-verifier",
          authorityOverlap: true,
        } as never,
      ),
    /disjoint declared authority/,
  );
});
