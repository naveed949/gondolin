import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";

import {
  CAPABILITY_EVIDENCE_SCHEMA_VERSION,
  CAPABILITY_FEATURE_SCHEMA_VERSION,
  CAPABILITY_INVOCATION_SCHEMA_VERSION,
  EXECUTION_IDENTITY_RETENTION_MS,
  getCapabilityEvidenceVerifierIdentity,
  getCapabilityInvocationFeatureManifest,
  probeCapabilityInvocationTeardown,
  verifyCapabilityInvocationEvidence,
  verifyCapabilityInvocationResult,
} from "../src/index.ts";
import {
  __test,
  AuthenticatedExecutionIdentity,
  capabilityQualificationId,
  capabilityResultDigest,
  gondolinVersion,
  sealCapabilityEvidence,
} from "../src/invocation-evidence.ts";

const requestDigest = `sha256:${"1".repeat(64)}`;
const ceilingDigest = `sha256:${"2".repeat(64)}`;
const vmId = "vm-evidence-fixture";
const runtime = {
  vmm: "qemu" as const,
  hostPlatform: process.platform,
  hostArchitecture: process.arch,
  guestArchitecture: "x86_64",
  imageDigest: `sha256:${"3".repeat(64)}`,
  guestKernelDigest: `sha256:${"4".repeat(64)}`,
  guestControlDigest: `sha256:${"5".repeat(64)}`,
  guestFeatures: ["exec.clear-env/v1"],
};
const policyVersions = {
  admission: "exact-reader/v1" as const,
  filesystem: "snapshot-vfs/v1" as const,
  lifecycle: "one-shot-qemu/v1" as const,
};

function fixture() {
  const identity = AuthenticatedExecutionIdentity.begin(
    requestDigest,
    ceilingDigest,
  );
  identity.bindVm(vmId);
  const requested = [
    {
      ...identity.authenticate(vmId),
      domain: "filesystem" as const,
      operation: "read" as const,
      resourceId: `sha256:${"6".repeat(64)}`,
      guestPath: "/data/input.txt",
      decision: "requested" as const,
    },
  ];
  const granted = [
    {
      ...requested[0],
      ...identity.authenticate(vmId),
      decision: "granted" as const,
    },
  ];
  const attempted = [
    {
      ...requested[0],
      ...identity.authenticate(vmId),
      decision: "attempted" as const,
    },
  ];
  const observed = [
    {
      ...requested[0],
      ...identity.authenticate(vmId),
      decision: "observed" as const,
    },
  ];
  const processEvents = [
    {
      ...identity.authenticate(vmId),
      domain: "process" as const,
      kind: "start" as const,
      detail: "entrypoint launch dispatched",
      observedAt: "2026-09-04T00:00:00.000Z",
    },
    {
      ...identity.authenticate(vmId),
      domain: "lifecycle" as const,
      kind: "teardown" as const,
      detail: "disposable VM stopped",
      observedAt: "2026-09-04T00:00:01.000Z",
    },
  ];
  const teardown = {
    ...identity.authenticate(vmId),
    commandStopped: true,
    vmStopped: true,
    vfsHandlesRevoked: true,
    policyRemoved: true,
    ephemeralStateDestroyed: true,
    completedAt: "2026-09-04T00:00:01.000Z",
  };
  const result = {
    outcome: "success" as const,
    exitCode: 0,
    stdout: "fixture\n",
    stderr: "",
    outputTruncated: false,
  };
  const featureManifestDigest = sha256(
    stableJson(getCapabilityInvocationFeatureManifest()),
  );
  const qualificationId = capabilityQualificationId({
    gondolinVersion: gondolinVersion(),
    capabilitySchemaVersion: CAPABILITY_INVOCATION_SCHEMA_VERSION,
    evidenceSchemaVersion: CAPABILITY_EVIDENCE_SCHEMA_VERSION,
    featureManifestDigest,
    runtime,
    policyVersions,
  });
  identity.finish("completed", true);
  const evidence = sealCapabilityEvidence({
    schemaVersion: CAPABILITY_EVIDENCE_SCHEMA_VERSION,
    capabilitySchemaVersion: CAPABILITY_INVOCATION_SCHEMA_VERSION,
    gondolinVersion: gondolinVersion(),
    decision: "admitted" as const,
    outcome: result.outcome,
    requestDigest,
    ceilingDigest,
    executionId: identity.executionId,
    vmId,
    runtime,
    featureManifestDigest,
    qualificationId,
    policyVersions,
    inputDigest: `sha256:${"7".repeat(64)}`,
    outputDigest: `sha256:${"7".repeat(64)}`,
    requested,
    granted,
    attempted,
    denied: [],
    observed,
    processEvents,
    startedAt: "2026-09-04T00:00:00.000Z",
    settledAt: "2026-09-04T00:00:01.000Z",
    teardown,
    resultDigest: capabilityResultDigest(result),
  });
  return { ...result, evidence };
}

test("feature manifest versions and advertises authenticated evidence", () => {
  const manifest = getCapabilityInvocationFeatureManifest();
  assert.equal(manifest.schemaVersion, CAPABILITY_FEATURE_SCHEMA_VERSION);
  assert.equal(
    manifest.evidenceSchemas[CAPABILITY_EVIDENCE_SCHEMA_VERSION],
    "active",
  );
  assert.equal(
    manifest.guarantees["authenticated-execution-identity"],
    "active",
  );
  assert.equal(manifest.guarantees["concurrent-disjoint-authority"], "active");
  assert.equal(manifest.guarantees["tamper-evident-evidence"], "active");
  assert.equal(
    manifest.guarantees["independent-evidence-verification"],
    "active",
  );
});

test("public verifier validates exact bindings and an independent teardown probe", () => {
  const result = fixture();
  const verifier = getCapabilityEvidenceVerifierIdentity();
  const verified = verifyCapabilityInvocationResult(result, {
    requestDigest,
    ceilingDigest,
    executionId: result.evidence.executionId,
    vmId,
    runtime,
    policyVersions,
    qualificationId: result.evidence.qualificationId,
    signerKeyId: verifier.signerKeyId,
    publicKey: verifier.publicKey,
  });
  assert.deepEqual(verified.errors, []);
  assert.equal(verified.valid, true);

  assert.deepEqual(
    probeCapabilityInvocationTeardown(result.evidence.executionId, {
      requestDigest,
      ceilingDigest,
      vmId,
    }),
    {
      found: true,
      active: false,
      completed: true,
      revoked: false,
      teardownVerified: true,
      bindingMatches: true,
    },
  );
  assert.equal(
    probeCapabilityInvocationTeardown(result.evidence.executionId, {
      vmId: "substituted-vm",
    }).bindingMatches,
    false,
  );
});

test("tampering, truncation, omission, duplication, reordering, and substitution fail", () => {
  const first = fixture();
  const second = fixture();
  const mutations: Array<(value: any) => void> = [
    (value) => {
      value.evidence.observed[0].guestPath = "/data/substituted.txt";
    },
    (value) => {
      value.evidence.observed = [];
    },
    (value) => {
      value.evidence.observed.push(value.evidence.observed[0]);
    },
    (value) => {
      value.evidence.processEvents.reverse();
    },
    (value) => {
      delete value.evidence.teardown;
    },
    (value) => {
      value.evidence.requestDigest = `sha256:${"9".repeat(64)}`;
    },
    (value) => {
      value.evidence.vmId = "substituted-vm";
    },
    (value) => {
      value.evidence.runtime.vmm = "krun";
    },
    (value) => {
      value.evidence.observed[0] = second.evidence.observed[0];
    },
    (value) => {
      value.stdout = "substituted output";
    },
  ];
  for (const mutate of mutations) {
    const changed = structuredClone(first);
    mutate(changed);
    assert.equal(verifyCapabilityInvocationResult(changed).valid, false);
  }
});

test("structural verification rejects host-signed reordering and incomplete teardown", () => {
  const result = fixture();
  const unsigned: any = structuredClone(result.evidence);
  delete unsigned.integrity;
  unsigned.observed.push({ ...unsigned.observed[0] });
  const duplicated = sealCapabilityEvidence(unsigned);
  assert.match(
    verifyCapabilityInvocationEvidence(duplicated).errors.join("\n"),
    /duplicate evidence event sequence|sequence is invalid/,
  );

  const incomplete: any = structuredClone(result.evidence);
  delete incomplete.integrity;
  incomplete.teardown.vmStopped = false;
  const resigned = sealCapabilityEvidence(incomplete);
  assert.match(
    verifyCapabilityInvocationEvidence(resigned).errors.join("\n"),
    /incomplete teardown/,
  );

  const omittedGate: any = structuredClone(result.evidence);
  delete omittedGate.integrity;
  delete omittedGate.teardown.vmStopped;
  assert.match(
    verifyCapabilityInvocationEvidence(
      sealCapabilityEvidence(omittedGate),
    ).errors.join("\n"),
    /incomplete teardown/,
  );

  const nonFinalTeardown: any = structuredClone(result.evidence);
  delete nonFinalTeardown.integrity;
  nonFinalTeardown.processEvents.at(-1).sequence = 99;
  assert.match(
    verifyCapabilityInvocationEvidence(
      sealCapabilityEvidence(nonFinalTeardown),
    ).errors.join("\n"),
    /teardown event is not the final authenticated event/,
  );
});

test("result verification fails closed for unbound and malformed public fields", () => {
  const result: any = fixture();
  result.error = { attacker: true };
  assert.match(
    verifyCapabilityInvocationResult(result).errors.join("\n"),
    /result error is malformed/,
  );

  const cyclic: any = fixture();
  cyclic.resourceAccounting = cyclic;
  assert.doesNotThrow(() => verifyCapabilityInvocationResult(cyclic));
  assert.equal(verifyCapabilityInvocationResult(cyclic).valid, false);
});

test("guest-generated evidence signatures are rejected unless explicitly trusted", () => {
  const result = fixture();
  const forged: any = structuredClone(result.evidence);
  delete forged.integrity;
  const pair = generateKeyPairSync("ed25519");
  const publicKey = pair.publicKey
    .export({ type: "spki", format: "der" })
    .toString("base64");
  const canonical = stableJson(forged);
  forged.integrity = {
    algorithm: "Ed25519",
    signerKeyId: sha256(Buffer.from(publicKey, "base64")),
    publicKey,
    payloadDigest: sha256(canonical),
    signature: sign(null, Buffer.from(canonical), pair.privateKey).toString(
      "base64",
    ),
  };
  assert.match(
    verifyCapabilityInvocationEvidence(forged).errors.join("\n"),
    /signer key identity substitution|signer public key substitution/,
  );
  assert.equal(
    verifyCapabilityInvocationEvidence(forged, {
      signerKeyId: forged.integrity.signerKeyId,
      publicKey,
    }).valid,
    true,
  );
});

test("execution identities remain globally unique and reject stale authority", () => {
  const identities = Array.from({ length: 256 }, (_, index) =>
    AuthenticatedExecutionIdentity.begin(
      `sha256:${index.toString(16).padStart(64, "0")}`,
      ceilingDigest,
    ),
  );
  assert.equal(new Set(identities.map((item) => item.executionId)).size, 256);
  const completed = identities[0]!;
  completed.bindVm("one-vm");
  completed.authenticate("one-vm");
  completed.finish("completed", true);
  assert.throws(() => completed.authenticate("one-vm"), /completed/);
  assert.throws(() => completed.bindVm("other-vm"), /completed/);
  const bound = identities[1]!;
  bound.bindVm("bound-vm");
  assert.throws(() => bound.bindVm("substituted-vm"), /another VM/);
  assert.throws(
    () => bound.authenticate("substituted-vm"),
    /not authenticated/,
  );
  for (const identity of identities.slice(1)) identity.finish("revoked");
  assert.throws(() => identities[1]!.authenticate(), /revoked/);

  const stale = AuthenticatedExecutionIdentity.begin(
    requestDigest,
    ceilingDigest,
  );
  __test.executionRegistry.get(stale.executionId)!.createdAt =
    Date.now() - EXECUTION_IDENTITY_RETENTION_MS;
  assert.throws(() => stale.authenticate(), /revoked/);
});

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
