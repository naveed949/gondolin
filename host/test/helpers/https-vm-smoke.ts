import assert from "node:assert/strict";
import {
  HttpsInvocationContext,
  verifyHttpsInvocationResult,
} from "../../src/https-invocation.ts";
import {
  getCapabilityEvidenceVerifierIdentity,
  probeCapabilityInvocationTeardown,
} from "../../src/invocation-evidence.ts";
import { shouldSkipVmTests } from "./vm-fixture.ts";

// Public third-party development traffic; not controlled external qualification.
// CI must run this gate: missing acceleration, curl, network or valid TLS fails it.

function input(
  method: "GET" | "HEAD",
  maxResponseBytes = 65536,
  timeoutMs = 15000,
) {
  const authority = {
    protocol: "https",
    host: "example.com",
    port: 443,
    methods: [method],
    resolution: "public-only",
    redirects: "none",
    maxResponseBytes,
    timeoutMs,
  };
  return {
    ceiling: {
      schemaVersion: "gondolin.https-ceiling/v1",
      network: { https: [authority] },
      limits: { maxOutputBytes: 8192, maxWallTimeMs: 30000 },
    },
    request: {
      schemaVersion: "gondolin.https-request/v1",
      invocationId: `https-${method}-${maxResponseBytes}-${timeoutMs}`,
      request: { url: "https://example.com/", method },
      authority,
      limits: { outputBytes: 8192, wallTimeMs: 30000 },
    },
  };
}

async function success() {
  assert.equal(
    shouldSkipVmTests(),
    false,
    "required HTTPS CI gate needs hardware acceleration",
  );
  const verifier = getCapabilityEvidenceVerifierIdentity();
  const vmIds = new Set<string>();
  for (const method of ["GET", "HEAD"] as const) {
    const config = input(method),
      context = HttpsInvocationContext.create(config.ceiling);
    const result = await context.execute(config.request);
    assert.equal(result.outcome, "success", JSON.stringify(result));
    assert.equal(result.response?.status, 200);
    assert.equal(result.evidence.network.connection?.tlsVerified, true);
    assert.equal(
      result.evidence.network.connection?.tlsHostname,
      "example.com",
    );
    assert.equal(result.evidence.filesystem, "none");
    assert.equal(result.evidence.credentials, "none");
    assert.equal(result.evidence.teardown.networkChannelsClosed, true);
    assert.ok(!vmIds.has(result.evidence.vmId));
    vmIds.add(result.evidence.vmId);
    if (method === "GET")
      assert.match(
        Buffer.from(result.response!.bodyBase64, "base64").toString(),
        /Example Domain/,
      );
    else assert.equal(result.response!.bodyBytes, 0);
    const expected = {
      ...verifier,
      requestDigest: result.evidence.requestDigest,
      ceilingDigest: context.ceilingDigest,
      runtime: result.evidence.runtime,
      qualificationId: result.evidence.qualificationId,
    };
    assert.deepEqual(verifyHttpsInvocationResult(result, expected).errors, []);
    assert.equal(
      probeCapabilityInvocationTeardown(result.evidence.executionId, expected)
        .teardownVerified,
      true,
    );
    // Persisted data verification has no context or network dependency.
    assert.equal(
      verifyHttpsInvocationResult(JSON.parse(JSON.stringify(result)), expected)
        .valid,
      true,
    );
    await assert.rejects(context.execute(config.request), /single use/);
  }
}

async function bounds() {
  assert.equal(
    shouldSkipVmTests(),
    false,
    "required HTTPS CI gate needs hardware acceleration",
  );
  for (const [bytes, timeout] of [
    [1, 15000],
    [65536, 1],
  ]) {
    const config = input("GET", bytes, timeout),
      context = HttpsInvocationContext.create(config.ceiling);
    const result = await context.execute(config.request);
    assert.notEqual(result.outcome, "success", JSON.stringify(result));
    assert.equal(result.response, null);
    assert.equal(
      result.evidence.network.settlement,
      bytes === 1 ? "overflow" : "timeout",
      JSON.stringify(result),
    );
    assert.equal(result.evidence.teardown.networkChannelsClosed, true);
  }
}

// Plain child process: no inherited test-worker execArgv and no trust-policy bypass.
const mode = process.argv[2];
assert.equal(
  process.argv.length,
  3,
  "HTTPS VM helper requires exactly one mode",
);
assert.ok(
  mode === "success" || mode === "bounds",
  "unknown HTTPS VM helper mode",
);
await (mode === "success" ? success() : bounds());
process.stdout.write(`HTTPS VM ${mode}: PASS\n`);
