import assert from "node:assert/strict";
import test from "node:test";
import { VM } from "../src/vm/core.ts";
import {
  HttpsInvocationContext,
  canonicalizeHttpsInvocationRequest,
  verifyHttpsInvocationResult,
} from "../src/https-invocation.ts";
import {
  normalizeHttpsCeiling,
  admitHttpsRequest,
} from "../src/https-authority.ts";
import {
  sealCapabilityEvidence,
  getCapabilityEvidenceVerifierIdentity,
} from "../src/invocation-evidence.ts";
import { unavailableRuntimeIdentity } from "../src/capability-runtime.ts";
import { sha256, stableJson } from "../src/canonical-json.ts";

const rule = {
  protocol: "https",
  host: "example.com",
  port: 443,
  methods: ["GET"],
  resolution: "public-only",
  redirects: "none",
  maxResponseBytes: 1024,
  timeoutMs: 1000,
};
const ceiling = () => ({
  schemaVersion: "gondolin.https-ceiling/v1",
  network: { https: [rule] },
  limits: { maxOutputBytes: 1024, maxWallTimeMs: 30000 },
});
const request = () => ({
  schemaVersion: "gondolin.https-request/v1",
  invocationId: "unit-https",
  request: { url: "https://example.com/path?query=123", method: "GET" },
  authority: rule,
  limits: { outputBytes: 1024, wallTimeMs: 30000 },
});

test("HTTPS grammar preserves correlation and freezes canonical fields", () => {
  const original = request(),
    canonical = canonicalizeHttpsInvocationRequest(original);
  assert.equal(canonical.request.request.url, original.request.url);
  assert.equal(canonical.digest, sha256(canonical.canonical));
  assert.ok(Object.isFrozen(canonical.request.authority.methods));
  const crossed = ceiling();
  crossed.network.https = [
    { ...rule, maxResponseBytes: 1 },
    { ...rule, timeoutMs: 1 },
  ];
  assert.throws(
    () => admitHttpsRequest(canonical.request, normalizeHttpsCeiling(crossed)),
    /widens/,
  );
  assert.doesNotThrow(() =>
    admitHttpsRequest(canonical.request, normalizeHttpsCeiling(ceiling())),
  );
});

test("HTTPS rejects unsupported authority and ambiguous URL forms before useful work", () => {
  for (const value of [
    { ...request(), schemaVersion: "gondolin.capability-invocation/v1" },
    { ...request(), filesystem: "none" },
    { ...request(), launch: { executable: "/bin/sh" } },
    { ...request(), credentials: "none" },
    ...["POST", "CONNECT", "get"].map((method) => ({
      ...request(),
      authority: { ...rule, methods: [method] },
    })),
    ...[0, -1, 1.1, Infinity, "10"].map((maxResponseBytes) => ({
      ...request(),
      authority: { ...rule, maxResponseBytes },
    })),
    ...[
      "https://user@example.com/",
      "https://example.com./",
      "https://example.com:0443/",
      "https://example.com/#x",
      "https://example.com\\@evil.com/",
      "https://%65xample.com/",
      "https://127.1/",
      "https://example.com/\n",
    ].map((url) => ({ ...request(), request: { url, method: "GET" } })),
  ])
    assert.throws(() => canonicalizeHttpsInvocationRequest(value));
  assert.throws(
    () =>
      admitHttpsRequest(
        canonicalizeHttpsInvocationRequest({
          ...request(),
          authority: { ...rule, timeoutMs: 2147483648 },
        }).request,
        normalizeHttpsCeiling({
          ...ceiling(),
          network: { https: [{ ...rule, timeoutMs: 2147483648 }] },
        }),
      ),
    /timer/,
  );
});

test("HTTPS runtime rejects authority overrides and unsafe process trust", async () => {
  for (const runtime of [
    { credentialStore: {} },
    { fetch() {} },
    { env: {} },
    { console: "stdio" },
    { startTimeoutMs: 0 },
  ])
    assert.throws(() =>
      HttpsInvocationContext.create(ceiling(), runtime as never),
    );
  const old = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  try {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
    await assert.rejects(
      HttpsInvocationContext.create(ceiling()).execute(request()),
      /trust overrides/,
    );
  } finally {
    if (old === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    else process.env.NODE_TLS_REJECT_UNAUTHORIZED = old;
  }
});

test("HTTPS shared trust policy denies environment and startup overrides before VM creation", async () => {
  const originalCreate = VM.create;
  const originalExecArgv = process.execArgv;
  process.execArgv = [];
  let creates = 0;
  VM.create = (async () => {
    creates++;
    throw new Error("must not create VM");
  }) as typeof VM.create;
  try {
    const old = process.env.NODE_USE_SYSTEM_CA;
    try {
      process.env.NODE_USE_SYSTEM_CA = "1";
      await assert.rejects(
        HttpsInvocationContext.create(ceiling()).execute(request()),
        /trust overrides/,
      );
    } finally {
      if (old === undefined) delete process.env.NODE_USE_SYSTEM_CA;
      else process.env.NODE_USE_SYSTEM_CA = old;
    }
    process.execArgv.push("--use-system-ca");
    try {
      await assert.rejects(
        HttpsInvocationContext.create(ceiling()).execute(request()),
        /trust overrides/,
      );
    } finally {
      process.execArgv.pop();
    }
    assert.equal(creates, 0);
  } finally {
    VM.create = originalCreate;
    process.execArgv = originalExecArgv;
  }
});

test("HTTPS controller binds host response, confines launcher and verifies signed result", async () => {
  const saved = VM.create;
  const savedExecArgv = process.execArgv;
  // This fixture never opens TLS or creates a VM; test worker startup flags are irrelevant.
  process.execArgv = [];
  let options: any,
    execOptions: any,
    argv: string[] = [];
  let malformedDiagnostics = false;
  const runtime = {
    ...unavailableRuntimeIdentity(),
    guestFeatures: [
      "exec.clear-env/v1",
      "exec.descendants-denied/v1",
      "exec.executable-mount-policy/v1",
      "exec.exact-path-lsm/v1",
      "exec.payload-confinement/v1",
      "exec.landlock-allowlist/v1",
    ],
  };
  // Host-only controller unit fixture; does not claim a real VM or external observation.
  VM.create = (async (value) => {
    options = value;
    return {
      id: "unit-vm",
      getRuntimeIdentity: () => runtime,
      start: async () => {},
      getHostPid: () => null,
      close: async () => {},
      exec: async (command: string[], configuration: any) => {
        argv = command;
        execOptions = configuration;
        const observer = options.httpsObservation;
        observer.begin(request().request.url, "GET", false);
        observer.connected({
          connectionId: "unit-peer",
          peerAddress: "93.184.216.34",
          peerPort: 443,
          tlsHostname: "example.com",
          tlsVerified: true,
        });
        configuration.stdout.write(Buffer.from([0, 255, 13, 10]));
        if (malformedDiagnostics)
          configuration.stderr.write(Buffer.from([255]));
        observer.received(4);
        observer.complete(200, Buffer.from([0, 255, 13, 10]));
        return { exitCode: 0 };
      },
    } as unknown as VM;
  }) as typeof VM.create;
  try {
    const context = HttpsInvocationContext.create(ceiling());
    for (const name of ["ceiling", "ceilingDigest", "runtime", "used"])
      assert.equal(
        Reflect.set(context, name, name === "used" ? false : {}),
        false,
      );
    const result = await context.execute(request());
    assert.equal(result.outcome, "success");
    assert.equal(result.response?.bodyBase64, "AP8NCg==");
    assert.equal(result.evidence.filesystem, "none");
    assert.equal(result.evidence.credentials, "none");
    assert.equal(argv[0], "/usr/bin/curl");
    assert.equal(argv[1], "--disable");
    assert.ok(
      !argv.includes("--insecure") &&
        !argv.includes("--location") &&
        !argv.includes("--retry"),
    );
    assert.equal(argv[argv.indexOf("--output") + 1], "-");
    assert.equal(
      argv[argv.indexOf("--resolve") + 1],
      "example.com:443:192.0.2.1",
    );
    assert.deepEqual(options.dns, {
      mode: "synthetic",
      syntheticHostMapping: "single",
      syntheticIPv4: "192.0.2.1",
    });
    assert.equal(execOptions.isolateDevices, true);
    assert.equal(execOptions.clearEnv, true);
    assert.equal(execOptions.denyDescendants, true);
    assert.equal(options.maxHttpResponseBodyBytes, rule.maxResponseBytes);
    assert.throws(() =>
      options.vfs.hooks.before({ path: "/caller.txt", op: "read" }),
    );
    assert.throws(() =>
      options.vfs.hooks.before({
        path: "/etc/gondolin/mitm/ca.crt",
        op: "open",
        flags: "w",
      }),
    );
    const expected = {
      requestDigest: result.evidence.requestDigest,
      ceilingDigest: context.ceilingDigest,
      runtime,
      qualificationId: result.evidence.qualificationId,
      ...getCapabilityEvidenceVerifierIdentity(),
    };
    assert.deepEqual(verifyHttpsInvocationResult(result, expected).errors, []);
    assert.equal(
      verifyHttpsInvocationResult(
        { ...result, response: { ...result.response, status: 201 } },
        expected,
      ).valid,
      false,
    );
    for (const change of [
      (e: any) => {
        e.network.connection.peerAddress = "127.0.0.1";
      },
      (e: any) => {
        e.network.connection.tlsVerified = false;
      },
      (e: any) => {
        e.network.elapsedMs = e.network.timeoutMs + 1;
      },
      (e: any) => {
        e.network.sequence = 2;
      },
      (e: any) => {
        e.teardown.networkChannelsClosed = false;
      },
      (e: any) => {
        e.schemaVersion = "gondolin.capability-evidence/v3";
      },
      (e: any) => {
        e.network.urlDigest = sha256("https://example.com/other");
      },
    ]) {
      const evidence = structuredClone(result.evidence) as any;
      delete evidence.integrity;
      change(evidence);
      assert.equal(
        verifyHttpsInvocationResult(
          { ...result, evidence: sealCapabilityEvidence(evidence) },
          expected,
        ).valid,
        false,
      );
    }
    assert.equal(
      verifyHttpsInvocationResult(result, {
        ...expected,
        requestDigest: sha256("other"),
      }).valid,
      false,
    );
    assert.equal(verifyHttpsInvocationResult(result, {} as never).valid, false);
    const resealed = (change: (fixture: any) => void) => {
      const fixture = structuredClone(result) as any;
      change(fixture);
      fixture.evidence.outcome = fixture.outcome;
      if (fixture.outcome === "success")
        fixture.response = fixture.evidence.network.response;
      else fixture.response = null;
      const { evidence, ...publicResult } = fixture;
      delete evidence.integrity;
      evidence.resultDigest = sha256(stableJson(publicResult));
      fixture.evidence = sealCapabilityEvidence(evidence);
      return fixture;
    };
    for (const status of [301, 302, 303, 307, 308, 204, 205, 304]) {
      const fixture = resealed((fixture) => {
        fixture.evidence.network.response.status = status;
      });
      assert.equal(
        verifyHttpsInvocationResult(fixture, expected).valid,
        false,
        `invalid complete status ${status}`,
      );
    }
    for (const change of [
      (fixture: any) => {
        fixture.stdout = "x".repeat(rule.maxResponseBytes + 1);
      },
      (fixture: any) => {
        fixture.stdout = "x";
      },
      (fixture: any) => {
        fixture.outcome = "transport_failure";
      },
      (fixture: any) => {
        fixture.outcome = "command_failed";
        fixture.exitCode = 1;
        fixture.evidence.network.response = null;
      },
      (fixture: any) => {
        fixture.outcome = "command_failed";
        fixture.exitCode = 1;
        fixture.evidence.network.settlement = "timeout";
        fixture.evidence.network.response = null;
      },
      (fixture: any) => {
        fixture.outcome = "policy_denied";
        fixture.evidence.network.settlement = "overflow";
        fixture.evidence.network.response = null;
      },
    ])
      assert.equal(
        verifyHttpsInvocationResult(resealed(change), expected).valid,
        false,
      );
    for (const change of [
      (fixture: any) => {
        fixture.outcome = "command_failed";
        fixture.exitCode = 1;
      },
      (fixture: any) => {
        fixture.outcome = "timeout";
        fixture.evidence.network.settlement = "timeout";
        fixture.evidence.network.response = null;
      },
      (fixture: any) => {
        fixture.outcome = "policy_denied";
        fixture.evidence.network.settlement = "redirect_denied";
        fixture.evidence.network.response = null;
      },
      (fixture: any) => {
        fixture.outcome = "transport_failure";
        fixture.evidence.network.settlement = "overflow";
        fixture.evidence.network.response = null;
      },
      (fixture: any) => {
        fixture.outcome = "output_overflow";
        fixture.outputTruncated = true;
        fixture.evidence.network.settlement = "timeout";
        fixture.evidence.network.response = null;
      },
      (fixture: any) => {
        fixture.outcome = "teardown_failure";
        fixture.evidence.teardown.networkChannelsClosed = false;
        fixture.evidence.teardown.completedAt = null;
      },
    ])
      assert.deepEqual(
        verifyHttpsInvocationResult(resealed(change), expected).errors,
        [],
      );
    for (const status of [204, 205, 304]) {
      const fixture = resealed((fixture) => {
        Object.assign(fixture.evidence.network.response, {
          status,
          bodyBase64: "",
          bodyBytes: 0,
          bodyDigest: sha256(Buffer.alloc(0)),
        });
        fixture.evidence.network.receivedBytes = 0;
      });
      assert.deepEqual(
        verifyHttpsInvocationResult(fixture, expected).errors,
        [],
      );
    }
    malformedDiagnostics = true;
    const malformed = await HttpsInvocationContext.create(ceiling()).execute({
      ...request(),
      limits: { ...request().limits, outputBytes: 1 },
    });
    assert.equal(malformed.outcome, "output_overflow");
    assert.equal(malformed.stdout, "");
    assert.ok(Buffer.byteLength(malformed.stderr) <= 1);
    assert.deepEqual(
      verifyHttpsInvocationResult(malformed, {
        ...expected,
        requestDigest: malformed.evidence.requestDigest,
      }).errors,
      [],
    );
    assert.equal(Reflect.set(context, "used", false), false);
    await assert.rejects(context.execute(request()), /single use/);
  } finally {
    VM.create = saved;
    process.execArgv = savedExecArgv;
  }
});

test("HTTPS malformed evidence fails closed", () => {
  for (const input of [null, {}, [], { outcome: "success" }])
    assert.equal(verifyHttpsInvocationResult(input, {} as never).valid, false);
});
