import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  CAPABILITY_CEILING_SCHEMA_VERSION,
  CAPABILITY_INVOCATION_SCHEMA_VERSION,
  CapabilityAdmissionError,
  CapabilityInvocationContext,
  EXACT_READER_GUARANTEES,
  EXACT_WRITER_GUARANTEES,
  HTTP_TLS_EGRESS_GUARANTEES,
  canonicalizeCapabilityInvocationRequest,
  getCapabilityInvocationFeatureManifest,
  type ExactReaderCeiling,
  type ExactReaderInvocationRequest,
  type ExactWriterCeiling,
  type ExactWriterInvocationRequest,
  type CapabilityNetworkRule,
} from "../src/index.ts";
import { shouldSkipVmTests } from "./helpers/vm-fixture.ts";

const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "gondolin-capability-"));
const allowedFile = path.join(tempRoot, "allowed.txt");
const otherFile = path.join(tempRoot, "other.txt");
fs.writeFileSync(allowedFile, "capability-data\n", { mode: 0o600 });
fs.writeFileSync(otherFile, "other-data\n", { mode: 0o600 });

test.after(() => {
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

function ceiling(
  overrides: Partial<ExactReaderCeiling> = {},
): ExactReaderCeiling {
  return {
    schemaVersion: CAPABILITY_CEILING_SCHEMA_VERSION,
    profile: "exact-reader",
    allowedExecutables: ["/bin/cat"],
    filesystem: {
      sourcePaths: [allowedFile],
      guestPaths: ["/data/input.txt"],
    },
    limits: { maxOutputBytes: 4096, maxWallTimeMs: 10_000 },
    guarantees: [...EXACT_READER_GUARANTEES],
    ...overrides,
  };
}

function request(
  overrides: Partial<ExactReaderInvocationRequest> = {},
): ExactReaderInvocationRequest {
  return {
    schemaVersion: CAPABILITY_INVOCATION_SCHEMA_VERSION,
    invocationId: "reader-1",
    profile: "exact-reader",
    launch: { executable: "/bin/cat", args: ["/data/input.txt"] },
    capabilities: {
      filesystem: {
        sourcePath: allowedFile,
        guestPath: "/data/input.txt",
        operations: ["read"],
      },
      network: "none",
      environment: {},
    },
    limits: { outputBytes: 1024, wallTimeMs: 5000 },
    requiredGuarantees: [...EXACT_READER_GUARANTEES],
    ...overrides,
  };
}

function writerCeiling(
  targetPaths: string[],
  overrides: Partial<ExactWriterCeiling> = {},
): ExactWriterCeiling {
  return {
    schemaVersion: CAPABILITY_CEILING_SCHEMA_VERSION,
    profile: "exact-writer",
    allowedExecutables: ["/bin/sh"],
    filesystem: {
      targetPaths,
      guestPaths: ["/data/output.txt"],
      operations: ["create", "write", "truncate"],
    },
    limits: { maxOutputBytes: 4096, maxWallTimeMs: 10_000 },
    guarantees: [...EXACT_WRITER_GUARANTEES],
    ...overrides,
  };
}

function writerRequest(
  targetPath: string,
  overrides: Partial<ExactWriterInvocationRequest> = {},
): ExactWriterInvocationRequest {
  return {
    schemaVersion: CAPABILITY_INVOCATION_SCHEMA_VERSION,
    invocationId: "writer-1",
    profile: "exact-writer",
    launch: {
      executable: "/bin/sh",
      args: ["-c", "printf writer-data > /data/output.txt"],
    },
    capabilities: {
      filesystem: {
        targetPath,
        guestPath: "/data/output.txt",
        operations: ["write", "truncate"],
      },
      network: "none",
      environment: {},
    },
    limits: { outputBytes: 1024, wallTimeMs: 5000 },
    requiredGuarantees: [...EXACT_WRITER_GUARANTEES],
    ...overrides,
  };
}

function networkRule(
  overrides: Partial<CapabilityNetworkRule> = {},
): CapabilityNetworkRule {
  return {
    protocol: "tls",
    destination: "api.example.com",
    port: 443,
    methods: ["GET"],
    redirects: "deny",
    resolution: "checked-host",
    internalRanges: "deny",
    ...overrides,
  };
}

test("equivalent requests have byte-identical canonical representations", () => {
  const first = canonicalizeCapabilityInvocationRequest(request());
  const second = canonicalizeCapabilityInvocationRequest({
    requiredGuarantees: [...EXACT_READER_GUARANTEES].reverse(),
    limits: { wallTimeMs: 5000, outputBytes: 1024 },
    capabilities: {
      environment: {},
      network: "none",
      filesystem: {
        operations: ["read"],
        guestPath: "/data/input.txt",
        sourcePath: path.relative(process.cwd(), allowedFile),
      },
    },
    launch: { args: ["/data/input.txt"], executable: "/bin/cat" },
    profile: "exact-reader",
    invocationId: "reader-1",
    schemaVersion: CAPABILITY_INVOCATION_SCHEMA_VERSION,
  });

  assert.equal(first.canonical, second.canonical);
  assert.equal(first.digest, second.digest);
  assert.match(first.digest, /^sha256:[0-9a-f]{64}$/);
});

test("material request changes produce different request digests", () => {
  const baseline = canonicalizeCapabilityInvocationRequest(request()).digest;
  const variants = [
    request({ invocationId: "reader-2" }),
    request({
      launch: { executable: "/bin/cat", args: ["/data/input.txt", "extra"] },
    }),
    request({ limits: { outputBytes: 1023, wallTimeMs: 5000 } }),
  ];
  for (const variant of variants) {
    assert.notEqual(
      canonicalizeCapabilityInvocationRequest(variant).digest,
      baseline,
    );
  }
});

test("HTTP/TLS authorities canonicalize exact destinations, methods, and rule order", () => {
  const first = canonicalizeCapabilityInvocationRequest({
    ...request(),
    requiredGuarantees: [...HTTP_TLS_EGRESS_GUARANTEES],
    capabilities: {
      ...request().capabilities,
      network: {
        rules: [
          networkRule({
            protocol: "http",
            destination: "Example.COM.",
            port: 8080,
            methods: ["POST", "GET"],
          }),
          networkRule(),
        ],
      },
    },
  });
  const second = canonicalizeCapabilityInvocationRequest({
    ...request(),
    requiredGuarantees: [...HTTP_TLS_EGRESS_GUARANTEES].reverse(),
    capabilities: {
      ...request().capabilities,
      network: {
        rules: [
          networkRule(),
          networkRule({
            protocol: "http",
            destination: "example.com",
            port: 8080,
            methods: ["GET", "POST"],
          }),
        ],
      },
    },
  });

  assert.equal(first.canonical, second.canonical);
  assert.equal(first.digest, second.digest);
  const normalizedHttpRule =
    first.request.capabilities.network !== "none"
      ? first.request.capabilities.network.rules.find(
          (rule) => rule.destination === "example.com",
        )
      : undefined;
  assert.deepEqual(normalizedHttpRule?.methods, ["GET", "POST"]);
});

test("network schema fails closed for callbacks, ambiguous origins, and unsupported transports", () => {
  for (const network of [
    {
      rules: [{ ...networkRule(), isRequestAllowed: () => true }],
    },
    {
      rules: [networkRule(), networkRule({ methods: ["POST"] })],
    },
    {
      rules: [{ ...networkRule(), protocol: "tcp" }],
    },
    {
      rules: [
        networkRule({ destination: "127.0.0.1", internalRanges: "deny" }),
      ],
    },
    ...[
      "::ffff:127.0.0.1",
      "64:ff9b::7f00:1",
      "2001::1",
      "2002:7f00:1::",
      "3fff::1",
      "5f00::1",
    ].map((destination) => ({
      rules: [networkRule({ destination, internalRanges: "deny" })],
    })),
  ]) {
    assert.throws(
      () =>
        canonicalizeCapabilityInvocationRequest({
          ...request(),
          capabilities: { ...request().capabilities, network },
        }),
      CapabilityAdmissionError,
    );
  }
});

test("schema validation rejects unknown critical fields and ambiguous selectors", () => {
  assert.throws(
    () =>
      canonicalizeCapabilityInvocationRequest({
        ...request(),
        futureAuthority: true,
      }),
    (error: unknown) =>
      error instanceof CapabilityAdmissionError &&
      error.code === "invalid_request",
  );
  assert.throws(
    () =>
      canonicalizeCapabilityInvocationRequest({
        ...request(),
        capabilities: {
          ...request().capabilities,
          filesystem: {
            ...request().capabilities.filesystem,
            guestPath: "/data/../etc/passwd",
          },
        },
      }),
    CapabilityAdmissionError,
  );
  assert.throws(
    () =>
      canonicalizeCapabilityInvocationRequest({
        ...request(),
        schemaVersion: "future/v2",
      }),
    (error: unknown) =>
      error instanceof CapabilityAdmissionError && error.code === "unsupported",
  );
  assert.throws(
    () =>
      canonicalizeCapabilityInvocationRequest({
        ...request(),
        requiredGuarantees: [],
      }),
    (error: unknown) =>
      error instanceof CapabilityAdmissionError &&
      error.code === "invalid_request",
  );
});

test("immutable ceiling rejects widening before QEMU is created", async () => {
  const context = CapabilityInvocationContext.create(ceiling());
  assert.ok(Object.isFrozen(context.ceiling));
  assert.ok(Object.isFrozen(context.ceiling.filesystem));
  assert.throws(
    () => context.ceiling.filesystem.sourcePaths.push(otherFile),
    TypeError,
  );

  await assert.rejects(
    context.invoke({
      ...request(),
      capabilities: {
        ...request().capabilities,
        filesystem: {
          ...request().capabilities.filesystem,
          sourcePath: otherFile,
        },
      },
    }),
    (error: unknown) =>
      error instanceof CapabilityAdmissionError &&
      error.code === "ceiling_widening",
  );
  await assert.rejects(
    context.invoke({
      ...request(),
      limits: { outputBytes: 4097, wallTimeMs: 5000 },
    }),
    (error: unknown) =>
      error instanceof CapabilityAdmissionError &&
      error.code === "ceiling_widening",
  );
});

test("network authority is intersected with the immutable ceiling before QEMU is created", async () => {
  const ceilingRule = networkRule({
    methods: ["GET", "POST"],
    redirects: "same-origin",
  });
  const context = CapabilityInvocationContext.create(
    ceiling({
      network: { rules: [ceilingRule] },
      guarantees: [...EXACT_READER_GUARANTEES, ...HTTP_TLS_EGRESS_GUARANTEES],
    }),
  );

  for (const rule of [
    networkRule({ destination: "other.example.com" }),
    networkRule({ methods: ["DELETE"] }),
    networkRule({ redirects: "follow-authorized" }),
    networkRule({ internalRanges: "allow" }),
  ]) {
    await assert.rejects(
      context.invoke({
        ...request({
          invocationId: `widen-${rule.destination}-${rule.methods[0]}`,
        }),
        requiredGuarantees: [...HTTP_TLS_EGRESS_GUARANTEES],
        capabilities: {
          ...request().capabilities,
          network: { rules: [rule] },
        },
      }),
      (error: unknown) =>
        error instanceof CapabilityAdmissionError &&
        error.code === "ceiling_widening",
    );
  }
});

test("immutable ceiling rejects replacement of an admitted host file", async () => {
  const sourceDirectory = fs.mkdtempSync(path.join(tempRoot, "identity-"));
  const sourcePath = path.join(sourceDirectory, "input.txt");
  const originalPath = path.join(sourceDirectory, "original.txt");
  fs.writeFileSync(sourcePath, "original\n", { mode: 0o600 });

  const context = CapabilityInvocationContext.create(
    ceiling({
      filesystem: {
        sourcePaths: [sourcePath],
        guestPaths: ["/data/input.txt"],
      },
    }),
  );
  fs.renameSync(sourcePath, originalPath);
  fs.writeFileSync(sourcePath, "replacement\n", { mode: 0o600 });

  await assert.rejects(
    context.invoke({
      ...request({ invocationId: "reader-replaced-source" }),
      capabilities: {
        ...request().capabilities,
        filesystem: {
          sourcePath,
          guestPath: "/data/input.txt",
          operations: ["read"],
        },
      },
    }),
    (error: unknown) =>
      error instanceof CapabilityAdmissionError &&
      error.code === "invalid_request" &&
      /identity changed/.test(error.message),
  );
});

test("feature manifest advertises exact-reader and narrow HTTP/TLS mediation", () => {
  const manifest = getCapabilityInvocationFeatureManifest();
  assert.equal(manifest.profiles["exact-reader"], "active");
  assert.equal(manifest.backends.qemu, "active");
  assert.equal(manifest.backends.krun, "unverified");
  assert.equal(manifest.hosts.linux, "unverified");
  assert.equal(manifest.hosts.darwin, "unverified");
  assert.equal(manifest.hosts.win32, "unsupported");
  assert.equal(manifest.operations["filesystem.read.exact"], "active");
  assert.equal(manifest.operations["filesystem.write"], "unsupported");
  assert.equal(manifest.domains.network, "active");
  assert.equal(manifest.operations["network.none"], "active");
  assert.equal(manifest.operations["network.http1"], "active");
  assert.equal(manifest.operations["network.tls-http1"], "active");
  assert.equal(manifest.operations["network.dns.synthetic"], "active");
  assert.equal(manifest.operations["network.dns.open"], "unsupported");
  assert.equal(manifest.operations["network.raw-tcp"], "unsupported");
  assert.equal(manifest.operations["network.ssh"], "unsupported");
  assert.equal(manifest.operations["network.websocket"], "unsupported");
  assert.equal(manifest.operations["network.http2"], "unsupported");
  assert.equal(manifest.operations["network.http3"], "unsupported");
  assert.equal(manifest.operations["network.quic"], "unsupported");
  assert.equal(manifest.domains.environment, "unsupported");
  assert.equal(manifest.operations["environment.empty"], "active");
  assert.equal(
    manifest.guarantees["descendant-executable-restriction"],
    "active",
  );
  assert.ok(Object.isFrozen(manifest));
});

test("exact-writer requests are canonical and target-specific", () => {
  const firstTarget = path.join(tempRoot, "writer-first.txt");
  const secondTarget = path.join(tempRoot, "writer-second.txt");
  fs.writeFileSync(firstTarget, "first\n");
  fs.writeFileSync(secondTarget, "second\n");

  const first = canonicalizeCapabilityInvocationRequest(
    writerRequest(firstTarget),
  );
  const equivalent = canonicalizeCapabilityInvocationRequest({
    ...writerRequest(firstTarget),
    capabilities: {
      environment: {},
      network: "none",
      filesystem: {
        operations: ["truncate", "write"],
        guestPath: "/data/output.txt",
        targetPath: path.relative(process.cwd(), firstTarget),
      },
    },
    requiredGuarantees: [...EXACT_WRITER_GUARANTEES].reverse(),
  });
  const second = canonicalizeCapabilityInvocationRequest(
    writerRequest(secondTarget, { invocationId: "writer-2" }),
  );

  assert.equal(first.canonical, equivalent.canonical);
  assert.equal(first.digest, equivalent.digest);
  assert.notEqual(first.digest, second.digest);
});

test("exact-writer fails closed for empty, unsupported, and widening operations", async () => {
  const target = path.join(tempRoot, "writer-operation-target.txt");
  fs.writeFileSync(target, "before\n");
  const context = CapabilityInvocationContext.create(
    writerCeiling([target], {
      filesystem: {
        targetPaths: [target],
        guestPaths: ["/data/output.txt"],
        operations: ["write"],
      },
    }),
  );

  assert.throws(
    () =>
      CapabilityInvocationContext.create({
        ...writerCeiling([target]),
        network: "none",
      }),
    (error: unknown) =>
      error instanceof CapabilityAdmissionError &&
      error.code === "invalid_request" &&
      /unknown critical field\(s\): network/.test(error.message),
  );
  assert.throws(
    () =>
      canonicalizeCapabilityInvocationRequest({
        ...writerRequest(target),
        capabilities: {
          ...writerRequest(target).capabilities,
          network: { rules: [networkRule()] },
        },
      }),
    (error: unknown) =>
      error instanceof CapabilityAdmissionError && error.code === "unsupported",
  );

  assert.throws(
    () =>
      canonicalizeCapabilityInvocationRequest({
        ...writerRequest(target),
        capabilities: {
          ...writerRequest(target).capabilities,
          filesystem: {
            ...writerRequest(target).capabilities.filesystem,
            operations: [],
          },
        },
      }),
    (error: unknown) =>
      error instanceof CapabilityAdmissionError &&
      error.code === "invalid_request",
  );
  assert.throws(
    () =>
      canonicalizeCapabilityInvocationRequest({
        ...writerRequest(target),
        capabilities: {
          ...writerRequest(target).capabilities,
          filesystem: {
            ...writerRequest(target).capabilities.filesystem,
            operations: ["rename"],
          },
        },
      }),
    (error: unknown) =>
      error instanceof CapabilityAdmissionError && error.code === "unsupported",
  );
  await assert.rejects(
    context.invoke(writerRequest(target)),
    (error: unknown) =>
      error instanceof CapabilityAdmissionError &&
      error.code === "ceiling_widening",
  );
});

test("exact-writer pins missing and existing namespace identities", async () => {
  const existing = path.join(tempRoot, "writer-pinned.txt");
  const moved = path.join(tempRoot, "writer-pinned-original.txt");
  fs.writeFileSync(existing, "original\n");
  const existingContext = CapabilityInvocationContext.create(
    writerCeiling([existing]),
  );
  fs.renameSync(existing, moved);
  fs.writeFileSync(existing, "replacement\n");

  await assert.rejects(
    existingContext.invoke(
      writerRequest(existing, { invocationId: "writer-replaced" }),
    ),
    (error: unknown) =>
      error instanceof CapabilityAdmissionError &&
      /identity changed/.test(error.message),
  );
  assert.equal(fs.readFileSync(existing, "utf8"), "replacement\n");

  const missing = path.join(tempRoot, "writer-missing.txt");
  const missingContext = CapabilityInvocationContext.create(
    writerCeiling([missing]),
  );
  await assert.rejects(
    missingContext.invoke(
      writerRequest(missing, {
        invocationId: "writer-missing-without-create",
        capabilities: {
          ...writerRequest(missing).capabilities,
          filesystem: {
            ...writerRequest(missing).capabilities.filesystem,
            operations: ["write"],
          },
        },
      }),
    ),
    (error: unknown) =>
      error instanceof CapabilityAdmissionError &&
      /requires create authority/.test(error.message),
  );
  fs.writeFileSync(missing, "appeared\n");
  await assert.rejects(
    missingContext.invoke(
      writerRequest(missing, {
        invocationId: "writer-appeared",
        capabilities: {
          ...writerRequest(missing).capabilities,
          filesystem: {
            ...writerRequest(missing).capabilities.filesystem,
            operations: ["create", "write"],
          },
        },
      }),
    ),
    (error: unknown) =>
      error instanceof CapabilityAdmissionError &&
      /appeared/.test(error.message),
  );
});

test("exact-writer rejects Git metadata, symlinks, and hard-link aliases", () => {
  const repository = fs.mkdtempSync(path.join(tempRoot, "writer-repo-"));
  const gitDirectory = path.join(repository, ".git");
  fs.mkdirSync(gitDirectory);
  const hook = path.join(gitDirectory, "hooks-target");
  assert.throws(
    () => CapabilityInvocationContext.create(writerCeiling([hook])),
    (error: unknown) =>
      error instanceof CapabilityAdmissionError && error.code === "unsupported",
  );
  const caseFoldedGitDirectory = path.join(repository, ".GIT");
  fs.mkdirSync(caseFoldedGitDirectory);
  assert.throws(
    () =>
      CapabilityInvocationContext.create(
        writerCeiling([path.join(caseFoldedGitDirectory, "config")]),
      ),
    (error: unknown) =>
      error instanceof CapabilityAdmissionError && error.code === "unsupported",
  );

  const original = path.join(repository, "original.txt");
  const alias = path.join(repository, "alias.txt");
  fs.writeFileSync(original, "linked\n");
  fs.linkSync(original, alias);
  assert.throws(
    () => CapabilityInvocationContext.create(writerCeiling([original])),
    (error: unknown) =>
      error instanceof CapabilityAdmissionError &&
      /hard-linked/.test(error.message),
  );

  const symlink = path.join(repository, "symlink.txt");
  fs.symlinkSync(original, symlink);
  assert.throws(
    () => CapabilityInvocationContext.create(writerCeiling([symlink])),
    CapabilityAdmissionError,
  );
});

test("feature manifest advertises only exact writer mutations", () => {
  const manifest = getCapabilityInvocationFeatureManifest();
  assert.equal(manifest.profiles["exact-writer"], "active");
  assert.equal(manifest.operations["filesystem.create.exact"], "active");
  assert.equal(manifest.operations["filesystem.write.exact"], "active");
  assert.equal(manifest.operations["filesystem.truncate.exact"], "active");
  assert.equal(manifest.operations["filesystem.rename"], "unsupported");
  assert.equal(manifest.operations["filesystem.delete"], "unsupported");
  assert.equal(manifest.operations["filesystem.metadata-write"], "unsupported");
  assert.equal(manifest.operations["filesystem.link"], "unsupported");
  assert.equal(manifest.operations["filesystem.execute"], "unsupported");
});

test(
  "public seam allows only the exact reader and settles after teardown",
  { skip: shouldSkipVmTests(), timeout: 120_000 },
  async () => {
    const context = CapabilityInvocationContext.create(ceiling());
    const allowed = await context.invoke(request());

    assert.equal(allowed.outcome, "success", allowed.error);
    assert.equal(allowed.stdout, "capability-data\n");
    assert.equal(allowed.stderr, "");
    assert.match(allowed.evidence.executionId, /^[0-9a-f-]{36}$/);
    assert.notEqual(allowed.evidence.executionId, allowed.evidence.vmId);
    assert.equal(allowed.evidence.runtime.vmm, "qemu");
    assert.ok(
      allowed.evidence.observed.some((effect) => effect.operation === "read"),
    );
    assert.deepEqual(allowed.evidence.teardown, {
      commandStopped: true,
      vmStopped: true,
      vfsHandlesRevoked: true,
      policyRemoved: true,
      ephemeralStateDestroyed: true,
      completedAt: allowed.evidence.settledAt,
    });

    const malicious = await context.invoke({
      ...request({ invocationId: "reader-malicious" }),
      launch: { executable: "/bin/cat", args: ["/data/other.txt"] },
    });
    assert.equal(malicious.outcome, "command_failed", malicious.error);
    assert.ok(
      malicious.evidence.denied.some(
        (effect) => effect.guestPath === "/data/other.txt",
      ),
    );
    assert.equal(malicious.evidence.teardown.vmStopped, true);
    assert.notEqual(malicious.evidence.vmId, allowed.evidence.vmId);
    assert.notEqual(
      malicious.evidence.executionId,
      allowed.evidence.executionId,
    );

    const cleanEnvironment = CapabilityInvocationContext.create(
      ceiling({ allowedExecutables: ["/usr/bin/env"] }),
    );
    const envResult = await cleanEnvironment.invoke({
      ...request({ invocationId: "reader-clean-environment" }),
      launch: { executable: "/usr/bin/env", args: [] },
    });
    assert.equal(envResult.outcome, "success", envResult.error);
    assert.equal(envResult.stdout, "");

    const boundedOutput = CapabilityInvocationContext.create(
      ceiling({ limits: { maxOutputBytes: 4, maxWallTimeMs: 10_000 } }),
    );
    const overflow = await boundedOutput.invoke({
      ...request({ invocationId: "reader-output-overflow" }),
      limits: { outputBytes: 4, wallTimeMs: 5000 },
    });
    assert.equal(overflow.outcome, "output_overflow", overflow.error);
    assert.equal(Buffer.byteLength(overflow.stdout) <= 4, true);
    assert.equal(overflow.outputTruncated, true);
    assert.equal(overflow.evidence.teardown.vmStopped, true);

    const boundedTime = CapabilityInvocationContext.create(
      ceiling({
        allowedExecutables: ["/bin/sleep"],
        limits: { maxOutputBytes: 1024, maxWallTimeMs: 100 },
      }),
    );
    const timeout = await boundedTime.invoke({
      ...request({ invocationId: "reader-timeout" }),
      launch: { executable: "/bin/sleep", args: ["5"] },
      limits: { outputBytes: 1024, wallTimeMs: 100 },
    });
    assert.equal(timeout.outcome, "timeout", timeout.error);
    assert.equal(timeout.evidence.teardown.vmStopped, true);
  },
);

test(
  "public seam isolates two exact writers and reports host-visible effects",
  { skip: shouldSkipVmTests(), timeout: 120_000 },
  async () => {
    const firstTarget = path.join(tempRoot, "public-writer-first.txt");
    const secondTarget = path.join(tempRoot, "public-writer-second.txt");
    const createdTarget = path.join(tempRoot, "public-writer-created.txt");
    const unrelated = path.join(tempRoot, "public-writer-unrelated.txt");
    fs.writeFileSync(firstTarget, "first-before\n");
    fs.writeFileSync(secondTarget, "second-before\n");
    fs.writeFileSync(unrelated, "unrelated-before\n");
    const context = CapabilityInvocationContext.create(
      writerCeiling([firstTarget, secondTarget, createdTarget]),
    );

    const first = await context.invoke(writerRequest(firstTarget));
    const second = await context.invoke(
      writerRequest(secondTarget, {
        invocationId: "writer-2",
        launch: {
          executable: "/bin/sh",
          args: [
            "-c",
            "printf second-data > /data/output.txt; printf denied > /data/other.txt",
          ],
        },
      }),
    );

    assert.equal(first.outcome, "success", first.error);
    assert.equal(fs.readFileSync(firstTarget, "utf8"), "writer-data");
    assert.equal(fs.readFileSync(secondTarget, "utf8"), "second-data");
    assert.equal(fs.readFileSync(unrelated, "utf8"), "unrelated-before\n");
    assert.notEqual(
      first.evidence.requestDigest,
      second.evidence.requestDigest,
    );
    assert.notEqual(first.evidence.executionId, second.evidence.executionId);
    assert.notEqual(first.evidence.vmId, second.evidence.vmId);
    assert.notEqual(
      first.evidence.granted[0]?.resourceId,
      second.evidence.granted[0]?.resourceId,
    );
    assert.ok(
      first.evidence.observed.some((effect) => effect.operation === "write"),
    );
    assert.ok(
      first.evidence.observed.some((effect) => effect.operation === "truncate"),
    );
    assert.ok(
      second.evidence.denied.some(
        (effect) => effect.guestPath === "/data/other.txt",
      ),
    );
    assert.equal(first.evidence.teardown.completedAt, first.evidence.settledAt);
    assert.equal(
      second.evidence.teardown.completedAt,
      second.evidence.settledAt,
    );
    assert.equal(
      first.evidence.outputDigest,
      `sha256:${createHash("sha256").update("writer-data").digest("hex")}`,
    );

    const created = await context.invoke(
      writerRequest(createdTarget, {
        invocationId: "writer-create",
        capabilities: {
          ...writerRequest(createdTarget).capabilities,
          filesystem: {
            ...writerRequest(createdTarget).capabilities.filesystem,
            operations: ["create", "write"],
          },
        },
        launch: {
          executable: "/bin/sh",
          args: ["-c", "printf created-data > /data/output.txt"],
        },
      }),
    );
    assert.equal(created.outcome, "success", created.error);
    assert.equal(fs.readFileSync(createdTarget, "utf8"), "created-data");
    assert.ok(
      created.evidence.observed.some((effect) => effect.operation === "create"),
    );

    const deniedRead = await context.invoke(
      writerRequest(firstTarget, {
        invocationId: "writer-read-denied",
        capabilities: {
          ...writerRequest(firstTarget).capabilities,
          filesystem: {
            ...writerRequest(firstTarget).capabilities.filesystem,
            operations: ["write"],
          },
        },
        launch: {
          executable: "/bin/sh",
          args: ["-c", "cat /data/output.txt >/dev/null"],
        },
      }),
    );
    assert.equal(deniedRead.outcome, "command_failed", deniedRead.error);
    assert.ok(
      deniedRead.evidence.denied.some((effect) => effect.operation === "read"),
    );
    assert.equal(fs.readFileSync(firstTarget, "utf8"), "writer-data");

    const deniedLink = await context.invoke(
      writerRequest(firstTarget, {
        invocationId: "writer-link-denied",
        capabilities: {
          ...writerRequest(firstTarget).capabilities,
          filesystem: {
            ...writerRequest(firstTarget).capabilities.filesystem,
            operations: ["write"],
          },
        },
        launch: {
          executable: "/bin/sh",
          args: ["-c", "ln /data/output.txt /data/alias.txt"],
        },
      }),
    );
    assert.equal(deniedLink.outcome, "command_failed", deniedLink.error);
    assert.ok(
      deniedLink.evidence.denied.some((effect) => effect.operation === "link"),
    );

    const truncated = await context.invoke(
      writerRequest(firstTarget, {
        invocationId: "writer-truncate-only",
        capabilities: {
          ...writerRequest(firstTarget).capabilities,
          filesystem: {
            ...writerRequest(firstTarget).capabilities.filesystem,
            operations: ["truncate"],
          },
        },
        launch: {
          executable: "/bin/sh",
          args: ["-c", ": > /data/output.txt"],
        },
      }),
    );
    assert.equal(truncated.outcome, "success", truncated.error);
    assert.equal(fs.readFileSync(firstTarget, "utf8"), "");
    assert.deepEqual(
      truncated.evidence.granted.map((effect) => effect.operation),
      ["truncate"],
    );
  },
);

test(
  "public seam scopes HTTP redirects, resolution, connections, and teardown to one invocation",
  { skip: shouldSkipVmTests(), timeout: 240_000 },
  async () => {
    const server = http.createServer((incoming, response) => {
      if (incoming.url === "/redirect") {
        const address = server.address();
        assert.ok(address && typeof address === "object");
        response.writeHead(302, {
          location: `http://127.0.0.1:${address.port}/ok`,
        });
        response.end();
        return;
      }
      response.writeHead(200, { "content-type": "text/plain" });
      response.end(`${incoming.method} network-ok\n`);
    });
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });

    try {
      const address = server.address();
      assert.ok(address && typeof address === "object");
      const rules = [
        networkRule({
          protocol: "http",
          destination: "localhost",
          port: address.port,
          redirects: "follow-authorized",
          internalRanges: "allow",
        }),
        networkRule({
          protocol: "http",
          destination: "127.0.0.1",
          port: address.port,
          internalRanges: "allow",
        }),
      ];
      const context = CapabilityInvocationContext.create(
        ceiling({
          allowedExecutables: ["/bin/busybox"],
          network: { rules },
          guarantees: [
            ...EXACT_READER_GUARANTEES,
            ...HTTP_TLS_EGRESS_GUARANTEES,
          ],
        }),
      );
      const result = await context.invoke({
        ...request({ invocationId: "reader-http-redirect" }),
        launch: {
          executable: "/bin/busybox",
          args: ["wget", "-qO-", `http://localhost:${address.port}/redirect`],
        },
        capabilities: {
          ...request().capabilities,
          network: { rules },
        },
        requiredGuarantees: [...HTTP_TLS_EGRESS_GUARANTEES],
      });

      assert.equal(result.outcome, "success", result.error);
      assert.equal(result.stdout, "GET network-ok\n");
      const networkEffects = result.evidence.attempted.filter(
        (effect) => effect.domain === "network",
      );
      assert.ok(
        networkEffects.some((effect) => effect.operation === "request"),
      );
      assert.ok(
        networkEffects.some((effect) => effect.operation === "redirect"),
      );
      assert.ok(
        networkEffects.some((effect) => effect.operation === "resolution"),
      );
      assert.ok(
        networkEffects.some((effect) => effect.operation === "connection"),
      );
      assert.ok(
        result.evidence.observed.some(
          (effect) =>
            effect.domain === "network" && effect.operation === "completion",
        ),
      );
      assert.equal(result.evidence.teardown.networkChannelsClosed, true);
      assert.equal(
        result.evidence.policyVersions.network,
        "http-tls-mediator/v1",
      );
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  },
);
