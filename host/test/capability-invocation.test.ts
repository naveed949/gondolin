import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  CAPABILITY_CEILING_SCHEMA_VERSION,
  CAPABILITY_INVOCATION_SCHEMA_VERSION,
  CapabilityAdmissionError,
  CapabilityCredentialStore,
  CapabilityInvocationContext,
  DESTINATION_BOUND_CREDENTIAL_GUARANTEES,
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
  type CapabilityCredentialProjection,
} from "../src/index.ts";
import { __test as capabilityTest } from "../src/capability-invocation.ts";
import {
  commitExactWriterTarget,
  getHostWriterTargetIdentity,
} from "../src/capability-filesystem.ts";
import { deepFreeze } from "../src/canonical-json.ts";

const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "gondolin-capability-"));
const allowedFile = path.join(tempRoot, "allowed.txt");
const otherFile = path.join(tempRoot, "other.txt");
fs.writeFileSync(allowedFile, "capability-data\n", { mode: 0o600 });
fs.writeFileSync(otherFile, "other-data\n", { mode: 0o600 });

test.after(() => {
  fs.rmSync(tempRoot, { recursive: true, force: true });
});

test("exact-writer publication cannot mutate a concurrently linked alias", () => {
  const directory = fs.mkdtempSync(path.join(tempRoot, "writer-race-"));
  const target = path.join(directory, "target.txt");
  const alias = path.join(directory, "alias.txt");
  const before = Buffer.from("before\n");
  const after = Buffer.from("after\n");
  fs.writeFileSync(target, before, { mode: 0o600 });
  fs.chmodSync(target, 0o4600);
  const expected = getHostWriterTargetIdentity(target);

  const published = commitExactWriterTarget(
    target,
    expected,
    before,
    after,
    new Set(["truncate"]),
    {
      beforePublish: () => fs.linkSync(target, alias),
    },
  );

  assert.deepEqual(fs.readFileSync(target), after);
  assert.deepEqual(fs.readFileSync(alias), before);
  assert.equal(fs.statSync(target).mode & 0o7777, 0o4600);

  const final = Buffer.from("final\n");
  commitExactWriterTarget(
    target,
    published,
    after,
    final,
    new Set(["truncate"]),
  );
  assert.deepEqual(fs.readFileSync(target), final);
});

test("deepFreeze recursively freezes a shallow-frozen value", () => {
  const value = Object.freeze({ nested: { mutable: true } });

  deepFreeze(value);

  assert.equal(Object.isFrozen(value.nested), true);
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

function credentialProjection(
  overrides: Partial<CapabilityCredentialProjection> = {},
): CapabilityCredentialProjection {
  return {
    reference: "credential/github-api",
    projection: "GITHUB_TOKEN",
    redactionId: "github-api-token",
    protocol: "tls",
    destination: "api.example.com",
    port: 443,
    methods: ["GET"],
    validity: {},
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

test("credential policy canonicalizes opaque references without accepting values", () => {
  const first = canonicalizeCapabilityInvocationRequest({
    ...request(),
    requiredGuarantees: [...DESTINATION_BOUND_CREDENTIAL_GUARANTEES],
    capabilities: {
      ...request().capabilities,
      network: { rules: [networkRule()] },
      credentials: {
        projections: [
          credentialProjection({
            destination: "API.EXAMPLE.COM.",
            methods: ["POST", "GET"],
            validity: { expiresAt: "2030-01-01T00:00:00Z" },
          }),
        ],
      },
    },
  });
  const second = canonicalizeCapabilityInvocationRequest({
    ...request(),
    requiredGuarantees: [...DESTINATION_BOUND_CREDENTIAL_GUARANTEES].reverse(),
    capabilities: {
      ...request().capabilities,
      network: { rules: [networkRule()] },
      credentials: {
        projections: [
          credentialProjection({
            destination: "api.example.com",
            methods: ["GET", "POST"],
            validity: { expiresAt: "2030-01-01T00:00:00.000Z" },
          }),
        ],
      },
    },
  });
  assert.equal(first.canonical, second.canonical);
  assert.ok(!first.canonical.includes("host-secret-value"));

  assert.throws(
    () =>
      canonicalizeCapabilityInvocationRequest({
        ...request(),
        capabilities: {
          ...request().capabilities,
          network: { rules: [networkRule()] },
          credentials: {
            projections: [
              { ...credentialProjection(), value: "host-secret-value" },
            ],
          },
        },
      }),
    (error: unknown) =>
      error instanceof CapabilityAdmissionError &&
      error.code === "invalid_request" &&
      /unknown critical field\(s\): value/.test(error.message),
  );
  assert.throws(
    () =>
      canonicalizeCapabilityInvocationRequest({
        ...request(),
        capabilities: {
          ...request().capabilities,
          network: { rules: [networkRule()] },
          credentials: {
            projections: [credentialProjection(), credentialProjection()],
          },
        },
      }),
    (error: unknown) =>
      error instanceof CapabilityAdmissionError &&
      /ambiguous duplicate/.test(error.message),
  );
});

test("credential authority contracts ceiling, network, methods, and validity", async () => {
  const projection = credentialProjection({
    methods: ["GET", "POST"],
    validity: {
      notBefore: "2026-01-01T00:00:00Z",
      expiresAt: "2030-01-01T00:00:00Z",
    },
  });
  const network = {
    rules: [networkRule({ methods: ["GET", "POST"] })],
  } as const;
  const store = CapabilityCredentialStore.create({
    "credential/github-api": {
      value: "host-secret-value",
      redactionId: "github-api-token",
      protocol: "tls",
      destination: "api.example.com",
      port: 443,
      methods: ["GET", "POST"],
      expiresAt: "2030-01-01T00:00:00Z",
    },
  });
  const context = CapabilityInvocationContext.create(
    ceiling({
      network: { rules: [...network.rules] },
      credentials: { projections: [projection] },
      guarantees: [
        ...EXACT_READER_GUARANTEES,
        ...HTTP_TLS_EGRESS_GUARANTEES,
        ...DESTINATION_BOUND_CREDENTIAL_GUARANTEES,
      ],
    }),
    { credentialStore: store },
  );
  await assert.rejects(
    context.invoke({
      ...request({ invocationId: "host-secret-value" }),
      capabilities: {
        ...request().capabilities,
        network: { rules: [...network.rules] },
        credentials: { projections: [projection] },
      },
      requiredGuarantees: [...DESTINATION_BOUND_CREDENTIAL_GUARANTEES],
    }),
    (error: unknown) =>
      error instanceof CapabilityAdmissionError &&
      error.code === "invalid_request" &&
      /contains trusted credential material/.test(error.message) &&
      !error.message.includes("host-secret-value"),
  );
  const missingStoreContext = CapabilityInvocationContext.create(
    ceiling({
      network: { rules: [...network.rules] },
      credentials: { projections: [projection] },
      guarantees: [
        ...EXACT_READER_GUARANTEES,
        ...HTTP_TLS_EGRESS_GUARANTEES,
        ...DESTINATION_BOUND_CREDENTIAL_GUARANTEES,
      ],
    }),
  );
  await assert.rejects(
    missingStoreContext.invoke({
      ...request({ invocationId: "credential-missing-store" }),
      capabilities: {
        ...request().capabilities,
        network: { rules: [...network.rules] },
        credentials: { projections: [projection] },
      },
      requiredGuarantees: [...DESTINATION_BOUND_CREDENTIAL_GUARANTEES],
    }),
    (error: unknown) =>
      error instanceof CapabilityAdmissionError && error.code === "unsupported",
  );

  for (const narrowed of [
    credentialProjection({ destination: "other.example.com" }),
    credentialProjection({ methods: ["DELETE"] }),
    credentialProjection({ validity: {} }),
  ]) {
    await assert.rejects(
      context.invoke({
        ...request({
          invocationId: `credential-widen-${narrowed.destination}-${narrowed.methods[0]}`,
        }),
        capabilities: {
          ...request().capabilities,
          network: { rules: [...network.rules] },
          credentials: { projections: [narrowed] },
        },
        requiredGuarantees: [...DESTINATION_BOUND_CREDENTIAL_GUARANTEES],
      }),
      CapabilityAdmissionError,
    );
  }

  await assert.rejects(
    context.invoke({
      ...request({ invocationId: "credential-without-network" }),
      capabilities: {
        ...request().capabilities,
        credentials: { projections: [projection] },
      },
      requiredGuarantees: [...DESTINATION_BOUND_CREDENTIAL_GUARANTEES],
    }),
    (error: unknown) =>
      error instanceof CapabilityAdmissionError &&
      error.code === "invalid_request",
  );
});

test("trusted credential store rotates and revokes without exposing values", () => {
  const store = CapabilityCredentialStore.create({
    "credential/api": {
      value: "secret-v1",
      redactionId: "api-token",
      protocol: "tls",
      destination: "api.example.com",
      port: 443,
      methods: ["GET"],
    },
  });
  assert.deepEqual(store.inspect("credential/api"), {
    redactionId: "api-token",
    revoked: false,
    deleted: false,
    revision: 1,
  });
  assert.ok(
    !JSON.stringify(store.inspect("credential/api")).includes("secret-v1"),
  );
  store.set("credential/api", {
    value: "secret-v2",
    redactionId: "api-token",
    protocol: "tls",
    destination: "api.example.com",
    port: 443,
    methods: ["GET"],
  });
  assert.equal(store.inspect("credential/api")?.revision, 2);
  store.revoke("credential/api");
  assert.equal(store.inspect("credential/api")?.revoked, true);
  store.delete("credential/api");
  assert.equal(store.inspect("credential/api")?.deleted, true);
});

test("credential response redaction preserves unrelated binary bytes", () => {
  const prefix = Buffer.from([0xff, 0xfe, 0x00, 0x80]);
  const suffix = Buffer.from([0x81, 0x00, 0xfd]);
  const value = Buffer.concat([
    prefix,
    Buffer.from("secret-v1"),
    suffix,
    Buffer.from("c2VjcmV0LXYx"),
  ]);
  const redacted = capabilityTest.redactCredentialBuffer(value, ["secret-v1"]);

  assert.deepEqual(
    redacted,
    Buffer.concat([
      prefix,
      Buffer.from("[REDACTED_CREDENTIAL]"),
      suffix,
      Buffer.from("[REDACTED_CREDENTIAL]"),
    ]),
  );
  assert.ok(!redacted.includes(Buffer.from("secret-v1")));
  assert.ok(!redacted.includes(Buffer.from("c2VjcmV0LXYx")));
  assert.ok(redacted.includes(Buffer.from("[REDACTED_CREDENTIAL]")));

  const unrelated = Buffer.from([0xff, 0xfe, 0xfd, 0x00]);
  assert.deepEqual(
    capabilityTest.redactCredentialBuffer(unrelated, ["secret-v1"]),
    unrelated,
  );
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
  assert.equal(
    manifest.profiles["exact-reader.http-tls-credentials"],
    "active",
  );
  assert.equal(manifest.backends.qemu, "active");
  assert.equal(manifest.backends.krun, "unverified");
  assert.equal(manifest.hosts.linux, "unverified");
  assert.equal(manifest.hosts.darwin, "unverified");
  assert.equal(manifest.hosts.win32, "unsupported");
  assert.equal(manifest.operations["filesystem.read.exact"], "active");
  assert.equal(manifest.operations["filesystem.write"], "unsupported");
  assert.equal(manifest.domains.network, "active");
  assert.equal(manifest.domains.credentials, "active");
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
  assert.equal(
    manifest.operations["credentials.tls-header.destination-bound"],
    "active",
  );
  assert.equal(manifest.operations["credentials.raw-tcp"], "unsupported");
  assert.equal(manifest.operations["credentials.ssh"], "unsupported");
  assert.equal(manifest.operations["credentials.broker"], "unsupported");
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
