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
  type CapabilityInvocationResult,
} from "../src/index.ts";
import { __test as capabilityTest } from "../src/capability-invocation.ts";
import { shouldSkipVmTests } from "./helpers/vm-fixture.ts";
import { mockCapabilityNetworkDns } from "./helpers/capability-network.ts";

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
    allowedExecutables: ["/bin/busybox"],
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
    launch: { executable: "/bin/busybox", args: ["cat", "/data/input.txt"] },
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
    allowedExecutables: ["/bin/busybox"],
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
      executable: "/bin/busybox",
      args: ["sh", "-c", "printf writer-data > /data/output.txt"],
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

test(
  "public seam allows only the exact reader and settles after teardown",
  { skip: shouldSkipVmTests(), timeout: 120_000 },
  async () => {
    const context = CapabilityInvocationContext.create(ceiling(), {
      console: "stdio",
      startTimeoutMs: 15_000,
    });
    const allowed = await context.invoke(request());

    assert.equal(
      allowed.outcome,
      "success",
      `${allowed.error ?? ""}\n${allowed.stderr}`,
    );
    assert.equal(allowed.stdout, "capability-data\n");
    assert.equal(allowed.stderr, "");
    assert.match(allowed.evidence.executionId, /^[0-9a-f-]{36}$/);
    assert.notEqual(allowed.evidence.executionId, allowed.evidence.vmId);
    assert.equal(allowed.evidence.runtime.vmm, "qemu");
    assert.ok(
      allowed.evidence.observed.some((effect) => effect.operation === "read"),
    );
    assert.deepEqual(allowed.evidence.teardown, {
      executionId: allowed.evidence.executionId,
      sequence: allowed.evidence.teardown.sequence,
      commandStopped: true,
      vmStopped: true,
      vfsHandlesRevoked: true,
      policyRemoved: true,
      ephemeralStateDestroyed: true,
      completedAt: allowed.evidence.settledAt,
    });

    const malicious = await context.invoke({
      ...request({ invocationId: "reader-malicious" }),
      launch: { executable: "/bin/busybox", args: ["cat", "/data/other.txt"] },
    });
    assert.equal(malicious.outcome, "policy_denied", malicious.error);
    assert.ok(malicious.exitCode !== null && malicious.exitCode !== 0);
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

    const descendant = await context.invoke({
      ...request({ invocationId: "reader-undeclared-descendant" }),
      launch: {
        executable: "/bin/busybox",
        args: ["sh", "-c", "exec /usr/bin/env"],
      },
    });
    // Kernel executable rejection has no host-observed filesystem denial event.
    assert.equal(descendant.outcome, "command_failed", descendant.error);
    assert.deepEqual(descendant.evidence.denied, []);
    assert.notEqual(descendant.exitCode, 0);
    assert.equal(descendant.stdout, "");
    assert.equal(descendant.evidence.teardown.vmStopped, true);

    const cleanEnvironment = CapabilityInvocationContext.create(
      ceiling({ allowedExecutables: ["/bin/busybox"] }),
    );
    const envResult = await cleanEnvironment.invoke({
      ...request({ invocationId: "reader-clean-environment" }),
      launch: { executable: "/bin/busybox", args: ["env"] },
    });
    assert.equal(
      envResult.outcome,
      "success",
      `${envResult.error ?? ""}\n${envResult.stderr}`,
    );
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
        allowedExecutables: ["/bin/busybox"],
        limits: { maxOutputBytes: 1024, maxWallTimeMs: 100 },
      }),
    );
    const timeout = await boundedTime.invoke({
      ...request({ invocationId: "reader-timeout" }),
      launch: { executable: "/bin/busybox", args: ["sleep", "5"] },
      limits: { outputBytes: 1024, wallTimeMs: 100 },
    });
    assert.equal(timeout.outcome, "timeout", timeout.error);
    assert.equal(timeout.evidence.teardown.vmStopped, true);

    const noDescendants = await context.invoke({
      ...request({ invocationId: "reader-no-descendants" }),
      launch: {
        executable: "/bin/busybox",
        args: ["sh", "-c", "busybox echo child-ran & wait"],
      },
    });
    assert.notEqual(noDescendants.outcome, "success");
    assert.doesNotMatch(noDescendants.stdout, /child-ran/);
    assert.equal(noDescendants.evidence.teardown.vmStopped, true);
  },
);

test(
  "public seam isolates two exact writers and reports host-visible effects",
  { skip: shouldSkipVmTests(), timeout: 120_000 },
  async () => {
    const firstTarget = path.join(tempRoot, "public-writer-first.txt");
    const secondTarget = path.join(tempRoot, "public-writer-second.txt");
    const createdTarget = path.join(tempRoot, "public-writer-created.txt");
    const emptyTarget = path.join(tempRoot, "public-writer-empty.txt");
    const unusedTarget = path.join(tempRoot, "public-writer-unused.txt");
    const failedTarget = path.join(tempRoot, "public-writer-failed.txt");
    const unrelated = path.join(tempRoot, "public-writer-unrelated.txt");
    fs.writeFileSync(firstTarget, "first-before\n");
    fs.writeFileSync(secondTarget, "second-before\n");
    fs.writeFileSync(unrelated, "unrelated-before\n");
    const context = CapabilityInvocationContext.create(
      writerCeiling([
        firstTarget,
        secondTarget,
        createdTarget,
        emptyTarget,
        unusedTarget,
        failedTarget,
      ]),
    );

    const first = await context.invoke(writerRequest(firstTarget));
    const second = await context.invoke(
      writerRequest(secondTarget, {
        invocationId: "writer-2",
        launch: {
          executable: "/bin/busybox",
          args: [
            "sh",
            "-c",
            "printf second-data > /data/output.txt; printf denied > /data/other.txt",
          ],
        },
      }),
    );

    assert.equal(
      first.outcome,
      "success",
      `${first.error ?? ""}\n${first.stderr}`,
    );
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
          executable: "/bin/busybox",
          args: ["sh", "-c", "printf created-data > /data/output.txt"],
        },
      }),
    );
    assert.equal(
      created.outcome,
      "success",
      `${created.error ?? ""}\n${created.stderr}`,
    );
    assert.equal(fs.readFileSync(createdTarget, "utf8"), "created-data");
    assert.ok(
      created.evidence.observed.some((effect) => effect.operation === "create"),
    );

    await assert.rejects(
      context.invoke(
        writerRequest(unusedTarget, {
          invocationId: "writer-missing-create-authority",
        }),
      ),
      (error: unknown) =>
        error instanceof CapabilityAdmissionError &&
        /requires create authority/.test(error.message),
    );
    assert.equal(fs.existsSync(unusedTarget), false);

    for (const [target, invocationId, command, expected] of [
      [emptyTarget, "writer-create-empty", ": > /data/output.txt", "success"],
      [unusedTarget, "writer-unused-placeholder", "true", "success"],
      [failedTarget, "writer-failed-placeholder", "false", "command_failed"],
    ] as const) {
      const createOnly = await context.invoke(
        writerRequest(target, {
          invocationId,
          capabilities: {
            ...writerRequest(target).capabilities,
            filesystem: {
              ...writerRequest(target).capabilities.filesystem,
              operations: ["create"],
            },
          },
          launch: { executable: "/bin/busybox", args: ["sh", "-c", command] },
        }),
      );
      assert.equal(
        createOnly.outcome,
        expected,
        `${createOnly.error ?? ""}\n${createOnly.stderr}`,
      );
      assert.equal(createOnly.evidence.teardown.vmStopped, true);
      assert.deepEqual(createOnly.evidence.denied, []);
      if (target === emptyTarget) {
        assert.equal(fs.readFileSync(target, "utf8"), "");
        assert.deepEqual(
          createOnly.evidence.observed.map((effect) => effect.operation),
          ["create"],
        );
      } else {
        assert.equal(fs.existsSync(target), false);
        assert.deepEqual(createOnly.evidence.observed, []);
      }
    }

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
          executable: "/bin/busybox",
          args: ["cat", "/data/output.txt"],
        },
      }),
    );
    assert.equal(deniedRead.outcome, "policy_denied", deniedRead.error);
    assert.ok(deniedRead.exitCode !== null && deniedRead.exitCode !== 0);
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
          executable: "/bin/busybox",
          args: ["ln", "/data/output.txt", "/data/alias.txt"],
        },
      }),
    );
    assert.equal(deniedLink.outcome, "policy_denied", deniedLink.error);
    assert.ok(deniedLink.exitCode !== null && deniedLink.exitCode !== 0);
    assert.ok(
      // The VFS can reject destination lookup before a link RPC is possible.
      deniedLink.evidence.denied.some(
        (effect) =>
          effect.domain === "filesystem" &&
          effect.guestPath === "/data/alias.txt",
      ),
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
          executable: "/bin/busybox",
          args: ["sh", "-c", ": > /data/output.txt"],
        },
      }),
    );
    assert.equal(
      truncated.outcome,
      "success",
      `${truncated.error ?? ""}\n${truncated.stderr}`,
    );
    assert.equal(fs.readFileSync(firstTarget, "utf8"), "");
    assert.deepEqual(
      truncated.evidence.granted.map((effect) => effect.operation),
      ["truncate"],
    );
  },
);

function networkFailureDetails(result: CapabilityInvocationResult): string {
  return JSON.stringify({
    outcome: result.outcome,
    error: result.error,
    stderr: result.stderr,
    attempted: result.evidence.attempted.filter(
      (effect) => effect.domain === "network",
    ),
    denied: result.evidence.denied.filter(
      (effect) => effect.domain === "network",
    ),
    observed: result.evidence.observed.filter(
      (effect) => effect.domain === "network",
    ),
    processEvents: result.evidence.processEvents,
  });
}

test(
  "public seam scopes HTTP redirects, resolution, connections, and teardown to one invocation",
  { skip: shouldSkipVmTests(), timeout: 120_000 },
  async (t) => {
    mockCapabilityNetworkDns(t);
    const server = http.createServer((incoming, response) => {
      if (incoming.url === "/redirect") {
        const address = server.address();
        assert.ok(address && typeof address === "object");
        response.writeHead(302, {
          location: `http://capability.test:${address.port}/ok`,
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
          destination: "capability-alias.test",
          port: address.port,
          redirects: "follow-authorized",
          internalRanges: "allow",
        }),
        networkRule({
          protocol: "http",
          destination: "capability.test",
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
          args: [
            "wget",
            "-qO-",
            `http://capability-alias.test:${address.port}/redirect`,
          ],
        },
        capabilities: {
          ...request().capabilities,
          network: { rules },
        },
        requiredGuarantees: [...HTTP_TLS_EGRESS_GUARANTEES],
      });

      assert.equal(result.outcome, "success", networkFailureDetails(result));
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

test(
  "public seam binds, rotates, revokes, expires, redacts, and tears down credentials",
  { skip: shouldSkipVmTests(), timeout: 120_000 },
  async (t) => {
    mockCapabilityNetworkDns(t);
    const received: Array<{ path: string; credential: string | undefined }> =
      [];
    const server = http.createServer((incoming, response) => {
      received.push({
        path: incoming.url ?? "",
        credential: incoming.headers["x-api-token"] as string | undefined,
      });
      if (incoming.url === "/redirect") {
        const address = server.address();
        assert.ok(address && typeof address === "object");
        response.writeHead(302, {
          location: `http://capability-alias.test:${address.port}/redirected`,
        });
        response.end();
        return;
      }
      response.writeHead(200, {
        "content-type": "text/plain",
        "x-reflected-credential":
          incoming.url === "/rotated"
            ? "credential-v1 credential-v2"
            : (incoming.headers["x-api-token"] ?? "none"),
      });
      response.end(
        incoming.url === "/rotated"
          ? "credential-v1 credential-v2\n"
          : `${incoming.headers["x-api-token"] ?? "none"}\n`,
      );
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
          destination: "capability.test",
          port: address.port,
          redirects: "follow-authorized",
          internalRanges: "allow",
        }),
        networkRule({
          protocol: "http",
          destination: "capability-alias.test",
          port: address.port,
          internalRanges: "allow",
        }),
      ];
      const projection = credentialProjection({
        reference: "credential/local-api",
        projection: "API_TOKEN",
        redactionId: "local-api-token",
        protocol: "http",
        destination: "capability.test",
        port: address.port,
      });
      const store = CapabilityCredentialStore.create({
        "credential/local-api": {
          value: "credential-v1",
          redactionId: "local-api-token",
          protocol: "http",
          destination: "capability.test",
          port: address.port,
          methods: ["GET"],
        },
      });
      const context = CapabilityInvocationContext.create(
        ceiling({
          allowedExecutables: ["/bin/busybox"],
          network: { rules },
          credentials: { projections: [projection] },
          guarantees: [
            ...EXACT_READER_GUARANTEES,
            ...HTTP_TLS_EGRESS_GUARANTEES,
            ...DESTINATION_BOUND_CREDENTIAL_GUARANTEES,
          ],
        }),
        { credentialStore: store },
      );
      const credentialRequest = (
        invocationId: string,
        command: string,
      ): ExactReaderInvocationRequest => ({
        ...request({ invocationId }),
        launch: { executable: "/bin/busybox", args: ["sh", "-c", command] },
        capabilities: {
          ...request().capabilities,
          network: { rules },
          credentials: { projections: [projection] },
        },
        requiredGuarantees: [
          ...HTTP_TLS_EGRESS_GUARANTEES,
          ...DESTINATION_BOUND_CREDENTIAL_GUARANTEES,
        ],
      });

      const placeholderResult = await context.invoke(
        credentialRequest("credential-placeholder", 'printf %s "$API_TOKEN"'),
      );
      assert.equal(
        placeholderResult.outcome,
        "success",
        `${placeholderResult.error ?? ""}\n${placeholderResult.stderr}`,
      );
      assert.match(placeholderResult.stdout, /^GONDOLIN_CREDENTIAL_/);
      const stalePlaceholder = placeholderResult.stdout;

      const first = await context.invoke(
        credentialRequest(
          "credential-use-v1",
          `exec /bin/busybox wget -qO- --header=\"X-Api-Token: $API_TOKEN\" http://capability.test:${address.port}/echo`,
        ),
      );
      assert.equal(first.outcome, "success", networkFailureDetails(first));
      assert.equal(first.stdout, "[REDACTED_CREDENTIAL]\n");
      assert.equal(received.at(-1)?.credential, "credential-v1");
      assert.ok(
        first.evidence.observed.some(
          (effect) =>
            effect.domain === "credential" && effect.operation === "use",
        ),
      );
      assert.equal(first.evidence.teardown.credentialProjectionsRevoked, true);
      assert.ok(!JSON.stringify(first).includes("credential-v1"));

      const stale = await context.invoke(
        credentialRequest(
          "credential-stale-placeholder",
          `exec /bin/busybox wget -qO- --header=\"X-Api-Token: ${stalePlaceholder}\" http://capability.test:${address.port}/stale`,
        ),
      );
      assert.equal(stale.outcome, "policy_denied", stale.error);
      assert.ok(stale.exitCode !== null && stale.exitCode !== 0);
      assert.ok(
        stale.evidence.denied.some(
          (effect) =>
            effect.domain === "credential" && effect.reason === "stale",
        ),
      );
      assert.ok(!received.some((entry) => entry.path === "/stale"));

      const redirected = await context.invoke(
        credentialRequest(
          "credential-redirect-alias",
          `exec /bin/busybox wget -qO- --header=\"X-Api-Token: $API_TOKEN\" http://capability.test:${address.port}/redirect`,
        ),
      );
      assert.equal(redirected.outcome, "policy_denied", redirected.error);
      assert.ok(redirected.exitCode !== null && redirected.exitCode !== 0);
      assert.ok(
        redirected.evidence.denied.some(
          (effect) =>
            effect.domain === "credential" && effect.reason === "mismatch",
        ),
      );
      assert.ok(!received.some((entry) => entry.path === "/redirected"));

      store.set("credential/local-api", {
        value: "credential-v2",
        redactionId: "local-api-token",
        protocol: "http",
        destination: "capability.test",
        port: address.port,
        methods: ["GET"],
      });
      const rotated = await context.invoke(
        credentialRequest(
          "credential-use-v2",
          `exec /bin/busybox wget -qO- --header=\"X-Api-Token: $API_TOKEN\" http://capability.test:${address.port}/rotated`,
        ),
      );
      assert.equal(
        rotated.outcome,
        "success",
        `${rotated.error ?? ""}\n${rotated.stderr}`,
      );
      assert.equal(received.at(-1)?.credential, "credential-v2");
      assert.ok(!JSON.stringify(rotated).includes("credential-v1"));
      assert.ok(!JSON.stringify(rotated).includes("credential-v2"));

      store.revoke("credential/local-api");
      const revoked = await context.invoke(
        credentialRequest(
          "credential-revoked",
          `exec /bin/busybox wget -qO- --header=\"X-Api-Token: $API_TOKEN\" http://capability.test:${address.port}/revoked`,
        ),
      );
      assert.equal(revoked.outcome, "policy_denied", revoked.error);
      assert.ok(revoked.exitCode !== null && revoked.exitCode !== 0);
      assert.ok(
        revoked.evidence.denied.some(
          (effect) =>
            effect.domain === "credential" && effect.reason === "revoked",
        ),
      );
      assert.ok(!received.some((entry) => entry.path === "/revoked"));

      store.set("credential/local-api", {
        value: "credential-expired",
        redactionId: "local-api-token",
        protocol: "http",
        destination: "capability.test",
        port: address.port,
        methods: ["GET"],
        expiresAt: "2020-01-01T00:00:00Z",
      });
      const expired = await context.invoke(
        credentialRequest(
          "credential-expiry-check",
          `exec /bin/busybox wget -qO- --header=\"X-Api-Token: $API_TOKEN\" http://capability.test:${address.port}/expired`,
        ),
      );
      assert.equal(expired.outcome, "policy_denied", expired.error);
      assert.ok(expired.exitCode !== null && expired.exitCode !== 0);
      assert.ok(
        expired.evidence.denied.some(
          (effect) =>
            effect.domain === "credential" && effect.reason === "expired",
        ),
      );
      assert.ok(!received.some((entry) => entry.path === "/expired"));
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  },
);

for (const initiallyExists of [true, false]) {
  for (const scenario of [
    { outcome: "command_failed", suffix: "false" },
    { outcome: "output_overflow", suffix: "printf 123456789" },
    { outcome: "timeout", suffix: "while :; do :; done" },
    { outcome: "policy_denied", suffix: "read value < /data/output.txt; true" },
  ]) {
    test(
      `public writer discards mutations on ${scenario.outcome}, initially exists=${initiallyExists}`,
      { skip: shouldSkipVmTests(), timeout: 120_000 },
      async () => {
        const target = path.join(
          tempRoot,
          `failure-${scenario.outcome}-${initiallyExists}.txt`,
        );
        if (initiallyExists) fs.writeFileSync(target, "original");
        const context = CapabilityInvocationContext.create(
          writerCeiling([target]),
          { console: "stdio" },
        );
        const request = writerRequest(target, {
          invocationId: `failure-${scenario.outcome}-${initiallyExists}`,
          launch: {
            executable: "/bin/busybox",
            args: [
              "sh",
              "-c",
              `printf private-result > /data/output.txt; ${scenario.suffix}`,
            ],
          },
          limits: {
            outputBytes: scenario.outcome === "output_overflow" ? 4 : 1024,
            wallTimeMs: 1000,
          },
        });
        if (!initiallyExists)
          request.capabilities.filesystem.operations.push("create");
        const result = await context.invoke(request);
        assert.equal(result.outcome, scenario.outcome, result.error);
        assert.ok(
          result.evidence.observed.some(
            (effect) => effect.operation === "write",
          ),
        );
        assert.equal(result.evidence.teardown.vmStopped, true);
        if (initiallyExists)
          assert.equal(fs.readFileSync(target, "utf8"), "original");
        else assert.equal(fs.existsSync(target), false);
        assert.equal(
          result.evidence.outputDigest,
          initiallyExists
            ? `sha256:${createHash("sha256").update("original").digest("hex")}`
            : null,
        );
      },
    );
  }
}
