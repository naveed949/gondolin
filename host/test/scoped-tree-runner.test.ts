import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  CAPABILITY_CEILING_SCHEMA_VERSION,
  CAPABILITY_INVOCATION_SCHEMA_VERSION,
  CapabilityAdmissionError,
  getCapabilityInvocationFeatureManifest,
} from "../src/index.ts";
import { buildExecRequest } from "../src/sandbox/virtio-protocol.ts";
import {
  SCOPED_TREE_CPU_WAIT4_ALLOWANCE_USEC,
  SCOPED_TREE_RUNNER_GUARANTEES,
  ScopedTreeRunnerInvocationContext,
  canonicalizeScopedTreeRunnerInvocationRequest,
  cpuAgreesWithWait4,
  observeRootIdentity,
  peakChildren,
  preparePrivateRoot,
  __test,
  type ScopedTreeRunnerCeiling,
  type ScopedTreeRunnerInvocationRequest,
} from "../src/scoped-tree-runner.ts";

const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "gondolin-tree-runner-"));
const repository = path.join(tempRoot, "repo");
fs.mkdirSync(repository);
fs.writeFileSync(path.join(repository, "source.ts"), "export const answer = 42;\n");
const cache = preparePrivateRoot(tempRoot, "cache");
const temp = preparePrivateRoot(tempRoot, "temp");
const repoIdentity = observeRootIdentity(repository, "repository");

test.after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));

function ceiling(
  overrides: Partial<ScopedTreeRunnerCeiling> = {},
): ScopedTreeRunnerCeiling {
  return {
    schemaVersion: CAPABILITY_CEILING_SCHEMA_VERSION,
    profile: "scoped-tree-runner",
    allowedExecutables: ["/bin/busybox"],
    allowedWorkingDirectories: ["/data/repo"],
    filesystem: {
      repositoryHostPaths: [repository],
      repositoryGuestPaths: ["/data/repo"],
      cacheGuestPaths: ["/data/cache"],
      tempGuestPaths: ["/data/tmp"],
    },
    limits: {
      maxCpuMs: 10_000,
      maxMemoryBytes: 64 * 1024 * 1024 + 123,
      maxChildren: 4,
      maxOutputBytes: 4096,
      maxWallMs: 10_000,
    },
    guarantees: [...SCOPED_TREE_RUNNER_GUARANTEES],
    ...overrides,
  };
}

function request(
  overrides: Partial<ScopedTreeRunnerInvocationRequest> = {},
): ScopedTreeRunnerInvocationRequest {
  return {
    schemaVersion: CAPABILITY_INVOCATION_SCHEMA_VERSION,
    invocationId: "tree-1",
    profile: "scoped-tree-runner",
    launch: {
      executable: "/bin/busybox",
      args: ["cat", "/data/repo/source.ts"],
      cwd: "/data/repo",
    },
    capabilities: {
      filesystem: {
        repository: {
          hostPath: repository,
          guestPath: "/data/repo",
          identity: repoIdentity,
        },
        cache: { ...cache, guestPath: "/data/cache" },
        temp: { ...temp, guestPath: "/data/tmp" },
      },
      network: "none",
      credentials: "none",
      git: "none",
      ipc: "none",
      devices: "none",
    },
    limits: {
      cpuMs: 5000,
      memoryBytes: 32 * 1024 * 1024 + 77,
      children: 0,
      outputBytes: 1024,
      wallMs: 5000,
    },
    requiredGuarantees: [...SCOPED_TREE_RUNNER_GUARANTEES],
    ...overrides,
  };
}

test("scoped-tree-runner canonicalization is byte-stable and rejects extra fields", () => {
  const first = canonicalizeScopedTreeRunnerInvocationRequest(request());
  const second = canonicalizeScopedTreeRunnerInvocationRequest(
    JSON.parse(first.canonical) as ScopedTreeRunnerInvocationRequest,
  );
  assert.equal(first.digest, second.digest);
  assert.equal(first.request.limits.memoryBytes, 32 * 1024 * 1024 + 77);
  assert.throws(
    () =>
      canonicalizeScopedTreeRunnerInvocationRequest({
        ...request(),
        extra: true,
      }),
    (error: unknown) =>
      error instanceof CapabilityAdmissionError &&
      error.code === "invalid_request",
  );
});

test("byte memory limits are not rounded up to MiB", () => {
  const canonical = canonicalizeScopedTreeRunnerInvocationRequest(
    request({ limits: { ...request().limits, memoryBytes: 4097 } }),
  );
  assert.equal(canonical.request.limits.memoryBytes, 4097);
  const context = ScopedTreeRunnerInvocationContext.create(
    ceiling({ limits: { ...ceiling().limits, maxMemoryBytes: 4097 } }),
  );
  assert.equal(context.ceiling.limits.maxMemoryBytes, 4097);
});

test("children zero is valid and does not permit fork", () => {
  const canonical = canonicalizeScopedTreeRunnerInvocationRequest(request());
  assert.equal(canonical.request.limits.children, 0);
  assert.equal(peakChildren(1), 0);
  assert.equal(peakChildren(0), null);
  assert.equal(peakChildren(null), null);
});

test("wait4 CPU cross-check uses the native 5 ms allowance", () => {
  assert.equal(SCOPED_TREE_CPU_WAIT4_ALLOWANCE_USEC, 5000);
  assert.equal(cpuAgreesWithWait4(10_000, 10), true);
  assert.equal(cpuAgreesWithWait4(10_000, 15), true);
  assert.equal(cpuAgreesWithWait4(10_000, 16), false);
  assert.equal(cpuAgreesWithWait4(null, 1), false);
  assert.equal(cpuAgreesWithWait4(1000, null), false);
});

test("observation loss and contradictory CPU cannot be treated as success", () => {
  assert.equal(
    __test.validPayloadResourceUsage({
      cpuTimeMs: 1,
      memoryPeakBytes: 4096,
      pidsPeak: 1,
      exhausted: "memory",
      observationFailed: true,
      resourceGroupRemoved: true,
      wait4CpuMs: 1,
      cgroupCpuUsec: 1000,
    }),
    true,
  );
  assert.equal(cpuAgreesWithWait4(1000, 20), false);
  assert.equal(peakChildren(null), null);
  assert.equal(__test.resourceOutcome("pids"), "children_exhausted");
  assert.equal(__test.outcomeToExhausted("children_exhausted"), "children");
});

test("immutable ceiling contracts each independent resource budget", async () => {
  const context = ScopedTreeRunnerInvocationContext.create(ceiling());
  const wideningLimits = [
    { cpuMs: 10_001 },
    { memoryBytes: 64 * 1024 * 1024 + 124 },
    { children: 5 },
    { outputBytes: 4097 },
    { wallMs: 10_001 },
  ];
  for (const [index, override] of wideningLimits.entries()) {
    await assert.rejects(
      context.invoke(
        request({
          invocationId: `widening-limit-${index}`,
          limits: { ...request().limits, ...override },
        }),
      ),
      (error: unknown) =>
        error instanceof CapabilityAdmissionError &&
        error.code === "ceiling_widening",
    );
  }
});

test("exec protocol carries tree roots, empty-env, and payload pids = children+1", () => {
  const payload = buildExecRequest(3, {
    cmd: "/bin/busybox",
    clear_env: true,
    deny_descendants: true,
    deny_fork: true,
    isolate_ipc: true,
    isolate_devices: true,
    isolate_proc: false,
    allowed_readable_directories: ["/data/repo"],
    allowed_writable_directories: ["/data/cache", "/data/tmp"],
    resource_limits: {
      cpu_time_ms: 5000,
      memory_bytes: 4097,
      pids: 1,
    },
  });
  assert.equal(payload.p.isolate_proc, false);
  assert.equal(payload.p.deny_fork, true);
  assert.equal(payload.p.resource_limits?.memory_bytes, 4097);
  assert.equal(payload.p.resource_limits?.pids, 1);
  assert.deepEqual(payload.p.allowed_writable_directories, [
    "/data/cache",
    "/data/tmp",
  ]);
});

test("feature manifest does not advertise scoped-tree-runner before runtime evidence", () => {
  const manifest = getCapabilityInvocationFeatureManifest();
  assert.equal(manifest.profiles["scoped-tree-runner"], undefined);
  assert.equal(manifest.profiles["scoped-runner"], "active");
});

test("private-root destruction is observed independently of vm.close", () => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), "gondolin-tree-destroy-"));
  const isolatedCache = preparePrivateRoot(parent, "cache");
  const isolatedTemp = preparePrivateRoot(parent, "temp");
  fs.writeFileSync(path.join(isolatedCache.hostPath, "keep"), "x");
  const destroyed = __test.destroyPrivateRoots(
    request({
      capabilities: {
        ...request().capabilities,
        filesystem: {
          ...request().capabilities.filesystem,
          cache: isolatedCache,
          temp: isolatedTemp,
        },
      },
    }),
  );
  assert.equal(destroyed, true);
  assert.equal(fs.existsSync(isolatedCache.hostPath), false);
  assert.equal(fs.existsSync(isolatedTemp.hostPath), false);
  fs.rmSync(parent, { recursive: true, force: true });
});
