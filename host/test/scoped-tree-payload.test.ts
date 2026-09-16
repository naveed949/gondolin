import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  canonicalizeScopedTreeInvocationRequest,
  getCapabilityInvocationFeatureManifest,
  normalizeScopedTreeCeiling,
  SCOPED_RUNNER_GUARANTEES,
  SCOPED_TREE_POLICY_VERSIONS,
  SCOPED_TREE_PROFILE,
  ScopedTreeInvocationContext,
  verifyScopedTreeInvocationResult,
} from "../src/index.ts";
import { __test as invocationTest } from "../src/scoped-tree-invocation.ts";
import {
  acquirePinnedDirectory,
  pinHostDirectoryIdentity,
  ScopedTreeProvider,
} from "../src/scoped-tree-vfs.ts";
import { VM } from "../src/vm/core.ts";
import { unavailableRuntimeIdentity } from "../src/capability-runtime.ts";

const digest = createHash("sha256").update("unit-runner").digest("hex");
const executableDigest = `sha256:${digest}`;

function makeRoots() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gondolin-tree-"));
  const repository = path.join(root, "repo");
  const cache = path.join(root, "cache");
  const temp = path.join(root, "tmp");
  fs.mkdirSync(repository);
  fs.mkdirSync(path.join(repository, "nested"));
  fs.writeFileSync(path.join(repository, "readme.txt"), "repo\n");
  fs.mkdirSync(cache);
  fs.mkdirSync(path.join(cache, "nested"));
  fs.mkdirSync(temp);
  return { root, repository, cache, temp };
}

function ceiling(repositoryHostPath: string) {
  return {
    schemaVersion: "gondolin.scoped-tree-ceiling/v1",
    profile: SCOPED_TREE_PROFILE,
    repositoryHostPath,
    targets: [
      {
        id: "malicious-runner",
        executable: "/opt/gondolin/malicious-runner",
        executableDigest,
        args: ["--fixture"],
      },
    ],
    limits: {
      maxCpuMs: 2_000,
      maxMemoryBytes: 64 * 1024 * 1024,
      maxChildren: 4,
      maxOutputBytes: 4096,
      maxWallMs: 5_000,
    },
  };
}

function request(cacheHostPath: string, tempHostPath: string) {
  return {
    schemaVersion: "gondolin.scoped-tree-request/v1",
    invocationId: "tree-1",
    profile: SCOPED_TREE_PROFILE,
    target: "malicious-runner",
    filesystem: { cacheHostPath, tempHostPath },
    limits: {
      cpuMs: 1_000,
      memoryBytes: 32 * 1024 * 1024 + 1,
      children: 2,
      outputBytes: 1024,
      wallMs: 2_000,
    },
  };
}

test("scoped-tree canonicalization is byte-stable and rejects public command fields", () => {
  const roots = makeRoots();
  try {
    const first = canonicalizeScopedTreeInvocationRequest(
      request(roots.cache, roots.temp),
    );
    const second = canonicalizeScopedTreeInvocationRequest({
      limits: {
        wallMs: 2_000,
        outputBytes: 1024,
        children: 2,
        memoryBytes: 32 * 1024 * 1024 + 1,
        cpuMs: 1_000,
      },
      filesystem: { tempHostPath: roots.temp, cacheHostPath: roots.cache },
      target: "malicious-runner",
      profile: SCOPED_TREE_PROFILE,
      invocationId: "tree-1",
      schemaVersion: "gondolin.scoped-tree-request/v1",
    });
    assert.equal(first.canonical, second.canonical);
    assert.match(first.digest, /^sha256:[0-9a-f]{64}$/);
    for (const invalid of [
      {
        ...request(roots.cache, roots.temp),
        launch: { executable: "/bin/sh" },
      },
      { ...request(roots.cache, roots.temp), environment: { HOME: "/" } },
      { ...request(roots.cache, roots.temp), hooks: {} },
      { ...request(roots.cache, roots.temp), command: "id" },
      {
        ...request(roots.cache, roots.temp),
        limits: {
          ...request(roots.cache, roots.temp).limits,
          writableStorageBytes: 1,
        },
      },
    ]) {
      assert.throws(() => canonicalizeScopedTreeInvocationRequest(invalid));
    }
  } finally {
    fs.rmSync(roots.root, { recursive: true, force: true });
  }
});

test("immutable ceiling rejects unregistered targets, widened limits, and reused roots", async () => {
  const roots = makeRoots();
  try {
    const bound = normalizeScopedTreeCeiling(ceiling(roots.repository));
    assert.ok(Object.isFrozen(bound));
    const context = ScopedTreeInvocationContext.create(bound);
    assert.equal(context.ceiling.profile, SCOPED_TREE_PROFILE);
    await assert.rejects(
      () =>
        context.execute({
          ...request(roots.cache, roots.temp),
          target: "unknown-runner",
        }),
      /unregistered/,
    );
    await assert.rejects(() =>
      context.execute({
        ...request(roots.cache, roots.temp),
        limits: { ...request(roots.cache, roots.temp).limits, cpuMs: 2_001 },
      }),
    );
    await assert.rejects(() =>
      context.execute({
        ...request(roots.cache, roots.temp),
        filesystem: { cacheHostPath: roots.cache, tempHostPath: roots.cache },
      }),
    );
  } finally {
    fs.rmSync(roots.root, { recursive: true, force: true });
  }
});

test("live tree VFS allows in-root reads and late private regular files, not mkdir or escapes", () => {
  const roots = makeRoots();
  try {
    const repo = new ScopedTreeProvider(
      "repository",
      acquirePinnedDirectory(roots.repository),
    );
    const cache = new ScopedTreeProvider(
      "private",
      acquirePinnedDirectory(roots.cache),
    );
    try {
      assert.equal(repo.statSync("/readme.txt").isFile(), true);
      assert.deepEqual(
        repo.readdirSync("/").sort(),
        ["nested", "readme.txt"].sort(),
      );
      assert.throws(
        () => repo.openSync("/created.txt", "w"),
        /EACCES|ERRNO_13/,
      );
      cache.openSync("/late.bin", "w").writeFileSync("payload");
      cache.openSync("/late.bin", "r").closeSync();
      assert.equal(
        fs.readFileSync(path.join(roots.cache, "late.bin"), "utf8"),
        "payload",
      );
      const rewrite = cache.openSync("/late.bin", "r+");
      rewrite.writeFileSync("rewritten");
      rewrite.closeSync();
      cache.truncateSync("/late.bin", 5);
      assert.equal(
        fs.readFileSync(path.join(roots.cache, "late.bin"), "utf8"),
        "rewri",
      );
      cache.renameSync("/late.bin", "/renamed.bin");
      cache.linkSync("/renamed.bin", "/linked.bin");
      assert.throws(
        () => cache.renameSync("/renamed.bin", "/nested/away.bin"),
        /EACCES|ERRNO_13/,
      );
      assert.throws(() => cache.mkdirSync("/newdir"), /EACCES|ERRNO_13/);
      assert.throws(
        () => cache.symlinkSync("/etc/passwd", "/escape"),
        /EACCES|ERRNO_13/,
      );
      assert.throws(() => cache.chmodSync("/renamed.bin"), /EACCES|ERRNO_13/);
      assert.throws(() => repo.statSync("/../readme.txt"), /EACCES|ERRNO_13/);
      fs.symlinkSync("/etc/passwd", path.join(roots.repository, "outside"));
      assert.throws(() => repo.statSync("/outside"), /ENOENT|EACCES|ERRNO/);
      fs.symlinkSync("/proc/self/fd/0", path.join(roots.repository, "magic"));
      assert.throws(() => repo.statSync("/magic"), /EACCES|ERRNO_13/);
      fs.symlinkSync("readme.txt", path.join(roots.repository, "inside"));
      assert.equal(repo.statSync("/inside").isFile(), true);
    } finally {
      repo.closeRoot();
      cache.closeRoot();
    }
  } finally {
    fs.rmSync(roots.root, { recursive: true, force: true });
  }
});

test("root replacement after pin does not inherit the original grant", () => {
  const roots = makeRoots();
  try {
    const pinned = pinHostDirectoryIdentity(roots.repository);
    const replaced = path.join(roots.root, "replaced");
    fs.renameSync(roots.repository, replaced);
    fs.mkdirSync(roots.repository);
    fs.writeFileSync(path.join(roots.repository, "readme.txt"), "other\n");
    assert.throws(
      () => acquirePinnedDirectory(roots.repository, pinned.identity),
      /identity changed/,
    );
  } finally {
    fs.rmSync(roots.root, { recursive: true, force: true });
  }
});

test("payload usage never rounds memory up or treats QEMU CPU as payload CPU", () => {
  const output = {
    stdoutText: "ok",
    stderrText: "",
  } as { stdoutText: string; stderrText: string };
  const usage = invocationTest.payloadUsage(
    {
      cpuMs: 1000,
      memoryBytes: 32 * 1024 * 1024 + 1,
      children: 2,
      outputBytes: 1024,
      wallMs: 2000,
    },
    {
      cpuTimeMs: 12,
      memoryPeakBytes: 4096,
      pidsPeak: 1,
      exhausted: null,
      resourceGroupRemoved: true,
    },
    output as never,
    40,
  );
  assert.equal(usage.cpuMs, 12);
  assert.equal(usage.peakMemoryBytes, 4096);
  assert.equal(usage.peakChildren, 0);
  assert.equal(usage.observation, "complete");
  assert.equal(
    invocationTest.vmProvisioningMemory(32 * 1024 * 1024 + 1),
    "128M",
  );
  const missing = invocationTest.payloadUsage(
    {
      cpuMs: 1000,
      memoryBytes: 4096,
      children: 1,
      outputBytes: 1024,
      wallMs: 2000,
    },
    {
      cpuTimeMs: null,
      memoryPeakBytes: 1,
      pidsPeak: 1,
      exhausted: null,
      observationFailed: true,
      resourceGroupRemoved: true,
    },
    output as never,
    10,
  );
  assert.equal(missing.observation, "failed");
  assert.equal(missing.cpuMs, null);
});

test("feature manifest advertises the tree profile without qualifying resources", () => {
  const manifest = getCapabilityInvocationFeatureManifest();
  assert.equal(manifest.profiles["scoped-tree-runner/v1"], "active");
  assert.equal(manifest.profiles["scoped-runner"], "active");
  assert.equal(
    manifest.requestSchemas["gondolin.scoped-tree-request/v1"],
    "active",
  );
  assert.equal(manifest.operations["filesystem.read.tree"], "active");
  assert.equal(
    manifest.operations["filesystem.write.tree.regular-file"],
    "active",
  );
  assert.equal(manifest.operations["process.fork-denied"], "active");
  assert.equal(manifest.guarantees["per-invocation-cpu"], "unverified");
  assert.equal(
    manifest.operations["evidence.resource-usage.host-observed"],
    "unverified",
  );
  for (const guarantee of SCOPED_RUNNER_GUARANTEES) {
    assert.equal(manifest.guarantees[guarantee], "active", guarantee);
  }
  assert.equal(SCOPED_TREE_POLICY_VERSIONS.cpuRoundingAllowanceMs, 5);
});

test("runtime refuses extra authority channels and missing tree feature before launch", async () => {
  const roots = makeRoots();
  try {
    for (const runtime of [
      { env: {} },
      { credentialStore: {} },
      { fetch() {} },
    ]) {
      assert.throws(() =>
        ScopedTreeInvocationContext.create(
          ceiling(roots.repository),
          runtime as never,
        ),
      );
    }
    const saved = VM.create;
    VM.create = (async () => ({
      id: "unit-tree",
      getRuntimeIdentity: () => ({
        ...unavailableRuntimeIdentity(),
        guestFeatures: invocationTest.REQUIRED_FEATURES.filter(
          (feature) => feature !== "exec.scoped-tree-vfs/v1",
        ),
      }),
      start: async () => {
        throw new Error("must not start");
      },
      getHostPid: () => null,
      close: async () => {},
      exec: async () => ({ exitCode: 0 }),
    })) as typeof VM.create;
    try {
      await assert.rejects(
        ScopedTreeInvocationContext.create(ceiling(roots.repository)).execute(
          request(roots.cache, roots.temp),
        ),
        /exec.scoped-tree-vfs\/v1/,
      );
    } finally {
      VM.create = saved;
    }
  } finally {
    fs.rmSync(roots.root, { recursive: true, force: true });
  }
});

test("scoped-tree controller launches the registered target with payload cgroup bounds", async () => {
  const roots = makeRoots();
  const saved = VM.create;
  let execArgs: string[] = [];
  let execOptions: Record<string, unknown> = {};
  let vmOptions: Record<string, unknown> = {};
  VM.create = (async (value) => {
    vmOptions = value as Record<string, unknown>;
    return {
      id: "unit-tree-run",
      getRuntimeIdentity: () => ({
        ...unavailableRuntimeIdentity(),
        guestFeatures: [...invocationTest.REQUIRED_FEATURES],
      }),
      start: async () => {},
      getHostPid: () => 2147483646,
      close: async () => {},
      exec: async (command: string[], options: Record<string, unknown>) => {
        execArgs = command;
        execOptions = options;
        return {
          exitCode: 0,
          resourceUsage: {
            cpuTimeMs: 9,
            memoryPeakBytes: 2048,
            pidsPeak: 1,
            exhausted: null,
            resourceGroupRemoved: true,
          },
        };
      },
    };
  }) as typeof VM.create;
  try {
    const result = await ScopedTreeInvocationContext.create(
      ceiling(roots.repository),
    ).execute(request(roots.cache, roots.temp));
    assert.equal(result.outcome, "success");
    assert.deepEqual(execArgs, ["/opt/gondolin/malicious-runner", "--fixture"]);
    assert.equal(execOptions.clearEnv, true);
    assert.equal(execOptions.env, undefined);
    assert.equal(execOptions.denyFork, true);
    assert.equal(execOptions.denyDescendants, false);
    assert.deepEqual(execOptions.allowedWritableTrees, [
      "/data/cache",
      "/data/tmp",
    ]);
    assert.deepEqual(
      (execOptions.resourceLimits as { pids: number; memoryBytes: number })
        .pids,
      3,
    );
    assert.equal(
      (execOptions.resourceLimits as { memoryBytes: number }).memoryBytes,
      32 * 1024 * 1024 + 1,
    );
    assert.equal(result.resourceAccounting.peakChildren, 0);
    assert.equal(result.evidence.environment, "empty");
    assert.equal(result.evidence.network, "none");
    assert.equal(result.evidence.credentials, "none");
    assert.equal(result.evidence.resources.cgroupPidsCeiling, 3);
    const mounts = (vmOptions.vfs as { mounts: Record<string, unknown> })
      .mounts;
    assert.ok(mounts["/data/repo"]);
    assert.ok(mounts["/data/cache"]);
    assert.ok(mounts["/data/tmp"]);
    const verified = verifyScopedTreeInvocationResult(result, {
      requestDigest: result.evidence.requestDigest,
      ceilingDigest: result.evidence.ceilingDigest,
      runtime: result.evidence.runtime,
      qualificationId: result.evidence.qualificationId,
    });
    assert.equal(verified.valid, true, verified.errors.join("; "));
  } finally {
    VM.create = saved;
    fs.rmSync(roots.root, { recursive: true, force: true });
  }
});

test("missing payload observation cannot settle as success", async () => {
  const roots = makeRoots();
  const saved = VM.create;
  VM.create = (async () => ({
    id: "unit-tree-missing",
    getRuntimeIdentity: () => ({
      ...unavailableRuntimeIdentity(),
      guestFeatures: [...invocationTest.REQUIRED_FEATURES],
    }),
    start: async () => {},
    getHostPid: () => 2147483645,
    close: async () => {},
    exec: async () => ({
      exitCode: 0,
      resourceUsage: {
        cpuTimeMs: null,
        memoryPeakBytes: null,
        pidsPeak: null,
        exhausted: null,
        observationFailed: true,
        resourceGroupRemoved: true,
      },
    }),
  })) as typeof VM.create;
  try {
    const result = await ScopedTreeInvocationContext.create(
      ceiling(roots.repository),
    ).execute(request(roots.cache, roots.temp));
    assert.notEqual(result.outcome, "success");
    assert.equal(result.resourceAccounting.observation, "failed");
    assert.equal(result.resourceAccounting.cpuMs, null);
  } finally {
    VM.create = saved;
    fs.rmSync(roots.root, { recursive: true, force: true });
  }
});
