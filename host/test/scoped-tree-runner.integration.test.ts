import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  CAPABILITY_CEILING_SCHEMA_VERSION,
  CAPABILITY_INVOCATION_SCHEMA_VERSION,
  SCOPED_TREE_RUNNER_GUARANTEES,
  ScopedTreeRunnerInvocationContext,
  observeRootIdentity,
  preparePrivateRoot,
  type ScopedTreeRunnerCeiling,
  type ScopedTreeRunnerInvocationRequest,
} from "../src/index.ts";
import { shouldSkipVmTests } from "./helpers/vm-fixture.ts";

const parent = fs.mkdtempSync(path.join(os.tmpdir(), "gondolin-tree-int-"));
const repository = path.join(parent, "repo");
fs.mkdirSync(repository);
fs.writeFileSync(path.join(repository, "source.ts"), "export const answer = 42;\n");

test.after(() => fs.rmSync(parent, { recursive: true, force: true }));

function freshPrivate() {
  return {
    cache: preparePrivateRoot(parent, "cache"),
    temp: preparePrivateRoot(parent, "temp"),
  };
}

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
      maxCpuMs: 60_000,
      maxMemoryBytes: 512 * 1024 * 1024,
      maxChildren: 8,
      maxOutputBytes: 64 * 1024,
      maxWallMs: 60_000,
    },
    guarantees: [...SCOPED_TREE_RUNNER_GUARANTEES],
    ...overrides,
  };
}

function request(
  invocationId: string,
  args: string[],
  privateRoots = freshPrivate(),
  limitOverrides: Partial<ScopedTreeRunnerInvocationRequest["limits"]> = {},
): ScopedTreeRunnerInvocationRequest {
  return {
    schemaVersion: CAPABILITY_INVOCATION_SCHEMA_VERSION,
    invocationId,
    profile: "scoped-tree-runner",
    launch: {
      executable: "/bin/busybox",
      args,
      cwd: "/data/repo",
    },
    capabilities: {
      filesystem: {
        repository: {
          hostPath: repository,
          guestPath: "/data/repo",
          identity: observeRootIdentity(repository, "repository"),
        },
        cache: { ...privateRoots.cache, guestPath: "/data/cache" },
        temp: { ...privateRoots.temp, guestPath: "/data/tmp" },
      },
      network: "none",
      credentials: "none",
      git: "none",
      ipc: "none",
      devices: "none",
    },
    limits: {
      cpuMs: 30_000,
      memoryBytes: 64 * 1024 * 1024 + 4096,
      children: 0,
      outputBytes: 16 * 1024,
      wallMs: 30_000,
      ...limitOverrides,
    },
    requiredGuarantees: [...SCOPED_TREE_RUNNER_GUARANTEES],
  };
}

test(
  "scoped-tree-runner/v1 enforces live roots, empty ambient state, and payload resources",
  { skip: shouldSkipVmTests(), timeout: 120_000 },
  async (t) => {
    const context = ScopedTreeRunnerInvocationContext.create(ceiling());

    await t.test("reads the live repository tree", async () => {
      const result = await context.invoke(
        request("tree-read", ["cat", "/data/repo/source.ts"]),
      );
      assert.equal(result.outcome, "success", result.error);
      assert.equal(result.stdout, "export const answer = 42;\n");
      assert.equal(result.resourceAccounting.observations.cpu, "payload-cgroup-wait4");
      assert.equal(result.resourceAccounting.usage.children, 0);
      assert.equal(result.evidence.policyVersions.admission, "scoped-tree-runner/v1");
      assert.equal(result.evidence.policyVersions.resources, "payload-cgroup-wait4/v1");
      assert.equal(result.evidence.teardown.completedAt, result.evidence.settledAt);
      assert.equal(result.evidence.teardown.privateRootsDestroyed, true);
      assert.equal(result.evidence.teardown.vfsHandlesRevoked, true);
      assert.equal(result.evidence.teardown.vmStopped, true);
    });

    await t.test("late-creates a regular file under the private cache root", async () => {
      const result = await context.invoke(
        request("tree-late-create", [
          "cp",
          "/data/repo/source.ts",
          "/data/cache/late.txt",
        ]),
      );
      assert.equal(result.outcome, "success", result.error);
    });

    await t.test("environment is empty under the seeded credential challenge", async () => {
      const result = await context.invoke(request("tree-empty-env", ["env"]));
      assert.equal(result.outcome, "success", result.error);
      assert.equal(result.stdout.trim(), "");
      assert.doesNotMatch(result.stdout, /GONDOLIN_SCOPED_TREE_CHALLENGE/);
      assert.doesNotMatch(result.stdout, /seeded-credential/);
    });

    await t.test("only standard streams survive launch", async () => {
      const result = await context.invoke(
        request("tree-fds", ["ls", "/proc/self/fd"]),
      );
      assert.equal(result.outcome, "success", result.error);
      const fds = result.stdout
        .split("\n")
        .map((line) => line.trim())
        .filter((line) => /^\d+$/.test(line))
        .map(Number);
      assert.ok(fds.includes(0) && fds.includes(1) && fds.includes(2));
      assert.equal(
        fds.some((fd) => fd >= 10),
        false,
        `unexpected inherited descriptors: ${fds.join(",")}`,
      );
    });

    await t.test("repository writes, mkdir, and symlink are denied", async () => {
      const write = await context.invoke(
        request("tree-repo-write", ["touch", "/data/repo/escape.txt"]),
      );
      assert.notEqual(write.outcome, "success");
      assert.equal(fs.existsSync(path.join(repository, "escape.txt")), false);

      const mkdir = await context.invoke(
        request("tree-mkdir", ["mkdir", "/data/cache/dir"]),
      );
      assert.notEqual(mkdir.outcome, "success");

      const symlink = await context.invoke(
        request("tree-symlink", ["ln", "-s", "x", "/data/tmp/s"]),
      );
      assert.notEqual(symlink.outcome, "success");
    });

    await t.test("fork is denied by the initial profile", async () => {
      const result = await context.invoke(
        request("tree-fork-denied", [
          "sh",
          "-c",
          "busybox echo child-ran & wait; printf done",
        ]),
      );
      assert.notEqual(result.outcome, "success");
      assert.doesNotMatch(result.stdout, /child-ran/);
    });

    await t.test("payload CPU exhaustion is guest cgroup, not QEMU", async () => {
      const result = await context.invoke(
        request(
          "tree-cpu",
          ["sh", "-c", "while :; do :; done"],
          freshPrivate(),
          { cpuMs: 150, wallMs: 10_000 },
        ),
      );
      assert.equal(result.outcome, "cpu_exhausted", result.error);
      assert.equal(result.resourceAccounting.exhausted, "cpu");
      assert.equal(result.resourceAccounting.observations.cpu, "payload-cgroup-wait4");
      assert.ok(result.evidence.resources.usage.setupMs >= 0);
      assert.ok(result.evidence.resources.usage.teardownMs >= 0);
    });

    await t.test("byte memory ceiling is enforced without MiB rounding", async () => {
      const result = await context.invoke(
        request(
          "tree-memory",
          ["sh", "-c", "x=x; while :; do x=$x$x; done"],
          freshPrivate(),
          {
            memoryBytes: 4 * 1024 * 1024 + 111,
            cpuMs: 30_000,
            wallMs: 30_000,
            children: 0,
          },
        ),
      );
      assert.equal(result.outcome, "memory_exhausted", result.error);
      assert.equal(result.resourceAccounting.exhausted, "memory");
      assert.equal(result.resourceAccounting.limits.memoryBytes, 4 * 1024 * 1024 + 111);
    });

    await t.test("concurrent invocations use disjoint private roots", async () => {
      const firstRoots = freshPrivate();
      const secondRoots = freshPrivate();
      const [first, second] = await Promise.all([
        context.invoke(
          request("tree-concurrent-a", ["cat", "/data/repo/source.ts"], firstRoots),
        ),
        context.invoke(
          request("tree-concurrent-b", ["cat", "/data/repo/source.ts"], secondRoots),
        ),
      ]);
      assert.equal(first.outcome, "success", first.error);
      assert.equal(second.outcome, "success", second.error);
      assert.notEqual(first.evidence.roots.cache, second.evidence.roots.cache);
      assert.notEqual(first.evidence.roots.temp, second.evidence.roots.temp);
      assert.notEqual(first.evidence.executionId, second.evidence.executionId);
    });
  },
);
