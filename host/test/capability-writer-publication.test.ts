import assert from "node:assert/strict";
import crypto, { createHash } from "node:crypto";
import { syncBuiltinESMExports } from "node:module";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { Writable } from "node:stream";
import test from "node:test";
import {
  VM,
  CAPABILITY_CEILING_SCHEMA_VERSION,
  CAPABILITY_INVOCATION_SCHEMA_VERSION,
  CapabilityInvocationContext,
  EXACT_WRITER_GUARANTEES,
  type ExactWriterCeiling,
  type ExactWriterInvocationRequest,
} from "../src/index.ts";
import { unavailableRuntimeIdentity } from "../src/capability-runtime.ts";
import {
  commitExactWriterTarget,
  getHostWriterTargetIdentity,
  settleExactWriterTarget,
} from "../src/capability-filesystem.ts";
import {
  sealCapabilityEvidence,
  verifyCapabilityInvocationResult,
  probeCapabilityInvocationTeardown,
} from "../src/invocation-evidence.ts";
import type { CapabilitySnapshotProvider } from "../src/capability-snapshot.ts";

const descriptorFaults = ["parent", "staging", "current", "verification"].flatMap(
  (phase) => ["leak", "reuse"].map((effect) => `${phase}_${effect}`),
);

function injectDescriptorFault(
  t: import("node:test").TestContext,
  target: string,
  fault: string,
  active: () => boolean,
  published: () => boolean,
): () => void {
  const open = fs.openSync;
  const close = fs.closeSync;
  const owned = new Set<number>();
  let selected: number | undefined;
  let fired = false;
  let replacement: number | undefined;
  t.mock.method(fs, "openSync", (...args: Parameters<typeof open>) => {
    const fd = open(...args);
    if (!active() || fired) return fd;
    const name = String(args[0]);
    const phase = fault.split("_")[0];
    if (
      (phase === "parent" && name === path.dirname(target)) ||
      (phase === "staging" && name.includes(".gondolin-commit-")) ||
      (phase === "current" && name === target && !published()) ||
      (phase === "verification" && name === target && published())
    ) selected = fd;
    return fd;
  });
  t.mock.method(fs, "closeSync", (fd: number) => {
    if (fd !== selected || fired) return close(fd);
    fired = true;
    if (fault.endsWith("reuse")) {
      close(fd);
      replacement = open(target, fs.constants.O_RDONLY);
      assert.equal(replacement, fd, "fault must exercise reused fd number");
      owned.add(replacement);
    } else owned.add(fd);
    throw new Error("descriptor close effect unavailable");
  });
  t.after(() => {
    t.mock.restoreAll();
    for (const fd of owned) {
      try { close(fd); } catch {}
    }
  });
  return () => {
    assert.ok(fired, "selected descriptor fault reached");
    if (replacement !== undefined)
      assert.ok(fs.fstatSync(replacement).isFile(), "unrelated reused fd remains open");
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

// These public-API controller regressions deliberately mock the VM. They are
// not runtime conformance or independent teardown evidence.
for (const initiallyExists of [true, false]) {
  for (const scenario of [
    "success",
    "command_failed",
    "policy_denied",
    "descendant_denied",
    "transport_failure",
    "timeout",
    "output_overflow",
    "teardown_failure",
    "runner_alive",
    "cleanup_failure",
    "verification_failure",
    "unlink_failure",
    "visibility_throw",
    "signing_failure",
    ...(initiallyExists ? descriptorFaults : []),
  ]) {
    test(`writer ${scenario} publication, initially exists=${initiallyExists}`, async (t) => {
      const directory = fs.mkdtempSync(
        path.join(os.tmpdir(), "gondolin-publication-"),
      );
      t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
      const target = path.join(directory, "target.txt");
      if (initiallyExists) fs.writeFileSync(target, "original");
      let publicationActive = false;
      const assertUnpublished = () => {
        if (initiallyExists)
          assert.equal(fs.readFileSync(target, "utf8"), "original");
        else assert.equal(fs.existsSync(target), false);
      };
      t.mock.method(
        VM,
        "create",
        async (options: Parameters<typeof VM.create>[0]) => {
          const provider = options!.vfs!.mounts![
            "/"
          ] as CapabilitySnapshotProvider;
          const hooks = options!.vfs!.hooks as unknown as {
            before(context: { op: string; path: string; flags?: string }): void;
            after(context: { op: string; path: string; flags?: string }): void;
          };
          return {
            id: "mock-writer-vm",
            getRuntimeIdentity: () => ({
              ...unavailableRuntimeIdentity(),
              guestFeatures: [
                "exec.clear-env/v1",
                "exec.descendants-denied/v1",
                "exec.executable-mount-policy/v1",
                "exec.exact-path-lsm/v1",
                "exec.payload-confinement/v1",
                "exec.landlock-allowlist/v1",
              ],
            }),
            start: async () => {},
            getHostPid: () =>
              scenario === "runner_alive" ? process.pid : null,
            exec: async (
              _command: unknown,
              execOptions: { stdout: Writable; signal: AbortSignal },
            ) => {
              const open = { op: "open", path: "/output.txt", flags: "w" };
              hooks.before(open);
              const handle = await provider.open("/output.txt", "w");
              hooks.after(open);
              const write = { op: "write", path: "/output.txt" };
              hooks.before(write);
              await handle.writeFile("private result");
              hooks.after(write);
              await handle.close();
              assertUnpublished();
              if (scenario === "policy_denied") {
                assert.throws(() =>
                  hooks.before({ op: "read", path: "/output.txt" }),
                );
              }
              if (scenario === "transport_failure")
                throw new Error("lost transport");
              // Return exit zero even after abort to exercise the response race.
              if (scenario === "output_overflow")
                execOptions.stdout.write("12345");
              if (scenario === "timeout") {
                await new Promise<void>((resolve) => {
                  const keepAlive = setTimeout(resolve, 500);
                  execOptions.signal.addEventListener(
                    "abort",
                    () => {
                      clearTimeout(keepAlive);
                      resolve();
                    },
                    { once: true },
                  );
                });
                assert.equal(execOptions.signal.aborted, true);
              }
              return {
                exitCode: scenario === "command_failed" ? 1 : 0,
                resourceUsage: {
                  descendantDenied: scenario === "descendant_denied",
                },
              };
            },
            close: async () => {
              assertUnpublished();
              publicationActive = true;
              if (scenario === "teardown_failure")
                throw new Error("close failed");
            },
          } as unknown as VM;
        },
      );
      let visibilityReached = false;
      const primitive = initiallyExists ? "renameSync" : "linkSync";
      const publish = fs[primitive];
      t.mock.method(fs, primitive, (...args: Parameters<typeof publish>) => {
        publish(...args);
        visibilityReached = true;
        if (scenario === "visibility_throw")
          throw new Error("ambiguous syscall result");
      });
      if (scenario === "cleanup_failure") {
        const remove = fs.rmSync;
        t.mock.method(fs, "rmSync", (...args: Parameters<typeof remove>) => {
          if (String(args[0]).includes(".gondolin-commit-"))
            throw new Error("cleanup failed");
          return remove(...args);
        });
      }
      if (scenario === "verification_failure") {
        const stat = fs.lstatSync;
        t.mock.method(fs, "lstatSync", (...args: Parameters<typeof stat>) => {
          if (visibilityReached && String(args[0]) === target)
            throw new Error("target stat failed");
          return stat(...args);
        });
      }
      if (scenario === "unlink_failure" && !initiallyExists) {
        t.mock.method(fs, "unlinkSync", () => {
          throw new Error("unlink failed");
        });
      }
      if (scenario === "signing_failure") {
        t.mock.method(crypto, "sign", () => {
          throw new Error("signing unavailable");
        });
        syncBuiltinESMExports();
        t.after(() => {
          t.mock.restoreAll();
          syncBuiltinESMExports();
        });
      }
      const checkDescriptor = descriptorFaults.includes(scenario)
        ? injectDescriptorFault(t, target, scenario, () => publicationActive, () => visibilityReached)
        : null;
      const context = CapabilityInvocationContext.create(
        writerCeiling([target]),
      );
      const request = writerRequest(target);
      if (!initiallyExists)
        request.capabilities.filesystem.operations.push("create");
      request.limits = { outputBytes: 4, wallTimeMs: 10 };
      if (scenario === "signing_failure") {
        await assert.rejects(context.invoke(request), /signing unavailable/);
        assert.equal(fs.readFileSync(target, "utf8"), "private result");
        await assert.rejects(
          context.invoke({ ...request, invocationId: "retry" }),
          /no identity/,
        );
        return; // No fabricated receipt or automatic command retry after acknowledgement loss.
      }
      const result = await context.invoke(request);
      assert.deepEqual(verifyCapabilityInvocationResult(result).errors, []);
      if (checkDescriptor) {
        checkDescriptor();
        assert.equal(result.outcome, "teardown_failure");
        assert.equal(result.evidence.publication?.state,
          scenario.startsWith("verification") ? "published" : "not_published");
        assert.equal(result.evidence.publication?.stagingCleanup, "failed");
        assert.equal(result.evidence.teardown.ephemeralStateDestroyed, false);
        assert.equal(probeCapabilityInvocationTeardown(result.evidence.executionId).teardownVerified, false);
        assert.equal(fs.readFileSync(target, "utf8"),
          scenario.startsWith("verification") ? "private result" : "original");
        await assert.rejects(context.invoke({ ...request, invocationId: "retry" }), /no identity/);
        return;
      }
      if (
        [
          "cleanup_failure",
          "verification_failure",
          "unlink_failure",
          "visibility_throw",
        ].includes(scenario)
      ) {
        const expectedFailure =
          scenario === "unlink_failure" && initiallyExists
            ? "success"
            : scenario === "cleanup_failure"
              ? "teardown_failure"
              : "commit_failure";
        assert.equal(result.outcome, expectedFailure);
        assert.equal(fs.readFileSync(target, "utf8"), "private result");
        assert.equal(
          result.evidence.publication?.state,
          scenario === "visibility_throw" ? "indeterminate" : "published",
        );
        assert.equal(result.evidence.publication?.durability, "unknown");
        assert.equal(
          result.evidence.publication?.evidenceFinalization,
          "unknown",
        );
        assert.equal(
          result.evidence.teardown.ephemeralStateDestroyed,
          scenario !== "cleanup_failure",
        );
        assert.equal(
          probeCapabilityInvocationTeardown(result.evidence.executionId)
            .teardownVerified,
          scenario !== "cleanup_failure",
        );
        if (expectedFailure !== "success") {
          assert.equal(result.evidence.outputDigest, null);
          visibilityReached = false;
          await assert.rejects(
            context.invoke({ ...request, invocationId: "retry" }),
            /no identity/,
          );
        }
        assert.equal(
          fs
            .readdirSync(directory)
            .some((name) => name.startsWith(".gondolin-commit-")),
          scenario === "cleanup_failure",
        );
        return;
      }
      const expectedOutcome =
        scenario === "descendant_denied"
          ? "policy_denied"
          : scenario === "runner_alive"
            ? "teardown_failure"
            : scenario;
      assert.equal(result.outcome, expectedOutcome);
      assert.ok(
        result.evidence.observed.some((effect) => effect.operation === "write"),
      );
      if (scenario === "success") {
        assert.equal(result.evidence.publication?.state, "published");
        const alterations = [
          { state: "indeterminate" },
          { state: ["published"] },
          { phase: ["verified"] },
          { stagingCleanup: "failed" },
          { state: "not_published" },
          { preparedDigest: `sha256:${"0".repeat(64)}` },
          { expectedTarget: { parent: { dev: "bad", ino: "1" }, file: null } },
          { durability: "verified" },
          { evidenceFinalization: "verified" },
        ];
        for (const change of alterations) {
          const { integrity: _, ...unsigned } = result.evidence;
          const evidence = sealCapabilityEvidence({
            ...unsigned,
            publication: { ...unsigned.publication, ...change },
          });
          assert.equal(
            verifyCapabilityInvocationResult({ ...result, evidence }).valid,
            false,
          );
        }
        const { integrity: _, ...unsigned } = result.evidence;
        assert.equal(
          verifyCapabilityInvocationResult({
            ...result,
            evidence: sealCapabilityEvidence({
              ...unsigned,
              outputDigest: null,
            }),
          }).valid,
          false,
        );
        assert.equal(
          verifyCapabilityInvocationResult({
            ...result,
            evidence: sealCapabilityEvidence({
              ...unsigned,
              publication: null,
            }),
          }).valid,
          false,
        );
        assert.equal(fs.readFileSync(target, "utf8"), "private result");
      } else {
        assertUnpublished();
        assert.equal(
          result.evidence.outputDigest,
          initiallyExists
            ? `sha256:${createHash("sha256").update("original").digest("hex")}`
            : null,
        );
      }
      assert.deepEqual(
        fs.readdirSync(directory),
        initiallyExists || scenario === "success" ? ["target.txt"] : [],
      );
    });
  }
}

for (const stalled of [false, true]) {
  test(`staging handles short writes, stalled=${stalled}`, (t) => {
    const directory = fs.mkdtempSync(
      path.join(os.tmpdir(), "gondolin-short-write-"),
    );
    t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
    const target = path.join(directory, "target.txt");
    fs.writeFileSync(target, "original");
    const identity = getHostWriterTargetIdentity(target);
    const originalWrite = fs.writeSync;
    let calls = 0;
    t.mock.method(
      fs,
      "writeSync",
      (
        fd: number,
        data: Buffer,
        offset: number,
        length: number,
        position: number,
      ) => {
        calls++;
        if (stalled && calls > 1) return 0;
        return originalWrite(fd, data, offset, Math.min(length, 2), position);
      },
    );
    const commit = () =>
      commitExactWriterTarget(
        target,
        identity,
        Buffer.from("original"),
        Buffer.from("complete result"),
        new Set(["write"]),
      );
    if (stalled) {
      assert.throws(commit, /staging write made no progress/);
      assert.equal(fs.readFileSync(target, "utf8"), "original");
    } else {
      commit();
      assert.equal(fs.readFileSync(target, "utf8"), "complete result");
    }
    assert.ok(calls > 1);
    assert.deepEqual(fs.readdirSync(directory), ["target.txt"]);
  });
}

for (const initiallyExists of [true, false]) {
  for (const fault of [
    "prepare",
    "prepare_and_cleanup",
    "before_publish",
    "syscall_before",
    "syscall_after_same_bytes",
  ]) {
    test(`phase-aware helper ${fault}, initially exists=${initiallyExists}`, (t) => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), "gondolin-phase-"));
      const target = path.join(dir, "target");
      const before = initiallyExists ? Buffer.from("same bytes") : null;
      if (before) fs.writeFileSync(target, before);
      const expected = getHostWriterTargetIdentity(target);
      const remove = fs.rmSync;
      t.after(() => {
        t.mock.restoreAll();
        remove(dir, { recursive: true, force: true });
      });
      if (fault.startsWith("prepare"))
        t.mock.method(fs, "fsyncSync", () => {
          throw new Error("prepare failed");
        });
      if (fault === "prepare_and_cleanup")
        t.mock.method(fs, "rmSync", () => {
          throw new Error("cleanup failed");
        });
      if (fault.startsWith("syscall")) {
        const primitive = initiallyExists ? "renameSync" : "linkSync";
        const publish = fs[primitive];
        t.mock.method(fs, primitive, (...args: Parameters<typeof publish>) => {
          if (fault === "syscall_after_same_bytes") publish(...args);
          throw new Error("syscall result lost");
        });
      }
      const result = settleExactWriterTarget(
        target,
        expected,
        before,
        Buffer.from("same bytes"),
        new Set(["create", "write"]),
        {
          beforePublish: () => {
            if (fault === "before_publish")
              throw new Error("validation failed");
          },
        },
      );
      assert.ok(result.error);
      assert.equal(
        result.publication.state,
        fault.startsWith("syscall") ? "indeterminate" : "not_published",
      );
      assert.equal(
        result.publication.stagingCleanup,
        fault === "prepare_and_cleanup" ? "failed" : "verified",
      );
      assert.equal(result.publication.targetVerification, "unknown");
      assert.equal(
        fs.existsSync(target),
        initiallyExists || fault === "syscall_after_same_bytes",
      );
      if (fs.existsSync(target))
        assert.equal(fs.readFileSync(target, "utf8"), "same bytes");
      if (fault === "prepare_and_cleanup")
        assert.match(String(result.error), /prepare failed/);
    });
  }
}

test("lost staging allocation response keeps cleanup unknown", (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "gondolin-lost-stage-"));
  const target = path.join(dir, "target");
  const expected = getHostWriterTargetIdentity(target);
  const allocate = fs.mkdtempSync;
  const remove = fs.rmSync;
  t.after(() => {
    t.mock.restoreAll();
    remove(dir, { recursive: true, force: true });
  });
  t.mock.method(fs, "mkdtempSync", (...args: Parameters<typeof allocate>) => {
    allocate(...args);
    throw undefined;
  });
  const result = settleExactWriterTarget(
    target,
    expected,
    null,
    Buffer.from("output"),
    new Set(["create"]),
  );
  assert.equal(result.failed, true);
  assert.equal(result.error, undefined);
  assert.equal(result.publication.state, "not_published");
  assert.equal(result.publication.stagingCleanup, "unknown");
  assert.equal(fs.existsSync(target), false);
  assert.equal(fs.readdirSync(dir).length, 1);
});

test("in-place mutation of published inode fails content verification", (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "gondolin-inplace-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const target = path.join(dir, "target");
  fs.writeFileSync(target, "before");
  const expected = getHostWriterTargetIdentity(target);
  const rename = fs.renameSync;
  t.mock.method(fs, "renameSync", (...args: Parameters<typeof rename>) => {
    rename(...args);
    fs.writeFileSync(target, "external content");
  });
  const result = settleExactWriterTarget(
    target,
    expected,
    Buffer.from("before"),
    Buffer.from("output"),
    new Set(["write"]),
  );
  assert.equal(result.failed, true);
  assert.equal(result.publication.state, "published");
  assert.equal(result.publication.targetVerification, "failed");
  assert.equal(fs.readFileSync(target, "utf8"), "external content");
});

for (const fault of descriptorFaults) {
  test(`publication helper tracks descriptor ${fault}`, (t) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "gondolin-descriptor-"));
    const target = path.join(dir, "target");
    fs.writeFileSync(target, "original");
    const expected = getHostWriterTargetIdentity(target);
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
    let published = false;
    const rename = fs.renameSync;
    t.mock.method(fs, "renameSync", (...args: Parameters<typeof rename>) => {
      rename(...args);
      published = true;
    });
    const check = injectDescriptorFault(t, target, fault, () => true, () => published);
    const result = settleExactWriterTarget(target, expected, Buffer.from("original"),
      Buffer.from("output"), new Set(["write", "truncate"]));
    check();
    assert.equal(result.failed, true);
    assert.equal(result.publication.stagingCleanup, "failed");
    assert.equal(result.publication.state, fault.startsWith("verification") ? "published" : "not_published");
    assert.equal(fs.readFileSync(target, "utf8"), published ? "output" : "original");
  });
}

test("target stat failure closes the descriptor before ownership transfer", (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "gondolin-target-stat-"));
  const target = path.join(dir, "target");
  fs.writeFileSync(target, "original");
  const expected = getHostWriterTargetIdentity(target);
  const open = fs.openSync;
  const stat = fs.fstatSync;
  let targetFd: number | undefined;
  t.after(() => {
    t.mock.restoreAll();
    fs.rmSync(dir, { recursive: true, force: true });
  });
  t.mock.method(fs, "openSync", (...args: Parameters<typeof open>) => {
    const fd = open(...args);
    if (String(args[0]) === target) targetFd = fd;
    return fd;
  });
  t.mock.method(fs, "fstatSync", (...args: Parameters<typeof stat>) => {
    if (args[0] === targetFd) throw new Error("target stat failed");
    return stat(...args);
  });
  const result = settleExactWriterTarget(target, expected, Buffer.from("original"),
    Buffer.from("output"), new Set(["write", "truncate"]));
  assert.equal(result.failed, true);
  assert.equal(result.publication.state, "not_published");
  assert.equal(result.publication.stagingCleanup, "verified");
  assert.notEqual(targetFd, undefined);
  assert.throws(() => stat(targetFd!), { code: "EBADF" });
  assert.equal(fs.readFileSync(target, "utf8"), "original");
});
