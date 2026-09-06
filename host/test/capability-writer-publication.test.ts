import assert from "node:assert/strict";
import { createHash } from "node:crypto";
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
} from "../src/capability-filesystem.ts";
import type { CapabilitySnapshotProvider } from "../src/capability-snapshot.ts";

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
  ]) {
    test(`writer ${scenario} publication, initially exists=${initiallyExists}`, async (t) => {
      const directory = fs.mkdtempSync(
        path.join(os.tmpdir(), "gondolin-publication-"),
      );
      t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
      const target = path.join(directory, "target.txt");
      if (initiallyExists) fs.writeFileSync(target, "original");
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
              if (scenario === "teardown_failure")
                throw new Error("close failed");
            },
          } as unknown as VM;
        },
      );
      const context = CapabilityInvocationContext.create(
        writerCeiling([target]),
      );
      const request = writerRequest(target);
      if (!initiallyExists)
        request.capabilities.filesystem.operations.push("create");
      request.limits = { outputBytes: 4, wallTimeMs: 10 };
      const result = await context.invoke(request);
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
