import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  CAPABILITY_CEILING_SCHEMA_VERSION,
  CAPABILITY_INVOCATION_SCHEMA_VERSION,
  CapabilityAdmissionError,
  SCOPED_RUNNER_GUARANTEES,
  ScopedRunnerInvocationContext,
  canonicalizeScopedRunnerInvocationRequest,
  getCapabilityInvocationFeatureManifest,
  type ScopedRunnerCeiling,
  type ScopedRunnerInvocationRequest,
} from "../src/index.ts";
import { buildExecRequest } from "../src/sandbox/virtio-protocol.ts";
import { __test } from "../src/scoped-runner.ts";
import { shouldSkipVmTests } from "./helpers/vm-fixture.ts";

const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "gondolin-runner-"));
const sourcePath = path.join(tempRoot, "source.ts");
const unrelatedPath = path.join(tempRoot, "secret.txt");
fs.writeFileSync(sourcePath, "export const answer = 42;\n", { mode: 0o600 });
fs.writeFileSync(unrelatedPath, "not-declared\n", { mode: 0o600 });

test.after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));

function ceiling(
  overrides: Partial<ScopedRunnerCeiling> = {},
): ScopedRunnerCeiling {
  return {
    schemaVersion: CAPABILITY_CEILING_SCHEMA_VERSION,
    profile: "scoped-runner",
    allowedExecutables: ["/opt/tools/compiler"],
    allowedDescendantExecutables: ["/opt/tools/linker"],
    allowShell: false,
    allowedWorkingDirectories: ["/data/repo"],
    filesystem: {
      sourcePaths: [sourcePath],
      readGuestPaths: ["/data/repo/source.ts"],
      writeGuestPaths: ["/data/cache/output.bin"],
    },
    environment: { allowedNames: ["BUILD_MODE"] },
    limits: {
      maxCpuTimeMs: 10_000,
      maxMemoryBytes: 256 * 1024 * 1024,
      maxPids: 64,
      maxWritableStorageBytes: 4096,
      maxOutputBytes: 4096,
      maxWallTimeMs: 10_000,
    },
    guarantees: [...SCOPED_RUNNER_GUARANTEES],
    ...overrides,
  };
}

function request(
  overrides: Partial<ScopedRunnerInvocationRequest> = {},
): ScopedRunnerInvocationRequest {
  return {
    schemaVersion: CAPABILITY_INVOCATION_SCHEMA_VERSION,
    invocationId: "runner-1",
    profile: "scoped-runner",
    launch: {
      executable: "/opt/tools/compiler",
      args: ["source.ts", "-o", "/data/cache/output.bin"],
      cwd: "/data/repo",
      mode: "direct",
    },
    capabilities: {
      filesystem: {
        reads: [
          {
            sourcePath,
            guestPath: "/data/repo/source.ts",
            operations: ["read"],
          },
        ],
        writes: [
          {
            guestPath: "/data/cache/output.bin",
            operations: ["write", "truncate"],
          },
        ],
      },
      environment: { BUILD_MODE: "release" },
      process: {
        descendants: "allow-list",
        allowedExecutables: ["/opt/tools/linker"],
      },
      network: "none",
      credentials: "none",
      git: "none",
      ipc: "none",
      devices: "none",
    },
    limits: {
      cpuTimeMs: 5000,
      memoryBytes: 128 * 1024 * 1024,
      pids: 16,
      writableStorageBytes: 2048,
      outputBytes: 1024,
      wallTimeMs: 5000,
    },
    requiredGuarantees: [...SCOPED_RUNNER_GUARANTEES],
    ...overrides,
  };
}

test(
  "public seam enforces resource outcomes and verified teardown",
  { skip: shouldSkipVmTests(), timeout: 120_000 },
  async (t) => {
    const context = ScopedRunnerInvocationContext.create(
      ceiling({
        allowedExecutables: ["/bin/busybox"],
        allowedDescendantExecutables: ["/bin/busybox"],
        limits: {
          maxCpuTimeMs: 60_000,
          maxMemoryBytes: 512 * 1024 * 1024,
          maxPids: 128,
          maxWritableStorageBytes: 1024 * 1024,
          maxOutputBytes: 64 * 1024,
          maxWallTimeMs: 60_000,
        },
      }),
    );

    const invoke = (
      invocationId: string,
      script: string,
      limitOverrides: Partial<ScopedRunnerInvocationRequest["limits"]> = {},
    ) =>
      context.invoke(
        request({
          invocationId,
          launch: {
            executable: "/bin/busybox",
            args: ["sh", "-c", script],
            cwd: "/data/repo",
            mode: "direct",
          },
          capabilities: {
            ...request().capabilities,
            process: {
              descendants: "allow-list",
              allowedExecutables: ["/bin/busybox"],
            },
          },
          limits: {
            cpuTimeMs: 30_000,
            memoryBytes: 256 * 1024 * 1024,
            pids: 64,
            writableStorageBytes: 64 * 1024,
            outputBytes: 16 * 1024,
            wallTimeMs: 30_000,
            ...limitOverrides,
          },
        }),
      );

    const assertSettled = (
      result: Awaited<ReturnType<typeof invoke>>,
      exhausted: typeof result.resourceAccounting.exhausted,
    ) => {
      assert.equal(
        result.resourceAccounting.executionId,
        result.evidence.executionId,
      );
      assert.deepEqual(result.evidence.resources, result.resourceAccounting);
      assert.equal(result.resourceAccounting.exhausted, exhausted);
      assert.equal(
        result.resourceAccounting.observations.memory,
        "guest-reported-cgroup-v2",
      );
      assert.equal(
        result.resourceAccounting.observations.pids,
        "guest-reported-cgroup-v2",
      );
      if (exhausted === "memory" || exhausted === "pids") {
        assert.equal(
          result.resourceAccounting.exhaustionObservation,
          "guest-reported",
        );
      } else if (exhausted === "cpu") {
        assert.ok(
          result.resourceAccounting.exhaustionObservation ===
            "guest-reported" ||
            result.resourceAccounting.exhaustionObservation === "host-observed",
        );
      } else {
        assert.equal(
          result.resourceAccounting.exhaustionObservation,
          exhausted === null ? null : "host-observed",
        );
      }
      assert.equal(result.evidence.teardown.commandStopped, true);
      assert.equal(result.evidence.teardown.vmStopped, true);
      assert.equal(result.evidence.teardown.processTreeEmpty, true);
      assert.equal(result.evidence.teardown.resourceControllersRemoved, true);
      assert.equal(result.evidence.teardown.writableStateDestroyed, true);
      assert.equal(
        result.evidence.teardown.completedAt,
        result.evidence.settledAt,
      );
    };

    await t.test("valid workload", async () => {
      const result = await invoke(
        "runner-resource-valid",
        "test -r /data/repo/source.ts && test ! -e /dev/null && test ! -e /run/sandboxfs.failed && printf artifact > /data/cache/output.bin && printf 'valid\\n'",
      );
      assert.equal(result.outcome, "success", result.error);
      assert.equal(result.stdout, "valid\n");
      assert.equal(
        result.evidence.writeDigests["/data/cache/output.bin"],
        "sha256:c7c5c1d70c5dec4416ab6158afd0b223ef40c29b1dc1f97ed9428b94d4cadb1c",
      );
      assertSettled(result, null);
    });

    for (const [name, command] of [
      ["symlink alias", "exec /bin/cat /data/repo/source.ts"],
      [
        "direct ELF loader",
        `exec /lib/ld-musl-${process.arch === "arm64" ? "aarch64" : "x86_64"}.so.1 /usr/bin/env`,
      ],
    ]) {
      await t.test(
        `${name} cannot bypass the executable allowlist`,
        async () => {
          const result = await invoke(
            `runner-denied-${name.replaceAll(" ", "-")}`,
            command,
          );
          assert.equal(result.outcome, "command_failed", result.error);
          assert.notEqual(result.exitCode, 0);
          assert.equal(result.stdout, "");
          assertSettled(result, null);
        },
      );
    }

    await t.test("undeclared descendant executable is denied", async () => {
      const result = await context.invoke(
        request({
          invocationId: "runner-undeclared-descendant",
          launch: {
            executable: "/bin/busybox",
            args: ["sh", "-c", '/usr/bin/env & child=$!; wait "$child"'],
            cwd: "/data/repo",
            mode: "direct",
          },
          capabilities: {
            ...request().capabilities,
            process: {
              descendants: "allow-list",
              allowedExecutables: ["/bin/busybox"],
            },
          },
          limits: {
            cpuTimeMs: 30_000,
            memoryBytes: 256 * 1024 * 1024,
            pids: 64,
            writableStorageBytes: 64 * 1024,
            outputBytes: 16 * 1024,
            wallTimeMs: 30_000,
          },
        }),
      );
      assert.equal(result.outcome, "command_failed", result.error);
      assert.notEqual(result.exitCode, 0);
      assert.equal(result.stdout, "");
      assert.ok(
        result.evidence.processEvents.some(
          (event) => event.kind === "descendant",
        ),
      );
      assertSettled(result, null);
    });

    await t.test(
      "deny descendant policy prevents process creation",
      async () => {
        const result = await context.invoke(
          request({
            invocationId: "runner-deny-descendants",
            launch: {
              executable: "/bin/busybox",
              args: ["sh", "-c", "busybox echo child-ran & wait"],
              cwd: "/data/repo",
              mode: "direct",
            },
            capabilities: {
              ...request().capabilities,
              process: { descendants: "deny", allowedExecutables: [] },
            },
          }),
        );

        assert.equal(result.outcome, "policy_denied", result.error);
        assert.doesNotMatch(result.stdout, /child-ran/);
        assert.ok(
          result.evidence.processEvents.some(
            (event) =>
              event.kind === "denial" &&
              /descendant creation/.test(event.detail),
          ),
        );
        assertSettled(result, null);
      },
    );

    await t.test("undeclared temporary storage is denied", async () => {
      const result = await invoke(
        "runner-resource-temp-denied",
        "if printf escape > /tmp/gondolin-unaccounted; then exit 97; fi; if test -r /data/repo/secret.txt; then exit 98; fi; printf blocked",
      );
      assert.equal(result.outcome, "policy_denied", result.error);
      assert.equal(result.stdout, "blocked");
      assert.ok(
        result.evidence.processEvents.some((event) => event.kind === "denial"),
      );
      assertSettled(result, null);
    });

    const cases: Array<{
      name: string;
      invocationId: string;
      script: string;
      limits: Partial<ScopedRunnerInvocationRequest["limits"]>;
      outcome: Awaited<ReturnType<typeof invoke>>["outcome"];
      exhausted: NonNullable<
        Awaited<ReturnType<typeof invoke>>["resourceAccounting"]["exhausted"]
      >;
    }> = [
      {
        name: "CPU time",
        invocationId: "runner-resource-cpu",
        script: "while :; do :; done",
        limits: { cpuTimeMs: 100, wallTimeMs: 10_000 },
        outcome: "cpu_exhausted",
        exhausted: "cpu",
      },
      {
        name: "memory",
        invocationId: "runner-resource-memory",
        script:
          "payload=$(/bin/busybox yes x | /bin/busybox head -c 268435456); printf '%s' \"${#payload}\"",
        limits: {
          cpuTimeMs: 30_000,
          memoryBytes: 128 * 1024 * 1024,
          wallTimeMs: 30_000,
        },
        outcome: "memory_exhausted",
        exhausted: "memory",
      },
      {
        name: "PID fork burst",
        invocationId: "runner-resource-pids",
        script:
          'i=0; while [ "$i" -lt 64 ]; do (while :; do :; done) & i=$((i + 1)); done; wait',
        limits: { pids: 4, wallTimeMs: 10_000 },
        outcome: "pids_exhausted",
        exhausted: "pids",
      },
      {
        name: "writable storage",
        invocationId: "runner-resource-storage",
        script: "printf 12345 > /data/cache/output.bin",
        limits: { writableStorageBytes: 4 },
        outcome: "storage_exhausted",
        exhausted: "storage",
      },
      {
        name: "combined output",
        invocationId: "runner-resource-output",
        script: "printf 12345",
        limits: { outputBytes: 4 },
        outcome: "output_overflow",
        exhausted: "output",
      },
      {
        name: "wall time",
        invocationId: "runner-resource-timeout",
        script: "/bin/busybox sleep 30",
        limits: { cpuTimeMs: 30_000, wallTimeMs: 100 },
        outcome: "timeout",
        exhausted: "wall-time",
      },
    ];

    for (const candidate of cases) {
      await t.test(candidate.name, async () => {
        const result = await invoke(
          candidate.invocationId,
          candidate.script,
          candidate.limits,
        );
        assert.equal(result.outcome, candidate.outcome, result.error);
        assertSettled(result, candidate.exhausted);
      });
    }
  },
);
