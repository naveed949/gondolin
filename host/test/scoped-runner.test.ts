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

test("scoped-runner canonicalization is byte-stable across key and set order", () => {
  const first = canonicalizeScopedRunnerInvocationRequest(request());
  const second = canonicalizeScopedRunnerInvocationRequest({
    requiredGuarantees: [...SCOPED_RUNNER_GUARANTEES].reverse(),
    limits: {
      wallTimeMs: 5000,
      outputBytes: 1024,
      writableStorageBytes: 2048,
      pids: 16,
      memoryBytes: 128 * 1024 * 1024,
      cpuTimeMs: 5000,
    },
    capabilities: {
      devices: "none",
      ipc: "none",
      git: "none",
      credentials: "none",
      network: "none",
      process: {
        allowedExecutables: ["/opt/tools/linker"],
        descendants: "allow-list",
      },
      environment: { BUILD_MODE: "release" },
      filesystem: {
        writes: [
          {
            operations: ["truncate", "write"],
            guestPath: "/data/cache/output.bin",
          },
        ],
        reads: [
          {
            operations: ["read"],
            guestPath: "/data/repo/source.ts",
            sourcePath: path.relative(process.cwd(), sourcePath),
          },
        ],
      },
    },
    launch: {
      mode: "direct",
      cwd: "/data/repo",
      args: ["source.ts", "-o", "/data/cache/output.bin"],
      executable: "/opt/tools/compiler",
    },
    profile: "scoped-runner",
    invocationId: "runner-1",
    schemaVersion: CAPABILITY_INVOCATION_SCHEMA_VERSION,
  });

  assert.equal(first.canonical, second.canonical);
  assert.equal(first.digest, second.digest);
  assert.match(first.digest, /^sha256:[0-9a-f]{64}$/);
});

test("scoped-runner rejects omitted authority domains and ambiguous resources", () => {
  const { devices: _devices, ...missingDevices } = request().capabilities;
  assert.throws(
    () =>
      canonicalizeScopedRunnerInvocationRequest({
        ...request(),
        capabilities: missingDevices,
      }),
    (error: unknown) =>
      error instanceof CapabilityAdmissionError &&
      error.code === "invalid_request",
  );
  assert.throws(
    () =>
      canonicalizeScopedRunnerInvocationRequest({
        ...request(),
        capabilities: {
          ...request().capabilities,
          filesystem: {
            ...request().capabilities.filesystem,
            writes: [
              {
                guestPath: "/data/repo/../secret",
                operations: ["write"],
              },
            ],
          },
        },
      }),
    CapabilityAdmissionError,
  );
  assert.throws(
    () =>
      canonicalizeScopedRunnerInvocationRequest({
        ...request(),
        capabilities: {
          ...request().capabilities,
          process: { descendants: "deny", allowedExecutables: ["/bin/sh"] },
        },
      }),
    CapabilityAdmissionError,
  );
});

test("immutable runner ceiling rejects shell, environment, descendants, reads, and writes that widen", async () => {
  const context = ScopedRunnerInvocationContext.create(ceiling());
  assert.ok(Object.isFrozen(context.ceiling));

  const cases: ScopedRunnerInvocationRequest[] = [
    request({
      invocationId: "runner-shell",
      launch: {
        executable: "/bin/sh",
        args: ["-c", "true"],
        cwd: "/data/repo",
        mode: "shell",
      },
    }),
    request({
      invocationId: "runner-env",
      capabilities: {
        ...request().capabilities,
        environment: { HOME: "/root" },
      },
    }),
    request({
      invocationId: "runner-descendant",
      capabilities: {
        ...request().capabilities,
        process: { descendants: "allow-list", allowedExecutables: ["/bin/sh"] },
      },
    }),
    request({
      invocationId: "runner-read",
      capabilities: {
        ...request().capabilities,
        filesystem: {
          ...request().capabilities.filesystem,
          reads: [
            {
              sourcePath: unrelatedPath,
              guestPath: "/data/repo/source.ts",
              operations: ["read"],
            },
          ],
        },
      },
    }),
    request({
      invocationId: "runner-write",
      capabilities: {
        ...request().capabilities,
        filesystem: {
          ...request().capabilities.filesystem,
          writes: [
            { guestPath: "/data/repo/.git/config", operations: ["write"] },
          ],
        },
      },
    }),
  ];

  for (const candidate of cases) {
    await assert.rejects(
      context.invoke(candidate),
      (error: unknown) =>
        error instanceof CapabilityAdmissionError &&
        error.code === "ceiling_widening",
    );
  }
});

test("shell mode is explicit in the canonical request and ceiling", () => {
  const shellCeiling = ceiling({
    allowedExecutables: ["/bin/sh"],
    allowShell: true,
  });
  const context = ScopedRunnerInvocationContext.create(shellCeiling);
  assert.equal(context.ceiling.allowShell, true);
  const direct = request({
    invocationId: "runner-direct-shell-path",
    launch: {
      executable: "/bin/sh",
      args: ["-c", "true"],
      cwd: "/data/repo",
      mode: "direct",
    },
  });
  const shell = request({
    invocationId: "runner-explicit-shell",
    launch: {
      executable: "/bin/sh",
      args: ["-c", "true"],
      cwd: "/data/repo",
      mode: "shell",
    },
  });
  assert.notEqual(
    canonicalizeScopedRunnerInvocationRequest(shell).digest,
    canonicalizeScopedRunnerInvocationRequest(direct).digest,
  );
});

test("exec protocol preserves the exact process-tree executable allow-list", () => {
  const payload = buildExecRequest(7, {
    cmd: "/opt/tools/compiler",
    argv: ["source.ts"],
    clear_env: true,
    allowed_executables: ["/opt/tools/compiler", "/opt/tools/linker"],
  });
  assert.deepEqual(payload.p.allowed_executables, [
    "/opt/tools/compiler",
    "/opt/tools/linker",
  ]);
});

test("exec protocol carries the pre-start write policy and resource controllers", () => {
  const payload = buildExecRequest(8, {
    cmd: "/opt/tools/compiler",
    allowed_writable_paths: ["/data/cache/output.bin"],
    resource_limits: {
      cpu_time_ms: 5000,
      memory_bytes: 128 * 1024 * 1024,
      pids: 16,
    },
  });
  assert.deepEqual(payload.p.allowed_writable_paths, [
    "/data/cache/output.bin",
  ]);
  assert.deepEqual(payload.p.resource_limits, {
    cpu_time_ms: 5000,
    memory_bytes: 128 * 1024 * 1024,
    pids: 16,
  });
});

test("all six invocation resource limits validate independently", () => {
  const invalidLimits = [
    { cpuTimeMs: 0 },
    { memoryBytes: 127 * 1024 * 1024 },
    { memoryBytes: 128 * 1024 * 1024 + 1 },
    { pids: 0 },
    { writableStorageBytes: 0 },
    { outputBytes: 0 },
    { wallTimeMs: 0 },
  ];
  for (const [index, override] of invalidLimits.entries()) {
    assert.throws(
      () =>
        canonicalizeScopedRunnerInvocationRequest(
          request({
            invocationId: `invalid-limit-${index}`,
            limits: { ...request().limits, ...override },
          }),
        ),
      (error: unknown) =>
        error instanceof CapabilityAdmissionError &&
        error.code === "invalid_request",
    );
  }
});

test("immutable ceiling contracts each independent resource budget", async () => {
  const context = ScopedRunnerInvocationContext.create(ceiling());
  const wideningLimits = [
    { cpuTimeMs: 10_001 },
    { memoryBytes: 257 * 1024 * 1024 },
    { pids: 65 },
    { writableStorageBytes: 4097 },
    { outputBytes: 4097 },
    { wallTimeMs: 10_001 },
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

test("resource exhaustion outcomes remain structurally distinguishable", () => {
  assert.equal(__test.resourceOutcome("cpu"), "cpu_exhausted");
  assert.equal(__test.resourceOutcome("memory"), "memory_exhausted");
  assert.equal(__test.resourceOutcome("pids"), "pids_exhausted");
  assert.equal(__test.outcomeToExhausted("storage_exhausted"), "storage");
  assert.equal(__test.outcomeToExhausted("output_overflow"), "output");
  assert.equal(__test.outcomeToExhausted("timeout"), "wall-time");
});

test("host writable-storage budget aborts before an over-limit write", () => {
  const abort = new AbortController();
  const budget = new __test.WritableStorageBudget(4, abort);
  budget.reserve("/output", {
    op: "write",
    path: "/output",
    offset: 0,
    length: 4,
  });
  assert.equal(budget.usedBytes, 4);
  assert.throws(
    () =>
      budget.reserve("/output", {
        op: "write",
        path: "/output",
        offset: 4,
        length: 1,
      }),
    /ERRNO_28/,
  );
  assert.equal(budget.exhausted, true);
  assert.equal(abort.signal.aborted, true);
});

test("feature manifest advertises QEMU resource controls without claiming krun qualification", () => {
  const manifest = getCapabilityInvocationFeatureManifest();
  assert.equal(manifest.profiles["scoped-runner"], "active");
  for (const guarantee of SCOPED_RUNNER_GUARANTEES) {
    assert.equal(manifest.guarantees[guarantee], "active", guarantee);
  }
  assert.equal(
    manifest.guarantees["scoped-runner.descendant-executable-restriction"],
    "active",
  );
  assert.equal(
    manifest.operations["filesystem.write.ephemeral-exact"],
    "active",
  );
  assert.equal(manifest.operations["environment.projected"], "active");
  assert.equal(manifest.operations["process.descendant-allow-list"], "active");
  assert.equal(
    manifest.operations["process.descendants-denied"],
    "unsupported",
  );
  assert.equal(manifest.guarantees["per-invocation-cpu"], "active");
  assert.equal(manifest.guarantees["per-invocation-memory"], "active");
  assert.equal(manifest.guarantees["per-invocation-pids"], "active");
  assert.equal(manifest.guarantees["per-invocation-storage"], "active");
  assert.equal(manifest.backends.qemu, "active");
  assert.equal(manifest.backends.krun, "unverified");
  assert.equal(
    manifest.qualifications[
      "scoped-runner.resources/qemu/linux/released-image-kernel-arch-bundle"
    ],
    "unverified",
  );
});

test(
  "public seam enforces resource outcomes and verified teardown",
  { skip: shouldSkipVmTests(), timeout: 600_000 },
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
        "test -r /data/repo/source.ts && printf artifact > /data/cache/output.bin && printf 'valid\\n'",
      );
      assert.equal(result.outcome, "success", result.error);
      assert.equal(result.stdout, "valid\n");
      assert.equal(
        result.evidence.writeDigests["/data/cache/output.bin"],
        "sha256:c7c5c1d70c5dec4416ab6158afd0b223ef40c29b1dc1f97ed9428b94d4cadb1c",
      );
      assertSettled(result, null);
    });

    await t.test("undeclared temporary storage is denied", async () => {
      const result = await invoke(
        "runner-resource-temp-denied",
        "if printf escape > /tmp/gondolin-unaccounted; then exit 97; fi; printf blocked",
      );
      assert.equal(result.outcome, "success", result.error);
      assert.equal(result.stdout, "blocked");
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
          "payload=$(/bin/busybox head -c 268435456 /dev/zero | /bin/busybox tr '\\000' x); printf '%s' \"${#payload}\"",
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
