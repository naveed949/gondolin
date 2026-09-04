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

test("exec protocol carries pre-start write, resource, and isolation policy", () => {
  const payload = buildExecRequest(8, {
    cmd: "/opt/tools/compiler",
    allowed_writable_paths: ["/data/cache/output.bin"],
    resource_limits: {
      cpu_time_ms: 5000,
      memory_bytes: 128 * 1024 * 1024,
      pids: 16,
    },
    isolate_ipc: true,
    isolate_devices: true,
  });
  assert.deepEqual(payload.p.allowed_writable_paths, [
    "/data/cache/output.bin",
  ]);
  assert.deepEqual(payload.p.resource_limits, {
    cpu_time_ms: 5000,
    memory_bytes: 128 * 1024 * 1024,
    pids: 16,
  });
  assert.equal(payload.p.isolate_ipc, true);
  assert.equal(payload.p.isolate_devices, true);
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
