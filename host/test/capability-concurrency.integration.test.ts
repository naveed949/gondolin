import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  CAPABILITY_CEILING_SCHEMA_VERSION,
  CAPABILITY_INVOCATION_SCHEMA_VERSION,
  CapabilityCredentialStore,
  CapabilityInvocationContext,
  DESTINATION_BOUND_CREDENTIAL_GUARANTEES,
  EXACT_READER_GUARANTEES,
  EXACT_WRITER_GUARANTEES,
  HTTP_TLS_EGRESS_GUARANTEES,
  SCOPED_RUNNER_GUARANTEES,
  ScopedRunnerInvocationContext,
  probeCapabilityInvocationTeardown,
  verifyCapabilityInvocationResult,
  type CapabilityCredentialProjection,
  type CapabilityNetworkRule,
  type ExactReaderInvocationRequest,
} from "../src/index.ts";
import { shouldSkipVmTests } from "./helpers/vm-fixture.ts";
import { mockCapabilityNetworkDns } from "./helpers/capability-network.ts";

test(
  "concurrent public invocations cannot union filesystem, runner, environment, network, or credential authority",
  { skip: shouldSkipVmTests(), timeout: 120_000 },
  async (t) => {
    mockCapabilityNetworkDns(t);
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "gondolin-concurrent-"));
    const readerA = path.join(root, "reader-a.txt");
    const readerB = path.join(root, "reader-b.txt");
    const runnerInput = path.join(root, "runner.txt");
    const writerA = path.join(root, "writer-a.txt");
    const writerB = path.join(root, "writer-b.txt");
    fs.writeFileSync(readerA, "reader-a-only\n");
    fs.writeFileSync(readerB, "reader-b-only\n");
    fs.writeFileSync(runnerInput, "runner-only\n");
    fs.writeFileSync(writerA, "writer-a-before\n");
    fs.writeFileSync(writerB, "writer-b-before\n");

    const credentialsSeen: string[] = [];
    const server = http.createServer((request, response) => {
      credentialsSeen.push(String(request.headers["x-api-token"]));
      response.writeHead(200, { "content-type": "text/plain" });
      response.end("credential-ok\n");
    });
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });

    try {
      const address = server.address();
      assert.ok(address && typeof address === "object");
      const readerContextA = CapabilityInvocationContext.create({
        schemaVersion: CAPABILITY_CEILING_SCHEMA_VERSION,
        profile: "exact-reader",
        allowedExecutables: ["/bin/busybox"],
        filesystem: {
          sourcePaths: [readerA],
          guestPaths: ["/data/input.txt"],
        },
        limits: { maxOutputBytes: 4096, maxWallTimeMs: 30_000 },
        guarantees: [...EXACT_READER_GUARANTEES],
      });
      const readerContextB = CapabilityInvocationContext.create({
        schemaVersion: CAPABILITY_CEILING_SCHEMA_VERSION,
        profile: "exact-reader",
        allowedExecutables: ["/bin/busybox"],
        filesystem: {
          sourcePaths: [readerB],
          guestPaths: ["/data/input.txt"],
        },
        limits: { maxOutputBytes: 4096, maxWallTimeMs: 30_000 },
        guarantees: [...EXACT_READER_GUARANTEES],
      });
      const writerContext = CapabilityInvocationContext.create({
        schemaVersion: CAPABILITY_CEILING_SCHEMA_VERSION,
        profile: "exact-writer",
        allowedExecutables: ["/bin/busybox"],
        filesystem: {
          targetPaths: [writerA, writerB],
          guestPaths: ["/data/output.txt"],
          operations: ["write", "truncate"],
        },
        limits: { maxOutputBytes: 4096, maxWallTimeMs: 30_000 },
        guarantees: [...EXACT_WRITER_GUARANTEES],
      });
      const runnerContext = ScopedRunnerInvocationContext.create({
        schemaVersion: CAPABILITY_CEILING_SCHEMA_VERSION,
        profile: "scoped-runner",
        allowedExecutables: ["/bin/busybox"],
        allowedDescendantExecutables: [],
        allowShell: true,
        allowedWorkingDirectories: ["/data"],
        filesystem: {
          sourcePaths: [runnerInput],
          readGuestPaths: ["/data/runner.txt"],
          writeGuestPaths: ["/data/runner-output.txt"],
        },
        environment: { allowedNames: ["RUN_ID"] },
        limits: {
          maxCpuTimeMs: 20_000,
          maxMemoryBytes: 256 * 1024 * 1024,
          maxPids: 16,
          maxWritableStorageBytes: 4096,
          maxOutputBytes: 4096,
          maxWallTimeMs: 30_000,
        },
        guarantees: [...SCOPED_RUNNER_GUARANTEES],
      });
      const rule: CapabilityNetworkRule = {
        protocol: "http",
        destination: "capability.test",
        port: address.port,
        methods: ["GET"],
        redirects: "deny",
        resolution: "checked-host",
        internalRanges: "allow",
      };
      const projection: CapabilityCredentialProjection = {
        reference: "credential/concurrency-a",
        projection: "API_TOKEN",
        redactionId: "concurrency-token-a",
        protocol: "http",
        destination: "capability.test",
        port: address.port,
        methods: ["GET"],
        validity: {},
      };
      const credentialStore = CapabilityCredentialStore.create({
        "credential/concurrency-a": {
          value: "credential-a-secret",
          redactionId: "concurrency-token-a",
          protocol: "http",
          destination: "capability.test",
          port: address.port,
          methods: ["GET"],
        },
      });
      const credentialContext = CapabilityInvocationContext.create(
        {
          schemaVersion: CAPABILITY_CEILING_SCHEMA_VERSION,
          profile: "exact-reader",
          allowedExecutables: ["/bin/busybox"],
          filesystem: {
            sourcePaths: [readerA],
            guestPaths: ["/data/input.txt"],
          },
          network: { rules: [rule] },
          credentials: { projections: [projection] },
          limits: { maxOutputBytes: 4096, maxWallTimeMs: 30_000 },
          guarantees: [
            ...EXACT_READER_GUARANTEES,
            ...HTTP_TLS_EGRESS_GUARANTEES,
            ...DESTINATION_BOUND_CREDENTIAL_GUARANTEES,
          ],
        },
        { credentialStore },
      );

      const readerRequest = (
        invocationId: string,
        sourcePath: string,
      ): ExactReaderInvocationRequest => ({
        schemaVersion: CAPABILITY_INVOCATION_SCHEMA_VERSION,
        invocationId,
        profile: "exact-reader",
        launch: {
          executable: "/bin/busybox",
          args: ["cat", "/data/input.txt"],
        },
        capabilities: {
          filesystem: {
            sourcePath,
            guestPath: "/data/input.txt",
            operations: ["read"],
          },
          network: "none",
          environment: {},
        },
        limits: { outputBytes: 2048, wallTimeMs: 20_000 },
        requiredGuarantees: [...EXACT_READER_GUARANTEES],
      });

      const results = await Promise.all([
        readerContextA.invoke(readerRequest("concurrent-reader-a", readerA)),
        readerContextB.invoke(readerRequest("concurrent-reader-b", readerB)),
        writerContext.invoke({
          schemaVersion: CAPABILITY_INVOCATION_SCHEMA_VERSION,
          invocationId: "concurrent-writer-a",
          profile: "exact-writer",
          launch: {
            executable: "/bin/busybox",
            args: [
              "sh",
              "-c",
              "printf writer-a-after > /data/output.txt; printf denied > /data/other.txt",
            ],
          },
          capabilities: {
            filesystem: {
              targetPath: writerA,
              guestPath: "/data/output.txt",
              operations: ["write", "truncate"],
            },
            network: "none",
            environment: {},
          },
          limits: { outputBytes: 2048, wallTimeMs: 20_000 },
          requiredGuarantees: [...EXACT_WRITER_GUARANTEES],
        }),
        writerContext.invoke({
          schemaVersion: CAPABILITY_INVOCATION_SCHEMA_VERSION,
          invocationId: "concurrent-writer-b",
          profile: "exact-writer",
          launch: {
            executable: "/bin/busybox",
            args: ["sh", "-c", "printf writer-b-after > /data/output.txt"],
          },
          capabilities: {
            filesystem: {
              targetPath: writerB,
              guestPath: "/data/output.txt",
              operations: ["write", "truncate"],
            },
            network: "none",
            environment: {},
          },
          limits: { outputBytes: 2048, wallTimeMs: 20_000 },
          requiredGuarantees: [...EXACT_WRITER_GUARANTEES],
        }),
        runnerContext.invoke({
          schemaVersion: CAPABILITY_INVOCATION_SCHEMA_VERSION,
          invocationId: "concurrent-runner",
          profile: "scoped-runner",
          launch: {
            executable: "/bin/busybox",
            args: [
              "sh",
              "-c",
              'IFS= read -r source < /data/runner.txt; printf "%s:%s" "$RUN_ID" "$source"; printf runner-write > /data/runner-output.txt',
            ],
            cwd: "/data",
            mode: "direct",
          },
          capabilities: {
            filesystem: {
              reads: [
                {
                  sourcePath: runnerInput,
                  guestPath: "/data/runner.txt",
                  operations: ["read"],
                },
              ],
              writes: [
                {
                  guestPath: "/data/runner-output.txt",
                  operations: ["write", "truncate"],
                },
              ],
            },
            environment: { RUN_ID: "runner-a" },
            process: { descendants: "deny", allowedExecutables: [] },
            network: "none",
            credentials: "none",
            git: "none",
            ipc: "none",
            devices: "none",
          },
          limits: {
            cpuTimeMs: 10_000,
            memoryBytes: 128 * 1024 * 1024,
            pids: 8,
            writableStorageBytes: 2048,
            outputBytes: 2048,
            wallTimeMs: 20_000,
          },
          requiredGuarantees: [...SCOPED_RUNNER_GUARANTEES],
        }),
        credentialContext.invoke({
          ...readerRequest("concurrent-credential", readerA),
          launch: {
            executable: "/bin/busybox",
            args: [
              "sh",
              "-c",
              `exec /bin/busybox wget -qO- --header="X-Api-Token: $API_TOKEN" http://capability.test:${address.port}/credential`,
            ],
          },
          capabilities: {
            ...readerRequest("concurrent-credential", readerA).capabilities,
            network: { rules: [rule] },
            credentials: { projections: [projection] },
          },
          requiredGuarantees: [
            ...HTTP_TLS_EGRESS_GUARANTEES,
            ...DESTINATION_BOUND_CREDENTIAL_GUARANTEES,
          ],
        }),
      ]);

      assert.equal(results[0]!.stdout, "reader-a-only\n");
      assert.equal(results[1]!.stdout, "reader-b-only\n");
      assert.equal(fs.readFileSync(writerA, "utf8"), "writer-a-after");
      assert.equal(fs.readFileSync(writerB, "utf8"), "writer-b-after");
      assert.equal(results[4]!.stdout, "runner-a:runner-only");
      assert.equal(results[5]!.stdout, "credential-ok\n");
      assert.deepEqual(credentialsSeen, ["credential-a-secret"]);
      const executionIds = results.map((result) => result.evidence.executionId);
      const vmIds = results.map((result) => result.evidence.vmId);
      assert.equal(new Set(executionIds).size, results.length);
      assert.equal(new Set(vmIds).size, results.length);
      for (const result of results) {
        assert.equal(verifyCapabilityInvocationResult(result).valid, true);
        assert.equal(
          probeCapabilityInvocationTeardown(result.evidence.executionId, {
            requestDigest: result.evidence.requestDigest,
            ceilingDigest: result.evidence.ceilingDigest,
            vmId: result.evidence.vmId,
          }).teardownVerified,
          true,
        );
        for (const bucket of [
          result.evidence.requested,
          result.evidence.granted,
          result.evidence.attempted,
          result.evidence.denied,
          result.evidence.observed,
          result.evidence.processEvents,
        ]) {
          assert.ok(
            bucket.every(
              (event) => event.executionId === result.evidence.executionId,
            ),
          );
        }
      }
      assert.notEqual(
        results[2]!.evidence.granted[0]?.resourceId,
        results[3]!.evidence.granted[0]?.resourceId,
      );
      assert.ok(
        results[2]!.evidence.denied.some(
          (effect) => effect.guestPath === "/data/other.txt",
        ),
      );
      assert.ok(!JSON.stringify(results).includes("credential-a-secret"));
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
      fs.rmSync(root, { recursive: true, force: true });
    }
  },
);
