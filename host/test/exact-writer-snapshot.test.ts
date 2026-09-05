import assert from "node:assert/strict";
import test from "node:test";

import { __test } from "../src/capability-invocation.ts";
import type {
  CapabilityEffect,
  ExactWriterOperation,
} from "../src/capability-invocation.ts";
import { CapabilitySnapshotProvider } from "../src/capability-snapshot.ts";
import { AuthenticatedExecutionIdentity } from "../src/invocation-evidence.ts";
import { SandboxVfsProvider } from "../src/vfs/provider.ts";

async function snapshot(
  initial: Buffer | null,
  operations: ExactWriterOperation[],
) {
  const backend = new CapabilitySnapshotProvider();
  await __test.populateWriterSnapshot(backend, "/output.txt", initial);
  const attempted: CapabilityEffect[] = [];
  const denied: CapabilityEffect[] = [];
  const observed: CapabilityEffect[] = [];
  const hooks = __test.createWriterEvidenceHooks({
    identity: AuthenticatedExecutionIdentity.begin(
      `sha256:${"1".repeat(64)}`,
      `sha256:${"2".repeat(64)}`,
    ),
    exactPath: "/output.txt",
    guestPath: "/data/output.txt",
    resourceId: "target",
    targetInitiallyExists: initial !== null,
    operations: new Set(operations),
    attempted,
    denied,
    observed,
  });
  return {
    backend,
    provider: new SandboxVfsProvider(backend, hooks),
    observed,
    denied,
  };
}

for (const truncateBeforeOpen of [true, false]) {
  test(`new exact writer records creation with truncate ${truncateBeforeOpen ? "before" : "after"} open without granting later truncation`, async () => {
    const { backend, provider, observed, denied } = await snapshot(null, [
      "create",
      "write",
    ]);
    const inode = backend.statSync("/output.txt");
    assert.equal(inode.mode & 0o777, 0o600);
    assert.equal(inode.uid, 0);
    assert.equal(inode.size, 0);
    assert.equal(observed.length, 0);
    if (truncateBeforeOpen) await provider.truncate("/output.txt", 0);
    // FUSE OPEN strips O_CREAT and supplies the existing inode's access mode.
    const handle = await provider.open("/output.txt", "r+");
    if (!truncateBeforeOpen) await handle.truncate(0);
    await handle.writeFile("new output");
    await assert.rejects(handle.truncate(0), { errno: 13 });
    await assert.rejects(handle.readFile(), { errno: 13 });
    await handle.close();
    assert.equal(
      observed.filter((effect) => effect.operation === "create").length,
      1,
    );
    assert.ok(observed.some((effect) => effect.operation === "write"));
    assert.ok(!observed.some((effect) => effect.operation === "truncate"));
    assert.ok(denied.some((effect) => effect.operation === "truncate"));
    assert.ok(denied.some((effect) => effect.operation === "read"));
    const result = await backend.open("/output.txt", "r");
    assert.equal((await result.readFile()).toString(), "new output");
    await result.close();
    await assert.rejects(provider.open("/alias.txt", "w"), { errno: 13 });
    assert.equal(backend.statSync("/output.txt").mode & 0o777, 0o600);
  });
}

test("an unused new writer placeholder has no observed mutation", async () => {
  const { provider, observed } = await snapshot(null, ["create"]);
  await provider.stat("/output.txt");
  assert.deepEqual(observed, []);
});

test("create authority does not grant writes and existing writers still require truncate", async () => {
  const fresh = await snapshot(null, ["create"]);
  const handle = await fresh.provider.open("/output.txt", "r+");
  await assert.rejects(handle.writeFile("not allowed"), { errno: 13 });
  await handle.close();
  assert.equal(fresh.backend.statSync("/output.txt").size, 0);
  const existing = await snapshot(Buffer.from("keep"), ["write"]);
  await assert.rejects(existing.provider.truncate("/output.txt", 0), {
    errno: 13,
  });
  assert.ok(!existing.observed.some((effect) => effect.operation === "create"));
  const truncating = await snapshot(Buffer.from("remove"), ["truncate"]);
  await truncating.provider.truncate("/output.txt", 0);
  assert.equal(truncating.backend.statSync("/output.txt").size, 0);
  assert.ok(
    truncating.observed.some((effect) => effect.operation === "truncate"),
  );
});
