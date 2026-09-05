import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { CapabilitySnapshotProvider } from "../src/capability-snapshot.ts";
import { MemoryProvider } from "../src/vfs/node/index.ts";

test("capability snapshot maps non-root host ownership across path and descriptor stats without changing permissions", async (t) => {
  t.mock.method(process, "getuid", () => 1001);
  t.mock.method(process, "getgid", () => 2001);
  const temp = fs.mkdtempSync(
    path.join(os.tmpdir(), "gondolin-snapshot-owner-"),
  );
  t.after(() => fs.rmSync(temp, { recursive: true, force: true }));
  const source = path.join(temp, "source");
  fs.writeFileSync(source, "host snapshot", { mode: 0o400 });
  const before = fs.statSync(source);
  const ordinary = new MemoryProvider();
  assert.equal(ordinary.statSync("/").uid, 1001);
  assert.equal(ordinary.statSync("/").gid, 2001);
  const provider = new CapabilitySnapshotProvider();
  provider.mkdirSync("/repo", { mode: 0o500 });
  for (const [name, mode] of [
    ["read", 0o400],
    ["write", 0o600],
  ] as const) {
    const filePath = `/repo/${name}`;
    const handle = await provider.open(filePath, "w", mode);
    await handle.writeFile(fs.readFileSync(source));
    for (const stats of [
      provider.statSync(filePath),
      provider.lstatSync(filePath),
      await provider.stat(filePath),
      await provider.lstat(filePath),
      handle.statSync(),
      await handle.stat(),
    ]) {
      assert.equal(stats.uid, 0);
      assert.equal(stats.gid, 0);
      assert.equal(stats.mode & 0o777, mode);
      assert.equal(stats.isFile(), true);
    }
    await handle.close();
  }
  for (const stats of [
    provider.statSync("/repo"),
    await provider.lstat("/repo"),
  ]) {
    assert.equal(stats.uid, 0);
    assert.equal(stats.gid, 0);
    assert.equal(stats.mode & 0o777, 0o500);
    assert.equal(stats.isDirectory(), true);
  }
  assert.equal(provider.statSync("/").uid, 0);
  provider.setReadOnly();
  assert.throws(() => provider.openSync("/repo/read", "w"), /EROFS|read.only/i);
  assert.equal(ordinary.statSync("/").uid, 1001);
  assert.equal(ordinary.statSync("/").gid, 2001);
  const after = fs.statSync(source);
  assert.equal(after.uid, before.uid);
  assert.equal(after.gid, before.gid);
  assert.equal(after.mode, before.mode);
  assert.equal(fs.readFileSync(source, "utf8"), "host snapshot");
});
