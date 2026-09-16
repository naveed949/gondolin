import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { CapabilityAdmissionError } from "../src/capability-invocation.ts";
import {
  linuxAtAvailable,
  openat2,
  pinDirectory,
  parseDirectoryIdentity,
  RESOLVE_BENEATH,
  RESOLVE_NO_MAGICLINKS,
} from "../src/linux-at.ts";
import {
  ScopedTreeProvider,
  capabilityPath,
  toProviderPath,
} from "../src/vfs/scoped-tree.ts";
import {
  bindScopedTreeProvider,
  observeRootIdentity,
  preparePrivateRoot,
  type ScopedTreeRunnerInvocationRequest,
} from "../src/scoped-tree-runner.ts";
import { ERRNO } from "../src/vfs/utils.ts";

const skip = !linuxAtAvailable() ? "openat2 unavailable" : false;

function makeRoots() {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), "gondolin-tree-"));
  const repository = path.join(parent, "repo");
  fs.mkdirSync(repository);
  fs.writeFileSync(path.join(repository, "source.ts"), "export const n = 1;\n");
  fs.mkdirSync(path.join(repository, "nested"));
  fs.writeFileSync(path.join(repository, "nested", "inside.txt"), "in\n");
  const cache = preparePrivateRoot(parent, "cache");
  const temp = preparePrivateRoot(parent, "temp");
  const repoIdentity = observeRootIdentity(repository, "repository");
  return { parent, repository, cache, temp, repoIdentity };
}

function providerFrom(roots: ReturnType<typeof makeRoots>) {
  const request = {
    capabilities: {
      filesystem: {
        repository: {
          hostPath: roots.repository,
          guestPath: "/data/repo",
          identity: roots.repoIdentity,
        },
        cache: { ...roots.cache, guestPath: "/data/cache" },
        temp: { ...roots.temp, guestPath: "/data/tmp" },
      },
    },
  } as ScopedTreeRunnerInvocationRequest;
  return bindScopedTreeProvider(request);
}

test("toProviderPath strips the /data FUSE prefix", () => {
  assert.equal(toProviderPath("/data"), "/");
  assert.equal(toProviderPath("/data/repo"), "/repo");
  assert.throws(() => toProviderPath("/etc/passwd"), /outside \/data/);
});

test(
  "openat2 refuses path escape under a pinned directory",
  { skip },
  () => {
    const roots = makeRoots();
    try {
      const expected = parseDirectoryIdentity(roots.repoIdentity, "repository");
      const fd = pinDirectory(roots.repository, expected);
      try {
        const ok = openat2(
          fd,
          "source.ts",
          fs.constants.O_RDONLY | fs.constants.O_CLOEXEC,
        );
        fs.closeSync(ok);
        assert.throws(
          () =>
            openat2(
              fd,
              "../cache/x",
              fs.constants.O_RDONLY | fs.constants.O_CLOEXEC,
              0,
              RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS,
            ),
          (error: unknown) =>
            error instanceof Error &&
            /ERRNO_(18|2|13)/.test((error as Error).message),
        );
      } finally {
        fs.closeSync(fd);
      }
    } finally {
      fs.rmSync(roots.parent, { recursive: true, force: true });
    }
  },
);

test(
  "tree VFS enforces the per-root operation table and late creates",
  { skip },
  () => {
    const roots = makeRoots();
    const decisions: string[] = [];
    const request = {
      capabilities: {
        filesystem: {
          repository: {
            hostPath: roots.repository,
            guestPath: "/data/repo",
            identity: roots.repoIdentity,
          },
          cache: { ...roots.cache, guestPath: "/data/cache" },
          temp: { ...roots.temp, guestPath: "/data/tmp" },
        },
      },
    } as ScopedTreeRunnerInvocationRequest;
    const provider = bindScopedTreeProvider(request, (decision) => {
      decisions.push(`${decision.decision}:${decision.operation}:${decision.guestPath}`);
    });
    try {
      const source = provider.openSync("/repo/source.ts", "r");
      assert.match(String(source.readFileSync("utf8")), /export const n/);
      source.closeSync();

      const late = provider.openSync("/cache/late-created.bin", "w");
      late.writeFileSync("after-admission");
      late.closeSync();
      assert.equal(
        fs.readFileSync(path.join(roots.cache.hostPath, "late-created.bin"), "utf8"),
        "after-admission",
      );

      const renamed = provider.openSync("/cache/late-created.bin", "r");
      renamed.closeSync();
      provider.renameSync("/cache/late-created.bin", "/cache/renamed.bin");
      provider.linkSync("/cache/renamed.bin", "/cache/hardlink.bin");
      provider.unlinkSync("/cache/hardlink.bin");

      assert.throws(() => provider.openSync("/repo/new.txt", "w"), /ERRNO_1/);
      assert.throws(() => provider.mkdirSync("/cache/dir"), /ERRNO_1/);
      assert.throws(() => provider.rmdirSync("/repo/nested"), /ERRNO_1/);
      assert.throws(() => provider.symlinkSync("x", "/cache/link"), /ERRNO_1/);
      assert.throws(
        () => provider.renameSync("/cache/renamed.bin", "/tmp/escape.bin"),
        /ERRNO_1/,
      );
      assert.throws(
        () => provider.renameSync("/cache/renamed.bin", "/cache/nested/x.bin"),
        /ERRNO_1/,
      );
      assert.throws(() => provider.openSync("/repo/../cache/renamed.bin", "r"), /ERRNO_1/);
      assert.ok(
        decisions.some((entry) => entry.includes("denied:mkdir")),
      );
      assert.equal(capabilityPath("cache", "mkdir"), "filesystem.cache.mkdir");
    } finally {
      const disposed = provider.dispose();
      assert.equal(disposed.handlesRevoked, true);
      assert.equal(disposed.rootsClosed, true);
      fs.rmSync(roots.parent, { recursive: true, force: true });
    }
  },
);

test(
  "replaced directory identity is denied at the capability path",
  { skip },
  () => {
    const roots = makeRoots();
    try {
      fs.rmSync(roots.cache.hostPath, { recursive: true, force: true });
      fs.writeFileSync(roots.cache.hostPath, "not-a-directory");
      assert.throws(
        () => providerFrom(roots),
        (error: unknown) =>
          error instanceof CapabilityAdmissionError &&
          error.message.startsWith("filesystem.cache.identity:"),
      );
    } finally {
      fs.rmSync(roots.parent, { recursive: true, force: true });
    }
  },
);

test(
  "concurrent providers do not share writable objects or handles",
  { skip },
  () => {
    const first = makeRoots();
    const second = makeRoots();
    const a = providerFrom(first);
    const b = providerFrom(second);
    try {
      const handleA = a.openSync("/cache/a.bin", "w");
      handleA.writeFileSync("one");
      const handleB = b.openSync("/cache/a.bin", "w");
      handleB.writeFileSync("two");
      handleA.closeSync();
      handleB.closeSync();
      assert.equal(
        fs.readFileSync(path.join(first.cache.hostPath, "a.bin"), "utf8"),
        "one",
      );
      assert.equal(
        fs.readFileSync(path.join(second.cache.hostPath, "a.bin"), "utf8"),
        "two",
      );
      assert.notEqual(first.cache.hostPath, second.cache.hostPath);
    } finally {
      assert.equal(a.dispose().handlesRevoked, true);
      assert.equal(b.dispose().handlesRevoked, true);
      fs.rmSync(first.parent, { recursive: true, force: true });
      fs.rmSync(second.parent, { recursive: true, force: true });
    }
  },
);

test(
  "failed root close prevents independent revocation success",
  { skip },
  () => {
    const roots = makeRoots();
    const provider = providerFrom(roots);
    const fd = (
      provider as unknown as { roots: Array<{ fd: number }> }
    ).roots[0]!.fd;
    fs.closeSync(fd);
    const disposed = provider.dispose();
    assert.equal(disposed.rootsClosed, false);
    fs.rmSync(roots.parent, { recursive: true, force: true });
  },
);

test("errno constants used by denials are present", () => {
  assert.equal(typeof ERRNO.EPERM, "number");
});
