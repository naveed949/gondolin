import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  CAPABILITY_CEILING_SCHEMA_VERSION,
  CAPABILITY_INVOCATION_SCHEMA_VERSION,
  CapabilityAdmissionError,
  getCapabilityInvocationFeatureManifest,
} from "../src/index.ts";
import {
  SCOPED_TREE_RUNNER_PROFILE,
  ScopedTreeOperationError,
  ScopedTreeRunnerInvocationContext,
  ScopedTreeSession,
  canonicalizeScopedTreeRunnerCeiling,
  canonicalizeScopedTreeRunnerInvocationRequest,
} from "../src/scoped-tree.ts";

const linux = process.platform === "linux";

function makeTree(): {
  root: string;
  repository: string;
  cache: string;
  temp: string;
  outside: string;
} {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gondolin-scoped-tree-"));
  const repository = path.join(root, "repo");
  const cache = path.join(root, "cache");
  const temp = path.join(root, "temp");
  const outside = path.join(root, "outside");
  fs.mkdirSync(path.join(repository, "nested"), { recursive: true });
  fs.mkdirSync(path.join(cache, "nested"), { recursive: true });
  fs.mkdirSync(temp);
  fs.mkdirSync(outside);
  fs.writeFileSync(path.join(repository, "early.txt"), "early");
  fs.writeFileSync(path.join(repository, "nested", "inner.txt"), "inner");
  fs.writeFileSync(path.join(outside, "secret.txt"), "secret");
  return { root, repository, cache, temp, outside };
}

function ceilingFor(tree: ReturnType<typeof makeTree>) {
  return {
    schemaVersion: CAPABILITY_CEILING_SCHEMA_VERSION,
    profile: SCOPED_TREE_RUNNER_PROFILE,
    filesystem: {
      repository: { hostPath: tree.repository },
      cache: { hostPath: tree.cache },
      temp: { hostPath: tree.temp },
    },
    process: { descendants: "deny" as const },
    environment: "empty" as const,
    network: "none" as const,
    credentials: "none" as const,
    git: "none" as const,
    ipc: "none" as const,
    devices: "none" as const,
  };
}

function requestFor(tree: ReturnType<typeof makeTree>) {
  return {
    schemaVersion: CAPABILITY_INVOCATION_SCHEMA_VERSION,
    invocationId: "tree-1",
    profile: SCOPED_TREE_RUNNER_PROFILE,
    target: { id: "malicious-runner" },
    launch: { executable: "/opt/tools/malicious-runner", args: [] as string[] },
    capabilities: {
      filesystem: {
        repository: { hostPath: tree.repository },
        cache: { hostPath: tree.cache },
        temp: { hostPath: tree.temp },
      },
      process: { descendants: "deny" as const },
      environment: "empty" as const,
      network: "none" as const,
      credentials: "none" as const,
      git: "none" as const,
      ipc: "none" as const,
      devices: "none" as const,
    },
    limits: {
      cpuMs: 5,
      memoryBytes: 1024,
      children: 0,
      outputBytes: 32,
      wallMs: 100,
    },
  };
}

test("feature manifest keeps scoped-tree-runner unsupported", () => {
  const manifest = getCapabilityInvocationFeatureManifest();
  assert.equal(manifest.profiles["scoped-tree-runner"], "unsupported");
  assert.equal(manifest.profiles["scoped-runner"], "active");
  assert.equal(manifest.operations["filesystem.write"], "unsupported");
});

test("scoped-tree admission rejects omitted domains, callbacks, and adapter widening", () => {
  const tree = makeTree();
  try {
    const valid = ceilingFor(tree);
    canonicalizeScopedTreeRunnerCeiling(valid);
    assert.throws(
      () =>
        canonicalizeScopedTreeRunnerCeiling({
          ...valid,
          process: { descendants: "allow-list" },
        }),
      (error: unknown) =>
        error instanceof CapabilityAdmissionError &&
        error.code === "unsupported" &&
        /ceiling\.process\.descendants/.test(error.message),
    );
    assert.throws(
      () =>
        canonicalizeScopedTreeRunnerCeiling({
          ...valid,
          hooks: () => undefined,
        }),
      (error: unknown) =>
        error instanceof CapabilityAdmissionError &&
        /ceiling/.test(error.message) &&
        /hooks/.test(error.message),
    );
    assert.throws(
      () =>
        canonicalizeScopedTreeRunnerCeiling({
          ...valid,
          environment: { PATH: "/bin" },
        }),
      (error: unknown) =>
        error instanceof CapabilityAdmissionError &&
        /ceiling\.environment/.test(error.message),
    );
    const { git: _git, ...missingGit } = valid;
    assert.throws(
      () => canonicalizeScopedTreeRunnerCeiling(missingGit),
      /missing required field\(s\): git/,
    );
    assert.throws(
      () =>
        canonicalizeScopedTreeRunnerInvocationRequest({
          ...requestFor(tree),
          capabilities: {
            ...requestFor(tree).capabilities,
            devices: "kvm",
          },
        }),
      /request\.capabilities\.devices/,
    );
    assert.throws(
      () =>
        canonicalizeScopedTreeRunnerInvocationRequest({
          ...requestFor(tree),
          limits: {
            ...requestFor(tree).limits,
            writableStorageBytes: 4096,
          },
        }),
      /writableStorageBytes/,
    );
    assert.throws(
      () =>
        canonicalizeScopedTreeRunnerInvocationRequest({
          ...requestFor(tree),
          launch: {
            executable: () => "/opt/tools/malicious-runner",
            args: [],
          },
        }),
      /callbacks are not capability data/,
    );
    assert.throws(
      () =>
        canonicalizeScopedTreeRunnerInvocationRequest({
          ...requestFor(tree),
          capabilities: {
            ...requestFor(tree).capabilities,
            process: { descendants: "deny", afterFork: () => undefined },
          },
        }),
      /request\.capabilities\.process\.afterFork: callbacks are not capability data/,
    );
    assert.throws(
      () =>
        canonicalizeScopedTreeRunnerInvocationRequest({
          ...requestFor(tree),
          capabilities: {
            ...requestFor(tree).capabilities,
            process: { descendants: "deny", extra: "widen" },
          },
        }),
      /unknown critical field\(s\): extra/,
    );
  } finally {
    fs.rmSync(tree.root, { recursive: true, force: true });
  }
});

test("scoped-tree invoke fails closed before payload launch or resource translation", () => {
  const tree = makeTree();
  if (!linux) {
    assert.throws(
      () => ScopedTreeRunnerInvocationContext.create(ceilingFor(tree)),
      /filesystem\.live-root\.resolution/,
    );
    fs.rmSync(tree.root, { recursive: true, force: true });
    return;
  }
  const context = ScopedTreeRunnerInvocationContext.create(ceilingFor(tree));
  try {
    assert.throws(
      () => context.invoke(requestFor(tree)),
      (error: unknown) =>
        error instanceof CapabilityAdmissionError &&
        error.code === "unsupported" &&
        /request\.launch/.test(error.message),
    );
  } finally {
    fs.rmSync(tree.root, { recursive: true, force: true });
  }
});

test(
  "live repository tree is not an admission-time file list",
  { skip: !linux },
  () => {
    const tree = makeTree();
    const session = ScopedTreeSession.acquire({
      repository: tree.repository,
      cache: tree.cache,
      temp: tree.temp,
    });
    try {
      assert.equal(
        session.repository.readFile("early.txt").toString(),
        "early",
      );
      fs.writeFileSync(path.join(tree.repository, "late.txt"), "late");
      assert.equal(session.repository.readFile("late.txt").toString(), "late");
      assert.deepEqual(
        session.repository.enumerate(".").sort(),
        ["early.txt", "late.txt", "nested"].sort(),
      );
    } finally {
      session.dispose();
      fs.rmSync(tree.root, { recursive: true, force: true });
    }
  },
);

test(
  "root identity mismatch and pathname replacement do not inherit a grant",
  { skip: !linux },
  () => {
    const tree = makeTree();
    const session = ScopedTreeSession.acquire({
      repository: tree.repository,
      cache: tree.cache,
      temp: tree.temp,
    });
    try {
      const original = session.repository.identity;
      session.repository.verifyIdentity();
      const moved = path.join(tree.root, "repo-moved");
      const replacement = path.join(tree.root, "repo-replacement");
      fs.mkdirSync(replacement);
      fs.writeFileSync(path.join(replacement, "early.txt"), "replacement");
      fs.renameSync(tree.repository, moved);
      fs.renameSync(replacement, tree.repository);
      session.repository.verifyIdentity();
      assert.equal(
        session.repository.readFile("early.txt").toString(),
        "early",
      );
      const replaced = ScopedTreeSession.acquire({
        repository: tree.repository,
        cache: tree.cache,
        temp: tree.temp,
      });
      try {
        assert.notDeepEqual(replaced.repository.identity, original);
        assert.equal(
          replaced.repository.readFile("early.txt").toString(),
          "replacement",
        );
      } finally {
        replaced.dispose();
      }
    } finally {
      session.dispose();
      fs.rmSync(tree.root, { recursive: true, force: true });
    }
  },
);

test(
  "openat2 denies escapes, magic links, outside symlinks, and guest-config widening",
  { skip: !linux },
  () => {
    const tree = makeTree();
    fs.symlinkSync(
      path.join(tree.outside, "secret.txt"),
      path.join(tree.repository, "outside"),
    );
    fs.symlinkSync("early.txt", path.join(tree.repository, "inside-link"));
    fs.symlinkSync(
      "/proc/self/root/etc/passwd",
      path.join(tree.repository, "magic"),
    );
    assert.throws(
      () =>
        ScopedTreeSession.acquire({
          repository: tree.repository,
          cache: tree.cache,
          temp: tree.temp,
          hooks: { before: () => undefined },
        }),
      /hooks/,
    );
    assert.throws(
      () =>
        ScopedTreeSession.acquire({
          repository: tree.repository,
          cache: tree.cache,
          temp: tree.temp,
          mounts: { "/": tree.outside },
        }),
      /mounts/,
    );
    assert.throws(
      () =>
        ScopedTreeSession.acquire({
          repository: tree.repository,
          cache: tree.cache,
          temp: tree.temp,
          guestConfig: { privileged: true },
        }),
      /guestConfig/,
    );
    const session = ScopedTreeSession.acquire({
      repository: tree.repository,
      cache: tree.cache,
      temp: tree.temp,
    });
    try {
      assert.equal(
        session.repository.readFile("inside-link").toString(),
        "early",
      );
      for (const [operation, pathName] of [
        ["lookup", "../outside/secret.txt"],
        ["lookup", "outside"],
        ["lookup", "magic"],
        ["lookup", "/proc/self/fd/0"],
      ] as const) {
        assert.throws(
          () => session.repository.lookup(pathName),
          (error: unknown) =>
            error instanceof ScopedTreeOperationError &&
            error.capabilityPath === `filesystem.repository.${operation}` &&
            error.code === "denied",
          pathName,
        );
      }
    } finally {
      session.dispose();
      fs.rmSync(tree.root, { recursive: true, force: true });
    }
  },
);

test(
  "operation table is root-specific and keeps handles across unlink",
  { skip: !linux },
  () => {
    const tree = makeTree();
    const session = ScopedTreeSession.acquire({
      repository: tree.repository,
      cache: tree.cache,
      temp: tree.temp,
    });
    try {
      assert.throws(
        () => session.repository.createFile("new.txt"),
        (error: unknown) =>
          error instanceof ScopedTreeOperationError &&
          error.capabilityPath === "filesystem.repository.create",
      );
      assert.throws(
        () => session.repository.writeFile("early.txt", Buffer.from("x")),
        /filesystem\.repository\.write/,
      );
      assert.throws(() => session.repository.mkdir("dir"), /filesystem\.mkdir/);
      assert.throws(
        () => session.cache.symlink("early.txt", "link"),
        /filesystem\.symlink/,
      );
      assert.throws(() => session.cache.mount("nested"), /filesystem\.mount/);
      assert.throws(() => session.cache.rmdir("nested"), /filesystem\.rmdir/);
      assert.throws(() => session.cache.chmod("nested"), /filesystem\.chmod/);
      assert.throws(() => session.cache.chown("nested"), /filesystem\.chown/);
      session.cache.createFile("nested/late.txt");
      session.cache.writeFile(
        "nested/late.txt",
        Buffer.from("created-after-admission"),
      );
      assert.equal(
        session.cache.readFile("nested/late.txt").toString(),
        "created-after-admission",
      );
      session.cache.truncate("nested/late.txt", 7);
      assert.equal(
        session.cache.readFile("nested/late.txt").toString(),
        "created",
      );
      assert.throws(
        () => session.cache.renameSameDirectory("nested/late.txt", "moved.txt"),
        /filesystem\.private\.rename\.cross-directory/,
      );
      session.cache.createFile("same.txt");
      session.cache.writeFile("same.txt", Buffer.from("same-dir"));
      session.cache.renameSameDirectory("same.txt", "renamed.txt");
      session.cache.linkSameDirectory("renamed.txt", "linked.txt");
      const handle = session.cache.openHandle("linked.txt", "read");
      session.cache.unlink("linked.txt");
      assert.equal(session.cache.readHandle(handle).toString(), "same-dir");
      session.cache.closeHandle(handle);
      assert.throws(
        () => session.cache.readHandle(handle),
        /filesystem\.live-root\.handle/,
      );
      session.temp.createFile("keep.txt");
      session.temp.writeFile("keep.txt", Buffer.from("keep"));
      const closed = session.temp.openHandle("keep.txt", "read");
      const closedId = closed.id;
      session.temp.closeHandle(closed);
      const reopened = session.temp.openHandle("keep.txt", "read");
      assert.notEqual(reopened.id, closedId);
      assert.throws(
        () =>
          session.temp.readHandle({
            id: closedId,
            root: "temp",
            path: "keep.txt",
          }),
        /filesystem\.live-root\.handle/,
      );
      session.temp.closeHandle(reopened);
      execFileSync("mkfifo", [path.join(tree.cache, "fifo")]);
      assert.throws(
        () => session.cache.lookup("fifo"),
        (error: unknown) =>
          error instanceof ScopedTreeOperationError &&
          error.capabilityPath === "filesystem.private.lookup" &&
          error.code === "denied",
      );
      assert.throws(
        () => session.cache.readFile("fifo"),
        (error: unknown) =>
          error instanceof ScopedTreeOperationError &&
          error.capabilityPath === "filesystem.private.read" &&
          error.code === "denied",
      );
    } catch (error) {
      session.dispose();
      fs.rmSync(tree.root, { recursive: true, force: true });
      throw error;
    }
    session.dispose();
    fs.rmSync(tree.root, { recursive: true, force: true });
  },
);

test(
  "overlapping live roots fail closed and vfs widening cannot share identity",
  { skip: !linux },
  () => {
    const tree = makeTree();
    try {
      assert.throws(
        () =>
          ScopedTreeSession.acquire({
            repository: tree.repository,
            cache: tree.repository,
            temp: tree.temp,
          }),
        (error: unknown) =>
          error instanceof ScopedTreeOperationError &&
          error.capabilityPath === "filesystem.live-root.identity" &&
          error.code === "invalid",
      );
      assert.throws(
        () =>
          ScopedTreeSession.acquire({
            repository: tree.repository,
            cache: tree.cache,
            temp: tree.temp,
            vfs: { provider: "node" },
            backend: "qemu",
            callbacks: { onOpen: () => undefined },
          }),
        /vfs/,
      );
    } finally {
      fs.rmSync(tree.root, { recursive: true, force: true });
    }
  },
);

test(
  "concurrent sessions do not share writable roots or handle registries",
  { skip: !linux },
  () => {
    const firstTree = makeTree();
    const secondTree = makeTree();
    const first = ScopedTreeSession.acquire({
      repository: firstTree.repository,
      cache: firstTree.cache,
      temp: firstTree.temp,
    });
    const second = ScopedTreeSession.acquire({
      repository: secondTree.repository,
      cache: secondTree.cache,
      temp: secondTree.temp,
    });
    try {
      first.cache.createFile("a.txt");
      first.cache.writeFile("a.txt", Buffer.from("one"));
      second.cache.createFile("a.txt");
      second.cache.writeFile("a.txt", Buffer.from("two"));
      assert.equal(first.cache.readFile("a.txt").toString(), "one");
      assert.equal(second.cache.readFile("a.txt").toString(), "two");
      const handle = first.cache.openHandle("a.txt", "read");
      assert.throws(
        () => second.cache.readHandle(handle),
        /filesystem\.live-root\.handle/,
      );
      first.cache.closeHandle(handle);
    } finally {
      first.dispose();
      second.dispose();
      fs.rmSync(firstTree.root, { recursive: true, force: true });
      fs.rmSync(secondTree.root, { recursive: true, force: true });
    }
  },
);
