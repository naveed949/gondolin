import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  CAPABILITY_CEILING_SCHEMA_VERSION,
  CAPABILITY_INVOCATION_SCHEMA_VERSION,
  CapabilityAdmissionError,
} from "./capability-invocation.ts";
import {
  isDirectory,
  isRegularFile,
  loadLinuxScopedTreeAddon,
  type LinuxOpenat2Constants,
  type LinuxScopedTreeAddon,
  type LinuxStatx,
} from "./scoped-tree-linux.ts";

export const SCOPED_TREE_RUNNER_PROFILE = "scoped-tree-runner" as const;
export const SCOPED_TREE_RUNNER_ADMISSION = "scoped-tree-runner/v1" as const;

export type ScopedTreeRootKind = "repository" | "cache" | "temp";

export type ScopedTreeRootIdentity = {
  /** Decimal filesystem device major identity */
  devMajor: string;
  /** Decimal filesystem device minor identity */
  devMinor: string;
  /** Decimal directory inode identity */
  ino: string;
  /** Creation time from `statx` `btime` in `s` */
  btimeSec: string;
  /** Creation time from `statx` `btime` in `ns` */
  btimeNsec: number;
};

export type ScopedTreeRootBinding = {
  /** Live root kind */
  kind: ScopedTreeRootKind;
  /** Controller-owned host directory path */
  hostPath: string;
};

export type ScopedTreeHandle = {
  /** Session-local handle identity, never a reused kernel descriptor number */
  id: number;
  /** Root that granted the handle */
  root: ScopedTreeRootKind;
  /** Root-relative path used to open the handle */
  path: string;
};

export type ScopedTreeLookup = {
  /** Root-relative lookup path */
  path: string;
  /** Object kind after kernel-assisted resolution */
  type: "file" | "directory";
  /** Device/inode identity of the resolved object */
  identity: { devMajor: string; devMinor: string; ino: string };
};

export class ScopedTreeOperationError extends Error {
  readonly code:
    | "denied"
    | "unsupported"
    | "invalid"
    | "identity_mismatch"
    | "unavailable";
  /** Canonical capability path that failed closed */
  readonly capabilityPath: string;

  constructor(
    code: ScopedTreeOperationError["code"],
    capabilityPath: string,
    message: string,
  ) {
    super(`${capabilityPath}: ${message}`);
    this.name = "ScopedTreeOperationError";
    this.code = code;
    this.capabilityPath = capabilityPath;
  }
}

const CEILING_KEYS = [
  "schemaVersion",
  "profile",
  "filesystem",
  "process",
  "environment",
  "network",
  "credentials",
  "git",
  "ipc",
  "devices",
] as const;

const REQUEST_KEYS = [
  "schemaVersion",
  "invocationId",
  "profile",
  "target",
  "launch",
  "capabilities",
  "limits",
] as const;

const IDENTITY_MASK_NAMES = ["TYPE", "INO", "BTIME"] as const;

type OwnedHandle = {
  id: number;
  fd: number;
  root: ScopedTreeRootKind;
  path: string;
  ino: string;
  devMajor: string;
  devMinor: string;
};

type PinnedRoot = {
  kind: ScopedTreeRootKind;
  hostPath: string;
  fd: number;
  identity: ScopedTreeRootIdentity;
};

function deny(
  code: ScopedTreeOperationError["code"],
  capabilityPath: string,
  message: string,
): never {
  throw new ScopedTreeOperationError(code, capabilityPath, message);
}

function admission(
  code: CapabilityAdmissionError["code"],
  capabilityPath: string,
  message: string,
): never {
  throw new CapabilityAdmissionError(code, `${capabilityPath}: ${message}`);
}

function object(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    admission("invalid_request", label, "must be a plain data object");
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    admission("invalid_request", label, "must be a plain data object");
  }
  for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
    if (typeof entry === "function") {
      admission(
        "unsupported",
        `${label}.${key}`,
        "callbacks are not capability data",
      );
    }
  }
  return value as Record<string, unknown>;
}

function exactKeys(
  value: Record<string, unknown>,
  allowed: readonly string[],
  label: string,
): void {
  const unknown = Object.keys(value).filter((key) => !allowed.includes(key));
  const missing = allowed.filter((key) => !Object.hasOwn(value, key));
  if (unknown.length) {
    admission(
      "invalid_request",
      label,
      `contains unknown critical field(s): ${unknown.sort().join(", ")}`,
    );
  }
  if (missing.length) {
    admission(
      "invalid_request",
      label,
      `is missing required field(s): ${missing.join(", ")}`,
    );
  }
}

function literal(
  value: unknown,
  expected: string,
  capabilityPath: string,
  code: CapabilityAdmissionError["code"] = "unsupported",
): void {
  if (value !== expected) {
    admission(code, capabilityPath, `must be ${JSON.stringify(expected)}`);
  }
}

function nonEmptyString(value: unknown, capabilityPath: string): string {
  if (typeof value !== "string" || value.length === 0 || value.includes("\0")) {
    admission(
      "invalid_request",
      capabilityPath,
      "must be a non-empty string without NUL bytes",
    );
  }
  return value;
}

function identityFromStatx(stat: LinuxStatx): ScopedTreeRootIdentity {
  return {
    devMajor: String(stat.devMajor),
    devMinor: String(stat.devMinor),
    ino: stat.ino,
    btimeSec: stat.btimeSec,
    btimeNsec: stat.btimeNsec,
  };
}

function sameIdentity(
  left: ScopedTreeRootIdentity,
  right: ScopedTreeRootIdentity,
): boolean {
  return (
    left.devMajor === right.devMajor &&
    left.devMinor === right.devMinor &&
    left.ino === right.ino &&
    left.btimeSec === right.btimeSec &&
    left.btimeNsec === right.btimeNsec
  );
}

function requireIdentityFields(
  stat: LinuxStatx,
  constants: LinuxOpenat2Constants,
  capabilityPath: string,
): void {
  const missing = IDENTITY_MASK_NAMES.filter((name) => {
    const bit = constants[`STATX_${name}`];
    return (stat.mask & bit) !== bit;
  });
  if (missing.length) {
    deny(
      "unavailable",
      capabilityPath,
      `missing directory identity field(s): ${missing.join(", ").toLowerCase()}`,
    );
  }
}

function parentRelative(relativePath: string): {
  parent: string;
  name: string;
} {
  const normalized = relativePath.replace(/\\/g, "/").replace(/\/+$/, "");
  const index = normalized.lastIndexOf("/");
  if (index <= 0) {
    return { parent: ".", name: normalized === "." ? "" : normalized };
  }
  return {
    parent: normalized.slice(0, index) || ".",
    name: normalized.slice(index + 1),
  };
}

function rootRelativePath(input: string, capabilityPath: string): string {
  if (typeof input !== "string" || input.length === 0 || input.includes("\0")) {
    deny(
      "invalid",
      capabilityPath,
      "path must be a non-empty string without NUL bytes",
    );
  }
  if (input === "/") return ".";
  return input.startsWith("/") ? input.replace(/^\/+/, "") : input;
}

function catchLinux<T>(capabilityPath: string, operation: () => T): T {
  try {
    return operation();
  } catch (error) {
    if (
      error instanceof ScopedTreeOperationError ||
      error instanceof CapabilityAdmissionError
    ) {
      throw error;
    }
    const errno = (error as NodeJS.ErrnoException).errno;
    if (
      errno === os.constants.errno.ENOSYS ||
      errno === os.constants.errno.EOPNOTSUPP
    ) {
      deny(
        "unsupported",
        capabilityPath,
        "kernel-assisted resolution is unavailable on this host",
      );
    }
    deny(
      "denied",
      capabilityPath,
      errno != null
        ? `kernel-assisted resolution failed with errno ${errno}`
        : "kernel-assisted resolution failed",
    );
  }
}

/** One pinned live root with kernel-assisted resolution under the admitted descriptor */
export class ScopedTreeRoot {
  readonly kind: ScopedTreeRootKind;
  readonly hostPath: string;
  readonly identity: ScopedTreeRootIdentity;
  private readonly linux: LinuxScopedTreeAddon;
  private readonly constants: LinuxOpenat2Constants;
  private readonly resolveFlags: number;
  private readonly identityMask: number;
  private readonly handles = new Map<number, OwnedHandle>();
  private nextHandleId = 1;
  private fd: number;
  private closed = false;

  constructor(linux: LinuxScopedTreeAddon, pinned: PinnedRoot) {
    this.linux = linux;
    this.constants = linux.constants;
    this.kind = pinned.kind;
    this.hostPath = pinned.hostPath;
    this.identity = pinned.identity;
    this.fd = pinned.fd;
    this.resolveFlags =
      linux.constants.RESOLVE_BENEATH | linux.constants.RESOLVE_NO_MAGICLINKS;
    this.identityMask =
      linux.constants.STATX_TYPE |
      linux.constants.STATX_MODE |
      linux.constants.STATX_INO |
      linux.constants.STATX_BTIME |
      linux.constants.STATX_SIZE |
      linux.constants.STATX_NLINK;
  }

  private capability(operation: string): string {
    return this.kind === "repository"
      ? `filesystem.repository.${operation}`
      : `filesystem.private.${operation}`;
  }

  private requireOpen(): void {
    if (this.closed) {
      deny(
        "unavailable",
        "filesystem.live-root.handle",
        "root has been torn down",
      );
    }
  }

  private isPrivate(): boolean {
    return this.kind !== "repository";
  }

  private openResolved(
    relativePath: string,
    flags: number,
    capabilityPath: string,
    mode = 0,
  ): number {
    this.requireOpen();
    const resolved = rootRelativePath(relativePath, capabilityPath);
    return catchLinux(capabilityPath, () =>
      this.linux.openat2(this.fd, resolved, flags, mode, this.resolveFlags),
    );
  }

  private inspect(
    relativePath: string,
    capabilityPath: string,
    follow: boolean,
  ): LinuxStatx {
    const flags =
      this.constants.O_CLOEXEC |
      this.constants.O_PATH |
      (follow ? 0 : this.constants.O_NOFOLLOW);
    const fd = this.openResolved(relativePath, flags, capabilityPath);
    try {
      const stat = catchLinux(capabilityPath, () =>
        this.linux.statx(
          fd,
          "",
          this.constants.AT_EMPTY_PATH,
          this.identityMask,
        ),
      );
      requireIdentityFields(
        stat,
        this.constants,
        "filesystem.live-root.identity",
      );
      return stat;
    } finally {
      this.linux.close(fd);
    }
  }

  verifyIdentity(): ScopedTreeRootIdentity {
    this.requireOpen();
    const stat = catchLinux("filesystem.live-root.identity", () =>
      this.linux.statx(
        this.fd,
        "",
        this.constants.AT_EMPTY_PATH,
        this.identityMask,
      ),
    );
    requireIdentityFields(
      stat,
      this.constants,
      "filesystem.live-root.identity",
    );
    if (!isDirectory(stat.mode, this.constants)) {
      deny(
        "identity_mismatch",
        "filesystem.live-root.identity",
        "root is no longer a directory",
      );
    }
    const actual = identityFromStatx(stat);
    if (!sameIdentity(actual, this.identity)) {
      deny(
        "identity_mismatch",
        "filesystem.live-root.identity",
        "opened root descriptor identity does not match the admitted grant",
      );
    }
    return actual;
  }

  lookup(relativePath: string): ScopedTreeLookup {
    const capabilityPath = this.capability("lookup");
    const stat = this.inspect(relativePath, capabilityPath, true);
    if (isDirectory(stat.mode, this.constants)) {
      return {
        path: rootRelativePath(relativePath, capabilityPath),
        type: "directory",
        identity: {
          devMajor: String(stat.devMajor),
          devMinor: String(stat.devMinor),
          ino: stat.ino,
        },
      };
    }
    if (!isRegularFile(stat.mode, this.constants)) {
      deny(
        "denied",
        capabilityPath,
        "lookup is limited to regular files and directories within the admitted root",
      );
    }
    return {
      path: rootRelativePath(relativePath, capabilityPath),
      type: "file",
      identity: {
        devMajor: String(stat.devMajor),
        devMinor: String(stat.devMinor),
        ino: stat.ino,
      },
    };
  }

  enumerate(relativePath: string): string[] {
    const capabilityPath = this.capability("enumerate");
    const fd = this.openResolved(
      relativePath,
      this.constants.O_RDONLY |
        this.constants.O_DIRECTORY |
        this.constants.O_CLOEXEC,
      capabilityPath,
    );
    try {
      return catchLinux(capabilityPath, () => this.linux.listat(fd));
    } finally {
      this.linux.close(fd);
    }
  }

  readFile(relativePath: string): Buffer {
    const handle = this.openHandle(relativePath, "read");
    try {
      return this.readHandle(handle);
    } finally {
      this.closeHandle(handle);
    }
  }

  createFile(relativePath: string): void {
    const capabilityPath = this.capability("create");
    if (!this.isPrivate()) {
      deny("denied", capabilityPath, "repository roots cannot create files");
    }
    const fd = this.openResolved(
      relativePath,
      this.constants.O_RDWR |
        this.constants.O_CREAT |
        this.constants.O_EXCL |
        this.constants.O_CLOEXEC |
        this.constants.O_NONBLOCK,
      capabilityPath,
      0o600,
    );
    try {
      const stat = catchLinux(capabilityPath, () =>
        this.linux.statx(
          fd,
          "",
          this.constants.AT_EMPTY_PATH,
          this.identityMask,
        ),
      );
      if (!isRegularFile(stat.mode, this.constants)) {
        deny("denied", capabilityPath, "create is limited to regular files");
      }
    } finally {
      this.linux.close(fd);
    }
  }

  writeFile(relativePath: string, contents: Buffer): void {
    const capabilityPath = this.capability("write");
    if (!this.isPrivate()) {
      deny("denied", capabilityPath, "repository roots cannot write files");
    }
    const handle = this.openHandle(relativePath, "write");
    try {
      this.writeHandle(handle, contents);
    } finally {
      this.closeHandle(handle);
    }
  }

  truncate(relativePath: string, size: number): void {
    const capabilityPath = this.capability("truncate");
    if (!this.isPrivate()) {
      deny("denied", capabilityPath, "repository roots cannot truncate files");
    }
    const handle = this.openHandle(relativePath, "write");
    try {
      fs.ftruncateSync(this.requireHandle(handle, capabilityPath).fd, size);
    } finally {
      this.closeHandle(handle);
    }
  }

  unlink(relativePath: string): void {
    const capabilityPath = this.capability("unlink");
    if (!this.isPrivate()) {
      deny("denied", capabilityPath, "repository roots cannot unlink files");
    }
    const stat = this.inspect(relativePath, capabilityPath, false);
    if (!isRegularFile(stat.mode, this.constants)) {
      deny("denied", capabilityPath, "unlink is limited to regular files");
    }
    const { parent, name } = parentRelative(
      rootRelativePath(relativePath, capabilityPath),
    );
    const parentFd = this.openResolved(
      parent,
      this.constants.O_RDONLY |
        this.constants.O_DIRECTORY |
        this.constants.O_CLOEXEC,
      capabilityPath,
    );
    try {
      catchLinux(capabilityPath, () => this.linux.unlinkat(parentFd, name, 0));
    } finally {
      this.linux.close(parentFd);
    }
  }

  renameSameDirectory(oldPath: string, newPath: string): void {
    const capabilityPath = this.capability("rename");
    if (!this.isPrivate()) {
      deny("denied", capabilityPath, "repository roots cannot rename files");
    }
    const oldRelative = rootRelativePath(oldPath, capabilityPath);
    const newRelative = rootRelativePath(newPath, capabilityPath);
    const oldParent = parentRelative(oldRelative);
    const newParent = parentRelative(newRelative);
    if (oldParent.parent !== newParent.parent) {
      deny(
        "denied",
        "filesystem.private.rename.cross-directory",
        "rename across directories or roots is denied",
      );
    }
    const stat = this.inspect(oldRelative, capabilityPath, false);
    if (!isRegularFile(stat.mode, this.constants)) {
      deny("denied", capabilityPath, "rename is limited to regular files");
    }
    const parentFd = this.openResolved(
      oldParent.parent,
      this.constants.O_RDONLY |
        this.constants.O_DIRECTORY |
        this.constants.O_CLOEXEC,
      capabilityPath,
    );
    try {
      catchLinux(capabilityPath, () =>
        this.linux.renameat2(
          parentFd,
          oldParent.name,
          parentFd,
          newParent.name,
          0,
        ),
      );
    } finally {
      this.linux.close(parentFd);
    }
  }

  linkSameDirectory(existingPath: string, newPath: string): void {
    const capabilityPath = this.capability("link");
    if (!this.isPrivate()) {
      deny("denied", capabilityPath, "repository roots cannot hard-link files");
    }
    const existingRelative = rootRelativePath(existingPath, capabilityPath);
    const newRelative = rootRelativePath(newPath, capabilityPath);
    const existingParent = parentRelative(existingRelative);
    const newParent = parentRelative(newRelative);
    if (existingParent.parent !== newParent.parent) {
      deny(
        "denied",
        "filesystem.private.link.cross-directory",
        "hard links across directories or roots are denied",
      );
    }
    const stat = this.inspect(existingRelative, capabilityPath, false);
    if (!isRegularFile(stat.mode, this.constants)) {
      deny("denied", capabilityPath, "hard links are limited to regular files");
    }
    const parentFd = this.openResolved(
      existingParent.parent,
      this.constants.O_RDONLY |
        this.constants.O_DIRECTORY |
        this.constants.O_CLOEXEC,
      capabilityPath,
    );
    try {
      catchLinux(capabilityPath, () =>
        this.linux.linkat(
          parentFd,
          existingParent.name,
          parentFd,
          newParent.name,
          0,
        ),
      );
    } finally {
      this.linux.close(parentFd);
    }
  }

  mkdir(relativePath: string): never {
    deny(
      "denied",
      this.capability("mkdir"),
      `create directory is denied at ${relativePath}`,
    );
  }

  rmdir(relativePath: string): never {
    deny(
      "denied",
      this.capability("rmdir"),
      `remove directory is denied at ${relativePath}`,
    );
  }

  symlink(target: string, relativePath: string): never {
    deny(
      "denied",
      this.capability("symlink"),
      `create symlink is denied from ${relativePath} to ${target}`,
    );
  }

  chmod(relativePath: string): never {
    deny(
      "denied",
      this.capability("chmod"),
      `change mode is denied at ${relativePath}`,
    );
  }

  chown(relativePath: string): never {
    deny(
      "denied",
      this.capability("chown"),
      `change ownership is denied at ${relativePath}`,
    );
  }

  mount(relativePath: string): never {
    deny(
      "denied",
      this.capability("mount"),
      `mount is denied at ${relativePath}`,
    );
  }

  openHandle(relativePath: string, access: "read" | "write"): ScopedTreeHandle {
    const capabilityPath = this.capability(
      access === "read" ? "read" : "write",
    );
    if (access === "write" && !this.isPrivate()) {
      deny(
        "denied",
        capabilityPath,
        "repository roots cannot write through handles",
      );
    }
    const flags =
      this.constants.O_CLOEXEC |
      this.constants.O_NONBLOCK |
      (access === "read" ? this.constants.O_RDONLY : this.constants.O_RDWR);
    const fd = this.openResolved(relativePath, flags, capabilityPath);
    try {
      const stat = catchLinux(capabilityPath, () =>
        this.linux.statx(
          fd,
          "",
          this.constants.AT_EMPTY_PATH,
          this.identityMask,
        ),
      );
      if (!isRegularFile(stat.mode, this.constants)) {
        deny(
          "denied",
          capabilityPath,
          "open handles are limited to regular files",
        );
      }
      const id = this.nextHandleId++;
      this.handles.set(id, {
        id,
        fd,
        root: this.kind,
        path: rootRelativePath(relativePath, capabilityPath),
        ino: stat.ino,
        devMajor: String(stat.devMajor),
        devMinor: String(stat.devMinor),
      });
      return {
        id,
        root: this.kind,
        path: rootRelativePath(relativePath, capabilityPath),
      };
    } catch (error) {
      this.linux.close(fd);
      throw error;
    }
  }

  readHandle(handle: ScopedTreeHandle): Buffer {
    const owned = this.requireHandle(handle, "filesystem.live-root.handle");
    return fs.readFileSync(owned.fd);
  }

  writeHandle(handle: ScopedTreeHandle, contents: Buffer): void {
    if (!this.isPrivate()) {
      deny(
        "denied",
        this.capability("write"),
        "repository roots cannot write through handles",
      );
    }
    const owned = this.requireHandle(handle, this.capability("write"));
    fs.ftruncateSync(owned.fd, 0);
    fs.writeSync(owned.fd, contents, 0, contents.length, 0);
  }

  closeHandle(handle: ScopedTreeHandle): void {
    const owned = this.handles.get(handle.id);
    if (!owned) {
      deny(
        "denied",
        "filesystem.live-root.handle",
        "handle is closed or unknown",
      );
    }
    this.handles.delete(handle.id);
    try {
      this.linux.close(owned.fd);
    } catch {
      deny("unavailable", "filesystem.live-root.handle", "handle close failed");
    }
  }

  dispose(): void {
    if (this.closed) return;
    const failures: string[] = [];
    for (const owned of this.handles.values()) {
      try {
        this.linux.close(owned.fd);
      } catch {
        failures.push(`handle ${owned.id}`);
      }
    }
    this.handles.clear();
    try {
      this.linux.close(this.fd);
    } catch {
      failures.push("root");
    }
    this.closed = true;
    if (failures.length) {
      deny(
        "unavailable",
        "filesystem.live-root.handle",
        `teardown failed to close ${failures.join(", ")}`,
      );
    }
  }

  private requireHandle(
    handle: ScopedTreeHandle,
    capabilityPath: string,
  ): OwnedHandle {
    this.requireOpen();
    const owned = this.handles.get(handle.id);
    if (!owned || owned.root !== handle.root) {
      deny(
        "denied",
        capabilityPath,
        "handle is closed, reused, or unbound from this root",
      );
    }
    return owned;
  }
}

function pinRoot(
  linux: LinuxScopedTreeAddon,
  binding: ScopedTreeRootBinding,
): PinnedRoot {
  const hostPath = path.resolve(
    nonEmptyString(binding.hostPath, `filesystem.${binding.kind}.hostPath`),
  );
  const constants = linux.constants;
  const flags =
    constants.O_RDONLY |
    constants.O_DIRECTORY |
    constants.O_NOFOLLOW |
    constants.O_CLOEXEC;
  let fd: number;
  try {
    fd = linux.openat2(constants.AT_FDCWD, hostPath, flags, 0, 0);
  } catch (error) {
    const errno = (error as NodeJS.ErrnoException).errno;
    deny(
      "unavailable",
      `filesystem.${binding.kind}`,
      errno != null
        ? `could not open directory descriptor (errno ${errno})`
        : "could not open directory descriptor",
    );
  }
  try {
    const stat = catchLinux(`filesystem.${binding.kind}`, () =>
      linux.statx(
        fd,
        "",
        constants.AT_EMPTY_PATH,
        constants.STATX_TYPE |
          constants.STATX_MODE |
          constants.STATX_INO |
          constants.STATX_BTIME,
      ),
    );
    requireIdentityFields(stat, constants, "filesystem.live-root.identity");
    if (!isDirectory(stat.mode, constants)) {
      deny(
        "invalid",
        `filesystem.${binding.kind}`,
        "host path must remain a directory",
      );
    }
    return {
      kind: binding.kind,
      hostPath,
      fd,
      identity: identityFromStatx(stat),
    };
  } catch (error) {
    linux.close(fd);
    throw error;
  }
}

export type ScopedTreeRootsSpec = {
  /** Controller-owned repository read root */
  repository: string;
  /** Fresh invocation-owned cache write root */
  cache: string;
  /** Fresh invocation-owned temporary write root */
  temp: string;
  /** Adapter hook object rejected at admission */
  hooks?: unknown;
  /** Host VFS widening object rejected at admission */
  vfs?: unknown;
  /** Extra mount table rejected at admission */
  mounts?: unknown;
  /** Guest configuration widening object rejected at admission */
  guestConfig?: unknown;
  /** Callback table rejected at admission */
  callbacks?: unknown;
  /** Backend selection widening value rejected at admission */
  backend?: unknown;
};

/** Acquire three disjoint live roots and retain their directory descriptors */
export class ScopedTreeSession {
  readonly repository: ScopedTreeRoot;
  readonly cache: ScopedTreeRoot;
  readonly temp: ScopedTreeRoot;
  private disposed = false;

  private constructor(roots: {
    repository: ScopedTreeRoot;
    cache: ScopedTreeRoot;
    temp: ScopedTreeRoot;
  }) {
    this.repository = roots.repository;
    this.cache = roots.cache;
    this.temp = roots.temp;
  }

  static acquire(spec: ScopedTreeRootsSpec): ScopedTreeSession {
    for (const [name, value] of Object.entries({
      hooks: spec.hooks,
      vfs: spec.vfs,
      mounts: spec.mounts,
      guestConfig: spec.guestConfig,
      callbacks: spec.callbacks,
      backend: spec.backend,
    })) {
      if (value !== undefined) {
        admission(
          "unsupported",
          name,
          "adapter-specific inputs cannot widen live-root authority",
        );
      }
    }
    const linux = loadLinuxScopedTreeAddon();
    const pinned: PinnedRoot[] = [];
    try {
      for (const kind of ["repository", "cache", "temp"] as const) {
        pinned.push(pinRoot(linux, { kind, hostPath: spec[kind] }));
      }
    } catch (error) {
      for (const root of pinned) {
        try {
          linux.close(root.fd);
        } catch {
          // Preserve the original acquisition failure.
        }
      }
      throw error;
    }
    const identities = pinned.map(
      (root) =>
        `${root.identity.devMajor}:${root.identity.devMinor}:${root.identity.ino}:${root.identity.btimeSec}:${root.identity.btimeNsec}`,
    );
    if (new Set(identities).size !== pinned.length) {
      for (const root of pinned) {
        try {
          linux.close(root.fd);
        } catch {
          // Preserve the disjoint-root denial as the admission outcome.
        }
      }
      deny(
        "invalid",
        "filesystem.live-root.identity",
        "repository, cache, and temp roots must be disjoint filesystem objects",
      );
    }
    return new ScopedTreeSession({
      repository: new ScopedTreeRoot(linux, pinned[0]!),
      cache: new ScopedTreeRoot(linux, pinned[1]!),
      temp: new ScopedTreeRoot(linux, pinned[2]!),
    });
  }

  root(kind: ScopedTreeRootKind): ScopedTreeRoot {
    if (kind === "repository") return this.repository;
    if (kind === "cache") return this.cache;
    return this.temp;
  }

  dispose(): void {
    if (this.disposed) return;
    const roots = [this.repository, this.cache, this.temp];
    const errors: unknown[] = [];
    for (const root of roots) {
      try {
        root.dispose();
      } catch (error) {
        errors.push(error);
      }
    }
    this.disposed = true;
    if (errors.length) throw errors[0];
  }
}

export type ScopedTreeRunnerCeiling = {
  /** Capability ceiling schema identifier */
  schemaVersion: typeof CAPABILITY_CEILING_SCHEMA_VERSION;
  /** Future scoped-tree profile identifier, currently unsupported for launch */
  profile: typeof SCOPED_TREE_RUNNER_PROFILE;
  /** Controller-owned live roots */
  filesystem: {
    /** Host repository read-root directory */
    repository: { hostPath: string };
    /** Fresh private cache write-root directory */
    cache: { hostPath: string };
    /** Fresh private temporary write-root directory */
    temp: { hostPath: string };
  };
  /** Fork and subsequent exec remain denied */
  process: { descendants: "deny" };
  /** Payload environment must be empty */
  environment: "empty";
  /** Denied network authority */
  network: "none";
  /** Denied credential authority */
  credentials: "none";
  /** Denied Git authority */
  git: "none";
  /** Denied interprocess communication authority */
  ipc: "none";
  /** Denied device authority */
  devices: "none";
};

export type ScopedTreeRunnerInvocationRequest = {
  /** Capability invocation schema identifier */
  schemaVersion: typeof CAPABILITY_INVOCATION_SCHEMA_VERSION;
  /** Caller-selected replay identity */
  invocationId: string;
  /** Future scoped-tree profile identifier, currently unsupported for launch */
  profile: typeof SCOPED_TREE_RUNNER_PROFILE;
  /** Controller-registered target identity, never a public command */
  target: { id: string };
  /** Registered target binding; payload launch remains unimplemented */
  launch: {
    /** Exact executable path from trusted registration */
    executable: string;
    /** Literal argument vector excluding the executable */
    args: string[];
  };
  /** Complete invocation authority, with independent denied domains */
  capabilities: {
    /** Live repository read root and private write roots */
    filesystem: {
      /** Host repository read-root directory */
      repository: { hostPath: string };
      /** Fresh private cache write-root directory */
      cache: { hostPath: string };
      /** Fresh private temporary write-root directory */
      temp: { hostPath: string };
    };
    /** Fork and subsequent exec remain denied */
    process: { descendants: "deny" };
    /** Payload environment must be empty */
    environment: "empty";
    /** Denied network authority */
    network: "none";
    /** Denied credential authority */
    credentials: "none";
    /** Denied Git authority */
    git: "none";
    /** Denied interprocess communication authority */
    ipc: "none";
    /** Denied device authority */
    devices: "none";
  };
  /** Payload resource bounds, not enforced until payload accounting exists */
  limits: {
    /** Cumulative payload-subtree CPU in `ms` */
    cpuMs: number;
    /** Payload cgroup charged peak and ceiling in `bytes` */
    memoryBytes: number;
    /** Maximum descendants, excluding the entrypoint */
    children: number;
    /** Returned UTF-8 payload bound in `bytes` */
    outputBytes: number;
    /** Payload runner interval in `ms` */
    wallMs: number;
  };
};

function normalizeFilesystemRoots(
  value: unknown,
  label: string,
): ScopedTreeRunnerCeiling["filesystem"] {
  const filesystem = object(value, label);
  exactKeys(filesystem, ["repository", "cache", "temp"], label);
  const roots = {} as ScopedTreeRunnerCeiling["filesystem"];
  for (const kind of ["repository", "cache", "temp"] as const) {
    const root = object(filesystem[kind], `${label}.${kind}`);
    exactKeys(root, ["hostPath"], `${label}.${kind}`);
    roots[kind] = {
      hostPath: path.resolve(
        nonEmptyString(root.hostPath, `${label}.${kind}.hostPath`),
      ),
    };
  }
  return roots;
}

/** Normalize a scoped-tree ceiling without claiming an active profile */
export function canonicalizeScopedTreeRunnerCeiling(
  input: unknown,
): ScopedTreeRunnerCeiling {
  const root = object(input, "ceiling");
  exactKeys(root, CEILING_KEYS, "ceiling");
  literal(
    root.schemaVersion,
    CAPABILITY_CEILING_SCHEMA_VERSION,
    "ceiling.schemaVersion",
  );
  literal(root.profile, SCOPED_TREE_RUNNER_PROFILE, "ceiling.profile");
  const process = object(root.process, "ceiling.process");
  exactKeys(process, ["descendants"], "ceiling.process");
  literal(process.descendants, "deny", "ceiling.process.descendants");
  literal(root.environment, "empty", "ceiling.environment");
  literal(root.network, "none", "ceiling.network");
  literal(root.credentials, "none", "ceiling.credentials");
  literal(root.git, "none", "ceiling.git");
  literal(root.ipc, "none", "ceiling.ipc");
  literal(root.devices, "none", "ceiling.devices");
  return {
    schemaVersion: CAPABILITY_CEILING_SCHEMA_VERSION,
    profile: SCOPED_TREE_RUNNER_PROFILE,
    filesystem: normalizeFilesystemRoots(root.filesystem, "ceiling.filesystem"),
    process: { descendants: "deny" },
    environment: "empty",
    network: "none",
    credentials: "none",
    git: "none",
    ipc: "none",
    devices: "none",
  };
}

function finiteInteger(value: unknown, capabilityPath: string): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0) {
    admission(
      "invalid_request",
      capabilityPath,
      "must be a non-negative integer",
    );
  }
  return value;
}

/** Normalize a scoped-tree request; invoke remains unsupported */
export function canonicalizeScopedTreeRunnerInvocationRequest(
  input: unknown,
): ScopedTreeRunnerInvocationRequest {
  const root = object(input, "request");
  exactKeys(root, REQUEST_KEYS, "request");
  literal(
    root.schemaVersion,
    CAPABILITY_INVOCATION_SCHEMA_VERSION,
    "request.schemaVersion",
  );
  literal(root.profile, SCOPED_TREE_RUNNER_PROFILE, "request.profile");
  const target = object(root.target, "request.target");
  exactKeys(target, ["id"], "request.target");
  const launch = object(root.launch, "request.launch");
  exactKeys(launch, ["executable", "args"], "request.launch");
  if (
    !Array.isArray(launch.args) ||
    launch.args.some((arg) => typeof arg !== "string")
  ) {
    admission(
      "invalid_request",
      "request.launch.args",
      "must be a literal string vector",
    );
  }
  const capabilities = object(root.capabilities, "request.capabilities");
  exactKeys(
    capabilities,
    [
      "filesystem",
      "process",
      "environment",
      "network",
      "credentials",
      "git",
      "ipc",
      "devices",
    ],
    "request.capabilities",
  );
  const process = object(capabilities.process, "request.capabilities.process");
  exactKeys(process, ["descendants"], "request.capabilities.process");
  literal(
    process.descendants,
    "deny",
    "request.capabilities.process.descendants",
  );
  literal(
    capabilities.environment,
    "empty",
    "request.capabilities.environment",
  );
  literal(capabilities.network, "none", "request.capabilities.network");
  literal(capabilities.credentials, "none", "request.capabilities.credentials");
  literal(capabilities.git, "none", "request.capabilities.git");
  literal(capabilities.ipc, "none", "request.capabilities.ipc");
  literal(capabilities.devices, "none", "request.capabilities.devices");
  const limits = object(root.limits, "request.limits");
  exactKeys(
    limits,
    ["cpuMs", "memoryBytes", "children", "outputBytes", "wallMs"],
    "request.limits",
  );
  return {
    schemaVersion: CAPABILITY_INVOCATION_SCHEMA_VERSION,
    invocationId: nonEmptyString(root.invocationId, "request.invocationId"),
    profile: SCOPED_TREE_RUNNER_PROFILE,
    target: { id: nonEmptyString(target.id, "request.target.id") },
    launch: {
      executable: nonEmptyString(
        launch.executable,
        "request.launch.executable",
      ),
      args: launch.args as string[],
    },
    capabilities: {
      filesystem: normalizeFilesystemRoots(
        capabilities.filesystem,
        "request.capabilities.filesystem",
      ),
      process: { descendants: "deny" },
      environment: "empty",
      network: "none",
      credentials: "none",
      git: "none",
      ipc: "none",
      devices: "none",
    },
    limits: {
      cpuMs: finiteInteger(limits.cpuMs, "request.limits.cpuMs"),
      memoryBytes: finiteInteger(
        limits.memoryBytes,
        "request.limits.memoryBytes",
      ),
      children: finiteInteger(limits.children, "request.limits.children"),
      outputBytes: finiteInteger(
        limits.outputBytes,
        "request.limits.outputBytes",
      ),
      wallMs: finiteInteger(limits.wallMs, "request.limits.wallMs"),
    },
  };
}

/** One-shot profile context that pins live roots and refuses payload launch */
export class ScopedTreeRunnerInvocationContext {
  readonly ceiling: Readonly<ScopedTreeRunnerCeiling>;
  readonly session: ScopedTreeSession;

  private constructor(
    ceiling: ScopedTreeRunnerCeiling,
    session: ScopedTreeSession,
  ) {
    this.ceiling = ceiling;
    this.session = session;
  }

  static create(input: unknown): ScopedTreeRunnerInvocationContext {
    const ceiling = canonicalizeScopedTreeRunnerCeiling(input);
    const session = ScopedTreeSession.acquire({
      repository: ceiling.filesystem.repository.hostPath,
      cache: ceiling.filesystem.cache.hostPath,
      temp: ceiling.filesystem.temp.hostPath,
    });
    return new ScopedTreeRunnerInvocationContext(ceiling, session);
  }

  invoke(input: unknown): never {
    let requestError: unknown;
    try {
      canonicalizeScopedTreeRunnerInvocationRequest(input);
    } catch (error) {
      requestError = error;
    }
    try {
      this.session.dispose();
    } catch (error) {
      throw error;
    }
    if (requestError) throw requestError;
    admission(
      "unsupported",
      "request.launch",
      "scoped-tree-runner payload launch, guest ambient confinement, and payload-only resource accounting are unimplemented",
    );
  }
}
