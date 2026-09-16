import fs from "node:fs";
import type { Stats } from "node:fs";

import { createErrnoError } from "./vfs/errors.ts";
import type { VirtualFileHandle, VirtualProvider } from "./vfs/node/index.ts";
import { ERRNO, isWriteFlag, VirtualProviderClass } from "./vfs/utils.ts";

export type HostDirectoryIdentity = {
  /** Host filesystem device identity */
  dev: bigint;
  /** Host filesystem inode identity */
  ino: bigint;
  /** Directory creation time in `ns` */
  birthtimeNs: bigint;
};

export type ScopedTreeKind = "repository" | "private";

export type ScopedTreeDecision = {
  operation: string;
  guestPath: string;
  decision: "granted" | "denied";
  detail: string;
};

const SYMLINK_BOUND = 8;
const NOFOLLOW = fs.constants.O_NOFOLLOW ?? 0;
const DIRECTORY = fs.constants.O_DIRECTORY ?? 0;
const CLOEXEC = (fs.constants as { O_CLOEXEC?: number }).O_CLOEXEC ?? 0;
const RDONLY = fs.constants.O_RDONLY;
const CREAT = fs.constants.O_CREAT ?? 0;
const EXCL = fs.constants.O_EXCL ?? 0;

const PRIVATE_ALLOWED = new Set([
  "lookup",
  "read",
  "create",
  "write",
  "truncate",
  "unlink",
  "rename-same-directory",
  "link-same-directory",
]);
const REPOSITORY_ALLOWED = new Set(["lookup", "read"]);

export function serializeDirectoryIdentity(identity: HostDirectoryIdentity): {
  dev: string;
  ino: string;
  birthtimeNs: string;
} {
  return {
    dev: String(identity.dev),
    ino: String(identity.ino),
    birthtimeNs: String(identity.birthtimeNs),
  };
}

export function identitiesEqual(
  left: HostDirectoryIdentity,
  right: HostDirectoryIdentity,
): boolean {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.birthtimeNs === right.birthtimeNs
  );
}

function openatPath(dirfd: number, name: string): string {
  if (name.includes("/") || name.includes("\0") || name.length === 0) {
    throw createErrnoError(ERRNO.EINVAL, "open", name);
  }
  if (process.platform === "linux") return `/proc/self/fd/${dirfd}/${name}`;
  if (process.platform === "darwin") return `/dev/fd/${dirfd}/${name}`;
  throw createErrnoError(ERRNO.ENOSYS, "openat", name);
}

function openChild(
  dirfd: number,
  name: string,
  flags: number,
  mode?: number,
): number {
  return fs.openSync(openatPath(dirfd, name), flags | NOFOLLOW | CLOEXEC, mode);
}

function fdKey(fd: number): { dev: bigint; ino: bigint } {
  const stats = fs.fstatSync(fd, { bigint: true });
  return { dev: stats.dev, ino: stats.ino };
}

function guestOwned(stats: Stats): Stats {
  const result: Stats = Object.assign(
    Object.create(Object.getPrototypeOf(stats)),
    stats,
  );
  Reflect.set(result, "uid", typeof stats.uid === "bigint" ? 0n : 0);
  Reflect.set(result, "gid", typeof stats.gid === "bigint" ? 0n : 0);
  return result;
}

/** Open a host directory, pin device/inode/creation-time, and close the descriptor */
export function pinHostDirectoryIdentity(directoryPath: string): {
  identity: HostDirectoryIdentity;
} {
  const acquired = acquirePinnedDirectory(directoryPath);
  try {
    return { identity: acquired.identity };
  } finally {
    fs.closeSync(acquired.fd);
  }
}

/** Open a host directory and retain the descriptor for root-bound resolution */
export function acquirePinnedDirectory(
  directoryPath: string,
  expected?: HostDirectoryIdentity,
): { fd: number; identity: HostDirectoryIdentity } {
  let fd: number;
  try {
    fd = fs.openSync(directoryPath, RDONLY | DIRECTORY | NOFOLLOW | CLOEXEC);
  } catch (error) {
    if (error instanceof TypeError) throw error;
    throw new TypeError(`scoped root ${directoryPath} could not be opened`);
  }
  try {
    const stats = fs.fstatSync(fd, { bigint: true });
    if (!stats.isDirectory()) {
      throw new TypeError("scoped root is not a directory");
    }
    if (stats.birthtimeNs <= 0n) {
      throw new TypeError("scoped root creation identity is unavailable");
    }
    const identity = {
      dev: stats.dev,
      ino: stats.ino,
      birthtimeNs: stats.birthtimeNs,
    };
    if (expected && !identitiesEqual(identity, expected)) {
      throw new TypeError("scoped root identity changed after admission");
    }
    return { fd, identity };
  } catch (error) {
    fs.closeSync(fd);
    throw error;
  }
}

function relativePath(vfsPath: string): string {
  const normalized = vfsPath.replaceAll("\\", "/");
  if (normalized === "/" || normalized === "") return "";
  return normalized.startsWith("/") ? normalized.slice(1) : normalized;
}

function componentsOf(vfsPath: string): string[] {
  return relativePath(vfsPath)
    .split("/")
    .filter((part) => part.length > 0);
}

function isMagicTarget(target: string): boolean {
  return (
    target.startsWith("/proc/") ||
    target.startsWith("/dev/fd/") ||
    target.startsWith("/sys/") ||
    target === "/proc" ||
    target === "/dev" ||
    target === "/sys"
  );
}

type WalkKind = "final" | "parent" | "directory";

class PinnedHandle implements VirtualFileHandle {
  #fd: number;
  #closed = false;
  readonly path: string;
  readonly flags: string;
  readonly mode: number;
  position = 0;
  #onClose: (fd: number) => void;
  constructor(
    path: string,
    flags: string,
    mode: number,
    fd: number,
    onClose: (fd: number) => void,
  ) {
    this.path = path;
    this.flags = flags;
    this.mode = mode;
    this.#fd = fd;
    this.#onClose = onClose;
  }
  get closed() {
    return this.#closed;
  }
  private requireOpen(): number {
    if (this.#closed) throw createErrnoError(ERRNO.EBADF, "read", this.path);
    return this.#fd;
  }
  async read(
    buffer: Buffer,
    offset: number,
    length: number,
    position?: number | null,
  ) {
    const bytesRead = this.readSync(buffer, offset, length, position);
    return { bytesRead, buffer };
  }
  readSync(
    buffer: Buffer,
    offset: number,
    length: number,
    position?: number | null,
  ) {
    return fs.readSync(
      this.requireOpen(),
      buffer,
      offset,
      length,
      position ?? this.position,
    );
  }
  async write(
    buffer: Buffer,
    offset: number,
    length: number,
    position?: number | null,
  ) {
    const bytesWritten = this.writeSync(buffer, offset, length, position);
    return { bytesWritten, buffer };
  }
  writeSync(
    buffer: Buffer,
    offset: number,
    length: number,
    position?: number | null,
  ) {
    return fs.writeSync(
      this.requireOpen(),
      buffer,
      offset,
      length,
      position ?? this.position,
    );
  }
  async readFile(options?: { encoding?: BufferEncoding } | BufferEncoding) {
    return this.readFileSync(options);
  }
  readFileSync(options?: { encoding?: BufferEncoding } | BufferEncoding) {
    const stats = fs.fstatSync(this.requireOpen());
    const buffer = Buffer.alloc(Number(stats.size));
    fs.readSync(this.requireOpen(), buffer, 0, buffer.length, 0);
    if (options === undefined) return buffer;
    const encoding = typeof options === "string" ? options : options.encoding;
    return encoding ? buffer.toString(encoding) : buffer;
  }
  async writeFile(
    data: Buffer | string,
    options?: { encoding?: BufferEncoding },
  ) {
    this.writeFileSync(data, options);
  }
  writeFileSync(
    data: Buffer | string,
    options?: { encoding?: BufferEncoding },
  ) {
    const buffer = Buffer.isBuffer(data)
      ? data
      : Buffer.from(data, options?.encoding ?? "utf8");
    fs.ftruncateSync(this.requireOpen(), 0);
    fs.writeSync(this.requireOpen(), buffer, 0, buffer.length, 0);
  }
  async stat(options?: object) {
    return this.statSync(options);
  }
  statSync(options?: object) {
    return guestOwned(fs.fstatSync(this.requireOpen(), options));
  }
  async truncate(len?: number) {
    this.truncateSync(len);
  }
  truncateSync(len = 0) {
    fs.ftruncateSync(this.requireOpen(), len);
  }
  async close() {
    this.closeSync();
  }
  closeSync() {
    if (this.#closed) return;
    this.#closed = true;
    const fd = this.#fd;
    this.#fd = -1;
    try {
      fs.closeSync(fd);
    } finally {
      this.#onClose(fd);
    }
  }
}

/** Live root-bound VFS provider using kernel-assisted lookup under a pinned directory fd */
export class ScopedTreeProvider
  extends VirtualProviderClass
  implements VirtualProvider
{
  readonly kind: ScopedTreeKind;
  readonly identity: HostDirectoryIdentity;
  #rootFd: number;
  #handles = new Set<number>();
  #observer?: (decision: ScopedTreeDecision) => void;

  constructor(
    kind: ScopedTreeKind,
    acquired: { fd: number; identity: HostDirectoryIdentity },
    observer?: (decision: ScopedTreeDecision) => void,
  ) {
    super();
    this.kind = kind;
    this.identity = acquired.identity;
    this.#rootFd = acquired.fd;
    this.#observer = observer;
  }

  get readonly() {
    return this.kind === "repository";
  }
  get supportsSymlinks() {
    return true;
  }
  get supportsWatch() {
    return false;
  }

  closeRoot(): void {
    for (const fd of [...this.#handles]) {
      try {
        fs.closeSync(fd);
      } catch {
        // Relinquish the numeric descriptor even if close fails.
      }
      this.#handles.delete(fd);
    }
    if (this.#rootFd >= 0) {
      fs.closeSync(this.#rootFd);
      this.#rootFd = -1;
    }
  }

  handlesClosed(): boolean {
    return this.#handles.size === 0 && this.#rootFd === -1;
  }

  private decide(operation: string, guestPath: string, allowed: boolean): void {
    this.#observer?.({
      operation,
      guestPath,
      decision: allowed ? "granted" : "denied",
      detail: `${this.kind}:${operation}`,
    });
    if (!allowed) throw createErrnoError(ERRNO.EACCES, operation, guestPath);
  }

  private allow(operation: string, guestPath: string): void {
    const permitted =
      this.kind === "repository"
        ? REPOSITORY_ALLOWED.has(operation)
        : PRIVATE_ALLOWED.has(operation);
    this.decide(operation, guestPath, permitted);
  }

  private walk(
    vfsPath: string,
    kind: WalkKind,
    hops = 0,
    finalFlags = RDONLY,
  ): { fd: number; close: boolean } {
    if (this.#rootFd < 0) throw createErrnoError(ERRNO.EBADF, "open", vfsPath);
    const parts = componentsOf(vfsPath);
    if (kind === "parent") {
      if (parts.length === 0)
        throw createErrnoError(ERRNO.EINVAL, "open", vfsPath);
      parts.pop();
    }
    let current = this.#rootFd;
    let closeCurrent = false;
    const release = (fd: number, owned: boolean) => {
      if (owned && fd !== this.#rootFd) fs.closeSync(fd);
    };
    try {
      for (let index = 0; index < parts.length; index++) {
        const name = parts[index]!;
        const last = index === parts.length - 1;
        if (name === ".") continue;
        if (name === "..") {
          const key = fdKey(current);
          if (key.dev === this.identity.dev && key.ino === this.identity.ino) {
            throw createErrnoError(ERRNO.EACCES, "open", vfsPath);
          }
          const parent = openChild(current, "..", RDONLY | DIRECTORY);
          if (closeCurrent) fs.closeSync(current);
          current = parent;
          closeCurrent = true;
          continue;
        }
        const flags =
          last && kind === "final" ? finalFlags : RDONLY | DIRECTORY;
        let next: number;
        try {
          next = openChild(current, name, flags);
        } catch (error) {
          const code = (error as NodeJS.ErrnoException).code;
          if (code === "ELOOP" || code === "EMLINK") {
            if (hops >= SYMLINK_BOUND) {
              throw createErrnoError(ERRNO.ELOOP, "open", vfsPath);
            }
            const target = fs.readlinkSync(openatPath(current, name), "utf8");
            if (isMagicTarget(target)) {
              throw createErrnoError(ERRNO.EACCES, "open", vfsPath);
            }
            const remainder = parts.slice(index + 1);
            const resolved = target.startsWith("/")
              ? target
              : `/${[...parts.slice(0, index), target].join("/")}`;
            const joined = remainder.length
              ? `${resolved.replace(/\/+$/, "")}/${remainder.join("/")}`
              : resolved;
            if (closeCurrent) fs.closeSync(current);
            return this.walk(joined, kind, hops + 1, finalFlags);
          }
          throw error;
        }
        if (closeCurrent) fs.closeSync(current);
        current = next;
        closeCurrent = true;
      }
      if (kind === "directory" || kind === "parent") {
        const stats = fs.fstatSync(current);
        if (!stats.isDirectory()) {
          throw createErrnoError(ERRNO.ENOTDIR, "open", vfsPath);
        }
      }
      return { fd: current, close: closeCurrent };
    } catch (error) {
      release(current, closeCurrent);
      throw error;
    }
  }

  private withWalk<T>(
    vfsPath: string,
    kind: WalkKind,
    fn: (fd: number) => T,
    finalFlags = RDONLY,
  ): T {
    const walked = this.walk(vfsPath, kind, 0, finalFlags);
    try {
      return fn(walked.fd);
    } finally {
      if (walked.close) fs.closeSync(walked.fd);
    }
  }

  private parentAndName(vfsPath: string): {
    parentFd: number;
    close: boolean;
    name: string;
  } {
    const parts = componentsOf(vfsPath);
    if (parts.length === 0)
      throw createErrnoError(ERRNO.EINVAL, "open", vfsPath);
    const name = parts.at(-1)!;
    if (name === "." || name === "..") {
      throw createErrnoError(ERRNO.EINVAL, "open", vfsPath);
    }
    const parent = this.walk(vfsPath, "parent");
    return { parentFd: parent.fd, close: parent.close, name };
  }

  openSync(vfsPath: string, flags: string, mode?: number): VirtualFileHandle {
    const write = isWriteFlag(flags);
    const create = /[wa]/.test(flags) && !flags.startsWith("r+");
    this.allow(create ? "create" : write ? "write" : "read", vfsPath);
    if (create) {
      const parent = this.parentAndName(vfsPath);
      try {
        const fd = openChild(
          parent.parentFd,
          parent.name,
          (write ? fs.constants.O_RDWR : RDONLY) |
            CREAT |
            (flags.includes("wx") || flags.includes("ax") ? EXCL : 0) |
            (flags.startsWith("w") ? fs.constants.O_TRUNC : 0),
          mode ?? 0o600,
        );
        const stats = fs.fstatSync(fd);
        if (!stats.isFile()) {
          fs.closeSync(fd);
          throw createErrnoError(ERRNO.EACCES, "create", vfsPath);
        }
        this.#handles.add(fd);
        return new PinnedHandle(vfsPath, flags, mode ?? 0o600, fd, (closed) => {
          this.#handles.delete(closed);
        });
      } finally {
        if (parent.close) fs.closeSync(parent.parentFd);
      }
    }
    const walked = this.walk(
      vfsPath,
      "final",
      0,
      write ? fs.constants.O_RDWR : RDONLY,
    );
    try {
      const stats = fs.fstatSync(walked.fd);
      if (!stats.isFile()) {
        throw createErrnoError(ERRNO.EISDIR, "open", vfsPath);
      }
      if (!walked.close) {
        const dup = openChild(walked.fd, ".", RDONLY);
        this.#handles.add(dup);
        return new PinnedHandle(
          vfsPath,
          flags,
          mode ?? 0o400,
          dup,
          (closed) => {
            this.#handles.delete(closed);
          },
        );
      }
      this.#handles.add(walked.fd);
      return new PinnedHandle(
        vfsPath,
        flags,
        mode ?? 0o400,
        walked.fd,
        (closed) => this.#handles.delete(closed),
      );
    } catch (error) {
      if (walked.close) fs.closeSync(walked.fd);
      throw error;
    }
  }

  async open(vfsPath: string, flags: string, mode?: number) {
    return this.openSync(vfsPath, flags, mode);
  }

  statSync(vfsPath: string, options?: object): Stats {
    this.allow("lookup", vfsPath);
    return this.withWalk(vfsPath, "final", (fd) =>
      guestOwned(fs.fstatSync(fd, options)),
    );
  }
  async stat(vfsPath: string, options?: object) {
    return this.statSync(vfsPath, options);
  }

  lstatSync(vfsPath: string, options?: object): Stats {
    this.allow("lookup", vfsPath);
    const parent = this.parentAndName(vfsPath);
    try {
      return guestOwned(
        fs.lstatSync(openatPath(parent.parentFd, parent.name), options),
      );
    } finally {
      if (parent.close) fs.closeSync(parent.parentFd);
    }
  }
  async lstat(vfsPath: string, options?: object) {
    return this.lstatSync(vfsPath, options);
  }

  readdirSync(vfsPath: string, options?: object): Array<string | fs.Dirent> {
    this.allow("lookup", vfsPath);
    return this.withWalk(vfsPath, "directory", (fd) =>
      fs.readdirSync(openatPath(fd, "."), options as fs.EncodingOption),
    ) as Array<string | fs.Dirent>;
  }
  async readdir(vfsPath: string, options?: object) {
    return this.readdirSync(vfsPath, options);
  }

  mkdirSync(vfsPath: string): void {
    this.allow("mkdir", vfsPath);
  }
  async mkdir(vfsPath: string) {
    this.mkdirSync(vfsPath);
  }

  rmdirSync(vfsPath: string): void {
    this.allow("rmdir", vfsPath);
  }
  async rmdir(vfsPath: string) {
    this.rmdirSync(vfsPath);
  }

  unlinkSync(vfsPath: string): void {
    this.allow("unlink", vfsPath);
    const parent = this.parentAndName(vfsPath);
    try {
      fs.unlinkSync(openatPath(parent.parentFd, parent.name));
    } finally {
      if (parent.close) fs.closeSync(parent.parentFd);
    }
  }
  async unlink(vfsPath: string) {
    this.unlinkSync(vfsPath);
  }

  renameSync(oldPath: string, newPath: string): void {
    const sameDirectory =
      componentsOf(oldPath).slice(0, -1).join("/") ===
      componentsOf(newPath).slice(0, -1).join("/");
    this.allow(
      sameDirectory ? "rename-same-directory" : "rename-cross-directory",
      oldPath,
    );
    if (!sameDirectory) return;
    const source = this.parentAndName(oldPath);
    try {
      const destination = this.parentAndName(newPath);
      try {
        if (fdKey(source.parentFd).ino !== fdKey(destination.parentFd).ino) {
          throw createErrnoError(ERRNO.EACCES, "rename", oldPath);
        }
        fs.renameSync(
          openatPath(source.parentFd, source.name),
          openatPath(destination.parentFd, destination.name),
        );
      } finally {
        if (destination.close) fs.closeSync(destination.parentFd);
      }
    } finally {
      if (source.close) fs.closeSync(source.parentFd);
    }
  }
  async rename(oldPath: string, newPath: string) {
    this.renameSync(oldPath, newPath);
  }

  linkSync(existingPath: string, newPath: string): void {
    const sameDirectory =
      componentsOf(existingPath).slice(0, -1).join("/") ===
      componentsOf(newPath).slice(0, -1).join("/");
    this.allow(
      sameDirectory ? "link-same-directory" : "link-cross-directory",
      existingPath,
    );
    if (!sameDirectory) return;
    const source = this.parentAndName(existingPath);
    try {
      const destination = this.parentAndName(newPath);
      try {
        if (fdKey(source.parentFd).ino !== fdKey(destination.parentFd).ino) {
          throw createErrnoError(ERRNO.EACCES, "link", existingPath);
        }
        fs.linkSync(
          openatPath(source.parentFd, source.name),
          openatPath(destination.parentFd, destination.name),
        );
      } finally {
        if (destination.close) fs.closeSync(destination.parentFd);
      }
    } finally {
      if (source.close) fs.closeSync(source.parentFd);
    }
  }
  async link(existingPath: string, newPath: string) {
    this.linkSync(existingPath, newPath);
  }

  symlinkSync(target: string, vfsPath: string): void {
    this.allow("symlink", vfsPath);
    void target;
  }
  async symlink(target: string, vfsPath: string) {
    this.symlinkSync(target, vfsPath);
  }

  readlinkSync(vfsPath: string): string {
    this.allow("lookup", vfsPath);
    const parent = this.parentAndName(vfsPath);
    try {
      return fs.readlinkSync(openatPath(parent.parentFd, parent.name), "utf8");
    } finally {
      if (parent.close) fs.closeSync(parent.parentFd);
    }
  }
  async readlink(vfsPath: string) {
    return this.readlinkSync(vfsPath);
  }

  truncateSync(vfsPath: string, len = 0): void {
    this.allow("truncate", vfsPath);
    this.withWalk(
      vfsPath,
      "final",
      (fd) => fs.ftruncateSync(fd, len),
      fs.constants.O_RDWR,
    );
  }
  async truncate(vfsPath: string, len = 0) {
    this.truncateSync(vfsPath, len);
  }

  chmodSync(vfsPath: string): void {
    this.allow("metadata", vfsPath);
  }
  async chmod(vfsPath: string) {
    this.chmodSync(vfsPath);
  }
}

export const __test = {
  componentsOf,
  isMagicTarget,
  SYMLINK_BOUND,
  openatPath,
};
