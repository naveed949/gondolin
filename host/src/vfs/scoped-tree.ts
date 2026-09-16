import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { Dirent, Stats } from "node:fs";

import {
  directoryIdentityFromFd,
  formatDirectoryIdentity,
  getdents64,
  linkat,
  linuxOpenFlag,
  O_CLOEXEC,
  O_NOCTTY,
  O_PATH,
  openat2,
  renameat2,
  unlinkat,
  type DirectoryIdentity,
} from "../linux-at.ts";
import { createErrnoError } from "./errors.ts";
import type { VirtualFileHandle, VirtualProvider } from "./node/index.ts";
import { ERRNO, VirtualProviderClass, isWriteFlag, normalizeVfsPath } from "./utils.ts";

export type ScopedTreeRole = "repository" | "cache" | "temp";

export type ScopedTreeRootBinding = {
  /** Root classification */
  role: ScopedTreeRole;
  /** Guest-visible directory under the `/data` FUSE mount */
  guestPath: string;
  /** Pinned host directory descriptor */
  fd: number;
  /** Controller-retained device/inode/creation-time identity */
  identity: DirectoryIdentity;
};

export type ScopedTreeOpenKind =
  | "lookup"
  | "read"
  | "create"
  | "write"
  | "truncate";

export type ScopedTreeDecision = {
  /** Filesystem operation classification */
  operation: ScopedTreeOpenKind | "unlink" | "rename" | "link" | "mkdir" | "rmdir" | "symlink" | "other";
  /** Guest-visible resource path */
  guestPath: string;
  /** Policy decision */
  decision: "granted" | "denied";
  /** Capability path recorded on denial */
  capabilityPath?: string;
};

type Located = {
  root: ScopedTreeRootBinding;
  /** Path relative to the pinned root, or empty for the root itself */
  relative: string;
  parentRelative: string;
  basename: string;
};

class ScopedTreeHandle implements VirtualFileHandle {
  private readonly owner: ScopedTreeProvider;
  private readonly id: number;
  private fd: number | null;
  readonly path: string;
  readonly flags: string;
  readonly mode: number;
  position = 0;
  closed = false;

  constructor(
    owner: ScopedTreeProvider,
    id: number,
    fd: number,
    vfsPath: string,
    flags: string,
    mode: number,
  ) {
    this.owner = owner;
    this.id = id;
    this.fd = fd;
    this.path = vfsPath;
    this.flags = flags;
    this.mode = mode;
  }

  private requireFd(): number {
    if (this.closed || this.fd === null) {
      throw createErrnoError(ERRNO.EBADF, "read", this.path);
    }
    return this.fd;
  }

  async read(buffer: Buffer, offset: number, length: number, position?: number | null) {
    const bytesRead = this.readSync(buffer, offset, length, position);
    return { bytesRead, buffer };
  }

  readSync(buffer: Buffer, offset: number, length: number, position?: number | null): number {
    const fd = this.requireFd();
    const at = position === undefined || position === null ? this.position : position;
    const n = fs.readSync(fd, buffer, offset, length, at);
    if (position === undefined || position === null) this.position += n;
    return n;
  }

  async write(buffer: Buffer, offset: number, length: number, position?: number | null) {
    const bytesWritten = this.writeSync(buffer, offset, length, position);
    return { bytesWritten, buffer };
  }

  writeSync(buffer: Buffer, offset: number, length: number, position?: number | null): number {
    const fd = this.requireFd();
    const at = position === undefined || position === null ? this.position : position;
    const n = fs.writeSync(fd, buffer, offset, length, at);
    if (position === undefined || position === null) this.position += n;
    return n;
  }

  async readFile(options?: { encoding?: BufferEncoding } | BufferEncoding) {
    return this.readFileSync(options);
  }

  readFileSync(options?: { encoding?: BufferEncoding } | BufferEncoding): Buffer | string {
    const fd = this.requireFd();
    const stats = fs.fstatSync(fd);
    const buffer = Buffer.alloc(Number(stats.size));
    let read = 0;
    while (read < buffer.length) {
      const n = fs.readSync(fd, buffer, read, buffer.length - read, read);
      if (n === 0) break;
      read += n;
    }
    const data = buffer.subarray(0, read);
    const encoding = typeof options === "string" ? options : options?.encoding;
    return encoding ? data.toString(encoding) : data;
  }

  async writeFile(data: Buffer | string, options?: { encoding?: BufferEncoding }) {
    this.writeFileSync(data, options);
  }

  writeFileSync(data: Buffer | string, options?: { encoding?: BufferEncoding }): void {
    const fd = this.requireFd();
    const buffer = Buffer.isBuffer(data)
      ? data
      : Buffer.from(data, options?.encoding ?? "utf8");
    fs.ftruncateSync(fd, 0);
    fs.writeSync(fd, buffer, 0, buffer.length, 0);
    this.position = buffer.length;
  }

  async stat(options?: object) {
    return this.statSync(options);
  }

  statSync(options?: object): Stats {
    return fs.fstatSync(this.requireFd()) as Stats;
  }

  async truncate(len = 0) {
    this.truncateSync(len);
  }

  truncateSync(len = 0): void {
    fs.ftruncateSync(this.requireFd(), len);
  }

  async close() {
    this.closeSync();
  }

  closeSync(): void {
    if (this.closed) return;
    this.closed = true;
    const fd = this.fd;
    this.fd = null;
    this.owner.releaseHandle(this.id, fd);
  }
}

/** Live root-bound VFS: kernel-assisted resolution under pinned directory descriptors */
export class ScopedTreeProvider
  extends VirtualProviderClass
  implements VirtualProvider
{
  readonly readonly = false;
  readonly supportsSymlinks = true;
  readonly supportsWatch = false;
  private readonly roots: ScopedTreeRootBinding[];
  private readonly handles = new Map<number, { fd: number | null }>();
  private nextHandle = 1;
  private closed = false;
  private readonly onDecision?: (decision: ScopedTreeDecision) => void;

  constructor(
    roots: ScopedTreeRootBinding[],
    onDecision?: (decision: ScopedTreeDecision) => void,
  ) {
    super();
    this.roots = roots;
    this.onDecision = onDecision;
  }

  get rootIdentities(): Record<ScopedTreeRole, string> {
    return {
      repository: formatDirectoryIdentity(this.requireRole("repository").identity),
      cache: formatDirectoryIdentity(this.requireRole("cache").identity),
      temp: formatDirectoryIdentity(this.requireRole("temp").identity),
    };
  }

  verifyPinnedIdentities(): void {
    for (const root of this.roots) {
      const actual = directoryIdentityFromFd(root.fd);
      if (
        actual === null ||
        actual.dev !== root.identity.dev ||
        actual.ino !== root.identity.ino ||
        actual.birthtimeNs !== root.identity.birthtimeNs
      ) {
        throw createErrnoError(
          ERRNO.ESTALE ?? ERRNO.EIO,
          "open",
          root.guestPath,
        );
      }
    }
  }

  async open(vfsPath: string, flags: string, mode?: number) {
    return this.openSync(vfsPath, flags, mode);
  }

  openSync(vfsPath: string, flags: string, mode?: number): VirtualFileHandle {
    this.requireOpen();
    const located = this.locate(vfsPath, "open");
    const write = isWriteFlag(flags);
    const create = /[wa]/u.test(flags);
    const truncate = flags.includes("w") && !flags.includes("a");
    const kind: ScopedTreeOpenKind = create
      ? "create"
      : truncate
        ? "truncate"
        : write
          ? "write"
          : "read";
    this.authorize(located, kind, vfsPath);
    const numeric = flagsToNumber(flags);
    const creat = (numeric & fs.constants.O_CREAT) !== 0;
    const fd = openat2(
      located.root.fd,
      located.relative,
      numeric | linuxOpenFlag("O_CLOEXEC", O_CLOEXEC) | linuxOpenFlag("O_NOCTTY", O_NOCTTY),
      creat ? (mode ?? 0o600) : 0,
    );
    let adopted = false;
    try {
      const stats = fs.fstatSync(fd);
      if (stats.isDirectory() && write) {
        throw createErrnoError(ERRNO.EISDIR, "open", vfsPath);
      }
      if (stats.isSymbolicLink()) {
        this.deny("other", vfsPath, capabilityPath(located.root.role, "symlink-final"));
      }
      if (!stats.isDirectory() && !stats.isFile()) {
        this.deny("other", vfsPath, capabilityPath(located.root.role, "special-file"));
      }
      const id = this.nextHandle++;
      this.handles.set(id, { fd });
      adopted = true;
      return new ScopedTreeHandle(this, id, fd, vfsPath, flags, mode ?? 0o600);
    } finally {
      if (!adopted) {
        try {
          fs.closeSync(fd);
        } catch {
          // The numeric descriptor is already abandoned.
        }
      }
    }
  }

  async stat(vfsPath: string, options?: object) {
    return this.statSync(vfsPath, options);
  }

  statSync(vfsPath: string, options?: object): Stats {
    return this.statWith(vfsPath, 0, options);
  }

  async lstat(vfsPath: string, options?: object) {
    return this.lstatSync(vfsPath, options);
  }

  lstatSync(vfsPath: string, options?: object): Stats {
    return this.statWith(vfsPath, fs.constants.O_NOFOLLOW, options);
  }

  async readdir(vfsPath: string, options?: object) {
    return this.readdirSync(vfsPath, options);
  }

  readdirSync(vfsPath: string, options?: object): Array<string | Dirent> {
    this.requireOpen();
    const located = this.locate(vfsPath, "readdir");
    this.authorize(located, "lookup", vfsPath);
    const fd = openat2(
      located.root.fd,
      located.relative,
      linuxOpenFlag("O_RDONLY", fs.constants.O_RDONLY) |
        linuxOpenFlag("O_DIRECTORY", fs.constants.O_DIRECTORY) |
        linuxOpenFlag("O_CLOEXEC", O_CLOEXEC),
    );
    try {
      const names = getdents64(fd);
      if (options && typeof options === "object" && "withFileTypes" in options) {
        return names.map((name) => ({
          name,
          isFile: () => true,
          isDirectory: () => false,
          isSymbolicLink: () => false,
          isBlockDevice: () => false,
          isCharacterDevice: () => false,
          isFIFO: () => false,
          isSocket: () => false,
        })) as Dirent[];
      }
      return names;
    } finally {
      fs.closeSync(fd);
    }
  }

  async mkdir(vfsPath: string) {
    this.mkdirSync(vfsPath);
  }

  mkdirSync(vfsPath: string): void {
    this.requireOpen();
    const located = this.locate(vfsPath, "mkdir");
    this.deny("mkdir", vfsPath, capabilityPath(located.root.role, "mkdir"));
  }

  async rmdir(vfsPath: string) {
    this.rmdirSync(vfsPath);
  }

  rmdirSync(vfsPath: string): void {
    this.requireOpen();
    const located = this.locate(vfsPath, "rmdir");
    this.deny("rmdir", vfsPath, capabilityPath(located.root.role, "rmdir"));
  }

  async unlink(vfsPath: string) {
    this.unlinkSync(vfsPath);
  }

  unlinkSync(vfsPath: string): void {
    this.requireOpen();
    const located = this.locate(vfsPath, "unlink");
    if (located.root.role === "repository" || located.relative === "") {
      this.deny("unlink", vfsPath, capabilityPath(located.root.role, "unlink"));
    }
    this.grant("unlink", vfsPath);
    unlinkat(located.root.fd, located.relative, 0);
  }

  async rename(oldPath: string, newPath: string) {
    this.renameSync(oldPath, newPath);
  }

  renameSync(oldPath: string, newPath: string): void {
    this.requireOpen();
    const source = this.locate(oldPath, "rename");
    const target = this.locate(newPath, "rename");
    if (
      source.root.role === "repository" ||
      target.root.role === "repository" ||
      source.root.role !== target.root.role ||
      source.parentRelative !== target.parentRelative ||
      source.relative === "" ||
      target.relative === ""
    ) {
      this.deny(
        "rename",
        oldPath,
        capabilityPath(source.root.role, "rename.cross-directory"),
      );
    }
    this.grant("rename", oldPath);
    renameat2(source.root.fd, source.relative, target.root.fd, target.relative);
  }

  async link(existingPath: string, newPath: string) {
    this.linkSync(existingPath, newPath);
  }

  linkSync(existingPath: string, newPath: string): void {
    this.requireOpen();
    const source = this.locate(existingPath, "link");
    const target = this.locate(newPath, "link");
    if (
      source.root.role === "repository" ||
      target.root.role === "repository" ||
      source.root.role !== target.root.role ||
      source.parentRelative !== target.parentRelative ||
      source.relative === "" ||
      target.relative === ""
    ) {
      this.deny(
        "link",
        existingPath,
        capabilityPath(source.root.role, "link.cross-directory"),
      );
    }
    this.grant("link", existingPath);
    linkat(source.root.fd, source.relative, target.root.fd, target.relative, 0);
  }

  async symlink(_target: string, vfsPath: string) {
    this.symlinkSync(_target, vfsPath);
  }

  symlinkSync(_target: string, vfsPath: string): void {
    this.requireOpen();
    const located = this.locate(vfsPath, "symlink");
    this.deny("symlink", vfsPath, capabilityPath(located.root.role, "symlink"));
  }

  async realpath(vfsPath: string) {
    return this.realpathSync(vfsPath);
  }

  realpathSync(vfsPath: string): string {
    this.statSync(vfsPath);
    return normalizeVfsPath(vfsPath);
  }

  releaseHandle(id: number, fd: number | null): void {
    const record = this.handles.get(id);
    if (!record) return;
    this.handles.delete(id);
    record.fd = null;
    if (fd !== null) {
      try {
        fs.closeSync(fd);
      } catch {
        // Descriptor numbers are never reused for a closed handle.
      }
    }
  }

  closeAllHandles(): { closed: number; failed: boolean } {
    let failed = false;
    let closed = 0;
    for (const [id, record] of [...this.handles.entries()]) {
      this.handles.delete(id);
      if (record.fd === null) continue;
      try {
        fs.closeSync(record.fd);
        closed += 1;
      } catch {
        failed = true;
      }
      record.fd = null;
    }
    return { closed, failed };
  }

  dispose(): { handlesRevoked: boolean; rootsClosed: boolean } {
    const handles = this.closeAllHandles();
    let rootsClosed = true;
    for (const root of this.roots) {
      try {
        fs.closeSync(root.fd);
      } catch {
        rootsClosed = false;
      }
    }
    this.closed = true;
    return { handlesRevoked: !handles.failed, rootsClosed };
  }

  private requireRole(role: ScopedTreeRole): ScopedTreeRootBinding {
    const root = this.roots.find((candidate) => candidate.role === role);
    if (!root) throw new Error(`missing scoped tree root ${role}`);
    return root;
  }

  private requireOpen(): void {
    if (this.closed) throw createErrnoError(ERRNO.ESTALE ?? ERRNO.EIO, "open");
  }

  private locate(vfsPath: string, syscall: string): Located {
    const normalized = normalizeVfsPath(vfsPath);
    if (vfsPath.split("/").includes("..") || normalized.split("/").includes("..")) {
      throw createErrnoError(ERRNO.EPERM, syscall, vfsPath);
    }
    const matches = this.roots
      .map((root) => {
        const prefix = toProviderPath(root.guestPath);
        if (normalized === prefix) {
          return { root, relative: "", parentRelative: "", basename: "" };
        }
        if (normalized.startsWith(`${prefix}/`)) {
          const relative = normalized.slice(prefix.length + 1);
          if (relative.split("/").includes("..")) return null;
          const basename = path.posix.basename(relative);
          const parentRelative = path.posix.dirname(relative);
          return {
            root,
            relative,
            parentRelative: parentRelative === "." ? "" : parentRelative,
            basename,
          };
        }
        return null;
      })
      .filter((value): value is Located => value !== null);
    if (matches.length !== 1) {
      throw createErrnoError(ERRNO.ENOENT, syscall, vfsPath);
    }
    return matches[0]!;
  }

  private authorize(located: Located, kind: ScopedTreeOpenKind, vfsPath: string): void {
    const writable = located.root.role !== "repository";
    if (kind === "lookup" || kind === "read") {
      this.grant(kind, vfsPath);
      return;
    }
    if (!writable) {
      this.deny(kind, vfsPath, capabilityPath(located.root.role, kind));
    }
    this.grant(kind, vfsPath);
  }

  private grant(operation: ScopedTreeDecision["operation"], guestPath: string): void {
    this.onDecision?.({ operation, guestPath, decision: "granted" });
  }

  private deny(
    operation: ScopedTreeDecision["operation"],
    guestPath: string,
    capabilityPath: string,
  ): never {
    this.onDecision?.({
      operation,
      guestPath,
      decision: "denied",
      capabilityPath,
    });
    throw createErrnoError(ERRNO.EPERM, operation, guestPath);
  }

  private statWith(vfsPath: string, extraFlags: number, _options?: object): Stats {
    this.requireOpen();
    const located = this.locate(vfsPath, "stat");
    this.authorize(located, "lookup", vfsPath);
    const fd = openat2(
      located.root.fd,
      located.relative,
      linuxOpenFlag("O_PATH", O_PATH) | linuxOpenFlag("O_CLOEXEC", O_CLOEXEC) | extraFlags,
    );
    try {
      return fs.fstatSync(fd) as Stats;
    } finally {
      fs.closeSync(fd);
    }
  }
}

export function toProviderPath(guestPath: string): string {
  const normalized = path.posix.normalize(guestPath);
  if (normalized === "/data") return "/";
  if (!normalized.startsWith("/data/")) {
    throw new Error(`guest path is outside /data: ${guestPath}`);
  }
  return normalized.slice("/data".length);
}

export function capabilityPath(role: ScopedTreeRole, operation: string): string {
  return `filesystem.${role}.${operation}`;
}

function flagsToNumber(flags: string): number {
  const constants = fs.constants;
  let numeric = linuxOpenFlag("O_CLOEXEC", O_CLOEXEC);
  if (flags.includes("x")) numeric |= constants.O_EXCL;
  if (flags.startsWith("r") && flags.includes("+")) numeric |= constants.O_RDWR;
  else if (flags.startsWith("r")) numeric |= constants.O_RDONLY;
  else if (flags.startsWith("w") && flags.includes("+")) {
    numeric |= constants.O_RDWR | constants.O_CREAT | constants.O_TRUNC;
  } else if (flags.startsWith("w")) {
    numeric |= constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC;
  } else if (flags.startsWith("a") && flags.includes("+")) {
    numeric |= constants.O_RDWR | constants.O_CREAT | constants.O_APPEND;
  } else if (flags.startsWith("a")) {
    numeric |= constants.O_WRONLY | constants.O_CREAT | constants.O_APPEND;
  } else {
    numeric |= constants.O_RDONLY;
  }
  return numeric;
}

export const AT_REMOVEDIR = 0x200;
export { formatDirectoryIdentity, type DirectoryIdentity };
