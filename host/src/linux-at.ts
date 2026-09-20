import { createRequire } from "node:module";
import fs from "node:fs";
import os from "node:os";

import { createErrnoError } from "./vfs/errors.ts";

const require = createRequire(import.meta.url);

/** `openat2` resolve flag: refuse magic-link traversal */
export const RESOLVE_NO_MAGICLINKS = 0x02;
/** `openat2` resolve flag: keep the path under the directory descriptor */
export const RESOLVE_BENEATH = 0x08;

const SYS_OPENAT2 = 437;
const SYS_GETDENTS64 = process.arch === "arm64" ? 61 : 217;

type Libc = {
  syscall5(number: number, a: number, b: string, c: Buffer, d: number): number;
  getdents(number: number, fd: number, buffer: Buffer, length: number): number;
  renameat2(
    oldDirFd: number,
    oldPath: string,
    newDirFd: number,
    newPath: string,
    flags: number,
  ): number;
  linkat(
    oldDirFd: number,
    oldPath: string,
    newDirFd: number,
    newPath: string,
    flags: number,
  ): number;
  unlinkat(dirFd: number, path: string, flags: number): number;
  mkdirat(dirFd: number, path: string, mode: number): number;
  errno(): number;
};

let loaded: Libc | undefined;

function libc(): Libc {
  if (loaded) return loaded;
  if (process.platform !== "linux") {
    throw unsupported("host platform cannot perform openat2 root-bound resolution");
  }
  let koffi: {
    load(name: string): { func(sig: string): (...args: never[]) => unknown };
    errno(): number;
  };
  try {
    koffi = require("koffi");
  } catch {
    throw unsupported("host cannot load libc FFI for openat2");
  }
  try {
    const lib = koffi.load("libc.so.6");
    loaded = {
      syscall5: lib.func(
        "long syscall(long number, int a, const char *b, void *c, size_t d)",
      ) as Libc["syscall5"],
      getdents: lib.func(
        "long syscall(long number, int fd, void *buffer, size_t length)",
      ) as Libc["getdents"],
      renameat2: lib.func(
        "int renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags)",
      ) as Libc["renameat2"],
      linkat: lib.func(
        "int linkat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, int flags)",
      ) as Libc["linkat"],
      unlinkat: lib.func(
        "int unlinkat(int dirfd, const char *pathname, int flags)",
      ) as Libc["unlinkat"],
      mkdirat: lib.func(
        "int mkdirat(int dirfd, const char *pathname, unsigned int mode)",
      ) as Libc["mkdirat"],
      errno: () => koffi.errno(),
    };
    return loaded;
  } catch {
    throw unsupported("host libc does not export openat2 primitives");
  }
}

function unsupported(message: string): Error {
  const error = new Error(message);
  error.name = "LinuxAtUnsupportedError";
  return error;
}

function checked(
  result: number,
  syscall: string,
  path?: string,
): number {
  if (result >= 0) return result;
  throw createErrnoError(libc().errno() || os.constants.errno.EIO, syscall, path);
}

function openHow(flags: number, mode: number, resolve: number): Buffer {
  const how = Buffer.alloc(24);
  how.writeBigUInt64LE(BigInt(flags >>> 0), 0);
  // FUSE CREATE supplies `S_IFREG|mode`; openat2 allows only `07777` permission bits
  how.writeBigUInt64LE(BigInt((mode & 0o7777) >>> 0), 8);
  how.writeBigUInt64LE(BigInt(resolve >>> 0), 16);
  return how;
}

/** Kernel-assisted open under a pinned directory descriptor */
export function openat2(
  dirFd: number,
  relativePath: string,
  flags: number,
  mode = 0,
  resolve = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS,
): number {
  const path = relativePath.length === 0 ? "." : relativePath;
  return checked(
    libc().syscall5(SYS_OPENAT2, dirFd, path, openHow(flags, mode, resolve), 24),
    "openat2",
    path,
  );
}

/** Same-directory rename that cannot replace a directory */
export function renameat2(
  oldDirFd: number,
  oldPath: string,
  newDirFd: number,
  newPath: string,
  flags = 0,
): void {
  checked(
    libc().renameat2(oldDirFd, oldPath, newDirFd, newPath, flags),
    "renameat2",
    newPath,
  );
}

/** Hard-link creation relative to directory descriptors */
export function linkat(
  oldDirFd: number,
  oldPath: string,
  newDirFd: number,
  newPath: string,
  flags = 0,
): void {
  checked(
    libc().linkat(oldDirFd, oldPath, newDirFd, newPath, flags),
    "linkat",
    newPath,
  );
}

/** Unlink or rmdir relative to a directory descriptor */
export function unlinkat(dirFd: number, relativePath: string, flags = 0): void {
  checked(libc().unlinkat(dirFd, relativePath, flags), "unlinkat", relativePath);
}

/** Directory creation relative to a directory descriptor */
export function mkdirat(dirFd: number, relativePath: string, mode: number): void {
  checked(libc().mkdirat(dirFd, relativePath, mode), "mkdirat", relativePath);
}

/** Directory listing via `getdents64` on an already-opened descriptor */
export function getdents64(dirFd: number): string[] {
  const names: string[] = [];
  const buffer = Buffer.alloc(4096);
  for (;;) {
    const n = libc().getdents(SYS_GETDENTS64, dirFd, buffer, buffer.length);
    if (n === 0) break;
    if (n < 0) {
      throw createErrnoError(libc().errno() || os.constants.errno.EIO, "getdents64");
    }
    let offset = 0;
    while (offset < n) {
      const reclen = buffer.readUInt16LE(offset + 16);
      const nameStart = offset + 19;
      const name = buffer.toString("utf8", nameStart, offset + reclen).replace(/\0+$/u, "");
      if (name !== "." && name !== "..") names.push(name);
      offset += reclen;
    }
  }
  return names;
}

/** Linux `statx` birth time in `ns`, or `null` when the filesystem omits it */
export function birthtimeNs(fd: number): bigint | null {
  const stats = fs.fstatSync(fd, { bigint: true });
  const value = stats.birthtimeNs;
  if (typeof value !== "bigint" || value <= 0n) return null;
  return value;
}

export type DirectoryIdentity = {
  /** Host filesystem device identity */
  dev: bigint;
  /** Host filesystem inode identity */
  ino: bigint;
  /** Filesystem creation time in `ns` */
  birthtimeNs: bigint;
};

/** Identity string matching AdaptiveSandbox `dev:ino:birthtimeNs` */
export function formatDirectoryIdentity(identity: DirectoryIdentity): string {
  return `${identity.dev}:${identity.ino}:${identity.birthtimeNs}`;
}

/** Parse a controller-retained directory identity */
export function parseDirectoryIdentity(value: string, label: string): DirectoryIdentity {
  const match = /^(0|[1-9][0-9]*):(0|[1-9][0-9]*):(0|[1-9][0-9]*)$/u.exec(value);
  if (!match) {
    throw new Error(`${label} must be a device:inode:birthtime-ns identity`);
  }
  return {
    dev: BigInt(match[1]!),
    ino: BigInt(match[2]!),
    birthtimeNs: BigInt(match[3]!),
  };
}

/** Observe device, inode, and creation time from an opened directory */
export function directoryIdentityFromFd(fd: number): DirectoryIdentity | null {
  const stats = fs.fstatSync(fd, { bigint: true });
  if (!stats.isDirectory()) return null;
  const born = birthtimeNs(fd);
  if (born === null) return null;
  return { dev: stats.dev, ino: stats.ino, birthtimeNs: born };
}

/** Whether `openat2` and creation-time identity are available */
export function linuxAtAvailable(): boolean {
  if (process.platform !== "linux") return false;
  try {
    libc();
    return true;
  } catch {
    return false;
  }
}

/** Linux `O_CLOEXEC` */
export const O_CLOEXEC = 0x80000;
/** Linux `O_PATH` */
export const O_PATH = 0o10000000;
/** Linux `O_DIRECTORY` fallback */
export const O_DIRECTORY = 0x10000;
/** Linux `O_NOFOLLOW` fallback */
export const O_NOFOLLOW = 0x20000;
/** Linux `O_NOCTTY` fallback */
export const O_NOCTTY = 0x100;

/** Resolve a Linux open flag from `fs.constants` with a numeric fallback */
export function linuxOpenFlag(name: string, fallback: number): number {
  const value = (fs.constants as Record<string, number | undefined>)[name];
  return typeof value === "number" ? value : fallback;
}

/** Open a directory without following a final symlink and read its identity */
export function observeDirectoryIdentity(directoryPath: string): DirectoryIdentity | null {
  const noFollow = linuxOpenFlag("O_NOFOLLOW", 0x20000);
  const directory = linuxOpenFlag("O_DIRECTORY", 0x10000);
  const cloexec = linuxOpenFlag("O_CLOEXEC", 0x80000);
  if (typeof noFollow !== "number" || typeof directory !== "number") return null;
  let fd: number;
  try {
    fd = fs.openSync(directoryPath, fs.constants.O_RDONLY | directory | noFollow | cloexec);
  } catch {
    return null;
  }
  try {
    return directoryIdentityFromFd(fd);
  } finally {
    fs.closeSync(fd);
  }
}

/** Open a directory descriptor and refuse replacement of the retained identity */
export function pinDirectory(
  directoryPath: string,
  expected: DirectoryIdentity,
): number {
  const noFollow = linuxOpenFlag("O_NOFOLLOW", 0x20000);
  const directory = linuxOpenFlag("O_DIRECTORY", 0x10000);
  const cloexec = linuxOpenFlag("O_CLOEXEC", 0x80000);
  if (typeof noFollow !== "number" || typeof directory !== "number") {
    throw unsupported("host platform cannot pin directory descriptors without following links");
  }
  const fd = fs.openSync(
    directoryPath,
    fs.constants.O_RDONLY | directory | noFollow | cloexec,
  );
  try {
    const actual = directoryIdentityFromFd(fd);
    if (
      actual === null ||
      actual.dev !== expected.dev ||
      actual.ino !== expected.ino ||
      actual.birthtimeNs !== expected.birthtimeNs
    ) {
      throw new Error("scoped root identity is unavailable or changed");
    }
    return fd;
  } catch (error) {
    fs.closeSync(fd);
    throw error;
  }
}
