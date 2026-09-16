import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { CapabilityAdmissionError } from "./capability-invocation.ts";

export type LinuxStatx = {
  /** `statx` result mask */
  mask: number;
  /** File type and mode bits */
  mode: number;
  /** Hard-link count */
  nlink: number;
  /** Inode identity */
  ino: string;
  /** Device major identity */
  devMajor: number;
  /** Device minor identity */
  devMinor: number;
  /** Creation time seconds from `statx` `btime` */
  btimeSec: string;
  /** Creation time nanoseconds from `statx` `btime` in `ns` */
  btimeNsec: number;
  /** Object size in `bytes` */
  size: string;
};

export type LinuxOpenat2Constants = {
  O_RDONLY: number;
  O_WRONLY: number;
  O_RDWR: number;
  O_CREAT: number;
  O_EXCL: number;
  O_TRUNC: number;
  O_DIRECTORY: number;
  O_NOFOLLOW: number;
  O_CLOEXEC: number;
  O_PATH: number;
  O_NONBLOCK: number;
  RESOLVE_NO_XDEV: number;
  RESOLVE_NO_MAGICLINKS: number;
  RESOLVE_NO_SYMLINKS: number;
  RESOLVE_BENEATH: number;
  RESOLVE_IN_ROOT: number;
  AT_FDCWD: number;
  AT_EMPTY_PATH: number;
  AT_SYMLINK_NOFOLLOW: number;
  AT_REMOVEDIR: number;
  STATX_TYPE: number;
  STATX_MODE: number;
  STATX_NLINK: number;
  STATX_INO: number;
  STATX_SIZE: number;
  STATX_BTIME: number;
  S_IFMT: number;
  S_IFREG: number;
  S_IFDIR: number;
  S_IFLNK: number;
};

export type LinuxScopedTreeAddon = {
  openat2(
    dirfd: number,
    path: string,
    flags: number,
    mode: number,
    resolve: number,
  ): number;
  statx(dirfd: number, path: string, flags: number, mask: number): LinuxStatx;
  close(fd: number): void;
  unlinkat(dirfd: number, path: string, flags: number): void;
  renameat2(
    oldDirfd: number,
    oldPath: string,
    newDirfd: number,
    newPath: string,
    flags: number,
  ): void;
  linkat(
    oldDirfd: number,
    oldPath: string,
    newDirfd: number,
    newPath: string,
    flags: number,
  ): void;
  listat(dirfd: number): string[];
  constants: LinuxOpenat2Constants;
};

let loaded: LinuxScopedTreeAddon | undefined;

function sourceCandidates(): string[] {
  const here = fileURLToPath(new URL(".", import.meta.url));
  return [
    path.join(here, "native", "scoped-tree-linux.c"),
    path.join(here, "..", "..", "src", "native", "scoped-tree-linux.c"),
  ];
}

function resolveCSource(): string {
  for (const candidate of sourceCandidates()) {
    if (fs.existsSync(candidate)) return candidate;
  }
  throw new CapabilityAdmissionError(
    "unsupported",
    "filesystem.live-root.resolution cannot locate the Linux openat2 helper source",
  );
}

function compileAddon(sourcePath: string): string {
  const source = fs.readFileSync(sourcePath);
  const digest = createHash("sha256").update(source).digest("hex").slice(0, 16);
  const outDir = path.join(os.tmpdir(), "gondolin-scoped-tree-linux");
  fs.mkdirSync(outDir, { recursive: true });
  const outPath = path.join(outDir, `scoped-tree-linux-${digest}.node`);
  if (fs.existsSync(outPath)) return outPath;
  try {
    execFileSync(
      "cc",
      ["-shared", "-fPIC", "-O2", "-D_GNU_SOURCE", "-o", outPath, sourcePath],
      { stdio: ["ignore", "pipe", "pipe"] },
    );
  } catch {
    try {
      fs.unlinkSync(outPath);
    } catch {
      // The compiler may leave a partial image; ignore cleanup failure.
    }
    throw new CapabilityAdmissionError(
      "unsupported",
      "filesystem.live-root.resolution cannot compile Linux openat2 support",
    );
  }
  return outPath;
}

/** Load the kernel-assisted live-root helper, or fail closed */
export function loadLinuxScopedTreeAddon(): LinuxScopedTreeAddon {
  if (process.platform !== "linux") {
    throw new CapabilityAdmissionError(
      "unsupported",
      `filesystem.live-root.resolution is unsupported on ${process.platform}`,
    );
  }
  if (loaded) return loaded;
  const sourcePath = resolveCSource();
  const addonPath = compileAddon(sourcePath);
  const module = { exports: {} as LinuxScopedTreeAddon };
  try {
    process.dlopen(module, addonPath);
  } catch {
    throw new CapabilityAdmissionError(
      "unsupported",
      "filesystem.live-root.resolution cannot load Linux openat2 support",
    );
  }
  loaded = module.exports;
  return loaded;
}

export function isRegularFile(
  mode: number,
  constants: LinuxOpenat2Constants,
): boolean {
  return (mode & constants.S_IFMT) === constants.S_IFREG;
}

export function isDirectory(
  mode: number,
  constants: LinuxOpenat2Constants,
): boolean {
  return (mode & constants.S_IFMT) === constants.S_IFDIR;
}

export function isSymlink(
  mode: number,
  constants: LinuxOpenat2Constants,
): boolean {
  return (mode & constants.S_IFMT) === constants.S_IFLNK;
}
