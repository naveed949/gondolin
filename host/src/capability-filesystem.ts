import { randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export type HostFileIdentity = {
  /** Host filesystem device identity */
  dev: bigint;
  /** Host filesystem inode identity */
  ino: bigint;
};

export type HostWriterTargetIdentity = {
  /** Pinned parent-directory identity */
  parent: HostFileIdentity;
  /** Pinned target identity, or `null` when creation is required */
  file: HostFileIdentity | null;
};

export type ExactWriterOperation = "create" | "write" | "truncate";

export type CapabilityFilesystemValidation = {
  /** Reject malformed or changed filesystem state */
  invalid(message: string): never;
  /** Reject host platforms lacking a required primitive */
  unsupported(message: string): never;
  /** Normalize a required non-empty string */
  nonEmptyString(value: unknown, label: string): string;
};

export type ExactWriterCommitHooks = {
  /** Test-only synchronization point before atomic publication */
  beforePublish?: () => void;
};

const defaultValidation: CapabilityFilesystemValidation = {
  invalid(message): never {
    throw new Error(message);
  },
  unsupported(message): never {
    throw new Error(message);
  },
  nonEmptyString(value, label): string {
    if (typeof value !== "string" || value.length === 0) {
      throw new Error(`${label} must be a non-empty string`);
    }
    return value;
  },
};

export function canonicalHostFile(
  value: unknown,
  label: string,
  validation: CapabilityFilesystemValidation = defaultValidation,
): string {
  const input = validation.nonEmptyString(value, label);
  const lexical = path.resolve(input);
  let stats: fs.Stats;
  try {
    stats = fs.lstatSync(lexical);
  } catch {
    validation.invalid(`${label} must identify an existing host file`);
  }
  if (stats!.isSymbolicLink() || !stats!.isFile()) {
    validation.invalid(
      `${label} must identify a regular file without symlink indirection`,
    );
  }
  return fs.realpathSync(lexical);
}

export function canonicalHostTarget(
  value: unknown,
  label: string,
  validation: CapabilityFilesystemValidation = defaultValidation,
): string {
  const input = validation.nonEmptyString(value, label);
  const lexical = path.resolve(input);
  const parent = path.dirname(lexical);
  let canonicalParent: string;
  try {
    canonicalParent = fs.realpathSync(parent);
  } catch {
    validation.invalid(`${label} parent must identify an existing directory`);
  }
  const target = path.join(canonicalParent!, path.basename(lexical));
  if (
    target
      .split(path.sep)
      .some((component) => component.toLowerCase() === ".git")
  ) {
    validation.unsupported(`${label} cannot select Git metadata`);
  }
  try {
    const stats = fs.lstatSync(target, { bigint: true });
    if (stats.isSymbolicLink() || !stats.isFile()) {
      validation.invalid(
        `${label} must identify a regular file or a missing exact target`,
      );
    }
    if (stats.nlink !== 1n) {
      validation.invalid(`${label} cannot select a hard-linked file`);
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  return target;
}

export function getHostWriterTargetIdentity(
  targetPath: string,
  validation: CapabilityFilesystemValidation = defaultValidation,
): HostWriterTargetIdentity {
  const parent = getHostDirectoryIdentity(path.dirname(targetPath), validation);
  try {
    const stats = fs.lstatSync(targetPath, { bigint: true });
    if (stats.isSymbolicLink() || !stats.isFile() || stats.nlink !== 1n) {
      validation.invalid(
        "filesystem target must remain a uniquely linked regular file",
      );
    }
    return { parent, file: { dev: stats.dev, ino: stats.ino } };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return { parent, file: null };
    }
    throw error;
  }
}

export function getHostFileIdentity(
  filePath: string,
  validation: CapabilityFilesystemValidation = defaultValidation,
): HostFileIdentity {
  const fd = openNoFollow(
    filePath,
    fs.constants.O_RDONLY,
    "filesystem source",
    validation,
  );
  try {
    const stats = fs.fstatSync(fd, { bigint: true });
    if (!stats.isFile()) {
      validation.invalid("filesystem source is no longer a regular file");
    }
    return { dev: stats.dev, ino: stats.ino };
  } finally {
    fs.closeSync(fd);
  }
}

export function readExactHostFile(
  filePath: string,
  expected: HostFileIdentity,
  validation: CapabilityFilesystemValidation = defaultValidation,
): Buffer {
  const fd = openNoFollow(
    filePath,
    fs.constants.O_RDONLY,
    "filesystem source",
    validation,
  );
  try {
    const stats = fs.fstatSync(fd, { bigint: true });
    if (!stats.isFile()) {
      validation.invalid("filesystem source is no longer a regular file");
    }
    if (stats.dev !== expected.dev || stats.ino !== expected.ino) {
      validation.invalid(
        "filesystem source identity changed after ceiling creation",
      );
    }
    return fs.readFileSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

export function readExactWriterTarget(
  targetPath: string,
  expected: HostWriterTargetIdentity,
  validation: CapabilityFilesystemValidation = defaultValidation,
): Buffer | null {
  verifyHostDirectoryIdentity(
    path.dirname(targetPath),
    expected.parent,
    validation,
  );
  if (expected.file === null) {
    try {
      fs.lstatSync(targetPath);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw error;
    }
    validation.invalid("filesystem target appeared after ceiling creation");
  }
  const fd = openExactWriterFile(
    targetPath,
    expected.file,
    fs.constants.O_RDONLY,
    validation,
    true,
  );
  try {
    return fs.readFileSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

export function commitExactWriterTarget(
  targetPath: string,
  expected: HostWriterTargetIdentity,
  initial: Buffer | null,
  contents: Buffer,
  observedOperations: ReadonlySet<ExactWriterOperation>,
  hooks: ExactWriterCommitHooks = {},
  validation: CapabilityFilesystemValidation = defaultValidation,
): HostWriterTargetIdentity {
  verifyHostDirectoryIdentity(
    path.dirname(targetPath),
    expected.parent,
    validation,
  );
  if (expected.file === null && !observedOperations.has("create")) {
    validation.invalid(
      "writer produced a missing target without an observed create",
    );
  }
  if (
    initial !== null &&
    contents.length < initial.length &&
    !observedOperations.has("truncate")
  ) {
    validation.invalid(
      "writer shortened the target without truncate authority",
    );
  }

  const parent = path.dirname(targetPath);
  const stagingDirectory = fs.mkdtempSync(
    path.join(parent, `.gondolin-commit-${randomBytes(8).toString("hex")}-`),
  );
  const stagedPath = path.join(stagingDirectory, "payload");
  let stagedFd: number | null = null;
  try {
    stagedFd = openNoFollow(
      stagedPath,
      fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_RDWR,
      "filesystem staging target",
      validation,
      0o600,
    );
    if (contents.length > 0) {
      fs.writeSync(stagedFd, contents, 0, contents.length, 0);
    }
    fs.fsyncSync(stagedFd);
    fs.closeSync(stagedFd);
    stagedFd = null;

    hooks.beforePublish?.();
    verifyHostDirectoryIdentity(parent, expected.parent, validation);

    if (expected.file === null) {
      fs.linkSync(stagedPath, targetPath);
      fs.unlinkSync(stagedPath);
    } else {
      const currentFd = openExactWriterFile(
        targetPath,
        expected.file,
        fs.constants.O_RDONLY,
        validation,
        false,
      );
      try {
        const current = fs.readFileSync(currentFd);
        if (initial === null || !current.equals(initial)) {
          validation.invalid(
            "filesystem target contents changed before commit",
          );
        }
        const stats = fs.fstatSync(currentFd);
        fs.chownSync(stagedPath, stats.uid, stats.gid);
        fs.chmodSync(stagedPath, stats.mode & 0o7777);
      } finally {
        fs.closeSync(currentFd);
      }
      fs.renameSync(stagedPath, targetPath);
    }

    verifyHostDirectoryIdentity(parent, expected.parent, validation);
    const published = fs.lstatSync(targetPath, { bigint: true });
    if (
      !published.isFile() ||
      published.isSymbolicLink() ||
      published.nlink !== 1n
    ) {
      validation.invalid(
        "filesystem target publication was not an exact regular file",
      );
    }
    return {
      parent: expected.parent,
      file: { dev: published.dev, ino: published.ino },
    };
  } finally {
    if (stagedFd !== null) fs.closeSync(stagedFd);
    fs.rmSync(stagingDirectory, { recursive: true, force: true });
  }
}

function getHostDirectoryIdentity(
  directoryPath: string,
  validation: CapabilityFilesystemValidation,
): HostFileIdentity {
  let fd: number;
  try {
    fd = fs.openSync(
      directoryPath,
      fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY ?? 0),
    );
  } catch {
    validation.invalid(
      "filesystem target parent changed or could not be opened",
    );
  }
  try {
    const stats = fs.fstatSync(fd!, { bigint: true });
    if (!stats.isDirectory()) {
      validation.invalid("filesystem target parent is no longer a directory");
    }
    return { dev: stats.dev, ino: stats.ino };
  } finally {
    fs.closeSync(fd!);
  }
}

function verifyHostDirectoryIdentity(
  directoryPath: string,
  expected: HostFileIdentity,
  validation: CapabilityFilesystemValidation,
): void {
  const actual = getHostDirectoryIdentity(directoryPath, validation);
  if (actual.dev !== expected.dev || actual.ino !== expected.ino) {
    validation.invalid(
      "filesystem target parent identity changed after ceiling creation",
    );
  }
}

function openExactWriterFile(
  targetPath: string,
  expected: HostFileIdentity,
  access: number,
  validation: CapabilityFilesystemValidation,
  requireSingleLink: boolean,
): number {
  const fd = openNoFollow(targetPath, access, "filesystem target", validation);
  const stats = fs.fstatSync(fd, { bigint: true });
  if (
    !stats.isFile() ||
    (requireSingleLink && stats.nlink !== 1n) ||
    stats.dev !== expected.dev ||
    stats.ino !== expected.ino
  ) {
    fs.closeSync(fd);
    validation.invalid(
      "filesystem target identity changed after ceiling creation",
    );
  }
  return fd;
}

function openNoFollow(
  filePath: string,
  access: number,
  label: string,
  validation: CapabilityFilesystemValidation,
  mode?: number,
): number {
  const noFollow = fs.constants.O_NOFOLLOW;
  if (typeof noFollow !== "number") {
    validation.unsupported(
      "host platform cannot open exact files without following links",
    );
  }
  try {
    return fs.openSync(filePath, access | noFollow, mode);
  } catch {
    validation.invalid(
      `${label} changed or could not be opened without symlink traversal`,
    );
  }
}
