import { randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { sha256 } from "./canonical-json.ts";

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

/** Historical visibility evidence under the local exact-file publication profile */
export type ExactWriterPublication = {
  schemaVersion: "gondolin.exact-writer-publication/v1";
  /** Whether this invocation crossed the host visibility boundary */
  state: "not_published" | "published" | "indeterminate";
  /** Last publication phase reached, independently of cleanup */
  phase:
    | "not_attempted"
    | "preparing"
    | "prepared"
    | "publishing"
    | "published"
    | "verified";
  /** Local visibility primitive, without a crash-durability guarantee */
  primitive: "link" | "rename";
  /** Decimal device/inode identities pinned before execution */
  expectedTarget: SerializedWriterIdentity;
  /** Decimal device/inode identity of the prepared file */
  stagedIdentity: { dev: string; ino: string } | null;
  /** Initial content SHA-256, or `null` for an absent target */
  initialDigest: string | null;
  /** Prepared private output SHA-256, never a current-target assertion */
  preparedDigest: string | null;
  /** Postpublication identity verification status */
  targetVerification: "verified" | "failed" | "unknown";
  /** Removal of host staging objects and closure of all publication-owned descriptors */
  stagingCleanup: "verified" | "failed" | "unknown";
  /** Unsupported crash-durability proof */
  durability: "unknown";
  /** Unsupported durable evidence finalization and delivery proof */
  evidenceFinalization: "unknown";
};

type SerializedWriterIdentity = {
  parent: { dev: string; ino: string };
  file: { dev: string; ino: string } | null;
};

export function unpublishedWriterPublication(
  expected: HostWriterTargetIdentity,
  initial: Buffer | null,
): ExactWriterPublication {
  const serialize = (value: HostFileIdentity) => ({
    dev: String(value.dev),
    ino: String(value.ino),
  });
  return {
    schemaVersion: "gondolin.exact-writer-publication/v1",
    state: "not_published",
    phase: "not_attempted",
    primitive: expected.file === null ? "link" : "rename",
    expectedTarget: {
      parent: serialize(expected.parent),
      file: expected.file && serialize(expected.file),
    },
    stagedIdentity: null,
    initialDigest: initial === null ? null : sha256(initial),
    preparedDigest: null,
    targetVerification: "unknown",
    stagingCleanup: "verified",
    durability: "unknown",
    evidenceFinalization: "unknown",
  };
}

export type ExactWriterSettlement = {
  publication: ExactWriterPublication;
  /** Verified published identity, or `null` if unavailable, even when cleanup subsequently fails */
  identity: HostWriterTargetIdentity | null;
  /** Failure occurrence independent of the thrown JavaScript value */
  failed: boolean;
  /** Original local exception, excluded from signed evidence */
  error?: unknown;
};

// A failed close has an ambiguous effect: relinquish the numeric descriptor
// before attempting it, since retrying could close an unrelated reused fd.
class PublicationDescriptors {
  readonly owned = new Set<number>();
  ambiguousOpen = false;
  closeFailed = false;

  open(operation: () => number): number {
    this.ambiguousOpen = true;
    const fd = operation();
    this.owned.add(fd);
    this.ambiguousOpen = false;
    return fd;
  }

  close(fd: number): void {
    if (!this.owned.delete(fd)) return;
    try {
      fs.closeSync(fd);
    } catch (error) {
      this.closeFailed = true;
      throw error;
    }
  }
}

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
  descriptors?: PublicationDescriptors,
): Buffer | null {
  verifyHostDirectoryIdentity(
    path.dirname(targetPath),
    expected.parent,
    validation,
    descriptors,
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
    descriptors,
  );
  try {
    return fs.readFileSync(fd);
  } finally {
    if (descriptors) descriptors.close(fd);
    else fs.closeSync(fd);
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
  const settlement = settleExactWriterTarget(
    targetPath,
    expected,
    initial,
    contents,
    observedOperations,
    hooks,
    validation,
  );
  if (settlement.failed) throw settlement.error;
  return settlement.identity!;
}

export function settleExactWriterTarget(
  targetPath: string,
  expected: HostWriterTargetIdentity,
  initial: Buffer | null,
  contents: Buffer,
  observedOperations: ReadonlySet<ExactWriterOperation>,
  hooks: ExactWriterCommitHooks = {},
  validation: CapabilityFilesystemValidation = defaultValidation,
): ExactWriterSettlement {
  const publication = unpublishedWriterPublication(expected, initial);
  publication.phase = "preparing";
  publication.preparedDigest = sha256(contents);
  let stagingDirectory: string | null = null;
  let identity: HostWriterTargetIdentity | null = null;
  let error: unknown;
  let failed = false;
  const descriptors = new PublicationDescriptors();
  try {
    verifyHostDirectoryIdentity(
      path.dirname(targetPath),
      expected.parent,
      validation,
      descriptors,
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
    publication.stagingCleanup = "unknown";
    stagingDirectory = fs.mkdtempSync(
      path.join(parent, `.gondolin-commit-${randomBytes(8).toString("hex")}-`),
    );
    const stagedPath = path.join(stagingDirectory, "payload");
    const stagedFd = descriptors.open(() =>
      openNoFollow(
        stagedPath,
        fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_RDWR,
        "filesystem staging target",
        validation,
        0o600,
      ),
    );
    let written = 0;
    while (written < contents.length) {
      const count = fs.writeSync(
        stagedFd,
        contents,
        written,
        contents.length - written,
        written,
      );
      if (count <= 0) {
        validation.invalid("filesystem staging write made no progress");
      }
      written += count;
    }
    const staged = fs.fstatSync(stagedFd, { bigint: true });
    publication.stagedIdentity = {
      dev: String(staged.dev),
      ino: String(staged.ino),
    };
    fs.fsyncSync(stagedFd);
    descriptors.close(stagedFd);

    publication.phase = "prepared";
    hooks.beforePublish?.();
    verifyHostDirectoryIdentity(
      parent, expected.parent, validation, descriptors,
    );

    if (expected.file === null) {
      publication.state = "indeterminate";
      publication.phase = "publishing";
      fs.linkSync(stagedPath, targetPath);
      publication.state = "published";
      publication.phase = "published";
      fs.unlinkSync(stagedPath);
    } else {
      const currentFd = openExactWriterFile(
        targetPath,
        expected.file,
        fs.constants.O_RDONLY,
        validation,
        false,
        descriptors,
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
        descriptors.close(currentFd);
      }
      publication.state = "indeterminate";
      publication.phase = "publishing";
      fs.renameSync(stagedPath, targetPath);
      publication.state = "published";
      publication.phase = "published";
    }

    verifyHostDirectoryIdentity(
      parent, expected.parent, validation, descriptors,
    );
    const published = fs.lstatSync(targetPath, { bigint: true });
    if (
      !published.isFile() ||
      published.isSymbolicLink() ||
      published.nlink !== 1n ||
      String(published.dev) !== publication.stagedIdentity?.dev ||
      String(published.ino) !== publication.stagedIdentity?.ino
    ) {
      validation.invalid(
        "filesystem target publication was not an exact regular file",
      );
    }
    const verifiedContents = readExactWriterTarget(
      targetPath,
      {
        parent: expected.parent,
        file: { dev: published.dev, ino: published.ino },
      },
      validation,
      descriptors,
    );
    if (verifiedContents === null || !verifiedContents.equals(contents)) {
      validation.invalid(
        "filesystem published target contents changed during verification",
      );
    }
    publication.targetVerification = "verified";
    publication.phase = "verified";
    identity = {
      parent: expected.parent,
      file: { dev: published.dev, ino: published.ino },
    };
  } catch (caught) {
    failed = true;
    error = caught;
    if (publication.state === "published")
      publication.targetVerification = "failed";
  } finally {
    let cleanupFailed = false;
    for (const fd of descriptors.owned) {
      try {
        descriptors.close(fd);
      } catch (caught) {
        cleanupFailed = true;
        if (!failed) error = caught;
        failed = true;
      }
    }
    if (stagingDirectory !== null) {
      try {
        fs.rmSync(stagingDirectory, { recursive: true, force: true });
      } catch (caught) {
        cleanupFailed = true;
        if (!failed) error = caught;
        failed = true;
      }
    }
    publication.stagingCleanup = cleanupFailed || descriptors.closeFailed
      ? "failed"
      : descriptors.ambiguousOpen ||
          (stagingDirectory === null &&
            publication.stagingCleanup === "unknown")
        ? "unknown"
        : "verified";
  }
  return { publication, identity, failed, ...(failed ? { error } : {}) };
}

function getHostDirectoryIdentity(
  directoryPath: string,
  validation: CapabilityFilesystemValidation,
  descriptors?: PublicationDescriptors,
): HostFileIdentity {
  let fd: number;
  try {
    const open = () =>
      fs.openSync(
        directoryPath,
        fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY ?? 0),
      );
    fd = descriptors ? descriptors.open(open) : open();
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
    if (descriptors) descriptors.close(fd!);
    else fs.closeSync(fd!);
  }
}

function verifyHostDirectoryIdentity(
  directoryPath: string,
  expected: HostFileIdentity,
  validation: CapabilityFilesystemValidation,
  descriptors?: PublicationDescriptors,
): void {
  const actual = getHostDirectoryIdentity(
    directoryPath, validation, descriptors,
  );
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
  descriptors?: PublicationDescriptors,
): number {
  const open = () =>
    openNoFollow(targetPath, access, "filesystem target", validation);
  const fd = descriptors ? descriptors.open(open) : open();
  let validated = false;
  try {
    const stats = fs.fstatSync(fd, { bigint: true });
    if (
      !stats.isFile() ||
      (requireSingleLink && stats.nlink !== 1n) ||
      stats.dev !== expected.dev ||
      stats.ino !== expected.ino
    ) {
      validation.invalid(
        "filesystem target identity changed after ceiling creation",
      );
    }
    validated = true;
    return fd;
  } finally {
    if (!validated) {
      if (descriptors) descriptors.close(fd);
      else fs.closeSync(fd);
    }
  }
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
