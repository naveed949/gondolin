import fs from "fs";
import os from "os";
import path from "path";
import { execFileSync } from "child_process";

import { parseEnvEntry } from "../utils/env.ts";
import { assertSafeWritePath } from "./rootfs.ts";
import type { RootfsOwnershipEntry } from "./types.ts";

export class DownloadFileError extends Error {
  /** requested download URL */
  readonly url: string;
  /** upstream HTTP status code when available */
  readonly status?: number;

  constructor(
    url: string,
    options: { status?: number; message?: string; cause?: unknown } = {},
  ) {
    super(
      options.message ??
        (options.status !== undefined
          ? `Failed to download ${url}: HTTP ${options.status}`
          : `Failed to download ${url}`),
      options.cause !== undefined ? { cause: options.cause } : undefined,
    );
    this.name = "DownloadFileError";
    this.url = url;
    this.status = options.status;
  }
}

/** total download attempts, including the first */
const DOWNLOAD_ATTEMPTS = 3;
/** delay before each retry, in `ms` */
const DOWNLOAD_RETRY_BACKOFF_MS = [200, 500] as const;

const TRANSIENT_ERRNO_CODES = new Set([
  "ECONNRESET",
  "ETIMEDOUT",
  "ENOTFOUND",
  "EAI_AGAIN",
]);

export interface DownloadFileOptions {
  /** fetch implementation used for this download */
  fetch?: typeof globalThis.fetch;
  /** delay before each retry, in `ms` */
  backoffMs?: readonly number[];
}

/** Download `url` to `dest`, retrying transient network errors and HTTP 5xx */
export async function downloadFile(
  url: string,
  dest: string,
  options: DownloadFileOptions = {},
): Promise<void> {
  const doFetch = options.fetch ?? fetch;
  const backoffMs = options.backoffMs ?? DOWNLOAD_RETRY_BACKOFF_MS;
  let lastError: unknown;

  for (let attempt = 1; attempt <= DOWNLOAD_ATTEMPTS; attempt++) {
    const retry = attempt < DOWNLOAD_ATTEMPTS;
    try {
      const res = await doFetch(url, { redirect: "follow" });
      if (!res.ok) {
        await releaseResponse(res);
        const error = new DownloadFileError(url, { status: res.status });
        if (retry && isRetryableHttpStatus(res.status)) {
          lastError = error;
          await waitForDownloadRetry(url, attempt, error, backoffMs);
          continue;
        }
        throw error;
      }

      const buf = Buffer.from(await res.arrayBuffer());
      fs.writeFileSync(dest, buf);
      return;
    } catch (err) {
      if (err instanceof DownloadFileError) {
        throw err;
      }
      if (retry && isTransientDownloadError(err)) {
        lastError = err;
        await waitForDownloadRetry(url, attempt, err, backoffMs);
        continue;
      }
      if (isTransientDownloadError(err)) {
        throw new DownloadFileError(url, {
          message: `Failed to download ${url}: ${transientFailureDetail(err)}`,
          cause: err,
        });
      }
      throw err;
    }
  }

  const status =
    lastError instanceof DownloadFileError ? lastError.status : undefined;
  throw new DownloadFileError(url, {
    status,
    message:
      status !== undefined
        ? `Failed to download ${url}: HTTP ${status}`
        : `Failed to download ${url}: ${transientFailureDetail(lastError)}`,
    cause: lastError,
  });
}

function isRetryableHttpStatus(status: number): boolean {
  return status >= 500 && status <= 599;
}

function waitForDownloadRetry(
  url: string,
  attempt: number,
  err: unknown,
  backoffMs: readonly number[],
): Promise<void> {
  const backoff =
    backoffMs[attempt - 1] ?? backoffMs[backoffMs.length - 1] ?? 0;
  const detail = transientFailureDetail(err);
  console.error(
    `Retrying download (${attempt}/${DOWNLOAD_ATTEMPTS - 1}) ${url}: ${detail}`,
  );
  if (backoff <= 0) return Promise.resolve();
  return new Promise((resolve) => {
    setTimeout(resolve, backoff);
  });
}

function isTransientDownloadError(err: unknown): boolean {
  let transient = false;
  forEachError(err, (item) => {
    if (item instanceof TypeError && item.message === "fetch failed") {
      transient = true;
    }
    const code = readErrorCode(item);
    if (code !== undefined && isTransientNetworkCode(code)) {
      transient = true;
    }
  });
  return transient;
}

function transientFailureDetail(err: unknown): string {
  if (err instanceof DownloadFileError && err.status !== undefined) {
    return `HTTP ${err.status}`;
  }
  let fetchFailed = false;
  let code: string | undefined;
  forEachError(err, (item) => {
    if (
      !fetchFailed &&
      item instanceof TypeError &&
      item.message === "fetch failed"
    ) {
      fetchFailed = true;
    }
    if (code === undefined) {
      const itemCode = readErrorCode(item);
      if (itemCode !== undefined && isTransientNetworkCode(itemCode)) {
        code = itemCode;
      }
    }
  });
  if (fetchFailed && code !== undefined) {
    return `TypeError: fetch failed (${code})`;
  }
  if (fetchFailed) return "TypeError: fetch failed";
  if (code !== undefined) return code;
  if (err instanceof Error && err.message) return err.message;
  return "network error";
}

function isTransientNetworkCode(code: string): boolean {
  return TRANSIENT_ERRNO_CODES.has(code) || code.startsWith("UND_ERR_");
}

function readErrorCode(err: object): string | undefined {
  const code = (err as { code?: unknown }).code;
  return typeof code === "string" ? code : undefined;
}

function forEachError(err: unknown, visit: (item: object) => void): void {
  const seen = new Set<unknown>();
  const pending = [err];
  while (pending.length > 0) {
    const current = pending.pop();
    if (
      current === null ||
      current === undefined ||
      typeof current !== "object"
    ) {
      continue;
    }
    if (seen.has(current)) continue;
    seen.add(current);
    visit(current);
    const cause = (current as { cause?: unknown }).cause;
    if (cause !== undefined) pending.push(cause);
    const errors = (current as { errors?: unknown }).errors;
    if (Array.isArray(errors)) {
      for (const nested of errors) pending.push(nested);
    }
  }
}

async function releaseResponse(res: Response): Promise<void> {
  try {
    await res.body?.cancel();
  } catch {
    // Body cancel only frees the socket; the HTTP status is already decisive.
  }
}

export function copyExecutable(
  src: string,
  dest: string,
  rootDir?: string,
): void {
  if (rootDir) {
    assertSafeWritePath(dest, rootDir);
  }
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.copyFileSync(src, dest);
  fs.chmodSync(dest, 0o755);
}

export function writeExecutable(
  dest: string,
  content: string,
  rootDir?: string,
): void {
  if (rootDir) {
    assertSafeWritePath(dest, rootDir);
  }
  fs.mkdirSync(path.dirname(dest), { recursive: true });
  fs.writeFileSync(dest, content, { mode: 0o755 });
}

export function injectBeforeSandboxdExec(
  script: string,
  snippet: string,
): string {
  const marker = "\nexec /usr/bin/sandboxd\n";
  const idx = script.lastIndexOf(marker);
  if (idx !== -1) {
    return (
      script.slice(0, idx) + "\n" + snippet.trimEnd() + "\n" + script.slice(idx)
    );
  }

  return script.trimEnd() + "\n" + snippet.trimEnd() + "\n";
}

export function generateImageEnvScript(
  env: Record<string, string> | string[],
): string | null {
  const entries = normalizeEnvEntries(env);
  if (entries.length === 0) return null;

  const lines = entries.map(
    ([key, value]) => `export ${key}=${shSingleQuote(value)}`,
  );

  return (
    "# Generated by gondolin build\n" +
    "# shellcheck shell=sh\n" +
    lines.join("\n") +
    "\n"
  );
}

function normalizeEnvEntries(
  env: Record<string, string> | string[],
): Array<[string, string]> {
  const map = new Map<string, string>();

  if (Array.isArray(env)) {
    for (const entry of env) {
      const [key, value] = parseEnvEntry(entry);
      validateEnvKey(key);
      map.set(key, value);
    }
  } else {
    for (const [key, value] of Object.entries(env)) {
      validateEnvKey(key);
      map.set(key, value);
    }
  }

  return Array.from(map.entries()).sort(([a], [b]) => a.localeCompare(b));
}

function validateEnvKey(key: string): void {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) {
    throw new Error(
      `Invalid env var name for image env: ${JSON.stringify(key)}`,
    );
  }
}

function shSingleQuote(value: string): string {
  return `'${value.replace(/'/g, `'"'"'`)}'`;
}

/** Find mke2fs / mkfs.ext4 binary */
export function findMke2fs(): string {
  for (const cmd of ["mke2fs", "mkfs.ext4"]) {
    try {
      execFileSync("which", [cmd], { stdio: "pipe" });
      return cmd;
    } catch {
      // continue
    }
  }

  if (process.platform === "darwin") {
    const candidates = [
      "/opt/homebrew/opt/e2fsprogs/sbin/mke2fs",
      "/opt/homebrew/opt/e2fsprogs/bin/mke2fs",
      "/opt/homebrew/opt/e2fsprogs/sbin/mkfs.ext4",
      "/opt/homebrew/opt/e2fsprogs/bin/mkfs.ext4",
      "/usr/local/opt/e2fsprogs/sbin/mke2fs",
      "/usr/local/opt/e2fsprogs/bin/mke2fs",
      "/usr/local/opt/e2fsprogs/sbin/mkfs.ext4",
      "/usr/local/opt/e2fsprogs/bin/mkfs.ext4",
    ];
    for (const candidate of candidates) {
      if (fs.existsSync(candidate)) {
        return candidate;
      }
    }
  }

  throw new Error(
    "Missing required command: mke2fs (install e2fsprogs)\n" +
      "On macOS: brew install e2fsprogs\n" +
      "Then ensure mke2fs is on your PATH (Homebrew: brew --prefix e2fsprogs)",
  );
}

/** Create an ext4 rootfs image from a directory tree */
export function createRootfsImage(
  mkfsCmd: string,
  imagePath: string,
  sourceDir: string,
  label: string,
  fixedSizeMb?: number,
  ownershipEntries: RootfsOwnershipEntry[] = [],
): void {
  let sizeMb: number;

  if (fixedSizeMb !== undefined) {
    sizeMb = fixedSizeMb;
  } else {
    const sizeKb = getDirSizeKb(sourceDir);
    const paddedKb = sizeKb + Math.floor(sizeKb / 5) + 65536;
    sizeMb = Math.ceil(paddedKb / 1024);
  }

  execFileSync(
    mkfsCmd,
    [
      "-t",
      "ext4",
      "-d",
      sourceDir,
      "-L",
      label,
      "-m",
      "0",
      "-O",
      "^has_journal",
      "-E",
      "lazy_itable_init=0,lazy_journal_init=0",
      "-b",
      "4096",
      "-F",
      imagePath,
      `${sizeMb}M`,
    ],
    { stdio: "pipe" },
  );

  applyOwnershipMetadataToRootfsImage(
    mkfsCmd,
    imagePath,
    sourceDir,
    ownershipEntries,
  );
}

function applyOwnershipMetadataToRootfsImage(
  mkfsCmd: string,
  imagePath: string,
  sourceDir: string,
  ownershipEntries: RootfsOwnershipEntry[],
): void {
  if (ownershipEntries.length === 0) {
    return;
  }

  if (typeof process.getuid === "function" && process.getuid() === 0) {
    return;
  }

  const debugfs = findDebugfs(mkfsCmd);
  if (!debugfs) {
    throw new Error(
      "OCI rootfs ownership restoration requires debugfs (install e2fsprogs, and on Alpine add e2fsprogs-extra)",
    );
  }

  const commands: string[] = [];
  for (const entry of ownershipEntries) {
    const hostPath = path.join(sourceDir, ...entry.path.split("/"));
    let st: fs.Stats;
    try {
      st = fs.lstatSync(hostPath);
    } catch (err) {
      const e = err as NodeJS.ErrnoException;
      if (e.code === "ENOENT" || e.code === "ENOTDIR") {
        continue;
      }
      throw new Error(
        `Failed to inspect extracted OCI rootfs path '${entry.path}' before ownership fixup: ${e.message}`,
      );
    }

    if (st.uid === entry.uid && st.gid === entry.gid) {
      continue;
    }

    const imageEntryPath = `/${entry.path}`;
    const quotedPath = quoteDebugfsPath(imageEntryPath);
    commands.push(`sif ${quotedPath} uid ${entry.uid}`);
    commands.push(`sif ${quotedPath} gid ${entry.gid}`);
  }

  if (commands.length === 0) {
    return;
  }

  const cmdFile = path.join(
    fs.mkdtempSync(path.join(os.tmpdir(), "gondolin-debugfs-")),
    "commands.txt",
  );

  try {
    fs.writeFileSync(cmdFile, `${commands.join("\n")}\n`);
    execFileSync(debugfs, ["-w", "-f", cmdFile, imagePath], {
      stdio: ["ignore", "ignore", "pipe"],
      encoding: "utf8",
      maxBuffer: 64 * 1024 * 1024,
    });
  } catch (err) {
    const e = err as {
      code?: unknown;
      status?: unknown;
      stdout?: unknown;
      stderr?: unknown;
    };

    if (e.code === "ENOENT") {
      throw new Error(
        "OCI rootfs ownership restoration requires debugfs (install e2fsprogs, and on Alpine add e2fsprogs-extra)",
      );
    }

    const stdout =
      typeof e.stdout === "string"
        ? e.stdout
        : Buffer.isBuffer(e.stdout)
          ? e.stdout.toString("utf8")
          : "";
    const stderr =
      typeof e.stderr === "string"
        ? e.stderr
        : Buffer.isBuffer(e.stderr)
          ? e.stderr.toString("utf8")
          : "";

    throw new Error(
      `Failed to apply OCI rootfs ownership metadata with debugfs (exit ${String(e.status ?? "?")}):\n` +
        (stdout || stderr ? `${stdout}${stderr}` : ""),
    );
  } finally {
    fs.rmSync(path.dirname(cmdFile), { recursive: true, force: true });
  }
}

function findDebugfs(mkfsCmd: string): string | null {
  const candidates: string[] = [];

  if (path.isAbsolute(mkfsCmd)) {
    candidates.push(path.join(path.dirname(mkfsCmd), "debugfs"));
  }

  candidates.push("debugfs");

  if (process.platform === "darwin") {
    candidates.push(
      "/opt/homebrew/opt/e2fsprogs/sbin/debugfs",
      "/opt/homebrew/opt/e2fsprogs/bin/debugfs",
      "/usr/local/opt/e2fsprogs/sbin/debugfs",
      "/usr/local/opt/e2fsprogs/bin/debugfs",
    );
  }

  for (const candidate of candidates) {
    try {
      execFileSync(candidate, ["-V"], { stdio: "ignore" });
      return candidate;
    } catch {
      // continue
    }
  }

  return null;
}

function quoteDebugfsPath(pathSpec: string): string {
  if (/[\x00-\x1f\x7f]/.test(pathSpec)) {
    throw new Error(
      `OCI rootfs ownership path contains unsupported control characters: ${JSON.stringify(pathSpec)}`,
    );
  }
  return `"${pathSpec.replace(/([\\"])/g, "\\$1")}"`;
}

/** Create a compressed initramfs from a directory tree */
export function createInitramfs(sourceDir: string, outputPath: string): void {
  execFileSync(
    "sh",
    [
      "-c",
      `cd "${sourceDir}" && find . -print0 | cpio --null -ov --format=newc | lz4 -l -c > "${outputPath}"`,
    ],
    { stdio: "pipe" },
  );
}

function getDirSizeKb(dir: string): number {
  try {
    const output = execFileSync("du", ["-sk", dir], {
      encoding: "utf8",
      stdio: ["pipe", "pipe", "pipe"],
    });
    return parseInt(output.split(/\s/)[0], 10) || 0;
  } catch {
    return Math.ceil(walkDirSize(dir) / 1024);
  }
}

function walkDirSize(dir: string): number {
  let size = 0;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isSymbolicLink()) {
      continue;
    }
    if (entry.isDirectory()) {
      size += walkDirSize(full);
      continue;
    }
    if (entry.isFile()) {
      size += fs.statSync(full).size;
    }
  }
  return size;
}
