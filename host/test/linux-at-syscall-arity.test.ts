import assert from "node:assert/strict";
import { type SpawnSyncReturns, spawnSync } from "node:child_process";
import fs from "node:fs";
import { createRequire } from "node:module";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { LIBC_SYSCALL_SIGNATURES, linuxAtAvailable } from "../src/linux-at.ts";

const here = path.dirname(fileURLToPath(import.meta.url));
const helper = path.join(here, "helpers", "linux-at-guard-page.ts");
const linuxAtSource = path.join(here, "..", "src", "linux-at.ts");

const glibc = (
  process.report?.getReport() as
    | { header?: { glibcVersionRuntime?: string } }
    | undefined
)?.header?.glibcVersionRuntime;

function koffiVersion(): string | undefined {
  try {
    return String(createRequire(linuxAtSource)("koffi").version);
  } catch {
    return undefined;
  }
}

const guardSkip =
  process.platform !== "linux" || process.arch !== "x64"
    ? "guard-page layout targets glibc x86_64 syscall()"
    : glibc === undefined
      ? "host libc is not glibc"
      : !linuxAtAvailable()
        ? "openat2 unavailable"
        : !/^3\.3\./u.test(koffiVersion() ?? "")
          ? `guard-page harness reads koffi 3.3.x stack internals; found koffi ${koffiVersion()}`
          : false;

/** Attempts before a test skips because no safe guard layout was found */
const LAYOUT_ATTEMPTS = 5;

/**
 * Run the guard-page child against a fixture this process owns
 *
 * The child may die from SIGSEGV, so it never creates or deletes anything. A
 * child that finds a live mapping above koffi's stack exits 5 without touching
 * it, and a fresh process usually gets a different layout.
 */
function runHelper(mode: string, iterations: number): SpawnSyncReturns<string> {
  let result!: SpawnSyncReturns<string>;
  for (let attempt = 0; attempt < LAYOUT_ATTEMPTS; attempt++) {
    const fixture = fs.mkdtempSync(
      path.join(os.tmpdir(), "gondolin-linux-at-guard-"),
    );
    try {
      const root = path.join(fixture, "root");
      fs.mkdirSync(path.join(root, "nested"), { recursive: true });
      fs.writeFileSync(path.join(root, "nested", "file.txt"), "x\n");
      fs.writeFileSync(path.join(root, "top.txt"), "y\n");
      // Target of `../escape`: a lost RESOLVE_BENEATH would open it, not ENOENT
      fs.writeFileSync(path.join(fixture, "escape"), "outside\n");
      result = spawnSync(
        process.execPath,
        [helper, mode, String(iterations), fixture],
        { encoding: "utf8", timeout: 120_000 },
      );
    } finally {
      fs.rmSync(fixture, { recursive: true, force: true });
    }
    if (result.status !== 5) break;
  }
  return result;
}

/** Skip when the child reports that koffi's stack layout is not as expected */
function skipOnUnsupportedLayout(
  t: test.TestContext,
  result: ReturnType<typeof runHelper>,
): boolean {
  const reason = /^unsupported-layout: (.*)$/mu.exec(result.stdout)?.[1];
  if (result.status !== 5 || reason === undefined) return false;
  t.skip(`guard-page harness cannot place its guard: ${reason}`);
  return true;
}

test("every glibc syscall() binding declares the number plus six arguments", () => {
  for (const [name, signature] of Object.entries(LIBC_SYSCALL_SIGNATURES)) {
    const match = /^long syscall\((.*)\)$/u.exec(signature);
    assert.ok(match, `${name} binds syscall()`);
    const parameters = match[1]!
      .split(",")
      .map((parameter) => parameter.trim());
    assert.equal(parameters.length, 7, `${name}: ${signature}`);
    assert.match(parameters[0]!, /^long number$/u);
  }
});

test("linux-at binds syscall() only through LIBC_SYSCALL_SIGNATURES", () => {
  const source = fs.readFileSync(linuxAtSource, "utf8");
  const block =
    /export const LIBC_SYSCALL_SIGNATURES = \{[\s\S]*?\} as const;/u.exec(
      source,
    );
  assert.ok(block, "LIBC_SYSCALL_SIGNATURES declaration found");
  const outside = source
    .replace(block[0], "")
    .replace(/\/\*[\s\S]*?\*\//gu, "")
    .replace(/\/\/.*$/gmu, "");
  // Any other prototype string for syscall() would bypass the arity check
  assert.doesNotMatch(outside, /["'`][^"'`\n]*\bsyscall\s*\(/u);
  for (const name of Object.keys(LIBC_SYSCALL_SIGNATURES)) {
    assert.match(
      outside,
      new RegExp(
        `lib\\.func\\(\\s*LIBC_SYSCALL_SIGNATURES\\.${name}\\s*,?\\s*\\)`,
        "u",
      ),
      `${name} is bound with lib.func(LIBC_SYSCALL_SIGNATURES.${name})`,
    );
  }
});

test(
  "harness: pre-fix 5/4-argument syscall() bindings fault on a guard page above koffi's stack",
  { skip: guardSkip },
  (t) => {
    for (const mode of ["legacy-openat2", "legacy-getdents"]) {
      const result = runHelper(mode, 1000);
      if (skipOnUnsupportedLayout(t, result)) return;
      assert.match(
        result.stdout,
        /guard page at koffi stack top/u,
        `${mode}: ${result.stderr}`,
      );
      assert.equal(
        result.signal,
        "SIGSEGV",
        `${mode} should fault: ${result.stdout}${result.stderr}`,
      );
    }
  },
);

test(
  "openat2 and getdents64 survive 200k calls with a guard page above koffi's stack",
  { skip: guardSkip },
  (t) => {
    const result = runHelper("module", 200_000);
    if (skipOnUnsupportedLayout(t, result)) return;
    assert.equal(result.signal, null, `${result.stdout}${result.stderr}`);
    assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(
      result.stdout,
      /^ok 200000 openat2 \+ 50000 getdents64 calls$/mu,
    );
  },
);
