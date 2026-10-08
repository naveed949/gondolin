import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { LIBC_SYSCALL_SIGNATURES, linuxAtAvailable } from "../src/linux-at.ts";

const helper = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "helpers",
  "linux-at-guard-page.ts",
);

const glibc = (
  process.report?.getReport() as
    | { header?: { glibcVersionRuntime?: string } }
    | undefined
)?.header?.glibcVersionRuntime;

const guardSkip =
  process.platform !== "linux" || process.arch !== "x64"
    ? "guard-page layout targets glibc x86_64 syscall()"
    : glibc === undefined
      ? "host libc is not glibc"
      : !linuxAtAvailable()
        ? "openat2 unavailable"
        : false;

function runHelper(mode: string, iterations: number) {
  return spawnSync(process.execPath, [helper, mode, String(iterations)], {
    encoding: "utf8",
    timeout: 120_000,
  });
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

test(
  "harness: pre-fix 5/4-argument syscall() bindings fault on a guard page above koffi's stack",
  { skip: guardSkip },
  () => {
    for (const mode of ["legacy-openat2", "legacy-getdents"]) {
      const result = runHelper(mode, 1000);
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
  () => {
    const result = runHelper("module", 200_000);
    assert.equal(result.signal, null, `${result.stdout}${result.stderr}`);
    assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
    assert.match(
      result.stdout,
      /^ok 200000 openat2 \+ 50000 getdents64 calls$/mu,
    );
  },
);
