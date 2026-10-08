// Child process for test/linux-at-syscall-arity.test.ts.
//
// koffi runs native calls on its own 1 MiB stack with the call frame at the
// very top. glibc's x86_64 `syscall()` is variadic and always loads its 7th
// argument from `8(%rsp)`. When a binding declares fewer arguments, that load
// reads one slot past the end of koffi's stack. CI hit SIGSEGV whenever the
// next page happened to be a pthread guard page. This helper places a
// PROT_NONE page directly above koffi's stack to make that layout
// deterministic, then drives the bindings.
//
// The parent test owns the fixture directory: it creates `<fixture>/root`
// (holding `top.txt` and `nested/file.txt`) next to a real `<fixture>/escape`
// file, and removes it afterwards. This child never creates or deletes files,
// so dying from SIGSEGV leaks nothing.
//
// Usage: node linux-at-guard-page.ts <module|legacy-openat2|legacy-getdents> <iterations> <fixture>
//
// Exit codes: 0 ok, 2 usage or openat2 unsupported, 3 setup failure,
// 4 wrong result (a JSON diagnostic follows on stderr), 5 koffi's stack
// layout does not allow a safe guard page in this process (the parent test
// retries, then skips).
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createRequire } from "node:module";

import {
  RESOLVE_BENEATH,
  RESOLVE_NO_MAGICLINKS,
  getdents64,
  linuxAtAvailable,
  openat2,
} from "../../src/linux-at.ts";

const require = createRequire(import.meta.url);

const PAGE_SIZE = 4096;
const PROT_NONE = 0;
const MAP_PRIVATE = 0x02;
const MAP_ANONYMOUS = 0x20;
const MAP_FIXED_NOREPLACE = 0x100000;
const SYS_OPENAT2 = 437;
const SYS_GETDENTS64 = 217;
/** glibc x86_64 `ucontext_t` offset of `uc_mcontext.gregs[REG_RSP]` */
const UCONTEXT_RSP_OFFSET = 160;
/** koffi line whose call-stack layout this harness was written against */
const KOFFI_LINE = /^3\.3\./u;

const mode = process.argv[2] ?? "module";
const iterations = Number(process.argv[3] ?? "200000");
const fixture = process.argv[4];

type Mapping = { start: bigint; end: bigint; perms: string; line: string };

function mappingAt(address: bigint): Mapping | undefined {
  for (const line of fs.readFileSync("/proc/self/maps", "utf8").split("\n")) {
    if (line.length === 0) continue;
    const [range, perms] = line.split(/\s+/u);
    const [start, end] = range!.split("-").map((value) => BigInt(`0x${value}`));
    if (start! <= address && address < end!)
      return { start: start!, end: end!, perms: perms!, line };
  }
  return undefined;
}

function fail(message: string): never {
  console.error(`setup: ${message}`);
  process.exit(3);
}

function unsupportedLayout(message: string): never {
  console.log(`unsupported-layout: ${message}`);
  process.exit(5);
}

if (fixture === undefined || !path.isAbsolute(fixture)) {
  console.error(
    "usage: linux-at-guard-page.ts <mode> <iterations> <absolute fixture dir>",
  );
  process.exit(2);
}
const root = path.join(fixture, "root");

// Load the bindings under test first so koffi allocates its call stack.
if (!linuxAtAvailable()) {
  console.log("unsupported");
  process.exit(2);
}

const koffi = require("koffi");
if (!KOFFI_LINE.test(String(koffi.version))) {
  unsupportedLayout(`koffi ${koffi.version} is not 3.3.x`);
}
const libc = koffi.load("libc.so.6");
const getcontext = libc.func("int getcontext(void *ucp)");
const mmap = libc.func(
  "uint64_t mmap(uint64_t addr, size_t length, int prot, int flags, int fd, int64_t offset)",
);
const mprotect = libc.func(
  "int mprotect(uint64_t addr, size_t length, int prot)",
);

// getcontext() records the caller's stack pointer. A koffi call without
// stack-passed arguments sets RSP to the top of koffi's call stack, so this
// yields the exact first byte past that stack.
const context = Buffer.alloc(4096);
if (getcontext(context) !== 0) fail("getcontext failed");
const stackTop = context.readBigUInt64LE(UCONTEXT_RSP_OFFSET);
if (stackTop % BigInt(PAGE_SIZE) !== 0n) {
  unsupportedLayout(
    `koffi stack top 0x${stackTop.toString(16)} is not page aligned`,
  );
}
const stack = mappingAt(stackTop - 8n);
if (stack?.perms !== "rw-p") {
  unsupportedLayout(
    `no writable koffi stack mapping below 0x${stackTop.toString(16)}`,
  );
}

const above = mappingAt(stackTop);
if (above === undefined) {
  const result = BigInt(
    mmap(
      stackTop,
      PAGE_SIZE,
      PROT_NONE,
      MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
      -1,
      0,
    ),
  );
  if (result !== stackTop)
    fail(`mmap guard at 0x${stackTop.toString(16)} failed`);
} else if (above.perms === "r--p" && /\/koffi\.node$/u.test(above.line)) {
  // Usually the first page of koffi.node itself (its ELF headers), which
  // nothing in this process reads again. Revoking access to that one page
  // reproduces the guard-page layout CI hit.
  if (mprotect(stackTop, PAGE_SIZE, PROT_NONE) !== 0) {
    fail(`cannot revoke access above koffi stack: ${above.line}`);
  }
} else if (above.perms !== "---p") {
  // Anything else (a V8 heap or code page, a malloc arena) is live memory;
  // revoking it crashes unrelated threads. The parent retries in a new
  // process, where ASLR picks another layout.
  unsupportedLayout(`live mapping above koffi stack: ${above.line}`);
}
if (mappingAt(stackTop)?.perms !== "---p") fail("guard page was not installed");
console.log(`guard page at koffi stack top 0x${stackTop.toString(16)}`);

const dirFd = fs.openSync(
  root,
  fs.constants.O_RDONLY | fs.constants.O_DIRECTORY,
);
const names = [
  "top.txt",
  "nested",
  "nested/file.txt",
  "missing-" + "x".repeat(40),
  "../escape",
];
const expectedErrno = new Map<string, number>([
  [names[3]!, os.constants.errno.ENOENT],
  // `<fixture>/escape` exists, so only RESOLVE_BENEATH reaching the kernel
  // through the `how` argument turns this into EXDEV
  [names[4]!, os.constants.errno.EXDEV],
]);

function errnoOf(run: () => void): number | null {
  try {
    run();
    return null;
  } catch (error) {
    return (error as NodeJS.ErrnoException).errno ?? -1;
  }
}

function safely<T>(read: () => T): T | string {
  try {
    return read();
  } catch (error) {
    return String(error);
  }
}

/** Exit 4 with enough context to diagnose a wrong openat2/getdents64 result */
function mismatch(details: Record<string, unknown>): never {
  const stat = safely(() => fs.fstatSync(dirFd));
  const report = {
    ...details,
    resolve: `0x${(RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS).toString(16)}`,
    koffiErrnoNow: koffi.errno(),
    // Same call again: a different answer means the first one was transient
    retryErrno: errnoOf(() => {
      fs.closeSync(openat2(dirFd, String(details.name), fs.constants.O_RDONLY));
    }),
    dirFd,
    dirFdTarget: safely(() => fs.readlinkSync(`/proc/self/fd/${dirFd}`)),
    dirFdStat:
      typeof stat === "string" ? stat : { ino: stat.ino, nlink: stat.nlink },
    rootIno: safely(() => fs.statSync(root).ino),
    rootListing: safely(() => fs.readdirSync(root).sort()),
    nestedListing: safely(() => fs.readdirSync(path.join(root, "nested"))),
    fixtureListing: safely(() => fs.readdirSync(fixture!).sort()),
    cwd: process.cwd(),
  };
  console.error(`mismatch ${JSON.stringify(report)}`);
  process.exit(4);
}

try {
  if (mode === "module") {
    let previous: { name: string; errno: number | null } | undefined;
    for (let i = 0; i < iterations; i++) {
      const name = names[i % names.length]!;
      const want = expectedErrno.get(name) ?? null;
      let got: number | null = null;
      let message: string | undefined;
      try {
        fs.closeSync(openat2(dirFd, name, fs.constants.O_RDONLY));
      } catch (error) {
        got = (error as NodeJS.ErrnoException).errno ?? -1;
        message = String(error);
      }
      if (got !== want) {
        mismatch({
          call: "openat2",
          i,
          name,
          wantErrno: want,
          got,
          message,
          previous,
        });
      }
      previous = { name, errno: got };
    }
    const listings = Math.floor(iterations / 4);
    for (let i = 0; i < listings; i++) {
      const fd = fs.openSync(
        root,
        fs.constants.O_RDONLY | fs.constants.O_DIRECTORY,
      );
      try {
        const listed = getdents64(fd).sort().join(",");
        if (listed !== "nested,top.txt") {
          mismatch({ call: "getdents64", i, name: ".", listed });
        }
      } finally {
        fs.closeSync(fd);
      }
    }
    console.log(`ok ${iterations} openat2 + ${listings} getdents64 calls`);
  } else if (mode === "legacy-openat2") {
    // The pre-fix declaration from src/linux-at.ts
    const syscall5 = libc.func(
      "long syscall(long number, int a, const char *b, void *c, size_t d)",
    );
    const how = Buffer.alloc(24);
    how.writeBigUInt64LE(BigInt(RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS), 16);
    for (let i = 0; i < iterations; i++) {
      const fd = syscall5(
        SYS_OPENAT2,
        dirFd,
        names[i % names.length]!,
        how,
        24,
      ) as number;
      if (fd >= 0) fs.closeSync(fd);
    }
    console.log(`legacy openat2 survived ${iterations} calls`);
  } else if (mode === "legacy-getdents") {
    // The pre-fix declaration from src/linux-at.ts
    const getdents = libc.func(
      "long syscall(long number, int fd, void *buffer, size_t length)",
    );
    const buffer = Buffer.alloc(4096);
    for (let i = 0; i < iterations; i++) {
      const fd = fs.openSync(
        root,
        fs.constants.O_RDONLY | fs.constants.O_DIRECTORY,
      );
      getdents(SYS_GETDENTS64, fd, buffer, buffer.length);
      fs.closeSync(fd);
    }
    console.log(`legacy getdents survived ${iterations} calls`);
  } else {
    console.error(`unknown mode ${mode}`);
    process.exit(2);
  }
} finally {
  fs.closeSync(dirFd);
}
