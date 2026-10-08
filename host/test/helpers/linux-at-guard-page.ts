// Child process for test/linux-at-syscall-arity.test.ts.
//
// koffi runs native calls on its own 2 MiB stack with the call frame at the
// very top. glibc's x86_64 `syscall()` is variadic and always loads its 7th
// argument from `8(%rsp)`. When a binding declares fewer arguments, that load
// reads one slot past the end of koffi's stack. CI hit SIGSEGV whenever the
// next page happened to be a pthread guard page. This helper places a
// PROT_NONE page directly above koffi's stack to make that layout
// deterministic, then drives the bindings.
//
// Usage: node linux-at-guard-page.ts <module|legacy-openat2|legacy-getdents> <iterations>
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createRequire } from "node:module";

import { getdents64, linuxAtAvailable, openat2 } from "../../src/linux-at.ts";

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

const mode = process.argv[2] ?? "module";
const iterations = Number(process.argv[3] ?? "200000");

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

// Load the bindings under test first so koffi allocates its call stack.
if (!linuxAtAvailable()) {
  console.log("unsupported");
  process.exit(2);
}

const koffi = require("koffi");
const libc = koffi.load("libc.so.6");
const getcontext = libc.func("int getcontext(void *ucp)");
const mmap = libc.func(
  "uint64_t mmap(uint64_t addr, size_t length, int prot, int flags, int fd, int64_t offset)",
);

// getcontext() records the caller's stack pointer. A koffi call without
// stack-passed arguments sets RSP to the top of koffi's call stack, so this
// yields the exact first byte past that stack.
const mprotect = libc.func(
  "int mprotect(uint64_t addr, size_t length, int prot)",
);

const context = Buffer.alloc(4096);
if (getcontext(context) !== 0) fail("getcontext failed");
const stackTop = context.readBigUInt64LE(UCONTEXT_RSP_OFFSET);
if (stackTop % BigInt(PAGE_SIZE) !== 0n)
  fail(`koffi stack top 0x${stackTop.toString(16)} is not page aligned`);
const stack = mappingAt(stackTop - 8n);
if (stack?.perms !== "rw-p")
  fail(`no writable koffi stack below 0x${stackTop.toString(16)}`);

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
} else if (above.perms !== "---p") {
  // Usually the first page of koffi.node itself (its ELF headers), which
  // nothing in this process reads again. Revoking access to that one page
  // reproduces the guard-page layout CI hit.
  if (mprotect(stackTop, PAGE_SIZE, PROT_NONE) !== 0) {
    fail(`cannot revoke access above koffi stack: ${above.line}`);
  }
}
if (mappingAt(stackTop)?.perms !== "---p") fail("guard page was not installed");
console.log(`guard page at koffi stack top 0x${stackTop.toString(16)}`);

const root = fs.mkdtempSync(path.join(os.tmpdir(), "gondolin-linux-at-guard-"));
fs.mkdirSync(path.join(root, "nested"));
fs.writeFileSync(path.join(root, "nested", "file.txt"), "x\n");
fs.writeFileSync(path.join(root, "top.txt"), "y\n");
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
  // RESOLVE_BENEATH must still reach the kernel through the `how` argument
  [names[4]!, os.constants.errno.EXDEV],
]);

try {
  if (mode === "module") {
    for (let i = 0; i < iterations; i++) {
      const name = names[i % names.length]!;
      const want = expectedErrno.get(name);
      try {
        fs.closeSync(openat2(dirFd, name, fs.constants.O_RDONLY));
      } catch (error) {
        const errno = (error as NodeJS.ErrnoException).errno;
        if (want === undefined || errno !== want) throw error;
        continue;
      }
      if (want !== undefined) {
        console.error(`openat2(${name}) succeeded; expected errno ${want}`);
        process.exit(4);
      }
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
          console.error(`unexpected getdents64 listing: ${listed}`);
          process.exit(4);
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
    how.writeBigUInt64LE(0x0an, 16);
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
  fs.rmSync(root, { recursive: true, force: true });
}
