import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { INITRAMFS_INIT_SCRIPT } from "../src/alpine/init-scripts.ts";
import { ensureResolverMountTarget } from "../src/alpine/rootfs.ts";

test("resolver mount target preserves image content and refuses escaped creation", (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gondolin-resolver-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.mkdirSync(`${root}/etc`);
  ensureResolverMountTarget(root);
  assert.ok(fs.lstatSync(`${root}/etc/resolv.conf`).isFile());
  fs.writeFileSync(`${root}/etc/resolv.conf`, "nameserver 192.0.2.1\n");
  ensureResolverMountTarget(root);
  assert.equal(
    fs.readFileSync(`${root}/etc/resolv.conf`, "utf8"),
    "nameserver 192.0.2.1\n",
  );
  fs.unlinkSync(`${root}/etc/resolv.conf`);
  fs.mkdirSync(`${root}/other`);
  fs.symlinkSync(`${root}/etc`, `${root}/other/etc`);
  assert.throws(
    () => ensureResolverMountTarget(`${root}/other`),
    /outside|symlink/i,
  );
});

for (const readonly of [false, true]) {
  test(`DHCP resolver ${readonly ? "binds across a read-only root" : "copies into a writable root"}`, (t) => {
    const root = fs.mkdtempSync(
      path.join(os.tmpdir(), "gondolin-resolver-init-"),
    );
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    fs.mkdirSync(`${root}/etc`);
    fs.mkdirSync(`${root}/newroot/etc`, { recursive: true });
    fs.writeFileSync(`${root}/etc/resolv.conf`, "nameserver 192.168.127.1\n");
    ensureResolverMountTarget(`${root}/newroot`);
    const start = INITRAMFS_INIT_SCRIPT.lastIndexOf(
      "if [ -s /etc/resolv.conf ]; then",
    );
    const end = INITRAMFS_INIT_SCRIPT.indexOf("exec switch_root", start);
    assert.ok(start >= 0 && end > start);
    const setup = INITRAMFS_INIT_SCRIPT.slice(start, end).replace(
      /\/(?:newroot\/)?etc(?:\/resolv\.conf)?/g,
      (target) => `${root}${target}`,
    );
    execFileSync(
      "/bin/sh",
      [
        "-c",
        `
set -eu
log() { printf '%s\\n' "$*"; }
cp() { if [ "$READONLY" = 1 ]; then return 1; fi; command cp "$@"; }
mount() { printf '%s\\n' "$*" > "$MOUNT_LOG"; }
${setup}
`,
      ],
      {
        env: {
          ...process.env,
          READONLY: readonly ? "1" : "0",
          MOUNT_LOG: `${root}/mount`,
        },
      },
    );
    if (readonly) {
      assert.equal(
        fs.readFileSync(`${root}/mount`, "utf8"),
        `-o bind ${root}/etc/resolv.conf ${root}/newroot/etc/resolv.conf\n`,
      );
      assert.equal(
        fs.readFileSync(`${root}/newroot/etc/resolv.conf`, "utf8"),
        "",
      );
    } else {
      assert.ok(!fs.existsSync(`${root}/mount`));
      assert.equal(
        fs.readFileSync(`${root}/newroot/etc/resolv.conf`, "utf8"),
        "nameserver 192.168.127.1\n",
      );
    }
  });
}
