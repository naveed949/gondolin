import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  ROOTFS_INIT_SCRIPT,
  INITRAMFS_INIT_SCRIPT,
} from "../src/alpine/init-scripts.ts";

test("rootfs init uses current uv system certificates environment variable", () => {
  assert.match(ROOTFS_INIT_SCRIPT, /export UV_SYSTEM_CERTS=true/);
  assert.doesNotMatch(ROOTFS_INIT_SCRIPT, /UV_NATIVE_TLS/);
});

for (const networkEnabled of [false, true]) {
  test(`rootfs CA setup ${networkEnabled ? "installs the network CA" : "does not probe the unauthorized MITM mount"}`, () => {
    const root = mkdtempSync(path.join(os.tmpdir(), "gondolin-init-ca-"));
    try {
      mkdirSync(`${root}/etc/ssl/certs`, { recursive: true });
      mkdirSync(`${root}/etc/gondolin/mitm`, { recursive: true });
      writeFileSync(`${root}/etc/ssl/certs/ca-certificates.crt`, "system CA\n");
      writeFileSync(`${root}/etc/gondolin/mitm/ca.crt`, "MITM CA\n");
      if (networkEnabled) {
        mkdirSync(`${root}/sys/class/net/eth0`, { recursive: true });
      }

      mkdirSync(`${root}/bin`);
      writeFileSync(
        `${root}/bin/update-ca-certificates`,
        "#!/bin/sh\nexit 1\n",
        { mode: 0o755 },
      );

      const start = ROOTFS_INIT_SCRIPT.indexOf("setup_mitm_ca() {");
      const end = ROOTFS_INIT_SCRIPT.indexOf("\nmount -t proc", start);
      assert.ok(start >= 0 && end > start);
      // Redirect guest paths into the fixture and trace shell filesystem tests.
      const setup = ROOTFS_INIT_SCRIPT.slice(start, end)
        .replace(/\/(?:etc|sys|usr|run)\//g, (prefix) => `${root}${prefix}`)
        .replaceAll("[ ", "probe ")
        .replaceAll(" ]", "");
      const output = execFileSync(
        "/bin/sh",
        [
          "-c",
          `
set -eu
probe() { printf '%s\\n' "$*" >> "$PROBE_LOG"; test "$@"; }
log() { :; }
${setup}
setup_mitm_ca
printf '%s\\n' "$SSL_CERT_FILE" "\${NODE_EXTRA_CA_CERTS:-}"
`,
        ],
        {
          encoding: "utf8",
          env: {
            PATH: `${root}/bin:${process.env.PATH}`,
            PROBE_LOG: `${root}/probes`,
          },
        },
      );
      const probes = readFileSync(`${root}/probes`, "utf8");
      if (networkEnabled) {
        assert.ok(probes.includes(`${root}/etc/gondolin/mitm/ca.crt`));
        assert.equal(
          output,
          `${root}/run/gondolin/ca-certificates.crt\n${root}/etc/gondolin/mitm/ca.crt\n`,
        );
        assert.equal(
          readFileSync(`${root}/run/gondolin/ca-certificates.crt`, "utf8"),
          "system CA\n\nMITM CA\n",
        );
      } else {
        assert.ok(!probes.includes(`${root}/etc/gondolin/mitm`));
        assert.equal(output, `${root}/etc/ssl/certs/ca-certificates.crt\n\n`);
      }
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
}

test("both boot stages load packet sockets before the DHCP client", () => {
  for (const script of [INITRAMFS_INIT_SCRIPT, ROOTFS_INIT_SCRIPT]) {
    const packet = script.indexOf("modprobe af_packet");
    const dhcp = script.indexOf("if command -v udhcpc");
    assert.ok(packet >= 0 && packet < dhcp);
  }
});
