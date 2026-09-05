import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { syncKernelModules } from "../src/alpine/kernel-modules.ts";

function fixture(t: test.TestContext) {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), "gondolin-boot-modules-"));
  t.after(() => fs.rmSync(base, { recursive: true, force: true }));
  const rootfs = path.join(base, "rootfs");
  const initramfs = path.join(base, "initramfs");
  const relativeModules = "lib/modules/6.18.9-lts";
  const source = path.join(rootfs, relativeModules);
  const destination = path.join(initramfs, relativeModules);
  fs.mkdirSync(source, { recursive: true });
  const write = (name: string, contents = name) => {
    const file = path.join(source, name);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, contents);
  };
  return { rootfs, initramfs, source, destination, write };
}

for (const transport of ["virtio_pci", "virtio_mmio"]) {
  test(`initramfs includes modular console and independent ${transport} dependency tree`, (t) => {
    const f = fixture(t);
    const core = "kernel/drivers/virtio/virtio_ring.ko.gz";
    const console = "kernel/drivers/char/virtio_console.ko.gz";
    const transportModule = `kernel/drivers/virtio/${transport}.ko.gz`;
    const transportDependency = "kernel/drivers/virtio/transport_helper.ko.gz";
    const block = "kernel/drivers/block/virtio_blk.ko.gz";
    const unrelated = "kernel/drivers/media/unrelated.ko.gz";
    for (const name of [
      core,
      console,
      transportModule,
      transportDependency,
      block,
      unrelated,
    ])
      f.write(name);
    f.write(
      "modules.builtin",
      "kernel/fs/ext4/ext4.ko\nkernel/net/packet/af_packet.ko\n",
    );
    f.write(
      "modules.dep",
      [
        `${block}: ${core}`,
        `${console}: ${core}`,
        `${transportModule}: ${transportDependency} ${core}`,
        `${transportDependency}:`,
        `${core}:`,
        `${unrelated}:`,
      ].join("\n"),
    );

    syncKernelModules(f.rootfs, f.initramfs, () => {});

    for (const name of [
      core,
      console,
      transportModule,
      transportDependency,
      block,
    ]) {
      assert.equal(
        fs.readFileSync(path.join(f.destination, name), "utf8"),
        name,
      );
    }
    assert.equal(fs.existsSync(path.join(f.destination, unrelated)), false);
    assert.equal(
      fs.readFileSync(path.join(f.destination, "modules.dep"), "utf8"),
      fs.readFileSync(path.join(f.source, "modules.dep"), "utf8"),
    );
  });
}

test("initramfs accepts built-in console and transport without requiring unsupported transport", (t) => {
  const f = fixture(t);
  f.write(
    "modules.builtin",
    [
      "kernel/fs/ext4/ext4.ko",
      "kernel/net/packet/af_packet.ko",
      "kernel/drivers/block/virtio_blk.ko",
      "kernel/drivers/char/virtio_console.ko",
      "kernel/drivers/virtio/virtio_pci.ko",
    ].join("\n"),
  );
  syncKernelModules(f.rootfs, f.initramfs, () => {});
  assert.equal(
    fs.readFileSync(path.join(f.destination, "modules.builtin"), "utf8"),
    fs.readFileSync(path.join(f.source, "modules.builtin"), "utf8"),
  );
});

test("initramfs fails early when console or every supported transport is unavailable", (t) => {
  const f = fixture(t);
  const builtin = [
    "kernel/fs/ext4/ext4.ko",
    "kernel/net/packet/af_packet.ko",
    "kernel/drivers/block/virtio_blk.ko",
  ];
  f.write("modules.builtin", builtin.join("\n"));
  assert.throws(
    () => syncKernelModules(f.rootfs, f.initramfs, () => {}),
    /Required kernel module "virtio_console"/,
  );
  f.write(
    "modules.builtin",
    [...builtin, "kernel/drivers/char/virtio_console.ko"].join("\n"),
  );
  assert.throws(
    () => syncKernelModules(f.rootfs, f.initramfs, () => {}),
    /No supported virtio transport/,
  );
});

test("initramfs includes modular packet sockets needed by DHCP and fails if unavailable", (t) => {
  const f = fixture(t);
  f.write(
    "modules.builtin",
    [
      "kernel/fs/ext4/ext4.ko",
      "kernel/drivers/block/virtio_blk.ko",
      "kernel/drivers/char/virtio_console.ko",
      "kernel/drivers/virtio/virtio_pci.ko",
    ].join("\n"),
  );
  assert.throws(
    () => syncKernelModules(f.rootfs, f.initramfs, () => {}),
    /Required kernel module "af_packet"/,
  );
  const packet = "kernel/net/packet/af_packet.ko.gz";
  f.write(packet);
  f.write("modules.dep", `${packet}:\n`);
  syncKernelModules(f.rootfs, f.initramfs, () => {});
  assert.equal(
    fs.readFileSync(path.join(f.destination, packet), "utf8"),
    packet,
  );
});
