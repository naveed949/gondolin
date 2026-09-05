import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

import {
  getDefaultBuildConfig,
  parseBuildConfig,
  validateBuildConfig,
} from "../src/build/config.ts";

test("build-config: accepts postBuild.commands", () => {
  const cfg = {
    arch: "aarch64",
    distro: "alpine",
    alpine: { version: "3.23.0" },
    postBuild: {
      commands: ["pip3 install llm llm-anthropic"],
    },
  };

  assert.equal(validateBuildConfig(cfg), true);

  const parsed = parseBuildConfig(JSON.stringify(cfg));
  assert.deepEqual(parsed.postBuild?.commands, [
    "pip3 install llm llm-anthropic",
  ]);
});

test("build-config: accepts postBuild.copy", () => {
  const cfg = {
    arch: "aarch64",
    distro: "alpine",
    alpine: { version: "3.23.0" },
    postBuild: {
      copy: [
        {
          src: "./dist/my-tool.tar.gz",
          dest: "/tmp/my-tool.tar.gz",
        },
      ],
    },
  };

  assert.equal(validateBuildConfig(cfg), true);

  const parsed = parseBuildConfig(JSON.stringify(cfg));
  assert.deepEqual(parsed.postBuild?.copy, [
    {
      src: "./dist/my-tool.tar.gz",
      dest: "/tmp/my-tool.tar.gz",
    },
  ]);
});

test("build-config: rejects invalid postBuild.commands", () => {
  const invalid = {
    arch: "aarch64",
    distro: "alpine",
    alpine: { version: "3.23.0" },
    postBuild: {
      commands: [42],
    },
  };

  assert.equal(validateBuildConfig(invalid), false);
  assert.throws(
    () => parseBuildConfig(JSON.stringify(invalid)),
    /Invalid build configuration/,
  );
});

test("build-config: rejects invalid postBuild.copy", () => {
  const invalidType = {
    arch: "aarch64",
    distro: "alpine",
    alpine: { version: "3.23.0" },
    postBuild: {
      copy: [{ src: "./dist/tool.tar.gz", dest: 42 }],
    },
  };

  assert.equal(validateBuildConfig(invalidType), false);
  assert.throws(
    () => parseBuildConfig(JSON.stringify(invalidType)),
    /Invalid build configuration/,
  );

  const invalidRelativeDest = {
    arch: "aarch64",
    distro: "alpine",
    alpine: { version: "3.23.0" },
    postBuild: {
      copy: [{ src: "./dist/tool.tar.gz", dest: "tmp/tool.tar.gz" }],
    },
  };

  assert.equal(validateBuildConfig(invalidRelativeDest), false);
  assert.throws(
    () => parseBuildConfig(JSON.stringify(invalidRelativeDest)),
    /Invalid build configuration/,
  );
});

test("build-config: accepts runtimeDefaults.rootfsMode", () => {
  const cfg = {
    arch: "aarch64",
    distro: "alpine",
    alpine: { version: "3.23.0" },
    runtimeDefaults: {
      rootfsMode: "readonly",
    },
  };

  assert.equal(validateBuildConfig(cfg), true);

  const parsed = parseBuildConfig(JSON.stringify(cfg));
  assert.equal(parsed.runtimeDefaults?.rootfsMode, "readonly");
});

test("build-config: rejects invalid runtimeDefaults.rootfsMode", () => {
  const invalid = {
    arch: "aarch64",
    distro: "alpine",
    alpine: { version: "3.23.0" },
    runtimeDefaults: {
      rootfsMode: "qcow2",
    },
  };

  assert.equal(validateBuildConfig(invalid), false);
  assert.throws(
    () => parseBuildConfig(JSON.stringify(invalid)),
    /Invalid build configuration/,
  );
});

test("build-config: accepts oci rootfs configuration", () => {
  const cfg = {
    arch: "x86_64",
    distro: "alpine",
    alpine: { version: "3.23.0" },
    oci: {
      image: "docker.io/library/debian:bookworm-slim",
      runtime: "docker",
      platform: "linux/amd64",
      pullPolicy: "if-not-present",
    },
  };

  assert.equal(validateBuildConfig(cfg), true);

  const parsed = parseBuildConfig(JSON.stringify(cfg));
  assert.equal(parsed.oci?.image, "docker.io/library/debian:bookworm-slim");
  assert.equal(parsed.oci?.runtime, "docker");
  assert.equal(parsed.oci?.platform, "linux/amd64");
  assert.equal(parsed.oci?.pullPolicy, "if-not-present");
});

test("build-config: rejects invalid oci rootfs configuration", () => {
  const invalid = {
    arch: "x86_64",
    distro: "alpine",
    alpine: { version: "3.23.0" },
    oci: {
      image: "docker.io/library/debian:bookworm-slim",
      runtime: "runc",
      pullPolicy: "sometimes",
    },
  };

  assert.equal(validateBuildConfig(invalid), false);
  assert.throws(
    () => parseBuildConfig(JSON.stringify(invalid)),
    /Invalid build configuration/,
  );
});

test("build-config: fork capability image selects the LSM-capable kernel without changing generic defaults", () => {
  const config = parseBuildConfig(
    fs.readFileSync(
      new URL("../../images/alpine-base.json", import.meta.url),
      "utf8",
    ),
  );
  assert.equal(config.alpine?.kernelPackage, "linux-lts");
  assert.equal(config.alpine?.kernelImage, "vmlinuz-lts");
  assert.ok(config.alpine?.rootfsPackages?.includes("linux-lts"));
  assert.ok(!config.alpine?.rootfsPackages?.includes("linux-virt"));
  const defaults = getDefaultBuildConfig();
  assert.equal(defaults.alpine?.kernelPackage, "linux-virt");
  assert.equal(defaults.alpine?.kernelImage, "vmlinuz-virt");
});
