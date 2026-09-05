import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { pathToFileURL } from "node:url";

const repository = "naveed949/gondolin";
const architectures = ["aarch64", "x86_64"];
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const json = (file) => JSON.parse(fs.readFileSync(file, "utf8"));
const writeJson = (file, value) =>
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);

export function releaseIdentity(root, tag, sourceCommit) {
  const version = json(path.join(root, "host/package.json")).version;
  if (
    !/^0\.12\.1-adaptivesandbox\.[1-9][0-9]*$/.test(version) ||
    tag !== `v${version}`
  ) {
    throw new Error(
      "exact experimental release tag must match package version",
    );
  }
  if (!/^[a-f0-9]{40}$/.test(sourceCommit))
    throw new Error("source commit must be an exact SHA");
  for (const arch of ["darwin-arm64", "linux-x64"]) {
    const name = `@earendil-works/gondolin-krun-runner-${arch}`;
    if (
      json(
        path.join(root, `packages/gondolin-krun-runner-${arch}/package.json`),
      ).version !== version ||
      json(path.join(root, "host/package.json")).optionalDependencies[name] !==
        version
    ) {
      throw new Error("runner versions must match release");
    }
  }
  return { repository, tag, version, sourceCommit };
}

export function assembleRegistries(directory, identity) {
  const image = { schema: 1, refs: {}, builds: {} };
  const helpers = { schema: 1, refs: {}, builds: {} };
  const imageTargets = {};
  const helperTargets = {};
  const artifacts = [];
  for (const arch of architectures) {
    for (const kind of ["image", "sandbox-helpers"]) {
      const filename =
        kind === "image"
          ? `gondolin-image-alpine-base-${identity.version}-${arch}.tar.gz`
          : `gondolin-sandbox-helpers-${identity.version}-${arch}.tar.gz`;
      const metadata = json(path.join(directory, `${filename}.meta.json`));
      const digest = sha256(fs.readFileSync(path.join(directory, filename)));
      if (
        metadata.arch !== arch ||
        metadata.sha256 !== digest ||
        !/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(
          metadata.buildId,
        )
      ) {
        throw new Error(`invalid asset identity: ${filename}`);
      }
      const checksum = fs
        .readFileSync(path.join(directory, `${filename}.sha256`), "utf8")
        .trim();
      if (checksum !== `${digest}  ${filename}`)
        throw new Error(`checksum mismatch: ${filename}`);
      const url = `https://github.com/${repository}/releases/download/${identity.tag}/${filename}`;
      if (kind === "image") {
        imageTargets[arch] = metadata.buildId;
        image.builds[metadata.buildId] = { arch, url, sha256: digest };
      } else {
        if (
          metadata.gondolinVersion !== identity.version ||
          metadata.sourceRef !== identity.sourceCommit ||
          typeof metadata.zigVersion !== "string" ||
          typeof metadata.target !== "string"
        ) {
          throw new Error(`helper source/version mismatch: ${filename}`);
        }
        helperTargets[arch] = metadata.buildId;
        helpers.builds[metadata.buildId] = {
          arch,
          gondolinVersion: identity.version,
          zigVersion: metadata.zigVersion,
          target: metadata.target,
          url,
          sha256: digest,
        };
      }
      artifacts.push({ filename, sha256: digest, url, arch, kind });
    }
  }
  image.refs[`alpine-base:${identity.version}`] = imageTargets;
  image.refs["alpine-base:latest"] = imageTargets;
  helpers.refs[`gondolin:${identity.version}`] = helperTargets;
  return { image, helpers, artifacts };
}

export function packageRelease(root, directory, tag, sourceCommit) {
  const identity = releaseIdentity(root, tag, sourceCommit);
  const registries = assembleRegistries(directory, identity);
  writeJson(
    path.join(directory, "builtin-image-registry.json"),
    registries.image,
  );
  writeJson(
    path.join(directory, "builtin-sandbox-helper-registry.json"),
    registries.helpers,
  );
  const stage = fs.mkdtempSync(path.join(os.tmpdir(), "gondolin-release-"));
  let packageFilename;
  try {
    const pkg = json(path.join(root, "host/package.json"));
    // GitHub tarball only. Do not resolve upstream optional packages or run workspace scripts.
    delete pkg.optionalDependencies;
    delete pkg.scripts;
    delete pkg.devDependencies;
    delete pkg.publishConfig;
    pkg.private = true;
    writeJson(path.join(stage, "package.json"), pkg);
    fs.cpSync(path.join(root, "host/dist"), path.join(stage, "dist"), {
      recursive: true,
    });
    fs.copyFileSync(path.join(root, "LICENSE"), path.join(stage, "LICENSE"));
    const packed = JSON.parse(
      execFileSync(
        "npm",
        ["pack", "--json", "--ignore-scripts", "--pack-destination", directory],
        { cwd: stage, encoding: "utf8" },
      ),
    );
    packageFilename = packed[0].filename;
  } finally {
    fs.rmSync(stage, { recursive: true, force: true });
  }
  const names = [
    packageFilename,
    "builtin-image-registry.json",
    "builtin-sandbox-helper-registry.json",
  ];
  for (const filename of names)
    registries.artifacts.push({
      filename,
      sha256: sha256(fs.readFileSync(path.join(directory, filename))),
      url: `https://github.com/${repository}/releases/download/${tag}/${filename}`,
    });
  writeJson(path.join(directory, "release-manifest.json"), {
    schemaVersion: "gondolin.experimental-release/v1",
    ...identity,
    experimental: true,
    adaptiveSandboxQualified: false,
    vmm: "qemu",
    artifacts: registries.artifacts,
  });
  const checksums = [
    ...registries.artifacts.map((a) => `${a.sha256}  ${a.filename}`),
    `${sha256(fs.readFileSync(path.join(directory, "release-manifest.json")))}  release-manifest.json`,
  ];
  fs.writeFileSync(
    path.join(directory, "SHA256SUMS"),
    `${checksums.join("\n")}\n`,
  );
  return packageFilename;
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href
) {
  const [directory, tag, sourceCommit] = process.argv.slice(2);
  if (!directory)
    throw new Error(
      "usage: package-fork-release.mjs ARTIFACT_DIRECTORY TAG SOURCE_SHA",
    );
  packageRelease(process.cwd(), path.resolve(directory), tag, sourceCommit);
}
