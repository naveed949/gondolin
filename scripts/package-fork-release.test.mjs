import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import test from "node:test";
import {
  releaseIdentity,
  assembleRegistries,
  packageRelease,
} from "./package-fork-release.mjs";

const version = "0.12.1-adaptivesandbox.1";
const commit = "a".repeat(40);
const tag = `v${version}`;
function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "fork-release-test-"));
  const output = path.join(root, "artifacts");
  fs.mkdirSync(output);
  fs.mkdirSync(path.join(root, "host/dist/bin"), { recursive: true });
  fs.writeFileSync(
    path.join(root, "host/dist/bin/gondolin.js"),
    'console.log("fixture");\n',
  );
  fs.writeFileSync(path.join(root, "LICENSE"), "Apache-2.0 test fixture\n");
  const optionalDependencies = {};
  for (const arch of ["darwin-arm64", "linux-x64"]) {
    const name = `@earendil-works/gondolin-krun-runner-${arch}`;
    optionalDependencies[name] = version;
    const dir = path.join(root, `packages/gondolin-krun-runner-${arch}`);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(
      path.join(dir, "package.json"),
      JSON.stringify({ name, version }),
    );
  }
  fs.writeFileSync(
    path.join(root, "host/package.json"),
    JSON.stringify({
      name: "@earendil-works/gondolin",
      version,
      optionalDependencies,
      files: ["dist/"],
      scripts: { prepack: "exit 99" },
      private: true,
    }),
  );
  let index = 0;
  for (const arch of ["aarch64", "x86_64"]) {
    for (const kind of ["image-alpine-base", "sandbox-helpers"]) {
      const filename = `gondolin-${kind}-${version}-${arch}.tar.gz`;
      const bytes = Buffer.from(`fixture-${filename}`);
      const sha256 = createHash("sha256").update(bytes).digest("hex");
      fs.writeFileSync(path.join(output, filename), bytes);
      fs.writeFileSync(
        path.join(output, `${filename}.sha256`),
        `${sha256}  ${filename}\n`,
      );
      fs.writeFileSync(
        path.join(output, `${filename}.meta.json`),
        JSON.stringify({
          arch,
          sha256,
          buildId: `00000000-0000-4000-8000-00000000000${++index}`,
          gondolinVersion: version,
          sourceRef: commit,
          zigVersion: "0.16.0",
          target: `${arch}-linux-musl`,
        }),
      );
    }
  }
  return {
    root,
    output,
    clean: () => fs.rmSync(root, { recursive: true, force: true }),
  };
}

test("packed prerelease contains built runtime and no upstream optional dependencies or lifecycle scripts", () => {
  const f = fixture();
  try {
    const filename = packageRelease(f.root, f.output, tag, commit);
    const packed = JSON.parse(
      execFileSync(
        "tar",
        ["-xOf", path.join(f.output, filename), "package/package.json"],
        { encoding: "utf8" },
      ),
    );
    assert.equal(packed.version, version);
    assert.equal(packed.private, true);
    assert.equal(packed.optionalDependencies, undefined);
    assert.equal(packed.scripts, undefined);
    const list = execFileSync("tar", ["-tf", path.join(f.output, filename)], {
      encoding: "utf8",
    });
    assert.match(list, /package\/dist\/bin\/gondolin.js/);
    assert.match(list, /package\/LICENSE/);
    const manifest = JSON.parse(
      fs.readFileSync(path.join(f.output, "release-manifest.json")),
    );
    assert.equal(manifest.adaptiveSandboxQualified, false);
    assert.equal(manifest.sourceCommit, commit);
    for (const asset of manifest.artifacts) {
      assert.ok(
        asset.url.startsWith(
          `https://github.com/naveed949/gondolin/releases/download/${tag}/`,
        ),
      );
      assert.equal(
        asset.sha256,
        createHash("sha256")
          .update(fs.readFileSync(path.join(f.output, asset.filename)))
          .digest("hex"),
      );
    }
  } finally {
    f.clean();
  }
});

test("release identity rejects floating tags and mismatched package versions", () => {
  const f = fixture();
  try {
    for (const bad of ["main", "v0.12.0", "v0.12.1-adaptivesandbox.2"])
      assert.throws(() => releaseIdentity(f.root, bad, commit));
    assert.throws(() => releaseIdentity(f.root, tag, "main"));
    const p = path.join(
      f.root,
      "packages/gondolin-krun-runner-linux-x64/package.json",
    );
    fs.writeFileSync(p, JSON.stringify({ version: "0.12.0" }));
    assert.throws(
      () => releaseIdentity(f.root, tag, commit),
      /runner versions/,
    );
  } finally {
    f.clean();
  }
});

test("asset substitution and stale helper source fail before publication", () => {
  const f = fixture();
  try {
    const identity = releaseIdentity(f.root, tag, commit);
    const filename = `gondolin-sandbox-helpers-${version}-x86_64.tar.gz`;
    const metaPath = path.join(f.output, `${filename}.meta.json`);
    const meta = JSON.parse(fs.readFileSync(metaPath));
    fs.writeFileSync(
      metaPath,
      JSON.stringify({ ...meta, sourceRef: "b".repeat(40) }),
    );
    assert.throws(
      () => assembleRegistries(f.output, identity),
      /source\/version/,
    );
    fs.writeFileSync(metaPath, JSON.stringify(meta));
    fs.appendFileSync(path.join(f.output, filename), "substituted");
    assert.throws(
      () => assembleRegistries(f.output, identity),
      /asset identity/,
    );
  } finally {
    f.clean();
  }
});
