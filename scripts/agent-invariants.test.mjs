import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  DOCTOR_FAIL_REASONS,
  EARNED_ACTIVE_PROFILES,
  EXTRA_EVIDENCE_FILES,
  FEATURE_HEADINGS,
  checkAdvertisedProfiles,
  checkFeatureEvidenceNames,
  checkFeatureHeadings,
  checkSkillEvidenceNames,
  checkSoftPassRejected,
  checkVerifyEvidence,
  classifyDoctorProofFailure,
  evaluateDoctorProof,
  helperWrittenEvidenceFiles,
  packageVersion,
  repoRoot,
  runAgentInvariants,
} from "./agent-invariants.mjs";

function tempDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function write(file, text) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, text);
}

test("current checkout satisfies the agent invariant gates", async () => {
  assert.deepEqual(await runAgentInvariants(), []);
});

test("evaluateDoctorProof requires a ready doctor for this package version", () => {
  const version = "0.12.1-adaptivesandbox.12";
  assert.deepEqual(evaluateDoctorProof("", version), {
    ok: false,
    reason: "missing-doctor",
    detail:
      "doctor.txt is missing; tee doctor.sh into this directory before treating the run as proof",
  });
  assert.equal(
    evaluateDoctorProof("package_version=0.12.1-adaptivesandbox.12\n", version)
      .reason,
    "doctor-not-ready",
  );
  assert.equal(
    evaluateDoctorProof(
      "status=refuse\npackage_version=0.12.1-adaptivesandbox.12\n",
      version,
    ).reason,
    "doctor-not-ready",
  );
  assert.equal(
    evaluateDoctorProof("status=ready\n", version).reason,
    "missing-package-version",
  );
  assert.equal(
    evaluateDoctorProof(
      "status=ready\npackage_version=0.12.1-adaptivesandbox.10\n",
      version,
    ).reason,
    "stale-package-version",
  );
  assert.deepEqual(
    evaluateDoctorProof(
      "status=ready\npackage_version=0.12.1-adaptivesandbox.12\n",
      version,
    ),
    { ok: true, reason: null, detail: null },
  );
  assert.equal(
    evaluateDoctorProof(
      `package_version=${version}\nstatus=ready\nstatus=refuse\nreason=live session\n`,
      version,
    ).reason,
    "doctor-not-ready",
  );
  assert.equal(
    evaluateDoctorProof(
      `status=ready\npackage_version=${version}\npackage_version=0.12.1-adaptivesandbox.10\n`,
      version,
    ).reason,
    "stale-package-version",
  );
});

test("a leftover ok verify tree from an older package version is not proof", () => {
  const root = tempDir("gondolin-stale-ok-");
  try {
    const dir = path.join(root, "cli-exec", "leftover-10");
    write(path.join(dir, "result.txt"), "ok\n");
    write(
      path.join(dir, "doctor.txt"),
      "accel=tcg\npackage_version=0.12.1-adaptivesandbox.10\nstatus=ready\n",
    );
    const errors = checkVerifyEvidence({
      artifactsRoot: root,
      expectedVersion: "0.12.1-adaptivesandbox.12",
    });
    assert.equal(errors.length, 1);
    assert.match(errors[0], /leftover-10/);
    assert.match(errors[0], /0\.12\.1-adaptivesandbox\.10/);
    assert.match(errors[0], /host\/package\.json/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("an ok verify tree without doctor.txt is not proof", () => {
  const root = tempDir("gondolin-missing-doctor-");
  try {
    const dir = path.join(root, "cli-exec", "no-doctor");
    write(path.join(dir, "result.txt"), "ok\n");
    const errors = checkVerifyEvidence({
      artifactsRoot: root,
      expectedVersion: packageVersion(),
    });
    assert.equal(errors.length, 1);
    assert.match(errors[0], /doctor\.txt is missing/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("an ok verify tree whose doctor is not ready is not proof", () => {
  const root = tempDir("gondolin-doctor-not-ready-");
  try {
    const dir = path.join(root, "cli-exec", "refuse");
    write(path.join(dir, "result.txt"), "ok\n");
    write(
      path.join(dir, "doctor.txt"),
      `package_version=${packageVersion()}\nstatus=refuse\n`,
    );
    const errors = checkVerifyEvidence({
      artifactsRoot: root,
      expectedVersion: packageVersion(),
    });
    assert.equal(errors.length, 1);
    assert.match(errors[0], /status is not ready/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("a failed nested-KVM tree stays allowed as a non-proof artifact", () => {
  const root = tempDir("gondolin-failed-kvm-");
  try {
    const dir = path.join(root, "cli-exec", "kvm-timeout");
    write(
      path.join(dir, "result.txt"),
      "exec-exit,stdout-uname,stdout-os-release,marker\n",
    );
    write(
      path.join(dir, "doctor.txt"),
      "accel=kvm\npackage_version=0.12.1-adaptivesandbox.12\nstatus=ready\n",
    );
    assert.deepEqual(
      checkVerifyEvidence({
        artifactsRoot: root,
        expectedVersion: "0.12.1-adaptivesandbox.12",
      }),
      [],
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("feature files missing the verify-gondolin H2s fail the heading gate", () => {
  const dir = tempDir("gondolin-headings-");
  try {
    write(
      path.join(dir, "cli-exec.md"),
      "# Run a command\n\n## Sub-features\n\n## Gotchas\n",
    );
    const errors = checkFeatureHeadings({ featuresDir: dir });
    assert.equal(errors.length, 1);
    assert.match(errors[0], /cli-exec\.md/);
    for (const heading of FEATURE_HEADINGS) {
      assert.match(errors[0], new RegExp(heading.replace(/[()]/g, "\\$&")));
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("a helper comment does not allow an invented Evidence name", () => {
  const dir = tempDir("gondolin-helper-comment-");
  try {
    const helperPath = path.join(dir, "drive-cli-exec.sh");
    const skillPath = path.join(dir, "SKILL.md");
    write(
      helperPath,
      '# $EVIDENCE/image-size.txt\necho ok >"$EVIDENCE/result.txt"\n',
    );
    write(
      skillPath,
      [
        "# Verify Gondolin\n",
        "## Evidence\n",
        "- `result.txt` is `ok`\n",
        "- `image-size.txt` records the compressed alpine-base size\n",
        "## Cleanup\n",
      ].join(""),
    );
    const errors = checkSkillEvidenceNames({ skillPath, helperPath });
    assert.equal(errors.length, 1);
    assert.match(errors[0], /image-size\.txt/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("Evidence names keep underscores and capitals", () => {
  const file = path.join(tempDir("gondolin-underscore-"), "SKILL.md");
  try {
    write(
      file,
      [
        "# Verify Gondolin\n",
        "## Evidence\n",
        "- `image_size.txt` and `Image-size.txt`\n",
        "## Cleanup\n",
      ].join(""),
    );
    const errors = checkSkillEvidenceNames({ skillPath: file });
    assert.ok(errors.some((error) => /image_size\.txt/.test(error)));
    assert.ok(errors.some((error) => /Image-size\.txt/.test(error)));
  } finally {
    fs.rmSync(path.dirname(file), { recursive: true, force: true });
  }
});

test("an invented Proof filename in a feature file is rejected", () => {
  const dir = tempDir("gondolin-feature-proof-");
  try {
    write(
      path.join(dir, "cli-exec.md"),
      [
        "# Run a command\n",
        "## Sub-features\n",
        "## How to get to it (user POV)\n",
        "## Driving it with verify-gondolin\n",
        "- **Proof.** Save `image-size.txt`.\n",
        "## Gotchas\n",
      ].join(""),
    );
    const errors = checkFeatureEvidenceNames({ featuresDir: dir });
    assert.equal(errors.length, 1);
    assert.match(errors[0], /image-size\.txt/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("an invented Evidence filename that the helper does not write is rejected", () => {
  const file = path.join(tempDir("gondolin-invented-"), "SKILL.md");
  try {
    write(
      file,
      [
        "# Verify Gondolin\n",
        "## Evidence\n",
        "- `result.txt` is `ok`\n",
        "- `image-size.txt` records the compressed alpine-base size\n",
        "## Cleanup\n",
      ].join(""),
    );
    const errors = checkSkillEvidenceNames({ skillPath: file });
    assert.equal(errors.length, 1);
    assert.match(errors[0], /image-size\.txt/);
    assert.match(errors[0], /drive-cli-exec\.sh/);
    assert.ok(helperWrittenEvidenceFiles().has("result.txt"));
    assert.ok(EXTRA_EVIDENCE_FILES.includes("doctor.txt"));
  } finally {
    fs.rmSync(path.dirname(file), { recursive: true, force: true });
  }
});

test("the live feature manifest is the advertise source", async () => {
  assert.deepEqual(await checkAdvertisedProfiles(), []);
  const errors = await checkAdvertisedProfiles({
    manifest: {
      profiles: {
        invented: "active",
      },
    },
  });
  assert.ok(
    errors.some((error) =>
      /invented is active without an earning-test row/.test(error),
    ),
  );
});

test("advertising a profile without its earning test is rejected", async () => {
  const errors = await checkAdvertisedProfiles({
    manifest: {
      profiles: {
        "scoped-tree-runner": "active",
        "invented-runner": "active",
      },
    },
    root: repoRoot,
  });
  assert.ok(
    errors.some((error) =>
      /invented-runner is active without an earning-test row/.test(error),
    ),
  );
});

test("advertising scoped-tree-runner after dropping the denial title is rejected", async () => {
  const root = tempDir("gondolin-advertise-");
  try {
    const rel = EARNED_ACTIVE_PROFILES["scoped-tree-runner"].files[0];
    write(path.join(root, rel), 'const name = "unrelated success path";\n');
    const errors = await checkAdvertisedProfiles({
      manifest: { profiles: { "scoped-tree-runner": "active" } },
      root,
    });
    assert.equal(errors.length, 1);
    assert.match(errors[0], /denies cross-directory rename/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("a commented-out earning test is not enough to advertise", async () => {
  const root = tempDir("gondolin-commented-earn-");
  try {
    const rel = EARNED_ACTIVE_PROFILES["scoped-tree-runner"].files[0];
    const title = EARNED_ACTIVE_PROFILES["scoped-tree-runner"].requiredText;
    write(path.join(root, rel), `// vmTest("${title}", async () => {});\n`);
    const errors = await checkAdvertisedProfiles({
      manifest: { profiles: { "scoped-tree-runner": "active" } },
      root,
    });
    assert.equal(errors.length, 1);
    assert.match(errors[0], /denies cross-directory rename/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("an unused title next to test(name) is not enough to advertise", async () => {
  const root = tempDir("gondolin-detached-earn-");
  try {
    const rel = EARNED_ACTIVE_PROFILES["https-request"].files[0];
    const title = EARNED_ACTIVE_PROFILES["https-request"].requiredText;
    write(
      path.join(root, rel),
      `const leftover = ["${title}"];\ntest(name, () => {});\n`,
    );
    const errors = await checkAdvertisedProfiles({
      manifest: { profiles: { "https-request": "active" } },
      root,
    });
    assert.equal(errors.length, 1);
    assert.match(errors[0], /HTTPS VM public TLS/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("a skipped or string-wrapped earning title is not enough to advertise", async () => {
  const root = tempDir("gondolin-skip-wrap-");
  try {
    const rel = EARNED_ACTIVE_PROFILES["exact-reader"].files[0];
    const title = EARNED_ACTIVE_PROFILES["exact-reader"].requiredText;
    write(
      path.join(root, rel),
      `test("${title}", { skip: true }, async () => {});\n`,
    );
    const skipped = await checkAdvertisedProfiles({
      manifest: { profiles: { "exact-reader": "active" } },
      root,
    });
    assert.equal(skipped.length, 1);
    write(
      path.join(root, rel),
      "const x = `vmTest(\"" + title + "\", async () => {})`;\n",
    );
    const wrapped = await checkAdvertisedProfiles({
      manifest: { profiles: { "exact-reader": "active" } },
      root,
    });
    assert.equal(wrapped.length, 1);
    write(
      path.join(root, rel),
      `test("${title}", { timeout: 1, skip: true }, async () => {});\n`,
    );
    assert.equal(
      (
        await checkAdvertisedProfiles({
          manifest: { profiles: { "exact-reader": "active" } },
          root,
        })
      ).length,
      1,
    );
    write(
      path.join(root, rel),
      `test("${title}", { skip: "needs kvm" }, async () => {});\n`,
    );
    assert.equal(
      (
        await checkAdvertisedProfiles({
          manifest: { profiles: { "exact-reader": "active" } },
          root,
        })
      ).length,
      1,
    );
    write(
      path.join(root, rel),
      `const re = /test("${title}", () => {})/;\n`,
    );
    assert.equal(
      (
        await checkAdvertisedProfiles({
          manifest: { profiles: { "exact-reader": "active" } },
          root,
        })
      ).length,
      1,
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("Soft-PASS is rejected by the live compatibility-matrix parser", async () => {
  assert.deepEqual(await checkSoftPassRejected(), []);
});

test("a checker crash is not recorded as missing-doctor", () => {
  assert.equal(classifyDoctorProofFailure(""), "doctor-proof-failed");
  assert.equal(classifyDoctorProofFailure("ENOENT\n"), "doctor-proof-failed");
  for (const reason of DOCTOR_FAIL_REASONS) {
    assert.equal(classifyDoctorProofFailure(`${reason}\n`), reason);
  }
});

test("doctor-proof CLI writes the shared fail reasons", () => {
  const bin = path.join(repoRoot, "scripts/agent-invariants.mjs");
  const run = (file) =>
    spawnSync(process.execPath, [bin, "doctor-proof", file], {
      encoding: "utf8",
      cwd: repoRoot,
    });
  const missing = run(path.join(os.tmpdir(), "gondolin-no-doctor.txt"));
  assert.equal(missing.status, 1);
  assert.equal(missing.stdout.trim(), "missing-doctor");
  const dir = tempDir("gondolin-doctor-cli-");
  try {
    const ready = path.join(dir, "ready.txt");
    write(
      ready,
      `status=ready\npackage_version=${packageVersion()}\n`,
    );
    const ok = run(ready);
    assert.equal(ok.status, 0);
    const refuse = path.join(dir, "refuse.txt");
    write(refuse, `status=refuse\npackage_version=${packageVersion()}\n`);
    assert.equal(run(refuse).stdout.trim(), "doctor-not-ready");
    const noVersion = path.join(dir, "no-version.txt");
    write(noVersion, "status=ready\n");
    assert.equal(run(noVersion).stdout.trim(), "missing-package-version");
    const stale = path.join(dir, "stale.txt");
    write(stale, "status=ready\npackage_version=0.12.1-adaptivesandbox.10\n");
    assert.equal(run(stale).stdout.trim(), "stale-package-version");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("the helper fail-closed path calls doctor-proof", () => {
  const helper = fs.readFileSync(
    path.join(
      repoRoot,
      ".cursor/skills/verify-gondolin/helpers/drive-cli-exec.sh",
    ),
    "utf8",
  );
  assert.match(helper, /scripts\/agent-invariants\.mjs" doctor-proof/);
  assert.match(helper, /doctor-proof-failed/);
});
