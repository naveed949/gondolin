import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  EARNED_ACTIVE_PROFILES,
  EXTRA_EVIDENCE_FILES,
  FEATURE_HEADINGS,
  HELPER_EVIDENCE_FILES,
  checkAdvertisedProfiles,
  checkFeatureHeadings,
  checkSkillEvidenceNames,
  checkSoftPassRejected,
  checkVerifyEvidence,
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

test("current checkout satisfies the agent invariant gates", () => {
  assert.deepEqual(runAgentInvariants(), []);
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
    assert.ok(HELPER_EVIDENCE_FILES.includes("result.txt"));
    assert.ok(EXTRA_EVIDENCE_FILES.includes("doctor.txt"));
  } finally {
    fs.rmSync(path.dirname(file), { recursive: true, force: true });
  }
});

test("advertising a profile without its earning test is rejected", () => {
  const errors = checkAdvertisedProfiles({
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

test("advertising scoped-tree-runner after dropping the denial title is rejected", () => {
  const root = tempDir("gondolin-advertise-");
  try {
    const rel = EARNED_ACTIVE_PROFILES["scoped-tree-runner"].files[0];
    write(path.join(root, rel), 'test("unrelated success path", () => {});\n');
    const errors = checkAdvertisedProfiles({
      manifest: { profiles: { "scoped-tree-runner": "active" } },
      root,
    });
    assert.equal(errors.length, 1);
    assert.match(errors[0], /denies cross-directory rename/);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("Soft-PASS is not a qualification status", () => {
  assert.deepEqual(checkSoftPassRejected(), []);
  const invented = [
    'export type QualificationStatus = "verified" | "unverified" | "Soft-PASS";',
    'if (!["verified", "unverified", "Soft-PASS"].includes(String(input))) {',
  ].join("\n");
  const errors = checkSoftPassRejected({ source: invented });
  assert.ok(errors.some((error) => /Soft-PASS/.test(error)));
});
