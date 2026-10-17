#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
export const repoRoot = path.resolve(here, "..");

export const FEATURE_HEADINGS = [
  "Sub-features",
  "How to get to it (user POV)",
  "Driving it with verify-gondolin",
  "Gotchas",
];

export const HELPER_EVIDENCE_FILES = [
  "command.txt",
  "feature-id.txt",
  "entry-point.txt",
  "marker-expected.txt",
  "meta.txt",
  "stdout.txt",
  "stderr.txt",
  "exit-code.txt",
  "list-after.txt",
  "list-after.stderr.txt",
  "list-after.exit-code.txt",
  "marker-host.txt",
  "result.txt",
];

export const EXTRA_EVIDENCE_FILES = ["doctor.txt", "kvm-dmesg.txt"];

export const EARNED_ACTIVE_PROFILES = {
  "exact-reader": {
    files: ["host/test/capability-invocation.integration.test.ts"],
    requiredText: "public seam allows only the exact reader",
  },
  "https-request": {
    files: ["host/test/https-invocation.integration.test.ts"],
    requiredText: "one-shot HTTPS VM public TLS GET/HEAD",
  },
  "exact-reader.http-tls-credentials": {
    files: ["host/test/capability-invocation.test.ts"],
    requiredText: "credential authority contracts ceiling, network, methods, and validity",
  },
  "exact-writer": {
    files: ["host/test/capability-invocation.test.ts"],
    requiredText:
      "exact-writer fails closed for empty, unsupported, and widening operations",
  },
  "scoped-runner": {
    files: ["host/test/scoped-runner.test.ts"],
    requiredText: "resource exhaustion outcomes remain structurally distinguishable",
  },
  "scoped-tree-runner": {
    files: ["host/test/scoped-tree-runner.integration.test.ts"],
    requiredText:
      "scoped-tree-runner/v1 denies cross-directory rename, repository unlink, and chmod",
  },
};

export function packageVersion(root = repoRoot) {
  return JSON.parse(
    fs.readFileSync(path.join(root, "host/package.json"), "utf8"),
  ).version;
}

function read(file) {
  return fs.readFileSync(file, "utf8");
}

function walkDirs(dir) {
  if (!fs.existsSync(dir)) return [];
  const found = [];
  for (const name of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, name.name);
    if (name.isDirectory()) found.push(full, ...walkDirs(full));
  }
  return found;
}

export function checkVerifyEvidence({
  artifactsRoot,
  expectedVersion,
} = {}) {
  const root =
    artifactsRoot ??
    path.join(repoRoot, ".cursor/skills/verify-gondolin/artifacts");
  const version = expectedVersion ?? packageVersion();
  const errors = [];
  for (const dir of walkDirs(root)) {
    const resultPath = path.join(dir, "result.txt");
    if (!fs.existsSync(resultPath)) continue;
    const result = read(resultPath).trim();
    if (result !== "ok") continue;
    const rel = path.relative(root, dir);
    const doctorPath = path.join(dir, "doctor.txt");
    if (!fs.existsSync(doctorPath)) {
      errors.push(
        `${rel}: result.txt is ok but doctor.txt is missing; tee doctor.sh into this directory before treating the run as proof`,
      );
      continue;
    }
    const doctor = read(doctorPath);
    const match = doctor.match(/^package_version=(.+)$/m);
    if (!match) {
      errors.push(
        `${rel}: doctor.txt has no package_version line; refuse this tree as current proof`,
      );
      continue;
    }
    if (match[1] !== version) {
      errors.push(
        `${rel}: doctor.txt package_version=${match[1]} does not match host/package.json ${version}; a leftover ok tree is not proof for this checkout`,
      );
    }
  }
  return errors;
}

export function checkFeatureHeadings({
  featuresDir,
} = {}) {
  const dir =
    featuresDir ??
    path.join(repoRoot, ".cursor/skills/verify-gondolin/features");
  const errors = [];
  for (const name of fs.readdirSync(dir).sort()) {
    if (!name.endsWith(".md") || name === "README.md") continue;
    const headings = read(path.join(dir, name))
      .split("\n")
      .filter((line) => line.startsWith("## "))
      .map((line) => line.slice(3).trim());
    if (headings.join("\n") !== FEATURE_HEADINGS.join("\n")) {
      errors.push(
        `${name}: feature files need exactly these H2s in order: ${FEATURE_HEADINGS.join(", ")}`,
      );
    }
  }
  return errors;
}

export function checkSkillEvidenceNames({
  skillPath,
} = {}) {
  const file =
    skillPath ??
    path.join(repoRoot, ".cursor/skills/verify-gondolin/SKILL.md");
  const text = read(file);
  const start = text.indexOf("\n## Evidence\n");
  if (start === -1) return ["SKILL.md has no Evidence heading"];
  const rest = text.slice(start + 1);
  const end = rest.search(/\n## /);
  const section = end === -1 ? rest : rest.slice(0, end);
  const allowed = new Set([...HELPER_EVIDENCE_FILES, ...EXTRA_EVIDENCE_FILES]);
  const errors = [];
  for (const name of section.match(/\b[a-z0-9][a-z0-9.-]*\.txt\b/g) ?? []) {
    if (!allowed.has(name)) {
      errors.push(
        `SKILL.md Evidence names ${name}; drive-cli-exec.sh does not write that file. Drop the invented rule or add the file to the helper first`,
      );
    }
  }
  return errors;
}

export function readManifestProfiles(root = repoRoot) {
  const src = read(path.join(root, "host/src/capability-invocation.ts"));
  const start = src.indexOf("  profiles: {");
  if (start === -1) {
    throw new Error("FEATURE_MANIFEST profiles block is missing");
  }
  const slice = src.slice(start);
  const end = slice.indexOf("\n  },");
  const profiles = {};
  for (const match of slice
    .slice(0, end)
    .matchAll(/"([^"]+)": "(active|unsupported|unverified)"/g)) {
    profiles[match[1]] = match[2];
  }
  return profiles;
}

export function checkAdvertisedProfiles({
  manifest,
  root,
} = {}) {
  const features = manifest ?? { profiles: readManifestProfiles(root) };
  const base = root ?? repoRoot;
  const errors = [];
  for (const [profile, status] of Object.entries(features.profiles)) {
    if (status !== "active") continue;
    const earned = EARNED_ACTIVE_PROFILES[profile];
    if (!earned) {
      errors.push(
        `profiles.${profile} is active without an earning-test row in scripts/agent-invariants.mjs; advertise only after the tests exist`,
      );
      continue;
    }
    for (const rel of earned.files) {
      const file = path.join(base, rel);
      if (!fs.existsSync(file)) {
        errors.push(
          `profiles.${profile} is active but ${rel} is missing; restore the earning test before advertising`,
        );
        continue;
      }
      if (!read(file).includes(earned.requiredText)) {
        errors.push(
          `profiles.${profile} is active but ${rel} no longer contains ${JSON.stringify(earned.requiredText)}; keep the earning assertion`,
        );
      }
    }
  }
  return errors;
}

export function checkSoftPassRejected({
  source,
  sourcePath,
} = {}) {
  const text =
    source ??
    read(
      sourcePath ??
        path.join(repoRoot, "host/src/adaptivesandbox-conformance.ts"),
    );
  const errors = [];
  if (
    !/export type QualificationStatus = "verified" \| "unverified" \| "unsupported";/.test(
      text,
    )
  ) {
    errors.push(
      "QualificationStatus must stay verified | unverified | unsupported so Soft-PASS cannot be written",
    );
  }
  if (/Soft-PASS|soft-pass|softPass/.test(text)) {
    errors.push(
      "adaptivesandbox-conformance.ts names Soft-PASS; that status does not exist",
    );
  }
  if (
    !/\[\s*"verified",\s*"unverified",\s*"unsupported"\s*\]\.includes\(String\(input\)\)/.test(
      text,
    )
  ) {
    errors.push(
      "qualificationStatus must reject unknown statuses including Soft-PASS",
    );
  }
  return errors;
}

export function checkQualifiedFlagStaysFalse({
  root,
} = {}) {
  const base = root ?? repoRoot;
  const errors = [];
  const files = [
    "scripts/package-fork-release.mjs",
    "host/src/adaptivesandbox-conformance.ts",
  ];
  for (const rel of files) {
    const text = read(path.join(base, rel));
    if (/adaptiveSandboxQualified\s*:\s*true/.test(text)) {
      errors.push(
        `${rel} sets adaptiveSandboxQualified: true; the fork stays false until an independent conformance run`,
      );
    }
  }
  return errors;
}

export function runAgentInvariants(options = {}) {
  return [
    ...checkVerifyEvidence(options),
    ...checkFeatureHeadings(options),
    ...checkSkillEvidenceNames(options),
    ...checkAdvertisedProfiles(options),
    ...checkSoftPassRejected(options),
    ...checkQualifiedFlagStaysFalse(options),
  ];
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const errors = runAgentInvariants();
  if (errors.length) {
    for (const error of errors) console.error(error);
    process.exit(1);
  }
  console.log("agent-invariants: ok");
}
