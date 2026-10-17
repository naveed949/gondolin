#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { parseAdaptiveSandboxCompatibilityMatrix } from "../host/src/adaptivesandbox-conformance.ts";
import { getCapabilityInvocationFeatureManifest } from "../host/src/capability-invocation.ts";

const here = path.dirname(fileURLToPath(import.meta.url));
export const repoRoot = path.resolve(here, "..");

export const FEATURE_HEADINGS = [
  "Sub-features",
  "How to get to it (user POV)",
  "Driving it with verify-gondolin",
  "Gotchas",
];

export const EXTRA_EVIDENCE_FILES = ["doctor.txt", "kvm-dmesg.txt"];

export const EARNED_ACTIVE_PROFILES = {
  "exact-reader": {
    files: ["host/test/capability-invocation.integration.test.ts"],
    requiredText:
      "public seam allows only the exact reader and settles after teardown",
  },
  "https-request": {
    files: ["host/test/https-invocation.integration.test.ts"],
    requiredText:
      "one-shot HTTPS VM public TLS GET/HEAD development evidence",
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

function defaultHelperPath() {
  return path.join(
    repoRoot,
    ".cursor/skills/verify-gondolin/helpers/drive-cli-exec.sh",
  );
}

export function helperWrittenEvidenceFiles(helperPath = defaultHelperPath()) {
  const names = new Set();
  for (const match of read(helperPath).matchAll(
    /\$EVIDENCE\/([A-Za-z0-9.-]+\.txt)/g,
  )) {
    names.add(match[1]);
  }
  return names;
}

export function evaluateDoctorProof(doctorText, version) {
  if (doctorText == null || doctorText === "") {
    return {
      ok: false,
      reason: "missing-doctor",
      detail:
        "doctor.txt is missing; tee doctor.sh into this directory before treating the run as proof",
    };
  }
  if (!/^status=ready$/m.test(doctorText)) {
    return {
      ok: false,
      reason: "doctor-not-ready",
      detail: "doctor.txt status is not ready; refuse this tree as current proof",
    };
  }
  const match = doctorText.match(/^package_version=(.*)$/m);
  if (!match) {
    return {
      ok: false,
      reason: "missing-doctor",
      detail: "doctor.txt has no package_version line; refuse this tree as current proof",
    };
  }
  if (match[1] !== version) {
    return {
      ok: false,
      reason: "stale-package-version",
      detail: `doctor.txt package_version=${match[1]} does not match host/package.json ${version}; a leftover ok tree is not proof for this checkout`,
    };
  }
  return { ok: true, reason: null, detail: null };
}

function hasEarningTest(fileText, title) {
  const escaped = title.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  if (
    new RegExp(String.raw`(?:test|vmTest)\(\s*["\`]${escaped}["\`]`).test(
      fileText,
    )
  ) {
    return true;
  }
  const literal =
    fileText.includes(`"${title}"`) || fileText.includes(`\`${title}\``);
  return literal && /(?:test|vmTest)\(\s*name\b/.test(fileText);
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
    const doctor = fs.existsSync(doctorPath) ? read(doctorPath) : "";
    const proof = evaluateDoctorProof(doctor, version);
    if (!proof.ok) errors.push(`${rel}: ${proof.detail}`);
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
  helperPath,
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
  const allowed = new Set([
    ...helperWrittenEvidenceFiles(helperPath),
    ...EXTRA_EVIDENCE_FILES,
  ]);
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

export function checkAdvertisedProfiles({
  manifest,
  root,
} = {}) {
  const profiles =
    manifest?.profiles ?? getCapabilityInvocationFeatureManifest().profiles;
  if (!profiles || Object.keys(profiles).length === 0) {
    return [
      "feature manifest profiles is empty; refuse advertise checks until getCapabilityInvocationFeatureManifest() returns profiles",
    ];
  }
  const base = root ?? repoRoot;
  const errors = [];
  for (const [profile, status] of Object.entries(profiles)) {
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
      if (!hasEarningTest(read(file), earned.requiredText)) {
        errors.push(
          `profiles.${profile} is active but ${rel} no longer has a test or vmTest named ${JSON.stringify(earned.requiredText)}; keep the earning assertion`,
        );
      }
    }
  }
  return errors;
}

export function checkSoftPassRejected({
  pin,
  matrix,
} = {}) {
  const pinInput =
    pin ??
    JSON.parse(
      read(path.join(repoRoot, "conformance/adaptivesandbox-bundle.pin.json")),
    );
  const claimed = structuredClone(
    matrix ??
      JSON.parse(
        read(path.join(repoRoot, "conformance/compatibility-matrix.json")),
      ),
  );
  claimed.rows[0].status = "Soft-PASS";
  try {
    parseAdaptiveSandboxCompatibilityMatrix(claimed, pinInput);
    return [
      "compatibility matrix accepted status Soft-PASS; qualificationStatus must reject it",
    ];
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (!/unknown/.test(message)) {
      return [
        `Soft-PASS must fail as an unknown qualification status, not: ${message}`,
      ];
    }
    return [];
  }
}

export function runAgentInvariants(options = {}) {
  return [
    ...checkVerifyEvidence(options),
    ...checkFeatureHeadings(options),
    ...checkSkillEvidenceNames(options),
    ...checkAdvertisedProfiles(options),
    ...checkSoftPassRejected(options),
  ];
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  if (process.argv[2] === "doctor-proof") {
    const doctorPath = process.argv[3];
    const doctor = doctorPath && fs.existsSync(doctorPath) ? read(doctorPath) : "";
    const proof = evaluateDoctorProof(doctor, packageVersion());
    if (!proof.ok) {
      process.stdout.write(`${proof.reason}\n`);
      process.exit(1);
    }
    process.exit(0);
  }
  const errors = runAgentInvariants();
  if (errors.length) {
    for (const error of errors) console.error(error);
    process.exit(1);
  }
  console.log("agent-invariants: ok");
}
