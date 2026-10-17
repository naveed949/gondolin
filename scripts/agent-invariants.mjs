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

export const EXTRA_EVIDENCE_FILES = ["doctor.txt", "kvm-dmesg.txt"];

export const DOCTOR_FAIL_REASONS = [
  "missing-doctor",
  "doctor-not-ready",
  "missing-package-version",
  "stale-package-version",
];

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

const EVIDENCE_NAME = /\b[A-Za-z0-9][A-Za-z0-9._-]*\.txt\b/g;

export function helperWrittenEvidenceFiles(helperPath = defaultHelperPath()) {
  const names = new Set();
  for (const match of read(helperPath).matchAll(
    /(?:>>?|2>>?)\s*"?\$EVIDENCE\/([A-Za-z0-9._-]+\.txt)/g,
  )) {
    names.add(match[1]);
  }
  return names;
}

function lastAssignment(text, key) {
  let last;
  const pattern = new RegExp(`^${key}=(.*)$`, "gm");
  for (const match of text.matchAll(pattern)) last = match[1];
  return last;
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
  const status = lastAssignment(doctorText, "status");
  if (status !== "ready") {
    return {
      ok: false,
      reason: "doctor-not-ready",
      detail: "doctor.txt status is not ready; refuse this tree as current proof",
    };
  }
  const recorded = lastAssignment(doctorText, "package_version");
  if (recorded == null) {
    return {
      ok: false,
      reason: "missing-package-version",
      detail:
        "doctor.txt has no package_version line; refuse this tree as current proof",
    };
  }
  if (recorded !== version) {
    return {
      ok: false,
      reason: "stale-package-version",
      detail: `doctor.txt package_version=${recorded} does not match host/package.json ${version}; a leftover ok tree is not proof for this checkout`,
    };
  }
  return { ok: true, reason: null, detail: null };
}

export function classifyDoctorProofFailure(stdout) {
  const reason = String(stdout ?? "").trim();
  if (DOCTOR_FAIL_REASONS.includes(reason)) return reason;
  return "doctor-proof-failed";
}

function isIdentChar(ch) {
  return /[A-Za-z0-9_$]/.test(ch);
}

function earningTestCalls(source) {
  const calls = [];
  let i = 0;
  let state = "code";
  while (i < source.length) {
    const c = source[i];
    const n = source[i + 1];
    if (state === "line") {
      if (c === "\n") state = "code";
      i += 1;
      continue;
    }
    if (state === "block") {
      if (c === "*" && n === "/") {
        state = "code";
        i += 2;
        continue;
      }
      i += 1;
      continue;
    }
    if (state === "sq" || state === "dq" || state === "bt") {
      if (c === "\\") {
        i += 2;
        continue;
      }
      if (
        (state === "sq" && c === "'") ||
        (state === "dq" && c === '"') ||
        (state === "bt" && c === "`")
      ) {
        state = "code";
      }
      i += 1;
      continue;
    }
    if (c === "/" && n === "/") {
      state = "line";
      i += 2;
      continue;
    }
    if (c === "/" && n === "*") {
      state = "block";
      i += 2;
      continue;
    }
    if (c === "/" && n !== "*" && n !== "/") {
      let prev = i - 1;
      while (prev >= 0 && /\s/.test(source[prev])) prev -= 1;
      const before = prev < 0 ? "" : source[prev];
      if (prev < 0 || "(=:,[!&|?{};".includes(before)) {
        i += 1;
        while (i < source.length) {
          if (source[i] === "\\") {
            i += 2;
            continue;
          }
          if (source[i] === "[") {
            i += 1;
            while (i < source.length && source[i] !== "]") {
              if (source[i] === "\\") i += 2;
              else i += 1;
            }
            i += 1;
            continue;
          }
          if (source[i] === "/") {
            i += 1;
            while (/[gimsuy]/.test(source[i])) i += 1;
            break;
          }
          i += 1;
        }
        continue;
      }
    }
    if (c === "'") {
      state = "sq";
      i += 1;
      continue;
    }
    if (c === '"') {
      state = "dq";
      i += 1;
      continue;
    }
    if (c === "`") {
      state = "bt";
      i += 1;
      continue;
    }
    const kind = source.startsWith("vmTest", i)
      ? "vmTest"
      : source.startsWith("test", i)
        ? "test"
        : null;
    if (
      kind &&
      (i === 0 || !isIdentChar(source[i - 1])) &&
      !isIdentChar(source[i + kind.length])
    ) {
      i += kind.length;
      while (/\s/.test(source[i])) i += 1;
      if (source[i] !== "(") continue;
      i += 1;
      while (/\s/.test(source[i])) i += 1;
      const q = source[i];
      if (q !== '"' && q !== "'" && q !== "`") continue;
      i += 1;
      let title = "";
      while (i < source.length && source[i] !== q) {
        if (source[i] === "\\") {
          title += source[i + 1] ?? "";
          i += 2;
          continue;
        }
        title += source[i];
        i += 1;
      }
      i += 1;
      calls.push({
        title,
        skipTrue: optionsSkipLiteral(source.slice(i, i + 240)),
      });
      continue;
    }
    i += 1;
  }
  return calls;
}

function optionsSkipLiteral(after) {
  const comma = after.search(/\S/);
  if (comma === -1 || after[comma] !== ",") return false;
  let rest = after.slice(comma + 1);
  rest = rest.replace(/^\s*/, "");
  if (!rest.startsWith("{")) return false;
  const close = rest.indexOf("}");
  if (close === -1) return false;
  const body = rest.slice(1, close);
  if (/\bskip\s*:\s*false\b/.test(body)) return false;
  if (/\bskip\s*:\s*true\b/.test(body)) return true;
  return /\bskip\s*:\s*(["'`]|[\d])/.test(body);
}

function hasEarningTest(fileText, title) {
  return earningTestCalls(fileText).some(
    (call) => call.title === title && !call.skipTrue,
  );
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
  const section = stripFences(end === -1 ? rest : rest.slice(0, end));
  const allowed = evidenceAllowlist(helperPath);
  const errors = [];
  for (const name of section.match(EVIDENCE_NAME) ?? []) {
    if (!allowed.has(name)) {
      errors.push(
        `SKILL.md Evidence names ${name}; drive-cli-exec.sh does not write that file. Drop the invented rule or add the file to the helper first`,
      );
    }
  }
  return errors;
}

function stripFences(text) {
  return text.replace(/```[\s\S]*?```/g, "");
}

function evidenceAllowlist(helperPath) {
  return new Set([
    ...helperWrittenEvidenceFiles(helperPath),
    ...EXTRA_EVIDENCE_FILES,
  ]);
}

export function checkFeatureEvidenceNames({
  featuresDir,
  helperPath,
} = {}) {
  const dir =
    featuresDir ??
    path.join(repoRoot, ".cursor/skills/verify-gondolin/features");
  const allowed = evidenceAllowlist(helperPath);
  const errors = [];
  for (const name of fs.readdirSync(dir).sort()) {
    if (!name.endsWith(".md") || name === "README.md") continue;
    for (const line of read(path.join(dir, name)).split("\n")) {
      if (!/\*\*Proof\.\*\*/.test(line)) continue;
      for (const file of line.match(EVIDENCE_NAME) ?? []) {
        if (!allowed.has(file)) {
          errors.push(
            `${name}: Proof names ${file}; drive-cli-exec.sh does not write that file`,
          );
        }
      }
    }
  }
  return errors;
}

export async function checkAdvertisedProfiles({
  manifest,
  root,
} = {}) {
  let profiles = manifest?.profiles;
  if (!profiles) {
    const { getCapabilityInvocationFeatureManifest } = await import(
      "../host/src/capability-invocation.ts"
    );
    profiles = getCapabilityInvocationFeatureManifest().profiles;
  }
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

export async function checkSoftPassRejected({
  pin,
  matrix,
} = {}) {
  const { parseAdaptiveSandboxCompatibilityMatrix } = await import(
    "../host/src/adaptivesandbox-conformance.ts"
  );
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
    if (!/status is unknown/.test(message)) {
      return [
        `Soft-PASS must fail as an unknown qualification status, not: ${message}`,
      ];
    }
    return [];
  }
}

export async function runAgentInvariants(options = {}) {
  return [
    ...checkVerifyEvidence(options),
    ...checkFeatureHeadings(options),
    ...checkSkillEvidenceNames(options),
    ...checkFeatureEvidenceNames(options),
    ...(await checkAdvertisedProfiles(options)),
    ...(await checkSoftPassRejected(options)),
  ];
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  if (process.argv[2] === "doctor-proof") {
    try {
      const doctorPath = process.argv[3];
      const doctor =
        doctorPath && fs.existsSync(doctorPath) ? read(doctorPath) : "";
      const proof = evaluateDoctorProof(doctor, packageVersion());
      if (!proof.ok) {
        process.stdout.write(`${proof.reason}\n`);
        process.exit(1);
      }
      process.exit(0);
    } catch {
      process.stdout.write("doctor-proof-failed\n");
      process.exit(1);
    }
  }
  const errors = await runAgentInvariants();
  if (errors.length) {
    for (const error of errors) console.error(error);
    process.exit(1);
  }
  console.log("agent-invariants: ok");
}
