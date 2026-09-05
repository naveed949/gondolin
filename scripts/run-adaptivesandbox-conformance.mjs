#!/usr/bin/env node

import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  parseAdaptiveSandboxCompatibilityMatrix,
  parseAdaptiveSandboxConformancePin,
  parseAdaptiveSandboxQualificationReport,
  verifyAdaptiveSandboxBundle,
} from "../host/src/adaptivesandbox-conformance.ts";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const pinPath = path.join(
  root,
  "conformance",
  "adaptivesandbox-bundle.pin.json",
);
const matrixPath = path.join(root, "conformance", "compatibility-matrix.json");
const command = process.argv[2] ?? "check";

try {
  const pinInput = readJson(pinPath);
  const matrixInput = readJson(matrixPath);
  const pin = parseAdaptiveSandboxConformancePin(pinInput);
  const matrix = parseAdaptiveSandboxCompatibilityMatrix(matrixInput, pin);

  if (command === "check") {
    printState(pin, matrix);
  } else if (command === "qualify" || command === "qualify-if-pinned") {
    if (pin.status === "unavailable") {
      if (command === "qualify") {
        throw new Error(pin.reason);
      }
      printState(pin, matrix);
    } else {
      await qualify(pin, matrix);
    }
  } else {
    throw new Error(
      "usage: run-adaptivesandbox-conformance.mjs [check|qualify|qualify-if-pinned]",
    );
  }
} catch (error) {
  process.stderr.write(
    `${error instanceof Error ? error.message : "conformance check failed"}\n`,
  );
  process.exitCode = 1;
}

async function qualify(pin, matrix) {
  const response = await fetch(pin.artifact.url, { redirect: "follow" });
  if (!response.ok) {
    throw new Error(
      `failed to fetch pinned AdaptiveSandbox bundle: HTTP ${response.status}`,
    );
  }
  const bytes = new Uint8Array(await response.arrayBuffer());
  verifyAdaptiveSandboxBundle(bytes, pin);

  const temporary = fs.mkdtempSync(
    path.join(os.tmpdir(), "gondolin-adaptivesandbox-conformance-"),
  );
  try {
    const artifactPath = path.join(temporary, "bundle.mjs");
    const reportPath = path.join(temporary, "report.json");
    fs.writeFileSync(artifactPath, bytes, { mode: 0o500 });
    const sourceAdapter = path.join(
      root,
      "host",
      "bin",
      "adaptivesandbox-capability-adapter.ts",
    );
    const arguments_ = pin.execution.arguments.map((argument) => {
      if (argument === "{artifact}") return artifactPath;
      if (argument === "{adapter}") return sourceAdapter;
      if (argument === "{report}") return reportPath;
      return argument;
    });
    const exitCode = await run(process.execPath, arguments_);
    if (exitCode !== 0) {
      throw new Error(
        `pinned conformance bundle exited with status ${exitCode}`,
      );
    }
    const report = parseAdaptiveSandboxQualificationReport(
      readJson(reportPath),
      pin,
    );
    const row = matrix.rows.find(
      (candidate) =>
        stableJson(candidate.identity) === stableJson(report.identity),
    );
    if (!row) {
      throw new Error("qualification report has no exact compatibility row");
    }
    if (row.status !== report.status) {
      throw new Error(
        "qualification report status differs from the matrix row",
      );
    }
    if (stableJson(matrix.reports[row.report]) !== stableJson(report.summary)) {
      throw new Error(
        "qualification report summary differs from the matrix row",
      );
    }
    process.stdout.write(
      `${JSON.stringify({
        status: report.status,
        row: row.id,
        bundleVersion: pin.bundleVersion,
        bundleDigest: pin.artifact.sha256,
      })}\n`,
    );
  } finally {
    fs.rmSync(temporary, { recursive: true, force: true });
  }
}

function printState(pin, matrix) {
  const counts = { verified: 0, unverified: 0, unsupported: 0 };
  for (const row of matrix.rows) counts[row.status] += 1;
  process.stdout.write(
    `${JSON.stringify({
      pinStatus: pin.status,
      qualificationExecuted: false,
      rows: counts,
      reason: pin.status === "unavailable" ? pin.reason : undefined,
    })}\n`,
  );
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

async function run(executable, arguments_) {
  return await new Promise((resolve, reject) => {
    const child = spawn(executable, arguments_, {
      cwd: root,
      env: process.env,
      stdio: "inherit",
    });
    child.once("error", reject);
    child.once("exit", (code, signal) => {
      if (signal) reject(new Error(`bundle terminated by ${signal}`));
      else resolve(code ?? 1);
    });
  });
}

function stableJson(input) {
  if (input === null || typeof input !== "object") return JSON.stringify(input);
  if (Array.isArray(input)) return `[${input.map(stableJson).join(",")}]`;
  return `{${Object.keys(input)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableJson(input[key])}`)
    .join(",")}}`;
}
