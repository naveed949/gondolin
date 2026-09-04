#!/usr/bin/env node

import fs from "node:fs";
import readline from "node:readline";

import {
  CapabilityCredentialStore,
  CapabilityInvocationContext,
  ScopedRunnerInvocationContext,
  getCapabilityEvidenceVerifierIdentity,
  getCapabilityInvocationFeatureManifest,
  probeCapabilityInvocationTeardown,
  verifyControlledExecutionLink,
  verifyQualificationInvocation,
  type TrustedCapabilityCredential,
} from "../src/index.ts";

type AdapterRequest = {
  id: string;
  operation: "manifest" | "invoke" | "verify" | "controlled-link";
  principalId?: string;
  ceiling?: unknown;
  request?: unknown;
  result?: unknown;
  verification?: unknown;
  producerEvidence?: unknown;
  verifierEvidence?: unknown;
  principals?: unknown;
};

const credentialStore = loadCredentialStore();
const input = readline.createInterface({ input: process.stdin });

input.on("line", (line) => {
  void handleLine(line);
});

async function handleLine(line: string): Promise<void> {
  let id = "unknown";
  try {
    const request = JSON.parse(line) as AdapterRequest;
    id = requireString(request.id, "request id");
    const value = await dispatch(request);
    process.stdout.write(`${JSON.stringify({ id, ok: true, value })}\n`);
  } catch (error) {
    process.stdout.write(
      `${JSON.stringify({
        id,
        ok: false,
        error:
          error instanceof Error ? error.message : "adapter rejected request",
      })}\n`,
    );
  }
}

async function dispatch(request: AdapterRequest): Promise<unknown> {
  switch (request.operation) {
    case "manifest":
      return {
        protocol: "gondolin.adaptivesandbox-capability-adapter/v1",
        featureManifest: getCapabilityInvocationFeatureManifest(),
        verifier: getCapabilityEvidenceVerifierIdentity(),
      };
    case "invoke":
      return await invoke(request);
    case "verify": {
      const verification = requireObject(
        request.verification,
        "verification bindings",
      );
      verifyQualificationInvocation(request.result as never, {
        ...verification,
        producerPrincipal: requireString(
          verification.producerPrincipal,
          "producer principal",
        ),
        verifierPrincipal: requireString(
          verification.verifierPrincipal,
          "verifier principal",
        ),
        independent: requireObject(
          verification.independent,
          "independent checks",
        ) as never,
      });
      return { valid: true };
    }
    case "controlled-link":
      verifyControlledExecutionLink(
        requireObject(request.producerEvidence, "producer evidence") as never,
        requireObject(request.verifierEvidence, "verifier evidence") as never,
        requireObject(request.principals, "controlled principals") as never,
      );
      return { valid: true };
    default:
      throw new Error("unsupported adapter operation");
  }
}

async function invoke(request: AdapterRequest): Promise<unknown> {
  const principalId = requireString(request.principalId, "principal id");
  const ceiling = requireObject(request.ceiling, "capability ceiling");
  const invocation = requireObject(request.request, "capability request");
  const context =
    ceiling.profile === "scoped-runner"
      ? ScopedRunnerInvocationContext.create(ceiling)
      : CapabilityInvocationContext.create(ceiling, {
          credentialStore,
        });
  const result = await context.invoke(invocation);
  return {
    principalId,
    result,
    teardownProbe: probeCapabilityInvocationTeardown(
      result.evidence.executionId,
      {
        requestDigest: result.evidence.requestDigest,
        ceilingDigest: result.evidence.ceilingDigest,
        vmId: result.evidence.vmId,
      },
    ),
  };
}

function loadCredentialStore(): CapabilityCredentialStore | undefined {
  const configPath = process.env.GONDOLIN_CONFORMANCE_CREDENTIALS_FILE;
  if (!configPath) return undefined;
  const parsed = JSON.parse(fs.readFileSync(configPath, "utf8"));
  const credentials = requireObject(parsed, "trusted credential configuration");
  return CapabilityCredentialStore.create(
    credentials as Record<string, TrustedCapabilityCredential>,
  );
}

function requireObject(input: unknown, label: string): Record<string, unknown> {
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    throw new Error(`${label} must be an object`);
  }
  return input as Record<string, unknown>;
}

function requireString(input: unknown, label: string): string {
  if (typeof input !== "string" || input.length === 0) {
    throw new Error(`${label} must be a non-empty string`);
  }
  return input;
}
