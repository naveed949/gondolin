import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  HttpsInvocationContext,
  verifyHttpsInvocationResult,
} from "../../src/https-invocation.ts";
import { isPublicAddress } from "../../src/public-address.ts";
import {
  getCapabilityEvidenceVerifierIdentity,
  probeCapabilityInvocationTeardown,
} from "../../src/invocation-evidence.ts";
import { shouldSkipVmTests } from "./vm-fixture.ts";

// Public third-party development traffic; not controlled external qualification.
// CI must run this gate: missing acceleration, curl, network or valid TLS fails it.

function input(
  method: "GET" | "HEAD",
  maxResponseBytes = 65536,
  timeoutMs = 15000,
) {
  const authority = {
    protocol: "https",
    host: "example.com",
    port: 443,
    methods: [method],
    resolution: "public-only",
    redirects: "none",
    maxResponseBytes,
    timeoutMs,
  };
  return {
    ceiling: {
      schemaVersion: "gondolin.https-ceiling/v1",
      network: { https: [authority] },
      limits: { maxOutputBytes: 8192, maxWallTimeMs: 30000 },
    },
    request: {
      schemaVersion: "gondolin.https-request/v1",
      invocationId: `https-${method}-${maxResponseBytes}-${timeoutMs}`,
      request: { url: "https://example.com/", method },
      authority,
      limits: { outputBytes: 8192, wallTimeMs: 30000 },
    },
  };
}

async function success() {
  assert.equal(
    shouldSkipVmTests(),
    false,
    "required HTTPS CI gate needs hardware acceleration",
  );
  const verifier = getCapabilityEvidenceVerifierIdentity();
  const vmIds = new Set<string>();
  for (const method of ["GET", "HEAD"] as const) {
    const config = input(method),
      context = HttpsInvocationContext.create(config.ceiling);
    const result = await context.execute(config.request);
    assert.equal(result.outcome, "success", JSON.stringify(result));
    assert.equal(result.response?.status, 200);
    assert.equal(result.evidence.network.connection?.tlsVerified, true);
    assert.equal(
      result.evidence.network.connection?.tlsHostname,
      "example.com",
    );
    assert.equal(result.evidence.filesystem, "none");
    assert.equal(result.evidence.credentials, "none");
    assert.equal(result.evidence.teardown.networkChannelsClosed, true);
    assert.ok(!vmIds.has(result.evidence.vmId));
    vmIds.add(result.evidence.vmId);
    if (method === "GET")
      assert.match(
        Buffer.from(result.response!.bodyBase64, "base64").toString(),
        /Example Domain/,
      );
    else assert.equal(result.response!.bodyBytes, 0);
    const expected = {
      ...verifier,
      requestDigest: result.evidence.requestDigest,
      ceilingDigest: context.ceilingDigest,
      runtime: result.evidence.runtime,
      qualificationId: result.evidence.qualificationId,
    };
    assert.deepEqual(verifyHttpsInvocationResult(result, expected).errors, []);
    assert.equal(
      probeCapabilityInvocationTeardown(result.evidence.executionId, expected)
        .teardownVerified,
      true,
    );
    // Persisted data verification has no context or network dependency.
    assert.equal(
      verifyHttpsInvocationResult(JSON.parse(JSON.stringify(result)), expected)
        .valid,
      true,
    );
    await assert.rejects(context.execute(config.request), /single use/);
  }
}

function testRuntime(): {
  accel?: string;
  cpu?: string;
  memory?: string;
} {
  const runtime: { accel?: string; cpu?: string; memory?: string } = {};
  if (process.env.GONDOLIN_TEST_ACCEL)
    runtime.accel = process.env.GONDOLIN_TEST_ACCEL;
  if (process.env.GONDOLIN_TEST_CPU) runtime.cpu = process.env.GONDOLIN_TEST_CPU;
  if (process.env.GONDOLIN_TEST_MEMORY)
    runtime.memory = process.env.GONDOLIN_TEST_MEMORY;
  return runtime;
}

function spec(host: string, method: "GET" | "HEAD") {
  const authority = {
    protocol: "https",
    host,
    port: 443,
    methods: [method],
    resolution: "public-only",
    redirects: "none",
    maxResponseBytes: 65536,
    timeoutMs: 20000,
  };
  return {
    ceiling: {
      schemaVersion: "gondolin.https-ceiling/v1",
      network: { https: [authority] },
      limits: { maxOutputBytes: 8192, maxWallTimeMs: 60000 },
    },
    request: {
      schemaVersion: "gondolin.https-request/v1",
      invocationId: `https-concurrent-${host}-${method}`,
      request: { url: `https://${host}/`, method },
      authority,
      limits: { outputBytes: 8192, wallTimeMs: 60000 },
    },
  };
}

/** Little-endian `/proc/net/tcp` address words as an IP string */
function parseProcAddress(hex: string): string | null {
  if (hex.length === 8) {
    const value = Number.parseInt(hex, 16);
    return [
      value & 255,
      (value >> 8) & 255,
      (value >> 16) & 255,
      (value >> 24) & 255,
    ].join(".");
  }
  if (hex.length !== 32) return null;
  const groups: string[] = [];
  for (let index = 0; index < 32; index += 8) {
    const word = hex.slice(index, index + 8);
    groups.push(
      word.slice(6, 8),
      word.slice(4, 6),
      word.slice(2, 4),
      word.slice(0, 2),
    );
  }
  const hextets: string[] = [];
  for (let index = 0; index < groups.length; index += 2) {
    hextets.push(`${groups[index]}${groups[index + 1]}`);
  }
  return hextets.map((part) => part.replace(/^0+/, "") || "0").join(":");
}

function parseIpv4(address: string): Buffer | null {
  const parts = address.split(".");
  if (parts.length !== 4) return null;
  const bytes = Buffer.alloc(4);
  for (let index = 0; index < 4; index += 1) {
    const value = Number(parts[index]);
    if (!Number.isInteger(value) || value < 0 || value > 255) return null;
    bytes[index] = value;
  }
  return bytes;
}

function parseIpv6(address: string): Buffer | null {
  const bare = address.split("%")[0] ?? "";
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(bare);
  if (mapped) {
    const v4 = parseIpv4(mapped[1]!);
    if (!v4) return null;
    const bytes = Buffer.alloc(16);
    bytes[10] = 0xff;
    bytes[11] = 0xff;
    v4.copy(bytes, 12);
    return bytes;
  }
  const halves = bare.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 ? (halves[1] ? halves[1].split(":") : []) : [];
  if (halves.length === 1 && head.length !== 8) return null;
  const missing = 8 - head.length - tail.length;
  if (missing < 0) return null;
  const padding = Array.from({ length: missing }, () => "0");
  const groups = [...head, ...padding, ...tail];
  if (groups.length !== 8) return null;
  const bytes = Buffer.alloc(16);
  for (let index = 0; index < 8; index += 1) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(groups[index]!)) return null;
    const value = Number.parseInt(groups[index]!, 16);
    bytes[index * 2] = value >> 8;
    bytes[index * 2 + 1] = value & 255;
  }
  return bytes;
}

function addressBytes(address: string): Buffer | null {
  if (net.isIP(address) === 4) return parseIpv4(address);
  if (net.isIP(address) === 6) return parseIpv6(address);
  return null;
}

function sameAddress(left: string, right: string): boolean {
  if (left === right) return true;
  const a = addressBytes(left);
  const b = addressBytes(right);
  if (!a || !b) return false;
  if (a.equals(b)) return true;
  const mapped = (wide: Buffer, narrow: Buffer) =>
    wide.length === 16 &&
    narrow.length === 4 &&
    wide.subarray(0, 10).equals(Buffer.alloc(10)) &&
    wide[10] === 0xff &&
    wide[11] === 0xff &&
    wide.subarray(12).equals(narrow);
  return mapped(a, b) || mapped(b, a);
}

type HostSocket = {
  /** kernel socket inode */
  inode: string;
  /** remote IP parsed from `/proc/net/tcp` */
  remote: string;
  /** remote TCP port */
  port: number;
};

function readSocketTable(): HostSocket[] {
  const rows: HostSocket[] = [];
  for (const file of ["/proc/net/tcp", "/proc/net/tcp6"]) {
    let text = "";
    try {
      text = fs.readFileSync(file, "utf8");
    } catch {
      continue;
    }
    for (const line of text.split("\n").slice(1)) {
      const parts = line.trim().split(/\s+/);
      // 0A is LISTEN. Every other state can be the outbound flow.
      if (parts.length < 10 || parts[3] === "0A") continue;
      const [address, portHex] = parts[2]!.split(":");
      if (!address || !portHex || !parts[9]) continue;
      const remote = parseProcAddress(address);
      const port = Number.parseInt(portHex, 16);
      if (!remote || !Number.isInteger(port)) continue;
      rows.push({ inode: parts[9], remote, port });
    }
  }
  return rows;
}

function processSocketInodes(pid: number): Set<string> {
  const inodes = new Set<string>();
  let fds: string[] = [];
  try {
    fds = fs.readdirSync(`/proc/${pid}/fd`);
  } catch {
    return inodes;
  }
  for (const fd of fds) {
    try {
      const target = fs.readlinkSync(`/proc/${pid}/fd/${fd}`);
      const match = /^socket:\[(\d+)\]$/.exec(target);
      if (match?.[1]) inodes.add(match[1]);
    } catch {
      // descriptor closed between readdir and readlink
    }
  }
  return inodes;
}

function parentPid(pid: number): number | null {
  try {
    const match = /^PPid:\s+(\d+)/m.exec(
      fs.readFileSync(`/proc/${pid}/status`, "utf8"),
    );
    return match ? Number(match[1]) : null;
  } catch {
    return null;
  }
}

/** QEMU processes descended from the HTTPS helper, ignoring sibling tests */
function descendantQemuCount(ancestorPid: number): number {
  let count = 0;
  for (const entry of fs.readdirSync("/proc")) {
    if (!/^\d+$/.test(entry)) continue;
    const pid = Number(entry);
    try {
      if (!fs.readFileSync(`/proc/${pid}/comm`, "utf8").startsWith("qemu"))
        continue;
    } catch {
      continue;
    }
    let current: number | null = pid;
    for (let depth = 0; depth < 6 && current !== null; depth += 1) {
      current = parentPid(current);
      if (current === ancestorPid) {
        count += 1;
        break;
      }
    }
  }
  return count;
}

type ObservedSocket = HostSocket & {
  /** first sighting unix time in `ms` */
  first: number;
  /** last sighting unix time in `ms` */
  last: number;
};

/** Independent host socket table for one helper process. Not invocation evidence. */
function observeSockets(logPath: string, ancestorPid: number): void {
  let qemuPeak = 0;
  const sockets = new Map<string, ObservedSocket>();
  const scan = () => {
    qemuPeak = Math.max(qemuPeak, descendantQemuCount(ancestorPid));
    const owned = processSocketInodes(ancestorPid);
    const now = Date.now();
    for (const row of readSocketTable()) {
      if (row.port !== 443 || !owned.has(row.inode)) continue;
      const current = sockets.get(row.inode) ?? { ...row, first: now, last: now };
      current.last = now;
      sockets.set(row.inode, current);
    }
  };
  scan();
  fs.writeFileSync(`${logPath}.ready`, `${Date.now()}\n`);
  const timer = setInterval(scan, 5);
  const finish = () => {
    clearInterval(timer);
    scan();
    fs.writeFileSync(
      logPath,
      `${JSON.stringify({ qemuPeak, sockets: [...sockets.values()] })}\n`,
    );
    process.exit(0);
  };
  process.on("SIGTERM", finish);
}

async function concurrent() {
  assert.equal(
    shouldSkipVmTests(),
    false,
    "required HTTPS CI gate needs hardware acceleration",
  );
  assert.equal(
    fs.existsSync("/proc/net/tcp"),
    true,
    "concurrent HTTPS proof reads the host socket table",
  );
  const directory = fs.mkdtempSync(
    path.join(os.tmpdir(), "gondolin-https-concurrent-"),
  );
  const logPath = path.join(directory, "sockets.json");
  const readyPath = `${logPath}.ready`;
  const stderrPath = path.join(directory, "observer.err");
  const stderrFd = fs.openSync(stderrPath, "w");
  const observer = spawn(
    process.execPath,
    [
      ...process.execArgv,
      fileURLToPath(import.meta.url),
      "observe",
      logPath,
      String(process.pid),
    ],
    { stdio: ["ignore", "ignore", stderrFd] },
  );
  let observerExited = false;
  observer.once("exit", () => {
    observerExited = true;
  });
  const runtime = testRuntime();
  const jobs = [
    { host: "example.com", method: "GET" as const },
    { host: "example.org", method: "HEAD" as const },
  ];
  let started = 0;
  let results: Array<{
    host: string;
    method: "GET" | "HEAD";
    ms: number;
    result: Awaited<ReturnType<HttpsInvocationContext["execute"]>>;
    ceilingDigest: string;
  }>;
  try {
    const readyDeadline = Date.now() + 5000;
    while (!fs.existsSync(readyPath)) {
      if (observerExited || Date.now() > readyDeadline) {
        throw new Error(
          `socket observer did not start: ${fs.readFileSync(stderrPath, "utf8")}`,
        );
      }
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    started = Date.now();
    results = await Promise.all(
      jobs.map(async (job) => {
        const config = spec(job.host, job.method);
        const context = HttpsInvocationContext.create(config.ceiling, runtime);
        const began = Date.now();
        const result = await context.execute(config.request);
        return {
          ...job,
          ms: Date.now() - began,
          result,
          ceilingDigest: context.ceilingDigest,
        };
      }),
    );
  } finally {
    if (!observerExited) observer.kill("SIGTERM");
    await new Promise<void>((resolve) => {
      if (observer.exitCode !== null || observer.signalCode !== null) resolve();
      else observer.once("exit", () => resolve());
    });
    fs.closeSync(stderrFd);
  }
  const wallMs = Date.now() - started;
  const observation = JSON.parse(fs.readFileSync(logPath, "utf8")) as {
    qemuPeak: number;
    sockets: ObservedSocket[];
  };
  assert.ok(
    observation.qemuPeak >= 2,
    `overlapping sessions need two descendant QEMU processes: ${JSON.stringify(observation)}`,
  );
  assert.ok(
    wallMs + 1000 < results[0]!.ms + results[1]!.ms,
    `sessions did not overlap wall=${wallMs} durations=${results.map((item) => item.ms).join(",")}`,
  );
  const peers = new Set<string>();
  const vmIds = new Set<string>();
  const inodes = new Set<string>();
  for (const item of results) {
    assert.equal(item.result.outcome, "success", JSON.stringify(item.result));
    assert.equal(item.result.evidence.filesystem, "none");
    assert.equal(item.result.evidence.credentials, "none");
    assert.equal(item.result.evidence.network.connection?.tlsVerified, true);
    assert.equal(
      item.result.evidence.network.connection?.tlsHostname,
      item.host,
    );
    assert.equal(item.result.evidence.network.connection?.peerPort, 443);
    const peer = item.result.evidence.network.connection?.peerAddress;
    assert.equal(typeof peer, "string");
    assert.equal(isPublicAddress(peer!), true, peer);
    const owned = observation.sockets.filter(
      (row) => row.port === 443 && sameAddress(row.remote, peer!),
    );
    assert.ok(
      owned.length > 0,
      `no host socket for ${item.host} peer ${peer}: ${JSON.stringify(observation)}`,
    );
    for (const row of owned) inodes.add(row.inode);
    peers.add(peer!);
    vmIds.add(item.result.evidence.vmId);
    const verifier = getCapabilityEvidenceVerifierIdentity();
    const expected = {
      ...verifier,
      requestDigest: item.result.evidence.requestDigest,
      ceilingDigest: item.ceilingDigest,
      runtime: item.result.evidence.runtime,
      qualificationId: item.result.evidence.qualificationId,
    };
    assert.deepEqual(
      verifyHttpsInvocationResult(item.result, expected).errors,
      [],
    );
  }
  assert.equal(peers.size, 2);
  assert.equal(vmIds.size, 2);
  assert.equal(inodes.size, 2);
}

async function bounds() {
  assert.equal(
    shouldSkipVmTests(),
    false,
    "required HTTPS CI gate needs hardware acceleration",
  );
  for (const [bytes, timeout] of [
    [1, 15000],
    [65536, 1],
  ]) {
    const config = input("GET", bytes, timeout),
      context = HttpsInvocationContext.create(config.ceiling);
    const result = await context.execute(config.request);
    assert.notEqual(result.outcome, "success", JSON.stringify(result));
    assert.equal(result.response, null);
    assert.equal(
      result.evidence.network.settlement,
      bytes === 1 ? "overflow" : "timeout",
      JSON.stringify(result),
    );
    assert.equal(result.evidence.teardown.networkChannelsClosed, true);
  }
}

// Plain child process: no inherited test-worker execArgv and no trust-policy bypass.
const mode = process.argv[2];
if (mode === "observe") {
  const logPath = process.argv[3];
  const ancestorPid = Number(process.argv[4]);
  assert.equal(typeof logPath, "string");
  assert.equal(Number.isInteger(ancestorPid) && ancestorPid > 1, true);
  observeSockets(logPath, ancestorPid);
} else {
  assert.equal(
    process.argv.length,
    3,
    "HTTPS VM helper requires exactly one mode",
  );
  assert.ok(
    mode === "success" || mode === "bounds" || mode === "concurrent",
    "unknown HTTPS VM helper mode",
  );
  await (mode === "success"
    ? success()
    : mode === "bounds"
      ? bounds()
      : concurrent());
  process.stdout.write(`HTTPS VM ${mode}: PASS\n`);
}
