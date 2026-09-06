import assert from "node:assert/strict";
import { test } from "node:test";
import net from "node:net";
import tls from "node:tls";
import dns from "node:dns";
import forge from "node-forge";
import { QemuNetworkBackend } from "../src/qemu/net.ts";
import { createHttpsDispatcher } from "../src/http/utils.ts";
import { buildConnector } from "undici";
import { guardHttpsConnector, assertDefaultHttpsTrust, type HttpsConnectorObservation } from "../src/http/https-connector.ts";

const destination = { hostname: "example.com", port: 443, protocol: "https" as const };
const options = { hostname: "example.com", port: "443", protocol: "https:" };
function fixture() {
  const controller = new AbortController();
  const peers: unknown[] = [];
  const failures: string[] = [];
  const candidates: unknown[] = [];
  const observer: HttpsConnectorObservation = {
    signal: controller.signal,
    connected: (record) => { peers.push(record); },
    resolutionCandidate: (record) => { candidates.push(record); },
    fail: (reason) => { failures.push(reason); },
  };
  let built!: buildConnector.BuildOptions;
  let complete!: buildConnector.Callback;
  let calls = 0;
  const connector = guardHttpsConnector(destination, observer, (config) => {
    built = config;
    return (_options, callback) => { calls++; complete = callback; };
  });
  return { controller, observer, connector, peers, failures, candidates,
    get built() { return built; }, get complete() { return complete; }, get calls() { return calls; } };
}
function peer(overrides: Record<string, unknown> = {}) {
  const socket = new tls.TLSSocket();
  for (const [key, value] of Object.entries({
    authorized: true, remoteAddress: "93.184.216.34", remotePort: 443,
    servername: "example.com", ...overrides,
  })) Object.defineProperty(socket, key, { value, configurable: true });
  socket.getPeerCertificate = () => ({ subjectaltname: "DNS:example.com" }) as tls.PeerCertificate;
  return socket;
}

test("connector observes an actual TLS socket before HTTP handoff and refuses reuse", () => {
  const f = fixture();
  let accepted = false;
  f.connector(options, (error, socket) => { assert.ifError(error); accepted = true; assert.equal(f.peers.length, 1); socket?.destroy(); });
  const socket = peer();
  f.complete(null, socket);
  assert.equal(accepted, true);
  assert.equal(f.built.rejectUnauthorized, true);
  assert.equal(f.built.maxCachedSessions, 0);
  assert.equal(f.built.allowH2, false);
  assert.equal(f.built.signal, f.controller.signal);
  f.connector(options, (error) => assert.match(error!.message, /denied/));
  assert.equal(f.calls, 1);
});

for (const [name, socketFactory] of [
  ["non-TLS", () => new net.Socket()],
  ["unauthorized", () => peer({ authorized: false })],
  ["private actual address", () => peer({ remoteAddress: "127.0.0.1" })],
  ["missing address", () => peer({ remoteAddress: undefined })],
  ["wrong port", () => peer({ remotePort: 8443 })],
  ["wrong servername", () => peer({ servername: "other.example" })],
  ["certificate hostname mismatch", () => { const p = peer(); p.getPeerCertificate = () => ({ subjectaltname: "DNS:wrong.example" }) as tls.PeerCertificate; return p; }],
] as const) test(`connector denies ${name} without successful observation`, () => {
  const f = fixture();
  let denied = false;
  f.connector(options, (error) => { assert.ok(error); denied = true; });
  const socket = socketFactory();
  f.complete(null, socket);
  assert.equal(denied, true);
  assert.equal(socket.destroyed, true);
  assert.equal(f.peers.length, 0);
});

test("abort settles once and destroys a late secureConnect socket", () => {
  const f = fixture();
  let callbacks = 0;
  f.connector(options, (error) => { assert.ok(error); callbacks++; });
  f.controller.abort();
  assert.equal(callbacks, 1);
  const socket = peer();
  f.complete(null, socket);
  assert.equal(socket.destroyed, true);
  assert.equal(callbacks, 1);
  assert.equal(f.peers.length, 0);
});

test("expired invocation opens no connector and late DNS never yields an address", (t) => {
  const f = fixture();
  let dnsComplete!: (error: NodeJS.ErrnoException | null, address: string, family: number) => void;
  t.mock.method(dns, "lookup", (_name: string, _options: unknown, callback: typeof dnsComplete) => { dnsComplete = callback; });
  let result: Error | null = null;
  f.built.lookup!("example.com", {}, (error) => { result = error; });
  f.controller.abort();
  dnsComplete(null, "93.184.216.34", 4);
  assert.ok(result);
  assert.equal(f.candidates.length, 0);
  f.connector(options, (error) => assert.ok(error));
  assert.equal(f.calls, 0);
});

test("DNS candidates are independently public checked before connector use", (t) => {
  const f = fixture();
  t.mock.method(dns, "lookup", (_name: string, _options: unknown, callback: (e: null, address: string, family: number) => void) => callback(null, "10.0.0.1", 4));
  f.built.lookup!("example.com", {}, (error) => assert.ok(error));
  assert.equal(f.candidates.length, 0);
});

test("private literal destination and supplied transport sockets deny before connect", () => {
  const f = fixture();
  const connector = guardHttpsConnector({ hostname: "127.0.0.1", port: 443, protocol: "https" }, f.observer, () => { return () => assert.fail("must not connect"); });
  connector({ ...options, hostname: "127.0.0.1" }, (error) => assert.ok(error));
  f.connector({ ...options, httpSocket: new net.Socket() }, (error) => assert.ok(error));
  assert.equal(f.calls, 0);
});

test("TLS trust environment overrides cannot enter the dedicated profile", () => {
  const previous = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
  try {
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
    assert.throws(assertDefaultHttpsTrust, /trust overrides/);
  } finally {
    if (previous === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    else process.env.NODE_TLS_REJECT_UNAUTHORIZED = previous;
  }
});


test("real TLS default verification rejects an untrusted local certificate", { timeout: 5000 }, async () => {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = "01";
  cert.validity.notBefore = new Date(Date.now() - 60000);
  cert.validity.notAfter = new Date(Date.now() + 60000);
  cert.setSubject([{ name: "commonName", value: "example.com" }]);
  cert.setIssuer(cert.subject.attributes);
  cert.setExtensions([{ name: "subjectAltName", altNames: [{ type: 2, value: "example.com" }] }]);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  const server = tls.createServer({ key: forge.pki.privateKeyToPem(keys.privateKey), cert: forge.pki.certificateToPem(cert) });
  server.on("tlsClientError", () => {});
  const sockets = new Set<net.Socket>();
  server.on("connection", (socket) => { sockets.add(socket); socket.once("close", () => sockets.delete(socket)); });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const f = fixture();
  // Local routing is a private construction seam, not admitted public-only authority.
  const connector = guardHttpsConnector(destination, f.observer, (config) => {
    const realConnector = buildConnector(config);
    return (opts, callback) => realConnector({ ...opts, hostname: "127.0.0.1", port: String((server.address() as net.AddressInfo).port) }, callback);
  });
  try {
    const error = await new Promise<Error | null>((resolve) => connector(options, (error, socket) => { socket?.destroy(); resolve(error); }));
    assert.match(error!.message, /self-signed certificate/);
    assert.equal(f.peers.length, 0);
    // Test-only CA confirms the actual Node client socket's hostname field; this
    // remains local transport mechanics, never public-only acceptance evidence.
    const observed = await new Promise<{ authorized: boolean; servername: string }>((resolve, reject) => {
      const socket = tls.connect({ host: "127.0.0.1", port: (server.address() as net.AddressInfo).port,
        servername: "example.com", ca: forge.pki.certificateToPem(cert), rejectUnauthorized: true }, () => {
        resolve({ authorized: socket.authorized, servername: socket.servername });
        socket.destroy();
      });
      socket.once("error", reject);
    });
    assert.deepEqual(observed, { authorized: true, servername: "example.com" });
  } finally {
    f.controller.abort();
    for (const socket of sockets) socket.destroy();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

test("fresh dispatcher rejects a second dispatch and participates in awaited close", async () => {
  const f = fixture();
  const backend = new QemuNetworkBackend({ socketPath: "/unused-https-connector.sock" });
  const trustKeys = ["NODE_TLS_REJECT_UNAUTHORIZED", "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "SSL_CERT_DIR", "NODE_USE_SYSTEM_CA", "NODE_OPTIONS"];
  const saved = trustKeys.map((key) => [key, process.env[key]] as const);
  let dispatcher;
  const savedArgv = process.execArgv;
  try {
    process.execArgv = [];
    for (const key of trustKeys) delete process.env[key];
    dispatcher = createHttpsDispatcher(backend, destination, f.observer);
  } finally {
    process.execArgv = savedArgv;
    for (const [key, value] of saved) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
  }
  // Malformed first dispatch fails locally; it still consumes the one-attempt budget.
  let firstError: Error | undefined;
  dispatcher.dispatch({ origin: "https://example.com", path: "bad-path", method: "GET" }, { onError: (error) => { firstError = error; } });
  assert.ok(firstError);
  let secondError: Error | undefined;
  dispatcher.dispatch({ origin: "https://example.com", path: "/", method: "GET" }, { onError: (error) => { secondError = error; } });
  assert.match(secondError!.message, /one upstream request/);
  assert.equal(backend.http.sharedDispatchers.size, 1);
  await backend.close();
  assert.equal(backend.http.sharedDispatchers.size, 0);
  assert.equal(dispatcher.destroyed, true);
});
