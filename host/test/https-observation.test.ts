import assert from "node:assert/strict";
import http from "node:http";
import type net from "node:net";
import { gzipSync } from "node:zlib";
import { createHash } from "node:crypto";
import test from "node:test";
import { fetch } from "undici";
import { HttpsObservation } from "../src/http/https-observation.ts";
import { consumeObservedHttpsBody, fetchHookRequestAndRespond, type HttpSession } from "../src/qemu/http.ts";
import { HttpReceiveBuffer } from "../src/http/utils.ts";
import { QemuNetworkBackend } from "../src/qemu/net.ts";

function observation(maxResponseBytes = 8, timeoutMs = 1000, method: "GET" | "HEAD" = "GET") {
  const state = new HttpsObservation({ url: "https://example.com/", method, maxResponseBytes, timeoutMs });
  state.begin(state.policy.url, method, false);
  return state;
}
function peer(state: HttpsObservation) {
  state.connected({ connectionId: "test-connection", peerAddress: "93.184.216.34", peerPort: 443, tlsHostname: "example.com", tlsVerified: true });
}
async function server(t: test.TestContext, handler: http.RequestListener) {
  const origin = http.createServer(handler);
  await new Promise<void>(resolve => origin.listen(0, "127.0.0.1", resolve));
  t.after(async () => {
    origin.closeAllConnections();
    await new Promise<void>(resolve => origin.close(() => resolve()));
  });
  return `http://127.0.0.1:${(origin.address() as net.AddressInfo).port}/`;
}

// Local HTTP fixtures verify decoded streaming mechanics only, not public TLS admission.
for (const compressed of [false, true]) {
  for (const overflow of [false, true]) {
    test(`decoded ${compressed ? "gzip" : "chunked"} body ${overflow ? "overflow" : "exact limit"}`, async t => {
      const bytes = Buffer.from(overflow ? [0, 255, 128, 1, 2, 3, 4, 5, 6] : [0, 255, 128, 1, 2, 3, 4, 5]);
      const url = await server(t, (_req, res) => {
        if (compressed) { res.setHeader("content-encoding", "gzip"); res.end(gzipSync(bytes)); }
        else { res.write(bytes.subarray(0, 3)); res.end(bytes.subarray(3)); }
      });
      const state = observation();
      t.after(() => state.finish());
      const response = await fetch(url, { signal: state.signal });
      if (overflow) {
        await assert.rejects(consumeObservedHttpsBody(response, state, state.signal), /exceeds/);
        assert.equal(state.snapshot().settlement, "overflow");
        assert.equal(state.snapshot().response, null);
      } else {
        const body = await consumeObservedHttpsBody(response, state, state.signal);
        peer(state);
        state.complete(response.status, body);
        const snapshot = state.snapshot();
        assert.deepEqual(Buffer.from(snapshot.response!.bodyBase64, "base64"), bytes);
        assert.equal(snapshot.response!.bodyDigest, `sha256:${createHash("sha256").update(bytes).digest("hex")}`);
        assert.ok(Object.isFrozen(snapshot.response));
        assert.ok(Object.isFrozen(snapshot.connection));
      }
    });
  }
}

test("HEAD metadata is an empty entity despite compressed Content-Length", async t => {
  const url = await server(t, (_req, res) => {
    res.writeHead(200, { "content-length": "9999999", "content-encoding": "gzip" }); res.end();
  });
  const state = observation(8, 1000, "HEAD");
  t.after(() => state.finish());
  const response = await fetch(url, { method: "HEAD", signal: state.signal });
  const body = await consumeObservedHttpsBody(response, state, state.signal, true);
  peer(state); state.complete(response.status, body);
  assert.equal(state.snapshot().response!.bodyBytes, 0);
});

test("midbody timeout discards partial bytes and never authenticates a complete digest", async t => {
  const url = await server(t, (_req, res) => { res.writeHead(200); res.write("part"); });
  const state = observation(8, 100);
  const response = await fetch(url, { signal: state.signal });
  await assert.rejects(consumeObservedHttpsBody(response, state, state.signal));
  assert.equal(state.snapshot().settlement, "timeout");
  assert.equal(state.snapshot().receivedBytes, 4);
  assert.equal(state.snapshot().response, null);
});

test("disconnected body cannot be completed", async t => {
  const url = await server(t, (_req, res) => {
    res.writeHead(200); res.write("part"); setImmediate(() => res.destroy());
  });
  const state = observation();
  const response = await fetch(url, { signal: state.signal });
  await assert.rejects(consumeObservedHttpsBody(response, state, state.signal));
  assert.equal(state.snapshot().settlement, "transport_failure");
  assert.equal(state.snapshot().response, null);
});

test("completion requires connected peer and a second request invalidates prior completion", () => {
  const missing = observation();
  assert.throws(() => missing.complete(200, Buffer.alloc(0)), /provenance/);
  const state = observation(); peer(state); state.complete(200, Buffer.alloc(0));
  assert.equal(state.snapshot().settlement, "complete");
  assert.throws(() => state.begin(state.policy.url, "GET", false), /one-shot/);
  assert.equal(state.snapshot().settlement, "request_denied");
  assert.equal(state.snapshot().response, null);
});

for (const mismatch of ["url", "method", "body"]) {
  test(`one-shot ${mismatch} mismatch denies before connection`, () => {
    const state = new HttpsObservation({url:"https://example.com/",method:"GET",maxResponseBytes:8,timeoutMs:1000});
    assert.throws(() => state.begin(mismatch === "url" ? "https://other.example/" : state.policy.url,
      mismatch === "method" ? "HEAD" : "GET", mismatch === "body"));
    assert.equal(state.snapshot().connection, null);
    assert.equal(state.snapshot().settlement, "request_denied");
  });
}

function mediate(owner: QemuNetworkBackend, state: HttpsObservation) {
  // Internal test seam: controller plumbing is tested separately.
  Object.assign(owner.options, { httpsObservation: state });
  const session: HttpSession = { buffer: new HttpReceiveBuffer(), processing: true, closed: false,
    upstreamTainted: false, upstreamOriginKey: null };
  return fetchHookRequestAndRespond(owner, {
    request: { method:"GET", url:state.policy.url, headers:{}, body:null },
    httpVersion:"HTTP/1.1", httpSession:session, write:() => {},
  });
}

test("synthetic fetch and response hooks cannot produce authenticated upstream status", async () => {
  let called = false;
  const owner = new QemuNetworkBackend({ socketPath:"/unused", fetch: (async () => { called = true; return new Response("fake", {status:502}); }) as any });
  const state = new HttpsObservation({url:"https://example.com/",method:"GET",maxResponseBytes:8,timeoutMs:1000});
  await assert.rejects(mediate(owner, state), /transport replacement/);
  assert.equal(called, false);
  assert.equal(state.snapshot().response, null);
  assert.equal(state.snapshot().settlement, "request_denied");
  await owner.close();
});

test("deadline precedes DNS and discards late lookup completion", async () => {
  let finishLookup!: () => void;
  let lookedUp!: () => void;
  const started = new Promise<void>(resolve => { lookedUp = resolve; });
  const owner = new QemuNetworkBackend({socketPath:"/unused", httpHooks:{isIpAllowed:() => true},
    dnsLookup:(_host, _opts, callback) => { finishLookup = () => callback(null, [{address:"93.184.216.34",family:4}]); lookedUp(); }});
  const state = new HttpsObservation({url:"https://example.com/",method:"GET",maxResponseBytes:8,timeoutMs:40});
  const pending = mediate(owner, state);
  void pending.catch(() => {});
  await started;
  // A referenced timer keeps this DNS-only fixture alive while its deadline fires.
  const keepAlive = setTimeout(() => {}, 200);
  try { await assert.rejects(pending); } finally { clearTimeout(keepAlive); }
  finishLookup();
  await new Promise<void>(resolve => setImmediate(resolve));
  assert.equal(state.snapshot().settlement, "timeout");
  assert.equal(state.snapshot().connection, null);
  assert.equal(owner.http.sharedDispatchers.size, 0);
  await owner.close();
});

test("deadline includes response header wait", async t => {
  const url = await server(t, () => {});
  const state = observation(8, 60);
  await assert.rejects(fetch(url, {signal:state.signal}));
  assert.equal(state.snapshot().settlement, "timeout");
  assert.equal(state.snapshot().response, null);
});

test("an actual upstream 502 retains its status only with complete transport provenance", async t => {
  const url = await server(t, (_req, res) => { res.writeHead(502); res.end("upstream"); });
  const state = observation();
  const response = await fetch(url, {signal:state.signal});
  const bytes = await consumeObservedHttpsBody(response, state, state.signal);
  peer(state); state.complete(response.status, bytes);
  assert.equal(state.snapshot().response!.status, 502);
  assert.equal(state.snapshot().response!.bodyBase64, Buffer.from("upstream").toString("base64"));
});
