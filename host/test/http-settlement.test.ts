import assert from "node:assert/strict";
import http from "node:http";
import net from "node:net";
import test from "node:test";
import { QemuNetworkBackend } from "../src/qemu/net.ts";
import {
  fetchHookRequestAndRespond,
  type HttpSession,
} from "../src/qemu/http.ts";
import { HttpReceiveBuffer, getCheckedDispatcher } from "../src/http/utils.ts";

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

function backend() {
  return new QemuNetworkBackend({
    socketPath: "/unused-http-settlement.sock",
    httpHooks: { isIpAllowed: () => true },
  });
}

function request(owner: QemuNetworkBackend, url: string) {
  const session: HttpSession = {
    buffer: new HttpReceiveBuffer(),
    processing: true,
    closed: false,
    upstreamTainted: false,
    upstreamOriginKey: null,
  };
  const written: Buffer[] = [];
  const promise = fetchHookRequestAndRespond(owner, {
    request: { method: "GET", url, headers: {}, body: null },
    httpVersion: "HTTP/1.1",
    httpSession: session,
    write: (chunk) => {
      written.push(chunk);
    },
  });
  // Observe the rejection immediately; assertions below still inspect the result.
  void promise.catch(() => {});
  return { session, promise, written };
}

async function fixture(handler: http.RequestListener) {
  const server = http.createServer(handler);
  const sockets = new Set<net.Socket>();
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const url = `http://127.0.0.1:${(server.address() as net.AddressInfo).port}/`;
  return {
    url,
    async close() {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

for (const streaming of [false, true]) {
  test(
    `host HTTP close cancels ${streaming ? "an unfinished response body" : "hanging response headers"}`,
    { timeout: 6000 },
    async (t) => {
      const received = deferred();
      const disconnected = deferred();
      const origin = await fixture((_req, res) => {
        res.on("close", disconnected.resolve);
        if (streaming) {
          res.writeHead(200);
          res.write("partial");
        }
        received.resolve();
      });
      t.after(() => origin.close());
      const owner = backend();
      const active = request(owner, origin.url);
      await received.promise;
      await owner.close();
      await assert.rejects(active.promise);
      await disconnected.promise;
      const bytesAtClose = Buffer.concat(active.written).length;
      await owner.close();
      await assert.rejects(
        request(owner, origin.url).promise,
        /channels are closed/,
      );
      assert.equal(Buffer.concat(active.written).length, bytesAtClose);
      assert.equal(owner.http.sharedDispatchers.size, 0);
    },
  );
}

test(
  "host HTTP cancellation is isolated between backends",
  { timeout: 6000 },
  async (t) => {
    const firstReceived = deferred();
    const secondReceived = deferred();
    let secondResponse: http.ServerResponse;
    const origin = await fixture((req, res) => {
      if (req.url === "/first") firstReceived.resolve();
      else {
        secondResponse = res;
        secondReceived.resolve();
      }
    });
    t.after(() => origin.close());
    const first = backend();
    const second = backend();
    t.after(() => second.close());
    const one = request(first, origin.url + "first");
    const two = request(second, origin.url + "second");
    await Promise.all([firstReceived.promise, secondReceived.promise]);
    await first.close();
    await assert.rejects(one.promise);
    assert.equal(two.session.hostAbortController?.signal.aborted, false);
    secondResponse!.end("second remains active");
    await two.promise;
    assert.match(
      Buffer.concat(two.written).toString(),
      /second remains active/,
    );
  },
);

test(
  "guest disconnect aborts a request still awaiting response headers",
  { timeout: 6000 },
  async (t) => {
    const received = deferred();
    const disconnected = deferred();
    const origin = await fixture((_req, res) => {
      res.on("close", disconnected.resolve);
      received.resolve();
    });
    t.after(() => origin.close());
    const owner = backend();
    t.after(() => owner.close());
    const active = request(owner, origin.url);
    const key = "guest-request";
    owner.tcpSessions.set(key, {
      http: active.session,
      socket: null,
      pendingWrites: [],
      pendingWriteBytes: 0,
    } as any);
    await received.promise;
    (owner as any).handleTcpClose({ key, destroy: true });
    await assert.rejects(active.promise);
    await disconnected.promise;
  },
);

test("detached dispatcher destruction failure remains a rejected close", async () => {
  const owner = backend();
  const dispatcher = getCheckedDispatcher(owner, {
    hostname: "example.com",
    port: 443,
    protocol: "https",
  })!;
  const destroy = dispatcher.destroy.bind(dispatcher);
  dispatcher.destroy = (() =>
    Promise.reject(new Error("injected destroy rejection"))) as any;
  (owner as any).detachSocket();
  await assert.rejects(owner.close(), /dispatcher destruction failed/);
  await assert.rejects(owner.close(), /dispatcher destruction failed/);
  dispatcher.destroy = destroy;
  await destroy();
});

test(
  "unsettled dispatcher destruction has a finite failed close",
  { timeout: 6000 },
  async () => {
    const owner = backend();
    const dispatcher = getCheckedDispatcher(owner, {
      hostname: "example.com",
      port: 443,
      protocol: "https",
    })!;
    const destroy = dispatcher.destroy.bind(dispatcher);
    const blocked = deferred();
    dispatcher.destroy = (() => blocked.promise) as any;
    try {
      await assert.rejects(owner.close(), /settlement timed out/);
      await assert.rejects(owner.close(), /settlement timed out/);
    } finally {
      blocked.resolve();
      dispatcher.destroy = destroy;
      await destroy();
    }
  },
);

test(
  "a policy callback resumed after close cannot start a host fetch",
  { timeout: 6000 },
  async () => {
    const entered = deferred();
    const resume = deferred();
    let fetched = false;
    const owner = new QemuNetworkBackend({
      socketPath: "/unused-http-settlement.sock",
      httpHooks: {
        isRequestAllowed: async () => {
          entered.resolve();
          await resume.promise;
          return true;
        },
      },
      fetch: async () => {
        fetched = true;
        return new Response("unexpected");
      },
    });
    const active = request(owner, "http://127.0.0.1/");
    await entered.promise;
    const closing = owner.close();
    resume.resolve();
    await closing;
    await assert.rejects(active.promise);
    assert.equal(fetched, false);
  },
);

test(
  "guest transport reconnect opens a fresh generation only after settlement",
  { timeout: 6000 },
  async (t) => {
    const origin = await fixture((_req, res) => res.end("reconnected"));
    t.after(() => origin.close());
    const owner = backend();
    const firstSocket = new net.Socket();
    await (owner as any).attachSocket(firstSocket);
    (owner as any).detachSocket();
    const secondSocket = new net.Socket();
    await (owner as any).attachSocket(secondSocket);
    const active = request(owner, origin.url);
    await active.promise;
    assert.match(Buffer.concat(active.written).toString(), /reconnected/);
    await owner.close();
    const forbiddenSocket = new net.Socket();
    await (owner as any).attachSocket(forbiddenSocket);
    assert.equal(forbiddenSocket.destroyed, true);
    await assert.rejects(
      request(owner, origin.url).promise,
      /channels are closed/,
    );
  },
);
