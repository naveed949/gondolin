import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { DownloadFileError, downloadFile } from "../src/alpine/utils.ts";

const URL =
  "https://dl-cdn.alpinelinux.org/alpine/v3.23/main/x86_64/APKINDEX.tar.gz";

const noWait = { backoffMs: [0, 0] } as const;

test("downloadFile writes the body from a successful fetch", async (t) => {
  const dest = tempDest(t);
  const inits: Array<RequestInit | undefined> = [];

  await downloadFile(URL, dest, {
    ...noWait,
    fetch: async (_url, init) => {
      inits.push(init);
      return new Response(Buffer.from("apk-bytes"));
    },
  });

  assert.equal(fs.readFileSync(dest, "utf8"), "apk-bytes");
  assert.equal(inits.length, 1);
  assert.equal(inits[0]?.redirect, "follow");
});

test("downloadFile retries a transient fetch failure then writes the body", async (t) => {
  const dest = tempDest(t);
  const failures = [
    new TypeError("fetch failed"),
    Object.assign(new Error("reset"), { code: "ECONNRESET" }),
    Object.assign(new Error("timeout"), { code: "ETIMEDOUT" }),
    Object.assign(new Error("dns"), { code: "ENOTFOUND" }),
    Object.assign(new Error("again"), { code: "EAI_AGAIN" }),
    Object.assign(new Error("undici"), { code: "UND_ERR_SOCKET" }),
    new TypeError("fetch failed", {
      cause: Object.assign(new Error("reset"), { code: "ECONNRESET" }),
    }),
    new Error("wrapper", {
      cause: new AggregateError(
        [Object.assign(new Error("reset"), { code: "ECONNRESET" })],
        "connect",
      ),
    }),
  ];

  for (const failure of failures) {
    const inits: Array<RequestInit | undefined> = [];
    let calls = 0;
    await downloadFile(URL, dest, {
      ...noWait,
      fetch: async (_url, init) => {
        calls += 1;
        inits.push(init);
        if (calls === 1) throw failure;
        return new Response(Buffer.from("ok"));
      },
    });

    assert.equal(calls, 2);
    assert.equal(fs.readFileSync(dest, "utf8"), "ok");
    assert.equal(inits[0]?.redirect, "follow");
    assert.equal(inits[1]?.redirect, "follow");
  }
});

test("downloadFile retries HTTP 5xx then writes the body", async (t) => {
  const dest = tempDest(t);
  let calls = 0;

  await downloadFile(URL, dest, {
    ...noWait,
    fetch: async () => {
      calls += 1;
      if (calls < 3) return new Response("unavailable", { status: 503 });
      return new Response(Buffer.from("recovered"));
    },
  });

  assert.equal(calls, 3);
  assert.equal(fs.readFileSync(dest, "utf8"), "recovered");
});

test("downloadFile does not retry HTTP 4xx", async (t) => {
  const dest = tempDest(t);
  let calls = 0;

  await assert.rejects(
    downloadFile(URL, dest, {
      ...noWait,
      fetch: async () => {
        calls += 1;
        return new Response("missing", { status: 404 });
      },
    }),
    (err: unknown) => {
      assert.ok(err instanceof DownloadFileError);
      assert.equal(err.status, 404);
      assert.match(err.message, /HTTP 404/);
      return true;
    },
  );
  assert.equal(calls, 1);
  assert.equal(fs.existsSync(dest), false);
});

test("downloadFile throws DownloadFileError after transient retries are exhausted", async (t) => {
  const dest = tempDest(t);
  const cause = new TypeError("fetch failed", {
    cause: Object.assign(new Error("reset"), { code: "ECONNRESET" }),
  });
  let calls = 0;

  await assert.rejects(
    downloadFile(URL, dest, {
      ...noWait,
      fetch: async () => {
        calls += 1;
        throw cause;
      },
    }),
    (err: unknown) => {
      assert.ok(err instanceof DownloadFileError);
      assert.equal(err.status, undefined);
      assert.match(err.message, /TypeError: fetch failed \(ECONNRESET\)/);
      assert.equal(err.cause, cause);
      return true;
    },
  );
  assert.equal(calls, 3);
  assert.equal(fs.existsSync(dest), false);
});

test("downloadFile throws DownloadFileError after HTTP 5xx retries are exhausted", async (t) => {
  const dest = tempDest(t);
  let calls = 0;

  await assert.rejects(
    downloadFile(URL, dest, {
      ...noWait,
      fetch: async () => {
        calls += 1;
        return new Response("bad gateway", { status: 502 });
      },
    }),
    (err: unknown) => {
      assert.ok(err instanceof DownloadFileError);
      assert.equal(err.status, 502);
      assert.match(err.message, /HTTP 502/);
      return true;
    },
  );
  assert.equal(calls, 3);
});

test("downloadFile does not retry a non-transient fetch error", async (t) => {
  const dest = tempDest(t);
  const failure = new TypeError("invalid URL");
  let calls = 0;

  await assert.rejects(
    downloadFile(URL, dest, {
      ...noWait,
      fetch: async () => {
        calls += 1;
        throw failure;
      },
    }),
    (err: unknown) => {
      assert.equal(err, failure);
      return true;
    },
  );
  assert.equal(calls, 1);
});

function tempDest(t: test.TestContext): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "gondolin-download-"));
  t.after(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });
  return path.join(dir, "payload");
}
