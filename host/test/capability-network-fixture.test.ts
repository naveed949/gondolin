import assert from "node:assert/strict";
import dns from "node:dns";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { createLookupGuard } from "../src/http/utils.ts";
import {
  mockCapabilityNetworkDns,
  resolverProbe,
} from "./helpers/capability-network.ts";

test("fixture DNS resolves host loopback through the real connection policy", async (t) => {
  mockCapabilityNetworkDns(t);
  for (const hostname of ["capability.test", "capability-alias.test"]) {
    const addresses = await new Promise<dns.LookupAddress[]>(
      (resolve, reject) => {
        dns.lookup(hostname, { all: true }, (error, result) => {
          if (error) reject(error);
          else resolve(result);
        });
      },
    );
    assert.deepEqual(addresses, [{ address: "127.0.0.1", family: 4 }]);
  }
  const observations: string[] = [];
  const lookup = createLookupGuard(
    { hostname: "capability.test", port: 80, protocol: "http" },
    (info) => {
      observations.push(`${info.hostname}:${info.ip}`);
      return false;
    },
  );
  await assert.rejects(
    new Promise<void>((resolve, reject) => {
      lookup("capability.test", { all: true }, (error) => {
        if (error) reject(error);
        else resolve();
      });
    }),
  );
  assert.deepEqual(observations, ["capability.test:127.0.0.1"]);
});

test("guest resolver probe prints configuration before preserving payload stdout", (t) => {
  const directory = fs.mkdtempSync(
    path.join(os.tmpdir(), "gondolin-resolver-probe-"),
  );
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const resolver = path.join(directory, "resolv.conf");
  fs.writeFileSync(resolver, "nameserver 192.168.127.1\n");
  const result = spawnSync(
    "/bin/sh",
    [
      "-c",
      resolverProbe.replace("/etc/resolv.conf", resolver) + "printf network-ok",
    ],
    { encoding: "utf8" },
  );
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, "network-ok");
  assert.equal(
    result.stderr,
    "resolver-start\nresolver: nameserver 192.168.127.1\nresolver-end\n",
  );
});
