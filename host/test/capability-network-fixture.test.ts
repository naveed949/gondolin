import assert from "node:assert/strict";
import dns from "node:dns";
import test from "node:test";

import { createLookupGuard } from "../src/http/utils.ts";
import { mockCapabilityNetworkDns } from "./helpers/capability-network.ts";

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
