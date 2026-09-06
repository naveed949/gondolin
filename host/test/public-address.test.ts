import assert from "node:assert/strict";
import test from "node:test";
import net from "node:net";
import { isPublicAddress } from "../src/public-address.ts";
import {
  createLookupGuard,
  type LookupEntry,
  type LookupResult,
} from "../src/http/utils.ts";
import { __test, type CapabilityEffect } from "../src/capability-invocation.ts";
import { AuthenticatedExecutionIdentity } from "../src/invocation-evidence.ts";

const disallowed = [
  "",
  "example.com",
  " 8.8.8.8",
  "8.8.8.8 ",
  "0x08080808",
  "134744072",
  "010.0.0.1",
  "127.1",
  "[2606:4700::1111]",
  "2606:4700::1111%eth0",
  "0.0.0.0",
  "0.255.255.255",
  "10.0.0.0",
  "10.255.255.255",
  "100.64.0.0",
  "100.127.255.255",
  "127.0.0.1",
  "169.254.0.1",
  "172.16.0.0",
  "172.31.255.255",
  "192.0.0.9",
  "192.0.2.1",
  "192.31.196.1",
  "192.52.193.1",
  "192.88.99.0",
  "192.88.99.255",
  "192.168.0.1",
  "192.175.48.1",
  "198.18.0.0",
  "198.19.255.255",
  "198.51.100.1",
  "203.0.113.1",
  "224.0.0.0",
  "239.255.255.255",
  "240.0.0.0",
  "255.255.255.255",
  "::",
  "::1",
  "::8.8.8.8",
  "::ffff:8.8.8.8",
  "::ffff:127.0.0.1",
  "64:ff9b::808:808",
  "64:ff9b:1::1",
  "100::1",
  "100:0:0:1::1",
  "2001::1",
  "2001:1::1",
  "2001:1ff:ffff::1",
  "2001:db8::1",
  "2002:808:808::1",
  "2620:4f:8000::1",
  "3fff::1",
  "3fff:fff:ffff::1",
  "3fff:1000::1",
  "3ffe::1",
  "3ffe:831f::1",
  "3000::1",
  "2000::1",
  "2001:1000::1",
  "2001:4e00::1",
  "2001:6000::1",
  "2001:c000::1",
  "2003:4000::1",
  "2420::1",
  "2610:200::1",
  "2620:200::1",
  "2640::1",
  "2810::1",
  "2a20::1",
  "2c10::1",
  "4000::1",
  "5f00::1",
  "fc00::1",
  "fdff::1",
  "fe80::1",
  "febf::1",
  "fec0::1",
  "feff::1",
  "ff00::1",
  "ffff::1",
];

test("conservative public-address grammar rejects special, transition, malformed and scoped addresses", () => {
  for (const address of disallowed)
    assert.equal(isPublicAddress(address), false, address);
});

test("ordinary global-unicast addresses and exclusion boundaries remain supported", () => {
  for (const address of [
    "8.8.8.8",
    "1.1.1.1",
    "100.63.255.255",
    "100.128.0.0",
    "172.15.255.255",
    "172.32.0.0",
    "192.88.98.255",
    "192.88.100.0",
    "198.17.255.255",
    "198.20.0.0",
    "223.255.255.255",
    "2606:4700::1111",
    "2001:4860:4860::8888",
    "2001:200::1",
    "2620:4f:7fff::1",
    "2620:4f:8001::1",
  ])
    assert.equal(isPublicAddress(address), true, address);
});

test("RIR allocation boundary snapshot denies reserved gaps inside 2000::/3", () => {
  for (const [first, last, after] of [
    ["2001:200::", "2001:fff:ffff:ffff:ffff:ffff:ffff:ffff", "2001:1000::"],
    ["2001:1200::", "2001:4dff:ffff:ffff:ffff:ffff:ffff:ffff", "2001:4e00::"],
    ["2001:5000::", "2001:5fff:ffff:ffff:ffff:ffff:ffff:ffff", "2001:6000::"],
    ["2001:8000::", "2001:bfff:ffff:ffff:ffff:ffff:ffff:ffff", "2001:c000::"],
    ["2003::", "2003:3fff:ffff:ffff:ffff:ffff:ffff:ffff", "2003:4000::"],
    ["2400::", "241f:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "2420::"],
    ["2600::", "260f:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "2610:200::"],
    ["2610::", "2610:1ff:ffff:ffff:ffff:ffff:ffff:ffff", "2610:200::"],
    ["2620::", "2620:1ff:ffff:ffff:ffff:ffff:ffff:ffff", "2620:200::"],
    ["2630::", "263f:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "2640::"],
    ["2800::", "280f:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "2810::"],
    ["2a00::", "2a1f:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "2a20::"],
    ["2c00::", "2c0f:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "2c10::"],
  ]) {
    assert.equal(isPublicAddress(first!), true, first);
    assert.equal(isPublicAddress(last!), true, last);
    assert.equal(isPublicAddress(after!), false, after);
  }
});

function fixture() {
  const identity = AuthenticatedExecutionIdentity.begin(
    `sha256:${"1".repeat(64)}`,
    `sha256:${"2".repeat(64)}`,
  );
  const attempted: CapabilityEffect[] = [];
  const denied: CapabilityEffect[] = [];
  const observed: CapabilityEffect[] = [];
  const hooks = __test.createInvocationHttpHooks({
    identity,
    authority: {
      rules: [
        {
          protocol: "tls",
          destination: "example.com",
          port: 443,
          methods: ["GET"],
          redirects: "deny",
          resolution: "checked-host",
          internalRanges: "deny",
        },
      ],
    },
    requested: [],
    granted: [],
    attempted,
    denied,
    observed,
    credentialMediator: null,
  });
  const info = {
    hostname: "example.com",
    port: 443,
    protocol: "https" as const,
  };
  const lookup = (addresses: string[], all = true) =>
    new Promise<LookupResult>((resolve, reject) => {
      const guard = createLookupGuard(
        info,
        hooks.isIpAllowed!,
        (_host, _options, callback) => {
          const entries: LookupEntry[] = addresses.map((address) => ({
            address,
            family: net.isIP(address),
          }));
          callback(null, entries);
        },
      );
      guard("example.com", { all }, (error, result) =>
        error ? reject(error) : resolve(result),
      );
    });
  return { identity, hooks, info, lookup, attempted, denied, observed };
}

test("actual connection lookup guard filters non-public DNS candidates through capability policy", async () => {
  const f = fixture();
  try {
    assert.deepEqual(
      await f.lookup([
        "fec0::1",
        "100:0:0:1::1",
        "192.88.99.1",
        "8.8.8.8",
        "2606:4700::1111",
      ]),
      [
        { address: "8.8.8.8", family: 4 },
        { address: "2606:4700::1111", family: 6 },
      ],
    );
    assert.equal(f.denied.length, 3);
    assert.equal(f.observed.length, 2);
    assert.equal(f.attempted.length, 5);
    assert.equal(await f.lookup(["127.0.0.1", "1.1.1.1"], false), "1.1.1.1");
  } finally {
    f.identity.finish("revoked", true);
  }
});

test("connection-time DNS rebinding cannot reuse an earlier allowed resolution", async () => {
  const f = fixture();
  try {
    assert.equal(
      await f.hooks.isIpAllowed!({
        ...f.info,
        ip: "8.8.8.8",
        family: 4,
        phase: "resolution",
      }),
      true,
    );
    for (const address of [
      "3ffe::1",
      "2001:1000::1",
      "fec0::1",
      "100:0:0:1::1",
      "192.88.99.1",
      "127.0.0.1",
      "::ffff:127.0.0.1",
    ])
      await assert.rejects(f.lookup([address]), /blocked by policy/);
    assert.equal(f.denied.length, 7);
  } finally {
    f.identity.finish("revoked", true);
  }
});
