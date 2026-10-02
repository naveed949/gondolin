import assert from "node:assert/strict";
import test from "node:test";
import {
  remoteMatchesHostPeers,
  resolvePublicPeers,
} from "./helpers/https-public-peers.ts";

test("multi-A peer match accepts another resolved answer and mapped IPv6", () => {
  const peers = ["104.20.23.154", "172.66.147.243"];
  assert.equal(remoteMatchesHostPeers("172.66.147.243", peers), true);
  assert.equal(remoteMatchesHostPeers("::ffff:104.20.23.154", peers), true);
  // /proc/net/tcp6 prints IPv4-mapped peers as hextets, not dotted form.
  assert.equal(remoteMatchesHostPeers("::ffff:6814:179a", peers), true);
  assert.equal(remoteMatchesHostPeers("172.66.157.237", peers), false);
  assert.equal(remoteMatchesHostPeers("8.8.8.8", peers), false);
});

test("resolvePublicPeers unions public lookup, A, and AAAA answers", async () => {
  const peers = await resolvePublicPeers("example.com", {
    lookup: async () => ["10.0.0.1", "::ffff:104.20.23.154", "192.0.2.1"],
    resolve4: async () => ["172.66.147.243", "127.0.0.1"],
    resolve6: async () => {
      throw new Error("no AAAA");
    },
  });
  assert.deepEqual([...peers], ["104.20.23.154", "172.66.147.243"]);

  const withV6 = await resolvePublicPeers("example.com", {
    lookup: async () => [],
    resolve4: async () => ["104.20.23.154"],
    resolve6: async () => ["2606:4700:10::6814:179a", "2001:db8::1"],
  });
  assert.deepEqual([...withV6], ["104.20.23.154", "2606:4700:10::6814:179a"]);

  await assert.rejects(
    resolvePublicPeers("example.com", {
      lookup: async () => ["10.1.1.1"],
      resolve4: async () => {
        throw new Error("servfail");
      },
      resolve6: async () => ["2001:db8::2"],
    }),
    /no public address for example.com/,
  );
});
