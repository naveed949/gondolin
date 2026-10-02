import dns from "node:dns";
import net from "node:net";
import { isPublicAddress } from "../../src/public-address.ts";

/** Resolver queries that supply a hostname's public peer set */
export type PublicPeerSources = {
  /** System `dns.promises.lookup` addresses */
  lookup(hostname: string): Promise<readonly string[]>;
  /** Direct A records */
  resolve4(hostname: string): Promise<readonly string[]>;
  /** Direct AAAA records */
  resolve6(hostname: string): Promise<readonly string[]>;
};

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
  const tail =
    halves.length === 2 ? (halves[1] ? halves[1].split(":") : []) : [];
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

/** IPv4, IPv6, and IPv4-mapped IPv6 forms of one address */
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

function canonicalPublicAddress(address: string): string | null {
  if (typeof address !== "string" || address.includes("%")) return null;
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(address);
  const candidate = mapped?.[1] ?? address;
  if (net.isIP(candidate) === 0 || !isPublicAddress(candidate)) return null;
  return candidate;
}

async function readAddresses(
  load: () => Promise<readonly string[]>,
): Promise<readonly string[]> {
  try {
    return await load();
  } catch {
    return [];
  }
}

const systemPeerSources: PublicPeerSources = {
  async lookup(hostname) {
    const records = await dns.promises.lookup(hostname, {
      all: true,
      verbatim: true,
    });
    return records.map((record) => record.address);
  },
  resolve4(hostname) {
    return dns.promises.resolve4(hostname);
  },
  resolve6(hostname) {
    return dns.promises.resolve6(hostname);
  },
};

/** True when `remote` is one of `peers`, including IPv4-mapped IPv6 */
export function remoteMatchesHostPeers(
  remote: string,
  peers: readonly string[],
): boolean {
  return peers.some((peer) => sameAddress(remote, peer));
}

/** Public A/AAAA answers for `hostname` from lookup plus direct DNS */
export async function resolvePublicPeers(
  hostname: string,
  sources: PublicPeerSources = systemPeerSources,
): Promise<readonly string[]> {
  const batches = await Promise.all([
    readAddresses(() => sources.lookup(hostname)),
    readAddresses(() => sources.resolve4(hostname)),
    readAddresses(() => sources.resolve6(hostname)),
  ]);
  const peers: string[] = [];
  for (const batch of batches) {
    for (const address of batch) {
      const publicAddress = canonicalPublicAddress(address);
      if (!publicAddress || remoteMatchesHostPeers(publicAddress, peers))
        continue;
      peers.push(publicAddress);
    }
  }
  if (peers.length === 0) {
    throw new Error(`no public address for ${hostname}`);
  }
  return peers;
}
