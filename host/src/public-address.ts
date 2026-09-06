import net from "node:net";
import { parseIPv6Hextets } from "./utils/ip.ts";

/** Conservative Internet-unicast subset; see docs/public-address-policy.md. */
export const PUBLIC_ADDRESS_POLICY_VERSION = "gondolin.public-address/v1";

const excludedIPv4 = [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.31.196.0", 24],
  ["192.52.193.0", 24],
  ["192.88.99.0", 24],
  ["192.168.0.0", 16],
  ["192.175.48.0", 24],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4],
] as const;

function ipv4Number(address: string): number {
  return address
    .split(".")
    .reduce((value, octet) => value * 256 + Number(octet), 0);
}

const excludedIPv4Ranges = excludedIPv4.map(([address, prefix]) => {
  const start = ipv4Number(address);
  return [start, start + 2 ** (32 - prefix)] as const;
});

// IANA IPv6 Global Unicast allocations (2025-10-10 registry snapshot).
// Only RIR allocations are supported; absent/reserved and IANA special-purpose
// allocations stay denied. Every prefix fits within the first 32 bits.
const allocatedIPv6 = [
  [0x20010200, 23],
  [0x20010400, 23],
  [0x20010600, 23],
  [0x20010800, 22],
  [0x20010c00, 23],
  [0x20010e00, 23],
  [0x20011200, 23],
  [0x20011400, 22],
  [0x20011800, 23],
  [0x20011a00, 23],
  [0x20011c00, 22],
  [0x20012000, 19],
  [0x20014000, 23],
  [0x20014200, 23],
  [0x20014400, 23],
  [0x20014600, 23],
  [0x20014800, 23],
  [0x20014a00, 23],
  [0x20014c00, 23],
  [0x20015000, 20],
  [0x20018000, 19],
  [0x2001a000, 20],
  [0x2001b000, 20],
  [0x20030000, 18],
  [0x24000000, 12],
  [0x24100000, 12],
  [0x26000000, 12],
  [0x26100000, 23],
  [0x26200000, 23],
  [0x26300000, 12],
  [0x28000000, 12],
  [0x2a000000, 12],
  [0x2a100000, 12],
  [0x2c000000, 12],
] as const;
const allocatedIPv6Ranges = allocatedIPv6.map(
  ([start, prefix]) => [start, start + 2 ** (32 - prefix)] as const,
);

/** Pure classification of an unscoped, numeric connection candidate. No DNS. */
export function isPublicAddress(address: string): boolean {
  // Node accepts scoped IPv6; interfaces and zone identifiers are not authority.
  if (address.includes("%")) return false;
  const family = net.isIP(address);
  if (family === 4) {
    const value = ipv4Number(address);
    return !excludedIPv4Ranges.some(
      ([start, end]) => value >= start && value < end,
    );
  }
  if (family !== 6) return false;
  const parts = parseIPv6Hextets(address);
  if (!parts) return false;
  // The entire 2000::/3 is assignable, not allocated: reserved gaps and
  // returned 6bone space must not become public-address authority.
  const leading = parts[0]! * 65536 + parts[1]!;
  if (
    !allocatedIPv6Ranges.some(
      ([start, end]) => leading >= start && leading < end,
    )
  )
    return false;
  // Special-purpose exceptions within RIR allocations remain excluded.
  if (parts[0] === 0x2001 && parts[1] === 0x0db8) return false;
  if (parts[0] === 0x2620 && parts[1] === 0x004f && parts[2] === 0x8000)
    return false;
  return true;
}
