import dns from "node:dns";
import type { TestContext } from "node:test";

/** Resolve fixture hosts on the host after guest synthetic DNS routes egress. */
export function mockCapabilityNetworkDns(t: TestContext): void {
  const original = dns.lookup;
  const hosts = new Set(["capability.test", "capability-alias.test"]);
  t.mock.method(dns, "lookup", ((hostname: string, ...args: unknown[]) => {
    if (!hosts.has(hostname))
      return Reflect.apply(original, dns, [hostname, ...args]);
    const options = args[0];
    const callback = args[args.length - 1] as (
      error: NodeJS.ErrnoException | null,
      address: string | dns.LookupAddress[],
      family?: number,
    ) => void;
    queueMicrotask(() => {
      if (
        typeof options === "object" &&
        options !== null &&
        "all" in options &&
        options.all
      ) {
        callback(null, [{ address: "127.0.0.1", family: 4 }]);
      } else {
        callback(null, "127.0.0.1", 4);
      }
    });
  }) as typeof dns.lookup);
}
