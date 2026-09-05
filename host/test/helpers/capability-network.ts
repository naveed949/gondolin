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

/** Log guest boot and DNS metadata during the networking integration fixtures. */
export function enableCapabilityNetworkDebug(t: TestContext): void {
  const previous = process.env.GONDOLIN_DEBUG;
  process.env.GONDOLIN_DEBUG = "net,exec,protocol";
  t.after(() => {
    if (previous === undefined) delete process.env.GONDOLIN_DEBUG;
    else process.env.GONDOLIN_DEBUG = previous;
  });
}

/** Builtin-only resolver diagnostics preserve the payload process limit. */
export const resolverProbe =
  'printf "resolver-start\\n" >&2; while IFS= read -r line || [ -n "$line" ]; do printf "resolver: %s\\n" "$line" >&2; done < /etc/resolv.conf; printf "resolver-end\\n" >&2; ';
