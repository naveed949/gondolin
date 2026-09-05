import type { VmRuntimeIdentity } from "./vm/core.ts";

/** Return sorted unique string values */
export function uniqueSorted<T extends string>(values: T[]): T[] {
  return [...new Set(values)].sort() as T[];
}

/** Check whether a host process still exists */
export function isProcessAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code !== "ESRCH";
  }
}

/** Construct the runtime identity used when VM startup fails */
export function unavailableRuntimeIdentity(): VmRuntimeIdentity {
  return {
    vmm: "qemu",
    hostPlatform: process.platform,
    hostArchitecture: process.arch,
    guestArchitecture: "unknown",
    imageDigest: "unavailable",
    guestKernelDigest: "unavailable",
    guestControlDigest: "unavailable",
    guestFeatures: [],
  };
}
