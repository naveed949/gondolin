import type { Stats } from "node:fs";

import { MemoryProvider, type VirtualFileHandle } from "./vfs/node/index.ts";

function guestOwned(stats: Stats): Stats {
  // Keep the complete stat shape, prototype, modes, and numeric representation.
  const result: Stats = Object.assign(
    Object.create(Object.getPrototypeOf(stats)),
    stats,
  );
  Reflect.set(result, "uid", typeof stats.uid === "bigint" ? 0n : 0);
  Reflect.set(result, "gid", typeof stats.gid === "bigint" ? 0n : 0);
  return result;
}

/** Invocation-private snapshots owned by the guest payload, independent of host UID. */
export class CapabilitySnapshotProvider extends MemoryProvider {
  override statSync(path: string, options?: object): Stats {
    return guestOwned(super.statSync(path, options));
  }

  override lstatSync(path: string, options?: object): Stats {
    return guestOwned(super.lstatSync(path, options));
  }

  override openSync(
    path: string,
    flags: string,
    mode?: number,
  ): VirtualFileHandle {
    const handle = super.openSync(path, flags, mode);
    const statSync = handle.statSync.bind(handle);
    handle.statSync = (options?: object) => guestOwned(statSync(options));
    // MemoryProvider's async stat/lstat/open and handle.stat delegate to their
    // synchronous counterparts, covering both provider and descriptor RPCs.
    return handle;
  }
}
