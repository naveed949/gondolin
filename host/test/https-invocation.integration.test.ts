import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import test from "node:test";
import { shouldSkipVmTests } from "./helpers/vm-fixture.ts";

// Public third-party development traffic; not controlled external qualification.
// CI must run this gate: missing acceleration, curl, network or valid TLS fails it.
const skip = !process.env.CI && shouldSkipVmTests();
const run = promisify(execFile);
const helper = fileURLToPath(
  new URL("./helpers/https-vm-smoke.ts", import.meta.url),
);

for (const [mode, name] of [
  ["success", "one-shot HTTPS VM public TLS GET/HEAD development evidence"],
  [
    "bounds",
    "one-shot HTTPS VM enforces decoded response and request deadline bounds",
  ],
]) {
  test(name, { skip, timeout: 120000 }, async () => {
    // Node test workers synthesize TLS flags in execArgv. Start a plain Node
    // process with its normal default trust, inheriting all environment values.
    // The production preflight remains unchanged and rejects unsafe env options.
    const result = await run(process.execPath, [helper, mode], {
      timeout: 110000,
      maxBuffer: 2 * 1024 * 1024,
    });
    assert.match(result.stdout, new RegExp(`HTTPS VM ${mode}: PASS`));
  });
}
