# SDK exec

SDK exec creates a VM from `@earendil-works/gondolin`, runs a shell command, returns stdout and an exit code, and closes the VM.

## Sub-features

- `sdk-create` boots a QEMU VM and exposes `vm.id`.
- `sdk-exec` returns stdout `gondolin-verify-$GONDOLIN_VERIFY_RUN_ID` and exit code `0`.
- `sdk-close` leaves `gondolin list` with no running session.

## How to get to it (user POV)

- Import `VM` from `@earendil-works/gondolin`.
- Call `VM.create`, then `vm.exec`, then `vm.close`.
- Run `gondolin list` to see the session while the VM is open.

## Driving it with verify-gondolin

Preconditions:

- Doctor printed `status=ready` for this `GONDOLIN_VERIFY_RUN_ID`.
- `GONDOLIN_SESSIONS_DIR` and `GONDOLIN_CHECKPOINT_DIR` are exported in the environment of the `node` process.
- `pnpm install` and `pnpm --filter @earendil-works/gondolin build` have produced `host/dist`.
- The current working directory is the repo root so Node resolves `@earendil-works/gondolin`.

- **Write the script.** Save this file as `$GONDOLIN_VERIFY_ROOT/sdk-exec.mjs`:

```js
import { VM } from "@earendil-works/gondolin";

const marker = process.env.VERIFY_MARKER;
const vm = await VM.create({
  sessionLabel: `verify-gondolin sdk-exec ${marker}`,
  sandbox: { vmm: "qemu" },
});
console.log(`session=${vm.id}`);
try {
  const result = await vm.exec(
    '/bin/sh -lc \'printf "%s\\n" "$VERIFY_MARKER"\'',
    { env: { VERIFY_MARKER: marker } },
  );
  process.stdout.write(result.stdout);
  process.stderr.write(result.stderr);
  console.log(`exitCode=${result.exitCode}`);
  process.exitCode = result.exitCode === 0 ? 0 : result.exitCode;
} finally {
  await vm.close();
}
```

- **Run it.** Run `VERIFY_MARKER=gondolin-verify-$GONDOLIN_VERIFY_RUN_ID node "$GONDOLIN_VERIFY_ROOT/sdk-exec.mjs"`. Exit code `0`. Stdout contains `session=` plus a UUID, the line `gondolin-verify-$GONDOLIN_VERIFY_RUN_ID`, and `exitCode=0`.
- **Confirm the session ended.** Run `node host/dist/bin/gondolin.js list`. Stdout is `No running sessions.`
- **Proof.** Save stdout, stderr, and the exit code under `.cursor/skills/verify-gondolin/artifacts/sdk-exec/$GONDOLIN_VERIFY_RUN_ID/` with feature id `sdk-exec`.

## Gotchas

- The string form of `vm.exec` runs `/bin/sh -lc`. An array form needs an absolute executable.
- `VM.create` registers a session in `GONDOLIN_SESSIONS_DIR`. Unset, that is the shared registry under `~/.cache/gondolin/sessions`.
- Skipping `vm.close()` leaves QEMU running. Call close in `finally`, then run cleanup if the process is interrupted.
- `result.exitCode` is returned for a non-zero guest status. The script above copies that status to the Node process.
- A `cli-exec` proof does not prove this entry point.
