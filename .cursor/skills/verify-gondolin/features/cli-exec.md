# Run a command

Run a command starts a disposable micro-VM, runs one absolute command, writes a file through a host directory mount, prints the guest identity, and exits with that command's status. The VM is gone when the CLI returns.

## Sub-features

- `exec-identity` prints `Linux` and the Alpine os-release text.
- `exec-mount` writes a marker file on a host directory mounted at `/workspace`.
- `exec-exit` leaves `gondolin list` with no running session.

## How to get to it (user POV)

- Run `gondolin exec --mount-hostfs <host-dir>:/workspace -- <command>`.
- Run `gondolin exec -- <command>` when no host mount is required.

## Driving it with verify-gondolin

Preconditions:

- Doctor printed `status=ready` for this `GONDOLIN_VERIFY_RUN_ID`.
- `$GONDOLIN_VERIFY_ROOT/workspace` exists and is empty of `marker.txt`.
- `GONDOLIN_SESSIONS_DIR` is `$GONDOLIN_VERIFY_ROOT/sessions`.

- **Run the mounted command.** Run `.cursor/skills/verify-gondolin/helpers/drive-cli-exec.sh`. It executes `node host/dist/bin/gondolin.js exec --vmm qemu --mount-hostfs "$GONDOLIN_VERIFY_ROOT/workspace:/workspace" --env VERIFY_MARKER=gondolin-verify-$GONDOLIN_VERIFY_RUN_ID -- /bin/sh -lc 'printf "%s\n" "$VERIFY_MARKER" > /workspace/marker.txt && uname -s && cat /etc/os-release'`. Exit code `0`. Stdout contains a line `Linux` and the text `Alpine Linux`.
- **Confirm the mount.** Read `$GONDOLIN_VERIFY_ROOT/workspace/marker.txt`. The file text is `gondolin-verify-$GONDOLIN_VERIFY_RUN_ID`.
- **Confirm the session ended.** Run `node host/dist/bin/gondolin.js list` with the same `GONDOLIN_SESSIONS_DIR`. Stdout is `No running sessions.`
- **Proof.** The helper writes `command.txt`, `stdout.txt`, `stderr.txt`, `exit-code.txt`, `marker-host.txt`, `list-after.txt`, and `result.txt` under `.cursor/skills/verify-gondolin/artifacts/cli-exec/$GONDOLIN_VERIFY_RUN_ID/`. `result.txt` is `ok`.

## Gotchas

- `gondolin exec -- sh -lc ...` fails inside the guest because the exec form does not search `PATH`. Use `/bin/sh`.
- `--mount-hostfs` requires an existing host directory. A missing directory fails before the VM boots.
- `--env VERIFY_MARKER=...` is the guest-visible value. The host shell variable is not copied in on its own.
- `gondolin list` with `GONDOLIN_SESSIONS_DIR` unset reads `~/.cache/gondolin/sessions` and can attach to someone else's VM. Keep the private directory exported.
- A non-zero `exit-code.txt` or `result.txt` other than `ok` is a failed proof. Leave the artifact directory for cleanup.
