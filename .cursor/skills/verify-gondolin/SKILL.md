---
name: verify-gondolin
description: "Drive Gondolin, a local Linux micro-VM sandbox, through its QEMU CLI (exec, bash, list, attach) and TypeScript SDK (VM.create, vm.exec), including HTTP egress policy. Use to prove a user-facing Gondolin behavior, or when a change needs a real VM session instead of unit tests."
---

# Verify Gondolin

Gondolin runs commands inside a local Linux micro-VM. The primary surface is the `gondolin` CLI (`exec`, `bash`, `list`, `attach`) backed by QEMU. The same VM lifecycle is available as `VM.create` / `vm.exec` in `@earendil-works/gondolin`. HTTP egress policy and secret placeholders are a third user-facing surface on both the CLI and the SDK.

This fork's package version is the `version` field in `host/package.json`. Guest images resolve from that version's GitHub release registry (`builtin-image-registry.json` on the release), then the local store at `${XDG_CACHE_HOME:-$HOME/.cache}/gondolin/images`. `npx @earendil-works/gondolin` installs upstream npm, which is a different build. Verification uses the built file `host/dist/bin/gondolin.js` from this checkout.

## Launch

Launch builds the CLI once and caches `alpine-base:latest` for the host architecture. Each drive then starts its own short-lived QEMU process. There is no long-running server.

From the repo root, with `node` >= 23.6.0 first on `PATH` (`host/package.json` `engines`) and `pnpm` 8.15.0 (`packageManager`):

```bash
export GONDOLIN_VERIFY_RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
export GONDOLIN_VERIFY_ROOT="/tmp/gondolin-verify-${GONDOLIN_VERIFY_RUN_ID}"
export GONDOLIN_SESSIONS_DIR="${GONDOLIN_VERIFY_ROOT}/sessions"
export GONDOLIN_CHECKPOINT_DIR="${GONDOLIN_VERIFY_ROOT}/checkpoints"
export GONDOLIN_VMM=qemu
.cursor/skills/verify-gondolin/helpers/launch.sh
```

Ready when launch prints both `ready: gondolin help` and `ready: image alpine-base:latest arch=<host-arch>` and exits 0. `gondolin help` lists `exec`, `bash`, `list`, `attach`, `snapshot`, `build`, `image`, and `tools`.

If `command -v node` is older than 23.6.0, install Node 24 (or any 23.6+) and prepend its `bin` directory before launch. If `pnpm` is missing from that Node install: `corepack enable && corepack prepare pnpm@8.15.0 --activate`. If `qemu-system-x86_64` (x86_64) or `qemu-system-aarch64` (aarch64) is missing, install the matching QEMU system package before launch.

When `/dev/kvm` is not readable and writable, launch exports `GONDOLIN_START_TIMEOUT_MS=300000` unless it is already set. QEMU then uses TCG. The code default without that variable is `120000` ms (`GONDOLIN_START_TIMEOUT_MS` in `host/src/vm/core.ts`).

The first `image pull` downloads the alpine-base archive for this arch into the shared image store. For package `0.12.1-adaptivesandbox.10` the x86_64 archive is about 925 MB compressed. Later launches reuse that store. Launch does not point `GONDOLIN_IMAGE_STORE` at the verify root.

## Doctor

Doctor is read-only. Run it after launch, and again whenever a drive looks wrong, before starting another VM:

```bash
mkdir -p ".cursor/skills/verify-gondolin/artifacts/cli-exec/${GONDOLIN_VERIFY_RUN_ID}"
set -o pipefail
.cursor/skills/verify-gondolin/helpers/doctor.sh | tee ".cursor/skills/verify-gondolin/artifacts/cli-exec/${GONDOLIN_VERIFY_RUN_ID}/doctor.txt"
```

Exit 0 prints `status=ready`. It reports `node`, `node_path`, `qemu`, `qemu_path`, `host_arch`, `accel` (`kvm` or `tcg`), `package_version`, `image_store`, `image_ref=alpine-base:latest`, `sessions_live=0`, and the private `sessions_dir`.

Doctor exits 1 with `status=refuse` when any of these are true:

- `node` is missing or older than 23.6.0
- the arch-matching `qemu-system-*` binary is missing
- `host/dist/bin/gondolin.js` is missing
- the image store has no `alpine-base:latest` line for this arch from `gondolin image ls`
- `GONDOLIN_SESSIONS_DIR` is unset, or it is `${XDG_CACHE_HOME:-$HOME/.cache}/gondolin/sessions`
- that sessions directory already has a metadata file whose pid is alive and whose socket file exists

A live session in the private directory means another drive is using this run. Stop that drive with cleanup before doctor is run again. Doctor does not call `gondolin list` (that command garbage-collects session files) and does not pull images.

## Drive

The harness is the built CLI, a private session directory, and the helpers in this skill. Interactive `bash` needs a PTY; use `tmux`. SDK drives are a short-lived `node` ESM script in the verify root. Feature recipes live in `features/`.

Keep the launch exports set. Pass `--vmm qemu` on every CLI drive. The array form of `gondolin exec` does not search `PATH` inside the guest; command tokens are absolute paths such as `/bin/sh`.

Prove `cli-exec` with:

```bash
.cursor/skills/verify-gondolin/helpers/drive-cli-exec.sh
```

That helper runs:

```text
node host/dist/bin/gondolin.js exec --vmm qemu \
  --mount-hostfs "$GONDOLIN_VERIFY_ROOT/workspace:/workspace" \
  --env VERIFY_MARKER=gondolin-verify-$GONDOLIN_VERIFY_RUN_ID \
  -- /bin/sh -lc 'printf "%s\n" "$VERIFY_MARKER" > /workspace/marker.txt && uname -s && cat /etc/os-release'
```

Success is exit code 0, stdout containing a `Linux` line and `Alpine Linux`, the host file `$GONDOLIN_VERIFY_ROOT/workspace/marker.txt` equal to `gondolin-verify-$GONDOLIN_VERIFY_RUN_ID`, and a following `gondolin list` printing `No running sessions.`

Other mapped features (`cli-session`, `sdk-exec`, `http-egress`) use the commands in their feature files. A run that only drives `cli-exec` leaves those features unproven.

## Evidence

Proof for a drive is the command, stdout, stderr, exit code, and a second view of the side effect. For `cli-exec` the second view is the marker file written through the host mount.

`drive-cli-exec.sh` writes:

`.cursor/skills/verify-gondolin/artifacts/cli-exec/<GONDOLIN_VERIFY_RUN_ID>/`

- `feature-id.txt` (`cli-exec`)
- `entry-point.txt` (`gondolin exec --mount-hostfs`)
- `command.txt`, `stdout.txt`, `stderr.txt`, `exit-code.txt`
- `marker-expected.txt`, `marker-host.txt`
- `list-after.txt`, `list-after.stderr.txt`, `list-after.exit-code.txt`
- `meta.txt`, `result.txt` (`ok` when every check passed)
- `doctor.txt` when doctor was teed as shown above

`result.txt` other than `ok` means that run is not proof. Record the feature id that was actually driven. An entry point that was not run stays unproven.

## Cleanup

Cleanup signals processes recorded for this verify root whose `/proc/<pid>/cmdline` contains `host/dist/bin/gondolin.js` or `qemu-system-`, then deletes `/tmp/gondolin-verify-<run-id>`.

```bash
.cursor/skills/verify-gondolin/helpers/cleanup.sh
```

Run cleanup after a failed launch or drive as well, using the same `GONDOLIN_VERIFY_ROOT` and `GONDOLIN_SESSIONS_DIR`. Cleanup leaves `.cursor/skills/verify-gondolin/artifacts/` in place, including `doctor.txt` and the `cli-exec` files. It leaves the shared image store in place. It does not signal processes in `${XDG_CACHE_HOME:-$HOME/.cache}/gondolin/sessions`.

After cleanup, `test -f ".cursor/skills/verify-gondolin/artifacts/cli-exec/${GONDOLIN_VERIFY_RUN_ID}/stdout.txt"` still succeeds, and `test ! -d "$GONDOLIN_VERIFY_ROOT"` succeeds.

## Helpers

From the repo root:

```bash
.cursor/skills/verify-gondolin/helpers/launch.sh
.cursor/skills/verify-gondolin/helpers/doctor.sh
.cursor/skills/verify-gondolin/helpers/drive-cli-exec.sh
.cursor/skills/verify-gondolin/helpers/cleanup.sh
```

`helpers/common.sh` is sourced by those four scripts. It resolves the repo root, `host/dist/bin/gondolin.js`, the host arch, and the evidence directory.

## Secondary surfaces

These exist in the product and are outside the feature map. Driving them does not prove a mapped feature, and it does not prove AdaptiveSandbox conformance.

- Capability Invocation API (`CapabilityInvocationContext`, profiles `exact-reader`, `exact-writer`, `scoped-runner`) in `docs/capability-invocation.md`. `docs/fork-releases.md` keeps `adaptiveSandboxQualified` false until an independent conformance run says otherwise.
- `gondolin snapshot` and `gondolin bash --resume`
- ingress (`gondolin bash --listen`, `vm.enableIngress()`)
- SSH egress (`--ssh-allow-host`) and host SSH (`--ssh`)
- `--vmm krun` (needs a krun runner and hardware virtualization)
- `gondolin image` and `gondolin build` for custom images

## Maintenance

Keep this map aligned with the CLI and SDK using `/maintain-verification-skill`.
