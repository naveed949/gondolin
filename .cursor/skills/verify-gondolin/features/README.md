# Gondolin verification map

This directory is the maintained source for verifying the user-facing behavior of Gondolin. Read the index before driving the app, then use the matching feature file as the recipe.

## Baseline preconditions

- Build `host/dist/bin/gondolin.js` with `.cursor/skills/verify-gondolin/helpers/launch.sh`.
- Set `GONDOLIN_VERIFY_RUN_ID`, `GONDOLIN_VERIFY_ROOT=/tmp/gondolin-verify-$GONDOLIN_VERIFY_RUN_ID`, `GONDOLIN_SESSIONS_DIR=$GONDOLIN_VERIFY_ROOT/sessions`, and `GONDOLIN_CHECKPOINT_DIR=$GONDOLIN_VERIFY_ROOT/checkpoints`.
- Set `GONDOLIN_VMM=qemu`.
- Cache `alpine-base:latest` for the host arch in the image store (`gondolin image pull alpine-base:latest` during launch).
- Put Node >= 23.6.0 first on `PATH`.
- Run `.cursor/skills/verify-gondolin/helpers/doctor.sh` and require `status=ready`.
- Drive only the sessions directory created for this run.

## Driving conventions

- Start every recipe from the baseline state unless its preconditions say otherwise.
- Pass `--vmm qemu` on CLI drives.
- Use absolute guest executables (`/bin/sh`, `/usr/bin/curl`).
- Treat every command as literal. Keep quoted names and flags unchanged.
- Run one-shot CLI proof through `.cursor/skills/verify-gondolin/helpers/drive-cli-exec.sh`.
- Run interactive bash through `tmux` with the built CLI.
- Run SDK proof through `node` ESM that imports `@earendil-works/gondolin`.
- Restore nothing in the shared image store. Remove the verify root during cleanup. Keep proof artifacts.

## Proof and skip reporting

- Capture the user action and the resulting state, not only the final screen.
- CLI proof includes the command, stdout, stderr, and exit code.
- Mutation proof includes a read-only second view of the stored value.
- Record the feature ID and entry point used with every artifact.
- Report an unreachable path with the attempted command and the unmet precondition.
- Do not report a skipped entry point as verified through a different path.

## Feature entry contract

Each feature file starts with an H1 title and one paragraph describing the user-visible behavior. It then uses exactly four H2 sections in this order.

1. `Sub-features` lists short IDs with one line for each behavior.
2. `How to get to it (user POV)` lists every user entry point.
3. `Driving it with verify-gondolin` starts with `Preconditions:` and uses labeled bullets that pair each user action with an exact command and observable result.
4. `Gotchas` lists traps that can waste or invalidate a verification run.

Keep implementation details out of the map. Name only user paths, stable handles, required state, commands, and observable proof.

## Features

- [Run a command](./cli-exec.md) covers one-shot `gondolin exec`, a host-directory mount, and session exit.
- [Interactive session](./cli-session.md) covers `gondolin bash`, `gondolin list`, and `gondolin attach`.
- [SDK exec](./sdk-exec.md) covers `VM.create`, `vm.exec`, and `vm.close`.
- [HTTP egress policy](./http-egress.md) covers host allowlists and secret placeholders.
