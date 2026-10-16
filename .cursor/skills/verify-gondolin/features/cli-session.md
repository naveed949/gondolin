# Interactive session

Interactive session starts a shell that stays up, shows that shell in `gondolin list`, and runs a second command against the same VM with `gondolin attach`.

## Sub-features

- `bash-start` opens a shell in a new session.
- `bash-list` shows that session as alive.
- `bash-attach` runs a command on the same session id.
- `bash-stop` exits the owner shell and leaves no running session.

## How to get to it (user POV)

- Run `gondolin bash`.
- Run `gondolin list`.
- Run `gondolin attach <session-id>`.
- Press `Ctrl-]` in the owner shell to detach.

## Driving it with verify-gondolin

Preconditions:

- Doctor printed `status=ready` for this `GONDOLIN_VERIFY_RUN_ID`.
- `GONDOLIN_SESSIONS_DIR` is `$GONDOLIN_VERIFY_ROOT/sessions`.
- `tmux` is on `PATH`.
- No tmux session is named `gondolin-verify-$GONDOLIN_VERIFY_RUN_ID`.

- **Start bash.** Run `tmux new-session -d -s "gondolin-verify-$GONDOLIN_VERIFY_RUN_ID" -- node host/dist/bin/gondolin.js bash --vmm qemu`. The tmux session exists.
- **Send a command.** Run `tmux send-keys -t "gondolin-verify-$GONDOLIN_VERIFY_RUN_ID" 'echo gondolin-session-ready' Enter`, then `tmux capture-pane -p -t "gondolin-verify-$GONDOLIN_VERIFY_RUN_ID"`. The capture contains `gondolin-session-ready`.
- **List the session.** Run `node host/dist/bin/gondolin.js list`. Stdout has the header `ID  PID  AGE  ALIVE  LABEL` and a row whose `ALIVE` column is `yes`. The first column is the session id.
- **Attach.** Run `node host/dist/bin/gondolin.js attach <session-id> -- /bin/sh -lc 'echo gondolin-attached'`. Exit code `0`. Stdout contains `gondolin-attached`. A second `node host/dist/bin/gondolin.js list` still shows `ALIVE` `yes` for the same id.
- **Stop the owner.** Run `tmux send-keys -t "gondolin-verify-$GONDOLIN_VERIFY_RUN_ID" 'exit' Enter`. Then `node host/dist/bin/gondolin.js list` prints `No running sessions.`
- **Proof.** Save the pane capture, both `list` transcripts, the attach stdout/stderr/exit code, and the feature id `cli-session` under `.cursor/skills/verify-gondolin/artifacts/cli-session/$GONDOLIN_VERIFY_RUN_ID/`.

## Gotchas

- `gondolin bash -- /bin/sh -lc '...'` closes the VM when that command exits. It does not leave a session to attach to.
- `Ctrl-]` in the owner `gondolin bash` detaches and then closes that VM. The CLI prints `[gondolin] detached (Ctrl-])` and exits `130`.
- `gondolin attach` against a prefix matches one live id in `GONDOLIN_SESSIONS_DIR`. Use the full id printed by `list`.
- `gondolin list` removes stale session files. Run it only against the private sessions directory.
- Closing the tmux session with `tmux kill-session` without `exit` can leave a QEMU process. Record that pane's pid and run `.cursor/skills/verify-gondolin/helpers/cleanup.sh`.
