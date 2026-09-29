# HTTP egress policy

HTTP egress policy lets a guest call an allowlisted host and holds the real secret on the host. The guest environment receives a placeholder. A request to any other host is forbidden.

## Sub-features

- `egress-placeholder` shows a guest env value different from the host secret.
- `egress-deny` returns HTTP 403 for a host outside `--allow-host`.
- `egress-allow` returns HTTP 200 from an allowlisted public host.

## How to get to it (user POV)

- Run `gondolin exec --host-secret NAME@HOST=VALUE -- <command>`.
- Run `gondolin exec --allow-host <host> -- <command>`.
- Pass `createHttpHooks({ allowedHosts, secrets })` into `VM.create` together with the returned `env`.

## Driving it with verify-gondolin

Preconditions:

- Doctor printed `status=ready` for this `GONDOLIN_VERIFY_RUN_ID`.
- `GONDOLIN_SESSIONS_DIR` is `$GONDOLIN_VERIFY_ROOT/sessions`.
- The secret value used below is `verify-secret-value`.
- `egress-allow` needs outbound HTTPS from the host to `example.com`.

- **Show the placeholder.** Run `node host/dist/bin/gondolin.js exec --vmm qemu --host-secret VERIFY_TOKEN@example.com=verify-secret-value -- /bin/sh -lc 'printf %s "$VERIFY_TOKEN"'`. Exit code `0`. Stdout is non-empty and is not `verify-secret-value`.
- **Deny a host.** Run `node host/dist/bin/gondolin.js exec --vmm qemu --allow-host example.com -- /bin/sh -lc 'curl -sS -o /dev/null -w "%{http_code}\n" http://example.org/'`. Exit code `0`. Stdout is `403`.
- **Allow a host.** Run `node host/dist/bin/gondolin.js exec --vmm qemu --allow-host example.com -- /bin/sh -lc 'curl -sS -o /dev/null -w "%{http_code}\n" https://example.com/'`. Exit code `0`. Stdout is `200`.
- **Proof.** Save each command, stdout, stderr, and exit code under `.cursor/skills/verify-gondolin/artifacts/http-egress/$GONDOLIN_VERIFY_RUN_ID/` with feature id `http-egress`. A `403` on `example.org` does not prove the `egress-allow` sub-feature.

## Gotchas

- `--host-secret NAME` with no `@host` and no `=value` reads `$NAME` and may prompt for host suggestions. Verification passes `NAME@HOST=VALUE`.
- `--allow-host` is the guest-visible allowlist. `example.com` does not allow `example.org`.
- Hosts that resolve to internal addresses stay blocked when an allowlist entry would otherwise match them.
- The guest image `alpine-base` provides `/usr/bin/curl`. Invoke it via `/bin/sh -lc` so the shell can find `curl`.
- Placeholder proof is the guest stdout. Reading the host environment is not the guest view.
