# AdaptiveSandbox Conformance

Gondolin does **not currently claim AdaptiveSandbox conformance**. The checked-in
pin names the exact AdaptiveSandbox release `v0.1.0-conformance.2`. Compatibility
rows stay `unverified` or `unsupported`. A pinned bundle is not a qualification.

This distinction is deliberate. Ordinary `VM.exec()` behavior, lower-level
tests, and the presence of Capability Invocation profiles are not a substitute
for an exact released qualification run.

## Qualification boundary

The qualification adapter accepts backend-neutral ceilings and invocation
requests and passes them to `CapabilityInvocationContext` or
`ScopedRunnerInvocationContext`. It does not contain an AdaptiveSandbox policy
compiler, tool registry, Controlled Plan IR, transaction manager, verifier,
Procedure Unit language, authority resolver, or receipt signer.

The adapter creates a new context for each `invoke` message. Each admitted
request therefore uses the public Capability Invocation seam and receives a
fresh one-shot QEMU VM, VFS graph, policy, execution identity, and teardown.
Controlled-execution qualification supplies opaque producer and verifier
principal identities plus the independent comparison result for their declared
authority sets. The report validator requires disjoint authority, distinct
principals, distinct VM and execution IDs, and completed teardown; Gondolin only
links their independently verified evidence.

This is portable **Linux guest enforcement hosted on Linux or macOS**. It is not
native cross-platform enforcement. Linux and macOS rows are qualified
separately for each host architecture. Windows is unsupported, and experimental
libkrun remains unverified rather than inheriting a QEMU result.

## Reproducible release pin

[`conformance/adaptivesandbox-bundle.pin.json`](../conformance/adaptivesandbox-bundle.pin.json)
is strict and fail closed. The reviewed pin provides:

- an exact semantic bundle version and matching immutable release tag;
- a direct asset URL beneath that exact GitHub release, never a branch or
  `latest` URL;
- a lowercase SHA-256 identity for the exact asset bytes; and
- a fixed Node invocation containing `{artifact}`, `{adapter}`, and `{report}`
  placeholders.

`check` validates the pin and matrix and does not download the bundle. GitHub
Actions runs `check` because the repository's default `GITHUB_TOKEN` cannot read
private `naveed949/AdaptiveSandbox`. `qualify` and `qualify-if-pinned` download
the asset, hash the bytes before execution, and reject substitution.
AdaptiveSandbox is private, so an anonymous fetch of the asset URL returns HTTP
404. When `GH_TOKEN`, `GITHUB_TOKEN`, or `gh auth token` can read that
repository, the runner sends the value as a Bearer token on the GitHub download
and does not print it. A 401 or 404 still fails closed. A manually forced
qualification fails while the pin is unavailable:

```bash
npm run conformance:check
npm run conformance:ci
npm run conformance:qualify
```

`conformance:ci` attempts that download whenever the pin is `pinned`. It does
not run in GitHub Actions.

## Capability adapter protocol

The released bundle starts
`host/bin/adaptivesandbox-capability-adapter.ts` and exchanges one JSON object
per line. Responses repeat the caller's `id` and contain either
`{"ok":true,"value":...}` or a non-sensitive fail-closed error.

Supported operations are:

- `manifest`: returns the exact capability feature manifest and trusted
  evidence-verifier identity;
- `invoke`: accepts an opaque `principalId`, a complete declarative `ceiling`,
  and a complete `request`, then returns the public result plus a separately
  retained teardown probe;
- `verify`: verifies result signatures and exact caller-retained bindings and
  requires independent filesystem, process, resource, network, credential,
  request, and teardown checks; and
- `controlled-link`: requires the independent authority comparison to report no
  overlap, then confirms distinct producer/verifier principals, distinct
  one-shot VM and execution identities, and completed teardown on both runs.

Test credentials, when required, are read from the trusted host-only JSON file
named by `GONDOLIN_CONFORMANCE_CREDENTIALS_FILE`. Capability requests contain
only opaque credential references; values are never accepted in the capability
policy or emitted by the adapter.

## Earned compatibility rows

[`conformance/compatibility-matrix.json`](../conformance/compatibility-matrix.json)
is the machine-readable source of support claims. Each row binds:

- Gondolin, capability-schema, evidence-schema, and AdaptiveSandbox bundle
  versions;
- feature-manifest and policy-version digests;
- the AdaptiveSandbox bundle digest;
- VMM and exact QEMU version plus executable digest;
- guest image and kernel digests;
- host platform, host architecture, and guest architecture; and
- `verified`, `unverified`, or `unsupported` status.

An identity may be absent only on a non-verified row. A verified row requires
every identity, must match the checked-in bundle pin exactly, cannot contain
security failures, fixture skips, or false denials, and must publish measured
reader, writer, and runner workloads. Any recorded runtime or policy identity
change produces a different row and causes reproduction to fail.

The report validator requires passing exact-reader, exact-writer,
scoped-runner, environment, process, resource, HTTP/TLS, credential,
effect-evidence, replay-resistance, concurrency, failure, teardown,
controlled-execution, and dishonest-backend categories. Missing, failed, or
skipped required fixtures prevent `verified` status. Negative fixtures must
reject widened authority, forged or omitted effects, reused execution or VM
identities, stale manifests, runtime substitution, and premature teardown.

Reports publish security pass/fail/skip counts, allowed-fixture false denials
and rate, plus separate p50/p95 latency for cold boot, invocation setup, policy
installation, execution, observation, verification, and teardown for reader,
writer, and runner workloads. The Linux x64 QEMU row names the pinned bundle and
uses `unverified-pinned-bundle-http-tls-credential-skipped`: zero workload
samples, security counts `{passed: 0, failed: 13, skipped: 2}` from the
published fail-closed run (http-tls and credential skipped), and `unverified`
status. That summary is not a live measurement of this repository's adapter.
Other QEMU hosts, Windows, and libkrun do not claim the bundle result.
`not-run-no-released-bundle` remains their summary. No row is verified.

Procedure-generated operation compatibility stays `unverified` until a
released AdaptiveSandbox issue #24 conformance artifact proves every effect
uses the same invocation seam. Gondolin does not build a procedure platform.
