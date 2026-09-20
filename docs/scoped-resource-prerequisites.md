# Scoped resource prerequisites for AdaptiveSandbox

These implementation changes do not qualify a runtime combination. The
published `v0.12.1-adaptivesandbox.1` assets remain immutable; changes described
here require a new experimental release and independent conformance evidence.
Resource guarantees and qualified compatibility allowlists remain unverified
and empty, respectively.

## Linux CPU observation

The scoped runner binds `/proc/<pid>/stat` CPU counters to the QEMU process
start-time identity before dispatch. Each poll rejects missing or malformed
samples, identity changes, and counter regression. Losing this observer aborts
the invocation and prevents success, returning `host_controller_failure` for
otherwise successful or transport-failed execution. Independently known crash,
cancellation, timeout, command, and resource failures retain their outcomes;
lost observation is recorded separately. Teardown failure takes precedence.
The timer catches observation failures; they cannot escape as an unhandled
interval exception.

A final sample is taken before VM close. Crossing the CPU budget on that sample
cannot return success. Reporting after close uses only the last validated
sample, never a potentially reused PID. When no observer was established,
`resourceAccounting.usage.cpuTimeMs` is `null` and `observations.cpu` is
`unavailable`. If an established observer fails, its last measured lower bound
is retained and the source is `host-qemu-process-incomplete`. Guest CPU or an
invented zero never substitutes for an unavailable host measurement.

This remains a sampled QEMU-process CPU budget, with scheduler and 10 ms polling
overshoot. It includes QEMU work between baseline and final sample, rather than
measuring only payload CPU. It does not include arbitrary host helper process
CPU or prove that every host resource attributable to the invocation is bounded.
Linux start-time ticks improve PID-reuse detection but are not a kernel pidfd
identity. There is no macOS accounting implementation or macOS qualification.

## Remaining canonical and enforcement gaps

| Domain | Existing fork behavior | Required prerequisite or evidence |
| --- | --- | --- |
| Directory trees | Linux live-root identity, `openat2` resolution, and repository/private operation table exist as a source foundation; the profile is unsupported | Guest ambient confinement, payload launch through those roots, and independent qualification evidence |
| CPU | Host QEMU counter polling plus guest cgroup accounting | Defined attribution and overshoot contract, adversarial released-image enforcement evidence, and independent accounting checks |
| Memory | Whole-MiB guest RAM limit and guest cgroup limit/peak | Reconcile canonical byte budgets with alignment and VM overhead; independent peak and exhaustion evidence; guest reports do not constitute independent host accounting |
| Processes | Guest cgroup simultaneous PID limit/peak | Reconcile PID membership with AdaptiveSandbox descendant counts and independently validate complete-tree fork denial and cleanup |
| Storage | Aggregate bytes of exact ephemeral VFS files | Extend accounting to newly created tree descendants and metadata/resource exhaustion; validate unmounted/ambient writable escape denial |
| Teardown | `vm.close()` and host PID absence, with supplemental guest cgroup removal report | Independent observation of execution identity, remaining processes, transport and VFS handles, network channels, writable staging state, and resource controllers |

Host lifecycle registry entries bind evidence to the controller's execution;
they do not independently prove removal of those external resources. In
particular, assigning multiple teardown fields from the same successful close
and PID check does not supply independent evidence for each field.

AdaptiveSandbox's unchanged controlled/procedure qualification and independent
platform/performance checks must run against the exact new package/image
hashes. A Linux result cannot qualify macOS, and local unit tests with a fake VM
exercise settlement logic only. Tickets must remain open until the positive
canonical contracts and released-runtime evidence exist.

## Missing guest resource observations

The unreleased `qemu-cgroup-vfs/v2` accounting policy reports memory and PID
peaks as `null`, with observation source `unavailable`, when guest accounting
is absent or malformed. A measured zero remains zero. Missing required
accounting cannot yield success; independently known execution failures retain
their outcome, and teardown failure retains precedence. The evidence verifier
checks these measurement/source pairs and rejects success with unavailable
accounting. This changes the scoped-runner policy and qualification identity;
existing release pins do not inherit it. Guest reports remain guest observations,
not independent host qualification.

## Guest observation loss prerequisite

The next source revision adds guest feature `exec.resource-observation/v2` and
scoped resource evidence policy `qemu-cgroup-vfs/v3`. The daemon now treats
unreadable, truncated, missing, malformed, duplicate, overflowing or regressing
cgroup counters as observation failure. Polling requests payload termination on
that failure. Failure remains sticky through settlement: later readable counters
cannot repair the missing interval, and unavailable usage is encoded as null.
Previously observed exhaustion remains distinct from accounting loss.

The host requires the new binary-bound image feature before starting a scoped
invocation, checks explicit observation status, preserves known failure outcomes,
and refuses successful evidence when guest observation failed. Historical v2
receipts retain their original interpretation. This change requires a new reviewed
release before consumers can use it; `.7` assets and consumer pins are unchanged.

Guest tests cover strict parsing, counter regression, real control-file read loss
and recovery, and truncated input. Host tests cover null usage, observation loss
racing a successful exit, retained exhaustion, signed contradictory evidence and
old-image admission refusal. These tests do not independently qualify a runtime.
QEMU CPU accounting remains QEMU accounting, and the proposed
[scoped tree/payload profile](scoped-tree-payload-profile.md) is not enabled.
