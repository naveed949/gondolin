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
| Directory trees | Scoped reads and ephemeral writes are exact predeclared files | Canonical directory-root authority with descendant create/remove/rename semantics, safe symlink handling, and bounded accounting across all mutations; enumerating current files does not preserve tree authority |
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
