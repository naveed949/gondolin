# Scoped tree and payload resource profile

Status: runtime implemented and advertised as `scoped-tree-runner` after
host/guest tests, including CI VM evidence. AdaptiveSandbox admission and
qualification remain pending.
Tracking: [AdaptiveSandbox #39](https://github.com/naveed949/AdaptiveSandbox/issues/39)
and [Gondolin #23](https://github.com/naveed949/gondolin/issues/23).
The reference is AdaptiveSandbox's `docs/scoped-runner-native-contract.md` at
`76dc07520a8c518824bd66ce0381451572ec33ba`.

## Version and ownership

Introduce a distinct `scoped-tree-runner/v1` profile. Preserve the existing
`scoped-runner` exact-file profile and its historical evidence. Availability must
be negotiated against the exact package, image, enforcement policy and observer
versions (`root-bound-openat2/v1`, `no-fork-landlock/v1`,
`payload-cgroup-wait4/v1`, guest feature `exec.scoped-tree-runner/v1`). The
public feature manifest advertises the profile as active after implementation
and runtime tests. A source design or parser is not an active guarantee.

AdaptiveSandbox alone selects a registered target from the public `{ target }`
argument and compiles effective canonical authority. Gondolin receives the
controller-owned target binding, root objects and limits; it does not accept
public commands, shell strings, environment projection, hooks or new authority
from the payload. The target binding includes the exact executable digest and
literal argument vector. Registration is trusted controller configuration, never
an invocation argument. The initial profile prohibits fork and subsequent exec.
Each supported target needs its own runtime evidence; the native characterization
of `malicious-runner` does not qualify other targets or a host syntax preflight.

## Filesystem objects and operations

The effective request supplies one repository read root and two fresh private
write roots for cache and temporary files. The controller retains device, inode
and creation-time identities at admission. Runtime acquisition verifies those
identities against opened directory descriptors before launching the payload.
Missing identity support or replacement denies at the corresponding capability
path. A replacement pathname never inherits an existing root grant.

The repository remains a live root-bound read tree. Enumerating files at admission
cannot implement its authority. Resolution must be atomic relative to the pinned
root and disallow escapes, including magic links and concurrent namespace changes.
Linux implementation therefore requires kernel-assisted resolution under the
pinned descriptor; a `realpath` check followed by an ordinary open is insufficient.
Internal symlinks may resolve only within the same admitted root, with bounded
resolution. Unsupported resolution must deny explicitly; silently denying all
symlinks cannot establish equivalence with the reference.

Private root objects are invocation-owned. Existing nested directories are
prepared before confinement and remain part of the bound authority. The runtime
must allow new regular-file names chosen after admission. It must enforce this
operation table separately for each root and for open handles:

| Operation                                                   | Repository        | Private root      |
| ----------------------------------------------------------- | ----------------- | ----------------- |
| Lookup, enumerate, read regular files                       | Allow within root | Allow within root |
| Create, write, truncate, unlink regular files               | Deny              | Allow             |
| Rename or hard-link a regular file in the same directory    | Deny              | Allow             |
| Rename or link across directories or roots                  | Deny              | Deny              |
| Create/remove directories, create symlinks or special files | Deny              | Deny              |
| Change ownership, mode, mounts or filesystem policy         | Deny              | Deny              |

Open handles retain object identity across allowed rename/unlink. A closed or
revoked handle never regains authority when its descriptor number is reused.
Concurrent invocations share neither writable objects nor handle registries.
Teardown closes all admitted handles and disposes private state, including
unlinked files with outstanding handles. Failure to observe either operation
prevents successful completion.

The guest must also confine ambient filesystems and descriptors. Host VFS checks
alone do not restrict writable guest mounts, procfs, inherited handles or devices.
Only controller-owned standard streams survive launch, with empty stdin. Payloads launch with an empty environment; controller, image and supervisor
environment must not be inherited. Independent membership-bound observations
must verify that environment and descriptor inventory under the reference's
seeded synthetic credential challenge, including ordered descriptor revocation.
Guest mount policy, executable policy and syscall policy must all be installed before
the payload is released from its start gate. Network, credentials, Git mutation,
undeclared IPC and devices remain denied.

## Payload resources

Bounds come directly from effective `ScopedTestLimits`. They are distinct from
runtime provisioning and must not be widened during translation.

| Field         | Required meaning                                                                         |
| ------------- | ---------------------------------------------------------------------------------------- |
| `cpuMs`       | Cumulative payload-subtree CPU, excluding VM boot and host QEMU overhead                 |
| `memoryBytes` | Payload cgroup charged peak and ceiling in bytes; no upward MiB rounding                 |
| `children`    | Maximum descendants, excluding the entrypoint; does not permit fork                      |
| `outputBytes` | Returned UTF-8 payload bytes, with independently specified transport and per-file bounds |
| `wallMs`      | Payload runner interval, with setup and teardown recorded separately                     |

The cgroup membership ceiling is checked `children + 1`; reported peak children
is checked `pidsPeak - 1` only when entrypoint membership is established. Missing
membership evidence is unavailable. CPU and memory are payload observations,
never QEMU CPU or VM RAM allocation relabeled as payload usage. A separate guest
supervisor can observe the payload but remains part of the runtime trust boundary;
its report is not independent qualification evidence.

Sampling must bind the execution and cgroup identities, validate required fields,
reject counter regression and preserve observation loss. A final sample cannot
erase an earlier gap. Missing, malformed, truncated, duplicate or overflowing
control counters are unavailable, never measured zero. A failed observer must
stop the payload and prevent success. Preserve any separately known exhaustion,
execution or cleanup failure alongside the observation failure.

Each observation has an execution-bound sequence and monotonic collection time.
The versioned observer policy declares a maximum sample age and collection
interval. Stale or out-of-order observations, missing sequence entries and
contradictory CPU/wait4, process-membership or peak/current measurements prevent
success, even when each individual counter is syntactically valid and monotonic.

The enforcement interval, polling period, CPU rounding allowance and overshoot
must appear in the versioned policy and qualification observations. The native
reference cross-checks cgroup CPU against wait4 with a 5 ms allowance. The new
profile must meet that contract or deny the CPU capability; increasing an
allowance to pass a fixture changes the contract. Memory provisioning overhead
is runtime configuration, not additional payload authority. Budget conversion
must fail before launch when the guest cannot enforce the admitted byte limit.

There is no aggregate writable-storage field in `ScopedTestLimits`. Do not derive
one from output bytes. Runtime safety bounds, metadata exhaustion and any resulting
failure need explicit policy and observation; they do not authorize extra
filesystem operations or establish a caller storage guarantee.

## Evidence, failure and revocation

Evidence binds canonical request and ceiling digests, target registration, root
identities, execution/VM/cgroup identities, runtime and policy versions, observer
provenance, operation decisions and actual accounting intervals. Unavailable
usage is nullable with explicit observation status. Success requires complete
required observations, within-bound usage, successful execution and independently
verified revocation. Known setup refusal is distinguishable from post-launch
failure. Do not derive several independent revocation claims from one `vm.close()`.

Private state is never a controlled publication candidate. Apply
[ADR 0005](https://github.com/naveed949/AdaptiveSandbox/blob/76dc07520a8c518824bd66ce0381451572ec33ba/docs/decisions/0005-effect-settlement-and-authority-revocation.md)'s
separate execution, settlement and authority-revocation facts without claiming
durable publication. Missing observation is not proof that effects were absent.
Cleanup failure retains uncertainty and containment requirements.

Historical exact-file evidence retains its original policy and limitations.
Receipt-only replay verifies retained evidence without launching the runtime,
reopening filesystem authority, executing recovery or producing external effects.
An old receipt must not gain new resource or revocation guarantees through parsing.

## Implementation and release gates

1. Review this contract against S01–S12 before implementing the profile.
2. Correct guest accounting loss handling, then add atomic root resolution,
   operation-specific VFS enforcement, payload policy and resource accounting.
   Each prerequisite may merge independently, without advertising profile support.
   The Linux live-root identity/`openat2`/operation-table foundation is the next
   source prerequisite after guest observation-loss handling; it does not enable
   the profile or payload launch.
3. Run actual guest tests and independent ordinary-Gateway S01–S12 observations.
   Require positive controls, concurrent disjoint invocations, fault injection at
   real boundaries and receipt replay. Fake-VM tests validate logic only.
4. Review and merge source and release preparation; publish a new immutable
   experimental package/helper/image release through `docs/fork-releases.md`.
5. AdaptiveSandbox pins that release. Positive admission requires #38 and exact
   profile evidence; qualification requires the non-skipping released conformance
   bundle. Linux and macOS need separate supported implementation and evidence.

Parent issues, empty qualified allowlists and the native default remain unchanged
until their own acceptance criteria are satisfied.
