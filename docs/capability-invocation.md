# Capability Invocation API

The Capability Invocation API is Gondolin's public enforcement seam for
declarative, invocation-scoped authority. Version 1 qualifies three narrow
profiles in disposable QEMU microVMs: exact-reader, exact-writer, and
scoped-runner. Exact-reader supports either no network device or an
invocation-local HTTP/1.x and HTTP/1.x-over-TLS egress policy; the other
profiles remain network-free.

Existing `VM.exec()`, `VM.shell()`, VFS, networking, SSH, ingress, and CLI APIs
remain supported. They expose lower-level VM/session controls and are **not** an
AdaptiveSandbox-conformant capability invocation.

## Exact-reader v1

The trusted caller creates a context with an immutable maximum ceiling and then
submits a request below it:

```ts
import {
  CapabilityInvocationContext,
  EXACT_READER_GUARANTEES,
  HTTP_TLS_EGRESS_GUARANTEES,
} from "@earendil-works/gondolin";

const context = CapabilityInvocationContext.create({
  schemaVersion: "gondolin.capability-ceiling/v1",
  profile: "exact-reader",
  allowedExecutables: ["/bin/busybox"],
  filesystem: {
    sourcePaths: ["/srv/inputs/report.txt"],
    guestPaths: ["/data/input.txt"],
  },
  // Omit this field for the original no-network exact-reader ceiling.
  network: {
    rules: [
      {
        protocol: "tls",
        destination: "api.example.com",
        port: 443,
        methods: ["GET"],
        redirects: "deny",
        resolution: "checked-host",
        internalRanges: "deny",
      },
    ],
  },
  limits: { maxOutputBytes: 64 * 1024, maxWallTimeMs: 10_000 },
  guarantees: [...EXACT_READER_GUARANTEES, ...HTTP_TLS_EGRESS_GUARANTEES],
});

const result = await context.invoke({
  schemaVersion: "gondolin.capability-invocation/v1",
  invocationId: "report-reader-001",
  profile: "exact-reader",
  launch: {
    executable: "/bin/busybox",
    args: ["cat", "/data/input.txt"],
  },
  capabilities: {
    filesystem: {
      sourcePath: "/srv/inputs/report.txt",
      guestPath: "/data/input.txt",
      operations: ["read"],
    },
    network: {
      rules: [
        {
          protocol: "tls",
          destination: "api.example.com",
          port: 443,
          methods: ["GET"],
          redirects: "deny",
          resolution: "checked-host",
          internalRanges: "deny",
        },
      ],
    },
    environment: {},
  },
  limits: { outputBytes: 32 * 1024, wallTimeMs: 5_000 },
  requiredGuarantees: [
    "http-tls-egress",
    "checked-resolution",
    "redirect-reauthorization",
    "invocation-network-identity",
    "network-channel-teardown",
  ],
});
```

For the original exact-reader behavior, omit `ceiling.network`, set
`capabilities.network` to `"none"`, and require
`EXACT_READER_GUARANTEES`. A network-enabled request must not require the
contradictory `no-network` guarantee.

Admission is strict and happens before QEMU is created. Unknown fields or
versions, non-canonical paths, unsupported operations or guarantees, ceiling
widening, and empty ceilings fail closed with `CapabilityAdmissionError`.
Requests use direct absolute executables and literal arguments; there is no
implicit shell interpretation.

The selected host file's device and inode identity are pinned when the immutable
ceiling is created. Every invocation opens it without following the final symlink,
verifies the descriptor still has that identity, and copies it into an
invocation-private, read-only VFS snapshot. Version 1 requires its guest path to
be a direct child of `/data`. With `network: "none"`, the network device is
disabled exactly as in the original profile. Without credential projections the
guest process receives an explicitly empty environment; credential-aware
invocations receive only their fresh placeholders. Output and wall time are
bounded before the process starts, and the base guest root filesystem is
attached read-only.

## HTTP/TLS egress rules

Network rules are declarative data. The request cannot contain functions,
custom fetch implementations, policy callbacks, hooks, wildcard destinations,
or implicit ports. Hostnames are IDNA-normalized, lowercased, and matched
exactly; IP literals are canonicalized. Rules with the same
protocol/destination/port are rejected as ambiguous. Methods are uppercase and
limited to `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, and `OPTIONS`;
`CONNECT` is not HTTP authority in this profile.

`protocol: "http"` authorizes HTTP/1.0 or HTTP/1.1 over plain TCP.
`protocol: "tls"` authorizes those HTTP versions through Gondolin's TLS
mediator. It does not authorize opaque TLS. `resolution: "checked-host"` uses
synthetic DNS inside the guest and checks every host-side resolution candidate
again when the upstream connection is established. `internalRanges: "deny"`
rejects loopback, private, link-local, multicast, and IPv4-mapped internal
answers; `"allow"` is effective only when the immutable ceiling also allows it
for that exact origin.

Redirect policy is `"deny"`, `"same-origin"`, or `"follow-authorized"`. Every
redirect hop is checked before the next request is sent. `"same-origin"` keeps
the protocol, normalized destination, and port fixed. `"follow-authorized"`
still requires the target protocol, destination, port, and rewritten method to
match another granted rule. This means a 301/302/303 rewrite from `POST` to
`GET`, for example, requires `GET` authority at the target.

Raw TCP, mapped TCP, SSH, open or trusted guest DNS, WebSockets, HTTP/2,
HTTP/3, QUIC, and other UDP transports are separate unsupported features and
fail closed. The network stack and upstream connection pools belong to the
fresh VM and are closed before a network-enabled invocation settles.

## Destination-bound HTTP/TLS credentials

The exact-reader HTTP/TLS profile can project credentials without putting real
values in capability policy. Values live in a separate trusted host store;
ceilings and requests contain only opaque references and exact authority:

```ts
import {
  CapabilityCredentialStore,
  CapabilityInvocationContext,
  DESTINATION_BOUND_CREDENTIAL_GUARANTEES,
  EXACT_READER_GUARANTEES,
  HTTP_TLS_EGRESS_GUARANTEES,
} from "@earendil-works/gondolin";

const credentialStore = CapabilityCredentialStore.create({
  "credential/github-api": {
    value: process.env.GITHUB_TOKEN!,
    redactionId: "github-api-token",
    protocol: "tls",
    destination: "api.github.com",
    port: 443,
    methods: ["GET"],
    expiresAt: "2030-01-01T00:00:00Z",
  },
});

const projection = {
  reference: "credential/github-api",
  projection: "GITHUB_TOKEN",
  redactionId: "github-api-token",
  protocol: "tls" as const,
  destination: "api.github.com",
  port: 443,
  methods: ["GET" as const],
  validity: { expiresAt: "2030-01-01T00:00:00Z" },
};

const context = CapabilityInvocationContext.create(
  {
    schemaVersion: "gondolin.capability-ceiling/v1",
    profile: "exact-reader",
    allowedExecutables: ["/bin/busybox"],
    filesystem: {
      sourcePaths: ["/srv/inputs/request.txt"],
      guestPaths: ["/data/input.txt"],
    },
    network: {
      rules: [
        {
          protocol: "tls",
          destination: "api.github.com",
          port: 443,
          methods: ["GET"],
          redirects: "deny",
          resolution: "checked-host",
          internalRanges: "deny",
        },
      ],
    },
    credentials: { projections: [projection] },
    limits: { maxOutputBytes: 64 * 1024, maxWallTimeMs: 10_000 },
    guarantees: [
      ...EXACT_READER_GUARANTEES,
      ...HTTP_TLS_EGRESS_GUARANTEES,
      ...DESTINATION_BOUND_CREDENTIAL_GUARANTEES,
    ],
  },
  { credentialStore },
);

const result = await context.invoke({
  schemaVersion: "gondolin.capability-invocation/v1",
  invocationId: "github-user-001",
  profile: "exact-reader",
  launch: {
    executable: "/bin/busybox",
    args: [
      "sh",
      "-c",
      'wget -qO- --header="Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/user',
    ],
  },
  capabilities: {
    filesystem: {
      sourcePath: "/srv/inputs/request.txt",
      guestPath: "/data/input.txt",
      operations: ["read"],
    },
    network: {
      rules: [
        {
          protocol: "tls",
          destination: "api.github.com",
          port: 443,
          methods: ["GET"],
          redirects: "deny",
          resolution: "checked-host",
          internalRanges: "deny",
        },
      ],
    },
    environment: {},
    credentials: { projections: [projection] },
  },
  limits: { outputBytes: 32 * 1024, wallTimeMs: 5_000 },
  requiredGuarantees: [
    ...HTTP_TLS_EGRESS_GUARANTEES,
    ...DESTINATION_BOUND_CREDENTIAL_GUARANTEES,
  ],
});
```

`value` is accepted only by `CapabilityCredentialStore`, never by a capability
ceiling or request. Admission intersects a projection's reference, environment
name, redaction identity, protocol, exact destination, port, methods, and
validity with both the immutable credential ceiling and active network grant.
Duplicate references or projection names are ambiguous and rejected.

Every invocation gets a fresh, execution-bound placeholder. The live host store
is checked at each redemption, so missing, deleted, revoked, not-yet-valid,
expired, or scope-mismatched entries fail before the affected request is sent.
`credentialStore.set()` rotates a value, `revoke()` disables a reference, and
`delete()` removes it from use. A placeholder from a completed or different
invocation is recognized as stale and denied rather than forwarded.

Substitution is limited to HTTP request headers, including placeholders inside
Basic authentication. Query strings and request bodies are not credential
transports. Each redirect hop and rewritten method is re-authorized, DNS and
connection addresses retain the HTTP/TLS checks above, and disposable-VM
connection pools cannot transfer credential authority between invocations.

Credential evidence retains only the SHA-256 reference identity, projection,
redaction identity, exact destination scope, operation, and safe denial reason.
Current and rotated/revoked values are redacted from response headers and
bodies before they reach the guest and again from captured output and errors.
Teardown clears the mediator's placeholder table and reports
`credentialProjectionsRevoked` before successful settlement. Raw TCP, SSH,
WebSocket, query, body, and external broker credential transports remain
unsupported.

The selected image must declare `exec.clear-env/v1`,
`exec.executable-mount-policy/v1`, `exec.exact-path-lsm/v1`,
`exec.payload-confinement/v1`, and `exec.landlock-allowlist/v1` in its
bound asset manifest. Exact-reader and exact-writer send the single admitted
entrypoint as the complete-tree executable allow-list. A private noexec root
view re-enables execution only on that exact file and the read-only
runtime-library directories required by the ELF loader. Landlock permits the
admitted executable and its recorded ELF interpreter. A cgroup-bound BPF LSM
guard checks the original executable pathname, preventing direct loader
invocation and symlink aliases from widening the allow-list. The guard remains
pinned until the invocation cgroup is removed. Older images that lack any
implementation are rejected before the VM is started.

Exact executable admission supports native 64-bit little-endian ELF files.
Shebang scripts are not supported as direct entrypoints. Where the profile
allows it, callers can explicitly admit a native interpreter and supply its
script as an argument; this grants that interpreter's behavior within the
remaining invocation limits.

Every admitted call creates a new QEMU VM and fresh execution identity. The
promise settles only after `VM.close()` succeeds. Its result separates requested,
granted, attempted, denied, and observed effects and binds them to SHA-256 request,
ceiling, input, image, and kernel identities. Network evidence records
host-observed flow classifications, methods, normalized destinations, ports,
redirect decisions, resolution and connection checks, and completion. Resolved
addresses are represented by SHA-256 identities, and request/response payloads
are not retained. Evidence contains resource digests and guest paths, never host
file contents or environment values.

## Authenticated evidence and concurrent isolation

Capability evidence version 2 authenticates every host-observed filesystem,
network, credential, process, resource, and lifecycle record with the fresh
execution identity and a strictly increasing execution-local sequence. The host
identity lease is bound first to the canonical request and immutable ceiling,
then to exactly one disposable VM. It accepts events only while active. A lease
cannot be rebound, and completed or revoked identities remain rejected for a
24-hour retention window.

Every evidence payload records the Gondolin, request, evidence, feature-manifest,
runtime, image, kernel, guest architecture, and policy identities which formed
its exact qualification. It also records the final outcome and a digest of the
public command result. The canonical payload is signed with an Ed25519 host key,
so tampering, truncation, reordering, duplication, omission, cross-run splicing,
and request, VM, backend, or result substitution fail verification.

Use `getCapabilityEvidenceVerifierIdentity()` on the trusted controller and pin
that returned key outside untrusted guest state. Pass it to
`verifyCapabilityInvocationResult()` when evidence crosses a process or trust
boundary. The verifier checks the signature, exact optional caller bindings,
event identities and sequences, runtime/policy qualification, result digest,
and the rule that `success` is impossible until every reported teardown gate is
true. By default it trusts only the current controller process key; an embedded
key alone is never accepted as proof of host authorship.

`probeCapabilityInvocationTeardown()` is an independent process-local check of
retained host execution state. It confirms that the identity is no longer
active, that teardown was verified before completion, and that the retained
request, ceiling, and VM bindings match the caller's expectations. The probe is
not derived from the returned evidence object.

Concurrent calls never install mutable VM-wide invocation policy. Exact readers,
exact writers, scoped runners, network channels, and credential projections each
receive their own VM, VFS/provider graph, environment, output sinks, process and
resource boundary, HTTP connection pools, credential placeholder table, evidence
recorder, and execution identity. Therefore simultaneous requests remain an
intersection with their own canonical request and ceiling; they cannot combine
their grants into a union.

Use `getCapabilityInvocationFeatureManifest()` before requiring a feature. The
manifest reports HTTP/1.x, TLS-mediated HTTP/1.x, checked host resolution,
redirect reauthorization, internal-range handling, and synthetic DNS separately
from raw TCP, SSH, WebSockets, HTTP/2, HTTP/3, QUIC, trusted DNS, and open DNS.
It reports destination-bound HTTP/TLS header credentials independently from
unsupported query, body, raw TCP, SSH, and external broker credential
transports. It also marks libkrun, Windows, host-platform qualification,
general runners, Git, IPC, and devices as unsupported or unverified.
Scoped-runner resource enforcement is implemented only on its documented
QEMU/Linux path, but its public resource guarantees and operations remain
`unverified` until an exact released runtime combination passes qualification.
A required feature that is not active must not be treated as degraded success.

## Exact-writer v1

The exact-writer profile binds one invocation to one canonical host target and
grants only an explicit subset of `create`, `write`, and `truncate`:

```ts
import {
  CapabilityInvocationContext,
  EXACT_WRITER_GUARANTEES,
} from "@earendil-works/gondolin";

const context = CapabilityInvocationContext.create({
  schemaVersion: "gondolin.capability-ceiling/v1",
  profile: "exact-writer",
  allowedExecutables: ["/bin/busybox"],
  filesystem: {
    targetPaths: ["/srv/results/report.txt"],
    guestPaths: ["/data/output.txt"],
    operations: ["create", "write", "truncate"],
  },
  limits: { maxOutputBytes: 64 * 1024, maxWallTimeMs: 10_000 },
  guarantees: [...EXACT_WRITER_GUARANTEES],
});

const result = await context.invoke({
  schemaVersion: "gondolin.capability-invocation/v1",
  invocationId: "report-writer-001",
  profile: "exact-writer",
  launch: {
    executable: "/bin/busybox",
    args: ["sh", "-c", "printf report > /data/output.txt"],
  },
  capabilities: {
    filesystem: {
      targetPath: "/srv/results/report.txt",
      guestPath: "/data/output.txt",
      operations: ["write", "truncate"],
    },
    network: "none",
    environment: {},
  },
  limits: { outputBytes: 32 * 1024, wallTimeMs: 5_000 },
  requiredGuarantees: [...EXACT_WRITER_GUARANTEES],
});
```

The immutable ceiling names every eligible host target, guest binding, and
operation. A request selects exactly one target and a non-empty operation
subset. Missing targets require `create`; an existing target cannot receive a
meaningless create-only grant. Guest-visible rename, delete, metadata mutation,
link creation, execute, parent-directory access, Git metadata, reads,
networking, credentials, IPC, and devices are not granted by this profile.

Before admission, host targets are canonicalized and Git paths, symlinks, and
hard-linked files are rejected. Existing target device/inode identity, missing
target state, and parent-directory identity are pinned at ceiling creation and
rechecked before execution and commit. After an authorized atomic publication,
the context advances only that target's pin to the host-published inode so later
invocations remain usable without accepting an external replacement. Guest
writes occur only in a fresh memory VFS. Its exact output inode is prepared
before Landlock setup, including an empty placeholder when the host target does
not yet exist. The guest therefore sees an existing output path; it must not rely
on an exclusive-create syscall or absence check to infer host target state.
The first authorized writable open or mutation records logical creation, while
unused placeholders are never published. Initial zero-length truncation of a
still-empty new output is part of creation; truncation after writing content
requires explicit `truncate` authority. Landlock grants write access to only the
prepared file inode, never its parent. Host hooks deny reads and every non-target
or unsupported operation.
Only after the disposable VM has stopped is the private result copied to a
private staging inode in the pinned parent and atomically published at the exact
target path. The original inode is never mutated during publication, so a
concurrently created hard-link alias retains the original bytes. Creating an
exact target therefore does not expose its parent directory to the guest. This
host-mediated publication is part of the exact-writer contract: the host must
be able to create a private staging directory and replace the selected directory
entry. The `atomic-target-replacement` guarantee names this host authority
explicitly. For an existing target it preserves owner, group, and permission
bits, but intentionally publishes a new inode; ACLs, extended attributes, inode
flags, and timestamps are not preserved. A target whose parent cannot support
that publication is rejected with the distinct `commit_failure` outcome; it is
never reported as a successful invocation.

Writer evidence keeps requested, granted, attempted, denied, and observed
effects separate, identifies resources by digest without recording content,
and includes before/after content digests. Each invocation receives a fresh VM,
execution identity, VFS policy, and teardown record. Selecting another target
changes both the canonical request digest and enforced resource identity.

The feature manifest advertises only `filesystem.create.exact`,
`filesystem.write.exact`, and `filesystem.truncate.exact` as active writer
operations. Broad write, rename, delete, metadata, link, execute, libkrun,
Windows, and other unqualified capability domains remain unsupported or
unverified.

## Scoped-runner v1

`ScopedRunnerInvocationContext` runs one approved direct executable with exact
repository snapshots, exact ephemeral output files, a clean projected
environment, an explicit working directory, and an inherited executable
allow-list for the complete process tree:

```ts
import {
  SCOPED_RUNNER_GUARANTEES,
  ScopedRunnerInvocationContext,
} from "@earendil-works/gondolin";

const runner = ScopedRunnerInvocationContext.create({
  schemaVersion: "gondolin.capability-ceiling/v1",
  profile: "scoped-runner",
  allowedExecutables: ["/opt/tools/compiler"],
  allowedDescendantExecutables: ["/opt/tools/linker"],
  allowShell: false,
  allowedWorkingDirectories: ["/data/repo"],
  filesystem: {
    sourcePaths: ["/srv/repo/source.ts"],
    readGuestPaths: ["/data/repo/source.ts"],
    writeGuestPaths: ["/data/cache/output.bin"],
  },
  environment: { allowedNames: ["BUILD_MODE"] },
  limits: {
    maxCpuTimeMs: 10_000,
    maxMemoryBytes: 512 * 1024 * 1024,
    maxPids: 64,
    maxWritableStorageBytes: 128 * 1024 * 1024,
    maxOutputBytes: 64 * 1024,
    maxWallTimeMs: 10_000,
  },
  guarantees: [...SCOPED_RUNNER_GUARANTEES],
});

const result = await runner.invoke({
  schemaVersion: "gondolin.capability-invocation/v1",
  invocationId: "compile-001",
  profile: "scoped-runner",
  launch: {
    executable: "/opt/tools/compiler",
    args: ["source.ts", "-o", "/data/cache/output.bin"],
    cwd: "/data/repo",
    mode: "direct",
  },
  capabilities: {
    filesystem: {
      reads: [
        {
          sourcePath: "/srv/repo/source.ts",
          guestPath: "/data/repo/source.ts",
          operations: ["read"],
        },
      ],
      writes: [
        {
          guestPath: "/data/cache/output.bin",
          operations: ["write", "truncate"],
        },
      ],
    },
    environment: { BUILD_MODE: "release" },
    process: {
      descendants: "allow-list",
      allowedExecutables: ["/opt/tools/linker"],
    },
    network: "none",
    credentials: "none",
    git: "none",
    ipc: "none",
    devices: "none",
  },
  limits: {
    cpuTimeMs: 5_000,
    memoryBytes: 256 * 1024 * 1024,
    pids: 16,
    writableStorageBytes: 64 * 1024 * 1024,
    outputBytes: 32 * 1024,
    wallTimeMs: 5_000,
  },
  requiredGuarantees: [...SCOPED_RUNNER_GUARANTEES],
});
```

The request must state every authority domain. Omitted and unknown domains fail
closed. Read inputs are snapshotted after device/inode verification. Write files
are invocation-private and begin empty; only their final SHA-256 digests enter
evidence, and the bytes are destroyed during teardown. The read and write path
sets must be disjoint, and VFS operations outside the exact set are denied.

Process policy is carried over the authenticated exec channel and installed by
the guest before the entrypoint starts. The cgroup BPF LSM guard restricts
executable pathnames to the entrypoint plus the declared descendants, while
Landlock constrains admitted executable and interpreter inodes. These
restrictions also apply to forked children. To avoid inode-alias bypasses, executable paths must resolve to
themselves and identify files with one hard link. Shell mode is separate
declarative data and is admitted only when `allowShell` is true in the immutable
ceiling; direct mode never adds an implicit shell.

`process.descendants: "deny"` installs a pre-start cgroup PID ceiling of one,
so the admitted entrypoint may start but cannot fork, clone, spawn, or retain a
second process. Exact-reader and exact-writer invocations use the same explicit
no-descendants exec policy. The feature manifest advertises
`process.descendants-denied` only because the guest image declares and enforces
that protocol feature.

Each request independently contracts CPU time (`ms`), VM/process-tree memory
(`bytes`), simultaneous PIDs, aggregate exact-file writable storage (`bytes`),
combined output (`bytes`), and wall time (`ms`). Memory values are whole MiB
from 128 MiB through 64 GiB because the value is also the QEMU VM memory size.
The runtime `memory` option does not widen that request-selected VM boundary.

Resource admission is fail closed. The selected image must declare
`exec.resource-limits/v1`; sandboxd must create cgroup-v2 CPU-accounting,
memory, and PID controllers before releasing the child start gate; the QEMU
host PID and Linux `/proc` CPU accounting must also be available before the
entrypoint is dispatched. A degraded controller returns an `unsupported`
admission error after disposal of the unstarted invocation VM.

The cgroup contains the entrypoint before its first instruction and every fork
inherits membership. Linux Landlock simultaneously denies file creation,
namespace mutation, writes, and truncates outside the declared exact writable
files, so temporary directories, caches, root state, and other ambient guest
paths cannot become an unaccounted writable escape. The host VFS stops and
tears down the VM before an exact-file write can cross
`writableStorageBytes`.

The request also requires `exec.namespace-isolation/v1`. Before Landlock is
installed, sandboxd creates a private IPC namespace and a private mount
namespace with empty, non-executable tmpfs mounts over `/dev`, `/run`, `/tmp`,
and `/proc`. All capability profiles use this isolation. Inherited daemon file
descriptors are marked close-on-exec, all Linux capabilities are dropped, and
locked securebits prevent root execution from regaining them. An inherited
seccomp filter denies namespace creation and kernel injection interfaces;
Landlock scopes signals and abstract Unix sockets to the invocation domain.
Failure to install any required restriction fails the exec closed. These
restrictions apply per capability exec and do not change ordinary `VM.exec`
behavior.

The memory contract is deliberately whole-microVM for this one-invocation
profile. QEMU's `-m` value limits all guest RAM to the requested aligned
ceiling, while the guest cgroup applies the same ceiling to the complete
entrypoint process tree and reports `memory.peak`. No unrelated workload shares
the disposable VM, so guest RAM and process-tree accounting jointly cover the
only invocation; QEMU controller overhead is outside guest invocation memory.

CPU, memory, PID, storage, output, and wall-time exhaustion return respectively
`cpu_exhausted`, `memory_exhausted`, `pids_exhausted`, `storage_exhausted`,
`output_overflow`, and `timeout`. `resourceAccounting` binds the contracted
limits, host-observed QEMU CPU time, guest-cgroup peaks, host-observed writable
and output bytes, monotonic wall time, and terminating controller to the
execution identity. Guest-cgroup values are explicitly identified as guest
observations rather than host attestations.

The call settles only after the disposable QEMU process has stopped. Teardown
is complete only when that boundary proves the process tree empty and the VFS,
resource controllers, transport, and writable state are gone. If sandboxd
returns normally it additionally reports whether it emptied and removed its
cgroup before responding.

This resource profile currently runs only on QEMU on Linux. Its resource
guarantees and operations, libkrun, and the general Linux host entry remain
`unverified`; Windows remains `unsupported`. Resource status becomes `active`
only after an exact released image, kernel, architecture, and conformance bundle
combination passes the non-skipping qualification suite.

See [AdaptiveSandbox Conformance](adaptivesandbox-conformance.md) for the
released-artifact pin, public-seam adapter, compatibility matrix, required
negative fixtures, and reporting rules. The current matrix makes no conformance
claim because AdaptiveSandbox has not released a bundle to qualify.
