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
  allowedExecutables: ["/bin/cat"],
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
  launch: { executable: "/bin/cat", args: ["/data/input.txt"] },
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
disabled exactly as in the original profile. In both variants the guest process
receives an explicitly empty environment. Output and wall time are bounded before
the process starts, and the base guest root filesystem is attached read-only.

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

The selected image must declare `exec.clear-env/v1` in its bound asset manifest.
Older images that do not advertise the guest-side clean-environment
implementation are rejected before the VM is started.

Every admitted call creates a new QEMU VM and fresh execution identity. The
promise settles only after `VM.close()` succeeds. Its result separates requested,
granted, attempted, denied, and observed effects and binds them to SHA-256 request,
ceiling, input, image, and kernel identities. Network evidence records
host-observed flow classifications, methods, normalized destinations, ports,
redirect decisions, resolution and connection checks, and completion. Resolved
addresses are represented by SHA-256 identities, and request/response payloads
are not retained. Evidence contains resource digests and guest paths, never host
file contents or environment values.

Use `getCapabilityInvocationFeatureManifest()` before requiring a feature. The
manifest reports HTTP/1.x, TLS-mediated HTTP/1.x, checked host resolution,
redirect reauthorization, internal-range handling, and synthetic DNS separately
from raw TCP, SSH, WebSockets, HTTP/2, HTTP/3, QUIC, trusted DNS, and open DNS.
It also marks libkrun, Windows, host-platform qualification, general runners,
credentials, Git, IPC, devices,
and unimplemented resource controls as unsupported or unverified. A required
feature that is not active must not be treated as degraded success.

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
  allowedExecutables: ["/bin/sh"],
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
    executable: "/bin/sh",
    args: ["-c", "printf report > /data/output.txt"],
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
meaningless create-only grant. Rename, delete, metadata mutation, link creation,
execute, parent-directory mutation, Git metadata, reads, networking,
credentials, IPC, and devices are not granted by this profile.

Before admission, host targets are canonicalized and Git paths, symlinks, and
hard-linked files are rejected. Existing target device/inode identity, missing
target state, and parent-directory identity are pinned at ceiling creation and
rechecked before execution and commit. Guest writes occur only in a fresh
memory VFS. Host hooks deny reads and every non-target or unsupported operation.
Only after the disposable VM has stopped is the private result committed through
a no-follow, identity-checked descriptor. Creating an exact target therefore
does not expose its parent directory to the guest. A rejected or failed host
commit returns the distinct `commit_failure` outcome; it is never reported as a
successful invocation.

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
  lifecycle: { maxOutputBytes: 64 * 1024, maxWallTimeMs: 10_000 },
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
  lifecycle: { outputBytes: 32 * 1024, wallTimeMs: 5_000 },
  requiredGuarantees: [...SCOPED_RUNNER_GUARANTEES],
});
```

The request must state every authority domain. Omitted and unknown domains fail
closed. Read inputs are snapshotted after device/inode verification. Write files
are invocation-private and begin empty; only their final SHA-256 digests enter
evidence, and the bytes are destroyed during teardown. The read and write path
sets must be disjoint, and VFS operations outside the exact set are denied.

Process policy is carried over the authenticated exec channel and installed by
the guest before the entrypoint starts. Linux Landlock restricts `execve` to the
entrypoint plus the declared descendants, and the restriction is inherited by
forked children. To avoid inode-alias bypasses, executable paths must resolve to
themselves and identify files with one hard link. Shell mode is separate
declarative data and is admitted only when `allowShell` is true in the immutable
ceiling; direct mode never adds an implicit shell.

`process.descendants: "deny"` grants no additional executable path beyond the
entrypoint; it does not claim a general prohibition on `fork` or entrypoint
re-execution. Accordingly, `process.descendants-denied` remains unsupported in
the feature manifest while the exact descendant allow-list is active.

Cancellation, wall-time expiry, output overflow, policy denial, guest crash,
transport failure, and teardown failure have distinct structured outcomes. The
call settles only after the disposable QEMU process has stopped, which proves
that the invocation process tree is empty and revokes its VFS, executable
policy, transport, and writable state. Process lifecycle and filesystem effects
are bound to the canonical request, immutable ceiling, execution identity,
image, kernel, and VMM identities.

The scoped-runner slice does not claim complete CPU, memory, PID, or writable
storage budgets. Those guarantees remain `unsupported` in the feature manifest
until their separate conformance slice is implemented.
