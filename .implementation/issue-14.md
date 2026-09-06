# Issue #14 implementation

Source: https://github.com/naveed949/gondolin/issues/14

This branch implements truthful exact-writer publication state and independent
host-staging cleanup reporting. Known publication must survive later failures;
ambiguous settlement must not imply rollback or permit automatic write retry.
The signed evidence contract must be versioned and incompatible consumers deny.

This is not durable crash recovery, full transaction atomicity, scoped-tree
qualification, or AdaptiveSandbox admission. Existing released artifacts stay
unchanged. All changes remain in naveed949/gondolin.

Implemented evidence v3 with exact-writer publication state, settlement phase,
target identities and input/prepared/final digests. Publication facts survive
later verification or staging cleanup failures. Uncertain publication syscalls
produce `indeterminate`; cleanup has a separate result, prevents complete
teardown when unsuccessful, and cannot erase known publication. Stale or uncertain
target pins invalidate; legacy and contradictory signed records reject.

Descriptor cleanup now tracks every publication-owned descriptor, preserves a
failed close as incomplete cleanup, and never retries an ambiguous close against
a possibly reused descriptor number. Review regression cases cover close faults
before and after publication, including close-then-throw behavior.

Local integration validation: 117 focused publication, evidence, capability,
scoped-runner and conformance tests passed with zero skips; direct TypeScript
checking and all three release packaging tests passed. `make check` was attempted:
host checks passed, but guest lint/build could not execute because Zig is absent.
Ten added real-VM fault cases require the KVM CI runner; no CI pass is claimed here.
The conformance command reports no pinned released bundle and zero verified rows.

Durable host-crash recovery, whole transaction atomicity, scoped directory-tree
authority and independent external/resource/teardown qualification remain outside
this increment. Evidence signing failure can still leave no signed receipt;
callers must not infer rollback or automatically retry from a missing result.
Native remains the default in AdaptiveSandbox and qualified runtime allowlists
remain empty. The version and existing released assets are unchanged.
