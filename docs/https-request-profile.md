# Credential-free HTTPS runtime prerequisites after release .4

Inspected `gondolin-network47` at ba894ab, its AGENTS.md/README, the installed Undici connector implementation, the #47 specification, and AdaptiveSandbox's canonical-network-v2 documentation. This is a proposed contract, not implemented or qualified behavior. Changes belong only in naveed949/gondolin.

## Recommendation

Implement one coherent fork batch before another release: a dedicated `https-request` one-shot profile, mediator bounds and authenticated response observations, actual connected-peer/TLS observations, and source integration tests. Prepare the AdaptiveSandbox adapter and packaged Gateway smoke against that contract in parallel, but activate neither from .4. Publish a new release only after reviewing the complete source implementation and identifying the external acceptance infrastructure still missing. Release .4 fixes public-address classification and awaited HTTP settlement; it does not fill these remaining guarantees.

Prefer the dedicated profile over extending exact-reader. Exact-reader requires a real host `sourcePath`, snapshots it before execution, and emits granted filesystem read effects. A fake backend-owned empty file would conceal a new storage dependency and confuse the canonical filesystem:none meaning. Supporting optional filesystem in exact-reader would also change an established profile invariant. A network-only profile can reuse lifecycle, evidence, executable restrictions, and empty snapshot machinery internally without granting any caller filesystem access. Its immutable image executable/libraries and mediator CA are runtime infrastructure, integrity-bound in the measured image; they are not invented caller-file grants.

## Proposed public contract

Keep existing reader/writer request, ceiling, digest, and evidence identities unchanged. Add explicitly named request and ceiling schemas for the HTTPS profile (for example `gondolin.https-request/v1` and `gondolin.https-ceiling/v1`) rather than silently adding defaulted fields to v1 network rules. A separate `HttpsInvocationContext` may share internal machinery without broadening the legacy union. Unknown fields/schema versions deny. Use an HTTPS-specific evidence schema (`gondolin.https-evidence/v1`) and manifest feature identity; this avoids forcing all existing v3 consumers to migrate for an unrelated profile. Alternatively, if a unified public controller is required, explicitly introduce capability request/ceiling v2 and evidence v4 and retain v1/v3 historical verification; do not call that migration backward compatible by inference.

A request contains invocationId, exact normalized URL, method GET or HEAD, and canonical-derived network bounds; filesystem, credentials, environment, request body, arbitrary headers, redirects, custom executable and arbitrary args are absent/denied. The ceiling carries correlated HTTPS origin/method/bounds rules with public-only resolution, plus finite controller output and wall-time limits. Request limits must be within one covering correlated ceiling rule; combining max bytes from one rule with timeout from another is forbidden. Pass only effective canonical policy into the ceiling. Controller runtime settings may contract limits, never enlarge them. Other canonical methods remain explicitly unsupported until implemented.

Use a fixed direct image `/usr/bin/curl` launch with literal arguments, no shell, no config files, proxy bypass, redirects or retries, no insecure TLS flag, an explicit mediator CA, HTTPS-only protocol, HTTP/1.1, and a fixed body/status framing contract. Verify curl and its exact interpreter/libraries in actual image CI. URL normalization must bind the identical serialized path/query sent upstream (fragment and userinfo denied); canonical authority remains origin-wide. URL identity in evidence can be a SHA-256 digest of normalized URL to avoid retaining query text in logs, bound to the full canonical request digest. Do not expose arbitrary URL-looking credential data as credential authority.

## Mediation, bounds and failure behavior

The existing `onResponse` path is downstream of body buffering in `host/src/qemu/http.ts`; checking size only in that hook is too late. The one-request profile can map its canonical maxResponseBytes directly into `VM.create({maxHttpResponseBodyBytes})`, because no second request with different bounds is admitted. Always install the response observation hook so the streaming bypass is unavailable. Also enforce one actual upstream attempt; disable retries at client and dispatcher levels and count every transmitted request, including possible transport retries. A second attempt denies and invalidates invocation success. This is a deliberate tool contraction, not additional canonical authority.

Define maxResponseBytes as decoded response entity bytes delivered to the caller, matching current AdaptiveSandbox policy wording. Undici fetch decompresses and the bridge strips content-encoding; hash and count precisely those resulting bytes. Bound while consuming the decoded stream, including absent/false Content-Length and compressed expansion, before exposing any successful public result. Do not claim this is a bound on wire bytes or all decompressor memory. Treat HEAD and 204/205/304 as empty response entities; status is independently bound. Binary results should use canonical base64, with decoded byte count and digest, avoiding text replacement or newline normalization.

Start a monotonic per-request deadline before mediation/DNS, not just after connect or response headers. Propagate its AbortSignal to resolver/connector/fetch/body consumption and settle host transport through the existing awaited lifetime registry. DNS APIs which cannot be cancelled must have late results discarded and must never open a socket after expiry. Invocation wall time is a separate possibly tighter deadline; VM startup need not consume the request timeout unless that is explicitly specified. Timeout/overflow/disconnect/redirect refusal produces authenticated failure state, never a successful shortened body. Cancellation stops new writes/requests and awaits closure; it does not reverse a request the remote server already received. Partial failure evidence records received byte counts only as observations and cannot masquerade as a complete body digest.

## Actual peer and TLS observation

The current `createLookupGuard` emits operation `connection` for DNS candidates before any connection exists. Preserve legacy semantics for legacy profiles; give the new schema distinct `resolution_candidate` and `connected_peer` event kinds.

Wrap Undici's installed `buildConnector` with its default TLS verification intact and the existing guarded lookup. Its callback runs at secureConnect for HTTPS. Before handing the socket back to Undici for HTTP writes, inspect remoteAddress/remotePort, reapply the public-address predicate to the actual peer, require a TLSSocket with authorized true, bind the authorized hostname/servername and verified TLS session, and emit a fresh connection identity. Reject and destroy on missing/invalid observation. Never accept a caller-supplied socket, proxy, custom fetch, alternate trust store, lookup bypass or rejectUnauthorized:false in this profile. Default TLS verification must not be weakened by process environment; reject or sanitize unsupported global trust overrides before admitting a measured runtime.

Associate response provenance with that connection identity. For the first slice, disable connection reuse and allow one outstanding request, avoiding ambiguous request-to-socket mapping. A process-global diagnostics-channel listener without invocation filtering would not provide safe correlation. Unit tests may inject a private connector factory to exercise rejection branches; production controller admission must not expose that seam as trusted bypass authority. Observe actual TLS verification in live valid-certificate and hostname-mismatch tests.

## Authenticated result contract

Suggested evidence fields: executionId and fresh vmId; requestDigest and ceilingDigest; measured runtime and policy-version digests; exact request URL digest/method/origin; requestId and connectionId; actual peer address identity and port; TLS hostname plus verified boolean; upstream HTTP status; response entity encoding version; decoded byte count; complete body SHA-256; maxResponseBytes and timeoutMs; start/end monotonic elapsed duration; response settlement state complete/overflow/timeout/transport_failure/redirect_denied; host channel closure evidence. Null means unavailable, never zero or fabricated success. Complete response metadata is emitted only after a fully bounded upstream response is consumed. Distinguish upstream status from local mediator-generated errors so synthetic 502 can never authenticate as the remote response.

Keep authenticated event ordering and execution bindings; authenticate terminal response summary with the same reviewed signer. Guest stdout alone does not establish provenance. AdaptiveSandbox must verify the signed complete response, expected URL/method, public status/body bytes/digest, limits, actual-peer/TLS observation and teardown before accepting. Host evidence is still not independent external attestation. Failure can be denied with truthful evidence where settlement is complete; incomplete teardown retains existing fail-closed/unbound handling until separately specified.

Use Gondolin sha256:<hex> values internally; convert deliberately at AdaptiveSandbox canonical hashing boundaries. Signed AdaptiveSandbox v2 authority identity and version must be in receipt bindings. Receipt replay consumes persisted receipt/result/evidence linkage only, with no context construction, guest launch, DNS, socket or credential activity. Historical file receipts and v1 semantics remain intact.

## Test seams and acceptance infrastructure

Source unit/transport regression tests: unknown schema and field rejection, ceiling correlation, no filesystem and no credential effects, one attempt, second request/redirect refusal, exact-limit and limit+1 bodies, chunked/misleading length/compression expansion, HEAD/empty statuses/binary bytes, timeout before DNS/headers/midbody, late callbacks, abort and close failures, actual peer mismatch, TLS unauthorized/missing socket state, concurrent invocation isolation, forged response metadata, synthetic error confusion, and replay tampering. These are source implementation evidence, not platform qualification.

Source VM integration: fixed image curl launch, no source-file provider access, isolated one-shot lifecycle, complete response/body matching, denied late and duplicate traffic, and package-image version binding. Local loopback TLS under a test-only local policy can validate transport mechanics but does not pass public-only HTTPS acceptance.

Binding acceptance remains an ordinary AdaptiveSandbox Invocation Gateway call to a controlled public TLS origin with valid public trust. Need an origin/domain, certificate lifecycle, deterministic nonce endpoints, and independent request/connection logs. Provide body, redirect, slow/hanging stream, overflow and disconnect endpoints, a distinct unauthorized receiver, and an endpoint whose certificate fails the requested hostname. Record both positive request logs and zero unauthorized-request counts, correlated by nonce; after settlement prove no further traffic and connection closure. Controlled DNS rebinding needs an owned DNS zone/resolver harness; mocked resolver tests supplement but do not replace it. Never set internalRanges:allow or disable TLS validation merely to make this gate pass.

No controlled external endpoint inventory was available in the inspected repo/spec. That is a concrete external acceptance prerequisite. It does not block implementing/reviewing the runtime and test harness; it blocks claiming complete live public-only Gateway acceptance. Public third-party echo endpoints cannot establish independent unauthorized traffic or teardown assertions. Linux acceptance cannot qualify macOS.

## Proposed bounded implementation order

1. Fork profile/types/admission/lifecycle with no host files and fixed one-request executable; immutable manifest identity and explicit unsupported features.
2. Mediator bounds/deadline plus authenticated response and peer/TLS observation; unit and source VM tests for every claimed field/failure.
3. AdaptiveSandbox development adapter and ordinary Gateway harness against the candidate source package, still fail-closed for missing released schema; preserve native default and empty qualified allowlists.
4. Standards/spec/security review, fixes and final source CI. Prepare external fixture deployment artifacts and document any missing endpoint configuration without claiming a pass.
5. One coherent fork prerelease, verify exact package/image assets, consume it in AdaptiveSandbox and run packaged Gateway CI. Keep runtime development-only and PRD #35/#47 tickets open for remaining guarantees.

Do not bundle credentials, redirects, write publication recovery, resource accounting or promotion into this batch. They each require separate authority and evidence design; the batch should establish the minimum trustworthy credential-free GET/HEAD execution contract first.

## Concrete batch API and ownership decision

Use a separate exported `HttpsInvocationContext.create(ceiling, runtimeOptions)`, `canonicalizeHttpsInvocationRequest`, and `execute(request)`; do not add a fake exact-reader variant. Place controller/types/normalization in `host/src/https-invocation.ts`. Reuse existing authenticated execution identity/runtime evidence signing helpers through narrow internal exports or extraction; never duplicate a weaker verifier. The context is one-invocation and refuses reuse.

Example exact request (field names are the proposed contract):

```json
{
  "schemaVersion": "gondolin.https-request/v1",
  "invocationId": "caller-nonce",
  "request": {
    "url": "https://public.example.com/path?nonce=123",
    "method": "GET"
  },
  "authority": {
    "protocol": "https",
    "host": "public.example.com",
    "port": 443,
    "methods": ["GET"],
    "resolution": "public-only",
    "redirects": "none",
    "maxResponseBytes": 1024,
    "timeoutMs": 1000
  },
  "limits": {"outputBytes": 8192, "wallTimeMs": 30000}
}
```

```json
{
  "schemaVersion": "gondolin.https-ceiling/v1",
  "network": {"https": [{
    "protocol": "https", "host": "public.example.com", "port": 443,
    "methods": ["GET", "HEAD"], "resolution": "public-only",
    "redirects": "none", "maxResponseBytes": 1024, "timeoutMs": 1000
  }]},
  "limits": {"maxOutputBytes": 8192, "maxWallTimeMs": 30000}
}
```

Every object has an exact-key grammar. Request authority is a single contracted canonical rule; explicit no-grant domains cannot be added to these objects. Reject all methods except GET/HEAD at this profile even if a broader canonical policy exists. Safe integer positive limits; decoded body bound separate from base64/framing stdout overhead. No maxResponseBytes fallback from outputBytes. Canonicalizers perform no filesystem/DNS work and freeze normalized output. Runtime options supply measured QEMU/image and integrity-verified signer configuration only, not request authority or arbitrary guest executable options.

Evidence schema `gondolin.https-evidence/v1`, policy identities `https-request/v1`, `http-tls-mediator/v3`, `empty-snapshot-vfs/v1`, `exact-mount-landlock/v1`, and `one-shot-qemu/v1`. Feature manifest must explicitly advertise the new profile/schema/policy digest; keep existing exact-reader/writer evidence v3 identities stable. Add a HTTPS result union with `outcome`, command result as diagnostics, `response: {status, bodyBase64, bodyBytes, bodyDigest} | null`, and signed evidence. For success, response bytes originate from the host-observed complete mediated response and must equal the fixed guest transfer result if guest result is exposed. Prefer returning the host-observed bounded bytes as the authoritative public body while treating curl output purely as checked diagnostics, so a compromised guest cannot manufacture response provenance.

Implementation owners:

- **Controller owner:** `host/src/https-invocation.ts`, profile unit tests, public exports, manifest profile registration/docs. Own exact grammar, immutable correlated ceiling, fixed curl args/environment, empty snapshot, VM lifecycle, signer/runtime evidence integration, and terminal result acceptance. Coordinate minimal shared helper extraction with merger.
- **Mediator owner:** `host/src/qemu/http.ts`, `host/src/qemu/contracts.ts`, narrowly scoped internal observation types and tests. Add controller-only per-invocation request observer with bounded body/status lifecycle and a request deadline, before buffered accumulation. Keep generic HTTP behavior stable when absent. Enforce exact URL/method/no-body/one-attempt; observe actual upstream response separately from local error generation. Emit host-observed immutable result to controller. Generic public hooks must not allow synthesizing a successful upstream observation.
- **Connector owner:** `host/src/http/utils.ts` and connector-focused tests. Add actual socket observation/validation before callback, default TLS verification, no reuse for the narrow profile, per-invocation connection identity, late-deadline suppression, and settled destruction. Coordinate shared contract changes with mediator; use a single agreed callback interface rather than competing edits to contracts.ts.
- **Merger:** resolve shared exports/manifest changes, integrate tests/docs/source CI, and run separate Standards and Spec/security reviewers. Parent can prepare AdaptiveSandbox harness while fork agents implement.

Suggested internal controller-to-mediator contract is an object with immutable exact request URL/method, response byte limit, request timeout, `onConnected` socket-derived record, `onResponseComplete` immutable upstream record, `onFailure` typed stage/outcome, and one state owner. It is installed only by the dedicated controller, never populated from agent input. The mediator owner owns interface definition; other owners consume it. The callback cannot replace a response or inject authority.
