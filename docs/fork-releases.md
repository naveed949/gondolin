# Experimental fork releases

The next prepared fork release is `v0.12.1-adaptivesandbox.3`. It is a GitHub-only,
QEMU-only prerelease for adapter development. It is not an AdaptiveSandbox-qualified
release, and it does not unblock qualified production admission by itself.
The tag and release are created only after the preparation changes are merged
and the reviewed main commit passes CI. Existing release `.2` assets and
consumer pins remain unchanged until `.3` is actually published and verified.

## Prepare and publish

1. Merge the release preparation PR after CI passes. Check out the resulting main
   commit and confirm all host/runner versions and lockfile specifiers match.
2. Create the tag at that reviewed commit and push it:

   ```bash
   git switch main
   git pull --ff-only origin main
   git tag -a v0.12.1-adaptivesandbox.3 -m "Experimental AdaptiveSandbox integration release"
   git push origin v0.12.1-adaptivesandbox.3
   ```

3. Watch **Experimental GitHub Release** in Actions. It validates the tag, reuses
   the complete CI workflow against that exact commit, builds both guest-image
   and helper architectures without separate publication, builds the host package,
   assembles registries from the verified asset metadata, smoke-tests a fresh
   tarball install, verifies checksums, and publishes a prerelease. No npm token
   or npm package ownership is required. The workflow uses GitHub's repository
   token with release-write permission only for publication/build workflow calls.
4. Inspect the release assets and retain `release-manifest.json` and `SHA256SUMS`.
   The source commit, exact URLs, and SHA-256 values become development dependency
   pins. Do not replace them with `main` or `latest` when recording evidence.

An existing tag can also be dispatched via Actions → Experimental GitHub Release
→ Run workflow → `version`. The tag must already exist and match the package
version. The manual action does not create arbitrary tags. Never move a published
tag or overwrite a published artifact. Before publication, failed runs may be
rerun at the same commit. If publication partially succeeds, inspect the release;
automatic overwrite is deliberately refused. Use a new reviewed version for
changed bytes.

## Distribution and installation

The host tarball preserves `@earendil-works/gondolin` as its internal import name
for compatibility with the workspace and existing consumers. Package metadata
points to this fork and is marked `private` to prevent npm publication. The packed
artifact removes optional krun packages and workspace lifecycle scripts. It can
still be installed from a downloaded tarball:

```bash
gh release download v0.12.1-adaptivesandbox.3 --repo naveed949/gondolin --dir gondolin-release
cd gondolin-release
sha256sum --check SHA256SUMS
npm install ./earendil-works-gondolin-0.12.1-adaptivesandbox.3.tgz
```

On macOS, use `shasum -a 256 -c SHA256SUMS`. Install QEMU separately. The package's
image/helper registry defaults resolve the same package release's registry
assets in `naveed949/gondolin`; those registries bind archives by SHA-256 and never
fall back to upstream registry URLs. Explicit registry environment overrides
remain available for development. `GONDOLIN_GUEST_DIR` can point to an extracted
image archive for a fully explicit local setup.

The image registry includes an `alpine-base:latest` alias *within the fixed
release registry*. For explicit development identity use
`GONDOLIN_DEFAULT_IMAGE=alpine-base:0.12.1-adaptivesandbox.3`, or a digest-verified
extracted image directory. Existing local image caches and explicit overrides
are operator state, not qualification evidence.

## Capability image kernel

Fork CI and coordinated releases use `images/alpine-base.json`, which selects
Alpine `linux-lts` and matching rootfs modules. The capability executable guard
requires BPF LSM attachment and function tracing; Alpine 3.23's `linux-virt`
kernel lacks the required function-tracing support. Guard installation fails
closed if the selected kernel cannot attach it. Generic builder defaults remain
`linux-virt` for ordinary VM users.

For a local capability image, build from the repository root with:

```bash
node host/bin/gondolin.ts build --config images/alpine-base.json --output guest/image/out
```

The builder extracts `boot/vmlinuz-lts` from the selected package but retains the
historical output asset name `vmlinuz-virt`. The manifest hashes the actual kernel
bytes; that filename does not select the kernel flavor. Package download caches
include the package name, version, and architecture. Use the default fresh build
work directory when changing kernel packages.

## Qualification follows implementation

The release manifest deliberately records `adaptiveSandboxQualified: false`.
Gondolin's checked-in conformance pin remains unavailable. Next, implement the
AdaptiveSandbox adapter against the exact development artifact, create and release
the backend-neutral conformance bundle, pin its release asset and SHA-256 in
Gondolin, and run non-skipping qualification for each exact host/runtime tuple.
Fix failed or unavailable guarantees before publishing verified compatibility
rows. A package release alone cannot supply missing resource enforcement or
independent effects/teardown evidence. Keep Windows and libkrun deferred.

## Future versions

Update the host version, both runner versions, their optional dependency
specifiers, lockfile, and changelog together. `scripts/package-fork-release.mjs`
currently admits only `0.12.1-adaptivesandbox.N`; broadening that release series is
an explicit maintenance change. Public npm distribution would require a separate
scope migration and trusted publishing configuration; it is intentionally absent.

## Optional documentation hosting

Docs are built and checked on every PR and main push. Forks deploy them to GitHub
Pages only when the repository variable `DEPLOY_GITHUB_PAGES` is `true`. Before
setting it, enable Pages in repository settings and select GitHub Actions as the
build source. This avoids a failed deployment when Pages has not been configured.
