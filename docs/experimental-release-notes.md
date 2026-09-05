Experimental QEMU-only release of the `naveed949/gondolin` fork for AdaptiveSandbox adapter development.

This release includes the one-shot Capability Invocation API, exact reader/writer and scoped-runner profiles, and signed evidence interfaces. It does **not** claim AdaptiveSandbox qualification. Host/resource guarantees and conformance rows remain unverified until the exact released conformance bundle and runtime evidence pass the required gates.

Assets include a built npm-compatible host tarball (GitHub distribution only), guest images and sandbox helpers for aarch64 and x86_64, version-specific registries, `release-manifest.json`, and `SHA256SUMS`. The manifest binds the source commit and artifact hashes. Optional upstream krun dependencies are excluded; no npm registry packages are published.

Verify `SHA256SUMS` before installing the downloaded `.tgz` with `npm install ./<downloaded-package>.tgz`. The internal import name remains `@earendil-works/gondolin` for source compatibility; obtain this fork from these release assets, not from that upstream npm registry name. QEMU is an external host dependency. macOS hosts a Linux guest; it does not provide native macOS guest enforcement.

See `docs/fork-releases.md` at the tagged source commit for release, installation, and recovery instructions. Linux and macOS require separate qualification evidence. No existing compatibility row is promoted by this release.
