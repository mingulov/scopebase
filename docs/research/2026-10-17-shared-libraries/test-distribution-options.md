# Distributing tests to library users

Status: proposal. No Scopebase packages or commands described here exist yet. The goal is to let library users run shipped filesystem, mapping and conformance checks while maintainers continue to qualify every advertised behavior on its declared artifact and environment. User-run checks add evidence for that user's cell; they do not replace maintainer qualification.

## Cargo constraints

`cargo test` builds and runs test targets for the selected package(s). It builds dependencies as needed, but selecting an application that depends on a library does not select and run that dependency's unit, integration or documentation tests. A downstream package can run its own integration tests against the dependency's public API.

For a selected package, default `cargo test` runs enabled unit, integration and library documentation tests, while it builds examples to catch compile breakage; examples do not necessarily execute unless configured as test targets or explicitly selected. Target settings can disable tests or doctests. `--all-targets` covers library, binary, integration-test, benchmark and example targets, but excludes doctests; request `--doc` separately when the library supports them. Integration tests are distinct crates and can use only the library's public API. Test fixtures therefore need to be shipped as package files and addressed relative to the test package, not an assumed workspace root.

`[dev-dependencies]` are used to compile the package's own tests, examples and benchmarks; they are not propagated to packages that depend on it. A consumer can explicitly add a conformance package as its own dev-dependency and call it from its own tests. Keep test-only frameworks and heavy fixture tools out of the library's normal dependency graph. Features control optional code/dependencies; document and qualify each supported feature combination rather than relying on feature unification in one workspace.

`cargo package --list` shows the source archive's file set. `include`/`exclude`, Git ignore rules and Cargo's always-excluded nested packages or root `target/` directory affect what ships. `cargo package` builds the extracted archive to check it unless `--no-verify` is passed. These checks help expose workspace-only paths, but they do not run a downstream consumer's tests or qualify runtime behavior.

## Distribution choices

| Option | What users run | Advantages | Limits |
|---|---|---|---|
| Source archive with tests and fixtures | Download/extract the exact crate source and run its packaged Cargo test targets. | Most direct access to the unit/integration tests and fixtures; Cargo package verification can detect missing archive files. | Users run tests belonging to that crate, not automatically as a dependency. Fixtures must be deliberately included. Kernel, mount, privilege and architecture cases may be unavailable on a user's host and need explicit `SKIP`/`BLOCKED` results. |
| Installed diagnostic executable | Install a proposed `scopebase-doctor`-style binary and request filesystem/mapping diagnostics or an explicitly selected live probe. | Easy to run on a deployed host; can report actual host/kernel/filesystem capabilities and machine-readable results. | A CLI cannot automatically be an assertion in the consumer's test suite without a wrapper. A passing diagnostic covers only the probes and artifact it actually ran; it cannot establish every library contract. Privileged or mutating probes need narrow, opt-in fixtures. |
| Embeddable conformance API as a test-only dependency | Add a proposed `scopebase-testkit` crate under the consumer's `[dev-dependencies]`; the consumer supplies an adapter that calls its actual library instance and backend. | Can exercise the exact resolved library version and selected features through the consumer's public API, with independent expected results. Test helpers stay out of normal runtime dependencies. | Requires a maintained public test-support API, a consumer-supplied adapter, and explicit consumer test code. The API alone does not discover or exercise the application's library. Bind each result to the exact dependency version, enabled features and selected backend; inspect the resolved graph for duplicate versions. Do not expose privileged live probes as ordinary tests. |

## Recommended minimum

Require the third option as the developer interface: a proposed `scopebase-testkit` API with source-shipped fixtures, stable scenario IDs and result types. Require consumer-supplied adapters that explicitly bind the library version, features and backend under test. Also ship operator access through at least one runnable route: a standalone diagnostic executable or a command embedded in an adopting application. Keep portable filesystem and mapping scenarios callable without BPF or elevated privileges; label environment-dependent cases and provide explicit skip/block reasons. Keep the exact artifact, kernel/profile, independent population oracle, cleanup, and maintainer verdict attached to each advertised live behavior.

Proposed package/API names and any commands built around them are illustrative only. For example, a future `scopebase-testkit` API or `scopebase-doctor` CLI must not be documented as available until implemented and released.

## Standalone consumption checks for a future release

Run these checks on the candidate package, in a clean temporary directory outside the source workspace, without a sibling path dependency or private workspace configuration:

1. Inspect `cargo package --list` and the resulting `.crate`; confirm the documented tests, fixtures, licenses and helper files are present. Run Cargo's normal package verification (do not use `--no-verify`) and inspect the normalized manifest for unresolved private path/workspace dependencies.
2. Extract that exact archive and run the default tests and every documented feature matrix after dependencies have been cached. Run `cargo test --offline --locked` for enabled unit/integration/doc tests, and `cargo test --offline --locked --all-targets` for non-doctest targets; examples built by the default command are not necessarily executed. Run `cargo test --offline --locked --doc` separately when doctests apply. Offline mode requires cached registry/git sources and can resolve differently, so record the lockfile and do not present offline success as a general clean-network build.
3. In a separate minimal consumer crate with no workspace parent, depend on the exact released version and the proposed testkit as a dev-dependency. Supply an integration-test adapter that invokes the conformance API against the consumer's actual library API and selected backend; assert the dependency package ID/version and feature set from the resolved graph. Inspect `cargo tree --locked -d` for duplicate versions of the library under test and inspect its enabled feature graph. Then run the consumer tests. This verifies consumer use; Cargo still does not run dependency-owned tests automatically.
4. If a diagnostic is shipped, extract the package archive and install the exact source into a temporary root with `cargo install --path <extracted-package> --locked --offline` when testing the cached offline case; also test the published registry version. Run its version/help and non-privileged machine-readable smoke command. Record the binary hash and exit status. This checks installed packaging and invocation, not the entire conformance suite.
5. For maintained live qualifications, separately run the exact released library/diagnostic plus independent workload and cleanup checks in each advertised environment cell. Preserve `PASS`, `FAIL`, `SKIP`, `BLOCKED` and `NOT_RUN` distinctly.

## Primary Cargo references

- [cargo test](https://doc.rust-lang.org/cargo/commands/cargo-test.html): selected package targets and default test targets.
- [Cargo integration-test targets](https://doc.rust-lang.org/cargo/reference/cargo-targets.html#integration-tests): separate crates using the library's public API.
- [Cargo dependency tree](https://doc.rust-lang.org/cargo/commands/cargo-tree.html): duplicate package versions and resolved feature graph.
- [Development dependencies](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#development-dependencies): dev-dependency scope and publication behavior.
- [Cargo features](https://doc.rust-lang.org/cargo/reference/features.html): optional dependencies and feature selection.
- [Manifest include/exclude](https://doc.rust-lang.org/cargo/reference/manifest.html#the-exclude-and-include-fields): package file rules and `cargo package --list`.
- [cargo package](https://doc.rust-lang.org/cargo/commands/cargo-package.html): source archive creation, verification and offline/locked flags.
- [cargo install](https://doc.rust-lang.org/cargo/commands/cargo-install.html): installing binary packages into a selected root.
- [Cargo offline FAQ](https://doc.rust-lang.org/cargo/faq.html#how-can-cargo-work-offline): cache requirements and offline-mode caveat.
