# Code and API standards

These are engineering requirements for new and revised KTAPEOUT 0.5.0 code.
They do not change existing protocol bytes or public identifiers. The English
0.5.0 specification is the sole normative protocol text; implementation and
developer guides must agree with it. Existing code requires a staged cleanup.

## Comments and API documentation

All public source comments, docstrings, CLI help and diagnostic prose must be
English. Explain invariants, reasons and authority boundaries rather than
restating statements. Remove obsolete claims, copied implementation plans and
internal file paths. Link protocol-facing documentation to a stable public
specification section and state the supported version.

Public functions, types, fields and constants need useful Rust documentation.
For functions, describe input units and limits, output meaning, errors,
determinism and effects where applicable. Document commitment domains and
canonical ordering. Use Errors and Panics sections when relevant; do not claim
a function cannot panic until its input paths have been reviewed. Keep examples
small, deterministic and free of credentials. Maintainers validate examples in
CI or a controlled review environment; public exports include only reviewed
integration tests and exclude embedded unit-test modules.

## Naming and compatibility

Use snake_case for Rust modules, functions, fields and variables; UpperCamelCase
for types and traits; SCREAMING_SNAKE_CASE for constants. Prefer domain names to
generic names such as value, data or v when they clarify a public contract.
Avoid abbreviations unless they are established protocol terms.

Rust symbol names, JSON fields, canonical registry IDs, legacy package IDs,
schema versions, semantic versions, hashes and display names are separate
namespaces. Follow the [naming reference](../reference/naming.md) for protocol
identities. Preserve wire names and existing CLI flags. A Rust-only rename must
retain serialization names, public re-exports or compatibility adapters where
required. Distinguish validation of shape from verification of authenticated
evidence in API names and documentation.

## Responsibilities and input handling

Keep domain transformations independent of filesystem, CLI rendering and
network transport. Core codecs own canonical bytes and commitments. Profile
evaluators own their evaluation semantics. CLI handlers coordinate typed
operations; they should not contain a second protocol implementation.

Bound untrusted inputs before allocating full documents. Reject duplicate JSON
keys where documents enter an identity or authorization boundary. Define byte,
depth, node, collection and execution limits per input type. Use checked
arithmetic for nonces, epochs, resources and fees. Review indexing and unwraps
against their established invariants; do not replace safe guarded conversions
solely for appearance.

Use stable typed error codes with separate messages and context. Human-readable
OS errors must not determine protocol error codes. Do not expose secrets in
errors. Distinguish local validation, cryptographic verification and chain
readback. Pin serialization behavior with vectors before changing shared code.

## Build and review gates

For each public crate, run cargo fmt with --check and cargo clippy with --locked
and --all-targets -- -D warnings, plus the documented locked build check. Keep
build outputs outside the source tree. Review supported features separately;
a host build does not validate a WASM target. Declare a verified minimum Rust
version and CI toolchain before release.

Maintainers run meaningful conformance, negative-input and regression checks
in CI or a controlled review environment. Public release packages retain approved
schemas, vectors and unsigned examples, while excluding embedded unit-test modules, unselected
tests, wallets, credentials, caches and internal audit records. Do not add blanket lint
allowances or weaken validation to make a gate pass. Review dependency findings
explicitly and record any accepted disposition.

Each protocol-facing change must identify the normative requirement, affected
API or schema, compatibility impact, validation command and result. Update the
developer guide and capability table whenever supported behavior changes.
