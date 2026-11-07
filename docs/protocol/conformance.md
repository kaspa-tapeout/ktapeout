# Conformance

Conformance is layered:

1. schema and canonical-vector validation;
2. Rust Core and CLI conformance;
3. Profile Package, artifact and lock verification;
4. adapter-specific evidence and readback, when applicable.

The public candidate's reproducible local gate is the Rust Core/CLI check:

```powershell
cargo check --manifest-path core/rust-cli/Cargo.toml --locked
```

A local check proves only that the selected release-shaped crates resolve and
compile. It cannot promote a Profile-only result to `L1_VERIFIED`, and it
cannot establish Mainnet or production readiness. Conformance vectors, source
revision, toolchain and known limitations must be recorded with a release
candidate. This public candidate intentionally keeps the conformance surface
to the published Rust crates, schemas and vectors.
