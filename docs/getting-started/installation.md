# Install and verify

## Prerequisites

The public candidate requires Rust stable and Cargo. The selected dependency
lockfile is part of the candidate. Python, Node.js, browser-WASM and Studio
tooling belong to deferred maintainer-side packages and are not prerequisites
for this public Core/CLI path.

```powershell
rustc --version
cargo --version
```

The Rust `ktape` CLI is the public developer entrypoint. Most commands produce
local plans and verification results. Only `ktape tn10 sign` (which reads a key
you supply) and `ktape tn10 submit` (which broadcasts to Testnet-10) sign or
broadcast; see the [TN10 guide](../guides/publish-on-tn10-with-ktape.md).

In a clean Windows walkthrough on 2026-11-06, the first build took about 12
minutes; time varies with machine, network and cache state. It produced about
1.5 GB of build output. Keep
`CARGO_TARGET_DIR` outside the checkout so later builds reuse it.

## Client-neutral integration

An alternate client may be written in another language, but it must consume
the public schemas and vectors as contracts rather than reimplementing
protocol authority. Preserve canonical JSON, identifiers, hashes, bounds,
error codes and evidence labels exactly. A client may provide local parsing,
planning or diagnostics; provider-specific transport, signing, submission and
readback remain explicit integration boundaries.

This candidate does not ship Browser SDK, Studio or provider adapters. Their
absence is a release-scope decision, not a protocol incompatibility claim.

## Clean-checkout verification

Run from the candidate `core/` directory:

```powershell
cargo check --manifest-path rust-cli/Cargo.toml --locked
```

This checks the release-shaped Rust Core, runtime, verifier and CLI dependency
graph. Do not interpret a passing local check as Mainnet or security-audit
approval. Keep generated caches and build output outside the release tree.

## Build the CLI

```powershell
$env:CARGO_TARGET_DIR = Join-Path $env:TEMP "ktapeout-0.5.0-target"
cargo build --release --locked --manifest-path rust-cli/Cargo.toml
& (Join-Path $env:CARGO_TARGET_DIR "release\ktape.exe") --version
```

The preview binary is unsigned. A distributable binary requires a separate
release record containing target, toolchain, source/lock digests, checksum and
signature status.
