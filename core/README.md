# KTAPEOUT 0.5.0 Core and CLI Candidate

This directory contains the reviewed Rust implementation surface for the
KTAPEOUT Protocol 0.5.0 developer preview:

- `rust-core`: canonical Core codecs and bounded local verification helpers;
- `rust-runtime`: non-consensus deterministic runtime contracts;
- `rust-kaspa-verifier`: offline Kaspa Safe-JSON and input-script checks; and
- `rust-cli`: the JSON-first `ktape` command-line entrypoint, including
  provenance, history, maintenance, migration, runtime-descriptor and
  Studio-handoff validation modules. The provenance and maintenance paths can
  consume optional adapter-produced rebuild/readback evidence while remaining
  local, unsigned and fail-closed.

The Core, Runtime and Verifier crates do not sign transactions, hold wallet keys,
or broadcast to Kaspa. In the CLI crate, only the `ktape tn10` commands sign (with
a developer-supplied Testnet-10 key, behind the `developer-signing` feature) or
broadcast (behind `tn10-network`). Other signing and network providers remain
explicit integration boundaries.

The source is a release-shaped copy. Embedded unit-test modules and build
outputs are intentionally excluded; the public crates are the integration and
implementation surface. Apart from the `ktape tn10` flow, the CLI modules are
deterministic, unsigned preflight tooling; they do not provide application logic,
wallet custody or a general network writer.

## Build

From this directory:

```powershell
cargo check --manifest-path rust-cli/Cargo.toml --locked
cargo build --manifest-path rust-cli/Cargo.toml --release --locked
```

The candidate pins the official Rusty Kaspa v2.1.0 commit
`01b532e8b553523216471682649693af92f0fd16`; the lockfile is part of the
candidate. The strict dependency gate remains documented in the repository
root until all transitive advisories have a reviewed resolution.
This candidate is not a claim of Mainnet readiness or a security audit.
