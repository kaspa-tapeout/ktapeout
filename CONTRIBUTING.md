# Contributing to KTAPEOUT Protocol 0.5.0

Read the public documentation before changing protocol-facing behavior. Keep
the Rust Core, machine-readable contracts, vectors, examples and English
documentation aligned with the same protocol tag.

Follow [code and API standards](docs/contributing/code-standards.md), including
English comments, Rust documentation, naming, input limits and compatibility.
The English 0.5.0 specification is the sole normative protocol text.

From the repository root, the workspace commands cover all four Rust crates.
Keep build output outside the checkout.

For `just check` or `just audit`, install the optional `just` runner, Python 3
and `cargo-audit` 0.22.2. Install the pinned audit tool with:

```text
cargo install cargo-audit --locked --version 0.22.2
```

Install the optional task runner with `cargo install just --locked`. You can
also run the commands below directly without installing `just`.

PowerShell:

```powershell
$env:CARGO_TARGET_DIR = Join-Path $env:TEMP "ktapeout-0.5.0-target"
cargo fmt --all -- --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
python scripts/check_dependency_audit.py
```

Bash (Linux):

```bash
export CARGO_TARGET_DIR="${TMPDIR:-/tmp}/ktapeout-0.5.0-target"
cargo fmt --all -- --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
python3 scripts/check_dependency_audit.py
```

Windows was manually validated. The Ubuntu workflow covers Linux, but it has
not run for this candidate; macOS has not been validated.

The tests cover CLI deployment-readiness output, external-signing JSON bounds,
operation IDs, genesis-output validation, starter initialization and workflow
status semantics, structural vector parsing, and canonical record layout,
action, and seal encodings and commitments. They do not execute application
behavior or establish L1 admission. The dependency check allows only the
advisory IDs in `dependency-audit-policy.json`, and fails when any individual
exception expires or a new non-ignored advisory appears.

Validate local JSON references and Markdown links, then describe compatibility,
test evidence and any changed release boundary in the pull request.

Do not commit credentials, wallet material, generated build output, local
deployment data or copied research plans. Protocol or schema changes require a
requirements crosswalk and an explicit compatibility note.

Maintainer release checks additionally cover language, public-tree hygiene,
secret scanning and dependencies. These internal gates are distinct from
commands available in a developer's clean public checkout.
