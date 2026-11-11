# AI-assisted KTAPEOUT development

AI assistants should start with the repository-root [AGENTS.md](https://github.com/kaspa-tapeout/ktapeout/blob/main/AGENTS.md).

KTAPEOUT 0.5.0 can be developed with an AI coding assistant, provided that
the assistant is constrained by the protocol, repository boundary and signing
authority rules.

- [KTAPEOUT Application Developer Skill](application-developer.md) — the default
  entry: build, package and locally verify an application with an AI assistant.
- [KTAPEOUT Operator Release Skill](application-engineering.md) — operator-only
  release-authority material; application developers do not need it.
- [AI tool installation and use](ai-tool-installation-and-use.md) — safe setup
  guidance for common coding assistants.

AI assistance does not grant wallet custody, signing authority, broadcast
authority or Mainnet access. The developer remains responsible for reviewing
protocol changes, generated code, dependencies and commands before execution.

## AI task workflow

1. Confirm whether the checkout is the minimal public protocol candidate or the full engineering distribution. The public candidate includes the reviewed static adapter registry and a Host-free TN10 name-registration preview on the isolated V6 sovereign-lineage reference path (not the public developer path); end-to-end validation for existing `ktape.official.adapter.registry` 1.0.0 namespaces is incomplete. It does not include Studio, a live publisher, or every engineering adapter. Inspect `ktape release adapters` before choosing a release path.
2. Read the [current capability boundary](../reference/capabilities-and-status.md) and the relevant protocol or guide page before choosing commands.
3. Use the installed CLI's help and the examples shipped with that exact distribution. Do not infer an executable command from a protocol concept or an older Skill.
4. Validate locally and report the exact command, result and remaining boundary. Local validation is not chain inclusion, publisher authorization or production readiness.

The Skill guides task routing; the current architecture, normative specification, shipped implementation and capability status remain the sources of truth.

## First application with an AI assistant

Use this repeatable sequence after installing an assistant:

1. Open the KTAPEOUT repository root. The public specification, schemas and
   this guide are sufficient for local protocol work and read-only TN10 planning. The developer
   Skill is included; the operator Skill is operator-only.
2. Ask the assistant to read `docs/index.md`, the normative specification and
   [the first-application tutorial](../getting-started/first-application.md).
3. Require a file-level plan before any
   edit and ask the assistant to identify the Profile, Package, Recipe, locks
   and state commitments involved.
4. Run the generated local scaffold and workflow from an external Cargo target
   directory:

```powershell
$env:CARGO_TARGET_DIR = Join-Path $env:TEMP "ktapeout-0.5.0-target"
cargo run --manifest-path core/rust-cli/Cargo.toml --locked -- init `
  --template StateMachine --network testnet-10 --output .\my-app
cargo run --manifest-path core/rust-cli/Cargo.toml --locked -- dev workflow `
  .\my-app\workflow.json
```

5. Review the generated files and require the assistant to validate them against
   the public schemas and vectors. Keep the result `LOCAL_ONLY` until a
   separately reviewed external signing and readback boundary exists.

The assistant must stop and report missing capabilities instead of inventing a
provider, wallet, signer or network path. A local scaffold is intentionally
enough to begin application development; it is not an on-chain publication.
