# Scaffold and inspect a local project

This tutorial scaffolds a project and checks declarations; it does not execute
application behavior. The candidate has no general application runtime or
semantic test runner. It stays on the unsigned, local path and does not request
a wallet, sign a transaction or broadcast to Kaspa.

For AI-assisted local work, provide the included normative specification,
schemas, vectors and evidence boundaries to your assistant and ask for a plan
before editing. The optional complete Application Engineering Skill requires
the separate [engineering distribution](../ai/application-engineering.md).

Set an external Cargo target directory before running the CLI so generated
build output stays outside the checkout:

```powershell
$env:CARGO_TARGET_DIR = Join-Path $env:TEMP "ktapeout-0.5.0-target"
```

```powershell
cargo run --locked -p ktapeout-cli -- init --template StateMachine --network testnet-10 --output .\my-app
cargo run --locked -p ktapeout-cli -- dev workflow .\my-app\workflow.json
```

```bash
export CARGO_TARGET_DIR="${TMPDIR:-/tmp}/ktapeout-0.5.0-target"
cargo run --locked -p ktapeout-cli -- init --template StateMachine --network testnet-10 --output ./my-app
cargo run --locked -p ktapeout-cli -- dev workflow ./my-app/workflow.json
```

The first Rust build compiles the Kaspa dependency graph. In a clean Windows
walkthrough on 2026-11-06 it took about 12 minutes; build time varies by
machine, network and cache state. It produced about 1.5 GB of build output;
later builds reuse the cache. Set `CARGO_TARGET_DIR` to keep compiled files outside the checkout and
reuse them on later runs. If `just` is installed, `just demo` runs this same
scaffold-and-inspect flow. Set `KTAPEOUT_DEMO_DIR` to choose its output
directory; the default is `./my-app`.

The scaffold writes a source manifest, a quickstart result and a deterministic
workflow with `check`, `build`, `package` and `test` stages. Inspect those files
before changing the application. In this public candidate the manifest is a
declaration, not executable application code. Quickstart validation is
`STRUCTURE_ONLY` with one declared vector and `tests_executed: false`.
`ktape app test` returns `STRUCTURE_ONLY` with ToolResult `WARNING`; it checks
the structural vector declaration and does not run application behavior. The
starter workflow returns `INCOMPLETE`: check is `NEEDS_INPUT`, build is `PASS`
with a `LOCAL_ONLY` artifact, package is `REQUIRES_HUMAN_REVIEW`, and test is
`STRUCTURE_ONLY`. A successful `ktape init` means the starter files were
created, while exit code 0 from `dev workflow` means only that the command
completed. Neither result means the application passed the
unfinished stages. Implement and run the behavior checks needed for your app
before treating it as complete.

The generated `source-manifest.json` is the input declaration consumed by
`ktape dev workflow`. See the [CLI reference](../reference/cli.md) and
[capabilities and status](../reference/capabilities-and-status.md) for the
fields it binds and the limits of those checks.

For an existing Profile Package, bind it explicitly:

```powershell
ktape init --template StateMachine --network testnet-10 `
  --output .\my-app-locked --profile-package .\profiles\my-package
ktape dev workflow .\my-app-locked\workflow.json
```

The workflow must stop on a missing package, stale lock, unsupported provider,
unresolved conflict or unavailable evidence. `LOCAL_ONLY` identifies evidence
scope; it does not turn unexecuted stages into success. For an executable local
test, use a runner explicitly listed as supported by the installed distribution
and preserve its exact Profile/Project binding.

Published walletless access is read-only. Local simulation and drafts are
development-tool state, not a visitor write capability. Any L1 state change goes through a
user-selected wallet and an explicit per-operation signature. An application
may add a service signer as a separate, clearly disclosed integration; it
does not make the platform's walletless path writable. Calls that change state
in an external API follow that API's own authentication rules.

Ask the AI assistant to summarize the generated Profile, lock, artifact and
workflow before making the next change. Keep the first iteration application-
local and deterministic; defer wallet, signing, broadcast and live readback to
the separately reviewed external boundary.

## Next steps
- Build the included teaching counter into a deterministic local artifact:

```powershell
cargo run --manifest-path core/rust-cli/Cargo.toml --locked -- artifact build examples/golden-counter-source.json
```

The command returns an artifact marked `LOCAL_ONLY`. It verifies a local
artifact projection; it does not execute the counter's behavior or prove TN10
admission. The generated starter's `dev workflow` and `app test` remain
declaration/vector-structure checks until you bind an explicitly supported
Profile/Project runner.

- Inspect and verify a Profile Package with `ktape profile package-verify`.
- Build and verify a content-bound artifact with `ktape artifact build` and
  `ktape artifact verify`.
- Build a local runtime package with [`ktape package build`](../guides/build-runtime-package.md).
- Read [capabilities and status](../reference/capabilities-and-status.md)
  before planning any external signer or TN10 operation.
