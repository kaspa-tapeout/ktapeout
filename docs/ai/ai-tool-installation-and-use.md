# AI tool installation and use

The tools below are optional interfaces to the same KTAPEOUT public workflow.
Choose one assistant, install it using its official documentation, and then
apply the [KTAPEOUT Application Developer Skill](application-developer.md). Do not
install assistants inside the KTAPEOUT source tree or commit their caches.

## Common setup

1. Clone or unpack the reviewed KTAPEOUT source.
2. Open the repository root in the selected assistant.
3. Read `docs/index.md`, the relevant protocol page and the AI skill.
4. Ask for a plan before allowing edits.
5. Keep credentials and wallet software outside the workspace.
6. Review the diff and run the repository's documented checks yourself.

The public implementation is Rust-based. The baseline local check is:

```text
cargo check --manifest-path core/rust-cli/Cargo.toml --locked
```

Use an external `CARGO_TARGET_DIR` when building locally. The command does not
grant signing or broadcast authority.

## OpenAI Codex

Install and authenticate through the official [Codex CLI documentation](https://developers.openai.com/codex/cli/).
Open the repository directory, paste the safe starter prompt from the AI skill,
and ask Codex to plan before editing. Keep approval or sandbox controls enabled
for commands that write files or access the network. Review every proposed
protocol or dependency change before accepting it.

## Claude Code

Follow the official [Claude Code documentation](https://docs.anthropic.com/en/docs/claude-code/overview)
for installation and authentication. Start Claude Code from the repository
root, provide the KTAPEOUT skill as project instructions, and request a
read-only plan first. Keep signing, wallet and deployment actions outside the
assistant session.

## GitHub Copilot

Enable Copilot using the official [GitHub setup documentation](https://docs.github.com/en/copilot/how-tos/getting-started-with-copilot).
In the editor, add the KTAPEOUT skill text to the repository's reviewed AI
instructions or paste it into the chat context. Ask Copilot to explain the
affected schema and vector before generating code. Require human review for
all protocol-facing changes and pull requests.

## Cursor

Install Cursor from its official [documentation](https://docs.cursor.com/get-started/quickstart),
open the repository as a project, and add the KTAPEOUT skill to the project's
reviewed rules or chat context. Use planning mode for protocol changes and keep
network, terminal and file permissions limited to the project boundary.

## Windsurf

Follow the official [Windsurf documentation](https://docs.windsurf.com/windsurf/getting-started)
for installation. Open only the reviewed workspace, add the KTAPEOUT skill to
the project guidance, and use its planning/review flow before accepting edits.
Do not place wallet files, private keys or deployment credentials in the
workspace indexed by the assistant.

## Tool-neutral project instruction

If a tool supports a project instruction file, include a reviewed copy of the
following short rule and link to this document:

```text
Use the included KTAPEOUT 0.5.0 specification, schemas and local CLI guidance.
The developer Skill is docs/ai/application-developer.md; the operator Skill (docs/ai/application-engineering.md) is operator-only.
Preserve protocol identifiers, hashes, bounds and vectors. Never access secrets,
wallets, private keys, signing, broadcasting or credentialed endpoints. Plan
before editing, validate against schemas and run the documented checks.
```

Tool installation, model access and account permissions are managed by each
tool vendor. KTAPEOUT does not require or endorse a specific AI provider.
