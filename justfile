# Optional shortcuts for the public Rust workspace. Run from the repository root.
set dotenv-load := false

demo_dir := env_var_or_default("KTAPEOUT_DEMO_DIR", "./my-app")
python := if os() == "windows" { "python" } else { "python3" }

# Run formatting, workspace tests, lint, and the dependency audit.
check: fmt test lint audit

fmt:
    cargo fmt --all -- --check

test:
    cargo test --workspace --locked

lint:
    cargo clippy --workspace --all-targets --locked -- -D warnings

audit:
    {{python}} scripts/check_dependency_audit.py

# Scaffold a local unsigned TN10 example and inspect its workflow status.
demo:
    cargo run --locked -p ktapeout-cli -- init --template StateMachine --network testnet-10 --output "{{demo_dir}}"
    cargo run --locked -p ktapeout-cli -- dev workflow "{{demo_dir}}/workflow.json"
