# Guidance for AI coding assistants

This repository is a KTAPEOUT public preview: Developer preview · Testnet-10 only.

- First read `docs/reference/capabilities-and-status.md`. Do not present `NOT_IMPLEMENTED`, `UNVERIFIED`, or `MOCK_OR_VM` capabilities as available, and do not invent commands, wallets, signers, or network paths.
- Derive commands from the installed `ktape --help` and the relevant command-family help.
- Developer entry: `docs/ai/application-developer.md`. First application tutorial: `docs/getting-started/first-application.md`. Give a file-level plan before editing.
- Build the CLI with `CARGO_TARGET_DIR` outside the repository and candidate trees. The first build takes about 12 minutes, depending on the machine.
- Never read, request, or record private keys, recovery codes, or wallet files. Do not run `sign`, `submit`, or broadcast commands. Do not use `--yes` to bypass authorization confirmation. Do not create or modify GitHub resources. Stop and report when a required capability is missing.
- In each report, list commands run, results, and relevant hashes. Local validation is not chain inclusion, publisher authorization, or production readiness.
- Use verification labels accurately: `LIVE_TN10`, `LIVE_TN10_PRIVATE_TOOL`, `MOCK_OR_VM`, `LOCAL_OK`, `NOT_IMPLEMENTED`, and `UNVERIFIED`.
