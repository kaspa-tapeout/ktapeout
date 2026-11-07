# Security Policy

## Supported release

The `0.5.x` release is a developer preview. This policy applies to files in a
matching published release tag; it is not a Mainnet authorization or a security
audit.

## Reporting a vulnerability

Report vulnerabilities through the project's
[GitHub private vulnerability reporting channel](https://github.com/kaspa-tapeout/ktapeout/security/advisories/new).
Reports about this repository are accepted through the same channel. Do not send sensitive
vulnerability details through public issues or discussions.

Channel status: enabled, not yet tested end to end.

Include:

- the affected tag or commit;
- a minimal, redacted reproduction;
- the impact and preconditions; and
- any suggested containment or mitigation.

Do not include credentials or personal data in a report. The maintainer should
acknowledge receipt, reproduce in an isolated environment, and publish a
sanitized advisory only after a fix or mitigation is available.

## Scope boundaries

The public CLI has one key-handling path: `ktape tn10 sign`. It is limited to
Testnet-10 and reads a developer-supplied key only from a file (`--key-file`) or
standard input (`--key-stdin`), never from command-line arguments. The developer
keeps custody of the key; the tool does not generate, store, transmit or log it.
Key handling is confined to the `developer-signing` module, and planning,
submission and verification code does not reference key types. Memory clearing
covers tool-managed buffers only; it does not guarantee that copies made by
cryptographic libraries, the operating system or swap are removed. On Windows the
key file's access control list cannot be checked automatically and only a warning
is produced. Use a disposable test key, never a mainnet wallet or recovery phrase.
The standard library's internal stdin buffer is also outside the tool-managed
zeroization boundary. If Ctrl+C interrupts hidden terminal input, terminal echo
may remain disabled; restore the terminal's normal echo state before continuing.

`ktape tn10 submit` broadcasts a transaction that was signed and approved by the
developer. `ktape tn10 verify` recomputes inclusion proofs locally, but chain
acceptance is reported by the nodes it queries; node honesty and operator
independence are external assumptions. Mainnet is rejected.

Workflow authorization for release operations is exported for an external Ed25519
signer and verified on import. Local-key authorization commands for operator
workflows exist only in publisher/host builds with `publisher-signing`, which
this repository does not enable.

In scope for reports: key leakage, bypass of budget or approval checks, bypass of
network restrictions, and verification that accepts invalid proofs. Reports about
external signers, wallets, RPC providers, or live deployments must identify the
affected external component separately.
