# Publish an application on TN10 with `ktape`

This guide describes the offline-first public flow. It is limited to `testnet-10`; mainnet input is rejected.

## Before you begin

Build `ktape` from this checkout, or use a previously built binary. In the
examples below, replace `ktape` with `cargo run --locked -p ktapeout-cli --` or
the built binary path.

```powershell
$env:CARGO_BUILD_JOBS = '1'
cargo run --locked -p ktapeout-cli -- tn10 --help
# Or build once, then invoke the binary:
cargo build --locked -p ktapeout-cli
target\debug\ktape.exe tn10 --help
```

```bash
CARGO_BUILD_JOBS=1 cargo run --locked -p ktapeout-cli -- tn10 --help
# Or build once, then invoke the binary:
cargo build --locked -p ktapeout-cli
./target/debug/ktape tn10 --help
```

Generate a fresh, valueless test key locally and keep it outside the repository
and operation directory. The PowerShell example requires PowerShell 7 or later
(.NET 5 or later provides `RandomNumberGenerator.Fill` and `Convert.ToHexString`):

```powershell
$key = Join-Path $env:USERPROFILE 'tn10-test-key.hex'
$bytes = [byte[]]::new(32)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
[System.IO.File]::WriteAllText($key, [Convert]::ToHexString($bytes).ToLowerInvariant())
[Array]::Clear($bytes, 0, $bytes.Length)
```

On Unix, use `umask 077; openssl rand -hex 32 > "$HOME/tn10-test-key.hex"`.
The key file is a nonzero 32-byte secp256k1 scalar encoded as 64 lowercase hex
characters. To obtain its x-only public key and `kaspatest:` address, use a
separate, trusted Kaspa wallet/key utility that explicitly supports Testnet-10
and displays both values for the same key; compare the x-only key with the
plan's `signing_pubkey`. `ktape` currently has no key-derivation command. If
your wallet cannot display/export that public key, stop and use another trusted
utility; do not infer it from the secret.

Get test funds only from a TN10 faucet or operator. The [Kaspa Testnet wiki](https://wiki.kaspa.org/en/testnets)
lists the TN10 faucet and explorer; verify
current availability before use. A public endpoint pair can be selected from
[`core/studio/tn10-node-registry.json`](https://github.com/kaspa-tapeout/ktapeout/blob/main/core/studio/tn10-node-registry.json).
In PowerShell, set `KTAPE_TN10_ENDPOINTS` to the two semicolon-separated WSS URLs:

```powershell
$env:KTAPE_TN10_ENDPOINTS = 'wss://first.example/kaspa/testnet-10/wrpc/borsh;wss://second.example/kaspa/testnet-10/wrpc/borsh'
```

In Bash:

```bash
export KTAPE_TN10_ENDPOINTS='wss://first.example/kaspa/testnet-10/wrpc/borsh;wss://second.example/kaspa/testnet-10/wrpc/borsh'
```
The registry is a discovery aid and does not prove independent operation. Each
endpoint must be a `wss://` URL whose exact path is
`/kaspa/testnet-10/wrpc/borsh`. IP literals (including IPv4 and IPv6),
`localhost`, `.local`, `.internal`, `.lan` and `.home.arpa` names, user-info,
query strings and fragments are rejected. Ports must be valid numeric ports.
The client validates the hostname text but does not resolve DNS to detect a
public hostname that points to a private address; select trusted endpoints.
Invalid syntax returns `TN10_ENDPOINT_INVALID`; an endpoint without an
acceptable public DNS hostname returns `TN10_ENDPOINT_PUBLIC_DNS_REQUIRED`.

Building requires Git, network access to fetch the pinned GitHub dependency on
the first build, a C compiler, and Rust `1.91.0` via `rustup`. Windows was
manually validated. Linux is covered by the checked-in Ubuntu CI workflow, but
that workflow has not run for this candidate; macOS has not been validated. The checked-in node list is
[`core/studio/tn10-node-registry.json`](https://github.com/kaspa-tapeout/ktapeout/blob/main/core/studio/tn10-node-registry.json);
it is a discovery aid, not proof that listed endpoints have independent
operators. Verify the operators yourself.

1. Build the application release and prepare a JSON request containing the
   release artifact root, a canonical funding UTXO view, and a fee within the
   local budget. `ktape package build` does not print the root as a summary
   field. Read `content_commitment.artifact_root` from
   `<output>/runtime/testnet-10/<namespace>/<slug>/<release_id>/runtime-manifest.json`;
   it must equal `content_root` in the adjacent `content-commitment.json`. Hash
   the exact bytes of that `content-commitment.json` with SHA-256 for
   `content_commitment_sha256`. Do not use `package_digest` or `release_id` as
   the artifact root. `ktape tn10 plan` does not yet accept a runtime-manifest
   path, so compare these values manually before planning.
2. Run `ktape tn10 plan request.json plan.json`. This is deterministic and keyless; it emits the transaction and `input_sighash_all`.
3. Sign offline with `ktape tn10 sign plan.json signed.json --key-file "$HOME/tn10-test-key.hex"` in Bash or `--key-file "$env:USERPROFILE\tn10-test-key.hex"` in PowerShell, or use `--key-stdin` (hidden terminal input when interactive). Alternatively import a wallet's detached signature with `ktape tn10 sign plan.json signed.json --signature signature.json`. Both paths require genuine approval and enforce the same budgets.
4. Submit through the configured TN10 transport with `ktape tn10 submit`. It
   durably writes `SUBMISSION_UNKNOWN` before attempting broadcast. A successful
   matching acknowledgement changes the record to `SUBMITTED`; timeout,
    disconnect or mismatched acknowledgement remains `SUBMISSION_UNKNOWN` and
    exits nonzero. Reconcile with two nodes before any retry; absence from one
    node's mempool is not proof of non-submission. The CLI retry flag only
    permits resubmitting the identical txid and plan hash, and archives the old
    result before the new attempt.
5. Run `ktape tn10 verify evidence.json verified.json`. Evidence supplies `network` (`testnet-10`), the complete local `plan` object, `txid`, a containing `block_hash`, and exactly two `nodes` with distinct hostnames. Each endpoint must use `wss://` and the `/kaspa/testnet-10/wrpc/borsh` path. These are locators and claims, not proof of acceptance.

The commands expose these result states:

| Command | Result status | Exit | `txid` |
| --- | --- | --- | --- |
| `plan` | `UNSIGNED_LOCAL_PLAN` | 0 | Included; computed locally before signing |
| `sign` | `SIGNED_OFFLINE` | 0 | Included in the signed transaction |
| `utxos` | `UTXO_VIEW_MATCH` | 0 only when both views agree | No |
| `submit` | `SUBMITTED` | 0 after matching acknowledgement | Yes |
| `submit` | `SUBMISSION_UNKNOWN` | nonzero | Yes; `broadcast` is `"UNKNOWN"` |
| `locate` | `LOCATED_NOT_VERIFIED` | 0 when a common inclusion candidate is found | Yes |
| `verify` | `VERIFIED` | 0 only when proof, acceptance and required depth pass | Yes |
| `verify` | `CONFIRMATIONS_INSUFFICIENT` | nonzero | Yes |
| `verify` | `UNVERIFIED` marker | nonzero on validation, transport or disagreement error | May be absent if evidence could not be parsed |

Other common nonzero errors include `TN10_SUBMISSION_RESULT_EXISTS` (the
existing output is not an unknown result eligible for retry),
`TN10_RETRY_SAME_TXID_REQUIRED` (the explicit retry flag is missing),
`TN10_SUBMISSION_TXID_MISMATCH_RECONCILE` (txid or plan digest differs),
`TN10_BUDGET_LOCKED_RECONCILE_BEFORE_RETRY` and
`TN10_BUDGET_PENDING_RECONCILE_BEFORE_RETRY` (signing budget recovery needs
reconciliation), `TN10_SIGN_OUTPUT_EXISTS` (sign output already exists), and
`TN10_SUBMISSION_LOCK_EXISTS` (a concurrent or crashed submit left
`<result>.lock`; confirm no submit is running before deleting it), and
`TN10_CONFIRMATION_WINDOW_EXCEEDED` (requested depth exceeds the 64-block
window). A nonzero command result is not success, even if it wrote a JSON
record.

Locator failures exit nonzero: `TN10_SCAN_AT_TIP` means the start hash is the
current tip and no later blocks are available yet; it does not mean the
transaction was not submitted. `TN10_SCAN_CURSOR_STALLED` means the cursor did
not advance, and `TN10_LOCATOR_NOT_FOUND_SUBMISSION_UNKNOWN` means the bounded
scan did not find the transaction. `TN10_LOCATOR_NODES_DISAGREE` means the two
nodes did not identify the same containing block. These conditions do not
authorize a retry.

`LOCATED_NOT_VERIFIED` is not an acceptance verdict. A failed submit or verify
must be treated as non-success even when an output file contains a status.

Verification fetches the complete block independently from each node and locally recomputes transaction identifiers, the header hash and the transaction Merkle commitment. It checks the transaction outputs and payload against the local plan. An input `proof_valid` value is recorded only as a claim and never affects the result.

Each node must also report selected-parent-chain successors accepting the transaction.
A block in the `removed` set is not by itself a rejection: a blue merge-set block
may be removed from the selected parent path while a selected-chain successor
accepts its transaction. Verification requires that acceptance evidence on the
selected `added` path. Missing acceptance, unreachable nodes or disagreement
fails verification. Set optional `min_confirmations` to an integer from 1 to
64; larger values return `TN10_CONFIRMATION_WINDOW_EXCEEDED`. The default is 1, a minimal TN10 observation rather than a finality
guarantee. The verifier counts returned selected-chain blocks from the
accepting block inclusively. This is a conservative lower bound when the RPC
truncates its response. Both nodes must agree on the accepting block and
whether the threshold is met; their exact depths may differ. Insufficient depth
writes `CONFIRMATIONS_INSUFFICIENT` and exits unsuccessfully; only successful
inclusion and sufficient, agreed acceptance produce `VERIFIED`.

Local proof recomputation checks block-body consistency, not proof of work or
consensus independently of the nodes. Chain acceptance and virtual-chain data
come from the nodes. They remain dependent on two honest, independently
operated nodes and TLS; distinct hostnames alone do not establish independent
operators. Select endpoints accordingly.

The current plan is a `KTAPEOUT-RESOURCE-PAYLOAD-CANDIDATE-V1` transaction carrying an artifact-root payload. It is not a `COMPACT_NAME_TARGET/V1` Deed update, a name publication, or a guarantee of durable payload storage.

## Obtain the public inputs before signing

Create `utxos-request.json` with `network: "testnet-10"`, your public `kaspatest:` address as `address`, and exactly two checked wRPC endpoint strings as `nodes`. Both endpoints must use `wss://` and end in `/kaspa/testnet-10/wrpc/borsh`. Run:

```text
ktape tn10 utxos utxos-request.json utxos.json
```

The command requires two synchronized, UTXO-indexed TN10 nodes and identical UTXO sets after ordering by outpoint. `funding_utxos` contains ordinary, non-coinbase P2PK inputs matching the address; unsupported inputs appear in `excluded`. Select one entry and copy it unchanged into the `funding_utxo` field below. The command does not choose an input, reserve it, or spend it. Refresh just before signing: agreement does not prevent another wallet from spending the input.

Preserve the result's `nodes` and `observations`. Each observation includes a `start_hash` for a later bounded block scan and a virtual DAA score. Use the two start hashes in the same order as their endpoints. Distinct hostnames do not establish independent operators; `operator_independence_verified` is explicitly false.

Write `request.json` in this shape, replacing every angle-bracket placeholder with your own public data. The amounts are an illustrative budget, not permission to spend; use your actual authorized limits. One test KAS equals 100,000,000 sompi. Full input value, including change, must fit the value budget.

```json
{
  "schema": "KTAPEOUT-RESOURCE-PAYLOAD-CANDIDATE-V1",
  "network": "testnet-10",
  "address": "<your kaspatest address>",
  "artifact": {
    "application_uri": "ktape://testnet-10/app/demo/starter",
    "artifact_sha256": "<package build artifact root, 64 lowercase hex>",
    "content_commitment_sha256": "<SHA-256 of the generated content-commitment.json bytes>"
  },
  "funding_utxo": {
    "outpoint": "<transaction ID>:<output index>",
    "amount": 100000000,
    "block_daa_score": 123456,
    "script_public_key": "000020<64 lowercase public-key hex characters>ac",
    "covenant_id": null
  },
  "fee_sompi": 5000000,
  "max_fee_sompi": 5000000,
  "max_total_fee_sompi": 5000000,
  "max_value_sompi": 100000000,
  "max_total_value_sompi": 100000000
}
```

There is no artifact-root summary line in `ktape package build` output. Read it
from `content_commitment.artifact_root` in the runtime manifest at the path
above and compare it with `content_root` in `content-commitment.json`. Set
`artifact.content_commitment_sha256` to the SHA-256 of the exact
`content-commitment.json` bytes (including its final newline, if present).
Manually verify all three values before running `plan`; the current command
does not read a manifest or perform this cross-file check. Keep the packaged
runtime and commitment alongside the evidence: an on-chain root alone does not
preserve those files. Never put wallet files or secrets in this directory.

## Submit once and locate the containing block

After approving and signing the plan, select one of the previously checked endpoints for submission. In PowerShell:

```powershell
$env:KTAPE_TN10_ENDPOINT = '<your checked TN10 wss endpoint>'
ktape tn10 submit signed.json submit-result.json
```

In Bash, use the same endpoint value:

```bash
export KTAPE_TN10_ENDPOINT='wss://first.example/kaspa/testnet-10/wrpc/borsh'
ktape tn10 submit signed.json submit-result.json
```

Preserve the signed transaction and submission result. A first result file is
created exclusively; an existing non-unknown result returns
`TN10_SUBMISSION_RESULT_EXISTS`. An unknown result requires an explicit
`--retry-same-txid`, after reconciliation against both nodes. The retried
signed transaction must have the same `txid` and `plan_sha256`; a mismatch
returns `TN10_SUBMISSION_TXID_MISMATCH_RECONCILE`. The archive is never
overwritten; the main result file is rewritten as `SUBMISSION_UNKNOWN` before
the new attempt. `TN10_SUBMISSION_LOCK_EXISTS` means a concurrent or crashed
submit left `<result>.lock`; confirm no submit is running before deleting it.
Using a different `--output` path does not detect or prevent a duplicate
submission; nodes reject a conflicting spend. `SUBMISSION_UNKNOWN` has a nonzero exit and
contains the locally calculated `txid`, `plan_sha256`, and
`broadcast: "UNKNOWN"`. `SUBMITTED` has a successful exit and
`broadcast: true`. A preflight refusal before the durable record is written
does not broadcast; once the record is written, any ambiguous result must be
treated as possibly broadcast. Absence from one node's mempool does not prove
absence from its accepted chain. Use two-node `locate` and `verify` to gather
evidence; the tool cannot establish that reconciliation was performed. If the
result remains uncertain, keep `SUBMISSION_UNKNOWN` and stop. Only after
reconciliation may the operator explicitly pass `--retry-same-txid` for the
same transaction and plan.

Create `locate-request.json` with the **complete contents** of `plan.json` as `plan`, the `txid` already included in `plan.json`, network `testnet-10`, your two endpoint strings as `nodes`, and the two saved pre-submission hashes as `start_hashes`. Optional `max_pages` defaults to 4 and must be 1–16. Optional `min_confirmations` defaults to 1; do not lower an approved threshold to obtain success. The read commands use `KTAPE_TN10_ENDPOINTS` (two semicolon-separated endpoints) when set; otherwise they use the `nodes` in the request/evidence and report `endpoints_from_evidence: true`. With caller-supplied endpoints this field is false. Run:

```text
ktape tn10 locate locate-request.json evidence.json
```

The locator reads block bodies from both nodes, recomputes transaction IDs and inclusion, and requires a common containing block. It returns `LOCATED_NOT_VERIFIED`, never an acceptance verdict. Scans are bounded to 2,048 blocks/hashes per page, 16,384 transactions per block and 15 seconds per RPC request. `TN10_SCAN_AT_TIP` means no later block exists yet; `TN10_SCAN_CURSOR_STALLED`, `TN10_LOCATOR_NOT_FOUND_SUBMISSION_UNKNOWN` and `TN10_LOCATOR_NODES_DISAGREE` are non-success errors. If history was pruned, retain `SUBMISSION_UNKNOWN` and obtain a retained containing block from another source. No locator error proves non-submission. Do not substitute the accepting block hash: it need not contain the transaction body. Then run:

```text
ktape tn10 verify evidence.json verified.json
```

Only `VERIFIED` with successful exit is a passing observation. `LOCATED_NOT_VERIFIED` means the block scan found a common inclusion candidate but has not established acceptance. `CONFIRMATIONS_INSUFFICIENT` is written with a nonzero exit; wait and repeat the read-only verification. `UNVERIFIED` is the fail-closed output marker for failed verification. Other validation and disagreement errors exit nonzero. For a proof, target, network or node disagreement, preserve the evidence and investigate; do not re-sign or rebroadcast as a verification remedy. Verification does not check proof of work; the selected-chain and acceptance claims come from the queried nodes.

### Choosing independent nodes

Record each endpoint's operator and where that association was established (operator documentation or direct confirmation). Different DNS names, TLS certificates, IP addresses or matching answers do not establish independent control. If operator independence cannot be established, report "two endpoints; operator independence unverified" and retain that limitation. The CLI enforces distinct hostnames, not an operator trust registry.

Verification counts only the first 64 returned selected-chain blocks and reports a confirmation lower bound and whether that window truncated the response. Acceptance outside that window is unverified; 64 is a practical observation window, not a protocol guarantee. Verification memory use depends on the chosen nodes' responses; the client limits one message to 1 GiB. Use trusted nodes, and override evidence endpoints with `KTAPE_TN10_ENDPOINTS` when appropriate.

## Test keys and funds

Keep custody of your own keys. Use a fresh, disposable test key, never a mainnet wallet or recovery phrase. Generate 32 cryptographically random bytes offline, encode them as 64 hexadecimal characters, and keep the file outside the application and operation directory. A scalar must be nonzero and below the secp256k1 curve order; invalid scalars are rejected. For example, on a Unix workstation:

```sh
umask 077
openssl rand -hex 32 > "$HOME/tn10-test-key.hex"
chmod 600 "$HOME/tn10-test-key.hex"
```

Use a trusted wallet or offline public-key tool to derive the matching x-only public key and `kaspatest:` address; the funding UTXO's P2PK script must belong to that key. Obtain only TN10 test funds from a current testnet faucet or a testnet operator, verify the network with that operator, and export the funding UTXO view for the offline plan. This guide does not provide a verified faucet endpoint. Do not send mainnet funds.

The key file contains only the 64 hexadecimal characters, optionally surrounded by whitespace; it is not PEM, WIF or a mnemonic. Files larger than 128 bytes and symbolic links are refused. Unix group/other permissions must be absent. **Windows cannot automatically validate the file's ACL in this implementation: the tool emits a warning only.** Restrict the file's ACL yourself, or use hidden terminal input. Secret contents are never accepted as command-line arguments.

## Approval and budgets

TN10 does not impose a fixed 1 TKAS minimum change output. The planner requires positive change, recomputes its storage mass with the pinned Kaspa consensus library, rejects storage mass above the TN10 block limit, and commits that mass in the transaction. For example, a 100,000,000 sompi input with a 5,000,000 sompi fee returns 95,000,000 sompi change while remaining within a 1 TKAS total-value budget. Very small positive outputs can still exceed the storage-mass limit. Zero outputs are rejected before the library's storage formula, which divides by output value.

Before emitting a plan, the tool estimates the final signature script (66 bytes), computes non-contextual mass with the pinned library and applies that revision's default relay rate of 100,000 sompi/kg. Storage mass is not added to this relay-fee floor. If the computed minimum exceeds `max_fee_sompi`, planning fails with `TN10_MINIMUM_RELAY_FEE_EXCEEDS_BUDGET`; a smaller supplied fee fails with `TN10_FEE_BELOW_MINIMUM_RELAY`. Neither case increases an authorized ceiling. Node operators may configure a different relay policy, so passing this default-policy check is not proof of admission.

### Implementation limits, distinct from consensus rules

The 96 KiB artifact JSON bound is a local resource limit, not a TN10 payload limit. The 30,000,000 sompi absolute fee ceiling is an existing conservative tool limit; explicit lower authorization limits still apply. The single P2PK input/change-output shape and compute budget of 10 are this prototype's construction choices, not universal transaction requirements. The 15-second connection timeout is a local availability bound. The one-block minimum confirmation threshold is an observation policy, not finality. Key-file input is bounded to 128 bytes and interactive confirmation to 16 bytes for bounded parsing; neither is a consensus rule. These limits remain unchanged by the change-output correction.

The terminal prints the operation, network, artifact target, input amount, full outputs, fee, total value, public signing key and sighash. A shortened example of the display is:

```text
"operation": "TN10_RESOURCE_ROOT_PAYLOAD"
"network": "testnet-10"
"target": "<artifact SHA-256>"
"payload_sha256": "<SHA-256 of exact on-chain payload bytes>"
"payload_bytes": <payload byte count>
"artifact": {"application_uri":"...","artifact_sha256":"...","content_commitment_sha256":"..."}
"input_sompi": 1000000000
"outputs": [<complete transaction outputs>]
"fee_sompi": 30000000
"total_value_sompi": 1000000000
Type SIGN to approve exactly the operation above:
```

Check every output and amount before typing `SIGN`. Noninteractive use requires explicit `--yes`; neither `--yes` nor a JSON `confirmed:true` bypasses budget validation. The request may set `max_fee_sompi`, `max_value_sompi`, `max_total_fee_sompi` and `max_total_value_sompi`. Total value is the full input amount, including change. The default fee ceiling is 30,000,000 sompi; absent value ceilings default to the input value, and cumulative ceilings default to the corresponding single-operation ceiling.

The signer keeps an exclusive, persistent `.tn10-budget-<public-key>.json` ledger beside the plan, plus sibling `.tn10-budget-<public-key>.lock` and `.tn10-budget-<public-key>.pending` files while signing is active or recovery is pending. Preserve these files across operations; moving plans to a new directory or removing the ledger defeats local cumulative accounting. This is a local safety limit against operator mistakes, not a security boundary against an untrusted plan author and not a consensus-enforced spending policy. A reservation is conservative and can remain consumed if writing the signed output subsequently fails. Inspect and reconcile it before attempting recovery; do not delete it to retry blindly.

For external signing, `signature.json` contains `network: "testnet-10"`, `sighash` equal to the plan's `input_sighash_all`, and a lowercase hexadecimal `signature`: 64 Schnorr bytes followed by the `01` SIG_HASH_ALL byte. The tool verifies that signature before producing a signed transaction. External import still requires `SIGN` or `--yes`.

Common refusal codes include `TN10_CONFIRMATION_REQUIRED` (interactive
approval was not given), `TN10_SIGN_OUTPUT_EXISTS` (sign output already exists),
`TN10_BUDGET_LOCKED_RECONCILE_BEFORE_RETRY` (another signer holds the budget
lock), `TN10_BUDGET_PENDING_RECONCILE_BEFORE_RETRY` (a prior reservation needs
reconciliation), `TN10_SIGNING_KEY_MISMATCH` (key does not match the plan), and
`TN10_ENDPOINT_REQUIRED` (no submit endpoint was configured). Do not delete or
edit the budget state to bypass a refusal. The persistent ledger is
`.tn10-budget-<public-key>.json`; its exclusive lock and pending reservation
are `.tn10-budget-<public-key>.lock` and `.tn10-budget-<public-key>.pending`.
Back up these files, inspect the corresponding plan/sign/submit evidence and
reconcile with two nodes before any human-approved recovery. The cumulative
budget is a local accidental-spend control, not a security boundary against an
untrusted plan author or modified tool.

## Secret-handling limits

Managed secret input buffers use `zeroize`; owned secp256k1 key objects are erased on release. This does **not** guarantee removal of copies made by cryptographic libraries, the operating system, terminal, swap, crash dumps or the caller. Standard-library stdin internals are outside the tool-managed zeroization boundary. If Ctrl+C interrupts hidden terminal input, the console may leave echo disabled; restore it with the terminal's normal reset command before typing anything else. Tests check observable outputs for fixed test-key bytes; they do not prove all process memory is free of secrets. Never put keys, recovery material or private notes in plans, logs, evidence, shell history or command arguments.

## Validation status

The external-signature import path, real wRPC submission and dual-endpoint verification completed one real TN10 transaction with this implementation. Transaction ID: `0c94e084df6cf7738f22929ca09323068ca224d2641f6a0c77a074c5687d80c7`. An earlier verifier version reported a depth of 449; the current bounded-window verifier returned `VERIFIED` with `confirmation_depth_lower_bound: 64` and `truncated: true` (required: 1). The fee was 5,000,000 sompi. Later read-only observations used `utxos`, `locate` and `verify` with two public endpoints. These observations are limited to those queries and do not establish the endpoints' operator independence.

Built-in `--key-stdin` signing was also validated once with a 32-byte test key on TN10: transaction `a78694172da69875c5bf4820db3916127c3454e7d65f28aff3005c8a4d172a56` was located and verified through `vector-10.kaspa.green` and `neutrino-10.kaspa.stream`. The first submit attempt panicked before sending and left an unknown result; after a later fix to RPC timeout construction, the same signed transaction file completed the single successful submission. The available record does not independently establish whether the signing secret was entered interactively or piped to stdin. This does not establish that the endpoints have independent operators. Built-in `--key-file` signing remains validated with offline test keys only. These results do not establish mainnet readiness, naming, durable storage, finality or a security audit. Never reuse a published transaction's spent funding input or signature for a new operation.
