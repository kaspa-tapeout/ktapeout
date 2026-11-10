# Create a namespace and register a name on TN10

This advanced CLI flow uses Registry Adapter 1.0.0 under the existing ktape
root and the V6 named witness ABI. It does not create a root, change reserved
names, or operate on the existing CompactV1 namespaces. Ordinary root Gap
insertion is permissionless subject to the contract's interval/reservation
checks. The developer controls the new namespace and authorizes its child
registrations. Frozen NamespaceIssuanceV1 admission and this deployed adapter
are different contracts; do not substitute their requests or economics.

Prerequisites: Rust 1.91.0, Python 3, two synchronized TN10 wRPC nodes with
UTXO indexing, and your own funded TN10 key. Keep keys outside the repository.
Build from the repository root, then add `target/debug` to your PATH:

```sh
cargo build --locked -p ktapeout-cli --bin ktape --features tn10-network,developer-signing
cargo build --locked -p ktapeout-registry-issuer --bins
ktape name registry-info
```

Use `ktape name test-keygen` only for disposable TN10 testing, or supply your
own protected 32-byte hexadecimal key file. `ktape name test-key-info KEY_FILE`
prints public key/address information. The key file itself is never JSON.
On Windows restrict its ACL to your account. Do not put key bytes in arguments.

## Public inputs and identity

The pinned root identity and amounts are in
[`tn10-deployment-v1.json`](../../data/registry/tn10-deployment-v1.json).
Obtain fresh public state rather than copying historical outpoints. A public
UTXO request is `{"network":"testnet-10","address":"YOUR_ADDRESS","nodes":["NODE_A","NODE_B"]}`.
For a covenant replace `address` with `script_public_key` and use
`ktape tn10 registry-script-utxos REQUEST OUTPUT`; for wallet funds use
`ktape tn10 utxos REQUEST OUTPUT`. Both commands compare live UTXOs on two nodes.

Choose an unused canonical lowercase namespace and slug. Encode each as a
64-byte frame: one length byte, ASCII bytes, then zero padding. Namespace key
is SHA-256 of `KTAPEOUT/0.5.0/NAMESPACE_FRAME/V1\0`, byte `0a`, and namespace frame;
name key is SHA-256 of `KTAPEOUT/0.5.0/NAME_FRAME/V1\0`, byte `0a`, namespace
frame and slug frame. The CLI recomputes keys and rejects mismatches.

The root Gap must contain your namespace key and allow ordinary issuance.
Recover its constructor arguments from the public root transaction history,
following successor outputs from the pinned root genesis. Recompile them with
the public issuer's `INSPECT_STATE` operation and require the resulting script
to equal the live UTXO script. Its nine `state_args` are mode, lower key,
upper key, upper-is-max, reserved namespace key, reserved authority, controller,
ruleset version and parent bytecode length. Never guess them from an indexer
label or bypass a reserved interval. Competing root Gap spends require refresh.

## 1. Developer parent genesis

Create `parent-request.json` with schema
`KTAPEOUT-REGISTRY-ADAPTER-NAMESPACE-GENESIS-INPUT-V1` and these public fields:
`network` (`testnet-10`), `authority_xonly` (your key), `namespace_hash`,
`namespace_frame`, `authority_commitment`, `resolver_policy_hash`,
`registry_root` (pinned root CID), `nonce` (0), `funding_utxo` (fresh wallet
view item), `funding_change_script_public_key`, `fee_sompi`,
`parent_state_sompi` (1000000000), `gap_state_sompi` (100000000),
`compute_budget` (100). The authority commitment is SHA-256 of the decoded
32-byte authority x-only public key; keep the same commitment and policy later.
The compiler source and validation are in
[`namespace_parent_genesis.rs`](../../core/adapters/registry-issuer/src/namespace_parent_genesis.rs).

```sh
ktape name parent-genesis-transition plan parent-request.json parent-plan.json
ktape tn10 authorize-namespace-transition parent-plan.json parent-auth.json --node NODE_A NODE_B --max-total-sompi YOUR_DEBIT_CAP --max-fee-sompi YOUR_FEE_CAP --expires-utc UTC_EXPIRY --allow-broadcast
ktape name parent-genesis-transition sign parent-plan.json parent-signed.json --authorization parent-auth.json --key-file YOUR_KEY_FILE
ktape name parent-genesis-transition assemble parent-signed.json parent-assembled.json
ktape tn10 submit-namespace-transition parent-assembled.json parent-submit.json --node NODE_A NODE_B
```

Replace uppercase placeholders with your actual bounded values. Authorization
and signing prompt for the displayed exact plan hash; broadcast prompts for
the exact transaction ID. Output files must be fresh. Confirm the parent and
initial application Gap with `registry-script-utxos` before proceeding.

## 2. Insert the namespace into the existing root

Create `issue-request.json` as `{"action":"profile_state_transition","request":{...}}`.
The inner object has schema `KTAPEOUT-REGISTRY-ADAPTER-NAMESPACE-OPERATION-V1`,
`network:"testnet-10"`, `operation:"ISSUE_NAMESPACE"`, fresh `parent_utxo`,
`root_gap_utxo`, `fee_utxo`, verified `root_state_args`, `parent_state_args`
(`[namespace_hash,authority_commitment,resolver_policy_hash,registry_root,nonce]`),
`namespace_frame`, `claimant_public_key` and `fee_sompi`. Set
`public_signatures` to an object with null `parent_signature`,
`claimant_signature` and `fee_signature`. Use your own authority and fee key;
different keys can sign independently and combine public packets with the
same plan hash. No root-controller key is required for an ordinary Gap.

```sh
ktape name issuance-transition plan issue-request.json issue-plan.json
ktape tn10 authorize-namespace-transition issue-plan.json issue-auth.json --node NODE_A NODE_B --max-total-sompi YOUR_DEBIT_CAP --max-fee-sompi YOUR_FEE_CAP --expires-utc UTC_EXPIRY --allow-broadcast
ktape name issuance-transition sign issue-plan.json issue-signed.json --authorization issue-auth.json --key-file YOUR_KEY_FILE
ktape name issuance-transition assemble issue-signed.json issue-assembled.json
ktape tn10 submit-namespace-transition issue-assembled.json issue-submit.json --node NODE_A NODE_B
```

Confirm the certificate (output 2) and parent successor (output 0) on both
nodes. Issuance spends the initial parent; later registration uses its
successor, not the genesis outpoint. The initial application Gap stays unspent.

## 3. Prepare and register a child name

Create a public `witness-input.json` with schema
`KTAPEOUT-REGISTRY-ADAPTER-APP-REGISTRATION-INPUT-V1`, `network`,
`parent_covenant_id`, `authority_xonly`, the same five parent state fields,
`namespace_frame`, `slug_frame`, `name_key`, `claimant_xonly`,
`target_authority_xonly`, `target_commitment`, `child_resolver_policy_hash`,
`bond_sompi:100000000` and the containing application Gap's `gap_lo`, `gap_hi`,
`gap_hi_is_max`. For the first registration the empty Gap is zero/zero/max=1.
The target commitment is your application's public commitment, not a key.

```sh
ktape-name-registration-witness --input witness-input.json > witness.json
python scripts/prepare_name_registration.py --witness-input witness-input.json --witness witness.json --parent-view parent-view.json --gap-view gap-view.json --fee-view fee-view.json --fee-outpoint YOUR_FEE_OUTPOINT --namespace YOUR_NAMESPACE --slug YOUR_SLUG --issuance-txid YOUR_ISSUANCE_TXID --fee-reserve-sompi YOUR_FEE_CAP --output intent.json
ktape name register-request intent.json --names-file names.json request.json
ktape name register-plan request.json registration-plan.json
ktape tn10 authorize registration-plan.json registration-auth.json --max-total-sompi YOUR_INPUT_TOTAL_CAP --max-fee-sompi YOUR_FEE_CAP --expires-utc UTC_EXPIRY --allow-broadcast --allow-readback
ktape tn10 sign registration-plan.json partial.json --authorization registration-auth.json --key-file YOUR_KEY_FILE
ktape tn10 assemble registration-plan.json signed.json --authorization registration-auth.json --partial partial.json
```

`names.json` is your complete namespace inventory:
`{"schema":"KTAPEOUT-REGISTERED-NAMES-V1","network":"testnet-10","namespace":"YOUR_NAMESPACE","slugs":[]}`
for a newly created empty namespace. Keep it complete after each accepted
registration; it is an untrusted absence claim, not independent chain evidence.
The preparation script reads public data only. The plan refreshes live fee
quotes and validates witness bindings. Registration authorization currently
caps total input value, including existing covenant funds, rather than net spend.

Set the same two endpoints for registration submission. In a POSIX shell:

```sh
export KTAPE_TN10_ENDPOINTS='NODE_A;NODE_B'
ktape tn10 submit signed.json registration-submit.json
```

In PowerShell use `$env:KTAPE_TN10_ENDPOINTS='NODE_A;NODE_B'`.
Confirm the name Deed at output 2 using the generated `name_deed` script and
`registry-script-utxos`. Compare transaction ID, amount and covenant ID on both
nodes. This establishes registration, not payload upload or a hosted app.

## Cost and recovery

The deployed parent constructor requires 10 KAS plus a 1-KAS initial Gap.
Ordinary issuance replaces one root Gap with two Gaps and a certificate,
adding 2 KAS. Child registration replaces one application Gap with two Gaps
and a Deed, adding 2 KAS. The child has a 10-KAS logical state bond field but
the adapter's Deed carrier is 1 KAS; do not charge another 10 KAS. These values
come from the public adapter builders and were confirmed by the canary output
values. Fees are additional; bound them using fresh plans and quotes.

Do not retry an unknown broadcast blindly. Preserve the exact signed transaction
and submission record, reconcile the exact ID on both nodes, and inspect all
input outpoints. Only retry the same ID after both nodes prove absence and the
inputs remain unspent. An accepted transaction must never be resubmitted as a
new payment. Competing spends or expired authorizations require a new plan and
new signatures; do not edit signed JSON. Partial failures leave observable
on-chain state: resume from the confirmed parent/certificate rather than creating
another namespace. Existing output files are preserved to prevent accidental reuse.

## Limited live evidence

On 2026-11-10 a disposable, now-abandoned TN10 test namespace completed:

| Operation | Transaction ID | Two-node readback |
|---|---|---|
| Parent genesis | `2994c41663ef21746646944975fe45570262f8f4dcea138ea6f2982223807e64` | Parent and initial Gap matched |
| Namespace issuance | `2bf40cd3f6d9ce07a918305fc8eb46f66976eded8cb5ba2d6da9f378df335f74` | Certificate output 2 and successor parent matched |
| Child registration | `feb812c497196762bdc306c7128a9415be95a073fa3b37a78d2fe78c4561d197` | Deed output 2, 100000000 sompi and parent CID matched |

The public nodes were neutrino-10.kaspa.stream and quark-10.kaspa.red; operator
independence is not proven. The test namespace is abandoned and is not a
recommended namespace or application. See the [capability matrix](../reference/capabilities-and-status.md).
