# CLI reference

The public CLI is the Rust `ktape` binary. The command contract is recorded in
[`spec/KTAPEOUT_0.5.0_COMMAND_CONTRACTS.json`](../../spec/KTAPEOUT_0.5.0_COMMAND_CONTRACTS.json);
this page summarizes the safe entry
points.

It is not a complete listing of every top-level help family. Run `ktape --help`
and then `ktape <family> --help` for the full command set and options.

## Discovery V2 packaging

Build this candidate's CLI from `core/rust-cli/Cargo.toml` to use the current
`ktape package build` contract. It validates present V2 discovery metadata
and referenced bytes, commits metadata in the runtime, and extracts presentation
mirrors outside that runtime. Missing metadata produces a warning. Older
installed binaries may not implement this contract. See
[runtime packaging](../guides/build-runtime-package.md) and
[discovery metadata](../guides/application-discovery-media.md).

The workspace's separate `discovery validate` command is exposed and validates
legacy V1 discovery input. It is distinct from the Discovery V2 checks that
`ktape package build` performs for metadata embedded in a runtime package.
Packaging performs no upload, signing, broadcasting or name activation.

For a publication-bound candidate, pass the application identity and its
developer profile lock together:

```text
ktape package build --source <dir> --application-uri <namespace/slug> \
  --entrypoint index.html --output <out> \
  --application-id <64-lowercase-hex> --profile-lock <profile-lock.json>
```

The paired flags atomically emit `artifact.json`, `release.json`,
`name-binding.json` and `profile-lock.json` beside the runtime. Supplying only
one flag is rejected; the command remains local-only and does not sign,
broadcast, upload or activate a name.

`--profile-lock` must point to a `KTAPEOUT-DEVELOPER-LOCK-V1` document (or a
JSON wrapper whose `lock` member contains that document). It is not an
application release profile. Use a lock created by `ktape init --profile-package`
or `ktape profile lock`. `ktape init --profile-lock` consumes a lock; it does
not create one. The Rust CLI validates the lock
before creating any output and returns `PACKAGE_PROFILE_LOCK_INVALID` for a
profile, stale hash, missing field or other malformed input.

| Command family | Purpose | Network effect |
|---|---|---|
| `ktape init` | Create a local project and workflow | None |
| `ktape dev workflow` | Validate a local manifest and lock | None |
| `ktape package build` | Build a deterministic `KTAPEOUT-STATIC-RUNTIME-MANIFEST-V1` runtime package that the Shell loads directly | Local files; no upload or signing |
| `ktape profile` | Inspect, search, compose, lock and verify packages | None |
| `ktape artifact` | Select, build, inspect, verify, reproduce and simulate artifacts | None |
| `ktape name` | Normalize names and create unsigned plans | None or read-only evidence |
| `ktape name register-plan <request.json> <output.json> [--keys-file <list.json>]... [--keys-url <https-url>]` | Merge untrusted namespace-key lists, calculate the lock/fee estimate, and verify Gap/Deed state with two TN10 nodes; an optional `native_transaction_input` adds a deterministic unsigned 3-input/5-output transaction candidate | Read-only network; no secret-key parameters, signing, or broadcast |
| `ktape name register-request <intent.json> --names-file <inventory.json> <output.json>` | Build a registration request from a complete controller-maintained slug inventory and dual-RPC Gap/Deed/fee UTXO observations | Read-only network; no secret-key parameters, signing, or broadcast |
| `ktape resource` | Produce deterministic resource projections | None |
| `ktape operation recover` | Assess resumable operation state | Read-only |
| `ktape tn10 plan` | Build a deterministic unsigned TN10 artifact-root transaction with budgets | None |
| `ktape tn10 utxos` / `ktape tn10 locate` | Read two synchronized TN10 nodes for a funding view or a containing block. `KTAPE_TN10_ENDPOINTS` overrides evidence endpoints; otherwise the result marks `endpoints_from_evidence: true` | Read-only network |
| `ktape tn10 registry-script-utxos` | Recompute a Compact Registry script from the request, then read matching UTXOs from two synchronized TN10 nodes; rejects endpoint disagreement and never signs or submits | Read-only network |
| `ktape tn10 authorize <plan.json> <authorization.json> --max-total-sompi <N> --max-fee-sompi <N> --expires-utc <UTC>` | Review a live-dual-quoted native plan and create its bound authorization only after typing the plan digest in an interactive terminal | Local files and terminal only; no network or key access |
| `ktape tn10 sign` | Sign a supported plan with a developer-supplied key (`--key-file` or `--key-stdin`) or import an external signature; native plans require a user-created authorization record and interactive digest confirmation | Reads a local key; no network |
| `ktape tn10 assemble` | Revalidate a native plan, authorization and one or more partial packets, then combine signatures and assemble the transaction; never accepts keys | Local files only; no signing or network |
| `ktape tn10 submit` | Submit a legacy signed plan or verified native aggregate through `KTAPE_TN10_ENDPOINT`; retry an unknown attempt only with `--retry-same-txid` after two-node reconciliation and only for the same txid and plan hash | Broadcasts one transaction |
| `ktape tn10 verify` | Recompute inclusion and require two nodes to agree on acceptance and confirmation depth. It does not check proof of work; chain acceptance is reported from node responses | Read-only network |
| `ktape release` | Validate unsigned release, maintenance and migration plans | None |
| `ktape release candidate-build` | Verify a local Rust package and freeze a content-addressed application candidate | Local files only; no signing or broadcast |
| `ktape release adapters` | List the statically reviewed adapter registry and support boundaries | None |
| `ktape release ship --prepare-only` | Prepare a bounded unsigned operation for a registered adapter | None; no signing or broadcast |
| `ktape release status` | Inspect a resumable operation directory | Read-only |
| `ktape record verify/build/share/open` | Build, verify and exchange a self-consistent keyless application record | Local files; no chain or site credentials |
| `ktape release authorization-request` | Export the exact detached authorization request for review | None |
| `ktape release authorization-import` | Import a previously verified offline authorization packet | Local operation state only |
| `ktape release maintenance-verify` | Verify a maintenance plan and optional genesis/rebuild/readback evidence | None |
| `ktape genesis-provenance` | Compose or verify unsigned genesis provenance and optional rebuild/readback evidence | None |
| `ktape dev genesis-*` | Validate or compose genesis provenance material | None |
| `ktape dev studio-*` | Verify a bounded Studio handoff or build a local runtime bundle | None |
| `ktape doctor` | Diagnose bounded failure conditions | None |

### Read-only TN10 name registration plan

`ktape app publish <namespace>/<slug> --network testnet-10 --intent <intent.json> --names-file <names.json> --output <plan.json>`
provides the official-registry child-registration planning frontend. It uses
read-only dual-node observations and does not sign or broadcast. Its evidence
is `MOCK_OR_VM`; the live canary used `name register-request` and
`name register-plan`.

Name and namespace registration is a developer capability. The current ktape
root's ordinary namespace issuance and registration in the resulting
developer-owned namespace have limited live TN10 evidence. Follow the
[namespace and name guide](../guides/create-namespace-and-register-name.md) for
parent genesis, issuance, public witness tools, authorization and two-node
readback. Existing CompactV1 namespaces remain excluded; missing witness
context fails closed.

The request workflow begins with a local, complete namespace name inventory:

```text
ktape name register-request intent.json --names-file names.json request.json
ktape name register-plan request.json plan.json --keys-file namespace-keys.json
```

`register-request` never enumerates names on-chain. It uses the supplied inventory
to derive the Gap candidate, then requires both TN10 nodes to agree on the current
Gap, parent Deed, and selected fee UTXO. A missing/consumed candidate Gap fails
with `NAME_KEY_LIST_INCOMPLETE_OR_STALE` and points to `--names-file`; complete the
local inventory before retrying. The command accepts no key parameters.

`ktape name register-plan request.json output.json [--keys-file extra.json] [--keys-url https://keys.example/tn10.json]`
accepts a JSON request with
`network`, `namespace`, `slug`, public `owner`, `existing_slugs`,
`namespace_key_sources`, `estimated_mass`, `fee_rate_sompi_per_gram`, `states`
and two `nodes`. Each state has `role` (`gap` or `deed`) and a canonical
`script_public_key`; provide the current Gap and Deed scripts. The bundled
namespace key list is always included. Request-embedded sources and each
repeatable `--keys-file` plus one optional `--keys-url` are untrusted and
unioned after their names and keys are recomputed. The HTTPS source rejects
userinfo and non-443 ports, pins the connection to validated public DNS
answers, bypasses environment proxies, and rejects all redirects. Its response
is capped at 64 KiB and the whole fetch has an 8-second timeout. A malformed
source fails validation; an absent namespace or a key that does not recompute
fails with `NAME_KEY_LIST_INCOMPLETE_OR_STALE` and instructs the developer to
refresh the public list or supply a current `--keys-file` / `--keys-url`.

For a native transaction candidate, the request may also include
`native_transaction_input` with exactly three `inputs` (each containing
`outpoint`, `amount`, `block_daa_score`, and `script_public_key`) and five
ordered `outputs` (`parent_successor`, `left_gap`, `name_deed`, `right_gap`,
`fee_change`). Input signature scripts must be empty. The builder uses the
pinned economics metadata and native Kaspa transaction types. It checks the
parent Deed's `bondSompi` state field against the 10 KAS requirement; this is
not an extra 10 KAS charge per registration. Separately, it requires the
consumed parent Deed UTXO and child Name Deed output to match the reference
structure (the observed Name Deed output is 1 KAS), and checks each Gap against
its 1 KAS floor. The result includes `plan_sha256`, which commits to every input,
output and script. This field is an explicit unsigned transaction candidate;
`native_transaction_funding_claims_verified` remains false because this
command has not independently read back the supplied funding inputs. No
signature or broadcast is performed.

The command reads the requested scripts' UTXOs from both nodes and fails if
the nodes disagree, either state is absent, or its value is below the fixed
contract floor/bond. The returned bundle records the exact scripts and node
observations. It does not prove that a supplied script was rendered from the
pinned Gap/Deed templates or prove that the requested child name is absent;
`name_absence_claim` is therefore `NOT_ESTABLISHED_BY_THIS_COST_PLAN`.
`sequence` and `updated_at` in key lists are informational. The plan reports
sompi and KAS, estimated network fee, and newly locked value. For the observed
registration shape, net new locking is 2 KAS plus the fee: 10 KAS is the parent
Deed's `bondSompi` state requirement, not an amount added on each registration.
This correction is based on the 9edd, d385 and 97c9 TN10 registration samples
reviewed on 2026-11-02. It also reports
`refund_path: NONE_IN_V1`. It always sets `next_owner` to `owner`. This command
does not accept keys, sign, broadcast, register, transfer, refund, merge Gaps,
close namespaces, or operate on mainnet.

Registration submission readback compares the exact transaction returned by
both nodes and binds it to the saved plan and submission receipt. It does not
validate transaction signatures, re-query whether predecessor UTXOs have been
spent, or establish finality. A matching readback means only that both queried
nodes returned the same transaction bytes for the requested txid at observation
time. Treat predecessor state as unchecked and finality as unchecked unless a
separate verifier establishes those facts.

### Native registration signing and assembly

The native local workflow is:

```text
ktape name register-request <intent.json> --names-file <names.json> <request.json>
ktape name register-plan <request.json> <plan.json> [--keys-file <keys.json>]
ktape tn10 authorize <plan.json> <authorization.json> --max-total-sompi <N> --max-fee-sompi <N> --expires-utc <YYYY-MM-DDTHH:MM:SSZ> [--allow-broadcast] [--allow-readback]
ktape tn10 sign <plan.json> <partial.json> --authorization <authorization.json> --key-stdin
ktape tn10 assemble <plan.json> <assembled.json> --authorization <authorization.json> --partial <partial.json>
ktape tn10 submit <assembled.json> <submission.json>
```

`authorize` requires both numeric caps and a UTC expiry supplied by the user.
The record is limited to 24 hours, binds the plan digest, network, role public
keys, amount and fee limits, creation/expiry times, and the requested broadcast
and readback scope. It rejects estimated fees: the plan must contain a fresh
`live_dual_node_quote` (at most 10 minutes old) with two distinct endpoints,
matching endpoint/rate entries, and no more than a 2x rate spread. It displays
the transaction inputs and outputs, public roles, `SAME_KEY` or
`DIFFERENT_KEY`, newly locked amount, quote source and both caps. The user must
type `AUTHORIZE <plan_sha256>` in the interactive terminal. The command has no
`--yes` option, requires a terminal, and creates the output file exclusively;
a plan JSON or a `REVIEW_ONLY_NO_APPROVAL` document is not authorization.
`sign` validates the record and separately asks for signing confirmation. Keep
the secret out of command arguments. With `SAME_KEY`, one `sign` invocation
produces one packet covering every matching role and one `assemble` invocation
consumes it. With `DIFFERENT_KEY`, run `sign` once per key against the same plan
and authorization, then pass every packet with a repeated `--partial` option.
Assembly verifies plan and authorization bindings, role-to-input assignments,
each partial signature, completeness and duplicates; it does not sign or submit.

`submit` persists `SUBMISSION_UNKNOWN` before attempting broadcast. An unknown
outcome must be reconciled with two nodes before retry; retry requires
`--retry-same-txid`, the same txid and plan digest, and preserves the prior
attempt. A successful submission acknowledgment is not a dual-node readback.
The public `tn10 verify <evidence.json> <output.json>` command checks inclusion,
acceptance and confirmation depth from two nodes; it is not an exact raw
transaction-byte readback. Exact transaction readback reconciliation is
currently exposed as a library operation and exercised by offline mock tests.

### Pinned Toccata VM evidence boundary

The offline verifier is pinned to rusty-kaspa v2.1.0 and requires the
Toccata transaction version. That version exposes no pre-Toccata execution
mode switch. The existing negative checks reject a transaction with the wrong
version and compare a 2,801-byte witness item with the historical 520-byte
threshold; the latter is a size assertion, not execution under a legacy VM.
As of 2026-11-04, v2.1.0 is the latest formal tagged release. The pin is kept
because it bounds compressed and uncompressed block-header parent counts before
TN10 verification recomputes commitments from untrusted RPC headers; untagged
development revisions are not treated as releases.
Earlier local verification used a real-contract fixture for `authorize_child`
and `register_interior` with `INTERIOR` registration, assembled through the
public G1c path and executed for every input in the pinned VM. The runnable
fixture test and its data are not included in this candidate, so a clean clone
cannot reproduce that result. The earlier fixture did not cover `issue`,
`change_owner_target`, or `SLOT`, and did not prove TN10 chain acceptance. The
separate `native_witness_assembly` test uses synthetic redeem scripts. The
2,801-byte witness comparison is a size assertion, not a pre-Toccata VM run;
v2.1.0 has no pre-Toccata mode switch. Values named
`committed_compute_mass_grams` are derived from the committed compute budget,
not measured by the VM. Real-contract chain validation remains pending M8-A.

TN10 result statuses and process exits are explicit; a JSON file containing a
status does not make a nonzero result successful:

| Command | Result status | Exit | `txid` |
| --- | --- | --- | --- |
| `plan` | `UNSIGNED_LOCAL_PLAN` | 0 | Included; computed locally before signing |
| `sign` | `SIGNED_OFFLINE` | 0 | Included in the signed transaction |
| `utxos` | `UTXO_VIEW_MATCH` | 0 only when both views agree | No |
| `submit` | `SUBMITTED` | 0 after matching acknowledgement | Yes |
| `submit` | `SUBMISSION_UNKNOWN` | nonzero | Yes; `broadcast` is `"UNKNOWN"` |
| `locate` | `LOCATED_NOT_VERIFIED` | 0 when a common inclusion candidate is found | Yes |
| `locate` | `TN10_SCAN_AT_TIP`, `TN10_SCAN_CURSOR_STALLED`, `TN10_LOCATOR_NOT_FOUND_SUBMISSION_UNKNOWN`, `TN10_LOCATOR_NODES_DISAGREE` | nonzero | Error output may identify txid |
| `verify` | `VERIFIED` | 0 only when proof, acceptance and required depth pass | Yes |
| `verify` | `CONFIRMATIONS_INSUFFICIENT` | nonzero | Yes |
| `verify` | `UNVERIFIED` marker | nonzero on validation, transport or disagreement error | May be absent if evidence could not be parsed |

`SUBMISSION_UNKNOWN` does not itself authorize retry. After two-node
reconciliation, `--retry-same-txid` permits only the same txid and plan hash;
the archive is never overwritten, and the main result file is rewritten as
`SUBMISSION_UNKNOWN` before the new attempt. `TN10_SUBMISSION_LOCK_EXISTS` means
a concurrent or crashed submit left `<result>.lock`; confirm no submit is
running before deleting it. A different txid is rejected for the same result
path. This does not protect a different `--output`
path; nodes reject any actual double spend. `locate` only finds a shared inclusion
candidate; it does not prove acceptance. Verification trusts the queried
nodes' chain-state responses and does not validate proof of work.

`TN10_SCAN_AT_TIP` means the locator start hash is the current tip and no later
blocks are available yet; it does not mean the transaction was not submitted.
`TN10_SCAN_CURSOR_STALLED` means the scan cursor did not advance.
`TN10_LOCATOR_NOT_FOUND_SUBMISSION_UNKNOWN` means the bounded scan found no
containing block, and `TN10_LOCATOR_NODES_DISAGREE` means the nodes did not
agree on a containing block. These are nonzero outcomes, not retry permission.

Commands that produce a plan, hash, receipt or UI result do not automatically
sign or broadcast. The `ktape tn10` flow is the exception for anchoring an artifact
root: `sign` uses a key you supply and `submit` broadcasts, each only when you run
it and approve the operation. Any other live write (names, Profile-specific
releases) requires an explicitly authorized external provider and the required
evidence/readback boundary.

### Generic application candidate

After `ktape package build` succeeds, freeze the package with the public Rust
candidate builder. The profile, package, snapshot store and result are all
local paths; the command verifies release/content identity and is idempotent.

```text
ktape release candidate-build \
  --profile <application-release-profile.json> \
  --package <package-directory> \
  --snapshot-store <snapshot-directory> \
  --output <candidate-result.json>
```

Pass the resulting file to `ktape release ship --prepare-only` when the selected
adapter is admitted. `candidate-build` never signs, broadcasts, imports a
receipt or deploys a site, and it does not make an unready adapter publishable.

`ktape release adapters` is a catalog only. A `READY` registry entry is not
executable evidence by itself; verify the published helper bundle manifest and
run the public closure-check script from the intended checkout before preparing
a workflow. These checks never invoke an adapter, sign, broadcast, or change a
release.

The public candidate does not include prebuilt helper binaries. Build the
Windows x86_64 helper bundle from source with
`cargo run --locked --bin ktape-release-helper-bundle -- --output NEW_DIRECTORY`.
The generator records the source toolchain and refuses to finalize a bundle when a
declared executable, role reference, or distribution asset is missing or has a
different digest. A bundle you build yourself will not match the maintainers'
registry pins, so `ktape release adapters` reports `BLOCKED` until you review and
pin your own digests; do not bypass that with a different binary. Then run the
helper-bundle manifest and closure checks.

### Keyless application records

Application publishers can prepare a Host-importable record without a site
credential. Use `ktape record build` with explicit identity fields, a card JSON
file and at least one digest-addressed locator; the command recomputes the
TN10 name key and target commitment and refuses inconsistent output. The
result is local and self-consistent only: `chain_verified` and
`content_verified` remain false until a Host performs its own source and
chain checks.

```text
ktape record verify <record.json>
ktape record share <record.json>
ktape record open 'ktape-record=<base64url-json>'
```

`share` and `open` round-trip the canonical record as a URL fragment. The
fragment carries no publisher secret and does not activate a name, upload
bytes, sign, broadcast or deploy. A Host may separately verify the optional
`deed_evidence` and `release_authorization` fields under its own policy.

`ktape app content-preflight ARTIFACT.json` verifies a bounded local
`OnChainContentV1` artifact. An optional package-local `discovery/media.json`
can describe icon/card images. Studio generates it from optional image inputs
and includes the descriptor and bytes in the ordinary content roots. The CLI
checks its schema, role budgets and declared path, MIME type, length and
SHA-256 against the verified artifact files; it does not decode image formats,
publish the artifact, or prove a current Registry/name binding. Browser display
must verify actual bytes and decode dimensions. Omit media when it adds no
value; media has no separate Profile, publication path or authority model.
For the complete author-to-directory workflow, see the
[Application discovery images guide](../guides/application-discovery-media.md).

Python CLI modules remain conformance-only. They must not be presented as a
second public signing CLI.

For Profile composition, the Rust CLI fills a capability requirement when
exactly one selected package provides it; missing or ambiguous providers are
reported for an explicit developer decision. Typed interface bindings require
matching definitions committed in both verified packages. Their current status
is `STATIC_ONLY`: compatible declarations do not prove cross-application L1
execution. Python reference tooling reports typed or external dependency
composition as `UNSUPPORTED_IN_REFERENCE`.

The release and developer commands are local preflight operations. They do not
execute migrations, sign, broadcast, or assert live-chain evidence.

Private-directory V2 structural verification is available through the
`ktapeout-runtime` library module. This public candidate does not expose a
corresponding CLI command.

`maintenance-verify` and `genesis-provenance verify` accept evidence produced by
an external adapter, but only validate its declared bindings locally. Supplying
evidence does not turn a receipt into consensus finality, signer authority or
L1 admission.

## Local runtime packaging

`ktape package build` creates a deterministic runtime package from a local
source directory. It writes a `KTAPEOUT-STATIC-RUNTIME-MANIFEST-V1` manifest and
the files at their original paths under
`runtime/<network>/<namespace>/<slug>/<release_id>/`, enforces the browser
verifier limits and rejects hidden files, key material and source maps. It
performs no upload, signing, broadcast, locator
publication, or activation. See [Build a local runtime package](../guides/build-runtime-package.md)
for the command example and limits.

The public authorization flow is `authorization-request` -> external Ed25519 signature
-> `authorization-import`. Local-key `authorization-sign` is available only in
publisher/host builds with the `publisher-signing` feature.
