# KTAPEOUT Application Developer Skill

For application developers and their AI assistants: write a static app, package it, verify it locally, and understand how publishing works. Operator and release-authority material is in [application-engineering.md](application-engineering.md) and is not needed here.

Only use commands that the installed binary lists in `ktape <command> --help`. If a command is unclear, stop and ask instead of guessing.

## 1. Install

```powershell
cargo build --locked -p ktapeout-cli
```

In a clean Windows walkthrough on 2026-11-06, the first build took about 12 minutes; time varies with machine, network and cache state. It produced about 1.5 GB of build output. Later builds reuse the cache. Use an external `CARGO_TARGET_DIR` so build output stays out of the source tree. The binary is `ktape` under `<target>/debug/`.

## 2. Scaffold

```powershell
ktape init --template StateMachine --network testnet-10 --output ./my-app
ktape dev workflow ./my-app/workflow.json
```

For the starter, `dev workflow` reports `INCOMPLETE`: `check` is `NEEDS_INPUT`, `build` is `PASS` with a `LOCAL_ONLY` artifact, `package` is `REQUIRES_HUMAN_REVIEW`, and `test` is `STRUCTURE_ONLY`. The successful build is only a local artifact projection; it does not execute application behavior or make the app publishable. Exit code 0 means the command completed, not that all stages passed.

## 3. Write a static app

Put plain static files, including your own `index.html`, in a dedicated source
directory such as `./my-app/site`. Keep development workflow outputs such as
`build/` and `package/` outside it; the packager includes every eligible file
under `--source`. `ktape init` creates `./my-app/discovery/metadata.json`, but
package build reads discovery metadata only from inside `--source`; move it
with `Move-Item .\my-app\discovery .\my-app\site\discovery` (PowerShell) or
`mv ./my-app/discovery ./my-app/site/discovery` (Bash). No server code, secrets
or wallet keys.

## 4. Package

```powershell
New-Item -ItemType Directory -Force .\out | Out-Null
ktape package build --source ./my-app/site --application-uri <namespace>/<slug> `
  --entrypoint index.html --output ./out
```

Create the output parent directory before running the command. Either keep
development outputs outside `site/` or package the site before running the
workflow. `--output` must be outside `--source`. Only `testnet-10` is admitted.
Verified output includes `package_digest`, `release_id`, `entrypoint` and
status `BUILT`. Nothing is signed or broadcast. `BUILT` means the package was
created locally, nothing more. Format details: [package format](../reference/package-format.md).

## 5. Keyless records

A record is a self-describing, unsigned description of a release that any Shell can open.

- `ktape record build` builds a record from explicit parts and refuses output it cannot verify.
- `ktape record verify <record>` checks that a record file is self-consistent. It does not touch the chain or artifact bytes.
- `ktape record share <record>` encodes a verified record as a URL fragment.
- `ktape record open <fragment>` decodes a fragment and verifies the record inside.

Run `ktape record build --help` for the required parts.

## 6. How publishing works

Publication to Testnet-10 has an artifact-root path and a developer-facing name-registration preview. To anchor an artifact root, follow [Publish an artifact root on TN10 with `ktape`](../guides/publish-on-tn10-with-ktape.md): `ktape tn10 plan` builds a bounded unsigned transaction, the developer signs it with their own disposable test key, `ktape tn10 submit` broadcasts it, and `ktape tn10 verify` recomputes the proof and requires two nodes to agree. Profile-specific application paths remain authority-gated: a bounded unsigned operation is prepared, authorized offline by whoever holds signing authority, then resumed and read back; see [capabilities and status](../reference/capabilities-and-status.md) and, for the operator procedure, [the Operator Release Skill](application-engineering.md).

For the current TN10 child-name registration shape, the parent Deed's `bondSompi`
state field must satisfy the 10 KAS requirement. It is not a new 10 KAS payment
for each name. The observed Name Deed output is 1 KAS, and the registration
adds 2 KAS net to its Gap outputs, plus the transaction fee. This accounting
was corrected on 2026-11-02 from the 9edd, d385 and 97c9 on-chain samples.

For registration submission reconciliation, matching transaction readback from
two nodes does not validate signatures, re-check whether predecessor UTXOs have
been spent, or prove finality. It reports only that both queried nodes returned
the same transaction bytes for the requested txid at that observation time.
Keep signature validity, predecessor state, and finality as separate unchecked
claims unless their own verification evidence is available.

Earlier local work exercised a real-contract fixture for `authorize_child` and
`register_interior` with `INTERIOR` registration through the public G1c path and
the pinned rusty-kaspa v2.1.0 verifier. That fixture and its test are absent
from this public candidate, so a clean clone cannot reproduce that result.
It did not establish acceptance on TN10 or cover `issue`,
`change_owner_target`, or the `SLOT` variant. The separate 2,801-byte versus
historical 520-byte check is a size comparison, not a pre-Toccata VM run; the
pinned verifier has no pre-Toccata mode switch. Values named
`committed_compute_mass_grams` are derived from the committed budget, not
measured by the VM. Do not claim chain acceptance or a completed Toccata
difference assessment; real-contract chain validation remains pending M8-A.
As of 2026-11-04, v2.1.0 is the latest formal tagged release. The pin retains
the upstream bound on compressed and uncompressed block-header parent counts
before commitments are recomputed from untrusted RPC headers. Untagged
development revisions are not treated as releases.

The V6 reference child-name workflow is `register-request` → `register-plan` → `authorize` → local `sign` → `assemble` → `submit` → verification/readback. Earlier local work verified assembly and VM execution, but its fixture is not included in this candidate and cannot be reproduced from a clean clone. End-to-end TN10 validation for existing CompactV1 namespaces is incomplete; `register-request` fails closed when required witness context is unavailable. Name and namespace registration is a developer capability, not an operator-only permission. The names file is the controller's complete local inventory; the request generator does not enumerate names on-chain. Request and plan generation use dual-RPC observations and never read a key. `authorize` is local-only and requires a live dual-node quote; plans marked `estimate` cannot receive a signing authorization.

After reviewing the exact plan, create its record in a terminal with user-provided cumulative amount and fee caps and an expiry no more than 24 hours away. The command displays the plan digest, network, inputs, outputs, role keys, key-sharing relationship, newly locked amount, quote source and limits, then requires typing `AUTHORIZE <plan_sha256>`. It binds the plan digest, network, role keys, both limits, quote digest, creation/expiry and broadcast/readback scope. A review-only record, `--yes`, or a plan file alone does not grant signing authority. Keep the secret out of command arguments:

```powershell
ktape tn10 authorize .\register-plan.json .\register-authorization.json `
  --max-total-sompi <N> --max-fee-sompi <N> `
  --expires-utc <YYYY-MM-DDTHH:MM:SSZ> --allow-broadcast --allow-readback
ktape tn10 sign .\register-plan.json .\register-partial.json `
  --authorization .\register-authorization.json --key-stdin
ktape tn10 assemble .\register-plan.json .\register-assembled.json `
  --authorization .\register-authorization.json --partial .\register-partial.json
ktape tn10 submit .\register-assembled.json .\register-submission.json
```

For `SAME_KEY`, one signing invocation covers all roles matched by that key and produces one partial packet. For `DIFFERENT_KEY`, run `sign` once per key against the same plan and authorization, then provide every packet through repeated `--partial` options to `assemble`. Assembly only verifies and combines packets; it does not sign or submit. `submit` broadcasts once and persists an unknown outcome before attempting the RPC. Reconcile an unknown submission with two nodes before retrying; only the same txid and plan digest may be retried with `--retry-same-txid`.

For a multi-step operation, do not authorize the next plan early: finish and verify the first step's required readback, then generate, review and authorize the second plan against its new state.

After submission, `ktape tn10 verify <evidence.json> <output.json>` checks inclusion, acceptance and confirmation depth using two nodes. This command is not exact raw-transaction readback. The Rust library's exact two-node transaction-byte reconciliation is currently covered by mock tests; it does not validate signatures, re-query whether predecessor UTXOs have been spent, or establish finality.

## 7. What you cannot do from this public candidate

- The `ktape tn10` artifact-root flow does not guarantee content retention or support Mainnet. Name and namespace registration is a developer capability, not an operator-only permission; the public name path is a V6 reference preview. Earlier local assembly and VM results are not reproducible from this candidate because the corresponding fixture is not included. End-to-end TN10 validation for existing CompactV1 namespaces is incomplete and `register-request` fails closed when required witness context is unavailable. Profile-specific releases remain separately authority-gated: `ktape release adapters` (run from the checkout) lists `tn10-publisher-release-v1` as `IDENTITY_ONLY`, so it implements no release phase here. Run from another directory it returns `RELEASE_ADAPTER_REGISTRY_NOT_FOUND`; run it from the checkout, or set `KTAPEOUT_RELEASE_ADAPTER_REGISTRY` to the registry JSON path.
- The first registry namespace release supports only read-only state discovery and unsigned planning. It does not transfer namespace ownership, refund registration bonds, merge Gaps, close a namespace, or use Mainnet. No bond-refund path exists in this release; do not imply that a bond can be recovered.
- No wallet provider or browser client is bundled.
- The starter's `ktape app test` result is `STRUCTURE_ONLY`: it checks that test vectors are declared, not that they execute. The included Rust integration tests exercise encoding, commitment recomputation, invalid-input rejection, signing boundaries, submit state and chain acceptance using offline fixtures. They do not show live chain inclusion or application runtime behavior.
- Never give an assistant a key file, recovery phrase or wallet, and never ask it to run `ktape tn10 sign`, `ktape tn10 submit` or any credentialed endpoint call on your behalf.

## Status labels

Report the weakest label the evidence supports. Never upgrade a weaker label because a command succeeded: a zero exit code, `BUILT`, a verified record or a passing vector is not chain inclusion, publisher authorization or production readiness. Keep results `LOCAL_ONLY` until a separately reviewed signing and readback boundary exists, and quote the exact command and result when reporting.
