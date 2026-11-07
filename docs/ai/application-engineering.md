# KTAPEOUT Operator Release Skill

> Application developers should use [application-developer.md](application-developer.md) instead. This page covers operator and release-authority procedures.

## Publication tooling boundary (2026-10-26)

Start with the installed `ktape --help`, then inspect the chosen command's help.
This public candidate ships the shared Rust release workflow entry points
`ktape release adapters`, `ktape release ship`, `ktape release status`,
`ktape release authorization-request` and
`ktape release authorization-import`.
Use `release ship --prepare-only` to construct a bounded unsigned operation,
export the detached authorization request, import only a verified offline
authorization, and then resume the same operation. These commands do not grant
signing, broadcasting or deployment authority.
Before preparing a workflow, run `ktape release adapters` from the intended
checkout and inspect the reported execution boundary. The registry catalog is
only a reviewed declaration; the published helper bundle manifest and its
closure-check script prove that every current-platform executable and
dependency exists and matches its pinned SHA-256. A missing or changed pin
returns `BLOCKED` and must not be bypassed with a different binary.

The engineering source now separates the candidate/package `adapter_id` from
the release-execution `release_adapter_id` in Application Release Profile V4;
V1–V3 profiles retain their single-ID interpretation. A valid package candidate
does not imply that its release executor is registered or ready. The shared
Rust registry is explicit about execution readiness. The executable
`tn10-name-controller-release-v1` line is `HOST_FREE_READY` on Windows x86_64.
The generic publisher `tn10-publisher-release-v1` remains `IDENTITY_ONLY` until
a pinned, end-to-end publisher release adapter is available.
Do not infer that a package is publishable merely because it validates.
Publisher execution and Host import/deployment are separate capabilities. The
public candidate bundles the reviewed static adapter registry. It does not include
prebuilt adapter binaries: build the helper bundle from source (see the CLI
reference), and expect `ktape release adapters` to report `BLOCKED` until the
built digests are reviewed and pinned. It does not grant signing or deployment
authority.

### Workflow-authority provenance

The `workflow_authority_public_key` in a release target is an operator-controlled
offline intent-authority key. It is deliberately distinct from the TN10 name
controller, an application publisher key, and any historical `release-key-2`
file. Keep the public key explicit in every target and keep the private key
outside the repository with an operating-system ACL restricted to the operator.
The Rust coordinator must reject a missing, malformed, stale, or reused
authority key and must verify every pinned helper against the same bundle before
authorization. A package or publisher authorization never substitutes for the
workflow authority and never grants signing, broadcasting, or deployment.
In the full engineering distribution, refreshing a real operator target may
use `--workflow-authority-manifest <path>`; this option is not available in the
minimal public candidate. The helper then fails closed if the target key differs
from the reviewed manifest. Omitting this check is allowed only for public
template generation, not for an operator target.

Use the generated candidate manifest and exporter comparison for the current
file inventory; do not rely on a count copied into this guide. Keep this
source synchronization separate from execution authorization: `release ship
--prepare-only` creates an unsigned bounded operation, while signing,
broadcasting, readback and receipt generation still require the external
workflow-authority signature.

### Reuse one operation and the existing offline authorization

Repeated `release ship --target TARGET` uses a target-digest operation directory
instead of creating another timestamped attempt. Completed operations return
their existing result. After interruption, `release ship --resume OPERATION`
uses the frozen target and reconciles unknown effects before any fresh action.
Only an intentionally new operation needs a new explicit `--workdir`.

The public build uses `authorization-request` -> an external Ed25519 signature
-> `authorization-import`. It verifies the detached signature before resuming.
Publisher/host builds with `publisher-signing` also provide the local-key
`authorization-sign` command and `release ship --authorization-key` composition.
The public build rejects a requested local key with `RELEASE_LOCAL_SIGNING_UNAVAILABLE`.

Local fixtures verify normal record intake and readback plus interrupted
coordinator recovery without repeating a simulated signature or broadcast.
They do not establish a new on-chain Canary publication or production Host
availability.

For a generic Rust application, build the package and freeze it with the public
Rust CLI; no Studio wrapper or application-specific script is required:

```text
ktape package build --source <dir> --application-uri <namespace>/<slug> \
  --entrypoint index.html --output <package>
ktape release candidate-build --profile <application-release-profile.json> \
  --package <package> --snapshot-store <snapshots> \
  --output <candidate-result.json>
ktape release ship --target <target.json> \
  --candidate-result <candidate-result.json> --prepare-only
```

`candidate-build` verifies the package, creates a content-addressed snapshot,
and emits the same candidate result consumed by the Rust coordinator. It is
local-only: it does not sign, broadcast, import, or deploy. A frozen candidate
does not make an `IDENTITY_ONLY` release adapter ready.

The engineering source now has a native Rust helper-bundle builder for Windows
x64 MSVC. It packages eight pinned executables, including `ktape`, the name
update adapter, Registry state helper, TN10 scanner and read-only two-endpoint
observer, verified submitter, block-inclusion verifier, and
`namespace_registry_child_signing_v1`, binding both Rust source-package
closures. Process checks cover CLI and adapter startup, known state
recomputation, scanner and observer rejection before network access, rejection
of an unverified transaction before network access, verifier rejection, and a
malformed Registry lifecycle envelope with empty stdout. A valid detached
authorization request is also rejected by the adapter as coordinator-managed,
without creating a response file or work state. The lifecycle helper only
constructs offline signing plans, verifies externally supplied signature
packets, or assembles a signed transaction; it does not generate keys, access
a wallet, use RPC, or broadcast. Wallet signing remains a separate hash-pinned
capability and is not distributed. The bundle is not part of this public
candidate and does not establish positive helper stdin/stdout contracts, all
adapter phases, unknown-submission recovery, clean-checkout or cross-machine
reproducibility, cross-platform availability, registry admission, or
application readiness. Do not bridge the remaining work with
application-specific Python scripts; continue with frozen-candidate recovery,
then curate and reproduce the workflow from a clean public checkout.

For the engineering native name-update coordinator, the six shared helper pins
are positional and must stay in this role order: `planner`, `fetcher`,
`state_helper`, `submitter`, `readback_scanner`, `readback_verifier`. Keep the
operation-specific `signer` and `current_receipt` pins after those six. The
coordinator rejects reordered, missing, or extra shared pins with
`ADAPTER_PIN_MISMATCH`. The reviewed public candidate includes the coordinator
and adapter registry, but these pins still describe the engineering helper
bundle and do not grant signing or deployment authority.

The full engineering source also contains a bounded Rust block-body commitment
helper. Its contract is one strict versioned JSON request on stdin and one
camelCase JSON result on stdout (exit 0 for an internal commitment match, 2 for
rejection). It checks body/header consistency only; it does not prove selected
chain membership, acceptance or finality. This helper is not included in the
minimal public candidate, so do not infer that public releases can run it.

The engineering distribution also contains an offline Registry Deed state
address helper. It accepts a bounded JSON state file for Testnet-10 and emits
the recomputed script public key; it does not prove a live UTXO or chain status.
It is not included in the minimal public candidate either.

Windows MSVC builds of the engineering `ktape-name-update-adapter` use the
reproducible-link option. Treat a digest as a platform-specific build result:
pin it only after reviewing and reproducing the complete executable and
dependency closure for that platform. Stable output from one Windows toolchain
does not establish Linux/macOS support or adapter readiness.

Once that workflow is shipped, use one immutable candidate and one operation
directory: prepare, export the exact authorization message, import its verified
offline signature, then resume. Reconciliation must resolve unknown submissions
before any retry. After strict two-node readback, the coordinator rebuilds the
resolution receipt from the operation's frozen inputs and fresh Deed/namespace
observations, then persists both observation and receipt for deterministic
recovery. A resumed operation must reproduce the same receipt; never treat an
RPC acknowledgement as publication completion. Keep workflow authority,
on-chain controller and application publisher identities distinct. Reuse
evidence for unchanged inputs, and run only checks affected by the current
change.

For the Host import handoff, configure `coordinatorResponseFile` and
`coordinatorPreparedDirectory` instead of manually selecting a receipt. The
importer requires the coordinator's `RECEIPT_VERIFIED_AND_WRITTEN` artifact,
`RECOMPUTED_FROM_STATE` binding, false signing/broadcast flags, the fixed
`application-resolution-receipt.json` filename, and matching SHA-256 digests
for that receipt and `receipt-observation.json`. It then repeats independent
live two-node verification before staging and consumes the same receipt bytes
whose digest it checked. Treat the coordinator response as a file-selection
and integrity handoff only, never as proof of current chain
state; keep both inputs from the same operation directory. For
`stage-release-import-batch.mjs`, put both fields on the matching release
entry. Relative paths resolve from the batch config file, and no manual
`receiptFile` is needed; single and batch imports share the same artifact
validation and live two-node check.

## Architecture and version boundary

For a full engineering checkout, choose naming operations from its configured
adapter and pinned root. The current engineering TN10 deployment uses
`ktape.official.adapter.registry` 1.0.0; a fixed CompactV2 default or an old
Registry receipt does not select that lineage. This minimal checkout does not
bundle the adapter, live application Host or configured release coordinator.
Do not invent a generic publish command from an engineering deployment example.

For retained-source repair, preserve the release and content commitment, verify
all bytes, refresh permitted descriptors and regenerate directory receipt
hashes. Check the actual isolated browser runtime and Service Worker. Keep
publisher authorization, current-name binding, finality and authenticated
save/export/restore as separate results; an unavailable wallet or test space
must remain an explicit acceptance gap.

The complete Skill targets KTAPEOUT 0.5.0. Before applying it, read the [developer documentation entry](../index.md), the [capability status](../reference/capabilities-and-status.md), and the protocol page relevant to the task. The architecture authority order is: normative specification and schemas; shipped Core, CLI and tests; then explanatory guidance. Where guidance and the installed CLI differ, follow the installed release and report the mismatch.

Use the Skill as a task router: load only the reference needed for the current task, then follow the supported path **Discover → Build → Verify → Publish**. For this public candidate, publishing guidance stops at preparation and the external signer/readback boundary. It does not authorize signing, broadcasting, deployment or Mainnet use.

For storage work, read [Storage, integrity and retention](../concepts/storage-and-retention.md) first, then use [Plan and verify application storage on TN10](../guides/manage-storage-on-tn10.md). Keep byte integrity, publisher authorization, chain readback, provider retention and clean-device recovery as separate claims; the public candidate does not bundle a generic storage provider or production recovery service.

For local runtime packaging, use [`ktape package build`](../guides/build-runtime-package.md). Put only publishable site files under a dedicated directory such as `my-app/site/`; the project root may also contain workflow-generated `build/` or `package/` files, and the packager includes every eligible file under `--source`. Supply your own `index.html` and create the output parent directory before packaging. The command rejects hidden files, key material and source maps; it does not upload, sign, broadcast, publish a locator, or activate a release. When preparing a publication candidate, pass `--application-id` and `--profile-lock` together. The `--profile-lock` input must be a `KTAPEOUT-DEVELOPER-LOCK-V1` document (raw or inside a `lock` wrapper), not an application release profile; create one with `ktape init --profile-package` or `ktape profile lock`. The Rust command validates that lock before writing and emits the runtime plus `artifact.json`, `release.json`, `name-binding.json` and `profile-lock.json` as one deterministic local output.

KTAPEOUT has one application-development Skill: **ktapeout-application-engineering**. Its authoritative entrypoint in the full 0.5.0 engineering distribution is:

For a keyless Host handoff, use the Rust record commands after the local
package is frozen: `ktape record build` creates a self-consistent
`KTAPEOUT-APPLICATION-RECORD-V1`, while `record verify`, `record share` and
`record open` provide the offline verification and transport loop. These
commands do not prove chain state or publisher authorization and never sign,
broadcast or deploy; those checks remain Host policy and separately authorized
publication stages.

When a Host configures `record_sources`, the Shell may fetch a record by name.
The record is untrusted: the name's current target is proven from Deed state on
two nodes, and every runtime file must be covered by a content commitment equal
to that proven `artifact_root`, so the name controller is the publisher and no
second publisher key is needed. A record runs with no permissions and only after
the user approves it. Only a Host-listed publisher can grant permissions, and
then its signed release authorization is mandatory. This is a bounded source
lookup, not automatic chain-wide enumeration; sources may remain disabled and
the Host may hide entries.

```text
skills/ktapeout-application-engineering/SKILL.md
```

Install or provide that complete folder to your assistant, including its `references/` and `scripts/` resources. Load only references needed for the task. Do not install the former Protocol Skill alongside it.

This minimal public protocol checkout does not bundle the engineering Skill, Studio or Native Host. Obtain the complete engineering distribution before using those components; do not assume a protocol checkout exposes them. For public-only work, the engineering Skill provides `references/public-checkout-guidance.md` for protocol/schema workflows.

Capability and implementation status belongs to `docs/reference/capabilities-and-status.md` in the engineering distribution. The Skill supplies workflow and routing; plans and local tests do not establish wallet support, admission or live recovery.

The engineering source tree has an unadmitted authenticated archive-verification candidate that reuses the Operation Batch scope digest and pinned Native adapters. It is not part of the signed 0.5.0 contract or a production recovery path; consult the current capability status and do not infer chain inclusion or clean-device availability from archive verification.

For private persistent applications, the full engineering Skill's
`references/private-persistent-apps.md` requires exact canonical-byte
budgeting for encrypted directories and a versioned bounded page-tree design
when a single snapshot's lifetime growth approaches its byte limit. This public source candidate includes a bounded Rust verifier that recomputes
the decrypted V2 tree structure and commitments. It does not authenticate
receipts, transactions, predecessor/CAS state or selected-chain inclusion.
The full Operation planner, trusted Host, wallet and archive-source integration
remain outside this package; local structural verification does not establish
production admission or live recovery.

The separate SITE/Cloudflare Web Shell has a browser-local exact Runtime digest
TOFU review for routes without a configured publisher policy. It prompts on
first use and any changed release identity. This is only a user review aid: it
does not authenticate the publisher, release ordering, on-chain binding or
protect against compromise of the SITE origin. It does not enable private Host
capabilities; consult the full engineering distribution and current status
before relying on any private persistence path.

The full engineering distribution also includes an unadmitted separate MV3
private-client candidate that keeps the pin in extension storage and checks
Chrome's actual Runtime-frame sender before using the existing Native Host
client. Its pin currently trusts the Runtime URL's digest claim; it does not
independently verify loaded bytes, and there is no installed production Native
Host or real-browser integration evidence. It does not make private recovery
available.

The engineering-only Windows x64 helper bundle also contains Testnet-10
Deed-state recomputation, two-endpoint transaction scanning and observation,
single-transaction submission, block-body commitment checks, and the Registry
lifecycle planner. These executables are not part of this minimal public source
candidate; the public Rust CLI does not provide their release workflow. A scan
or observation is only raw node data and must pass the strict readback verifier
before it can be used as publication evidence. The submitter rejects an
unverified transaction before RPC, but it treats `native_vm_verified` as an
upstream assertion; it does not independently verify VM execution. The bundle's
process checks exercise those rejection boundaries without connecting to nodes.

The engineering tree also has a low-level `tn10_submit_verified` helper. It
checks the exact transaction ID and TN10 endpoint before one RPC submission,
but its `native_vm_verified` JSON field is an upstream assertion, not a proof
that the submit process independently reran VM validation. Authorization,
durable attempt tracking and unknown-result reconciliation remain owned by the
Rust release coordinator. This helper is not in the minimal public candidate
and must not be exposed as a standalone generic publish workflow.
