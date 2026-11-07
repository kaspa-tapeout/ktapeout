# Changelog

## 2026-11-01 first public developer-preview release (TN10 only)

- Prepare the TN10-only developer preview with the disclosed dependency
  exception and repository security-reporting guidance.

## 2026-11-01 TN10 review corrections

- Clarify same-txid submission retry and archived attempt semantics, bounded
  confirmation-depth reporting, locator errors and endpoint restrictions.
- Correct platform-validation and package-source instructions. Remove four
  fixture files from the public selection because their only references are in
  stripped embedded unit tests; the private source fixtures remain unchanged.
- Keep real-network claims bounded to the recorded TN10 transactions and
  read-only observations. Built-in `--key-file`, Linux runtime, macOS, mainnet
  and endpoint-operator independence remain unverified.

## 2026-10-31 TN10 artifact-root flow

- Add `ktape tn10` (`plan`, `sign`, `submit`, `verify`, `utxos`, `locate`): a
  single-binary flow that anchors an artifact root on Testnet-10. Planning,
  signing and network code are separate modules; key handling is confined to the
  `developer-signing` module and the network code is behind `tn10-network`.
- Sign with a developer-supplied key from a file or standard input, never from
  arguments, with explicit approval and budget limits enforced before signing.
  An external signature can be imported instead.
- `verify` recomputes transaction, header and Merkle inclusion locally, and
  requires two nodes to agree on selected-chain acceptance and confirmation
  depth. It no longer trusts a `proof_valid` field in supplied evidence.
- Compute minimum fee and storage mass with the pinned Kaspa library instead of a
  fixed change floor.
- Pin the official Rusty Kaspa `v2.1.0` commit. The dependency graph is larger:
  expect a first build of roughly 5–15 minutes and about 1.5 GB of build output.
- TN10 observations: one real transaction used external-signature import and a
  second used `--key-stdin`; `utxos`, `locate` and `verify` each had one read-only
  query against two public nodes. Built-in `--key-file` signing, Linux runtime
  behavior, macOS behavior, mainnet and endpoint-operator independence remain
  unverified.
- Set `ktape` as the default binary so `cargo run -p ktapeout-cli -- …` works.

## 2026-10-28 release workflow simplification

- Reuse a target-digest operation directory by default, preserving explicit
  workdirs and frozen-snapshot recovery.
- Add optional local workflow-authority signing to `release ship` through the
  existing detached request/sign/import protocol, with scope confirmation.
- Verify interruption recovery and completed-operation reuse without repeating
  simulated signing or submission. Update AI guidance to distinguish local
  evidence, curated sources and publicly distributed executables.

## 2026-10-26 Host-free adapter build reproducibility

- Apply the MSVC reproducible-link option to the Windows native name-update
  adapter so independent cold builds with the same locked inputs are byte
  stable.
- Clarify that adapter digests are platform-specific and must not be pinned
  until the complete executable and dependency closure is reviewed and
  reproduced for each claimed platform. A stable binary is not adapter
  admission or end-to-end publication support.

## 2026-10-24 package discovery and commitment verification

- Add Discovery V2 metadata and media validation to `ktape package build`,
  using the shared Rust validator before the files enter the package commitment.
- Document that the discovery files are covered by the release commitment and
  that changing committed preview content requires a new release and name-target
  update.
- Clarify Shell rejection for incomplete commitment coverage and a release
  identity that differs from the name-bound release.
- Refresh the public candidate inventory and source snapshot after selecting
  the new Discovery V2 validator module.

## 2026-10-21 developer workflow improvements

- Add a root Cargo workspace and generic Rust integration-test targets across
  all four crates; CI now covers formatting, workspace tests, Clippy and the
  expiry-aware dependency audit.
- Extend CLI starter workflow coverage and verify Core canonical record
  encodings and commitments against the published specification vectors.
- Add an optional cross-platform `just` task file for `check`, `test`, `lint`,
  `audit` and unsigned TN10 `demo` workflows.
- Show equivalent PowerShell and Bash quickstart commands, explain the rough
  first-build time and external Cargo target directory, and clarify that
  `INCOMPLETE` with exit code 0 is the expected structural-only starter result.
- Add `ktape package build` as a generic local packaging step. It creates a
  content-addressed runtime package without uploading or signing; a complete
  storage-backed publish flow remains outside this candidate.
- `ktape package build` now emits the Shell's
  `KTAPEOUT-STATIC-RUNTIME-MANIFEST-V1` layout with files at their original
  paths, applies the browser verifier limits (128 files, 4 MiB per file,
  16 MiB total), uses a domain-separated package digest, rejects hidden files,
  key material, source maps and case-colliding paths, and accepts an optional
  `--release-id`.

## 2026-10-20 public source curation

- Regenerate the explicit public selection without build outputs or test sources.
- Include the bounded decrypted Private Directory Tree V2 structure verifier.
- Keep V6 integration, Browser SDK, Studio, signer/provider implementations and
  the complete engineering publication workflow outside this source package.
- Add reproducible Rust build configuration and minimal repository controls.
- Preserve the disclosed upstream dependency exception; the private security
  reporting channel is listed in SECURITY.md.
- Clarify the boundary between the broader platform lifecycle and this
  candidate's local unsigned tooling; label starter checks as structural only.
- Add copyable contribution checks, disclose the current rustfmt baseline
  differences and correct the platform overview's license link.
- (Historical) Mark the release candidate ready for private review.

Earlier entries below describe development history and contract evolution.
They are not an inventory of implementations bundled in this public candidate.

## Local engineering candidate — bounded private-directory V2 tree verification (2026-10-14)

- Add a release-mode Rust CLI candidate that verifies decrypted V2 Root/Page/Object structure and commitments with bounded NDJSON input. The candidate is not part of the published 0.5.0 binary and does not authenticate Receipts, transactions, predecessor/CAS state or chain inclusion.

## 0.5.0 — document recovery-root signer trust requirements (2026-10-13)

- State that application signing must remain a scoped Native-plan operation inside an authenticated Host; the current recovery provider and unchecked isolated Runtime do not implement it.

## 0.5.0 — document multi-authority P2PK signing boundary (2026-10-13)

- Clarify that the SDK can preserve a canonical application-signed P2PK input while a wallet signs its selected funding input, but only the Native Host verifies every signature and real-wallet compatibility remains unproven.

## 0.5.0 — bound wallet-scoped private-head discovery (2026-10-13)

- The public AI Skill now distinguishes authorized wallet addresses from a
  complete derivation range, requires aggregate UTXO/result budgets, and treats
  ordinary wallet-address markers as spendable by normal coin selection.

## 0.5.0 — clarify release block-verifier live checks (2026-10-13)

- The public AI Skill now distinguishes the release test harness from the
  standalone release executable and records the bounded dual-source TN10
  internal body-verification evidence without implying selected-chain or
  historical recovery.

## 0.5.0 — clarify private-object payload mass evidence (2026-10-13)

- The AI Skill now distinguishes an exact-wire, release-mode consensus mass
  projection from a live fee quote, wallet-signed network admission, and a
  complete writer/readback path.
- Record the measured one-input/one-output TN10 candidate sizes and warn that
  the largest supported envelope consumes about 78% of the transient block
  budget in that model.

## 0.5.0 — clarify wallet payload-signing evidence (2026-10-13)

- The AI Skill now requires PSKT transaction-body verification to bind exact
  payload bytes and distinguishes an SDK mutation regression from a specific
  wallet's payload-size support and network admission.
- Existing static-content TN10 signing evidence remains Profile-specific; it
  does not establish a private-object writer, mutable directory or recovery.

## 0.5.0 — clarify transport-safe wallet key-provider contracts (2026-10-13)

- The public AI Skill now treats wallet-only recovery as an application-selected
  policy and describes the optional wallet-native capability as unavailable in
  current KasWare/Kastle adapters.
- For a future wallet extension, it recommends evaluating short-lived opaque
  scope handles and wallet-side wrap/unwrap before transferring `CryptoKey`
  across an extension channel. Wallet root material stays inside the wallet;
  method names and wire schema remain unfrozen pending wallet interoperability
  and cryptographic review.
- The full-engineering wallet adaptation guide and private-app reference now
  document the same boundary. Existing application-key envelope v1 remains
  CryptoKey-based and does not claim compatibility with wallet RPC wrapping.

## 0.5.0 — clarify private-app key recovery options (2026-10-13)

- The public AI Skill distinguishes wallet-native scoped key recovery from
  wallet UI/signing, treats WebAuthn PRF/Passkeys as an optional host route
  with credential-manager dependence, and identifies user-held offline
  recovery material as a no-cloud option that adds a separate factor. No
  option is described as available until clean-device recovery is verified.

## 0.5.0 — document lossless wRPC JSON reads for wide integers (2026-10-13)

- The public AI Skill now directs developers handling consensus-sensitive
  integers to the full engineering release's `BrowserWrpcRawJsonCodec`, and
  distinguishes exact raw transport from application schema validation. The
  normal JSON codec fails closed on unsafe integer precision; raw RPC data
  remains untrusted until independently validated.

## 0.5.0 — document bounded supplied-block commitment verification (2026-10-13)

- The public AI Skill now describes the full engineering release's bounded
  native verifier for transaction IDs, the DAA/network-specific transaction
  Merkle root, supplied block-header hash and requested transaction presence.
  It explicitly limits the claim to internal block consistency and says this
  utility is not in the minimal public protocol checkout or wired into the
  SITE/Browser SDK reader. Chain membership, acceptance, finality, source
  completeness, locator binding and private-data recovery remain unproven.

## 0.5.0 — document staged immutable-object orchestration boundary (2026-10-13)

- The public AI Skill now directs developers using the full engineering release
  to reuse its local staged-operation coordinator for ordered immutable object
  Operations and a final directory commit. It also states that this utility is
  orchestration only and does not provide the private-object Profile, writer,
  locator, historical reader, atomic batch semantics, or recovery.

## 0.5.0 — reuse the SITE Runtime and known-locator reader (2026-10-13)

- The public AI Skill now distinguishes the isolated SITE/Cloudflare Runtime
  and dual-source exact-byte reader from the protocol release/Browser SDK.
  Reuse those implementations where deployed, while requiring authenticated
  Application/controller/Release binding before sensitive capabilities.
  Known-locator byte equality and resource hashes are not transaction inclusion,
  private-space discovery, or historical recovery evidence.

## 0.5.0 — clarify reusable wallet UI and secret recovery boundary (2026-10-13)

- The public AI Skill now says the reusable wallet component supplies connection
  UI and session context, while recoverable application secrets require a
  separate trusted-host provider. It explicitly rejects signatures, addresses,
  and injected properties as recovery mechanisms.

## 0.5.0 — record isolated Chromium sandbox runtime candidate (2026-10-13)

- The public AI Skill notes Chrome Web Store's remote-code policy exception for
  sandboxed contexts isolated from extension APIs. It treats this only as a G1
  prototype option and requires authenticated release bytes, a bounded broker,
  and user-data/privacy compliance; the KTAPEOUT static shell stays scriptless.

## 0.5.0 — separate identity discovery from private-key recovery (2026-10-13)

- The private-data guidance now evaluates a versioned public-key-derived
  locator before requiring a recoverable secret solely for space discovery.
  It explicitly treats that locator as linkable routing data, never as an
  encryption key or authentication proof, and keeps current-head/readback
  verification as a separate requirement.

## 0.5.0 — use the existing publication authority as the runtime trust root (2026-10-13)

- Clarified that a separate publisher signing key is not an automatic runtime
  requirement when a supported verifier authenticates the user-approved
  application identity, its current controller-authorized immutable Release,
  and the complete resource closure.
- Kept byte integrity, publisher authorization, runtime isolation, and wallet
  or decryption capability as distinct checks. A self-declared status or static
  receipt alone does not establish current authority.

## 0.5.0 — operation-scoped wallet capability gating (2026-10-11)

- The reusable Browser SDK chooser now disables detected providers that lack
  the capability required by the current operation, without triggering an
  approval request. PSKT and native-input requirements remain wallet-neutral;
  submit and covenant input handling remain explicit Host boundaries.

## 0.5.0 — clarify lock binding wording (2026-10-10)

- Clarified that the ApplicationLock binds walletless reads and wallet-backed
  writes to the same application instance; this does not introduce a
  walletless write capability.

## 0.5.0 — scope remote-service security requirements (2026-10-10)

- HTTPS origins, response signing and caller authentication are required only
  when a deployment exposes a remote operator/service boundary. Local and
  direct wallet-to-chain flows retain wallet-signature and receipt checks
  without adding a remote-service gate.

## 0.5.0 — make quickstart recovery guidance match executable scope (2026-10-10)

- Quickstart and `ktape init` now direct developers to complete and validate the
  Source Manifest. They explicitly describe `ktape app test` as a structural
  vector-presence check, not an application behavior test.

## 0.5.0 — reuse verified historical instance lineage evidence (2026-10-10)

- The shared AI development Skill now directs developers to reuse a complete,
  verified chain of signed deployment artifacts and state-transition receipts
  when it already links the admitted anchor to the current predecessor.
- It keeps recorded VM/readback evidence distinct from a fresh RPC observation
  or a new Native VM replay, and avoids requiring duplicate test instances or
  on-chain writes.

## 0.5.0 — align static publishing guidance with the implemented Host (2026-10-10)

- Clarified that the release has a Profile-specific static Genesis
  Operation/Receipt Host and a recorded TN10 instance.
- Kept URI publication distinct: a supported name transition must point the
  Registry/Deed to the new content, then the selected standard Resolver must
  verify that same tuple. This does not claim a turnkey general publisher.

## 0.5.0 — make reviewed Profile sidecar packaging explicit (2026-10-10)

- The shared AI development Skill now gives the public Rust CLI path for
  binding reviewed Contract/Effect sidecars to an exact Profile package before
  Recipe composition, including the required package verification step.
- This workflow creates a new package digest and does not infer business
  semantics or grant Profile admission, signing or publication authority.

## 0.5.0 — bind Profile transition signing to admitted build provenance (2026-10-10)

- Clarified that a Profile transition adapter must match its loaded compiler and
  codec artifacts, current input state and complete transaction to the selected
  admission evidence before requesting a wallet signature.
- Keep source/Profile, template, codec and compiled-script digests distinct by
  their declared contract semantics; a chain script match alone does not prove
  admission for the local candidate.
- If a required binding is unavailable, leave the operation unsigned and report
  the exact evidence needed to resume.

## 0.5.0 — distinguish static content creation from name publication (2026-10-10)

- The shared AI development Skill now states that a static content Genesis and
  its Receipt do not update a Registry/Deed or make a URI resolve to the new
  output. Name registration or repointing is a separate supported,
  explicitly authorized and recoverable transition.
- When that transition capability is unavailable, developers should preserve
  the content as unbound rather than resubmit Genesis or construct a state
  transition from a template-only Profile.

## 0.5.0 — document the live Resolver and imported package boundary (2026-10-10)

- The shared AI development Skill now explains that the infrastructure
  extension's Live TN10 path is read-only and uses dual-RPC verification.
- After L1 tuple verification, a user may import a bounded local Application
  Package JSON. The Resolver checks the exact Application/Release/artifact
  root and content digest before starting only sandboxed static HTML.
- The Live Resolver also accepts the original Studio `OnChainContentV1`
  artifact and constructs its Browser Package wrapper from the verified tuple;
  this remains static-only and does not convert the Studio semantic package.
- Clarified that the Studio semantic package and Resolver browser package are
  separate contracts; the static artifact handoff does not make a Studio
  semantic package directly Resolver-runnable.
- This does not establish generic publication, Profile execution, admission,
  finality, wallet signing or broadcast.

## 0.5.0 — clarify walletless access and L1 write defaults (2026-10-10)

- Clarified that published walletless access is read-only. Local simulation and
  drafts are developer-tool state, while L1 state changes require a selected
  wallet and an explicit per-operation signature (or a separately configured
  operator signer).
- Kept service-wallet integrations separate and opt-in. Interface bindings
  accept only `wallet` and `walletless-read`; the read mode is limited to
  read-only interfaces.

## 0.5.0 — initial public release (2026-10-10)

- Provides Source Manifest quickstart files and a four-stage local development
  workflow (`check`, `build`, `package`, `test`).
- Reports unresolved requirements, local-only artifact builds, package review
  requirements and structural-only vectors explicitly; these results do not
  claim application behavior execution, publication or network effects.

## 0.5.0 — bind local ApplicationLock evidence into application delivery plans (2026-10-10)

- Application publish packages can carry an ApplicationLock V2 and the
  existing passing development workflow result as a matched pair. The planner
  verifies the local evidence against the release artifact and emits a
  versioned DeliveryIntent V2; V1 packages remain compatible.
- The digest records deterministic local replay evidence only. It does not
  assert host honesty, Profile admission or L1 confirmation.
- V2 amount fields stay within the interoperable JSON safe-integer range to
  preserve identical values and hashes across runtimes.

## 0.5.0 — source alignment and public boundary review (2026-10-05)

- Aligned ProfileContractV1 schema with the local unsigned-composition form:
  `publisher_signature` may be null before publication; null is not a verified
  publisher signature or admission evidence.
- Revalidated the public Rust Core, Runtime, Kaspa verifier and CLI production
  surface against the current infrastructure line; source-only test modules
  remain excluded from the public export.
- Promoted the AI-assisted first-application path to the repository homepage,
  AI index and getting-started tutorial, including a copyable local scaffold
  and workflow command sequence.
- Documented local maintenance/history/provenance boundaries and the current
  release-upgrade rules for developers.
- Marked the newer Native-KAS adapter and Namespace Registry compiler/genesis
  tooling as deferred from this minimal candidate because their current source
  boundary includes separate adapter, vendor and external signer material.
- Kept the known upstream RustSec dependency exception non-blocking for this
  release because the reviewed Core/Verifier build and functional gates remain
  unaffected; the non-clean audit is still disclosed and must be revisited.

## 0.5.0 — public Testnet-10 Registry identity evidence (2026-10-03)

- Added the selected public Registry manifest, Bridge trust anchor and
  corroborating deployment readback under `release-evidence/tn10/`.
- Documented the Registry identity tuple, the distinction between the Compact
  and full deed Profile families, and fail-closed identity verification.
- The evidence identifies a declared Testnet-10 Registry root only; it does
  not grant signer authority, consensus finality or Mainnet status.

## 0.5.0 — public code refresh for neutral-client evidence boundaries (2026-10-03)

- Refreshed the Rust Core, Runtime, Kaspa verifier and CLI from the reviewed
  infrastructure line.
- Added local verification bindings for genesis provenance, source rebuild
  results, deployment readback and maintenance evidence.
- Kept adapter-produced evidence untrusted and non-authoritative: these paths
  never sign, broadcast or establish consensus finality.
- Removed embedded test modules from the public export and revalidated the
  four crates with locked offline checks.

## 0.5.0 — client-neutral documentation clarification (2026-10-03)

- Documented the client-neutral integration boundary across the overview,
  runtime, installation, capability and AI-development guidance.
- Clarified that alternate clients may consume the same contracts and vectors,
  but do not gain protocol authority or provider/signing capability.
- Kept Browser SDK, Studio and provider-specific client implementations outside
  this minimal public candidate until their source and release evidence are
  separately reviewed.

## 0.5.0 — public candidate refresh (2026-10-02)

- Refreshed the Rust Core, Runtime, Kaspa verifier and CLI sources from the
  reviewed 0.5.0 implementation line.
- Added the release-shaped CLI modules for provenance, history, maintenance,
  migration, runtime descriptors and Studio handoff verification.
- Removed embedded test modules from the public source export and retained the
  unsigned, application-free release boundary.
- Revalidated the four public crates with locked offline Cargo checks.

## 0.5.0 — public candidate

- Added the English developer documentation entrypoint and naming reference.
- Added the release-shaped Rust Core, Runtime, Kaspa verifier and CLI surface.
- Added machine-readable contracts, canonical vectors and unsigned examples.
- Added the normative English specification and requirements crosswalk.
- Added explicit capability, security and release-boundary documentation.

This entry describes a local public candidate. It is not a claim that the
protocol is Mainnet-ready or that the implementation has completed a security
audit.
