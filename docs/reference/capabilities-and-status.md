# Capabilities and status

This matrix describes only the public 0.5.0 candidate. `LOCAL_OK` means a
deterministic local command completed and its output was checked; it does not
claim chain admission, uploaded content, or a live service.
For release reports, hash the sorted UTF-8 relative paths (excluding
`candidate-manifest.json`) as `path || NUL || lowercase-hex-file-SHA-256 || LF`;
report the manifest SHA-256 separately. Candidate reproducibility still uses
the generator's exact path-to-file-hash inventory comparison.

| Capability | Public `ktape` command | Verification level | Evidence |
|---|---|---|---|
| Scaffold and starter workflow | `ktape init`, `ktape dev workflow`, `ktape app test` | `UNVERIFIED` | Clean-candidate run: workflow is `INCOMPLETE` because inputs, outputs, persistent state and actions are unspecified; artifact is only a shape estimate, package needs human review, and test is `STRUCTURE_ONLY` without runner binding or vector execution. `docs/getting-started/first-application.md` |
| Application package | `ktape package build` | `LOCAL_OK` | Two clean-candidate builds of the same `demo/starter` input produced identical package digest `48fafe1133bfb7030e84f86751c9495d1a19b501c3f85895b7feb2b0d71ae17f` and identical output file hashes. No upload, signing or publication. `docs/guides/build-runtime-package.md` |
| Application record | `ktape record build`, `ktape record verify` | `LOCAL_OK` | Clean-candidate build and verify returned `PASS` / `RECORD_SELF_CONSISTENT` for a local example; record digest `f8753a2154072e04ca33a45b082d38615ed410c7693059bb826d3cc0e7397370`. `chain_verified` and `content_verified` remain false. `docs/reference/cli.md` (Keyless application records) |
| TN10 artifact-root transaction | `ktape tn10 plan`, `sign`, `submit`, `verify` | `LIVE_TN10` | Documented TN10 transaction IDs `0c94e084df6cf7738f22929ca09323068ca224d2641f6a0c77a074c5687d80c7` and `a78694172da69875c5bf4820db3916127c3454e7d65f28aff3005c8a4d172a56`; documented evidence only, not rechecked online this round. `docs/guides/publish-on-tn10-with-ktape.md` (Validation status) |
| Kaspa artifact-root anchoring | `ktape tn10 submit` | `LIVE_TN10` | Same documented TN10 transaction IDs above; evidence was not rechecked online this round. The transaction anchors an artifact root; it does not store the application payload. `docs/guides/publish-on-tn10-with-ktape.md`; `docs/concepts/storage-and-retention.md` |
| External HTTPS payload storage | None | `NOT_IMPLEMENTED` | No generic provider upload/download adapter is bundled. `docs/concepts/storage-and-retention.md`; `docs/guides/manage-storage-on-tn10.md` |
| Arweave payload storage | None | `NOT_IMPLEMENTED` | No public `ktape` Arweave upload/readback command or adapter is provided. `docs/concepts/storage-and-retention.md` |
| Google Drive payload storage | None | `NOT_IMPLEMENTED` | No public `ktape` Drive import, upload or runtime-read adapter is provided. `docs/concepts/storage-and-retention.md` |
| Cloudflare R2 payload storage | None | `NOT_IMPLEMENTED` | R2 is not a documented candidate storage target and no public provider adapter is bundled. `docs/concepts/storage-and-retention.md` |
| Generic publication planning | `ktape publish plan` and related `ktape publish` commands | `UNVERIFIED` | CLI exposes coordinator operations, but the candidate does not provide a generic live storage publication path. `docs/reference/cli.md`; `docs/guides/manage-storage-on-tn10.md` |
| Native registration authorization and signing | `ktape tn10 authorize`, `ktape tn10 sign` | `MOCK_OR_VM` | Clean-candidate `registered_keys` 54/54 and `native_witness_real_contract` 14/14 passed; signing is exercised only with test fixtures, not as a live TN10 name registration. `docs/reference/cli.md` (Native registration signing and assembly; Pinned Toccata VM evidence boundary) |
| Native partial-signature assembly | `ktape tn10 assemble` | `MOCK_OR_VM` | Clean-candidate `registered_keys` 54/54 and `native_witness_real_contract` 14/14 passed; no live name-registration submission evidence. `docs/reference/cli.md` (Native registration signing and assembly; Pinned Toccata VM evidence boundary) |
| TN10 transaction submission | `ktape tn10 submit` | `LIVE_TN10` | The two documented TN10 transaction IDs above are submission examples; evidence was not rechecked online this round. Native name-registration plans are not covered by those transactions. `docs/guides/publish-on-tn10-with-ktape.md` (Validation status) |
| TN10 readback verification | `ktape tn10 verify`, `ktape tn10 locate` | `LIVE_TN10` | The two documented transaction IDs above have readback evidence; evidence was not rechecked online this round. Verification reports node acceptance and a confirmation-depth lower bound, not proof of work or finality. `docs/guides/publish-on-tn10-with-ktape.md` (Validation status; Readback boundary) |
| Namespace issuance | No `ktape name issue` command; `ktape name issuance-review` is review-only | `NOT_IMPLEMENTED` | The candidate CLI has no namespace issuance transaction path. `ktape name issue --help` fails with an unrecognized-subcommand error in the candidate walkthrough. |
| Name registration, V6 reference path | `ktape name register-request`, `ktape name register-plan` | `MOCK_OR_VM` | Clean-candidate `native_witness_real_contract` 14/14 and `registration_chain_vectors` 8/8 passed, including pinned-v2.1.0 VM and saved transaction-vector checks; this does not establish TN10 registration for existing CompactV1 namespaces. `docs/reference/cli.md` (Pinned Toccata VM evidence boundary) |
| Name registration in existing CompactV1 namespaces | `ktape name register-request`, `ktape name register-plan` | `NOT_IMPLEMENTED` | `register-request` fails closed when the required CompactV1 witness context is unavailable; TN10 end-to-end registration is incomplete. `docs/reference/cli.md` (Read-only TN10 name registration plan) |
| Namespace-key list inputs and validation | `ktape name register-plan --keys-file`, `--keys-url` | `MOCK_OR_VM` | Clean-candidate `registered_keys` 54/54 passed, including URL validation, bounded fetch, union and mock dual-RPC recomputation; no live plan was produced for the existing CompactV1 namespace. `docs/reference/cli.md` (Read-only TN10 name registration plan) |
| Browser application loading | KTAPEOUT Shell; no `ktape` command | `UNVERIFIED` | Candidate documents content checks, but the loader and its checks share the site origin; the candidate does not establish independent origin protection. `docs/concepts/storage-and-retention.md`; `docs/reference/capabilities-and-status.md` (Known limitations) |
| Historical Compact Registry deployment | No current public deployment command | `LIVE_TN10_PRIVATE_TOOL` | Candidate evidence records genesis outpoint/transaction ID `7c9c7542890f16a758b5610c277a787f5a43cc37350bb310e494ceda1bd0a850:0`; this is historical registry evidence, not namespace issuance or name registration. `release-evidence/tn10/compact-tn10-deployment-readback-20260928.json` |

Every `LIVE_TN10` and `LIVE_TN10_PRIVATE_TOOL` row is based on transaction IDs
documented in the cited evidence; those records were not rechecked online this
round. Two public RPC endpoints do not prove independent ownership. No matrix row establishes
Mainnet availability, production retention, cross-device recovery, or a
security audit.

### Known limitations

- Browser integrity checks and the service worker are served from the same
  origin. A compromised origin can replace both resources and their checks.
- Dual-node verification compares two public endpoints; it does not prove that
  different operators control them or establish independent validation.
- A `--key-file` path can appear in shell history or process arguments. File
  permissions depend on the host operating system and have not been validated.
- The security reporting channel is enabled but has not been tested end to end.
