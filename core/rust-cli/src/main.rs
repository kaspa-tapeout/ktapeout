use clap::{Parser, Subcommand};
use discovery_media::inspect_discovery_media;
use ktapeout_core::{
    encode_l1_content_state_050, simulate_state_machine_artifact_050, verify_content_artifact_050,
    NetworkBoundPlan, SuccessorBinding, MAX_RECORD_BYTES,
};
use ktapeout_runtime::{
    deterministic_operation_id, parse_strict_json, tool_result, validate_tool_result,
};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::OnceLock;

mod app_record;
mod dev_workflow;
mod discovery_media;
mod discovery_metadata;
mod genesis_provenance;
mod history;
mod lifecycle_cost;
mod maintenance;
mod migration;
mod name_space;
mod namespace_admission;
mod namespace_anchor;
mod package_build;
mod profile_execution_evidence;
mod profile_governance;
mod profile_solver;
mod profile_vector_runner;
mod publish_ship;
mod release_adapter_contract;
mod release_candidate_binding;
mod release_candidate_build;
mod release_closure;
mod release_escrow;
mod release_escrow_audit;
mod release_execute;
mod release_name_update;
mod release_native_adapter;
mod release_node_registry;
mod release_pipeline;
mod release_readback;
mod release_resolve;
mod release_retention;
mod release_workflow;
mod runtime_descriptor;
mod runtime_release_authorization;
mod site_delivery;
mod studio_cli_handoff;
mod studio_runtime_bundle;
#[cfg(feature = "tn10-network")]
use ktapeout_cli::tn10_pipeline;

const PROTOCOL: &str = "0.5.0";
const SOURCE_SCHEMA: &str = "KTAPEOUT-0.5.0-SOURCE-APPLICATION-MANIFEST-V1";
const MAX_JSON_INPUT_BYTES: usize = 4 * 1024 * 1024;
const MAX_SOURCE_MANIFEST_DEPTH: usize = 64;
const MAX_SOURCE_MANIFEST_NODES: usize = 65_536;
// Host-side Profile Package verifier budgets; these are not protocol or L1 limits.
const MAX_PROFILE_PACKAGE_FILES: usize = 256;
const MAX_PROFILE_PACKAGE_FILE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_PROFILE_PACKAGE_TOTAL_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Parser)]
#[command(
    name = "ktape",
    version,
    about = "KTAPEOUT 0.5.0 plan and verification CLI"
)]
struct Cli {
    /// Optional read-only Workspace/Project/Network/Signer context binding.
    #[arg(long, global = true)]
    context_state: Option<PathBuf>,
    #[arg(long, global = true)]
    context_project: Option<String>,
    #[arg(long, global = true)]
    context_network: Option<String>,
    #[arg(long, global = true)]
    context_signer: Option<String>,
    #[arg(long, global = true)]
    context_role: Option<String>,
    #[command(subcommand)]
    command: Command,
}

static ACTIVE_CONTEXT: OnceLock<Option<Value>> = OnceLock::new();

#[derive(Debug, Subcommand)]
enum Command {
    Version,
    Init {
        #[arg(long, default_value = "StateMachine")]
        template: String,
        #[arg(long, default_value = "testnet-10")]
        network: String,
        /// Optional project directory for a local, non-signing starter.
        #[arg(long)]
        output: Option<PathBuf>,
        /// Optional verified KTAPEOUT-DEVELOPER-LOCK-V1 JSON file.
        #[arg(long)]
        profile_lock: Option<PathBuf>,
        /// Optional Profile package directory; it is verified before a new Developer Lock is generated.
        #[arg(long)]
        profile_package: Option<PathBuf>,
        /// Bind a supplied network policy into the generated project and lock.
        #[arg(long)]
        network_policy: Option<PathBuf>,
    },
    Dev {
        #[command(subcommand)]
        action: DevAction,
    },
    /// Build a deterministic local application package; no upload or signing.
    Package {
        #[command(subcommand)]
        action: PackageAction,
    },
    Publish {
        #[command(subcommand)]
        action: PublishAction,
    },
    Deploy {
        #[command(subcommand)]
        action: DeployAction,
    },
    App {
        #[command(subcommand)]
        action: AppAction,
    },
    /// Application records: offline verify, share-link encode and open. Keyless.
    Record {
        #[command(subcommand)]
        action: RecordAction,
    },
    Name {
        #[command(subcommand)]
        action: NameAction,
    },
    Proof {
        #[command(subcommand)]
        action: ProofAction,
    },
    GenesisProvenance {
        #[command(subcommand)]
        action: GenesisProvenanceAction,
    },
    Index {
        #[command(subcommand)]
        action: IndexAction,
    },
    Profile {
        #[command(subcommand)]
        action: ProfileAction,
    },
    Resource {
        #[command(subcommand)]
        action: ResourceAction,
    },
    /// Build, sign (developer key or external signature), submit and verify a TN10 content transaction.
    #[cfg(feature = "tn10-network")]
    Tn10 {
        #[command(subcommand)]
        action: Tn10Action,
    },
    Artifact {
        #[command(subcommand)]
        action: ArtifactAction,
    },
    Release {
        #[command(subcommand)]
        action: ReleaseAction,
    },
    Runtime {
        #[command(subcommand)]
        action: RuntimeAction,
    },
    Doctor {
        result: PathBuf,
    },
    Operation {
        #[command(subcommand)]
        action: OperationAction,
    },
    Evidence {
        #[command(subcommand)]
        action: EvidenceAction,
    },
    Kaspa {
        #[command(subcommand)]
        action: KaspaAction,
    },
    Ai {
        #[command(subcommand)]
        action: AiAction,
    },
    /// Advisory application categories and metadata; grants no capabilities.
    Discovery {
        #[command(subcommand)]
        action: DiscoveryAction,
    },
    Shell {
        #[command(subcommand)]
        action: ShellAction,
    },
}

#[derive(Debug, Subcommand)]
#[cfg(feature = "tn10-network")]
enum Tn10Action {
    /// Read two synchronized TN10 nodes and export an agreed funding view; never signs or submits.
    Utxos { request: PathBuf, output: PathBuf },
    /// Read two synchronized TN10 nodes and export an agreed registry-script UTXO view; never signs or submits.
    RegistryScriptUtxos { request: PathBuf, output: PathBuf },
    /// Locate a containing block using bounded dual-node scans; run verify for acceptance.
    Locate { request: PathBuf, output: PathBuf },
    /// Build a deterministic unsigned TN10 transaction from a local artifact and UTXO view.
    Plan { input: PathBuf, output: PathBuf },
    /// Review a fresh live-quoted native plan and create a plan-bound authorization after terminal confirmation.
    #[cfg(feature = "developer-signing")]
    Authorize {
        plan: PathBuf,
        output: PathBuf,
        #[arg(long, required = true)]
        max_total_sompi: u64,
        #[arg(long, required = true)]
        max_fee_sompi: u64,
        #[arg(long, required = true)]
        expires_utc: String,
        #[arg(long)]
        allow_broadcast: bool,
        #[arg(long)]
        allow_readback: bool,
    },
    /// Create a bounded, terminal-confirmed authorization for a namespace issuance transition.
    #[cfg(feature = "developer-signing")]
    AuthorizeNamespaceTransition {
        plan: PathBuf,
        output: PathBuf,
        #[arg(long = "node", required = true, num_args = 2)]
        nodes: Vec<String>,
        #[arg(long, required = true)]
        max_total_sompi: u64,
        #[arg(long, required = true)]
        max_fee_sompi: u64,
        #[arg(long, required = true)]
        expires_utc: String,
        #[arg(long, action = clap::ArgAction::SetTrue)]
        allow_broadcast: bool,
    },
    /// Sign offline using a local secret, or import an external signature; explicit approval required.
    #[cfg(feature = "developer-signing")]
    Sign {
        plan: PathBuf,
        output: PathBuf,
        /// User-created native registration authorization record; required for native plans.
        #[arg(long)]
        authorization: Option<PathBuf>,
        /// Read a 32-byte hexadecimal secret from a protected local file (never the argument itself).
        #[arg(long = "key-file", conflicts_with_all = ["key_stdin", "signature"])]
        key_path: Option<PathBuf>,
        /// Read a bounded hexadecimal secret from standard input.
        #[arg(long, conflicts_with = "signature")]
        key_stdin: bool,
        /// Import a detached external Schnorr signature JSON instead of signing locally.
        #[arg(long)]
        signature: Option<PathBuf>,
        /// Explicit noninteractive approval; budgets and all transaction checks still apply.
        #[arg(long)]
        yes: bool,
    },
    /// Verify and assemble native partial-signature packets into a plan-bound signed transaction; never signs or submits.
    #[cfg(feature = "developer-signing")]
    Assemble {
        plan: PathBuf,
        output: PathBuf,
        #[arg(long, required = true)]
        authorization: PathBuf,
        /// Repeat once for each partial packet; a single key may cover several roles in one packet.
        #[arg(long = "partial", required = true, action = clap::ArgAction::Append)]
        partials: Vec<PathBuf>,
    },
    /// Submit through an injected transport; retrying an unknown txid requires an explicit flag.
    Submit {
        signed: PathBuf,
        output: PathBuf,
        #[arg(long)]
        retry_same_txid: bool,
    },
    /// Submit a revalidated namespace transition; unknown retries require matching two-node readback.
    SubmitNamespaceTransition {
        signed: PathBuf,
        output: PathBuf,
        #[arg(long = "node", required = true, num_args = 2)]
        nodes: Vec<String>,
        #[arg(long)]
        retry_same_txid: bool,
    },
    /// Recompute inclusion and require two TN10 nodes to agree on acceptance and confirmation depth.
    Verify { evidence: PathBuf, output: PathBuf },
}

#[derive(Debug, Subcommand)]
enum ShellAction {
    /// Validate and hash a walletless resolution snapshot. Never signs or broadcasts.
    Snapshot { document: PathBuf },
    /// Validate and hash a local starter loadout. Never grants L1 ownership.
    Loadout { document: PathBuf },
    /// Validate one explicit user-facing Shell state transition.
    Transition {
        #[arg(long)]
        current: String,
        #[arg(long)]
        target: String,
    },
}

#[derive(Debug, Subcommand)]
enum KaspaAction {
    /// Offline candidate check only; does not authenticate a plan or permit signing/broadcast.
    VerifySigned {
        #[arg(long)]
        unsigned: PathBuf,
        #[arg(long)]
        signed: PathBuf,
        #[arg(long)]
        signer_policy: PathBuf,
        #[arg(long)]
        utxo_context: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum AiContextAction {
    Export {
        project: PathBuf,
    },
    Delivery {
        intent: PathBuf,
        policy: PathBuf,
        provider: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum AiAction {
    /// Reduce a validated SourceApplicationManifest into generic requirements and MVP stages.
    Requirements {
        source: PathBuf,
        #[arg(long, default_value = "testnet-10")]
        network: String,
    },
    Context {
        #[command(subcommand)]
        action: AiContextAction,
    },
}

#[derive(Debug, Subcommand)]
enum DiscoveryAction {
    Catalog,
    Validate {
        metadata: PathBuf,
        #[arg(long)]
        network: Option<String>,
    },
    Hash {
        metadata: PathBuf,
    },
    MigrateUnclassified {
        application: PathBuf,
        #[arg(long, default_value = "testnet-10")]
        network: String,
    },
}

#[derive(Debug, Subcommand)]
// Clap's inline argument variant preserves the established flat CLI flags;
// boxing it would complicate the command schema without affecting execution.
#[allow(clippy::large_enum_variant)]
enum RecordAction {
    /// Check a record file is self-consistent; does not touch the chain or artifact bytes.
    Verify { record: PathBuf },
    /// Build a record from explicit parts (target tuple, card file, locators); refuses unverifiable output.
    Build {
        #[arg(long, default_value = "testnet-10")]
        network: String,
        #[arg(long)]
        namespace: String,
        #[arg(long)]
        slug: String,
        #[arg(long)]
        application_id: String,
        #[arg(long)]
        release_id: String,
        #[arg(long)]
        deployment_id: String,
        #[arg(long)]
        artifact_root: String,
        /// web | runner | other (unknown kinds are shown but never run by the Shell).
        #[arg(long)]
        runtime_kind: String,
        /// JSON file with title, summary, categories and media.
        #[arg(long)]
        card: PathBuf,
        #[arg(long = "locator", required = true)]
        locators: Vec<String>,
        /// SHA-256 of the digest-addressed runtime manifest a Shell fetches from the mirrors.
        #[arg(long, requires = "runtime_manifest_bytes")]
        runtime_manifest_sha256: Option<String>,
        #[arg(long, requires = "runtime_manifest_sha256")]
        runtime_manifest_bytes: Option<u64>,
        /// State-bearing resolution entry (JSON, or an evidence file with an `entry` field); untrusted until verified live.
        #[arg(long)]
        deed_evidence: Option<PathBuf>,
        /// Publisher-signed runtime authorization (JSON object) carried with the record; verified by the Host policy, not here.
        #[arg(long)]
        release_authorization: Option<PathBuf>,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Encode a verified record as a URL fragment for any Shell.
    Share { record: PathBuf },
    /// Decode a fragment and verify the record it carries.
    Open { fragment: String },
}

#[derive(Debug, Subcommand)]
enum AppAction {
    Scaffold {
        template: String,
        #[arg(long, default_value = "testnet-10")]
        network: String,
    },
    Quickstart {
        #[arg(long, default_value = "PureCompute")]
        template: String,
        #[arg(long, default_value = "testnet-10")]
        network: String,
    },
    Validate {
        manifest: PathBuf,
    },
    Check {
        manifest: PathBuf,
        #[arg(long, default_value = "testnet-10")]
        network: String,
    },
    Inspect {
        manifest: PathBuf,
    },
    /// Check that a source manifest declares test vectors; does not execute them.
    Test {
        manifest: PathBuf,
    },
    Simulate {
        manifest: PathBuf,
    },
    Preflight {
        manifest: PathBuf,
        #[arg(long, default_value = "testnet-10")]
        network: String,
    },
    /// Verify a bounded OnChainContentV1 artifact and report its L1 admission boundary.
    /// This is read-only: it never signs, broadcasts, or upgrades artifact import to L1 evidence.
    ContentPreflight {
        artifact: PathBuf,
        #[arg(long, default_value = "testnet-10")]
        network: String,
    },
    /// Compute the canonical L1ContentProfileV1 state commitment without signing or broadcasting.
    ContentStateCommitment {
        state: PathBuf,
    },
    Estimate {
        manifest: PathBuf,
        #[arg(long, default_value = "testnet-10")]
        network: String,
    },
    Plan {
        manifest: PathBuf,
        #[arg(long, default_value = "testnet-10")]
        network: String,
    },
    ComposePreflight {
        profiles: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum DevAction {
    /// Generate an unsigned local DevPackage consumable by Studio/Bridge.
    Package {
        manifest: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        developer_lock: Option<PathBuf>,
        #[arg(long)]
        network_policy: Option<PathBuf>,
        #[arg(long, default_value = "testnet-10")]
        network: String,
        #[arg(long, default_value = "local-simulation")]
        backend: String,
    },
    /// Check deployment prerequisites using the existing deployment planner.
    Publishability {
        manifest: PathBuf,
        #[arg(long)]
        network: String,
        #[arg(long, default_value = "local-simulation")]
        backend: String,
    },
    /// Run the existing local application check; this never claims L1 admission.
    Check {
        manifest: PathBuf,
        #[arg(long)]
        network: String,
    },
    /// Alias the canonical artifact builder; emits the same artifact result.
    Build {
        manifest: PathBuf,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        developer_lock: Option<PathBuf>,
        #[arg(long)]
        network_policy: Option<PathBuf>,
        #[arg(long, default_value = "local-simulation")]
        backend: String,
        #[arg(long, default_value = "0.5.0")]
        version: String,
    },
    /// Check declared vectors, or execute them through an explicitly verified built-in Profile.
    Test {
        manifest: PathBuf,
        /// Verified local Profile package directory for the supported pure vector interface.
        #[arg(long)]
        profile_package_root: Option<PathBuf>,
        /// Optional KTAPEOUT-DEV-EXECUTE-V1 handoff for dev workflow.
        #[arg(long)]
        execution_result_output: Option<PathBuf>,
    },
    /// Validate a generated developer workflow without signing or broadcasting.
    Workflow {
        workflow: PathBuf,
        /// Optional Studio KTAPEOUT-DEV-EXECUTE-V1 result. Relative paths use the current directory.
        #[arg(long)]
        execution_result: Option<PathBuf>,
    },
    /// Verify a browser Studio handoff boundary without signing or broadcasting.
    StudioHandoffVerify { handoff: PathBuf },
    /// Build a local, profile-specific runtime bundle from a verified Studio handoff.
    /// This never creates a signed transaction, broadcasts, or claims L1 admission.
    StudioBundleBuild {
        handoff: PathBuf,
        #[arg(long)]
        developer_lock: Option<PathBuf>,
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum PackageAction {
    /// Build a KTAPEOUT-STATIC-RUNTIME-MANIFEST-V1 package from a local directory.
    Build {
        /// Application source directory.
        #[arg(long)]
        source: PathBuf,
        /// KTAPEOUT application URI suffix: <namespace>/<slug>.
        #[arg(long)]
        application_uri: String,
        /// Runtime entrypoint, relative to --source.
        #[arg(long)]
        entrypoint: String,
        /// Output directory; must be outside --source.
        #[arg(long)]
        output: PathBuf,
        /// Target network. Only testnet-10 is currently admitted.
        #[arg(long, default_value = "testnet-10")]
        network: String,
        /// Bound release id (64 lowercase hex). Defaults to the package digest.
        #[arg(long)]
        release_id: Option<String>,
        /// Application identity for a package consumable by `publish plan`.
        #[arg(long, requires = "profile_lock")]
        application_id: Option<String>,
        /// Publisher-chosen deployment label bound into the compact name target tuple.
        #[arg(long, requires = "application_id")]
        deployment_id: Option<String>,
        /// DeveloperLock JSON; supplied together with --application-id.
        #[arg(long, requires = "application_id")]
        profile_lock: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum PublishAction {
    #[cfg(feature = "host-bridges")]
    /// Verify and atomically publish one TN10 application route, receipt and directory entry.
    Index {
        /// Reusable public target configuration; contains no secret material.
        #[arg(long)]
        target: PathBuf,
        /// Apply after reviewing the prepared operation.
        #[arg(long)]
        apply: bool,
        /// Reconcile and resume the same persisted operation after interruption.
        #[arg(long, requires = "apply")]
        resume: bool,
    },
    /// Verify a delivery policy without signing or broadcasting.
    PolicyVerify { policy: PathBuf },
    /// Publish with one scoped confirmation and durable resume, or use the legacy keyless preflight.
    Ship {
        package: Option<PathBuf>,
        policy: Option<PathBuf>,
        provider: Option<PathBuf>,
        /// Once-configured pinned release adapter and immutable target scope.
        #[arg(long)]
        target: Option<PathBuf>,
        /// Prepare or inspect an operation without prompting or applying changes.
        #[arg(long)]
        prepare_only: bool,
        #[arg(long, default_value = "APPLICATION_PUBLISH")]
        kind: String,
        /// Explicit UTC creation timestamp for a reproducible plan.
        #[arg(long)]
        at: Option<String>,
        /// Explicit UTC expiry timestamp; must be within the policy TTL.
        #[arg(long)]
        expires_at: Option<String>,
        /// Operation directory. Target mode allocates one under .agent-pack/releases when omitted.
        #[arg(long)]
        workdir: Option<PathBuf>,
        /// Resume an existing operation directory; uses its frozen target configuration.
        #[arg(long)]
        resume: Option<PathBuf>,
    },
    /// Create a deterministic unsigned DeliveryIntent from a prepared package.
    Plan {
        package: PathBuf,
        policy: PathBuf,
        #[arg(long, default_value = "APPLICATION_PUBLISH")]
        kind: String,
        /// Explicit UTC creation timestamp for reproducible plans.
        #[arg(long)]
        at: String,
        /// Explicit UTC expiry timestamp; must be within the policy TTL.
        #[arg(long)]
        expires_at: String,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Verify a DeliveryIntent and local provider capability without signing or broadcasting.
    Preflight {
        intent: PathBuf,
        policy: PathBuf,
        provider: PathBuf,
    },
    /// Bind an exact unsigned OperatorPlan to a durable local operation record.
    Bind {
        intent: PathBuf,
        policy: PathBuf,
        provider: PathBuf,
        operator_plan: PathBuf,
        /// Optional validated MaintenancePlan whose target must match the DeliveryIntent.
        #[arg(long)]
        maintenance_plan: Option<PathBuf>,
        #[arg(long)]
        project_lock_hash: String,
        #[arg(long)]
        operation_output: PathBuf,
        #[arg(long)]
        binding_output: PathBuf,
        #[arg(long)]
        reservation_ledger: Option<PathBuf>,
        #[arg(long)]
        wallet_reference_hash: Option<String>,
        #[arg(long = "outpoint")]
        outpoints: Vec<String>,
    },
    /// Reserve exact caller-selected outpoints in a local ledger; never queries or locks L1 inputs.
    Reserve {
        intent: PathBuf,
        policy: PathBuf,
        #[arg(long)]
        wallet_reference_hash: String,
        #[arg(long = "outpoint", required = true)]
        outpoints: Vec<String>,
        #[arg(long)]
        ledger: PathBuf,
    },
    /// Release an exact local reservation after a terminal operator stage; never changes L1.
    ReleaseReservation {
        binding: PathBuf,
        #[arg(long)]
        wallet_reference_hash: String,
        #[arg(long = "outpoint", required = true)]
        outpoints: Vec<String>,
        #[arg(long)]
        ledger: PathBuf,
        #[arg(long)]
        terminal_stage: String,
    },
    /// Verify a non-consensus operation receipt without signing or broadcasting.
    ReceiptVerify { receipt: PathBuf },
    /// Recover a publication from a binding and an operator receipt without retrying it.
    Recover { binding: PathBuf, receipt: PathBuf },
    /// Assess a local operation journal with explicit binding and time inputs.
    Status {
        operation: PathBuf,
        #[arg(long)]
        operation_id: String,
        #[arg(long)]
        project_lock_hash: String,
        #[arg(long)]
        plan_hash: String,
        #[arg(long)]
        network: String,
        #[arg(long)]
        now: String,
    },
}

#[derive(Debug, Subcommand)]
enum DeployAction {
    /// Check one application's staged site bytes and report unrelated site drift. Read-only.
    SiteCheck {
        root: PathBuf,
        #[arg(long)]
        application_uri: String,
    },
    /// Build a deterministic unsigned deployment plan from a source manifest.
    Plan {
        manifest: PathBuf,
        #[arg(long)]
        network: String,
        #[arg(long, default_value = "local-simulation")]
        backend: String,
        /// Optional tooling-only ApplicationLock V2 to carry into the plan.
        #[arg(long)]
        application_lock: Option<PathBuf>,
    },
    /// Run the local deployment preflight; signing and broadcast remain external.
    Preflight {
        manifest: PathBuf,
        #[arg(long)]
        network: String,
        #[arg(long, default_value = "local-simulation")]
        backend: String,
        /// Optional tooling-only ApplicationLock V2 to verify before preflight.
        #[arg(long)]
        application_lock: Option<PathBuf>,
    },
    /// Explicitly expose the external submit boundary without accepting a broadcast action.
    Submit { signed: PathBuf },
    /// Verify a non-signing deployment/readback receipt.
    Readback { receipt: PathBuf },
}

#[derive(Debug, Subcommand)]
enum NameAction {
    /// Show the pinned TN10 registry identity and historical economics; does not query or sign.
    RegistryInfo,
    /// Create a single-use TN10 test key under the system temp directory; never prints the secret.
    #[cfg(all(feature = "developer-signing", feature = "tn10-network"))]
    TestKeygen {
        output: PathBuf,
    },
    /// Derive public TN10 key information from a protected local key file without exposing the secret.
    #[cfg(all(feature = "developer-signing", feature = "tn10-network"))]
    TestKeyInfo {
        key_file: PathBuf,
    },
    Normalize {
        uri: String,
        #[arg(long)]
        default_network: Option<String>,
    },
    /// Build a read-only TN10 registration estimate and require matching live Gap/Deed states.
    #[cfg(feature = "tn10-network")]
    RegisterPlan {
        /// JSON request with public key-list sources, estimated fee inputs, and Gap/Deed scripts.
        request: PathBuf,
        /// Add an untrusted canonical namespace-key list; repeat to union independent files.
        #[arg(long = "keys-file")]
        keys_files: Vec<PathBuf>,
        /// Add an untrusted HTTPS namespace-key list; repeat to union independent sources.
        #[arg(long = "keys-url")]
        keys_urls: Vec<String>,
        /// Write the dual-RPC-checked, non-signing plan.
        output: PathBuf,
    },
    /// Build a native, unsigned CHANGE_OWNER_TARGET transaction plan from fixed public witness context.
    #[cfg(feature = "tn10-network")]
    OwnerTargetPlan {
        /// Public UTXO, covenant witness, role-key, and successor request JSON.
        request: PathBuf,
        /// Write the plan bound to the exact witness context and digest.
        output: PathBuf,
    },
    /// Generate a keyless registration request from a complete local slug inventory and dual-RPC state.
    #[cfg(feature = "tn10-network")]
    RegisterRequest {
        /// Public registration intent with namespace, target slug, state candidates and unsigned inputs.
        intent: PathBuf,
        /// Controller-maintained complete local namespace name inventory.
        #[arg(long = "names-file")]
        names_file: PathBuf,
        /// Write the dual-RPC-checked request. This command accepts no key arguments.
        output: PathBuf,
    },
    /// Recompute a TN10 namespace-issuance review and escrow its non-signable packet locally.
    IssuanceReview {
        /// Prepared namespace-issuance plan JSON.
        prepared: PathBuf,
        /// Write the recomputed review record.
        output: PathBuf,
        /// Distinct local escrow roots; at least two are required.
        #[arg(long = "escrow-dir", required = true)]
        escrow_dirs: Vec<PathBuf>,
    },
    /// Build an unsigned TN10 namespace issuance plan from public UTXO context.
    IssuancePlan {
        /// Public request JSON with the ktape registry root Gap, pre-authorized parent, and fee UTXOs.
        request: PathBuf,
        /// Write the deterministic plan. No keys are accepted and no network submission occurs.
        output: PathBuf,
    },
    /// Prepare, verify public signature packets, or assemble a TN10 issuance transition offline.
    IssuanceTransition {
        #[arg(value_parser = ["plan", "sign", "verify", "assemble"])]
        phase: String,
        /// Public transition request, or plan plus public signature packets.
        request: PathBuf,
        output: PathBuf,
        /// Terminal-confirmed transition authorization created with `tn10 authorize-namespace-transition`.
        #[arg(long)]
        authorization: Option<PathBuf>,
        /// Read the developer's local signing key from a protected file.
        #[arg(long = "key-file", conflicts_with = "key_stdin")]
        key_path: Option<PathBuf>,
        /// Read the developer's local signing key from standard input.
        #[arg(long = "key-stdin", conflicts_with = "key_path")]
        key_stdin: bool,
    },
    /// Build the developer-funded TN10 parent and initial Gap under a pinned registry root.
    ParentGenesisPlan {
        /// Public request JSON with a canonical namespace frame, root identity and funding UTXO.
        request: PathBuf,
        /// Write the unsigned genesis-group plan; no key or RPC is accepted.
        output: PathBuf,
    },
    /// Prepare, sign, verify, or assemble the developer-owned parent genesis offline.
    ParentGenesisTransition {
        #[arg(value_parser = ["plan", "sign", "verify", "assemble"])]
        phase: String,
        /// Public request for `plan`, or a plan with public packets for later phases.
        request: PathBuf,
        output: PathBuf,
        /// Terminal-confirmed transition authorization created with `tn10 authorize-namespace-transition`.
        #[arg(long)]
        authorization: Option<PathBuf>,
        /// Read the developer's local signing key from a protected file.
        #[arg(long = "key-file", conflicts_with = "key_stdin")]
        key_path: Option<PathBuf>,
        /// Read the developer's local signing key from standard input.
        #[arg(long = "key-stdin", conflicts_with = "key_path")]
        key_stdin: bool,
    },
    /// Keyless completeness plan: the Gaps that must be live when `--key` lists every Deed and reserved key.
    SpacePlan {
        /// Full 256-bit name key (hex); repeat for every registered or reserved key.
        #[arg(long = "key")]
        keys: Vec<String>,
        /// Add the reserved genesis keys recorded in a CompactV2 admission receipt.
        #[arg(long)]
        reserved_from: Option<PathBuf>,
        #[arg(long, default_value = "testnet-10")]
        network: String,
    },
    /// Judge an external adapter's observation: are all expected Gaps live, and is `--probe` unregistered?
    SpaceCheck {
        #[arg(long = "key")]
        keys: Vec<String>,
        #[arg(long)]
        reserved_from: Option<PathBuf>,
        /// JSON array of the live Gaps `{lo, hi, hiIsMax}` observed on two independent sources.
        #[arg(long)]
        live: PathBuf,
        /// A key to report on; answered only when the observation is complete.
        #[arg(long)]
        probe: Option<String>,
        #[arg(long, default_value = "testnet-10")]
        network: String,
    },
    /// Create a bounded external ingress alias. Never signs or broadcasts.
    AliasCreate {
        #[arg(long)]
        provider: String,
        #[arg(long)]
        external_name: String,
        #[arg(long)]
        network: String,
        #[arg(long)]
        canonical_uri: String,
        #[arg(long)]
        application_id: String,
        #[arg(long, default_value = "current")]
        release_policy: String,
        #[arg(long, default_value = "OWNER_BOUND")]
        binding_mode: String,
        #[arg(long)]
        provider_proof_ref: Option<String>,
        #[arg(long)]
        owner_signature: String,
    },
    /// Verify a bounded ingress alias packet. Provider proof remains external.
    AliasVerify {
        alias: PathBuf,
        #[arg(long)]
        expected_network: Option<String>,
    },
    /// Create an unsigned Registry lifecycle operation plan.
    LifecyclePlan {
        #[arg(long)]
        network: String,
        #[arg(long)]
        operation: String,
        #[arg(long)]
        genesis_outpoint: String,
        #[arg(long)]
        predecessor_outpoint: String,
        #[arg(long)]
        policy_hash: String,
        #[arg(long)]
        operation_nonce: u64,
        #[arg(long)]
        effective_point: String,
    },
    /// Inspect the shape of a Registry readback without treating it as L1 fact.
    VerifyReadback {
        receipt: PathBuf,
        #[arg(long)]
        expected_network: Option<String>,
        #[arg(long)]
        expected_plan_hash: Option<String>,
    },
    /// Verify two identical RPC observations against a NameDeed evidence candidate.
    EvidenceVerify {
        #[arg(long)]
        evidence: PathBuf,
        #[arg(long)]
        anchor: PathBuf,
        #[arg(long)]
        rpc_a: PathBuf,
        #[arg(long)]
        rpc_b: PathBuf,
    },
    /// Inspect one application lifecycle in a local Registry projection.
    InspectLifecycle {
        state: PathBuf,
        #[arg(long)]
        application_id: String,
    },
    PublicationVerify {
        receipt: PathBuf,
    },
    PublicationPreflight {
        state: PathBuf,
        uri: String,
        #[arg(long)]
        application_id: String,
        #[arg(long)]
        release_id: String,
        #[arg(long)]
        deployment_id: String,
    },
    PublicationOperationPlan {
        state: PathBuf,
        uri: String,
        #[arg(long)]
        application_id: String,
        #[arg(long)]
        release_id: String,
        #[arg(long)]
        deployment_id: String,
    },
}

#[derive(Debug, Subcommand)]
enum ProofAction {
    Inspect { proof: PathBuf },
    Verify { proof: PathBuf },
    Compare { left: PathBuf, right: PathBuf },
}

#[derive(Debug, Subcommand)]
enum IndexAction {
    Status {
        state: PathBuf,
    },
    Checkpoint {
        state: PathBuf,
    },
    Rebuild {
        state: PathBuf,
        #[arg(long)]
        write: bool,
    },
    Rollback {
        state: PathBuf,
        #[arg(long)]
        events: usize,
        #[arg(long)]
        write: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ProfileAction {
    /// Select bounded local Profile candidates from an Application Intent and Guidance catalog.
    Plan {
        intent: PathBuf,
        guidance: PathBuf,
        #[arg(long)]
        catalog_hash: Option<String>,
    },
    Search {
        root: PathBuf,
        #[arg(long)]
        profile_id: Option<String>,
    },
    Inspect {
        package: PathBuf,
    },
    Compose {
        packages: Vec<PathBuf>,
        /// Composition Draft V1 to verify and materialize as the existing Recipe V1.
        #[arg(long)]
        draft: Option<PathBuf>,
        /// Optional path for the verified Recipe JSON (draft mode only).
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Materialize the existing tooling-only ApplicationLock V2 from a
    /// verified Recipe and its exact Profile Package directories.
    ApplicationLockV2 {
        recipe: PathBuf,
        #[arg(long, required = true)]
        package_dir: Vec<PathBuf>,
        #[arg(long)]
        network_policy_id: String,
        #[arg(long)]
        created_at: String,
        #[arg(long)]
        runtime_digest: String,
        #[arg(long)]
        compiler_lock_digest: String,
        #[arg(long)]
        adapter_root: String,
        #[arg(long)]
        abi_root: String,
        #[arg(long)]
        vector_root: String,
        #[arg(long)]
        package_registry_root: String,
        #[arg(long)]
        dependency_root: Option<String>,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    Lock {
        package: PathBuf,
        #[arg(long)]
        network_policy_id: String,
        #[arg(long)]
        created_at: String,
    },
    PackageVerify {
        package: PathBuf,
    },
    /// Bind explicit Contract/Effect declarations to a verified Profile package and write a new package directory.
    PackageCompose {
        source: PathBuf,
        #[arg(long)]
        contract: PathBuf,
        #[arg(long)]
        effect_manifest: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Verify a signed VerificationAttestationV1 statement only; this is not Profile admission.
    VerificationAttestationVerify {
        attestation: PathBuf,
        #[arg(long)]
        publisher_keyring: PathBuf,
        #[arg(long)]
        trust_root: PathBuf,
        #[arg(long)]
        trust_root_update: PathBuf,
        #[arg(long)]
        trust_root_predecessor: PathBuf,
        #[arg(long)]
        publisher_delegation: PathBuf,
    },
    #[cfg(feature = "host-bridges")]
    /// Authenticate an existing bounded TN10 namespace admission receipt.
    AttestationVerify {
        attestation: PathBuf,
        #[arg(long)]
        publisher_keyring: PathBuf,
        #[arg(long)]
        namespace_admission_package: PathBuf,
        #[arg(long)]
        execution_report: PathBuf,
        #[arg(long)]
        trust_root: PathBuf,
        #[arg(long)]
        trust_root_update: PathBuf,
        #[arg(long)]
        trust_root_predecessor: PathBuf,
        #[arg(long)]
        publisher_delegation: PathBuf,
    },
    UpgradePlan {
        old_package: PathBuf,
        new_package: PathBuf,
    },
    /// Verify a Profile-provided bounded migration contract; never executes it.
    MigrationContractVerify {
        contract: PathBuf,
        /// Pair the contract with both locally verified Profile packages.
        #[arg(long, requires = "new_package")]
        old_package: Option<PathBuf>,
        #[arg(long, requires = "old_package")]
        new_package: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum ResourceAction {
    /// Explain one current layout's declared lifecycle fees and recovery inventory.
    LifecycleReport {
        request: PathBuf,
    },
    Explain {
        manifest: PathBuf,
    },
    Quote {
        manifest: PathBuf,
        #[arg(long, default_value = "testnet-10")]
        network: String,
    },
    Plan {
        manifest: PathBuf,
        envelope: PathBuf,
        #[arg(long, default_value = "testnet-10")]
        network: String,
    },
    BindShape {
        plan: PathBuf,
        bundle: PathBuf,
        source: PathBuf,
        developer_lock: PathBuf,
        network_policy: PathBuf,
    },
    CalibrationStatus,
}

#[derive(Debug, Subcommand)]
enum ArtifactAction {
    Backends,
    Select {
        #[arg(long)]
        backend: String,
        #[arg(long, default_value = "A0")]
        atomicity_class: String,
        #[arg(long, default_value = "offline")]
        network: String,
    },
    Build {
        manifest: PathBuf,
        #[arg(long)]
        developer_lock: Option<PathBuf>,
        #[arg(long)]
        network_policy: Option<PathBuf>,
        #[arg(long, default_value = "local-simulation")]
        backend: String,
        #[arg(long, default_value = "0.5.0")]
        version: String,
    },
    Inspect {
        bundle: PathBuf,
    },
    Verify {
        bundle: PathBuf,
        #[arg(long)]
        source: Option<PathBuf>,
        #[arg(long)]
        developer_lock: Option<PathBuf>,
        #[arg(long)]
        network_policy: Option<PathBuf>,
    },
    Diff {
        left: PathBuf,
        right: PathBuf,
    },
    Reproduce {
        manifest: PathBuf,
        bundle: PathBuf,
    },
    SimulateKtb1 {
        artifact: PathBuf,
        inputs: PathBuf,
        state: PathBuf,
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..=10_000))]
        steps: u32,
    },
    SimulateProject {
        bundle: PathBuf,
        inputs: PathBuf,
        state: PathBuf,
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..=10_000))]
        steps: u32,
        /// Persist the resulting local state vector atomically; never writes to L1.
        #[arg(long)]
        state_output: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum ReleaseAction {
    /// List statically reviewed release adapters and their declared support boundaries; read-only.
    Adapters,
    /// Build a deterministic LOCAL_BUILD_VERIFIED candidate from a Rust package. Never signs, broadcasts, or deploys.
    CandidateBuild {
        /// KTAPEOUT-APPLICATION-RELEASE-PROFILE-V4 (or compatible V1-V3) JSON.
        #[arg(long)]
        profile: PathBuf,
        /// Output directory produced by `ktape package build`.
        #[arg(long)]
        package: PathBuf,
        /// Content-addressed snapshot store.
        #[arg(long)]
        snapshot_store: PathBuf,
        /// Candidate-result JSON output.
        #[arg(long)]
        output: PathBuf,
    },
    /// Run the publisher or name-controller release workflow. Host deployment/import stays under `publish`.
    Ship {
        /// Optional local workflow-authority key; reuse detached signing after interactive confirmation.
        /// Never passed to adapters. Omit for an external signer.
        #[arg(long)]
        authorization_key: Option<PathBuf>,
        /// Publisher V2 or name-controller V3/V4 target configuration.
        #[arg(long)]
        target: Option<PathBuf>,
        /// Verified LOCAL_BUILD_VERIFIED result from `ktape release candidate-build`.
        /// Profile-owned identity fields are derived from it and frozen into this operation's target snapshot.
        #[arg(long)]
        candidate_result: Option<PathBuf>,
        /// Prepare or inspect an operation without prompting or applying changes.
        #[arg(long)]
        prepare_only: bool,
        /// Operation directory. Allocated under the project when omitted.
        #[arg(long)]
        workdir: Option<PathBuf>,
        /// Resume an existing operation directory using its frozen target snapshot.
        #[arg(long)]
        resume: Option<PathBuf>,
    },
    /// Inspect a persisted release operation without repairing state or contacting its adapter.
    Status {
        /// Existing operation directory.
        #[arg(long)]
        workdir: PathBuf,
    },
    /// Reconcile a pending name update from verified native readback and receipt evidence; never signs or broadcasts.
    ReconcileNative {
        #[arg(long)]
        workdir: PathBuf,
    },
    /// Close a SUBMISSION_UNKNOWN name update only when its executor proves no signing or submission attempt occurred.
    AbandonUnattempted {
        /// Existing operation directory.
        #[arg(long)]
        workdir: PathBuf,
    },
    /// Replace a proven incompatible CLI signer before any native signing attempt; requires fresh detached authorization.
    RepairCliSigner {
        #[arg(long)]
        workdir: PathBuf,
        #[arg(long)]
        signer: PathBuf,
        #[arg(long)]
        signer_sha256: String,
    },
    /// Rebind two escrow destinations before any signing attempt; requires fresh detached authorization.
    EscrowRebind {
        #[arg(long)]
        workdir: PathBuf,
        #[arg(long = "copy", num_args = 2)]
        copies: Vec<PathBuf>,
    },
    /// Export the exact authorization message for an external workflow-authority signer; read-only, never signs or executes.
    AuthorizationRequest {
        /// Prepared operation directory in AWAITING_CONFIRMATION state.
        #[arg(long)]
        workdir: PathBuf,
    },
    /// Sign a frozen workflow authorization with its dedicated authority key; never signs a transaction or broadcasts.
    #[cfg(feature = "publisher-signing")]
    AuthorizationSign {
        #[arg(long)]
        workdir: PathBuf,
        #[arg(long = "key-file")]
        signing_key: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Sign a release-bound publisher authorization under an explicit publisher scope.
    /// This is separate from workflow authorization and never signs a chain transaction.
    #[cfg(feature = "publisher-signing")]
    PublisherAuthorizationSign {
        #[arg(long)]
        authorization: PathBuf,
        #[arg(long)]
        publisher_scope: PathBuf,
        #[arg(long = "key-file")]
        signing_key: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Build an unsigned, Host-origin-bound publisher authorization from a verified runtime route and manifest.
    PublisherAuthorizationDraft {
        #[arg(long)]
        route: PathBuf,
        #[arg(long)]
        manifest: PathBuf,
        #[arg(long)]
        publisher_scope: PathBuf,
        /// Public HTTPS origin used by the Host to serve this runtime; contains no Host credentials.
        #[arg(long)]
        origin: String,
        #[arg(long)]
        release_sequence: u64,
    },
    /// Check publisher authorization inputs and local key binding without signing.
    #[cfg(feature = "publisher-signing")]
    PublisherAuthorizationPreflight {
        #[arg(long)]
        authorization: PathBuf,
        #[arg(long)]
        publisher_scope: PathBuf,
        #[arg(long = "key-file")]
        signing_key: PathBuf,
    },
    /// Verify a persisted publisher authorization during recovery without opening a private key.
    PublisherAuthorizationVerify {
        #[arg(long)]
        authorization: PathBuf,
        #[arg(long)]
        publisher_scope: PathBuf,
        #[arg(long)]
        signed: PathBuf,
    },
    /// Import a detached authorization; never executes effects.
    AuthorizationImport {
        /// Prepared operation directory in AWAITING_CONFIRMATION state.
        #[arg(long)]
        workdir: PathBuf,
        /// JSON signature envelope exported by the offline workflow-authority signer.
        #[arg(long)]
        signature: PathBuf,
    },
    /// Validate a prepared TN10 name update and print an unsigned authorization template. Never signs or broadcasts.
    NameUpdateCheck { config: PathBuf },
    /// Run the local review and live read-only preflight together, bound to the same four input digests.
    NameUpdateReview { config: PathBuf },
    /// Derive the native execution approval from a verified, signed coordinator request; never signs or broadcasts.
    NameUpdateAuthorizeWorkflow {
        config: PathBuf,
        #[arg(long)]
        adapter_request: PathBuf,
    },
    /// Refresh the exact reviewed plan against two live nodes without signing, broadcasting or writing escrow.
    NameUpdatePreflight { config: PathBuf },
    /// Inspect signing/submission journals without RPC, wallet access or mutation; unknown submissions remain non-retryable.
    NameUpdateInspect { config: PathBuf },
    /// Verify a two-node transaction scan against the executor's saved signed transaction and record it immutably.
    /// Read-only with respect to the network; never signs, broadcasts or retries a submission.
    NameUpdateReadback {
        config: PathBuf,
        scan: PathBuf,
        #[arg(long)]
        verifier: PathBuf,
        #[arg(long)]
        verifier_sha256: String,
    },
    /// Sign an approved, frozen TN10 name update through the pinned owner signer after live preflight and state escrow.
    /// Requires scoped human authorization; a configuration or approval JSON alone does not grant it.
    NameUpdateSign { config: PathBuf },
    /// Submit the VM-verified transaction once. An existing attempt always requires independent readback, never retry.
    NameUpdateSubmit { config: PathBuf },
    /// Build and strictly verify the current resolution receipt of a confirmed name update. Inputs: the previous receipt
    /// document, the review summary, the post-update state, the signed transaction, and a fresh two-node observation
    /// (`tn10_resolution_observe` over the new Deed script and the namespace certificate script).
    ReceiptBuild {
        previous_receipt: PathBuf,
        #[arg(long)]
        review: PathBuf,
        #[arg(long)]
        post_state: PathBuf,
        #[arg(long)]
        signed: PathBuf,
        #[arg(long)]
        observation: PathBuf,
        #[arg(long)]
        state_helper: PathBuf,
        #[arg(long)]
        state_helper_sha256: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Verify a submitted transaction from a raw scan of two nodes (`tn10_tx_scan`): accepted on both, exact signed bytes,
    /// block-body commitments re-checked by the pinned inclusion verifier. Read-only; proves inclusion, not finality.
    Readback {
        /// Raw scan output of `tn10_tx_scan`.
        scan: PathBuf,
        /// The signed transaction JSON (`transaction` field of the signer output).
        signed: PathBuf,
        #[arg(long)]
        txid: String,
        /// Independently projected storage mass from the unsigned plan (`mass_projection.storage_mass`).
        #[arg(long)]
        projected_storage_mass: Option<u64>,
        #[arg(long)]
        verifier: PathBuf,
        #[arg(long)]
        verifier_sha256: String,
    },
    /// Prepare (never sign) a name target update: read the live Deed and funding on two nodes, have the pinned native planner
    /// build the unsigned `CHANGE_OWNER_TARGET`, cross-check its successor script against a recompute of the new state, and
    /// write a review summary. The receipt item must carry `deed_state`.
    NameUpdatePrepare {
        receipt: PathBuf,
        /// New target tuple `{application_id, release_id, deployment_id, artifact_root}` (JSON).
        #[arg(long)]
        new_target: PathBuf,
        #[arg(long)]
        owner_xonly: String,
        /// Defaults to the owner key.
        #[arg(long)]
        target_authority_xonly: Option<String>,
        #[arg(long)]
        fetcher: PathBuf,
        #[arg(long)]
        fetcher_sha256: String,
        #[arg(long)]
        planner: PathBuf,
        #[arg(long)]
        planner_sha256: String,
        #[arg(long)]
        state_helper: PathBuf,
        #[arg(long)]
        state_helper_sha256: String,
        #[arg(long = "endpoint")]
        endpoints: Vec<String>,
        #[arg(long, default_value_t = 30_000_000)]
        fee_ceiling_sompi: u64,
        #[arg(long)]
        output: PathBuf,
    },
    /// Cold-read every file of a release from content-addressed sources (`{source}/sha256/{digest}`) through a pinned
    /// read-only helper, re-hash the bytes, and require two independent sources. Never signs or uploads.
    RetentionCheck {
        /// The release's `runtime-manifest.json`; its files and the manifest itself are checked.
        manifest: PathBuf,
        #[arg(long = "source", required = true)]
        sources: Vec<String>,
        #[arg(long)]
        helper: PathBuf,
        #[arg(long)]
        helper_sha256: String,
        /// Declare a temporary TN10 demo: one complete source is then reported as `TEMPORARY_DECLARED`.
        #[arg(long)]
        temporary: bool,
    },
    /// Save the Deed state a pending transition will create to at least two distinct directories and read each back.
    /// Run before signing. Writes only the given directories; never signs or broadcasts.
    EscrowState {
        /// JSON with `state_args` (the 15 arguments of the state the transaction creates).
        state: PathBuf,
        /// Script public key of the planned successor output (`summary.readback_outputs[0].script_public_key`).
        #[arg(long)]
        expect_spk: String,
        #[arg(long)]
        unsigned_txid: String,
        #[arg(long)]
        name: String,
        #[arg(long = "to", required = true)]
        destinations: Vec<PathBuf>,
        #[arg(long)]
        state_helper: PathBuf,
        #[arg(long)]
        state_helper_sha256: String,
    },
    /// Check that at least two distinct valid escrow copies exist for the planned successor script (signing gate).
    EscrowCheck {
        #[arg(long)]
        expect_spk: String,
        #[arg(long = "copy", required = true)]
        copies: Vec<PathBuf>,
        #[arg(long)]
        state_helper: PathBuf,
        #[arg(long)]
        state_helper_sha256: String,
    },
    /// Audit escrow replica directories against strictly verified current receipts and two live nodes. Read-only.
    EscrowAudit {
        #[arg(long = "directory", required = true)]
        directories: Vec<PathBuf>,
        #[arg(long = "receipt", required = true)]
        receipts: Vec<PathBuf>,
        #[arg(long)]
        state_helper: PathBuf,
        #[arg(long)]
        state_helper_sha256: String,
        #[arg(long)]
        fetcher: PathBuf,
        #[arg(long)]
        fetcher_sha256: String,
        #[arg(long = "endpoint", required = true)]
        endpoints: Vec<String>,
    },
    /// Read a name's live state from two nodes through a pinned read-only fetcher (empty environment) and verify it.
    /// Never signs, broadcasts or writes outside a temporary directory.
    Resolve {
        receipt: PathBuf,
        #[arg(long)]
        fetcher: PathBuf,
        #[arg(long)]
        fetcher_sha256: String,
        /// Two TN10 wRPC borsh endpoints on different hosts.
        #[arg(long = "endpoint")]
        endpoints: Vec<String>,
        #[arg(long, default_value_t = 60)]
        timeout_seconds: u64,
        /// Pinned `registry_deed_state_address` helper that recompiles the Deed script from `deed_state`.
        #[arg(long)]
        state_helper: Option<PathBuf>,
        #[arg(long)]
        state_helper_sha256: Option<String>,
        /// Accept a receipt without a Deed state preimage (its target stays an unproven assertion).
        #[arg(long)]
        unproven_state: bool,
    },
    /// Verify a name resolution from a resolution receipt plus the raw answers of two nodes (`{receipt, rpcA, rpcB}`).
    /// Offline and read-only: the answers are read by a separate fetcher; this command does no network I/O.
    ResolveVerify {
        observation: PathBuf,
        /// Accept a receipt without a Deed state preimage (its target stays an unproven assertion).
        #[arg(long)]
        unproven_state: bool,
    },
    /// Run the local freeze and validate stages of a KTAPEOUT-RELEASE-WORKFLOW-V1 config and record them in a state file.
    /// Read-only: later stages need a trusted Host and are not run.
    Check { config: PathBuf, state: PathBuf },
    /// Verify a local release directory under the public Shell and publisher closure rules.
    /// Read-only: never reads L1, signs, broadcasts or writes.
    Verify {
        dir: PathBuf,
        #[arg(long)]
        network: String,
        /// Application URI the Shell binds the runtime manifest to (namespace/name).
        #[arg(long)]
        application_uri: Option<String>,
        /// Release ID resolved for the route, or the external identity of a closure directory.
        #[arg(long)]
        release_id: Option<String>,
        /// Commitment path of a closure directory (runtime directories declare their own).
        #[arg(long)]
        commitment: Option<String>,
        /// Expected commitment schema; runtime directories default to the commitment's own.
        #[arg(long)]
        schema: Option<String>,
        /// Covered release-fields file that derives the release ID.
        #[arg(long)]
        release_file: Option<String>,
        /// Target the application fetches optionally; it may be absent from the closure.
        #[arg(long = "optional-fetch-target")]
        optional_fetch_targets: Vec<String>,
        /// Refuse the release when a relative reference resolves to no published file.
        #[arg(long)]
        strict_references: bool,
    },
    /// Bind a complete unsigned maintenance template to its canonical hash.
    /// This is local-only and never signs or broadcasts.
    MaintenancePlan {
        template: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    MaintenanceVerify {
        plan: PathBuf,
        /// Optional genesis provenance bound by the plan's GENESIS_DEPLOYMENT step.
        #[arg(long)]
        genesis_provenance: Option<PathBuf>,
        /// Optional independent Covenant ID; when supplied it must match the plan step.
        #[arg(long)]
        expected_covenant_id: Option<String>,
        /// Optional Adapter-produced source rebuild result.
        #[arg(long)]
        rebuild_result: Option<PathBuf>,
        /// Optional Adapter-produced deployment readback.
        #[arg(long)]
        readback: Option<PathBuf>,
    },
    /// Build the read-only maintenance summary shared with Studio/SDK.
    MaintenanceView {
        plan: PathBuf,
        state: PathBuf,
        /// Optional Profile migration contract required by a state-migration plan.
        #[arg(long)]
        migration_contract: Option<PathBuf>,
        /// Optional untrusted historical Release locator bundle.
        #[arg(long)]
        history_bundle: Option<PathBuf>,
        /// Optional validated maintenance execution journal.
        #[arg(long)]
        journal: Option<PathBuf>,
    },
    /// Export the existing KTAPEOUT-RECEIPT-V1 local maintenance preflight.
    /// This never executes migration, signs, broadcasts, or asserts L1 evidence.
    MaintenanceReceipt {
        plan: PathBuf,
        state: PathBuf,
        /// Optional Profile migration contract required by a state-migration plan.
        #[arg(long)]
        migration_contract: Option<PathBuf>,
        /// Optional untrusted historical Release locator bundle.
        #[arg(long)]
        history_bundle: Option<PathBuf>,
        /// Optional validated maintenance execution journal.
        #[arg(long)]
        journal: Option<PathBuf>,
        #[arg(long)]
        captured_at: String,
        #[arg(long)]
        valid_until: String,
        #[arg(long)]
        output: PathBuf,
    },
    /// Read-only projection of an existing OperationState bound to a maintenance plan.
    MaintenanceStatus { plan: PathBuf, state: PathBuf },
    /// Read-only recovery assessment; the project-lock hash is supplied explicitly.
    MaintenanceRecover {
        plan: PathBuf,
        state: PathBuf,
        #[arg(long)]
        project_lock_hash: String,
        #[arg(long)]
        now: String,
    },
    /// Verify historical Release/resource locators as untrusted candidates.
    HistoryVerify {
        bundle: PathBuf,
        /// Optional externally selected network for identity binding.
        #[arg(long)]
        expected_network: Option<String>,
        /// Optional externally selected Application ID.
        #[arg(long)]
        expected_application_id: Option<String>,
        /// Optional externally selected Release ID.
        #[arg(long)]
        expected_release_id: Option<String>,
        /// Optional externally selected Artifact root.
        #[arg(long)]
        expected_artifact_root: Option<String>,
    },
    Compare {
        old_package: PathBuf,
        new_package: PathBuf,
    },
    MigrationPlan {
        old_package: PathBuf,
        new_package: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum GenesisProvenanceAction {
    /// Bind a complete materialized genesis template to its provenance hash.
    Compose {
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Verify the genesis preimage and optionally compare an independent ID.
    Verify {
        proof: PathBuf,
        #[arg(long)]
        expected_covenant_id: Option<String>,
        #[arg(long)]
        rebuild_result: Option<PathBuf>,
        #[arg(long)]
        readback: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum RuntimeAction {
    Replay {
        bundle: PathBuf,
        runtime: PathBuf,
    },
    /// Verify a hash-bound RuntimeDescriptor and its Application Package reference.
    DescriptorVerify {
        #[arg(long)]
        descriptor: PathBuf,
        #[arg(long)]
        package: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum OperationAction {
    Init {
        #[arg(long)]
        operation_id: String,
        #[arg(long)]
        request_id: String,
        #[arg(long)]
        project_lock_hash: String,
        #[arg(long)]
        plan_hash: String,
        #[arg(long)]
        network: String,
        #[arg(long)]
        expiry: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long = "evidence-ref")]
        evidence_refs: Vec<String>,
    },
    Inspect {
        state: PathBuf,
    },
    Recover {
        state: PathBuf,
        #[arg(long)]
        operation_id: String,
        #[arg(long)]
        project_lock_hash: String,
        #[arg(long)]
        plan_hash: String,
        #[arg(long)]
        network: String,
        #[arg(long)]
        now: String,
    },
    Transition {
        state: PathBuf,
        #[arg(long)]
        stage: String,
        #[arg(long)]
        observed_tip: Option<String>,
        #[arg(long)]
        evidence_ref: Option<String>,
        #[arg(long)]
        next_action: Option<String>,
        #[arg(long)]
        write: bool,
    },
}

#[derive(Debug, Subcommand)]
enum EvidenceAction {
    Verify {
        receipt: PathBuf,
    },
    WriterVerify {
        input: PathBuf,
    },
    CodecVerify {
        input: PathBuf,
    },
    StatusVerify {
        input: PathBuf,
    },
    StatusDerive {
        #[arg(long)]
        semantic: String,
        #[arg(long)]
        build: String,
        #[arg(long)]
        receipt_status: Option<String>,
        #[arg(long, default_value = "PROFILE_ONLY")]
        domain: String,
    },
    Compare {
        left: PathBuf,
        right: PathBuf,
    },
    RecoveryCheck {
        receipt: PathBuf,
    },
}

fn canonical_json(value: &Value) -> Result<Vec<u8>, String> {
    ktapeout_runtime::canonical_json(value)
}

fn sha256_value(value: &Value) -> Result<String, String> {
    let bytes = canonical_json(value)?;
    Ok(hex_string(&Sha256::digest(bytes)))
}

fn hex_string(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(all(feature = "tn10-network", feature = "developer-signing"))]
fn assemble_native_signature_packets(
    plan_path: &Path,
    authorization_path: &Path,
    partial_paths: &[PathBuf],
    output: &Path,
) -> Result<(), String> {
    use std::io::Write;

    if output.exists() {
        return Err("TN10_ASSEMBLE_OUTPUT_EXISTS".into());
    }
    let plan_document = read_json(plan_path)?;
    let plan = plan_document
        .get("native_transaction_plan")
        .filter(|value| value.is_object())
        .cloned()
        .unwrap_or(plan_document);
    let authorization = read_json(authorization_path)?;
    let partials = partial_paths
        .iter()
        .map(|path| read_json(path))
        .collect::<Result<Vec<_>, _>>()?;
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "TN10_CLOCK_INVALID")?
        .as_secs();
    let aggregate = ktapeout_cli::tn10_developer_signing::combine_native_registration_partials(
        &plan,
        &authorization,
        &partials,
        now_unix,
    )
    .map_err(|error| error.to_string())?;
    let bytes = serde_json::to_vec_pretty(&aggregate).map_err(|error| error.to_string())?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .map_err(|error| format!("TN10_ASSEMBLE_OUTPUT_WRITE_FAILED:{error}"))?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("TN10_ASSEMBLE_OUTPUT_WRITE_FAILED:{error}"))
}

#[cfg(all(feature = "tn10-network", feature = "developer-signing"))]
fn authorize_native_plan(
    plan_path: &Path,
    output: &Path,
    max_total_sompi: u64,
    max_fee_sompi: u64,
    expires_utc: &str,
    allow_broadcast: bool,
    allow_readback: bool,
) -> Result<(), String> {
    use std::io::{IsTerminal, Write};

    if output.exists() {
        return Err("TN10_AUTHORIZE_OUTPUT_EXISTS".into());
    }
    if !std::io::stdin().is_terminal() {
        return Err("TN10_AUTHORIZE_TERMINAL_REQUIRED".into());
    }
    if !expires_utc.ends_with('Z') {
        return Err("TN10_AUTHORIZE_EXPIRY_MUST_BE_UTC".into());
    }
    let expires_at = chrono::DateTime::parse_from_rfc3339(expires_utc)
        .map_err(|_| "TN10_AUTHORIZE_EXPIRY_INVALID")?
        .timestamp()
        .try_into()
        .map_err(|_| "TN10_AUTHORIZE_EXPIRY_INVALID")?;
    let document = read_json(plan_path)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "TN10_CLOCK_INVALID")?
        .as_secs();
    let review = ktapeout_cli::tn10_pipeline::prepare_native_registration_authorization(
        &document,
        max_total_sompi,
        max_fee_sompi,
        expires_at,
        now,
        allow_broadcast,
        allow_readback,
    )
    .map_err(|error| error.to_string())?;
    let plan = document.get("native_transaction_plan").unwrap_or(&document);
    let role_map = plan["role_public_keys"]["roles"].as_object();
    let distinct_keys = role_map
        .map(|roles| {
            roles
                .values()
                .filter_map(|role| role["public_key"].as_str())
                .collect::<std::collections::BTreeSet<_>>()
                .len()
        })
        .unwrap_or_default();
    let review_document = json!({
        "network":plan["network"],
        "plan_sha256":plan["plan_sha256"],
        "inputs":plan["inputs"],
        "outputs":plan["outputs"],
        "roles":plan["role_public_keys"],
        "key_relationship":if distinct_keys <= 1 {"SAME_KEY"} else {"DIFFERENT_KEY"},
        "newly_locked_sompi":document["plan"]["newly_locked_sompi"],
        "fee_source":review["fee_source"],
        "fee_quote_sha256":review["fee_quote_sha256"],
        "fee_quote":document["fee_quote"],
        "max_total_sompi":max_total_sompi,
        "max_fee_sompi":max_fee_sompi,
        "expires_utc":expires_utc,
        "allow_broadcast":allow_broadcast,
        "allow_readback":allow_readback
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&review_document).map_err(|error| error.to_string())?
    );
    let plan_hash = plan["plan_sha256"]
        .as_str()
        .ok_or("TN10_REGISTRATION_PLAN_DIGEST_INVALID")?;
    let expected = format!("AUTHORIZE {plan_hash}");
    print!("Type {expected} to create this authorization record: ");
    std::io::stdout()
        .flush()
        .map_err(|error| error.to_string())?;
    let mut confirmation = String::new();
    std::io::stdin()
        .read_line(&mut confirmation)
        .map_err(|error| error.to_string())?;
    let authorization = ktapeout_cli::tn10_pipeline::create_native_registration_authorization(
        &document,
        max_total_sompi,
        max_fee_sompi,
        expires_at,
        now,
        allow_broadcast,
        allow_readback,
        confirmation.trim(),
    )
    .map_err(|error| error.to_string())?;
    let bytes = serde_json::to_vec_pretty(&authorization).map_err(|error| error.to_string())?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .map_err(|error| format!("TN10_AUTHORIZE_OUTPUT_WRITE_FAILED:{error}"))?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("TN10_AUTHORIZE_OUTPUT_WRITE_FAILED:{error}"))
}

#[cfg(all(feature = "tn10-network", feature = "developer-signing"))]
fn authorize_namespace_transition(
    plan_path: &Path,
    output: &Path,
    nodes: &[String],
    max_total_sompi: u64,
    max_fee_sompi: u64,
    expires_utc: &str,
    allow_broadcast: bool,
) -> Result<(), String> {
    use std::io::{IsTerminal, Write};
    if output.exists() {
        return Err("TN10_NAMESPACE_TRANSITION_AUTHORIZATION_OUTPUT_EXISTS".into());
    }
    if !std::io::stdin().is_terminal() {
        return Err("TN10_NAMESPACE_TRANSITION_AUTHORIZATION_TERMINAL_REQUIRED".into());
    }
    if !allow_broadcast {
        return Err("TN10_NAMESPACE_TRANSITION_BROADCAST_CONSENT_REQUIRED".into());
    }
    if !expires_utc.ends_with('Z') {
        return Err("TN10_NAMESPACE_TRANSITION_EXPIRY_MUST_BE_UTC".into());
    }
    let expires_at = chrono::DateTime::parse_from_rfc3339(expires_utc)
        .map_err(|_| "TN10_NAMESPACE_TRANSITION_EXPIRY_INVALID")?
        .timestamp()
        .try_into()
        .map_err(|_| "TN10_NAMESPACE_TRANSITION_EXPIRY_INVALID")?;
    let document = read_json(plan_path)?;
    let fee_quote = ktapeout_cli::tn10_pipeline::namespace_transition_fee_quote(nodes)
        .map_err(|error| error.to_string())?;
    // Compare the returned observation against a clock sampled after the network request.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "TN10_CLOCK_INVALID")?
        .as_secs();
    let review = ktapeout_cli::tn10_pipeline::prepare_namespace_transition_authorization(
        &document,
        &fee_quote,
        max_total_sompi,
        max_fee_sompi,
        expires_at,
        now,
        true,
    )
    .map_err(|error| error.to_string())?;
    println!(
        "{}",
        serde_json::to_string_pretty(&review).map_err(|error| error.to_string())?
    );
    let plan_hash = review["native_plan_hash"]
        .as_str()
        .ok_or("TN10_NAMESPACE_TRANSITION_PLAN_INVALID")?;
    let expected = format!("AUTHORIZE {plan_hash}");
    print!("Type {expected} to authorize this exact TN10 transition: ");
    std::io::stdout()
        .flush()
        .map_err(|error| error.to_string())?;
    let mut confirmation = String::new();
    std::io::stdin()
        .read_line(&mut confirmation)
        .map_err(|error| error.to_string())?;
    let authorization = ktapeout_cli::tn10_pipeline::create_namespace_transition_authorization(
        &document,
        &fee_quote,
        max_total_sompi,
        max_fee_sompi,
        true,
        ktapeout_cli::tn10_pipeline::NamespaceTransitionAuthorizationConfirmation {
            expires_at_unix: expires_at,
            now_unix: now,
            confirmation: confirmation.trim(),
        },
    )
    .map_err(|error| error.to_string())?;
    let bytes = serde_json::to_vec_pretty(&authorization).map_err(|error| error.to_string())?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .map_err(|error| format!("TN10_NAMESPACE_TRANSITION_AUTHORIZATION_WRITE_FAILED:{error}"))?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("TN10_NAMESPACE_TRANSITION_AUTHORIZATION_WRITE_FAILED:{error}"))
}

fn read_json(path: &Path) -> Result<Value, String> {
    let bytes = read_bounded_file(path, MAX_JSON_INPUT_BYTES, "INPUT_READ_ERROR")?;
    let text = String::from_utf8(bytes).map_err(|_| "INPUT_JSON_NOT_UTF8".to_string())?;
    parse_strict_json(text.as_bytes()).map_err(|error| format!("INPUT_JSON_ERROR:{error}"))
}

fn digest_bytes(bytes: &[u8], domain: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0]);
    hasher.update(bytes);
    hex_string(&hasher.finalize())
}

fn valid_profile_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 128
        && bytes[0].is_ascii_alphanumeric()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'.' | b'_' | b':' | b'-'))
}

fn valid_profile_semver(value: &str) -> bool {
    value.len() <= 64
        && value.split('.').count() == 3
        && value
            .split('.')
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

fn cache_component(value: &str, field: &str, max_length: usize) -> Result<String, String> {
    if value.is_empty() || value.len() > max_length {
        return Err(format!("PROFILE_PACKAGE_{field}_INVALID"));
    }
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(byte as char);
        } else {
            encoded.push('%');
            encoded.push_str(&format!("{byte:02X}"));
        }
    }
    if encoded == "."
        || encoded == ".."
        || encoded.contains('/')
        || encoded.contains('\\')
        || encoded.contains(':')
    {
        return Err(format!("PROFILE_PACKAGE_{field}_CACHE_COMPONENT_INVALID"));
    }
    Ok(encoded)
}

fn profile_package_files(
    root: &std::path::Path,
    current: &std::path::Path,
    files: &mut Vec<String>,
) -> Result<(), String> {
    let entries =
        fs::read_dir(current).map_err(|error| format!("PROFILE_PACKAGE_READ_ERROR:{error}"))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("PROFILE_PACKAGE_READ_ERROR:{error}"))?;
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .map_err(|_| "PROFILE_PACKAGE_PATH_ERROR".to_string())?;
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("PROFILE_PACKAGE_METADATA_ERROR:{error}"))?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "PROFILE_PACKAGE_SYMLINK_FORBIDDEN:{}",
                relative.to_string_lossy()
            ));
        }
        if metadata.is_dir() {
            profile_package_files(root, &path, files)?;
        } else if metadata.is_file() {
            let relative = relative.to_string_lossy().replace('\\', "/");
            if relative == "package.json" {
                continue;
            }
            let lower = relative.to_ascii_lowercase();
            if [
                ".exe", ".dll", ".ps1", ".bat", ".cmd", ".sh", ".com", ".scr",
            ]
            .iter()
            .any(|suffix| lower.ends_with(suffix))
            {
                return Err(format!("PROFILE_PACKAGE_EXECUTABLE_FORBIDDEN:{relative}"));
            }
            files.push(relative);
            if files.len() > MAX_PROFILE_PACKAGE_FILES {
                return Err("PROFILE_PACKAGE_FILE_COUNT_HOST_BUDGET".into());
            }
        } else {
            return Err(format!(
                "PROFILE_PACKAGE_UNSUPPORTED_FILESYSTEM_ENTRY:{}",
                relative.to_string_lossy()
            ));
        }
    }
    Ok(())
}

fn validate_profile_package_file_budget(
    root: &std::path::Path,
    files: &[String],
) -> Result<(), String> {
    let mut total = 0u64;
    for relative in files {
        let size = fs::metadata(root.join(relative))
            .map_err(|error| format!("PROFILE_PACKAGE_METADATA_ERROR:{error}"))?
            .len();
        if size > MAX_PROFILE_PACKAGE_FILE_BYTES {
            return Err("PROFILE_PACKAGE_FILE_SIZE_HOST_BUDGET".into());
        }
        total = total
            .checked_add(size)
            .ok_or_else(|| "PROFILE_PACKAGE_TOTAL_SIZE_HOST_BUDGET".to_string())?;
        if total > MAX_PROFILE_PACKAGE_TOTAL_BYTES {
            return Err("PROFILE_PACKAGE_TOTAL_SIZE_HOST_BUDGET".into());
        }
    }
    Ok(())
}

fn exact_json_keys(value: &Value, expected: &[&str]) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key))
}

fn profile_descriptor_commitment(
    descriptor: &Value,
    raw: &[u8],
    admission: &str,
) -> Result<String, String> {
    let error = || "PROFILE_PACKAGE_DESCRIPTOR_INVALID".to_string();
    let object = descriptor.as_object().ok_or_else(error)?;
    if object.get("schema").and_then(Value::as_str) != Some("KTAPEOUT-PROFILE-DESCRIPTOR-V0.5.0") {
        return Err(error());
    }
    if exact_json_keys(
        descriptor,
        &["schema", "profile_id", "profile_semver", "invariant_hash"],
    ) {
        if !matches!(admission, "REFERENCE" | "IMPLEMENTED") {
            return Err("PROFILE_PACKAGE_COMPLETE_DESCRIPTOR_REQUIRED".into());
        }
        return Ok(digest_bytes(raw, "KTAPEOUT/0.5.0/PROFILE_DESCRIPTOR/V1"));
    }
    let hashes = [
        "profile_hash",
        "state_encoding_hash",
        "transition_equation_hash",
        "invariant_hash",
        "input_shape_hash",
        "output_shape_hash",
        "lowering_template_hash",
        "selector_binding_hash",
        "predecessor_state_binding_hash",
        "dependency_manifest_hash",
        "exit_policy_hash",
        "capability_policy_hash",
    ];
    let fields = [
        "schema",
        "profile_id",
        "profile_semver",
        "core_protocol",
        "core_protocol_semver",
        "topology",
        "merge_mode",
        "proof_level",
        "max_partitions",
        "max_inputs",
        "max_outputs",
        "max_witness_bytes",
        "vector_set_id",
    ];
    if fields
        .iter()
        .chain(hashes.iter())
        .any(|key| !object.contains_key(*key))
        || object.keys().any(|key| {
            !fields.contains(&key.as_str())
                && !hashes.contains(&key.as_str())
                && key != "successor_contract_hash"
        })
        || object.get("core_protocol").and_then(Value::as_str) != Some("KTAPEOUT")
        || object.get("core_protocol_semver").and_then(Value::as_str) != Some(PROTOCOL)
    {
        return Err(error());
    }
    for key in hashes.iter().copied().chain(
        object
            .contains_key("successor_contract_hash")
            .then_some("successor_contract_hash"),
    ) {
        let hash = object.get(key).and_then(Value::as_str).ok_or_else(error)?;
        if !valid_hash(hash) || hash == "0".repeat(64) {
            return Err(error());
        }
    }
    for (key, allowed) in [
        (
            "topology",
            &["SINGLETON", "INDEPENDENT", "BOUNDED_COLLECTIVE"][..],
        ),
        (
            "merge_mode",
            &["NONE", "DISJOINT", "ORDERED", "REDUCER"][..],
        ),
        (
            "proof_level",
            &[
                "LOCAL_RECEIPT",
                "ACCUMULATOR",
                "FULL_BARRIER",
                "L1_ZK_VERIFIED",
            ][..],
        ),
    ] {
        if !allowed.contains(&object.get(key).and_then(Value::as_str).unwrap_or("")) {
            return Err(error());
        }
    }
    for (key, low, high) in [
        ("max_partitions", 1, 4294967295u64),
        ("max_inputs", 1, 64),
        ("max_outputs", 1, 64),
        ("max_witness_bytes", 0, 67108864),
    ] {
        let bound = object.get(key).and_then(Value::as_u64).ok_or_else(error)?;
        if bound < low || bound > high {
            return Err(error());
        }
    }
    if !valid_profile_id(
        object
            .get("vector_set_id")
            .and_then(Value::as_str)
            .unwrap_or(""),
    ) {
        return Err(error());
    }
    let mut material = descriptor.clone();
    material
        .as_object_mut()
        .ok_or_else(error)?
        .remove("profile_hash");
    let hash = digest_bytes(
        &canonical_json(&material)?,
        "KTAPEOUT/0.5.0/PROFILE_DESCRIPTOR/V1",
    );
    if object.get("profile_hash").and_then(Value::as_str) != Some(hash.as_str()) {
        return Err("PROFILE_PACKAGE_DESCRIPTOR_EMBEDDED_HASH_MISMATCH".into());
    }
    Ok(hash)
}

fn validate_profile_invariants(
    root: &Path,
    descriptor: &Value,
    profile_id: &str,
    profile_semver: &str,
) -> Result<(), String> {
    const CATEGORIES: [&str; 12] = [
        "state_owner",
        "mutation_authority",
        "valid_predecessor_roles",
        "authorized_successor_templates",
        "value_conservation",
        "fee_separation",
        "nonce_epoch_replay",
        "resource_ceilings",
        "exit_recovery",
        "availability_assumptions",
        "external_proof_device_assumptions",
        "composition_assumptions",
    ];
    const ENFORCEMENT: [&str; 5] = [
        "L1_CONSENSUS",
        "PROFILE_RUNTIME",
        "OPERATOR_POLICY",
        "EXTERNAL_ASSUMPTION",
        "UNSUPPORTED",
    ];
    const OUTCOMES: [&str; 3] = ["REJECT", "UNAVAILABLE", "REQUIRES_HUMAN_REVIEW"];
    let invariants = read_json(&root.join("invariants.json"))?;
    if !exact_json_keys(
        &invariants,
        &[
            "schema",
            "protocol_semver",
            "profile_id",
            "profile_semver",
            "vector_set_id",
            "invariants",
            "forbidden_transitions",
        ],
    ) || invariants.get("schema").and_then(Value::as_str)
        != Some("KTAPEOUT-PROFILE-INVARIANT-V1")
        || invariants.get("protocol_semver").and_then(Value::as_str) != Some(PROTOCOL)
    {
        return Err("PROFILE_INVARIANT_SHAPE_OR_IDENTITY_INVALID".into());
    }
    if invariants.get("profile_id").and_then(Value::as_str) != Some(profile_id)
        || invariants.get("profile_semver").and_then(Value::as_str) != Some(profile_semver)
    {
        return Err("PROFILE_INVARIANT_IDENTITY_MISMATCH".into());
    }
    if !invariants
        .get("vector_set_id")
        .and_then(Value::as_str)
        .is_some_and(valid_profile_id)
    {
        return Err("PROFILE_INVARIANT_VECTOR_SET_ID_INVALID".into());
    }
    let claims = invariants
        .get("invariants")
        .and_then(Value::as_object)
        .ok_or_else(|| "PROFILE_INVARIANT_CATEGORIES_INVALID".to_string())?;
    let expected_categories: std::collections::BTreeSet<&str> =
        CATEGORIES.iter().copied().collect();
    let actual_categories: std::collections::BTreeSet<&str> =
        claims.keys().map(String::as_str).collect();
    if actual_categories != expected_categories {
        return Err("PROFILE_INVARIANT_CATEGORIES_INCOMPLETE".into());
    }
    let mut references = std::collections::BTreeMap::<String, String>::new();
    for category in CATEGORIES {
        let claim = &claims[category];
        if !exact_json_keys(claim, &["enforcement", "statement", "negative_vector_ids"]) {
            return Err(format!("PROFILE_INVARIANT_CLAIM_INVALID:{category}"));
        }
        if !claim
            .get("enforcement")
            .and_then(Value::as_str)
            .is_some_and(|v| ENFORCEMENT.contains(&v))
        {
            return Err(format!("PROFILE_INVARIANT_ENFORCEMENT_INVALID:{category}"));
        }
        let statement = claim
            .get("statement")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if statement.trim().is_empty() || statement.chars().count() > 1024 {
            return Err(format!("PROFILE_INVARIANT_STATEMENT_INVALID:{category}"));
        }
        let ids = claim
            .get("negative_vector_ids")
            .and_then(Value::as_array)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| format!("PROFILE_INVARIANT_VECTOR_REFERENCES_INVALID:{category}"))?;
        let mut local = std::collections::BTreeSet::new();
        for id in ids {
            let id = id
                .as_str()
                .filter(|v| valid_profile_id(v))
                .ok_or_else(|| format!("PROFILE_INVARIANT_VECTOR_REFERENCES_INVALID:{category}"))?;
            if !local.insert(id.to_string())
                || references
                    .insert(id.to_string(), category.to_string())
                    .is_some()
            {
                return Err(format!(
                    "PROFILE_INVARIANT_VECTOR_REFERENCE_DUPLICATED:{id}"
                ));
            }
        }
    }
    let forbidden = invariants
        .get("forbidden_transitions")
        .and_then(Value::as_array)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| "PROFILE_INVARIANT_FORBIDDEN_TRANSITIONS_EMPTY".to_string())?;
    let mut transition_ids = std::collections::BTreeSet::new();
    for transition in forbidden {
        if !exact_json_keys(
            transition,
            &["transition_id", "statement", "negative_vector_id"],
        ) {
            return Err("PROFILE_INVARIANT_FORBIDDEN_TRANSITION_INVALID".into());
        }
        let transition_id = transition
            .get("transition_id")
            .and_then(Value::as_str)
            .filter(|v| valid_profile_id(v))
            .ok_or_else(|| "PROFILE_INVARIANT_TRANSITION_ID_INVALID".to_string())?;
        if !transition_ids.insert(transition_id.to_string()) {
            return Err("PROFILE_INVARIANT_TRANSITION_ID_INVALID".into());
        }
        let statement = transition
            .get("statement")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if statement.trim().is_empty() || statement.chars().count() > 1024 {
            return Err("PROFILE_INVARIANT_TRANSITION_STATEMENT_INVALID".into());
        }
        let vector_id = transition
            .get("negative_vector_id")
            .and_then(Value::as_str)
            .filter(|v| valid_profile_id(v))
            .ok_or_else(|| "PROFILE_INVARIANT_TRANSITION_VECTOR_INVALID".to_string())?;
        if references
            .insert(vector_id.to_string(), "forbidden_transitions".into())
            .is_some()
        {
            return Err("PROFILE_INVARIANT_TRANSITION_VECTOR_INVALID".into());
        }
    }
    let vector_set = read_json(&root.join("vectors/profile-invariants.json"))?;
    if !exact_json_keys(
        &vector_set,
        &[
            "schema",
            "protocol_semver",
            "profile_id",
            "profile_semver",
            "vectors",
        ],
    ) || vector_set.get("schema").and_then(Value::as_str)
        != Some("KTAPEOUT-PROFILE-INVARIANT-VECTORS-V1")
        || vector_set.get("protocol_semver").and_then(Value::as_str) != Some(PROTOCOL)
    {
        return Err("PROFILE_INVARIANT_VECTOR_SET_SHAPE_INVALID".into());
    }
    if vector_set.get("profile_id").and_then(Value::as_str) != Some(profile_id)
        || vector_set.get("profile_semver").and_then(Value::as_str) != Some(profile_semver)
    {
        return Err("PROFILE_INVARIANT_VECTOR_SET_IDENTITY_MISMATCH".into());
    }
    let vectors = vector_set
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| "PROFILE_INVARIANT_VECTORS_INVALID".to_string())?;
    let mut observed = std::collections::BTreeMap::<String, String>::new();
    for vector in vectors {
        if !exact_json_keys(
            vector,
            &["vector_id", "invariant_id", "input", "expected_outcome"],
        ) {
            return Err("PROFILE_INVARIANT_VECTOR_ENTRY_INVALID".into());
        }
        let vector_id = vector
            .get("vector_id")
            .and_then(Value::as_str)
            .filter(|v| valid_profile_id(v))
            .ok_or_else(|| "PROFILE_INVARIANT_VECTOR_ID_INVALID".to_string())?;
        let category = vector
            .get("invariant_id")
            .and_then(Value::as_str)
            .filter(|v| CATEGORIES.contains(v) || *v == "forbidden_transitions")
            .ok_or_else(|| format!("PROFILE_INVARIANT_VECTOR_CATEGORY_INVALID:{vector_id}"))?;
        if !vector.get("input").is_some_and(Value::is_object)
            || !vector
                .get("expected_outcome")
                .and_then(Value::as_str)
                .is_some_and(|v| OUTCOMES.contains(&v))
        {
            return Err(format!(
                "PROFILE_INVARIANT_VECTOR_OUTCOME_INVALID:{vector_id}"
            ));
        }
        if observed
            .insert(vector_id.to_string(), category.to_string())
            .is_some()
        {
            return Err("PROFILE_INVARIANT_VECTOR_ID_DUPLICATED".into());
        }
    }
    for (vector_id, category) in references {
        if observed.get(&vector_id) != Some(&category) {
            return Err(format!(
                "PROFILE_INVARIANT_VECTOR_REFERENCE_MISMATCH:{vector_id}"
            ));
        }
    }
    let mut hash_material = invariants.clone();
    hash_material
        .as_object_mut()
        .ok_or_else(|| "PROFILE_INVARIANT_OBJECT_INVALID".to_string())?
        .remove("profile_semver");
    let invariant_hash = digest_bytes(
        &canonical_json(&hash_material)?,
        "KTAPEOUT/0.5.0/PROFILE_INVARIANT/V1",
    );
    if descriptor.get("invariant_hash").and_then(Value::as_str) != Some(invariant_hash.as_str()) {
        return Err("PROFILE_INVARIANT_HASH_MISMATCH".into());
    }
    Ok(())
}

fn verify_profile_package(path: PathBuf) -> Result<(Value, Vec<String>), String> {
    let root =
        fs::canonicalize(&path).map_err(|error| format!("PROFILE_PACKAGE_PATH_ERROR:{error}"))?;
    if !root.is_dir() {
        return Err("PROFILE_PACKAGE_DIRECTORY_REQUIRED".into());
    }
    let package_path = root.join("package.json");
    let metadata = read_json(&package_path)?;
    let object = metadata
        .as_object()
        .ok_or_else(|| "PROFILE_PACKAGE_NOT_OBJECT".to_string())?;
    if object.get("schema").and_then(Value::as_str) != Some("KTAPEOUT-PROFILE-PACKAGE-V1")
        || object.get("protocol_semver").and_then(Value::as_str) != Some(PROTOCOL)
    {
        return Err("PROFILE_PACKAGE_IDENTITY_INVALID".into());
    }
    let required = [
        "profile_id",
        "profile_semver",
        "profile_hash",
        "package_digest",
        "runtime_digest",
        "compiler_lock_digest",
        "vector_root",
        "resource_envelope_digest",
        "supported_core",
        "admission_level",
        "publisher_id",
        "source_ref",
        "license_ref",
        "trust_tier",
        "file_digests",
    ];
    if required.iter().any(|field| !object.contains_key(*field)) {
        return Err("PROFILE_PACKAGE_FIELD_MISSING".into());
    }
    for field in [
        "profile_hash",
        "package_digest",
        "runtime_digest",
        "compiler_lock_digest",
        "vector_root",
        "resource_envelope_digest",
    ] {
        if !valid_hash(
            object
                .get(field)
                .and_then(Value::as_str)
                .unwrap_or_default(),
        ) {
            return Err(format!("PROFILE_PACKAGE_HASH_INVALID:{field}"));
        }
    }
    if object.get("supported_core").and_then(Value::as_str) != Some(PROTOCOL) {
        return Err("PROFILE_PACKAGE_CORE_MISMATCH".into());
    }
    let profile_id = object
        .get("profile_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "PROFILE_PACKAGE_PROFILE_ID_INVALID".to_string())?;
    if !valid_profile_id(profile_id) {
        return Err("PROFILE_PACKAGE_PROFILE_ID_INVALID".into());
    }
    let profile_semver = object
        .get("profile_semver")
        .and_then(Value::as_str)
        .ok_or_else(|| "PROFILE_PACKAGE_PROFILE_SEMVER_INVALID".to_string())?;
    if !valid_profile_semver(profile_semver) {
        return Err("PROFILE_PACKAGE_PROFILE_SEMVER_INVALID".into());
    }
    let _profile_cache_component = cache_component(profile_id, "PROFILE_ID", 128)?;
    let _semver_cache_component = cache_component(profile_semver, "PROFILE_SEMVER", 64)?;
    let descriptor = read_json(&root.join("profile.json"))?;
    if descriptor.get("profile_id").and_then(Value::as_str) != Some(profile_id)
        || descriptor.get("profile_semver").and_then(Value::as_str) != Some(profile_semver)
    {
        return Err("PROFILE_PACKAGE_DESCRIPTOR_IDENTITY_MISMATCH".into());
    }
    if !matches!(
        object.get("admission_level").and_then(Value::as_str),
        Some("REFERENCE")
            | Some("IMPLEMENTED")
            | Some("TESTNET_ADMITTED")
            | Some("PRODUCTION_CANDIDATE")
    ) {
        return Err("PROFILE_PACKAGE_ADMISSION_INVALID".into());
    }
    for field in ["publisher_id", "license_ref"] {
        let value = object
            .get(field)
            .and_then(Value::as_str)
            .unwrap_or_default();
        if value.is_empty() || value.len() > 128 || value.contains('\r') || value.contains('\n') {
            return Err(format!("PROFILE_PACKAGE_PROVENANCE_INVALID:{field}"));
        }
    }
    let source_ref = object
        .get("source_ref")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if source_ref.is_empty()
        || source_ref.len() > 256
        || source_ref.contains("..")
        || source_ref.contains('\\')
        || source_ref.starts_with("http://")
        || source_ref.starts_with("https://")
    {
        return Err("PROFILE_PACKAGE_SOURCE_REF_INVALID".into());
    }
    if !matches!(
        object.get("trust_tier").and_then(Value::as_str),
        Some("UNTRUSTED") | Some("COMMUNITY") | Some("VERIFIED") | Some("CORE_MAINTAINER")
    ) {
        return Err("PROFILE_PACKAGE_TRUST_TIER_INVALID".into());
    }
    let mut files = Vec::new();
    profile_package_files(&root, &root, &mut files)?;
    files.sort();
    validate_profile_package_file_budget(&root, &files)?;
    let file_set: std::collections::BTreeSet<String> = files.iter().cloned().collect();
    for required_file in [
        "profile.json",
        "interfaces.json",
        "resource-envelope.json",
        "admission.json",
        "invariants.json",
        "vectors/profile-invariants.json",
    ] {
        if !file_set.contains(required_file) {
            return Err("PROFILE_PACKAGE_REQUIRED_FILE_MISSING".into());
        }
    }
    let admission = read_json(&root.join("admission.json"))?;
    let admission_object = admission
        .as_object()
        .ok_or_else(|| "PROFILE_PACKAGE_ADMISSION_NOT_OBJECT".to_string())?;
    let admission_level = object
        .get("admission_level")
        .and_then(Value::as_str)
        .ok_or_else(|| "PROFILE_PACKAGE_ADMISSION_INVALID".to_string())?;
    if admission_object
        .get("admission_level")
        .and_then(Value::as_str)
        != Some(admission_level)
    {
        return Err("PROFILE_PACKAGE_ADMISSION_LEVEL_MISMATCH".into());
    }
    let invariants_value = read_json(&root.join("invariants.json"))?;
    let invariant_rows = invariants_value
        .get("invariants")
        .and_then(Value::as_object)
        .ok_or_else(|| "PROFILE_PACKAGE_INVARIANTS_INVALID".to_string())?;
    let mut exit_roles = std::collections::BTreeSet::new();
    if let Some(terminal_policies) = admission_object.get("state_exit_policies") {
        let terminal_policies = terminal_policies
            .as_array()
            .ok_or_else(|| "PROFILE_PACKAGE_STATE_EXIT_POLICIES_INVALID".to_string())?;
        if terminal_policies.len() > 32 {
            return Err("PROFILE_PACKAGE_STATE_EXIT_POLICIES_OVER_BUDGET".into());
        }
        for policy in terminal_policies {
            if !object_fields_exact(
                policy,
                &[
                    "state_role",
                    "exit_policy",
                    "carrier_sompi",
                    "refund",
                    "namespace_reallocation",
                    "invariant_id",
                ],
                &[],
            ) {
                return Err("PROFILE_PACKAGE_STATE_EXIT_POLICY_FIELDS_INVALID".into());
            }
            let role = policy["state_role"]
                .as_str()
                .filter(|v| !v.is_empty())
                .ok_or_else(|| "PROFILE_PACKAGE_STATE_EXIT_ROLE_INVALID".to_string())?;
            if !exit_roles.insert(role.to_string())
                || policy["exit_policy"] != "PERMANENT_UNSPENDABLE"
                || policy["carrier_sompi"]
                    .as_u64()
                    .is_none_or(|amount| amount == 0)
                || policy["refund"] != "NONE"
                || policy["namespace_reallocation"] != false
            {
                return Err("PROFILE_PACKAGE_STATE_EXIT_POLICY_CONTRADICTORY".into());
            }
            let invariant_id = policy["invariant_id"]
                .as_str()
                .ok_or_else(|| "PROFILE_PACKAGE_STATE_EXIT_INVARIANT_INVALID".to_string())?;
            if invariant_rows
                .get(invariant_id)
                .and_then(|value| value.get("enforcement"))
                .and_then(Value::as_str)
                != Some("L1_CONSENSUS")
            {
                return Err("PROFILE_PACKAGE_STATE_EXIT_INVARIANT_NOT_L1_ENFORCED".into());
            }
        }
    }
    let l1_attested = admission_object.get("l1_attested");
    if let Some(value) = l1_attested {
        if !value.is_boolean() {
            return Err("PROFILE_PACKAGE_L1_ATTESTED_TYPE_INVALID".into());
        }
    }
    if admission_level == "REFERENCE" && l1_attested.and_then(Value::as_bool) == Some(true) {
        return Err("PROFILE_PACKAGE_REFERENCE_L1_ATTESTED_INVALID".into());
    }
    if matches!(admission_level, "TESTNET_ADMITTED" | "PRODUCTION_CANDIDATE")
        && l1_attested.and_then(Value::as_bool) != Some(true)
    {
        return Err("PROFILE_PACKAGE_ADMISSION_L1_ATTESTATION_REQUIRED".into());
    }
    if !files.iter().any(|file| file.starts_with("vectors/")) {
        return Err("PROFILE_PACKAGE_VECTORS_MISSING".into());
    }
    let digests = object
        .get("file_digests")
        .and_then(Value::as_object)
        .ok_or_else(|| "PROFILE_PACKAGE_FILE_DIGESTS_INVALID".to_string())?;
    let declared: std::collections::BTreeSet<String> = digests.keys().cloned().collect();
    if declared != file_set {
        return Err("PROFILE_PACKAGE_FILE_DIGESTS_NOT_EXACT".into());
    }
    for relative in &files {
        let expected = digests
            .get(relative)
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !valid_hash(expected) {
            return Err(format!("PROFILE_PACKAGE_FILE_DIGEST_INVALID:{relative}"));
        }
        let bytes = fs::read(root.join(relative))
            .map_err(|error| format!("PROFILE_PACKAGE_FILE_READ_ERROR:{error}"))?;
        // File manifest entries use raw SHA-256, matching the Python package
        // verifier; domain separation is reserved for profile/package roots.
        let raw = hex_string(&Sha256::digest(&bytes));
        if raw != expected {
            return Err(format!("PROFILE_PACKAGE_FILE_DIGEST_MISMATCH:{relative}"));
        }
    }
    validate_profile_invariants(&root, &descriptor, profile_id, profile_semver)?;
    let profile_bytes = fs::read(root.join("profile.json"))
        .map_err(|error| format!("PROFILE_PACKAGE_PROFILE_READ_ERROR:{error}"))?;
    let profile_hash = profile_descriptor_commitment(
        &descriptor,
        &profile_bytes,
        object
            .get("admission_level")
            .and_then(Value::as_str)
            .unwrap_or(""),
    )?;
    if descriptor.get("core_protocol").is_some() {
        let invariants = read_json(&root.join("invariants.json"))?;
        if descriptor.get("vector_set_id") != invariants.get("vector_set_id") {
            return Err("PROFILE_PACKAGE_DESCRIPTOR_VECTOR_SET_MISMATCH".into());
        }
    }
    if object.get("profile_hash").and_then(Value::as_str) != Some(profile_hash.as_str()) {
        return Err("PROFILE_PACKAGE_PROFILE_HASH_MISMATCH".into());
    }
    if root.join("source/descriptor-material.json").exists() {
        let material = read_json(&root.join("source/descriptor-material.json"))?;
        let fields = [
            "state_encoding",
            "transition_equation",
            "input_shape",
            "output_shape",
            "lowering_template",
            "selector_binding",
            "predecessor_state_binding",
            "exit_policy",
            "capability_policy",
            "dependency_manifest",
        ];
        if descriptor.get("core_protocol").is_none() || !exact_json_keys(&material, &fields) {
            return Err("PROFILE_PACKAGE_DESCRIPTOR_MATERIAL_INVALID".into());
        }
        for field in fields {
            let value = &material[field];
            let hash = hex_string(&Sha256::digest(canonical_json(value)?));
            if !value.is_object()
                || descriptor
                    .get(format!("{field}_hash"))
                    .and_then(Value::as_str)
                    != Some(hash.as_str())
            {
                return Err(format!(
                    "PROFILE_PACKAGE_DESCRIPTOR_MATERIAL_MISMATCH:{field}"
                ));
            }
        }
        let dependencies = material["dependency_manifest"]["files"]
            .as_object()
            .ok_or("PROFILE_PACKAGE_DESCRIPTOR_DEPENDENCIES_INVALID")?;
        if dependencies.is_empty()
            || dependencies
                .iter()
                .any(|(name, hash)| digests.get(name) != Some(hash))
        {
            return Err("PROFILE_PACKAGE_DESCRIPTOR_DEPENDENCIES_MISMATCH".into());
        }
    }
    let mut material = metadata.clone();
    material
        .as_object_mut()
        .ok_or_else(|| "PROFILE_PACKAGE_METADATA_INVALID".to_string())?
        .insert("package_digest".into(), Value::String("0".repeat(64)));
    let package_json = canonical_json(&material)?;
    let package_digest = digest_bytes(&package_json, "KTAPEOUT/0.5.0/PROFILE_PACKAGE/V1");
    if object.get("package_digest").and_then(Value::as_str) != Some(package_digest.as_str()) {
        return Err("PROFILE_PACKAGE_DIGEST_MISMATCH".into());
    }
    if root.join("execution-evidence.json").exists() {
        profile_execution_evidence::verify(&root, &metadata)?;
    }
    Ok((metadata, files))
}

fn read_verified_profile_json(
    root: &Path,
    metadata: &Value,
    relative: &str,
) -> Result<Value, String> {
    let expected = metadata
        .get("file_digests")
        .and_then(Value::as_object)
        .and_then(|files| files.get(relative))
        .and_then(Value::as_str)
        .ok_or_else(|| format!("PROFILE_PACKAGE_FILE_NOT_COMMITTED:{relative}"))?;
    let bytes = fs::read(root.join(relative))
        .map_err(|error| format!("PROFILE_PACKAGE_FILE_READ_ERROR:{relative}:{error}"))?;
    if hex_string(&Sha256::digest(&bytes)) != expected {
        return Err(format!("PROFILE_PACKAGE_FILE_DIGEST_MISMATCH:{relative}"));
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("PROFILE_PACKAGE_JSON_INVALID:{relative}:{error}"))
}

fn missing_composition_sidecars(files: &[String]) -> Vec<&'static str> {
    ["profile-contract.json", "effect-manifest.json"]
        .into_iter()
        .filter(|required| !files.iter().any(|file| file == required))
        .collect()
}

fn profile_package_output_is_inside_source(source_root: &Path, output_parent: &Path) -> bool {
    output_parent == source_root || output_parent.starts_with(source_root)
}

fn profile_package_verify(path: PathBuf) -> Result<(), String> {
    let (metadata, files) = verify_profile_package(path)?;
    let object = metadata
        .as_object()
        .ok_or_else(|| "PROFILE_PACKAGE_NOT_OBJECT".to_string())?;
    let missing_composition_sidecars = missing_composition_sidecars(&files);
    emit_result(
        "ktape profile package-verify",
        None,
        json!({"schema":"KTAPEOUT-PROFILE-PACKAGE-VERIFICATION-V1", "verified":true, "profile_id":object.get("profile_id"), "profile_semver":object.get("profile_semver"), "profile_hash":object.get("profile_hash"), "package_digest":object.get("package_digest"), "file_count":files.len(), "composition_sidecars_committed":missing_composition_sidecars.is_empty(), "missing_composition_sidecars":missing_composition_sidecars, "unsigned":true, "broadcast":false}),
    )
}

fn profile_package_compose(
    source: PathBuf,
    contract_path: PathBuf,
    effect_path: PathBuf,
    output: PathBuf,
) -> Result<(), String> {
    let (mut metadata, files) = verify_profile_package(source.clone())?;
    let source_root =
        fs::canonicalize(&source).map_err(|error| format!("PROFILE_PACKAGE_PATH_ERROR:{error}"))?;
    if files
        .iter()
        .any(|file| file == "profile-contract.json" || file == "effect-manifest.json")
    {
        return Err("PROFILE_PACKAGE_COMPOSITION_SIDECARS_ALREADY_PRESENT".into());
    }
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if !parent.is_dir() {
        return Err("PROFILE_PACKAGE_OUTPUT_PARENT_MISSING".into());
    }
    let parent = fs::canonicalize(parent)
        .map_err(|error| format!("PROFILE_PACKAGE_OUTPUT_PARENT_ERROR:{error}"))?;
    if profile_package_output_is_inside_source(&source_root, &parent) {
        return Err("PROFILE_PACKAGE_OUTPUT_INSIDE_SOURCE_PACKAGE".into());
    }
    let output_name = output
        .file_name()
        .ok_or_else(|| "PROFILE_PACKAGE_OUTPUT_PATH_INVALID".to_string())?;
    let destination = parent.join(output_name);
    if fs::symlink_metadata(&destination).is_ok() {
        return Err("PROFILE_PACKAGE_OUTPUT_ALREADY_EXISTS".into());
    }
    let contract = read_json(&contract_path)?;
    let effect = read_json(&effect_path)?;
    profile_governance::validate_package_composition_sidecars(&contract, &effect, &metadata)?;

    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "PROFILE_PACKAGE_CLOCK_ERROR".to_string())?
        .as_nanos();
    let staging = parent.join(format!(
        ".ktape-profile-compose-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&staging)
        .map_err(|error| format!("PROFILE_PACKAGE_STAGING_CREATE_ERROR:{error}"))?;
    let staged_result = (|| -> Result<(Value, Vec<String>), String> {
        for relative in &files {
            let source_file = source_root.join(relative);
            let target_file = staging.join(relative);
            if let Some(directory) = target_file.parent() {
                fs::create_dir_all(directory)
                    .map_err(|error| format!("PROFILE_PACKAGE_STAGING_CREATE_ERROR:{error}"))?;
            }
            fs::copy(&source_file, &target_file)
                .map_err(|error| format!("PROFILE_PACKAGE_COPY_ERROR:{relative}:{error}"))?;
        }
        let contract_bytes = serde_json::to_vec_pretty(&contract)
            .map_err(|error| format!("PROFILE_PACKAGE_SIDECAR_ENCODE_ERROR:{error}"))?;
        let effect_bytes = serde_json::to_vec_pretty(&effect)
            .map_err(|error| format!("PROFILE_PACKAGE_SIDECAR_ENCODE_ERROR:{error}"))?;
        fs::write(staging.join("profile-contract.json"), &contract_bytes)
            .map_err(|error| format!("PROFILE_PACKAGE_SIDECAR_WRITE_ERROR:{error}"))?;
        fs::write(staging.join("effect-manifest.json"), &effect_bytes)
            .map_err(|error| format!("PROFILE_PACKAGE_SIDECAR_WRITE_ERROR:{error}"))?;

        let digest_map = metadata
            .get_mut("file_digests")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| "PROFILE_PACKAGE_FILE_DIGESTS_INVALID".to_string())?;
        digest_map.insert(
            "profile-contract.json".into(),
            Value::String(hex_string(&Sha256::digest(&contract_bytes))),
        );
        digest_map.insert(
            "effect-manifest.json".into(),
            Value::String(hex_string(&Sha256::digest(&effect_bytes))),
        );
        metadata["package_digest"] = Value::String("0".repeat(64));
        let material = canonical_json(&metadata)?;
        metadata["package_digest"] =
            Value::String(digest_bytes(&material, "KTAPEOUT/0.5.0/PROFILE_PACKAGE/V1"));
        let package_bytes = serde_json::to_vec_pretty(&metadata)
            .map_err(|error| format!("PROFILE_PACKAGE_METADATA_ENCODE_ERROR:{error}"))?;
        fs::write(staging.join("package.json"), package_bytes)
            .map_err(|error| format!("PROFILE_PACKAGE_METADATA_WRITE_ERROR:{error}"))?;
        verify_profile_package(staging.clone())
    })();
    let (verified_metadata, verified_files) = match staged_result {
        Ok(value) => value,
        Err(error) => {
            let _ = fs::remove_dir_all(&staging);
            return Err(error);
        }
    };
    if let Err(error) = fs::rename(&staging, &destination) {
        let _ = fs::remove_dir_all(&staging);
        return Err(format!("PROFILE_PACKAGE_OUTPUT_COMMIT_ERROR:{error}"));
    }
    emit_result(
        "ktape profile package-compose",
        None,
        json!({"schema":"KTAPEOUT-PROFILE-PACKAGE-COMPOSITION-V1", "status":"CREATED_NEW_PACKAGE", "profile_id":verified_metadata.get("profile_id"), "profile_semver":verified_metadata.get("profile_semver"), "profile_hash":verified_metadata.get("profile_hash"), "package_digest":verified_metadata.get("package_digest"), "file_count":verified_files.len(), "composition_sidecars_committed":true, "output":destination, "signing_allowed":false, "broadcast":false}),
    )
}

fn profile_inspect(path: PathBuf) -> Result<(), String> {
    let (metadata, files) = verify_profile_package(path)?;
    let object = metadata
        .as_object()
        .ok_or_else(|| "PROFILE_PACKAGE_NOT_OBJECT".to_string())?;
    emit_result(
        "ktape profile inspect",
        None,
        json!({
            "schema": "KTAPEOUT-PROFILE-PACKAGE-INSPECTION-V1",
            "verified": true,
            "profile_id": object.get("profile_id"),
            "profile_semver": object.get("profile_semver"),
            "profile_hash": object.get("profile_hash"),
            "package_digest": object.get("package_digest"),
            "admission_level": object.get("admission_level"),
            "trust_tier": object.get("trust_tier"),
            "file_count": files.len(),
            "signing_allowed": false,
            "broadcast": false
        }),
    )
}

fn discover_package_json(root: &PathBuf, found: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries =
        fs::read_dir(root).map_err(|error| format!("PROFILE_SEARCH_READ_ERROR:{error}"))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("PROFILE_SEARCH_ENTRY_ERROR:{error}"))?;
        let path = entry.path();
        if path.is_dir() {
            discover_package_json(&path, found)?;
        } else if path.file_name().and_then(|name| name.to_str()) == Some("package.json") {
            found.push(path);
        }
    }
    Ok(())
}

fn profile_search(root: PathBuf, profile_id: Option<String>) -> Result<(), String> {
    let mut candidates = Vec::new();
    discover_package_json(&root, &mut candidates)?;
    let mut accepted = Vec::new();
    let mut rejected = Vec::new();
    for package_json in candidates {
        let package_root = package_json
            .parent()
            .ok_or_else(|| "PROFILE_SEARCH_PATH_INVALID".to_string())?
            .to_path_buf();
        match verify_profile_package(package_root) {
            Ok((metadata, files)) => {
                let object = metadata
                    .as_object()
                    .ok_or_else(|| "PROFILE_PACKAGE_NOT_OBJECT".to_string())?;
                let id = object
                    .get("profile_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if profile_id.as_deref().is_none_or(|filter| filter == id) {
                    accepted.push(json!({
                        "profile_id": id,
                        "profile_semver": object.get("profile_semver"),
                        "profile_hash": object.get("profile_hash"),
                        "package_digest": object.get("package_digest"),
                        "file_count": files.len(),
                        "path": package_json
                    }));
                }
            }
            Err(error) => rejected.push(json!({"path": package_json, "error": error})),
        }
    }
    accepted.sort_by_key(|left| left.to_string());
    rejected.sort_by_key(|left| left.to_string());
    emit_result(
        "ktape profile search",
        None,
        json!({"schema":"KTAPEOUT-PROFILE-SEARCH-V1", "accepted":accepted, "rejected":rejected, "signing_allowed":false, "broadcast":false}),
    )
}

fn profile_compose(
    packages: Vec<PathBuf>,
    draft: Option<PathBuf>,
    output: Option<PathBuf>,
) -> Result<(), String> {
    if packages.is_empty() {
        return Err("PROFILE_COMPOSITION_EMPTY".into());
    }
    if let Some(draft_path) = draft {
        let draft_value = read_json(&draft_path)?;
        let mut verified = Vec::with_capacity(packages.len());
        for package in packages {
            let package_root = fs::canonicalize(&package)
                .map_err(|error| format!("PROFILE_PACKAGE_PATH_ERROR:{error}"))?;
            let (metadata, _) = verify_profile_package(package_root.clone())?;
            let contract =
                read_verified_profile_json(&package_root, &metadata, "profile-contract.json")?;
            let effect_manifest =
                read_verified_profile_json(&package_root, &metadata, "effect-manifest.json")?;
            let interfaces =
                read_verified_profile_json(&package_root, &metadata, "interfaces.json")?;
            let resource_envelope =
                read_verified_profile_json(&package_root, &metadata, "resource-envelope.json")?;
            verified.push(profile_governance::VerifiedProfilePackage {
                metadata,
                contract,
                effect_manifest,
                interfaces,
                resource_envelope,
            });
        }
        let composed = profile_governance::compose_recipe(&draft_value, &verified)?;
        if let Some(path) = output {
            if let Ok(metadata) = fs::symlink_metadata(&path) {
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    return Err("PROFILE_COMPOSITION_OUTPUT_NOT_REGULAR_FILE".into());
                }
            }
            let parent = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            if !parent.is_dir() {
                return Err("PROFILE_COMPOSITION_OUTPUT_PARENT_MISSING".into());
            }
            let mut bytes = serde_json::to_vec_pretty(&composed.recipe)
                .map_err(|error| format!("PROFILE_COMPOSITION_OUTPUT_ENCODE:{error}"))?;
            bytes.push(b'\n');
            atomic_write_file(&path, &bytes, "ktape-profile-recipe")?;
        }
        return emit_result_status(
            "ktape profile compose",
            None,
            "PASS",
            json!({"schema":"KTAPEOUT-PROFILE-COMPOSITION-V1", "status":"COMPOSED_REVIEW_REQUIRED", "recipe":composed.recipe, "recipe_hash":composed.recipe["recipe_hash"], "composition_root":composed.composition_root, "package_digests":composed.package_digests, "application_lock_status":"NOT_CREATED", "business_tests":"NOT_RUN", "signing_allowed":false, "broadcast":false}),
        );
    }
    if output.is_some() {
        return Err("PROFILE_COMPOSITION_OUTPUT_REQUIRES_DRAFT".into());
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut entries = Vec::new();
    let mut conflicts = Vec::new();
    let mut interface_units = std::collections::BTreeMap::new();
    let mut state_encodings = std::collections::BTreeMap::new();
    let mut total_inputs: u64 = 0;
    let mut total_outputs: u64 = 0;
    let mut total_witness_bytes: u64 = 0;
    for package in packages {
        let package_root = fs::canonicalize(&package)
            .map_err(|error| format!("PROFILE_PACKAGE_PATH_ERROR:{error}"))?;
        let (metadata, _) = verify_profile_package(package_root.clone())?;
        let object = metadata
            .as_object()
            .ok_or_else(|| "PROFILE_PACKAGE_NOT_OBJECT".to_string())?;
        let id = object
            .get("profile_id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !seen.insert(id.to_string()) {
            return Err(format!("PROFILE_COMPOSITION_CONFLICT:{id}"));
        }
        let descriptor = read_json(&package_root.join("profile.json"))?;
        let descriptor_object = descriptor
            .as_object()
            .ok_or_else(|| format!("PROFILE_COMPOSITION_DESCRIPTOR_INVALID:{id}"))?;
        let descriptor_id = descriptor_object
            .get("profile_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                format!("PROFILE_COMPOSITION_DESCRIPTOR_FIELD_MISSING:{id}:profile_id")
            })?;
        if descriptor_id != id {
            conflicts.push(json!({"class":"identity/version", "profiles":[id, descriptor_id], "reason":"package metadata and descriptor identity differ"}));
        }
        let profile_hash = descriptor_object
            .get("profile_hash")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                format!("PROFILE_COMPOSITION_DESCRIPTOR_FIELD_MISSING:{id}:profile_hash")
            })?;
        if !valid_hash(profile_hash) {
            conflicts.push(json!({"class":"identity/version", "profiles":[id], "reason":"profile_hash is invalid"}));
        }
        let state_hash = descriptor_object
            .get("state_encoding_hash")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                format!("PROFILE_COMPOSITION_DESCRIPTOR_FIELD_MISSING:{id}:state_encoding_hash")
            })?;
        let merge_mode = descriptor_object
            .get("merge_mode")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                format!("PROFILE_COMPOSITION_DESCRIPTOR_FIELD_MISSING:{id}:merge_mode")
            })?;
        if let Some(previous) = state_encodings.insert(state_hash.to_string(), id.to_string()) {
            if merge_mode == "NONE" {
                conflicts.push(json!({"class":"state", "profiles":[previous, id], "reason":"shared state encoding has no merge mode"}));
            }
        }
        let max_inputs = descriptor_object
            .get("max_inputs")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                format!("PROFILE_COMPOSITION_DESCRIPTOR_FIELD_INVALID:{id}:max_inputs")
            })?;
        let max_outputs = descriptor_object
            .get("max_outputs")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                format!("PROFILE_COMPOSITION_DESCRIPTOR_FIELD_INVALID:{id}:max_outputs")
            })?;
        let max_witness = descriptor_object
            .get("max_witness_bytes")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                format!("PROFILE_COMPOSITION_DESCRIPTOR_FIELD_INVALID:{id}:max_witness_bytes")
            })?;
        total_inputs = total_inputs
            .checked_add(max_inputs)
            .ok_or_else(|| "PROFILE_COMPOSITION_RESOURCE_OVERFLOW".to_string())?;
        total_outputs = total_outputs
            .checked_add(max_outputs)
            .ok_or_else(|| "PROFILE_COMPOSITION_RESOURCE_OVERFLOW".to_string())?;
        total_witness_bytes = total_witness_bytes
            .checked_add(max_witness)
            .ok_or_else(|| "PROFILE_COMPOSITION_RESOURCE_OVERFLOW".to_string())?;
        let interfaces = read_json(&package_root.join("interfaces.json"))?;
        let interface_object = interfaces
            .as_object()
            .ok_or_else(|| format!("PROFILE_COMPOSITION_INTERFACE_INVALID:{id}"))?;
        if let Some(ports) = interface_object.get("ports") {
            let ports = ports
                .as_object()
                .ok_or_else(|| format!("PROFILE_COMPOSITION_INTERFACE_PORTS_INVALID:{id}"))?;
            for (name, unit) in ports {
                let unit = unit.as_str().ok_or_else(|| {
                    format!("PROFILE_COMPOSITION_INTERFACE_UNIT_INVALID:{id}:{name}")
                })?;
                if let Some((previous_id, previous_unit)) = interface_units.get(name) {
                    if previous_unit != unit {
                        conflicts.push(json!({"class":"interface/unit", "profiles":[previous_id, id], "reason":format!("interface unit mismatch:{name}")}));
                    }
                } else {
                    interface_units.insert(name.clone(), (id.to_string(), unit.to_string()));
                }
            }
        }
        let _resource_envelope = read_json(&package_root.join("resource-envelope.json"))?;
        entries.push(json!({"profile_id": id, "profile_semver": object.get("profile_semver"), "profile_hash": object.get("profile_hash"), "package_digest": object.get("package_digest"), "state_encoding_hash": state_hash, "merge_mode": merge_mode, "max_inputs": max_inputs, "max_outputs": max_outputs, "max_witness_bytes": max_witness, "interface_root": sha256_value(&interfaces)?}));
    }
    if total_inputs > 64 || total_outputs > 64 || total_witness_bytes > 64 * 1024 * 1024 {
        conflicts.push(json!({"class":"resource", "reason":"composition resource envelope exceeded", "totals":{"max_inputs":total_inputs,"max_outputs":total_outputs,"max_witness_bytes":total_witness_bytes}, "limits":{"max_inputs":64,"max_outputs":64,"max_witness_bytes":64 * 1024 * 1024}}));
    }
    entries.sort_by_key(|left| left.to_string());
    let composition_root = sha256_value(&json!(entries))?;
    conflicts.sort_by_key(|left| left.to_string());
    let status = if conflicts.is_empty() {
        "COMPATIBLE"
    } else {
        "UNRESOLVED_CONFLICT"
    };
    emit_result_status(
        "ktape profile compose",
        None,
        if conflicts.is_empty() {
            "PASS"
        } else {
            "BLOCKED"
        },
        json!({"schema":"KTAPEOUT-PROFILE-COMPOSITION-V1", "status":status, "profiles":entries, "conflicts":conflicts, "resource_totals":{"max_inputs":total_inputs,"max_outputs":total_outputs,"max_witness_bytes":total_witness_bytes}, "composition_root":composition_root, "signing_allowed":false, "broadcast":false}),
    )
}

fn profile_lock(
    path: PathBuf,
    network_policy_id: String,
    created_at: String,
) -> Result<(), String> {
    let value = profile_lock_value(path, network_policy_id, created_at)?;
    emit_result(
        "ktape profile lock",
        None,
        json!({"schema":"KTAPEOUT-DEVELOPER-LOCK-V1", "lock":value, "signing_allowed":false, "broadcast":false}),
    )
}

fn application_lock_v2_result(lock: Value, caller_supplied_dependency_root: bool) -> Value {
    json!({
        "status":"APPLICATION_LOCK_V2_CREATED",
        "authority":"TOOLING_ONLY",
        "reproducibility_root_materials_verified":false,
        "reproducibility_root_verification":"DIGEST_FORMAT_AND_LOCK_BINDING_ONLY",
        "dependency_root_source":if caller_supplied_dependency_root { "CALLER_SUPPLIED_UNVERIFIED" } else { "DERIVED_FROM_VERIFIED_PACKAGE_SET" },
        "next_action":"Verify each runtime/compiler/adapter/ABI/vector/package-registry digest against its committed source manifest before claiming reproducibility.",
        "lock":lock,
        "signing_allowed":false,
        "broadcast":false
    })
}

// These CLI values map one-to-one to the ApplicationLock V2 fields.
#[allow(clippy::too_many_arguments)]
fn profile_application_lock_v2(
    recipe_path: PathBuf,
    package_dirs: Vec<PathBuf>,
    network_policy_id: String,
    created_at: String,
    runtime_digest: String,
    compiler_lock_digest: String,
    adapter_root: String,
    abi_root: String,
    vector_root: String,
    package_registry_root: String,
    dependency_root: Option<String>,
    output: Option<PathBuf>,
) -> Result<(), String> {
    let recipe = read_json(&recipe_path)?;
    let mut packages = Vec::with_capacity(package_dirs.len());
    for package_dir in package_dirs {
        let root = fs::canonicalize(&package_dir)
            .map_err(|error| format!("PROFILE_PACKAGE_PATH_ERROR:{error}"))?;
        let (metadata, _) = verify_profile_package(root.clone())?;
        packages.push(profile_governance::VerifiedProfilePackage {
            contract: read_verified_profile_json(&root, &metadata, "profile-contract.json")?,
            effect_manifest: read_verified_profile_json(&root, &metadata, "effect-manifest.json")?,
            interfaces: read_verified_profile_json(&root, &metadata, "interfaces.json")?,
            resource_envelope: read_verified_profile_json(
                &root,
                &metadata,
                "resource-envelope.json",
            )?,
            metadata,
        });
    }
    let lock = profile_governance::application_lock_v2(
        &recipe,
        &packages,
        &network_policy_id,
        &created_at,
        &runtime_digest,
        &compiler_lock_digest,
        &adapter_root,
        &abi_root,
        &vector_root,
        &package_registry_root,
        dependency_root.as_deref(),
    )?;
    let caller_supplied_dependency_root = dependency_root.is_some();
    if let Some(path) = output {
        let bytes = serde_json::to_vec_pretty(&lock)
            .map_err(|error| format!("APPLICATION_LOCK_OUTPUT_ENCODE:{error}"))?;
        atomic_write_file(
            &path,
            &[bytes, b"\n".to_vec()].concat(),
            "ktape-application-lock-v2",
        )?;
    }
    emit_result(
        "ktape profile application-lock-v2",
        None,
        application_lock_v2_result(lock, caller_supplied_dependency_root),
    )
}

fn profile_lock_value(
    path: PathBuf,
    network_policy_id: String,
    created_at: String,
) -> Result<Value, String> {
    let (metadata, _) = verify_profile_package(path)?;
    let object = metadata
        .as_object()
        .ok_or_else(|| "PROFILE_PACKAGE_NOT_OBJECT".to_string())?;
    let profile_id = object
        .get("profile_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "PROFILE_PACKAGE_ID_INVALID".to_string())?;
    let profile_hash = object
        .get("profile_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| "PROFILE_PACKAGE_HASH_INVALID".to_string())?;
    let package_digest = object
        .get("package_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| "PROFILE_PACKAGE_DIGEST_INVALID".to_string())?;
    let runtime_digest = object
        .get("runtime_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| "PROFILE_PACKAGE_RUNTIME_INVALID".to_string())?;
    let compiler_lock_digest = object
        .get("compiler_lock_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| "PROFILE_PACKAGE_COMPILER_LOCK_INVALID".to_string())?;
    let vector_root = object
        .get("vector_root")
        .and_then(Value::as_str)
        .ok_or_else(|| "PROFILE_PACKAGE_VECTOR_ROOT_INVALID".to_string())?;
    let provenance = json!({"publisher_id":object.get("publisher_id"), "source_ref":object.get("source_ref"), "license_ref":object.get("license_ref"), "trust_tier":object.get("trust_tier")});
    let mut lock = serde_json::Map::new();
    lock.insert("schema".into(), json!(ktapeout_runtime::LOCK_SCHEMA));
    lock.insert("protocol_semver".into(), json!(PROTOCOL));
    lock.insert("core_version".into(), json!(PROTOCOL));
    lock.insert("feature_set_root".into(), json!(profile_hash));
    lock.insert("composition_root".into(), json!(package_digest));
    lock.insert(
        "dependency_root".into(),
        json!(object
            .get("dependency_manifest_hash")
            .and_then(Value::as_str)
            .unwrap_or(compiler_lock_digest)),
    );
    lock.insert("runtime_digest".into(), json!(runtime_digest));
    lock.insert("compiler_lock_digest".into(), json!(compiler_lock_digest));
    lock.insert("adapter_hash".into(), json!("0".repeat(64)));
    lock.insert(
        "abi_version".into(),
        json!(object
            .get("abi_version")
            .and_then(Value::as_str)
            .unwrap_or("KTAPEOUT-0.5.0")),
    );
    lock.insert("vector_root".into(), json!(vector_root));
    lock.insert("network_policy_id".into(), json!(network_policy_id));
    lock.insert("created_at".into(), json!(created_at));
    lock.insert("profiles".into(), json!([{"profile_id":profile_id, "profile_hash":profile_hash, "package_digest":package_digest, "admission_level":object.get("admission_level"), "package_provenance":provenance}]));
    lock.insert("lock_hash".into(), json!("0".repeat(64)));
    let hash = ktapeout_runtime::lock_hash(&lock)?;
    lock.insert("lock_hash".into(), json!(hash));
    let value = Value::Object(lock);
    ktapeout_runtime::validate_developer_lock(&value)?;
    Ok(value)
}

fn release_delta(
    old_path: PathBuf,
    new_path: PathBuf,
) -> Result<(Value, Value, Vec<String>), String> {
    let (old_metadata, _) = verify_profile_package(old_path)?;
    let (new_metadata, _) = verify_profile_package(new_path)?;
    let old = old_metadata
        .as_object()
        .ok_or_else(|| "PROFILE_PACKAGE_NOT_OBJECT".to_string())?;
    let new = new_metadata
        .as_object()
        .ok_or_else(|| "PROFILE_PACKAGE_NOT_OBJECT".to_string())?;
    let fields = [
        "profile_id",
        "profile_semver",
        "profile_hash",
        "package_digest",
        "runtime_digest",
        "compiler_lock_digest",
        "vector_root",
        "resource_envelope_digest",
    ];
    let changed = fields
        .iter()
        .filter(|field| old.get(**field) != new.get(**field))
        .map(|field| (*field).to_string())
        .collect();
    Ok((
        Value::Object(old.clone()),
        Value::Object(new.clone()),
        changed,
    ))
}

fn release_compare(old_path: PathBuf, new_path: PathBuf) -> Result<(), String> {
    let (old, new, changed) = release_delta(old_path, new_path)?;
    let old_id = old
        .get("profile_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let new_id = new
        .get("profile_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let classification = if old_id != new_id {
        "REPLACEMENT"
    } else if changed.is_empty() {
        "IDENTICAL"
    } else if old.get("profile_hash") == new.get("profile_hash") {
        "PACKAGE_ONLY"
    } else {
        "SEMANTIC_CHANGE"
    };
    emit_result(
        "ktape release compare",
        None,
        json!({"schema":"KTAPEOUT-0.5.0-RELEASE-COMPARE-V1", "classification":classification, "changed_fields":changed, "old":{"profile_id":old.get("profile_id"),"profile_semver":old.get("profile_semver"),"profile_hash":old.get("profile_hash"),"package_digest":old.get("package_digest")}, "new":{"profile_id":new.get("profile_id"),"profile_semver":new.get("profile_semver"),"profile_hash":new.get("profile_hash"),"package_digest":new.get("package_digest")}, "signing_allowed":false, "broadcast":false}),
    )
}

fn release_migration_plan(old_path: PathBuf, new_path: PathBuf) -> Result<(), String> {
    let (old, new, changed) = release_delta(old_path, new_path)?;
    let old_id = old
        .get("profile_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let new_id = new
        .get("profile_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let profile_changed = old.get("profile_hash") != new.get("profile_hash");
    let requires_migration = old_id == new_id && profile_changed;
    let status = if old_id != new_id || requires_migration {
        "REVIEW_REQUIRED"
    } else if changed.is_empty() {
        "IDENTICAL"
    } else {
        "NO_STATE_MIGRATION"
    };
    let next_action = if old_id != new_id {
        "register a separate Application/Release"
    } else if requires_migration {
        "provide a bounded migration artifact and verify it before signing"
    } else if changed.is_empty() {
        "no release action"
    } else {
        "create a new immutable Release and rebuild the Developer Lock"
    };
    emit_result_status(
        "ktape release migration-plan",
        None,
        if status == "REVIEW_REQUIRED" {
            "BLOCKED"
        } else {
            "PASS"
        },
        json!({"schema":"KTAPEOUT-0.5.0-RELEASE-MIGRATION-PLAN-V1", "status":status, "requires_migration":requires_migration, "changed_fields":changed, "next_action":next_action, "signable":false, "signing_allowed":false, "broadcast":false}),
    )
}

fn release_maintenance_status(plan_path: PathBuf, state_path: PathBuf) -> Result<(), String> {
    let plan = read_json(&plan_path)?;
    maintenance::verify(&plan)?;
    let state = read_operation_state(&state_path)?;
    let operation_id = state["operation_id"].as_str().unwrap_or_default();
    let plan_hash = state["plan_hash"].as_str().unwrap_or_default();
    let network = state["network"].as_str().unwrap_or_default();
    let binding_matches = operation_id == plan["operation_id"].as_str().unwrap_or_default()
        && plan_hash == plan["plan_hash"].as_str().unwrap_or_default()
        && network == plan["network"].as_str().unwrap_or_default();
    emit_result_status(
        "ktape release maintenance-status",
        Some(network),
        if binding_matches { "PASS" } else { "BLOCKED" },
        json!({
            "schema":"KTAPEOUT-APPLICATION-MAINTENANCE-STATUS-V1",
            "plan_hash":plan["plan_hash"],
            "operation_id":operation_id,
            "network":network,
            "stage":state["stage"],
            "next_allowed_action":state["next_allowed_action"],
            "binding_matches":binding_matches,
            "signing_allowed":false,
            "broadcast":false,
            "next_action":if binding_matches { "use read-only operation recovery or the existing external adapter" } else { "rebuild from the current plan and OperationState" }
        }),
    )
}

fn release_maintenance_recover(
    plan_path: PathBuf,
    state_path: PathBuf,
    project_lock_hash: String,
    now: String,
) -> Result<(), String> {
    let plan = read_json(&plan_path)?;
    maintenance::verify(&plan)?;
    if !valid_hash(&project_lock_hash) {
        return Err("MAINTENANCE_PROJECT_LOCK_HASH_INVALID".into());
    }
    let state = read_operation_state(&state_path)?;
    if state["operation_id"] != plan["operation_id"]
        || state["plan_hash"] != plan["plan_hash"]
        || state["network"] != plan["network"]
    {
        return emit_result_status(
            "ktape release maintenance-recover",
            plan["network"].as_str(),
            "BLOCKED",
            json!({"schema":"KTAPEOUT-APPLICATION-MAINTENANCE-RECOVERY-V1","reason_code":"MAINTENANCE_PLAN_OPERATION_BINDING_MISMATCH","plan_hash":plan["plan_hash"],"automatic_retry_allowed":false,"automatic_signing_allowed":false,"automatic_broadcast_allowed":false}),
        );
    }
    operation_recovery_with_command(
        state_path,
        plan["operation_id"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        project_lock_hash,
        plan["plan_hash"].as_str().unwrap_or_default().to_string(),
        plan["network"].as_str().unwrap_or_default().to_string(),
        now,
        "ktape release maintenance-recover",
    )
}

fn semantic_descriptor(path: &PathBuf) -> Result<Value, String> {
    let root =
        fs::canonicalize(path).map_err(|error| format!("PROFILE_PACKAGE_PATH_ERROR:{error}"))?;
    read_json(&root.join("profile.json"))
}

fn semver(value: &str) -> Result<(u64, u64, u64), String> {
    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() != 3 {
        return Err("PROFILE_UPGRADE_VERSION_INVALID".into());
    }
    let parsed: Result<Vec<u64>, _> = parts.iter().map(|part| part.parse::<u64>()).collect();
    let parsed = parsed.map_err(|_| "PROFILE_UPGRADE_VERSION_INVALID".to_string())?;
    Ok((parsed[0], parsed[1], parsed[2]))
}

fn profile_upgrade_plan(old_path: PathBuf, new_path: PathBuf) -> Result<(), String> {
    let (old_metadata, _) = verify_profile_package(old_path.clone())?;
    let (new_metadata, _) = verify_profile_package(new_path.clone())?;
    let old = old_metadata
        .as_object()
        .ok_or_else(|| "PROFILE_PACKAGE_NOT_OBJECT".to_string())?;
    let new = new_metadata
        .as_object()
        .ok_or_else(|| "PROFILE_PACKAGE_NOT_OBJECT".to_string())?;
    let old_id = old
        .get("profile_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let new_id = new
        .get("profile_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let mut changed = Vec::<String>::new();
    let governance_changed = old.get("contract_hash") != new.get("contract_hash")
        || old.get("effect_hash") != new.get("effect_hash");
    let (classification, status, requires_migration, signable, reason, next_action) = if old_id
        != new_id
    {
        (
            "REPLACEMENT",
            "REVIEW_REQUIRED",
            false,
            false,
            "profile identity changed; this is a new application/profile, not an in-place upgrade",
            "register a separate Application/Release; do not mutate or migrate the old identity implicitly",
        )
    } else if old.get("profile_hash") == new.get("profile_hash") {
        if old.get("package_digest") == new.get("package_digest") {
            return Err("PROFILE_UPGRADE_IDENTICAL_PACKAGES".into());
        }
        if governance_changed {
            (
                "CONTRACT_CHANGE",
                "REVIEW_REQUIRED",
                false,
                false,
                "profile descriptor is unchanged but the publisher-bound Contract/effect commitment changed; create a new Release binding",
                "create a new immutable Release binding; do not reinterpret the old Release or claim a state migration",
            )
        } else {
            (
                "DOCUMENTATION_ONLY",
                "VALID",
                false,
                false,
                "profile descriptor and governance commitments are unchanged; package/UI/documentation changed only",
                "refresh local package metadata; retain existing Release and lock compatibility",
            )
        }
    } else {
        let old_version = semver(
            old.get("profile_semver")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        )?;
        let new_version = semver(
            new.get("profile_semver")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        )?;
        if new_version <= old_version {
            return Err("PROFILE_UPGRADE_VERSION_NOT_GREATER".into());
        }
        let old_descriptor = semantic_descriptor(&old_path)?;
        let new_descriptor = semantic_descriptor(&new_path)?;
        let old_object = old_descriptor
            .as_object()
            .ok_or_else(|| "PROFILE_DESCRIPTOR_NOT_OBJECT".to_string())?;
        let new_object = new_descriptor
            .as_object()
            .ok_or_else(|| "PROFILE_DESCRIPTOR_NOT_OBJECT".to_string())?;
        let fields = [
            "state_encoding_hash",
            "transition_equation_hash",
            "invariant_hash",
            "input_shape_hash",
            "output_shape_hash",
            "lowering_template_hash",
            "selector_binding_hash",
            "predecessor_state_binding_hash",
            "dependency_manifest_hash",
            "exit_policy_hash",
            "capability_policy_hash",
        ];
        for field in fields {
            let old_value = old_object
                .get(field)
                .ok_or_else(|| format!("PROFILE_UPGRADE_DESCRIPTOR_FIELD_MISSING:{field}"))?;
            let new_value = new_object
                .get(field)
                .ok_or_else(|| format!("PROFILE_UPGRADE_DESCRIPTOR_FIELD_MISSING:{field}"))?;
            if old_value != new_value {
                changed.push(field.to_string());
            }
        }
        if changed.is_empty() {
            (
                "PATCH_COMPATIBLE",
                "VALID",
                false,
                true,
                "descriptor changed without changing declared state-transition compatibility fields",
                "create a new immutable Release, rebuild the lock and run static/network preflight",
            )
        } else {
            (
                "STATE_MIGRATION",
                "REVIEW_REQUIRED",
                true,
                false,
                "one or more state, transition, capability, dependency or exit commitments changed",
                "write and verify a bounded migration artifact before any signer request",
            )
        }
    };
    let mut plan = json!({"schema":"KTAPEOUT-PROFILE-UPGRADE-PLAN-V1", "protocol_semver":PROTOCOL, "status":status, "classification":classification,
        "old":{"profile_id":old.get("profile_id"), "profile_semver":old.get("profile_semver"), "profile_hash":old.get("profile_hash"), "package_digest":old.get("package_digest")},
        "new":{"profile_id":new.get("profile_id"), "profile_semver":new.get("profile_semver"), "profile_hash":new.get("profile_hash"), "package_digest":new.get("package_digest")},
        "old_governance":{"contract_hash":old.get("contract_hash").cloned().unwrap_or(Value::Null),"effect_hash":old.get("effect_hash").cloned().unwrap_or(Value::Null)},
        "new_governance":{"contract_hash":new.get("contract_hash").cloned().unwrap_or(Value::Null),"effect_hash":new.get("effect_hash").cloned().unwrap_or(Value::Null)},
        "governance_changed":governance_changed, "changed_semantic_fields":changed, "requires_new_release":matches!(classification, "PATCH_COMPATIBLE" | "CONTRACT_CHANGE" | "STATE_MIGRATION" | "REPLACEMENT"), "requires_state_migration":requires_migration,
        "signable_without_migration":signable, "reason":reason, "next_action":next_action});
    let plan_hash = digest_bytes(
        &canonical_json(&plan)?,
        "KTAPEOUT/0.5.0/PROFILE_UPGRADE_PLAN/V1",
    );
    plan.as_object_mut()
        .ok_or_else(|| "PROFILE_UPGRADE_PLAN_OBJECT_INVALID".to_string())?
        .insert("plan_hash".into(), Value::String(plan_hash));
    emit_result("ktape profile upgrade-plan", None, plan)
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .chars()
            .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
}

fn valid_outpoint(value: &str) -> bool {
    let Some((txid, index)) = value.split_once(':') else {
        return false;
    };
    valid_hash(txid) && !index.is_empty() && index.bytes().all(|byte| byte.is_ascii_digit())
}

fn digest_json_domain(value: &Value, domain: &str) -> Result<String, String> {
    Ok(digest_bytes(&canonical_json(value)?, domain))
}

fn runtime_digest_list(
    value: &Value,
    field: &str,
) -> Result<std::collections::BTreeSet<String>, String> {
    let values = value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("RUNTIME_{field}_INVALID"))?;
    if values.len() > 128 {
        return Err(format!("RUNTIME_{field}_INVALID"));
    }
    let mut result = std::collections::BTreeSet::new();
    for item in values {
        let digest = item
            .as_str()
            .ok_or_else(|| format!("RUNTIME_{field}_INVALID"))?;
        if !valid_hash(digest) || !result.insert(digest.to_string()) {
            return Err(format!("RUNTIME_{field}_INVALID"));
        }
    }
    Ok(result)
}

fn validate_runtime_value(value: &Value) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or_else(|| "RUNTIME_RELEASE_NOT_OBJECT".to_string())?;
    let required = [
        "schema",
        "protocol_semver",
        "runtime_id",
        "runtime_digest",
        "compiler_lock_digest",
        "core_version",
        "compatibility_mode",
        "read_compatible_digests",
        "build_compatible_digests",
        "plan_compatible_digests",
        "operator_compatible_digests",
        "release_status",
    ];
    if object.len() != required.len() || required.iter().any(|field| !object.contains_key(*field)) {
        return Err("RUNTIME_RELEASE_FIELD_SET_INVALID".into());
    }
    if object.get("schema").and_then(Value::as_str) != Some("KTAPEOUT-RUNTIME-RELEASE-V1")
        || object.get("protocol_semver").and_then(Value::as_str) != Some(PROTOCOL)
    {
        return Err("RUNTIME_RELEASE_IDENTITY_INVALID".into());
    }
    for field in ["runtime_digest", "compiler_lock_digest", "core_version"] {
        if !valid_hash(
            object
                .get(field)
                .and_then(Value::as_str)
                .unwrap_or_default(),
        ) {
            return Err(format!("RUNTIME_HASH_INVALID:{field}"));
        }
    }
    if object
        .get("runtime_id")
        .and_then(Value::as_str)
        .is_none_or(|value| value.is_empty() || value.len() > 128)
    {
        return Err("RUNTIME_ID_INVALID".into());
    }
    if !matches!(
        object.get("compatibility_mode").and_then(Value::as_str),
        Some("STRICT") | Some("READ_COMPATIBLE")
    ) {
        return Err("RUNTIME_COMPATIBILITY_MODE_INVALID".into());
    }
    if !matches!(
        object.get("release_status").and_then(Value::as_str),
        Some("REFERENCE") | Some("TESTNET") | Some("PRODUCTION_CANDIDATE")
    ) {
        return Err("RUNTIME_RELEASE_STATUS_INVALID".into());
    }
    let read = runtime_digest_list(value, "read_compatible_digests")?;
    let build = runtime_digest_list(value, "build_compatible_digests")?;
    let plan = runtime_digest_list(value, "plan_compatible_digests")?;
    let operator = runtime_digest_list(value, "operator_compatible_digests")?;
    let current = object
        .get("runtime_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| "RUNTIME_CURRENT_DIGEST_INVALID".to_string())?;
    if read.contains(current)
        || build.contains(current)
        || plan.contains(current)
        || operator.contains(current)
    {
        return Err("RUNTIME_CURRENT_DIGEST_LISTED".into());
    }
    if !build.is_subset(&read) {
        return Err("RUNTIME_BUILD_NOT_READ_COMPATIBLE".into());
    }
    if !plan.is_subset(&build) {
        return Err("RUNTIME_PLAN_NOT_BUILD_COMPATIBLE".into());
    }
    if !operator.is_subset(&read) {
        return Err("RUNTIME_OPERATOR_NOT_READ_COMPATIBLE".into());
    }
    Ok(())
}

fn runtime_descriptor_verify(
    descriptor_path: PathBuf,
    package_path: PathBuf,
) -> Result<(), String> {
    let descriptor = read_json(&descriptor_path)?;
    let package = read_json(&package_path)?;
    let package_binding = runtime_descriptor::verify_package_binding(&package, &descriptor)?;
    emit_result(
        "ktape runtime descriptor-verify",
        None,
        json!({"schema":"KTAPEOUT-RUNTIME-DESCRIPTOR-RESULT-V1","descriptor_hash":descriptor["descriptor_hash"],"package_binding":package_binding,"execution_started":false,"signing_allowed":false,"broadcast":false}),
    )
}

fn runtime_replay(bundle_path: PathBuf, runtime_path: PathBuf) -> Result<(), String> {
    let bundle = read_json(&bundle_path)?;
    let runtime = read_json(&runtime_path)?;
    validate_runtime_value(&runtime)?;
    let bundle_object = bundle
        .as_object()
        .ok_or_else(|| "REPLAY_BUNDLE_NOT_OBJECT".to_string())?;
    let required = [
        "schema",
        "protocol_semver",
        "bundle_id",
        "lock_hash",
        "runtime_digest",
        "plan_hash",
        "evidence_hash",
        "network",
        "unsigned",
    ];
    if bundle_object.len() != required.len()
        || required
            .iter()
            .any(|field| !bundle_object.contains_key(*field))
    {
        return Err("REPLAY_BUNDLE_FIELD_SET_INVALID".into());
    }
    if bundle_object.get("schema").and_then(Value::as_str)
        != Some("KTAPEOUT-OFFLINE-REPLAY-BUNDLE-V1")
        || bundle_object.get("protocol_semver").and_then(Value::as_str) != Some(PROTOCOL)
    {
        return Err("REPLAY_BUNDLE_IDENTITY_INVALID".into());
    }
    for field in [
        "bundle_id",
        "lock_hash",
        "runtime_digest",
        "plan_hash",
        "evidence_hash",
    ] {
        if !valid_hash(
            bundle_object
                .get(field)
                .and_then(Value::as_str)
                .unwrap_or_default(),
        ) {
            return Err(format!("REPLAY_BUNDLE_HASH_INVALID:{field}"));
        }
    }
    if !matches!(
        bundle_object.get("network").and_then(Value::as_str),
        Some("testnet-10") | Some("mainnet")
    ) || bundle_object.get("unsigned").and_then(Value::as_bool) != Some(true)
    {
        return Err("REPLAY_BUNDLE_NETWORK_OR_SIGNING_INVALID".into());
    }
    let mut material = bundle.clone();
    material
        .as_object_mut()
        .ok_or_else(|| "REPLAY_BUNDLE_OBJECT_INVALID".to_string())?
        .insert("bundle_id".into(), Value::String("0".repeat(64)));
    if digest_json_domain(&material, "KTAPEOUT/0.5.0/OFFLINE_REPLAY_BUNDLE/V1")?
        != bundle_object
            .get("bundle_id")
            .and_then(Value::as_str)
            .ok_or_else(|| "REPLAY_BUNDLE_ID_INVALID".to_string())?
    {
        return Err("REPLAY_BUNDLE_ID_MISMATCH".into());
    }
    let runtime_object = runtime
        .as_object()
        .ok_or_else(|| "RUNTIME_DESCRIPTOR_INVALID".to_string())?;
    let old = bundle_object
        .get("runtime_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| "REPLAY_BUNDLE_RUNTIME_DIGEST_INVALID".to_string())?;
    let current = runtime_object
        .get("runtime_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| "RUNTIME_CURRENT_DIGEST_INVALID".to_string())?;
    let read = runtime_digest_list(&runtime, "read_compatible_digests")?;
    let build = runtime_digest_list(&runtime, "build_compatible_digests")?;
    let plan = runtime_digest_list(&runtime, "plan_compatible_digests")?;
    let operator = runtime_digest_list(&runtime, "operator_compatible_digests")?;
    let exact = old == current;
    let (mode, status, next_action) = if exact {
        (
            "EXACT",
            "REPLAYABLE",
            "retain the verified historical evidence",
        )
    } else if plan.contains(old) {
        (
            "PLAN_COMPATIBLE",
            "PLAN_REBUILDABLE",
            "regenerate the unsigned plan with the current Runtime before any sign or publish operation",
        )
    } else if build.contains(old) {
        (
            "BUILD_COMPATIBLE",
            "BUILD_VERIFIED",
            "rebuild the artifact and plan with the current Runtime before any sign or publish operation",
        )
    } else if read.contains(old) {
        (
            "READ_COMPATIBLE",
            "READ_VERIFIED",
            "rebuild with the current Runtime before any new sign or publish operation",
        )
    } else {
        (
            "INCOMPATIBLE",
            "REBUILD_REQUIRED",
            "resolve a compatible Runtime and rebuild the unsigned plan",
        )
    };
    emit_result(
        "ktape runtime replay",
        bundle_object.get("network").and_then(Value::as_str),
        json!({"schema":"KTAPEOUT-OFFLINE-REPLAY-RESULT-V1", "protocol_semver":PROTOCOL, "status":status, "mode":mode, "bundle_id":bundle_object.get("bundle_id"), "historical_runtime_digest":old, "current_runtime_digest":current, "network":bundle_object.get("network"), "read_compatible":exact || read.contains(old), "build_compatible":exact || build.contains(old), "plan_compatible":exact || plan.contains(old), "operator_compatible":exact || operator.contains(old), "l1_evidence":false, "signing_allowed":false, "next_action":next_action}),
    )
}

fn operation_stages() -> [&'static str; 8] {
    [
        "PLANNED",
        "SIGNED",
        "SUBMITTED",
        "SUBMISSION_UNKNOWN",
        "CONFIRMED",
        "REJECTED",
        "REORGED",
        "RECOVERY_REQUIRED",
    ]
}

fn valid_operation_value(value: &Value) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or_else(|| "OPERATION_NOT_OBJECT".to_string())?;
    let required = [
        "schema",
        "protocol_semver",
        "operation_id",
        "request_id",
        "project_lock_hash",
        "plan_hash",
        "network",
        "stage",
        "attempt_count",
        "expiry",
        "last_observed_tip",
        "evidence_refs",
        "next_allowed_action",
    ];
    if object.len() != required.len() || required.iter().any(|field| !object.contains_key(*field)) {
        return Err("OPERATION_FIELD_SET_INVALID".into());
    }
    if object.get("schema").and_then(Value::as_str) != Some("KTAPEOUT-OPERATION-STATE-V1")
        || object.get("protocol_semver").and_then(Value::as_str) != Some(PROTOCOL)
    {
        return Err("OPERATION_IDENTITY_INVALID".into());
    }
    let operation_id = object
        .get("operation_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !ktapeout_runtime::valid_operation_id(operation_id) {
        return Err("OPERATION_ID_INVALID".into());
    }
    if !matches!(
        object.get("network").and_then(Value::as_str),
        Some("testnet-10") | Some("mainnet")
    ) || !object
        .get("stage")
        .and_then(Value::as_str)
        .is_some_and(|stage| operation_stages().contains(&stage))
    {
        return Err("OPERATION_NETWORK_OR_STAGE_INVALID".into());
    }
    for field in ["project_lock_hash", "plan_hash"] {
        if !valid_hash(
            object
                .get(field)
                .and_then(Value::as_str)
                .unwrap_or_default(),
        ) {
            return Err(format!("OPERATION_HASH_INVALID:{field}"));
        }
    }
    if object
        .get("request_id")
        .and_then(Value::as_str)
        .is_none_or(|request| request.is_empty() || request.len() > 128)
        || object
            .get("expiry")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || object
            .get("next_allowed_action")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    {
        return Err("OPERATION_TEXT_INVALID".into());
    }
    if ktapeout_runtime::compare_utc_timestamps(
        object
            .get("expiry")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        object
            .get("expiry")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    )
    .is_none()
    {
        return Err("OPERATION_EXPIRY_INVALID".into());
    }
    if object
        .get("attempt_count")
        .and_then(Value::as_u64)
        .is_none_or(|count| count > 100)
    {
        return Err("OPERATION_ATTEMPT_COUNT_INVALID".into());
    }
    if let Some(tip) = object.get("last_observed_tip").and_then(Value::as_str) {
        if !valid_hash(tip) {
            return Err("OPERATION_TIP_INVALID".into());
        }
    }
    if object
        .get("evidence_refs")
        .and_then(Value::as_array)
        .is_none_or(|refs| {
            refs.iter()
                .any(|item| item.as_str().is_none_or(str::is_empty))
        })
    {
        return Err("OPERATION_EVIDENCE_REFS_INVALID".into());
    }
    Ok(())
}

fn read_operation_state(path: &Path) -> Result<Value, String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("OPERATION_READ_ERROR:{error}"))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err("OPERATION_STATE_MUST_BE_REGULAR_FILE".into());
    }
    let value = read_json(path)?;
    valid_operation_value(&value)?;
    Ok(value)
}

fn operation_lock_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("operation.json");
    path.with_file_name(format!("{name}.lock"))
}

struct OperationWriteLock {
    path: PathBuf,
    metadata: Vec<u8>,
}

impl Drop for OperationWriteLock {
    fn drop(&mut self) {
        if fs::read(&self.path).ok().as_deref() == Some(self.metadata.as_slice()) {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn acquire_operation_lock(path: &Path) -> Result<OperationWriteLock, String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| format!("OPERATION_LOCK_ERROR:{error}"))?;
    }
    let lock_path = operation_lock_path(path);
    let mut lock = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock_path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                "OPERATION_STATE_WRITER_LOCK_HELD".to_string()
            } else {
                format!("OPERATION_LOCK_ERROR:{error}")
            }
        })?;
    let metadata = format!(
        "{{\"schema\":\"KTAPEOUT-OPERATION-WRITER-LOCK-V1\",\"pid\":{},\"created_at_ns\":{}}}\n",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |value| value.as_nanos())
    )
    .into_bytes();
    if let Err(error) = lock.write_all(&metadata).and_then(|_| lock.sync_all()) {
        let _ = fs::remove_file(&lock_path);
        return Err(format!("OPERATION_LOCK_ERROR:{error}"));
    }
    Ok(OperationWriteLock {
        path: lock_path,
        metadata,
    })
}

fn atomic_replace_file(temp: &Path, target: &Path) -> Result<(), String> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        #[link(name = "kernel32")]
        extern "system" {
            fn MoveFileExW(from: *const u16, to: *const u16, flags: u32) -> i32;
        }
        let from: Vec<u16> = temp.as_os_str().encode_wide().chain(Some(0)).collect();
        let to: Vec<u16> = target.as_os_str().encode_wide().chain(Some(0)).collect();
        if unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), 9) } == 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        fs::rename(temp, target).map_err(|error| error.to_string())
    }
}

fn atomic_write_file(path: &Path, payload: &[u8], prefix: &str) -> Result<(), String> {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("state.json");
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |value| value.as_nanos());
    let temp = path.with_file_name(format!(".{name}.{}-{nonce}.tmp", std::process::id()));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp)
        .map_err(|error| format!("{prefix}:{error}"))?;
    if let Err(error) = file.write_all(payload).and_then(|_| file.sync_all()) {
        let _ = fs::remove_file(&temp);
        return Err(format!("{prefix}:{error}"));
    }
    if let Err(error) = atomic_replace_file(&temp, path) {
        let _ = fs::remove_file(&temp);
        return Err(format!("{prefix}:{error}"));
    }
    Ok(())
}

fn write_operation_state_unlocked(path: &PathBuf, value: &Value) -> Result<(), String> {
    valid_operation_value(value)?;
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            return Err("OPERATION_STATE_MUST_BE_REGULAR_FILE".into());
        }
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| format!("OPERATION_WRITE_ERROR:{error}"))?;
    }
    let payload = serde_json::to_string_pretty(value).map_err(|error| error.to_string())? + "\n";
    atomic_write_file(path, payload.as_bytes(), "OPERATION_WRITE_ERROR")
}

fn write_operation_state(path: &PathBuf, value: &Value) -> Result<(), String> {
    let _lock = acquire_operation_lock(path)?;
    write_operation_state_unlocked(path, value)
}

// The arguments are the operation-state schema fields accepted by this CLI command.
#[allow(clippy::too_many_arguments)]
fn operation_init(
    operation_id: String,
    request_id: String,
    project_lock_hash: String,
    plan_hash: String,
    network: String,
    expiry: String,
    output: PathBuf,
    evidence_refs: Vec<String>,
) -> Result<(), String> {
    let value = json!({"schema":"KTAPEOUT-OPERATION-STATE-V1", "protocol_semver":PROTOCOL, "operation_id":operation_id, "request_id":request_id, "project_lock_hash":project_lock_hash, "plan_hash":plan_hash, "network":network, "stage":"PLANNED", "attempt_count":0, "expiry":expiry, "last_observed_tip":Value::Null, "evidence_refs":evidence_refs, "next_allowed_action":"preflight"});
    valid_operation_value(&value)?;
    write_operation_state(&output, &value)?;
    let network_ref = value
        .get("network")
        .and_then(Value::as_str)
        .map(str::to_string);
    emit_result("ktape operation init", network_ref.as_deref(), value)
}

fn operation_inspect(path: PathBuf) -> Result<(), String> {
    let value = read_operation_state(&path)?;
    valid_operation_value(&value)?;
    let network_ref = value
        .get("network")
        .and_then(Value::as_str)
        .map(str::to_string);
    emit_result("ktape operation inspect", network_ref.as_deref(), value)
}

fn operation_recovery_with_command(
    path: PathBuf,
    expected_operation_id: String,
    expected_project_lock_hash: String,
    expected_plan_hash: String,
    expected_network: String,
    now: String,
    command: &str,
) -> Result<(), String> {
    let value = read_operation_state(&path)?;
    let expiry = value
        .get("expiry")
        .and_then(Value::as_str)
        .ok_or_else(|| "OPERATION_EXPIRY_INVALID".to_string())?;
    let time_order = ktapeout_runtime::compare_utc_timestamps(&now, expiry)
        .ok_or_else(|| "OPERATION_RECOVERY_TIMESTAMP_INVALID".to_string())?;
    let operation_id = value
        .get("operation_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let project_lock_hash = value
        .get("project_lock_hash")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let plan_hash = value
        .get("plan_hash")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let network = value
        .get("network")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let stage = value
        .get("stage")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let binding_matches = operation_id == expected_operation_id
        && project_lock_hash == expected_project_lock_hash
        && plan_hash == expected_plan_hash
        && network == expected_network;
    let (status, reason_code, next_action) = if !binding_matches {
        (
            "BLOCKED",
            "OPERATION_BINDING_MISMATCH",
            "REBUILD_FROM_CURRENT_PROJECT",
        )
    } else {
        match stage {
            "PLANNED" if time_order != std::cmp::Ordering::Less => {
                ("BLOCKED", "OPERATION_EXPIRED", "REBUILD_UNSIGNED_PLAN")
            }
            "PLANNED" => ("READY", "PREFLIGHT_REQUIRED", "RUN_PREFLIGHT"),
            "SIGNED" => (
                "OPERATOR_REVIEW",
                "SIGNED_PAYLOAD_NOT_PERSISTED",
                "REVALIDATE_INTENT_WITH_OPERATOR",
            ),
            "SUBMITTED" => (
                "NEEDS_CHAIN_LOOKUP",
                "SUBMISSION_MUST_BE_RECONCILED",
                "QUERY_TRANSACTION_STATUS",
            ),
            "SUBMISSION_UNKNOWN" => (
                "NEEDS_CHAIN_LOOKUP",
                "BLIND_RETRY_FORBIDDEN",
                "QUERY_INDEPENDENT_NODES",
            ),
            "CONFIRMED" => (
                "READ_ONLY_VERIFY",
                "CONFIRMATION_REQUIRES_SUCCESSOR_CHECK",
                "VERIFY_SUCCESSOR_STATE",
            ),
            "REJECTED" => (
                "TERMINAL",
                "OPERATION_REJECTED",
                "START_NEW_OPERATION_IF_NEEDED",
            ),
            "REORGED" => (
                "RECOVERY_REQUIRED",
                "REORG_REQUIRES_RECONCILIATION",
                "RECONCILE_CHAIN_STATE",
            ),
            "RECOVERY_REQUIRED" => (
                "OPERATOR_REVIEW",
                "EXPLICIT_RECOVERY_REVIEW_REQUIRED",
                "REBUILD_UNSIGNED_PLAN_AFTER_REVIEW",
            ),
            _ => return Err("OPERATION_STAGE_INVALID".into()),
        }
    };
    emit_result(
        command,
        Some(network),
        json!({
            "schema":"KTAPEOUT-OPERATION-RECOVERY-V1", "operation_id":operation_id,
            "project_lock_hash":project_lock_hash, "plan_hash":plan_hash, "network":network,
            "stage":stage, "assessed_at":now, "status":status, "reason_code":reason_code,
            "next_action":next_action, "automatic_retry_allowed":false,
            "automatic_signing_allowed":false, "automatic_broadcast_allowed":false
        }),
    )
}

fn operation_recovery(
    path: PathBuf,
    expected_operation_id: String,
    expected_project_lock_hash: String,
    expected_plan_hash: String,
    expected_network: String,
    now: String,
) -> Result<(), String> {
    operation_recovery_with_command(
        path,
        expected_operation_id,
        expected_project_lock_hash,
        expected_plan_hash,
        expected_network,
        now,
        "ktape operation recover",
    )
}

fn operation_transition(
    path: PathBuf,
    stage: String,
    observed_tip: Option<String>,
    evidence_ref: Option<String>,
    next_action: Option<String>,
    write: bool,
) -> Result<(), String> {
    let _lock = if write {
        Some(acquire_operation_lock(&path)?)
    } else {
        None
    };
    let value = read_operation_state(&path)?;
    valid_operation_value(&value)?;
    let current = value
        .get("stage")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let allowed = match current {
        "PLANNED" => ["SIGNED", "REJECTED", "RECOVERY_REQUIRED"].as_slice(),
        "SIGNED" => ["SUBMITTED", "REJECTED", "RECOVERY_REQUIRED"].as_slice(),
        "SUBMITTED" => ["CONFIRMED", "SUBMISSION_UNKNOWN", "REJECTED", "REORGED"].as_slice(),
        "SUBMISSION_UNKNOWN" => {
            ["CONFIRMED", "REJECTED", "REORGED", "RECOVERY_REQUIRED"].as_slice()
        }
        "CONFIRMED" => ["REORGED"].as_slice(),
        "REORGED" => ["RECOVERY_REQUIRED"].as_slice(),
        "RECOVERY_REQUIRED" => ["PLANNED", "REJECTED"].as_slice(),
        _ => [].as_slice(),
    };
    if !allowed.contains(&stage.as_str()) {
        return Err(format!("OPERATION_INVALID_TRANSITION:{current}->{stage}"));
    }
    if let Some(tip) = &observed_tip {
        if !valid_hash(tip) {
            return Err("OPERATION_TIP_INVALID".into());
        }
    }
    if let Some(reference) = &evidence_ref {
        if reference.is_empty() {
            return Err("OPERATION_EVIDENCE_REF_INVALID".into());
        }
    }
    let mut updated = value;
    let object = updated
        .as_object_mut()
        .ok_or_else(|| "OPERATION_NOT_OBJECT".to_string())?;
    object.insert("stage".into(), Value::String(stage));
    let attempts = object
        .get("attempt_count")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        + 1;
    object.insert("attempt_count".into(), Value::Number(attempts.into()));
    if let Some(tip) = observed_tip {
        object.insert("last_observed_tip".into(), Value::String(tip));
    }
    if let Some(reference) = evidence_ref {
        object
            .get_mut("evidence_refs")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| "OPERATION_EVIDENCE_REFS_INVALID".to_string())?
            .push(Value::String(reference));
    }
    if let Some(action) = next_action {
        if action.is_empty() {
            return Err("OPERATION_NEXT_ACTION_INVALID".into());
        }
        object.insert("next_allowed_action".into(), Value::String(action));
    }
    valid_operation_value(&updated)?;
    if write {
        write_operation_state_unlocked(&path, &updated)?;
    }
    let network_ref = updated
        .get("network")
        .and_then(Value::as_str)
        .map(str::to_string);
    emit_result(
        "ktape operation transition",
        network_ref.as_deref(),
        updated,
    )
}

fn validate_receipt_value(value: &Value) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or_else(|| "RECEIPT_NOT_OBJECT".to_string())?;
    let required = [
        "schema",
        "protocol_semver",
        "receipt_kind",
        "operation_id",
        "plan_hash",
        "lock_hash",
        "network",
        "status",
        "evidence_origin",
        "captured_at",
        "valid_until",
        "verifier_digest",
        "facts",
    ];
    if object.len() != required.len() || required.iter().any(|field| !object.contains_key(*field)) {
        return Err("RECEIPT_FIELD_SET_INVALID".into());
    }
    if object.get("schema").and_then(Value::as_str) != Some("KTAPEOUT-RECEIPT-V1")
        || object.get("protocol_semver").and_then(Value::as_str) != Some(PROTOCOL)
    {
        return Err("RECEIPT_IDENTITY_INVALID".into());
    }
    if !matches!(
        object.get("receipt_kind").and_then(Value::as_str),
        Some("PREFLIGHT") | Some("EVIDENCE")
    ) || !ktapeout_runtime::valid_operation_id(
        object
            .get("operation_id")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    ) {
        return Err("RECEIPT_KIND_OR_OPERATION_INVALID".into());
    }
    for field in ["plan_hash", "lock_hash", "verifier_digest"] {
        if !valid_hash(
            object
                .get(field)
                .and_then(Value::as_str)
                .unwrap_or_default(),
        ) {
            return Err(format!("RECEIPT_HASH_INVALID:{field}"));
        }
    }
    let captured_at = object
        .get("captured_at")
        .and_then(Value::as_str)
        .and_then(parse_utc_timestamp);
    let valid_until = object
        .get("valid_until")
        .and_then(Value::as_str)
        .and_then(parse_utc_timestamp);
    let time_valid = match (captured_at.as_ref(), valid_until.as_ref()) {
        (Some(captured), Some(valid)) => timestamp_after(valid, captured),
        _ => false,
    };
    if !matches!(
        object.get("network").and_then(Value::as_str),
        Some("testnet-10") | Some("mainnet")
    ) || !time_valid
    {
        return Err("RECEIPT_TIME_OR_NETWORK_INVALID".into());
    }
    let status = object
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let origin = object
        .get("evidence_origin")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if ![
        "READY",
        "BLOCKED",
        "SUBMITTED",
        "CONFIRMED",
        "SUBMISSION_UNKNOWN",
        "REORGED",
        "STALE",
    ]
    .contains(&status)
        || ![
            "STATIC",
            "LOCAL_SIMULATION",
            "SHAPE_ESTIMATE",
            "FRESH_NODE_OBSERVATION",
            "AUTHORIZED_TN10_RECEIPT",
            "UNAVAILABLE",
        ]
        .contains(&origin)
    {
        return Err("RECEIPT_STATUS_ORIGIN_INVALID".into());
    }
    match object.get("receipt_kind").and_then(Value::as_str) {
        Some("PREFLIGHT") if !["READY", "BLOCKED", "STALE"].contains(&status) => {
            return Err("PREFLIGHT_STATUS_INVALID".into());
        }
        Some("EVIDENCE")
            if ![
                "SUBMITTED",
                "CONFIRMED",
                "SUBMISSION_UNKNOWN",
                "REORGED",
                "STALE",
                "BLOCKED",
            ]
            .contains(&status) =>
        {
            return Err("EVIDENCE_STATUS_INVALID".into());
        }
        _ => {}
    }
    if !object.get("facts").is_some_and(Value::is_object) {
        return Err("RECEIPT_FACTS_INVALID".into());
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct UtcTimestamp {
    calendar: (u32, u32, u32, u32, u32, u32),
    fraction: String,
}

fn parse_utc_timestamp(value: &str) -> Option<UtcTimestamp> {
    let bytes = value.as_bytes();
    if bytes.len() < 20
        || *bytes.last().unwrap_or(&0) != b'Z'
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return None;
    }
    let digit = |range: std::ops::Range<usize>| bytes[range].iter().all(u8::is_ascii_digit);
    if !digit(0..4)
        || !digit(5..7)
        || !digit(8..10)
        || !digit(11..13)
        || !digit(14..16)
        || !digit(17..19)
    {
        return None;
    }
    if bytes.len() > 20
        && (bytes[19] != b'.'
            || bytes[20..bytes.len() - 1].is_empty()
            || !bytes[20..bytes.len() - 1].iter().all(u8::is_ascii_digit))
    {
        return None;
    }
    let number = |range: std::ops::Range<usize>| -> u32 {
        std::str::from_utf8(&bytes[range])
            .ok()
            .and_then(|part| part.parse().ok())
            .unwrap_or(u32::MAX)
    };
    let year = number(0..4);
    let month = number(5..7);
    let day = number(8..10);
    let hour = number(11..13);
    let minute = number(14..16);
    let second = number(17..19);
    if !(1..=12).contains(&month) || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if day < 1 || day > days {
        return None;
    }
    let fraction = if bytes.len() > 20 {
        std::str::from_utf8(&bytes[20..bytes.len() - 1])
            .ok()?
            .trim_end_matches('0')
            .to_string()
    } else {
        String::new()
    };
    Some(UtcTimestamp {
        calendar: (year, month, day, hour, minute, second),
        fraction,
    })
}

fn timestamp_after(left: &UtcTimestamp, right: &UtcTimestamp) -> bool {
    if left.calendar != right.calendar {
        return left.calendar > right.calendar;
    }
    let width = left.fraction.len().max(right.fraction.len());
    let left_fraction = format!("{:0<width$}", left.fraction, width = width);
    let right_fraction = format!("{:0<width$}", right.fraction, width = width);
    left_fraction > right_fraction
}

fn valid_utc_timestamp(value: &str) -> bool {
    parse_utc_timestamp(value).is_some()
}

fn evidence_verify(path: PathBuf) -> Result<(), String> {
    let value = read_json(&path)?;
    validate_receipt_value(&value)?;
    let network_ref = value
        .get("network")
        .and_then(Value::as_str)
        .map(str::to_string);
    emit_result("ktape evidence verify", network_ref.as_deref(), value)
}

fn evidence_writer_verify(path: PathBuf) -> Result<(), String> {
    const FIELDS: &[&str] = &[
        "schema",
        "protocol_semver",
        "profile_id",
        "writer_id",
        "topology",
        "root_domains",
        "predecessor_field",
        "successor_field",
        "auxiliary_intents_allowed",
        "composition_conflict_key",
    ];
    let value = read_json(&path)?;
    if !exact_json_keys(&value, FIELDS)
        || value.get("schema").and_then(Value::as_str)
            != Some("KTAPEOUT-CANONICAL-WRITER-POLICY-V1")
        || value.get("protocol_semver").and_then(Value::as_str) != Some(PROTOCOL)
    {
        return Err("WRITER_POLICY_IDENTITY_OR_FIELDS_INVALID".into());
    }
    for field in [
        "profile_id",
        "writer_id",
        "predecessor_field",
        "successor_field",
    ] {
        if value
            .get(field)
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            return Err("WRITER_POLICY_IDENTIFIERS_INVALID".into());
        }
    }
    if !matches!(
        value.get("topology").and_then(Value::as_str),
        Some("SINGLE_WRITER" | "BOUNDED_WRITERS")
    ) || value
        .get("auxiliary_intents_allowed")
        .and_then(Value::as_bool)
        .is_none()
    {
        return Err("WRITER_TOPOLOGY_INVALID".into());
    }
    let domains = value
        .get("root_domains")
        .and_then(Value::as_array)
        .filter(|domains| !domains.is_empty())
        .ok_or_else(|| "WRITER_ROOT_DOMAINS_INVALID".to_string())?;
    let mut unique_domains = std::collections::HashSet::with_capacity(domains.len());
    if domains.iter().any(|domain| {
        domain
            .as_str()
            .is_none_or(|domain| !unique_domains.insert(domain))
    }) {
        return Err("WRITER_ROOT_DOMAINS_INVALID".into());
    }
    let conflict_key = value
        .get("composition_conflict_key")
        .and_then(Value::as_str)
        .ok_or_else(|| "WRITER_CONFLICT_KEY_INVALID".to_string())?;
    if !valid_hash(conflict_key) {
        return Err("WRITER_CONFLICT_KEY_INVALID".into());
    }
    emit_result("ktape evidence writer-verify", None, value)
}

fn evidence_codec_verify(path: PathBuf) -> Result<(), String> {
    const FIELDS: &[&str] = &[
        "schema",
        "protocol_semver",
        "codec_id",
        "preimage_domain",
        "fields",
        "codec_hash",
        "vector_root",
    ];
    const CODEC_FIELDS: &[&str] = &["name", "width", "order", "domain_tag"];
    let value = read_json(&path)?;
    if !exact_json_keys(&value, FIELDS)
        || value.get("schema").and_then(Value::as_str) != Some("KTAPEOUT-STATE-CODEC-MANIFEST-V1")
        || value.get("protocol_semver").and_then(Value::as_str) != Some(PROTOCOL)
    {
        return Err("STATE_CODEC_IDENTITY_OR_FIELDS_INVALID".into());
    }
    for field in ["codec_id", "preimage_domain"] {
        if value
            .get(field)
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            return Err("STATE_CODEC_IDENTITY_INVALID".into());
        }
    }
    let codec_hash = value
        .get("codec_hash")
        .and_then(Value::as_str)
        .filter(|hash| valid_hash(hash))
        .ok_or_else(|| "STATE_CODEC_HASH_INVALID".to_string())?;
    let vector_root = value
        .get("vector_root")
        .and_then(Value::as_str)
        .filter(|hash| valid_hash(hash))
        .ok_or_else(|| "STATE_CODEC_HASH_INVALID".to_string())?;
    let _ = vector_root;
    let fields = value
        .get("fields")
        .and_then(Value::as_array)
        .filter(|fields| !fields.is_empty())
        .ok_or_else(|| "STATE_CODEC_FIELDS_REQUIRED".to_string())?;
    let mut names = std::collections::HashSet::with_capacity(fields.len());
    let mut orders = Vec::with_capacity(fields.len());
    for field in fields {
        if !exact_json_keys(field, CODEC_FIELDS) {
            return Err("STATE_CODEC_FIELD_SHAPE_INVALID".into());
        }
        let name = field
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
            .ok_or_else(|| "STATE_CODEC_FIELD_INVALID".to_string())?;
        let width = field
            .get("width")
            .and_then(Value::as_u64)
            .filter(|width| *width > 0)
            .ok_or_else(|| "STATE_CODEC_FIELD_INVALID".to_string())?;
        let order = field
            .get("order")
            .and_then(Value::as_u64)
            .ok_or_else(|| "STATE_CODEC_FIELD_INVALID".to_string())?;
        if field
            .get("domain_tag")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
            || !names.insert(name)
        {
            return Err("STATE_CODEC_FIELD_INVALID".into());
        }
        let _ = width;
        orders.push(order);
    }
    orders.sort_unstable();
    if orders
        .iter()
        .enumerate()
        .any(|(expected, actual)| *actual != expected as u64)
    {
        return Err("STATE_CODEC_FIELD_ORDER_INVALID".into());
    }
    let mut material = value.clone();
    material["codec_hash"] = json!("0".repeat(64));
    let expected_hash =
        ktapeout_runtime::digest_json(&material, "KTAPEOUT/0.5.0/STATE_CODEC_MANIFEST/V1")?;
    if codec_hash != expected_hash {
        return Err("STATE_CODEC_HASH_MISMATCH".into());
    }
    emit_result("ktape evidence codec-verify", None, value)
}

fn admission_status_value_valid(value: &str) -> bool {
    matches!(
        value,
        "FROZEN"
            | "UNFROZEN"
            | "PASS"
            | "BLOCKED"
            | "UNAVAILABLE"
            | "SHAPE_ONLY"
            | "LOCAL_REPLAY"
            | "SIGNED_DIGEST_REPLAY"
            | "CONSENSUS_ACCEPTED"
            | "DUAL_RPC_CONFIRMED"
            | "RECOVERY_CONFIRMED"
            | "CANDIDATE_ONLY"
            | "PROFILE_ONLY"
            | "PRODUCTION_CANDIDATE"
            | "NOT_AUTHORIZED"
            | "RELEASED"
    )
}

fn evidence_status_derive(
    semantic: String,
    build: String,
    receipt_status: Option<String>,
    domain: String,
) -> Result<(), String> {
    for value in [&semantic, &build, &domain] {
        if !admission_status_value_valid(value) {
            return Err("ADMISSION_STATUS_VALUE_INVALID".into());
        }
    }

    let evidence = match receipt_status.as_deref() {
        Some("CONFIRMED") => "DUAL_RPC_CONFIRMED",
        Some("SUBMISSION_UNKNOWN" | "SUBMITTED") => "SIGNED_DIGEST_REPLAY",
        _ => "SHAPE_ONLY",
    };
    let released = matches!(evidence, "DUAL_RPC_CONFIRMED" | "RECOVERY_CONFIRMED");
    let data = json!({
        "schema": "KTAPEOUT-ADMISSION-STATUS-V1",
        "protocol_semver": PROTOCOL,
        "semantic": semantic,
        "build": build,
        "consensus": if released { "PASS" } else { "UNAVAILABLE" },
        "evidence": evidence,
        "domain": domain,
        "release": if released { "RELEASED" } else { "NOT_AUTHORIZED" }
    });
    emit_result("ktape evidence status-derive", None, data)
}

fn evidence_status_verify(path: PathBuf) -> Result<(), String> {
    const FIELDS: &[&str] = &[
        "schema",
        "protocol_semver",
        "semantic",
        "build",
        "consensus",
        "evidence",
        "domain",
        "release",
    ];
    let value = read_json(&path)?;
    if !exact_json_keys(&value, FIELDS)
        || value.get("schema").and_then(Value::as_str) != Some("KTAPEOUT-ADMISSION-STATUS-V1")
        || value.get("protocol_semver").and_then(Value::as_str) != Some(PROTOCOL)
    {
        return Err("ADMISSION_STATUS_VECTOR_IDENTITY_OR_FIELDS_INVALID".into());
    }
    for field in [
        "semantic",
        "build",
        "consensus",
        "evidence",
        "domain",
        "release",
    ] {
        if value
            .get(field)
            .and_then(Value::as_str)
            .is_none_or(|status| !admission_status_value_valid(status))
        {
            return Err("ADMISSION_STATUS_VALUE_INVALID".into());
        }
    }
    if value.get("release").and_then(Value::as_str) == Some("RELEASED")
        && !matches!(
            value.get("evidence").and_then(Value::as_str),
            Some("DUAL_RPC_CONFIRMED" | "RECOVERY_CONFIRMED")
        )
    {
        return Err("ADMISSION_STATUS_RELEASE_EVIDENCE_INVALID".into());
    }
    emit_result("ktape evidence status-verify", None, value)
}

fn evidence_compare(left: PathBuf, right: PathBuf) -> Result<(), String> {
    let left_value = read_json(&left)?;
    let right_value = read_json(&right)?;
    validate_receipt_value(&left_value)?;
    validate_receipt_value(&right_value)?;
    let fields = [
        "operation_id",
        "plan_hash",
        "lock_hash",
        "network",
        "verifier_digest",
    ];
    let bindings_equal = fields
        .iter()
        .all(|field| left_value.get(*field) == right_value.get(*field));
    let status_equal = left_value.get("status") == right_value.get("status");
    let result_status = evidence_compare_result_status(bindings_equal, status_equal);
    emit_result_status(
        "ktape evidence compare",
        left_value.get("network").and_then(Value::as_str),
        result_status,
        json!({
            "schema": "KTAPEOUT-0.5.0-EVIDENCE-COMPARE-V1",
            "bindings_equal": bindings_equal,
            "status_equal": status_equal,
            "left_hash": sha256_value(&left_value)?,
            "right_hash": sha256_value(&right_value)?,
            "l1_attested": false,
            "requires_external_verifier": true,
            "signing_allowed": false,
            "broadcast": false
        }),
    )
}

fn evidence_recovery_check(path: PathBuf) -> Result<(), String> {
    let value = read_json(&path)?;
    validate_receipt_value(&value)?;
    let status = value
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let next_action = match status {
        "SUBMISSION_UNKNOWN" => "perform read-only operator lookup before any retry",
        "REORGED" => "re-run fresh preflight and rebuild a new plan",
        "STALE" => "refresh predecessor and rebuild the unsigned plan",
        "CONFIRMED" => "retain evidence and independently verify successor bindings",
        "SUBMITTED" => "poll dual readback; do not duplicate-submit",
        "BLOCKED" => "resolve the recorded blocker before signing",
        _ => "receipt is not a recoverable submission state",
    };
    emit_result_status(
        "ktape evidence recovery-check",
        value.get("network").and_then(Value::as_str),
        recovery_check_result_status(status),
        json!({
            "schema": "KTAPEOUT-0.5.0-EVIDENCE-RECOVERY-CHECK-V1",
            "status": status,
            "recovery_required": status == "SUBMISSION_UNKNOWN" || status == "REORGED" || status == "STALE",
            "duplicate_submit_forbidden": true,
            "next_action": next_action,
            "l1_attested": false,
            "requires_external_verifier": true,
            "signing_allowed": false,
            "broadcast": false
        }),
    )
}

fn evidence_compare_result_status(bindings_equal: bool, status_equal: bool) -> &'static str {
    if !bindings_equal {
        "BLOCKED"
    } else if !status_equal {
        "WARNING"
    } else {
        "PASS"
    }
}

fn recovery_check_result_status(receipt_status: &str) -> &'static str {
    match receipt_status {
        "SUBMISSION_UNKNOWN" | "REORGED" | "STALE" | "BLOCKED" => "BLOCKED",
        "CONFIRMED" | "SUBMITTED" => "WARNING",
        _ => "UNAVAILABLE",
    }
}

fn emit(value: Value) -> Result<(), String> {
    println!(
        "{}",
        serde_json::to_string_pretty(&value).map_err(|error| error.to_string())?
    );
    Ok(())
}

fn emit_result(command: &str, network: Option<&str>, data: Value) -> Result<(), String> {
    emit_result_status(command, network, "PASS", data)
}

fn require_release_target_line(
    actual_schema: &str,
    actual_line: &str,
    expected_schema: &str,
    expected_line: &str,
) -> Result<(), String> {
    if actual_schema != expected_schema || actual_line != expected_line {
        return Err("RELEASE_EXECUTION_LINE_MISMATCH".into());
    }
    Ok(())
}

fn require_release_target_line_any(
    actual_schema: &str,
    actual_line: &str,
    allowed: &[(&str, &str)],
) -> Result<(), String> {
    if allowed
        .iter()
        .any(|(schema, line)| actual_schema == *schema && actual_line == *line)
    {
        return Ok(());
    }
    Err("RELEASE_EXECUTION_LINE_MISMATCH".into())
}

// Keep the established workflow CLI options explicit at the command boundary.
#[allow(clippy::too_many_arguments)]
fn run_release_workflow(
    command: &str,
    target: Option<PathBuf>,
    workdir: Option<PathBuf>,
    resume: Option<PathBuf>,
    candidate_result: Option<PathBuf>,
    prepare_only: bool,
    authorization_key: Option<PathBuf>,
    allowed_lines: &[(&str, &str)],
) -> Result<(), String> {
    if resume.is_some() && (target.is_some() || workdir.is_some() || candidate_result.is_some()) {
        return Err("RELEASE_MIXED_RESUME_OPTIONS".into());
    }
    let target = target.or_else(|| resume.as_ref().map(|p| p.join("target.snapshot.json")));
    let workdir = workdir.or(resume);
    let target = target.ok_or("RELEASE_TARGET_REQUIRED")?;
    let mut profile: release_workflow::Target =
        serde_json::from_slice(&fs::read(&target).map_err(|_| "RELEASE_TARGET_UNAVAILABLE")?)
            .map_err(|_| "RELEASE_TARGET_INVALID")?;
    if let Some(candidate_result) = candidate_result.as_deref() {
        release_candidate_binding::attach_result(&mut profile, candidate_result)?;
    }
    require_release_target_line_any(&profile.schema, &profile.execution_line, allowed_lines)?;
    let workdir = match workdir {
        Some(path) => path,
        None => release_workflow::default_workdir(&profile)?,
    };
    emit_result(
        command,
        None,
        release_workflow::run_target_with_authority(
            profile,
            &workdir,
            prepare_only,
            authorization_key.as_deref(),
        )?,
    )
}

fn discovery_command(action: DiscoveryAction) -> Result<(), String> {
    match action {
        DiscoveryAction::Catalog => emit_result(
            "ktape discovery catalog",
            None,
            discovery_metadata::catalog(),
        ),
        DiscoveryAction::Validate { metadata, network } => {
            let value = read_json(&metadata)?;
            let validated = discovery_metadata::validate(&value, network.as_deref())?;
            emit_result(
                "ktape discovery validate",
                validated["network"].as_str(),
                json!({"schema":"KTAPEOUT-DISCOVERY-VALIDATE-V1","status":"PASS","metadata":validated,"signing_allowed":false,"broadcast":false}),
            )
        }
        DiscoveryAction::Hash { metadata } => {
            let value = read_json(&metadata)?;
            let digest = discovery_metadata::hash(&value)?;
            emit_result(
                "ktape discovery hash",
                value["network"].as_str(),
                json!({"schema":"KTAPEOUT-DISCOVERY-HASH-V1","status":"PASS","metadata_hash":digest,"metadata_id":value["metadata_id"],"signing_allowed":false,"broadcast":false}),
            )
        }
        DiscoveryAction::MigrateUnclassified {
            application,
            network,
        } => {
            let value = read_json(&application)?;
            let metadata = discovery_metadata::migrate(&value, &network)?;
            emit_result(
                "ktape discovery migrate-unclassified",
                Some(&network),
                metadata,
            )
        }
    }
}

fn configure_context(cli: &Cli) -> Result<(), String> {
    let supplied = cli.context_state.is_some()
        || cli.context_project.is_some()
        || cli.context_network.is_some()
        || cli.context_signer.is_some()
        || cli.context_role.is_some();
    if !supplied {
        let _ = ACTIVE_CONTEXT.set(None);
        return Ok(());
    }
    let state_path = cli
        .context_state
        .as_ref()
        .ok_or_else(|| "CONTEXT_STATE_REQUIRED".to_string())?;
    let project_id = cli
        .context_project
        .as_deref()
        .ok_or_else(|| "CONTEXT_PROJECT_REQUIRED".to_string())?;
    let network = cli
        .context_network
        .as_deref()
        .ok_or_else(|| "CONTEXT_NETWORK_REQUIRED".to_string())?;
    if !matches!(network, "testnet-10" | "mainnet") {
        return Err("CONTEXT_NETWORK_INVALID".into());
    }
    let state_bytes =
        read_bounded_file(state_path, MAX_JSON_INPUT_BYTES, "CONTEXT_STATE_READ_ERROR")?;
    let state_text =
        String::from_utf8(state_bytes).map_err(|_| "CONTEXT_STATE_NOT_UTF8".to_string())?;
    let state: Value = parse_strict_json(state_text.as_bytes())
        .map_err(|error| format!("CONTEXT_STATE_JSON_ERROR:{error}"))?;
    if state["schema"] != "KTAPEOUT-0.5.0-CONTEXT-V1" || state["protocol_semver"] != PROTOCOL {
        return Err("CONTEXT_STATE_IDENTITY_INVALID".into());
    }
    let workspace_id = state["workspace_id"]
        .as_str()
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .ok_or_else(|| "CONTEXT_WORKSPACE_INVALID".to_string())?;
    let project = state["projects"]
        .get(project_id)
        .and_then(Value::as_object)
        .ok_or_else(|| "CONTEXT_PROJECT_INVALID".to_string())?;
    if project.get("project_id").and_then(Value::as_str) != Some(project_id) {
        return Err("CONTEXT_PROJECT_ID_MISMATCH".into());
    }
    let signer_id = cli.context_signer.as_deref();
    if let Some(signer) = signer_id {
        if signer.is_empty() || signer.len() > 128 {
            return Err("CONTEXT_SIGNER_INVALID".into());
        }
        let signer_value = state["signers"]
            .get(signer)
            .and_then(Value::as_object)
            .ok_or_else(|| "CONTEXT_SIGNER_NOT_FOUND".to_string())?;
        if signer_value.get("network").and_then(Value::as_str) != Some(network) {
            return Err("CONTEXT_SIGNER_NETWORK_MISMATCH".into());
        }
        if let Some(role) = cli.context_role.as_deref() {
            let authorized = signer_value
                .get("roles")
                .and_then(Value::as_array)
                .is_some_and(|roles| roles.iter().any(|value| value.as_str() == Some(role)));
            if !authorized {
                return Err("CONTEXT_SIGNER_ROLE_UNAUTHORIZED".into());
            }
        }
    } else if cli.context_role.is_some() {
        return Err("CONTEXT_ROLE_REQUIRES_SIGNER".into());
    }
    let context = json!({
        "workspace_id": workspace_id,
        "project_id": project_id,
        "environment": network,
        "signer_id": signer_id,
        "role": cli.context_role,
    });
    let _ = ACTIVE_CONTEXT.set(Some(context));
    Ok(())
}

fn emit_result_status(
    command: &str,
    network: Option<&str>,
    status: &str,
    data: Value,
) -> Result<(), String> {
    let context = ACTIVE_CONTEXT.get().cloned().flatten();
    let operation_data = match context.as_ref() {
        Some(context) => json!({"context": context, "data": data}),
        None => data.clone(),
    };
    let material = json!({"command": command, "network": network, "data": operation_data});
    let operation_hash = ktapeout_runtime::digest_json(&material, "KTAPEOUT/0.5.0/OPERATION/V1")?;
    let mut result = tool_result(
        command,
        status,
        network,
        &format!("op_{}", &operation_hash[..32]),
        data,
    )?;
    if let Some(context) = context {
        result["context"] = context;
        validate_tool_result(&result)?;
    }
    emit(result)
}

fn scaffold_data(template: &str, network: &str) -> Result<Value, String> {
    let allowed = [
        "PureCompute",
        "StateMachine",
        "Content",
        "ValueSettlement",
        "Container",
        "Composition",
        "Machine",
        "BoundedStateMachine",
    ];
    if !allowed.contains(&template) {
        return Err(format!(
            "TEMPLATE_UNSUPPORTED: available templates: {}",
            allowed.join(", ")
        ));
    }
    Ok(json!({
            "schema_version": SOURCE_SCHEMA,
            "source_kind": if matches!(template, "Machine" | "BoundedStateMachine") { "StateMachine" } else { template },
            "source_hash": "0".repeat(64),
            "declared_purpose": "",
            "inputs": [],
            "outputs": [],
            "persistent_state": [],
            "authorities": [],
            "external_dependencies": [],
            "value_flows": [],
            "availability_expectations": [],
            "test_vectors": [],
            "instructions": template_instructions(template),
            "discovery": {"primary_category":"other","secondary_categories":[],"tags":[],"surfaces":["web"],"confirmation_required":true},
            "network": network
    }))
}

fn scaffold(template: String, network: String) -> Result<(), String> {
    emit_result(
        "ktape app scaffold",
        Some(&network),
        scaffold_data(&template, &network)?,
    )
}

fn quickstart_manifest(template: &str, network: &str) -> Result<Value, String> {
    let mut manifest = scaffold_data(template, network)?;
    {
        let object = manifest
            .as_object_mut()
            .ok_or_else(|| "SOURCE_MANIFEST_NOT_OBJECT".to_string())?;
        object.insert(
            "declared_purpose".to_string(),
            json!("KTAPEOUT 0.5.0 offline starter"),
        );
        object.insert(
            "test_vectors".to_string(),
            json!([{"input": 0, "expected": 0}]),
        );
        object.insert(
            "instructions".to_string(),
            json!(template_instructions(template)),
        );
    }
    let mut source_material = manifest.clone();
    source_material["source_hash"] = Value::String("0".repeat(64));
    let source_hash = sha256_value(&source_material)?;
    manifest
        .as_object_mut()
        .ok_or_else(|| "SOURCE_MANIFEST_NOT_OBJECT".to_string())?
        .insert("source_hash".to_string(), Value::String(source_hash));
    validate_manifest_value(&manifest)?;
    Ok(manifest)
}

fn template_instructions(template: &str) -> &'static str {
    match template {
        "PureCompute" => {
            "Declare bounded inputs and outputs, then replace the placeholder vector with a deterministic behavior case."
        }
        "StateMachine" | "Machine" | "BoundedStateMachine" => {
            "Declare persistent state, allowed transitions and an idempotency/replay rule, then replace the placeholder vector with a state progression case."
        }
        "Content" => {
            "Declare content inputs, public/private placement and the commitment or version rule before adding content vectors."
        }
        "ValueSettlement" => {
            "Declare value flows, recipient rules, limits, refund/timeout behavior and duplicate-request handling; do not infer payment semantics from this template."
        }
        "Container" => {
            "Declare the hosted dependency boundary, request/response shape, timeout and failure behavior before adding integration vectors."
        }
        "Composition" => {
            "Declare component identities, typed bindings, state merge rules and resource limits before adding composition vectors."
        }
        _ => {
            "Replace source_hash with the hash of the canonical source description and add at least one test vector."
        }
    }
}

fn quickstart(template: String, network: String) -> Result<(), String> {
    let manifest = quickstart_manifest(&template, &network)?;
    emit_result_status(
        "ktape app quickstart",
        Some(&network),
        quickstart_result_status(),
        json!({
            "schema": "KTAPEOUT-0.5.0-QUICKSTART-V1",
            "template": template,
            "network": network,
            "manifest": manifest,
            "validation": {"status": "STRUCTURE_ONLY", "test_vector_count": 1, "tests_executed": false},
            "template_status": "TEMPLATE_PLANNED",
            "implementation_status": "DECLARATION_ONLY",
            "plan": translate_manifest_value(&manifest, &network)?,
            "next_action": "for executable local scenarios choose a supported runtime Project; otherwise run ktape app validate and ktape app test for structural checks",
            "signing": false,
            "broadcast": false,
            "admission_level": "PLAN_ONLY"
        }),
    )
}

fn quickstart_result_status() -> &'static str {
    "WARNING"
}

fn contains_secret_key(value: &Value) -> Option<String> {
    fn walk(value: &Value, path: &str) -> Option<String> {
        match value {
            Value::Object(map) => {
                for (key, child) in map {
                    let normalized: String = key
                        .chars()
                        .filter(|character| character.is_ascii_alphanumeric())
                        .flat_map(char::to_lowercase)
                        .collect();
                    let declaration_suffix = normalized.ends_with("optional")
                        || normalized.ends_with("enabled")
                        || normalized.ends_with("required")
                        || normalized.ends_with("allowed")
                        || normalized.ends_with("supported");
                    let declaration_boolean = child.is_boolean() && declaration_suffix;
                    if (normalized == "seed"
                        || [
                            "privatekey",
                            "seedphrase",
                            "mnemonic",
                            "secretkey",
                            "signingkey",
                            "passphrase",
                            "password",
                            "credential",
                            "wif",
                            "apikey",
                            "accesstoken",
                            "clientsecret",
                        ]
                        .iter()
                        .any(|token| normalized.contains(token)))
                        && !declaration_boolean
                    {
                        return Some(format!("{path}.{key}"));
                    }
                    if let Some(found) = walk(child, &format!("{path}.{key}")) {
                        return Some(found);
                    }
                }
            }
            Value::Array(values) => {
                for (index, child) in values.iter().enumerate() {
                    if let Some(found) = walk(child, &format!("{path}[{index}]")) {
                        return Some(found);
                    }
                }
            }
            _ => {}
        }
        None
    }
    walk(value, "$")
}

fn translation_hash(value: Value) -> Result<String, String> {
    sha256_value(&value)
}

fn translate_manifest(path: PathBuf, network: String, command: &str) -> Result<(), String> {
    let source = read_json(&path)?;
    let result = translate_manifest_value(&source, &network)?;
    emit_result_status(
        command,
        Some(&network),
        translate_result_status(&result),
        result,
    )
}

fn translate_result_status(result: &Value) -> &'static str {
    if result["status"] == "REQUIRES_HUMAN_REVIEW" {
        "WARNING"
    } else {
        "PASS"
    }
}

fn translation_semantic_unknowns(source: &Value) -> Vec<Value> {
    let array_has_items = |name: &str| {
        source
            .get(name)
            .and_then(Value::as_array)
            .is_some_and(|items| !items.is_empty())
    };
    let mut unknowns = Vec::new();
    let has_state = array_has_items("persistent_state");
    let has_value = array_has_items("value_flows");
    let has_authority = array_has_items("authorities");
    unknowns.extend(
        dev_workflow::missing_application_contract(source)
            .iter()
            .map(|field| json!(format!("application contract missing: {field}"))),
    );
    if has_state && !has_authority {
        unknowns.push(json!("state authority/owner is not declared"));
    }
    if has_value {
        unknowns.extend([
            json!("value conservation rule"),
            json!("refund or failure path"),
        ]);
    }
    let dependencies = source
        .get("external_dependencies")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for dependency in dependencies {
        // A profile-vector declaration is already a content-pinned typed
        // dependency; generic provider/fallback inference does not apply.
        if dependency_has_valid_profile_vector_binding(&dependency, source) {
            continue;
        }
        let declared_kind = dependency.get("dependency_kind").and_then(Value::as_str);
        let mode = dependency.get("mode").and_then(Value::as_str);
        if matches!(declared_kind, Some("OBSERVATION_SOURCE"))
            || matches!(mode, Some("external_observation" | "oracle"))
        {
            unknowns.extend([
                json!("external observation authority"),
                json!("commitment and timeout policy"),
            ]);
        } else if declared_kind.is_none()
            && !matches!(
                mode,
                Some(
                    "external_content_provider"
                        | "external_delivery"
                        | "external_policy"
                        | "external_identity"
                )
            )
        {
            unknowns.push(json!("external dependency kind and fallback policy"));
        }
    }
    let write_mode = source
        .get("chain_write_policy")
        .and_then(|policy| policy.get("mode"))
        .and_then(Value::as_str)
        .unwrap_or(if has_value {
            "SETTLEMENT_ONLY"
        } else {
            "LOCAL_ONLY"
        });
    let action_requires_chain = source
        .get("action_declarations")
        .and_then(Value::as_array)
        .is_some_and(|actions| {
            actions.iter().any(|action| {
                action
                    .get("write_mode")
                    .and_then(Value::as_str)
                    .is_some_and(|mode| mode != "LOCAL_ONLY")
            })
        });
    let requires_chain = write_mode != "LOCAL_ONLY" || action_requires_chain;
    if requires_chain && !array_has_items("data_placement") {
        unknowns.push(json!("L1 data placement and visibility are not declared"));
    }
    if requires_chain {
        let placement_names: Vec<&str> = source
            .get("data_placement")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.get("name").and_then(Value::as_str))
                    .collect()
            })
            .unwrap_or_default();
        let undeclared_public = source
            .get("outputs")
            .and_then(Value::as_array)
            .map(|outputs| {
                outputs.iter().any(|output| {
                    let public = output
                        .get("visibility")
                        .and_then(Value::as_str)
                        .is_some_and(|value| {
                            matches!(value, "PUBLIC_COMMITMENT" | "PUBLIC_SETTLEMENT")
                        })
                        || output
                            .get("content_mode")
                            .and_then(Value::as_str)
                            .is_some_and(|value| {
                                matches!(value, "HASH_ONLY_PUBLIC" | "CANONICAL_PUBLIC")
                            });
                    let name = output
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or("unnamed");
                    public && !placement_names.contains(&name)
                })
            })
            .unwrap_or(false);
        if undeclared_public {
            unknowns.push(json!("public output placement is not declared"));
        }
    }
    let commitment_required = matches!(write_mode, "PERIODIC_COMMITMENT" | "EVENT_COMMITMENT")
        || source
            .get("action_declarations")
            .and_then(Value::as_array)
            .is_some_and(|actions| {
                actions.iter().any(|action| {
                    action
                        .get("write_mode")
                        .and_then(Value::as_str)
                        .is_some_and(|mode| {
                            matches!(mode, "PERIODIC_COMMITMENT" | "EVENT_COMMITMENT")
                        })
                })
            });
    if requires_chain && commitment_required && !array_has_items("commitments") {
        unknowns.push(json!("commitment specification is not declared"));
    }
    if source
        .get("availability_expectations")
        .and_then(Value::as_array)
        .is_some_and(|items| !items.is_empty())
    {
        unknowns.push(json!("availability budget and fallback policy"));
    }
    unknowns
}

fn dependency_has_valid_profile_vector_binding(dependency: &Value, source: &Value) -> bool {
    let Some(source_hash) = source.get("source_hash").and_then(Value::as_str) else {
        return false;
    };
    dependency
        .get("profile_vector_binding")
        .is_some_and(|binding| validate_profile_vector_binding(binding, source_hash).is_ok())
}

fn translate_manifest_value(source: &Value, network: &str) -> Result<Value, String> {
    let object = validate_manifest_value(source)?;
    if let Some(found) = contains_secret_key(source) {
        return Err(format!("SECRET_MATERIAL_FORBIDDEN:{found}"));
    }
    let source_kind = object
        .get("source_kind")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let requirements = derive_requirements_value(source, network)?;
    let lowered_kind = source_kind.to_ascii_lowercase();
    let template = match lowered_kind.as_str() {
        "compute" => "PureCompute",
        "state" => "StateMachine",
        "content" => "Content",
        "settlement" => "ValueSettlement",
        "container" => "Container",
        "composition" => "Composition",
        "purecompute" => "PureCompute",
        "statemachine" => "StateMachine",
        "valuesettlement" => "ValueSettlement",
        _ if object
            .get("persistent_state")
            .and_then(Value::as_array)
            .is_some_and(|state| !state.is_empty()) =>
        {
            "StateMachine"
        }
        _ => "PureCompute",
    };
    let classification = if [
        "compute",
        "state",
        "content",
        "settlement",
        "container",
        "composition",
        "PureCompute",
        "StateMachine",
        "Content",
        "ValueSettlement",
        "Container",
        "Composition",
    ]
    .contains(&source_kind)
        || [
            "compute",
            "state",
            "content",
            "settlement",
            "container",
            "composition",
            "purecompute",
            "statemachine",
            "valuesettlement",
        ]
        .contains(&lowered_kind.as_str())
    {
        "EXACT"
    } else {
        "REQUIRES_HUMAN_REVIEW"
    };
    let source_hash = object
        .get("source_hash")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let application_id =
        translation_hash(json!({"source_hash": source_hash, "template": template}))?;
    let metadata_root = translation_hash(
        json!({"purpose": object.get("declared_purpose").cloned().unwrap_or(Value::Null), "source_hash": source_hash}),
    )?;
    let profile_root = translation_hash(json!({"template": template, "source_hash": source_hash}))?;
    let vector_count = object
        .get("test_vectors")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let max_bytes = canonical_json(source)?.len();
    let storage_floor = canonical_json(
        object
            .get("persistent_state")
            .unwrap_or(&Value::Array(Vec::new())),
    )?
    .len();
    let mut statuses = vec![
        json!({"capability":"starter_template_classification", "status":classification, "reason":if classification == "EXACT" {"recognized starter template identifier/alias matched"} else {"unknown source kind; candidate template is a shape-based suggestion, not a semantic mapping"}}),
    ];
    if object
        .get("external_dependencies")
        .and_then(Value::as_array)
        .is_some_and(|items| !items.is_empty())
    {
        statuses.push(json!({"capability":"external_dependencies", "status":"COMMITTED_EXTERNAL", "reason":"dependency remains outside L1"}));
    }
    if object
        .get("availability_expectations")
        .and_then(Value::as_array)
        .is_some_and(|items| !items.is_empty())
    {
        statuses.push(json!({"capability":"availability", "status":"REQUIRES_HUMAN_REVIEW", "reason":"availability budget and fallback must be approved"}));
    }
    let semantic_unknowns = translation_semantic_unknowns(source);
    if !semantic_unknowns.is_empty() {
        statuses.push(json!({"capability":"semantic_requirements", "status":"REQUIRES_HUMAN_REVIEW", "reason":"application requirements remain unresolved", "unknowns":semantic_unknowns.clone()}));
    }
    let has_value = object
        .get("value_flows")
        .and_then(Value::as_array)
        .is_some_and(|items| !items.is_empty());
    let write_mode = object
        .get("chain_write_policy")
        .and_then(|policy| policy.get("mode"))
        .and_then(Value::as_str)
        .unwrap_or(if has_value {
            "SETTLEMENT_ONLY"
        } else {
            "LOCAL_ONLY"
        });
    let action_requires_chain = object
        .get("action_declarations")
        .and_then(Value::as_array)
        .is_some_and(|actions| {
            actions.iter().any(|action| {
                action
                    .get("write_mode")
                    .and_then(Value::as_str)
                    .is_some_and(|mode| mode != "LOCAL_ONLY")
            })
        });
    let requires_chain = write_mode != "LOCAL_ONLY" || action_requires_chain;
    let blocked = statuses.iter().any(|item| {
        matches!(
            item.get("status").and_then(Value::as_str),
            Some("UNSUPPORTED" | "REQUIRES_HUMAN_REVIEW")
        )
    });
    let delivery_next_action = if blocked {
        "resolve the listed semantic decisions before build or preflight"
    } else if !requires_chain {
        "run ktape app test for structural checks; choose a supported runtime Project for executable local behavior"
    } else {
        "run ktape app test, then ktape dev build and ktape app preflight"
    };
    let delivery_summary = json!({
        "schema": "KTAPEOUT-0.5.0-DELIVERY-SUMMARY-V1",
        "scope": "LOCAL_UNSIGNED_PLAN",
        "status": if blocked { "REQUIRES_HUMAN_REVIEW" } else { "READY_FOR_PREFLIGHT" },
        "network": network,
        "human_decisions": [
            {"kind":"semantic_choice", "required":blocked || !semantic_unknowns.is_empty(), "items":semantic_unknowns},
            {"kind":"external_signing", "required":requires_chain, "scope":"declared L1 actions only"},
            {"kind":"value_settlement", "required":has_value, "scope":"declared value flows only"},
            {"kind":"broadcast", "required":requires_chain, "scope":network}
        ],
        "automated_steps":["source_manifest_validation","requirements_derivation","candidate_application_and_profile_plan","unsigned_release_plan"],
        "performance": {"status":"SHAPE_ESTIMATE", "measured":false, "source_bytes":max_bytes, "max_actions":vector_count, "claim":"no latency, throughput, or device-performance guarantee"},
        "fees": {"status":if requires_chain {"REQUIRES_CHAIN_QUOTE"} else {"NOT_APPLICABLE_LOCAL_ONLY"}, "quoted":false, "claim":"local estimate is not a Kaspa fee quote"},
        "recovery": {"unchanged_input_retry":"DO_NOT_RETRY", "submission_unknown":"QUERY_EXISTING_SUBMISSION_BEFORE_RETRY", "material_plan_change":"INVALIDATE_PLAN_AND_AUTHORIZATION"},
        "will_happen":["local deterministic validation and plan generation"],
        "will_not_happen":["private-key access","signing","broadcast","L1 deployment","admission claim"],
        "next_action":delivery_next_action
    });
    Ok(json!({
        "result_schema":"KTAPEOUT-0.5.0-TRANSLATION-RESULT-V1",
        "source_hash":source_hash,
        "application_plan":{"template":template,"network":network,"application_id":application_id,"metadata_root":metadata_root,"discovery_plan":object.get("discovery").cloned().unwrap_or(json!({"primary_category":"other","secondary_categories":[],"tags":[],"surfaces":["web"],"confirmation_required":true}))},
        "profile_plan":{"profile_roots":[profile_root],"composition_root":profile_root},
        "release_plan":{"network":network,"unsigned":true,"broadcast":false,"admission_level":"PLAN_ONLY"},
        "requirements":requirements,
        "instance_plan":{"status":"NOT_DEPLOYED","unsigned":true},
        "capability_matrix":statuses,
        "state_mapping":{"persistent_state":object.get("persistent_state").cloned().unwrap_or(Value::Array(Vec::new())),"bounded":true},
        "authority_mapping":{"authorities":object.get("authorities").cloned().unwrap_or(Value::Array(Vec::new())),"external_signer_required":true},
        "resource_budget":{"max_bytes":max_bytes,"max_actions":vector_count,"storage_floor":storage_floor,"requires_estimate":false,"origin":"SHAPE_ESTIMATE"},
        "economics_plan":{"value_flows":object.get("value_flows").cloned().unwrap_or(Value::Array(Vec::new())),"policy":"EXPLICIT_REVIEW_REQUIRED"},
        "name_plan":{"status":"UNASSIGNED","network":network},
        "conflict_report":{"status":"NOT_RUN","conflicts":[]},
        "test_plan":{"vectors":object.get("test_vectors").cloned().unwrap_or(Value::Array(Vec::new())),"negative_vectors_required":true},
        "evidence_refs":[{"kind":"source_manifest","hash":translation_hash(source.clone())?}],
        "unsigned_operations":[],
        "delivery_summary":delivery_summary,
        "status":if blocked {"REQUIRES_HUMAN_REVIEW"} else {"READY_FOR_PREFLIGHT"}
    }))
}

fn derive_requirements_value(source: &Value, network: &str) -> Result<Value, String> {
    let object = validate_manifest_value(source)?;
    if let Some(found) = contains_secret_key(source) {
        return Err(format!("SECRET_MATERIAL_FORBIDDEN:{found}"));
    }
    if !matches!(network, "testnet-10" | "mainnet") {
        return Err("REQUIREMENTS_NETWORK_UNSUPPORTED".into());
    }
    let has_state = object
        .get("persistent_state")
        .and_then(Value::as_array)
        .is_some_and(|v| !v.is_empty());
    let has_value = object
        .get("value_flows")
        .and_then(Value::as_array)
        .is_some_and(|v| !v.is_empty());
    let external_dependencies = object
        .get("external_dependencies")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let dependency_classification: Vec<Value> = external_dependencies.iter().map(|dependency| {
        let declared = dependency.get("dependency_kind").and_then(Value::as_str);
        let kind = declared.or_else(|| dependency_has_valid_profile_vector_binding(dependency, source).then_some("PROFILE_PROVIDER")).unwrap_or_else(|| match dependency.get("mode").and_then(Value::as_str) {
            Some("external_content_provider") => "CONTENT_PROVIDER",
            Some("external_delivery") => "DELIVERY_PROVIDER",
            Some("external_policy") => "POLICY_PROVIDER",
            Some("external_identity") => "IDENTITY_PROVIDER",
            Some("external_observation") | Some("oracle") => "OBSERVATION_SOURCE",
            _ => "UNKNOWN_EXTERNAL",
        });
        json!({"name":dependency.get("name").cloned().unwrap_or_else(|| json!("unnamed")),"kind":kind,"declared_mode":dependency.get("mode").cloned().unwrap_or(Value::Null)})
    }).collect();
    let has_observation_external = dependency_classification
        .iter()
        .any(|item| item.get("kind").and_then(Value::as_str) == Some("OBSERVATION_SOURCE"));
    let has_unknown_external = dependency_classification
        .iter()
        .any(|item| item.get("kind").and_then(Value::as_str) == Some("UNKNOWN_EXTERNAL"));
    let has_authority = object
        .get("authorities")
        .and_then(Value::as_array)
        .is_some_and(|v| !v.is_empty());
    let read_login_required = object
        .get("authorities")
        .and_then(Value::as_array)
        .is_some_and(|items| {
            items
                .iter()
                .any(|item| item.get("read_login_required").and_then(Value::as_bool) == Some(true))
        });
    let encrypted_data_declared = object
        .get("outputs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .chain(
            object
                .get("persistent_state")
                .and_then(Value::as_array)
                .into_iter()
                .flatten(),
        )
        .any(|item| {
            item.get("content_mode").and_then(Value::as_str) == Some("ENCRYPTED_SHARED")
                || matches!(
                    item.get("type").and_then(Value::as_str),
                    Some("encrypted_object" | "encrypted_objects")
                )
        });
    let decryption_declared = object
        .get("authorities")
        .and_then(Value::as_array)
        .is_some_and(|items| {
            items.iter().any(|item| {
                item.get("decryption_capability_separate")
                    .and_then(Value::as_bool)
                    == Some(true)
            })
        });
    let write_policy = object
        .get("chain_write_policy")
        .cloned()
        .unwrap_or_else(|| json!({"mode":if has_value {"SETTLEMENT_ONLY"} else {"LOCAL_ONLY"}}));
    let write_mode = write_policy
        .get("mode")
        .and_then(Value::as_str)
        .unwrap_or("LOCAL_ONLY");
    let data_placement = object
        .get("data_placement")
        .cloned()
        .unwrap_or_else(|| json!([]));
    let commitments = object
        .get("commitments")
        .cloned()
        .unwrap_or_else(|| json!([]));
    let public_facts = object
        .get("outputs")
        .and_then(Value::as_array)
        .map(|outputs| {
            outputs
                .iter()
                .filter(|item| {
                    item.get("visibility")
                        .and_then(Value::as_str)
                        .is_some_and(|v| matches!(v, "PUBLIC_COMMITMENT" | "PUBLIC_SETTLEMENT"))
                        || item
                            .get("content_mode")
                            .and_then(Value::as_str)
                            .is_some_and(|v| matches!(v, "HASH_ONLY_PUBLIC" | "CANONICAL_PUBLIC"))
                })
                .cloned()
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let vectors = object
        .get("test_vectors")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let actions: Vec<Value> = vectors
        .iter()
        .enumerate()
        .map(|(index, vector)| {
            vector.get("action").and_then(Value::as_str).map_or_else(
                || json!(format!("vector-{}", index + 1)),
                |action| json!(action),
            )
        })
        .collect();
    let action_policy: Vec<Value> =
        if let Some(declarations) = object.get("action_declarations").and_then(Value::as_array) {
            declarations
                .iter()
                .map(|item| {
                    let mut policy = item.as_object().cloned().unwrap_or_default();
                    policy.insert("inferred".into(), json!(false));
                    Value::Object(policy)
                })
                .collect()
        } else {
            actions.iter().map(|action| json!({
            "name": action,
            "execution": if write_mode == "LOCAL_ONLY" {"LOCAL"} else {"L1"},
            "write_mode": write_mode,
            "authorization": if write_mode == "LOCAL_ONLY" {"NONE"} else {"USER_SIGNATURE"},
            "inferred": true
        })).collect()
        };
    let action_requires_chain = action_policy.iter().any(|item| {
        item.get("write_mode")
            .and_then(Value::as_str)
            .is_some_and(|mode| mode != "LOCAL_ONLY")
    });
    let effective_requires_chain = write_mode != "LOCAL_ONLY" || action_requires_chain;
    let commitment_required = action_policy.iter().any(|item| {
        item.get("write_mode")
            .and_then(Value::as_str)
            .is_some_and(|mode| matches!(mode, "PERIODIC_COMMITMENT" | "EVENT_COMMITMENT"))
    });
    let placement_names: Vec<&str> = data_placement
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.get("name").and_then(Value::as_str))
                .collect()
        })
        .unwrap_or_default();
    let undeclared_public: Vec<Value> = public_facts
        .iter()
        .filter_map(|item| {
            let name = item
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("unnamed");
            if effective_requires_chain && !placement_names.contains(&name) {
                Some(json!(name))
            } else {
                None
            }
        })
        .collect();
    let mut unknowns: Vec<Value> = Vec::new();
    let missing_contract = dev_workflow::missing_application_contract(source);
    unknowns.extend(
        missing_contract
            .iter()
            .map(|field| json!(format!("application contract missing: {field}"))),
    );
    if has_state && !has_authority {
        unknowns.push(json!("state authority/owner is not declared"));
    }
    if has_value {
        unknowns.push(json!("value conservation rule"));
        unknowns.push(json!("refund or failure path"));
    }
    if has_observation_external {
        unknowns.push(json!("external observation authority"));
        unknowns.push(json!("commitment and timeout policy"));
    }
    if has_unknown_external {
        unknowns.push(json!("external dependency kind and fallback policy"));
    }
    if effective_requires_chain
        && data_placement
            .as_array()
            .is_none_or(|items| items.is_empty())
    {
        unknowns.push(json!("L1 data placement and visibility are not declared"));
    }
    if effective_requires_chain
        && commitment_required
        && commitments.as_array().is_none_or(|items| items.is_empty())
    {
        unknowns.push(json!("commitment specification is not declared"));
    }
    if !undeclared_public.is_empty() {
        unknowns.push(json!("public output placement is not declared"));
    }
    if object
        .get("availability_expectations")
        .and_then(Value::as_array)
        .is_some_and(|v| !v.is_empty())
    {
        unknowns.push(json!("availability budget and fallback policy"));
    }
    if encrypted_data_declared && !decryption_declared {
        unknowns.push(json!("decryption/key lifecycle contract"));
    }
    if object
        .get("availability_expectations")
        .and_then(Value::as_array)
        .is_some_and(|items| {
            items
                .iter()
                .any(|item| item.get("complete_history").and_then(Value::as_bool) == Some(true))
        })
    {
        unknowns.push(json!("cross-device recovery evidence"));
    }
    let mut lifecycle = vec![json!("DRAFT"), json!("ACTIVE"), json!("RETIRED")];
    if has_value {
        lifecycle.extend([json!("CLOSED"), json!("SETTLED_OR_REFUNDED")]);
    }
    let mut invariants = vec![
        json!("bounded transition inputs"),
        json!("deterministic replay"),
    ];
    if has_state {
        invariants.extend([
            json!("state writer is explicit"),
            json!("nonce/version prevents replay"),
        ]);
    }
    if has_value {
        invariants.extend([
            json!("value conservation"),
            json!("settlement is idempotent"),
            json!("exposure is bounded"),
        ]);
    }
    if has_observation_external {
        invariants.extend([
            json!("external fact is commitment-bound"),
            json!("challenge/timeout path is explicit"),
        ]);
    }
    if effective_requires_chain
        && (matches!(write_mode, "PERIODIC_COMMITMENT" | "EVENT_COMMITMENT") || commitment_required)
    {
        invariants.extend([
            json!("commitment batch is bounded"),
            json!("projection root is reproducible"),
        ]);
    }
    let has_public_commitment = !public_facts.is_empty()
        || commitments
            .as_array()
            .is_some_and(|items| !items.is_empty())
        || commitment_required;
    let mvp = json!({
        "MVP-0":{"scope":["read","local_or_replay_simulation"],"status":if missing_contract.is_empty() {"READY"} else {"NEEDS_INPUT"}},
        "MVP-1":{"scope":["bounded_state_write","user_signature"],"status":if has_state || has_authority {"REQUIRES_REVIEW"} else {"NOT_REQUIRED"}},
        "MVP-2":{"scope":["value_settlement","public_commitment"],"status":if has_value || has_observation_external || has_public_commitment {"REQUIRES_REVIEW"} else {"NOT_REQUIRED"}}
    });
    let needs_review = !unknowns.is_empty();
    let source_hash = object.get("source_hash").cloned().unwrap_or(Value::Null);
    let mut requirements = json!({
        "schema":"KTAPEOUT-0.5.0-APPLICATION-REQUIREMENTS-V1", "protocol_semver":PROTOCOL,
        "network":network, "source_hash":source_hash,
        "source_kind":object.get("source_kind").cloned().unwrap_or(Value::Null),
        "actors":object.get("authorities").cloned().unwrap_or_else(|| json!([])),
        "resources":{"inputs":object.get("inputs").cloned().unwrap_or_else(|| json!([])),"outputs":object.get("outputs").cloned().unwrap_or_else(|| json!([]))},
        "actions":actions, "persistent_state":object.get("persistent_state").cloned().unwrap_or_else(|| json!([])),
        "public_facts":public_facts, "local_state":[],
        "value_flows":object.get("value_flows").cloned().unwrap_or_else(|| json!([])),
        "authorities":object.get("authorities").cloned().unwrap_or_else(|| json!([])),
        "external_dependencies":external_dependencies, "dependency_classification":dependency_classification,
        "lifecycle":lifecycle, "failure_paths":if has_value {json!(["invalid_transition","resource_or_fee_limit","refund_or_timeout"])} else {json!(["invalid_transition","resource_or_fee_limit"])},
        "wallet_policy":{"walletless_read":!read_login_required,"read_login_required":read_login_required,"l1_write_requires_signature":effective_requires_chain,"settlement_requires_signature":has_value},
        "capability_checks":{"identity":{"status":if has_authority {"DECLARED"} else {"MISSING"}},"write_authorization":{"status":if effective_requires_chain {"DECLARED"} else {"NOT_REQUIRED"}},"decryption":{"status":if decryption_declared {"DECLARED"} else if encrypted_data_declared {"REQUIRED_REVIEW"} else {"NOT_REQUIRED"}},"cross_device_recovery":{"status":if object.get("availability_expectations").and_then(Value::as_array).is_some_and(|v| !v.is_empty()) {"REQUIRED_REVIEW"} else {"NOT_REQUIRED"}}},
        "performance_budget":{"max_actions":action_policy.len(),"source_bytes":canonical_json(source)?.len()},
        "cost_budget":{"requires_chain_quote":effective_requires_chain,"local_execution_first":true},
        "invariants":invariants, "mvp_scope":mvp, "unknowns":unknowns,
        "data_placement":data_placement, "chain_write_policy":write_policy, "action_policy":action_policy, "commitments":commitments,
        "data_path":{"status":"DECLARATION_ONLY","declared_content_modes":object.get("outputs").and_then(Value::as_array).into_iter().flatten().chain(data_placement.as_array().into_iter().flatten()).filter_map(|item| item.get("content_mode").and_then(Value::as_str)).collect::<std::collections::BTreeSet<_>>(),"full_bytes_declared":object.get("outputs").and_then(Value::as_array).is_some_and(|items| items.iter().any(|item| item.get("full_bytes_on_l1").and_then(Value::as_bool)==Some(true))),"evidence_required":if object.get("outputs").and_then(Value::as_array).is_some_and(|items| items.iter().any(|item| item.get("full_bytes_on_l1").and_then(Value::as_bool)==Some(true))) {"WRITER_READBACK_AND_RECONSTRUCTION"} else {"COMMITMENT_READBACK"}},
        "privacy_lint":{"status":if undeclared_public.is_empty() && (!effective_requires_chain || data_placement.as_array().is_some_and(|items| !items.is_empty())) {"PASS"} else {"REVIEW_REQUIRED"},"public_field_count":public_facts.len(),"undeclared_l1_fields":if !undeclared_public.is_empty() {Value::Array(undeclared_public.clone())} else if !effective_requires_chain {json!([])} else if data_placement.as_array().is_some_and(|items| items.is_empty()) {json!(["outputs"])} else {json!([])}},
        "commitment_lint":{"status":if !commitment_required || commitments.as_array().is_some_and(|items| !items.is_empty()) {"PASS"} else {"REVIEW_REQUIRED"},"declared_count":commitments.as_array().map_or(0, |items| items.len())},
        "status":if !missing_contract.is_empty() {"NEEDS_INPUT"} else if needs_review {"REQUIRES_HUMAN_REVIEW"} else {"READY_FOR_COMPOSITION"}
    });
    let requirements_hash = sha256_value(&json!({
        "source_hash": requirements["source_hash"].clone(),
        "mvp": requirements["mvp_scope"].clone(),
        "invariants": requirements["invariants"].clone(),
    }))?;
    let source_manifest_hash = sha256_value(source)?;
    requirements
        .as_object_mut()
        .ok_or_else(|| "AI_REQUIREMENTS_OBJECT_INVALID".to_string())?
        .insert(
        "trace".into(),
        json!({"source_manifest_hash":source_manifest_hash,"requirements_hash":requirements_hash}),
    );
    Ok(requirements)
}

fn ai_requirements(path: PathBuf, network: String) -> Result<(), String> {
    let source = read_json(&path)?;
    let requirements = derive_requirements_value(&source, &network)?;
    let status = match requirements.get("status").and_then(Value::as_str) {
        Some("NEEDS_INPUT") => "BLOCKED",
        Some("REQUIRES_HUMAN_REVIEW") => "WARNING",
        _ => "PASS",
    };
    emit_result_status(
        "ktape ai requirements",
        Some(&network),
        status,
        requirements,
    )
}

fn ai_context_export(path: PathBuf) -> Result<(), String> {
    let project = read_json(&path)?;
    if let Some(found) = contains_secret_key(&project) {
        return Err(format!("SECRET_MATERIAL_FORBIDDEN:{found}"));
    }
    let object = project
        .as_object()
        .ok_or_else(|| "AI_CONTEXT_NOT_OBJECT".to_string())?;
    let network = object
        .get("network")
        .and_then(Value::as_str)
        .unwrap_or("testnet-10");
    if !matches!(network, "testnet-10" | "mainnet") {
        return Err("AI_CONTEXT_NETWORK_INVALID".into());
    }
    let profiles = object
        .get("profiles")
        .cloned()
        .unwrap_or(Value::Array(Vec::new()));
    let evidence_refs = object
        .get("evidence_refs")
        .cloned()
        .unwrap_or(Value::Array(Vec::new()));
    if !profiles.is_array() || !evidence_refs.is_array() {
        return Err("AI_CONTEXT_SHAPE_INVALID".into());
    }
    let allowed_commands = object.get("allowed_commands").cloned().unwrap_or_else(|| {
        json!([
            "ktape dev check",
            "ktape dev build",
            "ktape dev package",
            "ktape dev workflow",
            "ktape dev studio-handoff-verify",
            "ktape dev studio-bundle-build",
            "ktape dev test",
            "ktape dev publishability",
            "ktape app validate",
            "ktape app test",
            "ktape app preflight",
            "ktape doctor"
        ])
    });
    let approval_gates = json!([
        "semantic choice",
        "license/economics change",
        "live UTXO selection",
        "external signing",
        "broadcast",
        "Mainnet promotion"
    ]);
    let status = object
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("READY_FOR_LOCAL_TEST");
    let next_action = if matches!(status, "READY_FOR_LOCAL_TEST" | "READY_FOR_PREFLIGHT") {
        "ktape app test"
    } else {
        "ktape doctor"
    };
    let mut allowed = json!({
        "protocol_semver": object.get("protocol_semver").cloned().unwrap_or_else(|| json!(PROTOCOL)),
        "runtime_version": object.get("runtime_version").cloned().unwrap_or_else(|| json!(PROTOCOL)),
        "network": network,
        "project_id": object.get("project_id").cloned().unwrap_or(Value::Null),
        "lock": object.get("lock").cloned().unwrap_or(Value::Null),
        "profiles": profiles,
        "resource_capabilities": object.get("resource_capabilities").cloned().unwrap_or(Value::Array(Vec::new())),
        "errors": object.get("errors").cloned().unwrap_or(Value::Array(Vec::new())),
        "evidence_refs": evidence_refs,
        "allowed_commands": allowed_commands,
        "approval_gates": approval_gates,
        "next_action": next_action,
    });
    let context_hash = sha256_value(&allowed)?;
    let allowed_object = allowed
        .as_object_mut()
        .ok_or_else(|| "AI_CONTEXT_NOT_OBJECT".to_string())?;
    allowed_object.insert("context_hash".into(), Value::String(context_hash));
    allowed_object.insert("schema".into(), json!("KTAPEOUT-AI-CONTEXT-V1"));
    emit_result("ktape ai context export", None, allowed)
}

fn ai_context_delivery(
    intent_path: PathBuf,
    policy_path: PathBuf,
    provider_path: PathBuf,
) -> Result<(), String> {
    let intent = read_json(&intent_path)?;
    let policy = read_json(&policy_path)?;
    let provider = read_json(&provider_path)?;
    validate_delivery_intent_value(&intent, &policy)?;
    validate_delivery_provider_value(&provider)?;

    let network = intent
        .get("network")
        .and_then(Value::as_str)
        .ok_or_else(|| "DELIVERY_INTENT_NETWORK_INVALID".to_string())?;
    let operation_kind = intent
        .get("operation_kind")
        .and_then(Value::as_str)
        .ok_or_else(|| "DELIVERY_INTENT_OPERATION_KIND_INVALID".to_string())?;
    let supports_network = provider["networks"]
        .as_array()
        .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(network)));
    let supports_kind = provider["operation_kinds"]
        .as_array()
        .is_some_and(|values| {
            values
                .iter()
                .any(|value| value.as_str() == Some(operation_kind))
        });
    if !supports_network || !supports_kind {
        return Err("DELIVERY_PROVIDER_CAPABILITY_MISMATCH".into());
    }

    let mut value = json!({
        "schema": "KTAPEOUT-AI-DELIVERY-CONTEXT-V1",
        "protocol_semver": PROTOCOL,
        "network": network,
        "operation_id": intent["operation_id"],
        "idempotency_key": intent["idempotency_key"],
        "intent_hash": intent["intent_hash"],
        "network_policy_hash": policy["policy_hash"],
        "provider_id": provider["provider_id"],
        "operation_kind": operation_kind,
        "canonical_name": intent["canonical_name"],
        "package": {
            "application_id": intent["application_id"],
            "release_id": intent["release_id"],
            "artifact_root": intent["artifact_root"],
            "profile_lock_hash": intent["profile_lock_hash"]
        },
        "cost_ceiling_sompi": {
            "max_fee_sompi": intent["max_fee_sompi"],
            "max_bond_sompi": intent["max_bond_sompi"],
            "max_value_sompi": intent["max_value_sompi"]
        },
        "expires_at": intent["expires_at"],
        "delivery_state": "LOCAL_PREFLIGHT_REQUIRED",
        "next_action": "ktape publish preflight INTENT.json POLICY.json PROVIDER.json",
        "forbidden_actions": ["sign", "broadcast", "weaken_policy", "change_package_or_name"],
        "contains_secret_material": false
    });
    let context_hash = sha256_value(&value)?;
    value
        .as_object_mut()
        .ok_or_else(|| "AI_DELIVERY_CONTEXT_NOT_OBJECT".to_string())?
        .insert("context_hash".into(), Value::String(context_hash));
    emit_result("ktape ai context delivery", Some(network), value)
}

fn composition_preflight(path: PathBuf) -> Result<(), String> {
    let input = read_json(&path)?;
    let profiles = match input {
        Value::Array(values) => values,
        Value::Object(mut object) => object
            .remove("profiles")
            .and_then(|value| value.as_array().cloned())
            .ok_or_else(|| "PROFILES_REQUIRED".to_string())?,
        _ => return Err("PROFILES_REQUIRED".into()),
    };
    if profiles.is_empty() {
        return Err("PROFILES_REQUIRED".into());
    }
    let conflict_order = [
        "identity/version",
        "interface/unit",
        "state",
        "authority",
        "resource",
        "settlement",
        "lifecycle",
        "proof/finality",
        "availability",
    ];
    let rank = |class: &str| {
        conflict_order
            .iter()
            .position(|item| *item == class)
            .unwrap_or(conflict_order.len())
    };
    let mut conflicts: Vec<Value> = Vec::new();
    let mut seen_identity = BTreeMap::<String, String>::new();
    let mut state_names = BTreeMap::<String, (String, String)>::new();
    let mut interface_units = BTreeMap::<String, String>::new();
    let mut root_domains = BTreeMap::<String, (String, String)>::new();
    let mut canonical_writers = BTreeMap::<String, String>::new();
    let mut atomicity_classes = std::collections::BTreeSet::<String>::new();
    let mut highest_atomicity = "A0".to_string();
    let mut dependency_digests = BTreeMap::<String, String>::new();
    let mut authority_domains = BTreeMap::<String, String>::new();
    let mut observation_modes = BTreeMap::<String, String>::new();
    let mut output_writers = BTreeMap::<String, Vec<(String, String)>>::new();
    let mut seen_components = std::collections::BTreeSet::<String>::new();
    let mut route_targets = BTreeMap::<String, (String, String, String)>::new();
    let mut component_interfaces = BTreeMap::<String, BTreeMap<String, (String, String)>>::new();
    for item in &profiles {
        let Some(object) = item.as_object() else {
            continue;
        };
        let Some(profile_id) = object.get("profile_id").and_then(Value::as_str) else {
            continue;
        };
        let component_id = object
            .get("component_id")
            .and_then(Value::as_str)
            .unwrap_or(profile_id);
        let (Some(interfaces), Some(modes)) = (
            object.get("interfaces").and_then(Value::as_object),
            object.get("interface_modes").and_then(Value::as_object),
        ) else {
            continue;
        };
        let mut declared = BTreeMap::new();
        for (name, unit) in interfaces {
            let (Some(unit), Some(mode)) = (unit.as_str(), modes.get(name).and_then(Value::as_str))
            else {
                continue;
            };
            if mode == "input" || mode == "output" {
                declared.insert(name.clone(), (unit.to_string(), mode.to_string()));
            }
        }
        component_interfaces.insert(component_id.to_string(), declared);
    }
    let mut total_bytes: u64 = 0;
    let mut total_actions: u64 = 0;

    for profile in &profiles {
        let object = match profile.as_object() {
            Some(value) => value,
            None => {
                conflicts.push(json!({"class":"identity/version", "reason":"profile_id missing"}));
                continue;
            }
        };
        let profile_id_value = object.get("profile_id");
        if profile_id_value.is_none()
            || profile_id_value == Some(&Value::Null)
            || profile_id_value.is_some_and(|value| value.as_str().is_some_and(str::is_empty))
        {
            conflicts.push(json!({"class":"identity/version", "reason":"profile_id missing"}));
            continue;
        }
        let profile_id = match profile_id_value.and_then(Value::as_str) {
            Some(value) if !value.trim().is_empty() => value.to_string(),
            _ => {
                conflicts.push(json!({"class":"identity/version", "reason":"profile_id must be a non-empty string"}));
                continue;
            }
        };
        let component_id = match object.get("component_id") {
            None => profile_id.clone(),
            Some(value) if value.as_str().is_some_and(valid_profile_id) => value
                .as_str()
                .ok_or_else(|| "COMPONENT_ID_INVALID".to_string())?
                .to_string(),
            Some(_) => {
                conflicts.push(json!({"class":"identity/version", "profiles":[profile_id], "reason":"COMPONENT_ID_INVALID", "alternatives":["use a bounded ASCII component_id", "keep component identities unique within the composition"]}));
                continue;
            }
        };
        if !seen_components.insert(component_id.clone()) {
            conflicts.push(json!({"class":"identity/version", "profiles":[profile_id], "components":[component_id], "reason":"COMPONENT_ID_DUPLICATED", "alternatives":["assign each component instance a unique component_id", "remove the duplicate instance"]}));
            continue;
        }
        let mut atomicity = object
            .get("atomicity_class")
            .and_then(Value::as_str)
            .unwrap_or("A0")
            .to_string();
        if !["A0", "A1", "A2", "A3", "A4", "A5"].contains(&atomicity.as_str()) {
            conflicts.push(json!({"class":"availability", "profiles":[profile_id], "reason":"ATOMICITY_CLASS_INVALID"}));
            atomicity = "A0".to_string();
        } else {
            atomicity_classes.insert(atomicity.clone());
            let rank_of = |value: &str| {
                ["A0", "A1", "A2", "A3", "A4", "A5"]
                    .iter()
                    .position(|item| *item == value)
                    .unwrap_or(0)
            };
            if rank_of(&atomicity) > rank_of(&highest_atomicity) {
                highest_atomicity = atomicity.clone();
            }
            if atomicity == "A4" || atomicity == "A5" {
                conflicts.push(json!({"class":"availability", "profiles":[profile_id], "reason":"ATOMICITY_CLASS_UNSUPPORTED", "atomicity_class":atomicity}));
            }
        }
        if let Some(supported) = object.get("supported_atomicity_classes") {
            let compatible = supported
                .as_array()
                .map(|items| {
                    items.iter().all(|item| {
                        item.as_str().is_some_and(|value| {
                            ["A0", "A1", "A2", "A3", "A4", "A5"].contains(&value)
                        }) && item.as_str() == Some(atomicity.as_str())
                    })
                })
                .unwrap_or(false);
            if !compatible {
                conflicts.push(json!({"class":"availability", "profiles":[profile_id], "reason":"BACKEND_ATOMICITY_CAPABILITY_MISMATCH", "atomicity_class":atomicity}));
            }
        }
        if let Some(dependencies) = object.get("dependencies") {
            let Some(items) = dependencies.as_array() else {
                conflicts.push(json!({"class":"identity/version","profiles":[profile_id],"reason":"DEPENDENCY_LIST_INVALID","alternatives":["declare dependencies as id/digest pairs","remove the unverified dependency"]}));
                continue;
            };
            for dependency in items {
                let Some(item) = dependency.as_object() else {
                    conflicts.push(json!({"class":"identity/version","profiles":[profile_id],"reason":"DEPENDENCY_IDENTITY_INVALID","alternatives":["pin a lowercase bytes32 dependency digest","use a separately versioned Profile"]}));
                    continue;
                };
                let id = item.get("id").and_then(Value::as_str).unwrap_or_default();
                let digest = item
                    .get("digest")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if id.is_empty() || !valid_hash(digest) {
                    conflicts.push(json!({"class":"identity/version","profiles":[profile_id],"reason":"DEPENDENCY_IDENTITY_INVALID","alternatives":["pin a lowercase bytes32 dependency digest","use a separately versioned Profile"]}));
                    continue;
                }
                if let Some(previous) = dependency_digests.get(id) {
                    if previous != digest {
                        conflicts.push(json!({"class":"identity/version","profiles":[profile_id],"reason":"DEPENDENCY_SUBSTITUTION_CONFLICT","dependency":id,"alternatives":["use the same pinned digest","split the application into separate locks"]}));
                    }
                }
                dependency_digests.insert(id.to_string(), digest.to_string());
            }
        }
        if let Some(domains) = object.get("authority_domains") {
            let Some(items) = domains.as_object() else {
                conflicts.push(json!({"class":"authority","profiles":[profile_id],"reason":"AUTHORITY_DOMAIN_MAP_INVALID","alternatives":["declare explicit domain/authority pairs","keep authority domains disjoint"]}));
                continue;
            };
            for (domain, authority) in items {
                let Some(authority) = authority.as_str() else {
                    conflicts.push(json!({"class":"authority","profiles":[profile_id],"reason":"AUTHORITY_DOMAIN_INVALID","alternatives":["use non-empty authority domain and owner identifiers"]}));
                    continue;
                };
                if domain.is_empty() || authority.is_empty() {
                    conflicts.push(json!({"class":"authority","profiles":[profile_id],"reason":"AUTHORITY_DOMAIN_INVALID","alternatives":["use non-empty authority domain and owner identifiers"]}));
                    continue;
                }
                if let Some(previous) = authority_domains.get(domain) {
                    if previous != authority {
                        conflicts.push(json!({"class":"authority","profiles":[profile_id],"reason":"AUTHORITY_MERGE_CONFLICT","domain":domain,"alternatives":["assign one canonical authority","rename the domain before composition"]}));
                    }
                }
                authority_domains.insert(domain.clone(), authority.to_string());
            }
        }
        if let Some(observations) = object.get("observations") {
            let Some(items) = observations.as_object() else {
                conflicts.push(json!({"class":"proof/finality","profiles":[profile_id],"reason":"OBSERVATION_MAP_INVALID","alternatives":["declare observation name/mode pairs","move external observation behind a bounded proof"]}));
                continue;
            };
            for (name, mode) in items {
                let Some(mode) = mode.as_str() else {
                    conflicts.push(json!({"class":"proof/finality","profiles":[profile_id],"reason":"OBSERVATION_IDENTITY_INVALID","alternatives":["use non-empty observation names and modes"]}));
                    continue;
                };
                if name.is_empty() || mode.is_empty() {
                    conflicts.push(json!({"class":"proof/finality","profiles":[profile_id],"reason":"OBSERVATION_IDENTITY_INVALID","alternatives":["use non-empty observation names and modes"]}));
                    continue;
                }
                if let Some(previous) = observation_modes.get(name) {
                    if previous != mode {
                        conflicts.push(json!({"class":"proof/finality","profiles":[profile_id],"reason":"OBSERVATION_SEMANTICS_CONFLICT","observation":name,"alternatives":["normalize the observation mode","separate the observations by namespace"]}));
                    }
                }
                observation_modes.insert(name.clone(), mode.to_string());
            }
        }
        if let Some(modes) = object.get("interface_modes") {
            let Some(items) = modes.as_object() else {
                conflicts.push(json!({"class":"interface/unit","profiles":[profile_id],"reason":"INTERFACE_MODE_MAP_INVALID","alternatives":["declare input/output modes separately","use a single canonical writer"]}));
                continue;
            };
            for (name, mode) in items {
                let Some(mode) = mode.as_str() else {
                    conflicts.push(json!({"class":"interface/unit","profiles":[profile_id],"reason":"INTERFACE_MODE_INVALID","alternatives":["use mode input or output"]}));
                    continue;
                };
                if mode != "input" && mode != "output" {
                    conflicts.push(json!({"class":"interface/unit","profiles":[profile_id],"reason":"INTERFACE_MODE_INVALID","alternatives":["use mode input or output"]}));
                }
                if mode == "output" {
                    output_writers
                        .entry(name.clone())
                        .or_default()
                        .push((component_id.clone(), profile_id.clone()));
                }
            }
        }
        if let Some(routes) = object.get("routes") {
            let Some(items) = routes.as_array() else {
                conflicts.push(json!({"class":"interface/unit","profiles":[profile_id],"reason":"ROUTE_LIST_INVALID","alternatives":["declare routes as from/to endpoint pairs","connect through a bounded adapter"]}));
                continue;
            };
            for route in items {
                let Some(item) = route.as_object() else {
                    conflicts.push(json!({"class":"interface/unit","profiles":[profile_id],"reason":"ROUTE_ENDPOINT_INVALID","alternatives":["use profile.port endpoint names"]}));
                    continue;
                };
                let from = item.get("from").and_then(Value::as_str).unwrap_or_default();
                let to = item.get("to").and_then(Value::as_str).unwrap_or_default();
                if from.is_empty() || to.is_empty() {
                    conflicts.push(json!({"class":"interface/unit","profiles":[profile_id],"reason":"ROUTE_ENDPOINT_INVALID","alternatives":["use profile.port endpoint names"]}));
                    continue;
                }
                if let Some(previous) = route_targets.get(to) {
                    if previous.0 != from {
                        let mut participant_profiles = vec![previous.2.clone(), profile_id.clone()];
                        participant_profiles.sort();
                        participant_profiles.dedup();
                        let mut participant_components =
                            vec![previous.1.clone(), component_id.clone()];
                        participant_components.sort();
                        participant_components.dedup();
                        conflicts.push(json!({"class":"interface/unit","profiles":participant_profiles,"components":participant_components,"reason":"MULTIPLE_ROUTE_TARGETS","target":to,"alternatives":["fan-in through an explicit A2/A3 reducer","assign one route owner"]}));
                    }
                } else {
                    route_targets.insert(
                        to.to_string(),
                        (from.to_string(), component_id.clone(), profile_id.clone()),
                    );
                }
                let resolve = |endpoint: &str| -> Option<(String, String, String)> {
                    let mut ids: Vec<&String> = component_interfaces.keys().collect();
                    ids.sort_by_key(|id| std::cmp::Reverse(id.len()));
                    for id in ids {
                        let prefix = format!("{}.", id);
                        if let Some(port) = endpoint.strip_prefix(&prefix) {
                            return Some(match component_interfaces[id].get(port) {
                                Some((unit, mode)) => (id.clone(), unit.clone(), mode.clone()),
                                None => (id.clone(), String::new(), String::new()),
                            });
                        }
                    }
                    None
                };
                let (Some(source), Some(target_endpoint)) = (resolve(from), resolve(to)) else {
                    conflicts.push(json!({"class":"interface/unit","profiles":[profile_id],"reason":"ROUTE_ENDPOINT_UNRESOLVED","alternatives":["declare each endpoint as component_id.port with an interface unit and direction"]}));
                    continue;
                };
                if source.1.is_empty() || target_endpoint.1.is_empty() {
                    conflicts.push(json!({"class":"interface/unit","profiles":[profile_id],"reason":"ROUTE_PORT_UNDECLARED","alternatives":["declare both route ports in their component interfaces and interface_modes"]}));
                    continue;
                }
                if source.2 != "output" || target_endpoint.2 != "input" {
                    conflicts.push(json!({"class":"interface/unit","profiles":[profile_id],"reason":"ROUTE_DIRECTION_MISMATCH","alternatives":["route from an output port to an input port"]}));
                    continue;
                }
                if source.1 != target_endpoint.1 {
                    conflicts.push(json!({"class":"interface/unit","profiles":[profile_id],"reason":"ROUTE_UNIT_MISMATCH","alternatives":["use matching interface units or an explicit bounded adapter"]}));
                    continue;
                }
            }
        }
        let version = match object.get("version") {
            None => String::new(),
            Some(value) if value.is_string() => value.as_str().unwrap_or_default().to_string(),
            Some(_) => {
                conflicts.push(json!({"class":"identity/version", "profiles":[profile_id], "reason":"version must be a string"}));
                String::new()
            }
        };
        if let Some(previous) = seen_identity.get(&profile_id) {
            if previous != &version {
                conflicts.push(json!({"class":"identity/version", "profiles":[profile_id], "reason":"multiple versions of same profile", "alternatives":["pin one Profile version across all components", "split the application into separately locked compositions"]}));
            }
        }
        seen_identity.insert(profile_id.clone(), version);

        if let Some(writer) = object.get("canonical_writer") {
            let valid_writer = writer.as_object().and_then(|value| {
                let writer_id = value.get("writer_id").and_then(Value::as_str)?;
                let domains = value.get("root_domains").and_then(Value::as_array)?;
                if writer_id.is_empty() || domains.is_empty() {
                    None
                } else {
                    Some((
                        writer_id.to_string(),
                        domains.clone(),
                        match value.get("topology") {
                            None => "SINGLE_WRITER".to_string(),
                            Some(Value::String(topology)) => topology.clone(),
                            Some(_) => String::new(),
                        },
                    ))
                }
            });
            if let Some((writer_id, domains, topology)) = valid_writer {
                if topology != "SINGLE_WRITER" {
                    conflicts.push(json!({"class":"state", "profiles":[profile_id], "reason":"CANONICAL_WRITER_TOPOLOGY_UNSUPPORTED", "alternatives":["use the supported SINGLE_WRITER topology", "keep delegated or unknown writer topologies uncomposed until their ownership rules are implemented"]}));
                }
                for domain in domains {
                    match domain.as_str() {
                        Some(value) if !value.is_empty() => {
                            let previous_owner = root_domains.get(value).cloned();
                            let previous_writer = canonical_writers.get(value).cloned();
                            if topology == "SINGLE_WRITER" && previous_writer.as_deref().is_some_and(|previous| previous != writer_id.as_str()) {
                                let mut participant_profiles = previous_owner.as_ref().map(|previous| vec![previous.1.clone(), profile_id.clone()]).unwrap_or_else(|| vec![profile_id.clone()]);
                                participant_profiles.sort(); participant_profiles.dedup();
                                let mut participant_components = previous_owner.as_ref().map(|previous| vec![previous.0.clone(), component_id.clone()]).unwrap_or_else(|| vec![component_id.clone()]);
                                participant_components.sort(); participant_components.dedup();
                                conflicts.push(json!({"class":"state", "profiles":participant_profiles, "components":participant_components, "reason":"CANONICAL_WRITER_CONFLICT", "domain":value, "alternatives":["assign one canonical writer to the shared root domain", "partition the domain before composition"]}));
                            }
                            if let Some(previous) = previous_owner.as_ref() {
                                if previous.0 != component_id {
                                    let mut participant_profiles = vec![previous.1.clone(), profile_id.clone()]; participant_profiles.sort(); participant_profiles.dedup();
                                    let mut participant_components = vec![previous.0.clone(), component_id.clone()]; participant_components.sort(); participant_components.dedup();
                                    conflicts.push(json!({"class":"state", "profiles":participant_profiles, "components":participant_components, "reason":"CANONICAL_ROOT_DOMAIN_CONFLICT", "alternatives":["assign the root domain to one component", "rename or partition the root domain before composition"]}));
                                }
                            } else {
                                root_domains.insert(value.to_string(), (component_id.clone(), profile_id.clone()));
                            }
                            if topology == "SINGLE_WRITER" { canonical_writers.entry(value.to_string()).or_insert_with(|| writer_id.clone()); }
                        }
                        _ => conflicts.push(json!({"class":"state", "profiles":[profile_id], "reason":"CANONICAL_ROOT_DOMAIN_INVALID"})),
                    }
                }
            } else {
                conflicts.push(json!({"class":"state", "profiles":[profile_id], "reason":"CANONICAL_WRITER_POLICY_INVALID"}));
            }
        }

        let namespace = match object.get("state_namespace") {
            None | Some(Value::Null) => None,
            Some(value) if value.is_string() => value
                .as_str()
                .filter(|value| !value.is_empty())
                .map(str::to_string),
            Some(_) => {
                conflicts.push(json!({"class":"state", "profiles":[profile_id], "reason":"state namespace must be a string"}));
                None
            }
        };
        if let Some(namespace) = namespace {
            if let Some(previous) = state_names.get(&namespace) {
                if previous.0 != component_id {
                    let mut participant_profiles = vec![previous.1.clone(), profile_id.clone()];
                    participant_profiles.sort();
                    participant_profiles.dedup();
                    let mut participant_components = vec![previous.0.clone(), component_id.clone()];
                    participant_components.sort();
                    participant_components.dedup();
                    conflicts.push(json!({"class":"state", "profiles":participant_profiles, "components":participant_components, "reason":"state namespace collision", "alternatives":["assign each component a unique state namespace", "declare an explicit shared-state owner and bounded transition"]}));
                }
            }
            state_names.insert(namespace, (component_id.clone(), profile_id.clone()));
        }

        let interfaces = match object.get("interfaces") {
            None | Some(Value::Null) => None,
            Some(value) if value.is_object() => value.as_object(),
            Some(_) => {
                conflicts.push(json!({"class":"interface/unit", "profiles":[profile_id], "reason":"interfaces must be an object"}));
                None
            }
        };
        if let Some(interfaces) = interfaces {
            for (name, unit) in interfaces {
                let (Some(name), Some(unit)) = (Some(name.as_str()), unit.as_str()) else {
                    conflicts.push(json!({"class":"interface/unit", "profiles":[profile_id], "reason":"interface names and units must be non-empty strings"}));
                    continue;
                };
                if name.is_empty() || unit.is_empty() {
                    conflicts.push(json!({"class":"interface/unit", "profiles":[profile_id], "reason":"interface names and units must be non-empty strings"}));
                    continue;
                }
                if let Some(previous) = interface_units.get(name) {
                    if previous != unit {
                        conflicts.push(json!({"class":"interface/unit", "profiles":[profile_id], "reason":format!("interface unit mismatch:{name}")}));
                    }
                }
                interface_units.insert(name.to_string(), unit.to_string());
            }
        }

        for (field, total) in [
            ("max_bytes", &mut total_bytes),
            ("max_actions", &mut total_actions),
        ] {
            let value = object
                .get(field)
                .cloned()
                .unwrap_or(Value::Number(0.into()));
            let valid = if !value.is_boolean() {
                value.as_u64()
            } else {
                None
            };
            if let Some(amount) = valid {
                *total += amount;
            } else {
                conflicts.push(json!({"class":"resource", "profiles":[profile_id], "reason":format!("{field} must be a non-negative integer")}));
            }
        }
    }
    if total_bytes > 100_000 {
        conflicts.push(json!({"class":"resource", "reason":"max_bytes exceeded", "actual":total_bytes, "limit":100000}));
    }
    if total_actions > 1_000 {
        conflicts.push(json!({"class":"resource", "reason":"max_actions exceeded", "actual":total_actions, "limit":1000}));
    }
    for (interface, writers) in &output_writers {
        let components: std::collections::BTreeSet<_> = writers
            .iter()
            .map(|(component, _)| component.clone())
            .collect();
        if components.len() > 1 {
            let profiles: std::collections::BTreeSet<_> =
                writers.iter().map(|(_, profile)| profile.clone()).collect();
            conflicts.push(json!({"class":"interface/unit","profiles":profiles,"components":components,"reason":"MULTIPLE_OUTPUT_WRITERS","interface":interface,"alternatives":["select one canonical output writer","use an explicit reducer Profile"]}));
        }
    }
    conflicts.sort_by_key(|item| {
        rank(
            item.get("class")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        )
    });
    let status = if conflicts.is_empty() {
        "VALID"
    } else {
        "UNRESOLVED_CONFLICT"
    };
    let composition_root = sha256_value(&json!({"profiles":profiles, "status":status}))?;
    emit_result(
        "ktape app compose-preflight",
        None,
        json!({"schema":"KTAPEOUT-0.5.0-COMPOSITION-PREFLIGHT-V1","status":status,"conflicts":conflicts,"profile_count":profiles.len(),"atomicity":{"classes":atomicity_classes,"highest":highest_atomicity,"supported_max":"A3"},"resource_totals":{"max_bytes":total_bytes,"max_actions":total_actions},"limits":{"max_bytes":100000,"max_actions":1000},"settlement":[],"composition_root":composition_root}),
    )
}

fn copy_profile_package(source: &Path, destination: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(source)
        .map_err(|error| format!("INIT_PROFILE_PACKAGE_READ_ERROR:{error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("INIT_PROFILE_PACKAGE_DIRECTORY_REQUIRED".into());
    }
    let source_canonical = fs::canonicalize(source)
        .map_err(|error| format!("INIT_PROFILE_PACKAGE_READ_ERROR:{error}"))?;
    if let Some(parent) = destination.parent() {
        if let Ok(parent_canonical) = fs::canonicalize(parent) {
            if parent_canonical.starts_with(&source_canonical) {
                return Err("INIT_PROFILE_PACKAGE_OUTPUT_INSIDE_SOURCE_FORBIDDEN".into());
            }
        }
    }
    fs::create_dir_all(destination)
        .map_err(|error| format!("INIT_PROFILE_PACKAGE_COPY_ERROR:{error}"))?;
    for entry in
        fs::read_dir(source).map_err(|error| format!("INIT_PROFILE_PACKAGE_READ_ERROR:{error}"))?
    {
        let entry = entry.map_err(|error| format!("INIT_PROFILE_PACKAGE_READ_ERROR:{error}"))?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let metadata = fs::symlink_metadata(&source_path)
            .map_err(|error| format!("INIT_PROFILE_PACKAGE_READ_ERROR:{error}"))?;
        if metadata.file_type().is_symlink() {
            return Err("INIT_PROFILE_PACKAGE_SYMLINK_FORBIDDEN".into());
        }
        if metadata.is_dir() {
            copy_profile_package(&source_path, &destination_path)?;
        } else if metadata.is_file() {
            fs::copy(&source_path, &destination_path)
                .map_err(|error| format!("INIT_PROFILE_PACKAGE_COPY_ERROR:{error}"))?;
        } else {
            return Err("INIT_PROFILE_PACKAGE_ENTRY_UNSUPPORTED".into());
        }
    }
    Ok(())
}

fn init(
    template: String,
    network: String,
    output: Option<PathBuf>,
    profile_lock: Option<PathBuf>,
    profile_package: Option<PathBuf>,
    network_policy: Option<PathBuf>,
) -> Result<(), String> {
    let profile_binding_requested = profile_lock.is_some() || profile_package.is_some();
    if profile_lock.is_some() && profile_package.is_some() {
        return Err("INIT_PROFILE_INPUTS_EXCLUSIVE".into());
    }
    let runtime_starter = matches!(template.as_str(), "Machine" | "BoundedStateMachine");
    if runtime_starter && network != "testnet-10" {
        return Err("RUNTIME_STARTER_TESTNET_ONLY".into());
    }
    if runtime_starter && (profile_lock.is_some() || profile_package.is_some()) {
        return Err("RUNTIME_STARTER_PROFILE_BINDING_NOT_IMPLEMENTED".into());
    }
    let writes_runtime_starter = runtime_starter && output.is_some();
    if network_policy.is_some() && profile_lock.is_none() && profile_package.is_none() {
        return Err("INIT_NETWORK_POLICY_REQUIRES_PROFILE_BINDING".into());
    }
    let policy = network_policy
        .as_ref()
        .map(|path| read_json(path))
        .transpose()?;
    if let Some(policy) = &policy {
        if policy["network_id"] != network || policy["schema"] != "KTAPEOUT-NETWORK-POLICY-V0.5.0" {
            return Err("INIT_NETWORK_POLICY_MISMATCH".into());
        }
        let mut material = policy
            .as_object()
            .cloned()
            .ok_or("NETWORK_POLICY_SCHEMA_INVALID")?;
        let policy_id = material
            .remove("policy_id")
            .ok_or("NETWORK_POLICY_SCHEMA_INVALID")?;
        if policy_id
            != digest_json_domain(&Value::Object(material), "KTAPEOUT/0.5.0/NETWORK_POLICY/V1")?
        {
            return Err("INIT_NETWORK_POLICY_DIGEST_MISMATCH".into());
        }
        if let Some(lock_path) = &profile_lock {
            let value = read_json(lock_path)?;
            let lock = value.get("lock").unwrap_or(&value);
            if lock["network_policy_id"] != policy_id {
                return Err("INIT_LOCK_NETWORK_POLICY_MISMATCH".into());
            }
        }
    }
    let manifest = quickstart_manifest(&template, &network)?;
    let mut data = manifest.clone();
    data["template_status"] = json!(if writes_runtime_starter {
        "LOCAL_RUNTIME_PROJECT_STARTER"
    } else if runtime_starter {
        "STARTER_NOT_WRITTEN"
    } else {
        "TEMPLATE_PLANNED"
    });
    data["implementation_status"] = json!(if writes_runtime_starter {
        "EXECUTABLE"
    } else {
        "DECLARATION_ONLY"
    });
    data["tests_executed"] = json!(false);
    if let Some(object) = data.as_object_mut() {
        object.insert("init_mode".to_string(), json!("STANDARD"));
        object.insert(
            "next_action".to_string(),
            json!(if runtime_starter && !writes_runtime_starter {
                format!("rerun ktape init --template {template} --network testnet-10 --output <project-dir> to write the local Project, runtime bundle and workflow")
            } else {
                "run ktape app validate on source-manifest.json".to_string()
            }),
        );
        object.insert(
            "signing".to_string(),
            json!("developer-key-or-external-signature"),
        );
        object.insert("broadcast".to_string(), json!(false));
    }
    if let Some(destination) = output {
        fs::create_dir_all(&destination)
            .map_err(|error| format!("INIT_OUTPUT_CREATE_ERROR:{error}"))?;
        let manifest_path = destination.join("source-manifest.json");
        let quickstart_path = destination.join("quickstart-result.json");
        let workflow_path = destination.join("workflow.json");
        fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&manifest)
                .map_err(|error| format!("INIT_MANIFEST_ENCODE_ERROR:{error}"))?
                + "\n",
        )
        .map_err(|error| format!("INIT_MANIFEST_WRITE_ERROR:{error}"))?;
        let quickstart_result = json!({
            "schema": "KTAPEOUT-0.5.0-QUICKSTART-V1",
            "template": template,
            "network": network,
            "manifest": manifest,
            "validation": {"status": "STRUCTURE_ONLY", "test_vector_count": 1, "tests_executed": false},
            "template_status": if runtime_starter { "LOCAL_RUNTIME_PROJECT_STARTER" } else { "TEMPLATE_PLANNED" },
            "implementation_scope": if runtime_starter { "STUDIO_PROJECT_ONLY" } else { "DECLARATION_ONLY" },
            "next_action": if profile_binding_requested && policy.is_none() {
                "locate the exact lock-bound network policy and set workflow.network_policy; if this lock was generated with a placeholder policy ID, rerun ktape init with the same --profile-package or --profile-lock, a validated --network-policy, and a new --output directory"
            } else if runtime_starter { "run ktape dev workflow workflow.json" } else { "run ktape app validate on source-manifest.json" },
            "signing": false,
            "broadcast": false,
            "admission_level": "PLAN_ONLY"
        });
        fs::write(
            &quickstart_path,
            serde_json::to_string_pretty(&quickstart_result)
                .map_err(|error| format!("INIT_QUICKSTART_ENCODE_ERROR:{error}"))?
                + "\n",
        )
        .map_err(|error| format!("INIT_QUICKSTART_WRITE_ERROR:{error}"))?;
        let mut workflow = json!({
            "schema": "KTAPEOUT-DEV-WORKFLOW-V1",
            "protocol_semver": PROTOCOL,
            "manifest": "source-manifest.json",
            "network": network,
            "backend": "local-simulation",
            "build_output": "build",
            "package_output": "package",
            "stages": ["check", "build", "package", "test"]
        });
        let profile_package_mode = profile_package.is_some();
        let profile_package_source = profile_package.clone();
        let generated_lock = if let Some(package_path) = profile_package {
            let lock = profile_lock_value(
                package_path.clone(),
                policy
                    .as_ref()
                    .and_then(|value| value["policy_id"].as_str())
                    .map(str::to_owned)
                    .unwrap_or_else(|| format!("{network}-policy")),
                "1970-01-01T00:00:00Z".into(),
            )?;
            copy_profile_package(&package_path, &destination.join("profile-package"))?;
            Some((lock, package_path))
        } else if let Some(lock_path) = profile_lock {
            let lock = read_json(&lock_path)?;
            let lock = lock.get("lock").cloned().unwrap_or(lock);
            ktapeout_runtime::validate_developer_lock(&lock)
                .map_err(|_| "PROFILE_LOCK_INVALID".to_string())?;
            Some((lock, lock_path))
        } else {
            None
        };
        if let Some((lock, _source_path)) = generated_lock {
            fs::write(
                destination.join("profile-lock.json"),
                serde_json::to_string_pretty(&lock)
                    .map_err(|error| format!("INIT_PROFILE_LOCK_ENCODE_ERROR:{error}"))?
                    + "\n",
            )
            .map_err(|error| format!("INIT_PROFILE_LOCK_WRITE_ERROR:{error}"))?;
            workflow["profile_lock"] = Value::String("profile-lock.json".into());
            let mut binding = json!({
                "source": if profile_package_mode { "verified-profile-package" } else { "verified-developer-lock" }
            });
            if profile_package_source.is_some() {
                binding["package_root"] = Value::String("profile-package".into());
            }
            workflow["profile_binding"] = binding;
        }
        if let Some(policy) = &policy {
            atomic_write_file(
                &destination.join("network-policy.json"),
                (serde_json::to_string_pretty(policy).map_err(|e| e.to_string())? + "\n")
                    .as_bytes(),
                "INIT_NETWORK_POLICY_WRITE_ERROR",
            )?;
            workflow["network_policy"] = json!("network-policy.json");
        }
        fs::write(
            &workflow_path,
            serde_json::to_string_pretty(&workflow)
                .map_err(|error| format!("INIT_WORKFLOW_ENCODE_ERROR:{error}"))?
                + "\n",
        )
        .map_err(|error| format!("INIT_WORKFLOW_WRITE_ERROR:{error}"))?;
        data["output"] = Value::String(destination.display().to_string());
        data["files"] = json!(if workflow.get("profile_lock").is_some() {
            let mut files = vec![
                "source-manifest.json",
                "quickstart-result.json",
                "workflow.json",
                "profile-lock.json",
            ];
            if profile_package_source.is_some() {
                files.push("profile-package/");
            }
            if policy.is_some() {
                files.push("network-policy.json");
            }
            files
        } else {
            vec![
                "source-manifest.json",
                "quickstart-result.json",
                "workflow.json",
            ]
        });
        data["profile_lock"] = workflow.get("profile_lock").cloned().unwrap_or(Value::Null);
        data["next_action"] = json!(if workflow.get("profile_lock").is_some()
            && workflow.get("network_policy").is_none()
        {
            "locate the exact policy whose content-addressed policy_id matches profile-lock.json and set workflow.network_policy; if the lock contains a placeholder policy ID, rerun ktape init with the same --profile-package or --profile-lock, a validated --network-policy, and a new --output directory"
        } else {
            "run ktape dev workflow workflow.json"
        });
        if network == "testnet-10" {
            fs::create_dir_all(destination.join("discovery")).map_err(|e| e.to_string())?;
            atomic_write_file(
                &destination.join("discovery/metadata.json"),
                (serde_json::to_string_pretty(&package_build::discovery_template(&network))
                    .map_err(|e| e.to_string())?
                    + "\n")
                    .as_bytes(),
                "INIT_DISCOVERY_WRITE_ERROR",
            )?;
            data["files"]
                .as_array_mut()
                .ok_or("INIT_FILES_INVALID")?
                .push(json!("discovery/metadata.json"));
            data["discovery_status"] = json!("TEMPLATE_REQUIRES_APPLICATION_ID_AND_CANONICAL_URI");
        }
        if runtime_starter {
            data["runtime_starter"] = dev_workflow::write_runtime_starter(&destination, &template)?;
            workflow["runtime_project"] = json!("project.json");
            atomic_write_file(
                &workflow_path,
                (serde_json::to_string_pretty(&workflow).map_err(|e| e.to_string())? + "\n")
                    .as_bytes(),
                "INIT_WORKFLOW_WRITE_ERROR",
            )?;
            for name in [
                "project.json",
                "runtime-bundle.json",
                "inputs.json",
                "state.json",
                "index.html",
            ] {
                data["files"]
                    .as_array_mut()
                    .ok_or("INIT_FILES_INVALID")?
                    .push(json!(name));
            }
        }
    }
    emit_result_status(
        "ktape init",
        Some(&network),
        if writes_runtime_starter {
            "PASS"
        } else {
            "WARNING"
        },
        data,
    )
}

fn validate_delivery_policy_value(value: &Value) -> Result<(), String> {
    let required = [
        "schema",
        "protocol_semver",
        "network",
        "namespace_root",
        "rpc_sources",
        "max_inputs",
        "max_outputs",
        "max_fee_sompi",
        "max_bond_sompi",
        "max_value_sompi",
        "max_response_bytes",
        "rpc_timeout_ms",
        "max_retries",
        "plan_ttl_seconds",
        "min_readback_sources",
        "policy_hash",
    ];
    let object = value
        .as_object()
        .ok_or_else(|| "DELIVERY_POLICY_NOT_OBJECT".to_string())?;
    if object.len() != required.len() || required.iter().any(|field| !object.contains_key(*field)) {
        return Err("DELIVERY_POLICY_FIELDS_INVALID".into());
    }
    if value.get("schema").and_then(Value::as_str) != Some("KTAPEOUT-DELIVERY-NETWORK-POLICY-V1")
        || value.get("protocol_semver").and_then(Value::as_str) != Some(PROTOCOL)
        || !matches!(
            value.get("network").and_then(Value::as_str),
            Some("testnet-10" | "mainnet")
        )
        || value.get("namespace_root").and_then(Value::as_str) != Some("ktape")
    {
        return Err("DELIVERY_POLICY_IDENTITY_INVALID".into());
    }
    let sources = value
        .get("rpc_sources")
        .and_then(Value::as_array)
        .ok_or_else(|| "DELIVERY_POLICY_RPC_SOURCES_INVALID".to_string())?;
    if !(2..=8).contains(&sources.len()) {
        return Err("DELIVERY_POLICY_RPC_SOURCES_INVALID".into());
    }
    let mut seen = std::collections::BTreeSet::new();
    for source in sources {
        let source = source
            .as_str()
            .filter(|source| source.starts_with("wss://") && source.len() <= 256)
            .ok_or_else(|| "DELIVERY_POLICY_RPC_SOURCES_INVALID".to_string())?;
        if !seen.insert(source.to_string()) {
            return Err("DELIVERY_POLICY_RPC_SOURCES_INVALID".into());
        }
    }
    for (field, low, high) in [
        ("max_inputs", 1, 64),
        ("max_outputs", 1, 64),
        ("max_response_bytes", 1024, 1_048_576),
        ("rpc_timeout_ms", 1000, 60_000),
        ("max_retries", 0, 8),
        ("plan_ttl_seconds", 30, 3600),
    ] {
        let value = value
            .get(field)
            .and_then(Value::as_u64)
            .ok_or_else(|| format!("DELIVERY_POLICY_{field}_INVALID"))?;
        if value < low || value > high {
            return Err(format!("DELIVERY_POLICY_{field}_INVALID"));
        }
    }
    for field in ["max_fee_sompi", "max_bond_sompi", "max_value_sompi"] {
        if value.get(field).and_then(Value::as_u64).is_none() {
            return Err(format!("DELIVERY_POLICY_{field}_INVALID"));
        }
    }
    let minimum = value
        .get("min_readback_sources")
        .and_then(Value::as_u64)
        .ok_or_else(|| "DELIVERY_POLICY_MIN_READBACK_INVALID".to_string())?;
    if minimum < 2 || minimum > sources.len() as u64 {
        return Err("DELIVERY_POLICY_MIN_READBACK_INVALID".into());
    }
    let claimed = value
        .get("policy_hash")
        .and_then(Value::as_str)
        .filter(|value| valid_hash(value))
        .ok_or_else(|| "DELIVERY_POLICY_HASH_INVALID".to_string())?;
    let mut material = object.clone();
    material.remove("policy_hash");
    let expected = digest_json_domain(
        &Value::Object(material),
        "KTAPEOUT/0.5.0/DELIVERY_NETWORK_POLICY/V1",
    )?;
    if claimed != expected {
        return Err("DELIVERY_POLICY_HASH_MISMATCH".into());
    }
    Ok(())
}

fn publish_policy_verify(path: PathBuf) -> Result<(), String> {
    let policy = read_json(&path)?;
    validate_delivery_policy_value(&policy)?;
    emit_result(
        "ktape publish policy-verify",
        policy.get("network").and_then(Value::as_str),
        json!({"delivery_state":"POLICY_VERIFIED","policy":policy,"signing_allowed":false,"broadcast":false}),
    )
}

fn delivery_lock_compatibility_error(value: &Value) -> Option<&'static str> {
    (value.get("schema").and_then(Value::as_str) == Some("KTAPEOUT-APPLICATION-LOCK-V2"))
        .then_some("PUBLISH_APPLICATION_LOCK_V2_WRONG_INPUT_SLOT: profile-lock.json requires a DeveloperLock; pass ApplicationLock V2 as application-lock-v2.json with its matching dev-workflow-result.json")
}

fn package_delivery_identity(root: &Path, network: &str) -> Result<Value, String> {
    let metadata = fs::symlink_metadata(root)
        .map_err(|error| format!("PUBLISH_PACKAGE_READ_ERROR:{error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("PUBLISH_PACKAGE_DIRECTORY_REQUIRED".into());
    }
    let read = |name: &str| read_json(&root.join(name));
    let profile_value = read("profile-lock.json")?;
    let profile = profile_value.get("lock").cloned().unwrap_or(profile_value);
    if let Some(error) = delivery_lock_compatibility_error(&profile) {
        return Err(error.to_owned());
    }
    let artifact = read("artifact.json")?;
    let release = read("release.json")?;
    let binding = read("name-binding.json")?;
    for (name, value) in [
        ("artifact", &artifact),
        ("release", &release),
        ("name-binding", &binding),
    ] {
        if !value.is_object() {
            return Err(format!("PUBLISH_{name}_INVALID"));
        }
        if value.get("network").and_then(Value::as_str) != Some(network) {
            return Err("PUBLISH_PACKAGE_NETWORK_MISMATCH".into());
        }
    }
    ktapeout_runtime::validate_developer_lock(&profile)
        .map_err(|_| "PUBLISH_PROFILE_LOCK_INVALID".to_string())?;
    let application_id = artifact
        .get("application_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "PUBLISH_APPLICATION_ID_MISSING".to_string())?;
    if !valid_hash(application_id)
        || release.get("application_id").and_then(Value::as_str) != Some(application_id)
        || binding
            .get("expected_application_id")
            .and_then(Value::as_str)
            != Some(application_id)
    {
        return Err("PUBLISH_APPLICATION_ID_MISMATCH".into());
    }
    let artifact_root = artifact
        .get("artifact_root")
        .and_then(Value::as_str)
        .ok_or_else(|| "PUBLISH_ARTIFACT_ROOT_MISSING".to_string())?;
    if !valid_hash(artifact_root)
        || release.get("artifact_root").and_then(Value::as_str) != Some(artifact_root)
        || binding
            .get("expected_artifact_root")
            .and_then(Value::as_str)
            != Some(artifact_root)
    {
        return Err("PUBLISH_ARTIFACT_ROOT_MISMATCH".into());
    }
    let release_id = release
        .get("release_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "PUBLISH_RELEASE_ID_MISSING".to_string())?;
    if !valid_hash(release_id)
        || binding.get("expected_release_id").and_then(Value::as_str) != Some(release_id)
    {
        return Err("PUBLISH_RELEASE_ID_MISMATCH".into());
    }
    let canonical_uri = binding
        .get("canonical_uri")
        .and_then(Value::as_str)
        .ok_or_else(|| "PUBLISH_CANONICAL_NAME_MISSING".to_string())?;
    let normalized = normalize_name_value(canonical_uri, None)?;
    if normalized.get("canonical_uri").and_then(Value::as_str) != Some(canonical_uri) {
        return Err("PUBLISH_CANONICAL_NAME_NOT_NORMALIZED".into());
    }
    let profile_lock_hash = profile
        .get("lock_hash")
        .and_then(Value::as_str)
        .filter(|value| valid_hash(value))
        .map(str::to_owned)
        .unwrap_or(digest_json_domain(
            &profile,
            "KTAPEOUT/0.5.0/PROFILE_LOCK/V1",
        )?);
    let package_sidecar_exists = |path: &Path| -> Result<bool, String> {
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_file() => Ok(true),
            Ok(_) => Err("PUBLISH_APPLICATION_EVIDENCE_SIDECAR_NOT_REGULAR_FILE".into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(format!(
                "PUBLISH_APPLICATION_EVIDENCE_SIDECAR_READ_ERROR:{error}"
            )),
        }
    };
    let application_lock_path = root.join("application-lock-v2.json");
    let workflow_result_path = root.join("dev-workflow-result.json");
    let application_lock_exists = package_sidecar_exists(&application_lock_path)?;
    let workflow_result_exists = package_sidecar_exists(&workflow_result_path)?;
    if application_lock_exists != workflow_result_exists {
        return Err("PUBLISH_APPLICATION_EVIDENCE_PAIR_REQUIRED: include both application-lock-v2.json and dev-workflow-result.json".into());
    }
    let mut identity = json!({"application_id":application_id,"release_id":release_id,"artifact_root":artifact_root,"canonical_uri":canonical_uri,"profile_lock_hash":profile_lock_hash});
    if artifact.get("runtime_manifest").is_some()
        || artifact.get("runtime_manifest_sha256").is_some()
        || fs::symlink_metadata(root.join("runtime")).is_ok()
    {
        identity["runtime_evidence"] = package_build::verify_publication_runtime(
            root,
            &artifact,
            network,
            canonical_uri,
            release_id,
            artifact_root,
        )?;
    }
    let content_artifact_path = root.join("content-artifact.json");
    if package_sidecar_exists(&content_artifact_path)? {
        let raw = read_bounded_file(
            &content_artifact_path,
            256 * 1024,
            "PUBLISH_CONTENT_ARTIFACT_READ",
        )
        .map_err(|error| {
            if error == "INPUT_FILE_TOO_LARGE" {
                "PUBLISH_CONTENT_ARTIFACT_OVERSIZED".to_string()
            } else {
                error
            }
        })?;
        let projection = verify_content_artifact_050(&raw)
            .map_err(|_| "PUBLISH_CONTENT_ARTIFACT_INVALID".to_string())?;
        let projection = parse_strict_json(&projection)
            .map_err(|_| "PUBLISH_CONTENT_ARTIFACT_PROJECTION_INVALID".to_string())?;
        if projection.get("artifact_sha256").and_then(Value::as_str) != Some(artifact_root) {
            return Err("PUBLISH_CONTENT_ARTIFACT_ROOT_MISMATCH".into());
        }
        identity["content_artifact_evidence"] = projection;
    }
    if application_lock_exists {
        let application_lock = read_json(&application_lock_path)?;
        profile_governance::validate_application_lock_v2(&application_lock)
            .map_err(|_| "PUBLISH_APPLICATION_LOCK_V2_INVALID".to_string())?;
        let workflow_result = read_json(&workflow_result_path)?;
        let workflow_data = workflow_result
            .get("data")
            .ok_or_else(|| "PUBLISH_APPLICATION_EVIDENCE_WORKFLOW_RESULT_INVALID".to_string())?;
        if workflow_result.get("status").and_then(Value::as_str) != Some("PASS")
            || workflow_result.get("network").and_then(Value::as_str) != Some(network)
            || workflow_data.get("status").and_then(Value::as_str) != Some("PASS")
            || workflow_data["application_lock"]["status"] != "SELF_CONSISTENT"
            || workflow_data["application_lock"]["lock_hash"] != application_lock["lock_hash"]
        {
            return Err("PUBLISH_APPLICATION_EVIDENCE_WORKFLOW_BINDING_INVALID".into());
        }
        let evidence = workflow_data
            .get("application_evidence")
            .ok_or_else(|| "PUBLISH_APPLICATION_EVIDENCE_MISSING".to_string())?;
        dev_workflow::validate_application_evidence_for_delivery(
            evidence,
            application_lock["lock_hash"].as_str().unwrap_or_default(),
            artifact_root,
        )?;
        identity["application_lock_hash"] = application_lock["lock_hash"].clone();
        identity["application_evidence_digest"] = evidence["evidence_digest"].clone();
    }
    Ok(identity)
}

fn timestamp_delta_seconds(created: &UtcTimestamp, expires: &UtcTimestamp) -> Option<i64> {
    fn seconds(value: &UtcTimestamp) -> Option<i64> {
        let (year, month, day, hour, minute, second) = value.calendar;
        if year < 1970 {
            return None;
        }
        let mut days = 0i64;
        for candidate in 1970..year {
            days += if candidate % 4 == 0 && (candidate % 100 != 0 || candidate % 400 == 0) {
                366
            } else {
                365
            };
        }
        for candidate in 1..month {
            days += match candidate {
                2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
                2 => 28,
                4 | 6 | 9 | 11 => 30,
                _ => 31,
            };
        }
        Some(
            (days + i64::from(day - 1)) * 86_400
                + i64::from(hour) * 3600
                + i64::from(minute) * 60
                + i64::from(second),
        )
    }
    Some(seconds(expires)? - seconds(created)?)
}

fn validate_delivery_intent_value(intent: &Value, policy: &Value) -> Result<(), String> {
    let base_required = [
        "schema",
        "protocol_semver",
        "operation_id",
        "idempotency_key",
        "network",
        "network_policy_hash",
        "operation_kind",
        "application_id",
        "release_id",
        "artifact_root",
        "profile_lock_hash",
        "canonical_name",
        "max_fee_sompi",
        "max_bond_sompi",
        "max_value_sompi",
        "created_at",
        "expires_at",
        "intent_hash",
    ];
    let object = intent
        .as_object()
        .ok_or_else(|| "DELIVERY_INTENT_NOT_OBJECT".to_string())?;
    let schema = intent
        .get("schema")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let is_v2 = schema == "KTAPEOUT-APPLICATION-DELIVERY-INTENT-V2";
    let mut required: Vec<&str> = base_required.to_vec();
    if is_v2 {
        required.extend(["application_lock_hash", "application_evidence_digest"]);
    }
    if object.len() != required.len()
        || required.iter().any(|field| !object.contains_key(*field))
        || !matches!(
            schema,
            "KTAPEOUT-APPLICATION-DELIVERY-INTENT-V1" | "KTAPEOUT-APPLICATION-DELIVERY-INTENT-V2"
        )
        || intent.get("protocol_semver").and_then(Value::as_str) != Some(PROTOCOL)
    {
        return Err("DELIVERY_INTENT_FIELDS_INVALID".into());
    }
    if is_v2 {
        if intent.get("operation_kind").and_then(Value::as_str) != Some("APPLICATION_PUBLISH") {
            return Err("DELIVERY_INTENT_V2_KIND_INVALID".into());
        }
        for field in ["application_lock_hash", "application_evidence_digest"] {
            if intent
                .get(field)
                .and_then(Value::as_str)
                .filter(|value| valid_hash(value))
                .is_none()
            {
                return Err(format!("DELIVERY_INTENT_{field}_INVALID"));
            }
        }
    }
    validate_delivery_policy_value(policy)?;
    let network = intent
        .get("network")
        .and_then(Value::as_str)
        .ok_or_else(|| "DELIVERY_INTENT_NETWORK_INVALID".to_string())?;
    if network != policy.get("network").and_then(Value::as_str).unwrap_or("")
        || intent.get("network_policy_hash") != policy.get("policy_hash")
    {
        return Err("DELIVERY_INTENT_POLICY_MISMATCH".into());
    }
    let operation_suffix = intent
        .get("operation_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .strip_prefix("op_")
        .unwrap_or_default();
    if operation_suffix.len() != 32
        || !operation_suffix
            .chars()
            .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
    {
        return Err("DELIVERY_INTENT_OPERATION_ID_INVALID".into());
    }
    for field in [
        "idempotency_key",
        "network_policy_hash",
        "application_id",
        "release_id",
        "artifact_root",
        "profile_lock_hash",
        "intent_hash",
    ] {
        if intent
            .get(field)
            .and_then(Value::as_str)
            .filter(|value| valid_hash(value))
            .is_none()
        {
            return Err(format!("DELIVERY_INTENT_{field}_INVALID"));
        }
    }
    if !matches!(
        intent.get("operation_kind").and_then(Value::as_str),
        Some(
            "APPLICATION_PUBLISH"
                | "NAME_REGISTER"
                | "NAME_REBIND"
                | "NAME_TRANSFER"
                | "NAME_RELEASE"
                | "STATE_TRANSITION"
        )
    ) {
        return Err("DELIVERY_INTENT_KIND_INVALID".into());
    }
    let canonical = intent
        .get("canonical_name")
        .and_then(Value::as_str)
        .ok_or_else(|| "DELIVERY_INTENT_NAME_INVALID".to_string())?;
    if normalize_name_value(canonical, None)?
        .get("canonical_uri")
        .and_then(Value::as_str)
        != Some(canonical)
    {
        return Err("DELIVERY_INTENT_NAME_NOT_NORMALIZED".into());
    }
    let created = parse_utc_timestamp(
        intent
            .get("created_at")
            .and_then(Value::as_str)
            .unwrap_or(""),
    )
    .ok_or_else(|| "DELIVERY_INTENT_CREATED_AT_INVALID".to_string())?;
    let expires = parse_utc_timestamp(
        intent
            .get("expires_at")
            .and_then(Value::as_str)
            .unwrap_or(""),
    )
    .ok_or_else(|| "DELIVERY_INTENT_EXPIRES_AT_INVALID".to_string())?;
    let delta = timestamp_delta_seconds(&created, &expires)
        .ok_or_else(|| "DELIVERY_INTENT_TIMESTAMP_INVALID".to_string())?;
    if delta <= 0
        || delta
            > policy
                .get("plan_ttl_seconds")
                .and_then(Value::as_u64)
                .unwrap_or(0) as i64
    {
        return Err("DELIVERY_INTENT_EXPIRY_INVALID".into());
    }
    for field in ["max_fee_sompi", "max_bond_sompi", "max_value_sompi"] {
        if is_v2
            && intent
                .get(field)
                .and_then(Value::as_u64)
                .is_some_and(|value| value > 9_007_199_254_740_991)
        {
            return Err(format!("DELIVERY_INTENT_{field}_UNSAFE_JSON_INTEGER"));
        }
        if intent
            .get(field)
            .and_then(Value::as_u64)
            .unwrap_or(u64::MAX)
            > policy.get(field).and_then(Value::as_u64).unwrap_or(0)
        {
            return Err(format!("DELIVERY_INTENT_{field}_EXCEEDS_POLICY"));
        }
    }
    let mut material = object.clone();
    material.remove("intent_hash");
    let domain = if is_v2 {
        "KTAPEOUT/0.5.0/APPLICATION_DELIVERY_INTENT/V2"
    } else {
        "KTAPEOUT/0.5.0/APPLICATION_DELIVERY_INTENT/V1"
    };
    let expected = digest_json_domain(&Value::Object(material), domain)?;
    if intent.get("intent_hash").and_then(Value::as_str) != Some(expected.as_str()) {
        return Err("DELIVERY_INTENT_HASH_MISMATCH".into());
    }
    Ok(())
}

fn validate_delivery_provider_value(provider: &Value) -> Result<(), String> {
    let required = [
        "schema",
        "protocol_semver",
        "provider_id",
        "local",
        "networks",
        "operation_kinds",
        "signer_handoff",
        "verifier_build_hash",
        "readback_policy_hash",
    ];
    let object = provider
        .as_object()
        .ok_or_else(|| "DELIVERY_PROVIDER_NOT_OBJECT".to_string())?;
    if object.len() != required.len()
        || required.iter().any(|field| !object.contains_key(*field))
        || provider.get("schema").and_then(Value::as_str) != Some("KTAPEOUT-OPERATOR-PROVIDER-V1")
        || provider.get("protocol_semver").and_then(Value::as_str) != Some(PROTOCOL)
        || provider.get("local") != Some(&Value::Bool(true))
    {
        return Err("DELIVERY_PROVIDER_FIELDS_INVALID".into());
    }
    for field in ["verifier_build_hash", "readback_policy_hash"] {
        if provider
            .get(field)
            .and_then(Value::as_str)
            .filter(|value| valid_hash(value))
            .is_none()
        {
            return Err(format!("DELIVERY_PROVIDER_{field}_INVALID"));
        }
    }
    if provider
        .get("provider_id")
        .and_then(Value::as_str)
        .is_none_or(|value| value.is_empty() || value.len() > 64)
        || provider
            .get("signer_handoff")
            .and_then(Value::as_str)
            .is_none_or(|value| value.is_empty() || value.len() > 64)
    {
        return Err("DELIVERY_PROVIDER_ID_INVALID".into());
    }
    for (field, allowed) in [
        ("networks", vec!["testnet-10", "mainnet"]),
        (
            "operation_kinds",
            vec![
                "APPLICATION_PUBLISH",
                "NAME_REGISTER",
                "NAME_REBIND",
                "NAME_TRANSFER",
                "NAME_RELEASE",
                "STATE_TRANSITION",
            ],
        ),
    ] {
        let values = provider
            .get(field)
            .and_then(Value::as_array)
            .ok_or_else(|| format!("DELIVERY_PROVIDER_{field}_INVALID"))?;
        let mut previous = "";
        for value in values {
            let value = value
                .as_str()
                .ok_or_else(|| format!("DELIVERY_PROVIDER_{field}_INVALID"))?;
            if !allowed.contains(&value) || value <= previous {
                return Err(format!("DELIVERY_PROVIDER_{field}_INVALID"));
            }
            previous = value;
        }
    }
    Ok(())
}

fn validate_operator_plan_value(plan: &Value) -> Result<(), String> {
    let object = plan
        .as_object()
        .ok_or_else(|| "OPERATOR_PLAN_NOT_OBJECT".to_string())?;
    let required = [
        "schema",
        "protocol_semver",
        "intent_hash",
        "network",
        "network_policy_hash",
        "provider_id",
        "unsigned_tx_digest",
        "max_fee_sompi",
        "max_bond_sompi",
        "max_value_sompi",
        "expires_at",
        "review_digest",
        "plan_hash",
    ];
    if object.len() != required.len() || required.iter().any(|field| !object.contains_key(*field)) {
        return Err("OPERATOR_PLAN_FIELDS_INVALID".into());
    }
    if plan["schema"] != "KTAPEOUT-OPERATOR-PLAN-V1"
        || plan["protocol_semver"] != PROTOCOL
        || !matches!(plan["network"].as_str(), Some("testnet-10" | "mainnet"))
    {
        return Err("OPERATOR_PLAN_IDENTITY_INVALID".into());
    }
    for field in [
        "intent_hash",
        "network_policy_hash",
        "unsigned_tx_digest",
        "review_digest",
        "plan_hash",
    ] {
        if plan[field]
            .as_str()
            .filter(|candidate| valid_hash(candidate))
            .is_none()
        {
            return Err(format!("OPERATOR_PLAN_{field}_INVALID"));
        }
    }
    for field in ["max_fee_sompi", "max_bond_sompi", "max_value_sompi"] {
        if plan[field].as_u64().is_none() {
            return Err(format!("OPERATOR_PLAN_{field}_INVALID"));
        }
    }
    for field in ["provider_id", "expires_at"] {
        if plan[field]
            .as_str()
            .filter(|candidate| !candidate.is_empty() && candidate.len() <= 64)
            .is_none()
        {
            return Err(format!("OPERATOR_PLAN_{field}_INVALID"));
        }
    }
    let mut material = object.clone();
    let claimed = material
        .remove("plan_hash")
        .and_then(|entry| entry.as_str().map(str::to_owned))
        .ok_or_else(|| "OPERATOR_PLAN_HASH_INVALID".to_string())?;
    let expected = digest_json_domain(&Value::Object(material), "KTAPEOUT/0.5.0/OPERATOR_PLAN/V1")?;
    if claimed != expected {
        return Err("OPERATOR_PLAN_HASH_MISMATCH".into());
    }
    if canonical_json(plan)?.len() > 32 * 1024 {
        return Err("OPERATOR_PLAN_OVERSIZED".into());
    }
    Ok(())
}

fn publish_preflight(
    intent_path: PathBuf,
    policy_path: PathBuf,
    provider_path: PathBuf,
) -> Result<(), String> {
    let intent = read_json(&intent_path)?;
    let policy = read_json(&policy_path)?;
    let provider = read_json(&provider_path)?;
    validate_delivery_intent_value(&intent, &policy)?;
    validate_delivery_provider_value(&provider)?;
    let network = intent
        .get("network")
        .and_then(Value::as_str)
        .ok_or_else(|| "DELIVERY_INTENT_NETWORK_INVALID".to_string())?;
    let kind = intent
        .get("operation_kind")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let networks = provider
        .get("networks")
        .and_then(Value::as_array)
        .ok_or_else(|| "DELIVERY_PROVIDER_NETWORKS_INVALID".to_string())?;
    let kinds = provider
        .get("operation_kinds")
        .and_then(Value::as_array)
        .ok_or_else(|| "DELIVERY_PROVIDER_OPERATION_KINDS_INVALID".to_string())?;
    if !networks.iter().any(|value| value.as_str() == Some(network))
        || !kinds.iter().any(|value| value.as_str() == Some(kind))
    {
        return Err("DELIVERY_PROVIDER_CAPABILITY_MISMATCH".into());
    }
    emit_result(
        "ktape publish preflight",
        Some(network),
        json!({"delivery_state":"LOCAL_PREFLIGHT_PASSED","intent_hash":intent["intent_hash"],"provider_id":provider["provider_id"],"next_action":"OPERATOR_NATIVE_PREFLIGHT_REQUIRED","missing_evidence":["fresh_utxo","native_vm","exact_transaction","independent_readback"],"signing_allowed":false,"broadcast":false}),
    )
}

struct LocalWriterLock {
    path: PathBuf,
    metadata: Vec<u8>,
}

impl Drop for LocalWriterLock {
    fn drop(&mut self) {
        if fs::read(&self.path).ok().as_deref() == Some(self.metadata.as_slice()) {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn acquire_local_writer_lock(path: &Path) -> Result<LocalWriterLock, String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("INPUT_RESERVATION_DIRECTORY_ERROR:{error}"))?;
    }
    let lock_path = path.with_file_name(format!(
        "{}.lock",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("ledger")
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    let mut file = options
        .open(&lock_path)
        .map_err(|error| format!("INPUT_RESERVATION_LOCK_HELD:{error}"))?;
    let payload = canonical_json(&json!({
        "schema":"KTAPEOUT-INPUT-RESERVATION-WRITER-LOCK-V1",
        "pid":std::process::id(),
        "created_at_ns":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |value| value.as_nanos())
    }))?;
    file.write_all(&payload)
        .map_err(|error| format!("INPUT_RESERVATION_LOCK_WRITE_ERROR:{error}"))?;
    file.sync_all()
        .map_err(|error| format!("INPUT_RESERVATION_LOCK_SYNC_ERROR:{error}"))?;
    Ok(LocalWriterLock {
        path: lock_path,
        metadata: payload,
    })
}

fn valid_reservation_outpoint(value: &str) -> bool {
    let Some((txid, index)) = value.split_once(':') else {
        return false;
    };
    valid_hash(txid)
        && !index.is_empty()
        && index.len() <= 10
        && index.bytes().all(|byte| byte.is_ascii_digit())
}

fn sorted_reservation_outpoints(values: &[String]) -> Result<Vec<String>, String> {
    if values.is_empty() || values.len() > 64 {
        return Err("INPUT_RESERVATION_OUTPOINTS_INVALID".into());
    }
    let mut sorted = values.to_vec();
    sorted.sort();
    sorted.dedup();
    if sorted.len() != values.len()
        || sorted
            .iter()
            .any(|value| !valid_reservation_outpoint(value))
    {
        return Err("INPUT_RESERVATION_OUTPOINTS_INVALID".into());
    }
    Ok(sorted)
}

fn reservation_ledger_hash(value: &Value) -> Result<String, String> {
    let mut material = value
        .as_object()
        .cloned()
        .ok_or_else(|| "INPUT_RESERVATION_LEDGER_INVALID".to_string())?;
    material.remove("ledger_hash");
    digest_json_domain(
        &Value::Object(material),
        "KTAPEOUT/0.5.0/INPUT_RESERVATION_LEDGER/V1",
    )
}

fn validate_reservation_ledger(value: &Value) -> Result<(), String> {
    let required = [
        "schema",
        "protocol_semver",
        "network",
        "wallet_reference_hash",
        "reservations",
        "ledger_hash",
    ];
    let object = value
        .as_object()
        .ok_or_else(|| "INPUT_RESERVATION_LEDGER_INVALID".to_string())?;
    if object.len() != required.len()
        || required.iter().any(|field| !object.contains_key(*field))
        || value.get("schema").and_then(Value::as_str)
            != Some("KTAPEOUT-INPUT-RESERVATION-LEDGER-V1")
        || value.get("protocol_semver").and_then(Value::as_str) != Some(PROTOCOL)
        || !matches!(
            value.get("network").and_then(Value::as_str),
            Some("testnet-10" | "mainnet")
        )
    {
        return Err("INPUT_RESERVATION_LEDGER_IDENTITY_INVALID".into());
    }
    for field in ["wallet_reference_hash", "ledger_hash"] {
        if value
            .get(field)
            .and_then(Value::as_str)
            .filter(|value| valid_hash(value))
            .is_none()
        {
            return Err(format!("INPUT_RESERVATION_{field}_INVALID"));
        }
    }
    let reservations = value
        .get("reservations")
        .and_then(Value::as_object)
        .ok_or_else(|| "INPUT_RESERVATION_ENTRIES_INVALID".to_string())?;
    if reservations.len() > 128 {
        return Err("INPUT_RESERVATION_ENTRIES_INVALID".into());
    }
    for (outpoint, record) in reservations {
        if !valid_reservation_outpoint(outpoint) {
            return Err("INPUT_RESERVATION_ENTRY_INVALID".into());
        }
        let record = record
            .as_object()
            .ok_or_else(|| "INPUT_RESERVATION_ENTRY_INVALID".to_string())?;
        if record.len() != 3
            || !record.contains_key("operation_id")
            || !record.contains_key("intent_hash")
            || !record.contains_key("plan_hash")
        {
            return Err("INPUT_RESERVATION_ENTRY_INVALID".into());
        }
        let operation = record
            .get("operation_id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !operation.starts_with("op_")
            || operation.len() != 35
            || !operation[3..]
                .chars()
                .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
        {
            return Err("INPUT_RESERVATION_OPERATION_ID_INVALID".into());
        }
        for field in ["intent_hash", "plan_hash"] {
            if !record.get(field).is_some_and(Value::is_null)
                && record
                    .get(field)
                    .and_then(Value::as_str)
                    .filter(|value| valid_hash(value))
                    .is_none()
            {
                return Err(format!("INPUT_RESERVATION_{field}_INVALID"));
            }
        }
    }
    if value.get("ledger_hash").and_then(Value::as_str)
        != Some(reservation_ledger_hash(value)?.as_str())
    {
        return Err("INPUT_RESERVATION_LEDGER_HASH_MISMATCH".into());
    }
    Ok(())
}

fn publish_reserve(
    intent_path: PathBuf,
    policy_path: PathBuf,
    wallet_reference_hash: String,
    outpoints: Vec<String>,
    ledger_path: PathBuf,
) -> Result<(), String> {
    let intent = read_json(&intent_path)?;
    let policy = read_json(&policy_path)?;
    validate_delivery_intent_value(&intent, &policy)?;
    if !valid_hash(&wallet_reference_hash) {
        return Err("INPUT_RESERVATION_WALLET_REFERENCE_INVALID".into());
    }
    let selected = sorted_reservation_outpoints(&outpoints)?;
    let _lock = acquire_local_writer_lock(&ledger_path)?;
    let mut ledger = if ledger_path.exists() {
        let ledger = read_json(&ledger_path)?;
        validate_reservation_ledger(&ledger)?;
        ledger
    } else {
        let mut ledger = json!({"schema":"KTAPEOUT-INPUT-RESERVATION-LEDGER-V1","protocol_semver":PROTOCOL,"network":intent["network"],"wallet_reference_hash":wallet_reference_hash,"reservations":{},"ledger_hash":"0".repeat(64)});
        let hash = reservation_ledger_hash(&ledger)?;
        ledger["ledger_hash"] = Value::String(hash);
        validate_reservation_ledger(&ledger)?;
        ledger
    };
    if ledger["network"] != intent["network"]
        || ledger["wallet_reference_hash"] != wallet_reference_hash
    {
        return Err("INPUT_RESERVATION_LEDGER_CONTEXT_MISMATCH".into());
    }
    let operation_id = intent
        .get("operation_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "DELIVERY_INTENT_OPERATION_ID_INVALID".to_string())?;
    let intent_hash = intent
        .get("intent_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| "DELIVERY_INTENT_HASH_INVALID".to_string())?;
    let reservation_count;
    {
        let reservations = ledger["reservations"]
            .as_object_mut()
            .ok_or_else(|| "INPUT_RESERVATION_ENTRIES_INVALID".to_string())?;
        let mut conflicts = Vec::new();
        for outpoint in &selected {
            if let Some(record) = reservations.get(outpoint) {
                if record.get("operation_id").and_then(Value::as_str) != Some(operation_id)
                    || record.get("intent_hash").and_then(Value::as_str) != Some(intent_hash)
                {
                    conflicts.push(outpoint.clone());
                }
            }
        }
        if !conflicts.is_empty() {
            return Err("INPUTS_RESERVED".into());
        }
        for outpoint in &selected {
            reservations.entry(outpoint.clone()).or_insert_with(
                || json!({"operation_id":operation_id,"intent_hash":intent_hash,"plan_hash":null}),
            );
        }
        reservation_count = reservations.len();
    }
    let hash = reservation_ledger_hash(&ledger)?;
    ledger["ledger_hash"] = Value::String(hash.clone());
    validate_reservation_ledger(&ledger)?;
    let bytes = canonical_json(&ledger)?;
    let payload = bytes
        .iter()
        .copied()
        .chain(std::iter::once(b'\n'))
        .collect::<Vec<u8>>();
    atomic_write_file(
        &ledger_path,
        &payload,
        "INPUT_RESERVATION_LEDGER_WRITE_ERROR",
    )?;
    emit_result(
        "ktape publish reserve",
        intent.get("network").and_then(Value::as_str),
        json!({"delivery_state":"INPUTS_RESERVED","ledger_hash":hash,"reserved_input_count":reservation_count,"safe_to_retry":true,"signing_allowed":false,"broadcast":false}),
    )
}

fn validate_delivery_operation_binding_value(value: &Value) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or_else(|| "DELIVERY_OPERATION_BINDING_INVALID".to_string())?;
    let required = [
        "schema",
        "protocol_semver",
        "operation_id",
        "project_lock_hash",
        "intent_hash",
        "plan_hash",
        "network",
        "network_policy_hash",
        "provider_id",
        "binding_hash",
    ];
    let allowed = [
        "schema",
        "protocol_semver",
        "operation_id",
        "project_lock_hash",
        "intent_hash",
        "plan_hash",
        "network",
        "network_policy_hash",
        "provider_id",
        "binding_hash",
        "maintenance_plan_hash",
    ];
    if object.len() < required.len()
        || required.iter().any(|field| !object.contains_key(*field))
        || object
            .keys()
            .any(|field| !allowed.iter().any(|allowed| allowed == field))
    {
        return Err("DELIVERY_OPERATION_BINDING_FIELDS_INVALID".into());
    }
    if value["schema"] != "KTAPEOUT-DELIVERY-OPERATION-BINDING-V1"
        || value["protocol_semver"] != PROTOCOL
    {
        return Err("DELIVERY_OPERATION_BINDING_IDENTITY_INVALID".into());
    }
    let operation_id = value["operation_id"]
        .as_str()
        .filter(|candidate| {
            candidate.starts_with("op_")
                && candidate.len() == 35
                && candidate[3..].chars().all(|character| {
                    character.is_ascii_hexdigit() && !character.is_ascii_uppercase()
                })
        })
        .ok_or_else(|| "DELIVERY_OPERATION_BINDING_OPERATION_ID_INVALID".to_string())?;
    let _ = operation_id;
    if !matches!(value["network"].as_str(), Some("testnet-10" | "mainnet")) {
        return Err("DELIVERY_OPERATION_BINDING_NETWORK_INVALID".into());
    }
    if value["provider_id"]
        .as_str()
        .filter(|candidate| !candidate.is_empty() && candidate.len() <= 64)
        .is_none()
    {
        return Err("DELIVERY_OPERATION_BINDING_PROVIDER_INVALID".into());
    }
    for field in [
        "project_lock_hash",
        "intent_hash",
        "plan_hash",
        "network_policy_hash",
        "binding_hash",
    ] {
        if value[field]
            .as_str()
            .filter(|candidate| valid_hash(candidate))
            .is_none()
        {
            return Err(format!("DELIVERY_OPERATION_BINDING_{field}_INVALID"));
        }
    }
    if let Some(maintenance_plan_hash) = value.get("maintenance_plan_hash") {
        if maintenance_plan_hash
            .as_str()
            .filter(|candidate| valid_hash(candidate))
            .is_none()
        {
            return Err("DELIVERY_OPERATION_BINDING_MAINTENANCE_PLAN_HASH_INVALID".into());
        }
    }
    let mut material = object.clone();
    let claimed = material
        .remove("binding_hash")
        .and_then(|entry| entry.as_str().map(str::to_owned))
        .ok_or_else(|| "DELIVERY_OPERATION_BINDING_HASH_INVALID".to_string())?;
    let expected = digest_json_domain(
        &Value::Object(material),
        "KTAPEOUT/0.5.0/DELIVERY_OPERATION_BINDING/V1",
    )?;
    if claimed != expected {
        return Err("DELIVERY_OPERATION_BINDING_HASH_MISMATCH".into());
    }
    if canonical_json(value)?.len() > 8 * 1024 {
        return Err("DELIVERY_OPERATION_BINDING_OVERSIZED".into());
    }
    Ok(())
}

fn publish_release_reservation(
    binding_path: PathBuf,
    wallet_reference_hash: String,
    outpoints: Vec<String>,
    ledger_path: PathBuf,
    terminal_stage: String,
) -> Result<(), String> {
    let binding = read_json(&binding_path)?;
    validate_delivery_operation_binding_value(&binding)?;
    if !matches!(terminal_stage.as_str(), "CONFIRMED" | "REJECTED") {
        return Err("INPUT_RESERVATION_RELEASE_TERMINAL_STAGE_INVALID".into());
    }
    if !valid_hash(&wallet_reference_hash) {
        return Err("INPUT_RESERVATION_WALLET_REFERENCE_INVALID".into());
    }
    let selected = sorted_reservation_outpoints(&outpoints)?;
    let _lock = acquire_local_writer_lock(&ledger_path)?;
    let mut ledger = read_json(&ledger_path)?;
    validate_reservation_ledger(&ledger)?;
    if ledger["network"] != binding["network"]
        || ledger["wallet_reference_hash"] != wallet_reference_hash
    {
        return Err("INPUT_RESERVATION_LEDGER_CONTEXT_MISMATCH".into());
    }
    let expected = json!({"operation_id": binding["operation_id"], "intent_hash": binding["intent_hash"], "plan_hash": binding["plan_hash"]});
    for outpoint in &selected {
        if ledger["reservations"].get(outpoint) != Some(&expected) {
            return Err("INPUT_RESERVATION_OWNERSHIP_MISMATCH".into());
        }
    }
    let reservation_count;
    {
        let reservations = ledger["reservations"]
            .as_object_mut()
            .ok_or_else(|| "INPUT_RESERVATION_ENTRIES_INVALID".to_string())?;
        for outpoint in &selected {
            reservations.remove(outpoint);
        }
        reservation_count = reservations.len();
    }
    let hash = reservation_ledger_hash(&ledger)?;
    ledger["ledger_hash"] = Value::String(hash.clone());
    validate_reservation_ledger(&ledger)?;
    let bytes = canonical_json(&ledger)?;
    let payload = bytes
        .iter()
        .copied()
        .chain(std::iter::once(b'\n'))
        .collect::<Vec<u8>>();
    atomic_write_file(
        &ledger_path,
        &payload,
        "INPUT_RESERVATION_LEDGER_WRITE_ERROR",
    )?;
    emit_result(
        "ktape publish release-reservation",
        binding.get("network").and_then(Value::as_str),
        json!({"delivery_state":"INPUTS_RELEASED","ledger_hash":hash,"reserved_input_count":reservation_count,"terminal_stage":terminal_stage,"safe_to_retry":true,"signing_allowed":false,"broadcast":false}),
    )
}

fn publish_receipt_verify(receipt_path: PathBuf) -> Result<(), String> {
    let receipt = read_json(&receipt_path)?;
    validate_receipt_value(&receipt)?;
    let status = receipt
        .get("status")
        .and_then(Value::as_str)
        .ok_or_else(|| "RECEIPT_STATUS_INVALID".to_string())?;
    emit_result(
        "ktape publish receipt-verify",
        receipt.get("network").and_then(Value::as_str),
        json!({
            "delivery_state": status,
            "receipt": receipt,
            "signing_allowed": false,
            "broadcast": false
        }),
    )
}

fn validate_delivery_operation_receipt_value(value: &Value) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or_else(|| "DELIVERY_OPERATION_RECEIPT_INVALID".to_string())?;
    let required = [
        "schema",
        "protocol_semver",
        "plan_hash",
        "network",
        "network_policy_hash",
        "signed_tx_digest",
        "status",
        "readback_sources",
        "verification_level",
        "receipt_hash",
    ];
    let allowed = [
        "schema",
        "protocol_semver",
        "plan_hash",
        "network",
        "network_policy_hash",
        "signed_tx_digest",
        "status",
        "readback_sources",
        "verification_level",
        "receipt_hash",
        "maintenance_plan_hash",
    ];
    if object.len() < required.len()
        || required.iter().any(|field| !object.contains_key(*field))
        || object
            .keys()
            .any(|field| !allowed.iter().any(|allowed| allowed == field))
    {
        return Err("DELIVERY_OPERATION_RECEIPT_FIELDS_INVALID".into());
    }
    if value["schema"] != "KTAPEOUT-OPERATION-RECEIPT-V1" {
        return Err("DELIVERY_OPERATION_RECEIPT_IDENTITY_INVALID".into());
    }
    if value["protocol_semver"] != PROTOCOL
        || !matches!(value["network"].as_str(), Some("testnet-10" | "mainnet"))
        || !matches!(
            value["status"].as_str(),
            Some("SUBMITTED" | "UNKNOWN_SUBMISSION" | "READBACK_VERIFIED" | "REJECTED")
        )
    {
        return Err("DELIVERY_OPERATION_RECEIPT_IDENTITY_INVALID".into());
    }
    for field in [
        "plan_hash",
        "network_policy_hash",
        "signed_tx_digest",
        "receipt_hash",
    ] {
        if value[field]
            .as_str()
            .filter(|candidate| valid_hash(candidate))
            .is_none()
        {
            return Err(format!("DELIVERY_OPERATION_RECEIPT_{field}_INVALID"));
        }
    }
    if value["verification_level"]
        .as_str()
        .filter(|candidate| !candidate.is_empty() && candidate.len() <= 64)
        .is_none()
    {
        return Err("DELIVERY_OPERATION_RECEIPT_VERIFICATION_LEVEL_INVALID".into());
    }
    if let Some(maintenance_plan_hash) = value.get("maintenance_plan_hash") {
        if maintenance_plan_hash
            .as_str()
            .filter(|candidate| valid_hash(candidate))
            .is_none()
        {
            return Err("DELIVERY_OPERATION_RECEIPT_MAINTENANCE_PLAN_HASH_INVALID".into());
        }
    }
    let sources = value["readback_sources"]
        .as_array()
        .ok_or_else(|| "DELIVERY_OPERATION_RECEIPT_SOURCES_INVALID".to_string())?;
    if sources.len() > 8 {
        return Err("DELIVERY_OPERATION_RECEIPT_SOURCES_INVALID".into());
    }
    let mut seen = std::collections::BTreeSet::new();
    for source in sources {
        let source = source
            .as_str()
            .filter(|candidate| !candidate.is_empty())
            .ok_or_else(|| "DELIVERY_OPERATION_RECEIPT_SOURCES_INVALID".to_string())?;
        if !seen.insert(source.to_string()) {
            return Err("DELIVERY_OPERATION_RECEIPT_SOURCES_INVALID".into());
        }
    }
    let mut material = object.clone();
    let claimed = material
        .remove("receipt_hash")
        .and_then(|entry| entry.as_str().map(str::to_owned))
        .ok_or_else(|| "DELIVERY_OPERATION_RECEIPT_HASH_INVALID".to_string())?;
    if claimed
        != digest_json_domain(
            &Value::Object(material),
            "KTAPEOUT/0.5.0/OPERATION_RECEIPT/V1",
        )?
    {
        return Err("DELIVERY_OPERATION_RECEIPT_HASH_MISMATCH".into());
    }
    if canonical_json(value)?.len() > 32 * 1024 {
        return Err("DELIVERY_OPERATION_RECEIPT_OVERSIZED".into());
    }
    Ok(())
}

fn publish_recover(binding_path: PathBuf, receipt_path: PathBuf) -> Result<(), String> {
    let binding = read_json(&binding_path)?;
    let receipt = read_json(&receipt_path)?;
    validate_delivery_operation_binding_value(&binding)?;
    validate_delivery_operation_receipt_value(&receipt)?;
    if receipt["plan_hash"] != binding["plan_hash"]
        || receipt["network"] != binding["network"]
        || receipt["network_policy_hash"] != binding["network_policy_hash"]
        || receipt.get("maintenance_plan_hash") != binding.get("maintenance_plan_hash")
    {
        return Err("DELIVERY_RECOVERY_BINDING_MISMATCH".into());
    }
    let (state, next_action) = match receipt["status"].as_str().unwrap_or_default() {
        "SUBMITTED" | "UNKNOWN_SUBMISSION" => ("NEEDS_CHAIN_LOOKUP", "QUERY_INDEPENDENT_NODES"),
        "READBACK_VERIFIED" => ("READBACK_VERIFIED", "IMPORT_RUNTIME_OR_LIFECYCLE_FOLLOWUP"),
        "REJECTED" => ("TERMINAL", "REVIEW_THEN_RELEASE_RESERVED_INPUTS"),
        _ => return Err("DELIVERY_OPERATION_RECEIPT_STATUS_INVALID".into()),
    };
    emit_result(
        "ktape publish recover",
        binding.get("network").and_then(Value::as_str),
        json!({"delivery_state":state,"operation_id":binding["operation_id"],"binding_hash":binding["binding_hash"],"receipt_hash":receipt["receipt_hash"],"next_action":next_action,"automatic_retry_allowed":false,"automatic_signing_allowed":false,"automatic_broadcast_allowed":false}),
    )
}

fn publish_status(
    operation_path: PathBuf,
    expected_operation_id: String,
    expected_project_lock_hash: String,
    expected_plan_hash: String,
    expected_network: String,
    now: String,
) -> Result<(), String> {
    let value = read_operation_state(&operation_path)?;
    let expiry = value["expiry"]
        .as_str()
        .ok_or_else(|| "OPERATION_EXPIRY_INVALID".to_string())?;
    let order = ktapeout_runtime::compare_utc_timestamps(&now, expiry)
        .ok_or_else(|| "OPERATION_RECOVERY_TIMESTAMP_INVALID".to_string())?;
    let operation_id = value["operation_id"].as_str().unwrap_or_default();
    let project_lock_hash = value["project_lock_hash"].as_str().unwrap_or_default();
    let plan_hash = value["plan_hash"].as_str().unwrap_or_default();
    let network = value["network"].as_str().unwrap_or_default();
    let stage = value["stage"].as_str().unwrap_or_default();
    let binding_matches = operation_id == expected_operation_id
        && project_lock_hash == expected_project_lock_hash
        && plan_hash == expected_plan_hash
        && network == expected_network;
    let (status, reason_code, next_action) = if !binding_matches {
        (
            "BLOCKED",
            "OPERATION_BINDING_MISMATCH",
            "REBUILD_FROM_CURRENT_PROJECT",
        )
    } else {
        match stage {
            "PLANNED" if order != std::cmp::Ordering::Less => {
                ("BLOCKED", "OPERATION_EXPIRED", "REBUILD_UNSIGNED_PLAN")
            }
            "PLANNED" => ("READY", "PREFLIGHT_REQUIRED", "RUN_PREFLIGHT"),
            "SIGNED" => (
                "OPERATOR_REVIEW",
                "SIGNED_PAYLOAD_NOT_PERSISTED",
                "REVALIDATE_INTENT_WITH_OPERATOR",
            ),
            "SUBMITTED" => (
                "NEEDS_CHAIN_LOOKUP",
                "SUBMISSION_MUST_BE_RECONCILED",
                "QUERY_TRANSACTION_STATUS",
            ),
            "SUBMISSION_UNKNOWN" => (
                "NEEDS_CHAIN_LOOKUP",
                "BLIND_RETRY_FORBIDDEN",
                "QUERY_INDEPENDENT_NODES",
            ),
            "CONFIRMED" => (
                "READ_ONLY_VERIFY",
                "CONFIRMATION_REQUIRES_SUCCESSOR_CHECK",
                "VERIFY_SUCCESSOR_STATE",
            ),
            "REJECTED" => (
                "TERMINAL",
                "OPERATION_REJECTED",
                "START_NEW_OPERATION_IF_NEEDED",
            ),
            "REORGED" => (
                "RECOVERY_REQUIRED",
                "REORG_REQUIRES_RECONCILIATION",
                "RECONCILE_CHAIN_STATE",
            ),
            "RECOVERY_REQUIRED" => (
                "OPERATOR_REVIEW",
                "EXPLICIT_RECOVERY_REVIEW_REQUIRED",
                "REBUILD_UNSIGNED_PLAN_AFTER_REVIEW",
            ),
            _ => return Err("OPERATION_STAGE_INVALID".into()),
        }
    };
    let recovery = json!({"schema":"KTAPEOUT-OPERATION-RECOVERY-V1","operation_id":operation_id,"project_lock_hash":project_lock_hash,"plan_hash":plan_hash,"network":network,"stage":stage,"assessed_at":now,"status":status,"reason_code":reason_code,"next_action":next_action,"automatic_retry_allowed":false,"automatic_signing_allowed":false,"automatic_broadcast_allowed":false});
    emit_result(
        "ktape publish status",
        Some(expected_network.as_str()),
        json!({"delivery_state":stage,"recovery":recovery,"signing_allowed":false,"broadcast":false}),
    )
}

fn deployment_plan_value(
    manifest_path: &Path,
    network: &str,
    backend: &str,
    application_lock_path: Option<&Path>,
) -> Result<Value, String> {
    let application_lock = application_lock_path
        .map(read_json)
        .transpose()?
        .map(|value| {
            value
                .get("lock")
                .cloned()
                .or_else(|| value.get("data").and_then(|data| data.get("lock")).cloned())
                .unwrap_or(value)
        });
    deployment_plan_for_source(
        &read_json(manifest_path)?,
        network,
        backend,
        application_lock.as_ref(),
    )
}

fn deployment_plan_for_source(
    source: &Value,
    network: &str,
    backend: &str,
    application_lock: Option<&Value>,
) -> Result<Value, String> {
    if !matches!(network, "testnet-10" | "mainnet") {
        return Err("DEPLOY_NETWORK_INVALID".into());
    }
    validate_manifest_value(source)?;
    let artifact = artifact_build_value(source, backend, "0.5.0")?;
    deployment_plan_for_artifact(source, &artifact, network, application_lock)
}

fn deployment_plan_for_artifact(
    source: &Value,
    artifact: &Value,
    network: &str,
    application_lock: Option<&Value>,
) -> Result<Value, String> {
    if !matches!(network, "testnet-10" | "mainnet") {
        return Err("DEPLOY_NETWORK_INVALID".into());
    }
    validate_manifest_value(source)?;
    let artifact_backend = artifact
        .get("backend")
        .and_then(|value| value.get("id"))
        .and_then(Value::as_str)
        .ok_or("ARTIFACT_SHAPE_INVALID")?;
    let adapter = backend_adapter_descriptor(artifact_backend)?;
    if artifact_backend == "native-kas-bounded" && network != "testnet-10" {
        return Err("DEPLOY_BACKEND_NETWORK_UNSUPPORTED".into());
    }
    let source_hash = sha256_value(source)?;
    if artifact.get("source_hash").and_then(Value::as_str) != Some(source_hash.as_str()) {
        return Err("DEPLOY_ARTIFACT_SOURCE_MISMATCH".into());
    }
    let application_lock_projection = match application_lock {
        None => json!({"status":"NOT_CONFIGURED","lock_hash":Value::Null}),
        Some(lock) => {
            profile_governance::validate_application_lock_v2(lock)
                .map_err(|_| "DEPLOY_APPLICATION_LOCK_INVALID".to_string())?;
            json!({"status":"SELF_CONSISTENT","lock_hash":lock["lock_hash"],"recipe_package_revalidation":"NOT_PERFORMED"})
        }
    };
    let missing = vec![
        json!({"id":"profile_reference","reason":"required reference input was not supplied"}),
        json!({"id":"deployment_tuple","reason":"required reference input was not supplied"}),
        json!({"id":"codec_manifest","reason":"required reference input was not supplied"}),
        json!({"id":"node_observation","reason":"required reference input was not supplied"}),
        json!({"id":"signer_capability","reason":"required reference input was not supplied"}),
        json!({"id":"readback_capability","reason":"required reference input was not supplied"}),
    ];
    let mut plan = json!({
        "schema":"KTAPEOUT-DEV-DEPLOY-PLAN-V1", "protocol_semver":PROTOCOL,
        "network":network, "source_hash":source["source_hash"],
        "artifact_root":artifact["artifact"]["hash"], "backend":artifact["backend"],
        "project_lock":artifact["developer_lock_hash"], "references":{},
        "missing_evidence":missing, "reference_scope":"UNBOUND",
        "application_binding":Value::Null,
        "application_lock":application_lock_projection,
        "adapter_status":adapter["status"],
    });
    let plan_hash = digest_json_domain(&plan, "KTAPEOUT/0.5.0/DEV_DEPLOY_PLAN/V1")?;
    plan["plan_hash"] = Value::String(plan_hash);
    Ok(plan)
}

fn deployment_command_status(data: &Value) -> &'static str {
    match data["missing_evidence"].as_array() {
        Some(missing) if missing.is_empty() => "PASS",
        _ => "WARNING",
    }
}

fn deploy_plan(
    manifest: PathBuf,
    network: String,
    backend: String,
    application_lock: Option<PathBuf>,
) -> Result<(), String> {
    let plan = deployment_plan_value(&manifest, &network, &backend, application_lock.as_deref())?;
    let required_capabilities: Vec<Value> = plan["missing_evidence"]
        .as_array()
        .unwrap_or(&Vec::new())
        .iter()
        .filter_map(|item| item["id"].as_str().map(|id| Value::String(id.to_string())))
        .collect();
    let mut result = plan;
    result["lifecycle_status"] = Value::String("PLAN_ONLY".into());
    result["next_action"] = Value::String(
        "supply the missing reference inputs; no signing or broadcast is available here".into(),
    );
    result["required_capabilities"] = Value::Array(required_capabilities);
    result["external_action"] = Value::Bool(false);
    result["safe_to_retry"] = Value::Bool(true);
    result["network_effect"] = Value::String("NONE".into());
    result["signing_allowed"] = Value::Bool(false);
    result["broadcast"] = Value::Bool(false);
    let status = deployment_command_status(&result);
    emit_result_status("ktape deploy plan", Some(&network), status, result)
}

fn deploy_preflight(
    manifest: PathBuf,
    network: String,
    backend: String,
    application_lock: Option<PathBuf>,
) -> Result<(), String> {
    let plan = deployment_plan_value(&manifest, &network, &backend, application_lock.as_deref())?;
    let status = deployment_command_status(&plan);
    emit_result_status(
        "ktape deploy preflight",
        Some(&network),
        status,
        json!({"plan_hash":plan["plan_hash"],"application_lock":plan["application_lock"],"lifecycle_status":"PLAN_ONLY","missing_evidence":plan["missing_evidence"],"next_action":"supply the missing reference inputs before external operator preflight","external_action":false,"safe_to_retry":true,"network_effect":"NONE","signing_allowed":false,"broadcast":false}),
    )
}

fn deploy_submit(_signed: PathBuf) -> Result<(), String> {
    emit_result_status(
        "ktape deploy submit",
        None,
        "BLOCKED",
        json!({"schema":"KTAPEOUT-DEPLOY-SUBMIT-BOUNDARY-V1","lifecycle_status":"BLOCKED","next_action":"submit the locked signed plan through an admitted external operator, then run ktape deploy readback","missing_evidence":["external signer","authenticated submitter","dual RPC readback"],"external_action":false,"safe_to_retry":false,"network_effect":"NONE","signing_allowed":false,"broadcast":false}),
    )
}

fn deploy_readback(receipt_path: PathBuf) -> Result<(), String> {
    let receipt = read_json(&receipt_path)?;
    validate_receipt_value(&receipt)?;
    let facts = receipt["facts"]
        .as_object()
        .ok_or_else(|| "DEPLOY_READBACK_FACTS_INVALID".to_string())?;
    let confirmed = receipt["receipt_kind"] == "EVIDENCE" && receipt["status"] == "CONFIRMED";
    let authorized = receipt["evidence_origin"] == "AUTHORIZED_TN10_RECEIPT"
        && receipt["network"] == "testnet-10";
    let dual_rpc = facts.get("dual_rpc_readback") == Some(&Value::Bool(true));
    let observed = confirmed && authorized && dual_rpc;
    let mut missing = Vec::new();
    if !confirmed {
        missing
            .push(json!({"id":"confirmed_evidence","reason":"receipt is not CONFIRMED EVIDENCE"}));
    }
    if !authorized {
        missing.push(json!({"id":"authorized_tn10_origin","reason":"receipt is not an authorized testnet-10 receipt"}));
    }
    if !dual_rpc {
        missing.push(
            json!({"id":"dual_rpc_readback","reason":"facts.dual_rpc_readback must be true"}),
        );
    }
    let receipt_digest = digest_json_domain(&receipt, "KTAPEOUT/0.5.0/DEV_READBACK_RECEIPT/V1")?;
    emit_result(
        "ktape deploy readback",
        receipt.get("network").and_then(Value::as_str),
        json!({"schema":"KTAPEOUT-DEV-READBACK-V1","lifecycle_status":if observed {"TN10_OBSERVED"} else {"NOT_VERIFIED"},"receipt_digest":receipt_digest,"evidence_format":"KTAPEOUT-RECEIPT-V1","operation_id":receipt["operation_id"],"network":receipt["network"],"observed_tip":facts.get("observed_tip").cloned().unwrap_or(Value::Null),"missing_evidence":missing,"next_action":if observed {"resolve the application through the locked Bridge adapter"} else {"obtain a confirmed authorized TN10 receipt with independent dual RPC readback"},"external_action":false,"safe_to_retry":true,"network_effect":"NONE","signing_allowed":false,"broadcast":false}),
    )
}

fn write_binding_value(path: &Path, value: &Value) -> Result<(), String> {
    validate_delivery_operation_binding_value(value)?;
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            return Err("DELIVERY_OPERATION_BINDING_MUST_BE_REGULAR_FILE".into());
        }
        let existing = read_json(path)?;
        validate_delivery_operation_binding_value(&existing)?;
        if existing != *value {
            return Err("DELIVERY_OPERATION_BINDING_MISMATCH".into());
        }
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("DELIVERY_OPERATION_BINDING_DIRECTORY_ERROR:{error}"))?;
    }
    let payload = serde_json::to_string_pretty(value)
        .map_err(|error| format!("DELIVERY_OPERATION_BINDING_ENCODE_ERROR:{error}"))?
        + "\n";
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("DELIVERY_OPERATION_BINDING_WRITE_ERROR:{error}"))?;
    file.write_all(payload.as_bytes())
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("DELIVERY_OPERATION_BINDING_WRITE_ERROR:{error}"))?;
    Ok(())
}

fn bind_reserved_inputs(
    ledger_path: &Path,
    network: &str,
    wallet_reference_hash: &str,
    operation_id: &str,
    intent_hash: &str,
    plan_hash: &str,
    outpoints: &[String],
) -> Result<(), String> {
    if !valid_hash(wallet_reference_hash) || !valid_hash(intent_hash) || !valid_hash(plan_hash) {
        return Err("INPUT_RESERVATION_BINDING_HASH_INVALID".into());
    }
    let selected = sorted_reservation_outpoints(outpoints)?;
    let _lock = acquire_local_writer_lock(ledger_path)?;
    let mut ledger = read_json(ledger_path)?;
    validate_reservation_ledger(&ledger)?;
    if ledger["network"] != network || ledger["wallet_reference_hash"] != wallet_reference_hash {
        return Err("INPUT_RESERVATION_LEDGER_CONTEXT_MISMATCH".into());
    }
    for outpoint in &selected {
        let record = ledger["reservations"]
            .get(outpoint)
            .ok_or_else(|| "INPUT_RESERVATION_OWNERSHIP_MISMATCH".to_string())?;
        if record["operation_id"] != operation_id
            || record["intent_hash"] != intent_hash
            || !(record["plan_hash"].is_null() || record["plan_hash"] == plan_hash)
        {
            return Err("INPUT_RESERVATION_OWNERSHIP_MISMATCH".into());
        }
    }
    {
        let reservations = ledger["reservations"]
            .as_object_mut()
            .ok_or_else(|| "INPUT_RESERVATION_ENTRIES_INVALID".to_string())?;
        for outpoint in &selected {
            reservations.insert(outpoint.clone(), json!({"operation_id":operation_id,"intent_hash":intent_hash,"plan_hash":plan_hash}));
        }
    }
    let hash = reservation_ledger_hash(&ledger)?;
    ledger["ledger_hash"] = Value::String(hash);
    validate_reservation_ledger(&ledger)?;
    let bytes = canonical_json(&ledger)?;
    let payload = bytes
        .iter()
        .copied()
        .chain(std::iter::once(b'\n'))
        .collect::<Vec<u8>>();
    atomic_write_file(
        ledger_path,
        &payload,
        "INPUT_RESERVATION_LEDGER_WRITE_ERROR",
    )?;
    Ok(())
}

fn validate_maintenance_delivery_binding(
    maintenance_plan: &Value,
    intent: &Value,
    policy: &Value,
) -> Result<(), String> {
    if maintenance_plan["network"] != intent["network"]
        || maintenance_plan["network_policy_hash"] != intent["network_policy_hash"]
        || maintenance_plan["network_policy_hash"] != policy["policy_hash"]
        || maintenance_plan["application_id"] != intent["application_id"]
        || maintenance_plan["target"]["release_id"] != intent["release_id"]
        || maintenance_plan["target"]["artifact_root"] != intent["artifact_root"]
    {
        return Err("MAINTENANCE_DELIVERY_TUPLE_MISMATCH".into());
    }
    if maintenance_plan["expires_at"] != intent["expires_at"] {
        return Err("MAINTENANCE_DELIVERY_EXPIRY_MISMATCH".into());
    }
    maintenance::verify(maintenance_plan)?;
    if !matches!(
        intent["operation_kind"].as_str(),
        Some("APPLICATION_PUBLISH") | Some("NAME_REBIND") | Some("STATE_TRANSITION")
    ) {
        return Err("MAINTENANCE_DELIVERY_OPERATION_KIND_INVALID".into());
    }
    Ok(())
}

// CLI boundary: these fields map one-to-one to the published binding contract.
#[allow(clippy::too_many_arguments)]
fn publish_bind(
    intent_path: PathBuf,
    policy_path: PathBuf,
    provider_path: PathBuf,
    operator_plan_path: PathBuf,
    maintenance_plan_path: Option<PathBuf>,
    project_lock_hash: String,
    operation_output: PathBuf,
    binding_output: PathBuf,
    reservation_ledger: Option<PathBuf>,
    wallet_reference_hash: Option<String>,
    outpoints: Vec<String>,
) -> Result<(), String> {
    let policy = read_json(&policy_path)?;
    let intent = read_json(&intent_path)?;
    let provider = read_json(&provider_path)?;
    let plan = read_json(&operator_plan_path)?;
    let maintenance_plan = maintenance_plan_path
        .as_ref()
        .map(|path| read_json(path.as_path()))
        .transpose()?;
    validate_delivery_policy_value(&policy)?;
    validate_delivery_intent_value(&intent, &policy)?;
    validate_delivery_provider_value(&provider)?;
    validate_operator_plan_value(&plan)?;
    if let Some(maintenance_plan) = maintenance_plan.as_ref() {
        validate_maintenance_delivery_binding(maintenance_plan, &intent, &policy)?;
    }
    if !valid_hash(&project_lock_hash) {
        return Err("PROJECT_LOCK_HASH_INVALID".into());
    }
    if intent["network"] != plan["network"]
        || intent["intent_hash"] != plan["intent_hash"]
        || policy["policy_hash"] != plan["network_policy_hash"]
        || provider["provider_id"] != plan["provider_id"]
        || intent["expires_at"] != plan["expires_at"]
    {
        return Err("DELIVERY_BINDING_TUPLE_MISMATCH".into());
    }
    let operation = json!({"schema":"KTAPEOUT-OPERATION-STATE-V1","protocol_semver":PROTOCOL,"operation_id":intent["operation_id"],"request_id":format!("delivery:{}", intent["intent_hash"].as_str().unwrap_or_default()),"project_lock_hash":project_lock_hash,"plan_hash":plan["plan_hash"],"network":intent["network"],"stage":"PLANNED","attempt_count":0,"expiry":intent["expires_at"],"last_observed_tip":Value::Null,"evidence_refs":[],"next_allowed_action":"OPERATOR_NATIVE_PREFLIGHT_REQUIRED"});
    valid_operation_value(&operation)?;
    let mut binding = json!({"schema":"KTAPEOUT-DELIVERY-OPERATION-BINDING-V1","protocol_semver":PROTOCOL,"operation_id":operation["operation_id"],"project_lock_hash":operation["project_lock_hash"],"intent_hash":intent["intent_hash"],"plan_hash":plan["plan_hash"],"network":intent["network"],"network_policy_hash":policy["policy_hash"],"provider_id":provider["provider_id"],"binding_hash":"0".repeat(64)});
    if let Some(maintenance_plan) = maintenance_plan.as_ref() {
        binding["maintenance_plan_hash"] = maintenance_plan["plan_hash"].clone();
    }
    let mut material = binding
        .as_object()
        .cloned()
        .ok_or_else(|| "DELIVERY_BINDING_INTERNAL_ERROR".to_string())?;
    material.remove("binding_hash");
    binding["binding_hash"] = Value::String(digest_json_domain(
        &Value::Object(material),
        "KTAPEOUT/0.5.0/DELIVERY_OPERATION_BINDING/V1",
    )?);
    validate_delivery_operation_binding_value(&binding)?;
    if let Some(existing) = operation_output
        .exists()
        .then(|| read_operation_state(&operation_output))
        .transpose()?
    {
        if existing != operation {
            return Err("OPERATION_BINDING_MISMATCH".into());
        }
    } else {
        write_operation_state(&operation_output, &operation)?;
    }
    write_binding_value(&binding_output, &binding)?;
    match (
        reservation_ledger,
        wallet_reference_hash,
        outpoints.is_empty(),
    ) {
        (None, None, true) => {}
        (Some(ledger), Some(wallet), false) => bind_reserved_inputs(
            &ledger,
            intent["network"].as_str().unwrap_or_default(),
            &wallet,
            intent["operation_id"].as_str().unwrap_or_default(),
            intent["intent_hash"].as_str().unwrap_or_default(),
            plan["plan_hash"].as_str().unwrap_or_default(),
            &outpoints,
        )?,
        _ => return Err("INPUT_RESERVATION_ARGUMENTS_INCOMPLETE".into()),
    }
    emit_result(
        "ktape publish bind",
        intent.get("network").and_then(Value::as_str),
        json!({"delivery_state":"OPERATION_BOUND","operation":operation,"binding":binding,"maintenance_plan_bound":maintenance_plan.is_some(),"safe_to_retry":true,"next_action":"RUN_PUBLISH_STATUS_OR_HAND_TO_OPERATOR","signing_allowed":false,"broadcast":false}),
    )
}

fn publish_plan(
    package: PathBuf,
    policy_path: PathBuf,
    kind: String,
    at: String,
    expires_at: String,
    output: Option<PathBuf>,
) -> Result<(), String> {
    let policy = read_json(&policy_path)?;
    validate_delivery_policy_value(&policy)?;
    let network = policy
        .get("network")
        .and_then(Value::as_str)
        .ok_or_else(|| "DELIVERY_POLICY_NETWORK_INVALID".to_string())?;
    if !matches!(
        kind.as_str(),
        "APPLICATION_PUBLISH"
            | "NAME_REGISTER"
            | "NAME_REBIND"
            | "NAME_TRANSFER"
            | "NAME_RELEASE"
            | "STATE_TRANSITION"
    ) {
        return Err("DELIVERY_INTENT_KIND_INVALID".into());
    }
    let identity = package_delivery_identity(&package, network)?;
    let mut id_material = json!({"network":network,"policy":policy["policy_hash"],"kind":kind,"application_id":identity["application_id"],"release_id":identity["release_id"],"artifact_root":identity["artifact_root"],"canonical_uri":identity["canonical_uri"],"profile_lock_hash":identity["profile_lock_hash"]});
    let lock_bound = identity.get("application_lock_hash").is_some();
    if lock_bound {
        if kind != "APPLICATION_PUBLISH" {
            return Err("DELIVERY_INTENT_V2_KIND_INVALID".into());
        }
        id_material["application_lock_hash"] = identity["application_lock_hash"].clone();
        id_material["application_evidence_digest"] =
            identity["application_evidence_digest"].clone();
    }
    let operation_id = deterministic_operation_id("publish-plan", Some(network), &id_material)?;
    let idempotency_key =
        digest_json_domain(&id_material, "KTAPEOUT/0.5.0/DELIVERY_IDEMPOTENCY/V1")?;
    let mut intent = json!({"schema":if lock_bound {"KTAPEOUT-APPLICATION-DELIVERY-INTENT-V2"} else {"KTAPEOUT-APPLICATION-DELIVERY-INTENT-V1"},"protocol_semver":PROTOCOL,"operation_id":operation_id,"idempotency_key":idempotency_key,"network":network,"network_policy_hash":policy["policy_hash"],"operation_kind":kind,"application_id":identity["application_id"],"release_id":identity["release_id"],"artifact_root":identity["artifact_root"],"profile_lock_hash":identity["profile_lock_hash"],"canonical_name":identity["canonical_uri"],"max_fee_sompi":policy["max_fee_sompi"],"max_bond_sompi":policy["max_bond_sompi"],"max_value_sompi":policy["max_value_sompi"],"created_at":at,"expires_at":expires_at,"intent_hash":"0000000000000000000000000000000000000000000000000000000000000000"});
    if lock_bound {
        intent["application_lock_hash"] = identity["application_lock_hash"].clone();
        intent["application_evidence_digest"] = identity["application_evidence_digest"].clone();
    }
    let created =
        parse_utc_timestamp(&at).ok_or_else(|| "DELIVERY_INTENT_CREATED_AT_INVALID".to_string())?;
    let expires = parse_utc_timestamp(&expires_at)
        .ok_or_else(|| "DELIVERY_INTENT_EXPIRES_AT_INVALID".to_string())?;
    let delta = timestamp_delta_seconds(&created, &expires)
        .ok_or_else(|| "DELIVERY_INTENT_TIMESTAMP_INVALID".to_string())?;
    let ttl = policy
        .get("plan_ttl_seconds")
        .and_then(Value::as_u64)
        .unwrap_or(0) as i64;
    if delta <= 0 || delta > ttl {
        return Err("DELIVERY_INTENT_EXPIRY_INVALID".into());
    }
    let mut material = intent
        .as_object()
        .cloned()
        .ok_or_else(|| "DELIVERY_INTENT_INTERNAL_ERROR".to_string())?;
    material.remove("intent_hash");
    intent["intent_hash"] = Value::String(digest_json_domain(
        &Value::Object(material),
        if lock_bound {
            "KTAPEOUT/0.5.0/APPLICATION_DELIVERY_INTENT/V2"
        } else {
            "KTAPEOUT/0.5.0/APPLICATION_DELIVERY_INTENT/V1"
        },
    )?);
    let intent_object = intent
        .as_object()
        .ok_or_else(|| "DELIVERY_INTENT_INTERNAL_ERROR".to_string())?;
    for field in [
        "idempotency_key",
        "network_policy_hash",
        "application_id",
        "release_id",
        "artifact_root",
        "profile_lock_hash",
        "intent_hash",
    ] {
        if intent_object
            .get(field)
            .and_then(Value::as_str)
            .filter(|value| valid_hash(value))
            .is_none()
        {
            return Err(format!("DELIVERY_INTENT_{field}_INVALID"));
        }
    }
    let operation_suffix = intent_object
        .get("operation_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .strip_prefix("op_")
        .unwrap_or_default();
    if operation_suffix.len() != 32
        || !operation_suffix
            .chars()
            .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
    {
        return Err("DELIVERY_INTENT_OPERATION_ID_INVALID".into());
    }
    if normalize_name_value(&canonical_name_string(&intent)?, None)?
        .get("canonical_uri")
        .and_then(Value::as_str)
        != intent.get("canonical_name").and_then(Value::as_str)
    {
        return Err("DELIVERY_INTENT_NAME_NOT_NORMALIZED".into());
    }
    for field in ["max_fee_sompi", "max_bond_sompi", "max_value_sompi"] {
        if intent_object
            .get(field)
            .and_then(Value::as_u64)
            .unwrap_or(u64::MAX)
            > policy.get(field).and_then(Value::as_u64).unwrap_or(0)
        {
            return Err(format!("DELIVERY_INTENT_{field}_EXCEEDS_POLICY"));
        }
    }
    if let Some(path) = output {
        fs::write(
            &path,
            serde_json::to_string_pretty(&intent)
                .map_err(|error| format!("PUBLISH_INTENT_ENCODE_ERROR:{error}"))?
                + "\n",
        )
        .map_err(|error| format!("PUBLISH_INTENT_WRITE_ERROR:{error}"))?;
    }
    emit_result(
        "ktape publish plan",
        Some(network),
        json!({"delivery_state":"PLANNED","intent":intent,"runtime_evidence":identity.get("runtime_evidence"),"namespace_status":"CANONICAL_KTAPE_NAMESPACE","next_action":"RUN_PUBLISH_PREFLIGHT","safe_to_retry":true,"signing_allowed":false,"broadcast":false}),
    )
}

fn canonical_name_string(value: &Value) -> Result<String, String> {
    value
        .get("canonical_name")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| "DELIVERY_INTENT_NAME_INVALID".into())
}

fn dev_workflow(
    workflow_path: PathBuf,
    execution_result_path: Option<PathBuf>,
) -> Result<(), String> {
    let workflow_path = fs::canonicalize(&workflow_path)
        .map_err(|error| format!("DEV_WORKFLOW_READ_ERROR:{error}"))?;
    let workflow = read_json(&workflow_path)?;
    if workflow.get("schema").and_then(Value::as_str) != Some("KTAPEOUT-DEV-WORKFLOW-V1")
        || workflow.get("protocol_semver").and_then(Value::as_str) != Some(PROTOCOL)
    {
        return Err("DEV_WORKFLOW_SCHEMA_UNSUPPORTED".into());
    }
    let network = workflow
        .get("network")
        .and_then(Value::as_str)
        .ok_or_else(|| "DEV_WORKFLOW_NETWORK_MISSING".to_string())?;
    if !matches!(network, "testnet-10" | "mainnet") {
        return Err("DEV_WORKFLOW_NETWORK_UNSUPPORTED".into());
    }
    let manifest_value = workflow
        .get("manifest")
        .and_then(Value::as_str)
        .ok_or_else(|| "DEV_WORKFLOW_MANIFEST_MISSING".to_string())?;
    let manifest_path = workflow_path
        .parent()
        .ok_or_else(|| "DEV_WORKFLOW_PARENT_MISSING".to_string())?
        .join(manifest_value);
    let manifest = read_json(&manifest_path)?;
    validate_manifest_value(&manifest)?;

    let stages = workflow
        .get("stages")
        .and_then(Value::as_array)
        .ok_or_else(|| "DEV_WORKFLOW_STAGES_INVALID".to_string())?;
    let expected = ["check", "build", "package", "test", "publishability"];
    let actual: Vec<&str> = stages.iter().filter_map(Value::as_str).collect();
    if actual.is_empty()
        || actual.len() != stages.len()
        || actual
            .iter()
            .enumerate()
            .any(|(index, value)| expected.get(index) != Some(value))
    {
        return Err("DEV_WORKFLOW_STAGE_ORDER_INVALID".into());
    }

    let mut lock_status = "NOT_CONFIGURED";
    let mut lock_hash = Value::Null;
    let mut verified_lock: Option<Value> = None;
    if let Some(lock_name) = workflow.get("profile_lock").and_then(Value::as_str) {
        let lock_path = workflow_path
            .parent()
            .ok_or_else(|| "DEV_WORKFLOW_PARENT_MISSING".to_string())?
            .join(lock_name);
        let lock_value = read_json(&lock_path)?;
        let lock = lock_value.get("lock").cloned().unwrap_or(lock_value);
        ktapeout_runtime::validate_developer_lock(&lock)
            .map_err(|_| "DEV_WORKFLOW_PROFILE_LOCK_INVALID".to_string())?;
        lock_hash = lock.get("lock_hash").cloned().unwrap_or(Value::Null);
        lock_status = "VERIFIED";
        verified_lock = Some(lock);
    }
    if let Some(binding) = workflow.get("profile_binding") {
        let package_root = binding.get("package_root").and_then(Value::as_str);
        if package_root.is_none()
            && binding.get("source").and_then(Value::as_str) != Some("verified-developer-lock")
        {
            return Err("DEV_WORKFLOW_PROFILE_BINDING_INVALID".to_string());
        }
        if package_root.is_none() {
            // A supplied Developer Lock is already the trusted binding when no
            // package directory was copied into the project.
            let _ = verified_lock
                .as_ref()
                .ok_or_else(|| "DEV_WORKFLOW_PROFILE_BINDING_WITHOUT_LOCK".to_string())?;
        }
        if let Some(package_root) = package_root {
            let package_path = PathBuf::from(package_root);
            let package_path = if package_path.is_absolute() {
                package_path
            } else {
                workflow_path
                    .parent()
                    .ok_or_else(|| "DEV_WORKFLOW_PARENT_MISSING".to_string())?
                    .join(package_path)
            };
            let (metadata, _) = verify_profile_package(package_path)?;
            let lock = verified_lock
                .as_ref()
                .ok_or_else(|| "DEV_WORKFLOW_PROFILE_BINDING_WITHOUT_LOCK".to_string())?;
            let profile = lock
                .get("profiles")
                .and_then(Value::as_array)
                .and_then(|profiles| profiles.first())
                .ok_or_else(|| "DEV_WORKFLOW_PROFILE_LOCK_PROFILE_MISSING".to_string())?;
            for field in ["profile_hash", "package_digest"] {
                if metadata.get(field) != profile.get(field) {
                    return Err(format!("DEV_WORKFLOW_PROFILE_BINDING_MISMATCH:{field}"));
                }
            }
            for field in ["runtime_digest", "compiler_lock_digest", "vector_root"] {
                if metadata.get(field) != lock.get(field) {
                    return Err(format!("DEV_WORKFLOW_PROFILE_BINDING_MISMATCH:{field}"));
                }
            }
        }
    }

    let mut application_lock_status = "NOT_CONFIGURED";
    let mut application_lock_hash = Value::Null;
    let mut verified_application_lock: Option<Value> = None;
    if let Some(lock_name) = workflow.get("application_lock").and_then(Value::as_str) {
        let lock_path = workflow_path
            .parent()
            .ok_or_else(|| "DEV_WORKFLOW_PARENT_MISSING".to_string())?
            .join(lock_name);
        let lock_value = read_json(&lock_path)?;
        let lock = lock_value
            .get("lock")
            .cloned()
            .or_else(|| {
                lock_value
                    .get("data")
                    .and_then(|data| data.get("lock"))
                    .cloned()
            })
            .unwrap_or(lock_value);
        profile_governance::validate_application_lock_v2(&lock)
            .map_err(|_| "DEV_WORKFLOW_APPLICATION_LOCK_INVALID".to_string())?;
        application_lock_hash = lock["lock_hash"].clone();
        application_lock_status = "SELF_CONSISTENT";
        verified_application_lock = Some(lock);
    }

    let workflow_hash = sha256_value(&workflow)?;
    let manifest_hash = sha256_value(&manifest)?;
    let backend = workflow
        .get("backend")
        .and_then(Value::as_str)
        .unwrap_or("local-simulation");
    let base = workflow_path
        .parent()
        .ok_or("DEV_WORKFLOW_PARENT_MISSING")?;
    if execution_result_path.is_some() && workflow.get("local_execution_result").is_some() {
        return Err("DEV_WORKFLOW_EXECUTION_RESULT_CONFLICT".into());
    }
    let execution_source: Option<Result<Value, String>> =
        if let Some(path) = execution_result_path.as_ref() {
            Some(read_json(path))
        } else {
            match workflow.get("local_execution_result") {
                Some(Value::String(path)) => Some(read_json(&base.join(path))),
                Some(_) => Some(Err("DEV_WORKFLOW_LOCAL_EXECUTION_RESULT_INVALID".into())),
                None => None,
            }
        };
    let (mut local_execution, mut local_execution_error) = match execution_source {
        None => (None, None),
        Some(Ok(result)) => {
            if !actual.contains(&"test") {
                return Err("DEV_WORKFLOW_LOCAL_EXECUTION_REQUIRES_TEST_STAGE".into());
            }
            let expected_source_hash = manifest
                .get("source_hash")
                .and_then(Value::as_str)
                .ok_or_else(|| "SOURCE_HASH_MISSING".to_string())?;
            match dev_workflow::validate_local_execution_result(
                &result,
                expected_source_hash,
                &manifest_hash,
                manifest
                    .get("test_vectors")
                    .and_then(Value::as_array)
                    .map_or(0, Vec::len),
                manifest
                    .get("external_dependencies")
                    .and_then(Value::as_array)
                    .and_then(|dependencies| {
                        dependencies
                            .iter()
                            .find_map(|dependency| dependency.get("profile_vector_binding"))
                    }),
            ) {
                Ok(execution) => (Some(execution), None),
                Err(error) => (None, Some(error)),
            }
        }
        Some(Err(error)) => return Err(error),
    };
    if let Some(package) = workflow.get("profile_package_root") {
        let path = package
            .as_str()
            .filter(|path| !path.is_empty())
            .ok_or("DEV_WORKFLOW_PROFILE_PACKAGE_ROOT_INVALID")?;
        if !actual.contains(&"test") {
            return Err("DEV_WORKFLOW_LOCAL_EXECUTION_REQUIRES_TEST_STAGE".into());
        }
        if workflow.get("local_execution_result").is_some()
            || workflow.get("runtime_project").is_some()
        {
            return Err("DEV_WORKFLOW_TEST_EXECUTOR_CONFLICT".into());
        }
        let execution = profile_vector_runner::run(&manifest, &base.join(path))
            .and_then(|result| profile_vector_runner::execution_handoff(&result, &manifest))
            .and_then(|handoff| {
                dev_workflow::validate_local_execution_result(
                    &handoff,
                    manifest["source_hash"]
                        .as_str()
                        .ok_or("SOURCE_HASH_MISSING")?,
                    &manifest_hash,
                    manifest
                        .get("test_vectors")
                        .and_then(Value::as_array)
                        .map_or(0, Vec::len),
                    manifest
                        .get("external_dependencies")
                        .and_then(Value::as_array)
                        .and_then(|dependencies| {
                            dependencies
                                .iter()
                                .find_map(|dependency| dependency.get("profile_vector_binding"))
                        }),
                )
            });
        match execution {
            Ok(execution) => local_execution = Some(execution),
            Err(error) => local_execution_error = Some(error),
        }
    }
    if let Some(execution) = local_execution.as_mut() {
        if let Err(error) = dev_workflow::validate_local_execution_lock_binding(
            execution,
            verified_application_lock.as_ref(),
        ) {
            local_execution_error = Some(error.into());
            local_execution = None;
        }
    }
    let network_policy = match workflow.get("network_policy") {
        None => None,
        Some(Value::String(path)) => {
            if verified_lock.is_none() {
                return Err("DEV_WORKFLOW_POLICY_WITHOUT_LOCK".into());
            }
            let policy = read_json(&base.join(path))?;
            if policy.get("network_id").and_then(Value::as_str) != Some(network) {
                return Err("DEV_WORKFLOW_POLICY_NETWORK_MISMATCH".into());
            }
            Some(policy)
        }
        Some(_) => return Err("DEV_WORKFLOW_NETWORK_POLICY_INVALID".into()),
    };
    let package_output = dev_workflow::output_path(base, &workflow, "package_output", "package")?;
    let build_output = dev_workflow::output_path(base, &workflow, "build_output", "build")?;
    let binding = dev_workflow::BuildBinding {
        lock: verified_lock.as_ref(),
        policy: network_policy.as_ref(),
    };
    let mut project_binding_status = "NOT_CONFIGURED";
    let project = match workflow.get("runtime_project") {
        None => None,
        Some(Value::String(_)) => {
            project_binding_status = if verified_lock.is_some() {
                "PROJECT_LOCAL_NOT_BOUND_TO_PROFILE_LOCK"
            } else {
                "PROJECT_LOCAL"
            };
            let path =
                dev_workflow::output_path(base, &workflow, "runtime_project", "project.json")?;
            let project = read_json(&path)?;
            if project["publish_intent"]["network"] != network {
                return Err("DEV_WORKFLOW_PROJECT_NETWORK_MISMATCH".into());
            }
            Some(project)
        }
        Some(_) => return Err("DEV_WORKFLOW_RUNTIME_PROJECT_INVALID".into()),
    };
    if project.is_some() && local_execution.is_some() {
        return Err("DEV_WORKFLOW_EXECUTION_SUBJECTS_AMBIGUOUS".into());
    }
    let stage_results = dev_workflow::execute_stages(
        &actual,
        &manifest,
        network,
        backend,
        binding,
        &build_output,
        &package_output,
        project.as_ref(),
        local_execution.as_ref(),
        local_execution_error.as_deref(),
    );
    let status = dev_workflow::workflow_status(&stage_results);
    let next_action = dev_workflow::workflow_next_action(&stage_results, status);
    let application_binding = dev_workflow::workflow_application_binding(&stage_results);
    let application_evidence = dev_workflow::workflow_application_evidence(
        verified_application_lock.as_ref(),
        local_execution.as_ref(),
    )?;
    emit_result_status(
        "ktape dev workflow",
        Some(network),
        if status == "PASS" {
            "PASS"
        } else if status == "BLOCKED" {
            "BLOCKED"
        } else {
            "UNAVAILABLE"
        },
        json!({
            "schema": "KTAPEOUT-DEV-WORKFLOW-RESULT-V1",
            "status": status,
            "fact_scope": "LOCAL_ONLY",
            "workflow_hash": workflow_hash,
            "manifest_hash": manifest_hash,
            "profile_lock": {"status": lock_status, "lock_hash": lock_hash},
            "application_lock": {"status": application_lock_status, "lock_hash": application_lock_hash},
            "local_execution_result": workflow.get("local_execution_result").cloned().unwrap_or(Value::Null),
            "profile_package_root": workflow.get("profile_package_root").cloned().unwrap_or(Value::Null),
            "runtime_project_binding": project_binding_status,
            "application_binding": application_binding,
            "application_evidence": application_evidence,
            "stages": stage_results,
            "signing": false,
            "broadcast": false,
            "next_action": next_action
        }),
    )
}

fn dev_studio_bundle_build(
    handoff_path: PathBuf,
    developer_lock_path: Option<PathBuf>,
    output: Option<PathBuf>,
) -> Result<(), String> {
    let handoff = read_json(&handoff_path)?;
    let handoff_result = studio_cli_handoff::verify_handoff(&handoff)?;
    let project = handoff
        .get("project")
        .ok_or_else(|| "STUDIO_CLI_HANDOFF_PROJECT_MISSING".to_string())?;
    let embedded_lock = handoff
        .get("developer_lock")
        .filter(|value| !value.is_null());
    let lock_value = match developer_lock_path {
        Some(path) => Some(read_json(&path)?),
        None => embedded_lock.cloned(),
    };
    let bundle = studio_runtime_bundle::build_bundle(project, lock_value.as_ref())?;
    let bundle_hash = bundle
        .get("bundle_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| "RUNTIME_BUNDLE_HASH_INVALID".to_string())?;
    if let Some(path) = &output {
        fs::write(
            path,
            serde_json::to_string_pretty(&bundle)
                .map_err(|error| format!("RUNTIME_BUNDLE_ENCODE_ERROR:{error}"))?
                + "\n",
        )
        .map_err(|error| format!("RUNTIME_BUNDLE_WRITE_ERROR:{error}"))?;
    }
    let data = json!({
        "schema": "KTAPEOUT-STUDIO-RUNTIME-BUNDLE-RESULT-V1",
        "status": "BUILDABLE_LOCAL",
        "project_id": bundle["project_id"],
        "project_sha256": bundle["project_sha256"],
        "profile_id": bundle["profile_id"],
        "profile_version": bundle["profile_version"],
        "semantic_ir_hash": bundle["semantic_ir_hash"],
        "artifact_sha256": bundle["artifact_sha256"],
        "bundle_hash": bundle_hash,
        "handoff_hash": handoff.get("handoff_hash"),
        "handoff_status": handoff_result.get("lifecycle_status"),
        "output": output,
        "package_status": "LOCAL_RUNTIME_BUNDLE_NOT_ADMITTED_PACKAGE",
        "signing_allowed": false,
        "broadcast": false,
        "network_effect": "NONE",
        "next_action": "ktape artifact simulate-project BUNDLE.json INPUTS.json STATE.json --steps 1"
    });
    emit_result("ktape dev studio-bundle-build", Some("testnet-10"), data)
}

fn inspect_source_manifest_graph(
    value: &Value,
    depth: usize,
    nodes: &mut usize,
) -> Result<(), String> {
    if depth > MAX_SOURCE_MANIFEST_DEPTH {
        return Err("SOURCE_MANIFEST_GRAPH_LIMIT".to_string());
    }
    if matches!(value, Value::Array(_) | Value::Object(_)) {
        *nodes += 1;
        if *nodes > MAX_SOURCE_MANIFEST_NODES {
            return Err("SOURCE_MANIFEST_GRAPH_LIMIT".to_string());
        }
    }
    match value {
        Value::Array(values) => {
            for child in values {
                inspect_source_manifest_graph(child, depth + 1, nodes)?;
            }
        }
        Value::Object(map) => {
            for child in map.values() {
                inspect_source_manifest_graph(child, depth + 1, nodes)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_manifest_value(value: &Value) -> Result<&serde_json::Map<String, Value>, String> {
    let serialized_bytes =
        serde_json::to_vec(value).map_err(|_| "SOURCE_MANIFEST_SERIALIZE_FAILED".to_string())?;
    if serialized_bytes.len() > MAX_JSON_INPUT_BYTES {
        return Err("SOURCE_MANIFEST_SIZE_LIMIT".to_string());
    }
    let mut nodes = 0;
    inspect_source_manifest_graph(value, 0, &mut nodes)?;
    let object = value
        .as_object()
        .ok_or_else(|| "SOURCE_MANIFEST_NOT_OBJECT".to_string())?;
    if object.get("schema_version").and_then(Value::as_str) != Some(SOURCE_SCHEMA) {
        return Err("SOURCE_SCHEMA_UNSUPPORTED".to_string());
    }
    for field in [
        "source_kind",
        "source_hash",
        "declared_purpose",
        "inputs",
        "outputs",
        "persistent_state",
        "authorities",
        "external_dependencies",
        "value_flows",
        "availability_expectations",
        "test_vectors",
    ] {
        if !object.contains_key(field) {
            return Err(format!("SOURCE_FIELD_MISSING:{field}"));
        }
    }
    let allowed_fields = [
        "schema_version",
        "source_kind",
        "source_hash",
        "declared_purpose",
        "inputs",
        "outputs",
        "persistent_state",
        "authorities",
        "external_dependencies",
        "value_flows",
        "availability_expectations",
        "test_vectors",
        "atomicity_class",
        "network",
        "instructions",
        "discovery",
        "data_placement",
        "chain_write_policy",
        "action_declarations",
        "commitments",
    ];
    if object
        .keys()
        .any(|field| !allowed_fields.contains(&field.as_str()))
    {
        return Err("SOURCE_FIELDS_INVALID".to_string());
    }
    if object
        .get("source_kind")
        .and_then(Value::as_str)
        .filter(|kind| !kind.is_empty() && kind.len() <= 128)
        .is_none()
    {
        return Err("SOURCE_KIND_INVALID".to_string());
    }
    if object
        .get("declared_purpose")
        .and_then(Value::as_str)
        .is_none_or(|purpose| purpose.len() > 4096)
    {
        return Err("SOURCE_PURPOSE_INVALID".to_string());
    }
    for field in [
        "inputs",
        "outputs",
        "persistent_state",
        "authorities",
        "external_dependencies",
        "value_flows",
        "availability_expectations",
    ] {
        let entries = object
            .get(field)
            .and_then(Value::as_array)
            .ok_or_else(|| format!("SOURCE_ARRAY_INVALID:{field}"))?;
        if entries.len() > 4096 {
            return Err(format!("SOURCE_ARRAY_LIMIT_EXCEEDED:{field}"));
        }
        if entries.iter().any(|entry| !entry.is_object()) {
            return Err(format!("SOURCE_ARRAY_ITEM_INVALID:{field}"));
        }
    }
    if let Some(found) = contains_secret_key(value) {
        return Err(format!("SECRET_MATERIAL_FORBIDDEN:{found}"));
    }
    if let Some(dependencies) = object
        .get("external_dependencies")
        .and_then(Value::as_array)
    {
        let allowed_kinds = [
            "CONTENT_PROVIDER",
            "DELIVERY_PROVIDER",
            "POLICY_PROVIDER",
            "OBSERVATION_SOURCE",
            "IDENTITY_PROVIDER",
            "UNKNOWN_EXTERNAL",
        ];
        if dependencies.iter().any(|dependency| {
            dependency.get("dependency_kind").is_some_and(|kind| {
                !kind
                    .as_str()
                    .is_some_and(|value| allowed_kinds.contains(&value))
            })
        }) {
            return Err("DEPENDENCY_KIND_INVALID".to_string());
        }
        if dependencies.iter().any(|dependency| {
            dependency.get("profile_vector_binding").is_some()
                && dependency
                    .as_object()
                    .is_none_or(|object| object.len() != 1)
        }) {
            return Err("PROFILE_VECTOR_BINDING_FIELDS_INVALID".to_string());
        }
        let profile_bindings: Vec<&Value> = dependencies
            .iter()
            .filter_map(|dependency| dependency.get("profile_vector_binding"))
            .collect();
        if profile_bindings.len() > 1 {
            return Err("PROFILE_VECTOR_BINDING_DUPLICATE".to_string());
        }
        if let Some(binding) = profile_bindings.first() {
            validate_profile_vector_binding(
                binding,
                object
                    .get("source_hash")
                    .and_then(Value::as_str)
                    .unwrap_or(""),
            )?;
            let vectors = object
                .get("test_vectors")
                .and_then(Value::as_array)
                .ok_or_else(|| "PROFILE_VECTOR_TEST_VECTOR_SHAPE_INVALID".to_string())?;
            if vectors.iter().any(|vector| {
                !vector.as_object().is_some_and(|entry| {
                    entry.len() == 2
                        && entry.contains_key("input")
                        && entry.contains_key("expected")
                })
            }) {
                return Err("PROFILE_VECTOR_TEST_VECTOR_SHAPE_INVALID".to_string());
            }
        }
    }
    if object.get("atomicity_class").is_some_and(|value| {
        !value
            .as_str()
            .is_some_and(|class| ["A0", "A1", "A2", "A3", "A4", "A5"].contains(&class))
    }) {
        return Err("ATOMICITY_CLASS_UNSUPPORTED".to_string());
    }
    if object.get("network").is_some_and(|value| {
        !value
            .as_str()
            .is_some_and(|network| ["testnet-10", "mainnet"].contains(&network))
    }) {
        return Err("SOURCE_NETWORK_UNSUPPORTED".to_string());
    }
    if object
        .get("instructions")
        .is_some_and(|value| value.as_str().is_none_or(|text| text.len() > 4096))
    {
        return Err("SOURCE_INSTRUCTIONS_INVALID".to_string());
    }
    if let Some(placements) = object.get("data_placement") {
        let placements = placements
            .as_array()
            .ok_or_else(|| "DATA_PLACEMENT_INVALID".to_string())?;
        if placements.len() > 4096 || placements.iter().any(|item| !item.is_object()) {
            return Err("DATA_PLACEMENT_INVALID".to_string());
        }
        let visibilities = [
            "LOCAL_ONLY",
            "TENANT_SHARED",
            "CROSS_ORG_SHARED",
            "PUBLIC_COMMITMENT",
            "PUBLIC_SETTLEMENT",
        ];
        let content_modes = [
            "PLAINTEXT_LOCAL",
            "ENCRYPTED_SHARED",
            "HASH_ONLY_PUBLIC",
            "CANONICAL_PUBLIC",
        ];
        for placement in placements {
            if placement
                .get("name")
                .and_then(Value::as_str)
                .is_none_or(|name| name.is_empty())
                || !placement
                    .get("visibility")
                    .and_then(Value::as_str)
                    .is_some_and(|value| visibilities.contains(&value))
                || !placement
                    .get("content_mode")
                    .and_then(Value::as_str)
                    .is_some_and(|value| content_modes.contains(&value))
            {
                return Err("DATA_PLACEMENT_ENTRY_INVALID".to_string());
            }
        }
    }
    if let Some(policy) = object.get("chain_write_policy") {
        let policy = policy
            .as_object()
            .ok_or_else(|| "SOURCE_CHAIN_WRITE_POLICY_INVALID".to_string())?;
        if !policy
            .get("mode")
            .and_then(Value::as_str)
            .is_some_and(|mode| {
                [
                    "LOCAL_ONLY",
                    "PERIODIC_COMMITMENT",
                    "EVENT_COMMITMENT",
                    "SETTLEMENT_ONLY",
                ]
                .contains(&mode)
            })
        {
            return Err("SOURCE_CHAIN_WRITE_POLICY_INVALID".to_string());
        }
        for field in ["max_batch_events", "max_daily_sompi", "max_monthly_sompi"] {
            if policy
                .get(field)
                .is_some_and(|value| value.as_u64().is_none())
            {
                return Err(format!("CHAIN_WRITE_POLICY_FIELD_INVALID:{field}"));
            }
        }
    }
    if let Some(actions) = object.get("action_declarations") {
        let actions = actions
            .as_array()
            .ok_or_else(|| "ACTION_DECLARATIONS_INVALID".to_string())?;
        if actions.len() > 4096 || actions.iter().any(|item| !item.is_object()) {
            return Err("ACTION_DECLARATIONS_INVALID".to_string());
        }
        let mut names = std::collections::HashSet::new();
        for action in actions {
            let item = action
                .as_object()
                .ok_or_else(|| "ACTION_DECLARATIONS_INVALID".to_string())?;
            let name = item
                .get("name")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty() && value.len() <= 256)
                .ok_or_else(|| "ACTION_NAME_INVALID".to_string())?;
            if !names.insert(name) {
                return Err("ACTION_NAME_DUPLICATE".to_string());
            }
            if !item
                .get("execution")
                .and_then(Value::as_str)
                .is_some_and(|value| ["LOCAL", "EXTERNAL_PROVIDER", "L1"].contains(&value))
                || !item
                    .get("write_mode")
                    .and_then(Value::as_str)
                    .is_some_and(|value| {
                        [
                            "LOCAL_ONLY",
                            "PERIODIC_COMMITMENT",
                            "EVENT_COMMITMENT",
                            "SETTLEMENT_ONLY",
                        ]
                        .contains(&value)
                    })
                || !item
                    .get("authorization")
                    .and_then(Value::as_str)
                    .is_some_and(|value| {
                        ["NONE", "SESSION", "USER_SIGNATURE", "OPERATOR"].contains(&value)
                    })
            {
                return Err("ACTION_POLICY_INVALID".to_string());
            }
            if item.get("atomicity").is_some_and(|value| {
                !value
                    .as_str()
                    .is_some_and(|entry| ["A0", "A1", "A2", "A3", "A4", "A5"].contains(&entry))
            }) {
                return Err("ACTION_ATOMICITY_INVALID".to_string());
            }
            if item
                .get("idempotency")
                .is_some_and(|value| !value.is_boolean())
            {
                return Err("ACTION_IDEMPOTENCY_INVALID".to_string());
            }
            if item
                .get("max_events")
                .is_some_and(|value| value.as_u64().is_none())
            {
                return Err("ACTION_MAX_EVENTS_INVALID".to_string());
            }
        }
    }
    if let Some(commitments) = object.get("commitments") {
        let commitments = commitments
            .as_array()
            .ok_or_else(|| "COMMITMENTS_INVALID".to_string())?;
        if commitments.len() > 4096 || commitments.iter().any(|item| !item.is_object()) {
            return Err("COMMITMENTS_INVALID".to_string());
        }
        let mut names = std::collections::HashSet::new();
        for commitment in commitments {
            let item = commitment
                .as_object()
                .ok_or_else(|| "COMMITMENTS_INVALID".to_string())?;
            let name = item
                .get("name")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty() && value.len() <= 256)
                .ok_or_else(|| "COMMITMENT_FIELD_INVALID".to_string())?;
            for field in ["schema", "encoding", "hash_domain"] {
                if !item
                    .get(field)
                    .and_then(Value::as_str)
                    .is_some_and(|value| !value.is_empty() && value.len() <= 256)
                {
                    return Err("COMMITMENT_FIELD_INVALID".to_string());
                }
            }
            if !names.insert(name) {
                return Err("COMMITMENT_NAME_DUPLICATE".to_string());
            }
            if !item
                .get("ordering")
                .and_then(Value::as_str)
                .is_some_and(|value| {
                    ["CANONICAL", "SEQUENCE", "MERKLE_LEXICOGRAPHIC"].contains(&value)
                })
                || !item
                    .get("scope")
                    .and_then(Value::as_str)
                    .is_some_and(|value| ["LOCAL", "SHARED", "L1"].contains(&value))
            {
                return Err("COMMITMENT_POLICY_INVALID".to_string());
            }
        }
    }
    if let Some(discovery) = object.get("discovery") {
        let discovery = discovery
            .as_object()
            .ok_or_else(|| "DISCOVERY_FIELDS_INVALID".to_string())?;
        let allowed = [
            "primary_category",
            "secondary_categories",
            "tags",
            "surfaces",
            "confirmation_required",
        ];
        if discovery.keys().any(|key| !allowed.contains(&key.as_str())) {
            return Err("DISCOVERY_FIELDS_INVALID".to_string());
        }
        let categories = [
            "protocol",
            "infrastructure",
            "finance",
            "commerce",
            "marketplace",
            "game",
            "social",
            "content",
            "identity",
            "productivity",
            "developer",
            "science",
            "education",
            "simulation",
            "utility",
            "other",
        ];
        let tags = [
            "walletless",
            "wallet-optional",
            "user-signed",
            "operator-settlement",
            "non-custodial",
            "escrow",
            "payments",
            "trading",
            "prediction",
            "subscription",
            "multiplayer",
            "open-data",
            "scientific",
            "educational",
            "developer-tool",
        ];
        let surfaces = ["web", "pwa", "cli", "browser-extension", "studio", "api"];
        let primary = discovery
            .get("primary_category")
            .and_then(Value::as_str)
            .filter(|item| categories.contains(item))
            .ok_or_else(|| "DISCOVERY_PRIMARY_CATEGORY_INVALID".to_string())?;
        let secondary = discovery
            .get("secondary_categories")
            .and_then(Value::as_array)
            .ok_or_else(|| "DISCOVERY_SECONDARY_CATEGORIES_INVALID".to_string())?;
        if secondary.len() > 3
            || secondary
                .iter()
                .filter_map(Value::as_str)
                .collect::<std::collections::HashSet<_>>()
                .len()
                != secondary.len()
            || secondary.iter().any(|item| {
                item.as_str()
                    .is_none_or(|entry| entry == primary || !categories.contains(&entry))
            })
        {
            return Err("DISCOVERY_SECONDARY_CATEGORIES_INVALID".to_string());
        }
        let tag_values = discovery
            .get("tags")
            .and_then(Value::as_array)
            .ok_or_else(|| "DISCOVERY_TAGS_INVALID".to_string())?;
        if tag_values.len() > 8
            || tag_values
                .iter()
                .filter_map(Value::as_str)
                .collect::<std::collections::HashSet<_>>()
                .len()
                != tag_values.len()
            || tag_values
                .iter()
                .any(|item| item.as_str().is_none_or(|entry| !tags.contains(&entry)))
        {
            return Err("DISCOVERY_TAGS_INVALID".to_string());
        }
        let surface_values = discovery
            .get("surfaces")
            .and_then(Value::as_array)
            .ok_or_else(|| "DISCOVERY_SURFACES_INVALID".to_string())?;
        if surface_values.is_empty()
            || surface_values.len() > 4
            || surface_values
                .iter()
                .filter_map(Value::as_str)
                .collect::<std::collections::HashSet<_>>()
                .len()
                != surface_values.len()
            || surface_values
                .iter()
                .any(|item| item.as_str().is_none_or(|entry| !surfaces.contains(&entry)))
        {
            return Err("DISCOVERY_SURFACES_INVALID".to_string());
        }
        if !discovery
            .get("confirmation_required")
            .is_some_and(Value::is_boolean)
        {
            return Err("DISCOVERY_CONFIRMATION_FLAG_INVALID".to_string());
        }
    }
    let source_hash = object
        .get("source_hash")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if source_hash.len() != 64
        || !source_hash
            .chars()
            .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
    {
        return Err("SOURCE_HASH_INVALID".to_string());
    }
    let test_vectors = object
        .get("test_vectors")
        .and_then(Value::as_array)
        .filter(|vectors| !vectors.is_empty())
        .ok_or_else(|| "TEST_VECTORS_REQUIRED".to_string())?;
    if test_vectors.len() > 10000 {
        return Err("SOURCE_ARRAY_LIMIT_EXCEEDED:test_vectors".to_string());
    }
    if test_vectors.iter().any(|vector| !vector.is_object()) {
        return Err("SOURCE_ARRAY_ITEM_INVALID:test_vectors".to_string());
    }
    Ok(object)
}

fn validate_profile_vector_binding(value: &Value, source_hash: &str) -> Result<(), String> {
    let object = value.as_object().ok_or("PROFILE_VECTOR_BINDING_INVALID")?;
    let required = [
        "schema",
        "protocol_semver",
        "profile_id",
        "profile_semver",
        "package_digest",
        "entrypoint",
        "interface_binding",
    ];
    if object.len() != required.len()
        || required.iter().any(|field| !object.contains_key(*field))
        || object.get("schema").and_then(Value::as_str)
            != Some("KTAPEOUT-PROFILE-VECTOR-BINDING-V1")
        || object.get("protocol_semver").and_then(Value::as_str) != Some("0.5.0")
        || !object
            .get("profile_id")
            .and_then(Value::as_str)
            .is_some_and(valid_manifest_binding_id)
        || !object
            .get("profile_semver")
            .and_then(Value::as_str)
            .is_some_and(valid_manifest_binding_semver)
        || !object
            .get("package_digest")
            .and_then(Value::as_str)
            .is_some_and(valid_hash)
        || !object
            .get("entrypoint")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.is_empty() && value.len() <= 256)
    {
        return Err("PROFILE_VECTOR_BINDING_INVALID".to_string());
    }
    let interface = object
        .get("interface_binding")
        .and_then(Value::as_object)
        .ok_or("PROFILE_VECTOR_INTERFACE_BINDING_INVALID")?;
    let fields = [
        "schema",
        "interface_id",
        "interface_version",
        "consumer",
        "provider",
        "input_schema_hash",
        "output_schema_hash",
        "error_schema_hash",
        "wallet_mode",
        "settlement_mode",
        "adapter_hash",
    ];
    if interface.len() != fields.len()
        || fields.iter().any(|field| !interface.contains_key(*field))
        || interface.get("schema").and_then(Value::as_str) != Some("KTAPEOUT-INTERFACE-BINDING-V1")
        || !interface
            .get("interface_id")
            .and_then(Value::as_str)
            .is_some_and(valid_manifest_binding_id)
        || !interface
            .get("interface_version")
            .and_then(Value::as_str)
            .is_some_and(valid_manifest_binding_semver)
        || interface.get("consumer").and_then(Value::as_str) != Some(source_hash)
        || interface.get("provider").and_then(Value::as_str)
            != object.get("profile_id").and_then(Value::as_str)
        || [
            "input_schema_hash",
            "output_schema_hash",
            "error_schema_hash",
        ]
        .iter()
        .any(|field| {
            !interface
                .get(*field)
                .and_then(Value::as_str)
                .is_some_and(valid_hash)
        })
        || interface.get("wallet_mode").and_then(Value::as_str) != Some("walletless-read")
        || interface.get("settlement_mode").and_then(Value::as_str) != Some("NONE")
        || interface.get("adapter_hash").and_then(Value::as_str)
            != object.get("package_digest").and_then(Value::as_str)
    {
        return Err("PROFILE_VECTOR_INTERFACE_BINDING_INVALID".to_string());
    }
    Ok(())
}

fn valid_manifest_binding_id(value: &str) -> bool {
    value.len() <= 128
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphabetic)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn valid_manifest_binding_semver(value: &str) -> bool {
    let parts: Vec<&str> = value.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

fn validate_manifest(path: PathBuf) -> Result<(), String> {
    let value = read_json(&path)?;
    let object = validate_manifest_value(&value)?;
    let source_hash = object
        .get("source_hash")
        .and_then(Value::as_str)
        .unwrap_or_default();
    emit_result(
        "ktape app validate",
        object.get("network").and_then(Value::as_str),
        json!({"ok": true, "schema_version": SOURCE_SCHEMA, "source_hash": source_hash, "unsigned": true, "broadcast": false}),
    )
}

fn check_manifest(path: PathBuf, network: String) -> Result<(), String> {
    let source = read_json(&path)?;
    let result = check_manifest_value(&source, &network)?;
    let status = check_result_status(&result);
    emit_result_status("ktape app check", Some(&network), status, result)
}

fn check_result_status(result: &Value) -> &'static str {
    if matches!(
        result["stages"]["translation"].as_str(),
        Some("NEEDS_INPUT" | "REQUIRES_HUMAN_REVIEW")
    ) {
        "WARNING"
    } else {
        "PASS"
    }
}

/// Use the requirements derivation as the semantic source of truth for the
/// application check.  The artifact can still be built locally while the
/// application contract is incomplete, but that must remain visible to the
/// caller and to the workflow status reducer.
fn semantic_translation_status(
    requirements: &Value,
    translation: &Value,
) -> Result<&'static str, String> {
    match requirements["status"].as_str() {
        Some("NEEDS_INPUT") => Ok("NEEDS_INPUT"),
        Some("REQUIRES_HUMAN_REVIEW") => Ok("REQUIRES_HUMAN_REVIEW"),
        Some("READY_FOR_COMPOSITION") => {
            if translation["status"] == "REQUIRES_HUMAN_REVIEW" {
                Ok("REQUIRES_HUMAN_REVIEW")
            } else if translation["status"] == "READY_FOR_PREFLIGHT" {
                Ok("READY_FOR_PREFLIGHT")
            } else {
                Err("APPLICATION_TRANSLATION_STATUS_INVALID".into())
            }
        }
        _ => Err("APPLICATION_REQUIREMENTS_STATUS_INVALID".into()),
    }
}

fn check_manifest_value(source: &Value, network: &str) -> Result<Value, String> {
    if !matches!(network, "testnet-10" | "mainnet") {
        return Err("NETWORK_INVALID".to_string());
    }
    validate_manifest_value(source)?;
    if let Some(found) = contains_secret_key(source) {
        return Err(format!("SECRET_MATERIAL_FORBIDDEN:{found}"));
    }
    let artifact = artifact_build_value(source, "local-simulation", "0.5.0")?;
    validate_artifact_value(&artifact)?;
    let requirements = derive_requirements_value(source, network)?;
    let translation = translate_manifest_value(source, network)?;
    let status = semantic_translation_status(&requirements, &translation)?;
    let result_status = if status == "READY_FOR_PREFLIGHT" {
        "PASS"
    } else {
        status
    };
    Ok(json!({
        "schema":"KTAPEOUT-0.5.0-APPLICATION-CHECK-V1", "status":result_status, "network":network,
        "requirements":{"status":requirements["status"],"unknowns":requirements["unknowns"],"mvp_scope":requirements["mvp_scope"],"trace":requirements["trace"]},
        "stages":{"source_validation":"PASS", "translation":status, "capability_matrix":translation["capability_matrix"], "resource":{"schema":"KTAPEOUT-0.5.0-RESOURCE-EXPLANATION-V1","unsigned":true,"broadcast":false,"signing_allowed":false,"dimensions":resource_projection(source)?}, "artifact":{"schema":"KTAPEOUT-0.5.0-ARTIFACT-INSPECTION-V1","status":"PASS","identity_chain":{"source_hash":artifact.get("source_hash"),"semantic_ir_hash":artifact.get("semantic_ir_hash"),"developer_lock_hash":artifact.get("developer_lock_hash"),"artifact_hash":artifact.get("artifact").and_then(|value|value.get("hash"))},"backend":artifact.get("backend"),"profile_digests":artifact.get("profile_digests"),"resource_origin":artifact.get("resource_envelope").and_then(|value|value.get("origin")),"unsupported_claims":artifact.get("unsupported_claims")}},
        "next_action":if status == "READY_FOR_PREFLIGHT" {"review the unsigned artifact and operating plan before any external signer handoff"} else {"run ktape ai requirements SOURCE.json, resolve the listed contract unknowns, then rerun ktape app check"}, "signing_allowed":false, "broadcast":false
    }))
}

fn estimate(path: PathBuf, network: String) -> Result<(), String> {
    let value = read_json(&path)?;
    let object = validate_manifest_value(&value)?;
    let encoded = canonical_json(&value)?;
    let vector_count = object
        .get("test_vectors")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let storage_bytes = canonical_json(
        object
            .get("persistent_state")
            .unwrap_or(&Value::Array(Vec::new())),
    )?
    .len();
    emit_result(
        "ktape app estimate",
        Some(&network),
        json!({
            "schema": "KTAPEOUT-0.5.0-RESOURCE-ESTIMATE-V1",
            "network": network,
            "unsigned": true,
            "broadcast": false,
            "origin": "SHAPE_ESTIMATE",
            "estimate": {"max_bytes": encoded.len(), "max_actions": vector_count, "storage_floor": storage_bytes, "requires_estimate": false, "origin": "SHAPE_ESTIMATE"},
            "evidence_refs": [{"kind": "source_manifest", "hash": sha256_value(&value)?}]
        }),
    )
}

fn resource_projection(value: &Value) -> Result<Value, String> {
    let object = validate_manifest_value(value)?;
    let encoded = canonical_json(value)?;
    let vector_count = object
        .get("test_vectors")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let storage_bytes = canonical_json(
        object
            .get("persistent_state")
            .unwrap_or(&Value::Array(Vec::new())),
    )?
    .len();
    Ok(json!({
        "artifact_bytes": encoded.len(),
        "script_bytes": Value::Null,
        "witness_bytes": Value::Null,
        "transaction_bytes": Value::Null,
        "transaction_mass": Value::Null,
        "consensus_compute_mass": Value::Null,
        "per_input_execution_budget": Value::Null,
        "fee_rate": Value::Null,
        "quoted_fee": Value::Null,
        "actual_fee": Value::Null,
        "storage_value_floor_bytes": storage_bytes,
        "max_actions": vector_count,
        "origin": "SHAPE_ESTIMATE",
        "network_observation_required": true,
        "limitations": ["generic source manifest has no Profile-specific lowering", "Kaspa mass and actual fee are unavailable"]
    }))
}

fn resource_explain(path: PathBuf) -> Result<(), String> {
    let value = read_json(&path)?;
    let projection = resource_projection(&value)?;
    emit_result(
        "ktape resource explain",
        value.get("network").and_then(Value::as_str),
        json!({
            "schema": "KTAPEOUT-0.5.0-RESOURCE-EXPLANATION-V1",
            "unsigned": true,
            "broadcast": false,
            "signing_allowed": false,
            "dimensions": projection
        }),
    )
}

fn resource_quote(path: PathBuf, network: String) -> Result<(), String> {
    if !matches!(network.as_str(), "testnet-10" | "mainnet") {
        return Err("NETWORK_INVALID".to_string());
    }
    let value = read_json(&path)?;
    let projection = resource_projection(&value)?;
    emit_result(
        "ktape resource quote",
        Some(&network),
        json!({
            "schema": "KTAPEOUT-0.5.0-RESOURCE-QUOTE-V1",
            "network": network,
            "quote_status": "SHAPE_ONLY",
            "evidence_origin": "SHAPE_ESTIMATE",
            "dimensions": projection,
            "fee_authority": "UNAVAILABLE",
            "actual_network_fee": false,
            "unsigned": true,
            "broadcast": false,
            "signing_allowed": false
        }),
    )
}

fn operating_positive(
    object: &Map<String, Value>,
    field: &str,
    allow_zero: bool,
) -> Result<u64, String> {
    let value = object
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("OPERATING_INVALID:{field}"))?;
    if !allow_zero && value == 0 {
        return Err(format!("OPERATING_INVALID:{field}"));
    }
    Ok(value)
}

fn operating_reject_unknown_fields(
    object: &Map<String, Value>,
    allowed: &[&str],
    path: &str,
) -> Result<(), String> {
    let mut unknown: Vec<&str> = object
        .keys()
        .map(String::as_str)
        .filter(|field| !allowed.contains(field))
        .collect();
    unknown.sort_unstable();
    if let Some(field) = unknown.first() {
        return Err(format!("OPERATING_FIELD_UNKNOWN:{path}.{field}"));
    }
    Ok(())
}

fn parse_hash32_value(value: &Value, field: &str) -> Result<[u8; 32], String> {
    let text = value
        .as_str()
        .ok_or_else(|| format!("OPERATING_SHAPE_BINDING_INVALID:{field}"))?;
    if text.len() != 64
        || !text
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(format!("OPERATING_SHAPE_BINDING_INVALID:{field}"));
    }
    let mut out = [0u8; 32];
    for (index, chunk) in text.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(chunk)
            .map_err(|_| format!("OPERATING_SHAPE_BINDING_INVALID:{field}"))?;
        out[index] = u8::from_str_radix(pair, 16)
            .map_err(|_| format!("OPERATING_SHAPE_BINDING_INVALID:{field}"))?;
    }
    Ok(out)
}

fn validate_shape_binding_plan(plan: &Value) -> Result<String, String> {
    let object = plan
        .as_object()
        .ok_or_else(|| "OPERATING_SHAPE_BINDING_PLAN_INVALID".to_string())?;
    let required = [
        "schema",
        "protocol_semver",
        "network_id",
        "policy_id",
        "deployment_id",
        "layout_commitment",
        "action_commitment",
        "ordered_input_outpoints",
        "ordered_successor_outputs",
        "capability_commitments",
        "resource_bill_commitment",
        "transition_digest",
    ];
    if object.len() != required.len()
        || required.iter().any(|field| !object.contains_key(*field))
        || plan.get("schema").and_then(Value::as_str) != Some("KTAPEOUT-UNSIGNED-PLAN-V0.5.0")
        || plan.get("protocol_semver").and_then(Value::as_str) != Some(PROTOCOL)
    {
        return Err("OPERATING_SHAPE_BINDING_PLAN_INVALID".into());
    }
    let network = plan
        .get("network_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "OPERATING_SHAPE_BINDING_PLAN_INVALID".to_string())?;
    let policy_id = parse_hash32_value(&plan["policy_id"], "plan.policy_id")?;
    let deployment_id = parse_hash32_value(&plan["deployment_id"], "plan.deployment_id")?;
    let layout_commitment =
        parse_hash32_value(&plan["layout_commitment"], "plan.layout_commitment")?;
    let action_commitment =
        parse_hash32_value(&plan["action_commitment"], "plan.action_commitment")?;
    let resource_bill_commitment = parse_hash32_value(
        &plan["resource_bill_commitment"],
        "plan.resource_bill_commitment",
    )?;
    let input_values = plan["ordered_input_outpoints"]
        .as_array()
        .ok_or_else(|| "OPERATING_SHAPE_BINDING_PLAN_INVALID".to_string())?;
    let mut inputs = Vec::with_capacity(input_values.len());
    for item in input_values {
        if !object_fields_exact(item, &["txid", "output_index"], &[]) {
            return Err("OPERATING_SHAPE_BINDING_PLAN_INVALID".into());
        }
        let txid = parse_hash32_value(&item["txid"], "plan.input.txid")?;
        let index = item["output_index"]
            .as_u64()
            .filter(|v| *v <= u32::MAX as u64)
            .ok_or_else(|| "OPERATING_SHAPE_BINDING_PLAN_INVALID".to_string())?
            as u32;
        inputs.push((txid, index));
    }
    let successor_values = plan["ordered_successor_outputs"]
        .as_array()
        .ok_or_else(|| "OPERATING_SHAPE_BINDING_PLAN_INVALID".to_string())?;
    let mut successors = Vec::with_capacity(successor_values.len());
    for item in successor_values {
        if !object_fields_exact(
            item,
            &["output_bytes_hex", "lineage_hash", "state_root"],
            &[],
        ) {
            return Err("OPERATING_SHAPE_BINDING_PLAN_INVALID".into());
        }
        let raw = item["output_bytes_hex"]
            .as_str()
            .ok_or_else(|| "OPERATING_SHAPE_BINDING_PLAN_INVALID".to_string())?;
        if raw.is_empty() || raw.len() % 2 != 0 || raw.len() > 2 * 131072 {
            return Err("OPERATING_SHAPE_BINDING_PLAN_INVALID".into());
        }
        let mut bytes = Vec::with_capacity(raw.len() / 2);
        for chunk in raw.as_bytes().chunks_exact(2) {
            let pair = std::str::from_utf8(chunk)
                .map_err(|_| "OPERATING_SHAPE_BINDING_PLAN_INVALID".to_string())?;
            if !pair
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            {
                return Err("OPERATING_SHAPE_BINDING_PLAN_INVALID".into());
            }
            bytes.push(
                u8::from_str_radix(pair, 16)
                    .map_err(|_| "OPERATING_SHAPE_BINDING_PLAN_INVALID".to_string())?,
            );
        }
        successors.push(SuccessorBinding {
            output_bytes: bytes,
            lineage_hash: parse_hash32_value(&item["lineage_hash"], "plan.successor.lineage_hash")?,
            state_root: parse_hash32_value(&item["state_root"], "plan.successor.state_root")?,
        });
    }
    let capability_values = plan["capability_commitments"]
        .as_array()
        .ok_or_else(|| "OPERATING_SHAPE_BINDING_PLAN_INVALID".to_string())?;
    let mut capabilities = Vec::with_capacity(capability_values.len());
    for item in capability_values {
        capabilities.push(parse_hash32_value(item, "plan.capability")?);
    }
    let computed = ktapeout_core::network_bound_plan_digest_050(&NetworkBoundPlan {
        network_id: network.as_bytes(),
        policy_id: &policy_id,
        deployment_id: &deployment_id,
        layout_commitment: &layout_commitment,
        action_commitment: &action_commitment,
        input_outpoints: &inputs,
        successors: &successors,
        capability_commitments: &capabilities,
        resource_bill_commitment: &resource_bill_commitment,
    })
    .map_err(|e| e.0)?;
    let expected = hex_string(&computed);
    if plan.get("transition_digest").and_then(Value::as_str) != Some(expected.as_str()) {
        return Err("OPERATING_SHAPE_BINDING_TRANSITION_DIGEST_MISMATCH".into());
    }
    Ok(expected)
}

fn resource_bind_shape(
    plan_path: PathBuf,
    bundle_path: PathBuf,
    source_path: PathBuf,
    lock_path: PathBuf,
    policy_path: PathBuf,
) -> Result<(), String> {
    let plan = read_json(&plan_path)?;
    let bundle = read_json(&bundle_path)?;
    let source = read_json(&source_path)?;
    let lock = read_json(&lock_path)?;
    let policy = read_json(&policy_path)?;
    let transition_digest = validate_shape_binding_plan(&plan)?;
    ktapeout_runtime::validate_developer_lock(&lock)?;
    validate_artifact_v2_value(&bundle, &source, &lock, &policy)?;
    let network = plan["network_id"]
        .as_str()
        .ok_or_else(|| "OPERATING_SHAPE_BINDING_PLAN_INVALID".to_string())?;
    let policy_id = bundle["network_policy_id"]
        .as_str()
        .ok_or_else(|| "OPERATING_SHAPE_BINDING_BUNDLE_INVALID".to_string())?;
    if policy["network_id"].as_str() != Some(network)
        || source["network"].as_str() != Some(network)
        || plan["policy_id"].as_str() != Some(policy_id)
        || lock["network_policy_id"].as_str() != Some(policy_id)
    {
        return Err("OPERATING_SHAPE_BINDING_CROSS_REFERENCE_MISMATCH".into());
    }
    let material = json!({
        "schema":"KTAPEOUT-0.5.0-OPERATING-SHAPE-BINDING-V1", "protocol_semver":PROTOCOL,
        "status":"PARTIAL_UNVERIFIED_L1_FACTS", "verification_scope":"LOCAL_CROSS_REFERENCE_ONLY",
        "network_id":network,
        "references":{
            "unsigned_plan_digest":digest_json_domain(&plan, "KTAPEOUT/0.5.0/UNSIGNED_PLAN/V1")?,
            "transition_digest":transition_digest,
            "application_bundle_hash":bundle["bundle_hash"], "source_hash":bundle["source_hash"],
            "semantic_ir_hash":bundle["semantic_ir_hash"], "developer_lock_hash":lock["lock_hash"],
            "profile_digests":bundle["profile_digests"], "backend":bundle["backend"],
            "network_policy_id":policy_id
        },
        "application_plan_relation":"DECLARED_TOOLING_JOIN_NOT_PROFILE_EXECUTION_PROOF",
        "selected_utxo":{"status":"UNAVAILABLE","context_digest":Value::Null,"pinned_tip_hash":Value::Null},
        "witness":{"status":"UNAVAILABLE","template_digest":Value::Null,"measured_bytes":Value::Null},
        "limitations":[
            "the plan-to-application relation is a tooling cross-reference, not proof that the Profile executes this plan",
            "selected UTXO, pinned tip, and consensus freshness are unavailable and are not inferred from local inputs",
            "witness template and measured witness evidence are unavailable",
            "this binding grants no signing, broadcast, admission, or L1 authority"
        ],
        "signing_allowed":false,"broadcast":false
    });
    let binding_hash = digest_json_domain(&material, "KTAPEOUT/0.5.0/OPERATING_SHAPE_BINDING/V1")?;
    let mut output = material
        .as_object()
        .cloned()
        .ok_or_else(|| "OPERATING_SHAPE_BINDING_INTERNAL".to_string())?;
    output.insert("binding_hash".into(), json!(binding_hash));
    emit_result(
        "ktape resource bind-shape",
        Some(network),
        Value::Object(output),
    )
}

fn resource_plan(path: PathBuf, envelope_path: PathBuf, network: String) -> Result<(), String> {
    if !matches!(network.as_str(), "testnet-10" | "mainnet") {
        return Err("NETWORK_INVALID".to_string());
    }
    let manifest = read_json(&path)?;
    validate_manifest_value(&manifest)?;
    let envelope = read_json(&envelope_path)?;
    if envelope.get("schema").and_then(Value::as_str)
        != Some("KTAPEOUT-0.5.0-OPERATING-ENVELOPE-V1")
    {
        return Err("OPERATING_SCHEMA_INVALID".to_string());
    }
    let envelope_object = envelope
        .as_object()
        .ok_or_else(|| "OPERATING_SHAPE_INVALID".to_string())?;
    operating_reject_unknown_fields(
        envelope_object,
        &[
            "schema",
            "workload",
            "costs",
            "caps",
            "evidence",
            "operator_policy_only",
        ],
        "envelope",
    )?;
    let workload = envelope
        .get("workload")
        .and_then(Value::as_object)
        .ok_or_else(|| "OPERATING_SHAPE_INVALID".to_string())?;
    let costs = envelope
        .get("costs")
        .and_then(Value::as_object)
        .ok_or_else(|| "OPERATING_SHAPE_INVALID".to_string())?;
    let caps = match envelope.get("caps") {
        None => Map::new(),
        Some(value) => value
            .as_object()
            .cloned()
            .ok_or_else(|| "OPERATING_SHAPE_INVALID".to_string())?,
    };
    let evidence = envelope
        .get("evidence")
        .and_then(Value::as_object)
        .ok_or_else(|| "OPERATING_SHAPE_INVALID".to_string())?;
    operating_reject_unknown_fields(
        workload,
        &["actions_per_period", "peak_burst_actions", "periods"],
        "workload",
    )?;
    operating_reject_unknown_fields(
        costs,
        &[
            "one_time_sompi",
            "normal_action_sompi",
            "burst_action_sompi",
            "recovery_sompi",
            "exit_sompi",
        ],
        "costs",
    )?;
    operating_reject_unknown_fields(
        &caps,
        &["per_action_sompi", "per_period_sompi", "lifetime_sompi"],
        "caps",
    )?;
    operating_reject_unknown_fields(evidence, &["origin", "shape_binding"], "evidence")?;
    let actions = operating_positive(workload, "actions_per_period", true)?;
    let burst_actions = operating_positive(workload, "peak_burst_actions", true)
        .map_err(|_| "OPERATING_INVALID:workload.peak_burst_actions".to_string())?;
    let periods = operating_positive(workload, "periods", false)?;
    let one_time = operating_positive(costs, "one_time_sompi", true)?;
    let normal_action = operating_positive(costs, "normal_action_sompi", true)?;
    let burst_action = operating_positive(costs, "burst_action_sompi", true)?;
    let recovery = operating_positive(costs, "recovery_sompi", true)?;
    let exit = operating_positive(costs, "exit_sompi", true)?;
    let normal_period = actions
        .checked_mul(normal_action)
        .and_then(|value| value.checked_add(recovery))
        .and_then(|value| value.checked_add(exit))
        .ok_or_else(|| "OPERATING_OVERFLOW".to_string())?;
    let peak_burst = burst_actions
        .checked_mul(burst_action)
        .ok_or_else(|| "OPERATING_OVERFLOW".to_string())?;
    let lifetime = normal_period
        .checked_mul(periods)
        .and_then(|value| value.checked_add(one_time))
        .ok_or_else(|| "OPERATING_OVERFLOW".to_string())?;
    let conservative_period = actions
        .checked_mul(normal_action)
        .and_then(|value| value.checked_add(peak_burst))
        .and_then(|value| value.checked_add(recovery))
        .and_then(|value| value.checked_add(exit))
        .ok_or_else(|| "OPERATING_OVERFLOW".to_string())?;
    let conservative_lifetime = conservative_period
        .checked_mul(periods)
        .and_then(|value| value.checked_add(one_time))
        .ok_or_else(|| "OPERATING_OVERFLOW".to_string())?;
    let mut binding_diagnostics: Vec<Value> = Vec::new();
    for (field, measured, reason, equation) in [
        (
            "per_action_sompi",
            normal_action.max(burst_action),
            "PER_ACTION_CAP",
            "max(normal_action_sompi, burst_action_sompi)",
        ),
        (
            "per_period_sompi",
            conservative_period,
            "PER_PERIOD_CAP",
            "actions_per_period * normal_action_sompi + peak_burst_actions * burst_action_sompi + recovery_sompi + exit_sompi",
        ),
        (
            "lifetime_sompi",
            conservative_lifetime,
            "LIFETIME_CAP",
            "one_time_sompi + conservative_period_sompi * periods",
        ),
    ] {
        if let Some(cap_value) = caps.get(field).filter(|value| !value.is_null()) {
            let cap = cap_value
                .as_u64()
                .ok_or_else(|| format!("OPERATING_INVALID:{field}"))?;
            if measured > cap {
                binding_diagnostics.push(json!({
                    "limit": reason,
                    "actual_sompi": measured,
                    "cap_sompi": cap,
                    "over_by_sompi": measured - cap,
                    "equation": equation
                }));
            }
        }
    }
    let binding_limits: Vec<&str> = binding_diagnostics
        .iter()
        .filter_map(|item| item.get("limit").and_then(Value::as_str))
        .collect();
    let first_binding_limit = binding_diagnostics.first().cloned();
    let origin = evidence
        .get("origin")
        .and_then(Value::as_str)
        .ok_or_else(|| "OPERATING_ORIGIN_INVALID".to_string())?;
    if !matches!(
        origin,
        "STATIC"
            | "LOCAL_SIMULATION"
            | "SHAPE_ESTIMATE"
            | "FRESH_NODE_OBSERVATION"
            | "AUTHORIZED_TN10_RECEIPT"
            | "UNAVAILABLE"
    ) {
        return Err("OPERATING_ORIGIN_INVALID".to_string());
    }
    if matches!(origin, "FRESH_NODE_OBSERVATION" | "AUTHORIZED_TN10_RECEIPT") {
        return Err(format!("OPERATING_EVIDENCE_PROVENANCE_REQUIRED:{origin}"));
    }
    let shape_binding = evidence
        .get("shape_binding")
        .cloned()
        .unwrap_or(Value::Null);
    if !shape_binding.is_null() && !shape_binding.is_string() {
        return Err("OPERATING_INVALID:evidence.shape_binding".to_string());
    }
    if let Some(value) = envelope.get("operator_policy_only") {
        if !value.is_boolean() {
            return Err("OPERATING_INVALID:operator_policy_only".to_string());
        }
        if value.as_bool() != Some(true) {
            return Err("OPERATING_OPERATOR_POLICY_ONLY_REQUIRED".to_string());
        }
    }
    let status = if binding_limits.is_empty() {
        "FEASIBLE"
    } else {
        "ECONOMICALLY_INFEASIBLE_FOR_DECLARED_WORKLOAD"
    };
    let normalized_caps: Map<String, Value> = caps
        .iter()
        .filter(|(_, value)| !value.is_null())
        .map(|(field, value)| (field.clone(), value.clone()))
        .collect();
    let envelope_out = json!({
        "schema": "KTAPEOUT-0.5.0-OPERATING-ENVELOPE-V1",
        "workload": {"actions_per_period": actions, "peak_burst_actions": burst_actions, "periods": periods},
        "costs": {"one_time_sompi": one_time, "normal_action_sompi": normal_action, "burst_action_sompi": burst_action, "recovery_sompi": recovery, "exit_sompi": exit},
        "caps": normalized_caps,
        "evidence": {"origin": origin, "shape_binding": shape_binding},
        "operator_policy_only": true
    });
    emit_result(
        "ktape resource plan",
        Some(&network),
        json!({
            "schema": "KTAPEOUT-0.5.0-OPERATING-PLAN-V1",
            "network": network,
            "unsigned": true,
            "broadcast": false,
            "signing_allowed": false,
            "status": status,
            "evidence_origin": origin,
            "operator_policy_only": envelope.get("operator_policy_only").and_then(Value::as_bool).unwrap_or(true),
            "cost_sompi": {"one_time": one_time, "normal_period": normal_period, "peak_burst": peak_burst, "conservative_period": conservative_period, "lifetime": lifetime, "lifetime_conservative": conservative_lifetime},
            "binding_limits": binding_limits,
            "binding_diagnostics": binding_diagnostics,
            "first_binding_limit": first_binding_limit,
            "period_scenario": "NORMAL_PLUS_PEAK_BURST_EVERY_PERIOD_CONSERVATIVE",
            "limitations": [
                "period and lifetime caps are operator policy unless an admitted Profile or voucher tracks them on-chain",
                "shape_binding is opaque caller metadata; it is not verified and does not bind artifact, DeveloperLock, NetworkPolicy, UTXO, witness shape, or plan freshness"
            ],
            "envelope": envelope_out
        }),
    )
}

fn resource_calibration_status() -> Result<(), String> {
    emit_result_status(
        "ktape resource calibration-status",
        None,
        "UNAVAILABLE",
        json!({
            "schema": "KTAPEOUT-0.5.0-RESOURCE-CALIBRATION-STATUS-V1",
            "status": "UNAVAILABLE",
            "origin": "UNAVAILABLE",
            "authorized_receipt_required": true,
            "signing_allowed": false,
            "broadcast": false
        }),
    )
}

fn artifact_build_value(source: &Value, backend: &str, version: &str) -> Result<Value, String> {
    validate_manifest_value(source)?;
    if let Some(found) = contains_secret_key(source) {
        return Err(format!("SECRET_MATERIAL_FORBIDDEN:{found}"));
    }
    let adapter = backend_adapter_descriptor(backend)?;
    if adapter.get("version").and_then(Value::as_str) != Some(version) {
        return Err("BACKEND_VERSION_UNSUPPORTED".to_string());
    }
    let source_hash = sha256_value(source)?;
    let atomicity_class = source
        .get("atomicity_class")
        .and_then(Value::as_str)
        .unwrap_or("A0");
    if !["A0", "A1", "A2", "A3", "A4", "A5"].contains(&atomicity_class) {
        return Err("ATOMICITY_CLASS_UNSUPPORTED".to_string());
    }
    if !adapter
        .get("atomicity_classes")
        .and_then(Value::as_array)
        .is_some_and(|classes| {
            classes
                .iter()
                .any(|value| value.as_str() == Some(atomicity_class))
        })
    {
        return Err("BACKEND_CAPABILITY_MISMATCH".to_string());
    }
    let mut semantic = json!({"schema":"KTAPEOUT-0.5.0-APPLICATION-SEMANTIC-IR-V1", "source_kind":source.get("source_kind"), "inputs":source.get("inputs"), "outputs":source.get("outputs"), "persistent_state":source.get("persistent_state"), "authorities":source.get("authorities"), "value_flows":source.get("value_flows"), "availability_expectations":source.get("availability_expectations")});
    if source.get("atomicity_class").is_some() {
        semantic["atomicity_class"] = json!(atomicity_class);
    }
    if semantic
        .get("source_kind")
        .and_then(Value::as_str)
        .filter(|kind| !kind.is_empty() && kind.len() <= 128)
        .is_none()
    {
        return Err("APPLICATION_SEMANTIC_IR_SOURCE_KIND_INVALID".into());
    }
    for field in [
        "inputs",
        "outputs",
        "persistent_state",
        "authorities",
        "value_flows",
        "availability_expectations",
    ] {
        if !semantic.get(field).is_some_and(Value::is_array) {
            return Err("APPLICATION_SEMANTIC_IR_ARRAY_INVALID".into());
        }
    }
    let semantic_hash = digest_bytes(
        &canonical_json(&semantic)?,
        "KTAPEOUT/0.5.0/APPLICATION_SEMANTIC_IR/V1",
    );
    let backend_hash = backend_adapter_hash(backend)?;
    let lock = json!({"protocol_semver":"0.5.0", "source_hash":source_hash, "semantic_ir_hash":semantic_hash, "backend_id":backend, "backend_version":version, "backend_adapter_hash":backend_hash});
    let lock_hash = sha256_value(&lock)?;
    let payload = json!({"lock_hash":lock_hash, "semantic_ir_hash":semantic_hash, "backend_id":backend, "backend_version":version, "backend_adapter_hash":backend_hash, "source_hash":source_hash});
    let artifact_hash = sha256_value(&payload)?;
    Ok(json!({
        "schema":"KTAPEOUT-0.5.0-APPLICATION-ARTIFACT-BUNDLE-V1", "protocol_semver":"0.5.0", "source_hash":source_hash,
        "semantic_ir_hash":semantic_hash, "developer_lock_hash":lock_hash, "profile_digests":[],
        "backend":{"id":backend,"version":version,"digest":backend_hash},
        "artifact":{"format":"ktbin-local","hash":artifact_hash,"bytes":canonical_json(&payload)?.len(),"payload":payload},
        "dependencies":[], "resource_envelope":{"origin":"SHAPE_ESTIMATE","signing_allowed":false,"broadcast":false},
        "invariant_root":sha256_value(&json!({"invariants":[]}))?, "vector_root":sha256_value(&json!({"vectors":source.get("test_vectors").unwrap_or(&Value::Array(Vec::new()))}))?,
        "unsupported_claims":["no L1 admission","no signer authority","no Mainnet claim"], "status":"LOCAL_ONLY"
    }))
}

fn validate_artifact_value(value: &Value) -> Result<(), String> {
    if value.get("schema").and_then(Value::as_str)
        != Some("KTAPEOUT-0.5.0-APPLICATION-ARTIFACT-BUNDLE-V1")
        || value.get("status").and_then(Value::as_str) != Some("LOCAL_ONLY")
    {
        return Err("ARTIFACT_IDENTITY_INVALID".to_string());
    }
    let artifact = value
        .get("artifact")
        .and_then(Value::as_object)
        .ok_or_else(|| "ARTIFACT_SHAPE_INVALID".to_string())?;
    let payload = artifact
        .get("payload")
        .ok_or_else(|| "ARTIFACT_SHAPE_INVALID".to_string())?;
    let backend = value
        .get("backend")
        .and_then(Value::as_object)
        .ok_or_else(|| "ARTIFACT_SHAPE_INVALID".to_string())?;
    let backend_id = backend
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| "ARTIFACT_SHAPE_INVALID".to_string())?;
    let backend_version = backend
        .get("version")
        .and_then(Value::as_str)
        .ok_or_else(|| "ARTIFACT_SHAPE_INVALID".to_string())?;
    let adapter = backend_adapter_descriptor(backend_id)?;
    if adapter.get("version").and_then(Value::as_str) != Some(backend_version) {
        return Err("BACKEND_VERSION_UNSUPPORTED".to_string());
    }
    let adapter_hash = backend_adapter_hash(backend_id)?;
    if backend.get("digest").and_then(Value::as_str) != Some(adapter_hash.as_str()) {
        return Err("BACKEND_ADAPTER_HASH_MISMATCH".to_string());
    }
    let expected_lock = json!({"protocol_semver":"0.5.0", "source_hash":value.get("source_hash"), "semantic_ir_hash":value.get("semantic_ir_hash"), "backend_id":backend_id, "backend_version":backend_version, "backend_adapter_hash":adapter_hash});
    let expected_lock_hash = sha256_value(&expected_lock)?;
    if value.get("developer_lock_hash").and_then(Value::as_str) != Some(expected_lock_hash.as_str())
    {
        return Err("ARTIFACT_DEVELOPER_LOCK_MISMATCH".to_string());
    }
    let expected_payload = json!({"lock_hash":expected_lock_hash, "semantic_ir_hash":value.get("semantic_ir_hash"), "backend_id":backend_id, "backend_version":backend_version, "backend_adapter_hash":adapter_hash, "source_hash":value.get("source_hash")});
    if payload != &expected_payload {
        return Err("ARTIFACT_PAYLOAD_BINDING_MISMATCH".to_string());
    }
    let expected_hash = sha256_value(payload)?;
    if artifact.get("hash").and_then(Value::as_str) != Some(expected_hash.as_str()) {
        return Err("ARTIFACT_HASH_MISMATCH".to_string());
    }
    if artifact.get("bytes").and_then(Value::as_u64) != Some(canonical_json(payload)?.len() as u64)
    {
        return Err("ARTIFACT_BYTE_COUNT_MISMATCH".to_string());
    }
    if value
        .get("resource_envelope")
        .and_then(Value::as_object)
        .and_then(|v| v.get("signing_allowed"))
        .and_then(Value::as_bool)
        != Some(false)
        || value
            .get("resource_envelope")
            .and_then(Value::as_object)
            .and_then(|v| v.get("broadcast"))
            .and_then(Value::as_bool)
            != Some(false)
    {
        return Err("ARTIFACT_AUTHORITY_FORBIDDEN".to_string());
    }
    Ok(())
}

fn object_fields_exact(value: &Value, required: &[&str], optional: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        required.iter().all(|key| object.contains_key(*key))
            && object
                .keys()
                .all(|key| required.contains(&key.as_str()) || optional.contains(&key.as_str()))
    })
}

fn validate_artifact_v2_value(
    value: &Value,
    source: &Value,
    developer_lock: &Value,
    network_policy: &Value,
) -> Result<(), String> {
    fn validate_jcs_input(value: &Value, path: &str, depth: usize) -> Result<(), String> {
        if depth > 64 {
            return Err(format!("V2_CANONICAL_DEPTH_LIMIT:{path}"));
        }
        match value {
            Value::Number(number) => {
                let safe = number
                    .as_i64()
                    .is_some_and(|v| v.unsigned_abs() <= 9_007_199_254_740_991)
                    || number.as_u64().is_some_and(|v| v <= 9_007_199_254_740_991);
                if !safe {
                    return Err(format!("V2_CANONICAL_NUMBER_UNSAFE:{path}"));
                }
            }
            Value::Object(map) => {
                for (key, child) in map {
                    if !key.is_ascii() {
                        return Err(format!("V2_CANONICAL_KEY_INVALID:{path}"));
                    }
                    validate_jcs_input(child, path, depth + 1)?;
                }
            }
            Value::Array(values) => {
                for child in values {
                    validate_jcs_input(child, path, depth + 1)?;
                }
            }
            _ => (),
        }
        Ok(())
    }
    const REQUIRED: &[&str] = &[
        "schema",
        "protocol_semver",
        "artifact_build_identity_hash",
        "source_hash",
        "semantic_ir_hash",
        "developer_lock_hash",
        "profile_digests",
        "network_policy_id",
        "backend",
        "artifact",
        "dependencies",
        "resource_envelope",
        "invariant_root",
        "vector_root",
        "unsupported_claims",
        "status",
        "bundle_hash",
    ];
    let object = value
        .as_object()
        .ok_or_else(|| "V2_BUNDLE_NOT_OBJECT".to_string())?;
    if object.len() != REQUIRED.len()
        || REQUIRED.iter().any(|key| !object.contains_key(*key))
        || value.get("schema").and_then(Value::as_str)
            != Some("KTAPEOUT-0.5.0-APPLICATION-ARTIFACT-BUNDLE-V2")
        || value.get("protocol_semver").and_then(Value::as_str) != Some("0.5.0")
        || value.get("status").and_then(Value::as_str) != Some("LOCAL_ONLY")
    {
        return Err("V2_BUNDLE_IDENTITY_INVALID".into());
    }
    validate_jcs_input(value, "$bundle", 0)?;
    validate_jcs_input(source, "$source", 0)?;
    validate_jcs_input(developer_lock, "$developer_lock", 0)?;
    validate_jcs_input(network_policy, "$network_policy", 0)?;
    validate_manifest_value(source)?;
    ktapeout_runtime::validate_developer_lock(developer_lock)?;
    let policy = network_policy
        .as_object()
        .ok_or_else(|| "NETWORK_POLICY_SCHEMA_INVALID".to_string())?;
    let policy_required = [
        "schema",
        "policy_id",
        "network_id",
        "consensus_id",
        "transaction_version",
        "transaction_codec_id",
        "node_toolchain",
        "limits",
        "fee_policy",
        "confirmation_policy",
        "reorg_policy",
    ];
    if !object_fields_exact(network_policy, &policy_required, &["execution_features"])
        || network_policy.get("schema").and_then(Value::as_str)
            != Some("KTAPEOUT-NETWORK-POLICY-V0.5.0")
    {
        return Err("NETWORK_POLICY_SCHEMA_INVALID".into());
    }
    let node = network_policy
        .get("node_toolchain")
        .ok_or_else(|| "NETWORK_POLICY_SCHEMA_INVALID".to_string())?;
    let limits = network_policy
        .get("limits")
        .ok_or_else(|| "NETWORK_POLICY_SCHEMA_INVALID".to_string())?;
    let fee = network_policy
        .get("fee_policy")
        .ok_or_else(|| "NETWORK_POLICY_SCHEMA_INVALID".to_string())?;
    let confirmation = network_policy
        .get("confirmation_policy")
        .ok_or_else(|| "NETWORK_POLICY_SCHEMA_INVALID".to_string())?;
    let reorg = network_policy
        .get("reorg_policy")
        .ok_or_else(|| "NETWORK_POLICY_SCHEMA_INVALID".to_string())?;
    if !object_fields_exact(
        node,
        &["node_version", "sdk_version"],
        &["compiler_version"],
    ) || !["node_version", "sdk_version"].iter().all(|key| {
        node.get(*key)
            .and_then(Value::as_str)
            .is_some_and(|v| !v.is_empty() && v.len() <= 128)
    }) || !object_fields_exact(
        limits,
        &[
            "max_mass",
            "max_compute_units",
            "max_script_bytes",
            "max_transaction_bytes",
        ],
        &[],
    ) || ![
        "max_mass",
        "max_compute_units",
        "max_script_bytes",
        "max_transaction_bytes",
    ]
    .iter()
    .all(|key| {
        limits
            .get(*key)
            .and_then(Value::as_u64)
            .is_some_and(|v| v <= 9_007_199_254_740_991)
    }) || !object_fields_exact(
        fee,
        &["quote_method", "currency_unit", "requires_fresh_quote"],
        &[],
    ) || fee
        .get("quote_method")
        .and_then(Value::as_str)
        .is_none_or(|v| v.is_empty() || v.len() > 128)
        || fee
            .get("currency_unit")
            .and_then(Value::as_str)
            .is_none_or(|v| v.is_empty() || v.len() > 32)
        || fee
            .get("requires_fresh_quote")
            .and_then(Value::as_bool)
            .is_none()
        || !object_fields_exact(confirmation, &["state_labels", "minimum_observations"], &[])
        || !confirmation
            .get("state_labels")
            .and_then(Value::as_array)
            .is_some_and(|a| {
                !a.is_empty()
                    && a.len() <= 16
                    && a.iter()
                        .all(|v| v.as_str().is_some_and(|s| !s.is_empty() && s.len() <= 32))
            })
        || confirmation
            .get("minimum_observations")
            .and_then(Value::as_u64)
            .is_none()
        || !object_fields_exact(
            reorg,
            &["must_revalidate_outpoint", "terminal_state_on_reorg"],
            &[],
        )
        || reorg
            .get("must_revalidate_outpoint")
            .and_then(Value::as_bool)
            != Some(true)
        || reorg
            .get("terminal_state_on_reorg")
            .and_then(Value::as_str)
            .is_none_or(|v| v.is_empty() || v.len() > 32)
        || network_policy
            .get("network_id")
            .and_then(Value::as_str)
            .is_none_or(|v| {
                v.is_empty()
                    || v.len() > 64
                    || !v.is_ascii()
                    || !v.chars().all(|c| {
                        c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-')
                    })
            })
        || network_policy
            .get("consensus_id")
            .and_then(Value::as_str)
            .is_none_or(|v| v.is_empty() || v.len() > 128)
        || network_policy
            .get("transaction_version")
            .and_then(Value::as_u64)
            .is_none_or(|v| v > 255)
        || network_policy
            .get("transaction_codec_id")
            .and_then(Value::as_str)
            .is_none_or(|v| {
                v.is_empty()
                    || v.len() > 128
                    || !v.is_ascii()
                    || !v
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-'))
            })
    {
        return Err("NETWORK_POLICY_SCHEMA_INVALID".into());
    }
    if let Some(features) = network_policy.get("execution_features") {
        if !object_fields_exact(features, &[], &["opcodes", "precompiles"]) {
            return Err("NETWORK_POLICY_SCHEMA_INVALID".into());
        }
        for (key, max_len) in [("opcodes", 64usize), ("precompiles", 128usize)] {
            if let Some(items) = features.get(key) {
                if !items.as_array().is_some_and(|array| {
                    array.len() <= 256
                        && array.iter().all(|v| {
                            v.as_str()
                                .is_some_and(|s| !s.is_empty() && s.len() <= max_len)
                        })
                }) {
                    return Err("NETWORK_POLICY_SCHEMA_INVALID".into());
                }
            }
        }
    }
    let policy_id = network_policy
        .get("policy_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "NETWORK_POLICY_SCHEMA_INVALID".to_string())?;
    let mut policy_material = policy.clone();
    policy_material.remove("policy_id");
    let expected_policy = digest_bytes(
        &canonical_json(&Value::Object(policy_material))?,
        "KTAPEOUT/0.5.0/NETWORK_POLICY/V1",
    );
    if policy_id != expected_policy
        || developer_lock
            .get("network_policy_id")
            .and_then(Value::as_str)
            != Some(policy_id)
        || value.get("network_policy_id").and_then(Value::as_str) != Some(policy_id)
    {
        return Err("NETWORK_POLICY_HASH_OR_LOCK_MISMATCH".into());
    }
    let source_hash = sha256_value(source)?;
    if value.get("source_hash").and_then(Value::as_str) != Some(source_hash.as_str()) {
        return Err("SOURCE_HASH_MISMATCH".into());
    }
    let mut semantic = json!({"schema":"KTAPEOUT-0.5.0-APPLICATION-SEMANTIC-IR-V1", "source_kind":source.get("source_kind"), "inputs":source.get("inputs"), "outputs":source.get("outputs"), "persistent_state":source.get("persistent_state"), "authorities":source.get("authorities"), "value_flows":source.get("value_flows"), "availability_expectations":source.get("availability_expectations")});
    if let Some(class) = source.get("atomicity_class") {
        semantic["atomicity_class"] = class.clone();
    }
    let semantic_hash = digest_bytes(
        &canonical_json(&semantic)?,
        "KTAPEOUT/0.5.0/APPLICATION_SEMANTIC_IR/V1",
    );
    if value.get("semantic_ir_hash").and_then(Value::as_str) != Some(semantic_hash.as_str()) {
        return Err("SEMANTIC_IR_HASH_MISMATCH".into());
    }
    let lock_hash = developer_lock
        .get("lock_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| "DEVELOPER_LOCK_HASH_INVALID".to_string())?;
    if value.get("developer_lock_hash").and_then(Value::as_str) != Some(lock_hash) {
        return Err("DEVELOPER_LOCK_HASH_MISMATCH".into());
    }
    let profiles = developer_lock
        .get("profiles")
        .and_then(Value::as_array)
        .ok_or_else(|| "DEVELOPER_LOCK_PROFILES_INVALID".to_string())?;
    let mut profile_digests: Vec<String> = profiles
        .iter()
        .filter_map(|p| {
            p.get("package_digest")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .collect();
    profile_digests.sort();
    profile_digests.dedup();
    let expected_profiles: Vec<Value> = profile_digests.iter().map(|p| json!(p)).collect();
    if value.get("profile_digests") != Some(&json!(expected_profiles)) {
        return Err("PROFILE_DIGEST_SET_MISMATCH".into());
    }
    for field in [
        "artifact_build_identity_hash",
        "source_hash",
        "semantic_ir_hash",
        "developer_lock_hash",
        "invariant_root",
        "vector_root",
    ] {
        let hash = value
            .get(field)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("V2_HASH_FIELD_INVALID:{field}"))?;
        if hash.len() != 64
            || !hash
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(format!("V2_HASH_FIELD_INVALID:{field}"));
        }
    }
    let dependencies = value
        .get("dependencies")
        .and_then(Value::as_array)
        .ok_or_else(|| "V2_DEPENDENCIES_INVALID".to_string())?;
    if dependencies.len() > 64
        || dependencies.iter().any(|item| {
            item.as_str().is_none_or(|hash| {
                hash.len() != 64
                    || !hash
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            })
        })
    {
        return Err("V2_DEPENDENCIES_INVALID".into());
    }
    if !value
        .get("unsupported_claims")
        .and_then(Value::as_array)
        .is_some_and(|items| !items.is_empty() && items.iter().all(Value::is_string))
    {
        return Err("V2_UNSUPPORTED_CLAIMS_INVALID".into());
    }
    let backend = value
        .get("backend")
        .ok_or_else(|| "V2_BACKEND_INVALID".to_string())?;
    if !object_fields_exact(backend, &["id", "version", "digest"], &[]) {
        return Err("V2_BACKEND_INVALID".into());
    }
    let backend_id = backend
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| "V2_BACKEND_INVALID".to_string())?;
    let backend_version = backend
        .get("version")
        .and_then(Value::as_str)
        .ok_or_else(|| "V2_BACKEND_INVALID".to_string())?;
    let backend_hash = backend_adapter_hash(backend_id)?;
    let adapter = backend_adapter_descriptor(backend_id)?;
    if adapter.get("version").and_then(Value::as_str) != Some(backend_version)
        || backend.get("digest").and_then(Value::as_str) != Some(backend_hash.as_str())
    {
        return Err("BACKEND_ADAPTER_HASH_MISMATCH".into());
    }
    let atomicity_class = source
        .get("atomicity_class")
        .and_then(Value::as_str)
        .unwrap_or("A0");
    if !adapter
        .get("atomicity_classes")
        .and_then(Value::as_array)
        .is_some_and(|classes| {
            classes
                .iter()
                .any(|value| value.as_str() == Some(atomicity_class))
        })
    {
        return Err("BACKEND_CAPABILITY_MISMATCH".into());
    }
    let identity = json!({"schema":"KTAPEOUT-0.5.0-ARTIFACT-BUILD-IDENTITY-V2", "protocol_semver":"0.5.0", "source_hash":source_hash, "semantic_ir_hash":semantic_hash, "backend":{"id":backend_id,"version":backend_version,"digest":backend_hash}, "developer_lock_hash":lock_hash, "profile_package_digests":profile_digests, "network_policy_hash":policy_id});
    let identity_hash = digest_bytes(
        &canonical_json(&identity)?,
        "KTAPEOUT/0.5.0/ARTIFACT_BUILD_ID/V2",
    );
    if value
        .get("artifact_build_identity_hash")
        .and_then(Value::as_str)
        != Some(identity_hash.as_str())
    {
        return Err("ARTIFACT_BUILD_ID_HASH_MISMATCH".into());
    }
    let expected_payload = json!({"artifact_build_identity_hash":identity_hash,"source_hash":source_hash,"semantic_ir_hash":semantic_hash,"developer_lock_hash":lock_hash,"profile_package_digests":profile_digests,"network_policy_hash":policy_id,"backend":backend});
    let artifact = value
        .get("artifact")
        .and_then(Value::as_object)
        .ok_or_else(|| "V2_ARTIFACT_INVALID".to_string())?;
    if artifact.len() != 4
        || !["format", "hash", "bytes", "payload"]
            .iter()
            .all(|key| artifact.contains_key(*key))
        || artifact
            .get("format")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    {
        return Err("V2_ARTIFACT_INVALID".into());
    }
    let expected_artifact_hash = sha256_value(&expected_payload)?;
    if artifact.get("payload") != Some(&expected_payload)
        || artifact.get("hash").and_then(Value::as_str) != Some(expected_artifact_hash.as_str())
        || artifact.get("bytes").and_then(Value::as_u64)
            != Some(canonical_json(&expected_payload)?.len() as u64)
    {
        return Err("V2_ARTIFACT_PAYLOAD_MISMATCH".into());
    }
    if value
        .get("resource_envelope")
        .and_then(|v| v.get("signing_allowed"))
        .and_then(Value::as_bool)
        != Some(false)
        || value
            .get("resource_envelope")
            .and_then(|v| v.get("broadcast"))
            .and_then(Value::as_bool)
            != Some(false)
    {
        return Err("V2_ARTIFACT_AUTHORITY_FORBIDDEN".into());
    }
    let mut bundle_material = object.clone();
    let supplied_bundle_hash = bundle_material
        .remove("bundle_hash")
        .and_then(|h| h.as_str().map(str::to_owned))
        .ok_or_else(|| "ARTIFACT_BUNDLE_HASH_INVALID".to_string())?;
    let computed_bundle_hash = digest_bytes(
        &canonical_json(&Value::Object(bundle_material))?,
        "KTAPEOUT/0.5.0/APPLICATION_ARTIFACT_BUNDLE/V2",
    );
    if supplied_bundle_hash != computed_bundle_hash {
        return Err("ARTIFACT_BUNDLE_HASH_MISMATCH".into());
    }
    Ok(())
}

fn artifact_build_v2_value(
    source: &Value,
    developer_lock: &Value,
    network_policy: &Value,
    backend_id: &str,
    backend_version: &str,
) -> Result<Value, String> {
    validate_manifest_value(source)?;
    ktapeout_runtime::validate_developer_lock(developer_lock)?;
    if network_policy.get("schema").and_then(Value::as_str)
        != Some("KTAPEOUT-NETWORK-POLICY-V0.5.0")
    {
        return Err("NETWORK_POLICY_SCHEMA_INVALID".into());
    }
    let mut policy_material = network_policy
        .as_object()
        .cloned()
        .ok_or_else(|| "NETWORK_POLICY_SCHEMA_INVALID".to_string())?;
    let policy_id = policy_material
        .remove("policy_id")
        .and_then(|v| v.as_str().map(str::to_owned))
        .ok_or_else(|| "NETWORK_POLICY_SCHEMA_INVALID".to_string())?;
    let computed_policy = digest_bytes(
        &canonical_json(&Value::Object(policy_material))?,
        "KTAPEOUT/0.5.0/NETWORK_POLICY/V1",
    );
    if policy_id != computed_policy
        || developer_lock
            .get("network_policy_id")
            .and_then(Value::as_str)
            != Some(policy_id.as_str())
    {
        return Err("DEVELOPER_LOCK_NETWORK_POLICY_MISMATCH".into());
    }
    let adapter = backend_adapter_descriptor(backend_id)?;
    if adapter.get("version").and_then(Value::as_str) != Some(backend_version) {
        return Err("BACKEND_VERSION_UNSUPPORTED".into());
    }
    let source_hash = sha256_value(source)?;
    let mut semantic = json!({"schema":"KTAPEOUT-0.5.0-APPLICATION-SEMANTIC-IR-V1", "source_kind":source.get("source_kind"), "inputs":source.get("inputs"), "outputs":source.get("outputs"), "persistent_state":source.get("persistent_state"), "authorities":source.get("authorities"), "value_flows":source.get("value_flows"), "availability_expectations":source.get("availability_expectations")});
    if let Some(class) = source.get("atomicity_class") {
        semantic["atomicity_class"] = class.clone();
    }
    let semantic_hash = digest_bytes(
        &canonical_json(&semantic)?,
        "KTAPEOUT/0.5.0/APPLICATION_SEMANTIC_IR/V1",
    );
    let backend_hash = backend_adapter_hash(backend_id)?;
    let backend = json!({"id":backend_id,"version":backend_version,"digest":backend_hash});
    let lock_hash = developer_lock
        .get("lock_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| "DEVELOPER_LOCK_HASH_INVALID".to_string())?;
    let profiles = developer_lock
        .get("profiles")
        .and_then(Value::as_array)
        .ok_or_else(|| "DEVELOPER_LOCK_PROFILES_INVALID".to_string())?;
    let mut profile_digests: Vec<String> = profiles
        .iter()
        .filter_map(|p| {
            p.get("package_digest")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .collect();
    profile_digests.sort();
    profile_digests.dedup();
    if profile_digests.is_empty() || profile_digests.len() > 64 {
        return Err("PROFILE_DIGEST_SET_INVALID".into());
    }
    let identity = json!({"schema":"KTAPEOUT-0.5.0-ARTIFACT-BUILD-IDENTITY-V2", "protocol_semver":"0.5.0", "source_hash":source_hash, "semantic_ir_hash":semantic_hash, "backend":backend, "developer_lock_hash":lock_hash, "profile_package_digests":profile_digests, "network_policy_hash":policy_id});
    let identity_hash = digest_bytes(
        &canonical_json(&identity)?,
        "KTAPEOUT/0.5.0/ARTIFACT_BUILD_ID/V2",
    );
    let payload = json!({"artifact_build_identity_hash":identity_hash,"source_hash":source_hash,"semantic_ir_hash":semantic_hash,"developer_lock_hash":lock_hash,"profile_package_digests":profile_digests,"network_policy_hash":policy_id,"backend":backend});
    let artifact_hash = sha256_value(&payload)?;
    let mut bundle = json!({
        "schema":"KTAPEOUT-0.5.0-APPLICATION-ARTIFACT-BUNDLE-V2", "protocol_semver":"0.5.0", "artifact_build_identity_hash":identity_hash,
        "source_hash":source_hash,"semantic_ir_hash":semantic_hash,"developer_lock_hash":lock_hash,"profile_digests":profile_digests,"network_policy_id":policy_id,
        "backend":backend,"artifact":{"format":"ktbin-local","hash":artifact_hash,"bytes":canonical_json(&payload)?.len(),"payload":payload},"dependencies":[],
        "resource_envelope":{"origin":"SHAPE_ESTIMATE","signing_allowed":false,"broadcast":false},"invariant_root":sha256_value(&json!({"invariants":[]}))?,
        "vector_root":sha256_value(&json!({"vectors":source.get("test_vectors").unwrap_or(&Value::Array(Vec::new()))}))?,
        "unsupported_claims":["no L1 admission","no signer authority","no Mainnet claim"],"status":"LOCAL_ONLY"
    });
    let bundle_hash = digest_bytes(
        &canonical_json(&bundle)?,
        "KTAPEOUT/0.5.0/APPLICATION_ARTIFACT_BUNDLE/V2",
    );
    bundle["bundle_hash"] = json!(bundle_hash);
    validate_artifact_v2_value(&bundle, source, developer_lock, network_policy)?;
    Ok(bundle)
}

fn backend_adapter_descriptor(backend: &str) -> Result<Value, String> {
    let descriptor = match backend {
        "external-experimental" => {
            json!({"schema":"KTAPEOUT-0.5.0-BACKEND-ADAPTER-V1","adapter_id":backend,"version":"0.5.0","atomicity_classes":["A0","A1"],"networks":["offline"],"status":"EXPERIMENTAL","signing_allowed":false,"broadcast":false})
        }
        "local-simulation" => {
            json!({"schema":"KTAPEOUT-0.5.0-BACKEND-ADAPTER-V1","adapter_id":backend,"version":"0.5.0","atomicity_classes":["A0","A1","A2","A3"],"networks":["offline"],"status":"LOCAL_ONLY","signing_allowed":false,"broadcast":false})
        }
        "native-kas-bounded" => {
            json!({"schema":"KTAPEOUT-0.5.0-BACKEND-ADAPTER-V1","adapter_id":backend,"version":"0.5.0","atomicity_classes":["A0","A1","A2","A3"],"networks":["testnet-10"],"status":"PROFILE_ONLY","signing_allowed":false,"broadcast":false})
        }
        _ => return Err("BACKEND_UNSUPPORTED".to_string()),
    };
    Ok(descriptor)
}

fn backend_adapter_hash(backend: &str) -> Result<String, String> {
    Ok(digest_bytes(
        &canonical_json(&backend_adapter_descriptor(backend)?)?,
        "KTAPEOUT/0.5.0/BACKEND_ADAPTER/V1",
    ))
}

fn artifact_backends() -> Result<(), String> {
    let mut adapters = Vec::new();
    for backend in [
        "external-experimental",
        "local-simulation",
        "native-kas-bounded",
    ] {
        let mut adapter = backend_adapter_descriptor(backend)?;
        adapter
            .as_object_mut()
            .ok_or_else(|| "BACKEND_ADAPTER_DESCRIPTOR_INVALID".to_string())?
            .insert("adapter_hash".into(), json!(backend_adapter_hash(backend)?));
        adapters.push(adapter);
    }
    emit_result(
        "ktape artifact backends",
        None,
        json!({"schema":"KTAPEOUT-0.5.0-BACKEND-ADAPTER-REGISTRY-V1","adapters":adapters}),
    )
}

fn artifact_select(
    backend: String,
    atomicity_class: String,
    network: String,
) -> Result<(), String> {
    let adapter = backend_adapter_descriptor(&backend)?;
    if !["A0", "A1", "A2", "A3", "A4", "A5"].contains(&atomicity_class.as_str()) {
        return Err("ATOMICITY_CLASS_UNSUPPORTED".to_string());
    }
    if !adapter
        .get("atomicity_classes")
        .and_then(Value::as_array)
        .is_some_and(|classes| {
            classes
                .iter()
                .any(|value| value.as_str() == Some(&atomicity_class))
        })
        || !adapter
            .get("networks")
            .and_then(Value::as_array)
            .is_some_and(|networks| {
                networks
                    .iter()
                    .any(|value| value.as_str() == Some(&network))
            })
    {
        return Err("BACKEND_CAPABILITY_MISMATCH".to_string());
    }
    emit_result(
        "ktape artifact select",
        Some(&network),
        json!({"schema":"KTAPEOUT-0.5.0-BACKEND-SELECTION-V1","adapter_id":backend,"adapter_version":adapter.get("version"),"adapter_hash":backend_adapter_hash(&backend)?,"atomicity_class":atomicity_class,"network":network,"status":adapter.get("status"),"signing_allowed":false,"broadcast":false}),
    )
}

fn artifact_build_inputs(
    source: &Value,
    developer_lock: Option<PathBuf>,
    network_policy: Option<PathBuf>,
    backend: &str,
    version: &str,
) -> Result<Value, String> {
    match (developer_lock, network_policy) {
        (None, None) => artifact_build_value(source, backend, version),
        (Some(lock), Some(policy)) => artifact_build_v2_value(
            source,
            &read_json(&lock)?,
            &read_json(&policy)?,
            backend,
            version,
        ),
        _ => Err("--developer-lock and --network-policy must be supplied together".into()),
    }
}

fn artifact_command(action: ArtifactAction) -> Result<(), String> {
    match action {
        ArtifactAction::Backends => artifact_backends(),
        ArtifactAction::Select {
            backend,
            atomicity_class,
            network,
        } => artifact_select(backend, atomicity_class, network),
        ArtifactAction::Build {
            manifest,
            developer_lock,
            network_policy,
            backend,
            version,
        } => emit_result(
            "ktape artifact build",
            None,
            artifact_build_inputs(
                &read_json(&manifest)?,
                developer_lock,
                network_policy,
                &backend,
                &version,
            )?,
        ),
        ArtifactAction::Inspect { bundle } => {
            let value = read_json(&bundle)?;
            validate_artifact_value(&value)?;
            emit_result(
                "ktape artifact inspect",
                None,
                json!({"schema":"KTAPEOUT-0.5.0-ARTIFACT-INSPECTION-V1","status":"PASS","identity_chain":{"source_hash":value.get("source_hash"),"semantic_ir_hash":value.get("semantic_ir_hash"),"developer_lock_hash":value.get("developer_lock_hash"),"artifact_hash":value.get("artifact").and_then(|v|v.get("hash"))},"backend":value.get("backend"),"profile_digests":value.get("profile_digests"),"resource_origin":value.get("resource_envelope").and_then(|v|v.get("origin")),"unsupported_claims":value.get("unsupported_claims")}),
            )
        }
        ArtifactAction::Verify {
            bundle,
            source,
            developer_lock,
            network_policy,
        } => {
            let value = read_json(&bundle)?;
            if let (Some(source), Some(developer_lock), Some(network_policy)) = (
                source.as_ref(),
                developer_lock.as_ref(),
                network_policy.as_ref(),
            ) {
                validate_artifact_v2_value(
                    &value,
                    &read_json(source)?,
                    &read_json(developer_lock)?,
                    &read_json(network_policy)?,
                )?;
                return emit_result(
                    "ktape artifact verify",
                    None,
                    json!({"schema":"KTAPEOUT-0.5.0-ARTIFACT-VERIFY-V2","status":"PASS","signing_allowed":false,"broadcast":false,"bundle_hash":value.get("bundle_hash"),"artifact_build_identity_hash":value.get("artifact_build_identity_hash")}),
                );
            }
            if source.is_some() || developer_lock.is_some() || network_policy.is_some() {
                return Err(
                    "--source, --developer-lock and --network-policy must be supplied together"
                        .into(),
                );
            }
            validate_artifact_value(&value)?;
            emit_result(
                "ktape artifact verify",
                None,
                json!({"schema":"KTAPEOUT-0.5.0-ARTIFACT-VERIFY-V1","status":"PASS","signing_allowed":false,"broadcast":false,"artifact":value}),
            )
        }
        ArtifactAction::Diff { left, right } => {
            let a = read_json(&left)?;
            let b = read_json(&right)?;
            validate_artifact_value(&a)?;
            validate_artifact_value(&b)?;
            let fields = [
                "source_hash",
                "semantic_ir_hash",
                "developer_lock_hash",
                "backend",
                "profile_digests",
                "artifact",
            ];
            let changed: Vec<&str> = fields
                .iter()
                .copied()
                .filter(|field| a.get(*field) != b.get(*field))
                .collect();
            emit_result(
                "ktape artifact diff",
                None,
                json!({"schema":"KTAPEOUT-0.5.0-ARTIFACT-DIFF-V1","equal":changed.is_empty(),"changed_fields":changed,"signing_allowed":false,"broadcast":false}),
            )
        }
        ArtifactAction::SimulateKtb1 {
            artifact,
            inputs,
            state,
            steps,
        } => {
            let bytes = read_bounded_file(&artifact, MAX_RECORD_BYTES, "ARTIFACT_READ_FAILED")?;
            let inputs = read_bit_vector(&inputs)?;
            let state = read_bit_vector(&state)?;
            let result = simulate_state_machine_artifact_050(&bytes, &inputs, &state, steps)
                .map_err(|error| error.0)?;
            let output_count = *result
                .first()
                .ok_or_else(|| "KTB1_RESULT_INVALID".to_string())?
                as usize;
            let register_count_index = output_count
                .checked_add(1)
                .ok_or_else(|| "KTB1_RESULT_INVALID".to_string())?;
            let register_count = *result
                .get(register_count_index)
                .ok_or_else(|| "KTB1_RESULT_INVALID".to_string())?
                as usize;
            if result.len() != register_count_index + register_count + 1 {
                return Err("KTB1_RESULT_INVALID".to_string());
            }
            emit_result(
                "ktape artifact simulate-ktb1",
                None,
                json!({
                    "schema": "KTAPEOUT-0.5.0-KTB1-EXECUTION-V1",
                    "status": "PASS",
                    "execution_origin": "LOCAL_SIMULATION",
                    "artifact_sha256": hex_string(&Sha256::digest(&bytes)),
                    "steps": steps,
                    "outputs": &result[1..register_count_index],
                    "state": &result[register_count_index + 1..],
                    "signing_allowed": false,
                    "broadcast": false,
                    "limitation": "executes only canonical bounded KTB1 v1 artifacts; this is not L1 execution, fee estimation, or arbitrary Profile execution"
                }),
            )
        }
        ArtifactAction::SimulateProject {
            bundle,
            inputs,
            state,
            steps,
            state_output,
        } => {
            let bundle_bytes =
                read_bounded_file(&bundle, 3 * 1024 * 1024, "RUNTIME_BUNDLE_READ_FAILED")?;
            let bundle_value: Value = parse_strict_json(&bundle_bytes)
                .map_err(|_| "RUNTIME_BUNDLE_JSON_INVALID".to_string())?;
            let verified = studio_runtime_bundle::verify_bundle(&bundle_value)?;
            let inputs = read_bit_vector(&inputs)?;
            let state = read_bit_vector(&state)?;
            let result = simulate_state_machine_artifact_050(
                &verified.artifact_bytes,
                &inputs,
                &state,
                steps,
            )
            .map_err(|error| error.0)?;
            let output_count = *result
                .first()
                .ok_or_else(|| "KTB1_RESULT_INVALID".to_string())?
                as usize;
            let register_count_index = output_count
                .checked_add(1)
                .ok_or_else(|| "KTB1_RESULT_INVALID".to_string())?;
            let register_count = *result
                .get(register_count_index)
                .ok_or_else(|| "KTB1_RESULT_INVALID".to_string())?
                as usize;
            if result.len() != register_count_index + register_count + 1 {
                return Err("KTB1_RESULT_INVALID".to_string());
            }
            if let Some(path) = state_output.as_ref() {
                let state_bytes = serde_json::to_vec_pretty(&result[register_count_index + 1..])
                    .map_err(|_| "LOCAL_STATE_SERIALIZATION_FAILED".to_string())?;
                atomic_write_file(path, &state_bytes, "LOCAL_STATE_WRITE")?;
            }
            emit_result(
                "ktape artifact simulate-project",
                None,
                json!({
                    "schema": "KTAPEOUT-0.5.0-STUDIO-PROJECT-EXECUTION-V1",
                    "status": "PASS",
                    "execution_origin": "LOCAL_SIMULATION",
                    "profile_id": verified.profile_id,
                    "project_id": verified.project_id,
                    "project_sha256": verified.project_hash,
                    "semantic_ir_hash": verified.semantic_ir_hash,
                    "compiler_lock_hash": verified.compiler_lock_hash,
                    "developer_lock_hash": verified.developer_lock_hash,
                    "artifact_sha256": verified.artifact_hash,
                    "application_binding": {
                        "status": "LOCAL_ONLY",
                        "binding_kind": "RUNTIME_PROJECT",
                        "project_sha256": verified.project_hash,
                        "artifact_sha256": verified.artifact_hash,
                        "runtime_bundle_hash": bundle_value["bundle_hash"],
                        "runner_id": "ktapeout.bounded-state-machine",
                        "l1_evidence": false,
                        "signing_allowed": false,
                        "broadcast": false
                    },
                    "compiler_parity": "EXACT_KTB1_BYTES",
                    "steps": steps,
                    "outputs": &result[1..register_count_index],
                    "state": &result[register_count_index + 1..],
                    "state_output": state_output.as_ref().map(|path| path.display().to_string()),
                    "state_persistence": if state_output.is_some() { "LOCAL_FILE_ATOMIC" } else { "NOT_REQUESTED" },
                    "signing_allowed": false,
                    "broadcast": false,
                    "limitation": "Profile-specific local Machine/BoundedStateMachine execution only; not L1 evidence, fee estimation, authorization, or general Profile compilation"
                }),
            )
        }
        ArtifactAction::Reproduce { manifest, bundle } => {
            let expected = read_json(&bundle)?;
            validate_artifact_value(&expected)?;
            let backend = expected
                .get("backend")
                .and_then(Value::as_object)
                .ok_or_else(|| "ARTIFACT_SHAPE_INVALID".to_string())?;
            let id = backend
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| "ARTIFACT_SHAPE_INVALID".to_string())?;
            let version = backend
                .get("version")
                .and_then(Value::as_str)
                .ok_or_else(|| "ARTIFACT_SHAPE_INVALID".to_string())?;
            let reproduced = artifact_build_value(&read_json(&manifest)?, id, version)?;
            let fields = [
                "source_hash",
                "semantic_ir_hash",
                "developer_lock_hash",
                "backend",
                "profile_digests",
                "artifact",
            ];
            let changed: Vec<&str> = fields
                .iter()
                .copied()
                .filter(|field| expected.get(*field) != reproduced.get(*field))
                .collect();
            if !changed.is_empty() {
                return Err(format!("REPRODUCE_MISMATCH: {}", changed.join(",")));
            }
            emit_result(
                "ktape artifact reproduce",
                None,
                json!({"schema":"KTAPEOUT-0.5.0-ARTIFACT-REPRODUCE-V1","status":"PASS","reproduced":true,"artifact_hash":reproduced.get("artifact").and_then(|v|v.get("hash")),"backend":backend,"signing_allowed":false,"broadcast":false}),
            )
        }
    }
}

fn read_bit_vector(path: &Path) -> Result<Vec<u8>, String> {
    let value: Value = parse_strict_json(&read_bounded_file(path, 1024, "VECTOR_READ_FAILED")?)
        .map_err(|_| "VECTOR_JSON_INVALID".to_string())?;
    decode_bit_vector(&value)
}

fn read_bounded_file(path: &Path, max_bytes: usize, error_code: &str) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path).map_err(|_| error_code.to_string())?;
    if !metadata.file_type().is_file() {
        return Err(error_code.to_string());
    }
    let file = fs::File::open(path).map_err(|_| error_code.to_string())?;
    let mut bytes = Vec::with_capacity(max_bytes.min(4096));
    file.take(max_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| error_code.to_string())?;
    if bytes.len() > max_bytes {
        return Err("INPUT_FILE_TOO_LARGE".to_string());
    }
    Ok(bytes)
}

fn decode_bit_vector(value: &Value) -> Result<Vec<u8>, String> {
    let values = value
        .as_array()
        .ok_or_else(|| "VECTOR_MUST_BE_ARRAY".to_string())?;
    if values.is_empty() || values.len() > 64 {
        return Err("VECTOR_LENGTH_OUT_OF_BOUNDS".to_string());
    }
    values
        .iter()
        .map(|value| match value.as_u64() {
            Some(bit @ 0..=1) => Ok(bit as u8),
            _ => Err("VECTOR_VALUE_NOT_BIT".to_string()),
        })
        .collect()
}

fn inspect(path: PathBuf) -> Result<(), String> {
    let value = read_json(&path)?;
    emit_result(
        "ktape app inspect",
        value.get("network").and_then(Value::as_str),
        json!({"schema": "KTAPEOUT-0.5.0-APPLICATION-INSPECTION-V1", "schema_version": value.get("schema_version"), "source_kind": value.get("source_kind"), "source_hash": value.get("source_hash"), "field_count": value.as_object().map_or(0, |object| object.len()), "content_hash": sha256_value(&value)?}),
    )
}

fn test_manifest(path: PathBuf, command: &str) -> Result<(), String> {
    let value = read_json(&path)?;
    let result = test_manifest_value(&value)?;
    emit_result_status(
        command,
        value.get("network").and_then(Value::as_str),
        "WARNING",
        result,
    )
}

fn test_manifest_value(value: &Value) -> Result<Value, String> {
    let object = validate_manifest_value(value)?;
    let vectors = object
        .get("test_vectors")
        .and_then(Value::as_array)
        .ok_or_else(|| "TEST_VECTORS_REQUIRED".to_string())?;
    if vectors.is_empty() {
        return Err("TEST_VECTORS_REQUIRED".to_string());
    }
    Ok(json!({
        "schema": "KTAPEOUT-0.5.0-APPLICATION-TEST-RESULT-V1",
        "status": "STRUCTURE_ONLY",
        "test_mode": "STRUCTURAL_VECTOR_PRESENCE",
        "lifecycle_status": "STRUCTURE_ONLY",
        "vectors": vectors.len(),
        "evidence_origin": "STATIC",
        "next_action": "for supported Machine or BoundedStateMachine Project behavior, bind runtime_project in ktape dev workflow; for a Manifest bound to a supported pure Profile interface, set workflow.profile_package_root or run ktape dev test with --profile-package-root; other Source Manifest vectors remain STRUCTURE_ONLY",
        "missing_evidence": ["verified Profile Runner binding", "Manifest-to-interface input/output mapping", "vector execution trace and expected-result comparison", "negative and invariant execution results"],
        "unsigned": true,
        "broadcast": false,
        "signing_allowed": false
    }))
}

fn simulate_manifest(path: PathBuf) -> Result<(), String> {
    let value = read_json(&path)?;
    let result = simulate_manifest_value(&value)?;
    emit_result_status(
        "ktape app simulate",
        value.get("network").and_then(Value::as_str),
        "WARNING",
        result,
    )
}

fn simulate_manifest_value(value: &Value) -> Result<Value, String> {
    let object = validate_manifest_value(value)?;
    let vectors = object
        .get("test_vectors")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    Ok(json!({
        "schema": "KTAPEOUT-0.5.0-APPLICATION-SIMULATION-V1",
        "status": "STRUCTURE_ONLY",
        "simulation": "MANIFEST_SHAPE_ONLY",
        "lifecycle_status": "STRUCTURE_ONLY",
        "vectors": vectors,
        "evidence_origin": "STATIC",
        "unsigned": true,
        "broadcast": false,
        "signing_allowed": false,
        "limitation": "generic source manifests do not execute a Profile runtime"
    }))
}

fn preflight_manifest(path: PathBuf, network: String) -> Result<(), String> {
    let value = read_json(&path)?;
    let result = preflight_manifest_value(&value, &network)?;
    let tool_status = if result["status"] == "READY" {
        "PASS"
    } else {
        "WARNING"
    };
    emit_result_status("ktape app preflight", Some(&network), tool_status, result)
}

fn preflight_manifest_value(value: &Value, network: &str) -> Result<Value, String> {
    if !matches!(network, "testnet-10" | "mainnet") {
        return Err("NETWORK_INVALID".to_string());
    }
    let object = validate_manifest_value(value)?;
    let source_hash = object
        .get("source_hash")
        .and_then(Value::as_str)
        .ok_or_else(|| "SOURCE_HASH_INVALID".to_string())?;
    let requirements = derive_requirements_value(value, network)?;
    let requirements_status = requirements["status"]
        .as_str()
        .ok_or_else(|| "APPLICATION_REQUIREMENTS_STATUS_INVALID".to_string())?;
    let semantic_ready = requirements_status == "READY_FOR_COMPOSITION";
    let testnet_supported = network == "testnet-10";
    Ok(json!({
        "schema": "KTAPEOUT-0.5.0-PREFLIGHT-V1",
        "network": network,
        "source_hash": source_hash,
        "evidence_origin": "STATIC",
        "status": if semantic_ready { "READY" } else { requirements_status },
        "requirements_status": requirements_status,
        "requirements_unknowns": requirements["unknowns"],
        "requirements_mvp_scope": requirements["mvp_scope"],
        "unsigned": true,
        "broadcast": false,
        "signing_allowed": false,
        "network_state_change_authorized": false,
        "network_state_change_network_supported": testnet_supported,
        "operator_preflight_required": testnet_supported,
        "mainnet_state_change": false,
        "next_action": if !semantic_ready { "run ktape ai requirements SOURCE.json, resolve its listed unknowns, then rerun ktape app preflight" } else if testnet_supported { "obtain separate user authorization and complete external Profile/Operator preflight; this command does not authorize or perform a state change" } else { "Mainnet state changes are not authorized by this toolchain" }
    }))
}

fn content_preflight(path: PathBuf, network: String) -> Result<(), String> {
    if !matches!(network.as_str(), "testnet-10" | "mainnet") {
        return Err("NETWORK_INVALID".to_string());
    }
    let raw = read_bounded_file(&path, MAX_JSON_INPUT_BYTES, "CONTENT_ARTIFACT_READ")?;
    let projection = verify_content_artifact_050(&raw)
        .map_err(|error| format!("CONTENT_ARTIFACT_INVALID:{error:?}"))?;
    let projection_value: Value = parse_strict_json(&projection)
        .map_err(|error| format!("CONTENT_PROJECTION_INVALID:{error}"))?;
    let artifact_value: Value =
        parse_strict_json(&raw).map_err(|error| format!("CONTENT_ARTIFACT_INVALID:{error}"))?;
    let discovery_media = inspect_discovery_media(&artifact_value)?;
    let object = projection_value
        .as_object()
        .ok_or_else(|| "CONTENT_PROJECTION_INVALID".to_string())?;
    let artifact_sha256 = object
        .get("artifact_sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| "CONTENT_ARTIFACT_HASH_MISSING".to_string())?;
    let file_count = object
        .get("file_count")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let total_bytes = object
        .get("total_bytes")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    emit_result(
        "ktape app content-preflight",
        Some(&network),
        json!({
            "schema": "KTAPEOUT-CONTENT-ADMISSION-PREFLIGHT-V1",
            "network": network,
            "status": "PROFILE_ONLY",
            "content_artifact_verified": true,
            "profile_id": "OnChainContentV1",
            "artifact_sha256": artifact_sha256,
            "discovery_media": discovery_media,
            "file_count": file_count,
            "total_bytes": total_bytes,
            "l1_admission": false,
            "admission_level": "PROFILE_ONLY",
            "signing_allowed": false,
            "broadcast": false,
            "evidence_origin": "LOCAL_ARTIFACT_VERIFICATION",
            "next_required": [
                "L1_CONTENT_PROFILE_ADMITTED",
                "NATIVE_VM_EXECUTION_EVIDENCE",
                "CONTENT_CODEC_AND_SUCCESSOR_RULE",
                "UNSIGNED_TN10_OPERATOR_PLAN",
                "DUAL_RPC_READBACK"
            ],
            "next_action": "keep this artifact local; OnChainContentV1 is an artifact format, not an admitted L1 publishing Profile, and this release has no generic content-publication path. For mutable L1-resident content, consult the separate L1ContentProfileV1 specification and proceed only after its independent admission, codec/transition evidence, and a computeBudget-preserving TN10 submit/readback path are available",
            "limitation": "artifact import is not L1 publication or consensus evidence"
        }),
    )
}

fn content_state_commitment(path: PathBuf) -> Result<(), String> {
    let raw = read_bounded_file(&path, MAX_JSON_INPUT_BYTES, "CONTENT_STATE_READ")?;
    let commitment = encode_l1_content_state_050(&raw)
        .map_err(|error| format!("CONTENT_STATE_INVALID:{error:?}"))?;
    emit_result(
        "ktape app content-state-commitment",
        None,
        json!({
            "schema": "KTAPEOUT-L1-CONTENT-STATE-COMMITMENT-V1",
            "profile_id": "L1ContentProfileV1",
            "state_commitment": hex_string(&commitment),
            "evidence_origin": "LOCAL_CANONICAL_CODEC",
            "signing_allowed": false,
            "broadcast": false
        }),
    )
}

fn normalize_name_value(uri: &str, default_network: Option<&str>) -> Result<Value, String> {
    let prefix = "ktape://";
    if uri.trim() != uri
        || !uri.starts_with(prefix)
        || uri.contains('\\')
        || uri.contains('%')
        || uri.contains('?')
        || uri.contains('#')
    {
        return Err("NAME_URI_NOT_CANONICAL".to_string());
    }
    let rest = &uri[prefix.len()..];
    let (network_part, path) = rest
        .split_once('/')
        .ok_or_else(|| "NAME_URI_NOT_CANONICAL".to_string())?;
    let network = if network_part == "app" {
        default_network
            .ok_or_else(|| "DEFAULT_NETWORK_REQUIRED".to_string())?
            .to_string()
    } else {
        network_part.to_string()
    };
    if network != "testnet-10" && network != "mainnet" {
        return Err("NETWORK_INVALID".to_string());
    }
    let segments: Vec<&str> = path.split('/').collect();
    let (namespace, slug_part) = if network_part == "app" {
        if segments.len() != 2 {
            return Err("NAME_URI_NOT_CANONICAL".to_string());
        }
        (segments[0], segments[1])
    } else {
        if segments.len() != 3 || segments[0] != "app" {
            return Err("NAME_URI_NOT_CANONICAL".to_string());
        }
        (segments[1], segments[2])
    };
    let (slug, release) = slug_part
        .split_once('@')
        .map_or((slug_part, None), |(slug, release)| (slug, Some(release)));
    let valid_segment = |value: &str| {
        let bytes = value.as_bytes();
        !bytes.is_empty()
            && bytes.len() <= 63
            && bytes[0].is_ascii_alphanumeric()
            && bytes
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
    };
    if !valid_segment(namespace) || !valid_segment(slug) {
        return Err("NAME_SEGMENT_INVALID".to_string());
    }
    if let Some(value) = release {
        if !valid_hash(value) {
            return Err("RELEASE_ID_INVALID".to_string());
        }
    }
    let normalized_namespace = namespace.to_ascii_lowercase();
    let normalized_slug = slug.to_ascii_lowercase();
    let suffix = release.map_or(String::new(), |value| format!("@{value}"));
    Ok(json!({
        "status": "NORMALIZED",
        "canonical_uri": format!("ktape://{network}/app/{normalized_namespace}/{normalized_slug}{suffix}"),
        "network": network,
        "namespace": normalized_namespace,
        "slug": normalized_slug,
        "release_id": release,
    }))
}

fn normalize_name(uri: String, default_network: Option<String>) -> Result<(), String> {
    let value = normalize_name_value(&uri, default_network.as_deref())?;
    let network = value
        .get("network")
        .and_then(Value::as_str)
        .map(str::to_owned);
    emit_result("ktape name normalize", network.as_deref(), value)
}

fn application_name_key_value(
    network: &str,
    namespace: &str,
    slug: &str,
) -> Result<String, String> {
    if !matches!(network, "testnet-10" | "mainnet") {
        return Err("NETWORK_INVALID".to_string());
    }
    let canonical = format!("ktape://{network}/app/{namespace}/{slug}");
    let normalized = normalize_name_value(&canonical, None)?;
    if normalized.get("canonical_uri").and_then(Value::as_str) != Some(canonical.as_str()) {
        return Err("NAME_URI_NOT_CANONICAL".to_string());
    }
    if normalized
        .get("release_id")
        .is_some_and(|value| !value.is_null())
    {
        return Err("NAME_RELEASE_NOT_ALLOWED".to_string());
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"KTAPEOUT/0.5.0/APPLICATION_NAME_DEED/V1");
    for value in [network, namespace, slug] {
        let raw = value.as_bytes();
        if raw.len() > u16::MAX as usize {
            return Err("NAME_COMPONENT_TOO_LARGE".to_string());
        }
        hasher.update(&(raw.len() as u16).to_be_bytes());
        hasher.update(raw);
    }
    Ok(hex_string(hasher.finalize().as_bytes()))
}

fn name_space_plan(
    mut keys: Vec<String>,
    reserved_from: Option<PathBuf>,
    network: String,
) -> Result<(), String> {
    if let Some(path) = reserved_from {
        keys.extend(reserved_genesis_keys(&path)?);
    }
    let gaps = name_space::expected_gaps(&keys)?;
    name_space::assert_tiling(&gaps, &keys)?;
    let planned: Vec<Value> = gaps
        .iter()
        .map(|gap| {
            let mut entry = gap.to_json();
            entry["state_args"] = name_space::gap_state_args(gap);
            entry
        })
        .collect();
    emit_result(
        "ktape name space-plan",
        Some(&network),
        json!({
            "schema": "KTAPEOUT-NAME-SPACE-PLAN-V1",
            "keys_count": keys.len(),
            "expected_live_gaps": planned,
            "completeness_rule": "every expected gap live on two independent sources and tiling exact => any key outside the list is unregistered",
            "network_reads": "external read adapter",
            "signing_allowed": false,
            "broadcast": false,
        }),
    )
}

fn reserved_genesis_keys(path: &Path) -> Result<Vec<String>, String> {
    let receipt = read_json(path)?;
    let genesis = receipt["tn10"]["gaps"]
        .as_array()
        .ok_or("RESERVED_RECEIPT_INVALID")?;
    Ok(genesis
        .iter()
        .filter(|gap| gap["hi_is_max"] == 0)
        .filter_map(|gap| gap["gap_hi"].as_str().map(str::to_owned))
        .collect())
}

fn name_space_check(
    mut keys: Vec<String>,
    reserved_from: Option<PathBuf>,
    live: PathBuf,
    probe: Option<String>,
    network: String,
) -> Result<(), String> {
    if let Some(path) = reserved_from {
        keys.extend(reserved_genesis_keys(&path)?);
    }
    let expected = name_space::expected_gaps(&keys)?;
    let live_gaps = read_json(&live)?
        .as_array()
        .ok_or("LIVE_GAPS_INVALID")?
        .iter()
        .map(name_space::Gap::from_json)
        .collect::<Result<Vec<_>, _>>()?;
    let missing: Vec<Value> = expected
        .iter()
        .filter(|gap| !live_gaps.contains(gap))
        .map(|gap| gap.to_json())
        .collect();
    let unexpected: Vec<Value> = live_gaps
        .iter()
        .filter(|gap| !expected.contains(gap))
        .map(|gap| gap.to_json())
        .collect();
    let complete = missing.is_empty() && unexpected.is_empty();
    // The tiling rule only licenses an absence claim when the observation is exactly the expected cover.
    let probe_absent = match (&probe, complete) {
        (Some(key), true) => Some(
            name_space::key_is_absent(key, &live_gaps)?
                && !keys.iter().any(|k| k.eq_ignore_ascii_case(key)),
        ),
        _ => None,
    };
    emit_result(
        "ktape name space-check",
        Some(&network),
        json!({
            "schema": "KTAPEOUT-NAME-SPACE-CHECK-V1",
            "status": if complete { "COMPLETE" } else { "INCOMPLETE" },
            "missing_gaps": missing,
            "unexpected_gaps": unexpected,
            "probe": probe,
            "probe_unregistered": probe_absent,
            "signing_allowed": false,
            "broadcast": false,
        }),
    )
}

// Retained as private, non-dispatched migration code while the accepted native
// namespace commands are rebuilt. These helpers cannot be called through Clap.
#[allow(dead_code)]
fn application_name_key(network: String, namespace: String, slug: String) -> Result<(), String> {
    let key = application_name_key_value(&network, &namespace, &slug)?;
    emit_result(
        "ktape name key",
        Some(&network),
        json!({
            "schema": "KTAPEOUT-NAME-KEY-V1",
            "profile_family_id": "ApplicationNameDeedV1",
            "profile_version": 1,
            "network": network,
            "namespace": namespace,
            "slug": slug,
            "name_key": key,
            "signing_allowed": false,
            "broadcast": false
        }),
    )
}

// CLI boundary: these fields map one-to-one to the published alias contract.
#[allow(clippy::too_many_arguments)]
fn ingress_alias_value(
    provider: String,
    external_name: String,
    network: String,
    canonical_uri: String,
    application_id: String,
    release_policy: String,
    binding_mode: String,
    provider_proof_ref: Option<String>,
    owner_signature: String,
) -> Result<Value, String> {
    if provider.is_empty()
        || provider.len() > 32
        || provider == "ktape"
        || !provider.bytes().enumerate().all(|(index, byte)| {
            (index == 0 && byte.is_ascii_lowercase())
                || (index > 0
                    && (byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || byte == b'.'
                        || byte == b'_'
                        || byte == b'-'))
        })
    {
        return Err("EXTERNAL_PROVIDER_INVALID".to_string());
    }
    if external_name.is_empty()
        || external_name.len() > 256
        || external_name
            .chars()
            .any(|character| character.is_control())
    {
        return Err("EXTERNAL_NAME_INVALID".to_string());
    }
    if !matches!(network.as_str(), "testnet-10" | "mainnet") {
        return Err("NETWORK_INVALID".to_string());
    }
    let normalized = normalize_name_value(&canonical_uri, None)?;
    if normalized.get("canonical_uri").and_then(Value::as_str) != Some(canonical_uri.as_str())
        || normalized.get("network").and_then(Value::as_str) != Some(network.as_str())
    {
        return Err("CANONICAL_TARGET_INVALID".to_string());
    }
    if !valid_hash(&application_id) {
        return Err("APPLICATION_ID_INVALID".to_string());
    }
    let release_id = normalized.get("release_id").and_then(Value::as_str);
    if !matches!(release_policy.as_str(), "current" | "pinned")
        || (release_policy == "pinned" && release_id.is_none())
    {
        return Err("RELEASE_POLICY_INVALID".to_string());
    }
    if !matches!(binding_mode.as_str(), "DISPLAY_ALIAS" | "OWNER_BOUND") {
        return Err("BINDING_MODE_INVALID".to_string());
    }
    if let Some(reference) = &provider_proof_ref {
        if reference.is_empty()
            || reference.len() > 256
            || reference.chars().any(|c| c.is_control())
        {
            return Err("PROVIDER_PROOF_REF_INVALID".to_string());
        }
    }
    if owner_signature.is_empty()
        || owner_signature.len() > 1024
        || owner_signature
            .chars()
            .any(|character| character.is_control())
    {
        return Err("OWNER_SIGNATURE_INVALID".to_string());
    }
    Ok(json!({
        "schema": "KTAPEOUT-INGRESS-ALIAS-V1",
        "provider": provider,
        "external_name": external_name,
        "network": network,
        "canonical_uri": canonical_uri,
        "application_id": application_id,
        "release_policy": release_policy,
        "binding_mode": binding_mode,
        "provider_proof_ref": provider_proof_ref,
        "owner_signature": owner_signature
    }))
}

// CLI boundary: these fields map one-to-one to the published alias contract.
#[allow(clippy::too_many_arguments)]
fn ingress_alias_create(
    provider: String,
    external_name: String,
    network: String,
    canonical_uri: String,
    application_id: String,
    release_policy: String,
    binding_mode: String,
    provider_proof_ref: Option<String>,
    owner_signature: String,
) -> Result<(), String> {
    let value = ingress_alias_value(
        provider,
        external_name,
        network.clone(),
        canonical_uri,
        application_id,
        release_policy,
        binding_mode,
        provider_proof_ref,
        owner_signature,
    )?;
    emit_result("ktape name alias-create", Some(&network), value)
}

fn ingress_alias_verify(path: PathBuf, expected_network: Option<String>) -> Result<(), String> {
    let value = read_json(&path)?;
    let object = value
        .as_object()
        .ok_or_else(|| "ALIAS_OBJECT_REQUIRED".to_string())?;
    let allowed = [
        "schema",
        "provider",
        "external_name",
        "network",
        "canonical_uri",
        "application_id",
        "release_policy",
        "binding_mode",
        "provider_proof_ref",
        "owner_signature",
    ];
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err("ALIAS_UNKNOWN_FIELDS".to_string());
    }
    if value.get("schema").and_then(Value::as_str) != Some("KTAPEOUT-INGRESS-ALIAS-V1") {
        return Err("ALIAS_SCHEMA_INVALID".to_string());
    }
    let get = |field: &str| {
        value
            .get(field)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| format!("ALIAS_FIELD_INVALID:{field}"))
    };
    let provider = get("provider")?;
    let external_name = get("external_name")?;
    let network = get("network")?;
    let canonical_uri = get("canonical_uri")?;
    let application_id = get("application_id")?;
    let release_policy = get("release_policy")?;
    let binding_mode = get("binding_mode")?;
    let owner_signature = get("owner_signature")?;
    let provider_proof_ref = value
        .get("provider_proof_ref")
        .and_then(Value::as_str)
        .map(str::to_owned);
    if expected_network
        .as_deref()
        .is_some_and(|expected| expected != network)
    {
        return Err("NETWORK_MISMATCH".to_string());
    }
    let created = ingress_alias_value(
        provider,
        external_name,
        network.clone(),
        canonical_uri,
        application_id,
        release_policy,
        binding_mode,
        provider_proof_ref.clone(),
        owner_signature,
    )?;
    emit_result(
        "ktape name alias-verify",
        Some(&network),
        json!({
            "schema": "KTAPEOUT-INGRESS-ALIAS-RESULT-V1",
            "network": network,
            "provider": created["provider"],
            "external_name": created["external_name"],
            "canonical_uri": created["canonical_uri"],
            "application_id": created["application_id"],
            "release_policy": created["release_policy"],
            "binding_mode": created["binding_mode"],
            "provider_proof_ref": created["provider_proof_ref"],
            "provider_status": "EXTERNAL_INDEXED",
            "verification_level": "EXTERNAL_INDEXED",
            "signing_allowed": false,
            "broadcast": false
        }),
    )
}

#[allow(dead_code)]
fn name_quote(
    network: String,
    bond_sompi: Option<u64>,
    estimated_mass: u64,
    fee_rate_sompi_per_gram: u64,
) -> Result<(), String> {
    if !matches!(network.as_str(), "testnet-10" | "mainnet") {
        return Err("NETWORK_INVALID".into());
    }
    if !(1..=100_000).contains(&estimated_mass) {
        return Err("ESTIMATED_MASS_INVALID".into());
    }
    if fee_rate_sompi_per_gram == 0 {
        return Err("FEE_RATE_INVALID".into());
    }
    let bond = bond_sompi.unwrap_or(1_000_000_000);
    let network_fee = estimated_mass
        .checked_mul(fee_rate_sompi_per_gram)
        .ok_or_else(|| "QUOTE_OVERFLOW".to_string())?;
    let total = bond
        .checked_add(network_fee)
        .ok_or_else(|| "QUOTE_OVERFLOW".to_string())?;
    emit_result(
        "ktape name quote",
        Some(&network),
        json!({
            "schema": "KTAPEOUT-NAME-REGISTRATION-QUOTE-V1",
            "network": network,
            "bond_sompi": bond,
            "network_fee_sompi": network_fee,
            "total_sompi": total,
            "bond_refundable": bond > 0,
            "fee_is_estimate": true,
            "quote_inputs": {"estimated_mass": estimated_mass, "fee_rate_sompi_per_gram": fee_rate_sompi_per_gram}
        }),
    )
}

fn name_lifecycle_plan(
    network: String,
    operation: String,
    genesis_outpoint: String,
    predecessor_outpoint: String,
    policy_hash: String,
    operation_nonce: u64,
    effective_point: String,
) -> Result<(), String> {
    if !matches!(network.as_str(), "testnet-10" | "mainnet") {
        return Err("NETWORK_INVALID".into());
    }
    if !matches!(
        operation.as_str(),
        "UPGRADE" | "PAUSE" | "ROTATE" | "MIGRATE" | "DRAIN" | "RETIRE" | "RECOVER"
    ) {
        return Err("LIFECYCLE_OPERATION_INVALID".into());
    }
    if !valid_outpoint(&genesis_outpoint) || !valid_outpoint(&predecessor_outpoint) {
        return Err("OUTPOINT_INVALID".into());
    }
    if !valid_hash(&policy_hash) {
        return Err("POLICY_HASH_INVALID".into());
    }
    if effective_point.is_empty()
        || effective_point.len() > 128
        || effective_point
            .chars()
            .any(|c| c == '\0' || c == '\n' || c == '\r')
    {
        return Err("EFFECTIVE_POINT_INVALID".into());
    }
    let mut plan = json!({
        "schema": "KTAPEOUT-LIFECYCLE-OPERATION-PLAN-V1",
        "protocol_semver": PROTOCOL,
        "operation": operation,
        "network": network,
        "registry_genesis_outpoint": genesis_outpoint,
        "predecessor_outpoint": predecessor_outpoint,
        "policy_hash": policy_hash,
        "operation_nonce": operation_nonce,
        "effective_point": effective_point,
        "signing_allowed": false,
        "broadcast": false
    });
    let plan_hash = sha256_value(&plan)?;
    plan.as_object_mut()
        .ok_or_else(|| "LIFECYCLE_PLAN_OBJECT_INVALID".to_string())?
        .insert("plan_hash".into(), Value::String(plan_hash));
    let plan_network = plan
        .get("network")
        .and_then(Value::as_str)
        .map(str::to_owned);
    emit_result("ktape name lifecycle-plan", plan_network.as_deref(), plan)
}

fn name_verify_readback(
    path: PathBuf,
    expected_network: Option<String>,
    expected_plan_hash: Option<String>,
) -> Result<(), String> {
    let receipt = read_json(&path)?;
    if !receipt.is_object() {
        return Err("READBACK_OBJECT_REQUIRED".into());
    }
    if let Some(expected) = expected_network.as_deref() {
        if receipt.get("network").and_then(Value::as_str) != Some(expected) {
            return Err("READBACK_NETWORK_MISMATCH".into());
        }
    }
    if let Some(expected) = expected_plan_hash.as_deref() {
        if receipt.get("plan_hash").and_then(Value::as_str) != Some(expected) {
            return Err("READBACK_PLAN_HASH_MISMATCH".into());
        }
    }
    for field in ["network", "source_tip", "state_root", "evidence_hash"] {
        if receipt
            .get(field)
            .and_then(Value::as_str)
            .is_none_or(|value| !valid_hash(value))
        {
            return Err(format!("READBACK_{field}_INVALID"));
        }
    }
    emit_result(
        "ktape name verify-readback",
        None,
        json!({
            "schema": "KTAPEOUT-REGISTRY-READBACK-INSPECTION-V1",
            "structurally_valid": true,
            "verification_level": "UNAVAILABLE",
            "l1_attested": false,
            "signing_allowed": false,
            "broadcast": false,
            "receipt": receipt
        }),
    )
}

#[allow(dead_code)]
fn parse_gap_value(
    lo_text: &str,
    hi_text: &str,
    hi_is_max: bool,
) -> Result<(num_bigint::BigUint, num_bigint::BigUint, bool), String> {
    let parse_fixed = |value: &str| {
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err("GAP_ENCODING_INVALID".to_string());
        }
        num_bigint::BigUint::parse_bytes(value.as_bytes(), 16)
            .ok_or_else(|| "GAP_ENCODING_INVALID".to_string())
    };
    let lo = parse_fixed(lo_text)?;
    let encoded_hi = parse_fixed(hi_text)?;
    let limit = num_bigint::BigUint::from(1u8) << 256usize;
    let hi = if hi_is_max {
        if encoded_hi != num_bigint::BigUint::from(0u8) {
            return Err("GAP_MAX_UPPER_BOUND_MUST_BE_ZERO".into());
        }
        limit.clone()
    } else {
        encoded_hi
    };
    if lo >= hi || hi > limit {
        return Err("GAP_RANGE_INVALID".into());
    }
    Ok((lo, hi, hi_is_max))
}

#[allow(dead_code)]
fn parse_gap_range(value: &str) -> Result<(num_bigint::BigUint, num_bigint::BigUint), String> {
    let mut fields = value.split(':');
    let lo = fields
        .next()
        .ok_or_else(|| "GAP_ENCODING_INVALID".to_string())?;
    let hi = fields
        .next()
        .ok_or_else(|| "GAP_ENCODING_INVALID".to_string())?;
    let marker = fields.next();
    if fields.next().is_some() || marker.is_some_and(|value| value != "max") {
        return Err("GAP_ENCODING_INVALID".into());
    }
    let (lo, hi, _) = parse_gap_value(lo, hi, marker.is_some())?;
    Ok((lo, hi))
}

#[allow(dead_code)]
fn gap_json(lo: &num_bigint::BigUint, hi: &num_bigint::BigUint) -> Value {
    let fixed = |value: &num_bigint::BigUint, width: usize| {
        let encoded = format!("{value:x}");
        let raw = encoded.trim_start_matches('0');
        let raw = if raw.is_empty() { "0" } else { raw };
        if raw.len() >= width {
            raw.to_owned()
        } else {
            format!("{}{}", "0".repeat(width - raw.len()), raw)
        }
    };
    let limit = num_bigint::BigUint::from(1u8) << 256usize;
    let hi_is_max = *hi == limit;
    json!({"lo": fixed(lo, 64), "hi": if hi_is_max { "0".repeat(64) } else { fixed(hi, 64) }, "hi_is_max": if hi_is_max { 1 } else { 0 }})
}

#[allow(dead_code)]
fn deed_state(path: PathBuf) -> Result<(Value, String, String), String> {
    let raw = read_json(&path)?;
    let object = raw
        .as_object()
        .ok_or_else(|| "DEED_STATE_OBJECT_REQUIRED".to_string())?;
    let required: std::collections::BTreeSet<&str> = [
        "profile_family_id",
        "profile_version",
        "network",
        "provider_id",
        "canonical_uri",
        "name_key",
        "controller_policy_hash",
        "application_id",
        "release_id",
        "deployment_id",
        "artifact_root",
        "network_policy_hash",
        "resolver_policy_hash",
        "bond_sompi",
        "nonce",
        "status",
    ]
    .into_iter()
    .collect();
    if object
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>()
        != required
    {
        return Err("DEED_STATE_FIELDS_INVALID".into());
    }
    let uri = raw
        .get("canonical_uri")
        .and_then(Value::as_str)
        .ok_or_else(|| "DEED_URI_INVALID".to_string())?;
    let normalized = normalize_name_value(uri, None)?;
    if normalized.get("canonical_uri").and_then(Value::as_str) != Some(uri)
        || normalized.get("release_id").is_some_and(|v| !v.is_null())
        || raw.get("network") != normalized.get("network")
        || raw.get("provider_id").and_then(Value::as_str) != Some("ktape")
        || raw.get("profile_family_id").and_then(Value::as_str) != Some("ApplicationNameDeedV1")
        || raw.get("profile_version").and_then(Value::as_u64) != Some(1)
        || raw.get("status").and_then(Value::as_str) != Some("ACTIVE")
    {
        return Err("DEED_SCHEMA_INVALID".into());
    }
    let network = normalized
        .get("network")
        .and_then(Value::as_str)
        .ok_or_else(|| "DEED_NETWORK_INVALID".to_string())?
        .to_owned();
    let namespace = normalized
        .get("namespace")
        .and_then(Value::as_str)
        .ok_or_else(|| "DEED_NAMESPACE_INVALID".to_string())?
        .to_owned();
    let slug = normalized
        .get("slug")
        .and_then(Value::as_str)
        .ok_or_else(|| "DEED_SLUG_INVALID".to_string())?
        .to_owned();
    let key = application_name_key_value(&network, &namespace, &slug)?;
    if raw.get("name_key").and_then(Value::as_str) != Some(key.as_str()) {
        return Err("DEED_NAME_KEY_MISMATCH".into());
    }
    for field in [
        "controller_policy_hash",
        "application_id",
        "release_id",
        "artifact_root",
        "network_policy_hash",
        "resolver_policy_hash",
    ] {
        if !raw
            .get(field)
            .and_then(Value::as_str)
            .is_some_and(valid_hash)
        {
            return Err(format!("DEED_{field}_INVALID"));
        }
    }
    if raw
        .get("deployment_id")
        .and_then(Value::as_str)
        .is_none_or(|v| v.is_empty() || v.len() > 256)
    {
        return Err("DEED_DEPLOYMENT_ID_INVALID".into());
    }
    if raw
        .get("bond_sompi")
        .and_then(Value::as_u64)
        .is_none_or(|v| v < 1_000_000_000)
    {
        return Err("DEED_BOND_INVALID".into());
    }
    if raw.get("nonce").and_then(Value::as_u64).is_none() {
        return Err("DEED_NONCE_INVALID".into());
    }
    let uri_owned = uri.to_owned();
    Ok((raw, key, uri_owned))
}

#[allow(dead_code)]
fn deed_register_plan(
    gap_lo: String,
    gap_hi: String,
    gap_hi_is_max: bool,
    deed_path: PathBuf,
) -> Result<(), String> {
    let (gap_lo, gap_hi, _gap_hi_is_max) = parse_gap_value(&gap_lo, &gap_hi, gap_hi_is_max)?;
    let (deed, key, uri) = deed_state(deed_path)?;
    let key_int = num_bigint::BigUint::parse_bytes(key.as_bytes(), 16)
        .ok_or_else(|| "DEED_NAME_KEY_INVALID".to_string())?;
    if key_int < gap_lo || key_int >= gap_hi {
        return Err("NAME_KEY_OUTSIDE_GAP".into());
    }
    let mut outputs = Vec::new();
    if gap_lo < key_int {
        outputs.push(json!({"role":"predecessor_gap","gap":gap_json(&gap_lo, &key_int)}));
    }
    outputs.push(json!({"role":"deed","state":deed}));
    let one = num_bigint::BigUint::from(1u8);
    let successor = &key_int + &one;
    if successor < gap_hi {
        outputs.push(json!({"role":"successor_gap","gap":gap_json(&successor, &gap_hi)}));
    }
    let network = normalize_name_value(&uri, None)?
        .get("network")
        .cloned()
        .unwrap_or(Value::Null);
    emit_result(
        "ktape name deed-register-plan",
        network.as_str(),
        json!({
            "schema":"KTAPEOUT-NAME-DEED-REGISTRATION-PLAN-V1","profile_family_id":"ApplicationNameDeedV1","profile_version":1,
            "network":network,"input":{"role":"containing_gap","gap":gap_json(&gap_lo,&gap_hi)},"outputs":outputs,
            "name_key":key,"canonical_uri":uri,"signing_allowed":false,"broadcast":false
        }),
    )
}

#[allow(dead_code)]
fn increment_nonce(value: &Value, error_code: &str) -> Result<u64, String> {
    value
        .as_u64()
        .ok_or_else(|| error_code.to_string())?
        .checked_add(1)
        .ok_or_else(|| format!("{error_code}_OVERFLOW"))
}

#[allow(dead_code)]
fn deed_transfer_plan(
    deed_path: PathBuf,
    next_controller_policy_hash: String,
) -> Result<(), String> {
    if !valid_hash(&next_controller_policy_hash) {
        return Err("NEXT_CONTROLLER_POLICY_HASH_INVALID".into());
    }
    let (deed, key, uri) = deed_state(deed_path)?;
    let network = deed
        .get("network")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let mut output = deed.clone();
    output["controller_policy_hash"] = Value::String(next_controller_policy_hash);
    output["nonce"] = json!(increment_nonce(&deed["nonce"], "DEED_NONCE_INVALID")?);
    emit_result(
        "ktape name deed-transfer-plan",
        Some(&network),
        json!({
            "schema":"KTAPEOUT-NAME-DEED-TRANSFER-PLAN-V1","profile_family_id":"ApplicationNameDeedV1","profile_version":1,"network":network,"canonical_uri":uri,"name_key":key,
            "input":deed,"output":output,"signing_allowed":false,"broadcast":false
        }),
    )
}

// CLI boundary: these fields map one-to-one to the published rebind contract.
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
fn deed_rebind_plan(
    deed_path: PathBuf,
    application_id: String,
    release_id: String,
    deployment_id: String,
    artifact_root: String,
    network_policy_hash: String,
    resolver_policy_hash: String,
    next_controller_policy_hash: Option<String>,
) -> Result<(), String> {
    for value in [
        &application_id,
        &release_id,
        &artifact_root,
        &network_policy_hash,
        &resolver_policy_hash,
    ] {
        if !valid_hash(value) {
            return Err("REBIND_HASH_INVALID".into());
        }
    }
    if deployment_id.is_empty() || deployment_id.len() > 256 {
        return Err("REBIND_DEPLOYMENT_ID_INVALID".into());
    }
    if let Some(value) = &next_controller_policy_hash {
        if !valid_hash(value) {
            return Err("NEXT_CONTROLLER_POLICY_HASH_INVALID".into());
        }
    }
    let (deed, key, uri) = deed_state(deed_path)?;
    let network = deed
        .get("network")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let mut output = deed.clone();
    output["application_id"] = Value::String(application_id);
    output["release_id"] = Value::String(release_id);
    output["deployment_id"] = Value::String(deployment_id);
    output["artifact_root"] = Value::String(artifact_root);
    output["network_policy_hash"] = Value::String(network_policy_hash);
    output["resolver_policy_hash"] = Value::String(resolver_policy_hash);
    if let Some(value) = next_controller_policy_hash {
        output["controller_policy_hash"] = Value::String(value);
    }
    output["nonce"] = json!(increment_nonce(&deed["nonce"], "DEED_NONCE_INVALID")?);
    emit_result(
        "ktape name deed-rebind-plan",
        Some(&network),
        json!({
            "schema":"KTAPEOUT-NAME-DEED-REBIND-PLAN-V1","profile_family_id":"ApplicationNameDeedV1","profile_version":1,"network":network,"canonical_uri":uri,"name_key":key,
            "input":deed,"output":output,"signing_allowed":false,"broadcast":false
        }),
    )
}

#[allow(dead_code)]
fn deed_release_plan(
    deed_path: PathBuf,
    left_gap: Option<String>,
    right_gap: Option<String>,
    refund_script_hash: String,
) -> Result<(), String> {
    if left_gap.is_none() && right_gap.is_none() {
        return Err("RELEASE_ADJACENT_GAP_REQUIRED".into());
    }
    if !valid_hash(&refund_script_hash) {
        return Err("REFUND_SCRIPT_HASH_INVALID".into());
    }
    let (deed, key, uri) = deed_state(deed_path)?;
    let key_int = num_bigint::BigUint::parse_bytes(key.as_bytes(), 16)
        .ok_or_else(|| "DEED_NAME_KEY_INVALID".to_string())?;
    let left = left_gap.map(|value| parse_gap_range(&value)).transpose()?;
    let right = right_gap.map(|value| parse_gap_range(&value)).transpose()?;
    if left.as_ref().is_some_and(|(_, hi)| hi != &key_int) {
        return Err("LEFT_GAP_NOT_ADJACENT".into());
    }
    let one = num_bigint::BigUint::from(1u8);
    let successor = &key_int + &one;
    if right.as_ref().is_some_and(|(lo, _)| lo != &successor) {
        return Err("RIGHT_GAP_NOT_ADJACENT".into());
    }
    let merged_lo = left
        .as_ref()
        .map(|(lo, _)| lo.clone())
        .unwrap_or_else(|| key_int.clone());
    let merged_hi = right
        .as_ref()
        .map(|(_, hi)| hi.clone())
        .unwrap_or_else(|| successor.clone());
    let mut inputs = Vec::new();
    if let Some((lo, hi)) = left {
        inputs.push(json!({"role":"left_gap","gap":gap_json(&lo,&hi)}));
    }
    inputs.push(json!({"role":"deed","state":deed.clone()}));
    if let Some((lo, hi)) = right {
        inputs.push(json!({"role":"right_gap","gap":gap_json(&lo,&hi)}));
    }
    let network = deed
        .get("network")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    emit_result(
        "ktape name deed-release-plan",
        Some(&network),
        json!({
            "schema":"KTAPEOUT-NAME-DEED-RELEASE-PLAN-V1","profile_family_id":"ApplicationNameDeedV1","profile_version":1,"network":network,"canonical_uri":uri,"name_key":key,
            "inputs":inputs,"output":{"role":"merged_gap","gap":gap_json(&merged_lo,&merged_hi)},"refund":{"script_hash":refund_script_hash,"minimum_sompi":deed["bond_sompi"]},"signing_allowed":false,"broadcast":false
        }),
    )
}

/// Compact NameDeed families. V1 is frozen and orders keys as signed bytes; V2 orders
/// complete 256-bit keys as unsigned big-endian integers in half-open Gaps.
#[allow(dead_code)]
const COMPACT_FAMILY_V1: &str = "ApplicationNameDeedCompactV1";
#[allow(dead_code)]
const COMPACT_FAMILY_V2: &str = "ApplicationNameDeedCompactV2";

#[allow(dead_code)]
fn compact_family_version(family: &str) -> Result<u64, String> {
    match family {
        COMPACT_FAMILY_V1 => Ok(1),
        COMPACT_FAMILY_V2 => Ok(2),
        _ => Err("COMPACT_PROFILE_FAMILY_INVALID".into()),
    }
}

#[allow(dead_code)]
fn compact_uri_parts(uri: &str) -> Result<(String, String, String), String> {
    let normalized = normalize_name_value(uri, None)?;
    if normalized
        .get("release_id")
        .is_some_and(|value| !value.is_null())
        || normalized.get("canonical_uri").and_then(Value::as_str) != Some(uri)
    {
        return Err("COMPACT_CANONICAL_URI_INVALID".into());
    }
    let network = normalized
        .get("network")
        .and_then(Value::as_str)
        .ok_or_else(|| "NETWORK_INVALID".to_string())?
        .to_owned();
    let namespace = normalized
        .get("namespace")
        .and_then(Value::as_str)
        .ok_or_else(|| "NAMESPACE_INVALID".to_string())?
        .to_owned();
    let slug = normalized
        .get("slug")
        .and_then(Value::as_str)
        .ok_or_else(|| "SLUG_INVALID".to_string())?
        .to_owned();
    Ok((network, namespace, slug))
}

#[allow(dead_code)]
fn compact_state(path: PathBuf, canonical_uri: &str) -> Result<(Value, String, String), String> {
    let raw = read_json(&path)?;
    let object = raw
        .as_object()
        .ok_or_else(|| "COMPACT_DEED_STATE_OBJECT_REQUIRED".to_string())?;
    let required: std::collections::BTreeSet<&str> = [
        "profile_family_id",
        "profile_version",
        "network",
        "provider_id",
        "name_key",
        "controller_commitment",
        "target_commitment",
        "target_authority_commitment",
        "resolver_policy_hash",
        "bond_sompi",
        "nonce",
    ]
    .into_iter()
    .collect();
    if object
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>()
        != required
    {
        return Err("COMPACT_DEED_STATE_FIELDS_INVALID".into());
    }
    let (network, namespace, slug) = compact_uri_parts(canonical_uri)?;
    let key = application_name_key_value(&network, &namespace, &slug)?;
    let family = raw
        .get("profile_family_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if compact_family_version(family).ok() != raw.get("profile_version").and_then(Value::as_u64)
        || raw.get("network").and_then(Value::as_str) != Some(network.as_str())
        || raw.get("provider_id").and_then(Value::as_str) != Some("ktape")
        || raw.get("name_key").and_then(Value::as_str) != Some(key.as_str())
    {
        return Err("COMPACT_DEED_IDENTITY_INVALID".into());
    }
    for field in [
        "controller_commitment",
        "target_commitment",
        "target_authority_commitment",
        "resolver_policy_hash",
    ] {
        if !raw
            .get(field)
            .and_then(Value::as_str)
            .is_some_and(valid_hash)
        {
            return Err(format!("COMPACT_DEED_{field}_INVALID"));
        }
    }
    if raw
        .get("bond_sompi")
        .and_then(Value::as_u64)
        .is_none_or(|value| value < 1_000_000_000)
    {
        return Err("COMPACT_DEED_BOND_INVALID".into());
    }
    if raw.get("nonce").and_then(Value::as_u64).is_none() {
        return Err("COMPACT_DEED_NONCE_INVALID".into());
    }
    Ok((raw, key, canonical_uri.to_owned()))
}

// These are the distinct fields committed into the compact name state.
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
fn compact_state_value(
    family: &str,
    canonical_uri: &str,
    controller_commitment: &str,
    target_commitment: &str,
    target_authority_commitment: &str,
    resolver_policy_hash: &str,
    bond_sompi: u64,
    nonce: u64,
) -> Result<(Value, String, String), String> {
    for (field, value) in [
        ("controller_commitment", controller_commitment),
        ("target_commitment", target_commitment),
        ("target_authority_commitment", target_authority_commitment),
        ("resolver_policy_hash", resolver_policy_hash),
    ] {
        if !valid_hash(value) {
            return Err(format!("COMPACT_DEED_{field}_INVALID"));
        }
    }
    if bond_sompi < 1_000_000_000 {
        return Err("COMPACT_DEED_BOND_INVALID".into());
    }
    let (network, namespace, slug) = compact_uri_parts(canonical_uri)?;
    let key = application_name_key_value(&network, &namespace, &slug)?;
    let state = json!({
        "profile_family_id":family, "profile_version":compact_family_version(family)?,
        "network":network, "provider_id":"ktape", "name_key":key,
        "controller_commitment":controller_commitment, "target_commitment":target_commitment,
        "target_authority_commitment":target_authority_commitment,
        "resolver_policy_hash":resolver_policy_hash, "bond_sompi":bond_sompi, "nonce":nonce
    });
    Ok((state, key, canonical_uri.to_owned()))
}

// CLI boundary: these fields map one-to-one to the published registration contract.
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
fn compact_registration_plan(
    gap_lo: String,
    gap_hi: String,
    gap_hi_is_max: bool,
    canonical_uri: String,
    controller_commitment: String,
    target_commitment: String,
    target_authority_commitment: String,
    resolver_policy_hash: String,
    bond_sompi: u64,
    nonce: u64,
    family: String,
    admission_receipt: Option<PathBuf>,
) -> Result<(), String> {
    let (gap_lo, gap_hi, _gap_hi_is_max) = parse_gap_value(&gap_lo, &gap_hi, gap_hi_is_max)?;
    let (state, key, uri) = compact_state_value(
        &family,
        &canonical_uri,
        &controller_commitment,
        &target_commitment,
        &target_authority_commitment,
        &resolver_policy_hash,
        bond_sompi,
        nonce,
    )?;
    let key_int = num_bigint::BigUint::parse_bytes(key.as_bytes(), 16)
        .ok_or_else(|| "COMPACT_NAME_KEY_INVALID".to_string())?;
    if key_int < gap_lo || key_int >= gap_hi {
        return Err("NAME_KEY_OUTSIDE_GAP".into());
    }
    // CompactV1 registers only keys strictly above the Gap's lower bound.
    if family == COMPACT_FAMILY_V1 && key_int == gap_lo {
        return Err("COMPACT_V1_REQUIRES_KEY_ABOVE_GAP_LOWER_BOUND".into());
    }
    let admission_status = compact_plan_admission_status(&family, admission_receipt)?;
    let mut outputs = Vec::new();
    if gap_lo < key_int {
        outputs.push(json!({"role":"predecessor_gap","gap":gap_json(&gap_lo, &key_int)}));
    }
    outputs.push(json!({"role":"deed","state":state}));
    let successor = &key_int + num_bigint::BigUint::from(1u8);
    if successor < gap_hi {
        outputs.push(json!({"role":"successor_gap","gap":gap_json(&successor, &gap_hi)}));
    }
    let network = compact_uri_parts(&uri)?.0;
    emit_result(
        "ktape name compact-name-deed-register-plan",
        Some(&network),
        json!({
            "schema":"KTAPEOUT-COMPACT-NAME-DEED-REGISTRATION-PLAN-V1", "profile_family_id":family, "profile_version":compact_family_version(&family)?,
            "network":network, "input":{"role":"containing_gap","gap":gap_json(&gap_lo,&gap_hi)}, "outputs":outputs,
            "name_key":key, "canonical_uri":uri, "admission_status":admission_status, "signing_allowed":false, "broadcast":false
        }),
    )
}

#[allow(dead_code)]
fn compact_transfer_plan(
    deed_path: PathBuf,
    canonical_uri: String,
    next_controller_commitment: String,
) -> Result<(), String> {
    if !valid_hash(&next_controller_commitment) {
        return Err("NEXT_CONTROLLER_COMMITMENT_INVALID".into());
    }
    let (deed, key, uri) = compact_state(deed_path, &canonical_uri)?;
    let network = deed
        .get("network")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let mut output = deed.clone();
    output["controller_commitment"] = Value::String(next_controller_commitment);
    output["nonce"] = json!(increment_nonce(&deed["nonce"], "COMPACT_NONCE_INVALID")?);
    emit_result(
        "ktape name compact-name-deed-transfer-plan",
        Some(&network),
        json!({
            "schema":"KTAPEOUT-COMPACT-NAME-DEED-TRANSFER-PLAN-V1", "profile_family_id":deed["profile_family_id"], "profile_version":deed["profile_version"],
            "network":network, "canonical_uri":uri, "name_key":key, "inputs":[{"role":"deed","state":deed}], "output":{"role":"deed","state":output},
            "admission_status":"PROFILE_VARIANT_UNADMITTED", "signing_allowed":false, "broadcast":false
        }),
    )
}

fn compact_target_commitment(
    application_id: &str,
    release_id: &str,
    deployment_id: &str,
    artifact_root: &str,
) -> Result<String, String> {
    for (field, value) in [
        ("application_id", application_id),
        ("release_id", release_id),
        ("artifact_root", artifact_root),
    ] {
        if !valid_hash(value) {
            return Err(format!("{field}_INVALID"));
        }
    }
    if deployment_id.is_empty()
        || deployment_id.len() > 256
        || deployment_id
            .chars()
            .any(|character| character.is_control())
    {
        return Err("DEPLOYMENT_ID_INVALID".into());
    }
    let bytes = canonical_json(
        &json!({"application_id":application_id,"release_id":release_id,"deployment_id":deployment_id,"artifact_root":artifact_root}),
    )?;
    let mut hasher = Sha256::new();
    hasher.update(b"KTAPEOUT/0.5.0/COMPACT_NAME_TARGET/V1");
    hasher.update(bytes);
    Ok(hex_string(&hasher.finalize()))
}

// CLI boundary: these fields map one-to-one to the published rebind contract.
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
fn compact_rebind_plan(
    deed_path: PathBuf,
    canonical_uri: String,
    application_id: String,
    release_id: String,
    deployment_id: String,
    artifact_root: String,
    target_authority_commitment: String,
    resolver_policy_hash: String,
    next_controller_commitment: Option<String>,
) -> Result<(), String> {
    let target =
        compact_target_commitment(&application_id, &release_id, &deployment_id, &artifact_root)?;
    if !valid_hash(&target_authority_commitment) || !valid_hash(&resolver_policy_hash) {
        return Err("COMPACT_REBIND_HASH_INVALID".into());
    }
    if let Some(value) = &next_controller_commitment {
        if !valid_hash(value) {
            return Err("NEXT_CONTROLLER_COMMITMENT_INVALID".into());
        }
    }
    let (deed, key, uri) = compact_state(deed_path, &canonical_uri)?;
    let network = deed
        .get("network")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let mut output = deed.clone();
    output["target_commitment"] = Value::String(target);
    output["target_authority_commitment"] = Value::String(target_authority_commitment);
    output["resolver_policy_hash"] = Value::String(resolver_policy_hash);
    if let Some(value) = next_controller_commitment {
        output["controller_commitment"] = Value::String(value);
    }
    output["nonce"] = json!(increment_nonce(&deed["nonce"], "COMPACT_NONCE_INVALID")?);
    emit_result(
        "ktape name compact-name-deed-rebind-plan",
        Some(&network),
        json!({
            "schema":"KTAPEOUT-COMPACT-NAME-DEED-REBIND-PLAN-V1", "profile_family_id":deed["profile_family_id"], "profile_version":deed["profile_version"],
            "network":network, "canonical_uri":uri, "name_key":key, "inputs":[{"role":"deed","state":deed}], "output":{"role":"deed","state":output,
            "target_components":{"application_id":application_id,"release_id":release_id,"deployment_id":deployment_id,"artifact_root":artifact_root}},
            "admission_status":"PROFILE_VARIANT_UNADMITTED", "signing_allowed":false, "broadcast":false
        }),
    )
}

#[allow(dead_code)]
fn compact_release_plan(
    deed_path: PathBuf,
    canonical_uri: String,
    left_gap: Option<String>,
    right_gap: Option<String>,
    refund_script_hash: String,
) -> Result<(), String> {
    if left_gap.is_none() && right_gap.is_none() {
        return Err("RELEASE_ADJACENT_GAP_REQUIRED".into());
    }
    if !valid_hash(&refund_script_hash) {
        return Err("REFUND_SCRIPT_HASH_INVALID".into());
    }
    let (deed, key, uri) = compact_state(deed_path, &canonical_uri)?;
    let key_int = num_bigint::BigUint::parse_bytes(key.as_bytes(), 16)
        .ok_or_else(|| "COMPACT_NAME_KEY_INVALID".to_string())?;
    let left = left_gap.map(|value| parse_gap_range(&value)).transpose()?;
    let right = right_gap.map(|value| parse_gap_range(&value)).transpose()?;
    if left.as_ref().is_some_and(|(_, hi)| hi != &key_int) {
        return Err("LEFT_GAP_NOT_ADJACENT".into());
    }
    let successor = &key_int + num_bigint::BigUint::from(1u8);
    if right.as_ref().is_some_and(|(lo, _)| lo != &successor) {
        return Err("RIGHT_GAP_NOT_ADJACENT".into());
    }
    let merged_lo = left
        .as_ref()
        .map(|(lo, _)| lo.clone())
        .unwrap_or_else(|| key_int.clone());
    let merged_hi = right
        .as_ref()
        .map(|(_, hi)| hi.clone())
        .unwrap_or_else(|| successor.clone());
    let mut inputs = Vec::new();
    if let Some((lo, hi)) = left {
        inputs.push(json!({"role":"left_gap","gap":gap_json(&lo,&hi)}));
    }
    inputs.push(json!({"role":"deed","state":deed.clone()}));
    if let Some((lo, hi)) = right {
        inputs.push(json!({"role":"right_gap","gap":gap_json(&lo,&hi)}));
    }
    let network = deed
        .get("network")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    emit_result(
        "ktape name compact-name-deed-release-plan",
        Some(&network),
        json!({
            "schema":"KTAPEOUT-COMPACT-NAME-DEED-RELEASE-PLAN-V1", "profile_family_id":deed["profile_family_id"], "profile_version":deed["profile_version"],
            "network":network, "canonical_uri":uri, "name_key":key, "inputs":inputs,
            "output":{"role":"merged_gap","gap":gap_json(&merged_lo,&merged_hi),"refund":{"script_hash":refund_script_hash,"minimum_sompi":deed["bond_sompi"]}},
            "admission_status":"PROFILE_VARIANT_UNADMITTED", "signing_allowed":false, "broadcast":false
        }),
    )
}

#[allow(dead_code)]
const COMPACT_V2_RECEIPT_SCHEMA: &str = "KTAPEOUT-COMPACT-ADMISSION-RECEIPT-V2";
#[allow(dead_code)]
const COMPACT_V2_REQUIRED_CHECKS: [&str; 7] = [
    "compiler_within_script_budget",
    "vector_suite_passed",
    "register_planner_suite_passed",
    "admitted_operations_have_vm_mass_value_evidence",
    "genesis_native_vm_verified",
    "genesis_gaps_share_template",
    "genesis_dual_rpc_exact_readback",
];

/// Evaluate a CompactV2 admission receipt: the digest must match, every semantic and
/// on-chain check must hold, and each admitted operation needs native VM, mass and
/// value-conservation evidence. Offline only: it never reads RPC, signs or broadcasts.
#[allow(dead_code)]
fn compact_v2_admission(receipt: &Value) -> Result<Value, String> {
    let object = receipt
        .as_object()
        .ok_or_else(|| "COMPACT_ADMISSION_RECEIPT_OBJECT_REQUIRED".to_string())?;
    if object.get("profile_family_id").and_then(Value::as_str) != Some(COMPACT_FAMILY_V2)
        || object.get("profile_version").and_then(Value::as_u64) != Some(2)
        || object.get("network").and_then(Value::as_str) != Some("testnet-10")
        || object.get("key_ordering").and_then(Value::as_str) != Some("UNSIGNED_BIG_ENDIAN_256")
        || object.get("gap_interval").and_then(Value::as_str) != Some("HALF_OPEN")
        || object.get("successor_rule").and_then(Value::as_str) != Some("EXACT_KEY_PLUS_ONE")
    {
        return Err("COMPACT_V2_ADMISSION_PROFILE_INVALID".into());
    }
    for field in [
        "source_sha256",
        "template_hash",
        "root_script_sha256",
        "vector_suite_digest",
        "receipt_digest",
    ] {
        if !object
            .get(field)
            .and_then(Value::as_str)
            .is_some_and(valid_hash)
        {
            return Err(format!("COMPACT_V2_ADMISSION_{field}_INVALID"));
        }
    }
    let mut core = receipt.clone();
    core.as_object_mut()
        .map(|value| value.remove("receipt_digest"));
    if object["receipt_digest"].as_str() != Some(sha256_value(&core)?.as_str()) {
        return Err("COMPACT_V2_RECEIPT_DIGEST_MISMATCH".into());
    }
    let checks = object
        .get("checks")
        .and_then(Value::as_object)
        .ok_or_else(|| "COMPACT_V2_CHECKS_MISSING".to_string())?;
    let mut missing: Vec<String> = COMPACT_V2_REQUIRED_CHECKS
        .iter()
        .filter(|name| checks.get(**name) != Some(&Value::Bool(true)))
        .map(|name| format!("check.{name}"))
        .collect();
    let operations = object.get("operations").and_then(Value::as_object);
    for operation in ["register", "transfer", "rebind"] {
        let evidence = operations
            .and_then(|value| value.get(operation))
            .and_then(Value::as_object);
        let proven = evidence.is_some_and(|value| {
            value.get("vm_positive") == Some(&Value::Bool(true))
                && value.get("vm_negative") == Some(&Value::Bool(true))
                && value.get("value_conservation") == Some(&Value::Bool(true))
                && value.get("mass_evidence").and_then(Value::as_str) == Some("NATIVE_VM")
        });
        if !proven {
            missing.push(format!("operation.{operation}"));
        }
    }
    let tn10 = object.get("tn10").and_then(Value::as_object);
    if tn10.and_then(|value| value.get("dual_rpc_match")) != Some(&Value::Bool(true))
        || tn10
            .and_then(|value| value.get("gaps"))
            .and_then(Value::as_array)
            .is_none_or(Vec::is_empty)
    {
        missing.push("tn10.dual_rpc_genesis_readback".into());
    }
    let admitted = missing.is_empty()
        && object.get("admission_status").and_then(Value::as_str) == Some("TESTNET_ADMITTED");
    Ok(json!({
        "schema": COMPACT_V2_RECEIPT_SCHEMA, "profile_family_id": COMPACT_FAMILY_V2, "profile_version": 2,
        "network": "testnet-10", "status": if admitted { "ADMITTED" } else { "PROFILE_VARIANT_UNADMITTED" },
        "admission_eligible": admitted, "missing": missing, "release_operation": "NOT_ADMITTED",
        "template_hash": object["template_hash"], "receipt_digest": object["receipt_digest"],
        "signing_allowed": false, "broadcast": false
    }))
}

/// V1 plans stay `PROFILE_VARIANT_UNADMITTED` (frozen; use `compact-admission-status`). A V2 plan is
/// admitted only by a valid V2 receipt, so a plan can never claim a family it was not checked against.
#[allow(dead_code)]
fn compact_plan_admission_status(family: &str, receipt: Option<PathBuf>) -> Result<String, String> {
    compact_family_version(family)?;
    match (family, receipt) {
        (COMPACT_FAMILY_V2, Some(path)) => {
            let evaluated = compact_v2_admission(&read_json(&path)?)?;
            Ok(if evaluated["admission_eligible"] == true {
                "TESTNET_ADMITTED"
            } else {
                "PROFILE_VARIANT_UNADMITTED"
            }
            .to_owned())
        }
        (COMPACT_FAMILY_V1, Some(_)) => {
            Err("COMPACT_V1_ADMISSION_USES_compact-admission-status".into())
        }
        _ => Ok("PROFILE_VARIANT_UNADMITTED".to_owned()),
    }
}

#[allow(dead_code)]
fn compact_admission_status(path: PathBuf) -> Result<(), String> {
    let receipt = read_json(&path)?;
    if receipt.get("schema").and_then(Value::as_str) == Some(COMPACT_V2_RECEIPT_SCHEMA) {
        let evaluated = compact_v2_admission(&receipt)?;
        let network = evaluated["network"]
            .as_str()
            .unwrap_or("testnet-10")
            .to_owned();
        return emit_result(
            "ktape name compact-admission-status",
            Some(&network),
            evaluated,
        );
    }
    let object = receipt
        .as_object()
        .ok_or_else(|| "COMPACT_ADMISSION_RECEIPT_OBJECT_REQUIRED".to_string())?;
    if object.get("schema").and_then(Value::as_str) != Some("KTAPEOUT-COMPACT-ADMISSION-RECEIPT-V1")
    {
        return Err("COMPACT_ADMISSION_RECEIPT_SCHEMA_INVALID".into());
    }
    if object.get("profile_family_id").and_then(Value::as_str)
        != Some("ApplicationNameDeedCompactV1")
        || object.get("profile_version").and_then(Value::as_u64) != Some(1)
    {
        return Err("COMPACT_ADMISSION_PROFILE_INVALID".into());
    }
    if object.get("admission_path").and_then(Value::as_str) != Some("TEMPLATE_ADAPTER_V1") {
        return Err("COMPACT_ADMISSION_PATH_INVALID".into());
    }
    for field in [
        "profile_hash",
        "codec_hash",
        "template_hash",
        "manifest_digest",
    ] {
        if !object
            .get(field)
            .and_then(Value::as_str)
            .is_some_and(valid_hash)
        {
            return Err(format!("COMPACT_ADMISSION_{field}_INVALID"));
        }
    }
    let network = object
        .get("network")
        .and_then(Value::as_str)
        .ok_or_else(|| "COMPACT_ADMISSION_NETWORK_INVALID".to_string())?;
    if !matches!(network, "testnet-10" | "mainnet") {
        return Err("COMPACT_ADMISSION_NETWORK_INVALID".into());
    }
    let probe_ok = |value: Option<&Value>, max: u64| {
        value.and_then(Value::as_object).is_some_and(|probe| {
            probe.get("status").and_then(Value::as_str) == Some("PASS")
                && probe
                    .get("script_bytes")
                    .and_then(Value::as_u64)
                    .is_some_and(|bytes| bytes < max)
        })
    };
    if !probe_ok(object.get("adapter_probe"), 10_000) {
        return Err("COMPACT_ADAPTER_PROBE_INVALID".into());
    }
    if !probe_ok(object.get("release_adapter_probe"), 10_000) {
        return Err("COMPACT_RELEASE_PROBE_INVALID".into());
    }
    let representation = object
        .get("representation")
        .and_then(Value::as_object)
        .ok_or_else(|| "COMPACT_REPRESENTATION_MISSING".to_string())?;
    let representation_mode = representation.get("mode").and_then(Value::as_str);
    let mut missing = std::collections::BTreeSet::<String>::new();
    let representation_valid = representation.get("status").and_then(Value::as_str) == Some("PASS")
        && matches!(
            representation_mode,
            Some("DIRECT_SCRIPT") | Some("P2SH_REDEEM_PUSH")
        );
    let mut missing_representation = !representation_valid;
    if representation.get("vm_positive") != Some(&Value::Bool(true))
        || representation.get("vm_negative") != Some(&Value::Bool(true))
    {
        missing_representation = true;
    }
    if representation_mode == Some("DIRECT_SCRIPT") {
        if representation
            .get("compiler_api_status")
            .and_then(Value::as_str)
            != Some("PUBLIC_ADMITTED")
        {
            missing_representation = true;
        }
        if representation
            .get("script_bytes")
            .and_then(Value::as_u64)
            .is_none_or(|bytes| bytes > 10_000)
        {
            missing_representation = true;
        }
    } else if representation_mode == Some("P2SH_REDEEM_PUSH")
        && (representation
            .get("script_bytes")
            .and_then(Value::as_u64)
            .is_none_or(|bytes| bytes > 10_000)
            || representation
                .get("redeem_stack_element_bytes")
                .and_then(Value::as_u64)
                .is_none_or(|bytes| bytes > 1_000_000))
    {
        missing_representation = true;
    }
    if missing_representation {
        missing.insert("representation.admissible".into());
    }
    let operations = object
        .get("operations")
        .and_then(Value::as_object)
        .ok_or_else(|| "COMPACT_OPERATIONS_INVALID".to_string())?;
    let required_ops = ["register", "transfer", "rebind", "release"];
    if operations
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>()
        != required_ops.into_iter().collect()
    {
        return Err("COMPACT_OPERATIONS_KEYS_INVALID".into());
    }
    for operation in required_ops {
        let value = operations
            .get(operation)
            .and_then(Value::as_object)
            .ok_or_else(|| format!("COMPACT_{operation}_EVIDENCE_INVALID"))?;
        if value.get("vm_positive") != Some(&Value::Bool(true)) {
            missing.insert(format!("{operation}.vm_positive"));
        }
        if value.get("vm_negative") != Some(&Value::Bool(true)) {
            missing.insert(format!("{operation}.vm_negative"));
        }
        if value.get("value_conservation") != Some(&Value::Bool(true)) {
            missing.insert(format!("{operation}.value_conservation"));
        }
        if value
            .get("script_bytes")
            .and_then(Value::as_u64)
            .is_none_or(|bytes| bytes >= 10_000)
        {
            missing.insert(format!("{operation}.script_bytes"));
        }
        if value
            .get("witness_bytes")
            .and_then(Value::as_u64)
            .is_none_or(|bytes| bytes == 0 || bytes > 512 * 1024)
        {
            missing.insert(format!("{operation}.witness_bytes"));
        }
        if value
            .get("mass")
            .and_then(Value::as_u64)
            .is_none_or(|mass| mass == 0 || mass > 100_000_000)
        {
            missing.insert(format!("{operation}.mass"));
        }
        if value.get("fee_sompi").and_then(Value::as_u64).is_none() {
            missing.insert(format!("{operation}.fee_sompi"));
        }
        if !matches!(
            value.get("mass_evidence").and_then(Value::as_str),
            Some("NATIVE_VM") | Some("TN10_RPC")
        ) {
            missing.insert(format!("{operation}.mass_evidence"));
        }
        if representation_mode == Some("P2SH_REDEEM_PUSH")
            && value
                .get("redeem_stack_element_bytes")
                .and_then(Value::as_u64)
                .is_none_or(|bytes| bytes == 0 || bytes > 1_000_000)
        {
            missing.insert(format!("{operation}.redeem_stack_element_bytes"));
        }
    }
    let mut failure_codes = std::collections::BTreeSet::<String>::new();
    // Mainnet must use the canonical network_observation section. Existing
    // TN10 receipts remain readable through the legacy tn10 section, but a
    // Mainnet receipt can never fall back to TN10 evidence.
    let (observation, observation_label) =
        if let Some(value) = object.get("network_observation").and_then(Value::as_object) {
            (Some(value), "mainnet")
        } else if network == "testnet-10" {
            (object.get("tn10").and_then(Value::as_object), "tn10")
        } else {
            (None, "mainnet")
        };
    if let Some(value) = observation {
        if let Some(observed_network) = value.get("network").and_then(Value::as_str) {
            if observed_network != network {
                missing.insert(format!(
                    "{}.network",
                    if observation_label == "tn10" {
                        "tn10"
                    } else {
                        network
                    }
                ));
                failure_codes.insert("NETWORK_OBSERVATION_NETWORK_MISMATCH".into());
            }
        }
        for field in [
            "genesis_outpoint",
            "anchor_digest",
            "dual_rpc_match",
            "readback",
        ] {
            if value.get(field).is_none() {
                missing.insert(format!(
                    "{}.{field}",
                    if observation_label == "tn10" {
                        "tn10"
                    } else {
                        network
                    }
                ));
            }
        }
        let label = if observation_label == "tn10" {
            "tn10"
        } else {
            network
        };
        if value
            .get("genesis_outpoint")
            .and_then(Value::as_str)
            .is_none_or(|outpoint| !valid_outpoint(outpoint))
        {
            missing.insert(format!("{label}.genesis_outpoint"));
        }
        if value
            .get("anchor_digest")
            .and_then(Value::as_str)
            .is_none_or(|digest| !valid_hash(digest))
        {
            missing.insert(format!("{label}.anchor_digest"));
        }
        if value.get("dual_rpc_match") != Some(&Value::Bool(true)) {
            missing.insert(format!("{label}.dual_rpc_match"));
        }
        if value.get("readback") != Some(&Value::Bool(true)) {
            missing.insert(format!("{label}.readback"));
        }
    } else {
        missing.insert(format!("{network}.network_observation"));
    }
    if missing.contains("representation.admissible") {
        if representation.get("status").and_then(Value::as_str) != Some("PASS") {
            failure_codes.insert("REPRESENTATION_EVIDENCE_MISSING".into());
        }
        if representation.get("vm_positive") != Some(&Value::Bool(true))
            || representation.get("vm_negative") != Some(&Value::Bool(true))
        {
            failure_codes.insert("REPRESENTATION_VM_EVIDENCE_MISSING".into());
        }
        if representation_mode == Some("DIRECT_SCRIPT")
            && representation
                .get("compiler_api_status")
                .and_then(Value::as_str)
                != Some("PUBLIC_ADMITTED")
        {
            failure_codes.insert("PUBLIC_COMPILER_NOT_ADMITTED".into());
        }
        if representation_mode == Some("P2SH_REDEEM_PUSH")
            && representation
                .get("redeem_stack_element_bytes")
                .and_then(Value::as_u64)
                .is_none_or(|bytes| bytes > 1_000_000)
        {
            failure_codes.insert("P2SH_REDEEM_STACK_LIMIT".into());
        }
        if representation
            .get("script_bytes")
            .and_then(Value::as_u64)
            .is_some_and(|bytes| bytes > 10_000)
        {
            failure_codes.insert("DIRECT_SCRIPT_SIZE_LIMIT".into());
        }
    }
    if missing
        .iter()
        .any(|value| value.ends_with(".vm_positive") || value.ends_with(".vm_negative"))
    {
        failure_codes.insert("LIFECYCLE_VM_EVIDENCE_MISSING".into());
    }
    if missing
        .iter()
        .any(|value| value.ends_with(".value_conservation"))
    {
        failure_codes.insert("VALUE_CONSERVATION_EVIDENCE_MISSING".into());
    }
    if missing.iter().any(|value| {
        value.ends_with(".mass_evidence")
            || value.ends_with(".mass")
            || value.ends_with(".fee_sompi")
    }) {
        failure_codes.insert("RESOURCE_MEASUREMENT_MISSING".into());
    }
    if missing
        .iter()
        .any(|value| value.ends_with(".redeem_stack_element_bytes"))
    {
        failure_codes.insert("P2SH_REDEEM_STACK_LIMIT".into());
    }
    if missing
        .iter()
        .any(|value| value.starts_with("tn10.") || value.starts_with("testnet-10."))
    {
        failure_codes.insert("TN10_READBACK_MISSING".into());
    }
    if missing.iter().any(|value| value.starts_with("mainnet.")) {
        failure_codes.insert("MAINNET_READBACK_MISSING".into());
    }
    let mut core = receipt.clone();
    if let Some(core_object) = core.as_object_mut() {
        core_object.remove("receipt_digest");
        core_object.remove("status");
        core_object.remove("missing");
    }
    let expected = sha256_value(&core)?;
    if let Some(supplied) = object.get("receipt_digest").and_then(Value::as_str) {
        if supplied != expected {
            return Err("COMPACT_RECEIPT_DIGEST_MISMATCH".into());
        }
    }
    let admission_eligible = missing.is_empty();
    emit_result(
        "ktape name compact-admission-status",
        Some(network),
        json!({
            "schema":"KTAPEOUT-COMPACT-ADMISSION-RECEIPT-V1", "profile_family_id":"ApplicationNameDeedCompactV1", "profile_version":1,
            "network":network, "admission_path":"TEMPLATE_ADAPTER_V1", "status":if admission_eligible{"ADMITTED"}else{"PROFILE_VARIANT_UNADMITTED"},
            "admission_eligible":admission_eligible, "missing":missing, "failure_codes":failure_codes, "receipt_digest":expected,
            "signing_allowed":false, "broadcast":false
        }),
    )
}

fn name_inspect_lifecycle(path: PathBuf, application_id: String) -> Result<(), String> {
    let state = read_json(&path)?;
    if state.get("schema").and_then(Value::as_str) != Some("KTAPEOUT-0.5.0-APPLICATION-REGISTRY-V1")
    {
        return Err("REGISTRY_SCHEMA_INVALID".into());
    }
    let network = state
        .get("network")
        .and_then(Value::as_str)
        .ok_or_else(|| "REGISTRY_NETWORK_INVALID".to_string())?;
    if !matches!(network, "testnet-10" | "mainnet") {
        return Err("REGISTRY_NETWORK_INVALID".into());
    }
    let application = state
        .get("applications")
        .and_then(|v| v.get(&application_id))
        .ok_or_else(|| "APPLICATION_NOT_REGISTERED".to_string())?;
    let lifecycle = application
        .get("lifecycle")
        .and_then(Value::as_str)
        .ok_or_else(|| "APPLICATION_LIFECYCLE_INVALID".to_string())?;
    if !matches!(lifecycle, "ACTIVE" | "PAUSED" | "DRAINING" | "RETIRED") {
        return Err("APPLICATION_LIFECYCLE_INVALID".into());
    }
    emit_result(
        "ktape name inspect-lifecycle",
        Some(network),
        json!({
            "schema":"KTAPEOUT-REGISTRY-LIFECYCLE-INSPECTION-V1","protocol_semver":PROTOCOL,"network":network,
            "application_id":application_id,"lifecycle":lifecycle,"verification_level":"LOCAL_PROJECTION","signing_allowed":false,"broadcast":false,"l1_attested":false
        }),
    )
}

fn name_evidence_verify(
    evidence_path: PathBuf,
    anchor_path: PathBuf,
    rpc_a_path: PathBuf,
    rpc_b_path: PathBuf,
) -> Result<(), String> {
    let evidence = read_json(&evidence_path)?;
    let anchor = read_json(&anchor_path)?;
    namespace_anchor::verify_fixed_anchor(&anchor)?;
    let rpc_a = read_json(&rpc_a_path)?;
    let rpc_b = read_json(&rpc_b_path)?;
    let evidence_object = evidence
        .as_object()
        .ok_or_else(|| "EVIDENCE_OBJECT_REQUIRED".to_string())?;
    let expected: std::collections::BTreeSet<&str> = [
        "anchor_digest",
        "canonical_uri",
        "name_key",
        "deed_address",
        "deed_outpoint",
        "deed_state",
        "source_tip",
    ]
    .into_iter()
    .collect();
    if evidence_object
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>()
        != expected
    {
        return Err("EVIDENCE_FIELDS_INVALID".into());
    }
    if evidence.get("anchor_digest") != anchor.get("manifest_digest") {
        return Err("ANCHOR_DIGEST_MISMATCH".into());
    }
    let canonical_uri = evidence
        .get("canonical_uri")
        .and_then(Value::as_str)
        .ok_or_else(|| "CANONICAL_URI_INVALID".to_string())?;
    let normalized = normalize_name_value(canonical_uri, None)?;
    if normalized.get("canonical_uri").and_then(Value::as_str) != Some(canonical_uri)
        || normalized.get("release_id").is_some_and(|v| !v.is_null())
    {
        return Err("CANONICAL_URI_INVALID".into());
    }
    let network = normalized
        .get("network")
        .and_then(Value::as_str)
        .ok_or_else(|| "NETWORK_INVALID".to_string())?;
    if anchor.get("network").and_then(Value::as_str) != Some(network) {
        return Err("EVIDENCE_NETWORK_MISMATCH".into());
    }
    let namespace = normalized
        .get("namespace")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let slug = normalized
        .get("slug")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let key = application_name_key_value(network, namespace, slug)?;
    if evidence.get("name_key").and_then(Value::as_str) != Some(key.as_str()) || !valid_hash(&key) {
        return Err("EVIDENCE_NAME_KEY_INVALID".into());
    }
    let outpoint = evidence
        .get("deed_outpoint")
        .and_then(Value::as_str)
        .ok_or_else(|| "EVIDENCE_OUTPOINT_INVALID".to_string())?;
    if !valid_outpoint(outpoint) {
        return Err("EVIDENCE_OUTPOINT_INVALID".into());
    }
    let tip = evidence
        .get("source_tip")
        .and_then(Value::as_str)
        .ok_or_else(|| "EVIDENCE_SOURCE_TIP_INVALID".to_string())?;
    if !valid_hash(tip) {
        return Err("EVIDENCE_SOURCE_TIP_INVALID".into());
    }
    let deed = evidence
        .get("deed_state")
        .ok_or_else(|| "DEED_STATE_INVALID".to_string())?;
    let deed_object = deed
        .as_object()
        .ok_or_else(|| "DEED_STATE_OBJECT_INVALID".to_string())?;
    let required_deed_fields: std::collections::BTreeSet<&str> = [
        "profile_family_id",
        "profile_version",
        "network",
        "provider_id",
        "canonical_uri",
        "name_key",
        "controller_policy_hash",
        "application_id",
        "release_id",
        "deployment_id",
        "artifact_root",
        "network_policy_hash",
        "resolver_policy_hash",
        "bond_sompi",
        "nonce",
        "status",
    ]
    .into_iter()
    .collect();
    if deed_object
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>()
        != required_deed_fields
    {
        return Err("DEED_STATE_FIELDS_INVALID".into());
    }
    if deed.get("profile_family_id").and_then(Value::as_str) != Some("ApplicationNameDeedV1")
        || deed.get("profile_version").and_then(Value::as_u64) != Some(1)
        || deed.get("network").and_then(Value::as_str) != Some(network)
        || deed.get("provider_id").and_then(Value::as_str) != Some("ktape")
    {
        return Err("DEED_STATE_PROFILE_INVALID".into());
    }
    let lifecycle = deed
        .get("status")
        .and_then(Value::as_str)
        .ok_or_else(|| "DEED_STATE_LIFECYCLE_INVALID".to_string())?;
    if !matches!(lifecycle, "ACTIVE" | "PAUSED" | "DRAINING" | "RETIRED") {
        return Err("DEED_STATE_LIFECYCLE_INVALID".into());
    }
    if deed.get("canonical_uri").and_then(Value::as_str) != Some(canonical_uri)
        || deed.get("name_key").and_then(Value::as_str) != Some(key.as_str())
    {
        return Err("DEED_STATE_IDENTITY_MISMATCH".into());
    }
    for field in [
        "controller_policy_hash",
        "application_id",
        "release_id",
        "artifact_root",
        "network_policy_hash",
        "resolver_policy_hash",
    ] {
        if !deed
            .get(field)
            .and_then(Value::as_str)
            .is_some_and(valid_hash)
        {
            return Err(format!("DEED_STATE_{field}_INVALID"));
        }
    }
    if deed
        .get("deployment_id")
        .and_then(Value::as_str)
        .is_none_or(|v| v.is_empty() || v.len() > 256)
        || deed
            .get("bond_sompi")
            .and_then(Value::as_u64)
            .is_none_or(|v| v < 1_000_000_000)
    {
        return Err("DEED_STATE_FIELDS_INVALID".into());
    }
    if rpc_a != rpc_b {
        return Err("RPC_OBSERVATIONS_DISAGREE".into());
    }
    let observed = rpc_a
        .as_object()
        .ok_or_else(|| "RPC_OBSERVATION_INVALID".to_string())?;
    if observed.get("tip").and_then(Value::as_str) != Some(tip)
        || observed.get("outpoint").and_then(Value::as_str) != Some(outpoint)
        || observed.get("name_key").and_then(Value::as_str) != Some(key.as_str())
        || observed.get("state") != Some(deed)
        || observed.get("covenant_id") != anchor.get("covenant_id")
    {
        return Err("RPC_OBSERVATION_BINDING_MISMATCH".into());
    }
    emit_result(
        "ktape name evidence-verify",
        Some(network),
        json!({
            "schema":"KTAPEOUT-NAME-DEED-RESOLUTION-RESULT-V1","verification_level":"APPLICATION_BINDING_VERIFIED","network":network,"canonical_uri":canonical_uri,"deed_outpoint":outpoint,"name_key":key,"lifecycle_status":lifecycle,"source_tip":tip,"anchor_digest":evidence["anchor_digest"]
        }),
    )
}

fn name_publication_verify(path: PathBuf) -> Result<(), String> {
    let value = read_json(&path)?;
    let required = [
        "schema",
        "protocol_semver",
        "status",
        "network",
        "uri",
        "provider",
        "namespace",
        "slug",
        "application_id",
        "release_id",
        "deployment_id",
        "owner_authority",
        "network_policy_id",
        "name_claim_outpoint",
        "source_tip",
        "state_root",
        "evidence_hash",
    ];
    let mut missing: Vec<String> = required
        .iter()
        .filter(|field| {
            value
                .get(**field)
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
        })
        .map(|field| (*field).to_string())
        .collect();
    let mut binding_missing = Vec::new();
    let exact_fields: std::collections::BTreeSet<&str> = required.iter().copied().collect();
    if value.as_object().is_none_or(|object| {
        object
            .keys()
            .any(|field| !exact_fields.contains(field.as_str()))
    }) {
        binding_missing.push("unknown_fields".to_string());
    }
    if value.as_object().map_or(0, serde_json::Map::len) != exact_fields.len() {
        binding_missing.push("field_set".to_string());
    }
    if value.get("schema").and_then(Value::as_str) != Some("KTAPEOUT-NAME-PUBLICATION-RECEIPT-V1") {
        missing.push("schema".to_string());
    }
    if value.get("protocol_semver").and_then(Value::as_str) != Some(PROTOCOL) {
        missing.push("protocol_semver".to_string());
    }
    if value.get("status").and_then(Value::as_str) != Some("CONFIRMED") {
        missing.push("status".to_string());
    }
    let network = value.get("network").and_then(Value::as_str);
    if !matches!(network, Some("testnet-10") | Some("mainnet")) {
        missing.push("network".to_string());
    }
    for field in [
        "application_id",
        "release_id",
        "source_tip",
        "state_root",
        "evidence_hash",
    ] {
        if value
            .get(field)
            .and_then(Value::as_str)
            .is_none_or(|v| !valid_hash(v))
        {
            binding_missing.push(field.to_string());
        }
    }
    if value
        .get("name_claim_outpoint")
        .and_then(Value::as_str)
        .is_none_or(|v| !valid_outpoint(v))
    {
        binding_missing.push("name_claim_outpoint".to_string());
    }
    let identity_ok = value
        .get("uri")
        .and_then(Value::as_str)
        .and_then(|uri| normalize_name_value(uri, None).ok())
        .is_some_and(|normalized| {
            normalized.get("network") == value.get("network")
                && normalized.get("namespace") == value.get("namespace")
                && normalized.get("slug") == value.get("slug")
                && value.get("provider").and_then(Value::as_str) == Some("ktape")
        });
    if !identity_ok {
        binding_missing.push("name_identity".to_string());
    }
    missing.sort();
    missing.dedup();
    binding_missing.sort();
    binding_missing.dedup();
    let shape_valid = missing.is_empty();
    let structurally_bound = shape_valid && binding_missing.is_empty();
    emit_result_status(
        "ktape name publication-verify",
        network,
        if structurally_bound {
            "WARNING"
        } else {
            "BLOCKED"
        },
        json!({
            "schema": "KTAPEOUT-NAME-PUBLICATION-VERIFICATION-V1",
            "shape_valid": shape_valid,
            "structurally_bound": structurally_bound,
            "l1_bound": false,
            "l1_attested": false,
            "valid": false,
            "missing": missing,
            "binding_missing": binding_missing,
            "network": value.get("network"),
            "requires_external_verifier": true,
            "signing_allowed": false,
            "broadcast": false
        }),
    )
}

fn registry_map<'a>(
    state: &'a Value,
    field: &str,
) -> Result<&'a serde_json::Map<String, Value>, String> {
    let label = field.to_ascii_uppercase();
    state
        .get(field)
        .and_then(Value::as_object)
        .ok_or_else(|| format!("REGISTRY_{label}_INVALID"))
}

fn registry_deployment_available(
    state: &Value,
    application_id: &str,
    release_id: &str,
    deployment: &Value,
) -> bool {
    let Some(deployment_object) = deployment.as_object() else {
        return false;
    };
    let Some(applications) = state.get("applications").and_then(Value::as_object) else {
        return false;
    };
    let Some(releases) = state.get("releases").and_then(Value::as_object) else {
        return false;
    };
    let Some(application) = applications.get(application_id).and_then(Value::as_object) else {
        return false;
    };
    let Some(release) = releases.get(release_id).and_then(Value::as_object) else {
        return false;
    };
    let deployment_id = deployment_object
        .get("deployment_id")
        .and_then(Value::as_str);
    let belongs_to_application = application
        .get("deployment_ids")
        .and_then(Value::as_array)
        .is_some_and(|ids| ids.iter().any(|id| id.as_str() == deployment_id));
    let common_binding = deployment_object
        .get("application_id")
        .and_then(Value::as_str)
        == Some(application_id)
        && deployment_object.get("release_id").and_then(Value::as_str) == Some(release_id)
        && deployment_object.get("network") == state.get("network")
        && release.get("application_id").and_then(Value::as_str) == Some(application_id)
        && release.get("immutable") == Some(&Value::Bool(true))
        && belongs_to_application;
    if !common_binding {
        return false;
    }
    match (
        deployment_object.get("status").and_then(Value::as_str),
        deployment_object
            .get("verification_level")
            .and_then(Value::as_str),
    ) {
        (Some("PROJECTED"), Some("LOCAL_PROJECTION")) => true,
        (Some("VERIFIED"), Some("INDEXED")) => {
            let Some(evidence) = deployment_object
                .get("index_evidence")
                .and_then(Value::as_object)
            else {
                return false;
            };
            let fields = [
                "network",
                "application_id",
                "release_id",
                "deployment_id",
                "owner_authority",
                "artifact_id",
                "profile_hash",
                "network_policy_id",
                "source_tip",
                "source_outpoint",
                "evidence_hash",
            ];
            fields.iter().all(|field| evidence.contains_key(*field))
                && evidence.get("network") == state.get("network")
                && evidence.get("application_id").and_then(Value::as_str) == Some(application_id)
                && evidence.get("release_id").and_then(Value::as_str) == Some(release_id)
                && evidence.get("deployment_id").and_then(Value::as_str) == deployment_id
                && evidence.get("artifact_id") == release.get("artifact_id")
                && evidence.get("profile_hash") == release.get("profile_hash")
                && evidence.get("network_policy_id") == release.get("network_policy_id")
                && evidence
                    .get("source_tip")
                    .and_then(Value::as_str)
                    .is_some_and(valid_hash)
                && evidence
                    .get("evidence_hash")
                    .and_then(Value::as_str)
                    .is_some_and(valid_hash)
                && evidence
                    .get("source_outpoint")
                    .and_then(Value::as_str)
                    .is_some_and(|outpoint| {
                        let (txid, index) = outpoint.split_once(':').unwrap_or(("", ""));
                        valid_hash(txid) && index.parse::<u32>().is_ok()
                    })
        }
        _ => false,
    }
}

fn name_publication_preflight_value(
    state: &Value,
    uri: &str,
    application_id: &str,
    release_id: &str,
    deployment_id: &str,
) -> Result<Value, String> {
    if !valid_hash(application_id) {
        return Err("APPLICATION_ID_INVALID".to_string());
    }
    if !valid_hash(release_id) {
        return Err("RELEASE_ID_INVALID".to_string());
    }
    if deployment_id.is_empty() || deployment_id.len() > 256 {
        return Err("DEPLOYMENT_ID_INVALID".to_string());
    }
    if state.get("schema").and_then(Value::as_str) != Some("KTAPEOUT-0.5.0-APPLICATION-REGISTRY-V1")
    {
        return Err("REGISTRY_SCHEMA_INVALID".to_string());
    }
    let network = state
        .get("network")
        .and_then(Value::as_str)
        .ok_or_else(|| "REGISTRY_NETWORK_INVALID".to_string())?;
    if network != "testnet-10" && network != "mainnet" {
        return Err("REGISTRY_NETWORK_INVALID".to_string());
    }
    let normalized = normalize_name_value(uri, Some(network))?;
    if normalized.get("canonical_uri").and_then(Value::as_str) != Some(uri)
        || normalized.get("network").and_then(Value::as_str) != Some(network)
    {
        return Err("NAME_URI_NOT_CANONICAL_FOR_REGISTRY".to_string());
    }
    let namespace = normalized
        .get("namespace")
        .and_then(Value::as_str)
        .ok_or_else(|| "NAME_NAMESPACE_INVALID".to_string())?;
    let slug = normalized
        .get("slug")
        .and_then(Value::as_str)
        .ok_or_else(|| "NAME_SLUG_INVALID".to_string())?;
    let key = format!("{namespace}/{slug}");
    let names = registry_map(state, "names")?;
    let claim = names
        .get(&key)
        .and_then(Value::as_object)
        .ok_or_else(|| "NAME_NOT_BOUND".to_string())?;
    if !matches!(
        claim.get("status").and_then(Value::as_str),
        Some("BOUND") | Some("RENEWED")
    ) {
        return Err("NAME_NOT_BOUND".to_string());
    }
    if claim.get("provider").and_then(Value::as_str) == Some("ktape")
        && (claim
            .get("external_name")
            .is_some_and(|value| !value.is_null())
            || claim
                .get("proof_hash")
                .is_some_and(|value| !value.is_null()))
    {
        return Err("NAME_PROVIDER_FIELDS_FORGED".to_string());
    }
    let resolved_application = claim
        .get("application_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "NAME_APPLICATION_INVALID".to_string())?;
    if resolved_application != application_id
        || claim.get("release_id").and_then(Value::as_str) != Some(release_id)
    {
        return Err("NAME_PUBLICATION_BINDING_MISMATCH".to_string());
    }
    let applications = registry_map(state, "applications")?;
    let application = applications
        .get(application_id)
        .and_then(Value::as_object)
        .ok_or_else(|| "APPLICATION_NOT_REGISTERED".to_string())?;
    let releases = registry_map(state, "releases")?;
    let release = releases
        .get(release_id)
        .ok_or_else(|| "RELEASE_NOT_REGISTERED".to_string())?;
    if release.get("application_id").and_then(Value::as_str) != Some(application_id)
        || release.get("immutable") != Some(&Value::Bool(true))
    {
        return Err("RELEASE_BINDING_INVALID".to_string());
    }
    let deployments = registry_map(state, "deployments")?;
    let deployment = deployments
        .get(deployment_id)
        .ok_or_else(|| "DEPLOYMENT_NOT_REGISTERED".to_string())?;
    if !registry_deployment_available(state, application_id, release_id, deployment) {
        return Err("DEPLOYMENT_NOT_AVAILABLE".to_string());
    }
    let deployment_member = application
        .get("deployment_ids")
        .and_then(Value::as_array)
        .is_some_and(|ids| ids.iter().any(|id| id.as_str() == Some(deployment_id)));
    if !deployment_member {
        return Err("DEPLOYMENT_APPLICATION_MEMBERSHIP_INVALID".to_string());
    }
    let verification_level = deployment
        .get("verification_level")
        .and_then(Value::as_str)
        .ok_or_else(|| "DEPLOYMENT_VERIFICATION_LEVEL_INVALID".to_string())?;
    if !valid_hash(
        release
            .get("release_id")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    ) {
        return Err("REGISTRY_RELEASE_ID_INVALID".to_string());
    }
    Ok(json!({
        "schema": "KTAPEOUT-NAME-PUBLICATION-PREFLIGHT-V1",
        "status": "READY_FOR_L1_PREFLIGHT",
        "uri": uri,
        "network": network,
        "application_id": application_id,
        "release_id": release_id,
        "deployment_id": deployment_id,
        "verification_level": verification_level,
        "l1_attested": false,
        "signing_allowed": false,
        "next_action": "bind this tuple to an admitted Bridge and obtain a name-specific L1 readback receipt"
    }))
}

fn name_publication_preflight(
    state_path: PathBuf,
    uri: String,
    application_id: String,
    release_id: String,
    deployment_id: String,
) -> Result<(), String> {
    let state = read_json(&state_path)?;
    let value = name_publication_preflight_value(
        &state,
        &uri,
        &application_id,
        &release_id,
        &deployment_id,
    )?;
    let network = value
        .get("network")
        .and_then(Value::as_str)
        .map(str::to_string);
    emit_result(
        "ktape name publication-preflight",
        network.as_deref(),
        value,
    )
}

fn name_publication_operation_plan(
    state_path: PathBuf,
    uri: String,
    application_id: String,
    release_id: String,
    deployment_id: String,
) -> Result<(), String> {
    let state = read_json(&state_path)?;
    let preflight = name_publication_preflight_value(
        &state,
        &uri,
        &application_id,
        &release_id,
        &deployment_id,
    )?;
    let network = state
        .get("network")
        .and_then(Value::as_str)
        .ok_or_else(|| "REGISTRY_NETWORK_INVALID".to_string())?;
    let identity = json!({
        "network": network,
        "uri": uri,
        "application_id": application_id,
        "release_id": release_id,
        "deployment_id": deployment_id,
        "adapter_manifest_digest": Value::Null,
    });
    let operation_id = deterministic_operation_id(
        "registry publication-operation-plan",
        Some(network),
        &identity,
    )?;
    let stages = json!([
        {"id": "local-registry-preflight", "status": "CONFIRMED", "l1_attested": false, "signing_allowed": false},
        {"id": "namespace-claim", "status": "BLOCKED", "reason": "NAMESPACE_L1_TRANSITION_REQUIRED", "l1_attested": false, "signing_allowed": false},
        {"id": "nameclaim-adapter", "status": "BLOCKED", "reason": "NAMECLAIM_ADAPTER_NOT_CONFIGURED", "l1_attested": false, "signing_allowed": false},
        {"id": "application-release-bind", "status": "BLOCKED", "reason": "NAMECLAIM_READBACK_REQUIRED", "l1_attested": false, "signing_allowed": false},
        {"id": "name-claim-readback", "status": "BLOCKED", "reason": "NAMECLAIM_READBACK_REQUIRED", "l1_attested": false, "signing_allowed": false},
        {"id": "publication-complete", "status": "BLOCKED", "reason": "L1_NAME_PUBLICATION_NOT_ATTESTED", "l1_attested": false, "signing_allowed": false}
    ]);
    emit_result(
        "ktape name publication-operation-plan",
        Some(network),
        json!({
            "schema": "KTAPEOUT-NAME-PUBLICATION-OPERATION-V1",
            "protocol_semver": PROTOCOL,
            "operation_id": operation_id,
            "status": "BLOCKED",
            "network": network,
            "uri": uri,
            "application_id": application_id,
            "release_id": release_id,
            "deployment_id": deployment_id,
            "adapter_status": "ABSENT",
            "preflight": preflight,
            "stages": stages,
            "l1_attested": false,
            "signing_allowed": false,
            "broadcast": false,
            "next_action": "configure an admitted NameClaim Adapter, then revalidate this exact operation tuple before signer request"
        }),
    )
}

fn proof_inspect(path: PathBuf) -> Result<(), String> {
    let value = read_json(&path)?;
    emit_result(
        "ktape proof inspect",
        value.get("network").and_then(Value::as_str),
        json!({"schema": "KTAPEOUT-0.5.0-PROOF-INSPECTION-V1", "status": value.get("status").or_else(|| value.get("proof_status")), "fields": value.as_object().map_or(Vec::<String>::new(), |object| object.keys().cloned().collect::<Vec<_>>()), "content_hash": sha256_value(&value)?}),
    )
}

fn proof_verify(path: PathBuf) -> Result<(), String> {
    let value = read_json(&path)?;
    let required = ["status", "network", "source_tip", "evidence_hash"];
    let missing: Vec<&str> = required
        .iter()
        .copied()
        .filter(|field| {
            value
                .get(field)
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
        })
        .collect();
    let shape_valid = missing.is_empty()
        && matches!(
            value.get("status").and_then(Value::as_str),
            Some("VERIFIED") | Some("L1_VERIFIED")
        );
    let binding_fields = [
        "application_id",
        "release_id",
        "artifact_id",
        "deployment_id",
        "network_policy_id",
        "owner_authority",
        "source_outpoint",
    ];
    let mut binding_missing: Vec<String> = binding_fields
        .iter()
        .filter(|field| {
            value
                .get(**field)
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
        })
        .map(|field| (*field).to_string())
        .collect();
    match value.get("successor").and_then(Value::as_object) {
        Some(successor) => {
            for field in ["outpoint", "state_root"] {
                if successor
                    .get(field)
                    .and_then(Value::as_str)
                    .is_none_or(str::is_empty)
                {
                    binding_missing.push(format!("successor.{field}"));
                }
            }
        }
        None => binding_missing.push("successor".to_string()),
    }
    let l1_bound = shape_valid && binding_missing.is_empty();
    // JSON cannot carry the Registry's in-process external-verifier capability.
    let l1_attested = false;
    emit_result(
        "ktape proof verify",
        value.get("network").and_then(Value::as_str),
        json!({"schema": "KTAPEOUT-0.5.0-PROOF-VERIFICATION-V1", "shape_valid": shape_valid, "l1_bound": l1_bound, "l1_attested": l1_attested, "valid": l1_attested, "missing": missing, "binding_missing": binding_missing, "network": value.get("network"), "source_tip": value.get("source_tip")}),
    )
}

fn kaspa_verify_signed_candidate(
    unsigned_path: PathBuf,
    signed_path: PathBuf,
    signer_policy_path: PathBuf,
    utxo_context_path: PathBuf,
) -> Result<(), String> {
    const INPUT_LIMIT: usize = 512 * 1024;
    let unsigned = read_bounded_file(&unsigned_path, INPUT_LIMIT, "UNSIGNED_TX_READ_FAILED")?;
    let signed = read_bounded_file(&signed_path, INPUT_LIMIT, "SIGNED_TX_READ_FAILED")?;
    let policy_bytes = read_bounded_file(
        &signer_policy_path,
        INPUT_LIMIT,
        "SIGNER_POLICY_READ_FAILED",
    )?;
    let utxo_bytes =
        read_bounded_file(&utxo_context_path, INPUT_LIMIT, "UTXO_CONTEXT_READ_FAILED")?;
    // The Core guard is specialized for the external signing-envelope object;
    // these auxiliary documents are root arrays validated by closed typed DTOs.
    let policy: Vec<ktapeout_kaspa_verifier::AuthorizedSignerInputV1> =
        parse_strict_json(&policy_bytes)
            .and_then(|value| serde_json::from_value(value).map_err(|error| error.to_string()))
            .map_err(|_| "SIGNER_POLICY_JSON_INVALID".to_string())?;
    let utxo_context: Vec<ktapeout_kaspa_verifier::ExternalUtxoContextV1> =
        parse_strict_json(&utxo_bytes)
            .and_then(|value| serde_json::from_value(value).map_err(|error| error.to_string()))
            .map_err(|_| "UTXO_CONTEXT_JSON_INVALID".to_string())?;
    let evidence = ktapeout_kaspa_verifier::verify_signed_v0_matches_unsigned_transaction(
        &unsigned,
        &signed,
        &policy,
        &utxo_context,
    )
    .map_err(|error| error.to_string())?;
    emit_result(
        "ktape kaspa verify-signed-candidate",
        None,
        json!({
            "schema": "KTAPEOUT-KASPA-SIGNED-TRANSACTION-LOCAL-CANDIDATE-V1",
            "verifier_result": evidence,
            "authorization_state": "UNAUTHENTICATED_CANDIDATE",
            "plan_source_authenticated": false,
            "plan_bound": false,
            "profile_bound": false,
            "utxo_freshness_checked": false,
            "consensus_admission_checked": false,
            "signing_allowed": false,
            "broadcast_allowed": false,
            "next_action": "obtain trusted-host plan, Profile and freshness verification; this local result cannot authorize signing or submission"
        }),
    )
}

fn proof_compare(left: PathBuf, right: PathBuf) -> Result<(), String> {
    let left_value = read_json(&left)?;
    let right_value = read_json(&right)?;
    emit_result(
        "ktape proof compare",
        None,
        json!({"schema": "KTAPEOUT-0.5.0-PROOF-COMPARE-V1", "equal": left_value == right_value, "left_hash": sha256_value(&left_value)?, "right_hash": sha256_value(&right_value)?}),
    )
}

fn index_status(path: PathBuf, checkpoint: bool) -> Result<(), String> {
    let value = read_json(&path)?;
    let history_count = value
        .get("history")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let result = if checkpoint {
        json!({"schema": "KTAPEOUT-0.5.0-INDEX-CHECKPOINT-V1", "network": value.get("network"), "event_count": history_count, "checkpoint_hash": sha256_value(&json!({"network": value.get("network"), "history": value.get("history")}))?, "write": false})
    } else {
        json!({"schema": "KTAPEOUT-0.5.0-INDEX-STATUS-V1", "network": value.get("network"), "history_count": history_count, "application_count": value.get("applications").and_then(Value::as_object).map_or(0, |object| object.len()), "release_count": value.get("releases").and_then(Value::as_object).map_or(0, |object| object.len()), "projection_hash": sha256_value(&value)?, "write": false})
    };
    emit_result(
        if checkpoint {
            "ktape index checkpoint"
        } else {
            "ktape index status"
        },
        value.get("network").and_then(Value::as_str),
        result,
    )
}

fn replay_registry(state: &Value, event_count: usize) -> Result<Value, String> {
    let object = state
        .as_object()
        .ok_or_else(|| "REGISTRY_STATE_NOT_OBJECT".to_string())?;
    if object.get("schema").and_then(Value::as_str)
        != Some("KTAPEOUT-0.5.0-APPLICATION-REGISTRY-V1")
    {
        return Err("REGISTRY_SCHEMA_INVALID".into());
    }
    let network = object
        .get("network")
        .and_then(Value::as_str)
        .ok_or_else(|| "REGISTRY_NETWORK_INVALID".to_string())?;
    if network != "testnet-10" && network != "mainnet" {
        return Err("REGISTRY_NETWORK_INVALID".into());
    }
    let history = object
        .get("history")
        .and_then(Value::as_array)
        .ok_or_else(|| "REGISTRY_HISTORY_NOT_REPLAYABLE".to_string())?;
    if event_count > history.len() {
        return Err("ROLLBACK_EVENT_COUNT_INVALID".into());
    }
    let mut rebuilt = json!({
        "schema": "KTAPEOUT-0.5.0-APPLICATION-REGISTRY-V1",
        "protocol_semver": PROTOCOL,
        "network": network,
        "now": object.get("now").cloned().unwrap_or_else(|| json!(0)),
        "namespaces": {}, "applications": {}, "releases": {}, "deployments": {}, "names": {}, "history": []
    });
    let collections = [
        "namespaces",
        "applications",
        "releases",
        "deployments",
        "names",
    ];
    for (index, event) in history.iter().take(event_count).enumerate() {
        let event_object = event
            .as_object()
            .ok_or_else(|| format!("HISTORY_EVENT_INVALID:{index}"))?;
        if event_object.get("network").and_then(Value::as_str) != Some(network) {
            return Err(format!("HISTORY_EVENT_NETWORK_INVALID:{index}"));
        }
        let delta = event_object
            .get("projection_delta")
            .and_then(Value::as_object)
            .ok_or_else(|| format!("HISTORY_EVENT_DELTA_MISSING:{index}"))?;
        for field in collections {
            let Some(entries) = delta.get(field) else {
                continue;
            };
            let entries = entries
                .as_object()
                .ok_or_else(|| format!("HISTORY_EVENT_DELTA_INVALID:{index}:{field}"))?;
            let collection = rebuilt
                .get_mut(field)
                .and_then(Value::as_object_mut)
                .ok_or_else(|| format!("REGISTRY_COLLECTION_INVALID:{field}"))?;
            for (key, change) in entries {
                let change = change
                    .as_object()
                    .ok_or_else(|| format!("HISTORY_CHANGE_INVALID:{index}:{field}:{key}"))?;
                if change
                    .keys()
                    .any(|name| name != "present" && name != "value")
                    || !change.contains_key("present")
                    || !change.contains_key("value")
                {
                    return Err(format!(
                        "HISTORY_CHANGE_FIELDS_INVALID:{index}:{field}:{key}"
                    ));
                }
                if change.get("present").and_then(Value::as_bool) == Some(true) {
                    collection.insert(
                        key.clone(),
                        change.get("value").cloned().unwrap_or(Value::Null),
                    );
                } else if change.get("present").and_then(Value::as_bool) == Some(false) {
                    collection.remove(key);
                } else {
                    return Err(format!(
                        "HISTORY_CHANGE_PRESENT_INVALID:{index}:{field}:{key}"
                    ));
                }
            }
        }
        rebuilt
            .get_mut("history")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| "REGISTRY_HISTORY_INVALID".to_string())?
            .push(event.clone());
    }
    Ok(rebuilt)
}

fn index_rebuild(
    path: PathBuf,
    event_count: Option<usize>,
    write: bool,
    rollback: bool,
) -> Result<(), String> {
    let state = read_json(&path)?;
    let history_count = state
        .get("history")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let count = event_count.unwrap_or(history_count);
    let rebuilt = replay_registry(&state, count)?;
    if write {
        fs::write(
            &path,
            serde_json::to_string_pretty(&rebuilt)
                .map_err(|error| format!("OUTPUT_JSON_ERROR:{error}"))?
                + "\n",
        )
        .map_err(|error| format!("OUTPUT_WRITE_ERROR:{error}"))?;
    }
    let data = if rollback {
        json!({"schema": "KTAPEOUT-0.5.0-INDEX-ROLLBACK-V1", "network": state.get("network"), "from_event_count": history_count, "to_event_count": count, "projection_hash": sha256_value(&rebuilt)?, "unsigned": true, "write": write})
    } else {
        json!({"schema": "KTAPEOUT-0.5.0-INDEX-REBUILD-V1", "network": state.get("network"), "rebuildable": true, "source_event_count": history_count, "projection_hash": sha256_value(&state)?, "rebuilt_projection_hash": sha256_value(&rebuilt)?, "matches_current": rebuilt == state, "write": write})
    };
    emit_result(
        if rollback {
            "ktape index rollback"
        } else {
            "ktape index rebuild"
        },
        state.get("network").and_then(Value::as_str),
        data,
    )
}

fn doctor(path: PathBuf) -> Result<(), String> {
    let value = read_json(&path)?;
    if !value.is_object() {
        return Err("DIAGNOSTIC_INPUT_NOT_OBJECT".into());
    }
    let mut haystack = String::new();
    for field in ["error_code", "code", "status", "message", "error"] {
        if let Some(text) = value.get(field).and_then(Value::as_str) {
            haystack.push_str(&text.to_ascii_uppercase());
            haystack.push(' ');
        }
    }
    let rules = [
        (
            "E050_EXTERNAL_SUBMITTER_REQUIRED",
            "external",
            "Do not retry; provide the fixed signed handoff to an admitted external signer/operator, then run independent dual-RPC readback.",
            "ktape deploy submit/readback",
        ),
        (
            "OPERATOR_UNAVAILABLE",
            "external",
            "Do not retry; restore or select an admitted external signer/operator and reuse the existing fixed handoff.",
            "ktape deploy submit/readback",
        ),
        (
            "DEPENDENCY_GATED",
            "admission",
            "Do not retry; add the exact missing Profile/codec/NetworkPolicy/deployment evidence and rebuild the fixed handoff.",
            "ktape profile evidence verify",
        ),
        (
            "PROOF_INCOMPLETE",
            "admission",
            "Do not retry; resolve each listed evidence ref against the existing Profile/Adapter evidence verifier (for formal-admission:PROVEN, provide the exact tuple-bound manifest and CLOSED closure artifacts), or keep the result local-only.",
            "ktape profile evidence verify",
        ),
        (
            "CONSENSUS_COMPUTE_LIMIT",
            "consensus",
            "Do not retry; lower the bounded topology or select a supported shape.",
            "ktape resource explain",
        ),
        (
            "PER_INPUT_BUDGET",
            "consensus",
            "Do not retry; reduce per-input work or split the transition.",
            "ktape resource explain",
        ),
        (
            "STALE",
            "state",
            "Refresh the declared predecessor and rebuild the unsigned plan.",
            "ktape app preflight",
        ),
        (
            "REPLAY",
            "state",
            "Do not retry the old plan; inspect the operation and create a new nonce-bound plan.",
            "ktape evidence recovery-check",
        ),
        (
            "WRONG_NETWORK",
            "context",
            "Select the explicit network context and regenerate the plan.",
            "ktape context show",
        ),
        (
            "LOCK_DRIFT",
            "build",
            "Re-resolve the Profile package and create a new Developer Lock.",
            "ktape profile lock",
        ),
        (
            "ESTIMATE_MISMATCH",
            "observation",
            "Do not sign; compare the local estimate with the fresh network quote.",
            "ktape resource explain",
        ),
        (
            "RPC_DISAGREEMENT",
            "observation",
            "Do not promote status; obtain a bounded per-source DAG anchor and compare the exact reads again.",
            "ktape evidence compare",
        ),
        (
            "FIXTURE_INPUT",
            "operator",
            "Fixtures are never eligible for signing; obtain a verified-live input through the operator boundary.",
            "ktape app preflight",
        ),
        (
            "WRONG_TEMPLATE",
            "operator",
            "Reject the input/output role mismatch and obtain a transaction matching the declared template.",
            "ktape app preflight",
        ),
        (
            "WRONG_UTXO_ROLE",
            "operator",
            "Reject the UTXO role mismatch and obtain a verified-live input matching the declared role.",
            "ktape app preflight",
        ),
        (
            "SIGNATURE_ENVIRONMENT",
            "operator",
            "Stop and inspect signer network/domain/environment before any retry.",
            "ktape signer audit",
        ),
        (
            "SIGNATURE_SCRIPT_MISMATCH",
            "operator",
            "Stop and inspect the signer script and exact transaction codec before any retry.",
            "ktape signer audit",
        ),
        (
            "MISSING_ADMISSION_EVIDENCE",
            "admission",
            "Do not promote; collect the required Profile or Adapter evidence for this declared scope.",
            "ktape profile evidence verify",
        ),
    ];
    let matched = rules
        .iter()
        .find(|(marker, _, _, _)| haystack.contains(marker));
    let evidence_hash = ktapeout_runtime::digest_json(&value, "KTAPEOUT/0.5.0/DOCTOR/INPUT/V1")?;
    let data = match matched {
        Some((marker, layer, next_action, verifier)) => json!({
            "schema": "KTAPEOUT-DOCTOR-RESULT-V1", "status": "ACTION_REQUIRED", "failure_layer": layer,
            "error_code": marker, "forbidden_retry": true, "next_action": next_action,
            "verifier_command": verifier, "matched_rule": marker, "evidence_hash": evidence_hash
        }),
        None => {
            fn truthy(value: &Value) -> bool {
                match value {
                    Value::Null => false,
                    Value::Bool(value) => *value,
                    Value::Number(value) => value
                        .as_i64()
                        .map(|number| number != 0)
                        .or_else(|| value.as_u64().map(|number| number != 0))
                        .or_else(|| value.as_f64().map(|number| number != 0.0))
                        .unwrap_or(false),
                    Value::String(value) => !value.is_empty(),
                    Value::Array(value) => !value.is_empty(),
                    Value::Object(value) => !value.is_empty(),
                }
            }
            let error_code = value
                .get("error_code")
                .filter(|candidate| truthy(candidate))
                .or_else(|| value.get("code").filter(|candidate| truthy(candidate)))
                .cloned()
                .unwrap_or(Value::Null);
            json!({
                "schema": "KTAPEOUT-DOCTOR-RESULT-V1", "status": "UNKNOWN_CONSTRAINT", "failure_layer": "unknown",
                "error_code": error_code, "forbidden_retry": true,
                "next_action": "Collect the structured result and run the relevant profile/runtime verifier.",
                "verifier_command": Value::Null, "matched_rule": Value::Null, "evidence_hash": evidence_hash
            })
        }
    };
    emit_result(
        "ktape doctor",
        value.get("network").and_then(Value::as_str),
        data,
    )
}

fn shell_validate_hash(value: &Value, field: &str) -> Result<(), String> {
    let candidate = value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{}_INVALID", field.to_ascii_uppercase()))?;
    if !valid_hash(candidate) || candidate == "0".repeat(64) {
        return Err(format!("{}_INVALID", field.to_ascii_uppercase()));
    }
    Ok(())
}

fn shell_snapshot(document: PathBuf) -> Result<(), String> {
    let value = read_json(&document)?;
    let expected = [
        "schema",
        "version",
        "protocol_semver",
        "network",
        "tip_binding",
        "pinned_tip",
        "application_id",
        "release_id",
        "artifact_root",
        "resolver_policy_root",
        "providers",
        "observed_at",
    ];
    if !exact_json_keys(&value, &expected)
        || value.get("schema").and_then(Value::as_str) != Some("KTAPEOUT-RESOLUTION-SNAPSHOT-V2")
        || value.get("version") != Some(&json!(2))
        || value.get("protocol_semver").and_then(Value::as_str) != Some(PROTOCOL)
    {
        return Err("RESOLUTION_SNAPSHOT_IDENTITY_OR_FIELDS_INVALID".into());
    }
    if !matches!(
        value.get("network").and_then(Value::as_str),
        Some("testnet-10" | "mainnet")
    ) {
        return Err("RESOLUTION_SNAPSHOT_NETWORK_INVALID".into());
    }
    let tip_binding = value
        .get("tip_binding")
        .and_then(Value::as_str)
        .ok_or_else(|| "RESOLUTION_SNAPSHOT_TIP_BINDING_INVALID".to_string())?;
    if !matches!(tip_binding, "LOCAL_PREVIEW" | "PINNED_L1") {
        return Err("RESOLUTION_SNAPSHOT_TIP_BINDING_INVALID".into());
    }
    let tip = value
        .get("pinned_tip")
        .ok_or_else(|| "RESOLUTION_SNAPSHOT_TIP_INVALID".to_string())?;
    if !exact_json_keys(tip, &["hash", "daa_score", "observed_at"]) {
        return Err("RESOLUTION_SNAPSHOT_TIP_INVALID".into());
    }
    let tip_hash = tip
        .get("hash")
        .ok_or_else(|| "RESOLUTION_SNAPSHOT_TIP_INVALID".to_string())?;
    match tip_hash {
        Value::Null if tip_binding == "LOCAL_PREVIEW" => {}
        Value::String(hash)
            if valid_hash(hash) && hash != &"0".repeat(64) && tip_binding == "PINNED_L1" => {}
        _ => return Err("RESOLUTION_SNAPSHOT_TIP_INVALID".into()),
    }
    if let Some(daa) = tip.get("daa_score") {
        if !daa.is_null()
            && !daa
                .as_str()
                .map(|value| {
                    value == "0"
                        || (!value.starts_with('0')
                            && value.bytes().all(|byte| byte.is_ascii_digit()))
                })
                .unwrap_or(false)
        {
            return Err("RESOLUTION_SNAPSHOT_TIP_INVALID".into());
        }
    }
    if tip
        .get("observed_at")
        .and_then(Value::as_str)
        .filter(|value| valid_utc_timestamp(value))
        .is_none()
    {
        return Err("RESOLUTION_SNAPSHOT_TIP_INVALID".into());
    }
    for field in [
        "application_id",
        "release_id",
        "artifact_root",
        "resolver_policy_root",
    ] {
        shell_validate_hash(&value, field)?;
    }
    let providers = value
        .get("providers")
        .and_then(Value::as_array)
        .ok_or_else(|| "RESOLUTION_SNAPSHOT_PROVIDERS_INVALID".to_string())?;
    if providers.len() < 2 || providers.len() > 8 {
        return Err("RESOLUTION_SNAPSHOT_PROVIDER_COUNT_INVALID".into());
    }
    let mut names = std::collections::BTreeSet::new();
    for provider in providers {
        let name = provider
            .as_str()
            .filter(|candidate| !candidate.is_empty() && candidate.len() <= 64)
            .ok_or_else(|| "RESOLUTION_SNAPSHOT_PROVIDERS_INVALID".to_string())?;
        if !names.insert(name.to_string()) {
            return Err("RESOLUTION_SNAPSHOT_PROVIDERS_INVALID".into());
        }
    }
    if value
        .get("observed_at")
        .and_then(Value::as_str)
        .filter(|value| valid_utc_timestamp(value))
        .is_none()
    {
        return Err("RESOLUTION_SNAPSHOT_OBSERVED_AT_INVALID".into());
    }
    let snapshot_hash = digest_json_domain(&value, "KTAPEOUT/0.5.0/RESOLUTION_SNAPSHOT/V2")?;
    emit_result(
        "ktape shell snapshot",
        value.get("network").and_then(Value::as_str),
        json!({"schema":"KTAPEOUT-RESOLUTION-SNAPSHOT-RESULT-V1", "snapshot_hash":snapshot_hash, "snapshot":value, "signing":false, "broadcast":false}),
    )
}

fn shell_loadout(document: PathBuf) -> Result<(), String> {
    let value = read_json(&document)?;
    let expected = [
        "schema",
        "version",
        "application_id",
        "release_id",
        "capabilities",
        "state_origin",
        "wallet_required",
        "settlement_required",
    ];
    if !exact_json_keys(&value, &expected)
        || value.get("schema").and_then(Value::as_str) != Some("KTAPEOUT-STARTER-LOADOUT-V1")
        || value.get("version") != Some(&json!(1))
    {
        return Err("STARTER_LOADOUT_IDENTITY_OR_FIELDS_INVALID".into());
    }
    shell_validate_hash(&value, "application_id")?;
    shell_validate_hash(&value, "release_id")?;
    let capabilities = value
        .get("capabilities")
        .and_then(Value::as_array)
        .ok_or_else(|| "STARTER_LOADOUT_CAPABILITIES_INVALID".to_string())?;
    if capabilities.len() > 32 {
        return Err("STARTER_LOADOUT_CAPABILITIES_INVALID".into());
    }
    let mut seen = std::collections::BTreeSet::new();
    for capability in capabilities {
        let name = capability
            .as_str()
            .filter(|candidate| !candidate.is_empty() && candidate.len() <= 64)
            .ok_or_else(|| "STARTER_LOADOUT_CAPABILITIES_INVALID".to_string())?;
        if !seen.insert(name.to_string()) {
            return Err("STARTER_LOADOUT_CAPABILITIES_INVALID".into());
        }
    }
    let origin = value
        .get("state_origin")
        .and_then(Value::as_str)
        .unwrap_or("");
    if !matches!(
        origin,
        "LOCAL_SESSION" | "CLAIMED_CAPABILITY" | "SETTLED_ASSET"
    ) {
        return Err("STARTER_LOADOUT_STATE_ORIGIN_INVALID".into());
    }
    let wallet = value
        .get("wallet_required")
        .and_then(Value::as_bool)
        .ok_or_else(|| "STARTER_LOADOUT_WALLET_REQUIRED_INVALID".to_string())?;
    let settlement = value
        .get("settlement_required")
        .and_then(Value::as_bool)
        .ok_or_else(|| "STARTER_LOADOUT_SETTLEMENT_REQUIRED_INVALID".to_string())?;
    // Keep the policy branches explicit: local sessions cannot require a wallet or settlement,
    // and settlement always requires a wallet.
    #[allow(clippy::nonminimal_bool)]
    let invalid_policy =
        (origin == "LOCAL_SESSION" && (wallet || settlement)) || (settlement && !wallet);
    if invalid_policy {
        return Err("STARTER_LOADOUT_POLICY_INVALID".into());
    }
    let loadout_hash = digest_json_domain(&value, "KTAPEOUT/0.5.0/STARTER_LOADOUT/V1")?;
    emit_result(
        "ktape shell loadout",
        None,
        json!({"schema":"KTAPEOUT-STARTER-LOADOUT-RESULT-V1", "loadout_hash":loadout_hash, "loadout":value, "signing":false, "broadcast":false}),
    )
}

fn shell_transition(current: String, target: String) -> Result<(), String> {
    let allowed = matches!(
        (current.as_str(), target.as_str()),
        ("GUEST", "LOCAL_SESSION")
            | ("GUEST", "CONNECTED")
            | ("LOCAL_SESSION", "GUEST")
            | ("LOCAL_SESSION", "CONNECTED")
            | ("CONNECTED", "LOCAL_SESSION")
            | ("CONNECTED", "SIGNING_READY")
            | ("SIGNING_READY", "CONNECTED")
            | ("SIGNING_READY", "SETTLEMENT_READY")
            | ("SETTLEMENT_READY", "CONNECTED")
    );
    if !allowed {
        return Err("SHELL_STATE_TRANSITION_INVALID".into());
    }
    emit_result(
        "ktape shell transition",
        None,
        json!({"schema":"KTAPEOUT-SHELL-TRANSITION-RESULT-V1", "from":current, "to":target, "status":"ALLOWED", "signing":false, "broadcast":false}),
    )
}

fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Command::Version => emit_result(
            "ktape version",
            None,
            json!({"protocol_semver": PROTOCOL, "cli": "ktape", "implementation": "rust", "signing": "developer-key-or-external-signature"}),
        ),
        Command::Init {
            template,
            network,
            output,
            profile_lock,
            profile_package,
            network_policy,
        } => init(
            template,
            network,
            output,
            profile_lock,
            profile_package,
            network_policy,
        ),
        Command::Dev { action } => match action {
            DevAction::Package {
                manifest,
                output,
                developer_lock,
                network_policy,
                network,
                backend,
            } => {
                let source = read_json(&manifest)?;
                let lock = developer_lock
                    .as_ref()
                    .map(|path| read_json(path))
                    .transpose()?;
                let policy = network_policy
                    .as_ref()
                    .map(|path| read_json(path))
                    .transpose()?;
                let package = if lock.is_none() && policy.is_none() {
                    dev_workflow::build_package(&source, &network, &backend)?
                } else {
                    dev_workflow::build_package_bound(
                        &source,
                        &network,
                        &backend,
                        dev_workflow::BuildBinding {
                            lock: lock.as_ref(),
                            policy: policy.as_ref(),
                        },
                    )?
                };
                dev_workflow::write_package(&output, &package)?;
                emit_result("ktape dev package", Some(&network), package.descriptor)
            }
            DevAction::Publishability {
                manifest,
                network,
                backend,
            } => {
                let result = dev_workflow::publishability(
                    &read_json(&manifest)?,
                    &network,
                    &backend,
                    dev_workflow::BuildBinding {
                        lock: None,
                        policy: None,
                    },
                )?;
                emit_result_status(
                    "ktape dev publishability",
                    Some(&network),
                    if result["lifecycle_status"] == "NOT_PUBLISHABLE" {
                        "BLOCKED"
                    } else {
                        "PASS"
                    },
                    result,
                )
            }
            DevAction::Check { manifest, network } => check_manifest(manifest, network),
            DevAction::Build {
                manifest,
                output,
                developer_lock,
                network_policy,
                backend,
                version,
            } => {
                let source = read_json(&manifest)?;
                let artifact = artifact_build_inputs(
                    &source,
                    developer_lock,
                    network_policy,
                    &backend,
                    &version,
                )?;
                if let Some(output) = output {
                    dev_workflow::write_build(&output, &source, &artifact)?;
                }
                emit_result("ktape artifact build", None, artifact)
            }
            DevAction::Test {
                manifest,
                profile_package_root,
                execution_result_output,
            } => match profile_package_root {
                Some(package_root) => profile_vector_runner::test(
                    &manifest,
                    &package_root,
                    execution_result_output.as_deref(),
                ),
                None if execution_result_output.is_some() => {
                    Err("PROFILE_VECTOR_PACKAGE_REQUIRED".into())
                }
                None => test_manifest(manifest, "ktape dev test"),
            },
            DevAction::Workflow {
                workflow,
                execution_result,
            } => dev_workflow(workflow, execution_result),
            DevAction::StudioHandoffVerify { handoff } => {
                let value = read_json(&handoff)?;
                let result = studio_cli_handoff::verify_handoff(&value)?;
                let network = result
                    .get("network")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                emit_result(
                    "ktape dev studio-handoff-verify",
                    network.as_deref(),
                    result,
                )
            }
            DevAction::StudioBundleBuild {
                handoff,
                developer_lock,
                output,
            } => dev_studio_bundle_build(handoff, developer_lock, output),
        },
        Command::Package { action } => match action {
            PackageAction::Build {
                source,
                application_uri,
                entrypoint,
                output,
                network,
                release_id,
                application_id,
                deployment_id,
                profile_lock,
            } => {
                let result = match (application_id, profile_lock) {
                    (Some(application_id), Some(profile_lock)) => {
                        let deployment_id = deployment_id
                            .as_deref()
                            .ok_or("PACKAGE_DEPLOYMENT_ID_REQUIRED")?;
                        let value = read_json(&profile_lock)?;
                        let profile = value.get("lock").cloned().unwrap_or(value);
                        package_build::build_for_publication(
                            &source,
                            &network,
                            &application_uri,
                            &entrypoint,
                            release_id.as_deref(),
                            &output,
                            &application_id,
                            deployment_id,
                            &profile,
                        )?
                    }
                    (None, None) => package_build::build(
                        &source,
                        &network,
                        &application_uri,
                        &entrypoint,
                        release_id.as_deref(),
                        &output,
                    )?,
                    _ => return Err("PACKAGE_PUBLICATION_BINDING_ARGUMENTS_INCOMPLETE".into()),
                };
                emit_result("ktape package build", Some(&network), result)
            }
        },
        Command::Deploy { action } => match action {
            DeployAction::Plan {
                manifest,
                network,
                backend,
                application_lock,
            } => deploy_plan(manifest, network, backend, application_lock),
            DeployAction::Preflight {
                manifest,
                network,
                backend,
                application_lock,
            } => deploy_preflight(manifest, network, backend, application_lock),
            DeployAction::SiteCheck {
                root,
                application_uri,
            } => {
                let result = site_delivery::check(&root, &application_uri)?;
                emit_result("ktape deploy site-check", None, result)
            }
            DeployAction::Submit { signed } => deploy_submit(signed),
            DeployAction::Readback { receipt } => deploy_readback(receipt),
        },
        Command::Publish { action } => match action {
            #[cfg(feature = "host-bridges")]
            PublishAction::Index {
                target,
                apply,
                resume,
            } => {
                let (network, result) =
                    host_publish::publish_application_index(target, apply, resume)?;
                emit_result("ktape publish index", network.as_deref(), result)
            }
            PublishAction::PolicyVerify { policy } => publish_policy_verify(policy),
            PublishAction::Ship {
                package,
                policy,
                provider,
                kind,
                at,
                expires_at,
                workdir,
                target,
                prepare_only,
                resume,
            } => {
                if target.is_some() || resume.is_some() {
                    if package.is_some()
                        || policy.is_some()
                        || provider.is_some()
                        || at.is_some()
                        || expires_at.is_some()
                    {
                        return Err("RELEASE_MIXED_COMMAND_MODES".into());
                    }
                    let target_path = target
                        .clone()
                        .or_else(|| resume.as_ref().map(|p| p.join("target.snapshot.json")))
                        .ok_or("RELEASE_TARGET_REQUIRED")?;
                    let profile: release_workflow::Target = serde_json::from_slice(
                        &fs::read(&target_path).map_err(|_| "RELEASE_TARGET_UNAVAILABLE")?,
                    )
                    .map_err(|_| "RELEASE_TARGET_INVALID")?;
                    require_release_target_line(
                        &profile.schema,
                        &profile.execution_line,
                        "KTAPEOUT-RELEASE-TARGET-V1",
                        "",
                    )
                    .map_err(|_| "PUBLISH_HOST_TARGET_REQUIRED")?;
                    return run_release_workflow(
                        "ktape publish ship",
                        target,
                        workdir,
                        resume,
                        None,
                        prepare_only,
                        None,
                        &[("KTAPEOUT-RELEASE-TARGET-V1", "")],
                    );
                }
                if prepare_only {
                    return Err("RELEASE_TARGET_REQUIRED".into());
                }
                let workdir = workdir.ok_or("SHIP_WORKDIR_REQUIRED")?;
                let package = package.ok_or("SHIP_PACKAGE_REQUIRED")?;
                let policy = policy.ok_or("SHIP_POLICY_REQUIRED")?;
                let provider = provider.ok_or("SHIP_PROVIDER_REQUIRED")?;
                let at = at.ok_or("SHIP_AT_REQUIRED")?;
                let expires_at = expires_at.ok_or("SHIP_EXPIRY_REQUIRED")?;
                fs::create_dir_all(&workdir).map_err(|_| "SHIP_WORKDIR_UNAVAILABLE".to_string())?;
                let mut runner = publish_ship::SelfRunner::new()?;
                let result = publish_ship::ship(
                    &publish_ship::ShipInputs {
                        package: &package,
                        policy: &policy,
                        provider: &provider,
                        kind: &kind,
                        at: &at,
                        expires_at: &expires_at,
                        workdir: &workdir,
                    },
                    &mut runner,
                )?;
                emit_result("ktape publish ship", None, result)
            }
            PublishAction::Plan {
                package,
                policy,
                kind,
                at,
                expires_at,
                output,
            } => publish_plan(package, policy, kind, at, expires_at, output),
            PublishAction::Preflight {
                intent,
                policy,
                provider,
            } => publish_preflight(intent, policy, provider),
            PublishAction::Bind {
                intent,
                policy,
                provider,
                operator_plan,
                maintenance_plan,
                project_lock_hash,
                operation_output,
                binding_output,
                reservation_ledger,
                wallet_reference_hash,
                outpoints,
            } => publish_bind(
                intent,
                policy,
                provider,
                operator_plan,
                maintenance_plan,
                project_lock_hash,
                operation_output,
                binding_output,
                reservation_ledger,
                wallet_reference_hash,
                outpoints,
            ),
            PublishAction::Reserve {
                intent,
                policy,
                wallet_reference_hash,
                outpoints,
                ledger,
            } => publish_reserve(intent, policy, wallet_reference_hash, outpoints, ledger),
            PublishAction::ReleaseReservation {
                binding,
                wallet_reference_hash,
                outpoints,
                ledger,
                terminal_stage,
            } => publish_release_reservation(
                binding,
                wallet_reference_hash,
                outpoints,
                ledger,
                terminal_stage,
            ),
            PublishAction::ReceiptVerify { receipt } => publish_receipt_verify(receipt),
            PublishAction::Recover { binding, receipt } => publish_recover(binding, receipt),
            PublishAction::Status {
                operation,
                operation_id,
                project_lock_hash,
                plan_hash,
                network,
                now,
            } => publish_status(
                operation,
                operation_id,
                project_lock_hash,
                plan_hash,
                network,
                now,
            ),
        },
        Command::Record { action } => match action {
            RecordAction::Verify { record } => {
                let record = read_json(&record)?;
                let report = app_record::verify_record(&record)?;
                emit_result("ktape record verify", record["network"].as_str(), report)
            }
            RecordAction::Build {
                network,
                namespace,
                slug,
                application_id,
                release_id,
                deployment_id,
                artifact_root,
                runtime_kind,
                card,
                locators,
                runtime_manifest_sha256,
                runtime_manifest_bytes,
                deed_evidence,
                release_authorization,
                output,
            } => {
                let release_authorization = release_authorization
                    .map(|path| read_json(&path))
                    .transpose()?;
                let evidence = deed_evidence
                    .map(|path| {
                        read_json(&path).map(|value| value.get("entry").cloned().unwrap_or(value))
                    })
                    .transpose()?;
                let runtime = match (runtime_manifest_sha256, runtime_manifest_bytes) {
                    (Some(sha), Some(bytes)) => {
                        Some(json!({"manifest_sha256": sha, "manifest_byte_length": bytes}))
                    }
                    _ => None,
                };
                let record = app_record::build_record(app_record::RecordParts {
                    network: &network,
                    namespace: &namespace,
                    slug: &slug,
                    application_id: &application_id,
                    release_id: &release_id,
                    deployment_id: &deployment_id,
                    artifact_root: &artifact_root,
                    runtime_kind: &runtime_kind,
                    card: read_json(&card)?,
                    locators,
                    runtime,
                    deed_evidence: evidence,
                    release_authorization,
                })?;
                if let Some(path) = output {
                    fs::write(&path, canonical_json(&record)?)
                        .map_err(|_| "RECORD_OUTPUT_WRITE_ERROR".to_string())?;
                }
                let report = app_record::verify_record(&record)?;
                emit_result(
                    "ktape record build",
                    Some(&network),
                    json!({"record": record, "report": report, "fragment": app_record::share_fragment(&record)?}),
                )
            }
            RecordAction::Share { record } => {
                let record = read_json(&record)?;
                let fragment = app_record::share_fragment(&record)?;
                let report = app_record::verify_record(&record)?;
                emit_result(
                    "ktape record share",
                    record["network"].as_str(),
                    json!({"fragment": fragment, "record_digest": report["record_digest"]}),
                )
            }
            RecordAction::Open { fragment } => {
                let (record, report) = app_record::open_fragment(&fragment)?;
                emit_result("ktape record open", record["network"].as_str(), report)
            }
        },
        Command::App { action } => match action {
            AppAction::Scaffold { template, network } => scaffold(template, network),
            AppAction::Quickstart { template, network } => quickstart(template, network),
            AppAction::Validate { manifest } => validate_manifest(manifest),
            AppAction::Check { manifest, network } => check_manifest(manifest, network),
            AppAction::Inspect { manifest } => inspect(manifest),
            AppAction::Test { manifest } => test_manifest(manifest, "ktape app test"),
            AppAction::Simulate { manifest } => simulate_manifest(manifest),
            AppAction::Preflight { manifest, network } => preflight_manifest(manifest, network),
            AppAction::ContentPreflight { artifact, network } => {
                content_preflight(artifact, network)
            }
            AppAction::ContentStateCommitment { state } => content_state_commitment(state),
            AppAction::Estimate { manifest, network } => estimate(manifest, network),
            AppAction::Plan { manifest, network } => {
                translate_manifest(manifest, network, "ktape app plan")
            }
            AppAction::ComposePreflight { profiles } => composition_preflight(profiles),
        },
        Command::Name { action } => match action {
            NameAction::RegistryInfo => emit_result(
                "ktape name registry-info",
                Some("testnet-10"),
                serde_json::from_str(include_str!(
                    "../../../data/registry/tn10-deployment-v1.json"
                ))
                .map_err(|error| format!("REGISTRY_DEPLOYMENT_INVALID:{error}"))?,
            ),
            #[cfg(all(feature = "developer-signing", feature = "tn10-network"))]
            NameAction::TestKeygen { output } => emit_result(
                "ktape name test-keygen",
                Some("testnet-10"),
                ktapeout_cli::tn10_developer_signing::generate_tn10_test_key(&output)
                    .map_err(|error| error.to_string())?,
            ),
            #[cfg(all(feature = "developer-signing", feature = "tn10-network"))]
            NameAction::TestKeyInfo { key_file } => emit_result(
                "ktape name test-key-info",
                Some("testnet-10"),
                ktapeout_cli::tn10_developer_signing::inspect_tn10_test_key(&key_file)
                    .map_err(|error| error.to_string())?,
            ),
            NameAction::Normalize {
                uri,
                default_network,
            } => normalize_name(uri, default_network),
            #[cfg(feature = "tn10-network")]
            NameAction::RegisterPlan {
                request,
                keys_files,
                keys_urls,
                output,
            } => {
                tn10_pipeline::registry_register_plan(&request, &output, &keys_files, &keys_urls)
                    .map_err(|error| error.to_string())?;
                emit_result(
                    "ktape name register-plan",
                    Some("testnet-10"),
                    read_json(&output)?,
                )
            }
            #[cfg(feature = "tn10-network")]
            NameAction::OwnerTargetPlan { request, output } => {
                let request_value = read_json(&request)?;
                let plan = tn10_pipeline::build_native_owner_target_plan(&request_value)
                    .map_err(|error| error.to_string())?;
                fs::write(&output, canonical_json(&plan)?)
                    .map_err(|error| format!("OWNER_TARGET_PLAN_WRITE_ERROR:{error}"))?;
                emit_result("ktape name owner-target-plan", Some("testnet-10"), plan)
            }
            #[cfg(feature = "tn10-network")]
            NameAction::RegisterRequest {
                intent,
                names_file,
                output,
            } => {
                tn10_pipeline::registry_request_from_names(&intent, &names_file, &output)
                    .map_err(|error| error.to_string())?;
                emit_result(
                    "ktape name register-request",
                    Some("testnet-10"),
                    read_json(&output)?,
                )
            }
            NameAction::IssuanceReview {
                prepared,
                output,
                escrow_dirs,
            } => {
                let prepared = read_json(&prepared)?;
                let packet =
                    ktapeout_cli::namespace_issuance_review::build_review_packet(&prepared)
                        .map_err(|error| error.to_string())?;
                let review = ktapeout_cli::namespace_issuance_review::build_approval_review(
                    &prepared, &packet,
                )
                .map_err(|error| error.to_string())?;
                let escrow_files = ktapeout_cli::namespace_issuance_review::escrow_review_packet(
                    &prepared,
                    &escrow_dirs,
                )
                .map_err(|error| error.to_string())?;
                let record = json!({"packet":packet,"approval_review":review,"escrow_files":escrow_files,
                    "signing_allowed":false,"broadcast":false});
                let bytes = serde_json::to_vec_pretty(&record).map_err(|error| {
                    format!("NAMESPACE_ISSUANCE_REVIEW_SERIALIZE_ERROR:{error}")
                })?;
                fs::write(&output, bytes)
                    .map_err(|error| format!("NAMESPACE_ISSUANCE_REVIEW_WRITE_ERROR:{error}"))?;
                emit_result("ktape name issuance-review", Some("testnet-10"), record)
            }
            NameAction::IssuancePlan { request, output } => {
                let request = read_json(&request)?;
                let plan = ktapeout_050_adapter_workbench::namespace_issuance_v1_plan::build(
                    &request, false,
                )
                .map_err(|error| format!("NAMESPACE_ISSUANCE_PLAN_REJECTED:{error}"))?;
                if plan["body"]["network"] != "testnet-10"
                    || plan["body"]["adapter_id"] != "ktape.official.adapter.registry"
                    || plan["body"]["broadcast"] != false
                {
                    return Err("NAMESPACE_ISSUANCE_PLAN_SCOPE_INVALID".into());
                }
                let bytes = serde_json::to_vec_pretty(&plan)
                    .map_err(|error| format!("NAMESPACE_ISSUANCE_PLAN_SERIALIZE_ERROR:{error}"))?;
                fs::write(&output, bytes)
                    .map_err(|error| format!("NAMESPACE_ISSUANCE_PLAN_WRITE_ERROR:{error}"))?;
                emit_result("ktape name issuance-plan", Some("testnet-10"), plan)
            }
            NameAction::IssuanceTransition {
                phase,
                request,
                output,
                authorization,
                key_path,
                key_stdin,
            } => {
                if output.exists() {
                    return Err("NAMESPACE_ISSUANCE_TRANSITION_OUTPUT_EXISTS".into());
                }
                let mode = match phase.as_str() {
                    "plan" => "--transition-plan",
                    "verify" => "--verify-signatures",
                    "assemble" => "--merge-signatures",
                    "sign" => "sign",
                    _ => return Err("NAMESPACE_ISSUANCE_TRANSITION_PHASE_INVALID".into()),
                };
                let document = read_json(&request)?;
                let operation = if phase == "plan" {
                    &document["request"]
                } else {
                    &document["plan"]["request"]
                };
                if operation["network"] != "testnet-10"
                    || operation["operation"] != "ISSUE_NAMESPACE"
                {
                    return Err("NAMESPACE_ISSUANCE_TRANSITION_SCOPE_INVALID".into());
                }
                if phase == "sign" {
                    let authorization_path = authorization
                        .as_deref()
                        .ok_or("NAMESPACE_ISSUANCE_TRANSITION_AUTHORIZATION_REQUIRED")?;
                    let authorization = read_json(authorization_path)?;
                    ktapeout_cli::tn10_developer_signing::run_name_transition_sign(
                        &document,
                        &authorization,
                        &output,
                        key_path.as_deref(),
                        key_stdin,
                    )
                    .map_err(|error| {
                        format!("NAMESPACE_ISSUANCE_TRANSITION_SIGN_REJECTED:{error}")
                    })?;
                    return emit_result(
                        "ktape name issuance-transition sign",
                        Some("testnet-10"),
                        read_json(&output)?,
                    );
                }
                if key_path.is_some() || key_stdin {
                    return Err("NAMESPACE_ISSUANCE_TRANSITION_KEY_OPTION_UNSUPPORTED".into());
                }
                if authorization.is_some() {
                    return Err("NAMESPACE_ISSUANCE_TRANSITION_AUTHORIZATION_PHASE_INVALID".into());
                }
                let transition_input = if phase == "plan" {
                    json!({
                        "action":"profile_state_transition",
                        "request":operation
                    })
                } else {
                    json!({"plan":document["plan"],"packets":document["packets"]})
                };
                let result =
                    ktapeout_050_adapter_workbench::namespace_issuance_v1_plan::transition_command(
                        mode,
                        &transition_input,
                    )
                    .map_err(|error| format!("NAMESPACE_ISSUANCE_TRANSITION_REJECTED:{error}"))?;
                let mut result = if phase == "plan" {
                    json!({
                        "plan":{"action":"profile_state_transition","request":operation},
                        "signing":result,
                        "packets":[],
                        "broadcast":false
                    })
                } else {
                    result
                };
                if phase == "assemble" {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_err(|_| "TN10_CLOCK_INVALID")?
                        .as_secs();
                    ktapeout_cli::tn10_pipeline::verify_namespace_transition_authorization(
                        &document,
                        &document["authorization"],
                        now,
                    )
                    .map_err(|error| error.to_string())?;
                    result["authorization"] = document["authorization"].clone();
                }
                let bytes = serde_json::to_vec_pretty(&result).map_err(|error| {
                    format!("NAMESPACE_ISSUANCE_TRANSITION_SERIALIZE_ERROR:{error}")
                })?;
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&output)
                    .map_err(|error| {
                        format!("NAMESPACE_ISSUANCE_TRANSITION_WRITE_ERROR:{error}")
                    })?;
                file.write_all(&bytes)
                    .and_then(|_| file.sync_all())
                    .map_err(|error| {
                        format!("NAMESPACE_ISSUANCE_TRANSITION_WRITE_ERROR:{error}")
                    })?;
                emit_result("ktape name issuance-transition", Some("testnet-10"), result)
            }
            NameAction::ParentGenesisPlan { request, output } => {
                let request = read_json(&request)?;
                let plan =
                    ktapeout_050_adapter_workbench::namespace_parent_genesis::build(&request)
                        .map_err(|error| format!("NAMESPACE_PARENT_GENESIS_REJECTED:{error}"))?;
                if plan["adapter_id"] != "ktape.official.adapter.registry"
                    || plan["network"] != "testnet-10"
                    || plan["broadcast"] != false
                {
                    return Err("NAMESPACE_PARENT_GENESIS_SCOPE_INVALID".into());
                }
                let bytes = serde_json::to_vec_pretty(&plan)
                    .map_err(|error| format!("NAMESPACE_PARENT_GENESIS_SERIALIZE_ERROR:{error}"))?;
                fs::write(&output, bytes)
                    .map_err(|error| format!("NAMESPACE_PARENT_GENESIS_WRITE_ERROR:{error}"))?;
                emit_result("ktape name parent-genesis-plan", Some("testnet-10"), plan)
            }
            NameAction::ParentGenesisTransition {
                phase,
                request,
                output,
                authorization,
                key_path,
                key_stdin,
            } => {
                if output.exists() {
                    return Err("NAMESPACE_PARENT_GENESIS_TRANSITION_OUTPUT_EXISTS".into());
                }
                let mode = match phase.as_str() {
                    "plan" => "--transition-plan",
                    "verify" => "--verify-signatures",
                    "assemble" => "--merge-signatures",
                    "sign" => "sign",
                    _ => return Err("NAMESPACE_PARENT_GENESIS_TRANSITION_PHASE_INVALID".into()),
                };
                let document = read_json(&request)?;
                if phase == "sign" {
                    let authorization_path = authorization
                        .as_deref()
                        .ok_or("NAMESPACE_PARENT_GENESIS_TRANSITION_AUTHORIZATION_REQUIRED")?;
                    let authorization = read_json(authorization_path)?;
                    ktapeout_cli::tn10_developer_signing::run_name_transition_sign(
                        &document,
                        &authorization,
                        &output,
                        key_path.as_deref(),
                        key_stdin,
                    )
                    .map_err(|error| format!("NAMESPACE_PARENT_GENESIS_SIGN_REJECTED:{error}"))?;
                    return emit_result(
                        "ktape name parent-genesis-transition sign",
                        Some("testnet-10"),
                        read_json(&output)?,
                    );
                }
                if key_path.is_some() || key_stdin {
                    return Err("NAMESPACE_PARENT_GENESIS_KEY_OPTION_UNSUPPORTED".into());
                }
                if authorization.is_some() {
                    return Err(
                        "NAMESPACE_PARENT_GENESIS_TRANSITION_AUTHORIZATION_PHASE_INVALID".into(),
                    );
                }
                let transition_input = if phase == "plan" {
                    json!({"action":"namespace_parent_genesis","request":document})
                } else {
                    json!({"plan":document["plan"],"packets":document["packets"]})
                };
                let result =
                    ktapeout_050_adapter_workbench::namespace_parent_genesis::transition_command(
                        mode,
                        &transition_input,
                    )
                    .map_err(|error| {
                        format!("NAMESPACE_PARENT_GENESIS_TRANSITION_REJECTED:{error}")
                    })?;
                let mut result = if phase == "plan" {
                    json!({"plan":{"action":"namespace_parent_genesis","request":document},"signing":result,"packets":[],"broadcast":false})
                } else {
                    result
                };
                if phase == "assemble" {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_err(|_| "TN10_CLOCK_INVALID")?
                        .as_secs();
                    ktapeout_cli::tn10_pipeline::verify_namespace_transition_authorization(
                        &document,
                        &document["authorization"],
                        now,
                    )
                    .map_err(|error| error.to_string())?;
                    result["authorization"] = document["authorization"].clone();
                }
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&output)
                    .map_err(|_| "NAMESPACE_PARENT_GENESIS_TRANSITION_OUTPUT_EXISTS")?;
                let bytes = serde_json::to_vec_pretty(&result).map_err(|error| {
                    format!("NAMESPACE_PARENT_GENESIS_TRANSITION_SERIALIZE_ERROR:{error}")
                })?;
                file.write_all(&bytes)
                    .and_then(|_| file.sync_all())
                    .map_err(|error| {
                        format!("NAMESPACE_PARENT_GENESIS_TRANSITION_WRITE_ERROR:{error}")
                    })?;
                emit_result(
                    "ktape name parent-genesis-transition",
                    Some("testnet-10"),
                    result,
                )
            }
            NameAction::SpaceCheck {
                keys,
                reserved_from,
                live,
                probe,
                network,
            } => name_space_check(keys, reserved_from, live, probe, network),
            NameAction::SpacePlan {
                keys,
                reserved_from,
                network,
            } => name_space_plan(keys, reserved_from, network),
            NameAction::AliasCreate {
                provider,
                external_name,
                network,
                canonical_uri,
                application_id,
                release_policy,
                binding_mode,
                provider_proof_ref,
                owner_signature,
            } => ingress_alias_create(
                provider,
                external_name,
                network,
                canonical_uri,
                application_id,
                release_policy,
                binding_mode,
                provider_proof_ref,
                owner_signature,
            ),
            NameAction::AliasVerify {
                alias,
                expected_network,
            } => ingress_alias_verify(alias, expected_network),
            NameAction::LifecyclePlan {
                network,
                operation,
                genesis_outpoint,
                predecessor_outpoint,
                policy_hash,
                operation_nonce,
                effective_point,
            } => name_lifecycle_plan(
                network,
                operation,
                genesis_outpoint,
                predecessor_outpoint,
                policy_hash,
                operation_nonce,
                effective_point,
            ),
            NameAction::VerifyReadback {
                receipt,
                expected_network,
                expected_plan_hash,
            } => name_verify_readback(receipt, expected_network, expected_plan_hash),
            NameAction::EvidenceVerify {
                evidence,
                anchor,
                rpc_a,
                rpc_b,
            } => name_evidence_verify(evidence, anchor, rpc_a, rpc_b),
            NameAction::InspectLifecycle {
                state,
                application_id,
            } => name_inspect_lifecycle(state, application_id),
            NameAction::PublicationVerify { receipt } => name_publication_verify(receipt),
            NameAction::PublicationPreflight {
                state,
                uri,
                application_id,
                release_id,
                deployment_id,
            } => name_publication_preflight(state, uri, application_id, release_id, deployment_id),
            NameAction::PublicationOperationPlan {
                state,
                uri,
                application_id,
                release_id,
                deployment_id,
            } => name_publication_operation_plan(
                state,
                uri,
                application_id,
                release_id,
                deployment_id,
            ),
        },
        Command::Proof { action } => match action {
            ProofAction::Inspect { proof } => proof_inspect(proof),
            ProofAction::Verify { proof } => proof_verify(proof),
            ProofAction::Compare { left, right } => proof_compare(left, right),
        },
        Command::GenesisProvenance { action } => match action {
            GenesisProvenanceAction::Compose { input, output } => {
                let value = read_json(&input)?;
                let composed = genesis_provenance::compose(value)?;
                let payload = serde_json::to_string_pretty(&composed)
                    .map_err(|error| format!("GENESIS_PROVENANCE_SERIALIZE_ERROR:{error}"))?
                    + "\n";
                fs::write(&output, payload)
                    .map_err(|error| format!("GENESIS_PROVENANCE_WRITE_ERROR:{error}"))?;
                emit_result(
                    "ktape genesis-provenance compose",
                    composed["network"].as_str(),
                    json!({"status":"PASS","proof":output,"provenance_hash":composed["provenance_hash"],"signing_allowed":false,"broadcast":false}),
                )
            }
            GenesisProvenanceAction::Verify {
                proof,
                expected_covenant_id,
                rebuild_result,
                readback,
            } => {
                let value = read_json(&proof)?;
                let rebuild_value = rebuild_result
                    .as_ref()
                    .map(|path| read_json(path))
                    .transpose()?;
                let readback_value = readback.as_ref().map(|path| read_json(path)).transpose()?;
                let result = genesis_provenance::verify_with_evidence(
                    &value,
                    expected_covenant_id.as_deref(),
                    rebuild_value.as_ref(),
                    readback_value.as_ref(),
                )?;
                let network = result["network"].as_str().map(str::to_owned);
                emit_result(
                    "ktape genesis-provenance verify",
                    network.as_deref(),
                    result,
                )
            }
        },
        Command::Index { action } => match action {
            IndexAction::Status { state } => index_status(state, false),
            IndexAction::Checkpoint { state } => index_status(state, true),
            IndexAction::Rebuild { state, write } => index_rebuild(state, None, write, false),
            IndexAction::Rollback {
                state,
                events,
                write,
            } => index_rebuild(state, Some(events), write, true),
        },
        Command::Profile { action } => match action {
            ProfileAction::Plan {
                intent,
                guidance,
                catalog_hash,
            } => {
                let intent_value = read_json(&intent)?;
                let guidance_value = read_json(&guidance)?;
                let result =
                    profile_solver::solve(&intent_value, &guidance_value, catalog_hash.as_deref())?;
                let network = intent_value.get("network").and_then(Value::as_str);
                let status = if result.get("status").and_then(Value::as_str) == Some("SOLVED") {
                    "PASS"
                } else {
                    "BLOCKED"
                };
                emit_result_status("ktape profile plan", network, status, result)
            }
            ProfileAction::Search { root, profile_id } => profile_search(root, profile_id),
            ProfileAction::Inspect { package } => profile_inspect(package),
            ProfileAction::Compose {
                packages,
                draft,
                output,
            } => profile_compose(packages, draft, output),
            ProfileAction::ApplicationLockV2 {
                recipe,
                package_dir,
                network_policy_id,
                created_at,
                runtime_digest,
                compiler_lock_digest,
                adapter_root,
                abi_root,
                vector_root,
                package_registry_root,
                dependency_root,
                output,
            } => profile_application_lock_v2(
                recipe,
                package_dir,
                network_policy_id,
                created_at,
                runtime_digest,
                compiler_lock_digest,
                adapter_root,
                abi_root,
                vector_root,
                package_registry_root,
                dependency_root,
                output,
            ),
            ProfileAction::Lock {
                package,
                network_policy_id,
                created_at,
            } => profile_lock(package, network_policy_id, created_at),
            ProfileAction::PackageVerify { package } => profile_package_verify(package),
            ProfileAction::PackageCompose {
                source,
                contract,
                effect_manifest,
                output,
            } => profile_package_compose(source, contract, effect_manifest, output),
            ProfileAction::VerificationAttestationVerify {
                attestation,
                publisher_keyring,
                trust_root,
                trust_root_update,
                trust_root_predecessor,
                publisher_delegation,
            } => {
                let result = namespace_admission::verify_signed_attestation(
                    &read_json(&attestation)?,
                    &read_json(&publisher_keyring)?,
                    &read_json(&trust_root)?,
                    &read_json(&trust_root_update)?,
                    &read_json(&trust_root_predecessor)?,
                    &read_json(&publisher_delegation)?,
                    chrono::Utc::now(),
                )?;
                emit_result(
                    "ktape profile verification-attestation-verify",
                    None,
                    result,
                )
            }
            #[cfg(feature = "host-bridges")]
            ProfileAction::AttestationVerify {
                attestation,
                publisher_keyring,
                namespace_admission_package,
                execution_report,
                trust_root,
                trust_root_update,
                trust_root_predecessor,
                publisher_delegation,
            } => {
                let result = namespace_admission::verify(
                    &attestation,
                    &publisher_keyring,
                    &namespace_admission_package,
                    &execution_report,
                    &trust_root,
                    &trust_root_update,
                    &trust_root_predecessor,
                    &publisher_delegation,
                )?;
                emit_result(
                    "ktape profile attestation-verify",
                    Some("testnet-10"),
                    result,
                )
            }
            ProfileAction::UpgradePlan {
                old_package,
                new_package,
            } => profile_upgrade_plan(old_package, new_package),
            ProfileAction::MigrationContractVerify {
                contract,
                old_package,
                new_package,
            } => {
                let value = read_json(&contract)?;
                migration::verify(&value)?;
                let profile_pair = match (old_package, new_package) {
                    (Some(old_path), Some(new_path)) => {
                        let (old_metadata, _) = verify_profile_package(old_path.clone())?;
                        let (new_metadata, _) = verify_profile_package(new_path.clone())?;
                        let old_descriptor = semantic_descriptor(&old_path)?;
                        let new_descriptor = semantic_descriptor(&new_path)?;
                        Some(migration::verify_profile_pair(
                            &value,
                            &old_metadata,
                            &old_descriptor,
                            &new_metadata,
                            &new_descriptor,
                        )?)
                    }
                    (None, None) => None,
                    _ => return Err("MIGRATION_PROFILE_PACKAGE_PAIR_REQUIRED".into()),
                };
                emit_result(
                    "ktape profile migration-contract-verify",
                    None,
                    json!({"status":"PASS","verification_scope":if profile_pair.is_some() { "LOCAL_CONTRACT_AND_PROFILE_PAIR" } else { "LOCAL_MIGRATION_CONTRACT" },"contract_hash":value["contract_hash"],"profile_pair":profile_pair,"execution":false,"signing_allowed":false,"broadcast":false}),
                )
            }
        },
        Command::Resource { action } => match action {
            ResourceAction::LifecycleReport { request } => {
                let bytes = read_bounded_file(&request, 256 * 1024, "LIFECYCLE_INPUT_READ_ERROR")?;
                let value = lifecycle_cost::parse(&bytes)?;
                let report = lifecycle_cost::compose(&value)?;
                let network = report["network"]
                    .as_str()
                    .ok_or("LIFECYCLE_NETWORK_INVALID")?
                    .to_owned();
                emit_result("ktape resource lifecycle-report", Some(&network), report)
            }
            ResourceAction::Explain { manifest } => resource_explain(manifest),
            ResourceAction::Quote { manifest, network } => resource_quote(manifest, network),
            ResourceAction::Plan {
                manifest,
                envelope,
                network,
            } => resource_plan(manifest, envelope, network),
            ResourceAction::BindShape {
                plan,
                bundle,
                source,
                developer_lock,
                network_policy,
            } => resource_bind_shape(plan, bundle, source, developer_lock, network_policy),
            ResourceAction::CalibrationStatus => resource_calibration_status(),
        },
        #[cfg(feature = "tn10-network")]
        Command::Tn10 { action } => match action {
            Tn10Action::Utxos { request, output } => {
                tn10_pipeline::observe(&request, &output, false).map_err(|e| e.to_string())
            }
            Tn10Action::RegistryScriptUtxos { request, output } => {
                tn10_pipeline::registry_script_utxos(&request, &output).map_err(|e| e.to_string())
            }
            Tn10Action::Locate { request, output } => {
                tn10_pipeline::observe(&request, &output, true).map_err(|e| e.to_string())
            }
            Tn10Action::Plan { input, output } => {
                tn10_pipeline::plan(&input, &output).map_err(|e| e.to_string())
            }
            #[cfg(feature = "developer-signing")]
            Tn10Action::Authorize {
                plan,
                output,
                max_total_sompi,
                max_fee_sompi,
                expires_utc,
                allow_broadcast,
                allow_readback,
            } => authorize_native_plan(
                &plan,
                &output,
                max_total_sompi,
                max_fee_sompi,
                &expires_utc,
                allow_broadcast,
                allow_readback,
            ),
            #[cfg(feature = "developer-signing")]
            Tn10Action::AuthorizeNamespaceTransition {
                plan,
                output,
                nodes,
                max_total_sompi,
                max_fee_sompi,
                expires_utc,
                allow_broadcast,
            } => authorize_namespace_transition(
                &plan,
                &output,
                &nodes,
                max_total_sompi,
                max_fee_sompi,
                &expires_utc,
                allow_broadcast,
            ),
            #[cfg(feature = "developer-signing")]
            Tn10Action::Sign {
                plan,
                authorization,
                signature,
                output,
                key_path,
                key_stdin,
                yes,
            } => ktapeout_cli::tn10_developer_signing::run(
                &plan,
                authorization.as_deref(),
                &output,
                key_path.as_deref(),
                key_stdin,
                signature.as_deref(),
                yes,
            )
            .map_err(|e| e.to_string()),
            #[cfg(feature = "developer-signing")]
            Tn10Action::Assemble {
                plan,
                output,
                authorization,
                partials,
            } => assemble_native_signature_packets(&plan, &authorization, &partials, &output),
            Tn10Action::Submit {
                signed,
                output,
                retry_same_txid,
            } => {
                tn10_pipeline::submit(&signed, &output, retry_same_txid).map_err(|e| e.to_string())
            }
            Tn10Action::SubmitNamespaceTransition {
                signed,
                output,
                nodes,
                retry_same_txid,
            } => tn10_pipeline::submit_namespace_transition(
                &signed,
                &output,
                &nodes,
                retry_same_txid,
            )
            .map_err(|e| e.to_string()),
            Tn10Action::Verify { evidence, output } => {
                tn10_pipeline::verify(&evidence, &output).map_err(|e| e.to_string())
            }
        },
        Command::Artifact { action } => artifact_command(action),
        Command::Release { action } => match action {
            ReleaseAction::Adapters => emit_result(
                "ktape release adapters",
                None,
                release_workflow::adapter_catalog()?,
            ),
            ReleaseAction::CandidateBuild {
                profile,
                package,
                snapshot_store,
                output,
            } => emit_result(
                "ktape release candidate-build",
                Some("testnet-10"),
                release_candidate_build::build(&profile, &package, &snapshot_store, &output)?,
            ),
            ReleaseAction::Status { workdir } => emit_result(
                "ktape release status",
                None,
                release_workflow::inspect(&workdir)?,
            ),
            ReleaseAction::ReconcileNative { workdir } => emit_result(
                "ktape release reconcile-native",
                None,
                release_workflow::reconcile_native(&workdir)?,
            ),
            ReleaseAction::AbandonUnattempted { workdir } => emit_result(
                "ktape release abandon-unattempted",
                None,
                release_workflow::abandon_unattempted(&workdir)?,
            ),
            ReleaseAction::RepairCliSigner {
                workdir,
                signer,
                signer_sha256,
            } => emit_result(
                "ktape release repair-cli-signer",
                None,
                release_workflow::repair_cli_signer(&workdir, &signer, &signer_sha256)?,
            ),
            ReleaseAction::EscrowRebind { workdir, copies } => emit_result(
                "ktape release escrow-rebind",
                None,
                release_workflow::rebind_escrow(&workdir, &copies)?,
            ),
            ReleaseAction::AuthorizationRequest { workdir } => emit_result(
                "ktape release authorization-request",
                None,
                release_workflow::authorization_request(&workdir)?,
            ),
            #[cfg(feature = "publisher-signing")]
            ReleaseAction::AuthorizationSign {
                workdir,
                signing_key,
                output,
            } => emit_result(
                "ktape release authorization-sign",
                None,
                release_workflow::sign_authorization(&workdir, &signing_key, &output)?,
            ),
            #[cfg(feature = "publisher-signing")]
            ReleaseAction::PublisherAuthorizationSign {
                authorization,
                publisher_scope,
                signing_key,
                output,
            } => emit_result(
                "ktape release publisher-authorization-sign",
                None,
                runtime_release_signing::sign_files(
                    &authorization,
                    &publisher_scope,
                    &signing_key,
                    &output,
                )?,
            ),
            ReleaseAction::PublisherAuthorizationDraft {
                route,
                manifest,
                publisher_scope,
                origin,
                release_sequence,
            } => {
                let route = read_json(&route)?;
                let manifest = read_json(&manifest)?;
                let scope = read_json(&publisher_scope)?;
                emit_result(
                    "ktape release publisher-authorization-draft",
                    route["network"].as_str(),
                    runtime_release_authorization::draft(
                        &scope,
                        &route,
                        &manifest,
                        &origin,
                        release_sequence,
                    )?,
                )
            }
            #[cfg(feature = "publisher-signing")]
            ReleaseAction::PublisherAuthorizationPreflight {
                authorization,
                publisher_scope,
                signing_key,
            } => emit_result(
                "ktape release publisher-authorization-preflight",
                None,
                runtime_release_signing::preflight_files(
                    &authorization,
                    &publisher_scope,
                    &signing_key,
                )?,
            ),
            ReleaseAction::PublisherAuthorizationVerify {
                authorization,
                publisher_scope,
                signed,
            } => emit_result(
                "ktape release publisher-authorization-verify",
                None,
                runtime_release_authorization::verify_signed_files(
                    &authorization,
                    &publisher_scope,
                    &signed,
                )?,
            ),
            ReleaseAction::AuthorizationImport { workdir, signature } => emit_result(
                "ktape release authorization-import",
                None,
                release_workflow::import_authorization(&workdir, &signature)?,
            ),
            ReleaseAction::Ship {
                target,
                candidate_result,
                prepare_only,
                workdir,
                resume,
                authorization_key,
            } => run_release_workflow(
                "ktape release ship",
                target,
                workdir,
                resume,
                candidate_result,
                prepare_only,
                authorization_key,
                &[
                    ("KTAPEOUT-RELEASE-TARGET-V2", "publisher"),
                    ("KTAPEOUT-RELEASE-TARGET-V3", "name-controller"),
                    ("KTAPEOUT-RELEASE-TARGET-V4", "name-controller"),
                ],
            ),
            ReleaseAction::NameUpdateCheck { config } => emit_result(
                "ktape release name-update-check",
                Some("testnet-10"),
                release_execute::check(&config)?,
            ),
            ReleaseAction::NameUpdateReview { config } => emit_result(
                "ktape release name-update-review",
                Some("testnet-10"),
                release_execute::review(&config)?,
            ),
            ReleaseAction::NameUpdateAuthorizeWorkflow {
                config,
                adapter_request,
            } => emit_result(
                "ktape release name-update-authorize-workflow",
                Some("testnet-10"),
                release_execute::authorize_from_workflow(&config, &adapter_request)?,
            ),
            ReleaseAction::NameUpdatePreflight { config } => emit_result(
                "ktape release name-update-preflight",
                Some("testnet-10"),
                release_execute::preflight(&config)?,
            ),
            ReleaseAction::NameUpdateInspect { config } => emit_result(
                "ktape release name-update-inspect",
                Some("testnet-10"),
                release_execute::inspect(&config)?,
            ),
            ReleaseAction::NameUpdateReadback {
                config,
                scan,
                verifier,
                verifier_sha256,
            } => emit_result(
                "ktape release name-update-readback",
                Some("testnet-10"),
                release_execute::readback(&config, &scan, &verifier, &verifier_sha256)?,
            ),
            ReleaseAction::NameUpdateSign { config } => emit_result(
                "ktape release name-update-sign",
                Some("testnet-10"),
                release_execute::sign(&config)?,
            ),
            ReleaseAction::NameUpdateSubmit { config } => emit_result(
                "ktape release name-update-submit",
                Some("testnet-10"),
                release_execute::submit(&config)?,
            ),
            ReleaseAction::ReceiptBuild {
                previous_receipt,
                review,
                post_state,
                signed,
                observation,
                state_helper,
                state_helper_sha256,
                output,
            } => {
                let helper = release_resolve::StateHelper {
                    path: &state_helper,
                    sha256: &state_helper_sha256,
                };
                let signed_bytes =
                    fs::read(&signed).map_err(|_| "RECEIPT_SIGNED_UNAVAILABLE".to_string())?;
                let signed_value: Value = serde_json::from_slice(&signed_bytes)
                    .map_err(|_| "RECEIPT_SIGNED_INVALID".to_string())?;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let receipt = release_name_update::build_receipt(
                    &read_json(&previous_receipt)?,
                    &read_json(&review)?,
                    &read_json(&post_state)?,
                    &signed_value,
                    &signed_bytes,
                    &read_json(&observation)?,
                    &helper,
                    now,
                )?;
                fs::write(
                    &output,
                    serde_json::to_vec_pretty(&receipt)
                        .map_err(|_| "RECEIPT_ENCODE_FAILED".to_string())?,
                )
                .map_err(|_| "RECEIPT_WRITE_FAILED".to_string())?;
                emit_result(
                    "ktape release receipt-build",
                    Some("testnet-10"),
                    json!({"status":"RECEIPT_VERIFIED_AND_WRITTEN","output":output,"state_binding":"RECOMPUTED_FROM_STATE","signing_allowed":false,"broadcast":false}),
                )
            }
            ReleaseAction::Readback {
                scan,
                signed,
                txid,
                projected_storage_mass,
                verifier,
                verifier_sha256,
            } => {
                let scan = read_json(&scan)?;
                let signed = read_json(&signed)?;
                let signed = signed.get("transaction").cloned().unwrap_or(signed);
                let report = release_readback::verify(
                    &scan,
                    &txid,
                    &signed,
                    projected_storage_mass,
                    &verifier,
                    &verifier_sha256,
                )?;
                emit_result("ktape release readback", Some("testnet-10"), report)
            }
            ReleaseAction::NameUpdatePrepare {
                receipt,
                new_target,
                owner_xonly,
                target_authority_xonly,
                fetcher,
                fetcher_sha256,
                planner,
                planner_sha256,
                state_helper,
                state_helper_sha256,
                endpoints,
                fee_ceiling_sompi,
                output,
            } => {
                let receipt = read_json(&receipt)?;
                let item = receipt["applications"]
                    .get(0)
                    .ok_or("NAME_UPDATE_RECEIPT_INVALID")?;
                let new_target = read_json(&new_target)?;
                let helper = release_resolve::StateHelper {
                    path: &state_helper,
                    sha256: &state_helper_sha256,
                };
                let authority = target_authority_xonly.unwrap_or_else(|| owner_xonly.clone());
                let summary = release_name_update::prepare(&release_name_update::Inputs {
                    item,
                    new_target: &new_target,
                    owner_xonly: &owner_xonly,
                    target_authority_xonly: &authority,
                    fetcher: release_name_update::Pinned {
                        path: &fetcher,
                        sha256: &fetcher_sha256,
                    },
                    planner: release_name_update::Pinned {
                        path: &planner,
                        sha256: &planner_sha256,
                    },
                    state_helper: &helper,
                    endpoints: &endpoints,
                    fee_ceiling_sompi,
                    output: &output,
                })?;
                emit_result(
                    "ktape release name-update-prepare",
                    Some("testnet-10"),
                    summary,
                )
            }
            ReleaseAction::RetentionCheck {
                manifest,
                sources,
                helper,
                helper_sha256,
                temporary,
            } => {
                let bytes = fs::read(&manifest)
                    .map_err(|_| "RETENTION_MANIFEST_UNAVAILABLE".to_string())?;
                let value: Value = serde_json::from_slice(&bytes)
                    .map_err(|_| "RETENTION_MANIFEST_INVALID".to_string())?;
                let mut files: Vec<(String, u64)> =
                    vec![(hex::encode(Sha256::digest(&bytes)), bytes.len() as u64)];
                for file in value["files"]
                    .as_array()
                    .ok_or("RETENTION_MANIFEST_INVALID")?
                {
                    let digest = file["sha256"]
                        .as_str()
                        .ok_or("RETENTION_MANIFEST_INVALID")?;
                    let length = file["byte_length"]
                        .as_u64()
                        .ok_or("RETENTION_MANIFEST_INVALID")?;
                    if !files.iter().any(|(d, _)| d == digest) {
                        files.push((digest.to_string(), length));
                    }
                }
                let helper = release_retention::Helper {
                    path: &helper,
                    sha256: &helper_sha256,
                };
                let result = release_retention::cold_read(&helper, &sources, &files, temporary)?;
                emit_result("ktape release retention-check", Some("testnet-10"), result)
            }
            ReleaseAction::EscrowState {
                state,
                expect_spk,
                unsigned_txid,
                name,
                destinations,
                state_helper,
                state_helper_sha256,
            } => {
                let helper = release_resolve::StateHelper {
                    path: &state_helper,
                    sha256: &state_helper_sha256,
                };
                let args = release_escrow::read_state_file(&state)?;
                let record = release_escrow::record(&args, &expect_spk, &unsigned_txid, &name)?;
                let files = release_escrow::escrow(&record, &destinations, &helper, &expect_spk)?;
                emit_result(
                    "ktape release escrow-state",
                    Some("testnet-10"),
                    json!({"status":"ESCROWED","copies":files,"digest":record["digest"],"script_public_key":expect_spk,"signing_allowed":false,"broadcast":false}),
                )
            }
            ReleaseAction::EscrowCheck {
                expect_spk,
                copies,
                state_helper,
                state_helper_sha256,
            } => {
                let helper = release_resolve::StateHelper {
                    path: &state_helper,
                    sha256: &state_helper_sha256,
                };
                release_escrow::require_escrow(&copies, &helper, &expect_spk)?;
                emit_result(
                    "ktape release escrow-check",
                    Some("testnet-10"),
                    json!({"status":"ESCROW_VERIFIED","copies":copies.len(),"signing_allowed":false,"broadcast":false}),
                )
            }
            ReleaseAction::EscrowAudit {
                directories,
                receipts,
                state_helper,
                state_helper_sha256,
                fetcher,
                fetcher_sha256,
                endpoints,
            } => {
                let helper = release_resolve::StateHelper {
                    path: &state_helper,
                    sha256: &state_helper_sha256,
                };
                let fetcher = release_name_update::Pinned {
                    path: &fetcher,
                    sha256: &fetcher_sha256,
                };
                let report = release_escrow_audit::audit(
                    &directories,
                    &receipts,
                    &helper,
                    &fetcher,
                    &endpoints,
                )?;
                let blocked = report["status"] != "VERIFIED";
                emit_result("ktape release escrow-audit", Some("testnet-10"), report)?;
                if blocked {
                    return Err("ESCROW_AUDIT_BLOCKED".into());
                }
                Ok(())
            }
            ReleaseAction::Resolve {
                receipt,
                fetcher,
                fetcher_sha256,
                endpoints,
                timeout_seconds,
                state_helper,
                state_helper_sha256,
                unproven_state,
            } => {
                let receipt = read_json(&receipt)?;
                let helper = match (&state_helper, &state_helper_sha256) {
                    (Some(path), Some(sha256)) => {
                        Some(release_resolve::StateHelper { path, sha256 })
                    }
                    (None, None) => None,
                    _ => return Err("RESOLVE_STATE_HELPER_PIN_REQUIRED".into()),
                };
                let verified = release_resolve::resolve_with_fetcher(
                    &receipt,
                    &fetcher,
                    &fetcher_sha256,
                    &endpoints,
                    timeout_seconds,
                    helper.as_ref(),
                    unproven_state,
                )?;
                emit_result(
                    "ktape release resolve",
                    Some("testnet-10"),
                    json!({"status":"VERIFIED","resolution":verified,"signing_allowed":false,"broadcast":false}),
                )
            }
            ReleaseAction::ResolveVerify {
                observation,
                unproven_state,
            } => {
                let value = read_json(&observation)?;
                let item = &value["receipt"]["applications"][0];
                let field = |k: &str| {
                    item[k]
                        .as_str()
                        .ok_or_else(|| "RESOLUTION_OBSERVATION_INVALID".to_string())
                };
                let node = |k: &str| release_resolve::NodeReading {
                    dag: &value[k]["dag"],
                    utxos: &value[k]["utxos"],
                };
                // `state_spk` is the script `registry_deed_state_address` compiled from `deed_state`; without it the
                // target is only the receipt's own assertion and must be accepted explicitly.
                let binding = match (value["state_spk"].as_str(), unproven_state) {
                    (Some(script_public_key), _) => {
                        release_resolve::StateBinding::Recomputed { script_public_key }
                    }
                    (None, true) => release_resolve::StateBinding::Unproven,
                    (None, false) => return Err("L1_DEED_STATE_PREIMAGE_REQUIRED".into()),
                };
                let verified = release_resolve::verify_live_resolution(
                    &value["receipt"],
                    field("application_id")?,
                    field("release_id")?,
                    field("artifact_root")?,
                    &node("rpcA"),
                    &node("rpcB"),
                    &binding,
                )?;
                emit_result(
                    "ktape release resolve-verify",
                    Some("testnet-10"),
                    json!({"status":"VERIFIED","resolution":verified,"signing_allowed":false,"broadcast":false}),
                )
            }
            ReleaseAction::Check { config, state } => emit_result(
                "ktape release check",
                None,
                release_pipeline::check(&config, &state)?,
            ),
            ReleaseAction::Verify {
                dir,
                network,
                application_uri,
                release_id,
                commitment,
                schema,
                release_file,
                optional_fetch_targets,
                strict_references,
            } => {
                let policy = release_closure::VerifyPolicy {
                    network: &network,
                    application_uri: application_uri.as_deref(),
                    release_id: release_id.as_deref(),
                    commitment: commitment.as_deref(),
                    schema: schema.as_deref(),
                    release_file: release_file.as_deref(),
                    optional_fetch_targets: optional_fetch_targets.into_iter().collect(),
                    strict_references,
                };
                let verified = release_closure::verify_directory(&dir, &policy)?;
                emit_result("ktape release verify", Some(&network), verified)
            }
            ReleaseAction::MaintenancePlan { template, output } => {
                let value = read_json(&template)?;
                let built = maintenance::build(value)?;
                let payload = serde_json::to_string_pretty(&built)
                    .map_err(|error| format!("MAINTENANCE_PLAN_SERIALIZE_ERROR:{error}"))?
                    + "\n";
                fs::write(&output, payload)
                    .map_err(|error| format!("MAINTENANCE_PLAN_WRITE_ERROR:{error}"))?;
                emit_result(
                    "ktape release maintenance-plan",
                    None,
                    json!({"status":"PASS", "plan":output, "plan_hash":built["plan_hash"], "signing_allowed":false,"broadcast":false}),
                )
            }
            ReleaseAction::MaintenanceVerify {
                plan,
                genesis_provenance,
                expected_covenant_id,
                rebuild_result,
                readback,
            } => {
                let value = read_json(&plan)?;
                let provenance_value = genesis_provenance
                    .as_ref()
                    .map(|path| read_json(path.as_path()))
                    .transpose()?;
                let rebuild_value = rebuild_result
                    .as_ref()
                    .map(|path| read_json(path.as_path()))
                    .transpose()?;
                let readback_value = readback
                    .as_ref()
                    .map(|path| read_json(path.as_path()))
                    .transpose()?;
                let result = maintenance::verify_with_genesis_evidence(
                    &value,
                    provenance_value.as_ref(),
                    expected_covenant_id.as_deref(),
                    rebuild_value.as_ref(),
                    readback_value.as_ref(),
                )?;
                emit_result(
                    "ktape release maintenance-verify",
                    None,
                    json!({"status":"PASS", "verification":result, "signing_allowed":false,"broadcast":false}),
                )
            }
            ReleaseAction::MaintenanceView {
                plan,
                state,
                migration_contract,
                history_bundle,
                journal,
            } => {
                let plan_value = read_json(&plan)?;
                let state_value = read_operation_state(&state)?;
                let migration_value = migration_contract
                    .as_ref()
                    .map(|path| read_json(path.as_path()))
                    .transpose()?;
                let history_value = history_bundle
                    .as_ref()
                    .map(|path| read_json(path.as_path()))
                    .transpose()?;
                let journal_value = journal
                    .as_ref()
                    .map(|path| read_json(path.as_path()))
                    .transpose()?;
                let view = maintenance::view(
                    &plan_value,
                    &state_value,
                    migration_value.as_ref(),
                    history_value.as_ref(),
                    journal_value.as_ref(),
                )?;
                let network = view["network"].as_str().map(str::to_owned);
                emit_result("ktape release maintenance-view", network.as_deref(), view)
            }
            ReleaseAction::MaintenanceReceipt {
                plan,
                state,
                migration_contract,
                history_bundle,
                journal,
                captured_at,
                valid_until,
                output,
            } => {
                let plan_value = read_json(&plan)?;
                let state_value = read_operation_state(&state)?;
                let migration_value = migration_contract
                    .as_ref()
                    .map(|path| read_json(path.as_path()))
                    .transpose()?;
                let history_value = history_bundle
                    .as_ref()
                    .map(|path| read_json(path.as_path()))
                    .transpose()?;
                let journal_value = journal
                    .as_ref()
                    .map(|path| read_json(path.as_path()))
                    .transpose()?;
                let view_value = maintenance::view(
                    &plan_value,
                    &state_value,
                    migration_value.as_ref(),
                    history_value.as_ref(),
                    journal_value.as_ref(),
                )?;
                let receipt = maintenance::preflight_receipt(
                    &view_value,
                    &state_value,
                    &captured_at,
                    &valid_until,
                )?;
                let payload = serde_json::to_string_pretty(&receipt)
                    .map_err(|error| format!("MAINTENANCE_RECEIPT_SERIALIZE_ERROR:{error}"))?
                    + "\n";
                fs::write(&output, payload)
                    .map_err(|error| format!("MAINTENANCE_RECEIPT_WRITE_ERROR:{error}"))?;
                emit_result(
                    "ktape release maintenance-receipt",
                    receipt["network"].as_str(),
                    json!({"status":"PASS","receipt":output,"receipt_kind":"PREFLIGHT","plan_hash":receipt["plan_hash"],"evidence_origin":"LOCAL_SIMULATION","signing_allowed":false,"broadcast":false}),
                )
            }
            ReleaseAction::MaintenanceStatus { plan, state } => {
                release_maintenance_status(plan, state)
            }
            ReleaseAction::MaintenanceRecover {
                plan,
                state,
                project_lock_hash,
                now,
            } => release_maintenance_recover(plan, state, project_lock_hash, now),
            ReleaseAction::HistoryVerify {
                bundle,
                expected_network,
                expected_application_id,
                expected_release_id,
                expected_artifact_root,
            } => {
                let value = read_json(&bundle)?;
                let identity_bound = history::verify_with_expected(
                    &value,
                    expected_network.as_deref(),
                    expected_application_id.as_deref(),
                    expected_release_id.as_deref(),
                    expected_artifact_root.as_deref(),
                )?;
                emit_result(
                    "ktape release history-verify",
                    value["network"].as_str(),
                    json!({"status":"PASS","verification_scope":if identity_bound { "LOCAL_HISTORY_LOCATOR_AND_EXPECTED_RELEASE" } else { "LOCAL_HISTORY_LOCATOR_INTEGRITY" },"identity_binding":if identity_bound { "VERIFIED" } else { "UNBOUND" },"bundle_hash":value["bundle_hash"],"bytes_trusted":false,"signing_allowed":false,"broadcast":false}),
                )
            }
            ReleaseAction::Compare {
                old_package,
                new_package,
            } => release_compare(old_package, new_package),
            ReleaseAction::MigrationPlan {
                old_package,
                new_package,
            } => release_migration_plan(old_package, new_package),
        },
        Command::Runtime { action } => match action {
            RuntimeAction::Replay { bundle, runtime } => runtime_replay(bundle, runtime),
            RuntimeAction::DescriptorVerify {
                descriptor,
                package,
            } => runtime_descriptor_verify(descriptor, package),
        },
        Command::Doctor { result } => doctor(result),
        Command::Operation { action } => match action {
            OperationAction::Init {
                operation_id,
                request_id,
                project_lock_hash,
                plan_hash,
                network,
                expiry,
                output,
                evidence_refs,
            } => operation_init(
                operation_id,
                request_id,
                project_lock_hash,
                plan_hash,
                network,
                expiry,
                output,
                evidence_refs,
            ),
            OperationAction::Inspect { state } => operation_inspect(state),
            OperationAction::Recover {
                state,
                operation_id,
                project_lock_hash,
                plan_hash,
                network,
                now,
            } => operation_recovery(
                state,
                operation_id,
                project_lock_hash,
                plan_hash,
                network,
                now,
            ),
            OperationAction::Transition {
                state,
                stage,
                observed_tip,
                evidence_ref,
                next_action,
                write,
            } => operation_transition(state, stage, observed_tip, evidence_ref, next_action, write),
        },
        Command::Evidence { action } => match action {
            EvidenceAction::Verify { receipt } => evidence_verify(receipt),
            EvidenceAction::WriterVerify { input } => evidence_writer_verify(input),
            EvidenceAction::CodecVerify { input } => evidence_codec_verify(input),
            EvidenceAction::StatusVerify { input } => evidence_status_verify(input),
            EvidenceAction::StatusDerive {
                semantic,
                build,
                receipt_status,
                domain,
            } => evidence_status_derive(semantic, build, receipt_status, domain),
            EvidenceAction::Compare { left, right } => evidence_compare(left, right),
            EvidenceAction::RecoveryCheck { receipt } => evidence_recovery_check(receipt),
        },
        Command::Kaspa { action } => match action {
            KaspaAction::VerifySigned {
                unsigned,
                signed,
                signer_policy,
                utxo_context,
            } => kaspa_verify_signed_candidate(unsigned, signed, signer_policy, utxo_context),
        },
        Command::Ai { action } => match action {
            AiAction::Requirements { source, network } => ai_requirements(source, network),
            AiAction::Context { action } => match action {
                AiContextAction::Export { project } => ai_context_export(project),
                AiContextAction::Delivery {
                    intent,
                    policy,
                    provider,
                } => ai_context_delivery(intent, policy, provider),
            },
        },
        Command::Discovery { action } => discovery_command(action),
        Command::Shell { action } => match action {
            ShellAction::Snapshot { document } => shell_snapshot(document),
            ShellAction::Loadout { document } => shell_loadout(document),
            ShellAction::Transition { current, target } => shell_transition(current, target),
        },
    }
}

fn stable_error_code(error: &str) -> String {
    const STABLE_ERROR_TAIL_MAX: usize = 100;
    let prefix = error.split(':').next().unwrap_or_default();
    let mut tail = prefix
        .bytes()
        .filter(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || *byte == b'_')
        .map(char::from)
        .collect::<String>();
    if tail == "SOURCE_FIELD_MISSING" {
        if let Some(field) = error
            .split(':')
            .nth(1)
            .and_then(|value| value.split_whitespace().next())
        {
            let field = field.to_ascii_uppercase();
            if !field.is_empty()
                && field.bytes().all(|byte| {
                    byte.is_ascii_uppercase() || byte.is_ascii_digit() || b"_.-".contains(&byte)
                })
            {
                tail.push('_');
                tail.push_str(&field);
            }
        }
    }
    if tail.is_empty() {
        tail = "CLI_OPERATION_BLOCKED".to_string();
    }
    if tail.len() > STABLE_ERROR_TAIL_MAX {
        tail.truncate(STABLE_ERROR_TAIL_MAX);
    }
    format!("E050_{tail}")
}

fn error_next_action(error: &str) -> String {
    if let Some(field) = error
        .strip_prefix("SOURCE_FIELD_MISSING:")
        .and_then(|value| value.split_whitespace().next())
        .filter(|field| {
            !field.is_empty()
                && field
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
        })
    {
        return format!("add_required_manifest_field:{field}");
    }
    if error.starts_with("PROFILE_PACKAGE_OUTPUT_INSIDE_SOURCE_PACKAGE") {
        "choose a new output directory outside the source Profile package so the verified source remains unchanged".to_string()
    } else if error.starts_with("PROFILE_PACKAGE_FILE_NOT_COMMITTED:")
        && (error.contains("profile-contract.json") || error.contains("effect-manifest.json"))
    {
        "author and review both Contract/Effect sidecars for the exact Profile package, run ktape profile package-compose <source-dir> --contract <profile-contract.json> --effect-manifest <effect-manifest.json> --output <new-package-dir>, then verify the new package; do not infer business effects".to_string()
    } else if error.starts_with("PROFILE_COMPOSITION_DESCRIPTOR_FIELD_MISSING:") {
        "use a Profile Package with complete composition semantics; package verification alone is not composition proof; do not fill missing state, interface, or resource fields with defaults".to_string()
    } else if error.starts_with("PROFILE_COMPOSITION_DRAFT_PACKAGE_SIDECAR_MISMATCH")
        || error.starts_with("PROFILE_COMPOSITION_CONTRACT_HASH_MISMATCH")
        || error.starts_with("PROFILE_COMPOSITION_EFFECT_HASH_MISMATCH")
    {
        "re-verify the package and regenerate the draft sidecars from that exact package; do not edit package-bound hashes by hand".to_string()
    } else if error.starts_with("PROFILE_COMPOSITION_OUTPUT_PARENT_MISSING") {
        "create an existing local output directory or omit --output to review the Recipe in the result".to_string()
    } else if error.starts_with("PROFILE_COMPOSITION_OUTPUT_NOT_REGULAR_FILE") {
        "choose a regular local output file path; symlinks and non-file targets are rejected"
            .to_string()
    } else if error.starts_with("PROFILE_COMPOSITION_") {
        "correct the explicit Composition Draft or supplied package set, then rerun local verification; this result does not execute or publish the application".to_string()
    } else if error.contains("RELEASE_ADJACENT_GAP_REQUIRED")
        || error.contains("release requires at least one adjacent Gap")
    {
        "provide an exact adjacent Gap or use a separately admitted isolated-release Profile"
            .to_string()
    } else if error.contains("LEFT_GAP_NOT_ADJACENT") || error.contains("RIGHT_GAP_NOT_ADJACENT") {
        "query the exact predecessor/successor Gap and rebuild the unsigned plan".to_string()
    } else if error.contains("NETWORK_OBSERVATION_NETWORK_MISMATCH")
        || error.contains("MAINNET_READBACK_MISSING")
    {
        "obtain a fresh observation scoped to the requested network; do not reuse another network receipt".to_string()
    } else if error.contains("PARENT")
        && (error.contains("AUTH") || error.contains("OUTPOINT") || error.contains("WITNESS"))
    {
        "supply the versioned parent covenant inputs and authority witness before planning this operation".to_string()
    } else if error.contains("SOURCE_HASH_INVALID") {
        "recompute_source_hash_from_canonical_manifest".to_string()
    } else if error.contains("SOURCE_SCHEMA_UNSUPPORTED") {
        "convert_manifest_to_supported_0.5.0_schema".to_string()
    } else if error.contains("DEV_WORKFLOW_POLICY_WITHOUT_LOCK")
        || error.contains("LOCKED_BUILD_REQUIRES_NETWORK_POLICY")
    {
        "use the exact NetworkPolicy whose content-addressed policy_id matches developer_lock.network_policy_id and set workflow.network_policy; if the lock contains a placeholder policy ID, rerun ktape init with the same --profile-package or --profile-lock, a validated --network-policy, and a new --output directory; do not edit the lock or invent policy values".to_string()
    } else if error.contains("DEV_WORKFLOW_POLICY_NETWORK_MISMATCH")
        || error.contains("PACKAGE_NETWORK_POLICY_MISMATCH")
    {
        "use the network policy whose network_id and committed lock binding match the workflow network".to_string()
    } else if error.contains("INPUT_MUST_BE_REGULAR_NON_SYMLINK_FILE") {
        "provide_a_regular_non_symlink_input_file".to_string()
    } else if error.contains("SECRET") {
        "remove_secret_material_and_rotate_if_real_secret_was_exposed".to_string()
    } else if error.contains("JSON")
        || error.contains("ENCODING")
        || error.contains("JSONDecodeError")
        || error.contains("Expecting value")
        || error.contains("Extra data")
    {
        "repair_json_syntax_then_validate_again".to_string()
    } else {
        "inspect the stable error code and correct the input before retrying".to_string()
    }
}

fn error_recovery(error: &str, error_code: &str) -> Value {
    json!({
        "cause": error,
        "forbidden_retry": "DO_NOT_RETRY_UNCHANGED_INPUT",
        "evidence_refs": [format!("error-code:{error_code}")],
        "smallest_next_action": error_next_action(error),
    })
}

fn main() -> ExitCode {
    const CLI_STACK_SIZE: usize = 8 * 1024 * 1024;
    match std::thread::Builder::new()
        .name("ktape-cli".into())
        .stack_size(CLI_STACK_SIZE)
        .spawn(run_cli)
    {
        Ok(handle) => match handle.join() {
            Ok(code) => code,
            Err(_) => {
                eprintln!("KTAPE_CLI_THREAD_PANICKED");
                ExitCode::from(101)
            }
        },
        Err(_) => {
            eprintln!("KTAPE_CLI_THREAD_START_FAILED");
            ExitCode::from(101)
        }
    }
}

fn run_cli() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            let args: Vec<_> = std::env::args_os().collect();
            let is_sign = args
                .windows(2)
                .any(|pair| pair[0] == "tn10" && pair[1] == "sign");
            if is_sign
                && !matches!(
                    error.kind(),
                    clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
                )
            {
                // Never echo an accidentally supplied secret in clap's diagnostic.
                eprintln!(
                    "TN10_SIGN_ARGUMENTS_INVALID: use --key-file PATH or --key-stdin; secret values are never accepted as arguments."
                );
                return ExitCode::from(2);
            }
            error.exit();
        }
    };
    match configure_context(&cli).and_then(|_| run(cli)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let error_code = stable_error_code(&error);
            let data =
                json!({"error": error.clone(), "recovery": error_recovery(&error, &error_code)});
            // Keep the operation identity bound to the original failure text;
            // adding recovery guidance must not change idempotency or replay
            // identity for an already observed failed operation.
            let operation_material = json!({"command": "ktape", "network": Value::Null, "data": {"error": error.clone()}});
            let operation_id =
                ktapeout_runtime::digest_json(&operation_material, "KTAPEOUT/0.5.0/OPERATION/V1")
                    .map(|hash| format!("op_{}", &hash[..32]))
                    .unwrap_or_else(|_| "op_00000000000000000000000000000000".to_string());
            let mut result = ktapeout_runtime::tool_result("ktape", "BLOCKED", None, &operation_id, data)
                .unwrap_or_else(|_| json!({"schema": "KTAPEOUT-TOOL-RESULT-V1", "protocol_semver": PROTOCOL, "command": "ktape", "operation_id": operation_id, "status": "BLOCKED", "network": null, "observed_tip": null, "context": null, "error_code": null, "warnings": [], "evidence_refs": [], "unsigned_operations": [], "data": {}}));
            result["error_code"] = Value::String(error_code);
            eprintln!(
                "{}",
                serde_json::to_string(&result).unwrap_or_else(|_| {
                    "{\"schema\":\"KTAPEOUT-TOOL-RESULT-V1\",\"status\":\"BLOCKED\"}".to_string()
                })
            );
            ExitCode::from(2)
        }
    }
}
