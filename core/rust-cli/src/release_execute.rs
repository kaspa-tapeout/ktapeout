//! Local orchestration of an approved TN10 name update. No keys are read here: a
//! pinned native signer receives only a digest and the owner's wallet-file path.
//! A JSON approval is an audit receipt, not a substitute for human authorization.
use crate::release_closure::{canonical_json, sha256};
use crate::release_name_update::{self as update, Pinned};
use crate::release_resolve::{compute_state_spk, target_commitment, StateHelper};
use serde::Deserialize;
use serde_json::{json, Value};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Clone, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Program {
    pub path: PathBuf,
    pub sha256: String,
}

impl Program {
    fn pinned(&self) -> Pinned<'_> {
        Pinned {
            path: &self.path,
            sha256: &self.sha256,
        }
    }
}

#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct RegisteredNodePair {
    pub primary: String,
    pub secondary: String,
}

#[derive(Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub schema: String,
    pub prepared: PathBuf,
    pub authorization: PathBuf,
    pub wallet_file: PathBuf,
    pub escrow_copies: Vec<PathBuf>,
    #[serde(default)]
    pub endpoints: Vec<String>,
    #[serde(default)]
    pub node_ids: Option<RegisteredNodePair>,
    pub signer: Program,
    pub planner: Program,
    pub fetcher: Program,
    pub state_helper: Program,
    pub submitter: Program,
    #[serde(default)]
    pub readback_scanner: Option<Program>,
    #[serde(default)]
    pub readback_verifier: Option<Program>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PinnedInput {
    path: PathBuf,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HostFreeNameUpdateSettings {
    schema: String,
    current_receipt: PinnedInput,
    new_target: Value,
    target_authority_xonly: String,
    node_ids: RegisteredNodePair,
    wallet_file: PathBuf,
    escrow_copies: Vec<PathBuf>,
    signer: Program,
    planner: Program,
    fetcher: Program,
    state_helper: Program,
    submitter: Program,
    readback_scanner: Program,
    readback_verifier: Program,
}

/// Validate the exact native settings shape before accepting it in an adapter registry.
/// Binding to the candidate, dependency pins and paths is checked when deriving the config.
pub fn valid_native_name_update_settings_shape(value: &Value) -> bool {
    serde_json::from_value::<HostFreeNameUpdateSettings>(value.clone()).is_ok_and(|settings| {
        settings.schema == "KTAPEOUT-HOST-FREE-NAME-UPDATE-SETTINGS-V1"
            && settings.new_target.is_object()
    })
}

/// Derive the local native executor configuration from a validated Host-free target.
/// Paths and program hashes are declared once in that target; no endpoint URLs, credentials,
/// candidate identity or planner inputs can be supplied through a second configuration file.
pub fn config_from_host_free_target(target: &Value, workdir: &Path) -> Result<Value, String> {
    crate::release_adapter_contract::validate_host_free_target_values(target)
        .map_err(|_| "RELEASE_HOST_FREE_TARGET_INVALID".to_string())?;
    if !crate::release_adapter_contract::is_host_free_name_controller_target(target) {
        return Err("RELEASE_HOST_FREE_TARGET_INVALID".into());
    }

    let project = target["project"]
        .as_str()
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or("RELEASE_HOST_FREE_TARGET_INVALID")?;
    if !project.is_absolute()
        || project
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err("RELEASE_HOST_FREE_PROJECT_PATH_INVALID".into());
    }
    let settings: HostFreeNameUpdateSettings =
        serde_json::from_value(target["settings"]["native_name_update"].clone())
            .map_err(|_| "RELEASE_HOST_FREE_SETTINGS_INVALID")?;
    require_digest_signer_role(&settings.signer)?;
    if settings.schema != "KTAPEOUT-HOST-FREE-NAME-UPDATE-SETTINGS-V1"
        || settings.escrow_copies.len() < crate::release_escrow::MIN_COPIES
        || !hex64(&settings.target_authority_xonly)
        || settings
            .target_authority_xonly
            .bytes()
            .any(|byte| byte.is_ascii_uppercase())
    {
        return Err("RELEASE_HOST_FREE_SETTINGS_INVALID".into());
    }
    // The workflow plan and executor currently bind owner and target authority to one
    // controller. Reject unsupported combinations before contacting nodes or writing state.
    if target["scope"]["name_controller_public_key"].as_str()
        != Some(settings.target_authority_xonly.as_str())
    {
        return Err("RELEASE_HOST_FREE_TARGET_AUTHORITY_MISMATCH".into());
    }
    crate::release_node_registry::validate_dual_node_ids(
        &settings.node_ids.primary,
        &settings.node_ids.secondary,
    )
    .map_err(|_| "RELEASE_HOST_FREE_NODE_PAIR_INVALID".to_string())?;

    let candidate = target["application_candidate"]
        .as_object()
        .ok_or("RELEASE_HOST_FREE_CANDIDATE_REQUIRED")?;
    let scope = target["scope"]
        .as_object()
        .ok_or("RELEASE_HOST_FREE_TARGET_INVALID")?;
    let new_target = settings
        .new_target
        .as_object()
        .ok_or("RELEASE_HOST_FREE_TARGET_TUPLE_INVALID")?;
    target_commitment(&settings.new_target)
        .map_err(|_| "RELEASE_HOST_FREE_TARGET_TUPLE_INVALID")?;
    if candidate.get("network") != Some(&json!("testnet-10"))
        || candidate.get("application_uri") != scope.get("application_uri")
        || candidate.get("release_id") != new_target.get("release_id")
        || candidate.get("content_root") != new_target.get("artifact_root")
        || !new_target.contains_key("application_id")
        || !new_target.contains_key("deployment_id")
    {
        return Err("RELEASE_HOST_FREE_CANDIDATE_MISMATCH".into());
    }

    let dependencies: Vec<Program> = serde_json::from_value(target["dependencies"].clone())
        .map_err(|_| "RELEASE_HOST_FREE_DEPENDENCIES_INVALID")?;
    let mut dependency_paths = std::collections::HashSet::new();
    for dependency in &dependencies {
        if !hex64(&dependency.sha256) || !dependency_paths.insert(dependency.path.clone()) {
            return Err("RELEASE_HOST_FREE_DEPENDENCIES_INVALID".into());
        }
    }
    let required_pins = [
        &settings.signer,
        &settings.planner,
        &settings.fetcher,
        &settings.state_helper,
        &settings.submitter,
        &settings.readback_scanner,
        &settings.readback_verifier,
    ];
    for pin in required_pins {
        if !hex64(&pin.sha256)
            || !dependencies
                .iter()
                .any(|dependency| dependency.path == pin.path && dependency.sha256 == pin.sha256)
        {
            return Err("RELEASE_HOST_FREE_DEPENDENCY_PIN_MISMATCH".into());
        }
    }
    let receipt_pin = &settings.current_receipt;
    if !hex64(&receipt_pin.sha256)
        || !dependencies.iter().any(|dependency| {
            dependency.path == receipt_pin.path && dependency.sha256 == receipt_pin.sha256
        })
    {
        return Err("RELEASE_HOST_FREE_RECEIPT_PIN_MISMATCH".into());
    }

    let resolve = |path: &Path| -> Result<PathBuf, String> {
        if path.as_os_str().is_empty()
            || path
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
        {
            return Err("RELEASE_HOST_FREE_PATH_INVALID".into());
        }
        Ok(if path.is_absolute() {
            path.to_owned()
        } else {
            project.join(path)
        })
    };
    let escrow_copies = settings
        .escrow_copies
        .iter()
        .map(|path| resolve(path))
        .collect::<Result<Vec<_>, _>>()?;
    let unique_escrow = escrow_copies
        .iter()
        .collect::<std::collections::HashSet<_>>();
    if unique_escrow.len() < crate::release_escrow::MIN_COPIES {
        return Err("RELEASE_HOST_FREE_ESCROW_COPIES_NOT_DISTINCT".into());
    }

    let mut signer = settings.signer;
    let mut planner = settings.planner;
    let mut fetcher = settings.fetcher;
    let mut state_helper = settings.state_helper;
    let mut submitter = settings.submitter;
    let mut readback_scanner = settings.readback_scanner;
    let mut readback_verifier = settings.readback_verifier;
    for program in [
        &mut signer,
        &mut planner,
        &mut fetcher,
        &mut state_helper,
        &mut submitter,
        &mut readback_scanner,
        &mut readback_verifier,
    ] {
        program.path = resolve(&program.path)?;
    }
    let config = Config {
        schema: "KTAPEOUT-NAME-UPDATE-EXECUTION-V2".into(),
        prepared: workdir.join("native-name-update"),
        authorization: workdir.join("native-name-update-authorization.json"),
        wallet_file: resolve(&settings.wallet_file)?,
        escrow_copies,
        endpoints: Vec::new(),
        node_ids: Some(settings.node_ids),
        signer,
        planner,
        fetcher,
        state_helper,
        submitter,
        readback_scanner: Some(readback_scanner),
        readback_verifier: Some(readback_verifier),
    };
    serde_json::to_value(config).map_err(|_| "RELEASE_HOST_FREE_CONFIG_ENCODE_FAILED".into())
}

fn read(path: &Path) -> Result<Value, String> {
    let mut file = fs::File::open(path).map_err(|_| "RELEASE_INPUT_UNAVAILABLE")?;
    use std::io::Read;
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "RELEASE_INPUT_UNAVAILABLE")?;
    if bytes.len() > 16 * 1024 * 1024 {
        return Err("RELEASE_INPUT_TOO_LARGE".into());
    }
    serde_json::from_slice(&bytes).map_err(|_| "RELEASE_INPUT_INVALID".into())
}

fn digest(value: &Value) -> Result<String, String> {
    Ok(sha256(canonical_json(value)?.as_bytes()))
}

fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str, String> {
    v[key]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("RELEASE_FIELD_MISSING:{key}"))
}

fn hex64(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn load(file: &Path) -> Result<Config, String> {
    let mut config: Config =
        serde_json::from_value(read(file)?).map_err(|_| "RELEASE_EXECUTION_CONFIG_INVALID")?;
    match config.schema.as_str() {
        "KTAPEOUT-NAME-UPDATE-EXECUTION-V1" if config.node_ids.is_none() => {
            crate::release_node_registry::validate_dual_endpoints(&config.endpoints)
                .map_err(|_| "RELEASE_TWO_ENDPOINTS_REQUIRED")?;
        }
        "KTAPEOUT-NAME-UPDATE-EXECUTION-V2"
            if config.endpoints.is_empty() && config.node_ids.is_some() =>
        {
            let nodes = config.node_ids.as_ref().expect("guarded above");
            config.endpoints =
                crate::release_node_registry::dual_endpoints(&nodes.primary, &nodes.secondary)?
                    .into();
        }
        _ => return Err("RELEASE_EXECUTION_CONFIG_INVALID".into()),
    }
    let parent = fs::canonicalize(file)
        .map_err(|_| "RELEASE_INPUT_UNAVAILABLE")?
        .parent()
        .ok_or("RELEASE_INPUT_UNAVAILABLE")?
        .to_owned();
    for p in [
        &mut config.prepared,
        &mut config.authorization,
        &mut config.wallet_file,
    ] {
        if p.is_relative() {
            *p = parent.join(&*p);
        }
    }
    for p in &mut config.escrow_copies {
        if p.is_relative() {
            *p = parent.join(&*p);
        }
    }
    for program in [
        &mut config.signer,
        &mut config.planner,
        &mut config.fetcher,
        &mut config.state_helper,
        &mut config.submitter,
    ] {
        if program.path.is_relative() {
            program.path = parent.join(&program.path);
        }
        if !hex64(&program.sha256) {
            return Err("RELEASE_PROGRAM_PIN_INVALID".into());
        }
    }
    Ok(config)
}

/// The approval binds every input to the execution, including helper binaries,
/// wallet path and backup locations. It contains paths and public data, never keys.
pub(crate) fn execution_digest_with_copies(
    file: &Path,
    copies: &[PathBuf],
) -> Result<String, String> {
    let mut config = load(file)?;
    config.escrow_copies = copies.to_vec();
    execution_digest(&config)
}

// Compatibility recovery for the reviewed 2026-10-27 helper CLI accidentally
// installed in the digest-signer role. Its clap parser rejects --wallet-file
// before command dispatch. Do not generalize this proof to an arbitrary failed
// process: a failed signer may already have signed.
pub(crate) const REJECTED_CLI_SIGNER_SHA256: &str =
    "1d82739ae40a7612c606891d2f803b7c4bea2dc1a4e33a13744216b8f7bf9b10";

fn require_digest_signer_role(signer: &Program) -> Result<(), String> {
    if signer.sha256 == REJECTED_CLI_SIGNER_SHA256
        || signer
            .path
            .file_stem()
            .is_some_and(|name| name.to_string_lossy().eq_ignore_ascii_case("ktape"))
    {
        return Err("RELEASE_SIGNER_ROLE_INVALID:expected_digest_signer_not_ktape_cli".into());
    }
    Ok(())
}

pub(crate) fn rejected_cli_signer_lock(file: &Path, original: &Value) -> Result<fs::File, String> {
    let c = load(file)?;
    let request = read(&c.prepared.join("request.json"))?;
    let guard = lock(&c, text(&request["witness_input"], "owner_xonly")?)?;
    let old: Config =
        serde_json::from_value(original.clone()).map_err(|_| "RELEASE_CONFIG_INVALID")?;
    if old.signer.sha256 != REJECTED_CLI_SIGNER_SHA256 {
        return Err("RELEASE_SIGNER_NO_EFFECT_NOT_PROVEN".into());
    }
    update::pinned_bytes(&old.signer.pinned())?;
    for name in [
        "signed.json",
        "signing-complete.json",
        "submission-signed.json",
        "submission-attempt.json",
        "submission-result.json",
        "readback.json",
    ] {
        if c.prepared
            .join(name)
            .try_exists()
            .map_err(|_| "RELEASE_JOURNAL_UNREADABLE")?
        {
            return Err("RELEASE_SIGNER_NO_EFFECT_NOT_PROVEN".into());
        }
    }
    Ok(guard)
}

pub(crate) fn execution_digest_with_signer(file: &Path, signer: Program) -> Result<String, String> {
    let mut config = load(file)?;
    config.signer = signer;
    execution_digest(&config)
}

pub(crate) fn execution_digest(c: &Config) -> Result<String, String> {
    digest(&json!({"prepared":c.prepared,"wallet_file":c.wallet_file,
        "escrow_copies":c.escrow_copies,"endpoints":c.endpoints,
        "signer":[c.signer.path,c.signer.sha256],"planner":[c.planner.path,c.planner.sha256],
        "fetcher":[c.fetcher.path,c.fetcher.sha256],"state_helper":[c.state_helper.path,c.state_helper.sha256],
        "submitter":[c.submitter.path,c.submitter.sha256]}))
}

fn check_approval(
    a: &Value,
    review: &Value,
    request: &Value,
    plan: &Value,
    execution: &str,
    now: i64,
) -> Result<(), String> {
    if a["schema"] != "KTAPEOUT-NAME-UPDATE-AUTHORIZATION-V1"
        || a["status"] != "APPROVED"
        || a["network"] != "testnet-10"
        || a["operation"] != "CHANGE_OWNER_TARGET"
    {
        return Err("RELEASE_SCOPED_AUTHORIZATION_REQUIRED".into());
    }
    for (key, expected) in [
        ("review_sha256", digest(review)?),
        ("request_sha256", digest(request)?),
        ("plan_sha256", digest(plan)?),
        ("execution_sha256", execution.to_owned()),
    ] {
        if text(a, key)? != expected {
            return Err(format!("RELEASE_AUTHORIZATION_MISMATCH:{key}"));
        }
    }
    let parse = |key| -> Result<i64, String> {
        chrono::DateTime::parse_from_rfc3339(text(a, key)?)
            .map(|d| d.timestamp())
            .map_err(|_| "RELEASE_AUTHORIZATION_TIME_INVALID".into())
    };
    let start = parse("not_before_utc")?;
    let end = parse("expires_at_utc")?;
    if start > now || now >= end || end <= start {
        return Err("RELEASE_AUTHORIZATION_EXPIRED_OR_NOT_YET_VALID".into());
    }
    let fee = request["transaction_input"]["fee_sompi"]
        .as_u64()
        .filter(|f| *f > 0)
        .ok_or("RELEASE_FEE_INVALID")?;
    if fee
        > a["cumulative_fee_cap_sompi"]
            .as_u64()
            .ok_or("RELEASE_FEE_CAP_REQUIRED")?
    {
        return Err("RELEASE_FEE_EXCEEDS_AUTHORIZATION".into());
    }
    Ok(())
}

/// Requiring a field before comparing prevents missing == missing acceptance.
/// Derive the low-level name-update approval only from a cryptographically verified release
/// workflow request whose signed action binds every native executor input. This writes an
/// approval receipt with create-new semantics; it never opens a wallet or invokes a helper.
pub fn authorize_from_workflow(
    config_path: &Path,
    adapter_request_path: &Path,
) -> Result<Value, String> {
    let config = load(config_path)?;
    let adapter_request = read(adapter_request_path)?;
    if adapter_request["phase"] != "execute" {
        return Err("RELEASE_WORKFLOW_EXECUTE_PHASE_REQUIRED".into());
    }
    let verified = crate::release_adapter_contract::verify_adapter_authorization(&adapter_request)?;
    let target = &adapter_request["target"];
    let plan = &adapter_request["plan"];
    crate::release_adapter_contract::validate_plan_values(target, plan)?;
    let review = read(&config.prepared.join("review.json"))?;
    let request = read(&config.prepared.join("request.json"))?;
    let native_plan = read(&config.prepared.join("plan.json"))?;
    let signer = text(&request["witness_input"], "owner_xonly")?;
    validate_native_target_scope(target, &review, signer)?;
    check_plan(&review, &request, &native_plan, signer)?;
    let execution_sha256 = execution_digest(&config)?;
    let now = chrono::Utc::now();
    let (approval, action_id, application_uri, release_id, fee_sompi) = derive_workflow_approval(
        target,
        plan,
        &verified,
        &review,
        &request,
        &native_plan,
        signer,
        &execution_sha256,
        now,
    )?;
    if config.authorization.exists() {
        let existing = read(&config.authorization)?;
        check_approval(
            &existing,
            &review,
            &request,
            &native_plan,
            &execution_sha256,
            now.timestamp(),
        )?;
        for field in [
            "schema",
            "status",
            "network",
            "operation",
            "review_sha256",
            "request_sha256",
            "plan_sha256",
            "execution_sha256",
            "signer_public_key",
            "cumulative_fee_cap_sompi",
            "expires_at_utc",
        ] {
            if existing[field] != approval[field] {
                return Err("RELEASE_AUTHORIZATION_CHANGED".into());
            }
        }
    } else {
        create_atomic_new(&config.authorization, &approval)?;
    }
    Ok(json!({
        "schema":"KTAPEOUT-NAME-UPDATE-WORKFLOW-AUTHORIZATION-V1",
        "status":"AUTHORIZED_FROM_VERIFIED_WORKFLOW_SIGNATURE",
        "intent_sha256":verified.intent_sha256,
        "action_id":action_id,
        "application_uri":application_uri,
        "release_id":release_id,
        "fee_sompi":fee_sompi,
        "authorization_file":config.authorization,
        "wallet_opened":false,
        "signing_allowed":false,
        "broadcast":false
    }))
}

fn validate_native_target_scope(
    target: &Value,
    review: &Value,
    signer: &str,
) -> Result<(), String> {
    crate::release_adapter_contract::validate_host_free_target_values(target)
        .map_err(|_| "RELEASE_WORKFLOW_NATIVE_TARGET_INVALID".to_string())?;
    let scope = target["scope"].as_object().ok_or("TARGET_INVALID")?;
    let workflow_authority = scope["workflow_authority_public_key"]
        .as_str()
        .unwrap_or_default();
    let name_controller = scope["name_controller_public_key"]
        .as_str()
        .unwrap_or_default();
    if !crate::release_adapter_contract::is_host_free_name_controller_target(target)
        || !scope["application_uri"]
            .as_str()
            .is_some_and(|uri| uri.starts_with("ktape://testnet-10/app/") && uri == review["name"])
        || name_controller != signer
        || workflow_authority == name_controller
    {
        return Err("RELEASE_WORKFLOW_NATIVE_TARGET_INVALID".into());
    }
    Ok(())
}

// These values are independently verified inputs from distinct workflow artifacts; keeping them
// explicit avoids a wrapper type that would only bundle unrelated references.
#[allow(clippy::too_many_arguments)]
fn derive_workflow_approval(
    target: &Value,
    workflow_plan: &Value,
    verified: &crate::release_adapter_contract::VerifiedAdapterAuthorization,
    review: &Value,
    request: &Value,
    native_plan: &Value,
    signer: &str,
    execution_sha256: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(Value, String, String, String, u64), String> {
    let actions = workflow_plan["actions"]
        .as_array()
        .ok_or("RELEASE_WORKFLOW_PLAN_INVALID")?;
    let mut actions = actions
        .iter()
        .filter(|action| action["kind"] == "name-target-update");
    let action = actions
        .next()
        .ok_or("RELEASE_NAME_UPDATE_ACTION_REQUIRED")?;
    if actions.next().is_some() || action["id"] != "chain-target-update" {
        return Err("RELEASE_NAME_UPDATE_ACTION_AMBIGUOUS".into());
    }
    let binding = action
        .get("name_update_binding")
        .ok_or("RELEASE_NAME_UPDATE_BINDING_REQUIRED")?;
    let fee_sompi = request["transaction_input"]["fee_sompi"]
        .as_u64()
        .filter(|fee| *fee > 0)
        .ok_or("RELEASE_FEE_INVALID")?;
    let release_id = text(workflow_plan, "release_id")?.to_owned();
    let application_uri = text(binding, "application_uri")?.to_owned();
    let action_fee = action["fee_sompi"].as_u64().ok_or("RELEASE_FEE_INVALID")?;
    if verified.max_fee_sompi < action_fee
        || action_fee != fee_sompi
        || binding["schema"] != "KTAPEOUT-NAME-UPDATE-EXECUTION-BINDING-V1"
        || binding["network"] != "testnet-10"
        || application_uri != text(review, "name")?
        || application_uri
            != target["scope"]["application_uri"]
                .as_str()
                .unwrap_or_default()
        || binding["release_id"] != release_id
        || binding["target_commitment"] != text(review, "new_target_commitment")?
        || binding["signer_public_key"] != signer
        || binding["signer_public_key"]
            != target["scope"]["name_controller_public_key"]
                .as_str()
                .unwrap_or_default()
        || binding["review_sha256"] != digest(review)?
        || binding["request_sha256"] != digest(request)?
        || binding["plan_sha256"] != digest(native_plan)?
        || binding["execution_sha256"] != execution_sha256
    {
        return Err("RELEASE_WORKFLOW_NATIVE_BINDING_MISMATCH".into());
    }
    let expires_timestamp = i64::try_from(verified.valid_until)
        .map_err(|_| "RELEASE_WORKFLOW_AUTHORIZATION_TIME_INVALID")?;
    let expires = chrono::DateTime::from_timestamp(expires_timestamp, 0)
        .ok_or("RELEASE_WORKFLOW_AUTHORIZATION_TIME_INVALID")?;
    let approval = json!({
        "schema":"KTAPEOUT-NAME-UPDATE-AUTHORIZATION-V1",
        "status":"APPROVED",
        "network":"testnet-10",
        "operation":"CHANGE_OWNER_TARGET",
        "review_sha256":binding["review_sha256"],
        "request_sha256":binding["request_sha256"],
        "plan_sha256":binding["plan_sha256"],
        "execution_sha256":binding["execution_sha256"],
        "signer_public_key":binding["signer_public_key"],
        "cumulative_fee_cap_sompi":action_fee,
        "not_before_utc":now.to_rfc3339(),
        "expires_at_utc":expires.to_rfc3339()
    });
    check_approval(
        &approval,
        review,
        request,
        native_plan,
        execution_sha256,
        now.timestamp(),
    )?;
    Ok((
        approval,
        action["id"].as_str().unwrap_or_default().to_owned(),
        application_uri,
        release_id,
        fee_sompi,
    ))
}

fn check_plan(review: &Value, request: &Value, plan: &Value, key: &str) -> Result<(), String> {
    if !hex64(key)
        || review["schema"] != "KTAPEOUT-NAME-UPDATE-REVIEW-V1"
        || review["network"] != "testnet-10"
        || request["network"] != "testnet-10"
        || review["operation"] != "CHANGE_OWNER_TARGET"
        || request["operation"] != "CHANGE_OWNER_TARGET"
    {
        return Err("RELEASE_PLAN_INVALID".into());
    }
    let txid = text(review, "unsigned_txid")?;
    if !hex64(txid)
        || plan["safe_transaction"]["id"].as_str() != Some(txid)
        || text(review, "request_digest")? != digest(request)?
        || !hex64(text(review, "scan_start_hash")?)
    {
        return Err("RELEASE_REVIEW_PLAN_MISMATCH".into());
    }
    let witness = &request["witness_input"];
    for field in ["owner_xonly", "next_owner_xonly", "target_authority_xonly"] {
        if text(witness, field)? != key {
            return Err("RELEASE_MULTISIGNER_OR_OWNER_CHANGE_REQUIRES_HOST".into());
        }
    }
    if text(witness, "next_target_commitment")? != target_commitment(&review["new_target"])?
        || witness["next_target_commitment"] != review["new_target_commitment"]
    {
        return Err("RELEASE_TARGET_MISMATCH".into());
    }
    let tx = &request["transaction_input"];
    let fee = tx["fee_sompi"]
        .as_u64()
        .filter(|f| *f > 0)
        .ok_or("RELEASE_FEE_INVALID")?;
    if text(tx, "fee_change_script_public_key")? != format!("000020{key}ac")
        || text(&tx["child_utxo"], "outpoint")? != text(review, "deed_input")?
        || text(&tx["fee_utxo"], "outpoint")? != text(review, "fee_input")?
        || review["fee_sompi"].as_u64() != Some(fee)
    {
        return Err("RELEASE_INPUT_OR_CHANGE_MISMATCH".into());
    }
    let requests = plan["requests"]
        .as_array()
        .filter(|r| r.len() == 2)
        .ok_or("RELEASE_SIGNING_REQUESTS_INVALID")?;
    for (index, r) in requests.iter().enumerate() {
        if text(r, "signer_public_key")? != key
            || r["sighash_type"] != 1
            || r["input_index"].as_u64() != Some(index as u64)
            || r["network"] != "testnet-10"
            || !hex64(text(r, "sighash")?)
            || text(r, "native_plan_hash")? != text(plan, "native_plan_hash")?
        {
            return Err("RELEASE_SIGNING_REQUESTS_INVALID".into());
        }
    }
    Ok(())
}

fn check_copies(
    files: &[PathBuf],
    expected_spk: &str,
    txid: &str,
    name: &str,
) -> Result<(), String> {
    let mut locations = Vec::new();
    for file in files {
        let actual = fs::canonicalize(file).map_err(|_| "ESCROW_COPY_MISSING")?;
        let parent = actual.parent().ok_or("ESCROW_COPY_MISSING")?.to_owned();
        let copy = read(&actual)?;
        if text(&copy, "unsigned_txid")? != txid
            || text(&copy, "name")? != name
            || text(&copy, "script_public_key")? != expected_spk
            || copy["network"] != "testnet-10"
        {
            return Err("ESCROW_NOT_THE_AUTHORIZED_TRANSACTION".into());
        }
        if !locations.contains(&parent) {
            locations.push(parent);
        }
    }
    if locations.len() < 2 {
        return Err("ESCROW_TWO_DISTINCT_LOCATIONS_REQUIRED".into());
    }
    Ok(())
}

fn create(path: &Path, value: &Value) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| "RELEASE_OUTPUT_EXISTS_OR_UNAVAILABLE")?;
    file.write_all(&serde_json::to_vec_pretty(value).map_err(|_| "RELEASE_OUTPUT_INVALID")?)
        .map_err(|_| "RELEASE_OUTPUT_WRITE_FAILED")?;
    file.sync_all()
        .map_err(|_| "RELEASE_OUTPUT_SYNC_FAILED".into())
}

pub(crate) fn create_atomic_new(path: &Path, value: &Value) -> Result<(), String> {
    let parent = path.parent().ok_or("RELEASE_OUTPUT_UNAVAILABLE")?;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "RELEASE_OUTPUT_UNAVAILABLE")?
        .as_nanos();
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("RELEASE_OUTPUT_UNAVAILABLE")?;
    let temporary = parent.join(format!(".{name}.{}.{}.tmp", std::process::id(), nonce));
    let write = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|_| "RELEASE_OUTPUT_EXISTS_OR_UNAVAILABLE")?;
        file.write_all(&serde_json::to_vec_pretty(value).map_err(|_| "RELEASE_OUTPUT_INVALID")?)
            .map_err(|_| "RELEASE_OUTPUT_WRITE_FAILED")?;
        file.sync_all().map_err(|_| "RELEASE_OUTPUT_SYNC_FAILED")?;
        fs::hard_link(&temporary, path).map_err(|_| "RELEASE_OUTPUT_EXISTS_OR_UNAVAILABLE")?;
        fs::remove_file(&temporary).map_err(|_| "RELEASE_OUTPUT_WRITE_FAILED")?;
        Ok(())
    })();
    if write.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    write
}

fn persist_readback_record(path: &Path, record: &Value) -> Result<String, String> {
    if path.exists() {
        let bytes = fs::read(path).map_err(|_| "RELEASE_JOURNAL_UNREADABLE")?;
        let existing: Value =
            serde_json::from_slice(&bytes).map_err(|_| "RELEASE_READBACK_RECORD_CONFLICT")?;
        if existing != *record {
            return Err("RELEASE_READBACK_RECORD_CONFLICT".into());
        }
    } else {
        create_atomic_new(path, record)?;
    }
    let bytes = fs::read(path).map_err(|_| "RELEASE_JOURNAL_UNREADABLE")?;
    Ok(sha256(&bytes))
}

fn confirmed_effect_evidence(txid: &str, record_sha256: &str) -> Value {
    json!({
        "schema":"KTAPEOUT-RELEASE-EFFECT-EVIDENCE-V1",
        "action_id":"chain-target-update",
        "external_effect_id":txid,
        "artifact_sha256":record_sha256,
        "outcome":"CONFIRMED"
    })
}

fn lock(c: &Config, key: &str) -> Result<fs::File, String> {
    let root = std::env::temp_dir().join("ktape-name-update-locks");
    fs::create_dir_all(&root).map_err(|_| "RELEASE_LOCK_UNAVAILABLE")?;
    // All prepared transactions for this controller serialize, including fee inputs.
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(root.join(format!("testnet-10-{key}.lock")))
        .map_err(|_| "RELEASE_LOCK_UNAVAILABLE")?;
    file.try_lock().map_err(|_| "RELEASE_CONTROLLER_LOCKED")?;
    if !c.prepared.is_dir() {
        return Err("RELEASE_PREPARED_UNAVAILABLE".into());
    }
    Ok(file)
}

fn helper(c: &Config) -> StateHelper<'_> {
    StateHelper {
        path: &c.state_helper.path,
        sha256: &c.state_helper.sha256,
    }
}

fn check_observation_tips(raw: &Value, now_ms: i64) -> Result<(), String> {
    let mut scores = Vec::new();
    for node in ["rpcA", "rpcB"] {
        let dag = &raw[node]["dag"];
        let time = dag["pastMedianTime"]
            .as_i64()
            .ok_or("RELEASE_NODE_TIME_MISSING")?;
        if dag["network"] != "testnet-10" || time.abs_diff(now_ms) > 300_000 {
            return Err("RELEASE_NODE_STALE_OR_WRONG_NETWORK".into());
        }
        scores.push(
            dag["virtualDaaScore"]
                .as_u64()
                .ok_or("RELEASE_NODE_SCORE_MISSING")?,
        );
    }
    if scores[0].abs_diff(scores[1]) > 8 {
        return Err("RELEASE_NODE_TIPS_DISAGREE".into());
    }
    Ok(())
}

/// Shared parser for the priority-bucket feerate used by release refresh and TN10 planning.
pub(crate) fn parse_priority_fee_rate(value: &Value) -> Result<f64, String> {
    let estimate = value.get("fee_estimate").unwrap_or(value);
    estimate["estimate"]["priorityBucket"]["feerate"]
        .as_f64()
        .filter(|rate| rate.is_finite() && *rate >= 0.0)
        .ok_or_else(|| "RELEASE_FEE_ESTIMATE_MISSING".to_owned())
}

fn refresh(c: &Config, request: &Value, plan: &Value, phase: &str) -> Result<Value, String> {
    update::pinned_bytes(&c.fetcher.pinned())?;
    let tx = &request["transaction_input"];
    let spks = [
        text(&tx["child_utxo"], "script_public_key")?,
        text(&tx["fee_utxo"], "script_public_key")?,
    ];
    // Read-only failures may be retried without deleting evidence from an earlier attempt.
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "RELEASE_CLOCK_INVALID")?
        .as_nanos();
    let observation_dir = c.prepared.join(format!("{phase}-observe-{stamp}"));
    fs::create_dir(&observation_dir).map_err(|_| "RELEASE_OBSERVATION_UNAVAILABLE")?;
    let input = observation_dir.join("request.json");
    let output = observation_dir.join("observation.json");
    create(
        &input,
        &json!({"endpoints":c.endpoints,"script_public_keys":spks,"include_fee_estimate":true}),
    )?;
    if output.exists() {
        return Err("RELEASE_OBSERVATION_ALREADY_EXISTS".into());
    }
    update::run_env_free(&c.fetcher.path, &[&input, &output], None, 120)?;
    let raw = read(&output)?;
    if raw["schema"] != "KTAPEOUT-RESOLUTION-OBSERVATION-RAW-V1"
        || raw["rpcA"]["endpoint"].as_str() != Some(c.endpoints[0].as_str())
        || raw["rpcB"]["endpoint"].as_str() != Some(c.endpoints[1].as_str())
    {
        return Err("RELEASE_OBSERVATION_INVALID".into());
    }
    check_observation_tips(&raw, chrono::Utc::now().timestamp_millis())?;
    for node in ["rpcA", "rpcB"] {
        let rate =
            parse_priority_fee_rate(&raw[node]).map_err(|_| "RELEASE_FEE_ESTIMATE_MISSING")?;
        if rate > 110.0 {
            return Err("RELEASE_FEE_RATE_CHANGED".into());
        }
    }
    let mut refreshed = request.clone();
    for field in ["child_utxo", "fee_utxo"] {
        let old = &tx[field];
        let spk = text(old, "script_public_key")?;
        let point = text(old, "outpoint")?;
        let entries = update::agreed_entries(&raw, spk)?;
        let entry = entries
            .get(point)
            .ok_or("RELEASE_PREDECESSOR_MISSING_OR_DISAGREES")?;
        let actual = update::native_utxo(point, entry);
        for k in ["amount", "script_public_key", "covenant_id"] {
            if actual.get(k).is_none() || actual[k] != old[k] {
                return Err("RELEASE_PREDECESSOR_CHANGED".into());
            }
        }
        refreshed["transaction_input"][field] = actual;
    }
    update::pinned_bytes(&c.planner.pinned())?;
    let current = update::plan(&c.planner.pinned(), &refreshed)?;
    // Signature requests are also compared, not only the unsigned transaction ID.
    for field in [
        "transaction",
        "safe_transaction",
        "requests",
        "native_plan_hash",
    ] {
        if current.get(field).is_none() || current[field] != plan[field] {
            return Err("RELEASE_REFRESH_CHANGED_REVIEWED_PLAN".into());
        }
    }
    if phase == "submit" {
        let start = text(&raw["rpcA"]["dag"], "sink")?;
        if !hex64(start) {
            return Err("RELEASE_READBACK_START_HASH_INVALID".into());
        }
        let anchor = c.prepared.join("submission-scan-anchor.json");
        // Discovery metadata only: preserve the observation made immediately before
        // submission so an old preparation does not exhaust the bounded block scan.
        let value =
            json!({"start_hash":start,"observation":output,"observation_sha256":digest(&raw)?});
        fs::write(
            &anchor,
            serde_json::to_vec_pretty(&value).map_err(|_| "RELEASE_INPUT_INVALID")?,
        )
        .map_err(|_| "RELEASE_OBSERVATION_UNAVAILABLE")?;
    }
    Ok(refreshed)
}

fn validated(c: &Config, a: &Value) -> Result<(Value, Value, Value), String> {
    let review = read(&c.prepared.join("review.json"))?;
    let request = read(&c.prepared.join("request.json"))?;
    let plan = read(&c.prepared.join("plan.json"))?;
    check_approval(
        a,
        &review,
        &request,
        &plan,
        &execution_digest(c)?,
        chrono::Utc::now().timestamp(),
    )?;
    check_plan(&review, &request, &plan, text(a, "signer_public_key")?)?;
    Ok((review, request, plan))
}

pub fn check(file: &Path) -> Result<Value, String> {
    let c = load(file)?;
    let review = read(&c.prepared.join("review.json"))?;
    let request = read(&c.prepared.join("request.json"))?;
    let plan = read(&c.prepared.join("plan.json"))?;
    let key = text(&request["witness_input"], "owner_xonly")?;
    check_plan(&review, &request, &plan, key)?;
    Ok(
        json!({"status":"REVIEW_REQUIRED","review":review,"authorization_template":{
        "schema":"KTAPEOUT-NAME-UPDATE-AUTHORIZATION-V1","status":"REVIEW_REQUIRED","network":"testnet-10",
        "operation":"CHANGE_OWNER_TARGET","review_sha256":digest(&review)?,"request_sha256":digest(&request)?,
        "plan_sha256":digest(&plan)?,"execution_sha256":execution_digest(&c)?,"signer_public_key":key,
        "cumulative_fee_cap_sompi":null,"not_before_utc":null,"expires_at_utc":null},
        "signing_allowed":false,"broadcast":false}),
    )
}

fn combine_review_preflight(review: &Value, preflight: &Value) -> Result<Value, String> {
    if review["status"] != "REVIEW_REQUIRED"
        || preflight["status"] != "LIVE_PREFLIGHT_VERIFIED"
        || preflight["signing_allowed"] != false
        || preflight["broadcast"] != false
    {
        return Err("RELEASE_REVIEW_PREFLIGHT_INVALID".into());
    }
    let template = &review["authorization_template"];
    let binding = &preflight["input_binding"];
    for key in [
        "review_sha256",
        "request_sha256",
        "plan_sha256",
        "execution_sha256",
    ] {
        if text(template, key)? != text(binding, key)? {
            return Err(format!("RELEASE_REVIEW_PREFLIGHT_INPUT_CHANGED:{key}"));
        }
    }
    Ok(json!({
        "status":"REVIEW_AND_PREFLIGHT_VERIFIED",
        "review":review,
        "live_preflight":preflight,
        "signing_allowed":false,
        "broadcast":false
    }))
}

/// Run the local review and live, read-only preflight in one digest-bound invocation.
pub fn review(file: &Path) -> Result<Value, String> {
    let review = check(file)?;
    let preflight = preflight(file)?;
    combine_review_preflight(&review, &preflight)
}

/// Exercise the exact signing preflight without authorization, key access or writes to escrow.
pub fn preflight(file: &Path) -> Result<Value, String> {
    let c = load(file)?;
    let review = read(&c.prepared.join("review.json"))?;
    let request = read(&c.prepared.join("request.json"))?;
    let plan = read(&c.prepared.join("plan.json"))?;
    let key = text(&request["witness_input"], "owner_xonly")?;
    check_plan(&review, &request, &plan, key)?;
    let _lock = lock(&c, key)?;
    let state = crate::release_escrow::read_state_file(&c.prepared.join("post-state.json"))?;
    if compute_state_spk(&helper(&c), &state)? != text(&review, "successor_script_public_key")? {
        return Err("RELEASE_POST_STATE_MISMATCH".into());
    }
    refresh(&c, &request, &plan, "preflight")?;
    Ok(
        json!({"status":"LIVE_PREFLIGHT_VERIFIED","unsigned_txid":review["unsigned_txid"],
        "fee_sompi":review["fee_sompi"],"input_binding":{
            "review_sha256":digest(&review)?,"request_sha256":digest(&request)?,
            "plan_sha256":digest(&plan)?,"execution_sha256":execution_digest(&c)?},
        "signing_allowed":false,"broadcast":false}),
    )
}

/// Read the executor's durable side-effect markers without acquiring a lock, refreshing RPC
/// state, reading a wallet, or changing files. This reports structural journal state only;
/// it is not proof of chain acceptance and never permits a submission retry. Since the read is
/// intentionally lock-free, callers must treat an inconsistent snapshot as a stop condition.
pub fn inspect(file: &Path) -> Result<Value, String> {
    let c = load(file)?;
    let review = read(&c.prepared.join("review.json"))?;
    let txid = text(&review, "unsigned_txid")?;
    let fee = review["fee_sompi"].as_u64().ok_or("RELEASE_FEE_INVALID")?;
    inspect_journal(&c.prepared, txid, fee)
}

/// Hold the same controller lock as signing while retiring an unattempted execution.
/// The tombstone is durable before the coordinator releases its active-operation owner.
pub(crate) fn abandon_unattempted<F>(
    file: &Path,
    binding: &Value,
    finish: F,
) -> Result<Value, String>
where
    F: FnOnce(Value) -> Result<Value, String>,
{
    let c = load(file)?;
    let request = read(&c.prepared.join("request.json"))?;
    let _lock = lock(&c, text(&request["witness_input"], "owner_xonly")?)?;
    let checked = check(file)?;
    let template = &checked["authorization_template"];
    for field in [
        "review_sha256",
        "request_sha256",
        "plan_sha256",
        "execution_sha256",
        "signer_public_key",
    ] {
        if binding[field].as_str().is_none() || binding[field] != template[field] {
            return Err("RELEASE_WORKFLOW_NATIVE_BINDING_MISMATCH".into());
        }
    }
    if binding["network"] != "testnet-10"
        || binding["application_uri"] != checked["review"]["name"]
        || binding["target_commitment"] != checked["review"]["new_target_commitment"]
    {
        return Err("RELEASE_WORKFLOW_NATIVE_BINDING_MISMATCH".into());
    }
    let inspection = inspect(file)?;
    let marker = c.prepared.join("abandoned-unattempted.json");
    let evidence = json!({
        "schema":"KTAPEOUT-NAME-UPDATE-ABANDONMENT-V1",
        "status":"ABORTED_NO_EFFECT", "binding":binding,
        "txid":inspection["txid"], "fee_sompi":inspection["fee_sompi"],
        "signing_allowed":false, "broadcast":false
    });
    retire_unattempted_journal(&marker, &inspection, &evidence)?;
    finish(inspection)
}

pub(crate) fn unattempted_lock(file: &Path) -> Result<fs::File, String> {
    let c = load(file)?;
    let request = read(&c.prepared.join("request.json"))?;
    let guard = lock(&c, text(&request["witness_input"], "owner_xonly")?)?;
    if inspect(file)?["status"] != "NOT_ATTEMPTED" {
        return Err("RELEASE_ABANDON_NO_EFFECT_NOT_PROVEN".into());
    }
    Ok(guard)
}

fn retire_unattempted_journal(
    marker: &Path,
    inspection: &Value,
    evidence: &Value,
) -> Result<(), String> {
    match inspection["status"].as_str() {
        Some("NOT_ATTEMPTED") => create_atomic_new(marker, evidence)?,
        Some("ABORTED_NO_EFFECT") if read(marker)? == *evidence => {}
        _ => return Err("RELEASE_ABANDON_NO_EFFECT_NOT_PROVEN".into()),
    }
    Ok(())
}

fn optional_record(path: &Path) -> Result<Option<(Value, String)>, String> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("RELEASE_JOURNAL_UNREADABLE".into()),
    };
    let sha256 = sha256(&bytes);
    // A torn result written after a possible external submit is an unknown outcome, not a
    // reason to lose the opportunity to reconcile against independent chain evidence.
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    Ok(Some((value, sha256)))
}

fn inspect_journal(prepared: &Path, txid: &str, fee: u64) -> Result<Value, String> {
    let names = [
        "signing-attempt.json",
        "signed.json",
        "signing-complete.json",
        "submission-signed.json",
        "submission-attempt.json",
        "submission-result.json",
        "readback.json",
    ];
    let mut records = serde_json::Map::new();
    for name in names {
        if let Some((value, digest)) = optional_record(&prepared.join(name))? {
            records.insert(name.to_owned(), json!({"value":value,"sha256":digest}));
        }
    }
    let value = |name: &str| records.get(name).map(|entry| &entry["value"]);
    let attempt = value("signing-attempt.json");
    let signed = value("signed.json");
    let completion = value("signing-complete.json");
    let submission_signed = value("submission-signed.json");
    let submission = value("submission-attempt.json");
    let submission_result = value("submission-result.json");
    let readback = value("readback.json");

    let signing_consistent = signed.zip(completion).is_some_and(|(signed, completion)| {
        digest(signed).ok().as_deref() == completion["signed_sha256"].as_str()
            && completion["txid"].as_str() == Some(txid)
            && signed["txid"].as_str() == Some(txid)
            && signed["native_vm_verified"] == true
            && completion["authorization_sha256"]
                .as_str()
                .is_some_and(hex64)
    });
    let submission_attempt_consistent =
        submission_signed
            .zip(signed)
            .is_some_and(|(snapshot, signed)| {
                snapshot == signed
                    && submission.is_some_and(|attempt| {
                        attempt["txid"].as_str() == Some(txid)
                            && attempt["fee_sompi"].as_u64() == Some(fee)
                    })
            });
    let submission_consistent = submission_attempt_consistent
        && submission_result.is_some_and(|result| {
            result["txid"].as_str() == Some(txid) && result["requires_independent_readback"] == true
        });
    let readback_consistent = submission_signed
        .zip(readback)
        .is_some_and(|(signed, record)| {
            let report = &record["report"];
            let nodes = report["nodes"].as_array();
            record["schema"] == "KTAPEOUT-NAME-UPDATE-READBACK-RECORD-V1"
                && record["txid"].as_str() == Some(txid)
                && record["signed_sha256"].as_str() == digest(signed).ok().as_deref()
                && record["report_sha256"].as_str().is_some_and(hex64)
                && digest(report).ok().as_deref() == record["report_sha256"].as_str()
                && report["schema"] == "KTAPEOUT-READBACK-V1"
                && report["status"]
                    == "TWO_NODE_ACCEPTANCE_EXACT_TRANSACTION_AND_BLOCK_COMMITMENTS_VERIFIED"
                && report["txid"].as_str() == Some(txid)
                && report["finality_proven"] == false
                && report["signing_allowed"] == false
                && report["broadcast"] == false
                && nodes.is_some_and(|nodes| {
                    nodes.len() == 2
                        && nodes[0]["endpoint"] != nodes[1]["endpoint"]
                        && nodes.iter().all(|node| {
                            node["accepted"] == true
                                && node["exact_signed_bytes_match"] == true
                                && node["inclusion"].is_object()
                        })
                })
                && signed["txid"].as_str() == Some(txid)
        });

    let abandoned = prepared
        .join("abandoned-unattempted.json")
        .try_exists()
        .map_err(|_| "RELEASE_JOURNAL_UNREADABLE")?;
    let status = if submission.is_some() {
        if submission_attempt_consistent && readback_consistent {
            "TWO_NODE_READBACK_RECORDED"
        } else if submission_consistent
            && submission_result
                .is_some_and(|result| result["state"] == "RPC_ACKNOWLEDGED_READBACK_REQUIRED")
        {
            "READBACK_REQUIRED"
        } else {
            "SUBMISSION_UNKNOWN"
        }
    } else if signing_consistent && attempt.is_some_and(|attempt| attempt["txid"] == txid) {
        "SIGNED_NOT_SUBMITTED"
    } else if attempt.is_some() || signed.is_some() || completion.is_some() {
        "SIGNING_UNKNOWN"
    } else if submission_signed.is_some() || submission_result.is_some() || readback.is_some() {
        "JOURNAL_INCONSISTENT"
    } else if abandoned {
        "ABORTED_NO_EFFECT"
    } else {
        "NOT_ATTEMPTED"
    };

    let next_action = match status {
        "NOT_ATTEMPTED" => "AWAIT_AUTHORIZATION_THEN_SIGN",
        "SIGNED_NOT_SUBMITTED" => "AWAIT_AUTHORIZATION_THEN_SUBMIT_ONCE",
        "SIGNING_UNKNOWN" => "RECONCILE_SIGNER_OUTCOME",
        "SUBMISSION_UNKNOWN" | "READBACK_REQUIRED" => "INDEPENDENT_CHAIN_READBACK",
        "TWO_NODE_READBACK_RECORDED" => "CONTINUE_RECEIPT_AND_ROUTE_VERIFICATION",
        _ => "STOP_AND_REVIEW",
    };

    let evidence: serde_json::Map<String, Value> = records
        .into_iter()
        .map(|(name, record)| (name, record["sha256"].clone()))
        .collect();
    Ok(json!({
        "schema":"KTAPEOUT-NAME-UPDATE-EXECUTION-STATE-V1",
        "status":status,
        "network":"testnet-10",
        "txid":txid,
        "fee_sompi":fee,
        "read_only":true,
        "journal_assurance":"STRUCTURAL_ONLY",
        "next_action":next_action,
        "signing_retry_allowed":status == "NOT_ATTEMPTED",
        "submission_first_attempt_allowed":status == "SIGNED_NOT_SUBMITTED",
        "submission_retry_allowed":false,
        "independent_readback_required":matches!(status,"READBACK_REQUIRED"|"SUBMISSION_UNKNOWN"),
        "evidence_sha256":evidence
    }))
}

/// Verify a raw two-node scan and bind the resulting report to this executor's single submitted
/// transaction. This is read-only with respect to the network and never signs or submits; the
/// immutable record lets `inspect` distinguish an unknown submission from a verified readback.
pub fn readback(
    file: &Path,
    scan_file: &Path,
    verifier: &Path,
    verifier_sha256: &str,
) -> Result<Value, String> {
    let c = load(file)?;
    let request = read(&c.prepared.join("request.json"))?;
    let _lock = lock(&c, text(&request["witness_input"], "owner_xonly")?)?;
    let review = read(&c.prepared.join("review.json"))?;
    let plan = read(&c.prepared.join("plan.json"))?;
    let txid = text(&review, "unsigned_txid")?;
    let signed = read(&c.prepared.join("submission-signed.json"))?;
    let journal_state = inspect(file)?;
    if !matches!(
        journal_state["status"].as_str(),
        Some("SUBMISSION_UNKNOWN" | "READBACK_REQUIRED")
    ) || signed["txid"].as_str() != Some(txid)
        || !c.prepared.join("submission-attempt.json").is_file()
    {
        return Err("RELEASE_READBACK_NOT_READY_OR_ALREADY_RECORDED".into());
    }
    let transaction = signed
        .get("transaction")
        .cloned()
        .ok_or("RELEASE_SIGNED_RECORD_MISMATCH")?;
    let scan = read(scan_file)?;
    let projected_mass = plan["mass_projection"]["normalized_mass"]
        .as_u64()
        .ok_or("RELEASE_READBACK_PROJECTION_MISSING")?;
    let report = crate::release_readback::verify(
        &scan,
        txid,
        &transaction,
        Some(projected_mass),
        verifier,
        verifier_sha256,
    )?;
    let record = json!({
        "schema":"KTAPEOUT-NAME-UPDATE-READBACK-RECORD-V1",
        "txid":txid,
        "signed_sha256":digest(&signed)?,
        "report_sha256":digest(&report)?,
        "report":report
    });
    let record_path = c.prepared.join("readback.json");
    let record_sha256 = persist_readback_record(&record_path, &record)?;
    let status = inspect(file)?;
    if status["status"] != "TWO_NODE_READBACK_RECORDED" {
        return Err("RELEASE_READBACK_RECORD_INCONSISTENT".into());
    }
    Ok(json!({
        "status":"TWO_NODE_READBACK_RECORDED",
        "txid":txid,
        "record":record_path,
        "record_sha256":record_sha256,
        "effect_evidence":confirmed_effect_evidence(txid, &record_sha256),
        "next_action":"CONTINUE_RECEIPT_AND_ROUTE_VERIFICATION",
        "signing_allowed":false,
        "broadcast":false
    }))
}

pub fn sign(file: &Path) -> Result<Value, String> {
    let c = load(file)?;
    require_digest_signer_role(&c.signer)?;
    let a = read(&c.authorization)?;
    let (review, request, plan) = validated(&c, &a)?;
    let _lock = lock(&c, text(&a, "signer_public_key")?)?;
    if c.prepared
        .join("abandoned-unattempted.json")
        .try_exists()
        .map_err(|_| "RELEASE_JOURNAL_UNREADABLE")?
    {
        return Err("RELEASE_EXECUTION_ABANDONED".into());
    }
    if c.prepared.join("signing-attempt.json").exists() || c.prepared.join("signed.json").exists() {
        return Err("RELEASE_SIGNING_ALREADY_ATTEMPTED_RECONCILE".into());
    }
    let spk = text(&review, "successor_script_public_key")?;
    let txid = text(&review, "unsigned_txid")?;
    let state = crate::release_escrow::read_state_file(&c.prepared.join("post-state.json"))?;
    if compute_state_spk(&helper(&c), &state)? != spk {
        return Err("RELEASE_POST_STATE_MISMATCH".into());
    }
    let record = crate::release_escrow::record(&state, spk, txid, text(&review, "name")?)?;
    // Only explicitly approved file destinations are used; never overwrite a backup.
    for path in &c.escrow_copies {
        if path.exists() {
            if read(path)? != record {
                return Err("RELEASE_ESCROW_EXISTING_RECORD_MISMATCH".into());
            }
        } else {
            create(path, &record)?;
        }
    }
    check_copies(&c.escrow_copies, spk, txid, text(&review, "name")?)?;
    crate::release_escrow::require_escrow(&c.escrow_copies, &helper(&c), spk)?;
    let refreshed = refresh(&c, &request, &plan, "sign")?;
    update::pinned_bytes(&c.signer.pinned())?;
    create(
        &c.prepared.join("signing-attempt.json"),
        &json!({"state":"SIGNING_ATTEMPT_RECORDED","txid":txid,"authorization_sha256":digest(&a)?}),
    )?;
    let mut packets = Vec::new();
    for req in plan["requests"]
        .as_array()
        .ok_or("RELEASE_SIGNING_REQUESTS_INVALID")?
    {
        // Re-read the approval before each signer invocation, including its expiry.
        let current = read(&c.authorization)?;
        if current != a {
            return Err("RELEASE_AUTHORIZATION_CHANGED".into());
        }
        validated(&c, &current)?;
        update::pinned_bytes(&c.signer.pinned())?;
        let input = json!({"digest":req["sighash"]}).to_string();
        let bytes = update::run_env_free(
            &c.signer.path,
            &[Path::new("--wallet-file"), &c.wallet_file],
            Some(&input),
            15,
        )?;
        let sig = std::str::from_utf8(&bytes)
            .map_err(|_| "RELEASE_SIGNATURE_INVALID")?
            .trim();
        if sig.len() != 128 || !sig.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("RELEASE_SIGNATURE_INVALID".into());
        }
        packets.push(json!({"native_plan_hash":req["native_plan_hash"],"input_index":req["input_index"],
            "signer_public_key":req["signer_public_key"],"sighash_type":req["sighash_type"],"signature":sig}));
    }
    update::pinned_bytes(&c.planner.pinned())?;
    let merge =
        json!({"plan":{"action":"profile_state_transition","request":refreshed},"packets":packets});
    let bytes = update::run_env_free(
        &c.planner.path,
        &[Path::new("--merge-signatures")],
        Some(&merge.to_string()),
        120,
    )?;
    let signed: Value =
        serde_json::from_slice(&bytes).map_err(|_| "RELEASE_SIGNED_RESULT_INVALID")?;
    if signed["native_vm_verified"] != true
        || signed["txid"].as_str() != Some(txid)
        || !signed["transaction"].is_object()
    {
        return Err("RELEASE_NATIVE_VM_VERIFICATION_FAILED".into());
    }
    create(&c.prepared.join("signed.json"), &signed)?;
    create(
        &c.prepared.join("signing-complete.json"),
        &json!({"state":"SIGNED_AND_NATIVE_VM_VERIFIED","txid":txid,
        "signed_sha256":digest(&signed)?,"authorization_sha256":digest(&a)?,"merge":merge}),
    )?;
    Ok(json!({"status":"SIGNED_AND_NATIVE_VM_VERIFIED","txid":txid,"broadcast":false}))
}

/// Persist before calling the broadcaster. An existing/torn marker always blocks
/// another call, including after a crash or an acknowledgement whose body was lost.
fn submit_once<T>(
    journal: &Path,
    txid: &str,
    fee: u64,
    action: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    create(
        journal,
        &json!({"state":"SUBMISSION_ATTEMPT_RECORDED","txid":txid,"fee_sompi":fee,
        "started_at":chrono::Utc::now().to_rfc3339()}),
    )?;
    action()
}

pub fn submit(file: &Path) -> Result<Value, String> {
    let c = load(file)?;
    let a = read(&c.authorization)?;
    let (review, request, plan) = validated(&c, &a)?;
    let _lock = lock(&c, text(&a, "signer_public_key")?)?;
    if c.prepared
        .join("abandoned-unattempted.json")
        .try_exists()
        .map_err(|_| "RELEASE_JOURNAL_UNREADABLE")?
    {
        return Err("RELEASE_EXECUTION_ABANDONED".into());
    }
    let txid = text(&review, "unsigned_txid")?;
    let journal = c.prepared.join("submission-attempt.json");
    if journal.exists() {
        return Err("RELEASE_SUBMISSION_ALREADY_ATTEMPTED_RECONCILE".into());
    }
    let signed = read(&c.prepared.join("signed.json"))?;
    let completion = read(&c.prepared.join("signing-complete.json"))?;
    if completion["signed_sha256"].as_str() != Some(digest(&signed)?.as_str())
        || completion["authorization_sha256"].as_str() != Some(digest(&a)?.as_str())
        || signed["txid"].as_str() != Some(txid)
        || signed["native_vm_verified"] != true
    {
        return Err("RELEASE_SIGNED_RECORD_MISMATCH".into());
    }
    check_copies(
        &c.escrow_copies,
        text(&review, "successor_script_public_key")?,
        txid,
        text(&review, "name")?,
    )?;
    crate::release_escrow::require_escrow(
        &c.escrow_copies,
        &helper(&c),
        text(&review, "successor_script_public_key")?,
    )?;
    refresh(&c, &request, &plan, "submit")?;
    // Do not trust a boolean on disk: re-merge the signatures through the native VM.
    update::pinned_bytes(&c.planner.pinned())?;
    let bytes = update::run_env_free(
        &c.planner.path,
        &[Path::new("--merge-signatures")],
        Some(&completion["merge"].to_string()),
        120,
    )?;
    let verified: Value =
        serde_json::from_slice(&bytes).map_err(|_| "RELEASE_SIGNED_RESULT_INVALID")?;
    if verified != signed {
        return Err("RELEASE_SIGNED_RECORD_MISMATCH".into());
    }
    let current_authorization = read(&c.authorization)?;
    if current_authorization != a {
        return Err("RELEASE_AUTHORIZATION_CHANGED".into());
    }
    validated(&c, &current_authorization)?;
    update::pinned_bytes(&c.submitter.pinned())?;
    let fee = review["fee_sompi"].as_u64().ok_or("RELEASE_FEE_INVALID")?;
    let snapshot = c.prepared.join("submission-signed.json");
    create(&snapshot, &verified)?;
    let result = submit_once(&journal, txid, fee, || {
        update::run_env_free(
            &c.submitter.path,
            &[&snapshot, Path::new(txid), Path::new(&c.endpoints[0])],
            None,
            90,
        )
    });
    // A native acknowledgement is not independent chain acceptance. Always read back.
    let status = if result.is_ok() {
        "RPC_ACKNOWLEDGED_READBACK_REQUIRED"
    } else {
        "OUTCOME_UNKNOWN_RECONCILE"
    };
    create(
        &c.prepared.join("submission-result.json"),
        &json!({"state":status,"txid":txid,"requires_independent_readback":true}),
    )?;
    Ok(json!({"status":status,"txid":txid,"readback_required":true,"retry_allowed":false}))
}
