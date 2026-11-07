//! Registry-independent verification shared by the release coordinator and native adapters.
//!
//! Keep this module free of `release_workflow` imports: an adapter binary pinned by the static
//! registry must be able to verify the coordinator's signed intent without embedding that
//! registry (which would create a digest cycle).
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn err(code: &str) -> String {
    format!("RELEASE_{code}")
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn value_hash<T: Serialize>(value: &T) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| hash(&bytes))
        .map_err(|_| err("JSON_INVALID"))
}
fn valid_hash(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_lower_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn contains_host_or_secret_key(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, nested)| {
            let normalized = key.to_ascii_lowercase().replace(['-', '_'], "");
            [
                "origin",
                "remoteroot",
                "sshhost",
                "secret",
                "privatekey",
                "mnemonic",
                "recoverycode",
                "seedphrase",
            ]
            .iter()
            .any(|forbidden| normalized.contains(forbidden))
                || contains_host_or_secret_key(nested)
        }),
        Value::Array(items) => items.iter().any(contains_host_or_secret_key),
        _ => false,
    }
}

/// Validate the shared, Host-free target scope before a coordinator or adapter acts on it.
/// V4 combines publisher identity and permissions with a separate TN10 name controller;
/// unknown fields fail closed so Host credentials cannot cross the settings boundary.
pub fn validate_host_free_target_values(target: &Value) -> Result<(), String> {
    if contains_host_or_secret_key(target) {
        return Err(err("TARGET_INVALID"));
    }
    let target: Target =
        serde_json::from_value(target.clone()).map_err(|_| err("TARGET_INVALID"))?;
    let scope = target
        .scope
        .as_object()
        .ok_or_else(|| err("TARGET_INVALID"))?;
    let mut allowed = std::collections::HashSet::from([
        "network",
        "application_uri",
        "wallet_address",
        "workflow_authority_public_key",
        "permissions",
        "runtime_smoke_test",
    ]);
    match (target.schema.as_str(), target.execution_line.as_str()) {
        ("KTAPEOUT-RELEASE-TARGET-V2", "publisher") => {
            allowed.extend(["publisher_id", "publisher_key_id"]);
        }
        ("KTAPEOUT-RELEASE-TARGET-V3", "name-controller") => {
            allowed.insert("name_controller_public_key");
        }
        ("KTAPEOUT-RELEASE-TARGET-V4", "name-controller") => {
            allowed.extend([
                "publisher_id",
                "publisher_key_id",
                "name_controller_public_key",
            ]);
        }
        _ => return Err(err("TARGET_INVALID")),
    }
    let application_uri = scope
        .get("application_uri")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let authority = scope["workflow_authority_public_key"]
        .as_str()
        .unwrap_or_default();
    if scope.keys().any(|key| !allowed.contains(key.as_str()))
        || scope.get("network").and_then(Value::as_str) != Some("testnet-10")
        || !application_uri.starts_with("ktape://testnet-10/app/")
        || application_uri.len() <= "ktape://testnet-10/app/".len()
        || scope
            .get("wallet_address")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || !valid_lower_hash(authority)
        || scope
            .get("permissions")
            .is_none_or(|value| !value.is_array())
        || scope
            .get("runtime_smoke_test")
            .is_some_and(|value| !value.is_boolean())
        || !(60..=86400).contains(&target.authorization_ttl_seconds)
        || !(1..=1800).contains(&target.timeout_seconds)
        || target.max_fee_sompi == 0
    {
        return Err(err("TARGET_INVALID"));
    }
    match target.execution_line.as_str() {
        "publisher"
            if scope
                .get("publisher_id")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
                || scope
                    .get("publisher_key_id")
                    .and_then(Value::as_str)
                    .is_none_or(str::is_empty) =>
        {
            Err(err("TARGET_INVALID"))
        }
        "name-controller" if target.schema == "KTAPEOUT-RELEASE-TARGET-V3" => {
            let controller = scope
                .get("name_controller_public_key")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if !valid_lower_hash(controller)
                || controller == authority
                || !scope
                    .get("permissions")
                    .and_then(Value::as_array)
                    .is_some_and(Vec::is_empty)
            {
                return Err(err("TARGET_INVALID"));
            }
            Ok(())
        }
        "name-controller" => {
            let controller = scope
                .get("name_controller_public_key")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if scope
                .get("publisher_id")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
                || scope
                    .get("publisher_key_id")
                    .and_then(Value::as_str)
                    .is_none_or(str::is_empty)
                || !valid_lower_hash(controller)
                || controller == authority
                || !scope
                    .get("permissions")
                    .and_then(Value::as_array)
                    .is_some_and(|permissions| permissions.iter().all(Value::is_string))
            {
                return Err(err("TARGET_INVALID"));
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

pub fn is_host_free_name_controller_target(target: &Value) -> bool {
    matches!(
        (target["schema"].as_str(), target["execution_line"].as_str()),
        (Some("KTAPEOUT-RELEASE-TARGET-V3"), Some("name-controller"))
            | (Some("KTAPEOUT-RELEASE-TARGET-V4"), Some("name-controller"))
    )
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
struct Pin {
    path: PathBuf,
    sha256: String,
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
struct ApplicationCandidateBinding {
    snapshot_directory: PathBuf,
    snapshot_digest: String,
    profile_digest: String,
    profile_scope: Value,
    adapter_id: String,
    application_uri: String,
    network: String,
    release_id: String,
    content_root: String,
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
struct Target {
    schema: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    execution_line: String,
    project: PathBuf,
    scope: Value,
    settings: Value,
    max_fee_sompi: u64,
    authorization_ttl_seconds: u64,
    adapter: Pin,
    arguments: Vec<String>,
    dependencies: Vec<Pin>,
    timeout_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    application_candidate: Option<ApplicationCandidateBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    release_adapter_id: Option<String>,
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
struct NameUpdateExecutionBinding {
    schema: String,
    network: String,
    application_uri: String,
    release_id: String,
    target_commitment: String,
    signer_public_key: String,
    review_sha256: String,
    request_sha256: String,
    plan_sha256: String,
    execution_sha256: String,
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
struct Action {
    id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kind: Option<String>,
    fee_sompi: u64,
    effect: bool,
    #[serde(default)]
    retry_safe: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    name_update_binding: Option<NameUpdateExecutionBinding>,
}

#[derive(Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
struct Plan {
    schema: String,
    scope: Value,
    release_id: String,
    source_sha256: String,
    unchanged: bool,
    actions: Vec<Action>,
    artifacts: Vec<Pin>,
    summary: Value,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAdapterAuthorization {
    pub intent_sha256: String,
    pub plan_sha256: String,
    pub max_fee_sompi: u64,
    pub valid_until: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdapterRequest {
    schema: String,
    phase: String,
    target: Value,
    workdir: PathBuf,
    intent_sha256: Option<String>,
    valid_until: Option<u64>,
    plan: Option<Value>,
    action: Option<Value>,
    pending: bool,
    receipts: Option<Vec<Value>>,
    authorization: Option<Value>,
}

/// Validate the exact request envelope shared by the coordinator and pinned native adapters.
/// This checks structure and bindings only; each phase still runs its own operation-specific
/// preflight and effect evidence checks.
pub fn validate_adapter_request(request: &Value) -> Result<(), String> {
    let envelope: AdapterRequest =
        serde_json::from_value(request.clone()).map_err(|_| err("ADAPTER_REQUEST_INVALID"))?;
    if envelope.schema != "KTAPEOUT-RELEASE-ADAPTER-REQUEST-V2"
        || !envelope.workdir.is_absolute()
        || !matches!(
            envelope.phase.as_str(),
            "prepare" | "preflight" | "authorize" | "execute" | "reconcile"
        )
    {
        return Err(err("ADAPTER_REQUEST_INVALID"));
    }
    validate_host_free_target_values(&envelope.target)?;

    if envelope.phase == "prepare" {
        if envelope.intent_sha256.is_some()
            || envelope.valid_until.is_some()
            || envelope.plan.is_some()
            || envelope.action.is_some()
            || envelope.pending
            || envelope.receipts.is_some()
            || envelope.authorization.is_some()
        {
            return Err(err("ADAPTER_REQUEST_STATE_INVALID"));
        }
        return Ok(());
    }

    let plan = envelope
        .plan
        .as_ref()
        .ok_or_else(|| err("ADAPTER_REQUEST_STATE_INVALID"))?;
    let intent_sha256 = envelope
        .intent_sha256
        .as_deref()
        .filter(|hash| valid_lower_hash(hash))
        .ok_or_else(|| err("ADAPTER_REQUEST_STATE_INVALID"))?;
    let valid_until = envelope
        .valid_until
        .ok_or_else(|| err("ADAPTER_REQUEST_STATE_INVALID"))?;
    validate_plan_values(&envelope.target, plan)?;
    if value_hash(&json!({
        "target": envelope.target,
        "plan": plan,
        "valid_until": valid_until
    }))? != intent_sha256
    {
        return Err(err("ADAPTER_REQUEST_INTENT_MISMATCH"));
    }

    match (&envelope.action, envelope.phase.as_str()) {
        (Some(action), "execute" | "reconcile") => {
            let plan: Plan = serde_json::from_value(plan.clone())
                .map_err(|_| err("ADAPTER_REQUEST_STATE_INVALID"))?;
            if !plan
                .actions
                .iter()
                .any(|candidate| serde_json::to_value(candidate).ok().as_ref() == Some(action))
            {
                return Err(err("ADAPTER_REQUEST_ACTION_MISMATCH"));
            }
            if envelope.phase == "execute" && envelope.pending
                || envelope.phase == "reconcile" && !envelope.pending
            {
                return Err(err("ADAPTER_REQUEST_PENDING_MISMATCH"));
            }
        }
        (None, "execute" | "reconcile") => {
            return Err(err("ADAPTER_REQUEST_ACTION_REQUIRED"));
        }
        _ => {}
    }

    match envelope.phase.as_str() {
        "execute" => {
            verify_adapter_authorization(request)?;
        }
        "reconcile" => {
            verify_adapter_reconciliation_authorization(request)?;
        }
        _ => {}
    }
    Ok(())
}

fn check_pin(pin: &Pin) -> Result<(), String> {
    let meta = fs::symlink_metadata(&pin.path).map_err(|_| err("PIN_UNAVAILABLE"))?;
    if !pin.path.is_absolute() || !meta.is_file() || meta.file_type().is_symlink() {
        return Err(err("PIN_INVALID"));
    }
    let mut file = fs::File::open(&pin.path).map_err(|_| err("PIN_UNAVAILABLE"))?;
    let mut digest = Sha256::new();
    let mut buffer = [0; 65_536];
    loop {
        let count = file.read(&mut buffer).map_err(|_| err("PIN_READ_FAILED"))?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    if hex::encode(digest.finalize()) != pin.sha256 {
        return Err(err("PIN_CHANGED"));
    }
    Ok(())
}

fn check_name_update_binding(target: &Target, plan: &Plan, action: &Action) -> Result<(), String> {
    let Some(binding) = action.name_update_binding.as_ref() else {
        return if action.kind.as_deref() == Some("name-target-update") {
            Err(err("NAME_UPDATE_BINDING_REQUIRED"))
        } else {
            Ok(())
        };
    };
    let signer = target.scope["name_controller_public_key"]
        .as_str()
        .unwrap_or_default();
    if action.kind.as_deref() != Some("name-target-update")
        || binding.schema != "KTAPEOUT-NAME-UPDATE-EXECUTION-BINDING-V1"
        || !action.effect
        || action.retry_safe
        || action.fee_sompi == 0
        || binding.network != "testnet-10"
        || target.execution_line != "name-controller"
        || binding.network != plan.scope["network"].as_str().unwrap_or_default()
        || binding.application_uri != plan.scope["application_uri"].as_str().unwrap_or_default()
        || binding.release_id != plan.release_id
        || binding.signer_public_key != signer
        || !valid_hash(&binding.target_commitment)
        || !valid_hash(signer)
        || !valid_hash(&binding.review_sha256)
        || !valid_hash(&binding.request_sha256)
        || !valid_hash(&binding.plan_sha256)
        || !valid_hash(&binding.execution_sha256)
    {
        return Err(err("NAME_UPDATE_BINDING_INVALID"));
    }
    Ok(())
}

pub fn validate_name_update_binding_values(
    target: &Value,
    plan: &Value,
    action: &Value,
) -> Result<(), String> {
    let target: Target =
        serde_json::from_value(target.clone()).map_err(|_| err("TARGET_INVALID"))?;
    let plan: Plan = serde_json::from_value(plan.clone()).map_err(|_| err("PLAN_SCOPE_INVALID"))?;
    let action: Action =
        serde_json::from_value(action.clone()).map_err(|_| err("ACTION_INVALID"))?;
    check_name_update_binding(&target, &plan, &action)
}

fn check_plan(target: &Target, plan: &Plan) -> Result<(), String> {
    let v1 = plan.schema == "KTAPEOUT-RELEASE-PLAN-V1";
    let v2 = plan.schema == "KTAPEOUT-RELEASE-PLAN-V2";
    if target
        .application_candidate
        .as_ref()
        .is_some_and(|candidate| candidate.release_id != plan.release_id)
    {
        return Err(err("APPLICATION_CANDIDATE_RELEASE_MISMATCH"));
    }
    if (!v1 && !v2)
        || plan.scope != target.scope
        || !valid_hash(&plan.release_id)
        || !valid_hash(&plan.source_sha256)
        || plan.actions.len() > 64
        || plan.artifacts.len() > 512
        || plan.artifacts.is_empty()
        || (plan.unchanged && !plan.actions.is_empty())
        || (!plan.unchanged && plan.actions.is_empty())
    {
        return Err(err("PLAN_SCOPE_INVALID"));
    }
    let mut ids = std::collections::HashSet::new();
    let mut total = 0u64;
    for action in &plan.actions {
        let action_kind_valid = matches!(
            action.kind.as_deref(),
            Some(
                "host-stage"
                    | "host-activate"
                    | "host-record-publish"
                    | "content-sign"
                    | "deed-sign"
                    | "publisher-sign"
                    | "chain-broadcast"
                    | "name-target-update"
                    | "chain-readback"
                    | "release-verify"
                    | "desktop-acceptance"
                    | "kasware-operation"
                    | "android-acceptance",
            )
        );
        if action.id.is_empty()
            || !action
                .id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || !ids.insert(&action.id)
            || (!action.effect && action.fee_sompi != 0)
            || (v1 && action.kind.is_some())
            || (v2 && !action_kind_valid)
        {
            return Err(err(if v2 {
                "ACTION_KIND_INVALID"
            } else {
                "ACTION_INVALID"
            }));
        }
        check_name_update_binding(target, plan, action)?;
        total = total
            .checked_add(action.fee_sompi)
            .ok_or_else(|| err("BUDGET_OVERFLOW"))?;
    }
    if total > target.max_fee_sompi {
        return Err(err("BUDGET_EXCEEDED"));
    }
    for artifact in &plan.artifacts {
        check_pin(artifact)?;
    }
    Ok(())
}

/// Validate coordinator plan data at the adapter boundary. Kept public so the coordinator can
/// delegate to this same implementation instead of maintaining a second plan validator.
pub fn validate_plan_values(target: &Value, plan: &Value) -> Result<(), String> {
    let target: Target =
        serde_json::from_value(target.clone()).map_err(|_| err("TARGET_INVALID"))?;
    let plan: Plan = serde_json::from_value(plan.clone()).map_err(|_| err("PLAN_SCOPE_INVALID"))?;
    check_plan(&target, &plan)
}

/// Verify the signed intent at an adapter boundary without linking the coordinator/registry.
pub fn verify_adapter_authorization(
    request: &Value,
) -> Result<VerifiedAdapterAuthorization, String> {
    verify_adapter_authorization_inner(request, true)
}

/// Reconciliation is read-only and must remain available after an authorization expires,
/// so an uncertain prior submission can be resolved without permitting a new effect.
pub fn verify_adapter_reconciliation_authorization(
    request: &Value,
) -> Result<VerifiedAdapterAuthorization, String> {
    if request["phase"] != "reconcile" {
        return Err(err("ADAPTER_AUTHORIZATION_REQUEST_INVALID"));
    }
    verify_adapter_authorization_inner(request, false)
}

fn verify_adapter_authorization_inner(
    request: &Value,
    enforce_expiry: bool,
) -> Result<VerifiedAdapterAuthorization, String> {
    if request["schema"] != "KTAPEOUT-RELEASE-ADAPTER-REQUEST-V2"
        || request["phase"] != "execute" && request["phase"] != "reconcile"
    {
        return Err(err("ADAPTER_AUTHORIZATION_REQUEST_INVALID"));
    }
    let target: Target = serde_json::from_value(request["target"].clone())
        .map_err(|_| err("ADAPTER_AUTHORIZATION_REQUEST_INVALID"))?;
    let plan: Plan = serde_json::from_value(request["plan"].clone())
        .map_err(|_| err("ADAPTER_AUTHORIZATION_REQUEST_INVALID"))?;
    let authorization = &request["authorization"];
    let intent_sha256 = authorization["intent_sha256"]
        .as_str()
        .ok_or_else(|| err("AUTHORIZATION_INVALID"))?;
    let signature = authorization["signature"]
        .as_str()
        .ok_or_else(|| err("AUTHORIZATION_INVALID"))?;
    let valid_until = authorization["valid_until"]
        .as_u64()
        .ok_or_else(|| err("AUTHORIZATION_INVALID"))?;
    let plan_sha256 = value_hash(&plan)?;
    if authorization["plan_sha256"].as_str() != Some(plan_sha256.as_str())
        || authorization["max_fee_sompi"].as_u64() != Some(target.max_fee_sompi)
        || enforce_expiry && now() > valid_until
        || plan
            .actions
            .iter()
            .try_fold(0u64, |sum, action| sum.checked_add(action.fee_sompi))
            .is_none_or(|total| total > target.max_fee_sompi)
    {
        return Err(err("AUTHORIZATION_SCOPE_MISMATCH"));
    }
    let expected_intent =
        value_hash(&json!({"target":target,"plan":plan,"valid_until":valid_until}))?;
    if intent_sha256 != expected_intent {
        return Err(err("AUTHORIZATION_SCOPE_MISMATCH"));
    }
    let public = hex::decode(
        target.scope["workflow_authority_public_key"]
            .as_str()
            .ok_or_else(|| err("AUTHORITY_INVALID"))?,
    )
    .map_err(|_| err("AUTHORITY_INVALID"))?;
    let key_bytes: [u8; 32] = public.try_into().map_err(|_| err("AUTHORITY_INVALID"))?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| err("AUTHORITY_INVALID"))?;
    let signature = hex::decode(signature).map_err(|_| err("AUTHORIZATION_INVALID"))?;
    let signature = ed25519_dalek::Signature::from_slice(&signature)
        .map_err(|_| err("AUTHORIZATION_INVALID"))?;
    let mut message = b"KTAPEOUT/RELEASE-AUTHORIZATION/V1\0".to_vec();
    message.extend_from_slice(intent_sha256.as_bytes());
    key.verify_strict(&message, &signature)
        .map_err(|_| err("AUTHORIZATION_INVALID"))?;
    check_plan(&target, &plan)?;
    Ok(VerifiedAdapterAuthorization {
        intent_sha256: intent_sha256.to_owned(),
        plan_sha256,
        max_fee_sompi: target.max_fee_sompi,
        valid_until,
    })
}
