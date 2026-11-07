//! Durable release coordinator. Adapters own boundary operations, never authorization or retries.
//!
//! V1 targets name a site (`ssh_host`, `remote_root`, `origin`) and remain the host line. V2 publisher targets omit all host
//! fields so release preparation and chain-bound publication can be configured without site credentials. Both use this same
//! durable coordinator and adapter contract; adapters do not grant authorization or retry uncertain effects.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Pin {
    pub path: PathBuf,
    pub sha256: String,
}
#[derive(Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ApplicationCandidateBinding {
    pub snapshot_directory: PathBuf,
    pub snapshot_digest: String,
    pub profile_digest: String,
    pub profile_scope: Value,
    pub adapter_id: String,
    pub application_uri: String,
    pub network: String,
    pub release_id: String,
    pub content_root: String,
}
#[derive(Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub schema: String,
    /// V1 omits this field and remains the legacy host workflow. V2/V3 use static release adapters.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub execution_line: String,
    pub project: PathBuf,
    pub scope: Value,
    pub settings: Value,
    pub max_fee_sompi: u64,
    pub authorization_ttl_seconds: u64,
    pub adapter: Pin,
    pub arguments: Vec<String>,
    pub dependencies: Vec<Pin>,
    pub timeout_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application_candidate: Option<ApplicationCandidateBinding>,
    /// Required for V2/V3 targets and checked against the shared static adapter registry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_adapter_id: Option<String>,
}
#[derive(Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Action {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    pub fee_sompi: u64,
    pub effect: bool,
    #[serde(default)]
    pub retry_safe: bool,
    /// Exact native executor inputs for the one name-target update authorized by this action.
    /// When present, this object is included in the workflow plan signature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name_update_binding: Option<NameUpdateExecutionBinding>,
}
#[derive(Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct NameUpdateExecutionBinding {
    pub schema: String,
    pub network: String,
    pub application_uri: String,
    pub release_id: String,
    pub target_commitment: String,
    pub signer_public_key: String,
    pub review_sha256: String,
    pub request_sha256: String,
    pub plan_sha256: String,
    pub execution_sha256: String,
}
#[derive(Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub schema: String,
    pub scope: Value,
    pub release_id: String,
    pub source_sha256: String,
    pub unchanged: bool,
    pub actions: Vec<Action>,
    pub artifacts: Vec<Pin>,
    pub summary: Value,
}
#[derive(Deserialize, Serialize)]
struct State {
    schema: String,
    target_sha256: String,
    intent_sha256: String,
    plan: Plan,
    authorized: bool,
    authorization_signature: Option<String>,
    valid_until: u64,
    status: String,
    next: usize,
    reserved_fee_sompi: u64,
    pending: bool,
    receipts: Vec<Value>,
    #[serde(default)]
    timings_ms: std::collections::BTreeMap<String, u64>,
    #[serde(default)]
    timing_attempts: std::collections::BTreeMap<String, u64>,
    #[serde(default)]
    last_timings_ms: std::collections::BTreeMap<String, u64>,
    #[serde(default)]
    evidence: Vec<WorkflowEvidence>,
}
#[derive(Deserialize, Serialize, Clone)]
struct WorkflowEvidence {
    schema: String,
    stage: String,
    input_sha256: String,
    validator_sha256: String,
    environment_sha256: String,
    observed_at: u64,
    outcome: String,
    #[serde(default)]
    capabilities: Vec<CapabilityObservation>,
    evidence_sha256: String,
}
#[derive(Deserialize, Serialize, Clone)]
#[serde(deny_unknown_fields)]
struct CapabilityObservation {
    id: String,
    status: String,
    evidence_sha256: String,
    valid_until: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CapabilityReport {
    schema: String,
    intent_sha256: String,
    adapter_sha256: String,
    observed_at: u64,
    items: Vec<CapabilityObservation>,
}
#[derive(Deserialize, Serialize)]
struct PrepareAttempt {
    schema: String,
    target_sha256: String,
    attempt: u64,
    status: String,
    started_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    elapsed_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_code: Option<String>,
}
fn err(s: &str) -> String {
    format!("RELEASE_{s}")
}

/// Translate the native name-update executor's structural journal snapshot into the only
/// safe next step. An inspection snapshot is never chain proof, including when it reports a
/// completed two-node readback; callers must still verify and consume the immutable readback.
pub fn executor_disposition(inspection: &Value) -> Result<&'static str, String> {
    if inspection["schema"] != "KTAPEOUT-NAME-UPDATE-EXECUTION-STATE-V1"
        || inspection["network"] != "testnet-10"
        || inspection["read_only"] != true
        || inspection["journal_assurance"] != "STRUCTURAL_ONLY"
        || inspection["submission_retry_allowed"] != false
    {
        return Err(err("EXECUTOR_INSPECTION_INVALID"));
    }

    match inspection["status"].as_str() {
        Some("NOT_ATTEMPTED")
            if inspection["signing_retry_allowed"] == true
                && inspection["submission_first_attempt_allowed"] == false =>
        {
            Ok("SIGN_AFTER_COORDINATOR_AUTHORIZATION")
        }
        Some("SIGNED_NOT_SUBMITTED")
            if inspection["signing_retry_allowed"] == false
                && inspection["submission_first_attempt_allowed"] == true =>
        {
            Ok("SUBMIT_ONCE_AFTER_COORDINATOR_AUTHORIZATION")
        }
        Some("SIGNING_UNKNOWN") => Ok("STOP_AND_RECONCILE_SIGNER"),
        Some("SUBMISSION_UNKNOWN") | Some("READBACK_REQUIRED") => {
            if inspection["independent_readback_required"] == true {
                Ok("REQUIRE_INDEPENDENT_CHAIN_READBACK")
            } else {
                Err(err("EXECUTOR_INSPECTION_INVALID"))
            }
        }
        Some("TWO_NODE_READBACK_RECORDED") => Ok("VERIFY_IMMUTABLE_READBACK_EVIDENCE"),
        Some("JOURNAL_INCONSISTENT") => Ok("STOP_AND_REVIEW_JOURNAL"),
        _ => Err(err("EXECUTOR_INSPECTION_INVALID")),
    }
}

fn validate_effect_evidence(
    target: &Target,
    action: &Action,
    phase: &str,
    response: &Value,
) -> Result<(), String> {
    if !action.effect || target.execution_line.is_empty() {
        return Ok(());
    }
    let status = response["status"]
        .as_str()
        .ok_or_else(|| err("EFFECT_EVIDENCE_INVALID"))?;
    let expected_outcome = match (phase, status) {
        ("execute", "COMPLETE") | ("reconcile", "COMPLETE") => "CONFIRMED",
        ("execute", "ROLLED_BACK") => "ROLLED_BACK",
        ("reconcile", "RETRY_SAFE") => "ABSENT",
        _ => return Ok(()),
    };
    let evidence = &response["effect_evidence"];
    let external_id = evidence["external_effect_id"].as_str().unwrap_or_default();
    if evidence["schema"] != "KTAPEOUT-RELEASE-EFFECT-EVIDENCE-V1"
        || evidence["action_id"] != action.id
        || evidence["outcome"] != expected_outcome
        || external_id.is_empty()
        || external_id.len() > 256
        || !evidence["artifact_sha256"].as_str().is_some_and(|digest| {
            digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
    {
        return Err(err("EFFECT_EVIDENCE_INVALID"));
    }
    if expected_outcome == "CONFIRMED"
        && target.execution_line == "name-controller"
        && action.kind.as_deref() == Some("name-target-update")
        && response.get("executor_inspection").is_none()
    {
        return Err(err("EFFECT_EVIDENCE_INVALID"));
    }
    if let Some(inspection) = response.get("executor_inspection") {
        let disposition = executor_disposition(inspection)?;
        if expected_outcome == "CONFIRMED" {
            let readback_sha256 = inspection["evidence_sha256"]["readback.json"]
                .as_str()
                .ok_or_else(|| err("EFFECT_EVIDENCE_INVALID"))?;
            if disposition != "VERIFY_IMMUTABLE_READBACK_EVIDENCE"
                || evidence["external_effect_id"] != inspection["txid"]
                || evidence["artifact_sha256"] != readback_sha256
            {
                return Err(err("EFFECT_EVIDENCE_INVALID"));
            }
            if target.execution_line == "name-controller"
                && action.kind.as_deref() == Some("name-target-update")
            {
                let receipt = &inspection["receipt_artifact"];
                let receipt_sha256 = evidence["receipt_sha256"].as_str().unwrap_or_default();
                let observation_sha256 =
                    evidence["observation_sha256"].as_str().unwrap_or_default();
                let is_digest = |value: &str| {
                    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
                };
                if receipt["schema"] != "KTAPEOUT-VERIFIED-RECEIPT-ARTIFACT-V1"
                    || receipt["status"] != "RECEIPT_VERIFIED_AND_WRITTEN"
                    || receipt["path"] != "application-resolution-receipt.json"
                    || receipt["state_binding"] != "RECOMPUTED_FROM_STATE"
                    || receipt["signing_allowed"] != false
                    || receipt["broadcast"] != false
                    || !is_digest(receipt_sha256)
                    || !is_digest(observation_sha256)
                    || receipt["sha256"] != receipt_sha256
                    || receipt["observation_sha256"] != observation_sha256
                {
                    return Err(err("EFFECT_EVIDENCE_INVALID"));
                }
            }
        } else if expected_outcome == "ABSENT" {
            // Structural journal inspection cannot prove that a transaction is absent; do not
            // let it authorize a retry of a potentially submitted transaction.
            return Err(err("EFFECT_EVIDENCE_INVALID"));
        }
    }
    Ok(())
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
fn value_hash<T: Serialize>(v: &T) -> Result<String, String> {
    serde_json::to_vec(v)
        .map(|b| hash(&b))
        .map_err(|_| err("JSON_INVALID"))
}
fn required_capabilities(t: &Target) -> Result<Vec<String>, String> {
    let Some(value) = t.settings.get("required_capabilities") else {
        return Ok(Vec::new());
    };
    let values = value
        .as_array()
        .filter(|items| items.len() <= 32)
        .ok_or_else(|| err("CAPABILITY_REQUIREMENTS_INVALID"))?;
    let mut result = Vec::with_capacity(values.len());
    for value in values {
        let id = value
            .as_str()
            .filter(|id| {
                !id.is_empty()
                    && id.len() <= 64
                    && id.bytes().all(|b| {
                        b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-'
                    })
                    && known_capability_id(id)
            })
            .ok_or_else(|| err("CAPABILITY_REQUIREMENTS_INVALID"))?;
        if result.iter().any(|existing| existing == id) {
            return Err(err("CAPABILITY_REQUIREMENTS_INVALID"));
        }
        result.push(id.to_owned());
    }
    Ok(result)
}
fn required_capabilities_for_plan(t: &Target, plan: &Plan) -> Result<Vec<String>, String> {
    let mut result = required_capabilities(t)?;
    for action in &plan.actions {
        let required: &[&str] = if plan.schema == "KTAPEOUT-RELEASE-PLAN-V2" {
            action_kind_capabilities(
                action
                    .kind
                    .as_deref()
                    .ok_or_else(|| err("ACTION_KIND_INVALID"))?,
            )?
        } else if matches!(action.id.as_str(), "host-stage" | "host-activate") {
            // V1 compatibility: legacy host actions only encoded stage readiness.
            &["host.pages.stage"]
        } else {
            &[]
        };
        for id in required {
            if !result.iter().any(|existing| existing == id) {
                result.push((*id).to_owned());
            }
        }
    }
    if result.len() > 32 {
        return Err(err("CAPABILITY_REQUIREMENTS_INVALID"));
    }
    Ok(result)
}
fn action_kind_capabilities(kind: &str) -> Result<&'static [&'static str], String> {
    match kind {
        "host-stage" => Ok(&["host.pages.stage"]),
        "host-activate" => Ok(&["host.pages.stage", "host.pages.activate"]),
        // Host record ingestion is distinct from activating Pages.
        "host-record-publish" => Ok(&["host.intake.publish"]),
        "content-sign" => Ok(&["signer.content"]),
        "deed-sign" => Ok(&["signer.deed"]),
        "publisher-sign" => Ok(&["signer.publisher"]),
        "chain-broadcast" => Ok(&["chain.broadcast"]),
        "name-target-update" => Ok(&["chain.broadcast"]),
        "chain-readback" | "release-verify" => Ok(&["chain.read"]),
        "desktop-acceptance" => Ok(&["browser.desktop"]),
        "kasware-operation" => Ok(&["wallet.kasware"]),
        "android-acceptance" => Ok(&["device.android"]),
        _ => Err(err("ACTION_KIND_INVALID")),
    }
}

fn known_capability_id(id: &str) -> bool {
    matches!(
        id,
        "host.pages.activate"
            | "host.pages.stage"
            | "host.intake.publish"
            | "signer.content"
            | "signer.deed"
            | "signer.publisher"
            | "chain.read"
            | "chain.broadcast"
            | "browser.desktop"
            | "wallet.kasware"
            | "device.android"
    )
}
fn capability_observations(
    t: &Target,
    s: &State,
    response: &Value,
) -> Result<Vec<CapabilityObservation>, String> {
    let Some(value) = response.get("capabilities") else {
        return Ok(Vec::new());
    };
    let report: CapabilityReport =
        serde_json::from_value(value.clone()).map_err(|_| err("CAPABILITY_REPORT_INVALID"))?;
    if report.schema != "KTAPEOUT-RELEASE-CAPABILITY-REPORT-V1"
        || report.intent_sha256 != s.intent_sha256
        || report.adapter_sha256 != t.adapter.sha256
        || report.observed_at > now()
        || now().saturating_sub(report.observed_at) > 300
        || report.items.len() > 32
    {
        return Err(err("CAPABILITY_REPORT_INVALID"));
    }
    let mut seen = std::collections::HashSet::new();
    for item in &report.items {
        if item.id.is_empty()
            || item.id.len() > 64
            || !item
                .id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
            || !known_capability_id(&item.id)
            || !seen.insert(item.id.as_str())
            || ![
                "AVAILABLE",
                "MISSING",
                "NEEDS_AUTHORIZATION",
                "UNKNOWN",
                "NOT_APPLICABLE",
            ]
            .contains(&item.status.as_str())
            || item.evidence_sha256.len() != 64
            || !item.evidence_sha256.bytes().all(|b| b.is_ascii_hexdigit())
            || item.valid_until < report.observed_at
        {
            return Err(err("CAPABILITY_REPORT_INVALID"));
        }
        let expected = value_hash(&json!({
            "id": item.id,
            "status": item.status,
            "observed_at": report.observed_at,
            "valid_until": item.valid_until,
        }))?;
        if item.evidence_sha256 != expected {
            return Err(err("CAPABILITY_REPORT_INVALID"));
        }
    }
    Ok(report.items)
}
fn check_required_capabilities(
    t: &Target,
    plan: &Plan,
    items: &[CapabilityObservation],
) -> Result<(), String> {
    let requirements = required_capabilities_for_plan(t, plan)?;
    for id in requirements {
        let Some(item) = items.iter().find(|item| item.id == id) else {
            return Err(err("CAPABILITY_UNKNOWN"));
        };
        if item.valid_until < now() {
            return Err(err("CAPABILITY_UNKNOWN"));
        }
        match item.status.as_str() {
            "AVAILABLE" => {}
            "MISSING" => return Err(err("CAPABILITY_MISSING")),
            "NEEDS_AUTHORIZATION" => return Err(err("CAPABILITY_NEEDS_AUTHORIZATION")),
            _ => return Err(err("CAPABILITY_UNKNOWN")),
        }
    }
    Ok(())
}
fn preflight_evidence(
    t: &Target,
    s: &State,
    outcome: &str,
    capabilities: Vec<CapabilityObservation>,
) -> Result<WorkflowEvidence, String> {
    if !["AVAILABLE", "BLOCKED", "UNKNOWN"].contains(&outcome) {
        return Err(err("EVIDENCE_OUTCOME_INVALID"));
    }
    let mut evidence = WorkflowEvidence {
        schema: "KTAPEOUT-RELEASE-EVIDENCE-V1".into(),
        stage: "host-preflight".into(),
        input_sha256: s.intent_sha256.clone(),
        validator_sha256: t.adapter.sha256.clone(),
        environment_sha256: value_hash(&t.scope)?,
        observed_at: now(),
        outcome: outcome.into(),
        capabilities,
        evidence_sha256: String::new(),
    };
    evidence.evidence_sha256 = value_hash(&json!({
        "schema": evidence.schema,
        "stage": evidence.stage,
        "input_sha256": evidence.input_sha256,
        "validator_sha256": evidence.validator_sha256,
        "environment_sha256": evidence.environment_sha256,
        "observed_at": evidence.observed_at,
        "outcome": evidence.outcome,
        "capabilities": evidence.capabilities,
    }))?;
    Ok(evidence)
}
fn read<T: for<'de> Deserialize<'de>>(p: &Path) -> Result<T, String> {
    let meta = fs::symlink_metadata(p).map_err(|_| err("FILE_UNAVAILABLE"))?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > 16 * 1024 * 1024 {
        return Err(err("FILE_INVALID"));
    }
    serde_json::from_slice(&fs::read(p).map_err(|_| err("FILE_UNAVAILABLE"))?)
        .map_err(|_| err("JSON_INVALID"))
}
fn check_pin(pin: &Pin) -> Result<(), String> {
    let meta = fs::symlink_metadata(&pin.path).map_err(|_| err("PIN_UNAVAILABLE"))?;
    if !pin.path.is_absolute() || !meta.is_file() || meta.file_type().is_symlink() {
        return Err(err("PIN_INVALID"));
    }
    let mut file = fs::File::open(&pin.path).map_err(|_| err("PIN_UNAVAILABLE"))?;
    let mut digest = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let n = file.read(&mut buffer).map_err(|_| err("PIN_READ_FAILED"))?;
        if n == 0 {
            break;
        }
        digest.update(&buffer[..n]);
    }
    if hex::encode(digest.finalize()) != pin.sha256 {
        return Err(err("PIN_CHANGED"));
    }
    Ok(())
}
pub(crate) fn check_target(t: &Target) -> Result<(), String> {
    check_target_registration(t, true)
}

fn check_target_registration(t: &Target, require_current_registration: bool) -> Result<(), String> {
    let host_line = t.schema == "KTAPEOUT-RELEASE-TARGET-V1" && t.execution_line.is_empty();
    let publisher_line = t.schema == "KTAPEOUT-RELEASE-TARGET-V2"
        && t.execution_line == "publisher"
        && ["origin", "remote_root", "ssh_host"]
            .iter()
            .all(|key| t.scope.get(*key).is_none_or(Value::is_null));
    let combined_publisher_name_controller_line =
        t.schema == "KTAPEOUT-RELEASE-TARGET-V4" && t.execution_line == "name-controller";
    let name_controller_line = (t.schema == "KTAPEOUT-RELEASE-TARGET-V3"
        || combined_publisher_name_controller_line)
        && t.execution_line == "name-controller"
        && ["origin", "remote_root", "ssh_host"]
            .iter()
            .all(|key| t.scope.get(*key).is_none_or(Value::is_null));
    if (!host_line && !publisher_line && !name_controller_line)
        || t.scope["network"] != "testnet-10"
        || !t.project.is_absolute()
        || !t.project.is_dir()
        || !(1..=1800).contains(&t.timeout_seconds)
        || t.scope["application_uri"]
            .as_str()
            .filter(|s| s.starts_with("ktape://testnet-10/app/"))
            .is_none()
        || (host_line
            && (t.scope["origin"]
                .as_str()
                .filter(|s| s.starts_with("https://"))
                .is_none()
                || t.scope["remote_root"]
                    .as_str()
                    .filter(|s| {
                        s.starts_with('/') && s.len() > 1 && !s.split('/').any(|p| p == "..")
                    })
                    .is_none()))
        || t.scope["workflow_authority_public_key"]
            .as_str()
            .filter(|v| v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit()))
            .is_none()
        || !t.scope["permissions"].is_array()
        || (name_controller_line
            && ((t.schema == "KTAPEOUT-RELEASE-TARGET-V3"
                && t.scope["permissions"]
                    .as_array()
                    .is_none_or(|permissions| !permissions.is_empty()))
                || t.scope["name_controller_public_key"]
                    .as_str()
                    .filter(|v| v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit()))
                    .is_none()
                || t.scope["workflow_authority_public_key"]
                    == t.scope["name_controller_public_key"]))
        || !(60..=86400).contains(&t.authorization_ttl_seconds)
        || t.dependencies.len() > 2048
        || ["wallet_address"]
            .iter()
            .any(|k| t.scope[*k].as_str().filter(|s| !s.is_empty()).is_none())
        || ((host_line || publisher_line || combined_publisher_name_controller_line)
            && ["publisher_id", "publisher_key_id"]
                .iter()
                .any(|k| t.scope[*k].as_str().filter(|s| !s.is_empty()).is_none()))
        || (host_line
            && t.scope["ssh_host"]
                .as_str()
                .filter(|s| !s.is_empty())
                .is_none())
    {
        return Err(err("TARGET_INVALID"));
    }
    if !host_line {
        check_host_free_scope(t)?;
        if require_current_registration {
            check_registered_release_adapter(t)?;
        }
    }
    required_capabilities(t)?;
    crate::release_candidate_binding::check(t)?;
    Ok(())
}

fn check_host_free_scope(t: &Target) -> Result<(), String> {
    let target = serde_json::to_value(t).map_err(|_| err("TARGET_INVALID"))?;
    crate::release_adapter_contract::validate_host_free_target_values(&target)
        .map_err(|_| err("TARGET_INVALID"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegisteredReleaseAdapter {
    status: String,
    execution_line: String,
    implemented_phases: Vec<String>,
    host_dependencies: Vec<String>,
    executables: BTreeMap<String, Pin>,
    arguments: Vec<String>,
    dependencies: Vec<Pin>,
    settings: Value,
    operator_settings_schema: std::collections::BTreeMap<String, String>,
    evidence: String,
    reason: String,
}

fn same_pin(left: &Pin, right: &Pin) -> bool {
    left.path == right.path && left.sha256 == right.sha256
}

fn native_name_update_dependencies(settings: &Value, fixed: &[Pin]) -> Result<Vec<Pin>, String> {
    let value = &settings["native_name_update"];
    if !crate::release_execute::valid_native_name_update_settings_shape(value) {
        return Err(err("ADAPTER_SETTINGS_INVALID"));
    }
    let pin = |role: &str| -> Result<Pin, String> {
        let pin: Pin =
            serde_json::from_value(value[role].clone()).map_err(|_| err("ADAPTER_PIN_MISMATCH"))?;
        if !pin.path.to_str().is_some_and(is_safe_absolute_path)
            || pin.sha256.len() != 64
            || !pin
                .sha256
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(err("ADAPTER_PIN_MISMATCH"));
        }
        Ok(pin)
    };
    let roles = [
        "planner",
        "fetcher",
        "state_helper",
        "submitter",
        "readback_scanner",
        "readback_verifier",
    ];
    if fixed.len() != roles.len() {
        return Err(err("ADAPTER_PIN_MISMATCH"));
    }
    for (role, registered) in roles.iter().zip(fixed) {
        let item = pin(role)?;
        if !same_pin(registered, &item) {
            return Err(err("ADAPTER_PIN_MISMATCH"));
        }
    }
    let mut dependencies = fixed.to_vec();
    for role in ["signer", "current_receipt"] {
        let item = pin(role)?;
        if dependencies
            .iter()
            .any(|registered| registered.path == item.path)
        {
            return Err(err("ADAPTER_PIN_MISMATCH"));
        }
        dependencies.push(item);
    }
    Ok(dependencies)
}

fn resolve_registered_pin(pin: &Pin, root: &Path) -> Result<Pin, String> {
    if pin.path.is_absolute() {
        return Ok(pin.clone());
    }
    let relative = pin
        .path
        .to_str()
        .ok_or_else(|| err("ADAPTER_REGISTRY_INVALID"))?;
    if !is_safe_project_relative_path(relative) {
        return Err(err("ADAPTER_REGISTRY_INVALID"));
    }
    Ok(Pin {
        path: root.join(&pin.path),
        sha256: pin.sha256.clone(),
    })
}

// The reviewed registry fixes each artifact's relative location and digest; the target
// supplies its installation location. This keeps released binaries independent of the
// directory on the machine that compiled them.
fn registered_install_root(adapter: &Pin, registered: &Pin) -> Result<PathBuf, String> {
    let relative = registered
        .path
        .to_str()
        .ok_or_else(|| err("ADAPTER_REGISTRY_INVALID"))?;
    if registered.path.is_absolute()
        || !is_safe_project_relative_path(relative)
        || !adapter.path.to_str().is_some_and(is_safe_absolute_path)
        || !adapter.path.ends_with(&registered.path)
    {
        return Err(err("ADAPTER_PIN_MISMATCH"));
    }
    let mut root = adapter.path.clone();
    for _ in registered.path.components() {
        if !root.pop() {
            return Err(err("ADAPTER_PIN_MISMATCH"));
        }
    }
    if !root.is_absolute() {
        return Err(err("ADAPTER_PIN_MISMATCH"));
    }
    Ok(root)
}

fn release_adapter_platform_key(os: &str, arch: &str) -> Result<&'static str, String> {
    match (os, arch) {
        ("windows", "x86_64") => Ok("windows-x86_64"),
        ("linux", "x86_64") => Ok("linux-x86_64"),
        ("linux", "aarch64") => Ok("linux-aarch64"),
        ("macos", "x86_64") => Ok("macos-x86_64"),
        ("macos", "aarch64") => Ok("macos-aarch64"),
        _ => Err(err("ADAPTER_PLATFORM_UNSUPPORTED")),
    }
}

fn current_release_adapter_platform_key() -> Result<&'static str, String> {
    release_adapter_platform_key(std::env::consts::OS, std::env::consts::ARCH)
}

fn is_safe_project_relative_path(value: &str) -> bool {
    !value.trim().is_empty()
        && !value.starts_with('/')
        && !value.contains('\\')
        && !value.contains('\0')
        && !value.contains(':')
        && value.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && !segment.ends_with('.')
                && !segment.ends_with(' ')
        })
}

fn is_safe_absolute_path(value: &str) -> bool {
    if value.trim().is_empty() || value.trim() != value || value.contains('\0') {
        return false;
    }
    #[cfg(windows)]
    let segments = {
        let bytes = value.as_bytes();
        if bytes.len() < 4
            || !bytes[0].is_ascii_alphabetic()
            || bytes[1] != b':'
            || !matches!(bytes[2], b'/' | b'\\')
        {
            return false;
        }
        value[3..].split(['/', '\\']).collect::<Vec<_>>()
    };
    #[cfg(not(windows))]
    let segments = {
        if !value.starts_with('/') || value.starts_with("//") || value.contains('\\') {
            return false;
        }
        value[1..].split('/').collect::<Vec<_>>()
    };
    !segments.is_empty()
        && segments.iter().all(|segment| {
            !segment.is_empty()
                && *segment != "."
                && *segment != ".."
                && !segment.ends_with('.')
                && !segment.ends_with(' ')
        })
}

fn check_operator_adapter_settings(
    fixed_settings: &Value,
    schema: &std::collections::BTreeMap<String, String>,
    settings: &Value,
) -> Result<(), String> {
    let fixed = fixed_settings
        .as_object()
        .ok_or_else(|| err("ADAPTER_REGISTRY_INVALID"))?;
    let values = settings
        .as_object()
        .ok_or_else(|| err("ADAPTER_SETTINGS_INVALID"))?;
    let forbidden = [
        "origin",
        "remote_root",
        "ssh_host",
        "secret",
        "private_key",
        "mnemonic",
        "recovery_code",
        "seed_phrase",
    ];
    let valid_type = |kind: &str, value: &Value| match kind {
        "string" => value.as_str().is_some_and(|text| !text.trim().is_empty()),
        "boolean" => value.is_boolean(),
        "integer" => {
            value
                .as_i64()
                .is_some_and(|number| number.unsigned_abs() <= 9_007_199_254_740_991)
                || value
                    .as_u64()
                    .is_some_and(|number| number <= 9_007_199_254_740_991)
        }
        "sha256" => value.as_str().is_some_and(|text| {
            text.len() == 64
                && text
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        }),
        "project_path" => value.as_str().is_some_and(is_safe_project_relative_path),
        "absolute_path" => value.as_str().is_some_and(is_safe_absolute_path),
        "tn10_node_id" => value
            .as_str()
            .is_some_and(crate::release_node_registry::is_registered_node_id),
        "native_name_update" => {
            crate::release_execute::valid_native_name_update_settings_shape(value)
        }
        _ => false,
    };
    for (key, kind) in schema {
        let normalized = key.to_ascii_lowercase();
        if key.is_empty()
            || key.len() > 64
            || !key.bytes().enumerate().all(|(index, byte)| {
                if index == 0 {
                    byte.is_ascii_lowercase()
                } else {
                    byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
                }
            })
            || forbidden.iter().any(|part| normalized.contains(part))
            || fixed.contains_key(key)
            || !matches!(
                kind.as_str(),
                "string"
                    | "boolean"
                    | "integer"
                    | "sha256"
                    | "project_path"
                    | "absolute_path"
                    | "tn10_node_id"
                    | "native_name_update"
            )
            || (kind == "native_name_update" && key != "native_name_update")
        {
            return Err(err("ADAPTER_SETTINGS_SCHEMA_INVALID"));
        }
    }
    for (key, value) in fixed {
        let normalized = key.to_ascii_lowercase();
        if key.is_empty()
            || key.len() > 64
            || !key.bytes().enumerate().all(|(index, byte)| {
                if index == 0 {
                    byte.is_ascii_lowercase()
                } else {
                    byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
                }
            })
            || forbidden.iter().any(|part| normalized.contains(part))
            || !(value.as_str().is_some_and(|text| !text.trim().is_empty())
                || value.is_boolean()
                || value
                    .as_i64()
                    .is_some_and(|number| number.unsigned_abs() <= 9_007_199_254_740_991)
                || value
                    .as_u64()
                    .is_some_and(|number| number <= 9_007_199_254_740_991))
        {
            return Err(err("ADAPTER_REGISTRY_INVALID"));
        }
    }
    if values
        .keys()
        .any(|key| !schema.contains_key(key) && !fixed.contains_key(key))
        || fixed
            .iter()
            .any(|(key, expected)| values.get(key) != Some(expected))
        || schema
            .iter()
            .any(|(key, kind)| values.get(key).is_none_or(|value| !valid_type(kind, value)))
    {
        return Err(err("ADAPTER_SETTINGS_INVALID"));
    }
    let has_primary = schema.contains_key("readback_node_primary");
    let has_secondary = schema.contains_key("readback_node_secondary");
    if has_primary != has_secondary
        || (has_primary
            && (schema.get("readback_node_primary").map(String::as_str) != Some("tn10_node_id")
                || schema.get("readback_node_secondary").map(String::as_str)
                    != Some("tn10_node_id")))
    {
        return Err(err("ADAPTER_NODE_PAIR_INVALID"));
    }
    if has_primary {
        let primary = values["readback_node_primary"].as_str().unwrap_or_default();
        let secondary = values["readback_node_secondary"]
            .as_str()
            .unwrap_or_default();
        crate::release_node_registry::validate_dual_node_ids(primary, secondary)
            .map_err(|_| err("ADAPTER_NODE_PAIR_INVALID"))?;
    }
    Ok(())
}

fn load_release_adapter_registry(project: Option<&Path>) -> Result<Value, String> {
    let mut candidates = Vec::new();
    if let Some(path) = std::env::var_os("KTAPEOUT_RELEASE_ADAPTER_REGISTRY") {
        candidates.push(PathBuf::from(path));
    }
    if let Some(project) = project {
        candidates.push(project.join("config/application-release-target-adapter-registry.json"));
        candidates.push(project.join("studio/application-release-target-adapter-registry.json"));
    }
    if let Ok(current) = std::env::current_dir() {
        candidates.extend(registry_ancestor_candidates(&current));
    }
    if let Ok(executable) = std::env::current_exe() {
        if let Some(parent) = executable.parent() {
            candidates.extend(registry_ancestor_candidates(parent));
        }
    }
    candidates
        .into_iter()
        .find_map(|path| fs::read_to_string(path).ok())
        .ok_or_else(|| err("ADAPTER_REGISTRY_NOT_FOUND"))
        .and_then(|source| {
            serde_json::from_str(&source).map_err(|_| err("ADAPTER_REGISTRY_INVALID"))
        })
}

fn registry_ancestor_candidates(start: &Path) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    let mut current = Some(start);
    for _ in 0..=6 {
        let Some(path) = current else { break };
        candidates.push(path.join("config/application-release-target-adapter-registry.json"));
        candidates.push(path.join("studio/application-release-target-adapter-registry.json"));
        current = path.parent();
    }
    candidates
}

fn check_registered_release_adapter(t: &Target) -> Result<(), String> {
    let registry = load_release_adapter_registry(Some(&t.project))?;
    check_registered_release_adapter_in(t, &registry)
}

/// Return the reviewed static release-adapter catalog without starting a workflow or
/// touching adapter executables. This lets developers discover support boundaries before
/// constructing a release target; the catalog never upgrades a registered status to READY.
pub fn adapter_catalog() -> Result<Value, String> {
    let registry = load_release_adapter_registry(None)?;
    if registry["schema"] != "KTAPEOUT-RELEASE-TARGET-ADAPTER-REGISTRY-V3"
        || !registry["adapters"].is_object()
        || registry["required_workflow_phases"]
            != json!(["prepare", "preflight", "authorize", "execute", "reconcile"])
        || registry["coordinator_managed_phases"] != json!(["authorize"])
    {
        return Err(err("ADAPTER_REGISTRY_INVALID"));
    }
    let current_platform = current_release_adapter_platform_key().ok();
    let adapters = registry["adapters"]
        .as_object()
        .ok_or_else(|| err("ADAPTER_REGISTRY_INVALID"))?
        .iter()
        .map(|(adapter_id, entry)| {
            let executables = entry["executables"]
                .as_object()
                .ok_or_else(|| err("ADAPTER_REGISTRY_INVALID"))?;
            let host_dependencies = entry["host_dependencies"]
                .as_array()
                .ok_or_else(|| err("ADAPTER_REGISTRY_INVALID"))?;
            let implemented_phases = entry["implemented_phases"]
                .as_array()
                .ok_or_else(|| err("ADAPTER_REGISTRY_INVALID"))?;
            Ok(json!({
                "adapter_id": adapter_id,
                "status": entry["status"],
                "execution_line": entry["execution_line"],
                "implemented_phases": implemented_phases,
                "coordinator_managed_phases": registry["coordinator_managed_phases"],
                "host_dependencies": host_dependencies,
                "supported_platforms": executables.keys().collect::<Vec<_>>(),
                "current_platform": current_platform,
                "current_platform_registered": current_platform
                    .as_ref()
                    .is_some_and(|platform| executables.contains_key(*platform)),
                "reason": entry["reason"],
                "evidence": entry["evidence"]
            }))
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(json!({
        "schema": "KTAPEOUT-RELEASE-ADAPTER-CATALOG-V1",
        "workflow_phases": registry["required_workflow_phases"],
        "current_platform": current_platform,
        "adapters": adapters
    }))
}

fn check_registered_release_adapter_in(t: &Target, registry: &Value) -> Result<(), String> {
    if registry["schema"] != "KTAPEOUT-RELEASE-TARGET-ADAPTER-REGISTRY-V3"
        || !registry["adapters"].is_object()
        || registry.as_object().is_none_or(|fields| {
            fields.keys().any(|key| {
                ![
                    "schema",
                    "required_workflow_phases",
                    "coordinator_managed_phases",
                    "adapters",
                ]
                .contains(&key.as_str())
            })
        })
    {
        return Err(err("ADAPTER_REGISTRY_INVALID"));
    }
    const REQUIRED_PHASES: [&str; 5] =
        ["prepare", "preflight", "authorize", "execute", "reconcile"];
    let declared_phases = registry["required_workflow_phases"]
        .as_array()
        .ok_or_else(|| err("ADAPTER_REGISTRY_PHASES_INVALID"))?;
    if declared_phases.len() != REQUIRED_PHASES.len()
        || declared_phases
            .iter()
            .zip(REQUIRED_PHASES)
            .any(|(declared, required)| declared != required)
        || registry["coordinator_managed_phases"] != json!(["authorize"])
    {
        return Err(err("ADAPTER_REGISTRY_PHASES_INVALID"));
    }
    let adapter_id = t
        .release_adapter_id
        .as_deref()
        .ok_or_else(|| err("ADAPTER_ID_REQUIRED"))?;
    let entry_value = registry["adapters"]
        .get(adapter_id)
        .ok_or_else(|| err("ADAPTER_NOT_REGISTERED"))?;
    let entry: RegisteredReleaseAdapter =
        serde_json::from_value(entry_value.clone()).map_err(|_| err("ADAPTER_REGISTRY_INVALID"))?;
    if entry.evidence.trim().is_empty() || entry.reason.trim().is_empty() {
        return Err(err("ADAPTER_REGISTRY_INVALID"));
    }
    if entry.execution_line != t.execution_line {
        return Err(err("ADAPTER_EXECUTION_LINE_MISMATCH"));
    }
    if entry.status != "HOST_FREE_READY" {
        return Err(err("ADAPTER_NOT_READY"));
    }
    let adapter_phases = ["prepare", "preflight", "execute", "reconcile"];
    let phases_complete = adapter_phases
        .iter()
        .all(|phase| entry.implemented_phases.iter().any(|item| item == phase))
        && entry.implemented_phases.len() == adapter_phases.len()
        && entry
            .implemented_phases
            .iter()
            .all(|phase| adapter_phases.contains(&phase.as_str()));
    if !phases_complete || !entry.host_dependencies.is_empty() {
        return Err(err("ADAPTER_READINESS_INVALID"));
    }
    let platform = current_release_adapter_platform_key()?;
    let executable = entry
        .executables
        .get(platform)
        .ok_or_else(|| err("ADAPTER_PINS_INCOMPLETE"))?;
    let allowed_platforms = [
        "windows-x86_64",
        "linux-x86_64",
        "linux-aarch64",
        "macos-x86_64",
        "macos-aarch64",
    ];
    let mut all_pin_paths = std::collections::BTreeSet::new();
    for (platform, pin) in &entry.executables {
        if !allowed_platforms.contains(&platform.as_str()) || pin.path.is_absolute() {
            return Err(err("ADAPTER_EXECUTABLE_PLATFORM_INVALID"));
        }
        let relative = pin
            .path
            .to_str()
            .ok_or_else(|| err("ADAPTER_REGISTRY_INVALID"))?;
        if !is_safe_project_relative_path(relative) {
            return Err(err("ADAPTER_REGISTRY_INVALID"));
        }
        if !all_pin_paths.insert(pin.path.clone()) {
            return Err(err("ADAPTER_PIN_PATH_DUPLICATE"));
        }
    }
    for pin in &entry.dependencies {
        if pin.path.is_absolute()
            || !is_safe_project_relative_path(
                pin.path
                    .to_str()
                    .ok_or_else(|| err("ADAPTER_REGISTRY_INVALID"))?,
            )
        {
            return Err(err("ADAPTER_REGISTRY_INVALID"));
        }
    }
    for pin in &entry.dependencies {
        if !all_pin_paths.insert(pin.path.clone()) {
            return Err(err("ADAPTER_PIN_PATH_DUPLICATE"));
        }
    }
    let root = registered_install_root(&t.adapter, executable)?;
    let executable = resolve_registered_pin(executable, &root)?;
    let mut dependencies = entry
        .dependencies
        .iter()
        .map(|pin| resolve_registered_pin(pin, &root))
        .collect::<Result<Vec<_>, _>>()?;
    check_operator_adapter_settings(
        &entry.settings,
        &entry.operator_settings_schema,
        &t.settings,
    )?;
    if entry
        .operator_settings_schema
        .get("native_name_update")
        .map(String::as_str)
        == Some("native_name_update")
    {
        dependencies = native_name_update_dependencies(&t.settings, &dependencies)?;
        if dependencies
            .iter()
            .skip(entry.dependencies.len())
            .any(|pin| all_pin_paths.contains(&pin.path))
        {
            return Err(err("ADAPTER_PIN_PATH_DUPLICATE"));
        }
    }
    if !same_pin(&executable, &t.adapter)
        || entry.arguments != t.arguments
        || dependencies.len() != t.dependencies.len()
        || !dependencies
            .iter()
            .zip(&t.dependencies)
            .all(|(left, right)| same_pin(left, right))
    {
        return Err(err("ADAPTER_PIN_MISMATCH"));
    }
    Ok(())
}

fn coordinator_manages_authorization(t: &Target) -> bool {
    matches!(
        (t.schema.as_str(), t.execution_line.as_str()),
        ("KTAPEOUT-RELEASE-TARGET-V2", "publisher")
            | ("KTAPEOUT-RELEASE-TARGET-V3", "name-controller")
            | ("KTAPEOUT-RELEASE-TARGET-V4", "name-controller")
    ) && t.release_adapter_id.is_some()
        && ["origin", "remote_root", "ssh_host"]
            .iter()
            .all(|key| t.scope.get(*key).is_none_or(Value::is_null))
}
fn check_tools(t: &Target) -> Result<(), String> {
    check_pin(&t.adapter)?;
    for p in &t.dependencies {
        check_pin(p)?;
    }
    Ok(())
}

fn clear_adapter_environment(command: &mut Command) {
    const HOST_ENVIRONMENT: [&str; 3] = [
        "KTAPE_HOST_INTAKE_ORIGIN",
        "KTAPE_HOST_INTAKE_TOKEN",
        "KTAPE_HOST_INTAKE_TEST",
    ];
    let mut preserved = vec!["SystemRoot", "windir"]
        .into_iter()
        .chain(HOST_ENVIRONMENT)
        .filter_map(|key| std::env::var(key).ok().map(|value| (key, value)))
        .collect::<Vec<_>>();
    command.env_clear().envs(preserved.drain(..));
}

fn configure_adapter_environment(command: &mut Command, work: &Path) {
    clear_adapter_environment(command);
    // Do not inherit potentially untrusted temporary-directory settings.
    command
        .env("TMP", work)
        .env("TEMP", work)
        .env("TMPDIR", work);
}

fn check_plan(t: &Target, p: &Plan) -> Result<(), String> {
    let target = serde_json::to_value(t).map_err(|_| err("JSON_INVALID"))?;
    let plan = serde_json::to_value(p).map_err(|_| err("JSON_INVALID"))?;
    crate::release_adapter_contract::validate_plan_values(&target, &plan)
}
// Append-only snapshots avoid non-atomic replacement on Windows. A partial last line is ignored;
// it can only roll back to a persisted pending marker, which forces read-only reconciliation.
fn save(work: &Path, state: &State) -> Result<(), String> {
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(work.join("state.jsonl"))
        .map_err(|_| err("STATE_WRITE_FAILED"))?;
    let mut bytes = serde_json::to_vec(state).map_err(|_| err("JSON_INVALID"))?;
    bytes.push(b'\n');
    f.write_all(&bytes)
        .and_then(|_| f.sync_all())
        .map_err(|_| err("STATE_WRITE_FAILED"))
}
fn append_prepare_attempt(work: &Path, attempt: &PrepareAttempt) -> Result<(), String> {
    let path = work.join("prepare-attempts.jsonl");
    if path.exists() {
        let bytes = fs::read(&path).map_err(|_| err("PREPARE_DIAGNOSTIC_READ_FAILED"))?;
        let complete = bytes.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
        if complete != bytes.len() {
            OpenOptions::new()
                .write(true)
                .open(&path)
                .and_then(|file| file.set_len(complete as u64))
                .map_err(|_| err("PREPARE_DIAGNOSTIC_REPAIR_FAILED"))?;
        }
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|_| err("PREPARE_DIAGNOSTIC_WRITE_FAILED"))?;
    let mut bytes = serde_json::to_vec(attempt).map_err(|_| err("JSON_INVALID"))?;
    bytes.push(b'\n');
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| err("PREPARE_DIAGNOSTIC_WRITE_FAILED"))
}
fn prepare_attempt_summary(work: &Path, target_sha256: &str) -> Result<(u64, u64, u64), String> {
    let path = work.join("prepare-attempts.jsonl");
    let bytes = fs::read(&path).map_err(|_| err("PREPARE_DIAGNOSTIC_READ_FAILED"))?;
    let complete = bytes.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
    if complete != bytes.len() {
        OpenOptions::new()
            .write(true)
            .open(&path)
            .and_then(|file| file.set_len(complete as u64))
            .map_err(|_| err("PREPARE_DIAGNOSTIC_REPAIR_FAILED"))?;
    }
    let mut attempts = 0u64;
    let mut total_ms = 0u64;
    let mut last_ms = 0u64;
    for line in bytes[..complete]
        .split(|b| *b == b'\n')
        .filter(|line| !line.is_empty())
    {
        let record: PrepareAttempt =
            serde_json::from_slice(line).map_err(|_| err("PREPARE_DIAGNOSTIC_INVALID"))?;
        if record.schema != "KTAPEOUT-RELEASE-PREPARE-ATTEMPT-V1"
            || record.target_sha256 != target_sha256
        {
            continue;
        }
        if record.status == "STARTED" {
            attempts = attempts.max(record.attempt);
        } else if let Some(elapsed) = record.elapsed_ms {
            total_ms = total_ms.saturating_add(elapsed);
            last_ms = elapsed;
        }
    }
    Ok((attempts, total_ms, last_ms))
}
fn safe_prepare_error_code(error: &str) -> String {
    error
        .strip_prefix("RELEASE_")
        .filter(|code| {
            !code.is_empty()
                && code
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        })
        .map(|code| format!("RELEASE_{code}"))
        .unwrap_or_else(|| "RELEASE_PREPARE_FAILED".into())
}
fn load(work: &Path) -> Result<Option<State>, String> {
    let file = work.join("state.jsonl");
    if !file.exists() {
        return Ok(None);
    }
    let bytes = fs::read(file).map_err(|_| err("STATE_READ_FAILED"))?;
    let complete = bytes
        .iter()
        .rposition(|b| *b == b'\n')
        .ok_or_else(|| err("STATE_INCOMPLETE"))?
        + 1;
    let last = bytes[..complete]
        .split(|b| *b == b'\n')
        .filter(|s| !s.is_empty())
        .next_back()
        .ok_or_else(|| err("STATE_INVALID"))?;
    let state = serde_json::from_slice(last).map_err(|_| err("STATE_INVALID"))?;
    // Remove only a torn tail before appending the next complete checkpoint.
    if complete != bytes.len() {
        OpenOptions::new()
            .write(true)
            .open(work.join("state.jsonl"))
            .and_then(|f| f.set_len(complete as u64))
            .map_err(|_| err("STATE_REPAIR_FAILED"))?;
    }
    Ok(Some(state))
}
struct ReadOnlyCheckpoint {
    work: PathBuf,
    target: Target,
    state: State,
    incomplete_tail_preserved: bool,
}

/// Read the latest complete checkpoint without repairing a torn tail or invoking an adapter.
fn read_only_checkpoint(work: &Path) -> Result<ReadOnlyCheckpoint, String> {
    read_only_checkpoint_mode(work, false)
}

fn read_only_checkpoint_mode(
    work: &Path,
    reconciliation: bool,
) -> Result<ReadOnlyCheckpoint, String> {
    let work = if work.is_absolute() {
        work.to_owned()
    } else {
        std::env::current_dir()
            .map_err(|_| err("CWD_UNAVAILABLE"))?
            .join(work)
    };
    let work_meta = fs::symlink_metadata(&work).map_err(|_| err("WORKDIR_UNAVAILABLE"))?;
    if !work_meta.is_dir() || work_meta.file_type().is_symlink() {
        return Err(err("WORKDIR_INVALID"));
    }
    let state_path = work.join("state.jsonl");
    let state_meta = fs::symlink_metadata(&state_path).map_err(|_| err("STATE_READ_FAILED"))?;
    if !state_meta.is_file()
        || state_meta.file_type().is_symlink()
        || state_meta.len() > 16 * 1024 * 1024
    {
        return Err(err("STATE_INVALID"));
    }
    let bytes = fs::read(&state_path).map_err(|_| err("STATE_READ_FAILED"))?;
    let complete = bytes
        .iter()
        .rposition(|byte| *byte == b'\n')
        .ok_or_else(|| err("STATE_INCOMPLETE"))?
        + 1;
    let state_bytes = bytes[..complete]
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .next_back()
        .ok_or_else(|| err("STATE_INVALID"))?;
    let state: State = serde_json::from_slice(state_bytes).map_err(|_| err("STATE_INVALID"))?;
    if state.schema != "KTAPEOUT-RELEASE-STATE-V1"
        || state.next > state.plan.actions.len()
        || state.receipts.len() != state.next
    {
        return Err(err("STATE_INVALID"));
    }
    let target: Target = read(&work.join("target.snapshot.json"))?;
    // A completed, signed checkpoint is historical evidence, not a request to run
    // its old adapter again. Keep validating its frozen scope and authorization
    // even after the live registry has advanced to a newer executable.
    let completed_replay = reconciliation && state.authorized && state.status == "COMPLETE";
    check_target_registration(&target, !completed_replay)?;
    if value_hash(&target)? != state.target_sha256
        || state.intent_sha256
            != value_hash(
                &json!({"target":target,"plan":state.plan,"valid_until":state.valid_until}),
            )?
    {
        return Err(err("SCOPE_CHANGED"));
    }
    if state.reserved_fee_sompi > target.max_fee_sompi {
        return Err(err("BUDGET_EXCEEDED"));
    }
    check_plan(&target, &state.plan)?;
    if state.authorized {
        if reconciliation {
            crate::release_adapter_contract::verify_adapter_reconciliation_authorization(
                &adapter_request(&target, &work, "reconcile", Some(&state))?,
            )?;
        } else {
            verify_authorization(&target, &state)?;
        }
    } else if state.authorization_signature.is_some() {
        return Err(err("AUTHORIZATION_INVALID"));
    }
    Ok(ReadOnlyCheckpoint {
        work,
        target,
        state,
        incomplete_tail_preserved: complete != bytes.len(),
    })
}

/// Inspect a persisted operation without repairing state or contacting its adapter.
pub fn inspect(work: &Path) -> Result<Value, String> {
    let checkpoint = read_only_checkpoint_mode(work, true)?;
    let state = &checkpoint.state;
    let mut output = result(&checkpoint.target, &checkpoint.work, state);
    output["read_only"] = Value::Bool(true);
    output["checkpoint_authenticity"] = Value::String(
        if state.authorized {
            "AUTHORIZATION_SIGNATURE_VALID"
        } else {
            "STRUCTURAL_ONLY"
        }
        .into(),
    );
    output["incomplete_tail_preserved"] = Value::Bool(checkpoint.incomplete_tail_preserved);
    output
        .as_object_mut()
        .map(|object| object.remove("resume_argv"));
    Ok(output)
}

/// Close a coordinator operation that failed before any signing or submission attempt.
/// The executor journal, not the coordinator's failed subprocess result, is authoritative.
/// Finish a pending native update using this tool's read-only verifier. Frozen adapter
/// executables remain untouched; this path cannot authorize, sign or submit an effect.
pub fn reconcile_native(work: &Path) -> Result<Value, String> {
    let work = if work.is_absolute() {
        work.to_owned()
    } else {
        std::env::current_dir()
            .map_err(|_| err("CWD_UNAVAILABLE"))?
            .join(work)
    };
    let _work_lock = lock(&work)?;
    let checkpoint = read_only_checkpoint_mode(&work, true)?;
    let target = checkpoint.target;
    let mut state = checkpoint.state;
    if state.status == "COMPLETE" {
        let resource_dir = target
            .project
            .join(".agent-pack/release-locks")
            .join(value_hash(&json!([
                target.scope["network"],
                target.scope["wallet_address"]
            ]))?);
        let _resource_lock = lock(&resource_dir)?;
        let active_path = resource_dir.join("active.json");
        if active_path.exists() && read::<PathBuf>(&active_path)? == work {
            fs::remove_file(active_path).map_err(|_| err("STATE_WRITE_FAILED"))?;
        }
        return Ok(result(&target, &work, &state));
    }
    if !state.authorized || !state.pending || state.next + 1 != state.plan.actions.len() {
        return Err(err("NATIVE_RECONCILE_STATE_INVALID"));
    }
    let action = &state.plan.actions[state.next];
    if !action.effect || action.kind.as_deref() != Some("name-target-update") {
        return Err(err("NATIVE_RECONCILE_ACTION_INVALID"));
    }
    let resource_dir = target
        .project
        .join(".agent-pack/release-locks")
        .join(value_hash(&json!([
            target.scope["network"],
            target.scope["wallet_address"]
        ]))?);
    let _resource_lock = lock(&resource_dir)?;
    let active_path = resource_dir.join("active.json");
    if active_path.exists() && read::<PathBuf>(&active_path)? != work {
        return Err(err("ACTIVE_OPERATION_UNRESOLVED"));
    }
    let request = adapter_request(&target, &work, "reconcile", Some(&state))?;
    let request_path = work.join("native-reconciliation-request.json");
    if request_path.exists() {
        if read::<Value>(&request_path)? != request {
            return Err(err("SCOPE_CHANGED"));
        }
    } else {
        crate::release_execute::create_atomic_new(&request_path, &request)?;
    }
    let response = crate::release_native_adapter::run(&request_path)?;
    validate_effect_evidence(&target, action, "reconcile", &response)?;
    if response["status"] != "COMPLETE"
        || response["intent_sha256"] != state.intent_sha256
        || response["action_id"] != action.id
        || response["fee_sompi"].as_u64() != Some(action.fee_sompi)
    {
        return Err(err("NATIVE_RECONCILE_NOT_COMPLETE"));
    }
    state.receipts.push(response);
    state.next += 1;
    state.pending = false;
    state.status = "COMPLETE".into();
    save(&work, &state)?;
    if active_path.exists() {
        fs::remove_file(active_path).map_err(|_| err("STATE_WRITE_FAILED"))?;
    }
    Ok(result(&target, &work, &state))
}

pub fn abandon_unattempted(work: &Path) -> Result<Value, String> {
    let work = if work.is_absolute() {
        work.to_owned()
    } else {
        std::env::current_dir()
            .map_err(|_| err("CWD_UNAVAILABLE"))?
            .join(work)
    };
    let _work_lock = lock(&work)?;
    let checkpoint = read_only_checkpoint_mode(&work, true)?;
    let snapshot = checkpoint.target;
    let mut state = checkpoint.state;
    if !state.authorized
        || !matches!(
            state.status.as_str(),
            "SUBMISSION_UNKNOWN" | "ABORTED_NO_EFFECT"
        )
        || (state.status == "SUBMISSION_UNKNOWN" && !state.pending)
        || state.next != 0
        || !state.receipts.is_empty()
    {
        return Err(err("ABANDON_STATE_INVALID"));
    }
    let action = state
        .plan
        .actions
        .get(state.next)
        .filter(|action| action.effect && action.kind.as_deref() == Some("name-target-update"))
        .ok_or_else(|| err("ABANDON_ACTION_INVALID"))?;
    let binding = serde_json::to_value(
        action
            .name_update_binding
            .as_ref()
            .ok_or_else(|| err("ABANDON_BINDING_REQUIRED"))?,
    )
    .map_err(|_| err("JSON_INVALID"))?;
    let fee = action.fee_sompi;
    let txid = state.plan.summary["unsigned_txid"]
        .as_str()
        .ok_or_else(|| err("ABANDON_PLAN_INVALID"))?
        .to_owned();
    let network = state.plan.summary["network"]
        .as_str()
        .ok_or_else(|| err("ABANDON_PLAN_INVALID"))?
        .to_owned();

    let resource_dir = snapshot
        .project
        .join(".agent-pack/release-locks")
        .join(value_hash(&json!([
            snapshot.scope["network"],
            snapshot.scope["wallet_address"]
        ]))?);
    let _resource_lock = lock(&resource_dir)?;
    let active_path = resource_dir.join("active.json");
    let active_owner: Option<PathBuf> = if active_path.exists() {
        Some(read(&active_path)?)
    } else {
        None
    };
    if active_owner.as_ref().is_some_and(|owner| owner != &work)
        || active_owner.is_none() && state.status != "ABORTED_NO_EFFECT"
    {
        return Err(err("ABANDON_ACTIVE_OPERATION_MISMATCH"));
    }
    crate::release_execute::abandon_unattempted(
        &work.join("native-name-update-config.json"),
        &binding,
        |inspection| {
            if inspection["txid"] != txid
                || inspection["network"] != network
                || inspection["fee_sompi"].as_u64() != Some(fee)
            {
                return Err(err("ABANDON_PLAN_INVALID"));
            }
            let evidence = json!({
                "schema":"KTAPEOUT-RELEASE-ABANDONMENT-V1",
                "status":"ABORTED_NO_EFFECT",
                "reason":"EXECUTOR_PROVES_NOT_ATTEMPTED",
                "intent_sha256":state.intent_sha256,
                "plan_sha256":value_hash(&state.plan)?,
                "network":network,
                "txid":txid,
                "fee_sompi":fee,
                "binding":binding,
                "signing_allowed":false,
                "broadcast":false
            });
            let audit_path = work.join("abandonment.json");
            if audit_path.exists() {
                if read::<Value>(&audit_path)? != evidence {
                    return Err(err("ABANDON_AUDIT_MISMATCH"));
                }
            } else {
                crate::release_execute::create_atomic_new(&audit_path, &evidence)?;
            }
            state.pending = false;
            state.status = "ABORTED_NO_EFFECT".into();
            save(&work, &state)?;
            if active_owner.is_some() {
                fs::remove_file(active_path).map_err(|_| err("ACTIVE_OPERATION_CLEAR_FAILED"))?;
            }
            Ok(evidence)
        },
    )
}

/// Replace backup destinations before any native effect, retaining the signed old checkpoint.
/// A durable transition record permits recovery between the three local file replacements.
/// Repair the known helper-CLI/digest-signer role mismatch in the same operation.
/// This is not a general reset of unknown signer outcomes. The legacy executable
/// is byte-pinned to a reviewed parser that cannot dispatch --wallet-file.
pub fn repair_cli_signer(
    work: &Path,
    signer_path: &Path,
    signer_sha256: &str,
) -> Result<Value, String> {
    let work = fs::canonicalize(work).map_err(|_| err("WORKDIR_UNAVAILABLE"))?;
    // Avoid Windows verbatim path spelling becoming a new frozen identity.
    let work = PathBuf::from(
        work.to_string_lossy()
            .strip_prefix("\\\\?\\")
            .unwrap_or(&work.to_string_lossy())
            .to_string(),
    );
    if !signer_path.is_absolute() {
        return Err(err("SIGNER_PATH_MUST_BE_ABSOLUTE"));
    }
    let signer = Pin {
        path: signer_path.to_owned(),
        sha256: signer_sha256.to_owned(),
    };
    check_pin(&signer)?;
    if signer.sha256 == crate::release_execute::REJECTED_CLI_SIGNER_SHA256 {
        return Err(err("SIGNER_ROLE_INVALID"));
    }
    let _work_lock = lock(&work)?;
    let transition_path = work.join("cli-signer-repair.json");
    let transition: Value = if transition_path.exists() {
        read(&transition_path)?
    } else {
        let checkpoint = read_only_checkpoint_mode(&work, true)?;
        if !checkpoint.state.authorized
            || checkpoint.state.status != "SUBMISSION_UNKNOWN"
            || !checkpoint.state.pending
            || checkpoint.state.next != 0
            || !checkpoint.state.receipts.is_empty()
        {
            return Err(err("SIGNER_REPAIR_STATE_INVALID"));
        }
        let config: Value = read(&work.join("native-name-update-config.json"))?;
        let prepared = PathBuf::from(
            config["prepared"]
                .as_str()
                .ok_or_else(|| err("CONFIG_INVALID"))?,
        );
        let approval: Value = read(Path::new(
            config["authorization"]
                .as_str()
                .ok_or_else(|| err("CONFIG_INVALID"))?,
        ))?;
        let attempt: Value = read(&prepared.join("signing-attempt.json"))?;
        if attempt["state"] != "SIGNING_ATTEMPT_RECORDED"
            || attempt["authorization_sha256"] != value_hash(&approval)?
        {
            return Err(err("SIGNER_NO_EFFECT_NOT_PROVEN"));
        }
        json!({"schema":"KTAPEOUT-CLI-SIGNER-REPAIR-V1", "old_target":checkpoint.target,
            "old_state":checkpoint.state,"old_config":config,"old_approval":approval,
            "old_attempt":attempt,"signer":signer})
    };
    if transition["schema"] != "KTAPEOUT-CLI-SIGNER-REPAIR-V1"
        || transition["signer"] != json!(signer)
    {
        return Err(err("SIGNER_REPAIR_SCOPE_CHANGED"));
    }
    let old_target: Target = serde_json::from_value(transition["old_target"].clone())
        .map_err(|_| err("TARGET_INVALID"))?;
    let old_state: State = serde_json::from_value(transition["old_state"].clone())
        .map_err(|_| err("STATE_INVALID"))?;
    if old_state.target_sha256 != value_hash(&old_target)?
        || !old_state.authorized
        || !old_state.pending
        || old_state.next != 0
        || old_state.status != "SUBMISSION_UNKNOWN"
        || !old_state.receipts.is_empty()
    {
        return Err(err("SIGNER_REPAIR_STATE_INVALID"));
    }
    crate::release_adapter_contract::verify_adapter_reconciliation_authorization(
        &adapter_request(&old_target, &work, "reconcile", Some(&old_state))?,
    )?;
    let resource_dir = old_target
        .project
        .join(".agent-pack/release-locks")
        .join(value_hash(&json!([
            old_target.scope["network"],
            old_target.scope["wallet_address"]
        ]))?);
    let _resource_lock = lock(&resource_dir)?;
    if read::<PathBuf>(&resource_dir.join("active.json"))? != work {
        return Err(err("ACTIVE_OPERATION_UNRESOLVED"));
    }
    let config_path = work.join("native-name-update-config.json");
    let _execution_lock =
        crate::release_execute::rejected_cli_signer_lock(&config_path, &transition["old_config"])?;
    let mut target = old_target;
    target.settings["native_name_update"]["signer"] = json!(signer);
    let rejected_path = transition["old_config"]["signer"]["path"]
        .as_str()
        .ok_or_else(|| err("CONFIG_INVALID"))?;
    let rejected_pin = target
        .dependencies
        .iter_mut()
        .find(|pin| pin.path == Path::new(rejected_path))
        .ok_or_else(|| err("SIGNER_REPAIR_NATIVE_INPUT_CHANGED"))?;
    *rejected_pin = signer.clone();
    check_target(&target)?;
    check_tools(&target)?;
    let mut config = transition["old_config"].clone();
    config["signer"] = json!(signer);
    let mut state = old_state;
    let binding = state
        .plan
        .actions
        .get_mut(0)
        .and_then(|a| a.name_update_binding.as_mut())
        .ok_or_else(|| err("ABANDON_BINDING_REQUIRED"))?;
    let check = crate::release_execute::check(&config_path)?;
    let new_execution = crate::release_execute::execution_digest_with_signer(
        &config_path,
        crate::release_execute::Program {
            path: signer.path.clone(),
            sha256: signer.sha256.clone(),
        },
    )?;
    for field in [
        "review_sha256",
        "request_sha256",
        "plan_sha256",
        "signer_public_key",
    ] {
        if serde_json::to_value(&*binding).map_err(|_| err("JSON_INVALID"))?[field]
            != check["authorization_template"][field]
            || transition["old_approval"][field] != check["authorization_template"][field]
        {
            return Err(err("SIGNER_REPAIR_NATIVE_INPUT_CHANGED"));
        }
    }
    if transition["old_approval"]["execution_sha256"] != binding.execution_sha256
        || (check["authorization_template"]["execution_sha256"] != binding.execution_sha256
            && check["authorization_template"]["execution_sha256"] != new_execution)
    {
        return Err(err("SIGNER_REPAIR_NATIVE_INPUT_CHANGED"));
    }
    binding.execution_sha256 = new_execution;
    state.target_sha256 = value_hash(&target)?;
    let legacy_repair_intent =
        value_hash(&json!({"target":target,"plan":state.plan,"valid_until":state.valid_until}))?;
    let rejected_artifact = state
        .plan
        .artifacts
        .iter_mut()
        .find(|pin| pin.path == Path::new(rejected_path))
        .ok_or_else(|| err("SIGNER_REPAIR_NATIVE_INPUT_CHANGED"))?;
    *rejected_artifact = signer.clone();
    state.intent_sha256 =
        value_hash(&json!({"target":target,"plan":state.plan,"valid_until":state.valid_until}))?;
    state.authorized = false;
    state.authorization_signature = None;
    state.status = "AWAITING_CONFIRMATION".into();
    state.pending = false;
    state.reserved_fee_sompi = 0;
    let current = load(&work)?.ok_or_else(|| err("STATE_INVALID"))?;
    if current.intent_sha256 != transition["old_state"]["intent_sha256"]
        && current.intent_sha256 != legacy_repair_intent
        && current.intent_sha256 != state.intent_sha256
    {
        return Err(err("SIGNER_REPAIR_SCOPE_CHANGED"));
    }
    // Durable proof precedes removal from the active journal. A crash can resume
    // only this exact transition; original attempt and approval remain archived.
    if !transition_path.exists() {
        crate::release_execute::create_atomic_new(&transition_path, &transition)?;
    }
    let archive = work.join("rejected-cli-signer");
    fs::create_dir_all(&archive).map_err(|_| err("STATE_WRITE_FAILED"))?;
    for (path, saved, name) in [
        (
            PathBuf::from(transition["old_config"]["prepared"].as_str().unwrap())
                .join("signing-attempt.json"),
            &transition["old_attempt"],
            "signing-attempt.json",
        ),
        (
            PathBuf::from(transition["old_config"]["authorization"].as_str().unwrap()),
            &transition["old_approval"],
            "authorization.json",
        ),
    ] {
        let archived = archive.join(name);
        if archived.exists() {
            if read::<Value>(&archived)? != *saved {
                return Err(err("SIGNER_REPAIR_ARCHIVE_CHANGED"));
            }
        } else {
            crate::release_execute::create_atomic_new(&archived, saved)?;
        }
        if path.exists() {
            if read::<Value>(&path)? != *saved {
                return Err(err("SIGNER_REPAIR_SCOPE_CHANGED"));
            }
            fs::remove_file(path).map_err(|_| err("STATE_WRITE_FAILED"))?;
        }
    }
    for (path, old, new) in [
        (
            work.join("target.snapshot.json"),
            &transition["old_target"],
            serde_json::to_value(&target).map_err(|_| err("JSON_INVALID"))?,
        ),
        (config_path, &transition["old_config"], config),
    ] {
        let current: Value = read(&path)?;
        if current != *old && current != new {
            return Err(err("SIGNER_REPAIR_SCOPE_CHANGED"));
        }
        let staged = path.with_extension("repair-tmp");
        fs::write(
            &staged,
            serde_json::to_vec_pretty(&new).map_err(|_| err("JSON_INVALID"))?,
        )
        .map_err(|_| err("STATE_WRITE_FAILED"))?;
        OpenOptions::new()
            .write(true)
            .open(&staged)
            .and_then(|f| f.sync_all())
            .map_err(|_| err("STATE_WRITE_FAILED"))?;
        fs::rename(staged, path).map_err(|_| err("STATE_WRITE_FAILED"))?;
    }
    save(&work, &state)?;
    Ok(detached_authorization_result(&target, &work, &state))
}

pub fn rebind_escrow(work: &Path, copies: &[PathBuf]) -> Result<Value, String> {
    let work = if work.is_absolute() {
        work.to_owned()
    } else {
        std::env::current_dir()
            .map_err(|_| err("CWD_UNAVAILABLE"))?
            .join(work)
    };
    if copies.len() != 2 || copies[0] == copies[1] || copies.iter().any(|p| !p.is_absolute()) {
        return Err(err("ESCROW_TWO_ABSOLUTE_LOCATIONS_REQUIRED"));
    }
    let _work_lock = lock(&work)?;
    let transition_path = work.join("escrow-rebind.json");
    let transition: Value = if transition_path.exists() {
        read(&transition_path)?
    } else {
        let checkpoint = read_only_checkpoint_mode(&work, true)?;
        if !checkpoint.state.authorized
            || checkpoint.state.status != "AUTHORIZED_READY"
            || checkpoint.state.pending
            || checkpoint.state.next != 0
            || !checkpoint.state.receipts.is_empty()
        {
            return Err(err("ESCROW_REBIND_STATE_INVALID"));
        }
        json!({"schema":"KTAPEOUT-ESCROW-REBIND-V1", "old_target":checkpoint.target,
            "old_state":checkpoint.state, "old_config":read::<Value>(&work.join("native-name-update-config.json"))?,
            "copies":copies, "valid_until":checkpoint.state.valid_until})
    };
    if transition["schema"] != "KTAPEOUT-ESCROW-REBIND-V1" || transition["copies"] != json!(copies)
    {
        return Err(err("ESCROW_REBIND_SCOPE_CHANGED"));
    }
    let old_target: Target = serde_json::from_value(transition["old_target"].clone())
        .map_err(|_| err("TARGET_INVALID"))?;
    let old_state: State = serde_json::from_value(transition["old_state"].clone())
        .map_err(|_| err("STATE_INVALID"))?;
    check_target(&old_target)?;
    if old_state.target_sha256 != value_hash(&old_target)?
        || !old_state.authorized
        || old_state.pending
        || old_state.next != 0
        || old_state.status != "AUTHORIZED_READY"
    {
        return Err(err("ESCROW_REBIND_STATE_INVALID"));
    }
    crate::release_adapter_contract::verify_adapter_reconciliation_authorization(
        &adapter_request(&old_target, &work, "reconcile", Some(&old_state))?,
    )?;
    let resource_dir = old_target
        .project
        .join(".agent-pack/release-locks")
        .join(value_hash(&json!([
            old_target.scope["network"],
            old_target.scope["wallet_address"]
        ]))?);
    let _resource_lock = lock(&resource_dir)?;
    let active_path = resource_dir.join("active.json");
    if active_path.exists() && read::<PathBuf>(&active_path)? != work {
        return Err(err("ACTIVE_OPERATION_UNRESOLVED"));
    }
    let config_path = work.join("native-name-update-config.json");
    let _execution_lock = crate::release_execute::unattempted_lock(&config_path)?;
    if let Some(approval) = transition["old_config"]["authorization"].as_str() {
        let approval = PathBuf::from(approval);
        let approval = if approval.is_absolute() {
            approval
        } else {
            work.join(approval)
        };
        if approval.exists() {
            return Err(err("ESCROW_REBIND_NATIVE_APPROVAL_ALREADY_EXISTS"));
        }
    }
    let mut target = old_target;
    target.settings["native_name_update"]["escrow_copies"] = json!(copies);
    check_target(&target)?;
    let mut config = transition["old_config"].clone();
    config["escrow_copies"] = json!(copies);
    let mut state = old_state;
    let binding = state
        .plan
        .actions
        .get_mut(0)
        .and_then(|a| a.name_update_binding.as_mut())
        .ok_or_else(|| err("ABANDON_BINDING_REQUIRED"))?;
    let old_check = crate::release_execute::check(&config_path)?;
    let new_execution = crate::release_execute::execution_digest_with_copies(&config_path, copies)?;
    for field in [
        "review_sha256",
        "request_sha256",
        "plan_sha256",
        "signer_public_key",
    ] {
        if serde_json::to_value(&*binding).map_err(|_| err("JSON_INVALID"))?[field]
            != old_check["authorization_template"][field]
        {
            return Err(err("ESCROW_REBIND_NATIVE_INPUT_CHANGED"));
        }
    }
    if old_check["authorization_template"]["execution_sha256"] != binding.execution_sha256
        && old_check["authorization_template"]["execution_sha256"] != new_execution
    {
        return Err(err("ESCROW_REBIND_NATIVE_INPUT_CHANGED"));
    }
    binding.execution_sha256 = new_execution;
    state.valid_until = transition["valid_until"]
        .as_u64()
        .ok_or_else(|| err("AUTHORIZATION_INVALID"))?
        .min(state.valid_until);
    state.target_sha256 = value_hash(&target)?;
    state.intent_sha256 =
        value_hash(&json!({"target":target,"plan":state.plan,"valid_until":state.valid_until}))?;
    state.authorized = false;
    state.authorization_signature = None;
    state.status = "AWAITING_CONFIRMATION".into();
    state.reserved_fee_sompi = 0;
    let current_state = load(&work)?.ok_or_else(|| err("STATE_INVALID"))?;
    if current_state.intent_sha256 != transition["old_state"]["intent_sha256"]
        && current_state.intent_sha256 != state.intent_sha256
    {
        return Err(err("ESCROW_REBIND_SCOPE_CHANGED"));
    }
    if let Ok(current) = read_only_checkpoint(&work) {
        if current.state.intent_sha256 == state.intent_sha256 && current.state.authorized {
            return Ok(result(&current.target, &work, &current.state));
        }
    }
    for (path, old, new) in [
        (
            work.join("target.snapshot.json"),
            &transition["old_target"],
            serde_json::to_value(&target).map_err(|_| err("JSON_INVALID"))?,
        ),
        (config_path, &transition["old_config"], config),
    ] {
        let current: Value = read(&path)?;
        if current != *old && current != new {
            return Err(err("ESCROW_REBIND_SCOPE_CHANGED"));
        }
        if !transition_path.exists() {
            crate::release_execute::create_atomic_new(&transition_path, &transition)?;
        }
        let staged = path.with_extension("rebind-tmp");
        fs::write(
            &staged,
            serde_json::to_vec_pretty(&new).map_err(|_| err("JSON_INVALID"))?,
        )
        .map_err(|_| err("STATE_WRITE_FAILED"))?;
        OpenOptions::new()
            .write(true)
            .open(&staged)
            .and_then(|f| f.sync_all())
            .map_err(|_| err("STATE_WRITE_FAILED"))?;
        fs::rename(staged, path).map_err(|_| err("STATE_WRITE_FAILED"))?;
    }
    // A partial state append is repaired by load before appending the new checkpoint.
    let _ = load(&work)?;
    save(&work, &state)?;
    Ok(detached_authorization_result(&target, &work, &state))
}

/// Export the exact domain-separated message for an external workflow-authority signer.
/// This is read-only and does not authorize, sign, or invoke the release adapter.
pub fn authorization_request(work: &Path) -> Result<Value, String> {
    let checkpoint = read_only_checkpoint(work)?;
    let target = &checkpoint.target;
    let state = &checkpoint.state;
    if state.status != "AWAITING_CONFIRMATION"
        || state.authorized
        || state.authorization_signature.is_some()
        || state.next != 0
        || !state.receipts.is_empty()
        || state.pending
    {
        return Err(err("AUTHORIZATION_REQUEST_STATE_INVALID"));
    }
    if now() > state.valid_until {
        return Err(err("AUTHORIZATION_EXPIRED"));
    }
    let planned_fee = state
        .plan
        .actions
        .iter()
        .try_fold(0u64, |sum, action| sum.checked_add(action.fee_sompi))
        .ok_or_else(|| err("BUDGET_EXCEEDED"))?;
    if planned_fee > target.max_fee_sompi {
        return Err(err("BUDGET_EXCEEDED"));
    }
    let mut message = b"KTAPEOUT/RELEASE-AUTHORIZATION/V1\0".to_vec();
    message.extend_from_slice(state.intent_sha256.as_bytes());
    let plan_sha256 = value_hash(&state.plan)?;
    Ok(json!({
        "schema":"KTAPEOUT-RELEASE-AUTHORIZATION-REQUEST-V1",
        "read_only":true,
        "requires_human_authorization":true,
        "signature_algorithm":"Ed25519",
        "domain":"KTAPEOUT/RELEASE-AUTHORIZATION/V1",
        "signable_message_hex":hex::encode(message),
        "intent_sha256":state.intent_sha256,
        "plan_sha256":plan_sha256,
        "network":target.scope.get("network"),
        "application_uri":target.application_candidate.as_ref().map(|binding| binding.application_uri.as_str()).or_else(|| target.scope["application_uri"].as_str()),
        "release_id":state.plan.release_id,
        "scope":target.scope,
        "planned_actions":state.plan.actions,
        "plan_summary":state.plan.summary,
        "planned_fee_sompi":planned_fee,
        "max_fee_sompi":target.max_fee_sompi,
        "valid_until":state.valid_until,
        "workflow_authority_public_key":target.scope.get("workflow_authority_public_key")
    }))
}

/// Sign only a prepared workflow intent with an explicitly selected local key.
/// This does not authorize transaction signing, invoke adapters, or submit anything.
#[cfg(feature = "publisher-signing")]
pub fn sign_authorization(work: &Path, signing_key: &Path, output: &Path) -> Result<Value, String> {
    workflow_signing::sign_authorization(work, signing_key, output)
}

/// Import a detached workflow-authority signature for a prepared operation.
/// This validates and records authorization only; it never invokes the adapter,
/// native transaction signer, submitter, or network.
pub fn import_authorization(work: &Path, signed_request_path: &Path) -> Result<Value, String> {
    let work = if work.is_absolute() {
        work.to_owned()
    } else {
        std::env::current_dir()
            .map_err(|_| err("CWD_UNAVAILABLE"))?
            .join(work)
    };
    let _lock = lock(&work)?;
    let checkpoint = read_only_checkpoint(&work)?;
    if checkpoint.incomplete_tail_preserved {
        return Err(err("STATE_INCOMPLETE"));
    }
    let target = checkpoint.target;
    let mut state = checkpoint.state;
    if state.schema != "KTAPEOUT-RELEASE-STATE-V1"
        || state.status != "AWAITING_CONFIRMATION"
        || state.authorized
        || state.authorization_signature.is_some()
        || state.next != 0
        || !state.receipts.is_empty()
        || state.pending
        || state.reserved_fee_sompi != 0
    {
        return Err(err("AUTHORIZATION_IMPORT_STATE_INVALID"));
    }
    if value_hash(&target)? != state.target_sha256
        || state.intent_sha256
            != value_hash(
                &json!({"target":target,"plan":state.plan,"valid_until":state.valid_until}),
            )?
    {
        return Err(err("SCOPE_CHANGED"));
    }
    check_plan(&target, &state.plan)?;
    if now() > state.valid_until {
        return Err(err("AUTHORIZATION_EXPIRED"));
    }
    let signed: ImportedAuthorization = serde_json::from_value(read(signed_request_path)?)
        .map_err(|_| err("AUTHORIZATION_IMPORT_INVALID"))?;
    if signed.schema != "KTAPEOUT-RELEASE-AUTHORIZATION-SIGNATURE-V1"
        || signed.intent_sha256 != state.intent_sha256
        || signed.plan_sha256 != value_hash(&state.plan)?
        || signed.signature.len() != 128
        || !signed
            .signature
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(err("AUTHORIZATION_SCOPE_MISMATCH"));
    }
    state.authorization_signature = Some(signed.signature);
    verify_authorization(&target, &state)?;
    state.authorized = true;
    state.status = "AUTHORIZED_READY".into();
    save(&work, &state)?;
    Ok(json!({
        "schema":"KTAPEOUT-RELEASE-AUTHORIZATION-IMPORT-V1",
        "status":state.status,
        "authorized":state.authorized,
        "intent_sha256":state.intent_sha256,
        "release_id":state.plan.release_id,
        "workdir":work,
        "adapter_invoked":false,
        "transaction_signed":false,
        "transaction_submitted":false
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportedAuthorization {
    schema: String,
    intent_sha256: String,
    plan_sha256: String,
    signature: String,
}
// Kernel lock is released on process death; no stale-lock removal or operator intervention.
fn lock(work: &Path) -> Result<fs::File, String> {
    fs::create_dir_all(work).map_err(|_| err("WORKDIR_UNAVAILABLE"))?;
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(work.join("run.lock"))
        .map_err(|_| err("LOCK_UNAVAILABLE"))?;
    file.try_lock().map_err(|_| err("OPERATION_LOCKED"))?;
    Ok(file)
}
fn authorization_projection(
    authorized: bool,
    target: &Target,
    plan: &Plan,
    intent_sha256: &str,
    signature: Option<&str>,
    valid_until: u64,
) -> Result<Value, String> {
    if !authorized {
        return Ok(Value::Null);
    }
    Ok(json!({
        "intent_sha256":intent_sha256,
        "signature":signature.ok_or_else(|| err("AUTHORIZATION_INVALID"))?,
        "valid_until":valid_until,
        "plan_sha256":value_hash(plan)?,
        "max_fee_sompi":target.max_fee_sompi
    }))
}

fn adapter_request(
    t: &Target,
    work: &Path,
    phase: &str,
    state: Option<&State>,
) -> Result<Value, String> {
    let authorization = state
        .map(|s| {
            authorization_projection(
                s.authorized,
                t,
                &s.plan,
                &s.intent_sha256,
                s.authorization_signature.as_deref(),
                s.valid_until,
            )
        })
        .transpose()?
        .unwrap_or(Value::Null);
    Ok(json!({
        "schema":"KTAPEOUT-RELEASE-ADAPTER-REQUEST-V2",
        "phase":phase,
        "target":t,
        "workdir":work,
        "intent_sha256":state.map(|s| &s.intent_sha256),
        "valid_until":state.map(|s| s.valid_until),
        "plan":state.map(|s| &s.plan),
        "action":state.and_then(|s| s.plan.actions.get(s.next)),
        // Durable pending is written before dispatch to survive a crash. On a fresh execute
        // request it is a reservation, not an uncertain previous attempt. Only reconcile
        // carries that uncertainty across the adapter boundary.
        "pending":phase != "execute" && state.map(|s|s.pending).unwrap_or(false),
        "receipts":state.map(|s| &s.receipts),
        "authorization":authorization
    }))
}

/// Verified high-level release authorization exposed to a statically pinned adapter.
/// This is an intent approval, not a native transaction signature or wallet capability.
pub use crate::release_adapter_contract::VerifiedAdapterAuthorization;

/// Verify the coordinator envelope at the adapter boundary instead of trusting fields merely
/// because the coordinator passed them in a request file. The authorization binds the exact
/// frozen target and plan; adapters must still run native plan/preflight/approval checks.
pub fn verify_adapter_authorization(
    request: &Value,
) -> Result<VerifiedAdapterAuthorization, String> {
    crate::release_adapter_contract::verify_adapter_authorization(request)
}

fn call(t: &Target, work: &Path, phase: &str, state: Option<&State>) -> Result<Value, String> {
    check_target(t)?;
    check_tools(t)?;
    let request = adapter_request(t, work, phase, state)?;
    if !t.execution_line.is_empty() {
        crate::release_adapter_contract::validate_adapter_request(&request)?;
    }
    let request_path = work.join("adapter-request.json");
    let response_path = work.join("adapter-response.json");
    fs::write(
        &request_path,
        serde_json::to_vec(&request).map_err(|_| err("JSON_INVALID"))?,
    )
    .map_err(|_| err("REQUEST_WRITE_FAILED"))?;
    if response_path.exists() {
        fs::remove_file(&response_path).map_err(|_| err("RESPONSE_RESET_FAILED"))?;
    }
    let log_id = format!(
        "{}-{}-{}",
        phase,
        state
            .and_then(|s| s.plan.actions.get(s.next))
            .map(|a| a.id.as_str())
            .unwrap_or("release"),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    );
    let stdout = fs::File::create(work.join(format!("{log_id}.stdout.log")))
        .map_err(|_| err("LOG_UNAVAILABLE"))?;
    let stderr = fs::File::create(work.join(format!("{log_id}.stderr.log")))
        .map_err(|_| err("LOG_UNAVAILABLE"))?;
    // Host bridges are deliberately kept outside the Rust binary so their credentials remain
    // on the Host. The bridge itself is still pinned by the adapter digest; Rust remains the
    // public workflow entry point and owns authorization, locks and recovery.
    let mut command = adapter_process_command(&t.adapter.path)?;
    command
        .args(&t.arguments)
        .arg(&request_path)
        .arg(&response_path)
        .current_dir(&t.project)
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr);
    configure_adapter_environment(&mut command, work);
    let mut child = command.spawn().map_err(|_| err("ADAPTER_SPAWN_FAILED"))?;
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait().map_err(|_| err("ADAPTER_WAIT_FAILED"))? {
            if !status.success() {
                return Err(err("ADAPTER_FAILED_CHECK_LOG"));
            }
            break;
        }
        if started.elapsed() > Duration::from_secs(t.timeout_seconds) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(err("ADAPTER_TIMEOUT"));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let response: Value = read(&response_path)?;
    if response["schema"] != "KTAPEOUT-RELEASE-ADAPTER-RESPONSE-V1" {
        return Err(err("ADAPTER_RESPONSE_INVALID"));
    }
    Ok(response)
}

fn adapter_process_command(path: &Path) -> Result<Command, String> {
    #[cfg(feature = "host-bridges")]
    {
        crate::host_bridges::adapter_process_command(path)
    }
    #[cfg(not(feature = "host-bridges"))]
    {
        Ok(Command::new(path))
    }
}

fn timed_call(t: &Target, work: &Path, phase: &str, state: &mut State) -> Result<Value, String> {
    let key = if matches!(phase, "execute" | "reconcile") {
        state
            .plan
            .actions
            .get(state.next)
            .map(|action| format!("{phase}:{}", action.id))
            .unwrap_or_else(|| phase.to_string())
    } else {
        phase.to_string()
    };
    let started = Instant::now();
    let result = call(t, work, phase, Some(state));
    let elapsed = started.elapsed().as_millis().min(u64::MAX as u128) as u64;
    let timing = state.timings_ms.entry(key.clone()).or_default();
    *timing = timing.saturating_add(elapsed);
    let attempts = state.timing_attempts.entry(key.clone()).or_default();
    *attempts = attempts.saturating_add(1);
    state.last_timings_ms.insert(key, elapsed);
    save(work, state)?;
    result
}
fn verify_authorization(t: &Target, s: &State) -> Result<(), String> {
    let authorization = authorization_projection(
        true,
        t,
        &s.plan,
        &s.intent_sha256,
        s.authorization_signature.as_deref(),
        s.valid_until,
    )?;
    verify_adapter_authorization(&json!({
        "schema":"KTAPEOUT-RELEASE-ADAPTER-REQUEST-V2",
        "phase":"execute",
        "target":t,
        "plan":s.plan,
        "authorization":authorization
    }))?;
    Ok(())
}
fn result(t: &Target, work: &Path, s: &State) -> Value {
    let latest_preflight = s
        .evidence
        .iter()
        .rev()
        .find(|e| e.stage == "host-preflight");
    let workflow_complete = s.status == "COMPLETE" || s.status == "NOOP";
    let name_update_only =
        t.schema == "KTAPEOUT-RELEASE-TARGET-V3" && t.execution_line == "name-controller";
    let publisher_line =
        t.schema == "KTAPEOUT-RELEASE-TARGET-V2" && t.execution_line == "publisher";
    let combined_publisher_name_controller_line =
        t.schema == "KTAPEOUT-RELEASE-TARGET-V4" && t.execution_line == "name-controller";
    let host_activation_receipt = s
        .plan
        .actions
        .iter()
        .position(|action| action.kind.as_deref() == Some("host-activate"))
        .filter(|index| *index < s.next)
        .is_some_and(|index| {
            let Some(action) = s.plan.actions.get(index) else {
                return false;
            };
            let Some(receipt) = s.receipts.get(index) else {
                return false;
            };
            receipt["status"] == "COMPLETE"
                && receipt["action_id"].as_str() == Some(action.id.as_str())
                && receipt["intent_sha256"].as_str() == Some(s.intent_sha256.as_str())
                && receipt["fee_sompi"].as_u64() == Some(action.fee_sompi)
                && validate_effect_evidence(t, action, "execute", receipt).is_ok()
        });
    let host_record_publish_receipt = s
        .plan
        .actions
        .iter()
        .position(|action| action.kind.as_deref() == Some("host-record-publish"))
        .filter(|index| *index < s.next)
        .is_some_and(|index| {
            let Some(action) = s.plan.actions.get(index) else {
                return false;
            };
            let Some(receipt) = s.receipts.get(index) else {
                return false;
            };
            receipt["status"] == "COMPLETE"
                && receipt["action_id"].as_str() == Some(action.id.as_str())
                && receipt["intent_sha256"].as_str() == Some(s.intent_sha256.as_str())
                && receipt["fee_sompi"].as_u64() == Some(action.fee_sompi)
                && validate_effect_evidence(t, action, "execute", receipt).is_ok()
        });
    let publisher_delivery_complete = (!publisher_line || host_activation_receipt)
        && (!combined_publisher_name_controller_line || host_record_publish_receipt);
    json!({"schema":"KTAPEOUT-PUBLISH-SHIP-V2", "status":s.status,
        "workflow_complete":workflow_complete,
        "delivery_complete":workflow_complete && !name_update_only && publisher_delivery_complete,
        "delivery_next_step":if workflow_complete && name_update_only { Some("BUILD_VERIFIED_RECEIPT_AND_PUBLISH_RESOURCES") } else if workflow_complete && publisher_line && !host_activation_receipt { Some("HOST_ACTIVATION_REQUIRED") } else if workflow_complete && combined_publisher_name_controller_line && !host_record_publish_receipt { Some("HOST_RECORD_PUBLISH_REQUIRED") } else { None },
        "intent_sha256":s.intent_sha256,"release_id":s.plan.release_id,"workdir":work,"next_action":s.plan.actions.get(s.next),
        "reserved_fee_sompi":s.reserved_fee_sompi,"authorized":s.authorized,"summary":s.plan.summary,
        "timings_ms":s.timings_ms,"timing_attempts":s.timing_attempts,"last_timings_ms":s.last_timings_ms,
        "capabilities":{"release_host_preflight":latest_preflight.map(|e| json!({"status":e.outcome,"observed_at":e.observed_at,"evidence_sha256":e.evidence_sha256,"items":e.capabilities})).unwrap_or(json!({"status":"NOT_CHECKED","items":[]}))},
        "evidence":s.evidence,
        "completed_actions":s.next,"resume_argv":[if t.execution_line.is_empty() { "publish" } else { "release" },"ship","--resume",work]})
}

fn detached_authorization_result(t: &Target, work: &Path, s: &State) -> Value {
    let mut output = result(t, work, s);
    output["authorization_next_step"] = json!({
        "mode":"COORDINATOR_DETACHED",
        "request_command":["ktape", "release", "authorization-request", "--workdir", work],
        "import_command":["ktape", "release", "authorization-import", "--workdir", work, "--signature", "<signed-envelope.json>"],
        "resume_command":["ktape", "release", "ship", "--resume", work],
        "adapter_signing":false,
        "network_effects":false
    });
    output["authorization_mode"] = json!(if coordinator_manages_authorization(t) {
        "COORDINATOR_DETACHED"
    } else {
        "ADAPTER"
    });
    output
}
pub fn default_workdir(target: &Target) -> Result<PathBuf, String> {
    Ok(target
        .project
        .join(".agent-pack/releases")
        .join(value_hash(target)?))
}

/// Compose the existing detached authorization protocol; never pass the key to an adapter.
pub fn run_target_with_authority(
    target: Target,
    work: &Path,
    prepare_only: bool,
    authority_key: Option<&Path>,
) -> Result<Value, String> {
    if authority_key.is_none() {
        return run_target(target, work, prepare_only);
    }
    run_target_with_authority_confirmation(
        target,
        work,
        prepare_only,
        authority_key,
        confirm_publication,
    )
}

fn confirm_publication() -> Result<bool, String> {
    if !std::io::stdin().is_terminal() {
        return Ok(false);
    }
    eprint!("Publish this scope within the cumulative budget? Type publish: ");
    std::io::stderr()
        .flush()
        .map_err(|_| err("CONSOLE_FAILED"))?;
    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .map_err(|_| err("CONSOLE_FAILED"))?;
    Ok(answer.trim() == "publish")
}

#[cfg(not(feature = "publisher-signing"))]
fn run_target_with_authority_confirmation(
    target: Target,
    work: &Path,
    prepare_only: bool,
    authority_key: Option<&Path>,
    confirm: impl FnOnce() -> Result<bool, String>,
) -> Result<Value, String> {
    if authority_key.is_some() {
        return Err(err("LOCAL_SIGNING_UNAVAILABLE"));
    }
    run_with_target_confirmation(target, work, prepare_only, confirm)
}

#[cfg(feature = "publisher-signing")]
fn run_target_with_authority_confirmation(
    target: Target,
    work: &Path,
    prepare_only: bool,
    authority_key: Option<&Path>,
    confirm: impl FnOnce() -> Result<bool, String>,
) -> Result<Value, String> {
    let Some(key) = authority_key.filter(|_| !prepare_only) else {
        return run_with_target_confirmation(target, work, prepare_only, confirm);
    };
    let prepared = run_with_target_confirmation(target.clone(), work, true, || Ok(false))?;
    if matches!(
        prepared["status"].as_str(),
        Some("COMPLETE" | "NOOP" | "ABORTED")
    ) {
        return Ok(prepared);
    }
    if prepared["authorized"] != true {
        let request = authorization_request(work)?;
        eprintln!("Release authorization: {}", request);
        if !confirm()? {
            return Ok(prepared);
        }
        let intent = request["intent_sha256"]
            .as_str()
            .ok_or_else(|| err("INTENT_INVALID"))?;
        let signature = work.join(format!("authorization-{intent}.json"));
        if !signature.exists() {
            sign_authorization(work, key, &signature)?;
        }
        import_authorization(work, &signature)?;
    }
    run_with_target_confirmation(target, work, false, || Ok(false))
}

pub fn run_target(target: Target, work: &Path, prepare_only: bool) -> Result<Value, String> {
    run_with_target_confirmation(target, work, prepare_only, || {
        if !std::io::stdin().is_terminal() {
            return Ok(false);
        }
        eprint!("Publish this scope within the cumulative budget? Type publish: ");
        std::io::stderr()
            .flush()
            .map_err(|_| err("CONSOLE_FAILED"))?;
        let mut answer = String::new();
        std::io::stdin()
            .read_line(&mut answer)
            .map_err(|_| err("CONSOLE_FAILED"))?;
        Ok(answer.trim() == "publish")
    })
}

fn refresh_preflight(t: &Target, work: &Path, s: &mut State) -> Result<(), String> {
    let response = timed_call(t, work, "preflight", s);
    let observations = response
        .as_ref()
        .ok()
        .map(|value| capability_observations(t, s, value))
        .transpose();
    let gate = match &observations {
        Ok(Some(items)) => check_required_capabilities(t, &s.plan, items),
        Ok(None) if required_capabilities_for_plan(t, &s.plan)?.is_empty() => Ok(()),
        Ok(None) => Err(err("CAPABILITY_UNKNOWN")),
        Err(error) => Err(error.clone()),
    };
    let outcome = if response.is_err() || observations.is_err() {
        "UNKNOWN"
    } else if gate.is_err()
        || !response
            .as_ref()
            .is_ok_and(|value| value["status"] == "PASS")
    {
        "BLOCKED"
    } else {
        "AVAILABLE"
    };
    let items = observations
        .as_ref()
        .ok()
        .and_then(|items| items.clone())
        .unwrap_or_default();
    s.evidence.push(preflight_evidence(t, s, outcome, items)?);
    if s.evidence.len() > 64 {
        s.evidence.drain(..s.evidence.len() - 64);
    }
    save(work, s)?;
    if response?["status"] != "PASS" {
        return Err(err("PREFLIGHT_FAILED"));
    }
    observations?;
    gate
}
fn run_with_target_confirmation(
    t: Target,
    work: &Path,
    prepare_only: bool,
    confirm: impl FnOnce() -> Result<bool, String>,
) -> Result<Value, String> {
    let work = if work.is_absolute() {
        work.to_owned()
    } else {
        std::env::current_dir()
            .map_err(|_| err("CWD_UNAVAILABLE"))?
            .join(work)
    };
    check_target(&t)?;
    let _lock = lock(&work)?;
    eprintln!("Release operation: {}", work.display());
    // Serialize operations sharing a wallet, even when their operation directories differ.
    let resource_dir = t
        .project
        .join(".agent-pack/release-locks")
        .join(value_hash(&json!([
            t.scope["network"],
            t.scope["wallet_address"]
        ]))?);
    let _resource_lock = lock(&resource_dir)?;
    let active_path = resource_dir.join("active.json");
    let target_hash = value_hash(&t)?;
    let snapshot = work.join("target.snapshot.json");
    if snapshot.exists() {
        let frozen: Target = read(&snapshot).map_err(|_| err("SCOPE_CHANGED"))?;
        if check_target(&frozen).is_err() || value_hash(&frozen)? != target_hash {
            return Err(err("SCOPE_CHANGED"));
        }
    } else {
        fs::write(
            &snapshot,
            serde_json::to_vec_pretty(&t).map_err(|_| err("JSON_INVALID"))?,
        )
        .map_err(|_| err("STATE_WRITE_FAILED"))?;
    }
    let mut s = if let Some(s) = load(&work)? {
        s
    } else {
        let (previous_attempts, _, _) = if work.join("prepare-attempts.jsonl").exists() {
            prepare_attempt_summary(&work, &target_hash)?
        } else {
            (0, 0, 0)
        };
        let attempt = previous_attempts.saturating_add(1);
        let started_at = now();
        append_prepare_attempt(
            &work,
            &PrepareAttempt {
                schema: "KTAPEOUT-RELEASE-PREPARE-ATTEMPT-V1".into(),
                target_sha256: target_hash.clone(),
                attempt,
                status: "STARTED".into(),
                started_at,
                elapsed_ms: None,
                error_code: None,
            },
        )?;
        let started = Instant::now();
        let prepared = (|| {
            let response = call(&t, &work, "prepare", None)?;
            let plan: Plan = serde_json::from_value(response["plan"].clone())
                .map_err(|_| err("PLAN_INVALID"))?;
            check_plan(&t, &plan)?;
            Ok::<Plan, String>(plan)
        })();
        let prepare_ms = started.elapsed().as_millis().min(u64::MAX as u128) as u64;
        let completion = match &prepared {
            Ok(_) => PrepareAttempt {
                schema: "KTAPEOUT-RELEASE-PREPARE-ATTEMPT-V1".into(),
                target_sha256: target_hash.clone(),
                attempt,
                status: "SUCCEEDED".into(),
                started_at,
                elapsed_ms: Some(prepare_ms),
                error_code: None,
            },
            Err(error) => PrepareAttempt {
                schema: "KTAPEOUT-RELEASE-PREPARE-ATTEMPT-V1".into(),
                target_sha256: target_hash.clone(),
                attempt,
                status: "FAILED".into(),
                started_at,
                elapsed_ms: Some(prepare_ms),
                error_code: Some(safe_prepare_error_code(error)),
            },
        };
        append_prepare_attempt(&work, &completion)?;
        let plan = prepared?;
        let (prepare_attempts, total_prepare_ms, last_prepare_ms) =
            prepare_attempt_summary(&work, &target_hash)?;
        let valid_until = now() + t.authorization_ttl_seconds;
        let intent_hash = value_hash(&json!({"target":t,"plan":plan,"valid_until":valid_until}))?;
        let s = State {
            schema: "KTAPEOUT-RELEASE-STATE-V1".into(),
            target_sha256: target_hash.clone(),
            intent_sha256: intent_hash,
            plan,
            authorized: false,
            authorization_signature: None,
            valid_until,
            status: "AWAITING_CONFIRMATION".into(),
            next: 0,
            reserved_fee_sompi: 0,
            pending: false,
            receipts: vec![],
            timings_ms: std::collections::BTreeMap::from([("prepare".into(), total_prepare_ms)]),
            timing_attempts: std::collections::BTreeMap::from([(
                "prepare".into(),
                prepare_attempts,
            )]),
            last_timings_ms: std::collections::BTreeMap::from([(
                "prepare".into(),
                last_prepare_ms,
            )]),
            evidence: vec![],
        };
        save(&work, &s)?;
        s
    };
    if s.target_sha256 != target_hash
        || s.intent_sha256
            != value_hash(&json!({"target":t,"plan":s.plan,"valid_until":s.valid_until}))?
        || s.next > s.plan.actions.len()
        || s.receipts.len() != s.next
    {
        return Err(err("SCOPE_CHANGED"));
    }
    check_plan(&t, &s.plan)?;
    if s.authorized {
        if s.pending || matches!(s.status.as_str(), "COMPLETE" | "NOOP" | "ABORTED_NO_EFFECT") {
            crate::release_adapter_contract::verify_adapter_reconciliation_authorization(
                &adapter_request(&t, &work, "reconcile", Some(&s))?,
            )?;
        } else {
            verify_authorization(&t, &s)?;
        }
    }
    if s.status == "ABORTED_NO_EFFECT" {
        return Ok(result(&t, &work, &s));
    }
    if s.status == "COMPLETE" {
        return Ok(result(&t, &work, &s));
    }
    if s.status == "ROLLED_BACK" {
        let restart = s
            .plan
            .actions
            .iter()
            .position(|a| a.id == "host-activate" && a.retry_safe)
            .ok_or_else(|| err("ROLLBACK_RESUME_UNAVAILABLE"))?;
        s.next = restart;
        s.receipts.truncate(restart);
        s.status = "RUNNING".into();
        save(&work, &s)?;
    }
    // A pending effect must be reconciled even if its spent inputs no longer pass preflight.
    // No new effect is permitted by this path; a later fresh action still needs preflight.
    let reconcile_only = s.pending
        && s.plan
            .actions
            .get(s.next)
            .is_some_and(|action| action.effect);
    if !reconcile_only {
        refresh_preflight(&t, &work, &mut s)?;
    }
    if s.plan.unchanged {
        s.status = "NOOP".into();
        save(&work, &s)?;
        return Ok(result(&t, &work, &s));
    }
    if active_path.exists() {
        let owner: PathBuf = read(&active_path)?;
        if owner != work {
            let previous = load(&owner)?.ok_or_else(|| err("ACTIVE_OPERATION_UNRESOLVED"))?;
            if previous.status != "COMPLETE" && previous.status != "NOOP" {
                return Err(format!(
                    "{}:{}",
                    err("ACTIVE_OPERATION_UNRESOLVED"),
                    owner.display()
                ));
            }
        }
    }
    if prepare_only {
        return Ok(if coordinator_manages_authorization(&t) {
            detached_authorization_result(&t, &work, &s)
        } else {
            result(&t, &work, &s)
        });
    }
    if !s.authorized {
        if now() > s.valid_until {
            return Err(err("AUTHORIZATION_EXPIRED"));
        }
        eprintln!("{}",serde_json::to_string_pretty(&json!({"scope":t.scope,"release":s.plan.release_id,"summary":s.plan.summary,
            "planned_fee_sompi":s.plan.actions.iter().map(|a|a.fee_sompi).sum::<u64>(),"cumulative_cap_sompi":t.max_fee_sompi,
            "valid_until":s.valid_until,"intent_sha256":s.intent_sha256})).map_err(|_|err("JSON_INVALID"))?);
        if !confirm()? {
            return Ok(result(&t, &work, &s));
        }
        if coordinator_manages_authorization(&t) {
            return Ok(detached_authorization_result(&t, &work, &s));
        }
        let authorization = call(&t, &work, "authorize", Some(&s))?;
        if authorization["intent_sha256"] != s.intent_sha256 {
            return Err(err("AUTHORIZATION_INVALID"));
        }
        s.authorization_signature = authorization["signature"].as_str().map(str::to_owned);
        verify_authorization(&t, &s)?;
        s.authorized = true;
        s.status = "RUNNING".into();
        save(&work, &s)?;
    }
    fs::write(
        &active_path,
        serde_json::to_vec(&work).map_err(|_| err("JSON_INVALID"))?,
    )
    .map_err(|_| err("STATE_WRITE_FAILED"))?;
    let mut needs_preflight = reconcile_only;
    while s.next < s.plan.actions.len() {
        if needs_preflight && !s.pending {
            refresh_preflight(&t, &work, &mut s)?;
            needs_preflight = false;
        }
        let started = Instant::now();
        for receipt in &s.receipts {
            if let Some(pins) = receipt.get("artifacts") {
                let pins: Vec<Pin> = serde_json::from_value(pins.clone())
                    .map_err(|_| err("RECEIPT_ARTIFACTS_INVALID"))?;
                for pin in pins {
                    check_pin(&pin)?;
                }
            }
        }
        let action = s.plan.actions[s.next].clone();
        eprintln!(
            "[{}/{}] {}{}",
            s.next + 1,
            s.plan.actions.len(),
            action.id,
            if s.pending { " (resume)" } else { "" }
        );
        // Reconcile uncertain effects before even considering another signature/submission.
        let (response, response_phase) = if s.pending && action.effect {
            let r = timed_call(&t, &work, "reconcile", &mut s)?;
            if validate_effect_evidence(&t, &action, "reconcile", &r).is_err()
                && !t.execution_line.is_empty()
            {
                s.status = "SUBMISSION_UNKNOWN".into();
                save(&work, &s)?;
                return Ok(result(&t, &work, &s));
            }
            if r["status"] == "RETRY_SAFE" && action.retry_safe && now() <= s.valid_until {
                (timed_call(&t, &work, "execute", &mut s)?, "execute")
            } else if r["status"] == "COMPLETE" {
                (r, "reconcile")
            } else {
                s.status = "SUBMISSION_UNKNOWN".into();
                save(&work, &s)?;
                return Ok(result(&t, &work, &s));
            }
        } else {
            if now() > s.valid_until {
                return Err(err("AUTHORIZATION_EXPIRED"));
            }
            check_plan(&t, &s.plan)?;
            if !s.pending {
                s.reserved_fee_sompi = s
                    .reserved_fee_sompi
                    .checked_add(action.fee_sompi)
                    .filter(|n| *n <= t.max_fee_sompi)
                    .ok_or_else(|| err("BUDGET_EXCEEDED"))?;
                s.pending = true;
                save(&work, &s)?;
            }
            match timed_call(&t, &work, "execute", &mut s) {
                Ok(r) => (r, "execute"),
                Err(e) => {
                    s.status = if action.effect {
                        "SUBMISSION_UNKNOWN"
                    } else {
                        "RETRYABLE"
                    }
                    .into();
                    save(&work, &s)?;
                    return Err(e);
                }
            }
        };
        if validate_effect_evidence(&t, &action, response_phase, &response).is_err()
            && !t.execution_line.is_empty()
        {
            s.status = "SUBMISSION_UNKNOWN".into();
            save(&work, &s)?;
            return Ok(result(&t, &work, &s));
        }
        if response["status"] == "ROLLED_BACK"
            && response["intent_sha256"] == s.intent_sha256
            && response["action_id"] == action.id
        {
            s.status = "ROLLED_BACK".into();
            s.pending = false;
            save(&work, &s)?;
            return Ok(result(&t, &work, &s));
        }
        if response["status"] != "COMPLETE"
            || response["intent_sha256"] != s.intent_sha256
            || response["action_id"] != action.id
            || response["fee_sompi"].as_u64() != Some(action.fee_sompi)
        {
            s.status = if action.effect {
                "SUBMISSION_UNKNOWN"
            } else {
                "RETRYABLE"
            }
            .into();
            save(&work, &s)?;
            return Err(err("ACTION_RECEIPT_INVALID"));
        }
        let timing = s.timings_ms.entry(action.id.clone()).or_default();
        *timing = timing.saturating_add(started.elapsed().as_millis() as u64);
        s.receipts.push(response);
        s.next += 1;
        s.pending = false;
        s.status = "RUNNING".into();
        save(&work, &s)?;
    }
    s.status = "COMPLETE".into();
    save(&work, &s)?;
    fs::remove_file(active_path).map_err(|_| err("STATE_WRITE_FAILED"))?;
    Ok(result(&t, &work, &s))
}
