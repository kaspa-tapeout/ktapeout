use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const DOMAIN: &[u8] = b"KTAPEOUT/0.5.0/APPLICATION_MAINTENANCE_PLAN/V1\0";
const JOURNAL_DOMAIN: &[u8] = b"KTAPEOUT/0.5.0/APPLICATION_MAINTENANCE_JOURNAL/V1\0";

fn exact_keys(value: &Value, required: &[&str], optional: &[&str]) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    object.len()
        == required.len()
            + optional
                .iter()
                .filter(|key| object.contains_key(**key))
                .count()
        && required.iter().all(|key| object.contains_key(*key))
        && object
            .keys()
            .all(|key| required.contains(&key.as_str()) || optional.contains(&key.as_str()))
}

fn validate_genesis_step(step: &Value) -> Result<(), String> {
    let Some(raw_kind) = step.get("operation_kind") else {
        return Ok(());
    };
    let kind = raw_kind
        .as_str()
        .ok_or("MAINTENANCE_OPERATION_KIND_UNSUPPORTED")?;
    if kind != "GENESIS_DEPLOYMENT" {
        return Err("MAINTENANCE_OPERATION_KIND_UNSUPPORTED".into());
    }
    for field in [
        "subplan_hash",
        "genesis_provenance_hash",
        "network_policy_hash",
    ] {
        if !step
            .get(field)
            .and_then(Value::as_str)
            .is_some_and(super::valid_hash)
        {
            return Err(format!("MAINTENANCE_GENESIS_STEP_HASH_INVALID:{field}"));
        }
    }
    let expected = step
        .get("expected_result")
        .and_then(Value::as_object)
        .ok_or("MAINTENANCE_GENESIS_EXPECTED_RESULT_REQUIRED")?;
    if !expected
        .get("covenant_id")
        .and_then(Value::as_str)
        .is_some_and(super::valid_hash)
    {
        return Err("MAINTENANCE_GENESIS_EXPECTED_COVENANT_ID_INVALID".into());
    }
    let indices = expected
        .get("output_indices")
        .and_then(Value::as_array)
        .filter(|values| !values.is_empty() && values.len() <= 64)
        .ok_or("MAINTENANCE_GENESIS_OUTPUT_INDICES_INVALID")?;
    let mut previous = None;
    for index in indices {
        let current = index
            .as_u64()
            .filter(|value| *value <= u32::MAX as u64)
            .ok_or("MAINTENANCE_GENESIS_OUTPUT_INDICES_INVALID")?;
        if previous.is_some_and(|value| value >= current) {
            return Err("MAINTENANCE_GENESIS_OUTPUT_INDICES_ORDER_INVALID".into());
        }
        previous = Some(current);
    }
    Ok(())
}

/// Bind a completed, unsigned maintenance template to its canonical plan hash.
/// This only creates a local plan artifact; it does not admit, sign, or broadcast it.
pub fn build(mut plan: Value) -> Result<Value, String> {
    let object = plan
        .as_object_mut()
        .ok_or("MAINTENANCE_PLAN_OBJECT_REQUIRED")?;
    object.insert("plan_hash".into(), Value::String("0".repeat(64)));
    let candidate = Value::Object(object.clone());
    if let Err(error) = verify(&candidate) {
        if error != "MAINTENANCE_PLAN_HASH_MISMATCH" {
            return Err(error);
        }
    }
    let mut material = object.clone();
    material.remove("plan_hash");
    let mut digest = Sha256::new();
    digest.update(DOMAIN);
    digest.update(super::canonical_json(&Value::Object(material))?);
    object.insert(
        "plan_hash".into(),
        Value::String(
            digest
                .finalize()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        ),
    );
    verify(&Value::Object(object.clone()))?;
    Ok(Value::Object(object.clone()))
}

/// Local plan integrity only. Adapter admission and live predecessor checks
/// remain necessary before any external signing request.
pub fn verify(plan: &Value) -> Result<(), String> {
    let object = plan.as_object().ok_or("MAINTENANCE_PLAN_OBJECT_REQUIRED")?;
    let fields = [
        "schema",
        "protocol_semver",
        "application_id",
        "network",
        "network_policy_hash",
        "operation_id",
        "expires_at",
        "predecessor",
        "target",
        "changes",
        "steps",
        "budget",
        "recovery",
        "plan_hash",
    ];
    if object.len() != fields.len() || fields.iter().any(|key| !object.contains_key(*key)) {
        return Err("MAINTENANCE_PLAN_FIELDS_INVALID".into());
    }
    if plan["schema"] != "KTAPEOUT-APPLICATION-MAINTENANCE-PLAN-V1"
        || plan["protocol_semver"] != "0.5.0"
    {
        return Err("MAINTENANCE_PLAN_VERSION_INVALID".into());
    }
    if !matches!(plan["network"].as_str(), Some("testnet-10" | "mainnet")) {
        return Err("MAINTENANCE_NETWORK_INVALID".into());
    }
    let operation_id = plan["operation_id"]
        .as_str()
        .filter(|value| {
            value.len() == 35
                && value.starts_with("op_")
                && value[3..]
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
        .ok_or("MAINTENANCE_OPERATION_ID_INVALID")?;
    let _ = operation_id;
    let expires_at = plan["expires_at"]
        .as_str()
        .filter(|value| {
            value.ends_with('Z')
                && value.len() >= 20
                && value.as_bytes().get(4) == Some(&b'-')
                && value.as_bytes().get(7) == Some(&b'-')
                && value.as_bytes().get(10) == Some(&b'T')
                && value.as_bytes().get(13) == Some(&b':')
                && value.as_bytes().get(16) == Some(&b':')
        })
        .ok_or("MAINTENANCE_EXPIRY_INVALID")?;
    if ktapeout_runtime::compare_utc_timestamps(expires_at, expires_at).is_none() {
        return Err("MAINTENANCE_EXPIRY_INVALID".into());
    }
    for key in ["application_id", "network_policy_hash", "plan_hash"] {
        if !plan[key].as_str().is_some_and(super::valid_hash) {
            return Err(format!("MAINTENANCE_HASH_INVALID:{key}"));
        }
    }
    for key in ["predecessor", "target", "changes", "budget", "recovery"] {
        if !plan[key].is_object() {
            return Err(format!("MAINTENANCE_OBJECT_REQUIRED:{key}"));
        }
    }
    if !exact_keys(&plan["predecessor"], &["release_id", "artifact_root"], &[]) {
        return Err("MAINTENANCE_PREDECESSOR_FIELDS_INVALID".into());
    }
    if !exact_keys(&plan["target"], &["release_id", "artifact_root"], &[]) {
        return Err("MAINTENANCE_TARGET_FIELDS_INVALID".into());
    }
    if !exact_keys(
        &plan["changes"],
        &["classification", "requires_state_migration"],
        &["migration_contract_hash"],
    ) {
        return Err("MAINTENANCE_CHANGES_FIELDS_INVALID".into());
    }
    if !exact_keys(&plan["budget"], &["max_fee_sompi"], &[]) {
        return Err("MAINTENANCE_BUDGET_FIELDS_INVALID".into());
    }
    if !exact_keys(&plan["recovery"], &["rollback_policy"], &[]) {
        return Err("MAINTENANCE_RECOVERY_FIELDS_INVALID".into());
    }
    for key in ["predecessor", "target"] {
        for field in ["release_id", "artifact_root"] {
            if !plan[key][field].as_str().is_some_and(super::valid_hash) {
                return Err(format!("MAINTENANCE_DESCRIPTOR_HASH_INVALID:{key}.{field}"));
            }
        }
    }
    if !matches!(
        plan["changes"]["classification"].as_str(),
        Some(
            "DOCUMENTATION_ONLY"
                | "PATCH_COMPATIBLE"
                | "CONTRACT_CHANGE"
                | "STATE_MIGRATION"
                | "REPLACEMENT"
        )
    ) || !plan["changes"]["requires_state_migration"].is_boolean()
    {
        return Err("MAINTENANCE_CHANGES_INVALID".into());
    }
    let same_release_pair = plan["predecessor"]["release_id"] == plan["target"]["release_id"]
        && plan["predecessor"]["artifact_root"] == plan["target"]["artifact_root"];
    if same_release_pair && plan["changes"]["classification"] != "DOCUMENTATION_ONLY" {
        return Err("MAINTENANCE_TARGET_UNCHANGED".into());
    }
    let requires_migration = plan["changes"]["requires_state_migration"]
        .as_bool()
        .unwrap_or(false);
    match (
        requires_migration,
        plan["changes"]["migration_contract_hash"].as_str(),
    ) {
        (true, Some(value)) if super::valid_hash(value) => {}
        (true, _) => return Err("MAINTENANCE_MIGRATION_CONTRACT_HASH_REQUIRED".into()),
        (false, Some(value)) if !super::valid_hash(value) => {
            return Err("MAINTENANCE_MIGRATION_CONTRACT_HASH_INVALID".into())
        }
        _ => {}
    }
    if plan["budget"]["max_fee_sompi"]
        .as_u64()
        .is_none_or(|value| value == 0 || value > 9_007_199_254_740_991)
    {
        return Err("MAINTENANCE_BUDGET_INVALID".into());
    }
    if !matches!(
        plan["recovery"]["rollback_policy"].as_str(),
        Some("RETAIN_PREDECESSOR" | "FORWARD_FIX_ONLY" | "UNSUPPORTED")
    ) {
        return Err("MAINTENANCE_RECOVERY_INVALID".into());
    }
    let steps = plan["steps"]
        .as_array()
        .ok_or("MAINTENANCE_STEPS_REQUIRED")?;
    if steps.is_empty() || steps.len() > 64 {
        return Err("MAINTENANCE_STEP_LIMIT".into());
    }
    let mut seen = BTreeSet::new();
    for step in steps {
        validate_genesis_step(step)?;
        if step.get("operation_kind").and_then(Value::as_str) == Some("GENESIS_DEPLOYMENT")
            && step.get("network_policy_hash") != plan.get("network_policy_hash")
        {
            return Err("MAINTENANCE_GENESIS_NETWORK_POLICY_MISMATCH".into());
        }
        let id = step["step_id"]
            .as_str()
            .filter(|id| !id.is_empty() && id.chars().count() <= 128)
            .ok_or("MAINTENANCE_STEP_ID_INVALID")?;
        let dependencies = step["depends_on"]
            .as_array()
            .ok_or("MAINTENANCE_DEPENDENCIES_REQUIRED")?;
        let mut unique = BTreeSet::new();
        for dependency in dependencies {
            let name = dependency
                .as_str()
                .ok_or("MAINTENANCE_DEPENDENCY_INVALID")?;
            if name.is_empty()
                || name.chars().count() > 128
                || !seen.contains(name)
                || !unique.insert(name)
            {
                return Err("MAINTENANCE_DEPENDENCY_ORDER_INVALID".into());
            }
        }
        if !seen.insert(id) {
            return Err("MAINTENANCE_DUPLICATE_STEP".into());
        }
    }
    let bytes = super::canonical_json(plan)?;
    if bytes.len() > 256 * 1024 {
        return Err("MAINTENANCE_PLAN_SIZE_LIMIT".into());
    }
    let mut material = object.clone();
    material.remove("plan_hash");
    let mut digest = Sha256::new();
    digest.update(DOMAIN);
    digest.update(super::canonical_json(&Value::Object(material))?);
    let actual = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if plan["plan_hash"].as_str() != Some(&actual) {
        return Err("MAINTENANCE_PLAN_HASH_MISMATCH".into());
    }
    Ok(())
}

fn journal_hash(value: &Value) -> Result<String, String> {
    let mut material = value
        .as_object()
        .ok_or("MAINTENANCE_JOURNAL_OBJECT_REQUIRED")?
        .clone();
    material.remove("journal_hash");
    let mut digest = Sha256::new();
    digest.update(JOURNAL_DOMAIN);
    digest.update(super::canonical_json(&Value::Object(material))?);
    Ok(digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

/// Validate the existing maintenance execution-journal contract and return a
/// derived summary. This is tooling evidence only: it never enters
/// OperationStateV1 and never enables signing or broadcast.
pub fn journal_view(plan: &Value, journal: &Value) -> Result<Value, String> {
    verify(plan)?;
    let object = journal
        .as_object()
        .ok_or("MAINTENANCE_JOURNAL_OBJECT_REQUIRED")?;
    let required = [
        "schema",
        "protocol_semver",
        "plan_hash",
        "entries",
        "journal_hash",
    ];
    if object.len() != required.len() || required.iter().any(|field| !object.contains_key(*field)) {
        return Err("MAINTENANCE_JOURNAL_FIELDS_INVALID".into());
    }
    if journal["schema"] != "KTAPEOUT-MAINTENANCE-JOURNAL-V1"
        || journal["protocol_semver"] != "0.5.0"
        || journal["plan_hash"] != plan["plan_hash"]
    {
        return Err("MAINTENANCE_JOURNAL_BINDING_INVALID".into());
    }
    let entries = journal["entries"]
        .as_array()
        .ok_or("MAINTENANCE_JOURNAL_ENTRIES_REQUIRED")?;
    if entries.len() > 64 {
        return Err("MAINTENANCE_JOURNAL_ENTRY_LIMIT".into());
    }
    let plan_steps = plan["steps"]
        .as_array()
        .ok_or("MAINTENANCE_STEPS_REQUIRED")?;
    let step_ids = plan_steps
        .iter()
        .filter_map(|step| step["step_id"].as_str())
        .collect::<BTreeSet<_>>();
    let mut seen = BTreeSet::new();
    let mut status_by_step = BTreeMap::<String, String>::new();
    let valid_status = [
        "PLANNED",
        "SIGNED",
        "SUBMITTED",
        "SUBMISSION_UNKNOWN",
        "CONFIRMED",
        "REJECTED",
        "RECOVERY_REQUIRED",
        "ACTIVATED_WITH_RUNTIME_FAILURE",
    ];
    for (index, entry) in entries.iter().enumerate() {
        let item = entry
            .as_object()
            .ok_or("MAINTENANCE_JOURNAL_ENTRY_INVALID")?;
        let fields = [
            "step_id",
            "operation_id",
            "status",
            "input_commitment",
            "output_commitment",
            "receipt_ref",
            "reason_code",
            "safe_to_retry",
            "evidence_refs",
        ];
        if item.len() != fields.len() || fields.iter().any(|field| !item.contains_key(*field)) {
            return Err("MAINTENANCE_JOURNAL_ENTRY_FIELDS_INVALID".into());
        }
        let step_id = item["step_id"]
            .as_str()
            .filter(|value| !value.is_empty() && value.chars().count() <= 128)
            .ok_or("MAINTENANCE_JOURNAL_STEP_ID_INVALID")?;
        let expected_step = plan_steps
            .get(index)
            .and_then(|step| step["step_id"].as_str())
            .ok_or("MAINTENANCE_JOURNAL_STEP_ORDER_INVALID")?;
        if step_id != expected_step || !step_ids.contains(step_id) || !seen.insert(step_id) {
            return Err("MAINTENANCE_JOURNAL_STEP_ORDER_INVALID".into());
        }
        let operation_id = item["operation_id"]
            .as_str()
            .filter(|value| {
                value.len() == 35
                    && value.starts_with("op_")
                    && value[3..]
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            })
            .ok_or("MAINTENANCE_JOURNAL_OPERATION_ID_INVALID")?;
        let _ = operation_id;
        let status = item["status"]
            .as_str()
            .filter(|value| valid_status.contains(value))
            .ok_or("MAINTENANCE_JOURNAL_STATUS_INVALID")?;
        let dependencies = plan_steps[index]["depends_on"]
            .as_array()
            .ok_or("MAINTENANCE_JOURNAL_DEPENDENCIES_INVALID")?;
        if dependencies.iter().any(|dependency| {
            dependency
                .as_str()
                .and_then(|name| status_by_step.get(name))
                .map(String::as_str)
                != Some("CONFIRMED")
        }) {
            return Err("MAINTENANCE_JOURNAL_DEPENDENCY_NOT_CONFIRMED".into());
        }
        status_by_step.insert(step_id.to_string(), status.to_string());
        for field in ["input_commitment", "output_commitment"] {
            if !item[field].is_null() && !item[field].as_str().is_some_and(super::valid_hash) {
                return Err(format!("MAINTENANCE_JOURNAL_COMMITMENT_INVALID:{field}"));
            }
        }
        if !item["receipt_ref"].is_null()
            && (!item["receipt_ref"].is_string()
                || item["receipt_ref"].as_str().unwrap_or_default().is_empty())
        {
            return Err("MAINTENANCE_JOURNAL_RECEIPT_REF_INVALID".into());
        }
        if !item["reason_code"]
            .as_str()
            .is_some_and(|value| !value.is_empty() && value.chars().count() <= 128)
            || !item["safe_to_retry"].is_boolean()
        {
            return Err("MAINTENANCE_JOURNAL_RESULT_INVALID".into());
        }
        let evidence = item["evidence_refs"]
            .as_array()
            .ok_or("MAINTENANCE_JOURNAL_EVIDENCE_INVALID")?;
        if evidence.len() > 8
            || evidence
                .iter()
                .filter_map(Value::as_str)
                .collect::<BTreeSet<_>>()
                .len()
                != evidence.len()
            || evidence
                .iter()
                .any(|value| value.as_str().is_none_or(|text| text.is_empty()))
        {
            return Err("MAINTENANCE_JOURNAL_EVIDENCE_INVALID".into());
        }
    }
    let expected = journal_hash(journal)?;
    if journal["journal_hash"].as_str() != Some(&expected) {
        return Err("MAINTENANCE_JOURNAL_HASH_MISMATCH".into());
    }
    let has_failure = entries
        .iter()
        .any(|entry| matches!(entry["status"].as_str(), Some("REJECTED")));
    let has_unknown = entries.iter().any(|entry| {
        matches!(
            entry["status"].as_str(),
            Some("SUBMISSION_UNKNOWN" | "RECOVERY_REQUIRED")
        )
    });
    let has_runtime_failure = entries
        .iter()
        .any(|entry| entry["status"] == "ACTIVATED_WITH_RUNTIME_FAILURE");
    let complete = entries.len() == plan_steps.len()
        && entries.iter().all(|entry| entry["status"] == "CONFIRMED");
    let aggregate_status = if complete {
        "COMPLETED"
    } else if has_runtime_failure {
        "ACTIVATED_WITH_RUNTIME_FAILURE"
    } else if has_unknown {
        "RECOVERY_REQUIRED"
    } else if has_failure || entries.len() < plan_steps.len() {
        "PARTIAL"
    } else {
        "IN_PROGRESS"
    };
    let safe_to_retry = !entries.is_empty()
        && entries
            .iter()
            .all(|entry| entry["status"] == "PLANNED" && entry["safe_to_retry"] == true);
    Ok(
        json!({"schema":"KTAPEOUT-0.5.0-MAINTENANCE-JOURNAL-VIEW-V1","protocol_semver":"0.5.0","plan_hash":plan["plan_hash"],"journal_hash":journal["journal_hash"],"step_count":plan_steps.len(),"recorded_step_count":entries.len(),"aggregate_status":aggregate_status,"safe_to_retry":safe_to_retry,"signing_allowed":false,"broadcast":false}),
    )
}

/// Verify a maintenance plan and, when supplied, consume the genesis
/// provenance evidence bound by its single GENESIS_DEPLOYMENT step.  This is
/// still local verification: it never signs, broadcasts, or upgrades the
/// plan's evidence to finality.
pub fn verify_with_genesis_evidence(
    plan: &Value,
    provenance: Option<&Value>,
    expected_covenant_id: Option<&str>,
    rebuild: Option<&Value>,
    readback: Option<&Value>,
) -> Result<Value, String> {
    verify(plan)?;
    let genesis_steps = plan["steps"]
        .as_array()
        .ok_or("MAINTENANCE_STEPS_REQUIRED")?
        .iter()
        .filter(|step| {
            step.get("operation_kind").and_then(Value::as_str) == Some("GENESIS_DEPLOYMENT")
        })
        .collect::<Vec<_>>();
    let has_evidence_input = provenance.is_some()
        || expected_covenant_id.is_some()
        || rebuild.is_some()
        || readback.is_some();
    if !has_evidence_input {
        return Ok(json!({
            "verification_scope": "LOCAL_PLAN_INTEGRITY",
            "plan_hash": plan["plan_hash"],
            "genesis_steps": genesis_steps.len(),
            "genesis_evidence": "NOT_PROVIDED",
            "signing_allowed": false,
            "broadcast": false
        }));
    }
    let proof = provenance.ok_or("MAINTENANCE_GENESIS_PROVENANCE_REQUIRED")?;
    let step = match genesis_steps.as_slice() {
        [step] => *step,
        [] => return Err("MAINTENANCE_GENESIS_STEP_REQUIRED".into()),
        _ => return Err("MAINTENANCE_GENESIS_EVIDENCE_AMBIGUOUS".into()),
    };
    let step_expected_id = step["expected_result"]["covenant_id"]
        .as_str()
        .ok_or("MAINTENANCE_GENESIS_EXPECTED_COVENANT_ID_INVALID")?;
    if let Some(expected) = expected_covenant_id {
        if expected != step_expected_id {
            return Err("MAINTENANCE_GENESIS_EXPECTED_COVENANT_ID_MISMATCH".into());
        }
    }
    if proof["network"] != plan["network"] {
        return Err("MAINTENANCE_GENESIS_NETWORK_MISMATCH".into());
    }
    if proof["network_policy_hash"] != step["network_policy_hash"] {
        return Err("MAINTENANCE_GENESIS_NETWORK_POLICY_MISMATCH".into());
    }
    if proof["provenance_hash"] != step["genesis_provenance_hash"] {
        return Err("MAINTENANCE_GENESIS_PROVENANCE_HASH_MISMATCH".into());
    }
    let expected_indices = step["expected_result"]["output_indices"]
        .as_array()
        .ok_or("MAINTENANCE_GENESIS_OUTPUT_INDICES_INVALID")?;
    let observed_indices = proof["genesis"]["outputs"]
        .as_array()
        .ok_or("MAINTENANCE_GENESIS_PROVENANCE_OUTPUTS_REQUIRED")?
        .iter()
        .map(|output| {
            output["index"]
                .as_u64()
                .map(Value::from)
                .ok_or("MAINTENANCE_GENESIS_PROVENANCE_OUTPUT_INDEX_INVALID")
        })
        .collect::<Result<Vec<_>, _>>()?;
    if expected_indices != &observed_indices {
        return Err("MAINTENANCE_GENESIS_OUTPUT_INDICES_MISMATCH".into());
    }
    let genesis = super::genesis_provenance::verify_with_evidence(
        proof,
        Some(step_expected_id),
        rebuild,
        readback,
    )?;
    Ok(json!({
        "verification_scope": "LOCAL_PLAN_AND_GENESIS_EVIDENCE",
        "plan_hash": plan["plan_hash"],
        "genesis_steps": genesis_steps.len(),
        "genesis_evidence": genesis,
        "signing_allowed": false,
        "broadcast": false
    }))
}

/// Produce the CLI/AI read-only maintenance summary. OperationState validation
/// and plan binding happen before this function is called; this function adds
/// no signing, broadcast, migration execution, or L1 authority.
pub fn view(
    plan: &Value,
    state: &Value,
    migration_contract: Option<&Value>,
    history_bundle: Option<&Value>,
    journal: Option<&Value>,
) -> Result<Value, String> {
    verify(plan)?;
    super::valid_operation_value(state)?;
    for field in ["operation_id", "plan_hash", "network"] {
        if plan[field] != state[field] {
            return Err(format!("MAINTENANCE_VIEW_BINDING_MISMATCH:{field}"));
        }
    }
    if plan["expires_at"] != state["expiry"] {
        return Err("MAINTENANCE_VIEW_BINDING_MISMATCH:expiry".into());
    }
    let classification = plan["changes"]["classification"]
        .as_str()
        .ok_or("MAINTENANCE_VIEW_CLASSIFICATION_INVALID")?;
    let requires_state_migration = plan["changes"]["requires_state_migration"]
        .as_bool()
        .ok_or("MAINTENANCE_VIEW_MIGRATION_FLAG_INVALID")?;
    let migration = if requires_state_migration {
        let contract = migration_contract.ok_or("MAINTENANCE_VIEW_MIGRATION_CONTRACT_REQUIRED")?;
        super::migration::verify(contract)?;
        let expected = plan["changes"]["migration_contract_hash"]
            .as_str()
            .ok_or("MAINTENANCE_VIEW_MIGRATION_CONTRACT_HASH_REQUIRED")?;
        if contract["contract_hash"].as_str() != Some(expected) {
            return Err("MAINTENANCE_VIEW_MIGRATION_CONTRACT_BINDING_MISMATCH".into());
        }
        let release_pair_binding = if contract["schema"] == "KTAPEOUT-PROFILE-MIGRATION-CONTRACT-V2"
        {
            for field in ["network", "application_id"] {
                if contract[field] != plan[field] {
                    return Err(format!(
                        "MAINTENANCE_VIEW_MIGRATION_RELEASE_BINDING_MISMATCH:{field}"
                    ));
                }
            }
            for key in ["predecessor", "target"] {
                for field in ["release_id", "artifact_root"] {
                    if contract[key][field] != plan[key][field] {
                        return Err(format!(
                            "MAINTENANCE_VIEW_MIGRATION_RELEASE_BINDING_MISMATCH:{key}.{field}"
                        ));
                    }
                }
            }
            "PLAN_TUPLE_MATCH"
        } else {
            "UNBOUND"
        };
        serde_json::json!({
            "status":"HASH_BOUND_DECLARATION",
            "applicability":"UNVERIFIED_AGAINST_RELEASES",
            "release_pair_binding":release_pair_binding,
            "contract_hash":contract["contract_hash"],
            "execution":false
        })
    } else {
        serde_json::json!({"status":"NOT_REQUIRED", "applicability":"NOT_APPLICABLE", "execution":false})
    };
    let history = if let Some(bundle) = history_bundle {
        super::history::verify(bundle)?;
        let predecessor_pair = bundle["release_id"] == plan["predecessor"]["release_id"]
            && bundle["artifact_root"] == plan["predecessor"]["artifact_root"];
        let target_pair = bundle["release_id"] == plan["target"]["release_id"]
            && bundle["artifact_root"] == plan["target"]["artifact_root"];
        if bundle["application_id"] != plan["application_id"]
            || bundle["network"] != plan["network"]
            || (!predecessor_pair && !target_pair)
        {
            return Err("MAINTENANCE_VIEW_HISTORY_BINDING_MISMATCH".into());
        }
        serde_json::json!({
            "status":"LOCATOR_DECLARATION_VERIFIED",
            "bundle_hash":bundle["bundle_hash"],
            "bytes_trusted":false
        })
    } else {
        serde_json::json!({"status":"NOT_PROVIDED"})
    };
    let permission_impact = if matches!(
        classification,
        "CONTRACT_CHANGE" | "STATE_MIGRATION" | "REPLACEMENT"
    ) {
        "REVIEW_REQUIRED"
    } else {
        "NO_DECLARED_AUTHORITY_CHANGE"
    };
    let journal_summary = journal.map(|value| journal_view(plan, value)).transpose()?;
    let mut result = serde_json::json!({
        "schema": "KTAPEOUT-0.5.0-MAINTENANCE-VIEW-V1",
        "protocol_semver": "0.5.0",
        "application_id": plan["application_id"],
        "network": plan["network"],
        "operation_id": plan["operation_id"],
        "plan_hash": plan["plan_hash"],
        "classification": classification,
        "requires_state_migration": requires_state_migration,
        "permission_impact": permission_impact,
        "step_count": plan["steps"].as_array().map_or(0, Vec::len),
        "max_fee_sompi": plan["budget"]["max_fee_sompi"],
        "rollback_policy": plan["recovery"]["rollback_policy"],
        "migration": migration,
        "history": history,
        "recovery": Value::Null,
        "operation_stage": state["stage"],
        "next_allowed_action": state["next_allowed_action"],
        "signing_allowed": false,
        "broadcast": false
    });
    if let Some(summary) = journal_summary {
        result["journal"] = summary;
    }
    Ok(result)
}

/// Build the existing KTAPEOUT-RECEIPT-V1 local preflight receipt.
pub fn preflight_receipt(
    view: &Value,
    state: &Value,
    captured_at: &str,
    valid_until: &str,
) -> Result<Value, String> {
    super::valid_operation_value(state)?;
    if view["schema"] != "KTAPEOUT-0.5.0-MAINTENANCE-VIEW-V1" || view["protocol_semver"] != "0.5.0"
    {
        return Err("MAINTENANCE_RECEIPT_VIEW_IDENTITY_INVALID".into());
    }
    for field in ["operation_id", "plan_hash", "network"] {
        if view[field] != state[field] {
            return Err(format!("MAINTENANCE_RECEIPT_BINDING_MISMATCH:{field}"));
        }
    }
    if view["operation_stage"] != state["stage"] {
        return Err("MAINTENANCE_RECEIPT_BINDING_MISMATCH:operation_stage".into());
    }
    if view["signing_allowed"] != false || view["broadcast"] != false {
        return Err("MAINTENANCE_RECEIPT_UNSAFE_VIEW".into());
    }
    let plan_hash = view["plan_hash"]
        .as_str()
        .filter(|value| super::valid_hash(value))
        .ok_or("MAINTENANCE_RECEIPT_PLAN_HASH_INVALID")?;
    let lock_hash = state["project_lock_hash"]
        .as_str()
        .filter(|value| super::valid_hash(value))
        .ok_or("MAINTENANCE_RECEIPT_LOCK_HASH_INVALID")?;
    let captured =
        crate::parse_utc_timestamp(captured_at).ok_or("MAINTENANCE_RECEIPT_CAPTURED_AT_INVALID")?;
    let valid =
        crate::parse_utc_timestamp(valid_until).ok_or("MAINTENANCE_RECEIPT_VALID_UNTIL_INVALID")?;
    if !crate::timestamp_after(&valid, &captured) {
        return Err("MAINTENANCE_RECEIPT_VALID_UNTIL_INVALID".into());
    }
    let plan_expiry = crate::parse_utc_timestamp(
        state["expiry"]
            .as_str()
            .ok_or("MAINTENANCE_RECEIPT_STATE_EXPIRY_INVALID")?,
    )
    .ok_or("MAINTENANCE_RECEIPT_STATE_EXPIRY_INVALID")?;
    if crate::timestamp_after(&valid, &plan_expiry) {
        return Err("MAINTENANCE_RECEIPT_VALID_UNTIL_EXCEEDS_PLAN".into());
    }
    let verifier_digest = super::digest_json_domain(view, "KTAPEOUT/0.5.0/MAINTENANCE_VIEW/V1")?;
    let next_action = view["next_allowed_action"].as_str().unwrap_or_default();
    let journal_has_progress = view["journal"]["recorded_step_count"]
        .as_u64()
        .is_some_and(|count| count > 0);
    let status = if next_action.to_ascii_uppercase().contains("BLOCKED")
        || state["stage"] != "PLANNED"
        || journal_has_progress
    {
        "BLOCKED"
    } else {
        "READY"
    };
    let mut facts = serde_json::json!({
        "maintenance_view_schema":"KTAPEOUT-0.5.0-MAINTENANCE-VIEW-V1",
        "maintenance_view_digest":verifier_digest,
        "classification":view["classification"],
        "operation_stage":view["operation_stage"],
        "next_allowed_action":view["next_allowed_action"],
        "permission_impact":view["permission_impact"],
        "migration":view["migration"],
        "history":view["history"],
        "recovery":view["recovery"],
        "chain_evidence":false,
        "content_bytes_verified":false,
        "migration_executed":false,
        "signing_allowed":false,
        "broadcast":false,
        "external_signer_required":true,
        "external_readback_required":true
    });
    if let Some(journal) = view.get("journal") {
        facts["maintenance_journal"] = journal.clone();
    }
    let receipt = serde_json::json!({
        "schema":"KTAPEOUT-RECEIPT-V1",
        "protocol_semver":"0.5.0",
        "receipt_kind":"PREFLIGHT",
        "operation_id":view["operation_id"],
        "plan_hash":plan_hash,
        "lock_hash":lock_hash,
        "network":view["network"],
        "status":status,
        "evidence_origin":"LOCAL_SIMULATION",
        "captured_at":captured_at,
        "valid_until":valid_until,
        "verifier_digest":verifier_digest,
        "facts":facts
    });
    super::validate_receipt_value(&receipt)?;
    Ok(receipt)
}
