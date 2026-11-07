//! Optional declared-input diagnostics. Never changes a plan or grants admission.
use ktapeout_runtime::parse_strict_json;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

// Typed intake rejects duplicate fields before serde_json::Value can discard them.
macro_rules! record {
    ($name:ident { $($field:ident : $ty:ty),* $(,)? }) => {
        #[allow(dead_code)]
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct $name { $($field: $ty),* }
    };
}
record!(Request {
    schema: String, protocol_semver: String, network: String, binding: Binding,
    representation: String, operations: Vec<Operation>, scenarios: Vec<Scenario>,
    recovery_materials: RecoveryMaterials,
});
record!(Binding {
    commitments: Vec<Commitment>,
    network_policy_id: Option<String>,
});
record!(Commitment {
    kind: String,
    digest: String
});
record!(Operation {
    id: String, kind: String, fee_sompi: Option<u64>, mass: Option<u64>,
    redeem_script_bytes: Option<u64>, witness_bytes: Option<u64>,
});
record!(Scenario { id: String, counts: Vec<Count>, peak_locked_sompi: Option<u64> });
record!(Count {
    operation_id: String,
    count: u64
});
record!(RecoveryMaterials {
    redeem_script: Option<String>, constructor_manifest: Option<String>, abi: Option<String>,
    exit_witness_template: Option<String>, initial_state: Option<String>, recovery_preflight: Option<String>,
});

pub fn parse(bytes: &[u8]) -> Result<Value, String> {
    if bytes.len() > 256 * 1024 {
        return Err("LIFECYCLE_SIZE_LIMIT".into());
    }
    let value = parse_strict_json(bytes).map_err(|error| {
        let message = error.to_string();
        if message.contains("duplicate JSON object key") {
            "LIFECYCLE_INPUT_JSON_ERROR: duplicate field".to_string()
        } else {
            format!("LIFECYCLE_INPUT_JSON_ERROR:{message}")
        }
    })?;
    let _: Request = serde_json::from_value(value.clone())
        .map_err(|error| format!("LIFECYCLE_INPUT_JSON_ERROR:{error}"))?;
    Ok(value)
}

pub const REQUEST_SCHEMA: &str = "KTAPEOUT-LIFECYCLE-COST-REQUEST-V1";
pub const REPORT_SCHEMA: &str = "KTAPEOUT-LIFECYCLE-COST-REPORT-V1";
const DOMAIN: &str = "KTAPEOUT/0.5.0/LIFECYCLE_COST_REPORT/V1";
const MAX_SAFE: u64 = 9_007_199_254_740_991;
const MATERIALS: &[&str] = &[
    "redeem_script",
    "constructor_manifest",
    "abi",
    "exit_witness_template",
    "initial_state",
    "recovery_preflight",
];

fn exact(value: &Value, keys: &[&str]) -> Result<(), String> {
    let obj = value.as_object().ok_or("LIFECYCLE_OBJECT_REQUIRED")?;
    if obj.len() != keys.len() || keys.iter().any(|key| !obj.contains_key(*key)) {
        return Err("LIFECYCLE_FIELDS_INVALID".into());
    }
    Ok(())
}

fn id(value: &Value) -> Result<&str, String> {
    value
        .as_str()
        .filter(|s| {
            !s.is_empty()
                && s.len() <= 64
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
        .ok_or_else(|| "LIFECYCLE_ID_INVALID".into())
}

fn amount(value: &Value) -> Result<u64, String> {
    value
        .as_u64()
        .filter(|n| *n <= MAX_SAFE)
        .ok_or_else(|| "LIFECYCLE_INTEGER_INVALID".into())
}

fn optional_amount(value: &Value) -> Result<Option<u64>, String> {
    if value.is_null() {
        Ok(None)
    } else {
        amount(value).map(Some)
    }
}

fn list(value: &Value, max: usize) -> Result<&Vec<Value>, String> {
    value
        .as_array()
        .filter(|a| !a.is_empty() && a.len() <= max)
        .ok_or_else(|| "LIFECYCLE_ARRAY_LIMIT".into())
}

fn hash(value: &Value) -> Result<(), String> {
    if !value.as_str().is_some_and(super::valid_hash) {
        return Err("LIFECYCLE_HASH_INVALID".into());
    }
    Ok(())
}

pub fn compose(request: &Value) -> Result<Value, String> {
    exact(
        request,
        &[
            "schema",
            "protocol_semver",
            "network",
            "binding",
            "representation",
            "operations",
            "scenarios",
            "recovery_materials",
        ],
    )?;
    if request["schema"] != REQUEST_SCHEMA || request["protocol_semver"] != "0.5.0" {
        return Err("LIFECYCLE_SCHEMA_INVALID".into());
    }
    if !matches!(request["network"].as_str(), Some("testnet-10" | "mainnet")) {
        return Err("LIFECYCLE_NETWORK_INVALID".into());
    }
    exact(&request["binding"], &["commitments", "network_policy_id"])?;
    let commitments = list(&request["binding"]["commitments"], 10)?;
    let allowed_kinds = [
        "adapter",
        "artifact",
        "codec",
        "compiler",
        "developer_lock",
        "evidence",
        "manifest",
        "network_policy",
        "profile",
        "template",
    ];
    let mut kinds = BTreeSet::new();
    for commitment in commitments {
        exact(commitment, &["kind", "digest"])?;
        let kind = commitment["kind"]
            .as_str()
            .filter(|kind| allowed_kinds.contains(kind))
            .ok_or("LIFECYCLE_COMMITMENT_KIND_INVALID")?;
        if !kinds.insert(kind) {
            return Err("LIFECYCLE_DUPLICATE_COMMITMENT".into());
        }
        hash(&commitment["digest"])?;
    }
    if let Some(policy_id) = request["binding"]["network_policy_id"].as_str() {
        if policy_id.is_empty()
            || policy_id.len() > 128
            || policy_id.trim() != policy_id
            || !policy_id.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
        {
            return Err("LIFECYCLE_NETWORK_POLICY_ID_INVALID".into());
        }
    } else if !request["binding"]["network_policy_id"].is_null() {
        return Err("LIFECYCLE_NETWORK_POLICY_ID_INVALID".into());
    }
    if !matches!(
        request["representation"].as_str(),
        Some("CURRENT" | "P2SH" | "DIRECT")
    ) {
        return Err("LIFECYCLE_REPRESENTATION_INVALID".into());
    }
    let mut operations = BTreeMap::new();
    let mut kinds = BTreeSet::new();
    for operation in list(&request["operations"], 16)? {
        exact(
            operation,
            &[
                "id",
                "kind",
                "fee_sompi",
                "mass",
                "redeem_script_bytes",
                "witness_bytes",
            ],
        )?;
        let key = id(&operation["id"])?;
        let kind = operation["kind"].as_str().ok_or("LIFECYCLE_KIND_INVALID")?;
        if !matches!(
            kind,
            "GENESIS" | "ACTIVATE" | "NORMAL" | "RECOVERY" | "EXIT" | "MIGRATION"
        ) {
            return Err("LIFECYCLE_KIND_INVALID".into());
        }
        for field in ["fee_sompi", "mass", "redeem_script_bytes", "witness_bytes"] {
            optional_amount(&operation[field])?;
        }
        if let (Some(redeem), Some(witness)) = (
            optional_amount(&operation["redeem_script_bytes"])?,
            optional_amount(&operation["witness_bytes"])?,
        ) {
            // Funding may create a P2SH output without spending any P2SH input.
            if request["representation"] == "P2SH" && redeem > 0 && witness <= redeem {
                return Err("LIFECYCLE_REDEEM_PUSH_NOT_ACCOUNTED".into());
            }
        }
        if operations.insert(key, operation).is_some() {
            return Err("LIFECYCLE_DUPLICATE_OPERATION".into());
        }
        kinds.insert(kind);
    }
    let mut scenario_ids = BTreeSet::new();
    let mut summaries = Vec::new();
    for scenario in list(&request["scenarios"], 8)? {
        exact(scenario, &["id", "counts", "peak_locked_sompi"])?;
        let key = id(&scenario["id"])?;
        if !scenario_ids.insert(key) {
            return Err("LIFECYCLE_DUPLICATE_SCENARIO".into());
        }
        optional_amount(&scenario["peak_locked_sompi"])?;
        let mut seen = BTreeSet::new();
        let mut subtotal = 0u64;
        let mut tx_count = 0u64;
        let mut unknown = Vec::new();
        for entry in list(&scenario["counts"], 16)? {
            exact(entry, &["operation_id", "count"])?;
            let operation_id = id(&entry["operation_id"])?;
            if !seen.insert(operation_id) {
                return Err("LIFECYCLE_DUPLICATE_COUNT".into());
            }
            let operation = operations
                .get(operation_id)
                .ok_or("LIFECYCLE_UNKNOWN_OPERATION")?;
            let count = amount(&entry["count"])?;
            if count == 0 {
                return Err("LIFECYCLE_ZERO_COUNT".into());
            }
            tx_count = tx_count
                .checked_add(count)
                .filter(|v| *v <= MAX_SAFE)
                .ok_or("LIFECYCLE_OVERFLOW")?;
            if let Some(fee) = optional_amount(&operation["fee_sompi"])? {
                subtotal = fee
                    .checked_mul(count)
                    .and_then(|n| subtotal.checked_add(n))
                    .filter(|n| *n <= MAX_SAFE)
                    .ok_or("LIFECYCLE_OVERFLOW")?;
            } else {
                unknown.push(operation_id);
            }
        }
        summaries.push(json!({"id":key,"declared_operation_count":tx_count,
            "known_fee_subtotal_sompi":subtotal,
            "total_fee_sompi":if unknown.is_empty() { json!(subtotal) } else { Value::Null },
            "unknown_fee_operations":unknown,"declared_peak_locked_sompi":scenario["peak_locked_sompi"]}));
    }
    exact(&request["recovery_materials"], MATERIALS)?;
    let mut missing = Vec::new();
    for field in MATERIALS {
        if request["recovery_materials"][*field].is_null() {
            missing.push(*field);
        } else {
            hash(&request["recovery_materials"][*field])?;
        }
    }
    if super::canonical_json(request)?.len() > 256 * 1024 {
        return Err("LIFECYCLE_SIZE_LIMIT".into());
    }
    let unlisted: Vec<_> = [
        "GENESIS",
        "ACTIVATE",
        "NORMAL",
        "RECOVERY",
        "EXIT",
        "MIGRATION",
    ]
    .into_iter()
    .filter(|kind| !kinds.contains(kind))
    .collect();
    let mut report = json!({"schema":REPORT_SCHEMA,"protocol_semver":"0.5.0",
        "network":request["network"],"request":request,"scenarios":summaries,
        "unlisted_operation_kinds":unlisted,"evidence_origin":"DECLARED_INPUT",
        "binding_verification":"NOT_CHECKED","native_execution":"NOT_CHECKED",
        "recovery":{"inventory_status":if missing.is_empty() {"INVENTORY_ONLY"} else {"MISSING_MATERIALS"},
            "missing_materials":missing,"availability":"NOT_CHECKED","execution":"NOT_CHECKED"},
        "signing_allowed":false,"broadcast":false,
        "limitations":["Declared fees and capital are not a live quote or a network floor measurement.",
            "Hashes are caller references; source, binding, deployment and material availability are not verified.",
            "Unlisted operations are unknown or profile-specific, never implicitly free or supported.",
            "Inventory completeness does not prove an executable or authorized recovery/exit.",
            "Counts describe scenarios, not transaction dependencies, latency or TPS."]});
    let digest = super::digest_bytes(&super::canonical_json(&report)?, DOMAIN);
    report["report_hash"] = json!(digest);
    Ok(report)
}
