//! Non-consensus developer-runtime contracts.
//! This crate never owns keys, signs, broadcasts, or changes Core bytes.

use ktapeout_core::parse_strict_json_canonical_bytes;
use serde_json::{json, Map, Number, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const PROTOCOL: &str = "0.5.0";
pub const TOOL_RESULT_SCHEMA: &str = "KTAPEOUT-TOOL-RESULT-V1";
pub const LOCK_SCHEMA: &str = "KTAPEOUT-DEVELOPER-LOCK-V1";
const CANONICAL_JSON_MAX_DEPTH: usize = 64;
const CANONICAL_JSON_MAX_NODES: usize = 65_536;
const CANONICAL_JSON_MAX_BYTES: usize = 4 * 1024 * 1024;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Serialize tooling JSON with the same sorted-object, compact representation
/// used by the Python compatibility runtime and the Rust CLI. This is not a
/// consensus codec; it is the cross-runtime identity boundary for locks,
/// operation IDs and other developer-runtime material. Object keys follow
/// lexicographic UTF-8 byte order; BTreeMap provides that order for valid
/// Unicode strings.
pub fn canonical_json(value: &Value) -> Result<Vec<u8>, String> {
    fn inspect(
        value: &Value,
        depth: usize,
        nodes: &mut usize,
        estimated_bytes: &mut usize,
    ) -> Result<(), String> {
        if depth > CANONICAL_JSON_MAX_DEPTH {
            return Err("JSON_GRAPH_LIMIT".into());
        }
        match value {
            Value::String(text) => *estimated_bytes = estimated_bytes.saturating_add(text.len()),
            Value::Array(values) => {
                *nodes = nodes.saturating_add(1);
                if *nodes > CANONICAL_JSON_MAX_NODES {
                    return Err("JSON_GRAPH_LIMIT".into());
                }
                *estimated_bytes = estimated_bytes.saturating_add(2);
                for child in values {
                    inspect(child, depth + 1, nodes, estimated_bytes)?;
                }
            }
            Value::Object(map) => {
                *nodes = nodes.saturating_add(1);
                if *nodes > CANONICAL_JSON_MAX_NODES {
                    return Err("JSON_GRAPH_LIMIT".into());
                }
                *estimated_bytes = estimated_bytes.saturating_add(2);
                for (key, child) in map {
                    *estimated_bytes = estimated_bytes.saturating_add(key.len().saturating_add(4));
                    inspect(child, depth + 1, nodes, estimated_bytes)?;
                }
            }
            Value::Number(number) => {
                let valid = number
                    .as_i64()
                    .is_some_and(|value| value.unsigned_abs() <= 9_007_199_254_740_991)
                    || number
                        .as_u64()
                        .is_some_and(|value| value <= 9_007_199_254_740_991)
                    || number.as_f64().is_some_and(|value| {
                        value.is_finite()
                            && value.fract() == 0.0
                            && value.abs() <= 9_007_199_254_740_991.0
                    });
                if !valid {
                    return Err("JSON_NUMBER_INVALID".into());
                }
            }
            Value::Null | Value::Bool(_) => {}
        }
        if *estimated_bytes > CANONICAL_JSON_MAX_BYTES {
            return Err("JSON_SIZE_LIMIT".into());
        }
        Ok(())
    }

    let mut nodes = 0;
    let mut estimated_bytes = 0;
    inspect(value, 0, &mut nodes, &mut estimated_bytes)?;
    fn canonical(value: &Value) -> Value {
        match value {
            Value::Object(map) => {
                let ordered: BTreeMap<String, Value> = map
                    .iter()
                    .map(|(key, child)| (key.clone(), canonical(child)))
                    .collect();
                Value::Object(ordered.into_iter().collect())
            }
            Value::Array(values) => Value::Array(values.iter().map(canonical).collect()),
            Value::Number(number) => {
                if let Some(value) = number.as_i64() {
                    Value::Number(Number::from(value))
                } else if let Some(value) = number.as_u64() {
                    Value::Number(Number::from(value))
                } else {
                    Value::Number(Number::from(
                        number.as_f64().expect("validated number") as i64
                    ))
                }
            }
            other => other.clone(),
        }
    }
    serde_json::to_vec(&canonical(value)).map_err(|e| format!("JSON_ENCODE_ERROR:{e}"))
}

/// Parse externally supplied JSON using the single Core implementation.
pub fn parse_strict_json(bytes: &[u8]) -> Result<Value, String> {
    let canonical = parse_strict_json_canonical_bytes(bytes).map_err(|error| error.0)?;
    serde_json::from_slice(&canonical).map_err(|error| format!("E050_JSON_STRICT_REPARSE: {error}"))
}

pub fn digest_json(value: &Value, domain: &str) -> Result<String, String> {
    let body = canonical_json(value)?;
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0]);
    hasher.update(body);
    Ok(hex(&hasher.finalize()))
}

pub fn tool_result(
    command: &str,
    status: &str,
    network: Option<&str>,
    operation_id: &str,
    data: Value,
) -> Result<Value, String> {
    if command.is_empty()
        || command.len() > 128
        || !command
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._ -".contains(c))
    {
        return Err("TOOL_COMMAND_INVALID".into());
    }
    if !matches!(status, "PASS" | "BLOCKED" | "WARNING" | "UNAVAILABLE") {
        return Err("TOOL_STATUS_INVALID".into());
    }
    if !valid_operation_id(operation_id) {
        return Err("TOOL_OPERATION_ID_INVALID".into());
    }
    if !matches!(network, None | Some("testnet-10") | Some("mainnet")) {
        return Err("TOOL_NETWORK_INVALID".into());
    }
    if !data.is_object() {
        return Err("TOOL_DATA_NOT_OBJECT".into());
    }
    Ok(json!({
        "schema": TOOL_RESULT_SCHEMA,
        "protocol_semver": PROTOCOL,
        "command": command,
        "operation_id": operation_id,
        "status": status,
        "network": network,
        "observed_tip": Value::Null,
        "context": Value::Null,
        "error_code": Value::Null,
        "warnings": [],
        "evidence_refs": [],
        "unsigned_operations": [],
        "data": data
    }))
}

pub fn valid_operation_id(value: &str) -> bool {
    value.len() == 35
        && value.starts_with("op_")
        && value[3..]
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

fn valid_hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_command(value: &str) -> bool {
    !value.is_empty()
        && value.chars().count() <= 128
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ". _-".contains(c))
}

fn valid_error_code(value: &str) -> bool {
    value.strip_prefix("E050_").is_some_and(|tail| {
        !tail.is_empty()
            && tail
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    })
}

fn validate_context(value: &Value) -> Result<(), String> {
    if value.is_null() {
        return Ok(());
    }
    let object = value
        .as_object()
        .ok_or_else(|| "TOOL_CONTEXT_INVALID".to_string())?;
    let required = [
        "workspace_id",
        "project_id",
        "environment",
        "signer_id",
        "role",
    ];
    if object.len() != required.len() || required.iter().any(|field| !object.contains_key(*field)) {
        return Err("TOOL_CONTEXT_INVALID".into());
    }
    for field in ["workspace_id", "project_id"] {
        let text = object
            .get(field)
            .and_then(Value::as_str)
            .ok_or_else(|| "TOOL_CONTEXT_INVALID".to_string())?;
        if text.is_empty() || text.chars().count() > 128 {
            return Err("TOOL_CONTEXT_INVALID".into());
        }
    }
    if !matches!(
        object.get("environment").and_then(Value::as_str),
        Some("testnet-10") | Some("mainnet")
    ) {
        return Err("TOOL_CONTEXT_INVALID".into());
    }
    if let Some(value) = object.get("signer_id") {
        if !value.is_null() && value.as_str().is_none_or(|text| text.chars().count() > 128) {
            return Err("TOOL_CONTEXT_INVALID".into());
        }
    }
    if let Some(value) = object.get("role") {
        if !value.is_null() && value.as_str().is_none_or(|text| text.chars().count() > 64) {
            return Err("TOOL_CONTEXT_INVALID".into());
        }
    }
    Ok(())
}

fn validate_string_array(
    value: &Value,
    max_items: usize,
    max_length: usize,
    error: &str,
) -> Result<(), String> {
    let array = value.as_array().ok_or_else(|| error.to_string())?;
    if array.len() > max_items
        || array.iter().any(|item| {
            item.as_str()
                .is_none_or(|text| text.chars().count() > max_length)
        })
    {
        return Err(error.into());
    }
    Ok(())
}

pub fn validate_tool_result(value: &Value) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or_else(|| "TOOL_RESULT_NOT_OBJECT".to_string())?;
    if object.get("schema").and_then(Value::as_str) != Some(TOOL_RESULT_SCHEMA)
        || object.get("protocol_semver").and_then(Value::as_str) != Some(PROTOCOL)
    {
        return Err("TOOL_RESULT_IDENTITY_INVALID".into());
    }
    for field in [
        "command",
        "operation_id",
        "status",
        "network",
        "observed_tip",
        "context",
        "error_code",
        "warnings",
        "evidence_refs",
        "unsigned_operations",
        "data",
    ] {
        if !object.contains_key(field) {
            return Err(format!("TOOL_RESULT_FIELD_MISSING:{field}"));
        }
    }
    let operation_id = object
        .get("operation_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "TOOL_OPERATION_ID_INVALID".to_string())?;
    if !valid_operation_id(operation_id) {
        return Err("TOOL_OPERATION_ID_INVALID".into());
    }
    if !object
        .get("command")
        .and_then(Value::as_str)
        .is_some_and(valid_command)
    {
        return Err("TOOL_COMMAND_INVALID".into());
    }
    if !object
        .get("status")
        .and_then(Value::as_str)
        .map(|v| matches!(v, "PASS" | "BLOCKED" | "WARNING" | "UNAVAILABLE"))
        .unwrap_or(false)
    {
        return Err("TOOL_STATUS_INVALID".into());
    }
    if !object.get("network").is_some_and(|value| {
        value.is_null()
            || value
                .as_str()
                .is_some_and(|network| network == "testnet-10" || network == "mainnet")
    }) {
        return Err("TOOL_NETWORK_INVALID".into());
    }
    if !object
        .get("observed_tip")
        .is_some_and(|value| value.is_null() || value.as_str().is_some_and(valid_hex64))
    {
        return Err("TOOL_OBSERVED_TIP_INVALID".into());
    }
    if !object
        .get("error_code")
        .is_some_and(|value| value.is_null() || value.as_str().is_some_and(valid_error_code))
    {
        return Err("TOOL_ERROR_CODE_INVALID".into());
    }
    validate_context(
        object
            .get("context")
            .ok_or_else(|| "TOOL_CONTEXT_INVALID".to_string())?,
    )?;
    validate_string_array(
        object
            .get("warnings")
            .ok_or_else(|| "TOOL_WARNINGS_INVALID".to_string())?,
        64,
        512,
        "TOOL_WARNINGS_INVALID",
    )?;
    validate_string_array(
        object
            .get("evidence_refs")
            .ok_or_else(|| "TOOL_EVIDENCE_REFS_INVALID".to_string())?,
        128,
        256,
        "TOOL_EVIDENCE_REFS_INVALID",
    )?;
    validate_string_array(
        object
            .get("unsigned_operations")
            .ok_or_else(|| "TOOL_UNSIGNED_OPERATIONS_INVALID".to_string())?,
        32,
        256,
        "TOOL_UNSIGNED_OPERATIONS_INVALID",
    )?;
    if !object.get("data").map(Value::is_object).unwrap_or(false) {
        return Err("TOOL_DATA_NOT_OBJECT".into());
    }
    Ok(())
}

pub fn lock_hash(lock: &Map<String, Value>) -> Result<String, String> {
    let mut material = Value::Object(lock.clone());
    if let Value::Object(object) = &mut material {
        object.insert("lock_hash".into(), Value::String("0".repeat(64)));
    } else {
        return Err("DEVELOPER_LOCK_OBJECT_REQUIRED".into());
    }
    digest_json(&material, "KTAPEOUT/0.5.0/DEVELOPER_LOCK/V1")
}

pub fn deterministic_operation_id(
    command: &str,
    network: Option<&str>,
    data: &Value,
) -> Result<String, String> {
    let material = json!({"command": command, "network": network, "data": data});
    Ok(format!(
        "op_{}",
        &digest_json(&material, "KTAPEOUT/0.5.0/OPERATION/V1")?[..32]
    ))
}

pub fn validate_developer_lock(value: &Value) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or_else(|| "LOCK_NOT_OBJECT".to_string())?;
    let required_fields = [
        "schema",
        "protocol_semver",
        "lock_hash",
        "core_version",
        "feature_set_root",
        "profiles",
        "composition_root",
        "dependency_root",
        "runtime_digest",
        "compiler_lock_digest",
        "adapter_hash",
        "abi_version",
        "vector_root",
        "network_policy_id",
        "created_at",
    ];
    if object.len() != required_fields.len()
        || required_fields
            .iter()
            .any(|field| !object.contains_key(*field))
    {
        return Err("LOCK_FIELDS_INVALID".into());
    }
    if object.get("schema").and_then(Value::as_str) != Some(LOCK_SCHEMA)
        || object.get("protocol_semver").and_then(Value::as_str) != Some(PROTOCOL)
        || object.get("core_version").and_then(Value::as_str) != Some(PROTOCOL)
    {
        return Err("LOCK_IDENTITY_INVALID".into());
    }
    let expected = lock_hash(object)?;
    if object.get("lock_hash").and_then(Value::as_str) != Some(expected.as_str()) {
        return Err("LOCK_HASH_MISMATCH".into());
    }
    for field in [
        "feature_set_root",
        "composition_root",
        "dependency_root",
        "runtime_digest",
        "compiler_lock_digest",
        "adapter_hash",
        "vector_root",
    ] {
        let value = object
            .get(field)
            .and_then(Value::as_str)
            .unwrap_or_default();
        if value.len() != 64
            || !value
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        {
            return Err(format!("LOCK_HASH_INVALID:{field}"));
        }
    }
    let profiles = object
        .get("profiles")
        .and_then(Value::as_array)
        .ok_or_else(|| "LOCK_PROFILES_INVALID".to_string())?;
    if profiles.is_empty() {
        return Err("LOCK_PROFILES_INVALID".into());
    }
    for profile in profiles {
        let profile_object = profile
            .as_object()
            .ok_or_else(|| "LOCK_PROFILE_INVALID".to_string())?;
        let profile_fields = [
            "profile_id",
            "profile_hash",
            "package_digest",
            "admission_level",
            "package_provenance",
        ];
        if profile_object.len() != profile_fields.len()
            || profile_fields
                .iter()
                .any(|field| !profile_object.contains_key(*field))
        {
            return Err("LOCK_PROFILE_FIELDS_INVALID".into());
        }
        if profile
            .get("profile_id")
            .and_then(Value::as_str)
            .is_none_or(|item| item.is_empty() || item.len() > 128)
        {
            return Err("LOCK_PROFILE_ID_INVALID".into());
        }
        for field in ["profile_hash", "package_digest"] {
            let hash = profile
                .get(field)
                .and_then(Value::as_str)
                .unwrap_or_default();
            if hash.len() != 64
                || !hash
                    .chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
            {
                return Err(format!("LOCK_PROFILE_HASH_INVALID:{field}"));
            }
        }
        if !matches!(
            profile.get("admission_level").and_then(Value::as_str),
            Some("REFERENCE" | "IMPLEMENTED" | "TESTNET_ADMITTED" | "PRODUCTION_CANDIDATE")
        ) {
            return Err("LOCK_PROFILE_ADMISSION_INVALID".into());
        }
        let provenance = profile
            .get("package_provenance")
            .and_then(Value::as_object)
            .ok_or_else(|| "LOCK_PROFILE_PROVENANCE_INVALID".to_string())?;
        let provenance_fields = ["publisher_id", "source_ref", "license_ref", "trust_tier"];
        if provenance.len() != provenance_fields.len()
            || provenance_fields
                .iter()
                .any(|field| !provenance.contains_key(*field))
        {
            return Err("LOCK_PROFILE_PROVENANCE_INVALID".into());
        }
        for field in ["publisher_id", "source_ref", "license_ref", "trust_tier"] {
            let value = provenance
                .get(field)
                .and_then(Value::as_str)
                .unwrap_or_default();
            let max_len = if field == "source_ref" { 256 } else { 128 };
            if value.is_empty() || value.len() > max_len {
                return Err(format!("LOCK_PROFILE_PROVENANCE_INVALID:{field}"));
            }
        }
        if !matches!(
            provenance.get("trust_tier").and_then(Value::as_str),
            Some("UNTRUSTED" | "COMMUNITY" | "VERIFIED" | "CORE_MAINTAINER")
        ) {
            return Err("LOCK_PROFILE_TRUST_TIER_INVALID".into());
        }
    }
    if object
        .get("abi_version")
        .and_then(Value::as_str)
        .is_none_or(|value| value.is_empty() || value.len() > 64)
    {
        return Err("LOCK_ABI_VERSION_INVALID".into());
    }
    if object
        .get("network_policy_id")
        .and_then(Value::as_str)
        .is_none_or(|value| value.is_empty() || value.len() > 128)
    {
        return Err("LOCK_NETWORK_POLICY_INVALID".into());
    }
    if object
        .get("created_at")
        .and_then(Value::as_str)
        .is_none_or(|value| !valid_utc_expiry(value))
    {
        return Err("LOCK_CREATED_AT_INVALID".into());
    }
    Ok(())
}

pub const OPERATOR_SIGNER_REQUEST_SCHEMA: &str = "KTAPEOUT-OPERATOR-SIGNER-REQUEST-V1";
pub const OPERATOR_SIGNER_RESPONSE_SCHEMA: &str = "KTAPEOUT-OPERATOR-SIGNER-RESPONSE-V1";
pub const WALLET_SIGN_REQUEST_SCHEMA: &str = "KTAPEOUT-WALLET-SIGN-REQUEST-V1";
pub const WALLET_SIGN_REQUEST_V2_SCHEMA: &str = "KTAPEOUT-WALLET-SIGN-REQUEST-V2";
const MAX_OPERATOR_PAYLOAD_BYTES: usize = 512 * 1024;
const MAX_WALLET_SIGN_REQUEST_BYTES: usize = 16 * 1024;

fn valid_lower_hex(value: &str, lengths: &[usize]) -> bool {
    lengths.contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_wallet_role(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        && value.len() <= 64
        && bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
}

/// Validate a non-consensus, bounded request asking a wallet to sign specific
/// transaction inputs. This checks structure only; the exact PSKT codec,
/// transaction semantics, freshness, replay, and signature verification are
/// separate Bridge/Adapter responsibilities.
pub fn validate_wallet_sign_request(value: &Value) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or_else(|| "WALLET_SIGN_REQUEST_NOT_OBJECT".to_string())?;
    let fields = [
        "schema",
        "protocol_semver",
        "network_id",
        "operation_id",
        "request_id",
        "profile_id",
        "plan_hash",
        "unsigned_tx_digest",
        "pskt_digest",
        "expires_at_unix_ms",
        "input_count",
        "sign_inputs",
        "expected_signer_pubkey",
        "max_fee_sompi",
    ];
    if !exact_fields(object, &fields) {
        return Err("WALLET_SIGN_REQUEST_FIELDS_INVALID".into());
    }
    if object.get("schema").and_then(Value::as_str) != Some(WALLET_SIGN_REQUEST_SCHEMA)
        || object.get("protocol_semver").and_then(Value::as_str) != Some(PROTOCOL)
        || !matches!(
            object.get("network_id").and_then(Value::as_str),
            Some("testnet-10" | "mainnet")
        )
    {
        return Err("WALLET_SIGN_REQUEST_IDENTITY_INVALID".into());
    }
    if !object
        .get("operation_id")
        .and_then(Value::as_str)
        .is_some_and(valid_operation_id)
    {
        return Err("WALLET_SIGN_OPERATION_ID_INVALID".into());
    }
    if !object
        .get("request_id")
        .and_then(Value::as_str)
        .is_some_and(|value| valid_lower_hex(value, &[32]))
    {
        return Err("WALLET_SIGN_REQUEST_ID_INVALID".into());
    }
    let profile = object
        .get("profile_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if profile.is_empty()
        || profile.len() > 64
        || !profile.is_ascii()
        || !profile
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        || !profile.as_bytes()[0].is_ascii_alphanumeric()
    {
        return Err("WALLET_SIGN_PROFILE_ID_INVALID".into());
    }
    for field in ["plan_hash", "unsigned_tx_digest", "pskt_digest"] {
        if !object
            .get(field)
            .and_then(Value::as_str)
            .is_some_and(|value| valid_lower_hex(value, &[64]))
        {
            return Err("WALLET_SIGN_DIGEST_INVALID".into());
        }
    }
    if object
        .get("expires_at_unix_ms")
        .and_then(Value::as_u64)
        .is_none_or(|value| value > 9_007_199_254_740_991)
    {
        return Err("WALLET_SIGN_EXPIRY_INVALID".into());
    }
    let input_count = object
        .get("input_count")
        .and_then(Value::as_u64)
        .filter(|value| (1..=64).contains(value))
        .ok_or_else(|| "WALLET_SIGN_INPUT_COUNT_INVALID".to_string())?;
    let inputs = object
        .get("sign_inputs")
        .and_then(Value::as_array)
        .filter(|values| !values.is_empty() && values.len() <= 64)
        .ok_or_else(|| "WALLET_SIGN_INPUTS_INVALID".to_string())?;
    let mut previous_index: Option<u64> = None;
    for input in inputs {
        let input = input
            .as_object()
            .ok_or_else(|| "WALLET_SIGN_INPUT_INVALID".to_string())?;
        if !exact_fields(input, &["index", "role", "sighash_type"]) {
            return Err("WALLET_SIGN_INPUT_FIELDS_INVALID".into());
        }
        let index = input
            .get("index")
            .and_then(Value::as_u64)
            .ok_or_else(|| "WALLET_SIGN_INPUT_INDEX_INVALID".to_string())?;
        if index >= input_count {
            return Err("WALLET_SIGN_INPUT_INDEX_OUT_OF_RANGE".into());
        }
        if previous_index.is_some_and(|previous| index <= previous) {
            return Err("WALLET_SIGN_INPUTS_NOT_STRICTLY_SORTED".into());
        }
        previous_index = Some(index);
        if !input
            .get("role")
            .and_then(Value::as_str)
            .is_some_and(valid_wallet_role)
        {
            return Err("WALLET_SIGN_INPUT_ROLE_INVALID".into());
        }
        if input.get("sighash_type").and_then(Value::as_u64) != Some(1) {
            return Err("WALLET_SIGN_SIGHASH_UNSUPPORTED".into());
        }
    }
    if !object
        .get("expected_signer_pubkey")
        .and_then(Value::as_str)
        .is_some_and(|value| valid_lower_hex(value, &[64, 66]))
    {
        return Err("WALLET_SIGNER_PUBKEY_INVALID".into());
    }
    let fee = object
        .get("max_fee_sompi")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if fee.is_empty()
        || fee.len() > 20
        || (fee.len() > 1 && fee.starts_with('0'))
        || !fee.bytes().all(|byte| byte.is_ascii_digit())
        || fee.parse::<u64>().is_err()
    {
        return Err("WALLET_SIGN_FEE_INVALID".into());
    }
    if canonical_json(value)?.len() > MAX_WALLET_SIGN_REQUEST_BYTES {
        return Err("WALLET_SIGN_REQUEST_OVERSIZED".into());
    }
    Ok(())
}

pub fn wallet_sign_request_digest(value: &Value) -> Result<String, String> {
    validate_wallet_sign_request(value)?;
    digest_json(value, "KTAPEOUT/0.5.0/WALLET_SIGN_REQUEST/V1")
}

/// Validate a tooling-only V2 envelope. This checks claimed digest shape and
/// request structure only; a trusted Kaspa codec must recompute transaction
/// digests and verify their relationship to the locked plan before use.
pub fn validate_wallet_sign_request_v2(value: &Value) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or_else(|| "WALLET_SIGN_REQUEST_NOT_OBJECT".to_string())?;
    let fields = [
        "schema",
        "protocol_semver",
        "network_id",
        "operation_id",
        "request_id",
        "profile_id",
        "plan_hash",
        "canonical_tx_digest",
        "safe_json_input_digest",
        "codec_manifest_digest",
        "expires_at_unix_ms",
        "input_count",
        "sign_inputs",
        "expected_signer_pubkey",
        "max_fee_sompi",
    ];
    if !exact_fields(object, &fields) {
        return Err("WALLET_SIGN_REQUEST_FIELDS_INVALID".into());
    }
    if object.get("schema").and_then(Value::as_str) != Some(WALLET_SIGN_REQUEST_V2_SCHEMA) {
        return Err("WALLET_SIGN_REQUEST_IDENTITY_INVALID".into());
    }
    for field in [
        "canonical_tx_digest",
        "safe_json_input_digest",
        "codec_manifest_digest",
    ] {
        if !object
            .get(field)
            .and_then(Value::as_str)
            .is_some_and(|digest| valid_lower_hex(digest, &[64]))
        {
            return Err("WALLET_SIGN_DIGEST_INVALID".into());
        }
    }
    let mut legacy = value.clone();
    let legacy_object = legacy
        .as_object_mut()
        .ok_or_else(|| "WALLET_SIGN_REQUEST_NOT_OBJECT".to_string())?;
    legacy_object.remove("canonical_tx_digest");
    legacy_object.remove("safe_json_input_digest");
    legacy_object.remove("codec_manifest_digest");
    legacy_object.insert(
        "schema".into(),
        Value::String(WALLET_SIGN_REQUEST_SCHEMA.into()),
    );
    legacy_object.insert(
        "unsigned_tx_digest".into(),
        object["canonical_tx_digest"].clone(),
    );
    legacy_object.insert(
        "pskt_digest".into(),
        object["safe_json_input_digest"].clone(),
    );
    validate_wallet_sign_request(&legacy)?;
    if canonical_json(value)?.len() > MAX_WALLET_SIGN_REQUEST_BYTES {
        return Err("WALLET_SIGN_REQUEST_OVERSIZED".into());
    }
    Ok(())
}

pub fn wallet_sign_request_v2_digest(value: &Value) -> Result<String, String> {
    validate_wallet_sign_request_v2(value)?;
    digest_json(value, "KTAPEOUT/0.5.0/WALLET_SIGN_REQUEST/V2")
}

pub fn validate_wallet_codec_manifest(value: &Value) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or_else(|| "WALLET_CODEC_MANIFEST_FIELDS_INVALID".to_string())?;
    let fields = [
        "schema",
        "protocol_semver",
        "codec_id",
        "upstream_repository",
        "upstream_commit",
        "upstream_source_sha256",
        "cargo_lock_sha256",
        "adapter_source_sha256",
        "safe_json_api_id",
        "transaction_versions",
        "script_versions",
        "feature_set",
    ];
    if !exact_fields(object, &fields) {
        return Err("WALLET_CODEC_MANIFEST_FIELDS_INVALID".into());
    }
    if object.get("schema").and_then(Value::as_str) != Some("KTAPEOUT-KASPA-CODEC-MANIFEST-V1")
        || object.get("protocol_semver").and_then(Value::as_str) != Some(PROTOCOL)
    {
        return Err("WALLET_CODEC_MANIFEST_IDENTITY_INVALID".into());
    }
    for field in ["codec_id", "safe_json_api_id"] {
        let candidate = object
            .get(field)
            .and_then(Value::as_str)
            .unwrap_or_default();
        let mut bytes = candidate.bytes();
        if !bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
            || candidate.len() > 64
            || !bytes.all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || b".-".contains(&byte)
            })
        {
            return Err("WALLET_CODEC_MANIFEST_IDENTIFIER_INVALID".into());
        }
    }
    let repository = object
        .get("upstream_repository")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let repository_path = repository.strip_prefix("https://").unwrap_or_default();
    if repository_path.is_empty()
        || repository_path.len() > 240
        || !repository_path.is_ascii()
        || !repository_path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"./_-".contains(&byte))
    {
        return Err("WALLET_CODEC_MANIFEST_REPOSITORY_INVALID".into());
    }
    if !object
        .get("upstream_commit")
        .and_then(Value::as_str)
        .is_some_and(|commit| valid_lower_hex(commit, &[40]))
    {
        return Err("WALLET_CODEC_MANIFEST_COMMIT_INVALID".into());
    }
    for field in [
        "upstream_source_sha256",
        "cargo_lock_sha256",
        "adapter_source_sha256",
    ] {
        if !object
            .get(field)
            .and_then(Value::as_str)
            .is_some_and(|hash| valid_lower_hex(hash, &[64]))
        {
            return Err("WALLET_CODEC_MANIFEST_DIGEST_INVALID".into());
        }
    }
    for field in ["transaction_versions", "script_versions"] {
        let versions = object
            .get(field)
            .and_then(Value::as_array)
            .filter(|items| !items.is_empty() && items.len() <= 16)
            .ok_or_else(|| "WALLET_CODEC_MANIFEST_VERSIONS_INVALID".to_string())?;
        let mut previous: Option<u64> = None;
        for version in versions {
            let value = version
                .as_u64()
                .filter(|value| *value <= 255)
                .ok_or_else(|| "WALLET_CODEC_MANIFEST_VERSIONS_INVALID".to_string())?;
            if previous.is_some_and(|prior| value <= prior) {
                return Err("WALLET_CODEC_MANIFEST_VERSIONS_NOT_STRICTLY_SORTED".into());
            }
            previous = Some(value);
        }
    }
    let features = object
        .get("feature_set")
        .and_then(Value::as_array)
        .filter(|items| items.len() <= 32)
        .ok_or_else(|| "WALLET_CODEC_MANIFEST_FEATURES_INVALID".to_string())?;
    let mut previous: Option<&str> = None;
    for feature in features {
        let feature = feature.as_str().unwrap_or_default();
        let mut bytes = feature.bytes();
        if !bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
            || feature.len() > 64
            || !bytes.all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || b".-".contains(&byte)
            })
        {
            return Err("WALLET_CODEC_MANIFEST_FEATURES_INVALID".into());
        }
        if previous.is_some_and(|prior| feature <= prior) {
            return Err("WALLET_CODEC_MANIFEST_FEATURES_NOT_STRICTLY_SORTED".into());
        }
        previous = Some(feature);
    }
    if canonical_json(value)?.len() > MAX_WALLET_SIGN_REQUEST_BYTES {
        return Err("WALLET_CODEC_MANIFEST_OVERSIZED".into());
    }
    Ok(())
}

pub fn wallet_codec_manifest_digest(value: &Value) -> Result<String, String> {
    validate_wallet_codec_manifest(value)?;
    digest_json(value, "KTAPEOUT/0.5.0/KASPA_CODEC_MANIFEST/V1")
}

fn wallet_text_digest(value: &str, domain: &str) -> Result<String, String> {
    if value.is_empty() || value.len() > 512 * 1024 {
        return Err("WALLET_SIGN_TRANSACTION_TEXT_INVALID".into());
    }
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0]);
    hasher.update(value.as_bytes());
    Ok(hex(&hasher.finalize()))
}

/// Digest of Safe-JSON output supplied by the pinned codec; not a verifier.
pub fn wallet_canonical_tx_digest(codec_serialized_safe_json: &str) -> Result<String, String> {
    wallet_text_digest(
        codec_serialized_safe_json,
        "KTAPEOUT/0.5.0/KASPA_SAFE_JSON_TX/V1",
    )
}

/// Digest the exact UTF-8 string to be passed to the provider; not a parser.
pub fn wallet_safe_json_input_digest(exact_provider_text: &str) -> Result<String, String> {
    wallet_text_digest(
        exact_provider_text,
        "KTAPEOUT/0.5.0/KASPA_SAFE_JSON_INPUT/V1",
    )
}

fn valid_utc_expiry(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 20
        || bytes.len() > 64
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || *bytes.last().unwrap_or(&0) != b'Z'
    {
        return false;
    }
    let required_digits = [0usize, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15];
    if required_digits
        .iter()
        .any(|index| !bytes[*index].is_ascii_digit())
    {
        return false;
    }
    if bytes.len() > 20
        && (bytes[19] != b'.'
            || bytes[20..bytes.len() - 1].is_empty()
            || bytes[20..bytes.len() - 1]
                .iter()
                .any(|byte| !byte.is_ascii_digit()))
    {
        return false;
    }
    let number = |start: usize| -> u32 {
        ((bytes[start] - b'0') as u32) * 10 + (bytes[start + 1] - b'0') as u32
    };
    let year = ((bytes[0] - b'0') as u32) * 1000
        + ((bytes[1] - b'0') as u32) * 100
        + ((bytes[2] - b'0') as u32) * 10
        + (bytes[3] - b'0') as u32;
    let month = number(5);
    let day = number(8);
    let hour = number(11);
    let minute = number(14);
    let second = number(17);
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let days = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        _ => 0,
    };
    (1..=12).contains(&month)
        && (1..=days).contains(&day)
        && hour <= 23
        && minute <= 59
        && second <= 59
}

/// Compare canonical UTC timestamps accepted by `valid_utc_expiry`.
/// Returns `None` for malformed or non-UTC values instead of guessing.
pub fn compare_utc_timestamps(left: &str, right: &str) -> Option<std::cmp::Ordering> {
    type TimestampParts<'a> = ((u32, u32, u32, u32, u32, u32), &'a str);
    fn parts(value: &str) -> Option<TimestampParts<'_>> {
        if !valid_utc_expiry(value) {
            return None;
        }
        let bytes = value.as_bytes();
        let number = |start: usize, length: usize| -> u32 {
            value[start..start + length].parse().unwrap_or(0)
        };
        let base = (
            number(0, 4),
            number(5, 2),
            number(8, 2),
            number(11, 2),
            number(14, 2),
            number(17, 2),
        );
        let fraction = if bytes.len() > 20 {
            &value[20..value.len() - 1]
        } else {
            ""
        };
        Some((base, fraction))
    }
    let (left_base, left_fraction) = parts(left)?;
    let (right_base, right_fraction) = parts(right)?;
    let base_order = left_base.cmp(&right_base);
    if base_order != std::cmp::Ordering::Equal {
        return Some(base_order);
    }
    let width = left_fraction.len().max(right_fraction.len());
    for index in 0..width {
        let left_digit = left_fraction.as_bytes().get(index).copied().unwrap_or(b'0');
        let right_digit = right_fraction
            .as_bytes()
            .get(index)
            .copied()
            .unwrap_or(b'0');
        let order = left_digit.cmp(&right_digit);
        if order != std::cmp::Ordering::Equal {
            return Some(order);
        }
    }
    Some(std::cmp::Ordering::Equal)
}

fn contains_credential_key(value: &Value) -> bool {
    match value {
        Value::Object(map) => map.iter().any(|(key, child)| {
            let lower = key.to_ascii_lowercase();
            lower.contains("private_key")
                || lower.contains("privatekey")
                || lower.contains("mnemonic")
                || lower.contains("passphrase")
                || lower.contains("password")
                || lower.contains("wif")
                || lower.contains("credential")
                || lower == "seed"
                || lower.ends_with("_seed")
                || contains_credential_key(child)
        }),
        Value::Array(values) => values.iter().any(contains_credential_key),
        _ => false,
    }
}

fn exact_fields(object: &serde_json::Map<String, Value>, fields: &[&str]) -> bool {
    object.len() == fields.len() && fields.iter().all(|field| object.contains_key(*field))
}

/// Validate the non-consensus request passed from a developer tool to an
/// authenticated external operator. This function deliberately does not own
/// keys, verify an operator signature, sign bytes, or broadcast anything.
pub fn validate_operator_signer_request(value: &Value) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or_else(|| "OPERATOR_REQUEST_NOT_OBJECT".to_string())?;
    let fields = [
        "schema",
        "protocol_semver",
        "network",
        "operation",
        "plan_hash",
        "request_nonce",
        "expires_at",
        "payload",
    ];
    if !exact_fields(object, &fields) {
        return Err("OPERATOR_REQUEST_FIELD_SET_INVALID".into());
    }
    if object.get("schema").and_then(Value::as_str) != Some(OPERATOR_SIGNER_REQUEST_SCHEMA)
        || object.get("protocol_semver").and_then(Value::as_str) != Some(PROTOCOL)
        || object.get("network").and_then(Value::as_str) != Some("testnet-10")
    {
        return Err("OPERATOR_REQUEST_IDENTITY_INVALID".into());
    }
    if !matches!(
        object.get("operation").and_then(Value::as_str),
        Some("SELECT_INPUTS") | Some("SIGN") | Some("SUBMIT") | Some("REVALIDATE")
    ) {
        return Err("OPERATOR_REQUEST_OPERATION_INVALID".into());
    }
    for field in ["plan_hash", "request_nonce"] {
        if !object
            .get(field)
            .and_then(Value::as_str)
            .is_some_and(valid_hex64)
        {
            return Err(format!(
                "OPERATOR_REQUEST_{field_upper}_INVALID",
                field_upper = field.to_ascii_uppercase()
            ));
        }
    }
    if !object
        .get("expires_at")
        .and_then(Value::as_str)
        .is_some_and(valid_utc_expiry)
    {
        return Err("OPERATOR_REQUEST_EXPIRY_INVALID".into());
    }
    let payload = object
        .get("payload")
        .ok_or_else(|| "OPERATOR_REQUEST_PAYLOAD_INVALID".to_string())?;
    if !payload.is_object() || contains_credential_key(payload) {
        return Err("OPERATOR_REQUEST_CREDENTIAL_OR_PAYLOAD_INVALID".into());
    }
    if canonical_json(payload)?.len() > MAX_OPERATOR_PAYLOAD_BYTES {
        return Err("OPERATOR_REQUEST_PAYLOAD_OVERSIZED".into());
    }
    Ok(())
}

pub fn operator_request_digest(value: &Value) -> Result<String, String> {
    validate_operator_signer_request(value)?;
    digest_json(value, "KTAPEOUT/0.5.0/OPERATOR_REQUEST/V1")
}

/// Validate an operator response's shape and binding. The opaque attestation
/// is intentionally not treated as cryptographic proof here; a deployment
/// must inject a separately audited verifier before it can be admitted.
pub fn validate_operator_signer_response(request: &Value, response: &Value) -> Result<(), String> {
    let request_object = request
        .as_object()
        .ok_or_else(|| "OPERATOR_REQUEST_NOT_OBJECT".to_string())?;
    validate_operator_signer_request(request)?;
    let object = response
        .as_object()
        .ok_or_else(|| "OPERATOR_RESPONSE_NOT_OBJECT".to_string())?;
    let fields = [
        "schema",
        "protocol_semver",
        "network",
        "operation",
        "plan_hash",
        "request_nonce",
        "expires_at",
        "signed_tx",
        "signed_tx_digest",
        "signer_pubkey",
        "operator_attestation",
        "operator_request_digest",
    ];
    if !exact_fields(object, &fields) {
        return Err("OPERATOR_RESPONSE_FIELD_SET_INVALID".into());
    }
    if object.get("schema").and_then(Value::as_str) != Some(OPERATOR_SIGNER_RESPONSE_SCHEMA)
        || object.get("protocol_semver").and_then(Value::as_str) != Some(PROTOCOL)
        || object.get("network").and_then(Value::as_str) != Some("testnet-10")
        || object.get("operation") != request_object.get("operation")
        || object.get("plan_hash") != request_object.get("plan_hash")
        || object.get("request_nonce") != request_object.get("request_nonce")
        || object.get("expires_at") != request_object.get("expires_at")
    {
        return Err("OPERATOR_RESPONSE_BINDING_INVALID".into());
    }
    let signed_tx = object
        .get("signed_tx")
        .and_then(Value::as_str)
        .ok_or_else(|| "OPERATOR_RESPONSE_SIGNED_TX_INVALID".to_string())?;
    if signed_tx.is_empty()
        || signed_tx.len() > MAX_OPERATOR_PAYLOAD_BYTES
        || contains_credential_key(response)
    {
        return Err("OPERATOR_RESPONSE_SIGNED_TX_INVALID".into());
    }
    let expected_tx_digest = hex(&Sha256::digest(signed_tx.as_bytes()));
    if object.get("signed_tx_digest").and_then(Value::as_str) != Some(expected_tx_digest.as_str())
        || !object
            .get("signer_pubkey")
            .and_then(Value::as_str)
            .is_some_and(valid_hex64)
        || object
            .get("operator_attestation")
            .and_then(Value::as_str)
            .is_none_or(|value| value.is_empty() || value.len() > 256)
        || object
            .get("operator_request_digest")
            .and_then(Value::as_str)
            != Some(operator_request_digest(request)?.as_str())
    {
        return Err("OPERATOR_RESPONSE_BINDING_INVALID".into());
    }
    Ok(())
}
