use ktapeout_kaspa_verifier::{covenant_id_from_genesis_v1, GenesisOutputV1};
use serde_json::Value;
use sha2::{Digest, Sha256};

const SCHEMA: &str = "KTAPEOUT-GENESIS-PROVENANCE-V1";
const DOMAIN: &[u8] = b"KTAPEOUT/0.5.0/GENESIS_PROVENANCE/V1\0";
const MAX_PROOF_BYTES: usize = 256 * 1024;

fn exact_keys(value: &Value, required: &[&str]) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or("GENESIS_PROVENANCE_OBJECT_REQUIRED")?;
    if object.len() != required.len() || required.iter().any(|key| !object.contains_key(*key)) {
        return Err("GENESIS_PROVENANCE_FIELDS_INVALID".into());
    }
    Ok(())
}

fn valid_hash(value: &Value) -> Result<String, String> {
    let text = value
        .as_str()
        .filter(|value| super::valid_hash(value))
        .ok_or("GENESIS_PROVENANCE_HASH_INVALID")?;
    Ok(text.to_owned())
}

fn parse_hex32(value: &Value, error: &'static str) -> Result<[u8; 32], String> {
    let text = value.as_str().ok_or(error)?;
    let bytes = hex::decode(text).map_err(|_| error)?;
    bytes.try_into().map_err(|_| error.to_string())
}

fn canonical_digest(material: &Value) -> Result<String, String> {
    let bytes = super::canonical_json(material)?;
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    hasher.update(bytes);
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn parse_and_validate(
    value: &Value,
    allow_claim_placeholder: bool,
) -> Result<(String, String), String> {
    if super::canonical_json(value)?.len() > MAX_PROOF_BYTES {
        return Err("GENESIS_PROVENANCE_SIZE_LIMIT".into());
    }
    exact_keys(
        value,
        &[
            "schema",
            "protocol_semver",
            "network",
            "network_policy_hash",
            "adapter",
            "build",
            "genesis",
            "provenance_hash",
        ],
    )?;
    if value["schema"] != SCHEMA || value["protocol_semver"] != "0.5.0" {
        return Err("GENESIS_PROVENANCE_VERSION_INVALID".into());
    }
    if !matches!(value["network"].as_str(), Some("testnet-10" | "mainnet")) {
        return Err("GENESIS_PROVENANCE_NETWORK_INVALID".into());
    }
    valid_hash(&value["network_policy_hash"])?;
    let adapter = &value["adapter"];
    exact_keys(adapter, &["adapter_id", "codec_id", "adapter_hash"])?;
    for key in ["adapter_id", "codec_id"] {
        if adapter[key]
            .as_str()
            .is_none_or(|value| value.is_empty() || value.len() > 128)
        {
            return Err("GENESIS_PROVENANCE_ADAPTER_INVALID".into());
        }
    }
    valid_hash(&adapter["adapter_hash"])?;
    let build = &value["build"];
    exact_keys(
        build,
        &[
            "source_root",
            "dependency_root",
            "compiler_id",
            "compiler_version",
            "backend_id",
            "backend_version",
            "instantiation_hash",
        ],
    )?;
    for key in ["source_root", "dependency_root", "instantiation_hash"] {
        valid_hash(&build[key])?;
    }
    for key in [
        "compiler_id",
        "compiler_version",
        "backend_id",
        "backend_version",
    ] {
        if build[key]
            .as_str()
            .is_none_or(|value| value.is_empty() || value.len() > 128)
        {
            return Err("GENESIS_PROVENANCE_BUILD_INVALID".into());
        }
    }

    let genesis = &value["genesis"];
    exact_keys(
        genesis,
        &["authorizing_outpoint", "outputs", "claimed_covenant_id"],
    )?;
    let outpoint = &genesis["authorizing_outpoint"];
    exact_keys(outpoint, &["transaction_id", "index"])?;
    let txid = parse_hex32(&outpoint["transaction_id"], "GENESIS_OUTPOINT_INVALID")?;
    if txid == [0; 32] || outpoint["index"].as_u64().is_none() {
        return Err("GENESIS_OUTPOINT_INVALID".into());
    }
    let outputs = genesis["outputs"]
        .as_array()
        .filter(|outputs| !outputs.is_empty() && outputs.len() <= 64)
        .ok_or("GENESIS_OUTPUT_GROUP_INVALID")?;
    let mut materialized = Vec::with_capacity(outputs.len());
    let mut previous_index = None;
    for output in outputs {
        exact_keys(
            output,
            &[
                "index",
                "value_sompi",
                "script_public_key_version",
                "script_public_key",
            ],
        )?;
        let index = output["index"]
            .as_u64()
            .filter(|value| *value <= u32::MAX as u64)
            .ok_or("GENESIS_OUTPUT_INDEX_INVALID")? as u32;
        if previous_index.is_some_and(|previous| previous >= index) {
            return Err("GENESIS_OUTPUT_INDEX_ORDER_INVALID".into());
        }
        previous_index = Some(index);
        let value_sompi = output["value_sompi"]
            .as_u64()
            .filter(|value| *value > 0)
            .ok_or("GENESIS_OUTPUT_VALUE_INVALID")?;
        let version = output["script_public_key_version"]
            .as_u64()
            .filter(|value| *value == 0)
            .ok_or("GENESIS_SCRIPT_VERSION_UNSUPPORTED")? as u16;
        let script = output["script_public_key"]
            .as_str()
            .ok_or("GENESIS_SCRIPT_INVALID")?;
        if script.len() < 2
            || script.len() > 600_000
            || script
                .bytes()
                .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
        {
            return Err("GENESIS_SCRIPT_INVALID".into());
        }
        let script_bytes = hex::decode(script).map_err(|_| "GENESIS_SCRIPT_INVALID")?;
        materialized.push(GenesisOutputV1 {
            index,
            value_sompi,
            script_public_key_version: version,
            script_public_key: script_bytes,
        });
    }
    let claimed = valid_hash(&genesis["claimed_covenant_id"])?;
    let computed = covenant_id_from_genesis_v1(
        txid,
        outpoint["index"].as_u64().unwrap() as u32,
        &materialized,
    )
    .map_err(|error| error.to_string())?;
    if claimed != computed && !(allow_claim_placeholder && claimed == "0".repeat(64)) {
        return Err("GENESIS_COVENANT_ID_MISMATCH".into());
    }
    Ok((claimed, computed))
}

/// Bind a complete, already materialized genesis template to its provenance hash.
pub fn compose(mut value: Value) -> Result<Value, String> {
    let (_, computed) = parse_and_validate(&value, true)?;
    value["genesis"]["claimed_covenant_id"] = Value::String(computed);
    value["provenance_hash"] = Value::String("0".repeat(64));
    let mut material = value
        .as_object()
        .ok_or("GENESIS_PROVENANCE_OBJECT_REQUIRED")?
        .clone();
    material.remove("provenance_hash");
    value["provenance_hash"] = Value::String(canonical_digest(&Value::Object(material))?);
    verify(&value, None)?;
    Ok(value)
}

/// Verify provenance and optionally compare with an independent Covenant ID.
pub fn verify(value: &Value, expected_id: Option<&str>) -> Result<Value, String> {
    verify_with_evidence(value, expected_id, None, None)
}

fn serialized_script(version: u16, script: &str) -> String {
    format!("{version:04x}{script}")
}

fn verify_source_rebuild(proof: &Value, rebuild: &Value) -> Result<(), String> {
    let object = rebuild
        .as_object()
        .ok_or("GENESIS_REBUILD_RESULT_OBJECT_REQUIRED")?;
    let required = [
        "schema",
        "status",
        "adapter_id",
        "codec_id",
        "adapter_hash",
        "source_root",
        "dependency_root",
        "compiler_id",
        "compiler_version",
        "backend_id",
        "backend_version",
        "instantiation_hash",
        "outputs",
    ];
    if object.len() != required.len() || required.iter().any(|key| !object.contains_key(*key)) {
        return Err("GENESIS_REBUILD_RESULT_FIELDS_INVALID".into());
    }
    if rebuild["schema"] != "KTAPEOUT-GENESIS-SOURCE-REBUILD-RESULT-V1"
        || rebuild["status"] != "PASS"
    {
        return Err("GENESIS_REBUILD_RESULT_NOT_PASS".into());
    }
    let adapter = &proof["adapter"];
    let build = &proof["build"];
    for (left, right) in [
        ("adapter_id", &adapter["adapter_id"]),
        ("codec_id", &adapter["codec_id"]),
        ("adapter_hash", &adapter["adapter_hash"]),
        ("source_root", &build["source_root"]),
        ("dependency_root", &build["dependency_root"]),
        ("compiler_id", &build["compiler_id"]),
        ("compiler_version", &build["compiler_version"]),
        ("backend_id", &build["backend_id"]),
        ("backend_version", &build["backend_version"]),
        ("instantiation_hash", &build["instantiation_hash"]),
    ] {
        if rebuild[left] != *right {
            return Err(format!("GENESIS_REBUILD_RESULT_BINDING_MISMATCH:{left}"));
        }
    }
    let proof_outputs = proof["genesis"]["outputs"]
        .as_array()
        .ok_or("GENESIS_OUTPUT_GROUP_INVALID")?;
    let rebuilt_outputs = rebuild["outputs"]
        .as_array()
        .filter(|items| items.len() == proof_outputs.len())
        .ok_or("GENESIS_REBUILD_OUTPUTS_INVALID")?;
    for (proof_output, rebuilt_output) in proof_outputs.iter().zip(rebuilt_outputs) {
        if rebuilt_output.as_object().is_none()
            || rebuilt_output.as_object().unwrap().len() != 2
            || rebuilt_output.get("index").is_none()
            || rebuilt_output.get("script_public_key").is_none()
        {
            return Err("GENESIS_REBUILD_OUTPUT_INVALID".into());
        }
        if rebuilt_output["index"] != proof_output["index"]
            || rebuilt_output["script_public_key"]
                != serialized_script(
                    proof_output["script_public_key_version"].as_u64().unwrap() as u16,
                    proof_output["script_public_key"].as_str().unwrap(),
                )
        {
            return Err("GENESIS_REBUILD_SCRIPT_MISMATCH".into());
        }
    }
    Ok(())
}

fn verify_deployment_readback(proof: &Value, readback: &Value) -> Result<(), String> {
    let proof_outputs = proof["genesis"]["outputs"]
        .as_array()
        .ok_or("GENESIS_READBACK_PROOF_OUTPUTS_INVALID")?;
    if proof_outputs.len() != 1 {
        return Err("GENESIS_READBACK_PROFILE_SHAPE_UNSUPPORTED".into());
    }
    if readback["network"] != proof["network"]
        || readback["status"] != "CONFIRMED_DUAL_RPC"
        || readback["dual_rpc_readback"] != true
    {
        return Err("GENESIS_READBACK_STATUS_INVALID".into());
    }
    let txid = readback["txid"]
        .as_str()
        .filter(|value| super::valid_hash(value))
        .ok_or("GENESIS_READBACK_TXID_INVALID")?;
    let input_outpoint = readback["input"]["outpoint"]
        .as_str()
        .ok_or("GENESIS_READBACK_INPUT_INVALID")?;
    let expected_input = format!(
        "{}:{}",
        proof["genesis"]["authorizing_outpoint"]["transaction_id"]
            .as_str()
            .unwrap(),
        proof["genesis"]["authorizing_outpoint"]["index"]
            .as_u64()
            .unwrap()
    );
    if input_outpoint != expected_input {
        return Err("GENESIS_READBACK_INPUT_MISMATCH".into());
    }
    let output = &readback["profile_output"];
    if output["index"] != proof["genesis"]["outputs"][0]["index"]
        || output["amount_sompi"] != proof["genesis"]["outputs"][0]["value_sompi"]
        || output["covenant_id"] != proof["genesis"]["claimed_covenant_id"]
    {
        return Err("GENESIS_READBACK_OUTPUT_MISMATCH".into());
    }
    let serialized = output["script_public_key"]
        .as_str()
        .filter(|value| {
            value.len() >= 4
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
        .ok_or("GENESIS_READBACK_SCRIPT_INVALID")?;
    let expected_script = serialized_script(
        proof["genesis"]["outputs"][0]["script_public_key_version"]
            .as_u64()
            .unwrap() as u16,
        proof["genesis"]["outputs"][0]["script_public_key"]
            .as_str()
            .unwrap(),
    );
    if serialized != expected_script {
        return Err("GENESIS_READBACK_SCRIPT_MISMATCH".into());
    }
    if readback["rpc_observations"]
        .as_array()
        .filter(|items| {
            items.len() >= 2
                && items
                    .iter()
                    .all(|item| item["exact_profile_outpoint"] == true)
        })
        .is_none()
    {
        return Err("GENESIS_READBACK_DUAL_RPC_INVALID".into());
    }
    let _ = txid;
    Ok(())
}

pub fn verify_with_evidence(
    value: &Value,
    expected_id: Option<&str>,
    rebuild: Option<&Value>,
    readback: Option<&Value>,
) -> Result<Value, String> {
    let (claimed, computed) = parse_and_validate(value, false)?;
    let actual_hash = {
        let mut material = value
            .as_object()
            .ok_or("GENESIS_PROVENANCE_OBJECT_REQUIRED")?
            .clone();
        material.insert("provenance_hash".into(), Value::String("0".repeat(64)));
        material.remove("provenance_hash");
        canonical_digest(&Value::Object(material))?
    };
    if value["provenance_hash"].as_str() != Some(actual_hash.as_str()) {
        return Err("GENESIS_PROVENANCE_HASH_MISMATCH".into());
    }
    let independent_match = expected_id
        .map(|expected| expected == computed)
        .unwrap_or(false);
    if let Some(expected) = expected_id {
        if !super::valid_hash(expected) {
            return Err("GENESIS_EXPECTED_ID_INVALID".into());
        }
        if !independent_match {
            return Err("GENESIS_EXPECTED_ID_MISMATCH".into());
        }
    }
    let source_match = if let Some(rebuild) = rebuild {
        verify_source_rebuild(value, rebuild)?;
        "PASS"
    } else {
        "NOT_CHECKED"
    };
    let deployment_observation = if let Some(readback) = readback {
        verify_deployment_readback(value, readback)?;
        "PASS"
    } else {
        "NOT_CHECKED"
    };
    let authorized_output_indices = value["genesis"]["outputs"]
        .as_array()
        .ok_or("GENESIS_OUTPUT_GROUP_INVALID")?
        .iter()
        .map(|output| output["index"].clone())
        .collect::<Vec<_>>();
    Ok(serde_json::json!({
        "schema": "KTAPEOUT-GENESIS-PROVENANCE-RESULT-V1",
        "protocol_semver": "0.5.0",
        "network": value["network"],
        "provenance_hash": value["provenance_hash"],
        "expected_covenant_id": expected_id,
        "computed_covenant_id": computed,
        "genesis_match": "PASS",
        "source_match": source_match,
        "deployment_observation": deployment_observation,
        "independent_id_match": independent_match,
        "verification_scope": "GENESIS_PROVENANCE",
        "identity_basis": {
            "kind": "COVENANT_GENESIS",
            "covenant_id": computed,
            "authorizing_outpoint": value["genesis"]["authorizing_outpoint"],
            "authorized_output_indices": authorized_output_indices
        },
        "state_scope": "GENESIS_ONLY",
        "current_state": "NOT_CHECKED",
        "signing_allowed": false,
        "broadcast": false,
        "claimed_covenant_id": claimed
    }))
}
