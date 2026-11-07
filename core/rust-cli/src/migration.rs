use serde_json::Value;
use sha2::{Digest, Sha256};

const DOMAIN_V1: &[u8] = b"KTAPEOUT/0.5.0/PROFILE_MIGRATION_CONTRACT/V1\0";
const DOMAIN_V2: &[u8] = b"KTAPEOUT/0.5.0/PROFILE_MIGRATION_CONTRACT/V2\0";

/// Verify a Profile-provided bounded migration declaration.
/// This validates a contract and never executes migration code or grants L1 authority.
pub fn verify(contract: &Value) -> Result<(), String> {
    let object = contract
        .as_object()
        .ok_or("MIGRATION_CONTRACT_OBJECT_REQUIRED")?;
    let base_fields = [
        "schema",
        "protocol_semver",
        "migration_id",
        "profile_id",
        "mode",
        "old_state_schema_hash",
        "new_state_schema_hash",
        "input_root",
        "output_root",
        "invariant_root",
        "authorization",
        "replay",
        "failure",
        "max_items",
        "max_input_bytes",
        "max_output_bytes",
        "max_fee_sompi",
        "reversible",
        "contract_hash",
    ];
    let is_release_bound = contract["schema"] == "KTAPEOUT-PROFILE-MIGRATION-CONTRACT-V2";
    let release_fields = ["application_id", "network", "predecessor", "target"];
    let expected_count = base_fields.len()
        + if is_release_bound {
            release_fields.len()
        } else {
            0
        };
    if object.len() != expected_count
        || base_fields.iter().any(|key| !object.contains_key(*key))
        || (is_release_bound && release_fields.iter().any(|key| !object.contains_key(*key)))
    {
        return Err("MIGRATION_CONTRACT_FIELDS_INVALID".into());
    }
    if !matches!(
        contract["schema"].as_str(),
        Some("KTAPEOUT-PROFILE-MIGRATION-CONTRACT-V1" | "KTAPEOUT-PROFILE-MIGRATION-CONTRACT-V2")
    ) || contract["protocol_semver"] != "0.5.0"
    {
        return Err("MIGRATION_CONTRACT_VERSION_INVALID".into());
    }
    if is_release_bound {
        if !contract["application_id"]
            .as_str()
            .is_some_and(super::valid_hash)
        {
            return Err("MIGRATION_APPLICATION_ID_INVALID".into());
        }
        if !matches!(contract["network"].as_str(), Some("testnet-10" | "mainnet")) {
            return Err("MIGRATION_NETWORK_INVALID".into());
        }
        for key in ["predecessor", "target"] {
            let tuple = contract[key]
                .as_object()
                .filter(|value| value.len() == 2)
                .ok_or_else(|| format!("MIGRATION_RELEASE_TUPLE_INVALID:{key}"))?;
            for field in ["release_id", "artifact_root"] {
                if !tuple
                    .get(field)
                    .and_then(Value::as_str)
                    .is_some_and(super::valid_hash)
                {
                    return Err(format!("MIGRATION_RELEASE_HASH_INVALID:{key}.{field}"));
                }
            }
        }
        if contract["predecessor"]["release_id"] == contract["target"]["release_id"]
            && contract["predecessor"]["artifact_root"] == contract["target"]["artifact_root"]
        {
            return Err("MIGRATION_RELEASE_PAIR_UNCHANGED".into());
        }
    }
    let migration_id = contract["migration_id"]
        .as_str()
        .filter(|value| {
            value.len() == 36
                && value.starts_with("mig_")
                && value[4..]
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
        .ok_or("MIGRATION_ID_INVALID")?;
    let _ = migration_id;
    let profile_id = contract["profile_id"]
        .as_str()
        .filter(|value| super::valid_profile_id(value))
        .ok_or("MIGRATION_PROFILE_ID_INVALID")?;
    let _ = profile_id;
    if !matches!(
        contract["mode"].as_str(),
        Some("SHARED_STATE" | "USER_LAZY" | "BATCH_DOMAIN")
    ) {
        return Err("MIGRATION_MODE_INVALID".into());
    }
    for key in [
        "old_state_schema_hash",
        "new_state_schema_hash",
        "input_root",
        "output_root",
        "invariant_root",
        "contract_hash",
    ] {
        if !contract[key].as_str().is_some_and(super::valid_hash) {
            return Err(format!("MIGRATION_HASH_INVALID:{key}"));
        }
    }
    for key in ["authorization", "replay", "failure"] {
        if !contract[key].is_object() {
            return Err(format!("MIGRATION_OBJECT_REQUIRED:{key}"));
        }
    }
    let max_items = bounded_u64(contract, "max_items", 1, 1_000_000)?;
    let max_input_bytes = bounded_u64(contract, "max_input_bytes", 1, 4 * 1024 * 1024)?;
    let max_output_bytes = bounded_u64(contract, "max_output_bytes", 1, 4 * 1024 * 1024)?;
    let max_fee_sompi = contract["max_fee_sompi"]
        .as_u64()
        .ok_or("MIGRATION_FEE_INVALID")?;
    if max_fee_sompi == 0 || max_items == 0 || max_input_bytes == 0 || max_output_bytes == 0 {
        return Err("MIGRATION_BOUND_INVALID".into());
    }
    if !contract["reversible"].is_boolean() {
        return Err("MIGRATION_REVERSIBILITY_INVALID".into());
    }
    let _ = (max_items, max_input_bytes, max_output_bytes);
    let material = object
        .clone()
        .into_iter()
        .filter(|(key, _)| key != "contract_hash")
        .collect();
    let mut digest = Sha256::new();
    digest.update(if is_release_bound {
        DOMAIN_V2
    } else {
        DOMAIN_V1
    });
    digest.update(super::canonical_json(&Value::Object(material))?);
    let actual = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if contract["contract_hash"].as_str() != Some(&actual) {
        return Err("MIGRATION_CONTRACT_HASH_MISMATCH".into());
    }
    Ok(())
}

/// Match a verified migration declaration to two package-verified Profile
/// descriptors. This proves only the local Profile/schema pair; callers must
/// bind these packages to the application Releases separately.
pub fn verify_profile_pair(
    contract: &Value,
    old_package: &Value,
    old_descriptor: &Value,
    new_package: &Value,
    new_descriptor: &Value,
) -> Result<Value, String> {
    verify(contract)?;
    let profile_id = contract["profile_id"]
        .as_str()
        .ok_or("MIGRATION_PROFILE_ID_INVALID")?;
    if old_package["profile_id"].as_str() != Some(profile_id)
        || new_package["profile_id"].as_str() != Some(profile_id)
    {
        return Err("MIGRATION_PROFILE_PAIR_ID_MISMATCH".into());
    }
    for (label, package, descriptor) in [
        ("old", old_package, old_descriptor),
        ("new", new_package, new_descriptor),
    ] {
        let profile_id = package
            .get("profile_id")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("MIGRATION_PROFILE_PAIR_PACKAGE_INVALID:{label}"))?;
        let profile_hash = package
            .get("profile_hash")
            .and_then(Value::as_str)
            .filter(|value| super::valid_hash(value))
            .ok_or_else(|| format!("MIGRATION_PROFILE_PAIR_PACKAGE_INVALID:{label}"))?;
        if !package
            .get("package_digest")
            .and_then(Value::as_str)
            .is_some_and(super::valid_hash)
        {
            return Err(format!("MIGRATION_PROFILE_PAIR_PACKAGE_INVALID:{label}"));
        }
        if descriptor.get("profile_id").and_then(Value::as_str) != Some(profile_id)
            || descriptor.get("profile_hash").and_then(Value::as_str) != Some(profile_hash)
        {
            return Err(format!(
                "MIGRATION_PROFILE_PAIR_DESCRIPTOR_MISMATCH:{label}"
            ));
        }
    }

    let old_state_schema_hash = old_descriptor["state_encoding_hash"]
        .as_str()
        .filter(|value| super::valid_hash(value))
        .ok_or("MIGRATION_PROFILE_PAIR_STATE_SCHEMA_INVALID:old")?;
    let new_state_schema_hash = new_descriptor["state_encoding_hash"]
        .as_str()
        .filter(|value| super::valid_hash(value))
        .ok_or("MIGRATION_PROFILE_PAIR_STATE_SCHEMA_INVALID:new")?;
    if contract["old_state_schema_hash"].as_str() != Some(old_state_schema_hash) {
        return Err("MIGRATION_PROFILE_PAIR_OLD_SCHEMA_MISMATCH".into());
    }
    if contract["new_state_schema_hash"].as_str() != Some(new_state_schema_hash) {
        return Err("MIGRATION_PROFILE_PAIR_NEW_SCHEMA_MISMATCH".into());
    }
    Ok(serde_json::json!({
        "status":"MATCHED_LOCAL_PROFILE_PAIR",
        "profile_id":profile_id,
        "old_profile_hash":old_package["profile_hash"],
        "old_package_digest":old_package["package_digest"],
        "old_state_schema_hash":old_state_schema_hash,
        "new_profile_hash":new_package["profile_hash"],
        "new_package_digest":new_package["package_digest"],
        "new_state_schema_hash":new_state_schema_hash,
        "application_release_binding":"NOT_CHECKED",
        "migration_execution":false
    }))
}

fn bounded_u64(contract: &Value, key: &str, minimum: u64, maximum: u64) -> Result<u64, String> {
    let value = contract[key]
        .as_u64()
        .ok_or_else(|| format!("MIGRATION_BOUND_INVALID:{key}"))?;
    if value < minimum || value > maximum {
        return Err(format!("MIGRATION_BOUND_INVALID:{key}"));
    }
    Ok(value)
}
