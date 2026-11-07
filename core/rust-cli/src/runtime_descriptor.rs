use serde_json::{Map, Value};

const SCHEMA: &str = "KTAPEOUT-RUNTIME-DESCRIPTOR-V1";
const DOMAIN: &str = "KTAPEOUT/0.5.0/RUNTIME_DESCRIPTOR/V1";

fn object<'a>(value: &'a Value, code: &str) -> Result<&'a Map<String, Value>, String> {
    value.as_object().ok_or_else(|| code.to_string())
}
fn exact(value: &Value, required: &[&str], optional: &[&str], code: &str) -> Result<(), String> {
    let object = object(value, code)?;
    if object
        .keys()
        .any(|key| !required.contains(&key.as_str()) && !optional.contains(&key.as_str()))
        || required.iter().any(|key| !object.contains_key(*key))
    {
        return Err(code.to_string());
    }
    Ok(())
}
fn hash(value: &Value, code: &str) -> Result<(), String> {
    match value.as_str() {
        Some(value)
            if value.len() == 64
                && value
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) =>
        {
            Ok(())
        }
        _ => Err(code.to_string()),
    }
}
fn identifier(value: &Value, code: &str) -> Result<(), String> {
    let value = value.as_str().ok_or_else(|| code.to_string())?;
    if value.is_empty()
        || value.len() > 64
        || !value.as_bytes()[0].is_ascii_lowercase()
        || !value.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
    {
        return Err(code.to_string());
    }
    Ok(())
}
fn roles(value: &Value, code: &str) -> Result<(), String> {
    let values = value.as_array().ok_or_else(|| code.to_string())?;
    if values.is_empty() || values.len() > 64 {
        return Err(code.to_string());
    }
    for (i, item) in values.iter().enumerate() {
        identifier(item, &format!("{code}:{i}"))?;
    }
    let mut sorted = values
        .iter()
        .map(|v| v.as_str().unwrap_or_default())
        .collect::<Vec<_>>();
    let before = sorted.len();
    sorted.sort_unstable();
    sorted.dedup();
    if sorted.len() != before {
        return Err(code.to_string());
    }
    Ok(())
}

pub fn verify(value: &Value) -> Result<(), String> {
    exact(
        value,
        &[
            "schema",
            "descriptor_semver",
            "executor",
            "definitions",
            "resources",
            "state_contract",
            "capability_policy_ref",
            "resource_policy_ref",
            "descriptor_hash",
        ],
        &[],
        "RUNTIME_DESCRIPTOR_FIELDS_INVALID",
    )?;
    if value["schema"] != SCHEMA || value["descriptor_semver"] != "1.0.0" {
        return Err("RUNTIME_DESCRIPTOR_IDENTITY_INVALID".into());
    }
    let executor = &value["executor"];
    exact(
        executor,
        &["artifact_hash", "format", "abi_hash", "entrypoint"],
        &[],
        "RUNTIME_DESCRIPTOR_EXECUTOR_FIELDS_INVALID",
    )?;
    hash(
        &executor["artifact_hash"],
        "RUNTIME_DESCRIPTOR_EXECUTOR_ARTIFACT_INVALID",
    )?;
    hash(
        &executor["abi_hash"],
        "RUNTIME_DESCRIPTOR_EXECUTOR_ABI_INVALID",
    )?;
    identifier(
        &executor["format"],
        "RUNTIME_DESCRIPTOR_EXECUTOR_FORMAT_INVALID",
    )?;
    let entrypoint = executor["entrypoint"]
        .as_str()
        .ok_or("RUNTIME_DESCRIPTOR_ENTRYPOINT_INVALID")?;
    if entrypoint.is_empty()
        || entrypoint.len() > 128
        || !entrypoint.as_bytes()[0].is_ascii_lowercase()
        || !entrypoint.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'/' | b'-')
        })
    {
        return Err("RUNTIME_DESCRIPTOR_ENTRYPOINT_INVALID".into());
    }
    for (field, hash_field, code) in [
        (
            "definitions",
            "schema_hash",
            "RUNTIME_DESCRIPTOR_DEFINITIONS_FIELDS_INVALID",
        ),
        (
            "resources",
            "manifest_hash",
            "RUNTIME_DESCRIPTOR_RESOURCES_FIELDS_INVALID",
        ),
    ] {
        let item = &value[field];
        exact(item, &[hash_field, "roles"], &[], code)?;
        hash(
            &item[hash_field],
            &format!(
                "RUNTIME_DESCRIPTOR_{}_{}_INVALID",
                field.to_uppercase(),
                hash_field.to_uppercase()
            ),
        )?;
        roles(
            &item["roles"],
            &format!("RUNTIME_DESCRIPTOR_{}_ROLES_INVALID", field.to_uppercase()),
        )?;
    }
    let state = &value["state_contract"];
    exact(
        state,
        &["schema_hash", "scope", "migration_contract_hash"],
        &[],
        "RUNTIME_DESCRIPTOR_STATE_FIELDS_INVALID",
    )?;
    hash(
        &state["schema_hash"],
        "RUNTIME_DESCRIPTOR_STATE_SCHEMA_INVALID",
    )?;
    if !["LOCAL", "USER", "APPLICATION", "PARTITION"]
        .contains(&state["scope"].as_str().unwrap_or_default())
    {
        return Err("RUNTIME_DESCRIPTOR_STATE_SCOPE_INVALID".into());
    }
    if !state["migration_contract_hash"].is_null() {
        hash(
            &state["migration_contract_hash"],
            "RUNTIME_DESCRIPTOR_MIGRATION_HASH_INVALID",
        )?;
    }
    hash(
        &value["capability_policy_ref"],
        "RUNTIME_DESCRIPTOR_CAPABILITY_POLICY_INVALID",
    )?;
    hash(
        &value["resource_policy_ref"],
        "RUNTIME_DESCRIPTOR_RESOURCE_POLICY_INVALID",
    )?;
    hash(&value["descriptor_hash"], "RUNTIME_DESCRIPTOR_HASH_INVALID")?;
    let mut material = value.clone();
    material.as_object_mut().unwrap().remove("descriptor_hash");
    if crate::digest_json_domain(&material, DOMAIN)? != value["descriptor_hash"] {
        return Err("RUNTIME_DESCRIPTOR_HASH_MISMATCH".into());
    }
    Ok(())
}

pub fn verify_package_binding(package: &Value, descriptor: &Value) -> Result<Value, String> {
    verify(descriptor)?;
    if package.get("schema").and_then(Value::as_str) != Some("KTAPEOUT-APPLICATION-PACKAGE-V0.5.0")
        || package.get("protocol_semver").and_then(Value::as_str) != Some("0.5.0")
    {
        return Err("RUNTIME_DESCRIPTOR_PACKAGE_IDENTITY_INVALID".into());
    }
    let expected = descriptor["descriptor_hash"].as_str().unwrap();
    let actual = package
        .get("extensions")
        .and_then(Value::as_object)
        .and_then(|v| v.get("runtime_descriptor_ref"))
        .and_then(Value::as_str);
    if actual != Some(expected) {
        return Err("RUNTIME_DESCRIPTOR_PACKAGE_BINDING_MISMATCH".into());
    }
    let artifact_id = package
        .get("identity")
        .and_then(|v| v.get("artifact_id"))
        .and_then(Value::as_str)
        .filter(|value| super::valid_hash(value))
        .ok_or("RUNTIME_DESCRIPTOR_PACKAGE_ARTIFACT_INVALID")?;
    if Some(artifact_id) != descriptor["executor"]["artifact_hash"].as_str() {
        return Err("RUNTIME_DESCRIPTOR_ARTIFACT_BINDING_MISMATCH".into());
    }
    let provenance = package
        .get("provenance")
        .and_then(Value::as_object)
        .ok_or("RUNTIME_DESCRIPTOR_PACKAGE_PROVENANCE_INVALID")?;
    if provenance.get("artifact_format") != descriptor["executor"].get("format") {
        return Err("RUNTIME_DESCRIPTOR_FORMAT_BINDING_MISMATCH".into());
    }
    let abi_hash = provenance
        .get("abi_hash")
        .and_then(Value::as_str)
        .filter(|value| super::valid_hash(value))
        .ok_or("RUNTIME_DESCRIPTOR_PACKAGE_ABI_INVALID")?;
    if Some(abi_hash) != descriptor["executor"]["abi_hash"].as_str() {
        return Err("RUNTIME_DESCRIPTOR_ABI_BINDING_MISMATCH".into());
    }
    let entrypoint_binding = match provenance.get("entrypoints") {
        None => "NOT_DECLARED",
        Some(value) => {
            let entrypoints = value
                .as_array()
                .ok_or("RUNTIME_DESCRIPTOR_PACKAGE_ENTRYPOINTS_INVALID")?;
            if entrypoints.len() > 32 {
                return Err("RUNTIME_DESCRIPTOR_ENTRYPOINT_BINDING_MISMATCH".into());
            }
            let mut names = Vec::with_capacity(entrypoints.len());
            for item in entrypoints {
                identifier(item, "RUNTIME_DESCRIPTOR_PACKAGE_ENTRYPOINTS_INVALID")?;
                names.push(item.as_str().unwrap_or_default());
            }
            let before = names.len();
            names.sort_unstable();
            names.dedup();
            if names.len() != before {
                return Err("RUNTIME_DESCRIPTOR_PACKAGE_ENTRYPOINTS_INVALID".into());
            }
            if !names.contains(
                &descriptor["executor"]["entrypoint"]
                    .as_str()
                    .unwrap_or_default(),
            ) {
                return Err("RUNTIME_DESCRIPTOR_ENTRYPOINT_BINDING_MISMATCH".into());
            }
            "MATCHED"
        }
    };
    Ok(serde_json::json!({
        "status":"MATCHED",
        "artifact_binding":"MATCHED",
        "format_binding":"MATCHED",
        "abi_binding":"MATCHED",
        "entrypoint_binding":entrypoint_binding
    }))
}
