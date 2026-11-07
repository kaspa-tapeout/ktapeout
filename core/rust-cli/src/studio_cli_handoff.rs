//! Rust-side verifier for the browser Studio -> CLI handoff.
//! This is a local developer boundary only: it does not compile a package,
//! sign, broadcast, or claim L1 admission.
use ktapeout_runtime::{canonical_json, digest_json};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const SCHEMA: &str = "KTAPEOUT-STUDIO-CLI-HANDOFF-V1";
const PROTOCOL: &str = "0.5.0";
const SOURCE_CONTRACT: &str = "KTAPEOUT-PROJECT-V2";
const DOMAIN: &str = "KTAPEOUT/0.5.0/STUDIO_CLI_HANDOFF/V1";
const MAX_ARTIFACT_BYTES: usize = 256 * 1024;
const MAX_HANDOFF_BYTES: usize = 4 * 1024 * 1024;

fn fail(code: &str) -> String {
    code.to_string()
}

fn object<'a>(value: &'a Value, code: &str) -> Result<&'a Map<String, Value>, String> {
    value.as_object().ok_or_else(|| fail(code))
}

fn exact_keys(value: &Value, keys: &[&str], code: &str) -> Result<(), String> {
    let map = object(value, code)?;
    let expected: BTreeSet<&str> = keys.iter().copied().collect();
    if map.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected {
        return Err(fail(code));
    }
    Ok(())
}

fn text<'a>(value: &'a Value, code: &str) -> Result<&'a str, String> {
    value
        .as_str()
        .filter(|item| !item.is_empty())
        .ok_or_else(|| fail(code))
}

fn raw_sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2)
        || value.len() > MAX_ARTIFACT_BYTES * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(fail("STUDIO_CLI_HANDOFF_ARTIFACT_INVALID"));
    }
    value
        .as_bytes()
        .chunks(2)
        .map(|pair| {
            let high = (pair[0] as char)
                .to_digit(16)
                .ok_or_else(|| fail("STUDIO_CLI_HANDOFF_ARTIFACT_INVALID"))?;
            let low = (pair[1] as char)
                .to_digit(16)
                .ok_or_else(|| fail("STUDIO_CLI_HANDOFF_ARTIFACT_INVALID"))?;
            Ok(((high << 4) | low) as u8)
        })
        .collect()
}

pub(crate) fn verify_handoff(value: &Value) -> Result<Value, String> {
    let map = object(value, "STUDIO_CLI_HANDOFF_IDENTITY_INVALID")?;
    exact_keys(
        value,
        &[
            "schema",
            "protocol_semver",
            "source_contract",
            "network",
            "project",
            "project_sha256",
            "artifact",
            "developer_lock",
            "lifecycle_status",
            "evidence_origin",
            "package_status",
            "next_action",
            "network_effect",
            "signing_allowed",
            "broadcast",
            "handoff_hash",
        ],
        "STUDIO_CLI_HANDOFF_FIELDS_INVALID",
    )?;
    if map.get("schema").and_then(Value::as_str) != Some(SCHEMA)
        || map.get("protocol_semver").and_then(Value::as_str) != Some(PROTOCOL)
        || map.get("source_contract").and_then(Value::as_str) != Some(SOURCE_CONTRACT)
        || !matches!(
            map.get("network").and_then(Value::as_str),
            Some("testnet-10" | "mainnet")
        )
        || map.get("lifecycle_status").and_then(Value::as_str) != Some("STUDIO_HANDOFF_LOCAL")
        || map.get("evidence_origin").and_then(Value::as_str) != Some("LOCAL_STUDIO")
        || map.get("package_status").and_then(Value::as_str) != Some("NOT_A_DEV_PACKAGE")
        || map.get("next_action").and_then(Value::as_str)
            != Some("ktape dev studio-handoff-verify HANDOFF.json")
        || map.get("network_effect").and_then(Value::as_str) != Some("NONE")
        || map.get("signing_allowed") != Some(&Value::Bool(false))
        || map.get("broadcast") != Some(&Value::Bool(false))
    {
        return Err(fail("STUDIO_CLI_HANDOFF_BOUNDARY_OR_IDENTITY_INVALID"));
    }

    let project = map
        .get("project")
        .ok_or_else(|| fail("STUDIO_CLI_HANDOFF_PROJECT_INVALID"))?;
    let canonical_project = crate::studio_runtime_bundle::project_design(project)?;
    let project_bytes = canonical_json(&canonical_project)
        .map_err(|_| fail("STUDIO_CLI_HANDOFF_PROJECT_HASH_INVALID"))?;
    let project_hash = raw_sha256(&project_bytes);
    if map.get("project_sha256").and_then(Value::as_str) != Some(project_hash.as_str())
        || !valid_hash(&project_hash)
    {
        return Err(fail("STUDIO_CLI_HANDOFF_PROJECT_HASH_INVALID"));
    }

    match map.get("artifact") {
        Some(Value::Null) => {}
        Some(artifact) => {
            exact_keys(
                artifact,
                &["info", "sha256", "bytes_hex"],
                "STUDIO_CLI_HANDOFF_ARTIFACT_INVALID",
            )?;
            let artifact_map = object(artifact, "STUDIO_CLI_HANDOFF_ARTIFACT_INVALID")?;
            let bytes_hex = text(
                artifact_map
                    .get("bytes_hex")
                    .ok_or_else(|| fail("STUDIO_CLI_HANDOFF_ARTIFACT_INVALID"))?,
                "STUDIO_CLI_HANDOFF_ARTIFACT_INVALID",
            )?;
            let bytes = decode_hex(bytes_hex)?;
            let artifact_hash = text(
                artifact_map
                    .get("sha256")
                    .ok_or_else(|| fail("STUDIO_CLI_HANDOFF_ARTIFACT_INVALID"))?,
                "STUDIO_CLI_HANDOFF_ARTIFACT_INVALID",
            )?;
            if !valid_hash(artifact_hash) || raw_sha256(&bytes) != artifact_hash {
                return Err(fail("STUDIO_CLI_HANDOFF_ARTIFACT_HASH_INVALID"));
            }
            let info = artifact_map
                .get("info")
                .ok_or_else(|| fail("STUDIO_CLI_HANDOFF_ARTIFACT_INVALID"))?;
            if info.get("artifact_sha256").and_then(Value::as_str) != Some(artifact_hash) {
                return Err(fail("STUDIO_CLI_HANDOFF_ARTIFACT_HASH_INVALID"));
            }
        }
        None => return Err(fail("STUDIO_CLI_HANDOFF_ARTIFACT_INVALID")),
    }

    let mut material = map.clone();
    material.remove("handoff_hash");
    let material = Value::Object(material);
    let handoff_hash =
        digest_json(&material, DOMAIN).map_err(|_| fail("STUDIO_CLI_HANDOFF_HASH_INVALID"))?;
    if map.get("handoff_hash").and_then(Value::as_str) != Some(handoff_hash.as_str()) {
        return Err(fail("STUDIO_CLI_HANDOFF_HASH_INVALID"));
    }
    let encoded = serde_json::to_vec(value).map_err(|_| fail("STUDIO_CLI_HANDOFF_SIZE_INVALID"))?;
    if encoded.len() > MAX_HANDOFF_BYTES {
        return Err(fail("STUDIO_CLI_HANDOFF_SIZE_INVALID"));
    }

    Ok(serde_json::json!({
        "schema": "KTAPEOUT-STUDIO-CLI-HANDOFF-RESULT-V1",
        "network": map.get("network"),
        "project_id": project.get("project_id"),
        "project_sha256": project_hash,
        "artifact_sha256": map.get("artifact").and_then(|item| item.get("sha256")),
        "lifecycle_status": "STUDIO_HANDOFF_LOCAL",
        "package_status": "NOT_A_DEV_PACKAGE",
        "signing_allowed": false,
        "broadcast": false,
        "next_action": "translate or author a supported CLI input, then run the canonical CLI workflow"
    }))
}
