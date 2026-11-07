use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const DOMAIN: &[u8] = b"KTAPEOUT/0.5.0/RELEASE_LOCATOR_BUNDLE/V1\0";

/// Verify historical Release/resource locators as candidates only.
/// Bytes and locators are never trusted without later digest verification.
pub fn verify(bundle: &Value) -> Result<(), String> {
    let object = bundle.as_object().ok_or("HISTORY_BUNDLE_OBJECT_REQUIRED")?;
    let fields = [
        "schema",
        "protocol_semver",
        "network",
        "application_id",
        "release_id",
        "artifact_root",
        "resources",
        "availability_status",
        "bundle_hash",
    ];
    if object.len() != fields.len() || fields.iter().any(|key| !object.contains_key(*key)) {
        return Err("HISTORY_BUNDLE_FIELDS_INVALID".into());
    }
    if bundle["schema"] != "KTAPEOUT-RELEASE-LOCATOR-BUNDLE-V1"
        || bundle["protocol_semver"] != "0.5.0"
    {
        return Err("HISTORY_BUNDLE_VERSION_INVALID".into());
    }
    if !matches!(bundle["network"].as_str(), Some("testnet-10" | "mainnet")) {
        return Err("HISTORY_NETWORK_INVALID".into());
    }
    for key in [
        "application_id",
        "release_id",
        "artifact_root",
        "bundle_hash",
    ] {
        if !bundle[key].as_str().is_some_and(super::valid_hash) {
            return Err(format!("HISTORY_HASH_INVALID:{key}"));
        }
    }
    let status = bundle["availability_status"]
        .as_str()
        .ok_or("HISTORY_STATUS_INVALID")?;
    if !matches!(status, "COMPLETE" | "PARTIAL" | "UNAVAILABLE") {
        return Err("HISTORY_STATUS_INVALID".into());
    }
    let resources = bundle["resources"]
        .as_array()
        .ok_or("HISTORY_RESOURCES_REQUIRED")?;
    if resources.len() > 64 || (status == "COMPLETE" && resources.is_empty()) {
        return Err("HISTORY_RESOURCE_LIMIT".into());
    }
    let mut paths = BTreeSet::new();
    for resource in resources {
        let obj = resource.as_object().ok_or("HISTORY_RESOURCE_INVALID")?;
        if obj.len() != 4
            || !obj.contains_key("path")
            || !obj.contains_key("length")
            || !obj.contains_key("digest")
            || !obj.contains_key("locators")
        {
            return Err("HISTORY_RESOURCE_FIELDS_INVALID".into());
        }
        let path = obj["path"]
            .as_str()
            .filter(|value| {
                !value.is_empty()
                    && value.len() <= 256
                    && !value.starts_with('/')
                    && !value.contains("..")
                    && value.bytes().all(|byte| !byte.is_ascii_control())
            })
            .ok_or("HISTORY_PATH_INVALID")?;
        if !paths.insert(path) {
            return Err("HISTORY_DUPLICATE_PATH".into());
        }
        let length = obj["length"].as_u64().ok_or("HISTORY_LENGTH_INVALID")?;
        if length > 4 * 1024 * 1024 {
            return Err("HISTORY_LENGTH_LIMIT".into());
        }
        if !obj["digest"].as_str().is_some_and(super::valid_hash) {
            return Err("HISTORY_RESOURCE_DIGEST_INVALID".into());
        }
        let locators = obj["locators"]
            .as_array()
            .ok_or("HISTORY_LOCATORS_REQUIRED")?;
        if locators.len() > 8 || (status == "COMPLETE" && locators.is_empty()) {
            return Err("HISTORY_LOCATOR_LIMIT".into());
        }
        let mut unique = BTreeSet::new();
        for locator in locators {
            let value = locator
                .as_str()
                .filter(|value| {
                    value.len() <= 1024
                        && (value.starts_with("https://")
                            || value.starts_with("ipfs://")
                            || value.starts_with("ktape://")
                            || value.starts_with("kaspa://"))
                })
                .ok_or("HISTORY_LOCATOR_INVALID")?;
            if !unique.insert(value) {
                return Err("HISTORY_DUPLICATE_LOCATOR".into());
            }
        }
    }
    let material = object
        .clone()
        .into_iter()
        .filter(|(key, _)| key != "bundle_hash")
        .collect();
    let mut digest = Sha256::new();
    digest.update(DOMAIN);
    digest.update(super::canonical_json(&Value::Object(material))?);
    let actual = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if bundle["bundle_hash"].as_str() != Some(&actual) {
        return Err("HISTORY_BUNDLE_HASH_MISMATCH".into());
    }
    Ok(())
}

/// Verify a locator bundle and bind it to an externally selected Release
/// tuple. The tuple is caller context, never taken from the bundle itself.
pub fn verify_with_expected(
    bundle: &Value,
    expected_network: Option<&str>,
    expected_application_id: Option<&str>,
    expected_release_id: Option<&str>,
    expected_artifact_root: Option<&str>,
) -> Result<bool, String> {
    verify(bundle)?;
    let expected = [
        expected_network,
        expected_application_id,
        expected_release_id,
        expected_artifact_root,
    ];
    if expected.iter().all(Option::is_none) {
        return Ok(false);
    }
    if expected.iter().any(Option::is_none) {
        return Err("HISTORY_EXPECTED_TUPLE_INCOMPLETE".into());
    }
    let network = expected_network.unwrap();
    if !matches!(network, "testnet-10" | "mainnet") {
        return Err("HISTORY_NETWORK_INVALID".into());
    }
    for (field, value) in [
        ("application_id", expected_application_id.unwrap()),
        ("release_id", expected_release_id.unwrap()),
        ("artifact_root", expected_artifact_root.unwrap()),
    ] {
        if !super::valid_hash(value) {
            return Err(format!("HISTORY_EXPECTED_HASH_INVALID:{field}"));
        }
    }
    if bundle["network"] != network
        || bundle["application_id"] != expected_application_id.unwrap()
        || bundle["release_id"] != expected_release_id.unwrap()
        || bundle["artifact_root"] != expected_artifact_root.unwrap()
    {
        return Err("HISTORY_EXPECTED_TUPLE_MISMATCH".into());
    }
    Ok(true)
}

/// Verify bytes obtained from a locator against one declared resource.
/// The locator itself is never trusted as a content proof; callers must pass
/// the bytes they actually obtained and keep the result bound to the resource.
/// This is an embedding/Bridge boundary; the standalone CLI intentionally
/// verifies locator bundles only and never reads arbitrary paths.
#[allow(dead_code)]
pub fn verify_resource_bytes(resource: &Value, bytes: &[u8]) -> Result<(), String> {
    let object = resource.as_object().ok_or("HISTORY_RESOURCE_INVALID")?;
    let length = object["length"].as_u64().ok_or("HISTORY_LENGTH_INVALID")?;
    if length != bytes.len() as u64 {
        return Err("HISTORY_RESOURCE_LENGTH_MISMATCH".into());
    }
    let expected = object["digest"]
        .as_str()
        .filter(|value| super::valid_hash(value))
        .ok_or("HISTORY_RESOURCE_DIGEST_INVALID")?;
    let actual = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if actual != expected {
        return Err("HISTORY_RESOURCE_DIGEST_MISMATCH".into());
    }
    Ok(())
}
