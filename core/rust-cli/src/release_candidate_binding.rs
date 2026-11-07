//! Validate a frozen application candidate before it enters the durable release intent.
#[cfg(feature = "coordinator")]
use crate::release_workflow::{ApplicationCandidateBinding, Target};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::fs;
#[cfg(feature = "coordinator")]
use std::io::Read;
use std::path::{Path, PathBuf};

#[cfg(feature = "coordinator")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateResult {
    schema: String,
    evidence_level: String,
    adapter_id: String,
    application_uri: String,
    network: String,
    profile_digest: String,
    profile_scope: Value,
    entrypoint: String,
    release_id: String,
    content_root: String,
    covered_file_count: usize,
    snapshot_digest: String,
    snapshot_directory: PathBuf,
}

fn error(code: &str) -> String {
    code.to_owned()
}

fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn value_hash(value: &Value) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| hash(&bytes))
        .map_err(|_| error("APPLICATION_CANDIDATE_JSON_INVALID"))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn safe_relative_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && !value.starts_with('/')
        && !value.contains('\\')
        && value
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

fn collect_files(
    root: &Path,
    directory: &Path,
    files: &mut BTreeMap<String, PathBuf>,
    total_bytes: &mut u64,
) -> Result<(), String> {
    let entries =
        fs::read_dir(directory).map_err(|_| error("APPLICATION_CANDIDATE_UNAVAILABLE"))?;
    for entry in entries {
        let entry = entry.map_err(|_| error("APPLICATION_CANDIDATE_UNAVAILABLE"))?;
        let path = entry.path();
        let metadata =
            fs::symlink_metadata(&path).map_err(|_| error("APPLICATION_CANDIDATE_UNAVAILABLE"))?;
        if metadata.file_type().is_symlink() {
            return Err(error("APPLICATION_CANDIDATE_LINK_FORBIDDEN"));
        }
        if metadata.is_dir() {
            collect_files(root, &path, files, total_bytes)?;
            continue;
        }
        if !metadata.is_file() {
            return Err(error("APPLICATION_CANDIDATE_ENTRY_FORBIDDEN"));
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|_| error("APPLICATION_CANDIDATE_PATH_INVALID"))?
            .to_str()
            .ok_or_else(|| error("APPLICATION_CANDIDATE_PATH_INVALID"))?
            .replace(std::path::MAIN_SEPARATOR, "/");
        if !safe_relative_path(&relative) || files.len() >= 513 {
            return Err(error("APPLICATION_CANDIDATE_FILE_SET_INVALID"));
        }
        *total_bytes = total_bytes
            .checked_add(metadata.len())
            .ok_or_else(|| error("APPLICATION_CANDIDATE_OVER_BUDGET"))?;
        if *total_bytes > 64 * 1024 * 1024 {
            return Err(error("APPLICATION_CANDIDATE_OVER_BUDGET"));
        }
        if files.insert(relative, path).is_some() {
            return Err(error("APPLICATION_CANDIDATE_FILE_SET_INVALID"));
        }
    }
    Ok(())
}

fn profile_scope(profile: &Value) -> Result<Value, String> {
    let schema = profile["schema"]
        .as_str()
        .ok_or_else(|| error("APPLICATION_CANDIDATE_PROFILE_INVALID"))?;
    let network = profile["network"]
        .as_str()
        .ok_or_else(|| error("APPLICATION_CANDIDATE_PROFILE_INVALID"))?;
    let application_uri = profile["application"]["uri"]
        .as_str()
        .ok_or_else(|| error("APPLICATION_CANDIDATE_PROFILE_INVALID"))?;
    let runtime_smoke_test = profile["runtime"]["smoke_test"]
        .as_bool()
        .ok_or_else(|| error("APPLICATION_CANDIDATE_PROFILE_INVALID"))?;
    let authority = match schema {
        "KTAPEOUT-APPLICATION-RELEASE-PROFILE-V1" => {
            let publisher = &profile["publisher"];
            json!({"kind":"publisher","publisher_id":publisher["publisher_id"],"key_id":publisher["key_id"],"permissions":publisher["permissions"]})
        }
        "KTAPEOUT-APPLICATION-RELEASE-PROFILE-V2"
        | "KTAPEOUT-APPLICATION-RELEASE-PROFILE-V3"
        | "KTAPEOUT-APPLICATION-RELEASE-PROFILE-V4" => profile["authority"].clone(),
        _ => return Err(error("APPLICATION_CANDIDATE_PROFILE_INVALID")),
    };
    let permissions = authority["permissions"]
        .as_array()
        .ok_or_else(|| error("APPLICATION_CANDIDATE_PROFILE_INVALID"))?;
    if network != "testnet-10" || !application_uri.starts_with("ktape://testnet-10/app/") {
        return Err(error("APPLICATION_CANDIDATE_PROFILE_INVALID"));
    }
    match authority["kind"].as_str() {
        Some("publisher") => {
            let publisher_id = authority["publisher_id"]
                .as_str()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| error("APPLICATION_CANDIDATE_PROFILE_INVALID"))?;
            let key_id = authority["key_id"]
                .as_str()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| error("APPLICATION_CANDIDATE_PROFILE_INVALID"))?;
            if permissions.iter().any(|value| value.as_str().is_none()) {
                return Err(error("APPLICATION_CANDIDATE_PROFILE_INVALID"));
            }
            Ok(
                json!({"network":network,"application_uri":application_uri,"publisher_id":publisher_id,"publisher_key_id":key_id,"runtime_smoke_test":runtime_smoke_test,"permissions":permissions}),
            )
        }
        Some("name-controller") => {
            let public_key = authority["public_key"]
                .as_str()
                .filter(|value| valid_digest(value))
                .ok_or_else(|| error("APPLICATION_CANDIDATE_PROFILE_INVALID"))?;
            if !permissions.is_empty() {
                return Err(error("APPLICATION_CANDIDATE_PROFILE_INVALID"));
            }
            Ok(
                json!({"network":network,"application_uri":application_uri,"name_controller_public_key":public_key,"runtime_smoke_test":runtime_smoke_test,"permissions":[]}),
            )
        }
        _ => Err(error("APPLICATION_CANDIDATE_PROFILE_INVALID")),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateBinding {
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

fn check_binding(target_scope: &Value, binding: &CandidateBinding) -> Result<(), String> {
    if !binding.snapshot_directory.is_absolute()
        || ![
            &binding.snapshot_digest,
            &binding.profile_digest,
            &binding.release_id,
            &binding.content_root,
        ]
        .iter()
        .all(|value| valid_digest(value))
        || binding.network != "testnet-10"
        || binding.network != target_scope["network"].as_str().unwrap_or_default()
        || binding.application_uri != target_scope["application_uri"].as_str().unwrap_or_default()
    {
        return Err(error("APPLICATION_CANDIDATE_IDENTITY_MISMATCH"));
    }

    let supplied_root = fs::symlink_metadata(&binding.snapshot_directory)
        .map_err(|_| error("APPLICATION_CANDIDATE_UNAVAILABLE"))?;
    if !supplied_root.is_dir() || supplied_root.file_type().is_symlink() {
        return Err(error("APPLICATION_CANDIDATE_ROOT_INVALID"));
    }
    let root = fs::canonicalize(&binding.snapshot_directory)
        .map_err(|_| error("APPLICATION_CANDIDATE_UNAVAILABLE"))?;
    let root_metadata =
        fs::symlink_metadata(&root).map_err(|_| error("APPLICATION_CANDIDATE_UNAVAILABLE"))?;
    if !root_metadata.is_dir() || root_metadata.file_type().is_symlink() {
        return Err(error("APPLICATION_CANDIDATE_ROOT_INVALID"));
    }
    let manifest_bytes = fs::read(root.join("snapshot-manifest.json"))
        .map_err(|_| error("APPLICATION_CANDIDATE_MANIFEST_INVALID"))?;
    let manifest: Value = serde_json::from_slice(&manifest_bytes)
        .map_err(|_| error("APPLICATION_CANDIDATE_MANIFEST_INVALID"))?;
    if manifest.as_object().is_none_or(|object| object.len() != 8)
        || manifest["schema"] != "KTAPEOUT-APPLICATION-RELEASE-SNAPSHOT-V1"
        || manifest["snapshot_digest"] != binding.snapshot_digest
        || manifest["adapter_id"] != binding.adapter_id
        || manifest["application_uri"] != binding.application_uri
        || manifest["network"] != binding.network
        || manifest["release_id"] != binding.release_id
        || manifest["content_root"] != binding.content_root
        || !manifest["files"].is_array()
    {
        return Err(error("APPLICATION_CANDIDATE_IDENTITY_MISMATCH"));
    }

    let mut files = BTreeMap::new();
    let mut total_bytes = 0;
    collect_files(&root, &root, &mut files, &mut total_bytes)?;
    let declared = manifest["files"].as_array().unwrap();
    if declared.len() + 1 != files.len() {
        return Err(error("APPLICATION_CANDIDATE_FILE_SET_MISMATCH"));
    }
    let mut seen = HashSet::new();
    for item in declared {
        let path = item["path"]
            .as_str()
            .filter(|value| safe_relative_path(value))
            .ok_or_else(|| error("APPLICATION_CANDIDATE_MANIFEST_INVALID"))?;
        let expected_length = item["byte_length"]
            .as_u64()
            .ok_or_else(|| error("APPLICATION_CANDIDATE_MANIFEST_INVALID"))?;
        let expected_hash = item["sha256"]
            .as_str()
            .filter(|value| valid_digest(value))
            .ok_or_else(|| error("APPLICATION_CANDIDATE_MANIFEST_INVALID"))?;
        if item.as_object().is_none_or(|object| object.len() != 3)
            || path == "snapshot-manifest.json"
            || !seen.insert(path)
        {
            return Err(error("APPLICATION_CANDIDATE_MANIFEST_INVALID"));
        }
        let file_path = files
            .get(path)
            .ok_or_else(|| error("APPLICATION_CANDIDATE_FILE_SET_MISMATCH"))?;
        let bytes = fs::read(file_path).map_err(|_| error("APPLICATION_CANDIDATE_UNAVAILABLE"))?;
        if bytes.len() as u64 != expected_length || hash(&bytes) != expected_hash {
            return Err(error("APPLICATION_CANDIDATE_FILE_DIGEST_MISMATCH"));
        }
    }
    if files
        .keys()
        .any(|path| path != "snapshot-manifest.json" && !seen.contains(path.as_str()))
    {
        return Err(error("APPLICATION_CANDIDATE_FILE_SET_MISMATCH"));
    }
    let material = json!({
        "schema":manifest["schema"],
        "adapter_id":manifest["adapter_id"],
        "application_uri":manifest["application_uri"],
        "network":manifest["network"],
        "files":manifest["files"]
    });
    if value_hash(&material)? != binding.snapshot_digest {
        return Err(error("APPLICATION_CANDIDATE_DIGEST_MISMATCH"));
    }

    let profile_path = files
        .get("profile.json")
        .ok_or_else(|| error("APPLICATION_CANDIDATE_PROFILE_INVALID"))?;
    let profile: Value = serde_json::from_slice(
        &fs::read(profile_path).map_err(|_| error("APPLICATION_CANDIDATE_PROFILE_INVALID"))?,
    )
    .map_err(|_| error("APPLICATION_CANDIDATE_PROFILE_INVALID"))?;
    if value_hash(&profile)? != binding.profile_digest
        || profile["adapter_id"] != binding.adapter_id
        || profile["application"]["uri"] != binding.application_uri
        || profile["network"] != binding.network
        || profile_scope(&profile)? != binding.profile_scope
    {
        return Err(error("APPLICATION_CANDIDATE_PROFILE_INVALID"));
    }
    for key in [
        "network",
        "application_uri",
        "publisher_id",
        "publisher_key_id",
        "name_controller_public_key",
        "permissions",
    ] {
        if let Some(value) = binding.profile_scope.get(key) {
            if target_scope.get(key) != Some(value) {
                return Err(error("APPLICATION_CANDIDATE_SCOPE_MISMATCH"));
            }
        }
    }
    Ok(())
}

/// Verify the frozen candidate using only the serialized target contract. This surface is also
/// available to a separately pinned Host-free adapter, without linking the coordinator or its
/// embedded adapter registry.
pub fn check_value(target: &Value) -> Result<(), String> {
    crate::release_adapter_contract::validate_host_free_target_values(target)?;
    check_candidate(target)
}

fn check_candidate(target: &Value) -> Result<(), String> {
    let scope = target
        .get("scope")
        .filter(|value| value.is_object())
        .ok_or_else(|| error("APPLICATION_CANDIDATE_SCOPE_MISMATCH"))?;
    if let Some(binding) = target
        .get("application_candidate")
        .filter(|value| !value.is_null())
    {
        let binding: CandidateBinding = serde_json::from_value(binding.clone())
            .map_err(|_| error("APPLICATION_CANDIDATE_IDENTITY_MISMATCH"))?;
        check_binding(scope, &binding)?;
    }
    Ok(())
}

#[cfg(feature = "coordinator")]
pub fn check(target: &Target) -> Result<(), String> {
    let value =
        serde_json::to_value(target).map_err(|_| error("APPLICATION_CANDIDATE_TARGET_INVALID"))?;
    // The coordinator validates V1 Host targets separately. Candidate verification must
    // preserve that route without applying the V2/V3 prohibition on Host fields to it.
    if target.schema == "KTAPEOUT-RELEASE-TARGET-V1" {
        check_candidate(&value)
    } else {
        check_value(&value)
    }
}

#[cfg(feature = "coordinator")]
pub fn attach_result(target: &mut Target, path: &Path) -> Result<(), String> {
    if target.application_candidate.is_some() {
        return Err(error("APPLICATION_CANDIDATE_ALREADY_BOUND"));
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| error("APPLICATION_CANDIDATE_RESULT_UNAVAILABLE"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 64 * 1024 {
        return Err(error("APPLICATION_CANDIDATE_RESULT_INVALID"));
    }
    let file =
        fs::File::open(path).map_err(|_| error("APPLICATION_CANDIDATE_RESULT_UNAVAILABLE"))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(64 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| error("APPLICATION_CANDIDATE_RESULT_UNAVAILABLE"))?;
    if bytes.len() > 64 * 1024 {
        return Err(error("APPLICATION_CANDIDATE_RESULT_INVALID"));
    }
    let result: CandidateResult = serde_json::from_slice(&bytes)
        .map_err(|_| error("APPLICATION_CANDIDATE_RESULT_INVALID"))?;
    if result.schema != "KTAPEOUT-APPLICATION-RELEASE-CANDIDATE-V1"
        || result.evidence_level != "LOCAL_BUILD_VERIFIED"
        || result.covered_file_count == 0
        || result.covered_file_count > 512
        || !safe_relative_path(&result.entrypoint)
        || !result.profile_scope.is_object()
    {
        return Err(error("APPLICATION_CANDIDATE_RESULT_INVALID"));
    }

    let mut merged_scope = target.scope.clone();
    let scope = merged_scope
        .as_object_mut()
        .ok_or_else(|| error("APPLICATION_CANDIDATE_SCOPE_MISMATCH"))?;
    for (key, value) in result.profile_scope.as_object().unwrap() {
        if scope.get(key).is_some_and(|existing| existing != value) {
            return Err(error("APPLICATION_CANDIDATE_SCOPE_MISMATCH"));
        }
        scope.insert(key.clone(), value.clone());
    }

    target.scope = merged_scope;
    target.application_candidate = Some(ApplicationCandidateBinding {
        snapshot_directory: result.snapshot_directory,
        snapshot_digest: result.snapshot_digest,
        profile_digest: result.profile_digest,
        profile_scope: result.profile_scope,
        adapter_id: result.adapter_id,
        application_uri: result.application_uri,
        network: result.network,
        release_id: result.release_id,
        content_root: result.content_root,
    });
    Ok(())
}
