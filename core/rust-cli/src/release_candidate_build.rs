//! Build a deterministic, local-only application release candidate from a Rust package.
//!
//! This is deliberately the public counterpart of the reviewed package candidate flow. It
//! never signs, broadcasts, imports, or deploys anything; it only freezes bytes and emits the
//! `KTAPEOUT-APPLICATION-RELEASE-CANDIDATE-V1` input consumed by `release ship`.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Component, Path};

const ADAPTER_ID: &str = "rust-package-canonical-chunks-v1-tn10";
const NETWORK: &str = "testnet-10";
const SNAPSHOT_SCHEMA: &str = "KTAPEOUT-APPLICATION-RELEASE-SNAPSHOT-V1";
const CANDIDATE_SCHEMA: &str = "KTAPEOUT-APPLICATION-RELEASE-CANDIDATE-V1";

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn canonical(value: &Value) -> Result<Vec<u8>, String> {
    ktapeout_runtime::canonical_json(value)
}

fn read_json(path: &Path, error: &str) -> Result<Value, String> {
    let bytes = fs::read(path).map_err(|_| error.to_string())?;
    serde_json::from_slice(&bytes).map_err(|_| error.to_string())
}

fn valid_relative(path: &Path) -> Result<String, String> {
    if path
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err("APPLICATION_RELEASE_PACKAGE_PATH_INVALID".into());
    }
    let value = path
        .to_str()
        .ok_or("APPLICATION_RELEASE_PACKAGE_PATH_NOT_UTF8")?
        .replace('\\', "/");
    if value.is_empty()
        || value.len() > 256
        || value
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || value
            .chars()
            .any(|character| matches!(character, '?' | '#' | '%') || (character as u32) <= 0x20)
    {
        return Err("APPLICATION_RELEASE_PACKAGE_PATH_INVALID".into());
    }
    Ok(value)
}

fn collect_files(
    root: &Path,
    current: &Path,
    files: &mut BTreeMap<String, Vec<u8>>,
) -> Result<(), String> {
    let mut entries = fs::read_dir(current)
        .map_err(|_| "APPLICATION_RELEASE_PACKAGE_UNAVAILABLE".to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "APPLICATION_RELEASE_PACKAGE_UNAVAILABLE".to_string())?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let relative = valid_relative(
            path.strip_prefix(root)
                .map_err(|_| "APPLICATION_RELEASE_PACKAGE_PATH_ESCAPE")?,
        )?;
        let metadata =
            fs::symlink_metadata(&path).map_err(|_| "APPLICATION_RELEASE_PACKAGE_UNAVAILABLE")?;
        if metadata.file_type().is_symlink() {
            return Err("APPLICATION_RELEASE_PACKAGE_SYMLINK_FORBIDDEN".into());
        }
        if metadata.is_dir() {
            collect_files(root, &path, files)?;
        } else if metadata.is_file() {
            let bytes = fs::read(&path).map_err(|_| "APPLICATION_RELEASE_PACKAGE_UNAVAILABLE")?;
            if files.insert(relative, bytes).is_some() {
                return Err("APPLICATION_RELEASE_PACKAGE_FILE_SET_INVALID".into());
            }
        } else {
            return Err("APPLICATION_RELEASE_PACKAGE_SPECIAL_FILE_FORBIDDEN".into());
        }
    }
    Ok(())
}

fn profile_scope(profile: &Value) -> Result<Value, String> {
    let schema = profile["schema"]
        .as_str()
        .ok_or("APPLICATION_RELEASE_PROFILE_INVALID")?;
    if !matches!(
        schema,
        "KTAPEOUT-APPLICATION-RELEASE-PROFILE-V1"
            | "KTAPEOUT-APPLICATION-RELEASE-PROFILE-V2"
            | "KTAPEOUT-APPLICATION-RELEASE-PROFILE-V3"
            | "KTAPEOUT-APPLICATION-RELEASE-PROFILE-V4"
    ) {
        return Err("APPLICATION_RELEASE_PROFILE_INVALID".into());
    }
    let network = profile["network"]
        .as_str()
        .ok_or("APPLICATION_RELEASE_PROFILE_INVALID")?;
    let application_uri = profile["application"]["uri"]
        .as_str()
        .ok_or("APPLICATION_RELEASE_PROFILE_INVALID")?;
    let smoke_test = profile["runtime"]["smoke_test"]
        .as_bool()
        .ok_or("APPLICATION_RELEASE_PROFILE_INVALID")?;
    let authority = if schema == "KTAPEOUT-APPLICATION-RELEASE-PROFILE-V1" {
        let publisher = &profile["publisher"];
        json!({
            "kind": "publisher",
            "publisher_id": publisher["publisher_id"],
            "key_id": publisher["key_id"],
            "permissions": publisher["permissions"]
        })
    } else {
        profile["authority"].clone()
    };
    let permissions = authority["permissions"]
        .as_array()
        .ok_or("APPLICATION_RELEASE_PROFILE_INVALID")?;
    if network != NETWORK || !application_uri.starts_with("ktape://testnet-10/app/") {
        return Err("APPLICATION_RELEASE_PROFILE_INVALID".into());
    }
    match authority["kind"].as_str() {
        Some("publisher") => {
            let publisher_id = authority["publisher_id"]
                .as_str()
                .filter(|value| !value.is_empty())
                .ok_or("APPLICATION_RELEASE_PROFILE_INVALID")?;
            let key_id = authority["key_id"]
                .as_str()
                .filter(|value| !value.is_empty())
                .ok_or("APPLICATION_RELEASE_PROFILE_INVALID")?;
            if permissions.iter().any(|value| value.as_str().is_none()) {
                return Err("APPLICATION_RELEASE_PROFILE_INVALID".into());
            }
            Ok(json!({
                "network": network,
                "application_uri": application_uri,
                "publisher_id": publisher_id,
                "publisher_key_id": key_id,
                "runtime_smoke_test": smoke_test,
                "permissions": permissions
            }))
        }
        Some("name-controller") => {
            let public_key = authority["public_key"]
                .as_str()
                .filter(|value| is_digest(value))
                .ok_or("APPLICATION_RELEASE_PROFILE_INVALID")?;
            if !permissions.is_empty() {
                return Err("APPLICATION_RELEASE_PROFILE_INVALID".into());
            }
            Ok(json!({
                "network": network,
                "application_uri": application_uri,
                "name_controller_public_key": public_key,
                "runtime_smoke_test": smoke_test,
                "permissions": []
            }))
        }
        _ => Err("APPLICATION_RELEASE_PROFILE_INVALID".into()),
    }
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| "APPLICATION_RELEASE_OUTPUT_WRITE_ERROR")?;
    file.write_all(bytes)
        .map_err(|_| "APPLICATION_RELEASE_OUTPUT_WRITE_ERROR".to_string())
}

fn copy_new(source: &Path, destination: &Path) -> Result<(), String> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).map_err(|_| "APPLICATION_RELEASE_SNAPSHOT_WRITE_ERROR")?;
    }
    write_new(
        destination,
        &fs::read(source).map_err(|_| "APPLICATION_RELEASE_PACKAGE_UNAVAILABLE")?,
    )
}

fn verify_existing_snapshot(directory: &Path, manifest: &Value) -> Result<(), String> {
    let existing = read_json(
        &directory.join("snapshot-manifest.json"),
        "APPLICATION_RELEASE_SNAPSHOT_INVALID",
    )?;
    if existing != *manifest {
        return Err("APPLICATION_RELEASE_SNAPSHOT_COLLISION".into());
    }
    Ok(())
}

/// Build one generic Rust package candidate. This is local-only and has no signing or network side effects.
pub fn build(
    profile_path: &Path,
    package_directory: &Path,
    snapshot_store: &Path,
    output: &Path,
) -> Result<Value, String> {
    let profile = read_json(profile_path, "APPLICATION_RELEASE_PROFILE_UNAVAILABLE")?;
    let scope = profile_scope(&profile)?;
    let application_uri = profile["application"]["uri"]
        .as_str()
        .ok_or("APPLICATION_RELEASE_PROFILE_INVALID")?;
    let entrypoint = profile["runtime"]["entrypoint"]
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or("APPLICATION_RELEASE_PROFILE_INVALID")?;
    valid_relative(Path::new(entrypoint)).map_err(|_| "APPLICATION_RELEASE_PROFILE_INVALID")?;
    let package_directory = fs::canonicalize(package_directory)
        .map_err(|_| "APPLICATION_RELEASE_PACKAGE_UNAVAILABLE")?;
    if !package_directory.is_dir()
        || fs::symlink_metadata(&package_directory)
            .map_err(|_| "APPLICATION_RELEASE_PACKAGE_UNAVAILABLE")?
            .file_type()
            .is_symlink()
    {
        return Err("APPLICATION_RELEASE_PACKAGE_DIRECTORY_REQUIRED".into());
    }

    let mut package_files = BTreeMap::new();
    collect_files(&package_directory, &package_directory, &mut package_files)?;
    let artifact_bytes = package_files
        .get("artifact.json")
        .ok_or("APPLICATION_RELEASE_PACKAGE_OUTPUT_INCOMPLETE")?;
    let release_bytes = package_files
        .get("release.json")
        .ok_or("APPLICATION_RELEASE_PACKAGE_OUTPUT_INCOMPLETE")?;
    let artifact: Value = serde_json::from_slice(artifact_bytes)
        .map_err(|_| "APPLICATION_RELEASE_PACKAGE_JSON_INVALID")?;
    let release: Value = serde_json::from_slice(release_bytes)
        .map_err(|_| "APPLICATION_RELEASE_PACKAGE_JSON_INVALID")?;
    let release_id = release["release_id"]
        .as_str()
        .filter(|value| is_digest(value))
        .ok_or("APPLICATION_RELEASE_PACKAGE_IDENTITY_INVALID")?;
    let content_root = artifact["artifact_root"]
        .as_str()
        .filter(|value| is_digest(value))
        .ok_or("APPLICATION_RELEASE_PACKAGE_IDENTITY_INVALID")?;
    if release["network"].as_str() != Some(NETWORK)
        || artifact["network"].as_str() != Some(NETWORK)
        || release["application_id"] != artifact["application_id"]
        || artifact["runtime_manifest"].as_str().is_none()
    {
        return Err("APPLICATION_RELEASE_PACKAGE_IDENTITY_INVALID".into());
    }

    let runtime_manifest = package_directory.join(
        artifact["runtime_manifest"]
            .as_str()
            .ok_or("APPLICATION_RELEASE_PACKAGE_IDENTITY_INVALID")?,
    );
    let runtime: Value = read_json(
        &runtime_manifest,
        "APPLICATION_RELEASE_RUNTIME_MANIFEST_INVALID",
    )?;
    if runtime["application_uri"].as_str() != Some(application_uri)
        || runtime["network"].as_str() != Some(NETWORK)
        || runtime["release_id"].as_str() != Some(release_id)
        || runtime["content_commitment"]["artifact_root"].as_str() != Some(content_root)
        || runtime["entrypoint"].as_str().is_none()
    {
        return Err("APPLICATION_RELEASE_PACKAGE_IDENTITY_INVALID".into());
    }
    crate::package_build::verify_publication_runtime(
        &package_directory,
        &artifact,
        NETWORK,
        application_uri,
        release_id,
        content_root,
    )?;
    let runtime_files = runtime["files"]
        .as_array()
        .filter(|files| !files.is_empty() && files.len() <= 512)
        .ok_or("APPLICATION_RELEASE_RUNTIME_MANIFEST_INVALID")?;

    let profile_bytes = canonical(&profile)?;
    let mut inputs = Vec::with_capacity(package_files.len() + 1);
    inputs.push(("profile.json".to_string(), profile_bytes.clone()));
    inputs.extend(
        package_files
            .iter()
            .map(|(path, bytes)| (format!("package/{path}"), bytes.clone())),
    );
    inputs.sort_by(|left, right| left.0.cmp(&right.0));
    let inventory: Vec<Value> = inputs
        .iter()
        .map(|(path, bytes)| json!({"path": path, "byte_length": bytes.len(), "sha256": digest(bytes)}))
        .collect();
    let material = json!({
        "schema": SNAPSHOT_SCHEMA,
        "adapter_id": ADAPTER_ID,
        "application_uri": application_uri,
        "network": NETWORK,
        "files": inventory,
    });
    let snapshot_digest = digest(&canonical(&material)?);
    let snapshot_directory = snapshot_store.join(&snapshot_digest);
    let manifest = json!({
        "schema": SNAPSHOT_SCHEMA,
        "adapter_id": ADAPTER_ID,
        "application_uri": application_uri,
        "network": NETWORK,
        "files": material["files"],
        "snapshot_digest": snapshot_digest,
        "release_id": release_id,
        "content_root": content_root,
    });

    if snapshot_directory.exists() {
        verify_existing_snapshot(&snapshot_directory, &manifest)?;
    } else {
        fs::create_dir_all(&snapshot_directory)
            .map_err(|_| "APPLICATION_RELEASE_SNAPSHOT_WRITE_ERROR")?;
        for (path, _) in &inputs {
            let destination = snapshot_directory.join(path);
            if path == "profile.json" {
                write_new(&destination, &profile_bytes)?;
            } else {
                let relative = path
                    .strip_prefix("package/")
                    .ok_or("APPLICATION_RELEASE_SNAPSHOT_WRITE_ERROR")?;
                copy_new(&package_directory.join(relative), &destination)?;
            }
        }
        let mut manifest_bytes = serde_json::to_vec_pretty(&manifest)
            .map_err(|_| "APPLICATION_RELEASE_SNAPSHOT_WRITE_ERROR")?;
        manifest_bytes.push(b'\n');
        write_new(
            &snapshot_directory.join("snapshot-manifest.json"),
            &manifest_bytes,
        )?;
    }

    let result = json!({
        "schema": CANDIDATE_SCHEMA,
        "evidence_level": "LOCAL_BUILD_VERIFIED",
        "adapter_id": ADAPTER_ID,
        "application_uri": application_uri,
        "network": NETWORK,
        "profile_digest": digest(&profile_bytes),
        "profile_scope": scope,
        "entrypoint": entrypoint,
        "release_id": release_id,
        "content_root": content_root,
        "covered_file_count": runtime_files.len(),
        "snapshot_digest": snapshot_digest,
        "snapshot_directory": fs::canonicalize(&snapshot_directory)
            .map_err(|_| "APPLICATION_RELEASE_SNAPSHOT_UNAVAILABLE")?,
    });
    if output.exists() {
        let existing = read_json(output, "APPLICATION_RELEASE_OUTPUT_INVALID")?;
        if existing != result {
            return Err("APPLICATION_RELEASE_OUTPUT_COLLISION".into());
        }
    } else {
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent).map_err(|_| "APPLICATION_RELEASE_OUTPUT_WRITE_ERROR")?;
        }
        let bytes = serde_json::to_vec_pretty(&result)
            .map_err(|_| "APPLICATION_RELEASE_OUTPUT_WRITE_ERROR")?;
        write_new(output, &bytes)?;
    }
    Ok(result)
}
