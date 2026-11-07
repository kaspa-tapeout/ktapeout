//! Deterministic, local-only application runtime packaging.
//!
//! Emits the Shell-consumable `KTAPEOUT-STATIC-RUNTIME-MANIFEST-V1` layout:
//! `<output>/runtime/<network>/<namespace>/<slug>/<release_id>/` holds the files at their
//! original relative paths plus `runtime-manifest.json`. Limits and path rules mirror the
//! browser verifier (`browser-content-runtime.mjs`), so a package that builds also loads.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path, PathBuf};
#[path = "discovery_v2.rs"]
mod discovery_v2;

pub fn discovery_template(network: &str) -> Value {
    json!({"schema":discovery_v2::SCHEMA,"network":network,"application_id":"0".repeat(64),
      "canonical_uri":format!("ktape://{network}/app/demo/starter"),"default_language":"en",
      "locales":{"en":{"name":"Starter application","summary":"Replace this description and bind the application identity before publication."}},
      "categories":["utility"],"wallet":"walletless","media":[]})
}

const SCHEMA: &str = "KTAPEOUT-STATIC-RUNTIME-MANIFEST-V1";
const DIGEST_DOMAIN: &[u8] = b"KTAPEOUT/0.5.0/STATIC_RUNTIME_PACKAGE/V1\0";
const MANIFEST_NAME: &str = "runtime-manifest.json";
const COMMITMENT_NAME: &str = "content-commitment.json";
const MAX_FILES: usize = 128;
const MAX_RESOURCE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 16 * 1024 * 1024;
const MAX_PATH_LEN: usize = 256;
const SENSITIVE_SUFFIXES: &[&str] = &[
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".jks",
    ".keystore",
    ".kdbx",
    ".map",
];
const SENSITIVE_PREFIXES: &[&str] = &["id_rsa", "id_ecdsa", "id_ed25519", "id_dsa"];

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PackageFile {
    path: String,
    sha256: String,
    byte_length: u64,
    media_type: String,
}

#[derive(Debug, Serialize)]
struct StaticRuntimeManifest<'a> {
    schema: &'static str,
    network: &'a str,
    application_uri: &'a str,
    release_id: &'a str,
    package_digest: &'a str,
    content_commitment: Value,
    entrypoint: &'a str,
    files: &'a [PackageFile],
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn is_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn valid_deployment_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}

fn valid_app_uri(uri: &str) -> bool {
    let mut parts = uri.split('/');
    let valid_part = |part: &str| {
        !part.is_empty()
            && part.len() <= 63
            && part
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && part.as_bytes()[0].is_ascii_lowercase()
            && part.as_bytes()[part.len() - 1].is_ascii_alphanumeric()
    };
    parts.next().is_some_and(valid_part)
        && parts.next().is_some_and(valid_part)
        && parts.next().is_none()
}

/// Same rules as the browser `safePath`: relative, `/`-separated, no empty/dot segments,
/// at most 256 bytes, and none of `\ ? # %` or ASCII control/space characters.
fn valid_relative(path: &Path) -> Result<String, String> {
    if path
        .components()
        .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err("PACKAGE_PATH_INVALID".into());
    }
    let value = path
        .to_str()
        .ok_or("PACKAGE_PATH_NOT_UTF8")?
        .replace('\\', "/");
    let windows_unsafe_component = |part: &str| {
        let device_name = part
            .split('.')
            .next()
            .unwrap_or(part)
            .trim_end_matches([' ', '.'])
            .to_ascii_uppercase();
        let reserved_device = matches!(device_name.as_str(), "CON" | "PRN" | "AUX" | "NUL")
            || ["COM", "LPT"].iter().any(|prefix| {
                device_name.strip_prefix(prefix).is_some_and(|suffix| {
                    suffix.len() == 1 && matches!(suffix.as_bytes()[0], b'1'..=b'9')
                })
            });
        reserved_device
            || part.ends_with('.')
            || part
                .chars()
                .any(|c| matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*'))
    };
    if value.is_empty()
        || value.len() > MAX_PATH_LEN
        || value.split('/').any(|part| {
            part.is_empty() || part == "." || part == ".." || windows_unsafe_component(part)
        })
        || value
            .chars()
            .any(|c| matches!(c, '?' | '#' | '%') || (c as u32) <= 0x20 || c == '\u{7f}')
    {
        return Err(format!("PACKAGE_PATH_INVALID:{value}"));
    }
    Ok(value)
}

/// Fail closed on files that must never be published: hidden files/directories (`.env`,
/// `.git`, `.npmrc`, ...), key material, and source maps.
fn sensitive(path: &str) -> bool {
    path.split('/').any(|part| part.starts_with('.')) || {
        let name = path.rsplit('/').next().unwrap_or(path).to_ascii_lowercase();
        SENSITIVE_SUFFIXES.iter().any(|s| name.ends_with(s))
            || SENSITIVE_PREFIXES.iter().any(|p| name.starts_with(p))
    }
}

fn collect(root: &Path, current: &Path, files: &mut Vec<(String, Vec<u8>)>) -> Result<(), String> {
    collect_resources(root, current, files, false)
}

fn collect_resources(
    root: &Path,
    current: &Path,
    files: &mut Vec<(String, Vec<u8>)>,
    skip_manifest: bool,
) -> Result<(), String> {
    let mut entries = fs::read_dir(current)
        .map_err(|_| "PACKAGE_SOURCE_READ_ERROR")?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "PACKAGE_SOURCE_READ_ERROR")?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let relative = path.strip_prefix(root).map_err(|_| "PACKAGE_PATH_ESCAPE")?;
        let name = valid_relative(relative)?;
        if sensitive(&name) {
            return Err(format!("PACKAGE_SENSITIVE_PATH_FORBIDDEN:{name}"));
        }
        let metadata = fs::symlink_metadata(&path).map_err(|_| "PACKAGE_SOURCE_READ_ERROR")?;
        if metadata.file_type().is_symlink() {
            return Err(format!("PACKAGE_SYMLINK_FORBIDDEN:{name}"));
        }
        if metadata.is_dir() {
            collect_resources(root, &path, files, skip_manifest)?;
            continue;
        }
        if !metadata.is_file() {
            return Err(format!("PACKAGE_SPECIAL_FILE_FORBIDDEN:{name}"));
        }
        if skip_manifest && name == MANIFEST_NAME {
            continue;
        }
        if metadata.len() > MAX_RESOURCE_BYTES {
            return Err(format!("PACKAGE_RESOURCE_LIMIT_EXCEEDED:{name}"));
        }
        if files.len() == MAX_FILES {
            return Err("PACKAGE_FILE_LIMIT_EXCEEDED".into());
        }
        let bytes = fs::read(&path).map_err(|_| "PACKAGE_SOURCE_READ_ERROR")?;
        if bytes.len() as u64 != metadata.len() {
            return Err("PACKAGE_SOURCE_CHANGED_DURING_READ".into());
        }
        files.push((name, bytes));
    }
    Ok(())
}

fn media_type(path: &str) -> &'static str {
    match Path::new(path)
        .extension()
        .and_then(|v| v.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
        .as_str()
    {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" => "application/json",
        "wasm" => "application/wasm",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "txt" => "text/plain; charset=utf-8",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "mp3" => "audio/mpeg",
        "mp4" => "video/mp4",
        _ => "application/octet-stream",
    }
}

fn write_file(root: &Path, relative: &str, bytes: &[u8]) -> Result<(), String> {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|_| "PACKAGE_OUTPUT_WRITE_ERROR")?;
    }
    fs::write(path, bytes).map_err(|_| "PACKAGE_OUTPUT_WRITE_ERROR".into())
}

fn verify_existing(
    output: &Path,
    release_dir: &str,
    manifest_bytes: &[u8],
    files: &[PackageFile],
) -> Result<bool, String> {
    if !output.exists() {
        return Ok(false);
    }
    let metadata = fs::symlink_metadata(output).map_err(|_| "PACKAGE_OUTPUT_READ_ERROR")?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("PACKAGE_OUTPUT_NOT_ORDINARY_DIRECTORY".into());
    }
    let release = output.join(release_dir);
    if fs::read(release.join(MANIFEST_NAME)).ok().as_deref() != Some(manifest_bytes) {
        return Err("PACKAGE_OUTPUT_COLLISION".into());
    }
    for file in files {
        let object = release.join(&file.path);
        let metadata =
            fs::symlink_metadata(&object).map_err(|_| "PACKAGE_OUTPUT_CONTENT_MISSING")?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err("PACKAGE_OUTPUT_CONTENT_INVALID".into());
        }
        let bytes = fs::read(object).map_err(|_| "PACKAGE_OUTPUT_CONTENT_MISSING")?;
        if bytes.len() as u64 != file.byte_length || sha256(&bytes) != file.sha256 {
            return Err("PACKAGE_OUTPUT_CONTENT_MISMATCH".into());
        }
    }
    Ok(true)
}

fn absolute_output(output: &Path) -> Result<PathBuf, String> {
    let output = if output.is_absolute() {
        output.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| "PACKAGE_CWD_UNAVAILABLE")?
            .join(output)
    };
    let output_parent = output.parent().ok_or("PACKAGE_OUTPUT_PATH_INVALID")?;
    let parent =
        fs::canonicalize(output_parent).map_err(|_| "PACKAGE_OUTPUT_PARENT_UNAVAILABLE")?;
    Ok(parent.join(output.file_name().ok_or("PACKAGE_OUTPUT_PATH_INVALID")?))
}

/// `package_digest` binds network, application, relative entrypoint and every file; it
/// deliberately excludes `release_id`, which defaults to the digest itself.
fn package_digest(
    network: &str,
    application_uri: &str,
    entrypoint: &str,
    files: &[PackageFile],
) -> Result<String, String> {
    let body = json!({
        "schema": SCHEMA,
        "network": network,
        "application_uri": application_uri,
        "entrypoint": entrypoint,
        "files": files,
    });
    let mut hasher = Sha256::new();
    hasher.update(DIGEST_DOMAIN);
    hasher.update(ktapeout_runtime::canonical_json(&body)?);
    Ok(format!("{:x}", hasher.finalize()))
}

pub fn build(
    source: &Path,
    network: &str,
    application_uri: &str,
    entrypoint: &str,
    release_id: Option<&str>,
    output: &Path,
) -> Result<Value, String> {
    build_bound(
        source,
        network,
        application_uri,
        entrypoint,
        release_id,
        output,
        None,
    )
}

/// Publication descriptors are outside the runtime commitment. They bind the caller's
/// application identity and DeveloperLock to the verified runtime, without claiming L1 evidence.
// Preserve the explicit publication contract fields at this public API boundary.
#[allow(clippy::too_many_arguments)]
pub fn build_for_publication(
    source: &Path,
    network: &str,
    application_uri: &str,
    entrypoint: &str,
    release_id: Option<&str>,
    output: &Path,
    application_id: &str,
    deployment_id: &str,
    profile: &Value,
) -> Result<Value, String> {
    if !is_hash(application_id) {
        return Err("PACKAGE_APPLICATION_ID_INVALID".into());
    }
    if !valid_deployment_id(deployment_id) {
        return Err("PACKAGE_DEPLOYMENT_ID_INVALID".into());
    }
    ktapeout_runtime::validate_developer_lock(profile)
        .map_err(|_| "PACKAGE_PROFILE_LOCK_INVALID".to_string())?;
    build_bound(
        source,
        network,
        application_uri,
        entrypoint,
        release_id,
        output,
        Some((application_id, deployment_id, profile)),
    )
}

fn build_bound(
    source: &Path,
    network: &str,
    application_uri: &str,
    entrypoint: &str,
    release_id: Option<&str>,
    output: &Path,
    publication: Option<(&str, &str, &Value)>,
) -> Result<Value, String> {
    if network != "testnet-10" {
        return Err("PACKAGE_NETWORK_NOT_ADMITTED".into());
    }
    if !valid_app_uri(application_uri) {
        return Err("PACKAGE_APPLICATION_URI_INVALID".into());
    }
    if release_id.is_some_and(|id| !is_hash(id)) {
        return Err("PACKAGE_RELEASE_ID_INVALID".into());
    }
    if valid_relative(Path::new(entrypoint))? != entrypoint {
        return Err("PACKAGE_ENTRYPOINT_INVALID".into());
    }
    let root = fs::canonicalize(source).map_err(|_| "PACKAGE_SOURCE_UNAVAILABLE")?;
    if !root.is_dir()
        || fs::symlink_metadata(source)
            .map_err(|_| "PACKAGE_SOURCE_UNAVAILABLE")?
            .file_type()
            .is_symlink()
    {
        return Err("PACKAGE_SOURCE_DIRECTORY_REQUIRED".into());
    }
    let output = absolute_output(output)?;
    if output.starts_with(&root) || root.starts_with(&output) {
        return Err("PACKAGE_OUTPUT_MUST_BE_OUTSIDE_SOURCE".into());
    }

    let mut source_files = Vec::new();
    collect(&root, &root, &mut source_files)?;
    let mut mirrors = Vec::new();
    let has_discovery = source_files
        .iter()
        .any(|(name, _)| name == "discovery/metadata.json");
    if let Some((_, bytes)) = source_files
        .iter()
        .find(|(name, _)| name == "discovery/metadata.json")
    {
        if bytes.len() > 16384 {
            return Err("DISCOVERY_METADATA_TOO_LARGE".into());
        }
        let metadata: Value =
            serde_json::from_slice(bytes).map_err(|_| "DISCOVERY_METADATA_INVALID")?;
        if metadata["schema"] == discovery_v2::SCHEMA {
            discovery_v2::validate(
                &metadata,
                network,
                application_uri,
                publication.map(|p| p.0),
            )?;
            let refs = discovery_v2::references(&metadata);
            for r in &refs {
                let relative = r["path"].as_str().ok_or("DISCOVERY_V2_INVALID")?;
                let (_, data) = source_files
                    .iter()
                    .find(|(name, _)| name == relative)
                    .ok_or("DISCOVERY_REFERENCE_MISSING")?;
                discovery_v2::verify(r, data)?;
                mirrors.push((
                    format!(
                        "assets/application-media/sha256/{}",
                        r["sha256"].as_str().ok_or("DISCOVERY_V2_INVALID")?
                    ),
                    data.clone(),
                ));
            }
            if source_files.iter().any(|(name, _)| {
                name.starts_with("discovery/")
                    && name != "discovery/metadata.json"
                    && !refs.iter().any(|r| r["path"] == *name)
            }) {
                return Err("DISCOVERY_UNDECLARED_FILE".into());
            }
            source_files.retain(|(name, _)| {
                !name.starts_with("discovery/") || name == "discovery/metadata.json"
            });
        }
    }
    if source_files.is_empty() {
        return Err("PACKAGE_SOURCE_EMPTY".into());
    }
    source_files.sort_by(|a, b| a.0.cmp(&b.0));
    let mut folded = BTreeSet::new();
    for (name, bytes) in &source_files {
        if name == MANIFEST_NAME || name == COMMITMENT_NAME {
            return Err(format!("PACKAGE_RESERVED_PATH:{name}"));
        }
        // Case-insensitive hosts (Windows, macOS, some object stores) would merge these.
        if !folded.insert(name.to_lowercase()) {
            return Err(format!("PACKAGE_PATH_CASE_COLLISION:{name}"));
        }
        if name.ends_with(".json") {
            if let Ok(value) = serde_json::from_slice::<Value>(bytes) {
                if carries_release_identity(&value) {
                    return Err(format!("PACKAGE_IDENTITY_FIELD:{name}"));
                }
            }
        }
    }
    if !source_files.iter().any(|(name, _)| name == entrypoint) {
        return Err("PACKAGE_ENTRYPOINT_MISSING".into());
    }
    // The anchor covers source bytes only. Its own digest enters the package identity,
    // so neither the anchor nor a covered resource needs to embed the release ID.
    let chunks = source_files
        .iter()
        .map(|(path, bytes)| json!({"path": path, "sha256": sha256(bytes)}))
        .collect::<Vec<_>>();
    let root =
        sha256(&serde_json::to_vec(&chunks).map_err(|_| "PACKAGE_COMMITMENT_ENCODE_FAILED")?);
    let anchor = json!({
        "schema": "KTAPEOUT-CANONICAL-CHUNKS-CONTENT-V1",
        "network": network,
        "root_scheme": "sha256-canonical-chunks-v1",
        "content_root": root,
        "chunks": chunks,
    });
    let anchor_bytes =
        serde_json::to_vec(&anchor).map_err(|_| "PACKAGE_COMMITMENT_ENCODE_FAILED")?;
    if anchor_bytes.len() > 64 * 1024 || source_files.len() >= MAX_FILES {
        return Err("PACKAGE_COMMITMENT_LIMIT_EXCEEDED".into());
    }
    source_files.push((COMMITMENT_NAME.into(), anchor_bytes));
    source_files.sort_by(|a, b| a.0.cmp(&b.0));
    let total_bytes = source_files
        .iter()
        .try_fold(0u64, |total, (_, bytes)| {
            total
                .checked_add(bytes.len() as u64)
                .filter(|n| *n <= MAX_TOTAL_BYTES)
        })
        .ok_or("PACKAGE_BYTE_LIMIT_EXCEEDED")?;

    let files = source_files
        .iter()
        .map(|(name, bytes)| PackageFile {
            path: name.clone(),
            sha256: sha256(bytes),
            byte_length: bytes.len() as u64,
            media_type: media_type(name).into(),
        })
        .collect::<Vec<_>>();
    let full_uri = format!("ktape://{network}/app/{application_uri}");
    let digest = package_digest(network, &full_uri, entrypoint, &files)?;
    let release_id = release_id.unwrap_or(&digest);
    for (name, bytes) in &source_files {
        if name != COMMITMENT_NAME
            && bytes
                .windows(release_id.len())
                .any(|part| part == release_id.as_bytes())
        {
            return Err(format!("PACKAGE_RELEASE_ID_EMBEDDED:{name}"));
        }
    }
    let release_dir = format!("runtime/{network}/{application_uri}/{release_id}");
    let entry_url = format!("/{release_dir}/{entrypoint}");
    if entry_url.len() - 1 > MAX_PATH_LEN {
        return Err("PACKAGE_ENTRYPOINT_PATH_TOO_LONG".into());
    }
    let manifest = StaticRuntimeManifest {
        schema: SCHEMA,
        network,
        application_uri: &full_uri,
        release_id,
        package_digest: &digest,
        content_commitment: json!({
            "schema": "KTAPEOUT-RUNTIME-CONTENT-COMMITMENT-V1",
            "adapter_id": "sha256-canonical-chunks-v1",
            "artifact_root": root,
            "manifest_path": COMMITMENT_NAME,
        }),
        entrypoint: &entry_url,
        files: &files,
    };
    let mut manifest_bytes =
        serde_json::to_vec_pretty(&manifest).map_err(|_| "PACKAGE_MANIFEST_ENCODE_FAILED")?;
    manifest_bytes.push(b'\n');
    let display_output = output.to_string_lossy().replace(r"\\?\", "");
    let summary = |status: &str| {
        json!({"status":status,"schema":SCHEMA,"network":network,"application_uri":full_uri,
            "release_id":release_id,"package_digest":digest,"entrypoint":entry_url,
            "files":files.len(),"bytes":total_bytes,"output":display_output,
            "manifest":format!("{release_dir}/{MANIFEST_NAME}"),"discovery_mirrors":mirrors.len(),
            "warnings":if has_discovery {Vec::<String>::new()} else {vec!["DISCOVERY_METADATA_MISSING: directory will use site-provided information".into()]},
            "signing":false,"broadcast":false})
    };
    let mut descriptors = Vec::new();
    if let Some((application_id, deployment_id, profile)) = publication {
        let values = [
            (
                "artifact.json",
                json!({
                    "schema":"KTAPEOUT-ARTIFACT-DESCRIPTOR-V1", "network":network,
                    "application_id":application_id, "artifact_root":root,
                    "runtime_manifest":format!("{release_dir}/{MANIFEST_NAME}"),
                    "runtime_manifest_sha256":sha256(&manifest_bytes),
                    "entrypoint":entry_url, "immutable":true,
                    "external_requests":"DENY_BY_DEFAULT"
                }),
            ),
            (
                "release.json",
                json!({
                    "schema":"KTAPEOUT-RELEASE-DESCRIPTOR-V1", "network":network,
                    "application_id":application_id, "release_id":release_id,
                    "deployment_id":deployment_id,
                    "artifact_root":root, "status":"LOCAL_UNSIGNED"
                }),
            ),
            (
                "name-target.json",
                json!({
                    "application_id":application_id, "release_id":release_id,
                    "deployment_id":deployment_id, "artifact_root":root
                }),
            ),
            (
                "name-binding.json",
                json!({
                    "schema":"KTAPEOUT-NAME-BINDING-PLAN-V1", "network":network,
                    "logical_name":application_uri, "canonical_uri":full_uri,
                    "expected_application_id":application_id, "expected_release_id":release_id,
                    "expected_artifact_root":root, "binding_status":"LOCAL_UNSIGNED",
                    "runtime_status":"LOCAL_VERIFIED", "write_allowed":false
                }),
            ),
            ("profile-lock.json", profile.clone()),
        ];
        for (name, value) in values {
            descriptors.push((
                name,
                serde_json::to_vec_pretty(&value)
                    .map_err(|_| "PACKAGE_DESCRIPTOR_ENCODE_FAILED")?,
            ));
        }
    }
    if verify_existing(&output, &release_dir, &manifest_bytes, &files)? {
        for (name, bytes) in &mirrors {
            let file = output.join(name);
            if !fs::symlink_metadata(&file)
                .map_err(|_| "DISCOVERY_MIRROR_MISSING")?
                .file_type()
                .is_file()
                || fs::read(file).map_err(|_| "DISCOVERY_MIRROR_MISSING")? != *bytes
            {
                return Err("DISCOVERY_MIRROR_MISMATCH".into());
            }
        }
        for (name, bytes) in &descriptors {
            let metadata = fs::symlink_metadata(output.join(name))
                .map_err(|_| "PACKAGE_OUTPUT_DESCRIPTOR_MISMATCH")?;
            if !metadata.file_type().is_file() {
                return Err("PACKAGE_OUTPUT_DESCRIPTOR_MISMATCH".into());
            }
            if fs::read(output.join(name)).ok().as_ref() != Some(bytes) {
                return Err("PACKAGE_OUTPUT_DESCRIPTOR_MISMATCH".into());
            }
        }
        return Ok(summary("UNCHANGED"));
    }
    if output.exists() {
        return Err("PACKAGE_OUTPUT_COLLISION".into());
    }
    let staging = output.with_extension(format!("incoming-{digest}"));
    if staging.exists() {
        return Err("PACKAGE_STAGING_EXISTS".into());
    }
    fs::create_dir(&staging).map_err(|_| "PACKAGE_STAGING_CREATE_FAILED")?;
    let staged = (|| {
        let release = staging.join(&release_dir);
        for (name, bytes) in &source_files {
            write_file(&release, name, bytes)?;
        }
        write_file(&release, MANIFEST_NAME, &manifest_bytes)?;
        for (name, bytes) in &mirrors {
            write_file(&staging, name, bytes)?;
        }
        for (name, bytes) in &descriptors {
            write_file(&staging, name, bytes)?;
        }
        fs::rename(&staging, &output).map_err(|_| "PACKAGE_ACTIVATION_FAILED".to_string())
    })();
    if let Err(error) = staged {
        let _ = fs::remove_dir_all(&staging);
        return Err(error);
    }
    Ok(summary("BUILT"))
}

fn carries_release_identity(value: &Value) -> bool {
    match value {
        Value::Array(items) => items.iter().any(carries_release_identity),
        Value::Object(fields) => {
            fields
                .keys()
                .any(|key| key == "release_id" || key == "content_root")
                || fields.values().any(carries_release_identity)
        }
        _ => false,
    }
}

/// Re-read the complete runtime closure before making a publication intent. A descriptor
/// or manifest digest alone is insufficient: extra files and identity-bearing bytes reject.
pub fn verify_publication_runtime(
    package: &Path,
    artifact: &Value,
    network: &str,
    canonical_uri: &str,
    release_id: &str,
    artifact_root: &str,
) -> Result<Value, String> {
    let application_uri = canonical_uri
        .strip_prefix(&format!("ktape://{network}/app/"))
        .filter(|uri| valid_app_uri(uri))
        .ok_or("PUBLISH_RUNTIME_URI_INVALID")?;
    if !is_hash(release_id) || !is_hash(artifact_root) {
        return Err("PUBLISH_RUNTIME_IDENTITY_INVALID".into());
    }
    let relative = format!("runtime/{network}/{application_uri}/{release_id}/{MANIFEST_NAME}");
    if artifact["runtime_manifest"].as_str() != Some(relative.as_str()) {
        return Err("PUBLISH_RUNTIME_MANIFEST_PATH_MISMATCH".into());
    }
    // Inspect every parent, since checking only the final file does not catch directory links.
    let mut path = package.to_path_buf();
    for part in relative.split('/') {
        path.push(part);
        let metadata = fs::symlink_metadata(&path).map_err(|_| "PUBLISH_RUNTIME_UNAVAILABLE")?;
        if metadata.file_type().is_symlink() {
            return Err("PUBLISH_RUNTIME_SYMLINK_FORBIDDEN".into());
        }
    }
    if fs::metadata(&path)
        .map_err(|_| "PUBLISH_RUNTIME_UNAVAILABLE")?
        .len()
        > 256 * 1024
    {
        return Err("PUBLISH_RUNTIME_MANIFEST_OVERSIZED".into());
    }
    let raw = fs::read(&path).map_err(|_| "PUBLISH_RUNTIME_UNAVAILABLE")?;
    if artifact["runtime_manifest_sha256"].as_str() != Some(sha256(&raw).as_str()) {
        return Err("PUBLISH_RUNTIME_MANIFEST_DIGEST_MISMATCH".into());
    }
    let manifest = ktapeout_runtime::parse_strict_json(&raw)
        .map_err(|_| "PUBLISH_RUNTIME_MANIFEST_INVALID")?;
    let descriptor = &manifest["content_commitment"];
    if manifest["schema"] != SCHEMA
        || manifest["network"] != network
        || manifest["application_uri"] != canonical_uri
        || manifest["release_id"] != release_id
        || descriptor["schema"] != "KTAPEOUT-RUNTIME-CONTENT-COMMITMENT-V1"
        || descriptor["adapter_id"] != "sha256-canonical-chunks-v1"
        || descriptor["manifest_path"] != COMMITMENT_NAME
        || descriptor["artifact_root"] != artifact_root
    {
        return Err("PUBLISH_RUNTIME_BINDING_MISMATCH".into());
    }
    let files: Vec<PackageFile> = serde_json::from_value(manifest["files"].clone())
        .map_err(|_| "PUBLISH_RUNTIME_FILES_INVALID")?;
    if files.is_empty() || files.len() > MAX_FILES {
        return Err("PUBLISH_RUNTIME_FILES_INVALID".into());
    }
    let mut source = Vec::new();
    collect_resources(
        path.parent().ok_or("PUBLISH_RUNTIME_PATH_INVALID")?,
        path.parent().ok_or("PUBLISH_RUNTIME_PATH_INVALID")?,
        &mut source,
        true,
    )?;
    source.sort_by(|a, b| a.0.cmp(&b.0));
    let mut actual = Vec::new();
    let mut chunks = Vec::new();
    let mut anchor = None;
    let mut total = 0u64;
    let mut folded = BTreeSet::new();
    for (name, bytes) in &source {
        total = total
            .checked_add(bytes.len() as u64)
            .filter(|n| *n <= MAX_TOTAL_BYTES)
            .ok_or("PUBLISH_RUNTIME_BYTE_LIMIT")?;
        if !folded.insert(name.to_lowercase()) {
            return Err("PUBLISH_RUNTIME_PATH_CASE_COLLISION".into());
        }
        actual.push(PackageFile {
            path: name.clone(),
            sha256: sha256(bytes),
            byte_length: bytes.len() as u64,
            media_type: media_type(name).into(),
        });
        if name == COMMITMENT_NAME {
            if bytes.len() > 64 * 1024 {
                return Err("PUBLISH_RUNTIME_ANCHOR_OVERSIZED".into());
            }
            anchor = Some(
                ktapeout_runtime::parse_strict_json(bytes)
                    .map_err(|_| "PUBLISH_RUNTIME_ANCHOR_INVALID")?,
            );
            continue;
        }
        if name.ends_with(".json") {
            if let Ok(value) = serde_json::from_slice::<Value>(bytes) {
                if carries_release_identity(&value) {
                    return Err(format!("PUBLISH_RUNTIME_IDENTITY_FIELD:{name}"));
                }
            }
        }
        if bytes
            .windows(release_id.len())
            .any(|part| part == release_id.as_bytes())
        {
            return Err(format!("PUBLISH_RUNTIME_RELEASE_ID_EMBEDDED:{name}"));
        }
        chunks.push(json!({"path":name,"sha256":sha256(bytes)}));
    }
    if actual != files {
        return Err("PUBLISH_RUNTIME_FILE_COVERAGE_OR_DIGEST_MISMATCH".into());
    }
    let anchor = anchor.ok_or("PUBLISH_RUNTIME_ANCHOR_MISSING")?;
    let root =
        sha256(&serde_json::to_vec(&chunks).map_err(|_| "PUBLISH_RUNTIME_ROOT_ENCODE_FAILED")?);
    if anchor["schema"] != "KTAPEOUT-CANONICAL-CHUNKS-CONTENT-V1"
        || anchor["network"] != network
        || anchor["root_scheme"] != "sha256-canonical-chunks-v1"
        || anchor["chunks"] != json!(chunks)
        || anchor["content_root"] != root
        || root != artifact_root
    {
        return Err("PUBLISH_RUNTIME_ANCHOR_MISMATCH".into());
    }
    let prefix = format!("/runtime/{network}/{application_uri}/{release_id}/");
    let entry = manifest["entrypoint"]
        .as_str()
        .and_then(|v| v.strip_prefix(&prefix))
        .filter(|v| files.iter().any(|f| f.path == *v))
        .ok_or("PUBLISH_RUNTIME_ENTRYPOINT_INVALID")?;
    let digest = package_digest(network, canonical_uri, entry, &files)?;
    if manifest["package_digest"] != digest {
        return Err("PUBLISH_RUNTIME_PACKAGE_DIGEST_MISMATCH".into());
    }
    if let Some((_, bytes)) = source
        .iter()
        .find(|(name, _)| name == "discovery/metadata.json")
    {
        let metadata: Value = serde_json::from_slice(bytes).map_err(|_| "DISCOVERY_V2_INVALID")?;
        if metadata["schema"] == discovery_v2::SCHEMA {
            discovery_v2::validate(
                &metadata,
                network,
                application_uri,
                artifact["application_id"].as_str(),
            )?;
            for reference in discovery_v2::references(&metadata) {
                let relative = format!(
                    "assets/application-media/sha256/{}",
                    reference["sha256"].as_str().ok_or("DISCOVERY_V2_INVALID")?
                );
                let mut mirror = package.to_path_buf();
                for part in relative.split('/') {
                    mirror.push(part);
                    if fs::symlink_metadata(&mirror)
                        .map_err(|_| "DISCOVERY_MIRROR_MISSING")?
                        .file_type()
                        .is_symlink()
                    {
                        return Err("DISCOVERY_MIRROR_SYMLINK_FORBIDDEN".into());
                    }
                }
                let stat = fs::metadata(&mirror).map_err(|_| "DISCOVERY_MIRROR_MISSING")?;
                if !stat.is_file()
                    || stat.len()
                        != reference["byte_length"]
                            .as_u64()
                            .ok_or("DISCOVERY_V2_INVALID")?
                {
                    return Err("DISCOVERY_MIRROR_SIZE_MISMATCH".into());
                }
                discovery_v2::verify(
                    reference,
                    &fs::read(mirror).map_err(|_| "DISCOVERY_MIRROR_MISSING")?,
                )?;
            }
        }
    }
    Ok(
        json!({"status":"LOCAL_VERIFIED", "artifact_root":root,"package_digest":digest,
        "manifest_sha256":sha256(&raw),"files":files.len(),"bytes":total,
        "signing_allowed":false,"broadcast":false}),
    )
}
