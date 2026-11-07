use ktapeout_runtime::parse_strict_json;
use serde_json::{json, Value};
use std::collections::BTreeMap;

const DESCRIPTOR_PATH: &str = "discovery/media.json";
const MAX_DESCRIPTOR_BYTES: usize = 8 * 1024;
const MAX_TOTAL_IMAGE_BYTES: u64 = 96 * 1024;

fn exact_keys(value: &Value, expected: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key))
    })
}

fn invalid_asset(role: &str) -> String {
    format!("CONTENT_MEDIA_ASSET_INVALID:{role}")
}

fn inspect_asset(
    role: &str,
    asset: &Value,
    files: &[Value],
    unique_bytes: &mut BTreeMap<String, u64>,
) -> Result<(), String> {
    if !exact_keys(
        asset,
        &[
            "path",
            "media_type",
            "byte_length",
            "width",
            "height",
            "sha256",
            "alt",
        ],
    ) {
        return Err(format!("CONTENT_MEDIA_ASSET_FIELDS_INVALID:{role}"));
    }
    let path = asset
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_asset(role))?;
    let safe_path = !path.is_empty()
        && path.len() <= 256
        && path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'/' | b'-'))
        && !path.starts_with('/')
        && !path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..");
    if !safe_path {
        return Err(format!("CONTENT_MEDIA_PATH_INVALID:{role}"));
    }

    let media_type = asset
        .get("media_type")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_asset(role))?;
    if !matches!(media_type, "image/png" | "image/webp" | "image/jpeg") {
        return Err(format!("CONTENT_MEDIA_TYPE_UNSUPPORTED:{role}"));
    }
    let bytes = asset
        .get("byte_length")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid_asset(role))?;
    let width = asset
        .get("width")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid_asset(role))?;
    let height = asset
        .get("height")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid_asset(role))?;
    let (max_bytes, max_width, max_height) = match role {
        "icon" => (32 * 1024, 256, 256),
        "card" => (64 * 1024, 768, 432),
        _ => return Err("CONTENT_MEDIA_ROLE_INVALID".to_string()),
    };
    if bytes == 0
        || bytes > max_bytes
        || width == 0
        || height == 0
        || width > max_width
        || height > max_height
    {
        return Err(format!("CONTENT_MEDIA_ROLE_LIMIT_EXCEEDED:{role}"));
    }
    let digest = asset
        .get("sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_asset(role))?;
    if digest.len() != 64
        || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        || digest != digest.to_ascii_lowercase()
    {
        return Err(format!("CONTENT_MEDIA_HASH_INVALID:{role}"));
    }
    let alt = asset
        .get("alt")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_asset(role))?;
    if alt.trim().is_empty() || alt.chars().count() > 160 || alt.chars().any(char::is_control) {
        return Err(format!("CONTENT_MEDIA_ALT_INVALID:{role}"));
    }

    let file = files
        .iter()
        .find(|file| file.get("path").and_then(Value::as_str) == Some(path))
        .ok_or_else(|| format!("CONTENT_MEDIA_FILE_MISSING:{path}"))?;
    if file.get("size").and_then(Value::as_u64) != Some(bytes)
        || file.get("content_type").and_then(Value::as_str) != Some(media_type)
        || file.get("sha256").and_then(Value::as_str) != Some(digest)
    {
        return Err(format!("CONTENT_MEDIA_FILE_MISMATCH:{path}"));
    }
    if let Some(previous) = unique_bytes.insert(path.to_owned(), bytes) {
        if previous != bytes {
            return Err("CONTENT_MEDIA_SHARED_PATH_MISMATCH".to_string());
        }
    }
    Ok(())
}

pub(super) fn inspect_discovery_media(artifact: &Value) -> Result<Value, String> {
    let files = artifact
        .get("files")
        .and_then(Value::as_array)
        .ok_or_else(|| "CONTENT_MEDIA_ARTIFACT_FILES_INVALID".to_string())?;
    let Some(file) = files
        .iter()
        .find(|file| file.get("path").and_then(Value::as_str) == Some(DESCRIPTOR_PATH))
    else {
        return Ok(json!({"status":"NOT_DECLARED"}));
    };
    if file.get("size").and_then(Value::as_u64).unwrap_or(u64::MAX) > MAX_DESCRIPTOR_BYTES as u64 {
        return Err("CONTENT_MEDIA_DESCRIPTOR_SIZE_LIMIT".to_string());
    }
    let chunks = file
        .get("chunks")
        .and_then(Value::as_array)
        .ok_or_else(|| "CONTENT_MEDIA_DESCRIPTOR_CHUNKS_INVALID".to_string())?;
    let mut raw = Vec::new();
    for chunk in chunks {
        let encoded = chunk
            .as_str()
            .ok_or_else(|| "CONTENT_MEDIA_DESCRIPTOR_CHUNKS_INVALID".to_string())?;
        let decoded = hex::decode(encoded)
            .map_err(|_| "CONTENT_MEDIA_DESCRIPTOR_CHUNKS_INVALID".to_string())?;
        if raw.len() + decoded.len() > MAX_DESCRIPTOR_BYTES {
            return Err("CONTENT_MEDIA_DESCRIPTOR_SIZE_LIMIT".to_string());
        }
        raw.extend_from_slice(&decoded);
    }
    let descriptor =
        parse_strict_json(&raw).map_err(|_| "CONTENT_MEDIA_DESCRIPTOR_JSON_INVALID".to_string())?;
    let canonical = serde_json::to_vec(&descriptor)
        .map_err(|_| "CONTENT_MEDIA_DESCRIPTOR_JSON_INVALID".to_string())?;
    if canonical != raw {
        return Err("CONTENT_MEDIA_DESCRIPTOR_NOT_CANONICAL".to_string());
    }
    if !exact_keys(&descriptor, &["schema", "assets"])
        || descriptor.get("schema").and_then(Value::as_str) != Some("KTAPEOUT-DISCOVERY-MEDIA-V1")
    {
        return Err("CONTENT_MEDIA_DESCRIPTOR_SCHEMA_INVALID".to_string());
    }
    let assets = descriptor
        .get("assets")
        .and_then(Value::as_object)
        .ok_or_else(|| "CONTENT_MEDIA_ASSETS_INVALID".to_string())?;
    if assets.is_empty()
        || assets
            .keys()
            .any(|role| !matches!(role.as_str(), "icon" | "card"))
    {
        return Err("CONTENT_MEDIA_ASSETS_INVALID".to_string());
    }
    let mut unique_bytes = BTreeMap::new();
    for (role, asset) in assets {
        inspect_asset(role, asset, files, &mut unique_bytes)?;
    }
    let total: u64 = unique_bytes.values().sum();
    if total > MAX_TOTAL_IMAGE_BYTES {
        return Err("CONTENT_MEDIA_TOTAL_SIZE_LIMIT".to_string());
    }
    Ok(json!({
        "status":"CONTENT_BOUND",
        "asset_count":assets.len(),
        "unique_image_bytes":total,
        "format_decode":"NOT_PERFORMED_BY_CLI",
        "evidence":"DESCRIPTOR_AND_ASSET_BYTES_MATCH_VERIFIED_CONTENT_ARTIFACT"
    }))
}
