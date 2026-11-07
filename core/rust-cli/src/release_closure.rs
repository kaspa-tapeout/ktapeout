//! Release-closure and Shell load-time checks, ported rule for rule from the publisher and browser
//! runtime implementations (references, full coverage, identity, runtime manifest, bytes, and content commitment).
//! Both implementations run shared vectors maintained outside this repository;
//! a release this module accepts
//! is one the public Shell accepts. Read-only: never signs, broadcasts or writes.
//!
//! Intentional strictness over the JS side (reject where JS might accept): malformed chunk rows are `COMMITMENT_INVALID`,
//! JSON must be valid UTF-8, numbers in release fields must have one JS rendering, and OnChainContentV1 artifacts must be
//! canonical bytes (`ktapeout_core::verify_content_artifact_050`).
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

/// Published path -> bytes, in byte order of the path.
pub type Files = BTreeMap<String, Vec<u8>>;

pub const GENERATED: [&str; 2] = ["runtime-manifest.json", "content-locator.json"];
const IDENTITY_FIELDS: [&str; 2] = ["release_id", "content_root"];
pub const ROOT_SCHEME: &str = "sha256-canonical-chunks-v1";
const ONCHAIN_ADAPTER: &str = "OnChainContentV1";
const STATIC_MANIFEST: &str = "KTAPEOUT-STATIC-RUNTIME-MANIFEST-V1";
const LOCATOR_MANIFEST: &str = "KTAPEOUT-BROWSER-CONTENT-LOCATOR-V1";
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// Shell limits (`LIMITS` in browser-content-runtime.mjs).
pub const SHELL_MAX_FILES: usize = 128;
pub const SHELL_MAX_RESOURCE_BYTES: u64 = 4 * 1024 * 1024;
pub const SHELL_MAX_TOTAL_BYTES: u64 = 16 * 1024 * 1024;
const CANONICAL_MANIFEST_MAX_BYTES: usize = 64 * 1024;
const ONCHAIN_ARTIFACT_MAX_BYTES: usize = 256 * 1024;
/// Local tree bounds; far above the Shell limits so the Shell rule, not the reader, decides.
const TREE_MAX_FILES: usize = 4096;
const TREE_MAX_BYTES: u64 = 256 * 1024 * 1024;

pub fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn is_hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack.len() >= needle.len()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn js_string(value: &str) -> String {
    serde_json::to_string(value).expect("a string always encodes")
}

/// Number.isSafeInteger for a non-negative JSON number.
fn safe_uint(value: &Value) -> Option<u64> {
    if let Some(n) = value.as_u64() {
        return (n <= MAX_SAFE_INTEGER).then_some(n);
    }
    let f = value.as_f64()?;
    (f.fract() == 0.0 && (0.0..=MAX_SAFE_INTEGER as f64).contains(&f)).then_some(f as u64)
}

// ---------------------------------------------------------------------------------------------------------------------
// Canonical encodings
// ---------------------------------------------------------------------------------------------------------------------

/// Root of the sha256-canonical-chunks-v1 adapter: SHA-256 of `JSON.stringify([{path, sha256}, ...])` in declared order.
pub fn canonical_chunks_root<'a>(leaves: impl IntoIterator<Item = (&'a str, &'a str)>) -> String {
    let body = leaves
        .into_iter()
        .map(|(path, digest)| {
            format!(
                "{{\"path\":{},\"sha256\":{}}}",
                js_string(path),
                js_string(digest)
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    sha256(format!("[{body}]").as_bytes())
}

fn js_number(number: &serde_json::Number) -> Result<String, String> {
    if let Some(n) = number.as_u64() {
        if n <= MAX_SAFE_INTEGER {
            return Ok(n.to_string());
        }
    } else if let Some(n) = number.as_i64() {
        if n.unsigned_abs() <= MAX_SAFE_INTEGER {
            return Ok(n.to_string());
        }
    } else if let Some(f) = number.as_f64() {
        if f == 0.0 {
            return Ok("0".into());
        }
        // Inside this range Rust's shortest round-trip rendering equals Number.prototype.toString.
        if f.is_finite() && (1e-6..1e21).contains(&f.abs()) {
            return Ok(format!("{f}"));
        }
    }
    Err("CANONICAL_JSON_NUMBER_UNSUPPORTED".into())
}

/// Sorted-key canonical JSON, identical to `canonicalJson` in release-closure.mjs (keys in UTF-16 order).
pub fn canonical_json(value: &Value) -> Result<String, String> {
    Ok(match value {
        Value::Null => "null".into(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => js_number(n)?,
        Value::String(s) => js_string(s),
        Value::Array(items) => format!(
            "[{}]",
            items
                .iter()
                .map(canonical_json)
                .collect::<Result<Vec<_>, _>>()?
                .join(",")
        ),
        Value::Object(map) => {
            let mut keys = map.keys().collect::<Vec<_>>();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            let parts = keys
                .into_iter()
                .map(|key| Ok(format!("{}:{}", js_string(key), canonical_json(&map[key])?)))
                .collect::<Result<Vec<_>, String>>()?;
            format!("{{{}}}", parts.join(","))
        }
    })
}

/// release_id = SHA-256 of the release fields with the root bound in as content_root.
pub fn release_id_for(release: &Map<String, Value>, content_root: &str) -> Result<String, String> {
    let mut bound = release.clone();
    bound.insert("content_root".into(), Value::String(content_root.into()));
    Ok(sha256(canonical_json(&Value::Object(bound))?.as_bytes()))
}

// Commitment over every file except the commitment itself and the generated manifests, in path order. With
// `release_file`, the anchor also names the release_id derived from that covered file's fields and the root.
// Used by the freeze step; until it lands only the shared vectors call it.

// ---------------------------------------------------------------------------------------------------------------------
// Publisher closure (release-closure.mjs)
// ---------------------------------------------------------------------------------------------------------------------

fn is_text_file(path: &str) -> bool {
    path.rsplit_once('.').is_some_and(|(_, ext)| {
        ["htm", "html", "js", "mjs", "css", "json", "webmanifest"].contains(&ext)
    })
}

fn is_js_space(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200a}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202f}'
                | '\u{205f}'
                | '\u{3000}'
                | '\u{feff}'
    )
}

/// The reference prefixes of `SPEC`, in alternation order; `*` is `\s*` and `+` is `\s+`.
const REFERENCE_PREFIXES: [&str; 8] = [
    "from*",
    "import*(*",
    "import+",
    "src*=*",
    "href*=*",
    "fetch*(*",
    "new+Worker*(*",
    "importScripts*(*",
];

fn match_prefix(text: &[char], mut at: usize, pattern: &str) -> Option<usize> {
    for token in pattern.chars() {
        match token {
            '*' | '+' => {
                let start = at;
                while at < text.len() && is_js_space(text[at]) {
                    at += 1;
                }
                if token == '+' && at == start {
                    return None;
                }
            }
            literal => {
                if text.get(at) != Some(&literal) {
                    return None;
                }
                at += 1;
            }
        }
    }
    Some(at)
}

/// Every `(is_fetch, reference)` the SPEC regex finds, scanning left to right without overlap.
fn references(text: &[char]) -> Vec<(bool, String)> {
    let mut found = Vec::new();
    let mut at = 0;
    'scan: while at < text.len() {
        for pattern in REFERENCE_PREFIXES {
            let Some(quote_at) = match_prefix(text, at, pattern) else {
                continue;
            };
            let Some(&quote) = text.get(quote_at).filter(|c| matches!(c, '\'' | '"')) else {
                continue;
            };
            let mut end = quote_at + 1;
            while end < text.len() && !matches!(text[end], '\'' | '"' | '?' | '#') {
                end += 1;
            }
            if end == quote_at + 1 || text.get(end) != Some(&quote) {
                continue;
            }
            found.push((
                pattern.starts_with("fetch"),
                text[quote_at + 1..end].iter().collect(),
            ));
            at = end + 1;
            continue 'scan;
        }
        at += 1;
    }
    found
}

fn is_external_reference(reference: &str) -> bool {
    if reference.starts_with('/') || reference.starts_with('#') {
        return true;
    }
    let mut chars = reference.chars();
    if !chars.next().is_some_and(|c| c.is_ascii_alphabetic()) {
        return false;
    }
    chars
        .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-')))
        .is_some_and(|c| c == ':')
}

fn normalize(path: &str) -> Option<String> {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            _ => parts.push(part),
        }
    }
    Some(parts.join("/"))
}

/// Relative module, page and fetch targets in listed text files that resolve to no listed file. Targets the application
/// declared optional may be absent only when referenced by fetch(). Result is sorted by target.
pub fn unresolved_references(
    files: &Files,
    optional_fetch_targets: &BTreeSet<String>,
) -> Vec<(String, Vec<String>)> {
    let mut missing: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (path, bytes) in files {
        if !is_text_file(path) {
            continue;
        }
        let text = String::from_utf8_lossy(bytes).chars().collect::<Vec<_>>();
        for (is_fetch, reference) in references(&text) {
            if is_external_reference(&reference) {
                continue;
            }
            let joined = match path.rsplit_once('/') {
                Some((dir, _)) => format!("{dir}/{reference}"),
                None => reference.clone(),
            };
            let target =
                normalize(&joined).unwrap_or_else(|| format!("(outside closure) {joined}"));
            if files.contains_key(&target) || (is_fetch && optional_fetch_targets.contains(&target))
            {
                continue;
            }
            missing.entry(target).or_default().insert(path.clone());
        }
    }
    missing
        .into_iter()
        .map(|(target, referrers)| (target, referrers.into_iter().collect()))
        .collect()
}

/// Formal coverage of a sha256-canonical-chunks-v1 commitment: every published file except the commitment and the
/// generated manifests is covered with matching bytes, the root recomputes, and no covered file embeds the root.
pub fn formal_coverage_failures(
    files: &Files,
    commitment: &Value,
    commitment_path: &str,
) -> Vec<String> {
    let invalid = || vec!["COMMITMENT_INVALID".to_string()];
    let Some(chunks) = commitment.get("chunks").and_then(Value::as_array) else {
        return invalid();
    };
    if commitment["root_scheme"] != ROOT_SCHEME {
        return invalid();
    }
    let mut leaves = Vec::with_capacity(chunks.len());
    for chunk in chunks {
        match (
            chunk.get("path").and_then(Value::as_str),
            chunk.get("sha256").and_then(Value::as_str),
        ) {
            (Some(path), Some(digest)) => leaves.push((path, digest)),
            _ => return invalid(),
        }
    }
    let mut failures = Vec::new();
    let root = canonical_chunks_root(leaves.iter().copied());
    if commitment["content_root"].as_str() != Some(root.as_str()) {
        failures.push(format!("COMMITMENT_ROOT_MISMATCH {root}"));
    }
    let covered = leaves
        .iter()
        .map(|(path, _)| *path)
        .collect::<BTreeSet<_>>();
    if covered.len() != leaves.len() {
        failures.push("COMMITMENT_DUPLICATE_PATH".into());
    }
    if covered.contains(commitment_path) {
        failures.push("COMMITMENT_COVERS_ITSELF".into());
    }
    for (path, digest) in &leaves {
        match files.get(*path) {
            None => failures.push(format!("COMMITTED_FILE_MISSING {path}")),
            Some(bytes) if sha256(bytes) != *digest => {
                failures.push(format!("COMMITTED_FILE_DIGEST {path}"))
            }
            Some(_) => {}
        }
    }
    for path in files.keys() {
        if path != commitment_path
            && !GENERATED.contains(&path.as_str())
            && !covered.contains(path.as_str())
        {
            failures.push(format!("UNCOVERED {path}"));
        }
    }
    for (path, bytes) in files {
        if path != commitment_path && contains(bytes, root.as_bytes()) {
            failures.push(format!("SELF_REFERENCE {path}"));
        }
    }
    failures
}

/// OnChainContentV1 coverage: the artifact declares every published file except itself, with matching digest and size.
pub fn onchain_artifact_coverage_failures(
    files: &Files,
    artifact: &Value,
    artifact_path: &str,
) -> Vec<String> {
    let Some(declared) = artifact.get("files").and_then(Value::as_array) else {
        return vec!["ARTIFACT_INVALID".into()];
    };
    let mut rows = BTreeMap::new();
    for row in declared {
        let Some(path) = row.get("path").and_then(Value::as_str) else {
            return vec!["ARTIFACT_INVALID".into()];
        };
        rows.insert(path, row);
    }
    let mut failures = Vec::new();
    if rows.len() != declared.len() {
        failures.push("ARTIFACT_DUPLICATE_PATH".into());
    }
    if rows.contains_key(artifact_path) {
        failures.push("ARTIFACT_COVERS_ITSELF".into());
    }
    for path in declared.iter().filter_map(|row| row["path"].as_str()) {
        if !files.contains_key(path) {
            failures.push(format!("COMMITTED_FILE_MISSING {path}"));
        }
    }
    for (path, bytes) in files {
        if path == artifact_path || GENERATED.contains(&path.as_str()) {
            continue;
        }
        match rows.get(path.as_str()) {
            None => failures.push(format!("UNCOVERED {path}")),
            Some(row)
                if row["sha256"] != sha256(bytes)
                    || safe_uint(&row["size"]) != Some(bytes.len() as u64) =>
            {
                failures.push(format!("COMMITTED_FILE_DIGEST {path}"))
            }
            Some(_) => {}
        }
    }
    failures
}

fn holds_identity_field(value: &Value) -> bool {
    match value {
        Value::Array(items) => items.iter().any(holds_identity_field),
        Value::Object(map) => {
            map.keys()
                .any(|key| IDENTITY_FIELDS.contains(&key.as_str()))
                || map.values().any(holds_identity_field)
        }
        _ => false,
    }
}

/// No covered JSON file holds an identity field (any depth) and no covered file embeds an identity value.
pub fn identity_leak_failures(
    files: &Files,
    commitment_path: &str,
    values: &[&str],
) -> Vec<String> {
    let needles = values
        .iter()
        .filter(|value| is_hex64(value))
        .collect::<Vec<_>>();
    let mut failures = Vec::new();
    for (path, bytes) in files {
        if path == commitment_path || GENERATED.contains(&path.as_str()) {
            continue;
        }
        if path.ends_with(".json")
            && serde_json::from_slice::<Value>(bytes)
                .is_ok_and(|value| holds_identity_field(&value))
        {
            failures.push(format!("IDENTITY_FIELD {path}"));
        }
        if needles
            .iter()
            .any(|needle| contains(bytes, needle.as_bytes()))
        {
            failures.push(format!("RELEASE_ID_EMBEDDED {path}"));
        }
    }
    failures
}

fn release_fields(files: &Files, release_file: &str) -> Result<Map<String, Value>, &'static str> {
    let bytes = files.get(release_file).ok_or("RELEASE_FILE_MISSING")?;
    match serde_json::from_slice::<Value>(bytes) {
        Ok(Value::Object(map)) => Ok(map),
        _ => Err("RELEASE_FILE_INVALID"),
    }
}

/// Release-anchor failures when release fields come from a covered release file.
pub fn release_anchor_failures(
    files: &Files,
    commitment: &Value,
    commitment_path: &str,
    release_file: &str,
) -> Vec<String> {
    let release = match release_fields(files, release_file) {
        Ok(release) => release,
        Err(code) => return vec![code.into()],
    };
    let mut failures = Vec::new();
    if IDENTITY_FIELDS
        .iter()
        .any(|field| release.contains_key(*field))
    {
        failures.push("RELEASE_CARRIES_IDENTITY".to_string());
    }
    let release_id = commitment
        .get("release_id")
        .and_then(Value::as_str)
        .filter(|id| is_hex64(id));
    match release_id {
        None => failures.push("RELEASE_ID_MISSING".into()),
        Some(id) if failures.is_empty() => {
            let root = commitment["content_root"].as_str().unwrap_or_default();
            if release_id_for(&release, root).ok().as_deref() != Some(id) {
                failures.push("RELEASE_ID_MISMATCH".into());
            }
        }
        Some(_) => {}
    }
    failures.extend(identity_leak_failures(
        files,
        commitment_path,
        &[release_id.unwrap_or_default()],
    ));
    failures
}

/// How a closure's release_id is established: from a covered release-fields file, or supplied by the caller.
pub enum Identity<'a> {
    ReleaseFile(&'a str),
    External(&'a str),
}

/// `verifyCanonicalReleaseClosure`: the anchor's schema and network match the policy, the closure is fully covered, and the
/// release identity holds. Errors are `RELEASE_CLOSURE_REJECTED:<first failure>`.
pub fn verify_canonical_release_closure(
    files: &Files,
    commitment_path: &str,
    network: &str,
    schema: &str,
    identity: &Identity,
) -> Result<Value, String> {
    let reject = |code: &str| format!("RELEASE_CLOSURE_REJECTED:{code}");
    let identity_value = match identity {
        Identity::ReleaseFile(v) | Identity::External(v) => *v,
    };
    if network.is_empty() || schema.is_empty() || identity_value.is_empty() {
        return Err(reject("IDENTITY_POLICY_INVALID"));
    }
    let anchor_bytes = files
        .get(commitment_path)
        .ok_or_else(|| reject("COMMITMENT_MISSING"))?;
    let anchor: Value =
        serde_json::from_slice(anchor_bytes).map_err(|_| reject("COMMITMENT_INVALID"))?;
    if anchor.get("schema").and_then(Value::as_str) != Some(schema)
        || anchor.get("network").and_then(Value::as_str) != Some(network)
    {
        return Err(reject("COMMITMENT_IDENTITY_MISMATCH"));
    }
    let mut failures = formal_coverage_failures(files, &anchor, commitment_path);
    let mut fields = Value::Null;
    let release_id;
    match identity {
        Identity::ReleaseFile(release_file) => {
            failures.extend(release_anchor_failures(
                files,
                &anchor,
                commitment_path,
                release_file,
            ));
            if failures.is_empty() {
                let release = release_fields(files, release_file).map_err(reject)?;
                if release.get("network").and_then(Value::as_str) != Some(network) {
                    failures.push("RELEASE_NETWORK_MISMATCH".into());
                }
                fields = Value::Object(release);
            }
            release_id = anchor["release_id"].clone();
        }
        Identity::External(external) => {
            if !is_hex64(external) {
                failures.push("RELEASE_ID_INVALID".into());
            }
            if anchor
                .get("release_id")
                .is_some_and(|declared| declared != external)
            {
                failures.push("RELEASE_ID_MISMATCH".into());
            }
            failures.extend(identity_leak_failures(files, commitment_path, &[external]));
            release_id = Value::String((*external).into());
        }
    }
    if let Some(first) = failures.first() {
        return Err(reject(first));
    }
    Ok(json!({
        "release_id": release_id,
        "content_root": anchor["content_root"],
        "identity_derivation": match identity { Identity::ReleaseFile(_) => "COVERED_RELEASE_FIELDS", Identity::External(_) => "EXTERNAL" },
        "release_fields": fields,
        "anchor_sha256": sha256(anchor_bytes),
    }))
}

// ---------------------------------------------------------------------------------------------------------------------
// Shell load-time checks (browser-content-runtime.mjs)
// ---------------------------------------------------------------------------------------------------------------------

/// What the Shell binds a manifest to: the chain-resolved network, application and release.
pub struct RuntimeContext<'a> {
    pub network: &'a str,
    pub application_uri: &'a str,
    pub release_id: &'a str,
}

fn safe_path(path: &str) -> Result<&str, String> {
    if path.is_empty()
        || path.encode_utf16().count() > 256
        || path.starts_with('/')
        || path
            .chars()
            .any(|c| matches!(c, '\\' | '?' | '#' | '%') || c <= '\u{20}')
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err("CONTENT_PATH_INVALID".into());
    }
    Ok(path)
}

fn safe_path_value(value: &Value) -> Result<&str, String> {
    safe_path(value.as_str().ok_or("CONTENT_PATH_INVALID")?)
}

/// `sameOriginPath`: the value must be a pathname the URL parser leaves unchanged, then a safe path.
fn same_origin_path(value: &Value) -> Result<&str, String> {
    let invalid = || "CONTENT_URL_INVALID".to_string();
    let path = value.as_str().ok_or_else(invalid)?;
    if !path.starts_with('/') || path.starts_with("//") {
        return Err(invalid());
    }
    let rewritten =
        |c: char| !c.is_ascii() || c <= ' ' || c == '\u{7f}' || "\"#<>?`{}\\".contains(c);
    let dot_segment = |s: &str| {
        matches!(
            s.to_ascii_lowercase().as_str(),
            "." | ".." | "%2e" | ".%2e" | "%2e." | "%2e%2e"
        )
    };
    if path.chars().any(rewritten) || path.split('/').any(dot_segment) {
        return Err(invalid());
    }
    safe_path(&path[1..])?;
    Ok(path)
}

fn runtime_resource_base<'a>(entry: &'a str, release_id: &str) -> Result<&'a str, String> {
    let segment = format!("/{release_id}/");
    let base = match entry.rfind(&segment) {
        Some(offset) => &entry[..offset + segment.len()],
        None => &entry[..entry.rfind('/').map_or(0, |i| i + 1)],
    };
    if !base.starts_with("/runtime/") {
        return Err("CONTENT_RUNTIME_BASE_INVALID".into());
    }
    Ok(base)
}

fn valid_media_type(value: &str) -> bool {
    let token = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".+-".contains(&b))
    };
    let value = value.strip_suffix("; charset=utf-8").unwrap_or(value);
    value
        .split_once('/')
        .is_some_and(|(a, b)| token(a) && token(b))
}

struct ValidatedManifest<'a> {
    base: String,
    entry: String,
    total: u64,
    resources: Vec<(&'a str, &'a str, u64)>,
}

/// `validateManifest` with the default adapter policy plus the adapters the caller admits.
fn validate_manifest<'a>(
    manifest: &'a Value,
    ctx: &RuntimeContext,
    allowed: &[&str],
) -> Result<ValidatedManifest<'a>, String> {
    let schema = manifest.get("schema").and_then(Value::as_str);
    if !matches!(schema, Some(STATIC_MANIFEST | LOCATOR_MANIFEST)) {
        return Err("CONTENT_MANIFEST_INVALID".into());
    }
    if manifest["network"] != ctx.network
        || manifest["application_uri"]
            != format!("ktape://{}/app/{}", ctx.network, ctx.application_uri)
        || manifest["release_id"] != ctx.release_id
        || !manifest["package_digest"].as_str().is_some_and(is_hex64)
    {
        return Err("CONTENT_MANIFEST_IDENTITY_MISMATCH".into());
    }
    let entry = same_origin_path(&manifest["entrypoint"])?;
    let base = runtime_resource_base(entry, ctx.release_id)?;
    let files = manifest["files"]
        .as_array()
        .filter(|f| !f.is_empty() && f.len() <= SHELL_MAX_FILES);
    let files = files.ok_or("CONTENT_FILE_LIMIT")?;
    let mut resources = Vec::with_capacity(files.len());
    let mut paths = BTreeSet::new();
    let mut total = 0u64;
    for file in files {
        let path = safe_path_value(&file["path"])?;
        let digest = file["sha256"].as_str().filter(|d| is_hex64(d));
        let length = safe_uint(&file["byte_length"]).filter(|n| *n <= SHELL_MAX_RESOURCE_BYTES);
        let (Some(digest), Some(length)) = (digest, length) else {
            return Err("CONTENT_RESOURCE_INVALID".into());
        };
        if paths.contains(path) {
            return Err("CONTENT_RESOURCE_INVALID".into());
        }
        if !file["media_type"].as_str().is_some_and(valid_media_type) {
            return Err("CONTENT_MIME_INVALID".into());
        }
        paths.insert(path);
        total += length;
        resources.push((path, digest, length));
    }
    let entry_relative = &entry[base.len()..];
    if total > SHELL_MAX_TOTAL_BYTES || !paths.contains(entry_relative) {
        return Err("CONTENT_TOTAL_OR_ENTRY_INVALID".into());
    }
    if let Some(commitment) = manifest.get("content_commitment") {
        let descriptor_ok = commitment.as_object().is_some_and(|object| {
            object.keys().map(String::as_str).collect::<Vec<_>>()
                == ["adapter_id", "artifact_root", "manifest_path", "schema"]
        }) && commitment["schema"] == "KTAPEOUT-RUNTIME-CONTENT-COMMITMENT-V1"
            && matches!(
                commitment["adapter_id"].as_str(),
                Some(ROOT_SCHEME | ONCHAIN_ADAPTER)
            )
            && commitment["artifact_root"].as_str().is_some_and(is_hex64);
        if !descriptor_ok {
            return Err("CONTENT_COMMITMENT_DESCRIPTOR_INVALID".into());
        }
        if !commitment["adapter_id"]
            .as_str()
            .is_some_and(|id| allowed.contains(&id))
        {
            return Err("CONTENT_COMMITMENT_ADAPTER_UNAUTHORIZED".into());
        }
        if !paths.contains(safe_path_value(&commitment["manifest_path"])?) {
            return Err("CONTENT_COMMITMENT_MANIFEST_MISSING".into());
        }
    }
    Ok(ValidatedManifest {
        base: base.into(),
        entry: entry_relative.into(),
        total,
        resources,
    })
}

fn require_full_coverage(
    resources: &[(&str, &str, u64)],
    manifest_path: &str,
    covered: &BTreeSet<String>,
) -> Result<(), String> {
    if resources
        .iter()
        .any(|(path, _, _)| *path != manifest_path && !covered.contains(*path))
    {
        return Err("CONTENT_COMMITMENT_COVERAGE_INCOMPLETE".into());
    }
    Ok(())
}

fn manifest_directory(manifest_path: &str) -> &str {
    manifest_path
        .rfind('/')
        .map_or("", |i| &manifest_path[..=i])
}

fn verify_canonical_chunks(
    manifest: &Value,
    files: &Files,
    resources: &[(&str, &str, u64)],
) -> Result<Value, String> {
    let commitment = &manifest["content_commitment"];
    let manifest_path = commitment["manifest_path"].as_str().unwrap_or_default();
    let invalid = || "CONTENT_COMMITMENT_MANIFEST_INVALID".to_string();
    let source = files
        .get(manifest_path)
        .filter(|b| b.len() <= CANONICAL_MANIFEST_MAX_BYTES)
        .ok_or_else(invalid)?;
    let declared: Value = serde_json::from_slice(source).map_err(|_| invalid())?;
    let schema_ok = declared["schema"]
        .as_str()
        .is_some_and(|s| (1..=128).contains(&s.encode_utf16().count()));
    let chunks = declared["chunks"]
        .as_array()
        .filter(|c| !c.is_empty() && c.len() <= SHELL_MAX_FILES);
    if !declared.is_object()
        || !schema_ok
        || declared["network"] != manifest["network"]
        || declared["root_scheme"] != ROOT_SCHEME
        || declared["content_root"] != commitment["artifact_root"]
        || chunks.is_none()
    {
        return Err(invalid());
    }
    if declared
        .get("release_id")
        .is_some_and(|id| *id != manifest["release_id"])
    {
        return Err("CONTENT_COMMITMENT_RELEASE_MISMATCH".into());
    }
    let directory = manifest_directory(manifest_path);
    let by_path = resources
        .iter()
        .map(|(p, d, _)| (*p, *d))
        .collect::<BTreeMap<_, _>>();
    let mut seen = BTreeSet::new();
    let mut covered = BTreeSet::new();
    let mut leaves = Vec::new();
    for chunk in chunks.into_iter().flatten() {
        let path = chunk.get("path").and_then(Value::as_str);
        let digest = chunk
            .get("sha256")
            .and_then(Value::as_str)
            .filter(|d| is_hex64(d));
        let (Some(path), Some(digest)) = (path, digest) else {
            return Err("CONTENT_COMMITMENT_CHUNK_INVALID".into());
        };
        safe_path(path)?;
        if !seen.insert(path) {
            return Err("CONTENT_COMMITMENT_CHUNK_INVALID".into());
        }
        let resource_path = format!("{directory}{path}");
        safe_path(&resource_path)?;
        if by_path.get(resource_path.as_str()) != Some(&digest) {
            return Err("CONTENT_COMMITMENT_CHUNK_MISMATCH".into());
        }
        covered.insert(resource_path);
        leaves.push((path, digest));
    }
    let root = canonical_chunks_root(leaves);
    if commitment["artifact_root"] != root {
        return Err("CONTENT_COMMITMENT_ROOT_MISMATCH".into());
    }
    require_full_coverage(resources, manifest_path, &covered)?;
    Ok(json!({"status": "VERIFIED", "artifact_root": root, "adapter_id": ROOT_SCHEME}))
}

fn verify_onchain_content(
    manifest: &Value,
    files: &Files,
    resources: &[(&str, &str, u64)],
) -> Result<Value, String> {
    let commitment = &manifest["content_commitment"];
    let manifest_path = commitment["manifest_path"].as_str().unwrap_or_default();
    let invalid = || "CONTENT_COMMITMENT_MANIFEST_INVALID".to_string();
    let source = files
        .get(manifest_path)
        .filter(|b| b.len() <= ONCHAIN_ARTIFACT_MAX_BYTES)
        .ok_or_else(invalid)?;
    let declared: Value = serde_json::from_slice(source).map_err(|_| invalid())?;
    ktapeout_core::verify_content_artifact_050(source).map_err(|_| invalid())?;
    if declared["artifact_sha256"] != commitment["artifact_root"] {
        return Err("CONTENT_COMMITMENT_ROOT_MISMATCH".into());
    }
    let directory = manifest_directory(manifest_path);
    let release_id = manifest["release_id"].as_str().unwrap_or_default();
    let entrypoint = manifest["entrypoint"].as_str().unwrap_or_default();
    let manifest_entry = match entrypoint.find(release_id) {
        Some(at) if !release_id.is_empty() => entrypoint
            .get(at + release_id.len() + 1..)
            .unwrap_or_default(),
        _ => entrypoint.trim_start_matches('/'),
    };
    if format!(
        "{directory}{}",
        declared["entrypoint"].as_str().ok_or_else(invalid)?
    ) != manifest_entry
    {
        return Err(invalid());
    }
    let by_path = resources
        .iter()
        .map(|(p, d, n)| (*p, (*d, *n)))
        .collect::<BTreeMap<_, _>>();
    let mut covered = BTreeSet::new();
    for file in declared["files"].as_array().ok_or_else(invalid)? {
        let resource_path = format!("{directory}{}", file["path"].as_str().ok_or_else(invalid)?);
        let matches = by_path
            .get(resource_path.as_str())
            .is_some_and(|(digest, length)| {
                file["sha256"] == *digest && safe_uint(&file["size"]) == Some(*length)
            });
        if !matches {
            return Err("CONTENT_COMMITMENT_CHUNK_MISMATCH".into());
        }
        covered.insert(resource_path);
    }
    require_full_coverage(resources, manifest_path, &covered)?;
    Ok(
        json!({"status": "VERIFIED", "artifact_root": declared["artifact_sha256"], "adapter_id": ONCHAIN_ADAPTER}),
    )
}

/// The Shell's `prepareRuntime` over local bytes: manifest validation, then every declared file's bytes in declared
/// order, then the content commitment. `files` maps resource paths (relative to the release base) to bytes.
pub fn verify_runtime(
    manifest: &Value,
    files: &Files,
    ctx: &RuntimeContext,
    allowed: &[&str],
) -> Result<Value, String> {
    verify_runtime_with(manifest, ctx, allowed, &mut |_, path| {
        Ok(files.get(path).cloned())
    })
}

type RuntimeFetch<'a> = dyn FnMut(&str, &str) -> Result<Option<Vec<u8>>, String> + 'a;

/// `verify_runtime` with the Shell's fetch replaced by `fetch(base, path)`; `Ok(None)` is a missing resource and an
/// error aborts verification as a failed fetch would.
pub fn verify_runtime_with(
    manifest: &Value,
    ctx: &RuntimeContext,
    allowed: &[&str],
    fetch: &mut RuntimeFetch<'_>,
) -> Result<Value, String> {
    let validated = validate_manifest(manifest, ctx, allowed)?;
    if manifest["schema"] == LOCATOR_MANIFEST {
        return Err("CONTENT_L1_READER_REQUIRED".into());
    }
    let mut files = Files::new();
    for (path, digest, length) in &validated.resources {
        let bytes = fetch(&validated.base, path)?.ok_or("CONTENT_FETCH_UNAVAILABLE")?;
        if bytes.len() as u64 > *length {
            return Err("CONTENT_RESPONSE_TOO_LARGE".into());
        }
        if bytes.len() as u64 != *length || sha256(&bytes) != *digest {
            return Err("CONTENT_BYTES_MISMATCH".into());
        }
        files.insert(path.to_string(), bytes);
    }
    let commitment = match manifest["content_commitment"]["adapter_id"].as_str() {
        None => json!({"status": "NOT_DECLARED", "artifact_root": null}),
        Some(ROOT_SCHEME) => verify_canonical_chunks(manifest, &files, &validated.resources)?,
        Some(ONCHAIN_ADAPTER) => verify_onchain_content(manifest, &files, &validated.resources)?,
        Some(_) => return Err("CONTENT_COMMITMENT_DESCRIPTOR_INVALID".into()),
    };
    Ok(json!({
        "entry": validated.entry, "files": validated.resources.len(), "bytes": validated.total,
        "runtime_integrity": "DECLARED_MANIFEST_BYTES_VERIFIED", "content_commitment": commitment,
    }))
}

/// `localeCompare` under Node's ICU root collation, for the characters it is implemented for: `_ - . /` sort before
/// digits, digits before letters, letters compare case-insensitively first and lowercase first on a tie. `None` for any
/// other character, so callers refuse rather than guess an order.
pub fn locale_compare(a: &str, b: &str) -> Option<std::cmp::Ordering> {
    let primary = |c: char| -> Option<u32> {
        Some(match c {
            '_' => 0,
            '-' => 1,
            '.' => 2,
            '/' => 3,
            '0'..='9' => 10 + c as u32 - '0' as u32,
            'a'..='z' => 30 + c as u32 - 'a' as u32,
            'A'..='Z' => 30 + c as u32 - 'A' as u32,
            _ => return None,
        })
    };
    let keys = |s: &str| {
        s.chars()
            .map(|c| primary(c).map(|p| (p, c.is_ascii_uppercase())))
            .collect::<Option<Vec<_>>>()
    };
    let (a, b) = (keys(a)?, keys(b)?);
    let first = a.iter().map(|k| k.0).cmp(b.iter().map(|k| k.0));
    Some(first.then_with(|| a.iter().map(|k| k.1).cmp(b.iter().map(|k| k.1))))
}

/// The Shell runtime pin (`runtimePin` in publisher-authorization.mjs): SHA-256 of `JSON.stringify(runtimeIdentity(...))`
/// for a route served on `origin`, under the default adapter policy.
pub fn runtime_pin(manifest: &Value, route: &Value, origin: &str) -> Result<String, String> {
    if !origin.starts_with("https://") || !is_origin(origin) {
        return Err("PUBLISHER_ORIGIN_INVALID".into());
    }
    let hex = |key: &str| route[key].as_str().filter(|v| is_hex64(v));
    let (Some(application_id), Some(release_id)) = (hex("application_id"), hex("release_id"))
    else {
        return Err("PUBLISHER_IDENTITY_INVALID".into());
    };
    let network = route["network"].as_str().unwrap_or_default();
    let application_uri = route["application_uri"].as_str().unwrap_or_default();
    if manifest["network"] != route["network"]
        || manifest["release_id"] != release_id
        || manifest["application_uri"] != format!("ktape://{network}/app/{application_uri}")
    {
        return Err("PUBLISHER_MANIFEST_MISMATCH".into());
    }
    let ctx = RuntimeContext {
        network,
        application_uri,
        release_id,
    };
    let validated = validate_manifest(manifest, &ctx, &[ROOT_SCHEME])?;
    let mut files = manifest["files"].as_array().cloned().unwrap_or_default();
    let path = |f: &Value| f["path"].as_str().unwrap_or_default().to_string();
    for (a, b) in files.iter().zip(files.iter().skip(1)) {
        locale_compare(&path(a), &path(b)).ok_or("RUNTIME_PIN_PATH_ORDER_UNSUPPORTED")?;
    }
    files.sort_by(|a, b| locale_compare(&path(a), &path(b)).unwrap_or(std::cmp::Ordering::Equal));
    let field = |v: &Value| serde_json::to_string(v).expect("JSON value encodes");
    let rows = files
        .iter()
        .map(|f| {
            format!(
                "{{\"path\":{},\"sha256\":{},\"byte_length\":{},\"media_type\":{}}}",
                field(&f["path"]),
                field(&f["sha256"]),
                field(&f["byte_length"]),
                field(&f["media_type"])
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let mut identity = format!(
        "{{\"network\":{},\"application_uri\":{},\"release_id\":{},\"package_digest\":{},\"entry\":{},\"files\":[{rows}]",
        field(&manifest["network"]),
        field(&manifest["application_uri"]),
        field(&manifest["release_id"]),
        field(&manifest["package_digest"]),
        js_string(&validated.entry)
    );
    if let Some(c) = manifest.get("content_commitment") {
        identity += &format!(
            ",\"content_commitment\":{{\"schema\":{},\"adapter_id\":{},\"artifact_root\":{},\"manifest_path\":{}}}",
            field(&c["schema"]),
            field(&c["adapter_id"]),
            field(&c["artifact_root"]),
            field(&c["manifest_path"])
        );
    }
    identity += &format!(
        ",\"application_id\":{},\"embedder_origin\":{}",
        js_string(application_id),
        js_string(origin)
    );
    if let Some(hashes) = route.get("inline_script_hashes") {
        let hashes = hashes
            .as_array()
            .filter(|h| h.len() <= 32)
            .ok_or("CONTENT_SCRIPT_POLICY_INVALID")?;
        let hashes = hashes
            .iter()
            .map(|h| h.as_str().filter(|v| is_hex64(v)))
            .collect::<Option<BTreeSet<_>>>();
        let hashes = hashes.ok_or("CONTENT_SCRIPT_POLICY_INVALID")?;
        identity += &format!(
            ",\"inline_script_hashes\":{}",
            serde_json::to_string(&hashes).expect("strings encode")
        );
    }
    identity.push('}');
    Ok(sha256(identity.as_bytes()))
}

/// `new URL(value).origin === value` for http(s): lowercase host, no path, no default port.
pub fn is_origin(value: &str) -> bool {
    let Some((scheme, rest)) = value.split_once("://") else {
        return false;
    };
    let default_port = match scheme {
        "https" => "443",
        "http" => "80",
        _ => return false,
    };
    let (host, port) = rest
        .rsplit_once(':')
        .map_or((rest, None), |(h, p)| (h, Some(p)));
    let host_ok = !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
        && !host.starts_with('.')
        && !host.ends_with('.');
    let port_ok = port.is_none_or(|p| {
        !p.is_empty()
            && p.bytes().all(|b| b.is_ascii_digit())
            && !p.starts_with('0')
            && p != default_port
            && p.parse::<u16>().is_ok()
    });
    host_ok && port_ok
}

// ---------------------------------------------------------------------------------------------------------------------
// Local release directories
// ---------------------------------------------------------------------------------------------------------------------

fn walk(root: &Path, dir: &Path, files: &mut Files, total: &mut u64) -> Result<(), String> {
    let mut entries = fs::read_dir(dir)
        .map_err(|_| "RELEASE_VERIFY_DIRECTORY_UNAVAILABLE")?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "RELEASE_VERIFY_DIRECTORY_UNAVAILABLE")?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let kind = entry
            .file_type()
            .map_err(|_| "RELEASE_VERIFY_DIRECTORY_UNAVAILABLE")?;
        let relative = path
            .strip_prefix(root)
            .ok()
            .and_then(|p| p.to_str())
            .map(|p| p.replace('\\', "/"))
            .ok_or("RELEASE_VERIFY_PATH_INVALID")?;
        if kind.is_symlink() {
            return Err(format!("RELEASE_VERIFY_SYMLINK_FORBIDDEN:{relative}"));
        }
        if kind.is_dir() {
            walk(root, &path, files, total)?;
            continue;
        }
        let bytes =
            fs::read(&path).map_err(|_| format!("RELEASE_VERIFY_FILE_UNAVAILABLE:{relative}"))?;
        *total += bytes.len() as u64;
        if files.len() >= TREE_MAX_FILES || *total > TREE_MAX_BYTES {
            return Err("RELEASE_VERIFY_TREE_TOO_LARGE".into());
        }
        files.insert(relative, bytes);
    }
    Ok(())
}

/// Every regular file under `root`, keyed by `/`-separated relative path. Symlinks are refused.
pub fn read_tree(root: &Path) -> Result<Files, String> {
    if fs::symlink_metadata(root)
        .map_err(|_| "RELEASE_VERIFY_DIRECTORY_UNAVAILABLE")?
        .file_type()
        .is_symlink()
    {
        return Err("RELEASE_VERIFY_SYMLINK_FORBIDDEN:.".into());
    }
    let mut files = Files::new();
    walk(root, root, &mut files, &mut 0)?;
    Ok(files)
}

/// What `ktape release verify` checks beyond the bytes themselves.
pub struct VerifyPolicy<'a> {
    pub network: &'a str,
    pub application_uri: Option<&'a str>,
    pub release_id: Option<&'a str>,
    pub commitment: Option<&'a str>,
    pub schema: Option<&'a str>,
    pub release_file: Option<&'a str>,
    pub optional_fetch_targets: BTreeSet<String>,
    pub strict_references: bool,
}

/// Reference closure. The scan is lexical (it cannot see import maps or tell code from minified text), so unresolved
/// targets are reported, and refuse the release only under `strict_references`.
fn reference_report(files: &Files, policy: &VerifyPolicy) -> Result<Value, String> {
    let unresolved = unresolved_references(files, &policy.optional_fetch_targets);
    if let (true, Some((target, referrers))) = (policy.strict_references, unresolved.first()) {
        return Err(format!(
            "RELEASE_CLOSURE_REJECTED:UNRESOLVED_REFERENCE {target} <- {}",
            referrers.join(",")
        ));
    }
    Ok(json!({
        "status": if unresolved.is_empty() { "COMPLETE" } else { "UNRESOLVED_WARNING" },
        "optional_fetch_targets": policy.optional_fetch_targets,
        "unresolved": unresolved.iter().map(|(target, referrers)| json!({"target": target, "referrers": referrers})).collect::<Vec<_>>(),
    }))
}

/// Verify a local release directory. A directory with `runtime-manifest.json` is checked exactly as the Shell loads it
/// (bound to `--application-uri`/`--release-id`), then as a publisher closure under the declared commitment. Any other
/// directory is checked as a publisher closure under `--commitment`, `--schema` and one identity source.
pub fn verify_directory(dir: &Path, policy: &VerifyPolicy) -> Result<Value, String> {
    let mut files = read_tree(dir)?;
    let manifest_bytes = files.remove("runtime-manifest.json");
    files.remove("content-locator.json");
    let Some(manifest_bytes) = manifest_bytes else {
        return verify_closure_directory(&files, policy);
    };

    let (Some(application_uri), Some(release_id)) = (policy.application_uri, policy.release_id)
    else {
        return Err("RELEASE_VERIFY_RUNTIME_BINDING_REQUIRED".into());
    };
    let manifest: Value =
        serde_json::from_slice(&manifest_bytes).map_err(|_| "CONTENT_MANIFEST_INVALID")?;
    let ctx = RuntimeContext {
        network: policy.network,
        application_uri,
        release_id,
    };
    let shell = verify_runtime(&manifest, &files, &ctx, &[ROOT_SCHEME, ONCHAIN_ADAPTER])?;
    let commitment = &manifest["content_commitment"];
    let commitment_path = commitment["manifest_path"]
        .as_str()
        .ok_or("RELEASE_VERIFY_COMMITMENT_REQUIRED")?;
    if commitment_path.contains('/') {
        return Err("RELEASE_VERIFY_NESTED_COMMITMENT_UNSUPPORTED".into());
    }
    let closure = if commitment["adapter_id"] == ONCHAIN_ADAPTER {
        let artifact: Value = serde_json::from_slice(&files[commitment_path])
            .map_err(|_| "CONTENT_COMMITMENT_MANIFEST_INVALID")?;
        let mut failures = onchain_artifact_coverage_failures(&files, &artifact, commitment_path);
        failures.extend(identity_leak_failures(
            &files,
            commitment_path,
            &[release_id],
        ));
        if let Some(first) = failures.first() {
            return Err(format!("RELEASE_CLOSURE_REJECTED:{first}"));
        }
        json!({"release_id": release_id, "content_root": artifact["artifact_sha256"], "identity_derivation": "EXTERNAL"})
    } else {
        let anchor: Value = serde_json::from_slice(&files[commitment_path])
            .map_err(|_| "CONTENT_COMMITMENT_MANIFEST_INVALID")?;
        let schema = policy
            .schema
            .or(anchor["schema"].as_str())
            .unwrap_or_default();
        let identity = policy
            .release_file
            .map_or(Identity::External(release_id), Identity::ReleaseFile);
        let closure = verify_canonical_release_closure(
            &files,
            commitment_path,
            policy.network,
            schema,
            &identity,
        )?;
        if closure["release_id"] != release_id {
            return Err("RELEASE_CLOSURE_REJECTED:RELEASE_ID_MISMATCH".into());
        }
        closure
    };
    let references = reference_report(&files, policy)?;
    Ok(json!({
        "schema": "KTAPEOUT-RELEASE-VERIFY-V1", "status": "VERIFIED", "mode": "RUNTIME",
        "network": policy.network, "application_uri": application_uri, "release_id": release_id,
        "content_root": closure["content_root"], "identity_derivation": closure["identity_derivation"],
        "commitment_path": commitment_path, "manifest_sha256": sha256(&manifest_bytes), "shell": shell, "closure": closure, "references": references,
        "scope": "Local bytes checked under the public Shell and publisher closure rules; does not read L1, the name binding or the host.",
        "signing_allowed": false, "broadcast": false,
    }))
}

fn verify_closure_directory(files: &Files, policy: &VerifyPolicy) -> Result<Value, String> {
    let commitment_path = policy
        .commitment
        .ok_or("RELEASE_VERIFY_COMMITMENT_REQUIRED")?;
    let schema = policy.schema.ok_or("RELEASE_VERIFY_SCHEMA_REQUIRED")?;
    let identity = match (policy.release_file, policy.release_id) {
        (Some(file), None) => Identity::ReleaseFile(file),
        (None, Some(id)) => Identity::External(id),
        _ => return Err("RELEASE_CLOSURE_REJECTED:IDENTITY_POLICY_INVALID".into()),
    };
    let closure = verify_canonical_release_closure(
        files,
        commitment_path,
        policy.network,
        schema,
        &identity,
    )?;
    let references = reference_report(files, policy)?;
    Ok(json!({
        "schema": "KTAPEOUT-RELEASE-VERIFY-V1", "status": "VERIFIED", "mode": "CLOSURE",
        "network": policy.network, "release_id": closure["release_id"], "content_root": closure["content_root"],
        "identity_derivation": closure["identity_derivation"], "commitment_path": commitment_path,
        "files": files.len(), "closure": closure, "references": references,
        "scope": "Local bytes checked under the publisher closure rules; does not read L1, the name binding or the host.",
        "signing_allowed": false, "broadcast": false,
    }))
}
