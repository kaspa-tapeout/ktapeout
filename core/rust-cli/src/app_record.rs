//! Application record: the small, content-addressed JSON object that carries a
//! name's plaintext, its target tuple and a publisher-claimed listing card.
//!
//! Offline checks only. A record that passes here is self-consistent
//! (`RECORD_SELF_CONSISTENT`); binding to the live Deed and to artifact bytes
//! is verified separately by the resolver and the content verifier.

use crate::{application_name_key_value, compact_target_commitment, hex_string};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ktapeout_runtime::{canonical_json, parse_strict_json};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

pub const RECORD_SCHEMA: &str = "KTAPEOUT-APPLICATION-RECORD-V1";
pub const REPORT_SCHEMA: &str = "KTAPEOUT-APPLICATION-RECORD-REPORT-V1";
pub const SHARE_PREFIX: &str = "ktape-record=";
const DIGEST_DOMAIN: &[u8] = b"KTAPEOUT/0.5.0/APPLICATION_RECORD/V1";
const MAX_RECORD_BYTES: usize = 8 * 1024;
const MAX_LOCATORS: usize = 8;
const MAX_LOCATOR_LEN: usize = 512;
const MAX_CATEGORIES: usize = 4;
const MAX_TOTAL_IMAGE_BYTES: u64 = 96 * 1024;
const FIELDS: [&str; 10] = [
    "schema",
    "network",
    "canonical_uri",
    "name_key",
    "target",
    "target_commitment",
    "runtime_kind",
    "card",
    "locators",
    "critical",
];
const OPTIONAL_FIELDS: [&str; 4] = [
    "extensions",
    "runtime",
    "deed_evidence",
    "release_authorization",
];
const MAX_RUNTIME_MANIFEST_BYTES: u64 = 1024 * 1024;
const TARGET_FIELDS: [&str; 4] = [
    "application_id",
    "release_id",
    "deployment_id",
    "artifact_root",
];
const MEDIA_FIELDS: [&str; 6] = [
    "sha256",
    "byte_length",
    "media_type",
    "width",
    "height",
    "locators",
];

fn exact_keys(object: &Map<String, Value>, expected: &[&str]) -> bool {
    object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key))
}

fn is_hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn text<'a>(object: &'a Map<String, Value>, key: &str, code: &str) -> Result<&'a str, String> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| code.to_owned())
}

fn is_extension_key(key: &str) -> bool {
    let mut labels = key.split('.');
    let well_formed = |label: &str| {
        !label.is_empty()
            && label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    };
    labels.next().is_some_and(well_formed) && key.contains('.') && key.split('.').all(well_formed)
}

/// https (no credentials), ipfs and ar locators only; a locator is a hint, never an authority.
fn validate_locator(locator: &Value) -> Result<(), String> {
    let text = locator.as_str().ok_or("RECORD_LOCATOR_INVALID")?;
    let well_formed = !text.is_empty()
        && text.len() <= MAX_LOCATOR_LEN
        && text.bytes().all(|byte| byte.is_ascii_graphic());
    if !well_formed {
        return Err("RECORD_LOCATOR_INVALID".into());
    }
    if let Some(rest) = text.strip_prefix("https://") {
        let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
        if authority.is_empty() || authority.contains('@') {
            return Err("RECORD_LOCATOR_INVALID".into());
        }
        return Ok(());
    }
    let bare = text
        .strip_prefix("ipfs://")
        .or_else(|| text.strip_prefix("ar://"));
    if bare.is_some_and(|rest| !rest.is_empty()) {
        return Ok(());
    }
    Err("RECORD_LOCATOR_SCHEME_UNSUPPORTED".into())
}

fn validate_locators(value: &Value, code: &str) -> Result<(), String> {
    let list = value.as_array().ok_or_else(|| code.to_owned())?;
    if list.is_empty() || list.len() > MAX_LOCATORS {
        return Err(code.to_owned());
    }
    list.iter().try_for_each(validate_locator)
}

fn validate_media(role: &str, media: &Value, total: &mut u64) -> Result<(), String> {
    let invalid = || format!("RECORD_MEDIA_INVALID:{role}");
    let object = media
        .as_object()
        .filter(|o| exact_keys(o, &MEDIA_FIELDS))
        .ok_or_else(invalid)?;
    let (max_bytes, max_width, max_height) = match role {
        "icon" => (32 * 1024, 256, 256),
        "card" => (64 * 1024, 768, 432),
        _ => return Err(invalid()),
    };
    if !matches!(
        text(object, "media_type", "")?,
        "image/png" | "image/webp" | "image/jpeg"
    ) {
        return Err(invalid());
    }
    if !is_hex64(text(object, "sha256", "")?) {
        return Err(invalid());
    }
    let dimension = |key: &str, limit: u64| {
        object
            .get(key)
            .and_then(Value::as_u64)
            .filter(|v| (1..=limit).contains(v))
            .ok_or_else(invalid)
    };
    dimension("width", max_width)?;
    dimension("height", max_height)?;
    *total += dimension("byte_length", max_bytes)?;
    validate_locators(&object["locators"], &invalid())
}

fn validate_card(card: &Value) -> Result<(), String> {
    let object = card.as_object().ok_or("RECORD_CARD_INVALID")?;
    if !exact_keys(object, &["title", "summary", "categories", "media"]) {
        return Err("RECORD_CARD_FIELDS_INVALID".into());
    }
    let clean = |key: &str, max: usize| {
        let value = text(object, key, "RECORD_CARD_INVALID")?;
        let count = value.chars().count();
        if count == 0 || count > max || value.chars().any(char::is_control) {
            return Err("RECORD_CARD_INVALID".to_owned());
        }
        Ok(())
    };
    clean("title", 64)?;
    clean("summary", 120)?;
    let categories = object["categories"]
        .as_array()
        .ok_or("RECORD_CARD_INVALID")?;
    let category_ok = |value: &Value| {
        value.as_str().is_some_and(|c| {
            (1..=24).contains(&c.len())
                && c.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
                && c.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
    };
    if categories.len() > MAX_CATEGORIES || !categories.iter().all(category_ok) {
        return Err("RECORD_CARD_INVALID".into());
    }
    let media = object["media"].as_object().ok_or("RECORD_CARD_INVALID")?;
    let mut total = 0;
    for (role, entry) in media {
        validate_media(role, entry, &mut total)?;
    }
    if total > MAX_TOTAL_IMAGE_BYTES {
        return Err("RECORD_MEDIA_TOTAL_LIMIT_EXCEEDED".into());
    }
    Ok(())
}

fn validate_extensions(record: &Map<String, Value>) -> Result<(), String> {
    let extensions = match record.get("extensions") {
        None => Map::new(),
        Some(value) => value
            .as_object()
            .cloned()
            .ok_or("RECORD_EXTENSIONS_INVALID")?,
    };
    if !extensions.keys().all(|key| is_extension_key(key)) {
        return Err("RECORD_EXTENSIONS_INVALID".into());
    }
    let critical = record["critical"]
        .as_array()
        .ok_or("RECORD_CRITICAL_INVALID")?;
    let listed = critical
        .iter()
        .map(|k| k.as_str().filter(|k| extensions.contains_key(*k)));
    if listed.clone().any(|key| key.is_none()) {
        return Err("RECORD_CRITICAL_INVALID".into());
    }
    // This reader understands no extension, so any critical one must be refused.
    if !critical.is_empty() {
        return Err("RECORD_CRITICAL_UNSUPPORTED".into());
    }
    Ok(())
}

/// `runtime` names the digest-addressed runtime manifest a Shell fetches from the mirrors.
fn validate_runtime(record: &Map<String, Value>) -> Result<(), String> {
    let Some(runtime) = record.get("runtime") else {
        return Ok(());
    };
    let object = runtime
        .as_object()
        .filter(|o| exact_keys(o, &["manifest_sha256", "manifest_byte_length"]))
        .ok_or("RECORD_RUNTIME_INVALID")?;
    let length_ok = object["manifest_byte_length"]
        .as_u64()
        .is_some_and(|n| (1..=MAX_RUNTIME_MANIFEST_BYTES).contains(&n));
    if !is_hex64(text(object, "manifest_sha256", "RECORD_RUNTIME_INVALID")?) || !length_ok {
        return Err("RECORD_RUNTIME_INVALID".into());
    }
    Ok(())
}

/// The publisher-signed runtime authorization the Host policy verifies. Here it is only bounded; it is never trusted.
fn validate_release_authorization(record: &Map<String, Value>) -> Result<(), String> {
    let Some(authorization) = record.get("release_authorization") else {
        return Ok(());
    };
    let object = authorization
        .as_object()
        .filter(|o| (1..=16).contains(&o.len()))
        .ok_or("RECORD_RELEASE_AUTHORIZATION_INVALID")?;
    let size = crate::release_closure::canonical_json(&Value::Object(object.clone()))?.len();
    if size > 8192 {
        return Err("RECORD_RELEASE_AUTHORIZATION_INVALID".into());
    }
    Ok(())
}

/// `deed_evidence` is a state-bearing resolution entry. It stays untrusted input for the live
/// dual-RPC verifier; here it must only agree with the record it travels in.
fn validate_deed_evidence(
    record: &Map<String, Value>,
    uri: &str,
    name_key: &str,
    commitment: &str,
) -> Result<(), String> {
    let Some(evidence) = record.get("deed_evidence") else {
        return Ok(());
    };
    let object = evidence.as_object().ok_or("RECORD_DEED_EVIDENCE_INVALID")?;
    let target = record["target"]
        .as_object()
        .ok_or("RECORD_TARGET_INVALID")?;
    let path = uri.splitn(4, '/').nth(3).unwrap_or("");
    let path = path.strip_prefix("app/").unwrap_or(path);
    let agrees = |key: &str, want: &str| object.get(key).and_then(Value::as_str) == Some(want);
    let consistent = agrees("name_key", name_key)
        && agrees("target_commitment", commitment)
        && agrees("network", record["network"].as_str().unwrap_or(""))
        && agrees("application_uri", path)
        && TARGET_FIELDS
            .iter()
            .all(|k| agrees(k, target[*k].as_str().unwrap_or("")))
        && object.get("successor").is_some_and(Value::is_object);
    if consistent {
        Ok(())
    } else {
        Err("RECORD_DEED_EVIDENCE_MISMATCH".into())
    }
}

/// Split `ktape://<network>/app/<namespace>/<slug>` strictly; the name-key helper
/// then enforces canonical form.
/// Name key of a `ktape.official.adapter.registry` application name, the key stored in the Deed state (`state[5]`):
/// `SHA-256("KTAPEOUT/0.5.0/NAME_FRAME/V1" 00 0a || frame(namespace) || frame(slug))`, a frame being the length byte, the ASCII
/// text and zero padding to 64 bytes. The retired CompactV1 family used a different (BLAKE3) key; records for current names
/// must carry this one or they can never match the chain. TN10 only: the mainnet key domain is not admitted.
pub fn registry_adapter_name_key(
    network: &str,
    namespace: &str,
    slug: &str,
) -> Result<String, String> {
    // Shared canonical-URI and character-set validation; its (Compact) key value is deliberately unused.
    application_name_key_value(network, namespace, slug)?;
    if network != "testnet-10" {
        return Err("NETWORK_INVALID".into());
    }
    let frame = |text: &str| -> Result<[u8; 64], String> {
        let raw = text.as_bytes();
        if raw.is_empty() || raw.len() > 63 || !raw.is_ascii() {
            return Err("NAME_URI_NOT_CANONICAL".into());
        }
        let mut out = [0u8; 64];
        out[0] = raw.len() as u8;
        out[1..=raw.len()].copy_from_slice(raw);
        Ok(out)
    };
    let mut input = b"KTAPEOUT/0.5.0/NAME_FRAME/V1\0\x0a".to_vec();
    input.extend_from_slice(&frame(namespace)?);
    input.extend_from_slice(&frame(slug)?);
    Ok(crate::release_closure::sha256(&input))
}

fn uri_parts(uri: &str) -> Result<(&str, &str, &str), String> {
    let rest = uri.strip_prefix("ktape://").ok_or("RECORD_URI_INVALID")?;
    match rest.split('/').collect::<Vec<_>>()[..] {
        [network, "app", namespace, slug] => Ok((network, namespace, slug)),
        _ => Err("RECORD_URI_INVALID".into()),
    }
}

pub fn record_digest(record: &Value) -> Result<String, String> {
    let bytes = canonical_json(record)?;
    let mut hasher = Sha256::new();
    hasher.update(DIGEST_DOMAIN);
    hasher.update(&bytes);
    Ok(hex_string(&hasher.finalize()))
}

/// Offline self-consistency check; never claims L1 or content verification.
pub fn verify_record(record: &Value) -> Result<Value, String> {
    let object = record.as_object().ok_or("RECORD_INVALID")?;
    let known = object
        .keys()
        .all(|k| FIELDS.contains(&k.as_str()) || OPTIONAL_FIELDS.contains(&k.as_str()));
    if !known || !FIELDS.iter().all(|field| object.contains_key(*field)) {
        return Err("RECORD_FIELDS_INVALID".into());
    }
    if canonical_json(record)?.len() > MAX_RECORD_BYTES {
        return Err("RECORD_TOO_LARGE".into());
    }
    if text(object, "schema", "RECORD_SCHEMA_INVALID")? != RECORD_SCHEMA {
        return Err("RECORD_SCHEMA_INVALID".into());
    }
    let uri = text(object, "canonical_uri", "RECORD_URI_INVALID")?;
    let (network, namespace, slug) = uri_parts(uri)?;
    if text(object, "network", "RECORD_NETWORK_INVALID")? != network {
        return Err("RECORD_NETWORK_INVALID".into());
    }
    let name_key = registry_adapter_name_key(network, namespace, slug)?;
    if text(object, "name_key", "RECORD_NAME_KEY_MISMATCH")? != name_key {
        return Err("RECORD_NAME_KEY_MISMATCH".into());
    }
    let target = object["target"]
        .as_object()
        .filter(|t| exact_keys(t, &TARGET_FIELDS));
    let target = target.ok_or("RECORD_TARGET_INVALID")?;
    let part = |key: &str| text(target, key, "RECORD_TARGET_INVALID");
    let commitment = compact_target_commitment(
        part("application_id")?,
        part("release_id")?,
        part("deployment_id")?,
        part("artifact_root")?,
    )
    .map_err(|_| "RECORD_TARGET_INVALID".to_owned())?;
    if text(
        object,
        "target_commitment",
        "RECORD_TARGET_COMMITMENT_MISMATCH",
    )? != commitment
    {
        return Err("RECORD_TARGET_COMMITMENT_MISMATCH".into());
    }
    let kind = text(object, "runtime_kind", "RECORD_RUNTIME_KIND_INVALID")?;
    let kind_ok = kind.len() <= 32
        && kind.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
        && kind
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if !kind_ok {
        return Err("RECORD_RUNTIME_KIND_INVALID".into());
    }
    validate_card(&object["card"])?;
    validate_locators(&object["locators"], "RECORD_LOCATORS_INVALID")?;
    validate_extensions(object)?;
    validate_runtime(object)?;
    validate_deed_evidence(object, uri, &name_key, &commitment)?;
    validate_release_authorization(object)?;
    Ok(json!({
        "schema": REPORT_SCHEMA,
        "verification_level": "RECORD_SELF_CONSISTENT",
        "record_digest": record_digest(record)?,
        "canonical_uri": uri,
        "name_key": name_key,
        "target_commitment": commitment,
        "runtime_kind": kind,
        "runtime_kind_known": matches!(kind, "web" | "runner" | "other"),
        // Only `web` runs inside the Shell; every other kind is shown, never executed there.
        "shell_runnable": kind == "web",
        "chain_verified": false,
        "content_verified": false,
    }))
}

/// Inputs for `build_record`; every field is explicit so a record never depends on ambient state.
pub struct RecordParts<'a> {
    pub network: &'a str,
    pub namespace: &'a str,
    pub slug: &'a str,
    pub application_id: &'a str,
    pub release_id: &'a str,
    pub deployment_id: &'a str,
    pub artifact_root: &'a str,
    pub runtime_kind: &'a str,
    pub card: Value,
    pub locators: Vec<String>,
    pub runtime: Option<Value>,
    pub deed_evidence: Option<Value>,
    pub release_authorization: Option<Value>,
}

/// Assemble a record from explicit parts and refuse to return anything that does not verify.
pub fn build_record(parts: RecordParts) -> Result<Value, String> {
    let name_key = registry_adapter_name_key(parts.network, parts.namespace, parts.slug)?;
    let target = json!({
        "application_id": parts.application_id,
        "release_id": parts.release_id,
        "deployment_id": parts.deployment_id,
        "artifact_root": parts.artifact_root,
    });
    let target_commitment = compact_target_commitment(
        parts.application_id,
        parts.release_id,
        parts.deployment_id,
        parts.artifact_root,
    )
    .map_err(|_| "RECORD_TARGET_INVALID".to_owned())?;
    let record = json!({
        "schema": RECORD_SCHEMA,
        "network": parts.network,
        "canonical_uri": format!("ktape://{}/app/{}/{}", parts.network, parts.namespace, parts.slug),
        "name_key": name_key,
        "target": target,
        "target_commitment": target_commitment,
        "runtime_kind": parts.runtime_kind,
        "card": parts.card,
        "locators": parts.locators,
        "critical": [],
    });
    let mut record = record;
    for (key, value) in [
        ("runtime", parts.runtime),
        ("deed_evidence", parts.deed_evidence),
        ("release_authorization", parts.release_authorization),
    ] {
        if let Some(value) = value {
            record[key] = value;
        }
    }
    verify_record(&record)?;
    Ok(record)
}

/// Encode canonical record bytes for a URL fragment (`#ktape-record=...`).
pub fn share_fragment(record: &Value) -> Result<String, String> {
    verify_record(record)?;
    Ok(format!(
        "{SHARE_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(canonical_json(record)?)
    ))
}

/// Decode a fragment (with or without the leading `#`) and verify the record it carries.
pub fn open_fragment(fragment: &str) -> Result<(Value, Value), String> {
    let payload = fragment
        .trim_start_matches('#')
        .strip_prefix(SHARE_PREFIX)
        .ok_or("RECORD_FRAGMENT_INVALID")?;
    if payload.len() > MAX_RECORD_BYTES * 2 {
        return Err("RECORD_TOO_LARGE".into());
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| "RECORD_FRAGMENT_INVALID")?;
    let record = parse_strict_json(&bytes)?;
    if canonical_json(&record)? != bytes {
        return Err("RECORD_NOT_CANONICAL".into());
    }
    let report = verify_record(&record)?;
    Ok((record, report))
}
