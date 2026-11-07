//! Drafting and verification for the publisher-signed runtime authorization carried by ApplicationRecordV1.
//!
//! This module implements the byte contract used by the browser runtime. It only verifies an
//! imported signature against an explicit Host trust entry; it never reads or creates a private
//! key and does not treat a record-provided public key as a trust root.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use serde_json::json;
use std::fs;
use std::path::Path;

pub(super) const SCHEMA: &str = "KTAPEOUT-RUNTIME-RELEASE-AUTHORIZATION-V1";
const DOMAIN: &[u8] = b"KTAPEOUT/0.5.0/RUNTIME_RELEASE_AUTHORIZATION/V1\0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpectedBinding<'a> {
    pub network: &'a str,
    pub application_id: &'a str,
    pub application_uri: &'a str,
    pub release_id: &'a str,
    pub runtime_pin: &'a str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedPublisher<'a> {
    pub publisher_id: &'a str,
    pub key_id: &'a str,
    pub algorithm: &'a str,
    pub status: &'a str,
    pub public_key_base64url: &'a str,
    pub networks: &'a [&'a str],
    pub application_ids: &'a [&'a str],
    pub permissions: &'a [&'a str],
    pub minimum_release_sequence: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Authorization {
    pub(super) schema: String,
    pub(super) protocol_semver: String,
    pub(super) network: String,
    pub(super) application_id: String,
    pub(super) application_uri: String,
    pub(super) release_id: String,
    pub(super) runtime_pin: String,
    pub(super) permissions: Vec<String>,
    pub(super) release_sequence: u64,
    pub(super) publisher_id: String,
    pub(super) key_id: String,
    #[serde(default)]
    pub(super) signature: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PublisherScope {
    schema: String,
    pub(super) publisher_id: String,
    pub(super) key_id: String,
    pub(super) application_id: String,
    pub(super) network: String,
    pub(super) permissions: Vec<String>,
    pub(super) minimum_release_sequence: u64,
    pub(super) public_key: String,
}

pub(super) fn err(code: &str) -> String {
    format!("RUNTIME_RELEASE_AUTHORIZATION_{code}")
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 128
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'.' | b'_' | b':' | b'-'))
}

fn valid_network(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 32
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

pub(super) fn signing_bytes(value: &Authorization) -> Result<Vec<u8>, String> {
    if value.schema != SCHEMA
        || value.protocol_semver != "0.5.0"
        || !valid_hash(&value.application_id)
        || !valid_hash(&value.release_id)
        || !valid_hash(&value.runtime_pin)
        || !valid_network(&value.network)
        || !valid_id(&value.publisher_id)
        || !valid_id(&value.key_id)
        || value.release_sequence == 0
        || value.permissions.len() > 32
        || value
            .permissions
            .iter()
            .any(|permission| !valid_id(permission))
        || value.permissions.windows(2).any(|pair| pair[0] >= pair[1])
        || !value
            .application_uri
            .starts_with(&format!("ktape://{}/app/", value.network))
        || !(1..=256).contains(&value.application_uri.len())
    {
        return Err(err("INVALID"));
    }

    let tuple = json!([
        &value.schema,
        &value.protocol_semver,
        &value.network,
        &value.application_id,
        &value.application_uri,
        &value.release_id,
        &value.runtime_pin,
        &value.permissions,
        value.release_sequence,
        &value.publisher_id,
        &value.key_id
    ]);
    let tuple = serde_json::to_vec(&tuple).map_err(|_| err("INVALID"))?;
    let mut bytes = Vec::with_capacity(DOMAIN.len() + tuple.len());
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(&tuple);
    Ok(bytes)
}

pub(super) fn read_regular_file(
    path: &Path,
    max_bytes: u64,
    code: &str,
) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path).map_err(|_| err(code))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > max_bytes {
        return Err(err(code));
    }
    fs::read(path).map_err(|_| err(code))
}

/// Sign one exact release authorization under a publisher-owned scope.
/// The private key is read locally; scope violations and key mismatches fail before output.
/// Build the unsigned publisher authorization from the candidate's runtime manifest and route.
/// The origin is public Host identity, not a credential; the resulting draft is still untrusted
/// until the publisher signs it and the Host verifies that signature against its own trust policy.
pub fn draft(
    scope_value: &serde_json::Value,
    route: &serde_json::Value,
    manifest: &serde_json::Value,
    origin: &str,
    release_sequence: u64,
) -> Result<serde_json::Value, String> {
    let scope = parse_scope(scope_value)?;
    let network = route["network"].as_str().ok_or_else(|| err("INVALID"))?;
    let application_id = route["application_id"]
        .as_str()
        .ok_or_else(|| err("INVALID"))?;
    let release_id = route["release_id"].as_str().ok_or_else(|| err("INVALID"))?;
    let application_path = route["application_uri"]
        .as_str()
        .ok_or_else(|| err("INVALID"))?;
    if network != scope.network || application_id != scope.application_id || release_sequence == 0 {
        return Err(err("SCOPE_UNAUTHORIZED"));
    }
    let runtime_pin = crate::release_closure::runtime_pin(manifest, route, origin)
        .map_err(|_| err("RUNTIME_BINDING_INVALID"))?;
    let value = json!({
        "schema": SCHEMA,
        "protocol_semver": "0.5.0",
        "network": network,
        "application_id": application_id,
        "application_uri": format!("ktape://{network}/app/{application_path}"),
        "release_id": release_id,
        "runtime_pin": runtime_pin,
        "permissions": scope.permissions,
        "release_sequence": release_sequence,
        "publisher_id": scope.publisher_id,
        "key_id": scope.key_id,
        "signature": ""
    });
    validate_draft_scope(&value, scope_value)?;
    Ok(value)
}

pub(super) fn validate_draft_scope(
    draft: &serde_json::Value,
    scope_value: &serde_json::Value,
) -> Result<(PublisherScope, Authorization), String> {
    let scope = parse_scope(scope_value)?;
    let parsed: Authorization =
        serde_json::from_value(draft.clone()).map_err(|_| err("INVALID"))?;
    if !parsed.signature.is_empty()
        || parsed.network != scope.network
        || parsed.application_id != scope.application_id
        || parsed.publisher_id != scope.publisher_id
        || parsed.key_id != scope.key_id
        || parsed.release_sequence < scope.minimum_release_sequence
    {
        return Err(err("SCOPE_UNAUTHORIZED"));
    }
    let mut expected_permissions = scope.permissions.clone();
    expected_permissions.sort();
    if parsed.permissions != expected_permissions {
        return Err(err("SCOPE_UNAUTHORIZED"));
    }
    signing_bytes(&parsed)?;
    Ok((scope, parsed))
}

/// Check the exact draft, scope and local publisher key without producing a signature.
/// Coordinators use this during preflight; only the separately authorized execute phase calls
/// `sign_files`.
pub(super) fn parse_scope(scope_value: &serde_json::Value) -> Result<PublisherScope, String> {
    let scope: PublisherScope =
        serde_json::from_value(scope_value.clone()).map_err(|_| err("SCOPE_INVALID"))?;
    if scope.schema != "KTAPEOUT-PUBLISHER-SCOPE-V1"
        || !valid_hash(&scope.application_id)
        || !valid_network(&scope.network)
        || !valid_id(&scope.publisher_id)
        || !valid_id(&scope.key_id)
        || scope.minimum_release_sequence == 0
        || scope.permissions.len() > 32
        || scope
            .permissions
            .iter()
            .any(|permission| !valid_id(permission))
        || scope
            .permissions
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len()
            != scope.permissions.len()
    {
        return Err(err("SCOPE_INVALID"));
    }
    Ok(scope)
}

pub(super) fn verify_existing_signature(
    draft: &serde_json::Value,
    scope_value: &serde_json::Value,
    signed: &serde_json::Value,
) -> Result<(), String> {
    let scope = parse_scope(scope_value)?;
    let draft_value = draft;
    let draft: Authorization =
        serde_json::from_value(draft_value.clone()).map_err(|_| err("INPUT_INVALID"))?;
    if !draft.signature.is_empty()
        || draft.network != scope.network
        || draft.application_id != scope.application_id
        || draft.publisher_id != scope.publisher_id
        || draft.key_id != scope.key_id
        || draft.release_sequence < scope.minimum_release_sequence
    {
        return Err(err("SCOPE_UNAUTHORIZED"));
    }
    let mut expected_permissions = scope.permissions.clone();
    expected_permissions.sort();
    if draft.permissions != expected_permissions {
        return Err(err("SCOPE_UNAUTHORIZED"));
    }

    let mut expected_signed = draft_value.clone();
    expected_signed["signature"] = signed["signature"].clone();
    if expected_signed != *signed {
        return Err(err("BINDING_MISMATCH"));
    }

    let networks = [scope.network.as_str()];
    let application_ids = [scope.application_id.as_str()];
    let permission_refs: Vec<_> = expected_permissions.iter().map(String::as_str).collect();
    let trusted = TrustedPublisher {
        publisher_id: &scope.publisher_id,
        key_id: &scope.key_id,
        algorithm: "Ed25519",
        status: "ACTIVE",
        public_key_base64url: &scope.public_key,
        networks: &networks,
        application_ids: &application_ids,
        permissions: &permission_refs,
        minimum_release_sequence: scope.minimum_release_sequence,
    };
    let expected = ExpectedBinding {
        network: &draft.network,
        application_id: &draft.application_id,
        application_uri: &draft.application_uri,
        release_id: &draft.release_id,
        runtime_pin: &draft.runtime_pin,
    };
    verify(signed, &expected, &trusted)
}

pub(super) fn sign_result(
    status: &str,
    output_path: &Path,
    signed: &serde_json::Value,
    bytes: &[u8],
) -> serde_json::Value {
    json!({
        "schema":"KTAPEOUT-RUNTIME-RELEASE-AUTHORIZATION-SIGN-RESULT-V1",
        "status":status,
        "output":output_path,
        "sha256":crate::release_closure::sha256(bytes),
        "network":signed["network"],
        "application_id":signed["application_id"],
        "release_id":signed["release_id"],
        "publisher_id":signed["publisher_id"],
        "key_id":signed["key_id"]
    })
}

pub(super) fn existing_output(output_path: &Path) -> Result<Option<Vec<u8>>, String> {
    match fs::symlink_metadata(output_path) {
        Ok(metadata) => {
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || metadata.len() > 1024 * 1024
            {
                return Err(err("OUTPUT_INVALID"));
            }
            fs::read(output_path)
                .map(Some)
                .map_err(|_| err("OUTPUT_UNAVAILABLE"))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(err("OUTPUT_UNAVAILABLE")),
    }
}

/// Read bounded regular inputs, sign, then publish the result atomically without overwriting.
/// Verify a persisted publisher authorization during recovery without opening a private key.
/// An absent output is an error: reconciliation must never turn into an implicit signing retry.
pub fn verify_signed_files(
    draft_path: &Path,
    scope_path: &Path,
    output_path: &Path,
) -> Result<serde_json::Value, String> {
    let draft: serde_json::Value = serde_json::from_slice(&read_regular_file(
        draft_path,
        1024 * 1024,
        "INPUT_INVALID",
    )?)
    .map_err(|_| err("INPUT_INVALID"))?;
    let scope: serde_json::Value =
        serde_json::from_slice(&read_regular_file(scope_path, 64 * 1024, "SCOPE_INVALID")?)
            .map_err(|_| err("SCOPE_INVALID"))?;
    let bytes = existing_output(output_path)?.ok_or_else(|| err("OUTPUT_UNAVAILABLE"))?;
    let signed: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| err("OUTPUT_INVALID"))?;
    verify_existing_signature(&draft, &scope, &signed)?;
    Ok(sign_result(
        "VERIFIED_EXISTING",
        output_path,
        &signed,
        &bytes,
    ))
}

/// Verify one imported authorization against a Host-owned publisher trust entry and exact release.
pub fn verify(
    authorization: &serde_json::Value,
    expected: &ExpectedBinding<'_>,
    trusted: &TrustedPublisher<'_>,
) -> Result<(), String> {
    if trusted.networks.is_empty()
        || trusted.networks.len() > 8
        || trusted.application_ids.is_empty()
        || trusted.application_ids.len() > 64
        || trusted.permissions.len() > 32
        || !valid_id(trusted.publisher_id)
        || !valid_id(trusted.key_id)
        || trusted.algorithm != "Ed25519"
        || trusted.status != "ACTIVE"
        || trusted.minimum_release_sequence == 0
        || trusted
            .networks
            .iter()
            .any(|network| !valid_network(network))
        || trusted
            .networks
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len()
            != trusted.networks.len()
        || trusted
            .application_ids
            .iter()
            .any(|application_id| !valid_hash(application_id))
        || trusted
            .application_ids
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len()
            != trusted.application_ids.len()
        || trusted
            .permissions
            .iter()
            .any(|permission| !valid_id(permission))
        || trusted
            .permissions
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len()
            != trusted.permissions.len()
    {
        return Err(err("TRUST_ENTRY_INVALID"));
    }
    let value: Authorization =
        serde_json::from_value(authorization.clone()).map_err(|_| err("INVALID"))?;
    let expected_network_uri = format!("ktape://{}/app/", expected.network);
    if value.network != expected.network
        || value.application_id != expected.application_id
        || value.application_uri != expected.application_uri
        || value.release_id != expected.release_id
        || value.runtime_pin != expected.runtime_pin
        || !value.application_uri.starts_with(&expected_network_uri)
    {
        return Err(err("BINDING_MISMATCH"));
    }
    if value.publisher_id != trusted.publisher_id
        || value.key_id != trusted.key_id
        || !trusted.networks.contains(&expected.network)
        || !trusted.application_ids.contains(&expected.application_id)
        || value.release_sequence < trusted.minimum_release_sequence
        || value
            .permissions
            .iter()
            .any(|permission| !trusted.permissions.contains(&permission.as_str()))
    {
        return Err(err("SCOPE_UNAUTHORIZED"));
    }

    let key_bytes = URL_SAFE_NO_PAD
        .decode(trusted.public_key_base64url)
        .map_err(|_| err("TRUST_KEY_INVALID"))?;
    if URL_SAFE_NO_PAD.encode(&key_bytes) != trusted.public_key_base64url {
        return Err(err("TRUST_KEY_INVALID"));
    }
    let key_bytes: [u8; 32] = key_bytes.try_into().map_err(|_| err("TRUST_KEY_INVALID"))?;
    let key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| err("TRUST_KEY_INVALID"))?;
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(&value.signature)
        .map_err(|_| err("SIGNATURE_INVALID"))?;
    let signature =
        Signature::from_slice(&signature_bytes).map_err(|_| err("SIGNATURE_INVALID"))?;
    key.verify_strict(&signing_bytes(&value)?, &signature)
        .map_err(|_| err("SIGNATURE_INVALID"))
}
