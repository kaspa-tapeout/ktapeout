//! Canonical, non-authoritative TN10 namespace-key discovery lists.
//!
//! Entries are recomputed locally. This module does not treat a list as proof of
//! registration; callers must match the resulting keys to live dual-RPC state.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Read;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::time::Duration;

const DOMAIN: &[u8] = b"KTAPEOUT/0.5.0/NAMESPACE_FRAME/V1\0\x0a";
const NAME_DOMAIN: &[u8] = b"KTAPEOUT/0.5.0/NAME_FRAME/V1\0\x0a";
const SCHEMA: &str = "KTAPEOUT-REGISTERED-KEYS-V1";
const BUNDLED_KEYS_DATA: &str = include_str!("../../../data/registry/tn10-registered-keys-v1.json");
const ECONOMICS_DATA: &str = include_str!("../../../data/registry/registry-economics-v1.json");
const ECONOMICS_SOURCE_SHA256: &str =
    "82e9f38bdd590d491bb328ab1766e0f5d6af74d4faffcf9eaa37c99b14661cc6";

pub(crate) fn registry_economics_data() -> &'static str {
    ECONOMICS_DATA
}
// Key lists are tiny metadata: 64 KiB allows many namespace entries while bounding memory use.
pub const KEY_LIST_MAX_BYTES: usize = 64 * 1024;
// An 8-second whole-operation cap keeps discovery from holding a CLI invocation indefinitely.
const KEY_LIST_TIMEOUT: Duration = Duration::from_secs(8);
const KEY_LIST_REFRESH_HINT: &str =
    "refresh the public namespace-key list or provide --keys-file / --keys-url";

pub fn stale_key_list_error() -> String {
    format!("NAME_KEY_LIST_INCOMPLETE_OR_STALE: {KEY_LIST_REFRESH_HINT}")
}

pub struct RegistrationPlanInput<'a> {
    pub network: &'a str,
    pub namespace: &'a str,
    pub slug: &'a str,
    pub owner: &'a str,
    pub existing_slugs: &'a [String],
    pub namespace_key_sources: &'a [Value],
    pub normalized_mass: u64,
    pub fee_rate_sompi_per_gram: u64,
}

/// Build a deterministic, read-only name-registration estimate from fixed contract metadata.
/// The caller must supply the live dual-RPC observations before treating the plan as actionable.
pub fn plan_registration(input: RegistrationPlanInput<'_>) -> Result<Value, &'static str> {
    if input.network != "testnet-10" {
        return Err("NETWORK_NOT_ADMITTED");
    }
    if !input.owner.starts_with("kaspatest:") || input.owner.len() <= "kaspatest:".len() {
        return Err("REGISTRATION_OWNER_INVALID");
    }
    if input.normalized_mass == 0 || input.fee_rate_sompi_per_gram == 0 {
        return Err("REGISTRATION_FEE_INPUT_INVALID");
    }
    let namespace = namespace_key(input.namespace)?;
    let bundled: Value =
        serde_json::from_str(BUNDLED_KEYS_DATA).map_err(|_| "NAME_KEY_LIST_INVALID")?;
    let mut all_sources = Vec::with_capacity(input.namespace_key_sources.len() + 1);
    all_sources.push(bundled);
    all_sources.extend(input.namespace_key_sources.iter().cloned());
    let sources = merge_lists(&all_sources)?;
    if !sources
        .iter()
        .any(|entry| entry.namespace == input.namespace && entry.key_hex == namespace)
    {
        return Err("NAME_KEY_LIST_INCOMPLETE_OR_STALE");
    }
    let name_key = child_name_key(input.namespace, input.slug)?;
    let existing = child_name_keys(input.namespace, input.existing_slugs)?;
    if existing.binary_search(&name_key).is_ok() {
        return Err("NAME_ALREADY_REGISTERED");
    }
    let metadata: Value =
        serde_json::from_str(ECONOMICS_DATA).map_err(|_| "REGISTRY_ECONOMICS_INVALID")?;
    if metadata["schema"].as_str() != Some("KTAPEOUT-REGISTRY-ECONOMICS-V1")
        || metadata["profile_id"].as_str() != Some("NamespaceNamedLifecycleV6")
        || metadata["profile_semver"].as_str() != Some("1.0.0")
        || metadata["network"].as_str() != Some(input.network)
        || metadata["contract_source_sha256"].as_str() != Some(ECONOMICS_SOURCE_SHA256)
        || metadata["refund_path"].as_str() != Some("NONE_IN_V1")
    {
        return Err("REGISTRY_ECONOMICS_PIN_MISMATCH");
    }
    let sompi_per_kas = metadata["sompi_per_kas"]
        .as_u64()
        .filter(|amount| *amount > 0)
        .ok_or("REGISTRY_ECONOMICS_INVALID")?;
    let deed_state_bond = metadata["deed_state_bond_sompi"]
        .as_u64()
        .filter(|amount| *amount > 0)
        .ok_or("REGISTRY_ECONOMICS_INVALID")?;
    let name_deed_output = metadata["name_deed_output_sompi"]
        .as_u64()
        .filter(|amount| *amount > 0)
        .ok_or("REGISTRY_ECONOMICS_INVALID")?;
    let gap_floor = metadata["adapter_gap_floor_sompi"]
        .as_u64()
        .filter(|amount| *amount > 0)
        .ok_or("REGISTRY_ECONOMICS_INVALID")?;
    let network_fee = input
        .normalized_mass
        .checked_mul(input.fee_rate_sompi_per_gram)
        .ok_or("REGISTRATION_FEE_OVERFLOW")?;
    // The child-registration transition preserves the parent Deed and consumed
    // Gap value, then creates two new Gap floors plus the child Deed output.
    // The 10 KAS bond is a parent Deed state field, not a per-registration lock.
    let newly_locked = gap_floor
        .checked_mul(2)
        .ok_or("REGISTRATION_FEE_OVERFLOW")?;
    let total_upfront = newly_locked
        .checked_add(network_fee)
        .ok_or("REGISTRATION_FEE_OVERFLOW")?;
    Ok(json!({
        "schema":"KTAPEOUT-NAME-REGISTER-PLAN-V1",
        "status":"READ_ONLY_PLAN",
        "network":input.network,
        "namespace":input.namespace,
        "namespace_key":namespace,
        "namespace_key_sources_merged":all_sources.len(),
        "slug":input.slug,
        "name_key":name_key,
        "owner":input.owner,
        "next_owner":input.owner,
        "contract_source_sha256":metadata["contract_source_sha256"],
        "deed_state_bond_sompi":deed_state_bond,
        "deed_state_bond_kas":format_kas(deed_state_bond, sompi_per_kas),
        "name_deed_output_sompi":name_deed_output,
        "name_deed_output_kas":format_kas(name_deed_output, sompi_per_kas),
        "adapter_gap_floor_sompi":gap_floor,
        "adapter_gap_floor_kas":format_kas(gap_floor, sompi_per_kas),
        "network_fee_sompi":network_fee,
        "network_fee_kas":format_kas(network_fee, sompi_per_kas),
        "fee_source":"estimate",
        "normalized_mass":input.normalized_mass,
        "fee_rate_sompi_per_gram":input.fee_rate_sompi_per_gram,
        "newly_locked_sompi":newly_locked,
        "newly_locked_kas":format_kas(newly_locked, sompi_per_kas),
        "total_upfront_sompi":total_upfront,
        "total_upfront_kas":format_kas(total_upfront, sompi_per_kas),
        "refund_path":"NONE_IN_V1",
        "signing_allowed":false,
        "broadcast":false
    }))
}

fn format_kas(sompi: u64, sompi_per_kas: u64) -> String {
    format!("{}.{:08}", sompi / sompi_per_kas, sompi % sompi_per_kas)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamespaceKey {
    pub namespace: String,
    pub key_hex: String,
}

pub fn namespace_key(namespace: &str) -> Result<String, &'static str> {
    let frame = component_frame(namespace, "NAMESPACE_NON_CANONICAL")?;
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    hasher.update(frame);
    Ok(hex::encode(hasher.finalize()))
}

fn component_frame(value: &str, error: &'static str) -> Result<[u8; 64], &'static str> {
    if value.is_empty()
        || value.len() > 63
        || !value.is_ascii()
        || !value.bytes().enumerate().all(|(index, byte)| {
            if index == 0 {
                byte.is_ascii_lowercase() || byte.is_ascii_digit()
            } else {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
            }
        })
    {
        return Err(error);
    }
    let mut frame = [0u8; 64];
    frame[0] = value.len() as u8;
    frame[1..1 + value.len()].copy_from_slice(value.as_bytes());
    Ok(frame)
}

/// Derive a child name key with the pinned CompactV2 namespace/name framing.
pub fn child_name_key(namespace: &str, slug: &str) -> Result<String, &'static str> {
    let namespace = component_frame(namespace, "NAMESPACE_NON_CANONICAL")?;
    let slug = component_frame(slug, "NAME_SLUG_NON_CANONICAL")?;
    let mut hasher = Sha256::new();
    hasher.update(NAME_DOMAIN);
    hasher.update(namespace);
    hasher.update(slug);
    Ok(hex::encode(hasher.finalize()))
}

/// Derive and sort the complete child-name key set supplied by a namespace controller.
/// A repeated key is an ambiguous local registration inventory and must not be ignored.
pub fn child_name_keys(namespace: &str, slugs: &[String]) -> Result<Vec<String>, &'static str> {
    let mut keys = slugs
        .iter()
        .map(|slug| child_name_key(namespace, slug))
        .collect::<Result<Vec<_>, _>>()?;
    keys.sort_unstable();
    if keys.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("NAME_KEY_DUPLICATE");
    }
    Ok(keys)
}

/// Parse exact canonical JSON and recompute every namespace key.
pub fn parse_list(value: &Value) -> Result<Vec<NamespaceKey>, &'static str> {
    let object = value.as_object().ok_or("NAME_KEY_LIST_INVALID")?;
    if object.len() != 5
        || object.get("schema").and_then(Value::as_str) != Some(SCHEMA)
        || object.get("network").and_then(Value::as_str) != Some("testnet-10")
        || object.get("sequence").and_then(Value::as_u64).is_none()
        || object
            .get("updated_at")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    {
        return Err("NAME_KEY_LIST_INVALID");
    }
    let entries = object
        .get("keys")
        .and_then(Value::as_array)
        .ok_or("NAME_KEY_LIST_INVALID")?;
    let mut parsed = Vec::with_capacity(entries.len());
    let mut previous: Option<&str> = None;
    for entry in entries {
        let item = entry.as_object().ok_or("NAME_KEY_LIST_INVALID")?;
        if !(2..=3).contains(&item.len()) {
            return Err("NAME_KEY_LIST_INVALID");
        }
        if item
            .keys()
            .any(|key| !matches!(key.as_str(), "namespace" | "key_hex" | "evidence_ref"))
        {
            return Err("NAME_KEY_LIST_INVALID");
        }
        let namespace = item
            .get("namespace")
            .and_then(Value::as_str)
            .ok_or("NAME_KEY_LIST_INVALID")?;
        let key_hex = item
            .get("key_hex")
            .and_then(Value::as_str)
            .ok_or("NAME_KEY_LIST_INVALID")?;
        if previous.is_some_and(|prior| prior >= namespace) {
            return Err("NAME_KEY_LIST_NON_CANONICAL_ORDER");
        }
        previous = Some(namespace);
        if key_hex.len() != 64
            || !key_hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("NAME_KEY_LIST_INVALID");
        }
        if namespace_key(namespace)? != key_hex {
            return Err("NAME_KEY_LIST_KEY_MISMATCH");
        }
        if item
            .get("evidence_ref")
            .is_some_and(|reference| reference.as_str().is_none_or(str::is_empty))
        {
            return Err("NAME_KEY_LIST_INVALID");
        }
        parsed.push(NamespaceKey {
            namespace: namespace.to_owned(),
            key_hex: key_hex.to_owned(),
        });
    }
    Ok(parsed)
}

/// Merge independent untrusted sources by namespace, rejecting conflicting claims.
pub fn merge_lists(sources: &[Value]) -> Result<Vec<NamespaceKey>, &'static str> {
    let mut union = BTreeMap::<String, String>::new();
    for source in sources {
        for key in parse_list(source).map_err(|error| {
            if error == "NAME_KEY_LIST_KEY_MISMATCH" {
                "NAME_KEY_LIST_INCOMPLETE_OR_STALE"
            } else {
                error
            }
        })? {
            if union
                .insert(key.namespace.clone(), key.key_hex.clone())
                .is_some_and(|prior| prior != key.key_hex)
            {
                return Err("NAME_KEY_LIST_CONFLICT");
            }
        }
    }
    Ok(union
        .into_iter()
        .map(|(namespace, key_hex)| NamespaceKey { namespace, key_hex })
        .collect())
}

/// Merge the bundled discovery baseline with untrusted caller sources and recompute every key.
pub fn merged_namespace_keys(sources: &[Value]) -> Result<Vec<NamespaceKey>, &'static str> {
    let baseline: Value =
        serde_json::from_str(BUNDLED_KEYS_DATA).map_err(|_| "NAME_KEY_LIST_INVALID")?;
    let mut all = Vec::with_capacity(sources.len() + 1);
    all.push(baseline);
    all.extend(sources.iter().cloned());
    merge_lists(&all)
}

pub fn list_value(sequence: u64, updated_at: &str, keys: &[NamespaceKey]) -> Value {
    json!({
        "schema": SCHEMA,
        "network": "testnet-10",
        "sequence": sequence,
        "updated_at": updated_at,
        "keys": keys.iter().map(|key| json!({
            "namespace": key.namespace,
            "key_hex": key.key_hex,
        })).collect::<Vec<_>>(),
    })
}

/// Emit one discovery entry only from a successful dual-RPC namespace-key verification report.
/// The resulting row is still an untrusted list hint; consumers must perform their own RPC check.
pub fn namespace_key_entry_from_verification(
    namespace: &str,
    verification: &Value,
    evidence_ref: Option<&str>,
) -> Result<Value, &'static str> {
    if verification["schema"] != "KTAPEOUT-TN10-MERGED-NAMESPACE-KEY-VERIFICATION-V1"
        || verification["status"] != "TN10_DUAL_RPC_MERGED_NAMESPACE_KEYS_MATCH"
        || verification["network"] != "testnet-10"
    {
        return Err("NAME_KEY_VERIFICATION_REQUIRED");
    }
    let key_hex = namespace_key(namespace)?;
    let matches = verification["verified"]
        .as_array()
        .ok_or("NAME_KEY_VERIFICATION_REQUIRED")?
        .iter()
        .filter(|item| item["namespace"].as_str() == Some(namespace))
        .collect::<Vec<_>>();
    if matches.len() != 1
        || matches[0]["namespace_key"].as_str() != Some(key_hex.as_str())
        || matches[0]["status"] != "TN10_DUAL_RPC_NAMESPACE_STATE_MATCH"
    {
        return Err("NAME_KEY_VERIFICATION_REQUIRED");
    }
    let mut entry = json!({"namespace":namespace,"key_hex":key_hex});
    if let Some(reference) = evidence_ref {
        if reference.is_empty() {
            return Err("NAME_KEY_LIST_INVALID");
        }
        entry["evidence_ref"] = json!(reference);
    }
    Ok(entry)
}

/// Validate an optional untrusted list URL before any DNS or HTTP request.
pub fn validate_keys_url(url: &str) -> Result<(), &'static str> {
    let authority = url
        .split_once("://")
        .map(|(_, rest)| rest.split(['/', '?', '#']).next().unwrap_or_default())
        .unwrap_or_default();
    if authority.contains('@') {
        return Err("NAME_KEY_URL_INVALID");
    }
    let parsed = reqwest::Url::parse(url).map_err(|_| "NAME_KEY_URL_INVALID")?;
    if parsed.scheme() != "https" {
        return Err("NAME_KEY_URL_HTTPS_REQUIRED");
    }
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err("NAME_KEY_URL_INVALID");
    }
    let host = parsed
        .host_str()
        .ok_or("NAME_KEY_URL_INVALID")?
        .trim_start_matches('[')
        .trim_end_matches(']');
    if parsed.port_or_known_default() != Some(443) {
        return Err("NAME_KEY_URL_PORT_NOT_ALLOWED");
    }
    if host.parse::<IpAddr>().is_ok()
        || host
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        return Err("NAME_KEY_URL_PUBLIC_DNS_REQUIRED");
    }
    let host = host.to_ascii_lowercase();
    let labels: Vec<&str> = host.split('.').collect();
    if host.len() > 253
        || !host.contains('.')
        || host.ends_with('.')
        || ["localhost", "local", "internal", "lan", "home.arpa"]
            .iter()
            .any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}")))
        || labels.iter().any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || label.bytes().all(|byte| byte.is_ascii_digit())
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err("NAME_KEY_URL_PUBLIC_DNS_REQUIRED");
    }
    Ok(())
}

/// Fetch a key-list candidate through an injectable boundary, then validate its full document.
/// The source is never authoritative; callers still merge it and verify derived keys against RPC.
pub fn fetch_key_list_with<F>(url: &str, fetcher: F) -> Result<Value, &'static str>
where
    F: FnOnce(&str) -> Result<(u16, Vec<u8>), &'static str> + Send + 'static,
{
    fetch_key_list_with_timeout(url, KEY_LIST_TIMEOUT, fetcher)
}

/// Injectable bounded fetch boundary, also used to test timeout behavior without network I/O.
pub fn fetch_key_list_with_timeout<F>(
    url: &str,
    timeout: Duration,
    fetcher: F,
) -> Result<Value, &'static str>
where
    F: FnOnce(&str) -> Result<(u16, Vec<u8>), &'static str> + Send + 'static,
{
    validate_keys_url(url)?;
    let (status, body) = fetch_with_timeout(url.to_owned(), timeout, fetcher)?;
    if (300..400).contains(&status) {
        return Err("NAME_KEY_URL_REDIRECT_REJECTED");
    }
    if !(200..300).contains(&status) {
        return Err("NAME_KEY_URL_HTTP_ERROR");
    }
    if body.len() > KEY_LIST_MAX_BYTES {
        return Err("NAME_KEY_URL_RESPONSE_TOO_LARGE");
    }
    let document: Value = serde_json::from_slice(&body).map_err(|_| "NAME_KEY_LIST_INVALID")?;
    match parse_list(&document) {
        Ok(_) => Ok(document),
        Err("NAME_KEY_LIST_KEY_MISMATCH") => Err("NAME_KEY_LIST_INCOMPLETE_OR_STALE"),
        Err(error) => Err(error),
    }
}

/// Resolve once, reject every non-global answer, and pin the HTTPS client to those addresses.
/// Redirects are disabled, so neither host changes nor port changes can escape this check.
pub fn fetch_key_list(url: &str) -> Result<Value, &'static str> {
    fetch_key_list_with(url, fetch_keys_https)
}

fn fetch_with_timeout<F>(
    url: String,
    timeout: Duration,
    fetcher: F,
) -> Result<(u16, Vec<u8>), &'static str>
where
    F: FnOnce(&str) -> Result<(u16, Vec<u8>), &'static str> + Send + 'static,
{
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let _ = sender.send(fetcher(&url));
    });
    receiver
        .recv_timeout(timeout)
        .map_err(|_| "NAME_KEY_URL_TIMEOUT")?
}

fn fetch_keys_https(url: &str) -> Result<(u16, Vec<u8>), &'static str> {
    let parsed = reqwest::Url::parse(url).map_err(|_| "NAME_KEY_URL_INVALID")?;
    let host = parsed.host_str().ok_or("NAME_KEY_URL_INVALID")?;
    let port = parsed
        .port_or_known_default()
        .ok_or("NAME_KEY_URL_INVALID")?;
    let addresses = (host, port)
        .to_socket_addrs()
        .map_err(|_| "NAME_KEY_URL_PUBLIC_DNS_REQUIRED")?
        .collect::<Vec<_>>();
    validate_public_dns_answers(&addresses.iter().map(SocketAddr::ip).collect::<Vec<_>>())?;
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(KEY_LIST_TIMEOUT)
        .resolve_to_addrs(host, &addresses)
        .build()
        .map_err(|_| "NAME_KEY_URL_CLIENT_FAILED")?;
    let mut response = client.get(parsed).send().map_err(|error| {
        if error.is_timeout() {
            "NAME_KEY_URL_TIMEOUT"
        } else {
            "NAME_KEY_URL_FETCH_FAILED"
        }
    })?;
    let status = response.status().as_u16();
    if (300..400).contains(&status) {
        return Err("NAME_KEY_URL_REDIRECT_REJECTED");
    }
    if !(200..300).contains(&status) {
        return Err("NAME_KEY_URL_HTTP_ERROR");
    }
    if response
        .content_length()
        .is_some_and(|length| length > KEY_LIST_MAX_BYTES as u64)
    {
        return Err("NAME_KEY_URL_RESPONSE_TOO_LARGE");
    }
    let mut body = Vec::with_capacity(KEY_LIST_MAX_BYTES.min(4096));
    response
        .by_ref()
        .take(KEY_LIST_MAX_BYTES as u64 + 1)
        .read_to_end(&mut body)
        .map_err(|_| "NAME_KEY_URL_FETCH_FAILED")?;
    if body.len() > KEY_LIST_MAX_BYTES {
        return Err("NAME_KEY_URL_RESPONSE_TOO_LARGE");
    }
    Ok((status, body))
}

pub fn validate_public_dns_answers(addresses: &[IpAddr]) -> Result<(), &'static str> {
    if addresses.is_empty() || addresses.iter().any(|address| !is_public_ip(*address)) {
        return Err("NAME_KEY_URL_PUBLIC_DNS_REQUIRED");
    }
    Ok(())
}

fn is_public_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(ip) => {
            let [a, b, c, d] = ip.octets();
            !(a == 0
                || a == 10
                || a == 127
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && b == 0 && c == 0)
                || (a == 192 && b == 0 && c == 2)
                || (a == 192 && b == 168)
                || (a == 192 && b == 88 && c == 99)
                || (a == 198 && (b == 18 || b == 19))
                || (a == 198 && b == 51 && c == 100)
                || (a == 203 && b == 0 && c == 113)
                || a >= 224
                || (a == 255 && b == 255 && c == 255 && d == 255))
        }
        IpAddr::V6(ip) => {
            let bytes = ip.octets();
            (bytes[0] & 0xe0) == 0x20
                && !(bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] <= 0x01)
                && !(bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x0d && bytes[3] == 0xb8)
                && !(bytes[0] == 0x20 && bytes[1] == 0x02)
                && !(bytes[0] == 0x3f && bytes[1] & 0xf0 == 0xf0)
        }
    }
}
