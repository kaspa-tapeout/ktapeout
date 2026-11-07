//! Authenticate a retained bounded assertion. No signing, VM replay, or RPC.
use super::{canonical_json, digest_bytes};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

fn require(ok: bool, label: &str) -> Result<(), String> {
    if ok {
        Ok(())
    } else {
        Err(format!("NAMESPACE_ADMISSION_INVALID:{label}"))
    }
}
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str, String> {
    v[key]
        .as_str()
        .ok_or_else(|| format!("NAMESPACE_ADMISSION_STRING_REQUIRED:{key}"))
}
fn array<'a>(v: &'a Value, key: &str) -> Result<&'a Vec<Value>, String> {
    let a = v[key]
        .as_array()
        .ok_or_else(|| format!("NAMESPACE_ADMISSION_ARRAY_REQUIRED:{key}"))?;
    require(a.len() <= 64, key)?;
    Ok(a)
}
fn fields(v: &Value, names: &[&str], schema: &str) -> Result<(), String> {
    require(
        super::exact_json_keys(v, names)
            && v["schema"] == schema
            && v["protocol_semver"] == "0.5.0",
        schema,
    )
}
fn without(v: &Value, omit: &[&str]) -> Result<Value, String> {
    let mut m = v
        .as_object()
        .ok_or("NAMESPACE_ADMISSION_OBJECT_REQUIRED")?
        .clone();
    for k in omit {
        m.remove(*k);
    }
    Ok(Value::Object(m))
}
fn hash(v: &Value, domain: &str) -> Result<String, String> {
    Ok(digest_bytes(
        &canonical_json(v)?,
        &format!("KTAPEOUT/0.5.0/{domain}"),
    ))
}
fn check_hash(v: &Value, field: &str, omit: &[&str], domain: &str) -> Result<(), String> {
    require(v[field] == hash(&without(v, omit)?, domain)?, field)
}
fn utc(v: &Value, key: &str) -> Result<DateTime<Utc>, String> {
    let s = text(v, key)?;
    require(s.len() <= 64 && s.ends_with('Z'), key)?;
    DateTime::parse_from_rfc3339(s)
        .map(|t| t.with_timezone(&Utc))
        .map_err(|_| format!("NAMESPACE_ADMISSION_TIME_INVALID:{key}"))
}
fn strings(v: &Value, key: &str) -> Result<Vec<String>, String> {
    array(v, key)?
        .iter()
        .map(|x| {
            let s = x
                .as_str()
                .ok_or("NAMESPACE_ADMISSION_STRING_LIST_INVALID")?;
            let limit = if key == "signatures" { 4096 } else { 256 };
            require(!s.is_empty() && s.len() <= limit, key)?;
            Ok(s.to_owned())
        })
        .collect()
}
fn decode(s: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(s.trim_end_matches('='))
        .map_err(|_| "NAMESPACE_ADMISSION_BASE64_INVALID".into())
}
fn keys(v: &Value) -> Result<(), String> {
    let mut seen = BTreeSet::new();
    for k in array(v, "keys")? {
        require(
            super::exact_json_keys(k, &["key_id", "algorithm", "public_key", "status"]),
            "key fields",
        )?;
        let id = text(k, "key_id")?;
        require(
            super::valid_profile_id(id)
                && seen.insert(id.to_owned())
                && k["algorithm"] == "Ed25519"
                && matches!(k["status"].as_str(), Some("ACTIVE" | "RETIRED")),
            "key identity/status",
        )?;
        require(
            decode(text(k, "public_key")?)?.len() == 32,
            "public key length",
        )?;
    }
    let revoked = strings(v, "revoked_key_ids")?;
    require(
        revoked.iter().collect::<BTreeSet<_>>().len() == revoked.len()
            && revoked.iter().all(|x| seen.contains(x)),
        "revoked keys",
    )
}
fn signature(
    hash: &str,
    sig: &str,
    ring: &Value,
    domain: &str,
    active_only: bool,
) -> Result<String, String> {
    require(
        super::valid_hash(hash) && sig.len() <= 4096,
        "signature hash/size",
    )?;
    let parts: Vec<_> = sig.split(':').collect();
    require(
        parts.len() == 3 && parts[0] == "ed25519",
        "signature format",
    )?;
    let id = parts[1];
    require(
        !strings(ring, "revoked_key_ids")?.iter().any(|x| x == id),
        "revoked signer",
    )?;
    let key = array(ring, "keys")?
        .iter()
        .find(|k| k["key_id"] == id)
        .ok_or("NAMESPACE_ADMISSION_UNKNOWN_SIGNER")?;
    require(!active_only || key["status"] == "ACTIVE", "inactive signer")?;
    let raw: [u8; 32] = decode(text(key, "public_key")?)?
        .try_into()
        .map_err(|_| "NAMESPACE_ADMISSION_KEY_LENGTH")?;
    let key = VerifyingKey::from_bytes(&raw).map_err(|_| "NAMESPACE_ADMISSION_KEY_INVALID")?;
    let sig = Signature::from_slice(&decode(parts[2])?)
        .map_err(|_| "NAMESPACE_ADMISSION_SIGNATURE_LENGTH")?;
    let payload = format!("KTAPEOUT/0.5.0/{domain}\0{hash}");
    key.verify_strict(payload.as_bytes(), &sig)
        .map_err(|_| "NAMESPACE_ADMISSION_SIGNATURE_INVALID")?;
    Ok(id.to_owned())
}
fn threshold(v: &Value, field: &str, ring: &Value, domain: &str) -> Result<(), String> {
    let required = ring["threshold"].as_u64().unwrap_or(1) as usize;
    let mut signed = BTreeSet::new();
    for sig in strings(v, "signatures")? {
        // Invalid signatures cannot contribute to the distinct-key threshold.
        if let Ok(id) = signature(text(v, field)?, &sig, ring, domain, false) {
            signed.insert(id);
        }
    }
    require(
        required > 0 && signed.len() >= required,
        "signature threshold",
    )
}
fn root_manifest(v: &Value) -> Result<(), String> {
    fields(
        v,
        &[
            "schema",
            "protocol_semver",
            "root_id",
            "keys",
            "revoked_key_ids",
            "manifest_hash",
        ],
        "KTAPEOUT-TRUST-ROOT-MANIFEST-V1",
    )?;
    keys(v)?;
    check_hash(
        v,
        "manifest_hash",
        &["manifest_hash"],
        "TRUST_ROOT_MANIFEST/V1",
    )
}
fn root_update(v: &Value) -> Result<(), String> {
    fields(
        v,
        &[
            "schema",
            "protocol_semver",
            "trust_domain_id",
            "root_id",
            "epoch",
            "predecessor_manifest_hash",
            "issued_at",
            "valid_from",
            "valid_until",
            "keys",
            "revoked_key_ids",
            "threshold",
            "signer_key_ids",
            "root_policy_hash",
            "signatures",
            "update_hash",
        ],
        "KTAPEOUT-TRUST-ROOT-UPDATE-V2",
    )?;
    keys(v)?;
    require(
        v["epoch"].as_u64().is_some() && super::valid_hash(text(v, "predecessor_manifest_hash")?),
        "epoch/predecessor",
    )?;
    require(
        utc(v, "valid_from")? < utc(v, "valid_until")?
            && utc(v, "issued_at")? <= utc(v, "valid_until")?,
        "root time window",
    )?;
    let n = v["threshold"]
        .as_u64()
        .ok_or("NAMESPACE_ADMISSION_THRESHOLD_INVALID")? as usize;
    let signers = strings(v, "signer_key_ids")?;
    require(
        n >= 1
            && n <= array(v, "keys")?.len()
            && signers.len() >= n
            && signers.iter().all(|id| {
                array(v, "keys").unwrap().iter().any(|k| k["key_id"] == *id)
                    && !strings(v, "revoked_key_ids").unwrap().contains(id)
            }),
        "root signer policy",
    )?;
    require(
        v["root_policy_hash"]
            == hash(
                &json!({"threshold":n,"signer_key_ids":signers}),
                "TRUST_ROOT_POLICY/V2",
            )?,
        "root policy hash",
    )?;
    check_hash(
        v,
        "update_hash",
        &["update_hash", "signatures"],
        "TRUST_ROOT_UPDATE/V2",
    )
}

// Case-sensitive fnmatch syntax used by publisher delegation scopes.
fn scope_matches(pattern: &str, subject: &str) -> bool {
    fn run(p: &[char], s: &[char], memo: &mut BTreeMap<(usize, usize), bool>) -> bool {
        let key = (p.len(), s.len());
        if let Some(v) = memo.get(&key) {
            return *v;
        }
        let result = match p.first() {
            None => s.is_empty(),
            Some('*') => run(&p[1..], s, memo) || (!s.is_empty() && run(p, &s[1..], memo)),
            Some('?') => !s.is_empty() && run(&p[1..], &s[1..], memo),
            Some('[') if !s.is_empty() => {
                let start = if p.get(1) == Some(&'!') { 2 } else { 1 };
                let search = if p.get(start) == Some(&']') {
                    start + 1
                } else {
                    start
                };
                if let Some(end) = (search..p.len()).find(|i| p[*i] == ']') {
                    let mut hit = false;
                    let mut i = start;
                    while i < end {
                        if i + 2 < end && p[i + 1] == '-' {
                            hit |= p[i] <= s[0] && s[0] <= p[i + 2];
                            i += 3;
                        } else {
                            hit |= p[i] == s[0];
                            i += 1;
                        }
                    }
                    (hit != (start == 2)) && run(&p[end + 1..], &s[1..], memo)
                } else {
                    s[0] == '[' && run(&p[1..], &s[1..], memo)
                }
            }
            Some(c) => !s.is_empty() && *c == s[0] && run(&p[1..], &s[1..], memo),
        };
        memo.insert(key, result);
        result
    }
    run(
        &pattern.chars().collect::<Vec<_>>(),
        &subject.chars().collect::<Vec<_>>(),
        &mut BTreeMap::new(),
    )
}

// Inputs remain separate because each maps to a distinct signed trust-chain document.
#[allow(clippy::too_many_arguments)]
fn authenticate(
    a: &Value,
    ring: &Value,
    root: &Value,
    update: &Value,
    prev: &Value,
    d: &Value,
    now: DateTime<Utc>,
    scope_subject: &str,
) -> Result<(), String> {
    root_manifest(root)?;
    root_update(update)?;
    require(
        root["keys"] == update["keys"] && root["revoked_key_ids"] == update["revoked_key_ids"],
        "pinned active root",
    )?;
    let previous_hash = if prev["schema"] == "KTAPEOUT-TRUST-ROOT-UPDATE-V2" {
        root_update(prev)?;
        &prev["update_hash"]
    } else {
        root_manifest(prev)?;
        &prev["manifest_hash"]
    };
    require(
        update["predecessor_manifest_hash"] == *previous_hash
            && update["epoch"].as_u64() == prev["epoch"].as_u64().unwrap_or(0).checked_add(1)
            && (prev.get("trust_domain_id").is_none()
                || prev["trust_domain_id"] == update["trust_domain_id"]),
        "root chain",
    )?;
    threshold(
        update,
        "update_hash",
        prev,
        "TRUST_ROOT_UPDATE/SIGNATURE/V2",
    )?;
    fields(
        ring,
        &[
            "schema",
            "protocol_semver",
            "publisher_id",
            "keys",
            "revoked_key_ids",
            "keyring_hash",
            "root_key_id",
            "root_signature",
        ],
        "KTAPEOUT-PUBLISHER-KEYRING-V1",
    )?;
    keys(ring)?;
    check_hash(
        ring,
        "keyring_hash",
        &["keyring_hash", "root_signature"],
        "PUBLISHER_KEYRING/V1",
    )?;
    require(
        signature(
            text(ring, "keyring_hash")?,
            text(ring, "root_signature")?,
            root,
            "PUBLISHER_KEYRING/SIGNATURE/V1",
            true,
        )? == text(ring, "root_key_id")?,
        "keyring root signer",
    )?;
    fields(
        d,
        &[
            "schema",
            "protocol_semver",
            "trust_domain_id",
            "publisher_id",
            "keyring_hash",
            "key_id",
            "purposes",
            "scope",
            "valid_from",
            "valid_until",
            "predecessor_delegation_hash",
            "signatures",
            "delegation_hash",
        ],
        "KTAPEOUT-PUBLISHER-DELEGATION-V2",
    )?;
    check_hash(
        d,
        "delegation_hash",
        &["delegation_hash", "signatures"],
        "PUBLISHER_DELEGATION/V2",
    )?;
    require(
        super::valid_hash(text(d, "predecessor_delegation_hash")?)
            && d["publisher_id"] == ring["publisher_id"]
            && d["keyring_hash"] == ring["keyring_hash"]
            && d["trust_domain_id"] == update["trust_domain_id"]
            && a["trust_domain_id"] == d["trust_domain_id"]
            && a["signer_id"] == ring["publisher_id"],
        "delegation binding",
    )?;
    threshold(
        d,
        "delegation_hash",
        update,
        "PUBLISHER_DELEGATION/SIGNATURE/V2",
    )?;
    let issued = utc(a, "issued_at")?;
    require(
        utc(d, "valid_from")? <= issued && issued <= now && now <= utc(d, "valid_until")?,
        "delegation validity",
    )?;
    require(
        strings(d, "purposes")?.iter().any(|s| s == "ATTESTATION"),
        "delegation purpose",
    )?;
    require(
        strings(d, "scope")?
            .iter()
            .any(|p| scope_matches(p, scope_subject)),
        "delegation scope",
    )?;
    let id = signature(
        text(a, "attestation_hash")?,
        text(a, "signature")?,
        ring,
        "VERIFICATION_ATTESTATION/SIGNATURE/V1",
        true,
    )?;
    require(id == text(d, "key_id")?, "delegated signature key")
}

/// Verify only the authenticity of a generic VerificationAttestationV1.
/// This does not validate the referenced package/report or promote admission.
pub fn verify_signed_attestation(
    a: &Value,
    ring: &Value,
    root: &Value,
    update: &Value,
    prev: &Value,
    d: &Value,
    now: DateTime<Utc>,
) -> Result<Value, String> {
    fields(
        a,
        &[
            "schema",
            "protocol_semver",
            "subject_kind",
            "subject_hash",
            "package_digest",
            "contract_hash",
            "effect_hash",
            "application_lock_hash",
            "adapter_root",
            "abi_root",
            "vector_root",
            "verifier_id",
            "verifier_release_hash",
            "test_vector_root",
            "trust_domain_id",
            "issued_at",
            "validity_policy",
            "signer_id",
            "signature",
            "attestation_hash",
        ],
        "KTAPEOUT-VERIFICATION-ATTESTATION-V1",
    )?;
    require(
        matches!(
            a["subject_kind"].as_str(),
            Some("PROFILE_PACKAGE" | "RECIPE" | "APPLICATION")
        ),
        "subject kind",
    )?;
    for field in [
        "subject_hash",
        "package_digest",
        "contract_hash",
        "effect_hash",
        "application_lock_hash",
        "adapter_root",
        "abi_root",
        "vector_root",
        "verifier_release_hash",
        "test_vector_root",
    ] {
        require(super::valid_hash(text(a, field)?), field)?;
    }
    for field in [
        "verifier_id",
        "trust_domain_id",
        "validity_policy",
        "signer_id",
    ] {
        require(super::valid_profile_id(text(a, field)?), field)?;
    }
    utc(a, "issued_at")?;
    check_hash(
        a,
        "attestation_hash",
        &["attestation_hash", "signature"],
        "VERIFICATION_ATTESTATION/V1",
    )?;
    // The delegation scope is interpreted as signer namespace + subject kind.
    // The signed subject_hash remains exact; this check does not claim that the
    // referenced package/report was re-executed or admitted.
    let scope_subject = format!(
        "{}.{}",
        text(ring, "publisher_id")?,
        text(a, "subject_kind")?
    );
    authenticate(a, ring, root, update, prev, d, now, &scope_subject)?;
    Ok(json!({
        "schema":"KTAPEOUT-PROFILE-VERIFICATION-ATTESTATION-RESULT-V1",
        "status":"ATTESTATION_VERIFIED",
        "attestation_hash":a["attestation_hash"],
        "subject_kind":a["subject_kind"],
        "subject_hash":a["subject_hash"],
        "package_digest":a["package_digest"],
        "trust_domain_id":a["trust_domain_id"],
        "delegation_scope_subject":scope_subject,
        "evidence_truth":"NOT_REEXECUTED",
        "profile_admission":"UNPROVEN",
        "network_admission":"NOT_EVALUATED",
        "finality":"NOT_CLAIMED",
        "signing_allowed":false,
        "broadcast":false
    }))
}

// Source location is local configuration discovered from the explicit package,
// never a build-machine path or part of the publisher's identity.
#[cfg(feature = "host-bridges")]
fn verifier_source_root(package: &Path) -> Result<std::path::PathBuf, String> {
    let package = package.canonicalize().map_err(|e| e.to_string())?;
    let marker = "spec/ktapeout-release-manifest-v0.5.0.json";
    let source = "ktapeout_050_profile_package.py";
    let root = package
        .ancestors()
        .find(|root| root.join(marker).is_file() && root.join(source).is_file())
        .ok_or("NAMESPACE_ADMISSION_RELEASE_ROOT_NOT_FOUND")?;
    contained_source(root, marker)?;
    contained_source(root, source)?;
    Ok(root.to_owned())
}

#[cfg(feature = "host-bridges")]
fn contained_source(root: &Path, name: &str) -> Result<std::path::PathBuf, String> {
    let mut path = root.to_owned();
    require(!name.is_empty(), "source path")?;
    for component in Path::new(name).components() {
        let std::path::Component::Normal(part) = component else {
            return Err("NAMESPACE_ADMISSION_INVALID:source path".into());
        };
        path.push(part);
        let metadata = std::fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
        require(!metadata.file_type().is_symlink(), "source symlink")?;
        require(
            path.canonicalize()
                .map_err(|e| e.to_string())?
                .starts_with(root),
            "source path",
        )?;
    }
    require(path.is_file(), "source file")?;
    path.canonicalize().map_err(|e| e.to_string())
}

#[allow(clippy::too_many_arguments)]
#[cfg(feature = "host-bridges")]
pub fn verify(
    attestation: &Path,
    keyring: &Path,
    package: &Path,
    report: &Path,
    root: &Path,
    update: &Path,
    predecessor: &Path,
    delegation: &Path,
) -> Result<Value, String> {
    let a = read_json(attestation)?;
    let ring = read_json(keyring)?;
    let d = read_json(delegation)?;
    let expected = expected_attestation(package, &read_json(report)?, &a, &ring, &d, false)?;
    require(
        without(&a, &["signature"])? == expected,
        "exact package/report/deployment tuple",
    )?;
    let is_v6 = a["validity_policy"] == "TN10_NAMESPACE_NAMED_LIFECYCLE_V6_BOUNDED";
    let profile_id = if is_v6 {
        "NamespaceNamedLifecycleV6"
    } else {
        "NamespaceIssuanceV1"
    };
    authenticate(
        &a,
        &ring,
        &read_json(root)?,
        &read_json(update)?,
        &read_json(predecessor)?,
        &d,
        Utc::now(),
        &format!("{}.{}", text(&ring, "publisher_id")?, profile_id),
    )?;
    if is_v6 {
        return Ok(
            json!({"status":"TESTNET_ADMITTED","formal_admission":"PROVEN","network":"testnet-10","scope":"ISOLATED_NAMED_LIFECYCLE_V6_SEQUENCE","profile_id":"NamespaceNamedLifecycleV6","attestation_hash":a["attestation_hash"],"profile_hash":a["subject_hash"],"package_digest":a["package_digest"],"trust_domain_id":d["trust_domain_id"],"observed_sequence_steps":11,"current_utxo_verified":false,"global_name_uniqueness":false,"official_namespace_root_admitted":false,"legacy_migration":false,"live_fee_mass_verified":false,"finality":"NOT_CLAIMED","mainnet_authorized":false,"l1_adapter_status":"NOT_ADMITTED","signing_allowed":false,"broadcast":false,"excluded":["global_namespace_uniqueness","official_namespace_root_binding","legacy_name_migration","current_utxo_availability","consensus_finality","live_fee_mass_admission","mainnet_authority"]}),
        );
    }
    Ok(
        json!({"status":"TESTNET_ADMITTED","formal_admission":"PROVEN","network":"testnet-10","scope":"GENESIS_INTERIOR_ISSUANCE_TERMINAL_CERTIFICATE","attestation_hash":a["attestation_hash"],"profile_hash":a["subject_hash"],"package_digest":a["package_digest"],"trust_domain_id":d["trust_domain_id"],"current_utxo_verified":false,"finality":"NOT_CLAIMED","mainnet_authorized":false,"signing_allowed":false,"broadcast":false,"excluded":["namespace_reallocation","four_output_boundary_split","maximum_key_successor","worst_case_resource_admission","child_lifecycle_profile_admission","generic_adapter_admission"]}),
    )
}
