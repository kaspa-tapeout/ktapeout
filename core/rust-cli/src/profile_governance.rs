//! Local Composition Draft -> Recipe materialization using the existing 0.5.0
//! Recipe/Contract/Effect semantics. This module grants no execution or L1 authority.
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const PROTOCOL: &str = "0.5.0";
const RECIPE_SCHEMA: &str = "KTAPEOUT-COMPOSITION-RECIPE-V1";
const CONTRACT_SCHEMA: &str = "KTAPEOUT-PROFILE-CONTRACT-V1";
const EFFECT_SCHEMA: &str = "KTAPEOUT-EFFECT-MANIFEST-V1";
const COMPARE_BUDGET: usize = 250_000;

#[derive(Clone, Debug)]
pub struct VerifiedProfilePackage {
    pub metadata: Value,
    pub contract: Value,
    pub effect_manifest: Value,
    pub interfaces: Value,
    pub resource_envelope: Value,
}

#[derive(Clone, Debug)]
pub struct ComposedRecipe {
    pub recipe: Value,
    pub composition_root: String,
    pub package_digests: Vec<String>,
}

/// Materialize the existing ApplicationLock V2 tooling object from one
/// verified Recipe and its exact verified Profile Packages.  This function
/// is intentionally local: it grants no signer, submitter or L1 authority.
// Each argument is a separately committed input to the generated lock document.
#[allow(clippy::too_many_arguments)]
pub fn application_lock_v2(
    recipe: &Value,
    packages: &[VerifiedProfilePackage],
    network_policy_id: &str,
    created_at: &str,
    runtime_digest: &str,
    compiler_lock_digest: &str,
    adapter_root: &str,
    abi_root: &str,
    vector_root: &str,
    package_registry_root: &str,
    dependency_root: Option<&str>,
) -> Result<Value, String> {
    if recipe.get("schema").and_then(Value::as_str) != Some(RECIPE_SCHEMA)
        || recipe.get("protocol_semver").and_then(Value::as_str) != Some(PROTOCOL)
    {
        return Err(fail("APPLICATION_LOCK_RECIPE_INVALID"));
    }
    verify_recipe_against_packages(recipe, packages)?;
    let recipe_hash = valid_hash(&recipe["recipe_hash"])
        .ok_or_else(|| fail("APPLICATION_LOCK_RECIPE_HASH_INVALID"))?;
    if valid_id(&Value::String(network_policy_id.to_owned()), 128).is_none()
        || !valid_timestamp(created_at)
    {
        return Err(fail("APPLICATION_LOCK_IDENTITY_INVALID"));
    }
    for (field, value) in [
        ("runtime_digest", runtime_digest),
        ("compiler_lock_digest", compiler_lock_digest),
        ("adapter_root", adapter_root),
        ("abi_root", abi_root),
        ("vector_root", vector_root),
        ("package_registry_root", package_registry_root),
    ] {
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(format!("APPLICATION_LOCK_{field}_INVALID"));
        }
    }
    let components = recipe["components"]
        .as_array()
        .filter(|items| !items.is_empty() && items.len() <= 128)
        .ok_or_else(|| fail("APPLICATION_LOCK_COMPONENTS_INVALID"))?;
    let mut by_digest = BTreeMap::new();
    for package in packages {
        let digest = valid_hash(&package.metadata["package_digest"])
            .ok_or_else(|| fail("APPLICATION_LOCK_PACKAGE_DIGEST_INVALID"))?;
        if by_digest.insert(digest.to_owned(), package).is_some() {
            return Err(fail("APPLICATION_LOCK_PACKAGE_DUPLICATE"));
        }
    }
    let mut bound = Vec::with_capacity(components.len());
    let mut dependency_digests = Vec::with_capacity(components.len());
    for component in components {
        let package_digest = valid_hash(&component["package_digest"])
            .ok_or_else(|| fail("APPLICATION_LOCK_COMPONENT_PACKAGE_INVALID"))?;
        let package = by_digest.get(package_digest).ok_or_else(|| {
            format!(
                "APPLICATION_LOCK_PACKAGE_MISSING:{}",
                component["component_id"]
            )
        })?;
        let metadata = &package.metadata;
        for field in ["profile_id", "profile_hash", "package_digest"] {
            if component[field] != metadata[field] {
                return Err(format!("APPLICATION_LOCK_{field}_MISMATCH"));
            }
        }
        if component["contract_hash"] != package.contract["contract_hash"] {
            return Err(fail("APPLICATION_LOCK_SIDECAR_HASH_MISMATCH"));
        }
        bound.push(json!({
            "component_id": component["component_id"],
            "profile_id": metadata["profile_id"],
            "profile_semver": metadata["profile_semver"],
            "profile_hash": metadata["profile_hash"],
            "contract_hash": package.contract["contract_hash"],
            "effect_hash": package.effect_manifest["effect_hash"],
            "package_digest": metadata["package_digest"],
            "admission_level": metadata["admission_level"],
            "package_provenance": {
                "publisher_id": metadata["publisher_id"],
                "source_ref": metadata["source_ref"],
                "license_ref": metadata["license_ref"],
                "trust_tier": metadata["trust_tier"]
            }
        }));
        dependency_digests.push(Value::String(package_digest.to_owned()));
    }
    let dependency_root = match dependency_root {
        Some(value) if valid_hash(&Value::String(value.to_owned())).is_some() => value.to_owned(),
        Some(_) => return Err(fail("APPLICATION_LOCK_DEPENDENCY_ROOT_INVALID")),
        None => hash_any(
            &Value::Array(dependency_digests),
            "KTAPEOUT/0.5.0/APPLICATION_DEPENDENCY_ROOT/V1",
        )?,
    };
    let mut lock = json!({
        "schema":"KTAPEOUT-APPLICATION-LOCK-V2",
        "protocol_semver":PROTOCOL,
        "lock_hash":"0".repeat(64),
        "recipe_hash":recipe_hash,
        "composition_root":composition_root(recipe)?,
        "components":bound,
        "interface_binding_root":hash_any(&recipe["interface_bindings"], "KTAPEOUT/0.5.0/INTERFACE_BINDING_ROOT/V1")?,
        "effect_scope_root":hash_any(recipe.get("effect_scopes").unwrap_or(&recipe["effect_graph"]), "KTAPEOUT/0.5.0/EFFECT_SCOPE_ROOT/V1")?,
        "resource_policy_hash":hash_any(&recipe["resource_policy"], "KTAPEOUT/0.5.0/RESOURCE_POLICY/V1")?,
        "settlement_policy_hash":hash_any(&recipe["settlement_policy"], "KTAPEOUT/0.5.0/SETTLEMENT_POLICY/V1")?,
        "dependency_root":dependency_root,
        "runtime_digest":runtime_digest,
        "compiler_lock_digest":compiler_lock_digest,
        "network_policy_id":network_policy_id,
        "created_at":created_at,
        "reproducibility_roots":{"adapter_root":adapter_root,"abi_root":abi_root,"vector_root":vector_root,"package_registry_root":package_registry_root}
    });
    let lock_hash = hash(&lock, "KTAPEOUT/0.5.0/APPLICATION_LOCK/V2", &["lock_hash"])?;
    lock["lock_hash"] = Value::String(lock_hash);
    Ok(lock)
}

/// Validate a tooling-only ApplicationLock V2 without requiring package I/O.
/// Package-to-Recipe correspondence is checked when the lock is created;
/// this validator protects later workflow/recovery imports from tampering.
pub fn validate_application_lock_v2(value: &Value) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or_else(|| fail("APPLICATION_LOCK_V2_OBJECT_REQUIRED"))?;
    let required = [
        "schema",
        "protocol_semver",
        "lock_hash",
        "recipe_hash",
        "composition_root",
        "components",
        "interface_binding_root",
        "effect_scope_root",
        "resource_policy_hash",
        "settlement_policy_hash",
        "dependency_root",
        "runtime_digest",
        "compiler_lock_digest",
        "network_policy_id",
        "created_at",
        "reproducibility_roots",
    ];
    if object.len() != required.len()
        || required.iter().any(|field| !object.contains_key(*field))
        || object["schema"] != "KTAPEOUT-APPLICATION-LOCK-V2"
        || object["protocol_semver"] != PROTOCOL
    {
        return Err(fail("APPLICATION_LOCK_V2_FIELDS_INVALID"));
    }
    for field in [
        "lock_hash",
        "recipe_hash",
        "composition_root",
        "interface_binding_root",
        "effect_scope_root",
        "resource_policy_hash",
        "settlement_policy_hash",
        "dependency_root",
        "runtime_digest",
        "compiler_lock_digest",
    ] {
        if valid_hash(&object[field]).is_none() {
            return Err(format!("APPLICATION_LOCK_V2_{field}_INVALID"));
        }
    }
    if valid_id(&object["network_policy_id"], 128).is_none()
        || !object["created_at"].as_str().is_some_and(valid_timestamp)
    {
        return Err(fail("APPLICATION_LOCK_V2_IDENTITY_INVALID"));
    }
    let roots = object["reproducibility_roots"]
        .as_object()
        .ok_or_else(|| fail("APPLICATION_LOCK_V2_ROOTS_INVALID"))?;
    let root_fields = [
        "adapter_root",
        "abi_root",
        "vector_root",
        "package_registry_root",
    ];
    if roots.len() != root_fields.len()
        || root_fields.iter().any(|field| !roots.contains_key(*field))
    {
        return Err(fail("APPLICATION_LOCK_V2_ROOTS_INVALID"));
    }
    for field in root_fields {
        if valid_hash(&roots[field]).is_none() {
            return Err(format!("APPLICATION_LOCK_V2_{field}_INVALID"));
        }
    }
    let components = object["components"]
        .as_array()
        .filter(|items| !items.is_empty() && items.len() <= 128)
        .ok_or_else(|| fail("APPLICATION_LOCK_V2_COMPONENTS_INVALID"))?;
    let mut ids = BTreeSet::new();
    for component in components {
        let component = component
            .as_object()
            .ok_or_else(|| fail("APPLICATION_LOCK_V2_COMPONENT_INVALID"))?;
        let component_fields = [
            "component_id",
            "profile_id",
            "profile_semver",
            "profile_hash",
            "contract_hash",
            "effect_hash",
            "package_digest",
            "admission_level",
            "package_provenance",
        ];
        if component.len() != component_fields.len()
            || component_fields
                .iter()
                .any(|field| !component.contains_key(*field))
        {
            return Err(fail("APPLICATION_LOCK_V2_COMPONENT_FIELDS_INVALID"));
        }
        for field in component_fields {
            if !component.contains_key(field) {
                return Err(fail("APPLICATION_LOCK_V2_COMPONENT_FIELDS_INVALID"));
            }
        }
        let component_id = valid_id(&component["component_id"], 128)
            .ok_or_else(|| fail("APPLICATION_LOCK_V2_COMPONENT_ID_INVALID"))?;
        if !ids.insert(component_id.to_owned())
            || valid_id(&component["profile_id"], 128).is_none()
            || !valid_semver(&component["profile_semver"])
        {
            return Err(fail("APPLICATION_LOCK_V2_COMPONENT_IDENTITY_INVALID"));
        }
        for field in [
            "profile_hash",
            "contract_hash",
            "effect_hash",
            "package_digest",
        ] {
            if valid_hash(&component[field]).is_none() {
                return Err(format!("APPLICATION_LOCK_V2_COMPONENT_{field}_INVALID"));
            }
        }
        if !matches!(
            component["admission_level"].as_str(),
            Some("REFERENCE" | "IMPLEMENTED" | "TESTNET_ADMITTED" | "PRODUCTION_CANDIDATE")
        ) {
            return Err(fail("APPLICATION_LOCK_V2_COMPONENT_ADMISSION_INVALID"));
        }
        let provenance = component["package_provenance"]
            .as_object()
            .ok_or_else(|| fail("APPLICATION_LOCK_V2_PROVENANCE_INVALID"))?;
        let provenance_fields = ["publisher_id", "source_ref", "license_ref", "trust_tier"];
        if provenance.len() != provenance_fields.len()
            || provenance_fields
                .iter()
                .any(|field| !provenance.contains_key(*field))
        {
            return Err(fail("APPLICATION_LOCK_V2_PROVENANCE_INVALID"));
        }
        for field in provenance_fields {
            if !provenance.contains_key(field) {
                return Err(fail("APPLICATION_LOCK_V2_PROVENANCE_INVALID"));
            }
        }
        if valid_id(&provenance["publisher_id"], 128).is_none()
            || !matches!(
                provenance["trust_tier"].as_str(),
                Some("UNTRUSTED" | "COMMUNITY" | "VERIFIED" | "CORE_MAINTAINER")
            )
        {
            return Err(fail("APPLICATION_LOCK_V2_PROVENANCE_INVALID"));
        }
    }
    if hash(value, "KTAPEOUT/0.5.0/APPLICATION_LOCK/V2", &["lock_hash"])? != object["lock_hash"] {
        return Err(fail("APPLICATION_LOCK_V2_HASH_MISMATCH"));
    }
    Ok(())
}

/// Recompute the recipe commitments at the point where the exact recipe and
/// packages are available. A detached lock alone can only be self-consistent.
pub fn validate_recipe_commitments(recipe: &Value) -> Result<(), String> {
    if recipe.get("schema").and_then(Value::as_str) != Some(RECIPE_SCHEMA)
        || recipe.get("protocol_semver").and_then(Value::as_str) != Some(PROTOCOL)
    {
        return Err(fail("APPLICATION_LOCK_RECIPE_INVALID"));
    }
    let expected = hash(
        recipe,
        "KTAPEOUT/0.5.0/COMPOSITION_RECIPE/V1",
        &["recipe_hash", "publisher_signature"],
    )?;
    if recipe.get("recipe_hash").and_then(Value::as_str) != Some(expected.as_str()) {
        return Err(fail("APPLICATION_LOCK_RECIPE_HASH_MISMATCH"));
    }
    Ok(())
}

fn verify_recipe_against_packages(
    recipe: &Value,
    packages: &[VerifiedProfilePackage],
) -> Result<ComposedRecipe, String> {
    validate_recipe_commitments(recipe)?;
    let components = recipe["components"]
        .as_array()
        .filter(|rows| !rows.is_empty() && rows.len() <= 128)
        .ok_or_else(|| fail("APPLICATION_LOCK_RECIPE_COMPONENTS_INVALID"))?;
    let by_digest: BTreeMap<&str, &VerifiedProfilePackage> = packages
        .iter()
        .filter_map(|package| Some((package.metadata["package_digest"].as_str()?, package)))
        .collect();
    if by_digest.len() != packages.len() || by_digest.len() != components.len() {
        return Err(fail("APPLICATION_LOCK_RECIPE_PACKAGE_SET_MISMATCH"));
    }
    let mut draft_components = Vec::with_capacity(components.len());
    for component in components {
        let digest = component["package_digest"]
            .as_str()
            .ok_or_else(|| fail("APPLICATION_LOCK_RECIPE_PACKAGE_INVALID"))?;
        let package = by_digest
            .get(digest)
            .ok_or_else(|| fail("APPLICATION_LOCK_RECIPE_PACKAGE_MISSING"))?;
        draft_components.push(json!({
            "component_id":component["component_id"],
            "contract":package.contract,
            "effect_manifest":package.effect_manifest,
            "package_digest":digest
        }));
    }
    let mut draft = json!({
        "schema":recipe["schema"],"protocol_semver":recipe["protocol_semver"],
        "recipe_id":recipe["recipe_id"],"recipe_semver":recipe["recipe_semver"],
        "components":draft_components,"interface_bindings":recipe["interface_bindings"],
        "state_namespaces":recipe["state_namespaces"],"resource_policy":recipe["resource_policy"],
        "settlement_policy":recipe["settlement_policy"],"test_vectors":recipe["test_vectors"]
    });
    for field in [
        "typed_interface_bindings",
        "effect_scopes",
        "external_requirements",
    ] {
        if let Some(value) = recipe.get(field) {
            draft[field] = value.clone();
        }
    }
    let mut composed = compose_recipe(&draft, packages)?;
    if let Some(publisher_id) = recipe.get("publisher_id") {
        if valid_id(publisher_id, 128).is_none() {
            return Err(fail("APPLICATION_LOCK_RECIPE_PUBLISHER_INVALID"));
        }
        composed.recipe["publisher_id"] = publisher_id.clone();
        let recipe_hash = hash(
            &composed.recipe,
            "KTAPEOUT/0.5.0/COMPOSITION_RECIPE/V1",
            &["recipe_hash", "publisher_signature"],
        )?;
        composed.recipe["recipe_hash"] = Value::String(recipe_hash);
    }
    for field in [
        "recipe_hash",
        "components",
        "interface_bindings",
        "typed_interface_bindings",
        "external_requirements",
        "interface_execution_status",
        "state_namespaces",
        "resource_policy",
        "settlement_policy",
        "test_vectors",
        "effect_graph",
        "effect_scopes",
        "policy_merge",
    ] {
        if let Some(expected) = composed.recipe.get(field) {
            if recipe.get(field) != Some(expected) {
                return Err(format!(
                    "APPLICATION_LOCK_RECIPE_DERIVED_FIELD_MISMATCH:{field}"
                ));
            }
        } else if recipe.get(field).is_some()
            && !matches!(
                field,
                "typed_interface_bindings" | "external_requirements" | "effect_scopes"
            )
        {
            return Err(format!("APPLICATION_LOCK_RECIPE_UNEXPECTED_FIELD:{field}"));
        }
    }
    Ok(composed)
}

fn fail(code: &str) -> String {
    code.to_string()
}

fn hash(value: &Value, domain: &str, excluded: &[&str]) -> Result<String, String> {
    let mut material = value
        .as_object()
        .cloned()
        .ok_or_else(|| fail("PROFILE_COMPOSITION_OBJECT_REQUIRED"))?;
    for key in excluded {
        material.remove(*key);
    }
    let bytes = ktapeout_runtime::canonical_json(&Value::Object(material))
        .map_err(|_| fail("PROFILE_COMPOSITION_CANONICAL_JSON_INVALID"))?;
    let mut digest = Sha256::new();
    digest.update(domain.as_bytes());
    digest.update([0]);
    digest.update(bytes);
    Ok(hex::encode(digest.finalize()))
}

fn hash_any(value: &Value, domain: &str) -> Result<String, String> {
    let bytes = ktapeout_runtime::canonical_json(value)
        .map_err(|_| fail("PROFILE_COMPOSITION_CANONICAL_JSON_INVALID"))?;
    let mut digest = Sha256::new();
    digest.update(domain.as_bytes());
    digest.update([0]);
    digest.update(bytes);
    Ok(hex::encode(digest.finalize()))
}

fn valid_hash(value: &Value) -> Option<&str> {
    let text = value.as_str()?;
    (text.len() == 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    .then_some(text)
}

fn valid_id(value: &Value, max: usize) -> Option<&str> {
    let text = value.as_str()?;
    let bytes = text.as_bytes();
    (!bytes.is_empty()
        && bytes.len() <= max
        && bytes[0].is_ascii_alphanumeric()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(byte)))
    .then_some(text)
}

fn valid_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 20 || bytes.last() != Some(&b'Z') {
        return false;
    }
    for index in [4, 7, 10, 13, 16] {
        let expected = match index {
            4 | 7 => b'-',
            10 => b'T',
            13 | 16 => b':',
            _ => unreachable!(),
        };
        if bytes[index] != expected {
            return false;
        }
    }
    for index in [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18] {
        if !bytes[index].is_ascii_digit() {
            return false;
        }
    }
    bytes.len() == 20
        || (bytes[19] == b'.'
            && bytes.len() > 21
            && bytes[20..bytes.len() - 1].iter().all(u8::is_ascii_digit))
}

fn valid_semver(value: &Value) -> bool {
    value.as_str().is_some_and(|text| {
        text.len() <= 64
            && text.split('.').count() == 3
            && text
                .split('.')
                .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
    })
}

fn exact_keys(value: &Value, required: &[&str], optional: &[&str]) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    required.iter().all(|key| object.contains_key(*key))
        && object
            .keys()
            .all(|key| required.contains(&key.as_str()) || optional.contains(&key.as_str()))
}

fn string_set(value: &Value, max_items: usize, max_len: usize) -> Result<BTreeSet<String>, String> {
    let items = value
        .as_array()
        .filter(|items| items.len() <= max_items)
        .ok_or_else(|| fail("PROFILE_COMPOSITION_STRING_ARRAY_INVALID"))?;
    let mut set = BTreeSet::new();
    for item in items {
        let text = item
            .as_str()
            .filter(|text| !text.is_empty() && text.len() <= max_len)
            .ok_or_else(|| fail("PROFILE_COMPOSITION_STRING_ARRAY_INVALID"))?;
        if !set.insert(text.to_string()) {
            return Err(fail("PROFILE_COMPOSITION_STRING_ARRAY_DUPLICATE"));
        }
    }
    Ok(set)
}

pub fn validate_package_composition_sidecars(
    contract: &Value,
    effect: &Value,
    metadata: &Value,
) -> Result<(), String> {
    validate_contract(contract, metadata)?;
    validate_effect(effect, &metadata["profile_hash"])?;
    if contract["effect_manifest_hash"] != effect["effect_hash"]
        || contract["profile_id"] != effect["profile_id"]
    {
        return Err(fail("PROFILE_COMPOSITION_SIDECAR_BINDING_MISMATCH"));
    }
    Ok(())
}

fn validate_contract(value: &Value, metadata: &Value) -> Result<(), String> {
    let fields = [
        "schema",
        "protocol_semver",
        "profile_id",
        "profile_semver",
        "profile_hash",
        "publisher_id",
        "contract_semver",
        "profile_family",
        "provides",
        "requires",
        "effect_manifest_hash",
        "authority_scope",
        "settlement_modes",
        "wallet_modes",
        "limitations",
        "evidence_policy_hash",
        "contract_hash",
        "publisher_signature",
    ];
    if !exact_keys(value, &fields, &[])
        || value["schema"] != CONTRACT_SCHEMA
        || value["protocol_semver"] != PROTOCOL
    {
        return Err(fail("PROFILE_COMPOSITION_CONTRACT_FIELDS_INVALID"));
    }
    if valid_id(&value["profile_id"], 128).is_none()
        || !valid_semver(&value["profile_semver"])
        || valid_id(&value["contract_semver"], 64).is_none()
        || valid_id(&value["publisher_id"], 128).is_none()
        || valid_hash(&value["profile_hash"]).is_none()
        || valid_hash(&value["effect_manifest_hash"]).is_none()
        || valid_hash(&value["evidence_policy_hash"]).is_none()
        || valid_hash(&value["contract_hash"]).is_none()
        || !value["profile_family"]
            .as_str()
            .is_some_and(|family| !family.is_empty() && family.len() <= 64)
    {
        return Err(fail("PROFILE_COMPOSITION_CONTRACT_IDENTITY_INVALID"));
    }
    for key in [
        "provides",
        "requires",
        "authority_scope",
        "settlement_modes",
        "wallet_modes",
        "limitations",
    ] {
        string_set(&value[key], 128, 256)?;
    }
    if value["profile_id"] != metadata["profile_id"]
        || value["profile_semver"] != metadata["profile_semver"]
        || value["profile_hash"] != metadata["profile_hash"]
        || value["publisher_id"] != metadata["publisher_id"]
    {
        return Err(fail("PROFILE_COMPOSITION_CONTRACT_PACKAGE_MISMATCH"));
    }
    if !value["publisher_signature"].is_null()
        && !value["publisher_signature"]
            .as_str()
            .is_some_and(|signature| !signature.is_empty() && signature.len() <= 4096)
    {
        return Err(fail("PROFILE_COMPOSITION_CONTRACT_SIGNATURE_INVALID"));
    }
    if hash(
        value,
        "KTAPEOUT/0.5.0/PROFILE_CONTRACT/V1",
        &["contract_hash", "publisher_signature"],
    )? != value["contract_hash"]
    {
        return Err(fail("PROFILE_COMPOSITION_CONTRACT_HASH_MISMATCH"));
    }
    Ok(())
}

fn validate_effect(value: &Value, profile_hash: &Value) -> Result<(), String> {
    let fields = [
        "schema",
        "protocol_semver",
        "profile_id",
        "profile_hash",
        "effects",
        "effect_hash",
    ];
    if !exact_keys(value, &fields, &[])
        || value["schema"] != EFFECT_SCHEMA
        || value["protocol_semver"] != PROTOCOL
    {
        return Err(fail("PROFILE_COMPOSITION_EFFECT_FIELDS_INVALID"));
    }
    if valid_id(&value["profile_id"], 128).is_none()
        || valid_hash(&value["profile_hash"]).is_none()
        || valid_hash(&value["effect_hash"]).is_none()
        || &value["profile_hash"] != profile_hash
    {
        return Err(fail("PROFILE_COMPOSITION_EFFECT_IDENTITY_INVALID"));
    }
    let effects = value["effects"]
        .as_array()
        .filter(|effects| effects.len() <= 256)
        .ok_or_else(|| fail("PROFILE_COMPOSITION_EFFECTS_INVALID"))?;
    let mut seen = BTreeSet::new();
    for effect in effects {
        let effect_fields = [
            "effect_id",
            "state_root",
            "selector_kind",
            "selector",
            "access_mode",
            "ordering_key",
            "commutativity_proof",
        ];
        if !exact_keys(effect, &effect_fields, &[]) {
            return Err(fail("PROFILE_COMPOSITION_EFFECT_ENTRY_FIELDS_INVALID"));
        }
        let id = valid_id(&effect["effect_id"], 128)
            .ok_or_else(|| fail("PROFILE_COMPOSITION_EFFECT_ID_INVALID"))?;
        if !seen.insert(id.to_string()) || valid_id(&effect["state_root"], 128).is_none() {
            return Err(fail("PROFILE_COMPOSITION_EFFECT_ID_OR_STATE_INVALID"));
        }
        if !matches!(
            effect["selector_kind"].as_str(),
            Some("EXACT_KEY" | "WILDCARD" | "DOMAIN")
        ) || !effect["selector"]
            .as_str()
            .is_some_and(|selector| !selector.is_empty() && selector.len() <= 512)
            || !matches!(
                effect["access_mode"].as_str(),
                Some("READ" | "WRITE" | "APPEND" | "REDUCE")
            )
        {
            return Err(fail(
                "PROFILE_COMPOSITION_EFFECT_SELECTOR_OR_ACCESS_INVALID",
            ));
        }
        for field in ["ordering_key", "commutativity_proof"] {
            let item = &effect[field];
            if !item.is_null()
                && !item
                    .as_str()
                    .is_some_and(|text| !text.is_empty() && text.len() <= 256)
            {
                return Err(fail("PROFILE_COMPOSITION_EFFECT_OPTIONAL_FIELD_INVALID"));
            }
        }
    }
    if hash(value, "KTAPEOUT/0.5.0/EFFECT_MANIFEST/V1", &["effect_hash"])? != value["effect_hash"] {
        return Err(fail("PROFILE_COMPOSITION_EFFECT_HASH_MISMATCH"));
    }
    Ok(())
}

fn selector_overlap(left: &Value, right: &Value) -> Option<bool> {
    if left["state_root"] != right["state_root"] {
        return Some(false);
    }
    let left_kind = left["selector_kind"].as_str().unwrap_or_default();
    let right_kind = right["selector_kind"].as_str().unwrap_or_default();
    if left_kind == "EXACT_KEY" && right_kind == "EXACT_KEY" {
        return Some(left["selector"] == right["selector"]);
    }
    if left_kind == "WILDCARD" || right_kind == "WILDCARD" {
        return Some(true);
    }
    None
}

fn effect_conflicts(left: &Value, right: &Value, budget: &mut usize) -> Result<Vec<Value>, String> {
    let mut conflicts = Vec::new();
    for a in left["effects"].as_array().into_iter().flatten() {
        for b in right["effects"].as_array().into_iter().flatten() {
            *budget = budget
                .checked_add(1)
                .ok_or_else(|| fail("PROFILE_COMPOSITION_COMPARE_BUDGET"))?;
            if *budget > COMPARE_BUDGET {
                return Err(fail("PROFILE_COMPOSITION_COMPARE_BUDGET"));
            }
            let overlap = selector_overlap(a, b);
            if overlap == Some(false) {
                continue;
            }
            let writes = [a, b]
                .iter()
                .any(|item| !matches!(item["access_mode"].as_str(), Some("READ")));
            if !writes {
                continue;
            }
            conflicts.push(json!({
                "left_effect": a["effect_id"], "right_effect": b["effect_id"],
                "state_root": a["state_root"],
                "selector_relation": if overlap == Some(true) { "OVERLAP" } else { "UNKNOWN" },
                "status": if overlap.is_none() { "UNRESOLVED_CONFLICT" } else { "CONFLICT" },
                "reason": "shared mutable state requires ordering or a bounded Adapter proof"
            }));
        }
    }
    Ok(conflicts)
}

fn validate_bindings(bindings: &Value, contracts: &BTreeMap<String, Value>) -> Result<(), String> {
    let rows = bindings
        .as_array()
        .filter(|rows| rows.len() <= 256)
        .ok_or_else(|| fail("PROFILE_COMPOSITION_BINDINGS_INVALID"))?;
    let mut seen = BTreeSet::new();
    for binding in rows {
        let keys = ["consumer", "requirement", "provider", "capability"];
        if !exact_keys(binding, &keys, &[]) {
            return Err(fail("PROFILE_COMPOSITION_BINDING_FIELDS_INVALID"));
        }
        let consumer = valid_id(&binding["consumer"], 128)
            .ok_or_else(|| fail("PROFILE_COMPOSITION_BINDING_COMPONENT_INVALID"))?;
        let provider = valid_id(&binding["provider"], 128)
            .ok_or_else(|| fail("PROFILE_COMPOSITION_BINDING_COMPONENT_INVALID"))?;
        let requirement = valid_id(&binding["requirement"], 128)
            .ok_or_else(|| fail("PROFILE_COMPOSITION_BINDING_CAPABILITY_INVALID"))?;
        let capability = valid_id(&binding["capability"], 128)
            .ok_or_else(|| fail("PROFILE_COMPOSITION_BINDING_CAPABILITY_INVALID"))?;
        if consumer == provider
            || !contracts.contains_key(consumer)
            || !contracts.contains_key(provider)
        {
            return Err(fail("PROFILE_COMPOSITION_BINDING_COMPONENT_INVALID"));
        }
        let consumer_requires = string_set(&contracts[consumer]["requires"], 128, 256)?;
        let provider_provides = string_set(&contracts[provider]["provides"], 128, 256)?;
        if !consumer_requires.contains(requirement)
            || !provider_provides.contains(capability)
            || requirement != capability
        {
            return Err(fail("PROFILE_COMPOSITION_BINDING_UNSATISFIED"));
        }
        if !seen.insert((
            consumer.to_string(),
            requirement.to_string(),
            provider.to_string(),
            capability.to_string(),
        )) {
            return Err(fail("PROFILE_COMPOSITION_BINDING_DUPLICATE"));
        }
    }
    Ok(())
}

fn resolve_bindings(
    bindings: &Value,
    external_requirements: &Value,
    contracts: &BTreeMap<String, Value>,
) -> Result<Value, String> {
    let rows = bindings
        .as_array()
        .filter(|rows| rows.len() <= 256)
        .ok_or_else(|| fail("PROFILE_COMPOSITION_BINDINGS_INVALID"))?;
    let mut resolved = rows.clone();
    let mut provider_index = BTreeMap::<String, Vec<String>>::new();
    for (provider, contract) in contracts {
        for capability in string_set(&contract["provides"], 128, 256)? {
            provider_index
                .entry(capability)
                .or_default()
                .push(provider.clone());
        }
    }
    let external_rows = if external_requirements.is_null() {
        &[][..]
    } else {
        external_requirements
            .as_array()
            .filter(|items| items.len() <= 256)
            .ok_or_else(|| fail("PROFILE_COMPOSITION_EXTERNAL_REQUIREMENTS_INVALID"))?
    };
    let mut external = BTreeSet::new();
    for row in external_rows {
        if !exact_keys(
            row,
            &["consumer", "requirement", "source", "evidence_policy_hash"],
            &[],
        ) {
            return Err(fail(
                "PROFILE_COMPOSITION_EXTERNAL_REQUIREMENT_FIELDS_INVALID",
            ));
        }
        let consumer = valid_id(&row["consumer"], 128)
            .ok_or_else(|| fail("PROFILE_COMPOSITION_EXTERNAL_REQUIREMENT_ID_INVALID"))?;
        let requirement = valid_id(&row["requirement"], 128)
            .ok_or_else(|| fail("PROFILE_COMPOSITION_EXTERNAL_REQUIREMENT_ID_INVALID"))?;
        if !contracts.contains_key(consumer)
            || !string_set(&contracts[consumer]["requires"], 128, 256)?.contains(requirement)
            || valid_id(&row["source"], 256).is_none()
            || valid_hash(&row["evidence_policy_hash"]).is_none()
            || !external.insert((consumer.to_string(), requirement.to_string()))
        {
            return Err(fail("PROFILE_COMPOSITION_EXTERNAL_REQUIREMENT_INVALID"));
        }
    }
    for (consumer, contract) in contracts {
        for requirement in string_set(&contract["requires"], 128, 256)? {
            let explicit: Vec<&Value> = resolved
                .iter()
                .filter(|row| {
                    row["consumer"].as_str() == Some(consumer.as_str())
                        && row["requirement"].as_str() == Some(requirement.as_str())
                })
                .collect();
            let candidates: Vec<&String> = provider_index
                .get(&requirement)
                .into_iter()
                .flatten()
                .filter(|provider| *provider != consumer)
                .collect();
            let external_key = (consumer.clone(), requirement.clone());
            if external.contains(&external_key) {
                if !explicit.is_empty() || !candidates.is_empty() {
                    return Err(fail("PROFILE_COMPOSITION_EXTERNAL_REQUIREMENT_AMBIGUOUS"));
                }
                continue;
            }
            if explicit.len() > 1 {
                return Err(fail("PROFILE_COMPOSITION_REQUIREMENT_BOUND_MULTIPLE"));
            }
            if let Some(binding) = explicit.first() {
                let provider = binding["provider"].as_str().unwrap_or_default();
                if !candidates
                    .iter()
                    .any(|candidate| candidate.as_str() == provider)
                {
                    return Err(fail("PROFILE_COMPOSITION_BINDING_UNSATISFIED"));
                }
            } else if candidates.len() == 1 {
                resolved.push(json!({"consumer":consumer,"requirement":requirement,"provider":candidates[0],"capability":requirement}));
            } else if candidates.is_empty() {
                return Err(format!(
                    "PROFILE_COMPOSITION_REQUIREMENT_UNBOUND:{consumer}:{requirement}"
                ));
            } else {
                return Err(format!(
                    "PROFILE_COMPOSITION_REQUIREMENT_AMBIGUOUS:{consumer}:{requirement}"
                ));
            }
        }
    }
    validate_bindings(&Value::Array(resolved.clone()), contracts)?;
    Ok(Value::Array(resolved))
}

fn validate_typed_bindings(
    value: &Value,
    components: &BTreeMap<String, (Value, Value)>,
) -> Result<(), String> {
    let rows = value
        .as_array()
        .filter(|rows| rows.len() <= 256)
        .ok_or_else(|| fail("PROFILE_COMPOSITION_TYPED_BINDINGS_INVALID"))?;
    let required = [
        "schema",
        "interface_id",
        "interface_version",
        "consumer",
        "provider",
        "input_schema_hash",
        "output_schema_hash",
        "error_schema_hash",
        "wallet_mode",
        "settlement_mode",
        "adapter_hash",
    ];
    let mut seen = BTreeSet::new();
    for row in rows {
        if !exact_keys(row, &required, &[]) || row["schema"] != "KTAPEOUT-INTERFACE-BINDING-V1" {
            return Err(fail("PROFILE_COMPOSITION_TYPED_BINDING_FIELDS_INVALID"));
        }
        for field in ["interface_id", "consumer", "provider"] {
            if valid_id(&row[field], 128).is_none() {
                return Err(fail("PROFILE_COMPOSITION_TYPED_BINDING_ID_INVALID"));
            }
        }
        let consumer = row["consumer"].as_str().unwrap();
        let provider = row["provider"].as_str().unwrap();
        if consumer == provider
            || !components.contains_key(consumer)
            || !components.contains_key(provider)
            || !valid_semver(&row["interface_version"])
            || [
                "input_schema_hash",
                "output_schema_hash",
                "error_schema_hash",
            ]
            .iter()
            .any(|field| valid_hash(&row[field]).is_none())
            || !matches!(
                row["wallet_mode"].as_str(),
                Some("wallet" | "walletless-read")
            )
            || !row["settlement_mode"]
                .as_str()
                .is_some_and(|text| !text.is_empty() && text.len() <= 128)
            || (!row["adapter_hash"].is_null() && valid_hash(&row["adapter_hash"]).is_none())
        {
            return Err(fail("PROFILE_COMPOSITION_TYPED_BINDING_INVALID"));
        }
        let (consumer_contract, consumer_interfaces) = &components[consumer];
        let (provider_contract, provider_interfaces) = &components[provider];
        let consumer_definition = find_interface_definition(
            consumer_interfaces,
            row["interface_id"].as_str().unwrap(),
            &row["interface_version"],
            "REQUIRES",
        )?;
        let provider_definition = find_interface_definition(
            provider_interfaces,
            row["interface_id"].as_str().unwrap(),
            &row["interface_version"],
            "PROVIDES",
        )?;
        for field in [
            "input_schema_hash",
            "output_schema_hash",
            "error_schema_hash",
        ] {
            if row[field] != consumer_definition[field] || row[field] != provider_definition[field]
            {
                return Err(fail("PROFILE_COMPOSITION_TYPED_BINDING_SCHEMA_MISMATCH"));
            }
        }
        for (contract, definition) in [
            (consumer_contract, consumer_definition),
            (provider_contract, provider_definition),
        ] {
            let wallet_modes = string_set(&contract["wallet_modes"], 128, 256)?;
            let declared_wallets = string_set(&definition["wallet_modes"], 8, 32)?;
            if !declared_wallets.is_subset(&wallet_modes) {
                return Err(fail("PROFILE_COMPOSITION_INTERFACE_WALLET_EXPANSION"));
            }
            let settlement_modes = string_set(&contract["settlement_modes"], 128, 256)?;
            let declared_settlement = string_set(&definition["settlement_modes"], 8, 32)?;
            if !declared_settlement.is_subset(&settlement_modes) {
                return Err(fail("PROFILE_COMPOSITION_INTERFACE_SETTLEMENT_EXPANSION"));
            }
        }
        let mode = row["wallet_mode"].as_str().unwrap();
        let contract_mode = match mode {
            "wallet" => "WALLET",
            "walletless-read" => "WALLETLESS",
            _ => unreachable!(),
        };
        if !consumer_definition["wallet_modes"]
            .as_array()
            .is_some_and(|modes| modes.iter().any(|value| value == contract_mode))
            || !provider_definition["wallet_modes"]
                .as_array()
                .is_some_and(|modes| modes.iter().any(|value| value == contract_mode))
        {
            return Err(fail(
                "PROFILE_COMPOSITION_TYPED_BINDING_WALLET_MODE_UNSUPPORTED",
            ));
        }
        let settlement = row["settlement_mode"].as_str().unwrap();
        if !consumer_definition["settlement_modes"]
            .as_array()
            .is_some_and(|modes| modes.iter().any(|value| value == settlement))
            || !provider_definition["settlement_modes"]
                .as_array()
                .is_some_and(|modes| modes.iter().any(|value| value == settlement))
        {
            return Err(fail(
                "PROFILE_COMPOSITION_TYPED_BINDING_SETTLEMENT_MODE_UNSUPPORTED",
            ));
        }
        if mode == "walletless-read"
            && (consumer_definition["consumption"] != "READ_ONLY"
                || provider_definition["consumption"] != "READ_ONLY")
        {
            return Err(fail(
                "PROFILE_COMPOSITION_WALLETLESS_READ_MUTATION_UNSUPPORTED",
            ));
        }
        if consumer_definition["consumption"] != provider_definition["consumption"]
            || consumer_definition["evidence_verifier"] != provider_definition["evidence_verifier"]
            || consumer_definition["result_finality"] != provider_definition["result_finality"]
            || consumer_definition["resource_bound"] != provider_definition["resource_bound"]
        {
            return Err(fail("PROFILE_COMPOSITION_TYPED_BINDING_SEMANTICS_MISMATCH"));
        }
        if !row["adapter_hash"].is_null() {
            return Err(fail("PROFILE_COMPOSITION_TYPED_ADAPTER_UNSUPPORTED"));
        }
        let key = (
            consumer.to_string(),
            provider.to_string(),
            row["interface_id"].as_str().unwrap().to_string(),
        );
        if !seen.insert(key) {
            return Err(fail("PROFILE_COMPOSITION_TYPED_BINDING_DUPLICATE"));
        }
    }
    Ok(())
}

fn find_interface_definition<'a>(
    interfaces: &'a Value,
    interface_id: &str,
    version: &Value,
    role: &str,
) -> Result<&'a Value, String> {
    let definitions = interfaces
        .get("interface_definitions")
        .and_then(Value::as_array)
        .ok_or_else(|| fail("PROFILE_COMPOSITION_TYPED_BINDING_INTERFACE_UNDECLARED"))?;
    let found: Vec<&Value> = definitions
        .iter()
        .filter(|definition| {
            definition.get("interface_id").and_then(Value::as_str) == Some(interface_id)
                && definition.get("interface_version") == Some(version)
                && definition.get("role").and_then(Value::as_str) == Some(role)
        })
        .collect();
    if found.len() != 1 {
        return Err(fail(
            "PROFILE_COMPOSITION_TYPED_BINDING_INTERFACE_UNDECLARED_OR_AMBIGUOUS",
        ));
    }
    Ok(found[0])
}

fn validate_interface_definitions(
    interfaces: &Value,
    contract: &Value,
    resource_envelope: &Value,
) -> Result<(), String> {
    let Some(value) = interfaces.get("interface_definitions") else {
        return Ok(());
    };
    let rows = value
        .as_array()
        .filter(|rows| rows.len() <= 64)
        .ok_or_else(|| fail("PROFILE_COMPOSITION_INTERFACE_DEFINITIONS_INVALID"))?;
    let provides = string_set(&contract["provides"], 128, 256)?;
    let requires = string_set(&contract["requires"], 128, 256)?;
    let contract_wallets = string_set(&contract["wallet_modes"], 128, 256)?;
    let contract_settlements = string_set(&contract["settlement_modes"], 128, 256)?;
    let mut seen = BTreeSet::new();
    for row in rows {
        let fields = [
            "schema",
            "interface_id",
            "interface_version",
            "role",
            "entrypoint",
            "input_schema",
            "output_schema",
            "error_schema",
            "input_schema_hash",
            "output_schema_hash",
            "error_schema_hash",
            "wallet_modes",
            "settlement_modes",
            "consumption",
            "evidence_verifier",
            "result_finality",
            "resource_bound",
        ];
        if !exact_keys(row, &fields, &[]) || row["schema"] != "KTAPEOUT-INTERFACE-DEFINITION-V1" {
            return Err(fail(
                "PROFILE_COMPOSITION_INTERFACE_DEFINITION_FIELDS_INVALID",
            ));
        }
        let id = valid_id(&row["interface_id"], 128)
            .ok_or_else(|| fail("PROFILE_COMPOSITION_INTERFACE_DEFINITION_ID_INVALID"))?;
        if !valid_semver(&row["interface_version"])
            || !matches!(row["role"].as_str(), Some("PROVIDES" | "REQUIRES"))
            || valid_id(&row["entrypoint"], 128).is_none()
            || valid_id(&row["result_finality"], 128).is_none()
            || valid_id(&row["resource_bound"], 128).is_none()
        {
            return Err(fail(
                "PROFILE_COMPOSITION_INTERFACE_DEFINITION_IDENTITY_INVALID",
            ));
        }
        if !interfaces["entrypoints"]
            .as_array()
            .is_some_and(|items| items.iter().any(|entry| entry == &row["entrypoint"]))
            || resource_envelope
                .get(row["resource_bound"].as_str().unwrap_or_default())
                .is_none()
        {
            return Err(fail(
                "PROFILE_COMPOSITION_INTERFACE_RESOURCE_OR_ENTRYPOINT_UNBOUND",
            ));
        }
        let role = row["role"].as_str().unwrap();
        let declared = if role == "PROVIDES" {
            &provides
        } else {
            &requires
        };
        if !declared.contains(id) {
            return Err(fail("PROFILE_COMPOSITION_INTERFACE_CONTRACT_LINK_MISSING"));
        }
        let key = (
            id.to_owned(),
            row["interface_version"].as_str().unwrap().to_owned(),
            role.to_owned(),
        );
        if !seen.insert(key) {
            return Err(fail("PROFILE_COMPOSITION_INTERFACE_DEFINITION_DUPLICATE"));
        }
        for (schema_field, hash_field, domain) in [
            (
                "input_schema",
                "input_schema_hash",
                "KTAPEOUT/0.5.0/INTERFACE_INPUT_SCHEMA/V1",
            ),
            (
                "output_schema",
                "output_schema_hash",
                "KTAPEOUT/0.5.0/INTERFACE_OUTPUT_SCHEMA/V1",
            ),
            (
                "error_schema",
                "error_schema_hash",
                "KTAPEOUT/0.5.0/INTERFACE_ERROR_SCHEMA/V1",
            ),
        ] {
            if !row[schema_field].is_object()
                || valid_hash(&row[hash_field]).is_none()
                || hash_any(&row[schema_field], domain)? != row[hash_field]
            {
                return Err(fail("PROFILE_COMPOSITION_INTERFACE_SCHEMA_HASH_MISMATCH"));
            }
        }
        let wallets = string_set(&row["wallet_modes"], 8, 32)?;
        let settlements = string_set(&row["settlement_modes"], 8, 32)?;
        if wallets.is_empty()
            || !wallets.is_subset(&contract_wallets)
            || settlements.is_empty()
            || !settlements.is_subset(&contract_settlements)
        {
            return Err(fail("PROFILE_COMPOSITION_INTERFACE_POLICY_EXPANSION"));
        }
        if !matches!(
            row["consumption"].as_str(),
            Some("READ_ONLY" | "CONSUME_ONCE" | "REUSABLE_EVIDENCE")
        ) {
            return Err(fail("PROFILE_COMPOSITION_INTERFACE_CONSUMPTION_INVALID"));
        }
        if !row["evidence_verifier"].is_null() {
            let verifier = &row["evidence_verifier"];
            if !exact_keys(verifier, &["id", "hash"], &[])
                || valid_id(&verifier["id"], 128).is_none()
                || valid_hash(&verifier["hash"]).is_none()
            {
                return Err(fail("PROFILE_COMPOSITION_INTERFACE_VERIFIER_INVALID"));
            }
        }
    }
    Ok(())
}

fn validate_effect_scopes(value: &Value, component_ids: &BTreeSet<String>) -> Result<(), String> {
    let rows = value
        .as_array()
        .filter(|rows| rows.len() <= 256)
        .ok_or_else(|| fail("PROFILE_COMPOSITION_EFFECT_SCOPES_INVALID"))?;
    let fields = [
        "schema",
        "component_id",
        "state_root",
        "selector_kind",
        "selector",
        "input_outpoint_scope",
        "authority_scope",
        "nonce_scope",
        "resource_scope",
        "settlement_scope",
        "escrow_scope",
        "access_mode",
        "ordering_key",
        "commutativity_proof",
        "scope_hash",
    ];
    let mut seen = BTreeSet::new();
    for row in rows {
        if !exact_keys(row, &fields, &[]) || row["schema"] != "KTAPEOUT-EFFECT-SCOPE-V1" {
            return Err(fail("PROFILE_COMPOSITION_EFFECT_SCOPE_FIELDS_INVALID"));
        }
        let id = valid_id(&row["component_id"], 128)
            .ok_or_else(|| fail("PROFILE_COMPOSITION_EFFECT_SCOPE_COMPONENT_INVALID"))?;
        let scope_key = (
            id.to_string(),
            row["state_root"].as_str().unwrap_or_default().to_string(),
            row["selector_kind"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            row["selector"].as_str().unwrap_or_default().to_string(),
        );
        if !component_ids.contains(id)
            || !seen.insert(scope_key)
            || valid_id(&row["state_root"], 128).is_none()
        {
            return Err(fail("PROFILE_COMPOSITION_EFFECT_SCOPE_COMPONENT_INVALID"));
        }
        if !matches!(
            row["selector_kind"].as_str(),
            Some("EXACT_KEY" | "WILDCARD" | "DOMAIN")
        ) || !row["selector"]
            .as_str()
            .is_some_and(|x| !x.is_empty() && x.len() <= 256)
        {
            return Err(fail("PROFILE_COMPOSITION_EFFECT_SCOPE_SELECTOR_INVALID"));
        }
        for field in [
            "input_outpoint_scope",
            "authority_scope",
            "nonce_scope",
            "resource_scope",
            "settlement_scope",
            "escrow_scope",
        ] {
            string_set(&row[field], 64, 256)?;
        }
        if !matches!(
            row["access_mode"].as_str(),
            Some("READ" | "WRITE" | "APPEND" | "REDUCE")
        ) {
            return Err(fail("PROFILE_COMPOSITION_EFFECT_SCOPE_ACCESS_INVALID"));
        }
        if !row["ordering_key"].is_null() && valid_id(&row["ordering_key"], 128).is_none() {
            return Err(fail("PROFILE_COMPOSITION_EFFECT_SCOPE_ORDERING_INVALID"));
        }
        if !row["commutativity_proof"].is_null()
            && valid_hash(&row["commutativity_proof"]).is_none()
        {
            return Err(fail("PROFILE_COMPOSITION_EFFECT_SCOPE_PROOF_INVALID"));
        }
        if valid_hash(&row["scope_hash"]).is_none()
            || hash(row, "KTAPEOUT/0.5.0/EFFECT_SCOPE/V1", &["scope_hash"])? != row["scope_hash"]
        {
            return Err(fail("PROFILE_COMPOSITION_EFFECT_SCOPE_HASH_MISMATCH"));
        }
    }
    Ok(())
}

fn validate_effect_scopes_against(
    scopes: &Value,
    effects: &BTreeMap<String, Value>,
) -> Result<(), String> {
    let rows = scopes
        .as_array()
        .ok_or_else(|| fail("PROFILE_COMPOSITION_EFFECT_SCOPES_INVALID"))?;
    let mut exclusive = BTreeMap::<(&str, &str), String>::new();
    for scope in rows {
        let component = scope["component_id"].as_str().unwrap_or_default();
        let manifest = effects
            .get(component)
            .ok_or_else(|| fail("PROFILE_COMPOSITION_EFFECT_SCOPE_COMPONENT_INVALID"))?;
        let matching = manifest["effects"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|effect| {
                effect["state_root"] == scope["state_root"]
                    && effect["selector_kind"] == scope["selector_kind"]
                    && effect["selector"] == scope["selector"]
                    && effect["access_mode"] == scope["access_mode"]
                    && effect["ordering_key"] == scope["ordering_key"]
                    && effect["commutativity_proof"] == scope["commutativity_proof"]
            })
            .count();
        if matching != 1 {
            return Err(fail(
                "PROFILE_COMPOSITION_EFFECT_SCOPE_NOT_BACKED_BY_MANIFEST",
            ));
        }
        if scope["access_mode"] == "READ" {
            continue;
        }
        for field in ["input_outpoint_scope", "nonce_scope", "authority_scope"] {
            for item in scope[field].as_array().into_iter().flatten() {
                let value = item.as_str().unwrap_or_default();
                if let Some(previous) = exclusive.insert((field, value), component.to_string()) {
                    if previous != component {
                        return Err(format!("PROFILE_COMPOSITION_EFFECT_SCOPE_SHARED_EXCLUSIVE_RESOURCE:{field}:{value}"));
                    }
                }
            }
        }
    }
    Ok(())
}

fn policy_merge(
    contracts: &BTreeMap<String, Value>,
    resource_policy: &Value,
    settlement_policy: &Value,
) -> Result<Value, String> {
    if contracts.is_empty() || !resource_policy.is_object() || !settlement_policy.is_object() {
        return Err(fail("PROFILE_COMPOSITION_POLICY_OBJECT_INVALID"));
    }
    let mut wallet_modes: Option<BTreeSet<String>> = None;
    let mut settlement_modes: Option<BTreeSet<String>> = None;
    let mut authority_scope = BTreeSet::new();
    for contract in contracts.values() {
        let wallets = string_set(&contract["wallet_modes"], 128, 256)?;
        let settlements = string_set(&contract["settlement_modes"], 128, 256)?;
        wallet_modes = Some(match wallet_modes {
            None => wallets,
            Some(current) => current.intersection(&wallets).cloned().collect(),
        });
        settlement_modes = Some(match settlement_modes {
            None => settlements,
            Some(current) => current.intersection(&settlements).cloned().collect(),
        });
        authority_scope.extend(string_set(&contract["authority_scope"], 128, 256)?);
    }
    let atomicity = match settlement_policy.get("atomicity") {
        None => "PER_COMPONENT",
        Some(value) => value
            .as_str()
            .ok_or_else(|| fail("PROFILE_COMPOSITION_ATOMICITY_INVALID"))?,
    };
    if !matches!(atomicity, "PER_COMPONENT" | "GROUP" | "ATOMIC") {
        return Err(fail("PROFILE_COMPOSITION_ATOMICITY_INVALID"));
    }
    let limits = resource_policy
        .get("limits")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let limits = limits
        .as_object()
        .filter(|x| x.len() <= 64)
        .ok_or_else(|| fail("PROFILE_COMPOSITION_RESOURCE_LIMITS_INVALID"))?;
    let mut normalized = Map::new();
    for (key, value) in limits {
        if valid_id(&Value::String(key.clone()), 128).is_none()
            || value.as_u64().filter(|v| *v <= 10_000_000_000).is_none()
        {
            return Err(fail("PROFILE_COMPOSITION_RESOURCE_LIMIT_INVALID"));
        }
        normalized.insert(key.clone(), value.clone());
    }
    let wallets = wallet_modes.unwrap_or_default();
    let settlements = settlement_modes.unwrap_or_default();
    let status = if !wallets.is_empty() && !settlements.is_empty() && atomicity == "PER_COMPONENT" {
        "VALID"
    } else {
        "UNRESOLVED_CONFLICT"
    };
    let boundary = settlement_policy
        .get("boundary")
        .and_then(Value::as_array)
        .map(|items| {
            let mut strings: Vec<String> = items
                .iter()
                .map(|item| {
                    item.as_str()
                        .map(str::to_string)
                        .unwrap_or_else(|| item.to_string())
                })
                .collect();
            strings.sort();
            strings
        })
        .unwrap_or_default();
    let mut result = json!({"schema":"KTAPEOUT-POLICY-MERGE-V1","protocol_semver":PROTOCOL,"wallet_modes":wallets,"settlement_modes":settlements,"authority_scope":authority_scope,"atomicity":atomicity,"resource_totals":normalized,"settlement_boundary":boundary,"status":status});
    let merge_hash = hash(&result, "KTAPEOUT/0.5.0/POLICY_MERGE/V1", &[])?;
    result
        .as_object_mut()
        .unwrap()
        .insert("merge_hash".into(), Value::String(merge_hash));
    Ok(result)
}

fn composition_root(recipe: &Value) -> Result<String, String> {
    let mut material = Map::new();
    for field in [
        "recipe_hash",
        "components",
        "interface_bindings",
        "state_namespaces",
        "resource_policy",
        "settlement_policy",
    ] {
        material.insert(field.into(), recipe[field].clone());
    }
    for field in ["effect_graph", "effect_scopes", "policy_merge"] {
        material.insert(
            field.into(),
            recipe.get(field).cloned().unwrap_or(Value::Null),
        );
    }
    hash(
        &Value::Object(material),
        "KTAPEOUT/0.5.0/COMPOSITION_ROOT/V1",
        &[],
    )
}

pub fn compose_recipe(
    draft: &Value,
    packages: &[VerifiedProfilePackage],
) -> Result<ComposedRecipe, String> {
    let required = [
        "schema",
        "protocol_semver",
        "recipe_id",
        "recipe_semver",
        "components",
        "interface_bindings",
        "state_namespaces",
        "resource_policy",
        "settlement_policy",
        "test_vectors",
    ];
    let optional = [
        "typed_interface_bindings",
        "effect_scopes",
        "external_requirements",
    ];
    if !exact_keys(draft, &required, &optional)
        || draft["schema"] != RECIPE_SCHEMA
        || draft["protocol_semver"] != PROTOCOL
    {
        return Err(fail("PROFILE_COMPOSITION_DRAFT_IDENTITY_OR_FIELDS_INVALID"));
    }
    if valid_id(&draft["recipe_id"], 128).is_none() || !valid_semver(&draft["recipe_semver"]) {
        return Err(fail("PROFILE_COMPOSITION_RECIPE_ID_INVALID"));
    }
    let raw_components = draft["components"]
        .as_array()
        .filter(|rows| !rows.is_empty() && rows.len() <= 128)
        .ok_or_else(|| fail("PROFILE_COMPOSITION_COMPONENTS_INVALID"))?;
    if packages.len() != raw_components.len() {
        return Err(fail("PROFILE_COMPOSITION_PACKAGE_SET_MISMATCH"));
    }
    let mut package_by_digest = BTreeMap::new();
    for package in packages {
        let digest = valid_hash(&package.metadata["package_digest"])
            .ok_or_else(|| fail("PROFILE_COMPOSITION_PACKAGE_DIGEST_INVALID"))?;
        if package_by_digest
            .insert(digest.to_string(), package)
            .is_some()
        {
            return Err(fail("PROFILE_COMPOSITION_PACKAGE_DUPLICATE"));
        }
    }
    let mut components = Vec::new();
    let mut contracts = BTreeMap::new();
    let mut effects = BTreeMap::new();
    let mut seen_profiles = BTreeSet::new();
    let mut package_digests = Vec::new();
    for item in raw_components {
        let fields = [
            "component_id",
            "contract",
            "effect_manifest",
            "package_digest",
        ];
        if !exact_keys(item, &fields, &[]) {
            return Err(fail("PROFILE_COMPOSITION_DRAFT_COMPONENT_FIELDS_INVALID"));
        }
        let component_id = valid_id(&item["component_id"], 128)
            .ok_or_else(|| fail("PROFILE_COMPOSITION_COMPONENT_ID_INVALID"))?;
        if contracts.contains_key(component_id) {
            return Err(fail("PROFILE_COMPOSITION_COMPONENT_ID_DUPLICATE"));
        }
        let package_digest = valid_hash(&item["package_digest"])
            .ok_or_else(|| fail("PROFILE_COMPOSITION_PACKAGE_DIGEST_INVALID"))?;
        let package = package_by_digest
            .get(package_digest)
            .ok_or_else(|| fail("PROFILE_COMPOSITION_PACKAGE_MISSING"))?;
        validate_contract(&item["contract"], &package.metadata)?;
        validate_effect(&item["effect_manifest"], &package.metadata["profile_hash"])?;
        if item["contract"] != package.contract
            || item["effect_manifest"] != package.effect_manifest
        {
            return Err(fail("PROFILE_COMPOSITION_DRAFT_PACKAGE_SIDECAR_MISMATCH"));
        }
        if item["contract"]["effect_manifest_hash"] != item["effect_manifest"]["effect_hash"] {
            return Err(fail("PROFILE_COMPOSITION_CONTRACT_EFFECT_MISMATCH"));
        }
        if item["contract"]["profile_id"] != item["effect_manifest"]["profile_id"] {
            return Err(fail("PROFILE_COMPOSITION_CONTRACT_EFFECT_MISMATCH"));
        }
        let profile_hash = item["contract"]["profile_hash"].as_str().unwrap();
        if !seen_profiles.insert(profile_hash.to_string()) {
            return Err(fail("PROFILE_COMPOSITION_PROFILE_DUPLICATE"));
        }
        let contract = item["contract"].clone();
        let effect = item["effect_manifest"].clone();
        validate_interface_definitions(&package.interfaces, &contract, &package.resource_envelope)?;
        contracts.insert(component_id.to_string(), contract.clone());
        effects.insert(component_id.to_string(), effect.clone());
        components.push(json!({"component_id":component_id,"profile_id":contract["profile_id"],"profile_hash":contract["profile_hash"],"contract_hash":contract["contract_hash"],"package_digest":package_digest}));
        package_digests.push(package_digest.to_string());
    }
    let ids: Vec<String> = components
        .iter()
        .map(|component| component["component_id"].as_str().unwrap().to_string())
        .collect();
    let mut conflicts = Vec::new();
    let mut compare_budget = 0usize;
    for i in 0..ids.len() {
        for j in (i + 1)..ids.len() {
            for conflict in
                effect_conflicts(&effects[&ids[i]], &effects[&ids[j]], &mut compare_budget)?
            {
                let mut row = Map::new();
                row.insert("left_component".into(), json!(ids[i]));
                row.insert("right_component".into(), json!(ids[j]));
                row.extend(conflict.as_object().unwrap().clone());
                conflicts.push(Value::Object(row));
            }
        }
    }
    if !conflicts.is_empty() {
        return Err(format!(
            "PROFILE_COMPOSITION_EFFECT_CONFLICT:{}",
            Value::Array(conflicts)
        ));
    }
    let external_requirements = draft
        .get("external_requirements")
        .cloned()
        .unwrap_or(Value::Null);
    let normalized_bindings = resolve_bindings(
        &draft["interface_bindings"],
        &external_requirements,
        &contracts,
    )?;
    let component_ids: BTreeSet<String> = ids.iter().cloned().collect();
    if let Some(bindings) = draft.get("typed_interface_bindings") {
        let typed_components: BTreeMap<String, (Value, Value)> = components
            .iter()
            .filter_map(|component| {
                let id = component["component_id"].as_str()?;
                let package = package_by_digest.get(component["package_digest"].as_str()?)?;
                Some((
                    id.to_string(),
                    (package.contract.clone(), package.interfaces.clone()),
                ))
            })
            .collect();
        validate_typed_bindings(bindings, &typed_components)?;
    }
    if let Some(scopes) = draft.get("effect_scopes") {
        validate_effect_scopes(scopes, &component_ids)?;
        validate_effect_scopes_against(scopes, &effects)?;
    }
    string_set(&draft["state_namespaces"], 256, 256)?;
    if !draft["resource_policy"].is_object() || !draft["settlement_policy"].is_object() {
        return Err(fail("PROFILE_COMPOSITION_POLICY_OBJECT_INVALID"));
    }
    if draft["test_vectors"]
        .as_array()
        .filter(|rows| rows.len() <= 256)
        .is_none()
    {
        return Err(fail("PROFILE_COMPOSITION_TEST_VECTORS_INVALID"));
    }
    let merged = policy_merge(
        &contracts,
        &draft["resource_policy"],
        &draft["settlement_policy"],
    )?;
    let mut recipe = Map::new();
    for key in required {
        recipe.insert(key.into(), draft[key].clone());
    }
    recipe.insert("interface_bindings".into(), normalized_bindings);
    if let Some(value) = draft.get("external_requirements") {
        recipe.insert("external_requirements".into(), value.clone());
    }
    if let Some(value) = draft.get("typed_interface_bindings") {
        recipe.insert("typed_interface_bindings".into(), value.clone());
    }
    if let Some(value) = draft.get("effect_scopes") {
        recipe.insert("effect_scopes".into(), value.clone());
    }
    recipe.insert("components".into(), Value::Array(components.clone()));
    recipe.insert("policy_merge".into(), merged);
    let mut effect_edges = Vec::new();
    for i in 0..ids.len() {
        for j in (i + 1)..ids.len() {
            effect_edges.push(
                json!({"left_component":ids[i],"right_component":ids[j],"relation":"NON_CONFLICTING_UNDER_DECLARED_EFFECTS"}),
            );
        }
    }
    recipe.insert("effect_graph".into(),json!({
        "schema":"KTAPEOUT-EFFECT-GRAPH-V1","proof":"LOCAL_PAIRWISE_EFFECT_CHECK_V1",
        "nodes":components.iter().map(|component|json!({"component_id":component["component_id"],"profile_hash":component["profile_hash"],"effect_hash":effects[component["component_id"].as_str().unwrap()]["effect_hash"]})).collect::<Vec<_>>(),
        "edges":effect_edges
    }));
    recipe.insert(
        "interface_execution_status".into(),
        Value::String(
            if draft
                .get("typed_interface_bindings")
                .and_then(Value::as_array)
                .is_some_and(|bindings| !bindings.is_empty())
            {
                "STATIC_ONLY"
            } else {
                "NOT_REQUESTED"
            }
            .into(),
        ),
    );
    let mut recipe = Value::Object(recipe);
    let recipe_hash = hash(
        &recipe,
        "KTAPEOUT/0.5.0/COMPOSITION_RECIPE/V1",
        &["recipe_hash", "publisher_signature"],
    )?;
    recipe
        .as_object_mut()
        .unwrap()
        .insert("recipe_hash".into(), Value::String(recipe_hash));
    let root = composition_root(&recipe)?;
    package_digests.sort();
    Ok(ComposedRecipe {
        recipe,
        composition_root: root,
        package_digests,
    })
}
