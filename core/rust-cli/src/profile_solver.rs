//! Bounded, deterministic local Profile selection shared by the public CLI.
//! This produces a catalog candidate only; it never grants execution or L1 authority.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const MAX_COMPONENTS: usize = 8;
const MAX_CANDIDATES: usize = 3;
const MAX_COMPARISONS: usize = 250_000;
const INPUT_LOCK: &str = include_str!("../../spec/ktapeout-solver-input-lock-v1.json");
const NAMING_REGISTRY: &str = include_str!("../../spec/ktapeout-naming-alias-registry-v1.json");
const OFFICIAL_GUIDANCE: &str =
    include_str!("../../guidance/official-tn10-profile-guidance-v1.json");
const SCENARIO_CORPUS: &str = include_str!("../../spec/ktapeout-solver-scenario-corpus-v1.json");
const ERROR_TAXONOMY: &str = include_str!("../../spec/ktapeout-error-codes-v0.5.0.json");

fn fail(message: &str) -> String {
    message.to_string()
}
fn canonical(value: &Value) -> Result<Vec<u8>, String> {
    ktapeout_runtime::canonical_json(value)
}
fn hash(value: &Value, domain: &str) -> Result<String, String> {
    let mut h = Sha256::new();
    h.update(domain.as_bytes());
    h.update([0]);
    h.update(canonical(value)?);
    Ok(hex::encode(h.finalize()))
}
fn raw_hash(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}
fn solver_input_lock() -> Result<Value, String> {
    let lock: Value = serde_json::from_str(INPUT_LOCK)
        .map_err(|_| fail("embedded solver input lock is invalid"))?;
    if lock["schema"] != "KTAPEOUT-SOLVER-INPUT-LOCK-V1" || lock["protocol_semver"] != "0.5.0" {
        return Err(fail("embedded solver input lock identity is invalid"));
    }
    let naming: Value = serde_json::from_str(NAMING_REGISTRY)
        .map_err(|_| fail("embedded naming registry is invalid"))?;
    let guidance: Value = serde_json::from_str(OFFICIAL_GUIDANCE)
        .map_err(|_| fail("embedded official Guidance catalog is invalid"))?;
    let taxonomy: Value = serde_json::from_str(ERROR_TAXONOMY)
        .map_err(|_| fail("embedded error taxonomy is invalid"))?;
    let expected = [
        ("naming_registry_hash", naming["registry_hash"].clone()),
        ("guidance_catalog_hash", guidance["catalog_hash"].clone()),
        ("scenario_corpus_sha256", json!(raw_hash(SCENARIO_CORPUS))),
        ("error_taxonomy", taxonomy["schema"].clone()),
        ("error_taxonomy_sha256", json!(raw_hash(ERROR_TAXONOMY))),
    ];
    for (field, value) in expected {
        if lock[field] != value {
            return Err(format!("embedded solver input lock {field} mismatch"));
        }
    }
    let lock_hash = lock["lock_hash"]
        .as_str()
        .filter(|value| valid_hash(value))
        .ok_or_else(|| fail("embedded solver input lock hash is missing"))?;
    let mut body = lock
        .as_object()
        .ok_or_else(|| fail("embedded solver input lock is invalid"))?
        .clone();
    body.remove("lock_hash");
    if hash(&Value::Object(body), "KTAPEOUT/0.5.0/SOLVER_INPUT_LOCK/V1")? != lock_hash {
        return Err(fail("embedded solver input lock hash mismatch"));
    }
    Ok(lock)
}
fn validate_intent(intent: &Value) -> Result<(), String> {
    let object = intent
        .as_object()
        .ok_or_else(|| fail("intent must be an object"))?;
    let allowed: BTreeSet<&str> = [
        "schema",
        "protocol_semver",
        "intent_id",
        "declared_purpose",
        "required_capabilities",
        "forbidden_capabilities",
        "wallet_modes",
        "settlement_modes",
        "max_components",
        "network",
        "required_evidence_refs",
        "resource_parameters",
    ]
    .into_iter()
    .collect();
    if object.keys().any(|key| !allowed.contains(key.as_str())) {
        return Err(fail("intent contains unknown fields"));
    }
    if intent["schema"] != "KTAPEOUT-APPLICATION-INTENT-V1" || intent["protocol_semver"] != "0.5.0"
    {
        return Err(fail("intent identity is invalid"));
    }
    for (field, max_len) in [("intent_id", 128), ("declared_purpose", 4096)] {
        if !intent[field]
            .as_str()
            .is_some_and(|text| !text.is_empty() && text.chars().count() <= max_len)
        {
            return Err(format!("{field} is invalid"));
        }
    }
    for (field, max_count, max_len) in [
        ("required_capabilities", 128, 256),
        ("forbidden_capabilities", 128, 256),
        ("wallet_modes", 16, 64),
        ("settlement_modes", 16, 64),
        ("required_evidence_refs", 128, 256),
    ] {
        if field == "required_evidence_refs" && !object.contains_key(field) {
            continue;
        }
        let values = intent
            .get(field)
            .and_then(Value::as_array)
            .ok_or_else(|| format!("{field} is invalid"))?;
        if values.len() > max_count
            || values.iter().any(|value| {
                !value
                    .as_str()
                    .is_some_and(|text| !text.is_empty() && text.chars().count() <= max_len)
            })
        {
            return Err(format!("{field} is invalid"));
        }
    }
    let max = intent["max_components"]
        .as_u64()
        .filter(|value| (1..=MAX_COMPONENTS as u64).contains(value));
    if max.is_none() {
        return Err(fail("max_components is invalid"));
    }
    if let Some(network) = intent.get("network") {
        if !matches!(network.as_str(), Some("testnet-10" | "mainnet")) {
            return Err(fail("network is invalid"));
        }
    }
    if let Some(parameters) = intent.get("resource_parameters") {
        let params = parameters
            .as_object()
            .ok_or_else(|| fail("resource_parameters is invalid"))?;
        if params.keys().any(|key| key != "direct_payout_sompi") {
            return Err(fail("resource_parameters is invalid"));
        }
        if let Some(value) = params.get("direct_payout_sompi") {
            if value.as_u64().filter(|amount| *amount > 0).is_none() {
                return Err(fail("resource_parameters.direct_payout_sompi is invalid"));
            }
        }
    }
    Ok(())
}
fn set(value: &Value, field: &str) -> Result<BTreeSet<String>, String> {
    let items = value
        .as_array()
        .ok_or_else(|| format!("{field} must be a string array"))?;
    let mut out = BTreeSet::new();
    for item in items {
        let s = item
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| format!("{field} must be a string array"))?;
        out.insert(s.to_string());
    }
    Ok(out)
}
fn strings(record: &Value, field: &str) -> Result<BTreeSet<String>, String> {
    set(
        record
            .get(field)
            .ok_or_else(|| format!("guidance field missing: {field}"))?,
        field,
    )
}
fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn validate_guidance(record: &Value) -> Result<(), String> {
    let o = record
        .as_object()
        .ok_or_else(|| fail("guidance must be an object"))?;
    let mut required: BTreeSet<&str> = [
        "schema",
        "protocol_semver",
        "object_kind",
        "canonical_id",
        "profile_id",
        "profile_semver",
        "profile_hash",
        "contract_hash",
        "publisher_id",
        "family",
        "maturity",
        "provides",
        "requires",
        "forbids",
        "compatible_profiles",
        "conflicting_profiles",
        "state_topology",
        "authority_model",
        "resource_class",
        "wallet_modes",
        "settlement_modes",
        "external_assumptions",
        "evidence_refs",
        "limitations",
        "guidance_hash",
    ]
    .into_iter()
    .collect();
    if o.keys()
        .any(|k| !required.contains(k.as_str()) && k != "implementation_status")
    {
        return Err(fail("guidance identity or fields are invalid"));
    }
    for key in o.keys() {
        required.remove(key.as_str());
    }
    if !required.is_empty()
        || record["schema"] != "KTAPEOUT-PROFILE-GUIDANCE-V1"
        || record["protocol_semver"] != "0.5.0"
        || record["object_kind"] != "profile"
    {
        return Err(fail("guidance identity or fields are invalid"));
    }
    if let Some(status) = record.get("implementation_status") {
        if !matches!(
            status.as_str(),
            Some("PLANNED" | "EXECUTABLE" | "PUBLISHABLE")
        ) {
            return Err(fail("guidance implementation_status is invalid"));
        }
    }
    let id = record["canonical_id"]
        .as_str()
        .ok_or_else(|| fail("canonical_id is invalid"))?;
    let p: Vec<&str> = id.split('.').collect();
    if p.len() != 5
        || p[0] != "ktape"
        || p[2] != "profile"
        || p.iter().any(|s| {
            s.is_empty()
                || *s != s.to_ascii_lowercase()
                || s.len() > 63
                || !s.as_bytes()[0].is_ascii_lowercase() && !s.as_bytes()[0].is_ascii_digit()
                || !s
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
    {
        return Err(fail("canonical_id does not match the profile namespace"));
    }
    for field in ["profile_hash", "contract_hash", "guidance_hash"] {
        if !record[field].as_str().is_some_and(valid_hash) {
            return Err(format!("{field} is invalid"));
        }
    }
    for field in [
        "profile_id",
        "profile_semver",
        "publisher_id",
        "family",
        "maturity",
        "state_topology",
        "authority_model",
        "resource_class",
    ] {
        if !record[field]
            .as_str()
            .is_some_and(|s| !s.is_empty() && s.len() <= 256)
        {
            return Err(format!("{field} is invalid"));
        }
    }
    for field in [
        "provides",
        "requires",
        "forbids",
        "compatible_profiles",
        "conflicting_profiles",
        "wallet_modes",
        "settlement_modes",
        "external_assumptions",
        "evidence_refs",
        "limitations",
    ] {
        let values = record[field]
            .as_array()
            .ok_or_else(|| format!("{field} is invalid"))?;
        if values.len() > 128
            || values
                .iter()
                .any(|v| !v.as_str().is_some_and(|s| !s.is_empty() && s.len() <= 256))
        {
            return Err(format!("{field} is invalid"));
        }
    }
    let mut body = o.clone();
    body.remove("guidance_hash");
    let digest = hash(&Value::Object(body), "KTAPEOUT/0.5.0/PROFILE_GUIDANCE/V1")?;
    if record["guidance_hash"].as_str() != Some(digest.as_str()) {
        return Err(fail("guidance_hash mismatch"));
    }
    Ok(())
}

fn catalog_records(
    value: &Value,
    network: Option<&str>,
    requested: Option<&str>,
) -> Result<(Vec<Value>, String), String> {
    let (records, digest) = if value.is_array() {
        let records = value.as_array().unwrap().clone();
        (
            records.clone(),
            hash(
                &Value::Array(records),
                "KTAPEOUT/0.5.0/PROFILE_GUIDANCE_CATALOG/V1",
            )?,
        )
    } else {
        let o = value
            .as_object()
            .ok_or_else(|| fail("guidance JSON must be an array or an object with records"))?;
        let catalog_fields: BTreeSet<&str> = [
            "schema",
            "protocol_semver",
            "network",
            "status",
            "catalog_version",
            "source_bundle_hash",
            "source_attestation",
            "records",
            "catalog_hash",
        ]
        .into_iter()
        .collect();
        if o.keys().any(|k| !catalog_fields.contains(k.as_str()))
            || o.len() != catalog_fields.len()
            || o["schema"] != "KTAPEOUT-PROFILE-GUIDANCE-CATALOG-V1"
            || o["protocol_semver"] != "0.5.0"
            || o["status"] != "PUBLIC_RELEASED_SOURCE_PROJECTION"
            || !matches!(o["network"].as_str(), Some("testnet-10" | "mainnet"))
            || o["catalog_version"].as_str().is_none_or(|s| s.is_empty())
        {
            return Err(fail("guidance catalog identity is invalid"));
        }
        if network.is_some_and(|n| o["network"].as_str() != Some(n)) {
            return Err(fail("CATALOG_NETWORK_MISMATCH"));
        }
        if !o["source_bundle_hash"].as_str().is_some_and(valid_hash)
            || o["source_attestation"].as_object().is_none_or(|a| {
                a.len() != 2 || !a.contains_key("publisher_id") || !a.contains_key("signature")
            })
        {
            return Err(fail("guidance catalog source binding is invalid"));
        }
        let mut body = o.clone();
        let declared = body
            .remove("catalog_hash")
            .and_then(|v| v.as_str().map(str::to_owned))
            .ok_or_else(|| fail("guidance catalog hash is missing"))?;
        let actual = hash(
            &Value::Object(body),
            "KTAPEOUT/0.5.0/PROFILE_GUIDANCE_CATALOG_ENVELOPE/V1",
        )?;
        if declared != actual {
            return Err(fail("guidance catalog hash mismatch"));
        }
        (
            o["records"]
                .as_array()
                .ok_or_else(|| fail("guidance catalog records are invalid"))?
                .clone(),
            declared,
        )
    };
    if records.is_empty() {
        return Err(fail("guidance records are empty"));
    }
    if requested.is_some_and(|v| v != digest) {
        return Err(fail("CATALOG_HASH_MISMATCH"));
    }
    let mut ids = BTreeSet::new();
    for r in &records {
        validate_guidance(r)?;
        if !ids.insert(r["canonical_id"].as_str().unwrap().to_owned()) {
            return Err(fail("guidance canonical IDs are duplicated"));
        }
    }
    Ok((records, digest))
}

fn visit_combinations<F>(
    records: &[Value],
    start: usize,
    limit: usize,
    chosen: &mut Vec<usize>,
    count: &mut usize,
    visitor: &mut F,
) -> Result<(), String>
where
    F: FnMut(&[usize]) -> Result<(), String>,
{
    if !chosen.is_empty() {
        *count += 1;
        if *count > MAX_COMPARISONS {
            return Err(fail("RESOURCE_EXCEEDED: solver comparison budget"));
        }
        visitor(chosen)?;
    }
    if chosen.len() == limit {
        return Ok(());
    }
    for i in start..records.len() {
        chosen.push(i);
        visit_combinations(records, i + 1, limit, chosen, count, visitor)?;
        chosen.pop();
    }
    Ok(())
}

fn compare_candidates(a: &Value, b: &Value, implemented: &BTreeSet<String>) -> std::cmp::Ordering {
    let sa = a["score"].as_array().unwrap();
    let sb = b["score"].as_array().unwrap();
    let quality = sa[0]
        .as_u64()
        .unwrap_or(0)
        .cmp(&sb[0].as_u64().unwrap_or(0))
        .then(
            sa[1]
                .as_u64()
                .unwrap_or(0)
                .cmp(&sb[1].as_u64().unwrap_or(0)),
        );
    if quality != std::cmp::Ordering::Equal {
        return quality;
    }
    let has_unimplemented = |candidate: &Value| {
        candidate["profile_ids"]
            .as_array()
            .unwrap()
            .iter()
            .any(|id| !implemented.contains(id.as_str().unwrap_or("")))
    };
    has_unimplemented(a)
        .cmp(&has_unimplemented(b))
        .then(
            sa[2]
                .as_u64()
                .unwrap_or(0)
                .cmp(&sb[2].as_u64().unwrap_or(0)),
        )
        .then(sa[3].to_string().cmp(&sb[3].to_string()))
}

pub fn solve(
    intent: &Value,
    guidance: &Value,
    requested_catalog_hash: Option<&str>,
) -> Result<Value, String> {
    validate_intent(intent)?;
    let required = set(
        intent
            .get("required_capabilities")
            .unwrap_or(&Value::Array(vec![])),
        "required_capabilities",
    )?;
    let forbidden = set(
        intent
            .get("forbidden_capabilities")
            .unwrap_or(&Value::Array(vec![])),
        "forbidden_capabilities",
    )?;
    let wallet = set(
        intent.get("wallet_modes").unwrap_or(&Value::Array(vec![])),
        "wallet_modes",
    )?;
    let settlement = set(
        intent
            .get("settlement_modes")
            .unwrap_or(&Value::Array(vec![])),
        "settlement_modes",
    )?;
    let evidence = set(
        intent
            .get("required_evidence_refs")
            .unwrap_or(&Value::Array(vec![])),
        "required_evidence_refs",
    )?;
    let max = intent["max_components"].as_u64().unwrap() as usize;
    let (mut records, catalog_hash) = catalog_records(
        guidance,
        intent.get("network").and_then(Value::as_str),
        requested_catalog_hash,
    )?;
    records.sort_by(|a, b| {
        (
            a["canonical_id"].as_str().unwrap_or(""),
            a["profile_hash"].as_str().unwrap_or(""),
        )
            .cmp(&(
                b["canonical_id"].as_str().unwrap_or(""),
                b["profile_hash"].as_str().unwrap_or(""),
            ))
    });
    let mut comparisons = 0;
    let mut reject = BTreeMap::from([
        ("REQUIRED_CAPABILITY_UNCOVERED", 0usize),
        ("FORBIDDEN_CAPABILITY", 0),
        ("WALLET_POLICY_INCOMPATIBLE", 0),
        ("SETTLEMENT_POLICY_INCOMPATIBLE", 0),
        ("PROFILE_CONFLICT", 0),
        ("DEPENDENCY_UNSATISFIED", 0),
    ]);
    let mut candidates = Vec::<Value>::new();
    let implemented: BTreeSet<String> = records
        .iter()
        .filter(|r| {
            matches!(
                r.get("implementation_status").and_then(Value::as_str),
                Some("EXECUTABLE" | "PUBLISHABLE")
            )
        })
        .filter_map(|r| r["canonical_id"].as_str().map(str::to_owned))
        .collect();
    let mut candidate_count_before_limit = 0usize;
    visit_combinations(
        &records,
        0,
        max.min(records.len()),
        &mut Vec::new(),
        &mut comparisons,
        &mut |combo| {
            let mut provides = BTreeSet::new();
            let mut needs = BTreeSet::new();
            let mut common_wallet: Option<BTreeSet<String>> = None;
            let mut common_settlement: Option<BTreeSet<String>> = None;
            let mut ids = Vec::new();
            let mut gaps = BTreeSet::new();
            let mut declared = BTreeSet::new();
            for i in combo {
                let r = &records[*i];
                ids.push(r["canonical_id"].as_str().unwrap().to_owned());
                provides.extend(strings(r, "provides")?);
                needs.extend(strings(r, "requires")?);
                let w = strings(r, "wallet_modes")?;
                common_wallet = Some(
                    common_wallet.map_or(w.clone(), |s| s.intersection(&w).cloned().collect()),
                );
                let st = strings(r, "settlement_modes")?;
                common_settlement = Some(
                    common_settlement
                        .map_or(st.clone(), |s| s.intersection(&st).cloned().collect()),
                );
                for e in strings(r, "evidence_refs")? {
                    if e.starts_with("MISSING:") {
                        gaps.insert(e);
                    } else {
                        declared.insert(e);
                    }
                }
                if strings(r, "limitations")?.contains("FORMAL_ADMISSION_UNPROVEN") {
                    gaps.insert("formal-admission:PROVEN".into());
                }
            }
            let cw = common_wallet.unwrap_or_default();
            let cs = common_settlement.unwrap_or_default();
            if !required.is_subset(&provides) {
                *reject.get_mut("REQUIRED_CAPABILITY_UNCOVERED").unwrap() += 1;
                return Ok(());
            }
            if !provides.is_disjoint(&forbidden) {
                *reject.get_mut("FORBIDDEN_CAPABILITY").unwrap() += 1;
                return Ok(());
            }
            if !wallet.is_empty() && wallet.is_disjoint(&cw) {
                *reject.get_mut("WALLET_POLICY_INCOMPATIBLE").unwrap() += 1;
                return Ok(());
            }
            if !settlement.is_empty() && settlement.is_disjoint(&cs) {
                *reject.get_mut("SETTLEMENT_POLICY_INCOMPATIBLE").unwrap() += 1;
                return Ok(());
            }
            let mut conflict = false;
            for (pos, i) in combo.iter().enumerate() {
                for j in combo.iter().skip(pos + 1) {
                    let a = &records[*i];
                    let b = &records[*j];
                    if strings(a, "conflicting_profiles")?
                        .contains(b["canonical_id"].as_str().unwrap())
                        || strings(b, "conflicting_profiles")?
                            .contains(a["canonical_id"].as_str().unwrap())
                    {
                        conflict = true;
                    }
                }
            }
            if conflict {
                *reject.get_mut("PROFILE_CONFLICT").unwrap() += 1;
                return Ok(());
            }
            let missing: BTreeSet<_> = needs.difference(&provides).cloned().collect();
            if !missing.is_empty() {
                *reject.get_mut("DEPENDENCY_UNSATISFIED").unwrap() += 1;
            }
            let mut missing_evidence: BTreeSet<_> = gaps;
            missing_evidence.extend(evidence.difference(&declared).cloned());
            let score = json!([missing.len(), missing_evidence.len(), combo.len(), ids]);
            candidates.push(json!({
                "profile_ids": ids,
                "provides": provides,
                "missing": missing,
                "evidence_gaps": missing_evidence,
                "common_wallet_modes": cw,
                "common_settlement_modes": cs,
                "component_count": combo.len(),
                "proof_status": if missing.is_empty() && missing_evidence.is_empty() { "CANDIDATE" } else { "PROOF_INCOMPLETE" },
                "score": score
            }));
            candidate_count_before_limit += 1;
            candidates.sort_by(|a, b| compare_candidates(a, b, &implemented));
            candidates.truncate(MAX_CANDIDATES);
            Ok(())
        },
    )?;
    let before = candidates.first().cloned();
    let all_provided: BTreeMap<String, Vec<String>> = required
        .iter()
        .map(|cap| {
            let ps = records
                .iter()
                .filter(|r| strings(r, "provides").is_ok_and(|p| p.contains(cap)))
                .filter_map(|r| r["canonical_id"].as_str().map(str::to_owned))
                .collect();
            (cap.clone(), ps)
        })
        .collect();
    let unprovided: Vec<_> = all_provided
        .iter()
        .filter(|(_, p)| p.is_empty())
        .map(|(k, _)| k.clone())
        .collect();
    let all = unprovided.is_empty();
    let covered_uncomposable: Vec<_> = all_provided
        .iter()
        .filter(|(_, p)| all && !p.is_empty() && candidates.is_empty())
        .map(|(k, _)| k.clone())
        .collect();
    let raw_status = if candidates
        .first()
        .is_some_and(|c| c["proof_status"] == "CANDIDATE")
    {
        "SOLVED"
    } else if candidates.is_empty() {
        "UNRESOLVED_CONFLICT"
    } else {
        "PROOF_INCOMPLETE"
    };
    candidates.truncate(MAX_CANDIDATES);
    let selected = candidates.first().cloned();
    let mut implementation_pending: Vec<String> = selected
        .as_ref()
        .map(|s| {
            records
                .iter()
                .filter(|r| {
                    s["profile_ids"]
                        .as_array()
                        .unwrap()
                        .contains(&r["canonical_id"])
                        && r.get("implementation_status")
                            .and_then(Value::as_str)
                            .unwrap_or("PLANNED")
                            == "PLANNED"
                })
                .filter_map(|r| r["canonical_id"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    implementation_pending.sort();
    implementation_pending.dedup();
    let status = if raw_status == "SOLVED" && !implementation_pending.is_empty() {
        "SOLVED_NOT_EXECUTABLE"
    } else {
        raw_status
    };
    let selected_missing = selected
        .as_ref()
        .map(|s| s["missing"].clone())
        .unwrap_or(json!(required));
    let selected_gaps = selected
        .as_ref()
        .map(|s| s["evidence_gaps"].clone())
        .unwrap_or(json!(evidence));
    let (handoff_status, next_action) = match status {
        "SOLVED" => ("NONE", "none"),
        "SOLVED_NOT_EXECUTABLE" => (
            "PENDING_IMPLEMENTATION",
            "supply an implemented Profile Package and runner, or select an implemented alternative",
        ),
        "PROOF_INCOMPLETE" => (
            "PENDING_EXTERNAL_EVIDENCE",
            "supply the listed evidence or revise the application intent",
        ),
        _ => ("UNRESOLVED", "resolve candidate/profile conflicts"),
    };
    let lock = solver_input_lock()?;
    let lock_hash = lock["lock_hash"].as_str().unwrap();
    let mut result = json!({
        "schema": "KTAPEOUT-SOLUTION-PLAN-V1",
        "protocol_semver": "0.5.0",
        "solver_version": "KTAPEOUT-SOLVER-V1",
        "intent_hash": hash(intent, "KTAPEOUT/0.5.0/APPLICATION_INTENT/V1")?,
        "catalog_hash": catalog_hash,
        "solver_input_lock_hash": lock_hash,
        "status": status,
        "implementation_pending": implementation_pending,
        "candidate_count": candidates.len(),
        "candidates": candidates,
        "selected": selected,
        "recipe_status": if selected.is_some() { "PACKAGE_INPUT_REQUIRED" } else { "NOT_AVAILABLE" },
        "application_lock_status": if selected.is_some() { "PACKAGE_INPUT_REQUIRED" } else { "NOT_AVAILABLE" },
        "signing_allowed": false,
        "broadcast": false,
        "pending_handoff": {
            "schema": "KTAPEOUT-PENDING-EVIDENCE-HANDOFF-V1",
            "status": handoff_status,
            "missing_capabilities": selected_missing,
            "required_evidence_refs": selected_gaps,
            "next_action": next_action,
            "signing_allowed": false,
            "broadcast": false
        },
        "capability_diagnostics": {
            "schema": "KTAPEOUT-CAPABILITY-DIAGNOSTICS-V1",
            "required": required,
            "providers": all_provided,
            "unprovided": unprovided,
            "covered_but_uncomposable": covered_uncomposable,
            "candidate_count_before_limit": candidate_count_before_limit,
            "comparison_count": comparisons,
            "rejection_counts": reject,
            "wallet_constraints": wallet,
            "settlement_constraints": settlement,
            "evidence_gap_count": before.as_ref().and_then(|v| v["evidence_gaps"].as_array().map(Vec::len)),
            "scope": "LOCAL_CATALOG_DIAGNOSTIC"
        }
    });
    if let Some(obj) = result.as_object_mut() {
        let mut body = obj.clone();
        body.remove("capability_diagnostics");
        let plan_hash = hash(&Value::Object(body), "KTAPEOUT/0.5.0/SOLUTION_PLAN/V1")?;
        obj.insert("plan_hash".into(), json!(plan_hash));
    }
    Ok(result)
}
