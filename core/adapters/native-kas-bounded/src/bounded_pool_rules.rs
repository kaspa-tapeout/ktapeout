//! Pure bounded-pool allocation rules shared by local validation and transaction planning.
//!
//! This module validates and commits the declared recipient schedule. It does not inspect UTXOs,
//! compile covenants, request signatures, connect to a node, or submit transactions.

use secp256k1::XOnlyPublicKey;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashSet;

pub const ALLOCATION_DOMAIN: &str = "KTAPEOUT/0.5.0/BOUNDED_POOL_ALLOCATION/v1";
pub const ALLOCATION_VALIDATION_INTERFACE: &str = "bounded-pool.allocation.validate";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    pub id: String,
    pub owner: [u8; 32],
    pub amount: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Allocation {
    pub grants: Vec<Grant>,
    pub pool_size: usize,
    pub max_batch: usize,
    pub digest: [u8; 32],
    pub total: u64,
}

fn exact_keys(value: &Value, keys: &[&str]) -> Result<(), String> {
    let object = value.as_object().ok_or("object required")?;
    if object.len() != keys.len() || keys.iter().any(|key| !object.contains_key(*key)) {
        return Err("unexpected fields".into());
    }
    Ok(())
}

fn bounded_usize(value: &Value, min: usize, max: usize) -> Result<usize, String> {
    value
        .as_u64()
        .and_then(|number| usize::try_from(number).ok())
        .filter(|number| (min..=max).contains(number))
        .ok_or_else(|| "parameter out of range".into())
}

fn canonical_bytes32(value: &Value) -> Result<[u8; 32], String> {
    let text = value.as_str().ok_or("32-byte hex required")?;
    if text.len() != 64
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("canonical lowercase 32-byte hex required".into());
    }
    let mut bytes = [0u8; 32];
    for (index, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        let digit = |byte: u8| match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => unreachable!("hex alphabet validated"),
        };
        bytes[index] = (digit(pair[0]) << 4) | digit(pair[1]);
    }
    Ok(bytes)
}

fn allocation_input_with_numeric_amounts(value: &Value) -> Result<Value, String> {
    let mut normalized = value.clone();
    let Some(rows) = normalized.get_mut("grants").and_then(Value::as_array_mut) else {
        return Ok(normalized);
    };
    for row in rows {
        let Some(object) = row.as_object_mut() else {
            continue;
        };
        if let Some(amount) = object.get("amount") {
            let Some(text) = amount.as_str() else {
                return Err("canonical decimal u64 amount required".into());
            };
            let parsed = text
                .parse::<u64>()
                .map_err(|_| "canonical decimal u64 amount required")?;
            if parsed.to_string() != text {
                return Err("canonical decimal u64 amount required".into());
            }
            object.insert("amount".into(), Value::from(parsed));
        }
    }
    Ok(normalized)
}

/// Validate a recipient schedule and derive the exact commitment used by the native planner.
///
/// Bounds are supplied by the Profile adapter so the rules remain independent of a particular
/// transaction codec while preserving the Profile's resource limits.
pub fn validate_allocation(
    value: &Value,
    max_pool_size: usize,
    max_batch_size: usize,
    max_grants: usize,
    max_amount: u64,
) -> Result<Allocation, String> {
    exact_keys(value, &["pool_size", "max_batch", "grants"])?;
    let pool_size = bounded_usize(&value["pool_size"], 1, max_pool_size)?;
    let max_batch = bounded_usize(&value["max_batch"], 1, max_batch_size)?;
    let rows = value["grants"].as_array().ok_or("grants array required")?;
    if rows.is_empty() || rows.len() > max_grants {
        return Err("grant count out of range".into());
    }

    let mut ids = HashSet::with_capacity(rows.len());
    let mut grants = Vec::with_capacity(rows.len());
    let mut total = 0u64;
    for row in rows {
        exact_keys(row, &["grant_id", "owner_public_key", "amount"])?;
        let id = row["grant_id"]
            .as_str()
            .filter(|text| (1..=128).contains(&text.len()))
            .ok_or("invalid grant_id")?;
        if !ids.insert(id) {
            return Err("duplicate grant_id".into());
        }
        let owner = canonical_bytes32(&row["owner_public_key"])?;
        XOnlyPublicKey::from_slice(&owner).map_err(|_| "invalid x-only public key")?;
        let amount = row["amount"]
            .as_u64()
            .filter(|amount| *amount > 0 && *amount <= max_amount)
            .ok_or("amount outside Profile range")?;
        total = total
            .checked_add(amount)
            .ok_or("allocation total overflow")?;
        grants.push(Grant {
            id: id.to_owned(),
            owner,
            amount,
        });
    }

    let pool_size_commitment =
        u32::try_from(pool_size).map_err(|_| "pool_size exceeds commitment width")?;
    let max_batch_commitment =
        u32::try_from(max_batch).map_err(|_| "max_batch exceeds commitment width")?;
    let mut preimage = ALLOCATION_DOMAIN.as_bytes().to_vec();
    preimage.extend(pool_size_commitment.to_le_bytes());
    preimage.extend(max_batch_commitment.to_le_bytes());
    for grant in &grants {
        preimage.extend((grant.id.len() as u32).to_le_bytes());
        preimage.extend(grant.id.as_bytes());
        preimage.extend(grant.owner);
        preimage.extend(grant.amount.to_le_bytes());
    }
    let digest = Sha256::digest(&preimage).into();
    Ok(Allocation {
        grants,
        pool_size,
        max_batch,
        digest,
        total,
    })
}

/// Execute bounded allocation vectors against the exact rules used by the native planner.
///
/// Each vector has exactly `input` and `expected` fields. `expected` is compared as canonical
/// JSON data with the deterministic accepted/rejected projection below. This is local Profile
/// behavior only; it does not inspect transactions or produce L1 evidence.
pub fn execute_allocation_vectors(
    vectors: &Value,
    max_pool_size: usize,
    max_batch_size: usize,
    max_grants: usize,
    max_amount: u64,
) -> Value {
    let Some(rows) = vectors.as_array().filter(|rows| !rows.is_empty()) else {
        return serde_json::json!({"status":"BLOCKED","execution_trace":[],"reason":"non-empty vector array required"});
    };
    let execution_trace: Vec<Value> = rows
        .iter()
        .enumerate()
        .map(|(vector_index, vector)| {
            let actual = if exact_keys(vector, &["input", "expected"]).is_err() {
                serde_json::json!({"status":"INVALID_VECTOR"})
            } else {
                let input = allocation_input_with_numeric_amounts(&vector["input"]);
                match input.and_then(|input| {
                    validate_allocation(
                        &input,
                        max_pool_size,
                        max_batch_size,
                        max_grants,
                        max_amount,
                    )
                }) {
                    Ok(allocation) => serde_json::json!({
                        "status":"ACCEPTED",
                        "allocation_digest":hex::encode(allocation.digest),
                        "grant_count":allocation.grants.len(),
                        "total_amount":allocation.total.to_string()
                    }),
                    Err(error) => serde_json::json!({"status":"REJECTED","error":error}),
                }
            };
            let passed = vector.get("expected") == Some(&actual);
            serde_json::json!({
                "vector_index":vector_index,
                "status":if passed {"PASS"} else {"FAIL"},
                "observed":actual
            })
        })
        .collect();
    let all_passed = execution_trace
        .iter()
        .all(|entry| entry.get("status").and_then(Value::as_str) == Some("PASS"));
    serde_json::json!({
        "status":if all_passed {"LOCAL_EXECUTABLE"} else {"VECTOR_FAILURE"},
        "execution_trace":execution_trace,
        "network_effect":"NONE",
        "signing_allowed":false,
        "broadcast":false
    })
}
