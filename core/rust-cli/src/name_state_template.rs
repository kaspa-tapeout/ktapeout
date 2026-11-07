//! Frozen, compiler-derived state templates used by public name lifecycle commands.

use blake2b_simd::Params as Blake2bParams;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const DEED_TEMPLATE_DATA: &str = include_str!("../../../data/registry/deed-state-template-v1.json");
const DEED_SOURCE_SHA256: &str = "845d9e26c63ca2ee1b27f09ce591b4eb7ccfe46c86d0ca79e1ef02b75106ea2e";
const DEED_TEMPLATE_SHA256: &str =
    "cce09f84208dc13f009bb4516e8631f65c2a5a7242572ea306ed15a0185bdf6c";

#[derive(Debug, Deserialize)]
pub struct StateTemplateV1 {
    pub schema: String,
    pub adapter: String,
    pub contract_source_sha256: String,
    pub template_sha256: String,
    pub fixed_state: BTreeMap<String, u64>,
    pub hash_sites: BTreeMap<String, Vec<usize>>,
    pub int_sites: BTreeMap<String, usize>,
    pub template_hex: String,
}

pub fn blake2b_256(bytes: &[u8]) -> [u8; 32] {
    Blake2bParams::new()
        .hash_length(32)
        .to_state()
        .update(bytes)
        .finalize()
        .as_bytes()
        .try_into()
        .expect("BLAKE2b-256 always returns 32 bytes")
}

/// Hash the canonical prefix/suffix framing used by the pinned Silverscript adapter.
pub fn template_hash(prefix: &[u8], suffix: &[u8]) -> Result<[u8; 32], &'static str> {
    let prefix_len = u64::try_from(prefix.len()).map_err(|_| "TEMPLATE_TOO_LARGE")?;
    let suffix_len = u64::try_from(suffix.len()).map_err(|_| "TEMPLATE_TOO_LARGE")?;
    let mut framed = Vec::with_capacity(16 + prefix.len() + suffix.len());
    framed.extend_from_slice(&prefix_len.to_le_bytes());
    framed.extend_from_slice(prefix);
    framed.extend_from_slice(&suffix_len.to_le_bytes());
    framed.extend_from_slice(suffix);
    Ok(blake2b_256(&framed))
}

pub fn embedded_deed_template() -> Result<StateTemplateV1, &'static str> {
    let template: StateTemplateV1 =
        serde_json::from_str(DEED_TEMPLATE_DATA).map_err(|_| "DEED_TEMPLATE_INVALID")?;
    if template.schema != "KTAPEOUT-DEED-STATE-TEMPLATE-V1"
        || template.contract_source_sha256 != DEED_SOURCE_SHA256
        || template.template_sha256 != DEED_TEMPLATE_SHA256
        || template.adapter != "ktape.official.adapter.registry 1.0.0"
        || template.fixed_state
            != BTreeMap::from([
                ("0".to_owned(), 1),
                ("4".to_owned(), 0),
                ("13".to_owned(), 1),
                ("14".to_owned(), 867),
            ])
    {
        return Err("DEED_TEMPLATE_SOURCE_MISMATCH");
    }
    let script = hex::decode(&template.template_hex).map_err(|_| "DEED_TEMPLATE_INVALID")?;
    if hex::encode(Sha256::digest(script)) != template.template_sha256 {
        return Err("DEED_TEMPLATE_DIGEST_MISMATCH");
    }
    Ok(template)
}

pub fn deed_state_script_public_key(state_args: &[Value]) -> Result<String, &'static str> {
    if state_args.len() != 15 {
        return Err("STATE_ARGS_INVALID");
    }
    let template = embedded_deed_template()?;
    let integer_slots = [0usize, 1, 4, 10, 13, 14];
    for slot in integer_slots {
        let value = state_args[slot].as_u64().ok_or("STATE_INTEGER_INVALID")?;
        if value > 9_007_199_254_740_991 {
            return Err("STATE_INTEGER_INVALID");
        }
        if let Some(fixed) = template.fixed_state.get(&slot.to_string()) {
            if value != *fixed {
                return Err(if slot == 0 || slot == 4 {
                    "DEED_STATE_REQUIRED"
                } else {
                    "STATE_PARAMETER_UNSUPPORTED"
                });
            }
        }
    }

    let mut script = hex::decode(&template.template_hex).map_err(|_| "DEED_TEMPLATE_INVALID")?;
    for (slot, sites) in &template.hash_sites {
        let index = slot.parse::<usize>().map_err(|_| "DEED_TEMPLATE_INVALID")?;
        let text = state_args[index].as_str().ok_or("STATE_HASH_INVALID")?;
        if text.len() % 2 != 0 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("STATE_HASH_INVALID");
        }
        if text.len() != 64 || text.bytes().any(|byte| byte.is_ascii_uppercase()) {
            return Err("STATE_HASH_NON_CANONICAL");
        }
        let raw = hex::decode(text).map_err(|_| "STATE_HASH_INVALID")?;
        for offset in sites {
            let end = offset
                .checked_add(raw.len())
                .ok_or("DEED_TEMPLATE_INVALID")?;
            let target = script
                .get_mut(*offset..end)
                .ok_or("DEED_TEMPLATE_INVALID")?;
            target.copy_from_slice(&raw);
        }
    }
    for (slot, offset) in &template.int_sites {
        let index = slot.parse::<usize>().map_err(|_| "DEED_TEMPLATE_INVALID")?;
        let value = state_args[index].as_u64().ok_or("STATE_INTEGER_INVALID")?;
        let end = offset.checked_add(8).ok_or("DEED_TEMPLATE_INVALID")?;
        let target = script
            .get_mut(*offset..end)
            .ok_or("DEED_TEMPLATE_INVALID")?;
        target.copy_from_slice(&value.to_le_bytes());
    }
    Ok(format!("0000aa20{}87", hex::encode(blake2b_256(&script))))
}
