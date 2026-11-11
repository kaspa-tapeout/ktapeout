//! Validated renderers for the frozen TN10 registry covenant templates.
//!
//! The templates are public data and are never compiled at runtime. This module only
//! applies the exact mutable byte ranges recorded by the offline compiler vectors.

use serde_json::Value;
use sha2::{Digest, Sha256};

const GAP_DATA: &str = include_str!("../../../data/registry/adapter-gap-state-template-v1.json");
const PARENT_DATA: &str =
    include_str!("../../../data/registry/adapter-parent-state-template-v1.json");
const CERTIFICATE_DATA: &str =
    include_str!("../../../data/registry/namespace-issuance-certificate-template-v1.json");
const REGISTRATION_GAP_DATA: &str =
    include_str!("../../../data/registry/adapter-registry-redeem-templates-v1.json");

const GAP_SCHEMA: &str = "KTAPEOUT-REGISTRY-ADAPTER-GAP-TEMPLATE-V1";
const PARENT_SCHEMA: &str = "KTAPEOUT-REGISTRY-ADAPTER-PARENT-TEMPLATE-V1";
const CERTIFICATE_SCHEMA: &str = "KTAPEOUT-NAMESPACE-ISSUANCE-CERTIFICATE-TEMPLATE-V1";
const GAP_SOURCE_SHA256: &str = "845d9e26c63ca2ee1b27f09ce591b4eb7ccfe46c86d0ca79e1ef02b75106ea2e";
const PARENT_SOURCE_SHA256: &str =
    "5808c120b5c5200d8cff9dda8b76068590bd17236bdd0264dc7918d140bfe92c";
const CERTIFICATE_SOURCE_SHA256: &str =
    "d18528abbaffd2b77694480266ae524fcffb61dbc8510480c11e327f84a44af5";
const GAP_TEMPLATE_HASH: &str = "4eacb1eb2b3bc67c2a421f9f58da2d17052648cbc29627992bd79e0b0a0e869b";
const PARENT_TEMPLATE_HASH: &str =
    "b9cdbfb106476a616b3532747b8432c1cb1308584e0d4d8bb00dd3ad6093d754";
const CERTIFICATE_TEMPLATE_HASH: &str =
    "e1d01090830692479ad199f73b92ed8bbd9f16407340b32882892fb7ce893380";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistryTemplate {
    GapFinite,
    GapUnbounded,
    AdapterParent,
    IssuanceCertificate,
    RegistrationGapFinite,
    RegistrationGapUnbounded,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ByteWrite {
    pub offset: usize,
    pub bytes: Vec<u8>,
}

/// Render the Gap consumed by registration in the official adapter lineage.
pub fn render_registration_gap(
    hi_is_max: bool,
    writes: &[ByteWrite],
) -> Result<Vec<u8>, &'static str> {
    render(
        if hi_is_max {
            RegistryTemplate::RegistrationGapUnbounded
        } else {
            RegistryTemplate::RegistrationGapFinite
        },
        writes,
    )
}

/// Bind reconstructed redeems to the two input script commitments. The caller must obtain
/// these scripts from authenticated UTXO observations, not from the state backup itself.
pub fn registration_witness_for_inputs(
    state: &Value,
    input_scripts: &[Vec<u8>; 2],
) -> Result<[Vec<u8>; 2], &'static str> {
    registration_witness_bound(state, Some(input_scripts)).map(|result| result.0)
}

/// Generate ABI contexts only after both input script commitments match.
pub fn registration_contexts_for_inputs(
    state: &Value,
    input_scripts: &[Vec<u8>; 2],
) -> Result<Value, &'static str> {
    registration_witness_bound(state, Some(input_scripts)).map(|result| result.1)
}

/// Derive the parent successor and three child outputs from the same validated state
/// and column-major nextStates used by the official registration witness.
pub fn registration_output_scripts(state: &Value) -> Result<[String; 4], &'static str> {
    let (_, contexts) = registration_witness_bound(state, None)?;
    let parent = hex::decode(
        contexts[0]["redeem_script_hex"]
            .as_str()
            .ok_or("REGISTRATION_STATE_INVALID")?,
    )
    .map_err(|_| "REGISTRATION_STATE_INVALID")?;
    let gap = hex::decode(
        contexts[1]["redeem_script_hex"]
            .as_str()
            .ok_or("REGISTRATION_STATE_INVALID")?,
    )
    .map_err(|_| "REGISTRATION_STATE_INVALID")?;
    let p2sh = |redeem: &[u8]| {
        format!(
            "0000aa20{}87",
            hex::encode(crate::name_state_template::blake2b_256(redeem))
        )
    };
    let mut scripts = [p2sh(&parent), String::new(), String::new(), String::new()];
    for output in 0..3 {
        let mut redeem = gap.clone();
        for (column, offset) in [2usize, 11, 20, 53, 86, 95, 128, 161, 194, 227, 260]
            .into_iter()
            .enumerate()
        {
            let width = if [0, 1, 4, 10].contains(&column) {
                8
            } else {
                32
            };
            let bytes = hex::decode(
                contexts[1]["arguments"][column]["data_hex"]
                    .as_str()
                    .ok_or("REGISTRATION_STATE_INVALID")?,
            )
            .map_err(|_| "REGISTRATION_STATE_INVALID")?;
            let value = bytes
                .get(output * width..(output + 1) * width)
                .ok_or("REGISTRATION_STATE_INVALID")?;
            redeem[offset..offset + width].copy_from_slice(value);
        }
        scripts[output + 1] = p2sh(&redeem);
    }
    Ok(scripts)
}

/// Encode unsigned registration witnesses; caller must first authenticate the input states.
pub fn registration_witness(state: &Value) -> Result<[Vec<u8>; 2], &'static str> {
    registration_witness_bound(state, None).map(|result| result.0)
}

fn registration_witness_bound(
    state: &Value,
    input_scripts: Option<&[Vec<u8>; 2]>,
) -> Result<([Vec<u8>; 2], Value), &'static str> {
    use std::collections::BTreeMap;
    let invalid = "REGISTRATION_STATE_INVALID";
    if state["network"].as_str() != Some("testnet-10") {
        return Err(invalid);
    }
    let mut fields = BTreeMap::<String, Vec<u8>>::new();
    for name in [
        "namespace_hash",
        "authority_commitment",
        "resolver_policy_hash",
        "registry_root",
        "authority_xonly",
        "gap_lo",
        "gap_hi",
        "name_key",
        "claimant_xonly",
        "target_commitment",
        "target_authority_xonly",
        "child_resolver_policy_hash",
        "namespace_frame",
        "slug_frame",
    ] {
        let text = state[name].as_str().ok_or(invalid)?;
        let bytes = hex::decode(text).map_err(|_| invalid)?;
        let width = if name.ends_with("_frame") { 64 } else { 32 };
        if bytes.len() != width || hex::encode(&bytes) != text {
            return Err(invalid);
        }
        fields.insert(name.into(), bytes);
    }
    let namespace = registration_component(&fields["namespace_frame"])?;
    let slug = registration_component(&fields["slug_frame"])?;
    if crate::registered_keys::namespace_key(namespace)? != hex::encode(&fields["namespace_hash"])
        || crate::registered_keys::child_name_key(namespace, slug)?
            != hex::encode(&fields["name_key"])
        || hex::encode(&fields["registry_root"])
            != "4e5507386557eb92c0cbce76ce0c90f8bd8e265ea9bb3d331a49ad947ce61bb4"
    {
        return Err(invalid);
    }
    let nonce = state["nonce"].as_u64().ok_or(invalid)?;
    let bond = state["bond_sompi"]
        .as_u64()
        .filter(|n| *n >= 100_000_000)
        .ok_or(invalid)?;
    let hi = state["gap_hi_is_max"]
        .as_u64()
        .filter(|n| *n <= 1)
        .ok_or(invalid)?;
    if fields["gap_lo"] >= fields["name_key"]
        || (hi == 0 && fields["name_key"] >= fields["gap_hi"])
        || (hi == 1 && fields["gap_hi"].iter().any(|b| *b != 0))
        || Sha256::digest(&fields["authority_xonly"]).as_slice() != fields["authority_commitment"]
    {
        return Err(invalid);
    }
    let parent_writes: Vec<_> = [
        "namespace_hash",
        "authority_commitment",
        "resolver_policy_hash",
        "registry_root",
    ]
    .iter()
    .enumerate()
    .map(|(i, name)| ByteWrite {
        offset: 2 + i * 33,
        bytes: fields[*name].clone(),
    })
    .chain(std::iter::once(ByteWrite {
        offset: 134,
        bytes: nonce.to_le_bytes().to_vec(),
    }))
    .collect();
    let parent = render(RegistryTemplate::AdapterParent, &parent_writes)?;
    let mut gap_writes = vec![ByteWrite {
        offset: 20,
        bytes: fields["gap_lo"].clone(),
    }];
    if hi == 0 {
        gap_writes.push(ByteWrite {
            offset: 53,
            bytes: fields["gap_hi"].clone(),
        });
    }
    for offset in [774, 1150, 8369] {
        gap_writes.push(ByteWrite {
            offset,
            bytes: fields["namespace_hash"].clone(),
        });
    }
    let gap = render_registration_gap(hi == 1, &gap_writes)?;
    if let Some(input_scripts) = input_scripts {
        for (redeem, observed) in [&parent, &gap].into_iter().zip(input_scripts) {
            let expected = [
                vec![0, 0, 0xaa, 0x20],
                crate::name_state_template::blake2b_256(redeem).to_vec(),
                vec![0x87],
            ]
            .concat();
            if *observed != expected {
                return Err("REGISTRATION_INPUT_SCRIPT_MISMATCH");
            }
        }
    }
    let mut successor = fields["name_key"].clone();
    let mut carry = true;
    for byte in successor.iter_mut().rev() {
        if carry {
            let (next, overflow) = byte.overflowing_add(1);
            *byte = next;
            carry = overflow;
        }
    }
    if carry {
        return Err(invalid);
    }
    let zero = vec![0; 32];
    let numbers = |values: [u64; 3]| {
        values
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect::<Vec<_>>()
    };
    let columns = vec![
        numbers([0, 1, 0]),
        numbers([0, 0, 0]),
        [
            fields["gap_lo"].clone(),
            fields["name_key"].clone(),
            successor.clone(),
        ]
        .concat(),
        [
            fields["name_key"].clone(),
            successor.clone(),
            fields["gap_hi"].clone(),
        ]
        .concat(),
        numbers([0, 0, hi]),
        [zero.clone(), fields["name_key"].clone(), zero.clone()].concat(),
        [
            zero.clone(),
            Sha256::digest(&fields["claimant_xonly"]).to_vec(),
            zero.clone(),
        ]
        .concat(),
        [
            zero.clone(),
            fields["target_commitment"].clone(),
            zero.clone(),
        ]
        .concat(),
        [
            zero.clone(),
            Sha256::digest(&fields["target_authority_xonly"]).to_vec(),
            zero.clone(),
        ]
        .concat(),
        [
            zero.clone(),
            fields["child_resolver_policy_hash"].clone(),
            zero,
        ]
        .concat(),
        numbers([0, bond, 0]),
    ];
    for (i, column) in columns.into_iter().enumerate() {
        fields.insert(format!("next_state_{i}"), column);
    }
    fields.insert("nonce".into(), unsigned_script_number(nonce));
    fields.insert("bond_sompi".into(), unsigned_script_number(bond));
    fields.insert("signature".into(), vec![0; 65]);
    fields.insert("zero".into(), vec![]);
    fields.insert("successor_key".into(), successor);
    fields.insert("parent_prefix".into(), parent[..1].to_vec());
    fields.insert("parent_suffix".into(), parent[142..].to_vec());
    fields.insert("parent_redeem".into(), parent);
    fields.insert("gap_redeem".into(), gap);
    let abi: Value = serde_json::from_str(include_str!("../../../data/regi-abi-v1.json"))
        .map_err(|_| invalid)?;
    let mut result = [Vec::new(), Vec::new()];
    let mut contexts = Vec::new();
    for (index, (script, name)) in result.iter_mut().zip(["parent", "child"]).enumerate() {
        let arguments = abi[name].as_array().ok_or(invalid)?;
        let mut context_arguments = Vec::new();
        for (position, argument) in arguments.iter().enumerate() {
            let bytes = fields
                .get(argument.as_str().ok_or(invalid)?)
                .ok_or(invalid)?;
            push_witness_item(script, bytes)?;
            if position + 1 < arguments.len() {
                context_arguments.push(match bytes.as_slice() {
                    [] => serde_json::json!({"opcode": 0}),
                    [byte @ 1..=16] => serde_json::json!({"opcode": 0x50 + byte}),
                    _ => serde_json::json!({"data_hex": hex::encode(bytes)}),
                });
            }
        }
        contexts.push(serde_json::json!({
            "input_index": index,
            "entrypoint": (["authorize_child", "register_interior"][index]),
            "registration_kind": "INTERIOR",
            "redeem_script_hex": hex::encode(&fields[if index == 0 { "parent_redeem" } else { "gap_redeem" }]),
            "arguments": context_arguments,
            "signature_slot_indices": abi["signature_slots"][name],
        }));
    }
    Ok((result, Value::Array(contexts)))
}

fn registration_component(frame: &[u8]) -> Result<&str, &'static str> {
    let invalid = "REGISTRATION_STATE_INVALID";
    let length = usize::from(*frame.first().ok_or(invalid)?);
    if length == 0
        || length > 63
        || frame.len() != 64
        || frame[1 + length..].iter().any(|byte| *byte != 0)
    {
        return Err(invalid);
    }
    let component = std::str::from_utf8(&frame[1..1 + length]).map_err(|_| invalid)?;
    crate::registered_keys::namespace_key(component).map_err(|_| invalid)?;
    Ok(component)
}

fn unsigned_script_number(value: u64) -> Vec<u8> {
    let mut bytes = value.to_le_bytes().to_vec();
    while bytes.last() == Some(&0) {
        bytes.pop();
    }
    if bytes.last().is_some_and(|byte| byte & 0x80 != 0) {
        bytes.push(0);
    }
    bytes
}

fn push_witness_item(script: &mut Vec<u8>, bytes: &[u8]) -> Result<(), &'static str> {
    match bytes {
        [] => script.push(0),
        [n @ 1..=16] => script.push(0x50 + n),
        _ => {
            match bytes.len() {
                n @ 1..=75 => script.push(n as u8),
                n @ 76..=255 => script.extend([0x4c, n as u8]),
                n @ 256..=65535 => {
                    script.push(0x4d);
                    script.extend((n as u16).to_le_bytes());
                }
                _ => return Err("REGISTRATION_WITNESS_ITEM_TOO_LARGE"),
            }
            script.extend(bytes);
        }
    }
    Ok(())
}

/// Render one frozen registry script after checking the pinned metadata and every byte write.
/// Every mutable slot must be supplied exactly once; fixed and unknown slots are rejected.
pub fn render(template: RegistryTemplate, writes: &[ByteWrite]) -> Result<Vec<u8>, &'static str> {
    let (data, schema, source_sha, template_hash, variant) = match template {
        RegistryTemplate::RegistrationGapFinite | RegistryTemplate::RegistrationGapUnbounded => (
            REGISTRATION_GAP_DATA,
            "KTAPEOUT-REGISTRY-ADAPTER-REGISTRATION-GAP-TEMPLATE-V1",
            GAP_SOURCE_SHA256,
            "43044e7e0d3b694657d815c2d9ed2e5a94973827d2e2f61838a1afcd0c5fa95a",
            Some(usize::from(
                template == RegistryTemplate::RegistrationGapUnbounded,
            )),
        ),
        RegistryTemplate::GapFinite => (
            GAP_DATA,
            GAP_SCHEMA,
            GAP_SOURCE_SHA256,
            GAP_TEMPLATE_HASH,
            Some(0),
        ),
        RegistryTemplate::GapUnbounded => (
            GAP_DATA,
            GAP_SCHEMA,
            GAP_SOURCE_SHA256,
            GAP_TEMPLATE_HASH,
            Some(1),
        ),
        RegistryTemplate::AdapterParent => (
            PARENT_DATA,
            PARENT_SCHEMA,
            PARENT_SOURCE_SHA256,
            PARENT_TEMPLATE_HASH,
            None,
        ),
        RegistryTemplate::IssuanceCertificate => (
            CERTIFICATE_DATA,
            CERTIFICATE_SCHEMA,
            CERTIFICATE_SOURCE_SHA256,
            CERTIFICATE_TEMPLATE_HASH,
            None,
        ),
    };
    let document: Value = serde_json::from_str(data).map_err(|_| "REGISTRY_TEMPLATE_INVALID")?;
    if document["schema"].as_str() != Some(schema)
        || document["source_sha256"].as_str() != Some(source_sha)
        || document["template_hash"].as_str() != Some(template_hash)
    {
        return Err("REGISTRY_TEMPLATE_PIN_MISMATCH");
    }
    let selected = if let Some(index) = variant {
        let variants = document["variants"]
            .as_array()
            .ok_or("REGISTRY_TEMPLATE_INVALID")?;
        let item = variants.get(index).ok_or("REGISTRY_TEMPLATE_INVALID")?;
        let expected_flag = u64::from(index == 1);
        if item["hi_is_max"].as_u64() != Some(expected_flag) {
            return Err("REGISTRY_TEMPLATE_PIN_MISMATCH");
        }
        item
    } else {
        &document
    };

    let mut script = hex::decode(
        selected["template_hex"]
            .as_str()
            .ok_or("REGISTRY_TEMPLATE_INVALID")?,
    )
    .map_err(|_| "REGISTRY_TEMPLATE_INVALID")?;
    let base_hash = hex::encode(Sha256::digest(&script));
    if selected["script_sha256"].as_str() != Some(base_hash.as_str()) {
        return Err("REGISTRY_TEMPLATE_PIN_MISMATCH");
    }

    if let Some(fixed) = selected["fixed"].as_array() {
        for field in fixed {
            let offset = field["offset"]
                .as_u64()
                .and_then(|value| usize::try_from(value).ok())
                .ok_or("REGISTRY_TEMPLATE_INVALID")?;
            let length = field["length"]
                .as_u64()
                .and_then(|value| usize::try_from(value).ok())
                .ok_or("REGISTRY_TEMPLATE_INVALID")?;
            let expected = hex::decode(field["hex"].as_str().ok_or("REGISTRY_TEMPLATE_INVALID")?)
                .map_err(|_| "REGISTRY_TEMPLATE_INVALID")?;
            let end = offset
                .checked_add(length)
                .filter(|end| *end <= script.len())
                .ok_or("REGISTRY_TEMPLATE_INVALID")?;
            if expected.len() != length || script[offset..end] != expected {
                return Err("REGISTRY_TEMPLATE_PIN_MISMATCH");
            }
        }
    }

    let mutable = selected["mutable"]
        .as_array()
        .ok_or("REGISTRY_TEMPLATE_INVALID")?;
    if writes.len() != mutable.len() {
        return Err("REGISTRY_TEMPLATE_WRITE_SET_INCOMPLETE");
    }
    let mut written = Vec::with_capacity(writes.len());
    for write in writes {
        if written.contains(&write.offset) {
            return Err("REGISTRY_TEMPLATE_WRITE_DUPLICATE");
        }
        let site = mutable
            .iter()
            .find(|site| site["offset"].as_u64() == u64::try_from(write.offset).ok())
            .ok_or("REGISTRY_TEMPLATE_WRITE_NOT_MUTABLE")?;
        let expected_len = site["length"]
            .as_u64()
            .and_then(|length| usize::try_from(length).ok())
            .ok_or("REGISTRY_TEMPLATE_INVALID")?;
        if write.bytes.len() != expected_len {
            return Err("REGISTRY_TEMPLATE_WRITE_LENGTH_MISMATCH");
        }
        let end = write
            .offset
            .checked_add(expected_len)
            .filter(|end| *end <= script.len())
            .ok_or("REGISTRY_TEMPLATE_INVALID")?;
        script[write.offset..end].copy_from_slice(&write.bytes);
        written.push(write.offset);
    }
    Ok(script)
}
