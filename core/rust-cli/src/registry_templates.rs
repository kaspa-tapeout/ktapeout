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
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ByteWrite {
    pub offset: usize,
    pub bytes: Vec<u8>,
}

/// Render one frozen registry script after checking the pinned metadata and every byte write.
/// Every mutable slot must be supplied exactly once; fixed and unknown slots are rejected.
pub fn render(template: RegistryTemplate, writes: &[ByteWrite]) -> Result<Vec<u8>, &'static str> {
    let (data, schema, source_sha, template_hash, variant) = match template {
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
