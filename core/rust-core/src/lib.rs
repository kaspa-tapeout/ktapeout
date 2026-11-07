//! Independent KTAPEOUT v0.5.0 Core codec.
//!
//! This crate intentionally implements only the consensus-facing record
//! boundary.  It does not construct transactions, sign keys, or broadcast.

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt;

mod content_chunk_set;
pub use content_chunk_set::verify_l1_content_chunk_set_050;

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

pub const ZERO32: [u8; 32] = [0; 32];
pub const MAX_TEXT: usize = 128;
pub const MAX_RECORD_BYTES: usize = 256 * 1024;
/// Maximum plaintext accepted by the generic private-object wire candidate.
pub const PRIVATE_OBJECT_WIRE_V1_MAX_PLAINTEXT_BYTES: usize = 190 * 1024;
/// Maximum complete private-object wire envelope accepted by the candidate codec.
pub const PRIVATE_OBJECT_WIRE_V1_MAX_BYTES: usize = 256 * 1024;
pub const MAX_BATCH: usize = 64;
const MAX_CONTENT_FILES: usize = 64;
const MAX_CONTENT_CHUNK_BYTES: usize = 96 * 1024;
const MAX_CONTENT_ARTIFACT_BYTES: usize = 256 * 1024;
const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_LIFE_NEURONS: u64 = 302;
const MAX_LIFE_CELLS: u64 = 1024;
const MAX_LIFE_STEPS: u32 = 10_000;
const MAX_LIFE_VECTOR: usize = 64;
const MAX_EXTERNAL_SIGNING_JSON_BYTES: usize = 512 * 1024;
const MAX_EXTERNAL_SIGNING_JSON_DEPTH: usize = 64;
const MAX_EXTERNAL_SIGNING_JSON_NODES: usize = 16_384;
const MAX_EXTERNAL_SIGNING_JSON_ENTRIES: usize = 4_096;
const PRIVATE_OBJECT_WIRE_V1_MAGIC: &[u8; 8] = b"KTOBJ001";
const PRIVATE_OBJECT_WIRE_V1_NONCE_BYTES: usize = 12;
const PRIVATE_OBJECT_WIRE_V1_TAG_BYTES: usize = 16;
const PRIVATE_OBJECT_WIRE_V1_HASH_BYTES: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodecError(pub String);

impl fmt::Display for CodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for CodecError {}

type Result<T> = std::result::Result<T, CodecError>;

fn err(message: &str) -> CodecError {
    CodecError(message.to_owned())
}

struct StrictJsonValue(Value);

impl<'de> serde::Deserialize<'de> for StrictJsonValue {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        deserializer.deserialize_any(StrictJsonVisitor).map(Self)
    }
}

struct StrictJsonVisitor;

impl<'de> Visitor<'de> for StrictJsonVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("JSON without duplicate object keys")
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> std::result::Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> std::result::Result<Self::Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> std::result::Result<Self::Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> std::result::Result<Self::Value, E> {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("nonfinite JSON number"))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> std::result::Result<Self::Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E: de::Error>(self, value: String) -> std::result::Result<Self::Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E: de::Error>(self) -> std::result::Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E: de::Error>(self) -> std::result::Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(
        self,
        mut sequence: A,
    ) -> std::result::Result<Self::Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<StrictJsonValue>()? {
            values.push(value.0);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A: MapAccess<'de>>(
        self,
        mut map: A,
    ) -> std::result::Result<Self::Value, A::Error> {
        let mut values = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom("duplicate JSON object key"));
            }
            values.insert(key, map.next_value::<StrictJsonValue>()?.0);
        }
        Ok(Value::Object(values))
    }
}

/// Parse caller-provided JSON without allowing duplicate object keys.
///
/// This is the single Rust boundary used by Core, Runtime, CLI and adapters.
/// Ordinary `serde_json::Value` parsing keeps the last duplicate key, which is
/// not acceptable before commitment, signing, or policy validation.
pub fn parse_strict_json(raw_json: &[u8]) -> Result<Value> {
    serde_json::from_slice::<StrictJsonValue>(raw_json)
        .map(|value| value.0)
        .map_err(|error| err(&format!("E050_JSON_STRICT_PARSE: {error}")))
}

/// Validate strict JSON at the Core boundary without exporting a
/// `serde_json::Value` type across crate boundaries. Returning canonical bytes
/// keeps Runtime/CLI independent from the exact serde_json crate instance
/// selected by their own Cargo lockfile while preserving duplicate-key
/// rejection in this crate.
pub fn parse_strict_json_canonical_bytes(raw_json: &[u8]) -> Result<Vec<u8>> {
    let value = parse_strict_json(raw_json)?;
    serde_json::to_vec(&value).map_err(|error| err(&format!("E050_JSON_STRICT_ENCODE: {error}")))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExternalSigningJsonGuardSummary {
    pub byte_length: usize,
    pub node_count: usize,
    pub max_depth: usize,
}

#[derive(Default)]
struct ExternalSigningJsonBudget {
    node_count: usize,
    max_depth: usize,
    root_is_object: bool,
}

struct ExternalSigningJsonSeed<'a> {
    budget: &'a mut ExternalSigningJsonBudget,
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for ExternalSigningJsonSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if self.depth > MAX_EXTERNAL_SIGNING_JSON_DEPTH {
            return Err(de::Error::custom("E050_TXJSON_DEPTH_LIMIT"));
        }
        self.budget.node_count += 1;
        if self.budget.node_count > MAX_EXTERNAL_SIGNING_JSON_NODES {
            return Err(de::Error::custom("E050_TXJSON_NODE_LIMIT"));
        }
        self.budget.max_depth = self.budget.max_depth.max(self.depth);
        deserializer.deserialize_any(ExternalSigningJsonVisitor {
            budget: self.budget,
            depth: self.depth,
        })
    }
}

struct ExternalSigningJsonVisitor<'a> {
    budget: &'a mut ExternalSigningJsonBudget,
    depth: usize,
}

impl<'de> Visitor<'de> for ExternalSigningJsonVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("bounded JSON without duplicate or credential-bearing keys")
    }

    fn visit_bool<E>(self, _: bool) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_i64<E>(self, _: i64) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_u64<E>(self, _: u64) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_f64<E>(self, _: f64) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_str<E>(self, _: &str) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_string<E>(self, _: String) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_unit<E>(self) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_none<E>(self) -> std::result::Result<(), E> {
        Ok(())
    }

    fn visit_some<D>(self, deserializer: D) -> std::result::Result<(), D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        ExternalSigningJsonSeed {
            budget: self.budget,
            depth: self.depth + 1,
        }
        .deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<(), A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut entries = 0;
        while sequence
            .next_element_seed(ExternalSigningJsonSeed {
                budget: &mut *self.budget,
                depth: self.depth + 1,
            })?
            .is_some()
        {
            entries += 1;
            if entries > MAX_EXTERNAL_SIGNING_JSON_ENTRIES {
                return Err(de::Error::custom("E050_TXJSON_CONTAINER_LIMIT"));
            }
        }
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<(), A::Error>
    where
        A: MapAccess<'de>,
    {
        if self.depth == 0 {
            self.budget.root_is_object = true;
        }
        let mut keys = HashSet::new();
        let mut entries = 0;
        while let Some(key) = map.next_key::<String>()? {
            entries += 1;
            if entries > MAX_EXTERNAL_SIGNING_JSON_ENTRIES {
                return Err(de::Error::custom("E050_TXJSON_CONTAINER_LIMIT"));
            }
            if !keys.insert(key.clone()) {
                return Err(de::Error::custom("E050_TXJSON_DUPLICATE_KEY"));
            }
            if contains_credential_key(&key) {
                return Err(de::Error::custom("E050_TXJSON_CREDENTIAL_KEY"));
            }
            map.next_value_seed(ExternalSigningJsonSeed {
                budget: &mut *self.budget,
                depth: self.depth + 1,
            })?;
        }
        Ok(())
    }
}

fn contains_credential_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut search_from = 0;
    let seed_token = loop {
        let Some(offset) = lower[search_from..].find("seed") else {
            break false;
        };
        let start = search_from + offset;
        let end = start + 4;
        let left_boundary = start == 0 || matches!(bytes[start - 1], b'_' | b'-');
        let right_boundary = end == bytes.len() || matches!(bytes[end], b'_' | b'-');
        if left_boundary && right_boundary {
            break true;
        }
        search_from = end;
        if search_from >= bytes.len() {
            break false;
        }
    };
    lower.contains("private_key")
        || lower.contains("private-key")
        || lower.contains("privatekey")
        || lower.contains("mnemonic")
        || lower.contains("passphrase")
        || lower.contains("password")
        || lower.contains("wif")
        || lower.contains("credential")
        || seed_token
}

/// Apply parse-time resource and ambiguity limits to untrusted signing JSON.
/// This is only an input guard: it does not decode Kaspa transactions, verify
/// signatures, bind a SignPlan, or authorize signing/broadcast.
pub fn guard_external_signing_json_050(raw_json: &[u8]) -> Result<ExternalSigningJsonGuardSummary> {
    if raw_json.is_empty() || raw_json.len() > MAX_EXTERNAL_SIGNING_JSON_BYTES {
        return Err(err("E050_TXJSON_BYTE_LIMIT"));
    }
    let mut budget = ExternalSigningJsonBudget::default();
    let mut deserializer = serde_json::Deserializer::from_slice(raw_json);
    ExternalSigningJsonSeed {
        budget: &mut budget,
        depth: 0,
    }
    .deserialize(&mut deserializer)
    .map_err(|error| err(&format!("E050_TXJSON_PARSE: {error}")))?;
    deserializer
        .end()
        .map_err(|error| err(&format!("E050_TXJSON_PARSE: {error}")))?;
    if !budget.root_is_object {
        return Err(err("E050_TXJSON_ROOT_OBJECT_REQUIRED"));
    }
    Ok(ExternalSigningJsonGuardSummary {
        byte_length: raw_json.len(),
        node_count: budget.node_count,
        max_depth: budget.max_depth,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Topology {
    Singleton,
    Independent,
    BoundedCollective,
}
impl Topology {
    fn wire(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeMode {
    None,
    Disjoint,
    Ordered,
    Reducer,
}
impl MergeMode {
    fn wire(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionKind {
    Local,
    AtomicBatch,
    Migration,
}
impl ActionKind {
    fn wire(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealStrength {
    LocalReceipt,
    Accumulator,
    FullBarrier,
}
impl SealStrength {
    fn wire(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BarrierMode {
    None,
    DirectCoverage,
    L1Proof,
}
impl BarrierMode {
    fn wire(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectorKind {
    FixedRange,
    MerkleCommitment,
}
impl SelectorKind {
    fn wire(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionLayout {
    pub version: u32,
    pub protocol_id: String,
    pub protocol_semver: String,
    pub critical_features_root: [u8; 32],
    pub optional_features_root: [u8; 32],
    pub deployment_id: [u8; 32],
    pub profile_hash: [u8; 32],
    pub layout_id: [u8; 32],
    pub partition_id_domain: [u8; 32],
    pub partition_count: u32,
    pub leaf_encoding_hash: [u8; 32],
    pub topology: Topology,
    pub merge_mode: MergeMode,
    pub template_root: [u8; 32],
    pub invariant_hash: [u8; 32],
    pub network_policy_class: [u8; 32],
    pub max_partition_state_bytes: u64,
    pub max_batch_inputs: u32,
    pub max_batch_outputs: u32,
    pub max_selector_proof_bytes: u64,
    pub max_witness_bytes: u64,
    pub max_ops: u64,
    pub max_compute_units: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionAction {
    pub version: u32,
    pub layout_hash: [u8; 32],
    pub action_kind: ActionKind,
    pub epoch: u64,
    pub action_nonce: u64,
    pub selector_kind: SelectorKind,
    pub selector_commitment: [u8; 32],
    pub input_outpoint_root: [u8; 32],
    pub previous_state_root: [u8; 32],
    pub successor_root: [u8; 32],
    pub capability_hash: [u8; 32],
    pub policy_hash: [u8; 32],
    pub resource_bill_hash: [u8; 32],
    pub dependency_root: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectiveSeal {
    pub version: u32,
    pub layout_hash: [u8; 32],
    pub epoch: u64,
    pub seal_strength: SealStrength,
    pub barrier_mode: BarrierMode,
    pub previous_seal_hash: [u8; 32],
    pub expected_selector_commitment: [u8; 32],
    pub included_action_root: [u8; 32],
    pub coverage_commitment: [u8; 32],
    pub state_commitment: [u8; 32],
    pub proof_binding_hash: [u8; 32],
    pub authority_hash: [u8; 32],
    pub resource_bill_hash: [u8; 32],
}

fn u32le(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn u64le(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn hash(out: &mut Vec<u8>, v: &[u8; 32]) {
    out.extend_from_slice(v);
}

fn text(out: &mut Vec<u8>, value: &str, field: &str) -> Result<()> {
    let raw = value.as_bytes();
    if raw.is_empty() || raw.len() > MAX_TEXT || raw.len() > u16::MAX as usize {
        return Err(err(&format!("E050_ENCODING: {field} text bound")));
    }
    let size = raw.len() as u16;
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(raw);
    Ok(())
}

fn nonzero(value: &[u8; 32], field: &str) -> Result<()> {
    if value == &ZERO32 {
        Err(err(&format!("E050_BINDING: {field} cannot be zero")))
    } else {
        Ok(())
    }
}

fn finish(out: Vec<u8>) -> Result<Vec<u8>> {
    if out.len() > MAX_RECORD_BYTES {
        Err(err("E050_RESOURCE: record exceeds max bytes"))
    } else {
        Ok(out)
    }
}

pub fn encode_partition_layout(v: &PartitionLayout) -> Result<Vec<u8>> {
    if v.version != 1 || v.protocol_id != "KTAPEOUT" || v.protocol_semver != "0.5.0" {
        return Err(err(
            "E050_VERSION: layout version or protocol semver is invalid",
        ));
    }
    if v.partition_count == 0
        || v.max_partition_state_bytes == 0
        || v.max_batch_inputs == 0
        || v.max_batch_outputs == 0
        || v.max_batch_inputs > 64
        || v.max_batch_outputs > 64
    {
        return Err(err("E050_LAYOUT: layout bounds are invalid"));
    }
    if v.critical_features_root == ZERO32 || v.optional_features_root == ZERO32 {
        return Err(err("E050_VERSION: feature root cannot be zero"));
    }
    for (field, value) in [
        ("deployment_id", &v.deployment_id),
        ("profile_hash", &v.profile_hash),
        ("layout_id", &v.layout_id),
        ("partition_id_domain", &v.partition_id_domain),
        ("leaf_encoding_hash", &v.leaf_encoding_hash),
        ("template_root", &v.template_root),
        ("invariant_hash", &v.invariant_hash),
        ("network_policy_class", &v.network_policy_class),
    ] {
        nonzero(value, field)?;
    }
    if matches!(v.topology, Topology::Singleton) && !matches!(v.merge_mode, MergeMode::None) {
        return Err(err("E050_LAYOUT: singleton cannot declare merge mode"));
    }
    if matches!(v.topology, Topology::BoundedCollective) && matches!(v.merge_mode, MergeMode::None)
    {
        return Err(err("E050_LAYOUT: collective topology requires merge mode"));
    }
    let mut out = Vec::new();
    u32le(&mut out, v.version);
    text(&mut out, &v.protocol_id, "protocol_id")?;
    text(&mut out, &v.protocol_semver, "protocol_semver")?;
    for value in [
        &v.critical_features_root,
        &v.optional_features_root,
        &v.deployment_id,
        &v.profile_hash,
        &v.layout_id,
        &v.partition_id_domain,
    ] {
        hash(&mut out, value);
    }
    u32le(&mut out, v.partition_count);
    hash(&mut out, &v.leaf_encoding_hash);
    out.push(v.topology.wire());
    out.push(v.merge_mode.wire());
    for value in [&v.template_root, &v.invariant_hash, &v.network_policy_class] {
        hash(&mut out, value);
    }
    u64le(&mut out, v.max_partition_state_bytes);
    u32le(&mut out, v.max_batch_inputs);
    u32le(&mut out, v.max_batch_outputs);
    u64le(&mut out, v.max_selector_proof_bytes);
    u64le(&mut out, v.max_witness_bytes);
    u64le(&mut out, v.max_ops);
    u64le(&mut out, v.max_compute_units);
    finish(out)
}

pub fn encode_partition_action(v: &PartitionAction) -> Result<Vec<u8>> {
    if v.version != 1 {
        return Err(err("E050_VERSION: action version is invalid"));
    }
    for (field, value) in [
        ("layout_hash", &v.layout_hash),
        ("selector_commitment", &v.selector_commitment),
        ("input_outpoint_root", &v.input_outpoint_root),
        ("successor_root", &v.successor_root),
        ("capability_hash", &v.capability_hash),
        ("policy_hash", &v.policy_hash),
        ("resource_bill_hash", &v.resource_bill_hash),
        ("dependency_root", &v.dependency_root),
    ] {
        nonzero(value, field)?;
    }
    if v.epoch > 0 && v.previous_state_root == ZERO32 {
        return Err(err(
            "E050_BINDING: non-genesis action state root cannot be zero",
        ));
    }
    let mut out = Vec::new();
    u32le(&mut out, v.version);
    hash(&mut out, &v.layout_hash);
    out.push(v.action_kind.wire());
    u64le(&mut out, v.epoch);
    u64le(&mut out, v.action_nonce);
    out.push(v.selector_kind.wire());
    for value in [
        &v.selector_commitment,
        &v.input_outpoint_root,
        &v.previous_state_root,
        &v.successor_root,
        &v.capability_hash,
        &v.policy_hash,
        &v.resource_bill_hash,
        &v.dependency_root,
    ] {
        hash(&mut out, value);
    }
    finish(out)
}

pub fn encode_collective_seal(v: &CollectiveSeal) -> Result<Vec<u8>> {
    if v.version != 1 {
        return Err(err("E050_VERSION: seal version is invalid"));
    }
    for (field, value) in [
        ("layout_hash", &v.layout_hash),
        (
            "expected_selector_commitment",
            &v.expected_selector_commitment,
        ),
        ("included_action_root", &v.included_action_root),
        ("coverage_commitment", &v.coverage_commitment),
        ("state_commitment", &v.state_commitment),
        ("authority_hash", &v.authority_hash),
        ("resource_bill_hash", &v.resource_bill_hash),
    ] {
        nonzero(value, field)?;
    }
    match (v.seal_strength, v.barrier_mode) {
        (SealStrength::LocalReceipt | SealStrength::Accumulator, BarrierMode::None)
            if v.proof_binding_hash == ZERO32 => {}
        (SealStrength::FullBarrier, BarrierMode::DirectCoverage)
            if v.proof_binding_hash == ZERO32 => {}
        (SealStrength::FullBarrier, BarrierMode::L1Proof) if v.proof_binding_hash != ZERO32 => {}
        _ => return Err(err("E050_BARRIER: seal strength and barrier are ambiguous")),
    }
    if v.epoch == 0 && v.previous_seal_hash != ZERO32 {
        return Err(err(
            "E050_REPLAY: genesis seal must have zero previous seal",
        ));
    }
    if v.epoch > 0 && v.previous_seal_hash == ZERO32 {
        return Err(err("E050_REPLAY: non-genesis seal must link previous seal"));
    }
    let mut out = Vec::new();
    u32le(&mut out, v.version);
    hash(&mut out, &v.layout_hash);
    u64le(&mut out, v.epoch);
    out.push(v.seal_strength.wire());
    out.push(v.barrier_mode.wire());
    for value in [
        &v.previous_seal_hash,
        &v.expected_selector_commitment,
        &v.included_action_root,
        &v.coverage_commitment,
        &v.state_commitment,
        &v.proof_binding_hash,
        &v.authority_hash,
        &v.resource_bill_hash,
    ] {
        hash(&mut out, value);
    }
    finish(out)
}

struct Reader<'a> {
    raw: &'a [u8],
    cursor: usize,
}

impl<'a> Reader<'a> {
    fn new(raw: &'a [u8]) -> Result<Self> {
        if raw.len() > MAX_RECORD_BYTES {
            return Err(err("E050_ENCODING: record bytes exceed max"));
        }
        Ok(Self { raw, cursor: 0 })
    }
    fn take(&mut self, width: usize, field: &str) -> Result<&'a [u8]> {
        let end = self
            .cursor
            .checked_add(width)
            .ok_or_else(|| err("E050_ENCODING: cursor overflow"))?;
        if end > self.raw.len() {
            return Err(err(&format!("E050_ENCODING: {field} is truncated")));
        }
        let result = &self.raw[self.cursor..end];
        self.cursor = end;
        Ok(result)
    }
    fn take_array<const N: usize>(&mut self, field: &str) -> Result<[u8; N]> {
        self.take(N, field)?
            .try_into()
            .map_err(|_| err(&format!("E050_ENCODING: {field} width mismatch")))
    }
    fn u32(&mut self, field: &str) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take_array(field)?))
    }
    fn u64(&mut self, field: &str) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take_array(field)?))
    }
    fn hash(&mut self, field: &str) -> Result<[u8; 32]> {
        self.take_array(field)
    }
    fn text(&mut self, field: &str) -> Result<String> {
        let size = u16::from_le_bytes(self.take_array(field)?) as usize;
        if size == 0 || size > MAX_TEXT {
            return Err(err(&format!("E050_ENCODING: {field} text bound")));
        }
        String::from_utf8(self.take(size, field)?.to_vec())
            .map_err(|_| err(&format!("E050_ENCODING: {field} is not UTF-8")))
    }
    fn done(&self, field: &str) -> Result<()> {
        if self.cursor != self.raw.len() {
            Err(err(&format!(
                "E050_ENCODING: {field} contains trailing bytes"
            )))
        } else {
            Ok(())
        }
    }
}

fn topology(byte: u8) -> Result<Topology> {
    match byte {
        0 => Ok(Topology::Singleton),
        1 => Ok(Topology::Independent),
        2 => Ok(Topology::BoundedCollective),
        _ => Err(err("E050_LAYOUT: topology ordinal is invalid")),
    }
}
fn merge_mode(byte: u8) -> Result<MergeMode> {
    match byte {
        0 => Ok(MergeMode::None),
        1 => Ok(MergeMode::Disjoint),
        2 => Ok(MergeMode::Ordered),
        3 => Ok(MergeMode::Reducer),
        _ => Err(err("E050_LAYOUT: merge_mode ordinal is invalid")),
    }
}
fn action_kind(byte: u8) -> Result<ActionKind> {
    match byte {
        0 => Ok(ActionKind::Local),
        1 => Ok(ActionKind::AtomicBatch),
        2 => Ok(ActionKind::Migration),
        _ => Err(err("E050_LAYOUT: action_kind ordinal is invalid")),
    }
}
fn selector_kind(byte: u8) -> Result<SelectorKind> {
    match byte {
        0 => Ok(SelectorKind::FixedRange),
        1 => Ok(SelectorKind::MerkleCommitment),
        _ => Err(err("E050_LAYOUT: selector_kind ordinal is invalid")),
    }
}
fn seal_strength(byte: u8) -> Result<SealStrength> {
    match byte {
        0 => Ok(SealStrength::LocalReceipt),
        1 => Ok(SealStrength::Accumulator),
        2 => Ok(SealStrength::FullBarrier),
        _ => Err(err("E050_LAYOUT: seal_strength ordinal is invalid")),
    }
}
fn barrier_mode(byte: u8) -> Result<BarrierMode> {
    match byte {
        0 => Ok(BarrierMode::None),
        1 => Ok(BarrierMode::DirectCoverage),
        2 => Ok(BarrierMode::L1Proof),
        _ => Err(err("E050_LAYOUT: barrier_mode ordinal is invalid")),
    }
}

pub fn decode_partition_layout(raw: &[u8]) -> Result<PartitionLayout> {
    let mut r = Reader::new(raw)?;
    let v = PartitionLayout {
        version: r.u32("version")?,
        protocol_id: r.text("protocol_id")?,
        protocol_semver: r.text("protocol_semver")?,
        critical_features_root: r.hash("critical_features_root")?,
        optional_features_root: r.hash("optional_features_root")?,
        deployment_id: r.hash("deployment_id")?,
        profile_hash: r.hash("profile_hash")?,
        layout_id: r.hash("layout_id")?,
        partition_id_domain: r.hash("partition_id_domain")?,
        partition_count: r.u32("partition_count")?,
        leaf_encoding_hash: r.hash("leaf_encoding_hash")?,
        topology: topology(r.take(1, "topology")?[0])?,
        merge_mode: merge_mode(r.take(1, "merge_mode")?[0])?,
        template_root: r.hash("template_root")?,
        invariant_hash: r.hash("invariant_hash")?,
        network_policy_class: r.hash("network_policy_class")?,
        max_partition_state_bytes: r.u64("max_partition_state_bytes")?,
        max_batch_inputs: r.u32("max_batch_inputs")?,
        max_batch_outputs: r.u32("max_batch_outputs")?,
        max_selector_proof_bytes: r.u64("max_selector_proof_bytes")?,
        max_witness_bytes: r.u64("max_witness_bytes")?,
        max_ops: r.u64("max_ops")?,
        max_compute_units: r.u64("max_compute_units")?,
    };
    r.done("partition_layout")?;
    encode_partition_layout(&v)?;
    Ok(v)
}

pub fn decode_partition_action(raw: &[u8]) -> Result<PartitionAction> {
    let mut r = Reader::new(raw)?;
    let v = PartitionAction {
        version: r.u32("version")?,
        layout_hash: r.hash("layout_hash")?,
        action_kind: action_kind(r.take(1, "action_kind")?[0])?,
        epoch: r.u64("epoch")?,
        action_nonce: r.u64("action_nonce")?,
        selector_kind: selector_kind(r.take(1, "selector_kind")?[0])?,
        selector_commitment: r.hash("selector_commitment")?,
        input_outpoint_root: r.hash("input_outpoint_root")?,
        previous_state_root: r.hash("previous_state_root")?,
        successor_root: r.hash("successor_root")?,
        capability_hash: r.hash("capability_hash")?,
        policy_hash: r.hash("policy_hash")?,
        resource_bill_hash: r.hash("resource_bill_hash")?,
        dependency_root: r.hash("dependency_root")?,
    };
    r.done("partition_action")?;
    encode_partition_action(&v)?;
    Ok(v)
}

pub fn decode_collective_seal(raw: &[u8]) -> Result<CollectiveSeal> {
    let mut r = Reader::new(raw)?;
    let v = CollectiveSeal {
        version: r.u32("version")?,
        layout_hash: r.hash("layout_hash")?,
        epoch: r.u64("epoch")?,
        seal_strength: seal_strength(r.take(1, "seal_strength")?[0])?,
        barrier_mode: barrier_mode(r.take(1, "barrier_mode")?[0])?,
        previous_seal_hash: r.hash("previous_seal_hash")?,
        expected_selector_commitment: r.hash("expected_selector_commitment")?,
        included_action_root: r.hash("included_action_root")?,
        coverage_commitment: r.hash("coverage_commitment")?,
        state_commitment: r.hash("state_commitment")?,
        proof_binding_hash: r.hash("proof_binding_hash")?,
        authority_hash: r.hash("authority_hash")?,
        resource_bill_hash: r.hash("resource_bill_hash")?,
    };
    r.done("collective_seal")?;
    encode_collective_seal(&v)?;
    Ok(v)
}

fn commitment(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(domain);
    h.update([0]);
    h.update(bytes);
    h.finalize().into()
}

fn canonical_json_value(value: Value) -> Result<Value> {
    match value {
        Value::Object(object) => {
            let mut sorted = Map::new();
            let mut entries: Vec<(String, Value)> = object.into_iter().collect();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            for (key, child) in entries {
                sorted.insert(key, canonical_json_value(child)?);
            }
            Ok(Value::Object(sorted))
        }
        Value::Array(array) => Ok(Value::Array(
            array
                .into_iter()
                .map(canonical_json_value)
                .collect::<Result<Vec<_>>>()?,
        )),
        Value::Number(number) if number.is_f64() => Err(err(
            "E050X_ENCODING: extension JSON numbers must be integers",
        )),
        other => Ok(other),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex_bytes(value: &str, field: &str) -> Result<Vec<u8>> {
    if !value.len().is_multiple_of(2) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(err(&format!("E050_CONTENT: {field} is not hexadecimal")));
    }
    let mut output = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let high = (pair[0] as char)
            .to_digit(16)
            .ok_or_else(|| err(&format!("E050_CONTENT: {field} is not hexadecimal")))?;
        let low = (pair[1] as char)
            .to_digit(16)
            .ok_or_else(|| err(&format!("E050_CONTENT: {field} is not hexadecimal")))?;
        output.push(((high << 4) | low) as u8);
    }
    Ok(output)
}

fn content_string<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a str> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| err(&format!("E050_CONTENT: {field} must be a string")))
}

fn content_u64(object: &Map<String, Value>, field: &str) -> Result<u64> {
    object.get(field).and_then(Value::as_u64).ok_or_else(|| {
        err(&format!(
            "E050_CONTENT: {field} must be an unsigned integer"
        ))
    })
}

fn content_safe_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.contains('\\')
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

/// Verify the bounded, read-only OnChainContentV1 artifact and return its
/// canonical projection as JSON bytes.  This is deliberately a profile
/// verifier: it does not publish, sign, or authorize any L1 operation.
pub fn verify_content_artifact_050(raw_json: &[u8]) -> Result<Vec<u8>> {
    if raw_json.is_empty() || raw_json.len() > MAX_CONTENT_ARTIFACT_BYTES {
        return Err(err("E050_CONTENT: artifact bytes are outside the bound"));
    }
    let parsed =
        parse_strict_json(raw_json).map_err(|_| err("E050_CONTENT: artifact JSON is invalid"))?;
    let canonical = canonical_json_value(parsed)?;
    let canonical_bytes = serde_json::to_vec(&canonical)
        .map_err(|_| err("E050_CONTENT: artifact cannot be canonicalized"))?;
    if raw_json != canonical_bytes.as_slice() {
        return Err(err("E050_CONTENT: artifact JSON is not canonical"));
    }
    if canonical_bytes.len() > MAX_CONTENT_ARTIFACT_BYTES {
        return Err(err("E050_CONTENT: artifact exceeds 256 KiB"));
    }
    let object = canonical
        .as_object()
        .ok_or_else(|| err("E050_CONTENT: artifact must be an object"))?;
    if content_string(object, "schema")? != "KTAPEOUT-ONCHAIN-CONTENT-ARTIFACT-V1"
        || content_string(object, "profile_id")? != "OnChainContentV1"
        || object.get("profile_version").and_then(Value::as_u64) != Some(1)
        || object.get("broadcast").and_then(Value::as_bool) != Some(false)
    {
        return Err(err("E050_CONTENT: invalid artifact envelope"));
    }
    let artifact_hash = content_string(object, "artifact_sha256")?;
    if artifact_hash.len() != 64
        || !artifact_hash.bytes().all(|byte| byte.is_ascii_hexdigit())
        || artifact_hash != artifact_hash.to_ascii_lowercase()
    {
        return Err(err(
            "E050_CONTENT: artifact_sha256 is not lowercase SHA-256 hex",
        ));
    }
    let mut without_hash = object.clone();
    without_hash.remove("artifact_sha256");
    let without_hash_bytes = serde_json::to_vec(&Value::Object(without_hash))
        .map_err(|_| err("E050_CONTENT: artifact hash input cannot be encoded"))?;
    if sha256_hex(&without_hash_bytes) != artifact_hash {
        return Err(err("E050_CONTENT: artifact_sha256 mismatch"));
    }
    let entrypoint = content_string(object, "entrypoint")?;
    if !content_safe_path(entrypoint) {
        return Err(err("E050_CONTENT: entrypoint is not a safe path"));
    }
    let files = object
        .get("files")
        .and_then(Value::as_array)
        .ok_or_else(|| err("E050_CONTENT: files must be an array"))?;
    if files.is_empty() || files.len() > MAX_CONTENT_FILES {
        return Err(err("E050_CONTENT: file count is out of bounds"));
    }
    let mut paths = std::collections::BTreeSet::new();
    let mut metadata = Vec::with_capacity(files.len());
    let mut content = Vec::with_capacity(files.len());
    let mut total_bytes = 0u64;
    for file in files {
        let file_object = file
            .as_object()
            .ok_or_else(|| err("E050_CONTENT: file must be an object"))?;
        let path = content_string(file_object, "path")?;
        if !content_safe_path(path) || !paths.insert(path.to_owned()) {
            return Err(err("E050_CONTENT: file path is invalid or duplicated"));
        }
        let size = content_u64(file_object, "size")?;
        let chunk_count = content_u64(file_object, "chunk_count")?;
        if size > MAX_SAFE_JSON_INTEGER
            || chunk_count == 0
            || chunk_count > MAX_SAFE_JSON_INTEGER
            || chunk_count > usize::MAX as u64
        {
            return Err(err("E050_CONTENT: size or chunk_count is out of bounds"));
        }
        let sha256 = content_string(file_object, "sha256")?;
        if sha256.len() != 64
            || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
            || sha256 != sha256.to_ascii_lowercase()
        {
            return Err(err(
                "E050_CONTENT: file sha256 is not lowercase SHA-256 hex",
            ));
        }
        let chunks = file_object
            .get("chunks")
            .and_then(Value::as_array)
            .ok_or_else(|| err("E050_CONTENT: chunks must be an array"))?;
        if chunks.len() != chunk_count as usize {
            return Err(err("E050_CONTENT: chunk_count does not match chunks"));
        }
        let mut bytes = Vec::new();
        let mut chunk_values = Vec::with_capacity(chunks.len());
        for chunk in chunks {
            let raw = chunk
                .as_str()
                .ok_or_else(|| err("E050_CONTENT: chunk must be a string"))?;
            let decoded = decode_hex_bytes(raw, "chunk")?;
            if decoded.len() > MAX_CONTENT_CHUNK_BYTES {
                return Err(err("E050_CONTENT: chunk exceeds 96 KiB"));
            }
            bytes.extend_from_slice(&decoded);
            chunk_values.push(Value::String(raw.to_owned()));
        }
        if bytes.len() as u64 != size || sha256_hex(&bytes) != sha256 {
            return Err(err("E050_CONTENT: file bytes do not match metadata"));
        }
        total_bytes = total_bytes
            .checked_add(size)
            .ok_or_else(|| err("E050_CONTENT: total byte count overflow"))?;
        let mut metadata_entry = Map::new();
        metadata_entry.insert("path".to_owned(), Value::String(path.to_owned()));
        metadata_entry.insert("size".to_owned(), Value::from(size));
        if let Some(content_type) = file_object.get("content_type") {
            metadata_entry.insert("content_type".to_owned(), content_type.clone());
        }
        metadata_entry.insert("sha256".to_owned(), Value::String(sha256.to_owned()));
        metadata_entry.insert("chunk_count".to_owned(), Value::from(chunk_count));
        metadata.push(Value::Object(metadata_entry));
        let mut content_entry = Map::new();
        content_entry.insert("path".to_owned(), Value::String(path.to_owned()));
        content_entry.insert("chunks".to_owned(), Value::Array(chunk_values));
        content.push(Value::Object(content_entry));
    }
    if !paths.contains(entrypoint) {
        return Err(err("E050_CONTENT: entrypoint is not declared"));
    }
    let mut manifest = Map::new();
    manifest.insert(
        "entrypoint".to_owned(),
        Value::String(entrypoint.to_owned()),
    );
    manifest.insert("files".to_owned(), Value::Array(metadata));
    let manifest_bytes = serde_json::to_vec(&Value::Object(manifest))
        .map_err(|_| err("E050_CONTENT: manifest cannot be encoded"))?;
    let manifest_root = sha256_hex(&manifest_bytes);
    let mut content_object = Map::new();
    content_object.insert(
        "manifest_root".to_owned(),
        Value::String(manifest_root.clone()),
    );
    content_object.insert("chunks".to_owned(), Value::Array(content));
    let content_bytes = serde_json::to_vec(&Value::Object(content_object))
        .map_err(|_| err("E050_CONTENT: content root cannot be encoded"))?;
    let content_root = sha256_hex(&content_bytes);
    if content_string(object, "manifest_root")? != manifest_root
        || content_string(object, "content_root")? != content_root
    {
        return Err(err("E050_CONTENT: content root mismatch"));
    }
    let mut projection = Map::new();
    projection.insert(
        "artifact_sha256".to_owned(),
        Value::String(artifact_hash.to_owned()),
    );
    projection.insert("content_root".to_owned(), Value::String(content_root));
    projection.insert(
        "entrypoint".to_owned(),
        Value::String(entrypoint.to_owned()),
    );
    projection.insert("file_count".to_owned(), Value::from(files.len() as u64));
    projection.insert("manifest_root".to_owned(), Value::String(manifest_root));
    projection.insert("total_bytes".to_owned(), Value::from(total_bytes));
    serde_json::to_vec(&Value::Object(projection))
        .map_err(|_| err("E050_CONTENT: projection cannot be encoded"))
}

/// Canonical, bounded state codec for the proposed L1ContentProfileV1.
/// This function is deliberately pure: it validates the state envelope and
/// returns the domain-separated state commitment bytes. It does not sign,
/// query RPC, authorize an adapter, or broadcast a transaction.
pub fn encode_l1_content_state_050(raw_json: &[u8]) -> Result<Vec<u8>> {
    const FIELDS: &[&str] = &[
        "application_id",
        "artifact_root",
        "bond_sompi",
        "chunk_count",
        "content_root",
        "controller_commitment",
        "manifest_root",
        "nonce",
        "profile_id",
        "profile_version",
        "release_id",
        "resolver_policy_hash",
        "total_bytes",
    ];
    if raw_json.is_empty() || raw_json.len() > MAX_RECORD_BYTES {
        return Err(err("E050_CONTENT_STATE: state bytes are outside the bound"));
    }
    let parsed = parse_strict_json(raw_json)
        .map_err(|_| err("E050_CONTENT_STATE: state JSON is invalid"))?;
    let canonical = canonical_json_value(parsed)?;
    let canonical_bytes = serde_json::to_vec(&canonical)
        .map_err(|_| err("E050_CONTENT_STATE: state cannot be canonicalized"))?;
    if raw_json != canonical_bytes.as_slice() {
        return Err(err("E050_CONTENT_STATE: state JSON is not canonical"));
    }
    let object = canonical
        .as_object()
        .ok_or_else(|| err("E050_CONTENT_STATE: state must be an object"))?;
    if object.len() != FIELDS.len() || FIELDS.iter().any(|field| !object.contains_key(*field)) {
        return Err(err("E050_CONTENT_STATE: state fields are not exact"));
    }
    if object.get("profile_id").and_then(Value::as_str) != Some("L1ContentProfileV1")
        || object.get("profile_version").and_then(Value::as_u64) != Some(1)
    {
        return Err(err("E050_CONTENT_STATE: profile identity is invalid"));
    }
    let hash_fields = [
        "application_id",
        "artifact_root",
        "content_root",
        "controller_commitment",
        "manifest_root",
        "release_id",
        "resolver_policy_hash",
    ];
    let mut hashes = Vec::with_capacity(hash_fields.len());
    for field in hash_fields {
        let value = content_string(object, field)?;
        let decoded = decode_hex_bytes(value, field)?;
        if decoded.len() != 32 {
            return Err(err(&format!(
                "E050_CONTENT_STATE: {field} must be 32 bytes"
            )));
        }
        hashes.push(decoded);
    }
    let chunk_count = content_u64(object, "chunk_count")?;
    let total_bytes = content_u64(object, "total_bytes")?;
    let nonce = content_u64(object, "nonce")?;
    let bond_sompi = content_u64(object, "bond_sompi")?;
    if !(1..=62).contains(&chunk_count) || total_bytes > 256 * 1024 {
        return Err(err("E050_CONTENT_STATE: chunk or byte bounds exceeded"));
    }
    let mut preimage = b"KTAPEOUT/0.5.0/L1_CONTENT_STATE/V1".to_vec();
    preimage.push(0);
    for hash in hashes {
        preimage.extend_from_slice(&hash);
    }
    preimage.extend_from_slice(&chunk_count.to_be_bytes());
    preimage.extend_from_slice(&total_bytes.to_be_bytes());
    preimage.extend_from_slice(&nonce.to_be_bytes());
    preimage.extend_from_slice(&bond_sompi.to_be_bytes());
    Ok(Sha256::digest(preimage).to_vec())
}

/// Canonical commitment for one immutable ContentChunkV1 output.
pub fn encode_l1_content_chunk_050(raw_json: &[u8]) -> Result<Vec<u8>> {
    const FIELDS: &[&str] = &[
        "application_id",
        "artifact_root",
        "chunk_bytes",
        "chunk_count",
        "chunk_index",
        "chunk_sha256",
        "content_root",
        "profile_id",
        "profile_version",
        "release_id",
    ];
    if raw_json.is_empty() || raw_json.len() > MAX_RECORD_BYTES {
        return Err(err("E050_CONTENT_CHUNK: bytes are outside the bound"));
    }
    let parsed =
        parse_strict_json(raw_json).map_err(|_| err("E050_CONTENT_CHUNK: JSON is invalid"))?;
    let canonical = canonical_json_value(parsed)?;
    let canonical_bytes = serde_json::to_vec(&canonical)
        .map_err(|_| err("E050_CONTENT_CHUNK: JSON cannot be canonicalized"))?;
    if raw_json != canonical_bytes.as_slice() {
        return Err(err("E050_CONTENT_CHUNK: JSON is not canonical"));
    }
    let object = canonical
        .as_object()
        .ok_or_else(|| err("E050_CONTENT_CHUNK: value must be an object"))?;
    if object.len() != FIELDS.len() || FIELDS.iter().any(|field| !object.contains_key(*field)) {
        return Err(err("E050_CONTENT_CHUNK: fields are not exact"));
    }
    if object.get("profile_id").and_then(Value::as_str) != Some("ContentChunkV1")
        || object.get("profile_version").and_then(Value::as_u64) != Some(1)
    {
        return Err(err("E050_CONTENT_CHUNK: profile identity is invalid"));
    }
    let hash_fields = [
        "application_id",
        "artifact_root",
        "content_root",
        "release_id",
    ];
    let mut hashes = Vec::with_capacity(hash_fields.len());
    for field in hash_fields {
        let decoded = decode_hex_bytes(content_string(object, field)?, field)?;
        if decoded.len() != 32 {
            return Err(err(&format!(
                "E050_CONTENT_CHUNK: {field} must be 32 bytes"
            )));
        }
        hashes.push(decoded);
    }
    let chunk_index = content_u64(object, "chunk_index")?;
    let chunk_count = content_u64(object, "chunk_count")?;
    if chunk_count == 0 || chunk_count > 62 || chunk_index >= chunk_count {
        return Err(err("E050_CONTENT_CHUNK: index or count is out of bounds"));
    }
    let chunk_bytes = decode_hex_bytes(content_string(object, "chunk_bytes")?, "chunk_bytes")?;
    if chunk_bytes.is_empty() || chunk_bytes.len() > 96 * 1024 {
        return Err(err("E050_CONTENT_CHUNK: chunk size is out of bounds"));
    }
    let claimed = content_string(object, "chunk_sha256")?;
    if claimed != sha256_hex(&chunk_bytes) {
        return Err(err("E050_CONTENT_CHUNK: chunk_sha256 mismatch"));
    }
    let mut preimage = b"KTAPEOUT/0.5.0/CONTENT_CHUNK/V1".to_vec();
    preimage.push(0);
    for hash in hashes {
        preimage.extend_from_slice(&hash);
    }
    preimage.extend_from_slice(&chunk_index.to_be_bytes());
    preimage.extend_from_slice(&chunk_count.to_be_bytes());
    preimage.extend_from_slice(&Sha256::digest(&chunk_bytes));
    preimage.extend_from_slice(&(chunk_bytes.len() as u64).to_be_bytes());
    Ok(Sha256::digest(preimage).to_vec())
}

/// Execute only the bounded, local-only Life profile projection.  This is not
/// a VM and does not create a consensus or publication capability.
pub fn simulate_life_manifest_050(
    raw_json: &[u8],
    vector: &[u8],
    epoch: u64,
    occupied_cells: u64,
    steps: u32,
) -> Result<Vec<u8>> {
    if raw_json.is_empty() || raw_json.len() > MAX_RECORD_BYTES {
        return Err(err("E050_LIFE: manifest bytes are outside the bound"));
    }
    let parsed =
        parse_strict_json(raw_json).map_err(|_| err("E050_LIFE: manifest JSON is invalid"))?;
    let canonical = canonical_json_value(parsed)?;
    let canonical_bytes = serde_json::to_vec(&canonical)
        .map_err(|_| err("E050_LIFE: manifest cannot be canonicalized"))?;
    if raw_json != canonical_bytes.as_slice() {
        return Err(err("E050_LIFE: manifest JSON is not canonical"));
    }
    let object = canonical
        .as_object()
        .ok_or_else(|| err("E050_LIFE: manifest must be an object"))?;
    if object.get("schema").and_then(Value::as_u64) != Some(1)
        || content_string(object, "profile_id")? != "Life"
        || object.get("profile_version").and_then(Value::as_u64) != Some(1)
        || content_string(object, "admission")? != "local-only"
    {
        return Err(err("E050_LIFE: invalid manifest identity or admission"));
    }
    let components = object
        .get("components")
        .and_then(Value::as_array)
        .ok_or_else(|| err("E050_LIFE: components must be an array"))?;
    let expected_components = ["NeuronTile", "CellFoodConservation", "Machine"];
    if components.len() != expected_components.len()
        || components
            .iter()
            .zip(expected_components)
            .any(|(actual, expected)| actual.as_str() != Some(expected))
    {
        return Err(err("E050_LIFE: component list is not canonical"));
    }
    let neurons = content_u64(object, "neurons")?;
    let cells = content_u64(object, "cells")?;
    let max_steps = content_u64(object, "steps")?;
    if !(1..=MAX_LIFE_NEURONS).contains(&neurons)
        || !(1..=MAX_LIFE_CELLS).contains(&cells)
        || !(1..=u64::from(MAX_LIFE_STEPS)).contains(&max_steps)
        || !["topology_hash_hex", "semantics_hash_hex"]
            .iter()
            .all(|field| {
                content_string(object, field)
                    .map(|value| {
                        value.len() == 64
                            && value.bytes().all(|byte| byte.is_ascii_hexdigit())
                            && value == value.to_ascii_lowercase()
                    })
                    .unwrap_or(false)
            })
    {
        return Err(err("E050_LIFE: manifest bounds or hashes are invalid"));
    }
    if vector.len() > MAX_LIFE_VECTOR
        || steps == 0
        || steps > MAX_LIFE_STEPS
        || u64::from(steps) > max_steps
    {
        return Err(err("E050_LIFE: vector or step bounds are invalid"));
    }
    if epoch > MAX_SAFE_JSON_INTEGER || occupied_cells > MAX_SAFE_JSON_INTEGER {
        return Err(err("E050_LIFE: state exceeds safe integer bounds"));
    }
    let activity = vector.iter().filter(|bit| **bit != 0).count() as u64;
    let next_epoch = epoch
        .checked_add(u64::from(steps))
        .ok_or_else(|| err("E050_LIFE: epoch overflow"))?;
    let active_neurons = neurons.min(activity.saturating_mul(u64::from(steps)));
    let next_occupied = cells.min(occupied_cells.saturating_add(activity));
    let mut output = Vec::with_capacity(24);
    output.extend_from_slice(&next_epoch.to_le_bytes());
    output.extend_from_slice(&active_neurons.to_le_bytes());
    output.extend_from_slice(&next_occupied.to_le_bytes());
    Ok(output)
}

/// Compute the same extension commitment as the Python validator for a JSON
/// document. Schema validation remains a Profile/tooling responsibility; this
/// function supplies the independent Rust/WASM hashing boundary.
pub fn extension_commitment_json(kind: &str, raw_json: &str) -> Result<[u8; 32]> {
    if kind.is_empty()
        || kind.len() > 64
        || !kind
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(err("E050X_ENCODING: extension kind is not canonical"));
    }
    if raw_json.is_empty() || raw_json.len() > 1024 * 1024 {
        return Err(err("E050X_ENCODING: extension JSON is outside the bound"));
    }
    let parsed = parse_strict_json(raw_json.as_bytes())
        .map_err(|_| err("E050X_ENCODING: extension JSON is invalid"))?;
    let canonical = canonical_json_value(parsed)?;
    let bytes = serde_json::to_vec(&canonical)
        .map_err(|_| err("E050X_ENCODING: extension JSON cannot be canonicalized"))?;
    let mut domain = b"KTAPEOUT/0.5.0/EXTENSIONS/V1/".to_vec();
    domain.extend_from_slice(kind.as_bytes());
    Ok(commitment(&domain, &bytes))
}

const MAX_BOOLEAN_GATES: usize = 1_000;
const MAX_BOOLEAN_SIGNALS: usize = MAX_BOOLEAN_GATES + 64;
const MAX_STATE_STEPS: u32 = 10_000;
const MAX_NEURON_MEMBRANE: i64 = 1_000_000_000;
const MAX_CELL_VALUE: u64 = 9_007_199_254_740_991;

fn read_boolean_varint(raw: &[u8], cursor: &mut usize, field: &str) -> Result<usize> {
    let mut value = 0usize;
    let mut shift = 0u32;
    for _ in 0..5 {
        let byte = *raw
            .get(*cursor)
            .ok_or_else(|| err(&format!("E050_BOOLEAN: {field} varint is truncated")))?;
        *cursor += 1;
        let part = usize::from(byte & 0x7f);
        if shift >= usize::BITS || (part << shift) >> shift != part {
            return Err(err(&format!("E050_BOOLEAN: {field} varint overflows")));
        }
        value |= part << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
    }
    Err(err(&format!("E050_BOOLEAN: {field} varint is too long")))
}

/// Execute the bounded canonical KTB1 Boolean artifact used by the Studio
/// BooleanNetlistV1 Profile.  This is a local deterministic execution helper;
/// it is not a covenant, signer, broadcaster or L1 evidence source.
pub fn simulate_boolean_artifact_050(artifact: &[u8], inputs: &[u8]) -> Result<Vec<u8>> {
    if artifact.len() > MAX_RECORD_BYTES || artifact.len() < 9 {
        return Err(err("E050_BOOLEAN: artifact bytes are outside the bound"));
    }
    if &artifact[..4] != b"KTB1" || artifact[4] != 1 || artifact[5] != 0 {
        return Err(err(
            "E050_BOOLEAN: artifact header is not canonical KTB1 v1",
        ));
    }
    let mut cursor = 6usize;
    let input_count = read_boolean_varint(artifact, &mut cursor, "input count")?;
    let gate_count = read_boolean_varint(artifact, &mut cursor, "gate count")?;
    let output_count = read_boolean_varint(artifact, &mut cursor, "output count")?;
    let reserved = *artifact
        .get(cursor)
        .ok_or_else(|| err("E050_BOOLEAN: artifact flags are truncated"))?;
    cursor += 1;
    if reserved != 0 {
        return Err(err("E050_BOOLEAN: reserved flags are non-zero"));
    }
    if input_count == 0
        || input_count > 64
        || gate_count == 0
        || gate_count > MAX_BOOLEAN_GATES
        || output_count == 0
        || output_count > 64
    {
        return Err(err(
            "E050_BOOLEAN: artifact dimensions are outside the bound",
        ));
    }
    if input_count + gate_count > MAX_BOOLEAN_SIGNALS || inputs.len() != input_count {
        return Err(err("E050_BOOLEAN: input vector length is invalid"));
    }
    if inputs.iter().any(|value| *value > 1) {
        return Err(err("E050_BOOLEAN: input vector contains a non-bit"));
    }
    let mut signals = inputs.to_vec();
    for gate_index in 0..gate_count {
        let opcode = *artifact
            .get(cursor)
            .ok_or_else(|| err("E050_BOOLEAN: gate opcode is truncated"))?;
        cursor += 1;
        if opcode != 0 {
            return Err(err("E050_BOOLEAN: unsupported gate opcode"));
        }
        let left = read_boolean_varint(artifact, &mut cursor, "gate left")?;
        let right = read_boolean_varint(artifact, &mut cursor, "gate right")?;
        let signal_limit = input_count + gate_index;
        if left >= signal_limit || right >= signal_limit {
            return Err(err(
                "E050_BOOLEAN: gate reference is not topologically earlier",
            ));
        }
        signals.push(u8::from(!(signals[left] == 1 && signals[right] == 1)));
    }
    let mut outputs = Vec::with_capacity(output_count);
    for _ in 0..output_count {
        let signal = read_boolean_varint(artifact, &mut cursor, "output signal")?;
        if signal >= signals.len() {
            return Err(err("E050_BOOLEAN: output reference is out of range"));
        }
        outputs.push(signals[signal]);
    }
    if cursor != artifact.len() {
        return Err(err(
            "E050_BOOLEAN: trailing artifact bytes are not canonical",
        ));
    }
    Ok(outputs)
}

/// Execute the bounded canonical KTB1 state-machine artifact. The returned
/// bytes are `[output_count, outputs..., register_count, state...]`, with all
/// values represented as one canonical bit byte. Register state is ordered by
/// the artifact's canonical slot order.
pub fn simulate_state_machine_artifact_050(
    artifact: &[u8],
    inputs: &[u8],
    initial_state: &[u8],
    steps: u32,
) -> Result<Vec<u8>> {
    if artifact.len() > MAX_RECORD_BYTES || artifact.len() < 10 {
        return Err(err("E050_STATE: artifact bytes are outside the bound"));
    }
    if &artifact[..4] != b"KTB1" || artifact[4] != 1 || artifact[5] != 0 {
        return Err(err("E050_STATE: artifact header is not canonical KTB1 v1"));
    }
    if !(1..=MAX_STATE_STEPS).contains(&steps) {
        return Err(err("E050_STATE: step count is outside the bound"));
    }
    let mut cursor = 6usize;
    let input_count = read_boolean_varint(artifact, &mut cursor, "input count")?;
    let operation_count = read_boolean_varint(artifact, &mut cursor, "operation count")?;
    let output_count = read_boolean_varint(artifact, &mut cursor, "output count")?;
    let register_count = read_boolean_varint(artifact, &mut cursor, "register count")?;
    if input_count == 0
        || input_count > 64
        || operation_count == 0
        || operation_count > 256
        || output_count == 0
        || output_count > 64
        || register_count == 0
        || register_count > 64
        || inputs.len() != input_count
        || initial_state.len() != register_count
    {
        return Err(err(
            "E050_STATE: artifact dimensions or vectors are invalid",
        ));
    }
    if inputs.iter().chain(initial_state).any(|value| *value > 1) {
        return Err(err("E050_STATE: input or state vector contains a non-bit"));
    }
    let mut opcodes = Vec::with_capacity(operation_count);
    let mut gate_refs = Vec::with_capacity(operation_count);
    let mut register_op_indices = Vec::new();
    for operation_index in 0..operation_count {
        let opcode = *artifact
            .get(cursor)
            .ok_or_else(|| err("E050_STATE: operation opcode is truncated"))?;
        cursor += 1;
        match opcode {
            0 => {
                let left = read_boolean_varint(artifact, &mut cursor, "gate left")?;
                let right = read_boolean_varint(artifact, &mut cursor, "gate right")?;
                let signal_limit = input_count + operation_index;
                if left >= signal_limit || right >= signal_limit {
                    return Err(err(
                        "E050_STATE: NAND reference is not topologically earlier",
                    ));
                }
                gate_refs.push(Some((left, right)));
            }
            1 => {
                register_op_indices.push(operation_index);
                gate_refs.push(None);
            }
            _ => return Err(err("E050_STATE: unsupported operation opcode")),
        }
        opcodes.push(opcode);
    }
    if register_op_indices.len() != register_count {
        return Err(err("E050_STATE: register count does not match operations"));
    }
    let mut output_refs = Vec::with_capacity(output_count);
    for _ in 0..output_count {
        let signal = read_boolean_varint(artifact, &mut cursor, "output signal")?;
        if signal >= input_count + operation_count {
            return Err(err("E050_STATE: output reference is out of range"));
        }
        output_refs.push(signal);
    }
    let mut mappings = Vec::with_capacity(register_count);
    for _ in 0..register_count {
        let register_signal = read_boolean_varint(artifact, &mut cursor, "register signal")?;
        let source = read_boolean_varint(artifact, &mut cursor, "register source")?;
        if register_signal < input_count
            || register_signal >= input_count + operation_count
            || opcodes[register_signal - input_count] != 1
            || source >= input_count + operation_count
        {
            return Err(err("E050_STATE: register mapping is invalid"));
        }
        mappings.push((register_signal, source));
    }
    let mut state_index_by_signal = vec![None; operation_count];
    for (state_index, (register_signal, _)) in mappings.iter().enumerate() {
        let operation_index = register_signal - input_count;
        if state_index_by_signal[operation_index]
            .replace(state_index)
            .is_some()
        {
            return Err(err("E050_STATE: duplicate register signal mapping"));
        }
    }
    if cursor != artifact.len() {
        return Err(err("E050_STATE: trailing artifact bytes are not canonical"));
    }
    let mut state = initial_state.to_vec();
    let mut final_outputs = vec![0u8; output_count];
    for _ in 0..steps {
        let mut signals = vec![0u8; input_count + operation_count];
        signals[..input_count].copy_from_slice(inputs);
        for operation_index in &register_op_indices {
            let state_index = state_index_by_signal[*operation_index]
                .ok_or_else(|| err("E050_STATE: register operation has no mapping"))?;
            signals[input_count + *operation_index] = state[state_index];
        }
        for operation_index in 0..operation_count {
            if let Some((left, right)) = gate_refs[operation_index] {
                signals[input_count + operation_index] =
                    u8::from(!(signals[left] == 1 && signals[right] == 1));
            }
        }
        for (index, signal) in output_refs.iter().enumerate() {
            final_outputs[index] = signals[*signal];
        }
        let next_state = mappings
            .iter()
            .map(|(_, source)| signals[*source])
            .collect::<Vec<_>>();
        state = next_state;
    }
    let mut result = Vec::with_capacity(2 + output_count + register_count);
    result.push(output_count as u8);
    result.extend_from_slice(&final_outputs);
    result.push(register_count as u8);
    result.extend_from_slice(&state);
    Ok(result)
}

/// Execute the canonical NeuronTile manifest. The returned bytes are
/// `[neuron_count, spikes..., membrane_count, membrane_i32_le...]`.
pub fn simulate_neuron_tile_manifest_050(
    raw_json: &[u8],
    inputs: &[i32],
    initial_membrane: &[i32],
    steps: u32,
) -> Result<Vec<u8>> {
    if raw_json.is_empty() || raw_json.len() > MAX_RECORD_BYTES {
        return Err(err("E050_NEURON: manifest bytes are outside the bound"));
    }
    if !(1..=MAX_STATE_STEPS).contains(&steps) {
        return Err(err("E050_NEURON: step count is outside the bound"));
    }
    let parsed =
        parse_strict_json(raw_json).map_err(|_| err("E050_NEURON: manifest JSON is invalid"))?;
    let canonical = canonical_json_value(parsed)?;
    let canonical_bytes = serde_json::to_vec(&canonical)
        .map_err(|_| err("E050_NEURON: manifest cannot be canonicalized"))?;
    if canonical_bytes != raw_json {
        return Err(err("E050_NEURON: manifest JSON is not canonical"));
    }
    let object = canonical
        .as_object()
        .ok_or_else(|| err("E050_NEURON: manifest must be an object"))?;
    let expected = [
        "inputs",
        "kind",
        "leak",
        "neurons",
        "nonce",
        "owner_hex",
        "profile_id",
        "profile_version",
        "schema",
        "semantics_hash_hex",
        "threshold",
    ];
    let mut keys = object.keys().map(String::as_str).collect::<Vec<_>>();
    keys.sort_unstable();
    if keys != expected {
        return Err(err("E050_NEURON: manifest fields are not canonical"));
    }
    if object.get("schema").and_then(Value::as_u64) != Some(1)
        || object.get("profile_version").and_then(Value::as_u64) != Some(1)
        || object.get("kind").and_then(Value::as_str) != Some("spike")
        || object.get("profile_id").and_then(Value::as_str) != Some("NeuronTile")
    {
        return Err(err("E050_NEURON: manifest identity is invalid"));
    }
    let neurons_raw = object
        .get("neurons")
        .and_then(Value::as_u64)
        .ok_or_else(|| err("E050_NEURON: neurons is invalid"))?;
    let input_count_raw = object
        .get("inputs")
        .and_then(Value::as_u64)
        .ok_or_else(|| err("E050_NEURON: inputs is invalid"))?;
    let threshold = object
        .get("threshold")
        .and_then(Value::as_i64)
        .ok_or_else(|| err("E050_NEURON: threshold is invalid"))?;
    let leak = object
        .get("leak")
        .and_then(Value::as_i64)
        .ok_or_else(|| err("E050_NEURON: leak is invalid"))?;
    let nonce = object
        .get("nonce")
        .and_then(Value::as_u64)
        .ok_or_else(|| err("E050_NEURON: nonce is invalid"))?;
    if !(1..=4).contains(&neurons_raw)
        || !(1..=4).contains(&input_count_raw)
        || threshold > 4096
        || leak > 4096
        || nonce > 4096
        || threshold < 0
        || leak < 0
        || !matches!(object.get("owner_hex").and_then(Value::as_str), Some(value) if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()))
        || !matches!(object.get("semantics_hash_hex").and_then(Value::as_str), Some(value) if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()))
        || inputs.len() != input_count_raw as usize
        || initial_membrane.len() != neurons_raw as usize
    {
        return Err(err("E050_NEURON: manifest shape is outside the bound"));
    }
    let neurons = neurons_raw as usize;
    if inputs
        .iter()
        .any(|value| i64::from(*value).abs() > MAX_NEURON_MEMBRANE)
        || initial_membrane
            .iter()
            .any(|value| i64::from(*value).abs() > MAX_NEURON_MEMBRANE)
    {
        return Err(err("E050_NEURON: input or membrane is outside the bound"));
    }
    let mut membrane = initial_membrane
        .iter()
        .map(|value| i64::from(*value))
        .collect::<Vec<_>>();
    let mut spikes = vec![0i32; neurons];
    for _ in 0..steps {
        for neuron in 0..neurons {
            let mut potential = membrane[neuron] - leak;
            for input in inputs {
                potential += i64::from(*input);
            }
            if potential >= threshold {
                membrane[neuron] = 0;
                spikes[neuron] = 1;
            } else {
                if potential.abs() > MAX_NEURON_MEMBRANE {
                    return Err(err("E050_NEURON: membrane exceeds the bound"));
                }
                membrane[neuron] = potential;
                spikes[neuron] = 0;
            }
        }
    }
    let mut result = Vec::with_capacity(2 + neurons * 5);
    result.push(neurons as u8);
    result.extend(spikes.iter().map(|value| *value as u8));
    result.push(neurons as u8);
    for value in membrane {
        result.extend_from_slice(&(value as i32).to_le_bytes());
    }
    Ok(result)
}

/// Execute the canonical Cell/Food conservation primitive. The returned bytes
/// are three little-endian u64 values: capacity, biomass and substrate.
pub fn simulate_cell_food_manifest_050(
    manifest_json: &[u8],
    state_json: &[u8],
    event_json: &[u8],
) -> Result<Vec<u8>> {
    fn canonical_object(raw: &[u8], field: &str) -> Result<Map<String, Value>> {
        if raw.is_empty() || raw.len() > MAX_RECORD_BYTES {
            return Err(err(&format!(
                "E050_CELL: {field} bytes are outside the bound"
            )));
        }
        let parsed = parse_strict_json(raw)
            .map_err(|_| err(&format!("E050_CELL: {field} JSON is invalid")))?;
        let canonical = canonical_json_value(parsed)?;
        let bytes = serde_json::to_vec(&canonical)
            .map_err(|_| err(&format!("E050_CELL: {field} cannot be canonicalized")))?;
        if bytes != raw {
            return Err(err(&format!("E050_CELL: {field} JSON is not canonical")));
        }
        canonical
            .as_object()
            .cloned()
            .ok_or_else(|| err(&format!("E050_CELL: {field} must be an object")))
    }
    let manifest = canonical_object(manifest_json, "manifest")?;
    let manifest_keys = manifest.keys().map(String::as_str).collect::<Vec<_>>();
    if manifest_keys
        != [
            "balance",
            "kind",
            "nonce",
            "owner_hex",
            "profile_id",
            "profile_version",
            "schema",
            "semantics_hash_hex",
        ]
        || manifest.get("schema").and_then(Value::as_u64) != Some(1)
        || manifest.get("profile_version").and_then(Value::as_u64) != Some(1)
        || manifest.get("kind").and_then(Value::as_str) != Some("food")
        || manifest.get("profile_id").and_then(Value::as_str) != Some("CellFoodConservation")
        || manifest.get("balance").and_then(Value::as_u64).is_none()
        || manifest.get("nonce").and_then(Value::as_u64).is_none()
        || !matches!(manifest.get("owner_hex").and_then(Value::as_str), Some(value) if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()))
        || !matches!(manifest.get("semantics_hash_hex").and_then(Value::as_str), Some(value) if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()))
    {
        return Err(err("E050_CELL: manifest identity or fields are invalid"));
    }
    let state = canonical_object(state_json, "state")?;
    if state.keys().map(String::as_str).collect::<Vec<_>>() != ["biomass", "capacity", "substrate"]
    {
        return Err(err("E050_CELL: state fields are not canonical"));
    }
    let capacity = state
        .get("capacity")
        .and_then(Value::as_u64)
        .ok_or_else(|| err("E050_CELL: capacity is invalid"))?;
    let biomass = state
        .get("biomass")
        .and_then(Value::as_u64)
        .ok_or_else(|| err("E050_CELL: biomass is invalid"))?;
    let substrate = state
        .get("substrate")
        .and_then(Value::as_u64)
        .ok_or_else(|| err("E050_CELL: substrate is invalid"))?;
    if capacity > MAX_CELL_VALUE
        || biomass > MAX_CELL_VALUE
        || substrate > MAX_CELL_VALUE
        || biomass > capacity
    {
        return Err(err("E050_CELL: state is outside the conservation bound"));
    }
    let event = canonical_object(event_json, "event")?;
    let (next_biomass, next_substrate) = match event.get("op").and_then(Value::as_str) {
        Some("consume")
            if event.keys().map(String::as_str).collect::<Vec<_>>() == ["op", "quantity"] =>
        {
            let quantity = event
                .get("quantity")
                .and_then(Value::as_u64)
                .ok_or_else(|| err("E050_CELL: quantity is invalid"))?;
            if quantity > biomass {
                return Err(err("E050_CELL: consumption exceeds biomass"));
            }
            (biomass - quantity, substrate)
        }
        Some("advance")
            if event.keys().map(String::as_str).collect::<Vec<_>>()
                == ["growth_rate_ppm", "op", "substrate_factor_ppm"] =>
        {
            let rate = event
                .get("growth_rate_ppm")
                .and_then(Value::as_u64)
                .ok_or_else(|| err("E050_CELL: growth rate is invalid"))?;
            let factor = event
                .get("substrate_factor_ppm")
                .and_then(Value::as_u64)
                .ok_or_else(|| err("E050_CELL: substrate factor is invalid"))?;
            if rate > 1_000_000 || factor > 1_000_000 {
                return Err(err("E050_CELL: growth parameters are out of bounds"));
            }
            let raw_growth =
                (biomass as u128 * rate as u128 * factor as u128) / 1_000_000_000_000u128;
            let growth = raw_growth
                .min((capacity - biomass) as u128)
                .min(substrate as u128) as u64;
            (biomass + growth, substrate - growth)
        }
        _ => return Err(err("E050_CELL: unknown or non-canonical event")),
    };
    let mut result = Vec::with_capacity(24);
    result.extend_from_slice(&capacity.to_le_bytes());
    result.extend_from_slice(&next_biomass.to_le_bytes());
    result.extend_from_slice(&next_substrate.to_le_bytes());
    Ok(result)
}

/// A checked projection of a fixed, already-declared allocation.
///
/// This is arithmetic only: it does not choose recipients, authorize a
/// transition, or imply that a Profile can settle the result on L1.  Profiles
/// and applications remain responsible for binding identities, ordering,
/// predecessor state and duplicate-claim rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedAllocationSummary {
    pub principal_sompi: u64,
    pub fee_sompi: u64,
    pub change_sompi: u64,
}

/// Check integer conservation for a bounded fixed allocation.
///
/// Every allocation amount must be positive and the number of entries is
/// bounded by the Core batch limit.  Fees are kept separate from principal;
/// any remainder is explicit change.  No floating point or implicit rounding
/// is involved.
pub fn reconcile_fixed_allocation(
    funding_sompi: u64,
    allocation_sompi: &[u64],
    fee_sompi: u64,
) -> Result<FixedAllocationSummary> {
    if allocation_sompi.is_empty() || allocation_sompi.len() > MAX_BATCH {
        return Err(err("E050_ALLOCATION: entry count is outside the bound"));
    }
    let mut principal_sompi = 0u64;
    for amount in allocation_sompi {
        if *amount == 0 {
            return Err(err("E050_ALLOCATION: amount must be positive"));
        }
        principal_sompi = principal_sompi
            .checked_add(*amount)
            .ok_or_else(|| err("E050_ALLOCATION: principal overflow"))?;
    }
    let required_sompi = principal_sompi
        .checked_add(fee_sompi)
        .ok_or_else(|| err("E050_ALLOCATION: funding requirement overflow"))?;
    let change_sompi = funding_sompi
        .checked_sub(required_sompi)
        .ok_or_else(|| err("E050_ALLOCATION: insufficient funding"))?;
    Ok(FixedAllocationSummary {
        principal_sompi,
        fee_sompi,
        change_sompi,
    })
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn simulate_boolean_artifact(
    artifact: &[u8],
    inputs: &[u8],
) -> std::result::Result<Vec<u8>, JsValue> {
    simulate_boolean_artifact_050(artifact, inputs).map_err(|error| JsValue::from_str(&error.0))
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn simulate_state_machine_artifact(
    artifact: &[u8],
    inputs: &[u8],
    initial_state: &[u8],
    steps: u32,
) -> std::result::Result<Vec<u8>, JsValue> {
    simulate_state_machine_artifact_050(artifact, inputs, initial_state, steps)
        .map_err(|error| JsValue::from_str(&error.0))
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn simulate_neuron_tile_manifest(
    raw_json: &[u8],
    inputs: &[i32],
    initial_membrane: &[i32],
    steps: u32,
) -> std::result::Result<Vec<u8>, JsValue> {
    simulate_neuron_tile_manifest_050(raw_json, inputs, initial_membrane, steps)
        .map_err(|error| JsValue::from_str(&error.0))
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn simulate_cell_food_manifest(
    manifest_json: &[u8],
    state_json: &[u8],
    event_json: &[u8],
) -> std::result::Result<Vec<u8>, JsValue> {
    simulate_cell_food_manifest_050(manifest_json, state_json, event_json)
        .map_err(|error| JsValue::from_str(&error.0))
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn verify_content_artifact(raw_json: &[u8]) -> std::result::Result<Vec<u8>, JsValue> {
    verify_content_artifact_050(raw_json).map_err(|error| JsValue::from_str(&error.0))
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn simulate_life_manifest(
    raw_json: &[u8],
    vector: &[u8],
    epoch: u64,
    occupied_cells: u64,
    steps: u32,
) -> std::result::Result<Vec<u8>, JsValue> {
    simulate_life_manifest_050(raw_json, vector, epoch, occupied_cells, steps)
        .map_err(|error| JsValue::from_str(&error.0))
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn verify_extension_commitment(
    kind: String,
    raw_json: String,
) -> std::result::Result<Vec<u8>, JsValue> {
    extension_commitment_json(&kind, &raw_json)
        .map(|value| value.to_vec())
        .map_err(|error| JsValue::from_str(&error.0))
}

#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn guard_external_signing_json(raw_json: &[u8]) -> std::result::Result<Vec<u8>, JsValue> {
    let summary =
        guard_external_signing_json_050(raw_json).map_err(|error| JsValue::from_str(&error.0))?;
    serde_json::to_vec(&serde_json::json!({
        "schema": "KTAPEOUT-EXTERNAL-SIGNING-JSON-GUARD-V1",
        "input_guard_only": true,
        "transaction_valid": false,
        "signing_allowed": false,
        "byte_length": summary.byte_length,
        "node_count": summary.node_count,
        "max_depth": summary.max_depth,
    }))
    .map_err(|_| JsValue::from_str("E050_TXJSON_SUMMARY_ENCODING"))
}

/// The transaction-visible successor binding used by the v0.5.0 lowering
/// boundary.  `output_bytes` must already be the canonical NetworkPolicy
/// transaction-output encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuccessorBinding {
    pub output_bytes: Vec<u8>,
    pub lineage_hash: [u8; 32],
    pub state_root: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkBoundPlan<'a> {
    pub network_id: &'a [u8],
    pub policy_id: &'a [u8; 32],
    pub deployment_id: &'a [u8; 32],
    pub layout_commitment: &'a [u8; 32],
    pub action_commitment: &'a [u8; 32],
    pub input_outpoints: &'a [([u8; 32], u32)],
    pub successors: &'a [SuccessorBinding],
    pub capability_commitments: &'a [[u8; 32]],
    pub resource_bill_commitment: &'a [u8; 32],
}

fn bounded_count(count: usize, field: &str) -> Result<()> {
    if !(1..=MAX_BATCH).contains(&count) {
        return Err(err(&format!(
            "E050_SELECTOR: {field} count is outside the bounded envelope"
        )));
    }
    Ok(())
}

/// Commit exact ordered `(txid, output_index)` pairs.
pub fn input_outpoint_root_050(outpoints: &[([u8; 32], u32)]) -> Result<[u8; 32]> {
    bounded_count(outpoints.len(), "input_outpoint")?;
    let mut bytes = Vec::with_capacity(2 + outpoints.len() * 36);
    bytes.extend_from_slice(&(outpoints.len() as u16).to_le_bytes());
    for (position, (txid, output_index)) in outpoints.iter().enumerate() {
        if outpoints[..position]
            .iter()
            .any(|(seen_txid, seen_index)| seen_txid == txid && seen_index == output_index)
        {
            return Err(err("E050_SELECTOR: duplicate input outpoint"));
        }
        bytes.extend_from_slice(txid);
        bytes.extend_from_slice(&output_index.to_le_bytes());
    }
    Ok(commitment(b"KTAPEOUT/0.5.0/INPUT_OUTPOINT_ROOT/V1", &bytes))
}

/// Commit exact ordered successor output bytes and their state bindings.
pub fn successor_root_050(successors: &[SuccessorBinding]) -> Result<[u8; 32]> {
    bounded_count(successors.len(), "successor_output")?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(successors.len() as u16).to_le_bytes());
    for successor in successors {
        if successor.output_bytes.is_empty() || successor.output_bytes.len() > 262_144 {
            return Err(err(
                "E050_ENCODING: successor output bytes are outside the bound",
            ));
        }
        bytes.extend_from_slice(&(successor.output_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&successor.output_bytes);
        bytes.extend_from_slice(&successor.lineage_hash);
        bytes.extend_from_slice(&successor.state_root);
    }
    Ok(commitment(b"KTAPEOUT/0.5.0/SUCCESSOR_ROOT/V1", &bytes))
}

/// Commit the exact ordered capability commitment list.
pub fn capability_set_root_050(capabilities: &[[u8; 32]]) -> Result<[u8; 32]> {
    bounded_count(capabilities.len(), "capability")?;
    let mut bytes = Vec::with_capacity(2 + capabilities.len() * 32);
    bytes.extend_from_slice(&(capabilities.len() as u16).to_le_bytes());
    for capability in capabilities {
        bytes.extend_from_slice(capability);
    }
    Ok(commitment(b"KTAPEOUT/0.5.0/CAPABILITY_SET_ROOT/V1", &bytes))
}

/// Hash the exact signer-bound v0.5.0 plan fields. This is still an unsigned
/// plan digest; transaction serialization and key authorization remain outside
/// the Core crate.
pub fn network_bound_plan_digest_050(plan: &NetworkBoundPlan<'_>) -> Result<[u8; 32]> {
    if plan.network_id.is_empty()
        || plan.network_id.len() > 64
        || !plan.network_id.iter().enumerate().all(|(i, byte)| {
            (i == 0 && byte.is_ascii_lowercase() && byte.is_ascii_alphanumeric())
                || (i > 0
                    && (byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'.' | b'_' | b'-')))
        })
    {
        return Err(err("E050_ENCODING: network_id is not canonical ASCII"));
    }
    bounded_count(plan.input_outpoints.len(), "input_outpoint")?;
    bounded_count(plan.successors.len(), "successor_output")?;
    if plan.capability_commitments.is_empty() || plan.capability_commitments.len() > MAX_BATCH {
        return Err(err(
            "E050_BINDING: capability count is outside the bounded envelope",
        ));
    }
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(plan.network_id.len() as u16).to_le_bytes());
    bytes.extend_from_slice(plan.network_id);
    bytes.extend_from_slice(plan.policy_id);
    bytes.extend_from_slice(plan.deployment_id);
    bytes.extend_from_slice(plan.layout_commitment);
    bytes.extend_from_slice(plan.action_commitment);
    bytes.extend_from_slice(&(plan.input_outpoints.len() as u16).to_le_bytes());
    for (position, (txid, index)) in plan.input_outpoints.iter().enumerate() {
        if plan.input_outpoints[..position]
            .iter()
            .any(|(seen_txid, seen_index)| seen_txid == txid && seen_index == index)
        {
            return Err(err("E050_SELECTOR: duplicate input outpoint"));
        }
        bytes.extend_from_slice(txid);
        bytes.extend_from_slice(&index.to_le_bytes());
    }
    bytes.extend_from_slice(&(plan.successors.len() as u16).to_le_bytes());
    for successor in plan.successors {
        if successor.output_bytes.is_empty() || successor.output_bytes.len() > MAX_RECORD_BYTES {
            return Err(err(
                "E050_ENCODING: successor output bytes are outside the bound",
            ));
        }
        bytes.extend_from_slice(&(successor.output_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&successor.output_bytes);
        bytes.extend_from_slice(&successor.lineage_hash);
        bytes.extend_from_slice(&successor.state_root);
    }
    bytes.extend_from_slice(&(plan.capability_commitments.len() as u16).to_le_bytes());
    for commitment in plan.capability_commitments {
        bytes.extend_from_slice(commitment);
    }
    bytes.extend_from_slice(plan.resource_bill_commitment);
    Ok(commitment(b"KTAPEOUT/0.5.0/NETWORK_BOUND_PLAN/V1", &bytes))
}

/// Verify a decoded action against the exact facts supplied to the lowerer.
/// The transaction/covenant layer must repeat these checks from its own view.
pub fn verify_action_fact_bindings_050(
    action: &PartitionAction,
    layout_commitment: &[u8; 32],
    inputs: &[([u8; 32], u32)],
    successors: &[SuccessorBinding],
    capabilities: &[[u8; 32]],
    policy_id: &[u8; 32],
    resource_bill_commitment: &[u8; 32],
) -> Result<()> {
    if action.layout_hash != *layout_commitment {
        return Err(err(
            "E050_BINDING: action layout_hash does not bind layout commitment",
        ));
    }
    if action.input_outpoint_root != input_outpoint_root_050(inputs)? {
        return Err(err(
            "E050_BINDING: action input_outpoint_root does not bind ordered inputs",
        ));
    }
    if action.successor_root != successor_root_050(successors)? {
        return Err(err(
            "E050_BINDING: action successor_root does not bind ordered successors",
        ));
    }
    if action.capability_hash != capability_set_root_050(capabilities)? {
        return Err(err(
            "E050_BINDING: action capability_hash does not bind capability list",
        ));
    }
    if action.policy_hash != *policy_id {
        return Err(err(
            "E050_BINDING: action policy_hash does not bind policy_id",
        ));
    }
    if action.resource_bill_hash != *resource_bill_commitment {
        return Err(err(
            "E050_BINDING: action resource_bill_hash does not bind resource bill",
        ));
    }
    Ok(())
}

/// Verify action sequencing against the live predecessor context. A deployed
/// covenant must repeat this check from its own state rather than trust an
/// off-chain receipt.
pub fn verify_action_context_050(
    action: &PartitionAction,
    expected_epoch: u64,
    expected_action_nonce: u64,
    previous_state_root: &[u8; 32],
    genesis: bool,
) -> Result<()> {
    encode_partition_action(action)?;
    if action.epoch != expected_epoch {
        return Err(err("E050_REPLAY: action epoch does not match live context"));
    }
    if action.action_nonce != expected_action_nonce {
        return Err(err("E050_REPLAY: action nonce is stale or replayed"));
    }
    if genesis {
        if expected_epoch != 0 || action.previous_state_root != ZERO32 {
            return Err(err("E050_REPLAY: genesis context is invalid"));
        }
    } else if *previous_state_root == ZERO32 || action.previous_state_root != *previous_state_root {
        return Err(err(
            "E050_REPLAY: action previous state root is stale or mismatched",
        ));
    }
    Ok(())
}

pub fn partition_layout_commitment(v: &PartitionLayout) -> Result<[u8; 32]> {
    Ok(commitment(
        b"KTAPEOUT/0.5.0/PARTITION_LAYOUT/V1",
        &encode_partition_layout(v)?,
    ))
}
pub fn partition_action_commitment(v: &PartitionAction) -> Result<[u8; 32]> {
    Ok(commitment(
        b"KTAPEOUT/0.5.0/PARTITION_ACTION/V1",
        &encode_partition_action(v)?,
    ))
}
pub fn collective_seal_commitment(v: &CollectiveSeal) -> Result<[u8; 32]> {
    Ok(commitment(
        b"KTAPEOUT/0.5.0/COLLECTIVE_SEAL/V1",
        &encode_collective_seal(v)?,
    ))
}

/// Minimal browser boundary: validate canonical bytes and return the
/// network-independent Core commitment. Kind ordinals are deliberately fixed
/// here and are not inferred from user-controlled labels:
/// 0 = partition_layout, 1 = partition_action, 2 = collective_seal.
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn verify_core_record_and_commit(
    kind: u8,
    raw: &[u8],
) -> std::result::Result<Vec<u8>, JsValue> {
    let digest = match kind {
        0 => decode_partition_layout(raw).and_then(|v| partition_layout_commitment(&v)),
        1 => decode_partition_action(raw).and_then(|v| partition_action_commitment(&v)),
        2 => decode_collective_seal(raw).and_then(|v| collective_seal_commitment(&v)),
        _ => return Err(JsValue::from_str("E050_DOMAIN: unknown record kind")),
    };
    digest
        .map(|value| value.to_vec())
        .map_err(|e| JsValue::from_str(&e.0))
}

/// Candidate byte fields for one immutable encrypted application object.
///
/// This codec defines transport bytes only. It does not verify AEAD,
/// commitments, transaction identity, chain inclusion, or Profile admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateObjectWireV1 {
    /// Stable lower-case Profile identifier encoded as ASCII.
    pub profile_id: String,
    /// Key epoch bound by the encrypted record.
    pub epoch: u32,
    /// Original plaintext byte length, before the 16-byte GCM tag.
    pub plaintext_length: u32,
    /// AES-GCM nonce.
    pub nonce: [u8; PRIVATE_OBJECT_WIRE_V1_NONCE_BYTES],
    /// Ciphertext followed by the 16-byte authentication tag.
    pub ciphertext: Vec<u8>,
    /// SHA-256 of the ciphertext bytes.
    pub ciphertext_digest: [u8; PRIVATE_OBJECT_WIRE_V1_HASH_BYTES],
    /// Object identifier commitment.
    pub object_id: [u8; PRIVATE_OBJECT_WIRE_V1_HASH_BYTES],
    /// Commitment to the full persisted record.
    pub record_commitment: [u8; PRIVATE_OBJECT_WIRE_V1_HASH_BYTES],
    /// Commitment to the exact decryption context.
    pub context_commitment: [u8; PRIVATE_OBJECT_WIRE_V1_HASH_BYTES],
}

fn validate_private_object_wire_v1(value: &PrivateObjectWireV1) -> Result<usize> {
    let profile = value.profile_id.as_bytes();
    if profile.is_empty()
        || profile.len() > 64
        || (!profile[0].is_ascii_lowercase() && !profile[0].is_ascii_digit())
        || profile[1..].iter().any(|byte| {
            !byte.is_ascii_lowercase()
                && !byte.is_ascii_digit()
                && !matches!(*byte, b'.' | b'_' | b'/' | b'-')
        })
    {
        return Err(err("E050_PRIVATE_OBJECT_PROFILE_INVALID"));
    }
    let plaintext_length = usize::try_from(value.plaintext_length)
        .map_err(|_| err("E050_PRIVATE_OBJECT_PLAINTEXT_LENGTH_INVALID"))?;
    if plaintext_length > PRIVATE_OBJECT_WIRE_V1_MAX_PLAINTEXT_BYTES
        || value.ciphertext.len() != plaintext_length + PRIVATE_OBJECT_WIRE_V1_TAG_BYTES
    {
        return Err(err("E050_PRIVATE_OBJECT_LENGTH_INVALID"));
    }
    let wire_length = PRIVATE_OBJECT_WIRE_V1_MAGIC.len()
        + 1
        + profile.len()
        + 4
        + 4
        + PRIVATE_OBJECT_WIRE_V1_NONCE_BYTES
        + 4
        + value.ciphertext.len()
        + 4 * PRIVATE_OBJECT_WIRE_V1_HASH_BYTES;
    if wire_length > PRIVATE_OBJECT_WIRE_V1_MAX_BYTES {
        return Err(err("E050_PRIVATE_OBJECT_WIRE_LIMIT"));
    }
    Ok(wire_length)
}

/// Encode the bounded `KTOBJ001` private-object candidate envelope.
///
/// Integers use big-endian byte order. The four final hashes are ordered as
/// ciphertext digest, object ID, record commitment, and context commitment.
/// The function validates lengths and identifier shape before allocating the
/// output buffer. It does not authenticate the hash values or ciphertext.
///
/// # Errors
///
/// Returns a stable `E050_PRIVATE_OBJECT_*` `CodecError` for an invalid
/// Profile identifier, length relation, or wire budget.
///
/// # Panics
///
/// The output allocation may panic if the process cannot reserve memory.
pub fn encode_private_object_wire_v1(value: &PrivateObjectWireV1) -> Result<Vec<u8>> {
    let wire_length = validate_private_object_wire_v1(value)?;
    let profile = value.profile_id.as_bytes();
    let mut output = Vec::with_capacity(wire_length);
    output.extend_from_slice(PRIVATE_OBJECT_WIRE_V1_MAGIC);
    output.push(profile.len() as u8);
    output.extend_from_slice(profile);
    output.extend_from_slice(&value.epoch.to_be_bytes());
    output.extend_from_slice(&value.plaintext_length.to_be_bytes());
    output.extend_from_slice(&value.nonce);
    output.extend_from_slice(&(value.ciphertext.len() as u32).to_be_bytes());
    output.extend_from_slice(&value.ciphertext);
    output.extend_from_slice(&value.ciphertext_digest);
    output.extend_from_slice(&value.object_id);
    output.extend_from_slice(&value.record_commitment);
    output.extend_from_slice(&value.context_commitment);
    debug_assert_eq!(output.len(), wire_length);
    Ok(output)
}

/// Decode one exact `KTOBJ001` envelope, rejecting truncation and trailing bytes.
///
/// This validates the syntactic envelope only. Callers must separately verify
/// the cryptographic commitments and decrypt within the bound application
/// context before treating the content as authentic.
///
/// # Errors
///
/// Returns a stable `E050_PRIVATE_OBJECT_*` `CodecError` for invalid magic,
/// lengths, Profile identifiers, truncation, trailing bytes, or wire budgets.
///
/// # Panics
///
/// The ciphertext copy may panic if the process cannot reserve memory.
pub fn decode_private_object_wire_v1(raw: &[u8]) -> Result<PrivateObjectWireV1> {
    const MIN_WIRE_BYTES: usize = 8 + 1 + 1 + 4 + 4 + 12 + 4 + 16 + 4 * 32;
    if raw.len() < MIN_WIRE_BYTES || raw.len() > PRIVATE_OBJECT_WIRE_V1_MAX_BYTES {
        return Err(err("E050_PRIVATE_OBJECT_WIRE_LENGTH_INVALID"));
    }
    if raw.get(..PRIVATE_OBJECT_WIRE_V1_MAGIC.len()) != Some(PRIVATE_OBJECT_WIRE_V1_MAGIC) {
        return Err(err("E050_PRIVATE_OBJECT_WIRE_MAGIC_INVALID"));
    }
    let mut offset = PRIVATE_OBJECT_WIRE_V1_MAGIC.len();
    let profile_length = usize::from(raw[offset]);
    offset += 1;
    let profile_end = offset
        .checked_add(profile_length)
        .ok_or_else(|| err("E050_PRIVATE_OBJECT_WIRE_LENGTH_INVALID"))?;
    if profile_length == 0 || profile_length > 64 || profile_end > raw.len() {
        return Err(err("E050_PRIVATE_OBJECT_PROFILE_LENGTH_INVALID"));
    }
    let profile_id = std::str::from_utf8(&raw[offset..profile_end])
        .map_err(|_| err("E050_PRIVATE_OBJECT_PROFILE_INVALID"))?
        .to_owned();
    offset = profile_end;
    let read_u32 = |position: usize| -> Result<u32> {
        let bytes: [u8; 4] = raw
            .get(position..position + 4)
            .ok_or_else(|| err("E050_PRIVATE_OBJECT_WIRE_LENGTH_INVALID"))?
            .try_into()
            .map_err(|_| err("E050_PRIVATE_OBJECT_WIRE_LENGTH_INVALID"))?;
        Ok(u32::from_be_bytes(bytes))
    };
    let epoch = read_u32(offset)?;
    offset += 4;
    let plaintext_length = read_u32(offset)?;
    offset += 4;
    let nonce_end = offset + PRIVATE_OBJECT_WIRE_V1_NONCE_BYTES;
    let nonce: [u8; PRIVATE_OBJECT_WIRE_V1_NONCE_BYTES] = raw
        .get(offset..nonce_end)
        .ok_or_else(|| err("E050_PRIVATE_OBJECT_WIRE_LENGTH_INVALID"))?
        .try_into()
        .map_err(|_| err("E050_PRIVATE_OBJECT_WIRE_LENGTH_INVALID"))?;
    offset = nonce_end;
    let ciphertext_length = usize::try_from(read_u32(offset)?)
        .map_err(|_| err("E050_PRIVATE_OBJECT_LENGTH_INVALID"))?;
    offset += 4;
    let plaintext_length_usize =
        usize::try_from(plaintext_length).map_err(|_| err("E050_PRIVATE_OBJECT_LENGTH_INVALID"))?;
    if plaintext_length_usize > PRIVATE_OBJECT_WIRE_V1_MAX_PLAINTEXT_BYTES
        || ciphertext_length != plaintext_length_usize + PRIVATE_OBJECT_WIRE_V1_TAG_BYTES
    {
        return Err(err("E050_PRIVATE_OBJECT_LENGTH_INVALID"));
    }
    let ciphertext_end = offset
        .checked_add(ciphertext_length)
        .ok_or_else(|| err("E050_PRIVATE_OBJECT_WIRE_LENGTH_INVALID"))?;
    let hashes_end = ciphertext_end
        .checked_add(4 * PRIVATE_OBJECT_WIRE_V1_HASH_BYTES)
        .ok_or_else(|| err("E050_PRIVATE_OBJECT_WIRE_LENGTH_INVALID"))?;
    if hashes_end != raw.len() {
        return Err(err("E050_PRIVATE_OBJECT_WIRE_LENGTH_INVALID"));
    }
    let ciphertext = raw[offset..ciphertext_end].to_vec();
    offset = ciphertext_end;
    let read_hash = |position: usize| -> Result<[u8; PRIVATE_OBJECT_WIRE_V1_HASH_BYTES]> {
        raw.get(position..position + PRIVATE_OBJECT_WIRE_V1_HASH_BYTES)
            .ok_or_else(|| err("E050_PRIVATE_OBJECT_WIRE_LENGTH_INVALID"))?
            .try_into()
            .map_err(|_| err("E050_PRIVATE_OBJECT_WIRE_LENGTH_INVALID"))
    };
    let value = PrivateObjectWireV1 {
        profile_id,
        epoch,
        plaintext_length,
        nonce,
        ciphertext,
        ciphertext_digest: read_hash(offset)?,
        object_id: read_hash(offset + PRIVATE_OBJECT_WIRE_V1_HASH_BYTES)?,
        record_commitment: read_hash(offset + 2 * PRIVATE_OBJECT_WIRE_V1_HASH_BYTES)?,
        context_commitment: read_hash(offset + 3 * PRIVATE_OBJECT_WIRE_V1_HASH_BYTES)?,
    };
    validate_private_object_wire_v1(&value)?;
    Ok(value)
}
