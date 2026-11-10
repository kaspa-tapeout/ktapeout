//! Shared metadata for the confirmed namespace child-registration V2 route.
//!
//! This is intentionally only the contract identity and role ordering.  It is
//! shared by the candidate compiler, witness workbench, and unsigned body
//! codec so those tools cannot silently drift.  It does not make the route a
//! canonical codec, enable signing, or grant Profile/L1 admission.

use serde_json::Value;
use sha2::{Digest, Sha256};

const CONTRACT_JSON: &str =
    include_str!("../../../../spec/ktapeout-namespace-child-registration-v2-contract.json");

pub const CODEC_ID: &str = "namespace-child-registration-canonical-v2";
pub const WIRE_VERSION: u64 = 2;
pub const SIGNING_DOMAIN: &str = "KTAPEOUT/0.5.0/NAMESPACE_CHILD_REGISTRATION/CANONICAL/V2";

pub const INPUT_ROLES: [&str; 3] = [
    "parent_namespace_state",
    "containing_gap_state",
    "fee_input",
];

pub const OUTPUT_ROLES: [&str; 5] = [
    "parent_successor",
    "left_gap",
    "name_deed",
    "right_gap",
    "fee_change",
];

pub fn metadata() -> Value {
    let mut value: Value = serde_json::from_str(CONTRACT_JSON)
        .expect("published V2 contract metadata must be valid JSON");
    assert_eq!(value["codec_id"], CODEC_ID, "published codec id drifted");
    assert_eq!(
        value["wire_version"], WIRE_VERSION,
        "published wire version drifted"
    );
    assert_eq!(
        value["signing_domain"], SIGNING_DOMAIN,
        "published signing domain drifted"
    );
    assert_eq!(
        value["input_roles"],
        serde_json::json!(INPUT_ROLES),
        "published input roles drifted"
    );
    assert_eq!(
        value["output_roles"],
        serde_json::json!(OUTPUT_ROLES),
        "published output roles drifted"
    );
    value["manifest_sha256"] = Value::String(hex::encode(Sha256::digest(CONTRACT_JSON.as_bytes())));
    value
}

/// Independently versioned lifecycle identity; never relabel historical V2.
pub fn recovery_metadata() -> Value {
    const RAW: &str =
        include_str!("../../../../spec/ktapeout-namespace-lifecycle-v5-contract.json");
    let mut value: Value =
        serde_json::from_str(RAW).expect("published V5 contract must be valid JSON");
    assert_eq!(value["wire_version"], 5);
    assert_eq!(value["codec_id"], "namespace-lifecycle-candidate-v5");
    value["manifest_sha256"] = Value::String(hex::encode(Sha256::digest(RAW.as_bytes())));
    value
}

pub fn named_metadata() -> Value {
    const RAW: &str =
        include_str!("../../../../spec/ktapeout-namespace-named-lifecycle-v6-contract.json");
    let mut value: Value = serde_json::from_str(RAW).expect("published named contract JSON");
    let base = recovery_metadata();
    assert_eq!(value["base_manifest_sha256"], base["manifest_sha256"]);
    assert_eq!(value["wire_version"], 6);
    value["state_constructor_order"] = base["state_constructor_order"].clone();
    value["operations"] = base["operations"].clone();
    value["operations"]["TRANSFER_AUTHORITY"] = serde_json::json!({"inputs":["parent_namespace_state","fee_input"],"outputs":["parent_successor","fee_change"]});
    value["transaction_signature"] = base["transaction_signature"].clone();
    value["manifest_sha256"] = Value::String(hex::encode(Sha256::digest(RAW.as_bytes())));
    value
}
