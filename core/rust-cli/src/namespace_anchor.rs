//! Compile-time pin for the admitted TN10 namespace issuance root.

use serde_json::Value;
use sha2::{Digest, Sha256};

const ANCHOR_JSON: &str =
    include_str!("../../../data/registry/tn10-namespace-issuance-anchor-v1.json");
const ANCHOR_BYTES_SHA256: &str =
    "884292c78196af0c178c3ccf6e269ecca1bca7c025131dcd6b314afb56647c7d";

/// Require a caller-supplied anchor document to match the exact compiled TN10 pin.
pub fn verify_fixed_anchor(candidate: &Value) -> Result<(), &'static str> {
    let digest = hex::encode(Sha256::digest(ANCHOR_JSON.as_bytes()));
    if digest != ANCHOR_BYTES_SHA256 {
        return Err("NAMESPACE_ANCHOR_PIN_MISMATCH");
    }
    let expected: Value =
        serde_json::from_str(ANCHOR_JSON).map_err(|_| "NAMESPACE_ANCHOR_PIN_MISMATCH")?;
    let candidate_fields = candidate
        .as_object()
        .ok_or("NAMESPACE_ANCHOR_PIN_MISMATCH")?;
    let expected_fields = expected
        .as_object()
        .ok_or("NAMESPACE_ANCHOR_PIN_MISMATCH")?;
    if candidate_fields.len() != expected_fields.len()
        || expected_fields
            .iter()
            .any(|(field, pinned)| candidate_fields.get(field) != Some(pinned))
    {
        return Err("NAMESPACE_ANCHOR_PIN_MISMATCH");
    }
    Ok(())
}
