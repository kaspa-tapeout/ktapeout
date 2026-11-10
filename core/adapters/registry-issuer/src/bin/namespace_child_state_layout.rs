//! Shared candidate state-layout metadata for namespace child workbenches.
//!
//! This describes the current Silverscript source layout for tooling and AI
//! handoff. It is deliberately labelled as a candidate and is not a wire
//! codec or Profile admission artifact.

use serde_json::Value;

const CONTRACT_JSON: &str =
    include_str!("../../../../spec/ktapeout-namespace-child-registration-v2-contract.json");

pub fn candidate_state_layout(include_child: bool) -> Value {
    let contract: Value = serde_json::from_str(CONTRACT_JSON)
        .expect("published V2 contract metadata must be valid JSON");
    let mut result = contract["state_layout"].clone();
    if !include_child {
        result
            .as_object_mut()
            .expect("state layout must be an object")
            .remove("child");
    }
    result
}
