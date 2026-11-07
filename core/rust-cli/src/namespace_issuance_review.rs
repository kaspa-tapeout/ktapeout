//! Fail-closed review artifacts for namespace issuance plans.
//!
//! Namespace issuance remains unverified on TN10. This module deliberately creates review and
//! escrow artifacts only; it has no signing or broadcast path.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

#[cfg(feature = "tn10-network")]
use crate::tn10_pipeline::Transport;
#[cfg(feature = "tn10-network")]
use kaspa_consensus_core::tx::Transaction;
#[cfg(feature = "tn10-network")]
use kaspa_rpc_core::RpcTransaction;

const PLAN_DOMAIN: &[u8] = b"KTAPEOUT/0.5.0/NAMESPACE_ISSUANCE/V1\0";
const UNVERIFIED: &str = "UNVERIFIED_ON_CHAIN: \u{547d}\u{540d}\u{7a7a}\u{95f4}\u{53d1}\u{884c}\u{8ba1}\u{5212}\u{53ca}\u{5176}\u{6210}\u{672c}\u{5c1a}\u{672a}\u{7ecf}\u{8fc7}\u{771f}\u{5b9e} TN10 \u{9a8c}\u{8bc1}";

pub fn plan_hash(body: &Value) -> Result<String, String> {
    let bytes = serde_json::to_vec(body).map_err(|_| "NAMESPACE_ISSUANCE_PLAN_INVALID")?;
    let mut hash = Sha256::new();
    hash.update(PLAN_DOMAIN);
    hash.update(bytes);
    Ok(hex::encode(hash.finalize()))
}

fn validate_prepared(prepared: &Value) -> Result<&Value, String> {
    let body = prepared
        .get("body")
        .ok_or("NAMESPACE_ISSUANCE_PLAN_INVALID")?;
    if body["schema"] != "KTAPEOUT-NAMESPACE-ISSUANCE-BODY-V1"
        || body["network"] != "testnet-10"
        || body["verification_status"] != UNVERIFIED
        || prepared["plan_hash"].as_str() != Some(plan_hash(body)?.as_str())
    {
        return Err("NAMESPACE_ISSUANCE_PLAN_INVALID_OR_CHAIN_UNVERIFIED".into());
    }
    if body["signing_allowed"] != false {
        return Err("NAMESPACE_ISSUANCE_UNVERIFIED_SIGNING_DISABLED".into());
    }
    if body["broadcast"] != false {
        return Err("NAMESPACE_ISSUANCE_UNVERIFIED_SUBMISSION_DISABLED".into());
    }
    let warnings = body["permanent_warnings"]
        .as_array()
        .ok_or("NAMESPACE_ISSUANCE_WARNINGS_REQUIRED")?;
    for required in [
        "\u{6ca1}\u{6709}\u{9000}\u{8fd8}\u{8def}\u{5f84}",
        "\u{4e22}\u{5931}\u{63a7}\u{5236}\u{5bc6}\u{94a5}\u{5c06}\u{6c38}\u{4e45}\u{5931}\u{53bb}\u{547d}\u{540d}\u{7a7a}\u{95f4}\u{63a7}\u{5236}\u{6743}",
        "\u{7b2c}\u{4e00}\u{7248}\u{4e0d}\u{652f}\u{6301}\u{8f6c}\u{8ba9}\u{548c}\u{5173}\u{95ed}\u{547d}\u{540d}\u{7a7a}\u{95f4}",
    ] {
        if !warnings
            .iter()
            .any(|warning| warning.as_str().is_some_and(|s| s.contains(required)))
        {
            return Err("NAMESPACE_ISSUANCE_WARNINGS_REQUIRED".into());
        }
    }
    Ok(body)
}

fn validate_role_keys(body: &Value) -> Result<(), String> {
    let Some(keys) = body.get("role_public_keys") else {
        return Ok(());
    };
    let keys = keys
        .as_object()
        .ok_or("NAMESPACE_ISSUANCE_ROLE_PUBLIC_KEY_INVALID")?;
    for role in ["namespace_authority", "claimant", "fee_input"] {
        let key = keys
            .get(role)
            .ok_or("NAMESPACE_ISSUANCE_ROLE_PUBLIC_KEYS_REQUIRED")?;
        if key.is_null() {
            continue;
        }
        let key = key
            .as_str()
            .ok_or("NAMESPACE_ISSUANCE_ROLE_PUBLIC_KEY_INVALID")?;
        if key.len() != 64
            || !key
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err("NAMESPACE_ISSUANCE_ROLE_PUBLIC_KEY_INVALID".into());
        }
    }
    Ok(())
}

pub fn build_review_packet(prepared: &Value) -> Result<Value, String> {
    let body = validate_prepared(prepared)?;
    validate_role_keys(body)?;
    let mut packet = json!({
        "schema":"KTAPEOUT-NAMESPACE-ISSUANCE-REVIEW-PACKET-V1",
        "network":"testnet-10",
        "plan_hash":prepared["plan_hash"],
        "body":body,
        "verification_status":UNVERIFIED,
        "review_only":true,
        "signing_allowed":false,
        "broadcast":false
    });
    packet["packet_hash"] = json!(hex::encode(Sha256::digest(
        serde_json::to_vec(&packet).map_err(|_| "NAMESPACE_ISSUANCE_PACKET_INVALID")?
    )));
    Ok(packet)
}

pub fn verify_review_packet(prepared: &Value, packet: &Value) -> Result<(), String> {
    let expected = build_review_packet(prepared)?;
    if packet != &expected {
        return Err("NAMESPACE_ISSUANCE_REVIEW_PACKET_MISMATCH".into());
    }
    Ok(())
}

pub fn build_approval_review(prepared: &Value, packet: &Value) -> Result<Value, String> {
    verify_review_packet(prepared, packet)?;
    validate_role_keys(&prepared["body"])?;
    let empty_keys = json!({});
    let keys = prepared["body"]
        .get("role_public_keys")
        .unwrap_or(&empty_keys);
    let roles = ["namespace_authority", "claimant", "fee_input"];
    let role_keys = roles
        .iter()
        .map(|role| {
            let key = &keys[*role];
            if key.is_null() {
                json!({"role":role,"public_key":Value::Null,"status":"NOT_PRESENT_IN_PLAN"})
            } else {
                json!({"role":role,"public_key":key,"status":"PRESENT_IN_PLAN"})
            }
        })
        .collect::<Vec<_>>();
    let mut relationships = Vec::new();
    for i in 0..roles.len() {
        for j in i + 1..roles.len() {
            relationships.push(json!({
                "role_a":roles[i],
                "role_b":roles[j],
                "relationship":if keys[roles[i]].is_null() || keys[roles[j]].is_null() {"UNAVAILABLE"} else if keys[roles[i]] == keys[roles[j]] {"SAME_KEY"} else {"DIFFERENT_KEY"}
            }));
        }
    }
    let mut review = json!({
        "schema":"KTAPEOUT-NAMESPACE-ISSUANCE-APPROVAL-REVIEW-V1",
        "status":"REVIEW_ONLY_NO_APPROVAL",
        "network":"testnet-10",
        "plan_hash":prepared["plan_hash"],
        "packet_hash":packet["packet_hash"],
        "verification_status":UNVERIFIED,
        "role_public_keys":role_keys,
        "role_key_relationships":relationships,
        "signing_or_broadcast_authorized":false
    });
    review["review_hash"] = json!(hex::encode(Sha256::digest(
        serde_json::to_vec(&review).map_err(|_| "NAMESPACE_ISSUANCE_REVIEW_INVALID")?
    )));
    Ok(review)
}

pub fn verify_approval_review(
    prepared: &Value,
    packet: &Value,
    review: &Value,
) -> Result<(), String> {
    let expected = build_approval_review(prepared, packet)?;
    if review != &expected {
        return Err("NAMESPACE_ISSUANCE_APPROVAL_REVIEW_MISMATCH".into());
    }
    Ok(())
}

/// Save the review packet to two distinct local roots. This stores no signing request or key.
pub fn escrow_review_packet(
    prepared: &Value,
    destinations: &[PathBuf],
) -> Result<Vec<PathBuf>, String> {
    let packet = build_review_packet(prepared)?;
    let mut roots = Vec::new();
    for destination in destinations {
        fs::create_dir_all(destination).map_err(|_| "NAMESPACE_ISSUANCE_ESCROW_IO_ERROR")?;
        let metadata =
            fs::symlink_metadata(destination).map_err(|_| "NAMESPACE_ISSUANCE_ESCROW_IO_ERROR")?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("NAMESPACE_ISSUANCE_ESCROW_DESTINATION_INVALID".into());
        }
        let root =
            fs::canonicalize(destination).map_err(|_| "NAMESPACE_ISSUANCE_ESCROW_IO_ERROR")?;
        if !roots.contains(&root) {
            roots.push(root);
        }
    }
    if roots.len() < 2 {
        return Err("NAMESPACE_ISSUANCE_ESCROW_TWO_DISTINCT_DESTINATIONS_REQUIRED".into());
    }
    let filename = format!(
        "namespace-issuance-review-{}.json",
        &prepared["plan_hash"]
            .as_str()
            .ok_or("NAMESPACE_ISSUANCE_PLAN_INVALID")?[..16]
    );
    let mut paths = Vec::new();
    for root in roots {
        let path = root.join(&filename);
        if path.exists() {
            let existing: Value = serde_json::from_slice(
                &fs::read(&path).map_err(|_| "NAMESPACE_ISSUANCE_ESCROW_IO_ERROR")?,
            )
            .map_err(|_| "NAMESPACE_ISSUANCE_ESCROW_FILE_INVALID")?;
            verify_review_packet(prepared, &existing)?;
        } else {
            let bytes = serde_json::to_vec_pretty(&packet)
                .map_err(|_| "NAMESPACE_ISSUANCE_PACKET_INVALID")?;
            fs::write(&path, bytes).map_err(|_| "NAMESPACE_ISSUANCE_ESCROW_IO_ERROR")?;
        }
        paths.push(path);
    }
    Ok(paths)
}

/// Issuance signing stays closed until a separate M8-B authorization and TN10 verification.
pub fn require_signing_authorized(_prepared: &Value) -> Result<(), String> {
    Err("NAMESPACE_ISSUANCE_UNVERIFIED_SIGNING_DISABLED".into())
}

pub fn require_chain_submission_enabled(_prepared: &Value) -> Result<(), String> {
    Err("NAMESPACE_ISSUANCE_UNVERIFIED_SUBMISSION_DISABLED".into())
}

/// Read-only M4-style reconciliation for a transaction that an external workflow already reports.
/// This does not create, sign, submit, or retry a transaction.
#[cfg(feature = "tn10-network")]
pub fn reconcile_submission_with_transports(
    prepared: &Value,
    submission: &Value,
    signed_transaction: &Value,
    txid: &str,
    first: &mut dyn Transport,
    second: &mut dyn Transport,
) -> Result<Value, String> {
    validate_prepared(prepared)?;
    if submission["schema"] != "KTAPEOUT-TN10-NAMESPACE-ISSUANCE-SUBMIT-V1"
        || submission["network"] != "testnet-10"
        || !matches!(
            submission["status"].as_str(),
            Some("SUBMISSION_UNKNOWN" | "SUBMITTED")
        )
        || submission["plan_hash"].as_str() != prepared["plan_hash"].as_str()
        || submission["txid"].as_str() != Some(txid)
    {
        return Err("NAMESPACE_ISSUANCE_SUBMISSION_BINDING_MISMATCH".into());
    }
    let unsigned_rpc: RpcTransaction =
        serde_json::from_value(prepared["body"]["transaction"].clone())
            .map_err(|_| "NAMESPACE_ISSUANCE_TRANSACTION_INVALID")?;
    let mut expected = Transaction::try_from(unsigned_rpc)
        .map_err(|_| "NAMESPACE_ISSUANCE_TRANSACTION_INVALID")?;
    for input in &mut expected.inputs {
        input.signature_script.clear();
    }
    let signed_rpc: RpcTransaction = serde_json::from_value(signed_transaction.clone())
        .map_err(|_| "NAMESPACE_ISSUANCE_TRANSACTION_INVALID")?;
    let signed =
        Transaction::try_from(signed_rpc).map_err(|_| "NAMESPACE_ISSUANCE_TRANSACTION_INVALID")?;
    let mut stripped_signed = signed.clone();
    for input in &mut stripped_signed.inputs {
        input.signature_script.clear();
    }
    if stripped_signed != expected || signed.id().to_string() != txid {
        return Err("NAMESPACE_ISSUANCE_PLAN_TRANSACTION_MISMATCH".into());
    }
    let left = first
        .read_transaction(txid)
        .map_err(|_| "TN10_READBACK_RPC_FAILED")?;
    let right = second
        .read_transaction(txid)
        .map_err(|_| "TN10_READBACK_RPC_FAILED")?;
    let base = json!({
        "schema":"KTAPEOUT-TN10-NAMESPACE-ISSUANCE-READBACK-V1",
        "network":"testnet-10",
        "operation":"READBACK_ONLY",
        "txid":txid,
        "plan_hash":prepared["plan_hash"],
        "signature_validity":"NOT_VERIFIED_BY_READBACK",
        "finality":"FINALITY_UNCHECKED",
        "broadcast_action":"NOT_PERFORMED_BY_READBACK"
    });
    match (left, right) {
        (None, None) => {
            let mut receipt = base;
            receipt["status"] = json!("NOT_FOUND_BOTH_REQUIRES_REVIEW");
            receipt["node_observations"] = json!(["NOT_FOUND", "NOT_FOUND"]);
            Ok(receipt)
        }
        (Some(left), Some(right)) => {
            let left_rpc: RpcTransaction =
                serde_json::from_value(left).map_err(|_| "TN10_TRANSACTION_INVALID")?;
            let right_rpc: RpcTransaction =
                serde_json::from_value(right).map_err(|_| "TN10_TRANSACTION_INVALID")?;
            let left_native =
                Transaction::try_from(left_rpc).map_err(|_| "TN10_TRANSACTION_INVALID")?;
            let right_native =
                Transaction::try_from(right_rpc).map_err(|_| "TN10_TRANSACTION_INVALID")?;
            if left_native != right_native {
                return Err("TN10_DUAL_NODE_DISAGREEMENT".into());
            }
            if left_native != signed || left_native.id().to_string() != txid {
                return Err("NAMESPACE_ISSUANCE_READBACK_TRANSACTION_MISMATCH".into());
            }
            let mut receipt = base;
            receipt["status"] = json!("FOUND_BOTH_MATCH");
            receipt["node_observations"] = json!(["MATCH", "MATCH"]);
            Ok(receipt)
        }
        _ => Err("TN10_DUAL_NODE_DISAGREEMENT".into()),
    }
}

pub fn is_within_root(path: &Path, root: &Path) -> bool {
    path.starts_with(root)
}
