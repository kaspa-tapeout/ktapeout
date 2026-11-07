//! Readback of a submitted transaction. Two independent nodes must each report the transaction accepted by the selected
//! chain and each return a block holding exactly the bytes that were signed; the block's own body commitments are then
//! re-verified by the pinned inclusion verifier. Raw answers come from the read-only scan helper and are never trusted
//! beyond what is re-checked here. It does not prove finality and it never signs or submits.
use serde_json::{json, Value};
use std::path::Path;
use std::process::{Command, Stdio};

/// Remove node-added `verboseData` at any depth: it is derived by the node, not part of the signed bytes.
fn clean(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(clean).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .filter(|(k, _)| k.as_str() != "verboseData")
                .map(|(k, v)| (k.clone(), clean(v)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// The signed transaction as the node reports it: natively planned transactions carry no storage mass until a node fills it
/// in, so a zero mass is replaced by the independently projected value. A mass that differs otherwise is a mismatch.
fn expected_transaction(signed: &Value, projected_storage_mass: Option<u64>) -> Value {
    let mut tx = clean(signed);
    if let (Some(object), Some(mass)) = (tx.as_object_mut(), projected_storage_mass) {
        for field in ["mass", "storageMass"] {
            if object.get(field).and_then(Value::as_u64).unwrap_or(0) == 0 {
                object.insert(field.into(), json!(mass));
            }
        }
    }
    tx
}

fn transaction_in<'a>(block: &'a Value, txid: &str) -> Option<&'a Value> {
    block["transactions"]
        .as_array()?
        .iter()
        .find(|tx| tx["verboseData"]["transactionId"] == txid)
}

/// Pure comparison of the raw scan against the signed bytes; returns, per node, the blocks whose copy matches exactly.
pub fn matching_blocks<'a>(
    scan: &'a Value,
    txid: &str,
    signed: &Value,
    projected_storage_mass: Option<u64>,
) -> Result<Vec<(&'a str, Vec<&'a Value>)>, String> {
    if scan["schema"] != "KTAPEOUT-TX-SCAN-RAW-V1" || scan["txid"] != txid {
        return Err("READBACK_SCAN_INVALID".into());
    }
    let nodes = scan["nodes"]
        .as_array()
        .filter(|n| n.len() == 2)
        .ok_or("READBACK_TWO_NODES_REQUIRED")?;
    if nodes[0]["endpoint"] == nodes[1]["endpoint"] {
        return Err("READBACK_TWO_NODES_REQUIRED".into());
    }
    let expected = expected_transaction(signed, projected_storage_mass);
    let mut out = Vec::new();
    for node in nodes {
        let endpoint = node["endpoint"].as_str().ok_or("READBACK_SCAN_INVALID")?;
        if node["accepted"].as_array().is_none_or(Vec::is_empty) {
            return Err(format!("READBACK_NOT_ACCEPTED:{endpoint}"));
        }
        let blocks: Vec<&Value> = node["matches"]
            .as_array()
            .ok_or("READBACK_SCAN_INVALID")?
            .iter()
            .filter(|block| transaction_in(block, txid).is_some_and(|tx| clean(tx) == expected))
            .collect();
        if blocks.is_empty() {
            return Err(format!(
                "READBACK_TRANSACTION_DIFFERS_FROM_SIGNED:{endpoint}"
            ));
        }
        out.push((endpoint, blocks));
    }
    Ok(out)
}

/// Verify the block-body commitments of the first matching block on each node with the pinned inclusion verifier.
pub fn verify(
    scan: &Value,
    txid: &str,
    signed: &Value,
    projected_storage_mass: Option<u64>,
    verifier: &Path,
    verifier_sha256: &str,
) -> Result<Value, String> {
    let bytes = std::fs::read(verifier).map_err(|_| "READBACK_VERIFIER_UNAVAILABLE")?;
    if crate::release_closure::sha256(&bytes) != verifier_sha256 {
        return Err("READBACK_VERIFIER_CHANGED".into());
    }
    let mut reports = Vec::new();
    for (endpoint, blocks) in matching_blocks(scan, txid, signed, projected_storage_mass)? {
        let block = blocks[0];
        let hash = block["verboseData"]["hash"]
            .as_str()
            .ok_or("READBACK_SCAN_INVALID")?;
        let request = json!({"schema": "KTAPEOUT-KASPA-BLOCK-BODY-INCLUSION-VERIFY-V1", "network": "testnet-10",
            "expectedBlockHash": hash, "transactionId": txid, "block": block});
        let mut child = Command::new(verifier)
            .env_clear()
            .envs(
                ["SystemRoot", "windir"]
                    .iter()
                    .filter_map(|k| std::env::var(k).ok().map(|v| (*k, v))),
            )
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| "READBACK_VERIFIER_SPAWN_FAILED")?;
        {
            use std::io::Write;
            child
                .stdin
                .take()
                .ok_or("READBACK_VERIFIER_SPAWN_FAILED")?
                .write_all(request.to_string().as_bytes())
                .map_err(|_| "READBACK_VERIFIER_SPAWN_FAILED")?;
        }
        let output = child
            .wait_with_output()
            .map_err(|_| "READBACK_VERIFIER_FAILED")?;
        if !output.status.success() {
            return Err(format!("READBACK_INCLUSION_FAILED:{endpoint}"));
        }
        let inclusion: Value = serde_json::from_slice(&output.stdout)
            .map_err(|_| "READBACK_VERIFIER_OUTPUT_INVALID")?;
        reports.push(json!({"endpoint": endpoint, "accepted": true, "exact_signed_bytes_match": true, "block_hash": hash, "inclusion": inclusion}));
    }
    Ok(
        json!({"schema": "KTAPEOUT-READBACK-V1", "status": "TWO_NODE_ACCEPTANCE_EXACT_TRANSACTION_AND_BLOCK_COMMITMENTS_VERIFIED",
        "txid": txid, "nodes": reports, "finality_proven": false, "signing_allowed": false, "broadcast": false}),
    )
}
