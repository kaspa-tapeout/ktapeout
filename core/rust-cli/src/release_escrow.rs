//! Deed state escrow. The state arguments of an application Deed are hashes, a nonce and constants: not secret, but
//! unrecoverable once the transaction that created them is pruned (the live UTXO holds only their script hash). The owner
//! needs them to spend the Deed again, and anyone needs them to prove the name's target. Before a transition is signed,
//! the state it will create is written to at least `MIN_COPIES` independent locations and read back.
//!
//! No encryption: there is nothing to hide, and a plain file is recoverable without this tool. Integrity comes from
//! recomputing the Deed script from the saved state and comparing it with the script the unsigned transaction creates.
use crate::release_closure::{canonical_json, sha256};
use crate::release_resolve::{compute_state_spk, StateHelper};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

pub const MIN_COPIES: usize = 2;
const SCHEMA: &str = "KTAPEOUT-DEED-STATE-ESCROW-V1";

/// Canonical record for one Deed state. `digest` covers every other field.
pub fn record(
    state_args: &[Value],
    script_public_key: &str,
    unsigned_txid: &str,
    name: &str,
) -> Result<Value, String> {
    if state_args.len() != 15 {
        return Err("ESCROW_STATE_INVALID".into());
    }
    let body = json!({
        "schema": SCHEMA, "network": "testnet-10", "name": name, "state_args": state_args,
        "script_public_key": script_public_key, "unsigned_txid": unsigned_txid,
    });
    let digest = sha256(canonical_json(&body)?.as_bytes());
    let mut full = body;
    full["digest"] = Value::String(digest);
    Ok(full)
}

/// A record is valid when its digest holds and the helper recompiles its state to the script it names.
pub fn verify_record(
    value: &Value,
    helper: &StateHelper,
    expected_spk: Option<&str>,
) -> Result<(), String> {
    let mut body = value.clone();
    let digest = body
        .as_object_mut()
        .and_then(|o| o.remove("digest"))
        .and_then(|d| d.as_str().map(String::from));
    if value["schema"] != SCHEMA || digest.is_none() {
        return Err("ESCROW_RECORD_INVALID".into());
    }
    if digest.as_deref() != Some(sha256(canonical_json(&body)?.as_bytes()).as_str()) {
        return Err("ESCROW_DIGEST_MISMATCH".into());
    }
    let state = value["state_args"]
        .as_array()
        .ok_or("ESCROW_RECORD_INVALID")?;
    let script = value["script_public_key"]
        .as_str()
        .ok_or("ESCROW_RECORD_INVALID")?;
    if compute_state_spk(helper, state)? != script {
        return Err("ESCROW_STATE_SCRIPT_MISMATCH".into());
    }
    if expected_spk.is_some_and(|expected| expected != script) {
        return Err("ESCROW_SCRIPT_NOT_THE_PLANNED_SUCCESSOR".into());
    }
    Ok(())
}

fn file_name(record: &Value) -> String {
    format!(
        "deed-state-{}.json",
        &record["script_public_key"].as_str().unwrap_or_default()[..16.min(
            record["script_public_key"]
                .as_str()
                .unwrap_or_default()
                .len()
        )]
    )
}

/// Write the record into each distinct directory, then read each copy back and verify it again. Returns the paths.
pub fn escrow(
    record: &Value,
    destinations: &[PathBuf],
    helper: &StateHelper,
    expected_spk: &str,
) -> Result<Vec<PathBuf>, String> {
    verify_record(record, helper, Some(expected_spk))?;
    let mut canonical_dirs = Vec::new();
    for dir in destinations {
        fs::create_dir_all(dir).map_err(|_| "ESCROW_DESTINATION_UNAVAILABLE")?;
        let real = fs::canonicalize(dir).map_err(|_| "ESCROW_DESTINATION_UNAVAILABLE")?;
        if !canonical_dirs.contains(&real) {
            canonical_dirs.push(real);
        }
    }
    if canonical_dirs.len() < MIN_COPIES {
        return Err("ESCROW_TWO_DISTINCT_DESTINATIONS_REQUIRED".into());
    }
    let mut bytes = serde_json::to_vec_pretty(record).map_err(|_| "ESCROW_RECORD_INVALID")?;
    bytes.push(b'\n');
    let mut written = Vec::new();
    for dir in &canonical_dirs {
        let target = dir.join(file_name(record));
        if let Ok(existing) = fs::read(&target) {
            if existing != bytes {
                return Err("ESCROW_DESTINATION_HOLDS_A_DIFFERENT_RECORD".into());
            }
        } else {
            let temp = target.with_extension("tmp");
            fs::write(&temp, &bytes).map_err(|_| "ESCROW_WRITE_FAILED")?;
            fs::rename(&temp, &target).map_err(|_| "ESCROW_WRITE_FAILED")?;
        }
        let back: Value =
            serde_json::from_slice(&fs::read(&target).map_err(|_| "ESCROW_READBACK_FAILED")?)
                .map_err(|_| "ESCROW_READBACK_FAILED")?;
        verify_record(&back, helper, Some(expected_spk))?;
        written.push(target);
    }
    Ok(written)
}

/// Gate used before signing: at least `MIN_COPIES` distinct, valid copies exist for the planned successor script.
pub fn require_escrow(
    files: &[PathBuf],
    helper: &StateHelper,
    expected_spk: &str,
) -> Result<(), String> {
    let mut seen = Vec::new();
    for file in files {
        let real = fs::canonicalize(file).map_err(|_| "ESCROW_COPY_MISSING")?;
        if seen.contains(&real) {
            continue;
        }
        let value: Value =
            serde_json::from_slice(&fs::read(&real).map_err(|_| "ESCROW_COPY_MISSING")?)
                .map_err(|_| "ESCROW_RECORD_INVALID")?;
        verify_record(&value, helper, Some(expected_spk))?;
        seen.push(real);
    }
    if seen.len() < MIN_COPIES {
        return Err("ESCROW_TWO_DISTINCT_COPIES_REQUIRED".into());
    }
    Ok(())
}

pub fn read_state_file(path: &Path) -> Result<Vec<Value>, String> {
    let value: Value =
        serde_json::from_slice(&fs::read(path).map_err(|_| "ESCROW_STATE_UNAVAILABLE")?)
            .map_err(|_| "ESCROW_STATE_INVALID")?;
    value["state_args"]
        .as_array()
        .cloned()
        .ok_or_else(|| "ESCROW_STATE_INVALID".into())
}
