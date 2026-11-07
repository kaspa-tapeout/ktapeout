//! Read-only reconciliation of escrow replicas and current name receipts. Absence from
//! the UTXO set means inactive, not proof that a historical transaction was spent.
use crate::release_closure::sha256;
use crate::release_name_update::{pinned_bytes, run_env_free, Pinned};
use crate::release_resolve::{resolve_with_fetcher, StateHelper};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

struct AuditTemp(PathBuf);
fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl Drop for AuditTemp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn entries(raw: &Value, node: &str, script: &str) -> Result<BTreeMap<String, Value>, String> {
    let rows = raw[node]["utxos"][script]["entries"]
        .as_array()
        .ok_or("ESCROW_AUDIT_OBSERVATION_INVALID")?;
    let mut result = BTreeMap::new();
    for row in rows {
        let entry = &row["utxoEntry"];
        if entry["scriptPublicKey"].as_str() != Some(script) {
            return Err("ESCROW_AUDIT_WRONG_SCRIPT".into());
        }
        let id = row["outpoint"]["transactionId"]
            .as_str()
            .ok_or("ESCROW_AUDIT_OBSERVATION_INVALID")?;
        let index = row["outpoint"]["index"]
            .as_u64()
            .ok_or("ESCROW_AUDIT_OBSERVATION_INVALID")?;
        if !hash(id) || index > u32::MAX as u64 || entry["amount"].as_u64().is_none() {
            return Err("ESCROW_AUDIT_OBSERVATION_INVALID".into());
        }
        if result
            .insert(format!("{id}:{index}"), entry.clone())
            .is_some()
        {
            return Err("ESCROW_AUDIT_DUPLICATE_OUTPOINT".into());
        }
    }
    Ok(result)
}

pub fn classify(
    raw: &Value,
    script: &str,
    current: bool,
    copies_match: bool,
) -> Result<&'static str, String> {
    if !copies_match {
        return Ok("COPY_MISSING_OR_DIFFERENT");
    }
    for node in ["rpcA", "rpcB"] {
        if raw[node]["dag"]["network"] != "testnet-10"
            || raw[node]["dag"]["virtualDaaScore"].as_u64().is_none()
            || raw[node]["dag"]["tipHashes"].as_array().is_none_or(|tips| {
                tips.is_empty() || tips.iter().any(|t| !t.as_str().is_some_and(hash))
            })
        {
            return Err("ESCROW_AUDIT_NODE_ANCHOR_INVALID".into());
        }
    }
    if raw["rpcA"]["dag"]["virtualDaaScore"]
        .as_u64()
        .unwrap()
        .abs_diff(raw["rpcB"]["dag"]["virtualDaaScore"].as_u64().unwrap())
        > 300
    {
        return Err("ESCROW_AUDIT_NODE_TIP_SKEW".into());
    }
    let (a, b) = (entries(raw, "rpcA", script)?, entries(raw, "rpcB", script)?);
    if a != b {
        return Ok("NODE_DISAGREEMENT");
    }
    if a.len() > 1 {
        return Ok("AMBIGUOUS_LIVE_STATE");
    }
    Ok(match (current, a.is_empty()) {
        (true, false) => "CURRENT_LIVE",
        (true, true) => "CURRENT_NOT_LIVE",
        (false, false) => "LIVE_NOT_IN_CURRENT_RECEIPTS",
        (false, true) => "INACTIVE_HISTORY",
    })
}

pub fn audit(
    destinations: &[PathBuf],
    receipts: &[PathBuf],
    helper: &StateHelper,
    fetcher: &Pinned,
    endpoints: &[String],
) -> Result<Value, String> {
    if endpoints.len() != 2 || endpoints[0] == endpoints[1] || receipts.is_empty() {
        return Err("ESCROW_AUDIT_CURRENT_RECEIPTS_AND_TWO_NODES_REQUIRED".into());
    }
    let hosts: Vec<_> = endpoints
        .iter()
        .map(|e| {
            e.strip_prefix("wss://")
                .unwrap_or("")
                .split('/')
                .next()
                .unwrap_or("")
                .to_ascii_lowercase()
        })
        .collect();
    if hosts.iter().any(|h| {
        h.is_empty()
            || !h
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    }) || hosts[0] == hosts[1]
    {
        return Err("ESCROW_AUDIT_DISTINCT_NODE_HOSTS_REQUIRED".into());
    }
    let dirs: BTreeSet<_> = destinations
        .iter()
        .map(std::fs::canonicalize)
        .collect::<Result<_, _>>()
        .map_err(|_| "ESCROW_AUDIT_DESTINATION_UNAVAILABLE")?;
    if dirs.len() < crate::release_escrow::MIN_COPIES {
        return Err("ESCROW_TWO_DISTINCT_DESTINATIONS_REQUIRED".into());
    }
    let mut current = BTreeSet::new();
    for path in receipts {
        let receipt: Value = serde_json::from_slice(
            &std::fs::read(path).map_err(|_| "ESCROW_AUDIT_RECEIPT_UNAVAILABLE")?,
        )
        .map_err(|_| "ESCROW_AUDIT_RECEIPT_INVALID")?;
        if receipt["applications"]
            .as_array()
            .is_none_or(|items| items.len() != 1)
        {
            return Err("ESCROW_AUDIT_SINGLE_APPLICATION_RECEIPT_REQUIRED".into());
        }
        resolve_with_fetcher(
            &receipt,
            fetcher.path,
            fetcher.sha256,
            endpoints,
            60,
            Some(helper),
            false,
        )?;
        current.insert(
            receipt["applications"][0]["successor"]["script_public_key"]
                .as_str()
                .ok_or("ESCROW_AUDIT_RECEIPT_INVALID")?
                .to_string(),
        );
    }
    // Group by script, not filename: earlier tooling used transaction-prefix filenames.
    let mut groups: BTreeMap<String, BTreeMap<PathBuf, String>> = BTreeMap::new();
    let mut failures = Vec::new();
    for dir in &dirs {
        for entry in std::fs::read_dir(dir).map_err(|_| "ESCROW_AUDIT_DESTINATION_UNAVAILABLE")? {
            let entry = entry.map_err(|_| "ESCROW_AUDIT_READ_FAILED")?;
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.starts_with("deed-state-") || !name.ends_with(".json") {
                continue;
            }
            if !entry
                .file_type()
                .map_err(|_| "ESCROW_AUDIT_READ_FAILED")?
                .is_file()
            {
                return Err("ESCROW_AUDIT_NONREGULAR_COPY".into());
            }
            let bytes = std::fs::read(entry.path()).map_err(|_| "ESCROW_AUDIT_READ_FAILED")?;
            let value: Value =
                serde_json::from_slice(&bytes).map_err(|_| "ESCROW_RECORD_INVALID")?;
            if value["network"] != "testnet-10" {
                return Err("ESCROW_AUDIT_NETWORK_INVALID".into());
            }
            crate::release_escrow::verify_record(&value, helper, None)?;
            let script = value["script_public_key"]
                .as_str()
                .ok_or("ESCROW_RECORD_INVALID")?
                .to_string();
            let hash = sha256(&bytes);
            let group = groups.entry(script).or_default();
            if group
                .insert(dir.clone(), hash.clone())
                .is_some_and(|old| old != hash)
            {
                return Err("ESCROW_AUDIT_CONFLICTING_LOCAL_COPIES".into());
            }
        }
    }
    for script in &current {
        groups.entry(script.clone()).or_default();
    }
    pinned_bytes(fetcher)?;
    let temp = AuditTemp(std::env::temp_dir().join(format!(
            "ktape-escrow-audit-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| "ESCROW_AUDIT_CLOCK_INVALID")?
                .as_nanos()
        )));
    std::fs::create_dir(&temp.0).map_err(|_| "ESCROW_AUDIT_WORKDIR_UNAVAILABLE")?;
    let input = temp.0.join("request.json");
    let output = temp.0.join("raw.json");
    std::fs::write(
        &input,
        json!({"endpoints":endpoints,"script_public_keys":groups.keys().collect::<Vec<_>>()})
            .to_string(),
    )
    .map_err(|_| "ESCROW_AUDIT_WRITE_FAILED")?;
    run_env_free(fetcher.path, &[&input, &output], None, 120)?;
    let raw: Value = serde_json::from_slice(
        &std::fs::read(&output).map_err(|_| "ESCROW_AUDIT_OBSERVATION_MISSING")?,
    )
    .map_err(|_| "ESCROW_AUDIT_OBSERVATION_INVALID")?;
    if raw["schema"] != "KTAPEOUT-RESOLUTION-OBSERVATION-RAW-V1"
        || raw["rpcA"]["endpoint"].as_str() != Some(&endpoints[0])
        || raw["rpcB"]["endpoint"].as_str() != Some(&endpoints[1])
    {
        return Err("ESCROW_AUDIT_OBSERVATION_INVALID".into());
    }
    let mut rows = Vec::new();
    for (script, copies) in groups {
        let equal =
            copies.len() == dirs.len() && copies.values().collect::<BTreeSet<_>>().len() == 1;
        let status = classify(&raw, &script, current.contains(&script), equal)?;
        if !matches!(status, "CURRENT_LIVE" | "INACTIVE_HISTORY") {
            failures.push(json!({"script_public_key":script,"status":status}));
        }
        rows.push(json!({"script_public_key":script,"status":status,"copies":copies.len(),"current":current.contains(&script)}));
    }
    Ok(
        json!({"status":if failures.is_empty(){"VERIFIED"}else{"BLOCKED"},"network":"testnet-10","states":rows,"failures":failures,"current_receipts":receipts.len(),"signing_allowed":false,"broadcast":false}),
    )
}
