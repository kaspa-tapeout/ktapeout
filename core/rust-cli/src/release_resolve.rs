//! Pure verifier for a live name resolution, ported from `resolveLiveStateBearingApplication` and
//! `resolutionSnapshotFromStateBearingReceipt` in `browser-sdk/shell.ts`. It performs no I/O: the caller supplies the raw
//! `getBlockDagInfo` and `getUtxosByAddresses` answers of two independent nodes (a fetcher outside this binary reads them),
//! and every check, including that both nodes agree, runs here. Captured live
//! resolution vectors are maintained outside this repository.
use crate::release_closure::{canonical_json, sha256};
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;

/// TN10 root of `ktape.official.adapter.registry` 1.0.0.
pub const REGISTRY_ADAPTER_ROOT_TN10: &str =
    "4e5507386557eb92c0cbce76ce0c90f8bd8e265ea9bb3d331a49ad947ce61bb4";
const CARRIER: u64 = 100_000_000;
const MIN_APP_BOND: u64 = 100_000_000;
const MAX_DAA_SKEW: u64 = 8;
const COMPACT_TARGET_DOMAIN: &str = "KTAPEOUT/0.5.0/COMPACT_NAME_TARGET/V1";
const CURRENT_ANCHOR: &str = "STATE_BEARING_SPEND_RECEIPT_PLUS_CURRENT_DUAL_RPC_UTXO";

fn hex64(v: &Value) -> Option<&str> {
    v.as_str().filter(|s| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

fn outpoint(v: &Value) -> bool {
    v.as_str()
        .and_then(|s| s.split_once(':'))
        .is_some_and(|(t, i)| {
            hex64(&json!(t)).is_some() && !i.is_empty() && i.bytes().all(|b| b.is_ascii_digit())
        })
}

/// `liveNumber`: a safe non-negative integer, as a JSON number or a canonical decimal string.
fn live_number(v: &Value, code: &str) -> Result<u64, String> {
    let max = (1u64 << 53) - 1;
    let n = match v {
        Value::Number(n) => n.as_u64(),
        Value::String(s)
            if s == "0"
                || (!s.starts_with('0')
                    && !s.is_empty()
                    && s.bytes().all(|b| b.is_ascii_digit())) =>
        {
            s.parse().ok()
        }
        _ => None,
    };
    n.filter(|n| *n <= max).ok_or_else(|| code.to_string())
}

/// `COMPACT_NAME_TARGET/V1` commitment over the sorted-key tuple.
pub fn target_commitment(tuple: &Value) -> Result<String, String> {
    let keys = [
        "application_id",
        "release_id",
        "deployment_id",
        "artifact_root",
    ];
    let object = tuple
        .as_object()
        .filter(|o| o.len() == keys.len() && keys.iter().all(|k| o.contains_key(*k)));
    let object = object.ok_or("TARGET_TUPLE_FIELDS_INVALID")?;
    for key in ["application_id", "release_id", "artifact_root"] {
        hex64(&object[key]).ok_or_else(|| format!("TARGET_{}_INVALID", key.to_uppercase()))?;
    }
    let deployment = object["deployment_id"]
        .as_str()
        .filter(|d| !d.is_empty() && d.len() <= 256);
    if deployment.is_none_or(|d| {
        d.chars()
            .any(|c| c <= '\u{1f}' || ('\u{7f}'..='\u{9f}').contains(&c))
    }) {
        return Err("TARGET_DEPLOYMENT_ID_INVALID".into());
    }
    Ok(sha256(
        format!("{COMPACT_TARGET_DOMAIN}{}", canonical_json(tuple)?).as_bytes(),
    ))
}

fn check_target_commitment(item: &Value) -> Result<(), String> {
    if item.get("target_commitment").is_none() {
        return Ok(());
    }
    let declared = hex64(&item["target_commitment"]).ok_or("L1_TARGET_COMMITMENT_INVALID")?;
    let tuple = json!({"application_id": item["application_id"], "release_id": item["release_id"],
        "deployment_id": item["deployment_id"], "artifact_root": item["artifact_root"]});
    let expected = target_commitment(&tuple).map_err(|e| {
        if e == "TARGET_DEPLOYMENT_ID_INVALID" {
            "L1_DEPLOYMENT_ID_INVALID".to_string()
        } else {
            "L1_TARGET_TUPLE_INVALID".to_string()
        }
    })?;
    if declared != expected {
        return Err("L1_TARGET_COMMITMENT_MISMATCH".into());
    }
    Ok(())
}

fn certificate(item: &Value) -> Result<&Map<String, Value>, String> {
    let invalid = || "RESOLUTION_RECEIPT_NAMESPACE_CERTIFICATE_INVALID".to_string();
    let c = item["namespace_certificate"]
        .as_object()
        .ok_or_else(invalid)?;
    let ok = c.get("covenant_id").and_then(Value::as_str) == Some(REGISTRY_ADAPTER_ROOT_TN10)
        && hex64(&c["namespace_covenant_id"]).is_some()
        && outpoint(&c["outpoint"])
        && c["amount"].as_u64() == Some(CARRIER)
        && c["address"].as_str().is_some_and(|a| a.len() <= 128)
        && c["script_public_key"].as_str().is_some_and(|s| {
            !s.is_empty()
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        });
    ok.then_some(c).ok_or_else(invalid)
}

/// The receipt-only part (`resolutionSnapshotFromStateBearingReceipt`): returns the application item it selected.
pub fn select_item<'a>(
    receipt: &'a Value,
    application_id: &str,
    release_id: &str,
    artifact_root: &str,
) -> Result<&'a Value, String> {
    if receipt["schema"] != "KTAPEOUT-TN10-OFFICIAL-APPLICATION-RESOLUTION-RECEIPT-V1"
        || receipt["protocol_semver"] != "0.5.0"
        || receipt["network"] != "testnet-10"
        || receipt["status"] != "VERIFIED"
        || receipt["read_only"] != true
        || receipt["signing_allowed"] != false
        || receipt["broadcast"] != false
    {
        return Err("RESOLUTION_RECEIPT_IDENTITY_INVALID".into());
    }
    if receipt["interpretation"]["equivalent_c1_state_bearing_proof"] != true
        || receipt["interpretation"]["official_indexer_used"] != false
    {
        return Err("RESOLUTION_RECEIPT_PROVENANCE_INVALID".into());
    }
    let item = receipt["applications"].as_array().and_then(|apps| {
        apps.iter().find(|a| {
            a["application_id"] == application_id
                && a["release_id"] == release_id
                && a["artifact_root"] == artifact_root
        })
    });
    let item = item.filter(|i| {
        i["verification_level"] == "L1_VERIFIED"
            && i["proof_status"] == "L1_VERIFIED"
            && i["walletless_eligible"] == true
            && i["runnable_eligible"] == false
            && i["historical_pinned_query"] == false
            && i["read_anchor"] == CURRENT_ANCHOR
    });
    let item = item.ok_or("RESOLUTION_RECEIPT_APPLICATION_NOT_ELIGIBLE")?;
    check_target_commitment(item)?;
    let tip = &item["source_tip"];
    let score = tip["virtual_daa_score"].as_str().is_some_and(|s| {
        s == "0" || (!s.starts_with('0') && !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
    });
    if hex64(&tip["hash"]).is_none() || !score {
        return Err("RESOLUTION_RECEIPT_TIP_INVALID".into());
    }
    if item.get("namespace_certificate").is_none() {
        return Err("RESOLUTION_RECEIPT_LINEAGE_UNSUPPORTED".into());
    }
    let expected_covenant = certificate(item)?["namespace_covenant_id"]
        .as_str()
        .unwrap_or_default();
    let spend = &item["spend_receipt"];
    let initial = spend["nonce_before"].is_null();
    let valid_nonce = if initial {
        spend["nonce_after"] == 0
    } else {
        match (
            spend["nonce_before"].as_u64(),
            spend["nonce_after"].as_u64(),
        ) {
            (Some(b), Some(a)) => b < (1 << 53) && a == b + 1,
            _ => false,
        }
    };
    let s = &item["successor"];
    let invalid = || "RESOLUTION_RECEIPT_SUCCESSOR_INVALID".to_string();
    if !valid_nonce
        || s["amount"].as_u64().is_none_or(|a| a < MIN_APP_BOND)
        || s["covenant_id"] != expected_covenant
        || s.get("observed_covenant_id")
            .is_some_and(|c| c != expected_covenant)
    {
        return Err(invalid());
    }
    let index = if initial { 2 } else { 0 };
    let txid = hex64(&spend["txid"]);
    if spend["native_vm"] != true
        || txid.is_none()
        || s["outpoint"] != format!("{}:{index}", txid.unwrap_or_default())
    {
        return Err(invalid());
    }
    Ok(item)
}

fn anchors(dag: &Value) -> Result<(u64, Vec<String>), String> {
    let tips = dag["tipHashes"]
        .as_array()
        .ok_or("L1_TIP_RESPONSE_INVALID")?;
    let mut tips: Vec<String> = tips
        .iter()
        .filter_map(|t| hex64(t).map(String::from))
        .collect();
    tips.sort();
    if tips.is_empty() {
        return Err("L1_TIP_HASHES_INVALID".into());
    }
    Ok((
        live_number(&dag["virtualDaaScore"], "VIRTUAL_DAA_SCORE_INVALID")?,
        tips,
    ))
}

/// `liveEntries`: the UTXOs of one `getUtxosByAddresses` answer, normalised and keyed by outpoint.
fn entries(answer: &Value) -> Result<Vec<Value>, String> {
    let rows = answer["entries"]
        .as_array()
        .filter(|r| r.len() <= 4096)
        .ok_or("L1_UTXO_RESPONSE_INVALID")?;
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for row in rows {
        let (op, utxo) = (&row["outpoint"], &row["utxoEntry"]);
        let txid = hex64(&op["transactionId"]).ok_or("L1_UTXO_ENTRY_INVALID")?;
        let index = op["index"].as_u64().ok_or("L1_UTXO_ENTRY_INVALID")?;
        let amount = live_number(&utxo["amount"], "L1_UTXO_ENTRY_INVALID")?;
        let block_daa = live_number(&utxo["blockDaaScore"], "L1_UTXO_ENTRY_INVALID")?;
        let covenant = match utxo.get("covenantId") {
            None | Some(Value::Null) => None,
            Some(v) => Some(
                hex64(&json!(v.as_str().unwrap_or_default().to_lowercase()))
                    .map(String::from)
                    .ok_or("L1_COVENANT_ID_INVALID")?,
            ),
        };
        let key = format!("{txid}:{index}");
        if !seen.insert(key.clone()) {
            return Err("L1_DUPLICATE_UTXO".into());
        }
        let script = match &utxo["scriptPublicKey"] {
            Value::String(s) => Some(s.as_str()),
            other => other["scriptPublicKey"]
                .as_str()
                .or(other["script"].as_str()),
        };
        let script = script
            .map(|s| s.to_lowercase())
            .map(|s| s.strip_prefix("0x").map(String::from).unwrap_or(s));
        let script = script.filter(|s| {
            (4..=10_002).contains(&s.len())
                && s.len() % 2 == 0
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        });
        let script = script.ok_or("L1_SCRIPT_PUBLIC_KEY_INVALID")?;
        out.push(json!({"outpoint": key, "amount": amount, "block_daa_score": block_daa.to_string(), "covenant_id": covenant, "script_public_key": script}));
    }
    Ok(out)
}

/// The single entry at `wanted` on both nodes, which must be identical.
fn unique_agreed(
    a: &Value,
    b: &Value,
    wanted: &str,
    missing: &str,
    disagree: &str,
) -> Result<Value, String> {
    let pick = |answer: &Value| -> Result<Value, String> {
        let mut hits: Vec<Value> = entries(answer)?
            .into_iter()
            .filter(|e| e["outpoint"] == wanted)
            .collect();
        if hits.len() != 1 {
            return Err(missing.to_string());
        }
        Ok(hits.remove(0))
    };
    let (ea, eb) = (pick(a)?, pick(b)?);
    if canonical_json(&ea)? != canonical_json(&eb)? {
        return Err(disagree.to_string());
    }
    Ok(ea)
}

/// Raw answers of one node: `dag` is `getBlockDagInfo`; `utxos` maps an address to its `getUtxosByAddresses` answer.
pub struct NodeReading<'a> {
    pub dag: &'a Value,
    pub utxos: &'a Value,
}

/// How the receipt's claimed Deed state is tied to the live script. `Recomputed` carries the script public key the pinned
/// helper compiled from the state arguments; `Unproven` accepts the receipt's own assertion and is reported as such.
pub enum StateBinding<'a> {
    Recomputed { script_public_key: &'a str },
    Unproven,
}

/// The 15 Deed state arguments a receipt item carries as `deed_state.state_args`.
pub fn deed_state_args(item: &Value) -> Result<&Vec<Value>, String> {
    item["deed_state"]["state_args"]
        .as_array()
        .filter(|a| a.len() == 15)
        .ok_or_else(|| "L1_DEED_STATE_PREIMAGE_REQUIRED".to_string())
}

fn check_state_binding(
    item: &Value,
    live_script: &str,
    binding: &StateBinding,
) -> Result<&'static str, String> {
    let StateBinding::Recomputed { script_public_key } = binding else {
        return Ok("UNPROVEN_RECEIPT_ASSERTION");
    };
    let state = deed_state_args(item)?;
    let nonce = item["spend_receipt"]["nonce_after"].as_u64();
    let consistent = state[0] == 1
        && state[1].as_u64() == nonce
        && state[5] == item["name_key"]
        && state[7] == item["target_commitment"];
    if !consistent {
        return Err("L1_DEED_STATE_RECEIPT_MISMATCH".into());
    }
    if *script_public_key != live_script
        || item["successor"]["script_public_key"].as_str() != Some(live_script)
    {
        return Err("L1_DEED_STATE_SCRIPT_MISMATCH".into());
    }
    Ok("RECOMPUTED_FROM_STATE")
}

/// `resolveLiveStateBearingApplication`: the receipt's successor (and namespace certificate) is live, identical and
/// unspent on both nodes, whose tips are within `MAX_DAA_SKEW`.
pub fn verify_live_resolution(
    receipt: &Value,
    application_id: &str,
    release_id: &str,
    artifact_root: &str,
    a: &NodeReading,
    b: &NodeReading,
    binding: &StateBinding,
) -> Result<Value, String> {
    let item = select_item(receipt, application_id, release_id, artifact_root)?;
    let s = &item["successor"];
    let address = s["address"]
        .as_str()
        .filter(|a| a.len() <= 128)
        .ok_or("L1_SUCCESSOR_ADDRESS_INVALID")?;
    let (score_a, tips_a) = anchors(a.dag)?;
    let (score_b, tips_b) = anchors(b.dag)?;
    let skew = score_a.abs_diff(score_b);
    if skew > MAX_DAA_SKEW {
        return Err("L1_TIP_SKEW_EXCEEDED".into());
    }
    let wanted = s["outpoint"]
        .as_str()
        .filter(|_| outpoint(&s["outpoint"]))
        .ok_or("L1_SUCCESSOR_OUTPOINT_INVALID")?;
    let covenant = s["covenant_id"]
        .as_str()
        .filter(|c| hex64(&json!(c.to_lowercase())).is_some())
        .ok_or("L1_SUCCESSOR_COVENANT_INVALID")?;
    let amount = s["amount"].as_u64().ok_or("L1_SUCCESSOR_AMOUNT_INVALID")?;
    let observed_covenant = match s.get("observed_covenant_id") {
        None => covenant,
        Some(v) => v
            .as_str()
            .filter(|c| hex64(&json!(c.to_lowercase())).is_some())
            .ok_or("L1_SUCCESSOR_OBSERVED_COVENANT_INVALID")?,
    };
    let answer = |node: &NodeReading, addr: &str| {
        node.utxos
            .get(addr)
            .cloned()
            .ok_or_else(|| "L1_UTXO_RESPONSE_INVALID".to_string())
    };
    let live = unique_agreed(
        &answer(a, address)?,
        &answer(b, address)?,
        wanted,
        "L1_SUCCESSOR_NOT_UNIQUELY_LIVE",
        "L1_SUCCESSOR_OBSERVATIONS_DISAGREE",
    )?;
    let expected_script = s["script_public_key"]
        .as_str()
        .map(|x| x.to_lowercase())
        .map(|x| x.strip_prefix("0x").map(String::from).unwrap_or(x));
    if expected_script.as_ref().is_some_and(|x| {
        x.is_empty()
            || !x
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }) {
        return Err("L1_SUCCESSOR_SCRIPT_PUBLIC_KEY_INVALID".into());
    }
    let binding_ok = live["covenant_id"] == observed_covenant.to_lowercase()
        && live["amount"].as_u64() == Some(amount)
        && expected_script
            .as_ref()
            .is_none_or(|x| live["script_public_key"].as_str() == Some(x));
    if !binding_ok {
        return Err("L1_SUCCESSOR_BINDING_INVALID".into());
    }
    let state_binding = check_state_binding(
        item,
        live["script_public_key"].as_str().unwrap_or_default(),
        binding,
    )?;
    let cert = certificate(item)?;
    let cert_address = cert["address"].as_str().unwrap_or_default();
    let cert_outpoint = cert["outpoint"].as_str().unwrap_or_default();
    let live_cert = unique_agreed(
        &answer(a, cert_address)?,
        &answer(b, cert_address)?,
        cert_outpoint,
        "L1_NAMESPACE_CERTIFICATE_NOT_UNIQUELY_LIVE",
        "L1_NAMESPACE_CERTIFICATE_OBSERVATIONS_DISAGREE",
    )?;
    if live_cert["covenant_id"] != REGISTRY_ADAPTER_ROOT_TN10
        || live_cert["amount"].as_u64() != Some(CARRIER)
        || live_cert["script_public_key"] != cert["script_public_key"]
    {
        return Err("L1_NAMESPACE_CERTIFICATE_BINDING_INVALID".into());
    }
    Ok(json!({
        "evidence_origin": "L1_VERIFIED_CURRENT_STATE_BEARING",
        "application_id": application_id, "release_id": release_id, "artifact_root": artifact_root,
        "deployment_id": item["deployment_id"], "target_commitment": item["target_commitment"],
        "sources": [{"virtual_daa_score": score_a.to_string(), "tip_hashes": tips_a}, {"virtual_daa_score": score_b.to_string(), "tip_hashes": tips_b}],
        "max_daa_skew": skew, "state_binding": state_binding, "successor": live,
    }))
}

/// Run the pinned read-only fetcher with an empty environment and verify its answers. The fetcher is untrusted: only the
/// bytes it writes are read, and `verify_live_resolution` decides everything.
pub fn resolve_with_fetcher(
    receipt: &Value,
    fetcher: &std::path::Path,
    fetcher_sha256: &str,
    endpoints: &[String],
    timeout_seconds: u64,
    helper: Option<&StateHelper>,
    allow_unproven_state: bool,
) -> Result<Value, String> {
    use std::process::{Command, Stdio};
    let bytes = std::fs::read(fetcher).map_err(|_| "RESOLVE_FETCHER_UNAVAILABLE")?;
    if sha256(&bytes) != fetcher_sha256 {
        return Err("RESOLVE_FETCHER_CHANGED".into());
    }
    let item = receipt["applications"]
        .get(0)
        .ok_or("RESOLUTION_RECEIPT_APPLICATION_NOT_ELIGIBLE")?;
    let id = |k: &str| {
        item[k]
            .as_str()
            .ok_or_else(|| "RESOLUTION_RECEIPT_APPLICATION_NOT_ELIGIBLE".to_string())
    };
    let (application_id, release_id, artifact_root) = (
        id("application_id")?,
        id("release_id")?,
        id("artifact_root")?,
    );
    select_item(receipt, application_id, release_id, artifact_root)?;
    let dir = std::env::temp_dir().join(format!(
        "ktape-resolve-{}-{}",
        std::process::id(),
        &fetcher_sha256[..8]
    ));
    std::fs::create_dir_all(&dir).map_err(|_| "RESOLVE_WORKDIR_UNAVAILABLE")?;
    let (request, output) = (dir.join("request.json"), dir.join("raw.json"));
    let _ = std::fs::remove_file(&output);
    let addresses = [
        item["successor"]["address"].clone(),
        item["namespace_certificate"]["address"].clone(),
    ];
    std::fs::write(
        &request,
        json!({"endpoints": endpoints, "addresses": addresses}).to_string(),
    )
    .map_err(|_| "RESOLVE_WORKDIR_UNAVAILABLE")?;
    let mut child = Command::new(fetcher)
        .arg(&request)
        .arg(&output)
        .env_clear()
        // Windows sockets and DNS fail without these; they carry no secrets.
        .envs(
            ["SystemRoot", "windir"]
                .iter()
                .filter_map(|k| std::env::var(k).ok().map(|v| (*k, v))),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "RESOLVE_FETCHER_SPAWN_FAILED")?;
    let started = std::time::Instant::now();
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|_| "RESOLVE_FETCHER_WAIT_FAILED")?
        {
            break status;
        }
        if started.elapsed().as_secs() > timeout_seconds {
            let _ = child.kill();
            let _ = child.wait();
            return Err("RESOLVE_FETCHER_TIMEOUT".into());
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    if !status.success() {
        return Err("RESOLVE_FETCHER_FAILED".into());
    }
    let raw: Value =
        serde_json::from_slice(&std::fs::read(&output).map_err(|_| "RESOLVE_FETCHER_NO_OUTPUT")?)
            .map_err(|_| "RESOLVE_FETCHER_OUTPUT_INVALID")?;
    let _ = std::fs::remove_dir_all(&dir);
    if raw["schema"] != "KTAPEOUT-RESOLUTION-OBSERVATION-RAW-V1"
        || raw["rpcA"]["endpoint"] == raw["rpcB"]["endpoint"]
    {
        return Err("RESOLVE_FETCHER_OUTPUT_INVALID".into());
    }
    let node = |k: &str| NodeReading {
        dag: &raw[k]["dag"],
        utxos: &raw[k]["utxos"],
    };
    let spk;
    let binding = match (item.get("deed_state").is_some(), helper) {
        (true, Some(helper)) => {
            spk = compute_state_spk(helper, deed_state_args(item)?)?;
            StateBinding::Recomputed {
                script_public_key: &spk,
            }
        }
        (true, None) => return Err("RESOLVE_STATE_HELPER_REQUIRED".into()),
        (false, _) if allow_unproven_state => StateBinding::Unproven,
        (false, _) => return Err("L1_DEED_STATE_PREIMAGE_REQUIRED".into()),
    };
    verify_live_resolution(
        receipt,
        application_id,
        release_id,
        artifact_root,
        &node("rpcA"),
        &node("rpcB"),
        &binding,
    )
}

/// The pinned read-only helper (`registry_deed_state_address`) that compiles the adapter Deed script from its state.
pub struct StateHelper<'a> {
    pub path: &'a std::path::Path,
    pub sha256: &'a str,
}

/// Script public key the helper compiles from the 15 state arguments. The helper is untrusted code with an empty
/// environment; its output is only ever compared with the live script.
pub fn compute_state_spk(helper: &StateHelper, state_args: &[Value]) -> Result<String, String> {
    use std::process::{Command, Stdio};
    let bytes = std::fs::read(helper.path).map_err(|_| "RESOLVE_STATE_HELPER_UNAVAILABLE")?;
    if sha256(&bytes) != helper.sha256 {
        return Err("RESOLVE_STATE_HELPER_CHANGED".into());
    }
    let dir = std::env::temp_dir().join(format!(
        "ktape-state-{}-{}",
        std::process::id(),
        &helper.sha256[..8]
    ));
    std::fs::create_dir_all(&dir).map_err(|_| "RESOLVE_WORKDIR_UNAVAILABLE")?;
    let input = dir.join("state.json");
    std::fs::write(
        &input,
        json!({"network": "testnet-10", "state_args": state_args}).to_string(),
    )
    .map_err(|_| "RESOLVE_WORKDIR_UNAVAILABLE")?;
    let output = Command::new(helper.path)
        .arg(&input)
        .env_clear()
        .envs(
            ["SystemRoot", "windir"]
                .iter()
                .filter_map(|k| std::env::var(k).ok().map(|v| (*k, v))),
        )
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output();
    let _ = std::fs::remove_dir_all(&dir);
    let output = output.map_err(|_| "RESOLVE_STATE_HELPER_SPAWN_FAILED")?;
    // The pinned helper also emits the compiled template (about 17 KiB total).
    // Keep a bounded response while accepting the current helper contract.
    if !output.status.success() || output.stdout.len() > 32 * 1024 {
        return Err("RESOLVE_STATE_HELPER_FAILED".into());
    }
    let value: Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| "RESOLVE_STATE_HELPER_OUTPUT_INVALID")?;
    if value["schema"] != "KTAPEOUT-REGISTRY-DEED-STATE-ADDRESS-V1" {
        return Err("RESOLVE_STATE_HELPER_OUTPUT_INVALID".into());
    }
    value["script_public_key"]
        .as_str()
        .map(String::from)
        .ok_or_else(|| "RESOLVE_STATE_HELPER_OUTPUT_INVALID".into())
}
