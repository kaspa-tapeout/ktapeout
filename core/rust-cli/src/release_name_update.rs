//! Publisher line, prepare step of a name target update (`CHANGE_OWNER_TARGET`): read the live Deed and the controller's
//! funding from two nodes, build the unsigned request, have the pinned native planner produce the unsigned transaction, and
//! cross-check the planner's successor script against an independent recompute of the post-update state. Writes files only
//! into the given directory and returns a review summary. It never signs, broadcasts or reads a key: signing stays with the
//! owner's signer, behind the escrow gate (`ktape release escrow-check`) and the scoped authorization.
// The test module sits beside plan construction while receipt helpers follow it below.
#![allow(clippy::items_after_test_module)]

use crate::release_closure::{canonical_json, sha256};
use crate::release_resolve::{compute_state_spk, deed_state_args, target_commitment, StateHelper};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const MIN_FEE_SOMPI: u64 = 2_000_000;
const FEE_RATE_SOMPI_PER_MASS: u64 = 110;
const FUNDING_FLOOR_SOMPI: u64 = 230_000_000;
const OWNER_INPUT_SCHEMA: &str = "KTAPEOUT-REGISTRY-ADAPTER-APP-OWNER-INPUT-V1";
const OWNER_UNSIGNED_SCHEMA: &str = "KTAPEOUT-REGISTRY-ADAPTER-APP-OWNER-UNSIGNED-INPUT-V1";
const REQUEST_SCHEMA: &str = "KTAPEOUT-REGISTRY-ADAPTER-LIFECYCLE-OPERATION-INPUT-V1";

/// A pinned local program: refused unless its SHA-256 is the expected one.
pub struct Pinned<'a> {
    pub path: &'a Path,
    pub sha256: &'a str,
}

pub struct Inputs<'a> {
    /// Receipt item of the current binding; must carry `deed_state`.
    pub item: &'a Value,
    /// New target tuple `{application_id, release_id, deployment_id, artifact_root}`.
    pub new_target: &'a Value,
    pub owner_xonly: &'a str,
    pub target_authority_xonly: &'a str,
    pub fetcher: Pinned<'a>,
    pub planner: Pinned<'a>,
    pub state_helper: &'a StateHelper<'a>,
    pub endpoints: &'a [String],
    pub fee_ceiling_sompi: u64,
    pub output: &'a Path,
}

fn hex32(v: &Value) -> bool {
    v.as_str().is_some_and(|s| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

pub(crate) fn pinned_bytes(p: &Pinned) -> Result<(), String> {
    let bytes = std::fs::read(p.path).map_err(|_| "NAME_UPDATE_PROGRAM_UNAVAILABLE")?;
    if sha256(&bytes) != p.sha256 {
        return Err("NAME_UPDATE_PROGRAM_CHANGED".into());
    }
    Ok(())
}

pub(crate) fn run_env_free(
    program: &Path,
    args: &[&Path],
    stdin: Option<&str>,
    timeout: u64,
) -> Result<Vec<u8>, String> {
    let mut command = Command::new(program);
    command
        .args(args)
        .env_clear()
        .envs(
            ["SystemRoot", "windir"]
                .iter()
                .filter_map(|k| std::env::var(k).ok().map(|v| (*k, v))),
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
    let mut child = command.spawn().map_err(|_| "NAME_UPDATE_SPAWN_FAILED")?;
    if let (Some(text), Some(mut pipe)) = (stdin, child.stdin.take()) {
        use std::io::Write;
        pipe.write_all(text.as_bytes())
            .map_err(|_| "NAME_UPDATE_SPAWN_FAILED")?;
    }
    let started = Instant::now();
    let mut stdout = child.stdout.take().ok_or("NAME_UPDATE_SPAWN_FAILED")?;
    let reader = std::thread::spawn(move || {
        use std::io::Read;
        let mut out = Vec::new();
        let _ = stdout.by_ref().take(8 * 1024 * 1024).read_to_end(&mut out);
        out
    });
    loop {
        if let Some(status) = child.try_wait().map_err(|_| "NAME_UPDATE_WAIT_FAILED")? {
            let out = reader.join().map_err(|_| "NAME_UPDATE_WAIT_FAILED")?;
            return if status.success() {
                Ok(out)
            } else {
                Err("NAME_UPDATE_PROGRAM_FAILED".into())
            };
        }
        if started.elapsed() > Duration::from_secs(timeout) {
            let _ = child.kill();
            let _ = child.wait();
            return Err("NAME_UPDATE_PROGRAM_TIMEOUT".into());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Entries by outpoint at `key` that both nodes report identically.
pub(crate) fn agreed_entries(raw: &Value, key: &str) -> Result<BTreeMap<String, Value>, String> {
    let read = |node: &str| -> Result<BTreeMap<String, Value>, String> {
        let rows = raw[node]["utxos"][key]["entries"]
            .as_array()
            .ok_or("NAME_UPDATE_OBSERVATION_INVALID")?;
        let mut entries = BTreeMap::new();
        for row in rows {
            let txid = row["outpoint"]["transactionId"]
                .as_str()
                .filter(|txid| hex32(&json!(txid)))
                .ok_or("NAME_UPDATE_OBSERVATION_INVALID")?;
            let index = row["outpoint"]["index"]
                .as_u64()
                .filter(|index| *index <= u32::MAX as u64)
                .ok_or("NAME_UPDATE_OBSERVATION_INVALID")?;
            let entry = row["utxoEntry"]
                .as_object()
                .ok_or("NAME_UPDATE_OBSERVATION_INVALID")?;
            if entries
                .insert(format!("{txid}:{index}"), Value::Object(entry.clone()))
                .is_some()
            {
                return Err("NAME_UPDATE_OBSERVATION_INVALID".into());
            }
        }
        Ok(entries)
    };
    let (a, b) = (read("rpcA")?, read("rpcB")?);
    Ok(a.into_iter().filter(|(k, v)| b.get(k) == Some(v)).collect())
}

fn check_observation_endpoints(raw: &Value, endpoints: &[String]) -> Result<(), String> {
    if endpoints.len() != 2
        || endpoints[0] == endpoints[1]
        || raw["schema"] != "KTAPEOUT-RESOLUTION-OBSERVATION-RAW-V1"
        || raw["rpcA"]["endpoint"].as_str() != Some(endpoints[0].as_str())
        || raw["rpcB"]["endpoint"].as_str() != Some(endpoints[1].as_str())
    {
        return Err("NAME_UPDATE_OBSERVATION_INVALID".into());
    }
    Ok(())
}

pub(crate) fn native_utxo(outpoint: &str, entry: &Value) -> Value {
    json!({"outpoint": outpoint, "amount": entry["amount"], "script_public_key": entry["scriptPublicKey"],
        "block_daa_score": entry["blockDaaScore"], "covenant_id": entry.get("covenantId").cloned().unwrap_or(Value::Null)})
}

pub(crate) fn plan(planner: &Pinned, request: &Value) -> Result<Value, String> {
    let input = json!({"action": "profile_state_transition", "request": request}).to_string();
    let out = run_env_free(
        planner.path,
        &[Path::new("--transition-plan")],
        Some(&input),
        90,
    )?;
    serde_json::from_slice(&out).map_err(|_| "NAME_UPDATE_PLAN_INVALID".to_string())
}

/// The review summary also lists what must happen before signing.
pub fn prepare(inputs: &Inputs) -> Result<Value, String> {
    let item = inputs.item;
    if inputs.endpoints.len() != 2 {
        return Err("NAME_UPDATE_TWO_ENDPOINTS_REQUIRED".into());
    }
    if !hex32(&inputs.owner_xonly.into()) || !hex32(&inputs.target_authority_xonly.into()) {
        return Err("NAME_UPDATE_KEY_INVALID".into());
    }
    let state = deed_state_args(item)?.clone();
    let namespace_covenant = item["namespace_certificate"]["namespace_covenant_id"]
        .as_str()
        .filter(|c| hex32(&json!(c)))
        .ok_or("NAME_UPDATE_NAMESPACE_MISSING")?;
    let current_spk = item["successor"]["script_public_key"]
        .as_str()
        .ok_or("NAME_UPDATE_RECEIPT_INVALID")?;
    let current_outpoint = item["successor"]["outpoint"]
        .as_str()
        .ok_or("NAME_UPDATE_RECEIPT_INVALID")?;

    // The receipt's state must be the live Deed's state before anything is built on it.
    if compute_state_spk(inputs.state_helper, &state)? != current_spk {
        return Err("NAME_UPDATE_CURRENT_STATE_NOT_THE_LIVE_SCRIPT".into());
    }
    let new_tuple = inputs
        .new_target
        .as_object()
        .ok_or("NAME_UPDATE_TARGET_INVALID")?;
    if new_tuple.get("application_id") != item.get("application_id") {
        return Err("NAME_UPDATE_APPLICATION_MUST_NOT_CHANGE".into());
    }
    let new_commitment = target_commitment(inputs.new_target)?;
    if new_commitment == state[7].as_str().unwrap_or_default() {
        return Err("NAME_UPDATE_TARGET_UNCHANGED".into());
    }

    // Read the Deed and the controller's funding on two nodes.
    pinned_bytes(&inputs.fetcher)?;
    pinned_bytes(&inputs.planner)?;
    std::fs::create_dir_all(inputs.output).map_err(|_| "NAME_UPDATE_OUTPUT_UNAVAILABLE")?;
    let wallet_spk = format!("000020{}ac", inputs.owner_xonly);
    let request_file = inputs.output.join("observe-request.json");
    let raw_file = inputs.output.join("observation.json");
    std::fs::write(
        &request_file,
        json!({"endpoints": inputs.endpoints, "script_public_keys": [current_spk, wallet_spk]})
            .to_string(),
    )
    .map_err(|_| "NAME_UPDATE_OUTPUT_UNAVAILABLE")?;
    let _ = std::fs::remove_file(&raw_file);
    run_env_free(inputs.fetcher.path, &[&request_file, &raw_file], None, 120)?;
    let raw: Value = serde_json::from_slice(
        &std::fs::read(&raw_file).map_err(|_| "NAME_UPDATE_OBSERVATION_MISSING")?,
    )
    .map_err(|_| "NAME_UPDATE_OBSERVATION_INVALID")?;
    check_observation_endpoints(&raw, inputs.endpoints)?;
    let deed_entries = agreed_entries(&raw, current_spk)?;
    let deed_entry = deed_entries
        .get(current_outpoint)
        .ok_or("NAME_UPDATE_DEED_NOT_UNIQUELY_LIVE")?;
    if deed_entry["scriptPublicKey"] != current_spk
        || deed_entry["amount"] != item["successor"]["amount"]
    {
        return Err("NAME_UPDATE_DEED_CHANGED".into());
    }
    let funding = agreed_entries(&raw, &wallet_spk)?;
    let (fee_outpoint, fee_entry) = funding
        .iter()
        .filter(|(_, e)| {
            e["isCoinbase"] != true
                && e.get("covenantId").is_none_or(Value::is_null)
                && e["amount"]
                    .as_u64()
                    .is_some_and(|a| a > FUNDING_FLOOR_SOMPI)
        })
        .min_by_key(|(k, e)| (e["amount"].as_u64().unwrap_or(u64::MAX), (*k).clone()))
        .ok_or("NAME_UPDATE_NO_JOINTLY_OBSERVED_FUNDING")?;

    // Build the request. The post-update state keeps the owner and interval and takes the new target.
    let policy = state[9].clone();
    let mut witness = Map::new();
    for (k, v) in [
        ("schema", json!(OWNER_INPUT_SCHEMA)),
        ("network", json!("testnet-10")),
        ("operation", json!("CHANGE_OWNER_TARGET")),
        ("parent_covenant_id", json!(namespace_covenant)),
        ("state_args", Value::Array(state.clone())),
        ("owner_xonly", json!(inputs.owner_xonly)),
        ("next_owner_xonly", json!(inputs.owner_xonly)),
        (
            "target_authority_xonly",
            json!(inputs.target_authority_xonly),
        ),
        ("next_target_commitment", json!(new_commitment)),
        ("next_resolver_policy_hash", policy.clone()),
    ] {
        witness.insert(k.into(), v);
    }
    let request_with_fee = |fee: u64| {
        json!({"schema": REQUEST_SCHEMA, "network": "testnet-10", "operation": "CHANGE_OWNER_TARGET", "witness_input": witness,
            "transaction_input": {"schema": OWNER_UNSIGNED_SCHEMA, "network": "testnet-10", "child_utxo": native_utxo(current_outpoint, deed_entry),
                "fee_utxo": native_utxo(fee_outpoint, fee_entry), "witness": {}, "fee_change_script_public_key": wallet_spk, "compute_budget": 256, "fee_sompi": fee}})
    };
    let probe = plan(&inputs.planner, &request_with_fee(inputs.fee_ceiling_sompi))?;
    let mass = probe["mass_projection"]["normalized_mass"]
        .as_u64()
        .ok_or("NAME_UPDATE_PLAN_INVALID")?;
    let fee = (mass * FEE_RATE_SOMPI_PER_MASS).max(MIN_FEE_SOMPI);
    if fee > inputs.fee_ceiling_sompi {
        return Err("NAME_UPDATE_FEE_EXCEEDS_CEILING".into());
    }
    let request = request_with_fee(fee);
    let planned = plan(&inputs.planner, &request)?;
    let planned_spk = planned["summary"]["readback_outputs"][0]["script_public_key"]
        .as_str()
        .ok_or("NAME_UPDATE_PLAN_INVALID")?
        .to_string();

    // Independent cross-check: the post-update state, recompiled by the state helper, is the planner's successor script.
    let mut post = state.clone();
    post[1] = json!(state[1].as_u64().ok_or("NAME_UPDATE_STATE_INVALID")? + 1);
    post[7] = json!(new_commitment);
    let recomputed = compute_state_spk(inputs.state_helper, &post)?;
    if recomputed != planned_spk {
        return Err("NAME_UPDATE_PLANNER_AND_STATE_DISAGREE".into());
    }

    let post_file = inputs.output.join("post-state.json");
    let write = |name: &str, value: &Value| -> Result<PathBuf, String> {
        let path = inputs.output.join(name);
        let mut bytes =
            serde_json::to_vec_pretty(value).map_err(|_| "NAME_UPDATE_OUTPUT_UNAVAILABLE")?;
        bytes.push(b'\n');
        std::fs::write(&path, bytes).map_err(|_| "NAME_UPDATE_OUTPUT_UNAVAILABLE")?;
        Ok(path)
    };
    write(
        "post-state.json",
        &json!({"network": "testnet-10", "name": item["application_uri"], "state_args": post}),
    )?;
    write("request.json", &request)?;
    write("plan.json", &planned)?;
    let unsigned_txid = planned["safe_transaction"]["id"]
        .as_str()
        .ok_or("NAME_UPDATE_PLAN_INVALID")?
        .to_string();
    let summary = json!({
        "schema": "KTAPEOUT-NAME-UPDATE-REVIEW-V1", "status": "UNSIGNED_PREPARED", "network": "testnet-10",
        "operation": "CHANGE_OWNER_TARGET", "name": item["application_uri"], "application_id": item["application_id"],
        "old_target_commitment": state[7], "new_target_commitment": new_commitment, "new_target": inputs.new_target,
        "deed_input": current_outpoint, "fee_input": fee_outpoint, "fee_sompi": fee, "fee_ceiling_sompi": inputs.fee_ceiling_sompi,
        "mass": mass, "unsigned_txid": unsigned_txid, "successor_script_public_key": planned_spk,
        "successor_state_recomputed_by_helper": true,
        // Recorded at preparation, i.e. before any submission: the readback scan starts here, not from a hash found afterwards.
        "scan_start_hash": raw["rpcA"]["dag"]["sink"],
        "signer_requests": planned["requests"].as_array().map_or(0, Vec::len),
        "request_digest": sha256(canonical_json(&request)?.as_bytes()),
        "files": {"request": "request.json", "plan": "plan.json", "post_state": post_file.file_name().and_then(|n| n.to_str())},
        "before_signing": [
            format!("ktape release escrow-state post-state.json --expect-spk {planned_spk} --unsigned-txid {unsigned_txid} --name <name> --to <dirA> --to <dirB> ..."),
            "ktape release escrow-check ... (must pass with two distinct copies)",
            "scoped human authorization covering this name, tuple, signer, fee ceiling and validity",
            "after submission: coordinator reconcile runs the pinned TN10 scanner from scan_start_hash and strict readback verifier; then continue receipt and route verification",
        ],
        "signing_allowed": false, "broadcast": false,
    });
    write("review.json", &summary)?;
    Ok(summary)
}

/// Bind an unsigned native name-update review to the coordinator's signed plan format.
/// This is deliberately a pure transform: it neither refreshes observations nor signs,
/// submits, or authorizes the transaction. The coordinator plan commits to every native
/// artifact digest consumed later by `release_execute`.
pub fn workflow_plan_from_prepared(
    target: &Value,
    review: &Value,
    request: &Value,
    native_plan: &Value,
    execution_sha256: &str,
    signer_public_key: &str,
) -> Result<Value, String> {
    let hash_ok = |value: &str| {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    };
    let candidate = &target["application_candidate"];
    let scope = &target["scope"];
    let release_id = candidate["release_id"]
        .as_str()
        .filter(|value| hash_ok(value))
        .ok_or("NAME_UPDATE_WORKFLOW_CANDIDATE_INVALID")?;
    let source_sha256 = candidate["snapshot_digest"]
        .as_str()
        .filter(|value| hash_ok(value))
        .ok_or("NAME_UPDATE_WORKFLOW_CANDIDATE_INVALID")?;
    let artifacts = target["dependencies"]
        .as_array()
        .filter(|items| !items.is_empty())
        .ok_or("NAME_UPDATE_WORKFLOW_ARTIFACTS_REQUIRED")?;
    if !hash_ok(execution_sha256)
        || !hash_ok(signer_public_key)
        || scope["network"] != "testnet-10"
        || scope["application_uri"] != review["name"]
        || scope["name_controller_public_key"] != signer_public_key
        || review["schema"] != "KTAPEOUT-NAME-UPDATE-REVIEW-V1"
        || review["status"] != "UNSIGNED_PREPARED"
        || review["network"] != "testnet-10"
        || request["network"] != "testnet-10"
        || request["operation"] != "CHANGE_OWNER_TARGET"
        || review["operation"] != "CHANGE_OWNER_TARGET"
        || review["new_target"]["release_id"] != release_id
        || candidate["application_uri"] != review["name"]
        || candidate["content_root"] != review["new_target"]["artifact_root"]
        || review["request_digest"] != sha256(canonical_json(request)?.as_bytes())
        || native_plan["safe_transaction"]["id"] != review["unsigned_txid"]
        || !review["successor_state_recomputed_by_helper"]
            .as_bool()
            .unwrap_or(false)
    {
        return Err("NAME_UPDATE_WORKFLOW_INPUT_INVALID".into());
    }
    let application_uri = review["name"]
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or("NAME_UPDATE_WORKFLOW_INPUT_INVALID")?;
    let target_commitment = review["new_target_commitment"]
        .as_str()
        .filter(|value| hash_ok(value))
        .ok_or("NAME_UPDATE_WORKFLOW_INPUT_INVALID")?;
    let fee_sompi = review["fee_sompi"]
        .as_u64()
        .filter(|fee| *fee > 0 && request["transaction_input"]["fee_sompi"] == *fee)
        .ok_or("NAME_UPDATE_WORKFLOW_INPUT_INVALID")?;
    for field in ["owner_xonly", "next_owner_xonly", "target_authority_xonly"] {
        if request["witness_input"][field] != signer_public_key {
            return Err("NAME_UPDATE_WORKFLOW_SIGNER_MISMATCH".into());
        }
    }
    let binding = json!({
        "schema":"KTAPEOUT-NAME-UPDATE-EXECUTION-BINDING-V1",
        "network":"testnet-10",
        "application_uri":application_uri,
        "release_id":release_id,
        "target_commitment":target_commitment,
        "signer_public_key":signer_public_key,
        "review_sha256":sha256(canonical_json(review)?.as_bytes()),
        "request_sha256":sha256(canonical_json(request)?.as_bytes()),
        "plan_sha256":sha256(canonical_json(native_plan)?.as_bytes()),
        "execution_sha256":execution_sha256
    });
    let workflow_plan = json!({
        "schema":"KTAPEOUT-RELEASE-PLAN-V2",
        "scope":scope,
        "release_id":release_id,
        "source_sha256":source_sha256,
        "unchanged":false,
        "actions":[{
            "id":"chain-target-update",
            "kind":"name-target-update",
            "fee_sompi":fee_sompi,
            "effect":true,
            "retry_safe":false,
            "name_update_binding":binding
        }],
        "artifacts":artifacts,
        "summary":{
            "network":"testnet-10",
            "application_uri":application_uri,
            "unsigned_txid":review["unsigned_txid"],
            "target_commitment":target_commitment,
            "signing_allowed":false,
            "broadcast":false
        }
    });
    crate::release_adapter_contract::validate_name_update_binding_values(
        target,
        &workflow_plan,
        &workflow_plan["actions"][0],
    )
    .map_err(|_| "NAME_UPDATE_WORKFLOW_PLAN_INVALID")?;
    Ok(workflow_plan)
}

// Load the three read-only native preparation artifacts, bind them to the frozen target, and
// persist the coordinator plan without replacing an existing plan. Keeping this operation in
// Rust avoids a second adapter-side implementation of the digest and identity checks.

// Keep workflow tests beside plan construction; receipt assembly is the following API section.

/// Build the current resolution receipt of a confirmed name update and verify it before returning: the new Deed output must
/// be live and identical on two nodes, the post-update state must recompile to its script, and the whole receipt must pass
/// the strict live resolution check. `raw` is the fetcher's observation of `[new Deed script, namespace certificate script]`.
fn reviewed_previous_item<'a>(document: &'a Value, review: &Value) -> Result<&'a Value, String> {
    let name = review["name"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or("RECEIPT_REVIEW_INVALID")?;
    let application_id = review["application_id"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or("RECEIPT_REVIEW_INVALID")?;
    let short = name.strip_prefix("ktape://testnet-10/app/");
    let items = document["applications"]
        .as_array()
        .ok_or("RECEIPT_PREVIOUS_INVALID")?;
    let mut matches = items.iter().filter(|item| {
        let uri = item["application_uri"].as_str();
        (uri == Some(name) || short.is_some_and(|s| uri == Some(s)))
            && item["application_id"].as_str() == Some(application_id)
    });
    let item = matches.next().ok_or("RECEIPT_PREVIOUS_IDENTITY_MISMATCH")?;
    if matches.next().is_some() {
        return Err("RECEIPT_PREVIOUS_IDENTITY_AMBIGUOUS".into());
    }
    Ok(item)
}

// Receipt construction keeps its independently validated inputs explicit at this boundary.
#[allow(clippy::too_many_arguments)]
pub fn build_receipt(
    previous_document: &Value,
    review: &Value,
    post_state: &Value,
    signed: &Value,
    signed_file_bytes: &[u8],
    raw: &Value,
    helper: &StateHelper,
    now_unix: u64,
) -> Result<Value, String> {
    let previous = reviewed_previous_item(previous_document, review)?;
    let txid = signed["txid"].as_str().ok_or("RECEIPT_SIGNED_INVALID")?;
    if review["unsigned_txid"] != txid || signed["native_vm_verified"] != true {
        return Err("RECEIPT_SIGNED_DOES_NOT_MATCH_REVIEW".into());
    }
    let output = signed["transaction"]["outputs"]
        .get(0)
        .ok_or("RECEIPT_SIGNED_INVALID")?;
    let spk = output["scriptPublicKey"]
        .as_str()
        .ok_or("RECEIPT_SIGNED_INVALID")?;
    if review["successor_script_public_key"] != spk {
        return Err("RECEIPT_SUCCESSOR_NOT_THE_REVIEWED_ONE".into());
    }
    let state = post_state["state_args"]
        .as_array()
        .ok_or("RECEIPT_STATE_INVALID")?;
    let outpoint = format!("{txid}:0");
    let live = agreed_entries(raw, spk)?
        .remove(&outpoint)
        .ok_or("RECEIPT_DEED_NOT_UNIQUELY_LIVE")?;
    if live["scriptPublicKey"] != spk
        || live["amount"] != output["value"]
        || live["covenantId"] != output["covenant"]["covenantId"]
    {
        return Err("RECEIPT_LIVE_BINDING_CHANGED".into());
    }
    let address = raw["rpcA"]["utxos"][spk]["entries"]
        .as_array()
        .and_then(|rows| {
            rows.iter().find(|r| {
                format!(
                    "{}:{}",
                    r["outpoint"]["transactionId"].as_str().unwrap_or_default(),
                    r["outpoint"]["index"]
                ) == outpoint
            })
        })
        .and_then(|r| r["address"].as_str())
        .ok_or("RECEIPT_ADDRESS_MISSING")?;
    let new = review["new_target"]
        .as_object()
        .ok_or("RECEIPT_REVIEW_INVALID")?;
    let sources: Vec<String> = ["rpcA", "rpcB"]
        .iter()
        .map(|k| {
            raw[*k]["endpoint"]
                .as_str()
                .unwrap_or_default()
                .replace("/wrpc/borsh", "/wrpc/json")
        })
        .collect();
    let anchors: Vec<Value> = ["rpcA", "rpcB"]
        .iter()
        .map(|k| json!({"tip_hashes": raw[*k]["dag"]["tipHashes"].as_array().and_then(|t| t.first()).cloned().unwrap_or(Value::Null),
            "virtual_daa_score": raw[*k]["dag"]["virtualDaaScore"]}))
        .map(|mut a| { a["tip_hashes"] = json!([a["tip_hashes"].clone()]); a })
        .collect();
    let scores: Vec<u64> = ["rpcA", "rpcB"]
        .iter()
        .filter_map(|k| raw[*k]["dag"]["virtualDaaScore"].as_u64())
        .collect();
    let skew = scores.iter().max().unwrap_or(&0) - scores.iter().min().unwrap_or(&0);
    let mut item = previous.clone();
    let object = item.as_object_mut().ok_or("RECEIPT_PREVIOUS_INVALID")?;
    for (k, v) in new {
        object.insert(k.clone(), v.clone());
    }
    object.insert(
        "target_commitment".into(),
        review["new_target_commitment"].clone(),
    );
    object.insert("sources".into(), json!(sources));
    object.insert("observation_anchor".into(), json!({"max_daa_skew": skew, "policy": "PER_SOURCE_TIPS_WITH_BOUNDED_DAA_SKEW", "sources": anchors}));
    object.insert("source_tip".into(), json!({"hash": raw["rpcA"]["dag"]["tipHashes"][0], "virtual_daa_score": scores.first().map(|s| s.to_string())}));
    object.insert("successor".into(), json!({"address": address, "amount": live["amount"], "block_daa_score": live["blockDaaScore"].to_string().trim_matches('"'),
        "covenant_id": live["covenantId"], "outpoint": outpoint, "script_public_key": spk}));
    let nonce_after = state[1].as_u64().ok_or("RECEIPT_STATE_INVALID")?;
    object.insert("spend_receipt".into(), json!({"input_outpoint": review["deed_input"], "native_vm": true, "nonce_before": nonce_after - 1,
        "nonce_after": nonce_after, "receipt_digest": sha256(signed_file_bytes), "txid": txid}));
    object.insert("deed_state".into(), json!({"state_args": state}));
    let mut receipt = json!({"schema": "KTAPEOUT-TN10-OFFICIAL-APPLICATION-RESOLUTION-RECEIPT-V1", "protocol_semver": "0.5.0", "network": "testnet-10",
        "status": "VERIFIED", "read_only": true, "signing_allowed": false, "broadcast": false, "generated_at_unix": now_unix,
        "interpretation": previous_document.get("interpretation").cloned().unwrap_or_else(|| json!({"equivalent_c1_state_bearing_proof": true, "historical_pinned_query": false, "official_indexer_used": false, "runnable_status": "PENDING_SHELL_IMPORT"})),
        "applications": [item]});
    if let Some(registry) = previous_document.get("registry") {
        receipt["registry"] = registry.clone();
    }
    let item_ref = &receipt["applications"][0];
    // The observation is keyed by script; the live resolution check looks entries up by address.
    let mut by_address = raw.clone();
    let certificate_script = previous["namespace_certificate"]["script_public_key"]
        .as_str()
        .unwrap_or_default();
    let certificate_address = previous["namespace_certificate"]["address"]
        .as_str()
        .unwrap_or_default();
    for node_key in ["rpcA", "rpcB"] {
        for (script, address) in [(spk, address), (certificate_script, certificate_address)] {
            let entries = raw[node_key]["utxos"][script].clone();
            by_address[node_key]["utxos"][address] = entries;
        }
    }
    let node = |k: &str| crate::release_resolve::NodeReading {
        dag: &by_address[k]["dag"],
        utxos: &by_address[k]["utxos"],
    };
    let spk_check = compute_state_spk(helper, state)?;
    crate::release_resolve::verify_live_resolution(
        &receipt,
        item_ref["application_id"].as_str().unwrap_or_default(),
        item_ref["release_id"].as_str().unwrap_or_default(),
        item_ref["artifact_root"].as_str().unwrap_or_default(),
        &node("rpcA"),
        &node("rpcB"),
        &crate::release_resolve::StateBinding::Recomputed {
            script_public_key: &spk_check,
        },
    )?;
    Ok(receipt)
}
