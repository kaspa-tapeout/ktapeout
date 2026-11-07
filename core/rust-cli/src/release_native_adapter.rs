//! Host-free name updates using the existing native executor and its sole side-effect journal.
//! Authorization belongs to the coordinator's detached-signature flow, never this adapter.
use crate::release_closure::{canonical_json, sha256};
use crate::{release_adapter_contract as contract, release_execute as executor};
use serde_json::{json, Value};
use std::{
    fs,
    io::Write,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

fn read(path: &Path) -> Result<Value, String> {
    serde_json::from_slice(&read_bytes(path)?).map_err(|_| "RELEASE_ADAPTER_INPUT_INVALID".into())
}

fn read_bytes(path: &Path) -> Result<Vec<u8>, String> {
    let meta = fs::symlink_metadata(path).map_err(|_| "RELEASE_ADAPTER_INPUT_UNAVAILABLE")?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > 16 * 1024 * 1024 {
        return Err("RELEASE_ADAPTER_INPUT_INVALID".into());
    }
    fs::read(path).map_err(|_| "RELEASE_ADAPTER_INPUT_UNAVAILABLE".into())
}

fn persist(path: &Path, value: &Value) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|_| "RELEASE_ADAPTER_JSON_INVALID")?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .ok_or("RELEASE_ADAPTER_WRITE_FAILED")?
        .to_string_lossy();

    // Never expose a partially written final file. A same-directory hard link is an atomic,
    // no-clobber publication: recovery sees either no file or the complete, synced bytes.
    for attempt in 0..8 {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "RELEASE_CLOCK_INVALID")?
            .as_nanos();
        let temporary = parent.join(format!(
            ".{name}.{}.{}.{}.tmp",
            std::process::id(),
            nonce,
            attempt
        ));
        let mut file = match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err("RELEASE_ADAPTER_WRITE_FAILED".into()),
        };
        let write_result = file.write_all(&bytes).and_then(|_| file.sync_all());
        drop(file);
        if write_result.is_err() {
            let _ = fs::remove_file(&temporary);
            return Err("RELEASE_ADAPTER_WRITE_FAILED".into());
        }

        let publish_result = fs::hard_link(&temporary, path);
        let _ = fs::remove_file(&temporary);
        match publish_result {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                if read(path)? != *value {
                    return Err("RELEASE_ADAPTER_CONFIG_CHANGED".into());
                }
                return Ok(());
            }
            Err(_) => return Err("RELEASE_ADAPTER_WRITE_FAILED".into()),
        }
    }
    Err("RELEASE_ADAPTER_WRITE_FAILED".into())
}

fn response(request: &Value, inspection: Value) -> Result<Value, String> {
    let complete = inspection["status"] == "TWO_NODE_READBACK_RECORDED";
    let mut result = json!({
        "schema":"KTAPEOUT-RELEASE-ADAPTER-RESPONSE-V1",
        "status":if complete {"COMPLETE"} else {"UNKNOWN"},
        "intent_sha256":request["intent_sha256"],
        "action_id":request["action"]["id"],
        "fee_sompi":request["action"]["fee_sompi"],
        "next_action":inspection["next_action"],
        "executor_inspection":inspection
    });
    if complete {
        let inspection = &result["executor_inspection"];
        let receipt = &inspection["receipt_artifact"];
        let txid = inspection["txid"]
            .as_str()
            .filter(|value| {
                value.len() == 64
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
            .ok_or("RELEASE_ADAPTER_READBACK_INVALID")?;
        let digest = inspection["evidence_sha256"]["readback.json"]
            .as_str()
            .filter(|hash| {
                hash.len() == 64
                    && hash
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
            .ok_or("RELEASE_ADAPTER_READBACK_INVALID")?;
        let receipt_digest = receipt["sha256"]
            .as_str()
            .filter(|hash| {
                hash.len() == 64
                    && hash
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
            .ok_or("RELEASE_ADAPTER_RECEIPT_INVALID")?;
        let observation_digest = receipt["observation_sha256"]
            .as_str()
            .filter(|hash| {
                hash.len() == 64
                    && hash
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
            .ok_or("RELEASE_ADAPTER_RECEIPT_INVALID")?;
        if inspection["network"] != "testnet-10"
            || inspection["read_only"] != true
            || inspection["journal_assurance"] != "STRUCTURAL_ONLY"
            || inspection["independent_readback_required"] != false
            || receipt["schema"] != "KTAPEOUT-VERIFIED-RECEIPT-ARTIFACT-V1"
            || receipt["status"] != "RECEIPT_VERIFIED_AND_WRITTEN"
            || receipt["path"] != "application-resolution-receipt.json"
            || receipt["state_binding"] != "RECOMPUTED_FROM_STATE"
            || receipt["signing_allowed"] != false
            || receipt["broadcast"] != false
            || inspection["fee_sompi"] != request["action"]["fee_sompi"]
            || request["action"]["fee_sompi"].as_u64().is_none()
        {
            return Err("RELEASE_ADAPTER_READBACK_INVALID".into());
        }
        result["effect_evidence"] = json!({
            "schema":"KTAPEOUT-RELEASE-EFFECT-EVIDENCE-V1",
            "action_id":request["action"]["id"],"outcome":"CONFIRMED",
            "external_effect_id":txid,"artifact_sha256":digest,
            "receipt_sha256":receipt_digest,"observation_sha256":observation_digest
        });
    }
    Ok(result)
}

trait Effects {
    fn inspect(&mut self) -> Result<Value, String>;
    fn reconcile(&mut self) -> Result<Value, String>;
    fn authorize(&mut self) -> Result<(), String>;
    fn sign(&mut self) -> Result<(), String>;
    fn submit(&mut self) -> Result<(), String>;
}

fn effect_phase(request: &Value, backend: &mut impl Effects) -> Result<Value, String> {
    // Reconciliation never signs or submits, including after authorization expiration.
    if request["phase"] == "reconcile" {
        return response(request, backend.reconcile()?);
    }
    let inspection = backend.inspect()?;
    if inspection["status"] != "NOT_ATTEMPTED" {
        return Err("RELEASE_ADAPTER_EFFECT_ALREADY_STARTED_RECONCILE".into());
    }
    backend.authorize()?;
    backend.sign()?;
    backend.submit()?;
    // RPC acknowledgement is followed by read-only proof collection in the same
    // invocation. A failed readback leaves durable submission evidence for resume.
    response(request, backend.reconcile()?)
}

struct Native<'a> {
    config: &'a Path,
    request: &'a Path,
}

fn verify_program(program: &executor::Program) -> Result<(), String> {
    let metadata =
        fs::symlink_metadata(&program.path).map_err(|_| "RELEASE_PROGRAM_UNAVAILABLE")?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > 256 * 1024 * 1024
    {
        return Err("RELEASE_PROGRAM_INVALID".into());
    }
    let bytes = fs::read(&program.path).map_err(|_| "RELEASE_PROGRAM_UNAVAILABLE")?;
    if sha256(&bytes) != program.sha256 {
        return Err("RELEASE_PROGRAM_CHANGED".into());
    }
    Ok(())
}

fn readback_pending(inspection: &Value) -> bool {
    matches!(
        inspection["status"].as_str(),
        Some("SUBMISSION_UNKNOWN" | "READBACK_REQUIRED")
    )
}

fn automatic_readback(config_path: &Path) -> Result<Value, String> {
    let config = executor::load(config_path)?;
    let inspection = executor::inspect(config_path)?;
    if !readback_pending(&inspection) {
        return Ok(inspection);
    }

    let scanner = config
        .readback_scanner
        .as_ref()
        .ok_or("RELEASE_READBACK_SCANNER_NOT_CONFIGURED")?;
    let verifier = config
        .readback_verifier
        .as_ref()
        .ok_or("RELEASE_READBACK_VERIFIER_NOT_CONFIGURED")?;
    verify_program(scanner)?;
    verify_program(verifier)?;

    let node_ids = config
        .node_ids
        .as_ref()
        .ok_or("RELEASE_READBACK_NODE_PAIR_REQUIRED")?;
    let endpoints =
        crate::release_node_registry::dual_endpoints(&node_ids.primary, &node_ids.secondary)?;
    let review = read(&config.prepared.join("review.json"))?;
    let txid = review["unsigned_txid"]
        .as_str()
        .filter(|value| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .ok_or("RELEASE_READBACK_TXID_INVALID")?;
    let anchor_path = config.prepared.join("submission-scan-anchor.json");
    let anchor = if anchor_path.exists() {
        read(&anchor_path)?
    } else {
        json!({"start_hash":review["scan_start_hash"]})
    };
    let start_hash = anchor["start_hash"]
        .as_str()
        .filter(|value| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .ok_or("RELEASE_READBACK_START_HASH_INVALID")?;
    let signed = read(&config.prepared.join("submission-signed.json"))?;
    if signed["txid"] != txid {
        return Err("RELEASE_SIGNED_RECORD_MISMATCH".into());
    }
    let submission_attempt = config.prepared.join("submission-attempt.json");
    let attempt_metadata =
        fs::symlink_metadata(&submission_attempt).map_err(|_| "RELEASE_READBACK_NOT_READY")?;
    if !attempt_metadata.is_file() || attempt_metadata.file_type().is_symlink() {
        return Err("RELEASE_READBACK_NOT_READY".into());
    }

    // A fresh private attempt directory gives the scanner a new output path. A crashed or
    // partial scan is never mistaken for evidence and can be retried without touching signing.
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "RELEASE_CLOCK_INVALID")?
        .as_nanos();
    let attempt = config.prepared.join(format!("readback-scan-{nonce}"));
    fs::create_dir(&attempt).map_err(|_| "RELEASE_READBACK_ATTEMPT_CREATE_FAILED")?;
    let request_path = attempt.join("request.json");
    let scan_path = attempt.join("scan.json");
    persist(
        &request_path,
        &json!({"schema":"KTAPEOUT-TX-SCAN-REQUEST-V1","network":"testnet-10",
            "endpoints":endpoints,"start_hash":start_hash,"txid":txid}),
    )?;
    crate::release_name_update::run_env_free(
        &scanner.path,
        &[&request_path, &scan_path],
        None,
        180,
    )?;
    let scan = read(&scan_path)?;
    if scan["schema"] != "KTAPEOUT-TX-SCAN-RAW-V1"
        || scan["txid"] != txid
        || scan["start_hash"] != start_hash
    {
        return Err("RELEASE_READBACK_SCAN_MISMATCH".into());
    }
    executor::readback(config_path, &scan_path, &verifier.path, &verifier.sha256)?;
    executor::inspect(config_path)
}

fn receipt_previous_document(target: &Value) -> Result<Value, String> {
    let pin = &target["settings"]["native_name_update"]["current_receipt"];
    let project = Path::new(target["project"].as_str().ok_or("RELEASE_TARGET_INVALID")?);
    let path = project.join(pin["path"].as_str().ok_or("RELEASE_TARGET_INVALID")?);
    let bytes = read_bytes(&path)?;
    if sha256(&bytes) != pin["sha256"].as_str().unwrap_or_default() {
        return Err("RELEASE_ADAPTER_RECEIPT_CHANGED".into());
    }
    serde_json::from_slice(&bytes).map_err(|_| "RELEASE_ADAPTER_INPUT_INVALID".into())
}

fn ensure_verified_receipt(
    config_path: &Path,
    target: &Value,
    mut inspection: Value,
) -> Result<Value, String> {
    if inspection["status"] != "TWO_NODE_READBACK_RECORDED" {
        return Ok(inspection);
    }
    let config = executor::load(config_path)?;
    verify_program(&config.fetcher)?;
    verify_program(&config.state_helper)?;
    let review = read(&config.prepared.join("review.json"))?;
    let post_state = read(&config.prepared.join("post-state.json"))?;
    let signed_path = config.prepared.join("submission-signed.json");
    let signed_bytes = read_bytes(&signed_path)?;
    let signed: Value =
        serde_json::from_slice(&signed_bytes).map_err(|_| "RELEASE_ADAPTER_INPUT_INVALID")?;
    let previous = receipt_previous_document(target)?;
    let item = prepared_receipt_item(target)?;
    let successor_spk = review["successor_script_public_key"]
        .as_str()
        .ok_or("RELEASE_READBACK_INVALID")?;
    let certificate_spk = item["namespace_certificate"]["script_public_key"]
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or("RELEASE_ADAPTER_RECEIPT_INVALID")?;

    // Preserve the first live observation. Recovery re-runs the strict receipt builder over
    // these exact bytes, so it cannot silently replace a proven receipt with a later snapshot.
    let raw_path = config.prepared.join("receipt-observation.json");
    let raw = if raw_path.exists() {
        read(&raw_path)?
    } else {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "RELEASE_CLOCK_INVALID")?
            .as_nanos();
        let attempt = config.prepared.join(format!("receipt-observation-{nonce}"));
        fs::create_dir(&attempt).map_err(|_| "RELEASE_READBACK_ATTEMPT_CREATE_FAILED")?;
        let request_path = attempt.join("request.json");
        let output_path = attempt.join("observation.json");
        persist(
            &request_path,
            &json!({"endpoints":config.endpoints,"script_public_keys":[successor_spk,certificate_spk]}),
        )?;
        crate::release_name_update::run_env_free(
            &config.fetcher.path,
            &[&request_path, &output_path],
            None,
            120,
        )?;
        let observation = read(&output_path)?;
        if observation["schema"] != "KTAPEOUT-RESOLUTION-OBSERVATION-RAW-V1"
            || observation["rpcA"]["endpoint"].as_str()
                != config.endpoints.first().map(String::as_str)
            || observation["rpcB"]["endpoint"].as_str()
                != config.endpoints.get(1).map(String::as_str)
        {
            return Err("RELEASE_RECEIPT_OBSERVATION_INVALID".into());
        }
        persist(&raw_path, &observation)?;
        observation
    };
    if raw["schema"] != "KTAPEOUT-RESOLUTION-OBSERVATION-RAW-V1"
        || raw["rpcA"]["endpoint"].as_str() != config.endpoints.first().map(String::as_str)
        || raw["rpcB"]["endpoint"].as_str() != config.endpoints.get(1).map(String::as_str)
    {
        return Err("RELEASE_RECEIPT_OBSERVATION_INVALID".into());
    }

    let receipt_path = config.prepared.join("application-resolution-receipt.json");
    let previous_receipt = if receipt_path.exists() {
        Some(read(&receipt_path)?)
    } else {
        None
    };
    let generated_at = previous_receipt
        .as_ref()
        .and_then(|receipt| receipt["generated_at_unix"].as_u64())
        .unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        });
    let receipt = crate::release_name_update::build_receipt(
        &previous,
        &review,
        &post_state,
        &signed,
        &signed_bytes,
        &raw,
        &crate::release_resolve::StateHelper {
            path: &config.state_helper.path,
            sha256: &config.state_helper.sha256,
        },
        generated_at,
    )?;
    if let Some(previous_receipt) = previous_receipt {
        if previous_receipt != receipt {
            return Err("RELEASE_RECEIPT_ARTIFACT_CHANGED".into());
        }
    } else {
        persist(&receipt_path, &receipt)?;
    }
    let receipt_bytes = read_bytes(&receipt_path)?;
    let stored: Value =
        serde_json::from_slice(&receipt_bytes).map_err(|_| "RELEASE_RECEIPT_ARTIFACT_INVALID")?;
    if stored != receipt {
        return Err("RELEASE_RECEIPT_ARTIFACT_CHANGED".into());
    }
    inspection["receipt_artifact"] = json!({
        "schema":"KTAPEOUT-VERIFIED-RECEIPT-ARTIFACT-V1",
        "status":"RECEIPT_VERIFIED_AND_WRITTEN",
        "path":"application-resolution-receipt.json",
        "sha256":sha256(&receipt_bytes),
        "observation_sha256":sha256(&read_bytes(&raw_path)?),
        "state_binding":"RECOMPUTED_FROM_STATE",
        "signing_allowed":false,
        "broadcast":false
    });
    Ok(inspection)
}

impl Effects for Native<'_> {
    fn inspect(&mut self) -> Result<Value, String> {
        executor::inspect(self.config)
    }
    fn reconcile(&mut self) -> Result<Value, String> {
        let inspection = automatic_readback(self.config)?;
        let request = read(self.request)?;
        ensure_verified_receipt(self.config, &request["target"], inspection)
    }
    fn authorize(&mut self) -> Result<(), String> {
        executor::authorize_from_workflow(self.config, self.request).map(|_| ())
    }
    fn sign(&mut self) -> Result<(), String> {
        executor::sign(self.config).map(|_| ())
    }
    fn submit(&mut self) -> Result<(), String> {
        executor::submit(self.config).map(|_| ())
    }
}

fn workflow_plan(
    target: &Value,
    config_path: &Path,
    config: &executor::Config,
) -> Result<Value, String> {
    let review = read(&config.prepared.join("review.json"))?;
    let native_request = read(&config.prepared.join("request.json"))?;
    let plan = read(&config.prepared.join("plan.json"))?;
    let execution = executor::check(config_path)?;
    crate::release_name_update::workflow_plan_from_prepared(
        target,
        &review,
        &native_request,
        &plan,
        execution["authorization_template"]["execution_sha256"]
            .as_str()
            .ok_or("RELEASE_ADAPTER_EXECUTION_DIGEST_MISSING")?,
        target["scope"]["name_controller_public_key"]
            .as_str()
            .ok_or("RELEASE_TARGET_INVALID")?,
    )
}

fn prepared_receipt_item(target: &Value) -> Result<Value, String> {
    let settings = &target["settings"]["native_name_update"];
    let receipt_pin = &settings["current_receipt"];
    let project = Path::new(target["project"].as_str().ok_or("RELEASE_TARGET_INVALID")?);
    let receipt_path = project.join(
        receipt_pin["path"]
            .as_str()
            .ok_or("RELEASE_TARGET_INVALID")?,
    );
    let bytes = read_bytes(&receipt_path)?;
    if sha256(&bytes) != receipt_pin["sha256"].as_str().unwrap_or_default() {
        return Err("RELEASE_ADAPTER_RECEIPT_CHANGED".into());
    }
    let receipt: Value =
        serde_json::from_slice(&bytes).map_err(|_| "RELEASE_ADAPTER_INPUT_INVALID")?;
    let uri = target["scope"]["application_uri"]
        .as_str()
        .ok_or("RELEASE_TARGET_INVALID")?;
    let short = uri
        .strip_prefix("ktape://testnet-10/app/")
        .ok_or("RELEASE_TARGET_INVALID")?;
    let matches_uri = |item: &&Value| {
        item["application_uri"]
            .as_str()
            .is_some_and(|name| name == uri || name == short)
    };
    let canonical_item = |item: &Value| -> Value {
        let mut item = item.clone();
        item["application_uri"] = json!(uri);
        item
    };
    let items = match (receipt.get("items"), receipt.get("applications")) {
        (Some(items), None) => items.as_array().ok_or("RELEASE_ADAPTER_RECEIPT_INVALID")?,
        (None, Some(applications)) => {
            if receipt["schema"] != "KTAPEOUT-TN10-OFFICIAL-APPLICATION-RESOLUTION-RECEIPT-V1"
                || receipt["network"] != "testnet-10"
            {
                return Err("RELEASE_ADAPTER_RECEIPT_INVALID".into());
            }
            applications
                .as_array()
                .ok_or("RELEASE_ADAPTER_RECEIPT_INVALID")?
        }
        (None, None) => {
            return if matches_uri(&&receipt) {
                Ok(canonical_item(&receipt))
            } else {
                Err("RELEASE_ADAPTER_RECEIPT_AMBIGUOUS".into())
            };
        }
        _ => return Err("RELEASE_ADAPTER_RECEIPT_INVALID".into()),
    };
    let matching: Vec<_> = items.iter().filter(matches_uri).collect();
    if matching.len() != 1 {
        return Err("RELEASE_ADAPTER_RECEIPT_AMBIGUOUS".into());
    }
    Ok(canonical_item(matching[0]))
}

/// Validate before creating files or invoking helpers. The same executable serves every
/// admitted name-controller target; publisher permissions and Host deployment are separate.
pub fn run(request_path: &Path) -> Result<Value, String> {
    let request = read(request_path)?;
    contract::validate_adapter_request(&request)?;
    if request["phase"] == "authorize" {
        return Err("RELEASE_COORDINATOR_DETACHED_AUTHORIZATION_REQUIRED".into());
    }
    let target = &request["target"];
    crate::release_candidate_binding::check_value(target)?;
    let work = Path::new(
        request["workdir"]
            .as_str()
            .ok_or("RELEASE_ADAPTER_WORKDIR_INVALID")?,
    );
    let config_value = executor::config_from_host_free_target(target, work)?;
    // Verify frozen source bytes before creating the operation directory or writing its config.
    let prepared_item = if request["phase"] == "prepare" {
        Some(prepared_receipt_item(target)?)
    } else {
        None
    };
    let config_path = work.join("native-name-update-config.json");
    if request["phase"] == "prepare" {
        fs::create_dir_all(work).map_err(|_| "RELEASE_ADAPTER_WRITE_FAILED")?;
        persist(&config_path, &config_value)?;
    } else if read(&config_path)? != config_value {
        return Err("RELEASE_ADAPTER_CONFIG_CHANGED".into());
    }
    let config = executor::load(&config_path)?;
    if request["phase"] != "prepare"
        && workflow_plan(target, &config_path, &config)? != request["plan"]
    {
        return Err("RELEASE_ADAPTER_PREPARED_PLAN_CHANGED".into());
    }
    match request["phase"].as_str() {
        Some("prepare") => {
            let settings = &target["settings"]["native_name_update"];
            let item = prepared_item
                .as_ref()
                .ok_or("RELEASE_ADAPTER_RECEIPT_UNAVAILABLE")?;
            let owner = target["scope"]["name_controller_public_key"]
                .as_str()
                .ok_or("RELEASE_TARGET_INVALID")?;
            crate::release_name_update::prepare(&crate::release_name_update::Inputs {
                item,
                new_target: &settings["new_target"],
                owner_xonly: owner,
                target_authority_xonly: settings["target_authority_xonly"]
                    .as_str()
                    .ok_or("RELEASE_TARGET_INVALID")?,
                fetcher: crate::release_name_update::Pinned {
                    path: &config.fetcher.path,
                    sha256: &config.fetcher.sha256,
                },
                planner: crate::release_name_update::Pinned {
                    path: &config.planner.path,
                    sha256: &config.planner.sha256,
                },
                state_helper: &crate::release_resolve::StateHelper {
                    path: &config.state_helper.path,
                    sha256: &config.state_helper.sha256,
                },
                endpoints: &config.endpoints,
                fee_ceiling_sompi: target["max_fee_sompi"]
                    .as_u64()
                    .ok_or("RELEASE_TARGET_INVALID")?,
                output: &config.prepared,
            })?;
            let workflow_plan = workflow_plan(target, &config_path, &config)?;
            Ok(json!({"schema":"KTAPEOUT-RELEASE-ADAPTER-RESPONSE-V1","plan":workflow_plan}))
        }
        Some("preflight") => {
            executor::preflight(&config_path)?;
            // Native preflight checks live inputs; a pinned submitter is the admitted transport,
            // not evidence that a transaction has been accepted or that a wallet is unlocked.
            let submitter =
                fs::read(&config.submitter.path).map_err(|_| "RELEASE_PROGRAM_UNAVAILABLE")?;
            if sha256(&submitter) != config.submitter.sha256 {
                return Err("RELEASE_PROGRAM_CHANGED".into());
            }
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| "RELEASE_CLOCK_INVALID")?
                .as_secs();
            let until = now.saturating_add(60);
            let evidence = json!({"id":"chain.broadcast","status":"AVAILABLE","observed_at":now,"valid_until":until});
            Ok(
                json!({"schema":"KTAPEOUT-RELEASE-ADAPTER-RESPONSE-V1","status":"PASS",
                "capabilities":{"schema":"KTAPEOUT-RELEASE-CAPABILITY-REPORT-V1",
                    "intent_sha256":request["intent_sha256"],"adapter_sha256":target["adapter"]["sha256"],
                    "observed_at":now,"items":[{"id":"chain.broadcast","status":"AVAILABLE",
                        "valid_until":until,"evidence_sha256":sha256(canonical_json(&evidence)?.as_bytes())}]}}),
            )
        }
        Some("execute" | "reconcile") => {
            if request["action"]["kind"] != "name-target-update"
                || request["action"]["id"] != "chain-target-update"
            {
                return Err("RELEASE_ADAPTER_ACTION_UNSUPPORTED".into());
            }
            effect_phase(
                &request,
                &mut Native {
                    config: &config_path,
                    request: request_path,
                },
            )
        }
        _ => Err("RELEASE_ADAPTER_PHASE_UNSUPPORTED".into()),
    }
}
