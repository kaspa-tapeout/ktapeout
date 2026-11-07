#![cfg(all(feature = "developer-signing", feature = "tn10-network"))]

use kaspa_consensus_core::tx::Transaction;
use kaspa_rpc_core::RpcTransaction;
use ktapeout_cli::tn10_pipeline::{self, Transport};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

fn temp_dir() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "kt-submit-state-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&path).unwrap();
    path
}

fn signed_plan(dir: &Path) -> PathBuf {
    let request = json!({
        "schema":"KTAPEOUT-RESOURCE-PAYLOAD-CANDIDATE-V1",
        "network":"testnet-10",
        "artifact":{"artifact_sha256":"00".repeat(32),"files":[]},
        "funding_utxo":{
            "outpoint":format!("{}:0", "01".repeat(32)),
            "amount":1_000_000_000u64,
            "script_public_key":"0000201cf37eb561f80022293855860f47122025c0929a05f6f08c503ed7f2325cafd5ac",
            "block_daa_score":1,
            "covenant_id":null
        },
        "fee_sompi":30_000_000
    });
    let request_path = dir.join("request.json");
    let plan_path = dir.join("signed.json");
    fs::write(&request_path, serde_json::to_vec(&request).unwrap()).unwrap();
    tn10_pipeline::plan(&request_path, &plan_path).unwrap();
    let plan: Value = serde_json::from_slice(&fs::read(&plan_path).unwrap()).unwrap();
    let sig = "928b38f579392ede103f1a15900ae9f3e32688c26e4643284719a041529f1a2831bc6028f6a53aa0a0e03338a10fb033cff0aa6619b798983fe01e5711a2823d01";
    let signed = tn10_pipeline::attach_signature(&plan, sig).unwrap();
    fs::write(&plan_path, serde_json::to_vec(&signed).unwrap()).unwrap();
    plan_path
}

struct TimeoutThenAbsent {
    output: PathBuf,
    saw_prebroadcast_record: bool,
    saw_submit_lock: bool,
    calls: usize,
}

impl Transport for TimeoutThenAbsent {
    fn submit(&mut self, _: &RpcTransaction) -> Result<String, String> {
        self.calls += 1;
        let mut lock_path = self.output.as_os_str().to_os_string();
        lock_path.push(".lock");
        self.saw_submit_lock = Path::new(&lock_path).exists();
        let record: Value = serde_json::from_slice(&fs::read(&self.output).unwrap()).unwrap();
        self.saw_prebroadcast_record = record["status"] == "SUBMISSION_UNKNOWN"
            && record["broadcast"] == "UNKNOWN"
            && record["txid"].as_str().is_some()
            && record["plan_sha256"].as_str().is_some();
        Err("timeout after possible send".into())
    }

    fn read_transaction(&mut self, _: &str) -> Result<Option<Value>, String> {
        Ok(None)
    }
}

#[test]
fn unknown_submission_is_durable_and_same_txid_retry_requires_flag() {
    let dir = temp_dir();
    let signed = signed_plan(&dir);
    let output = dir.join("submission.json");
    let mut transport = TimeoutThenAbsent {
        output: output.clone(),
        saw_prebroadcast_record: false,
        saw_submit_lock: false,
        calls: 0,
    };

    let result = tn10_pipeline::submit_with_transport(&signed, &output, &mut transport);
    assert!(
        transport.saw_prebroadcast_record,
        "unknown record must precede submit; found {:?}",
        fs::read(&output)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
    );
    assert!(result.is_err(), "unknown result is not a successful submit");
    assert!(
        transport.saw_submit_lock,
        "submit lock must cover transport I/O"
    );
    let mut lock_path = output.as_os_str().to_os_string();
    lock_path.push(".lock");
    assert!(
        !Path::new(&lock_path).exists(),
        "submit lock releases on failure"
    );
    let record: Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    assert_eq!(record["status"], "SUBMISSION_UNKNOWN");
    assert_eq!(record["broadcast"], "UNKNOWN");
    assert!(record["txid"].as_str().is_some());
    assert!(record["plan_sha256"].as_str().is_some());
    assert_eq!(record["reconcile"], "REQUIRED_WITH_TWO_NODES_BEFORE_RETRY");
    assert!(record.get("single_node_observation").is_none());
    assert_ne!(record["status"], "SUBMISSION_RETRY_ALLOWED");
    let calls_before_retry = transport.calls;
    assert_eq!(
        tn10_pipeline::submit_with_transport(&signed, &output, &mut transport)
            .unwrap_err()
            .to_string(),
        "TN10_RETRY_SAME_TXID_REQUIRED"
    );
    assert_eq!(transport.calls, calls_before_retry);
    assert_eq!(
        tn10_pipeline::submit_with_transport_retry(&signed, &output, true, &mut transport)
            .unwrap_err()
            .to_string(),
        "TN10_SUBMISSION_UNKNOWN"
    );
    assert_eq!(transport.calls, calls_before_retry + 1);
    assert!(dir.join("submission.json.attempt-1.json").exists());
}

#[test]
fn retry_same_txid_rejects_changed_txid_or_plan_without_side_effects() {
    for field in ["txid", "plan_sha256"] {
        let dir = temp_dir();
        let signed = signed_plan(&dir);
        let output = dir.join("submission.json");
        let mut transport = TimeoutThenAbsent {
            output: output.clone(),
            saw_prebroadcast_record: false,
            saw_submit_lock: false,
            calls: 0,
        };
        assert_eq!(
            tn10_pipeline::submit_with_transport(&signed, &output, &mut transport)
                .unwrap_err()
                .to_string(),
            "TN10_SUBMISSION_UNKNOWN"
        );

        let mut record: Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
        record[field] = json!("ff".repeat(32));
        fs::write(&output, serde_json::to_vec(&record).unwrap()).unwrap();
        let before = fs::read(&output).unwrap();
        let calls_before_retry = transport.calls;
        assert_eq!(
            tn10_pipeline::submit_with_transport_retry(&signed, &output, true, &mut transport)
                .unwrap_err()
                .to_string(),
            "TN10_SUBMISSION_TXID_MISMATCH_RECONCILE"
        );
        assert_eq!(fs::read(&output).unwrap(), before);
        assert!(!dir.join("submission.json.attempt-1.json").exists());
        assert_eq!(transport.calls, calls_before_retry);
    }
}

#[test]
fn submit_refuses_to_overwrite_a_submitted_result() {
    let dir = temp_dir();
    let signed = signed_plan(&dir);
    let output = dir.join("submission.json");
    fs::write(&output, br#"{"status":"SUBMITTED","txid":"preserve"}"#).unwrap();
    let before = fs::read(&output).unwrap();
    let mut unused = TimeoutThenAbsent {
        output: output.clone(),
        saw_prebroadcast_record: false,
        saw_submit_lock: false,
        calls: 0,
    };

    let error = tn10_pipeline::submit_with_transport_retry(&signed, &output, true, &mut unused)
        .unwrap_err()
        .to_string();
    assert_eq!(error, "TN10_SUBMISSION_RESULT_EXISTS");
    assert_eq!(fs::read(output).unwrap(), before);
}

#[test]
fn submit_rejects_an_existing_lock_before_transport() {
    let dir = temp_dir();
    let signed = signed_plan(&dir);
    let output = dir.join("submission.json");
    let mut lock_path = output.as_os_str().to_os_string();
    lock_path.push(".lock");
    fs::write(&lock_path, b"held").unwrap();
    let mut transport = TimeoutThenAbsent {
        output: output.clone(),
        saw_prebroadcast_record: false,
        saw_submit_lock: false,
        calls: 0,
    };

    let error = tn10_pipeline::submit_with_transport(&signed, &output, &mut transport)
        .unwrap_err()
        .to_string();
    assert!(error.starts_with("TN10_SUBMISSION_LOCK_EXISTS:"));
    assert!(error.contains("inspect for an active submit before removing a stale lock"));
    assert_eq!(transport.calls, 0);
    assert!(!output.exists());
}

#[test]
fn plan_contains_its_locally_computed_txid() {
    let dir = temp_dir();
    let signed = signed_plan(&dir);
    let plan: Value = serde_json::from_slice(&fs::read(signed).unwrap()).unwrap();
    let transaction: RpcTransaction = serde_json::from_value(plan["transaction"].clone()).unwrap();
    let expected = Transaction::try_from(transaction).unwrap().id().to_string();
    assert_eq!(plan["txid"], expected);
}

struct MismatchedAcknowledgement {
    output: PathBuf,
    saw_prebroadcast_record: bool,
}

impl Transport for MismatchedAcknowledgement {
    fn submit(&mut self, _: &RpcTransaction) -> Result<String, String> {
        let record: Value = serde_json::from_slice(&fs::read(&self.output).unwrap()).unwrap();
        self.saw_prebroadcast_record = record["status"] == "SUBMISSION_UNKNOWN"
            && record["broadcast"] == "UNKNOWN"
            && record["txid"].as_str().is_some()
            && record["plan_sha256"].as_str().is_some();
        Ok("different-txid".into())
    }

    fn read_transaction(&mut self, _: &str) -> Result<Option<Value>, String> {
        panic!("a mismatched acknowledgement must not be treated as proof of absence")
    }
}

#[test]
fn mismatched_acknowledgement_remains_unknown_and_never_claims_no_broadcast() {
    let dir = temp_dir();
    let signed = signed_plan(&dir);
    let output = dir.join("submission.json");
    let mut transport = MismatchedAcknowledgement {
        output: output.clone(),
        saw_prebroadcast_record: false,
    };
    assert!(tn10_pipeline::submit_with_transport(&signed, &output, &mut transport).is_err());
    assert!(transport.saw_prebroadcast_record);
    let record: Value = serde_json::from_slice(&fs::read(output).unwrap()).unwrap();
    assert_eq!(record["status"], "SUBMISSION_UNKNOWN");
    assert_eq!(record["broadcast"], "UNKNOWN");
    assert!(record["txid"].as_str().is_some());
    assert!(record["plan_sha256"].as_str().is_some());
    assert_eq!(record["reconcile"], "REQUIRED_WITH_TWO_NODES_BEFORE_RETRY");
    assert_ne!(record["status"], "SUBMISSION_RETRY_ALLOWED");
}
