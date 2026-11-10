#![cfg(all(feature = "developer-signing", feature = "tn10-network"))]

use kaspa_consensus_core::tx::{
    ScriptPublicKey, Transaction, TransactionId, TransactionOutpoint, UtxoEntry,
};
use kaspa_rpc_core::{RpcAddress, RpcTransaction, RpcUtxosByAddressesEntry};
use ktapeout_050_adapter_workbench::namespace_parent_genesis::transition_command;
use ktapeout_cli::tn10_pipeline::{self, Transport};
use secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
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
    let secp = secp256k1::Secp256k1::new();
    let signing_key = secp256k1::SecretKey::from_slice(&[2u8; 32]).unwrap();
    let keypair = secp256k1::Keypair::from_secret_key(&secp, &signing_key);
    let (xonly_key, _) = keypair.x_only_public_key();
    let request = json!({
        "schema":"KTAPEOUT-RESOURCE-PAYLOAD-CANDIDATE-V1",
        "network":"testnet-10",
        "artifact":{"artifact_sha256":"00".repeat(32),"files":[]},
        "funding_utxo":{
            "outpoint":format!("{}:0", "01".repeat(32)),
            "amount":1_000_000_000u64,
            "script_public_key":format!("000020{}ac", xonly_key),
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
    let message = secp256k1::Message::from_digest_slice(
        &hex::decode(plan["input_sighash_all"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    let signature = secp.sign_schnorr_no_aux_rand(&message, &keypair);
    let sig = format!("{}01", signature);
    let signed = tn10_pipeline::attach_signature(&plan, &sig).unwrap();
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

struct ReadbackTransport(Option<Value>);

impl Transport for ReadbackTransport {
    fn submit(&mut self, _: &RpcTransaction) -> Result<String, String> {
        panic!("readback must never submit")
    }

    fn read_transaction(&mut self, _: &str) -> Result<Option<Value>, String> {
        Ok(self.0.clone())
    }
}

struct NamespaceSubmitTransport {
    readback: Option<Value>,
    submit_result: Option<String>,
    submit_calls: usize,
}

struct LiveInputTransport {
    utxos_by_address: HashMap<String, Value>,
    observation: Value,
}

impl Transport for LiveInputTransport {
    fn submit(&mut self, _: &RpcTransaction) -> Result<String, String> {
        panic!("input freshness verification must never submit")
    }

    fn read_transaction(&mut self, _: &str) -> Result<Option<Value>, String> {
        panic!("input freshness verification must never read transactions")
    }

    fn read_utxos(&mut self, address: &str) -> Result<Value, String> {
        Ok(self
            .utxos_by_address
            .get(address)
            .cloned()
            .unwrap_or_else(|| json!([])))
    }

    fn read_observation(&mut self) -> Result<Value, String> {
        Ok(self.observation.clone())
    }
}

fn live_input(script: &str, amount: u64, tx_byte: u8) -> (String, Value) {
    let script_bytes = hex::decode(script.strip_prefix("0000").unwrap()).unwrap();
    let (version, address_hash) = if script_bytes.len() == 35
        && script_bytes[0] == 0xaa
        && script_bytes[1] == 0x20
        && script_bytes[34] == 0x87
    {
        (8u8, &script_bytes[2..34])
    } else {
        (0u8, &script_bytes[1..33])
    };
    let address = RpcAddress::new(
        "kaspatest".try_into().unwrap(),
        version.try_into().unwrap(),
        address_hash,
    );
    let entry = UtxoEntry::new(
        amount,
        ScriptPublicKey::from_vec(0, script_bytes),
        1_000,
        false,
        None,
    );
    let utxos = serde_json::to_value(vec![RpcUtxosByAddressesEntry {
        address: Some(address.clone()),
        outpoint: TransactionOutpoint::new(TransactionId::from_bytes([tx_byte; 32]), 0).into(),
        utxo_entry: entry.into(),
    }])
    .unwrap();
    let input = json!({
        "outpoint":format!("{}:0", hex::encode([tx_byte; 32])),
        "amount":amount,
        "script_public_key":script,
        "block_daa_score":1_000,
        "covenant_id":null
    });
    (address.to_string(), json!({"utxos":utxos,"input":input}))
}

#[test]
fn namespace_transition_inputs_require_exact_dual_node_live_utxo_readback() {
    let secret = SecretKey::from_slice(&[9; 32]).unwrap();
    let public = hex::encode(
        Keypair::from_secret_key(&Secp256k1::new(), &secret)
            .x_only_public_key()
            .0
            .serialize(),
    );
    let script = format!("000020{public}ac");
    let input = json!({
        "outpoint":format!("{}:0", "ab".repeat(32)),
        "amount":1_200_000_000u64,
        "script_public_key":script,
        "block_daa_score":1_000,
        "covenant_id":null
    });
    let (address, live) = live_input(&script, 1_200_000_000, 0xab);
    let observation = json!({
        "network":"testnet-10",
        "synced":true,
        "utxo_indexed":true,
        "start_hash":"cd".repeat(32)
    });
    let signed = json!({
        "transition_plan":{
            "action":"namespace_parent_genesis",
            "request":{"funding_utxo":input}
        }
    });
    let mut first = LiveInputTransport {
        utxos_by_address: HashMap::from([(address.clone(), live["utxos"].clone())]),
        observation: observation.clone(),
    };
    let mut second = LiveInputTransport {
        utxos_by_address: HashMap::from([(address, live["utxos"].clone())]),
        observation,
    };
    let verified = tn10_pipeline::verify_namespace_transition_inputs_with_transports(
        &signed,
        &mut first,
        &mut second,
    )
    .unwrap();
    assert_eq!(verified["checked_input_count"], 1);
    assert_eq!(
        verified["status"],
        "ALL_INPUTS_UNSPENT_AND_IDENTICAL_ON_BOTH_NODES"
    );

    second.observation["start_hash"] = json!("de".repeat(32));
    let verified = tn10_pipeline::verify_namespace_transition_inputs_with_transports(
        &signed,
        &mut first,
        &mut second,
    )
    .unwrap();
    assert_eq!(verified["checked_input_count"], 1);

    second.utxos_by_address.clear();
    assert_eq!(
        tn10_pipeline::verify_namespace_transition_inputs_with_transports(
            &signed,
            &mut first,
            &mut second,
        )
        .unwrap_err()
        .to_string(),
        "TN10_NAMESPACE_TRANSITION_INPUT_NODES_DISAGREE"
    );
}

impl Transport for NamespaceSubmitTransport {
    fn submit(&mut self, transaction: &RpcTransaction) -> Result<String, String> {
        self.submit_calls += 1;
        let txid = Transaction::try_from(transaction.clone())
            .map_err(|_| "invalid tx".to_string())?
            .id()
            .to_string();
        self.submit_result
            .clone()
            .map(|ack| if ack == "expected" { txid } else { ack })
            .ok_or_else(|| "timeout after possible send".into())
    }

    fn read_transaction(&mut self, _: &str) -> Result<Option<Value>, String> {
        Ok(self.readback.clone())
    }
}

#[test]
fn namespace_issuance_inputs_require_all_three_current_utxos() {
    let claimant = hex::encode(
        Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[8; 32]).unwrap())
            .x_only_public_key()
            .0
            .serialize(),
    );
    let scripts = [
        format!("0000aa20{}87", "11".repeat(32)),
        format!("0000aa20{}87", "22".repeat(32)),
        format!("000020{claimant}ac"),
    ];
    let amounts = [1_000_000_000u64, 100_000_000, 500_000_000];
    let mut inputs = Vec::new();
    let mut utxos_by_address = HashMap::new();
    for (index, (script, amount)) in scripts.iter().zip(amounts).enumerate() {
        let (address, live) = live_input(script, amount, 0xb0 + index as u8);
        inputs.push(live["input"].clone());
        utxos_by_address.insert(address, live["utxos"].clone());
    }
    let signed = json!({
        "transition_plan":{
            "action":"profile_state_transition",
            "request":{
                "operation":"ISSUE_NAMESPACE",
                "parent_utxo":inputs[0],
                "root_gap_utxo":inputs[1],
                "fee_utxo":inputs[2]
            }
        }
    });
    let observation = json!({
        "network":"testnet-10",
        "synced":true,
        "utxo_indexed":true,
        "start_hash":"ef".repeat(32)
    });
    let mut first = LiveInputTransport {
        utxos_by_address: utxos_by_address.clone(),
        observation: observation.clone(),
    };
    let mut second = LiveInputTransport {
        utxos_by_address,
        observation,
    };
    let verified = tn10_pipeline::verify_namespace_transition_inputs_with_transports(
        &signed,
        &mut first,
        &mut second,
    )
    .unwrap();
    assert_eq!(verified["checked_input_count"], 3);

    second.utxos_by_address.clear();
    assert_eq!(
        tn10_pipeline::verify_namespace_transition_inputs_with_transports(
            &signed,
            &mut first,
            &mut second,
        )
        .unwrap_err()
        .to_string(),
        "TN10_NAMESPACE_TRANSITION_INPUT_NODES_DISAGREE"
    );
}

#[test]
fn native_registration_inputs_require_exact_dual_node_live_utxo_readback() {
    let claimant = hex::encode(
        Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[7; 32]).unwrap())
            .x_only_public_key()
            .0
            .serialize(),
    );
    let scripts = [
        format!("0000aa20{}87", "31".repeat(32)),
        format!("0000aa20{}87", "42".repeat(32)),
        format!("000020{claimant}ac"),
    ];
    let amounts = [1_000_000_000u64, 100_000_000, 500_000_000];
    let mut inputs = Vec::new();
    let mut utxos_by_address = HashMap::new();
    for (index, (script, amount)) in scripts.iter().zip(amounts).enumerate() {
        let (address, live) = live_input(script, amount, 0xc0 + index as u8);
        inputs.push(live["input"].clone());
        utxos_by_address.insert(address, live["utxos"].clone());
    }
    let observation = json!({
        "network":"testnet-10",
        "synced":true,
        "utxo_indexed":true,
        "start_hash":"ef".repeat(32)
    });
    let mut first = LiveInputTransport {
        utxos_by_address: utxos_by_address.clone(),
        observation: observation.clone(),
    };
    let mut second = LiveInputTransport {
        utxos_by_address,
        observation,
    };
    let plan = json!({"inputs":inputs});
    let verified = tn10_pipeline::verify_native_registration_inputs_with_transports(
        &plan,
        &mut first,
        &mut second,
    )
    .unwrap();
    assert_eq!(verified["checked_input_count"], 3);
    assert_eq!(
        verified["status"],
        "ALL_INPUTS_UNSPENT_AND_IDENTICAL_ON_BOTH_NODES"
    );

    second.observation["start_hash"] = json!("fa".repeat(32));
    let verified = tn10_pipeline::verify_native_registration_inputs_with_transports(
        &plan,
        &mut first,
        &mut second,
    )
    .unwrap();
    assert_eq!(verified["checked_input_count"], 3);

    second.utxos_by_address.clear();
    assert_eq!(
        tn10_pipeline::verify_native_registration_inputs_with_transports(
            &plan,
            &mut first,
            &mut second,
        )
        .unwrap_err()
        .to_string(),
        "TN10_REGISTRATION_INPUT_NODES_DISAGREE"
    );
}

fn namespace_signed_document(dir: &Path) -> PathBuf {
    let secp = Secp256k1::new();
    let funder_secret = SecretKey::from_slice(&[3; 32]).unwrap();
    let funder = hex::encode(
        Keypair::from_secret_key(&secp, &funder_secret)
            .x_only_public_key()
            .0
            .serialize(),
    );
    let claimant_secret = SecretKey::from_slice(&[2; 32]).unwrap();
    let claimant = hex::encode(
        Keypair::from_secret_key(&secp, &claimant_secret)
            .x_only_public_key()
            .0
            .serialize(),
    );
    let mut frame = vec![0u8; 64];
    frame[0] = 6;
    frame[1..7].copy_from_slice(b"n2test");
    let namespace_hash = Sha256::digest(
        [
            b"KTAPEOUT/0.5.0/NAMESPACE_FRAME/V1\0\x0a".as_slice(),
            &frame,
        ]
        .concat(),
    );
    let change_script = format!("000020{funder}ac");
    let request = json!({
        "schema":"KTAPEOUT-REGISTRY-ADAPTER-NAMESPACE-GENESIS-INPUT-V1",
        "network":"testnet-10",
        "authority_xonly":claimant,
        "namespace_hash":hex::encode(namespace_hash),
        "namespace_frame":hex::encode(frame),
        "authority_commitment":hex::encode(Sha256::digest(hex::decode(&claimant).unwrap())),
        "resolver_policy_hash":"11".repeat(32),
        "registry_root":"22".repeat(32),
        "nonce":0,
        "funding_utxo":{
            "outpoint":format!("{}:0", "33".repeat(32)),
            "amount":1_200_000_000u64,
            "script_public_key":change_script,
            "block_daa_score":1000,
            "covenant_id":null
        },
        "funding_change_script_public_key":change_script,
        "fee_sompi":1_000_000u64,
        "parent_state_sompi":1_000_000_000u64,
        "gap_state_sompi":100_000_000u64,
        "compute_budget":100
    });
    let plan = json!({"action":"namespace_parent_genesis","request":request});
    let signing = transition_command("--transition-plan", &plan).unwrap();
    let signing_request = &signing["requests"][0];
    let digest: [u8; 32] = hex::decode(signing_request["sighash"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let signature = secp.sign_schnorr_no_aux_rand(
        &Message::from_digest(digest),
        &Keypair::from_secret_key(&secp, &funder_secret),
    );
    let packet = json!({
        "native_plan_hash":signing_request["native_plan_hash"],
        "input_index":signing_request["input_index"],
        "signer_public_key":signing_request["signer_public_key"],
        "sighash_type":1,
        "signature":hex::encode(signature.as_ref())
    });
    let mut signed = transition_command(
        "--merge-signatures",
        &json!({"plan":plan,"packets":[packet]}),
    )
    .unwrap();
    let fee_quote = json!({
        "source":"live_dual_node_quote",
        "fee_rate_sompi_per_gram":2,
        "node_rates":[
            {"endpoint":"wss://one.example","feerate":1.5},
            {"endpoint":"wss://two.example","feerate":2.0}
        ],
        "endpoints":["wss://one.example","wss://two.example"],
        "observed_at":"1970-01-01T00:01:40Z"
    });
    signed["authorization"] = tn10_pipeline::create_namespace_transition_authorization(
        &json!({"plan":signed["transition_plan"],"signing":signing}),
        &fee_quote,
        1_300_000_000,
        1_000_000,
        true,
        tn10_pipeline::NamespaceTransitionAuthorizationConfirmation {
            expires_at_unix: 10_000,
            now_unix: 100,
            confirmation: &format!(
                "AUTHORIZE {}",
                signing["requests"][0]["native_plan_hash"].as_str().unwrap()
            ),
        },
    )
    .unwrap();
    let output = dir.join("namespace-signed.json");
    fs::write(&output, serde_json::to_vec(&signed).unwrap()).unwrap();
    output
}

#[test]
fn namespace_transition_retry_performs_dual_readback_before_rebroadcast() {
    let dir = temp_dir();
    let signed = namespace_signed_document(&dir);
    let signed_document: Value = serde_json::from_slice(&fs::read(&signed).unwrap()).unwrap();
    let broadcast_confirmation = format!("BROADCAST {}", signed_document["txid"].as_str().unwrap());
    let state = dir.join("namespace-submission.json");
    let mut initial = NamespaceSubmitTransport {
        readback: None,
        submit_result: None,
        submit_calls: 0,
    };
    let mut unused = NamespaceSubmitTransport {
        readback: None,
        submit_result: None,
        submit_calls: 0,
    };
    assert_eq!(
        tn10_pipeline::submit_namespace_transition_with_transports(
            &signed,
            &state,
            false,
            100,
            &broadcast_confirmation,
            &mut initial,
            &mut unused,
        )
        .unwrap_err()
        .to_string(),
        "TN10_NAMESPACE_TRANSITION_SUBMISSION_UNKNOWN"
    );
    assert_eq!(initial.submit_calls, 1);
    let unknown: Value = serde_json::from_slice(&fs::read(&state).unwrap()).unwrap();
    assert_eq!(unknown["status"], "SUBMISSION_UNKNOWN");
    assert_eq!(unknown["broadcast"], "UNKNOWN");

    let mut first = NamespaceSubmitTransport {
        readback: None,
        submit_result: Some("expected".into()),
        submit_calls: 0,
    };
    let mut second = NamespaceSubmitTransport {
        readback: None,
        submit_result: None,
        submit_calls: 0,
    };
    tn10_pipeline::submit_namespace_transition_with_transports(
        &signed,
        &state,
        true,
        101,
        &broadcast_confirmation,
        &mut first,
        &mut second,
    )
    .unwrap();
    assert_eq!(first.submit_calls, 1);
    let submitted: Value = serde_json::from_slice(&fs::read(&state).unwrap()).unwrap();
    assert_eq!(submitted["status"], "SUBMITTED");
    assert!(dir
        .join("namespace-submission.json.attempt-1.json")
        .exists());
}

#[test]
fn namespace_transition_readback_requires_two_matching_nodes_and_never_submits() {
    let dir = temp_dir();
    let signed_path = signed_plan(&dir);
    let original: Value = serde_json::from_slice(&fs::read(signed_path).unwrap()).unwrap();
    let transaction: RpcTransaction =
        serde_json::from_value(original["transaction"].clone()).unwrap();
    let txid = Transaction::try_from(transaction).unwrap().id().to_string();
    let signed = json!({
        "schema":"KTAPEOUT-TN10-NAMESPACE-PARENT-GENESIS-SIGNED-V1",
        "network":"testnet-10",
        "native_plan_hash":"11".repeat(32),
        "transaction":original["transaction"],
        "txid":txid,
        "native_vm_verified":true,
        "broadcast":false
    });
    let mut absent_a = ReadbackTransport(None);
    let mut absent_b = ReadbackTransport(None);
    let absent = tn10_pipeline::reconcile_namespace_transition_with_transports(
        &signed,
        &mut absent_a,
        &mut absent_b,
    )
    .unwrap();
    assert_eq!(absent["status"], "NOT_FOUND_BOTH");
    assert_eq!(absent["retry_authorized"], false);

    let transaction = signed["transaction"].clone();
    let mut found_a = ReadbackTransport(Some(transaction.clone()));
    let mut found_b = ReadbackTransport(Some(transaction));
    let found = tn10_pipeline::reconcile_namespace_transition_with_transports(
        &signed,
        &mut found_a,
        &mut found_b,
    )
    .unwrap();
    assert_eq!(found["status"], "FOUND_BOTH_MATCH");

    let mut split_a = ReadbackTransport(None);
    let mut split_b = ReadbackTransport(Some(signed["transaction"].clone()));
    assert_eq!(
        tn10_pipeline::reconcile_namespace_transition_with_transports(
            &signed,
            &mut split_a,
            &mut split_b,
        )
        .unwrap_err()
        .to_string(),
        "TN10_NAMESPACE_TRANSITION_DUAL_NODE_DISAGREEMENT"
    );
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

#[test]
fn namespace_transition_authorization_binds_plan_value_fee_quote_and_expiry() {
    let document = json!({
        "plan":{"action":"namespace_parent_genesis","request":{
            "funding_utxo":{"amount":1_200_000_000u64},"fee_sompi":1_000_000u64,
            "parent_state_sompi":1_099_000_000u64,"gap_state_sompi":100_000_000u64
        }},
        "signing":{"requests":[{"native_plan_hash":"ab".repeat(32)}]}
    });
    let quote = json!({
        "source":"live_dual_node_quote",
        "fee_rate_sompi_per_gram":2,
        "node_rates":[
            {"endpoint":"wss://one.example","feerate":1.5},
            {"endpoint":"wss://two.example","feerate":2.0}
        ],
        "endpoints":["wss://one.example","wss://two.example"],
        "observed_at":"1970-01-01T00:16:40Z"
    });
    let authorization = tn10_pipeline::create_namespace_transition_authorization(
        &document,
        &quote,
        1_300_000_000,
        1_000_000,
        true,
        tn10_pipeline::NamespaceTransitionAuthorizationConfirmation {
            expires_at_unix: 2_000,
            now_unix: 1_000,
            confirmation: &format!("AUTHORIZE {}", "ab".repeat(32)),
        },
    )
    .unwrap();
    tn10_pipeline::verify_namespace_transition_authorization(&document, &authorization, 1_100)
        .unwrap();
    assert!(tn10_pipeline::verify_namespace_transition_authorization(
        &document,
        &authorization,
        2_000
    )
    .is_err());
    assert!(tn10_pipeline::create_namespace_transition_authorization(
        &document,
        &quote,
        1_199_999_999,
        1_000_000,
        true,
        tn10_pipeline::NamespaceTransitionAuthorizationConfirmation {
            expires_at_unix: 2_000,
            now_unix: 1_000,
            confirmation: &format!("AUTHORIZE {}", "ab".repeat(32))
        },
    )
    .is_err());
    assert!(tn10_pipeline::create_namespace_transition_authorization(
        &document,
        &quote,
        3_000_000_001,
        1_000_000,
        true,
        tn10_pipeline::NamespaceTransitionAuthorizationConfirmation {
            expires_at_unix: 2_000,
            now_unix: 1_000,
            confirmation: &format!("AUTHORIZE {}", "ab".repeat(32))
        },
    )
    .is_ok());
}
