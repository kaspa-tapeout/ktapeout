use kaspa_consensus_core::tx::Transaction;
use kaspa_rpc_core::RpcTransaction;
use ktapeout_050_adapter_workbench::namespace_parent_genesis::{build, transition_command};
use ktapeout_cli::tn10_pipeline::{self, Transport};
use secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;

fn xonly(secret: [u8; 32]) -> String {
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(&secret).unwrap();
    hex::encode(
        Keypair::from_secret_key(&secp, &secret)
            .x_only_public_key()
            .0
            .serialize(),
    )
}

fn request() -> Value {
    let claimant = xonly([2; 32]);
    let funder = xonly([3; 32]);
    let mut frame = vec![0u8; 64];
    frame[0] = 6;
    frame[1..7].copy_from_slice(b"n2test");
    let frame_hex = hex::encode(frame);
    let namespace_hash = Sha256::digest(
        [
            b"KTAPEOUT/0.5.0/NAMESPACE_FRAME/V1\0\x0a".as_slice(),
            &hex::decode(&frame_hex).unwrap(),
        ]
        .concat(),
    );
    let change_script = format!("000020{funder}ac");
    json!({
        "schema":"KTAPEOUT-REGISTRY-ADAPTER-NAMESPACE-GENESIS-INPUT-V1",
        "network":"testnet-10",
        "authority_xonly":claimant,
        "namespace_hash":hex::encode(namespace_hash),
        "namespace_frame":frame_hex,
        "authority_commitment":hex::encode(Sha256::digest(hex::decode(&claimant).unwrap())),
        "resolver_policy_hash":"1111111111111111111111111111111111111111111111111111111111111111",
        "registry_root":"2222222222222222222222222222222222222222222222222222222222222222",
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
    })
}

struct OfflineSubmitTransport {
    submitted: Option<String>,
}

impl Transport for OfflineSubmitTransport {
    fn submit(&mut self, transaction: &RpcTransaction) -> Result<String, String> {
        let txid = Transaction::try_from(transaction.clone())
            .map_err(|error| error.to_string())?
            .id()
            .to_string();
        self.submitted = Some(txid.clone());
        Ok(txid)
    }

    fn read_transaction(&mut self, _: &str) -> Result<Option<Value>, String> {
        Ok(None)
    }
}

#[test]
fn parent_genesis_emits_a_funding_key_bound_native_signing_request() {
    let plan = build(&request()).unwrap();
    assert_eq!(
        plan["schema"],
        "KTAPEOUT-UNSIGNED-REGISTRY-ADAPTER-NAMESPACE-GENESIS-V1"
    );
    assert_eq!(plan["signing_allowed"], true);
    assert_eq!(plan["broadcast"], false);
    assert_eq!(
        plan["native_signing"]["schema"],
        "KTAPEOUT-NATIVE-SIGNING-REQUESTS-V1"
    );
    assert_eq!(
        plan["native_signing"]["requests"].as_array().unwrap().len(),
        1
    );
    assert_eq!(plan["native_signing"]["requests"][0]["input_index"], 0);
    assert_eq!(
        plan["native_signing"]["requests"][0]["signer_public_key"],
        xonly([3; 32])
    );
    assert_eq!(plan["native_signing"]["requests"][0]["sighash_type"], 1);
}

#[test]
fn parent_genesis_rejects_non_p2pk_funding_script_for_signing() {
    let mut input = request();
    input["funding_utxo"]["script_public_key"] = json!("000051");
    input["funding_change_script_public_key"] = json!("000051");
    assert!(build(&input).is_err());
}

#[test]
fn parent_genesis_recomputes_plan_and_native_vm_verifies_assembled_signature() {
    let mut request = request();
    // A large wallet UTXO remains mostly as same-script change. The release authorization
    // budget must cap locked value plus fee, not mistake the entire input for a spend.
    request["funding_utxo"]["amount"] = json!(889_644_274_244u64);
    let plan = json!({"action":"namespace_parent_genesis","request":request});
    let signing = transition_command("--transition-plan", &plan).unwrap();
    let request = &signing["requests"][0];
    let digest: [u8; 32] = hex::decode(request["sighash"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let secp = Secp256k1::new();
    let key = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[3; 32]).unwrap());
    let signature = secp.sign_schnorr_no_aux_rand(&Message::from_digest(digest), &key);
    let packet = json!({
        "native_plan_hash":request["native_plan_hash"],
        "input_index":request["input_index"],
        "signer_public_key":request["signer_public_key"],
        "sighash_type":1,
        "signature":hex::encode(signature.as_ref())
    });
    let document = json!({"plan":plan.clone(),"packets":[packet]});
    assert_eq!(
        transition_command("--verify-signatures", &document).unwrap()["verified"],
        true
    );
    let authorization_document = json!({"plan":plan.clone(),"signing":signing.clone()});
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
        &authorization_document,
        &quote,
        1_300_000_000,
        1_000_000,
        true,
        tn10_pipeline::NamespaceTransitionAuthorizationConfirmation {
            expires_at_unix: 2_000,
            now_unix: 1_000,
            confirmation: &format!(
                "AUTHORIZE {}",
                signing["requests"][0]["native_plan_hash"].as_str().unwrap()
            ),
        },
    )
    .unwrap();
    assert_eq!(authorization["input_total_sompi"], 889_644_274_244u64);
    assert_eq!(authorization["authorized_debit_sompi"], 1_101_000_000u64);
    let mut assembled = transition_command("--merge-signatures", &document).unwrap();
    assembled["authorization"] = authorization;
    assert_eq!(assembled["native_vm_verified"], true);
    assert_eq!(assembled["broadcast"], false);
    ktapeout_cli::tn10_pipeline::verify_namespace_transition_artifact(&assembled).unwrap();
    let mut altered = assembled.clone();
    altered["transaction"]["outputs"][0]["value"] = serde_json::json!(1);
    assert!(ktapeout_cli::tn10_pipeline::verify_namespace_transition_artifact(&altered).is_err());
    assert_eq!(
        assembled["transaction"]["inputs"][0]["signatureScript"]
            .as_str()
            .unwrap()
            .len(),
        132
    );
    let directory = std::env::temp_dir().join(format!("n2-parent-submit-{}", std::process::id()));
    fs::create_dir_all(&directory).unwrap();
    let input = directory.join("assembled.json");
    let output = directory.join("submission.json");
    fs::write(&input, serde_json::to_vec(&assembled).unwrap()).unwrap();
    let broadcast_confirmation = format!("BROADCAST {}", assembled["txid"].as_str().unwrap());
    let mut first = OfflineSubmitTransport { submitted: None };
    let mut second = OfflineSubmitTransport { submitted: None };
    tn10_pipeline::submit_namespace_transition_with_transports(
        &input,
        &output,
        false,
        1_100,
        &broadcast_confirmation,
        &mut first,
        &mut second,
    )
    .unwrap();
    let record: Value = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    assert_eq!(record["status"], "SUBMITTED");
    assert_eq!(record["txid"].as_str(), first.submitted.as_deref());
    assert!(record["authorization_sha256"].as_str().is_some());
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn parent_genesis_authorization_rejects_a_cap_below_locked_value_and_fee() {
    let request = request();
    let plan = json!({"action":"namespace_parent_genesis","request":request});
    let signing = transition_command("--transition-plan", &plan).unwrap();
    let authorization_document = json!({"plan":plan,"signing":signing});
    let quote = json!({
        "source":"live_dual_node_quote",
        "fee_rate_sompi_per_gram":2,
        "node_rates":[{"endpoint":"wss://one.example","feerate":1.5},{"endpoint":"wss://two.example","feerate":2.0}],
        "endpoints":["wss://one.example","wss://two.example"],
        "observed_at":"1970-01-01T00:16:40Z"
    });
    let error = tn10_pipeline::prepare_namespace_transition_authorization(
        &authorization_document,
        &quote,
        1_100_999_999,
        1_000_000,
        2_000,
        1_000,
        true,
    )
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        "TN10_NAMESPACE_TRANSITION_AUTHORIZATION_BUDGET_EXCEEDED"
    );
}
