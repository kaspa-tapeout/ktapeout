//! Generic contract test for canonical namespace discovery-list parsing and merge semantics.

use kaspa_consensus_core::tx::{
    ScriptPublicKey, Transaction, TransactionId, TransactionOutpoint, UtxoEntry,
};
use kaspa_rpc_core::{RpcAddress, RpcTransaction, RpcUtxosByAddressesEntry};
use ktapeout_cli::registered_keys::{
    child_name_key, child_name_keys, fetch_key_list_with, fetch_key_list_with_timeout, merge_lists,
    namespace_key, parse_list, plan_registration, validate_keys_url, validate_public_dns_answers,
    RegistrationPlanInput,
};
use ktapeout_cli::tn10_pipeline::{
    add_namespace_key_url_sources, dual_fee_quote_with_transports,
    registry_register_plan_with_transports, registry_request_with_names_and_transports, Transport,
};
use serde_json::{json, Value};
use std::net::IpAddr;
use std::time::Duration;

const BASELINE: &str = include_str!("../../../data/registry/tn10-registered-keys-v1.json");

struct FeeMock {
    response: Result<Value, String>,
}

impl Transport for FeeMock {
    fn submit(&mut self, _: &RpcTransaction) -> Result<String, String> {
        panic!("fee quoting must never submit")
    }
    fn read_transaction(&mut self, _: &str) -> Result<Option<Value>, String> {
        panic!("fee quoting must never read transactions")
    }
    fn read_fee_estimate(&mut self) -> Result<Value, String> {
        self.response.clone()
    }
}

fn fee_mock(rate: f64) -> FeeMock {
    FeeMock {
        response: Ok(serialized_fee_estimate(rate)),
    }
}

fn serialized_fee_estimate(rate: f64) -> Value {
    serde_json::to_value(kaspa_rpc_core::RpcFeeEstimate {
        priority_bucket: kaspa_rpc_core::RpcFeerateBucket {
            feerate: rate,
            estimated_seconds: 1.0,
        },
        normal_buckets: Vec::new(),
        low_buckets: Vec::new(),
    })
    .unwrap()
}

fn fee_request() -> Value {
    json!({"network":"testnet-10","nodes":[
        "wss://node-a.example/kaspa/testnet-10/wrpc/borsh",
        "wss://node-b.example/kaspa/testnet-10/wrpc/borsh"
    ]})
}

#[test]
fn dual_fee_quote_accepts_equal_rates_and_records_provenance() {
    assert_eq!(
        serialized_fee_estimate(2.5),
        json!({
            "priorityBucket":{"feerate":2.5,"estimatedSeconds":1.0},
            "normalBuckets":[],
            "lowBuckets":[]
        })
    );
    let quote =
        dual_fee_quote_with_transports(&fee_request(), &mut fee_mock(2.5), &mut fee_mock(2.5))
            .unwrap();
    assert_eq!(quote["fee_rate_sompi_per_gram"], 3);
    assert_eq!(quote["source"], "live_dual_node_quote");
    assert_eq!(quote["node_rates"][0]["feerate"], 2.5);
    assert_eq!(quote["node_rates"][1]["feerate"], 2.5);
    assert_eq!(quote["endpoints"].as_array().unwrap().len(), 2);
    assert!(quote["observed_at"].as_str().is_some());
}

#[test]
fn dual_fee_quote_keeps_the_existing_release_wrapped_shape() {
    let wrapped = |rate| FeeMock {
        response: Ok(json!({"estimate":{"priorityBucket":{"feerate":rate}}})),
    };
    let quote =
        dual_fee_quote_with_transports(&fee_request(), &mut wrapped(2.0), &mut wrapped(3.0))
            .unwrap();
    assert_eq!(quote["fee_rate_sompi_per_gram"], 3);
}

#[test]
fn dual_fee_quote_uses_the_higher_rate_within_twofold_range() {
    let quote =
        dual_fee_quote_with_transports(&fee_request(), &mut fee_mock(2.0), &mut fee_mock(4.0))
            .unwrap();
    assert_eq!(quote["fee_rate_sompi_per_gram"], 4);
}

#[test]
fn dual_fee_quote_rejects_rates_more_than_twofold_apart() {
    let error =
        dual_fee_quote_with_transports(&fee_request(), &mut fee_mock(1.0), &mut fee_mock(2.01))
            .unwrap_err()
            .to_string();
    assert!(error.contains("TN10_FEE_NODES_DISAGREE"));
}

#[test]
fn dual_fee_quote_fails_closed_when_one_node_fails() {
    let mut failed = FeeMock {
        response: Err("mock read failed".into()),
    };
    let error = dual_fee_quote_with_transports(&fee_request(), &mut fee_mock(2.0), &mut failed)
        .unwrap_err()
        .to_string();
    assert!(error.contains("TN10_FEE_ESTIMATE_READ_FAILED"));
}

#[test]
fn dual_fee_quote_rejects_missing_rate_field() {
    let mut malformed = FeeMock {
        response: Ok(json!({"normalBuckets":[],"lowBuckets":[]})),
    };
    let error = dual_fee_quote_with_transports(&fee_request(), &mut fee_mock(2.0), &mut malformed)
        .unwrap_err()
        .to_string();
    assert!(error.contains("TN10_FEE_ESTIMATE_INVALID"));
}

fn list(entries: Value) -> Value {
    json!({
        "schema":"KTAPEOUT-REGISTERED-KEYS-V1",
        "network":"testnet-10",
        "sequence":1,
        "updated_at":"2026-11-01T00:00:00Z",
        "keys":entries
    })
}

struct RegistryMock {
    entries: Vec<Value>,
    index: usize,
    fail_read: bool,
}

impl Transport for RegistryMock {
    fn read_fee_estimate(&mut self) -> Result<Value, String> {
        Ok(json!({"estimate":{"priorityBucket":{"feerate":2.0}}}))
    }

    fn submit(&mut self, _: &RpcTransaction) -> Result<String, String> {
        panic!("registration planning must never submit")
    }

    fn read_transaction(&mut self, _: &str) -> Result<Option<Value>, String> {
        panic!("registration planning must not read transactions")
    }

    fn read_utxos(&mut self, address: &str) -> Result<Value, String> {
        if self.fail_read {
            return Err("mock transport failure".into());
        }
        let entry = self
            .entries
            .get(self.index)
            .cloned()
            .ok_or("unexpected UTXO read")?;
        if let Some(expected_address) = entry
            .as_array()
            .and_then(|entries| entries.first())
            .and_then(|utxo| utxo["address"].as_str())
        {
            if address != expected_address {
                return Err(format!(
                    "mock UTXO address mismatch: expected {expected_address}, received {address}"
                ));
            }
        }
        self.index += 1;
        Ok(entry)
    }

    fn read_observation(&mut self) -> Result<Value, String> {
        Ok(
            json!({"network":"testnet-10","synced":true,"utxo_indexed":true,
            "start_hash":"11".repeat(32),"virtual_daa_score":50}),
        )
    }
}

fn state_utxo(script_public_key: &str, amount: u64, tx_byte: u8) -> Value {
    let script = hex::decode(script_public_key.strip_prefix("0000").unwrap()).unwrap();
    let address = RpcAddress::new(
        "kaspatest".try_into().unwrap(),
        8u8.try_into().unwrap(),
        &script[2..34],
    );
    let txid = TransactionId::from_bytes([tx_byte; 32]);
    let entry = UtxoEntry::new(amount, ScriptPublicKey::from_vec(0, script), 1, false, None);
    serde_json::to_value(vec![RpcUtxosByAddressesEntry {
        address: Some(address),
        outpoint: TransactionOutpoint::new(txid, 0).into(),
        utxo_entry: entry.into(),
    }])
    .unwrap()
}

fn registry_mock(gap: &str, deed: &str) -> RegistryMock {
    RegistryMock {
        entries: vec![
            state_utxo(gap, 100_000_000, 0x21),
            state_utxo(deed, 1_000_000_000, 0x22),
        ],
        index: 0,
        fail_read: false,
    }
}

fn registration_registry_mock(gap: &str, deed: &str) -> RegistryMock {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../examples/namespace-child-registration-v6-cli-parity-v1-vector.json"
    ))
    .unwrap();
    let fee = &fixture["manifest"]["transaction_input"]["fee_utxo"];
    RegistryMock {
        entries: vec![
            state_utxo(gap, 4_000_000_000, 0x21),
            state_utxo(deed, 1_500_000_000, 0x22),
            address_utxo(
                fee["script_public_key"].as_str().unwrap(),
                2_500_000_000,
                0xcc,
            ),
        ],
        index: 0,
        fail_read: false,
    }
}

fn registration_registry_mock_with_fee(gap: &str, deed: &str, fee_script: &str) -> RegistryMock {
    RegistryMock {
        entries: vec![
            state_utxo(gap, 4_000_000_000, 0x21),
            state_utxo(deed, 1_500_000_000, 0x22),
            address_utxo(fee_script, 2_500_000_000, 0xcc),
        ],
        index: 0,
        fail_read: false,
    }
}

fn address_utxo(script_public_key: &str, amount: u64, tx_byte: u8) -> Value {
    let script = hex::decode(script_public_key.strip_prefix("0000").unwrap()).unwrap();
    let address = RpcAddress::new(
        "kaspatest".try_into().unwrap(),
        0u8.try_into().unwrap(),
        &script[1..33],
    );
    let txid = TransactionId::from_bytes([tx_byte; 32]);
    let entry = UtxoEntry::new(
        amount,
        ScriptPublicKey::from_vec(0, script),
        55,
        false,
        None,
    );
    serde_json::to_value(vec![RpcUtxosByAddressesEntry {
        address: Some(address),
        outpoint: TransactionOutpoint::new(txid, 0).into(),
        utxo_entry: entry.into(),
    }])
    .unwrap()
}

#[test]
fn published_fee_public_key_derives_the_expected_testnet_p2pk_address() {
    // Public key copied verbatim from name-canary-preflight.json:47.
    let public_key =
        hex::decode("aa0ada4f5bf5369de10ea33599d335f5fb52eba0bb509c50217e91009a9282d5").unwrap();
    let address = RpcAddress::new(
        "kaspatest".try_into().unwrap(),
        0u8.try_into().unwrap(),
        &public_key,
    );
    assert_eq!(
        address.to_string(),
        "kaspatest:qz4q4kj0t06nd80pp63ntxwnxh6lk5ht5za4p8zsy9lfzqy6j2pd23n6xch62"
    );
}

fn native_registration_input(tx_input: &Value) -> Value {
    let fee_script =
        hex::decode(tx_input["fee_utxo"]["script_public_key"].as_str().unwrap()).unwrap();
    let fee_key = hex::encode(&fee_script[3..35]);
    let mut input = json!({
        "inputs":[tx_input["parent_utxo"],tx_input["gap_utxo"],tx_input["fee_utxo"]],
        "outputs":tx_input["outputs"],
        "deed_state_bond_sompi":1_000_000_000u64,
        "registration_entrypoint":"register_interior",
        "role_public_keys":{
            "parent":fee_key.clone(),
            "claimant":fee_key.clone(),
            "target":fee_key.clone(),
            "parent_for_child":fee_key.clone(),
            "fee":fee_key
        }
    });
    for (index, budget) in [10u64, 47, 10].into_iter().enumerate() {
        input["inputs"][index]["compute_budget"] = json!(budget);
    }
    let old_name_deed = input["outputs"][2]["value"].as_u64().unwrap();
    input["outputs"][2]["value"] = json!(100_000_000u64);
    let old_fee_change = input["outputs"][4]["value"].as_u64().unwrap();
    input["outputs"][4]["value"] = json!(old_fee_change + old_name_deed - 100_000_000);
    input["registration_kind"] = json!("INTERIOR");
    let witness_contexts = [
        (0usize, "authorize_child", vec![0x51; 300], vec![6usize]),
        (
            1usize,
            "register_interior",
            vec![0x52; 301],
            vec![11usize, 13, 22],
        ),
    ]
    .into_iter()
    .map(
        |(input_index, entrypoint, redeem_script, signature_slots)| {
            let spk = format!(
                "0000aa20{}87",
                hex::encode(ktapeout_cli::name_state_template::blake2b_256(
                    &redeem_script
                ))
            );
            input["inputs"][input_index]["script_public_key"] = json!(spk);
            // V6 named-reference register_interior contexts contain 29 arguments;
            // keep the synthetic plan fixture on that supported ABI layout.
            let argument_count = if entrypoint == "register_interior" {
                29
            } else {
                signature_slots.iter().max().unwrap() + 1
            };
            let mut arguments = vec![json!({"data_hex":"01"}); argument_count];
            for slot in signature_slots {
                arguments[slot] = json!({"data_hex":"00".repeat(65)});
            }
            json!({
                "input_index":input_index,
                "entrypoint":entrypoint,
                "redeem_script_hex":hex::encode(redeem_script),
                "arguments":arguments
            })
        },
    )
    .collect::<Vec<_>>();
    input["covenant_witness_contexts"] = json!(witness_contexts);
    input
}

#[test]
fn registration_plan_requires_hash_bound_witness_context_for_covenant_inputs() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../examples/namespace-child-registration-v6-cli-parity-v1-vector.json"
    ))
    .unwrap();
    let request = native_registration_input(&fixture["manifest"]["transaction_input"]);
    let mut request = request;
    request
        .as_object_mut()
        .unwrap()
        .remove("covenant_witness_contexts");
    assert_eq!(
        ktapeout_cli::tn10_pipeline::build_native_registration_plan(&request)
            .unwrap_err()
            .to_string(),
        "TN10_REGISTRATION_WITNESS_CONTEXT_REQUIRED"
    );
}

#[test]
fn register_plan_cli_path_combines_costs_with_dual_rpc_mock_states() {
    let baseline: Value = serde_json::from_str(BASELINE).unwrap();
    let namespace_keys = list(json!([{
        "namespace":"myspace",
        "key_hex":namespace_key("myspace").unwrap()
    }]));
    let url_document = list(json!([{
        "namespace":"fromurl",
        "key_hex":namespace_key("fromurl").unwrap()
    }]));
    let url_body = serde_json::to_vec(&url_document).unwrap();
    let gap = format!("0000aa20{}87", "31".repeat(32));
    let deed = format!("0000aa20{}87", "42".repeat(32));
    let native_fixture: Value = serde_json::from_str(include_str!(
        "../../../examples/namespace-child-registration-v6-cli-parity-v1-vector.json"
    ))
    .unwrap();
    let native_source = &native_fixture["manifest"]["transaction_input"];
    let native_input = native_registration_input(native_source);
    let request = json!({
        "network":"testnet-10",
        "namespace":"myspace",
        "slug":"notes",
        "owner":"kaspatest:qzowner",
        "existing_slugs":[],
        "namespace_key_sources":[baseline, namespace_keys],
        "estimated_mass":1,
        "fee_rate_sompi_per_gram":2,
        "native_transaction_input":native_input,
        "states":[
            {"role":"gap","script_public_key":gap},
            {"role":"deed","script_public_key":deed}
        ],
        "nodes":[
            "wss://node-a.example/kaspa/testnet-10/wrpc/borsh",
            "wss://node-b.example/kaspa/testnet-10/wrpc/borsh"
        ]
    });
    let mut request = request;
    add_namespace_key_url_sources(
        &mut request,
        &["https://keys.example/keys.json".to_owned()],
        |_| {
            let body = url_body.clone();
            fetch_key_list_with("https://keys.example/keys.json", move |_| Ok((200, body)))
        },
    )
    .unwrap();
    let result = registry_register_plan_with_transports(
        &request,
        &mut registry_mock(&gap, &deed),
        &mut registry_mock(&gap, &deed),
    )
    .unwrap();

    assert_eq!(result["status"], "DUAL_RPC_UNSIGNED_NATIVE_PLAN");
    assert_eq!(result["plan"]["namespace_key_sources_merged"], 4);
    assert_eq!(result["plan"]["deed_state_bond_kas"], "10.00000000");
    assert_eq!(result["plan"]["newly_locked_sompi"], 200_000_000u64);
    assert_eq!(result["plan"]["fee_source"], "live_dual_node_quote");
    assert_eq!(result["fee_quote"]["source"], "live_dual_node_quote");
    assert_eq!(result["fee_quote"]["fee_rate_sompi_per_gram"], 2);
    assert_eq!(
        result["verified_state_bundle"]["states"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(result["signing_allowed"], false);
    assert_eq!(result["broadcast"], false);
    assert_eq!(
        result["native_transaction_plan"]["transaction"]["inputs"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    assert_eq!(
        result["native_transaction_plan"]["transaction"]["outputs"]
            .as_array()
            .unwrap()
            .len(),
        5
    );
    assert_eq!(result["native_transaction_funding_claims_verified"], false);
    let quality = &result["native_transaction_plan"]["quality"];
    assert_eq!(quality["compute_mass"], 10_197);
    assert_eq!(quality["transient_mass"], 6_628);
    assert_eq!(quality["storage_mass"], 45_707);
    assert_eq!(quality["normalized_total_mass"], 45_707);
    assert_eq!(quality["mass_source"], "pinned_v2.1.0_consensus_calculator");
    assert_eq!(quality["signature_scripts_are_placeholders"], true);
    let script_lengths = quality["signature_script_lengths"].as_array().unwrap();
    assert!(script_lengths[0].as_u64().unwrap() > 66);
    assert!(script_lengths[1].as_u64().unwrap() > 66);
    assert_eq!(script_lengths[2].as_u64(), Some(66));
    assert_eq!(
        result["plan"]["normalized_mass"],
        quality["normalized_total_mass"]
    );
    assert_eq!(
        result["plan"]["network_fee_sompi"],
        quality["normalized_total_mass"].as_u64().unwrap() * 2
    );
    assert_eq!(
        result["native_transaction_plan"]["fee_sompi"],
        result["plan"]["network_fee_sompi"]
    );

    // The deprecated caller field must have no influence on quality or fees.
    let mut changed_mass_hint = request.clone();
    changed_mass_hint["estimated_mass"] = json!(u64::MAX);
    let same_plan = registry_register_plan_with_transports(
        &changed_mass_hint,
        &mut registry_mock(&gap, &deed),
        &mut registry_mock(&gap, &deed),
    )
    .unwrap();
    assert_eq!(
        same_plan["native_transaction_plan"]["quality"],
        result["native_transaction_plan"]["quality"]
    );
    assert_eq!(
        same_plan["plan"]["network_fee_sompi"],
        result["plan"]["network_fee_sompi"]
    );

    let mut stale_request = request.clone();
    stale_request["namespace"] = json!("missing");
    let stale_error = registry_register_plan_with_transports(
        &stale_request,
        &mut registry_mock(&gap, &deed),
        &mut registry_mock(&gap, &deed),
    )
    .unwrap_err()
    .to_string();
    assert!(stale_error.starts_with("NAME_KEY_LIST_INCOMPLETE_OR_STALE"));
    assert!(stale_error.contains("--keys-file / --keys-url"));
}

#[test]
fn bundled_namespace_keys_recompute_and_union_is_sorted() {
    let baseline: Value = serde_json::from_str(BASELINE).unwrap();
    let parsed = parse_list(&baseline).unwrap();
    assert_eq!(parsed.len(), 3);
    assert_eq!(namespace_key("ktape").unwrap(), parsed[0].key_hex);

    let added = list(json!([{
        "namespace":"myspace",
        "key_hex":namespace_key("myspace").unwrap()
    }]));
    let expected_names = {
        let mut names = parsed
            .iter()
            .map(|item| item.namespace.clone())
            .collect::<Vec<_>>();
        names.push("myspace".to_owned());
        names.sort();
        names
    };
    let merged = merge_lists(&[baseline, added]).unwrap();
    assert_eq!(
        merged
            .iter()
            .map(|item| item.namespace.as_str())
            .collect::<Vec<_>>(),
        expected_names
    );
}

#[test]
fn native_registration_plan_rejects_economic_floors_before_returning_a_transaction() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../examples/namespace-child-registration-v6-cli-parity-v1-vector.json"
    ))
    .expect("pinned native registration vector");
    let tx_input = &fixture["manifest"]["transaction_input"];
    let mut input = native_registration_input(tx_input);
    let plan = ktapeout_cli::tn10_pipeline::build_native_registration_plan(&input)
        .expect("valid 3-input/5-output unsigned plan");
    assert_eq!(plan["inputs"].as_array().unwrap().len(), 3);
    assert_eq!(plan["outputs"].as_array().unwrap().len(), 5);
    assert_eq!(plan["transaction"]["inputs"].as_array().unwrap().len(), 3);
    assert_eq!(plan["transaction"]["outputs"].as_array().unwrap().len(), 5);
    assert_eq!(plan["fee_sompi"], 40_000_000u64);
    for (index, input) in plan["transaction"]["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        assert_eq!(
            input["signatureScript"], "",
            "input {index} must remain unsigned"
        );
    }
    assert_eq!(plan["signing_allowed"], false);
    assert_eq!(plan["broadcast"], false);
    assert!(ktapeout_cli::tn10_pipeline::verify_native_registration_plan_digest(&plan));
    for path in ["inputs", "outputs", "transaction"] {
        let mut changed = plan.clone();
        if path == "inputs" {
            changed["inputs"][0]["outpoint"] = json!("11".repeat(32) + ":0");
        } else if path == "outputs" {
            changed["outputs"][4]["value"] =
                json!(changed["outputs"][4]["value"].as_u64().unwrap() - 1);
        } else {
            changed["transaction"]["inputs"][0]["signatureScript"] = json!("01");
        }
        assert!(
            !ktapeout_cli::tn10_pipeline::verify_native_registration_plan_digest(&changed),
            "mutating {path} must invalidate plan digest"
        );
    }

    input["outputs"][2]["value"] = json!(99_999_999u64);
    let below_bond = ktapeout_cli::tn10_pipeline::build_native_registration_plan(&input)
        .unwrap_err()
        .to_string();
    assert!(below_bond.contains("TN10_REGISTRY_NAME_DEED_VALUE_MISMATCH"));
    assert!(!below_bond.contains("transaction"));

    input = native_registration_input(tx_input);
    input["deed_state_bond_sompi"] = json!(999_999_999u64);
    let below_bond = ktapeout_cli::tn10_pipeline::build_native_registration_plan(&input)
        .unwrap_err()
        .to_string();
    assert!(below_bond.contains("TN10_REGISTRY_DEED_STATE_BOND_BELOW_MINIMUM"));
    assert!(!below_bond.contains("transaction"));

    input["deed_state_bond_sompi"] = json!(1_000_000_000u64);
    input["outputs"][1]["value"] = json!(99_999_999u64);
    let below_gap = ktapeout_cli::tn10_pipeline::build_native_registration_plan(&input)
        .unwrap_err()
        .to_string();
    assert!(below_gap.contains("TN10_REGISTRY_GAP_VALUE_BELOW_FLOOR"));
    assert!(!below_gap.contains("transaction"));
}

#[test]
fn native_registration_plan_v3_binds_role_keys_covenant_utxos_and_witness_slots() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../examples/namespace-child-registration-v6-cli-parity-v1-vector.json"
    ))
    .unwrap();
    let tx_input = &fixture["manifest"]["transaction_input"];
    let mut request = native_registration_input(tx_input);
    let fee_script =
        hex::decode(request["inputs"][2]["script_public_key"].as_str().unwrap()).unwrap();
    assert_eq!(fee_script[2], 0x20, "fee input fixture is a P2PK script");
    let fee_key = hex::encode(&fee_script[3..35]);
    let plan = ktapeout_cli::tn10_pipeline::build_native_registration_plan(&request)
        .expect("native plan records all role and covenant witness context");
    assert_eq!(
        plan["schema"],
        "KTAPEOUT-TN10-NATIVE-CHILD-REGISTRATION-PLAN-V3"
    );
    assert_eq!(plan["role_input_map"]["parent"], 0);
    assert_eq!(plan["role_input_map"]["claimant"], 1);
    assert_eq!(plan["role_input_map"]["target"], 1);
    assert_eq!(plan["role_input_map"]["parent_for_child"], 1);
    assert_eq!(plan["role_input_map"]["fee"], 2);
    assert_eq!(
        plan["role_public_keys"]["roles"]["fee"]["public_key"],
        fee_key
    );
    assert_eq!(
        plan["role_public_keys"]["roles"]["fee"]["source"],
        "derived_from_p2pk_script"
    );
    assert_eq!(plan["role_public_keys"]["key_relationship"], "SAME_KEY");
    assert_eq!(
        plan["covenant_utxos"][0]["covenant_id"],
        request["inputs"][0]["covenant_id"]
    );
    assert_eq!(
        plan["covenant_utxos"][1]["covenant_id"],
        request["inputs"][1]["covenant_id"]
    );
    assert_eq!(
        plan["witness_templates"][0]["entrypoint"],
        "authorize_child"
    );
    assert_eq!(
        plan["witness_templates"][1]["entrypoint"],
        "register_interior"
    );
    assert_eq!(
        plan["witness_templates"][0]["signature_slots"][0]["signature_slot_index"],
        6
    );
    assert_eq!(
        plan["witness_templates"][1]["signature_slots"][0]["signature_slot_index"],
        11
    );
    assert_eq!(
        plan["witness_templates"][1]["signature_slots"][1]["signature_slot_index"],
        13
    );
    assert_eq!(
        plan["witness_templates"][1]["signature_slots"][2]["signature_slot_index"],
        22
    );
    assert_eq!(
        plan["covenant_witness_contexts"].as_array().unwrap().len(),
        2
    );
    assert_eq!(
        plan["witness_templates"][1]["signature_slots"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    assert!(ktapeout_cli::tn10_pipeline::verify_native_registration_plan_digest(&plan));

    for (path, value) in [
        ("role_public_keys", json!("55".repeat(32))),
        ("witness_templates", json!("register_slot")),
        ("covenant_witness_contexts", json!("changed")),
        ("covenant_utxos", json!("00".repeat(32))),
    ] {
        let mut changed = plan.clone();
        match path {
            "role_public_keys" => {
                changed["role_public_keys"]["roles"]["parent"]["public_key"] = value
            }
            "witness_templates" => changed["witness_templates"][1]["entrypoint"] = value,
            "covenant_witness_contexts" => {
                changed["covenant_witness_contexts"][0]["redeem_script_hex"] = value
            }
            _ => changed["covenant_utxos"][0]["covenant_id"] = value,
        }
        assert!(
            !ktapeout_cli::tn10_pipeline::verify_native_registration_plan_digest(&changed),
            "mutating {path} must invalidate the plan digest"
        );
    }

    let mut changed_argument = plan.clone();
    changed_argument["covenant_witness_contexts"][0]["arguments"][0]["data_hex"] = json!("02");
    assert!(
        !ktapeout_cli::tn10_pipeline::verify_native_registration_plan_digest(&changed_argument)
    );

    let mut mismatched_redeem = request.clone();
    mismatched_redeem["inputs"][0]["script_public_key"] =
        json!("0000aa20".to_owned() + &"00".repeat(32) + "87");
    assert_eq!(
        ktapeout_cli::tn10_pipeline::build_native_registration_plan(&mismatched_redeem)
            .unwrap_err()
            .to_string(),
        "TN10_REGISTRATION_WITNESS_REDEEM_HASH_MISMATCH"
    );

    let mut bad_placeholder = request.clone();
    bad_placeholder["covenant_witness_contexts"][1]["arguments"][11]["data_hex"] =
        json!("01".repeat(65));
    assert_eq!(
        ktapeout_cli::tn10_pipeline::build_native_registration_plan(&bad_placeholder)
            .unwrap_err()
            .to_string(),
        "TN10_REGISTRATION_WITNESS_SIGNATURE_SLOT_INVALID"
    );

    let secp = secp256k1::Secp256k1::new();
    let fixture_signing_key = secp256k1::SecretKey::from_slice(&[2u8; 32]).unwrap();
    let keypair = secp256k1::Keypair::from_secret_key(&secp, &fixture_signing_key);
    let mismatch_key = hex::encode(
        secp256k1::XOnlyPublicKey::from_keypair(&keypair)
            .0
            .serialize(),
    );
    request["role_public_keys"]["fee"] = json!(mismatch_key);
    assert_eq!(
        ktapeout_cli::tn10_pipeline::build_native_registration_plan(&request)
            .unwrap_err()
            .to_string(),
        "TN10_REGISTRATION_ROLE_PUBLIC_KEY_MISMATCH"
    );
}

#[test]
fn native_registration_authorization_binds_plan_roles_amount_fee_and_expiry() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../examples/namespace-child-registration-v6-cli-parity-v1-vector.json"
    ))
    .unwrap();
    let request = native_registration_input(&fixture["manifest"]["transaction_input"]);
    let plan = ktapeout_cli::tn10_pipeline::build_native_registration_plan(&request).unwrap();
    let amount_limit = plan["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|input| input["amount"].as_u64().unwrap())
        .sum::<u64>();
    let authorization = json!({
        "schema":"KTAPEOUT-TN10-REGISTRATION-AUTHORIZATION-V1",
        "network":"testnet-10",
        "plan_sha256":plan["plan_sha256"],
        "role_public_keys":plan["role_public_keys"],
        "cumulative_amount_limit_sompi":amount_limit,
        "fee_limit_sompi":plan["fee_sompi"],
        "fee_source":"live_dual_node_quote",
        "fee_quote_sha256":"aa".repeat(32),
        "created_at_unix":1000u64,
        "expires_at_unix":2000u64,
        "allow_broadcast":true,
        "allow_readback":true,
        "confirmation_method":"TERMINAL_TYPED_PLAN_DIGEST",
        "created_with_terminal_confirmation":true
    });
    assert!(
        ktapeout_cli::tn10_pipeline::verify_native_registration_authorization(
            &plan,
            &authorization,
            1500
        )
        .is_ok()
    );
    assert!(
        ktapeout_cli::tn10_pipeline::verify_native_registration_authorization(
            &plan,
            &authorization,
            2000
        )
        .is_err()
    );
    for (field, value) in [
        ("plan_sha256", json!("44".repeat(32))),
        ("role_public_keys", json!({"roles":{}})),
        ("cumulative_amount_limit_sompi", json!(amount_limit - 1)),
        (
            "fee_limit_sompi",
            json!(plan["fee_sompi"].as_u64().unwrap() - 1),
        ),
        ("expires_at_unix", json!(900u64)),
    ] {
        let mut changed = authorization.clone();
        changed[field] = value;
        assert!(
            ktapeout_cli::tn10_pipeline::verify_native_registration_authorization(
                &plan, &changed, 1500
            )
            .is_err(),
            "accepted altered {field}"
        );
    }
}

#[test]
fn native_registration_authorization_requires_live_quote_and_broadcast_scope_fields() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../examples/namespace-child-registration-v6-cli-parity-v1-vector.json"
    ))
    .unwrap();
    let request = native_registration_input(&fixture["manifest"]["transaction_input"]);
    let plan = ktapeout_cli::tn10_pipeline::build_native_registration_plan(&request).unwrap();
    let total = plan["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|input| input["amount"].as_u64().unwrap())
        .sum::<u64>();
    let legacy_record = json!({
        "schema":"KTAPEOUT-TN10-REGISTRATION-AUTHORIZATION-V1",
        "network":"testnet-10",
        "plan_sha256":plan["plan_sha256"],
        "role_public_keys":plan["role_public_keys"],
        "cumulative_amount_limit_sompi":total,
        "fee_limit_sompi":plan["fee_sompi"],
        "created_at_unix":1000u64,
        "expires_at_unix":2000u64
    });
    assert!(
        ktapeout_cli::tn10_pipeline::verify_native_registration_authorization(
            &plan,
            &legacy_record,
            1500
        )
        .is_err()
    );
}

#[test]
fn tn10_authorize_help_requires_user_supplied_caps_expiry_and_has_no_yes_flag() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_ktape"))
        .args(["tn10", "authorize", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    for argument in ["--max-total-sompi", "--max-fee-sompi", "--expires-utc"] {
        assert!(help.contains(argument), "missing {argument} from help");
    }
    assert!(!help.contains("--yes"));
}

#[test]
fn tn10_authorize_rejects_missing_required_arguments() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_ktape"))
        .args(["tn10", "authorize"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("--max-total-sompi"));
    assert!(error.contains("--max-fee-sompi"));
    assert!(error.contains("--expires-utc"));
}

#[test]
fn tn10_authorize_rejects_piped_input_without_terminal_confirmation() {
    let output_path = std::env::temp_dir().join(format!(
        "ktape-authorize-noninteractive-{}-{}.json",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_ktape"))
        .args([
            "tn10",
            "authorize",
            "missing-plan.json",
            output_path.to_str().unwrap(),
            "--max-total-sompi",
            "100",
            "--max-fee-sompi",
            "10",
            "--expires-utc",
            "2026-11-05T00:00:00Z",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("TN10_AUTHORIZE_TERMINAL_REQUIRED"));
    assert!(!output_path.exists());
}

#[test]
fn authorization_creation_requires_fresh_live_quote_budgets_expiry_and_typed_confirmation() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../examples/namespace-child-registration-v6-cli-parity-v1-vector.json"
    ))
    .unwrap();
    let request = native_registration_input(&fixture["manifest"]["transaction_input"]);
    let plan = ktapeout_cli::tn10_pipeline::build_native_registration_plan(&request).unwrap();
    let now = 1_800_000_000u64;
    let fee = plan["fee_sompi"].as_u64().unwrap();
    let rate = 1u64;
    let quote = json!({
        "source":"live_dual_node_quote",
        "fee_rate_sompi_per_gram":rate,
        "node_rates":[
            {"endpoint":"ws://node-a.invalid","feerate":rate as f64},
            {"endpoint":"ws://node-b.invalid","feerate":rate as f64}
        ],
        "endpoints":["ws://node-a.invalid","ws://node-b.invalid"],
        "observed_at":chrono::DateTime::from_timestamp(now as i64,0).unwrap().to_rfc3339()
    });
    let document = json!({
        "schema":"KTAPEOUT-TN10-NAME-REGISTER-PLAN-V1",
        "network":"testnet-10",
        "fee_quote":quote,
        "native_transaction_plan":plan
    });
    let total = document["native_transaction_plan"]["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|input| input["amount"].as_u64().unwrap())
        .sum::<u64>();
    let expires = now + 3600;
    let digest = document["native_transaction_plan"]["plan_sha256"]
        .as_str()
        .unwrap();
    let confirmation = format!("AUTHORIZE {digest}");
    let record = ktapeout_cli::tn10_pipeline::create_native_registration_authorization(
        &document,
        total,
        fee,
        expires,
        now,
        true,
        true,
        &confirmation,
    )
    .unwrap();
    assert_eq!(record["fee_source"], "live_dual_node_quote");
    assert_eq!(record["allow_broadcast"], true);
    assert_eq!(record["allow_readback"], true);
    assert_eq!(record["created_with_terminal_confirmation"], true);
    ktapeout_cli::tn10_pipeline::verify_native_registration_authorization(
        &document["native_transaction_plan"],
        &record,
        now,
    )
    .unwrap();

    assert_eq!(
        ktapeout_cli::tn10_pipeline::create_native_registration_authorization(
            &document, total, fee, expires, now, true, true, ""
        )
        .unwrap_err()
        .to_string(),
        "TN10_REGISTRATION_AUTHORIZATION_CONFIRMATION_REQUIRED"
    );
    assert!(
        ktapeout_cli::tn10_pipeline::prepare_native_registration_authorization(
            &document,
            total - 1,
            fee,
            expires,
            now,
            true,
            true
        )
        .is_err()
    );
    assert!(
        ktapeout_cli::tn10_pipeline::prepare_native_registration_authorization(
            &document,
            total,
            fee - 1,
            expires,
            now,
            true,
            true
        )
        .is_err()
    );
    assert!(
        ktapeout_cli::tn10_pipeline::prepare_native_registration_authorization(
            &document, total, fee, now, now, true, true
        )
        .is_err()
    );
    assert!(
        ktapeout_cli::tn10_pipeline::prepare_native_registration_authorization(
            &document,
            total,
            fee,
            now + 24 * 60 * 60 + 1,
            now,
            true,
            true
        )
        .is_err()
    );

    let mut estimate = document.clone();
    estimate["fee_quote"]["source"] = json!("estimate");
    assert!(
        ktapeout_cli::tn10_pipeline::prepare_native_registration_authorization(
            &estimate, total, fee, expires, now, true, true
        )
        .is_err()
    );
    let mut tampered = document.clone();
    tampered["native_transaction_plan"]["outputs"][0]["value"] = json!(
        tampered["native_transaction_plan"]["outputs"][0]["value"]
            .as_u64()
            .unwrap()
            + 1
    );
    assert!(
        ktapeout_cli::tn10_pipeline::prepare_native_registration_authorization(
            &tampered, total, fee, expires, now, true, true
        )
        .is_err()
    );
}

#[test]
fn native_registration_signature_requests_bind_each_role_key_to_its_input_sighash() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../examples/namespace-child-registration-v6-cli-parity-v1-vector.json"
    ))
    .unwrap();
    let request = native_registration_input(&fixture["manifest"]["transaction_input"]);
    let plan = ktapeout_cli::tn10_pipeline::build_native_registration_plan(&request).unwrap();
    let requests = ktapeout_cli::tn10_pipeline::native_registration_signature_requests(&plan)
        .expect("role-bound per-input sighash requests");

    assert_eq!(
        requests["schema"],
        "KTAPEOUT-TN10-REGISTRATION-SIGNATURE-REQUESTS-V1"
    );
    assert_eq!(requests["plan_sha256"], plan["plan_sha256"]);
    let entries = requests["requests"].as_array().unwrap();
    assert_eq!(entries.len(), 5);
    for (role, input_index) in [
        ("parent", 0u64),
        ("claimant", 1),
        ("target", 1),
        ("parent_for_child", 1),
        ("fee", 2),
    ] {
        let entry = entries.iter().find(|entry| entry["role"] == role).unwrap();
        assert_eq!(entry["input_index"], input_index, "{role}");
        assert_eq!(entry["sighash_type"], 1, "{role}");
        assert_eq!(entry["sighash"].as_str().unwrap().len(), 64, "{role}");
        assert_eq!(
            entry["signer_public_key"],
            plan["role_public_keys"]["roles"][role]["public_key"]
        );
    }

    let mut tampered = plan.clone();
    tampered["transaction"]["outputs"][0]["value"] = json!(
        tampered["transaction"]["outputs"][0]["value"]
            .as_u64()
            .unwrap()
            + 1
    );
    assert!(
        ktapeout_cli::tn10_pipeline::native_registration_signature_requests(&tampered).is_err()
    );
}

#[test]
fn native_registration_partial_signature_groups_same_key_roles_per_input() {
    let secret = [73u8; 32];
    let secp = secp256k1::Secp256k1::new();
    let secret_key = secp256k1::SecretKey::from_slice(&secret).unwrap();
    let public_key = secp256k1::Keypair::from_secret_key(&secp, &secret_key)
        .x_only_public_key()
        .0;
    let public_hex = hex::encode(public_key.serialize());
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../examples/namespace-child-registration-v6-cli-parity-v1-vector.json"
    ))
    .unwrap();
    let mut request = native_registration_input(&fixture["manifest"]["transaction_input"]);
    request["inputs"][2]["script_public_key"] = json!(format!("000020{public_hex}ac"));
    for role in ["parent", "claimant", "target", "parent_for_child", "fee"] {
        request["role_public_keys"][role] = json!(public_hex);
    }
    let plan = ktapeout_cli::tn10_pipeline::build_native_registration_plan(&request).unwrap();
    let key_review =
        ktapeout_cli::tn10_developer_signing::native_registration_key_review(&plan, secret)
            .unwrap();
    assert_eq!(key_review["identity_mode"], "SAME_KEY");
    assert_eq!(key_review["matching_roles"].as_array().unwrap().len(), 5);
    assert!(key_review["role_checks"]
        .as_array()
        .unwrap()
        .iter()
        .all(|check| check["matches"] == true));
    let total = plan["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|input| input["amount"].as_u64().unwrap())
        .sum::<u64>();
    let authorization = json!({
        "schema":"KTAPEOUT-TN10-REGISTRATION-AUTHORIZATION-V1",
        "network":"testnet-10",
        "plan_sha256":plan["plan_sha256"],
        "role_public_keys":plan["role_public_keys"],
        "cumulative_amount_limit_sompi":total,
        "fee_limit_sompi":plan["fee_sompi"],
        "fee_source":"live_dual_node_quote",
        "fee_quote_sha256":"aa".repeat(32),
        "created_at_unix":1000u64,
        "expires_at_unix":2000u64,
        "allow_broadcast":true,
        "allow_readback":true,
        "confirmation_method":"TERMINAL_TYPED_PLAN_DIGEST",
        "created_with_terminal_confirmation":true
    });
    let packet = ktapeout_cli::tn10_developer_signing::sign_native_registration_partial(
        &plan,
        &authorization,
        secret,
        1500,
        &format!("SIGN {}", plan["plan_sha256"].as_str().unwrap()),
    )
    .expect("one key can sign its matching roles without collapsing input slots");
    assert_eq!(packet["native_plan_hash"], plan["plan_sha256"]);
    assert_eq!(packet["signatures"].as_array().unwrap().len(), 3);
    assert_eq!(
        packet["signatures"][0]["roles"].as_array().unwrap().len(),
        1
    );
    assert_eq!(
        packet["signatures"][1]["roles"].as_array().unwrap().len(),
        3
    );
    assert_eq!(
        packet["signatures"][2]["roles"].as_array().unwrap().len(),
        1
    );
    assert_eq!(packet["witness_assembly"], "PENDING_COVENANT_CONTEXT");
    assert_eq!(packet["broadcast"], false);
    assert!(
        ktapeout_cli::tn10_developer_signing::sign_native_registration_partial(
            &plan,
            &authorization,
            secret,
            1500,
            "SIGN wrong-digest"
        )
        .is_err()
    );
    assert!(
        ktapeout_cli::tn10_developer_signing::sign_native_registration_partial(
            &plan,
            &authorization,
            [74u8; 32],
            1500,
            &format!("SIGN {}", plan["plan_sha256"].as_str().unwrap())
        )
        .is_err()
    );
    assert!(
        ktapeout_cli::tn10_developer_signing::sign_native_registration_partial(
            &plan,
            &json!({}),
            secret,
            1500,
            &format!("SIGN {}", plan["plan_sha256"].as_str().unwrap())
        )
        .is_err()
    );
    let mut expired = authorization.clone();
    expired["expires_at_unix"] = json!(1499u64);
    assert!(
        ktapeout_cli::tn10_developer_signing::sign_native_registration_partial(
            &plan,
            &expired,
            secret,
            1500,
            &format!("SIGN {}", plan["plan_sha256"].as_str().unwrap())
        )
        .is_err()
    );
}

#[test]
fn native_registration_partial_signature_packets_merge_per_role_and_reject_incomplete_sets() {
    let secrets = [[73u8; 32], [75u8; 32], [76u8; 32], [77u8; 32]];
    let secp = secp256k1::Secp256k1::new();
    let public_keys = secrets.map(|secret| {
        let key = secp256k1::SecretKey::from_slice(&secret).unwrap();
        hex::encode(
            secp256k1::Keypair::from_secret_key(&secp, &key)
                .x_only_public_key()
                .0
                .serialize(),
        )
    });
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../examples/namespace-child-registration-v6-cli-parity-v1-vector.json"
    ))
    .unwrap();
    let mut request = native_registration_input(&fixture["manifest"]["transaction_input"]);
    request["inputs"][2]["script_public_key"] = json!(format!("000020{}ac", public_keys[3]));
    request["role_public_keys"] = json!({
        "parent":public_keys[0],
        "claimant":public_keys[1],
        "target":public_keys[2],
        "parent_for_child":public_keys[1],
        "fee":public_keys[3]
    });
    let plan = ktapeout_cli::tn10_pipeline::build_native_registration_plan(&request).unwrap();
    let key_review =
        ktapeout_cli::tn10_developer_signing::native_registration_key_review(&plan, secrets[1])
            .unwrap();
    assert_eq!(key_review["identity_mode"], "DIFFERENT_KEY");
    assert_eq!(
        key_review["matching_roles"],
        json!(["claimant", "parent_for_child"])
    );
    assert!(key_review["role_checks"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|check| check["role"] == "claimant" || check["role"] == "parent_for_child")
        .all(|check| check["matches"] == true));
    let total = plan["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|input| input["amount"].as_u64().unwrap())
        .sum::<u64>();
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let authorization = json!({
        "schema":"KTAPEOUT-TN10-REGISTRATION-AUTHORIZATION-V1",
        "network":"testnet-10",
        "plan_sha256":plan["plan_sha256"],
        "role_public_keys":plan["role_public_keys"],
        "cumulative_amount_limit_sompi":total,
        "fee_limit_sompi":plan["fee_sompi"],
        "fee_source":"live_dual_node_quote",
        "fee_quote_sha256":"aa".repeat(32),
        "created_at_unix":now_unix - 60,
        "expires_at_unix":now_unix + 3600,
        "allow_broadcast":true,
        "allow_readback":true,
        "confirmation_method":"TERMINAL_TYPED_PLAN_DIGEST",
        "created_with_terminal_confirmation":true
    });
    let confirmation = format!("SIGN {}", plan["plan_sha256"].as_str().unwrap());
    let packets = secrets
        .iter()
        .map(|secret| {
            ktapeout_cli::tn10_developer_signing::sign_native_registration_partial(
                &plan,
                &authorization,
                *secret,
                now_unix,
                &confirmation,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let complete = ktapeout_cli::tn10_developer_signing::combine_native_registration_partials(
        &plan,
        &authorization,
        &packets,
        now_unix,
    )
    .expect("all roles from distinct keys should combine");
    assert_eq!(complete["signatures"].as_array().unwrap().len(), 5);
    assert_eq!(complete["witness_assembly"], "ASSEMBLED_TOCCATA_INPUTS");
    assert_eq!(complete["plan"]["plan_sha256"], plan["plan_sha256"]);
    assert_eq!(
        complete["authorization"]["plan_sha256"],
        plan["plan_sha256"]
    );
    let assembled_inputs = complete["transaction"]["inputs"].as_array().unwrap();
    assert_eq!(assembled_inputs.len(), 3);
    assert!(assembled_inputs
        .iter()
        .all(|input| !input["signatureScript"].as_str().unwrap().is_empty()));
    for input_index in 0..2 {
        let script = hex::decode(
            assembled_inputs[input_index]["signatureScript"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        assert!(
            script.len() > 300,
            "covenant input {input_index} uses PUSHDATA2 witness"
        );
        assert_eq!(script.last(), Some(&[0x51, 0x52][input_index]));
    }
    assert_eq!(complete["broadcast"], false);

    struct NativeSubmitAck(String);
    impl Transport for NativeSubmitAck {
        fn submit(&mut self, _: &RpcTransaction) -> Result<String, String> {
            Ok(self.0.clone())
        }
        fn read_transaction(&mut self, _: &str) -> Result<Option<Value>, String> {
            Ok(None)
        }
    }
    let complete_tx: RpcTransaction =
        serde_json::from_value(complete["transaction"].clone()).unwrap();
    let complete_txid = Transaction::try_from(complete_tx).unwrap().id().to_string();
    let scratch = std::env::temp_dir().join(format!(
        "ktape-native-assemble-submit-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&scratch).unwrap();
    let assembled_path = scratch.join("assembled.json");
    let plan_path = scratch.join("plan.json");
    let authorization_path = scratch.join("authorization.json");
    std::fs::write(&plan_path, serde_json::to_vec(&plan).unwrap()).unwrap();
    std::fs::write(
        &authorization_path,
        serde_json::to_vec(&authorization).unwrap(),
    )
    .unwrap();
    let partial_paths = packets
        .iter()
        .enumerate()
        .map(|(index, packet)| {
            let path = scratch.join(format!("partial-{index}.json"));
            std::fs::write(&path, serde_json::to_vec(packet).unwrap()).unwrap();
            path
        })
        .collect::<Vec<_>>();
    let mut assemble = std::process::Command::new(env!("CARGO_BIN_EXE_ktape"));
    assemble.args([
        "tn10",
        "assemble",
        plan_path.to_str().unwrap(),
        assembled_path.to_str().unwrap(),
        "--authorization",
        authorization_path.to_str().unwrap(),
    ]);
    for partial in &partial_paths {
        assemble.args(["--partial", partial.to_str().unwrap()]);
    }
    let assemble_output = assemble.output().expect("run ktape tn10 assemble");
    assert!(
        assemble_output.status.success(),
        "assemble failed: {}",
        String::from_utf8_lossy(&assemble_output.stderr)
    );
    let cli_aggregate: Value =
        serde_json::from_slice(&std::fs::read(&assembled_path).unwrap()).unwrap();
    assert_eq!(cli_aggregate, complete);
    let receipt_path = scratch.join("submit.json");
    let submit_result = ktapeout_cli::tn10_pipeline::submit_with_transport_retry_at(
        &assembled_path,
        &receipt_path,
        false,
        now_unix,
        &mut NativeSubmitAck(complete_txid.clone()),
    );
    assert!(
        submit_result.is_ok(),
        "the public submit path must accept the assembled native transaction: {submit_result:?}"
    );
    let receipt: Value = serde_json::from_slice(&std::fs::read(&receipt_path).unwrap()).unwrap();
    assert_eq!(receipt["status"], "SUBMITTED");
    assert_eq!(receipt["txid"], complete_txid);
    let mut tampered_aggregate = complete.clone();
    tampered_aggregate["authorization"]["expires_at_unix"] = json!(1400u64);
    let tampered_path = scratch.join("tampered.json");
    let rejected_receipt = scratch.join("rejected-submit.json");
    std::fs::write(
        &tampered_path,
        serde_json::to_vec(&tampered_aggregate).unwrap(),
    )
    .unwrap();
    let mut should_not_submit = NativeSubmitAck(complete_txid.clone());
    assert_eq!(
        ktapeout_cli::tn10_pipeline::submit_with_transport_retry_at(
            &tampered_path,
            &rejected_receipt,
            false,
            now_unix,
            &mut should_not_submit,
        )
        .unwrap_err()
        .to_string(),
        "TN10_REGISTRATION_AUTHORIZATION_EXPIRED"
    );
    assert!(!rejected_receipt.exists());
    let submitted_tx = complete["transaction"].clone();
    let mut readback_a = RegistrationReadbackMock {
        result: Ok(Some(submitted_tx.clone())),
    };
    let mut readback_b = RegistrationReadbackMock {
        result: Ok(Some(submitted_tx.clone())),
    };
    let readback =
        ktapeout_cli::tn10_pipeline::reconcile_native_registration_readback_with_transports(
            &plan,
            &submitted_tx,
            &complete_txid,
            &mut readback_a,
            &mut readback_b,
        )
        .unwrap();
    assert_eq!(readback["status"], "FOUND_BOTH_MATCH");
    assert_eq!(readback["plan_sha256"], plan["plan_sha256"]);
    std::fs::remove_dir_all(scratch).unwrap();

    let missing = &packets[..3];
    assert!(
        ktapeout_cli::tn10_developer_signing::combine_native_registration_partials(
            &plan,
            &authorization,
            missing,
            1500,
        )
        .is_err()
    );
    let duplicate = vec![
        packets[0].clone(),
        packets[0].clone(),
        packets[1].clone(),
        packets[2].clone(),
        packets[3].clone(),
    ];
    assert!(
        ktapeout_cli::tn10_developer_signing::combine_native_registration_partials(
            &plan,
            &authorization,
            &duplicate,
            1500,
        )
        .is_err()
    );
    let mut wrong_digest = packets.clone();
    wrong_digest[0]["native_plan_hash"] = json!("00".repeat(32));
    assert!(
        ktapeout_cli::tn10_developer_signing::combine_native_registration_partials(
            &plan,
            &authorization,
            &wrong_digest,
            1500,
        )
        .is_err()
    );
    let mut wrong_role_key = packets.clone();
    wrong_role_key[0]["signatures"][0]["roles"] = json!(["target"]);
    assert!(
        ktapeout_cli::tn10_developer_signing::combine_native_registration_partials(
            &plan,
            &authorization,
            &wrong_role_key,
            1500,
        )
        .is_err()
    );
    let mut bad_signature = packets.clone();
    let mut signature = bad_signature[0]["signatures"][0]["signature"]
        .as_str()
        .unwrap()
        .to_owned();
    let last = signature.pop().unwrap();
    signature.push(if last == '0' { '1' } else { '0' });
    bad_signature[0]["signatures"][0]["signature"] = json!(signature);
    assert!(
        ktapeout_cli::tn10_developer_signing::combine_native_registration_partials(
            &plan,
            &authorization,
            &bad_signature,
            1500,
        )
        .is_err()
    );
    assert!(
        ktapeout_cli::tn10_developer_signing::combine_native_registration_partials(
            &plan,
            &authorization,
            &packets,
            2001,
        )
        .is_err()
    );
}

#[test]
fn three_real_registrations_use_one_kas_name_deed_outputs_with_ten_kas_state_bond() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../examples/namespace-child-registration-v6-cli-parity-v1-vector.json"
    ))
    .unwrap();
    let tx_input = &fixture["manifest"]["transaction_input"];
    let real_txids = [
        "9eddc2cec1302e63a6ea1adca815186476e2a9dc2ed65c4b1c070b2603e5a354",
        "d385ea5bc95d6e134005754a9def12094812ce386c32d398b6ac205592f27d24",
        "97c95fb189f7ad1ce97af1d437f86534c234264ab61a5d6ac870971aec912454",
    ];
    for txid in real_txids {
        let mut request = native_registration_input(tx_input);
        request["evidence_txid"] = json!(txid);
        let plan = ktapeout_cli::tn10_pipeline::build_native_registration_plan(&request)
            .unwrap_or_else(|error| panic!("{txid}: {error}"));
        assert_eq!(plan["outputs"][2]["role"], "name_deed", "{txid}");
        assert_eq!(plan["outputs"][2]["value"], 100_000_000u64, "{txid}");
        assert_eq!(plan["deed_state_bond_sompi"], 1_000_000_000u64, "{txid}");
    }
}

#[test]
fn native_registration_signing_packet_is_recomputed_from_the_immutable_plan() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../examples/namespace-child-registration-v6-cli-parity-v1-vector.json"
    ))
    .expect("pinned native registration vector");
    let tx_input = &fixture["manifest"]["transaction_input"];
    let request = native_registration_input(tx_input);
    let plan = ktapeout_cli::tn10_pipeline::build_native_registration_plan(&request).unwrap();
    let packet = ktapeout_cli::tn10_pipeline::build_native_registration_signing_packet(&plan)
        .expect("valid unsigned registration plan becomes a review packet");

    assert_eq!(
        packet["schema"],
        "KTAPEOUT-TN10-REGISTRATION-SIGNING-PACKET-V3"
    );
    assert_eq!(packet["network"], "testnet-10");
    assert_eq!(packet["plan_sha256"], plan["plan_sha256"]);
    assert_eq!(packet["local_signing_allowed"], false);
    assert_eq!(packet["broadcast"], false);
    assert_eq!(packet["role_public_keys"], plan["role_public_keys"]);
    assert_eq!(packet["witness_templates"], plan["witness_templates"]);
    assert!(
        ktapeout_cli::tn10_pipeline::verify_native_registration_signing_packet(&plan, &packet)
            .is_ok()
    );

    let mut changed_output = packet.clone();
    changed_output["transaction"]["outputs"][0]["value"] = json!(
        changed_output["transaction"]["outputs"][0]["value"]
            .as_u64()
            .unwrap()
            + 1
    );
    assert_eq!(
        ktapeout_cli::tn10_pipeline::verify_native_registration_signing_packet(
            &plan,
            &changed_output
        )
        .unwrap_err()
        .to_string(),
        "REGISTRY_SIGNING_PACKET_MISMATCH"
    );

    let mut changed_plan = plan.clone();
    changed_plan["outputs"][4]["value"] =
        json!(changed_plan["outputs"][4]["value"].as_u64().unwrap() - 1);
    assert!(
        ktapeout_cli::tn10_pipeline::build_native_registration_signing_packet(&changed_plan)
            .is_err()
    );
}

#[test]
fn native_registration_signing_packet_escrow_requires_two_verified_copies() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../examples/namespace-child-registration-v6-cli-parity-v1-vector.json"
    ))
    .expect("pinned native registration vector");
    let tx_input = &fixture["manifest"]["transaction_input"];
    let plan = ktapeout_cli::tn10_pipeline::build_native_registration_plan(
        &native_registration_input(tx_input),
    )
    .unwrap();
    let root = std::env::temp_dir().join(format!(
        "ktape-registry-escrow-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let first = root.join("first");
    let second = root.join("second");
    let files = ktapeout_cli::tn10_pipeline::escrow_native_registration_signing_packet(
        &plan,
        &[first.clone(), second.clone()],
    )
    .expect("write and read back two independent escrow copies");
    assert_eq!(files.len(), 2);
    assert!(
        ktapeout_cli::tn10_pipeline::require_native_registration_signing_packet_escrow(
            &plan, &files
        )
        .is_ok()
    );
    assert_eq!(
        ktapeout_cli::tn10_pipeline::escrow_native_registration_signing_packet(
            &plan,
            &[first.clone(), first.clone()]
        )
        .unwrap_err()
        .to_string(),
        "REGISTRY_ESCROW_TWO_DISTINCT_DESTINATIONS_REQUIRED"
    );

    let first_file = &files[0];
    let mut corrupt: Value = serde_json::from_slice(&std::fs::read(first_file).unwrap()).unwrap();
    corrupt["outputs"][0]["value"] = json!(corrupt["outputs"][0]["value"].as_u64().unwrap() + 1);
    let corrupt_bytes = serde_json::to_vec(&corrupt).unwrap();
    std::fs::write(first_file, &corrupt_bytes).unwrap();
    assert_eq!(
        ktapeout_cli::tn10_pipeline::escrow_native_registration_signing_packet(
            &plan,
            &[first.clone(), second.clone()]
        )
        .unwrap_err()
        .to_string(),
        "REGISTRY_SIGNING_PACKET_MISMATCH",
        "escrow must reject a conflicting existing packet instead of replacing it"
    );
    assert_eq!(
        std::fs::read(first_file).unwrap(),
        corrupt_bytes,
        "a failed escrow attempt must leave the existing file unchanged"
    );
    assert_eq!(
        ktapeout_cli::tn10_pipeline::require_native_registration_signing_packet_escrow(
            &plan, &files
        )
        .unwrap_err()
        .to_string(),
        "REGISTRY_SIGNING_PACKET_MISMATCH"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn native_registration_approval_review_is_recomputed_from_plan_and_packet() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../examples/namespace-child-registration-v6-cli-parity-v1-vector.json"
    ))
    .unwrap();
    let tx_input = &fixture["manifest"]["transaction_input"];
    let plan = ktapeout_cli::tn10_pipeline::build_native_registration_plan(
        &native_registration_input(tx_input),
    )
    .unwrap();
    let packet =
        ktapeout_cli::tn10_pipeline::build_native_registration_signing_packet(&plan).unwrap();
    let review =
        ktapeout_cli::tn10_pipeline::build_native_registration_approval_review(&plan, &packet)
            .unwrap();
    assert!(
        ktapeout_cli::tn10_pipeline::verify_native_registration_approval_review(
            &plan, &packet, &review
        )
        .is_ok()
    );
    assert_eq!(review["role_public_keys"], plan["role_public_keys"]);
    assert_eq!(review["covenant_utxos"], plan["covenant_utxos"]);
    let mut altered = review.clone();
    altered["fee_sompi"] = json!(review["fee_sompi"].as_u64().unwrap() + 1);
    assert_eq!(
        ktapeout_cli::tn10_pipeline::verify_native_registration_approval_review(
            &plan, &packet, &altered
        )
        .unwrap_err()
        .to_string(),
        "REGISTRY_APPROVAL_REVIEW_MISMATCH"
    );
    let mut changed_packet = packet.clone();
    changed_packet["plan_sha256"] = json!("00".repeat(32));
    assert!(
        ktapeout_cli::tn10_pipeline::build_native_registration_approval_review(
            &plan,
            &changed_packet
        )
        .is_err()
    );
}

struct RegistrationReadbackMock {
    result: Result<Option<Value>, String>,
}

struct SubmitAckMock(String);

impl Transport for SubmitAckMock {
    fn submit(&mut self, _: &RpcTransaction) -> Result<String, String> {
        Ok(self.0.clone())
    }

    fn read_transaction(&mut self, _: &str) -> Result<Option<Value>, String> {
        Ok(None)
    }
}

struct SubmitUnknownMock;

impl Transport for SubmitUnknownMock {
    fn submit(&mut self, _: &RpcTransaction) -> Result<String, String> {
        Err("mock acknowledgement lost".into())
    }

    fn read_transaction(&mut self, _: &str) -> Result<Option<Value>, String> {
        panic!("submission transport does not perform readback")
    }
}

impl ktapeout_cli::tn10_pipeline::Transport for RegistrationReadbackMock {
    fn submit(&mut self, _transaction: &kaspa_rpc_core::RpcTransaction) -> Result<String, String> {
        Err("SUBMIT_MUST_NOT_BE_CALLED".into())
    }

    fn read_transaction(&mut self, _txid: &str) -> Result<Option<Value>, String> {
        self.result.clone()
    }
}

#[test]
fn native_registration_readback_reconciles_two_nodes_without_submission() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../examples/namespace-child-registration-v6-cli-parity-v1-vector.json"
    ))
    .unwrap();
    let tx_input = &fixture["manifest"]["transaction_input"];
    let plan = ktapeout_cli::tn10_pipeline::build_native_registration_plan(
        &native_registration_input(tx_input),
    )
    .unwrap();
    let packet =
        ktapeout_cli::tn10_pipeline::build_native_registration_signing_packet(&plan).unwrap();
    let tx = packet["transaction"].clone();
    let txid =
        ktapeout_cli::tn10_pipeline::build_native_registration_approval_review(&plan, &packet)
            .unwrap()["txid"]
            .as_str()
            .unwrap()
            .to_owned();
    let mut first = RegistrationReadbackMock {
        result: Ok(Some(tx.clone())),
    };
    let mut second = RegistrationReadbackMock {
        result: Ok(Some(tx.clone())),
    };
    let receipt =
        ktapeout_cli::tn10_pipeline::reconcile_native_registration_readback_with_transports(
            &plan,
            &tx,
            &txid,
            &mut first,
            &mut second,
        )
        .unwrap();
    assert_eq!(receipt["status"], "FOUND_BOTH_MATCH");
    assert_eq!(receipt["finality"], "FINALITY_UNCHECKED");
    assert_eq!(receipt["operation"], "READBACK_ONLY");
    assert_eq!(receipt["broadcast_action"], "NOT_PERFORMED_BY_READBACK");

    let mut signed_tx = tx.clone();
    signed_tx["inputs"][0]["signatureScript"] = json!("00");
    let signed_native =
        Transaction::try_from(serde_json::from_value::<RpcTransaction>(signed_tx.clone()).unwrap())
            .unwrap();
    let signed_txid = signed_native.id().to_string();
    let mut signed_a = RegistrationReadbackMock {
        result: Ok(Some(signed_tx.clone())),
    };
    let mut signed_b = RegistrationReadbackMock {
        result: Ok(Some(signed_tx.clone())),
    };
    let signed_receipt =
        ktapeout_cli::tn10_pipeline::reconcile_native_registration_readback_with_transports(
            &plan,
            &signed_tx,
            &signed_txid,
            &mut signed_a,
            &mut signed_b,
        )
        .unwrap();
    assert_eq!(signed_receipt["status"], "FOUND_BOTH_MATCH");
    assert_eq!(
        signed_receipt["signature_validity"],
        "NOT_VERIFIED_BY_READBACK"
    );

    let mut absent_a = RegistrationReadbackMock { result: Ok(None) };
    let mut absent_b = RegistrationReadbackMock { result: Ok(None) };
    assert_eq!(
        ktapeout_cli::tn10_pipeline::reconcile_native_registration_readback_with_transports(
            &plan,
            &tx,
            &txid,
            &mut absent_a,
            &mut absent_b
        )
        .unwrap()["status"],
        "NOT_FOUND_BOTH_RETRY_REQUIRES_REVIEW"
    );

    let mut present = RegistrationReadbackMock {
        result: Ok(Some(tx.clone())),
    };
    let mut absent = RegistrationReadbackMock { result: Ok(None) };
    assert_eq!(
        ktapeout_cli::tn10_pipeline::reconcile_native_registration_readback_with_transports(
            &plan,
            &tx,
            &txid,
            &mut present,
            &mut absent
        )
        .unwrap_err()
        .to_string(),
        "TN10_DUAL_NODE_DISAGREEMENT"
    );

    let mut failed = RegistrationReadbackMock {
        result: Err("offline".into()),
    };
    let mut available = RegistrationReadbackMock {
        result: Ok(Some(tx.clone())),
    };
    assert_eq!(
        ktapeout_cli::tn10_pipeline::reconcile_native_registration_readback_with_transports(
            &plan,
            &tx,
            &txid,
            &mut failed,
            &mut available
        )
        .unwrap_err()
        .to_string(),
        "TN10_READBACK_RPC_FAILED"
    );

    let mut wrong = tx.clone();
    wrong["inputs"][0]["signatureScript"] = json!("00");
    let mut one = RegistrationReadbackMock {
        result: Ok(Some(tx.clone())),
    };
    let mut other = RegistrationReadbackMock {
        result: Ok(Some(wrong)),
    };
    assert_eq!(
        ktapeout_cli::tn10_pipeline::reconcile_native_registration_readback_with_transports(
            &plan, &tx, &txid, &mut one, &mut other
        )
        .unwrap_err()
        .to_string(),
        "TN10_DUAL_NODE_DISAGREEMENT"
    );
}

#[test]
fn native_registration_submission_reconciliation_binds_receipt_and_readback() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../examples/namespace-child-registration-v6-cli-parity-v1-vector.json"
    ))
    .unwrap();
    let tx_input = &fixture["manifest"]["transaction_input"];
    let plan = ktapeout_cli::tn10_pipeline::build_native_registration_plan(
        &native_registration_input(tx_input),
    )
    .unwrap();
    let packet =
        ktapeout_cli::tn10_pipeline::build_native_registration_signing_packet(&plan).unwrap();
    let transaction = packet["transaction"].clone();
    let review =
        ktapeout_cli::tn10_pipeline::build_native_registration_approval_review(&plan, &packet)
            .unwrap();
    let txid = review["txid"].as_str().unwrap();
    let submission = json!({
        "schema":"KTAPEOUT-TN10-REGISTRATION-SUBMIT-V1",
        "network":"testnet-10",
        "status":"SUBMISSION_UNKNOWN",
        "txid":txid,
        "plan_sha256":plan["plan_sha256"],
        "broadcast":"UNKNOWN"
    });
    let mut first = RegistrationReadbackMock {
        result: Ok(Some(transaction.clone())),
    };
    let mut second = RegistrationReadbackMock {
        result: Ok(Some(transaction.clone())),
    };
    let receipt =
        ktapeout_cli::tn10_pipeline::reconcile_native_registration_submission_with_transports(
            &plan,
            &submission,
            &transaction,
            txid,
            &mut first,
            &mut second,
        )
        .unwrap();
    assert_eq!(receipt["submission_state"], "SUBMISSION_UNKNOWN");
    assert_eq!(receipt["readback_status"], "FOUND_BOTH_MATCH");
    assert_eq!(receipt["predecessor_status"], "NOT_RECHECKED_BY_READBACK");
    assert_eq!(receipt["retry_authorized"], false);
    assert_eq!(receipt["finality"], "FINALITY_UNCHECKED");
    assert_eq!(
        receipt["predecessor_outpoints"].as_array().unwrap().len(),
        3
    );

    let mut absent_a = RegistrationReadbackMock { result: Ok(None) };
    let mut absent_b = RegistrationReadbackMock { result: Ok(None) };
    let unresolved =
        ktapeout_cli::tn10_pipeline::reconcile_native_registration_submission_with_transports(
            &plan,
            &submission,
            &transaction,
            txid,
            &mut absent_a,
            &mut absent_b,
        )
        .unwrap();
    assert_eq!(
        unresolved["readback_status"],
        "NOT_FOUND_BOTH_RETRY_REQUIRES_REVIEW"
    );
    assert_eq!(unresolved["retry_authorized"], false);

    let mut mismatched = submission.clone();
    mismatched["plan_sha256"] = json!("00".repeat(32));
    let mut no_read_a = RegistrationReadbackMock { result: Ok(None) };
    let mut no_read_b = RegistrationReadbackMock { result: Ok(None) };
    assert_eq!(
        ktapeout_cli::tn10_pipeline::reconcile_native_registration_submission_with_transports(
            &plan,
            &mismatched,
            &transaction,
            txid,
            &mut no_read_a,
            &mut no_read_b,
        )
        .unwrap_err()
        .to_string(),
        "TN10_REGISTRATION_SUBMISSION_RECEIPT_MISMATCH"
    );
}

fn namespace_candidate(namespace: &str) -> (Value, String) {
    let key = namespace_key(namespace).unwrap();
    namespace_candidate_for_key(namespace, &key)
}

fn namespace_candidate_for_key(namespace: &str, key_hex: &str) -> (Value, String) {
    let state_args = json!([
        key_hex,
        "11".repeat(32),
        "22".repeat(32),
        "33".repeat(32),
        7
    ]);
    let script = ktapeout_cli::registry_templates::render(
        ktapeout_cli::registry_templates::RegistryTemplate::AdapterParent,
        &[
            ktapeout_cli::registry_templates::ByteWrite {
                offset: 2,
                bytes: hex::decode(state_args[0].as_str().unwrap()).unwrap(),
            },
            ktapeout_cli::registry_templates::ByteWrite {
                offset: 35,
                bytes: hex::decode(state_args[1].as_str().unwrap()).unwrap(),
            },
            ktapeout_cli::registry_templates::ByteWrite {
                offset: 68,
                bytes: hex::decode(state_args[2].as_str().unwrap()).unwrap(),
            },
            ktapeout_cli::registry_templates::ByteWrite {
                offset: 101,
                bytes: hex::decode(state_args[3].as_str().unwrap()).unwrap(),
            },
            ktapeout_cli::registry_templates::ByteWrite {
                offset: 134,
                bytes: 7u64.to_le_bytes().to_vec(),
            },
        ],
    )
    .unwrap();
    let spk = format!(
        "0000aa20{}87",
        hex::encode(ktapeout_cli::name_state_template::blake2b_256(&script))
    );
    (json!({"namespace":namespace,"state_args":state_args}), spk)
}

#[test]
fn merged_namespace_keys_are_recomputed_and_dual_rpc_checked_per_key() {
    let baseline: Value = serde_json::from_str(BASELINE).unwrap();
    let candidates = baseline["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            namespace_candidate_for_key(
                entry["namespace"].as_str().unwrap(),
                entry["key_hex"].as_str().unwrap(),
            )
        })
        .collect::<Vec<_>>();
    let request = json!({
        "network":"testnet-10",
        "namespace_key_sources":[],
        "namespace_state_candidates":candidates.iter().map(|item| item.0.clone()).collect::<Vec<_>>(),
        "nodes":["wss://node-a.example/kaspa/testnet-10/wrpc/borsh","wss://node-b.example/kaspa/testnet-10/wrpc/borsh"]
    });
    let make_mock = |omit_last: bool| RegistryMock {
        entries: candidates
            .iter()
            .enumerate()
            .map(|(i, (_, spk))| {
                if omit_last && i == 2 {
                    json!([])
                } else {
                    state_utxo(spk, 100_000_000, 0x41 + i as u8)
                }
            })
            .collect(),
        index: 0,
        fail_read: false,
    };
    let result = ktapeout_cli::tn10_pipeline::verify_merged_namespace_keys_with_transports(
        &request,
        &mut make_mock(false),
        &mut make_mock(false),
    )
    .unwrap();
    assert_eq!(result["verified"].as_array().unwrap().len(), 3);
    assert!(result["verified"]
        .as_array()
        .unwrap()
        .iter()
        .all(|item| item["status"] == "TN10_DUAL_RPC_NAMESPACE_STATE_MATCH"));

    let mut below_floor_a = make_mock(false);
    let mut below_floor_b = make_mock(false);
    below_floor_a.entries[0] = state_utxo(&candidates[0].1, 99_999_999, 0x41);
    below_floor_b.entries[0] = state_utxo(&candidates[0].1, 99_999_999, 0x41);
    assert_eq!(
        ktapeout_cli::tn10_pipeline::verify_merged_namespace_keys_with_transports(
            &request,
            &mut below_floor_a,
            &mut below_floor_b
        )
        .unwrap_err()
        .to_string(),
        "TN10_REGISTRY_ADAPTER_PARENT_VALUE_BELOW_FLOOR"
    );

    let mut disagree = make_mock(false);
    disagree.entries[2] = json!([]);
    assert!(
        ktapeout_cli::tn10_pipeline::verify_merged_namespace_keys_with_transports(
            &request,
            &mut make_mock(false),
            &mut disagree
        )
        .unwrap_err()
        .to_string()
        .contains("TN10_UTXO_NODES_DISAGREE")
    );

    let mut failed = make_mock(false);
    failed.fail_read = true;
    assert!(
        ktapeout_cli::tn10_pipeline::verify_merged_namespace_keys_with_transports(
            &request,
            &mut failed,
            &mut make_mock(false)
        )
        .is_err()
    );

    assert!(
        ktapeout_cli::tn10_pipeline::verify_merged_namespace_keys_with_transports(
            &request,
            &mut make_mock(true),
            &mut make_mock(true)
        )
        .unwrap_err()
        .to_string()
        .contains("NAME_KEY_LIST_INCOMPLETE_OR_STALE")
    );

    let mut mismatched_state = request.clone();
    mismatched_state["namespace_state_candidates"][0]["state_args"][0] = json!("ff".repeat(32));
    assert!(
        ktapeout_cli::tn10_pipeline::verify_merged_namespace_keys_with_transports(
            &mismatched_state,
            &mut make_mock(false),
            &mut make_mock(false)
        )
        .unwrap_err()
        .to_string()
        .contains("NAME_KEY_LIST_INCOMPLETE_OR_STALE")
    );
}

#[test]
fn issued_namespace_key_entry_roundtrips_through_keys_file_and_dual_rpc() {
    let namespace = "m6-issuance-roundtrip";
    let source = list(json!([{
        "namespace": namespace,
        "key_hex": namespace_key(namespace).unwrap(),
        "evidence_ref": "kaspa:tn10:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    }]));
    let keys = ktapeout_cli::registered_keys::merged_namespace_keys(std::slice::from_ref(&source))
        .unwrap();
    let candidates = keys
        .iter()
        .map(|key| namespace_candidate(&key.namespace))
        .collect::<Vec<_>>();
    let request = json!({
        "network":"testnet-10",
        "namespace_key_sources":[source],
        "namespace_state_candidates":candidates.iter().map(|item| item.0.clone()).collect::<Vec<_>>(),
        "nodes":["wss://node-a.example/kaspa/testnet-10/wrpc/borsh","wss://node-b.example/kaspa/testnet-10/wrpc/borsh"]
    });
    let make_mock = || RegistryMock {
        entries: candidates
            .iter()
            .enumerate()
            .map(|(i, (_, spk))| state_utxo(spk, 100_000_000, 0x51 + i as u8))
            .collect(),
        index: 0,
        fail_read: false,
    };
    let verified = ktapeout_cli::tn10_pipeline::verify_merged_namespace_keys_with_transports(
        &request,
        &mut make_mock(),
        &mut make_mock(),
    )
    .unwrap();
    let entry = ktapeout_cli::registered_keys::namespace_key_entry_from_verification(
        namespace,
        &verified,
        Some("kaspa:tn10:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
    )
    .unwrap();
    assert_eq!(entry["namespace"], namespace);
    assert_eq!(entry["key_hex"], namespace_key(namespace).unwrap());
    assert_eq!(
        entry["evidence_ref"],
        "kaspa:tn10:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );

    let document = list(json!([entry]));
    let path = std::env::temp_dir().join(format!(
        "ktapeout-namespace-keys-{}-{}.json",
        std::process::id(),
        namespace
    ));
    std::fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
    let mut sources = Vec::new();
    ktapeout_cli::tn10_pipeline::load_namespace_key_files(
        &mut sources,
        std::slice::from_ref(&path),
        std::path::Path::new("request.json"),
        std::path::Path::new("plan.json"),
    )
    .unwrap();
    std::fs::remove_file(&path).unwrap();
    assert_eq!(sources, vec![document]);

    let mut imported_request = request;
    imported_request["namespace_key_sources"] = json!(sources);
    let imported = ktapeout_cli::tn10_pipeline::verify_merged_namespace_keys_with_transports(
        &imported_request,
        &mut make_mock(),
        &mut make_mock(),
    )
    .unwrap();
    assert_eq!(
        imported["status"],
        "TN10_DUAL_RPC_MERGED_NAMESPACE_KEYS_MATCH"
    );
    assert!(imported["verified"].as_array().unwrap().iter().any(|item| {
        item["namespace"] == namespace && item["namespace_key"] == namespace_key(namespace).unwrap()
    }));
}

#[test]
fn namespace_issuance_review_packet_is_recomputed_and_displays_role_key_identity() {
    let mut body = json!({
        "schema":"KTAPEOUT-NAMESPACE-ISSUANCE-BODY-V1",
        "network":"testnet-10",
        "verification_status":"UNVERIFIED_ON_CHAIN: \u{547d}\u{540d}\u{7a7a}\u{95f4}\u{53d1}\u{884c}\u{8ba1}\u{5212}\u{53ca}\u{5176}\u{6210}\u{672c}\u{5c1a}\u{672a}\u{7ecf}\u{8fc7}\u{771f}\u{5b9e} TN10 \u{9a8c}\u{8bc1}",
        "signing_allowed":false,
        "broadcast":false,
        "input_roles":["parent_namespace_state","root_gap","fee_input"],
        "output_roles":["parent_successor","root_left_gap","namespace_issuance_certificate","root_right_gap","fee_change"],
        "role_public_keys":{
            "namespace_authority":"11".repeat(32),
            "claimant":"11".repeat(32),
            "fee_input":"22".repeat(32)
        },
        "transaction":{"inputs":[{"signatureScript":"00"},{"signatureScript":"00"},{"signatureScript":"00"}],"outputs":[{"value":1}]},
        "economics":{"newly_locked_sompi":100000000,"fee_estimate_sompi":13637360},
        "permanent_warnings":["\u{6ca1}\u{6709}\u{9000}\u{8fd8}\u{8def}\u{5f84}","\u{4e22}\u{5931}\u{63a7}\u{5236}\u{5bc6}\u{94a5}\u{5c06}\u{6c38}\u{4e45}\u{5931}\u{53bb}\u{547d}\u{540d}\u{7a7a}\u{95f4}\u{63a7}\u{5236}\u{6743}","\u{7b2c}\u{4e00}\u{7248}\u{4e0d}\u{652f}\u{6301}\u{8f6c}\u{8ba9}\u{548c}\u{5173}\u{95ed}\u{547d}\u{540d}\u{7a7a}\u{95f4}"]
    });
    let prepared = json!({"plan_hash":ktapeout_cli::namespace_issuance_review::plan_hash(&body).unwrap(),"body":body});
    let packet = ktapeout_cli::namespace_issuance_review::build_review_packet(&prepared).unwrap();
    assert_eq!(packet["signing_allowed"], false);
    assert_eq!(packet["broadcast"], false);
    ktapeout_cli::namespace_issuance_review::verify_review_packet(&prepared, &packet).unwrap();
    let review =
        ktapeout_cli::namespace_issuance_review::build_approval_review(&prepared, &packet).unwrap();
    assert_eq!(review["status"], "REVIEW_ONLY_NO_APPROVAL");
    assert_eq!(
        review["role_key_relationships"][0]["relationship"],
        "SAME_KEY"
    );
    assert_eq!(
        review["role_key_relationships"][1]["relationship"],
        "DIFFERENT_KEY"
    );
    ktapeout_cli::namespace_issuance_review::verify_approval_review(&prepared, &packet, &review)
        .unwrap();

    let mut tampered_packet = packet.clone();
    tampered_packet["body"]["transaction"]["outputs"][0]["value"] = json!(2);
    assert!(
        ktapeout_cli::namespace_issuance_review::verify_review_packet(&prepared, &tampered_packet)
            .is_err()
    );
    let mut tampered_review = review.clone();
    tampered_review["role_key_relationships"][0]["relationship"] = json!("DIFFERENT_KEY");
    assert!(
        ktapeout_cli::namespace_issuance_review::verify_approval_review(
            &prepared,
            &packet,
            &tampered_review
        )
        .is_err()
    );

    body["signing_allowed"] = json!(true);
    let invalid = json!({"plan_hash":ktapeout_cli::namespace_issuance_review::plan_hash(&body).unwrap(),"body":body});
    assert_eq!(
        ktapeout_cli::namespace_issuance_review::build_review_packet(&invalid)
            .unwrap_err()
            .to_string(),
        "NAMESPACE_ISSUANCE_UNVERIFIED_SIGNING_DISABLED"
    );
}

#[test]
fn namespace_issuance_review_escrow_requires_two_roots_and_signing_stays_closed() {
    let body = json!({
        "schema":"KTAPEOUT-NAMESPACE-ISSUANCE-BODY-V1",
        "network":"testnet-10",
        "verification_status":"UNVERIFIED_ON_CHAIN: \u{547d}\u{540d}\u{7a7a}\u{95f4}\u{53d1}\u{884c}\u{8ba1}\u{5212}\u{53ca}\u{5176}\u{6210}\u{672c}\u{5c1a}\u{672a}\u{7ecf}\u{8fc7}\u{771f}\u{5b9e} TN10 \u{9a8c}\u{8bc1}",
        "signing_allowed":false,
        "broadcast":false,
        "role_public_keys":{"namespace_authority":"11".repeat(32),"claimant":"11".repeat(32),"fee_input":"22".repeat(32)},
        "transaction":{"inputs":[],"outputs":[]},
        "permanent_warnings":["\u{6ca1}\u{6709}\u{9000}\u{8fd8}\u{8def}\u{5f84}","\u{4e22}\u{5931}\u{63a7}\u{5236}\u{5bc6}\u{94a5}\u{5c06}\u{6c38}\u{4e45}\u{5931}\u{53bb}\u{547d}\u{540d}\u{7a7a}\u{95f4}\u{63a7}\u{5236}\u{6743}","\u{7b2c}\u{4e00}\u{7248}\u{4e0d}\u{652f}\u{6301}\u{8f6c}\u{8ba9}\u{548c}\u{5173}\u{95ed}\u{547d}\u{540d}\u{7a7a}\u{95f4}"]
    });
    let prepared = json!({"plan_hash":ktapeout_cli::namespace_issuance_review::plan_hash(&body).unwrap(),"body":body});
    assert_eq!(
        ktapeout_cli::namespace_issuance_review::require_signing_authorized(&prepared).unwrap_err(),
        "NAMESPACE_ISSUANCE_UNVERIFIED_SIGNING_DISABLED"
    );
    assert_eq!(
        ktapeout_cli::namespace_issuance_review::require_chain_submission_enabled(&prepared)
            .unwrap_err(),
        "NAMESPACE_ISSUANCE_UNVERIFIED_SUBMISSION_DISABLED"
    );

    let base = std::env::temp_dir().join(format!("ktape-issuance-review-{}", std::process::id()));
    let a = base.join("a");
    let b = base.join("b");
    let paths = ktapeout_cli::namespace_issuance_review::escrow_review_packet(
        &prepared,
        &[a.clone(), b.clone()],
    )
    .unwrap();
    assert_eq!(paths.len(), 2);
    assert_eq!(
        ktapeout_cli::namespace_issuance_review::escrow_review_packet(
            &prepared,
            &[a.clone(), a.clone()]
        )
        .unwrap_err(),
        "NAMESPACE_ISSUANCE_ESCROW_TWO_DISTINCT_DESTINATIONS_REQUIRED"
    );
    assert!(paths.iter().all(|path| path.exists()));
    std::fs::remove_dir_all(base).unwrap();
}

#[test]
fn namespace_issuance_review_reports_unprovided_role_keys_without_inference() {
    let body = json!({
        "schema":"KTAPEOUT-NAMESPACE-ISSUANCE-BODY-V1",
        "network":"testnet-10",
        "verification_status":"UNVERIFIED_ON_CHAIN: \u{547d}\u{540d}\u{7a7a}\u{95f4}\u{53d1}\u{884c}\u{8ba1}\u{5212}\u{53ca}\u{5176}\u{6210}\u{672c}\u{5c1a}\u{672a}\u{7ecf}\u{8fc7}\u{771f}\u{5b9e} TN10 \u{9a8c}\u{8bc1}",
        "signing_allowed":false,
        "broadcast":false,
        "role_public_keys":{"namespace_authority":"11".repeat(32),"claimant":"11".repeat(32),"fee_input":null},
        "transaction":{"inputs":[],"outputs":[]},
        "permanent_warnings":["\u{6ca1}\u{6709}\u{9000}\u{8fd8}\u{8def}\u{5f84}","\u{4e22}\u{5931}\u{63a7}\u{5236}\u{5bc6}\u{94a5}\u{5c06}\u{6c38}\u{4e45}\u{5931}\u{53bb}\u{547d}\u{540d}\u{7a7a}\u{95f4}\u{63a7}\u{5236}\u{6743}","\u{7b2c}\u{4e00}\u{7248}\u{4e0d}\u{652f}\u{6301}\u{8f6c}\u{8ba9}\u{548c}\u{5173}\u{95ed}\u{547d}\u{540d}\u{7a7a}\u{95f4}"]
    });
    let prepared = json!({"plan_hash":ktapeout_cli::namespace_issuance_review::plan_hash(&body).unwrap(),"body":body});
    let packet = ktapeout_cli::namespace_issuance_review::build_review_packet(&prepared).unwrap();
    let review =
        ktapeout_cli::namespace_issuance_review::build_approval_review(&prepared, &packet).unwrap();
    assert_eq!(review["role_public_keys"][2]["role"], "fee_input");
    assert_eq!(review["role_public_keys"][2]["public_key"], Value::Null);
    assert_eq!(
        review["role_public_keys"][2]["status"],
        "NOT_PRESENT_IN_PLAN"
    );
    assert_eq!(
        review["role_key_relationships"][1]["relationship"],
        "UNAVAILABLE"
    );
}

#[test]
fn namespace_issuance_submission_reconciliation_reuses_dual_rpc_readback_only() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../examples/namespace-child-registration-v6-cli-parity-v1-vector.json"
    ))
    .unwrap();
    let tx_input = &fixture["manifest"]["transaction_input"];
    let child_plan = ktapeout_cli::tn10_pipeline::build_native_registration_plan(
        &native_registration_input(tx_input),
    )
    .unwrap();
    let packet =
        ktapeout_cli::tn10_pipeline::build_native_registration_signing_packet(&child_plan).unwrap();
    let transaction = packet["transaction"].clone();
    let approval = ktapeout_cli::tn10_pipeline::build_native_registration_approval_review(
        &child_plan,
        &packet,
    )
    .unwrap();
    let txid = approval["txid"].as_str().unwrap();
    let body = json!({
        "schema":"KTAPEOUT-NAMESPACE-ISSUANCE-BODY-V1",
        "network":"testnet-10",
        "verification_status":"UNVERIFIED_ON_CHAIN: \u{547d}\u{540d}\u{7a7a}\u{95f4}\u{53d1}\u{884c}\u{8ba1}\u{5212}\u{53ca}\u{5176}\u{6210}\u{672c}\u{5c1a}\u{672a}\u{7ecf}\u{8fc7}\u{771f}\u{5b9e} TN10 \u{9a8c}\u{8bc1}",
        "signing_allowed":false,
        "broadcast":false,
        "role_public_keys":{"namespace_authority":"11".repeat(32),"claimant":"11".repeat(32),"fee_input":"22".repeat(32)},
        "transaction":transaction,
        "permanent_warnings":["\u{6ca1}\u{6709}\u{9000}\u{8fd8}\u{8def}\u{5f84}","\u{4e22}\u{5931}\u{63a7}\u{5236}\u{5bc6}\u{94a5}\u{5c06}\u{6c38}\u{4e45}\u{5931}\u{53bb}\u{547d}\u{540d}\u{7a7a}\u{95f4}\u{63a7}\u{5236}\u{6743}","\u{7b2c}\u{4e00}\u{7248}\u{4e0d}\u{652f}\u{6301}\u{8f6c}\u{8ba9}\u{548c}\u{5173}\u{95ed}\u{547d}\u{540d}\u{7a7a}\u{95f4}"]
    });
    let prepared = json!({"plan_hash":ktapeout_cli::namespace_issuance_review::plan_hash(&body).unwrap(),"body":body});
    let submission = json!({
        "schema":"KTAPEOUT-TN10-NAMESPACE-ISSUANCE-SUBMIT-V1",
        "network":"testnet-10",
        "status":"SUBMISSION_UNKNOWN",
        "plan_hash":prepared["plan_hash"],
        "txid":txid
    });
    let mut first = RegistrationReadbackMock {
        result: Ok(Some(transaction.clone())),
    };
    let mut second = RegistrationReadbackMock {
        result: Ok(Some(transaction.clone())),
    };
    let result = ktapeout_cli::namespace_issuance_review::reconcile_submission_with_transports(
        &prepared,
        &submission,
        &transaction,
        txid,
        &mut first,
        &mut second,
    )
    .unwrap();
    assert_eq!(result["status"], "FOUND_BOTH_MATCH");
    assert_eq!(result["signature_validity"], "NOT_VERIFIED_BY_READBACK");
    assert_eq!(result["finality"], "FINALITY_UNCHECKED");
    assert_eq!(result["broadcast_action"], "NOT_PERFORMED_BY_READBACK");
}

#[test]
fn registry_economics_names_state_bond_and_output_lock_separately() {
    let economics: Value = serde_json::from_str(include_str!(
        "../../../data/registry/registry-economics-v1.json"
    ))
    .unwrap();
    assert_eq!(economics["deed_state_bond_sompi"], 1_000_000_000u64);
    assert_eq!(economics["name_deed_output_sompi"], 100_000_000u64);
    assert_eq!(economics["adapter_gap_floor_sompi"], 100_000_000u64);
    assert!(economics.get("namespace_deed_bond_sompi").is_none());
}

#[test]
fn https_key_list_fetch_is_bounded_and_fail_closed_without_network() {
    let url = "https://keys.example/keys.json";
    let valid = list(json!([{
        "namespace":"myspace",
        "key_hex":namespace_key("myspace").unwrap()
    }]));
    let body = serde_json::to_vec(&valid).unwrap();

    let oversized = fetch_key_list_with(url, |_| Ok((200, vec![b' '; 64 * 1024 + 1])));
    assert_eq!(oversized.unwrap_err(), "NAME_KEY_URL_RESPONSE_TOO_LARGE");

    let timeout_body = body.clone();
    let timeout = fetch_key_list_with_timeout(url, Duration::from_millis(5), move |_| {
        std::thread::sleep(Duration::from_millis(30));
        Ok((200, timeout_body))
    });
    assert_eq!(timeout.unwrap_err(), "NAME_KEY_URL_TIMEOUT");

    assert_eq!(
        fetch_key_list_with("http://keys.example/keys.json", |_| unreachable!()).unwrap_err(),
        "NAME_KEY_URL_HTTPS_REQUIRED"
    );
    assert_eq!(
        fetch_key_list_with("https://user@keys.example/keys.json", |_| unreachable!()).unwrap_err(),
        "NAME_KEY_URL_INVALID"
    );

    let redirect = fetch_key_list_with(url, |_| Ok((302, Vec::new())));
    assert_eq!(redirect.unwrap_err(), "NAME_KEY_URL_REDIRECT_REJECTED");

    let malformed = fetch_key_list_with(url, |_| Ok((200, b"{".to_vec())));
    assert_eq!(malformed.unwrap_err(), "NAME_KEY_LIST_INVALID");

    let mismatched = list(json!([{"namespace":"myspace","key_hex":"00".repeat(32)}]));
    let mismatch_body = serde_json::to_vec(&mismatched).unwrap();
    assert_eq!(
        fetch_key_list_with(url, |_| Ok((200, mismatch_body))).unwrap_err(),
        "NAME_KEY_LIST_INCOMPLETE_OR_STALE"
    );

    let empty = list(json!([]));
    let empty_body = serde_json::to_vec(&empty).unwrap();
    let fetched = fetch_key_list_with(url, |_| Ok((200, empty_body))).unwrap();
    assert_eq!(parse_list(&fetched).unwrap().len(), 0);
    assert_eq!(
        plan_registration(RegistrationPlanInput {
            network: "testnet-10",
            namespace: "myspace",
            slug: "notes",
            owner: "kaspatest:qzowner",
            existing_slugs: &[],
            namespace_key_sources: &[fetched],
            normalized_mass: 1200,
            fee_rate_sompi_per_gram: 2,
        })
        .unwrap_err(),
        "NAME_KEY_LIST_INCOMPLETE_OR_STALE"
    );

    let valid_body = body;
    assert_eq!(
        fetch_key_list_with(url, |_| Ok((200, valid_body))).unwrap()["keys"][0]["namespace"],
        "myspace"
    );
}

#[test]
fn public_dns_validation_rejects_private_or_empty_answers() {
    let public: IpAddr = "8.8.8.8".parse().unwrap();
    let private: IpAddr = "10.0.0.1".parse().unwrap();
    let loopback_v6: IpAddr = "::1".parse().unwrap();
    assert!(validate_public_dns_answers(&[public]).is_ok());
    assert_eq!(
        validate_public_dns_answers(&[public, private]).unwrap_err(),
        "NAME_KEY_URL_PUBLIC_DNS_REQUIRED"
    );
    assert_eq!(
        validate_public_dns_answers(&[loopback_v6]).unwrap_err(),
        "NAME_KEY_URL_PUBLIC_DNS_REQUIRED"
    );
    assert_eq!(
        validate_public_dns_answers(&[]).unwrap_err(),
        "NAME_KEY_URL_PUBLIC_DNS_REQUIRED"
    );
}

#[test]
fn only_one_url_is_allowed_to_preserve_a_single_total_fetch_deadline() {
    let mut request = json!({"namespace_key_sources": []});
    let urls = vec![
        "https://one.example/keys.json".to_owned(),
        "https://two.example/keys.json".to_owned(),
    ];
    let error = add_namespace_key_url_sources(&mut request, &urls, |_| unreachable!())
        .unwrap_err()
        .to_string();
    assert_eq!(error, "NAME_KEY_URL_COUNT_EXCEEDED");
}

#[test]
fn child_name_key_uses_the_fixed_width_namespace_and_slug_frames() {
    assert_eq!(
        child_name_key("demo", "app").unwrap(),
        "f19f832b2cd7f5135f2598933497c4ef865ea0985ba9d0d7d62f0cab1324e410"
    );
}

#[test]
fn child_name_inventory_is_sorted_and_duplicate_names_fail_closed() {
    let names = vec!["zebra".to_owned(), "app".to_owned()];
    let keys = child_name_keys("demo", &names).unwrap();
    assert_eq!(keys.len(), 2);
    assert!(keys.windows(2).all(|pair| pair[0] < pair[1]));
    assert!(keys.contains(&child_name_key("demo", "app").unwrap()));
    assert_eq!(
        child_name_keys("demo", &["app".into(), "app".into()]).unwrap_err(),
        "NAME_KEY_DUPLICATE"
    );
}

#[test]
fn invalid_names_order_unknown_name_key_and_mismatched_key_fail_closed() {
    assert_eq!(
        namespace_key("Upper").unwrap_err(),
        "NAMESPACE_NON_CANONICAL"
    );
    assert_eq!(
        namespace_key("with_underscore").unwrap_err(),
        "NAMESPACE_NON_CANONICAL"
    );
    assert_eq!(
        child_name_key("ktape", "BadSlug").unwrap_err(),
        "NAME_SLUG_NON_CANONICAL"
    );
    assert_eq!(
        child_name_key("ktape", "with_underscore").unwrap_err(),
        "NAME_SLUG_NON_CANONICAL"
    );

    let unsorted = list(json!([
        {"namespace":"zeta","key_hex":namespace_key("zeta").unwrap()},
        {"namespace":"alpha","key_hex":namespace_key("alpha").unwrap()}
    ]));
    assert_eq!(
        parse_list(&unsorted).unwrap_err(),
        "NAME_KEY_LIST_NON_CANONICAL_ORDER"
    );

    let name_key = list(json!([{
        "kind":"name",
        "namespace":"alpha",
        "key_hex":namespace_key("alpha").unwrap()
    }]));
    assert_eq!(parse_list(&name_key).unwrap_err(), "NAME_KEY_LIST_INVALID");

    let mismatch = list(json!([{"namespace":"alpha","key_hex":"00".repeat(32)}]));
    assert_eq!(
        parse_list(&mismatch).unwrap_err(),
        "NAME_KEY_LIST_KEY_MISMATCH"
    );
}

#[test]
fn age_is_informational_and_conflicting_sources_are_rejected() {
    let old = list(json!([{
        "namespace":"alpha",
        "key_hex":namespace_key("alpha").unwrap()
    }]));
    let mut old = old;
    old["updated_at"] = json!("2000-01-01T00:00:00Z");
    assert_eq!(parse_list(&old).unwrap().len(), 1);

    let conflict = list(json!([{"namespace":"alpha","key_hex":"ff".repeat(32)}]));
    assert_eq!(
        merge_lists(&[old, conflict]).unwrap_err(),
        "NAME_KEY_LIST_INCOMPLETE_OR_STALE"
    );
}

#[test]
fn keys_url_requires_https_and_public_dns_authority() {
    assert!(validate_keys_url("https://keys.example.org/tn10.json").is_ok());
    assert_eq!(
        validate_keys_url("http://keys.example.org/tn10.json").unwrap_err(),
        "NAME_KEY_URL_HTTPS_REQUIRED"
    );
    for url in [
        "https://localhost/keys.json",
        "https://node.internal/keys.json",
        "https://203.0.113.1/keys.json",
        "https://[::1]/keys.json",
        "https://user@keys.example.org/keys.json",
        "https://keys.example.org/keys.json?redirect=http://127.0.0.1",
        "https://keys.example.org:8443/keys.json",
    ] {
        assert!(validate_keys_url(url).is_err(), "accepted {url}");
    }
}

#[test]
fn register_plan_unions_untrusted_namespace_sources_and_reports_locked_costs() {
    let baseline: Value = serde_json::from_str(BASELINE).unwrap();
    let extra = list(json!([{
        "namespace":"myspace",
        "key_hex":namespace_key("myspace").unwrap()
    }]));
    let plan = plan_registration(RegistrationPlanInput {
        network: "testnet-10",
        namespace: "myspace",
        slug: "notes",
        owner: "kaspatest:qzowner",
        existing_slugs: &[],
        namespace_key_sources: &[baseline, extra],
        normalized_mass: 1200,
        fee_rate_sompi_per_gram: 2,
    })
    .unwrap();

    assert_eq!(plan["status"], "READ_ONLY_PLAN");
    assert_eq!(plan["namespace_key"], namespace_key("myspace").unwrap());
    assert_eq!(
        plan["name_key"],
        child_name_key("myspace", "notes").unwrap()
    );
    assert_eq!(plan["owner"], "kaspatest:qzowner");
    assert_eq!(plan["next_owner"], plan["owner"]);
    assert_eq!(plan["deed_state_bond_sompi"], 1_000_000_000u64);
    assert_eq!(plan["deed_state_bond_kas"], "10.00000000");
    assert_eq!(plan["name_deed_output_sompi"], 100_000_000u64);
    assert_eq!(plan["name_deed_output_kas"], "1.00000000");
    assert_eq!(plan["adapter_gap_floor_sompi"], 100_000_000u64);
    assert_eq!(plan["adapter_gap_floor_kas"], "1.00000000");
    assert_eq!(plan["network_fee_sompi"], 2400u64);
    assert_eq!(plan["newly_locked_sompi"], 200_000_000u64);
    assert_eq!(plan["total_upfront_sompi"], 200_002_400u64);
    assert_eq!(plan["signing_allowed"], false);
    assert_eq!(plan["broadcast"], false);
}

#[test]
fn real_registration_vectors_lock_only_the_two_new_gap_floors() {
    // Values are read back from the 9edd, d385 and 97c9 TN10 registrations.
    // Registry inputs are parent successor + consumed gap; outputs are parent
    // successor + left gap + name deed + right gap. Fee inputs/change are excluded.
    let real_vectors = [
        (
            "9eddc2…a354",
            [1_000_000_000u64, 100_000_000],
            [1_000_000_000u64, 100_000_000, 100_000_000, 100_000_000],
        ),
        (
            "d385ea…7d24",
            [1_000_000_000u64, 100_000_000],
            [1_000_000_000u64, 100_000_000, 100_000_000, 100_000_000],
        ),
        (
            "97c95f…2454",
            [1_000_000_000u64, 100_000_000],
            [1_000_000_000u64, 100_000_000, 100_000_000, 100_000_000],
        ),
    ];
    for (txid, registry_inputs, registry_outputs) in real_vectors {
        let inputs: u64 = registry_inputs.into_iter().sum();
        let outputs: u64 = registry_outputs.into_iter().sum();
        assert_eq!(outputs - inputs, 200_000_000, "{txid}");
    }
}

#[test]
fn register_plan_fails_closed_for_missing_namespace_or_existing_name() {
    let baseline: Value = serde_json::from_str(BASELINE).unwrap();
    let missing = plan_registration(RegistrationPlanInput {
        network: "testnet-10",
        namespace: "unknown",
        slug: "notes",
        owner: "kaspatest:qzowner",
        existing_slugs: &[],
        namespace_key_sources: std::slice::from_ref(&baseline),
        normalized_mass: 1000,
        fee_rate_sompi_per_gram: 1,
    })
    .unwrap_err();
    assert_eq!(missing, "NAME_KEY_LIST_INCOMPLETE_OR_STALE");

    let present = plan_registration(RegistrationPlanInput {
        network: "testnet-10",
        namespace: "ktape",
        slug: "notes",
        owner: "kaspatest:qzowner",
        existing_slugs: &["notes".to_owned()],
        namespace_key_sources: &[baseline],
        normalized_mass: 1000,
        fee_rate_sompi_per_gram: 1,
    })
    .unwrap_err();
    assert_eq!(present, "NAME_ALREADY_REGISTERED");
}

#[test]
fn public_help_omits_retired_name_routes_and_private_compiler_bridges() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_ktape"))
        .args(["name", "--help"])
        .output()
        .expect("run ktape name help");
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).expect("UTF-8 help output");
    assert!(help.contains("register-plan"));
    assert!(help.contains("register-request"));
    for retired in [
        " key ",
        " quote ",
        " deed-register-plan ",
        " deed-transfer-plan ",
        " deed-rebind-plan ",
        " deed-release-plan ",
        " compact-name-deed-register-plan ",
        " compact-name-deed-transfer-plan ",
        " compact-name-deed-rebind-plan ",
        " compact-name-deed-release-plan ",
        " compact-admission-status ",
        " tn10-namespace-issuance-plan ",
        " tn10-namespace-child-registration-plan ",
    ] {
        assert!(
            !help
                .lines()
                .any(|line| line.split_whitespace().next() == Some(retired.trim())),
            "retired route remains in help: {retired}"
        );
    }

    let plan_help = std::process::Command::new(env!("CARGO_BIN_EXE_ktape"))
        .args(["name", "register-plan", "--help"])
        .output()
        .expect("run ktape name register-plan help");
    assert!(plan_help.status.success());
    let plan_help = String::from_utf8(plan_help.stdout).expect("UTF-8 plan help");
    assert!(plan_help.contains("--keys-file"));
    assert!(plan_help.contains("--keys-url"));
    assert!(!plan_help.contains("--key-file"));

    let request_help = std::process::Command::new(env!("CARGO_BIN_EXE_ktape"))
        .args(["name", "register-request", "--help"])
        .output()
        .expect("run ktape name register-request help");
    assert!(request_help.status.success());
    let request_help = String::from_utf8(request_help.stdout).expect("UTF-8 request help");
    assert!(request_help.contains("--names-file"));
    assert!(!request_help.contains("--key-file"));
    assert!(!request_help.contains("--key-stdin"));
}

#[test]
fn package_publication_emits_a_complete_change_owner_target_tuple() {
    let root = std::env::temp_dir().join(format!(
        "ktape-package-target-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let source = root.join("source");
    let output = root.join("package");
    let profile = root.join("developer-lock.json");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(source.join("index.html"), "<h1>package target</h1>").unwrap();
    std::fs::write(
        &profile,
        r#"{
          "abi_version":"KTAPEOUT-0.5.0",
          "adapter_hash":"2222222222222222222222222222222222222222222222222222222222222222",
          "compiler_lock_digest":"1111111111111111111111111111111111111111111111111111111111111111",
          "composition_root":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
          "core_version":"0.5.0",
          "created_at":"2026-09-20T00:00:00Z",
          "dependency_root":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
          "feature_set_root":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "lock_hash":"e9fcfa77c856eba214fdfd82a3e163fd308ea7d67513fa2b8c74b0efb7d3c6f8",
          "network_policy_id":"testnet-10-policy",
          "profiles":[{"admission_level":"IMPLEMENTED","package_digest":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","package_provenance":{"license_ref":"MIT","publisher_id":"ktapeout","source_ref":"content:fixture","trust_tier":"VERIFIED"},"profile_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","profile_id":"PureCompute"}],
          "protocol_semver":"0.5.0",
          "runtime_digest":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
          "schema":"KTAPEOUT-DEVELOPER-LOCK-V1",
          "vector_root":"3333333333333333333333333333333333333333333333333333333333333333"
        }"#,
    )
    .unwrap();
    let app_id = "a".repeat(64);
    let deployment_id = "tn10-demo-app-20261102";
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_ktape"))
        .args([
            "package",
            "build",
            "--source",
            source.to_str().unwrap(),
            "--application-uri",
            "demo/app",
            "--entrypoint",
            "index.html",
            "--output",
            output.to_str().unwrap(),
            "--application-id",
            &app_id,
            "--deployment-id",
            deployment_id,
            "--profile-lock",
            profile.to_str().unwrap(),
        ])
        .output()
        .expect("run ktape package build");
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let target: Value =
        serde_json::from_slice(&std::fs::read(output.join("name-target.json")).unwrap()).unwrap();
    let release: Value =
        serde_json::from_slice(&std::fs::read(output.join("release.json")).unwrap()).unwrap();
    assert_eq!(target.as_object().unwrap().len(), 4);
    assert_eq!(target["application_id"], app_id);
    assert_eq!(target["release_id"], release["release_id"]);
    assert_eq!(target["deployment_id"], deployment_id);
    assert_eq!(target["artifact_root"], release["artifact_root"]);
    assert_eq!(release["deployment_id"], deployment_id);
    std::fs::remove_dir_all(root).unwrap();
}

fn registration_request_seed(gap: &str, deed: &str) -> Value {
    let mut request = json!({
        "network":"testnet-10",
        "namespace":"myspace",
        "slug":"notes",
        "owner":"kaspatest:qzowner",
        "namespace_key_sources":[list(json!([{
            "namespace":"myspace",
            "key_hex":namespace_key("myspace").unwrap()
        }]))],
        "estimated_mass":1200,
        "nodes":[
            "wss://node-a.example/kaspa/testnet-10/wrpc/borsh",
            "wss://node-b.example/kaspa/testnet-10/wrpc/borsh"
        ],
        "states":[{"role":"deed","script_public_key":deed}],
        "gap_candidates":[{
            "gap":{"lo":"0000000000000000000000000000000000000000000000000000000000000000","hi":"0000000000000000000000000000000000000000000000000000000000000000","hiIsMax":1},
            "script_public_key":gap
        }]
    });
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../examples/namespace-child-registration-v6-cli-parity-v1-vector.json"
    ))
    .unwrap();
    request["native_transaction_input"] =
        native_registration_input(&fixture["manifest"]["transaction_input"]);
    request
}

fn decode_witness_pushes(script: &[u8]) -> Vec<Value> {
    let mut items = Vec::new();
    let mut cursor = 0usize;
    while cursor < script.len() {
        let opcode = script[cursor];
        cursor += 1;
        let length = match opcode {
            0 => {
                items.push(json!({"opcode":0}));
                continue;
            }
            1..=75 => opcode as usize,
            76 => {
                let length = *script.get(cursor).expect("PUSHDATA1 length") as usize;
                cursor += 1;
                length
            }
            77 => {
                let bytes: [u8; 2] = script
                    .get(cursor..cursor + 2)
                    .expect("PUSHDATA2 length")
                    .try_into()
                    .unwrap();
                cursor += 2;
                u16::from_le_bytes(bytes) as usize
            }
            79 | 81..=96 => {
                items.push(json!({"opcode":opcode}));
                continue;
            }
            _ => panic!("unexpected witness push opcode {opcode:#04x}"),
        };
        let end = cursor.checked_add(length).expect("push length overflow");
        let bytes = script.get(cursor..end).expect("witness push is complete");
        items.push(json!({"data_hex":hex::encode(bytes)}));
        cursor = end;
    }
    items
}

#[test]
fn names_file_request_sign_assemble_submit_and_dual_readback_e2e() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../examples/namespace-child-registration-v6-cli-parity-v1-vector.json"
    ))
    .unwrap();
    let mut native_input = native_registration_input(&fixture["manifest"]["transaction_input"]);
    for input in native_input["inputs"].as_array_mut().unwrap() {
        input.as_object_mut().unwrap().remove("compute_budget");
    }
    let saved_vectors: Value = serde_json::from_str(include_str!(
        "../../../data/registry/real-registration-sigscript-vectors-v1.json"
    ))
    .unwrap();
    let owner_vector = saved_vectors["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|vector| vector["txid"].as_str().unwrap().starts_with("089f52"))
        .unwrap();
    let signed_owner_witness = hex::decode(
        owner_vector["inputs"][0]["signature_script_hex"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let mut owner_arguments = decode_witness_pushes(&signed_owner_witness);
    let owner_redeem_script = owner_arguments
        .pop()
        .expect("saved witness includes a redeem script")["data_hex"]
        .as_str()
        .unwrap()
        .to_owned();
    owner_arguments[11] = json!({"data_hex":"00".repeat(65)});
    owner_arguments[14] = json!({"data_hex":"00".repeat(65)});
    let owner_deed_spk = format!(
        "0000aa20{}87",
        hex::encode(ktapeout_cli::name_state_template::blake2b_256(
            &hex::decode(&owner_redeem_script).unwrap()
        ))
    );
    // The mock registration readback's new Deed output is shaped to the saved
    // owner-target witness context so the next local plan can consume that exact UTXO.
    native_input["outputs"][2]["script_public_key"] = json!(owner_deed_spk);
    let gap = native_input["inputs"][1]["script_public_key"]
        .as_str()
        .unwrap()
        .to_owned();
    let deed = native_input["inputs"][0]["script_public_key"]
        .as_str()
        .unwrap()
        .to_owned();
    let secret = [83u8; 32];
    let secp = secp256k1::Secp256k1::new();
    let key = secp256k1::SecretKey::from_slice(&secret).unwrap();
    let public_key = hex::encode(
        secp256k1::Keypair::from_secret_key(&secp, &key)
            .x_only_public_key()
            .0
            .serialize(),
    );
    let fee_script = format!("000020{public_key}ac");
    let mut request = registration_request_seed(&gap, &deed);
    request["native_transaction_input"] = native_input;
    request["native_transaction_input"]["role_public_keys"] = json!({
        "parent":public_key,
        "claimant":public_key,
        "target":public_key,
        "parent_for_child":public_key,
        "fee":public_key
    });
    request["native_transaction_input"]["inputs"][2]["script_public_key"] = json!(fee_script);
    request["native_transaction_input"]["outputs"][4]["script_public_key"] = json!(fee_script);
    let names = json!({
        "schema":"KTAPEOUT-REGISTERED-NAMES-V1",
        "network":"testnet-10",
        "namespace":"myspace",
        "slugs":[]
    });
    let generated = registry_request_with_names_and_transports(
        &request,
        &names,
        &mut registration_registry_mock_with_fee(&gap, &deed, &fee_script),
        &mut registration_registry_mock_with_fee(&gap, &deed, &fee_script),
    )
    .unwrap();
    assert_eq!(generated["request"]["existing_slugs"], json!([]));
    assert_eq!(generated["request"]["states"].as_array().unwrap().len(), 2);
    assert_eq!(
        generated["request"]["native_transaction_input"]["inputs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|input| input["compute_budget"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        vec![10, 47, 10],
        "request generation must attach the pinned VM-measured budget to each input"
    );
    assert_eq!(
        generated["request"]["native_transaction_input"]["inputs"][2]["amount"],
        2_500_000_000u64
    );
    let original_fee_amount = request["native_transaction_input"]["inputs"][2]["amount"]
        .as_u64()
        .unwrap();
    let original_change = request["native_transaction_input"]["outputs"][4]["value"]
        .as_u64()
        .unwrap();
    assert_eq!(
        generated["request"]["native_transaction_input"]["outputs"][4]["value"],
        original_change + 2_500_000_000u64 - original_fee_amount
    );
    assert_eq!(generated["broadcast"], false);
    let plan = registry_register_plan_with_transports(
        &generated,
        &mut registration_registry_mock_with_fee(&gap, &deed, &fee_script),
        &mut registration_registry_mock_with_fee(&gap, &deed, &fee_script),
    )
    .unwrap();
    assert_eq!(plan["status"], "DUAL_RPC_UNSIGNED_NATIVE_PLAN");
    assert_eq!(plan["plan"]["slug"], "notes");

    let native_plan = &plan["native_transaction_plan"];
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let total = native_plan["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|input| input["amount"].as_u64().unwrap())
        .sum::<u64>();
    let authorization = json!({
        "schema":"KTAPEOUT-TN10-REGISTRATION-AUTHORIZATION-V1",
        "network":"testnet-10",
        "plan_sha256":native_plan["plan_sha256"],
        "role_public_keys":native_plan["role_public_keys"],
        "cumulative_amount_limit_sompi":total,
        "fee_limit_sompi":native_plan["fee_sompi"],
        "fee_source":"live_dual_node_quote",
        "fee_quote_sha256":"aa".repeat(32),
        "created_at_unix":now_unix - 60,
        "expires_at_unix":now_unix + 3600,
        "allow_broadcast":true,
        "allow_readback":true,
        "confirmation_method":"TERMINAL_TYPED_PLAN_DIGEST",
        "created_with_terminal_confirmation":true
    });
    let confirmation = format!("SIGN {}", native_plan["plan_sha256"].as_str().unwrap());
    let packet = ktapeout_cli::tn10_developer_signing::sign_native_registration_partial(
        native_plan,
        &authorization,
        secret,
        now_unix,
        &confirmation,
    )
    .unwrap();
    let scratch = std::env::temp_dir().join(format!(
        "ktape-registration-e2e-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&scratch).unwrap();
    let plan_path = scratch.join("plan.json");
    let authorization_path = scratch.join("authorization.json");
    let partial_path = scratch.join("partial.json");
    let aggregate_path = scratch.join("aggregate.json");
    let submit_path = scratch.join("submit.json");
    std::fs::write(&plan_path, serde_json::to_vec(native_plan).unwrap()).unwrap();
    std::fs::write(
        &authorization_path,
        serde_json::to_vec(&authorization).unwrap(),
    )
    .unwrap();
    std::fs::write(&partial_path, serde_json::to_vec(&packet).unwrap()).unwrap();
    let assemble_output = std::process::Command::new(env!("CARGO_BIN_EXE_ktape"))
        .args([
            "tn10",
            "assemble",
            plan_path.to_str().unwrap(),
            aggregate_path.to_str().unwrap(),
            "--authorization",
            authorization_path.to_str().unwrap(),
            "--partial",
            partial_path.to_str().unwrap(),
        ])
        .output()
        .expect("run native assembly command");
    assert!(
        assemble_output.status.success(),
        "assemble failed: {}",
        String::from_utf8_lossy(&assemble_output.stderr)
    );
    let aggregate: Value =
        serde_json::from_slice(&std::fs::read(&aggregate_path).unwrap()).unwrap();
    assert_eq!(aggregate["native_plan_hash"], native_plan["plan_sha256"]);
    assert_eq!(aggregate["signatures"].as_array().unwrap().len(), 5);

    let transaction = aggregate["transaction"].clone();
    let txid = Transaction::try_from(
        serde_json::from_value::<RpcTransaction>(transaction.clone()).unwrap(),
    )
    .unwrap()
    .id()
    .to_string();
    assert!(ktapeout_cli::tn10_pipeline::submit_with_transport_retry_at(
        &aggregate_path,
        &submit_path,
        false,
        now_unix,
        &mut SubmitAckMock(txid.clone()),
    )
    .is_ok());
    let receipt: Value = serde_json::from_slice(&std::fs::read(&submit_path).unwrap()).unwrap();
    assert_eq!(receipt["status"], "SUBMITTED");
    assert_eq!(receipt["plan_sha256"], native_plan["plan_sha256"]);
    assert_eq!(receipt["txid"], txid);
    let mut first_readback = RegistrationReadbackMock {
        result: Ok(Some(transaction.clone())),
    };
    let mut second_readback = RegistrationReadbackMock {
        result: Ok(Some(transaction)),
    };
    let readback =
        ktapeout_cli::tn10_pipeline::reconcile_native_registration_readback_with_transports(
            native_plan,
            &aggregate["transaction"],
            &txid,
            &mut first_readback,
            &mut second_readback,
        )
        .unwrap();
    assert_eq!(readback["status"], "FOUND_BOTH_MATCH");
    assert_eq!(readback["plan_sha256"], native_plan["plan_sha256"]);

    let readback_transaction = Transaction::try_from(
        serde_json::from_value::<RpcTransaction>(
            first_readback
                .result
                .as_ref()
                .unwrap()
                .as_ref()
                .unwrap()
                .clone(),
        )
        .unwrap(),
    )
    .expect("readback transaction parses as the registered transaction");
    let deed_output = &readback_transaction.outputs[2];
    let deed_outpoint = format!("{txid}:2");
    let deed_script = format!(
        "{:04x}{}",
        deed_output.script_public_key.version(),
        hex::encode(deed_output.script_public_key.script())
    );
    assert_eq!(deed_script, owner_deed_spk);
    let owner_key = owner_arguments[12]["data_hex"].as_str().unwrap();
    let target_key = owner_arguments[15]["data_hex"].as_str().unwrap();
    let owner_fee = 4_399_120u64;
    let owner_fee_input = 1_000_000_000u64;
    let owner_target_request = json!({
        "inputs":[
            {"outpoint":deed_outpoint,"amount":deed_output.value,"block_daa_score":605_673_488,
             "script_public_key":deed_script,"covenant_id":native_plan["outputs"][2]["covenant_id"],
             "compute_budget":256,"signature_script":""},
            {"outpoint":format!("{txid}:99"),"amount":owner_fee_input,"block_daa_score":605_673_488,
             "script_public_key":fee_script,"covenant_id":null,"compute_budget":10,"signature_script":""}
        ],
        "outputs":[
            {"role":"deed_successor","value":deed_output.value,
             "script_public_key":"0000aa20d7c7afdc7930411a78c652fe35479b37a577557ab483c3e0c5d2b41155fb1d4787",
             "covenant_id":native_plan["outputs"][2]["covenant_id"],"authorizing_input":0},
            {"role":"fee_change","value":owner_fee_input-owner_fee,
             "script_public_key":fee_script,"covenant_id":null,"authorizing_input":null}
        ],
        "covenant_witness_contexts":[{"input_index":0,"entrypoint":"change_owner_target",
          "redeem_script_hex":owner_redeem_script,"arguments":owner_arguments}],
        "role_public_keys":{"deed_owner":owner_key,"target_authority":target_key,"fee":public_key},
        "fee_sompi":owner_fee
    });
    let owner_target_plan =
        ktapeout_cli::tn10_pipeline::build_native_owner_target_plan(&owner_target_request)
            .expect("step two plan uses the Deed UTXO confirmed by step one readback");
    assert_eq!(owner_target_plan["inputs"][0]["outpoint"], deed_outpoint);
    assert_eq!(owner_target_plan["inputs"][0]["amount"], deed_output.value);
    assert_eq!(
        owner_target_plan["inputs"][0]["script_public_key"],
        deed_script
    );
    assert_eq!(
        owner_target_plan["inputs"][0]["covenant_id"],
        native_plan["outputs"][2]["covenant_id"]
    );
    assert!(
        ktapeout_cli::tn10_pipeline::verify_native_registration_plan_digest(&owner_target_plan)
    );

    let mut unavailable_readback = RegistrationReadbackMock {
        result: Err("mock node unavailable".into()),
    };
    let mut available_readback = RegistrationReadbackMock {
        result: Ok(Some(aggregate["transaction"].clone())),
    };
    assert_eq!(
        ktapeout_cli::tn10_pipeline::reconcile_native_registration_readback_with_transports(
            native_plan,
            &aggregate["transaction"],
            &txid,
            &mut unavailable_readback,
            &mut available_readback,
        )
        .unwrap_err()
        .to_string(),
        "TN10_READBACK_RPC_FAILED"
    );
    let mut matching_readback = RegistrationReadbackMock {
        result: Ok(Some(aggregate["transaction"].clone())),
    };
    let mut missing_readback = RegistrationReadbackMock { result: Ok(None) };
    assert_eq!(
        ktapeout_cli::tn10_pipeline::reconcile_native_registration_readback_with_transports(
            native_plan,
            &aggregate["transaction"],
            &txid,
            &mut matching_readback,
            &mut missing_readback,
        )
        .unwrap_err()
        .to_string(),
        "TN10_DUAL_NODE_DISAGREEMENT"
    );

    let unknown_path = scratch.join("unknown-submit.json");
    assert_eq!(
        ktapeout_cli::tn10_pipeline::submit_with_transport_retry_at(
            &aggregate_path,
            &unknown_path,
            false,
            now_unix,
            &mut SubmitUnknownMock,
        )
        .unwrap_err()
        .to_string(),
        "TN10_SUBMISSION_UNKNOWN"
    );
    let unknown: Value = serde_json::from_slice(&std::fs::read(&unknown_path).unwrap()).unwrap();
    assert_eq!(unknown["status"], "SUBMISSION_UNKNOWN");
    assert_eq!(unknown["txid"], txid);
    assert_eq!(unknown["plan_sha256"], native_plan["plan_sha256"]);
    assert_eq!(unknown["reconcile"], "REQUIRED_WITH_TWO_NODES_BEFORE_RETRY");
    assert_eq!(
        ktapeout_cli::tn10_pipeline::submit_with_transport_retry_at(
            &aggregate_path,
            &unknown_path,
            false,
            now_unix,
            &mut SubmitAckMock(txid.clone()),
        )
        .unwrap_err()
        .to_string(),
        "TN10_RETRY_SAME_TXID_REQUIRED"
    );
    let mut retry_readback_a = RegistrationReadbackMock {
        result: Ok(Some(aggregate["transaction"].clone())),
    };
    let mut retry_readback_b = RegistrationReadbackMock {
        result: Ok(Some(aggregate["transaction"].clone())),
    };
    let retry_reconciled =
        ktapeout_cli::tn10_pipeline::reconcile_native_registration_readback_with_transports(
            native_plan,
            &aggregate["transaction"],
            &txid,
            &mut retry_readback_a,
            &mut retry_readback_b,
        )
        .unwrap();
    assert_eq!(retry_reconciled["status"], "FOUND_BOTH_MATCH");
    ktapeout_cli::tn10_pipeline::submit_with_transport_retry_at(
        &aggregate_path,
        &unknown_path,
        true,
        now_unix,
        &mut SubmitAckMock(txid.clone()),
    )
    .unwrap();
    let retried: Value = serde_json::from_slice(&std::fs::read(&unknown_path).unwrap()).unwrap();
    assert_eq!(retried["status"], "SUBMITTED");
    assert_eq!(retried["txid"], txid);
    assert!(scratch.join("unknown-submit.json.attempt-1.json").exists());
    std::fs::remove_dir_all(scratch).unwrap();
}

#[test]
fn names_file_request_rejects_unmeasured_slot_compute_budget() {
    let gap = format!("0000aa20{}87", "31".repeat(32));
    let deed = format!("0000aa20{}87", "42".repeat(32));
    let mut request = registration_request_seed(&gap, &deed);
    request["native_transaction_input"]["registration_kind"] = json!("SLOT");
    let names = json!({
        "schema":"KTAPEOUT-REGISTERED-NAMES-V1",
        "network":"testnet-10",
        "namespace":"myspace",
        "slugs":[]
    });
    let error = registry_request_with_names_and_transports(
        &request,
        &names,
        &mut registration_registry_mock(&gap, &deed),
        &mut registration_registry_mock(&gap, &deed),
    )
    .unwrap_err();
    assert!(error
        .to_string()
        .contains("TN10_REGISTRATION_COMPUTE_BUDGET_UNMEASURED"));
}

#[test]
fn names_file_rejects_already_registered_slug_before_rpc_reads() {
    let gap = format!("0000aa20{}87", "31".repeat(32));
    let deed = format!("0000aa20{}87", "42".repeat(32));
    let request = registration_request_seed(&gap, &deed);
    let names = json!({
        "schema":"KTAPEOUT-REGISTERED-NAMES-V1",
        "network":"testnet-10",
        "namespace":"myspace",
        "slugs":["notes"]
    });
    let error = registry_request_with_names_and_transports(
        &request,
        &names,
        &mut registry_mock(&gap, &deed),
        &mut registry_mock(&gap, &deed),
    )
    .unwrap_err();
    assert!(error.to_string().contains("NAME_ALREADY_REGISTERED"));
}

#[test]
fn names_file_request_fails_closed_when_nodes_disagree() {
    let gap = format!("0000aa20{}87", "31".repeat(32));
    let deed = format!("0000aa20{}87", "42".repeat(32));
    let request = registration_request_seed(&gap, &deed);
    let names = json!({
        "schema":"KTAPEOUT-REGISTERED-NAMES-V1",
        "network":"testnet-10",
        "namespace":"myspace",
        "slugs":[]
    });
    let mut disagree = registry_mock(&gap, &deed);
    disagree.entries[0] = state_utxo(&gap, 100_000_001, 0x21);
    let error = registry_request_with_names_and_transports(
        &request,
        &names,
        &mut registry_mock(&gap, &deed),
        &mut disagree,
    )
    .unwrap_err();
    assert!(error.to_string().contains("TN10_UTXO_NODES_DISAGREE"));
}

#[test]
fn names_file_target_gap_already_spent_is_stale_and_fails_closed() {
    let gap = format!("0000aa20{}87", "31".repeat(32));
    let deed = format!("0000aa20{}87", "42".repeat(32));
    let request = registration_request_seed(&gap, &deed);
    let names = json!({
        "schema":"KTAPEOUT-REGISTERED-NAMES-V1",
        "network":"testnet-10",
        "namespace":"myspace",
        "slugs":[]
    });
    let mut spent_gap = RegistryMock {
        entries: vec![json!([]), json!([])],
        index: 0,
        fail_read: false,
    };
    let mut spent_deed = RegistryMock {
        entries: vec![json!([]), json!([])],
        index: 0,
        fail_read: false,
    };
    let error = registry_request_with_names_and_transports(
        &request,
        &names,
        &mut spent_gap,
        &mut spent_deed,
    )
    .unwrap_err();
    assert!(error
        .to_string()
        .contains("NAME_KEY_LIST_INCOMPLETE_OR_STALE"));
    assert!(error.to_string().contains("--names-file"));
}

#[test]
fn name_evidence_verification_rejects_a_non_pinned_namespace_anchor_first() {
    let root = std::env::temp_dir().join(format!(
        "ktape-fixed-anchor-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let evidence = root.join("evidence.json");
    let anchor = root.join("anchor.json");
    let rpc_a = root.join("rpc-a.json");
    let rpc_b = root.join("rpc-b.json");
    std::fs::write(&evidence, "{}").unwrap();
    std::fs::write(
        &anchor,
        r#"{"schema":"KTAPEOUT-NAMESPACE-ISSUANCE-TRUST-ANCHOR-V1","network":"testnet-10","profile_id":"NamespaceIssuanceV1","profile_version":1,"covenant_id":"0000000000000000000000000000000000000000000000000000000000000000","genesis_outpoint":"0000000000000000000000000000000000000000000000000000000000000000:0","source_sha256":"0000000000000000000000000000000000000000000000000000000000000000","child_manifest_sha256":"0000000000000000000000000000000000000000000000000000000000000000","namespace_reallocation":false,"certificate_carrier_sompi":100000000,"manifest_digest":"0000000000000000000000000000000000000000000000000000000000000000"}"#,
    )
    .unwrap();
    std::fs::write(&rpc_a, "{}").unwrap();
    std::fs::write(&rpc_b, "{}").unwrap();

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_ktape"))
        .args([
            "name",
            "evidence-verify",
            "--evidence",
            evidence.to_str().unwrap(),
            "--anchor",
            anchor.to_str().unwrap(),
            "--rpc-a",
            rpc_a.to_str().unwrap(),
            "--rpc-b",
            rpc_b.to_str().unwrap(),
        ])
        .output()
        .expect("run name evidence verifier");
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("NAMESPACE_ANCHOR_PIN_MISMATCH"),
        "unexpected error: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn name_evidence_verification_rejects_each_mutated_fixed_anchor_field() {
    let root = std::env::temp_dir().join(format!(
        "ktape-anchor-fields-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let evidence = root.join("evidence.json");
    let anchor_path = root.join("anchor.json");
    let rpc_a = root.join("rpc-a.json");
    let rpc_b = root.join("rpc-b.json");
    let pinned: Value = serde_json::from_str(include_str!(
        "../../../data/registry/tn10-namespace-issuance-anchor-v1.json"
    ))
    .unwrap();
    std::fs::write(&evidence, "{}").unwrap();
    std::fs::write(&rpc_a, "{}").unwrap();
    std::fs::write(&rpc_b, "{}").unwrap();

    let verify = |anchor: &Value| {
        std::fs::write(&anchor_path, serde_json::to_vec(anchor).unwrap()).unwrap();
        std::process::Command::new(env!("CARGO_BIN_EXE_ktape"))
            .args([
                "name",
                "evidence-verify",
                "--evidence",
                evidence.to_str().unwrap(),
                "--anchor",
                anchor_path.to_str().unwrap(),
                "--rpc-a",
                rpc_a.to_str().unwrap(),
                "--rpc-b",
                rpc_b.to_str().unwrap(),
            ])
            .output()
            .expect("run name evidence verifier")
    };

    let baseline = verify(&pinned);
    assert!(!String::from_utf8_lossy(&baseline.stderr).contains("NAMESPACE_ANCHOR_PIN_MISMATCH"));
    for (field, value) in pinned.as_object().unwrap() {
        let mut changed = pinned.clone();
        changed[field] = match value {
            Value::Bool(flag) => Value::Bool(!flag),
            Value::Number(_) => serde_json::json!(999_999_999_u64),
            Value::String(text) => Value::String(format!("{text}-changed")),
            _ => panic!("unexpected anchor field type for {field}"),
        };
        let output = verify(&changed);
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("NAMESPACE_ANCHOR_PIN_MISMATCH"),
            "changed anchor field {field} was accepted: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}
