use kaspa_consensus_core::tx::{ScriptPublicKey, TransactionId, TransactionOutpoint, UtxoEntry};
use kaspa_rpc_core::{RpcAddress, RpcUtxoEntry, RpcUtxosByAddressesEntry};
use ktapeout_cli::tn10_pipeline::{
    registry_script_utxos_with_transports, registry_state_bundle_with_transports, Transport,
};
use serde_json::{json, Value};

struct MockTransport {
    observation: Value,
    entries: Value,
    address: String,
    additional_entries: Vec<(String, Value)>,
}

impl Transport for MockTransport {
    fn submit(&mut self, _: &kaspa_rpc_core::RpcTransaction) -> Result<String, String> {
        Err("NOT_USED".into())
    }

    fn read_transaction(&mut self, _: &str) -> Result<Option<Value>, String> {
        Ok(None)
    }

    fn read_utxos(&mut self, address: &str) -> Result<Value, String> {
        if let Some((_, entries)) = self
            .additional_entries
            .iter()
            .find(|(expected, _)| expected == address)
        {
            return Ok(entries.clone());
        }
        if address != self.address {
            return Err("ADDRESS_MISMATCH".into());
        }
        Ok(self.entries.clone())
    }

    fn read_observation(&mut self) -> Result<Value, String> {
        Ok(self.observation.clone())
    }
}

fn script_address(script_hash: &[u8; 32]) -> String {
    RpcAddress::new(
        "kaspatest".try_into().unwrap(),
        8u8.try_into().unwrap(),
        script_hash,
    )
    .to_string()
}

fn observation(start_hash: &str) -> Value {
    json!({
        "network":"testnet-10",
        "synced":true,
        "utxo_indexed":true,
        "start_hash":start_hash,
        "virtual_daa_score":100
    })
}

fn entries(address: &RpcAddress, script: Vec<u8>) -> Value {
    let utxo = UtxoEntry::new(
        1_000_000_000,
        ScriptPublicKey::from_vec(0, script),
        100,
        false,
        None,
    );
    serde_json::to_value(vec![RpcUtxosByAddressesEntry {
        address: Some(address.clone()),
        outpoint: TransactionOutpoint::new(TransactionId::from_bytes([0x42; 32]), 0).into(),
        utxo_entry: RpcUtxoEntry::from(utxo),
    }])
    .unwrap()
}

fn registry_request(script_public_key: String) -> Value {
    json!({
        "network":"testnet-10",
        "nodes":[
            "wss://node-a.example/kaspa/testnet-10/wrpc/borsh",
            "wss://node-b.example/kaspa/testnet-10/wrpc/borsh"
        ],
        "script_public_key":script_public_key
    })
}

fn state_bundle_request(scripts: &[(&str, [u8; 32])]) -> Value {
    json!({
        "network":"testnet-10",
        "nodes":[
            "wss://node-a.example/kaspa/testnet-10/wrpc/borsh",
            "wss://node-b.example/kaspa/testnet-10/wrpc/borsh"
        ],
        "states":scripts.iter().map(|(role, hash)| json!({
            "role":role,
            "script_public_key":format!("0000{}", hex::encode([vec![0xaa,0x20],hash.to_vec(),vec![0x87]].concat()))
        })).collect::<Vec<_>>()
    })
}

fn mock(address: &str, entries: Value, start_hash: &str) -> MockTransport {
    MockTransport {
        observation: observation(start_hash),
        entries,
        address: address.to_owned(),
        additional_entries: Vec::new(),
    }
}

#[test]
fn script_utxo_lookup_derives_tn10_script_hash_address_and_rejects_other_scripts() {
    let script = [vec![0xaa, 0x20], vec![0x11; 32], vec![0x87]].concat();
    let address = script_address(&[0x11; 32]);
    let parsed_address: RpcAddress = address.as_str().try_into().unwrap();
    let request = registry_request(format!("0000{}", hex::encode(&script)));
    let mut first = mock(
        &address,
        entries(&parsed_address, script.clone()),
        &"22".repeat(32),
    );
    let mut second = mock(&address, entries(&parsed_address, script), &"22".repeat(32));

    let result = registry_script_utxos_with_transports(&request, &mut first, &mut second).unwrap();

    assert_eq!(result["status"], "TN10_DUAL_RPC_SCRIPT_UTXOS_MATCH");
    assert_eq!(result["address"], address);
    assert_eq!(result["utxos"].as_array().unwrap().len(), 1);

    let malformed = registry_request("000051".into());
    assert_eq!(
        registry_script_utxos_with_transports(&malformed, &mut first, &mut second)
            .unwrap_err()
            .to_string(),
        "TN10_REGISTRY_SCRIPT_HASH_REQUIRED"
    );
}

#[test]
fn script_utxo_lookup_fails_closed_on_rpc_disagreement_and_script_mismatch() {
    let expected_script = [vec![0xaa, 0x20], vec![0x11; 32], vec![0x87]].concat();
    let address = script_address(&[0x11; 32]);
    let parsed_address: RpcAddress = address.as_str().try_into().unwrap();
    let request = registry_request(format!("0000{}", hex::encode(&expected_script)));

    let mut first = mock(
        &address,
        entries(&parsed_address, expected_script.clone()),
        &"22".repeat(32),
    );
    let mut disagree = mock(&address, json!([]), &"22".repeat(32));
    assert_eq!(
        registry_script_utxos_with_transports(&request, &mut first, &mut disagree)
            .unwrap_err()
            .to_string(),
        "TN10_UTXO_NODES_DISAGREE"
    );

    let wrong_script = vec![0x51];
    let mut mismatch_a = mock(
        &address,
        entries(&parsed_address, wrong_script.clone()),
        &"22".repeat(32),
    );
    let mut mismatch_b = mock(
        &address,
        entries(&parsed_address, wrong_script),
        &"33".repeat(32),
    );
    assert_eq!(
        registry_script_utxos_with_transports(&request, &mut mismatch_a, &mut mismatch_b)
            .unwrap_err()
            .to_string(),
        "TN10_SCRIPT_UTXO_MISMATCH"
    );
}

#[test]
fn registry_state_bundle_requires_matching_gap_and_deed_utxos_on_both_nodes() {
    let scripts = [("gap", [0x11; 32]), ("deed", [0x22; 32])];
    let request = state_bundle_request(&scripts);
    let first = scripts
        .iter()
        .map(|(_, hash)| {
            let address = script_address(hash);
            let parsed: RpcAddress = address.as_str().try_into().unwrap();
            (
                address,
                entries(
                    &parsed,
                    [vec![0xaa, 0x20], hash.to_vec(), vec![0x87]].concat(),
                ),
            )
        })
        .collect::<Vec<_>>();
    let second = first.clone();
    let mut a = mock(&first[0].0, first[0].1.clone(), &"22".repeat(32));
    let mut b = mock(&second[0].0, second[0].1.clone(), &"22".repeat(32));
    a.additional_entries = vec![first[1].clone()];
    b.additional_entries = vec![second[1].clone()];

    let result = registry_state_bundle_with_transports(&request, &mut a, &mut b).unwrap();

    assert_eq!(result["status"], "TN10_DUAL_RPC_REGISTRY_STATES_MATCH");
    assert_eq!(result["states"].as_array().unwrap().len(), 2);
}

#[test]
fn registry_state_bundle_rejects_disagreement_single_node_failure_missing_state_and_bad_utxo() {
    let scripts = [("gap", [0x11; 32])];
    let request = state_bundle_request(&scripts);
    let hash = scripts[0].1;
    let address = script_address(&hash);
    let parsed: RpcAddress = address.as_str().try_into().unwrap();
    let good = entries(
        &parsed,
        [vec![0xaa, 0x20], hash.to_vec(), vec![0x87]].concat(),
    );

    let mut mismatch_view = mock(&address, good.clone(), &"22".repeat(32));
    let mut missing_on_second = mock(&address, json!([]), &"22".repeat(32));
    assert_eq!(
        registry_state_bundle_with_transports(&request, &mut mismatch_view, &mut missing_on_second)
            .unwrap_err()
            .to_string(),
        "TN10_UTXO_NODES_DISAGREE"
    );

    let mut failed = mock("wrong-address", good.clone(), &"22".repeat(32));
    let mut healthy = mock(&address, good.clone(), &"22".repeat(32));
    assert_eq!(
        registry_state_bundle_with_transports(&request, &mut failed, &mut healthy)
            .unwrap_err()
            .to_string(),
        "ADDRESS_MISMATCH"
    );

    let mut absent_a = mock(&address, json!([]), &"22".repeat(32));
    let mut absent_b = mock(&address, json!([]), &"22".repeat(32));
    assert_eq!(
        registry_state_bundle_with_transports(&request, &mut absent_a, &mut absent_b)
            .unwrap_err()
            .to_string(),
        "TN10_REGISTRY_STATE_MISSING:gap"
    );

    let bad = entries(&parsed, vec![0x51]);
    let mut bad_a = mock(&address, bad.clone(), &"22".repeat(32));
    let mut bad_b = mock(&address, bad, &"22".repeat(32));
    assert_eq!(
        registry_state_bundle_with_transports(&request, &mut bad_a, &mut bad_b)
            .unwrap_err()
            .to_string(),
        "TN10_SCRIPT_UTXO_MISMATCH"
    );
}
