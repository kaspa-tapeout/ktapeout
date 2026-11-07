#![cfg(feature = "tn10-network")]

use kaspa_rpc_core::GetBlocksResponse;
use ktapeout_cli::tn10_pipeline::{self, chain_acceptance_from_snapshot, ChainSnapshot, Transport};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP_DIR: AtomicU64 = AtomicU64::new(0);

struct ScanTransport {
    observations: Vec<String>,
}

impl Transport for ScanTransport {
    fn submit(&mut self, _: &kaspa_rpc_core::RpcTransaction) -> Result<String, String> {
        panic!("locate must not submit")
    }

    fn read_transaction(&mut self, _: &str) -> Result<Option<Value>, String> {
        panic!("locate scans block bodies")
    }

    fn read_observation(&mut self) -> Result<Value, String> {
        let start_hash = if self.observations.len() > 1 {
            self.observations.remove(0)
        } else {
            self.observations[0].clone()
        };
        Ok(json!({"network":"testnet-10","synced":true,"start_hash":start_hash}))
    }

    fn read_blocks_after(&mut self, _: &str) -> Result<GetBlocksResponse, String> {
        Ok(GetBlocksResponse {
            block_hashes: Vec::new(),
            blocks: Vec::new(),
        })
    }
}

fn locator_request() -> (PathBuf, Value, String, String) {
    let dir = std::env::temp_dir().join(format!(
        "kt-locator-status-{}-{}",
        std::process::id(),
        NEXT_TEMP_DIR.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&dir).unwrap();
    let request_path = dir.join("request.json");
    let plan_path = dir.join("plan.json");
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
    fs::write(&request_path, serde_json::to_vec(&request).unwrap()).unwrap();
    tn10_pipeline::plan(&request_path, &plan_path).unwrap();
    let plan: Value = serde_json::from_slice(&fs::read(plan_path).unwrap()).unwrap();
    let start = "11".repeat(32);
    let other = "22".repeat(32);
    let evidence = json!({
        "network":"testnet-10",
        "nodes":[
            "wss://node-a.example/kaspa/testnet-10/wrpc/borsh",
            "wss://node-b.example/kaspa/testnet-10/wrpc/borsh"
        ],
        "start_hashes":[start, other],
        "txid":plan["txid"],
        "plan":plan,
        "block_hash":start,
        "min_confirmations":1,
        "max_pages":1
    });
    (dir, evidence, start, other)
}

#[test]
fn locate_distinguishes_tip_from_stalled_cursor() {
    let (_dir, evidence, start, other) = locator_request();
    let mut at_tip = ScanTransport {
        observations: vec![start.clone(), start.clone()],
    };
    let mut unused = ScanTransport {
        observations: vec![other.clone()],
    };
    assert_eq!(
        tn10_pipeline::locate_with_transports(&evidence, &mut at_tip, &mut unused)
            .unwrap_err()
            .to_string(),
        "TN10_SCAN_AT_TIP"
    );

    let mut stalled = ScanTransport {
        observations: vec![start, other.clone()],
    };
    let mut unused = ScanTransport {
        observations: vec![other],
    };
    assert_eq!(
        tn10_pipeline::locate_with_transports(&evidence, &mut stalled, &mut unused)
            .unwrap_err()
            .to_string(),
        "TN10_SCAN_CURSOR_STALLED"
    );
}

#[test]
fn removed_merge_block_can_be_accepted_on_the_selected_chain() {
    let included_block = "11".repeat(32);
    let accepting_block = "22".repeat(32);
    let next_block = "33".repeat(32);
    let txid = "44".repeat(32);
    let state = ChainSnapshot {
        network: "testnet-10".into(),
        removed: vec![included_block.clone()],
        added: vec![accepting_block.clone(), next_block],
        accepted: [(accepting_block.clone(), vec![txid.clone()])].into(),
    };

    let result = chain_acceptance_from_snapshot(state, &txid, &included_block, 2).unwrap();
    assert_eq!(result.accepting_block, accepting_block);
    assert_eq!(result.confirmations, 2);
    assert!(result.sufficient);
}

#[test]
fn removed_path_without_the_included_block_is_rejected_as_inconsistent() {
    let included_block = "11".repeat(32);
    let accepting_block = "22".repeat(32);
    let txid = "44".repeat(32);
    let state = ChainSnapshot {
        network: "testnet-10".into(),
        removed: vec!["55".repeat(32)],
        added: vec![accepting_block.clone()],
        accepted: BTreeMap::from([(accepting_block, vec![txid.clone()])]),
    };

    assert_eq!(
        chain_acceptance_from_snapshot(state, &txid, &included_block, 1)
            .unwrap_err()
            .to_string(),
        "TN10_BLOCK_NOT_ON_SELECTED_PARENT_CHAIN"
    );
}

#[test]
fn removed_side_block_without_transaction_acceptance_is_not_established() {
    let included_block = "11".repeat(32);
    let txid = "44".repeat(32);
    let state = ChainSnapshot {
        network: "testnet-10".into(),
        removed: vec![included_block.clone()],
        added: vec!["22".repeat(32)],
        accepted: BTreeMap::new(),
    };

    assert_eq!(
        chain_acceptance_from_snapshot(state, &txid, &included_block, 1)
            .unwrap_err()
            .to_string(),
        "TN10_TRANSACTION_ACCEPTANCE_NOT_ESTABLISHED"
    );
}
