#![cfg(feature = "tn10-network")]

use kaspa_consensus_core::{
    config::params::Params,
    header::Header,
    merkle::calc_hash_merkle_root,
    network::{NetworkId, NetworkType},
    tx::{Transaction, TransactionId},
};
use kaspa_rpc_core::{RpcBlock, RpcHeader, RpcTransaction};
use ktapeout_cli::tn10_pipeline::{self, ChainSnapshot, Transport};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

fn dir() -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    let p = std::env::temp_dir().join(format!(
        "kt-verify-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&p).unwrap();
    p
}

fn plan(dir: &Path) -> Value {
    let request = json!({"schema":"KTAPEOUT-RESOURCE-PAYLOAD-CANDIDATE-V1","network":"testnet-10",
        "artifact":{"artifact_sha256":"00".repeat(32),"files":[]},
        "funding_utxo":{"outpoint":format!("{}:0","01".repeat(32)),"amount":1_000_000_000u64,
            "script_public_key":"0000201cf37eb561f80022293855860f47122025c0929a05f6f08c503ed7f2325cafd5ac","block_daa_score":1,"covenant_id":null},
        "fee_sompi":30_000_000});
    let i = dir.join("request.json");
    let p = dir.join("plan.json");
    fs::write(&i, serde_json::to_vec(&request).unwrap()).unwrap();
    tn10_pipeline::plan(&i, &p).unwrap();
    serde_json::from_slice(&fs::read(p).unwrap()).unwrap()
}

#[derive(Clone)]
struct Fake {
    block: RpcBlock,
    chain: ChainSnapshot,
    unavailable: bool,
}

impl Fake {
    fn new(plan: &Value) -> Self {
        let rpc_tx: RpcTransaction = serde_json::from_value(plan["transaction"].clone()).unwrap();
        let tx = Transaction::try_from(rpc_tx.clone()).unwrap();
        let daa = Params::from(NetworkId::with_suffix(NetworkType::Testnet, 10))
            .crescendo_activation
            .daa_score();
        let header = Header::new_finalized(
            1,
            vec![vec![TransactionId::from_bytes([17; 32])]]
                .try_into()
                .unwrap(),
            calc_hash_merkle_root([&tx].into_iter()),
            TransactionId::from_bytes([34; 32]),
            TransactionId::from_bytes([51; 32]),
            1,
            0x1d00ffff,
            7,
            daa,
            0u64.into(),
            1,
            TransactionId::from_bytes([68; 32]),
        );
        let accepting = TransactionId::from_bytes([85; 32]).to_string();
        Self {
            block: RpcBlock {
                header: RpcHeader::from(&header),
                transactions: vec![rpc_tx],
                verbose_data: None,
            },
            chain: ChainSnapshot {
                network: "testnet-10".into(),
                removed: vec![],
                added: vec![accepting.clone()],
                accepted: BTreeMap::from([(accepting, vec![tx.id().to_string()])]),
            },
            unavailable: false,
        }
    }
}

impl Transport for Fake {
    fn submit(&mut self, _: &RpcTransaction) -> Result<String, String> {
        Err("not used".into())
    }
    fn read_transaction(&mut self, _: &str) -> Result<Option<Value>, String> {
        Ok(None)
    }
    fn read_block(&mut self, hash: &str) -> Result<RpcBlock, String> {
        if self.unavailable {
            return Err("offline".into());
        }
        if self.block.header.hash.to_string() != hash {
            return Err("not found".into());
        }
        Ok(self.block.clone())
    }
    fn read_chain_state(&mut self, _: &str) -> Result<ChainSnapshot, String> {
        if self.unavailable {
            return Err("offline".into());
        }
        Ok(self.chain.clone())
    }
}

fn evidence(plan: Value, block: &RpcBlock) -> Value {
    let tx: RpcTransaction = serde_json::from_value(plan["transaction"].clone()).unwrap();
    let tx = Transaction::try_from(tx).unwrap();
    json!({"network":"testnet-10","plan":plan,"txid":tx.id().to_string(),"block_hash":block.header.hash.to_string(),
        "nodes":["wss://node-a.example/kaspa/testnet-10/wrpc/borsh","wss://node-b.example/kaspa/testnet-10/wrpc/borsh"]})
}

#[test]
fn registry_transaction_requires_matching_transaction_id() {
    let d = dir();
    let p = plan(&d);
    let mut a = Fake::new(&p);
    let mut b = Fake::new(&p);
    let mut request = evidence(p, &a.block);
    request["schema"] = json!("KTAPEOUT-TN10-REGISTRY-VERIFY-V1");
    request["transaction"] = request["plan"]["transaction"].clone();
    request.as_object_mut().unwrap().remove("plan");
    let out = d.join("verify.json");
    tn10_pipeline::verify_with_transports(&request, &out, &mut a, &mut b).unwrap();
    request["txid"] = json!("00".repeat(32));
    assert_eq!(
        tn10_pipeline::verify_with_transports(&request, &out, &mut a, &mut b)
            .unwrap_err()
            .to_string(),
        "TN10_PLAN_TRANSACTION_MISMATCH"
    );
}

#[test]
fn proof_is_recomputed_and_proof_valid_is_only_a_claim() {
    let d = dir();
    let p = plan(&d);
    let mut a = Fake::new(&p);
    let e = evidence(p, &a.block);
    let out = d.join("verify.json");
    let mut false_claim = e.clone();
    false_claim["proof_valid"] = json!(false);
    tn10_pipeline::verify_with_transports(
        &false_claim,
        &out,
        &mut a,
        &mut Fake::new(&false_claim["plan"]),
    )
    .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(&out).unwrap()).unwrap()["status"],
        "VERIFIED"
    );
    let mut bad = Fake::new(&e["plan"]);
    bad.block.transactions[0].payload.push(7);
    let mut true_claim = e;
    true_claim["proof_valid"] = json!(true);
    assert_eq!(
        tn10_pipeline::verify_with_transports(
            &true_claim,
            &out,
            &mut bad,
            &mut Fake::new(&true_claim["plan"])
        )
        .unwrap_err()
        .to_string(),
        "TRANSACTION_MERKLE_ROOT_MISMATCH"
    );
}

#[test]
fn proof_rejects_mutated_header_or_missing_transaction() {
    let d = dir();
    let p = plan(&d);
    let base = Fake::new(&p);
    let e = evidence(p, &base.block);
    let out = d.join("verify.json");
    for mutate in 0..2 {
        let mut bad = Fake::new(&e["plan"]);
        if mutate == 0 {
            bad.block.header.hash = "99".repeat(32).parse().unwrap();
        } else {
            bad.block.transactions.clear();
        }
        assert!(tn10_pipeline::verify_with_transports(
            &e,
            &out,
            &mut bad,
            &mut Fake::new(&e["plan"])
        )
        .is_err());
    }
}

#[test]
fn verify_requires_two_matching_nodes_and_selected_chain_depth() {
    let d = dir();
    let p = plan(&d);
    let base = Fake::new(&p);
    let mut e = evidence(p, &base.block);
    let out = d.join("verify.json");
    e["min_confirmations"] = json!(2);
    assert_eq!(
        tn10_pipeline::verify_with_transports(
            &e,
            &out,
            &mut Fake::new(&e["plan"]),
            &mut Fake::new(&e["plan"])
        )
        .unwrap_err()
        .to_string(),
        "TN10_CONFIRMATIONS_INSUFFICIENT"
    );
    let mut other = Fake::new(&e["plan"]);
    other.chain.added.push("66".repeat(32));
    assert_eq!(
        tn10_pipeline::verify_with_transports(&e, &out, &mut Fake::new(&e["plan"]), &mut other)
            .unwrap_err()
            .to_string(),
        "TN10_DUAL_NODE_DISAGREEMENT"
    );
    let mut offline = Fake::new(&e["plan"]);
    offline.unavailable = true;
    assert!(tn10_pipeline::verify_with_transports(
        &e,
        &out,
        &mut Fake::new(&e["plan"]),
        &mut offline
    )
    .is_err());
}

#[test]
fn verify_accepts_blue_merge_block_when_selected_chain_accepts_transaction() {
    let d = dir();
    let p = plan(&d);
    let mut merge = Fake::new(&p);
    let e = evidence(p, &merge.block);
    merge
        .chain
        .removed
        .push(merge.block.header.hash.to_string());
    let mut selected = Fake::new(&e["plan"]);
    tn10_pipeline::verify_with_transports(&e, &d.join("verify.json"), &mut merge, &mut selected)
        .unwrap();
}

#[test]
fn large_chain_snapshot_reports_only_a_bounded_confirmation_lower_bound() {
    const WINDOW: usize = 64;
    let txid = "aa".repeat(32);
    let block_hash = "ff".repeat(32);
    let added: Vec<String> = (1..=128).map(|n| format!("{n:064x}")).collect();
    let accepted_block = added[0].clone();
    let snapshot = ChainSnapshot {
        network: "testnet-10".into(),
        removed: vec![],
        added,
        accepted: BTreeMap::from([(accepted_block, vec![txid.clone()])]),
    };

    let acceptance =
        tn10_pipeline::chain_acceptance_from_snapshot(snapshot, &txid, &block_hash, WINDOW as u64)
            .unwrap();

    assert_eq!(acceptance.confirmations, WINDOW as u64);
    assert!(acceptance.sufficient);
    assert!(acceptance.truncated);
}

#[test]
fn acceptance_outside_window_fails_closed() {
    let txid = "aa".repeat(32);
    let added: Vec<String> = (1..=65).map(|n| format!("{n:064x}")).collect();
    let snapshot = ChainSnapshot {
        network: "testnet-10".into(),
        removed: vec![],
        accepted: BTreeMap::from([(added[64].clone(), vec![txid.clone()])]),
        added,
    };
    assert_eq!(
        tn10_pipeline::chain_acceptance_from_snapshot(snapshot, &txid, &"ff".repeat(32), 1)
            .unwrap_err()
            .to_string(),
        "TN10_TRANSACTION_ACCEPTANCE_OUTSIDE_WINDOW"
    );
}

#[test]
fn verify_window_reports_lower_bound_and_rejects_disagreement() {
    let d = dir();
    let p = plan(&d);
    let mut first = Fake::new(&p);
    let mut second = first.clone();
    let e = evidence(p, &first.block);
    let out = d.join("verify.json");
    for n in 1..=70 {
        let hash = format!("{n:064x}");
        first.chain.added.push(hash.clone());
        second.chain.added.push(hash);
    }
    tn10_pipeline::verify_with_transports(&e, &out, &mut first, &mut second).unwrap();
    let result: Value = serde_json::from_slice(&fs::read(&out).unwrap()).unwrap();
    assert_eq!(result["confirmations_lower_bound"], 64);
    assert_eq!(result["truncated"], true);
    second.chain.accepted.clear();
    assert!(tn10_pipeline::verify_with_transports(&e, &out, &mut first, &mut second).is_err());
}

#[test]
fn minimum_confirmations_above_window_is_rejected() {
    let txid = "aa".repeat(32);
    let block_hash = "ff".repeat(32);
    let added: Vec<String> = (1..=128).map(|n| format!("{n:064x}")).collect();
    let accepted_block = added[0].clone();
    let snapshot = ChainSnapshot {
        network: "testnet-10".into(),
        removed: vec![],
        added,
        accepted: BTreeMap::from([(accepted_block, vec![txid.clone()])]),
    };

    assert_eq!(
        tn10_pipeline::chain_acceptance_from_snapshot(snapshot, &txid, &block_hash, 65)
            .unwrap_err()
            .to_string(),
        "TN10_CONFIRMATION_WINDOW_EXCEEDED"
    );
}

#[test]
fn wrpc_block_read_uses_shared_runtime_timeout_helper_source_check() {
    let source = include_str!("../src/tn10_pipeline.rs");
    let read_block = source
        .split("fn read_block(&mut self, hash: &str)")
        .nth(1)
        .expect("WrpcTransport::read_block must remain present")
        .split("fn read_chain_state")
        .next()
        .expect("read_block must end before read_chain_state");

    assert!(read_block.contains("run_with_timeout"));
    assert!(read_block.contains("RPC_TIMEOUT"));
    assert!(!read_block.contains(".block_on("));
    assert!(!read_block.contains("tokio::time::timeout("));
}
