#![cfg(all(feature = "developer-signing", feature = "tn10-network"))]

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
use sha2::Digest;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

fn directory() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let p = std::env::temp_dir().join(format!(
        "kt-sign-cli-{}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&p).unwrap();
    p
}
fn request() -> Value {
    json!({"schema":"KTAPEOUT-RESOURCE-PAYLOAD-CANDIDATE-V1","network":"testnet-10",
        "artifact":{"artifact_sha256":"00".repeat(32),"files":[]},
        "funding_utxo":{"outpoint":format!("{}:0","01".repeat(32)),"amount":1_000_000_000u64,
            "script_public_key":"0000201cf37eb561f80022293855860f47122025c0929a05f6f08c503ed7f2325cafd5ac", "block_daa_score":1,"covenant_id":null},
        "fee_sompi":30_000_000})
}
fn plan(dir: &Path, req: &Value) -> PathBuf {
    let input = dir.join("request.json");
    let output = dir.join("plan.json");
    fs::write(&input, serde_json::to_vec(req).unwrap()).unwrap();
    tn10_pipeline::plan(&input, &output).unwrap();
    output
}
fn command(dir: &Path, extra: &[&str], stdin_material: Option<&str>) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ktape"))
        .args(["tn10", "sign"])
        .arg(dir.join("plan.json"))
        .arg(dir.join("signed.json"))
        .args(extra)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(value) = stdin_material {
        child
            .stdin
            .take()
            .unwrap()
            .write_all(value.as_bytes())
            .unwrap();
    }
    drop(child.stdin.take());
    child.wait_with_output().unwrap()
}
fn assert_no_secret(bytes: &[u8]) {
    use base64::Engine;
    for raw in [[73u8; 32], [72u8; 32]] {
        for needle in [
            raw.to_vec(),
            hex::encode(raw).into_bytes(),
            hex::encode_upper(raw).into_bytes(),
            base64::engine::general_purpose::STANDARD
                .encode(raw)
                .into_bytes(),
        ] {
            assert!(
                !bytes.windows(needle.len()).any(|w| w == needle),
                "secret leaked into public output"
            );
        }
    }
}
#[derive(Clone)]
struct Fake {
    block: RpcBlock,
    chain: ChainSnapshot,
    timeout: bool,
}
impl Fake {
    fn new(signed: &Value) -> Self {
        let rpc: RpcTransaction = serde_json::from_value(signed["transaction"].clone()).unwrap();
        let tx = Transaction::try_from(rpc.clone()).unwrap();
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
                transactions: vec![rpc],
                verbose_data: None,
            },
            chain: ChainSnapshot {
                network: "testnet-10".into(),
                removed: vec![],
                added: vec![accepting.clone()],
                accepted: [(accepting, vec![tx.id().to_string()])].into(),
            },
            timeout: false,
        }
    }
}
impl Transport for Fake {
    fn submit(&mut self, tx: &RpcTransaction) -> Result<String, String> {
        if self.timeout {
            return Err("timeout".into());
        }
        Ok(Transaction::try_from(tx.clone()).unwrap().id().to_string())
    }
    fn read_transaction(&mut self, _: &str) -> Result<Option<Value>, String> {
        Err("offline reconciliation unavailable".into())
    }
    fn read_block(&mut self, _: &str) -> Result<RpcBlock, String> {
        Ok(self.block.clone())
    }
    fn read_chain_state(&mut self, _: &str) -> Result<ChainSnapshot, String> {
        Ok(self.chain.clone())
    }
}

#[test]
fn local_signature_passes_submission_validation_without_secret_leakage() {
    let dir = directory();
    plan(&dir, &request());
    let output = command(&dir, &["--key-stdin", "--yes"], Some(&"49".repeat(32)));
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_no_secret(&output.stdout);
    assert_no_secret(&output.stderr);
    fs::write(dir.join("stdout.log"), &output.stdout).unwrap();
    fs::write(dir.join("stderr.log"), &output.stderr).unwrap();
    let signed: Value =
        serde_json::from_slice(&fs::read(dir.join("signed.json")).unwrap()).unwrap();
    let mut first = Fake::new(&signed);
    let mut second = first.clone();
    let evidence = dir.join("submit.json");
    tn10_pipeline::submit_with_transport(&dir.join("signed.json"), &evidence, &mut first).unwrap();
    let submitted: Value = serde_json::from_slice(&fs::read(&evidence).unwrap()).unwrap();
    assert_eq!(submitted["status"], "SUBMITTED");
    let proof = json!({"network":"testnet-10", "plan":signed,
        "txid":submitted["txid"], "block_hash":first.block.header.hash.to_string(),
        "nodes":["wss://node-a.example/kaspa/testnet-10/wrpc/borsh",
                 "wss://node-b.example/kaspa/testnet-10/wrpc/borsh"]});
    fs::write(dir.join("proof.json"), serde_json::to_vec(&proof).unwrap()).unwrap();
    let verification = dir.join("verify.json");
    tn10_pipeline::verify_with_transports(&proof, &verification, &mut first, &mut second).unwrap();
    let verified: Value = serde_json::from_slice(&fs::read(&verification).unwrap()).unwrap();
    assert_eq!(verified["status"], "VERIFIED");
    first.timeout = true;
    let timeout = dir.join("timeout.json");
    assert_eq!(
        tn10_pipeline::submit_with_transport(&dir.join("signed.json"), &timeout, &mut first)
            .unwrap_err()
            .to_string(),
        "TN10_SUBMISSION_UNKNOWN"
    );
    let unknown: Value = serde_json::from_slice(&fs::read(timeout).unwrap()).unwrap();
    assert_eq!(unknown["status"], "SUBMISSION_UNKNOWN");
    second.block.transactions.clear();
    let error = tn10_pipeline::verify_with_transports(
        &proof,
        &dir.join("invalid-proof.json"),
        &mut first,
        &mut second,
    )
    .unwrap_err();
    fs::write(dir.join("error.log"), error.to_string()).unwrap();
    for entry in fs::read_dir(&dir).unwrap() {
        let p = entry.unwrap().path();
        if p.is_file() {
            assert_no_secret(&fs::read(p).unwrap());
        }
    }
}

#[test]
fn refusals_never_echo_secret_or_emit_signed_output() {
    let cases = [
        vec!["--key-stdin"],
        vec![
            "--key",
            "4949494949494949494949494949494949494949494949494949494949494949",
            "--yes",
        ],
        vec!["--key-stdin", "--yes"],
    ];
    for (i, args) in cases.iter().enumerate() {
        let dir = directory();
        let mut req = request();
        if i == 2 {
            req["max_total_fee_sompi"] = json!(1);
        }
        plan(&dir, &req);
        let output = command(&dir, args, Some(&"49".repeat(32)));
        assert!(!output.status.success());
        assert!(!dir.join("signed.json").exists());
        assert_no_secret(&output.stdout);
        assert_no_secret(&output.stderr);
    }
}

#[test]
fn external_import_requires_real_approval_and_yes_keeps_budgets() {
    let source = directory();
    plan(&source, &request());
    // Worthless fixed test key; never fund.
    assert!(
        command(&source, &["--key-stdin", "--yes"], Some(&"49".repeat(32)))
            .status
            .success()
    );
    let signed: Value =
        serde_json::from_slice(&fs::read(source.join("signed.json")).unwrap()).unwrap();
    for case in ["file_confirmation", "yes", "over_budget"] {
        let dir = directory();
        let path = plan(&dir, &request());
        let mut frozen: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        frozen["confirmed"] = json!(true);
        if case == "over_budget" {
            frozen["request"]["max_fee_sompi"] = json!(1);
        }
        fs::write(path, serde_json::to_vec(&frozen).unwrap()).unwrap();
        fs::write(
            dir.join("signature.json"),
            serde_json::to_vec(&json!({
                "network":"testnet-10", "sighash":signed["input_sighash_all"],
                "signature":signed["signature"], "confirmed":true,
            }))
            .unwrap(),
        )
        .unwrap();
        let signature = dir.join("signature.json");
        let mut args = vec!["--signature", signature.to_str().unwrap()];
        if case != "file_confirmation" {
            args.push("--yes");
        }
        let result = command(&dir, &args, None);
        assert_eq!(
            result.status.success(),
            case == "yes",
            "{case}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(dir.join("signed.json").exists(), case == "yes");
        assert_no_secret(&result.stdout);
        assert_no_secret(&result.stderr);
        for entry in fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_file() {
                assert_no_secret(&fs::read(path).unwrap());
            }
        }
    }
}

#[cfg(unix)]
#[test]
fn sign_rejects_group_or_other_readable_secret_path() {
    use std::os::unix::fs::PermissionsExt;

    let dir = directory();
    plan(&dir, &request());
    let key = dir.join("test-key.hex");
    fs::write(&key, "49".repeat(32)).unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();

    let result = Command::new(env!("CARGO_BIN_EXE_ktape"))
        .args(["tn10", "sign"])
        .arg(dir.join("plan.json"))
        .arg(dir.join("signed.json"))
        .args(["--key-file"])
        .arg(&key)
        .arg("--yes")
        .output()
        .unwrap();

    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("TN10_SECRET_FILE_PERMISSIONS_UNSAFE"));
    assert!(!dir.join("signed.json").exists());
}

#[test]
fn fee_value_and_wrong_key_refusals_leave_no_secret_in_artifacts() {
    for case in ["fee", "value", "total_value", "wrong_key", "network"] {
        let dir = directory();
        let req = request();
        let plan_path = plan(&dir, &req);
        let mut frozen: Value = serde_json::from_slice(&fs::read(&plan_path).unwrap()).unwrap();
        match case {
            "fee" => frozen["request"]["max_fee_sompi"] = json!(1),
            "value" => frozen["request"]["max_value_sompi"] = json!(1),
            "total_value" => frozen["request"]["max_total_value_sompi"] = json!(1),
            "network" => frozen["network"] = json!("mainnet"),
            _ => {}
        }
        fs::write(&plan_path, serde_json::to_vec(&frozen).unwrap()).unwrap();
        let signing_material = if case == "wrong_key" { "48" } else { "49" }.repeat(32);
        let output = command(&dir, &["--key-stdin", "--yes"], Some(&signing_material));
        assert!(!output.status.success(), "{case}");
        assert!(!dir.join("signed.json").exists(), "{case}");
        assert_no_secret(&output.stdout);
        assert_no_secret(&output.stderr);
        for entry in fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_file() {
                assert_no_secret(&fs::read(path).unwrap());
            }
        }
    }
}

#[test]
fn signing_source_text_is_the_only_secret_boundary_and_has_no_transport() {
    // This is a source-text boundary check, not a runtime isolation proof.
    let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let signer = fs::read_to_string(source.join("tn10_developer_signing.rs")).unwrap();
    for forbidden in [
        "kaspa_wrpc",
        "RpcClient",
        "Transport",
        "TcpStream",
        "reqwest",
    ] {
        assert!(
            !signer.contains(forbidden),
            "network dependency in signer: {forbidden}"
        );
    }
    for file in ["tn10_pipeline.rs", "tn10_block_proof.rs"] {
        let keyless = fs::read_to_string(source.join(file)).unwrap();
        for forbidden in [
            concat!("Secret", "Key"),
            concat!("Key", "pair"),
            concat!("Signing", "Key"),
        ] {
            assert!(
                !keyless.contains(forbidden),
                "secret type in keyless phase: {forbidden}"
            );
        }
    }
}

#[test]
fn approval_summary_binds_payload_digest_size_and_artifact() {
    let dir = directory();
    let plan_path = plan(&dir, &request());
    let frozen: Value = serde_json::from_slice(&fs::read(&plan_path).unwrap()).unwrap();
    let summary = tn10_pipeline::signing_summary(&frozen).unwrap();
    let payload = hex::decode(frozen["transaction"]["payload"].as_str().unwrap()).unwrap();
    let expected = hex::encode(sha2::Sha256::digest(&payload));
    assert_eq!(summary["payload_sha256"], expected);
    assert_eq!(summary["payload_bytes"], payload.len());
    assert_eq!(summary["artifact"], frozen["request"]["artifact"]);
    let mut approval = Vec::new();
    ktapeout_cli::tn10_developer_signing::confirm(
        &frozen,
        false,
        true,
        std::io::Cursor::new(b"SIGN\n"),
        &mut approval,
    )
    .unwrap();
    let printed = String::from_utf8(approval).unwrap();
    assert!(printed.contains(&expected));
    assert_eq!(printed.matches(&expected).count(), 1);
    assert!(printed.contains("payload_sha256"));
    assert!(printed.contains("payload_bytes"));
    assert!(printed.contains(&payload.len().to_string()));

    let mut changed = request();
    changed["artifact"]["artifact_sha256"] = json!("ab".repeat(32));
    let changed_path = plan(&dir, &changed);
    let changed_plan: Value = serde_json::from_slice(&fs::read(changed_path).unwrap()).unwrap();
    let changed_summary = tn10_pipeline::signing_summary(&changed_plan).unwrap();
    assert_ne!(summary["payload_sha256"], changed_summary["payload_sha256"]);
}

#[test]
fn plan_rejects_uppercase_content_commitment_digest() {
    let dir = directory();
    let mut req = request();
    req["artifact"]["content_commitment_sha256"] = json!("AB".repeat(32));
    let input = dir.join("request.json");
    let output = dir.join("plan.json");
    fs::write(&input, serde_json::to_vec(&req).unwrap()).unwrap();

    let error = tn10_pipeline::plan(&input, &output)
        .unwrap_err()
        .to_string();
    assert_eq!(error, "TN10_CONTENT_COMMITMENT_SHA256_NONCANONICAL");
    assert!(!output.exists());
}
