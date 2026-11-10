//! Single-binary TN10 publication pipeline.
//!
//! `plan` is deterministic and keyless. `sign` can use a developer key locally
//! or import a detached Schnorr signature from an external offline signer.
//! `submit` and `verify` consume only public transaction/evidence bytes and an
//! injected transport.

use kaspa_consensus_core::hashing::sighash::{
    calc_schnorr_signature_hash, SigHashReusedValuesUnsync,
};
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::tx::{
    CovenantBinding, MutableTransaction, ScriptPublicKey, Transaction, TransactionId,
    TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry,
};
use kaspa_consensus_core::Hash;
use kaspa_rpc_core::{RpcBlock, RpcTransaction};
use secp256k1::{schnorr::Signature, Message, Secp256k1, XOnlyPublicKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

const SCHEMA: &str = "KTAPEOUT-RESOURCE-PAYLOAD-CANDIDATE-V1";
const NETWORK: &str = "testnet-10";
const MAX_ARTIFACT_BYTES: usize = 96 * 1024;
const RPC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
const NATIVE_REGISTRATION_COMPUTE_BUDGETS: &str =
    include_str!("../../../data/registry/native-registration-compute-budgets-v1.json");
// A bounded prefix proves only a lower bound; acceptance beyond it fails closed.
const CHAIN_WINDOW: usize = 64;
// TN10 has no fixed one-KAS change floor; storage mass constrains small outputs.
const MIN_CHANGE_SOMPI: u64 = 1;
/// One accepting selected-chain block is the minimum TN10 observation, not finality.
pub const DEFAULT_MIN_CONFIRMATIONS: u64 = 1;

fn parse_native_witness_item(
    item: &Value,
) -> Result<ktapeout_kaspa_verifier::toccata_witness::WitnessItem, Error> {
    use ktapeout_kaspa_verifier::toccata_witness::WitnessItem;
    if let Some(raw) = item["data_hex"].as_str() {
        if raw.len() % 2 != 0
            || raw
                .bytes()
                .any(|byte| byte.is_ascii_uppercase() || !byte.is_ascii_hexdigit())
        {
            return Err("TN10_REGISTRATION_WITNESS_CONTEXT_INVALID".into());
        }
        return Ok(WitnessItem::Data(hex::decode(raw)?));
    }
    if let Some(opcode) = item["opcode"]
        .as_u64()
        .filter(|value| *value <= u8::MAX as u64)
    {
        return Ok(WitnessItem::Opcode(opcode as u8));
    }
    Err("TN10_REGISTRATION_WITNESS_CONTEXT_INVALID".into())
}

fn native_registration_witness_contexts(request: &Value, inputs: &[Value]) -> Result<Value, Error> {
    use ktapeout_kaspa_verifier::toccata_witness::{
        build_toccata_p2sh_witness, signature_slot_indices_for_arguments, AbiEntryPoint,
    };
    let contexts = request["covenant_witness_contexts"]
        .as_array()
        .filter(|contexts| contexts.len() == 2)
        .ok_or("TN10_REGISTRATION_WITNESS_CONTEXT_REQUIRED")?;
    let expected_entrypoints = ["authorize_child", "register_interior"];
    let mut normalized = Vec::with_capacity(2);
    for (input_index, (context, entrypoint_name)) in
        contexts.iter().zip(expected_entrypoints).enumerate()
    {
        if context["input_index"].as_u64() != Some(input_index as u64)
            || context["entrypoint"].as_str() != Some(entrypoint_name)
        {
            return Err("TN10_REGISTRATION_WITNESS_CONTEXT_INVALID".into());
        }
        let registration_kind = if input_index == 1 {
            let kind = request["registration_kind"]
                .as_str()
                .filter(|kind| matches!(*kind, "INTERIOR" | "SLOT"))
                .ok_or("TN10_REGISTRATION_KIND_INVALID")?;
            Some(kind)
        } else {
            None
        };
        let entrypoint = AbiEntryPoint::parse(entrypoint_name)
            .map_err(|_| "TN10_REGISTRATION_WITNESS_ENTRYPOINT_INVALID")?;
        let redeem_hex = context["redeem_script_hex"]
            .as_str()
            .filter(|raw| {
                raw.len() >= 512
                    && raw.len() <= u16::MAX as usize * 2
                    && raw.len() % 2 == 0
                    && raw
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            })
            .ok_or("TN10_REGISTRATION_WITNESS_REDEEM_SCRIPT_INVALID")?;
        let redeem_script = hex::decode(redeem_hex)?;
        let public_key = inputs[input_index]["script_public_key"]
            .as_str()
            .filter(|raw| raw.len() == 74 && raw.starts_with("0000aa20") && raw.ends_with("87"))
            .ok_or("TN10_REGISTRATION_WITNESS_SPK_INVALID")?;
        let expected_hash = crate::name_state_template::blake2b_256(&redeem_script);
        if public_key[8..72] != hex::encode(expected_hash) {
            return Err("TN10_REGISTRATION_WITNESS_REDEEM_HASH_MISMATCH".into());
        }
        let arguments = context["arguments"]
            .as_array()
            .filter(|items| !items.is_empty())
            .ok_or("TN10_REGISTRATION_WITNESS_ARGUMENTS_REQUIRED")?
            .iter()
            .map(parse_native_witness_item)
            .collect::<Result<Vec<_>, _>>()?;
        let signature_slots = signature_slot_indices_for_arguments(entrypoint, &arguments)
            .map_err(|_| "TN10_REGISTRATION_WITNESS_CONTEXT_INVALID")?;
        for slot in signature_slots {
            if !matches!(arguments.get(*slot), Some(ktapeout_kaspa_verifier::toccata_witness::WitnessItem::Data(bytes)) if bytes.len() == 65 && bytes.iter().all(|byte| *byte == 0))
            {
                return Err("TN10_REGISTRATION_WITNESS_SIGNATURE_SLOT_INVALID".into());
            }
        }
        build_toccata_p2sh_witness(entrypoint, &arguments, &redeem_script)
            .map_err(|_| "TN10_REGISTRATION_WITNESS_CONTEXT_INVALID")?;
        normalized.push(json!({
            "input_index":input_index,
            "entrypoint":entrypoint_name,
            "registration_kind":registration_kind,
            "redeem_script_hex":redeem_hex,
            "arguments":context["arguments"],
            "signature_slot_indices":signature_slots
        }));
    }
    Ok(Value::Array(normalized))
}

fn is_native_signable_plan(plan: &Value) -> bool {
    matches!(
        plan["schema"].as_str(),
        Some("KTAPEOUT-TN10-NATIVE-CHILD-REGISTRATION-PLAN-V3")
            | Some("KTAPEOUT-TN10-NATIVE-OWNER-TARGET-PLAN-V1")
    )
}

fn validate_endpoint(endpoint: &str) -> Result<(), Error> {
    let rest = endpoint
        .strip_prefix("wss://")
        .ok_or("TN10_ENDPOINT_INVALID")?;
    let (authority, path) = rest.split_once('/').ok_or("TN10_ENDPOINT_INVALID")?;
    if authority.is_empty()
        || authority.contains(['@', '?', '#'])
        || path != "kaspa/testnet-10/wrpc/borsh"
    {
        return Err("TN10_ENDPOINT_INVALID".into());
    }
    let (host, port) = match authority.split_once(':') {
        Some((host, port)) if !port.is_empty() && !port.contains(':') => (host, Some(port)),
        Some(_) => return Err("TN10_ENDPOINT_INVALID".into()),
        None => (authority, None),
    };
    if port.is_some_and(|value| value.parse::<u16>().is_err())
        || host.parse::<IpAddr>().is_ok()
        || host
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        return Err("TN10_ENDPOINT_PUBLIC_DNS_REQUIRED".into());
    }
    let host = host.to_ascii_lowercase();
    let labels: Vec<&str> = host.split('.').collect();
    if host.len() > 253
        || !host.contains('.')
        || labels.last().is_none_or(|label| {
            !label.starts_with("xn--") && !label.bytes().any(|byte| byte.is_ascii_alphabetic())
        })
        || ["localhost", "local", "internal", "lan"]
            .iter()
            .any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}")))
        || host.ends_with(".home.arpa")
        || labels.iter().any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || label.bytes().all(|byte| byte.is_ascii_digit())
                || label.strip_prefix("0x").is_some_and(|suffix| {
                    !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err("TN10_ENDPOINT_PUBLIC_DNS_REQUIRED".into());
    }
    Ok(())
}

pub type Error = Box<dyn std::error::Error>;

/// A node's virtual-chain observation, never caller-supplied proof of acceptance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainSnapshot {
    pub network: String,
    pub removed: Vec<String>,
    pub added: Vec<String>,
    pub accepted: std::collections::BTreeMap<String, Vec<String>>,
}

/// Minimal network boundary. Implementations must not receive signing keys.
pub trait Transport {
    fn submit(&mut self, transaction: &RpcTransaction) -> Result<String, String>;
    fn read_transaction(&mut self, txid: &str) -> Result<Option<Value>, String>;
    fn read_fee_estimate(&mut self) -> Result<Value, String> {
        Err("TN10_FEE_ESTIMATE_TRANSPORT_REQUIRED".into())
    }
    fn read_utxos(&mut self, _address: &str) -> Result<Value, String> {
        Err("TN10_UTXO_TRANSPORT_REQUIRED".into())
    }
    fn read_observation(&mut self) -> Result<Value, String> {
        Err("TN10_OBSERVATION_TRANSPORT_REQUIRED".into())
    }
    fn read_blocks_after(
        &mut self,
        _hash: &str,
    ) -> Result<kaspa_rpc_core::GetBlocksResponse, String> {
        Err("TN10_SCAN_TRANSPORT_REQUIRED".into())
    }
    fn read_block(&mut self, _hash: &str) -> Result<RpcBlock, String> {
        Err("TN10_BLOCK_TRANSPORT_REQUIRED".into())
    }
    /// Locate a transaction in an explicitly nominated block; no global index is assumed.
    fn read_transaction_in_block(
        &mut self,
        txid: &str,
        hash: &str,
    ) -> Result<Option<RpcTransaction>, String> {
        let block = self.read_block(hash)?;
        for transaction in block.transactions {
            let canonical = Transaction::try_from(transaction.clone())
                .map_err(|_| "TN10_TRANSACTION_INVALID")?;
            if canonical.id().to_string() == txid {
                return Ok(Some(transaction));
            }
        }
        Ok(None)
    }
    fn read_chain_state(&mut self, _hash: &str) -> Result<ChainSnapshot, String> {
        Err("TN10_CHAIN_STATE_TRANSPORT_REQUIRED".into())
    }
}

#[cfg(feature = "tn10-network")]
pub struct WrpcTransport {
    client: kaspa_wrpc_client::KaspaRpcClient,
    runtime: tokio::runtime::Runtime,
}

#[cfg(feature = "tn10-network")]
#[doc(hidden)]
pub fn run_with_timeout<F: std::future::Future>(
    runtime: &tokio::runtime::Runtime,
    timeout: std::time::Duration,
    future: F,
) -> Result<F::Output, tokio::time::error::Elapsed> {
    runtime.block_on(async { tokio::time::timeout(timeout, future).await })
}

#[cfg(feature = "tn10-network")]
impl WrpcTransport {
    pub fn connect(endpoint: &str) -> Result<Self, Error> {
        use kaspa_rpc_core::api::rpc::RpcApi;
        let network = kaspa_wrpc_client::prelude::NetworkId::with_suffix(
            kaspa_wrpc_client::prelude::NetworkType::Testnet,
            10,
        );
        validate_endpoint(endpoint)?;
        let client = kaspa_wrpc_client::KaspaRpcClient::new(
            kaspa_wrpc_client::WrpcEncoding::Borsh,
            Some(endpoint),
            None,
            Some(network),
            None,
        )?;
        let runtime = tokio::runtime::Runtime::new()?;
        run_with_timeout(
            &runtime,
            RPC_TIMEOUT,
            client.connect(Some(kaspa_wrpc_client::client::ConnectOptions {
                block_async_connect: true,
                connect_timeout: Some(std::time::Duration::from_secs(15)),
                strategy: kaspa_wrpc_client::client::ConnectStrategy::Fallback,
                ..Default::default()
            })),
        )
        .map_err(|_| "TN10_CONNECT_TIMEOUT")??;
        let dag = run_with_timeout(&runtime, RPC_TIMEOUT, client.get_block_dag_info())
            .map_err(|_| "TN10_READ_TIMEOUT")??;
        if dag.network != network {
            return Err("TN10_NETWORK_MISMATCH".into());
        }
        Ok(Self { client, runtime })
    }
}

#[cfg(feature = "tn10-network")]
impl Transport for WrpcTransport {
    fn read_fee_estimate(&mut self) -> Result<Value, String> {
        use kaspa_rpc_core::api::rpc::RpcApi;
        let estimate = run_with_timeout(&self.runtime, RPC_TIMEOUT, self.client.get_fee_estimate())
            .map_err(|_| "TN10_READ_TIMEOUT".to_string())?
            .map_err(|error| error.to_string())?;
        serde_json::to_value(estimate).map_err(|error| error.to_string())
    }

    fn read_observation(&mut self) -> Result<Value, String> {
        use kaspa_rpc_core::api::rpc::RpcApi;
        run_with_timeout(&self.runtime, RPC_TIMEOUT, async {
            let dag = self
                .client
                .get_block_dag_info()
                .await
                .map_err(|e| e.to_string())?;
            let info = self.client.get_info().await.map_err(|e| e.to_string())?;
            Ok(
                json!({"network":dag.network.to_string(), "synced":info.is_synced,
                    "utxo_indexed":info.is_utxo_indexed, "start_hash":dag.sink.to_string(),
                    "virtual_daa_score":dag.virtual_daa_score}),
            )
        })
        .map_err(|_| "TN10_READ_TIMEOUT".to_string())?
    }

    fn read_blocks_after(
        &mut self,
        hash: &str,
    ) -> Result<kaspa_rpc_core::GetBlocksResponse, String> {
        use kaspa_rpc_core::api::rpc::RpcApi;
        let hash = hash.parse().map_err(|_| "TN10_BLOCK_HASH_INVALID")?;
        run_with_timeout(
            &self.runtime,
            RPC_TIMEOUT,
            self.client.get_blocks(Some(hash), true, true),
        )
        .map_err(|_| "TN10_READ_TIMEOUT".to_string())?
        .map_err(|e| e.to_string())
    }

    fn read_utxos(&mut self, address: &str) -> Result<Value, String> {
        use kaspa_rpc_core::api::rpc::RpcApi;
        if !address.starts_with("kaspatest:") {
            return Err("TN10_ADDRESS_REQUIRED".into());
        }
        let address = address.try_into().map_err(|_| "TN10_ADDRESS_INVALID")?;
        let entries = run_with_timeout(
            &self.runtime,
            RPC_TIMEOUT,
            self.client.get_utxos_by_addresses(vec![address]),
        )
        .map_err(|_| "TN10_READ_TIMEOUT".to_string())?
        .map_err(|error| error.to_string())?;
        serde_json::to_value(entries).map_err(|error| error.to_string())
    }

    fn read_block(&mut self, hash: &str) -> Result<RpcBlock, String> {
        use kaspa_rpc_core::api::rpc::RpcApi;
        let hash = hash.parse().map_err(|_| "TN10_BLOCK_HASH_INVALID")?;
        run_with_timeout(
            &self.runtime,
            RPC_TIMEOUT,
            self.client.get_block(hash, true),
        )
        .map_err(|_| "TN10_READ_TIMEOUT".to_string())?
        .map_err(|error| error.to_string())
    }

    fn read_chain_state(&mut self, hash: &str) -> Result<ChainSnapshot, String> {
        use kaspa_rpc_core::api::rpc::RpcApi;
        let hash = hash.parse().map_err(|_| "TN10_BLOCK_HASH_INVALID")?;
        let (dag, response) = run_with_timeout(&self.runtime, RPC_TIMEOUT, async {
            let dag = self
                .client
                .get_block_dag_info()
                .await
                .map_err(|e| e.to_string())?;
            let response = self
                .client
                .get_virtual_chain_from_block(hash, true, None)
                .await
                .map_err(|e| e.to_string())?;
            Ok::<_, String>((dag, response))
        })
        .map_err(|_| "TN10_READ_TIMEOUT".to_string())??;
        let network = dag.network.to_string();
        if network != NETWORK {
            return Err("TN10_NETWORK_MISMATCH".into());
        }
        Ok(ChainSnapshot {
            network,
            removed: response
                .removed_chain_block_hashes
                .iter()
                .map(ToString::to_string)
                .collect(),
            added: response
                .added_chain_block_hashes
                .iter()
                .map(ToString::to_string)
                .collect(),
            accepted: response
                .accepted_transaction_ids
                .into_iter()
                .map(|entry| {
                    (
                        entry.accepting_block_hash.to_string(),
                        entry
                            .accepted_transaction_ids
                            .iter()
                            .map(ToString::to_string)
                            .collect(),
                    )
                })
                .collect(),
        })
    }

    fn submit(&mut self, transaction: &RpcTransaction) -> Result<String, String> {
        use kaspa_rpc_core::api::rpc::RpcApi;
        run_with_timeout(
            &self.runtime,
            RPC_TIMEOUT,
            self.client.submit_transaction(transaction.clone(), false),
        )
        .map_err(|_| "TN10_SUBMISSION_UNKNOWN".to_string())?
        .map(|id| id.to_string())
        .map_err(|error| error.to_string())
    }

    fn read_transaction(&mut self, txid: &str) -> Result<Option<Value>, String> {
        use kaspa_rpc_core::api::rpc::RpcApi;
        let entries = run_with_timeout(
            &self.runtime,
            RPC_TIMEOUT,
            self.client.get_mempool_entries(false, false),
        )
        .map_err(|_| "TN10_READ_TIMEOUT".to_string())?
        .map_err(|error| error.to_string())?;
        Ok(entries
            .into_iter()
            .find(|entry| {
                Transaction::try_from(entry.transaction.clone())
                    .map(|transaction| transaction.id().to_string() == txid)
                    .unwrap_or(false)
            })
            .map(|entry| json!({"txid": txid, "mempool": true, "entry": entry})))
    }
}

#[cfg(feature = "tn10-network")]
impl Drop for WrpcTransport {
    fn drop(&mut self) {
        let _ = run_with_timeout(&self.runtime, RPC_TIMEOUT, self.client.disconnect());
    }
}

fn read_json(path: &Path) -> Result<Value, Error> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn write_json(path: &Path, value: &Value) -> Result<(), Error> {
    fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

fn write_json_new_atomic(path: &Path, value: &Value) -> Result<(), Error> {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path.file_name().ok_or("TN10_SUBMISSION_PATH_INVALID")?;
    let temporary = parent.join(format!(
        ".{}.{}.{}.tmp",
        name.to_string_lossy(),
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let bytes = serde_json::to_vec_pretty(value)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    let linked = fs::hard_link(&temporary, path);
    let _ = fs::remove_file(&temporary);
    let result: Result<(), Error> = linked.map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            Box::<dyn std::error::Error>::from(std::io::Error::new(
                error.kind(),
                "TN10_SUBMISSION_RESULT_EXISTS",
            ))
        } else {
            Box::<dyn std::error::Error>::from(error)
        }
    });
    result?;
    sync_parent(parent)?;
    Ok(())
}

fn replace_json_atomic(path: &Path, value: &Value) -> Result<(), Error> {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path.file_name().ok_or("TN10_SUBMISSION_PATH_INVALID")?;
    let temporary = parent.join(format!(
        ".{}.{}.{}.replace",
        name.to_string_lossy(),
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let bytes = serde_json::to_vec_pretty(value)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, path)?;
    sync_parent(parent)?;
    Ok(())
}

fn validate_input_output_paths(input: &Path, output: &Path) -> Result<(), Error> {
    if let Ok(metadata) = fs::symlink_metadata(output) {
        if metadata.file_type().is_symlink() {
            return Err("TN10_OUTPUT_SYMLINK_REJECTED".into());
        }
    }
    let input = fs::canonicalize(input).map_err(|_| "TN10_INPUT_PATH_INVALID")?;
    let output_absolute = if output.exists() {
        fs::canonicalize(output).map_err(|_| "TN10_OUTPUT_PATH_INVALID")?
    } else {
        let parent = output
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        fs::canonicalize(parent)
            .map_err(|_| "TN10_OUTPUT_PATH_INVALID")?
            .join(output.file_name().ok_or("TN10_OUTPUT_PATH_INVALID")?)
    };
    if input == output_absolute {
        return Err("TN10_INPUT_OUTPUT_PATHS_MUST_DIFFER".into());
    }
    Ok(())
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> Result<(), Error> {
    std::fs::File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(windows)]
fn sync_parent(path: &Path) -> Result<(), Error> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{
        CloseHandle, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FlushFileBuffers, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };

    let wide_path = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    // Flush the directory entry after the already-flushed record is linked/renamed.
    let handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error().into());
    }
    let flushed = unsafe { FlushFileBuffers(handle) };
    unsafe { CloseHandle(handle) };
    if flushed == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn sync_parent(_path: &Path) -> Result<(), Error> {
    Ok(())
}

fn plan_digest(plan: &Value) -> Result<String, Error> {
    let summary = signing_summary(plan)?;
    use sha2::Digest;
    Ok(hex::encode(sha2::Sha256::digest(serde_json::to_vec(
        &summary,
    )?)))
}

fn parse_spk(value: &Value) -> Result<ScriptPublicKey, Error> {
    let text = value.as_str().ok_or("TN10_SCRIPT_REQUIRED")?;
    let bytes = hex::decode(text)?;
    if bytes.len() < 3 || bytes[0] != 0 || bytes[1] != 0 || hex::encode(&bytes) != text {
        return Err("TN10_SCRIPT_NONCANONICAL".into());
    }
    Ok(ScriptPublicKey::from_vec(0, bytes[2..].to_vec()))
}

fn parse_utxo(value: &Value) -> Result<(TransactionOutpoint, UtxoEntry), Error> {
    let o = value.as_object().ok_or("TN10_UTXO_REQUIRED")?;
    let raw = o
        .get("outpoint")
        .and_then(Value::as_str)
        .ok_or("TN10_OUTPOINT_REQUIRED")?;
    let (txid, index) = raw.split_once(':').ok_or("TN10_OUTPOINT_NONCANONICAL")?;
    let id: [u8; 32] = hex::decode(txid)?
        .try_into()
        .map_err(|_| "TN10_TXID_INVALID")?;
    let index: u32 = index.parse()?;
    if id == [0; 32] || format!("{}:{}", hex::encode(id), index) != raw {
        return Err("TN10_OUTPOINT_NONCANONICAL".into());
    }
    let amount = o
        .get("amount")
        .and_then(Value::as_u64)
        .ok_or("TN10_UTXO_AMOUNT_REQUIRED")?;
    let daa = o
        .get("block_daa_score")
        .and_then(Value::as_u64)
        .ok_or("TN10_DAA_REQUIRED")?;
    let covenant_id = match o.get("covenant_id") {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) => {
            let bytes: [u8; 32] = hex::decode(value)?
                .try_into()
                .map_err(|_| "TN10_COVENANT_ID_INVALID")?;
            if hex::encode(bytes) != *value {
                return Err("TN10_COVENANT_ID_INVALID".into());
            }
            Some(Hash::from_bytes(bytes))
        }
        _ => return Err("TN10_COVENANT_ID_INVALID".into()),
    };
    let spk = parse_spk(o.get("script_public_key").ok_or("TN10_SCRIPT_REQUIRED")?)?;
    Ok((
        TransactionOutpoint::new(TransactionId::from_bytes(id), index),
        UtxoEntry::new(amount, spk, daa, false, covenant_id),
    ))
}

fn native_registration_role_keys(request: &Value) -> Result<Value, Error> {
    let keys = request["role_public_keys"]
        .as_object()
        .ok_or("TN10_REGISTRATION_ROLE_PUBLIC_KEYS_REQUIRED")?;
    let roles = [
        ("parent", 0usize),
        ("claimant", 1usize),
        ("target", 1usize),
        ("parent_for_child", 1usize),
        ("fee", 2usize),
    ];
    let role_count = roles.len();
    if keys.len() != roles.len() {
        return Err("TN10_REGISTRATION_ROLE_PUBLIC_KEYS_INVALID".into());
    }
    let fee_script = hex::decode(
        request["inputs"][2]["script_public_key"]
            .as_str()
            .ok_or("TN10_SCRIPT_REQUIRED")?,
    )?;
    let fee_key = if fee_script.len() == 36 && fee_script[2] == 0x20 && fee_script[35] == 0xac {
        Some(hex::encode(&fee_script[3..35]))
    } else {
        None
    };
    let mut result = serde_json::Map::new();
    for (role, input_index) in roles {
        let public_key = keys
            .get(role)
            .and_then(Value::as_str)
            .ok_or("TN10_REGISTRATION_ROLE_PUBLIC_KEYS_INVALID")?;
        let key_bytes = hex::decode(public_key)
            .map_err(|_| Error::from("TN10_REGISTRATION_ROLE_PUBLIC_KEYS_INVALID"))?;
        let key: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| "TN10_REGISTRATION_ROLE_PUBLIC_KEYS_INVALID")?;
        if hex::encode(key) != public_key {
            return Err("TN10_REGISTRATION_ROLE_PUBLIC_KEYS_INVALID".into());
        }
        XOnlyPublicKey::from_slice(&key)
            .map_err(|_| "TN10_REGISTRATION_ROLE_PUBLIC_KEYS_INVALID")?;
        let (source, derivation) = if role == "fee" {
            let derived = fee_key
                .as_deref()
                .ok_or("TN10_REGISTRATION_FEE_INPUT_NOT_P2PK")?;
            if public_key != derived {
                return Err("TN10_REGISTRATION_ROLE_PUBLIC_KEY_MISMATCH".into());
            }
            ("derived_from_p2pk_script", "script_public_key")
        } else {
            ("request_explicit", "not_derivable_from_p2sh_hash")
        };
        result.insert(
            role.to_owned(),
            json!({
                "input_index":input_index,
                "public_key":public_key,
                "source":source,
                "derivation":derivation
            }),
        );
    }
    let same_key = result
        .values()
        .filter_map(|record| record["public_key"].as_str())
        .collect::<std::collections::BTreeSet<_>>()
        .len()
        < role_count;
    Ok(json!({
        "roles":result,
        "key_relationship":if same_key {"SAME_KEY"} else {"DIFFERENT_KEY"}
    }))
}

/// Construct an unsigned native Kaspa transaction from a previously reviewed V6 registration
/// skeleton. This consumes no keys and deliberately refuses populated signature scripts.
pub fn build_native_registration_plan(request: &Value) -> Result<Value, Error> {
    let inputs = request["inputs"]
        .as_array()
        .ok_or("TN10_REGISTRATION_INPUTS_REQUIRED")?;
    let outputs = request["outputs"]
        .as_array()
        .ok_or("TN10_REGISTRATION_OUTPUTS_REQUIRED")?;
    if inputs.len() != 3 || outputs.len() != 5 {
        return Err("TN10_REGISTRATION_SHAPE_INVALID".into());
    }
    let economics: Value = serde_json::from_str(crate::registered_keys::registry_economics_data())?;
    let deed_state_bond_minimum = economics["deed_state_bond_sompi"]
        .as_u64()
        .ok_or("REGISTRY_ECONOMICS_INVALID")?;
    let name_deed_output = economics["name_deed_output_sompi"]
        .as_u64()
        .ok_or("REGISTRY_ECONOMICS_INVALID")?;
    let gap_floor = economics["adapter_gap_floor_sompi"]
        .as_u64()
        .ok_or("REGISTRY_ECONOMICS_INVALID")?;
    // The 10 KAS minimum is the parent Deed's bondSompi state field. The newly
    // issued child Deed output follows the pinned reference structure (1 KAS).
    let deed_state_bond = request["deed_state_bond_sompi"]
        .as_u64()
        .ok_or("TN10_REGISTRY_DEED_STATE_BOND_REQUIRED")?;
    // Reject covenant minima before building any Transaction or plan-shaped data.
    if deed_state_bond < deed_state_bond_minimum {
        return Err("TN10_REGISTRY_DEED_STATE_BOND_BELOW_MINIMUM".into());
    }
    if outputs[2]["value"]
        .as_u64()
        .is_none_or(|value| value < name_deed_output)
    {
        return Err("TN10_REGISTRY_NAME_DEED_VALUE_MISMATCH".into());
    }
    if [1usize, 3usize].iter().any(|index| {
        outputs[*index]["value"]
            .as_u64()
            .is_none_or(|value| value < gap_floor)
    }) {
        return Err("TN10_REGISTRY_GAP_VALUE_BELOW_FLOOR".into());
    }
    let roles = [
        "parent_successor",
        "left_gap",
        "name_deed",
        "right_gap",
        "fee_change",
    ];
    let mut native_inputs = Vec::with_capacity(3);
    let mut input_total = 0u64;
    for (index, item) in inputs.iter().enumerate() {
        if !item["signature_script"].as_str().unwrap_or("").is_empty() {
            return Err(format!("TN10_REGISTRATION_INPUT_{index}_MUST_BE_UNSIGNED").into());
        }
        let (outpoint, entry) = parse_utxo(&json!({
            "outpoint":item["outpoint"], "amount":item["amount"],
            "block_daa_score":item["block_daa_score"], "script_public_key":item["script_public_key"],
            "covenant_id":item["covenant_id"]
        }))?;
        input_total = input_total
            .checked_add(entry.amount)
            .ok_or("TN10_REGISTRATION_VALUE_OVERFLOW")?;
        let compute_budget = item["compute_budget"]
            .as_u64()
            .filter(|budget| *budget > 0 && *budget <= u16::MAX as u64)
            .ok_or("TN10_REGISTRATION_COMPUTE_BUDGET_INVALID")?;
        native_inputs.push(TransactionInput::new_with_compute_budget(
            outpoint,
            Vec::new(),
            0,
            compute_budget as u16,
        ));
    }
    if inputs[0]["covenant_id"].as_str().is_none()
        || inputs[1]["covenant_id"].as_str().is_none()
        || !inputs[2]["covenant_id"].is_null()
    {
        return Err("TN10_REGISTRATION_COVENANT_INPUT_CONTEXT_INVALID".into());
    }
    let role_public_keys = native_registration_role_keys(request)?;
    if request["registration_entrypoint"].as_str() != Some("register_interior") {
        return Err("TN10_REGISTRATION_WITNESS_ENTRYPOINT_INVALID".into());
    }
    let witness_contexts = native_registration_witness_contexts(request, inputs)?;
    let role_input_map = json!({
        "parent":0,
        "claimant":1,
        "target":1,
        "parent_for_child":1,
        "fee":2
    });
    let witness_templates = json!([
        {
            "input_index":0,
            "script_class":"p2sh",
            "entrypoint":"authorize_child",
            "redeem_script_hex":witness_contexts[0]["redeem_script_hex"],
            "arguments":witness_contexts[0]["arguments"],
            "signature_slots":[{"role":"parent","signature_slot_index":6}]
        },
        {
            "input_index":1,
            "script_class":"p2sh",
            "entrypoint":"register_interior",
            "registration_kind":witness_contexts[1]["registration_kind"],
            "redeem_script_hex":witness_contexts[1]["redeem_script_hex"],
            "arguments":witness_contexts[1]["arguments"],
            "signature_slots":[
                {"role":"claimant","signature_slot_index":witness_contexts[1]["signature_slot_indices"][0]},
                {"role":"target","signature_slot_index":witness_contexts[1]["signature_slot_indices"][1]},
                {"role":"parent_for_child","signature_slot_index":witness_contexts[1]["signature_slot_indices"][2]}
            ]
        },
        {"input_index":2,"script_class":"p2pk","entrypoint":"p2pk_fee","signature_slots":[{"role":"fee","signature_slot_index":0}]}
    ]);
    let covenant_utxos = inputs
        .iter()
        .take(2)
        .map(|input| {
            json!({
                "outpoint":input["outpoint"],
                "amount":input["amount"],
                "block_daa_score":input["block_daa_score"],
                "script_public_key":input["script_public_key"],
                "covenant_id":input["covenant_id"]
            })
        })
        .collect::<Vec<_>>();
    let mut native_outputs = Vec::with_capacity(5);
    let mut output_total = 0u64;
    let mut output_json = Vec::with_capacity(5);
    for (index, item) in outputs.iter().enumerate() {
        if item["role"].as_str() != Some(roles[index]) {
            return Err(format!("TN10_REGISTRATION_OUTPUT_{index}_ROLE_MISMATCH").into());
        }
        let value = item["value"]
            .as_u64()
            .ok_or("TN10_REGISTRATION_OUTPUT_VALUE_INVALID")?;
        output_total = output_total
            .checked_add(value)
            .ok_or("TN10_REGISTRATION_VALUE_OVERFLOW")?;
        let covenant = match item["covenant_id"].as_str() {
            Some(raw) => {
                let id: [u8; 32] = hex::decode(raw)?
                    .try_into()
                    .map_err(|_| "TN10_REGISTRATION_OUTPUT_COVENANT_INVALID")?;
                if hex::encode(id) != raw {
                    return Err("TN10_REGISTRATION_OUTPUT_COVENANT_INVALID".into());
                }
                let authorizing_input = item["authorizing_input"]
                    .as_u64()
                    .filter(|index| *index < inputs.len() as u64 && *index <= u16::MAX as u64)
                    .ok_or("TN10_REGISTRATION_OUTPUT_AUTHORIZER_INVALID")?;
                Some(CovenantBinding::new(
                    authorizing_input as u16,
                    Hash::from_bytes(id),
                ))
            }
            None if item["covenant_id"].is_null() && item["authorizing_input"].is_null() => None,
            _ => return Err("TN10_REGISTRATION_OUTPUT_COVENANT_INVALID".into()),
        };
        native_outputs.push(TransactionOutput {
            value,
            script_public_key: parse_spk(&item["script_public_key"])?,
            covenant,
        });
        output_json.push(json!({"role":roles[index],"value":value,"script_public_key":item["script_public_key"],"covenant_id":item["covenant_id"],"authorizing_input":item["authorizing_input"]}));
    }
    let fee = input_total
        .checked_sub(output_total)
        .filter(|value| *value > 0)
        .ok_or("TN10_REGISTRATION_FEE_INVALID")?;
    let tx = Transaction::new(
        1,
        native_inputs,
        native_outputs,
        0,
        Default::default(),
        0,
        Vec::new(),
    );
    let quality = native_registration_transaction_quality(&tx, inputs, &witness_contexts)?;
    let native = RpcTransaction::from(&tx);
    let tx_value = serde_json::to_value(native)?;
    let mut plan = json!({
        "schema":"KTAPEOUT-TN10-NATIVE-CHILD-REGISTRATION-PLAN-V3",
        "network":NETWORK,
        "status":"UNSIGNED_NATIVE_TRANSACTION_PLAN",
        "transaction":tx_value,
        "inputs":inputs,
        "covenant_utxos":covenant_utxos,
        "role_input_map":role_input_map,
        "role_public_keys":role_public_keys,
        "witness_templates":witness_templates,
        "covenant_witness_contexts":witness_contexts,
        "quality":quality,
        "outputs":output_json,
        "fee_sompi":fee,
        "deed_state_bond_sompi":deed_state_bond,
        "adapter_gap_floor_sompi":gap_floor,
        "signature_script_status":"EMPTY_AWAITING_EXTERNAL_SIGNATURES",
        "signing_allowed":false,
        "broadcast":false
    });
    let digest = native_registration_plan_digest(&plan)?;
    plan["plan_sha256"] = json!(digest);
    Ok(plan)
}

/// Construct an unsigned CHANGE_OWNER_TARGET transaction from the frozen witness ABI context.
/// The caller supplies observed UTXOs and outputs; all role keys and witness slots are rebound
/// to the exact covenant arguments before the plan digest is calculated.
pub fn build_native_owner_target_plan(request: &Value) -> Result<Value, Error> {
    use ktapeout_kaspa_verifier::toccata_witness::{
        build_toccata_p2sh_witness, signature_slot_indices_for_arguments, AbiEntryPoint,
    };

    let inputs = request["inputs"]
        .as_array()
        .filter(|items| items.len() == 2)
        .ok_or("TN10_OWNER_TARGET_INPUTS_REQUIRED")?;
    let outputs = request["outputs"]
        .as_array()
        .filter(|items| items.len() == 2)
        .ok_or("TN10_OWNER_TARGET_OUTPUTS_REQUIRED")?;
    let contexts = request["covenant_witness_contexts"]
        .as_array()
        .filter(|items| items.len() == 1)
        .ok_or("TN10_OWNER_TARGET_WITNESS_CONTEXT_REQUIRED")?;
    if inputs
        .iter()
        .any(|item| !item["signature_script"].as_str().unwrap_or("").is_empty())
    {
        return Err("TN10_OWNER_TARGET_INPUT_MUST_BE_UNSIGNED".into());
    }
    if inputs[0]["covenant_id"].as_str().is_none() || !inputs[1]["covenant_id"].is_null() {
        return Err("TN10_OWNER_TARGET_COVENANT_INPUT_CONTEXT_INVALID".into());
    }
    let mut native_inputs = Vec::with_capacity(2);
    let mut input_total = 0u64;
    for input in inputs {
        let (outpoint, entry) = parse_utxo(input)?;
        input_total = input_total
            .checked_add(entry.amount)
            .ok_or("TN10_OWNER_TARGET_VALUE_OVERFLOW")?;
        let budget = input["compute_budget"]
            .as_u64()
            .filter(|value| *value > 0 && *value <= u16::MAX as u64)
            .ok_or("TN10_OWNER_TARGET_COMPUTE_BUDGET_INVALID")?;
        native_inputs.push(TransactionInput::new_with_compute_budget(
            outpoint,
            Vec::new(),
            0,
            budget as u16,
        ));
    }

    let context = &contexts[0];
    if context["input_index"].as_u64() != Some(0)
        || context["entrypoint"].as_str() != Some("change_owner_target")
    {
        return Err("TN10_OWNER_TARGET_WITNESS_CONTEXT_INVALID".into());
    }
    let redeem_hex = context["redeem_script_hex"]
        .as_str()
        .filter(|raw| {
            raw.len() >= 512
                && raw.len() % 2 == 0
                && raw
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
        .ok_or("TN10_OWNER_TARGET_REDEEM_SCRIPT_INVALID")?;
    let redeem_script = hex::decode(redeem_hex)?;
    let deed_spk = inputs[0]["script_public_key"]
        .as_str()
        .filter(|raw| raw.starts_with("0000aa20") && raw.ends_with("87"))
        .ok_or("TN10_OWNER_TARGET_DEED_SPK_INVALID")?;
    if deed_spk[8..72] != hex::encode(crate::name_state_template::blake2b_256(&redeem_script)) {
        return Err("TN10_OWNER_TARGET_REDEEM_HASH_MISMATCH".into());
    }
    let raw_arguments = context["arguments"]
        .as_array()
        .ok_or("TN10_OWNER_TARGET_ARGUMENTS_REQUIRED")?;
    let arguments = raw_arguments
        .iter()
        .map(parse_native_witness_item)
        .collect::<Result<Vec<_>, _>>()?;
    let entrypoint = AbiEntryPoint::ChangeOwnerTarget;
    let signature_slots = signature_slot_indices_for_arguments(entrypoint, &arguments)
        .map_err(|_| "TN10_OWNER_TARGET_WITNESS_CONTEXT_INVALID")?;
    if signature_slots != [11, 14]
        || signature_slots.iter().any(|slot| {
            !matches!(arguments.get(*slot), Some(ktapeout_kaspa_verifier::toccata_witness::WitnessItem::Data(bytes)) if bytes.len() == 65 && bytes.iter().all(|byte| *byte == 0))
        })
    {
        return Err("TN10_OWNER_TARGET_SIGNATURE_SLOTS_INVALID".into());
    }
    let bytes_at = |index: usize| -> Result<&[u8], Error> {
        match arguments.get(index) {
            Some(ktapeout_kaspa_verifier::toccata_witness::WitnessItem::Data(bytes)) => Ok(bytes),
            _ => Err("TN10_OWNER_TARGET_ARGUMENT_SHAPE_INVALID".into()),
        }
    };
    let owner_key = bytes_at(12)?;
    let next_owner_key = bytes_at(13)?;
    let target_key = bytes_at(15)?;
    if owner_key.len() != 32 || target_key.len() != 32 || next_owner_key != owner_key {
        return Err("TN10_OWNER_TARGET_ROLE_KEY_MISMATCH".into());
    }
    let role_keys = request["role_public_keys"]
        .as_object()
        .filter(|roles| roles.len() == 3)
        .ok_or("TN10_OWNER_TARGET_ROLE_PUBLIC_KEYS_REQUIRED")?;
    for (role, expected) in [("deed_owner", owner_key), ("target_authority", target_key)] {
        let supplied = role_keys[role]
            .as_str()
            .ok_or("TN10_OWNER_TARGET_ROLE_PUBLIC_KEYS_INVALID")?;
        if hex::decode(supplied)? != expected {
            return Err("TN10_OWNER_TARGET_ROLE_PUBLIC_KEY_MISMATCH".into());
        }
        XOnlyPublicKey::from_slice(expected)
            .map_err(|_| "TN10_OWNER_TARGET_ROLE_PUBLIC_KEYS_INVALID")?;
    }
    let fee_script = hex::decode(
        inputs[1]["script_public_key"]
            .as_str()
            .ok_or("TN10_SCRIPT_REQUIRED")?,
    )?;
    if fee_script.len() != 36 || fee_script[2] != 0x20 || fee_script[35] != 0xac {
        return Err("TN10_OWNER_TARGET_FEE_INPUT_NOT_P2PK".into());
    }
    let fee_key = &fee_script[3..35];
    if hex::decode(
        role_keys["fee"]
            .as_str()
            .ok_or("TN10_OWNER_TARGET_ROLE_PUBLIC_KEYS_INVALID")?,
    )? != fee_key
    {
        return Err("TN10_OWNER_TARGET_ROLE_PUBLIC_KEY_MISMATCH".into());
    }
    // The frozen state commits the current owner and target authority by SHA-256.
    let owner_commit = Sha256::digest(owner_key);
    let target_commit = Sha256::digest(target_key);
    if bytes_at(6)? != owner_commit.as_slice() || bytes_at(8)? != target_commit.as_slice() {
        return Err("TN10_OWNER_TARGET_STATE_ROLE_COMMITMENT_MISMATCH".into());
    }
    build_toccata_p2sh_witness(entrypoint, &arguments, &redeem_script)
        .map_err(|_| "TN10_OWNER_TARGET_WITNESS_CONTEXT_INVALID")?;
    let witness_contexts = json!([{
        "input_index":0,
        "entrypoint":"change_owner_target",
        "redeem_script_hex":redeem_hex,
        "arguments":raw_arguments,
        "signature_slot_indices":signature_slots
    }]);

    let output_roles = ["deed_successor", "fee_change"];
    let mut native_outputs = Vec::with_capacity(2);
    let mut output_json = Vec::with_capacity(2);
    let mut output_total = 0u64;
    for (index, output) in outputs.iter().enumerate() {
        if output["role"].as_str() != Some(output_roles[index]) {
            return Err("TN10_OWNER_TARGET_OUTPUT_ROLE_MISMATCH".into());
        }
        let value = output["value"]
            .as_u64()
            .ok_or("TN10_OWNER_TARGET_OUTPUT_VALUE_INVALID")?;
        output_total = output_total
            .checked_add(value)
            .ok_or("TN10_OWNER_TARGET_VALUE_OVERFLOW")?;
        let covenant = if index == 0 {
            let raw = output["covenant_id"]
                .as_str()
                .ok_or("TN10_OWNER_TARGET_OUTPUT_COVENANT_INVALID")?;
            if raw != inputs[0]["covenant_id"].as_str().unwrap_or("")
                || output["authorizing_input"].as_u64() != Some(0)
            {
                return Err("TN10_OWNER_TARGET_OUTPUT_COVENANT_INVALID".into());
            }
            let id: [u8; 32] = hex::decode(raw)?
                .try_into()
                .map_err(|_| "TN10_OWNER_TARGET_OUTPUT_COVENANT_INVALID")?;
            Some(CovenantBinding::new(0, Hash::from_bytes(id)))
        } else {
            if !output["covenant_id"].is_null() || !output["authorizing_input"].is_null() {
                return Err("TN10_OWNER_TARGET_OUTPUT_COVENANT_INVALID".into());
            }
            None
        };
        native_outputs.push(TransactionOutput {
            value,
            script_public_key: parse_spk(&output["script_public_key"])?,
            covenant,
        });
        output_json.push(output.clone());
    }
    let fee = input_total
        .checked_sub(output_total)
        .filter(|value| *value > 0)
        .ok_or("TN10_OWNER_TARGET_FEE_INVALID")?;
    if request["fee_sompi"].as_u64() != Some(fee) {
        return Err("TN10_OWNER_TARGET_FEE_MISMATCH".into());
    }
    let tx = Transaction::new(
        1,
        native_inputs,
        native_outputs,
        0,
        Default::default(),
        0,
        Vec::new(),
    );
    let quality = native_registration_transaction_quality(&tx, inputs, &witness_contexts)?;
    let tx_value = serde_json::to_value(RpcTransaction::from(&tx))?;
    let covenant_utxos = json!([inputs[0]]);
    let role_public_keys = json!({
        "roles":{
            "deed_owner":{"input_index":0,"public_key":role_keys["deed_owner"],"source":"witness_argument","derivation":"change_owner_target.owner"},
            "target_authority":{"input_index":0,"public_key":role_keys["target_authority"],"source":"witness_argument","derivation":"change_owner_target.target_authority"},
            "fee":{"input_index":1,"public_key":role_keys["fee"],"source":"derived_from_p2pk_script","derivation":"script_public_key"}
        },
        "key_relationship":if role_keys["deed_owner"] == role_keys["target_authority"] || role_keys["deed_owner"] == role_keys["fee"] || role_keys["target_authority"] == role_keys["fee"] {"SAME_KEY"} else {"DIFFERENT_KEY"}
    });
    let role_input_map = json!({"deed_owner":0,"target_authority":0,"fee":1});
    let witness_templates = json!([
        {"input_index":0,"script_class":"p2sh","entrypoint":"change_owner_target","redeem_script_hex":redeem_hex,"arguments":raw_arguments,"signature_slots":[{"role":"deed_owner","signature_slot_index":11},{"role":"target_authority","signature_slot_index":14}]},
        {"input_index":1,"script_class":"p2pk","entrypoint":"p2pk_fee","signature_slots":[{"role":"fee","signature_slot_index":0}]}
    ]);
    let mut plan = json!({
        "schema":"KTAPEOUT-TN10-NATIVE-OWNER-TARGET-PLAN-V1",
        "operation":"CHANGE_OWNER_TARGET",
        "network":NETWORK,
        "status":"UNSIGNED_NATIVE_TRANSACTION_PLAN",
        "transaction":tx_value,
        "inputs":inputs,
        "covenant_utxos":covenant_utxos,
        "role_input_map":role_input_map,
        "role_public_keys":role_public_keys,
        "witness_templates":witness_templates,
        "covenant_witness_contexts":witness_contexts,
        "outputs":output_json,
        "quality":quality,
        "fee_sompi":fee,
        "next_owner_xonly":hex::encode(owner_key),
        "signature_script_status":"EMPTY_AWAITING_EXTERNAL_SIGNATURES",
        "signing_allowed":false,
        "broadcast":false
    });
    let digest = native_registration_plan_digest(&plan)?;
    plan["plan_sha256"] = json!(digest);
    Ok(plan)
}

/// Calculate the complete registered transaction mass with the pinned node's
/// consensus calculator. Signature placeholders use the declared final 65-byte
/// Schnorr+sighash shape; covenant witnesses are serialized through the single
/// Toccata P2SH assembler. No caller-provided mass value is trusted.
fn native_registration_transaction_quality(
    unsigned_tx: &Transaction,
    inputs: &[Value],
    witness_contexts: &Value,
) -> Result<Value, Error> {
    use ktapeout_kaspa_verifier::toccata_witness::{
        assemble_toccata_p2sh_witness, signature_slot_indices_for_arguments, AbiEntryPoint,
        WitnessItem,
    };
    let contexts = witness_contexts
        .as_array()
        .filter(|items| !items.is_empty())
        .ok_or("TN10_REGISTRATION_WITNESS_CONTEXT_REQUIRED")?;
    if inputs.len() != unsigned_tx.inputs.len() {
        return Err("TN10_REGISTRATION_INPUT_CONTEXT_INVALID".into());
    }
    let mut transaction = unsigned_tx.clone();
    for context in contexts {
        let index = context["input_index"]
            .as_u64()
            .ok_or("TN10_REGISTRATION_INPUT_CONTEXT_INVALID")? as usize;
        if index >= transaction.inputs.len() {
            return Err("TN10_REGISTRATION_INPUT_CONTEXT_INVALID".into());
        }
        let entrypoint = AbiEntryPoint::parse(
            context["entrypoint"]
                .as_str()
                .ok_or("TN10_REGISTRATION_WITNESS_ENTRYPOINT_INVALID")?,
        )
        .map_err(|_| "TN10_REGISTRATION_WITNESS_ENTRYPOINT_INVALID")?;
        let arguments = context["arguments"]
            .as_array()
            .ok_or("TN10_REGISTRATION_WITNESS_ARGUMENTS_REQUIRED")?
            .iter()
            .map(parse_native_witness_item)
            .collect::<Result<Vec<WitnessItem>, _>>()?;
        let slots = signature_slot_indices_for_arguments(entrypoint, &arguments)
            .map_err(|_| "TN10_REGISTRATION_WITNESS_CONTEXT_INVALID")?;
        let signatures = slots
            .iter()
            .map(|slot| {
                let mut signature = vec![0; 64];
                signature.push(1);
                (*slot, signature)
            })
            .collect::<Vec<_>>();
        let redeem_script = hex::decode(
            context["redeem_script_hex"]
                .as_str()
                .ok_or("TN10_REGISTRATION_WITNESS_REDEEM_SCRIPT_INVALID")?,
        )?;
        transaction.inputs[index].signature_script =
            assemble_toccata_p2sh_witness(entrypoint, &arguments, &redeem_script, &signatures)
                .map_err(|_| "TN10_REGISTRATION_WITNESS_CONTEXT_INVALID")?;
    }
    // Non-covenant fee inputs use one 65-byte Schnorr signature item.
    for (index, input) in inputs.iter().enumerate() {
        if input["covenant_id"].is_null() {
            transaction.inputs[index].signature_script = std::iter::once(0x41)
                .chain(std::iter::repeat_n(0, 64))
                .chain(std::iter::once(1))
                .collect();
        }
    }
    if transaction.outputs.iter().any(|output| output.value == 0) {
        return Err("TN10_REGISTRATION_MASS_UNAVAILABLE".into());
    }
    let entries = inputs
        .iter()
        .map(|input| parse_utxo(input).map(|(_, entry)| entry))
        .collect::<Result<Vec<UtxoEntry>, _>>()?;
    let params = kaspa_consensus_core::config::params::Params::from(
        kaspa_consensus_core::network::NetworkId::with_suffix(
            kaspa_consensus_core::network::NetworkType::Testnet,
            10,
        ),
    );
    let calculator = kaspa_consensus_core::mass::MassCalculator::new_with_consensus_params(&params);
    let non_contextual = calculator.calc_non_contextual_masses(&transaction);
    let populated = MutableTransaction::with_entries(transaction.clone(), entries);
    let contextual = calculator
        .calc_contextual_masses(&populated.as_verifiable())
        .ok_or("TN10_REGISTRATION_STORAGE_MASS_UNAVAILABLE")?;
    let mass = kaspa_consensus_core::mass::Mass::new(non_contextual, contextual);
    let normalized_total = mass.normalized_max(&params.block_mass_limits.cofactors());
    if non_contextual.compute_mass > params.block_mass_limits.compute
        || non_contextual.transient_mass > params.block_mass_limits.transient
        || contextual.storage_mass > params.block_mass_limits.storage
        || normalized_total > params.block_mass_limits.reference()
    {
        return Err("TN10_REGISTRATION_TRANSACTION_MASS_EXCEEDED".into());
    }
    let compute_budgets = transaction
        .inputs
        .iter()
        .enumerate()
        .map(|(index, input)| {
            Ok(json!({
                "input_index":index,
                "compute_budget":input.compute_commit.compute_budget()
                    .ok_or("TN10_REGISTRATION_COMPUTE_BUDGET_INVALID")?
            }))
        })
        .collect::<Result<Vec<_>, &'static str>>()?;
    Ok(json!({
        "mass_source":"pinned_v2.1.0_consensus_calculator",
        "signature_scripts_are_placeholders":true,
        "signature_script_lengths":transaction.inputs.iter().map(|input| input.signature_script.len()).collect::<Vec<_>>(),
        "compute_budgets":compute_budgets,
        "compute_mass":non_contextual.compute_mass,
        "transient_mass":non_contextual.transient_mass,
        "storage_mass":contextual.storage_mass,
        "normalized_total_mass":normalized_total,
        "limits":{
            "compute":params.block_mass_limits.compute,
            "transient":params.block_mass_limits.transient,
            "storage":params.block_mass_limits.storage,
            "normalized":params.block_mass_limits.reference()
        }
    }))
}

/// Price the exact unsigned transaction. The fee-change output is adjusted from
/// the pinned consensus calculator's mass until its actual input/output delta
/// equals normalized mass times the dual-node quote. Output amount encoding can
/// affect mass, so this is a bounded fixed-point calculation rather than a
/// hand-derived byte-size estimate.
fn build_native_registration_plan_at_fee_quote(
    request: &Value,
    fee_rate_sompi_per_mass: u64,
) -> Result<Value, Error> {
    if fee_rate_sompi_per_mass == 0 {
        return Err("REGISTRATION_FEE_INPUT_INVALID".into());
    }
    let mut priced_request = request.clone();
    let outputs = priced_request["outputs"]
        .as_array()
        .filter(|outputs| outputs.len() == 5)
        .ok_or("TN10_REGISTRATION_OUTPUTS_REQUIRED")?;
    let inputs = priced_request["inputs"]
        .as_array()
        .filter(|inputs| inputs.len() == 3)
        .ok_or("TN10_REGISTRATION_INPUTS_REQUIRED")?;
    let input_total = inputs.iter().try_fold(0u64, |total, input| {
        total
            .checked_add(
                input["amount"]
                    .as_u64()
                    .ok_or("TN10_REGISTRATION_INPUT_AMOUNT_INVALID")?,
            )
            .ok_or_else(|| Error::from("TN10_REGISTRATION_VALUE_OVERFLOW"))
    })?;
    let fixed_output_total = outputs[..4].iter().try_fold(0u64, |total, output| {
        total
            .checked_add(
                output["value"]
                    .as_u64()
                    .ok_or("TN10_REGISTRATION_OUTPUT_VALUE_INVALID")?,
            )
            .ok_or_else(|| Error::from("TN10_REGISTRATION_VALUE_OVERFLOW"))
    })?;
    let mut plan = build_native_registration_plan(&priced_request)?;
    for _ in 0..8 {
        let mass = plan["quality"]["normalized_total_mass"]
            .as_u64()
            .filter(|mass| *mass > 0)
            .ok_or("TN10_REGISTRATION_MASS_UNAVAILABLE")?;
        let quoted_fee = mass
            .checked_mul(fee_rate_sompi_per_mass)
            .ok_or("REGISTRATION_FEE_OVERFLOW")?;
        let fee_change = input_total
            .checked_sub(fixed_output_total)
            .and_then(|available| available.checked_sub(quoted_fee))
            .filter(|change| *change > 0)
            .ok_or("TN10_REGISTRATION_FEE_EXCEEDS_AVAILABLE_CHANGE")?;
        if plan["fee_sompi"].as_u64() == Some(quoted_fee) {
            return Ok(plan);
        }
        priced_request["outputs"][4]["value"] = json!(fee_change);
        plan = build_native_registration_plan(&priced_request)?;
    }
    Err("TN10_REGISTRATION_FEE_MASS_DID_NOT_CONVERGE".into())
}

fn native_registration_plan_digest(plan: &Value) -> Result<String, Error> {
    let committed = json!({
        "schema":plan["schema"],
        "network":plan["network"],
        "transaction":plan["transaction"],
        "inputs":plan["inputs"],
        "covenant_utxos":plan["covenant_utxos"],
        "role_input_map":plan["role_input_map"],
        "role_public_keys":plan["role_public_keys"],
        "witness_templates":plan["witness_templates"],
        "covenant_witness_contexts":plan["covenant_witness_contexts"],
        "outputs":plan["outputs"],
        "quality":plan["quality"],
        "fee_sompi":plan["fee_sompi"],
        "deed_state_bond_sompi":plan["deed_state_bond_sompi"],
        "adapter_gap_floor_sompi":plan["adapter_gap_floor_sompi"]
        ,"operation":plan["operation"],
        "next_owner_xonly":plan["next_owner_xonly"]
    });
    Ok(hex::encode(sha2::Sha256::digest(serde_json::to_vec(
        &committed,
    )?)))
}

pub fn verify_native_registration_plan_digest(plan: &Value) -> bool {
    native_registration_plan_digest(plan)
        .ok()
        .is_some_and(|expected| plan["plan_sha256"].as_str() == Some(expected.as_str()))
}

/// Create a deterministic, unsigned review/signing handoff for a native child-registration plan.
/// This does not sign, authorize, or submit the transaction; a downstream wallet must review the
/// displayed transaction and return signatures bound to this exact plan digest.
pub fn build_native_registration_signing_packet(plan: &Value) -> Result<Value, Error> {
    if !is_native_signable_plan(plan) || !verify_native_registration_plan_digest(plan) {
        return Err("TN10_REGISTRATION_PLAN_DIGEST_INVALID".into());
    }
    let inputs = plan["transaction"]["inputs"]
        .as_array()
        .filter(|items| {
            items.len()
                == plan["transaction"]["inputs"]
                    .as_array()
                    .map(Vec::len)
                    .unwrap_or_default()
        })
        .ok_or("TN10_REGISTRATION_SHAPE_INVALID")?;
    if inputs.iter().any(|input| {
        input["signatureScript"]
            .as_str()
            .is_none_or(|script| !script.is_empty())
    }) {
        return Err("TN10_REGISTRATION_INPUT_MUST_BE_UNSIGNED".into());
    }
    if plan["transaction"]["outputs"].as_array().map(Vec::len) != Some(inputs.len() + 2)
        && plan["schema"] == "KTAPEOUT-TN10-NATIVE-CHILD-REGISTRATION-PLAN-V3"
    {
        return Err("TN10_REGISTRATION_SHAPE_INVALID".into());
    }
    let mut packet = json!({
        "schema":"KTAPEOUT-TN10-REGISTRATION-SIGNING-PACKET-V3",
        "network":plan["network"],
        "plan_sha256":plan["plan_sha256"],
        "transaction":plan["transaction"],
        "inputs":plan["inputs"],
        "covenant_utxos":plan["covenant_utxos"],
        "role_input_map":plan["role_input_map"],
        "role_public_keys":plan["role_public_keys"],
        "witness_templates":plan["witness_templates"],
        "covenant_witness_contexts":plan["covenant_witness_contexts"],
        "outputs":plan["outputs"],
        "quality":plan["quality"],
        "fee_sompi":plan["fee_sompi"],
        "deed_state_bond_sompi":plan["deed_state_bond_sompi"],
        "adapter_gap_floor_sompi":plan["adapter_gap_floor_sompi"],
        "local_signing_allowed":false,
        "broadcast":false
    });
    let digest = hex::encode(sha2::Sha256::digest(serde_json::to_vec(&packet)?));
    packet["packet_sha256"] = json!(digest);
    Ok(packet)
}

/// Recompute a signing packet from the immutable native plan and require exact JSON equality.
/// This is a structural handoff check; it makes no claim that external signatures are valid.
pub fn verify_native_registration_signing_packet(
    plan: &Value,
    packet: &Value,
) -> Result<(), Error> {
    let expected = build_native_registration_signing_packet(plan)?;
    if packet != &expected {
        return Err("REGISTRY_SIGNING_PACKET_MISMATCH".into());
    }
    Ok(())
}

/// Build one signing request per declared role from the immutable native plan.
/// Roles sharing an input intentionally receive the same consensus sighash but
/// retain separate public-key identities for partial signing and witness assembly.
pub fn native_registration_signature_requests(plan: &Value) -> Result<Value, Error> {
    if !is_native_signable_plan(plan)
        || plan["network"] != NETWORK
        || !verify_native_registration_plan_digest(plan)
    {
        return Err("TN10_REGISTRATION_PLAN_DIGEST_INVALID".into());
    }
    let packet = build_native_registration_signing_packet(plan)?;
    verify_native_registration_signing_packet(plan, &packet)?;
    let transaction = Transaction::try_from(serde_json::from_value::<RpcTransaction>(
        plan["transaction"].clone(),
    )?)?;
    let input_count = transaction.inputs.len();
    let inputs = plan["inputs"]
        .as_array()
        .filter(|items| items.len() == input_count)
        .ok_or("TN10_REGISTRATION_INPUT_CONTEXT_INVALID")?;
    let entries = inputs
        .iter()
        .map(|input| parse_utxo(input).map(|(_, entry)| entry))
        .collect::<Result<Vec<_>, _>>()?;
    let authorities = plan["role_input_map"]
        .as_object()
        .ok_or("TN10_REGISTRATION_ROLE_MAP_INVALID")?;
    let roles = plan["role_public_keys"]["roles"]
        .as_object()
        .ok_or("TN10_REGISTRATION_ROLE_PUBLIC_KEYS_INVALID")?;
    if authorities.len() != roles.len() {
        return Err("TN10_REGISTRATION_ROLE_MAP_INVALID".into());
    }
    let mutable = MutableTransaction::with_entries(transaction, entries);
    let mut requests = Vec::with_capacity(roles.len());
    for (role, key_record) in roles {
        let input_index = authorities[role]
            .as_u64()
            .and_then(|index| usize::try_from(index).ok())
            .ok_or("TN10_REGISTRATION_ROLE_MAP_INVALID")?;
        if input_index >= input_count
            || key_record["input_index"].as_u64() != Some(input_index as u64)
        {
            return Err("TN10_REGISTRATION_ROLE_MAP_INVALID".into());
        }
        let public_key = key_record["public_key"]
            .as_str()
            .ok_or("TN10_REGISTRATION_ROLE_PUBLIC_KEYS_INVALID")?;
        let digest = calc_schnorr_signature_hash(
            &mutable.as_verifiable(),
            input_index,
            SIG_HASH_ALL,
            &SigHashReusedValuesUnsync::new(),
        );
        requests.push(json!({
            "role":role,
            "input_index":input_index,
            "signer_public_key":public_key,
            "sighash_type":1,
            "sighash":hex::encode(digest.as_bytes())
        }));
    }
    requests.sort_by(|left, right| {
        left["input_index"]
            .as_u64()
            .cmp(&right["input_index"].as_u64())
            .then_with(|| left["role"].as_str().cmp(&right["role"].as_str()))
    });
    Ok(json!({
        "schema":"KTAPEOUT-TN10-REGISTRATION-SIGNATURE-REQUESTS-V1",
        "network":NETWORK,
        "plan_sha256":plan["plan_sha256"],
        "requests":requests,
        "witness_assembly":"PENDING_COVENANT_SIGNATURES",
        "broadcast":false
    }))
}

/// Replace the native plan's signature placeholders only after the caller has
/// verified each aggregate role signature against `native_registration_signature_requests`.
/// Covenant inputs use the single frozen Toccata P2SH serializer; the fee input
/// uses its P2PK script form and is never used as a covenant witness.
pub(crate) fn assemble_native_registration_transaction(
    plan: &Value,
    signatures: &[Value],
) -> Result<Value, Error> {
    use ktapeout_kaspa_verifier::toccata_witness::{assemble_toccata_p2sh_witness, AbiEntryPoint};

    if !is_native_signable_plan(plan) || !verify_native_registration_plan_digest(plan) {
        return Err("TN10_REGISTRATION_PLAN_DIGEST_INVALID".into());
    }
    let requests = native_registration_signature_requests(plan)?["requests"]
        .as_array()
        .cloned()
        .ok_or("TN10_NATIVE_SIGNATURE_REQUESTS_INVALID")?;
    if signatures.len() != requests.len() {
        return Err("TN10_NATIVE_SIGNATURE_SET_INCOMPLETE".into());
    }
    let mut by_role = BTreeMap::<(usize, String), (String, Vec<u8>)>::new();
    let secp = Secp256k1::verification_only();
    for request in &requests {
        let input_index = request["input_index"]
            .as_u64()
            .ok_or("TN10_NATIVE_SIGNATURE_REQUESTS_INVALID")? as usize;
        let role = request["role"]
            .as_str()
            .ok_or("TN10_NATIVE_SIGNATURE_REQUESTS_INVALID")?
            .to_owned();
        let expected_key = request["signer_public_key"]
            .as_str()
            .ok_or("TN10_NATIVE_SIGNATURE_REQUESTS_INVALID")?;
        let expected_hash = request["sighash"]
            .as_str()
            .ok_or("TN10_NATIVE_SIGNATURE_REQUESTS_INVALID")?;
        let matching = signatures
            .iter()
            .filter(|item| {
                item["input_index"].as_u64() == Some(input_index as u64)
                    && item["role"].as_str() == Some(role.as_str())
            })
            .collect::<Vec<_>>();
        if matching.len() != 1 {
            return Err("TN10_NATIVE_SIGNATURE_SET_INCOMPLETE_OR_DUPLICATE".into());
        }
        let item = matching[0];
        if item["signer_public_key"].as_str() != Some(expected_key)
            || item["sighash_type"].as_u64() != Some(1)
            || item["sighash"].as_str() != Some(expected_hash)
        {
            return Err("TN10_NATIVE_SIGNATURE_ROLE_BINDING_MISMATCH".into());
        }
        let key_bytes: [u8; 32] = hex::decode(expected_key)?
            .try_into()
            .map_err(|_| "TN10_NATIVE_SIGNATURE_PUBLIC_KEY_INVALID")?;
        let public_key = XOnlyPublicKey::from_slice(&key_bytes)
            .map_err(|_| "TN10_NATIVE_SIGNATURE_PUBLIC_KEY_INVALID")?;
        let hash_bytes: [u8; 32] = hex::decode(expected_hash)?
            .try_into()
            .map_err(|_| "TN10_NATIVE_SIGNATURE_SIGHASH_INVALID")?;
        let signature_bytes = hex::decode(
            item["signature"]
                .as_str()
                .ok_or("TN10_NATIVE_SIGNATURE_INVALID")?,
        )?;
        if signature_bytes.len() != 64 {
            return Err("TN10_NATIVE_SIGNATURE_INVALID".into());
        }
        let signature =
            Signature::from_slice(&signature_bytes).map_err(|_| "TN10_NATIVE_SIGNATURE_INVALID")?;
        secp.verify_schnorr(&signature, &Message::from_digest(hash_bytes), &public_key)
            .map_err(|_| "TN10_NATIVE_SIGNATURE_INVALID")?;
        if by_role
            .insert(
                (input_index, role),
                (expected_key.to_owned(), signature_bytes),
            )
            .is_some()
        {
            return Err("TN10_NATIVE_SIGNATURE_DUPLICATE".into());
        }
    }
    if by_role.len() != signatures.len() {
        return Err("TN10_NATIVE_SIGNATURE_ROLE_NOT_IN_PLAN".into());
    }

    let mut transaction = plan["transaction"].clone();
    let templates = plan["witness_templates"]
        .as_array()
        .ok_or("TN10_REGISTRATION_WITNESS_TEMPLATE_INVALID")?;
    for template in templates {
        let input_index = template["input_index"]
            .as_u64()
            .ok_or("TN10_REGISTRATION_WITNESS_TEMPLATE_INVALID")?
            as usize;
        let entrypoint = template["entrypoint"]
            .as_str()
            .ok_or("TN10_REGISTRATION_WITNESS_TEMPLATE_INVALID")?;
        if template["script_class"] == "p2sh" {
            let entry = AbiEntryPoint::parse(entrypoint)
                .map_err(|_| "TN10_REGISTRATION_WITNESS_ENTRYPOINT_INVALID")?;
            let args = template["arguments"]
                .as_array()
                .ok_or("TN10_REGISTRATION_WITNESS_TEMPLATE_INVALID")?
                .iter()
                .map(parse_native_witness_item)
                .collect::<Result<Vec<_>, _>>()?;
            let slots = template["signature_slots"]
                .as_array()
                .ok_or("TN10_REGISTRATION_WITNESS_TEMPLATE_INVALID")?;
            let slot_signatures = slots
                .iter()
                .map(|slot| {
                    let role = slot["role"]
                        .as_str()
                        .ok_or("TN10_REGISTRATION_WITNESS_TEMPLATE_INVALID")?;
                    let position = slot["signature_slot_index"]
                        .as_u64()
                        .ok_or("TN10_REGISTRATION_WITNESS_TEMPLATE_INVALID")?
                        as usize;
                    let (_, mut signature) = by_role
                        .get(&(input_index, role.to_owned()))
                        .cloned()
                        .ok_or("TN10_NATIVE_SIGNATURE_SET_INCOMPLETE")?;
                    signature.push(1);
                    Ok((position, signature))
                })
                .collect::<Result<Vec<_>, Error>>()?;
            let redeem_script = hex::decode(
                template["redeem_script_hex"]
                    .as_str()
                    .ok_or("TN10_REGISTRATION_WITNESS_TEMPLATE_INVALID")?,
            )?;
            let script =
                assemble_toccata_p2sh_witness(entry, &args, &redeem_script, &slot_signatures)
                    .map_err(|_| "TN10_REGISTRATION_WITNESS_ASSEMBLY_FAILED")?;
            transaction["inputs"][input_index]["signatureScript"] = json!(hex::encode(script));
        } else if template["script_class"] == "p2pk" && entrypoint == "p2pk_fee" {
            let (_, mut signature) = by_role
                .get(&(input_index, "fee".to_owned()))
                .cloned()
                .ok_or("TN10_NATIVE_SIGNATURE_SET_INCOMPLETE")?;
            signature.push(1);
            let mut script = Vec::with_capacity(66);
            script.push(signature.len() as u8);
            script.extend_from_slice(&signature);
            transaction["inputs"][input_index]["signatureScript"] = json!(hex::encode(script));
        } else {
            return Err("TN10_REGISTRATION_WITNESS_TEMPLATE_INVALID".into());
        }
    }
    Ok(transaction)
}

/// Build a deterministic display record for explicit human review. It is not an approval token.
pub fn build_native_registration_approval_review(
    plan: &Value,
    packet: &Value,
) -> Result<Value, Error> {
    verify_native_registration_signing_packet(plan, packet)?;
    let rpc_transaction: RpcTransaction = serde_json::from_value(packet["transaction"].clone())?;
    let transaction = Transaction::try_from(rpc_transaction)?;
    let inputs = plan["inputs"]
        .as_array()
        .ok_or("TN10_REGISTRATION_INPUTS_REQUIRED")?;
    let reviewed_inputs = inputs
        .iter()
        .enumerate()
        .map(|(index, input)| {
            json!({
                "input_index":index,
                "outpoint":input["outpoint"],
                "amount_sompi":input["amount"],
                "script_public_key":input["script_public_key"],
                "signature_required":true
            })
        })
        .collect::<Vec<_>>();
    let mut review = json!({
        "schema":"KTAPEOUT-TN10-REGISTRATION-APPROVAL-REVIEW-V2",
        "status":"REVIEW_ONLY_NO_APPROVAL",
        "network":NETWORK,
        "plan_sha256":plan["plan_sha256"],
        "packet_sha256":packet["packet_sha256"],
        "txid":transaction.id().to_string(),
        "inputs":reviewed_inputs,
        "covenant_utxos":plan["covenant_utxos"],
        "role_input_map":plan["role_input_map"],
        "role_public_keys":plan["role_public_keys"],
        "witness_templates":plan["witness_templates"],
        "outputs":plan["outputs"],
        "fee_sompi":plan["fee_sompi"],
        "deed_state_bond_sompi":plan["deed_state_bond_sompi"],
        "adapter_gap_floor_sompi":plan["adapter_gap_floor_sompi"],
        "signature_scripts_empty":true,
        "signing_or_broadcast_authorized":false
    });
    let digest = hex::encode(sha2::Sha256::digest(serde_json::to_vec(&review)?));
    review["review_sha256"] = json!(digest);
    Ok(review)
}

/// Recompute the review from its immutable plan and packet; serialized user fields are not trusted.
pub fn verify_native_registration_approval_review(
    plan: &Value,
    packet: &Value,
    review: &Value,
) -> Result<(), Error> {
    let expected = build_native_registration_approval_review(plan, packet)?;
    if review != &expected {
        return Err("REGISTRY_APPROVAL_REVIEW_MISMATCH".into());
    }
    Ok(())
}

/// Validate the separately created user authorization required for native registration signing.
/// `--yes` and review-only records do not create or replace this authorization.
pub fn verify_native_registration_authorization(
    plan: &Value,
    authorization: &Value,
    now_unix: u64,
) -> Result<(), Error> {
    if !is_native_signable_plan(plan)
        || plan["network"] != NETWORK
        || !verify_native_registration_plan_digest(plan)
    {
        return Err("TN10_REGISTRATION_PLAN_DIGEST_INVALID".into());
    }
    if authorization["schema"] != "KTAPEOUT-TN10-REGISTRATION-AUTHORIZATION-V1"
        || authorization["network"] != NETWORK
        || authorization["plan_sha256"] != plan["plan_sha256"]
        || authorization["role_public_keys"] != plan["role_public_keys"]
        || authorization["fee_source"] != "live_dual_node_quote"
        || authorization["fee_quote_sha256"]
            .as_str()
            .is_none_or(|hash| {
                hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
        || authorization["confirmation_method"] != "TERMINAL_TYPED_PLAN_DIGEST"
        || authorization["created_with_terminal_confirmation"] != true
        || authorization["allow_broadcast"].as_bool().is_none()
        || authorization["allow_readback"].as_bool().is_none()
    {
        return Err("TN10_REGISTRATION_AUTHORIZATION_BINDING_MISMATCH".into());
    }
    let created_at = authorization["created_at_unix"]
        .as_u64()
        .ok_or("TN10_REGISTRATION_AUTHORIZATION_TIME_INVALID")?;
    let expires_at = authorization["expires_at_unix"]
        .as_u64()
        .filter(|expires| *expires > created_at && *expires > now_unix)
        .ok_or("TN10_REGISTRATION_AUTHORIZATION_EXPIRED")?;
    if created_at > now_unix || expires_at <= created_at {
        return Err("TN10_REGISTRATION_AUTHORIZATION_TIME_INVALID".into());
    }
    if expires_at - created_at > 24 * 60 * 60 {
        return Err("TN10_REGISTRATION_AUTHORIZATION_VALIDITY_TOO_LONG".into());
    }
    let input_total = plan["inputs"]
        .as_array()
        .filter(|inputs| {
            inputs.len()
                == plan["transaction"]["inputs"]
                    .as_array()
                    .map(Vec::len)
                    .unwrap_or_default()
        })
        .ok_or("TN10_REGISTRATION_SHAPE_INVALID")?
        .iter()
        .try_fold(0u64, |total, input| {
            let amount = input["amount"]
                .as_u64()
                .ok_or("TN10_REGISTRATION_INPUT_AMOUNT_INVALID")?;
            total
                .checked_add(amount)
                .ok_or_else(|| Error::from("TN10_REGISTRATION_VALUE_OVERFLOW"))
        })?;
    let amount_limit = authorization["cumulative_amount_limit_sompi"]
        .as_u64()
        .ok_or("TN10_REGISTRATION_AUTHORIZATION_AMOUNT_LIMIT_INVALID")?;
    let fee_limit = authorization["fee_limit_sompi"]
        .as_u64()
        .ok_or("TN10_REGISTRATION_AUTHORIZATION_FEE_LIMIT_INVALID")?;
    let fee = plan["fee_sompi"]
        .as_u64()
        .ok_or("TN10_REGISTRATION_FEE_INVALID")?;
    if amount_limit < input_total || fee_limit < fee {
        return Err("TN10_REGISTRATION_AUTHORIZATION_BUDGET_EXCEEDED".into());
    }
    Ok(())
}

/// Prepare a user-reviewed native authorization from a complete register-plan result.
/// The fee quote must be a fresh, internally consistent dual-node quote; estimates cannot grant
/// signing authority. Confirmation is added only by `create_native_registration_authorization`.
pub fn prepare_native_registration_authorization(
    document: &Value,
    max_total_sompi: u64,
    max_fee_sompi: u64,
    expires_at_unix: u64,
    now_unix: u64,
    allow_broadcast: bool,
    allow_readback: bool,
) -> Result<Value, Error> {
    const MAX_AUTHORIZATION_AGE_SECONDS: u64 = 10 * 60;
    const MAX_AUTHORIZATION_LIFETIME_SECONDS: u64 = 24 * 60 * 60;

    let plan = document.get("native_transaction_plan").unwrap_or(document);
    if !is_native_signable_plan(plan)
        || plan["network"] != NETWORK
        || !verify_native_registration_plan_digest(plan)
    {
        return Err("TN10_REGISTRATION_PLAN_DIGEST_INVALID".into());
    }
    let quote = document
        .get("fee_quote")
        .ok_or("TN10_LIVE_FEE_QUOTE_REQUIRED")?;
    if quote["source"] != "live_dual_node_quote" {
        return Err("TN10_LIVE_FEE_QUOTE_REQUIRED".into());
    }
    let endpoints = quote["endpoints"]
        .as_array()
        .filter(|items| items.len() == 2)
        .ok_or("TN10_FEE_QUOTE_INVALID")?;
    let rates = quote["node_rates"]
        .as_array()
        .filter(|items| items.len() == 2)
        .ok_or("TN10_FEE_QUOTE_INVALID")?;
    let endpoint_values = endpoints
        .iter()
        .map(|endpoint| endpoint.as_str().ok_or("TN10_FEE_QUOTE_INVALID"))
        .collect::<Result<Vec<_>, _>>()?;
    if endpoint_values[0] == endpoint_values[1]
        || rates.iter().enumerate().any(|(index, rate)| {
            rate["endpoint"].as_str() != Some(endpoint_values[index])
                || rate["feerate"]
                    .as_f64()
                    .is_none_or(|value| !value.is_finite() || value <= 0.0)
        })
    {
        return Err("TN10_FEE_QUOTE_INVALID".into());
    }
    let first_rate = rates[0]["feerate"]
        .as_f64()
        .ok_or("TN10_FEE_QUOTE_INVALID")?;
    let second_rate = rates[1]["feerate"]
        .as_f64()
        .ok_or("TN10_FEE_QUOTE_INVALID")?;
    let low = first_rate.min(second_rate);
    let high = first_rate.max(second_rate);
    if high > low * 2.0 || quote["fee_rate_sompi_per_gram"].as_u64() != Some(high.ceil() as u64) {
        return Err("TN10_FEE_QUOTE_INVALID".into());
    }
    let observed_at = quote["observed_at"]
        .as_str()
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .ok_or("TN10_FEE_QUOTE_INVALID")?
        .timestamp();
    if observed_at < 0
        || observed_at as u64 > now_unix
        || now_unix - observed_at as u64 > MAX_AUTHORIZATION_AGE_SECONDS
    {
        return Err("TN10_FEE_QUOTE_STALE".into());
    }
    quote["fee_rate_sompi_per_gram"]
        .as_u64()
        .ok_or("TN10_FEE_QUOTE_INVALID")?;

    let input_total = plan["inputs"]
        .as_array()
        .filter(|inputs| {
            inputs.len()
                == plan["transaction"]["inputs"]
                    .as_array()
                    .map(Vec::len)
                    .unwrap_or_default()
        })
        .ok_or("TN10_REGISTRATION_SHAPE_INVALID")?
        .iter()
        .try_fold(0u64, |total, input| {
            total
                .checked_add(
                    input["amount"]
                        .as_u64()
                        .ok_or("TN10_REGISTRATION_INPUT_AMOUNT_INVALID")?,
                )
                .ok_or_else(|| Error::from("TN10_REGISTRATION_VALUE_OVERFLOW"))
        })?;
    let fee = plan["fee_sompi"]
        .as_u64()
        .ok_or("TN10_REGISTRATION_FEE_INVALID")?;
    if max_total_sompi < input_total || max_fee_sompi < fee {
        return Err("TN10_REGISTRATION_AUTHORIZATION_BUDGET_EXCEEDED".into());
    }
    if expires_at_unix <= now_unix {
        return Err("TN10_REGISTRATION_AUTHORIZATION_EXPIRED".into());
    }
    if expires_at_unix - now_unix > MAX_AUTHORIZATION_LIFETIME_SECONDS {
        return Err("TN10_REGISTRATION_AUTHORIZATION_VALIDITY_TOO_LONG".into());
    }
    let quote_hash = hex::encode(Sha256::digest(serde_json::to_vec(quote)?));
    Ok(json!({
        "schema":"KTAPEOUT-TN10-REGISTRATION-AUTHORIZATION-V1",
        "network":NETWORK,
        "plan_sha256":plan["plan_sha256"],
        "role_public_keys":plan["role_public_keys"],
        "cumulative_amount_limit_sompi":max_total_sompi,
        "fee_limit_sompi":max_fee_sompi,
        "fee_source":"live_dual_node_quote",
        "fee_quote_sha256":quote_hash,
        "created_at_unix":now_unix,
        "expires_at_unix":expires_at_unix,
        "allow_broadcast":allow_broadcast,
        "allow_readback":allow_readback,
        "confirmation_method":"TERMINAL_TYPED_PLAN_DIGEST",
        "created_with_terminal_confirmation":false
    }))
}

// Keep the explicit per-call limits and consent flags visible at this security boundary.
#[allow(clippy::too_many_arguments)]
pub fn create_native_registration_authorization(
    document: &Value,
    max_total_sompi: u64,
    max_fee_sompi: u64,
    expires_at_unix: u64,
    now_unix: u64,
    allow_broadcast: bool,
    allow_readback: bool,
    confirmation: &str,
) -> Result<Value, Error> {
    let mut authorization = prepare_native_registration_authorization(
        document,
        max_total_sompi,
        max_fee_sompi,
        expires_at_unix,
        now_unix,
        allow_broadcast,
        allow_readback,
    )?;
    let expected = format!(
        "AUTHORIZE {}",
        authorization["plan_sha256"].as_str().unwrap_or("")
    );
    if confirmation != expected {
        return Err("TN10_REGISTRATION_AUTHORIZATION_CONFIRMATION_REQUIRED".into());
    }
    authorization["created_with_terminal_confirmation"] = json!(true);
    Ok(authorization)
}

/// Reconcile a plan-bound transaction through two read-only transports.
/// This helper never calls `submit`; absence from both nodes remains unresolved and does not
/// authorize a retry. Signature validity is outside this readback operation and is never claimed.
pub fn reconcile_native_registration_readback_with_transports(
    plan: &Value,
    expected_transaction: &Value,
    txid: &str,
    first: &mut dyn Transport,
    second: &mut dyn Transport,
) -> Result<Value, Error> {
    if !is_native_signable_plan(plan) || !verify_native_registration_plan_digest(plan) {
        return Err("TN10_REGISTRATION_PLAN_OR_TRANSACTION_MISMATCH".into());
    }
    let expected_rpc: RpcTransaction = serde_json::from_value(expected_transaction.clone())?;
    let mut expected_native = Transaction::try_from(expected_rpc)?;
    for input in &mut expected_native.inputs {
        input.signature_script.clear();
    }
    let plan_rpc: RpcTransaction = serde_json::from_value(plan["transaction"].clone())?;
    let plan_native = Transaction::try_from(plan_rpc)?;
    if expected_native != plan_native {
        return Err("TN10_REGISTRATION_PLAN_OR_TRANSACTION_MISMATCH".into());
    }
    let expected_rpc: RpcTransaction = serde_json::from_value(expected_transaction.clone())?;
    let expected_native = Transaction::try_from(expected_rpc)?;
    if expected_native.id().to_string() != txid {
        return Err("TN10_REGISTRATION_READBACK_TXID_MISMATCH".into());
    }
    let a = first
        .read_transaction(txid)
        .map_err(|_| "TN10_READBACK_RPC_FAILED")?;
    let b = second
        .read_transaction(txid)
        .map_err(|_| "TN10_READBACK_RPC_FAILED")?;
    match (a, b) {
        (None, None) => Ok(json!({
            "schema":"KTAPEOUT-TN10-REGISTRATION-READBACK-V1",
            "network":NETWORK,
            "status":"NOT_FOUND_BOTH_RETRY_REQUIRES_REVIEW",
            "operation":"READBACK_ONLY",
            "txid":txid,
            "plan_sha256":plan["plan_sha256"],
            "node_observations":["NOT_FOUND","NOT_FOUND"],
            "signature_validity":"NOT_VERIFIED_BY_READBACK",
            "finality":"FINALITY_UNCHECKED",
            "broadcast_action":"NOT_PERFORMED_BY_READBACK"
        })),
        (Some(left), Some(right)) => {
            let left_rpc: RpcTransaction = serde_json::from_value(left)?;
            let right_rpc: RpcTransaction = serde_json::from_value(right)?;
            let left_native = Transaction::try_from(left_rpc)?;
            let right_native = Transaction::try_from(right_rpc)?;
            if left_native != right_native {
                return Err("TN10_DUAL_NODE_DISAGREEMENT".into());
            }
            if left_native != expected_native || left_native.id().to_string() != txid {
                return Err("TN10_REGISTRATION_READBACK_TRANSACTION_MISMATCH".into());
            }
            Ok(json!({
                "schema":"KTAPEOUT-TN10-REGISTRATION-READBACK-V1",
                "network":NETWORK,
                "status":"FOUND_BOTH_MATCH",
                "operation":"READBACK_ONLY",
                "txid":txid,
                "plan_sha256":plan["plan_sha256"],
                "node_observations":["MATCH","MATCH"],
                "signature_validity":"NOT_VERIFIED_BY_READBACK",
                "finality":"FINALITY_UNCHECKED",
                "broadcast_action":"NOT_PERFORMED_BY_READBACK"
            }))
        }
        _ => Err("TN10_DUAL_NODE_DISAGREEMENT".into()),
    }
}

/// Read back one already assembled namespace transition from two independent TN10 transports.
/// This operation never signs, submits, or authorizes a retry.
pub fn reconcile_namespace_transition_with_transports(
    signed: &Value,
    first: &mut dyn Transport,
    second: &mut dyn Transport,
) -> Result<Value, Error> {
    if signed["network"] != NETWORK
        || signed["native_vm_verified"] != true
        || signed["broadcast"] != false
        || signed["native_plan_hash"].as_str().is_none_or(|hash| {
            hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
    {
        return Err("TN10_NAMESPACE_TRANSITION_SIGNED_DOCUMENT_INVALID".into());
    }
    let expected_rpc: RpcTransaction = serde_json::from_value(signed["transaction"].clone())?;
    let expected = Transaction::try_from(expected_rpc)?;
    let txid = expected.id().to_string();
    if signed["txid"].as_str() != Some(txid.as_str()) {
        return Err("TN10_NAMESPACE_TRANSITION_TXID_MISMATCH".into());
    }
    let left = first
        .read_transaction(&txid)
        .map_err(|_| "TN10_NAMESPACE_TRANSITION_READBACK_FAILED")?;
    let right = second
        .read_transaction(&txid)
        .map_err(|_| "TN10_NAMESPACE_TRANSITION_READBACK_FAILED")?;
    let status = match (left, right) {
        (None, None) => "NOT_FOUND_BOTH",
        (Some(left), Some(right)) => {
            let left: RpcTransaction = serde_json::from_value(left)?;
            let right: RpcTransaction = serde_json::from_value(right)?;
            let left = Transaction::try_from(left)?;
            let right = Transaction::try_from(right)?;
            if left != right || left != expected || left.id().to_string() != txid {
                return Err("TN10_NAMESPACE_TRANSITION_DUAL_NODE_MISMATCH".into());
            }
            "FOUND_BOTH_MATCH"
        }
        _ => return Err("TN10_NAMESPACE_TRANSITION_DUAL_NODE_DISAGREEMENT".into()),
    };
    Ok(json!({
        "schema":"KTAPEOUT-TN10-NAMESPACE-TRANSITION-READBACK-V1",
        "network":NETWORK,
        "status":status,
        "txid":txid,
        "native_plan_hash":signed["native_plan_hash"],
        "node_observations":if status == "NOT_FOUND_BOTH" { ["NOT_FOUND","NOT_FOUND"] } else { ["MATCH","MATCH"] },
        "retry_authorized":false,
        "broadcast_action":"NOT_PERFORMED_BY_READBACK"
    }))
}

/// Combine an existing submission receipt with a dual-node transaction lookup.
/// This is read-only: it never submits, re-signs, or authorizes a retry, and it does not
/// claim that the plan's predecessor UTXOs remain unspent.
pub fn reconcile_native_registration_submission_with_transports(
    plan: &Value,
    submission: &Value,
    signed_transaction: &Value,
    txid: &str,
    first: &mut dyn Transport,
    second: &mut dyn Transport,
) -> Result<Value, Error> {
    if submission["schema"] != "KTAPEOUT-TN10-REGISTRATION-SUBMIT-V1"
        || submission["network"] != NETWORK
        || !matches!(
            submission["status"].as_str(),
            Some("SUBMISSION_UNKNOWN" | "SUBMITTED")
        )
        || submission["txid"].as_str() != Some(txid)
        || submission["plan_sha256"] != plan["plan_sha256"]
    {
        return Err("TN10_REGISTRATION_SUBMISSION_RECEIPT_MISMATCH".into());
    }
    let readback = reconcile_native_registration_readback_with_transports(
        plan,
        signed_transaction,
        txid,
        first,
        second,
    )?;
    let predecessor_outpoints = plan["inputs"]
        .as_array()
        .ok_or("TN10_REGISTRATION_INPUTS_REQUIRED")?
        .iter()
        .map(|input| {
            input
                .get("outpoint")
                .cloned()
                .ok_or("TN10_REGISTRATION_PREDECESSOR_REQUIRED")
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(json!({
        "schema":"KTAPEOUT-TN10-REGISTRATION-SUBMISSION-RECONCILIATION-V1",
        "operation":"READBACK_ONLY",
        "network":NETWORK,
        "status":"RECONCILED_READBACK",
        "txid":txid,
        "plan_sha256":plan["plan_sha256"],
        "submission_state":submission["status"],
        "submission_broadcast":submission["broadcast"],
        "readback_status":readback["status"],
        "node_observations":readback["node_observations"],
        "predecessor_outpoints":predecessor_outpoints,
        "predecessor_status":"NOT_RECHECKED_BY_READBACK",
        "inclusion_evidence":if readback["status"] == "FOUND_BOTH_MATCH" {"TRANSACTION_LOOKUP_ONLY"} else {"NOT_FOUND_BOTH"},
        "signature_validity":"NOT_VERIFIED_BY_READBACK",
        "finality":"FINALITY_UNCHECKED",
        "retry_authorized":false,
        "broadcast_action":"NOT_PERFORMED_BY_READBACK"
    }))
}

/// Save a verified unsigned signing packet to two distinct local escrow directories.
/// Existing files are never replaced; every copy is read back and recomputed.
pub fn escrow_native_registration_signing_packet(
    plan: &Value,
    destinations: &[PathBuf],
) -> Result<Vec<PathBuf>, Error> {
    let packet = build_native_registration_signing_packet(plan)?;
    let plan_digest = plan["plan_sha256"]
        .as_str()
        .ok_or("TN10_REGISTRATION_PLAN_DIGEST_INVALID")?;
    let filename = format!("registry-signing-packet-{}.json", &plan_digest[..16]);
    let mut roots = Vec::new();
    for destination in destinations {
        fs::create_dir_all(destination)?;
        let metadata = fs::symlink_metadata(destination)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("REGISTRY_ESCROW_DESTINATION_INVALID".into());
        }
        let root = fs::canonicalize(destination)?;
        if !roots.contains(&root) {
            roots.push(root);
        }
    }
    if roots.len() < 2 {
        return Err("REGISTRY_ESCROW_TWO_DISTINCT_DESTINATIONS_REQUIRED".into());
    }

    let mut files = Vec::with_capacity(roots.len());
    for root in roots {
        let path = root.join(&filename);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                return Err("REGISTRY_ESCROW_FILE_INVALID".into());
            }
            Ok(_) => {
                verify_native_registration_signing_packet(plan, &read_json(&path)?)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                write_json_new_atomic(&path, &packet)?;
            }
            Err(error) => return Err(error.into()),
        }
        verify_native_registration_signing_packet(plan, &read_json(&path)?)?;
        files.push(path);
    }
    Ok(files)
}

/// Require two independently located escrow copies and validate each against the plan.
pub fn require_native_registration_signing_packet_escrow(
    plan: &Value,
    files: &[PathBuf],
) -> Result<(), Error> {
    let mut roots = Vec::new();
    if files.len() < 2 {
        return Err("REGISTRY_ESCROW_TWO_DISTINCT_DESTINATIONS_REQUIRED".into());
    }
    for path in files {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err("REGISTRY_ESCROW_FILE_INVALID".into());
        }
        let root = fs::canonicalize(path.parent().ok_or("REGISTRY_ESCROW_FILE_INVALID")?)?;
        if !roots.contains(&root) {
            roots.push(root);
        }
        verify_native_registration_signing_packet(plan, &read_json(path)?)?;
    }
    if roots.len() < 2 {
        return Err("REGISTRY_ESCROW_TWO_DISTINCT_DESTINATIONS_REQUIRED".into());
    }
    Ok(())
}

fn build_transaction(request: &Value) -> Result<(Transaction, UtxoEntry, String, u64), Error> {
    let o = request.as_object().ok_or("TN10_REQUEST_OBJECT_REQUIRED")?;
    if o.get("schema") != Some(&Value::String(SCHEMA.into()))
        || o.get("network") != Some(&Value::String(NETWORK.into()))
    {
        return Err("TN10_NETWORK_OR_SCHEMA_INVALID".into());
    }
    let artifact = serde_json::to_vec(o.get("artifact").ok_or("TN10_ARTIFACT_REQUIRED")?)?;
    if artifact.len() > MAX_ARTIFACT_BYTES {
        return Err("TN10_ARTIFACT_TOO_LARGE".into());
    }
    let artifact_root = o["artifact"]
        .get("artifact_sha256")
        .and_then(Value::as_str)
        .ok_or("TN10_ARTIFACT_ROOT_REQUIRED")?;
    if artifact_root.len() != 64 || hex::decode(artifact_root).is_err() {
        return Err("TN10_ARTIFACT_ROOT_INVALID".into());
    }
    if artifact_root.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err("TN10_ARTIFACT_ROOT_NONCANONICAL".into());
    }
    if let Some(content_commitment_sha256) = o["artifact"].get("content_commitment_sha256") {
        let content_commitment_sha256 = content_commitment_sha256
            .as_str()
            .ok_or("TN10_CONTENT_COMMITMENT_SHA256_INVALID")?;
        if content_commitment_sha256.len() != 64 || hex::decode(content_commitment_sha256).is_err()
        {
            return Err("TN10_CONTENT_COMMITMENT_SHA256_INVALID".into());
        }
        if content_commitment_sha256
            .bytes()
            .any(|byte| byte.is_ascii_uppercase())
        {
            return Err("TN10_CONTENT_COMMITMENT_SHA256_NONCANONICAL".into());
        }
    }
    let fee = o
        .get("fee_sompi")
        .and_then(Value::as_u64)
        .ok_or("TN10_FEE_REQUIRED")?;
    if !(1..=30_000_000).contains(&fee) {
        return Err("TN10_FEE_BUDGET_EXCEEDED".into());
    }
    let (outpoint, entry) = parse_utxo(o.get("funding_utxo").ok_or("TN10_FUNDING_REQUIRED")?)?;
    let script = entry.script_public_key.script();
    if script.len() != 34 || script[0] != 0x20 || script[33] != 0xac {
        return Err("TN10_SCHNORR_P2PK_REQUIRED".into());
    }
    XOnlyPublicKey::from_slice(&script[1..33])?;
    let change = entry
        .amount
        .checked_sub(fee)
        .filter(|v| *v >= MIN_CHANGE_SOMPI)
        .ok_or("TN10_INSUFFICIENT_FUNDING")?;
    if let Some(max_fee) = o.get("max_fee_sompi").and_then(Value::as_u64) {
        if fee > max_fee {
            return Err("TN10_FEE_BUDGET_EXCEEDED".into());
        }
    }
    if let Some(max_value) = o.get("max_value_sompi").and_then(Value::as_u64) {
        if entry.amount > max_value {
            return Err("TN10_VALUE_BUDGET_EXCEEDED".into());
        }
    }
    let payload =
        serde_json::to_vec(&json!({"schema":SCHEMA,"network":NETWORK,"artifact":o["artifact"]}))?;
    let tx = Transaction::new(
        1,
        vec![TransactionInput::new_with_compute_budget(
            outpoint,
            vec![],
            0,
            10,
        )],
        vec![TransactionOutput {
            value: change,
            script_public_key: entry.script_public_key.clone(),
            covenant: None,
        }],
        0,
        Default::default(),
        0,
        payload,
    );
    let params = kaspa_consensus_core::config::params::Params::from(
        kaspa_consensus_core::network::NetworkId::with_suffix(
            kaspa_consensus_core::network::NetworkType::Testnet,
            10,
        ),
    );
    let calculator = kaspa_consensus_core::mass::MassCalculator::new_with_consensus_params(&params);
    // Match the pinned node's default relay policy, using the final 65-byte
    // Schnorr signature plus its one-byte script push, not the unsigned size.
    let mut signed_size = tx.clone();
    signed_size.inputs[0].signature_script = vec![0; 66];
    let masses = calculator.calc_non_contextual_masses(&signed_size);
    // The pinned upstream relay checker uses normalized non-contextual compute
    // and transient mass; storage mass is enforced separately by consensus.
    // See rusty-kaspa 01b532e8, mining/src/mempool/check_transaction_standard.rs.
    let fee_mass = masses.normalized_max(&params.block_mass_limits.cofactors());
    // kaspa-mining DEFAULT_MINIMUM_RELAY_TRANSACTION_FEE, sompi/kg.
    const DEFAULT_RELAY_RATE: u64 = 100_000;
    let minimum_fee = fee_mass.saturating_mul(DEFAULT_RELAY_RATE) / 1000;
    let minimum_fee = if minimum_fee == 0 {
        DEFAULT_RELAY_RATE
    } else {
        minimum_fee
    }
    .min(kaspa_consensus_core::constants::MAX_SOMPI);
    let max_fee = o
        .get("max_fee_sompi")
        .and_then(Value::as_u64)
        .unwrap_or(30_000_000);
    if minimum_fee > max_fee {
        return Err(format!(
            "TN10_MINIMUM_RELAY_FEE_EXCEEDS_BUDGET:required={minimum_fee},limit={max_fee}"
        )
        .into());
    }
    if fee < minimum_fee {
        return Err(
            format!("TN10_FEE_BELOW_MINIMUM_RELAY:required={minimum_fee},provided={fee}").into(),
        );
    }
    if masses.compute_mass > params.block_mass_limits.compute
        || masses.transient_mass > params.block_mass_limits.transient
    {
        return Err("TN10_NON_CONTEXTUAL_MASS_EXCEEDED".into());
    }
    commit_storage_mass(&tx, &entry, &calculator, params.block_mass_limits.storage)?;
    Ok((tx, entry, artifact_root.to_owned(), fee))
}

fn commit_storage_mass(
    tx: &Transaction,
    entry: &UtxoEntry,
    calculator: &kaspa_consensus_core::mass::MassCalculator,
    storage_limit: u64,
) -> Result<(), Error> {
    // The pinned library's storage formula divides by output value; zero is
    // rejected before calling it rather than allowing a panic.
    if tx.outputs.iter().any(|output| output.value == 0) {
        return Err("TN10_STORAGE_MASS_INCOMPUTABLE".into());
    }
    let populated = MutableTransaction::with_entries(tx.clone(), vec![entry.clone()]);
    let mass = calculator
        .calc_contextual_masses(&populated.as_verifiable())
        .ok_or("TN10_STORAGE_MASS_INCOMPUTABLE")?
        .storage_mass;
    if mass > storage_limit {
        return Err("TN10_STORAGE_MASS_EXCEEDED".into());
    }
    tx.set_storage_mass(mass);
    Ok(())
}

pub fn plan(input: &Path, output: &Path) -> Result<(), Error> {
    let request = read_json(input)?;
    let (tx, entry, artifact_root, fee) = build_transaction(&request)?;
    let signing_pubkey = hex::encode(&entry.script_public_key.script()[1..33]);
    let mutable = MutableTransaction::with_entries(tx.clone(), vec![entry]);
    let digest = calc_schnorr_signature_hash(
        &mutable.as_verifiable(),
        0,
        SIG_HASH_ALL,
        &SigHashReusedValuesUnsync::new(),
    );
    let tx_json = serde_json::to_value(RpcTransaction::from(&tx))?;
    let txid = tx.id().to_string();
    write_json(
        output,
        &json!({
            "schema":"KTAPEOUT-TN10-PLAN-V1", "network":NETWORK,
            "candidate_schema":SCHEMA, "artifact_root":artifact_root, "fee_sompi":fee,
            "transaction":tx_json, "txid":txid, "signing_pubkey":signing_pubkey,
            "input_sighash_all":hex::encode(digest.as_bytes()),
            "status":"UNSIGNED_LOCAL_PLAN", "signing_allowed":false, "broadcast":false,
            "network_admission_verified":false, "durable_payload_readback_verified":false,
            "request":request
        }),
    )
}

/// Rebuild all signable bytes from the funding view; summary fields are never authoritative.
pub fn signing_summary(plan: &Value) -> Result<Value, Error> {
    if plan["schema"] != "KTAPEOUT-TN10-PLAN-V1" || plan["network"] != NETWORK {
        return Err("TN10_PLAN_INVALID".into());
    }
    let request = &plan["request"];
    let (expected, entry, root, fee) = build_transaction(request)?;
    if let Some(address) = request.get("address").and_then(Value::as_str) {
        if !address.starts_with("kaspatest:") {
            return Err("TN10_ADDRESS_REQUIRED".into());
        }
    }
    let mut actual = Transaction::try_from(serde_json::from_value::<RpcTransaction>(
        plan["transaction"].clone(),
    )?)?;
    for input in &mut actual.inputs {
        input.signature_script.clear();
    }
    if serde_json::to_value(RpcTransaction::from(&actual))?
        != serde_json::to_value(RpcTransaction::from(&expected))?
        || plan["artifact_root"] != root
        || plan["fee_sompi"] != fee
    {
        return Err("TN10_PLAN_TRANSACTION_MISMATCH".into());
    }
    let pubkey = hex::encode(&entry.script_public_key.script()[1..33]);
    let mutable = MutableTransaction::with_entries(expected.clone(), vec![entry.clone()]);
    let digest = calc_schnorr_signature_hash(
        &mutable.as_verifiable(),
        0,
        SIG_HASH_ALL,
        &SigHashReusedValuesUnsync::new(),
    );
    if plan["signing_pubkey"] != pubkey
        || plan["input_sighash_all"] != hex::encode(digest.as_bytes())
    {
        return Err("TN10_PLAN_SIGHASH_MISMATCH".into());
    }
    let payload_sha256 = hex::encode(sha2::Sha256::digest(&expected.payload));
    let payload: Value = serde_json::from_slice(&expected.payload)?;
    let limit = |name: &str, fallback: u64| -> Result<u64, Error> {
        match request.get(name) {
            Some(value) => value.as_u64().ok_or_else(|| "TN10_BUDGET_INVALID".into()),
            None => Ok(fallback),
        }
    };
    let max_fee = limit("max_fee_sompi", 30_000_000)?;
    let max_value = limit("max_value_sompi", entry.amount)?;
    if fee > max_fee {
        return Err("TN10_FEE_BUDGET_EXCEEDED".into());
    }
    if entry.amount > max_value {
        return Err("TN10_VALUE_BUDGET_EXCEEDED".into());
    }
    let budget = json!({
        "max_total_fee_sompi":limit("max_total_fee_sompi", max_fee)?,
        "max_total_value_sompi":limit("max_total_value_sompi", max_value)?,
        "spent_fee_sompi":limit("spent_fee_sompi", 0)?,
        "spent_value_sompi":limit("spent_value_sompi", 0)?
    });
    for (spent, amount, maximum) in [
        (
            budget["spent_fee_sompi"].as_u64().unwrap(),
            fee,
            budget["max_total_fee_sompi"].as_u64().unwrap(),
        ),
        (
            budget["spent_value_sompi"].as_u64().unwrap(),
            entry.amount,
            budget["max_total_value_sompi"].as_u64().unwrap(),
        ),
    ] {
        if spent.checked_add(amount).is_none_or(|v| v > maximum) {
            return Err("TN10_CUMULATIVE_BUDGET_EXCEEDED".into());
        }
    }
    Ok(
        json!({"operation":"TN10_RESOURCE_ROOT_PAYLOAD", "network":NETWORK,
        "target":root,"payload_sha256":payload_sha256,"payload_bytes":expected.payload.len(),
        "artifact":payload["artifact"],"input_sompi":entry.amount,"outputs":serde_json::to_value(RpcTransaction::from(&expected))?["outputs"],
        "fee_sompi":fee,"total_value_sompi":entry.amount,"budget":budget,
        "signing_pubkey":pubkey,"input_sighash_all":hex::encode(digest.as_bytes())}),
    )
}

/// Verify a detached signature and install its canonical P2PK signature script.
pub fn attach_signature(plan: &Value, bytes: &str) -> Result<Value, Error> {
    signing_summary(plan)?;
    let raw = hex::decode(bytes).map_err(|_| "TN10_SIGNATURE_NONCANONICAL")?;
    if raw.len() != 65 || raw[64] != 1 || hex::encode(&raw) != bytes {
        return Err("TN10_SIGNATURE_NONCANONICAL".into());
    }
    Secp256k1::verification_only()
        .verify_schnorr(
            &Signature::from_slice(&raw[..64])?,
            &Message::from_digest_slice(&hex::decode(
                plan["input_sighash_all"].as_str().unwrap(),
            )?)?,
            &XOnlyPublicKey::from_slice(&hex::decode(plan["signing_pubkey"].as_str().unwrap())?)?,
        )
        .map_err(|_| "TN10_SIGNATURE_INVALID")?;
    let mut tx = Transaction::try_from(serde_json::from_value::<RpcTransaction>(
        plan["transaction"].clone(),
    )?)?;
    tx.inputs[0].signature_script = [vec![65], raw].concat();
    let mut signed = plan.clone();
    signed["transaction"] = serde_json::to_value(RpcTransaction::from(&tx))?;
    signed["signature"] = json!(bytes);
    signed["status"] = json!("SIGNED_OFFLINE");
    Ok(signed)
}

pub fn sign(plan_path: &Path, signature_path: &Path, output: &Path) -> Result<(), Error> {
    let plan = read_json(plan_path)?;
    if plan["schema"] != "KTAPEOUT-TN10-PLAN-V1" || plan["network"] != NETWORK {
        return Err("TN10_PLAN_INVALID".into());
    }
    let sig = read_json(signature_path)?;
    // Legacy API cannot authorize from a JSON assertion. CLI uses the confirmation module.
    let _ = (sig, output);
    Err("TN10_CONFIRMATION_REQUIRED".into())
}

pub fn import_signature(plan: &Value, sig: &Value) -> Result<Value, Error> {
    let digest = plan["input_sighash_all"]
        .as_str()
        .ok_or("TN10_SIGHASH_MISSING")?;
    if sig["network"] != NETWORK || sig["sighash"] != digest {
        return Err("TN10_SIGNATURE_BINDING_MISMATCH".into());
    }
    let bytes = sig["signature"].as_str().ok_or("TN10_SIGNATURE_MISSING")?;
    attach_signature(plan, bytes)
}

pub fn submit_with_transport<T: Transport>(
    input: &Path,
    output: &Path,
    transport: &mut T,
) -> Result<(), Error> {
    submit_with_transport_retry(input, output, false, transport)
}

struct SubmitLock(PathBuf);

impl SubmitLock {
    fn acquire(output: &Path) -> Result<Self, Error> {
        let mut lock_path = output.as_os_str().to_os_string();
        lock_path.push(".lock");
        let lock_path = PathBuf::from(lock_path);
        let _file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
            .map_err(|error| -> Error {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        "TN10_SUBMISSION_LOCK_EXISTS: inspect for an active submit before removing a stale lock",
                    ))
                } else {
                    Box::new(error)
                }
            })?;
        Ok(Self(lock_path))
    }
}

impl Drop for SubmitLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

pub fn submit_with_transport_retry<T: Transport>(
    input: &Path,
    output: &Path,
    retry_same_txid: bool,
    transport: &mut T,
) -> Result<(), Error> {
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "TN10_CLOCK_INVALID")?
        .as_secs();
    submit_with_transport_retry_at(input, output, retry_same_txid, now_unix, transport)
}

/// Deterministic-time variant used by offline tests; production submit always supplies the system clock.
pub fn submit_with_transport_retry_at<T: Transport>(
    input: &Path,
    output: &Path,
    retry_same_txid: bool,
    now_unix: u64,
    transport: &mut T,
) -> Result<(), Error> {
    let _submit_lock = SubmitLock::acquire(output)?;
    let signed = read_json(input)?;
    let (checked, summary_digest) = if signed["schema"]
        == "KTAPEOUT-TN10-NATIVE-SIGNATURES-AGGREGATE-V1"
    {
        let verified =
            crate::tn10_developer_signing::verify_native_registration_aggregate(&signed, now_unix)?;
        if signed["authorization"]["allow_broadcast"] != true {
            return Err("TN10_REGISTRATION_BROADCAST_NOT_AUTHORIZED".into());
        }
        let plan_hash = verified["native_plan_hash"]
            .as_str()
            .ok_or("TN10_NATIVE_AGGREGATE_INVALID")?
            .to_owned();
        (json!({"transaction":verified["transaction"]}), plan_hash)
    } else {
        if signed["schema"] != "KTAPEOUT-TN10-PLAN-V1" || signed["network"] != NETWORK {
            return Err("TN10_SIGNED_PLAN_INVALID".into());
        }
        if signed.get("signature").and_then(Value::as_str).is_none() {
            return Err("TN10_SIGNATURE_REQUIRED".into());
        }
        let checked = attach_signature(&signed, signed["signature"].as_str().unwrap())?;
        if checked["transaction"] != signed["transaction"] {
            return Err("TN10_SIGNED_TRANSACTION_MISMATCH".into());
        }
        let digest = plan_digest(&signed)?;
        (checked, digest)
    };
    let tx: RpcTransaction = serde_json::from_value(checked["transaction"].clone())?;
    let txid = Transaction::try_from(tx.clone())?.id().to_string();
    let retrying = fs::symlink_metadata(output).is_ok();
    if retrying {
        if fs::symlink_metadata(output)?.file_type().is_symlink() {
            return Err("TN10_SUBMISSION_RESULT_EXISTS".into());
        }
        let previous = read_json(output)?;
        if previous["status"] != "SUBMISSION_UNKNOWN" {
            return Err("TN10_SUBMISSION_RESULT_EXISTS".into());
        }
        if !retry_same_txid {
            return Err("TN10_RETRY_SAME_TXID_REQUIRED".into());
        }
        if previous["txid"] != txid || previous["plan_sha256"] != summary_digest {
            return Err("TN10_SUBMISSION_TXID_MISMATCH_RECONCILE".into());
        }
        let mut attempt = 1u64;
        loop {
            let history = output.with_file_name(format!(
                "{}.attempt-{attempt}.json",
                output
                    .file_name()
                    .ok_or("TN10_OUTPUT_PATH_INVALID")?
                    .to_string_lossy()
            ));
            if fs::symlink_metadata(&history).is_err() {
                write_json_new_atomic(&history, &previous)?;
                break;
            }
            attempt += 1;
        }
    }
    let receipt_schema = if signed["schema"] == "KTAPEOUT-TN10-NATIVE-SIGNATURES-AGGREGATE-V1" {
        "KTAPEOUT-TN10-REGISTRATION-SUBMIT-V1"
    } else {
        "KTAPEOUT-TN10-SUBMIT-V1"
    };
    let mut record = json!({
        "schema":receipt_schema, "network":NETWORK,
        "status":"SUBMISSION_UNKNOWN", "txid":txid, "plan_sha256":summary_digest,
        "broadcast":"UNKNOWN", "reconcile":"REQUIRED_WITH_TWO_NODES_BEFORE_RETRY"
    });
    if retrying {
        replace_json_atomic(output, &record)?;
    } else {
        write_json_new_atomic(output, &record)?;
    }
    match transport.submit(&tx) {
        Ok(ack) if ack == txid => {
            record["status"] = json!("SUBMITTED");
            record["broadcast"] = json!(true);
            replace_json_atomic(output, &record)
        }
        Ok(_) => {
            record["acknowledgement"] = json!("MISMATCH");
            replace_json_atomic(output, &record)?;
            Err("TN10_SUBMISSION_UNKNOWN".into())
        }
        Err(_) => {
            // A single-node observation cannot resolve an unknown broadcast.
            // Keep the pre-broadcast record unchanged; `locate` must reconcile
            // against two nodes before the operator decides whether to retry.
            Err("TN10_SUBMISSION_UNKNOWN".into())
        }
    }
}

/// Submit an assembled namespace transition and require a fresh two-node readback before retry.
pub fn submit_namespace_transition_with_transports(
    input: &Path,
    output: &Path,
    retry_same_txid: bool,
    now_unix: u64,
    broadcast_confirmation: &str,
    first: &mut dyn Transport,
    second: &mut dyn Transport,
) -> Result<(), Error> {
    let _submit_lock = SubmitLock::acquire(output)?;
    let signed = read_json(input)?;
    verify_namespace_transition_artifact(&signed)?;
    let transition_plan = signed["transition_plan"].clone();
    let authorization_signing = match transition_plan["action"].as_str() {
        Some("namespace_parent_genesis") => {
            ktapeout_050_adapter_workbench::namespace_parent_genesis::transition_command(
                "--transition-plan",
                &transition_plan,
            )
        }
        Some("profile_state_transition")
            if transition_plan["request"]["operation"] == "ISSUE_NAMESPACE" =>
        {
            ktapeout_050_adapter_workbench::namespace_issuance_v1_plan::transition_command(
                "--transition-plan",
                &transition_plan,
            )
        }
        _ => return Err("TN10_NAMESPACE_TRANSITION_SIGNED_DOCUMENT_INVALID".into()),
    }
    .map_err(|_| "TN10_NAMESPACE_TRANSITION_SIGNATURE_REVALIDATION_FAILED")?;
    verify_namespace_transition_authorization(
        &json!({"plan":transition_plan,"signing":authorization_signing}),
        &signed["authorization"],
        now_unix,
    )?;
    let authorization_sha256 = hex::encode(Sha256::digest(serde_json::to_vec(
        &signed["authorization"],
    )?));
    if !matches!(
        signed["schema"].as_str(),
        Some("KTAPEOUT-TN10-NAMESPACE-PARENT-GENESIS-SIGNED-V1")
            | Some("KTAPEOUT-TN10-NAMESPACE-ISSUANCE-SIGNED-V1")
    ) || signed["network"] != NETWORK
        || signed["native_vm_verified"] != true
        || signed["broadcast"] != false
    {
        return Err("TN10_NAMESPACE_TRANSITION_SIGNED_DOCUMENT_INVALID".into());
    }
    let rpc: RpcTransaction = serde_json::from_value(signed["transaction"].clone())?;
    let transaction = Transaction::try_from(rpc.clone())?;
    let txid = transaction.id().to_string();
    if signed["txid"].as_str() != Some(txid.as_str()) {
        return Err("TN10_NAMESPACE_TRANSITION_TXID_MISMATCH".into());
    }
    if broadcast_confirmation != format!("BROADCAST {txid}") {
        return Err("TN10_NAMESPACE_TRANSITION_BROADCAST_CONFIRMATION_REQUIRED".into());
    }
    let plan_hash = signed["native_plan_hash"]
        .as_str()
        .filter(|hash| hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or("TN10_NAMESPACE_TRANSITION_PLAN_HASH_INVALID")?;
    let retrying = fs::symlink_metadata(output).is_ok();
    let mut attempt = 0u64;
    if retrying {
        if fs::symlink_metadata(output)?.file_type().is_symlink() {
            return Err("TN10_SUBMISSION_RESULT_EXISTS".into());
        }
        let previous = read_json(output)?;
        if previous["status"] != "SUBMISSION_UNKNOWN" {
            return Err("TN10_SUBMISSION_RESULT_EXISTS".into());
        }
        if !retry_same_txid {
            return Err("TN10_RETRY_SAME_TXID_REQUIRED".into());
        }
        if previous["txid"] != txid || previous["plan_sha256"] != plan_hash {
            return Err("TN10_SUBMISSION_TXID_MISMATCH_RECONCILE".into());
        }
        if previous["authorization_sha256"] != authorization_sha256 {
            return Err("TN10_NAMESPACE_TRANSITION_AUTHORIZATION_MISMATCH".into());
        }
        let reconciliation =
            reconcile_namespace_transition_with_transports(&signed, first, second)?;
        if reconciliation["status"] != "NOT_FOUND_BOTH" {
            return Err("TN10_NAMESPACE_TRANSITION_FOUND_OR_UNRESOLVED_NO_RETRY".into());
        }
        loop {
            attempt += 1;
            let history = output.with_file_name(format!(
                "{}.attempt-{attempt}.json",
                output
                    .file_name()
                    .ok_or("TN10_OUTPUT_PATH_INVALID")?
                    .to_string_lossy()
            ));
            if fs::symlink_metadata(&history).is_err() {
                write_json_new_atomic(&history, &previous)?;
                break;
            }
        }
    } else if retry_same_txid {
        return Err("TN10_RETRY_WITHOUT_UNKNOWN_SUBMISSION".into());
    }
    let mut record = json!({
        "schema":"KTAPEOUT-TN10-NAMESPACE-TRANSITION-SUBMIT-V1",
        "network":NETWORK,
        "status":"SUBMISSION_UNKNOWN",
        "txid":txid,
        "plan_sha256":plan_hash,
        "authorization_sha256":authorization_sha256,
        "broadcast":"UNKNOWN",
        "attempt":attempt + 1,
        "attempted_at_unix":now_unix,
        "reconcile":"TWO_NODE_READBACK_REQUIRED_BEFORE_RETRY"
    });
    if retrying {
        replace_json_atomic(output, &record)?;
    } else {
        write_json_new_atomic(output, &record)?;
    }
    match first.submit(&rpc) {
        Ok(ack) if ack == txid => {
            record["status"] = json!("SUBMITTED");
            record["broadcast"] = json!(true);
            replace_json_atomic(output, &record)
        }
        Ok(_) => {
            record["acknowledgement"] = json!("MISMATCH");
            replace_json_atomic(output, &record)?;
            Err("TN10_NAMESPACE_TRANSITION_SUBMISSION_UNKNOWN".into())
        }
        Err(_) => Err("TN10_NAMESPACE_TRANSITION_SUBMISSION_UNKNOWN".into()),
    }
}

/// Rebuild the signed transaction from its public plan and signature packets before network use.
pub fn verify_namespace_transition_artifact(signed: &Value) -> Result<(), Error> {
    if signed["network"] != NETWORK
        || signed["broadcast"] != false
        || signed["native_vm_verified"] != true
        || signed["transition_plan"].is_null()
        || !signed["signature_packets"].is_array()
    {
        return Err("TN10_NAMESPACE_TRANSITION_SIGNED_DOCUMENT_INVALID".into());
    }
    let packets = signed["signature_packets"].clone();
    let input = json!({"plan":signed["transition_plan"],"packets":packets});
    let rebuilt = match signed["transition_plan"]["action"].as_str() {
        Some("namespace_parent_genesis") => {
            ktapeout_050_adapter_workbench::namespace_parent_genesis::transition_command(
                "--merge-signatures",
                &input,
            )
        }
        Some("profile_state_transition")
            if signed["transition_plan"]["request"]["operation"] == "ISSUE_NAMESPACE" =>
        {
            ktapeout_050_adapter_workbench::namespace_issuance_v1_plan::transition_command(
                "--merge-signatures",
                &input,
            )
        }
        _ => return Err("TN10_NAMESPACE_TRANSITION_SIGNED_DOCUMENT_INVALID".into()),
    }
    .map_err(|_| "TN10_NAMESPACE_TRANSITION_SIGNATURE_REVALIDATION_FAILED")?;
    if rebuilt["transaction"] != signed["transaction"]
        || rebuilt["native_plan_hash"] != signed["native_plan_hash"]
        || rebuilt["native_vm_verified"] != true
    {
        return Err("TN10_NAMESPACE_TRANSITION_SIGNATURE_REVALIDATION_FAILED".into());
    }
    let rpc: RpcTransaction = serde_json::from_value(signed["transaction"].clone())?;
    let transaction = Transaction::try_from(rpc)?;
    if signed["txid"].as_str() != Some(transaction.id().to_string().as_str()) {
        return Err("TN10_NAMESPACE_TRANSITION_TXID_MISMATCH".into());
    }
    Ok(())
}

/// Require each signed namespace-transition input to still be unspent and byte-identical on two
/// synchronized TN10 UTXO indexes immediately before broadcast.
pub fn verify_namespace_transition_inputs_with_transports(
    signed: &Value,
    first: &mut dyn Transport,
    second: &mut dyn Transport,
) -> Result<Value, Error> {
    let plan = &signed["transition_plan"];
    let request = &plan["request"];
    let inputs = match plan["action"].as_str() {
        Some("namespace_parent_genesis") => vec![request["funding_utxo"].clone()],
        Some("profile_state_transition") if request["operation"] == "ISSUE_NAMESPACE" => vec![
            request["parent_utxo"].clone(),
            request["root_gap_utxo"].clone(),
            request["fee_utxo"].clone(),
        ],
        _ => return Err("TN10_NAMESPACE_TRANSITION_PLAN_INVALID".into()),
    };
    let mut verified = Vec::with_capacity(inputs.len());
    for input in &inputs {
        let script_text = input["script_public_key"]
            .as_str()
            .ok_or("TN10_NAMESPACE_TRANSITION_INPUT_INVALID")?;
        let script = hex::decode(
            script_text
                .strip_prefix("0000")
                .ok_or("TN10_NAMESPACE_TRANSITION_INPUT_INVALID")?,
        )?;
        let address =
            if script.len() == 35 && script[0] == 0xaa && script[1] == 0x20 && script[34] == 0x87 {
                kaspa_rpc_core::RpcAddress::new(
                    "kaspatest".try_into()?,
                    8u8.try_into()?,
                    &script[2..34],
                )
            } else if script.len() == 34 && script[0] == 0x20 && script[33] == 0xac {
                kaspa_rpc_core::RpcAddress::new(
                    "kaspatest".try_into()?,
                    0u8.try_into()?,
                    &script[1..33],
                )
            } else {
                return Err("TN10_NAMESPACE_TRANSITION_INPUT_SCRIPT_UNSUPPORTED".into());
            };
        let observations = [checked_observation(first)?, checked_observation(second)?];
        if observations.iter().any(|node| node["utxo_indexed"] != true) {
            return Err("TN10_UTXO_INDEX_REQUIRED".into());
        }
        // Sequential observations may have different live DAG tips; compare the UTXOs below.
        let address_text = address.to_string();
        let left = canonical_utxos(first.read_utxos(&address_text)?, &address)?;
        let right = canonical_utxos(second.read_utxos(&address_text)?, &address)?;
        if left != right {
            return Err("TN10_NAMESPACE_TRANSITION_INPUT_NODES_DISAGREE".into());
        }
        let outpoint = input["outpoint"]
            .as_str()
            .ok_or("TN10_NAMESPACE_TRANSITION_INPUT_INVALID")?;
        let current = left
            .as_array()
            .and_then(|utxos| utxos.iter().find(|utxo| utxo["outpoint"] == outpoint))
            .ok_or("TN10_NAMESPACE_TRANSITION_INPUT_SPENT_OR_MISSING")?;
        for field in [
            "amount",
            "script_public_key",
            "block_daa_score",
            "covenant_id",
        ] {
            if current[field] != input[field] {
                return Err("TN10_NAMESPACE_TRANSITION_INPUT_CHANGED".into());
            }
        }
        verified.push(json!({
            "outpoint":outpoint,
            "amount_sompi":input["amount"],
            "script_public_key_sha256":hex::encode(Sha256::digest(script_text.as_bytes()))
        }));
    }
    Ok(json!({
        "status":"ALL_INPUTS_UNSPENT_AND_IDENTICAL_ON_BOTH_NODES",
        "checked_input_count":verified.len(),
        "inputs":verified
    }))
}

/// Require every V6 child-registration input to remain unspent and byte-identical on two
/// synchronized TN10 UTXO indexes immediately before broadcast.
pub fn verify_native_registration_inputs_with_transports(
    plan: &Value,
    first: &mut dyn Transport,
    second: &mut dyn Transport,
) -> Result<Value, Error> {
    let inputs = plan["inputs"]
        .as_array()
        .filter(|inputs| !inputs.is_empty())
        .ok_or("TN10_REGISTRATION_INPUTS_REQUIRED")?;
    let mut verified = Vec::with_capacity(inputs.len());
    for input in inputs {
        let script_text = input["script_public_key"]
            .as_str()
            .ok_or("TN10_REGISTRATION_INPUT_INVALID")?;
        let script = hex::decode(
            script_text
                .strip_prefix("0000")
                .ok_or("TN10_REGISTRATION_INPUT_INVALID")?,
        )?;
        let address =
            if script.len() == 35 && script[0] == 0xaa && script[1] == 0x20 && script[34] == 0x87 {
                kaspa_rpc_core::RpcAddress::new(
                    "kaspatest".try_into()?,
                    8u8.try_into()?,
                    &script[2..34],
                )
            } else if script.len() == 34 && script[0] == 0x20 && script[33] == 0xac {
                kaspa_rpc_core::RpcAddress::new(
                    "kaspatest".try_into()?,
                    0u8.try_into()?,
                    &script[1..33],
                )
            } else {
                return Err("TN10_REGISTRATION_INPUT_SCRIPT_UNSUPPORTED".into());
            };
        let observations = [checked_observation(first)?, checked_observation(second)?];
        if observations.iter().any(|node| node["utxo_indexed"] != true) {
            return Err("TN10_UTXO_INDEX_REQUIRED".into());
        }
        // Sequential observations may have different live DAG tips; compare the UTXOs below.
        let address_text = address.to_string();
        let left = canonical_utxos(first.read_utxos(&address_text)?, &address)?;
        let right = canonical_utxos(second.read_utxos(&address_text)?, &address)?;
        if left != right {
            return Err("TN10_REGISTRATION_INPUT_NODES_DISAGREE".into());
        }
        let outpoint = input["outpoint"]
            .as_str()
            .ok_or("TN10_REGISTRATION_INPUT_INVALID")?;
        let current = left
            .as_array()
            .and_then(|utxos| utxos.iter().find(|utxo| utxo["outpoint"] == outpoint))
            .ok_or("TN10_REGISTRATION_INPUT_SPENT_OR_MISSING")?;
        for field in [
            "amount",
            "script_public_key",
            "block_daa_score",
            "covenant_id",
        ] {
            if current[field] != input[field] {
                return Err("TN10_REGISTRATION_INPUT_CHANGED".into());
            }
        }
        verified.push(json!({
            "outpoint":outpoint,
            "amount_sompi":input["amount"],
            "script_public_key_sha256":hex::encode(Sha256::digest(script_text.as_bytes()))
        }));
    }
    Ok(json!({
        "status":"ALL_INPUTS_UNSPENT_AND_IDENTICAL_ON_BOTH_NODES",
        "checked_input_count":verified.len(),
        "inputs":verified
    }))
}

fn namespace_transition_limits(document: &Value) -> Result<(String, u64, u64, u64), Error> {
    let transition_plan = &document["plan"];
    let request = &transition_plan["request"];
    let action = transition_plan["action"]
        .as_str()
        .ok_or("TN10_NAMESPACE_TRANSITION_PLAN_INVALID")?;
    let inputs = match action {
        "namespace_parent_genesis" => vec![&request["funding_utxo"]],
        "profile_state_transition" if request["operation"] == "ISSUE_NAMESPACE" => {
            vec![
                &request["parent_utxo"],
                &request["root_gap_utxo"],
                &request["fee_utxo"],
            ]
        }
        _ => return Err("TN10_NAMESPACE_TRANSITION_PLAN_INVALID".into()),
    };
    let input_total = inputs.iter().try_fold(0u64, |total, input| {
        total
            .checked_add(
                input["amount"]
                    .as_u64()
                    .ok_or("TN10_NAMESPACE_TRANSITION_INPUT_AMOUNT_INVALID")?,
            )
            .ok_or_else(|| Error::from("TN10_NAMESPACE_TRANSITION_VALUE_OVERFLOW"))
    })?;
    let fee = request["fee_sompi"]
        .as_u64()
        .ok_or("TN10_NAMESPACE_TRANSITION_FEE_INVALID")?;
    // The authorization cap covers value actually committed plus the fee. A large funding
    // UTXO is not itself a spend: genesis returns its remainder to the exact funding script.
    // Bind the debit to the canonical plan request so changing the locked amounts changes the
    // native plan hash and invalidates this authorization.
    let authorized_debit = match action {
        "namespace_parent_genesis" => request["parent_state_sompi"]
            .as_u64()
            .and_then(|parent| {
                request["gap_state_sompi"]
                    .as_u64()
                    .and_then(|gap| parent.checked_add(gap))
            })
            .and_then(|locked| locked.checked_add(fee))
            .ok_or("TN10_NAMESPACE_TRANSITION_VALUE_OVERFLOW")?,
        // The issuance planner validates the parent successor and computes the incremental
        // carrier value over the consumed root Gap. Preserve its accounting instead of counting
        // the existing covenant inputs as newly spent wallet funds.
        "profile_state_transition" => {
            let issuance =
                ktapeout_050_adapter_workbench::namespace_issuance_v1_plan::build(request, false)?;
            // The adapter plan does not expose the legacy review-only economics object.
            // Its canonical fee change returns to the funding script, so the wallet
            // debit is exactly the fee input less that change (including the fee).
            let transaction: RpcTransaction =
                serde_json::from_value(issuance["body"]["transaction"].clone())?;
            request["fee_utxo"]["amount"]
                .as_u64()
                .and_then(|amount| {
                    transaction
                        .outputs
                        .last()
                        .and_then(|change| amount.checked_sub(change.value))
                })
                .ok_or("TN10_NAMESPACE_TRANSITION_VALUE_OVERFLOW")?
        }
        _ => return Err("TN10_NAMESPACE_TRANSITION_PLAN_INVALID".into()),
    };
    let requests = document["signing"]["requests"]
        .as_array()
        .filter(|requests| !requests.is_empty())
        .ok_or("TN10_NAMESPACE_TRANSITION_PLAN_INVALID")?;
    let plan_hash = requests[0]["native_plan_hash"]
        .as_str()
        .filter(|hash| hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or("TN10_NAMESPACE_TRANSITION_PLAN_INVALID")?;
    if requests
        .iter()
        .any(|request| request["native_plan_hash"].as_str() != Some(plan_hash))
    {
        return Err("TN10_NAMESPACE_TRANSITION_PLAN_INVALID".into());
    }
    Ok((plan_hash.to_owned(), input_total, fee, authorized_debit))
}

/// Prepare a bounded authorization for the exact public namespace transition plan.
/// The quote must be a fresh two-node observation; creation still requires typed terminal consent.
pub fn prepare_namespace_transition_authorization(
    document: &Value,
    fee_quote: &Value,
    max_total_sompi: u64,
    max_fee_sompi: u64,
    expires_at_unix: u64,
    now_unix: u64,
    allow_broadcast: bool,
) -> Result<Value, Error> {
    const MAX_QUOTE_AGE_SECONDS: u64 = 10 * 60;
    const MAX_AUTHORIZATION_LIFETIME_SECONDS: u64 = 24 * 60 * 60;
    let (plan_hash, input_total, fee, authorized_debit) = namespace_transition_limits(document)?;
    let endpoints = fee_quote["endpoints"]
        .as_array()
        .filter(|items| items.len() == 2)
        .ok_or("TN10_NAMESPACE_TRANSITION_FEE_QUOTE_INVALID")?;
    let rates = fee_quote["node_rates"]
        .as_array()
        .filter(|items| items.len() == 2)
        .ok_or("TN10_NAMESPACE_TRANSITION_FEE_QUOTE_INVALID")?;
    let endpoint_values = endpoints
        .iter()
        .map(|endpoint| {
            endpoint
                .as_str()
                .ok_or("TN10_NAMESPACE_TRANSITION_FEE_QUOTE_INVALID")
        })
        .collect::<Result<Vec<_>, _>>()?;
    let first_rate = rates[0]["feerate"]
        .as_f64()
        .ok_or("TN10_NAMESPACE_TRANSITION_FEE_QUOTE_INVALID")?;
    let second_rate = rates[1]["feerate"]
        .as_f64()
        .ok_or("TN10_NAMESPACE_TRANSITION_FEE_QUOTE_INVALID")?;
    if fee_quote["source"] != "live_dual_node_quote"
        || endpoint_values[0] == endpoint_values[1]
        || rates
            .iter()
            .enumerate()
            .any(|(index, rate)| rate["endpoint"].as_str() != Some(endpoint_values[index]))
        || [first_rate, second_rate]
            .iter()
            .any(|rate| !rate.is_finite() || *rate <= 0.0)
        || first_rate.max(second_rate) > first_rate.min(second_rate) * 2.0
        || fee_quote["fee_rate_sompi_per_gram"].as_u64()
            != Some(first_rate.max(second_rate).ceil() as u64)
    {
        return Err("TN10_NAMESPACE_TRANSITION_FEE_QUOTE_INVALID".into());
    }
    let observed_at = fee_quote["observed_at"]
        .as_str()
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .ok_or("TN10_NAMESPACE_TRANSITION_FEE_QUOTE_INVALID")?
        .timestamp();
    if observed_at < 0
        || observed_at as u64 > now_unix
        || now_unix - observed_at as u64 > MAX_QUOTE_AGE_SECONDS
    {
        return Err("TN10_NAMESPACE_TRANSITION_FEE_QUOTE_STALE".into());
    }
    if max_total_sompi < authorized_debit || max_fee_sompi < fee {
        return Err("TN10_NAMESPACE_TRANSITION_AUTHORIZATION_BUDGET_EXCEEDED".into());
    }
    if expires_at_unix <= now_unix
        || expires_at_unix - now_unix > MAX_AUTHORIZATION_LIFETIME_SECONDS
    {
        return Err("TN10_NAMESPACE_TRANSITION_AUTHORIZATION_EXPIRY_INVALID".into());
    }
    let quote_sha256 = hex::encode(Sha256::digest(serde_json::to_vec(fee_quote)?));
    Ok(json!({
        "schema":"KTAPEOUT-TN10-NAMESPACE-TRANSITION-AUTHORIZATION-V1",
        "network":NETWORK,
        "native_plan_hash":plan_hash,
        "input_total_sompi":input_total,
        "authorized_debit_sompi":authorized_debit,
        "fee_sompi":fee,
        "max_total_sompi":max_total_sompi,
        "max_fee_sompi":max_fee_sompi,
        "fee_quote_sha256":quote_sha256,
        "fee_quote":fee_quote,
        "created_at_unix":now_unix,
        "expires_at_unix":expires_at_unix,
        "allow_broadcast":allow_broadcast,
        "allow_readback":true,
        "confirmation_method":"TERMINAL_TYPED_PLAN_DIGEST",
        "created_with_terminal_confirmation":false
    }))
}

pub struct NamespaceTransitionAuthorizationConfirmation<'a> {
    pub expires_at_unix: u64,
    pub now_unix: u64,
    pub confirmation: &'a str,
}

pub fn create_namespace_transition_authorization(
    document: &Value,
    fee_quote: &Value,
    max_total_sompi: u64,
    max_fee_sompi: u64,
    allow_broadcast: bool,
    confirmation: NamespaceTransitionAuthorizationConfirmation<'_>,
) -> Result<Value, Error> {
    let mut authorization = prepare_namespace_transition_authorization(
        document,
        fee_quote,
        max_total_sompi,
        max_fee_sompi,
        confirmation.expires_at_unix,
        confirmation.now_unix,
        allow_broadcast,
    )?;
    let expected = format!(
        "AUTHORIZE {}",
        authorization["native_plan_hash"].as_str().unwrap_or("")
    );
    if confirmation.confirmation != expected {
        return Err("TN10_NAMESPACE_TRANSITION_AUTHORIZATION_CONFIRMATION_REQUIRED".into());
    }
    authorization["created_with_terminal_confirmation"] = json!(true);
    Ok(authorization)
}

pub fn verify_namespace_transition_authorization(
    document: &Value,
    authorization: &Value,
    now_unix: u64,
) -> Result<(), Error> {
    let (plan_hash, input_total, fee, authorized_debit) = namespace_transition_limits(document)?;
    let created = authorization["created_at_unix"]
        .as_u64()
        .ok_or("TN10_NAMESPACE_TRANSITION_AUTHORIZATION_TIME_INVALID")?;
    let expires = authorization["expires_at_unix"]
        .as_u64()
        .filter(|expires| *expires > now_unix && *expires > created)
        .ok_or("TN10_NAMESPACE_TRANSITION_AUTHORIZATION_EXPIRED")?;
    if expires - created > 24 * 60 * 60 || created > now_unix {
        return Err("TN10_NAMESPACE_TRANSITION_AUTHORIZATION_TIME_INVALID".into());
    }
    let quote_hash = hex::encode(Sha256::digest(serde_json::to_vec(
        &authorization["fee_quote"],
    )?));
    let quote_observed_at = authorization["fee_quote"]["observed_at"]
        .as_str()
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .ok_or("TN10_NAMESPACE_TRANSITION_FEE_QUOTE_INVALID")?
        .timestamp();
    if quote_observed_at < 0
        || quote_observed_at as u64 > now_unix
        || now_unix - quote_observed_at as u64 > 10 * 60
    {
        return Err("TN10_NAMESPACE_TRANSITION_FEE_QUOTE_STALE".into());
    }
    if authorization["schema"] != "KTAPEOUT-TN10-NAMESPACE-TRANSITION-AUTHORIZATION-V1"
        || authorization["network"] != NETWORK
        || authorization["native_plan_hash"] != plan_hash
        || authorization["input_total_sompi"] != input_total
        || authorization["authorized_debit_sompi"] != authorized_debit
        || authorization["fee_sompi"] != fee
        || authorization["max_total_sompi"]
            .as_u64()
            .is_none_or(|limit| limit < authorized_debit)
        || authorization["max_fee_sompi"]
            .as_u64()
            .is_none_or(|limit| limit < fee)
        || authorization["fee_quote_sha256"] != quote_hash
        || authorization["allow_broadcast"] != true
        || authorization["allow_readback"] != true
        || authorization["confirmation_method"] != "TERMINAL_TYPED_PLAN_DIGEST"
        || authorization["created_with_terminal_confirmation"] != true
    {
        return Err("TN10_NAMESPACE_TRANSITION_AUTHORIZATION_BINDING_MISMATCH".into());
    }
    Ok(())
}

/// Validate the signed artifact, then submit with two independent TN10 transports available for
/// mandatory readback before any retry of an unknown submission.
pub fn submit_namespace_transition(
    input: &Path,
    output: &Path,
    nodes: &[String],
    retry_same_txid: bool,
) -> Result<(), Error> {
    #[cfg(feature = "tn10-network")]
    {
        use std::io::{BufRead, IsTerminal, Read, Write};
        let signed = read_json(input)?;
        verify_namespace_transition_artifact(&signed)?;
        if !std::io::stdin().is_terminal() {
            return Err("TN10_NAMESPACE_TRANSITION_BROADCAST_TERMINAL_REQUIRED".into());
        }
        let endpoints = verification_endpoints(&json!({"network":NETWORK,"nodes":nodes}))?;
        let mut first = WrpcTransport::connect(&endpoints[0])?;
        let mut second = WrpcTransport::connect(&endpoints[1])?;
        let input_readback =
            verify_namespace_transition_inputs_with_transports(&signed, &mut first, &mut second)?;
        let txid = signed["txid"]
            .as_str()
            .ok_or("TN10_NAMESPACE_TRANSITION_TXID_MISMATCH")?;
        let confirmation = format!("BROADCAST {txid}");
        eprintln!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "network":NETWORK,
                "txid":txid,
                "input_total_sompi":signed["authorization"]["input_total_sompi"],
                "fee_sompi":signed["authorization"]["fee_sompi"],
                "max_total_sompi":signed["authorization"]["max_total_sompi"],
                "max_fee_sompi":signed["authorization"]["max_fee_sompi"],
                "authorization_sha256":hex::encode(Sha256::digest(serde_json::to_vec(&signed["authorization"])?)),
                "live_input_readback":input_readback,
                "retry_same_txid":retry_same_txid
            }))?
        );
        eprint!("Type {confirmation} to submit this exact transaction: ");
        std::io::stderr()
            .flush()
            .map_err(|_| "TN10_NAMESPACE_TRANSITION_BROADCAST_CONFIRMATION_REQUIRED")?;
        let mut entered = String::new();
        std::io::stdin()
            .lock()
            .take(256)
            .read_line(&mut entered)
            .map_err(|_| "TN10_NAMESPACE_TRANSITION_BROADCAST_CONFIRMATION_REQUIRED")?;
        if entered.trim() != confirmation {
            return Err("TN10_NAMESPACE_TRANSITION_BROADCAST_CONFIRMATION_REQUIRED".into());
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "TN10_CLOCK_INVALID")?
            .as_secs();
        submit_namespace_transition_with_transports(
            input,
            output,
            retry_same_txid,
            now,
            &confirmation,
            &mut first,
            &mut second,
        )
    }
    #[cfg(not(feature = "tn10-network"))]
    {
        let _ = (input, output, nodes, retry_same_txid);
        Err("TN10_NETWORK_TRANSPORT_REQUIRED".into())
    }
}

pub fn submit(input: &Path, output: &Path, retry_same_txid: bool) -> Result<(), Error> {
    #[cfg(feature = "tn10-network")]
    {
        let signed = read_json(input)?;
        if signed["schema"] == "KTAPEOUT-TN10-NATIVE-SIGNATURES-AGGREGATE-V1" {
            use std::io::{BufRead, IsTerminal, Read, Write};
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| "TN10_CLOCK_INVALID")?
                .as_secs();
            let verified =
                crate::tn10_developer_signing::verify_native_registration_aggregate(&signed, now)?;
            let native_transaction =
                Transaction::try_from(serde_json::from_value::<RpcTransaction>(
                    verified["transaction"].clone(),
                )?)?;
            let txid = native_transaction.id().to_string();
            let endpoints = verification_endpoints(&json!({"network":NETWORK,"nodes":[]}))?;
            let mut first = WrpcTransport::connect(&endpoints[0])?;
            let mut second = WrpcTransport::connect(&endpoints[1])?;
            if retry_same_txid {
                let previous = read_json(output)?;
                let reconciled = reconcile_native_registration_submission_with_transports(
                    &signed["plan"],
                    &previous,
                    &verified["transaction"],
                    &txid,
                    &mut first,
                    &mut second,
                )?;
                if reconciled["readback_status"] != "NOT_FOUND_BOTH_RETRY_REQUIRES_REVIEW" {
                    return Err("TN10_REGISTRATION_RETRY_REQUIRES_READBACK_REVIEW".into());
                }
            }
            let input_readback = verify_native_registration_inputs_with_transports(
                &signed["plan"],
                &mut first,
                &mut second,
            )?;
            if !std::io::stdin().is_terminal() {
                return Err("TN10_REGISTRATION_BROADCAST_TERMINAL_REQUIRED".into());
            }
            let confirmation = format!("BROADCAST {txid}");
            eprintln!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "network":NETWORK,
                    "txid":txid,
                    "authorization_sha256":signed["authorization_sha256"],
                    "input_readback":input_readback,
                    "retry_same_txid":retry_same_txid
                }))?
            );
            eprint!("Type {confirmation} to submit this exact transaction: ");
            std::io::stderr()
                .flush()
                .map_err(|_| "TN10_REGISTRATION_BROADCAST_CONFIRMATION_REQUIRED")?;
            let mut entered = String::new();
            std::io::stdin()
                .lock()
                .take(256)
                .read_line(&mut entered)
                .map_err(|_| "TN10_REGISTRATION_BROADCAST_CONFIRMATION_REQUIRED")?;
            if entered.trim() != confirmation {
                return Err("TN10_REGISTRATION_BROADCAST_CONFIRMATION_REQUIRED".into());
            }
            return submit_with_transport_retry(input, output, retry_same_txid, &mut first);
        }
        let endpoint =
            std::env::var("KTAPE_TN10_ENDPOINT").map_err(|_| "TN10_ENDPOINT_REQUIRED")?;
        let mut transport = WrpcTransport::connect(&endpoint)?;
        submit_with_transport_retry(input, output, retry_same_txid, &mut transport)
    }

    #[cfg(not(feature = "tn10-network"))]
    {
        struct NoNetwork;
        impl Transport for NoNetwork {
            fn submit(&mut self, _: &RpcTransaction) -> Result<String, String> {
                Err("TN10_NETWORK_TRANSPORT_REQUIRED".into())
            }
            fn read_transaction(&mut self, _: &str) -> Result<Option<Value>, String> {
                Err("TN10_NETWORK_TRANSPORT_REQUIRED".into())
            }
        }
        let _ = retry_same_txid;
        submit_with_transport(input, output, &mut NoNetwork)
    }
}

fn verification_endpoints(evidence: &Value) -> Result<[String; 2], Error> {
    if evidence["network"] != NETWORK {
        return Err("TN10_NETWORK_INVALID".into());
    }
    let endpoints: Vec<String> = match std::env::var("KTAPE_TN10_ENDPOINTS") {
        Ok(value) => value.split(';').map(str::to_owned).collect(),
        Err(_) => evidence["nodes"]
            .as_array()
            .ok_or("TN10_TWO_NODE_EVIDENCE_REQUIRED")?
            .iter()
            .map(|node| {
                node.as_str()
                    .map(str::to_owned)
                    .ok_or("TN10_ENDPOINT_REQUIRED")
            })
            .collect::<Result<_, _>>()?,
    };
    if endpoints.len() != 2 {
        return Err("TN10_TWO_INDEPENDENT_NODES_REQUIRED".into());
    }
    let mut hosts = Vec::new();
    for endpoint in &endpoints {
        validate_endpoint(endpoint)?;
        let authority = endpoint
            .strip_prefix("wss://")
            .and_then(|rest| rest.split('/').next())
            .ok_or("TN10_ENDPOINT_INVALID")?;
        hosts.push(
            authority
                .split(':')
                .next()
                .unwrap_or_default()
                .to_ascii_lowercase(),
        );
    }
    if hosts[0] == hosts[1] {
        return Err("TN10_TWO_INDEPENDENT_NODES_REQUIRED".into());
    }
    Ok([endpoints[0].clone(), endpoints[1].clone()])
}

fn verification_target(evidence: &Value) -> Result<(Transaction, String, String), Error> {
    let plan = &evidence["plan"];
    if plan["network"] != NETWORK || plan["schema"] != "KTAPEOUT-TN10-PLAN-V1" {
        return Err("TN10_PLAN_INVALID".into());
    }
    let rpc: RpcTransaction = serde_json::from_value(plan["transaction"].clone())?;
    let expected = Transaction::try_from(rpc)?;
    let payload: Value = serde_json::from_slice(&expected.payload)?;
    if payload["network"] != NETWORK
        || payload["schema"] != SCHEMA
        || !plan["artifact_root"].is_string()
        || payload["artifact"]["artifact_sha256"] != plan["artifact_root"]
    {
        return Err("TN10_TARGET_MISMATCH".into());
    }
    let txid = evidence["txid"]
        .as_str()
        .ok_or("TN10_TRANSACTION_ID_REQUIRED")?;
    if expected.id().to_string() != txid {
        return Err("TN10_PLAN_TRANSACTION_MISMATCH".into());
    }
    let hash = evidence["block_hash"]
        .as_str()
        .ok_or("TN10_BLOCK_HASH_REQUIRED")?;
    Ok((expected, txid.to_owned(), hash.to_owned()))
}

fn node_inclusion(
    transport: &mut dyn Transport,
    expected: &Transaction,
    txid: &str,
    hash: &str,
) -> Result<crate::tn10_block_proof::InclusionProof, Error> {
    let block = transport.read_block(hash)?;
    let proof = crate::tn10_block_proof::verify_block_inclusion(NETWORK, hash, txid, &block)?;
    let actual = Transaction::try_from(block.transactions[proof.transaction_index].clone())?;
    // A transaction ID is not a substitute for checking the intended payload and outputs.
    if actual.outputs != expected.outputs || actual.payload != expected.payload {
        return Err("TN10_TARGET_MISMATCH".into());
    }
    Ok(proof)
}

#[doc(hidden)]
#[derive(Debug, PartialEq, Eq)]
pub struct ChainAcceptance {
    pub accepting_block: String,
    pub confirmations: u64,
    pub sufficient: bool,
    pub truncated: bool,
}

fn minimum_confirmations(evidence: &Value) -> Result<u64, Error> {
    match evidence.get("min_confirmations") {
        None => Ok(DEFAULT_MIN_CONFIRMATIONS),
        Some(value) => value
            .as_u64()
            .filter(|n| *n >= 1)
            .ok_or_else(|| "TN10_MIN_CONFIRMATIONS_INVALID".into()),
    }
}

fn node_chain_acceptance(
    node: &mut dyn Transport,
    txid: &str,
    block_hash: &str,
    minimum: u64,
) -> Result<ChainAcceptance, Error> {
    let state = node.read_chain_state(block_hash)?;
    chain_acceptance_from_snapshot(state, txid, block_hash, minimum)
}

/// Evaluate a node's virtual-chain response for a transaction included in a DAG block.
///
/// A nonempty removed path can be legitimate: the included block may be a blue
/// mergeset block, while a later selected-chain block lists its transaction as
/// accepted. Acceptance is established only by the accepted map on the selected
/// added path, not by the inclusion block being selected itself. In pinned
/// rusty-kaspa 01b532e8, `get_virtual_chain_from_block` computes the path from
/// the queried block to the current sink; the path may therefore place that
/// blue merge block in `removed` while its accepted transaction appears in
/// `added` (consensus/src/consensus/mod.rs:846).
#[doc(hidden)]
pub fn chain_acceptance_from_snapshot(
    state: ChainSnapshot,
    txid: &str,
    block_hash: &str,
    minimum: u64,
) -> Result<ChainAcceptance, Error> {
    if state.network != NETWORK {
        return Err("TN10_NETWORK_MISMATCH".into());
    }
    if minimum < 1 {
        return Err("TN10_MIN_CONFIRMATIONS_INVALID".into());
    }
    if minimum > CHAIN_WINDOW as u64 {
        return Err("TN10_CONFIRMATION_WINDOW_EXCEEDED".into());
    }
    let mut removed = std::collections::BTreeSet::new();
    for hash in &state.removed {
        let parsed: TransactionId = hash.parse().map_err(|_| "TN10_CHAIN_STATE_INVALID")?;
        if parsed.to_string() != *hash || !removed.insert(hash.clone()) {
            return Err("TN10_CHAIN_STATE_INVALID".into());
        }
    }
    if !removed.is_empty() && !removed.contains(block_hash) {
        return Err("TN10_BLOCK_NOT_ON_SELECTED_PARENT_CHAIN".into());
    }
    let mut unique = std::collections::BTreeSet::new();
    for hash in &state.added {
        let parsed: TransactionId = hash.parse().map_err(|_| "TN10_CHAIN_STATE_INVALID")?;
        if parsed.to_string() != *hash || hash == block_hash || !unique.insert(hash) {
            return Err("TN10_CHAIN_STATE_INVALID".into());
        }
    }
    if state.accepted.keys().any(|hash| !unique.contains(hash)) {
        return Err("TN10_CHAIN_STATE_INVALID".into());
    }
    let truncated = state.added.len() > CHAIN_WINDOW;
    let matches: Vec<_> = state
        .added
        .iter()
        .take(CHAIN_WINDOW)
        .enumerate()
        .filter(|(_, hash)| {
            state
                .accepted
                .get(*hash)
                .is_some_and(|ids| ids.iter().any(|id| id == txid))
        })
        .collect();
    if matches.len() != 1 {
        return Err(if truncated {
            "TN10_TRANSACTION_ACCEPTANCE_OUTSIDE_WINDOW"
        } else {
            "TN10_TRANSACTION_ACCEPTANCE_NOT_ESTABLISHED"
        }
        .into());
    }
    let (index, hash) = matches[0];
    // A bounded RPC batch is a conservative lower bound, never extrapolated.
    let confirmations = (state.added.len().min(CHAIN_WINDOW) - index) as u64;
    Ok(ChainAcceptance {
        accepting_block: hash.clone(),
        confirmations,
        sufficient: confirmations >= minimum,
        truncated,
    })
}

pub fn verify_with_transports(
    evidence: &Value,
    output: &Path,
    first: &mut dyn Transport,
    second: &mut dyn Transport,
) -> Result<(), Error> {
    reset_verification(output)?;
    verification_endpoints(evidence)?;
    let minimum = minimum_confirmations(evidence)?;
    let (expected, txid, hash) = verification_target(evidence)?;
    let a = node_inclusion(first, &expected, &txid, &hash)?;
    let b = node_inclusion(second, &expected, &txid, &hash)?;
    if a != b {
        return Err("TN10_DUAL_NODE_DISAGREEMENT".into());
    }
    let chain_a = node_chain_acceptance(first, &txid, &hash, minimum)?;
    let chain_b = node_chain_acceptance(second, &txid, &hash, minimum)?;
    if chain_a.accepting_block != chain_b.accepting_block
        || chain_a.sufficient != chain_b.sufficient
    {
        return Err("TN10_DUAL_NODE_DISAGREEMENT".into());
    }
    let status = if chain_a.sufficient {
        "VERIFIED"
    } else {
        "CONFIRMATIONS_INSUFFICIENT"
    };
    write_json(
        output,
        &json!({"schema":"KTAPEOUT-TN10-VERIFY-V1","network":NETWORK,
            "status":status,"included":true,"accepted":true,"accepted_by_selected_chain":true,
            "min_confirmations":minimum,"confirmations_sufficient":chain_a.sufficient,
            "confirmations_lower_bound":chain_a.confirmations.min(chain_b.confirmations),
            "node_confirmations":[chain_a.confirmations,chain_b.confirmations],
            "truncated":chain_a.truncated || chain_b.truncated,
            "accepting_block":chain_a.accepting_block,
            "nodes":evidence["nodes"],
            "endpoints_from_evidence":evidence["endpoints_from_evidence"].as_bool().unwrap_or(true),
            "broadcast":false,"txid":txid,"block_hash":hash,
            "merkle_root":a.merkle_root,"claims":evidence.get("proof_valid")}),
    )?;
    if !chain_a.sufficient {
        return Err("TN10_CONFIRMATIONS_INSUFFICIENT".into());
    }
    Ok(())
}

fn reset_verification(output: &Path) -> Result<(), Error> {
    replace_json_atomic(
        output,
        &json!({"schema":"KTAPEOUT-TN10-VERIFY-V1","network":NETWORK,
        "status":"UNVERIFIED","included":false,"accepted":false,"broadcast":false}),
    )
}

pub fn verify(input: &Path, output: &Path) -> Result<(), Error> {
    validate_input_output_paths(input, output)?;
    let evidence = read_json(input)?;
    reset_verification(output)?;
    let endpoints_from_evidence = std::env::var_os("KTAPE_TN10_ENDPOINTS").is_none();
    let endpoints = verification_endpoints(&evidence)?;
    let mut evidence = evidence;
    evidence["endpoints_from_evidence"] = json!(endpoints_from_evidence);
    evidence["nodes"] = json!(endpoints);
    verification_target(&evidence)?;
    minimum_confirmations(&evidence)?;
    let mut first = WrpcTransport::connect(&endpoints[0])?;
    let mut second = WrpcTransport::connect(&endpoints[1])?;
    verify_with_transports(&evidence, output, &mut first, &mut second)
}

fn canonical_hash(value: &Value) -> Result<String, Error> {
    let raw = value.as_str().ok_or("TN10_HASH_REQUIRED")?;
    let hash: TransactionId = raw.parse().map_err(|_| "TN10_HASH_INVALID")?;
    if hash.to_string() != raw {
        return Err("TN10_HASH_NONCANONICAL".into());
    }
    Ok(raw.to_owned())
}

fn checked_observation(transport: &mut dyn Transport) -> Result<Value, Error> {
    let observation = transport.read_observation()?;
    if observation["network"] != NETWORK || observation["synced"] != true {
        return Err("TN10_NODE_NOT_SYNCED_OR_NETWORK_MISMATCH".into());
    }
    canonical_hash(&observation["start_hash"])?;
    Ok(observation)
}

fn canonical_utxos(raw: Value, address: &kaspa_rpc_core::RpcAddress) -> Result<Value, Error> {
    let entries: Vec<kaspa_rpc_core::RpcUtxosByAddressesEntry> = serde_json::from_value(raw)?;
    let mut view = std::collections::BTreeMap::new();
    for entry in entries {
        if entry.address.as_ref().is_some_and(|found| found != address) {
            return Err("TN10_UTXO_ADDRESS_MISMATCH".into());
        }
        let outpoint = format!("{}:{}", entry.outpoint.transaction_id, entry.outpoint.index);
        let utxo = entry.utxo_entry;
        let item = json!({"outpoint":outpoint, "amount":utxo.amount,
            "block_daa_score":utxo.block_daa_score,
            "script_public_key":utxo.script_public_key, "covenant_id":utxo.covenant_id,
            "is_coinbase":utxo.is_coinbase});
        if view.insert(outpoint, item).is_some() {
            return Err("TN10_DUPLICATE_UTXO".into());
        }
    }
    Ok(Value::Array(view.into_values().collect()))
}

/// Derive the TN10 address used by the v2.1.0 UTXO index for a standard covenant P2SH script.
/// Registry state scripts have the exact `OP_BLAKE2B <32-byte hash> OP_EQUAL` form.
fn registry_script_address(script_public_key: &str) -> Result<kaspa_rpc_core::RpcAddress, Error> {
    let bytes = hex::decode(
        script_public_key
            .strip_prefix("0000")
            .ok_or("TN10_SCRIPT_VERSION_UNSUPPORTED")?,
    )?;
    if bytes.len() != 35 || bytes[0] != 0xaa || bytes[1] != 0x20 || bytes[34] != 0x87 {
        return Err("TN10_REGISTRY_SCRIPT_HASH_REQUIRED".into());
    }
    Ok(kaspa_rpc_core::RpcAddress::new(
        "kaspatest".try_into()?,
        8u8.try_into()?,
        &bytes[2..34],
    ))
}

/// Read an exact covenant script's current UTXOs from both TN10 nodes.
/// The v2.1.0 address index supports P2SH script hashes; every result is checked against the
/// requested script bytes, and no state supplied by the caller is treated as chain evidence.
pub fn registry_script_utxos_with_transports(
    request: &Value,
    first: &mut dyn Transport,
    second: &mut dyn Transport,
) -> Result<Value, Error> {
    let endpoints = verification_endpoints(request)?;
    let script_public_key = request["script_public_key"]
        .as_str()
        .ok_or("TN10_SCRIPT_REQUIRED")?;
    let address = registry_script_address(script_public_key)?;
    let address_text = address.to_string();
    let observations = [checked_observation(first)?, checked_observation(second)?];
    if observations.iter().any(|node| node["utxo_indexed"] != true) {
        return Err("TN10_UTXO_INDEX_REQUIRED".into());
    }
    let a = canonical_utxos(first.read_utxos(&address_text)?, &address)?;
    let b = canonical_utxos(second.read_utxos(&address_text)?, &address)?;
    if a != b {
        return Err("TN10_UTXO_NODES_DISAGREE".into());
    }
    for item in a.as_array().ok_or("TN10_UTXO_VIEW_INVALID")? {
        let spk = parse_spk(&item["script_public_key"])?;
        if hex::encode(spk.script())
            != hex::encode(hex::decode(
                script_public_key
                    .strip_prefix("0000")
                    .ok_or("TN10_SCRIPT_VERSION_UNSUPPORTED")?,
            )?)
        {
            return Err("TN10_SCRIPT_UTXO_MISMATCH".into());
        }
    }
    Ok(json!({
        "schema":"KTAPEOUT-TN10-REGISTRY-SCRIPT-UTXO-V1",
        "status":"TN10_DUAL_RPC_SCRIPT_UTXOS_MATCH",
        "network":NETWORK,
        "script_public_key":script_public_key,
        "address":address_text,
        "nodes":endpoints,
        "observations":observations,
        "utxos":a,
        "broadcast":false,
        "operator_independence_verified":false
    }))
}

/// Recompute each merged namespace's AdapterParent state and verify its live UTXO set on both nodes.
/// Discovery lists and supplied state fields are untrusted; the namespace hash must bind to the
/// derived state script, and the exact script must return one identical, sufficiently funded UTXO.
pub fn verify_merged_namespace_keys_with_transports(
    request: &Value,
    first: &mut dyn Transport,
    second: &mut dyn Transport,
) -> Result<Value, Error> {
    let sources = request["namespace_key_sources"]
        .as_array()
        .ok_or("NAME_KEY_LIST_SOURCE_REQUIRED")?;
    let keys =
        crate::registered_keys::merged_namespace_keys(sources).map_err(|error| -> Error {
            if error == "NAME_KEY_LIST_INCOMPLETE_OR_STALE" {
                crate::registered_keys::stale_key_list_error().into()
            } else {
                error.into()
            }
        })?;
    let candidates = request["namespace_state_candidates"]
        .as_array()
        .ok_or_else(crate::registered_keys::stale_key_list_error)?;
    let mut verified = Vec::with_capacity(keys.len());
    let economics: Value = serde_json::from_str(crate::registered_keys::registry_economics_data())?;
    let minimum = economics["adapter_gap_floor_sompi"]
        .as_u64()
        .ok_or("REGISTRY_ECONOMICS_INVALID")?;
    for key in keys {
        let matches = candidates
            .iter()
            .filter(|candidate| candidate["namespace"].as_str() == Some(key.namespace.as_str()))
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(crate::registered_keys::stale_key_list_error().into());
        }
        let state_args = matches[0]["state_args"]
            .as_array()
            .filter(|args| args.len() == 5)
            .ok_or_else(crate::registered_keys::stale_key_list_error)?;
        if state_args[0].as_str() != Some(key.key_hex.as_str()) {
            return Err(crate::registered_keys::stale_key_list_error().into());
        }
        let mut writes = Vec::with_capacity(5);
        for (index, offset) in [2usize, 35, 68, 101].into_iter().enumerate() {
            let raw = state_args[index]
                .as_str()
                .filter(|hex| {
                    hex.len() == 64
                        && hex
                            .bytes()
                            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                })
                .ok_or_else(crate::registered_keys::stale_key_list_error)?;
            writes.push(crate::registry_templates::ByteWrite {
                offset,
                bytes: hex::decode(raw)
                    .map_err(|_| crate::registered_keys::stale_key_list_error())?,
            });
        }
        let nonce = state_args[4]
            .as_u64()
            .ok_or_else(crate::registered_keys::stale_key_list_error)?;
        writes.push(crate::registry_templates::ByteWrite {
            offset: 134,
            bytes: nonce.to_le_bytes().to_vec(),
        });
        let script = crate::registry_templates::render(
            crate::registry_templates::RegistryTemplate::AdapterParent,
            &writes,
        )?;
        let script_public_key = format!(
            "0000aa20{}87",
            hex::encode(crate::name_state_template::blake2b_256(&script))
        );
        let mut read_request = request.clone();
        read_request["script_public_key"] = json!(script_public_key);
        let result = registry_script_utxos_with_transports(&read_request, first, second)?;
        let utxos = result["utxos"]
            .as_array()
            .ok_or("TN10_REGISTRY_STATE_MISSING")?;
        if utxos.len() != 1 {
            return Err(crate::registered_keys::stale_key_list_error().into());
        }
        let amount = utxos[0]["amount"]
            .as_u64()
            .ok_or("TN10_REGISTRY_STATE_MISSING")?;
        if amount < minimum {
            return Err("TN10_REGISTRY_ADAPTER_PARENT_VALUE_BELOW_FLOOR".into());
        }
        verified.push(json!({
            "namespace":key.namespace,
            "namespace_key":key.key_hex,
            "script_public_key":script_public_key,
            "state_args":state_args,
            "amount_sompi":amount,
            "status":"TN10_DUAL_RPC_NAMESPACE_STATE_MATCH"
        }));
    }
    Ok(json!({
        "schema":"KTAPEOUT-TN10-MERGED-NAMESPACE-KEY-VERIFICATION-V1",
        "status":"TN10_DUAL_RPC_MERGED_NAMESPACE_KEYS_MATCH",
        "network":NETWORK,
        "verified":verified,
        "broadcast":false
    }))
}

/// Read the requested live Gap/Deed covenant states from both configured TN10 nodes.
/// Each state is accepted only when the nodes report the same non-empty UTXO set and every
/// returned UTXO carries the exact requested script. The state descriptions are inputs, never
/// chain evidence; callers must derive them from the pinned public templates first.
pub fn registry_state_bundle_with_transports(
    request: &Value,
    first: &mut dyn Transport,
    second: &mut dyn Transport,
) -> Result<Value, Error> {
    let endpoints = verification_endpoints(request)?;
    let states = request["states"]
        .as_array()
        .filter(|items| !items.is_empty())
        .ok_or("TN10_REGISTRY_STATES_REQUIRED")?;
    let mut verified = Vec::with_capacity(states.len());
    let mut seen = std::collections::BTreeSet::new();
    for state in states {
        let role = state["role"]
            .as_str()
            .ok_or("TN10_REGISTRY_STATE_ROLE_REQUIRED")?;
        if !matches!(role, "gap" | "deed") {
            return Err("TN10_REGISTRY_STATE_ROLE_INVALID".into());
        }
        let script_public_key = state["script_public_key"]
            .as_str()
            .ok_or("TN10_SCRIPT_REQUIRED")?;
        if !seen.insert((role, script_public_key)) {
            return Err("TN10_REGISTRY_STATE_DUPLICATE".into());
        }
        let mut script_request = request.clone();
        script_request["script_public_key"] = json!(script_public_key);
        let result = registry_script_utxos_with_transports(&script_request, first, second)?;
        if result["utxos"].as_array().is_none_or(Vec::is_empty) {
            return Err(format!("TN10_REGISTRY_STATE_MISSING:{role}").into());
        }
        verified.push(json!({
            "role":role,
            "script_public_key":script_public_key,
            "address":result["address"],
            "utxos":result["utxos"]
        }));
    }
    Ok(json!({
        "schema":"KTAPEOUT-TN10-REGISTRY-STATE-BUNDLE-V1",
        "status":"TN10_DUAL_RPC_REGISTRY_STATES_MATCH",
        "network":NETWORK,
        "nodes":endpoints,
        "states":verified,
        "broadcast":false
    }))
}

fn registry_fee_input_with_transports(
    fee_input: &Value,
    first: &mut dyn Transport,
    second: &mut dyn Transport,
) -> Result<Value, Error> {
    let script_text = fee_input["script_public_key"]
        .as_str()
        .ok_or("TN10_REGISTRATION_FEE_SCRIPT_REQUIRED")?;
    let script = hex::decode(
        script_text
            .strip_prefix("0000")
            .ok_or("TN10_REGISTRATION_FEE_SCRIPT_INVALID")?,
    )?;
    if script.len() != 34 || script[0] != 0x20 || script[33] != 0xac {
        return Err("TN10_REGISTRATION_FEE_SCRIPT_INVALID".into());
    }
    let address =
        kaspa_rpc_core::RpcAddress::new("kaspatest".try_into()?, 0u8.try_into()?, &script[1..33]);
    let address_text = address.to_string();
    let observations = [checked_observation(first)?, checked_observation(second)?];
    if observations.iter().any(|node| node["utxo_indexed"] != true) {
        return Err("TN10_UTXO_INDEX_REQUIRED".into());
    }
    let a = canonical_utxos(first.read_utxos(&address_text)?, &address)?;
    let b = canonical_utxos(second.read_utxos(&address_text)?, &address)?;
    if a != b {
        return Err("TN10_REGISTRATION_FEE_INPUT_NODES_DISAGREE".into());
    }
    let expected_outpoint = fee_input["outpoint"]
        .as_str()
        .ok_or("TN10_REGISTRATION_FEE_OUTPOINT_REQUIRED")?;
    let utxo = a
        .as_array()
        .and_then(|entries| {
            entries
                .iter()
                .find(|entry| entry["outpoint"] == expected_outpoint)
        })
        .ok_or("TN10_REGISTRATION_FEE_INPUT_MISSING")?;
    if utxo["script_public_key"] != script_text {
        return Err("TN10_REGISTRATION_FEE_SCRIPT_MISMATCH".into());
    }
    Ok(utxo.clone())
}

fn normalize_registry_request(input: &Value) -> Result<Value, Error> {
    let request = input.get("request").unwrap_or(input);
    if !request.is_object() {
        return Err("TN10_REGISTER_REQUEST_INVALID".into());
    }
    Ok(request.clone())
}

fn attach_measured_registration_compute_budgets(input: &mut Value) -> Result<(), Error> {
    let kind = input["registration_kind"]
        .as_str()
        .ok_or("TN10_REGISTRATION_KIND_INVALID")?;
    let data: Value = serde_json::from_str(NATIVE_REGISTRATION_COMPUTE_BUDGETS)?;
    let profile = data["profiles"][kind].as_object().ok_or_else(|| {
        if kind == "SLOT" {
            "TN10_REGISTRATION_COMPUTE_BUDGET_UNMEASURED"
        } else {
            "TN10_REGISTRATION_KIND_INVALID"
        }
    })?;
    if profile["status"] != "MEASURED" {
        return Err("TN10_REGISTRATION_COMPUTE_BUDGET_UNMEASURED".into());
    }
    let inputs = input["inputs"]
        .as_array_mut()
        .ok_or("TN10_REGISTRATION_INPUTS_REQUIRED")?;
    let entries = profile["inputs"]
        .as_array()
        .filter(|entries| entries.len() == inputs.len())
        .ok_or("TN10_REGISTRATION_COMPUTE_BUDGET_PROFILE_INVALID")?;
    for (index, (item, entry)) in inputs.iter_mut().zip(entries).enumerate() {
        let script = item["script_public_key"]
            .as_str()
            .ok_or("TN10_SCRIPT_REQUIRED")?;
        let script_kind = match script.strip_prefix("0000").unwrap_or(script) {
            value if value.starts_with("aa20") && value.ends_with("87") => "p2sh-covenant",
            value if value.starts_with("20") && value.ends_with("ac") => "p2pk-schnorr",
            _ => return Err("TN10_REGISTRATION_COMPUTE_BUDGET_PROFILE_INVALID".into()),
        };
        if entry["input_index"].as_u64() != Some(index as u64)
            || entry["script_kind"] != script_kind
        {
            return Err("TN10_REGISTRATION_COMPUTE_BUDGET_PROFILE_INVALID".into());
        }
        item["compute_budget"] = entry["compute_budget"].clone();
    }
    Ok(())
}

/// Combine a read-only registration estimate with live, equal Gap/Deed UTXO views.
/// State scripts are caller-derived from the pinned templates; the returned bundle records the
/// exact scripts and dual-RPC observations so the plan never treats a local list as chain proof.
pub fn registry_register_plan_with_transports(
    request: &Value,
    first: &mut dyn Transport,
    second: &mut dyn Transport,
) -> Result<Value, Error> {
    let normalized_request = normalize_registry_request(request)?;
    let request = &normalized_request;
    let fee_quote = dual_fee_quote_with_transports(request, first, second)?;
    let native_transaction_plan = build_native_registration_plan_at_fee_quote(
        request
            .get("native_transaction_input")
            .ok_or("TN10_REGISTRATION_NATIVE_TRANSACTION_INPUT_REQUIRED")?,
        fee_quote["fee_rate_sompi_per_gram"]
            .as_u64()
            .ok_or("REGISTRATION_FEE_INPUT_INVALID")?,
    )?;
    let normalized_mass = native_transaction_plan["quality"]["normalized_total_mass"]
        .as_u64()
        .filter(|mass| *mass > 0)
        .ok_or("TN10_REGISTRATION_MASS_UNAVAILABLE")?;
    let existing_slugs = request["existing_slugs"]
        .as_array()
        .ok_or("NAMESPACE_NAMES_REQUIRED")?
        .iter()
        .map(|slug| {
            slug.as_str()
                .map(str::to_owned)
                .ok_or("NAMESPACE_NAMES_INVALID")
        })
        .collect::<Result<Vec<_>, _>>()?;
    let plan_result =
        crate::registered_keys::plan_registration(crate::registered_keys::RegistrationPlanInput {
            network: request["network"].as_str().ok_or("TN10_NETWORK_INVALID")?,
            namespace: request["namespace"].as_str().ok_or("NAMESPACE_REQUIRED")?,
            slug: request["slug"].as_str().ok_or("NAME_SLUG_REQUIRED")?,
            owner: request["owner"]
                .as_str()
                .ok_or("REGISTRATION_OWNER_INVALID")?,
            existing_slugs: &existing_slugs,
            namespace_key_sources: request["namespace_key_sources"]
                .as_array()
                .ok_or("NAME_KEY_LIST_SOURCE_REQUIRED")?,
            normalized_mass,
            fee_rate_sompi_per_gram: fee_quote["fee_rate_sompi_per_gram"]
                .as_u64()
                .ok_or("REGISTRATION_FEE_INPUT_INVALID")?,
        });
    let plan = plan_result.map_err(|error| -> Error {
        if error == "NAME_KEY_LIST_INCOMPLETE_OR_STALE" {
            crate::registered_keys::stale_key_list_error().into()
        } else {
            error.into()
        }
    })?;
    let bundle = registry_state_bundle_with_transports(request, first, second)?;
    let states = bundle["states"]
        .as_array()
        .ok_or("TN10_REGISTRY_STATES_REQUIRED")?;
    let has_role = |role: &str| states.iter().any(|state| state["role"] == role);
    if !has_role("gap") || !has_role("deed") {
        return Err("TN10_REGISTRY_GAP_AND_DEED_REQUIRED".into());
    }
    for state in states {
        let role = state["role"]
            .as_str()
            .ok_or("TN10_REGISTRY_STATE_ROLE_REQUIRED")?;
        let minimum = if role == "gap" {
            plan["adapter_gap_floor_sompi"].as_u64()
        } else {
            plan["deed_state_bond_sompi"].as_u64()
        }
        .ok_or("REGISTRY_ECONOMICS_INVALID")?;
        let utxos = state["utxos"]
            .as_array()
            .ok_or("TN10_REGISTRY_STATE_MISSING")?;
        if utxos.len() != 1
            || utxos[0]["amount"]
                .as_u64()
                .is_none_or(|amount| amount < minimum)
        {
            return Err(if role == "gap" {
                "TN10_REGISTRY_GAP_VALUE_BELOW_FLOOR"
            } else {
                "TN10_REGISTRY_DEED_UTXO_VALUE_BELOW_MINIMUM"
            }
            .into());
        }
    }
    let mut result = json!({
        "schema":"KTAPEOUT-TN10-NAME-REGISTER-PLAN-V1",
        "status":"DUAL_RPC_READ_ONLY_PLAN",
        "network":request["network"],
        "plan":plan,
        "fee_quote":fee_quote,
        "verified_state_bundle":bundle,
        "name_absence_claim":"NOT_ESTABLISHED_BY_THIS_COST_PLAN",
        "signing_allowed":false,
        "broadcast":false
    });
    result["plan"]["fee_source"] = json!("live_dual_node_quote");
    result["fee_is_estimate"] = json!(false);
    result["fee_quote_source"] = fee_quote["source"].clone();
    result["network_fee_sompi"] = plan["network_fee_sompi"].clone();
    result["network_fee_kas"] = plan["network_fee_kas"].clone();
    result["native_transaction_plan"] = native_transaction_plan;
    result["native_transaction_funding_claims_verified"] = json!(false);
    result["status"] = json!("DUAL_RPC_UNSIGNED_NATIVE_PLAN");
    Ok(result)
}

/// Generate the mutable part of a child-registration request from a controller's complete local
/// slug inventory. The inventory is not chain authority: the derived adjacent Gap and parent
/// Deed must each resolve to exactly one identical, unspent UTXO on both configured nodes.
pub fn registry_request_with_names_and_transports(
    seed: &Value,
    names_file: &Value,
    first: &mut dyn Transport,
    second: &mut dyn Transport,
) -> Result<Value, Error> {
    let namespace = seed["namespace"].as_str().ok_or("NAMESPACE_REQUIRED")?;
    if names_file["schema"].as_str() != Some("KTAPEOUT-REGISTERED-NAMES-V1")
        || names_file["network"].as_str() != Some(NETWORK)
        || names_file["namespace"].as_str() != Some(namespace)
    {
        return Err("NAMESPACE_NAMES_FILE_INVALID".into());
    }
    let slugs = names_file["slugs"]
        .as_array()
        .ok_or("NAMESPACE_NAMES_FILE_INVALID")?
        .iter()
        .map(|slug| {
            slug.as_str()
                .map(str::to_owned)
                .ok_or("NAMESPACE_NAMES_FILE_INVALID")
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut keys = slugs
        .iter()
        .map(|slug| crate::registered_keys::child_name_key(namespace, slug))
        .collect::<Result<Vec<_>, _>>()?;
    keys.sort_unstable();
    if keys.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("NAME_KEY_DUPLICATE".into());
    }
    let target = crate::registered_keys::child_name_key(
        namespace,
        seed["slug"].as_str().ok_or("NAME_SLUG_REQUIRED")?,
    )?;
    if keys.iter().any(|key| key == &target) {
        return Err("NAME_ALREADY_REGISTERED".into());
    }
    let expected_gaps = crate::name_space::expected_gaps(&keys)?;
    let candidates = seed["gap_candidates"]
        .as_array()
        .filter(|items| !items.is_empty())
        .ok_or("TN10_REGISTRY_GAP_CANDIDATES_REQUIRED")?;
    let mut selected = Vec::new();
    for candidate in candidates {
        let gap = crate::name_space::Gap::from_json(&candidate["gap"])?;
        if !expected_gaps.contains(&gap) {
            continue;
        }
        if crate::name_space::key_is_absent(&target, std::slice::from_ref(&gap))? {
            selected.push((candidate, gap));
        }
    }
    if selected.len() != 1 {
        return Err("NAME_KEY_LIST_INCOMPLETE_OR_STALE".into());
    }
    let candidate = selected[0].0;
    let gap_script = candidate["script_public_key"]
        .as_str()
        .filter(|script| !script.is_empty())
        .ok_or("TN10_SCRIPT_REQUIRED")?;
    let deed_states = seed["states"]
        .as_array()
        .ok_or("TN10_REGISTRY_STATES_REQUIRED")?
        .iter()
        .filter(|state| state["role"] == "deed")
        .collect::<Vec<_>>();
    if deed_states.len() != 1 {
        return Err("TN10_REGISTRY_DEED_REQUIRED".into());
    }
    let deed_script = deed_states[0]["script_public_key"]
        .as_str()
        .ok_or("TN10_SCRIPT_REQUIRED")?;
    let mut request = seed.clone();
    request["existing_slugs"] = json!(slugs);
    request["states"] = json!([
        {"role":"gap","script_public_key":gap_script},
        {"role":"deed","script_public_key":deed_script}
    ]);
    let verified = registry_state_bundle_with_transports(&request, first, second).map_err(|error| {
        if error.to_string().contains("TN10_REGISTRY_STATE_MISSING:gap") {
            "NAME_KEY_LIST_INCOMPLETE_OR_STALE: complete the local --names-file inventory and retry"
                .into()
        } else {
            error
        }
    })?;
    let states = verified["states"]
        .as_array()
        .ok_or("TN10_REGISTRY_STATES_REQUIRED")?;
    for state in states {
        if state["utxos"]
            .as_array()
            .is_none_or(|utxos| utxos.len() != 1)
        {
            return Err("NAME_KEY_LIST_INCOMPLETE_OR_STALE".into());
        }
    }
    let fee_input = {
        let tx_inputs = request["native_transaction_input"]["inputs"]
            .as_array_mut()
            .ok_or("TN10_REGISTRATION_INPUTS_REQUIRED")?;
        if tx_inputs.len() != 3 {
            return Err("TN10_REGISTRATION_INPUTS_REQUIRED".into());
        }
        for state in states {
            let target_index = match state["role"].as_str() {
                Some("deed") => 0,
                Some("gap") => 1,
                _ => return Err("TN10_REGISTRY_STATE_ROLE_INVALID".into()),
            };
            let utxo = &state["utxos"][0];
            tx_inputs[target_index]["outpoint"] = utxo["outpoint"].clone();
            tx_inputs[target_index]["amount"] = utxo["amount"].clone();
            tx_inputs[target_index]["block_daa_score"] = utxo["block_daa_score"].clone();
            tx_inputs[target_index]["script_public_key"] = utxo["script_public_key"].clone();
        }
        tx_inputs[2].clone()
    };
    let previous_fee_amount = fee_input["amount"]
        .as_u64()
        .ok_or("TN10_REGISTRATION_FEE_AMOUNT_REQUIRED")?;
    let live_fee_utxo = registry_fee_input_with_transports(&fee_input, first, second)?;
    let live_fee_amount = live_fee_utxo["amount"]
        .as_u64()
        .ok_or("TN10_REGISTRATION_FEE_INPUT_MISSING")?;
    let fee_change = request["native_transaction_input"]["outputs"]
        .as_array_mut()
        .and_then(|outputs| {
            let matches = outputs
                .iter_mut()
                .filter(|output| output["role"] == "fee_change")
                .collect::<Vec<_>>();
            (matches.len() == 1).then(|| matches.into_iter().next().unwrap())
        })
        .ok_or("TN10_REGISTRATION_FEE_CHANGE_REQUIRED")?;
    let old_change = fee_change["value"]
        .as_u64()
        .ok_or("TN10_REGISTRATION_FEE_CHANGE_INVALID")?;
    let new_change = if live_fee_amount >= previous_fee_amount {
        old_change
            .checked_add(live_fee_amount - previous_fee_amount)
            .ok_or("TN10_REGISTRATION_FEE_CHANGE_INVALID")?
    } else {
        old_change
            .checked_sub(previous_fee_amount - live_fee_amount)
            .filter(|amount| *amount > 0)
            .ok_or("TN10_REGISTRATION_FEE_CHANGE_INVALID")?
    };
    fee_change["value"] = json!(new_change);
    let tx_inputs = request["native_transaction_input"]["inputs"]
        .as_array_mut()
        .ok_or("TN10_REGISTRATION_INPUTS_REQUIRED")?;
    tx_inputs[2]["amount"] = live_fee_utxo["amount"].clone();
    tx_inputs[2]["block_daa_score"] = live_fee_utxo["block_daa_score"].clone();
    tx_inputs[2]["script_public_key"] = live_fee_utxo["script_public_key"].clone();
    attach_measured_registration_compute_budgets(&mut request["native_transaction_input"])?;
    Ok(json!({
        "schema":"KTAPEOUT-TN10-REGISTER-REQUEST-V1",
        "request":request,
        "derived_gap":selected[0].1.to_json(),
        "verified_state_bundle":verified,
        "signing_allowed":false,
        "broadcast":false
    }))
}

/// Compare read-only fee estimates from both configured TN10 endpoints.
/// The higher rate is charged into the unsigned estimate; a greater-than-2x spread fails closed.
pub fn dual_fee_quote_with_transports(
    request: &Value,
    first: &mut dyn Transport,
    second: &mut dyn Transport,
) -> Result<Value, Error> {
    let endpoints = verification_endpoints(request)?;
    let first_estimate = first
        .read_fee_estimate()
        .map_err(|_| "TN10_FEE_ESTIMATE_READ_FAILED")?;
    let second_estimate = second
        .read_fee_estimate()
        .map_err(|_| "TN10_FEE_ESTIMATE_READ_FAILED")?;
    let first_rate =
        parse_tn10_priority_fee_rate(&first_estimate).map_err(|_| "TN10_FEE_ESTIMATE_INVALID")?;
    let second_rate =
        parse_tn10_priority_fee_rate(&second_estimate).map_err(|_| "TN10_FEE_ESTIMATE_INVALID")?;
    let low = first_rate.min(second_rate);
    let high = first_rate.max(second_rate);
    if high > low * 2.0 {
        return Err("TN10_FEE_NODES_DISAGREE".into());
    }
    let fee_rate = high.ceil();
    if !fee_rate.is_finite() || fee_rate > u64::MAX as f64 {
        return Err("TN10_FEE_RATE_OUT_OF_RANGE".into());
    }
    Ok(json!({
        "source":"live_dual_node_quote",
        "fee_rate_sompi_per_gram":fee_rate as u64,
        "node_rates":[
            {"endpoint":endpoints[0],"feerate":first_rate},
            {"endpoint":endpoints[1],"feerate":second_rate}
        ],
        "endpoints":endpoints,
        "observed_at":chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
    }))
}

#[cfg(feature = "tn10-network")]
pub fn namespace_transition_fee_quote(nodes: &[String]) -> Result<Value, Error> {
    let request = json!({"network":NETWORK,"nodes":nodes});
    let endpoints = verification_endpoints(&request)?;
    let mut first = WrpcTransport::connect(&endpoints[0])?;
    let mut second = WrpcTransport::connect(&endpoints[1])?;
    dual_fee_quote_with_transports(&request, &mut first, &mut second)
}

fn parse_tn10_priority_fee_rate(value: &Value) -> Result<f64, String> {
    if let Ok(rate) = crate::release_execute::parse_priority_fee_rate(value) {
        return Ok(rate);
    }
    value["priorityBucket"]["feerate"]
        .as_f64()
        .filter(|rate| rate.is_finite() && *rate >= 0.0)
        .ok_or_else(|| "TN10_FEE_ESTIMATE_MISSING".to_owned())
}

/// Read-only public funding view. Never selects, reserves or spends an input.
pub fn utxos_with_transports(
    request: &Value,
    first: &mut dyn Transport,
    second: &mut dyn Transport,
) -> Result<Value, Error> {
    let endpoints = verification_endpoints(request)?;
    let address = request["address"].as_str().ok_or("TN10_ADDRESS_REQUIRED")?;
    if !address.starts_with("kaspatest:") {
        return Err("TN10_ADDRESS_REQUIRED".into());
    }
    let parsed: kaspa_rpc_core::RpcAddress = address.try_into()?;
    let observations = [checked_observation(first)?, checked_observation(second)?];
    if observations.iter().any(|node| node["utxo_indexed"] != true) {
        return Err("TN10_UTXO_INDEX_REQUIRED".into());
    }
    let a = canonical_utxos(first.read_utxos(address)?, &parsed)?;
    let b = canonical_utxos(second.read_utxos(address)?, &parsed)?;
    if a != b {
        return Err("TN10_UTXO_NODES_DISAGREE".into());
    }
    let mut funding = Vec::new();
    let mut excluded = Vec::new();
    for mut item in a
        .as_array()
        .ok_or("TN10_UTXO_VIEW_INVALID")?
        .iter()
        .cloned()
    {
        let supported = parse_utxo(&item).is_ok_and(|(_, utxo)| {
            let script = utxo.script_public_key.script();
            item["is_coinbase"] == false
                && utxo.amount > 0
                && script.len() == 34
                && script[0] == 0x20
                && script[33] == 0xac
                && script[1..33] == parsed.payload[..]
        });
        item.as_object_mut()
            .ok_or("TN10_UTXO_VIEW_INVALID")?
            .remove("is_coinbase");
        if supported {
            funding.push(item);
        } else {
            excluded
                .push(json!({"outpoint":item["outpoint"], "reason":"UNSUPPORTED_FUNDING_INPUT"}));
        }
    }
    Ok(
        json!({"schema":"KTAPEOUT-TN10-UTXO-VIEW-V1", "status":"UTXO_VIEW_MATCH",
        "network":NETWORK, "address":address, "nodes":endpoints,
        "observations":observations, "funding_utxos":funding, "excluded":excluded,
        "endpoints_from_evidence":request["endpoints_from_evidence"].as_bool().unwrap_or(true),
        "broadcast":false, "operator_independence_verified":false}),
    )
}

fn locate_on_node(
    transport: &mut dyn Transport,
    start: &str,
    txid: &str,
    pages: u64,
) -> Result<std::collections::BTreeSet<String>, Error> {
    checked_observation(transport)?;
    let mut cursor = start.to_owned();
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..pages {
        if !seen.insert(cursor.clone()) {
            return Err("TN10_SCAN_CURSOR_STALLED".into());
        }
        let page = transport.read_blocks_after(&cursor)?;
        if page.blocks.len() > 2048 || page.block_hashes.len() > 2048 {
            return Err("TN10_SCAN_PAGE_TOO_LARGE".into());
        }
        let mut matches = std::collections::BTreeSet::new();
        for block in page.blocks {
            if block.transactions.len() > 16_384 {
                return Err("TN10_SCAN_BLOCK_TOO_LARGE".into());
            }
            for transaction in &block.transactions {
                if Transaction::try_from(transaction.clone())?.id().to_string() == txid {
                    let hash = block.header.hash.to_string();
                    crate::tn10_block_proof::verify_block_inclusion(NETWORK, &hash, txid, &block)?;
                    matches.insert(hash);
                    break;
                }
            }
        }
        if !matches.is_empty() {
            return Ok(matches);
        }
        let next = page.block_hashes.last().map(ToString::to_string);
        if next.as_deref().is_none_or(|hash| seen.contains(hash)) {
            let tip = checked_observation(transport)?;
            if tip["start_hash"].as_str() == Some(cursor.as_str()) {
                return Err("TN10_SCAN_AT_TIP".into());
            }
            return Err("TN10_SCAN_CURSOR_STALLED".into());
        }
        cursor = next.expect("checked above");
    }
    Err("TN10_LOCATOR_NOT_FOUND_SUBMISSION_UNKNOWN".into())
}

/// Locate the containing block; this is not a chain-acceptance verdict or permission to retry.
pub fn locate_with_transports(
    request: &Value,
    first: &mut dyn Transport,
    second: &mut dyn Transport,
) -> Result<Value, Error> {
    let pages = locate_page_budget(request)?;
    verification_endpoints(request)?;
    let starts = request["start_hashes"]
        .as_array()
        .filter(|v| v.len() == 2)
        .ok_or("TN10_TWO_SCAN_STARTS_REQUIRED")?;
    let starts = [canonical_hash(&starts[0])?, canonical_hash(&starts[1])?];
    let txid = canonical_hash(&request["txid"])?;
    let mut evidence = request.clone();
    evidence["block_hash"] = Value::String(starts[0].clone());
    verification_target(&evidence)?;
    minimum_confirmations(&evidence)?;
    let a = locate_on_node(first, &starts[0], &txid, pages)?;
    let b = locate_on_node(second, &starts[1], &txid, pages)?;
    let hash = a
        .intersection(&b)
        .next()
        .ok_or("TN10_LOCATOR_NODES_DISAGREE")?;
    evidence["block_hash"] = Value::String(hash.clone());
    evidence["status"] = json!("LOCATED_NOT_VERIFIED");
    evidence["broadcast"] = json!(false);
    Ok(evidence)
}

fn locate_page_budget(request: &Value) -> Result<u64, Error> {
    match request.get("max_pages") {
        None => Ok(4),
        Some(value) => value
            .as_u64()
            .filter(|v| (1..=16).contains(v))
            .ok_or_else(|| "TN10_SCAN_LIMIT_INVALID".into()),
    }
}

pub fn observe(input: &Path, output: &Path, locate: bool) -> Result<(), Error> {
    validate_input_output_paths(input, output)?;
    let request = read_json(input)?;
    if locate {
        locate_page_budget(&request)?;
    }
    replace_json_atomic(output, &json!({"status":"UNVERIFIED", "broadcast":false}))?;
    let endpoints_from_evidence = std::env::var_os("KTAPE_TN10_ENDPOINTS").is_none();
    let endpoints = verification_endpoints(&request)?;
    let mut request = request;
    request["endpoints_from_evidence"] = json!(endpoints_from_evidence);
    request["nodes"] = json!(endpoints);
    let mut first = WrpcTransport::connect(&endpoints[0])?;
    let mut second = WrpcTransport::connect(&endpoints[1])?;
    let result = if locate {
        locate_with_transports(&request, &mut first, &mut second)?
    } else {
        utxos_with_transports(&request, &mut first, &mut second)?
    };
    replace_json_atomic(output, &result)
}

/// Read the current UTXOs for one registry script from both configured TN10 nodes.
/// This is a read-only observation; the request's state is never treated as chain evidence.
pub fn registry_script_utxos(input: &Path, output: &Path) -> Result<(), Error> {
    validate_input_output_paths(input, output)?;
    let request = read_json(input)?;
    let script_public_key = request["script_public_key"]
        .as_str()
        .ok_or("TN10_SCRIPT_REQUIRED")?;
    registry_script_address(script_public_key)?;
    verification_endpoints(&request)?;
    replace_json_atomic(
        output,
        &json!({"status":"UNVERIFIED","network":NETWORK,"broadcast":false}),
    )?;
    let endpoints_from_evidence = std::env::var_os("KTAPE_TN10_ENDPOINTS").is_none();
    let endpoints = verification_endpoints(&request)?;
    let mut request = request;
    request["endpoints_from_evidence"] = json!(endpoints_from_evidence);
    request["nodes"] = json!(endpoints);
    let mut first = WrpcTransport::connect(&endpoints[0])?;
    let mut second = WrpcTransport::connect(&endpoints[1])?;
    let result = registry_script_utxos_with_transports(&request, &mut first, &mut second)?;
    replace_json_atomic(output, &result)
}

/// Build a keyless name-registration estimate after reading the current Gap and Deed UTXOs
/// from both configured TN10 nodes. The caller supplies public state scripts and key-list
/// documents; neither input is treated as authoritative chain evidence.
pub fn registry_register_plan(
    input: &Path,
    output: &Path,
    keys_files: &[PathBuf],
    keys_urls: &[String],
) -> Result<(), Error> {
    validate_input_output_paths(input, output)?;
    let mut request = normalize_registry_request(&read_json(input)?)?;
    if request.get("namespace_key_sources").is_none() {
        request["namespace_key_sources"] = json!([]);
    }
    let sources = request["namespace_key_sources"]
        .as_array_mut()
        .ok_or("NAME_KEY_LIST_SOURCE_REQUIRED")?;
    load_namespace_key_files(sources, keys_files, input, output)?;
    add_namespace_key_url_sources(
        &mut request,
        keys_urls,
        crate::registered_keys::fetch_key_list,
    )?;
    let endpoints_from_evidence = std::env::var_os("KTAPE_TN10_ENDPOINTS").is_none();
    let endpoints = verification_endpoints(&request)?;
    request["endpoints_from_evidence"] = json!(endpoints_from_evidence);
    request["nodes"] = json!(endpoints);
    replace_json_atomic(
        output,
        &json!({"status":"UNVERIFIED","network":NETWORK,"signing_allowed":false,"broadcast":false}),
    )?;
    let mut first = WrpcTransport::connect(&endpoints[0])?;
    let mut second = WrpcTransport::connect(&endpoints[1])?;
    let result = registry_register_plan_with_transports(&request, &mut first, &mut second)?;
    replace_json_atomic(output, &result)
}

/// Read-only command implementation for deriving a name-registration request from local names.
pub fn registry_request_from_names(
    intent_path: &Path,
    names_path: &Path,
    output: &Path,
) -> Result<(), Error> {
    validate_input_output_paths(intent_path, output)?;
    if names_path == intent_path || names_path == output {
        return Err("TN10_PATH_ALIAS_REJECTED".into());
    }
    let request = read_json(intent_path)?;
    let names = read_json(names_path)?;
    let endpoints_from_evidence = std::env::var_os("KTAPE_TN10_ENDPOINTS").is_none();
    let endpoints = verification_endpoints(&request)?;
    let mut request = request;
    request["nodes"] = json!(endpoints);
    let mut first = WrpcTransport::connect(&endpoints[0])?;
    let mut second = WrpcTransport::connect(&endpoints[1])?;
    let mut result =
        registry_request_with_names_and_transports(&request, &names, &mut first, &mut second)?;
    result["endpoints_from_evidence"] = json!(endpoints_from_evidence);
    replace_json_atomic(output, &result)
}

/// Load caller-supplied namespace-key discovery lists without treating them as authoritative.
/// The caller must pass the merged sources through dual-RPC verification before relying on them.
pub fn load_namespace_key_files(
    sources: &mut Vec<Value>,
    keys_files: &[PathBuf],
    input: &Path,
    output: &Path,
) -> Result<(), Error> {
    for path in keys_files {
        if path == input || path == output {
            return Err("TN10_PATH_ALIAS_REJECTED".into());
        }
        sources.push(read_json(path)?);
    }
    Ok(())
}

/// Add one optional untrusted HTTPS key-list source. This injectable boundary keeps CLI
/// integration tests offline while production uses the bounded, DNS-pinned HTTPS fetcher.
pub fn add_namespace_key_url_sources<F>(
    request: &mut Value,
    keys_urls: &[String],
    mut fetcher: F,
) -> Result<(), Error>
where
    F: FnMut(&str) -> Result<Value, &'static str>,
{
    if keys_urls.len() > 1 {
        return Err("NAME_KEY_URL_COUNT_EXCEEDED".into());
    }
    let sources = request["namespace_key_sources"]
        .as_array_mut()
        .ok_or("NAME_KEY_LIST_SOURCE_REQUIRED")?;
    for url in keys_urls {
        let source = fetcher(url).map_err(|error| -> Error {
            if error == "NAME_KEY_LIST_INCOMPLETE_OR_STALE" {
                crate::registered_keys::stale_key_list_error().into()
            } else {
                error.into()
            }
        })?;
        sources.push(source);
    }
    Ok(())
}
