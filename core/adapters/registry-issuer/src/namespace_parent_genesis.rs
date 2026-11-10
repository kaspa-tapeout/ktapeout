//! Public unsigned bootstrap plan for a developer-owned namespace parent and its initial Gap.
//! This plan is bound to an existing TN10 registry root and never signs or broadcasts.

use crate::native_partial_signing::{InputAuthority, NativeSigningPlan, SignaturePacket};
use kaspa_consensus_core::tx::Transaction;
use kaspa_rpc_core::RpcTransaction;
use kaspa_txscript::pay_to_script_hash_script;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use silverscript_lang::ast::Expr;
use silverscript_lang::compiler::{CompileOptions, compile_contract};

#[path = "bin/application_name_deed_compact_v1_compile.rs"]
#[allow(dead_code)]
mod child_source;
#[path = "bin/namespace_name_frame_codec.rs"]
#[allow(dead_code)]
mod name_frame;
#[path = "bin/namespace_registry_child_auth_probe_v2_source.rs"]
#[allow(dead_code)]
mod parent_source;

type Error = Box<dyn std::error::Error>;

const INPUT_SCHEMA: &str = "KTAPEOUT-REGISTRY-ADAPTER-NAMESPACE-GENESIS-INPUT-V1";
const OUTPUT_SCHEMA: &str = "KTAPEOUT-UNSIGNED-REGISTRY-ADAPTER-NAMESPACE-GENESIS-V1";
const BOND_SOMPI: u64 = 1_000_000_000;

fn hash_arg(value: &Value, field: &str) -> Result<Vec<u8>, Error> {
    let text = value
        .as_str()
        .ok_or_else(|| format!("{field} must be lowercase hex"))?;
    let bytes = hex::decode(text)?;
    if bytes.len() != 32 || hex::encode(&bytes) != text || bytes.iter().all(|byte| *byte == 0) {
        return Err(format!("{field} must be nonzero canonical lowercase 32-byte hex").into());
    }
    Ok(bytes)
}

pub fn build(value: &Value) -> Result<Value, Error> {
    let object = value
        .as_object()
        .ok_or("namespace genesis input must be an object")?;
    let fields = [
        "schema",
        "network",
        "authority_xonly",
        "namespace_hash",
        "namespace_frame",
        "authority_commitment",
        "resolver_policy_hash",
        "registry_root",
        "nonce",
        "funding_utxo",
        "funding_change_script_public_key",
        "fee_sompi",
        "parent_state_sompi",
        "gap_state_sompi",
        "compute_budget",
    ];
    if object.len() != fields.len() || fields.iter().any(|field| !object.contains_key(*field)) {
        return Err("namespace genesis input fields are not canonical".into());
    }
    if value["schema"] != INPUT_SCHEMA || value["network"] != "testnet-10" {
        return Err("only the versioned TN10 registry-adapter genesis input is supported".into());
    }

    let authority = hash_arg(&value["authority_xonly"], "authority_xonly")?;
    let namespace = hash_arg(&value["namespace_hash"], "namespace_hash")?;
    let frame = name_frame::frame(&value["namespace_frame"])?;
    if namespace != name_frame::namespace_hash(&frame) {
        return Err("namespace hash/frame mismatch".into());
    }
    let authority_commitment = hash_arg(&value["authority_commitment"], "authority_commitment")?;
    if hex::encode(Sha256::digest(&authority)) != value["authority_commitment"] {
        return Err("authority commitment must equal sha256(authority_xonly)".into());
    }
    let resolver = hash_arg(&value["resolver_policy_hash"], "resolver_policy_hash")?;
    let registry_root = hash_arg(&value["registry_root"], "registry_root")?;
    if value["nonce"].as_i64() != Some(0) {
        return Err("namespace parent genesis nonce must be zero".into());
    }

    let parent_args = vec![
        Expr::bytes(namespace.clone()),
        Expr::bytes(authority_commitment),
        Expr::bytes(resolver),
        Expr::bytes(registry_root),
        Expr::int(0),
    ];
    let parent_source = parent_source::source_registry_adapter_parent_v1();
    let parent = compile_contract(&parent_source, &parent_args, CompileOptions::default())?;
    let zero = vec![0u8; 32];
    let gap_args = vec![
        Expr::int(0),
        Expr::int(0),
        Expr::bytes(zero.clone()),
        Expr::bytes(zero.clone()),
        Expr::int(1),
        Expr::bytes(zero.clone()),
        Expr::bytes(zero.clone()),
        Expr::bytes(zero.clone()),
        Expr::bytes(zero.clone()),
        Expr::bytes(zero.clone()),
        Expr::int(0),
        Expr::bytes(namespace),
        Expr::bytes(parent.template_hash().to_vec()),
        Expr::int(parent.state_layout.start as i64),
        Expr::int(
            (parent.script.len() - parent.state_layout.start - parent.state_layout.len) as i64,
        ),
    ];
    let gap_source = child_source::source_registry_adapter_app_v1();
    let gap = compile_contract(
        &gap_source,
        &gap_args,
        CompileOptions {
            allow_experimental_u256_successor: true,
            ..Default::default()
        },
    )?;
    if parent.script.len() > 10_000 || gap.script.len() > 10_000 {
        return Err("namespace parent/Gap script exceeds the consensus size limit".into());
    }

    let parent_value = value["parent_state_sompi"]
        .as_u64()
        .filter(|amount| *amount >= BOND_SOMPI)
        .ok_or("namespace parent must hold at least the pinned 10 KAS bond")?;
    let gap_value = value["gap_state_sompi"]
        .as_u64()
        .filter(|amount| *amount >= child_source::REGISTRY_ADAPTER_GAP_FLOOR_SOMPI)
        .ok_or("initial application Gap is below its pinned floor")?;
    let change_script =
        crate::native_transaction_codec::decode_spk(&value["funding_change_script_public_key"])?;
    let current = json!({"fee_input_script_hash":hex::encode(Sha256::digest(crate::native_transaction_codec::script_bytes(&change_script)))});
    let funding_request = json!({
        "current":current,
        "funding_utxo":value["funding_utxo"],
        "funding_change_script_public_key":value["funding_change_script_public_key"],
        "fee_sompi":value["fee_sompi"],
        "state_sompi":parent_value,
        "compute_budget":value["compute_budget"],
    });
    let mut plan = crate::native_transaction_codec::genesis_group_plan_with_scripts(
        &funding_request,
        &[
            pay_to_script_hash_script(&parent.script),
            pay_to_script_hash_script(&gap.script),
        ],
        &[parent_value, gap_value],
    )?;
    plan["schema"] = json!(OUTPUT_SCHEMA);
    plan["adapter_id"] = json!("ktape.official.adapter.registry");
    plan["adapter_semver"] = json!("1.0.0");
    plan["network"] = json!("testnet-10");
    plan["namespace_hash"] = value["namespace_hash"].clone();
    plan["namespace_frame"] = value["namespace_frame"].clone();
    plan["registry_root"] = value["registry_root"].clone();
    plan["namespace_bond_sompi"] = json!(parent_value);
    plan["state_roles"] = json!(["namespace_parent", "initial_application_gap"]);
    plan["candidate_compile"] = json!({
        "parent_source_sha256":hex::encode(Sha256::digest(parent_source.as_bytes())),
        "parent_script_sha256":hex::encode(Sha256::digest(&parent.script)),
        "parent_script_bytes":parent.script.len(),
        "gap_source_sha256":hex::encode(Sha256::digest(gap_source.as_bytes())),
        "gap_script_sha256":hex::encode(Sha256::digest(&gap.script)),
        "gap_script_bytes":gap.script.len(),
        "status":"COMPILED_LOCAL_PLAN",
    });
    let (outpoint, entry) =
        crate::native_transaction_codec::parse_utxo(&value["funding_utxo"], false)?;
    let fee_script = entry.script_public_key.script();
    if entry.script_public_key.version() != 0
        || fee_script.len() != 34
        || fee_script[0] != 0x20
        || fee_script[33] != 0xac
    {
        return Err("namespace genesis requires a canonical P2PK fee input".into());
    }
    if plan["transaction"]["inputs"].as_array().map(Vec::len) != Some(1) {
        return Err("namespace genesis signing input context mismatch".into());
    }
    let rpc: RpcTransaction = serde_json::from_value(plan["transaction"].clone())?;
    let transaction = Transaction::try_from(rpc)?;
    if transaction.inputs[0].previous_outpoint != outpoint {
        return Err("namespace genesis signing input context mismatch".into());
    }
    let signer_public_key = hex::encode(&fee_script[1..33]);
    let signing = NativeSigningPlan::new(
        transaction,
        vec![entry],
        vec![InputAuthority {
            input_index: 0,
            signer_public_key,
        }],
    )?;
    plan["native_signing"] = signing.requests()?;
    plan["signing_allowed"] = json!(true);
    plan["broadcast"] = json!(false);
    Ok(plan)
}

/// Rebuild and assemble a developer-parent genesis from its original request and public packets.
/// The plan is recomputed before packet verification; this function never signs or broadcasts.
pub fn transition_command(mode: &str, value: &Value) -> Result<Value, Error> {
    let (request, packets) = if mode == "--transition-plan" {
        if value.as_object().is_none_or(|o| o.len() != 2)
            || value["action"] != "namespace_parent_genesis"
            || !value["request"].is_object()
        {
            return Err("unsupported namespace parent genesis action".into());
        }
        (&value["request"], Vec::new())
    } else {
        if !matches!(mode, "--verify-signatures" | "--merge-signatures")
            || value.as_object().is_none_or(|o| o.len() != 2)
            || value["plan"]["action"] != "namespace_parent_genesis"
            || !value["plan"]["request"].is_object()
        {
            return Err("invalid namespace parent genesis packet document".into());
        }
        (
            &value["plan"]["request"],
            serde_json::from_value::<Vec<SignaturePacket>>(value["packets"].clone())?,
        )
    };
    let prepared = build(request)?;
    let expected = prepared["native_signing"].clone();
    let rpc: RpcTransaction = serde_json::from_value(prepared["transaction"].clone())?;
    let transaction: Transaction = rpc.try_into()?;
    let (_, entry) = crate::native_transaction_codec::parse_utxo(&request["funding_utxo"], false)?;
    let signer_public_key = expected["requests"][0]["signer_public_key"]
        .as_str()
        .ok_or("native signing key missing")?;
    let plan = NativeSigningPlan::new(
        transaction,
        vec![entry],
        vec![InputAuthority {
            input_index: 0,
            signer_public_key: signer_public_key.to_owned(),
        }],
    )?;
    if plan.requests()? != expected {
        return Err("namespace parent genesis signing plan mismatch".into());
    }
    if mode == "--transition-plan" {
        return Ok(expected);
    }
    let merged = plan.merge(&packets)?;
    if merged.len() != 1 {
        return Err("namespace parent genesis signature set incomplete".into());
    }
    if mode == "--verify-signatures" {
        return Ok(
            json!({"verified":true,"broadcast":false,"native_plan_hash":plan.hash(),"verified_packet_count":1}),
        );
    }
    let signed = plan.finish(&packets, |signatures| {
        let signature = signatures
            .get(&InputAuthority {
                input_index: 0,
                signer_public_key: signer_public_key.to_owned(),
            })
            .ok_or("namespace parent genesis signature missing")?;
        let mut witness = Vec::with_capacity(signature.len() + 2);
        witness.push((signature.len() + 1) as u8);
        witness.extend_from_slice(signature);
        witness.push(1);
        Ok(vec![witness])
    })?;
    Ok(json!({
        "schema":"KTAPEOUT-TN10-NAMESPACE-PARENT-GENESIS-SIGNED-V1",
        "network":"testnet-10",
        "transition_plan":{"action":"namespace_parent_genesis","request":request},
        "signature_packets":packets,
        "native_plan_hash":signed["native_plan_hash"],
        "transaction":signed["transaction"],
        "txid":signed["txid"],
        "native_vm_verified":signed["native_vm_verified"],
        "broadcast":false
    }))
}
