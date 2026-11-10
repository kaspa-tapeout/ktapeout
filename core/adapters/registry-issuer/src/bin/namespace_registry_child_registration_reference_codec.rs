//! Reference-only unsigned body codec for namespace child registration.
//!
//! This entrypoint owns only deterministic Kaspa transaction-body construction
//! and input sighash calculation. It does not compile covenant state, sign,
//! broadcast, or assert Profile/L1 admission. The canonical child codec must
//! still bind this body to an admitted contract and live predecessor evidence.

use kaspa_consensus_core::Hash;
use kaspa_consensus_core::hashing::sighash::{
    SigHashReusedValuesUnsync, calc_schnorr_signature_hash,
};
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::tx::{
    CovenantBinding, MutableTransaction, Transaction, TransactionInput, TransactionOutput,
    UtxoEntry,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use ktapeout_050_adapter_workbench::{bounded_public_json, native_transaction_codec};
#[path = "namespace_child_registration_contract.rs"]
mod contract;

const INPUT_SCHEMA: &str = "KTAPEOUT-NAMESPACE-REGISTRY-CHILD-UNSIGNED-INPUT-V1";
/// `ktape.official.adapter.registry` 1.0.0 body inputs (V6 body layouts, adapter value rules).
const ADAPTER_REGISTRATION_INPUT: &str =
    "KTAPEOUT-REGISTRY-ADAPTER-APP-REGISTRATION-UNSIGNED-INPUT-V1";
const ADAPTER_SLOT_INPUT: &str = "KTAPEOUT-REGISTRY-ADAPTER-APP-SLOT-UNSIGNED-INPUT-V1";
const ADAPTER_OWNER_INPUT: &str = "KTAPEOUT-REGISTRY-ADAPTER-APP-OWNER-UNSIGNED-INPUT-V1";
/// Gap floor enforced by the adapter app script (`REGISTRY_ADAPTER_GAP_FLOOR_SOMPI`).
const ADAPTER_GAP_FLOOR_SOMPI: u64 = 100_000_000;

fn verify_inputs(
    mutable: &MutableTransaction<Transaction>,
    entries: Vec<UtxoEntry>,
) -> Result<(), Box<dyn std::error::Error>> {
    use kaspa_consensus_core::tx::{PopulatedTransaction, VerifiableTransaction};
    use kaspa_txscript::caches::Cache;
    use kaspa_txscript::covenants::CovenantsContext;
    use kaspa_txscript::{EngineCtx, EngineFlags, TxScriptEngine};
    let populated = PopulatedTransaction::new(&mutable.tx, entries);
    let context = CovenantsContext::from_tx(&populated)?;
    let cache = Cache::new(100_000);
    let reused = SigHashReusedValuesUnsync::new();
    for (index, input) in mutable.tx.inputs.iter().enumerate() {
        let mut engine = TxScriptEngine::from_transaction_input(
            &populated,
            input,
            index,
            populated.utxo(index).ok_or("missing VM UTXO")?,
            EngineCtx::new(&cache)
                .with_reused(&reused)
                .with_covenants_ctx(&context),
            EngineFlags {
                sigop_script_units: 0.into(),
            },
        );
        engine
            .execute()
            .map_err(|error| format!("input {index} Native VM verification failed: {error}"))?;
    }
    Ok(())
}

pub fn build_parent_transfer_plan(
    value: &Value,
    verify_vm: bool,
) -> Result<Value, Box<dyn std::error::Error>> {
    let named = value["schema"] == "KTAPEOUT-NAMESPACE-PARENT-TRANSFER-UNSIGNED-INPUT-V6";
    exact_object(
        value,
        &[
            "schema",
            "network",
            "parent_covenant_id",
            "parent_utxo",
            "fee_utxo",
            "input_signature_scripts",
            "state_input_script_public_key",
            "parent_successor_script_public_key",
            "fee_change_script_public_key",
            "compute_budget",
            "fee_sompi",
        ],
        "parent transfer request",
    )?;
    if (!named && value["schema"] != "KTAPEOUT-NAMESPACE-PARENT-TRANSFER-UNSIGNED-INPUT-V2")
        || value["network"] != "testnet-10"
    {
        return Err("versioned TN10 parent transfer input required".into());
    }
    let cid = hash32(&value["parent_covenant_id"], "parent_covenant_id")?;
    let (parent_point, parent_entry) =
        native_transaction_codec::parse_utxo(&value["parent_utxo"], true)?;
    let (fee_point, fee_entry) = native_transaction_codec::parse_utxo(&value["fee_utxo"], false)?;
    if parent_point == fee_point
        || parent_entry.covenant_id != Some(cid)
        || fee_entry.covenant_id.is_some()
    {
        return Err("distinct parent lineage and ordinary fee input required".into());
    }
    if native_transaction_codec::decode_spk(&value["state_input_script_public_key"])?
        != parent_entry.script_public_key
    {
        return Err("compiled parent does not match live predecessor".into());
    }
    let fee = value["fee_sompi"]
        .as_u64()
        .filter(|value| *value > 0)
        .ok_or("positive fee required")?;
    let change = fee_entry
        .amount
        .checked_sub(fee)
        .filter(|value| *value > 0)
        .ok_or("fee input must cover positive change")?;
    let budget = value["compute_budget"]
        .as_u64()
        .filter(|value| *value > 0 && *value <= u16::MAX as u64)
        .ok_or("positive u16 compute budget required")? as u16;
    let scripts = value["input_signature_scripts"]
        .as_array()
        .filter(|value| value.len() == 2)
        .ok_or("two witness scripts required")?;
    let decode = |value: &Value| -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let text = value.as_str().ok_or("witness must be hex")?;
        if text.len() > 32_768 {
            return Err("witness exceeds bound".into());
        }
        let bytes = hex::decode(text)?;
        if hex::encode(&bytes) != text {
            return Err("noncanonical witness hex".into());
        }
        Ok(bytes)
    };
    let tx = Transaction::new(
        1,
        vec![
            TransactionInput::new_with_compute_budget(
                parent_point,
                decode(&scripts[0])?,
                0,
                budget,
            ),
            TransactionInput::new_with_compute_budget(fee_point, decode(&scripts[1])?, 0, 10),
        ],
        vec![
            TransactionOutput {
                value: parent_entry.amount,
                script_public_key: native_transaction_codec::decode_spk(
                    &value["parent_successor_script_public_key"],
                )?,
                covenant: Some(CovenantBinding {
                    authorizing_input: 0,
                    covenant_id: cid,
                }),
            },
            TransactionOutput {
                value: change,
                script_public_key: native_transaction_codec::decode_spk(
                    &value["fee_change_script_public_key"],
                )?,
                covenant: None,
            },
        ],
        0,
        Default::default(),
        0,
        vec![],
    );
    let entries = vec![parent_entry, fee_entry];
    let mutable = MutableTransaction::with_entries(tx, entries.clone());
    let mass = native_transaction_codec::local_mass_projection(&mutable.tx, entries.clone())?;
    if verify_vm {
        verify_inputs(&mutable, entries)?;
    }
    let digests: Vec<String> = (0..2)
        .map(|index| {
            hex::encode(
                calc_schnorr_signature_hash(
                    &mutable.as_verifiable(),
                    index,
                    SIG_HASH_ALL,
                    &SigHashReusedValuesUnsync::new(),
                )
                .as_bytes(),
            )
        })
        .collect();
    let rpc: kaspa_rpc_core::RpcTransaction = (&mutable.tx).into();
    let mut body = json!({"schema":"KTAPEOUT-NAMESPACE-PARENT-TRANSFER-BODY-V2", "network":"testnet-10",
        "codec_id":"namespace-parent-authority-transfer-candidate-v2", "parent_covenant_id":cid.to_string(),
        "transaction":rpc, "input_sighash_all":digests, "input_roles":["parent_namespace_state","fee_input"],
        "output_roles":["parent_successor","fee_change"], "fee_sompi":fee, "mass_projection":mass,
        "native_vm_verified":verify_vm, "status":if verify_vm {"VM_VERIFIED_LOCAL_TRANSACTION"} else {"UNSIGNED_LOCAL_REFERENCE"},
        "signing_allowed":false, "broadcast":false, "admission":"ENGINEERING_CANDIDATE_ONLY"});
    if named {
        body["schema"] = json!("KTAPEOUT-NAMESPACE-PARENT-TRANSFER-BODY-V6");
        body["codec_id"] = json!("namespace-parent-authority-transfer-candidate-v6");
        body["contract"] = contract::named_metadata();
    }
    let domain = if named {
        b"KTAPEOUT/0.5.0/PARENT_AUTHORITY_TRANSFER/CANDIDATE/V6\0".as_slice()
    } else {
        b"KTAPEOUT/0.5.0/PARENT_AUTHORITY_TRANSFER/CANDIDATE/V2\0".as_slice()
    };
    let digest = Sha256::digest([domain, serde_json::to_string(&body)?.as_bytes()].concat());
    Ok(json!({"plan_hash":hex::encode(digest), "body":body}))
}

pub fn build_owner_operation_plan(
    value: &Value,
    verify_vm: bool,
) -> Result<Value, Box<dyn std::error::Error>> {
    let adapter = value["schema"] == ADAPTER_OWNER_INPUT;
    let named = adapter || value["schema"] == "KTAPEOUT-NAMESPACE-CHILD-OWNER-UNSIGNED-INPUT-V6";
    let v5 = named || value["schema"] == "KTAPEOUT-NAMESPACE-CHILD-OWNER-UNSIGNED-INPUT-V5";
    let v4 = v5 || value["schema"] == "KTAPEOUT-NAMESPACE-CHILD-OWNER-UNSIGNED-INPUT-V4";
    exact_object(
        value,
        &[
            "schema",
            "network",
            "child_utxo",
            "fee_utxo",
            "witness",
            "fee_change_script_public_key",
            "compute_budget",
            "fee_sompi",
        ],
        "owner operation request",
    )?;
    if (!v4 && value["schema"] != "KTAPEOUT-NAMESPACE-CHILD-OWNER-UNSIGNED-INPUT-V3")
        || value["network"] != "testnet-10"
    {
        return Err("versioned TN10 owner codec input required".into());
    }
    let witness = &value["witness"];
    let witness_schema = if adapter {
        "KTAPEOUT-REGISTRY-ADAPTER-APP-OWNER-WITNESS-V1"
    } else if named {
        "KTAPEOUT-NAMESPACE-CHILD-OWNER-WITNESS-V6"
    } else if v5 {
        "KTAPEOUT-NAMESPACE-CHILD-OWNER-WITNESS-V5"
    } else if v4 {
        "KTAPEOUT-NAMESPACE-CHILD-OWNER-WITNESS-V4"
    } else {
        "KTAPEOUT-NAMESPACE-CHILD-OWNER-WITNESS-V3"
    };
    if witness["schema"] != witness_schema
        || witness["network"] != "testnet-10"
        || witness["signing_allowed"] != false
        || witness["broadcast"] != false
    {
        return Err("local-only public owner witness required".into());
    }
    let release = v4 && witness["operation"] == "RELEASE_NAME";
    let exit = match witness["operation"].as_str() {
        Some("OWNER_EXIT") if !v4 => true,
        Some("RELEASE_NAME") if v4 => true,
        Some("CHANGE_OWNER_TARGET") => false,
        _ => return Err("unsupported owner operation".into()),
    };
    if value["fee_change_script_public_key"] != value["fee_utxo"]["script_public_key"] {
        return Err("owner operation fee change must return to fee payer".into());
    }
    // Reuse the exact two-input/value-preserving Native transaction primitive.
    // Only role/schema/domain change; signatures and VM still bind all inputs.
    let request = json!({"schema":"KTAPEOUT-NAMESPACE-PARENT-TRANSFER-UNSIGNED-INPUT-V2","network":"testnet-10",
        "parent_covenant_id":witness["parent_covenant_id"],"parent_utxo":value["child_utxo"],"fee_utxo":value["fee_utxo"],
        "input_signature_scripts":witness["input_signature_scripts"],"state_input_script_public_key":witness["state_input_script_public_key"],
        "parent_successor_script_public_key":witness["state_successor_script_public_key"],"fee_change_script_public_key":value["fee_change_script_public_key"],
        "compute_budget":value["compute_budget"],"fee_sompi":value["fee_sompi"]});
    let mut plan = build_parent_transfer_plan(&request, verify_vm && !release)?;
    if release {
        let rpc: kaspa_rpc_core::RpcTransaction =
            serde_json::from_value(plan["body"]["transaction"].clone())?;
        let mut tx: Transaction = rpc.try_into()?;
        let (_, child) = native_transaction_codec::parse_utxo(&value["child_utxo"], true)?;
        let (_, fee) = native_transaction_codec::parse_utxo(&value["fee_utxo"], false)?;
        // V6 funds the released Gap from the bond; the adapter refunds the whole bond and
        // the fee payer funds the released Gap floor.
        let refund = if adapter {
            child.amount
        } else {
            child
                .amount
                .checked_sub(100_000_000)
                .filter(|n| *n > 0)
                .ok_or("child value must fund Gap and refund")?
        };
        tx.outputs[0].value = 100_000_000;
        tx.outputs.insert(
            1,
            TransactionOutput {
                value: refund,
                script_public_key: native_transaction_codec::decode_spk(
                    &witness["refund_script_public_key"],
                )?,
                covenant: None,
            },
        );
        if adapter {
            let change = tx.outputs[2]
                .value
                .checked_sub(ADAPTER_GAP_FLOOR_SOMPI)
                .filter(|n| *n > 0)
                .ok_or("fee input must fund the released Gap floor, fee and change")?;
            tx.outputs[2].value = change;
        }
        let entries = vec![child, fee];
        let mutable = MutableTransaction::with_entries(tx, entries.clone());
        let mass = native_transaction_codec::local_mass_projection(&mutable.tx, entries.clone())?;
        if verify_vm {
            verify_inputs(&mutable, entries)?;
        }
        let digests: Vec<String> = (0..2)
            .map(|i| {
                hex::encode(
                    calc_schnorr_signature_hash(
                        &mutable.as_verifiable(),
                        i,
                        SIG_HASH_ALL,
                        &SigHashReusedValuesUnsync::new(),
                    )
                    .as_bytes(),
                )
            })
            .collect();
        let rpc: kaspa_rpc_core::RpcTransaction = (&mutable.tx).into();
        plan["body"]["transaction"] = json!(rpc);
        plan["body"]["input_sighash_all"] = json!(digests);
        plan["body"]["mass_projection"] = mass;
        plan["body"]["native_vm_verified"] = json!(verify_vm);
        plan["body"]["status"] = json!(if verify_vm {
            "VM_VERIFIED_LOCAL_TRANSACTION"
        } else {
            "UNSIGNED_LOCAL_REFERENCE"
        });
    }
    let body = plan["body"]
        .as_object_mut()
        .ok_or("owner body object required")?;
    body.insert(
        "schema".into(),
        json!(if v5 {
            "KTAPEOUT-NAMESPACE-CHILD-OWNER-BODY-V5"
        } else if v4 {
            "KTAPEOUT-NAMESPACE-CHILD-OWNER-BODY-V4"
        } else {
            "KTAPEOUT-NAMESPACE-CHILD-OWNER-BODY-V3"
        }),
    );
    body.insert(
        "codec_id".into(),
        json!(if v5 {
            "namespace-child-owner-candidate-v5"
        } else if v4 {
            "namespace-child-owner-candidate-v4"
        } else {
            "namespace-child-owner-candidate-v3"
        }),
    );
    body.insert("operation".into(), witness["operation"].clone());
    if v5 {
        body.insert("contract".into(), contract::recovery_metadata());
    }
    if named {
        body.insert("contract".into(), contract::named_metadata());
        body.insert(
            "schema".into(),
            json!("KTAPEOUT-NAMESPACE-CHILD-OWNER-BODY-V6"),
        );
        body.insert(
            "codec_id".into(),
            json!("namespace-child-owner-candidate-v6"),
        );
    }
    if adapter {
        body.insert(
            "schema".into(),
            json!("KTAPEOUT-REGISTRY-ADAPTER-APP-OWNER-BODY-V1"),
        );
        body.insert(
            "adapter_id".into(),
            json!("ktape.official.adapter.registry"),
        );
        body.insert("adapter_semver".into(), json!("1.0.0"));
    }
    body.insert("input_roles".into(), json!(["child_deed", "fee_input"]));
    body.insert(
        "output_roles".into(),
        if release {
            json!(["released_gap", "owner_refund", "fee_change"])
        } else {
            json!([
                if exit {
                    "owner_refund"
                } else {
                    "deed_successor"
                },
                "fee_change"
            ])
        },
    );
    body.insert("l1_evidence".into(), json!(false));
    let domain = if named {
        b"KTAPEOUT/0.5.0/CHILD_OWNER/CANDIDATE/V6\0".as_slice()
    } else if v5 {
        b"KTAPEOUT/0.5.0/CHILD_OWNER/CANDIDATE/V5\0".as_slice()
    } else if v4 {
        b"KTAPEOUT/0.5.0/CHILD_OWNER/CANDIDATE/V4\0".as_slice()
    } else {
        b"KTAPEOUT/0.5.0/CHILD_OWNER/CANDIDATE/V3\0".as_slice()
    };
    let digest =
        Sha256::digest([domain, serde_json::to_string(&plan["body"])?.as_bytes()].concat());
    plan["plan_hash"] = json!(hex::encode(digest));
    Ok(plan)
}

pub fn build_recovery_plan(
    value: &Value,
    verify_vm: bool,
) -> Result<Value, Box<dyn std::error::Error>> {
    let named = value["schema"] == "KTAPEOUT-NAMESPACE-RECOVERY-UNSIGNED-INPUT-V6";
    exact_object(
        value,
        &[
            "schema",
            "network",
            "first_utxo",
            "second_utxo",
            "fee_utxo",
            "witness",
            "fee_change_script_public_key",
            "compute_budget",
            "fee_sompi",
        ],
        "recovery input",
    )?;
    if (!named && value["schema"] != "KTAPEOUT-NAMESPACE-RECOVERY-UNSIGNED-INPUT-V5")
        || value["network"] != "testnet-10"
    {
        return Err("versioned TN10 recovery body input required".into());
    }
    let w = &value["witness"];
    if w["schema"]
        != if named {
            "KTAPEOUT-NAMESPACE-RECOVERY-WITNESS-V6"
        } else {
            "KTAPEOUT-NAMESPACE-RECOVERY-WITNESS-V5"
        }
        || w["network"] != "testnet-10"
        || w["broadcast"] != false
        || w["signing_allowed"] != false
    {
        return Err("local recovery witness required".into());
    }
    let close = match w["operation"].as_str() {
        Some("MERGE_GAPS") => false,
        Some("CLOSE_NAMESPACE") => true,
        _ => return Err("unsupported recovery operation".into()),
    };
    let cid = hash32(&w["parent_covenant_id"], "parent_covenant_id")?;
    let (a, first) = native_transaction_codec::parse_utxo(&value["first_utxo"], true)?;
    let (b, second) = native_transaction_codec::parse_utxo(&value["second_utxo"], true)?;
    let (c, fee) = native_transaction_codec::parse_utxo(&value["fee_utxo"], false)?;
    if a == b
        || a == c
        || b == c
        || first.covenant_id != Some(cid)
        || second.covenant_id != Some(cid)
        || fee.covenant_id.is_some()
    {
        return Err("distinct matched lineage inputs and ordinary fee required".into());
    }
    let spks = w["state_input_script_public_keys"]
        .as_array()
        .filter(|a| a.len() == 2)
        .ok_or("two state input scripts required")?;
    if native_transaction_codec::decode_spk(&spks[0])? != first.script_public_key
        || native_transaction_codec::decode_spk(&spks[1])? != second.script_public_key
    {
        return Err("compiled recovery state does not match predecessors".into());
    }
    if value["fee_change_script_public_key"] != value["fee_utxo"]["script_public_key"] {
        return Err("fee change must return to fee payer".into());
    }
    let fee_sompi = value["fee_sompi"]
        .as_u64()
        .filter(|n| *n > 0)
        .ok_or("positive fee required")?;
    let change = fee
        .amount
        .checked_sub(fee_sompi)
        .filter(|n| *n > 0)
        .ok_or("fee input must cover positive change")?;
    let amount = first
        .amount
        .checked_add(second.amount)
        .ok_or("recovery value overflow")?;
    let budget = value["compute_budget"]
        .as_u64()
        .filter(|n| *n > 0 && *n <= u16::MAX as u64)
        .ok_or("positive u16 budget required")? as u16;
    let raw = w["input_signature_scripts"]
        .as_array()
        .filter(|a| a.len() == 3)
        .ok_or("three signature scripts required")?;
    let scripts: Vec<Vec<u8>> = raw
        .iter()
        .map(|v| -> Result<Vec<u8>, Box<dyn std::error::Error>> {
            let text = v.as_str().ok_or("hex witness required")?;
            if text.len() > 32768 {
                return Err("witness exceeds bound".into());
            }
            let bytes = hex::decode(text)?;
            if hex::encode(&bytes) != text {
                return Err("canonical witness required".into());
            }
            Ok(bytes)
        })
        .collect::<Result<_, _>>()?;
    let tx = Transaction::new(
        1,
        vec![
            TransactionInput::new_with_compute_budget(a, scripts[0].clone(), 0, budget),
            TransactionInput::new_with_compute_budget(b, scripts[1].clone(), 0, budget),
            TransactionInput::new_with_compute_budget(c, scripts[2].clone(), 0, 10),
        ],
        vec![
            TransactionOutput {
                value: amount,
                script_public_key: native_transaction_codec::decode_spk(
                    &w["state_successor_script_public_key"],
                )?,
                covenant: Some(CovenantBinding {
                    authorizing_input: 0,
                    covenant_id: cid,
                }),
            },
            TransactionOutput {
                value: change,
                script_public_key: fee.script_public_key.clone(),
                covenant: None,
            },
        ],
        0,
        Default::default(),
        0,
        vec![],
    );
    let entries = vec![first, second, fee];
    let mutable = MutableTransaction::with_entries(tx, entries.clone());
    let mass = native_transaction_codec::local_mass_projection(&mutable.tx, entries.clone())?;
    if verify_vm {
        verify_inputs(&mutable, entries)?;
    }
    let digests: Vec<String> = (0..3)
        .map(|i| {
            hex::encode(
                calc_schnorr_signature_hash(
                    &mutable.as_verifiable(),
                    i,
                    SIG_HASH_ALL,
                    &SigHashReusedValuesUnsync::new(),
                )
                .as_bytes(),
            )
        })
        .collect();
    let rpc: kaspa_rpc_core::RpcTransaction = (&mutable.tx).into();
    let body = json!({"schema":if named {"KTAPEOUT-NAMESPACE-RECOVERY-BODY-V6"}else{"KTAPEOUT-NAMESPACE-RECOVERY-BODY-V5"},"contract":if named {contract::named_metadata()}else{contract::recovery_metadata()},"network":"testnet-10","operation":w["operation"],"parent_covenant_id":cid.to_string(),"transaction":rpc,"input_sighash_all":digests,"input_roles":if close {vec!["namespace_parent","full_gap","fee_input"]}else{vec!["left_gap","right_gap","fee_input"]},"output_roles":[if close {"namespace_refund"}else{"merged_gap"},"fee_change"],"fee_sompi":fee_sompi,"mass_projection":mass,"native_vm_verified":verify_vm,"status":if verify_vm {"VM_VERIFIED_LOCAL_TRANSACTION"}else{"UNSIGNED_LOCAL_REFERENCE"},"broadcast":false,"signing_allowed":false,"l1_evidence":false});
    let domain = if named {
        b"KTAPEOUT/0.5.0/NAMESPACE_RECOVERY/CANDIDATE/V6\0".as_slice()
    } else {
        b"KTAPEOUT/0.5.0/NAMESPACE_RECOVERY/CANDIDATE/V5\0".as_slice()
    };
    let digest = Sha256::digest([domain, serde_json::to_string(&body)?.as_bytes()].concat());
    Ok(json!({"plan_hash":hex::encode(digest),"body":body}))
}

// Wallet recovery, not a namespace covenant transition: preserve the refund
// owner SPK and let its real Schnorr signature authorize an ordinary successor.
fn build_refund_spend(value: &Value, verify_vm: bool) -> Result<Value, Box<dyn std::error::Error>> {
    exact_object(
        value,
        &[
            "schema",
            "network",
            "refund_utxo",
            "signature_script",
            "fee_sompi",
        ],
        "refund spend",
    )?;
    if value["schema"] != "KTAPEOUT-NAMESPACE-REFUND-SPEND-INPUT-V1"
        || value["network"] != "testnet-10"
    {
        return Err("explicit TN10 refund spend required".into());
    }
    let (point, entry) = native_transaction_codec::parse_utxo(&value["refund_utxo"], true)?;
    let script = entry.script_public_key.script();
    if script.len() != 34
        || script[0] != 0x20
        || script[33] != 0xac
        || entry.script_public_key.version() != 0
    {
        return Err("wallet P2PK refund required".into());
    }
    secp256k1::XOnlyPublicKey::from_slice(&script[1..33])?;
    let text = value["signature_script"]
        .as_str()
        .ok_or("public signature script required")?;
    let signature = hex::decode(text)?;
    if hex::encode(&signature) != text || signature.len() > 66 {
        return Err("bounded canonical P2PK signature required".into());
    }
    let fee = value["fee_sompi"]
        .as_u64()
        .filter(|n| *n > 0)
        .ok_or("positive refund fee required")?;
    let amount = entry
        .amount
        .checked_sub(fee)
        .filter(|n| *n > 0)
        .ok_or("refund fee exceeds value")?;
    let tx = Transaction::new(
        1,
        vec![TransactionInput::new_with_compute_budget(
            point, signature, 0, 10,
        )],
        vec![TransactionOutput {
            value: amount,
            script_public_key: entry.script_public_key.clone(),
            covenant: None,
        }],
        0,
        Default::default(),
        0,
        vec![],
    );
    let mutable = MutableTransaction::with_entries(tx, vec![entry.clone()]);
    if verify_vm {
        verify_inputs(&mutable, vec![entry.clone()])?;
    }
    let mass = native_transaction_codec::local_mass_projection(&mutable.tx, vec![entry])?;
    let rpc: kaspa_rpc_core::RpcTransaction = (&mutable.tx).into();
    let digest = calc_schnorr_signature_hash(
        &mutable.as_verifiable(),
        0,
        SIG_HASH_ALL,
        &SigHashReusedValuesUnsync::new(),
    );
    let body = json!({"schema":"KTAPEOUT-NAMESPACE-REFUND-SPEND-BODY-V1","network":"testnet-10","transaction":rpc,"input_sighash_all":[hex::encode(digest.as_bytes())],"input_roles":["wallet_refund"],"output_roles":["ordinary_wallet_successor"],"fee_sompi":fee,"mass_projection":mass,"native_vm_verified":verify_vm,"broadcast":false,"signing_allowed":false,"l1_evidence":false});
    let hash = Sha256::digest(
        [
            b"KTAPEOUT/0.5.0/WALLET_REFUND_SPEND/V1\0".as_slice(),
            serde_json::to_string(&body)?.as_bytes(),
        ]
        .concat(),
    );
    Ok(json!({"body":body,"plan_hash":hex::encode(hash)}))
}

fn exact_object<'a>(
    value: &'a Value,
    fields: &[&str],
    label: &str,
) -> Result<&'a serde_json::Map<String, Value>, Box<dyn std::error::Error>> {
    let object = value
        .as_object()
        .ok_or_else(|| format!("{label} must be an object"))?;
    if object.len() != fields.len() || fields.iter().any(|field| !object.contains_key(*field)) {
        return Err(format!("{label} fields are not canonical").into());
    }
    Ok(object)
}

fn hash32(value: &Value, label: &str) -> Result<Hash, Box<dyn std::error::Error>> {
    let text = value
        .as_str()
        .ok_or_else(|| format!("{label} must be lowercase hex"))?;
    let bytes: [u8; 32] = hex::decode(text)?
        .try_into()
        .map_err(|_| format!("{label} must be 32 bytes"))?;
    if hex::encode(bytes) != text || bytes == [0; 32] {
        return Err(format!("{label} must be nonzero lowercase 32-byte hex").into());
    }
    Ok(Hash::from_bytes(bytes))
}

fn output(
    value: &Value,
    expected_role: &str,
) -> Result<TransactionOutput, Box<dyn std::error::Error>> {
    let object = exact_object(
        value,
        &[
            "role",
            "value",
            "script_public_key",
            "covenant_id",
            "authorizing_input",
        ],
        "output",
    )?;
    if object["role"] != expected_role {
        return Err(format!("output role must be {expected_role}").into());
    }
    let amount = object["value"]
        .as_u64()
        .ok_or("output value must be an integer")?;
    let script_public_key = native_transaction_codec::decode_spk(&object["script_public_key"])?;
    let covenant = if object["covenant_id"].is_null() {
        if !object["authorizing_input"].is_null() {
            return Err("ordinary output cannot have an authorizing input".into());
        }
        None
    } else {
        let covenant_id = hash32(&object["covenant_id"], "output covenant_id")?;
        let authorizing_input = object["authorizing_input"]
            .as_u64()
            .filter(|value| *value <= u16::MAX as u64)
            .ok_or("covenant output needs a u16 authorizing_input")?
            as u16;
        Some(CovenantBinding {
            authorizing_input,
            covenant_id,
        })
    };
    Ok(TransactionOutput {
        value: amount,
        script_public_key,
        covenant,
    })
}

pub fn build_plan_with_vm(
    value: &Value,
    verify_vm: bool,
) -> Result<Value, Box<dyn std::error::Error>> {
    let adapter = matches!(
        value["schema"].as_str(),
        Some(ADAPTER_REGISTRATION_INPUT | ADAPTER_SLOT_INPUT)
    );
    let named = adapter
        || matches!(
            value["schema"].as_str(),
            Some(
                "KTAPEOUT-NAMESPACE-REGISTRY-CHILD-UNSIGNED-INPUT-V6"
                    | "KTAPEOUT-NAMESPACE-CHILD-SLOT-UNSIGNED-INPUT-V6"
            )
        );
    let v5 = named
        || value["schema"] == "KTAPEOUT-NAMESPACE-REGISTRY-CHILD-UNSIGNED-INPUT-V5"
        || value["schema"] == "KTAPEOUT-NAMESPACE-CHILD-SLOT-UNSIGNED-INPUT-V5";
    let slot = matches!(
        value["schema"].as_str(),
        Some(
            "KTAPEOUT-NAMESPACE-CHILD-SLOT-UNSIGNED-INPUT-V4"
                | "KTAPEOUT-NAMESPACE-CHILD-SLOT-UNSIGNED-INPUT-V5"
                | "KTAPEOUT-NAMESPACE-CHILD-SLOT-UNSIGNED-INPUT-V6"
                | ADAPTER_SLOT_INPUT
        )
    );
    let request = value.as_object().ok_or("request must be an object")?;
    let required = [
        "schema",
        "network",
        "parent_covenant_id",
        "parent_utxo",
        "gap_utxo",
        "fee_utxo",
        "input_signature_scripts",
        "outputs",
        "compute_budget",
        "fee_sompi",
    ];
    let allowed = [
        "schema",
        "network",
        "parent_covenant_id",
        "parent_utxo",
        "gap_utxo",
        "fee_utxo",
        "input_signature_scripts",
        "outputs",
        "compute_budget",
        "fee_sompi",
        "state_output_script_public_keys",
    ];
    if required.iter().any(|field| !request.contains_key(*field))
        || request
            .keys()
            .any(|field| !allowed.contains(&field.as_str()))
    {
        return Err("request fields are not canonical".into());
    }
    if (!slot && !v5 && value["schema"] != INPUT_SCHEMA) || value["network"] != "testnet-10" {
        return Err("reference child codec accepts only its versioned testnet-10 schema".into());
    }
    let parent_covenant_id = hash32(&value["parent_covenant_id"], "parent_covenant_id")?;
    let (parent_outpoint, parent_entry) =
        native_transaction_codec::parse_utxo(&value["parent_utxo"], true)?;
    let (gap_outpoint, gap_entry) = native_transaction_codec::parse_utxo(&value["gap_utxo"], true)?;
    let (fee_outpoint, fee_entry) =
        native_transaction_codec::parse_utxo(&value["fee_utxo"], false)?;
    if parent_outpoint == gap_outpoint
        || parent_outpoint == fee_outpoint
        || gap_outpoint == fee_outpoint
    {
        return Err("parent, gap and fee outpoints must be distinct".into());
    }
    if parent_entry.covenant_id != Some(parent_covenant_id) {
        return Err("parent UTXO covenant_id does not match declared parent_covenant_id".into());
    }
    if gap_entry.covenant_id != Some(parent_covenant_id) {
        return Err("containing Gap UTXO covenant_id does not preserve parent lineage".into());
    }
    let outputs = value["outputs"]
        .as_array()
        .ok_or("outputs must be an array")?;
    let roles: &[&str] = if slot {
        &["parent_successor", "name_deed", "fee_change"]
    } else {
        &contract::OUTPUT_ROLES
    };
    if outputs.len() != roles.len() {
        return Err(format!(
            "reference child codec requires exactly {} outputs",
            roles.len()
        )
        .into());
    }
    let mut built_outputs = Vec::with_capacity(outputs.len());
    for (item, role) in outputs.iter().zip(roles.iter().copied()) {
        built_outputs.push(output(item, role)?);
    }
    if let Some(expected_value) = value.get("state_output_script_public_keys") {
        let expected = exact_object(
            expected_value,
            &roles[..roles.len() - 1],
            "state_output_script_public_keys",
        )?;
        for (index, role) in roles[..roles.len() - 1].iter().copied().enumerate() {
            let expected_script = expected[role].as_str().ok_or_else(|| {
                format!("state_output_script_public_keys.{role} must be lowercase hex")
            })?;
            if expected_script.len() > 65_536
                || expected_script.len() % 2 != 0
                || hex::encode(hex::decode(expected_script)?) != expected_script
            {
                return Err(format!(
                    "state_output_script_public_keys.{role} is not canonical bounded hex"
                )
                .into());
            }
            let declared_script = value["outputs"][index]["script_public_key"]
                .as_str()
                .ok_or_else(|| {
                    format!("outputs[{index}].script_public_key must be lowercase hex")
                })?;
            if declared_script != expected_script {
                return Err(format!(
                    "output role {role} does not match the supplied witness script"
                )
                .into());
            }
            native_transaction_codec::decode_spk(&Value::String(expected_script.to_string()))?;
        }
    }
    let parent_successor = &built_outputs[0];
    if parent_successor
        .covenant
        .as_ref()
        .map(|binding| binding.covenant_id)
        != Some(parent_covenant_id)
        || parent_successor
            .covenant
            .as_ref()
            .map(|binding| binding.authorizing_input)
            != Some(0)
        || parent_successor.value != parent_entry.amount
    {
        return Err(
            "parent_successor must preserve parent value and Covenant ID at output 0".into(),
        );
    }
    // The child input must authorize every state output produced by the Gap
    // split.  Checking only the parent successor is insufficient: a caller
    // could otherwise turn left_gap/name_deed/right_gap into ordinary outputs
    // or bind one of them to the fee input while still producing a plausible
    // five-output reference plan.  The concrete state transition and derived
    // Covenant IDs remain the responsibility of the canonical admitted codec.
    for (index, role) in roles
        .iter()
        .copied()
        .enumerate()
        .take(roles.len() - 1)
        .skip(1)
    {
        let binding = built_outputs[index]
            .covenant
            .as_ref()
            .ok_or_else(|| format!("{role} must be a covenant state output"))?;
        if binding.authorizing_input != 1 {
            return Err(
                format!("{role} must be authorized by containing_gap_state input 1").into(),
            );
        }
        if Some(binding.covenant_id) != gap_entry.covenant_id {
            return Err(
                format!("{role} covenant_id must preserve containing_gap_state lineage").into(),
            );
        }
    }
    if built_outputs[roles.len() - 1].covenant.is_some() {
        return Err("fee_change must be an ordinary output".into());
    }
    // Fail before signing on amounts the adapter script would refuse: the registrant funds
    // the bond and the second Gap floor; Gap capital is never drawn down.
    if adapter && !slot {
        let (left, right) = (built_outputs[1].value, built_outputs[3].value);
        if left < ADAPTER_GAP_FLOOR_SOMPI
            || right < ADAPTER_GAP_FLOOR_SOMPI
            || left
                .checked_add(right)
                .is_none_or(|sum| sum < gap_entry.amount)
        {
            return Err(
                "adapter registration may not draw on Gap capital or leave a Gap below its floor"
                    .into(),
            );
        }
    }
    if slot && built_outputs[2].script_public_key != fee_entry.script_public_key {
        return Err("slot fee change must return to fee payer".into());
    }
    let input_total = parent_entry
        .amount
        .checked_add(gap_entry.amount)
        .and_then(|total| total.checked_add(fee_entry.amount))
        .ok_or("input total overflow")?;
    let output_total = native_transaction_codec::positive_output_sum(&built_outputs)?;
    let fee_sompi = value["fee_sompi"]
        .as_u64()
        .ok_or("fee_sompi must be an integer")?;
    if input_total.checked_sub(output_total) != Some(fee_sompi) || fee_sompi == 0 {
        return Err("input_total - output_total must equal a positive fee_sompi".into());
    }
    let compute_budget = value["compute_budget"]
        .as_u64()
        .filter(|budget| *budget > 0 && *budget <= u16::MAX as u64)
        .ok_or("compute_budget must fit a positive u16")? as u16;
    let signature_scripts = value["input_signature_scripts"]
        .as_array()
        .ok_or("input_signature_scripts must be an array")?;
    if signature_scripts.len() != 3 {
        return Err("input_signature_scripts must contain exactly three entries".into());
    }
    let signature_scripts: Vec<Vec<u8>> = signature_scripts
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let text = value
                .as_str()
                .ok_or_else(|| format!("input_signature_scripts[{index}] must be lowercase hex"))?;
            if text.len() > 32_768 || text.len() % 2 != 0 || hex::encode(hex::decode(text)?) != text
            {
                return Err(format!(
                    "input_signature_scripts[{index}] is not canonical bounded hex"
                )
                .into());
            }
            Ok(hex::decode(text)?)
        })
        .collect::<Result<_, Box<dyn std::error::Error>>>()?;
    let tx = Transaction::new(
        1,
        vec![
            TransactionInput::new_with_compute_budget(
                parent_outpoint,
                signature_scripts[0].clone(),
                0,
                compute_budget,
            ),
            TransactionInput::new_with_compute_budget(
                gap_outpoint,
                signature_scripts[1].clone(),
                0,
                compute_budget,
            ),
            TransactionInput::new_with_compute_budget(
                fee_outpoint,
                signature_scripts[2].clone(),
                0,
                10,
            ),
        ],
        built_outputs,
        0,
        Default::default(),
        0,
        vec![],
    );
    let entries = vec![parent_entry, gap_entry, fee_entry];
    let mutable = MutableTransaction::with_entries(tx, entries.clone());
    // The body uses v1 inputs with ComputeBudget commitments.  The shared
    // helper keeps that version and policy consistent across all builders.
    let mass_projection =
        native_transaction_codec::local_mass_projection(&mutable.tx, entries.clone())?;
    if verify_vm {
        verify_inputs(&mutable, entries)?;
    }
    let digests: Vec<String> = (0..3)
        .map(|index| {
            hex::encode(
                calc_schnorr_signature_hash(
                    &mutable.as_verifiable(),
                    index,
                    SIG_HASH_ALL,
                    &SigHashReusedValuesUnsync::new(),
                )
                .as_bytes(),
            )
        })
        .collect();
    let rpc: kaspa_rpc_core::RpcTransaction = (&mutable.tx).into();
    let mut body = json!({
        "schema": "KTAPEOUT-NAMESPACE-REGISTRY-CHILD-UNSIGNED-BODY-REFERENCE-V1",
        "network": "testnet-10",
        "parent_covenant_id": parent_covenant_id.to_string(),
        "transaction": rpc,
        "input_sighash_all": digests,
        "contract": contract::metadata(),
        "input_roles": contract::INPUT_ROLES,
        "input_signature_scripts": signature_scripts.iter().map(hex::encode).collect::<Vec<_>>(),
        "output_roles": roles,
        "state_output_script_binding": if value.get("state_output_script_public_keys").is_some() { "VERIFIED" } else { "NOT_SUPPLIED" },
        "fee_sompi": fee_sompi,
        "compute_budget": compute_budget,
        "mass_projection": mass_projection,
        "status": if verify_vm { "VM_VERIFIED_LOCAL_TRANSACTION" } else { "UNSIGNED_LOCAL_REFERENCE" },
        "native_vm_verified": verify_vm,
        "signing_allowed": false,
        "broadcast": false,
        "missing_evidence": ["canonical_child_codec", "state_witness_codec", "live_mass_value_receipt", "tn10_readback", "deployment_tuple", "formal_profile_admission"]
    });
    if slot {
        body["schema"] = json!("KTAPEOUT-NAMESPACE-CHILD-SLOT-BODY-V4");
        body["contract"] = json!({"codec_id":"namespace-child-slot-candidate-v4","admission":"ENGINEERING_CANDIDATE_ONLY"});
    }
    if v5 {
        body["schema"] = json!(if slot {
            "KTAPEOUT-NAMESPACE-CHILD-SLOT-BODY-V5"
        } else {
            "KTAPEOUT-NAMESPACE-REGISTRY-CHILD-BODY-V5"
        });
        body["contract"] = contract::recovery_metadata();
    }
    if named {
        body["schema"] = json!(if slot {
            "KTAPEOUT-NAMESPACE-CHILD-SLOT-BODY-V6"
        } else {
            "KTAPEOUT-NAMESPACE-REGISTRY-CHILD-BODY-V6"
        });
        body["contract"] = contract::named_metadata();
    }
    if adapter {
        body["schema"] = json!(if slot {
            "KTAPEOUT-REGISTRY-ADAPTER-APP-SLOT-BODY-V1"
        } else {
            "KTAPEOUT-REGISTRY-ADAPTER-APP-REGISTRATION-BODY-V1"
        });
        body["adapter_id"] = json!("ktape.official.adapter.registry");
        body["adapter_semver"] = json!("1.0.0");
    }
    let domain = if named {
        b"KTAPEOUT/0.5.0/NAMESPACE_CHILD_REGISTRATION/CANDIDATE/V6\0".as_slice()
    } else if v5 {
        b"KTAPEOUT/0.5.0/NAMESPACE_CHILD_REGISTRATION/CANDIDATE/V5\0".as_slice()
    } else if slot {
        b"KTAPEOUT/0.5.0/NAMESPACE_CHILD_SLOT/CANDIDATE/V4\0".as_slice()
    } else {
        b"KTAPEOUT/0.5.0/NAMESPACE_CHILD_UNSIGNED_BODY_REFERENCE/V1\0".as_slice()
    };
    let digest = Sha256::digest([domain, serde_json::to_string(&body)?.as_bytes()].concat());
    Ok(json!({ "plan_hash": hex::encode(digest), "body": body }))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if !(args.len() == 2 || (args.len() == 3 && args[2] == "--verify-vm")) || args[0] != "--input" {
        return Err("usage: namespace_registry_child_registration_reference_codec --input PUBLIC.json [--verify-vm]".into());
    }
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(&args[1])?
        .take(262_145)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 262_144 {
        return Err("reference codec input exceeds 256 KiB".into());
    }
    let value: Value = bounded_public_json::parse_with_limit(&bytes, 262144)?;
    let plan = if value["schema"] == "KTAPEOUT-NAMESPACE-REFUND-SPEND-INPUT-V1" {
        build_refund_spend(&value, args.len() == 3)?
    } else if matches!(
        value["schema"].as_str(),
        Some(
            "KTAPEOUT-NAMESPACE-RECOVERY-UNSIGNED-INPUT-V5"
                | "KTAPEOUT-NAMESPACE-RECOVERY-UNSIGNED-INPUT-V6"
        )
    ) {
        build_recovery_plan(&value, args.len() == 3)?
    } else if matches!(
        value["schema"].as_str(),
        Some(
            "KTAPEOUT-NAMESPACE-CHILD-OWNER-UNSIGNED-INPUT-V3"
                | "KTAPEOUT-NAMESPACE-CHILD-OWNER-UNSIGNED-INPUT-V4"
                | "KTAPEOUT-NAMESPACE-CHILD-OWNER-UNSIGNED-INPUT-V5"
                | "KTAPEOUT-NAMESPACE-CHILD-OWNER-UNSIGNED-INPUT-V6"
                | ADAPTER_OWNER_INPUT
        )
    ) {
        build_owner_operation_plan(&value, args.len() == 3)?
    } else if matches!(
        value["schema"].as_str(),
        Some(
            "KTAPEOUT-NAMESPACE-PARENT-TRANSFER-UNSIGNED-INPUT-V2"
                | "KTAPEOUT-NAMESPACE-PARENT-TRANSFER-UNSIGNED-INPUT-V6"
        )
    ) {
        build_parent_transfer_plan(&value, args.len() == 3)?
    } else {
        build_plan_with_vm(&value, args.len() == 3)?
    };
    println!("{}", serde_json::to_string(&plan)?);
    Ok(())
}
