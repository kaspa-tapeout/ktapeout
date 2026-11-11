//! Pinned signed-registration transaction vectors for script-level regression checks.

use serde_json::json;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

use kaspa_consensus_core::tx::PopulatedTransaction;
use kaspa_consensus_core::{
    config::params::Params,
    mass::MassCalculator,
    network::{NetworkId, NetworkType},
    tx::{
        CovenantBinding, MutableTransaction, ScriptPublicKey, Transaction, TransactionId,
        TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry,
    },
    Hash,
};
use ktapeout_cli::tn10_pipeline::{
    build_native_owner_target_plan, build_native_registration_plan,
    verify_native_registration_plan_digest,
};
use ktapeout_kaspa_verifier::verify_post_toccata_populated_transaction;

const SIGSCRIPT_VECTORS: &str =
    include_str!("../../../data/registry/real-registration-sigscript-vectors-v1.json");

fn script_instructions(script: &[u8]) -> Vec<(usize, usize, String)> {
    let mut instructions = Vec::new();
    let mut cursor = 0;
    while cursor < script.len() {
        let start = cursor;
        let opcode = script[cursor];
        cursor += 1;
        let length = match opcode {
            0 => 0,
            1..=75 => opcode as usize,
            76 => {
                let length = *script.get(cursor).expect("PUSHDATA1 length");
                cursor += 1;
                length as usize
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
            _ => {
                instructions.push((start, cursor, format!("opcode_{opcode:02x}")));
                continue;
            }
        };
        let end = cursor
            .checked_add(length)
            .expect("push end does not overflow");
        assert!(
            end <= script.len(),
            "push at offset {start} exceeds script length"
        );
        instructions.push((
            start,
            end,
            if opcode == 0 {
                "OP_0".into()
            } else {
                "push".into()
            },
        ));
        cursor = end;
    }
    instructions
}

fn decode_witness_stack(script: &[u8]) -> Vec<Value> {
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
                let length = script[cursor] as usize;
                cursor += 1;
                length
            }
            77 => {
                let length = u16::from_le_bytes(script[cursor..cursor + 2].try_into().unwrap());
                cursor += 2;
                length as usize
            }
            79 | 81..=96 => {
                items.push(json!({"opcode":opcode}));
                continue;
            }
            _ => panic!("unexpected witness opcode {opcode:#04x}"),
        };
        let end = cursor + length;
        assert!(end <= script.len(), "witness push exceeds script length");
        items.push(json!({"data_hex":hex::encode(&script[cursor..end])}));
        cursor = end;
    }
    items
}

const CHAIN_COVENANT_ID: &str = "7d2e5f8c0593c425e6e6f16b67b3f2e5d9e5b735269ccbc71d32c51a4f0f57ea";
const CHAIN_FEE_KEY: &str = "aa0ada4f5bf5369de10ea33599d335f5fb52eba0bb509c50217e91009a9282d5";

fn registration_mass_fixture(signed: bool) -> (Transaction, Vec<UtxoEntry>, Option<Value>) {
    let document: Value = serde_json::from_str(SIGSCRIPT_VECTORS).unwrap();
    let vector = document["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|vector| {
            vector["txid"] == "9eddc2cec1302e63a6ea1adca815186476e2a9dc2ed65c4b1c070b2603e5a354"
        })
        .unwrap();
    let inputs = vector["inputs"].as_array().unwrap();
    let inputs_data = [
        (
            "97c95fb189f7ad1ce97af1d437f86534c234264ab61a5d6ac870971aec912454",
            0,
            1_000_000_000,
            "0000aa20e4bfcc173bed3da4850ad8f56e8c60887930eec81d2e5617d5ee33c097b4c27087",
            602_931_026,
            Some(CHAIN_COVENANT_ID),
            256,
        ),
        (
            "d385ea5bc95d6e134005754a9def12094812ce386c32d398b6ac205592f27d24",
            1,
            100_000_000,
            "0000aa2008ebcdb2dbd6ac4fb59a105f68cc9107a87363bde53ba1584fddce5c2fa8393187",
            602_930_693,
            Some(CHAIN_COVENANT_ID),
            256,
        ),
        (
            "ffa232c60152ac36389846293fef3c31175e32e24530fa9a0436565c8039457b",
            1,
            890_339_166_424,
            "000020aa0ada4f5bf5369de10ea33599d335f5fb52eba0bb509c50217e91009a9282d5ac",
            604_956_187,
            None,
            10,
        ),
    ];
    let covenant_id = Hash::from_bytes(hex::decode(CHAIN_COVENANT_ID).unwrap().try_into().unwrap());
    let mut tx_inputs = Vec::new();
    let mut utxos = Vec::new();
    let mut plan_inputs = Vec::new();
    let mut witness_contexts = Vec::new();
    for (index, (txid, output_index, amount, spk, daa, covenant, budget)) in
        inputs_data.iter().enumerate()
    {
        let txid = TransactionId::from_bytes(hex::decode(txid).unwrap().try_into().unwrap());
        let outpoint = TransactionOutpoint::new(txid, *output_index);
        let script = ScriptPublicKey::from_vec(
            0,
            hex::decode(&spk[4..]).expect("source script is canonical"),
        );
        let entry = UtxoEntry::new(
            *amount,
            script.clone(),
            *daa,
            false,
            covenant.map(|_| covenant_id),
        );
        let vector_script =
            hex::decode(inputs[index]["signature_script_hex"].as_str().unwrap()).unwrap();
        tx_inputs.push(TransactionInput::new_with_compute_budget(
            outpoint,
            if signed {
                vector_script.clone()
            } else {
                Vec::new()
            },
            0,
            *budget,
        ));
        utxos.push(entry);
        plan_inputs.push(json!({
            "outpoint":format!("{}:{}",hex::encode(txid.as_bytes()),output_index),
            "amount":amount,
            "block_daa_score":daa,
            "script_public_key":spk,
            "covenant_id":covenant,
            "compute_budget":budget,
            "signature_script":""
        }));
        if index < 2 {
            let mut stack = decode_witness_stack(&vector_script);
            let redeem = stack.pop().unwrap();
            let redeem_script = redeem["data_hex"].as_str().unwrap().to_owned();
            let mut arguments = stack;
            let slots: &[usize] = if index == 0 { &[6] } else { &[11, 13, 22] };
            for slot in slots {
                arguments[*slot] = json!({"data_hex":"00".repeat(65)});
            }
            witness_contexts.push(json!({
                "input_index":index,
                "entrypoint":if index == 0 {"authorize_child"} else {"register_interior"},
                "redeem_script_hex":redeem_script,
                "arguments":arguments
            }));
        }
    }
    let outputs_data = [
        (
            1_000_000_000u64,
            "0000aa20e4bfcc173bed3da4850ad8f56e8c60887930eec81d2e5617d5ee33c097b4c27087",
            Some(0u64),
        ),
        (
            100_000_000,
            "0000aa208364b3502da31ac06ef35e991f3cd8f138b35dd2a6825e4da1110adc2b485a8f87",
            Some(1),
        ),
        (
            100_000_000,
            "0000aa20e94e4f87eddc10a5e308ae504fd40d539ec4c5a3dbdbee7775566ba3260016d487",
            Some(1),
        ),
        (
            100_000_000,
            "0000aa20dbea96649c09cc0dc4d4bedb342547fd95c3eae5137c3c3c32c7113772e99b9387",
            Some(1),
        ),
        (
            890_125_529_064,
            "000020aa0ada4f5bf5369de10ea33599d335f5fb52eba0bb509c50217e91009a9282d5ac",
            None,
        ),
    ];
    let outputs = outputs_data
        .iter()
        .map(|(amount, spk, auth)| {
            let script = ScriptPublicKey::from_vec(0, hex::decode(&spk[4..]).unwrap());
            TransactionOutput::with_covenant(
                *amount,
                script,
                auth.map(|input| CovenantBinding::new(input as u16, covenant_id)),
            )
        })
        .collect();
    let tx = Transaction::new(1, tx_inputs, outputs, 0, Default::default(), 0, Vec::new());
    if signed {
        return (tx, utxos, None);
    }
    let outputs = outputs_data
        .iter()
        .enumerate()
        .map(|(index, (amount, spk, auth))| {
            let role = [
                "parent_successor",
                "left_gap",
                "name_deed",
                "right_gap",
                "fee_change",
            ][index];
            json!({
                "role":role,
                "value":amount,
                "script_public_key":spk,
                "covenant_id":auth.map(|_|CHAIN_COVENANT_ID),
                "authorizing_input":auth
            })
        })
        .collect::<Vec<_>>();
    let request = json!({
        "inputs":plan_inputs,
        "outputs":outputs,
        "deed_state_bond_sompi":1_000_000_000u64,
        "registration_entrypoint":"register_interior",
        "registration_kind":"INTERIOR",
        "role_public_keys":{
            "parent":CHAIN_FEE_KEY,
            "claimant":CHAIN_FEE_KEY,
            "target":CHAIN_FEE_KEY,
            "parent_for_child":CHAIN_FEE_KEY,
            "fee":CHAIN_FEE_KEY
        },
        "covenant_witness_contexts":witness_contexts
    });
    let plan = build_native_registration_plan(&request).unwrap();
    let mut tx = tx;
    for (index, input) in tx.inputs.iter_mut().enumerate() {
        input.signature_script = hex::decode(
            plan["transaction"]["inputs"][index]["signatureScript"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
    }
    let utxos = request["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|input| {
            let script = ScriptPublicKey::from_vec(
                0,
                hex::decode(&input["script_public_key"].as_str().unwrap()[4..]).unwrap(),
            );
            let covenant = input["covenant_id"].as_str().map(|_| covenant_id);
            UtxoEntry::new(
                input["amount"].as_u64().unwrap(),
                script,
                input["block_daa_score"].as_u64().unwrap(),
                false,
                covenant,
            )
        })
        .collect();
    (tx, utxos, Some(plan))
}

fn pinned_tn10_mass(tx: &Transaction, utxos: Vec<UtxoEntry>) -> (u64, u64, u64) {
    let params = Params::from(NetworkId::with_suffix(NetworkType::Testnet, 10));
    let calculator = MassCalculator::new_with_consensus_params(&params);
    let non_contextual = calculator.calc_non_contextual_masses(tx);
    let contextual = calculator
        .calc_contextual_masses(
            &MutableTransaction::with_entries(tx.clone(), utxos).as_verifiable(),
        )
        .expect("complete saved UTXO context produces contextual mass");
    (
        non_contextual.compute_mass,
        non_contextual.transient_mass,
        contextual.storage_mass,
    )
}

#[test]
fn pinned_v21_recomputes_saved_change_owner_target_mass() {
    let document: Value = serde_json::from_str(SIGSCRIPT_VECTORS).unwrap();
    let vector = document["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|vector| {
            vector["txid"] == "089f52c8e148672da4663397c0178fa88362fb826c74ae001d33bdedd3398b49"
        })
        .unwrap();
    let id = Hash::from_bytes(hex::decode(CHAIN_COVENANT_ID).unwrap().try_into().unwrap());
    let parent_spk = ScriptPublicKey::from_vec(
        0,
        hex::decode("aa20566ddb63bcc278c5a49529f2b43e1b7c8f34386e569b4eb73d2e9a047bf0ba0387")
            .unwrap(),
    );
    let fee_spk = ScriptPublicKey::from_vec(
        0,
        hex::decode("20aa0ada4f5bf5369de10ea33599d335f5fb52eba0bb509c50217e91009a9282d5ac")
            .unwrap(),
    );
    let previous = TransactionId::from_bytes(
        hex::decode("518143e6a38f029a49ac9dddc06f7c36440c161a5df6743c76555a1e6cf3f58a")
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let vector_inputs = vector["inputs"].as_array().unwrap();
    let inputs = vec![
        TransactionInput::new_with_compute_budget(
            TransactionOutpoint::new(previous, 0),
            hex::decode(vector_inputs[0]["signature_script_hex"].as_str().unwrap()).unwrap(),
            0,
            256,
        ),
        TransactionInput::new_with_compute_budget(
            TransactionOutpoint::new(previous, 1),
            hex::decode(vector_inputs[1]["signature_script_hex"].as_str().unwrap()).unwrap(),
            0,
            10,
        ),
    ];
    let transaction = Transaction::new(
        1,
        inputs,
        vec![
            TransactionOutput::with_covenant(
                100_000_000,
                ScriptPublicKey::from_vec(
                    0,
                    hex::decode(
                        "aa20d7c7afdc7930411a78c652fe35479b37a577557ab483c3e0c5d2b41155fb1d4787",
                    )
                    .unwrap(),
                ),
                Some(CovenantBinding::new(0, id)),
            ),
            TransactionOutput::with_covenant(890_112_331_704, fee_spk.clone(), None),
        ],
        0,
        Default::default(),
        0,
        Vec::new(),
    );
    let utxos = vec![
        UtxoEntry::new(100_000_000, parent_spk, 605_673_488, false, Some(id)),
        UtxoEntry::new(890_116_730_824, fee_spk, 605_673_488, false, None),
    ];
    let masses = pinned_tn10_mass(&transaction, utxos);
    println!("089f52 pinned v2.1.0 compute/transient/storage mass: {masses:?}");
    assert_eq!(masses, (36_708, 37_512, 39_992));
}

#[test]
fn native_owner_target_plan_matches_saved_089f_mass_and_binds_roles() {
    let document: Value = serde_json::from_str(SIGSCRIPT_VECTORS).unwrap();
    let vector = document["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|vector| {
            vector["txid"] == "089f52c8e148672da4663397c0178fa88362fb826c74ae001d33bdedd3398b49"
        })
        .unwrap();
    let signed_script = hex::decode(
        vector["inputs"][0]["signature_script_hex"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let mut stack = decode_witness_stack(&signed_script);
    let redeem_script = stack.pop().unwrap()["data_hex"]
        .as_str()
        .unwrap()
        .to_owned();
    // Signature slots are blank in an unsigned plan; all other arguments remain the
    // exact saved witness arguments for this frozen CHANGE_OWNER_TARGET ABI.
    stack[11] = json!({"data_hex": "00".repeat(65)});
    stack[14] = json!({"data_hex": "00".repeat(65)});
    let owner_key = stack[12]["data_hex"].as_str().unwrap();
    let target_key = stack[15]["data_hex"].as_str().unwrap();
    let fee_key = CHAIN_FEE_KEY;
    let request = json!({
        "inputs":[
            {
                "outpoint":"518143e6a38f029a49ac9dddc06f7c36440c161a5df6743c76555a1e6cf3f58a:0",
                "amount":100_000_000,"block_daa_score":605_673_488,
                "script_public_key":"0000aa20566ddb63bcc278c5a49529f2b43e1b7c8f34386e569b4eb73d2e9a047bf0ba0387",
                "covenant_id":CHAIN_COVENANT_ID,"compute_budget":256,"signature_script":""
            },
            {
                "outpoint":"518143e6a38f029a49ac9dddc06f7c36440c161a5df6743c76555a1e6cf3f58a:1",
                "amount":890_116_730_824u64,"block_daa_score":605_673_488,
                "script_public_key":"000020aa0ada4f5bf5369de10ea33599d335f5fb52eba0bb509c50217e91009a9282d5ac",
                "covenant_id":null,"compute_budget":10,"signature_script":""
            }
        ],
        "outputs":[
            {"role":"deed_successor","value":100_000_000,"script_public_key":"0000aa20d7c7afdc7930411a78c652fe35479b37a577557ab483c3e0c5d2b41155fb1d4787","covenant_id":CHAIN_COVENANT_ID,"authorizing_input":0},
            {"role":"fee_change","value":890_112_331_704u64,"script_public_key":format!("000020{fee_key}ac"),"covenant_id":null,"authorizing_input":null}
        ],
        "covenant_witness_contexts":[{"input_index":0,"entrypoint":"change_owner_target","redeem_script_hex":redeem_script,"arguments":stack}],
        "role_public_keys":{"deed_owner":owner_key,"target_authority":target_key,"fee":fee_key},
        "fee_sompi":4_399_120
    });

    let plan = build_native_owner_target_plan(&request).unwrap();
    assert_eq!(plan["schema"], "KTAPEOUT-TN10-NATIVE-OWNER-TARGET-PLAN-V1");
    assert_eq!(plan["transaction"]["inputs"].as_array().unwrap().len(), 2);
    assert_eq!(plan["transaction"]["outputs"].as_array().unwrap().len(), 2);
    assert_eq!(plan["next_owner_xonly"], owner_key);
    assert_eq!(
        plan["role_input_map"],
        json!({"deed_owner":0,"target_authority":0,"fee":1})
    );
    assert_eq!(plan["quality"]["compute_mass"], 36_708);
    assert_eq!(plan["quality"]["transient_mass"], 37_512);
    assert_eq!(plan["quality"]["storage_mass"], 39_992);
    assert!(verify_native_registration_plan_digest(&plan));
}

#[test]
fn pinned_v21_reconciles_9edd_real_transaction_and_register_plan_mass() {
    let (signed_tx, signed_utxos, _) = registration_mass_fixture(true);
    let signed_mass = pinned_tn10_mass(&signed_tx, signed_utxos);
    assert_eq!(
        signed_mass.0, 66_732,
        "9edd compute mass from pinned v2.1.0"
    );
    assert_eq!(
        signed_mass.2, 123_976,
        "9edd storage mass from pinned v2.1.0"
    );

    let (_, _, plan) = registration_mass_fixture(false);
    let plan = plan.expect("unsigned plan was constructed");
    assert!(plan["quality"]["signature_scripts_are_placeholders"] == true);
    assert_eq!(
        plan["quality"]["signature_script_lengths"],
        json!([1245, 10725, 66])
    );
    assert_eq!(
        plan["quality"]["compute_mass"].as_u64(),
        Some(signed_mass.0)
    );
    assert_eq!(
        plan["quality"]["transient_mass"].as_u64(),
        Some(signed_mass.1)
    );
    assert_eq!(
        plan["quality"]["storage_mass"].as_u64(),
        Some(signed_mass.2)
    );
    assert_eq!(
        plan["quality"]["normalized_total_mass"].as_u64(),
        Some(123_976)
    );
    println!("9edd signed compute/transient/storage: {signed_mass:?}");
    println!("9edd plan quality: {}", plan["quality"]);
}

#[test]
fn pinned_v21_executes_saved_9edd_transaction_with_chain_compute_budgets() {
    let (tx, utxos, _) = registration_mass_fixture(true);
    let metrics = verify_post_toccata_populated_transaction(&PopulatedTransaction::new(&tx, utxos))
        .expect("pinned v2.1.0 must execute the saved 9edd transaction inputs");
    assert_eq!(metrics.len(), 3);
    assert_eq!(
        metrics
            .iter()
            .map(|metric| metric.compute_budget)
            .collect::<Vec<_>>(),
        vec![256, 256, 10],
        "actual chain transaction input budgets are the regression baseline"
    );
    assert_eq!(
        metrics
            .iter()
            .map(|metric| metric.script_units_used)
            .collect::<Vec<_>>(),
        vec![107_990, 459_897, 100_001],
        "script units are measured by the pinned v2.1.0 post-Toccata VM"
    );
    for metric in &metrics {
        eprintln!(
            "9edd input {}: measured script_units={}, chain_compute_budget={}, allowed_script_units={}",
            metric.input_index, metric.script_units_used, metric.compute_budget, metric.allowed_script_units
        );
    }
}

#[test]
fn pinned_v21_executes_other_three_saved_official_registration_transactions() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../data/registry/adapter-registry-live-vectors-v1.json"
    ))
    .unwrap();
    for vector in fixture["vectors"].as_array().unwrap().iter().skip(1) {
        let rpc: kaspa_rpc_core::RpcTransaction =
            serde_json::from_value(vector["saved_transaction"].clone())
                .expect("saved transaction must be present, not a claimed verification flag");
        let tx = Transaction::try_from(rpc).unwrap();
        assert_eq!(tx.id().to_string(), vector["txid"].as_str().unwrap());
        let utxos = vector["saved_utxos"]
            .as_array()
            .unwrap()
            .iter()
            .map(|input| {
                let script = hex::decode(input["script_public_key"].as_str().unwrap()).unwrap();
                let version = u16::from_le_bytes(script[..2].try_into().unwrap());
                let covenant = input["covenant_id"]
                    .as_str()
                    .map(|value| Hash::from_bytes(hex::decode(value).unwrap().try_into().unwrap()));
                UtxoEntry::new(
                    input["amount"].as_u64().unwrap(),
                    ScriptPublicKey::from_vec(version, script[2..].to_vec()),
                    input["block_daa_score"].as_u64().unwrap(),
                    false,
                    covenant,
                )
            })
            .collect();
        let metrics =
            verify_post_toccata_populated_transaction(&PopulatedTransaction::new(&tx, utxos))
                .expect("each saved transaction must execute in the pinned VM");
        assert_eq!(metrics.len(), 3);
        assert!(metrics.iter().all(|metric| metric.script_units_used > 0));
    }
}

#[test]
fn lowered_quality_cannot_be_used_as_a_validated_registration_plan() {
    let (_, _, plan) = registration_mass_fixture(false);
    let mut plan = plan.expect("unsigned plan was constructed");
    plan["quality"]["compute_mass"] = json!(1);
    plan["quality"]["storage_mass"] = json!(1);
    plan["quality"]["normalized_total_mass"] = json!(1);
    assert!(!verify_native_registration_plan_digest(&plan));
}

#[test]
fn saved_registration_sigscript_vectors_are_pinned_to_transaction_ids() {
    let document: Value = serde_json::from_str(SIGSCRIPT_VECTORS).unwrap();
    assert_eq!(
        document["schema"],
        "KTAPEOUT-REAL-REGISTRY-SIGSCRIPT-VECTORS-V1"
    );
    let expected: [(&str, &str, usize, &[&str]); 5] = [
        (
            "9eddc2cec1302e63a6ea1adca815186476e2a9dc2ed65c4b1c070b2603e5a354",
            "registration-vector-1.json",
            5,
            &[
                "089dd2b62f1ff520e48324343c4aa7375de8c93f0d7a515523b1684d80033386",
                "c23736e2215caf7f0073a54dc56aa0c9bf1177482fe97b62ce1f668abcb18321",
                "bf84d00b9e16ccbcd3fc72d214f5fc5988bc8fb8d1f776994c4b6a6b3a37c5e0",
            ],
        ),
        (
            "518143e6a38f029a49ac9dddc06f7c36440c161a5df6743c76555a1e6cf3f58a",
            "registration-vector-2.json",
            2,
            &[
                "afb42df2d60cbf63780af51008db3cfdce783615a01a45352a5f8c559f9e3a2c",
                "371fbaf706371bb5362594a954c3c93706a1e21a89c76d2485e940fc25c39934",
            ],
        ),
        (
            "089f52c8e148672da4663397c0178fa88362fb826c74ae001d33bdedd3398b49",
            "registration-vector-3.json",
            2,
            &[
                "a9534f30fc08968af4e0b0c409091b2f885daf4d5eefd19f12a1c32f2abbdc72",
                "5fd6a6c3e37e274aaebd2eb48095abae42d60c705babc08b57d4770fd317f455",
            ],
        ),
        (
            "d385ea5bc95d6e134005754a9def12094812ce386c32d398b6ac205592f27d24",
            "registration-vector-4.json",
            5,
            &[
                "b696864e0bcca20281d5054564f7e38c9dfb444f6a4db4d45a4c114da3fa6b05",
                "24c3b99a214d803471496876da1ab9a22a83fcbca7b3704e9b3fe13d52918681",
                "f5f2f09b69467bdd71455adffbcc0f0dfacf8ba7b84b698164393c34519424f8",
            ],
        ),
        (
            "97c95fb189f7ad1ce97af1d437f86534c234264ab61a5d6ac870971aec912454",
            "registration-vector-5.json",
            5,
            &[
                "372fae44af194b8b9c129612be734e70a06a56f16708ed7034fd937bd65a7ce3",
                "d69cd841cb5725b64f757fdf1f8772001b74d7a85b75af6042b23c9abdc4ac42",
                "68efbe77683ea3674f0f9e8a0308d3a3b2ff1da6cb9edd01cbd8d99ab39b58d7",
            ],
        ),
    ];
    let vectors = document["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), expected.len());
    for ((txid, source, output_count, hashes), vector) in expected.iter().zip(vectors) {
        assert_eq!(vector["txid"], *txid);
        assert_eq!(vector["source_file"], *source);
        assert_eq!(vector["output_count"], *output_count);
        let inputs = vector["inputs"].as_array().unwrap();
        assert_eq!(inputs.len(), hashes.len());
        assert_eq!(vector["input_count"], hashes.len());
        for (index, (input, expected_hash)) in inputs.iter().zip(*hashes).enumerate() {
            assert_eq!(input["index"], index);
            let script = hex::decode(input["signature_script_hex"].as_str().unwrap()).unwrap();
            assert!(!script.is_empty());
            assert_eq!(
                hex::encode(Sha256::digest(script)),
                *expected_hash,
                "signature script vector changed: transaction {txid} input {index}"
            );
        }
    }
}

#[test]
fn saved_sigscript_parts_reassemble_and_match_operation_boundaries() {
    let document: Value = serde_json::from_str(SIGSCRIPT_VECTORS).unwrap();
    let vectors = document["vectors"].as_array().unwrap();
    let profiles = document["decomposition_profiles"].as_array().unwrap();
    let mut operations = BTreeSet::new();
    for vector in vectors {
        for (input_index, input) in vector["inputs"].as_array().unwrap().iter().enumerate() {
            let script = hex::decode(input["signature_script_hex"].as_str().unwrap()).unwrap();
            let profile = profiles
                .iter()
                .find(|profile| {
                    profile["txids"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|txid| txid == &vector["txid"])
                        && profile["input_indices"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .any(|index| index.as_u64() == Some(input_index as u64))
                })
                .expect("every input has a decomposition profile");
            let operation = profile["operation"].as_str().unwrap();
            operations.insert(operation.to_owned());
            let parts = profile["parts"].as_array().unwrap();
            let mut rebuilt = Vec::new();
            let mut expected_offset = 0usize;
            for part in parts {
                let offset = part["offset"].as_u64().unwrap() as usize;
                let length = part["length"].as_u64().unwrap() as usize;
                assert_eq!(
                    offset, expected_offset,
                    "{operation}: non-contiguous part {}",
                    part["name"]
                );
                assert!(!part["name"].as_str().unwrap().is_empty());
                assert!(length > 0, "{operation}: empty part {}", part["name"]);
                rebuilt.extend_from_slice(&script[offset..offset + length]);
                expected_offset += length;
            }
            assert_eq!(
                expected_offset,
                script.len(),
                "{operation}: parts do not cover sig_script"
            );
            assert_eq!(
                rebuilt, script,
                "{operation}: decomposed bytes do not reassemble"
            );
            assert_eq!(
                profile["script_length"].as_u64(),
                Some(script.len() as u64),
                "{operation}: unexpected script length"
            );
            if let Some(selector) = profile.get("selector") {
                let offset = selector["offset"].as_u64().unwrap() as usize;
                let length = selector["length"].as_u64().unwrap() as usize;
                assert_eq!(
                    hex::encode(&script[offset..offset + length]),
                    selector["hex"].as_str().unwrap(),
                    "{operation}: selector bytes differ"
                );
                assert!(
                    parts.iter().any(|part| part["name"] == selector["name"]),
                    "{operation}: selector is not a named decomposed part"
                );
            }
            let boundaries = script_instructions(&script);
            for part in parts {
                if part["encoding"] == "instruction" {
                    let offset = part["offset"].as_u64().unwrap() as usize;
                    let length = part["length"].as_u64().unwrap() as usize;
                    assert!(
                        boundaries
                            .iter()
                            .any(|(start, end, _)| *start == offset && *end - *start == length),
                        "{operation}: {} is not an instruction boundary",
                        part["name"]
                    );
                }
            }
        }
    }
    assert!(operations.contains("authorize_child"));
    assert!(operations.contains("register_interior"));
    assert!(operations.contains("change_owner_target"));
    assert!(
        profiles.iter().any(|profile| profile["transition_action"]
            == "register_interior_issues_name_deed_and_successor_gaps"),
        "saved registration vector must identify the Deed issue transition"
    );
}

#[test]
fn generated_toccata_witness_vectors_are_complete_and_byte_pinned() {
    let vectors: Value = serde_json::from_str(include_str!(
        "../../../data/registry/toccata-native-witness-vectors-v1.json"
    ))
    .expect("generated Toccata witness vector JSON");
    assert_eq!(
        vectors["schema"],
        "KTAPEOUT-TOCCATA-NATIVE-WITNESS-VECTORS-V1"
    );
    assert_eq!(
        vectors["consensus_baseline"],
        "rusty-kaspa-v2.1.0-toccata-post"
    );
    assert_eq!(vectors["generator"], "private-compiler-one-time-offline");
    assert_eq!(vectors["vectors"].as_array().unwrap().len(), 6);
    let coverage: BTreeSet<_> = vectors["coverage"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap())
        .collect();
    assert_eq!(
        coverage,
        BTreeSet::from([
            "gap-kind-0-hi-is-max-0",
            "gap-kind-0-hi-is-max-1",
            "five-field-adapter-parent",
            "nine-field-certificate",
            "boundary-values",
            "maximum-generated-witness-length",
        ])
    );
    assert!(vectors["maximum_generated_witness_bytes"].as_u64().unwrap() >= 10_000);
    let operations: BTreeSet<_> = vectors["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|vector| vector["entrypoint"].as_str().unwrap())
        .collect();
    assert_eq!(
        operations,
        BTreeSet::from([
            "authorize_child",
            "register_interior",
            "issue",
            "change_owner_target",
        ])
    );
    for vector in vectors["vectors"].as_array().unwrap() {
        assert!(vector["source_sha256"].as_str().unwrap().len() == 64);
        let bytes = hex::decode(vector["witness_hex"].as_str().unwrap()).unwrap();
        assert_eq!(
            bytes.len(),
            vector["witness_bytes"].as_u64().unwrap() as usize
        );
        assert_eq!(
            hex::encode(Sha256::digest(&bytes)),
            vector["witness_sha256"].as_str().unwrap(),
            "entrypoint {}",
            vector["entrypoint"]
        );
        assert!(!vector["state_shape"].as_str().unwrap().is_empty());
    }
}
