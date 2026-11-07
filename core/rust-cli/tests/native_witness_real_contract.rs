use kaspa_consensus_core::{
    tx::{PopulatedTransaction, ScriptPublicKey, Transaction, UtxoEntry},
    Hash,
};
use ktapeout_kaspa_verifier::verify_post_toccata_populated_transaction;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::ops::Range;

const FIXTURE: &str = include_str!("../../../data/registry/native-registration-contract-v1.json");
const OWNER_TARGET_VECTORS: &str =
    include_str!("../../../data/registry/real-registration-sigscript-vectors-v1.json");
const DEED_TEMPLATE: &str = include_str!("../../../data/registry/deed-state-template-v1.json");

fn test_authorization(plan: &Value) -> Value {
    let total = plan["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|input| input["amount"].as_u64().unwrap())
        .sum::<u64>();
    json!({
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
    })
}

fn worthless_test_secret(scalar: u8) -> [u8; 32] {
    let mut secret = [0u8; 32];
    secret[31] = scalar;
    secret
}

fn deed_state_from_script(script: &[u8], template: &Value) -> Vec<Value> {
    let mut state = vec![Value::Null; 15];
    for (slot, value) in template["fixed_state"].as_object().unwrap() {
        state[slot.parse::<usize>().unwrap()] = json!(value.as_u64().unwrap());
    }
    for (slot, offsets) in template["hash_sites"].as_object().unwrap() {
        let offset = offsets[0].as_u64().unwrap() as usize;
        state[slot.parse::<usize>().unwrap()] = json!(hex::encode(&script[offset..offset + 32]));
    }
    for (slot, offset) in template["int_sites"].as_object().unwrap() {
        let offset = offset.as_u64().unwrap() as usize;
        let value = u64::from_le_bytes(script[offset..offset + 8].try_into().unwrap());
        state[slot.parse::<usize>().unwrap()] = json!(value);
    }
    state
}

fn render_deed_state(state: &[Value], template: &Value) -> Vec<u8> {
    let mut script = hex::decode(template["template_hex"].as_str().unwrap()).unwrap();
    for (slot, offsets) in template["hash_sites"].as_object().unwrap() {
        let value = hex::decode(state[slot.parse::<usize>().unwrap()].as_str().unwrap()).unwrap();
        for offset in offsets.as_array().unwrap() {
            let offset = offset.as_u64().unwrap() as usize;
            script[offset..offset + value.len()].copy_from_slice(&value);
        }
    }
    for (slot, offset) in template["int_sites"].as_object().unwrap() {
        let value = state[slot.parse::<usize>().unwrap()].as_u64().unwrap();
        let offset = offset.as_u64().unwrap() as usize;
        script[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    script
}

fn state_item(arguments: &[Value], index: usize) -> Value {
    if let Some(opcode) = arguments[index]["opcode"].as_u64() {
        return json!(if opcode == 0 { 0 } else { opcode - 80 });
    }
    if index == 10 {
        let bytes: [u8; 4] = hex::decode(arguments[index]["data_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        return json!(u32::from_le_bytes(bytes));
    }
    json!(arguments[index]["data_hex"].as_str().unwrap())
}

fn push_range(script: &[u8], wanted: usize) -> Option<Range<usize>> {
    let mut cursor = 0usize;
    let mut item = 0usize;
    while cursor < script.len() {
        let opcode = script[cursor];
        cursor += 1;
        let length = match opcode {
            0x00 | 0x4f | 0x51..=0x60 => 0usize,
            0x01..=0x4b => opcode as usize,
            0x4c => {
                let length = *script.get(cursor)? as usize;
                cursor += 1;
                length
            }
            0x4d => {
                let bytes: [u8; 2] = script.get(cursor..cursor + 2)?.try_into().ok()?;
                cursor += 2;
                u16::from_le_bytes(bytes) as usize
            }
            0x4e => {
                let bytes: [u8; 4] = script.get(cursor..cursor + 4)?.try_into().ok()?;
                cursor += 4;
                usize::try_from(u32::from_le_bytes(bytes)).ok()?
            }
            _ => return None,
        };
        let end = cursor.checked_add(length)?;
        if end > script.len() {
            return None;
        }
        if item == wanted {
            return Some(cursor..end);
        }
        cursor = end;
        item += 1;
    }
    None
}

fn verify_fixture_tx(tx: &Transaction, utxos: Vec<UtxoEntry>) -> bool {
    verify_post_toccata_populated_transaction(&PopulatedTransaction::new(tx, utxos)).is_ok()
}

fn owner_target_request() -> (Value, [[u8; 32]; 3]) {
    let secrets = [
        worthless_test_secret(1),
        worthless_test_secret(2),
        worthless_test_secret(3),
    ];
    let secp = secp256k1::Secp256k1::new();
    let keys = secrets.map(|test_key_bytes| {
        let signing_key = secp256k1::SecretKey::from_slice(&test_key_bytes).unwrap();
        let pair = secp256k1::Keypair::from_secret_key(&secp, &signing_key);
        secp256k1::XOnlyPublicKey::from_keypair(&pair).0.serialize()
    });
    let owner_key = hex::encode(keys[0]);
    let target_key = hex::encode(keys[1]);
    let fee_key = hex::encode(keys[2]);

    let vectors: Value = serde_json::from_str(OWNER_TARGET_VECTORS).unwrap();
    let vector = vectors["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| {
            item["txid"] == "089f52c8e148672da4663397c0178fa88362fb826c74ae001d33bdedd3398b49"
        })
        .unwrap();
    let signed_script = hex::decode(
        vector["inputs"][0]["signature_script_hex"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let mut arguments = decode_witness_stack(&signed_script);
    let redeem = arguments.pop().unwrap()["data_hex"]
        .as_str()
        .unwrap()
        .to_owned();
    let template: Value = serde_json::from_str(DEED_TEMPLATE).unwrap();
    let original_redeem = hex::decode(&redeem).unwrap();
    let mut previous_state = deed_state_from_script(&original_redeem, &template);
    assert_eq!(
        render_deed_state(&previous_state, &template),
        original_redeem
    );
    let owner_commit = Sha256::digest(keys[0]);
    let target_commit = Sha256::digest(keys[1]);
    previous_state[6] = json!(hex::encode(owner_commit));
    previous_state[8] = json!(hex::encode(target_commit));
    arguments[6] = json!({"data_hex":hex::encode(owner_commit)});
    arguments[8] = json!({"data_hex":hex::encode(target_commit)});
    arguments[11] = json!({"data_hex":"00".repeat(65)});
    arguments[12] = json!({"data_hex":owner_key});
    arguments[13] = json!({"data_hex":owner_key});
    arguments[14] = json!({"data_hex":"00".repeat(65)});
    arguments[15] = json!({"data_hex":target_key});

    let redeem_bytes = render_deed_state(&previous_state, &template);
    let redeem = hex::encode(&redeem_bytes);
    let input_deed_spk = format!(
        "0000aa20{}87",
        hex::encode(ktapeout_cli::name_state_template::blake2b_256(
            &redeem_bytes
        ))
    );
    let mut next_state = previous_state.clone();
    for (index, state) in next_state.iter_mut().enumerate().take(11) {
        *state = state_item(&arguments, index);
    }
    let output_deed_spk =
        ktapeout_cli::name_state_template::deed_state_script_public_key(&next_state)
            .expect("next Deed state is rendered from the frozen template");
    let fee_spk = format!("000020{fee_key}ac");
    let fee = 4_399_120u64;
    let request = json!({
        "inputs":[
            {
                "outpoint":"518143e6a38f029a49ac9dddc06f7c36440c161a5df6743c76555a1e6cf3f58a:0",
                "amount":100_000_000,"block_daa_score":605_673_488,
                "script_public_key":input_deed_spk,"covenant_id":"7d2e5f8c0593c425e6e6f16b67b3f2e5d9e5b735269ccbc71d32c51a4f0f57ea",
                "compute_budget":256,"signature_script":""
            },
            {
                "outpoint":"518143e6a38f029a49ac9dddc06f7c36440c161a5df6743c76555a1e6cf3f58a:1",
                "amount":890_116_730_824u64,"block_daa_score":605_673_488,
                "script_public_key":fee_spk,"covenant_id":null,"compute_budget":10,"signature_script":""
            }
        ],
        "outputs":[
            {"role":"deed_successor","value":100_000_000,"script_public_key":output_deed_spk,"covenant_id":"7d2e5f8c0593c425e6e6f16b67b3f2e5d9e5b735269ccbc71d32c51a4f0f57ea","authorizing_input":0},
            {"role":"fee_change","value":890_112_331_704u64,"script_public_key":fee_spk,"covenant_id":null,"authorizing_input":null}
        ],
        "covenant_witness_contexts":[{"input_index":0,"entrypoint":"change_owner_target","redeem_script_hex":redeem,"arguments":arguments}],
        "role_public_keys":{"deed_owner":owner_key,"target_authority":target_key,"fee":fee_key},
        "fee_sompi":fee
    });
    (request, secrets)
}

fn assemble_owner_target_fixture() -> (Transaction, Vec<UtxoEntry>, Value) {
    let (request, secrets) = owner_target_request();
    let plan = ktapeout_cli::tn10_pipeline::build_native_owner_target_plan(&request)
        .expect("native owner-target plan binds the frozen contract context");
    let authorization = test_authorization(&plan);
    let confirmation = format!("SIGN {}", plan["plan_sha256"].as_str().unwrap());
    let packets = secrets
        .into_iter()
        .map(|secret| {
            ktapeout_cli::tn10_developer_signing::sign_native_registration_partial(
                &plan,
                &authorization,
                secret,
                1500,
                &confirmation,
            )
            .expect("each worthless key signs its matching owner-target role")
        })
        .collect::<Vec<_>>();
    let aggregate = ktapeout_cli::tn10_developer_signing::combine_native_registration_partials(
        &plan,
        &authorization,
        &packets,
        1500,
    )
    .expect("G1c combines owner, target, and fee role partials");
    let rpc: kaspa_rpc_core::RpcTransaction =
        serde_json::from_value(aggregate["transaction"].clone()).unwrap();
    let tx = Transaction::try_from(rpc).expect("assembled transaction parses");
    let utxos = request["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|input| {
            let script = hex::decode(
                input["script_public_key"]
                    .as_str()
                    .unwrap()
                    .strip_prefix("0000")
                    .unwrap(),
            )
            .unwrap();
            let covenant_id = input["covenant_id"]
                .as_str()
                .map(|raw| Hash::from_bytes(hex::decode(raw).unwrap().try_into().unwrap()));
            UtxoEntry::new(
                input["amount"].as_u64().unwrap(),
                ScriptPublicKey::from_vec(0, script),
                input["block_daa_score"].as_u64().unwrap(),
                false,
                covenant_id,
            )
        })
        .collect();
    (tx, utxos, plan)
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

fn assembled_fixture(parent_key: Option<&str>) -> (Transaction, Vec<UtxoEntry>) {
    let value: Value = serde_json::from_str(FIXTURE).expect("fixture must be valid JSON");
    let mut request = value["request"].clone();
    if let Some(key) = parent_key {
        request["role_public_keys"]["parent"] = json!(key);
    }
    for (input, budget) in [10u64, 47, 10].into_iter().enumerate() {
        request["inputs"][input]["compute_budget"] = json!(budget);
    }
    let plan = ktapeout_cli::tn10_pipeline::build_native_registration_plan(&request)
        .expect("public registration planner accepts the fixture");
    let authorization = test_authorization(&plan);
    let confirmation = format!("SIGN {}", plan["plan_sha256"].as_str().unwrap());
    let packets = [1u8, 2, 3]
        .into_iter()
        .map(|scalar| {
            ktapeout_cli::tn10_developer_signing::sign_native_registration_partial(
                &plan,
                &authorization,
                worthless_test_secret(scalar),
                1500,
                &confirmation,
            )
            .expect("worthless fixed fixture key signs its planned roles")
        })
        .collect::<Vec<_>>();
    let aggregate = ktapeout_cli::tn10_developer_signing::combine_native_registration_partials(
        &plan,
        &authorization,
        &packets,
        1500,
    )
    .expect("public G1c path assembles fixture witnesses");
    let rpc: kaspa_rpc_core::RpcTransaction =
        serde_json::from_value(aggregate["transaction"].clone()).unwrap();
    let tx = Transaction::try_from(rpc).expect("assembled RPC transaction parses");
    let utxos = request["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|input| {
            let script = hex::decode(
                input["script_public_key"]
                    .as_str()
                    .unwrap()
                    .strip_prefix("0000")
                    .unwrap(),
            )
            .unwrap();
            let covenant_id = input["covenant_id"]
                .as_str()
                .map(|raw| Hash::from_bytes(hex::decode(raw).unwrap().try_into().unwrap()));
            UtxoEntry::new(
                input["amount"].as_u64().unwrap(),
                ScriptPublicKey::from_vec(0, script),
                input["block_daa_score"].as_u64().unwrap(),
                false,
                covenant_id,
            )
        })
        .collect();
    (tx, utxos)
}

#[test]
fn public_g1c_assembly_executes_real_registration_contracts_in_pinned_vm() {
    let value: Value = serde_json::from_str(FIXTURE).expect("fixture must be valid JSON");
    assert_eq!(
        value["schema"],
        "KTAPEOUT-NATIVE-REGISTRATION-CONTRACT-FIXTURE-V1"
    );
    let mut request = value["request"].clone();
    assert!(
        ktapeout_cli::tn10_pipeline::build_native_registration_plan(&request)
            .unwrap_err()
            .to_string()
            .contains("TN10_REGISTRATION_COMPUTE_BUDGET_INVALID"),
        "the planner must not substitute a preset compute budget"
    );
    for (input, budget) in [10u64, 47, 10].into_iter().enumerate() {
        request["inputs"][input]["compute_budget"] = json!(budget);
    }
    let plan = ktapeout_cli::tn10_pipeline::build_native_registration_plan(&request)
        .expect("public registration planner accepts full 3-input/5-output fixture");
    let authorization = test_authorization(&plan);
    let confirmation = format!("SIGN {}", plan["plan_sha256"].as_str().unwrap());
    let secrets = [
        worthless_test_secret(1),
        worthless_test_secret(2),
        worthless_test_secret(3),
    ];
    let packets = secrets
        .iter()
        .map(|secret| {
            ktapeout_cli::tn10_developer_signing::sign_native_registration_partial(
                &plan,
                &authorization,
                *secret,
                1500,
                &confirmation,
            )
            .expect("fixed worthless fixture keys satisfy planned roles")
        })
        .collect::<Vec<_>>();
    let aggregate = ktapeout_cli::tn10_developer_signing::combine_native_registration_partials(
        &plan,
        &authorization,
        &packets,
        1500,
    )
    .expect("public G1c path assembles the covenant witnesses");
    assert_eq!(aggregate["witness_assembly"], "ASSEMBLED_TOCCATA_INPUTS");
    assert_eq!(
        aggregate["transaction"]["inputs"].as_array().unwrap().len(),
        3
    );
    assert_eq!(
        aggregate["transaction"]["outputs"]
            .as_array()
            .unwrap()
            .len(),
        5
    );

    let rpc: kaspa_rpc_core::RpcTransaction =
        serde_json::from_value(aggregate["transaction"].clone()).unwrap();
    let tx = Transaction::try_from(rpc).expect("assembled RPC transaction parses");
    assert_eq!(
        tx.inputs
            .iter()
            .map(|input| input.compute_commit.compute_budget().unwrap())
            .collect::<Vec<_>>(),
        vec![10, 47, 10],
        "the plan carries per-input budgets measured from full VM execution"
    );
    assert_eq!(
        tx.inputs[2].signature_script.len(),
        66,
        "P2PK scriptSig is a single signature push"
    );
    assert_eq!(tx.inputs[2].signature_script[0], 65);
    assert_eq!(
        tx.outputs[0]
            .covenant
            .as_ref()
            .map(|binding| binding.authorizing_input),
        Some(0)
    );
    assert_eq!(
        tx.outputs[1]
            .covenant
            .as_ref()
            .map(|binding| binding.authorizing_input),
        Some(1)
    );
    let utxos = request["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|input| {
            let script = hex::decode(
                input["script_public_key"]
                    .as_str()
                    .unwrap()
                    .strip_prefix("0000")
                    .unwrap(),
            )
            .unwrap();
            let covenant_id = input["covenant_id"]
                .as_str()
                .map(|raw| Hash::from_bytes(hex::decode(raw).unwrap().try_into().unwrap()));
            UtxoEntry::new(
                input["amount"].as_u64().unwrap(),
                ScriptPublicKey::from_vec(0, script),
                input["block_daa_score"].as_u64().unwrap(),
                false,
                covenant_id,
            )
        })
        .collect::<Vec<_>>();
    let populated = PopulatedTransaction::new(&tx, utxos);
    let metrics = verify_post_toccata_populated_transaction(&populated)
        .expect("pinned v2.1.0 VM accepts every real-contract input");
    assert_eq!(metrics.len(), 3);
    for (index, entrypoint) in [(0usize, "authorize_child"), (1, "register_interior")] {
        let metric = &metrics[index];
        assert!(
            metric.script_units_used > 10_000,
            "{entrypoint} must execute the full real covenant, measured {} units",
            metric.script_units_used
        );
        assert_eq!(metric.compute_budget, [10, 47][index]);
        assert_eq!(metric.input_index, index);
        eprintln!(
            "{entrypoint}: measured script_units={}, compute_budget={}, allowed_script_units={}",
            metric.script_units_used, metric.compute_budget, metric.allowed_script_units
        );
    }
    assert_eq!(metrics[2].compute_budget, 10);
}

#[test]
fn real_contract_vm_rejects_tampered_authority_signature() {
    let (mut tx, utxos) = assembled_fixture(None);
    let signature = push_range(&tx.inputs[0].signature_script, 6)
        .expect("parent role signature is a pushed witness item");
    assert_eq!(signature.len(), 65);
    tx.inputs[0].signature_script[signature.start] ^= 1;
    assert!(
        !verify_fixture_tx(&tx, utxos),
        "real covenant execution must reject a modified authority signature"
    );
}

#[test]
fn real_contract_vm_rejects_tampered_parent_state_argument() {
    let (mut tx, utxos) = assembled_fixture(None);
    let state_argument = push_range(&tx.inputs[0].signature_script, 0)
        .expect("parent state is a pushed witness item");
    assert!(!state_argument.is_empty());
    tx.inputs[0].signature_script[state_argument.start] ^= 1;
    assert!(
        !verify_fixture_tx(&tx, utxos),
        "real covenant execution must reject a modified parent state argument"
    );
}

#[test]
fn real_contract_vm_rejects_role_key_not_committed_by_parent_contract() {
    let alternate_parent_key = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
    let (tx, utxos) = assembled_fixture(Some(alternate_parent_key));
    assert!(
        !verify_fixture_tx(&tx, utxos),
        "the covenant must reject a parent role key that differs from its committed state"
    );
}

#[test]
fn public_g1c_owner_target_assembly_executes_real_deed_contract() {
    let (tx, utxos, plan) = assemble_owner_target_fixture();
    assert_eq!(plan["operation"], "CHANGE_OWNER_TARGET");
    assert_eq!(
        plan["next_owner_xonly"],
        plan["role_public_keys"]["roles"]["deed_owner"]["public_key"]
    );
    assert_eq!(tx.inputs.len(), 2);
    assert_eq!(tx.outputs.len(), 2);
    let metrics = verify_post_toccata_populated_transaction(&PopulatedTransaction::new(&tx, utxos))
        .expect("pinned v2.1.0 executes every owner-target and fee input");
    assert_eq!(metrics.len(), 2);
    assert_eq!(metrics[0].input_index, 0);
    assert_eq!(metrics[1].input_index, 1);
    assert_eq!(metrics[0].compute_budget, 256);
    assert_eq!(metrics[1].compute_budget, 10);
    eprintln!(
        "change_owner_target: measured script_units={}, compute_budget={}, allowed_script_units={}",
        metrics[0].script_units_used, metrics[0].compute_budget, metrics[0].allowed_script_units
    );
}

#[test]
fn owner_target_vm_rejects_modified_signature_state_and_role_key() {
    let (tx, utxos, _) = assemble_owner_target_fixture();
    let mut bad_signature = tx.clone();
    let signature = push_range(&bad_signature.inputs[0].signature_script, 11)
        .expect("owner signature is an encoded witness item");
    assert_eq!(signature.len(), 65);
    bad_signature.inputs[0].signature_script[signature.start] ^= 1;
    assert!(!verify_fixture_tx(&bad_signature, utxos.clone()));

    let mut bad_state = tx.clone();
    let state = push_range(&bad_state.inputs[0].signature_script, 8)
        .expect("target commitment is an encoded witness item");
    bad_state.inputs[0].signature_script[state.start] ^= 1;
    assert!(!verify_fixture_tx(&bad_state, utxos.clone()));

    let mut bad_role_key = tx;
    let role_key = push_range(&bad_role_key.inputs[0].signature_script, 15)
        .expect("target authority key is an encoded witness item");
    assert_eq!(role_key.len(), 32);
    bad_role_key.inputs[0].signature_script[role_key.start] ^= 1;
    assert!(!verify_fixture_tx(&bad_role_key, utxos));
}

#[test]
fn registration_vm_rejects_zero_cross_input_and_replayed_signatures() {
    let (valid_tx, valid_utxos) = assembled_fixture(None);

    let mut zero_signature = valid_tx.clone();
    let signature = push_range(&zero_signature.inputs[0].signature_script, 6).unwrap();
    zero_signature.inputs[0].signature_script[signature].fill(0);
    assert!(!verify_fixture_tx(&zero_signature, valid_utxos.clone()));

    let mut cross_input_signature = valid_tx.clone();
    cross_input_signature.inputs[0].signature_script =
        cross_input_signature.inputs[1].signature_script.clone();
    assert!(!verify_fixture_tx(
        &cross_input_signature,
        valid_utxos.clone()
    ));

    let mut replayed_witness = valid_tx.clone();
    replayed_witness.outputs[4].value = replayed_witness.outputs[4].value.saturating_sub(1);
    assert!(!verify_fixture_tx(&replayed_witness, valid_utxos));
}

#[test]
fn registration_vm_rejects_input_order_and_output_mutations() {
    let (valid_tx, valid_utxos) = assembled_fixture(None);

    let mut reordered_inputs = valid_tx.clone();
    let mut reordered_utxos = valid_utxos.clone();
    reordered_inputs.inputs.swap(0, 1);
    reordered_utxos.swap(0, 1);
    assert!(!verify_fixture_tx(&reordered_inputs, reordered_utxos));

    let mut duplicate_input = valid_tx.clone();
    let mut duplicate_utxos = valid_utxos.clone();
    duplicate_input.inputs[1] = duplicate_input.inputs[0].clone();
    duplicate_utxos[1] = duplicate_utxos[0].clone();
    assert!(!verify_fixture_tx(&duplicate_input, duplicate_utxos));

    let (owner_target_tx, owner_target_utxos, _) = assemble_owner_target_fixture();
    let mut unrelated_deed = valid_tx.clone();
    let mut unrelated_utxo = valid_utxos.clone();
    unrelated_deed.inputs[1] = owner_target_tx.inputs[0].clone();
    unrelated_utxo[1] = owner_target_utxos[0].clone();
    assert!(!verify_fixture_tx(&unrelated_deed, unrelated_utxo));

    let mut reordered_outputs = valid_tx.clone();
    reordered_outputs.outputs.swap(0, 1);
    assert!(!verify_fixture_tx(&reordered_outputs, valid_utxos.clone()));

    let mut changed_amount = valid_tx.clone();
    changed_amount.outputs[0].value = changed_amount.outputs[0].value.saturating_sub(1);
    assert!(!verify_fixture_tx(&changed_amount, valid_utxos.clone()));

    let mut changed_script = valid_tx.clone();
    changed_script.outputs[0].script_public_key = ScriptPublicKey::from_vec(0, vec![0x51]);
    assert!(!verify_fixture_tx(&changed_script, valid_utxos.clone()));

    let mut missing_output = valid_tx.clone();
    missing_output.outputs.pop();
    assert!(!verify_fixture_tx(&missing_output, valid_utxos.clone()));

    let mut extra_output = valid_tx;
    let duplicate = extra_output.outputs[4].clone();
    extra_output.outputs.push(duplicate);
    assert!(!verify_fixture_tx(&extra_output, valid_utxos));
}

#[test]
fn registration_vm_rejects_insufficient_fee_input_and_swallowed_change() {
    let (valid_tx, valid_utxos) = assembled_fixture(None);
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    let fee_input = &fixture["request"]["inputs"][2];
    let fee_script = hex::decode(
        fee_input["script_public_key"]
            .as_str()
            .unwrap()
            .strip_prefix("0000")
            .unwrap(),
    )
    .unwrap();
    let mut insufficient_utxos = valid_utxos.clone();
    insufficient_utxos[2] = UtxoEntry::new(
        1,
        ScriptPublicKey::from_vec(0, fee_script),
        fee_input["block_daa_score"].as_u64().unwrap(),
        false,
        None,
    );
    assert!(!verify_fixture_tx(&valid_tx, insufficient_utxos));

    let mut swallowed_change = valid_tx;
    swallowed_change.outputs[4].value = 0;
    assert!(!verify_fixture_tx(&swallowed_change, valid_utxos));
}

#[test]
fn registration_vm_rejects_bond_below_contract_floor() {
    let (mut tx, utxos) = assembled_fixture(None);
    let asserted_bond = push_range(&tx.inputs[1].signature_script, 20)
        .expect("register_interior witness contains asserted bond");
    assert_eq!(asserted_bond.len(), 4);
    assert_eq!(
        &tx.inputs[1].signature_script[asserted_bond.clone()],
        &[0x00, 0xca, 0x9a, 0x3b]
    );
    tx.inputs[1].signature_script[asserted_bond].fill(0);
    assert!(
        !verify_fixture_tx(&tx, utxos),
        "the real registration covenant must reject bond below its floor"
    );
}

#[test]
fn registration_vm_rejects_parent_sequence_rollback() {
    let (mut tx, utxos) = assembled_fixture(None);
    let previous_state = push_range(&tx.inputs[1].signature_script, 0)
        .expect("register_interior witness begins with previous state");
    assert_eq!(previous_state.len(), 24);
    assert_eq!(
        &tx.inputs[1].signature_script[previous_state.start + 8..previous_state.start + 16],
        &1u64.to_le_bytes(),
        "fixture previous-state sequence starts at one"
    );
    tx.inputs[1].signature_script[previous_state.start + 8..previous_state.start + 16]
        .copy_from_slice(&0u64.to_le_bytes());
    assert!(
        !verify_fixture_tx(&tx, utxos),
        "the real covenant must reject a parent sequence rollback"
    );
}

#[test]
fn registration_vm_rejects_unrelated_gap_input() {
    let (tx, mut utxos) = assembled_fixture(None);
    let fixture: Value = serde_json::from_str(FIXTURE).unwrap();
    let input = &fixture["request"]["inputs"][1];
    let unrelated_gap_script = tx.outputs[1].script_public_key.clone();
    assert_ne!(unrelated_gap_script, utxos[1].script_public_key);
    utxos[1] = UtxoEntry::new(
        tx.outputs[1].value,
        unrelated_gap_script,
        input["block_daa_score"].as_u64().unwrap(),
        false,
        utxos[1].covenant_id,
    );
    assert!(
        !verify_fixture_tx(&tx, utxos),
        "the registration witness must not authorize an unrelated Gap state"
    );
}

#[test]
fn registration_vm_rejects_other_role_signature_substitution() {
    let (mut tx, utxos) = assembled_fixture(None);
    let parent_signature = push_range(&tx.inputs[0].signature_script, 6)
        .expect("input zero carries the parent authority signature");
    let registration_signature = (0..64)
        .filter_map(|index| push_range(&tx.inputs[1].signature_script, index))
        .find(|range| range.len() == 65)
        .expect("input one carries a role signature");
    assert_eq!(parent_signature.len(), 65);
    let other_role_signature = tx.inputs[0].signature_script[parent_signature].to_vec();
    tx.inputs[1].signature_script[registration_signature].copy_from_slice(&other_role_signature);
    assert!(
        !verify_fixture_tx(&tx, utxos),
        "the contract must reject a signature from a different role/input"
    );
}

#[test]
fn owner_target_vm_rejects_zero_signature_and_cross_path_witness() {
    let (owner_tx, owner_utxos, _) = assemble_owner_target_fixture();

    let mut zero_signature = owner_tx.clone();
    let signature = push_range(&zero_signature.inputs[0].signature_script, 11).unwrap();
    zero_signature.inputs[0].signature_script[signature].fill(0);
    assert!(!verify_fixture_tx(&zero_signature, owner_utxos.clone()));

    let (mut registration_tx, registration_utxos) = assembled_fixture(None);
    registration_tx.inputs[0].signature_script = owner_tx.inputs[0].signature_script.clone();
    assert!(!verify_fixture_tx(&registration_tx, registration_utxos));
}
