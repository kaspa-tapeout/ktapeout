//! Contract-test exception rationale: this external test exercises the frozen public Deed
//! template and its compiler-derived state vectors; it contains no application-specific tests.

use ktapeout_cli::name_state_template::{
    blake2b_256, deed_state_script_public_key, embedded_deed_template, template_hash,
};
use serde_json::Value;

#[test]
fn official_registration_outputs_match_saved_transactions() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../data/registry/adapter-registry-live-vectors-v1.json"
    ))
    .unwrap();
    for vector in fixture["vectors"].as_array().unwrap().iter().skip(1) {
        let scripts =
            ktapeout_cli::registry_templates::registration_output_scripts(&vector["state"])
                .unwrap();
        for (index, script) in scripts.iter().enumerate() {
            assert_eq!(
                script,
                vector["saved_transaction"]["outputs"][index]["scriptPublicKey"]
                    .as_str()
                    .unwrap(),
                "{} output {index}",
                vector["txid"]
            );
        }
    }
}

#[test]
fn registration_witness_requires_both_input_script_commitments() {
    use ktapeout_cli::registry_templates::registration_witness_for_inputs;
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../data/registry/adapter-registry-live-vectors-v1.json"
    ))
    .unwrap();
    for vector in fixture["vectors"].as_array().unwrap() {
        let scripts = ["parent_redeem_hex", "gap_redeem_hex"].map(|field| {
            let redeem = hex::decode(vector[field].as_str().unwrap()).unwrap();
            [
                vec![0, 0, 0xaa, 0x20],
                blake2b_256(&redeem).to_vec(),
                vec![0x87],
            ]
            .concat()
        });
        assert!(registration_witness_for_inputs(&vector["state"], &scripts).is_ok());
        let contexts = ktapeout_cli::registry_templates::registration_contexts_for_inputs(
            &vector["state"],
            &scripts,
        )
        .unwrap();
        for (index, field) in ["parent_redeem_hex", "gap_redeem_hex"].iter().enumerate() {
            assert_eq!(contexts[index]["input_index"], index);
            assert_eq!(contexts[index]["redeem_script_hex"], vector[field]);
            assert_eq!(
                contexts[index]["arguments"].as_array().unwrap().len(),
                [8, 29][index]
            );
            use ktapeout_kaspa_verifier::toccata_witness::{
                build_toccata_p2sh_witness, AbiEntryPoint, WitnessItem,
            };
            let arguments: Vec<_> = contexts[index]["arguments"]
                .as_array()
                .unwrap()
                .iter()
                .map(|item| {
                    if let Some(opcode) = item["opcode"].as_u64() {
                        WitnessItem::Opcode(opcode as u8)
                    } else {
                        WitnessItem::Data(hex::decode(item["data_hex"].as_str().unwrap()).unwrap())
                    }
                })
                .collect();
            let rebuilt = build_toccata_p2sh_witness(
                AbiEntryPoint::parse(contexts[index]["entrypoint"].as_str().unwrap()).unwrap(),
                &arguments,
                &hex::decode(vector[field].as_str().unwrap()).unwrap(),
            )
            .unwrap();
            assert_eq!(
                hex::encode(rebuilt),
                vector["unsigned_signature_scripts"][index]
            );
        }
        for index in 0..2 {
            let mut changed = scripts.clone();
            changed[index][4] ^= 1;
            assert_eq!(
                ktapeout_cli::registry_templates::registration_contexts_for_inputs(
                    &vector["state"],
                    &changed,
                )
                .err(),
                Some("REGISTRATION_INPUT_SCRIPT_MISMATCH")
            );
            assert_eq!(
                registration_witness_for_inputs(&vector["state"], &changed).err(),
                Some("REGISTRATION_INPUT_SCRIPT_MISMATCH"),
                "input {index}"
            );
        }
    }
}

#[test]
fn registration_witness_rejects_unbound_name_frames_and_lineage() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../data/registry/adapter-registry-live-vectors-v1.json"
    ))
    .unwrap();
    let original = &fixture["vectors"][0]["state"];
    for field in ["namespace_frame", "slug_frame", "registry_root"] {
        let mut state = original.clone();
        let mut bytes = hex::decode(state[field].as_str().unwrap()).unwrap();
        let index = if field.ends_with("_frame") { 2 } else { 0 };
        bytes[index] ^= 1;
        state[field] = hex::encode(bytes).into();
        assert_eq!(
            ktapeout_cli::registry_templates::registration_witness(&state).err(),
            Some("REGISTRATION_STATE_INVALID"),
            "{field}"
        );
    }
    let mut state = original.clone();
    let mut frame = hex::decode(state["slug_frame"].as_str().unwrap()).unwrap();
    frame[63] = 1;
    state["slug_frame"] = hex::encode(frame).into();
    assert_eq!(
        ktapeout_cli::registry_templates::registration_witness(&state).err(),
        Some("REGISTRATION_STATE_INVALID")
    );
}

#[test]
fn registration_witnesses_match_four_saved_transactions() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../data/registry/adapter-registry-live-vectors-v1.json"
    ))
    .unwrap();
    let vectors = fixture["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 4);
    for vector in vectors {
        let scripts =
            ktapeout_cli::registry_templates::registration_witness(&vector["state"]).unwrap();
        for (index, script) in scripts.iter().enumerate() {
            assert_eq!(
                hex::encode(script),
                vector["unsigned_signature_scripts"][index]
                    .as_str()
                    .unwrap(),
                "{} input {index}",
                vector["txid"]
            );
        }
    }
}

#[test]
fn registration_redeems_match_four_saved_transactions() {
    use ktapeout_cli::registry_templates::{
        render, render_registration_gap, ByteWrite, RegistryTemplate,
    };
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../data/registry/adapter-registry-live-vectors-v1.json"
    ))
    .unwrap();
    let vectors = fixture["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 4);
    for vector in vectors {
        let writes = |field: &str| {
            vector[field]
                .as_array()
                .unwrap()
                .iter()
                .map(|write| ByteWrite {
                    offset: write["offset"].as_u64().unwrap() as usize,
                    bytes: hex::decode(write["hex"].as_str().unwrap()).unwrap(),
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(
            hex::encode(render(RegistryTemplate::AdapterParent, &writes("parent_writes")).unwrap()),
            vector["parent_redeem_hex"].as_str().unwrap(),
            "parent {}",
            vector["txid"]
        );
        assert_eq!(
            hex::encode(
                render_registration_gap(
                    vector["state"]["gap_hi_is_max"].as_u64().unwrap() == 1,
                    &writes("gap_writes"),
                )
                .unwrap()
            ),
            vector["gap_redeem_hex"].as_str().unwrap(),
            "gap {}",
            vector["txid"]
        );
    }
}

#[test]
fn matches_all_compiler_derived_deed_vectors() {
    let vectors: Value = serde_json::from_str(include_str!("fixtures/registry-deed-state-v1.json"))
        .expect("checked-in vector JSON");
    assert_eq!(vectors["valid"].as_array().unwrap().len(), 4);
    assert_eq!(vectors["invalid"].as_array().unwrap().len(), 5);

    for vector in vectors["valid"].as_array().unwrap() {
        let state = vector["state_args"].as_array().unwrap();
        assert_eq!(
            deed_state_script_public_key(state).unwrap(),
            vector["script_public_key"].as_str().unwrap(),
            "{}",
            vector["name"]
        );
    }
    for vector in vectors["invalid"].as_array().unwrap() {
        let state = vector["state_args"].as_array().unwrap();
        assert!(
            deed_state_script_public_key(state).is_err(),
            "{}",
            vector["name"]
        );
    }
}

#[test]
fn uses_blake2b_256_and_unambiguous_fixed_width_template_framing() {
    assert_eq!(
        hex::encode(blake2b_256(b"")),
        "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"
    );
    assert_ne!(
        template_hash(b"a", b"bc").unwrap(),
        template_hash(b"ab", b"c").unwrap()
    );
    assert_eq!(
        hex::encode(template_hash(b"a", b"bc").unwrap()),
        "77bbcab7072b897c548327378f11776f4853104c71bdb95a12ded5d2783523bf"
    );
}

#[test]
fn pins_the_public_deed_kind_one_template_to_its_compiler_source() {
    let template = embedded_deed_template().expect("pinned Deed template");
    assert_eq!(template.schema, "KTAPEOUT-DEED-STATE-TEMPLATE-V1");
    assert_eq!(
        template.contract_source_sha256,
        "845d9e26c63ca2ee1b27f09ce591b4eb7ccfe46c86d0ca79e1ef02b75106ea2e"
    );
    assert_eq!(
        template.template_sha256,
        "cce09f84208dc13f009bb4516e8631f65c2a5a7242572ea306ed15a0185bdf6c"
    );
    assert_eq!(template.fixed_state.get("0"), Some(&1));
    assert_eq!(template.fixed_state.get("4"), Some(&0));
    assert_eq!(template.fixed_state.get("13"), Some(&1));
    assert_eq!(template.fixed_state.get("14"), Some(&867));
}
