//! Contract-test exception rationale: this external test verifies frozen generic
//! namespace and Gap compiler templates with state-splice vectors, not an application.

use ktapeout_cli::registry_templates::{render, ByteWrite, RegistryTemplate};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn bytes(hex_text: &str) -> Vec<u8> {
    hex::decode(hex_text).expect("canonical template hex")
}

fn apply_writes(template: &[u8], writes: &[Value]) -> Vec<u8> {
    let mut output = template.to_vec();
    for write in writes {
        let offset = write["offset"].as_u64().unwrap() as usize;
        let replacement = bytes(write["hex"].as_str().unwrap());
        let end = offset + replacement.len();
        output[offset..end].copy_from_slice(&replacement);
    }
    output
}

fn assert_compiler_vectors(template_hex: &str, vectors: &[Value]) {
    let template = bytes(template_hex);
    for vector in vectors {
        let spliced = apply_writes(&template, vector["writes"].as_array().unwrap());
        let digest = hex::encode(Sha256::digest(&spliced));
        assert_eq!(digest, vector["compiler_script_sha256"].as_str().unwrap());
    }
}

fn runtime_writes(template_hex: &str, mutable: &[Value], writes: &[Value]) -> Vec<ByteWrite> {
    let template = bytes(template_hex);
    let mut result = mutable
        .iter()
        .map(|site| {
            let offset = site["offset"].as_u64().unwrap() as usize;
            let length = site["length"].as_u64().unwrap() as usize;
            ByteWrite {
                offset,
                bytes: template[offset..offset + length].to_vec(),
            }
        })
        .collect::<Vec<_>>();
    for write in writes {
        let offset = write["offset"].as_u64().unwrap() as usize;
        let target = result
            .iter_mut()
            .find(|item| item.offset == offset)
            .unwrap();
        target.bytes = bytes(write["hex"].as_str().unwrap());
    }
    result
}

#[test]
fn finite_and_unbounded_kind_zero_gap_templates_match_compiler_splices() {
    let data: Value = serde_json::from_str(include_str!(
        "../../../data/registry/adapter-gap-state-template-v1.json"
    ))
    .unwrap();
    assert_eq!(data["kind"], 0);
    assert_eq!(data["variants"].as_array().unwrap().len(), 2);
    assert_eq!(
        data["source_sha256"],
        "845d9e26c63ca2ee1b27f09ce591b4eb7ccfe46c86d0ca79e1ef02b75106ea2e"
    );

    for variant in data["variants"].as_array().unwrap() {
        let template = bytes(variant["template_hex"].as_str().unwrap());
        assert_eq!(
            hex::encode(Sha256::digest(&template)),
            variant["script_sha256"].as_str().unwrap()
        );
        assert_compiler_vectors(
            variant["template_hex"].as_str().unwrap(),
            variant["vectors"].as_array().unwrap(),
        );
        let template = if variant["hi_is_max"] == 0 {
            RegistryTemplate::GapFinite
        } else {
            RegistryTemplate::GapUnbounded
        };
        for vector in variant["vectors"].as_array().unwrap() {
            let compiler_bytes = apply_writes(
                &bytes(variant["template_hex"].as_str().unwrap()),
                vector["writes"].as_array().unwrap(),
            );
            let rendered = render(
                template,
                &runtime_writes(
                    variant["template_hex"].as_str().unwrap(),
                    variant["mutable"].as_array().unwrap(),
                    vector["writes"].as_array().unwrap(),
                ),
            )
            .unwrap();
            assert_eq!(
                rendered, compiler_bytes,
                "Gap template hi_is_max={} byte splice",
                variant["hi_is_max"]
            );
            assert_eq!(
                hex::encode(Sha256::digest(rendered)),
                vector["compiler_script_sha256"].as_str().unwrap()
            );
        }
    }
    let finite = &data["variants"][0];
    assert_eq!(finite["hi_is_max"], 0);
    assert_eq!(finite["mutable"][0]["offset"], 20);
    assert_eq!(finite["mutable"][1]["offset"], 53);
    let unbounded = &data["variants"][1];
    assert_eq!(unbounded["hi_is_max"], 1);
    assert_eq!(unbounded["fixed"][0]["offset"], 53);
}

#[test]
fn five_field_adapter_parent_namespace_template_matches_compiler_splice() {
    let data: Value = serde_json::from_str(include_str!(
        "../../../data/registry/adapter-parent-state-template-v1.json"
    ))
    .unwrap();
    assert_eq!(
        data["source_sha256"],
        "5808c120b5c5200d8cff9dda8b76068590bd17236bdd0264dc7918d140bfe92c"
    );
    let offsets = data["mutable"]
        .as_array()
        .unwrap()
        .iter()
        .map(|field| field["offset"].as_u64().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(offsets, [2, 35, 68, 101, 134]);
    assert_eq!(data["mutable"][4]["encoding"], "uint64-le");
    assert_compiler_vectors(
        data["template_hex"].as_str().unwrap(),
        data["vectors"].as_array().unwrap(),
    );
    for vector in data["vectors"].as_array().unwrap() {
        let compiler_bytes = apply_writes(
            &bytes(data["template_hex"].as_str().unwrap()),
            vector["writes"].as_array().unwrap(),
        );
        let rendered = render(
            RegistryTemplate::AdapterParent,
            &runtime_writes(
                data["template_hex"].as_str().unwrap(),
                data["mutable"].as_array().unwrap(),
                vector["writes"].as_array().unwrap(),
            ),
        )
        .unwrap();
        assert_eq!(
            rendered, compiler_bytes,
            "five-field adapter-parent byte splice"
        );
        assert_eq!(
            hex::encode(Sha256::digest(rendered)),
            vector["compiler_script_sha256"].as_str().unwrap()
        );
    }
}

#[test]
fn nine_field_issuance_certificate_name_and_parent_id_splice_match_compiler() {
    let data: Value = serde_json::from_str(include_str!(
        "../../../data/registry/namespace-issuance-certificate-template-v1.json"
    ))
    .unwrap();
    assert_eq!(
        data["source_sha256"],
        "d18528abbaffd2b77694480266ae524fcffb61dbc8510480c11e327f84a44af5"
    );
    assert_eq!(data["state_layout"]["start"], 0);
    assert_eq!(data["state_layout"]["length"], 150);
    let offsets = data["mutable"]
        .as_array()
        .unwrap()
        .iter()
        .map(|field| field["offset"].as_u64().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(offsets, [85, 118]);
    assert_compiler_vectors(
        data["template_hex"].as_str().unwrap(),
        data["vectors"].as_array().unwrap(),
    );
    for vector in data["vectors"].as_array().unwrap() {
        let compiler_bytes = apply_writes(
            &bytes(data["template_hex"].as_str().unwrap()),
            vector["writes"].as_array().unwrap(),
        );
        let rendered = render(
            RegistryTemplate::IssuanceCertificate,
            &runtime_writes(
                data["template_hex"].as_str().unwrap(),
                data["mutable"].as_array().unwrap(),
                vector["writes"].as_array().unwrap(),
            ),
        )
        .unwrap();
        assert_eq!(
            rendered, compiler_bytes,
            "nine-field issuance-certificate byte splice"
        );
        assert_eq!(
            &rendered[data["state_layout"]["start"].as_u64().unwrap() as usize
                ..(data["state_layout"]["start"].as_u64().unwrap()
                    + data["state_layout"]["length"].as_u64().unwrap()) as usize],
            &compiler_bytes[data["state_layout"]["start"].as_u64().unwrap() as usize
                ..(data["state_layout"]["start"].as_u64().unwrap()
                    + data["state_layout"]["length"].as_u64().unwrap()) as usize],
            "issuance-certificate 150-byte state splice"
        );
        assert_eq!(
            hex::encode(Sha256::digest(rendered)),
            vector["compiler_script_sha256"].as_str().unwrap()
        );
    }
}

#[test]
fn runtime_registry_renderer_rejects_missing_duplicate_fixed_and_wrong_length_writes() {
    let valid = ByteWrite {
        offset: 20,
        bytes: vec![0x33; 32],
    };
    assert_eq!(
        render(RegistryTemplate::GapFinite, &[]).unwrap_err(),
        "REGISTRY_TEMPLATE_WRITE_SET_INCOMPLETE"
    );
    assert_eq!(
        render(
            RegistryTemplate::GapFinite,
            &[
                valid.clone(),
                valid.clone(),
                valid.clone(),
                valid.clone(),
                valid.clone(),
                valid.clone(),
                valid.clone()
            ]
        )
        .unwrap_err(),
        "REGISTRY_TEMPLATE_WRITE_DUPLICATE"
    );
    assert_eq!(
        render(
            RegistryTemplate::GapUnbounded,
            &[
                ByteWrite {
                    offset: 53,
                    bytes: vec![0; 32],
                },
                ByteWrite {
                    offset: 20,
                    bytes: vec![0; 32],
                },
                ByteWrite {
                    offset: 95,
                    bytes: vec![0; 32],
                },
                ByteWrite {
                    offset: 128,
                    bytes: vec![0; 32],
                },
                ByteWrite {
                    offset: 161,
                    bytes: vec![0; 32],
                },
                ByteWrite {
                    offset: 194,
                    bytes: vec![0; 32],
                },
            ],
        )
        .unwrap_err(),
        "REGISTRY_TEMPLATE_WRITE_NOT_MUTABLE"
    );
    let mut wrong_length = valid;
    wrong_length.bytes.pop();
    assert_eq!(
        render(
            RegistryTemplate::GapFinite,
            &[
                wrong_length,
                ByteWrite {
                    offset: 53,
                    bytes: vec![0; 32]
                },
                ByteWrite {
                    offset: 95,
                    bytes: vec![0; 32]
                },
                ByteWrite {
                    offset: 128,
                    bytes: vec![0; 32]
                },
                ByteWrite {
                    offset: 161,
                    bytes: vec![0; 32]
                },
                ByteWrite {
                    offset: 194,
                    bytes: vec![0; 32]
                },
                ByteWrite {
                    offset: 227,
                    bytes: vec![0; 32]
                },
            ],
        )
        .unwrap_err(),
        "REGISTRY_TEMPLATE_WRITE_LENGTH_MISMATCH"
    );
}
