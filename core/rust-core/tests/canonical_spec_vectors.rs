use ktapeout_core::{
    collective_seal_commitment, decode_collective_seal, decode_partition_action,
    decode_partition_layout, encode_collective_seal, encode_partition_action,
    encode_partition_layout, partition_action_commitment, partition_layout_commitment,
};
use serde_json::Value;

const RECORD_VECTORS: &str = include_str!("../../../spec/ktapeout-core-v0.5.0-record-vectors.json");

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0, "hex vector must contain whole bytes");
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                _ => panic!("invalid hex byte in spec vector"),
            };
            digit(pair[0]) * 16 + digit(pair[1])
        })
        .collect()
}

fn commitment_hex(bytes: [u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn vectors() -> Vec<Value> {
    let document: Value = serde_json::from_str(RECORD_VECTORS).expect("spec vectors are JSON");
    assert_eq!(document["schema"], "ktapeout-core-v0.5.0-record-vectors");
    document["vectors"]
        .as_array()
        .expect("spec vectors are an array")
        .clone()
}

fn roundtrip(vector: &Value) -> Vec<u8> {
    let bytes = decode_hex(vector["canonical_bytes_hex"].as_str().unwrap());
    let expected_commitment = vector["commitment_sha256"].as_str().unwrap();

    let (encoded, commitment) = match vector["record_kind"].as_str().unwrap() {
        "partition_layout" => {
            let decoded = decode_partition_layout(&bytes).expect("decode layout vector");
            (
                encode_partition_layout(&decoded).expect("encode layout vector"),
                commitment_hex(partition_layout_commitment(&decoded).expect("layout commitment")),
            )
        }
        "partition_action" => {
            let decoded = decode_partition_action(&bytes).expect("decode action vector");
            (
                encode_partition_action(&decoded).expect("encode action vector"),
                commitment_hex(partition_action_commitment(&decoded).expect("action commitment")),
            )
        }
        "collective_seal" => {
            let decoded = decode_collective_seal(&bytes).expect("decode seal vector");
            (
                encode_collective_seal(&decoded).expect("encode seal vector"),
                commitment_hex(collective_seal_commitment(&decoded).expect("seal commitment")),
            )
        }
        kind => panic!("unsupported record kind in spec vectors: {kind}"),
    };

    assert_eq!(encoded, bytes, "canonical encoding differs for {vector}");
    assert_eq!(
        commitment, expected_commitment,
        "commitment differs for {vector}"
    );
    bytes
}

#[test]
fn canonical_record_vectors_match_spec_bytes_and_commitments() {
    let vectors = vectors();
    assert_eq!(
        vectors.len(),
        3,
        "update this test when the spec vector set changes"
    );

    for vector in &vectors {
        roundtrip(vector);
    }
}

#[test]
fn record_decoders_reject_trailing_bytes_after_spec_vectors() {
    for vector in vectors() {
        let mut bytes = roundtrip(&vector);
        bytes.push(0);

        let error = match vector["record_kind"].as_str().unwrap() {
            "partition_layout" => decode_partition_layout(&bytes).map(|_| ()),
            "partition_action" => decode_partition_action(&bytes).map(|_| ()),
            "collective_seal" => decode_collective_seal(&bytes).map(|_| ()),
            kind => panic!("unsupported record kind in spec vectors: {kind}"),
        };

        assert!(error.is_err(), "decoder accepted trailing data: {vector}");
    }
}
