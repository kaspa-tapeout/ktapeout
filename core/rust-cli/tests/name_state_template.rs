//! Contract-test exception rationale: this external test exercises the frozen public Deed
//! template and its compiler-derived state vectors; it contains no application-specific tests.

use ktapeout_cli::name_state_template::{
    blake2b_256, deed_state_script_public_key, embedded_deed_template, template_hash,
};
use serde_json::Value;

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
