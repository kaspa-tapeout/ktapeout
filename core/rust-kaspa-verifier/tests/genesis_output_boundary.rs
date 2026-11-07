use ktapeout_kaspa_verifier::covenant_id_from_genesis_v1;

#[test]
fn genesis_covenant_id_rejects_an_empty_output_group() {
    let error = covenant_id_from_genesis_v1([0; 32], 0, &[]).unwrap_err();
    assert_eq!(error.0, "GENESIS_OUTPUT_GROUP_INVALID");
}
