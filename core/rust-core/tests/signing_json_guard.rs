use ktapeout_core::guard_external_signing_json_050;

#[test]
fn signing_json_guard_accepts_an_object_and_rejects_other_roots() {
    assert!(guard_external_signing_json_050(br#"{"transaction":{}}"#).is_ok());
    assert!(guard_external_signing_json_050(b"[]").is_err());
    assert!(guard_external_signing_json_050(b"").is_err());
}
