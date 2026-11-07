use ktapeout_runtime::valid_operation_id;

#[test]
fn operation_id_requires_lowercase_32_digit_hex() {
    assert!(valid_operation_id(&format!("op_{}", "a".repeat(32))));
    assert!(!valid_operation_id(&format!("op_{}", "A".repeat(32))));
    assert!(!valid_operation_id("op_short"));
}
