use std::{
    fs,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

#[test]
fn test_key_info_derives_public_identity_without_emitting_secret() {
    let id = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("ktape-test-key-info-{}-{id}", std::process::id()));
    fs::create_dir(&dir).unwrap();
    let key_file = dir.join("test-key.txt");
    let synthetic_scalar_hex = format!("{}\n", "00".repeat(31) + "01");
    fs::write(&key_file, &synthetic_scalar_hex).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&key_file, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let result = Command::new(env!("CARGO_BIN_EXE_ktape"))
        .args(["name", "test-key-info"])
        .arg(&key_file)
        .output()
        .unwrap();
    let stdout = String::from_utf8(result.stdout).unwrap();
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(result.status.success(), "{stderr}");
    let response: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        response["data"]["public_key_xonly"],
        "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    );
    assert_eq!(response["data"]["network"], "testnet-10");
    assert_eq!(response["data"]["secret_emitted"], false);
    assert!(!stdout.contains(synthetic_scalar_hex.trim()));
}

#[test]
fn issuance_transition_signer_emits_only_owned_input_packet() {
    let secret = {
        let mut bytes = [0u8; 32];
        bytes[31] = 3;
        bytes
    };
    let hash = "ab".repeat(32);
    let second_secret = {
        let mut bytes = [0u8; 32];
        bytes[31] = 4;
        bytes
    };
    let secp = secp256k1::Secp256k1::new();
    let second_key = secp256k1::Keypair::from_secret_key(
        &secp,
        &secp256k1::SecretKey::from_slice(&second_secret).unwrap(),
    )
    .x_only_public_key()
    .0;
    let signing = serde_json::json!({
        "requests":[
            {
                "native_plan_hash":hash.clone(),
                "input_index":0,
                "signer_public_key":"f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
                "sighash":"11".repeat(32)
            },
            {
                "native_plan_hash":hash,
                "input_index":1,
                "signer_public_key":hex::encode(second_key.serialize()),
                "sighash":"33".repeat(32)
            }
        ]
    });
    assert_eq!(
        ktapeout_cli::tn10_developer_signing::sign_issuance_transition_partial(
            &signing,
            secret,
            "SIGN invalid"
        )
        .unwrap_err()
        .to_string(),
        "NAMESPACE_ISSUANCE_SIGN_CONFIRMATION_REQUIRED"
    );
    let packets = ktapeout_cli::tn10_developer_signing::sign_issuance_transition_partial(
        &signing,
        secret,
        &format!("SIGN {hash}"),
    )
    .unwrap();
    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0]["input_index"], 0);
    assert_eq!(
        packets[0]["signer_public_key"],
        "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
    );
    let second_packets = ktapeout_cli::tn10_developer_signing::sign_issuance_transition_partial(
        &signing,
        second_secret,
        &format!("SIGN {hash}"),
    )
    .unwrap();
    let combined = ktapeout_cli::tn10_developer_signing::append_issuance_transition_packets(
        &signing,
        &packets,
        second_packets.clone(),
    )
    .unwrap();
    assert_eq!(combined.len(), 2);
    assert!(
        ktapeout_cli::tn10_developer_signing::append_issuance_transition_packets(
            &signing,
            &combined,
            second_packets,
        )
        .is_err()
    );
}

#[test]
fn issuance_transition_rejects_mainnet_before_writing_output() {
    let id = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir =
        std::env::temp_dir().join(format!("ktape-issuance-scope-{}-{id}", std::process::id()));
    fs::create_dir(&dir).unwrap();
    let input = dir.join("request.json");
    let output = dir.join("result.json");
    fs::write(&input, br#"{"action":"profile_state_transition","request":{"network":"mainnet","operation":"ISSUE_NAMESPACE"}}"#).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_ktape"))
        .args(["name", "issuance-transition", "plan"])
        .arg(&input)
        .arg(&output)
        .output()
        .unwrap();
    let absent = !output.exists();
    fs::remove_file(&input).unwrap();
    fs::remove_dir(&dir).unwrap();
    assert!(!result.status.success());
    assert!(absent);
    let diagnostic = format!(
        "{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        diagnostic.contains("NAMESPACE_ISSUANCE_TRANSITION_SCOPE_INVALID"),
        "{diagnostic}"
    );
}

#[test]
fn issuance_transition_does_not_expose_registry_root_genesis() {
    let id = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "ktape-issuance-root-genesis-{}-{id}",
        std::process::id()
    ));
    fs::create_dir(&dir).unwrap();
    let input = dir.join("request.json");
    let output = dir.join("result.json");
    fs::write(
        &input,
        br#"{"action":"profile_state_transition","request":{"network":"testnet-10","operation":"GENESIS"}}"#,
    )
    .unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_ktape"))
        .args(["name", "issuance-transition", "plan"])
        .arg(&input)
        .arg(&output)
        .output()
        .unwrap();
    let absent = !output.exists();
    fs::remove_file(&input).unwrap();
    fs::remove_dir(&dir).unwrap();
    assert!(!result.status.success());
    assert!(absent);
    let diagnostic = format!(
        "{}{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        diagnostic.contains("NAMESPACE_ISSUANCE_TRANSITION_SCOPE_INVALID"),
        "{diagnostic}"
    );
}
