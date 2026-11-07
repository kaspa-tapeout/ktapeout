#![cfg(feature = "tn10-network")]

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

fn temp_dir() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "kt-tn10-io-paths-{}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&path).unwrap();
    path
}

#[test]
fn verify_rejects_same_input_and_output_without_clobbering_evidence() {
    let dir = temp_dir();
    let evidence = dir.join("evidence.json");
    let original = br#"{"network":"testnet-10","nodes":[]}"#;
    fs::write(&evidence, original).unwrap();

    let result = Command::new(env!("CARGO_BIN_EXE_ktape"))
        .args(["tn10", "verify"])
        .arg(&evidence)
        .arg(&evidence)
        .output()
        .unwrap();

    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("TN10_INPUT_OUTPUT_PATHS_MUST_DIFFER"));
    assert_eq!(fs::read(evidence).unwrap(), original);
}

#[test]
fn verify_rejects_symlink_output_without_changing_target() {
    let dir = temp_dir();
    let request = dir.join("request.json");
    let target = dir.join("target.json");
    let output = dir.join("verify.json");
    fs::write(&request, br#"{"network":"testnet-10","nodes":[]}"#).unwrap();
    let original = b"keep this file unchanged";
    fs::write(&target, original).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(&target, &output).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&target, &output).unwrap();

    let result = Command::new(env!("CARGO_BIN_EXE_ktape"))
        .args(["tn10", "verify"])
        .arg(&request)
        .arg(&output)
        .output()
        .unwrap();

    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("TN10_OUTPUT_SYMLINK_REJECTED"));
    assert_eq!(fs::read(target).unwrap(), original);
}

#[test]
fn utxos_rejects_same_input_and_output_before_network_access() {
    let dir = temp_dir();
    let request = dir.join("request.json");
    let original = br#"{"network":"testnet-10","nodes":[]}"#;
    fs::write(&request, original).unwrap();

    let result = Command::new(env!("CARGO_BIN_EXE_ktape"))
        .args(["tn10", "utxos"])
        .arg(&request)
        .arg(&request)
        .output()
        .unwrap();

    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("TN10_INPUT_OUTPUT_PATHS_MUST_DIFFER"));
    assert_eq!(fs::read(request).unwrap(), original);
}

#[test]
fn tn10_commands_reject_untrusted_endpoint_forms_before_connecting() {
    let dir = temp_dir();
    let request = dir.join("request.json");
    fs::write(&request, br#"{"network":"testnet-10","nodes":[]}"#).unwrap();

    let invalid = [
        "wss://localhost/kaspa/testnet-10/wrpc/borsh",
        "wss://127.0.0.1/kaspa/testnet-10/wrpc/borsh",
        "wss://10.2.3.4/kaspa/testnet-10/wrpc/borsh",
        "wss://169.254.3.4/kaspa/testnet-10/wrpc/borsh",
        "wss://0x7f.0.0.1/kaspa/testnet-10/wrpc/borsh",
        "wss://0xa.1.1.1/kaspa/testnet-10/wrpc/borsh",
        "wss://node.example./kaspa/testnet-10/wrpc/borsh",
        "wss://user:pw@node.example/kaspa/testnet-10/wrpc/borsh",
        "wss://node.example/kaspa/testnet-10/wrpc/borsh?token=x",
        "wss://[::1]/kaspa/testnet-10/wrpc/borsh",
    ];
    let good = "wss://other.example/kaspa/testnet-10/wrpc/borsh";
    for endpoint in invalid {
        let verify = Command::new(env!("CARGO_BIN_EXE_ktape"))
            .args(["tn10", "verify"])
            .arg(&request)
            .arg(dir.join("verify.json"))
            .env("KTAPE_TN10_ENDPOINTS", format!("{endpoint};{good}"))
            .output()
            .unwrap();
        assert!(!verify.status.success(), "verify accepted {endpoint}");

        let locate = Command::new(env!("CARGO_BIN_EXE_ktape"))
            .args(["tn10", "locate"])
            .arg(&request)
            .arg(dir.join("locate.json"))
            .env("KTAPE_TN10_ENDPOINTS", format!("{endpoint};{good}"))
            .output()
            .unwrap();
        assert!(!locate.status.success(), "locate accepted {endpoint}");

        let utxos = Command::new(env!("CARGO_BIN_EXE_ktape"))
            .args(["tn10", "utxos"])
            .arg(&request)
            .arg(dir.join("utxos.json"))
            .env("KTAPE_TN10_ENDPOINTS", format!("{endpoint};{good}"))
            .output()
            .unwrap();
        assert!(!utxos.status.success(), "utxos accepted {endpoint}");

        let submit = Command::new(env!("CARGO_BIN_EXE_ktape"))
            .args(["tn10", "submit"])
            .arg(&request)
            .arg(dir.join("submit.json"))
            .env("KTAPE_TN10_ENDPOINT", endpoint)
            .output()
            .unwrap();
        assert!(!submit.status.success(), "submit accepted {endpoint}");

        for output in [verify, locate, utxos, submit] {
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                stderr.contains("TN10_ENDPOINT_INVALID")
                    || stderr.contains("TN10_ENDPOINT_PUBLIC_DNS_REQUIRED"),
                "unexpected endpoint error for {endpoint}: {stderr}"
            );
        }
    }
}

#[test]
fn endpoint_accepts_public_dns_hostname_without_connecting() {
    let dir = temp_dir();
    let request = dir.join("request.json");
    fs::write(&request, br#"{"network":"testnet-10","nodes":[]}"#).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_ktape"))
        .args(["tn10", "verify"])
        .arg(&request)
        .arg(dir.join("verify.json"))
        .env(
            "KTAPE_TN10_ENDPOINTS",
            "wss://node-a.example/kaspa/testnet-10/wrpc/borsh;wss://node-b.example/kaspa/testnet-10/wrpc/borsh",
        )
        .output()
        .unwrap();

    assert!(!result.status.success());
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        !stderr.contains("TN10_ENDPOINT_INVALID")
            && !stderr.contains("TN10_ENDPOINT_PUBLIC_DNS_REQUIRED"),
        "valid DNS endpoints were rejected: {stderr}"
    );
}

#[test]
fn locate_rejects_invalid_page_budget_before_endpoint_validation() {
    let dir = temp_dir();
    let request = dir.join("request.json");
    fs::write(
        &request,
        br#"{"network":"testnet-10","nodes":[],"max_pages":0}"#,
    )
    .unwrap();

    let result = Command::new(env!("CARGO_BIN_EXE_ktape"))
        .args(["tn10", "locate"])
        .arg(&request)
        .arg(dir.join("locate.json"))
        .output()
        .unwrap();

    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("TN10_SCAN_LIMIT_INVALID"));
}

#[test]
fn tn10_help_describes_both_signing_paths() {
    let result = Command::new(env!("CARGO_BIN_EXE_ktape"))
        .args(["tn10", "--help"])
        .output()
        .unwrap();

    assert!(result.status.success());
    let help = String::from_utf8_lossy(&result.stdout);
    assert!(help.contains("Build, sign (developer key or external signature), submit and verify"));
    assert!(!help.contains("Build, externally sign, submit and verify"));

    let version = Command::new(env!("CARGO_BIN_EXE_ktape"))
        .arg("version")
        .output()
        .unwrap();
    assert!(version.status.success());
    let version_json: serde_json::Value = serde_json::from_slice(&version.stdout).unwrap();
    assert_eq!(
        version_json["data"]["signing"],
        "developer-key-or-external-signature"
    );

    let dir = temp_dir();
    let init = Command::new(env!("CARGO_BIN_EXE_ktape"))
        .args(["init", "--network", "testnet-10", "--output"])
        .arg(dir.join("starter"))
        .output()
        .unwrap();
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    let init_json: serde_json::Value = serde_json::from_slice(&init.stdout).unwrap();
    assert_eq!(
        init_json["data"]["signing"],
        "developer-key-or-external-signature"
    );
}

#[test]
fn timeout_helper_returns_error_from_an_ordinary_thread() {
    let result = std::thread::spawn(|| {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        ktapeout_cli::tn10_pipeline::run_with_timeout(
            &runtime,
            Duration::from_millis(1),
            std::future::pending::<()>(),
        )
    })
    .join()
    .expect("timeout helper must return an error instead of panicking");

    assert!(result.is_err());
}
