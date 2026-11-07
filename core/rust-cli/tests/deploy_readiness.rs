use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;

fn run_deploy(command: &str) -> Value {
    let manifest =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/golden-counter-source.json");
    let output = Command::new(env!("CARGO_BIN_EXE_ktape"))
        .args(["deploy", command, "--network", "testnet-10"])
        .arg(manifest)
        .output()
        .expect("run ktape deploy command");

    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("CLI returns JSON")
}

#[test]
fn plan_reports_missing_external_evidence_as_warning() {
    let result = run_deploy("plan");

    assert_eq!(result["status"], "WARNING");
    assert_eq!(result["data"]["lifecycle_status"], "PLAN_ONLY");
    assert_eq!(result["data"]["network_effect"], "NONE");
    assert_eq!(result["data"]["signing_allowed"], false);
    assert_eq!(result["data"]["broadcast"], false);
    assert_eq!(
        result["data"]["missing_evidence"].as_array().unwrap().len(),
        6
    );
}

#[test]
fn preflight_reports_missing_external_evidence_as_warning() {
    let result = run_deploy("preflight");

    assert_eq!(result["status"], "WARNING");
    assert_eq!(result["data"]["lifecycle_status"], "PLAN_ONLY");
    assert_eq!(result["data"]["network_effect"], "NONE");
    assert_eq!(result["data"]["signing_allowed"], false);
    assert_eq!(result["data"]["broadcast"], false);
    assert_eq!(
        result["data"]["missing_evidence"].as_array().unwrap().len(),
        6
    );
}
