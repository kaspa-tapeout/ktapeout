use ktapeout_kaspa_verifier::{
    verify_canonical_v0_input_scripts, InputScriptVerificationV1, MAX_RAW_JSON_BYTES,
};
use serde_json::json;
use std::io::{self, Read};

fn main() {
    if std::env::args().nth(1).as_deref() != Some("verify-safe-json-v0") {
        eprintln!("usage: ktapeout-kaspa-verifier verify-safe-json-v0 < transaction.safe.json");
        std::process::exit(64);
    }
    let mut raw = Vec::new();
    if io::stdin()
        .take((MAX_RAW_JSON_BYTES + 1) as u64)
        .read_to_end(&mut raw)
        .is_err()
    {
        emit_error("INPUT_READ_FAILED");
        std::process::exit(1);
    }
    match verify_canonical_v0_input_scripts(&raw) {
        Ok(report) => emit_report(report),
        Err(error) => {
            emit_error(error.0);
            std::process::exit(2);
        }
    }
}

fn emit_report(report: InputScriptVerificationV1) {
    match serde_json::to_string(&report) {
        Ok(value) => println!("{value}"),
        Err(_) => {
            emit_error("REPORT_ENCODING_FAILED");
            std::process::exit(1);
        }
    }
}

fn emit_error(code: &str) {
    println!(
        "{}",
        json!({
            "schema": "KTAPEOUT-KASPA-INPUT-SCRIPT-VERIFICATION-V1",
            "status": "REJECTED",
            "error_code": code,
            "signing_allowed": false,
            "broadcast_allowed": false
        })
    );
}
