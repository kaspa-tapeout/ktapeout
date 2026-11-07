use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet, VecDeque},
    env, fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

use std::time::Duration;

const PINNED_RUST: &str = "1.91.0";
const PINNED_HOST: &str = "x86_64-pc-windows-msvc";

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args_os().skip(1);
    if args.next().as_deref() != Some(std::ffi::OsStr::new("--output")) {
        return Err("usage: ktape-release-helper-bundle --output NEW_DIRECTORY".into());
    }
    let output = PathBuf::from(args.next().ok_or("BUNDLE_OUTPUT_REQUIRED")?);
    if args.next().is_some() {
        return Err("BUNDLE_ARGUMENTS_INVALID".into());
    }

    let crate_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let release_root = crate_root
        .parent()
        .ok_or("BUNDLE_SOURCE_ROOT_INVALID")?
        .to_path_buf();
    let adapter_root = release_root.join("adapters/native-kas-bounded");
    let rustc = command_output(&crate_root, "rustc", &["-Vv"])?;
    let cargo = command_output(&crate_root, "cargo", &["-V"])?;
    let toolchain = parse_toolchain(&rustc, &cargo)?;
    validate_toolchain(&toolchain)?;

    let toolchain_file = fs::read_to_string(crate_root.join("rust-toolchain.toml"))
        .map_err(|_| "BUNDLE_TOOLCHAIN_PIN_MISSING")?;
    if !toolchain_file.contains(&format!("channel = \"{PINNED_RUST}\"")) {
        return Err("BUNDLE_TOOLCHAIN_PIN_MISMATCH".into());
    }

    let output = normalized_new_output(&output)?;
    let parent = output.parent().ok_or("BUNDLE_OUTPUT_PARENT_REQUIRED")?;
    let file_name = output
        .file_name()
        .ok_or("BUNDLE_OUTPUT_NAME_REQUIRED")?
        .to_string_lossy();
    let stage = parent.join(format!(".{file_name}.staging-{}", std::process::id()));
    if path_exists(&output) || path_exists(&stage) {
        return Err("BUNDLE_OUTPUT_ALREADY_EXISTS".into());
    }
    fs::create_dir(&stage).map_err(|_| "BUNDLE_STAGE_CREATE_FAILED")?;

    let result = build_into(
        &crate_root,
        &adapter_root,
        &release_root,
        &stage,
        &rustc,
        &cargo,
        &toolchain,
    );
    if result.is_err() {
        let _ = fs::remove_dir_all(&stage);
    }
    result?;
    finalize_bundle(&stage, &output)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "command": "ktape release helper-bundle-build",
            "status": "LOCAL_BUILD_RECORDED",
            "output": output,
            "platform": PINNED_HOST,
            "signing": false,
            "broadcast": false,
            "deployment": false
        }))
        .map_err(|_| "BUNDLE_RESULT_ENCODE_FAILED")?
    );
    Ok(())
}

fn build_into(
    crate_root: &Path,
    adapter_root: &Path,
    release_root: &Path,
    stage: &Path,
    rustc: &str,
    cargo: &str,
    toolchain: &BTreeMap<String, String>,
) -> Result<(), String> {
    let release_root = fs::canonicalize(release_root).map_err(|_| "BUNDLE_SOURCE_ROOT_INVALID")?;
    let mut package_sources = source_packages(&crate_root.join("Cargo.toml"), &release_root)?;
    package_sources.extend(source_packages(
        &adapter_root.join("Cargo.toml"),
        &release_root,
    )?);
    package_sources.sort_by(|a, b| a["manifest"].as_str().cmp(&b["manifest"].as_str()));
    package_sources.dedup_by(|a, b| a["manifest"] == b["manifest"]);
    let lock_digest = digest_file(&crate_root.join("Cargo.lock"))?;
    let adapter_lock_digest = digest_file(&adapter_root.join("Cargo.lock"))?;
    let mut config_digests = cargo_config_digests(crate_root, &release_root)?;
    config_digests.extend(cargo_config_digests(adapter_root, &release_root)?);
    config_digests.sort_by(|a, b| a["scope"].as_str().cmp(&b["scope"].as_str()));
    config_digests.dedup_by(|a, b| a["scope"] == b["scope"]);
    let adapter_build = vec![
        "build",
        "--offline",
        "--locked",
        "--release",
        "--no-default-features",
        "--features",
        "tn10-wrpc,retention-http",
        "--manifest-path",
        "../adapters/native-kas-bounded/Cargo.toml",
        "--bin",
        "registry_deed_state_address",
        "--bin",
        "tn10_tx_scan",
        "--bin",
        "tn10_resolution_observe",
        "--bin",
        "tn10_submit_verified",
        "--bin",
        "kaspa_block_body_inclusion_verify",
        "--bin",
        "namespace_registry_child_signing_v1",
    ];
    #[cfg(feature = "publisher-adapter")]
    let adapter_build = {
        let mut adapter_build = adapter_build;
        adapter_build.extend(["--bin", "host_record_publish"]);
        adapter_build
    };
    let builds = [
        vec![
            "build",
            "--offline",
            "--locked",
            "--release",
            "--bin",
            "ktape",
        ],
        vec![
            "build",
            "--offline",
            "--locked",
            "--release",
            "--no-default-features",
            "--features",
            "host-free-native-adapter",
            "--bin",
            "ktape-name-update-adapter",
        ],
        adapter_build,
    ];
    for args in &builds {
        let output = run_command(crate_root, "cargo", args)?;
        if !output.status.success() {
            let diagnostics = String::from_utf8_lossy(&output.stderr);
            let relevant: Vec<&str> = diagnostics
                .lines()
                .filter(|line| {
                    line.contains("error:")
                        || line.contains("link.exe")
                        || line.contains("LNK")
                        || line.contains("Try 'link --help'")
                        || line.contains("note: you may need to install Visual Studio")
                })
                .take(12)
                .collect();
            return Err(format!(
                "BUNDLE_CARGO_BUILD_FAILED:{}",
                relevant.join(" | ")
            ));
        }
    }

    let release_dir = bundle_target_dir().join("release");
    let adapter_targets = [
        (
            "registry_deed_state_address",
            "registry_deed_state_address.exe",
            "adapters/native-kas-bounded/src/bin/registry_deed_state_address.rs",
            json!({"arguments":["STATE.json"],"input":"KTAPEOUT registry deed state preimage","success":"one KTAPEOUT-REGISTRY-DEED-STATE-ADDRESS-V1 JSON line on stdout","failure":"nonzero exit"}),
        ),
        (
            "tn10_tx_scan",
            "tn10_tx_scan.exe",
            "adapters/native-kas-bounded/src/bin/tn10_tx_scan.rs",
            json!({"arguments":["REQUEST.json","OUTPUT.json"],"network":"TN10 wRPC read-only; two configured endpoints","success":"raw dual-node scan JSON written to output file","failure":"nonzero exit"}),
        ),
        (
            "tn10_resolution_observe",
            "tn10_resolution_observe.exe",
            "adapters/native-kas-bounded/src/bin/tn10_resolution_observe.rs",
            json!({"arguments":["REQUEST.json","OUTPUT.json"],"network":"TN10 wRPC read-only; two configured endpoints","success":"raw dual-node observation JSON written to output file","failure":"nonzero exit"}),
        ),
        (
            "tn10_submit_verified",
            "tn10_submit_verified.exe",
            "adapters/native-kas-bounded/src/bin/tn10_submit_verified.rs",
            json!({"arguments":["SIGNED_JSON","CONFIRM_TXID","TN10_ENDPOINT?"],"network":"one TN10 wRPC transaction submission after exact native-VM confirmation","success":"RPC acknowledgement only; independent readback remains required","failure":"nonzero exit; unknown submission must reconcile before retry"}),
        ),
        (
            "kaspa_block_body_inclusion_verify",
            "kaspa_block_body_inclusion_verify.exe",
            "adapters/native-kas-bounded/src/bin/kaspa_block_body_inclusion_verify.rs",
            json!({"input":"one bounded KTAPEOUT-KASPA-BLOCK-BODY-INCLUSION-VERIFY-V1 JSON value on stdin","success":"one structured verification JSON line on stdout","failure":"structured REJECTED JSON and nonzero exit"}),
        ),
        (
            "namespace_registry_child_signing_v1",
            "namespace_registry_child_signing_v1.exe",
            "adapters/native-kas-bounded/src/bin/namespace_registry_child_signing_v1.rs",
            json!({"arguments":["--transition-plan|--verify-signatures|--merge-signatures"],"input":"bounded JSON on stdin","effect":"offline signing-plan construction, signature packet verification and signed-transaction assembly; no key generation, wallet access, RPC, or broadcast","failure":"nonzero exit and no stdout"}),
        ),
    ];
    let binaries = [
        (
            "ktape",
            "ktape.exe",
            "src/main.rs",
            vec!["coordinator"],
            json!({
                "invocation": "ktape <command>",
                "output": "command-specific JSON result on stdout; errors use nonzero exit and stable error code on stderr"
            }),
        ),
        (
            "ktape-name-update-adapter",
            "ktape-name-update-adapter.exe",
            "src/bin/ktape-name-update-adapter.rs",
            vec!["host-free-native-adapter", "default-features-disabled"],
            json!({
                "arguments": ["REQUEST_JSON", "RESPONSE_JSON"],
                "success": "exit 0 and JSON response file; stdout is empty",
                "failure": "nonzero exit and stable error code on stderr"
            }),
        ),
    ];
    let bin_dir = stage.join("bin");
    fs::create_dir(&bin_dir).map_err(|_| "BUNDLE_BIN_DIR_CREATE_FAILED")?;
    let mut executable_records = Vec::new();
    for (target, filename, source_target, features, contract) in binaries {
        let source = release_dir.join(filename);
        if !source.is_file() {
            return Err("BUNDLE_BUILT_EXECUTABLE_MISSING".into());
        }
        let destination = bin_dir.join(filename);
        fs::copy(&source, &destination).map_err(|_| "BUNDLE_EXECUTABLE_COPY_FAILED")?;
        executable_records.push(json!({
            "target": target,
            "source_target": format!("rust-cli/{source_target}"),
            "features": features,
            "bundle_path": format!("bin/{filename}"),
            "sha256": digest_file(&destination)?,
            "process_contract": contract
        }));
    }
    for (target, filename, source_target, contract) in adapter_targets {
        let source = release_dir.join(filename);
        if !source.is_file() {
            return Err("BUNDLE_BUILT_EXECUTABLE_MISSING".into());
        }
        let destination = bin_dir.join(filename);
        fs::copy(&source, &destination).map_err(|_| "BUNDLE_EXECUTABLE_COPY_FAILED")?;
        executable_records.push(json!({
            "target": target,
            "source_target": source_target,
            "features": ["tn10-wrpc", "default-features-disabled"],
            "bundle_path": format!("bin/{filename}"),
            "sha256": digest_file(&destination)?,
            "process_contract": contract
        }));
    }
    #[cfg(feature = "publisher-adapter")]
    {
        let publisher_source = release_dir.join("host_record_publish.exe");
        if !publisher_source.is_file() {
            return Err("BUNDLE_BUILT_EXECUTABLE_MISSING".into());
        }
        let publisher_destination = bin_dir.join("host_record_publish.exe");
        fs::copy(&publisher_source, &publisher_destination)
            .map_err(|_| "BUNDLE_EXECUTABLE_COPY_FAILED")?;
        executable_records.push(json!({
            "target": "host_record_publish",
            "source_target": "adapters/native-kas-bounded/src/bin/host_record_publish.rs",
            "features": ["retention-http", "default-features-disabled"],
            "bundle_path": "bin/host_record_publish.exe",
            "sha256": digest_file(&publisher_destination)?,
            "process_contract": {
                "arguments": ["REQUEST_JSON", "RESPONSE_JSON"],
                "network": "HTTPS Host intake POST and exact name readback; TN10 loopback is test-only",
                "success": "exit 0 and JSON response file; stdout is empty",
                "failure": "nonzero exit and stable error code on stderr"
            }
        }));
    }
    let process_contract_checks = verify_process_contracts(&bin_dir)?;
    let name_update_programs = name_update_programs(&executable_records)?;
    let distribution_assets = copy_public_distribution_assets(&release_root, stage)?;

    let build_steps: Vec<Value> = builds
        .iter()
        .map(|args| {
            json!({
                "program": "cargo",
                "arguments": args,
                "offline": true,
                "locked": true
            })
        })
        .collect();
    let bundle = json!({
        "schema": "KTAPEOUT-NATIVE-HELPER-BUNDLE-V1",
        "status": "LOCAL_BUILD_RECORD_UNSIGNED",
        "platform": PINNED_HOST,
        "toolchain": toolchain,
        "rustc_vv": rustc,
        "cargo_version": cargo.trim(),
        "cargo_lock": {
            "path": "rust-cli/Cargo.lock",
            "sha256": lock_digest
        },
        "additional_cargo_locks": [{
            "path": "adapters/native-kas-bounded/Cargo.lock",
            "sha256": adapter_lock_digest
        }],
        "cargo_config_sha256": config_digests,
        "source_packages": package_sources,
        "build_steps": build_steps,
        "executables": executable_records,
        "name_update_programs": name_update_programs,
        "distribution_assets": distribution_assets,
        "process_contract_checks": process_contract_checks,
        "effects": {
            "network_access": false,
            "wallet_access": false,
            "signing": false,
            "broadcast": false,
            "deployment": false
        }
    });
    let bytes = serde_json::to_vec_pretty(&bundle).map_err(|_| "BUNDLE_MANIFEST_ENCODE_FAILED")?;
    fs::write(stage.join("bundle.json"), bytes).map_err(|_| "BUNDLE_MANIFEST_WRITE_FAILED")?;
    validate_bundle_manifest(stage)?;
    Ok(())
}

fn validate_bundle_manifest(stage: &Path) -> Result<(), String> {
    let manifest_path = stage.join("bundle.json");
    let manifest: Value = serde_json::from_slice(
        &fs::read(&manifest_path).map_err(|_| "BUNDLE_MANIFEST_READ_FAILED")?,
    )
    .map_err(|_| "BUNDLE_MANIFEST_INVALID")?;

    let executable_records = manifest["executables"]
        .as_array()
        .ok_or("BUNDLE_EXECUTABLE_RECORDS_INVALID")?;
    for record in executable_records {
        validate_bundle_record(stage, record, "bundle_path", "BUNDLE_EXECUTABLE")?;
    }
    let distribution_records = manifest["distribution_assets"]
        .as_array()
        .ok_or("BUNDLE_DISTRIBUTION_RECORDS_INVALID")?;
    for record in distribution_records {
        validate_bundle_record(stage, record, "path", "BUNDLE_DISTRIBUTION")?;
    }
    let programs = manifest["name_update_programs"]
        .as_object()
        .ok_or("BUNDLE_ROLE_RECORDS_INVALID")?;
    for record in programs.values() {
        validate_bundle_record(stage, record, "bundle_path", "BUNDLE_ROLE")?;
    }
    let registry: Value = serde_json::from_slice(
        &fs::read(stage.join("config/application-release-target-adapter-registry.json"))
            .map_err(|_| "BUNDLE_ADAPTER_REGISTRY_MISSING")?,
    )
    .map_err(|_| "BUNDLE_ADAPTER_REGISTRY_INVALID")?;
    validate_registered_programs(&registry, executable_records)?;
    Ok(())
}

fn validate_registered_programs(registry: &Value, executables: &[Value]) -> Result<(), String> {
    for id in [
        "tn10-name-controller-release-v1",
        "tn10-publisher-release-v1",
    ] {
        let adapter = &registry["adapters"][id];
        if adapter["status"] != "HOST_FREE_READY" {
            continue;
        }
        let executable = &adapter["executables"]["windows-x86_64"];
        let dependencies = adapter["dependencies"]
            .as_array()
            .ok_or("BUNDLE_ADAPTER_REGISTRY_INVALID")?;
        for registered in std::iter::once(executable).chain(dependencies.iter()) {
            let path = registered["path"]
                .as_str()
                .ok_or("BUNDLE_ADAPTER_REGISTRY_INVALID")?;
            let recorded = executables
                .iter()
                .find(|record| record["bundle_path"].as_str() == Some(path))
                .ok_or("BUNDLE_REGISTERED_PROGRAM_MISSING")?;
            if registered["sha256"].as_str().is_none() || registered["sha256"] != recorded["sha256"]
            {
                return Err("BUNDLE_REGISTERED_PROGRAM_DIGEST_MISMATCH".into());
            }
        }
    }
    Ok(())
}

fn validate_bundle_record(
    stage: &Path,
    record: &Value,
    path_field: &str,
    label: &str,
) -> Result<(), String> {
    let relative = record[path_field]
        .as_str()
        .ok_or_else(|| format!("{label}_PATH_INVALID"))?;
    let relative_path = Path::new(relative);
    if relative_path.is_absolute()
        || relative_path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(format!("{label}_PATH_INVALID"));
    }
    let file = stage.join(relative_path);
    if !file.is_file() {
        return Err(format!("{label}_FILE_MISSING"));
    }
    let expected = record["sha256"]
        .as_str()
        .ok_or_else(|| format!("{label}_DIGEST_INVALID"))?;
    if digest_file(&file)? != expected {
        return Err(format!("{label}_DIGEST_MISMATCH"));
    }
    Ok(())
}

fn copy_public_distribution_assets(release_root: &Path, stage: &Path) -> Result<Value, String> {
    let files = [
        (
            "skills/ktapeout-application-engineering",
            "skills/ktapeout-application-engineering",
            true,
        ),
        (
            "studio/application-release-target-adapter-registry.json",
            "config/application-release-target-adapter-registry.json",
            false,
        ),
        (
            "templates/release-target-v3.template.json",
            "templates/release-target-v3.template.json",
            false,
        ),
    ];
    let mut records = Vec::new();
    for (source_relative, bundle_relative, recursive) in files {
        let source = release_root.join(source_relative);
        let destination = stage.join(bundle_relative);
        if recursive {
            copy_distribution_tree(&source, &destination, stage, &mut records)?;
        } else {
            let metadata =
                fs::symlink_metadata(&source).map_err(|_| "BUNDLE_DISTRIBUTION_ASSET_MISSING")?;
            if !metadata.is_file() {
                return Err("BUNDLE_DISTRIBUTION_ASSET_INVALID".into());
            }
            let parent = destination
                .parent()
                .ok_or("BUNDLE_DISTRIBUTION_PATH_INVALID")?;
            fs::create_dir_all(parent).map_err(|_| "BUNDLE_DISTRIBUTION_DIR_CREATE_FAILED")?;
            fs::copy(&source, &destination).map_err(|_| "BUNDLE_DISTRIBUTION_COPY_FAILED")?;
            records.push(json!({
                "path": bundle_relative.replace('\\', "/"),
                "sha256": digest_file(&destination)?
            }));
        }
    }
    records.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
    Ok(json!(records))
}

fn copy_distribution_tree(
    source: &Path,
    destination: &Path,
    distribution_root: &Path,
    records: &mut Vec<Value>,
) -> Result<(), String> {
    let metadata = fs::symlink_metadata(source).map_err(|_| "BUNDLE_DISTRIBUTION_ASSET_MISSING")?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("BUNDLE_DISTRIBUTION_ASSET_INVALID".into());
    }
    fs::create_dir_all(destination).map_err(|_| "BUNDLE_DISTRIBUTION_DIR_CREATE_FAILED")?;
    for entry in fs::read_dir(source).map_err(|_| "BUNDLE_DISTRIBUTION_READ_FAILED")? {
        let entry = entry.map_err(|_| "BUNDLE_DISTRIBUTION_READ_FAILED")?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        let file_type = entry
            .file_type()
            .map_err(|_| "BUNDLE_DISTRIBUTION_READ_FAILED")?;
        if file_type.is_symlink() {
            return Err("BUNDLE_DISTRIBUTION_SYMLINK_REJECTED".into());
        }
        if file_type.is_dir() {
            copy_distribution_tree(&source_path, &destination_path, distribution_root, records)?;
            continue;
        }
        if !file_type.is_file() {
            return Err("BUNDLE_DISTRIBUTION_ASSET_INVALID".into());
        }
        fs::copy(&source_path, &destination_path).map_err(|_| "BUNDLE_DISTRIBUTION_COPY_FAILED")?;
        let relative = destination_path
            .strip_prefix(distribution_root)
            .unwrap_or(&destination_path);
        records.push(json!({
            "path": relative.to_string_lossy().replace('\\', "/"),
            "sha256": digest_file(&destination_path)?
        }));
    }
    Ok(())
}

// Keep the executor's roles tied to the same bytes already recorded in the bundle.
// This is an unsigned local build record, not an adapter registration or signer.
fn name_update_programs(records: &[Value]) -> Result<Value, String> {
    let roles = [
        ("planner", "namespace_registry_child_signing_v1"),
        ("fetcher", "tn10_resolution_observe"),
        ("state_helper", "registry_deed_state_address"),
        ("submitter", "tn10_submit_verified"),
        ("readback_scanner", "tn10_tx_scan"),
        ("readback_verifier", "kaspa_block_body_inclusion_verify"),
    ];
    let mut programs = serde_json::Map::new();
    for (role, target) in roles {
        let mut matches = records.iter().filter(|record| record["target"] == target);
        let record = matches.next().ok_or("BUNDLE_ROLE_TARGET_MISSING")?;
        if matches.next().is_some() {
            return Err("BUNDLE_ROLE_TARGET_AMBIGUOUS".into());
        }
        let path = record["bundle_path"]
            .as_str()
            .ok_or("BUNDLE_ROLE_TARGET_INVALID")?;
        let hash = record["sha256"]
            .as_str()
            .ok_or("BUNDLE_ROLE_TARGET_INVALID")?;
        programs.insert(role.into(), json!({"bundle_path": path, "sha256": hash}));
    }
    Ok(Value::Object(programs))
}

fn verify_process_contracts(bin_dir: &Path) -> Result<Value, String> {
    let cli = bin_dir.join("ktape.exe");
    let cli_path = cli.to_str().ok_or("BUNDLE_EXECUTABLE_PATH_INVALID")?;
    let help = run_command(bin_dir, cli_path, &["--help"])?;
    if !help.status.success() || help.stdout.is_empty() || !help.stderr.is_empty() {
        return Err("BUNDLE_KTAPE_HELP_CONTRACT_FAILED".into());
    }
    for command in [
        "authorization-sign",
        "authorization-import",
        "abandon-unattempted",
        "escrow-rebind",
        "repair-cli-signer",
        "reconcile-native",
    ] {
        let help = run_command(bin_dir, cli_path, &["release", command, "--help"])?;
        if !help.status.success() || help.stdout.is_empty() || !help.stderr.is_empty() {
            return Err(format!("BUNDLE_RELEASE_COMMAND_MISSING:{command}"));
        }
    }

    let adapter = bin_dir.join("ktape-name-update-adapter.exe");
    let adapter_path = adapter.to_str().ok_or("BUNDLE_EXECUTABLE_PATH_INVALID")?;
    let no_args = run_command(bin_dir, adapter_path, &[])?;
    if no_args.status.success()
        || !no_args.stdout.is_empty()
        || String::from_utf8_lossy(&no_args.stderr).trim() != "RELEASE_ADAPTER_ARGUMENTS_INVALID"
    {
        return Err("BUNDLE_ADAPTER_ARGUMENT_CONTRACT_FAILED".into());
    }
    verify_detached_authorization_contract(bin_dir, adapter_path)?;
    let state = run_command(
        bin_dir,
        bin_dir
            .join("registry_deed_state_address.exe")
            .to_str()
            .ok_or("BUNDLE_EXECUTABLE_PATH_INVALID")?,
        &[],
    )?;
    if state.status.success()
        || !String::from_utf8_lossy(&state.stderr)
            .contains("usage: registry_deed_state_address STATE.json")
    {
        return Err("BUNDLE_STATE_HELPER_ARGUMENT_CONTRACT_FAILED".into());
    }
    let state_fixture = bin_dir.join("process-check-state.json");
    fs::write(
        &state_fixture,
        r#"{"network":"testnet-10","state_args":[1,1,"4fb442ac8c0159800b7dbd5dadca5d913352a2722de1cba423e0c8b9b3b4dd78","4fb442ac8c0159800b7dbd5dadca5d913352a2722de1cba423e0c8b9b3b4dd79",0,"4fb442ac8c0159800b7dbd5dadca5d913352a2722de1cba423e0c8b9b3b4dd78","7eff588487b26ba65b326b2e54c88d97a7125e95a0fa751f10ff2a3369fb138d","b882a2ded6803f84de3b26547904a3d43ea7056b9ffef6df0d7004edab0807a7","7eff588487b26ba65b326b2e54c88d97a7125e95a0fa751f10ff2a3369fb138d","dac700fd74378f83484975119ecde08a2510a7ee04aed8897e63dd8f1d7d20ce",100000000,"f8dbe37435c81fedc3c2a91ef2b13d6b6fe60c45e0e1c9ecc4e7f0cdc84e4d9c","b9cdbfb106476a616b3532747b8432c1cb1308584e0d4d8bb00dd3ad6093d754",1,867]}"#,
    )
    .map_err(|_| "BUNDLE_PROCESS_CHECK_FIXTURE_WRITE_FAILED")?;
    let state_output = run_command(
        bin_dir,
        bin_dir
            .join("registry_deed_state_address.exe")
            .to_str()
            .ok_or("BUNDLE_EXECUTABLE_PATH_INVALID")?,
        &[state_fixture.to_str().ok_or("BUNDLE_PATH_INVALID")?],
    )?;
    let state_result: Value = serde_json::from_slice(&state_output.stdout)
        .map_err(|_| "BUNDLE_STATE_HELPER_OUTPUT_INVALID")?;
    if !state_output.status.success()
        || !state_output.stderr.is_empty()
        || state_result["schema"] != "KTAPEOUT-REGISTRY-DEED-STATE-ADDRESS-V1"
        || state_result["network"] != "testnet-10"
        || state_result["script_public_key"]
            != "0000aa20566ddb63bcc278c5a49529f2b43e1b7c8f34386e569b4eb73d2e9a047bf0ba0387"
        || state_result["signing_allowed"] != false
        || state_result["broadcast"] != false
    {
        return Err("BUNDLE_STATE_HELPER_PROCESS_CONTRACT_FAILED".into());
    }
    fs::remove_file(&state_fixture).map_err(|_| "BUNDLE_PROCESS_CHECK_FIXTURE_REMOVE_FAILED")?;

    let scanner = run_command(
        bin_dir,
        bin_dir
            .join("tn10_tx_scan.exe")
            .to_str()
            .ok_or("BUNDLE_EXECUTABLE_PATH_INVALID")?,
        &[],
    )?;
    if scanner.status.success()
        || !String::from_utf8_lossy(&scanner.stderr)
            .contains("usage: tn10_tx_scan REQUEST.json OUTPUT.json")
    {
        return Err("BUNDLE_TX_SCANNER_ARGUMENT_CONTRACT_FAILED".into());
    }
    let scanner_fixture = bin_dir.join("process-check-scan-request.json");
    fs::write(
        &scanner_fixture,
        r#"{"schema":"wrong-schema","network":"testnet-10"}"#,
    )
    .map_err(|_| "BUNDLE_PROCESS_CHECK_FIXTURE_WRITE_FAILED")?;
    let scanner_output = run_command(
        bin_dir,
        bin_dir
            .join("tn10_tx_scan.exe")
            .to_str()
            .ok_or("BUNDLE_EXECUTABLE_PATH_INVALID")?,
        &[
            scanner_fixture.to_str().ok_or("BUNDLE_PATH_INVALID")?,
            bin_dir
                .join("process-check-scan-output.json")
                .to_str()
                .ok_or("BUNDLE_PATH_INVALID")?,
        ],
    )?;
    if scanner_output.status.success()
        || !String::from_utf8_lossy(&scanner_output.stderr).contains("REQUEST_SCHEMA_INVALID")
        || !scanner_output.stdout.is_empty()
    {
        return Err("BUNDLE_TX_SCANNER_INPUT_CONTRACT_FAILED".into());
    }
    fs::remove_file(&scanner_fixture).map_err(|_| "BUNDLE_PROCESS_CHECK_FIXTURE_REMOVE_FAILED")?;

    let observer = bin_dir.join("tn10_resolution_observe.exe");
    let observer_path = observer.to_str().ok_or("BUNDLE_EXECUTABLE_PATH_INVALID")?;
    let observer_usage = run_command(bin_dir, observer_path, &[])?;
    if observer_usage.status.success()
        || !String::from_utf8_lossy(&observer_usage.stderr)
            .contains("usage: tn10_resolution_observe REQUEST_JSON OUTPUT_JSON")
    {
        return Err("BUNDLE_RESOLUTION_OBSERVER_ARGUMENT_CONTRACT_FAILED".into());
    }
    let observer_fixture = bin_dir.join("process-check-observation-request.json");
    let observer_output_path = bin_dir.join("process-check-observation-output.json");
    fs::write(&observer_fixture, r#"{"endpoints":[],"addresses":[]}"#)
        .map_err(|_| "BUNDLE_PROCESS_CHECK_FIXTURE_WRITE_FAILED")?;
    let observer_output = run_command(
        bin_dir,
        observer_path,
        &[
            observer_fixture.to_str().ok_or("BUNDLE_PATH_INVALID")?,
            observer_output_path.to_str().ok_or("BUNDLE_PATH_INVALID")?,
        ],
    )?;
    if observer_output.status.success()
        || !String::from_utf8_lossy(&observer_output.stderr).contains("REQUEST_INVALID")
        || observer_output_path.exists()
    {
        return Err("BUNDLE_RESOLUTION_OBSERVER_REJECTS_INVALID_REQUEST_FAILED".into());
    }
    fs::remove_file(&observer_fixture).map_err(|_| "BUNDLE_PROCESS_CHECK_FIXTURE_REMOVE_FAILED")?;

    let submitter = bin_dir.join("tn10_submit_verified.exe");
    let submitter_path = submitter.to_str().ok_or("BUNDLE_EXECUTABLE_PATH_INVALID")?;
    let submitter_usage = run_command(bin_dir, submitter_path, &[])?;
    if submitter_usage.status.success()
        || !String::from_utf8_lossy(&submitter_usage.stderr)
            .contains("usage: tn10_submit_verified SIGNED_JSON CONFIRM_TXID")
    {
        return Err("BUNDLE_SUBMITTER_ARGUMENT_CONTRACT_FAILED".into());
    }
    let submitter_fixture = bin_dir.join("process-check-submit-request.json");
    fs::write(
        &submitter_fixture,
        r#"{"native_vm_verified":false,"txid":"abababababababababababababababababababababababababababababababab"}"#,
    )
    .map_err(|_| "BUNDLE_PROCESS_CHECK_FIXTURE_WRITE_FAILED")?;
    let submitter_output = run_command(
        bin_dir,
        submitter_path,
        &[
            submitter_fixture.to_str().ok_or("BUNDLE_PATH_INVALID")?,
            "abababababababababababababababababababababababababababababababab",
        ],
    )?;
    if submitter_output.status.success()
        || !String::from_utf8_lossy(&submitter_output.stderr)
            .contains("VERIFIED_TRANSACTION_AND_EXACT_ID_REQUIRED")
        || !submitter_output.stdout.is_empty()
    {
        return Err("BUNDLE_SUBMITTER_REJECTS_UNVERIFIED_TRANSACTION_FAILED".into());
    }
    fs::remove_file(&submitter_fixture)
        .map_err(|_| "BUNDLE_PROCESS_CHECK_FIXTURE_REMOVE_FAILED")?;

    let verifier = run_command(
        bin_dir,
        bin_dir
            .join("kaspa_block_body_inclusion_verify.exe")
            .to_str()
            .ok_or("BUNDLE_EXECUTABLE_PATH_INVALID")?,
        &[],
    )?;
    let rejected: Value = serde_json::from_slice(&verifier.stdout)
        .map_err(|_| "BUNDLE_READBACK_VERIFIER_CONTRACT_FAILED")?;
    if verifier.status.success()
        || rejected["status"] != "REJECTED"
        || rejected["schema"] != "KTAPEOUT-KASPA-BLOCK-BODY-INCLUSION-VERIFY-V1"
    {
        return Err("BUNDLE_READBACK_VERIFIER_CONTRACT_FAILED".into());
    }
    let lifecycle_helper = bin_dir.join("namespace_registry_child_signing_v1.exe");
    let lifecycle_output = run_command_with_stdin(
        bin_dir,
        lifecycle_helper
            .to_str()
            .ok_or("BUNDLE_EXECUTABLE_PATH_INVALID")?,
        &["--transition-plan"],
        br#"{"schema":"UNKNOWN"}"#,
    )?;
    if lifecycle_output.status.success()
        || !lifecycle_output.stdout.is_empty()
        || !String::from_utf8_lossy(&lifecycle_output.stderr)
            .contains("transition envelope fields are not canonical")
    {
        return Err("BUNDLE_LIFECYCLE_HELPER_REJECTS_INVALID_ENVELOPE_FAILED".into());
    }
    Ok(json!({
        "ktape_help": "PASS",
        "adapter_missing_arguments_rejected": "PASS",
        "adapter_detached_authorization_is_coordinator_managed": "PASS",
        "state_helper_usage_contract": "PASS",
        "state_helper_valid_fixture_contract": "PASS",
        "tx_scanner_usage_contract": "PASS",
        "tx_scanner_rejects_invalid_schema_before_network": "PASS",
        "resolution_observer_usage_contract": "PASS",
        "resolution_observer_rejects_invalid_request_before_network": "PASS",
        "submitter_usage_contract": "PASS",
        "submitter_rejects_unverified_transaction_before_network": "PASS",
        "readback_verifier_rejects_empty_input": "PASS",
        "registry_lifecycle_helper_rejects_invalid_envelope_without_output": "PASS"
    }))
}

fn verify_detached_authorization_contract(
    bin_dir: &Path,
    adapter_path: &str,
) -> Result<(), String> {
    let artifact_path = bin_dir.join("process-check-frozen-input.json");
    let artifact_bytes = br#"{"frozen":true}"#;
    fs::write(&artifact_path, artifact_bytes)
        .map_err(|_| "BUNDLE_PROCESS_CHECK_FIXTURE_WRITE_FAILED")?;
    let target = json!({
        "schema":"KTAPEOUT-RELEASE-TARGET-V3",
        "execution_line":"name-controller",
        "project":bin_dir,
        "scope":{
            "network":"testnet-10",
            "application_uri":"ktape://testnet-10/app/example/app",
            "wallet_address":"kaspatest:qexample",
            "workflow_authority_public_key":"01".repeat(32),
            "name_controller_public_key":"02".repeat(32),
            "permissions":[]
        },
        "settings":{},
        "max_fee_sompi":5000000,
        "authorization_ttl_seconds":3600,
        "adapter":{"path":bin_dir.join("ktape-name-update-adapter.exe"),"sha256":"03".repeat(32)},
        "arguments":[],
        "dependencies":[],
        "timeout_seconds":60,
        "release_adapter_id":"tn10-name-controller-release-v1"
    });
    let plan = json!({
        "schema":"KTAPEOUT-RELEASE-PLAN-V1",
        "scope":target["scope"],
        "release_id":"04".repeat(32),
        "source_sha256":"05".repeat(32),
        "unchanged":true,
        "actions":[],
        "artifacts":[{"path":artifact_path,"sha256":hex::encode(Sha256::digest(artifact_bytes))}],
        "summary":{}
    });
    let valid_until = 2_000_000_000u64;
    let intent_bytes = serde_json::to_vec(&json!({
        "target":target,
        "plan":plan,
        "valid_until":valid_until
    }))
    .map_err(|_| "BUNDLE_PROCESS_CHECK_FIXTURE_ENCODE_FAILED")?;
    let intent_sha256 = hex::encode(Sha256::digest(intent_bytes));
    let request_path = bin_dir.join("process-check-authorization-request.json");
    let response_path = bin_dir.join("process-check-authorization-response.json");
    let request = json!({
        "schema":"KTAPEOUT-RELEASE-ADAPTER-REQUEST-V2",
        "phase":"authorize",
        "target":target,
        "workdir":bin_dir.join("process-check-authorization-work"),
        "intent_sha256":intent_sha256,
        "valid_until":valid_until,
        "plan":plan,
        "action":null,
        "pending":false,
        "receipts":null,
        "authorization":null
    });
    let bytes =
        serde_json::to_vec(&request).map_err(|_| "BUNDLE_PROCESS_CHECK_FIXTURE_ENCODE_FAILED")?;
    fs::write(&request_path, bytes).map_err(|_| "BUNDLE_PROCESS_CHECK_FIXTURE_WRITE_FAILED")?;
    let output = run_command(
        bin_dir,
        adapter_path,
        &[
            request_path.to_str().ok_or("BUNDLE_PATH_INVALID")?,
            response_path.to_str().ok_or("BUNDLE_PATH_INVALID")?,
        ],
    )?;
    let _ = fs::remove_file(&artifact_path);
    let _ = fs::remove_file(&request_path);
    if output.status.success()
        || !output.stdout.is_empty()
        || String::from_utf8_lossy(&output.stderr).trim()
            != "RELEASE_COORDINATOR_DETACHED_AUTHORIZATION_REQUIRED"
        || response_path.exists()
        || bin_dir.join("process-check-authorization-work").exists()
    {
        return Err("BUNDLE_ADAPTER_DETACHED_AUTHORIZATION_CONTRACT_FAILED".into());
    }
    Ok(())
}

fn command_output(cwd: &Path, program: &str, args: &[&str]) -> Result<String, String> {
    let output = run_command(cwd, program, args)?;
    if !output.status.success() {
        return Err(format!("BUNDLE_TOOLCHAIN_COMMAND_FAILED:{program}"));
    }
    String::from_utf8(output.stdout).map_err(|_| "BUNDLE_TOOLCHAIN_OUTPUT_INVALID".into())
}

fn run_command(cwd: &Path, program: &str, args: &[&str]) -> Result<Output, String> {
    let mut command = Command::new(program);
    command.current_dir(cwd).args(args).env_clear();
    for key in [
        "PATH",
        "SystemRoot",
        "windir",
        "USERPROFILE",
        "HOMEDRIVE",
        "HOMEPATH",
        "HOME",
        "APPDATA",
        "LOCALAPPDATA",
        "PROGRAMDATA",
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",
        "PROGRAMW6432",
        "SYSTEMDRIVE",
        "TEMP",
        "TMP",
        "CARGO_HOME",
        "RUSTUP_HOME",
        "COMSPEC",
        "PATHEXT",
        "CARGO_TARGET_DIR",
    ] {
        if let Some(value) = env::var_os(key) {
            command.env(key, value);
        }
    }
    if cfg!(windows) && program.eq_ignore_ascii_case("cargo") {
        let mut flags = env::var("RUSTFLAGS").unwrap_or_default();
        if !flags.contains("/Brepro") {
            flags.push_str(" -C link-arg=/Brepro");
        }
        command.env("RUSTFLAGS", flags.trim());
    }
    if program.eq_ignore_ascii_case("cargo") {
        command.env("CARGO_TARGET_DIR", bundle_target_dir());
    }
    command
        .output()
        .map_err(|_| format!("BUNDLE_TOOL_SPAWN_FAILED:{program}"))
}

fn bundle_target_dir() -> PathBuf {
    env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| env::temp_dir().join("ktapeout-050-release-helper-target"))
}

fn run_command_with_stdin(
    cwd: &Path,
    program: &str,
    args: &[&str],
    input: &[u8],
) -> Result<Output, String> {
    let mut command = Command::new(program);
    command
        .current_dir(cwd)
        .args(args)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for key in [
        "PATH",
        "SystemRoot",
        "windir",
        "USERPROFILE",
        "HOMEDRIVE",
        "HOMEPATH",
        "HOME",
        "APPDATA",
        "LOCALAPPDATA",
        "PROGRAMDATA",
        "PROGRAMFILES",
        "PROGRAMFILES(X86)",
        "PROGRAMW6432",
        "SYSTEMDRIVE",
        "TEMP",
        "TMP",
    ] {
        if let Some(value) = env::var_os(key) {
            command.env(key, value);
        }
    }
    let mut child = command
        .spawn()
        .map_err(|_| "BUNDLE_PROCESS_CHECK_START_FAILED")?;
    child
        .stdin
        .take()
        .ok_or("BUNDLE_PROCESS_CHECK_STDIN_UNAVAILABLE")?
        .write_all(input)
        .map_err(|_| "BUNDLE_PROCESS_CHECK_STDIN_WRITE_FAILED")?;
    child
        .wait_with_output()
        .map_err(|_| "BUNDLE_PROCESS_CHECK_WAIT_FAILED".into())
}

fn cargo_metadata(manifest: &Path, cwd: &Path) -> Result<Value, String> {
    let manifest = manifest.to_str().ok_or("BUNDLE_PATH_INVALID")?;
    let output = run_command(
        cwd,
        "cargo",
        &[
            "metadata",
            "--offline",
            "--locked",
            "--format-version",
            "1",
            "--no-deps",
            "--manifest-path",
            manifest,
        ],
    )?;
    if !output.status.success() {
        return Err("BUNDLE_CARGO_METADATA_FAILED".into());
    }
    serde_json::from_slice(&output.stdout).map_err(|_| "BUNDLE_CARGO_METADATA_INVALID".into())
}

fn source_packages(root_manifest: &Path, release_root: &Path) -> Result<Vec<Value>, String> {
    let mut queue = VecDeque::new();
    queue.push_back(root_manifest.to_path_buf());
    let mut visited = HashSet::new();
    let mut records = BTreeMap::new();
    while let Some(manifest) = queue.pop_front() {
        let manifest = fs::canonicalize(manifest).map_err(|_| "BUNDLE_PACKAGE_MANIFEST_MISSING")?;
        if !visited.insert(manifest.clone()) {
            continue;
        }
        let package_metadata = cargo_metadata(
            &manifest,
            manifest.parent().ok_or("BUNDLE_PACKAGE_ROOT_INVALID")?,
        )?;
        let packages = package_metadata["packages"]
            .as_array()
            .ok_or("BUNDLE_METADATA_PACKAGES_INVALID")?;
        for package in packages {
            let package_manifest = PathBuf::from(
                package["manifest_path"]
                    .as_str()
                    .ok_or("BUNDLE_PACKAGE_MANIFEST_MISSING")?,
            );
            let package_root = package_manifest
                .parent()
                .ok_or("BUNDLE_PACKAGE_ROOT_INVALID")?;
            let relative = package_root
                .strip_prefix(release_root)
                .map_err(|_| "BUNDLE_LOCAL_DEPENDENCY_OUTSIDE_RELEASE_ROOT")?;
            records.insert(
                path_string(relative)?,
                json!({
                    "name": package["name"],
                    "version": package["version"],
                    "manifest": format!("{}/Cargo.toml", path_string(relative)?),
                    "source_tree_sha256": digest_tree(package_root)?
                }),
            );
            for dependency in package["dependencies"]
                .as_array()
                .ok_or("BUNDLE_METADATA_DEPS_INVALID")?
            {
                if let Some(path) = dependency["path"].as_str() {
                    let path = PathBuf::from(path);
                    queue.push_back(if path.is_dir() {
                        path.join("Cargo.toml")
                    } else {
                        path
                    });
                }
            }
        }
    }
    if records.is_empty() {
        return Err("BUNDLE_SOURCE_CLOSURE_EMPTY".into());
    }
    Ok(records.into_values().collect())
}

fn cargo_config_digests(crate_root: &Path, release_root: &Path) -> Result<Vec<Value>, String> {
    let mut seen = BTreeSet::new();
    let mut files = Vec::new();
    let mut current = Some(crate_root);
    while let Some(dir) = current {
        for name in ["config.toml", "config"] {
            let path = dir.join(".cargo").join(name);
            if path.is_file()
                && seen.insert(fs::canonicalize(&path).map_err(|_| "BUNDLE_CARGO_CONFIG_INVALID")?)
            {
                let scope = match path.strip_prefix(release_root) {
                    Ok(relative) => path_string(relative)?,
                    Err(_) => "project-ancestor-config".into(),
                };
                files.push(json!({"scope": scope, "sha256": digest_file(&path)?}));
            }
        }
        current = dir.parent();
    }
    let cargo_home = env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("USERPROFILE").map(|p| PathBuf::from(p).join(".cargo")));
    if let Some(home) = cargo_home {
        for name in ["config.toml", "config"] {
            let path = home.join(name);
            if path.is_file()
                && seen.insert(fs::canonicalize(&path).map_err(|_| "BUNDLE_CARGO_CONFIG_INVALID")?)
            {
                files.push(json!({
                    "scope": format!("cargo-home/{name}"),
                    "sha256": digest_file(&path)?
                }));
            }
        }
    }
    Ok(files)
}

fn digest_tree(root: &Path) -> Result<String, String> {
    let mut files = Vec::new();
    collect_files(root, root, &mut files)?;
    files.sort_by(|a, b| a.0.cmp(&b.0));
    let mut digest = Sha256::new();
    for (relative, path) in files {
        let relative = relative.as_bytes();
        let bytes = fs::read(path).map_err(|_| "BUNDLE_SOURCE_READ_FAILED")?;
        digest.update((relative.len() as u64).to_be_bytes());
        digest.update(relative);
        digest.update((bytes.len() as u64).to_be_bytes());
        digest.update(bytes);
    }
    Ok(hex::encode(digest.finalize()))
}

fn collect_files(
    root: &Path,
    dir: &Path,
    files: &mut Vec<(String, PathBuf)>,
) -> Result<(), String> {
    let mut entries = fs::read_dir(dir)
        .map_err(|_| "BUNDLE_SOURCE_READ_FAILED")?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "BUNDLE_SOURCE_READ_FAILED")?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let kind = entry.file_type().map_err(|_| "BUNDLE_SOURCE_READ_FAILED")?;
        if kind.is_symlink() {
            return Err("BUNDLE_SOURCE_SYMLINK_UNSUPPORTED".into());
        }
        if kind.is_dir() {
            let name = entry.file_name();
            if name == "target" || name == ".git" || name == ".build-cache" {
                continue;
            }
            collect_files(root, &path, files)?;
        } else if kind.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| "BUNDLE_SOURCE_PATH_INVALID")?;
            files.push((path_string(relative)?, path));
        }
    }
    Ok(())
}

fn digest_file(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|_| "BUNDLE_SOURCE_READ_FAILED")?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn path_string(path: &Path) -> Result<String, String> {
    path.to_str()
        .map(|p| p.replace('\\', "/"))
        .ok_or_else(|| "BUNDLE_PATH_NOT_UTF8".into())
}

fn parse_toolchain(rustc: &str, cargo: &str) -> Result<BTreeMap<String, String>, String> {
    let mut values = BTreeMap::new();
    for line in rustc.lines() {
        if let Some((key, value)) = line.split_once(": ") {
            if key == "release" || key == "host" || key == "commit-hash" {
                values.insert(key.to_owned(), value.to_owned());
            }
        }
    }
    if !cargo.starts_with("cargo ") {
        return Err("BUNDLE_CARGO_VERSION_INVALID".into());
    }
    if !values.contains_key("release") || !values.contains_key("host") {
        return Err("BUNDLE_RUSTC_VERSION_INVALID".into());
    }
    Ok(values)
}

fn validate_toolchain(toolchain: &BTreeMap<String, String>) -> Result<(), String> {
    if toolchain.get("release").map(String::as_str) != Some(PINNED_RUST)
        || toolchain.get("host").map(String::as_str) != Some(PINNED_HOST)
    {
        return Err("BUNDLE_PLATFORM_OR_TOOLCHAIN_UNSUPPORTED".into());
    }
    Ok(())
}

fn normalized_new_output(path: &Path) -> Result<PathBuf, String> {
    let name = path.file_name().ok_or("BUNDLE_OUTPUT_NAME_REQUIRED")?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = fs::canonicalize(parent).map_err(|_| "BUNDLE_OUTPUT_PARENT_UNAVAILABLE")?;
    Ok(parent.join(name))
}

fn path_exists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

/// Finalization can briefly race with Windows antivirus/indexer handles that
/// were opened while the staged files were written. Keep the publish step
/// atomic (rename only), but retry the same-volume rename for a short bounded
/// window instead of reporting a spurious build failure.
fn finalize_bundle(stage: &Path, output: &Path) -> Result<(), String> {
    let mut last_error = None;
    for attempt in 0..20 {
        match fs::rename(stage, output) {
            Ok(()) => return Ok(()),
            Err(error) => {
                last_error = Some(error.to_string());
                if attempt < 19 {
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }
    Err(format!(
        "BUNDLE_FINALIZE_FAILED:{}",
        last_error.unwrap_or_else(|| "unknown rename error".into())
    ))
}
