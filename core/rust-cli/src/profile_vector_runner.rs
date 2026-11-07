//! Built-in, no-side-effect executor for the one Profile vector interface
//! currently linked into the KTAPEOUT CLI. It verifies the content-addressed
//! Profile package, then calls the same pure rules module as its planner. It
//! never loads or launches code from the package directory.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs, path::Path};

#[path = "../../adapters/native-kas-bounded/src/bounded_pool_rules.rs"]
mod bounded_pool_rules;

const PROFILE_ID: &str = "BoundedPoolIssuanceV1";
const INTERFACE_ID: &str = bounded_pool_rules::ALLOCATION_VALIDATION_INTERFACE;
const ENTRYPOINT: &str = "bounded_pool_rules::execute_allocation_vectors";
const RULES_FILE: &str = "source/tree/adapters/native-kas-bounded/src/bounded_pool_rules.rs";
const LINKED_RULES_SOURCE: &[u8] =
    include_bytes!("../../adapters/native-kas-bounded/src/bounded_pool_rules.rs");

pub(crate) fn run(manifest: &Value, package_root: &Path) -> Result<Value, String> {
    let source = super::validate_manifest_value(manifest)?;
    let source_hash = source["source_hash"]
        .as_str()
        .ok_or("SOURCE_HASH_INVALID")?;
    let binding = source["external_dependencies"]
        .as_array()
        .and_then(|dependencies| {
            dependencies
                .iter()
                .find_map(|dependency| dependency.get("profile_vector_binding"))
        })
        .ok_or("PROFILE_VECTOR_BINDING_REQUIRED")?;
    let interface_binding = binding
        .get("interface_binding")
        .ok_or("PROFILE_VECTOR_INTERFACE_BINDING_INVALID")?;

    let package_root = fs::canonicalize(package_root)
        .map_err(|error| format!("PROFILE_PACKAGE_PATH_ERROR:{error}"))?;
    let (package, _) = super::verify_profile_package(package_root.clone())?;
    if package.get("profile_id").and_then(Value::as_str) != Some(PROFILE_ID)
        || binding.get("profile_id").and_then(Value::as_str) != Some(PROFILE_ID)
        || binding.get("profile_semver") != package.get("profile_semver")
        || binding.get("package_digest") != package.get("package_digest")
        || interface_binding.get("consumer").and_then(Value::as_str) != Some(source_hash)
        || interface_binding.get("provider").and_then(Value::as_str) != Some(PROFILE_ID)
        || interface_binding.get("adapter_hash") != package.get("package_digest")
    {
        return Err("PROFILE_VECTOR_PACKAGE_BINDING_MISMATCH".into());
    }

    let file_digests = package
        .get("file_digests")
        .and_then(Value::as_object)
        .ok_or("PROFILE_PACKAGE_FILE_DIGESTS_INVALID")?;
    if file_digests.get(RULES_FILE).and_then(Value::as_str)
        != Some(super::hex_string(&Sha256::digest(LINKED_RULES_SOURCE)).as_str())
    {
        return Err("PROFILE_VECTOR_LINKED_RULES_SOURCE_MISMATCH".into());
    }

    let interface_bytes = fs::read(package_root.join("interfaces.json"))
        .map_err(|error| format!("PROFILE_VECTOR_INTERFACE_READ_ERROR:{error}"))?;
    let expected_interface_digest = file_digests
        .get("interfaces.json")
        .and_then(Value::as_str)
        .ok_or("PROFILE_PACKAGE_INTERFACE_DIGEST_MISSING")?;
    if super::hex_string(&Sha256::digest(&interface_bytes)) != expected_interface_digest {
        return Err("PROFILE_PACKAGE_FILE_DIGEST_MISMATCH:interfaces.json".into());
    }
    let interface_file = super::parse_strict_json(&interface_bytes)
        .map_err(|error| format!("PROFILE_VECTOR_INTERFACE_JSON_INVALID:{error}"))?;
    let local_interfaces = interface_file
        .get("local_vector_interfaces")
        .and_then(Value::as_array)
        .ok_or("PROFILE_VECTOR_INTERFACE_NOT_FOUND")?;
    let interface = local_interfaces
        .iter()
        .find(|interface| {
            interface.get("interface_id").and_then(Value::as_str) == Some(INTERFACE_ID)
        })
        .ok_or("PROFILE_VECTOR_INTERFACE_NOT_FOUND")?;
    if interface.get("entrypoint").and_then(Value::as_str) != Some(ENTRYPOINT)
        || interface.get("execution_scope").and_then(Value::as_str)
            != Some("PURE_DETERMINISTIC_LOCAL")
        || interface.get("network_effect").and_then(Value::as_str) != Some("NONE")
        || interface.get("signing_allowed") != Some(&Value::Bool(false))
        || interface.get("broadcast") != Some(&Value::Bool(false))
        || binding.get("entrypoint").and_then(Value::as_str) != Some(ENTRYPOINT)
        || interface_binding.get("interface_id") != interface.get("interface_id")
        || interface_binding.get("interface_version") != interface.get("interface_version")
        || interface_binding.get("input_schema_hash") != interface.get("input_schema_hash")
        || interface_binding.get("output_schema_hash") != interface.get("output_schema_hash")
        || interface_binding.get("error_schema_hash") != interface.get("error_schema_hash")
        || interface_binding.get("wallet_mode").and_then(Value::as_str) != Some("walletless-read")
        || interface_binding
            .get("settlement_mode")
            .and_then(Value::as_str)
            != Some("NONE")
    {
        return Err("PROFILE_VECTOR_INTERFACE_BINDING_MISMATCH".into());
    }

    for (schema_field, hash_field) in [
        ("input_schema", "input_schema_hash"),
        ("output_schema", "output_schema_hash"),
        ("error_schema", "error_schema_hash"),
    ] {
        let schema = interface
            .get(schema_field)
            .ok_or("PROFILE_VECTOR_INTERFACE_SCHEMA_MISSING")?;
        if interface.get(hash_field).and_then(Value::as_str)
            != Some(super::sha256_value(schema)?.as_str())
        {
            return Err("PROFILE_VECTOR_INTERFACE_SCHEMA_HASH_MISMATCH".into());
        }
    }

    let input_schema = interface
        .get("input_schema")
        .and_then(|schema| schema.get("items"))
        .and_then(|schema| schema.get("properties"))
        .and_then(|schema| schema.get("input"))
        .ok_or("PROFILE_VECTOR_INTERFACE_SCHEMA_INVALID")?;
    let input_properties = input_schema
        .get("properties")
        .ok_or("PROFILE_VECTOR_INTERFACE_SCHEMA_INVALID")?;
    let max_pool_size = schema_bound(
        input_properties
            .get("pool_size")
            .and_then(|field| field.get("maximum"))
            .ok_or("PROFILE_VECTOR_INTERFACE_LIMIT_MISSING")?,
    )?;
    let max_batch_size = schema_bound(
        input_properties
            .get("max_batch")
            .and_then(|field| field.get("maximum"))
            .ok_or("PROFILE_VECTOR_INTERFACE_LIMIT_MISSING")?,
    )?;
    let max_grants = schema_bound(
        input_properties
            .get("grants")
            .and_then(|field| field.get("maxItems"))
            .ok_or("PROFILE_VECTOR_INTERFACE_LIMIT_MISSING")?,
    )?;
    let vectors = Value::Array(
        source["test_vectors"]
            .as_array()
            .ok_or("TEST_VECTORS_REQUIRED")?
            .to_vec(),
    );
    let result = bounded_pool_rules::execute_allocation_vectors(
        &vectors,
        max_pool_size,
        max_batch_size,
        max_grants,
        u64::MAX,
    );
    let execution_trace = result
        .get("execution_trace")
        .cloned()
        .unwrap_or_else(|| json!([]));
    let status = result
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("BLOCKED");
    Ok(json!({
        "schema":"KTAPEOUT-LOCAL-RUNNER-V1",
        "protocol_semver":"0.5.0",
        "runner_id":"bounded-pool-allocation-v1",
        "status":status,
        "evidence_origin":"BUILT_IN_PROFILE_VECTOR_EXECUTION",
        "execution_scope":"PROFILE_RULES",
        "source_hash":source_hash,
        "application_source_hash":source_hash,
        "source_manifest_hash":super::sha256_value(manifest)?,
        "profile_id":PROFILE_ID,
        "profile_semver":package["profile_semver"],
        "profile_package_digest":package["package_digest"],
        "profile_vector_binding":binding,
        "execution_trace":execution_trace,
        "network_effect":"NONE",
        "signing_allowed":false,
        "broadcast":false
    }))
}

pub(crate) fn write_execution_handoff(
    runner_result: &Value,
    manifest: &Value,
    output: &Path,
) -> Result<(), String> {
    if let Some(parent) = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent).map_err(|error| format!("PROFILE_VECTOR_OUTPUT_DIR:{error}"))?;
    }
    if let Ok(metadata) = fs::symlink_metadata(output) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err("PROFILE_VECTOR_OUTPUT_NOT_REGULAR_FILE".into());
        }
    }
    let handoff = execution_handoff(runner_result, manifest)?;
    let text = serde_json::to_string_pretty(&handoff).map_err(|error| error.to_string())? + "\n";
    super::atomic_write_file(
        output,
        text.as_bytes(),
        "PROFILE_VECTOR_HANDOFF_WRITE_ERROR",
    )
}

pub(crate) fn execution_handoff(runner_result: &Value, manifest: &Value) -> Result<Value, String> {
    let passed = runner_result.get("status").and_then(Value::as_str) == Some("LOCAL_EXECUTABLE");
    Ok(json!({
        "schema":"KTAPEOUT-DEV-EXECUTE-V1",
        "protocol_semver":"0.5.0",
        "lifecycle_status":if passed {"EXECUTED_LOCAL"} else {"LOCAL_EXECUTION_FAILED"},
        "runner_status":runner_result["status"],
        "source_hash":manifest["source_hash"],
        "source_manifest_hash":super::sha256_value(manifest)?,
        "artifact_hash":null,
        "execution_scope":"PROFILE_RULES",
        "runner_result":runner_result,
        "external_action":false,
        "network_effect":"NONE",
        "signing_allowed":false,
        "broadcast":false
    }))
}

pub(crate) fn test(
    manifest_path: &Path,
    package_root: &Path,
    execution_result_output: Option<&Path>,
) -> Result<(), String> {
    let manifest = super::read_json(manifest_path)?;
    let runner_result = run(&manifest, package_root)?;
    if let Some(output) = execution_result_output {
        write_execution_handoff(&runner_result, &manifest, output)?;
    }
    let trace = runner_result["execution_trace"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let passed = runner_result["status"] == "LOCAL_EXECUTABLE";
    let result = json!({
        "schema":"KTAPEOUT-DEV-TEST-V1",
        "protocol_semver":"0.5.0",
        "lifecycle_status":if passed {"EXECUTED_LOCAL"} else {"LOCAL_EXECUTION_FAILED"},
        "test_mode":"BUILT_IN_PROFILE_VECTOR_EXECUTION",
        "execution_scope":"PROFILE_RULES",
        "source_hash":manifest["source_hash"],
        "source_manifest_hash":super::sha256_value(&manifest)?,
        "test_vector_count":trace.len(),
        "test_summary":{
            "cases":trace.len(),
            "passed":trace.iter().filter(|row| row["status"] == "PASS").count(),
            "failed":trace.iter().filter(|row| row["status"] != "PASS").count(),
            "all_passed":passed
        },
        "execution_trace":trace,
        "runner_result":runner_result,
        "execution_result_output":execution_result_output.map(|path| path.display().to_string()),
        "external_action":false,
        "safe_to_retry":true,
        "network_effect":"NONE",
        "signing_allowed":false,
        "broadcast":false,
        "next_action":if passed {
            "use execution_result_output as workflow.local_execution_result to join this trace with the workflow build and ApplicationLock"
        } else {
            "repair the failing Profile vectors and rerun the explicit local Profile executor"
        }
    });
    super::emit_result_status(
        "ktape dev test",
        manifest.get("network").and_then(Value::as_str),
        if passed { "PASS" } else { "BLOCKED" },
        result,
    )
}

fn schema_bound(value: &Value) -> Result<usize, String> {
    value
        .as_u64()
        .and_then(|value| usize::try_from(value).ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| "PROFILE_VECTOR_INTERFACE_LIMIT_INVALID".to_string())
}
