//! Local workflow orchestration reuses the public CLI's implementations.
//! A manifest check or artifact descriptor never proves runtime execution.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fs, path::Path};

pub(crate) struct LocalPackage {
    pub descriptor: Value,
    pub files: Vec<(&'static str, String)>,
}

#[derive(Clone, Copy)]
pub(crate) struct BuildBinding<'a> {
    pub lock: Option<&'a Value>,
    pub policy: Option<&'a Value>,
}

/// Validate the result emitted by the existing local Profile runner boundary.
/// The Rust workflow consumes a result file rather than starting an arbitrary
/// process: execution remains host-owned, while source binding and the
/// no-side-effect boundary are checked in the canonical workflow.
pub(crate) fn validate_local_execution_result(
    value: &Value,
    source_hash: &str,
    source_manifest_hash: &str,
    expected_vector_count: usize,
    expected_profile_vector_binding: Option<&Value>,
) -> Result<Value, String> {
    let data = value.get("data").unwrap_or(value);
    let object = data
        .as_object()
        .ok_or_else(|| "DEV_WORKFLOW_LOCAL_EXECUTION_RESULT_INVALID".to_string())?;
    if object.get("schema").and_then(Value::as_str) != Some("KTAPEOUT-DEV-EXECUTE-V1")
        || object.get("protocol_semver").and_then(Value::as_str) != Some("0.5.0")
        || object.get("lifecycle_status").and_then(Value::as_str) != Some("EXECUTED_LOCAL")
        || object.get("runner_status").and_then(Value::as_str) != Some("LOCAL_EXECUTABLE")
        || object.get("source_hash").and_then(Value::as_str) != Some(source_hash)
        || object.get("source_manifest_hash").and_then(Value::as_str) != Some(source_manifest_hash)
        || object.get("external_action") != Some(&Value::Bool(false))
        || object.get("network_effect").and_then(Value::as_str) != Some("NONE")
        || object.get("signing_allowed") != Some(&Value::Bool(false))
        || object.get("broadcast") != Some(&Value::Bool(false))
    {
        return Err("DEV_WORKFLOW_LOCAL_EXECUTION_RESULT_UNBOUND_OR_SIDE_EFFECTING".into());
    }
    let runner_result = object
        .get("runner_result")
        .and_then(Value::as_object)
        .ok_or_else(|| "DEV_WORKFLOW_LOCAL_EXECUTION_RESULT_RUNNER_MISSING".to_string())?;
    let execution_scope = object.get("execution_scope");
    if execution_scope != runner_result.get("execution_scope")
        || execution_scope.is_some_and(|scope| {
            !matches!(
                scope.as_str(),
                Some("PROFILE_RULES" | "APPLICATION_ARTIFACT")
            )
        })
    {
        return Err("DEV_WORKFLOW_LOCAL_EXECUTION_SCOPE_INVALID".into());
    }
    let profile_rules = execution_scope.and_then(Value::as_str) == Some("PROFILE_RULES");
    if profile_rules && expected_profile_vector_binding.is_none() {
        return Err("DEV_WORKFLOW_PROFILE_VECTOR_BINDING_MISMATCH".into());
    }
    if runner_result.get("schema").and_then(Value::as_str) != Some("KTAPEOUT-LOCAL-RUNNER-V1")
        || runner_result.get("status").and_then(Value::as_str) != Some("LOCAL_EXECUTABLE")
        || runner_result.get("network_effect").and_then(Value::as_str) != Some("NONE")
        || runner_result.get("signing_allowed") != Some(&Value::Bool(false))
        || runner_result.get("broadcast") != Some(&Value::Bool(false))
        || runner_result
            .get("source_manifest_hash")
            .and_then(Value::as_str)
            != Some(source_manifest_hash)
    {
        return Err("DEV_WORKFLOW_LOCAL_EXECUTION_RUNNER_BOUNDARY_INVALID".into());
    }
    match (
        expected_profile_vector_binding,
        runner_result.get("profile_vector_binding"),
    ) {
        (Some(expected), Some(reported)) if expected == reported => {}
        (Some(_), _) | (None, Some(_)) => {
            return Err("DEV_WORKFLOW_PROFILE_VECTOR_BINDING_MISMATCH".into())
        }
        (None, None) => {}
    }
    let trace = runner_result
        .get("execution_trace")
        .and_then(Value::as_array)
        .ok_or_else(|| "DEV_WORKFLOW_LOCAL_EXECUTION_TRACE_MISSING".to_string())?;
    if trace.len() != expected_vector_count {
        return Err("DEV_WORKFLOW_LOCAL_EXECUTION_TRACE_COUNT_MISMATCH".into());
    }
    let mut seen = vec![false; expected_vector_count];
    for item in trace {
        let object = item
            .as_object()
            .ok_or_else(|| "DEV_WORKFLOW_LOCAL_EXECUTION_TRACE_ENTRY_INVALID".to_string())?;
        let index = object
            .get("vector_index")
            .and_then(Value::as_u64)
            .and_then(|index| usize::try_from(index).ok())
            .filter(|index| *index < expected_vector_count)
            .ok_or_else(|| "DEV_WORKFLOW_LOCAL_EXECUTION_TRACE_BINDING_INVALID".to_string())?;
        if seen[index] {
            return Err("DEV_WORKFLOW_LOCAL_EXECUTION_TRACE_BINDING_INVALID".into());
        }
        seen[index] = true;
        if object.get("status").and_then(Value::as_str) != Some("PASS") {
            return Err("DEV_WORKFLOW_LOCAL_EXECUTION_VECTOR_FAILED".into());
        }
    }
    if seen.iter().any(|observed| !observed) {
        return Err("DEV_WORKFLOW_LOCAL_EXECUTION_TRACE_BINDING_INVALID".into());
    }
    let runner_result_bytes = serde_json::to_vec(&Value::Object(runner_result.clone()))
        .map_err(|_| "DEV_WORKFLOW_LOCAL_EXECUTION_RUNNER_RESULT_SERIALIZATION_FAILED")?;
    let runner_result_digest = super::digest_bytes(
        &runner_result_bytes,
        "KTAPEOUT/0.5.0/LOCAL_RUNNER_RESULT/V1",
    );
    for field in ["application_source_hash", "source_hash"] {
        if runner_result
            .get(field)
            .is_some_and(|value| value.as_str() != Some(source_hash))
        {
            return Err("DEV_WORKFLOW_LOCAL_EXECUTION_SOURCE_BINDING_MISMATCH".into());
        }
    }
    let artifact_hash = match object.get("artifact_hash") {
        None | Some(Value::Null) => Value::Null,
        Some(value) if is_lower_hash(value) => value.clone(),
        Some(_) => return Err("DEV_WORKFLOW_LOCAL_EXECUTION_ARTIFACT_HASH_INVALID".into()),
    };
    if profile_rules && artifact_hash != Value::Null {
        return Err("DEV_WORKFLOW_PROFILE_RULES_ARTIFACT_NOT_APPLICABLE".into());
    }
    for field in ["artifact_hash", "artifact_sha256"] {
        if runner_result
            .get(field)
            .is_some_and(|value| value != &artifact_hash)
        {
            return Err("DEV_WORKFLOW_LOCAL_EXECUTION_ARTIFACT_BINDING_MISMATCH".into());
        }
    }
    let runner_package_hash = match object.get("runner_package_hash") {
        None | Some(Value::Null) => Value::Null,
        Some(value) if is_lower_hash(value) => value.clone(),
        Some(_) => return Err("DEV_WORKFLOW_RUNNER_PACKAGE_HASH_INVALID".into()),
    };
    if runner_result
        .get("runner_package_hash")
        .is_some_and(|value| value != &runner_package_hash)
    {
        return Err("DEV_WORKFLOW_RUNNER_PACKAGE_BINDING_MISMATCH".into());
    }
    let application_binding = match object.get("application_binding") {
        None | Some(Value::Null) => Value::Null,
        Some(Value::Object(binding)) => {
            if binding.get("status").and_then(Value::as_str) != Some("LOCAL_ONLY")
                || binding
                    .get("binding_kind")
                    .and_then(Value::as_str)
                    .is_none_or(str::is_empty)
                || binding
                    .get("runner_id")
                    .and_then(Value::as_str)
                    .is_none_or(str::is_empty)
                || binding.get("l1_evidence") != Some(&Value::Bool(false))
                || binding.get("signing_allowed") != Some(&Value::Bool(false))
                || binding.get("broadcast") != Some(&Value::Bool(false))
            {
                return Err("DEV_WORKFLOW_LOCAL_APPLICATION_BINDING_INVALID".into());
            }
            for field in ["project_sha256", "artifact_sha256", "runtime_bundle_hash"] {
                match binding.get(field) {
                    Some(Value::Null) => {}
                    Some(value) if is_lower_hash(value) => {}
                    _ => return Err("DEV_WORKFLOW_LOCAL_APPLICATION_BINDING_INVALID".into()),
                }
            }
            if binding["artifact_sha256"] != Value::Null
                && binding["artifact_sha256"] != artifact_hash
            {
                return Err("DEV_WORKFLOW_LOCAL_APPLICATION_ARTIFACT_MISMATCH".into());
            }
            if runner_result.get("runner_id").is_some_and(|runner_id| {
                runner_id.as_str() != binding.get("runner_id").and_then(Value::as_str)
            }) {
                return Err("DEV_WORKFLOW_LOCAL_APPLICATION_RUNNER_MISMATCH".into());
            }
            Value::Object(binding.clone())
        }
        Some(_) => return Err("DEV_WORKFLOW_LOCAL_APPLICATION_BINDING_INVALID".into()),
    };
    if profile_rules && application_binding != Value::Null {
        return Err("DEV_WORKFLOW_PROFILE_RULES_APPLICATION_BINDING_NOT_APPLICABLE".into());
    }
    let application_lock_hash = match object.get("application_lock_hash") {
        None => Value::Null,
        Some(value) if value.is_null() => Value::Null,
        Some(value) if is_lower_hash(value) => value.clone(),
        Some(_) => return Err("DEV_WORKFLOW_APPLICATION_LOCK_HASH_INVALID".into()),
    };
    if runner_result
        .get("application_lock_hash")
        .is_some_and(|value| value != &application_lock_hash)
    {
        return Err("DEV_WORKFLOW_APPLICATION_LOCK_BINDING_MISMATCH".into());
    }
    let external_input_binding = match object.get("external_input_binding") {
        None => Value::Null,
        Some(binding) => {
            validate_external_input_binding(binding, &application_lock_hash)?;
            if profile_rules
                || execution_scope.and_then(Value::as_str) != Some("APPLICATION_ARTIFACT")
            {
                return Err("DEV_WORKFLOW_EXTERNAL_INPUT_SCOPE_INVALID".into());
            }
            if runner_result.get("external_input_digest") != binding.get("input_digest")
                || runner_result.get("application_lock_hash")
                    != binding.get("application_lock_hash")
            {
                return Err("DEV_WORKFLOW_EXTERNAL_INPUT_RUNNER_BINDING_MISMATCH".into());
            }
            binding.clone()
        }
    };
    if external_input_binding == Value::Null && runner_result.get("external_input_digest").is_some()
    {
        return Err("DEV_WORKFLOW_EXTERNAL_INPUT_HANDOFF_MISSING".into());
    }
    let mut normalized = json!({
        "schema":"KTAPEOUT-LOCAL-EXECUTION-EVIDENCE-V1",
        "status":"LOCAL_EXECUTED",
        "evidence_origin":"LOCAL_EXECUTION",
        "execution_scope":execution_scope,
        "profile_vector_binding":runner_result.get("profile_vector_binding"),
        "source_hash":source_hash,
        "source_manifest_hash":source_manifest_hash,
        "artifact_hash":artifact_hash,
        "artifact_binding":"UNVERIFIED_UNTIL_WORKFLOW_BUILD",
        "runner_status":object["runner_status"],
        "test_vector_count":trace.len(),
        "runner_result_digest":runner_result_digest,
        "runner_package_hash":runner_package_hash,
        "application_binding":application_binding,
        "application_lock_hash":application_lock_hash,
        "network_effect":"NONE",
        "signing_allowed":false,
        "broadcast":false
    });
    if external_input_binding != Value::Null {
        normalized["external_input_binding"] = external_input_binding;
    }
    Ok(normalized)
}

/// Validate the value-free observation projection emitted by Studio. This
/// preserves a local audit link; it does not authenticate the provider or
/// upgrade the observation to L1 evidence.
fn validate_external_input_binding(
    binding: &Value,
    application_lock_hash: &Value,
) -> Result<(), String> {
    const FIELDS: [&str; 11] = [
        "schema",
        "kind",
        "purpose",
        "application_lock_hash",
        "input_digest",
        "request_digest",
        "response_digest",
        "captured_at",
        "time_basis",
        "authenticated",
        "l1_evidence",
    ];
    let object = binding
        .as_object()
        .ok_or_else(|| "DEV_WORKFLOW_EXTERNAL_INPUT_BINDING_INVALID".to_string())?;
    if object.len() != FIELDS.len()
        || FIELDS.iter().any(|field| !object.contains_key(*field))
        || binding.get("schema").and_then(Value::as_str) != Some("KTAPEOUT-EXTERNAL-INPUT-V1")
        || !matches!(
            binding.get("kind").and_then(Value::as_str),
            Some("http" | "mcp")
        )
        || !matches!(
            binding.get("purpose").and_then(Value::as_str),
            Some("COMPUTE_INPUT" | "PLAN_INPUT" | "PROPOSAL_INPUT")
        )
        || !is_lower_hash(application_lock_hash)
        || binding.get("application_lock_hash") != Some(application_lock_hash)
        || !["input_digest", "request_digest", "response_digest"]
            .iter()
            .all(|field| binding.get(*field).is_some_and(is_lower_hash))
        || binding
            .get("captured_at")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || binding.get("time_basis").and_then(Value::as_str) != Some("HOST_CLOCK")
        || binding.get("authenticated") != Some(&Value::Bool(false))
        || binding.get("l1_evidence") != Some(&Value::Bool(false))
    {
        return Err("DEV_WORKFLOW_EXTERNAL_INPUT_BINDING_INVALID".into());
    }
    Ok(())
}

fn is_lower_hash(value: &Value) -> bool {
    value.as_str().is_some_and(|hash| {
        hash.len() == 64
            && hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

pub(crate) fn validate_local_execution_lock_binding(
    execution: &mut Value,
    application_lock: Option<&Value>,
) -> Result<(), &'static str> {
    let execution_lock_hash = execution
        .get("application_lock_hash")
        .filter(|value| !value.is_null())
        .cloned();
    match (application_lock, execution_lock_hash.as_ref()) {
        (Some(lock), Some(hash)) if hash == &lock["lock_hash"] => {}
        (Some(_), Some(_)) => return Err("DEV_WORKFLOW_APPLICATION_LOCK_BINDING_MISMATCH"),
        (Some(_), None) => {}
        (None, Some(_)) => return Err("DEV_WORKFLOW_APPLICATION_LOCK_RESULT_WITHOUT_LOCK"),
        (None, None) => return Ok(()),
    }

    let Some(lock) = application_lock else {
        return Ok(());
    };
    if execution.get("execution_scope").and_then(Value::as_str) == Some("PROFILE_RULES") {
        let binding = execution
            .get("profile_vector_binding")
            .ok_or("DEV_WORKFLOW_APPLICATION_LOCK_PROFILE_BINDING_MISSING")?;
        let components = lock
            .get("components")
            .and_then(Value::as_array)
            .ok_or("DEV_WORKFLOW_APPLICATION_LOCK_COMPONENTS_INVALID")?;
        let matches_component = components.iter().any(|component| {
            component.get("profile_id") == binding.get("profile_id")
                && component.get("profile_semver") == binding.get("profile_semver")
                && component.get("package_digest") == binding.get("package_digest")
        });
        if !matches_component {
            return Err("DEV_WORKFLOW_APPLICATION_LOCK_PROFILE_COMPONENT_MISMATCH");
        }
        if let Some(object) = execution.as_object_mut() {
            object.insert("application_lock_hash".into(), lock["lock_hash"].clone());
        }
        return Ok(());
    }
    if execution_lock_hash.is_none() {
        return Err("DEV_WORKFLOW_APPLICATION_LOCK_RESULT_HASH_REQUIRED");
    }
    Ok(())
}

/// A Studio Project starter, using the same canonical compiler as handoff builds.
/// Its execution is distinct from the editable Source Manifest contract.
pub(crate) fn write_runtime_starter(output: &Path, profile: &str) -> Result<Value, String> {
    let bit = |direction: &str| json!({"direction":direction,"type":"Bit"});
    let project = json!({
        "schema":"KTAPEOUT-PROJECT-V2","protocol_semver":"0.5.0",
        "project_id":"starter","profile":profile,"profile_version":"1",
        "revision":1,"parent_revision":null,
        "design":{"nodes":[
            {"id":"a","kind":"Input","params":{},"ports":{"out":bit("out")}},
            {"id":"b","kind":"Input","params":{},"ports":{"out":bit("out")}},
            {"id":"n","kind":"NAND","params":{},"ports":{"a":bit("in"),"b":bit("in"),"out":bit("out")}},
            {"id":"r","kind":"Register","params":{"slot":0},"ports":{"in":bit("in"),"out":bit("out")}},
            {"id":"o","kind":"Output","params":{},"ports":{"in":bit("in")}}
        ],"connections":[
            {"from":{"node":"a","port":"out"},"to":{"node":"n","port":"a"}},
            {"from":{"node":"b","port":"out"},"to":{"node":"n","port":"b"}},
            {"from":{"node":"n","port":"out"},"to":{"node":"r","port":"in"}},
            {"from":{"node":"r","port":"out"},"to":{"node":"o","port":"in"}}
        ],"parameters":{},"modules":[]},
        "tests":[
            {"id":"capture-one","inputs":[0,0],"state":[0],"steps":2,"expected_outputs":[1],"expected_state":[1]},
            {"id":"capture-zero","inputs":[1,1],"state":[1],"steps":2,"expected_outputs":[0],"expected_state":[0]},
            {"id":"preserve-initial","inputs":[0,1],"state":[1],"steps":1,"expected_outputs":[1],"expected_state":[1]}
        ],
        "layout":{"nodes":{},"viewport":{"x":0,"y":0,"zoom":1}},
        "publish_intent":{"network":"testnet-10","profile_status":"local-only"}
    });
    let bundle = super::studio_runtime_bundle::build_bundle(&project, None)?;
    let text = serde_json::to_string_pretty(&project).map_err(|e| e.to_string())? + "\n";
    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>KTAPEOUT Starter Reference Simulation</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; background: #0d1117; color: #c9d1d9; padding: 2rem; }}
    .badge {{ display: inline-block; padding: 0.25rem 0.6rem; background: #da3633; color: #ffffff; border-radius: 4px; font-weight: bold; margin-bottom: 0.5rem; font-size: 0.85rem; letter-spacing: 0.05em; }}
    .badge-secondary {{ display: inline-block; padding: 0.2rem 0.5rem; background: #30363d; color: #8b949e; border-radius: 4px; font-size: 0.8rem; margin-bottom: 0.5rem; margin-left: 0.4rem; }}
    .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 1.5rem; max-width: 650px; }}
    h2 {{ margin-top: 0; color: #58a6ff; }}
    .info {{ margin: 0.5rem 0; }}
    .notice {{ background: #1f1b16; border-left: 3px solid #d29922; color: #e3b341; padding: 0.75rem 1rem; margin: 1rem 0; font-size: 0.88rem; border-radius: 0 4px 4px 0; line-height: 1.4; }}
    .state-panel {{ background: #0d1117; border: 1px solid #21262d; border-radius: 4px; padding: 1rem; margin: 1rem 0; font-family: monospace; }}
    button {{ background: #238636; color: #ffffff; border: none; padding: 0.6rem 1.2rem; border-radius: 6px; cursor: pointer; font-size: 0.95rem; font-weight: 600; }}
    button:hover {{ background: #2ea043; }}
    code {{ background: #0d1117; padding: 0.15rem 0.4rem; border-radius: 3px; font-family: monospace; }}
  </style>
</head>
<body>
  <div>
    <span class="badge">[LOCAL_SIMULATION_ONLY]</span>
    <span class="badge-secondary">[STANDALONE_REFERENCE_SAMPLE]</span>
  </div>
  <div class="card">
    <h2>KTAPEOUT Reference Simulation Demo</h2>
    <div class="notice">
      <strong>Notice:</strong> This standalone HTML demonstration simulates the default state transition pattern (NAND + Register) for quick reference. It is an independent static sample and does <em>not</em> dynamically execute or reload modified <code>project.json</code> designs. To compile and simulate your project, run:
      <br><br>
      <code>ktape artifact simulate-project runtime-bundle.json inputs.json state.json --steps 2</code>
    </div>
    <div class="info">Profile: <strong>{profile}</strong></div>
    <div class="info">Mode: Static Browser Demonstration (No L1 Network Effect)</div>
    <div class="state-panel">
      <div>Inputs: <span id="inputs">[0, 0]</span></div>
      <div>State (Register): <span id="state">[0]</span></div>
      <div>Output: <span id="output">1</span></div>
      <div>Step Count: <span id="steps">0</span></div>
    </div>
    <button id="stepBtn">Execute Reference Step</button>
  </div>
  <script>
    let state = 0;
    let stepCount = 0;
    const inputs = [0, 0];
    document.getElementById('stepBtn').addEventListener('click', () => {{
      const a = inputs[0];
      const b = inputs[1];
      const nand = (a === 1 && b === 1) ? 0 : 1;
      state = nand;
      stepCount++;
      document.getElementById('state').textContent = `[${{state}}]`;
      document.getElementById('output').textContent = state;
      document.getElementById('steps').textContent = stepCount;
    }});
  </script>
</body>
</html>
"#
    );
    write_generated_files(
        output,
        &[
            ("project.json", text),
            ("inputs.json", "[0,0]\n".into()),
            ("state.json", "[0]\n".into()),
            ("index.html", html),
        ],
        "runtime-bundle.json",
        &bundle,
    )?;
    Ok(
        json!({"status":"BUILDABLE_LOCAL","profile":profile,"project":"project.json",
        "bundle":"runtime-bundle.json","bundle_hash":bundle["bundle_hash"],
        "evidence_origin":"STATIC","tests_executed":false,
        "scope":"STUDIO_PROJECT_STARTER_NOT_SOURCE_MANIFEST_IMPLEMENTATION",
        "next_action":"ktape artifact simulate-project runtime-bundle.json inputs.json state.json --steps 2"}),
    )
}

pub(crate) fn build_package(
    source: &Value,
    network: &str,
    backend: &str,
) -> Result<LocalPackage, String> {
    build_package_bound(
        source,
        network,
        backend,
        BuildBinding {
            lock: None,
            policy: None,
        },
    )
}

pub(crate) fn build_package_bound(
    source: &Value,
    network: &str,
    backend: &str,
    binding: BuildBinding<'_>,
) -> Result<LocalPackage, String> {
    super::validate_manifest_value(source)?;
    if !matches!(network, "testnet-10" | "mainnet") {
        return Err("PACKAGE_NETWORK_UNSUPPORTED".into());
    }
    if source
        .get("network")
        .and_then(Value::as_str)
        .is_some_and(|v| v != network)
    {
        return Err("SOURCE_NETWORK_PROJECT_MISMATCH".into());
    }
    let translation = super::translate_manifest_value(source, network)?;
    let artifact = match (binding.lock, binding.policy) {
        (Some(lock), Some(policy)) => {
            if policy["network_id"] != network {
                return Err("PACKAGE_NETWORK_POLICY_MISMATCH".into());
            }
            super::artifact_build_v2_value(source, lock, policy, backend, "0.5.0")?
        }
        (None, None) => {
            let artifact = super::artifact_build_value(source, backend, "0.5.0")?;
            super::validate_artifact_value(&artifact)?;
            artifact
        }
        _ => return Err("PACKAGE_BUILD_BINDING_INCOMPLETE".into()),
    };
    let source_text = serde_json::to_string_pretty(source).map_err(|e| e.to_string())? + "\n";
    let artifact_text = serde_json::to_string_pretty(&artifact).map_err(|e| e.to_string())? + "\n";
    // Keep generated files within the existing Studio/Bridge consumer envelope.
    if source_text.len() > 256 * 1024 || artifact_text.len() > 256 * 1024 {
        return Err("DEV_PACKAGE_FILE_OVERSIZED".into());
    }
    let mut descriptor = json!({
        "schema":"KTAPEOUT-DEV-PACKAGE-V1", "protocol_semver":"0.5.0", "network":network,
        "backend":artifact["backend"], "source_hash":source["source_hash"],
        "artifact_source_hash":artifact["source_hash"], "artifact_root":artifact["artifact"]["hash"],
        "project_lock":artifact["developer_lock_hash"], "translation_status":translation["status"],
        "capability_matrix":translation["capability_matrix"],
        "files":{
            "source_manifest":{"path":"source-manifest.json", "content_hash":source["source_hash"],
                "file_sha256":hex::encode(Sha256::digest(source_text.as_bytes()))},
            "artifact_bundle":{"path":"artifact.json", "content_hash":artifact["artifact"]["hash"],
                "file_sha256":hex::encode(Sha256::digest(artifact_text.as_bytes()))}
        },
        "package_hash":"0".repeat(64), "lifecycle_status":"PACKAGED_LOCAL",
        "evidence_origin":"LOCAL_SIMULATION", "external_action":false,"safe_to_retry":true,
        "network_effect":"NONE","signing_allowed":false,"broadcast":false
    });
    let mut files = vec![
        ("source-manifest.json", source_text),
        ("artifact.json", artifact_text),
    ];
    if let (Some(lock), Some(policy)) = (binding.lock, binding.policy) {
        for (key, path, value, content_hash) in [
            (
                "developer_lock",
                "developer-lock.json",
                lock,
                &lock["lock_hash"],
            ),
            (
                "network_policy",
                "network-policy.json",
                policy,
                &policy["policy_id"],
            ),
        ] {
            let text = serde_json::to_string_pretty(value).map_err(|e| e.to_string())? + "\n";
            if text.len() > 256 * 1024 {
                return Err("DEV_PACKAGE_FILE_OVERSIZED".into());
            }
            descriptor["files"][key] = json!({"path":path,"content_hash":content_hash,
                "file_sha256":hex::encode(Sha256::digest(text.as_bytes()))});
            files.push((path, text));
        }
    }
    descriptor["package_hash"] = json!(super::digest_json_domain(
        &descriptor,
        "KTAPEOUT/0.5.0/DEV_PACKAGE/V1"
    )?);
    Ok(LocalPackage { descriptor, files })
}

pub(crate) fn write_package(output: &Path, package: &LocalPackage) -> Result<(), String> {
    write_generated_files(
        output,
        &package.files,
        "ktapeout-package.json",
        &package.descriptor,
    )
}

pub(crate) fn write_build(
    output: &Path,
    source: &Value,
    artifact: &Value,
) -> Result<Value, String> {
    let text = serde_json::to_string_pretty(artifact).map_err(|e| e.to_string())? + "\n";
    let mut descriptor = json!({
        "schema":"KTAPEOUT-DEV-BUILD-BUNDLE-V1","protocol_semver":"0.5.0",
        "source_hash":source["source_hash"],"artifact_source_hash":artifact["source_hash"],
        "artifact_root":artifact["artifact"]["hash"],"project_lock":artifact["developer_lock_hash"],
        "backend":artifact["backend"],"artifact_file":"artifact.json",
        "artifact_file_sha256":hex::encode(Sha256::digest(text.as_bytes())),
        "runtime":{"status":"NOT_CONFIGURED","entrypoint":null,"evidence_origin":"STATIC"},
        "build_hash":"0".repeat(64),"lifecycle_status":"BUILDABLE_LOCAL",
        "evidence_origin":"STATIC","network_effect":"NONE","signing_allowed":false,"broadcast":false
    });
    descriptor["build_hash"] = json!(super::digest_json_domain(
        &descriptor,
        "KTAPEOUT/0.5.0/DEV_BUILD_BUNDLE/V1"
    )?);
    write_generated_files(
        output,
        &[("artifact.json", text)],
        "ktapeout-build.json",
        &descriptor,
    )?;
    Ok(descriptor)
}

fn write_generated_files(
    output: &Path,
    files: &[(&str, String)],
    descriptor_name: &str,
    descriptor_value: &Value,
) -> Result<(), String> {
    // Generated files may be updated, but never follow a caller-supplied link.
    let absolute = if output.is_absolute() {
        output.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| e.to_string())?
            .join(output)
    };
    for ancestor in absolute.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(meta) if meta.file_type().is_symlink() || !meta.is_dir() => {
                return Err("PACKAGE_OUTPUT_NOT_REGULAR_DIRECTORY".into())
            }
            Ok(_) => (),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(format!("PACKAGE_OUTPUT_READ_ERROR:{e}")),
        }
    }
    fs::create_dir_all(&absolute).map_err(|e| format!("PACKAGE_OUTPUT_CREATE_ERROR:{e}"))?;
    for name in files
        .iter()
        .map(|(name, _)| *name)
        .chain(std::iter::once(descriptor_name))
    {
        match fs::symlink_metadata(absolute.join(name)) {
            Ok(meta) if meta.file_type().is_symlink() || !meta.is_file() => {
                return Err("PACKAGE_OUTPUT_FILE_NOT_REGULAR".into())
            }
            Ok(_) => (),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            Err(e) => return Err(format!("PACKAGE_OUTPUT_READ_ERROR:{e}")),
        }
    }
    for (name, text) in files {
        super::atomic_write_file(&absolute.join(name), text.as_bytes(), "PACKAGE_WRITE_ERROR")?;
    }
    // Descriptor is installed last so consumers reject any interrupted update.
    let descriptor =
        serde_json::to_string_pretty(descriptor_value).map_err(|e| e.to_string())? + "\n";
    super::atomic_write_file(
        &absolute.join(descriptor_name),
        descriptor.as_bytes(),
        "PACKAGE_WRITE_ERROR",
    )
}

pub(crate) fn output_path(
    base: &Path,
    workflow: &Value,
    field: &str,
    default: &str,
) -> Result<std::path::PathBuf, String> {
    let value = match workflow.get(field) {
        None => default,
        Some(Value::String(value)) => value,
        Some(_) => {
            return Err(format!(
                "DEV_WORKFLOW_{}_INVALID",
                field.to_ascii_uppercase()
            ))
        }
    };
    let name = Path::new(value);
    if name.as_os_str().is_empty()
        || name.components().any(|part| {
            !matches!(
                part,
                std::path::Component::Normal(_) | std::path::Component::CurDir
            )
        })
    {
        return Err(format!(
            "DEV_WORKFLOW_{}_MUST_BE_RELATIVE",
            field.to_ascii_uppercase()
        ));
    }
    Ok(base.join(name))
}

pub(crate) fn publishability(
    source: &Value,
    network: &str,
    backend: &str,
    binding: BuildBinding<'_>,
) -> Result<Value, String> {
    let plan = match (binding.lock, binding.policy) {
        (Some(lock), Some(policy)) => {
            if policy["network_id"] != network {
                return Err("PACKAGE_NETWORK_POLICY_MISMATCH".into());
            }
            let artifact = super::artifact_build_v2_value(source, lock, policy, backend, "0.5.0")?;
            super::deployment_plan_for_artifact(source, &artifact, network, None)?
        }
        (None, None) => super::deployment_plan_for_source(source, network, backend, None)?,
        _ => return Err("DEV_WORKFLOW_BUILD_BINDING_INCOMPLETE".into()),
    };
    let missing = &plan["missing_evidence"];
    let ready = missing.as_array().is_some_and(|items| items.is_empty());
    let next_action = if ready {
        "hand the exact plan to a selected wallet or local signer; a remote Operator is optional"
    } else {
        "supply the missing reference inputs, then choose a direct wallet/local signer; configure remote Operator transport only if a remote service is desired"
    };
    Ok(json!({
        "schema":"KTAPEOUT-DEV-PUBLISHABILITY-V1","network":network,
        "source_hash":source["source_hash"],"plan_hash":plan["plan_hash"],
        "artifact_root":plan["artifact_root"],"project_lock":plan["project_lock"],
        "lifecycle_status":if ready {"TN10_PUBLISHABLE_PLAN"} else {"NOT_PUBLISHABLE"},
        "missing_evidence":missing,"next_action":next_action,
        "write_paths":write_path_contract(),
        "external_action":false,"safe_to_retry":true,"network_effect":"NONE","signing_allowed":false,"broadcast":false
    }))
}

fn write_path_contract() -> Value {
    json!({
        "direct_wallet_or_cli": {
            "requires_remote_operator": false,
            "requires_plan_signature": true
        },
        "remote_operator": {
            "optional": true,
            "requires_exact_https_origin": true,
            "requires_caller_authentication": true,
            "requires_response_signature": true
        }
    })
}

pub(crate) fn missing_application_contract(source: &Value) -> Vec<&'static str> {
    let has = |field: &str| {
        source
            .get(field)
            .and_then(Value::as_array)
            .is_some_and(|v| !v.is_empty())
    };
    let has_action = has("action_declarations");
    let has_inputs = has("inputs");
    let has_outputs = has("outputs");
    let has_purpose = source
        .get("declared_purpose")
        .and_then(Value::as_str)
        .is_some_and(|value| !value.trim().is_empty());

    if has_action || (has_inputs && has_outputs) || (has_outputs && has_purpose) {
        Vec::new()
    } else if has_inputs {
        vec!["outputs or actions"]
    } else if has_outputs {
        vec!["declared_purpose or inputs or actions"]
    } else if has("persistent_state") {
        vec!["inputs/outputs or actions"]
    } else {
        vec!["inputs", "outputs", "persistent_state", "actions"]
    }
}

pub(crate) fn test_project(project: &Value) -> Result<Value, String> {
    let bundle = super::studio_runtime_bundle::build_bundle(project, None)?;
    let verified = super::studio_runtime_bundle::verify_bundle(&bundle)?;
    let tests = project["tests"].as_array().ok_or("PROJECT_TESTS_INVALID")?;
    if tests.is_empty() || tests.len() > 64 {
        return Err("PROJECT_TEST_COUNT_INVALID".into());
    }
    let mut results = Vec::new();
    let mut total_steps = 0u64;
    let mut test_ids = BTreeSet::new();
    for test in tests {
        let fields = [
            "id",
            "inputs",
            "state",
            "steps",
            "expected_outputs",
            "expected_state",
        ];
        if !test.is_object()
            || test.as_object().is_some_and(|object| {
                object.len() != fields.len()
                    || fields.iter().any(|field| !object.contains_key(*field))
            })
        {
            return Err("PROJECT_TEST_FIELDS_INVALID".into());
        }
        let id = test["id"]
            .as_str()
            .filter(|id| !id.is_empty() && id.len() <= 64)
            .ok_or("PROJECT_TEST_ID_INVALID")?;
        if !test_ids.insert(id) {
            return Err("PROJECT_TEST_ID_DUPLICATED".into());
        }
        let inputs = super::decode_bit_vector(&test["inputs"])?;
        let state = super::decode_bit_vector(&test["state"])?;
        let expected_outputs = super::decode_bit_vector(&test["expected_outputs"])?;
        let expected_state = super::decode_bit_vector(&test["expected_state"])?;
        let steps = test["steps"]
            .as_u64()
            .filter(|steps| *steps > 0 && *steps <= 1024)
            .ok_or("PROJECT_TEST_STEPS_INVALID")?;
        total_steps += steps;
        if total_steps > 4096 {
            return Err("PROJECT_TEST_STEP_BUDGET_EXCEEDED".into());
        }
        let execution = super::simulate_state_machine_artifact_050(
            &verified.artifact_bytes,
            &inputs,
            &state,
            steps as u32,
        )
        .map_err(|e| e.0)?;
        let count = *execution.first().ok_or("KTB1_RESULT_INVALID")? as usize;
        let state_index = count + 1;
        let registers = *execution.get(state_index).ok_or("KTB1_RESULT_INVALID")? as usize;
        if execution.len() != state_index + 1 + registers {
            return Err("KTB1_RESULT_INVALID".into());
        }
        let outputs = &execution[1..state_index];
        let state = &execution[state_index + 1..];
        results.push(json!({"id":id,"status":if outputs == expected_outputs && state == expected_state {"PASS"} else {"FAIL"},
            "steps":steps,"outputs":outputs,"state":state,"expected_outputs":expected_outputs,"expected_state":expected_state}));
    }
    Ok(json!({"schema":"KTAPEOUT-DEV-PROJECT-TEST-V1",
        "status":if results.iter().all(|result| result["status"] == "PASS") {"PASS"} else {"FAIL"},
        "evidence_origin":"LOCAL_SIMULATION","scope":"STUDIO_PROJECT_ONLY",
        "source_manifest_validation":"STRUCTURE_ONLY_SEPARATE_CONTRACT",
        "project_sha256":verified.project_hash,"artifact_sha256":verified.artifact_hash,
        "bundle_hash":bundle["bundle_hash"],
        "application_binding":{
            "status":"LOCAL_ONLY",
            "binding_kind":"RUNTIME_PROJECT",
            "project_sha256":verified.project_hash,
            "artifact_sha256":verified.artifact_hash,
            "bundle_hash":bundle["bundle_hash"],
            "runner_id":"ktapeout.bounded-state-machine",
            "l1_evidence":false,
            "signing_allowed":false,
            "broadcast":false
        },
        "tests":results,"signing_allowed":false,"broadcast":false}))
}

// These are the explicit inputs and outputs of the ordered stage runner.
#[allow(clippy::too_many_arguments)]
pub(crate) fn execute_stages(
    stages: &[&str],
    source: &Value,
    network: &str,
    backend: &str,
    binding: BuildBinding<'_>,
    build_output: &Path,
    package_output: &Path,
    project: Option<&Value>,
    local_execution: Option<&Value>,
    local_execution_error: Option<&str>,
) -> Vec<Value> {
    let mut results = Vec::new();
    let mut blocked = false;
    let mut built_artifact_hash: Option<String> = None;
    let has_lock = binding.lock.is_some();
    for stage in stages {
        if blocked {
            results
                .push(json!({"stage":stage,"status":"NOT_RUN","reason":"PREVIOUS_STAGE_BLOCKED"}));
            continue;
        }
        let result = match *stage {
            "check" => super::check_manifest_value(source, network),
            "build" if !has_lock || binding.policy.is_some() => {
                let artifact = match (binding.lock, binding.policy) {
                    (Some(lock), Some(policy)) => {
                        super::artifact_build_v2_value(source, lock, policy, backend, "0.5.0")
                    }
                    (None, None) => {
                        super::artifact_build_value(source, backend, "0.5.0").and_then(|artifact| {
                            super::validate_artifact_value(&artifact)?;
                            Ok(artifact)
                        })
                    }
                    _ => Err("DEV_WORKFLOW_BUILD_BINDING_INCOMPLETE".into()),
                };
                artifact.and_then(|artifact| {
                    write_build(build_output, source, &artifact)?;
                    if local_execution.is_some() {
                        built_artifact_hash = artifact
                            .get("artifact")
                            .and_then(|value| value.get("hash"))
                            .and_then(Value::as_str)
                            .map(str::to_owned);
                    }
                    Ok(artifact)
                })
            }
            "package" if !has_lock || binding.policy.is_some() => build_package_bound(
                source,
                network,
                backend,
                BuildBinding {
                    lock: binding.lock,
                    policy: binding.policy,
                },
            )
            .and_then(|package| {
                write_package(package_output, &package)?;
                Ok(package.descriptor)
            }),
            "publishability" if !has_lock || binding.policy.is_some() => {
                publishability(source, network, backend, binding)
            }
            "test" if local_execution_error.is_some() => {
                Err(local_execution_error.unwrap().to_owned())
            }
            "test" => match (project, local_execution) {
                (Some(project), _) => test_project(project),
                (None, Some(evidence)) => {
                    let mut evidence = evidence.clone();
                    if evidence["execution_scope"] == "PROFILE_RULES" {
                        evidence["artifact_binding"] = json!("NOT_APPLICABLE_PROFILE_RULES");
                        Ok(evidence)
                    } else if let Some(expected) = built_artifact_hash.as_deref() {
                        if evidence.get("artifact_hash").and_then(Value::as_str) != Some(expected) {
                            Err("DEV_WORKFLOW_LOCAL_EXECUTION_ARTIFACT_MISMATCH".into())
                        } else {
                            evidence["artifact_binding"] = json!("WORKFLOW_BUILD_MATCHED");
                            Ok(evidence)
                        }
                    } else {
                        evidence["artifact_binding"] = json!(if evidence
                            .get("artifact_hash")
                            .and_then(Value::as_str)
                            .is_some()
                        {
                            "ARTIFACT_NOT_CHECKED_BUILD_UNAVAILABLE"
                        } else {
                            "SOURCE_ONLY_LEGACY"
                        });
                        Ok(evidence)
                    }
                }
                (None, None) => super::test_manifest_value(source),
            },
            _ => {
                results.push(json!({"stage":stage,"status":"NOT_RUN","reason":
                    if has_lock && binding.policy.is_none() {"LOCKED_BUILD_REQUIRES_NETWORK_POLICY"}
                    else if has_lock {"LOCKED_STAGE_NOT_IMPLEMENTED"} else {"NOT_IMPLEMENTED_IN_PUBLIC_CLI"}}));
                continue;
            }
        };
        match result {
            Ok(result) => {
                let failed = *stage == "test" && project.is_some() && result["status"] == "FAIL";
                blocked |= failed;
                let stage_status = if failed {
                    "BLOCKED"
                } else if *stage == "test" && local_execution.is_some() {
                    "LOCAL_EXECUTED"
                } else if *stage == "test" && project.is_none() {
                    "STRUCTURE_ONLY"
                } else if *stage == "publishability"
                    && result["lifecycle_status"] == "NOT_PUBLISHABLE"
                {
                    "NOT_PUBLISHABLE"
                } else if matches!(
                    result["stages"]["translation"].as_str(),
                    Some("NEEDS_INPUT" | "REQUIRES_HUMAN_REVIEW")
                ) || result["translation_status"].as_str()
                    == Some("REQUIRES_HUMAN_REVIEW")
                {
                    result["stages"]["translation"]
                        .as_str()
                        .or_else(|| result["translation_status"].as_str())
                        .unwrap_or("REQUIRES_HUMAN_REVIEW")
                } else {
                    "PASS"
                };
                results.push(json!({"stage":stage,"status":stage_status,
                "evidence_origin":if *stage == "test" && project.is_some() {"LOCAL_SIMULATION"} else if *stage == "test" && local_execution.is_some() {"LOCAL_EXECUTION"} else {"STATIC"},"result":result}));
            }
            Err(error) => {
                let recoverable_handoff = *stage == "test"
                    && (local_execution_error.is_some()
                        || error == "DEV_WORKFLOW_LOCAL_EXECUTION_ARTIFACT_MISMATCH");
                if !recoverable_handoff {
                    blocked = true;
                }
                results.push(json!({"stage":stage,"status":if recoverable_handoff {"NEEDS_INPUT"} else {"BLOCKED"},"error_code":super::stable_error_code(&error),"reason":error}));
            }
        }
    }
    results
}

pub(crate) fn workflow_status(stages: &[Value]) -> &'static str {
    if stages.iter().any(|v| v["status"] == "BLOCKED") {
        "BLOCKED"
    } else if stages.iter().any(|stage| !workflow_stage_completed(stage)) {
        "INCOMPLETE"
    } else {
        "PASS"
    }
}

fn workflow_stage_completed(stage: &Value) -> bool {
    if stage["status"] == "PASS" {
        return true;
    }
    let result = &stage["result"];
    stage["status"] == "LOCAL_EXECUTED"
        && result["status"] == "LOCAL_EXECUTED"
        && result["evidence_origin"] == "LOCAL_EXECUTION"
        && result["execution_scope"] == "PROFILE_RULES"
        && result["network_effect"] == "NONE"
        && result["signing_allowed"] == false
        && result["broadcast"] == false
        && result["runner_status"] == "LOCAL_EXECUTABLE"
}

/// Expose the first verified application-level local binding at the workflow
/// boundary. Stage-local evidence remains intact; this projection only avoids
/// making CLI/Studio/AI consumers know which stage produced it.
pub(crate) fn workflow_application_binding(stages: &[Value]) -> Value {
    stages
        .iter()
        .find_map(|stage| stage.get("result")?.get("application_binding").cloned())
        .unwrap_or(Value::Null)
}

/// Build the smallest replayable application evidence projection from already
/// verified workflow inputs. This is a local join, not a new authority or
/// execution proof: the lock and execution handoff were validated by the
/// caller before this projection is emitted.
pub(crate) fn workflow_application_evidence(
    application_lock: Option<&Value>,
    local_execution: Option<&Value>,
) -> Result<Value, String> {
    let (Some(lock), Some(execution)) = (application_lock, local_execution) else {
        return Ok(Value::Null);
    };
    let runner_result_digest = execution
        .get("runner_result_digest")
        .filter(|value| is_lower_hash(value))
        .ok_or_else(|| "DEV_WORKFLOW_RUNNER_RESULT_DIGEST_MISSING".to_string())?;
    let source_manifest_hash = execution
        .get("source_manifest_hash")
        .filter(|value| is_lower_hash(value))
        .ok_or_else(|| "DEV_WORKFLOW_SOURCE_MANIFEST_HASH_MISSING".to_string())?;
    let material = json!({
        "application_lock_hash": lock["lock_hash"],
        "source_hash": execution["source_hash"],
        "source_manifest_hash": source_manifest_hash,
        "artifact_hash": execution["artifact_hash"],
        "artifact_binding": execution["artifact_binding"],
        "runner_result_digest": runner_result_digest,
        "runner_package_hash": execution["runner_package_hash"],
        "runner_status": execution["runner_status"],
        "application_binding": execution.get("application_binding").cloned().unwrap_or(Value::Null),
    });
    let profile_rules = execution["execution_scope"] == "PROFILE_RULES";
    let mut material = material;
    let external_input_binding = execution.get("external_input_binding").cloned();
    if let Some(binding) = external_input_binding.as_ref() {
        validate_external_input_binding(binding, &lock["lock_hash"])?;
        if profile_rules || execution["execution_scope"] != "APPLICATION_ARTIFACT" {
            return Err("DEV_WORKFLOW_EXTERNAL_INPUT_SCOPE_INVALID".into());
        }
        material["external_input_binding"] = binding.clone();
    }
    let evidence_digest_domain = if external_input_binding.is_some() {
        "KTAPEOUT/0.5.0/APPLICATION_EXECUTION_EVIDENCE/V3"
    } else {
        "KTAPEOUT/0.5.0/APPLICATION_EXECUTION_EVIDENCE/V2"
    };
    if profile_rules {
        material["execution_scope"] = execution["execution_scope"].clone();
        material["profile_vector_binding"] = execution["profile_vector_binding"].clone();
    }
    let evidence_digest = super::digest_json_domain(&material, evidence_digest_domain)?;
    let mut evidence = json!({
        "status":if profile_rules {"PROFILE_RULES_EXECUTED"} else {"LOCAL_REPLAYABLE"},
        "evidence_scope":if profile_rules {"LOCKED_PROFILE_RULES_HANDOFF"} else {"LOCKED_LOCAL_EXECUTION_HANDOFF"},
        "execution_scope":execution.get("execution_scope"),
        "profile_vector_binding":execution.get("profile_vector_binding"),
        "evidence_digest_domain":evidence_digest_domain,
        "application_lock_hash":lock["lock_hash"],
        "source_hash":execution["source_hash"],
        "source_manifest_hash":source_manifest_hash,
        "artifact_hash":execution["artifact_hash"],
        "artifact_binding":execution["artifact_binding"],
        "runner_result_digest":runner_result_digest,
        "runner_package_hash":execution["runner_package_hash"],
        "runner_status":execution["runner_status"],
        "application_binding":execution.get("application_binding").cloned().unwrap_or(Value::Null),
        "evidence_digest":evidence_digest,
        "l1_evidence":false,
        "signing_allowed":false,
        "broadcast":false,
    });
    if let Some(binding) = external_input_binding {
        evidence["external_input_binding"] = binding;
    }
    Ok(evidence)
}

/// Revalidate the exact local evidence projection before it is bound to a
/// delivery intent. This confirms its deterministic digest and the lock/build
/// tuple; it does not replay execution or upgrade the evidence to L1 proof.
pub(crate) fn validate_application_evidence_for_delivery(
    evidence: &Value,
    application_lock_hash: &str,
    artifact_root: &str,
) -> Result<(), String> {
    let fields = [
        "status",
        "evidence_scope",
        "execution_scope",
        "profile_vector_binding",
        "evidence_digest_domain",
        "application_lock_hash",
        "source_hash",
        "source_manifest_hash",
        "artifact_hash",
        "artifact_binding",
        "runner_result_digest",
        "runner_package_hash",
        "runner_status",
        "application_binding",
        "evidence_digest",
        "l1_evidence",
        "signing_allowed",
        "broadcast",
    ];
    let object = evidence
        .as_object()
        .ok_or_else(|| "PUBLISH_APPLICATION_EVIDENCE_FIELDS_INVALID".to_string())?;
    let external_input_binding = evidence.get("external_input_binding");
    let has_external_input = external_input_binding.is_some();
    if object.len() != fields.len() + usize::from(has_external_input)
        || fields.iter().any(|field| !object.contains_key(*field))
        || (has_external_input && !object.contains_key("external_input_binding"))
    {
        return Err("PUBLISH_APPLICATION_EVIDENCE_FIELDS_INVALID".into());
    }
    let expected_domain = if has_external_input {
        "KTAPEOUT/0.5.0/APPLICATION_EXECUTION_EVIDENCE/V3"
    } else {
        "KTAPEOUT/0.5.0/APPLICATION_EXECUTION_EVIDENCE/V2"
    };
    if evidence.get("status").and_then(Value::as_str) != Some("LOCAL_REPLAYABLE")
        || evidence.get("evidence_scope").and_then(Value::as_str)
            != Some("LOCKED_LOCAL_EXECUTION_HANDOFF")
        || evidence.get("execution_scope").and_then(Value::as_str) != Some("APPLICATION_ARTIFACT")
        || evidence.get("profile_vector_binding") != Some(&Value::Null)
        || evidence
            .get("evidence_digest_domain")
            .and_then(Value::as_str)
            != Some(expected_domain)
        || evidence
            .get("application_lock_hash")
            .and_then(Value::as_str)
            != Some(application_lock_hash)
        || evidence.get("artifact_hash").and_then(Value::as_str) != Some(artifact_root)
        || evidence.get("artifact_binding").and_then(Value::as_str)
            != Some("WORKFLOW_BUILD_MATCHED")
        || evidence.get("runner_status").and_then(Value::as_str) != Some("LOCAL_EXECUTABLE")
        || evidence.get("l1_evidence") != Some(&Value::Bool(false))
        || evidence.get("signing_allowed") != Some(&Value::Bool(false))
        || evidence.get("broadcast") != Some(&Value::Bool(false))
    {
        return Err("PUBLISH_APPLICATION_EVIDENCE_SCOPE_OR_BINDING_INVALID".into());
    }
    for field in [
        "application_lock_hash",
        "source_hash",
        "source_manifest_hash",
        "artifact_hash",
        "runner_result_digest",
        "evidence_digest",
    ] {
        if !evidence.get(field).is_some_and(is_lower_hash) {
            return Err(format!("PUBLISH_APPLICATION_EVIDENCE_{field}_INVALID"));
        }
    }
    let binding = evidence
        .get("application_binding")
        .filter(|value| value.is_object())
        .ok_or_else(|| "PUBLISH_APPLICATION_EVIDENCE_APPLICATION_BINDING_MISSING".to_string())?;
    if binding.get("status").and_then(Value::as_str) != Some("LOCAL_ONLY")
        || binding.get("artifact_sha256").and_then(Value::as_str) != Some(artifact_root)
        || binding.get("l1_evidence") != Some(&Value::Bool(false))
        || binding.get("signing_allowed") != Some(&Value::Bool(false))
        || binding.get("broadcast") != Some(&Value::Bool(false))
    {
        return Err("PUBLISH_APPLICATION_EVIDENCE_APPLICATION_BINDING_INVALID".into());
    }
    let material = json!({
        "application_lock_hash": evidence["application_lock_hash"],
        "source_hash": evidence["source_hash"],
        "source_manifest_hash": evidence["source_manifest_hash"],
        "artifact_hash": evidence["artifact_hash"],
        "artifact_binding": evidence["artifact_binding"],
        "runner_result_digest": evidence["runner_result_digest"],
        "runner_package_hash": evidence["runner_package_hash"],
        "runner_status": evidence["runner_status"],
        "application_binding": evidence["application_binding"],
    });
    let mut material = material;
    if let Some(binding) = external_input_binding {
        validate_external_input_binding(binding, &evidence["application_lock_hash"])?;
        material["external_input_binding"] = binding.clone();
    }
    let expected = super::digest_json_domain(&material, expected_domain)?;
    if evidence.get("evidence_digest").and_then(Value::as_str) != Some(expected.as_str()) {
        return Err("PUBLISH_APPLICATION_EVIDENCE_DIGEST_MISMATCH".into());
    }
    Ok(())
}

pub(crate) fn workflow_next_action(stages: &[Value], status: &str) -> &'static str {
    if status == "PASS"
        && !stages
            .iter()
            .any(|stage| stage["status"] == "NOT_PUBLISHABLE")
    {
        return "configured local stages passed; run ktape dev publishability <manifest> --network <network> when preparing delivery";
    }
    if stages.iter().any(|stage| {
        stage["stage"] == "test"
            && stage["status"] == "NEEDS_INPUT"
            && stage["error_code"].as_str().is_some_and(|code| {
                code.contains("APPLICATION_LOCK_PROFILE_COMPONENT_MISMATCH")
                    || code.contains("APPLICATION_LOCK_PROFILE_BINDING_MISSING")
            })
    }) {
        return "select the Profile package recorded by ApplicationLock, then rebuild the Recipe and lock together before rerunning ktape dev workflow";
    }
    if stages.iter().any(|stage| {
        stage["stage"] == "test"
            && stage["status"] == "NEEDS_INPUT"
            && stage["error_code"]
                .as_str()
                .is_some_and(|code| code.contains("APPLICATION_LOCK_RESULT_HASH_REQUIRED"))
    }) {
        return "rerun the host-local Application Artifact Runner with the verified ApplicationLock hash and export a fresh execution result";
    }
    if stages.iter().any(|stage| {
        stage["stage"] == "test"
            && stage["status"] == "NEEDS_INPUT"
            && stage["error_code"].as_str().is_some_and(|code| {
                code.contains("PROFILE_VECTOR") || code.contains("PROFILE_RULES")
            })
    }) {
        return "verify workflow.profile_package_root points to the Manifest-bound Profile package, correct the failing or stale vectors/binding, then rerun ktape dev workflow";
    }
    if stages.iter().any(|stage| {
        stage["stage"] == "test"
            && stage["status"] == "NEEDS_INPUT"
            && stage["error_code"].as_str().is_some_and(|code| {
                code.starts_with("E050_DEV_WORKFLOW_LOCAL_EXECUTION_")
                    || code.starts_with("E050_DEV_WORKFLOW_APPLICATION_LOCK_")
            })
    }) || stages.iter().any(|stage| {
        stage["status"] == "BLOCKED"
            && stage["error_code"] == "E050_DEV_WORKFLOW_LOCAL_EXECUTION_ARTIFACT_MISMATCH"
    }) {
        return "rebuild the current Artifact, rerun the host-local Runner against the current source and lock, export a fresh KTAPEOUT-DEV-EXECUTE-V1 result, update workflow.local_execution_result, then rerun ktape dev workflow";
    }
    if stages.iter().any(|stage| stage["status"] == "BLOCKED") {
        return "inspect the first BLOCKED stage and apply its error recovery action before rerunning ktape dev workflow";
    }
    if stages.iter().any(|stage| {
        stage["status"] == "NOT_RUN" && stage["reason"] == "LOCKED_BUILD_REQUIRES_NETWORK_POLICY"
    }) {
        return "use the exact NetworkPolicy whose content-addressed policy_id matches developer_lock.network_policy_id and set workflow.network_policy; if the lock contains a placeholder policy ID, rerun ktape init with the same --profile-package or --profile-lock, a validated --network-policy, and a new --output directory; do not edit the lock or invent policy values";
    }
    if stages.iter().any(|stage| {
        stage["status"] == "NOT_RUN" && stage["reason"] == "LOCKED_STAGE_NOT_IMPLEMENTED"
    }) {
        return "remove the unsupported locked stage or use the documented unlocked local path; do not treat NOT_RUN as success";
    }
    if stages
        .iter()
        .any(|stage| stage["status"] == "NOT_PUBLISHABLE")
    {
        return "local stage results remain usable; inspect publishability.missing_evidence and resolve deployment inputs separately when preparing delivery; rerun publishability only after those inputs change";
    }
    if stages.iter().any(|stage| stage["status"] == "NEEDS_INPUT") {
        return "run ktape ai requirements SOURCE.json, resolve the listed contract unknowns, then rerun ktape dev workflow";
    }
    if stages
        .iter()
        .any(|stage| stage["status"] == "REQUIRES_HUMAN_REVIEW")
    {
        return "resolve the listed semantic requirements and external decisions, then rerun ktape dev workflow";
    }
    if stages
        .iter()
        .any(|stage| stage["status"] == "STRUCTURE_ONLY")
    {
        return "for executable local behavior, bind a supported Machine or BoundedStateMachine Project as workflow.runtime_project, or use ktape artifact simulate-project; Source Manifest vectors remain unexecuted";
    }
    if stages.iter().any(|stage| {
        stage["stage"] == "test" && stage["result"]["execution_scope"] == "PROFILE_RULES"
    }) {
        return "Profile rule vectors passed locally; application Artifact execution and deployment evidence remain separate requirements";
    }
    if stages
        .iter()
        .any(|stage| stage["status"] == "LOCAL_EXECUTED")
    {
        return "local runner evidence is source-bound and side-effect free; bind the same execution to an implemented Profile/Application Package before deployment";
    }
    "resolve the first blocked or NOT_RUN stage; structural checks do not prove application execution or publishability"
}
