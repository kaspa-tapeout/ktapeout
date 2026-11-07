//! Rust implementation of the release workflow's `freeze` and `validate` stages.
//! It reads the same `KTAPEOUT-RELEASE-WORKFLOW-V1` config and records the two stages in a state file of the same
//! schema. Later stages (publish .. accept) need a trusted Host and are not ported yet. Local and read-only: no network,
//! signing, broadcast or deployment.
use crate::release_closure::{sha256, verify_runtime_with, RuntimeContext, ROOT_SCHEME};
use serde_json::{json, Value};
use std::fs;
use std::path::{Component, Path, PathBuf};

const CONFIG_SCHEMA: &str = "KTAPEOUT-RELEASE-WORKFLOW-V1";
const STATE_SCHEMA: &str = "KTAPEOUT-RELEASE-WORKFLOW-STATE-V1";
const MAX_FILE: u64 = 64 * 1024 * 1024;

fn is_hex64(v: &str) -> bool {
    v.len() == 64
        && v.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A path relative to `root` that stays inside it and crosses no symlink.
fn source_file(root: &Path, relative: &str) -> Result<PathBuf, String> {
    let bad = relative.is_empty()
        || relative.contains('\\')
        || Path::new(relative)
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
        || relative
            .split('/')
            .any(|s| s.is_empty() || s == "." || s == "..");
    if bad {
        return Err("FREEZE_PATH_INVALID".into());
    }
    let mut path = root.to_path_buf();
    for part in relative.split('/') {
        path.push(part);
        if fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink()) {
            return Err("FREEZE_PATH_ESCAPE".into());
        }
    }
    Ok(path)
}

fn read_source(root: &Path, relative: &str) -> Result<Vec<u8>, String> {
    let path = source_file(root, relative)?;
    let meta = fs::metadata(&path).map_err(|_| format!("FROZEN_INPUT_UNAVAILABLE:{relative}"))?;
    if !meta.is_file() || meta.len() > MAX_FILE {
        return Err(format!("FROZEN_INPUT_UNAVAILABLE:{relative}"));
    }
    fs::read(path).map_err(|_| format!("FROZEN_INPUT_UNAVAILABLE:{relative}"))
}

fn require_identity_match(actual: &Value, expected: &Value) -> Result<(), String> {
    for key in ["application_id", "release_id", "artifact_root"] {
        let valid = |v: &Value| v[key].as_str().is_some_and(is_hex64);
        if !valid(actual) || !valid(expected) {
            return Err(format!("RELEASE_IDENTITY_MISSING_OR_INVALID:{key}"));
        }
        if actual[key] != expected[key] {
            return Err(format!("RELEASE_IDENTITY_MISMATCH:{key}"));
        }
    }
    Ok(())
}

pub struct Config {
    value: Value,
    root: PathBuf,
    source_root: PathBuf,
}

pub fn load_config(file: &Path) -> Result<Config, String> {
    let value: Value =
        serde_json::from_slice(&fs::read(file).map_err(|_| "RELEASE_CONFIG_UNAVAILABLE")?)
            .map_err(|_| "RELEASE_CONFIG_INVALID")?;
    let dir = file.parent().unwrap_or(Path::new("."));
    let resolve = |key: &str| dir.join(value[key].as_str().unwrap_or("."));
    let root = resolve("root");
    let source_root = if value["source_root"].is_string() {
        resolve("source_root")
    } else {
        root.clone()
    };
    let origin = value["origin"].as_str().unwrap_or_default();
    let mode = value["mode"].as_str().unwrap_or_default();
    if value["schema"] != CONFIG_SCHEMA || !["production", "fixture", "observe"].contains(&mode) {
        return Err("RELEASE_CONFIG_INVALID".into());
    }
    require_identity_match(&value["identity"], &value["identity"])?;
    if value["network"] != "testnet-10"
        || value["route"]["network"] != value["network"]
        || !crate::release_closure::is_origin(origin)
    {
        return Err("RELEASE_SCOPE_INVALID".into());
    }
    if mode != "fixture" && !origin.starts_with("https://") {
        return Err("RELEASE_ORIGIN_INVALID".into());
    }
    Ok(Config {
        value,
        root,
        source_root,
    })
}

/// Every pinned input still has its frozen digest, and a build script is among them.
pub fn verify_frozen_inputs(config: &Config) -> Result<usize, String> {
    let inputs = config.value["inputs"].as_array().filter(|i| !i.is_empty());
    let inputs = inputs.filter(|i| i.iter().any(|x| x["role"] == "build-script"));
    let inputs = inputs.ok_or("FREEZE_BUILD_SCRIPT_REQUIRED")?;
    let mut seen = std::collections::BTreeSet::new();
    for item in inputs {
        let path = item["path"].as_str().unwrap_or_default();
        let digest = item["sha256"].as_str().filter(|d| is_hex64(d));
        let Some(digest) = digest.filter(|_| seen.insert(path)) else {
            return Err("FREEZE_INPUT_INVALID".into());
        };
        if sha256(&read_source(&config.source_root, path)?) != digest {
            return Err(format!("FROZEN_INPUT_CHANGED:{path}"));
        }
    }
    Ok(inputs.len())
}

/// The configured runtime manifest, loaded from `root` and checked as the Shell loads it, with the route's pinned digest.
pub fn validate_runtime(config: &Config) -> Result<Value, String> {
    let v = &config.value;
    require_identity_match(&v["identity"], &v["route"])?;
    let manifest_path = v["runtime_manifest"].as_str().unwrap_or_default();
    let bytes = read_source(&config.root, manifest_path)?;
    if v["route"]["manifest_sha256"] != sha256(&bytes) {
        return Err("RUNTIME_MANIFEST_HASH_MISMATCH".into());
    }
    let manifest: Value = serde_json::from_slice(&bytes).map_err(|_| "CONTENT_MANIFEST_INVALID")?;
    let route = &v["route"];
    let commitment_required =
        route["require_content_commitment"] == true || manifest.get("content_commitment").is_some();
    if manifest["entrypoint"] != route["entrypoint"]
        || (commitment_required
            && manifest["content_commitment"]["artifact_root"] != v["identity"]["artifact_root"])
    {
        return Err("RUNTIME_MANIFEST_IDENTITY_MISMATCH".into());
    }
    let prefix = format!(
        "{}/",
        route["manifest"]
            .as_str()
            .unwrap_or_default()
            .rsplit_once('/')
            .map_or("", |p| p.0)
    );
    let ctx = RuntimeContext {
        network: route["network"].as_str().unwrap_or_default(),
        application_uri: route["application_uri"].as_str().unwrap_or_default(),
        release_id: route["release_id"].as_str().unwrap_or_default(),
    };
    let allowed = [ROOT_SCHEME, "OnChainContentV1"];
    let shell = verify_runtime_with(&manifest, &ctx, &allowed, &mut |base, path| {
        if !format!("{base}{path}").starts_with(&prefix) {
            return Err("RUNTIME_PATH_ESCAPE".into());
        }
        Ok(read_source(&config.root, &format!("{base}{path}")[1..]).ok())
    })?;
    if route["require_content_commitment"] == true
        && shell["content_commitment"]["status"] != "VERIFIED"
    {
        return Err("RUNTIME_CONTENT_COMMITMENT_REQUIRED".into());
    }
    if shell["content_commitment"]["status"] != "VERIFIED" {
        return Err("RUNTIME_COMMITMENT_REQUIRED".into());
    }
    Ok(json!({"files": shell["files"], "content_commitment_status": "VERIFIED"}))
}

/// Run `freeze` then `validate` and write the state file. Existing state must belong to the same config.
pub fn check(config_file: &Path, state_file: &Path) -> Result<Value, String> {
    let config = load_config(config_file)?;
    let config_sha256 = sha256(&fs::read(config_file).map_err(|_| "RELEASE_CONFIG_UNAVAILABLE")?);
    let mut state = match fs::read(state_file) {
        Ok(bytes) => {
            serde_json::from_slice::<Value>(&bytes).map_err(|_| "RELEASE_STATE_INVALID")?
        }
        Err(_) => {
            json!({"schema": STATE_SCHEMA, "config_sha256": config_sha256, "host_id": "KTAPE_RUST_LOCAL", "mode": config.value["mode"], "steps": {}})
        }
    };
    if state["schema"] != STATE_SCHEMA
        || state["config_sha256"] != config_sha256
        || state["mode"] != config.value["mode"]
    {
        return Err("RELEASE_CONTINUATION_MISMATCH".into());
    }
    // Both stages are pure functions of the files: re-run them every time rather than trusting a recorded result.
    let inputs = verify_frozen_inputs(&config)?;
    state["steps"]["freeze"] = json!({"status": "DONE", "result": {"inputs": inputs}});
    let validated = validate_runtime(&config)?;
    state["steps"]["validate"] = json!({"status": "DONE", "result": validated});
    let mut out = serde_json::to_vec_pretty(&state).map_err(|_| "RELEASE_STATE_INVALID")?;
    out.push(b'\n');
    let temp = state_file.with_extension("tmp");
    fs::write(&temp, out).map_err(|_| "RELEASE_STATE_WRITE_FAILED")?;
    fs::rename(&temp, state_file).map_err(|_| "RELEASE_STATE_WRITE_FAILED")?;
    Ok(
        json!({"schema": "KTAPEOUT-RELEASE-CHECK-V1", "status": "FROZEN_AND_VALIDATED", "stages": ["freeze", "validate"],
        "freeze": state["steps"]["freeze"]["result"], "validate": state["steps"]["validate"]["result"],
        "pending_stages": ["publish", "readback", "import", "deploy", "accept"],
        "signing_allowed": false, "broadcast": false, "deployment": false}),
    )
}
