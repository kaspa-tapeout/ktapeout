use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT_TEMP_ID: AtomicUsize = AtomicUsize::new(0);

struct TempWorkspace(PathBuf);

impl TempWorkspace {
    fn new() -> Self {
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "ktapeout-cli-quickstart-{}-{id}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create isolated CLI test directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run_cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ktape"))
        .args(args)
        .output()
        .expect("run ktape CLI")
}

fn parse_output(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "CLI should return JSON on stdout: {error}; stderr={}",
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn parse_error(output: &Output) -> Value {
    serde_json::from_slice(&output.stderr).unwrap_or_else(|error| {
        panic!(
            "blocked CLI command should return JSON on stderr: {error}; stdout={}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn path_arg(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[test]
fn init_and_dev_workflow_report_expected_starter_boundaries() {
    let temp = TempWorkspace::new();
    let output_dir = temp.path().join("starter");
    let output_arg = path_arg(&output_dir);
    let init = run_cli(&[
        "init",
        "--template",
        "StateMachine",
        "--network",
        "testnet-10",
        "--output",
        &output_arg,
    ]);

    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    let quickstart: Value = serde_json::from_slice(
        &fs::read(output_dir.join("quickstart-result.json")).expect("quickstart result exists"),
    )
    .expect("quickstart result is JSON");
    assert_eq!(
        quickstart["validation"],
        json!({
            "status": "STRUCTURE_ONLY",
            "test_vector_count": 1,
            "tests_executed": false
        })
    );
    let generated_workflow: Value = serde_json::from_slice(
        &fs::read(output_dir.join("workflow.json")).expect("workflow exists"),
    )
    .expect("workflow is JSON");
    assert_eq!(
        generated_workflow["stages"],
        json!(["check", "build", "package", "test"])
    );
    assert!(!output_dir.join("profile-lock.json").exists());

    let app_test = run_cli(&[
        "app",
        "test",
        &path_arg(&output_dir.join("source-manifest.json")),
    ]);
    assert!(app_test.status.success());
    let app_result = parse_output(&app_test);
    assert_eq!(app_result["status"], "WARNING");
    assert_eq!(app_result["data"]["status"], "STRUCTURE_ONLY");
    assert_eq!(
        app_result["data"]["test_mode"],
        "STRUCTURAL_VECTOR_PRESENCE"
    );
    assert_eq!(app_result["data"]["vectors"], 1);
    assert_eq!(app_result["data"]["signing_allowed"], false);
    assert_eq!(app_result["data"]["broadcast"], false);
    assert!(app_result["data"].get("behavior_executed").is_none());

    let workflow = run_cli(&[
        "dev",
        "workflow",
        &path_arg(&output_dir.join("workflow.json")),
    ]);
    assert!(
        workflow.status.success(),
        "{}",
        String::from_utf8_lossy(&workflow.stderr)
    );
    let result = parse_output(&workflow);
    assert_eq!(result["status"], "UNAVAILABLE");
    assert_eq!(result["data"]["status"], "INCOMPLETE");
    assert_eq!(result["data"]["signing"], false);
    assert_eq!(result["data"]["broadcast"], false);
    assert_eq!(
        result["data"]["next_action"],
        "run ktape ai requirements SOURCE.json, resolve the listed contract unknowns, then rerun ktape dev workflow"
    );
    let stages = result["data"]["stages"]
        .as_array()
        .expect("workflow stages are an array");
    assert_eq!(stages.len(), 4);
    for (stage, expected) in [
        ("check", "NEEDS_INPUT"),
        ("build", "PASS"),
        ("package", "REQUIRES_HUMAN_REVIEW"),
        ("test", "STRUCTURE_ONLY"),
    ] {
        assert!(
            stages
                .iter()
                .any(|item| item["stage"] == stage && item["status"] == expected),
            "missing expected {stage}={expected} result: {}",
            result["data"]["stages"]
        );
    }
    let build = stages
        .iter()
        .find(|item| item["stage"] == "build")
        .expect("build stage exists");
    assert_eq!(build["result"]["status"], "LOCAL_ONLY");
    assert!(stages.iter().all(|item| item["stage"] != "publishability"));
}

#[test]
fn init_rejects_unsupported_template_with_a_stable_error() {
    let output = run_cli(&[
        "init",
        "--template",
        "Unsupported",
        "--network",
        "testnet-10",
    ]);

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        parse_error(&output)["error_code"],
        "E050_TEMPLATE_UNSUPPORTED"
    );
}

#[test]
fn dev_workflow_rejects_an_unsupported_schema() {
    let temp = TempWorkspace::new();
    let workflow = temp.path().join("workflow.json");
    fs::write(
        &workflow,
        br#"{"schema":"WRONG","protocol_semver":"0.5.0"}"#,
    )
    .expect("write invalid workflow fixture");

    let output = run_cli(&["dev", "workflow", &path_arg(&workflow)]);

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        parse_error(&output)["error_code"],
        "E050_DEV_WORKFLOW_SCHEMA_UNSUPPORTED"
    );
}

#[test]
fn app_test_rejects_a_manifest_without_vectors() {
    let temp = TempWorkspace::new();
    let output_dir = temp.path().join("starter");
    let init = run_cli(&["init", "--output", &path_arg(&output_dir)]);
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );

    let manifest_path = output_dir.join("source-manifest.json");
    let mut manifest: Value =
        serde_json::from_slice(&fs::read(&manifest_path).expect("source manifest exists"))
            .expect("source manifest is JSON");
    manifest["test_vectors"] = json!([]);
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .expect("write manifest without vectors");

    let output = run_cli(&["app", "test", &path_arg(&manifest_path)]);

    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        parse_error(&output)["error_code"],
        "E050_TEST_VECTORS_REQUIRED"
    );
}
