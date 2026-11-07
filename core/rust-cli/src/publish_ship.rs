//! One command for the keyless half of a publication: policy check -> plan -> preflight, then stop.
//!
//! `ship` adds no publishing logic. It runs the existing `ktape publish` steps in order, stops at the
//! first failure, and never goes past the point where an external operator must build the
//! OperatorPlan, select inputs, sign and broadcast. The result tells the operator exactly what is
//! pending and which commands run after the receipt exists.

use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub struct ShipInputs<'a> {
    pub package: &'a Path,
    pub policy: &'a Path,
    pub provider: &'a Path,
    pub kind: &'a str,
    pub at: &'a str,
    pub expires_at: &'a str,
    pub workdir: &'a Path,
}

/// Runs one `ktape` invocation and returns its parsed JSON envelope, or the stable error code.
pub trait StepRunner {
    fn run(&mut self, args: &[String]) -> Result<Value, String>;
}

/// Calls this same executable, so every step keeps its own validation and output contract.
pub struct SelfRunner {
    executable: PathBuf,
}

impl SelfRunner {
    pub fn new() -> Result<Self, String> {
        Ok(Self {
            executable: std::env::current_exe()
                .map_err(|_| "SHIP_EXECUTABLE_UNAVAILABLE".to_owned())?,
        })
    }
}

impl StepRunner for SelfRunner {
    fn run(&mut self, args: &[String]) -> Result<Value, String> {
        let output = Command::new(&self.executable)
            .args(args)
            .stdin(Stdio::null())
            .output()
            .map_err(|_| "SHIP_STEP_SPAWN_FAILED".to_owned())?;
        if output.status.success() {
            return serde_json::from_slice(&output.stdout)
                .map_err(|_| "SHIP_STEP_OUTPUT_INVALID".to_owned());
        }
        Err(failure_code(&output.stdout, &output.stderr))
    }
}

/// A failing step reports its stable error envelope on stderr; stdout is only a fallback.
fn failure_code(stdout: &[u8], stderr: &[u8]) -> String {
    [stderr, stdout]
        .iter()
        .filter_map(|bytes| serde_json::from_slice::<Value>(bytes).ok())
        .find_map(|envelope| envelope["data"]["error"].as_str().map(str::to_owned))
        .unwrap_or_else(|| "SHIP_STEP_FAILED".to_owned())
}

fn arg(value: impl AsRef<std::ffi::OsStr>) -> String {
    value.as_ref().to_string_lossy().into_owned()
}

fn step(
    runner: &mut dyn StepRunner,
    name: &str,
    args: Vec<String>,
    done: &mut Vec<Value>,
) -> Result<Value, String> {
    let envelope = runner
        .run(&args)
        .map_err(|code| format!("SHIP_STEP_FAILED:{name}:{code}"))?;
    done.push(json!({"step": name, "status": "PASS"}));
    Ok(envelope)
}

pub fn ship(inputs: &ShipInputs, runner: &mut dyn StepRunner) -> Result<Value, String> {
    let intent = inputs.workdir.join("intent.json");
    let mut done = Vec::new();
    step(
        runner,
        "policy-verify",
        vec!["publish".into(), "policy-verify".into(), arg(inputs.policy)],
        &mut done,
    )?;
    step(
        runner,
        "plan",
        vec![
            "publish".into(),
            "plan".into(),
            arg(inputs.package),
            arg(inputs.policy),
            "--kind".into(),
            inputs.kind.into(),
            "--at".into(),
            inputs.at.into(),
            "--expires-at".into(),
            inputs.expires_at.into(),
            "--output".into(),
            arg(&intent),
        ],
        &mut done,
    )?;
    step(
        runner,
        "preflight",
        vec![
            "publish".into(),
            "preflight".into(),
            arg(&intent),
            arg(inputs.policy),
            arg(inputs.provider),
        ],
        &mut done,
    )?;
    Ok(json!({
        "schema": "KTAPEOUT-PUBLISH-SHIP-V1",
        "status": "PREFLIGHT_ONLY",
        "delivery_complete": false,
        "steps": done,
        "intent_path": arg(&intent),
        "handoff": {
            "stopped_before": "external OperatorPlan, exact input selection, signing and broadcast",
            "operator_must": [
                "build the exact OperatorPlan for this intent outside ktape",
                "select the exact outpoints and keep signing and broadcast outside ktape"
            ],
            "then_run": [
                "ktape publish reserve <intent> <policy> --wallet-reference-hash <hash> --outpoint <txid:index> --ledger <file>",
                "ktape publish bind <intent> <policy> <provider> <operator-plan> --project-lock-hash <hash> --operation-output <file> --binding-output <file>",
                "ktape deploy readback <receipt>",
                "ktape record build ... --output <record.json>",
                "ktape record share <record.json>"
            ]
        },
        "signing_allowed": false,
        "broadcast": false,
    }))
}
