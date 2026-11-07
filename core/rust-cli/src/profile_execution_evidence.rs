//! Retained issuer execution binding; not admission, VM replay or fresh RPC.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::Path};

fn require(ok: bool, field: &str) -> Result<(), String> {
    if ok {
        Ok(())
    } else {
        Err(format!("PROFILE_EXECUTION_EVIDENCE_INVALID:{field}"))
    }
}

// Original Operator receipts hash Python json.dumps(sort_keys=True), including
// its spaces and ASCII escaping. Do not reinterpret these historical hashes
// as JCS or replace the public transaction codec.
fn receipt_json(value: &Value) -> Result<String, String> {
    Ok(match value {
        Value::Object(map) => {
            let mut keys: Vec<_> = map.keys().collect();
            keys.sort();
            let fields = keys
                .into_iter()
                .map(|key| {
                    Ok(format!(
                        "{}: {}",
                        receipt_json(&Value::String(key.clone()))?,
                        receipt_json(&map[key])?
                    ))
                })
                .collect::<Result<Vec<_>, String>>()?;
            format!("{{{}}}", fields.join(", "))
        }
        Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(receipt_json)
                .collect::<Result<Vec<_>, _>>()?
                .join(", ")
        ),
        Value::String(_) => {
            let encoded = serde_json::to_string(value).map_err(|e| e.to_string())?;
            let mut result = String::new();
            for ch in encoded.chars() {
                if ch.is_ascii() {
                    result.push(ch);
                } else {
                    for unit in ch.encode_utf16(&mut [0; 2]) {
                        result.push_str(&format!("\\u{unit:04x}"));
                    }
                }
            }
            result
        }
        Value::Number(number) => {
            require(
                number.is_i64() || number.is_u64(),
                "noninteger receipt number",
            )?;
            number.to_string()
        }
        _ => value.to_string(),
    })
}

pub fn verify(root: &Path, metadata: &Value) -> Result<Value, String> {
    let read = |path: &str| -> Result<Value, String> {
        require(
            metadata["file_digests"].get(path).is_some(),
            "unbound evidence path",
        )?;
        super::read_json(&root.join(path))
    };
    let binding = read("execution-evidence.json")?;
    let envelope = read("resource-envelope.json")?;
    require(
        envelope["network"] == "testnet-10" && envelope["worst_case_resource_admitted"] == false,
        "resource envelope network/worst-case claim",
    )?;
    require(
        super::object_fields_exact(
            &binding,
            &[
                "schema",
                "network",
                "profile_hash",
                "scope",
                "state_policies",
                "steps",
                "namespace_issuance",
            ],
            &[],
        ),
        "binding fields",
    )?;
    require(
        binding["schema"] == "KTAPEOUT-PROFILE-EXECUTION-EVIDENCE-V1"
            && binding["profile_hash"] == metadata["profile_hash"]
            && binding["network"] == "testnet-10"
            && binding["scope"] == "RETAINED_ENGINEERING_OBSERVATIONS",
        "binding identity/scope",
    )?;
    let policy = json!([{"role":"namespace_certificate", "exit_policy":"PERMANENT_TERMINAL", "refundable":false,"carrier_sompi":100000000}]);
    require(
        binding["state_policies"] == policy,
        "certificate refund policy",
    )?;
    let steps = binding["steps"]
        .as_array()
        .ok_or("PROFILE_EXECUTION_STEPS_REQUIRED")?;
    require(steps.len() == 5, "issuer execution step count")?;
    let mut bodies = BTreeMap::new();
    let mut receipts = BTreeMap::new();
    let mut txids = std::collections::BTreeSet::new();
    let mut observations = Vec::new();
    let mut resource_observations = Vec::new();
    let mut fee = 0u64;
    for step in steps {
        require(
            super::object_fields_exact(step, &["operation", "plan", "receipt", "txid"], &[]),
            "step fields",
        )?;
        let operation = step["operation"]
            .as_str()
            .ok_or("PROFILE_EXECUTION_OPERATION_REQUIRED")?;
        let txid = step["txid"]
            .as_str()
            .ok_or("PROFILE_EXECUTION_TXID_REQUIRED")?;
        require(
            super::valid_hash(txid)
                && txids.insert(txid.to_string())
                && !bodies.contains_key(operation),
            "duplicate operation/transaction",
        )?;
        let plan = read(
            step["plan"]
                .as_str()
                .ok_or("PROFILE_EXECUTION_PLAN_REQUIRED")?,
        )?;
        let body = plan.get("body").unwrap_or(&plan).clone();
        let receipt = read(
            step["receipt"]
                .as_str()
                .ok_or("PROFILE_EXECUTION_RECEIPT_REQUIRED")?,
        )?;
        require(
            body["network"] == "testnet-10"
                && receipt["network"] == "testnet-10"
                && body["native_vm_verified"] == true,
            "network/VM observation",
        )?;
        require(
            receipt["schema"] == "KTAPEOUT-TN10-CANDIDATE-WRITE-RECEIPT-V1"
                && receipt["status"] == "TN10_DUAL_RPC_STATE_CONFIRMED"
                && receipt["txid"] == txid,
            "receipt identity",
        )?;
        let hash = hex::encode(Sha256::digest(receipt_json(&body)?.as_bytes()));
        require(receipt["body_sha256"] == hash, "signed body digest")?;
        let step_fee = body["fee_sompi"]
            .as_u64()
            .ok_or("PROFILE_EXECUTION_FEE_INVALID")?;
        require(receipt["fee_sompi"] == body["fee_sompi"], "receipt fee")?;
        fee = fee
            .checked_add(step_fee)
            .ok_or("PROFILE_EXECUTION_FEE_OVERFLOW")?;
        let urls = receipt["rpc_urls"]
            .as_array()
            .ok_or("PROFILE_EXECUTION_RPC_URLS_REQUIRED")?;
        require(
            urls.len() == 2 && urls[0] != urls[1],
            "distinct RPC observations",
        )?;
        let inputs = body["transaction"]["inputs"]
            .as_array()
            .ok_or("PROFILE_EXECUTION_INPUTS_REQUIRED")?;
        let outputs = body["transaction"]["outputs"]
            .as_array()
            .ok_or("PROFILE_EXECUTION_OUTPUTS_REQUIRED")?;
        require(
            (1..=64).contains(&inputs.len()) && (1..=64).contains(&outputs.len()),
            "transaction shape",
        )?;
        if matches!(operation, "root-genesis" | "namespace-issuance") {
            let bound = |field: &str| {
                envelope[field]
                    .as_u64()
                    .filter(|n| *n > 0)
                    .ok_or_else(|| format!("PROFILE_EXECUTION_RESOURCE_BOUND_INVALID:{field}"))
            };
            require(
                inputs.len() as u64 <= bound("max_inputs")?
                    && outputs.len() as u64 <= bound("max_outputs")?,
                "issuer resource shape",
            )?;
            let mass = body["mass_projection"]["normalized_mass"]
                .as_u64()
                .filter(|n| *n > 0)
                .ok_or("PROFILE_EXECUTION_MASS_INVALID")?;
            let minimum_fee = mass
                .checked_mul(bound("observed_relay_sompi_per_gram")?)
                .ok_or("PROFILE_EXECUTION_MASS_FEE_OVERFLOW")?;
            let cap = if operation == "root-genesis" {
                "max_genesis_fee_sompi"
            } else {
                "max_issuance_fee_sompi"
            };
            require(
                mass <= bound("max_mass")? && minimum_fee <= step_fee && step_fee <= bound(cap)?,
                "issuer measured resource policy",
            )?;
            resource_observations.push(json!({"operation":operation,"normalized_mass":mass,
                "fee_sompi":step_fee,"scope":"RETAINED_LOCAL_MASS_PROJECTION"}));
        }
        let consumed = json!([vec![true; inputs.len()], vec![true; inputs.len()]]);
        require(receipt["inputs_consumed"] == consumed, "input consumption")?;
        let rows = receipt["outputs"]
            .as_array()
            .ok_or("PROFILE_EXECUTION_ROWS_REQUIRED")?;
        require(
            rows.len() == outputs.len() && receipt["readback"] == json!([rows, rows]),
            "dual RPC observations",
        )?;
        for (index, (output, row)) in outputs.iter().zip(rows).enumerate() {
            require(
                row["amount"].as_u64().is_some()
                    && output["value"].as_u64().is_some()
                    && row["outpoint"] == format!("{txid}:{index}")
                    && row["amount"] == output["value"]
                    && row["script_public_key"] == output["scriptPublicKey"]
                    && row["covenant_id"] == output["covenant"]["covenantId"],
                "output commitment",
            )?;
        }
        observations.push(json!({"operation":operation,"txid":txid,"fee_sompi":step_fee}));
        bodies.insert(operation.to_string(), body);
        receipts.insert(operation.to_string(), receipt);
    }
    let required = [
        "root-genesis",
        "namespace-parent-genesis",
        "namespace-issuance",
        "content-genesis",
        "name-registration",
    ];
    require(
        required.iter().all(|key| bodies.contains_key(*key)),
        "incomplete issuer path",
    )?;
    let links = &binding["namespace_issuance"];
    require(
        super::object_fields_exact(links, &["anchor", "application"], &[]),
        "deployment binding fields",
    )?;
    let anchor = read(
        links["anchor"]
            .as_str()
            .ok_or("PROFILE_EXECUTION_ANCHOR_REQUIRED")?,
    )?;
    let bundle = read(
        links["application"]
            .as_str()
            .ok_or("PROFILE_EXECUTION_APPLICATION_REQUIRED")?,
    )?;
    let app = &bundle["evidence"];
    let root_body = &bodies["root-genesis"];
    let issuer = &bodies["namespace-issuance"];
    let parent = &bodies["namespace-parent-genesis"];
    let content = &bodies["content-genesis"];
    let root_cid = &anchor["covenant_id"];
    require(
        anchor["network"] == "testnet-10" && app["network"] == "testnet-10",
        "deployment network",
    )?;
    let outpoint =
        |op: &str, index: u32| format!("{}:{index}", receipts[op]["txid"].as_str().unwrap_or(""));
    require(
        anchor["genesis_outpoint"] == outpoint("root-genesis", 0)
            && root_body["covenant_id"] == *root_cid
            && issuer["root_covenant_id"] == *root_cid
            && root_body["source_sha256"] == anchor["source_sha256"]
            && issuer["source_sha256"] == anchor["source_sha256"],
        "root/source identity",
    )?;
    let parent_cid = &app["name_evidence"]["covenant_id"];
    require(
        parent["covenant_id"] == *parent_cid && issuer["parent_covenant_id"] == *parent_cid,
        "parent identity",
    )?;
    require(
        issuer["transaction"]["inputs"][0]["previousOutpoint"]
            == json!({"transactionId":receipts["namespace-parent-genesis"]["txid"],"index":0})
            && issuer["transaction"]["inputs"][1]["previousOutpoint"]
                == json!({"transactionId":receipts["root-genesis"]["txid"],"index":0}),
        "issuer predecessor binding",
    )?;
    let cert = &app["namespace_certificate"];
    let cert_row = &receipts["namespace-issuance"]["outputs"][2];
    require(
        cert["outpoint"] == outpoint("namespace-issuance", 2)
            && cert_row["amount"] == 100000000
            && cert_row["covenant_id"] == *root_cid
            && cert_row["script_public_key"] == cert["script_public_key"]
            && cert["state_args"][0] == 1
            && cert["state_args"][5] == *parent_cid
            && cert["state_args"][4] == issuer["namespace_hash"],
        "certificate binding",
    )?;
    require(
        issuer["certificate_policy"] == "PERMANENT_NO_NAMESPACE_REALLOCATION"
            && anchor["namespace_reallocation"] == false,
        "terminal policy",
    )?;
    require(
        app["name_evidence"]["deed_outpoint"] == outpoint("name-registration", 2)
            && app["content"]["outpoint"] == outpoint("content-genesis", 0)
            && app["target"]["deployment_id"]
                == format!("tn10:{}", content["covenant_id"].as_str().unwrap_or(""))
            && app["target"]["artifact_root"] == content["artifact_root"],
        "application binding",
    )?;
    Ok(
        json!({"scope":binding["scope"],"network":binding["network"],"observations":observations,
        "fee_sompi":fee,"state_policies":policy,"formal_admission":false,
        "current_utxo_verified":false,"native_vm_reexecuted":false,
        "resource_observations":resource_observations,"worst_case_resource_admitted":false}),
    )
}
