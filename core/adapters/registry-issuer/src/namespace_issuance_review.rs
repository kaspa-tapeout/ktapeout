use serde_json::Value;

#[derive(Clone, Copy, Debug)]
pub struct IssuanceAccounting {
    pub parent_input_sompi: u64,
    pub parent_successor_sompi: u64,
    pub root_gap_input_sompi: u64,
    pub carrier_sompi: u64,
    pub state_output_count: u64,
    pub fee_sompi: u64,
}

pub fn attach_review(body: &mut Value, accounting: IssuanceAccounting) -> Result<(), &'static str> {
    if accounting.parent_input_sompi != accounting.parent_successor_sompi {
        return Err("NAMESPACE_PARENT_SUCCESSOR_VALUE_MISMATCH");
    }
    if accounting.state_output_count == 0 || accounting.carrier_sompi == 0 {
        return Err("NAMESPACE_STATE_OUTPUTS_INVALID");
    }
    let state_outputs = accounting
        .carrier_sompi
        .checked_mul(accounting.state_output_count)
        .ok_or("NAMESPACE_STATE_OUTPUTS_OVERFLOW")?;
    let newly_locked_sompi = state_outputs
        .checked_sub(accounting.root_gap_input_sompi)
        .ok_or("NAMESPACE_STATE_OUTPUTS_UNDERFUNDED")?;

    if !body.is_object() {
        *body = serde_json::json!({});
    }
    if let Some(object) = body.as_object_mut() {
        object.remove("namespace_bond_sompi");
        object.insert(
            "verification_status".into(),
            serde_json::json!(
                "UNVERIFIED_ON_CHAIN: The namespace issuance plan and its costs have not been verified on live TN10"
            ),
        );
        object.insert("signing_allowed".into(), serde_json::json!(false));
        object.insert("broadcast".into(), serde_json::json!(false));
        object.insert("native_signing".into(), Value::Null);
        object.insert(
            "economics".into(),
            serde_json::json!({
                "parent_input_sompi": accounting.parent_input_sompi,
                "parent_successor_sompi": accounting.parent_successor_sompi,
                "root_gap_input_sompi": accounting.root_gap_input_sompi,
                "carrier_sompi_each": accounting.carrier_sompi,
                "state_output_count": accounting.state_output_count,
                "newly_locked_sompi": newly_locked_sompi,
                "fee_estimate_sompi": accounting.fee_sompi,
                "fee_estimate_kas": accounting.fee_sompi as f64 / 100_000_000.0
            }),
        );
        object.insert(
            "permanent_warnings".into(),
            serde_json::json!([
                "There is no refund path. The locked amount is non-refundable.",
                "Losing the control key permanently forfeits control of the namespace.",
                "Version 1 does not support transferring or closing namespaces."
            ]),
        );
    }
    Ok(())
}
