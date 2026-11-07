//! Pinned Kaspa transaction parsing and input-script verification for a
//! trusted host. This module is intentionally not an authorization decision:
//! it does not bind a KTAPEOUT plan/Profile, prove UTXO freshness, establish
//! consensus admission, sign, or broadcast.

use kaspa_consensus_client::Transaction;
use kaspa_consensus_core::{
    constants::TX_VERSION_TOCCATA,
    hashing::{sighash::SigHashReusedValuesUnsync, sighash_type::SigHashType},
    mass::{ComputeBudget, Gram},
    tx::{
        PopulatedTransaction, ScriptPublicKey, TransactionId, TransactionOutpoint,
        TransactionOutput,
    },
};
use kaspa_txscript::{
    caches::Cache, covenants::CovenantsContext, hex, parse_script, script_class::ScriptClass,
    EngineCtx, EngineFlags, TxScriptEngine,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;

pub mod toccata_witness;

pub const KASPA_SOURCE_COMMIT: &str = "01b532e8b553523216471682649693af92f0fd16";
pub const MAX_RAW_JSON_BYTES: usize = 512 * 1024;
const MAX_INPUTS: usize = 64;
const MAX_OUTPUTS: usize = 64;
const MAX_EXTERNAL_UTXO_SCRIPT_BYTES: usize = 300 * 1024;
const MAX_EXTERNAL_UTXO_ADDRESS_BYTES: usize = 128;
const MAX_EXTERNAL_UTXO_COVENANT_ID_BYTES: usize = 256;
const SUPPORTED_TRANSACTION_VERSION: u64 = 0;
const SUPPORTED_SCRIPT_VERSION: u16 = 0;

/// One output in the complete, globally indexed genesis group.
///
/// This is deliberately typed and independent of the CLI JSON shape so the
/// consensus preimage is constructed in one place and cannot be reimplemented
/// by each caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenesisOutputV1 {
    pub index: u32,
    pub value_sompi: u64,
    pub script_public_key_version: u16,
    pub script_public_key: Vec<u8>,
}

/// Compute the Kaspa covenant ID committed by a genesis input and its complete
/// output group. This performs no RPC, signing, broadcasting, or liveness
/// check. The caller must compare the result with an independently obtained ID.
pub fn covenant_id_from_genesis_v1(
    authorizing_txid: [u8; 32],
    authorizing_input_index: u32,
    outputs: &[GenesisOutputV1],
) -> Result<String, VerifyError> {
    if outputs.is_empty() || outputs.len() > MAX_OUTPUTS {
        return Err(VerifyError("GENESIS_OUTPUT_GROUP_INVALID"));
    }
    if outputs
        .windows(2)
        .any(|pair| pair[0].index >= pair[1].index)
    {
        return Err(VerifyError("GENESIS_OUTPUT_INDEX_ORDER_INVALID"));
    }
    let outpoint = TransactionOutpoint::new(
        TransactionId::from_bytes(authorizing_txid),
        authorizing_input_index,
    );
    let materialized: Vec<(u32, TransactionOutput)> = outputs
        .iter()
        .map(|output| {
            if output.value_sompi == 0 || output.script_public_key.len() > 300_000 {
                return Err(VerifyError("GENESIS_OUTPUT_INVALID"));
            }
            if output.script_public_key_version != SUPPORTED_SCRIPT_VERSION {
                return Err(VerifyError("GENESIS_SCRIPT_VERSION_UNSUPPORTED"));
            }
            Ok((
                output.index,
                TransactionOutput {
                    value: output.value_sompi,
                    script_public_key: ScriptPublicKey::from_vec(
                        output.script_public_key_version,
                        output.script_public_key.clone(),
                    ),
                    covenant: None,
                },
            ))
        })
        .collect::<Result<_, _>>()?;
    let id = kaspa_consensus_core::hashing::covenant_id::covenant_id(
        outpoint,
        materialized.iter().map(|(index, output)| (*index, output)),
    );
    Ok(id.to_string())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyError(pub &'static str);

impl fmt::Display for VerifyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for VerifyError {}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct InputScriptVerificationV1 {
    pub schema: &'static str,
    pub transaction_id: String,
    pub transaction_version: u16,
    pub input_count: usize,
    pub output_count: usize,
    pub verified_input_indices: Vec<usize>,
    pub kaspa_source_commit: &'static str,
    pub canonical_safe_json: bool,
    pub input_scripts_verified: bool,
    pub external_utxo_context_matched: bool,
    pub external_utxo_context_source_authenticated: bool,
    pub plan_bound: bool,
    pub profile_bound: bool,
    pub utxo_freshness_checked: bool,
    pub consensus_admission_checked: bool,
    pub signing_allowed: bool,
    pub broadcast_allowed: bool,
}

/// Per-input execution evidence from the pinned post-Toccata VM. This is a
/// local script-execution result, not transaction admission or finality proof.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ToccataInputExecutionV1 {
    pub input_index: usize,
    pub script_units_used: u64,
    pub allowed_script_units: u64,
    pub compute_budget: u16,
    pub committed_compute_mass_grams: u64,
}

/// Execute every input of a populated Toccata transaction with the pinned
/// v2.1.0 VM, an explicit sigop pricing value, covenant context, and each
/// input's committed compute-budget limit. This does not establish UTXO
/// freshness, block admission, or finality.
pub fn verify_post_toccata_populated_transaction(
    populated: &PopulatedTransaction<'_>,
) -> Result<Vec<ToccataInputExecutionV1>, VerifyError> {
    if populated.tx.version != TX_VERSION_TOCCATA {
        return Err(VerifyError("TOCCATA_TRANSACTION_VERSION_REQUIRED"));
    }
    if populated.tx.inputs.is_empty() || populated.tx.inputs.len() != populated.entries.len() {
        return Err(VerifyError("TOCCATA_POPULATED_INPUT_COUNT_INVALID"));
    }
    if populated
        .tx
        .inputs
        .iter()
        .any(|input| input.compute_commit.compute_budget().is_none())
    {
        return Err(VerifyError("TOCCATA_COMPUTE_BUDGET_REQUIRED"));
    }

    let covenant_context = CovenantsContext::from_tx(populated)
        .map_err(|_| VerifyError("TOCCATA_COVENANT_CONTEXT_INVALID"))?;
    let cache = Cache::new(10_000);
    let reused = SigHashReusedValuesUnsync::new();
    let mut metrics = Vec::with_capacity(populated.tx.inputs.len());
    for (input_index, (input, utxo)) in populated
        .tx
        .inputs
        .iter()
        .zip(&populated.entries)
        .enumerate()
    {
        if utxo.script_public_key.version != SUPPORTED_SCRIPT_VERSION {
            return Err(VerifyError("TOCCATA_SCRIPT_VERSION_UNSUPPORTED"));
        }
        let budget = input
            .compute_commit
            .compute_budget()
            .expect("budget checked above");
        let allowed = input.compute_commit.allowed_script_units();
        // TN10's pinned v2.1.0 consensus parameters set mass_per_sig_op to
        // 1000 grams (consensus/core/src/config/params.rs). Specify this
        // explicitly: EngineFlags::default() is not a consensus preset.
        let flags = EngineFlags {
            sigop_script_units: Gram(1000).into(),
        };
        let mut engine = TxScriptEngine::from_transaction_input_with_script_units_limit(
            populated,
            input,
            input_index,
            utxo,
            EngineCtx::new(&cache)
                .with_reused(&reused)
                .with_covenants_ctx(&covenant_context),
            flags,
            allowed,
        );
        engine
            .execute()
            .map_err(|_| VerifyError("TOCCATA_INPUT_SCRIPT_INVALID"))?;
        metrics.push(ToccataInputExecutionV1 {
            input_index,
            script_units_used: engine.used_script_units().0,
            allowed_script_units: allowed.0,
            compute_budget: budget,
            committed_compute_mass_grams: ComputeBudget(budget).to_grams().0,
        });
    }
    Ok(metrics)
}

/// Structural comparison result only. A caller-supplied unsigned transaction
/// is not proof that it came from an authenticated or locked KTAPEOUT plan.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SignedTransactionPlanDiffV1 {
    pub schema: &'static str,
    pub transaction_id: String,
    pub authorized_signer_input_indices: Vec<usize>,
    pub authorized_signer_sighash_types: Vec<u8>,
    pub transaction_structure_matched: bool,
    pub authorized_signature_fields_changed: bool,
    pub authorized_signature_policy_matched: bool,
    pub authorized_signature_policy_authenticated: bool,
    pub input_scripts_verified: bool,
    pub plan_source_authenticated: bool,
    pub plan_bound: bool,
    pub profile_bound: bool,
    pub utxo_freshness_checked: bool,
    pub signing_allowed: bool,
    pub broadcast_allowed: bool,
}

/// Caller-declared signing policy for one input. The policy must be obtained
/// from an authenticated locked SignPlan before it can authorize signing.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedSignerInputV1 {
    pub input_index: usize,
    pub expected_sighash_type: u8,
}

/// Independently sourced UTXO facts to compare with one Safe-JSON input.
/// This type records facts only; it does not authenticate the source or prove
/// that the outpoint is currently unspent.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExternalUtxoContextV1 {
    pub transaction_id: String,
    pub output_index: u32,
    pub address: Option<String>,
    pub amount_sompi: u64,
    pub script_public_key: String,
    pub block_daa_score: u64,
    pub is_coinbase: bool,
    pub covenant_id: Option<String>,
}

/// Strictly parse one canonical Kaspa v0 Safe-JSON transaction, finalize and
/// compare its txid, then execute every populated input script using the
/// pinned Kaspa engine. The Core raw-input guard runs before either JSON
/// deserialization. This is deliberately narrower than full KTAPEOUT W2b.
pub fn verify_canonical_v0_input_scripts(
    raw_json: &[u8],
) -> Result<InputScriptVerificationV1, VerifyError> {
    verify_canonical_v0_input_scripts_inner(raw_json, None)
}

/// Verify Safe-JSON input scripts only after every embedded UTXO record and
/// outpoint exactly matches an independently supplied context in transaction
/// input order. The caller remains responsible for obtaining that context
/// from an authenticated source and revalidating that each outpoint is fresh.
pub fn verify_canonical_v0_input_scripts_with_external_utxos(
    raw_json: &[u8],
    external_utxos: &[ExternalUtxoContextV1],
) -> Result<InputScriptVerificationV1, VerifyError> {
    verify_canonical_v0_input_scripts_inner(raw_json, Some(external_utxos))
}

/// Compare a signed v0 transaction with its caller-supplied unsigned form.
/// Only `signatureScript` fields at the sorted, unique authorized indices may
/// change. The signed transaction must independently pass the pinned Kaspa
/// input-script engine against the supplied UTXO context. This does not
/// authenticate the plan, its source, or UTXO freshness and is not signing
/// authorization.
pub fn verify_signed_v0_matches_unsigned_transaction(
    unsigned_json: &[u8],
    signed_json: &[u8],
    authorized_signer_inputs: &[AuthorizedSignerInputV1],
    external_utxos: &[ExternalUtxoContextV1],
) -> Result<SignedTransactionPlanDiffV1, VerifyError> {
    let (unsigned_value, _) = canonical_v0_value(unsigned_json)?;
    let (mut signed_value, transaction_id) = canonical_v0_value(signed_json)?;
    let unsigned_inputs = unsigned_value
        .get("inputs")
        .and_then(Value::as_array)
        .ok_or(VerifyError("TRANSACTION_INPUTS_REQUIRED"))?;
    let signed_inputs = signed_value
        .as_object_mut()
        .and_then(|root| root.get_mut("inputs"))
        .and_then(Value::as_array_mut)
        .ok_or(VerifyError("TRANSACTION_INPUTS_REQUIRED"))?;
    if unsigned_inputs.is_empty()
        || unsigned_inputs.len() > MAX_INPUTS
        || unsigned_inputs.len() != signed_inputs.len()
        || authorized_signer_inputs.is_empty()
        || authorized_signer_inputs.len() > unsigned_inputs.len()
        || authorized_signer_inputs
            .windows(2)
            .any(|pair| pair[0].input_index >= pair[1].input_index)
        || authorized_signer_inputs
            .iter()
            .any(|policy| policy.input_index >= unsigned_inputs.len())
    {
        return Err(VerifyError("AUTHORIZED_INPUT_SET_INVALID"));
    }

    for policy in authorized_signer_inputs {
        if SigHashType::from_u8(policy.expected_sighash_type).is_err() {
            return Err(VerifyError("AUTHORIZED_SIGHASH_TYPE_INVALID"));
        }
        let utxo = external_utxos
            .get(policy.input_index)
            .ok_or(VerifyError("EXTERNAL_UTXO_CONTEXT_COUNT_MISMATCH"))?;
        if !is_lower_even_hex(&utxo.script_public_key, MAX_EXTERNAL_UTXO_SCRIPT_BYTES) {
            return Err(VerifyError("EXTERNAL_UTXO_CONTEXT_INVALID"));
        }
        let utxo_script = hex::decode(&utxo.script_public_key)
            .map_err(|_| VerifyError("EXTERNAL_UTXO_CONTEXT_INVALID"))?;
        if utxo_script.len() < 3 || utxo_script[..2] != [0, 0] {
            return Err(VerifyError("AUTHORIZED_INPUT_SCRIPT_TEMPLATE_UNSUPPORTED"));
        }
        let script_body = &utxo_script[2..];
        if !ScriptClass::is_pay_to_pubkey(script_body)
            && !ScriptClass::is_pay_to_pubkey_ecdsa(script_body)
        {
            return Err(VerifyError("AUTHORIZED_INPUT_SCRIPT_TEMPLATE_UNSUPPORTED"));
        }
        let signed_script_hex = signed_inputs[policy.input_index]
            .get("signatureScript")
            .and_then(Value::as_str)
            .ok_or(VerifyError("TRANSACTION_SIGNATURE_SCRIPT_INVALID"))?;
        let signed_script = hex::decode(signed_script_hex)
            .map_err(|_| VerifyError("TRANSACTION_SIGNATURE_SCRIPT_INVALID"))?;
        let parsed_script =
            parse_script::<PopulatedTransaction, SigHashReusedValuesUnsync>(&signed_script)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| VerifyError("TRANSACTION_SIGNATURE_SCRIPT_INVALID"))?;
        if parsed_script.len() != 1 || !parsed_script[0].is_push_opcode() {
            return Err(VerifyError("AUTHORIZED_INPUT_SCRIPT_TEMPLATE_UNSUPPORTED"));
        }
        let pushed_signature = parsed_script[0].get_data();
        if pushed_signature.len() < 2 {
            return Err(VerifyError("TRANSACTION_SIGNATURE_SCRIPT_INVALID"));
        }
        let actual_sighash_type = pushed_signature
            .last()
            .copied()
            .ok_or(VerifyError("TRANSACTION_SIGNATURE_SCRIPT_INVALID"))?;
        if SigHashType::from_u8(actual_sighash_type).is_err() {
            return Err(VerifyError("AUTHORIZED_SIGHASH_TYPE_INVALID"));
        }
        if actual_sighash_type != policy.expected_sighash_type {
            return Err(VerifyError("AUTHORIZED_SIGHASH_MISMATCH"));
        }
    }

    let mut changed_authorized_scripts = 0usize;
    for (index, (unsigned_input, signed_input)) in unsigned_inputs
        .iter()
        .zip(signed_inputs.iter_mut())
        .enumerate()
    {
        let unsigned_script = unsigned_input
            .get("signatureScript")
            .and_then(Value::as_str)
            .ok_or(VerifyError("TRANSACTION_SIGNATURE_SCRIPT_INVALID"))?;
        let signed_script = signed_input
            .get("signatureScript")
            .and_then(Value::as_str)
            .ok_or(VerifyError("TRANSACTION_SIGNATURE_SCRIPT_INVALID"))?;
        if authorized_signer_inputs
            .binary_search_by_key(&index, |policy| policy.input_index)
            .is_ok()
        {
            if signed_script == unsigned_script {
                return Err(VerifyError("AUTHORIZED_SIGNATURE_MISSING"));
            }
            changed_authorized_scripts += 1;
            signed_input["signatureScript"] = Value::String(unsigned_script.to_owned());
        }
    }

    // Transaction IDs necessarily differ when signature scripts are inserted.
    // All other Safe-JSON fields, including input order, UTXO records, outputs,
    // fees (derivable from inputs/outputs), payload and sequence must be equal.
    let mut unsigned_shape = unsigned_value;
    unsigned_shape
        .as_object_mut()
        .ok_or(VerifyError("SAFE_JSON_ROOT_OBJECT_REQUIRED"))?
        .remove("id");
    signed_value
        .as_object_mut()
        .ok_or(VerifyError("SAFE_JSON_ROOT_OBJECT_REQUIRED"))?
        .remove("id");
    if unsigned_shape != signed_value {
        return Err(VerifyError("SIGNED_TRANSACTION_PLAN_MISMATCH"));
    }

    let signed_verification =
        verify_canonical_v0_input_scripts_with_external_utxos(signed_json, external_utxos)?;
    Ok(SignedTransactionPlanDiffV1 {
        schema: "KTAPEOUT-KASPA-SIGNED-TRANSACTION-DIFF-V1",
        transaction_id,
        authorized_signer_input_indices: authorized_signer_inputs
            .iter()
            .map(|policy| policy.input_index)
            .collect(),
        authorized_signer_sighash_types: authorized_signer_inputs
            .iter()
            .map(|policy| policy.expected_sighash_type)
            .collect(),
        transaction_structure_matched: true,
        authorized_signature_fields_changed: changed_authorized_scripts
            == authorized_signer_inputs.len(),
        authorized_signature_policy_matched: true,
        authorized_signature_policy_authenticated: false,
        input_scripts_verified: signed_verification.input_scripts_verified,
        plan_source_authenticated: false,
        plan_bound: false,
        profile_bound: false,
        utxo_freshness_checked: false,
        signing_allowed: false,
        broadcast_allowed: false,
    })
}

fn canonical_v0_value(raw_json: &[u8]) -> Result<(Value, String), VerifyError> {
    ktapeout_core::guard_external_signing_json_050(raw_json)
        .map_err(|_| VerifyError("SAFE_JSON_INPUT_GUARD_REJECTED"))?;
    let input_value: Value =
        serde_json::from_slice(raw_json).map_err(|_| VerifyError("SAFE_JSON_INVALID"))?;
    let root = input_value
        .as_object()
        .ok_or(VerifyError("SAFE_JSON_ROOT_OBJECT_REQUIRED"))?;
    if root.get("version").and_then(Value::as_u64) != Some(SUPPORTED_TRANSACTION_VERSION) {
        return Err(VerifyError("TRANSACTION_VERSION_UNSUPPORTED"));
    }
    let safe_json =
        std::str::from_utf8(raw_json).map_err(|_| VerifyError("SAFE_JSON_UTF8_INVALID"))?;
    let transaction = Transaction::deserialize_from_safe_json(safe_json)
        .map_err(|_| VerifyError("KASPA_SAFE_JSON_REJECTED"))?;
    let parsed_canonical: Value = serde_json::from_str(
        &transaction
            .serialize_to_json_safe()
            .map_err(|_| VerifyError("KASPA_SAFE_JSON_SERIALIZE_FAILED"))?,
    )
    .map_err(|_| VerifyError("KASPA_SAFE_JSON_INTERNAL"))?;
    if input_value != parsed_canonical {
        return Err(VerifyError("SAFE_JSON_NOT_EXACT_CANONICAL_SHAPE"));
    }
    let inputs = input_value
        .get("inputs")
        .and_then(Value::as_array)
        .ok_or(VerifyError("TRANSACTION_INPUTS_REQUIRED"))?;
    let outputs = input_value
        .get("outputs")
        .and_then(Value::as_array)
        .ok_or(VerifyError("TRANSACTION_OUTPUTS_REQUIRED"))?;
    if inputs.is_empty() || inputs.len() > MAX_INPUTS {
        return Err(VerifyError("TRANSACTION_INPUT_BOUNDS_INVALID"));
    }
    if outputs.is_empty() || outputs.len() > MAX_OUTPUTS {
        return Err(VerifyError("TRANSACTION_OUTPUT_BOUNDS_INVALID"));
    }
    let supplied_txid = transaction.id().to_string();
    let transaction_id = transaction
        .finalize()
        .map_err(|_| VerifyError("TRANSACTION_ID_FINALIZE_FAILED"))?
        .to_string();
    if supplied_txid != transaction_id {
        return Err(VerifyError("TRANSACTION_ID_MISMATCH"));
    }
    let finalized: Value = serde_json::from_str(
        &transaction
            .serialize_to_json_safe()
            .map_err(|_| VerifyError("KASPA_SAFE_JSON_SERIALIZE_FAILED"))?,
    )
    .map_err(|_| VerifyError("KASPA_SAFE_JSON_INTERNAL"))?;
    if input_value != finalized {
        return Err(VerifyError("SAFE_JSON_FINALIZATION_CHANGED_TRANSACTION"));
    }
    Ok((finalized, transaction_id))
}

fn verify_canonical_v0_input_scripts_inner(
    raw_json: &[u8],
    external_utxos: Option<&[ExternalUtxoContextV1]>,
) -> Result<InputScriptVerificationV1, VerifyError> {
    ktapeout_core::guard_external_signing_json_050(raw_json)
        .map_err(|_| VerifyError("SAFE_JSON_INPUT_GUARD_REJECTED"))?;

    let input_value: Value =
        serde_json::from_slice(raw_json).map_err(|_| VerifyError("SAFE_JSON_INVALID"))?;
    let root = input_value
        .as_object()
        .ok_or(VerifyError("SAFE_JSON_ROOT_OBJECT_REQUIRED"))?;
    if root.get("version").and_then(Value::as_u64) != Some(SUPPORTED_TRANSACTION_VERSION) {
        return Err(VerifyError("TRANSACTION_VERSION_UNSUPPORTED"));
    }

    let safe_json =
        std::str::from_utf8(raw_json).map_err(|_| VerifyError("SAFE_JSON_UTF8_INVALID"))?;
    let transaction = Transaction::deserialize_from_safe_json(safe_json)
        .map_err(|_| VerifyError("KASPA_SAFE_JSON_REJECTED"))?;

    // Safe-JSON serde intentionally ignores unknown fields and normalizes
    // values. Require the supplied object to equal the official serializer's
    // pre-finalize shape so unknown, missing, aliased, or lossy fields fail.
    let parsed_canonical: Value = serde_json::from_str(
        &transaction
            .serialize_to_json_safe()
            .map_err(|_| VerifyError("KASPA_SAFE_JSON_SERIALIZE_FAILED"))?,
    )
    .map_err(|_| VerifyError("KASPA_SAFE_JSON_INTERNAL"))?;
    if input_value != parsed_canonical {
        return Err(VerifyError("SAFE_JSON_NOT_EXACT_CANONICAL_SHAPE"));
    }

    if let Some(external_utxos) = external_utxos {
        let inputs = input_value
            .get("inputs")
            .and_then(Value::as_array)
            .ok_or(VerifyError("TRANSACTION_INPUTS_REQUIRED"))?;
        if external_utxos.len() != inputs.len() || external_utxos.len() > MAX_INPUTS {
            return Err(VerifyError("EXTERNAL_UTXO_CONTEXT_COUNT_MISMATCH"));
        }
        for (input, expected) in inputs.iter().zip(external_utxos) {
            if !is_lower_hex_32(&expected.transaction_id)
                || !is_lower_even_hex(&expected.script_public_key, MAX_EXTERNAL_UTXO_SCRIPT_BYTES)
                || expected
                    .address
                    .as_ref()
                    .is_some_and(|value| value.len() > MAX_EXTERNAL_UTXO_ADDRESS_BYTES)
                || expected
                    .covenant_id
                    .as_ref()
                    .is_some_and(|value| value.len() > MAX_EXTERNAL_UTXO_COVENANT_ID_BYTES)
            {
                return Err(VerifyError("EXTERNAL_UTXO_CONTEXT_INVALID"));
            }
            if input.get("transactionId").and_then(Value::as_str)
                != Some(expected.transaction_id.as_str())
                || input.get("index").and_then(Value::as_u64)
                    != Some(u64::from(expected.output_index))
            {
                return Err(VerifyError("EXTERNAL_UTXO_CONTEXT_MISMATCH"));
            }

            let expected_utxo = serde_json::json!({
                "address": expected.address,
                "amount": expected.amount_sompi.to_string(),
                "scriptPublicKey": expected.script_public_key,
                "blockDaaScore": expected.block_daa_score.to_string(),
                "isCoinbase": expected.is_coinbase,
                "covenantId": expected.covenant_id,
            });
            if input.get("utxo") != Some(&expected_utxo) {
                return Err(VerifyError("EXTERNAL_UTXO_CONTEXT_MISMATCH"));
            }
        }
    }

    let supplied_txid = transaction.id().to_string();
    let computed_txid = transaction
        .finalize()
        .map_err(|_| VerifyError("TRANSACTION_ID_FINALIZE_FAILED"))?
        .to_string();
    if supplied_txid != computed_txid {
        return Err(VerifyError("TRANSACTION_ID_MISMATCH"));
    }
    let finalized_canonical: Value = serde_json::from_str(
        &transaction
            .serialize_to_json_safe()
            .map_err(|_| VerifyError("KASPA_SAFE_JSON_SERIALIZE_FAILED"))?,
    )
    .map_err(|_| VerifyError("KASPA_SAFE_JSON_INTERNAL"))?;
    if input_value != finalized_canonical {
        return Err(VerifyError("SAFE_JSON_FINALIZATION_CHANGED_TRANSACTION"));
    }

    let version = transaction.inner().version;
    let (core_transaction, utxos) = transaction
        .tx_and_utxos()
        .map_err(|_| VerifyError("TRANSACTION_UTXO_CONTEXT_MISSING"))?;
    let input_count = core_transaction.inputs.len();
    let output_count = core_transaction.outputs.len();
    if input_count == 0 || input_count > MAX_INPUTS || input_count != utxos.len() {
        return Err(VerifyError("TRANSACTION_INPUT_BOUNDS_INVALID"));
    }
    if output_count == 0 || output_count > MAX_OUTPUTS {
        return Err(VerifyError("TRANSACTION_OUTPUT_BOUNDS_INVALID"));
    }
    if utxos
        .iter()
        .any(|utxo| utxo.script_public_key.version != SUPPORTED_SCRIPT_VERSION)
        || core_transaction
            .outputs
            .iter()
            .any(|output| output.script_public_key.version != SUPPORTED_SCRIPT_VERSION)
    {
        return Err(VerifyError("SCRIPT_VERSION_UNSUPPORTED"));
    }

    let populated = PopulatedTransaction::new(&core_transaction, utxos.clone());
    let cache = Cache::new(10_000);
    let reused = SigHashReusedValuesUnsync::new();
    let mut verified_input_indices = Vec::with_capacity(input_count);
    for (index, (input, utxo)) in core_transaction.inputs.iter().zip(&utxos).enumerate() {
        // The upstream constructor asserts the input index is valid; bounds
        // and vector parity are checked above before reaching that API.
        let mut engine = TxScriptEngine::from_transaction_input(
            &populated,
            input,
            index,
            utxo,
            EngineCtx::new(&cache).with_reused(&reused),
            EngineFlags::default(),
        );
        engine
            .execute()
            .map_err(|_| VerifyError("INPUT_SCRIPT_VERIFICATION_FAILED"))?;
        verified_input_indices.push(index);
    }

    Ok(InputScriptVerificationV1 {
        schema: "KTAPEOUT-KASPA-INPUT-SCRIPT-VERIFICATION-V1",
        transaction_id: computed_txid,
        transaction_version: version,
        input_count,
        output_count,
        verified_input_indices,
        kaspa_source_commit: KASPA_SOURCE_COMMIT,
        canonical_safe_json: true,
        input_scripts_verified: true,
        external_utxo_context_matched: external_utxos.is_some(),
        external_utxo_context_source_authenticated: false,
        plan_bound: false,
        profile_bound: false,
        utxo_freshness_checked: false,
        consensus_admission_checked: false,
        signing_allowed: false,
        broadcast_allowed: false,
    })
}

fn is_lower_hex_32(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_lower_even_hex(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len().is_multiple_of(2)
        && value.len() / 2 <= max_bytes
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
