//! Public unsigned-transaction building blocks. No wallet, signer or RPC client.
use kaspa_consensus_core::Hash;
use kaspa_consensus_core::constants::MAX_SOMPI;
use kaspa_consensus_core::mass::{BlockMassLimits, Mass, MassCalculator};
use kaspa_consensus_core::tx::{
    PopulatedTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionOutpoint,
    TransactionOutput, UtxoEntry,
};
use serde_json::{Value, json};
pub type Error = Box<dyn std::error::Error>;

pub const LOCAL_MASS_PER_TX_BYTE: u64 = 1;
pub const LOCAL_MASS_PER_SCRIPT_PUB_KEY_BYTE: u64 = 10;
pub const LOCAL_MASS_SHARED_LIMIT: u64 = 500_000;

pub fn script_bytes(spk: &ScriptPublicKey) -> Vec<u8> {
    let mut bytes = spk.version().to_le_bytes().to_vec();
    bytes.extend_from_slice(spk.script());
    bytes
}
pub fn decode_spk(value: &Value) -> Result<ScriptPublicKey, Error> {
    let text = value.as_str().ok_or("serialized script string required")?;
    let bytes = hex::decode(text)?;
    if bytes.len() < 3 || bytes.len() > 10_002 || hex::encode(&bytes) != text {
        return Err("invalid serialized script".into());
    }
    if bytes[0] != 0 || bytes[1] != 0 {
        return Err("unsupported script version".into());
    }
    Ok(ScriptPublicKey::from_vec(0, bytes[2..].to_vec()))
}
pub fn parse_utxo(
    v: &Value,
    cov_required: bool,
) -> Result<(TransactionOutpoint, UtxoEntry), Error> {
    let obj = v.as_object().ok_or("UTXO object required")?;
    let fields = [
        "outpoint",
        "amount",
        "script_public_key",
        "block_daa_score",
        "covenant_id",
    ];
    if obj.len() != fields.len() || fields.iter().any(|k| !obj.contains_key(*k)) {
        return Err("unexpected UTXO fields".into());
    }
    let raw = v["outpoint"].as_str().ok_or("outpoint string required")?;
    let (txid, index) = raw.split_once(':').ok_or("outpoint separator required")?;
    let id: [u8; 32] = hex::decode(txid)?
        .try_into()
        .map_err(|_| "invalid transaction id")?;
    let index: u32 = index.parse()?;
    if id == [0; 32] || format!("{}:{}", hex::encode(id), index) != raw {
        return Err("noncanonical outpoint".into());
    }
    let amount = v["amount"]
        .as_u64()
        .filter(|n| *n > 0 && *n <= MAX_SOMPI)
        .ok_or("invalid UTXO amount")?;
    let daa = v["block_daa_score"]
        .as_u64()
        .ok_or("DAA score integer required")?;
    let covenant = if cov_required {
        let text = v["covenant_id"]
            .as_str()
            .ok_or("binding covenant required")?;
        let id: [u8; 32] = hex::decode(text)?
            .try_into()
            .map_err(|_| "invalid covenant id")?;
        if id == [0; 32] || hex::encode(id) != text {
            return Err("noncanonical covenant id".into());
        }
        Some(Hash::from_bytes(id))
    } else {
        if !v["covenant_id"].is_null() {
            return Err("fee UTXO must be ordinary".into());
        }
        None
    };
    // These planning inputs are ordinary non-coinbase spends. Live validation and
    // coinbase maturity, if applicable, remain mandatory external signer checks.
    Ok((
        TransactionOutpoint::new(TransactionId::from_bytes(id), index),
        UtxoEntry::new(
            amount,
            decode_spk(&v["script_public_key"])?,
            daa,
            false,
            covenant,
        ),
    ))
}

pub fn positive_output_sum(outputs: &[TransactionOutput]) -> Result<u64, Error> {
    let mut total = 0u64;
    for o in outputs {
        if o.value == 0 || o.value > MAX_SOMPI {
            return Err("output value outside consensus range".into());
        }
        total = total
            .checked_add(o.value)
            .filter(|n| *n <= MAX_SOMPI)
            .ok_or("total output value outside consensus range")?;
    }
    Ok(total)
}

/// Return a reproducible local mass projection for an unsigned transaction.
///
/// This intentionally does not verify signatures or claim a live network fee.
/// Callers must provide the exact input entries used to build `tx`; the helper
/// uses the transaction's native version and compute-commit semantics.
pub fn local_mass_projection(tx: &Transaction, entries: Vec<UtxoEntry>) -> Result<Value, Error> {
    if tx.inputs.len() != entries.len() {
        return Err("mass projection input/UTXO entry count mismatch".into());
    }
    let populated = PopulatedTransaction::new(tx, entries);
    let calculator = MassCalculator::new(
        LOCAL_MASS_PER_TX_BYTE,
        LOCAL_MASS_PER_SCRIPT_PUB_KEY_BYTE,
        kaspa_consensus_core::constants::STORAGE_MASS_PARAMETER,
    );
    let non_contextual = calculator.calc_non_contextual_masses(tx);
    let contextual = calculator
        .calc_contextual_masses(&populated)
        .ok_or("local contextual mass calculation unavailable for this unsigned body")?;
    let normalized = Mass::new(non_contextual, contextual)
        .normalized_max(&BlockMassLimits::with_shared_limit(LOCAL_MASS_SHARED_LIMIT).cofactors());
    Ok(json!({
     "status": "LOCAL_NATIVE_MASS_PROJECTION",
     "normalized_mass": normalized,
     "compute_mass": non_contextual.compute_mass,
     "transient_mass": non_contextual.transient_mass,
     "storage_mass": contextual.storage_mass,
     "witness_verification": "NOT_PERFORMED",
     "signature_scripts_unverified": true,
     "policy": {
      "mass_per_transaction_byte": LOCAL_MASS_PER_TX_BYTE,
      "mass_per_script_public_key_byte": LOCAL_MASS_PER_SCRIPT_PUB_KEY_BYTE,
      "storage_mass_parameter": kaspa_consensus_core::constants::STORAGE_MASS_PARAMETER,
      "shared_limit": LOCAL_MASS_SHARED_LIMIT,
      "shared_limit_is_network_admission": false
     },
     "live_network_fee_verified": false
    }))
}

/// Construct an unsigned genesis using the pinned consensus implementation,
/// never an externally supplied Covenant ID. Funding is not authenticated here.
pub fn genesis_plan(
    v: &Value,
    state_spk: ScriptPublicKey,
    state_value: u64,
) -> Result<Value, Error> {
    if v["state_sompi"].as_u64() != Some(state_value) || state_value == 0 {
        return Err("genesis state amount mismatch".into());
    }
    genesis_group_plan(v, state_spk, &[state_value])
}

/// Construct one or more genesis state outputs in a single Covenant group.
///
/// This is the minimal safe bootstrap for applications whose first transition
/// needs multiple lineage-bearing state objects (for example a parent cursor
/// plus its initial Gap). The consensus library derives one Covenant ID for the
/// whole output group; callers cannot supply or forge it. The ordinary change
/// output is deliberately outside the group.
pub fn genesis_group_plan(
    v: &Value,
    state_spk: ScriptPublicKey,
    state_values: &[u64],
) -> Result<Value, Error> {
    let scripts: Vec<ScriptPublicKey> =
        (0..state_values.len()).map(|_| state_spk.clone()).collect();
    genesis_group_plan_with_scripts(v, &scripts, state_values)
}

/// Variant used when the initial state objects have different state-machine
/// scripts but must still share one genesis Covenant group.
pub fn genesis_group_plan_with_scripts(
    v: &Value,
    state_spks: &[ScriptPublicKey],
    state_values: &[u64],
) -> Result<Value, Error> {
    use kaspa_consensus_core::hashing::sighash::{
        SigHashReusedValuesUnsync, calc_schnorr_signature_hash,
    };
    use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
    use kaspa_consensus_core::tx::{
        GenesisCovenantGroup, MutableTransaction, Transaction, TransactionInput,
    };
    use sha2::{Digest, Sha256};
    let obj = v.as_object().ok_or("genesis request object required")?;
    let fields = [
        "current",
        "funding_utxo",
        "funding_change_script_public_key",
        "fee_sompi",
        "state_sompi",
        "compute_budget",
    ];
    if obj.len() != fields.len() || fields.iter().any(|k| !obj.contains_key(*k)) {
        return Err("unexpected genesis request fields".into());
    }
    if state_values.is_empty()
        || state_values.len() != state_spks.len()
        || state_values.contains(&0)
    {
        return Err("genesis state values/scripts must be non-empty and aligned".into());
    }
    let (outpoint, entry) = parse_utxo(&v["funding_utxo"], false)?;
    let change_spk = decode_spk(&v["funding_change_script_public_key"])?;
    if hex::encode(Sha256::digest(script_bytes(&change_spk)))
        != v["current"]["fee_input_script_hash"]
    {
        return Err("genesis change must support future fee input policy".into());
    }
    let fee = v["fee_sompi"]
        .as_u64()
        .filter(|n| *n > 0)
        .ok_or("positive genesis fee required")?;
    let budget = v["compute_budget"]
        .as_u64()
        .filter(|n| *n > 0 && *n <= u16::MAX as u64)
        .ok_or("bounded compute budget required")?;
    let state_total = state_values
        .iter()
        .try_fold(0u64, |total, value| total.checked_add(*value))
        .ok_or("genesis state value overflow")?;
    let change = entry
        .amount
        .checked_sub(state_total)
        .and_then(|n| n.checked_sub(fee))
        .filter(|n| *n > 0)
        .ok_or("insufficient genesis funding or no change")?;
    let mut outputs: Vec<TransactionOutput> = state_values
        .iter()
        .zip(state_spks.iter())
        .map(|(value, script)| TransactionOutput {
            value: *value,
            script_public_key: script.clone(),
            covenant: None,
        })
        .collect();
    outputs.push(TransactionOutput {
        value: change,
        script_public_key: change_spk,
        covenant: None,
    });
    positive_output_sum(&outputs)?;
    let mut tx = Transaction::new(
        1,
        vec![TransactionInput::new_with_compute_budget(
            outpoint,
            vec![],
            0,
            budget as u16,
        )],
        outputs,
        0,
        Default::default(),
        0,
        vec![],
    );
    let state_indices: Vec<u32> = (0..state_values.len() as u32).collect();
    tx.populate_genesis_covenants(&[GenesisCovenantGroup::new(0, state_indices.clone())])?;
    tx.finalize();
    let cid = tx.outputs[0]
        .covenant
        .as_ref()
        .ok_or("missing derived covenant")?
        .covenant_id;
    if state_indices.iter().any(|index| {
        tx.outputs[*index as usize]
            .covenant
            .map(|binding| binding.covenant_id)
            != Some(cid)
    }) {
        return Err("genesis covenant group binding mismatch".into());
    }
    let genesis_outpoints: Vec<String> = state_indices
        .iter()
        .map(|index| format!("{}:{index}", tx.id()))
        .collect();
    let mutable = MutableTransaction::with_entries(tx, vec![entry.clone()]);
    let mass_projection = local_mass_projection(&mutable.tx, vec![entry])?;
    let digest = calc_schnorr_signature_hash(
        &mutable.as_verifiable(),
        0,
        SIG_HASH_ALL,
        &SigHashReusedValuesUnsync::new(),
    );
    let rpc: kaspa_rpc_core::RpcTransaction = (&mutable.tx).into();
    Ok(
        serde_json::json!({"schema":"KTAPEOUT-UNSIGNED-GENESIS-V1","network":"testnet-10","transaction":rpc,
  "current_compile_inputs":v["current"],"funding_utxo":v["funding_utxo"],"fee_sompi":fee,
  "input_sighash_all":[hex::encode(digest.as_bytes())],"predicted_genesis_outpoint":genesis_outpoints[0],"predicted_genesis_outpoints":genesis_outpoints,"state_output_indices":state_indices,"covenant_id":cid.to_string(),"mass_projection":mass_projection,
  "status":"UNSIGNED_LOCAL_PLAN","signing_allowed":false,"broadcast":false,
  "missing_evidence":["live_funding_readback","funding_signature","native_vm_signed_transaction","network_fee_mass_validation","genesis_readback"]}),
    )
}
