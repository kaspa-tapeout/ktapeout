//! Merge signatures onto the original native v1 body. PSKT extraction is never
//! used, so compute budgets and all transaction fields stay byte-for-byte fixed.
use crate::native_transaction_codec::{self as codec, Error};

/// TN10/mainnet `mass_per_sig_op`: consensus charges this many grams per signature operation.
const CONSENSUS_MASS_PER_SIG_OP: u64 = 1000;
use kaspa_consensus_core::{
    hashing::{
        sighash::{SigHashReusedValuesUnsync, calc_schnorr_signature_hash},
        sighash_type::SIG_HASH_ALL,
    },
    tx::{MutableTransaction, PopulatedTransaction, Transaction, UtxoEntry, VerifiableTransaction},
};
use kaspa_txscript::{
    EngineCtx, EngineFlags, TxScriptEngine, caches::Cache, covenants::CovenantsContext,
};
use secp256k1::{Message, Secp256k1, XOnlyPublicKey, schnorr::Signature};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct InputAuthority {
    pub input_index: usize,
    pub signer_public_key: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignaturePacket {
    pub native_plan_hash: String,
    pub input_index: usize,
    pub signer_public_key: String,
    pub sighash_type: u8,
    pub signature: String,
}
pub struct NativeSigningPlan {
    transaction: Transaction,
    entries: Vec<UtxoEntry>,
    authorities: Vec<InputAuthority>,
    hash: String,
}
impl NativeSigningPlan {
    pub fn new(
        transaction: Transaction,
        entries: Vec<UtxoEntry>,
        authorities: Vec<InputAuthority>,
    ) -> Result<Self, Error> {
        Self::new_with_unsigned_inputs(transaction, entries, authorities, &[])
    }
    /// Inputs listed in `unsigned_inputs` are authorized by covenant script alone; the builder
    /// supplies their fixed witness. Every other input still needs a signer authority.
    pub fn new_with_unsigned_inputs(
        transaction: Transaction,
        entries: Vec<UtxoEntry>,
        authorities: Vec<InputAuthority>,
        unsigned_inputs: &[usize],
    ) -> Result<Self, Error> {
        Self::new_with_witness_templates(transaction, entries, authorities, unsigned_inputs, &[])
    }

    /// Build a signing plan for scripts whose sighash contract requires a
    /// fixed-size placeholder witness. The supplied transaction must contain
    /// those exact templates; finalization still replaces them and verifies
    /// every resulting input with the native VM.
    pub fn new_with_witness_templates(
        transaction: Transaction,
        entries: Vec<UtxoEntry>,
        mut authorities: Vec<InputAuthority>,
        unsigned_inputs: &[usize],
        witness_templates: &[Vec<u8>],
    ) -> Result<Self, Error> {
        if !witness_templates.is_empty()
            && (witness_templates.len() != transaction.inputs.len()
                || transaction
                    .inputs
                    .iter()
                    .zip(witness_templates)
                    .any(|(input, template)| input.signature_script != *template))
        {
            return Err("fixed witness template does not match transaction".into());
        }
        if transaction.version != 1
            || transaction.inputs.is_empty()
            || transaction.inputs.len() > 64
            || transaction.outputs.is_empty()
            || transaction.outputs.len() > 64
            || entries.len() != transaction.inputs.len()
            || transaction.inputs.iter().enumerate().any(|(index, i)| {
                let is_unsigned = unsigned_inputs.contains(&index);
                let template = witness_templates.get(index);
                (is_unsigned && !i.signature_script.is_empty())
                    || (!is_unsigned
                        && if witness_templates.is_empty() {
                            !i.signature_script.is_empty()
                        } else {
                            template.is_none_or(|template| template.is_empty())
                        })
                    || i.compute_commit.compute_budget().is_none_or(|b| b == 0)
            })
        {
            return Err("invalid unsigned native v1 transaction".into());
        }
        if authorities.is_empty() || authorities.len() > 256 {
            return Err("invalid authority count".into());
        }
        let mut inputs = HashSet::new();
        if transaction
            .inputs
            .iter()
            .any(|i| !inputs.insert(i.previous_outpoint))
        {
            return Err("duplicate input".into());
        }
        codec::positive_output_sum(&transaction.outputs)?;
        let sum = entries
            .iter()
            .try_fold(0u64, |a, e| a.checked_add(e.amount))
            .ok_or("input value overflow")?;
        let output_sum = codec::positive_output_sum(&transaction.outputs)?;
        if sum <= output_sum {
            return Err("positive fee required".into());
        }
        authorities.sort();
        if authorities.windows(2).any(|a| a[0] == a[1]) {
            return Err("duplicate authority".into());
        }
        for a in &authorities {
            if a.input_index >= transaction.inputs.len() {
                return Err("authority input out of range".into());
            }
            let bytes = hex::decode(&a.signer_public_key)?;
            if hex::encode(&bytes) != a.signer_public_key {
                return Err("noncanonical public key".into());
            }
            XOnlyPublicKey::from_slice(&bytes)?;
        }
        let n = transaction.inputs.len();
        if unsigned_inputs
            .iter()
            .any(|&i| i >= n || authorities.iter().any(|a| a.input_index == i))
        {
            return Err("invalid unsigned input".into());
        }
        if (0..n).any(|i| {
            !unsigned_inputs.contains(&i) && !authorities.iter().any(|a| a.input_index == i)
        }) {
            return Err("unauthorized input".into());
        }
        let encoded = serde_json::to_vec(
            &json!({"transaction":transaction,"entries":entries,"authorities":authorities}),
        )?;
        if encoded.len() > 512 * 1024 {
            return Err("native plan exceeds byte limit".into());
        }
        let mut preimage = b"KTAPEOUT/0.5.0/NATIVE_INPUT_SIGNING_PLAN/V1\0".to_vec();
        preimage.extend(encoded);
        Ok(Self {
            transaction,
            entries,
            authorities,
            hash: hex::encode(Sha256::digest(preimage)),
        })
    }
    pub fn hash(&self) -> &str {
        &self.hash
    }
    pub fn transaction(&self) -> &Transaction {
        &self.transaction
    }
    pub fn authorities(&self) -> &[InputAuthority] {
        &self.authorities
    }
    pub fn entries(&self) -> &[UtxoEntry] {
        &self.entries
    }
    pub fn digest(&self, index: usize) -> Result<[u8; 32], Error> {
        if index >= self.transaction.inputs.len() {
            return Err("input out of range".into());
        }
        let mutable =
            MutableTransaction::with_entries(self.transaction.clone(), self.entries.clone());
        Ok(calc_schnorr_signature_hash(
            &mutable.as_verifiable(),
            index,
            SIG_HASH_ALL,
            &SigHashReusedValuesUnsync::new(),
        )
        .as_bytes())
    }
    pub fn requests(&self) -> Result<Value, Error> {
        let mut requests = Vec::new();
        for a in &self.authorities {
            requests.push(json!({"network":"testnet-10","native_plan_hash":self.hash,
            "input_index":a.input_index,"signer_public_key":a.signer_public_key,"sighash_type":1,"sighash":hex::encode(self.digest(a.input_index)?)}));
        }
        let safe_transaction = self.safe_transaction()?;
        Ok(
            json!({"schema":"KTAPEOUT-NATIVE-SIGNING-REQUESTS-V1","native_plan_hash":self.hash,
            "transaction":kaspa_rpc_core::RpcTransaction::from(&self.transaction),
            "safe_transaction":safe_transaction,"requests":requests,"broadcast":false}),
        )
    }
    /// Safe-JSON signing view built from this exact transaction and its pinned UTXO entries.
    /// The host uses it only for wallet review; packet verification and final merge still use
    /// this NativeSigningPlan and its original sighashes.
    fn safe_transaction(&self) -> Result<Value, Error> {
        let rpc = serde_json::to_value(kaspa_rpc_core::RpcTransaction::from(&self.transaction))?;
        let rpc_inputs = rpc["inputs"]
            .as_array()
            .ok_or("RPC transaction inputs missing")?;
        let rpc_outputs = rpc["outputs"]
            .as_array()
            .ok_or("RPC transaction outputs missing")?;
        if rpc_inputs.len() != self.entries.len()
            || rpc_outputs.len() != self.transaction.outputs.len()
        {
            return Err("RPC transaction context count mismatch".into());
        }
        let inputs = rpc_inputs.iter().zip(&self.entries).map(|(input, entry)| {
            let previous = input.get("previousOutpoint").ok_or("RPC previous outpoint missing")?;
            let transaction_id = previous.get("transactionId").and_then(Value::as_str).ok_or("RPC transaction id missing")?;
            let outpoint_index = previous.get("index").and_then(Value::as_u64).ok_or("RPC outpoint index missing")?;
            let sequence = safe_integer_text(input.get("sequence").ok_or("RPC sequence missing")?)?;
            let compute_budget = input.get("computeBudget").and_then(Value::as_u64).ok_or("RPC compute budget missing")?;
            let sig_op_count = input.get("sigOpCount").and_then(Value::as_u64).ok_or("RPC signature operation count missing")?;
            let signature_script = input.get("signatureScript").and_then(Value::as_str).ok_or("RPC signature script missing")?;
            let covenant_id = entry.covenant_id.as_ref().map(ToString::to_string);
            Ok(json!({
                "transactionId":transaction_id,"index":outpoint_index,"sequence":sequence,
                "sigOpCount":sig_op_count,"computeBudget":compute_budget,"signatureScript":signature_script,
                "utxo":{"amount":entry.amount.to_string(),
                    "scriptPublicKey":hex::encode(codec::script_bytes(&entry.script_public_key)),
                    "blockDaaScore":entry.block_daa_score.to_string(),"isCoinbase":entry.is_coinbase,
                    "covenantId":covenant_id,
                    "outpoint":{"transactionId":transaction_id,"index":outpoint_index}}
            }))
        }).collect::<Result<Vec<_>, Error>>()?;
        let outputs = rpc_outputs
            .iter()
            .map(|output| {
                let value =
                    safe_integer_text(output.get("value").ok_or("RPC output value missing")?)?;
                let script = output
                    .get("scriptPublicKey")
                    .and_then(Value::as_str)
                    .ok_or("RPC output script missing")?;
                let covenant = output
                    .get("covenant")
                    .cloned()
                    .ok_or("RPC output covenant missing")?;
                Ok(json!({"covenant":covenant,"scriptPublicKey":script,"value":value}))
            })
            .collect::<Result<Vec<_>, Error>>()?;
        Ok(json!({
            "id":self.transaction.id().to_string(),
            "version":rpc.get("version").cloned().ok_or("RPC transaction version missing")?,
            "inputs":inputs,"outputs":outputs,
            "subnetworkId":rpc.get("subnetworkId").cloned().ok_or("RPC subnetwork id missing")?,
            "lockTime":safe_integer_text(rpc.get("lockTime").ok_or("RPC lock time missing")?)?,
            "gas":safe_integer_text(rpc.get("gas").ok_or("RPC gas missing")?)?,
            "storageMass":safe_integer_text(rpc.get("storageMass").ok_or("RPC storage mass missing")?)?,
            "payload":rpc.get("payload").cloned().ok_or("RPC payload missing")?
        }))
    }
    /// Project the exact transaction body using caller-built witness placeholders.
    /// Signature bytes are fixed-size, but this projection does not verify them.
    pub fn mass_projection_with_witnesses(&self, witnesses: &[Vec<u8>]) -> Result<Value, Error> {
        if witnesses.len() != self.transaction.inputs.len()
            || witnesses
                .iter()
                .any(|s| s.is_empty() || s.len() > 64 * 1024)
        {
            return Err("invalid resource-preview witness set".into());
        }
        let mut projected = self.transaction.clone();
        for (input, script) in projected.inputs.iter_mut().zip(witnesses) {
            input.signature_script = script.clone();
        }
        if serde_json::to_vec(&projected)?.len() > 512 * 1024 {
            return Err("projected transaction exceeds byte limit".into());
        }
        let mut mass = codec::local_mass_projection(&projected, self.entries.clone())?;
        mass["witness_verification"] = json!("NOT_PERFORMED");
        mass["signature_scripts_unverified"] = json!(true);
        mass["projection_basis"] = json!("EXACT_BODY_WITH_FIXED_LENGTH_SIGNATURE_PLACEHOLDERS");
        Ok(mass)
    }
    /// Verify each signature before duplicate handling; never let a duplicate
    /// overwrite another signer's authorization or alter the native body.
    pub fn merge(
        &self,
        packets: &[SignaturePacket],
    ) -> Result<BTreeMap<InputAuthority, Vec<u8>>, Error> {
        if packets.len() > 512 {
            return Err("signature packet limit exceeded".into());
        }
        let verifier = Secp256k1::verification_only();
        let mut signatures = BTreeMap::new();
        for p in packets {
            let authority = InputAuthority {
                input_index: p.input_index,
                signer_public_key: p.signer_public_key.clone(),
            };
            if p.native_plan_hash != self.hash
                || p.sighash_type != 1
                || self.authorities.binary_search(&authority).is_err()
            {
                return Err("signature packet not authorized for plan".into());
            }
            let bytes = hex::decode(&p.signature)?;
            if bytes.len() != 64 || hex::encode(&bytes) != p.signature {
                return Err("noncanonical Schnorr signature".into());
            }
            let key = XOnlyPublicKey::from_slice(&hex::decode(&p.signer_public_key)?)?;
            verifier.verify_schnorr(
                &Signature::from_slice(&bytes)?,
                &Message::from_digest(self.digest(p.input_index)?),
                &key,
            )?;
            if let Some(previous) = signatures.get(&authority)
                && previous != &bytes
            {
                return Err("conflicting signature packet".into());
            }
            signatures.insert(authority, bytes);
        }
        Ok(signatures)
    }
    pub fn finish<F>(&self, packets: &[SignaturePacket], witnesses: F) -> Result<Value, Error>
    where
        F: FnOnce(&BTreeMap<InputAuthority, Vec<u8>>) -> Result<Vec<Vec<u8>>, Error>,
    {
        let signatures = self.merge(packets)?;
        if signatures.len() != self.authorities.len() {
            return Err("signature set incomplete".into());
        }
        let scripts = witnesses(&signatures)?;
        if scripts.len() != self.transaction.inputs.len()
            || scripts.iter().any(|s| s.is_empty() || s.len() > 64 * 1024)
        {
            return Err("invalid witness set".into());
        }
        let mut signed = self.transaction.clone();
        for (input, script) in signed.inputs.iter_mut().zip(scripts) {
            input.signature_script = script;
        }
        if serde_json::to_vec(&signed)?.len() > 512 * 1024 {
            return Err("signed transaction exceeds byte limit".into());
        }
        verify_all_inputs(&signed, self.entries.clone())?;
        let script_units = verify_all_inputs_consensus(&signed, self.entries.clone())?;
        let mut mass = codec::local_mass_projection(&signed, self.entries.clone())?;
        mass["witness_verification"] = json!("NATIVE_VM_VERIFIED");
        mass["signature_scripts_unverified"] = json!(false);
        if mass["normalized_mass"].as_u64().ok_or("mass unavailable")?
            > codec::LOCAL_MASS_SHARED_LIMIT
        {
            return Err(format!(
                "RESOURCE_EXCEEDED: signed transaction mass {}",
                mass["normalized_mass"]
            )
            .into());
        }
        signed.finalize();
        Ok(
            json!({"native_plan_hash":self.hash,"transaction":kaspa_rpc_core::RpcTransaction::from(&signed),
            "txid":signed.id().to_string(),"native_vm_verified":true,"consensus_script_units_used":script_units,"mass_projection":mass,
            "network_admission":"UNPROVEN","broadcast":false}),
        )
    }
}

fn safe_integer_text(value: &Value) -> Result<String, Error> {
    if let Some(number) = value.as_u64() {
        return Ok(number.to_string());
    }
    if let Some(text) = value.as_str() {
        let number = text.parse::<u64>()?;
        if number.to_string() == text {
            return Ok(text.to_owned());
        }
    }
    Err("Safe-JSON integer is not canonical".into())
}
/// Execute every input exactly as consensus does after Toccata: covenant rules on,
/// signature operations charged at `mass_per_sig_op`, and each input limited to the
/// script units its declared compute budget allows. Returns the units each input
/// consumed, so planners can size compute budgets before anything is broadcast.
pub fn verify_all_inputs_consensus(
    transaction: &Transaction,
    entries: Vec<UtxoEntry>,
) -> Result<Vec<u64>, Error> {
    if entries.len() != transaction.inputs.len() {
        return Err("input context mismatch".into());
    }
    let populated = PopulatedTransaction::new(transaction, entries);
    let context = CovenantsContext::from_tx(&populated)?;
    let cache = Cache::new(100_000);
    let reused = SigHashReusedValuesUnsync::new();
    let flags = EngineFlags {
        sigop_script_units: kaspa_consensus_core::mass::Gram(CONSENSUS_MASS_PER_SIG_OP).into(),
    };
    let mut used = Vec::with_capacity(transaction.inputs.len());
    for (index, input) in transaction.inputs.iter().enumerate() {
        let allowed = input.compute_commit.allowed_script_units();
        let mut vm = TxScriptEngine::from_transaction_input_with_script_units_limit(
            &populated,
            input,
            index,
            populated.utxo(index).ok_or("missing input context")?,
            EngineCtx::new(&cache)
                .with_reused(&reused)
                .with_covenants_ctx(&context),
            flags,
            allowed,
        );
        let outcome = vm.execute();
        let consumed = u64::from(vm.used_script_units());
        outcome.map_err(|error| format!("consensus VM check failed at input {index} (used {consumed} of {} script units): {error}", u64::from(allowed)))?;
        used.push(consumed);
    }
    Ok(used)
}

pub fn verify_all_inputs(transaction: &Transaction, entries: Vec<UtxoEntry>) -> Result<(), Error> {
    if entries.len() != transaction.inputs.len() {
        return Err("input context mismatch".into());
    }
    let populated = PopulatedTransaction::new(transaction, entries);
    let context = CovenantsContext::from_tx(&populated)?;
    let cache = Cache::new(100_000);
    let reused = SigHashReusedValuesUnsync::new();
    for (index, input) in transaction.inputs.iter().enumerate() {
        TxScriptEngine::from_transaction_input(
            &populated,
            input,
            index,
            populated.utxo(index).ok_or("missing input context")?,
            EngineCtx::new(&cache)
                .with_reused(&reused)
                .with_covenants_ctx(&context),
            EngineFlags {
                sigop_script_units: 0.into(),
            },
        )
        .execute()
        .map_err(|error| format!("native VM verification failed at input {index}: {error}"))?;
    }
    Ok(())
}
