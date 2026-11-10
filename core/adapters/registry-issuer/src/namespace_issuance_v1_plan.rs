//! Append-only namespace issuance against an existing registry-root Gap.
//! The claimant controls its own parent; the Gap contract enforces allocation rules.
//! A certificate binds one canonical namespace to a real independent parent CID.
use crate::native_partial_signing::{InputAuthority, NativeSigningPlan, SignaturePacket};
use kaspa_consensus_core::hashing::sighash::{
    SigHashReusedValuesUnsync, calc_schnorr_signature_hash,
};
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::tx::{
    CovenantBinding, MutableTransaction, PopulatedTransaction, Transaction, TransactionInput,
    TransactionOutput, UtxoEntry, VerifiableTransaction,
};
use kaspa_txscript::caches::Cache;
use kaspa_txscript::covenants::CovenantsContext;
use kaspa_txscript::{EngineCtx, EngineFlags, TxScriptEngine, pay_to_script_hash_script};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use silverscript_lang::ast::Expr;
use silverscript_lang::compiler::{
    CompileOptions, CovenantDeclCallOptions, compile_contract, struct_object,
};
#[path = "bounded_public_json.rs"]
mod bounded;
#[path = "native_transaction_codec.rs"]
mod codec;
#[path = "bin/namespace_name_frame_codec.rs"]
pub mod frames;
#[path = "bin/namespace_registry_child_auth_probe_v2_source.rs"]
mod parent_source;
pub type Error = Box<dyn std::error::Error>;
const CARRIER: u64 = 100_000_000;
const ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";
static ROOT_SOURCE: std::sync::LazyLock<String> = std::sync::LazyLock::new(source);
static PARENT_SOURCE: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(parent_source::source_recovery_parent_v4);
static ADAPTER_ROOT_SOURCE: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| adapter_source(ADAPTER_NAMESPACE_BOND_TN10));
static ADAPTER_PARENT_SOURCE: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(parent_source::source_registry_adapter_parent_v1);
#[path = "bin/application_name_deed_compact_v1_compile.rs"]
#[allow(dead_code)]
mod app_candidate;
static ADAPTER_APP_SOURCE: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(app_candidate::source_registry_adapter_app_v1);

const V1_SCHEMA: &str = "KTAPEOUT-NAMESPACE-ISSUANCE-OPERATION-V1";
const ADAPTER_SCHEMA: &str = "KTAPEOUT-REGISTRY-ADAPTER-NAMESPACE-OPERATION-V1";

/// The frozen contract family an operation targets, selected only by request schema.
#[derive(Clone, Copy)]
struct Flavor {
    root: &'static str,
    parent: &'static str,
    bond: u64,
    adapter: bool,
}
fn v1_flavor() -> Flavor {
    Flavor {
        root: ROOT_SOURCE.as_str(),
        parent: PARENT_SOURCE.as_str(),
        bond: 0,
        adapter: false,
    }
}
fn flavor(schema: &Value) -> Result<Flavor, Error> {
    match schema.as_str() {
        Some(V1_SCHEMA) => Ok(v1_flavor()),
        Some(ADAPTER_SCHEMA) => Ok(Flavor {
            root: ADAPTER_ROOT_SOURCE.as_str(),
            parent: ADAPTER_PARENT_SOURCE.as_str(),
            bond: ADAPTER_NAMESPACE_BOND_TN10,
            adapter: true,
        }),
        _ => Err("versioned TN10 issuer operation required".into()),
    }
}

fn source() -> String {
    let mut s = String::from(
        r#"pragma silverscript ^0.1.0;
contract NamespaceIssuanceV1(
 int initObjectKind, byte[32] initGapLo, byte[32] initGapHi, int initHiIsMax,
 byte[32] initNameKey, byte[32] initParentCovenantId,
 byte[32] initParentTemplateHash, int initParentPrefixLen, int initParentSuffixLen
) {
 int objectKind=initObjectKind;
 byte[32] gapLo=initGapLo; byte[32] gapHi=initGapHi; int hiIsMax=initHiIsMax;
 byte[32] nameKey=initNameKey; byte[32] parentCovenantId=initParentCovenantId;
 struct NamespaceParentState { byte[32] namespaceHash; byte[32] authorityCommitment; byte[32] resolverPolicyHash; byte[32] registryRoot; int nonce; }
 function inside(byte[32] key,byte[32] lo,byte[32] hi,int hiMax):(int) {
 int greater=0; int less=0;
"#,
    );
    for (chunk, start) in (0..32).step_by(7).enumerate() {
        let end = (start + 7).min(32);
        for n in ["key", "lo", "hi"] {
            let b = (start..end)
                .rev()
                .map(|i| format!("bytes({n}[{i}])"))
                .collect::<Vec<_>>()
                .join("+");
            s.push_str(&format!("int {n}{chunk}=OpBin2Num({b}+0x00);\n"));
        }
        s.push_str(&format!("if(greater==0) {{if(key{chunk}>lo{chunk}) {{greater=1;}} else if(key{chunk}<lo{chunk}) {{greater=-1;}}}}\nif(less==0) {{if(key{chunk}<hi{chunk}) {{less=1;}} else if(key{chunk}>hi{chunk}) {{less=-1;}}}}\n"));
    }
    s.push_str(
        r#" return(greater!=-1 && (hiMax==1 || less==1)); }
 function requireGap(State g) {
 require(g.objectKind==0);
 require(g.nameKey==0x0000000000000000000000000000000000000000000000000000000000000000);
 require(g.parentCovenantId==g.nameKey);
 require(g.hiIsMax==0 || g.hiIsMax==1);
 if(g.hiIsMax==0) {require(g.gapLo!=g.gapHi);}
 }
 #[covenant(mode=transition,binding=auth,from=1,to=3)]
 function issue(State prevState,State[] nextStates,byte[64] namespaceFrame,
 sig claimantSig,pubkey claimant):(State[]) {
 require(this.activeInputIndex==1 && tx.inputs.length==3);
 requireGap(prevState); require(checkSig(claimantSig,claimant));
 int len=OpBin2Num(bytes(namespaceFrame[0])+0x00);
 require(len>=1 && len<=63);
"#,
    );
    // As in named V6, L1 hashes the entire opaque fixed frame. Canonical ASCII
    // and padding are the shared presentation codec's responsibility; an alias
    // has a different SHA256 key and cannot occupy another canonical namespace.
    s.push_str(r#"
 byte[32] key=sha256(byte[]("KTAPEOUT/0.5.0/NAMESPACE_FRAME/V1")+byte[1](0)+byte[1](10)+namespaceFrame);
 byte[32] successor=experimentalU256IncBe32(key);
 require(inside(key,prevState.gapLo,prevState.gapHi,prevState.hiIsMax).0==1);
 NamespaceParentState parent=readInputStateWithTemplate(0,initParentPrefixLen,initParentSuffixLen,initParentTemplateHash);
 require(parent.namespaceHash==key && parent.nonce==0 && parent.authorityCommitment==sha256(claimant));
 require(parent.registryRoot==OpInputCovenantId(1));
 require(OpInputCovenantId(0)!=OpInputCovenantId(1) && OpInputCovenantId(0)==OpOutputCovenantId(0));
 require(tx.outputs[0].value==tx.inputs[0].value);
 // The pinned parent covenant executes in input0 and admits only its
 // preserving authorize_child transition for this 3/5-output shape.
 int left=0; int right=0;
 if(key!=prevState.gapLo) {left=1;}
 if(prevState.hiIsMax==1 || successor!=prevState.gapHi) {right=1;}
 require(nextStates.length==left+1+right && tx.outputs.length==nextStates.length+2);
 if(left==1) {requireGap(nextStates[0]); require(nextStates[0].gapLo==prevState.gapLo && nextStates[0].gapHi==key && nextStates[0].hiIsMax==0);}
 State certificate=nextStates[left];
 require(certificate.objectKind==1);
 require(certificate.gapLo==0x0000000000000000000000000000000000000000000000000000000000000000 && certificate.gapHi==certificate.gapLo && certificate.hiIsMax==0);
 require(certificate.nameKey==key && certificate.parentCovenantId==OpInputCovenantId(0));
 if(right==1) {State r=nextStates[left+1]; requireGap(r); require(r.gapLo==successor && r.gapHi==prevState.gapHi && r.hiIsMax==prevState.hiIsMax);}
 require(tx.inputs[1].value==100000000);
 for(i,0,3,3) {if(i<nextStates.length) {require(tx.outputs[i+1].value==100000000);}}
 require(tx.outputs[tx.outputs.length-1].scriptPubKey==tx.inputs[2].scriptPubKey);
 return(nextStates);
 }
}
"#);
    s
}
/// Namespace bond for the TN10 `ktape.official.adapter.registry` root (10 KAS).
const ADAPTER_NAMESPACE_BOND_TN10: u64 = 1_000_000_000;

/// `ktape.official.adapter.registry` namespace root, adapter_semver 1.0.0.
/// Differences from NamespaceIssuanceV1 (frozen): issuance requires the namespace
/// parent to hold at least `bond` (refundable deposit paid by the registrant), and a
/// certificate can be released back into a single-key Gap, but only in the same
/// transaction that closes its own parent (see `source_registry_adapter_parent_v1`).
fn adapter_source(bond: u64) -> String {
    let mut s = source();
    let keep = " require(tx.outputs[0].value==tx.inputs[0].value);\n";
    assert_eq!(s.matches(keep).count(), 1, "issuance parent value rule");
    s = s.replace(
        keep,
        &format!(
            " require(tx.outputs[0].value==tx.inputs[0].value && tx.inputs[0].value>={bond});\n"
        ),
    );
    let close = s.rfind('}').expect("root terminator");
    s.insert_str(close, r#" #[covenant(mode=transition,binding=auth,from=1,to=1)]
 function release_namespace(State prevState,State nextState):(State) {
 require(this.activeInputIndex==2 && tx.inputs.length==4 && tx.outputs.length==3);
 require(prevState.objectKind==1);
 NamespaceParentState parent=readInputStateWithTemplate(0,initParentPrefixLen,initParentSuffixLen,initParentTemplateHash);
 require(parent.namespaceHash==prevState.nameKey && OpInputCovenantId(0)==prevState.parentCovenantId);
 requireGap(nextState);
 require(nextState.gapLo==prevState.nameKey && nextState.gapHi==experimentalU256IncBe32(prevState.nameKey) && nextState.hiIsMax==0);
 require(OpAuthOutputCount(2)==1 && OpAuthOutputIdx(2,0)==1);
 require(tx.inputs[2].value==100000000 && tx.outputs[1].value==100000000);
 return(nextState);
 }
"#);
    s.replace(
        "contract NamespaceIssuanceV1(",
        "contract KtapeoutRegistryAdapterNamespaceV1(",
    )
}

fn opts() -> CompileOptions {
    CompileOptions {
        allow_experimental_u256_successor: true,
        ..Default::default()
    }
}
fn bytes(v: &Value) -> Result<Vec<u8>, Error> {
    let t = v.as_str().ok_or("hex string required")?;
    let b = hex::decode(t)?;
    if hex::encode(&b) != t {
        return Err("canonical lowercase hex required".into());
    }
    Ok(b)
}
fn hash(v: &Value) -> Result<Vec<u8>, Error> {
    let b = bytes(v)?;
    if b.len() != 32 {
        return Err("32-byte hash required".into());
    }
    Ok(b)
}
fn exact(v: &Value, fields: &[&str]) -> Result<(), Error> {
    let o = v.as_object().ok_or("object required")?;
    if o.len() != fields.len() || fields.iter().any(|k| !o.contains_key(*k)) {
        return Err("unexpected public input fields".into());
    }
    Ok(())
}
fn args(state: &Value) -> Result<Vec<Expr<'static>>, Error> {
    let a = state
        .as_array()
        .filter(|a| a.len() == 9)
        .ok_or("9 root state/constructor fields required")?;
    a.iter()
        .enumerate()
        .map(|(i, v)| {
            if [0, 3, 7, 8].contains(&i) {
                Ok(Expr::int(
                    v.as_i64()
                        .filter(|n| *n >= 0)
                        .ok_or("state integer required")?,
                ))
            } else {
                Ok(Expr::bytes(hash(v)?))
            }
        })
        .collect()
}
fn state_object(state: &Value) -> Result<Expr<'static>, Error> {
    let names = [
        "objectKind",
        "gapLo",
        "gapHi",
        "hiIsMax",
        "nameKey",
        "parentCovenantId",
    ];
    let a = args(state)?;
    Ok(struct_object(
        names.iter().zip(a).map(|(n, e)| (*n, e)).collect(),
    ))
}
fn root_initial_for(f: Flavor) -> Result<Value, Error> {
    let p = compile_contract(
        f.parent,
        &[
            Expr::bytes(vec![0; 32]),
            Expr::bytes(vec![0; 32]),
            Expr::bytes(vec![0; 32]),
            Expr::bytes(vec![0; 32]),
            Expr::int(0),
        ],
        CompileOptions::default(),
    )?;
    Ok(json!([
        0,
        ZERO,
        ZERO,
        1,
        ZERO,
        ZERO,
        hex::encode(p.template_hash()),
        p.state_layout.start,
        p.script.len() - p.state_layout.start - p.state_layout.len
    ]))
}
fn validate_constructor(state: &Value, f: Flavor) -> Result<(), Error> {
    let base = root_initial_for(f)?;
    let a = state
        .as_array()
        .filter(|a| a.len() == 9)
        .ok_or("9 fields required")?;
    if !matches!(a[0].as_u64(), Some(0 | 1)) || !matches!(a[3].as_u64(), Some(0 | 1)) {
        return Err("issuer objectKind and hiIsMax must be canonical 0/1 integers".into());
    }
    if a[6..] != base.as_array().unwrap()[6..] {
        return Err("parent constructor/template not pinned".into());
    }
    Ok(())
}
fn compiled_state_for(
    state: &Value,
    f: Flavor,
) -> Result<silverscript_lang::compiler::CompiledContract<'static>, Error> {
    validate_constructor(state, f)?;
    let c = compile_contract(f.root, &args(state)?, opts())?;
    if c.script.len() > 10_000 {
        return Err(format!("root script exceeds 10k budget: {}", c.script.len()).into());
    }
    Ok(c)
}
fn signature(v: &Value, name: &str) -> Result<Vec<u8>, Error> {
    if v[name].is_null() {
        return Ok(vec![0; 65]);
    }
    let b = bytes(&v[name])?;
    if b.len() != 65 || b[64] != 1 {
        return Err("Schnorr SIGHASH_ALL signature required".into());
    }
    Ok(b)
}
fn push(script: &[u8]) -> Vec<u8> {
    let mut b = if script.len() <= 75 {
        vec![script.len() as u8]
    } else if script.len() <= 255 {
        vec![0x4c, script.len() as u8]
    } else {
        let mut p = vec![0x4d];
        p.extend((script.len() as u16).to_le_bytes());
        p
    };
    b.extend(script);
    b
}
fn verify(tx: &Transaction, entries: Vec<UtxoEntry>) -> Result<(), Error> {
    let p = PopulatedTransaction::new(tx, entries);
    let c = CovenantsContext::from_tx(&p)?;
    let cache = Cache::new(100_000);
    let reused = SigHashReusedValuesUnsync::new();
    for (i, input) in tx.inputs.iter().enumerate() {
        let mut e = TxScriptEngine::from_transaction_input(
            &p,
            input,
            i,
            p.utxo(i).ok_or("VM entry absent")?,
            EngineCtx::new(&cache)
                .with_reused(&reused)
                .with_covenants_ctx(&c),
            EngineFlags {
                sigop_script_units: 0.into(),
            },
        );
        e.execute()
            .map_err(|e| format!("Native VM input {i}: {e}"))?;
    }
    Ok(())
}
fn check_resource_policy(mass: &Value, fee_sompi: u64) -> Result<(), Error> {
    let normalized = mass["normalized_mass"]
        .as_u64()
        .ok_or("normalized mass is missing")?;
    if normalized == 0 || normalized > 500_000 {
        return Err("issuer projected mass exceeds the 500000 local policy limit".into());
    }
    // Conservative preparation baseline from the retained TN10 observations.
    // Passing is not a live relay quote or a network acceptance promise.
    let minimum = normalized
        .checked_mul(100)
        .ok_or("issuer fee baseline overflow")?;
    if fee_sompi < minimum {
        return Err(format!(
            "issuer fee below local mass baseline: requires {minimum} sompi, offered {fee_sompi}"
        )
        .into());
    }
    Ok(())
}

fn envelope(
    tx: Transaction,
    entries: Vec<UtxoEntry>,
    verify_vm: bool,
    extra: Value,
    request: &Value,
    f: Flavor,
) -> Result<Value, Error> {
    let mass = codec::local_mass_projection(&tx, entries.clone())?;
    check_resource_policy(&mass, extra["fee_sompi"].as_u64().ok_or("fee is missing")?)?;
    if verify_vm {
        verify(&tx, entries.clone())?;
    }
    let issuance_review_only = !f.adapter && request["operation"] == "ISSUE_NAMESPACE";
    let issuance_accounting = if issuance_review_only {
        let state_outputs = tx
            .outputs
            .get(1..tx.outputs.len().saturating_sub(1))
            .ok_or("namespace state outputs are missing")?;
        let carrier_sompi = state_outputs
            .first()
            .ok_or("namespace state outputs are missing")?
            .value;
        if state_outputs
            .iter()
            .any(|output| output.value != carrier_sompi)
        {
            return Err("NAMESPACE_STATE_OUTPUT_CARRIER_MISMATCH".into());
        }
        Some(crate::namespace_issuance_review::IssuanceAccounting {
            parent_input_sompi: entries.first().ok_or("parent input is missing")?.amount,
            parent_successor_sompi: tx
                .outputs
                .first()
                .ok_or("parent successor is missing")?
                .value,
            root_gap_input_sompi: entries.get(1).ok_or("root Gap input is missing")?.amount,
            carrier_sompi,
            state_output_count: state_outputs.len() as u64,
            fee_sompi: extra["fee_sompi"].as_u64().ok_or("fee is missing")?,
        })
    } else {
        None
    };
    let native_signing = if issuance_review_only {
        None
    } else {
        signing_plan(&tx, &entries, request)?
            .map(|plan| plan.requests())
            .transpose()?
    };
    let signed_txid = if verify_vm {
        Some(tx.id().to_string())
    } else {
        None
    };
    let m = MutableTransaction::with_entries(tx, entries);
    let digests: Vec<String> = (0..m.tx.inputs.len())
        .map(|i| {
            hex::encode(
                calc_schnorr_signature_hash(
                    &m.as_verifiable(),
                    i,
                    SIG_HASH_ALL,
                    &SigHashReusedValuesUnsync::new(),
                )
                .as_bytes(),
            )
        })
        .collect();
    let rpc: kaspa_rpc_core::RpcTransaction = (&m.tx).into();
    let schema = if f.adapter {
        "KTAPEOUT-REGISTRY-ADAPTER-NAMESPACE-BODY-V1"
    } else {
        "KTAPEOUT-NAMESPACE-ISSUANCE-BODY-V1"
    };
    let mut body = json!({"schema":schema,"network":"testnet-10","transaction":rpc,"input_sighash_all":digests,"mass_projection":mass,"native_vm_verified":verify_vm,"signing_allowed":false,"broadcast":false,"source_sha256":hex::encode(Sha256::digest(f.root.as_bytes()))});
    if f.adapter {
        body["adapter_id"] = json!("ktape.official.adapter.registry");
        body["adapter_semver"] = json!("1.0.0");
        body["parent_source_sha256"] = json!(hex::encode(Sha256::digest(f.parent.as_bytes())));
    }
    body.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    if let Some(accounting) = issuance_accounting {
        crate::namespace_issuance_review::attach_review(&mut body, accounting)?;
    }
    let digest = Sha256::digest(
        [
            b"KTAPEOUT/0.5.0/NAMESPACE_ISSUANCE/V1\0".as_slice(),
            serde_json::to_string(&body)?.as_bytes(),
        ]
        .concat(),
    );
    Ok(json!({"plan_hash":hex::encode(digest),"body":body,
        "native_signing":native_signing,"signed_txid":signed_txid}))
}

// Reuse the existing wallet-safe plan and packet binding. The covenant witness
// is reconstructed by this planner after signatures return; it is not supplied
// by the wallet. Clearing witnesses does not change SIGHASH_ALL commitments.
fn signing_plan(
    tx: &Transaction,
    entries: &[UtxoEntry],
    request: &Value,
) -> Result<Option<NativeSigningPlan>, Error> {
    let fields: &[&str] = if request["operation"] == "GENESIS" {
        &["fee_signature"]
    } else {
        &["parent_signature", "claimant_signature", "fee_signature"]
    };
    if fields
        .iter()
        .any(|field| !request["public_signatures"][*field].is_null())
    {
        return Ok(None);
    }
    let fee_index = entries.len().checked_sub(1).ok_or("fee input missing")?;
    let fee_script = entries[fee_index].script_public_key.script();
    if entries[fee_index].script_public_key.version() != 0
        || fee_script.len() != 34
        || fee_script[0] != 0x20
        || fee_script[33] != 0xac
    {
        return Ok(None); // Other script shapes retain unsigned planning only.
    }
    let mut authorities = Vec::new();
    if fields.len() == 3 {
        for input_index in [0, 1] {
            authorities.push(InputAuthority {
                input_index,
                signer_public_key: request["claimant_public_key"]
                    .as_str()
                    .ok_or("claimant key missing")?
                    .to_owned(),
            });
        }
    }
    authorities.push(InputAuthority {
        input_index: fee_index,
        signer_public_key: hex::encode(&fee_script[1..33]),
    });
    let mut unsigned = tx.clone();
    for input in &mut unsigned.inputs {
        input.signature_script.clear();
    }
    // RELEASE_NAMESPACE: the certificate (input 2) is authorized by its covenant script alone.
    let script_only: &[usize] = if request["operation"] == "RELEASE_NAMESPACE" {
        &[2]
    } else {
        &[]
    };
    let plan = NativeSigningPlan::new_with_unsigned_inputs(
        unsigned,
        entries.to_vec(),
        authorities,
        script_only,
    )?;
    Ok(Some(plan))
}
pub fn build(v: &Value, verify_vm: bool) -> Result<Value, Error> {
    let f = flavor(&v["schema"])?;
    if !f.adapter && v["operation"] == "ISSUE_NAMESPACE" {
        if verify_vm {
            return Err("NAMESPACE_ISSUANCE_UNVERIFIED_SIGNING_DISABLED".into());
        }
        if ["parent_signature", "claimant_signature", "fee_signature"]
            .iter()
            .any(|role| !v["public_signatures"][role].is_null())
        {
            return Err("NAMESPACE_ISSUANCE_UNVERIFIED_SIGNING_DISABLED".into());
        }
    }
    build_impl(v, verify_vm)
}

// Internal verifier retained for deterministic local tests. The CLI uses
// `build`, which keeps unverified NamespaceIssuanceV1 transactions unsigned.
fn build_impl(v: &Value, verify_vm: bool) -> Result<Value, Error> {
    let f = flavor(&v["schema"])?;
    if v["network"] != "testnet-10" {
        return Err("versioned TN10 issuer operation required".into());
    }
    let op = v["operation"].as_str().ok_or("operation required")?;
    if op == "INSPECT_STATE" {
        exact(v, &["schema", "network", "operation", "state_args"])?;
        let c = compiled_state_for(&v["state_args"], f)?;
        return Ok(
            json!({"schema":"KTAPEOUT-NAMESPACE-ISSUANCE-STATE-BINDING-V1","network":"testnet-10","source_sha256":hex::encode(Sha256::digest(f.root.as_bytes())),"script_public_key":hex::encode(codec::script_bytes(&pay_to_script_hash_script(&c.script))),"script_bytes":c.script.len(),"state_args":v["state_args"],"valid":true,"signing_allowed":false,"broadcast":false,"l1_evidence":false}),
        );
    }
    let signatures = &v["public_signatures"];
    exact(
        signatures,
        &["parent_signature", "claimant_signature", "fee_signature"],
    )?;
    if op == "RELEASE_NAMESPACE" {
        if !f.adapter {
            return Err("NamespaceIssuanceV1 certificates are permanent".into());
        }
        return release_namespace(v, f, verify_vm);
    }
    if op == "GENESIS" {
        v["fee_sompi"]
            .as_u64()
            .filter(|n| *n > 0 && *n <= 30_000_000)
            .ok_or("root genesis fee must be <=0.30 KAS")?;
        exact(
            v,
            &[
                "schema",
                "network",
                "operation",
                "funding_utxo",
                "fee_sompi",
                "public_signatures",
            ],
        )?;
        let state = root_initial_for(f)?;
        let c = compiled_state_for(&state, f)?;
        let spk = pay_to_script_hash_script(&c.script);
        let req = json!({"current":{"fee_input_script_hash":hex::encode(Sha256::digest(codec::script_bytes(&codec::decode_spk(&v["funding_utxo"]["script_public_key"])?)))},"funding_utxo":v["funding_utxo"],"funding_change_script_public_key":v["funding_utxo"]["script_public_key"],"fee_sompi":v["fee_sompi"],"state_sompi":CARRIER,"compute_budget":10});
        let plan = codec::genesis_plan(&req, spk, CARRIER)?;
        let rpc: kaspa_rpc_core::RpcTransaction =
            serde_json::from_value(plan["transaction"].clone())?;
        let mut tx: Transaction = rpc.try_into()?;
        tx.inputs[0].signature_script = push(&signature(signatures, "fee_signature")?);
        tx.finalize();
        return envelope(
            tx,
            vec![codec::parse_utxo(&v["funding_utxo"], false)?.1],
            verify_vm,
            json!({"operation":op,"state_args":state,"fee_sompi":v["fee_sompi"],"covenant_id":plan["covenant_id"],"input_roles":["fee_input"],"output_roles":["root_gap","fee_change"]}),
            v,
            f,
        );
    }
    if op != "ISSUE_NAMESPACE" {
        return Err("unsupported issuer operation".into());
    }
    exact(
        v,
        &[
            "schema",
            "network",
            "operation",
            "parent_utxo",
            "root_gap_utxo",
            "fee_utxo",
            "root_state_args",
            "parent_state_args",
            "namespace_frame",
            "claimant_public_key",
            "fee_sompi",
            "public_signatures",
        ],
    )?;
    let frame = frames::frame(&v["namespace_frame"])?;
    let key = frames::namespace_hash(&frame);
    let pubkey = hash(&v["claimant_public_key"])?;
    secp256k1::XOnlyPublicKey::from_slice(&pubkey)?;
    let root = v["root_state_args"]
        .as_array()
        .ok_or("root state required")?;
    let c = compiled_state_for(&v["root_state_args"], f)?;
    let (rp, re) = codec::parse_utxo(&v["root_gap_utxo"], true)?;
    let (pp, pe) = codec::parse_utxo(&v["parent_utxo"], true)?;
    let (fp, fe) = codec::parse_utxo(&v["fee_utxo"], false)?;
    if pe.amount < f.bond {
        return Err(format!("namespace parent must hold the {} sompi bond", f.bond).into());
    }
    let issue_budgets = if f.adapter {
        ADAPTER_ISSUE_BUDGETS
    } else {
        [1000, 3000, 10]
    };
    if rp == pp
        || rp == fp
        || pp == fp
        || re.covenant_id == pe.covenant_id
        || re.amount != CARRIER
        || re.script_public_key != pay_to_script_hash_script(&c.script)
    {
        return Err("distinct authenticated root/parent/fee inputs required".into());
    }
    let pstate = v["parent_state_args"]
        .as_array()
        .filter(|a| a.len() == 5)
        .ok_or("five parent fields required")?;
    let pa = vec![
        Expr::bytes(hash(&pstate[0])?),
        Expr::bytes(hash(&pstate[1])?),
        Expr::bytes(hash(&pstate[2])?),
        Expr::bytes(hash(&pstate[3])?),
        Expr::int(pstate[4].as_i64().ok_or("parent nonce")?),
    ];
    let pc = compile_contract(f.parent, &pa, CompileOptions::default())?;
    if pe.script_public_key != pay_to_script_hash_script(&pc.script)
        || pstate[0] != hex::encode(&key)
        || pstate[1] != hex::encode(Sha256::digest(&pubkey))
        || pstate[3] != re.covenant_id.unwrap().to_string()
        || pstate[4] != 0
    {
        return Err("real unissued parent/key/owner/root binding required".into());
    }
    let lo = hash(&root[1])?;
    let hi = hash(&root[2])?;
    let max = root[3] == 1;
    if root[0] != 0 || root[4] != ZERO || root[5] != ZERO || key < lo || (!max && key >= hi) {
        return Err("namespace already allocated or invalid root Gap".into());
    }
    let successor = successor_of(&key)?;
    let mut next = Vec::<Value>::new();
    let mut roles = vec!["parent_successor"];
    if key != lo {
        let mut left = root.clone();
        left[2] = json!(hex::encode(&key));
        left[3] = json!(0);
        next.push(json!(left));
        roles.push("root_left_gap");
    }
    let certificate_index = next.len() + 1;
    let mut cert = root.clone();
    cert[..6].clone_from_slice(
        json!([
            1,
            ZERO,
            ZERO,
            0,
            hex::encode(&key),
            pe.covenant_id.unwrap().to_string()
        ])
        .as_array()
        .unwrap(),
    );
    next.push(json!(cert));
    roles.push("namespace_issuance_certificate");
    if max || successor != hi {
        let mut right = root.clone();
        right[1] = json!(hex::encode(successor));
        next.push(json!(right));
        roles.push("root_right_gap");
    }
    roles.push("fee_change");
    // The frozen V4 parent admits 3/5 outputs, not the four-output boundary
    // shape. Fail during preparation rather than presenting an unspendable plan.
    if next.len() == 2 {
        return Err(
            "issuer boundary split requires unsupported four-output parent transition".into(),
        );
    }
    let fee = v["fee_sompi"]
        .as_u64()
        .filter(|n| *n > 0 && *n <= 50_000_000)
        .ok_or("positive bounded issuance fee <=0.50 KAS required")?;
    let change = fe
        .amount
        .checked_add(CARRIER)
        .and_then(|n| n.checked_sub(CARRIER * next.len() as u64))
        .and_then(|n| n.checked_sub(fee))
        .filter(|n| *n > 0)
        .ok_or("insufficient issuance funding")?;
    let names = [
        "namespaceHash",
        "authorityCommitment",
        "resolverPolicyHash",
        "registryRoot",
        "nonce",
    ];
    let po = struct_object(names.iter().zip(pa).map(|(n, e)| (*n, e)).collect());
    let mut pw = pc.build_sig_script_for_covenant_decl(
        "authorize_child",
        vec![
            po,
            Expr::bytes(pubkey.clone()),
            Expr::bytes(signature(signatures, "parent_signature")?),
        ],
        CovenantDeclCallOptions { is_leader: true },
    )?;
    pw.extend(push(&pc.script));
    let objects = next
        .iter()
        .map(state_object)
        .collect::<Result<Vec<_>, _>>()?;
    let array = Expr::new(
        silverscript_lang::ast::ExprKind::Array(objects),
        Default::default(),
    );
    let mut rw = c.build_sig_script_for_covenant_decl(
        "issue",
        vec![
            array,
            Expr::bytes(frame),
            Expr::bytes(signature(signatures, "claimant_signature")?),
            Expr::bytes(pubkey),
        ],
        CovenantDeclCallOptions { is_leader: true },
    )?;
    rw.extend(push(&c.script));
    let mut outputs = vec![TransactionOutput {
        value: pe.amount,
        script_public_key: pe.script_public_key.clone(),
        covenant: Some(CovenantBinding {
            authorizing_input: 0,
            covenant_id: pe.covenant_id.unwrap(),
        }),
    }];
    for state in &next {
        outputs.push(TransactionOutput {
            value: CARRIER,
            script_public_key: pay_to_script_hash_script(&compiled_state_for(state, f)?.script),
            covenant: Some(CovenantBinding {
                authorizing_input: 1,
                covenant_id: re.covenant_id.unwrap(),
            }),
        });
    }
    outputs.push(TransactionOutput {
        value: change,
        script_public_key: fe.script_public_key.clone(),
        covenant: None,
    });
    let tx = Transaction::new(
        1,
        vec![
            TransactionInput::new_with_compute_budget(pp, pw, 0, issue_budgets[0]),
            TransactionInput::new_with_compute_budget(rp, rw, 0, issue_budgets[1]),
            TransactionInput::new_with_compute_budget(
                fp,
                push(&signature(signatures, "fee_signature")?),
                0,
                issue_budgets[2],
            ),
        ],
        outputs,
        0,
        Default::default(),
        0,
        vec![],
    );
    envelope(
        tx,
        vec![pe, re, fe],
        verify_vm,
        json!({"operation":op,"root_covenant_id":v["root_gap_utxo"]["covenant_id"],"parent_covenant_id":v["parent_utxo"]["covenant_id"],"namespace_hash":hex::encode(key),"certificate_output_index":certificate_index,"next_root_states":next,"fee_sompi":fee,"input_roles":["parent_namespace_state","root_gap","fee_input"],"output_roles":roles,
            "certificate_policy":if f.adapter {"RELEASED_ONLY_WITH_PARENT_CLOSE"} else {"PERMANENT_NO_NAMESPACE_REALLOCATION"},"certificate_carrier_sompi":CARRIER}),
        v,
        f,
    )
}

fn successor_of(key: &[u8]) -> Result<Vec<u8>, Error> {
    let mut successor = key.to_vec();
    for b in successor.iter_mut().rev() {
        let (n, overflow) = b.overflowing_add(1);
        *b = n;
        if !overflow {
            return Ok(successor);
        }
    }
    Err("maximum key is outside issuer successor domain".into())
}

/// Adapter compute budgets. Declared budget dominates projected mass (and so the fee), so each
/// value is about 2x the need measured with the consensus `mass_per_sig_op` weighting
/// (test `registry_adapter_bond_issue_release_and_reissue_round_trip`: issue [10, 22, 10],
/// release [10, 12, 5, 10]). The frozen V1 issuer keeps its original [1000, 3000, 10].
const ADAPTER_ISSUE_BUDGETS: [u16; 3] = [20, 44, 10];
/// Parent close, app Gap retire, certificate release, fee input.
const RELEASE_BUDGETS: [u16; 4] = [20, 24, 10, 10];

/// Close a namespace: refund the parent bond and the empty application Gap to the
/// authority, and return the certificate key to the root as a single-key Gap.
fn release_namespace(v: &Value, f: Flavor, verify_vm: bool) -> Result<Value, Error> {
    exact(
        v,
        &[
            "schema",
            "network",
            "operation",
            "parent_utxo",
            "parent_state_args",
            "app_gap_utxo",
            "certificate_utxo",
            "certificate_state_args",
            "fee_utxo",
            "refund_script_public_key",
            "claimant_public_key",
            "fee_sompi",
            "public_signatures",
        ],
    )?;
    let signatures = &v["public_signatures"];
    let pubkey = hash(&v["claimant_public_key"])?;
    secp256k1::XOnlyPublicKey::from_slice(&pubkey)?;
    let (pp, pe) = codec::parse_utxo(&v["parent_utxo"], true)?;
    let (gp, ge) = codec::parse_utxo(&v["app_gap_utxo"], true)?;
    let (cp, ce) = codec::parse_utxo(&v["certificate_utxo"], true)?;
    let (fp, fe) = codec::parse_utxo(&v["fee_utxo"], false)?;
    let outpoints = [pp, gp, cp, fp];
    if (0..4).any(|i| (i + 1..4).any(|j| outpoints[i] == outpoints[j])) {
        return Err("distinct parent/app-gap/certificate/fee inputs required".into());
    }
    if ge.covenant_id != pe.covenant_id || ce.covenant_id == pe.covenant_id || ce.amount != CARRIER
    {
        return Err(
            "app Gap must share the parent lineage; certificate must be a root carrier".into(),
        );
    }
    let pstate = v["parent_state_args"]
        .as_array()
        .filter(|a| a.len() == 5)
        .ok_or("five parent fields required")?;
    let namespace = hash(&pstate[0])?;
    let pa = vec![
        Expr::bytes(namespace.clone()),
        Expr::bytes(hash(&pstate[1])?),
        Expr::bytes(hash(&pstate[2])?),
        Expr::bytes(hash(&pstate[3])?),
        Expr::int(
            pstate[4]
                .as_i64()
                .filter(|n| *n >= 0)
                .ok_or("parent nonce")?,
        ),
    ];
    let pc = compile_contract(f.parent, &pa, CompileOptions::default())?;
    let parent_cid = pe.covenant_id.ok_or("parent covenant required")?;
    let root_cid = ce.covenant_id.ok_or("certificate covenant required")?;
    if pe.script_public_key != pay_to_script_hash_script(&pc.script)
        || pstate[1] != hex::encode(Sha256::digest(&pubkey))
        || pstate[3] != root_cid.to_string()
    {
        return Err("parent state, authority or registry root mismatch".into());
    }
    let cert = v["certificate_state_args"]
        .as_array()
        .ok_or("certificate state required")?;
    let cc = compiled_state_for(&v["certificate_state_args"], f)?;
    if ce.script_public_key != pay_to_script_hash_script(&cc.script)
        || cert[0] != 1
        || cert[4] != pstate[0]
        || cert[5] != parent_cid.to_string()
    {
        return Err("certificate does not belong to this namespace parent".into());
    }
    let zero = vec![0u8; 32];
    let parent_end = pc.state_layout.start + pc.state_layout.len;
    let gap_args = vec![
        Expr::int(0),
        Expr::int(0),
        Expr::bytes(zero.clone()),
        Expr::bytes(zero.clone()),
        Expr::int(1),
        Expr::bytes(zero.clone()),
        Expr::bytes(zero.clone()),
        Expr::bytes(zero.clone()),
        Expr::bytes(zero.clone()),
        Expr::bytes(zero),
        Expr::int(0),
        Expr::bytes(namespace.clone()),
        Expr::bytes(pc.template_hash().to_vec()),
        Expr::int(pc.state_layout.start as i64),
        Expr::int((pc.script.len() - parent_end) as i64),
    ];
    let gc = compile_contract(ADAPTER_APP_SOURCE.as_str(), &gap_args, opts())?;
    if ge.script_public_key != pay_to_script_hash_script(&gc.script) {
        return Err("app Gap must be the namespace's full empty adapter Gap".into());
    }
    let refund = codec::decode_spk(&v["refund_script_public_key"])?;
    let refund_hash = Sha256::digest(codec::script_bytes(&refund)).to_vec();
    let mut released = Value::Array(cert.clone());
    released[0] = json!(0);
    released[1] = json!(hex::encode(&namespace));
    released[2] = json!(hex::encode(successor_of(&namespace)?));
    released[3] = json!(0);
    released[4] = json!(ZERO);
    released[5] = json!(ZERO);
    let rc = compiled_state_for(&released, f)?;
    let fee = v["fee_sompi"]
        .as_u64()
        .filter(|n| *n > 0 && *n <= 50_000_000)
        .ok_or("positive bounded release fee <=0.50 KAS required")?;
    let change = fe
        .amount
        .checked_sub(fee)
        .filter(|n| *n > 0)
        .ok_or("insufficient release funding")?;
    let refund_value = pe.amount.checked_add(ge.amount).ok_or("refund overflow")?;
    let mut pw = pc.build_sig_script(
        "close_namespace_with_certificate",
        vec![
            Expr::bytes(signature(signatures, "parent_signature")?),
            Expr::bytes(pubkey.clone()),
            Expr::bytes(refund_hash.clone()),
        ],
    )?;
    pw.extend(push(&pc.script));
    let mut gw = gc.build_sig_script(
        "retire_namespace",
        vec![
            Expr::bytes(signature(signatures, "claimant_signature")?),
            Expr::bytes(pubkey),
            Expr::bytes(refund_hash),
        ],
    )?;
    gw.extend(push(&gc.script));
    let mut cw = cc.build_sig_script_for_covenant_decl(
        "release_namespace",
        vec![state_object(&released)?],
        CovenantDeclCallOptions { is_leader: true },
    )?;
    cw.extend(push(&cc.script));
    let outputs = vec![
        TransactionOutput {
            value: refund_value,
            script_public_key: refund,
            covenant: Some(CovenantBinding {
                authorizing_input: 0,
                covenant_id: parent_cid,
            }),
        },
        TransactionOutput {
            value: CARRIER,
            script_public_key: pay_to_script_hash_script(&rc.script),
            covenant: Some(CovenantBinding {
                authorizing_input: 2,
                covenant_id: root_cid,
            }),
        },
        TransactionOutput {
            value: change,
            script_public_key: fe.script_public_key.clone(),
            covenant: None,
        },
    ];
    let tx = Transaction::new(
        1,
        vec![
            TransactionInput::new_with_compute_budget(pp, pw, 0, RELEASE_BUDGETS[0]),
            TransactionInput::new_with_compute_budget(gp, gw, 0, RELEASE_BUDGETS[1]),
            TransactionInput::new_with_compute_budget(cp, cw, 0, RELEASE_BUDGETS[2]),
            TransactionInput::new_with_compute_budget(
                fp,
                push(&signature(signatures, "fee_signature")?),
                0,
                RELEASE_BUDGETS[3],
            ),
        ],
        outputs,
        0,
        Default::default(),
        0,
        vec![],
    );
    envelope(
        tx,
        vec![pe, ge, ce, fe],
        verify_vm,
        json!({"operation":"RELEASE_NAMESPACE","namespace_hash":hex::encode(&namespace),"released_root_state":released,"refund_sompi":refund_value,"fee_sompi":fee,
            "input_roles":["namespace_parent","app_full_gap","namespace_certificate","fee_input"],"output_roles":["bond_refund","root_single_key_gap","fee_change"]}),
        v,
        f,
    )
}
fn transition_summary(prepared: &Value) -> Result<Value, Error> {
    let rpc: kaspa_rpc_core::RpcTransaction =
        serde_json::from_value(prepared["body"]["transaction"].clone())?;
    let tx: Transaction = rpc.try_into()?;
    let roles = prepared["body"]["output_roles"]
        .as_array()
        .ok_or("output roles missing")?;
    if roles.len() != tx.outputs.len() {
        return Err("output roles mismatch".into());
    }
    let outputs: Vec<Value> = tx.outputs.iter().enumerate().filter(|(index, _)| roles[*index] != "fee_change")
        .map(|(index, output)| json!({"role":roles[index],"output_index":index,
            "amount":output.value.to_string(),"script_public_key":hex::encode(codec::script_bytes(&output.script_public_key)),
            "covenant_id":output.covenant.map(|binding| binding.covenant_id.to_string())})).collect();
    Ok(
        json!({"schema":"KTAPEOUT-PROFILE-TRANSITION-SUMMARY-V1","profile_family_id":"NamespaceIssuanceV1",
        "operation":prepared["body"]["operation"],"readback_outputs":outputs,
        "admission":"VERIFY_AT_TRUSTED_HOST_BOUNDARY"}),
    )
}

// Same process protocol as the existing Profile Operation Host; no new signer API.
pub fn transition_command(mode: &str, value: &Value) -> Result<Value, Error> {
    let request;
    let packets: Vec<SignaturePacket>;
    if mode == "--transition-plan" {
        exact(value, &["action", "request"])?;
        if value["action"] != "profile_state_transition" {
            return Err("unsupported Profile action".into());
        }
        request = &value["request"];
        packets = Vec::new();
    } else {
        exact(value, &["plan", "packets"])?;
        exact(&value["plan"], &["action", "request"])?;
        if value["plan"]["action"] != "profile_state_transition" {
            return Err("unsupported Profile action".into());
        }
        request = &value["plan"]["request"];
        packets = serde_json::from_value(value["packets"].clone())?;
    }
    let prepared = build(request, false)?;
    let mut signing = prepared["native_signing"].clone();
    if signing.is_null() {
        return Err("unsigned P2PK-funded operation required".into());
    }
    let summary = transition_summary(&prepared)?;
    signing["summary"] = summary.clone();
    signing["mass_projection"] = prepared["body"]["mass_projection"].clone();
    if mode == "--transition-plan" {
        return Ok(signing);
    }
    let rpc: kaspa_rpc_core::RpcTransaction =
        serde_json::from_value(prepared["body"]["transaction"].clone())?;
    let tx: Transaction = rpc.try_into()?;
    let entries = if request["operation"] == "GENESIS" {
        vec![codec::parse_utxo(&request["funding_utxo"], false)?.1]
    } else if request["operation"] == "RELEASE_NAMESPACE" {
        vec![
            codec::parse_utxo(&request["parent_utxo"], true)?.1,
            codec::parse_utxo(&request["app_gap_utxo"], true)?.1,
            codec::parse_utxo(&request["certificate_utxo"], true)?.1,
            codec::parse_utxo(&request["fee_utxo"], false)?.1,
        ]
    } else {
        vec![
            codec::parse_utxo(&request["parent_utxo"], true)?.1,
            codec::parse_utxo(&request["root_gap_utxo"], true)?.1,
            codec::parse_utxo(&request["fee_utxo"], false)?.1,
        ]
    };
    let plan = signing_plan(&tx, &entries, request)?.ok_or("signing plan missing")?;
    let signatures = plan.merge(&packets)?;
    let expected = signing["requests"]
        .as_array()
        .ok_or("signing requests missing")?;
    if signatures.len() != expected.len() {
        return Err("signature set incomplete".into());
    }
    if mode == "--verify-signatures" {
        let verified: Vec<Value> = signatures
            .keys()
            .map(|authority| {
                json!({
            "input_index":authority.input_index,"signer_public_key":authority.signer_public_key})
            })
            .collect();
        return Ok(
            json!({"verified":true,"broadcast":false,"native_plan_hash":plan.hash(),
            "verified_packet_count":verified.len(),"verified_packets":verified}),
        );
    }
    if mode != "--merge-signatures" {
        return Err("unsupported signing command".into());
    }
    let mut signed_request = request.clone();
    for (authority, signature) in signatures {
        // The fee input is always last; RELEASE_NAMESPACE puts the script-only certificate at input 2.
        let field =
            if request["operation"] == "GENESIS" || authority.input_index + 1 == entries.len() {
                "fee_signature"
            } else {
                ["parent_signature", "claimant_signature"]
                    .get(authority.input_index)
                    .copied()
                    .ok_or("unexpected signed input")?
            };
        signed_request["public_signatures"][field] = json!(format!("{}01", hex::encode(signature)));
    }
    let signed = build(&signed_request, true)?;
    if signed["body"]["transaction"]["outputs"] != prepared["body"]["transaction"]["outputs"] {
        return Err("signed output mismatch".into());
    }
    Ok(
        json!({"schema":"KTAPEOUT-TN10-NAMESPACE-ISSUANCE-SIGNED-V1","network":"testnet-10",
        "transition_plan":{"action":"profile_state_transition","request":request},
        "signature_packets":packets,
        "txid":signed["signed_txid"],"native_plan_hash":plan.hash(),"native_vm_verified":true,
        "transaction":signed["body"]["transaction"],"mass_projection":signed["body"]["mass_projection"],
        "summary":summary,"broadcast":false}),
    )
}

pub fn run() -> Result<(), Error> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    if !(a.len() == 1 || (a.len() == 2 && a[1] == "--verify-vm")) {
        return Err("usage: namespace_issuance_v1_plan PUBLIC.json|--stdin [--verify-vm] or --transition-plan|--verify-signatures|--merge-signatures < JSON stdin".into());
    }
    use std::io::Read;
    let mut b = Vec::new();
    let signing_mode = [
        "--transition-plan",
        "--verify-signatures",
        "--merge-signatures",
    ]
    .contains(&a[0].as_str());
    if signing_mode && a.len() != 1 {
        return Err("signing protocol accepts one mode only".into());
    }
    if signing_mode || a[0] == "--stdin" {
        std::io::stdin().take(262145).read_to_end(&mut b)?;
    } else {
        std::fs::File::open(&a[0])?
            .take(262145)
            .read_to_end(&mut b)?;
    }
    if b.len() > 262144 {
        return Err("public request >256KiB".into());
    }
    let value = bounded::parse(&b)?;
    let result = if signing_mode {
        transition_command(&a[0], &value)?
    } else {
        build(&value, a.len() == 2)?
    };
    println!("{result}");
    Ok(())
}
