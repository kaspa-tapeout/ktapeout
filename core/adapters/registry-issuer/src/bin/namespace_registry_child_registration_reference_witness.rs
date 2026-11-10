//! Build deterministic placeholder witnesses for the reference child-registration body codec.
//!
//! This is deliberately a reference workbench, not a canonical L1 writer.  It
//! compiles the pinned parent/child candidate sources and emits unsigned,
//! zero-signature witness scripts for the three transaction inputs.  It never
//! signs, reads live UTXOs, or broadcasts.

use kaspa_txscript::pay_to_script_hash_script;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use silverscript_lang::ast::Expr;
use silverscript_lang::compiler::{
    CompileOptions, CovenantDeclCallOptions, compile_contract, struct_object,
};

use ktapeout_050_adapter_workbench::bounded_public_json;
#[path = "application_name_deed_compact_v1_compile.rs"]
#[allow(dead_code)]
mod child_candidate;
#[path = "namespace_child_registration_contract.rs"]
mod contract;
#[path = "namespace_name_frame_codec.rs"]
mod name_frame;
#[path = "namespace_registry_child_auth_probe_v2_source.rs"]
mod parent_source;
#[path = "namespace_child_state_layout.rs"]
mod state_layout;

const SCHEMA: &str = "KTAPEOUT-NAMESPACE-REGISTRY-CHILD-REFERENCE-WITNESS-V1";
const MAX_INPUT_BYTES: usize = 64 * 1024;
const MIN_DEED_BOND_SOMPI: i64 = 1_000_000_000;
/// `ktape.official.adapter.registry` 1.0.0 input schemas (V6 witness layouts, adapter sources).
const ADAPTER_REGISTRATION_SCHEMA: &str = "KTAPEOUT-REGISTRY-ADAPTER-APP-REGISTRATION-INPUT-V1";
const ADAPTER_OWNER_SCHEMA: &str = "KTAPEOUT-REGISTRY-ADAPTER-APP-OWNER-INPUT-V1";
const ADAPTER_RECOVERY_SCHEMA: &str = "KTAPEOUT-REGISTRY-ADAPTER-APP-RECOVERY-INPUT-V1";

fn hex32(value: &Value, name: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let text = value
        .as_str()
        .ok_or_else(|| format!("{name} must be lowercase hex"))?;
    let bytes = hex::decode(text).map_err(|_| format!("{name} must be lowercase hex"))?;
    if bytes.len() != 32 || hex::encode(&bytes) != text {
        return Err(format!("{name} must be canonical 32-byte lowercase hex").into());
    }
    Ok(bytes)
}

fn nonzero_hex32(value: &Value, name: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let bytes = hex32(value, name)?;
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(format!("{name} must be nonzero").into());
    }
    Ok(bytes)
}

fn nonnegative(value: &Value, name: &str) -> Result<i64, Box<dyn std::error::Error>> {
    let n = value
        .as_i64()
        .ok_or_else(|| format!("{name} must be an integer"))?;
    if n < 0 {
        return Err(format!("{name} must be non-negative").into());
    }
    Ok(n)
}

fn nonce_value(value: &Value) -> Result<i64, Box<dyn std::error::Error>> {
    let n = nonnegative(value, "nonce")?;
    if n == i64::MAX {
        return Err("nonce must leave room for successor increment".into());
    }
    Ok(n)
}

fn deed_bond(value: &Value) -> Result<i64, Box<dyn std::error::Error>> {
    let bond = nonnegative(value, "bond_sompi")?;
    if bond < MIN_DEED_BOND_SOMPI {
        return Err(format!("bond_sompi must be at least {MIN_DEED_BOND_SOMPI}").into());
    }
    Ok(bond)
}

fn increment_be32(input: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if input.len() != 32 {
        return Err("name_key must be 32 bytes".into());
    }
    let mut out = input.to_vec();
    for byte in out.iter_mut().rev() {
        if *byte == 0xff {
            *byte = 0;
        } else {
            *byte += 1;
            return Ok(out);
        }
    }
    Err("name_key cannot be the maximum 256-bit value".into())
}

fn state(
    namespace: Vec<u8>,
    authority: Vec<u8>,
    resolver: Vec<u8>,
    root: Vec<u8>,
    nonce: i64,
) -> Expr<'static> {
    struct_object(vec![
        ("namespaceHash", Expr::bytes(namespace)),
        ("authorityCommitment", Expr::bytes(authority)),
        ("resolverPolicyHash", Expr::bytes(resolver)),
        ("registryRoot", Expr::bytes(root)),
        ("nonce", Expr::int(nonce)),
    ])
}

// Keep the eleven-field covenant state ABI explicit and in its fixed order.
#[allow(clippy::too_many_arguments)]
fn child_state(
    kind: i64,
    nonce: i64,
    lo: Vec<u8>,
    hi: Vec<u8>,
    hi_max: i64,
    key: Vec<u8>,
    controller: Vec<u8>,
    target: Vec<u8>,
    target_authority: Vec<u8>,
    policy: Vec<u8>,
    bond: i64,
) -> Expr<'static> {
    struct_object(vec![
        ("objectKind", Expr::int(kind)),
        ("nonce", Expr::int(nonce)),
        ("gapLo", Expr::bytes(lo)),
        ("gapHi", Expr::bytes(hi)),
        ("hiIsMax", Expr::int(hi_max)),
        ("nameKey", Expr::bytes(key)),
        ("controllerCommitment", Expr::bytes(controller)),
        ("targetCommitment", Expr::bytes(target)),
        ("targetAuthorityCommitment", Expr::bytes(target_authority)),
        ("resolverPolicyHash", Expr::bytes(policy)),
        ("bondSompi", Expr::int(bond)),
    ])
}

fn push_data(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x4d, (data.len() & 0xff) as u8, (data.len() >> 8) as u8];
    out.extend_from_slice(data);
    out
}

fn script_public_key_hex(script: &[u8]) -> String {
    let spk = pay_to_script_hash_script(script);
    let mut bytes = spk.version().to_le_bytes().to_vec();
    bytes.extend_from_slice(spk.script());
    hex::encode(bytes)
}

/// Public signatures in the canonical witness argument order. Each includes
/// the trailing SIGHASH_ALL byte; secrets remain in the external signer.
pub struct RegistrationSignatures {
    pub parent: Vec<u8>,
    pub claimant: Vec<u8>,
    pub target: Vec<u8>,
    pub parent_for_child: Vec<u8>,
    pub fee: Vec<u8>,
}

pub fn build_witness(
    value: &Value,
    signatures: Option<&RegistrationSignatures>,
) -> Result<Value, Box<dyn std::error::Error>> {
    if let Some(s) = signatures {
        for signature in [
            &s.parent,
            &s.claimant,
            &s.target,
            &s.parent_for_child,
            &s.fee,
        ] {
            if signature.len() != 65 || signature[64] != 1 {
                return Err(
                    "registration signatures must be 64-byte Schnorr plus SIGHASH_ALL".into(),
                );
            }
        }
    }
    let signature = |select: fn(&RegistrationSignatures) -> &Vec<u8>| {
        signatures
            .map(|s| select(s).clone())
            .unwrap_or_else(|| vec![0; 65])
    };
    let object = value.as_object().ok_or("input must be an object")?;
    // `ktape.official.adapter.registry` 1.0.0 uses the V6 witness layout with adapter sources.
    let adapter = value["schema"] == ADAPTER_REGISTRATION_SCHEMA;
    let named = adapter
        || value["schema"] == "KTAPEOUT-NAMESPACE-REGISTRY-CHILD-REFERENCE-WITNESS-INPUT-V6";
    let mut allowed = vec![
        "schema",
        "network",
        "parent_covenant_id",
        "authority_xonly",
        "namespace_hash",
        "authority_commitment",
        "resolver_policy_hash",
        "registry_root",
        "nonce",
        "gap_lo",
        "gap_hi",
        "gap_hi_is_max",
        "name_key",
        "claimant_xonly",
        "target_commitment",
        "target_authority_xonly",
        "child_resolver_policy_hash",
        "bond_sompi",
    ];
    if named {
        allowed.extend(["namespace_frame", "slug_frame"]);
    }
    if object.len() != allowed.len() || allowed.iter().any(|key| !object.contains_key(*key)) {
        return Err("input contains missing or unexpected fields".into());
    }
    let unsigned_ordering = match value["schema"].as_str() {
        Some("KTAPEOUT-NAMESPACE-REGISTRY-CHILD-REFERENCE-WITNESS-INPUT-V1") => false,
        Some("KTAPEOUT-NAMESPACE-REGISTRY-CHILD-REFERENCE-WITNESS-INPUT-V2") => true,
        Some("KTAPEOUT-NAMESPACE-REGISTRY-CHILD-REFERENCE-WITNESS-INPUT-V3") => true,
        Some("KTAPEOUT-NAMESPACE-REGISTRY-CHILD-REFERENCE-WITNESS-INPUT-V4") => true,
        Some("KTAPEOUT-NAMESPACE-REGISTRY-CHILD-REFERENCE-WITNESS-INPUT-V5") => true,
        Some("KTAPEOUT-NAMESPACE-REGISTRY-CHILD-REFERENCE-WITNESS-INPUT-V6") => true,
        Some(ADAPTER_REGISTRATION_SCHEMA) => true,
        _ => return Err("unsupported witness input schema".into()),
    };
    if value["network"] != "testnet-10" {
        return Err("testnet-10 required".into());
    }

    let parent_covenant_id = nonzero_hex32(&value["parent_covenant_id"], "parent_covenant_id")?;
    let authority_xonly = hex32(&value["authority_xonly"], "authority_xonly")?;
    let namespace_hash = hex32(&value["namespace_hash"], "namespace_hash")?;
    let authority_commitment = hex32(&value["authority_commitment"], "authority_commitment")?;
    let resolver_policy_hash = hex32(&value["resolver_policy_hash"], "resolver_policy_hash")?;
    let registry_root = hex32(&value["registry_root"], "registry_root")?;
    let nonce = nonce_value(&value["nonce"])?;
    let gap_lo = hex32(&value["gap_lo"], "gap_lo")?;
    let gap_hi = hex32(&value["gap_hi"], "gap_hi")?;
    let gap_hi_is_max = nonnegative(&value["gap_hi_is_max"], "gap_hi_is_max")?;
    if gap_hi_is_max > 1 || (gap_hi_is_max == 1 && gap_hi.iter().any(|byte| *byte != 0)) {
        return Err("gap_hi_is_max must be 0/1 and max gaps must encode gap_hi as zero".into());
    }
    if gap_hi_is_max == 0 && gap_lo >= gap_hi {
        return Err("finite gap must satisfy gap_lo < gap_hi".into());
    }
    let name_key = hex32(&value["name_key"], "name_key")?;
    let frames = if named {
        let ns = name_frame::frame(&value["namespace_frame"])?;
        let slug = name_frame::frame(&value["slug_frame"])?;
        if namespace_hash != name_frame::namespace_hash(&ns)
            || name_key != name_frame::name_key(&ns, &slug)
        {
            return Err("canonical frame/hash mismatch".into());
        }
        Some((ns, slug))
    } else {
        None
    };
    let claimant_xonly = hex32(&value["claimant_xonly"], "claimant_xonly")?;
    let target_commitment = hex32(&value["target_commitment"], "target_commitment")?;
    let target_authority_xonly = hex32(&value["target_authority_xonly"], "target_authority_xonly")?;
    let child_resolver_policy_hash = hex32(
        &value["child_resolver_policy_hash"],
        "child_resolver_policy_hash",
    )?;
    let bond_sompi = if adapter {
        let bond = nonnegative(&value["bond_sompi"], "bond_sompi")?;
        if (bond as u64) < child_candidate::REGISTRY_ADAPTER_GAP_FLOOR_SOMPI {
            return Err("adapter app bond must cover the Gap floor".into());
        }
        bond
    } else {
        deed_bond(&value["bond_sompi"])?
    };
    if Sha256::digest(&authority_xonly).as_slice() != authority_commitment {
        return Err("authority_commitment does not match authority_xonly".into());
    }
    if Sha256::digest(&target_authority_xonly).as_slice() == [0u8; 32] {
        return Err("target authority commitment must not be all zero".into());
    }
    let successor_key = increment_be32(&name_key)?;
    let target_authority_commitment = Sha256::digest(&target_authority_xonly).to_vec();
    if gap_lo > name_key || (gap_hi_is_max == 0 && name_key >= gap_hi) {
        return Err("name_key must be inside the supplied half-open gap".into());
    }

    let parent_args = vec![
        Expr::bytes(namespace_hash.clone()),
        Expr::bytes(authority_commitment.clone()),
        Expr::bytes(resolver_policy_hash.clone()),
        Expr::bytes(registry_root.clone()),
        Expr::int(nonce),
    ];
    let v5 =
        named || value["schema"] == "KTAPEOUT-NAMESPACE-REGISTRY-CHILD-REFERENCE-WITNESS-INPUT-V5";
    let slot_parent = if adapter {
        parent_source::source_registry_adapter_parent_v1()
    } else if v5 {
        parent_source::source_recovery_parent_v4()
    } else {
        parent_source::source_slot_parent_v3()
    };
    let v4 =
        v5 || value["schema"] == "KTAPEOUT-NAMESPACE-REGISTRY-CHILD-REFERENCE-WITNESS-INPUT-V4";
    let slot = v4 && gap_lo == name_key && gap_hi == successor_key && gap_hi_is_max == 0;
    let parent = compile_contract(
        if v4 {
            &slot_parent
        } else {
            parent_source::SOURCE_V2
        },
        &parent_args,
        CompileOptions::default(),
    )?;
    let parent_state_end = parent.state_layout.start + parent.state_layout.len;
    let parent_prefix = parent.script[..parent.state_layout.start].to_vec();
    let parent_suffix = parent.script[parent_state_end..].to_vec();
    let parent_state = state(
        namespace_hash.clone(),
        authority_commitment.clone(),
        resolver_policy_hash.clone(),
        registry_root.clone(),
        nonce,
    );
    let mut parent_witness = parent.build_sig_script_for_covenant_decl(
        "authorize_child",
        vec![
            parent_state,
            Expr::bytes(authority_xonly.clone()),
            Expr::bytes(signature(|s| &s.parent)),
        ],
        CovenantDeclCallOptions { is_leader: true },
    )?;
    parent_witness.extend_from_slice(&push_data(&parent.script));

    let zero = vec![0u8; 32];
    let child_source = if adapter {
        child_candidate::source_registry_adapter_app_v1()
    } else if named {
        child_candidate::source_gap_writer_named_recovery_v6()
    } else if v5 {
        child_candidate::source_gap_writer_parent_bootstrap_recovery_v5()
    } else if value["schema"] == "KTAPEOUT-NAMESPACE-REGISTRY-CHILD-REFERENCE-WITNESS-INPUT-V4" {
        child_candidate::source_gap_writer_parent_bootstrap_release_v4()
    } else if value["schema"] == "KTAPEOUT-NAMESPACE-REGISTRY-CHILD-REFERENCE-WITNESS-INPUT-V3" {
        child_candidate::source_gap_writer_parent_bootstrap_lifecycle_v3()
    } else if unsigned_ordering {
        child_candidate::source_gap_writer_parent_bootstrap_unsigned_v2()
    } else {
        child_candidate::source_gap_writer_parent_probe_runtime_lineage_with_fixed_successor()
    };
    let child_constructor = |kind: i64,
                             lo: Vec<u8>,
                             hi: Vec<u8>,
                             hi_max: i64,
                             key: Vec<u8>,
                             controller: Vec<u8>,
                             target: Vec<u8>,
                             target_authority: Vec<u8>,
                             policy: Vec<u8>,
                             bond: i64| {
        vec![
            Expr::int(kind),
            Expr::int(0),
            Expr::bytes(lo),
            Expr::bytes(hi),
            Expr::int(hi_max),
            Expr::bytes(key),
            Expr::bytes(controller),
            Expr::bytes(target),
            Expr::bytes(target_authority),
            Expr::bytes(policy),
            Expr::int(bond),
            Expr::bytes(namespace_hash.clone()),
            Expr::bytes(parent.template_hash().to_vec()),
            Expr::int(parent.state_layout.start as i64),
            Expr::int((parent.script.len() - parent_state_end) as i64),
        ]
    };
    let child_args = child_constructor(
        0,
        gap_lo.clone(),
        gap_hi.clone(),
        gap_hi_is_max,
        zero.clone(),
        zero.clone(),
        zero.clone(),
        zero.clone(),
        zero.clone(),
        0,
    );
    let child = compile_contract(
        &child_source,
        &child_args,
        CompileOptions {
            allow_experimental_u256_successor: true,
            ..Default::default()
        },
    )?;
    if child.script.len() > 10_000 {
        return Err(format!(
            "child candidate exceeds 10,000-byte script budget: {}",
            child.script.len()
        )
        .into());
    }
    let left = compile_contract(
        &child_source,
        &child_constructor(
            0,
            gap_lo.clone(),
            name_key.clone(),
            0,
            zero.clone(),
            zero.clone(),
            zero.clone(),
            zero.clone(),
            zero.clone(),
            0,
        ),
        CompileOptions {
            allow_experimental_u256_successor: true,
            ..Default::default()
        },
    )?;
    // Adapter deeds store their own interval [key, key+1); earlier versions keep zero Gap fields.
    let (deed_lo, deed_hi) = if adapter {
        (name_key.clone(), successor_key.clone())
    } else {
        (zero.clone(), zero.clone())
    };
    let deed = compile_contract(
        &child_source,
        &child_constructor(
            1,
            deed_lo.clone(),
            deed_hi.clone(),
            0,
            name_key.clone(),
            Sha256::digest(&claimant_xonly).to_vec(),
            target_commitment.clone(),
            target_authority_commitment.clone(),
            child_resolver_policy_hash.clone(),
            bond_sompi,
        ),
        CompileOptions {
            allow_experimental_u256_successor: true,
            ..Default::default()
        },
    )?;
    let right = compile_contract(
        &child_source,
        &child_constructor(
            0,
            successor_key.clone(),
            gap_hi.clone(),
            gap_hi_is_max,
            zero.clone(),
            zero.clone(),
            zero.clone(),
            zero.clone(),
            zero.clone(),
            0,
        ),
        CompileOptions {
            allow_experimental_u256_successor: true,
            ..Default::default()
        },
    )?;
    for (role, contract) in [
        ("left_gap", &left),
        ("name_deed", &deed),
        ("right_gap", &right),
    ] {
        if contract.script.len() > 10_000 {
            return Err(format!(
                "{role} candidate exceeds 10,000-byte script budget: {}",
                contract.script.len()
            )
            .into());
        }
    }
    let mut next_states = Expr::new(
        silverscript_lang::ast::ExprKind::Array(vec![
            child_state(
                0,
                0,
                gap_lo,
                name_key.clone(),
                0,
                zero.clone(),
                zero.clone(),
                zero.clone(),
                zero.clone(),
                zero.clone(),
                0,
            ),
            child_state(
                1,
                0,
                deed_lo.clone(),
                deed_hi.clone(),
                0,
                name_key.clone(),
                Sha256::digest(&claimant_xonly).to_vec(),
                target_commitment.clone(),
                target_authority_commitment,
                child_resolver_policy_hash.clone(),
                bond_sompi,
            ),
            child_state(
                0,
                0,
                successor_key.clone(),
                gap_hi,
                gap_hi_is_max,
                zero.clone(),
                zero.clone(),
                zero.clone(),
                zero.clone(),
                zero.clone(),
                0,
            ),
        ]),
        Default::default(),
    );
    if slot {
        next_states = Expr::new(
            silverscript_lang::ast::ExprKind::Array(vec![child_state(
                1,
                0,
                deed_lo.clone(),
                deed_hi.clone(),
                0,
                name_key.clone(),
                Sha256::digest(&claimant_xonly).to_vec(),
                target_commitment.clone(),
                Sha256::digest(&target_authority_xonly).to_vec(),
                child_resolver_policy_hash.clone(),
                bond_sompi,
            )]),
            Default::default(),
        );
    }
    let owner_state_args = json!([
        1,
        0,
        hex::encode(&deed_lo),
        hex::encode(&deed_hi),
        0,
        hex::encode(&name_key),
        hex::encode(Sha256::digest(&claimant_xonly)),
        hex::encode(&target_commitment),
        hex::encode(Sha256::digest(&target_authority_xonly)),
        hex::encode(&child_resolver_policy_hash),
        bond_sompi,
        hex::encode(&namespace_hash),
        hex::encode(parent.template_hash()),
        parent.state_layout.start,
        parent.script.len() - parent_state_end
    ]);
    let mut child_args_witness = vec![
        next_states,
        Expr::bytes(signature(|s| &s.claimant)),
        Expr::bytes(claimant_xonly),
        Expr::bytes(signature(|s| &s.target)),
        Expr::bytes(target_authority_xonly),
        Expr::bytes(name_key),
        Expr::bytes(target_commitment),
        Expr::bytes(child_resolver_policy_hash),
        Expr::int(bond_sompi),
        Expr::bytes(successor_key),
        Expr::bytes(signature(|s| &s.parent_for_child)),
        Expr::bytes(authority_xonly),
        Expr::int(0),
        Expr::int(0),
        Expr::bytes(parent_prefix),
        Expr::bytes(parent_suffix),
    ];
    if let Some((namespace, slug)) = frames {
        child_args_witness.splice(6..6, [Expr::bytes(namespace), Expr::bytes(slug)]);
    }
    let mut child_witness = child.build_sig_script_for_covenant_decl(
        "register_interior",
        child_args_witness,
        CovenantDeclCallOptions { is_leader: false },
    )?;
    child_witness.extend_from_slice(&push_data(&child.script));

    let fee_placeholder = signatures
        .map(|s| {
            let mut script = vec![65];
            script.extend_from_slice(&s.fee);
            script
        })
        .unwrap_or_else(|| vec![0x51]);
    let mut response = json!({
        "schema": SCHEMA,
        "network": "testnet-10",
        "parent_covenant_id": hex::encode(&parent_covenant_id),
        "contract": if named {contract::named_metadata()} else if v5 { contract::recovery_metadata() } else { contract::metadata() },
        "parent_template_hash": hex::encode(parent.template_hash()),
        "child_template_hash": hex::encode(child.template_hash()),
        "state_input_script_public_keys": {
            "parent": script_public_key_hex(&parent.script),
            "gap": script_public_key_hex(&child.script)
        },
        "signature_material_supplied": signatures.is_some(),
        "input_signature_scripts": [hex::encode(&parent_witness), hex::encode(&child_witness), hex::encode(&fee_placeholder)],
        "witness_bytes": {"parent": parent_witness.len(), "child": child_witness.len(), "fee": fee_placeholder.len()},
        "compiled_script_bytes": {"parent": parent.script.len(), "child": child.script.len()},
        "candidate_state_layout": state_layout::candidate_state_layout(true),
        "script_budget": {"limit_bytes": 10000, "child_headroom_bytes": 10000usize.saturating_sub(child.script.len()), "child_headroom_warning": child.script.len() > 9744},
        "state_output_script_public_keys": {
            "parent_successor": script_public_key_hex(&parent.script),
            "left_gap": script_public_key_hex(&left.script),
            "name_deed": script_public_key_hex(&deed.script),
            "right_gap": script_public_key_hex(&right.script)
        },
        "transition": "authorize_child + register_interior",
        "status": if signatures.is_some() { "SIGNATURES_ASSEMBLED_VM_UNVERIFIED" } else { "UNSIGNED_LOCAL_REFERENCE" },
        "signing_allowed": false,
        "broadcast": false,
        "missing_evidence": ["canonical_child_codec", "state_witness_codec", "live_mass_value_receipt", "tn10_readback", "deployment_tuple", "formal_profile_admission"]
    });
    if value["schema"] == "KTAPEOUT-NAMESPACE-REGISTRY-CHILD-REFERENCE-WITNESS-INPUT-V3" || v4 {
        response["owner_state_args"] = owner_state_args;
    }
    if adapter {
        response["schema"] = json!("KTAPEOUT-REGISTRY-ADAPTER-APP-REGISTRATION-WITNESS-V1");
        response["adapter_id"] = json!("ktape.official.adapter.registry");
        response["adapter_semver"] = json!("1.0.0");
        // The registrant's fee input funds the bond, the second Gap floor and the fee.
        response["value_rule"] = json!({"gap_capital":"LEFT_PLUS_RIGHT_AT_LEAST_INPUT_GAP","gap_floor_sompi":child_candidate::REGISTRY_ADAPTER_GAP_FLOOR_SOMPI,"min_app_bond_sompi":child_candidate::REGISTRY_ADAPTER_GAP_FLOOR_SOMPI});
    }
    if v4 {
        response["registration_kind"] = json!(if slot { "SLOT" } else { "INTERIOR" });
        if slot {
            let outputs = response["state_output_script_public_keys"]
                .as_object_mut()
                .ok_or("output script object required")?;
            outputs.remove("left_gap");
            outputs.remove("right_gap");
        }
    }
    Ok(response)
}

pub fn build_parent_transfer_witness(
    value: &Value,
    signatures: Option<&Value>,
) -> Result<Value, Box<dyn std::error::Error>> {
    let named = value["schema"] == "KTAPEOUT-NAMESPACE-PARENT-TRANSFER-WITNESS-INPUT-V6";
    let fields = [
        "schema",
        "network",
        "parent_covenant_id",
        "authority_xonly",
        "next_authority_xonly",
        "namespace_hash",
        "authority_commitment",
        "resolver_policy_hash",
        "registry_root",
        "nonce",
    ];
    let object = value
        .as_object()
        .ok_or("parent transfer input must be an object")?;
    if object.len() != fields.len() || fields.iter().any(|key| !object.contains_key(*key)) {
        return Err("parent transfer fields are not canonical".into());
    }
    if (!named && value["schema"] != "KTAPEOUT-NAMESPACE-PARENT-TRANSFER-WITNESS-INPUT-V2")
        || value["network"] != "testnet-10"
    {
        return Err("versioned TN10 parent transfer input required".into());
    }
    let cid = nonzero_hex32(&value["parent_covenant_id"], "parent_covenant_id")?;
    let current = hex32(&value["authority_xonly"], "authority_xonly")?;
    let next = hex32(&value["next_authority_xonly"], "next_authority_xonly")?;
    secp256k1::XOnlyPublicKey::from_slice(&current)?;
    secp256k1::XOnlyPublicKey::from_slice(&next)?;
    let commitment = hex32(&value["authority_commitment"], "authority_commitment")?;
    if commitment != Sha256::digest(&current).to_vec() {
        return Err("current authority commitment mismatch".into());
    }
    let namespace = hex32(&value["namespace_hash"], "namespace_hash")?;
    let resolver = hex32(&value["resolver_policy_hash"], "resolver_policy_hash")?;
    let root = hex32(&value["registry_root"], "registry_root")?;
    let nonce = nonce_value(&value["nonce"])?;
    let next_commitment = Sha256::digest(&next).to_vec();
    let source = if named {
        parent_source::source_recovery_parent_v4()
    } else {
        parent_source::SOURCE_V2.to_string()
    };
    let compile = |authority: Vec<u8>, nonce: i64| {
        compile_contract(
            &source,
            &[
                Expr::bytes(namespace.clone()),
                Expr::bytes(authority),
                Expr::bytes(resolver.clone()),
                Expr::bytes(root.clone()),
                Expr::int(nonce),
            ],
            CompileOptions::default(),
        )
    };
    let parent = compile(commitment, nonce)?;
    let successor = compile(next_commitment.clone(), nonce + 1)?;
    let mut parent_sig = vec![0; 65];
    let mut fee_script = vec![0x51];
    if let Some(signatures) = signatures {
        let object = signatures.as_object().ok_or("signature object required")?;
        if object.len() != 2 || !object.contains_key("parent") || !object.contains_key("fee") {
            return Err("exact parent/fee signature fields required".into());
        }
        let decode = |field: &str| -> Result<Vec<u8>, Box<dyn std::error::Error>> {
            let text = signatures[field].as_str().ok_or("signature must be hex")?;
            let bytes = hex::decode(text)?;
            if hex::encode(&bytes) != text || bytes.len() != 65 || bytes[64] != 1 {
                return Err("64-byte Schnorr plus SIGHASH_ALL required".into());
            }
            Ok(bytes)
        };
        parent_sig = decode("parent")?;
        fee_script = vec![65];
        fee_script.extend_from_slice(&decode("fee")?);
    }
    let mut witness = parent.build_sig_script_for_covenant_decl(
        "transfer_authority",
        vec![
            state(namespace, next_commitment, resolver, root, nonce + 1),
            Expr::bytes(current),
            Expr::bytes(next),
            Expr::bytes(parent_sig),
        ],
        CovenantDeclCallOptions { is_leader: true },
    )?;
    witness.extend_from_slice(&push_data(&parent.script));
    Ok(
        json!({"schema":if named {"KTAPEOUT-NAMESPACE-PARENT-TRANSFER-WITNESS-V6"}else{"KTAPEOUT-NAMESPACE-PARENT-TRANSFER-WITNESS-V2"}, "network":"testnet-10",
        "codec_id":"namespace-parent-authority-transfer-candidate-v2", "parent_covenant_id":hex::encode(cid),
        "state_input_script_public_key":script_public_key_hex(&parent.script),
        "parent_successor_script_public_key":script_public_key_hex(&successor.script),
        "input_signature_scripts":[hex::encode(witness), hex::encode(fee_script)],
        "nonce":nonce, "successor_nonce":nonce+1, "compiled_script_bytes":parent.script.len(),
        "status":"ENGINEERING_CANDIDATE_ONLY", "signing_allowed":false, "broadcast":false}),
    )
}

pub fn build_owner_operation_witness(
    value: &Value,
    signatures: Option<&Value>,
) -> Result<Value, Box<dyn std::error::Error>> {
    let adapter = value["schema"] == ADAPTER_OWNER_SCHEMA;
    let named = adapter || value["schema"] == "KTAPEOUT-NAMESPACE-CHILD-OWNER-WITNESS-INPUT-V6";
    let recovery_version =
        named || value["schema"] == "KTAPEOUT-NAMESPACE-CHILD-OWNER-WITNESS-INPUT-V5";
    let release_version =
        recovery_version || value["schema"] == "KTAPEOUT-NAMESPACE-CHILD-OWNER-WITNESS-INPUT-V4";
    let operation = value["operation"]
        .as_str()
        .ok_or("owner operation required")?;
    let release = operation == "RELEASE_NAME" && release_version;
    let exit = match operation {
        "CHANGE_OWNER_TARGET" => false,
        "OWNER_EXIT" if !release_version => true,
        "RELEASE_NAME" if release_version => true,
        _ => return Err("unsupported owner operation".into()),
    };
    let mut fields = vec![
        "schema",
        "network",
        "operation",
        "parent_covenant_id",
        "state_args",
        "owner_xonly",
    ];
    if exit {
        fields.push("refund_script_public_key");
    } else {
        fields.extend([
            "next_owner_xonly",
            "target_authority_xonly",
            "next_target_commitment",
            "next_resolver_policy_hash",
        ]);
    }
    let object = value.as_object().ok_or("owner input object required")?;
    if object.len() != fields.len() || fields.iter().any(|key| !object.contains_key(*key)) {
        return Err("owner witness fields are not canonical".into());
    }
    if (!release_version && value["schema"] != "KTAPEOUT-NAMESPACE-CHILD-OWNER-WITNESS-INPUT-V3")
        || value["network"] != "testnet-10"
    {
        return Err("versioned TN10 owner input required".into());
    }
    let cid = nonzero_hex32(&value["parent_covenant_id"], "parent_covenant_id")?;
    let state = value["state_args"]
        .as_array()
        .filter(|args| args.len() == 15)
        .ok_or("15 exact V3 constructor arguments required")?;
    let mut args = Vec::new();
    for (index, item) in state.iter().enumerate() {
        args.push(if [0, 1, 4, 10, 13, 14].contains(&index) {
            Expr::int(
                item.as_i64()
                    .filter(|n| *n >= 0)
                    .ok_or("nonnegative state integer required")?,
            )
        } else {
            Expr::bytes(hex32(item, "state hash")?)
        });
    }
    let nonce = state[1].as_i64().ok_or("nonce integer required")?;
    if adapter {
        let key = hex32(&state[5], "name_key")?;
        if state[0] != 1
            || state[4] != 0
            || state[2] != hex::encode(&key)
            || state[3] != hex::encode(increment_be32(&key)?)
            || (state[10].as_i64().unwrap() as u64)
                < child_candidate::REGISTRY_ADAPTER_GAP_FLOOR_SOMPI
        {
            return Err("canonical adapter Deed state required".into());
        }
    } else if state[0] != 1
        || state[4] != 0
        || state[2] != "00".repeat(32)
        || state[3] != "00".repeat(32)
        || state[10].as_i64().unwrap() < MIN_DEED_BOND_SOMPI
    {
        return Err("canonical Deed state required".into());
    }
    if !exit && nonce == i64::MAX {
        return Err("owner update nonce overflow".into());
    }
    let owner = hex32(&value["owner_xonly"], "owner_xonly")?;
    secp256k1::XOnlyPublicKey::from_slice(&owner)?;
    if hex::encode(Sha256::digest(&owner)) != state[6] {
        return Err("owner commitment mismatch".into());
    }
    let target_changes = !exit
        && (value["next_target_commitment"] != state[7]
            || value["next_resolver_policy_hash"] != state[9]
            || hex::encode(Sha256::digest(hex32(
                &value["target_authority_xonly"],
                "target authority",
            )?)) != state[8]);
    let signature_fields = if exit || (named && !target_changes) {
        vec!["owner", "fee"]
    } else {
        vec!["owner", "target", "fee"]
    };
    if let Some(s) = signatures {
        let map = s.as_object().ok_or("signature object required")?;
        if map.len() != signature_fields.len()
            || signature_fields.iter().any(|key| !map.contains_key(*key))
        {
            return Err("exact owner operation signature fields required".into());
        }
    }
    let signature = |field: &str| -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if named && field == "target" && !target_changes {
            return Ok(vec![0; 65]);
        }
        if let Some(s) = signatures {
            let text = s[field]
                .as_str()
                .ok_or("canonical public signature required")?;
            if text.len() != 130 {
                return Err("65-byte public signature required".into());
            }
            let bytes = hex::decode(text)?;
            if hex::encode(&bytes) != text || bytes[64] != 1 {
                return Err("Schnorr plus SIGHASH_ALL required".into());
            }
            Ok(bytes)
        } else {
            Ok(vec![0; 65])
        }
    };
    let source = if adapter {
        child_candidate::source_registry_adapter_app_v1()
    } else if named {
        child_candidate::source_gap_writer_named_recovery_v6()
    } else if recovery_version {
        child_candidate::source_gap_writer_parent_bootstrap_recovery_v5()
    } else if release_version {
        child_candidate::source_gap_writer_parent_bootstrap_release_v4()
    } else {
        child_candidate::source_gap_writer_parent_bootstrap_lifecycle_v3()
    };
    let options = CompileOptions {
        allow_experimental_u256_successor: true,
        ..Default::default()
    };
    let active = compile_contract(&source, &args, options)?;
    let mut required = vec!["owner", "fee"];
    let (mut witness, successor_spk, next_state) = if release {
        let refund = native_owner_spk(&value["refund_script_public_key"])?;
        let zero = vec![0; 32];
        let key = hex32(&state[5], "name_key")?;
        let upper = increment_be32(&key)?;
        let mut next = args.clone();
        next[0] = Expr::int(0);
        next[1] = Expr::int(0);
        next[2] = Expr::bytes(key.clone());
        next[3] = Expr::bytes(upper.clone());
        for i in [5, 6, 7, 8, 9] {
            next[i] = Expr::bytes(zero.clone());
        }
        next[10] = Expr::int(0);
        let gap = compile_contract(&source, &next, options)?;
        let mut next_json = state.clone();
        next_json[0] = json!(0);
        next_json[1] = json!(0);
        next_json[2] = json!(hex::encode(&key));
        next_json[3] = json!(hex::encode(&upper));
        for i in [5, 6, 7, 8, 9] {
            next_json[i] = json!(hex::encode(&zero));
        }
        next_json[10] = json!(0);
        let next_state = child_state(
            0,
            0,
            key,
            upper,
            0,
            zero.clone(),
            zero.clone(),
            zero.clone(),
            zero.clone(),
            zero,
            0,
        );
        (
            active.build_sig_script_for_covenant_decl(
                "release_name",
                vec![
                    next_state,
                    Expr::bytes(signature("owner")?),
                    Expr::bytes(owner),
                    Expr::bytes(Sha256::digest(refund).to_vec()),
                ],
                CovenantDeclCallOptions { is_leader: true },
            )?,
            script_public_key_hex(&gap.script),
            json!(next_json),
        )
    } else if exit {
        let spk = native_owner_spk(&value["refund_script_public_key"])?;
        let hash = Sha256::digest(&spk).to_vec();
        (
            active.build_sig_script(
                "owner_exit",
                vec![
                    Expr::bytes(signature("owner")?),
                    Expr::bytes(owner),
                    Expr::bytes(hash),
                ],
            )?,
            hex::encode(spk),
            Value::Null,
        )
    } else {
        let next_owner = hex32(&value["next_owner_xonly"], "next_owner_xonly")?;
        secp256k1::XOnlyPublicKey::from_slice(&next_owner)?;
        let next_target = hex32(&value["target_authority_xonly"], "target_authority_xonly")?;
        secp256k1::XOnlyPublicKey::from_slice(&next_target)?;
        let target = hex32(&value["next_target_commitment"], "next_target_commitment")?;
        let policy = hex32(
            &value["next_resolver_policy_hash"],
            "next_resolver_policy_hash",
        )?;
        let controller = Sha256::digest(&next_owner).to_vec();
        let target_authority = Sha256::digest(&next_target).to_vec();
        if hex::encode(&target) != state[7]
            || hex::encode(&target_authority) != state[8]
            || hex::encode(&policy) != state[9]
        {
            required.push("target");
        }
        let mut next_args = args.clone();
        next_args[1] = Expr::int(nonce + 1);
        next_args[6] = Expr::bytes(controller.clone());
        next_args[7] = Expr::bytes(target.clone());
        next_args[8] = Expr::bytes(target_authority.clone());
        next_args[9] = Expr::bytes(policy.clone());
        let successor = compile_contract(&source, &next_args, options)?;
        let mut next_json = state.clone();
        next_json[1] = json!(nonce + 1);
        next_json[6] = json!(hex::encode(&controller));
        next_json[7] = json!(hex::encode(&target));
        next_json[8] = json!(hex::encode(&target_authority));
        next_json[9] = json!(hex::encode(&policy));
        // Adapter deeds keep their stored interval across owner/target changes.
        let (keep_lo, keep_hi) = if adapter {
            (hex32(&state[2], "deed_lo")?, hex32(&state[3], "deed_hi")?)
        } else {
            (vec![0; 32], vec![0; 32])
        };
        let next_state = child_state(
            1,
            nonce + 1,
            keep_lo,
            keep_hi,
            0,
            hex32(&state[5], "name_key")?,
            controller,
            target,
            target_authority,
            policy,
            state[10].as_i64().unwrap(),
        );
        (
            active.build_sig_script_for_covenant_decl(
                "change_owner_target",
                vec![
                    next_state,
                    Expr::bytes(signature("owner")?),
                    Expr::bytes(owner),
                    Expr::bytes(next_owner),
                    Expr::bytes(signature("target")?),
                    Expr::bytes(next_target),
                ],
                CovenantDeclCallOptions { is_leader: true },
            )?,
            script_public_key_hex(&successor.script),
            json!(next_json),
        )
    };
    if active.script.len() > 10_000 {
        return Err("owner candidate exceeds script budget".into());
    }
    witness.extend_from_slice(&push_data(&active.script));
    let fee_script = if signatures.is_some() {
        [vec![65], signature("fee")?].concat()
    } else {
        vec![0x51]
    };
    let mut result = json!({"schema":if recovery_version {"KTAPEOUT-NAMESPACE-CHILD-OWNER-WITNESS-V5"}else if release_version {"KTAPEOUT-NAMESPACE-CHILD-OWNER-WITNESS-V4"} else {"KTAPEOUT-NAMESPACE-CHILD-OWNER-WITNESS-V3"},"network":"testnet-10","operation":operation,
        "parent_covenant_id":hex::encode(cid),"state_input_script_public_key":script_public_key_hex(&active.script),
        "state_successor_script_public_key":successor_spk,"input_signature_scripts":[hex::encode(witness),hex::encode(fee_script)],
        "successor_state_args":next_state,"required_signature_roles":required,"compiled_script_bytes":active.script.len(),
        "template_hash":hex::encode(active.template_hash()),"status":"LOCAL_ONLY_LIFECYCLE_CANDIDATE","signing_allowed":false,"broadcast":false});
    if recovery_version {
        result["contract"] = contract::recovery_metadata();
    }
    if named {
        result["schema"] = json!("KTAPEOUT-NAMESPACE-CHILD-OWNER-WITNESS-V6");
        result["contract"] = contract::named_metadata();
    }
    if adapter {
        result["schema"] = json!("KTAPEOUT-REGISTRY-ADAPTER-APP-OWNER-WITNESS-V1");
        result["adapter_id"] = json!("ktape.official.adapter.registry");
        result["adapter_semver"] = json!("1.0.0");
        // Adapter release refunds the whole bond; the fee input funds the new single-key Gap floor.
        if release {
            result["value_rule"] = json!({"released_gap_sompi":child_candidate::REGISTRY_ADAPTER_GAP_FLOOR_SOMPI,"refund_sompi":"EQUALS_DEED_INPUT_VALUE"});
        }
    }
    if release {
        result["refund_script_public_key"] = value["refund_script_public_key"].clone();
    }
    Ok(result)
}

pub fn build_recovery_witness(
    value: &Value,
    signatures: Option<&Value>,
) -> Result<Value, Box<dyn std::error::Error>> {
    let adapter = value["schema"] == ADAPTER_RECOVERY_SCHEMA;
    let named = adapter || value["schema"] == "KTAPEOUT-NAMESPACE-RECOVERY-WITNESS-INPUT-V6";
    let close = match value["operation"].as_str() {
        Some("MERGE_GAPS") => false,
        Some("CLOSE_NAMESPACE") => true,
        _ => return Err("recovery operation required".into()),
    };
    if adapter && close {
        return Err("adapter namespaces close only through RELEASE_NAMESPACE (namespace_issuance_v1_plan), which also releases the certificate".into());
    }
    let mut fields = vec!["schema", "network", "operation", "parent_covenant_id"];
    if close {
        fields.extend([
            "gap_state_args",
            "parent_state_args",
            "authority_xonly",
            "refund_script_public_key",
        ]);
    } else {
        fields.extend(["left_state_args", "right_state_args"]);
    }
    let object = value.as_object().ok_or("recovery object required")?;
    if object.len() != fields.len()
        || fields.iter().any(|k| !object.contains_key(*k))
        || (!named && value["schema"] != "KTAPEOUT-NAMESPACE-RECOVERY-WITNESS-INPUT-V5")
        || value["network"] != "testnet-10"
    {
        return Err("exact TN10 recovery fields required".into());
    }
    let cid = nonzero_hex32(&value["parent_covenant_id"], "parent_covenant_id")?;
    let roles = if close {
        vec!["parent", "gap", "fee"]
    } else {
        vec!["fee"]
    };
    if let Some(s) = signatures {
        let map = s.as_object().ok_or("signature object required")?;
        if map.len() != roles.len() || roles.iter().any(|k| !map.contains_key(*k)) {
            return Err("exact recovery signature roles required".into());
        }
    }
    let signature = |role: &str| -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if let Some(s) = signatures {
            let text = s[role].as_str().ok_or("public signature required")?;
            let raw = hex::decode(text)?;
            if raw.len() != 65 || raw[64] != 1 || hex::encode(&raw) != text {
                return Err("canonical Schnorr plus SIGHASH_ALL required".into());
            }
            Ok(raw)
        } else {
            Ok(vec![0; 65])
        }
    };
    let parse_gap =
        |v: &Value| -> Result<(Vec<Value>, Vec<Expr<'static>>), Box<dyn std::error::Error>> {
            let state = v
                .as_array()
                .filter(|a| a.len() == 15)
                .ok_or("15 exact Gap constructor arguments required")?
                .clone();
            let mut args = vec![];
            for (i, item) in state.iter().enumerate() {
                args.push(if [0, 1, 4, 10, 13, 14].contains(&i) {
                    Expr::int(nonnegative(item, "Gap integer")?)
                } else {
                    Expr::bytes(hex32(item, "Gap hash")?)
                });
            }
            if state[0] != 0
                || state[1] != 0
                || state[10] != 0
                || ![5, 6, 7, 8, 9].iter().all(|i| state[*i] == "00".repeat(32))
                || !(state[4] == 0 || state[4] == 1)
            {
                return Err("canonical Gap required".into());
            }
            if (state[4] == 1 && state[3] != "00".repeat(32))
                || (state[4] == 0 && state[2].as_str() > state[3].as_str())
            {
                return Err("invalid Gap interval".into());
            }
            Ok((state, args))
        };
    let source = if adapter {
        child_candidate::source_registry_adapter_app_v1()
    } else if named {
        child_candidate::source_gap_writer_named_recovery_v6()
    } else {
        child_candidate::source_gap_writer_parent_bootstrap_recovery_v5()
    };
    let options = CompileOptions {
        allow_experimental_u256_successor: true,
        ..Default::default()
    };
    let append = |mut witness: Vec<u8>, script: &[u8]| {
        witness.extend_from_slice(&push_data(script));
        hex::encode(witness)
    };
    let (input_spks, scripts, output_spk, next_state, script_bytes) = if close {
        let (gap_state, gap_args) = parse_gap(&value["gap_state_args"])?;
        if gap_state[2] != "00".repeat(32) || gap_state[4] != 1 {
            return Err("namespace close requires full empty keyspace".into());
        }
        let p = value["parent_state_args"]
            .as_array()
            .filter(|a| a.len() == 5)
            .ok_or("five parent constructor arguments required")?;
        let mut parent_args = vec![];
        for (i, item) in p.iter().enumerate() {
            parent_args.push(if i == 4 {
                Expr::int(nonnegative(item, "parent nonce")?)
            } else {
                Expr::bytes(hex32(item, "parent hash")?)
            });
        }
        let authority = hex32(&value["authority_xonly"], "authority_xonly")?;
        secp256k1::XOnlyPublicKey::from_slice(&authority)?;
        if p[1] != hex::encode(Sha256::digest(&authority)) || p[0] != gap_state[11] {
            return Err("parent authority/namespace mismatch".into());
        }
        let parent_source = parent_source::source_recovery_parent_v4();
        let parent = compile_contract(&parent_source, &parent_args, CompileOptions::default())?;
        if gap_state[12] != hex::encode(parent.template_hash())
            || gap_state[13] != json!(parent.state_layout.start)
            || gap_state[14]
                != json!(parent.script.len() - parent.state_layout.start - parent.state_layout.len)
        {
            return Err("Gap parent template/layout mismatch".into());
        }
        let gap = compile_contract(&source, &gap_args, options)?;
        if gap.script.len() > 10000 {
            return Err("recovery Gap exceeds script budget".into());
        }
        let refund = native_owner_spk(&value["refund_script_public_key"])?;
        let hash = Sha256::digest(&refund).to_vec();
        let a = parent.build_sig_script(
            "close_namespace",
            vec![
                Expr::bytes(signature("parent")?),
                Expr::bytes(authority.clone()),
                Expr::bytes(hash.clone()),
            ],
        )?;
        let b = gap.build_sig_script(
            "retire_namespace",
            vec![
                Expr::bytes(signature("gap")?),
                Expr::bytes(authority),
                Expr::bytes(hash),
            ],
        )?;
        (
            vec![
                script_public_key_hex(&parent.script),
                script_public_key_hex(&gap.script),
            ],
            vec![append(a, &parent.script), append(b, &gap.script)],
            hex::encode(refund),
            Value::Null,
            json!([parent.script.len(), gap.script.len()]),
        )
    } else {
        let (left_state, left_args) = parse_gap(&value["left_state_args"])?;
        let (right_state, right_args) = parse_gap(&value["right_state_args"])?;
        if left_state[4] != 0
            || left_state[3] != right_state[2]
            || left_state[11..] != right_state[11..]
        {
            return Err("adjacent same-template Gaps required".into());
        }
        let mut next = left_state.clone();
        next[3] = right_state[3].clone();
        next[4] = right_state[4].clone();
        let mut next_args = left_args.clone();
        next_args[3] = right_args[3].clone();
        next_args[4] = right_args[4].clone();
        let left = compile_contract(&source, &left_args, options)?;
        let right = compile_contract(&source, &right_args, options)?;
        let merged = compile_contract(&source, &next_args, options)?;
        if [left.script.len(), right.script.len(), merged.script.len()]
            .iter()
            .any(|n| *n > 10000)
        {
            return Err("recovery template exceeds script budget".into());
        }
        let state = child_state(
            0,
            0,
            hex32(&next[2], "lo")?,
            hex32(&next[3], "hi")?,
            next[4].as_i64().unwrap(),
            vec![0; 32],
            vec![0; 32],
            vec![0; 32],
            vec![0; 32],
            vec![0; 32],
            0,
        );
        let a = left.build_sig_script("merge_gaps", vec![state.clone()])?;
        let b = right.build_sig_script("merge_gaps", vec![state])?;
        (
            vec![
                script_public_key_hex(&left.script),
                script_public_key_hex(&right.script),
            ],
            vec![append(a, &left.script), append(b, &right.script)],
            script_public_key_hex(&merged.script),
            json!(next),
            json!([left.script.len(), right.script.len()]),
        )
    };
    let fee = if signatures.is_some() {
        hex::encode([vec![65], signature("fee")?].concat())
    } else {
        "51".into()
    };
    let mut scripts = scripts;
    scripts.push(fee);
    Ok(
        json!({"schema":if named {"KTAPEOUT-NAMESPACE-RECOVERY-WITNESS-V6"}else{"KTAPEOUT-NAMESPACE-RECOVERY-WITNESS-V5"},"contract":if named {contract::named_metadata()}else{contract::recovery_metadata()},"network":"testnet-10","operation":value["operation"],"parent_covenant_id":hex::encode(cid),"state_input_script_public_keys":input_spks,"state_successor_script_public_key":output_spk,"input_signature_scripts":scripts,"successor_state_args":next_state,"required_signature_roles":roles,"compiled_script_bytes":script_bytes,"broadcast":false,"signing_allowed":false,"l1_evidence":false}),
    )
}

fn native_owner_spk(value: &Value) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let text = value.as_str().ok_or("canonical refund SPK required")?;
    if text.len() < 6 || text.len() > 20004 {
        return Err("refund SPK outside bounds".into());
    }
    let raw = hex::decode(text)?;
    if hex::encode(&raw) != text || raw[0] != 0 || raw[1] != 0 {
        return Err("canonical version-0 refund SPK required".into());
    }
    Ok(raw)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if !(args.len() == 2 || (args.len() == 4 && args[2] == "--signatures")) || args[0] != "--input"
    {
        return Err("usage: namespace_registry_child_registration_reference_witness --input PUBLIC.json [--signatures PUBLIC_SIGNATURES.json]".into());
    }
    use std::io::Read;
    let mut raw = Vec::new();
    std::fs::File::open(&args[1])?
        .take((MAX_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut raw)?;
    if raw.len() > MAX_INPUT_BYTES {
        return Err("public witness input exceeds 64 KiB".into());
    }
    let value: Value = bounded_public_json::parse(&raw)?;
    if matches!(
        value["schema"].as_str(),
        Some(
            "KTAPEOUT-NAMESPACE-PARENT-TRANSFER-WITNESS-INPUT-V2"
                | "KTAPEOUT-NAMESPACE-PARENT-TRANSFER-WITNESS-INPUT-V6"
                | "KTAPEOUT-NAMESPACE-CHILD-OWNER-WITNESS-INPUT-V3"
                | "KTAPEOUT-NAMESPACE-CHILD-OWNER-WITNESS-INPUT-V4"
                | "KTAPEOUT-NAMESPACE-CHILD-OWNER-WITNESS-INPUT-V5"
                | "KTAPEOUT-NAMESPACE-CHILD-OWNER-WITNESS-INPUT-V6"
                | "KTAPEOUT-NAMESPACE-RECOVERY-WITNESS-INPUT-V5"
                | "KTAPEOUT-NAMESPACE-RECOVERY-WITNESS-INPUT-V6"
        )
    ) {
        let signatures = if args.len() == 4 {
            use std::io::Read;
            let mut raw = Vec::new();
            std::fs::File::open(&args[3])?
                .take(4097)
                .read_to_end(&mut raw)?;
            if raw.len() > 4096 {
                return Err("signature file exceeds 4 KiB".into());
            }
            Some(bounded_public_json::parse(&raw)?)
        } else {
            None
        };
        let result = if matches!(
            value["schema"].as_str(),
            Some(
                "KTAPEOUT-NAMESPACE-RECOVERY-WITNESS-INPUT-V5"
                    | "KTAPEOUT-NAMESPACE-RECOVERY-WITNESS-INPUT-V6"
            )
        ) {
            build_recovery_witness(&value, signatures.as_ref())?
        } else if matches!(
            value["schema"].as_str(),
            Some(
                "KTAPEOUT-NAMESPACE-PARENT-TRANSFER-WITNESS-INPUT-V2"
                    | "KTAPEOUT-NAMESPACE-PARENT-TRANSFER-WITNESS-INPUT-V6"
            )
        ) {
            build_parent_transfer_witness(&value, signatures.as_ref())?
        } else {
            build_owner_operation_witness(&value, signatures.as_ref())?
        };
        println!("{}", serde_json::to_string(&result)?);
        return Ok(());
    }
    let signatures = if args.len() == 4 {
        use std::io::Read;
        let mut raw = Vec::new();
        std::fs::File::open(&args[3])?
            .take(4097)
            .read_to_end(&mut raw)?;
        if raw.len() > 4096 {
            return Err("signature file exceeds 4 KiB".into());
        }
        let object: Value = bounded_public_json::parse(&raw)?;
        let fields = ["parent", "claimant", "target", "parent_for_child", "fee"];
        let map = object.as_object().ok_or("signature object required")?;
        if map.len() != fields.len() || fields.iter().any(|field| !map.contains_key(*field)) {
            return Err("exact public signature fields required".into());
        }
        let decode = |field: &str| -> Result<Vec<u8>, Box<dyn std::error::Error>> {
            let text = object[field]
                .as_str()
                .ok_or("signature must be lowercase hex")?;
            let bytes = hex::decode(text)?;
            if hex::encode(&bytes) != text {
                return Err("noncanonical signature hex".into());
            }
            Ok(bytes)
        };
        Some(RegistrationSignatures {
            parent: decode("parent")?,
            claimant: decode("claimant")?,
            target: decode("target")?,
            parent_for_child: decode("parent_for_child")?,
            fee: decode("fee")?,
        })
    } else {
        None
    };
    println!(
        "{}",
        serde_json::to_string(&build_witness(&value, signatures.as_ref())?)?
    );
    Ok(())
}
