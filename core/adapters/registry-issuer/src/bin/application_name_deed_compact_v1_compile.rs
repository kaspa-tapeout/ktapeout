//! Native compile candidate for ApplicationNameDeedCompactV1.
//!
//! This binary never signs or broadcasts.  It freezes the CompactV1 State
//! layout and emits machine-readable size/template evidence for the separate
//! VM and TN10 admission steps.

use sha2::{Digest, Sha256};
use silverscript_lang::ast::Expr;
use silverscript_lang::compiler::{CompileOptions, compile_contract};
#[path = "application_name_deed_compact_v1_admitted_source.rs"]
mod admitted_source;
#[path = "../bounded_public_json.rs"]
mod bounded_public_json;

fn source_full() -> String {
    // Byte-wise comparison is intentionally explicit. Kaspa script numeric
    // comparison is not a substitute for lexicographic comparison of a full
    // BLAKE3 key.
    let mut source = String::from(
        r#"pragma silverscript ^0.1.0;
contract ApplicationNameDeedCompactV1(
  int initObjectKind, int initNonce, byte[32] initGapLo, byte[32] initGapHi, int initHiIsMax,
  byte[32] initNameKey, byte[32] initControllerCommitment, byte[32] initTargetCommitment,
  byte[32] initTargetAuthorityCommitment, byte[32] initResolverPolicyHash, int initBondSompi
) {
  int objectKind = initObjectKind;
  int nonce = initNonce;
  byte[32] gapLo = initGapLo;
  byte[32] gapHi = initGapHi;
  int hiIsMax = initHiIsMax;
  byte[32] nameKey = initNameKey;
  byte[32] controllerCommitment = initControllerCommitment;
  byte[32] targetCommitment = initTargetCommitment;
  byte[32] targetAuthorityCommitment = initTargetAuthorityCommitment;
  byte[32] resolverPolicyHash = initResolverPolicyHash;
  int bondSompi = initBondSompi;

  function isStrictlyInside(byte[32] key, byte[32] lo, byte[32] hi, int hiMax) : (int) {
    int greater = 0;
    int less = 0;
    // The compiler lowers ranges as [start, end); all 32 key bytes must be
    // compared.  The old 0..15 bound silently left the suffix unconstrained.
    for(i, 0, 32, 32) {
      if (greater == 0) { if (key[i] > lo[i]) { greater = 1; } else if (key[i] < lo[i]) { greater = -1; } }
      if (less == 0) { if (key[i] < hi[i]) { less = 1; } else if (key[i] > hi[i]) { less = -1; } }
    }
    int result = greater == 1 && (hiMax == 1 || less == 1);
    return(result);
  }

  function isSuccessor(byte[32] key, byte[32] successor) : (int) {
    // The current candidate proves strict byte-key ordering only. Exact
    // adjacency requires a separately admitted writer template.
    int relation = 0;
    for(i, 0, 32, 32) {
      if (relation == 0) {
        if (successor[i] > key[i]) {
          relation = 1;
        }
        else if (successor[i] < key[i]) { relation = -1; }
      }
    }
    return(relation == 1);
  }

  function requireGap(State value) {
    require(value.objectKind == 0 && value.nonce == 0 && value.bondSompi == 0);
  }

  function requireDeed(State value) {
    require(value.objectKind == 1 && value.bondSompi >= 1000000000 && value.nonce >= 0);
  }

  #[covenant(mode = transition, binding = auth, from = 1, to = 3)]
  function register_interior(State prevState, State[] nextStates, sig claimantSig, pubkey claimant, sig targetSig, pubkey targetAuthority, byte[32] assertedKey, byte[32] assertedTarget, byte[32] assertedPolicy, int assertedBond, byte[32] assertedSuccessor) : (State[]) {
    require(checkSig(claimantSig, claimant));
    require(checkSig(targetSig, targetAuthority));
    require(nextStates.length == 3);
    requireGap(prevState);
    require(isStrictlyInside(assertedKey, prevState.gapLo, prevState.gapHi, prevState.hiIsMax).0 == 1);
    require(isSuccessor(assertedKey, assertedSuccessor).0 == 1);
    require(nextStates[0].gapLo == prevState.gapLo && nextStates[0].gapHi == assertedKey && nextStates[0].hiIsMax == 0);
    requireGap(nextStates[0]);
    requireDeed(nextStates[1]);
    require(nextStates[1].nameKey == assertedKey && nextStates[1].controllerCommitment == sha256(claimant));
    require(nextStates[1].targetCommitment == assertedTarget && nextStates[1].targetAuthorityCommitment == sha256(targetAuthority));
    require(nextStates[1].resolverPolicyHash == assertedPolicy && nextStates[1].bondSompi == assertedBond && nextStates[1].nonce == 0);
    require(nextStates[2].gapLo == assertedSuccessor && nextStates[2].gapHi == prevState.gapHi && nextStates[2].hiIsMax == prevState.hiIsMax);
    requireGap(nextStates[2]);
    require(tx.inputs.length == 1 && tx.outputs.length == 3 && tx.outputs[1].value >= assertedBond);
    return(nextStates);
  }

  #[covenant(mode = transition, binding = auth, from = 1, to = 1)]
  function transfer(State prevState, sig controllerSig, pubkey controller, pubkey nextController) : (State) {
    require(checkSig(controllerSig, controller)); requireDeed(prevState);
    require(prevState.controllerCommitment == sha256(controller));
    return({ objectKind: 1, nonce: prevState.nonce + 1, gapLo: byte[32](0x0000000000000000000000000000000000000000000000000000000000000000), gapHi: byte[32](0x0000000000000000000000000000000000000000000000000000000000000000), hiIsMax: 0,
      nameKey: prevState.nameKey, controllerCommitment: sha256(nextController), targetCommitment: prevState.targetCommitment,
      targetAuthorityCommitment: prevState.targetAuthorityCommitment, resolverPolicyHash: prevState.resolverPolicyHash, bondSompi: prevState.bondSompi });
  }

  #[covenant(mode = transition, binding = auth, from = 1, to = 1)]
  function rebind(State prevState, sig controllerSig, pubkey controller, sig targetSig, pubkey targetAuthority, byte[32] nextTarget, byte[32] nextPolicy) : (State) {
    require(checkSig(controllerSig, controller)); require(checkSig(targetSig, targetAuthority)); requireDeed(prevState);
    require(prevState.controllerCommitment == sha256(controller));
    return({ objectKind: 1, nonce: prevState.nonce + 1, gapLo: byte[32](0x0000000000000000000000000000000000000000000000000000000000000000), gapHi: byte[32](0x0000000000000000000000000000000000000000000000000000000000000000), hiIsMax: 0,
      nameKey: prevState.nameKey, controllerCommitment: prevState.controllerCommitment, targetCommitment: nextTarget,
      targetAuthorityCommitment: sha256(targetAuthority), resolverPolicyHash: nextPolicy, bondSompi: prevState.bondSompi });
  }

  #[covenant(mode = transition, binding = cov, from = 3, to = 1)]
  function release(State[] prevStates, sig controllerSig, pubkey controller, byte[32] refundScriptHash) : (State[]) {
    require(prevStates.length == 3);
    requireGap(prevStates[0]); requireDeed(prevStates[1]); requireGap(prevStates[2]);
    require(checkSig(controllerSig, controller)); require(prevStates[1].controllerCommitment == sha256(controller));
    require(prevStates[0].gapHi == prevStates[1].nameKey && prevStates[2].gapLo == prevStates[1].nameKey);
    require(tx.inputs.length == 3 && tx.outputs.length == 2);
    require(tx.outputs[1].value >= prevStates[1].bondSompi && sha256(tx.outputs[1].scriptPubKey) == refundScriptHash);
    return([{ objectKind: 0, nonce: 0, gapLo: prevStates[0].gapLo, gapHi: prevStates[2].gapHi, hiIsMax: prevStates[2].hiIsMax,
      nameKey: byte[32](0x0000000000000000000000000000000000000000000000000000000000000000), controllerCommitment: byte[32](0x0000000000000000000000000000000000000000000000000000000000000000), targetCommitment: byte[32](0x0000000000000000000000000000000000000000000000000000000000000000),
      targetAuthorityCommitment: byte[32](0x0000000000000000000000000000000000000000000000000000000000000000), resolverPolicyHash: byte[32](0x0000000000000000000000000000000000000000000000000000000000000000), bondSompi: 0 }]);
  }
}
    "#,
    );
    source.push_str("// source digest binds this exact native candidate\n");
    source
}

pub fn source_for_template(template: &str) -> String {
    let full = source_full();
    let register_marker = "\n  #[covenant(mode = transition, binding = auth, from = 1, to = 3)]\n  function register_interior";
    let register_at = full.find(register_marker).expect("register marker");
    let transfer_marker =
        "\n  #[covenant(mode = transition, binding = auth, from = 1, to = 1)]\n  function transfer";
    let transfer_at = full.find(transfer_marker).expect("transfer marker");
    match template {
        // Diagnostic-only split variants. They are not a V1 deployment
        // substitute: the pinned State codec rejects cross-template output
        // validation unless an explicit template adapter is separately proven.
        "gap" => format!("{}\n}}\n", &full[..transfer_at]),
        // Deed never creates arbitrary Gap successors: its only transitions
        // are single-output transfer/rebind under its immutable template.
        "deed" => format!("{}{}", &full[..register_at], &full[transfer_at..]),
        "full" => full,
        other => panic!("unsupported Compact template: {other}"),
    }
}

fn carry_only_successor_replacement(source: &mut String) {
    let start = source
        .find("  function isSuccessor")
        .expect("successor function");
    let end = source[start..]
        .find("\n  function requireGap")
        .map(|offset| start + offset)
        .expect("gap function");
    let mut replacement = String::from("  function increment(byte[32] key):(byte[32]) {\n");
    for i in (0..32).rev() {
        let carry = if i == 31 {
            "1".to_string()
        } else {
            format!("carry{}", i + 1)
        };
        replacement.push_str(&format!("    byte[1] next{i}=key[{i}]; int carry{i}=0;\n"));
        replacement.push_str(&format!("    if ({carry}==1) {{ if (key[{i}]==255) {{ next{i}=byte[1](0); carry{i}=1; }} else {{ next{i}=byte[1](OpNum2Bin(OpBin2Num(key[{i}])+1,1)); }} }}\n"));
    }
    replacement.push_str("    return(");
    for i in 0..32 {
        if i > 0 {
            replacement.push('+');
        }
        replacement.push_str(&format!("next{i}"));
    }
    replacement.push_str(");\n  }\n  function isSuccessor(byte[32] key, byte[32] successor):(int) { return(increment(key).0==successor); }\n");
    source.replace_range(start..end, &replacement);
}

/// Diagnostic-only registration writer candidate. It has exact Gap adjacency
/// and a bounded script, but deliberately has no namespace-parent input yet.
/// It must never be routed as an admitted Profile or signing target.
fn source_gap_writer_v2() -> String {
    let mut source = source_for_template("gap");
    carry_only_successor_replacement(&mut source);
    source = source.replace(
        "contract ApplicationNameDeedCompactV1",
        "contract ApplicationNameGapWriterV2",
    );
    source
}

/// Diagnostic-only parent-binding probe. It measures the smallest additional
/// script surface for reading and preserving a namespace parent state while
/// registering a child. It is not an admitted CLI template: the current
/// NamespaceRegistry transition does not admit this transaction shape, and
/// this probe has no signing/broadcast/deployment path.
pub fn source_gap_writer_parent_probe() -> String {
    let mut source = source_gap_writer_v2();
    source = source.replace(
        "int initBondSompi\n) {",
        "int initBondSompi, byte[32] initNamespaceHash, byte[32] initParentTemplateHash, int initParentPrefixLen, int initParentSuffixLen, byte[32] initParentCovenantId\n) {",
    );
    source = source.replace(
        "  int objectKind = initObjectKind;",
        "  struct NamespaceParentState { byte[32] namespaceHash; byte[32] authorityCommitment; byte[32] resolverPolicyHash; byte[32] registryRoot; int nonce; }\n  function verifyParent(int parentInputIndex, int parentOutputIndex, sig parentSig, pubkey parentAuthority, byte[] parentPrefix, byte[] parentSuffix) {\n    NamespaceParentState parent=readInputStateWithTemplate(parentInputIndex,initParentPrefixLen,initParentSuffixLen,initParentTemplateHash);\n    require(parentInputIndex==0 && parentOutputIndex==0);\n    require(OpInputCovenantId(parentInputIndex)==initParentCovenantId);\n    require(OpOutputCovenantId(parentOutputIndex)==initParentCovenantId);\n    // The Gap predecessor and all three state successors remain in the same\n    // parent-authorized lineage. The codec enforces the same rule before it\n    // constructs the transaction body.\n    require(OpInputCovenantId(1)==initParentCovenantId);\n    require(OpOutputCovenantId(1)==initParentCovenantId);\n    require(OpOutputCovenantId(2)==initParentCovenantId);\n    require(OpOutputCovenantId(3)==initParentCovenantId);\n    require(checkSig(parentSig,parentAuthority));\n    require(parent.namespaceHash==initNamespaceHash);\n    require(parent.authorityCommitment==sha256(parentAuthority));\n    validateOutputStateWithTemplate(parentOutputIndex,parent,parentPrefix,parentSuffix,initParentTemplateHash);\n  }\n  int objectKind = initObjectKind;",
    );
    source = source.replace(
        "byte[32] assertedSuccessor) : (State[]) {",
        "byte[32] assertedSuccessor, sig parentSig, pubkey parentAuthority, int parentInputIndex, int parentOutputIndex, byte[] parentPrefix, byte[] parentSuffix) : (State[]) {\n    verifyParent(parentInputIndex,parentOutputIndex,parentSig,parentAuthority,parentPrefix,parentSuffix);",
    );
    source = source.replace(
        "require(tx.inputs.length == 1 && tx.outputs.length == 3 && tx.outputs[1].value >= assertedBond);",
        "require(tx.inputs.length == 3 && tx.outputs.length == 5 && tx.outputs[2].value >= assertedBond);",
    );
    source = source.replace(
        "contract ApplicationNameGapWriterV2",
        "contract ApplicationNameGapWriterParentProbeV1",
    );
    source
}

/// Diagnostic-only parent probe using the opt-in fixed-width successor
/// lowering. This is a budget/shape experiment, not a Profile or deployment
/// source and has no signing or broadcast path.
pub fn source_gap_writer_parent_probe_with_fixed_successor() -> String {
    let marker = "  function isSuccessor(byte[32] key, byte[32] successor):(int) { return(increment(key).0==successor); }\n";
    source_gap_writer_parent_probe().replace(
        marker,
        "  function isSuccessor(byte[32] key, byte[32] successor):(int) { return(experimentalU256IncBe32(key)==successor); }\n",
    )
}

/// Bootstrap-safe parent probe: the initial Gap script binds its lineage to
/// the runtime Covenant ID group instead of a constructor Covenant ID. This
/// removes the otherwise circular dependency where the Gap script would need
/// the parent genesis ID before the genesis transaction exists.
pub fn source_gap_writer_parent_probe_runtime_lineage_with_fixed_successor() -> String {
    let mut source = source_gap_writer_parent_probe_with_fixed_successor();
    source = source.replace(", byte[32] initParentCovenantId", "");
    source = source.replace(
        "OpInputCovenantId(parentInputIndex)==initParentCovenantId",
        "OpInputCovenantId(parentInputIndex)==OpInputCovenantId(0)",
    );
    source = source.replace(
        "OpOutputCovenantId(parentOutputIndex)==initParentCovenantId",
        "OpOutputCovenantId(parentOutputIndex)==OpInputCovenantId(0)",
    );
    source = source.replace(
        "OpInputCovenantId(1)==initParentCovenantId",
        "OpInputCovenantId(1)==OpInputCovenantId(0)",
    );
    source = source.replace(
        "OpOutputCovenantId(1)==initParentCovenantId",
        "OpOutputCovenantId(1)==OpInputCovenantId(0)",
    );
    source = source.replace(
        "OpOutputCovenantId(2)==initParentCovenantId",
        "OpOutputCovenantId(2)==OpInputCovenantId(0)",
    );
    source = source.replace(
        "OpOutputCovenantId(3)==initParentCovenantId",
        "OpOutputCovenantId(3)==OpInputCovenantId(0)",
    );
    source.replace(
        "contract ApplicationNameGapWriterParentProbeV1",
        "contract ApplicationNameGapWriterParentBootstrapV1",
    )
}

/// Corrected candidate only: historical BootstrapV1 script bytes stay frozen.
/// Hash keys are unsigned big-endian and gaps are half-open [lo, hi).
pub fn source_gap_writer_parent_bootstrap_unsigned_v2() -> String {
    let mut source = source_gap_writer_parent_probe_runtime_lineage_with_fixed_successor();
    for operand in ["key[i]", "lo[i]", "hi[i]"] {
        source = source.replace(operand, &format!("OpBin2Num(bytes({operand}) + 0x00)"));
    }
    source = source.replace(
        "greater == 1 && (hiMax == 1 || less == 1)",
        "greater != -1 && (hiMax == 1 || less == 1)",
    );
    source.replace(
        "contract ApplicationNameGapWriterParentBootstrapV1",
        "contract ApplicationNameGapWriterParentBootstrapV2",
    )
}

/// Local-only lifecycle candidate. Never substituted for an existing Gap.
pub fn source_gap_writer_parent_bootstrap_lifecycle_v3() -> String {
    let mut source = source_gap_writer_parent_bootstrap_unsigned_v2();
    let close = source.rfind('}').expect("contract terminator");
    source.insert_str(close, r#"
  #[covenant(mode=transition,binding=auth,from=1,to=1)]
  function change_owner_target(State prevState, State nextState, sig ownerSig, pubkey owner, pubkey nextOwner, sig targetSig, pubkey nextTargetAuthority) : (State) {
    requireDeed(prevState);
    require(checkSig(ownerSig,owner) && prevState.controllerCommitment==sha256(owner));
    require(nextState.objectKind==1 && nextState.nonce==prevState.nonce+1);
    require(nextState.nameKey==prevState.nameKey && nextState.bondSompi==prevState.bondSompi);
    require(nextState.gapLo==0x0000000000000000000000000000000000000000000000000000000000000000 && nextState.gapHi==0x0000000000000000000000000000000000000000000000000000000000000000 && nextState.hiIsMax==0);
    require(nextState.controllerCommitment==sha256(nextOwner));
    require(nextState.targetAuthorityCommitment==sha256(nextTargetAuthority));
    if(nextState.targetCommitment!=prevState.targetCommitment || nextState.targetAuthorityCommitment!=prevState.targetAuthorityCommitment || nextState.resolverPolicyHash!=prevState.resolverPolicyHash) { require(checkSig(targetSig,nextTargetAuthority)); }
    require(this.activeInputIndex==0 && tx.inputs.length==2 && tx.outputs.length==2);
    require(tx.outputs[0].value==tx.inputs[0].value && tx.outputs[0].value>=prevState.bondSompi);
    require(OpInputCovenantId(0)==OpOutputCovenantId(0));
    return(nextState);
  }
  entrypoint function owner_exit(sig ownerSig, pubkey owner, byte[32] refundScriptHash) {
    require(objectKind==1 && controllerCommitment==sha256(owner) && checkSig(ownerSig,owner));
    require(this.activeInputIndex==0 && tx.inputs.length==2 && tx.outputs.length==2);
    require(OpAuthOutputCount(0)==1 && OpAuthOutputIdx(0,0)==0);
    require(tx.outputs[0].value==tx.inputs[0].value && sha256(tx.outputs[0].scriptPubKey)==refundScriptHash);
  }
"#);
    source.replace(
        "contract ApplicationNameGapWriterParentBootstrapV2",
        "contract ApplicationNameGapWriterParentBootstrapV3",
    )
}

/// Local-only name-release candidate. Old templates and live rights are immutable.
pub fn source_gap_writer_parent_bootstrap_release_v4() -> String {
    let mut source = source_gap_writer_parent_bootstrap_lifecycle_v3();
    // ScriptNum is little-endian and signed. Reverse each <=7-byte chunk
    // explicitly and append a zero sign byte: every value fits signed i64.
    // Lexicographic comparison of the five chunks is exact over all 32 bytes.
    let compare_start = source
        .find("  function isStrictlyInside(")
        .expect("ordering helper");
    let compare_end = source[compare_start..]
        .find("  function increment(")
        .map(|n| compare_start + n)
        .expect("increment helper");
    let mut compare = String::from(
        "  function isStrictlyInside(byte[32] key, byte[32] lo, byte[32] hi, int hiMax) : (int) {\n    int greater=0; int less=0;\n",
    );
    for (chunk, start) in (0..32).step_by(7).enumerate() {
        let end = (start + 7).min(32);
        for name in ["key", "lo", "hi"] {
            let bytes = (start..end)
                .rev()
                .map(|i| format!("bytes({name}[{i}])"))
                .collect::<Vec<_>>()
                .join("+");
            compare.push_str(&format!("    int {name}{chunk}=OpBin2Num({bytes}+0x00);\n"));
        }
        compare.push_str(&format!("    if(greater==0) {{if(key{chunk}>lo{chunk}) {{greater=1;}} else if(key{chunk}<lo{chunk}) {{greater=-1;}}}}\n    if(less==0) {{if(key{chunk}<hi{chunk}) {{less=1;}} else if(key{chunk}>hi{chunk}) {{less=-1;}}}}\n"));
    }
    compare.push_str("    return(greater!=-1 && (hiMax==1 || less==1));\n  }\n\n");
    source.replace_range(compare_start..compare_end, &compare);
    // Native CovenantsContext enforces output binding to its authorizing input;
    // the generated auth transition validates each output's state/template.
    // Keep the cross-input namespace lineage check, omit duplicate output IDs.
    for index in [1, 2, 3] {
        source = source.replace(
            &format!("    require(OpOutputCovenantId({index})==OpInputCovenantId(0));\n"),
            "",
        );
    }
    let start = source
        .find("  entrypoint function owner_exit(")
        .expect("V3 exit marker");
    let end = source[start..]
        .find("\n  }\n")
        .map(|n| start + n + 5)
        .expect("V3 exit end");
    source.replace_range(start..end,r#"  #[covenant(mode=transition,binding=auth,from=1,to=1)]
  function release_name(State prevState, State nextState, sig ownerSig, pubkey owner, byte[32] refundScriptHash) : (State) {
    requireDeed(prevState);
    require(prevState.controllerCommitment==sha256(owner) && checkSig(ownerSig,owner));
    requireGap(nextState);
    require(nextState.gapLo==prevState.nameKey && nextState.gapHi==experimentalU256IncBe32(prevState.nameKey) && nextState.hiIsMax==0);
    require(nextState.nameKey==0x0000000000000000000000000000000000000000000000000000000000000000 && nextState.controllerCommitment==nextState.nameKey && nextState.targetCommitment==nextState.nameKey && nextState.targetAuthorityCommitment==nextState.nameKey && nextState.resolverPolicyHash==nextState.nameKey);
    require(this.activeInputIndex==0 && tx.inputs.length==2 && tx.outputs.length==3);
    require(tx.outputs[0].value==100000000 && OpInputCovenantId(0)==OpOutputCovenantId(0));
    require(tx.outputs[1].value==tx.inputs[0].value-100000000 && sha256(tx.outputs[1].scriptPubKey)==refundScriptHash);
    return(nextState);
  }
"#);
    // The pinned fanout lowering accepts <=to outputs, not only exactly to.
    // Share registration policy instead of a duplicate register_slot entry.
    source=source.replace("require(nextStates.length == 3);", "require(nextStates.length==3 || nextStates.length==1);\n    int deedIndex=0; if(nextStates.length==3) {deedIndex=1;}\n    State nextDeed=nextStates[deedIndex];");
    source = source.replace(
        "    require(nextStates[0].gapLo == prevState.gapLo",
        "    if(nextStates.length==3) {\n    require(nextStates[0].gapLo == prevState.gapLo",
    );
    source=source.replace("    requireGap(nextStates[0]);", "    requireGap(nextStates[0]);\n    } else {require(prevState.gapLo==assertedKey && prevState.gapHi==assertedSuccessor && prevState.hiIsMax==0);}");
    source = source.replace("nextStates[1]", "nextDeed");
    source = source.replace(
        "    require(nextStates[2].gapLo == assertedSuccessor",
        "    if(nextStates.length==3) {\n    require(nextStates[2].gapLo == assertedSuccessor",
    );
    source = source.replace(
        "    requireGap(nextStates[2]);",
        "    requireGap(nextStates[2]);\n    }",
    );
    source=source.replace("require(tx.inputs.length == 3 && tx.outputs.length == 5 && tx.outputs[2].value >= assertedBond);", "require(this.activeInputIndex==1 && tx.inputs.length==3 && tx.outputs.length==nextStates.length+2 && tx.outputs[deedIndex+1].value>=assertedBond);\n    require(nextDeed.gapLo==0x0000000000000000000000000000000000000000000000000000000000000000 && nextDeed.gapHi==nextDeed.gapLo && nextDeed.hiIsMax==0);");
    source.replace(
        "contract ApplicationNameGapWriterParentBootstrapV3",
        "contract ApplicationNameGapWriterParentBootstrapV4",
    )
}

/// Local-only recovery version. Merge cannot redirect or discount Gap funds;
/// retirement requires a full-space Gap and the actual parent authority.
pub fn source_gap_writer_parent_bootstrap_recovery_v5() -> String {
    let mut source = source_gap_writer_parent_bootstrap_release_v4();
    let close = source.rfind('}').expect("V5 terminator");
    source.insert_str(close,r#"
  entrypoint function merge_gaps(State nextState) {
    require(this.activeInputIndex==0 || this.activeInputIndex==1);
    require(tx.inputs.length==3 && tx.outputs.length==2);
    require(OpInputCovenantId(0)==OpInputCovenantId(1));
    require(OpAuthOutputCount(0)==1 && OpAuthOutputIdx(0,0)==0 && OpAuthOutputCount(1)==0);
    State left=readInputState(0); State right=readInputState(1);
    requireGap(left); requireGap(right); requireGap(nextState);
    require(left.hiIsMax==0 && left.gapHi==right.gapLo);
    require(nextState.gapLo==left.gapLo && nextState.gapHi==right.gapHi && nextState.hiIsMax==right.hiIsMax);
    require(nextState.nameKey==0x0000000000000000000000000000000000000000000000000000000000000000 && nextState.controllerCommitment==nextState.nameKey && nextState.targetCommitment==nextState.nameKey && nextState.targetAuthorityCommitment==nextState.nameKey && nextState.resolverPolicyHash==nextState.nameKey);
    require(tx.outputs[0].value==tx.inputs[0].value+tx.inputs[1].value);
    validateOutputState(0,nextState);
  }
  entrypoint function retire_namespace(sig authoritySig, pubkey authority, byte[32] refundScriptHash) {
    require(this.activeInputIndex==1 && tx.inputs.length==3 && tx.outputs.length==2);
    require(objectKind==0 && nonce==0 && bondSompi==0 && gapLo==0x0000000000000000000000000000000000000000000000000000000000000000 && gapHi==gapLo && hiIsMax==1);
    NamespaceParentState parent=readInputStateWithTemplate(0,initParentPrefixLen,initParentSuffixLen,initParentTemplateHash);
    require(parent.namespaceHash==initNamespaceHash && parent.authorityCommitment==sha256(authority) && checkSig(authoritySig,authority));
    require(OpInputCovenantId(0)==OpInputCovenantId(1));
    require(OpAuthOutputCount(0)==1 && OpAuthOutputIdx(0,0)==0 && OpAuthOutputCount(1)==0);
    require(tx.outputs[0].value==tx.inputs[0].value+tx.inputs[1].value && sha256(tx.outputs[0].scriptPubKey)==refundScriptHash);
  }
"#);
    source.replace(
        "contract ApplicationNameGapWriterParentBootstrapV4",
        "contract ApplicationNameGapWriterParentBootstrapV5",
    )
}

/// Isolated named-key candidate. Opaque 64-byte frames are hash-bound on L1;
/// canonical ASCII presentation remains a separately versioned resolver rule.
/// V5 raw-key deployments are deliberately unchanged.
pub fn source_gap_writer_named_recovery_v6() -> String {
    let source = source_gap_writer_parent_bootstrap_recovery_v5();
    let marker = "byte[32] assertedKey, byte[32] assertedTarget";
    assert!(source.contains(marker));
    let source = source.replace(marker, "byte[32] assertedKey, byte[64] namespaceFrame, byte[64] slugFrame, byte[32] assertedTarget");
    let check = "    require(isStrictlyInside(assertedKey";
    assert!(source.contains(check));
    source.replace(check, "    require(initNamespaceHash==sha256(byte[](\"KTAPEOUT/0.5.0/NAMESPACE_FRAME/V1\")+byte[1](0)+byte[1](10)+namespaceFrame));\n    require(assertedKey==sha256(byte[](\"KTAPEOUT/0.5.0/NAME_FRAME/V1\")+byte[1](0)+byte[1](10)+namespaceFrame+slugFrame));\n    require(isStrictlyInside(assertedKey")
        .replace("contract ApplicationNameGapWriterParentBootstrapV5", "contract ApplicationNameGapWriterNamedRecoveryV6")
}

/// Minimum value kept in every Gap UTXO; equals the release seed used by `release_name`.
pub const REGISTRY_ADAPTER_GAP_FLOOR_SOMPI: u64 = 100_000_000;

/// `ktape.official.adapter.registry` application-name writer, adapter_semver 1.0.0.
/// Differences from V6 (whose script bytes and deployments are unchanged):
/// - an interior registration may not draw on Gap capital: the bond, the second Gap's
///   floor and the fee come from the registrant's funding input;
/// - the minimum application bond is the Gap floor (storage floor), not 10 KAS;
/// - `release_name` refunds the whole bond; the releaser funds the new single-key Gap;
/// - the namespace Gap retires only in the 4-input close that also consumes the
///   namespace certificate (see `source_registry_adapter_parent_v1`);
/// - a deed carries its own interval `[key, key+1)` in `gapLo/gapHi`, so release
///   restores it without a second on-chain 256-bit increment.
pub fn source_registry_adapter_app_v1() -> String {
    let floor = REGISTRY_ADAPTER_GAP_FLOOR_SOMPI;
    let mut source = source_gap_writer_named_recovery_v6();
    let mut edit = |from: &str, to: String| {
        assert_eq!(
            source.matches(from).count(),
            1,
            "adapter edit anchor must be unique: {from}"
        );
        source = source.replace(from, &to);
    };
    let register = "tx.outputs[deedIndex+1].value>=assertedBond);";
    edit(
        register,
        format!(
            "{register}\n    if(nextStates.length==3) {{require(tx.outputs[1].value>={floor} && tx.outputs[3].value>={floor} && tx.outputs[1].value+tx.outputs[3].value>=tx.inputs[1].value);}}"
        ),
    );
    edit(
        "value.bondSompi >= 1000000000",
        format!("value.bondSompi >= {floor}"),
    );
    edit(
        "require(tx.outputs[1].value==tx.inputs[0].value-100000000 &&",
        "require(tx.outputs[1].value==tx.inputs[0].value &&".to_string(),
    );
    edit(
        "require(this.activeInputIndex==1 && tx.inputs.length==3 && tx.outputs.length==2);\n    require(objectKind==0 && nonce==0",
        "require(this.activeInputIndex==1 && tx.inputs.length==4 && tx.outputs.length==3);\n    require(objectKind==0 && nonce==0".to_string(),
    );
    // A deed stores its own key interval [key, key+1) in its Gap fields at registration,
    // where the successor is already proven. Release copies it back instead of recomputing
    // the 256-bit increment, which saves a second inlined successor routine.
    let zero = "0x0000000000000000000000000000000000000000000000000000000000000000";
    edit(
        &format!("require(nextDeed.gapLo=={zero} && nextDeed.gapHi==nextDeed.gapLo && nextDeed.hiIsMax==0);"),
        "require(nextDeed.gapLo==assertedKey && nextDeed.gapHi==assertedSuccessor && nextDeed.hiIsMax==0);".to_string(),
    );
    edit(
        &format!("require(nextState.gapLo=={zero} && nextState.gapHi=={zero} && nextState.hiIsMax==0);"),
        "require(nextState.gapLo==prevState.gapLo && nextState.gapHi==prevState.gapHi && nextState.hiIsMax==0);".to_string(),
    );
    edit(
        "require(nextState.gapLo==prevState.nameKey && nextState.gapHi==experimentalU256IncBe32(prevState.nameKey) && nextState.hiIsMax==0);",
        "require(prevState.gapLo==prevState.nameKey && nextState.gapLo==prevState.gapLo && nextState.gapHi==prevState.gapHi && nextState.hiIsMax==0);".to_string(),
    );
    source.replace(
        "contract ApplicationNameGapWriterNamedRecoveryV6",
        "contract KtapeoutRegistryAdapterAppNameV1",
    )
}

fn main() {
    let cli: Vec<String> = std::env::args().skip(1).collect();
    if !cli.is_empty() {
        assert!(
            cli.len() == 2 && cli[0] == "--verify-owner-state",
            "usage: --verify-owner-state PUBLIC.json"
        );
        use std::io::Read;
        let file = std::fs::File::open(&cli[1]).expect("open public owner state");
        let mut bytes = Vec::new();
        file.take(16385)
            .read_to_end(&mut bytes)
            .expect("read owner state");
        assert!(bytes.len() <= 16384, "owner state exceeds 16 KiB");
        let value = bounded_public_json::parse(&bytes).expect("public owner JSON");
        println!(
            "{}",
            verify_owner_state(&value).expect("verify exact owner script")
        );
        return;
    }
    let zero = vec![0u8; 32];
    let args = vec![
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
    ];
    let template = std::env::var("KTAPE_COMPACT_TEMPLATE").unwrap_or_else(|_| "full".to_string());
    if template == "gap-v2" {
        eprintln!(
            "gap-v2 is diagnostic-only and is available only through focused workbench tests"
        );
        std::process::exit(2);
    }
    // The CLI must compile the same frozen source that the admission verifier
    // validates. The older local source_for_template copy is retained only for
    // legacy unit probes and is not the admitted deployment source.
    let source = if template == "gap-v2" {
        source_gap_writer_v2()
    } else {
        admitted_source::source_for_template(&template)
    };
    let compiled = compile_contract(&source, &args, CompileOptions::default())
        .expect("compile CompactV1 candidate");
    let status = if template == "gap-v2" {
        if compiled.script.len() <= 10_000 {
            "COMPILED_LOCAL_CANDIDATE_UNADMITTED_PARENT_AUTHORITY"
        } else {
            "COMPILED_LOCAL_CANDIDATE_BLOCKED_SCRIPT_SIZE"
        }
    } else if compiled.script.len() <= 10_000 {
        "COMPILED_LOCAL_CANDIDATE"
    } else {
        "COMPILED_LOCAL_CANDIDATE_BLOCKED_SCRIPT_SIZE"
    };
    let script_field = if std::env::var("KTAPE_COMPACT_EMIT_SCRIPT").ok().as_deref() == Some("1") {
        format!(",\"script_hex\":\"{}\"", hex::encode(&compiled.script))
    } else {
        String::new()
    };
    let state_field = if let Ok(raw) = std::env::var("KTAPE_COMPACT_STATE_ARGS") {
        let fields: Vec<&str> = raw.split('|').collect();
        assert_eq!(
            fields.len(),
            11,
            "KTAPE_COMPACT_STATE_ARGS requires 11 pipe-separated fields"
        );
        let int_field =
            |index: usize| -> i64 { fields[index].parse::<i64>().expect("state integer field") };
        let bytes_field = |index: usize| -> Vec<u8> {
            let bytes = hex::decode(fields[index]).expect("state byte field hex");
            assert_eq!(bytes.len(), 32, "state byte field must be 32 bytes");
            bytes
        };
        let state_args = vec![
            Expr::int(int_field(0)),
            Expr::int(int_field(1)),
            Expr::bytes(bytes_field(2)),
            Expr::bytes(bytes_field(3)),
            Expr::int(int_field(4)),
            Expr::bytes(bytes_field(5)),
            Expr::bytes(bytes_field(6)),
            Expr::bytes(bytes_field(7)),
            Expr::bytes(bytes_field(8)),
            Expr::bytes(bytes_field(9)),
            Expr::int(int_field(10)),
        ];
        let state_compiled = compile_contract(&source, &state_args, CompileOptions::default())
            .expect("compile state-parameterized CompactV1 candidate");
        format!(
            ",\"state_script_sha256\":\"{}\",\"state_script_bytes\":{},\"state_script_hex\":\"{}\"",
            hex::encode(Sha256::digest(&state_compiled.script)),
            state_compiled.script.len(),
            hex::encode(&state_compiled.script)
        )
    } else {
        String::new()
    };
    let profile_family_id = if template == "gap-v2" {
        "ApplicationNameGapWriterV2"
    } else {
        "ApplicationNameDeedCompactV1"
    };
    let json = format!(
        "{{\"schema\":\"KTAPEOUT-COMPACT-NAME-DEED-NATIVE-COMPILE-V1\",\"profile_family_id\":\"{}\",\"template_role\":\"{}\",\"source_sha256\":\"{}\",\"script_sha256\":\"{}\",\"template_hash_hex\":\"{}\",\"script_bytes\":{},\"state_len\":{},\"status\":\"{}\",\"broadcast\":false{}{} }}",
        profile_family_id,
        template,
        hex::encode(Sha256::digest(source.as_bytes())),
        hex::encode(Sha256::digest(&compiled.script)),
        hex::encode(compiled.template_hash()),
        compiled.script.len(),
        compiled.state_layout.len,
        status,
        script_field,
        state_field
    );
    if let Ok(path) = std::env::var("KTAPE_COMPACT_OUTPUT_PATH") {
        std::fs::write(path, format!("{}\n", json)).expect("write CompactV1 artifact");
    }
    println!("{}", json);
}

fn verify_owner_state(
    value: &serde_json::Value,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    const ADMITTED_PROFILE_HASH: &str =
        "efc5c8976c7ba6fde9150d1d35c0ef135155d54ea8f55fca9bddf3d600849566";
    const ADMITTED_SOURCE_SHA256: &str =
        "634b5994d249bd226170cec12581af4645cfe99dc6d4952dad42c52bcbc1e15b";
    const ADMITTED_TEMPLATE_HASH: &str =
        "77032e0cc6c8734c342222743c82994788a23d75357e86077c794ea70c04d363";
    const ADMITTED_GENESIS_SCRIPT_SHA256: &str =
        "c68a18b035965d1e2d60099620ffbf677820d3273d175dbb6ac9f0f61ba1dd70";
    let fields = [
        "network",
        "owner_public_key",
        "expected_script_public_key",
        "state_args",
        "template_role",
    ];
    let obj = value.as_object().ok_or("owner state must be an object")?;
    if obj.len() != 5 || fields.iter().any(|key| !obj.contains_key(*key)) {
        return Err("unexpected owner input fields".into());
    }
    if value["network"] != "testnet-10" {
        return Err("testnet-10 required".into());
    }
    let key_hex = value["owner_public_key"]
        .as_str()
        .ok_or("owner key required")?;
    let key = hex::decode(key_hex)?;
    secp256k1::XOnlyPublicKey::from_slice(&key)?;
    if hex::encode(&key) != key_hex {
        return Err("canonical owner key required".into());
    }
    let state = value["state_args"]
        .as_array()
        .ok_or("state_args array required")?;
    if state.len() != 11 {
        return Err("exact 11 state fields required".into());
    }
    let mut args = Vec::new();
    for (i, field) in state.iter().enumerate() {
        if [0, 1, 4, 10].contains(&i) {
            let n = field
                .as_i64()
                .filter(|n| *n >= 0)
                .ok_or("nonnegative state integer required")?;
            args.push(Expr::int(n));
        } else {
            let s = field.as_str().ok_or("state hash string required")?;
            let bytes = hex::decode(s)?;
            if bytes.len() != 32 || hex::encode(&bytes) != s {
                return Err("canonical state hash required".into());
            }
            args.push(Expr::bytes(bytes));
        }
    }
    if state[0] != 1 || state[4] != 0 || state[10].as_i64().unwrap() < 1_000_000_000 {
        return Err("deed state required".into());
    }
    if state[2] != "00".repeat(32) || state[3] != "00".repeat(32) {
        return Err("canonical deed gaps required".into());
    }
    if state[6] != hex::encode(Sha256::digest(&key)) {
        return Err("owner commitment mismatch".into());
    }
    let template = value["template_role"]
        .as_str()
        .ok_or("explicit template role required")?;
    if template != "full" {
        return Err("only the frozen admitted CompactV1 template is supported".into());
    }
    let source = admitted_source::source_for_template("full");
    let source_sha256 = hex::encode(Sha256::digest(source.as_bytes()));
    if source_sha256 != ADMITTED_SOURCE_SHA256 {
        return Err("frozen Compact source digest mismatch".into());
    }
    let compiled = compile_contract(&source, &args, CompileOptions::default())?;
    if hex::encode(compiled.template_hash()) != ADMITTED_TEMPLATE_HASH {
        return Err("admitted Compact template hash mismatch".into());
    }
    let zero = vec![0u8; 32];
    let genesis_args = vec![
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
    ];
    let genesis = compile_contract(&source, &genesis_args, CompileOptions::default())?;
    if hex::encode(Sha256::digest(&genesis.script)) != ADMITTED_GENESIS_SCRIPT_SHA256 {
        return Err("admitted Compact genesis script digest mismatch".into());
    }
    let spk = kaspa_txscript::pay_to_script_hash_script(&compiled.script);
    let mut serialized = spk.version().to_le_bytes().to_vec();
    serialized.extend_from_slice(spk.script());
    if value["expected_script_public_key"] != hex::encode(&serialized) {
        return Err("exact live script reconstruction mismatch".into());
    }
    Ok(
        serde_json::json!({"schema":"KTAPEOUT-COMPACT-ADMITTED-OWNER-STATE-RECONSTRUCTION-V1", "network":"testnet-10",
        "profile_family_id":"ApplicationNameDeedCompactV1","profile_version":1,"profile_hash":ADMITTED_PROFILE_HASH,
        "owner_public_key":key_hex,"controller_commitment":state[6],"name_key":state[5],"target_commitment":state[7],
        "nonce":state[1],"script_public_key":hex::encode(serialized),"template_hash":hex::encode(compiled.template_hash()),
        "template_role":template,"source_sha256":source_sha256,
        "admitted_genesis_script_sha256":hex::encode(Sha256::digest(&genesis.script)),
        "state_script_sha256":hex::encode(Sha256::digest(&compiled.script)),"state_script_bytes":compiled.script.len(),
        "status":"EXACT_ADMITTED_TEMPLATE_STATE_MATCH","l1_observation":"CALLER_SUPPLIED_AND_UNVERIFIED",
        "signing_allowed":false,"broadcast":false}),
    )
}
