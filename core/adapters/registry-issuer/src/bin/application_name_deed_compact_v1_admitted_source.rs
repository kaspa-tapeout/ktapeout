//! Byte-for-byte frozen CompactV1 contract source from the admitted deployment compiler.

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
    for(i, 0, 15, 15) {
      if (greater == 0) { if (key[i] > lo[i]) { greater = 1; } else if (key[i] < lo[i]) { greater = -1; } }
      if (less == 0) { if (key[i] < hi[i]) { less = 1; } else if (key[i] > hi[i]) { less = -1; } }
    }
    int result = greater == 1 && (hiMax == 1 || less == 1);
    return(result);
  }

  function isSuccessor(byte[32] key, byte[32] successor) : (int) {
    // A successor is the exclusive upper bound of the remaining sparse
    // interval.  Compare the complete 32-byte keys lexicographically; do
    // not use script numeric arithmetic, whose signed/byte interpretation can
    // accept a value below the asserted name key (the old V1 bug).
    int relation = 0;
    for(i, 0, 32, 32) {
      if (relation == 0) {
        if (successor[i] > key[i]) { relation = 1; }
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
