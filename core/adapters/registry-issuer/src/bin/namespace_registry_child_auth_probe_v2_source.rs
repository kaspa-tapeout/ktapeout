//! Shared source for the explicit V2 authority-transfer workbench candidate.

/// Local V3 parent admits both an interior split and an exact released-slot
/// registration. Historical SOURCE_V2 is never rewritten.
pub fn source_slot_parent_v3() -> String {
    SOURCE_V2
        .replace(
            "contract NamespaceRegistryChildAuthProbeV2",
            "contract NamespaceRegistryChildAuthProbeV3",
        )
        .replace(
            "require(tx.inputs.length == 3 && tx.outputs.length == 5);",
            "require(tx.inputs.length == 3 && (tx.outputs.length == 5 || tx.outputs.length == 3));",
        )
}

/// Independent local recovery parent; historical parent sources stay frozen.
pub fn source_recovery_parent_v4() -> String {
    let mut source = source_slot_parent_v3();
    let close = source.rfind('}').expect("parent terminator");
    source.insert_str(close,r#"
  entrypoint function close_namespace(sig authoritySig, pubkey authority, byte[32] refundScriptHash) {
    require(this.activeInputIndex==0 && tx.inputs.length==3 && tx.outputs.length==2);
    require(authorityCommitment==sha256(authority) && checkSig(authoritySig,authority));
    require(OpInputCovenantId(0)==OpInputCovenantId(1));
    require(OpAuthOutputCount(0)==1 && OpAuthOutputIdx(0,0)==0 && OpAuthOutputCount(1)==0);
    require(tx.outputs[0].value==tx.inputs[0].value+tx.inputs[1].value && sha256(tx.outputs[0].scriptPubKey)==refundScriptHash);
  }
"#);
    source.replace(
        "contract NamespaceRegistryChildAuthProbeV3",
        "contract NamespaceRegistryChildAuthProbeV4",
    )
}

/// `ktape.official.adapter.registry` namespace parent, adapter_semver 1.0.0.
/// The parent UTXO holds the namespace bond. It can only close together with its
/// issuance certificate (input 2, from the declared registry root lineage), so the
/// bond is never refunded while the namespace name stays occupied.
#[allow(dead_code)] // included by several bins; only the adapter planners call it
pub fn source_registry_adapter_parent_v1() -> String {
    let mut source = source_slot_parent_v3();
    let close = source.rfind('}').expect("parent terminator");
    source.insert_str(close, r#"
  entrypoint function close_namespace_with_certificate(sig authoritySig, pubkey authority, byte[32] refundScriptHash) {
    require(this.activeInputIndex==0 && tx.inputs.length==4 && tx.outputs.length==3);
    require(authorityCommitment==sha256(authority) && checkSig(authoritySig,authority));
    require(OpInputCovenantId(0)==OpInputCovenantId(1) && OpInputCovenantId(2)==registryRoot);
    require(OpAuthOutputCount(0)==1 && OpAuthOutputIdx(0,0)==0 && OpAuthOutputCount(1)==0);
    require(tx.outputs[0].value==tx.inputs[0].value+tx.inputs[1].value && sha256(tx.outputs[0].scriptPubKey)==refundScriptHash);
  }
"#);
    source.replace(
        "contract NamespaceRegistryChildAuthProbeV3",
        "contract KtapeoutRegistryAdapterNamespaceParentV1",
    )
}

pub const SOURCE_V2: &str = r#"pragma silverscript ^0.1.0;
contract NamespaceRegistryChildAuthProbeV2(
  byte[32] initNamespaceHash, byte[32] initAuthorityCommitment,
  byte[32] initResolverPolicyHash, byte[32] initRegistryRoot,
  int initNonce
) {
  byte[32] namespaceHash = initNamespaceHash;
  byte[32] authorityCommitment = initAuthorityCommitment;
  byte[32] resolverPolicyHash = initResolverPolicyHash;
  byte[32] registryRoot = initRegistryRoot;
  int nonce = initNonce;

  function requireCurrentAuthority(State prevState, pubkey currentAuthority, sig authoritySig) : () {
    require(prevState.authorityCommitment == sha256(currentAuthority));
    require(checkSig(authoritySig, currentAuthority));
  }

  function requireParentLineage() : () {
    // The genesis Covenant ID is derived from the genesis outpoint and is
    // therefore unavailable while compiling the genesis script.  Preserve
    // lineage by requiring the active parent input and successor output to
    // carry the same runtime Covenant ID; the concrete ID is bound by the
    // child codec and deployment tuple after genesis readback.
    require(OpInputCovenantId(0) == OpOutputCovenantId(0));
  }

  #[covenant(mode = transition, binding = auth, from = 1, to = 1)]
  function authorize_child(
    State prevState, State nextState, pubkey currentAuthority, sig authoritySig
  ) : (State) {
    requireCurrentAuthority(prevState, currentAuthority, authoritySig);
    requireParentLineage();
    require(prevState.namespaceHash == namespaceHash);
    require(prevState.resolverPolicyHash == resolverPolicyHash);
    require(prevState.registryRoot == registryRoot);
    require(prevState.nonce == nonce);
    require(nextState.namespaceHash == prevState.namespaceHash);
    require(nextState.authorityCommitment == prevState.authorityCommitment);
    require(nextState.resolverPolicyHash == prevState.resolverPolicyHash);
    require(nextState.registryRoot == prevState.registryRoot);
    require(nextState.nonce == prevState.nonce);
    require(this.activeInputIndex == 0);
    require(tx.inputs.length == 3 && tx.outputs.length == 5);
    require(OpAuthOutputCount(0) == 1 && OpAuthOutputIdx(0, 0) == 0);
    require(tx.outputs[0].value == tx.inputs[0].value);
    return(nextState);
  }

  #[covenant(mode = transition, binding = auth, from = 1, to = 1)]
  function transfer_authority(
    State prevState, State nextState, pubkey currentAuthority,
    pubkey nextAuthority, sig authoritySig
  ) : (State) {
    requireCurrentAuthority(prevState, currentAuthority, authoritySig);
    requireParentLineage();
    require(prevState.namespaceHash == namespaceHash);
    require(prevState.resolverPolicyHash == resolverPolicyHash);
    require(prevState.registryRoot == registryRoot);
    require(prevState.nonce == nonce);
    require(nextState.namespaceHash == prevState.namespaceHash);
    require(nextState.authorityCommitment == sha256(nextAuthority));
    require(nextState.resolverPolicyHash == prevState.resolverPolicyHash);
    require(nextState.registryRoot == prevState.registryRoot);
    require(nextState.nonce == nonce + 1);
    require(this.activeInputIndex == 0);
    require(tx.inputs.length == 2 && tx.outputs.length == 2);
    require(OpAuthOutputCount(0) == 1 && OpAuthOutputIdx(0, 0) == 0);
    require(tx.outputs[0].value == tx.inputs[0].value);
    return(nextState);
  }

  #[covenant(mode = transition, binding = auth, from = 1, to = 1)]
  function update(
    State prevState, State nextState, pubkey currentAuthority,
    sig authoritySig
  ) : (State) {
    requireCurrentAuthority(prevState, currentAuthority, authoritySig);
    requireParentLineage();
    require(prevState.namespaceHash == namespaceHash);
    require(prevState.resolverPolicyHash == resolverPolicyHash);
    require(prevState.registryRoot == registryRoot);
    require(prevState.nonce == nonce);
    require(nextState.namespaceHash == namespaceHash);
    require(nextState.authorityCommitment == prevState.authorityCommitment);
    require(nextState.nonce == nonce + 1);
    require(this.activeInputIndex == 0);
    require(tx.inputs.length == 2 && tx.outputs.length == 2);
    require(OpAuthOutputCount(0) == 1 && OpAuthOutputIdx(0, 0) == 0);
    require(tx.outputs[0].value == tx.inputs[0].value);
    return(nextState);
  }
}
"#;
