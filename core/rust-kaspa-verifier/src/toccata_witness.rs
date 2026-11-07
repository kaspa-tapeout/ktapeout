//! Frozen post-Toccata ABI witness encoding for the supported native registry
//! entrypoints. Runtime values are supplied by a validated registration plan;
//! compiler-generated witness bytes are kept in tests only as differential data.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbiEntryPoint {
    AuthorizeChild,
    RegisterInterior,
    Issue,
    ChangeOwnerTarget,
}

impl AbiEntryPoint {
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        match value {
            "authorize_child" => Ok(Self::AuthorizeChild),
            "register_interior" => Ok(Self::RegisterInterior),
            "issue" => Ok(Self::Issue),
            "change_owner_target" => Ok(Self::ChangeOwnerTarget),
            _ => Err("WITNESS_ENTRYPOINT_UNSUPPORTED"),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::AuthorizeChild => "authorize_child",
            Self::RegisterInterior => "register_interior",
            Self::Issue => "issue",
            Self::ChangeOwnerTarget => "change_owner_target",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WitnessItem {
    Data(Vec<u8>),
    Opcode(u8),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbiFieldType {
    Int,
    FixedBytes(usize),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AbiValue {
    Int(i64),
    Bytes(Vec<u8>),
}

fn descriptor_field_types(state_schema: &str) -> Result<Vec<AbiFieldType>, &'static str> {
    // Typed State order follows the pinned profile constructor declarations:
    // NamespaceNamedLifecycleV6 compiler.rs:20-31, NamespaceIssuanceV1
    // native-plan.rs:38-46, and its parent source:37-42. Their hashes and
    // line ranges are recorded in this ABI descriptor.
    let mut path = state_schema.split('.');
    let family = path.next().ok_or("WITNESS_STATE_SCHEMA_UNKNOWN")?;
    let variant = path.next().ok_or("WITNESS_STATE_SCHEMA_UNKNOWN")?;
    if path.next().is_some() {
        return Err("WITNESS_STATE_SCHEMA_UNKNOWN");
    }
    let descriptor: serde_json::Value = serde_json::from_str(include_str!(
        "../../../data/registry/toccata-native-witness-abi-v1.json"
    ))
    .map_err(|_| "WITNESS_ABI_DESCRIPTOR_INVALID")?;
    let values = descriptor
        .get("state_encodings")
        .and_then(|value| value.get("State"))
        .and_then(|value| value.get("field_types"))
        .and_then(|value| value.get(family))
        .and_then(|value| value.get(variant))
        .and_then(serde_json::Value::as_array)
        .ok_or("WITNESS_STATE_SCHEMA_UNKNOWN")?;
    values
        .iter()
        .map(|value| {
            let name = value.as_str().ok_or("WITNESS_ABI_DESCRIPTOR_INVALID")?;
            if name == "int" {
                return Ok(AbiFieldType::Int);
            }
            let length = name
                .strip_prefix("byte[")
                .and_then(|value| value.strip_suffix(']'))
                .and_then(|value| value.parse::<usize>().ok())
                .filter(|length| *length > 0 && *length <= u16::MAX as usize)
                .ok_or("WITNESS_ABI_DESCRIPTOR_INVALID")?;
            Ok(AbiFieldType::FixedBytes(length))
        })
        .collect()
}

/// Encode a complete State using the pinned type sequence in the ABI file.
pub fn encode_state(
    state_schema: &str,
    values: &[AbiValue],
) -> Result<Vec<WitnessItem>, &'static str> {
    let field_types = descriptor_field_types(state_schema)?;
    if values.len() != field_types.len() {
        return Err("WITNESS_STATE_FIELD_COUNT_MISMATCH");
    }
    field_types
        .into_iter()
        .zip(values.iter().cloned())
        .map(|(field_type, value)| encode_typed_field(field_type, value))
        .collect()
}

/// Encode State[] from the same ABI schema. Array fields are emitted in
/// declaration order and each primitive array occupies one stack item.
pub fn encode_state_array(
    state_schema: &str,
    states: &[Vec<AbiValue>],
) -> Result<Vec<WitnessItem>, &'static str> {
    let field_types = descriptor_field_types(state_schema)?;
    if states.iter().any(|state| state.len() != field_types.len()) {
        return Err("WITNESS_STATE_FIELD_COUNT_MISMATCH");
    }
    let mut output = Vec::with_capacity(field_types.len());
    for (field_index, field_type) in field_types.iter().enumerate() {
        let mut bytes = Vec::new();
        for state in states {
            match (field_type, &state[field_index]) {
                (AbiFieldType::Int, AbiValue::Int(value)) => {
                    bytes.extend_from_slice(&value.to_le_bytes());
                }
                (AbiFieldType::FixedBytes(expected), AbiValue::Bytes(value))
                    if value.len() == *expected =>
                {
                    bytes.extend_from_slice(value);
                }
                (AbiFieldType::FixedBytes(_), AbiValue::Bytes(_)) => {
                    return Err("WITNESS_STATE_FIELD_LENGTH_MISMATCH");
                }
                _ => return Err("WITNESS_STATE_FIELD_TYPE_MISMATCH"),
            }
        }
        output.push(WitnessItem::Data(bytes));
    }
    Ok(output)
}

/// Encode one State field using the vendored compiler's `push_typed_sigscript_arg`
/// and `push_sigscript_arg` rules (compiler/mod.rs:247-380).
fn encode_typed_field(
    field_type: AbiFieldType,
    value: AbiValue,
) -> Result<WitnessItem, &'static str> {
    match (field_type, value) {
        (AbiFieldType::Int, AbiValue::Int(value)) => Ok(script_number_item(value)),
        (AbiFieldType::FixedBytes(expected), AbiValue::Bytes(bytes)) if bytes.len() == expected => {
            Ok(WitnessItem::Data(bytes))
        }
        (AbiFieldType::FixedBytes(_), AbiValue::Bytes(_)) => {
            Err("WITNESS_STATE_FIELD_LENGTH_MISMATCH")
        }
        _ => Err("WITNESS_STATE_FIELD_TYPE_MISMATCH"),
    }
}

fn script_number_item(value: i64) -> WitnessItem {
    match value {
        0 => return WitnessItem::Opcode(0),
        -1 => return WitnessItem::Opcode(0x4f),
        1..=16 => return WitnessItem::Opcode(0x50 + value as u8),
        _ => {}
    }
    let mut magnitude = value.unsigned_abs();
    let mut bytes = Vec::new();
    while magnitude != 0 {
        bytes.push(magnitude as u8);
        magnitude >>= 8;
    }
    if bytes.last().is_some_and(|last| last & 0x80 != 0) {
        bytes.push(if value < 0 { 0x80 } else { 0 });
    } else if value < 0 {
        if let Some(last) = bytes.last_mut() {
            *last |= 0x80;
        }
    }
    WitnessItem::Data(bytes)
}

/// Return the ABI argument positions occupied by Schnorr signature slots.
/// Indices are zero-based and exclude the redeem script push.
pub fn signature_slot_indices(entrypoint: AbiEntryPoint) -> &'static [usize] {
    match entrypoint {
        AbiEntryPoint::AuthorizeChild => &[6],
        AbiEntryPoint::RegisterInterior => &[11, 13, 20],
        AbiEntryPoint::Issue => &[7],
        AbiEntryPoint::ChangeOwnerTarget => &[11, 14],
    }
}

/// Resolve witness signature positions for a frozen argument layout. The V6
/// named-reference form adds namespace and slug frames before the final parent
/// signature, moving that slot from 20 to 22. The stack shape is committed by
/// the registration plan, so unknown layouts fail closed.
pub fn signature_slot_indices_for_arguments(
    entrypoint: AbiEntryPoint,
    arguments: &[WitnessItem],
) -> Result<&'static [usize], &'static str> {
    match entrypoint {
        AbiEntryPoint::RegisterInterior if arguments.len() == 29 => Ok(&[11, 13, 22]),
        AbiEntryPoint::RegisterInterior if arguments.len() == 27 => Ok(&[11, 13, 20]),
        AbiEntryPoint::RegisterInterior => Err("WITNESS_ARGUMENT_LAYOUT_UNSUPPORTED"),
        _ => Ok(signature_slot_indices(entrypoint)),
    }
}

/// Build one post-Toccata P2SH scriptSig. This is the only production entry
/// point that serializes ABI pushes and appends the covenant redeem script.
pub fn build_toccata_p2sh_witness(
    entrypoint: AbiEntryPoint,
    arguments: &[WitnessItem],
    redeem_script: &[u8],
) -> Result<Vec<u8>, &'static str> {
    validate_abi_entrypoint(entrypoint)?;
    validate_signature_slots(entrypoint, arguments)?;
    if redeem_script.len() <= 255 || redeem_script.len() > u16::MAX as usize {
        return Err("WITNESS_REDEEM_SCRIPT_LENGTH_UNSUPPORTED");
    }
    let mut output = Vec::new();
    for item in arguments {
        match item {
            WitnessItem::Data(data) => push_data(&mut output, data)?,
            WitnessItem::Opcode(opcode) if is_allowed_small_opcode(*opcode) => output.push(*opcode),
            WitnessItem::Opcode(_) => return Err("WITNESS_OPCODE_UNSUPPORTED"),
        }
    }
    // P2SH redeem scripts are deliberately always encoded as PUSHDATA2. This
    // avoids legacy minimal-element policy from being mistaken for Toccata VM
    // consensus behavior when scripts exceed the historical 520-byte limit.
    output.push(0x4d);
    output.extend_from_slice(&(redeem_script.len() as u16).to_le_bytes());
    output.extend_from_slice(redeem_script);
    Ok(output)
}

/// Assemble a post-Toccata witness by replacing only the signature positions
/// declared by the frozen ABI. All serialization remains in
/// `build_toccata_p2sh_witness`, the sole P2SH construction path.
pub fn assemble_toccata_p2sh_witness(
    entrypoint: AbiEntryPoint,
    arguments: &[WitnessItem],
    redeem_script: &[u8],
    signatures: &[(usize, Vec<u8>)],
) -> Result<Vec<u8>, &'static str> {
    let slots = signature_slot_indices_for_arguments(entrypoint, arguments)?;
    if signatures.len() != slots.len() {
        return Err("WITNESS_SIGNATURE_SLOT_SET_MISMATCH");
    }
    let mut assembled = arguments.to_vec();
    let mut seen = std::collections::BTreeSet::new();
    for (slot, signature) in signatures {
        if !seen.insert(*slot) {
            return Err("WITNESS_SIGNATURE_SLOT_DUPLICATE");
        }
        if !slots.contains(slot) {
            return Err("WITNESS_SIGNATURE_SLOT_UNSUPPORTED");
        }
        if signature.len() != 65 || signature[64] != 1 {
            return Err("WITNESS_SIGNATURE_SLOT_INVALID");
        }
        let argument = assembled
            .get_mut(*slot)
            .ok_or("WITNESS_SIGNATURE_SLOT_SHAPE_MISMATCH")?;
        *argument = WitnessItem::Data(signature.clone());
    }
    if slots.iter().any(|slot| !seen.contains(slot)) {
        return Err("WITNESS_SIGNATURE_SLOT_SET_MISMATCH");
    }
    build_toccata_p2sh_witness(entrypoint, &assembled, redeem_script)
}

fn is_allowed_small_opcode(opcode: u8) -> bool {
    opcode == 0 || opcode == 0x4f || (0x51..=0x60).contains(&opcode)
}

fn push_data(output: &mut Vec<u8>, data: &[u8]) -> Result<(), &'static str> {
    if data.len() > u16::MAX as usize {
        return Err("WITNESS_ARGUMENT_LENGTH_UNSUPPORTED");
    }
    match data.len() {
        0 => output.push(0),
        1..=75 => output.push(data.len() as u8),
        76..=255 => {
            output.extend_from_slice(&[0x4c, data.len() as u8]);
        }
        length => {
            output.push(0x4d);
            output.extend_from_slice(&(length as u16).to_le_bytes());
        }
    }
    output.extend_from_slice(data);
    Ok(())
}

fn validate_abi_entrypoint(entrypoint: AbiEntryPoint) -> Result<(), &'static str> {
    let descriptor: serde_json::Value = serde_json::from_str(include_str!(
        "../../../data/registry/toccata-native-witness-abi-v1.json"
    ))
    .map_err(|_| "WITNESS_ABI_DESCRIPTOR_INVALID")?;
    let names = descriptor
        .get("entrypoints")
        .and_then(serde_json::Value::as_array)
        .ok_or("WITNESS_ABI_DESCRIPTOR_INVALID")?;
    if names.iter().any(|entry| {
        entry.get("name").and_then(serde_json::Value::as_str) == Some(entrypoint.name())
    }) {
        Ok(())
    } else {
        Err("WITNESS_ENTRYPOINT_UNSUPPORTED")
    }
}

fn validate_signature_slots(
    entrypoint: AbiEntryPoint,
    arguments: &[WitnessItem],
) -> Result<(), &'static str> {
    for index in signature_slot_indices_for_arguments(entrypoint, arguments)? {
        match arguments.get(*index) {
            Some(WitnessItem::Data(signature)) if signature.len() == 65 => {}
            _ => {
                return Err(match *index {
                    6 => "WITNESS_SIGNATURE_SLOT_SHAPE_MISMATCH_FIELD_6",
                    7 => "WITNESS_SIGNATURE_SLOT_SHAPE_MISMATCH_FIELD_7",
                    11 => "WITNESS_SIGNATURE_SLOT_SHAPE_MISMATCH_FIELD_11",
                    13 => "WITNESS_SIGNATURE_SLOT_SHAPE_MISMATCH_FIELD_13",
                    14 => "WITNESS_SIGNATURE_SLOT_SHAPE_MISMATCH_FIELD_14",
                    _ => "WITNESS_SIGNATURE_SLOT_SHAPE_MISMATCH",
                });
            }
        }
    }
    Ok(())
}
