//! Profile-specific ProjectModel V2 -> KTB1 parity checks for local handoff.
//! This module is developer tooling, not consensus/Core protocol semantics.
use ktapeout_runtime::{canonical_json, digest_json, validate_developer_lock};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

const BUNDLE_SCHEMA: &str = "KTAPEOUT-STUDIO-RUNTIME-BUNDLE-V1";
const BUNDLE_DOMAIN: &str = "KTAPEOUT/0.5.0/STUDIO_RUNTIME_BUNDLE/V1";
const IR_DOMAIN: &str = "KTAPEOUT/0.5.0/STUDIO_GRAPH_SEMANTIC_IR/V2";

#[derive(Debug)]
pub struct VerifiedBundle {
    pub profile_id: String,
    pub project_id: String,
    pub project_hash: String,
    pub semantic_ir_hash: String,
    pub compiler_lock_hash: String,
    pub developer_lock_hash: Option<String>,
    pub artifact_hash: String,
    pub artifact_bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
struct Node {
    id: String,
    kind: String,
    params: Value,
    ports: Value,
    state: Value,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
struct Endpoint {
    node: String,
    port: String,
}

fn fail(code: &str) -> String {
    code.to_string()
}
fn raw_sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
fn object<'a>(value: &'a Value, code: &str) -> Result<&'a Map<String, Value>, String> {
    value.as_object().ok_or_else(|| fail(code))
}
fn exact_keys(value: &Value, keys: &[&str], code: &str) -> Result<(), String> {
    let map = object(value, code)?;
    let expected: BTreeSet<&str> = keys.iter().copied().collect();
    if map.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected {
        return Err(fail(code));
    }
    Ok(())
}
fn text<'a>(value: &'a Value, code: &str) -> Result<&'a str, String> {
    value
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| fail(code))
}
fn is_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && bytes[0].is_ascii_alphabetic()
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_' || *byte == b'-')
}
pub(crate) fn project_design(project: &Value) -> Result<Value, String> {
    exact_keys(
        project,
        &[
            "schema",
            "protocol_semver",
            "project_id",
            "profile",
            "profile_version",
            "revision",
            "parent_revision",
            "design",
            "tests",
            "layout",
            "publish_intent",
        ],
        "PROJECT_FIELDS_INVALID",
    )?;
    if project.get("schema").and_then(Value::as_str) != Some("KTAPEOUT-PROJECT-V2")
        || project.get("protocol_semver").and_then(Value::as_str) != Some("0.5.0")
        || project
            .get("publish_intent")
            .and_then(|v| v.get("network"))
            .and_then(Value::as_str)
            != Some("testnet-10")
    {
        return Err(fail("PROJECT_IDENTITY_INVALID"));
    }
    let intent = project
        .get("publish_intent")
        .ok_or_else(|| fail("PROJECT_IDENTITY_INVALID"))?;
    let profile_status = intent
        .get("profile_status")
        .and_then(Value::as_str)
        .ok_or_else(|| fail("PROJECT_IDENTITY_INVALID"))?;
    let design = project
        .get("design")
        .ok_or_else(|| fail("PROJECT_DESIGN_INVALID"))?;
    exact_keys(
        design,
        &["nodes", "connections", "parameters", "modules"],
        "PROJECT_DESIGN_INVALID",
    )?;
    let nodes = design
        .get("nodes")
        .and_then(Value::as_array)
        .ok_or_else(|| fail("PROJECT_NODES_INVALID"))?;
    let connections = design
        .get("connections")
        .and_then(Value::as_array)
        .ok_or_else(|| fail("PROJECT_CONNECTIONS_INVALID"))?;
    if !design.get("parameters").is_some_and(Value::is_object) {
        return Err(fail("PROJECT_PARAMETERS_INVALID"));
    }
    let modules = design
        .get("modules")
        .filter(|value| value.is_array())
        .ok_or_else(|| fail("PROJECT_MODULES_INVALID"))?;
    let tests = project
        .get("tests")
        .filter(|value| value.is_array())
        .ok_or_else(|| fail("PROJECT_TESTS_INVALID"))?;
    if nodes.len() > 1000
        || connections.len() > 2000
        || modules.as_array().is_none_or(|items| items.len() > 256)
        || tests.as_array().is_none_or(|items| items.len() > 10000)
    {
        return Err(fail("PROJECT_BOUNDS_EXCEEDED"));
    }
    Ok(json!({
        "schema": "KTAPEOUT-PROJECT-V2", "protocol_semver": "0.5.0",
        "project_id": project.get("project_id").ok_or_else(|| fail("PROJECT_IDENTITY_INVALID"))?,
        "profile": project.get("profile").ok_or_else(|| fail("PROJECT_IDENTITY_INVALID"))?,
        "profile_version": project.get("profile_version").ok_or_else(|| fail("PROJECT_IDENTITY_INVALID"))?,
        "design": design, "tests": tests,
        "publish_intent": {"network": "testnet-10", "profile_status": profile_status}
    }))
}

fn expected_ports(kind: &str) -> Option<Vec<(&'static str, &'static str)>> {
    match kind {
        "Input" => Some(vec![("out", "out")]),
        "NAND" => Some(vec![("a", "in"), ("b", "in"), ("out", "out")]),
        "Register" => Some(vec![("in", "in"), ("out", "out")]),
        "Output" => Some(vec![("in", "in")]),
        _ => None,
    }
}

type ParsedNodes = (
    BTreeMap<String, Node>,
    Vec<String>,
    Vec<String>,
    Vec<String>,
    Vec<String>,
);

fn parse_nodes(project: &Value) -> Result<ParsedNodes, String> {
    let values = project["design"]["nodes"]
        .as_array()
        .ok_or_else(|| fail("PROJECT_NODES_INVALID"))?;
    let mut nodes = BTreeMap::new();
    let mut inputs = Vec::new();
    let mut gates = Vec::new();
    let mut registers = Vec::new();
    let mut outputs = Vec::new();
    for value in values {
        let fields = object(value, "PROJECT_NODE_INVALID")?;
        if fields
            .keys()
            .any(|key| !["id", "kind", "params", "ports", "state"].contains(&key.as_str()))
            || !["id", "kind", "params", "ports"]
                .iter()
                .all(|key| fields.contains_key(*key))
        {
            return Err(fail("PROJECT_NODE_INVALID"));
        }
        let id = text(&value["id"], "PROJECT_NODE_ID_INVALID")?.to_string();
        if !is_id(&id) {
            return Err(fail("PROJECT_NODE_ID_INVALID"));
        }
        let kind = text(&value["kind"], "PROJECT_NODE_KIND_INVALID")?.to_string();
        if expected_ports(&kind).is_none() {
            return Err(fail("PROFILE_NODE_UNSUPPORTED"));
        }
        let params = value
            .get("params")
            .filter(|item| item.is_object())
            .ok_or_else(|| fail("PROJECT_NODE_PARAMS_INVALID"))?
            .clone();
        let ports = value
            .get("ports")
            .filter(|item| item.is_object())
            .ok_or_else(|| fail("PROJECT_NODE_PORTS_INVALID"))?
            .clone();
        if let Some(state) = value.get("state") {
            if !state.is_null() {
                return Err(fail("PROFILE_NODE_STATE_UNSUPPORTED"));
            }
        }
        let expected = expected_ports(&kind).ok_or_else(|| fail("PROFILE_NODE_UNSUPPORTED"))?;
        let port_object = ports
            .as_object()
            .ok_or_else(|| fail("PROJECT_NODE_PORTS_INVALID"))?;
        if port_object.len() != expected.len() {
            return Err(fail("PROJECT_NODE_PORTS_INVALID"));
        }
        for (name, direction) in expected {
            let spec = ports
                .get(name)
                .ok_or_else(|| fail("PROJECT_NODE_PORTS_INVALID"))?;
            let port = object(spec, "PROJECT_PORT_INVALID")?;
            if port
                .keys()
                .any(|key| !["direction", "type", "required"].contains(&key.as_str()))
                || port.get("direction").and_then(Value::as_str) != Some(direction)
                || port.get("type").and_then(Value::as_str) != Some("Bit")
                || port
                    .get("required")
                    .is_some_and(|required| !required.is_boolean())
            {
                return Err(fail("PROJECT_PORT_INVALID"));
            }
        }
        match kind.as_str() {
            "Input" => {
                if !params
                    .as_object()
                    .ok_or_else(|| fail("PROJECT_NODE_PARAMS_INVALID"))?
                    .is_empty()
                {
                    return Err(fail("PROFILE_NODE_PARAMS_UNSUPPORTED"));
                }
                inputs.push(id.clone());
            }
            "NAND" => {
                if !params
                    .as_object()
                    .ok_or_else(|| fail("PROJECT_NODE_PARAMS_INVALID"))?
                    .is_empty()
                {
                    return Err(fail("PROFILE_NODE_PARAMS_UNSUPPORTED"));
                }
                gates.push(id.clone());
            }
            "Register" => {
                exact_keys(&params, &["slot"], "REGISTER_PARAMS_INVALID")?;
                let slot = params["slot"]
                    .as_u64()
                    .filter(|slot| *slot < 4096)
                    .ok_or_else(|| fail("REGISTER_SLOT_INVALID"))?;
                if slot > u16::MAX as u64 {
                    return Err(fail("REGISTER_SLOT_INVALID"));
                }
                registers.push(id.clone());
            }
            "Output" => {
                if !params
                    .as_object()
                    .ok_or_else(|| fail("PROJECT_NODE_PARAMS_INVALID"))?
                    .is_empty()
                {
                    return Err(fail("PROFILE_NODE_PARAMS_UNSUPPORTED"));
                }
                outputs.push(id.clone());
            }
            _ => unreachable!(),
        }
        let state = value.get("state").cloned().unwrap_or(Value::Null);
        if nodes
            .insert(
                id,
                Node {
                    id: text(&value["id"], "PROJECT_NODE_ID_INVALID")?.to_string(),
                    kind,
                    params,
                    ports,
                    state,
                },
            )
            .is_some()
        {
            return Err(fail("PROJECT_NODE_ID_DUPLICATE"));
        }
    }
    inputs.sort();
    gates.sort();
    registers.sort();
    outputs.sort();
    if inputs.is_empty()
        || registers.is_empty()
        || outputs.is_empty()
        || inputs.len() > 64
        || registers.len() > 64
        || outputs.len() > 64
        || gates.len() + registers.len() > 256
    {
        return Err(fail("PROFILE_DIMENSIONS_INVALID"));
    }
    Ok((nodes, inputs, gates, registers, outputs))
}
fn endpoint(value: &Value) -> Result<Endpoint, String> {
    exact_keys(value, &["node", "port"], "PROJECT_ENDPOINT_INVALID")?;
    let node = text(&value["node"], "PROJECT_ENDPOINT_INVALID")?.to_string();
    let port = text(&value["port"], "PROJECT_ENDPOINT_INVALID")?.to_string();
    if !is_id(&node) || !is_id(&port) {
        return Err(fail("PROJECT_ENDPOINT_INVALID"));
    }
    Ok(Endpoint { node, port })
}
fn parse_edges(
    project: &Value,
    nodes: &BTreeMap<String, Node>,
) -> Result<HashMap<(String, String), Endpoint>, String> {
    let mut incoming = HashMap::new();
    let connections = project["design"]["connections"]
        .as_array()
        .ok_or_else(|| fail("PROJECT_CONNECTIONS_INVALID"))?;
    for edge in connections {
        exact_keys(edge, &["from", "to"], "PROJECT_CONNECTION_INVALID")?;
        let from = endpoint(&edge["from"])?;
        let to = endpoint(&edge["to"])?;
        let source = nodes
            .get(&from.node)
            .ok_or_else(|| fail("PROJECT_ENDPOINT_UNKNOWN"))?;
        let target = nodes
            .get(&to.node)
            .ok_or_else(|| fail("PROJECT_ENDPOINT_UNKNOWN"))?;
        if source
            .ports
            .get(&from.port)
            .and_then(|v| v.get("direction"))
            .and_then(Value::as_str)
            != Some("out")
            || target
                .ports
                .get(&to.port)
                .and_then(|v| v.get("direction"))
                .and_then(Value::as_str)
                != Some("in")
            || source.ports.get(&from.port).and_then(|v| v.get("type"))
                != target.ports.get(&to.port).and_then(|v| v.get("type"))
        {
            return Err(fail("PROJECT_CONNECTION_TYPE_INVALID"));
        }
        if incoming
            .insert((to.node.clone(), to.port.clone()), from)
            .is_some()
        {
            return Err(fail("PROJECT_INPUT_MULTIPLE_DRIVERS"));
        }
    }
    for node in nodes.values() {
        let required: &[&str] = match node.kind.as_str() {
            "NAND" => &["a", "b"],
            "Register" | "Output" => &["in"],
            _ => &[],
        };
        for port in required {
            if !incoming.contains_key(&(node.id.clone(), (*port).to_string())) {
                return Err(fail("PROJECT_INPUT_UNCONNECTED"));
            }
        }
    }
    Ok(incoming)
}
fn visit(
    id: &str,
    inputs: &HashSet<String>,
    nodes: &BTreeMap<String, Node>,
    incoming: &HashMap<(String, String), Endpoint>,
    visiting: &mut HashSet<String>,
    visited: &mut HashSet<String>,
    ordered: &mut Vec<String>,
) -> Result<(), String> {
    if visited.contains(id) {
        return Ok(());
    }
    if !visiting.insert(id.to_string()) {
        return Err(fail("PROFILE_COMBINATIONAL_CYCLE"));
    }
    let node = nodes.get(id).ok_or_else(|| fail("PROJECT_NODE_UNKNOWN"))?;
    if node.kind == "NAND" {
        for port in ["a", "b"] {
            let source = incoming
                .get(&(id.to_string(), port.to_string()))
                .ok_or_else(|| fail("PROJECT_INPUT_UNCONNECTED"))?;
            if !inputs.contains(&source.node) {
                visit(
                    &source.node,
                    inputs,
                    nodes,
                    incoming,
                    visiting,
                    visited,
                    ordered,
                )?;
            }
        }
    }
    visiting.remove(id);
    visited.insert(id.to_string());
    ordered.push(id.to_string());
    Ok(())
}
fn signal(
    source: &Endpoint,
    input_index: &HashMap<String, usize>,
    indices: &HashMap<String, usize>,
) -> Result<usize, String> {
    if let Some(index) = input_index.get(&source.node) {
        return Ok(*index);
    }
    indices
        .get(&source.node)
        .copied()
        .ok_or_else(|| fail("PROFILE_SIGNAL_UNAVAILABLE"))
}
fn push_varint(mut value: usize, out: &mut Vec<u8>) {
    loop {
        let more = value >= 0x80;
        out.push(((value & 0x7f) as u8) | if more { 0x80 } else { 0 });
        value >>= 7;
        if !more {
            break;
        }
    }
}
fn compile_machine(project: &Value) -> Result<(Vec<u8>, String, String), String> {
    let profile = text(&project["profile"], "PROJECT_PROFILE_INVALID")?;
    if !["Machine", "BoundedStateMachine"].contains(&profile)
        || text(
            &project["profile_version"],
            "PROJECT_PROFILE_VERSION_INVALID",
        )? != "1"
    {
        return Err(fail("PROFILE_NOT_SUPPORTED"));
    }
    let design = &project["design"];
    if !design["parameters"].as_object().is_some_and(Map::is_empty)
        || !design["modules"].as_array().is_some_and(Vec::is_empty)
    {
        return Err(fail("PROFILE_PROJECT_FEATURE_UNSUPPORTED"));
    }
    let (nodes, inputs, gates, registers, outputs) = parse_nodes(project)?;
    let incoming = parse_edges(project, &nodes)?;
    let input_set: HashSet<String> = inputs.iter().cloned().collect();
    let mut ordered = Vec::new();
    let mut visiting = HashSet::new();
    let mut visited = HashSet::new();
    for id in gates.iter().chain(registers.iter()).chain(outputs.iter()) {
        visit(
            id,
            &input_set,
            &nodes,
            &incoming,
            &mut visiting,
            &mut visited,
            &mut ordered,
        )?;
    }
    let operation_nodes: Vec<String> = ordered
        .iter()
        .filter(|id| matches!(nodes[*id].kind.as_str(), "NAND" | "Register"))
        .cloned()
        .collect();
    if operation_nodes.is_empty() || operation_nodes.len() > 256 {
        return Err(fail("PROFILE_OPERATION_BOUNDS"));
    }
    let input_index: HashMap<String, usize> = inputs
        .iter()
        .enumerate()
        .map(|(index, id)| (id.clone(), index))
        .collect();
    let mut indices = HashMap::new();
    for (position, id) in operation_nodes.iter().enumerate() {
        indices.insert(id.clone(), inputs.len() + position);
    }
    let mut bytes = b"KTB1\x01\x00".to_vec();
    push_varint(inputs.len(), &mut bytes);
    push_varint(operation_nodes.len(), &mut bytes);
    push_varint(outputs.len(), &mut bytes);
    push_varint(registers.len(), &mut bytes);
    let mut register_mappings: Vec<(u64, usize, usize)> = Vec::new();
    for id in &ordered {
        let node = &nodes[id];
        match node.kind.as_str() {
            "NAND" => {
                let left = incoming
                    .get(&(id.clone(), "a".to_string()))
                    .ok_or_else(|| fail("PROJECT_INPUT_UNCONNECTED"))?;
                let right = incoming
                    .get(&(id.clone(), "b".to_string()))
                    .ok_or_else(|| fail("PROJECT_INPUT_UNCONNECTED"))?;
                bytes.push(0);
                push_varint(signal(left, &input_index, &indices)?, &mut bytes);
                push_varint(signal(right, &input_index, &indices)?, &mut bytes);
            }
            "Register" => {
                let slot = node.params["slot"]
                    .as_u64()
                    .ok_or_else(|| fail("REGISTER_SLOT_INVALID"))?;
                let register_signal = *indices
                    .get(id)
                    .ok_or_else(|| fail("PROFILE_SIGNAL_UNAVAILABLE"))?;
                let source = incoming
                    .get(&(id.clone(), "in".to_string()))
                    .ok_or_else(|| fail("PROJECT_INPUT_UNCONNECTED"))?;
                bytes.push(1);
                register_mappings.push((
                    slot,
                    register_signal,
                    signal(source, &input_index, &indices)?,
                ));
            }
            "Output" => {
                let source = incoming
                    .get(&(id.clone(), "in".to_string()))
                    .ok_or_else(|| fail("PROJECT_INPUT_UNCONNECTED"))?;
                indices.insert(id.clone(), signal(source, &input_index, &indices)?);
            }
            "Input" => {}
            _ => return Err(fail("PROFILE_NODE_UNSUPPORTED")),
        }
    }
    for id in &outputs {
        let source = incoming
            .get(&(id.clone(), "in".to_string()))
            .ok_or_else(|| fail("PROJECT_INPUT_UNCONNECTED"))?;
        push_varint(signal(source, &input_index, &indices)?, &mut bytes);
    }
    register_mappings.sort_by_key(|entry| entry.0);
    let slots: BTreeSet<u64> = register_mappings.iter().map(|entry| entry.0).collect();
    if slots.len() != register_mappings.len() {
        return Err(fail("REGISTER_SLOT_DUPLICATE"));
    }
    for (_, register_signal, source) in register_mappings {
        push_varint(register_signal, &mut bytes);
        push_varint(source, &mut bytes);
    }

    let mut semantic_nodes = Vec::new();
    for node in nodes.values() {
        let params: Value = serde_json::from_slice(
            &canonical_json(&node.params).map_err(|_| fail("SEMANTIC_IR_ENCODE_ERROR"))?,
        )
        .map_err(|_| fail("SEMANTIC_IR_ENCODE_ERROR"))?;
        let ports: Value = serde_json::from_slice(
            &canonical_json(&node.ports).map_err(|_| fail("SEMANTIC_IR_ENCODE_ERROR"))?,
        )
        .map_err(|_| fail("SEMANTIC_IR_ENCODE_ERROR"))?;
        semantic_nodes.push(
            json!({"id":node.id,"kind":node.kind,"ports":ports,"params":params,"state":node.state}),
        );
    }
    let mut semantic_connections = design["connections"]
        .as_array()
        .ok_or_else(|| fail("PROJECT_CONNECTIONS_INVALID"))?
        .clone();
    semantic_connections.sort_by_key(|edge| canonical_json(edge).unwrap_or_default());
    let ir = json!({"schema":"KTAPEOUT-SEMANTIC-IR-V2","profile":profile,"profile_version":project["profile_version"],"nodes":semantic_nodes,"connections":semantic_connections,"parameters":design["parameters"],"modules":design["modules"],"tests":project["tests"]});
    let semantic_hash = digest_json(&ir, IR_DOMAIN).map_err(|_| fail("SEMANTIC_IR_HASH_ERROR"))?;
    let project_material = project_design(project)?;
    let project_hash =
        raw_sha256(&canonical_json(&project_material).map_err(|_| fail("PROJECT_HASH_ERROR"))?);
    Ok((bytes, semantic_hash, project_hash))
}

pub fn verify_bundle(bundle: &Value) -> Result<VerifiedBundle, String> {
    exact_keys(
        bundle,
        &[
            "schema",
            "protocol_semver",
            "project_id",
            "project_sha256",
            "profile_id",
            "profile_version",
            "semantic_ir_hash",
            "developer_lock",
            "developer_lock_hash",
            "compiler_lock_hash",
            "artifact_format",
            "artifact_sha256",
            "artifact_bytes_hex",
            "bundle_hash",
            "project",
        ],
        "RUNTIME_BUNDLE_FIELDS_INVALID",
    )?;
    if bundle["schema"].as_str() != Some(BUNDLE_SCHEMA)
        || bundle["protocol_semver"].as_str() != Some("0.5.0")
        || bundle["artifact_format"].as_str() != Some("KTB1-v1")
    {
        return Err(fail("RUNTIME_BUNDLE_IDENTITY_INVALID"));
    }
    let project = &bundle["project"];
    let project_id = text(&project["project_id"], "PROJECT_IDENTITY_INVALID")?.to_string();
    let profile_id = text(&project["profile"], "PROJECT_PROFILE_INVALID")?.to_string();
    let profile_version = text(
        &project["profile_version"],
        "PROJECT_PROFILE_VERSION_INVALID",
    )?
    .to_string();
    if bundle["project_id"].as_str() != Some(project_id.as_str())
        || bundle["profile_id"].as_str() != Some(profile_id.as_str())
        || bundle["profile_version"].as_str() != Some(profile_version.as_str())
    {
        return Err(fail("RUNTIME_BUNDLE_PROJECT_BINDING_MISMATCH"));
    }
    let project_material = project_design(project)?;
    let project_hash =
        raw_sha256(&canonical_json(&project_material).map_err(|_| fail("PROJECT_HASH_ERROR"))?);
    if bundle["project_sha256"].as_str() != Some(project_hash.as_str()) {
        return Err(fail("PROJECT_HASH_MISMATCH"));
    }
    let (expected_artifact, semantic_ir_hash, compiled_project_hash) = compile_machine(project)?;
    if compiled_project_hash != project_hash {
        return Err(fail("PROJECT_HASH_MISMATCH"));
    }
    if bundle["semantic_ir_hash"].as_str() != Some(semantic_ir_hash.as_str()) {
        return Err(fail("SEMANTIC_IR_HASH_MISMATCH"));
    }
    let (developer_lock, developer_lock_hash) =
        match (&bundle["developer_lock"], &bundle["developer_lock_hash"]) {
            (Value::Null, Value::Null) => (None, None),
            (lock, Value::String(expected)) => {
                validate_developer_lock(lock).map_err(|_| fail("DEVELOPER_LOCK_INVALID"))?;
                let actual = lock
                    .get("lock_hash")
                    .and_then(Value::as_str)
                    .ok_or_else(|| fail("DEVELOPER_LOCK_INVALID"))?
                    .to_string();
                if actual != *expected {
                    return Err(fail("DEVELOPER_LOCK_HASH_MISMATCH"));
                }
                let profiles = lock["profiles"]
                    .as_array()
                    .ok_or_else(|| fail("DEVELOPER_LOCK_PROFILE_INVALID"))?;
                if profiles
                    .iter()
                    .filter(|entry| entry["profile_id"].as_str() == Some(profile_id.as_str()))
                    .count()
                    != 1
                {
                    return Err(fail("DEVELOPER_LOCK_PROFILE_MISMATCH"));
                }
                (Some(lock), Some(actual))
            }
            _ => return Err(fail("DEVELOPER_LOCK_BINDING_INVALID")),
        };
    let compiler_material = json!({"schema":"KTAPEOUT-COMPILER-LOCK-BINDING-V1","profile":profile_id,"profile_version":profile_version,"semantic_ir_hash":semantic_ir_hash,"compiler_lock_hash":null,"developer_lock_hash":developer_lock_hash});
    let compiler_lock_hash = raw_sha256(
        &canonical_json(&compiler_material).map_err(|_| fail("COMPILER_LOCK_HASH_ERROR"))?,
    );
    if bundle["compiler_lock_hash"].as_str() != Some(compiler_lock_hash.as_str()) {
        return Err(fail("COMPILER_LOCK_HASH_MISMATCH"));
    }
    let hex = text(&bundle["artifact_bytes_hex"], "ARTIFACT_HEX_INVALID")?;
    if hex.len() % 2 != 0
        || hex.len() > 512 * 1024
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(fail("ARTIFACT_HEX_INVALID"));
    }
    let artifact_bytes: Vec<u8> = hex
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| -> Result<u8, String> {
            Ok(((pair[0] as char)
                .to_digit(16)
                .ok_or_else(|| fail("ARTIFACT_HEX_INVALID"))?
                * 16
                + (pair[1] as char)
                    .to_digit(16)
                    .ok_or_else(|| fail("ARTIFACT_HEX_INVALID"))?) as u8)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if expected_artifact != artifact_bytes {
        return Err(fail("ARTIFACT_COMPILER_PARITY_MISMATCH"));
    }
    let artifact_hash = raw_sha256(&artifact_bytes);
    if bundle["artifact_sha256"].as_str() != Some(artifact_hash.as_str()) {
        return Err(fail("ARTIFACT_HASH_MISMATCH"));
    }
    let bundle_hash = bundle["bundle_hash"]
        .as_str()
        .ok_or_else(|| fail("RUNTIME_BUNDLE_HASH_INVALID"))?;
    let mut material = bundle.clone();
    material
        .as_object_mut()
        .ok_or_else(|| fail("RUNTIME_BUNDLE_HASH_INVALID"))?
        .remove("bundle_hash");
    let expected_bundle_hash =
        digest_json(&material, BUNDLE_DOMAIN).map_err(|_| fail("RUNTIME_BUNDLE_HASH_ERROR"))?;
    if bundle_hash != expected_bundle_hash {
        return Err(fail("RUNTIME_BUNDLE_HASH_MISMATCH"));
    }
    let _ = developer_lock;
    Ok(VerifiedBundle {
        profile_id,
        project_id,
        project_hash,
        semantic_ir_hash,
        compiler_lock_hash,
        developer_lock_hash,
        artifact_hash,
        artifact_bytes,
    })
}

/// Build the profile-specific local runtime bundle consumed by
/// `ktape artifact simulate-project`.
///
/// This is deliberately a developer-tool operation. It binds the exact
/// ProjectModel V2, compiler-derived KTB1 bytes and optional Developer Lock;
/// it does not create an admitted application package, a transaction, a
/// signer request or an L1 receipt.
pub fn build_bundle(project: &Value, developer_lock: Option<&Value>) -> Result<Value, String> {
    let (artifact_bytes, semantic_ir_hash, project_hash) = compile_machine(project)?;
    let project_id = text(&project["project_id"], "PROJECT_IDENTITY_INVALID")?;
    let profile_id = text(&project["profile"], "PROJECT_PROFILE_INVALID")?;
    let profile_version = text(
        &project["profile_version"],
        "PROJECT_PROFILE_VERSION_INVALID",
    )?;

    let (lock_value, developer_lock_hash) = match developer_lock {
        None => (Value::Null, Value::Null),
        Some(lock) => {
            validate_developer_lock(lock).map_err(|_| fail("DEVELOPER_LOCK_INVALID"))?;
            let lock_hash = lock
                .get("lock_hash")
                .and_then(Value::as_str)
                .ok_or_else(|| fail("DEVELOPER_LOCK_INVALID"))?;
            let profiles = lock
                .get("profiles")
                .and_then(Value::as_array)
                .ok_or_else(|| fail("DEVELOPER_LOCK_PROFILE_INVALID"))?;
            if profiles
                .iter()
                .filter(|entry| entry.get("profile_id").and_then(Value::as_str) == Some(profile_id))
                .count()
                != 1
            {
                return Err(fail("DEVELOPER_LOCK_PROFILE_MISMATCH"));
            }
            (lock.clone(), Value::String(lock_hash.to_string()))
        }
    };
    let compiler_material = json!({
        "schema": "KTAPEOUT-COMPILER-LOCK-BINDING-V1",
        "profile": profile_id,
        "profile_version": profile_version,
        "semantic_ir_hash": semantic_ir_hash,
        "compiler_lock_hash": null,
        "developer_lock_hash": developer_lock_hash,
    });
    let compiler_lock_hash = raw_sha256(
        &canonical_json(&compiler_material).map_err(|_| fail("COMPILER_LOCK_HASH_ERROR"))?,
    );
    let artifact_hash = raw_sha256(&artifact_bytes);
    let mut bundle = json!({
        "schema": BUNDLE_SCHEMA,
        "protocol_semver": "0.5.0",
        "project_id": project_id,
        "project_sha256": project_hash,
        "profile_id": profile_id,
        "profile_version": profile_version,
        "semantic_ir_hash": compiler_material["semantic_ir_hash"],
        "developer_lock": lock_value,
        "developer_lock_hash": compiler_material["developer_lock_hash"],
        "compiler_lock_hash": compiler_lock_hash,
        "artifact_format": "KTB1-v1",
        "artifact_sha256": artifact_hash,
        "artifact_bytes_hex": artifact_bytes.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
        "bundle_hash": null,
        "project": project,
    });
    let mut bundle_material = bundle.clone();
    bundle_material
        .as_object_mut()
        .ok_or_else(|| fail("RUNTIME_BUNDLE_SHAPE_INVALID"))?
        .remove("bundle_hash");
    let bundle_hash = digest_json(&bundle_material, BUNDLE_DOMAIN)
        .map_err(|_| fail("RUNTIME_BUNDLE_HASH_ERROR"))?;
    bundle["bundle_hash"] = Value::String(bundle_hash);
    verify_bundle(&bundle)?;
    Ok(bundle)
}
