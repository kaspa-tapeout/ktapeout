//! Static TN10 RPC admission list shared by target policies and native execution.
//! Membership permits an endpoint to be selected; live dual-node checks remain mandatory.

use std::collections::HashSet;

use serde_json::Value;

const REGISTRY: &str = include_str!("../../studio/tn10-node-registry.json");
const NODE_SCHEMA: &str = "KTAPEOUT-TN10-NODE-REGISTRY-V1";
const NETWORK: &str = "testnet-10";
const PROTOCOL_PATH: &str = "/kaspa/testnet-10/wrpc/borsh";

fn valid_host(host: &str) -> bool {
    let labels = host.split('.').collect::<Vec<_>>();
    labels.len() >= 2
        && labels.iter().all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .chars()
                    .next()
                    .is_some_and(|ch| ch.is_ascii_alphanumeric())
                && label
                    .chars()
                    .last()
                    .is_some_and(|ch| ch.is_ascii_alphanumeric())
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
        && labels.last().is_some_and(|label| {
            label.len() >= 2 && label.bytes().all(|byte| byte.is_ascii_lowercase())
        })
}

fn valid_node_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id.as_bytes()[0].is_ascii_lowercase()
        && id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn validate_registry(value: &Value) -> Result<(), String> {
    if value["schema"] != NODE_SCHEMA
        || value["network"] != NETWORK
        || value["protocol_path"] != PROTOCOL_PATH
        || value.as_object().is_none_or(|fields| {
            fields
                .keys()
                .any(|key| !["schema", "network", "protocol_path", "nodes"].contains(&key.as_str()))
        })
    {
        return Err("TN10_NODE_REGISTRY_INVALID".into());
    }
    let nodes = value["nodes"]
        .as_object()
        .ok_or_else(|| "TN10_NODE_REGISTRY_INVALID".to_string())?;
    if nodes.len() < 2 {
        return Err("TN10_NODE_REGISTRY_INVALID".into());
    }
    let mut hosts = HashSet::new();
    for (id, node) in nodes {
        let host = node["host"]
            .as_str()
            .ok_or_else(|| "TN10_NODE_REGISTRY_INVALID".to_string())?;
        if !valid_node_id(id)
            || node
                .as_object()
                .is_none_or(|fields| fields.len() != 1 || !fields.contains_key("host"))
            || !valid_host(host)
            || !hosts.insert(host)
        {
            return Err("TN10_NODE_REGISTRY_INVALID".into());
        }
    }
    Ok(())
}

fn registry() -> Result<Value, String> {
    let value: Value = serde_json::from_str(REGISTRY).map_err(|_| "TN10_NODE_REGISTRY_INVALID")?;
    validate_registry(&value)?;
    Ok(value)
}

pub fn node_ids() -> Result<Vec<String>, String> {
    let nodes = registry()?;
    let entries = nodes["nodes"]
        .as_object()
        .ok_or("TN10_NODE_REGISTRY_INVALID")?;
    let mut ids = entries.keys().cloned().collect::<Vec<_>>();
    ids.sort();
    Ok(ids)
}

pub fn is_registered_node_id(id: &str) -> bool {
    node_ids().is_ok_and(|ids| ids.iter().any(|registered| registered == id))
}

pub fn endpoint(id: &str) -> Result<String, String> {
    let nodes = registry()?;
    if !is_registered_node_id(id) {
        return Err("TN10_NODE_NOT_REGISTERED".into());
    }
    let host = nodes["nodes"][id]["host"]
        .as_str()
        .ok_or("TN10_NODE_REGISTRY_INVALID")?;
    Ok(format!("wss://{host}{PROTOCOL_PATH}"))
}

pub fn endpoint_node_id(endpoint: &str) -> Result<String, String> {
    for id in node_ids()? {
        if self::endpoint(&id)? == endpoint {
            return Ok(id);
        }
    }
    Err("TN10_ENDPOINT_NOT_REGISTERED".into())
}

pub fn validate_dual_node_ids(primary: &str, secondary: &str) -> Result<(), String> {
    if !is_registered_node_id(primary) || !is_registered_node_id(secondary) {
        return Err("TN10_NODE_NOT_REGISTERED".into());
    }
    if primary == secondary {
        return Err("TN10_DISTINCT_NODES_REQUIRED".into());
    }
    Ok(())
}

/// Resolve a configured pair of node IDs through the static TN10 registry.
/// Callers never need to accept arbitrary RPC URLs from operator settings.
pub fn dual_endpoints(primary: &str, secondary: &str) -> Result<[String; 2], String> {
    validate_dual_node_ids(primary, secondary)?;
    Ok([endpoint(primary)?, endpoint(secondary)?])
}

pub fn validate_dual_endpoints(endpoints: &[String]) -> Result<(), String> {
    if endpoints.len() != 2 {
        return Err("TN10_TWO_ENDPOINTS_REQUIRED".into());
    }
    let primary = endpoint_node_id(&endpoints[0])?;
    let secondary = endpoint_node_id(&endpoints[1])?;
    validate_dual_node_ids(&primary, &secondary)
}
