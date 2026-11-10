//! Bounded public JSON; duplicate keys are rejected at every object depth.
use serde_json::Value;

pub fn parse(bytes: &[u8]) -> Result<Value, Box<dyn std::error::Error>> {
    parse_with_limit(bytes, 16384)
}

pub fn parse_with_limit(bytes: &[u8], limit: usize) -> Result<Value, Box<dyn std::error::Error>> {
    if bytes.len() > limit {
        return Err(format!("public input exceeds {limit} bytes").into());
    }
    ktapeout_core::parse_strict_json(bytes).map_err(|error| error.0.into())
}
