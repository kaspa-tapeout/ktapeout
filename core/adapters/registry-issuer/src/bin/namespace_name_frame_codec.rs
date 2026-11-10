//! Canonical presentation codec for named candidate frames; no legacy fallback.
use serde_json::Value;
use sha2::{Digest, Sha256};

pub fn frame(value: &Value) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let text = value.as_str().ok_or("canonical name frame hex required")?;
    let raw = hex::decode(text)?;
    if raw.len() != 64 || hex::encode(&raw) != text {
        return Err("64-byte lowercase name frame required".into());
    }
    let n = raw[0] as usize;
    if !(1..=63).contains(&n) || raw[n + 1..].iter().any(|b| *b != 0) {
        return Err("canonical length/padding required".into());
    }
    let slug = &raw[1..n + 1];
    if !slug[0].is_ascii_lowercase() && !slug[0].is_ascii_digit() {
        return Err("slug must start with lowercase letter/digit".into());
    }
    if slug
        .iter()
        .any(|b| !b.is_ascii_lowercase() && !b.is_ascii_digit() && *b != b'-')
    {
        return Err("canonical ASCII slug required".into());
    }
    Ok(raw)
}

pub fn namespace_hash(frame: &[u8]) -> Vec<u8> {
    Sha256::digest([b"KTAPEOUT/0.5.0/NAMESPACE_FRAME/V1\0\x0a".as_slice(), frame].concat()).to_vec()
}
pub fn name_key(namespace: &[u8], slug: &[u8]) -> Vec<u8> {
    Sha256::digest(
        [
            b"KTAPEOUT/0.5.0/NAME_FRAME/V1\0\x0a".as_slice(),
            namespace,
            slug,
        ]
        .concat(),
    )
    .to_vec()
}
