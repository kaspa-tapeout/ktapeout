//! Complete-set validation for decoded V1 content readback.
//!
//! RPC inclusion, pinned-tip agreement, manifest-root verification and covenant
//! admission remain the caller's responsibility. This module does not establish
//! any of those facts from a set of locally supplied JSON records.

use crate::{
    decode_hex_bytes, encode_l1_content_chunk_050, encode_l1_content_state_050, err, Result,
};
use serde_json::Value;

/// Validate canonical records, identity, order, cardinality and aggregate size.
/// Returns the decoded content only after every chunk has passed verification.
/// Chunk boundaries need not be full sized; every chunk must be nonempty and
/// satisfy the existing V1 codec's 96 KiB bound.
pub fn verify_l1_content_chunk_set_050(state: &[u8], chunks: &[&[u8]]) -> Result<Vec<u8>> {
    encode_l1_content_state_050(state)?;
    let state: Value =
        serde_json::from_slice(state).map_err(|_| err("E050_CONTENT_SET: invalid state JSON"))?;
    let count = state["chunk_count"].as_u64().unwrap(); // validated by codec
    let total = state["total_bytes"].as_u64().unwrap();
    if chunks.len() as u64 != count || total == 0 {
        return Err(err("E050_CONTENT_SET: missing chunks or empty content"));
    }
    let mut bytes = Vec::with_capacity(total as usize);
    for (index, raw) in chunks.iter().enumerate() {
        encode_l1_content_chunk_050(raw)?;
        let chunk: Value =
            serde_json::from_slice(raw).map_err(|_| err("E050_CONTENT_SET: invalid chunk JSON"))?;
        if chunk["chunk_index"].as_u64() != Some(index as u64)
            || chunk["chunk_count"].as_u64() != Some(count)
        {
            return Err(err("E050_CONTENT_SET: chunk order or count mismatch"));
        }
        for field in [
            "application_id",
            "release_id",
            "artifact_root",
            "content_root",
        ] {
            if chunk[field] != state[field] {
                return Err(err("E050_CONTENT_SET: chunk identity mismatch"));
            }
        }
        let decoded = decode_hex_bytes(chunk["chunk_bytes"].as_str().unwrap(), "chunk_bytes")?;
        if bytes.len() as u64 + decoded.len() as u64 > total {
            return Err(err("E050_CONTENT_SET: aggregate byte count exceeded"));
        }
        bytes.extend_from_slice(&decoded);
    }
    if bytes.len() as u64 != total {
        return Err(err("E050_CONTENT_SET: aggregate byte count mismatch"));
    }
    Ok(bytes)
}
