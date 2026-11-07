//! Recompute full block-body commitments. This alone does not prove acceptance.
//!
//! Extracted from the native block-body inclusion verifier. Caller-supplied
//! transaction IDs and verbose RPC fields are never used as proof conclusions.

use kaspa_consensus_core::{
    block::Block,
    config::params::Params,
    merkle::{calc_hash_merkle_root, calc_hash_merkle_root_pre_crescendo},
    network::{NetworkId, NetworkType},
    tx::TransactionId,
};
use kaspa_rpc_core::RpcBlock;

const MAX_TRANSACTIONS: usize = 16_384;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionProof {
    pub block_hash: String,
    pub transaction_id: String,
    pub transaction_index: usize,
    pub transaction_count: usize,
    pub merkle_root: String,
}

pub fn verify_block_inclusion(
    network: &str,
    expected_block_hash: &str,
    transaction_id: &str,
    rpc_block: &RpcBlock,
) -> Result<InclusionProof, String> {
    let network = match network {
        "mainnet" => NetworkId::new(NetworkType::Mainnet),
        "testnet-10" => NetworkId::with_suffix(NetworkType::Testnet, 10),
        _ => return Err("NETWORK_UNSUPPORTED".into()),
    };
    let params = Params::from(network);
    let canonical_hash = |value: &str, field: &str| -> Result<TransactionId, String> {
        let parsed: TransactionId = value.parse().map_err(|_| format!("{field}_INVALID"))?;
        if parsed.to_string() != value {
            return Err(format!("{field}_NON_CANONICAL"));
        }
        Ok(parsed)
    };
    let expected_hash = canonical_hash(expected_block_hash, "BLOCK_HASH")?;
    let expected_txid = canonical_hash(transaction_id, "TRANSACTION_ID")?;
    let transaction_count = rpc_block.transactions.len();
    if transaction_count == 0 || transaction_count > MAX_TRANSACTIONS {
        return Err("TRANSACTION_COUNT_LIMIT".into());
    }
    let block = Block::try_from(rpc_block.clone()).map_err(|_| "RPC_BLOCK_INVALID")?;
    if block.header.hash != expected_hash {
        return Err("BLOCK_HASH_MISMATCH".into());
    }
    let mut header = block.header.as_ref().clone();
    header.finalize();
    if header.hash != expected_hash {
        return Err("BLOCK_HEADER_HASH_MISMATCH".into());
    }
    let root = if params.crescendo_activation.is_active(header.daa_score) {
        calc_hash_merkle_root(block.transactions.iter())
    } else {
        calc_hash_merkle_root_pre_crescendo(block.transactions.iter())
    };
    if root != header.hash_merkle_root {
        return Err("TRANSACTION_MERKLE_ROOT_MISMATCH".into());
    }
    let transaction_index = block
        .transactions
        .iter()
        .position(|tx| tx.id() == expected_txid)
        .ok_or("TRANSACTION_NOT_IN_BLOCK_BODY")?;
    Ok(InclusionProof {
        block_hash: expected_hash.to_string(),
        transaction_id: expected_txid.to_string(),
        transaction_index,
        transaction_count,
        merkle_root: root.to_string(),
    })
}
