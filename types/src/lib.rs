//! Shared types for subs and subs-prover.

pub use libveritas_zk::guest::Commitment;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// A request for the next proof that needs to be generated.
///
/// This type is shared between the subs operator and the subs-prover.
#[derive(Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub enum ProvingRequest {
    Step {
        commitment_id: i64,
        idx: usize,
        prev_root: Option<String>,
        root: String,
        exclusion_proof: Vec<u8>,
        zk_batch: Vec<u8>,
    },
    Fold {
        commitment_id: i64,
        idx: usize,
        prev_root: Option<String>,
        root: String,
        acc_receipt: Vec<u8>,
        acc_commitment: Commitment,
        step_receipt: Vec<u8>,
        step_commitment: Commitment,
    },
}

impl ProvingRequest {
    pub fn commitment_id(&self) -> i64 {
        match self {
            ProvingRequest::Step { commitment_id, .. } => *commitment_id,
            ProvingRequest::Fold { commitment_id, .. } => *commitment_id,
        }
    }

    pub fn idx(&self) -> usize {
        match self {
            ProvingRequest::Step { idx, .. } => *idx,
            ProvingRequest::Fold { idx, .. } => *idx,
        }
    }
}

/// Input data needed for SNARK compression.
#[derive(Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct CompressInput {
    pub receipt: Vec<u8>,
    pub commitment: Commitment,
}
