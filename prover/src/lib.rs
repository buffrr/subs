//! ZK prover library for subs.
//!
//! Provides the `Prover` struct for generating STARK proofs and SNARK compression.

pub mod server;

use anyhow::{anyhow, Result};
use libveritas::constants::{FOLD_ELF, FOLD_ID, STEP_ELF, STEP_ID};
use libveritas_zk::guest::Commitment;
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts, Receipt};
use subs_types::{CompressInput, ProvingRequest};

/// External prover for generating ZK proofs.
///
/// Handles both Step and Fold proving requests. Use this with
/// `Operator::get_next_proving_request()` and `Operator::fulfill_request()`.
///
/// # Example
/// ```ignore
/// use subs_prover::Prover;
///
/// let prover = Prover::new();
/// while let Some(request) = operator.get_next_proving_request(&space).await? {
///     let receipt = prover.prove(&request)?;
///     operator.fulfill_request(&space, &request, &receipt).await?;
/// }
/// ```
pub struct Prover;

impl Prover {
    pub fn new() -> Self {
        Self
    }

    /// Prove a ProvingRequest and return the serialized receipt.
    pub fn prove(&self, request: &ProvingRequest) -> Result<Vec<u8>> {
        match request {
            ProvingRequest::Step {
                idx,
                exclusion_proof,
                zk_batch,
                ..
            } => self.prove_step(*idx, exclusion_proof, zk_batch),
            ProvingRequest::Fold {
                idx,
                acc_receipt,
                acc_commitment,
                step_receipt,
                step_commitment,
                ..
            } => self.prove_fold(
                *idx,
                acc_receipt,
                acc_commitment,
                step_receipt,
                step_commitment,
            ),
        }
    }

    fn prove_step(&self, idx: usize, exclusion_proof: &[u8], zk_batch: &[u8]) -> Result<Vec<u8>> {
        let env = ExecutorEnv::builder()
            .write(&(
                exclusion_proof.to_vec(),
                zk_batch.to_vec(),
                STEP_ID,
                FOLD_ID,
            ))
            .map_err(|e| anyhow!("[#{}] env write: {}", idx, e))?
            .build()
            .map_err(|e| anyhow!("[#{}] env build: {}", idx, e))?;

        let prove_info = default_prover()
            .prove_with_opts(env, STEP_ELF, &ProverOpts::succinct())
            .map_err(|e| anyhow!("[#{}] prove step failed: {}", idx, e))?;

        let receipt_bytes = borsh::to_vec(&prove_info.receipt)
            .map_err(|e| anyhow!("[#{}] serialize receipt: {}", idx, e))?;

        Ok(receipt_bytes)
    }

    fn prove_fold(
        &self,
        idx: usize,
        acc_receipt: &[u8],
        acc_commitment: &Commitment,
        step_receipt: &[u8],
        step_commitment: &Commitment,
    ) -> Result<Vec<u8>> {
        let acc: Receipt = borsh::from_slice(acc_receipt)
            .map_err(|e| anyhow!("deserialize acc receipt: {}", e))?;
        let step: Receipt = borsh::from_slice(step_receipt)
            .map_err(|e| anyhow!("deserialize step receipt: {}", e))?;

        let env = ExecutorEnv::builder()
            .add_assumption(acc)
            .add_assumption(step)
            .write(&(acc_commitment.clone(), Some(step_commitment.clone())))
            .map_err(|e| anyhow!("[#{}] env write: {}", idx, e))?
            .build()
            .map_err(|e| anyhow!("[#{}] env build: {}", idx, e))?;

        let prove_info = default_prover()
            .prove_with_opts(env, FOLD_ELF, &ProverOpts::succinct())
            .map_err(|e| anyhow!("[#{}] fold prove failed: {}", idx, e))?;

        let receipt_bytes = borsh::to_vec(&prove_info.receipt)
            .map_err(|e| anyhow!("[#{}] serialize receipt: {}", idx, e))?;

        Ok(receipt_bytes)
    }

    /// Compress a STARK proof to SNARK (Groth16).
    pub fn compress(&self, input: &CompressInput) -> Result<Vec<u8>> {
        let receipt: Receipt = borsh::from_slice(&input.receipt)
            .map_err(|e| anyhow!("deserialize receipt: {}", e))?;

        let env = ExecutorEnv::builder()
            .add_assumption(receipt)
            .write(&(input.commitment.clone(), None::<Commitment>))
            .map_err(|e| anyhow!("env write: {}", e))?
            .build()
            .map_err(|e| anyhow!("env build: {}", e))?;

        let prover = default_prover();
        let opts = ProverOpts::groth16();
        let info = prover.prove_with_opts(env, FOLD_ELF, &opts)?;

        let receipt_bytes = borsh::to_vec(&info.receipt)
            .map_err(|e| anyhow!("serialize snark receipt: {}", e))?;

        Ok(receipt_bytes)
    }
}

impl Default for Prover {
    fn default() -> Self {
        Self::new()
    }
}
