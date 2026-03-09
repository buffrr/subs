//! Core business logic for subs - usable as a library.
//!
//! This module provides the core functionality without CLI dependencies.
//! All operations return structured results instead of printing.
//! Database and file I/O are run on blocking threads via `spawn_blocking`.

use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::{fs, io};

use anyhow::anyhow;
use bitcoin::ScriptBuf;
use libveritas::cert::{Certificate, HandleSubtree, Signature, Witness};
use libveritas::sname::{Label, NameLike, SName};
use serde::Serialize;
use libveritas::constants::{FOLD_ID, STEP_ID};
use libveritas_zk::guest::Commitment as ZkCommitment;
use libveritas_zk::BatchReader;
use risc0_zkvm::Receipt;
pub use subs_types::{CompressInput, ProvingRequest};
use spacedb::db::Database;
use spacedb::subtree::SubTree;
use spacedb::tx::ProofType;
use spacedb::{Hash, NodeHasher, Sha256Hasher};
use spaces_protocol::slabel::SLabel;
use tokio::task::spawn_blocking;

use crate::storage::Storage;
use crate::{Batch, BatchEntry, HandleRequest};

/// Result of adding requests to staging
#[derive(Debug, Clone, Serialize)]
pub struct AddResult {
    /// Entries added per space
    pub by_space: Vec<SpaceAddResult>,
    /// Total entries added across all spaces
    pub total_added: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SpaceAddResult {
    pub space: SLabel,
    pub added: Vec<SName>,
    pub skipped: Vec<SkippedEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SkippedEntry {
    pub handle: SName,
    pub reason: SkipReason,
}

#[derive(Debug, Clone, Serialize)]
pub enum SkipReason {
    AlreadyCommittedDifferentSpk,
    AlreadyStagedDifferentSpk,
    AlreadyCommitted,
    AlreadyStaged,
}

impl SkipReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            SkipReason::AlreadyCommittedDifferentSpk => "already committed with different spk",
            SkipReason::AlreadyStagedDifferentSpk => "already staged with different spk",
            SkipReason::AlreadyCommitted => "already committed",
            SkipReason::AlreadyStaged => "already staged",
        }
    }
}

/// Result of committing staged entries
#[derive(Debug, Clone, Serialize)]
pub struct CommitResult {
    pub commits: Vec<SpaceCommitResult>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SpaceCommitResult {
    pub space: SLabel,
    pub prev_root: Option<String>,
    pub root: String,
    pub handles_committed: usize,
    pub is_initial: bool,
}

/// Result of proving commitments
#[derive(Debug, Clone, Serialize)]
pub struct ProveResult {
    pub spaces: Vec<SpaceProveResult>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SpaceProveResult {
    pub space: SLabel,
    pub steps_proved: usize,
    pub steps_skipped: usize,
    pub aggregated: bool,
    pub step_times: Vec<StepProveInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StepProveInfo {
    pub idx: usize,
    pub prev_root: Option<String>,
    pub root: String,
    /// Duration in milliseconds
    pub duration_ms: u64,
}

/// Result of compressing proofs to SNARK
#[derive(Debug, Clone, Serialize)]
pub struct CompressResult {
    pub spaces: Vec<SpaceCompressResult>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SpaceCompressResult {
    pub space: SLabel,
    pub compressed: bool,
    pub skipped_reason: Option<String>,
}

/// Status of a space
#[derive(Debug, Clone, Serialize)]
pub struct SpaceStatus {
    pub space: SLabel,
    pub commitments: usize,
    pub total_handles: usize,
    pub staged_handles: usize,
    pub committed_handles: usize,
    pub has_receipt: bool,
    pub has_groth16: bool,
}

/// Result of status query
#[derive(Debug, Clone, Serialize, Default)]
pub struct StatusResult {
    pub spaces: Vec<SpaceStatus>,
}

/// Local proof data for building a space/root certificate
///
/// The caller must fetch on-chain proofs (spaces proof, ptrs proof) via RPC
/// and combine with this data to build the final Certificate.
pub struct SpaceReceipt {
    /// The ZK receipt proving the commitment chain (None for initial single-entry)
    pub receipt: Option<Receipt>,
    /// The commitment/state root (None if no entries committed yet)
    pub commitment_root: Option<[u8; 32]>,
}

/// Local proof data for building a handle/leaf certificate
///
/// The caller must fetch the key rotation proof via RPC
/// and combine with this data to build the final Certificate.
pub struct LocalHandleProof {
    /// The subject handle
    pub subject: SName,
    /// The genesis script pubkey for this handle
    pub script_pubkey: Vec<u8>,
    /// Merkle inclusion proof from SpaceDB
    pub inclusion_proof: SubTree<Sha256Hasher>,
}

/// Result of verifying a certificate
#[derive(Clone, Serialize)]
pub struct VerifyCertResult {
    pub valid: bool,
    pub root_zone: Option<libveritas::Zone>,
    pub leaf_zone: Option<libveritas::Zone>,
}


/// A local space with cached database connections.
///
/// Holds the storage (SQLite) and SpaceDB connections for a single space.
/// Database and file operations are offloaded to blocking threads.
pub struct LocalSpace {
    name: SLabel,
    storage: Storage,
    db: Arc<Mutex<Database<Sha256Hasher>>>,
}

impl LocalSpace {
    pub async fn new(name: SLabel, dir: PathBuf) -> anyhow::Result<Self> {
        let dir_clone = dir.clone();
        spawn_blocking(move || fs::create_dir_all(&dir_clone)).await??;

        let storage = Storage::open(&dir.join("subs.db")).await?;
        if storage.get_space().await?.is_none() {
            storage.set_space(&name).await?;
        }

        let db_path = dir.join(format!("{}.sdb", name));
        let db = spawn_blocking(move || Database::open(db_path.to_str().unwrap())).await??;

        Ok(Self {
            name,
            storage,
            db: Arc::new(Mutex::new(db)),
        })
    }

    pub fn name(&self) -> &SLabel {
        &self.name
    }

    pub fn storage(&self) -> Storage {
        self.storage.clone()
    }

    pub fn db(&self) -> Arc<Mutex<Database<Sha256Hasher>>> {
        self.db.clone()
    }

    // =========================================================================
    // Private sync helpers (for SpaceDB operations within spawn_blocking)
    // =========================================================================

    fn get_handle_proof_sync(
        db: &Database<Sha256Hasher>,
        handle: &SName,
    ) -> anyhow::Result<LocalHandleProof> {
        let mut snap = db.begin_read()?;

        let subspace = handle
            .subspace()
            .ok_or_else(|| anyhow!("handle must have subspace"))?;
        let key = Sha256Hasher::hash(subspace.as_slabel().as_ref());
        let spk = snap
            .get(&key)?
            .ok_or_else(|| anyhow!("handle '{}' not found", handle))?;

        let inclusion_proof = snap
            .prove(&[key], ProofType::Standard)
            .map_err(|e| anyhow!("could not generate inclusion proof: {}", e))?;

        Ok(LocalHandleProof {
            subject: handle.clone(),
            script_pubkey: spk,
            inclusion_proof,
        })
    }

    // =========================================================================
    // Public async methods
    // =========================================================================

    /// Get status of this space
    pub async fn status(&self) -> anyhow::Result<SpaceStatus> {
        let staged = self.storage.staged_count().await?;
        let committed = self.storage.committed_handle_count().await?;
        Ok(SpaceStatus {
            space: self.name.clone(),
            commitments: self.storage.commitment_count().await?,
            total_handles: staged + committed,
            staged_handles: staged,
            committed_handles: committed,
            has_receipt: self.storage.get_tip_receipt_id().await?.is_some(),
            has_groth16: self.storage.get_tip_groth16_id().await?.is_some(),
        })
    }

    /// Stage a single handle request
    pub async fn add_request(
        &self,
        request: &HandleRequest,
    ) -> anyhow::Result<Option<SkippedEntry>> {
        let script_pubkey = hex::decode(&request.script_pubkey)
            .map_err(|e| anyhow!("Invalid script_pubkey hex: {}", e))?;

        let sub_label = request.handle.subspace().expect("subspace").clone();
        let sub_label_key = sub_label.as_slabel().as_ref().to_vec();
        let handle_name = sub_label.to_string();

        // Check if already committed in SpaceDB
        let db = self.db.clone();
        let spk_clone = script_pubkey.clone();
        let handle_clone = request.handle.clone();
        let db_result: Option<SkippedEntry> = spawn_blocking(move || {
            let db = db.lock().unwrap();
            let mut reader = db.begin_read()?;
            if let Some(existing) = reader.get(&Sha256Hasher::hash(&sub_label_key))? {
                let reason = if existing != spk_clone {
                    SkipReason::AlreadyCommittedDifferentSpk
                } else {
                    SkipReason::AlreadyCommitted
                };
                return Ok(Some(SkippedEntry {
                    handle: handle_clone,
                    reason,
                }));
            }
            Ok::<_, anyhow::Error>(None)
        })
        .await??;

        if db_result.is_some() {
            return Ok(db_result);
        }

        // Check if already staged
        if let Some(existing) = self.storage.is_staged(&handle_name).await? {
            let reason = if existing != script_pubkey {
                SkipReason::AlreadyStagedDifferentSpk
            } else {
                SkipReason::AlreadyStaged
            };
            return Ok(Some(SkippedEntry {
                handle: request.handle.clone(),
                reason,
            }));
        }

        self.storage.add_handle(&handle_name, &script_pubkey).await?;
        Ok(None)
    }

    /// Prepare ZK input for this space
    pub async fn prepare_zk_input(&self) -> anyhow::Result<(Option<Vec<u8>>, Batch)> {
        let staged_handles = self.storage.list_staged_handles().await?;
        if staged_handles.is_empty() {
            return Err(anyhow!("No uncommitted changes found"));
        }

        let mut batch = Batch::new(self.name.clone());
        for handle in staged_handles {
            let sub_label = Label::from_str(&handle.name)
                .map_err(|e| anyhow!("invalid handle name '{}': {}", handle.name, e))?;
            batch.entries.push(BatchEntry {
                sub_label,
                script_pubkey: handle.script_pubkey.into(),
            });
        }

        if self.storage.commitment_count().await? == 0 {
            return Ok((None, batch));
        }

        // Generate exclusion proof from SpaceDB
        let db = self.db.clone();
        let zk_batch = batch.to_zk_input();
        let exclusion_proof = spawn_blocking(move || {
            let reader = BatchReader(zk_batch.as_slice());
            let keys = reader
                .iter()
                .map(|t| {
                    t.handle.try_into().map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "invalid subspace hash")
                    })
                })
                .collect::<Result<Vec<Hash>, io::Error>>()?;
            let db = db.lock().unwrap();
            let mut snapshot = db.begin_read()?;
            let proof = snapshot.prove(&keys, ProofType::Standard).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("could not generate exclusion proof: {}", e),
                )
            })?;
            let encoded = borsh::to_vec(&proof).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("could not encode exclusion proof: {}", e),
                )
            })?;
            Ok::<_, anyhow::Error>(encoded)
        })
        .await??;

        Ok((Some(exclusion_proof), batch))
    }

    /// Commit staged handles for this space
    pub async fn commit(&self, dry_run: bool) -> anyhow::Result<SpaceCommitResult> {
        if self.storage.staged_count().await? == 0 {
            return Err(anyhow!("No changes to commit for space {}", self.name));
        }

        let (exclusion_proof_opt, batch) = self.prepare_zk_input().await?;
        let zk_batch = batch.to_zk_input();
        let handles_committed = batch.entries.len();
        let name = self.name.clone();

        match exclusion_proof_opt {
            Some(exclusion_proof) => {
                let c = libveritas_zk::guest::run(
                    exclusion_proof.clone(),
                    zk_batch.clone(),
                    STEP_ID,
                    FOLD_ID,
                )
                .map_err(|e| anyhow!("could not validate program input: {}", e))?;

                if dry_run {
                    return Ok(SpaceCommitResult {
                        space: name,
                        prev_root: Some(hex::encode(&c.initial_root)),
                        root: hex::encode(&c.final_root),
                        handles_committed,
                        is_initial: false,
                    });
                }

                let prev_hex = hex::encode(&c.initial_root);
                let root_hex = hex::encode(&c.final_root);

                self.storage
                    .add_commitment(
                        Some(&prev_hex),
                        &root_hex,
                        &zk_batch,
                        Some(&exclusion_proof),
                    )
                    .await?;

                let db = self.db.clone();
                let entries = batch.entries;
                spawn_blocking(move || {
                    let db = db.lock().unwrap();
                    let mut tx = db.begin_write()?;
                    for e in entries {
                        tx = tx.insert(
                            Sha256Hasher::hash(e.sub_label.as_slabel().as_ref()),
                            e.script_pubkey.to_bytes(),
                        )?;
                    }
                    tx.commit()?;
                    Ok::<_, anyhow::Error>(())
                })
                .await??;

                self.storage.commit_staged_handles(&root_hex).await?;

                Ok(SpaceCommitResult {
                    space: name,
                    prev_root: Some(prev_hex),
                    root: root_hex,
                    handles_committed,
                    is_initial: false,
                })
            }

            None => {
                if dry_run {
                    return Ok(SpaceCommitResult {
                        space: name,
                        prev_root: None,
                        root: String::new(),
                        handles_committed,
                        is_initial: true,
                    });
                }

                let db = self.db.clone();
                let entries = batch.entries;
                let end_root = spawn_blocking(move || {
                    let db = db.lock().unwrap();
                    let mut tx = db.begin_write()?;
                    for e in &entries {
                        tx = tx.insert(
                            Sha256Hasher::hash(e.sub_label.as_slabel().as_ref()),
                            e.script_pubkey.to_bytes(),
                        )?;
                    }
                    tx.commit()?;
                    let root = db
                        .begin_read()
                        .expect("read")
                        .compute_root()
                        .expect("root");
                    Ok::<_, anyhow::Error>(hex::encode(root))
                })
                .await??;

                self.storage
                    .add_commitment(None, &end_root, &zk_batch, None)
                    .await?;
                self.storage.commit_staged_handles(&end_root).await?;

                Ok(SpaceCommitResult {
                    space: name,
                    prev_root: None,
                    root: end_root,
                    handles_committed,
                    is_initial: true,
                })
            }
        }
    }

    /// Look up a handle in SpaceDB
    pub async fn lookup_handle(&self, sub_label: &Label) -> anyhow::Result<Option<Vec<u8>>> {
        let db = self.db.clone();
        let sub_label = sub_label.clone();
        spawn_blocking(move || {
            let db = db.lock().unwrap();
            let mut snap = db.begin_read()?;
            let key = Sha256Hasher::hash(sub_label.as_slabel().as_ref());
            Ok(snap.get(&key)?)
        })
        .await?
    }

    /// Get the current tree root
    pub async fn get_tree_root(&self) -> anyhow::Result<[u8; 32]> {
        let db = self.db.clone();
        spawn_blocking(move || {
            let db = db.lock().unwrap();
            let mut snap = db.begin_read()?;
            Ok(snap.compute_root()?)
        })
        .await?
    }

    /// Get staged script pubkey for a handle
    pub async fn get_staged(&self, sub_label: &Label) -> anyhow::Result<Option<Vec<u8>>> {
        let handle_name = sub_label.to_string();
        self.storage.is_staged(&handle_name).await
    }

    /// Load a receipt and extract commitment info
    pub async fn load_receipt_and_commitment(
        &self,
        receipt_id: i64,
    ) -> anyhow::Result<(Receipt, ZkCommitment)> {
        let receipt_data = self
            .storage
            .get_receipt(receipt_id)
            .await?
            .ok_or_else(|| anyhow!("Receipt {} not found", receipt_id))?;
        let receipt: Receipt = borsh::from_slice(&receipt_data)
            .map_err(|e| anyhow!("could not decode receipt: {}", e))?;
        let zk_commitment: ZkCommitment = receipt.journal.decode()?;
        Ok((receipt, zk_commitment))
    }

    /// Get the tip receipt.
    ///
    /// If `prefer_compressed` is true, returns groth16 receipt if available.
    pub async fn get_tip_receipt(
        &self,
        prefer_compressed: bool,
    ) -> anyhow::Result<Option<(Receipt, ZkCommitment)>> {
        let receipt_id = if prefer_compressed {
            self.storage.get_tip_groth16_id().await?
        } else {
            self.storage.get_tip_receipt_id().await?
        };

        match receipt_id {
            Some(id) => {
                let (receipt, commitment) = self.load_receipt_and_commitment(id).await?;
                Ok(Some((receipt, commitment)))
            }
            None => Ok(None),
        }
    }

    /// Get local proof data for building a space/root certificate.
    ///
    /// If `prefer_compressed` is true, returns groth16 receipt if available.
    pub async fn get_receipt(&self, prefer_compressed: bool) -> anyhow::Result<SpaceReceipt> {
        let commitment_count = self.storage.commitment_count().await?;

        if commitment_count > 1 {
            let receipt_id = if prefer_compressed {
                self.storage.get_tip_groth16_id().await?
            } else {
                self.storage.get_tip_receipt_id().await?
            };

            let receipt_id = match receipt_id {
                Some(id) => id,
                None => {
                    let last_commitment = self
                        .storage
                        .get_last_commitment()
                        .await?
                        .ok_or_else(|| anyhow!("No commitments found"))?;
                    last_commitment
                        .step_receipt_id
                        .ok_or_else(|| anyhow!("No receipt found - run prove first"))?
                }
            };

            let (receipt, commitment_info) =
                self.load_receipt_and_commitment(receipt_id).await?;

            Ok(SpaceReceipt {
                receipt: Some(receipt),
                commitment_root: Some(commitment_info.final_root),
            })
        } else if commitment_count == 1 {
            let commitment = self
                .storage
                .get_commitment(0)
                .await?
                .ok_or_else(|| anyhow!("Commitment 0 not found"))?;
            let mut root = [0; 32];
            hex::decode_to_slice(&commitment.root, &mut root)
                .map_err(|e| anyhow!("invalid root: {}", e))?;
            Ok(SpaceReceipt {
                receipt: None,
                commitment_root: Some(root),
            })
        } else {
            Ok(SpaceReceipt {
                receipt: None,
                commitment_root: None,
            })
        }
    }

    /// Get local proof data for building a handle/leaf certificate
    pub async fn get_handle_proof(&self, handle: &SName) -> anyhow::Result<LocalHandleProof> {
        let db = self.db.clone();
        let handle = handle.clone();
        spawn_blocking(move || {
            let db = db.lock().unwrap();
            Self::get_handle_proof_sync(&db, &handle)
        })
        .await?
    }

    // =========================================================================
    // Local Certificates (no on-chain proofs)
    // =========================================================================

    /// Issue a certificate for a subject.
    pub async fn issue_cert(&self, subject: &SName) -> anyhow::Result<Certificate> {
        if subject.is_single_label() {
            return Ok(Certificate::new(
                subject.clone(),
                Witness::Root {
                    receipt: self.get_receipt(true).await?.receipt,
                },
            ));
        }
        let proof = self.get_handle_proof(subject).await?;
        Ok(Certificate::new(
            subject.clone(),
            Witness::Leaf {
                genesis_spk: ScriptBuf::from_bytes(proof.script_pubkey),
                handles: HandleSubtree(proof.inclusion_proof),
                signature: None,
            },
        ))
    }

    /// Issue a temporary certificate for a staged (uncommitted) handle.
    ///
    /// Temporary certificates are used for handles that haven't been committed yet.
    /// They include an optional exclusion proof (if prior commits exist) and signature.
    pub async fn issue_temp_cert(
        &self,
        handle: &SName,
        signature: [u8; 64],
    ) -> anyhow::Result<Certificate> {
        let subspace = handle
            .subspace()
            .ok_or_else(|| anyhow!("handle must have subspace"))?;
        let handle_name = subspace.to_string();

        let script_pubkey = self
            .storage
            .is_staged(&handle_name)
            .await?
            .ok_or_else(|| anyhow!("handle '{}' is not staged", handle))?;

        let exclusion = if self.storage.commitment_count().await? > 0 {
            let db = self.db.clone();
            let subspace = subspace.clone();
            spawn_blocking(move || {
                let db = db.lock().unwrap();
                let mut snap = db.begin_read()?;
                let key = Sha256Hasher::hash(subspace.as_slabel().as_ref());
                let exclusion_proof = snap
                    .prove(&[key], ProofType::Standard)
                    .map_err(|e| anyhow!("could not generate exclusion proof: {}", e))?;
                Ok::<_, anyhow::Error>(HandleSubtree(exclusion_proof))
            })
            .await??
        } else {
            HandleSubtree(SubTree::empty())
        };

        Ok(Certificate::new(
            handle.clone(),
            Witness::Leaf {
                genesis_spk: ScriptBuf::from_bytes(script_pubkey),
                handles: exclusion,
                signature: Some(Signature(signature)),
            },
        ))
    }

    // =========================================================================
    // Proving Support
    // =========================================================================

    /// Get the next proving request for this space.
    /// Returns None when all proofs are complete.
    pub async fn get_next_proving_request(&self) -> anyhow::Result<Option<ProvingRequest>> {
        let commitments = self.storage.list_commitments().await?;

        if commitments.len() < 2 {
            return Ok(None);
        }

        // First, check for any pending step proofs
        for commitment in commitments.iter().skip(1) {
            if commitment.step_receipt_id.is_some() {
                continue;
            }

            let exclusion_proof = commitment
                .exclusion_merkle_proof
                .as_ref()
                .ok_or_else(|| {
                    anyhow!("[#{}] missing exclusion_merkle_proof", commitment.idx)
                })?;

            return Ok(Some(ProvingRequest::Step {
                commitment_id: commitment.id,
                idx: commitment.idx,
                prev_root: commitment.prev_root.clone(),
                root: commitment.root.clone(),
                exclusion_proof: exclusion_proof.clone(),
                zk_batch: commitment.zk_batch.clone(),
            }));
        }

        // All steps done, check for pending folds
        let mut acc_receipt: Option<Vec<u8>> = None;
        let mut acc_commit: Option<ZkCommitment> = None;

        for commitment in commitments.iter().skip(1) {
            let step_receipt_id = match commitment.step_receipt_id {
                Some(id) => id,
                None => continue,
            };

            let step_receipt_bytes = self
                .storage
                .get_receipt(step_receipt_id)
                .await?
                .ok_or_else(|| anyhow!("step receipt {} not found", step_receipt_id))?;
            let step_receipt: Receipt = borsh::from_slice(&step_receipt_bytes)?;
            let step_commit: ZkCommitment = step_receipt.journal.decode()?;

            if acc_receipt.is_none() {
                acc_receipt = Some(step_receipt_bytes);
                acc_commit = Some(step_commit);
                continue;
            }

            if let Some(agg_id) = commitment.aggregate_receipt_id {
                let agg_receipt_bytes = self
                    .storage
                    .get_receipt(agg_id)
                    .await?
                    .ok_or_else(|| anyhow!("aggregate receipt {} not found", agg_id))?;
                let agg_receipt: Receipt = borsh::from_slice(&agg_receipt_bytes)?;
                let agg_commit: ZkCommitment = agg_receipt.journal.decode()?;
                acc_receipt = Some(agg_receipt_bytes);
                acc_commit = Some(agg_commit);
                continue;
            }

            return Ok(Some(ProvingRequest::Fold {
                commitment_id: commitment.id,
                idx: commitment.idx,
                prev_root: commitment.prev_root.clone(),
                root: commitment.root.clone(),
                acc_receipt: acc_receipt.clone().unwrap(),
                acc_commitment: acc_commit.clone().unwrap(),
                step_receipt: step_receipt_bytes,
                step_commitment: step_commit,
            }));
        }

        Ok(None)
    }

    /// Get input for SNARK compression. Returns None if nothing to compress.
    pub async fn get_compress_input(&self) -> anyhow::Result<Option<CompressInput>> {
        let tip_id = match self.storage.get_tip_receipt_id().await? {
            Some(id) => id,
            None => return Ok(None),
        };

        if self.storage.get_tip_groth16_id().await?.is_some() {
            return Ok(None);
        }

        let receipt_bytes = self
            .storage
            .get_receipt(tip_id)
            .await?
            .ok_or_else(|| anyhow!("tip receipt {} not found", tip_id))?;
        let receipt: Receipt = borsh::from_slice(&receipt_bytes)?;
        let zk_commitment: ZkCommitment = receipt.journal.decode()?;

        Ok(Some(CompressInput {
            receipt: receipt_bytes,
            commitment: zk_commitment,
        }))
    }

    /// Save a step receipt from an external prover
    pub async fn save_step_receipt(
        &self,
        commitment_id: i64,
        receipt_bytes: &[u8],
    ) -> anyhow::Result<()> {
        let receipt_bytes = receipt_bytes.to_vec();
        let bytes_for_verify = receipt_bytes.clone();
        spawn_blocking(move || {
            let receipt: Receipt = borsh::from_slice(&bytes_for_verify)
                .map_err(|e| anyhow!("could not deserialize receipt: {}", e))?;
            receipt
                .verify(STEP_ID)
                .map_err(|e| anyhow!("step receipt verification failed: {}", e))?;
            Ok::<_, anyhow::Error>(())
        })
        .await??;

        let receipt_id = self.storage.store_receipt("step", &receipt_bytes).await?;
        self.storage
            .update_commitment_step_receipt(commitment_id, receipt_id)
            .await?;
        Ok(())
    }

    /// Save a fold receipt
    pub async fn save_fold_receipt(
        &self,
        commitment_id: i64,
        receipt_bytes: &[u8],
    ) -> anyhow::Result<()> {
        let receipt_bytes = receipt_bytes.to_vec();
        let bytes_for_verify = receipt_bytes.clone();
        spawn_blocking(move || {
            let receipt: Receipt = borsh::from_slice(&bytes_for_verify)
                .map_err(|e| anyhow!("could not deserialize receipt: {}", e))?;
            receipt
                .verify(FOLD_ID)
                .map_err(|e| anyhow!("fold receipt verification failed: {}", e))?;
            Ok::<_, anyhow::Error>(())
        })
        .await??;

        let receipt_id = self.storage.store_receipt("fold", &receipt_bytes).await?;
        self.storage
            .update_commitment_aggregate_receipt(commitment_id, receipt_id)
            .await?;
        self.storage.set_tip_receipt_id(Some(receipt_id)).await?;
        Ok(())
    }

    /// Save a groth16 receipt
    pub async fn save_groth16_receipt(&self, receipt_bytes: &[u8]) -> anyhow::Result<()> {
        let receipt_bytes = receipt_bytes.to_vec();
        let bytes_for_verify = receipt_bytes.clone();
        spawn_blocking(move || {
            let receipt: Receipt = borsh::from_slice(&bytes_for_verify)
                .map_err(|e| anyhow!("could not deserialize receipt: {}", e))?;
            receipt
                .verify(FOLD_ID)
                .map_err(|e| anyhow!("groth16 receipt verification failed: {}", e))?;
            Ok::<_, anyhow::Error>(())
        })
        .await??;

        let groth16_id = self
            .storage
            .store_receipt("groth16", &receipt_bytes)
            .await?;
        if let Some(commitment) = self.storage.get_last_commitment().await? {
            self.storage
                .update_commitment_groth16(commitment.id, groth16_id)
                .await?;
        }
        self.storage.set_tip_groth16_id(Some(groth16_id)).await?;
        Ok(())
    }

    /// Save a receipt for a proving request (step or fold)
    pub async fn save_proving_receipt(
        &self,
        request: &ProvingRequest,
        receipt_bytes: &[u8],
    ) -> anyhow::Result<()> {
        match request {
            ProvingRequest::Step { commitment_id, .. } => {
                self.save_step_receipt(*commitment_id, receipt_bytes).await
            }
            ProvingRequest::Fold { commitment_id, .. } => {
                self.save_fold_receipt(*commitment_id, receipt_bytes).await
            }
        }
    }

    /// Save a proving receipt by commitment ID and type (for binary fulfill endpoint)
    pub async fn save_proving_receipt_by_id(
        &self,
        commitment_id: i64,
        is_fold: bool,
        receipt_bytes: &[u8],
    ) -> anyhow::Result<()> {
        if is_fold {
            self.save_fold_receipt(commitment_id, receipt_bytes).await
        } else {
            self.save_step_receipt(commitment_id, receipt_bytes).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::ScriptBuf;
    use std::str::FromStr;
    use tempfile::TempDir;

    fn test_space() -> SLabel {
        SLabel::try_from("@example").unwrap()
    }

    fn test_label(name: &str) -> Label {
        Label::from_str(name).unwrap()
    }

    fn test_script_pubkey() -> ScriptBuf {
        ScriptBuf::from_bytes(vec![0x01; 25])
    }

    fn make_request(handle: &str, spk: &[u8]) -> HandleRequest {
        HandleRequest {
            handle: SName::try_from(handle).unwrap(),
            script_pubkey: hex::encode(spk),
        }
    }

    #[test]
    fn test_batch_to_zk_input_format() {
        let space = test_space();
        let mut batch = Batch::new(space.clone());

        let label = test_label("alice");
        let spk = test_script_pubkey();
        batch.entries.push(BatchEntry {
            sub_label: label.clone(),
            script_pubkey: spk.clone(),
        });

        let zk_input = batch.to_zk_input();

        // First 32 bytes should be sha256(space)
        let space_hash = Sha256Hasher::hash(space.as_ref());
        assert_eq!(&zk_input[0..32], &space_hash);

        // Next 32 bytes should be sha256(subspace label)
        let subspace_hash = Sha256Hasher::hash(label.as_slabel().as_ref());
        assert_eq!(&zk_input[32..64], &subspace_hash);

        // Next 32 bytes should be sha256(script_pubkey)
        let spk_hash = Sha256Hasher::hash(spk.as_bytes());
        assert_eq!(&zk_input[64..96], &spk_hash);

        // Total size: 32 (space) + 32 (subspace) + 32 (spk) = 96 bytes
        assert_eq!(zk_input.len(), 96);
    }

    #[test]
    fn test_batch_reader_roundtrip() {
        let space = test_space();
        let mut batch = Batch::new(space.clone());

        let label = test_label("bob");
        let spk = test_script_pubkey();
        batch.entries.push(BatchEntry {
            sub_label: label.clone(),
            script_pubkey: spk.clone(),
        });

        let zk_input = batch.to_zk_input();
        let reader = BatchReader(zk_input.as_slice());

        let entries: Vec<_> = reader.iter().collect();
        assert_eq!(entries.len(), 1);

        let expected_hash = Sha256Hasher::hash(label.as_slabel().as_ref());
        assert_eq!(entries[0].handle, expected_hash);

        let expected_spk_hash = Sha256Hasher::hash(spk.as_bytes());
        assert_eq!(entries[0].script_pubkey, expected_spk_hash);
    }

    #[tokio::test]
    async fn test_storage_handles_operations() {
        let storage = Storage::in_memory().await.unwrap();
        let space = test_space();
        storage.set_space(&space).await.unwrap();

        // Initially no staged handles
        assert_eq!(storage.staged_count().await.unwrap(), 0);

        // Add a handle (staged by default - commitment_root is NULL)
        let handle_name = "alice@testspace";
        let spk = test_script_pubkey();
        storage
            .add_handle(handle_name, spk.as_bytes())
            .await
            .unwrap();

        assert_eq!(storage.staged_count().await.unwrap(), 1);

        // List staged handles
        let staged = storage.list_staged_handles().await.unwrap();
        assert_eq!(staged.len(), 1);
        assert_eq!(staged[0].name, handle_name);
        assert_eq!(staged[0].script_pubkey, spk.as_bytes());
        assert!(staged[0].commitment_root.is_none());

        // Check is_staged
        let is_staged = storage.is_staged(handle_name).await.unwrap();
        assert!(is_staged.is_some());
        assert_eq!(is_staged.unwrap(), spk.as_bytes());

        // Commit staged handles
        let committed_count = storage.commit_staged_handles("abc123").await.unwrap();
        assert_eq!(committed_count, 1);
        assert_eq!(storage.staged_count().await.unwrap(), 0);

        // Handle should no longer be staged
        assert!(storage.is_staged(handle_name).await.unwrap().is_none());

        // But should still exist with commitment_root set
        let handle = storage.get_handle(handle_name).await.unwrap().unwrap();
        assert_eq!(handle.commitment_root, Some("abc123".to_string()));
    }

    #[tokio::test]
    async fn test_storage_commitment_operations() {
        let storage = Storage::in_memory().await.unwrap();

        assert_eq!(storage.commitment_count().await.unwrap(), 0);

        let zk_batch = vec![1, 2, 3, 4];
        storage
            .add_commitment(None, "abc123", &zk_batch, None)
            .await
            .unwrap();

        assert_eq!(storage.commitment_count().await.unwrap(), 1);
        let commitment = storage.get_commitment(0).await.unwrap().unwrap();
        assert_eq!(commitment.idx, 0);
        assert_eq!(commitment.prev_root, None);
        assert_eq!(commitment.root, "abc123");
        assert_eq!(commitment.zk_batch, zk_batch);

        storage
            .add_commitment(Some("abc123"), "def456", &vec![5, 6, 7], Some(&vec![8, 9]))
            .await
            .unwrap();
        assert_eq!(storage.commitment_count().await.unwrap(), 2);

        let commitment = storage.get_commitment(1).await.unwrap().unwrap();
        assert_eq!(commitment.idx, 1);
        assert_eq!(commitment.prev_root, Some("abc123".to_string()));
        assert_eq!(commitment.root, "def456");

        let last = storage.get_last_commitment().await.unwrap().unwrap();
        assert_eq!(last.idx, 1);
    }

    async fn create_local_space(temp_dir: &TempDir) -> LocalSpace {
        let space = test_space();
        let space_dir = temp_dir.path().join(space.to_string());
        LocalSpace::new(space, space_dir).await.unwrap()
    }

    #[tokio::test]
    async fn test_add_and_commit_initial() {
        let temp_dir = TempDir::new().unwrap();
        let local_space = create_local_space(&temp_dir).await;

        let req = make_request("alice@example", &[0x01; 25]);
        let skipped = local_space.add_request(&req).await.unwrap();
        assert!(skipped.is_none());

        let commit_result = local_space.commit(false).await.unwrap();
        assert!(commit_result.is_initial);
        assert_eq!(commit_result.handles_committed, 1);

        // Verify in SpaceDB
        let label = test_label("alice");
        let stored = local_space.lookup_handle(&label).await.unwrap();
        assert!(stored.is_some());
        assert_eq!(stored.unwrap(), vec![0x01; 25]);
    }

    #[tokio::test]
    async fn test_add_and_commit_subsequent() {
        let temp_dir = TempDir::new().unwrap();
        let local_space = create_local_space(&temp_dir).await;

        // First commit
        let req1 = make_request("alice@example", &[0x01; 25]);
        local_space.add_request(&req1).await.unwrap();
        let result1 = local_space.commit(false).await.unwrap();
        assert!(result1.is_initial);

        // Second commit
        let req2 = make_request("bob@example", &[0x02; 25]);
        local_space.add_request(&req2).await.unwrap();
        let result2 = local_space.commit(false).await.unwrap();
        assert!(!result2.is_initial);
        assert!(result2.prev_root.is_some());

        // Both should exist
        assert!(local_space
            .lookup_handle(&test_label("alice"))
            .await
            .unwrap()
            .is_some());
        assert!(local_space
            .lookup_handle(&test_label("bob"))
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn test_skip_duplicate_in_staging() {
        let temp_dir = TempDir::new().unwrap();
        let local_space = create_local_space(&temp_dir).await;

        let req = make_request("alice@example", &[0x01; 25]);
        local_space.add_request(&req).await.unwrap();

        // Adding same request again should skip
        let skipped = local_space.add_request(&req).await.unwrap();
        assert!(skipped.is_some());
        assert!(matches!(
            skipped.unwrap().reason,
            SkipReason::AlreadyStaged
        ));
    }

    #[tokio::test]
    async fn test_skip_duplicate_after_commit() {
        let temp_dir = TempDir::new().unwrap();
        let local_space = create_local_space(&temp_dir).await;

        let req = make_request("alice@example", &[0x01; 25]);
        local_space.add_request(&req).await.unwrap();
        local_space.commit(false).await.unwrap();

        // Adding same request after commit should skip
        let skipped = local_space.add_request(&req).await.unwrap();
        assert!(skipped.is_some());
        assert!(matches!(
            skipped.unwrap().reason,
            SkipReason::AlreadyCommitted
        ));
    }

    #[tokio::test]
    async fn test_reject_duplicate_with_different_spk() {
        let temp_dir = TempDir::new().unwrap();
        let local_space = create_local_space(&temp_dir).await;

        let req1 = make_request("alice@example", &[0x01; 25]);
        local_space.add_request(&req1).await.unwrap();
        local_space.commit(false).await.unwrap();

        // Adding same handle with different spk should be skipped with reason
        let req2 = make_request("alice@example", &[0x02; 25]);
        let skipped = local_space.add_request(&req2).await.unwrap();
        assert!(skipped.is_some());
        assert!(matches!(
            skipped.unwrap().reason,
            SkipReason::AlreadyCommittedDifferentSpk
        ));
    }

    #[tokio::test]
    async fn test_multi_space_isolation() {
        let temp_dir = TempDir::new().unwrap();

        let space1 = SLabel::try_from("@space1").unwrap();
        let space2 = SLabel::try_from("@space2").unwrap();

        let local_space1 = LocalSpace::new(space1.clone(), temp_dir.path().join("@space1"))
            .await
            .unwrap();
        let local_space2 = LocalSpace::new(space2.clone(), temp_dir.path().join("@space2"))
            .await
            .unwrap();

        let req1 = make_request("alice@space1", &[0x01; 25]);
        let req2 = make_request("bob@space2", &[0x02; 25]);

        local_space1.add_request(&req1).await.unwrap();
        local_space2.add_request(&req2).await.unwrap();

        local_space1.commit(false).await.unwrap();
        local_space2.commit(false).await.unwrap();

        // alice only in space1
        assert!(local_space1
            .lookup_handle(&test_label("alice"))
            .await
            .unwrap()
            .is_some());
        assert!(local_space2
            .lookup_handle(&test_label("alice"))
            .await
            .unwrap()
            .is_none());

        // bob only in space2
        assert!(local_space1
            .lookup_handle(&test_label("bob"))
            .await
            .unwrap()
            .is_none());
        assert!(local_space2
            .lookup_handle(&test_label("bob"))
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn test_status() {
        let temp_dir = TempDir::new().unwrap();
        let local_space = create_local_space(&temp_dir).await;

        // Initially no commits
        let status = local_space.status().await.unwrap();
        assert_eq!(status.commitments, 0);
        assert_eq!(status.staged_handles, 0);

        // Add and commit
        let req = make_request("alice@example", &[0x01; 25]);
        local_space.add_request(&req).await.unwrap();
        local_space.commit(false).await.unwrap();

        let status = local_space.status().await.unwrap();
        assert_eq!(status.commitments, 1);
        assert_eq!(status.staged_handles, 0);
    }

    #[tokio::test]
    async fn test_zk_batch_verified_by_guest() {
        let temp_dir = TempDir::new().unwrap();
        let local_space = create_local_space(&temp_dir).await;

        // First commit
        let req1 = make_request("alice@example", &[0x01; 25]);
        local_space.add_request(&req1).await.unwrap();
        local_space.commit(false).await.unwrap();

        // Second commit - this will use ZK validation
        let req2 = make_request("bob@example", &[0x02; 25]);
        local_space.add_request(&req2).await.unwrap();

        let (exclusion_proof, batch) = local_space.prepare_zk_input().await.unwrap();
        assert!(exclusion_proof.is_some());

        let zk_batch = batch.to_zk_input();
        let commitment =
            libveritas_zk::guest::run(exclusion_proof.unwrap(), zk_batch, STEP_ID, FOLD_ID)
                .unwrap();

        assert_ne!(commitment.initial_root, [0u8; 32]);
        assert_ne!(commitment.final_root, [0u8; 32]);
        assert_ne!(commitment.initial_root, commitment.final_root);
    }
}
