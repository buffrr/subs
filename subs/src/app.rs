//! Operator - the main entry point for subs operations.
//!
//! Combines local space management with on-chain RPC operations.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::core::{
    CompressInput, LocalSpace, ProvingRequest, SkippedEntry, SpaceStatus, VerifyCertResult,
};
use crate::HandleRequest;
use anyhow::anyhow;
use bitcoin::hashes::{sha256, Hash as BitcoinHash};
use bitcoin::{FeeRate, ScriptBuf, Txid};
use fabric::client::Fabric;
use libveritas::cert::{Certificate, ChainProofRequestUtils, PtrsSubtree, SpacesSubtree, Witness};
use libveritas::msg::{ChainProof, Message};
use libveritas::sname::{NameLike, SName};
use libveritas::{ProvableOption, SovereigntyState, Zone};
use spacedb::subtree::SubTree;
use spacedb::{NodeHasher, Sha256Hasher};
use spaces_client::jsonrpsee::http_client::HttpClient;
use spaces_client::rpc::{CommitParams, RpcClient, RpcWalletRequest, RpcWalletTxBuilder};
use spaces_protocol::slabel::SLabel;
use spaces_protocol::{Bytes, FullSpaceOut};
use spaces_ptr::sptr::Sptr;
use spaces_ptr::FullPtrOut;
use spaces_ptr::{ChainProofRequest, RootAnchor};

pub struct Sha256;

pub struct LiveSpaceInfo {
    pub space: SLabel,
    pub sptr: Sptr,
    pub tip: Option<spaces_ptr::Commitment>,
    pub fso: FullSpaceOut,
    pub fdo: FullPtrOut,
    pub local: Arc<LocalSpace>,
}

impl spaces_protocol::hasher::KeyHasher for Sha256 {
    fn hash(data: &[u8]) -> spaces_protocol::hasher::Hash {
        Sha256Hasher::hash(data)
    }
}

/// Status of an on-chain commit
#[derive(Debug, Clone)]
pub enum CommitStatus {
    /// No pending commit
    None,
    /// Commit broadcast, waiting for confirmation
    Pending { txid: Txid, expected_root: [u8; 32] },
    /// Commit mined but not yet finalized
    Confirmed {
        txid: Txid,
        block_height: u32,
        confirmations: u32,
    },
    /// Commit finalized (144+ confirmations)
    Finalized { block_height: u32 },
}

/// Handle information for API responses
#[derive(Debug, Clone, serde::Serialize)]
pub struct HandleInfo {
    pub name: String,
    pub script_pubkey: String,
    pub status: String,
    pub commitment_root: Option<String>,
    pub publish_status: Option<String>,
}

/// Paginated list of handles
#[derive(Debug, Clone, serde::Serialize)]
pub struct HandlesListResult {
    pub handles: Vec<HandleInfo>,
    pub total: usize,
    pub page: usize,
    pub per_page: usize,
    pub total_pages: usize,
}

/// Pipeline step state
#[derive(Debug, Clone, serde::Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum StepState {
    Complete,
    InProgress,
    Pending,
    Skipped,
}

/// Commitment pipeline status for the UI stepper
#[derive(Debug, Clone, serde::Serialize)]
pub struct PipelineStatus {
    /// Whether there's a pending commitment being processed
    pub has_pending: bool,
    /// Number of staged handles ready to commit
    pub staged_count: usize,
    /// Commitment index (0 = initial)
    pub commitment_idx: Option<usize>,
    /// Root hash of the commitment
    pub root: Option<String>,
    /// Transaction ID (if broadcast)
    pub txid: Option<String>,
    /// Steps and their states
    pub steps: PipelineSteps,
    /// Current active step name
    pub current_step: Option<String>,
    /// Additional status message
    pub message: Option<String>,
    /// Number of handles that need certificate publishing
    pub unpublished: usize,
}

impl LiveSpaceInfo {
    pub async fn issue_cert(
        &self,
        rpc: &HttpClient,
        wallet: &str,
        name: &SName,
    ) -> anyhow::Result<Certificate> {
        let label_count = name.label_count();
        if label_count == 0 {
            return Err(anyhow!("Cannot issue cert for empty name"));
        }
        let tip = self.tip.as_ref().map(|c| c.state_root);

        if label_count == 1 {
            let Some(tip) = tip else {
                return Ok(Certificate::new(
                    SName::from_space(&self.space).unwrap(),
                    Witness::Root { receipt: None },
                ));
            };
            return Ok(self
                .local
                .issue_cert(&SName::from_space(&self.space).unwrap(), tip)
                .await?);
        }
        if label_count != 2 {
            return Err(anyhow!("Cannot issue cert for more than two labels"));
        }

        let sub = name.subspace().unwrap();
        let is_final = self.local.lookup_handle_in_tree(&sub, tip).await?.is_some();
        if is_final {
            return self.local.issue_cert(&name, tip.unwrap()).await;
        }

        // temp cert
        let Some(script_pubkey) = self.local.get_handle_spk(&sub).await? else {
            return Err(anyhow!("handle {} neither committed nor staged", name));
        };
        let zone = Zone {
            anchor: 0,
            sovereignty: SovereigntyState::Dependent,
            handle: name.clone(),
            script_pubkey,
            data: None,
            offchain_data: None,
            delegate: ProvableOption::Unknown,
            commitment: ProvableOption::Unknown,
        };

        let signature_bytes = rpc
            .wallet_sign_schnorr(
                wallet,
                spaces_wallet::Subject::Ptr(self.sptr),
                Bytes::new(zone.signing_bytes()),
            )
            .await
            .map_err(|e| anyhow!("failed to sign zone: {}", e))?;

        let sig_array: [u8; 64] = signature_bytes
            .to_vec()
            .try_into()
            .map_err(|_| anyhow!("signature must be 64 bytes"))?;

        let cert = self
            .local
            .issue_temp_cert(&zone.handle, tip, sig_array)
            .await?;
        Ok(cert)
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PipelineSteps {
    pub local: StepState,
    pub proving: StepState,
    pub broadcast: StepState,
    pub confirmed: StepState,
    pub finalized: StepState,
    pub published: StepState,
}

/// The main entry point for subs operations.
///
/// Combines local space management with on-chain RPC operations.
pub struct Operator {
    data_dir: PathBuf,
    wallet: String,
    rpc: Option<HttpClient>,
    fabric: Option<Fabric>,
    spaces: Arc<Mutex<HashMap<SLabel, Arc<LocalSpace>>>>,
}

impl Operator {
    /// Create a new Operator with RPC client.
    ///
    /// # Arguments
    /// * `data_dir` - Directory for storing space data
    /// * `wallet` - Wallet name for signing operations
    /// * `rpc` - RPC client for chain interaction
    pub fn new(data_dir: PathBuf, wallet: impl Into<String>, rpc: HttpClient) -> Self {
        Self {
            data_dir,
            wallet: wallet.into(),
            rpc: Some(rpc),
            spaces: Arc::new(Mutex::new(HashMap::new())),
            fabric: None,
        }
    }

    /// Create a new Operator for offline operations only.
    ///
    /// On-chain operations will fail without an RPC client.
    pub fn offline(data_dir: PathBuf) -> Self {
        Self {
            data_dir,
            wallet: String::new(),
            rpc: None,
            fabric: None,
            spaces: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Set the fabric client with default seeds.
    pub fn with_fabric(mut self) -> Self {
        self.fabric = Some(Fabric::new());
        self
    }

    /// Set the fabric client with custom bootstrap seed URLs.
    pub fn with_fabric_seeds(mut self, seeds: &[&str]) -> Self {
        self.fabric = Some(Fabric::with_seeds(seeds));
        self
    }

    pub fn data_dir(&self) -> &PathBuf {
        &self.data_dir
    }

    pub fn wallet(&self) -> &str {
        &self.wallet
    }

    pub fn rpc(&self) -> Option<&HttpClient> {
        self.rpc.as_ref()
    }

    fn require_rpc(&self) -> anyhow::Result<&HttpClient> {
        self.rpc
            .as_ref()
            .ok_or_else(|| anyhow!("RPC client required for this operation"))
    }

    fn require_fabric(&self) -> anyhow::Result<&Fabric> {
        self.fabric
            .as_ref()
            .ok_or_else(|| anyhow!("Fabric client required for this operation"))
    }

    /// Get a loaded space by name. Briefly locks the spaces map.
    fn get_local_space(&self, space: &SLabel) -> anyhow::Result<Arc<LocalSpace>> {
        self.spaces
            .lock()
            .unwrap()
            .get(space)
            .cloned()
            .ok_or_else(|| anyhow!("space '{}' not loaded", space))
    }

    // =========================================================================
    // Space Management
    // =========================================================================

    /// Check if the wallet can operate on a space (owns the delegated sptr).
    async fn can_operate(&self, space: &SLabel) -> anyhow::Result<bool> {
        use spaces_client::rpc::RpcClient;

        let rpc = self.require_rpc()?;
        let result = rpc
            .wallet_can_operate(&self.wallet, space.clone())
            .await
            .map_err(|e| {
                anyhow!(
                    "could not check if wallet can operate on '{}': {}",
                    space,
                    e
                )
            })?;
        Ok(result)
    }

    /// Load a space from disk without validation.
    ///
    /// This is used for loading existing spaces at startup.
    /// Does not check if the wallet can operate on the space.
    async fn load_space_unchecked(&self, space: &SLabel) -> anyhow::Result<()> {
        {
            let spaces_guard = self.spaces.lock().unwrap();
            if spaces_guard.contains_key(space) {
                return Ok(());
            }
        }

        let space_dir = self.data_dir.join(space.to_string());
        let local_space = LocalSpace::new(space.clone(), space_dir).await?;

        let mut spaces_guard = self.spaces.lock().unwrap();
        if !spaces_guard.contains_key(space) {
            spaces_guard.insert(space.clone(), Arc::new(local_space));
        }
        Ok(())
    }

    /// Load or create a space.
    ///
    /// Opens an existing space or creates a new one if it doesn't exist.
    /// For new spaces, verifies the wallet can operate on the space first.
    pub async fn load_or_create_space(&self, space: &SLabel) -> anyhow::Result<()> {
        // Check if already loaded
        {
            let spaces_guard = self.spaces.lock().unwrap();
            if spaces_guard.contains_key(space) {
                return Ok(());
            }
        }

        // Check if space already exists on disk - if so, just load it
        let space_dir = self.data_dir.join(space.to_string());
        let exists_on_disk = space_dir.join("subs.db").exists();

        // For NEW spaces (not on disk), verify we can operate on this space
        if !exists_on_disk && self.rpc.is_some() {
            let can_op = self.can_operate(space).await?;
            if !can_op {
                return Err(anyhow!(
                    "space '{}' is not delegated to wallet '{}'",
                    space,
                    self.wallet
                ));
            }
        }

        let local_space = LocalSpace::new(space.clone(), space_dir).await?;

        let mut spaces_guard = self.spaces.lock().unwrap();
        // Double-check in case another task created it
        if !spaces_guard.contains_key(space) {
            spaces_guard.insert(space.clone(), Arc::new(local_space));
        }
        Ok(())
    }

    /// List all loaded spaces.
    pub fn list_spaces(&self) -> Vec<SLabel> {
        self.spaces.lock().unwrap().keys().cloned().collect()
    }

    /// Get status of a loaded space.
    pub async fn get_space_status(&self, space: &SLabel) -> anyhow::Result<SpaceStatus> {
        let local_space = self.get_local_space(space)?;
        local_space.status().await
    }

    /// List handles for a space with pagination.
    pub async fn list_handles(
        &self,
        space: &SLabel,
        page: usize,
        per_page: usize,
    ) -> anyhow::Result<HandlesListResult> {
        let local_space = self.get_local_space(space)?;
        let storage = local_space.storage();

        let total = storage.handle_count().await?;
        let offset = (page.saturating_sub(1)) * per_page;
        let handles = storage.list_handles_paginated(offset, per_page).await?;

        let total_pages = (total + per_page - 1) / per_page.max(1);

        Ok(HandlesListResult {
            handles: handles
                .into_iter()
                .map(|h| HandleInfo {
                    name: h.name,
                    script_pubkey: hex::encode(&h.script_pubkey),
                    status: if h.commitment_root.is_some() {
                        "committed".to_string()
                    } else {
                        "staged".to_string()
                    },
                    commitment_root: h.commitment_root,
                    publish_status: h.publish_status,
                })
                .collect(),
            total,
            page,
            per_page,
            total_pages,
        })
    }

    /// Get handles by commitment root.
    pub async fn get_handles_by_commitment(
        &self,
        space: &SLabel,
        root: &str,
    ) -> anyhow::Result<Vec<HandleInfo>> {
        let local_space = self.get_local_space(space)?;
        let handles = local_space
            .storage()
            .list_handles_by_commitment(root)
            .await?;

        Ok(handles
            .into_iter()
            .map(|h| HandleInfo {
                name: h.name,
                script_pubkey: hex::encode(&h.script_pubkey),
                status: "committed".to_string(),
                commitment_root: h.commitment_root,
                publish_status: h.publish_status,
            })
            .collect())
    }

    /// List all spaces with subs.db files on disk.
    pub fn list_spaces_from_disk(&self) -> anyhow::Result<Vec<SLabel>> {
        let mut spaces = Vec::new();
        if !self.data_dir.exists() {
            return Ok(spaces);
        }
        for entry in std::fs::read_dir(&self.data_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() && path.join("subs.db").exists() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if let Ok(space) = SLabel::try_from(name) {
                        spaces.push(space);
                    }
                }
            }
        }
        Ok(spaces)
    }

    /// Load all spaces from disk.
    ///
    /// Loads existing space data without validating wallet delegation.
    /// Spaces that fail to load are logged and skipped.
    pub async fn load_all_spaces(&self) -> anyhow::Result<()> {
        let spaces = self.list_spaces_from_disk()?;
        for space in spaces {
            if let Err(e) = self.load_space_unchecked(&space).await {
                log::warn!("Failed to load space '{}': {}", space, e);
            }
        }
        Ok(())
    }

    /// Get status of all spaces.
    pub async fn status(&self) -> anyhow::Result<crate::core::StatusResult> {
        self.load_all_spaces().await?;

        let local_spaces: Vec<Arc<LocalSpace>> =
            { self.spaces.lock().unwrap().values().cloned().collect() };

        let mut statuses = Vec::new();
        for local_space in local_spaces {
            statuses.push(local_space.status().await?);
        }
        Ok(crate::core::StatusResult { spaces: statuses })
    }

    // =========================================================================
    // Staging
    // =========================================================================

    /// Stage a handle request.
    ///
    /// The handle will be added to the staging area for the space.
    /// Returns None if successful, or SkippedEntry if the handle was skipped.
    pub async fn stage_request(
        &self,
        request: HandleRequest,
    ) -> anyhow::Result<Option<SkippedEntry>> {
        let space = request
            .handle
            .space()
            .ok_or_else(|| anyhow!("handle must have a space"))?;

        // Ensure space is loaded
        self.load_or_create_space(&space).await?;

        let local_space = self.get_local_space(&space)?;
        local_space.add_request(&request).await
    }

    /// Add multiple handle requests to staging.
    ///
    /// Groups requests by space and stages them. Returns results per space.
    pub async fn add_requests(
        &self,
        requests: Vec<HandleRequest>,
    ) -> anyhow::Result<crate::core::AddResult> {
        use crate::core::{AddResult, SpaceAddResult};

        if requests.is_empty() {
            return Err(anyhow!("No requests to add"));
        }

        // Group requests by space
        let mut by_space: HashMap<SLabel, Vec<HandleRequest>> = HashMap::new();
        for req in requests {
            let space = req
                .handle
                .space()
                .ok_or_else(|| anyhow!("handle must have a space"))?;
            by_space.entry(space).or_default().push(req);
        }

        let mut results = Vec::new();
        let mut total_added = 0;

        for (space, space_requests) in by_space {
            // Ensure space is loaded
            self.load_or_create_space(&space).await?;

            let local_space = self.get_local_space(&space)?;

            let mut added = Vec::new();
            let mut skipped = Vec::new();

            for req in space_requests {
                match local_space.add_request(&req).await? {
                    Some(s) => skipped.push(s),
                    None => added.push(req.handle),
                }
            }

            total_added += added.len();
            results.push(SpaceAddResult {
                space,
                added,
                skipped,
            });
        }

        Ok(AddResult {
            by_space: results,
            total_added,
        })
    }

    // =========================================================================
    // Local Commit
    // =========================================================================

    /// Check if a local commit can be made for a space.
    ///
    /// Returns an error message if commit is blocked, None if allowed.
    /// Note: If RPC is not available, on-chain finalization checks are skipped.
    pub async fn can_commit_local(&self, space: &SLabel) -> anyhow::Result<Option<String>> {
        let local_space = self.get_local_space(space)?;
        let storage = local_space.storage();

        let last_commitment = storage.get_last_commitment().await?;
        let staging_count = storage.staged_count().await?;

        if staging_count == 0 {
            return Ok(Some("no staged changes to commit".to_string()));
        }

        let Some(commitment) = last_commitment else {
            // No previous commits, can always commit
            return Ok(None);
        };

        // Check if previous commitment needs proving (non-initial commits need proof)
        if commitment.prev_root.is_some() {
            // This was a non-initial commit, needs proof
            let has_proof = commitment.step_receipt_id.is_some()
                && (commitment.aggregate_receipt_id.is_some() || commitment.idx == 1);
            if !has_proof {
                return Ok(Some(format!(
                    "commitment #{} needs proving before new commit",
                    commitment.idx
                )));
            }
        }

        // On-chain finalization checks require RPC
        if let Some(rpc) = &self.rpc {
            // Check on-chain status if there's a commit_txid
            if commitment.commit_txid.is_some() {
                // Always check on-chain status via RPC
                let mut expected_root = [0u8; 32];
                hex::decode_to_slice(&commitment.root, &mut expected_root)
                    .map_err(|e| anyhow!("invalid root: {}", e))?;

                let on_chain = rpc.get_commitment(space.clone(), None).await?;

                if let Some(commitment) = on_chain {
                    if commitment.state_root == expected_root {
                        // Commit is on-chain, check finalization (144 blocks + 6 safety)
                        let tip = rpc.get_server_info().await?.tip.height;
                        let confirmations = tip.saturating_sub(commitment.block_height);
                        if confirmations < 150 {
                            return Ok(Some(format!(
                                "previous commit needs {} more confirmations ({}/150)",
                                150 - confirmations,
                                confirmations
                            )));
                        }
                        // Commit is finalized, can proceed
                    } else {
                        // Chain has different root - commit may have been replaced
                        return Ok(Some(
                            "on-chain commitment root doesn't match local entry".to_string(),
                        ));
                    }
                } else {
                    // Not on-chain yet
                    return Ok(Some(
                        "previous commit pending confirmation on-chain".to_string(),
                    ));
                }
            } else if commitment.idx > 0 {
                // Non-initial commitment without commit_txid means not committed on-chain yet
                return Ok(Some(
                    "previous commit not yet submitted on-chain".to_string(),
                ));
            }
        }

        Ok(None)
    }

    /// Commit staged changes locally.
    ///
    /// This validates and commits staged entries to the local database.
    /// For non-initial commits, this creates a proving request that must be
    /// fulfilled before the commit can be submitted on-chain.
    pub async fn commit_local(
        &self,
        space: &SLabel,
    ) -> anyhow::Result<crate::core::SpaceCommitResult> {
        // Check if we can commit
        if let Some(reason) = self.can_commit_local(space).await? {
            return Err(anyhow!("cannot commit: {}", reason));
        }

        let local_space = self.get_local_space(space)?;
        local_space.commit(false).await
    }

    // =========================================================================
    // Proving
    // =========================================================================

    /// Get the next proving request for a space.
    ///
    /// Returns None if no proving is needed.
    pub async fn get_next_proving_request(
        &self,
        space: &SLabel,
    ) -> anyhow::Result<Option<ProvingRequest>> {
        let local_space = self.get_local_space(space)?;
        local_space.get_next_proving_request().await
    }

    /// Fulfill a proving request with a receipt.
    ///
    /// Verifies and stores the receipt.
    pub async fn fulfill_request(
        &self,
        space: &SLabel,
        request: &ProvingRequest,
        receipt_bytes: &[u8],
    ) -> anyhow::Result<()> {
        let local_space = self.get_local_space(space)?;
        local_space
            .save_proving_receipt(request, receipt_bytes)
            .await
    }

    /// Fulfill a proving request by commitment ID and type (for binary endpoint)
    pub async fn fulfill_request_by_id(
        &self,
        space: &SLabel,
        commitment_id: i64,
        is_fold: bool,
        receipt_bytes: &[u8],
    ) -> anyhow::Result<()> {
        let local_space = self.get_local_space(space)?;
        local_space
            .save_proving_receipt_by_id(commitment_id, is_fold, receipt_bytes)
            .await
    }

    /// Get input for SNARK compression.
    pub async fn get_compress_input(
        &self,
        space: &SLabel,
    ) -> anyhow::Result<Option<CompressInput>> {
        let local_space = self.get_local_space(space)?;
        local_space.get_compress_input().await
    }

    /// Save a groth16 (SNARK) receipt.
    pub async fn save_snark(&self, space: &SLabel, receipt_bytes: &[u8]) -> anyhow::Result<()> {
        let local_space = self.get_local_space(space)?;
        local_space.save_groth16_receipt(receipt_bytes).await
    }

    // =========================================================================
    // On-Chain Commit
    // =========================================================================

    /// Commit the latest local entry on-chain.
    ///
    /// Broadcasts a transaction to commit the state root on-chain.
    /// Returns the transaction ID. If fee_rate is None, uses wallet default.
    pub async fn commit(&self, space: &SLabel, fee_rate: Option<FeeRate>) -> anyhow::Result<Txid> {
        // Verify we can still operate on this space (delegation may have been revoked)
        let can_op = self.can_operate(space).await?;
        if !can_op {
            return Err(anyhow!(
                "space '{}' is not delegated to wallet '{}' (delegation may have been revoked)",
                space,
                self.wallet
            ));
        }

        let local_space = self.get_local_space(space)?;
        let storage = local_space.storage();

        // Get the latest commitment's root
        let commitment = storage
            .get_last_commitment()
            .await?
            .ok_or_else(|| anyhow!("no commitments to broadcast"))?;

        // Check if already has a txid
        if commitment.commit_txid.is_some() {
            return Err(anyhow!("commitment already has a pending broadcast"));
        }

        // For non-initial commitments, check that proving is done
        if commitment.prev_root.is_some() {
            let has_proof = commitment.step_receipt_id.is_some();
            if !has_proof {
                return Err(anyhow!(
                    "commitment needs proving before on-chain broadcast"
                ));
            }
        }

        let mut root_bytes = [0u8; 32];
        hex::decode_to_slice(&commitment.root, &mut root_bytes)
            .map_err(|e| anyhow!("invalid root: {}", e))?;

        // Broadcast the commit transaction
        let rpc = self.require_rpc()?;
        let commit_request = RpcWalletRequest::Commit(CommitParams {
            space: space.clone(),
            root: Some(sha256::Hash::from_slice(&root_bytes)?),
        });

        let response = rpc
            .wallet_send_request(
                &self.wallet,
                RpcWalletTxBuilder {
                    bidouts: None,
                    requests: vec![commit_request],
                    fee_rate,
                    dust: None,
                    force: false,
                    confirmed_only: false,
                    skip_tx_check: false,
                },
            )
            .await?;

        // Check for errors
        for tx in &response.result {
            if let Some(e) = tx.error.as_ref() {
                let s = e
                    .iter()
                    .map(|(k, v)| format!("{k}:{v}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                return Err(anyhow!("commit failed: {}", s));
            }
        }

        let txid: Txid = response
            .result
            .first()
            .map(|r| r.txid)
            .ok_or_else(|| anyhow!("no txid in response"))?;

        // Store the txid
        storage
            .update_commitment_txid(commitment.id, &txid.to_string())
            .await?;

        Ok(txid)
    }

    /// Get the status of the on-chain commit for a space.
    pub async fn get_commit_status(&self, space: &SLabel) -> anyhow::Result<CommitStatus> {
        let local_space = self.get_local_space(space)?;
        let db_commitment = local_space.storage().get_last_commitment().await?;

        let Some(db_commitment) = db_commitment else {
            return Ok(CommitStatus::None);
        };

        let Some(txid_str) = db_commitment.commit_txid.clone() else {
            return Ok(CommitStatus::None);
        };

        let txid: Txid = txid_str
            .parse()
            .map_err(|e: bitcoin::hex::HexToArrayError| anyhow!("invalid txid: {}", e))?;

        let mut expected_root = [0u8; 32];
        hex::decode_to_slice(&db_commitment.root, &mut expected_root)
            .map_err(|e| anyhow!("invalid root: {}", e))?;

        // Check on-chain state
        let rpc = self.require_rpc()?;
        let on_chain = rpc.get_commitment(space.clone(), None).await?;

        if let Some(chain_commitment) = on_chain {
            if chain_commitment.state_root == expected_root {
                let tip = rpc.get_server_info().await?.tip.height;
                let confirmations = tip.saturating_sub(chain_commitment.block_height);

                if confirmations >= 150 {
                    return Ok(CommitStatus::Finalized {
                        block_height: chain_commitment.block_height,
                    });
                } else {
                    return Ok(CommitStatus::Confirmed {
                        txid,
                        block_height: chain_commitment.block_height,
                        confirmations,
                    });
                }
            }
        }

        // Not on-chain yet
        Ok(CommitStatus::Pending {
            txid,
            expected_root,
        })
    }

    /// Get pipeline status for UI stepper (offline-friendly version).
    pub async fn get_pipeline_status(&self, space: &SLabel) -> anyhow::Result<PipelineStatus> {
        let local_space = self.get_local_space(space)?;
        let storage = local_space.storage();

        // Get the latest commitment and staged count
        let commitment = storage.get_last_commitment().await?;
        let staged_count = storage.staged_count().await?;

        // No commitments yet - show message based on staged count
        let Some(commitment) = commitment else {
            let unpublished = storage.list_unpublished(None).await?.len();
            let message = if staged_count > 0 {
                Some(format!(
                    "{} handle(s) staged. Ready to commit.",
                    staged_count
                ))
            } else {
                Some("Stage handles to start a new commitment.".to_string())
            };
            return Ok(PipelineStatus {
                has_pending: false,
                staged_count,
                commitment_idx: None,
                root: None,
                txid: None,
                steps: PipelineSteps {
                    local: StepState::Pending,
                    proving: StepState::Pending,
                    broadcast: StepState::Pending,
                    confirmed: StepState::Pending,
                    finalized: StepState::Pending,
                    published: StepState::Pending,
                },
                current_step: None,
                message,
                unpublished,
            });
        };

        let is_initial = commitment.idx == 0;
        let has_proof = commitment.step_receipt_id.is_some();
        let is_broadcast = commitment.commit_txid.is_some();

        // Determine step states
        let local = StepState::Complete; // Always complete if commitment exists

        let proving = if is_initial {
            StepState::Skipped
        } else if has_proof {
            StepState::Complete
        } else {
            StepState::InProgress
        };

        // For broadcast/confirmed/finalized/published, check on-chain state
        let (broadcast, confirmed, finalized, published, current_step, message, is_done, confirmed_idx) =
            if !is_broadcast {
                // Not broadcast yet
                if is_initial || has_proof {
                    (
                        StepState::InProgress,
                        StepState::Pending,
                        StepState::Pending,
                        StepState::Pending,
                        Some("broadcast".to_string()),
                        Some("Ready to broadcast".to_string()),
                        false,
                        None,
                    )
                } else {
                    (
                        StepState::Pending,
                        StepState::Pending,
                        StepState::Pending,
                        StepState::Pending,
                        Some("proving".to_string()),
                        Some("Proving required before broadcast".to_string()),
                        false,
                        None,
                    )
                }
            } else {
                // Broadcast - check on-chain status
                let mut on_chain_info: Option<u32> = None; // confirmations

                if let Some(rpc) = &self.rpc {
                    let mut expected_root = [0u8; 32];
                    if hex::decode_to_slice(&commitment.root, &mut expected_root).is_ok() {
                        if let Ok(Some(on_chain)) = rpc.get_commitment(space.clone(), None).await {
                            if on_chain.state_root == expected_root {
                                if let Ok(info) = rpc.get_server_info().await {
                                    let confirmations =
                                        info.tip.height.saturating_sub(on_chain.block_height);
                                    on_chain_info = Some(confirmations);
                                }
                            }
                        }
                    }
                }

                match on_chain_info {
                    Some(conf) if conf >= 150 => {
                        // Finalized — check publish status
                        let is_published = commitment.published_at.is_some();
                        if is_published {
                            (
                                StepState::Complete,
                                StepState::Complete,
                                StepState::Complete,
                                StepState::Complete,
                                None,
                                Some("Certificates published".to_string()),
                                true,
                                Some(commitment.idx),
                            )
                        } else {
                            (
                                StepState::Complete,
                                StepState::Complete,
                                StepState::Complete,
                                StepState::InProgress,
                                Some("published".to_string()),
                                Some("Ready to publish certificates".to_string()),
                                false,
                                Some(commitment.idx),
                            )
                        }
                    }
                    Some(conf) => {
                        // Confirmed but not finalized
                        (
                            StepState::Complete,
                            StepState::Complete,
                            StepState::InProgress,
                            StepState::Pending,
                            Some("finalized".to_string()),
                            Some(format!("{}/150 confirmations", conf)),
                            false,
                            Some(commitment.idx),
                        )
                    }
                    None => {
                        // Not confirmed yet
                        (
                            StepState::Complete,
                            StepState::InProgress,
                            StepState::Pending,
                            StepState::Pending,
                            Some("confirmed".to_string()),
                            Some("Waiting for confirmation".to_string()),
                            false,
                            None,
                        )
                    }
                }
            };

        // has_pending is true until fully done (published)
        let has_pending = !is_done;

        let unpublished = storage.list_unpublished(confirmed_idx).await?.len();

        Ok(PipelineStatus {
            has_pending,
            staged_count,
            commitment_idx: Some(commitment.idx),
            root: Some(commitment.root),
            txid: commitment.commit_txid,
            steps: PipelineSteps {
                local,
                proving,
                broadcast,
                confirmed,
                finalized,
                published,
            },
            current_step,
            message,
            unpublished,
        })
    }

    /// Bump the fee for a pending commit.
    pub async fn bump_commit(&self, space: &SLabel, fee_rate: FeeRate) -> anyhow::Result<Txid> {
        let status = self.get_commit_status(space).await?;

        let txid = match status {
            CommitStatus::Pending { txid, .. } => txid,
            CommitStatus::None => return Err(anyhow!("no pending commit to bump")),
            CommitStatus::Confirmed { .. } | CommitStatus::Finalized { .. } => {
                return Err(anyhow!("commit already confirmed, cannot bump"))
            }
        };

        // Use wallet RBF to bump fee
        let rpc = self.require_rpc()?;
        let responses = rpc
            .wallet_bump_fee(&self.wallet, txid, fee_rate, false)
            .await?;

        let new_txid = responses
            .first()
            .map(|r| r.txid)
            .ok_or_else(|| anyhow!("no txid in bump response"))?;

        // Update stored txid
        let local_space = self.get_local_space(space)?;
        let storage = local_space.storage();
        let commitment = storage
            .get_last_commitment()
            .await?
            .ok_or_else(|| anyhow!("no commitment"))?;
        storage
            .update_commitment_txid(commitment.id, &new_txid.to_string())
            .await?;

        Ok(new_txid)
    }

    pub async fn submit_certs(&self, certs: Vec<Certificate>) -> anyhow::Result<()> {
        log::info!("submit_certs: building message for {} certs", certs.len());
        let msg = self.build_message(certs).await?;
        log::info!("submit_certs: message built, broadcasting via fabric");
        let fabric = self.require_fabric()?;
        let relays = fabric
            .bootstrap()
            .await
            .map_err(|e| anyhow!("fabric bootstrap error: {}", e))?;

        log::info!("relays available: {:?}", relays);
        fabric
            .broadcast(&msg.to_bytes())
            .await
            .map_err(|e| anyhow!("Could not broadcast message: {}", e))?;
        log::info!("submit_certs: broadcast OK");
        Ok(())
    }

    pub async fn build_message(&self, certs: Vec<Certificate>) -> anyhow::Result<Message> {
        log::info!("build_message: building chain proof request");
        let req = ChainProofRequest::from_certificates(certs.iter());
        for r in &req.spaces {
            log::info!("chain proof request has space: {}", r);
        }
        let rpc = self.require_rpc()?;
        log::info!("build_message: calling build_chain_proof RPC");
        let res = rpc.build_chain_proof(req, None).await?;
        log::info!("build_message: chain proof received");

        let stree = SubTree::<Sha256Hasher>::from_slice(res.spaces_proof.as_slice())
            .map_err(|e| anyhow!("could not decode spaces proof: {}", e))?;
        let ptree = SubTree::<Sha256Hasher>::from_slice(res.ptrs_proof.as_slice())
            .map_err(|e| anyhow!("could not decode ptrs proof: {}", e))?;

        let chain_proof = ChainProof {
            anchor: res.block,
            spaces: SpacesSubtree(stree),
            ptrs: PtrsSubtree(ptree),
        };
        log::info!("build_message: constructing message from certificates");
        Ok(Message::try_from_certificates(chain_proof, certs)?)
    }

    /// Issue a certificate for a single handle or space.
    ///
    /// Returns `(root_cert, Option<handle_cert>)`:
    /// - For `@space`: returns `(root_cert, None)`
    /// - For `alice@space`: returns `(root_cert, Some(handle_cert))`
    pub async fn issue_cert(
        &self,
        handle: &SName,
    ) -> anyhow::Result<(Certificate, Option<Certificate>)> {
        let certs = self.issue_certs(vec![handle.clone()]).await?;
        let mut iter = certs.into_iter();
        let root_cert = iter.next().ok_or_else(|| anyhow!("missing root cert"))?;
        let handle_cert = iter.next();
        Ok((root_cert, handle_cert))
    }

    pub async fn get_live_space(&self, space: SLabel) -> anyhow::Result<LiveSpaceInfo> {
        let rpc = self.require_rpc()?;
        let Some(fso) = rpc.get_space(&space.to_string()).await? else {
            return Err(anyhow!("space not found: {}", space));
        };
        let tip = rpc
            .get_commitment(space.clone(), None)
            .await
            .map_err(|e| anyhow!("could not retrieve commitment tip for {}: {}", space, e))?;
        let sptr = Sptr::from_spk::<Sha256>(fso.spaceout.script_pubkey.clone());
        let Some(fdo) = rpc.get_ptr(spaces_wallet::Subject::Ptr(sptr)).await? else {
            return Err(anyhow!("no delegate {} found for space {}", sptr, space));
        };
        let local = self.get_local_space(&space)?;
        Ok(LiveSpaceInfo {
            space,
            sptr,
            tip,
            fso,
            fdo,
            local,
        })
    }

    pub async fn issue_certs(&self, handles: Vec<SName>) -> anyhow::Result<Vec<Certificate>> {
        let mut certs = Vec::new();
        struct SpaceHandles {
            info: LiveSpaceInfo,
            handles: Vec<SName>,
        }

        let mut by_space = HashMap::new();
        for handle in handles {
            if !handle.is_single_label() && handle.label_count() != 2 {
                return Err(anyhow!("cannot issue cert for handle: {}", handle));
            }
            by_space
                .entry(handle.space().unwrap())
                .or_insert(Vec::new())
                .push(handle);
        }
        let rpc = self.require_rpc()?;
        let mut space_datas = Vec::new();
        for (space, handles) in by_space {
            let info = self.get_live_space(space.clone()).await?;
            space_datas.push(SpaceHandles { info, handles })
        }

        for space_data in space_datas {
            let space = SName::from_space(&space_data.info.space).unwrap();
            let root_cert = space_data
                .info
                .issue_cert(rpc, &self.wallet, &space)
                .await?;
            certs.push(root_cert);
            for handle in space_data.handles {
                let cert = space_data
                    .info
                    .issue_cert(rpc, &self.wallet, &handle)
                    .await?;
                certs.push(cert);
            }
        }

        Ok(certs)
    }

    // =========================================================================
    // Certificate Publishing
    // =========================================================================

    /// Publish certificates for all unpublished handles.
    ///
    /// Issues the appropriate cert type (temp or final) for each handle based on
    /// on-chain tip state and broadcasts them via fabric. Returns the number of handles published.
    pub async fn publish_certs(&self, space: &SLabel) -> anyhow::Result<usize> {
        self.require_fabric()?;

        let local_space = self.get_local_space(space)?;
        let storage = local_space.storage();

        let live = self.get_live_space(space.clone()).await?;
        let tip = live.tip.as_ref().map(|c| c.state_root);

        // Determine confirmed commitment idx from on-chain tip
        let confirmed_idx = if let Some(tip) = tip {
            storage.get_commitment_by_root(&hex::encode(tip)).await?.map(|c| c.idx)
        } else {
            None
        };

        let unpublished = storage.list_unpublished(confirmed_idx).await?;
        if unpublished.is_empty() {
            return Ok(0);
        }

        let handle_names: Vec<SName> = unpublished
            .iter()
            .map(|h| format!("{}@{}", h.name, space.as_str_unprefixed().unwrap()).parse())
            .collect::<Result<_, _>>()
            .map_err(|e| anyhow!("invalid handle name: {}", e))?;

        let count = handle_names.len();
        let certs = self.issue_certs(handle_names).await?;
        self.submit_certs(certs).await?;

        // Determine temp vs final per handle based on confirmed idx
        let mut temp_names = Vec::new();
        let mut final_names = Vec::new();
        for h in &unpublished {
            let is_final = match (h.commitment_idx, confirmed_idx) {
                (Some(h_idx), Some(c_idx)) if h_idx <= c_idx => true,
                _ => false,
            };
            if is_final {
                final_names.push(h.name.clone());
            } else {
                temp_names.push(h.name.clone());
            }
        }

        if !temp_names.is_empty() {
            storage.mark_handles_published(&temp_names, "temp").await?;
        }
        if !final_names.is_empty() {
            storage.mark_handles_published(&final_names, "final").await?;
            // If no more committed handles need publishing, mark commitment as published
            if storage.list_unpublished(confirmed_idx).await?.iter().all(|h| h.commitment_root.is_none()) {
                if let Some(commitment) = storage.get_last_commitment().await? {
                    if commitment.published_at.is_none() {
                        storage.mark_commitment_published(commitment.id).await?;
                    }
                }
            }
        }

        Ok(count)
    }

    /// Verify a certificate using anchors from the chain.
    pub async fn verify_certificate(
        &self,
        cert: Certificate,
        root_cert: Option<Certificate>,
    ) -> anyhow::Result<VerifyCertResult> {
        let rpc = self.require_rpc()?;
        let anchors = rpc
            .get_root_anchors()
            .await
            .map_err(|e| anyhow!("could not load anchors: {}", e))?;

        // TODO: unify RootAnchor type
        let veritas_anchors = serde_json::to_string_pretty(&anchors).expect("anchors");
        let veritas_anchors: Vec<RootAnchor> =
            serde_json::from_str(&veritas_anchors).expect("decode anchors");

        verify_certificate_with_anchors(cert, root_cert, veritas_anchors)
    }
}

/// Verify a certificate with provided anchors (static function).
pub fn verify_certificate_with_anchors(
    _cert: Certificate,
    _root_cert: Option<Certificate>,
    anchors: Vec<RootAnchor>,
) -> anyhow::Result<VerifyCertResult> {
    let _veritas = libveritas::Veritas::new()
        .with_anchors(anchors)
        .map_err(|e| anyhow!("invalid anchors: {}", e))?;
    todo!("verify certificate")
}
