//! Test rig module for running bitcoind + spaced in development mode.
//!
//! This module wraps spaces_testutil::TestRig to support persistent data directories.

use std::path::Path;
use std::str::FromStr;

use anyhow::{anyhow, Result};
use spaces_testutil::TestRig;
use spaces_client::rpc::RpcClient;
use spaces_wallet::export::WalletExport;

/// Handle to a running test rig.
///
/// When dropped, the test rig processes (bitcoind, spaced) are terminated.
pub struct TestRigHandle {
    rig: TestRig,
    spaced_rpc_url: String,
    bitcoin_rpc_url: String,
}

impl TestRigHandle {
    /// Start a test rig with data stored in the specified directory.
    ///
    /// If the directory already contains data from a previous run, it will be reused.
    /// Otherwise, fresh regtest preset data will be copied there.
    pub async fn start(data_dir: &Path) -> Result<Self> {
        let rig = TestRig::new_with_regtest_preset_with_path(data_dir.to_path_buf()).await
            .map_err(|e| anyhow!("Failed to start test rig: {}", e))?;

        let bitcoin_rpc_url = rig.bitcoind.rpc_url();
        let spaced_rpc_url = rig.spaced.rpc_url().to_string();

        // Get wallets path from the rig (same as e2e tests)
        let wallets_dir = rig.testdata_wallets_path().await;
        tracing::info!("Wallets directory: {}", wallets_dir.display());

        // Load wallets (spaced will sync in background)
        load_wallets(&rig, &wallets_dir).await?;

        tracing::info!("Spaced syncing in background...");

        Ok(Self {
            rig,
            spaced_rpc_url,
            bitcoin_rpc_url,
        })
    }

    /// Get the spaced RPC URL.
    pub fn spaced_rpc_url(&self) -> &str {
        &self.spaced_rpc_url
    }

    /// Get the bitcoin RPC URL.
    pub fn bitcoin_rpc_url(&self) -> &str {
        &self.bitcoin_rpc_url
    }

    /// Get a reference to the underlying TestRig.
    pub fn rig(&self) -> &TestRig {
        &self.rig
    }

    /// Gracefully stop bitcoind so it flushes all data to disk.
    /// Must be called before dropping, otherwise bitcoind gets SIGKILL
    /// and may lose recent blocks.
    pub async fn stop(&self) -> Result<()> {
        use spaces_testutil::bitcoind::bitcoincore_rpc::RpcApi;
        tracing::info!("Stopping bitcoind gracefully...");
        let c = self.rig.bitcoind.clone();
        tokio::task::spawn_blocking(move || {
            let _ = c.client.stop();
        })
        .await
        .map_err(|e| anyhow!("join error: {}", e))?;
        tracing::info!("bitcoind stopped cleanly");
        Ok(())
    }

    /// Mine blocks (useful for testing).
    pub async fn mine_blocks(&self, count: usize) -> Result<()> {
        self.rig.mine_blocks(count, None).await
            .map_err(|e| anyhow!("Failed to mine blocks: {}", e))?;
        self.rig.wait_until_synced().await
            .map_err(|e| anyhow!("Failed to sync after mining: {}", e))?;
        Ok(())
    }

    /// Start a certrelay instance connected to this test rig's spaced.
    ///
    /// Returns a shutdown sender that stops the relay when dropped.
    pub async fn start_certrelay(
        &self,
        data_dir: &Path,
        port: u16,
    ) -> Result<(String, tokio::sync::broadcast::Sender<()>)> {
        let certrelay_dir = data_dir.join("certrelay");
        std::fs::create_dir_all(&certrelay_dir)?;

        let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(1);
        let url = format!("http://127.0.0.1:{}", port);

        let args = vec![
            "certrelay".to_string(),
            "--chain".to_string(),
            "regtest".to_string(),
            "--data-dir".to_string(),
            certrelay_dir.to_string_lossy().to_string(),
            "--spaced-rpc-url".to_string(),
            self.spaced_rpc_url.replace("://", "://user:pass@"),
            "--port".to_string(),
            port.to_string(),
            "--self-url".to_string(),
            url.clone(),
            "--is-bootstrap".to_string(),
            "--anchor-refresh".to_string(),
            "1".to_string(),
        ];

        let tx = shutdown_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = relay::app::run(args, tx).await {
                tracing::error!("Certrelay exited with error: {}", e);
            }
        });

        tracing::info!("Certrelay started on {}", url);
        Ok((url, shutdown_tx))
    }
}

/// Load test wallets into spaced.
async fn load_wallets(rig: &TestRig, wallets_dir: &Path) -> Result<()> {
    // Load the main test wallets
    for wallet_name in &["wallet_99", "wallet_98"] {
        let wallet_file = wallets_dir.join(format!("{}.json", wallet_name));
        tracing::info!("Loading wallet from: {}", wallet_file.display());

        let json = std::fs::read_to_string(&wallet_file)
            .map_err(|e| anyhow!("Failed to read wallet file {}: {}", wallet_file.display(), e))?;

        let export = WalletExport::from_str(&json)
            .map_err(|e| anyhow!("Failed to parse wallet {}: {}", wallet_name, e))?;

        // Try to import wallet, if it already exists then load it
        match rig.spaced.client.wallet_import(export).await {
            Ok(_) => tracing::info!("Imported wallet: {}", wallet_name),
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("already exists") {
                    tracing::info!("Wallet {} exists, loading...", wallet_name);
                    rig.spaced.client.wallet_load(wallet_name).await
                        .map_err(|e| anyhow!("Failed to load wallet {}: {}", wallet_name, e))?;
                    tracing::info!("Loaded wallet: {}", wallet_name);
                } else {
                    return Err(anyhow!("Failed to import wallet {}: {}", wallet_name, e));
                }
            }
        }
    }

    // Wallets will sync in background
    tracing::info!("Wallets loaded, syncing in background...");

    Ok(())
}
