use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::anyhow;
use bitcoin::ScriptBuf;
use clap::builder::TypedValueParser;
use rusqlite::{params, Connection, OptionalExtension};
use spaces_protocol::slabel::SLabel;
use tokio::task::spawn_blocking;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS chain (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    space BLOB,
    tip_receipt_id INTEGER,
    tip_receipt_groth16_id INTEGER
);

CREATE TABLE IF NOT EXISTS commitments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    idx INTEGER NOT NULL UNIQUE,
    prev_root TEXT,
    root TEXT NOT NULL,
    zk_batch BLOB NOT NULL,
    exclusion_merkle_proof BLOB,
    step_receipt_id INTEGER,
    aggregate_receipt_id INTEGER,
    aggregate_groth16_id INTEGER,
    commit_txid TEXT,
    published_at TEXT
);

CREATE TABLE IF NOT EXISTS receipts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    data BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS handles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    script_pubkey BLOB NOT NULL,
    commitment_root TEXT,  -- NULL if staged, set to root hex when committed
    commitment_idx INTEGER, -- NULL if staged, set to commitment idx when committed
    publish_status TEXT    -- NULL = not published, 'temp' = temp cert, 'final' = final cert
);

INSERT OR IGNORE INTO chain (id) VALUES (1);
"#;

#[derive(Debug, Clone)]
pub struct Commitment {
    pub id: i64,
    pub idx: usize,
    pub prev_root: Option<String>,
    pub root: String,
    pub zk_batch: Vec<u8>,
    pub exclusion_merkle_proof: Option<Vec<u8>>,
    pub step_receipt_id: Option<i64>,
    pub aggregate_receipt_id: Option<i64>,
    pub aggregate_groth16_id: Option<i64>,
    /// Txid of the on-chain commit transaction (set after broadcast)
    pub commit_txid: Option<String>,
    /// When final certs for this commitment were published
    pub published_at: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Handle {
    pub id: i64,
    pub name: String,
    pub script_pubkey: Vec<u8>,
    /// NULL if staged, set to commitment root hex when committed
    pub commitment_root: Option<String>,
    /// NULL if staged, set to commitment idx when committed
    pub commitment_idx: Option<usize>,
    /// NULL = not published, "temp" = temp cert published, "final" = final cert published
    pub publish_status: Option<String>,
}

#[derive(Clone)]
pub struct Storage {
    conn: Arc<Mutex<Connection>>,
}

impl Storage {
    pub async fn open(path: &Path) -> anyhow::Result<Self> {
        let path = path.to_path_buf();
        spawn_blocking(move || Self::open_sync(&path))
            .await?
    }

    pub async fn in_memory() -> anyhow::Result<Self> {
        spawn_blocking(Self::in_memory_sync).await?
    }

    fn open_sync(path: &Path) -> anyhow::Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn: Arc::new(Mutex::new(conn)) })
    }

    fn in_memory_sync() -> anyhow::Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn: Arc::new(Mutex::new(conn)) })
    }

    // Chain metadata

    pub async fn get_space(&self) -> anyhow::Result<Option<SLabel>> {
        let conn = self.conn.clone();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let space: Option<Vec<u8>> = conn
                .query_row("SELECT space FROM chain WHERE id = 1", [], |row| row.get(0))?;
            match space {
                Some(bytes) => Ok(Some(
                    SLabel::try_from(bytes.as_slice())
                        .map_err(|_| anyhow!("invalid space label in db"))?,
                )),
                None => Ok(None),
            }
        })
        .await?
    }

    pub async fn set_space(&self, space: &SLabel) -> anyhow::Result<()> {
        let conn = self.conn.clone();
        let space = space.clone();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            conn.execute(
                "UPDATE chain SET space = ? WHERE id = 1",
                params![space.as_ref()],
            )?;
            Ok(())
        })
        .await?
    }

    pub async fn get_tip_receipt_id(&self) -> anyhow::Result<Option<i64>> {
        let conn = self.conn.clone();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            Ok(conn.query_row(
                "SELECT tip_receipt_id FROM chain WHERE id = 1",
                [],
                |row| row.get(0),
            )?)
        })
        .await?
    }

    pub async fn set_tip_receipt_id(&self, id: Option<i64>) -> anyhow::Result<()> {
        let conn = self.conn.clone();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            conn.execute(
                "UPDATE chain SET tip_receipt_id = ? WHERE id = 1",
                params![id],
            )?;
            Ok(())
        })
        .await?
    }

    pub async fn get_tip_groth16_id(&self) -> anyhow::Result<Option<i64>> {
        let conn = self.conn.clone();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            Ok(conn.query_row(
                "SELECT tip_receipt_groth16_id FROM chain WHERE id = 1",
                [],
                |row| row.get(0),
            )?)
        })
        .await?
    }

    pub async fn set_tip_groth16_id(&self, id: Option<i64>) -> anyhow::Result<()> {
        let conn = self.conn.clone();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            conn.execute(
                "UPDATE chain SET tip_receipt_groth16_id = ? WHERE id = 1",
                params![id],
            )?;
            Ok(())
        })
        .await?
    }

    // Commitments

    pub async fn commitment_count(&self) -> anyhow::Result<usize> {
        let conn = self.conn.clone();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let count: i64 = conn
                .query_row("SELECT COUNT(*) FROM commitments", [], |row| row.get(0))?;
            Ok(count as usize)
        })
        .await?
    }

    pub async fn get_commitment(&self, idx: usize) -> anyhow::Result<Option<Commitment>> {
        let conn = self.conn.clone();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let commitment = conn
                .query_row(
                    "SELECT id, idx, prev_root, root, zk_batch, exclusion_merkle_proof,
                            step_receipt_id, aggregate_receipt_id, aggregate_groth16_id,
                            commit_txid, published_at
                     FROM commitments WHERE idx = ?",
                    params![idx as i64],
                    |row| {
                        Ok(Commitment {
                            id: row.get(0)?,
                            idx: row.get::<_, i64>(1)? as usize,
                            prev_root: row.get(2)?,
                            root: row.get(3)?,
                            zk_batch: row.get(4)?,
                            exclusion_merkle_proof: row.get(5)?,
                            step_receipt_id: row.get(6)?,
                            aggregate_receipt_id: row.get(7)?,
                            aggregate_groth16_id: row.get(8)?,
                            commit_txid: row.get(9)?,
                            published_at: row.get(10)?,
                        })
                    },
                )
                .optional()?;
            Ok(commitment)
        })
        .await?
    }

    pub async fn get_last_commitment(&self) -> anyhow::Result<Option<Commitment>> {
        let conn = self.conn.clone();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let commitment = conn
                .query_row(
                    "SELECT id, idx, prev_root, root, zk_batch, exclusion_merkle_proof,
                            step_receipt_id, aggregate_receipt_id, aggregate_groth16_id,
                            commit_txid, published_at
                     FROM commitments ORDER BY idx DESC LIMIT 1",
                    [],
                    |row| {
                        Ok(Commitment {
                            id: row.get(0)?,
                            idx: row.get::<_, i64>(1)? as usize,
                            prev_root: row.get(2)?,
                            root: row.get(3)?,
                            zk_batch: row.get(4)?,
                            exclusion_merkle_proof: row.get(5)?,
                            step_receipt_id: row.get(6)?,
                            aggregate_receipt_id: row.get(7)?,
                            aggregate_groth16_id: row.get(8)?,
                            commit_txid: row.get(9)?,
                            published_at: row.get(10)?,
                        })
                    },
                )
                .optional()?;
            Ok(commitment)
        })
        .await?
    }

    pub async fn get_commitment_by_root(&self, root: &str) -> anyhow::Result<Option<Commitment>> {
        let conn = self.conn.clone();
        let root = root.to_string();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let commitment = conn
                .query_row(
                    "SELECT id, idx, prev_root, root, zk_batch, exclusion_merkle_proof,
                            step_receipt_id, aggregate_receipt_id, aggregate_groth16_id,
                            commit_txid, published_at
                     FROM commitments WHERE root = ?",
                    params![root],
                    |row| {
                        Ok(Commitment {
                            id: row.get(0)?,
                            idx: row.get::<_, i64>(1)? as usize,
                            prev_root: row.get(2)?,
                            root: row.get(3)?,
                            zk_batch: row.get(4)?,
                            exclusion_merkle_proof: row.get(5)?,
                            step_receipt_id: row.get(6)?,
                            aggregate_receipt_id: row.get(7)?,
                            aggregate_groth16_id: row.get(8)?,
                            commit_txid: row.get(9)?,
                            published_at: row.get(10)?,
                        })
                    },
                )
                .optional()?;
            Ok(commitment)
        })
        .await?
    }

    pub async fn list_commitments(&self) -> anyhow::Result<Vec<Commitment>> {
        let conn = self.conn.clone();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let mut stmt = conn.prepare(
                "SELECT id, idx, prev_root, root, zk_batch, exclusion_merkle_proof,
                        step_receipt_id, aggregate_receipt_id, aggregate_groth16_id,
                        commit_txid, published_at
                 FROM commitments ORDER BY idx ASC",
            )?;
            let commitments = stmt
                .query_map([], |row| {
                    Ok(Commitment {
                        id: row.get(0)?,
                        idx: row.get::<_, i64>(1)? as usize,
                        prev_root: row.get(2)?,
                        root: row.get(3)?,
                        zk_batch: row.get(4)?,
                        exclusion_merkle_proof: row.get(5)?,
                        step_receipt_id: row.get(6)?,
                        aggregate_receipt_id: row.get(7)?,
                        aggregate_groth16_id: row.get(8)?,
                        commit_txid: row.get(9)?,
                        published_at: row.get(10)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(commitments)
        })
        .await?
    }

    /// Returns (row_id, idx) where idx is the 0-based commitment index
    pub async fn add_commitment(
        &self,
        prev_root: Option<&str>,
        root: &str,
        zk_batch: &[u8],
        exclusion_merkle_proof: Option<&[u8]>,
    ) -> anyhow::Result<(i64, usize)> {
        let conn = self.conn.clone();
        let prev_root = prev_root.map(|s| s.to_string());
        let root = root.to_string();
        let zk_batch = zk_batch.to_vec();
        let exclusion_merkle_proof = exclusion_merkle_proof.map(|b| b.to_vec());
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let count: i64 = conn
                .query_row("SELECT COUNT(*) FROM commitments", [], |row| row.get(0))?;
            conn.execute(
                "INSERT INTO commitments (idx, prev_root, root, zk_batch, exclusion_merkle_proof)
                 VALUES (?, ?, ?, ?, ?)",
                params![
                    count,
                    prev_root,
                    root,
                    zk_batch,
                    exclusion_merkle_proof
                ],
            )?;
            Ok((conn.last_insert_rowid(), count as usize))
        })
        .await?
    }

    pub async fn update_commitment_step_receipt(
        &self,
        commitment_id: i64,
        receipt_id: i64,
    ) -> anyhow::Result<()> {
        let conn = self.conn.clone();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            conn.execute(
                "UPDATE commitments SET step_receipt_id = ? WHERE id = ?",
                params![receipt_id, commitment_id],
            )?;
            Ok(())
        })
        .await?
    }

    pub async fn update_commitment_aggregate_receipt(
        &self,
        commitment_id: i64,
        receipt_id: i64,
    ) -> anyhow::Result<()> {
        let conn = self.conn.clone();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            conn.execute(
                "UPDATE commitments SET aggregate_receipt_id = ? WHERE id = ?",
                params![receipt_id, commitment_id],
            )?;
            Ok(())
        })
        .await?
    }

    pub async fn update_commitment_groth16(
        &self,
        commitment_id: i64,
        receipt_id: i64,
    ) -> anyhow::Result<()> {
        let conn = self.conn.clone();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            conn.execute(
                "UPDATE commitments SET aggregate_groth16_id = ? WHERE id = ?",
                params![receipt_id, commitment_id],
            )?;
            Ok(())
        })
        .await?
    }

    pub async fn update_commitment_txid(
        &self,
        commitment_id: i64,
        txid: &str,
    ) -> anyhow::Result<()> {
        let conn = self.conn.clone();
        let txid = txid.to_string();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            conn.execute(
                "UPDATE commitments SET commit_txid = ? WHERE id = ?",
                params![txid, commitment_id],
            )?;
            Ok(())
        })
        .await?
    }

    // Handles

    /// Add a handle to the handles table (staged, with NULL commitment_root)
    pub async fn add_handle(&self, name: &str, script_pubkey: &[u8]) -> anyhow::Result<()> {
        let conn = self.conn.clone();
        let name = name.to_string();
        let script_pubkey = script_pubkey.to_vec();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            conn.execute(
                "INSERT OR REPLACE INTO handles (name, script_pubkey, commitment_root) VALUES (?, ?, NULL)",
                params![name, script_pubkey],
            )?;
            Ok(())
        })
        .await?
    }

    pub async fn get_handle(&self, name: &str) -> anyhow::Result<Option<Handle>> {
        let conn = self.conn.clone();
        let name = name.to_string();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let handle = conn
                .query_row(
                    "SELECT id, name, script_pubkey, commitment_root, commitment_idx, publish_status FROM handles WHERE name = ?",
                    params![name],
                    |row| {
                        Ok(Handle {
                            id: row.get(0)?,
                            name: row.get(1)?,
                            script_pubkey: row.get(2)?,
                            commitment_root: row.get(3)?,
                            commitment_idx: row.get::<_, Option<i64>>(4)?.map(|v| v as usize),
                            publish_status: row.get(5)?,
                        })
                    },
                )
                .optional()?;
            Ok(handle)
        })
        .await?
    }

    pub async fn list_handles(&self) -> anyhow::Result<Vec<Handle>> {
        let conn = self.conn.clone();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let mut stmt = conn
                .prepare("SELECT id, name, script_pubkey, commitment_root, commitment_idx, publish_status FROM handles ORDER BY name ASC")?;
            let handles = stmt
                .query_map([], |row| {
                    Ok(Handle {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        script_pubkey: row.get(2)?,
                        commitment_root: row.get(3)?,
                        commitment_idx: row.get::<_, Option<i64>>(4)?.map(|v| v as usize),
                        publish_status: row.get(5)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(handles)
        })
        .await?
    }

    /// Count total handles
    pub async fn handle_count(&self) -> anyhow::Result<usize> {
        let conn = self.conn.clone();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let count: i64 = conn
                .query_row("SELECT COUNT(*) FROM handles", [], |row| row.get(0))?;
            Ok(count as usize)
        })
        .await?
    }

    /// List handles with pagination (offset and limit), ordered by most recent first
    pub async fn list_handles_paginated(
        &self,
        offset: usize,
        limit: usize,
    ) -> anyhow::Result<Vec<Handle>> {
        let conn = self.conn.clone();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let mut stmt = conn.prepare(
                "SELECT id, name, script_pubkey, commitment_root, commitment_idx, publish_status FROM handles ORDER BY id DESC LIMIT ? OFFSET ?",
            )?;
            let handles = stmt
                .query_map(params![limit as i64, offset as i64], |row| {
                    Ok(Handle {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        script_pubkey: row.get(2)?,
                        commitment_root: row.get(3)?,
                        commitment_idx: row.get::<_, Option<i64>>(4)?.map(|v| v as usize),
                        publish_status: row.get(5)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(handles)
        })
        .await?
    }

    /// List all staged handles (commitment_root IS NULL)
    pub async fn list_staged_handles(&self) -> anyhow::Result<Vec<Handle>> {
        let conn = self.conn.clone();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let mut stmt = conn
                .prepare("SELECT id, name, script_pubkey, commitment_root, commitment_idx, publish_status FROM handles WHERE commitment_root IS NULL ORDER BY name ASC")?;
            let handles = stmt
                .query_map([], |row| {
                    Ok(Handle {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        script_pubkey: row.get(2)?,
                        commitment_root: row.get(3)?,
                        commitment_idx: row.get::<_, Option<i64>>(4)?.map(|v| v as usize),
                        publish_status: row.get(5)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(handles)
        })
        .await?
    }

    /// Commit all staged handles by setting their commitment_root and commitment_idx
    pub async fn commit_staged_handles(&self, root: &str, idx: usize) -> anyhow::Result<usize> {
        let conn = self.conn.clone();
        let root = root.to_string();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let count = conn.execute(
                "UPDATE handles SET commitment_root = ?, commitment_idx = ? WHERE commitment_root IS NULL",
                params![root, idx as i64],
            )?;
            Ok(count)
        })
        .await?
    }

    /// Count staged handles (commitment_root IS NULL)
    pub async fn staged_count(&self) -> anyhow::Result<usize> {
        let conn = self.conn.clone();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM handles WHERE commitment_root IS NULL",
                [],
                |row| row.get(0),
            )?;
            Ok(count as usize)
        })
        .await?
    }

    /// Count committed handles (commitment_root IS NOT NULL)
    pub async fn committed_handle_count(&self) -> anyhow::Result<usize> {
        let conn = self.conn.clone();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM handles WHERE commitment_root IS NOT NULL",
                [],
                |row| row.get(0),
            )?;
            Ok(count as usize)
        })
        .await?
    }

    pub async fn get_handle_spk(&self, name: &str) -> anyhow::Result<Option<ScriptBuf>> {
        let conn = self.conn.clone();
        let name = name.to_string();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let spk = conn
                .query_row(
                    "SELECT script_pubkey FROM handles WHERE name = ?",
                    params![name],
                    |row| row.get(0),
                )
                .optional()?;
            Ok(spk.map(|spk| ScriptBuf::from_bytes(spk)))
        })
            .await?
    }

    /// Check if a handle is staged (exists with NULL commitment_root)
    pub async fn is_staged(&self, name: &str) -> anyhow::Result<Option<Vec<u8>>> {
        let conn = self.conn.clone();
        let name = name.to_string();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let spk = conn
                .query_row(
                    "SELECT script_pubkey FROM handles WHERE name = ? AND commitment_root IS NULL",
                    params![name],
                    |row| row.get(0),
                )
                .optional()?;
            Ok(spk)
        })
        .await?
    }

    /// List handles by commitment root
    pub async fn list_handles_by_commitment(&self, root: &str) -> anyhow::Result<Vec<Handle>> {
        let conn = self.conn.clone();
        let root = root.to_string();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let mut stmt = conn.prepare(
                "SELECT id, name, script_pubkey, commitment_root, commitment_idx, publish_status FROM handles WHERE commitment_root = ? ORDER BY name ASC",
            )?;
            let handles = stmt
                .query_map(params![root], |row| {
                    Ok(Handle {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        script_pubkey: row.get(2)?,
                        commitment_root: row.get(3)?,
                        commitment_idx: row.get::<_, Option<i64>>(4)?.map(|v| v as usize),
                        publish_status: row.get(5)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(handles)
        })
        .await?
    }

    // Publishing

    /// List handles that need certificate publishing:
    /// - publish_status IS NULL (no cert yet), or
    /// - publish_status = 'temp' AND commitment_idx <= confirmed_idx (committed and included in confirmed tip)
    pub async fn list_unpublished(&self, confirmed_idx: Option<usize>) -> anyhow::Result<Vec<Handle>> {
        let conn = self.conn.clone();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let mut stmt = conn.prepare(
                "SELECT id, name, script_pubkey, commitment_root, commitment_idx, publish_status FROM handles
                 WHERE publish_status IS NULL
                    OR (publish_status = 'temp' AND commitment_idx IS NOT NULL AND commitment_idx <= ?)
                 ORDER BY name ASC",
            )?;
            // Use -1 when no confirmed idx so the temp upgrade clause never matches
            let idx_param = confirmed_idx.map(|v| v as i64).unwrap_or(-1);
            let handles = stmt
                .query_map(params![idx_param], |row| {
                    Ok(Handle {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        script_pubkey: row.get(2)?,
                        commitment_root: row.get(3)?,
                        commitment_idx: row.get::<_, Option<i64>>(4)?.map(|v| v as usize),
                        publish_status: row.get(5)?,
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(handles)
        })
        .await?
    }

    /// Mark handles as published with a given status ('temp' or 'final')
    pub async fn mark_handles_published(
        &self,
        names: &[String],
        status: &str,
    ) -> anyhow::Result<()> {
        let conn = self.conn.clone();
        let names = names.to_vec();
        let status = status.to_string();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            for name in &names {
                conn.execute(
                    "UPDATE handles SET publish_status = ? WHERE name = ?",
                    params![status, name],
                )?;
            }
            Ok(())
        })
        .await?
    }

    /// Mark a commitment as published
    pub async fn mark_commitment_published(&self, commitment_id: i64) -> anyhow::Result<()> {
        let conn = self.conn.clone();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            conn.execute(
                "UPDATE commitments SET published_at = datetime('now') WHERE id = ?",
                params![commitment_id],
            )?;
            Ok(())
        })
        .await?
    }

    // Receipts

    pub async fn store_receipt(&self, kind: &str, data: &[u8]) -> anyhow::Result<i64> {
        let conn = self.conn.clone();
        let kind = kind.to_string();
        let data = data.to_vec();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            conn.execute(
                "INSERT INTO receipts (kind, data) VALUES (?, ?)",
                params![kind, data],
            )?;
            Ok(conn.last_insert_rowid())
        })
        .await?
    }

    pub async fn get_receipt(&self, id: i64) -> anyhow::Result<Option<Vec<u8>>> {
        let conn = self.conn.clone();
        spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            let data = conn
                .query_row("SELECT data FROM receipts WHERE id = ?", params![id], |row| {
                    row.get(0)
                })
                .optional()?;
            Ok(data)
        })
        .await?
    }
}
