//! Configuration storage for subsd.
//!
//! Stores global configuration like prover and registry endpoints.

use anyhow::Result;
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::sync::Mutex;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"#;

/// Configuration keys
pub const KEY_PROVER_ENDPOINT: &str = "prover_endpoint";
pub const KEY_PROVER_AUTH_TOKEN: &str = "prover_auth_token";
pub const KEY_REGISTRY_ENDPOINT: &str = "registry_endpoint";
pub const KEY_REGISTRY_AUTH_TOKEN: &str = "registry_auth_token";
pub const KEY_REGISTRY_AUTO_SYNC: &str = "registry_auto_sync";

/// Configuration storage backed by SQLite.
pub struct ConfigStore {
    conn: Mutex<Connection>,
}

impl ConfigStore {
    /// Open or create a config database at the given path.
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Create an in-memory config store (for testing).
    #[allow(dead_code)]
    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Get a configuration value by key.
    pub fn get(&self, key: &str) -> Result<Option<String>> {
        let conn = self.conn.lock().unwrap();
        let value = conn
            .query_row(
                "SELECT value FROM config WHERE key = ?",
                params![key],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        Ok(value)
    }

    /// Set a configuration value.
    pub fn set(&self, key: &str, value: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)",
            params![key, value],
        )?;
        Ok(())
    }

    /// Delete a configuration value.
    pub fn delete(&self, key: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM config WHERE key = ?", params![key])?;
        Ok(())
    }

    /// Get the prover endpoint URL.
    pub fn prover_endpoint(&self) -> Result<Option<String>> {
        self.get(KEY_PROVER_ENDPOINT)
    }

    /// Set the prover endpoint URL.
    pub fn set_prover_endpoint(&self, url: &str) -> Result<()> {
        self.set(KEY_PROVER_ENDPOINT, url)
    }

    /// Get the optional bearer token to send with prover requests.
    pub fn prover_auth_token(&self) -> Result<Option<String>> {
        self.get(KEY_PROVER_AUTH_TOKEN)
    }

    /// Set the bearer token used for prover requests.
    pub fn set_prover_auth_token(&self, token: &str) -> Result<()> {
        self.set(KEY_PROVER_AUTH_TOKEN, token)
    }

    /// Get the registry endpoint URL.
    pub fn registry_endpoint(&self) -> Result<Option<String>> {
        self.get(KEY_REGISTRY_ENDPOINT)
    }

    /// Set the registry endpoint URL.
    pub fn set_registry_endpoint(&self, url: &str) -> Result<()> {
        self.set(KEY_REGISTRY_ENDPOINT, url)
    }

    /// Get the optional bearer token to send with registry requests.
    pub fn registry_auth_token(&self) -> Result<Option<String>> {
        self.get(KEY_REGISTRY_AUTH_TOKEN)
    }

    /// Set the bearer token used for registry requests.
    pub fn set_registry_auth_token(&self, token: &str) -> Result<()> {
        self.set(KEY_REGISTRY_AUTH_TOKEN, token)
    }

    /// Whether the background loop should pull from the registry and publish
    /// certificates on its own. Off unless explicitly enabled: publishing
    /// broadcasts to the relay, so it shouldn't start just because an
    /// endpoint happens to be configured.
    pub fn registry_auto_sync(&self) -> Result<bool> {
        Ok(self.get(KEY_REGISTRY_AUTO_SYNC)?.as_deref() == Some("1"))
    }

    /// Enable or disable automatic registry sync.
    pub fn set_registry_auto_sync(&self, enabled: bool) -> Result<()> {
        self.set(KEY_REGISTRY_AUTO_SYNC, if enabled { "1" } else { "0" })
    }
}
