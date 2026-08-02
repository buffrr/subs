//! Log tail endpoint backing the Logs page.

use axum::{extract::Query, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

use crate::logs::{global, LogEntry};

/// Cap per response so a client that has been away doesn't pull the whole
/// ring buffer in one go.
const MAX_BATCH: usize = 1000;

#[derive(Deserialize)]
pub struct LogsQuery {
    /// Return entries with `seq >= after`. Omit for the tail.
    #[serde(default)]
    pub after: Option<u64>,
    /// Max entries to return (clamped to MAX_BATCH).
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Serialize)]
pub struct LogsResponse {
    pub entries: Vec<LogEntry>,
    /// Pass back as `after` on the next poll.
    pub head: u64,
}

/// GET /logs - Recent log entries.
pub async fn get_logs(Query(q): Query<LogsQuery>) -> impl IntoResponse {
    let buffer = global();
    let limit = q.limit.unwrap_or(MAX_BATCH).min(MAX_BATCH);

    // No cursor means a fresh page load: show the tail rather than replaying
    // everything retained.
    let after = q.after.unwrap_or_else(|| buffer.head().saturating_sub(limit as u64));

    Json(LogsResponse {
        entries: buffer.since(after, limit),
        head: buffer.head(),
    })
}
