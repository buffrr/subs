//! Query endpoint for resolving handles via fabric.

use axum::{
    extract::State,
    http::StatusCode,
    Json,
    response::Response,
};
use serde::Deserialize;

use crate::state::AppState;
use super::json_error;

#[derive(Deserialize)]
pub struct QueryBody {
    pub handle: String,
}

/// POST /query - Resolve one or more comma-separated handles via the fabric network
pub async fn resolve_handle(
    State(state): State<AppState>,
    Json(body): Json<QueryBody>,
) -> Result<Json<Vec<libveritas::Zone>>, Response> {
    let handles: Vec<&str> = body.handle.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
    if handles.is_empty() {
        return Err(json_error(StatusCode::BAD_REQUEST, anyhow::anyhow!("no handles provided")));
    }
    state
        .operator
        .resolve(&handles)
        .await
        .map(Json)
        .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, e))
}
