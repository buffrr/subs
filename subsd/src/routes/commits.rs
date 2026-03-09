//! Commit endpoints.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
    response::Response,
};
use serde::{Deserialize, Serialize};
use subs::{PipelineStatus, SpaceCommitResult};

use crate::state::AppState;
use super::json_error;

/// Recommended fee rates from mempool.space
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecommendedFees {
    pub fastest_fee: u64,
    pub half_hour_fee: u64,
    pub hour_fee: u64,
    pub economy_fee: u64,
    pub minimum_fee: u64,
}

/// Fetch recommended fees from mempool.space API
async fn fetch_recommended_fees() -> Option<RecommendedFees> {
    let url = "https://mempool.space/api/v1/fees/recommended";

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .ok()?;

    client
        .get(url)
        .send()
        .await
        .ok()?
        .json::<RecommendedFees>()
        .await
        .ok()
}

/// GET /fees - Get recommended fee rates
pub async fn get_fees() -> Result<Json<RecommendedFees>, Response> {
    match fetch_recommended_fees().await {
        Some(fees) => Ok(Json(fees)),
        None => Err(json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "could not fetch fee rates from mempool.space",
        )),
    }
}

#[derive(Deserialize)]
pub struct CommitBody {
    #[serde(default)]
    pub dry_run: bool,
}

/// POST /spaces/{space}/commit - Commit staged handles locally
pub async fn commit_local(
    State(state): State<AppState>,
    Path(space): Path<String>,
    Json(body): Json<CommitBody>,
) -> Result<Json<SpaceCommitResult>, Response> {
    let space = space
        .parse()
        .map_err(|e| json_error(StatusCode::BAD_REQUEST, format!("invalid space: {}", e)))?;

    if body.dry_run {
        // For dry run, check if commit is possible
        if let Some(reason) = state
            .operator
            .can_commit_local(&space)
            .await
            .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, e))?
        {
            return Err(json_error(StatusCode::BAD_REQUEST, format!("cannot commit: {}", reason)));
        }
        // Return empty result for dry run
        return Ok(Json(SpaceCommitResult {
            space: space.clone(),
            prev_root: None,
            root: String::new(),
            handles_committed: 0,
            is_initial: false,
        }));
    }

    state
        .operator
        .commit_local(&space)
        .await
        .map(Json)
        .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, e))
}

#[derive(Deserialize)]
pub struct BroadcastBody {
    #[serde(default)]
    pub fee_rate: Option<f64>,
}

#[derive(Serialize)]
pub struct BroadcastResponse {
    pub txid: String,
}

/// POST /spaces/:space/broadcast - Broadcast commit on-chain
pub async fn broadcast(
    State(state): State<AppState>,
    Path(space): Path<String>,
    Json(body): Json<BroadcastBody>,
) -> Result<Json<BroadcastResponse>, Response> {
    use bitcoin::FeeRate;

    let space = space
        .parse()
        .map_err(|e| json_error(StatusCode::BAD_REQUEST, format!("invalid space: {}", e)))?;

    let fee_rate = body.fee_rate.map(|r| FeeRate::from_sat_per_vb_unchecked(r as u64));

    let txid = state
        .operator
        .commit(&space, fee_rate)
        .await
        .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok(Json(BroadcastResponse {
        txid: txid.to_string(),
    }))
}

#[derive(Serialize)]
pub struct CommitStatusResponse {
    pub status: String,
    pub txid: Option<String>,
    pub block_height: Option<u32>,
    pub confirmations: Option<u32>,
}

/// GET /spaces/{space}/commit/status - Get on-chain commit status
pub async fn get_commit_status(
    State(state): State<AppState>,
    Path(space): Path<String>,
) -> Result<Json<CommitStatusResponse>, Response> {
    use subs::app::CommitStatus;

    let space = space
        .parse()
        .map_err(|e| json_error(StatusCode::BAD_REQUEST, format!("invalid space: {}", e)))?;

    let status = state
        .operator
        .get_commit_status(&space)
        .await
        .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    let response = match status {
        CommitStatus::None => CommitStatusResponse {
            status: "none".to_string(),
            txid: None,
            block_height: None,
            confirmations: None,
        },
        CommitStatus::Pending { txid, .. } => CommitStatusResponse {
            status: "pending".to_string(),
            txid: Some(txid.to_string()),
            block_height: None,
            confirmations: None,
        },
        CommitStatus::Confirmed {
            txid,
            block_height,
            confirmations,
        } => CommitStatusResponse {
            status: "confirmed".to_string(),
            txid: Some(txid.to_string()),
            block_height: Some(block_height),
            confirmations: Some(confirmations),
        },
        CommitStatus::Finalized { block_height } => CommitStatusResponse {
            status: "finalized".to_string(),
            txid: None,
            block_height: Some(block_height),
            confirmations: None,
        },
    };

    Ok(Json(response))
}

#[derive(Serialize)]
pub struct PublishResponse {
    pub handles_published: usize,
}

/// POST /spaces/:space/publish - Publish final certs for finalized commitment
pub async fn publish_certs(
    State(state): State<AppState>,
    Path(space): Path<String>,
) -> Result<Json<PublishResponse>, Response> {
    let space = space
        .parse()
        .map_err(|e| json_error(StatusCode::BAD_REQUEST, format!("invalid space: {}", e)))?;

    let count = state
        .operator
        .publish_final_certs(&space)
        .await
        .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok(Json(PublishResponse {
        handles_published: count,
    }))
}

/// POST /spaces/:space/publish/staged - Publish temp certs for staged handles
pub async fn publish_staged(
    State(state): State<AppState>,
    Path(space): Path<String>,
) -> Result<Json<PublishResponse>, Response> {
    let space = space
        .parse()
        .map_err(|e| json_error(StatusCode::BAD_REQUEST, format!("invalid space: {}", e)))?;

    let count = state
        .operator
        .publish_staged_certs(&space)
        .await
        .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok(Json(PublishResponse {
        handles_published: count,
    }))
}

/// GET /spaces/:space/pipeline - Get commitment pipeline status for stepper UI
pub async fn get_pipeline_status(
    State(state): State<AppState>,
    Path(space): Path<String>,
) -> Result<Json<PipelineStatus>, Response> {
    let space = space
        .parse()
        .map_err(|e| json_error(StatusCode::BAD_REQUEST, format!("invalid space: {}", e)))?;

    // Ensure space is loaded
    state
        .operator
        .load_or_create_space(&space)
        .await
        .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    state
        .operator
        .get_pipeline_status(&space)
        .await
        .map(Json)
        .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, e))
}
