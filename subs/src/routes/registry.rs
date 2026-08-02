//! Registry integration routes.
//!
//! These routes allow subsd to pull pending handles from a configured registry
//! server and notify it when handles are committed.

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};

use crate::state::AppState;
use super::json_error;

#[derive(Serialize)]
pub struct SyncResponse {
    pub success: bool,
    pub pulled: usize,
    pub staged: usize,
    pub errors: Vec<String>,
}

#[derive(Deserialize)]
struct RegistryPendingResponse {
    handles: Vec<PendingHandle>,
}

#[derive(Deserialize)]
struct PendingHandle {
    handle: String,
    script_pubkey: String,
}

/// Outcome of a single pull -> stage -> ack cycle.
pub struct SyncOutcome {
    pub pulled: usize,
    pub staged: usize,
    pub errors: Vec<String>,
}

/// Pull pending handles from the registry, stage them, and acknowledge.
///
/// Shared by `POST /registry/sync` and the background loop, so the caller
/// decides what a missing endpoint means (400 for the route, skip for the
/// loop) rather than this deciding for them.
pub async fn sync_once(
    state: &AppState,
    registry_endpoint: &str,
    auth_token: Option<&str>,
) -> anyhow::Result<SyncOutcome> {
    let base = registry_endpoint.trim_end_matches('/');

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    let mut req = client.get(format!("{}/pending", base));
    if let Some(t) = auth_token {
        req = req.bearer_auth(t);
    }
    let response = req
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("failed to connect to registry: {}", e))?;

    if let Some(msg) = auth_error(response.status()) {
        anyhow::bail!(msg);
    }
    if !response.status().is_success() {
        anyhow::bail!("registry returned status: {}", response.status());
    }

    let pending: RegistryPendingResponse = response
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("invalid response from registry: {}", e))?;

    if pending.handles.is_empty() {
        return Ok(SyncOutcome {
            pulled: 0,
            staged: 0,
            errors: vec![],
        });
    }

    tracing::info!("Pulled {} pending handles from registry", pending.handles.len());

    let mut errors = Vec::new();

    // Group by space before staging. add_requests aborts the whole call if any
    // one space can't be loaded — an unknown space, a wallet that can't operate
    // it — so batching every space together lets one bad handle sink handles
    // that would otherwise stage fine.
    let mut by_space: std::collections::HashMap<String, Vec<(String, subs_core::HandleRequest)>> =
        std::collections::HashMap::new();

    for handle in &pending.handles {
        let handle_name: spaces_protocol::sname::SName = match handle.handle.parse() {
            Ok(h) => h,
            Err(e) => {
                errors.push(format!("{}: invalid handle: {}", handle.handle, e));
                continue;
            }
        };

        let space = match handle_name.space() {
            Some(s) => s.to_string(),
            None => {
                errors.push(format!("{}: handle has no space", handle.handle));
                continue;
            }
        };

        by_space.entry(space).or_default().push((
            handle.handle.clone(),
            subs_core::HandleRequest {
                handle: handle_name,
                script_pubkey: handle.script_pubkey.clone(),
                dev_private_key: None,
            },
        ));
    }

    let mut staged = 0;
    let mut to_ack: Vec<String> = Vec::new();

    for (space, entries) in by_space {
        let (names, requests): (Vec<String>, Vec<subs_core::HandleRequest>) =
            entries.into_iter().unzip();

        match state.operator.add_requests(requests).await {
            Ok(result) => {
                tracing::info!("[{}] Staged {} handles", space, result.total_added);
                for space_result in &result.by_space {
                    for skip in &space_result.skipped {
                        tracing::info!("Skipped: {} ({:?})", skip.handle, skip.reason);
                    }
                }
                staged += result.total_added;
                // Skips are settled outcomes (already staged, already
                // committed, taken by another spk), so they're acked too —
                // leaving them pending would re-pull them forever.
                to_ack.extend(names);
            }
            Err(e) => {
                // Deliberately not acked. Staging never happened, so acking
                // would mark them done at the registry and lose them; leaving
                // them pending means a fixed operator config picks them up.
                errors.push(format!("{}: failed to stage: {}", space, e));
            }
        }
    }

    // A failed ack leaves handles Pending at the registry, and the next cycle
    // re-pulls and re-acks them (add_requests dedupes), so this self-heals.
    if !to_ack.is_empty() {
        if let Err(e) = ack(&client, base, auth_token, &to_ack).await {
            // Not fatal: staging already succeeded locally.
            tracing::warn!("Failed to acknowledge handles to registry: {}", e);
            errors.push(format!("ack failed: {}", e));
        }
    }

    Ok(SyncOutcome {
        pulled: pending.handles.len(),
        staged,
        errors,
    })
}

/// POST /ack, checking the response rather than firing and forgetting.
async fn ack(
    client: &reqwest::Client,
    base: &str,
    auth_token: Option<&str>,
    handles: &[String],
) -> anyhow::Result<()> {
    #[derive(Serialize)]
    struct AckRequest<'a> {
        handles: &'a [String],
    }

    let mut req = client
        .post(format!("{}/ack", base))
        .json(&AckRequest { handles });
    if let Some(t) = auth_token {
        req = req.bearer_auth(t);
    }
    let response = req.send().await?;

    if let Some(msg) = auth_error(response.status()) {
        anyhow::bail!(msg);
    }
    if !response.status().is_success() {
        anyhow::bail!("registry returned {}", response.status());
    }
    Ok(())
}

/// Name the likely fix when the registry rejects our credentials, so a bad
/// token doesn't read like an ordinary upstream failure.
pub(crate) fn auth_error(status: reqwest::StatusCode) -> Option<String> {
    matches!(
        status,
        reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN
    )
    .then(|| format!("registry rejected our credentials ({}); check the auth token in Settings", status))
}

/// POST /registry/sync - Pull pending handles from registry and stage them
///
/// Only works when registry_endpoint is configured in settings.
pub async fn sync_from_registry(State(state): State<AppState>) -> Result<Json<SyncResponse>, impl IntoResponse> {
    let registry_endpoint = match state.config.registry_endpoint() {
        Ok(Some(url)) => url,
        Ok(None) => {
            return Err(json_error(
                StatusCode::BAD_REQUEST,
                "registry_endpoint not configured. Set it in Settings.",
            ));
        }
        Err(e) => {
            return Err(json_error(StatusCode::INTERNAL_SERVER_ERROR, e));
        }
    };

    let auth_token = state.config.registry_auth_token().ok().flatten();

    match sync_once(&state, &registry_endpoint, auth_token.as_deref()).await {
        Ok(outcome) => Ok(Json(SyncResponse {
            success: outcome.errors.is_empty(),
            pulled: outcome.pulled,
            staged: outcome.staged,
            errors: outcome.errors,
        })),
        Err(e) => Err(json_error(StatusCode::BAD_GATEWAY, e)),
    }
}

#[derive(Deserialize)]
pub struct NotifyRequest {
    /// Space to notify about (e.g., "@example")
    pub space: String,
    /// Commitment root
    pub root: String,
}

#[derive(Serialize)]
pub struct NotifyResponse {
    pub success: bool,
    pub notified: usize,
    pub message: Option<String>,
}

/// POST /registry/notify - Notify registry that handles were committed
///
/// Call this after a commitment is finalized to update the registry.
pub async fn notify_registry(
    State(state): State<AppState>,
    Json(req): Json<NotifyRequest>,
) -> Result<Json<NotifyResponse>, impl IntoResponse> {
    // Check if registry endpoint is configured
    let registry_endpoint = match state.config.registry_endpoint() {
        Ok(Some(url)) => url,
        Ok(None) => {
            return Err(json_error(
                StatusCode::BAD_REQUEST,
                "registry_endpoint not configured",
            ));
        }
        Err(e) => {
            return Err(json_error(StatusCode::INTERNAL_SERVER_ERROR, e));
        }
    };

    let space_label = req.space.parse().map_err(|e| {
        json_error(StatusCode::BAD_REQUEST, format!("invalid space: {}", e))
    })?;

    // Get handles for this commitment root
    let handles = state
        .operator
        .get_handles_by_commitment(&space_label, &req.root)
        .await
        .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    if handles.is_empty() {
        return Ok(Json(NotifyResponse {
            success: true,
            notified: 0,
            message: Some("No handles found for this commitment".to_string()),
        }));
    }

    // Build handle names (name@space format)
    let space_suffix = req.space.trim_start_matches('@');
    let handle_names: Vec<String> = handles
        .iter()
        .map(|h| format!("{}@{}", h.name, space_suffix))
        .collect();

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap();

    let committed_url = format!("{}/committed", registry_endpoint.trim_end_matches('/'));

    #[derive(Serialize)]
    struct WebhookPayload {
        root: String,
        handles: Vec<String>,
    }

    let payload = WebhookPayload {
        root: req.root,
        handles: handle_names.clone(),
    };

    let mut notify_req = client.post(&committed_url).json(&payload);
    if let Some(t) = state.config.registry_auth_token().ok().flatten() {
        notify_req = notify_req.bearer_auth(t);
    }
    let response = match notify_req.send().await {
        Ok(r) => r,
        Err(e) => {
            return Err(json_error(
                StatusCode::BAD_GATEWAY,
                format!("Failed to notify registry: {}", e),
            ));
        }
    };

    if !response.status().is_success() {
        return Err(json_error(
            StatusCode::BAD_GATEWAY,
            format!("Registry /committed returned: {}", response.status()),
        ));
    }

    Ok(Json(NotifyResponse {
        success: true,
        notified: handle_names.len(),
        message: None,
    }))
}

#[derive(Serialize)]
pub struct RegistryStatusResponse {
    pub configured: bool,
    pub endpoint: Option<String>,
}

/// GET /registry/status - Check if registry is configured
pub async fn registry_status(State(state): State<AppState>) -> impl IntoResponse {
    let endpoint = state.config.registry_endpoint().ok().flatten();

    Json(RegistryStatusResponse {
        configured: endpoint.is_some(),
        endpoint,
    })
}
