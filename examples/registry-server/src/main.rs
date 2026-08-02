//! Example Registry Server for Subs
//!
//! Accepts handle registrations, exposes a work queue to subsd, and receives
//! commit notifications. Two API keys guard the non-public surface:
//!
//! - `REGISTRY_API_KEY` → required on `POST /register`, this example's own
//!   intake path, on the assumption registrations arrive from a backend once
//!   a purchase is paid. How requests reach a registry is not part of the
//!   subs contract; a different registry might take them from a public form
//!   or an admin panel instead.
//! - `SUBSD_API_KEY` → required on `GET /health`, `GET /pending`, `POST /ack`,
//!   and `POST /committed` (called by subsd; it holds wallet keys so these
//!   endpoints must not be publicly reachable). `/health` sits inside the
//!   guarded set deliberately: subsd's "Test" button probes it, so a
//!   successful probe doubles as proof the token is wired correctly.
//!
//! `/status/:handle` remains open — it is the user's own status poll
//! endpoint.
//!
//! Both keys are checked as `Authorization: Bearer <key>`. If either is
//! missing at boot the process refuses to start (fail-secure).
//!
//! # Usage
//!
//! ```bash
//! REGISTRY_API_KEY=... SUBSD_API_KEY=... registry-server --port 8080
//! ```

use std::env;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::{Path, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

#[derive(Parser)]
#[command(
    name = "registry-server",
    about = "Example registry server for subs handle registration",
    version
)]
struct Cli {
    /// Server port
    #[arg(short, long, default_value = "8080")]
    port: u16,
}

/// Shared application state
struct AppState {
    /// In-memory store of registrations (in production, use a database)
    registrations: RwLock<Vec<Registration>>,
    /// Bearer token required for /register.
    registry_api_key: String,
    /// Bearer token required for /health, /pending, /ack, /committed.
    subsd_api_key: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct Registration {
    handle: String,
    script_pubkey: String,
    status: RegistrationStatus,
    commitment_root: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
enum RegistrationStatus {
    Pending,    // Waiting to be pulled by subsd
    Staged,     // Pulled by subsd, waiting for commit
    Committed,  // On-chain
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "registry_server=info,tower_http=debug".into()),
        )
        .init();

    let cli = Cli::parse();

    let registry_api_key = require_env("REGISTRY_API_KEY")?;
    let subsd_api_key = require_env("SUBSD_API_KEY")?;
    if registry_api_key == subsd_api_key {
        anyhow::bail!("REGISTRY_API_KEY and SUBSD_API_KEY must differ (blast-radius separation)");
    }

    let state = Arc::new(AppState {
        registrations: RwLock::new(Vec::new()),
        registry_api_key,
        subsd_api_key,
    });

    // Endpoints protected by REGISTRY_API_KEY (called by atbitcoin backend).
    let registry_routes = Router::new()
        .route("/register", post(register_handle))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_registry_key,
        ));

    // Endpoints protected by SUBSD_API_KEY (called by subsd).
    let subsd_routes = Router::new()
        .route("/health", get(health))
        .route("/pending", get(get_pending_handles))
        .route("/ack", post(ack_handles))
        .route("/committed", post(committed))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_subsd_key,
        ));

    let app = Router::new()
        .route("/status/:handle", get(get_status))
        .merge(registry_routes)
        .merge(subsd_routes)
        .layer(TraceLayer::new_for_http())
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], cli.port));
    tracing::info!("Registry server starting on http://{}", addr);
    tracing::info!("");
    tracing::info!("Public endpoints:");
    tracing::info!("  GET  /status/:handle    - User-facing status poll");
    tracing::info!("");
    tracing::info!("Requires REGISTRY_API_KEY (Bearer):");
    tracing::info!("  POST /register          - Enqueue a handle for registration");
    tracing::info!("");
    tracing::info!("Requires SUBSD_API_KEY (Bearer):");
    tracing::info!("  GET  /health            - Liveness + token check");
    tracing::info!("  GET  /pending           - Pull work queue");
    tracing::info!("  POST /ack               - Mark handles as staged");
    tracing::info!("  POST /committed         - Notify committed handles");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

fn require_env(name: &str) -> anyhow::Result<String> {
    match env::var(name) {
        Ok(v) if !v.trim().is_empty() => Ok(v),
        _ => anyhow::bail!(
            "{} must be set to a non-empty bearer token before starting the registry",
            name
        ),
    }
}

/// Extract the bearer token from `Authorization: Bearer <value>`.
fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::trim)
}

/// Constant-time-ish compare — good enough for short bearer tokens.
fn tokens_match(supplied: &str, expected: &str) -> bool {
    if supplied.len() != expected.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in supplied.bytes().zip(expected.bytes()) {
        diff |= a ^ b;
    }
    diff == 0
}

async fn require_registry_key(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    match bearer(request.headers()) {
        Some(token) if tokens_match(token, &state.registry_api_key) => Ok(next.run(request).await),
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}

async fn require_subsd_key(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    match bearer(request.headers()) {
        Some(token) if tokens_match(token, &state.subsd_api_key) => Ok(next.run(request).await),
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}

/// Health check endpoint
async fn health() -> &'static str {
    "ok"
}

#[derive(Deserialize)]
struct RegisterRequest {
    /// Handle to register (e.g., "alice@example")
    handle: String,
    /// Script pubkey in hex (the owner's taproot address script)
    script_pubkey: String,
}

#[derive(Serialize)]
struct RegisterResponse {
    success: bool,
    message: String,
}

/// POST /register - Register a new handle
async fn register_handle(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterRequest>,
) -> impl IntoResponse {
    tracing::info!("Registration request for handle: {}", req.handle);

    if !req.handle.contains('@') {
        return (
            StatusCode::BAD_REQUEST,
            Json(RegisterResponse {
                success: false,
                message: "Invalid handle format. Expected: name@space".to_string(),
            }),
        );
    }

    {
        let registrations = state.registrations.read().await;
        if registrations.iter().any(|r| r.handle == req.handle) {
            return (
                StatusCode::CONFLICT,
                Json(RegisterResponse {
                    success: false,
                    message: "Handle already registered".to_string(),
                }),
            );
        }
    }

    {
        let mut registrations = state.registrations.write().await;
        registrations.push(Registration {
            handle: req.handle.clone(),
            script_pubkey: req.script_pubkey,
            status: RegistrationStatus::Pending,
            commitment_root: None,
        });
    }

    tracing::info!("Handle {} added to pending registrations", req.handle);
    (
        StatusCode::OK,
        Json(RegisterResponse {
            success: true,
            message: format!("Handle {} has been queued for registration", req.handle),
        }),
    )
}

#[derive(Serialize)]
struct StatusResponse {
    handle: String,
    status: String,
    commitment_root: Option<String>,
}

/// GET /status/:handle - Get registration status (public)
async fn get_status(
    State(state): State<Arc<AppState>>,
    Path(handle): Path<String>,
) -> impl IntoResponse {
    let registrations = state.registrations.read().await;

    if let Some(reg) = registrations.iter().find(|r| r.handle == handle) {
        let status_str = match reg.status {
            RegistrationStatus::Pending => "pending",
            RegistrationStatus::Staged => "staged",
            RegistrationStatus::Committed => "committed",
        };
        Json(StatusResponse {
            handle: reg.handle.clone(),
            status: status_str.to_string(),
            commitment_root: reg.commitment_root.clone(),
        })
    } else {
        Json(StatusResponse {
            handle,
            status: "not_found".to_string(),
            commitment_root: None,
        })
    }
}

#[derive(Serialize)]
struct PendingHandle {
    handle: String,
    script_pubkey: String,
}

#[derive(Serialize)]
struct PendingResponse {
    handles: Vec<PendingHandle>,
}

/// GET /pending - Get pending handles for subsd to stage
async fn get_pending_handles(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let registrations = state.registrations.read().await;

    let pending: Vec<PendingHandle> = registrations
        .iter()
        .filter(|r| r.status == RegistrationStatus::Pending)
        .map(|r| PendingHandle {
            handle: r.handle.clone(),
            script_pubkey: r.script_pubkey.clone(),
        })
        .collect();

    tracing::info!("Returning {} pending handles", pending.len());
    Json(PendingResponse { handles: pending })
}

#[derive(Deserialize)]
struct AckRequest {
    handles: Vec<String>,
}

#[derive(Serialize)]
struct AckResponse {
    acknowledged: usize,
}

/// POST /ack - Acknowledge handles were staged by subsd
async fn ack_handles(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AckRequest>,
) -> impl IntoResponse {
    let mut registrations = state.registrations.write().await;
    let mut count = 0;

    for handle in &req.handles {
        if let Some(reg) = registrations.iter_mut().find(|r| r.handle == *handle) {
            if reg.status == RegistrationStatus::Pending {
                reg.status = RegistrationStatus::Staged;
                count += 1;
                tracing::info!("Handle {} acknowledged as staged", handle);
            }
        }
    }

    Json(AckResponse { acknowledged: count })
}

#[derive(Deserialize)]
struct CommittedPayload {
    root: String,
    handles: Vec<String>,
}

#[derive(Serialize)]
struct CommittedResponse {
    received: bool,
    updated: usize,
}

/// POST /committed - Called by subsd when handles are committed on-chain
async fn committed(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CommittedPayload>,
) -> impl IntoResponse {
    tracing::info!(
        "Webhook: {} handles committed with root {}",
        payload.handles.len(),
        payload.root
    );

    let mut registrations = state.registrations.write().await;
    let mut count = 0;

    for handle in &payload.handles {
        if let Some(reg) = registrations.iter_mut().find(|r| r.handle == *handle) {
            reg.status = RegistrationStatus::Committed;
            reg.commitment_root = Some(payload.root.clone());
            count += 1;
            tracing::info!("Handle {} marked as committed", handle);
        }
    }

    Json(CommittedResponse {
        received: true,
        updated: count,
    })
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::info!("Shutdown signal received");
}