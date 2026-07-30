//! Configuration routes for managing prover and registry endpoints.

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};

use crate::config::{KEY_PROVER_AUTH_TOKEN, KEY_PROVER_ENDPOINT, KEY_REGISTRY_ENDPOINT};
use crate::state::AppState;

#[derive(Deserialize)]
pub struct TestEndpointRequest {
    pub endpoint: String,
    /// Optional bearer token sent on the test request.
    #[serde(default)]
    pub auth_token: Option<String>,
}

#[derive(Serialize)]
pub struct TestEndpointResponse {
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Serialize)]
pub struct ConfigResponse {
    pub prover_endpoint: Option<String>,
    /// True when an auth token is configured. The actual token value is not
    /// returned so it doesn't leak via the UI / API.
    pub prover_auth_token_set: bool,
    pub registry_endpoint: Option<String>,
    /// Whether the background loop pulls from the registry and publishes.
    pub registry_auto_sync: bool,
}

#[derive(Deserialize)]
pub struct SetConfigRequest {
    pub prover_endpoint: Option<String>,
    /// New auth token. `Some("")` clears it. `None` leaves it unchanged.
    #[serde(default)]
    pub prover_auth_token: Option<String>,
    pub registry_endpoint: Option<String>,
    /// `None` leaves the auto-sync setting unchanged.
    #[serde(default)]
    pub registry_auto_sync: Option<bool>,
}

#[derive(Serialize)]
pub struct SetConfigResponse {
    pub success: bool,
    pub prover_endpoint: Option<String>,
    pub prover_auth_token_set: bool,
    pub registry_endpoint: Option<String>,
    pub registry_auto_sync: bool,
}

/// GET /config - Get current configuration
pub async fn get_config(State(state): State<AppState>) -> impl IntoResponse {
    let prover_endpoint = match state.config.prover_endpoint() {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    };

    let prover_auth_token_set = state
        .config
        .prover_auth_token()
        .ok()
        .flatten()
        .is_some_and(|s| !s.is_empty());

    let registry_endpoint = match state.config.registry_endpoint() {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    };

    let registry_auto_sync = state.config.registry_auto_sync().unwrap_or(false);

    Json(ConfigResponse {
        prover_endpoint,
        prover_auth_token_set,
        registry_endpoint,
        registry_auto_sync,
    })
    .into_response()
}

/// POST /config - Set configuration values
pub async fn set_config(
    State(state): State<AppState>,
    Json(req): Json<SetConfigRequest>,
) -> impl IntoResponse {
    // Set prover endpoint if provided
    if let Some(ref url) = req.prover_endpoint {
        if url.is_empty() {
            if let Err(e) = state.config.delete(KEY_PROVER_ENDPOINT) {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": e.to_string() })),
                )
                    .into_response();
            }
        } else {
            if let Err(e) = state.config.set_prover_endpoint(url) {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": e.to_string() })),
                )
                    .into_response();
            }
        }
    }

    // Set prover auth token if provided. Empty string clears it.
    if let Some(ref token) = req.prover_auth_token {
        if token.is_empty() {
            if let Err(e) = state.config.delete(KEY_PROVER_AUTH_TOKEN) {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": e.to_string() })),
                )
                    .into_response();
            }
        } else if let Err(e) = state.config.set_prover_auth_token(token) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    }

    // Set registry endpoint if provided
    if let Some(ref url) = req.registry_endpoint {
        if url.is_empty() {
            if let Err(e) = state.config.delete(KEY_REGISTRY_ENDPOINT) {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": e.to_string() })),
                )
                    .into_response();
            }
        } else {
            if let Err(e) = state.config.set_registry_endpoint(url) {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": e.to_string() })),
                )
                    .into_response();
            }
        }
    }

    // Set auto-sync if provided
    if let Some(enabled) = req.registry_auto_sync {
        if let Err(e) = state.config.set_registry_auto_sync(enabled) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    }

    // Return current config
    let prover_endpoint = state.config.prover_endpoint().ok().flatten();
    let prover_auth_token_set = state
        .config
        .prover_auth_token()
        .ok()
        .flatten()
        .is_some_and(|s| !s.is_empty());
    let registry_endpoint = state.config.registry_endpoint().ok().flatten();
    let registry_auto_sync = state.config.registry_auto_sync().unwrap_or(false);

    Json(SetConfigResponse {
        success: true,
        prover_endpoint,
        prover_auth_token_set,
        registry_endpoint,
        registry_auto_sync,
    })
    .into_response()
}

/// POST /config/test/prover - Test prover endpoint connectivity
pub async fn test_prover(
    State(state): State<AppState>,
    Json(req): Json<TestEndpointRequest>,
) -> impl IntoResponse {
    let endpoint = req.endpoint.trim_end_matches('/');

    // If the request didn't include a token, fall back to the stored one so
    // the user can re-test an existing setup without re-typing it.
    let token = match req.auth_token {
        Some(t) if !t.is_empty() => Some(t),
        Some(_) => None, // explicit empty string: test without auth
        None => state.config.prover_auth_token().ok().flatten(),
    };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();

    let health_url = format!("{}/health", endpoint);
    let mut req = client.get(&health_url);
    if let Some(t) = &token {
        req = req.bearer_auth(t);
    }

    match req.send().await {
        Ok(response) => {
            if response.status().is_success() {
                Json(TestEndpointResponse {
                    success: true,
                    error: None,
                })
            } else {
                Json(TestEndpointResponse {
                    success: false,
                    error: Some(format!("Prover returned status: {}", response.status())),
                })
            }
        }
        Err(e) => Json(TestEndpointResponse {
            success: false,
            error: Some(format!("Connection failed: {}", e)),
        }),
    }
}

/// POST /config/test/registry - Test registry endpoint connectivity
pub async fn test_registry(Json(req): Json<TestEndpointRequest>) -> impl IntoResponse {
    let endpoint = req.endpoint.trim_end_matches('/');

    // Try to connect to the registry's health endpoint
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();

    // Try common health check paths
    let health_url = format!("{}/health", endpoint);

    match client.get(&health_url).send().await {
        Ok(response) => {
            if response.status().is_success() {
                Json(TestEndpointResponse {
                    success: true,
                    error: None,
                })
            } else if response.status().as_u16() == 404 {
                // Try root path if /health doesn't exist
                match client.get(endpoint).send().await {
                    Ok(resp) => {
                        if resp.status().is_success() || resp.status().as_u16() < 500 {
                            Json(TestEndpointResponse {
                                success: true,
                                error: None,
                            })
                        } else {
                            Json(TestEndpointResponse {
                                success: false,
                                error: Some(format!("Registry returned status: {}", resp.status())),
                            })
                        }
                    }
                    Err(e) => Json(TestEndpointResponse {
                        success: false,
                        error: Some(format!("Connection failed: {}", e)),
                    }),
                }
            } else {
                Json(TestEndpointResponse {
                    success: false,
                    error: Some(format!("Registry returned status: {}", response.status())),
                })
            }
        }
        Err(e) => Json(TestEndpointResponse {
            success: false,
            error: Some(format!("Connection failed: {}", e)),
        }),
    }
}
