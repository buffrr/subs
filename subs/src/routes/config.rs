//! Configuration routes for managing prover and registry endpoints.

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};

use crate::config::{
    KEY_PROVER_AUTH_TOKEN, KEY_PROVER_ENDPOINT, KEY_REGISTRY_AUTH_TOKEN, KEY_REGISTRY_ENDPOINT,
};
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
    /// True when a registry auth token is configured. The value itself is
    /// never returned, so it can't leak via the UI / API.
    pub registry_auth_token_set: bool,
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
    /// New registry token. `Some("")` clears it. `None` leaves it unchanged.
    #[serde(default)]
    pub registry_auth_token: Option<String>,
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
    pub registry_auth_token_set: bool,
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

    let registry_auth_token_set = state
        .config
        .registry_auth_token()
        .ok()
        .flatten()
        .is_some_and(|s| !s.is_empty());
    let registry_auto_sync = state.config.registry_auto_sync().unwrap_or(false);

    Json(ConfigResponse {
        prover_endpoint,
        prover_auth_token_set,
        registry_endpoint,
        registry_auth_token_set,
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

    // Set registry auth token if provided. Empty string clears it.
    if let Some(ref token) = req.registry_auth_token {
        let result = if token.is_empty() {
            state.config.delete(KEY_REGISTRY_AUTH_TOKEN)
        } else {
            state.config.set_registry_auth_token(token)
        };
        if let Err(e) = result {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response();
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
    let registry_auth_token_set = state
        .config
        .registry_auth_token()
        .ok()
        .flatten()
        .is_some_and(|s| !s.is_empty());
    let registry_auto_sync = state.config.registry_auto_sync().unwrap_or(false);

    Json(SetConfigResponse {
        success: true,
        prover_endpoint,
        prover_auth_token_set,
        registry_endpoint,
        registry_auth_token_set,
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
pub async fn test_registry(
    State(state): State<AppState>,
    Json(req): Json<TestEndpointRequest>,
) -> impl IntoResponse {
    let endpoint = req.endpoint.trim_end_matches('/');

    // Fall back to the stored token so an existing setup can be re-tested
    // without retyping it. Explicit "" means "test without auth".
    let token = match req.auth_token {
        Some(t) if !t.is_empty() => Some(t),
        Some(_) => None,
        None => state.config.registry_auth_token().ok().flatten(),
    };

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();

    // /health sits inside the registry's authenticated set, so a 200 here
    // confirms both reachability and that the token is accepted.
    let mut probe = client.get(format!("{}/health", endpoint));
    if let Some(t) = &token {
        probe = probe.bearer_auth(t);
    }

    match probe.send().await {
        Ok(response) if response.status().is_success() => Json(TestEndpointResponse {
            success: true,
            error: None,
        }),
        Ok(response) if super::registry::auth_error(response.status()).is_some() => {
            Json(TestEndpointResponse {
                success: false,
                error: Some(match token {
                    Some(_) => format!("Registry rejected the auth token ({})", response.status()),
                    None => format!(
                        "Registry requires authentication ({}); set an auth token",
                        response.status()
                    ),
                }),
            })
        }
        Ok(response) => Json(TestEndpointResponse {
            success: false,
            error: Some(format!("Registry returned status: {}", response.status())),
        }),
        Err(e) => Json(TestEndpointResponse {
            success: false,
            error: Some(format!("Connection failed: {}", e)),
        }),
    }
}

