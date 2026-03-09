//! Web UI routes serving HTML pages.

use askama::Template;
use axum::{
    extract::{Path, State},
    response::Html,
};
use spaces_client::rpc::RpcClient;
use spaces_client::wallets::AddressKind;
use subs::SpaceStatus;

use crate::state::AppState;

#[derive(Template)]
#[template(path = "dashboard.html")]
pub struct DashboardTemplate {
    pub spaces: Vec<SpaceStatus>,
}

#[derive(Template)]
#[template(path = "requests.html")]
pub struct RequestsTemplate;

#[derive(Template)]
#[template(path = "operate.html")]
pub struct OperateTemplate {
    pub space_address: String,
}

#[derive(Template)]
#[template(path = "certs.html")]
pub struct CertsTemplate;

#[derive(Template)]
#[template(path = "settings.html")]
pub struct SettingsTemplate;

#[derive(Template)]
#[template(path = "space.html")]
pub struct SpaceTemplate {
    pub space: SpaceStatus,
}

/// GET / - Dashboard
pub async fn dashboard(State(state): State<AppState>) -> Html<String> {
    // Load all spaces from disk first
    let _ = state.operator.load_all_spaces().await;

    let status = state.operator.status().await.unwrap_or_default();

    let template = DashboardTemplate {
        spaces: status.spaces,
    };

    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e)))
}

/// GET /ui/requests - Add requests page
pub async fn requests_page() -> Html<String> {
    let template = RequestsTemplate;
    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e)))
}

/// GET /ui/operate - Operate space page
pub async fn operate_page(State(state): State<AppState>) -> Html<String> {
    let wallet_name = state.operator.wallet().to_string();

    let space_address = if let Some(rpc) = state.operator.rpc() {
        rpc.wallet_get_new_address(&wallet_name, AddressKind::Space)
            .await
            .unwrap_or_default()
    } else {
        String::new()
    };

    let template = OperateTemplate { space_address };
    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e)))
}

/// GET /ui/certs - Certificates page
pub async fn certs_page() -> Html<String> {
    let template = CertsTemplate;
    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e)))
}

/// GET /ui/settings - Settings page
pub async fn settings_page() -> Html<String> {
    let template = SettingsTemplate;
    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e)))
}

/// GET /ui/spaces/{space} - Space detail page
pub async fn space_page(
    State(state): State<AppState>,
    Path(space): Path<String>,
) -> Html<String> {
    let space_label = match space.parse() {
        Ok(s) => s,
        Err(e) => return Html(format!("Invalid space: {}", e)),
    };

    // Ensure space is loaded
    if let Err(e) = state.operator.load_or_create_space(&space_label).await {
        return Html(format!("Error loading space: {}", e));
    }

    let status = match state.operator.get_space_status(&space_label).await {
        Ok(s) => s,
        Err(e) => return Html(format!("Error getting status: {}", e)),
    };

    let template = SpaceTemplate { space: status };
    Html(template.render().unwrap_or_else(|e| format!("Template error: {}", e)))
}
