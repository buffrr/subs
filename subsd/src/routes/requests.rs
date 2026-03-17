//! Handle request endpoints.

use axum::{
    extract::State,
    http::StatusCode,
    Json,
    response::Response,
};
use serde::{Deserialize, Serialize};
use subs::{AddResult, HandleRequest};

use crate::state::AppState;
use super::json_error;

#[derive(Deserialize)]
pub struct AddRequestsBody {
    pub requests: Vec<HandleRequest>,
}

/// POST /requests - Add handle requests
pub async fn add_requests(
    State(state): State<AppState>,
    Json(body): Json<AddRequestsBody>,
) -> Result<Json<AddResult>, Response> {
    if body.requests.is_empty() {
        return Err(json_error(StatusCode::BAD_REQUEST, "no requests provided"));
    }

    state
        .operator
        .add_requests(body.requests)
        .await
        .map(Json)
        .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, e))
}

#[derive(Deserialize)]
pub struct GenerateRequestBody {
    pub handle: String,
    #[serde(default)]
    pub script_pubkey: Option<String>,
}

#[derive(Serialize)]
pub struct GenerateRequestResponse {
    pub request: HandleRequest,
    /// Private key (WIF format) if generated, null if script_pubkey was provided
    pub private_key: Option<String>,
}

/// POST /requests/generate - Generate a new handle request with optional keypair
pub async fn generate_request(
    Json(body): Json<GenerateRequestBody>,
) -> Result<Json<GenerateRequestResponse>, Response> {
    use bitcoin::key::Secp256k1;
    use bitcoin::secp256k1::rand;
    use bitcoin::{PrivateKey, Network, Address, XOnlyPublicKey};
    use libveritas::sname::SName;

    let handle: SName = body
        .handle
        .parse()
        .map_err(|e| json_error(StatusCode::BAD_REQUEST, format!("invalid handle: {}", e)))?;

    let (script_pubkey, private_key) = if let Some(spk) = body.script_pubkey {
        (spk, None)
    } else {
        // Generate new keypair
        let secp = Secp256k1::new();
        let keypair = bitcoin::secp256k1::Keypair::new(&secp, &mut rand::thread_rng());
        let (xonly, _parity) = XOnlyPublicKey::from_keypair(&keypair);

        let address = Address::p2tr(&secp, xonly, None, Network::Bitcoin);
        let spk = hex::encode(address.script_pubkey().as_bytes());

        let private_key = PrivateKey::new(keypair.secret_key(), Network::Bitcoin);

        (spk, Some(private_key.to_wif()))
    };

    let request = HandleRequest {
        handle,
        script_pubkey,
    };

    Ok(Json(GenerateRequestResponse {
        request,
        private_key,
    }))
}

#[derive(Deserialize)]
pub struct BulkGenerateBody {
    /// Space name (e.g. "@test10000")
    pub space: String,
    /// Number of handles to generate and stage
    pub count: usize,
    /// Optional prefix for handle names (default: "h")
    #[serde(default = "default_prefix")]
    pub prefix: String,
}

fn default_prefix() -> String {
    "h".to_string()
}

#[derive(Serialize)]
pub struct BulkGenerateResponse {
    pub staged: usize,
}

/// POST /requests/bulk-generate - Generate and stage N handles with random keys
pub async fn bulk_generate(
    State(state): State<AppState>,
    Json(body): Json<BulkGenerateBody>,
) -> Result<Json<BulkGenerateResponse>, Response> {
    use bitcoin::key::Secp256k1;
    use bitcoin::secp256k1::rand;
    use bitcoin::{Network, Address, XOnlyPublicKey};

    if body.count == 0 {
        return Err(json_error(StatusCode::BAD_REQUEST, "count must be > 0"));
    }

    let secp = Secp256k1::new();
    let mut requests = Vec::with_capacity(body.count);

    for i in 0..body.count {
        let handle_str = format!("{}{}{}", body.prefix, i, body.space);
        let handle: libveritas::sname::SName = handle_str
            .parse()
            .map_err(|e| json_error(StatusCode::BAD_REQUEST, format!("invalid handle {}: {}", handle_str, e)))?;

        let keypair = bitcoin::secp256k1::Keypair::new(&secp, &mut rand::thread_rng());
        let (xonly, _parity) = XOnlyPublicKey::from_keypair(&keypair);
        let address = Address::p2tr(&secp, xonly, None, Network::Bitcoin);
        let script_pubkey = hex::encode(address.script_pubkey().as_bytes());

        requests.push(HandleRequest {
            handle,
            script_pubkey,
        });
    }

    let count = requests.len();
    state
        .operator
        .add_requests(requests)
        .await
        .map_err(|e| json_error(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok(Json(BulkGenerateResponse { staged: count }))
}
