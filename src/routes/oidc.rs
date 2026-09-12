//! OIDC Discovery 与 JWKS。

use axum::extract::State;
use axum::Json;
use serde_json::{json, Value};

use club_auth_sdk::Jwks;
use club_common::AppError;

use crate::state::SharedState;

/// OIDC Discovery 文档。
pub async fn discovery(State(state): State<SharedState>) -> Json<Value> {
    let issuer = &state.config.issuer;
    Json(json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/api/v1/auth/oidc/authorize"),
        "token_endpoint": format!("{issuer}/api/v1/auth/oidc/token"),
        "userinfo_endpoint": format!("{issuer}/api/v1/auth/me"),
        "jwks_uri": format!("{issuer}/.well-known/jwks.json"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "code_challenge_methods_supported": ["S256"],
    }))
}

/// JWKS 公钥集合。
pub async fn jwks(State(state): State<SharedState>) -> Result<Json<Jwks>, AppError> {
    state.keys.jwks().map(Json).map_err(AppError::internal)
}
