//! 游客接口：票据换取 scope 化的短期游客 JWT。

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};

use club_common::{new_id, AppError};

use crate::crypto;
use crate::domain::{build_guest_claims, guest_ttl};
use crate::repo;
use crate::state::SharedState;

/// 游客票据兑换请求。
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GuestExchangeRequest {
    /// 邀请链接中的票据。
    pub ticket: String,
    /// 游客显示名（默认"游客"）。
    pub display_name: Option<String>,
}

/// 游客票据兑换响应。
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GuestExchangeResponse {
    /// 游客 Access Token（scope 限定单一资源）。
    pub access_token: String,
    /// 有效期（秒）。
    pub expires_in: i64,
    /// 游客主体（`guest:{grantId}`）。
    pub guest_id: String,
}

/// `POST /guest/exchange`：票据换取游客 JWT。
///
/// 票据一次性校验使用次数与有效期；换取的 JWT 仅包含 `{resourceType}:{resourceId}`
/// 这一个 scope，无法访问其他接口。
pub async fn exchange(
    State(state): State<SharedState>,
    Json(req): Json<GuestExchangeRequest>,
) -> Result<Json<GuestExchangeResponse>, AppError> {
    let now = state.now();
    let ticket_hash = crypto::hash_token(&req.ticket);
    let Some(grant) = repo::find_guest_grant_by_hash(&state.db, &ticket_hash).await? else {
        return Err(AppError::unauthorized(
            "AUTH_GUEST_TICKET_INVALID",
            "邀请链接无效",
        ));
    };
    if grant.revoked_at.is_some() {
        return Err(AppError::unauthorized(
            "AUTH_GUEST_TICKET_INVALID",
            "邀请链接已失效",
        ));
    }
    if grant.expires_at < now.fixed_offset() {
        return Err(AppError::forbidden(
            "AUTH_GUEST_TICKET_EXPIRED",
            "邀请链接已过期",
        ));
    }
    // 原子消费一次使用次数（并发安全）
    if !repo::consume_guest_grant_use(&state.db, grant.id, now).await? {
        return Err(AppError::forbidden(
            "AUTH_GUEST_TICKET_EXHAUSTED",
            "邀请链接使用次数已用完",
        ));
    }

    let display_name = req
        .display_name
        .as_deref()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .unwrap_or("游客");
    let ttl = guest_ttl(grant.expires_at, now);
    let claims = build_guest_claims(
        grant.id,
        display_name,
        &grant.resource_type,
        &grant.resource_id,
        ttl,
        &state.config.issuer,
        now,
        new_id(),
    );
    let access_token = state.keys.encode(&claims).map_err(AppError::internal)?;

    Ok(Json(GuestExchangeResponse {
        access_token,
        expires_in: ttl,
        guest_id: claims.sub,
    }))
}
