//! 内部服务接口：仅内网可达，通过服务令牌（HMAC）鉴权。

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::Json;
use chrono::{DateTime, Duration, FixedOffset};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use club_auth_sdk::verify_service_token;
use club_common::AppError;

use crate::crypto;
use crate::dto::UserDto;
use crate::entity::user;
use crate::repo;
use crate::state::{AppState, SharedState};

/// 服务令牌允许的时间偏差（秒，防重放）。
const SERVICE_TOKEN_LEEWAY: i64 = 60;

/// 允许的资源类型（游客票据）。
const RESOURCE_TYPES: &[&str] = &["meeting", "drive", "doc"];

/// 校验服务令牌，返回调用方服务名。
fn verify_service(state: &AppState, headers: &HeaderMap, body: &[u8]) -> Result<String, AppError> {
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string)
    };
    let service = header("x-service-name")
        .ok_or_else(|| AppError::unauthorized("AUTH_SERVICE_TOKEN_MISSING", "缺少服务令牌"))?;
    let timestamp: i64 = header("x-service-timestamp")
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| AppError::unauthorized("AUTH_SERVICE_TOKEN_MISSING", "缺少服务令牌"))?;
    let signature = header("x-service-signature")
        .ok_or_else(|| AppError::unauthorized("AUTH_SERVICE_TOKEN_MISSING", "缺少服务令牌"))?;
    verify_service_token(
        &service,
        state.config.internal_secret.as_bytes(),
        timestamp,
        body,
        &signature,
        state.now().timestamp(),
        SERVICE_TOKEN_LEEWAY,
    )
    .map_err(|_| AppError::unauthorized("AUTH_SERVICE_TOKEN_INVALID", "服务令牌无效"))?;
    Ok(service)
}

/// 创建游客票据请求。
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateGuestGrantRequest {
    /// 资源类型：meeting / drive / doc。
    pub resource_type: String,
    /// 资源 ID。
    pub resource_id: String,
    /// 最大使用次数（0 = 不限，默认 0）。
    pub max_uses: Option<i32>,
    /// 有效期（秒，默认 4 小时）。
    pub expires_in_seconds: Option<i64>,
    /// 创建人（用户 ID，可选）。
    pub created_by: Option<Uuid>,
}

/// 创建游客票据响应（票据明文仅返回一次）。
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateGuestGrantResponse {
    /// 票据明文（资源服务拼入邀请链接）。
    pub ticket: String,
    /// 过期时间。
    pub expires_at: DateTime<FixedOffset>,
}

/// `POST /internal/guest-grants`：资源服务创建游客票据。
pub async fn create_guest_grant(
    State(state): State<SharedState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<CreateGuestGrantResponse>, AppError> {
    verify_service(&state, &headers, &body)?;
    let req: CreateGuestGrantRequest = serde_json::from_slice(&body).map_err(|err| {
        AppError::bad_request("AUTH_INVALID_JSON", format!("请求体不是合法 JSON: {err}"))
    })?;
    if !RESOURCE_TYPES.contains(&req.resource_type.as_str()) {
        return Err(AppError::unprocessable(
            "AUTH_VALIDATION",
            "资源类型不合法",
            vec![club_common::FieldError::new(
                "resourceType",
                "仅支持 meeting / drive / doc",
            )],
        ));
    }
    if req.resource_id.trim().is_empty() {
        return Err(AppError::unprocessable(
            "AUTH_VALIDATION",
            "资源 ID 不能为空",
            vec![club_common::FieldError::new("resourceId", "不能为空")],
        ));
    }

    let ttl = req
        .expires_in_seconds
        .unwrap_or(4 * 3600)
        .clamp(60, 7 * 24 * 3600);
    let now = state.now();
    let expires_at = now + Duration::seconds(ttl);
    let ticket = crypto::generate_token();
    repo::insert_guest_grant(
        &state.db,
        req.resource_type.trim(),
        req.resource_id.trim(),
        crypto::hash_token(&ticket),
        req.max_uses.unwrap_or(0).max(0),
        expires_at,
        req.created_by,
        now,
    )
    .await?;

    Ok(Json(CreateGuestGrantResponse {
        ticket,
        expires_at: expires_at.fixed_offset(),
    }))
}

/// `GET /internal/users/{id}`：按 ID 查询用户信息。
pub async fn get_user(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Path(user_id): Path<Uuid>,
) -> Result<Json<UserDto>, AppError> {
    verify_service(&state, &headers, b"")?;
    let user = repo::find_user_by_id(&state.db, user_id)
        .await?
        .ok_or_else(|| AppError::not_found("AUTH_USER_NOT_FOUND", "用户不存在"))?;
    Ok(Json(UserDto::from(&user)))
}

/// 批量查询用户请求。
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BatchUsersRequest {
    /// 用户 ID 列表（单次最多 100 个）。
    pub ids: Vec<Uuid>,
}

/// `POST /internal/users/batch`：批量查询用户信息。
pub async fn batch_users(
    State(state): State<SharedState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Vec<UserDto>>, AppError> {
    verify_service(&state, &headers, &body)?;
    let req: BatchUsersRequest = serde_json::from_slice(&body).map_err(|err| {
        AppError::bad_request("AUTH_INVALID_JSON", format!("请求体不是合法 JSON: {err}"))
    })?;
    if req.ids.len() > 100 {
        return Err(AppError::unprocessable(
            "AUTH_VALIDATION",
            "单次最多查询 100 个用户",
            vec![club_common::FieldError::new("ids", "数量超限")],
        ));
    }
    let users = user::Entity::find()
        .filter(user::Column::Id.is_in(req.ids))
        .all(&state.db)
        .await
        .map_err(repo::map_db_err)?;
    Ok(Json(users.iter().map(UserDto::from).collect()))
}
