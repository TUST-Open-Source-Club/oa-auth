//! 认证核心接口：登录、刷新、登出、激活、找回密码、个人信息。

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use chrono::Duration;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use club_auth_sdk::AuthUser;
use club_common::{new_id, validate, AppError, FieldError};

use super::client_info;
use crate::crypto;
use crate::domain::{build_claims, decide_refresh, roles_of, scopes_for, RefreshDecision};
use crate::dto::UserDto;
use crate::entity::{activation_token, user};
use crate::repo;
use crate::state::SharedState;

/// 登录请求。
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginRequest {
    /// 用户名或邮箱。
    pub identifier: String,
    /// 密码。
    pub password: String,
    /// 客户端设备标识（用于设备管理与刷新令牌绑定）。
    pub device_id: Option<String>,
}

/// 令牌对（登录/刷新的返回值）。
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenPair {
    /// Access Token（JWT，短期）。
    pub access_token: String,
    /// Refresh Token（随机串，长期）。
    pub refresh_token: String,
    /// Access Token 有效期（秒）。
    pub expires_in: i64,
}

/// 登录响应。
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginResponse {
    /// 令牌对。
    #[serde(flatten)]
    pub tokens: TokenPair,
    /// 用户信息。
    pub user: UserDto,
}

/// 刷新请求。
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshRequest {
    /// 刷新令牌。
    pub refresh_token: String,
    /// 可选的设备标识（覆盖旧记录）。
    pub device_id: Option<String>,
}

/// 登出请求。
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogoutRequest {
    /// 刷新令牌。
    pub refresh_token: String,
    /// 是否登出该设备的所有会话（默认仅当前令牌）。
    pub all: Option<bool>,
}

/// 激活请求。
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivateRequest {
    /// 激活令牌（邮件中的一次性 token）。
    pub token: String,
    /// 新密码。
    pub password: String,
}

/// 找回密码请求。
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForgotPasswordRequest {
    /// 注册邮箱。
    pub email: String,
}

/// 重置密码请求。
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResetPasswordRequest {
    /// 重置令牌。
    pub token: String,
    /// 新密码。
    pub password: String,
}

/// 更新个人资料请求（None 表示不修改）。
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateProfileRequest {
    /// 昵称。
    pub nickname: Option<String>,
    /// 个人简介。
    pub bio: Option<String>,
    /// 部门/小组。
    pub department: Option<String>,
}

/// 修改密码请求。
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangePasswordRequest {
    /// 当前密码。
    pub old_password: String,
    /// 新密码。
    pub new_password: String,
}

/// 用户搜索参数。
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchQuery {
    /// 关键字（邮箱/登录名/昵称）。
    pub q: String,
}

/// 校验用户状态是否允许登录。
fn ensure_active(user: &user::Model) -> Result<(), AppError> {
    match user.status.as_str() {
        user::STATUS_ACTIVE => Ok(()),
        user::STATUS_PENDING => Err(AppError::forbidden(
            "AUTH_PENDING_ACTIVATION",
            "账号待激活，请先通过邮件中的链接设置密码",
        )),
        _ => Err(AppError::forbidden("AUTH_ACCOUNT_DISABLED", "账号已被禁用")),
    }
}

/// 统一的不安全凭据错误（不区分账号不存在/密码错误，避免枚举用户）。
fn invalid_credentials() -> AppError {
    AppError::unauthorized("AUTH_INVALID_CREDENTIALS", "账号或密码错误")
}

/// 密码策略校验，失败返回 422 字段错误。
fn validate_new_password(password: &str) -> Result<(), AppError> {
    if let Err(key) = validate::validate_password(password) {
        return Err(AppError::unprocessable(
            "AUTH_VALIDATION",
            "密码不符合要求",
            vec![FieldError::new("password", key)],
        ));
    }
    Ok(())
}

/// 签发令牌对并写入刷新令牌记录。
async fn issue_tokens(
    state: &crate::state::AppState,
    user: &user::Model,
    device_id: Option<String>,
    user_agent: Option<String>,
    ip: Option<String>,
    family_id: Option<Uuid>,
) -> Result<(TokenPair, Uuid), AppError> {
    let now = state.now();
    let roles = roles_of(user);
    let claims = build_claims(
        user,
        scopes_for(&roles),
        state.config.access_token_ttl_seconds,
        &state.config.issuer,
        now,
        new_id(),
    );
    let access_token = state.keys.encode(&claims).map_err(AppError::internal)?;

    // Refresh Token 明文只返回给客户端，数据库仅存哈希。
    let refresh_plain = crypto::generate_token();
    let family = family_id.unwrap_or_else(new_id);
    let expires_at = now + Duration::seconds(state.config.refresh_token_ttl_seconds);
    let model = repo::insert_refresh_token(
        &state.db,
        user.id,
        family,
        crypto::hash_token(&refresh_plain),
        device_id,
        user_agent,
        ip,
        expires_at,
        now,
    )
    .await?;

    Ok((
        TokenPair {
            access_token,
            refresh_token: refresh_plain,
            expires_in: state.config.access_token_ttl_seconds,
        },
        model.id,
    ))
}

/// `POST /login`：密码登录，返回令牌对与用户信息。
pub async fn login(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, AppError> {
    let (ip, user_agent) = client_info(&headers);
    let user = repo::find_user_by_identifier(&state.db, &req.identifier)
        .await?
        .ok_or_else(invalid_credentials)?;
    // 待激活账号（尚无密码）直接提示激活，避免用户困惑；
    // 账号由管理员创建，此处不构成开放注册场景下的用户枚举风险。
    if user.status == user::STATUS_PENDING && user.password_hash.is_none() {
        return Err(AppError::forbidden(
            "AUTH_PENDING_ACTIVATION",
            "账号待激活，请先通过邮件中的链接设置密码",
        ));
    }
    let Some(hash) = user.password_hash.as_deref() else {
        return Err(invalid_credentials());
    };
    if !crypto::verify_password(&req.password, hash) {
        repo::write_audit(
            &state.db,
            Some(user.id),
            "user.login_failed",
            Some("user"),
            Some(&user.id.to_string()),
            None,
            ip,
            user_agent,
            state.now(),
        )
        .await?;
        return Err(invalid_credentials());
    }
    ensure_active(&user)?;

    let (tokens, _) = issue_tokens(
        &state,
        &user,
        req.device_id,
        user_agent.clone(),
        ip.clone(),
        None,
    )
    .await?;
    repo::write_audit(
        &state.db,
        Some(user.id),
        "user.login",
        Some("user"),
        Some(&user.id.to_string()),
        None,
        ip,
        user_agent,
        state.now(),
    )
    .await?;

    Ok(Json(LoginResponse {
        tokens,
        user: UserDto::from(&user),
    }))
}

/// `POST /refresh`：旋转刷新令牌；检测到重放则吊销整个令牌链。
pub async fn refresh(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(req): Json<RefreshRequest>,
) -> Result<Json<TokenPair>, AppError> {
    let (ip, user_agent) = client_info(&headers);
    let token_hash = crypto::hash_token(&req.refresh_token);
    let Some(existing) = repo::find_refresh_by_hash(&state.db, &token_hash).await? else {
        return Err(AppError::unauthorized(
            "AUTH_INVALID_REFRESH",
            "刷新令牌无效",
        ));
    };

    let now = state.now();
    match decide_refresh(&existing, now) {
        RefreshDecision::ReuseDetected => {
            repo::revoke_refresh_family(&state.db, existing.family_id, now).await?;
            repo::write_audit(
                &state.db,
                Some(existing.user_id),
                "user.refresh_reuse_detected",
                Some("refresh_token"),
                Some(&existing.id.to_string()),
                None,
                ip,
                user_agent,
                now,
            )
            .await?;
            Err(AppError::unauthorized(
                "AUTH_REFRESH_REUSED",
                "检测到令牌重放，已注销该会话，请重新登录",
            ))
        }
        RefreshDecision::Revoked => Err(AppError::unauthorized(
            "AUTH_INVALID_REFRESH",
            "刷新令牌已失效",
        )),
        RefreshDecision::Expired => Err(AppError::unauthorized(
            "AUTH_REFRESH_EXPIRED",
            "登录已过期，请重新登录",
        )),
        RefreshDecision::Rotate => {
            let Some(user) = repo::find_user_by_id(&state.db, existing.user_id).await? else {
                return Err(AppError::unauthorized(
                    "AUTH_INVALID_REFRESH",
                    "刷新令牌无效",
                ));
            };
            ensure_active(&user)?;
            let (tokens, new_id) = issue_tokens(
                &state,
                &user,
                req.device_id.or(existing.device_id.clone()),
                user_agent,
                ip,
                Some(existing.family_id),
            )
            .await?;
            repo::mark_refresh_rotated(&state.db, &existing, new_id, now).await?;
            Ok(Json(tokens))
        }
    }
}

/// `POST /logout`：吊销当前刷新令牌或其整个令牌链。
pub async fn logout(
    State(state): State<SharedState>,
    Json(req): Json<LogoutRequest>,
) -> Result<StatusCode, AppError> {
    let token_hash = crypto::hash_token(&req.refresh_token);
    if let Some(existing) = repo::find_refresh_by_hash(&state.db, &token_hash).await? {
        let now = state.now();
        if req.all.unwrap_or(false) {
            repo::revoke_refresh_family(&state.db, existing.family_id, now).await?;
        } else {
            repo::revoke_refresh_token(&state.db, &existing, now).await?;
        }
    }
    // 无论令牌是否存在都返回成功，避免探测有效令牌。
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /users/activate`：凭激活令牌设置密码并激活账号。
pub async fn activate(
    State(state): State<SharedState>,
    Json(req): Json<ActivateRequest>,
) -> Result<StatusCode, AppError> {
    validate_new_password(&req.password)?;
    let now = state.now();
    let token_hash = crypto::hash_token(&req.token);
    let Some(token) = repo::consume_activation_token(
        &state.db,
        &token_hash,
        activation_token::PURPOSE_ACTIVATE,
        now,
    )
    .await?
    else {
        return Err(AppError::bad_request(
            "AUTH_TOKEN_INVALID",
            "激活链接无效或已过期，请联系管理员重新发送",
        ));
    };
    let Some(user) = repo::find_user_by_id(&state.db, token.user_id).await? else {
        return Err(AppError::bad_request("AUTH_TOKEN_INVALID", "激活链接无效"));
    };
    let password_hash = crypto::hash_password(&req.password)?;
    repo::set_user_password(&state.db, &user, password_hash, now).await?;
    repo::write_audit(
        &state.db,
        Some(user.id),
        "user.activated",
        Some("user"),
        Some(&user.id.to_string()),
        None,
        None,
        None,
        now,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /password/forgot`：发送重置邮件；无论邮箱是否存在均返回 204。
pub async fn forgot_password(
    State(state): State<SharedState>,
    Json(req): Json<ForgotPasswordRequest>,
) -> Result<StatusCode, AppError> {
    let email = validate::normalize_email(&req.email);
    if let Some(user) = repo::find_user_by_email(&state.db, &email).await? {
        let now = state.now();
        let plain = crypto::generate_token();
        let expires_at = now + Duration::seconds(state.config.activation_ttl_seconds);
        repo::insert_activation_token(
            &state.db,
            user.id,
            crypto::hash_token(&plain),
            activation_token::PURPOSE_RESET,
            expires_at,
            now,
        )
        .await?;
        let link = format!(
            "{}/reset?token={}",
            state.config.web_base_url,
            urlencoding(&plain)
        );
        state
            .mailer
            .send(
                &user.email,
                "重置你的社团 OA 密码",
                &format!(
                    "你好 {}：\n\n请在 {} 小时内打开以下链接重置密码：\n{}\n",
                    user.nickname,
                    state.config.activation_ttl_seconds / 3600,
                    link
                ),
            )
            .await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /password/reset`：凭重置令牌设置新密码。
pub async fn reset_password(
    State(state): State<SharedState>,
    Json(req): Json<ResetPasswordRequest>,
) -> Result<StatusCode, AppError> {
    validate_new_password(&req.password)?;
    let now = state.now();
    let token_hash = crypto::hash_token(&req.token);
    let Some(token) = repo::consume_activation_token(
        &state.db,
        &token_hash,
        activation_token::PURPOSE_RESET,
        now,
    )
    .await?
    else {
        return Err(AppError::bad_request(
            "AUTH_TOKEN_INVALID",
            "重置链接无效或已过期",
        ));
    };
    let Some(user) = repo::find_user_by_id(&state.db, token.user_id).await? else {
        return Err(AppError::bad_request("AUTH_TOKEN_INVALID", "重置链接无效"));
    };
    let password_hash = crypto::hash_password(&req.password)?;
    repo::update_user_password(&state.db, &user, password_hash, now).await?;
    // 重置密码后吊销全部会话，强制重新登录。
    repo::revoke_all_user_tokens(&state.db, user.id, now).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /me`：当前用户信息。
pub async fn me(
    State(state): State<SharedState>,
    auth: AuthUser,
) -> Result<Json<UserDto>, AppError> {
    let user = load_current_user(&state, &auth).await?;
    Ok(Json(UserDto::from(&user)))
}

/// `PATCH /me`：更新个人资料。
pub async fn update_me(
    State(state): State<SharedState>,
    auth: AuthUser,
    Json(req): Json<UpdateProfileRequest>,
) -> Result<Json<UserDto>, AppError> {
    let user = load_current_user(&state, &auth).await?;
    if let Some(nickname) = req.nickname.as_deref() {
        if nickname.trim().is_empty() || nickname.chars().count() > 64 {
            return Err(AppError::unprocessable(
                "AUTH_VALIDATION",
                "昵称不合法",
                vec![FieldError::new("nickname", "昵称需为 1 ~ 64 字符")],
            ));
        }
    }
    let updated = repo::update_user_profile(
        &state.db,
        &user,
        req.nickname,
        req.bio,
        req.department,
        state.now(),
    )
    .await?;
    Ok(Json(UserDto::from(&updated)))
}

/// `PUT /me/password`：修改密码（校验旧密码）。
pub async fn change_password(
    State(state): State<SharedState>,
    auth: AuthUser,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<StatusCode, AppError> {
    validate_new_password(&req.new_password)?;
    let user = load_current_user(&state, &auth).await?;
    let Some(hash) = user.password_hash.as_deref() else {
        return Err(AppError::bad_request(
            "AUTH_NO_PASSWORD",
            "账号尚未设置密码",
        ));
    };
    if !crypto::verify_password(&req.old_password, hash) {
        return Err(invalid_credentials());
    }
    let password_hash = crypto::hash_password(&req.new_password)?;
    let now = state.now();
    repo::update_user_password(&state.db, &user, password_hash, now).await?;
    repo::revoke_all_user_tokens(&state.db, user.id, now).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /users/search`：按关键字搜索用户（供选人组件使用）。
pub async fn search_users(
    State(state): State<SharedState>,
    _auth: AuthUser,
    Query(query): Query<SearchQuery>,
) -> Result<Json<Vec<UserDto>>, AppError> {
    let keyword = query.q.trim();
    if keyword.is_empty() {
        return Ok(Json(Vec::new()));
    }
    let users = repo::search_users(&state.db, keyword, 20).await?;
    Ok(Json(users.iter().map(UserDto::from).collect()))
}

/// 加载当前登录用户；用户不存在或已禁用时返回 401。
async fn load_current_user(
    state: &crate::state::AppState,
    auth: &AuthUser,
) -> Result<user::Model, AppError> {
    let user_id = auth
        .claims()
        .sub
        .parse::<Uuid>()
        .map_err(|_| AppError::unauthorized("AUTH_INVALID_TOKEN", "访问令牌无效"))?;
    let user = repo::find_user_by_id(&state.db, user_id)
        .await?
        .ok_or_else(|| AppError::unauthorized("AUTH_INVALID_TOKEN", "用户不存在"))?;
    ensure_active(&user)?;
    Ok(user)
}

/// 对 URL 查询参数做最小转义（令牌为 base64url，通常无需转义）。
fn urlencoding(value: &str) -> String {
    value
        .chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            other => format!("%{:02X}", other as u32 as u8),
        })
        .collect()
}
