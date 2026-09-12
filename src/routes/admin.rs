//! 管理员接口：创建账号（唯一建号入口）、用户列表、状态管理、重置密码。

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::Json;
use chrono::Duration;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use club_auth_sdk::AuthUser;
use club_common::{validate, AppError, FieldError, Page, PageParams};

use super::client_info;
use crate::crypto;
use crate::dto::UserDto;
use crate::entity::{activation_token, user};
use crate::repo;
use crate::state::SharedState;

/// 允许分配的角色白名单。
const ALLOWED_ROLES: &[&str] = &["member", "admin", "superadmin", "module_admin"];

/// 创建账号请求。
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateUserRequest {
    /// 邮箱（必填，受域名白名单限制）。
    pub email: String,
    /// 登录名（可选，默认从邮箱推导）。
    pub username: Option<String>,
    /// 昵称（可选，默认与登录名相同）。
    pub nickname: Option<String>,
    /// 部门/小组。
    pub department: Option<String>,
    /// 角色（可选，默认 member）。
    pub roles: Option<Vec<String>>,
}

/// 创建账号响应；开发模式附带激活令牌便于本地联调。
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateUserResponse {
    /// 新用户信息。
    pub user: UserDto,
    /// 激活令牌（仅 DEV_MODE 返回）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dev_activation_token: Option<String>,
    /// 激活链接（仅 DEV_MODE 返回）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dev_activation_url: Option<String>,
}

/// 用户列表查询参数。
///
/// 不使用 `#[serde(flatten)]`：serde_urlencoded 下 flatten 会把数字字段
/// 当作字符串反序列化导致 400，这里显式声明分页字段。
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListUsersQuery {
    /// 页码（从 1 开始）。
    pub page: Option<u32>,
    /// 每页条数。
    pub page_size: Option<u32>,
    /// 关键字。
    pub q: Option<String>,
}

impl ListUsersQuery {
    /// 转换为通用分页参数。
    fn page_params(&self) -> PageParams {
        PageParams {
            page: self.page,
            page_size: self.page_size,
        }
    }
}

/// 更新用户请求（None 表示不修改）。
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PatchUserRequest {
    /// 状态：active / disabled。
    pub status: Option<String>,
    /// 昵称。
    pub nickname: Option<String>,
    /// 部门/小组。
    pub department: Option<String>,
}

/// 从邮箱本地部分推导登录名；无法得到合法登录名时返回 None。
fn default_username_from_email(email: &str) -> Option<String> {
    let local = email.split('@').next()?;
    let sanitized: String = local
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '.'
            }
        })
        .collect();
    let candidate: String = sanitized
        .trim_matches('.')
        .chars()
        .take(validate::USERNAME_MAX_LEN)
        .collect();
    let candidate = candidate.trim_end_matches('.').to_string();
    validate::is_valid_username(&candidate).then_some(candidate)
}

/// `POST /admin/users`：创建账号并发送激活邮件。
pub async fn create_user(
    State(state): State<SharedState>,
    admin: AuthUser,
    headers: HeaderMap,
    Json(req): Json<CreateUserRequest>,
) -> Result<Json<CreateUserResponse>, AppError> {
    admin.require_admin()?;
    let (ip, user_agent) = client_info(&headers);

    let email = validate::normalize_email(&req.email);
    if !validate::is_valid_email(&email) {
        return Err(AppError::unprocessable(
            "AUTH_VALIDATION",
            "邮箱格式错误",
            vec![FieldError::new("email", "邮箱格式错误")],
        ));
    }
    // 域名白名单（空 = 不限制）
    if !validate::email_domain_allowed(&email, &state.config.account_email_domains) {
        return Err(AppError::unprocessable(
            "AUTH_EMAIL_DOMAIN_NOT_ALLOWED",
            "该邮箱域名不允许注册",
            vec![FieldError::new("email", "邮箱域名不在白名单内")],
        ));
    }

    let username = match req.username {
        Some(username) => username.trim().to_lowercase(),
        None => default_username_from_email(&email).ok_or_else(|| {
            AppError::unprocessable(
                "AUTH_VALIDATION",
                "无法从邮箱推导登录名",
                vec![FieldError::new("username", "请手动指定登录名")],
            )
        })?,
    };
    if !validate::is_valid_username(&username) {
        return Err(AppError::unprocessable(
            "AUTH_VALIDATION",
            "登录名不合法",
            vec![FieldError::new(
                "username",
                "登录名需为 3 ~ 32 位，字母数字开头，可含 . _ -",
            )],
        ));
    }

    let roles = req.roles.unwrap_or_else(|| vec!["member".to_string()]);
    if roles.is_empty() || roles.iter().any(|role| !ALLOWED_ROLES.contains(&role.as_str())) {
        return Err(AppError::unprocessable(
            "AUTH_VALIDATION",
            "角色不合法",
            vec![FieldError::new("roles", "包含未知角色")],
        ));
    }

    // 唯一性预检，给出清晰错误（数据库唯一索引兜底并发场景）
    if repo::find_user_by_email(&state.db, &email).await?.is_some() {
        return Err(AppError::conflict("AUTH_EMAIL_TAKEN", "邮箱已被使用"));
    }
    if repo::find_user_by_identifier(&state.db, &username)
        .await?
        .is_some()
    {
        return Err(AppError::conflict("AUTH_USERNAME_TAKEN", "登录名已被使用"));
    }

    let now = state.now();
    let nickname = req.nickname.unwrap_or_else(|| username.clone());
    let user = repo::insert_user(
        &state.db,
        repo::NewUser {
            email: email.clone(),
            username: username.clone(),
            nickname,
            department: req.department,
            roles,
        },
        now,
    )
    .await?;

    // 一次性激活令牌：明文仅出现在邮件与开发模式响应中
    let token_plain = crypto::generate_token();
    let expires_at = now + Duration::seconds(state.config.activation_ttl_seconds);
    repo::insert_activation_token(
        &state.db,
        user.id,
        crypto::hash_token(&token_plain),
        activation_token::PURPOSE_ACTIVATE,
        expires_at,
        now,
    )
    .await?;

    let activation_url = format!(
        "{}/activate?token={}",
        state.config.web_base_url, token_plain
    );
    state
        .mailer
        .send(
            &user.email,
            "激活你的社团 OA 账号",
            &format!(
                "你好 {}：\n\n管理员为你创建了社团 OA 账号，请在 {} 天内打开以下链接设置密码：\n{}\n",
                user.nickname,
                state.config.activation_ttl_seconds / 86400,
                activation_url
            ),
        )
        .await?;

    repo::write_audit(
        &state.db,
        Some(admin.claims().sub.parse().unwrap_or(Uuid::nil())),
        "user.create",
        Some("user"),
        Some(&user.id.to_string()),
        Some(serde_json::json!({ "email": email, "roles": user.roles })),
        ip,
        user_agent,
        now,
    )
    .await?;

    let (dev_token, dev_url) = if state.config.dev_mode {
        (Some(token_plain), Some(activation_url))
    } else {
        (None, None)
    };

    Ok(Json(CreateUserResponse {
        user: UserDto::from(&user),
        dev_activation_token: dev_token,
        dev_activation_url: dev_url,
    }))
}

/// `GET /admin/users`：分页查询用户。
pub async fn list_users(
    State(state): State<SharedState>,
    admin: AuthUser,
    Query(query): Query<ListUsersQuery>,
) -> Result<Json<Page<UserDto>>, AppError> {
    admin.require_admin()?;
    let page = query.page_params();
    let (users, total) = repo::list_users(&state.db, query.q.as_deref(), &page).await?;
    let items = users.iter().map(UserDto::from).collect();
    Ok(Json(Page::new(items, total, &page)))
}

/// `PATCH /admin/users/{id}`：更新状态或资料。
pub async fn patch_user(
    State(state): State<SharedState>,
    admin: AuthUser,
    Path(user_id): Path<Uuid>,
    headers: HeaderMap,
    Json(req): Json<PatchUserRequest>,
) -> Result<Json<UserDto>, AppError> {
    admin.require_admin()?;
    let (ip, user_agent) = client_info(&headers);
    let user = repo::find_user_by_id(&state.db, user_id)
        .await?
        .ok_or_else(|| AppError::not_found("AUTH_USER_NOT_FOUND", "用户不存在"))?;

    let now = state.now();
    let mut updated = user.clone();
    if let Some(status) = req.status.as_deref() {
        if !matches!(status, user::STATUS_ACTIVE | user::STATUS_DISABLED) {
            return Err(AppError::unprocessable(
                "AUTH_VALIDATION",
                "状态不合法",
                vec![FieldError::new("status", "仅支持 active / disabled")],
            ));
        }
        updated = repo::set_user_status(&state.db, &updated, status, now).await?;
        let action = if status == user::STATUS_DISABLED {
            "user.disable"
        } else {
            "user.enable"
        };
        repo::write_audit(
            &state.db,
            admin.claims().sub.parse().ok(),
            action,
            Some("user"),
            Some(&user_id.to_string()),
            None,
            ip.clone(),
            user_agent.clone(),
            now,
        )
        .await?;
    }
    if req.nickname.is_some() || req.department.is_some() {
        updated = repo::update_user_profile(
            &state.db,
            &updated,
            req.nickname,
            None,
            req.department,
            now,
        )
        .await?;
    }
    Ok(Json(UserDto::from(&updated)))
}

/// `POST /admin/users/{id}/reset-password`：发送密码重置邮件。
pub async fn reset_password(
    State(state): State<SharedState>,
    admin: AuthUser,
    Path(user_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, AppError> {
    admin.require_admin()?;
    let user = repo::find_user_by_id(&state.db, user_id)
        .await?
        .ok_or_else(|| AppError::not_found("AUTH_USER_NOT_FOUND", "用户不存在"))?;
    let now = state.now();
    let token_plain = crypto::generate_token();
    let expires_at = now + Duration::seconds(state.config.activation_ttl_seconds);
    repo::insert_activation_token(
        &state.db,
        user.id,
        crypto::hash_token(&token_plain),
        activation_token::PURPOSE_RESET,
        expires_at,
        now,
    )
    .await?;
    let link = format!("{}/reset?token={}", state.config.web_base_url, token_plain);
    state
        .mailer
        .send(
            &user.email,
            "重置你的社团 OA 密码",
            &format!("请打开以下链接重置密码：\n{link}\n"),
        )
        .await?;
    repo::write_audit(
        &state.db,
        admin.claims().sub.parse().ok(),
        "user.reset_password",
        Some("user"),
        Some(&user_id.to_string()),
        None,
        None,
        None,
        now,
    )
    .await?;

    Ok(Json(serde_json::json!({
        "devResetToken": state.config.dev_mode.then_some(token_plain),
        "devResetUrl": state.config.dev_mode.then_some(link),
    })))
}
