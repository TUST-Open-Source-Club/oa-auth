//! HTTP 路由装配与公共辅助。

use axum::http::HeaderMap;
use axum::routing::{get, patch, post, put};
use axum::Router;

use crate::state::SharedState;

pub mod admin;
pub mod auth;
pub mod guest;
pub mod health;
pub mod internal;
pub mod oidc;

/// 从请求头提取客户端信息：(IP, User-Agent)。
///
/// IP 优先取反向代理写入的 `X-Forwarded-For` 第一跳。
pub fn client_info(headers: &HeaderMap) -> (Option<String>, Option<String>) {
    let ip = headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(|value| value.trim().to_string())
        .or_else(|| {
            headers
                .get("x-real-ip")
                .and_then(|value| value.to_str().ok())
                .map(str::to_string)
        });
    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    (ip, user_agent)
}

/// `/api/v1/auth` 下的路由。
pub fn router() -> Router<SharedState> {
    Router::new()
        // 公开接口
        .route("/login", post(auth::login))
        .route("/refresh", post(auth::refresh))
        .route("/logout", post(auth::logout))
        .route("/users/activate", post(auth::activate))
        .route("/password/forgot", post(auth::forgot_password))
        .route("/password/reset", post(auth::reset_password))
        .route("/guest/exchange", post(guest::exchange))
        // 登录用户接口
        .route("/me", get(auth::me).patch(auth::update_me))
        .route("/me/password", put(auth::change_password))
        .route("/users", get(auth::list_users_by_ids))
        .route("/users/search", get(auth::search_users))
        // 管理员接口
        .route(
            "/admin/users",
            post(admin::create_user).get(admin::list_users),
        )
        .route("/admin/users/{id}", patch(admin::patch_user))
        .route(
            "/admin/users/{id}/reset-password",
            post(admin::reset_password),
        )
        // 内部服务接口（服务令牌保护）
        .route("/internal/guest-grants", post(internal::create_guest_grant))
        .route("/internal/users/{id}", get(internal::get_user))
        .route("/internal/users/batch", post(internal::batch_users))
}
