//! 社团 OA 统一身份认证服务（auth）。
//!
//! 职责：账号管理（仅管理员创建）、邮箱激活、登录/刷新/登出、JWKS 与 OIDC Discovery、
//! 游客票据交换、管理接口与内部服务接口。
//!
//! 设计要点：
//! - Access Token 为 RS256 JWT，各服务通过 `club-auth-sdk` 本地验签；
//! - Refresh Token 为随机串，仅存储哈希，支持旋转与重放检测；
//! - 所有时间通过 [`clock::Clock`] 注入，便于测试；
//! - 邮件通过 [`mailer::Mailer`] 抽象，开发环境记录到日志。

#![warn(missing_docs)]

pub mod clock;
pub mod config;
pub mod crypto;
/// 数据库连接辅助。
pub mod db;
/// 领域逻辑（纯函数）。
pub mod domain;
/// 对外 DTO。
pub mod dto;
/// SeaORM 实体。
pub mod entity;
/// JWT 密钥管理。
pub mod keys;
pub mod mailer;
/// 数据库迁移。
pub mod migration;
/// 数据访问层。
pub mod repo;
/// HTTP 路由。
pub mod routes;
/// 应用状态。
pub mod state;

use axum::Router;
use tower_http::trace::TraceLayer;

use crate::state::SharedState;

/// 构建完整的 HTTP 路由（/healthz、/readyz、OIDC 端点与 /api/v1/auth/*）。
pub fn build_router(state: SharedState) -> Router {
    Router::new()
        .route("/healthz", axum::routing::get(routes::health::healthz))
        .route("/readyz", axum::routing::get(routes::health::readyz))
        .route(
            "/.well-known/openid-configuration",
            axum::routing::get(routes::oidc::discovery),
        )
        .route(
            "/.well-known/jwks.json",
            axum::routing::get(routes::oidc::jwks),
        )
        .nest("/api/v1/auth", routes::router())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
