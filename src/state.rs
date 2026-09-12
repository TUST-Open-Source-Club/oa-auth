//! 应用状态（AppState）与令牌校验实现。

use std::sync::Arc;

use chrono::{DateTime, Utc};
use sea_orm::DatabaseConnection;

use club_auth_sdk::{decode_access_token, AuthUser, Claims, TokenVerifier};
use club_common::AppError;

use crate::clock::Clock;
use crate::config::Config;
use crate::keys::SigningKeys;
use crate::mailer::Mailer;

/// 共享应用状态。
pub struct AppState {
    /// 数据库连接（search_path 固定为 auth）。
    pub db: DatabaseConnection,
    /// 运行配置。
    pub config: Config,
    /// JWT 签名密钥。
    pub keys: SigningKeys,
    /// 邮件发送端口。
    pub mailer: Arc<dyn Mailer>,
    /// 可注入时钟。
    pub clock: Arc<dyn Clock>,
}

impl AppState {
    /// 当前时间（UTC）。
    pub fn now(&self) -> DateTime<Utc> {
        self.clock.now()
    }
}

impl TokenVerifier for AppState {
    /// 使用本地公钥验签（算法/issuer/过期），失败统一返回 401。
    fn verify_token(&self, token: &str) -> Result<Claims, AppError> {
        decode_access_token(token, &self.keys.decoding_key, &self.config.issuer)
            .map_err(|_| AppError::unauthorized("AUTH_INVALID_TOKEN", "访问令牌无效或已过期"))
    }
}

/// 共享状态句柄：Clone 廉价，并作为 axum 提取器的状态类型。
///
/// 之所以不直接使用 `Arc<AppState>`：`AuthUser` 提取器要求状态类型实现
/// `TokenVerifier`，而孤儿规则不允许为 `Arc<AppState>` 实现外部 trait。
#[derive(Clone)]
pub struct SharedState(Arc<AppState>);

impl SharedState {
    /// 包装应用状态。
    pub fn new(state: AppState) -> Self {
        Self(Arc::new(state))
    }

    /// 获取内部引用。
    pub fn inner(&self) -> &AppState {
        &self.0
    }
}

impl std::ops::Deref for SharedState {
    type Target = AppState;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TokenVerifier for SharedState {
    /// 委托给 [`AppState`] 的本地验签实现。
    fn verify_token(&self, token: &str) -> Result<Claims, AppError> {
        self.0.verify_token(token)
    }
}

/// 从请求中解析登录用户（内部使用 `AuthUser` 提取器）。
pub type CurrentUser = AuthUser;
