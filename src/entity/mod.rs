//! SeaORM 实体定义（仅覆盖 auth schema）。

/// 用户实体。
pub mod activation_token;
/// 审计日志实体。
pub mod audit_log;
/// 游客票据实体。
pub mod guest_grant;
/// 刷新令牌实体。
pub mod refresh_token;
/// 用户实体。
pub mod user;

/// 常用实体类型别名。
pub mod prelude {
    pub use super::activation_token::Entity as ActivationTokens;
    pub use super::audit_log::Entity as AuditLogs;
    pub use super::guest_grant::Entity as GuestGrants;
    pub use super::refresh_token::Entity as RefreshTokens;
    pub use super::user::Entity as Users;
}
