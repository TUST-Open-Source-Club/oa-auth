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
pub mod mailer;
