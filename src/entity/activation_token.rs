//! 激活/重置令牌实体。
//!
//! 数据库只存 SHA-256 哈希，令牌明文仅出现在邮件中。

use sea_orm::entity::prelude::*;

/// 用途：账号激活。
pub const PURPOSE_ACTIVATE: &str = "activate";
/// 用途：密码重置。
pub const PURPOSE_RESET: &str = "reset";

/// 激活令牌模型。
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "activation_tokens")]
pub struct Model {
    /// 记录 ID。
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// 所属用户。
    pub user_id: Uuid,
    /// 令牌 SHA-256 哈希（唯一）。
    pub token_hash: String,
    /// 用途：activate / reset。
    pub purpose: String,
    /// 过期时间。
    pub expires_at: DateTimeWithTimeZone,
    /// 创建时间。
    pub created_at: DateTimeWithTimeZone,
    /// 使用时间（一次性）。
    #[sea_orm(nullable)]
    pub used_at: Option<DateTimeWithTimeZone>,
}

/// 关系定义。
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
