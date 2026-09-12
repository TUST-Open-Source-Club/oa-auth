//! 刷新令牌实体。
//!
//! 只存储令牌的 SHA-256 哈希；通过 `family_id` + `rotated_to` 实现旋转与重放检测：
//! 同一个 family 的令牌链被复用即视为泄漏，整链吊销。

use sea_orm::entity::prelude::*;

/// 刷新令牌模型。
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "refresh_tokens")]
pub struct Model {
    /// 令牌记录 ID。
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// 所属用户。
    pub user_id: Uuid,
    /// 令牌链（family）ID：同一登录会话多次旋转共享。
    pub family_id: Uuid,
    /// 令牌 SHA-256 哈希（唯一）。
    pub token_hash: String,
    /// 设备标识（客户端生成，便于设备管理）。
    #[sea_orm(nullable)]
    pub device_id: Option<String>,
    /// 客户端 User-Agent（审计用）。
    #[sea_orm(nullable, column_type = "Text")]
    pub user_agent: Option<String>,
    /// 客户端 IP（审计用）。
    #[sea_orm(nullable)]
    pub ip: Option<String>,
    /// 过期时间。
    pub expires_at: DateTimeWithTimeZone,
    /// 创建时间。
    pub created_at: DateTimeWithTimeZone,
    /// 吊销时间（旋转后旧令牌会立即吊销）。
    #[sea_orm(nullable)]
    pub revoked_at: Option<DateTimeWithTimeZone>,
    /// 旋转后的新令牌 ID（用于重放检测）。
    #[sea_orm(nullable)]
    pub rotated_to: Option<Uuid>,
}

/// 关系定义。
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
