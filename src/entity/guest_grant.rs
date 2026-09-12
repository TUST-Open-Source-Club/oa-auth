//! 游客票据实体。
//!
//! 由资源服务（meeting/drive/doc）通过内部接口创建，游客凭票据换取 scope 化的游客 JWT。

use sea_orm::entity::prelude::*;

/// 游客票据模型。
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "guest_grants")]
pub struct Model {
    /// 票据 ID。
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// 资源类型：meeting / drive / doc。
    pub resource_type: String,
    /// 资源 ID。
    pub resource_id: String,
    /// 票据 SHA-256 哈希（唯一）。
    pub ticket_hash: String,
    /// 最大使用次数（0 表示不限）。
    pub max_uses: i32,
    /// 已使用次数。
    pub used_count: i32,
    /// 过期时间。
    pub expires_at: DateTimeWithTimeZone,
    /// 创建人（资源服务以用户身份创建；系统创建可为空）。
    #[sea_orm(nullable)]
    pub created_by: Option<Uuid>,
    /// 创建时间。
    pub created_at: DateTimeWithTimeZone,
    /// 吊销时间。
    #[sea_orm(nullable)]
    pub revoked_at: Option<DateTimeWithTimeZone>,
}

/// 关系定义。
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
