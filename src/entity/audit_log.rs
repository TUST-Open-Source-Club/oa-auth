//! 审计日志实体。

use sea_orm::entity::prelude::*;

/// 审计日志模型。
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "audit_logs")]
pub struct Model {
    /// 日志 ID。
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// 操作者用户 ID（系统操作可为空）。
    #[sea_orm(nullable)]
    pub actor_id: Option<Uuid>,
    /// 动作（如 user.create / user.login）。
    pub action: String,
    /// 目标类型（user / token / ...）。
    #[sea_orm(nullable)]
    pub target_type: Option<String>,
    /// 目标 ID。
    #[sea_orm(nullable)]
    pub target_id: Option<String>,
    /// 详情（JSON）。
    #[sea_orm(nullable, column_type = "JsonBinary")]
    pub detail: Option<Json>,
    /// 客户端 IP。
    #[sea_orm(nullable)]
    pub ip: Option<String>,
    /// 客户端 User-Agent。
    #[sea_orm(nullable, column_type = "Text")]
    pub user_agent: Option<String>,
    /// 发生时间。
    pub created_at: DateTimeWithTimeZone,
}

/// 关系定义。
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
