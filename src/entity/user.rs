//! 用户表实体。

use sea_orm::entity::prelude::*;

/// 用户状态：等待激活。
pub const STATUS_PENDING: &str = "pending_activation";
/// 用户状态：正常。
pub const STATUS_ACTIVE: &str = "active";
/// 用户状态：已禁用。
pub const STATUS_DISABLED: &str = "disabled";

/// 用户模型。
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "users")]
pub struct Model {
    /// 用户 ID（UUIDv7）。
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// 登录名（小写唯一）。
    pub username: String,
    /// 邮箱（小写唯一）。
    pub email: String,
    /// Argon2 密码哈希（未激活时为空）。
    #[sea_orm(nullable)]
    pub password_hash: Option<String>,
    /// 昵称。
    pub nickname: String,
    /// 头像存储 key。
    #[sea_orm(nullable)]
    pub avatar: Option<String>,
    /// 个人简介。
    #[sea_orm(nullable, column_type = "Text")]
    pub bio: Option<String>,
    /// 部门/小组。
    #[sea_orm(nullable)]
    pub department: Option<String>,
    /// 状态：pending_activation / active / disabled。
    pub status: String,
    /// 角色列表（如 `["member"]`）。
    #[sea_orm(column_type = "JsonBinary")]
    pub roles: Json,
    /// 创建时间。
    pub created_at: DateTimeWithTimeZone,
    /// 更新时间。
    pub updated_at: DateTimeWithTimeZone,
}

/// 关系定义（用户无直接外键关系）。
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
