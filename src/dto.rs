//! 对外数据结构（DTO）。
//!
//! 响应一律 camelCase，时间 RFC3339；绝不包含密码哈希等敏感字段。

use chrono::{DateTime, FixedOffset};
use serde::Serialize;

use crate::domain::roles_of;
use crate::entity::user;

/// 用户信息（对外可见字段）。
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserDto {
    /// 用户 ID。
    pub id: String,
    /// 登录名。
    pub username: String,
    /// 邮箱。
    pub email: String,
    /// 昵称。
    pub nickname: String,
    /// 头像存储 key。
    pub avatar: Option<String>,
    /// 个人简介。
    pub bio: Option<String>,
    /// 部门/小组。
    pub department: Option<String>,
    /// 状态。
    pub status: String,
    /// 角色列表。
    pub roles: Vec<String>,
    /// 账号类型：human / bot。
    pub account_type: String,
    /// Bot 权限矩阵。
    pub bot_permissions: serde_json::Value,
    /// 创建时间。
    pub created_at: DateTime<FixedOffset>,
}

impl From<&user::Model> for UserDto {
    /// 从实体转换为对外 DTO。
    fn from(model: &user::Model) -> Self {
        Self {
            id: model.id.to_string(),
            username: model.username.clone(),
            email: model.email.clone(),
            nickname: model.nickname.clone(),
            avatar: model.avatar.clone(),
            bio: model.bio.clone(),
            department: model.department.clone(),
            status: model.status.clone(),
            roles: roles_of(model),
            account_type: model.account_type.clone(),
            bot_permissions: model.bot_permissions.clone(),
            created_at: model.created_at,
        }
    }
}
