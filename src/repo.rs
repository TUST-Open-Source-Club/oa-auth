//! 数据访问层：只操作 auth schema。
//!
//! 所有函数把 `sea_orm::DbErr` 统一映射为 [`AppError`]；唯一约束冲突映射为 409。

use chrono::{DateTime, Utc};
use sea_orm::sea_query::{Expr, ExprTrait};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, DatabaseConnection, DbErr, EntityTrait,
    PaginatorTrait, QueryFilter, QueryOrder, QuerySelect, Set, TransactionTrait,
};
use serde_json::Value;
use uuid::Uuid;

use club_common::{new_id, AppError, PageParams};

use crate::domain::activation_is_valid;
use crate::entity::{activation_token, audit_log, guest_grant, refresh_token, user};

/// 将数据库错误映射为统一错误（唯一约束 → 409，其余 → 500）。
pub fn map_db_err(err: DbErr) -> AppError {
    let message = err.to_string();
    if message.contains("duplicate key") || message.contains("unique constraint") {
        AppError::conflict("AUTH_CONFLICT", "记录已存在")
    } else {
        AppError::internal(err)
    }
}

/// 创建用户所需的输入。
#[derive(Debug, Clone)]
pub struct NewUser {
    /// 邮箱（调用方已归一化）。
    pub email: String,
    /// 登录名（调用方已归一化）。
    pub username: String,
    /// 昵称。
    pub nickname: String,
    /// 部门/小组。
    pub department: Option<String>,
    /// 角色列表。
    pub roles: Vec<String>,
}

/// 创建用户（默认待激活、无密码）。
pub async fn insert_user(
    db: &DatabaseConnection,
    new: NewUser,
    now: DateTime<Utc>,
) -> Result<user::Model, AppError> {
    let model = user::ActiveModel {
        id: Set(new_id()),
        username: Set(new.username),
        email: Set(new.email),
        password_hash: Set(None),
        nickname: Set(new.nickname),
        avatar: Set(None),
        bio: Set(None),
        department: Set(new.department),
        status: Set(user::STATUS_PENDING.to_string()),
        roles: Set(Value::Array(
            new.roles.into_iter().map(Value::String).collect(),
        )),
        created_at: Set(now.fixed_offset()),
        updated_at: Set(now.fixed_offset()),
    };
    model.insert(db).await.map_err(map_db_err)
}

/// 按 ID 查询用户。
pub async fn find_user_by_id(
    db: &DatabaseConnection,
    id: Uuid,
) -> Result<Option<user::Model>, AppError> {
    user::Entity::find_by_id(id)
        .one(db)
        .await
        .map_err(map_db_err)
}

/// 按邮箱或登录名（不区分大小写）查询用户。
pub async fn find_user_by_identifier(
    db: &DatabaseConnection,
    identifier: &str,
) -> Result<Option<user::Model>, AppError> {
    let identifier = identifier.trim().to_lowercase();
    user::Entity::find()
        .filter(
            Condition::any()
                .add(user::Column::Email.eq(identifier.clone()))
                .add(user::Column::Username.eq(identifier)),
        )
        .one(db)
        .await
        .map_err(map_db_err)
}

/// 按邮箱查询用户。
pub async fn find_user_by_email(
    db: &DatabaseConnection,
    email: &str,
) -> Result<Option<user::Model>, AppError> {
    user::Entity::find()
        .filter(user::Column::Email.eq(email.trim().to_lowercase()))
        .one(db)
        .await
        .map_err(map_db_err)
}

/// 统计用户总数（用于首次启动引导管理员）。
pub async fn count_users(db: &DatabaseConnection) -> Result<u64, AppError> {
    user::Entity::find().count(db).await.map_err(map_db_err)
}

/// 分页查询用户列表，支持关键字模糊匹配（邮箱/登录名/昵称）。
pub async fn list_users(
    db: &DatabaseConnection,
    query: Option<&str>,
    params: &PageParams,
) -> Result<(Vec<user::Model>, i64), AppError> {
    let mut select = user::Entity::find();
    if let Some(query) = query.map(str::trim).filter(|q| !q.is_empty()) {
        let like = format!("%{query}%");
        select = select.filter(
            Condition::any()
                .add(user::Column::Email.like(like.clone()))
                .add(user::Column::Username.like(like.clone()))
                .add(user::Column::Nickname.like(like)),
        );
    }
    let paginator = select
        .order_by_desc(user::Column::CreatedAt)
        .paginate(db, u64::from(params.page_size()));
    let total = paginator.num_items().await.map_err(map_db_err)? as i64;
    let items = paginator
        .fetch_page(u64::from(params.page() - 1))
        .await
        .map_err(map_db_err)?;
    Ok((items, total))
}

/// 搜索用户（供 IM 选人等场景，限制返回条数）。
/// 按用户 ID 批量查询（单次最多 50，按昵称排序）。
pub async fn find_users_by_ids(
    db: &DatabaseConnection,
    ids: &[Uuid],
) -> Result<Vec<user::Model>, AppError> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    user::Entity::find()
        .filter(user::Column::Id.is_in(ids.iter().copied().take(50)))
        .order_by_asc(user::Column::Nickname)
        .all(db)
        .await
        .map_err(map_db_err)
}

pub async fn search_users(
    db: &DatabaseConnection,
    query: &str,
    limit: u64,
) -> Result<Vec<user::Model>, AppError> {
    let like = format!("%{}%", query.trim());
    user::Entity::find()
        .filter(
            Condition::any()
                .add(user::Column::Email.like(like.clone()))
                .add(user::Column::Username.like(like.clone()))
                .add(user::Column::Nickname.like(like)),
        )
        .order_by_asc(user::Column::Nickname)
        .limit(limit.clamp(1, 50))
        .all(db)
        .await
        .map_err(map_db_err)
}

/// 设置用户密码并激活账号。
pub async fn set_user_password(
    db: &DatabaseConnection,
    user: &user::Model,
    password_hash: String,
    now: DateTime<Utc>,
) -> Result<user::Model, AppError> {
    let mut active: user::ActiveModel = user.clone().into();
    active.password_hash = Set(Some(password_hash));
    active.status = Set(user::STATUS_ACTIVE.to_string());
    active.updated_at = Set(now.fixed_offset());
    active.update(db).await.map_err(map_db_err)
}

/// 更新用户状态（active / disabled）。
pub async fn set_user_status(
    db: &DatabaseConnection,
    user: &user::Model,
    status: &str,
    now: DateTime<Utc>,
) -> Result<user::Model, AppError> {
    let mut active: user::ActiveModel = user.clone().into();
    active.status = Set(status.to_string());
    active.updated_at = Set(now.fixed_offset());
    active.update(db).await.map_err(map_db_err)
}

/// 更新用户资料（昵称/简介/部门/头像，None 表示不修改）。
pub async fn update_user_profile(
    db: &DatabaseConnection,
    user: &user::Model,
    nickname: Option<String>,
    bio: Option<String>,
    department: Option<String>,
    now: DateTime<Utc>,
) -> Result<user::Model, AppError> {
    let mut active: user::ActiveModel = user.clone().into();
    if let Some(nickname) = nickname {
        active.nickname = Set(nickname);
    }
    if let Some(bio) = bio {
        active.bio = Set(Some(bio));
    }
    if let Some(department) = department {
        active.department = Set(Some(department));
    }
    active.updated_at = Set(now.fixed_offset());
    active.update(db).await.map_err(map_db_err)
}

/// 覆盖用户密码（管理员重置或用户自助修改）。
pub async fn update_user_password(
    db: &DatabaseConnection,
    user: &user::Model,
    password_hash: String,
    now: DateTime<Utc>,
) -> Result<user::Model, AppError> {
    let mut active: user::ActiveModel = user.clone().into();
    active.password_hash = Set(Some(password_hash));
    active.updated_at = Set(now.fixed_offset());
    active.update(db).await.map_err(map_db_err)
}

/// 创建激活/重置令牌（存储哈希）。
pub async fn insert_activation_token(
    db: &DatabaseConnection,
    user_id: Uuid,
    token_hash: String,
    purpose: &str,
    expires_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<activation_token::Model, AppError> {
    activation_token::ActiveModel {
        id: Set(new_id()),
        user_id: Set(user_id),
        token_hash: Set(token_hash),
        purpose: Set(purpose.to_string()),
        expires_at: Set(expires_at.fixed_offset()),
        created_at: Set(now.fixed_offset()),
        used_at: Set(None),
    }
    .insert(db)
    .await
    .map_err(map_db_err)
}

/// 校验并消费令牌（标记已使用），无效时返回 None。
pub async fn consume_activation_token(
    db: &DatabaseConnection,
    token_hash: &str,
    purpose: &str,
    now: DateTime<Utc>,
) -> Result<Option<activation_token::Model>, AppError> {
    let Some(token) = activation_token::Entity::find()
        .filter(activation_token::Column::TokenHash.eq(token_hash))
        .filter(activation_token::Column::Purpose.eq(purpose))
        .one(db)
        .await
        .map_err(map_db_err)?
    else {
        return Ok(None);
    };
    if !activation_is_valid(&token, now) {
        return Ok(None);
    }
    let mut active: activation_token::ActiveModel = token.into();
    active.used_at = Set(Some(now.fixed_offset()));
    active.update(db).await.map(Some).map_err(map_db_err)
}

/// 创建刷新令牌记录。
#[allow(clippy::too_many_arguments)]
pub async fn insert_refresh_token(
    db: &DatabaseConnection,
    user_id: Uuid,
    family_id: Uuid,
    token_hash: String,
    device_id: Option<String>,
    user_agent: Option<String>,
    ip: Option<String>,
    expires_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<refresh_token::Model, AppError> {
    refresh_token::ActiveModel {
        id: Set(new_id()),
        user_id: Set(user_id),
        family_id: Set(family_id),
        token_hash: Set(token_hash),
        device_id: Set(device_id),
        user_agent: Set(user_agent),
        ip: Set(ip),
        expires_at: Set(expires_at.fixed_offset()),
        created_at: Set(now.fixed_offset()),
        revoked_at: Set(None),
        rotated_to: Set(None),
    }
    .insert(db)
    .await
    .map_err(map_db_err)
}

/// 按哈希查询刷新令牌。
pub async fn find_refresh_by_hash(
    db: &DatabaseConnection,
    token_hash: &str,
) -> Result<Option<refresh_token::Model>, AppError> {
    refresh_token::Entity::find()
        .filter(refresh_token::Column::TokenHash.eq(token_hash))
        .one(db)
        .await
        .map_err(map_db_err)
}

/// 标记旧刷新令牌已旋转（写入 rotated_to 与吊销时间）。
pub async fn mark_refresh_rotated(
    db: &DatabaseConnection,
    old: &refresh_token::Model,
    new_id: Uuid,
    now: DateTime<Utc>,
) -> Result<(), AppError> {
    let mut active: refresh_token::ActiveModel = old.clone().into();
    active.rotated_to = Set(Some(new_id));
    active.revoked_at = Set(Some(now.fixed_offset()));
    active.update(db).await.map(|_| ()).map_err(map_db_err)
}

/// 吊销单个刷新令牌。
pub async fn revoke_refresh_token(
    db: &DatabaseConnection,
    token: &refresh_token::Model,
    now: DateTime<Utc>,
) -> Result<(), AppError> {
    let mut active: refresh_token::ActiveModel = token.clone().into();
    active.revoked_at = Set(Some(now.fixed_offset()));
    active.update(db).await.map(|_| ()).map_err(map_db_err)
}

/// 吊销整个令牌链（检测到重放或"登出全部设备"）。
pub async fn revoke_refresh_family(
    db: &DatabaseConnection,
    family_id: Uuid,
    now: DateTime<Utc>,
) -> Result<u64, AppError> {
    let result = refresh_token::Entity::update_many()
        .col_expr(
            refresh_token::Column::RevokedAt,
            Expr::value(now.fixed_offset()),
        )
        .filter(refresh_token::Column::FamilyId.eq(family_id))
        .filter(refresh_token::Column::RevokedAt.is_null())
        .exec(db)
        .await
        .map_err(map_db_err)?;
    Ok(result.rows_affected)
}

/// 吊销某用户的全部刷新令牌（改密/重置后强制重新登录）。
pub async fn revoke_all_user_tokens(
    db: &DatabaseConnection,
    user_id: Uuid,
    now: DateTime<Utc>,
) -> Result<u64, AppError> {
    let result = refresh_token::Entity::update_many()
        .col_expr(
            refresh_token::Column::RevokedAt,
            Expr::value(now.fixed_offset()),
        )
        .filter(refresh_token::Column::UserId.eq(user_id))
        .filter(refresh_token::Column::RevokedAt.is_null())
        .exec(db)
        .await
        .map_err(map_db_err)?;
    Ok(result.rows_affected)
}

/// 创建游客票据。
#[allow(clippy::too_many_arguments)]
pub async fn insert_guest_grant(
    db: &DatabaseConnection,
    resource_type: &str,
    resource_id: &str,
    ticket_hash: String,
    max_uses: i32,
    expires_at: DateTime<Utc>,
    created_by: Option<Uuid>,
    now: DateTime<Utc>,
) -> Result<guest_grant::Model, AppError> {
    guest_grant::ActiveModel {
        id: Set(new_id()),
        resource_type: Set(resource_type.to_string()),
        resource_id: Set(resource_id.to_string()),
        ticket_hash: Set(ticket_hash),
        max_uses: Set(max_uses),
        used_count: Set(0),
        expires_at: Set(expires_at.fixed_offset()),
        created_by: Set(created_by),
        created_at: Set(now.fixed_offset()),
        revoked_at: Set(None),
    }
    .insert(db)
    .await
    .map_err(map_db_err)
}

/// 按哈希查询游客票据。
pub async fn find_guest_grant_by_hash(
    db: &DatabaseConnection,
    ticket_hash: &str,
) -> Result<Option<guest_grant::Model>, AppError> {
    guest_grant::Entity::find()
        .filter(guest_grant::Column::TicketHash.eq(ticket_hash))
        .one(db)
        .await
        .map_err(map_db_err)
}

/// 原子消费一次游客票据使用次数。
///
/// 通过条件更新保证并发安全：`max_uses = 0` 表示不限次数；
/// 返回 `true` 表示本次消费成功。
pub async fn consume_guest_grant_use(
    db: &DatabaseConnection,
    grant_id: Uuid,
    now: DateTime<Utc>,
) -> Result<bool, AppError> {
    let txn = db.begin().await.map_err(map_db_err)?;
    let result = guest_grant::Entity::update_many()
        .col_expr(
            guest_grant::Column::UsedCount,
            Expr::col(guest_grant::Column::UsedCount).add(1),
        )
        .filter(guest_grant::Column::Id.eq(grant_id))
        .filter(guest_grant::Column::RevokedAt.is_null())
        .filter(guest_grant::Column::ExpiresAt.gte(now.fixed_offset()))
        .filter(
            Condition::any()
                .add(guest_grant::Column::MaxUses.eq(0))
                .add(
                    Expr::col(guest_grant::Column::UsedCount)
                        .lt(Expr::col(guest_grant::Column::MaxUses)),
                ),
        )
        .exec(&txn)
        .await
        .map_err(map_db_err)?;
    txn.commit().await.map_err(map_db_err)?;
    Ok(result.rows_affected == 1)
}

/// 写入审计日志。
#[allow(clippy::too_many_arguments)]
pub async fn write_audit(
    db: &DatabaseConnection,
    actor_id: Option<Uuid>,
    action: &str,
    target_type: Option<&str>,
    target_id: Option<&str>,
    detail: Option<Value>,
    ip: Option<String>,
    user_agent: Option<String>,
    now: DateTime<Utc>,
) -> Result<(), AppError> {
    audit_log::ActiveModel {
        id: Set(new_id()),
        actor_id: Set(actor_id),
        action: Set(action.to_string()),
        target_type: Set(target_type.map(str::to_string)),
        target_id: Set(target_id.map(str::to_string)),
        detail: Set(detail),
        ip: Set(ip),
        user_agent: Set(user_agent),
        created_at: Set(now.fixed_offset()),
    }
    .insert(db)
    .await
    .map(|_| ())
    .map_err(map_db_err)
}
