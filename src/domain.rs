//! 领域逻辑（纯函数，便于单元测试）。
//!
//! 不访问数据库、不依赖系统时钟，所有时间与 ID 由参数注入。

use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

use club_auth_sdk::Claims;

use crate::entity::{activation_token, refresh_token, user};

/// 成员默认可访问的模块 scope。
pub const MEMBER_SCOPES: &[&str] = &["im", "task", "doc", "meeting", "event", "drive"];

/// 游客令牌默认有效期（秒，4 小时；且不超过票据有效期）。
pub const GUEST_TOKEN_TTL_SECONDS: i64 = 4 * 3600;

/// 从用户模型的 roles JSON 解析角色列表（容忍脏数据，返回空列表）。
pub fn roles_of(user: &user::Model) -> Vec<String> {
    match &user.roles {
        Value::Array(items) => items
            .iter()
            .filter_map(|item| item.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    }
}

/// 根据角色计算模块 scope。
///
/// superadmin/admin 拥有全部模块；其他角色使用成员默认集合。
pub fn scopes_for(roles: &[String]) -> Vec<String> {
    let is_admin = roles
        .iter()
        .any(|role| role == "admin" || role == "superadmin");
    let _ = is_admin; // 当前管理员与成员模块范围一致，保留分支便于后续细分
    MEMBER_SCOPES.iter().map(|scope| scope.to_string()).collect()
}

/// 构建 Access Token claims。
pub fn build_claims(
    user: &user::Model,
    scopes: Vec<String>,
    ttl_seconds: i64,
    issuer: &str,
    now: DateTime<Utc>,
    jti: Uuid,
) -> Claims {
    Claims {
        sub: user.id.to_string(),
        name: user.nickname.clone(),
        avatar: user.avatar.clone(),
        roles: roles_of(user),
        scopes,
        guest: false,
        iss: issuer.to_string(),
        iat: now.timestamp(),
        exp: now.timestamp() + ttl_seconds,
        jti: jti.to_string(),
    }
}

/// 构建游客 claims（scope 严格限定单一资源）。
#[allow(clippy::too_many_arguments)]
pub fn build_guest_claims(
    grant_id: Uuid,
    display_name: &str,
    resource_type: &str,
    resource_id: &str,
    ttl_seconds: i64,
    issuer: &str,
    now: DateTime<Utc>,
    jti: Uuid,
) -> Claims {
    Claims {
        sub: format!("guest:{grant_id}"),
        name: display_name.to_string(),
        avatar: None,
        roles: Vec::new(),
        scopes: vec![format!("{resource_type}:{resource_id}")],
        guest: true,
        iss: issuer.to_string(),
        iat: now.timestamp(),
        exp: now.timestamp() + ttl_seconds,
        jti: jti.to_string(),
    }
}

/// 刷新令牌的处理决定。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshDecision {
    /// 正常旋转。
    Rotate,
    /// 已旋转过的令牌被再次使用：判定为泄漏，需吊销整个 family。
    ReuseDetected,
    /// 已被吊销（登出/管理员操作）。
    Revoked,
    /// 已过期。
    Expired,
}

/// 根据令牌状态与当前时间决定刷新行为（顺序即优先级）。
pub fn decide_refresh(token: &refresh_token::Model, now: DateTime<Utc>) -> RefreshDecision {
    if token.rotated_to.is_some() {
        return RefreshDecision::ReuseDetected;
    }
    if token.revoked_at.is_some() {
        return RefreshDecision::Revoked;
    }
    if token.expires_at < now.fixed_offset() {
        return RefreshDecision::Expired;
    }
    RefreshDecision::Rotate
}

/// 激活/重置令牌是否有效（未使用、未过期）。
pub fn activation_is_valid(token: &activation_token::Model, now: DateTime<Utc>) -> bool {
    token.used_at.is_none() && token.expires_at >= now.fixed_offset()
}

/// 计算游客令牌有效期：不超过票据剩余有效期。
pub fn guest_ttl(grant_expires_at: DateTime<chrono::FixedOffset>, now: DateTime<Utc>) -> i64 {
    let remaining = (grant_expires_at - now.fixed_offset()).num_seconds();
    remaining.clamp(1, GUEST_TOKEN_TTL_SECONDS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use sea_orm::prelude::Json;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 9, 13, 10, 0, 0).unwrap()
    }

    fn user_model(roles: Value) -> user::Model {
        user::Model {
            id: Uuid::nil(),
            username: "alice".into(),
            email: "alice@club.example.com".into(),
            password_hash: None,
            nickname: "Alice".into(),
            avatar: None,
            bio: None,
            department: None,
            status: user::STATUS_ACTIVE.into(),
            roles,
            created_at: now().fixed_offset(),
            updated_at: now().fixed_offset(),
        }
    }

    fn refresh_model(rotated: bool, revoked: bool, expires_in: i64) -> refresh_token::Model {
        refresh_token::Model {
            id: Uuid::nil(),
            user_id: Uuid::nil(),
            family_id: Uuid::nil(),
            token_hash: "h".into(),
            device_id: None,
            user_agent: None,
            ip: None,
            expires_at: (now() + chrono::Duration::seconds(expires_in)).fixed_offset(),
            created_at: now().fixed_offset(),
            revoked_at: revoked.then(|| now().fixed_offset()),
            rotated_to: rotated.then(Uuid::nil),
        }
    }

    #[test]
    fn roles_are_parsed_defensively() {
        assert_eq!(
            roles_of(&user_model(Json::Array(vec![Json::String("member".into())]))),
            vec!["member".to_string()]
        );
        assert!(roles_of(&user_model(Json::String("broken".into()))).is_empty());
        assert!(roles_of(&user_model(Json::Null)).is_empty());
    }

    #[test]
    fn scopes_cover_member_modules() {
        let scopes = scopes_for(&["member".to_string()]);
        assert!(scopes.contains(&"im".to_string()));
        assert!(scopes.contains(&"drive".to_string()));
        assert_eq!(scopes.len(), MEMBER_SCOPES.len());
    }

    #[test]
    fn claims_include_identity_and_expiry() {
        let model = user_model(Json::Array(vec![Json::String("member".into())]));
        let claims = build_claims(
            &model,
            vec!["im".into()],
            900,
            "https://oa.test",
            now(),
            Uuid::nil(),
        );
        assert_eq!(claims.sub, Uuid::nil().to_string());
        assert_eq!(claims.name, "Alice");
        assert_eq!(claims.iat, now().timestamp());
        assert_eq!(claims.exp, now().timestamp() + 900);
        assert!(!claims.guest);
    }

    #[test]
    fn guest_claims_are_scoped_to_single_resource() {
        let claims = build_guest_claims(
            Uuid::nil(),
            "游客甲",
            "meeting",
            "room-1",
            600,
            "https://oa.test",
            now(),
            Uuid::nil(),
        );
        assert!(claims.guest);
        assert_eq!(claims.scopes, vec!["meeting:room-1"]);
        assert!(claims.roles.is_empty());
        assert_eq!(claims.sub, format!("guest:{}", Uuid::nil()));
    }

    #[test]
    fn refresh_decision_follows_priority() {
        // 重放优先于已吊销
        assert_eq!(
            decide_refresh(&refresh_model(true, true, 100), now()),
            RefreshDecision::ReuseDetected
        );
        assert_eq!(
            decide_refresh(&refresh_model(false, true, 100), now()),
            RefreshDecision::Revoked
        );
        assert_eq!(
            decide_refresh(&refresh_model(false, false, -1), now()),
            RefreshDecision::Expired
        );
        assert_eq!(
            decide_refresh(&refresh_model(false, false, 100), now()),
            RefreshDecision::Rotate
        );
    }

    #[test]
    fn activation_validity_checks_used_and_expiry() {
        let mut token = activation_token::Model {
            id: Uuid::nil(),
            user_id: Uuid::nil(),
            token_hash: "h".into(),
            purpose: activation_token::PURPOSE_ACTIVATE.into(),
            expires_at: (now() + chrono::Duration::seconds(10)).fixed_offset(),
            created_at: now().fixed_offset(),
            used_at: None,
        };
        assert!(activation_is_valid(&token, now()));
        token.used_at = Some(now().fixed_offset());
        assert!(!activation_is_valid(&token, now()));
        token.used_at = None;
        token.expires_at = (now() - chrono::Duration::seconds(1)).fixed_offset();
        assert!(!activation_is_valid(&token, now()));
    }

    #[test]
    fn guest_ttl_is_capped_by_grant_expiry() {
        let grant_expires = (now() + chrono::Duration::seconds(60)).fixed_offset();
        assert_eq!(guest_ttl(grant_expires, now()), 60);
        let long = (now() + chrono::Duration::seconds(GUEST_TOKEN_TTL_SECONDS * 2)).fixed_offset();
        assert_eq!(guest_ttl(long, now()), GUEST_TOKEN_TTL_SECONDS);
        let past = (now() - chrono::Duration::seconds(10)).fixed_offset();
        assert_eq!(guest_ttl(past, now()), 1, "已过期至少给 1 秒避免 0");
    }
}
