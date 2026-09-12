//! 游客票据与内部服务接口集成测试。

mod common;

use axum::http::StatusCode;
use common::*;
use serde_json::json;

#[tokio::test]
async fn guest_ticket_exchange_limits_uses_and_scopes_token() {
    let app = spawn().await;

    // 资源服务（meeting）创建一次性票据
    let grant = service_post(
        &app,
        "meeting",
        "/api/v1/auth/internal/guest-grants",
        &json!({
            "resourceType": "meeting",
            "resourceId": "room-42",
            "maxUses": 1,
            "expiresInSeconds": 3600
        }),
    )
    .await;
    let grant = grant.expect(StatusCode::OK);
    let ticket = grant["ticket"].as_str().expect("票据").to_string();

    // 兑换游客 JWT
    let exchanged = request(
        &app.app,
        "POST",
        "/api/v1/auth/guest/exchange",
        None,
        Some(&json!({ "ticket": ticket, "displayName": "访客甲" })),
    )
    .await;
    let exchanged = exchanged.expect(StatusCode::OK);
    let access = exchanged["accessToken"].as_str().expect("游客令牌");

    // scope 必须严格限定单一资源，且标记为游客
    let claims = club_auth_sdk::decode_access_token(
        access,
        &app.state.keys.decoding_key,
        "https://oa.test",
    )
    .expect("验签游客令牌");
    assert!(claims.guest);
    assert_eq!(claims.scopes, vec!["meeting:room-42"]);
    assert_eq!(claims.name, "访客甲");
    assert!(claims.roles.is_empty());

    // 使用次数耗尽 → 403
    let second = request(
        &app.app,
        "POST",
        "/api/v1/auth/guest/exchange",
        None,
        Some(&json!({ "ticket": ticket, "displayName": "访客乙" })),
    )
    .await;
    let second_body = second.expect(StatusCode::FORBIDDEN);
    assert_eq!(second_body["code"], "AUTH_GUEST_TICKET_EXHAUSTED");
}

#[tokio::test]
async fn invalid_or_expired_guest_ticket_is_rejected() {
    let app = spawn().await;

    // 不存在的票据
    let unknown = request(
        &app.app,
        "POST",
        "/api/v1/auth/guest/exchange",
        None,
        Some(&json!({ "ticket": "does-not-exist" })),
    )
    .await;
    let unknown_body = unknown.expect(StatusCode::UNAUTHORIZED);
    assert_eq!(unknown_body["code"], "AUTH_GUEST_TICKET_INVALID");

    // 非法资源类型
    let invalid_type = service_post(
        &app,
        "im",
        "/api/v1/auth/internal/guest-grants",
        &json!({ "resourceType": "im", "resourceId": "x" }),
    )
    .await;
    invalid_type.expect(StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn internal_endpoints_require_valid_service_token() {
    let app = spawn().await;

    // 无服务令牌 → 401
    let missing = request(
        &app.app,
        "POST",
        "/api/v1/auth/internal/guest-grants",
        None,
        Some(&json!({ "resourceType": "meeting", "resourceId": "r1" })),
    )
    .await;
    missing.expect(StatusCode::UNAUTHORIZED);

    // 伪造签名 → 401
    let forged = request_with_headers(
        &app.app,
        "POST",
        "/api/v1/auth/internal/guest-grants",
        None,
        Some(&json!({ "resourceType": "meeting", "resourceId": "r1" })),
        &[
            ("x-service-name", "meeting".to_string()),
            ("x-service-timestamp", app.state.now().timestamp().to_string()),
            ("x-service-signature", "forged-signature".to_string()),
        ],
    )
    .await;
    forged.expect(StatusCode::UNAUTHORIZED);

    // 正确的服务令牌可创建票据
    let ok = service_post(
        &app,
        "drive",
        "/api/v1/auth/internal/guest-grants",
        &json!({ "resourceType": "drive", "resourceId": "share-1" }),
    )
    .await;
    ok.expect(StatusCode::OK);
}

#[tokio::test]
async fn internal_user_lookup_returns_profile() {
    let app = spawn().await;
    let user_id = seed_active_user(
        &app,
        "frank@club.example.com",
        "frank",
        "Frank1234",
        &["member"],
    )
    .await;

    let body = serde_json::to_vec(&json!({ "ids": [user_id.to_string()] })).expect("序列化");
    let headers = service_headers(&app, "im", &body);
    let response = request_with_headers(
        &app.app,
        "POST",
        "/api/v1/auth/internal/users/batch",
        None,
        Some(&json!({ "ids": [user_id.to_string()] })),
        &headers,
    )
    .await;
    let response = response.expect(StatusCode::OK);
    let items = response.as_array().expect("数组");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["username"], "frank");
}
