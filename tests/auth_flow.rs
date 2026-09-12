//! 认证主流程集成测试：建号 → 激活 → 登录 → 刷新旋转 → 重放检测 → 登出。

mod common;

use axum::http::StatusCode;
use common::*;
use serde_json::json;

fn member_login_body() -> serde_json::Value {
    json!({ "identifier": "alice", "password": "Alice1234" })
}

#[tokio::test]
async fn admin_create_activate_login_refresh_logout_flow() {
    let app = spawn().await;
    seed_active_user(
        &app,
        "admin@club.example.com",
        "admin",
        "Admin1234",
        &["superadmin"],
    )
    .await;

    // 管理员登录
    let admin_login = request(
        &app.app,
        "POST",
        "/api/v1/auth/login",
        None,
        Some(&json!({ "identifier": "admin@club.example.com", "password": "Admin1234" })),
    )
    .await;
    let admin_token = admin_login.expect(StatusCode::OK)["accessToken"]
        .as_str()
        .expect("管理员令牌")
        .to_string();

    // 创建成员账号（唯一建号入口）
    let created = request(
        &app.app,
        "POST",
        "/api/v1/auth/admin/users",
        Some(&admin_token),
        Some(&json!({
            "email": "alice@club.example.com",
            "username": "alice",
            "nickname": "Alice"
        })),
    )
    .await;
    let created = created.expect(StatusCode::OK);
    assert_eq!(created["user"]["status"], "pending_activation");
    let activation_token = created["devActivationToken"]
        .as_str()
        .expect("开发模式激活令牌")
        .to_string();

    // 未激活不能登录
    let pending = request(
        &app.app,
        "POST",
        "/api/v1/auth/login",
        None,
        Some(&member_login_body()),
    )
    .await;
    let pending_body = pending.expect(StatusCode::FORBIDDEN);
    assert_eq!(pending_body["code"], "AUTH_PENDING_ACTIVATION");

    // 激活并设置密码
    let activate = request(
        &app.app,
        "POST",
        "/api/v1/auth/users/activate",
        None,
        Some(&json!({ "token": activation_token, "password": "Alice1234" })),
    )
    .await;
    activate.expect(StatusCode::NO_CONTENT);

    // 激活令牌一次性
    let activate_again = request(
        &app.app,
        "POST",
        "/api/v1/auth/users/activate",
        None,
        Some(&json!({ "token": activation_token, "password": "Alice1234" })),
    )
    .await;
    activate_again.expect(StatusCode::BAD_REQUEST);

    // 登录
    let login = request(
        &app.app,
        "POST",
        "/api/v1/auth/login",
        None,
        Some(&member_login_body()),
    )
    .await;
    let login = login.expect(StatusCode::OK);
    let access = login["accessToken"].as_str().unwrap().to_string();
    let refresh = login["refreshToken"].as_str().unwrap().to_string();
    assert_eq!(login["user"]["email"], "alice@club.example.com");
    assert_eq!(login["expiresIn"], 900);

    // me
    let me = request(&app.app, "GET", "/api/v1/auth/me", Some(&access), None).await;
    let me = me.expect(StatusCode::OK);
    assert_eq!(me["username"], "alice");
    assert_eq!(me["roles"][0], "member");

    // 刷新旋转
    let rotated = request(
        &app.app,
        "POST",
        "/api/v1/auth/refresh",
        None,
        Some(&json!({ "refreshToken": refresh })),
    )
    .await;
    let rotated = rotated.expect(StatusCode::OK);
    let new_refresh = rotated["refreshToken"].as_str().unwrap().to_string();
    assert_ne!(new_refresh, refresh, "刷新必须旋转令牌");

    // 旧刷新令牌重放 → 整链吊销
    let reuse = request(
        &app.app,
        "POST",
        "/api/v1/auth/refresh",
        None,
        Some(&json!({ "refreshToken": refresh })),
    )
    .await;
    let reuse_body = reuse.expect(StatusCode::UNAUTHORIZED);
    assert_eq!(reuse_body["code"], "AUTH_REFRESH_REUSED");

    // 旋转后的令牌也已被吊销
    let revoked = request(
        &app.app,
        "POST",
        "/api/v1/auth/refresh",
        None,
        Some(&json!({ "refreshToken": new_refresh })),
    )
    .await;
    revoked.expect(StatusCode::UNAUTHORIZED);

    // 重新登录并登出
    let login2 = request(
        &app.app,
        "POST",
        "/api/v1/auth/login",
        None,
        Some(&member_login_body()),
    )
    .await;
    let refresh2 = login2.expect(StatusCode::OK)["refreshToken"]
        .as_str()
        .unwrap()
        .to_string();
    let logout = request(
        &app.app,
        "POST",
        "/api/v1/auth/logout",
        None,
        Some(&json!({ "refreshToken": refresh2 })),
    )
    .await;
    logout.expect(StatusCode::NO_CONTENT);
    let after_logout = request(
        &app.app,
        "POST",
        "/api/v1/auth/refresh",
        None,
        Some(&json!({ "refreshToken": refresh2 })),
    )
    .await;
    after_logout.expect(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn jwks_discovery_and_token_kid_match() {
    let app = spawn().await;
    seed_active_user(
        &app,
        "admin@club.example.com",
        "admin",
        "Admin1234",
        &["superadmin"],
    )
    .await;

    let login = request(
        &app.app,
        "POST",
        "/api/v1/auth/login",
        None,
        Some(&json!({ "identifier": "admin", "password": "Admin1234" })),
    )
    .await;
    let access = login.expect(StatusCode::OK)["accessToken"]
        .as_str()
        .unwrap()
        .to_string();

    let jwks = request(&app.app, "GET", "/.well-known/jwks.json", None, None).await;
    let jwks = jwks.expect(StatusCode::OK);
    let keys = jwks["keys"].as_array().expect("keys");
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["kty"], "RSA");
    assert_eq!(keys[0]["alg"], "RS256");
    let kid = keys[0]["kid"].as_str().expect("kid");

    let header = jsonwebtoken::decode_header(&access).expect("解码 JWT 头部");
    assert_eq!(header.kid.as_deref(), Some(kid), "JWT kid 应与 JWKS 一致");

    let discovery =
        request(&app.app, "GET", "/.well-known/openid-configuration", None, None).await;
    let discovery = discovery.expect(StatusCode::OK);
    assert_eq!(discovery["issuer"], "https://oa.test");
    assert!(discovery["jwks_uri"]
        .as_str()
        .unwrap()
        .ends_with("/.well-known/jwks.json"));
}

#[tokio::test]
async fn admin_create_validates_email_domain_username_and_duplicates() {
    let app = spawn_with_env(&[("ACCOUNT_EMAIL_DOMAINS", "club.example.com")]).await;
    seed_active_user(
        &app,
        "admin@club.example.com",
        "admin",
        "Admin1234",
        &["superadmin"],
    )
    .await;
    let login = request(
        &app.app,
        "POST",
        "/api/v1/auth/login",
        None,
        Some(&json!({ "identifier": "admin", "password": "Admin1234" })),
    )
    .await;
    let token = login.expect(StatusCode::OK)["accessToken"]
        .as_str()
        .unwrap()
        .to_string();

    // 邮箱格式错误
    let invalid = request(
        &app.app,
        "POST",
        "/api/v1/auth/admin/users",
        Some(&token),
        Some(&json!({ "email": "not-an-email" })),
    )
    .await;
    invalid.expect(StatusCode::UNPROCESSABLE_ENTITY);

    // 域名不在白名单
    let wrong_domain = request(
        &app.app,
        "POST",
        "/api/v1/auth/admin/users",
        Some(&token),
        Some(&json!({ "email": "bob@evil.com" })),
    )
    .await;
    let body = wrong_domain.expect(StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body["code"], "AUTH_EMAIL_DOMAIN_NOT_ALLOWED");

    // 正常创建
    let created = request(
        &app.app,
        "POST",
        "/api/v1/auth/admin/users",
        Some(&token),
        Some(&json!({ "email": "bob@club.example.com", "username": "bob" })),
    )
    .await;
    created.expect(StatusCode::OK);

    // 重复邮箱 → 409
    let duplicate = request(
        &app.app,
        "POST",
        "/api/v1/auth/admin/users",
        Some(&token),
        Some(&json!({ "email": "bob@club.example.com", "username": "bob2" })),
    )
    .await;
    let duplicate_body = duplicate.expect(StatusCode::CONFLICT);
    assert_eq!(duplicate_body["code"], "AUTH_EMAIL_TAKEN");

    // 非法用户名 → 422
    let bad_username = request(
        &app.app,
        "POST",
        "/api/v1/auth/admin/users",
        Some(&token),
        Some(&json!({ "email": "carol@club.example.com", "username": "C!" })),
    )
    .await;
    bad_username.expect(StatusCode::UNPROCESSABLE_ENTITY);

    // 非管理员访问管理接口 → 403
    seed_active_user(
        &app,
        "dave@club.example.com",
        "dave",
        "Dave1234",
        &["member"],
    )
    .await;
    let dave_login = request(
        &app.app,
        "POST",
        "/api/v1/auth/login",
        None,
        Some(&json!({ "identifier": "dave", "password": "Dave1234" })),
    )
    .await;
    let dave_token = dave_login.expect(StatusCode::OK)["accessToken"]
        .as_str()
        .unwrap()
        .to_string();
    let forbidden = request(&app.app, "GET", "/api/v1/auth/admin/users", Some(&dave_token), None).await;
    forbidden.expect(StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn disabled_user_cannot_login_and_admin_list_paginates() {
    let app = spawn().await;
    seed_active_user(
        &app,
        "admin@club.example.com",
        "admin",
        "Admin1234",
        &["superadmin"],
    )
    .await;
    let target_id = seed_active_user(
        &app,
        "erin@club.example.com",
        "erin",
        "Erin1234",
        &["member"],
    )
    .await;

    let login = request(
        &app.app,
        "POST",
        "/api/v1/auth/login",
        None,
        Some(&json!({ "identifier": "admin", "password": "Admin1234" })),
    )
    .await;
    let token = login.expect(StatusCode::OK)["accessToken"]
        .as_str()
        .unwrap()
        .to_string();

    // 禁用用户
    let patched = request(
        &app.app,
        "PATCH",
        &format!("/api/v1/auth/admin/users/{target_id}"),
        Some(&token),
        Some(&json!({ "status": "disabled" })),
    )
    .await;
    let patched = patched.expect(StatusCode::OK);
    assert_eq!(patched["status"], "disabled");

    // 禁用后不能登录
    let blocked = request(
        &app.app,
        "POST",
        "/api/v1/auth/login",
        None,
        Some(&json!({ "identifier": "erin", "password": "Erin1234" })),
    )
    .await;
    let blocked_body = blocked.expect(StatusCode::FORBIDDEN);
    assert_eq!(blocked_body["code"], "AUTH_ACCOUNT_DISABLED");

    // 用户列表分页
    let list = request(
        &app.app,
        "GET",
        "/api/v1/auth/admin/users?page=1&pageSize=1",
        Some(&token),
        None,
    )
    .await;
    let list = list.expect(StatusCode::OK);
    assert_eq!(list["items"].as_array().unwrap().len(), 1);
    assert_eq!(list["total"], 2);
    assert_eq!(list["page"], 1);
    assert_eq!(list["pageSize"], 1);
}
