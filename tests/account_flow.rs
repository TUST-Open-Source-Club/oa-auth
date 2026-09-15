//! 账号自助流程集成测试：健康检查、资料、改密、重置密码、搜索与错误分支。

mod common;

use axum::http::StatusCode;
use common::*;
use serde_json::json;

async fn admin_token(app: &TestApp) -> String {
    seed_active_user(
        app,
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
    login.expect(StatusCode::OK)["accessToken"]
        .as_str()
        .unwrap()
        .to_string()
}

async fn login_user(app: &TestApp, identifier: &str, password: &str) -> TestResponse {
    request(
        &app.app,
        "POST",
        "/api/v1/auth/login",
        None,
        Some(&json!({ "identifier": identifier, "password": password })),
    )
    .await
}


#[tokio::test]
async fn batch_users_lookup_by_ids() {
    let app = spawn().await;
    let _ = admin_token(&app).await;
    seed_active_user(&app, "bob@club.example.com", "bob", "Bob12345", &["member"]).await;

    let access = login_user(&app, "bob", "Bob12345").await.expect(StatusCode::OK)["accessToken"]
        .as_str()
        .unwrap()
        .to_string();
    let me = request(&app.app, "GET", "/api/v1/auth/me", Some(&access), None)
        .await
        .expect(StatusCode::OK);
    let id = me["id"].as_str().unwrap().to_string();

    // 批量查询命中
    let found = request(
        &app.app,
        "GET",
        &format!("/api/v1/auth/users?ids={id}"),
        Some(&access),
        None,
    )
    .await
    .expect(StatusCode::OK);
    let found = found.as_array().unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0]["username"], "bob");

    // 未知 ID → 空数组
    let missing = request(
        &app.app,
        "GET",
        &format!("/api/v1/auth/users?ids={}", uuid::Uuid::now_v7()),
        Some(&access),
        None,
    )
    .await
    .expect(StatusCode::OK);
    assert!(missing.as_array().unwrap().is_empty());

    // 非法 ID → 400
    request(
        &app.app,
        "GET",
        "/api/v1/auth/users?ids=not-a-uuid",
        Some(&access),
        None,
    )
    .await
    .expect(StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn health_and_ready_endpoints() {
    let app = spawn().await;
    let health = request(&app.app, "GET", "/healthz", None, None).await;
    assert_eq!(health.expect(StatusCode::OK)["status"], "ok");
    let ready = request(&app.app, "GET", "/readyz", None, None).await;
    assert_eq!(ready.expect(StatusCode::OK)["database"], "ok");
}

#[tokio::test]
async fn update_profile_change_password_and_search() {
    let app = spawn().await;
    let _ = admin_token(&app).await;
    seed_active_user(&app, "amy@club.example.com", "amy", "Amy12345", &["member"]).await;

    let login = login_user(&app, "amy", "Amy12345").await;
    let access = login.expect(StatusCode::OK)["accessToken"]
        .as_str()
        .unwrap()
        .to_string();

    // 更新资料
    let updated = request(
        &app.app,
        "PATCH",
        "/api/v1/auth/me",
        Some(&access),
        Some(&json!({ "nickname": "Amy Chen", "bio": "热爱社团", "department": "宣传部" })),
    )
    .await;
    let updated = updated.expect(StatusCode::OK);
    assert_eq!(updated["nickname"], "Amy Chen");
    assert_eq!(updated["department"], "宣传部");

    // 昵称为空 → 422
    let invalid = request(
        &app.app,
        "PATCH",
        "/api/v1/auth/me",
        Some(&access),
        Some(&json!({ "nickname": "   " })),
    )
    .await;
    invalid.expect(StatusCode::UNPROCESSABLE_ENTITY);

    // 修改密码：旧密码错误 → 401
    let wrong = request(
        &app.app,
        "PUT",
        "/api/v1/auth/me/password",
        Some(&access),
        Some(&json!({ "oldPassword": "Wrong1234", "newPassword": "Amy67890" })),
    )
    .await;
    wrong.expect(StatusCode::UNAUTHORIZED);

    // 弱密码 → 422
    let weak = request(
        &app.app,
        "PUT",
        "/api/v1/auth/me/password",
        Some(&access),
        Some(&json!({ "oldPassword": "Amy12345", "newPassword": "short" })),
    )
    .await;
    let weak_body = weak.expect(StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(weak_body["errors"][0]["field"], "password");

    // 正常修改密码（会吊销全部会话）
    let changed = request(
        &app.app,
        "PUT",
        "/api/v1/auth/me/password",
        Some(&access),
        Some(&json!({ "oldPassword": "Amy12345", "newPassword": "Amy67890" })),
    )
    .await;
    changed.expect(StatusCode::NO_CONTENT);
    login_user(&app, "amy", "Amy12345")
        .await
        .expect(StatusCode::UNAUTHORIZED);
    login_user(&app, "amy", "Amy67890")
        .await
        .expect(StatusCode::OK);

    // 用户搜索
    let search = request(
        &app.app,
        "GET",
        "/api/v1/auth/users/search?q=amy",
        Some(
            &login_user(&app, "amy", "Amy67890")
                .await
                .expect(StatusCode::OK)["accessToken"]
                .as_str()
                .unwrap()
                .to_string(),
        ),
        None,
    )
    .await;
    let results = search.expect(StatusCode::OK);
    assert_eq!(results.as_array().unwrap().len(), 1);
    assert_eq!(results[0]["username"], "amy");

    // 空关键字返回空数组
    let empty_search = request(
        &app.app,
        "GET",
        "/api/v1/auth/users/search?q=",
        Some(
            &login_user(&app, "amy", "Amy67890")
                .await
                .expect(StatusCode::OK)["accessToken"]
                .as_str()
                .unwrap()
                .to_string(),
        ),
        None,
    )
    .await;
    assert_eq!(
        empty_search
            .expect(StatusCode::OK)
            .as_array()
            .unwrap()
            .len(),
        0
    );

    // 无效令牌 → 401
    let invalid_me = request(&app.app, "GET", "/api/v1/auth/me", Some("invalid"), None).await;
    invalid_me.expect(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn admin_reset_password_flow_and_error_branches() {
    let app = spawn().await;
    let admin = admin_token(&app).await;
    let target_id = seed_active_user(
        &app,
        "erin@club.example.com",
        "erin",
        "Erin1234",
        &["member"],
    )
    .await;

    // 管理员重置密码
    let reset = request(
        &app.app,
        "POST",
        &format!("/api/v1/auth/admin/users/{target_id}/reset-password"),
        Some(&admin),
        None,
    )
    .await;
    let reset = reset.expect(StatusCode::OK);
    let reset_token = reset["devResetToken"]
        .as_str()
        .expect("重置令牌")
        .to_string();

    // 重置为弱密码 → 422
    let weak = request(
        &app.app,
        "POST",
        "/api/v1/auth/password/reset",
        None,
        Some(&json!({ "token": reset_token, "password": "weak" })),
    )
    .await;
    weak.expect(StatusCode::UNPROCESSABLE_ENTITY);

    // 正常重置
    let ok = request(
        &app.app,
        "POST",
        "/api/v1/auth/password/reset",
        None,
        Some(&json!({ "token": reset_token, "password": "Erin5678" })),
    )
    .await;
    ok.expect(StatusCode::NO_CONTENT);
    login_user(&app, "erin", "Erin5678")
        .await
        .expect(StatusCode::OK);

    // 重置令牌一次性
    let again = request(
        &app.app,
        "POST",
        "/api/v1/auth/password/reset",
        None,
        Some(&json!({ "token": reset_token, "password": "Erin9012" })),
    )
    .await;
    again.expect(StatusCode::BAD_REQUEST);

    // 忘记密码：存在与不存在的邮箱都返回 204（防枚举）
    let forgot = request(
        &app.app,
        "POST",
        "/api/v1/auth/password/forgot",
        None,
        Some(&json!({ "email": "erin@club.example.com" })),
    )
    .await;
    forgot.expect(StatusCode::NO_CONTENT);
    let forgot_unknown = request(
        &app.app,
        "POST",
        "/api/v1/auth/password/forgot",
        None,
        Some(&json!({ "email": "nobody@club.example.com" })),
    )
    .await;
    forgot_unknown.expect(StatusCode::NO_CONTENT);

    // 管理员更新昵称/部门；非法状态 → 422；不存在的用户 → 404
    let patched = request(
        &app.app,
        "PATCH",
        &format!("/api/v1/auth/admin/users/{target_id}"),
        Some(&admin),
        Some(&json!({ "nickname": "Erin W", "department": "外联部" })),
    )
    .await;
    let patched = patched.expect(StatusCode::OK);
    assert_eq!(patched["nickname"], "Erin W");

    let bad_status = request(
        &app.app,
        "PATCH",
        &format!("/api/v1/auth/admin/users/{target_id}"),
        Some(&admin),
        Some(&json!({ "status": "deleted" })),
    )
    .await;
    bad_status.expect(StatusCode::UNPROCESSABLE_ENTITY);

    let missing = request(
        &app.app,
        "PATCH",
        &format!("/api/v1/auth/admin/users/{}", uuid::Uuid::now_v7()),
        Some(&admin),
        Some(&json!({ "status": "active" })),
    )
    .await;
    missing.expect(StatusCode::NOT_FOUND);

    // 激活令牌非法 → 400
    let bad_activate = request(
        &app.app,
        "POST",
        "/api/v1/auth/users/activate",
        None,
        Some(&json!({ "token": "nope", "password": "Valid1234" })),
    )
    .await;
    bad_activate.expect(StatusCode::BAD_REQUEST);

    // 未知刷新令牌 → 401；未知用户重置 → 404
    let unknown_refresh = request(
        &app.app,
        "POST",
        "/api/v1/auth/refresh",
        None,
        Some(&json!({ "refreshToken": "nope" })),
    )
    .await;
    unknown_refresh.expect(StatusCode::UNAUTHORIZED);
    let missing_reset = request(
        &app.app,
        "POST",
        &format!(
            "/api/v1/auth/admin/users/{}/reset-password",
            uuid::Uuid::now_v7()
        ),
        Some(&admin),
        None,
    )
    .await;
    missing_reset.expect(StatusCode::NOT_FOUND);
}
