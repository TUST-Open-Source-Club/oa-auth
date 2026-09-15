//! 集成测试脚手架：真实 PostgreSQL（TEST_DATABASE_URL）+ 每测试独立 schema + 迁移。
//!
//! 测试使用固定时钟与日志邮件器，保证行为可预期且无外部依赖。

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use chrono::{DateTime, Utc};
use http_body_util::BodyExt;
use sea_orm::{ConnectionTrait, DatabaseConnection};
use sea_orm_migration::MigratorTrait;
use serde_json::Value;
use tower::ServiceExt;
use uuid::Uuid;

use auth_service::clock::FixedClock;
use auth_service::config::Config;
use auth_service::keys::SigningKeys;
use auth_service::mailer::LogMailer;
use auth_service::migration::Migrator;
use auth_service::state::{AppState, SharedState};
use auth_service::{build_router, crypto, db, repo};

/// 测试数据库连接串（默认指向本地测试容器）。
pub fn test_database_url() -> String {
    std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@127.0.0.1:55432/club_oa".to_string())
}

/// 测试应用实例。
pub struct TestApp {
    /// 应用状态（含数据库连接）。
    pub state: SharedState,
    /// HTTP 路由。
    pub app: Router,
    /// 独立 schema 名（仅供调试）。
    pub schema: String,
    /// 固定时钟。
    pub now: DateTime<Utc>,
}

/// 启动一个隔离的测试应用（独立 schema + 迁移 + 固定时钟）。
pub async fn spawn() -> TestApp {
    spawn_with_env(&[]).await
}

/// 带自定义环境变量启动测试应用。
pub async fn spawn_with_env(extra: &[(&str, &str)]) -> TestApp {
    let url = test_database_url();
    let schema = format!("test_{}", Uuid::now_v7().simple());
    let database = db::connect_with_schema(&url, &schema)
        .await
        .expect("连接测试数据库失败（确认 club-oa-pg-test 容器已启动）");
    Migrator::up(&database, None).await.expect("测试迁移失败");

    // 固定时钟取当前时间（截断到秒）：JWT 过期校验用的是真实系统时间，
    // 写死日期会让用例随着时间推移出现 401。
    let fixed_now = DateTime::<Utc>::from_timestamp(Utc::now().timestamp(), 0)
        .expect("构造固定时钟");
    let mut env: HashMap<String, String> = HashMap::new();
    env.insert("DATABASE_URL".to_string(), url);
    env.insert("AUTH_ISSUER".to_string(), "https://oa.test".to_string());
    env.insert("WEB_BASE_URL".to_string(), "https://web.test".to_string());
    env.insert("DEV_MODE".to_string(), "true".to_string());
    for (key, value) in extra {
        env.insert((*key).to_string(), (*value).to_string());
    }
    let config = Config::from_map(&env).expect("测试配置");

    let state = SharedState::new(AppState {
        db: database,
        config,
        keys: SigningKeys::generate().expect("测试密钥"),
        mailer: Arc::new(LogMailer),
        clock: Arc::new(FixedClock::new(fixed_now)),
    });
    let app = build_router(state.clone());
    TestApp {
        state,
        app,
        schema,
        now: fixed_now,
    }
}

/// 直接创建并激活一个用户（用于准备管理员等前置数据）。
pub async fn seed_active_user(
    app: &TestApp,
    email: &str,
    username: &str,
    password: &str,
    roles: &[&str],
) -> Uuid {
    let now = app.now;
    let user = repo::insert_user(
        &app.state.db,
        repo::NewUser {
            email: email.to_string(),
            username: username.to_string(),
            nickname: format!("用户{username}"),
            department: None,
            roles: roles.iter().map(|role| role.to_string()).collect(),
        },
        now,
    )
    .await
    .expect("创建测试用户");
    let hash = crypto::hash_password(password).expect("密码哈希");
    repo::set_user_password(&app.state.db, &user, hash, now)
        .await
        .expect("激活测试用户");
    user.id
}

/// HTTP 响应快照。
pub struct TestResponse {
    /// 状态码。
    pub status: StatusCode,
    /// JSON 响应体（非 JSON 或空体为 Null）。
    pub body: Value,
}

impl TestResponse {
    /// 断言状态码并返回 JSON。
    pub fn expect(self, status: StatusCode) -> Value {
        assert_eq!(self.status, status, "响应体: {}", self.body);
        self.body
    }
}

/// 发送 JSON 请求（可选 Bearer 令牌）。
pub async fn request(
    app: &Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<&Value>,
) -> TestResponse {
    request_with_headers(app, method, uri, token, body, &[]).await
}

/// 发送带额外请求头的 JSON 请求。
pub async fn request_with_headers(
    app: &Router,
    method: &str,
    uri: &str,
    token: Option<&str>,
    body: Option<&Value>,
    extra_headers: &[(&str, String)],
) -> TestResponse {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    for (name, value) in extra_headers {
        builder = builder.header(*name, value);
    }
    let body_bytes = body
        .map(|value| serde_json::to_vec(value).expect("序列化请求体"))
        .unwrap_or_default();
    let response = app
        .clone()
        .oneshot(builder.body(Body::from(body_bytes)).expect("构建请求"))
        .await
        .expect("执行请求");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("读取响应体")
        .to_bytes();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    TestResponse { status, body }
}

/// 生成内部服务令牌请求头（对精确 body 字节签名）。
pub fn service_headers(app: &TestApp, service: &str, body: &[u8]) -> Vec<(&'static str, String)> {
    let timestamp = app.state.now().timestamp();
    let signature = club_auth_sdk::sign_service_token(
        service,
        app.state.config.internal_secret.as_bytes(),
        timestamp,
        body,
    );
    vec![
        ("x-service-name", service.to_string()),
        ("x-service-timestamp", timestamp.to_string()),
        ("x-service-signature", signature),
    ]
}

/// 以服务身份发送 GET 请求（空 body 签名）。
pub async fn service_get(app: &TestApp, service: &str, uri: &str) -> TestResponse {
    let headers = service_headers(app, service, b"");
    request_with_headers(&app.app, "GET", uri, None, None, &headers).await
}

/// 以服务身份发送 POST JSON 请求。
pub async fn service_post(app: &TestApp, service: &str, uri: &str, body: &Value) -> TestResponse {
    let body_bytes = serde_json::to_vec(body).expect("序列化请求体");
    let headers = service_headers(app, service, &body_bytes);
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json");
    for (name, value) in &headers {
        builder = builder.header(*name, value);
    }
    let response = app
        .app
        .clone()
        .oneshot(builder.body(Body::from(body_bytes)).expect("构建请求"))
        .await
        .expect("执行请求");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("读取响应体")
        .to_bytes();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    TestResponse { status, body }
}

/// 暴露数据库连接（个别测试需要直接查询）。
pub fn database(app: &TestApp) -> &DatabaseConnection {
    &app.state.db
}

/// 清理测试数据（可选调用）。
pub async fn drop_schema(app: &TestApp) {
    let _ = app
        .state
        .db
        .execute_unprepared(&format!("DROP SCHEMA IF EXISTS \"{}\" CASCADE", app.schema))
        .await;
}
