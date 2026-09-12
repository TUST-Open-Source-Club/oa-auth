//! auth 服务入口：配置加载 → 数据库连接与迁移 → 密钥 → 首次管理员 → HTTP 服务。

use std::sync::Arc;

use anyhow::Context;
use sea_orm_migration::MigratorTrait;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

use auth_service::clock::SystemClock;
use auth_service::config::Config;
use auth_service::keys::SigningKeys;
use auth_service::mailer::LogMailer;
use auth_service::migration::Migrator;
use auth_service::state::AppState;
use auth_service::{build_router, crypto, db, repo};

/// 初始化日志（RUST_LOG 控制级别，默认 info）。
fn init_tracing() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();
}

/// 首次启动时创建超级管理员（仅当用户表为空且配置了 BOOTSTRAP_ADMIN_EMAIL）。
async fn bootstrap_admin(state: &AppState) -> anyhow::Result<()> {
    if repo::count_users(&state.db).await? > 0 {
        return Ok(());
    }
    let Some(email) = state.config.bootstrap_admin_email.clone() else {
        tracing::warn!("用户表为空且未配置 BOOTSTRAP_ADMIN_EMAIL，跳过管理员初始化");
        return Ok(());
    };
    let email = club_common::validate::normalize_email(&email);
    let username = email
        .split('@')
        .next()
        .map(|local| {
            local
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() {
                        c.to_ascii_lowercase()
                    } else {
                        '.'
                    }
                })
                .collect::<String>()
        })
        .filter(|name| club_common::validate::is_valid_username(name))
        .unwrap_or_else(|| "admin".to_string());

    let generated = state.config.bootstrap_admin_password.is_none();
    let password = state
        .config
        .bootstrap_admin_password
        .clone()
        .unwrap_or_else(crypto::generate_token);

    let now = state.now();
    let user = repo::insert_user(
        &state.db,
        repo::NewUser {
            email: email.clone(),
            username,
            nickname: state.config.bootstrap_admin_nickname.clone(),
            department: None,
            roles: vec!["superadmin".to_string()],
        },
        now,
    )
    .await?;
    let hash = crypto::hash_password(&password)?;
    repo::set_user_password(&state.db, &user, hash, now).await?;

    if generated {
        tracing::warn!(email = %email, password = %password, "已创建超级管理员（随机密码，请立即登录并修改）");
    } else {
        tracing::info!(email = %email, "已创建超级管理员");
    }
    Ok(())
}

/// 程序入口。
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    let config = Config::from_env()?;
    tracing::info!(issuer = %config.issuer, bind = %config.bind_addr, "auth 服务启动中");

    let db = db::connect_with_schema(&config.database_url, "auth")
        .await
        .context("连接数据库失败")?;
    Migrator::up(&db, None).await.context("执行数据库迁移失败")?;

    let keys = SigningKeys::load_or_generate(&config.key_dir, config.dev_mode)
        .context("加载 JWT 密钥失败")?;
    tracing::info!(kid = %keys.kid, "JWT 密钥就绪");

    let state = auth_service::state::SharedState::new(AppState {
        db,
        config,
        keys,
        mailer: Arc::new(LogMailer),
        clock: Arc::new(SystemClock),
    });
    bootstrap_admin(&state).await?;

    let listener = TcpListener::bind(&state.config.bind_addr)
        .await
        .with_context(|| format!("监听 {} 失败", state.config.bind_addr))?;
    tracing::info!(addr = %state.config.bind_addr, "HTTP 服务已就绪");
    axum::serve(listener, build_router(state))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("收到退出信号，正在关闭");
        })
        .await
        .context("HTTP 服务异常退出")?;
    Ok(())
}
