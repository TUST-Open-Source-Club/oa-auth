//! 环境变量配置。
//!
//! 所有配置集中于此，`from_map` 纯函数便于单元测试（不依赖真实环境变量）。

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{anyhow, Context};

/// 默认 Access Token 有效期（秒）。
pub const DEFAULT_ACCESS_TTL: i64 = 900;
/// 默认 Refresh Token 有效期（秒，30 天）。
pub const DEFAULT_REFRESH_TTL: i64 = 30 * 24 * 3600;
/// 默认激活令牌有效期（秒，7 天）。
pub const DEFAULT_ACTIVATION_TTL: i64 = 7 * 24 * 3600;

/// auth 服务运行配置。
#[derive(Debug, Clone)]
pub struct Config {
    /// PostgreSQL 连接串。
    pub database_url: String,
    /// HTTP 监听地址。
    pub bind_addr: String,
    /// OIDC issuer（同时作为 JWT 的 iss）。
    pub issuer: String,
    /// Web 门户基地址（用于拼接激活链接）。
    pub web_base_url: String,
    /// Access Token 有效期（秒）。
    pub access_token_ttl_seconds: i64,
    /// Refresh Token 有效期（秒）。
    pub refresh_token_ttl_seconds: i64,
    /// 激活令牌有效期（秒）。
    pub activation_ttl_seconds: i64,
    /// JWT 密钥目录（private.pem / public.pem）。
    pub key_dir: PathBuf,
    /// 开发模式：密钥缺失时自动生成、响应中返回激活链接。
    pub dev_mode: bool,
    /// 账号邮箱域名白名单（空 = 不限制）。
    pub account_email_domains: Vec<String>,
    /// 首次启动时创建的超级管理员邮箱。
    pub bootstrap_admin_email: Option<String>,
    /// 首次启动时创建的超级管理员密码（空则随机生成并打印一次）。
    pub bootstrap_admin_password: Option<String>,
    /// 超级管理员昵称。
    pub bootstrap_admin_nickname: String,
}

impl Config {
    /// 从进程环境变量加载配置。
    pub fn from_env() -> anyhow::Result<Self> {
        let map: HashMap<String, String> = std::env::vars().collect();
        Self::from_map(&map)
    }

    /// 从键值映射加载配置（便于测试）。
    pub fn from_map(map: &HashMap<String, String>) -> anyhow::Result<Self> {
        let get = |key: &str| map.get(key).map(String::as_str);

        let database_url = get("DATABASE_URL")
            .ok_or_else(|| anyhow!("缺少必填环境变量 DATABASE_URL"))?
            .to_string();

        let issuer = get("AUTH_ISSUER")
            .unwrap_or("http://localhost:8081")
            .trim_end_matches('/')
            .to_string();
        let web_base_url = get("WEB_BASE_URL")
            .unwrap_or("http://localhost:3000")
            .trim_end_matches('/')
            .to_string();

        Ok(Self {
            database_url,
            bind_addr: get("AUTH_BIND_ADDR").unwrap_or("0.0.0.0:8081").to_string(),
            issuer,
            web_base_url,
            access_token_ttl_seconds: parse_i64(map, "ACCESS_TOKEN_TTL", DEFAULT_ACCESS_TTL)?,
            refresh_token_ttl_seconds: parse_i64(
                map,
                "REFRESH_TOKEN_TTL",
                DEFAULT_REFRESH_TTL,
            )?,
            activation_ttl_seconds: parse_i64(
                map,
                "ACTIVATION_TOKEN_TTL",
                DEFAULT_ACTIVATION_TTL,
            )?,
            key_dir: PathBuf::from(get("KEY_DIR").unwrap_or("data/keys")),
            dev_mode: parse_bool(map, "DEV_MODE", false)?,
            account_email_domains: parse_list(map, "ACCOUNT_EMAIL_DOMAINS"),
            bootstrap_admin_email: get("BOOTSTRAP_ADMIN_EMAIL").map(str::to_string),
            bootstrap_admin_password: get("BOOTSTRAP_ADMIN_PASSWORD").map(str::to_string),
            bootstrap_admin_nickname: get("BOOTSTRAP_ADMIN_NICKNAME")
                .unwrap_or("超级管理员")
                .to_string(),
        })
    }
}

/// 解析整数配置；缺失用默认值，格式错误直接报错（避免带着错误配置启动）。
fn parse_i64(map: &HashMap<String, String>, key: &str, default: i64) -> anyhow::Result<i64> {
    match map.get(key) {
        None => Ok(default),
        Some(value) => value
            .parse::<i64>()
            .with_context(|| format!("环境变量 {key} 不是合法整数: {value}")),
    }
}

/// 解析布尔配置，接受 true/false/1/0。
fn parse_bool(map: &HashMap<String, String>, key: &str, default: bool) -> anyhow::Result<bool> {
    match map.get(key) {
        None => Ok(default),
        Some(value) => match value.as_str() {
            "true" | "1" => Ok(true),
            "false" | "0" => Ok(false),
            _ => Err(anyhow!("环境变量 {key} 不是合法布尔值: {value}")),
        },
    }
}

/// 解析逗号分隔列表（忽略空白项）。
fn parse_list(map: &HashMap<String, String>, key: &str) -> Vec<String> {
    map.get(key)
        .map(|value| {
            value
                .split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn requires_database_url() {
        let err = Config::from_map(&HashMap::new()).unwrap_err();
        assert!(err.to_string().contains("DATABASE_URL"));
    }

    #[test]
    fn applies_defaults() {
        let config = Config::from_map(&map(&[("DATABASE_URL", "postgres://x")])).unwrap();
        assert_eq!(config.bind_addr, "0.0.0.0:8081");
        assert_eq!(config.issuer, "http://localhost:8081");
        assert_eq!(config.web_base_url, "http://localhost:3000");
        assert_eq!(config.access_token_ttl_seconds, DEFAULT_ACCESS_TTL);
        assert_eq!(config.refresh_token_ttl_seconds, DEFAULT_REFRESH_TTL);
        assert!(!config.dev_mode);
        assert!(config.account_email_domains.is_empty());
        assert!(config.bootstrap_admin_email.is_none());
    }

    #[test]
    fn parses_overrides_and_trims_urls() {
        let config = Config::from_map(&map(&[
            ("DATABASE_URL", "postgres://x"),
            ("AUTH_ISSUER", "https://oa.test/"),
            ("WEB_BASE_URL", "https://web.test/"),
            ("AUTH_BIND_ADDR", "127.0.0.1:9000"),
            ("ACCESS_TOKEN_TTL", "60"),
            ("DEV_MODE", "1"),
            (
                "ACCOUNT_EMAIL_DOMAINS",
                "club.example.com, @school.edu.cn ,",
            ),
        ]))
        .unwrap();
        assert_eq!(config.issuer, "https://oa.test");
        assert_eq!(config.web_base_url, "https://web.test");
        assert_eq!(config.bind_addr, "127.0.0.1:9000");
        assert_eq!(config.access_token_ttl_seconds, 60);
        assert!(config.dev_mode);
        assert_eq!(
            config.account_email_domains,
            vec!["club.example.com".to_string(), "@school.edu.cn".to_string()]
        );
    }

    #[test]
    fn rejects_invalid_numbers_and_booleans() {
        assert!(Config::from_map(&map(&[
            ("DATABASE_URL", "postgres://x"),
            ("ACCESS_TOKEN_TTL", "abc"),
        ]))
        .is_err());
        assert!(Config::from_map(&map(&[
            ("DATABASE_URL", "postgres://x"),
            ("DEV_MODE", "yes"),
        ]))
        .is_err());
    }
}
