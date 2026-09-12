//! 密码哈希与令牌工具。
//!
//! - 密码使用 Argon2id（默认参数）哈希，禁止任何形式的明文存储；
//! - 激活/重置/刷新令牌均为 256 位随机串，数据库只存 SHA-256 哈希，
//!   即使数据库泄漏也无法直接使用令牌。

use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha256};

use club_common::AppError;

/// 随机令牌字节数（256 位）。
const TOKEN_BYTES: usize = 32;

/// 使用 Argon2id 哈希密码（内部生成随机盐），返回 PHC 字符串。
pub fn hash_password(password: &str) -> Result<String, AppError> {
    Argon2::default()
        .hash_password(password.as_bytes())
        .map(|hash| hash.to_string())
        .map_err(AppError::internal)
}

/// 校验密码是否匹配哈希；哈希格式非法时视为不匹配（不暴露内部细节）。
pub fn verify_password(password: &str, hash: &str) -> bool {
    match PasswordHash::new(hash) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

/// 生成 URL 安全的随机令牌（256 位，base64url 无填充）。
pub fn generate_token() -> String {
    let bytes: [u8; TOKEN_BYTES] = rand::random();
    URL_SAFE_NO_PAD.encode(bytes)
}

/// 计算令牌的 SHA-256 十六进制哈希（入库前调用）。
pub fn hash_token(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_hash_roundtrip() {
        let hash = hash_password("abcd1234").expect("hash");
        assert_ne!(hash, "abcd1234");
        assert!(hash.starts_with("$argon2"));
        assert!(verify_password("abcd1234", &hash));
        assert!(!verify_password("wrong1234", &hash));
    }

    #[test]
    fn same_password_produces_different_hashes() {
        let a = hash_password("abcd1234").expect("hash a");
        let b = hash_password("abcd1234").expect("hash b");
        assert_ne!(a, b, "随机盐导致哈希不同");
    }

    #[test]
    fn invalid_hash_never_verifies() {
        assert!(!verify_password("abcd1234", "not-a-phc-string"));
    }

    #[test]
    fn tokens_are_random_and_url_safe() {
        let tokens: std::collections::HashSet<String> =
            (0..100).map(|_| generate_token()).collect();
        assert_eq!(tokens.len(), 100);
        for token in &tokens {
            assert!(!token.contains('+') && !token.contains('/') && !token.contains('='));
            assert!(token.len() >= 42, "256 位 base64url 至少 43 字符");
        }
    }

    #[test]
    fn token_hash_is_stable_and_hex() {
        let token = "abc";
        let hashed = hash_token(token);
        assert_eq!(hashed, hash_token(token));
        assert_eq!(hashed.len(), 64);
        assert!(hashed.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(hashed, hash_token("abd"));
    }
}
