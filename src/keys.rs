//! JWT 签名密钥管理。
//!
//! 生产环境从 `KEY_DIR` 读取 `private.pem` / `public.pem`；开发模式允许自动生成
//! 并把密钥写入磁盘（仅限本地调试，绝不用于生产）。

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use jsonwebtoken::DecodingKey;
use rsa::pkcs8::{
    DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey, LineEnding,
};
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;

use club_auth_sdk::jwks::{jwk_from_rsa_public_components, key_id_from_pem, Jwks};
use club_auth_sdk::{encode_access_token, Claims, JwtError};

/// Rsa 密钥位数（2048 足够 RS256，兼顾性能）。
const RSA_BITS: usize = 2048;

/// 签名密钥集合。
pub struct SigningKeys {
    /// 私钥 PEM（签发用，禁止外泄）。
    pub private_pem: Vec<u8>,
    /// 公钥 PEM（对外发布 JWKS）。
    pub public_pem: Vec<u8>,
    /// 密钥 ID（由公钥派生，与 JWT 头部一致）。
    pub kid: String,
    /// 验签 key（缓存，避免每请求解析 PEM）。
    pub decoding_key: DecodingKey,
}

impl std::fmt::Debug for SigningKeys {
    /// 手动实现 Debug：绝不打印私钥内容。
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKeys")
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

impl SigningKeys {
    /// 从 PEM 内容构造。
    pub fn from_pems(private_pem: Vec<u8>, public_pem: Vec<u8>) -> Result<Self> {
        let kid = key_id_from_pem(&public_pem);
        let decoding_key = club_auth_sdk::decoding_key_from_rsa_pem(&public_pem)
            .map_err(|e| anyhow::anyhow!("公钥 PEM 无法解析: {e}"))?;
        Ok(Self {
            private_pem,
            public_pem,
            kid,
            decoding_key,
        })
    }

    /// 从目录加载；文件缺失且 `dev_mode` 时生成并落盘。
    pub fn load_or_generate(dir: &Path, dev_mode: bool) -> Result<Self> {
        let private_path = dir.join("private.pem");
        let public_path = dir.join("public.pem");
        if private_path.exists() && public_path.exists() {
            let private_pem = std::fs::read(&private_path)
                .with_context(|| format!("读取 {}", private_path.display()))?;
            let public_pem = std::fs::read(&public_path)
                .with_context(|| format!("读取 {}", public_path.display()))?;
            return Self::from_pems(private_pem, public_pem);
        }
        if !dev_mode {
            anyhow::bail!(
                "缺少 JWT 密钥文件（{} / {}），且未开启 DEV_MODE",
                private_path.display(),
                public_path.display()
            );
        }
        let keys = Self::generate()?;
        std::fs::create_dir_all(dir).with_context(|| format!("创建密钥目录 {}", dir.display()))?;
        std::fs::write(&private_path, &keys.private_pem)
            .with_context(|| format!("写入 {}", private_path.display()))?;
        // 私钥文件权限收紧（仅当前用户可读）。
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&private_path, std::fs::Permissions::from_mode(0o600));
        }
        std::fs::write(&public_path, &keys.public_pem)
            .with_context(|| format!("写入 {}", public_path.display()))?;
        Ok(keys)
    }

    /// 生成新的 RSA 密钥对。
    pub fn generate() -> Result<Self> {
        let mut rng = rand_core::OsRng;
        let private = RsaPrivateKey::new(&mut rng, RSA_BITS).context("生成 RSA 密钥失败")?;
        let private_pem = private
            .to_pkcs8_pem(LineEnding::LF)
            .context("编码私钥失败")?
            .as_bytes()
            .to_vec();
        let public_pem = rsa::RsaPublicKey::from(&private)
            .to_public_key_pem(LineEnding::LF)
            .context("编码公钥失败")?
            .into_bytes();
        Self::from_pems(private_pem, public_pem)
    }

    /// 签发 Access Token。
    pub fn encode(&self, claims: &Claims) -> Result<String, JwtError> {
        encode_access_token(claims, &self.private_pem, &self.kid)
    }

    /// 生成 JWKS 响应内容。
    pub fn jwks(&self) -> Result<Jwks> {
        let public = rsa::RsaPublicKey::from_public_key_pem(
            std::str::from_utf8(&self.public_pem).context("公钥 PEM 非法 UTF-8")?,
        )
        .context("公钥 PEM 解析失败")?;
        Ok(Jwks {
            keys: vec![jwk_from_rsa_public_components(
                &self.kid,
                &public.n().to_bytes_be(),
                &public.e().to_bytes_be(),
            )],
        })
    }

    /// 密钥文件默认目录（相对工作目录）。
    pub fn default_dir() -> PathBuf {
        PathBuf::from("data/keys")
    }

    /// 从私钥 PEM 还原并重新派生公钥（用于校验密钥对一致性）。
    pub fn public_pem_from_private(private_pem: &[u8]) -> Result<Vec<u8>> {
        let private = RsaPrivateKey::from_pkcs8_pem(
            std::str::from_utf8(private_pem).context("私钥 PEM 非法 UTF-8")?,
        )
        .context("私钥 PEM 解析失败")?;
        Ok(rsa::RsaPublicKey::from(&private)
            .to_public_key_pem(LineEnding::LF)
            .context("编码公钥失败")?
            .into_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use club_auth_sdk::decode_access_token;
    use club_common::new_id;

    fn sample_claims(iss: &str) -> Claims {
        Claims {
            sub: "u1".into(),
            name: "张三".into(),
            avatar: None,
            roles: vec!["member".into()],
            scopes: vec!["im".into()],
            guest: false,
            account_type: None,
            bot_permissions: None,
            iss: iss.into(),
            iat: Utc::now().timestamp(),
            exp: Utc::now().timestamp() + 900,
            jti: new_id().to_string(),
        }
    }

    #[test]
    fn generate_sign_verify_and_jwks() {
        let keys = SigningKeys::generate().expect("generate");
        let claims = sample_claims("https://oa.test");
        let token = keys.encode(&claims).expect("sign");
        let decoded =
            decode_access_token(&token, &keys.decoding_key, "https://oa.test").expect("verify");
        assert_eq!(decoded, claims);

        let jwks = keys.jwks().expect("jwks");
        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.keys[0].kid, keys.kid);
        assert_eq!(jwks.keys[0].alg, "RS256");

        // JWKS 公钥能验证同一 token（kid 与头部一致）
        let header = jsonwebtoken::decode_header(&token).expect("header");
        assert_eq!(header.kid.as_deref(), Some(keys.kid.as_str()));
        let key =
            club_auth_sdk::jwks::decoding_key_from_jwks(&jwks, header.kid.as_deref()).expect("key");
        decode_access_token(&token, &key, "https://oa.test").expect("verify via jwks");
    }

    #[test]
    fn private_and_public_pem_are_consistent() {
        let keys = SigningKeys::generate().expect("generate");
        let derived = SigningKeys::public_pem_from_private(&keys.private_pem).expect("derive");
        assert_eq!(derived, keys.public_pem);
        assert_eq!(key_id_from_pem(&derived), keys.kid);
    }

    #[test]
    fn load_or_generate_persists_keys_in_dev_mode() {
        let dir = std::env::temp_dir().join(format!("club-oa-keys-{}", new_id()));
        let first = SigningKeys::load_or_generate(&dir, true).expect("first");
        let second = SigningKeys::load_or_generate(&dir, true).expect("second");
        assert_eq!(first.kid, second.kid, "再次加载应得到同一对密钥");
        assert!(dir.join("private.pem").exists());

        // 非开发模式且文件缺失时报错
        let missing = std::env::temp_dir().join(format!("club-oa-keys-none-{}", new_id()));
        assert!(SigningKeys::load_or_generate(&missing, false).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
