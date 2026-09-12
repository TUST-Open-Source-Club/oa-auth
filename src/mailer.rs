//! 邮件发送抽象。
//!
//! 生产环境接入自建 mail 服务（Stalwart SMTP submission + 出站中继）；
//! 开发/测试环境使用 [`LogMailer`]，将邮件内容写入日志便于本地联调。

use async_trait::async_trait;

use club_common::AppError;

/// 邮件发送端口。
#[async_trait]
pub trait Mailer: Send + Sync {
    /// 发送纯文本邮件；失败返回 500（调用方决定是否阻断主流程）。
    async fn send(&self, to: &str, subject: &str, body: &str) -> Result<(), AppError>;
}

/// 日志邮件器：不真正发送，只记录收件人/主题/正文（含激活链接）。
#[derive(Debug, Clone, Default)]
pub struct LogMailer;

#[async_trait]
impl Mailer for LogMailer {
    async fn send(&self, to: &str, subject: &str, body: &str) -> Result<(), AppError> {
        tracing::info!(to = %to, subject = %subject, body = %body, "邮件（开发模式，未实际发送）");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn log_mailer_always_succeeds() {
        let mailer = LogMailer;
        assert!(mailer
            .send("a@b.cn", "激活账号", "请打开链接 https://oa.test/activate?token=x")
            .await
            .is_ok());
    }
}
