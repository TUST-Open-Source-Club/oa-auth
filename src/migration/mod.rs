//! SeaORM 数据库迁移。
//!
//! 服务启动时自动执行；也可以在部署流程中通过 `sea-orm-cli migrate up` 手动执行。

use sea_orm_migration::prelude::*;

/// 初始化迁移。
pub mod m20260913_000001_init;

/// Bot 账号与权限矩阵。
pub mod m20260913_000002_bot_accounts;

/// 迁移入口。
pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20260913_000001_init::Migration),
            Box::new(m20260913_000002_bot_accounts::Migration),
        ]
    }
}
