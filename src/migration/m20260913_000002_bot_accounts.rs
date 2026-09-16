//! Bot 账号：account_type 与权限矩阵（模块 → 读/写）。

use sea_orm_migration::prelude::*;

/// 迁移。
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        conn.execute_unprepared("ALTER TABLE users ADD COLUMN account_type text NOT NULL DEFAULT 'human'")
            .await?;
        conn.execute_unprepared("ALTER TABLE users ADD COLUMN bot_permissions jsonb NOT NULL DEFAULT '{}'")
            .await?;
        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        Ok(())
    }
}
