//! 初始化 auth schema：users / refresh_tokens / activation_tokens / guest_grants / audit_logs。

use sea_orm_migration::prelude::*;

/// 迁移定义。
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 表在连接设置的 search_path（auth）下创建；此处兜底确保 schema 存在。
        manager
            .get_connection()
            .execute_unprepared("CREATE SCHEMA IF NOT EXISTS auth")
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(Users::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Users::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(Users::Username).string_len(32).not_null())
                    .col(ColumnDef::new(Users::Email).string_len(254).not_null())
                    .col(ColumnDef::new(Users::PasswordHash).text())
                    .col(ColumnDef::new(Users::Nickname).string_len(64).not_null())
                    .col(ColumnDef::new(Users::Avatar).string_len(255))
                    .col(ColumnDef::new(Users::Bio).text())
                    .col(ColumnDef::new(Users::Department).string_len(64))
                    .col(ColumnDef::new(Users::Status).string_len(32).not_null())
                    .col(ColumnDef::new(Users::Roles).json_binary().not_null())
                    .col(
                        ColumnDef::new(Users::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Users::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("ux_users_email")
                    .table(Users::Table)
                    .col(Users::Email)
                    .unique()
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("ux_users_username")
                    .table(Users::Table)
                    .col(Users::Username)
                    .unique()
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(RefreshTokens::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(RefreshTokens::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(RefreshTokens::UserId).uuid().not_null())
                    .col(ColumnDef::new(RefreshTokens::FamilyId).uuid().not_null())
                    .col(
                        ColumnDef::new(RefreshTokens::TokenHash)
                            .string_len(64)
                            .not_null(),
                    )
                    .col(ColumnDef::new(RefreshTokens::DeviceId).string_len(128))
                    .col(ColumnDef::new(RefreshTokens::UserAgent).text())
                    .col(ColumnDef::new(RefreshTokens::Ip).string_len(64))
                    .col(
                        ColumnDef::new(RefreshTokens::ExpiresAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(RefreshTokens::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(ColumnDef::new(RefreshTokens::RevokedAt).timestamp_with_time_zone())
                    .col(ColumnDef::new(RefreshTokens::RotatedTo).uuid())
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("ux_refresh_tokens_hash")
                    .table(RefreshTokens::Table)
                    .col(RefreshTokens::TokenHash)
                    .unique()
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("ix_refresh_tokens_family")
                    .table(RefreshTokens::Table)
                    .col(RefreshTokens::FamilyId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(ActivationTokens::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(ActivationTokens::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(ActivationTokens::UserId).uuid().not_null())
                    .col(
                        ColumnDef::new(ActivationTokens::TokenHash)
                            .string_len(64)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ActivationTokens::Purpose)
                            .string_len(16)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ActivationTokens::ExpiresAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ActivationTokens::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(ColumnDef::new(ActivationTokens::UsedAt).timestamp_with_time_zone())
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("ux_activation_tokens_hash")
                    .table(ActivationTokens::Table)
                    .col(ActivationTokens::TokenHash)
                    .unique()
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(GuestGrants::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(GuestGrants::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(GuestGrants::ResourceType)
                            .string_len(32)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(GuestGrants::ResourceId)
                            .string_len(64)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(GuestGrants::TicketHash)
                            .string_len(64)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(GuestGrants::MaxUses)
                            .integer()
                            .not_null()
                            .default(0),
                    )
                    .col(
                        ColumnDef::new(GuestGrants::UsedCount)
                            .integer()
                            .not_null()
                            .default(0),
                    )
                    .col(
                        ColumnDef::new(GuestGrants::ExpiresAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(ColumnDef::new(GuestGrants::CreatedBy).uuid())
                    .col(
                        ColumnDef::new(GuestGrants::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(ColumnDef::new(GuestGrants::RevokedAt).timestamp_with_time_zone())
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("ux_guest_grants_ticket_hash")
                    .table(GuestGrants::Table)
                    .col(GuestGrants::TicketHash)
                    .unique()
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(AuditLogs::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(AuditLogs::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(AuditLogs::ActorId).uuid())
                    .col(ColumnDef::new(AuditLogs::Action).string_len(64).not_null())
                    .col(ColumnDef::new(AuditLogs::TargetType).string_len(32))
                    .col(ColumnDef::new(AuditLogs::TargetId).string_len(64))
                    .col(ColumnDef::new(AuditLogs::Detail).json_binary())
                    .col(ColumnDef::new(AuditLogs::Ip).string_len(64))
                    .col(ColumnDef::new(AuditLogs::UserAgent).text())
                    .col(
                        ColumnDef::new(AuditLogs::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 按依赖逆序删除（不同类型无法放入同一数组，逐条处理）
        manager
            .drop_table(Table::drop().table(AuditLogs::Table).if_exists().to_owned())
            .await?;
        manager
            .drop_table(
                Table::drop()
                    .table(GuestGrants::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(
                Table::drop()
                    .table(ActivationTokens::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(
                Table::drop()
                    .table(RefreshTokens::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(Users::Table).if_exists().to_owned())
            .await?;
        Ok(())
    }
}

/// users 表标识符。
#[derive(DeriveIden)]
enum Users {
    Table,
    Id,
    Username,
    Email,
    PasswordHash,
    Nickname,
    Avatar,
    Bio,
    Department,
    Status,
    Roles,
    CreatedAt,
    UpdatedAt,
}

/// refresh_tokens 表标识符。
#[derive(DeriveIden)]
enum RefreshTokens {
    Table,
    Id,
    UserId,
    FamilyId,
    TokenHash,
    DeviceId,
    UserAgent,
    Ip,
    ExpiresAt,
    CreatedAt,
    RevokedAt,
    RotatedTo,
}

/// activation_tokens 表标识符。
#[derive(DeriveIden)]
enum ActivationTokens {
    Table,
    Id,
    UserId,
    TokenHash,
    Purpose,
    ExpiresAt,
    CreatedAt,
    UsedAt,
}

/// guest_grants 表标识符。
#[derive(DeriveIden)]
enum GuestGrants {
    Table,
    Id,
    ResourceType,
    ResourceId,
    TicketHash,
    MaxUses,
    UsedCount,
    ExpiresAt,
    CreatedBy,
    CreatedAt,
    RevokedAt,
}

/// audit_logs 表标识符。
#[derive(DeriveIden)]
enum AuditLogs {
    Table,
    Id,
    ActorId,
    Action,
    TargetType,
    TargetId,
    Detail,
    Ip,
    UserAgent,
    CreatedAt,
}
