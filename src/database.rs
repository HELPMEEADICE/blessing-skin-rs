use sqlx::{
    FromRow, MySqlPool, PgPool, SqlitePool, mysql::MySqlPoolOptions, postgres::PgPoolOptions,
    sqlite::SqlitePoolOptions,
};
use thiserror::Error;

use crate::config::{DatabaseConfig, DatabaseConnection};

#[derive(Clone)]
pub enum DatabasePool {
    Sqlite(SqlitePool),
    MySql(MySqlPool),
    Postgres(PgPool),
}

#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
}

#[derive(Debug, FromRow)]
pub struct PlayerProfile {
    pub name: String,
    pub permission: i32,
    pub skin_type: Option<String>,
    pub skin_hash: Option<String>,
    pub cape_hash: Option<String>,
    pub last_modified: Option<String>,
}

#[derive(Debug, FromRow)]
pub struct AccessTokenRecord {
    pub user_id: Option<i64>,
    pub client_id: i64,
    pub revoked: bool,
}

#[derive(Debug, FromRow, serde::Serialize)]
pub struct UserProfile {
    pub uid: i64,
    pub email: String,
    pub nickname: String,
    pub locale: Option<String>,
    pub score: i64,
    pub avatar: i64,
    pub permission: i32,
    pub last_sign_at: String,
    pub register_at: String,
    pub verified: bool,
    pub is_dark_mode: bool,
}
#[derive(Debug, FromRow, serde::Serialize)]
pub struct PlayerRecord {
    pub pid: i64,
    pub uid: i64,
    pub name: String,
    pub tid_skin: i64,
    pub tid_cape: i64,
    pub last_modified: String,
}
#[derive(Debug, FromRow)]
pub struct PasswordCredential {
    pub uid: i64,
    pub password: String,
    pub permission: i32,
}
#[derive(Debug, FromRow)]
pub struct NotificationRecord {
    pub id: String,
    pub data: String,
    pub created_at: String,
}
#[derive(Debug)]
pub enum PlayerRenameOutcome {
    NotFound,
    Forbidden,
    NameExists,
    Renamed {
        previous_name: String,
        player: PlayerRecord,
    },
}
#[derive(Debug)]
pub enum PlayerTextureOutcome {
    NotFound,
    Forbidden,
    TextureNotFound,
    TextureNotInCloset,
    Updated(PlayerRecord),
}
impl DatabasePool {
    pub async fn connect(config: &DatabaseConfig) -> Result<Self, DatabaseError> {
        let pool = match &config.connection {
            DatabaseConnection::Sqlite(options) => Self::Sqlite(
                SqlitePoolOptions::new()
                    .max_connections(10)
                    .connect_with(options.clone())
                    .await?,
            ),
            DatabaseConnection::MySql(options) => Self::MySql(
                MySqlPoolOptions::new()
                    .max_connections(10)
                    .connect_with(options.clone())
                    .await?,
            ),
            DatabaseConnection::Postgres(options) => Self::Postgres(
                PgPoolOptions::new()
                    .max_connections(10)
                    .connect_with(options.clone())
                    .await?,
            ),
        };
        Ok(pool)
    }

    pub async fn ping(&self) -> Result<(), sqlx::Error> {
        match self {
            Self::Sqlite(pool) => {
                sqlx::query("SELECT 1").execute(pool).await?;
            }
            Self::MySql(pool) => {
                sqlx::query("SELECT 1").execute(pool).await?;
            }
            Self::Postgres(pool) => {
                sqlx::query("SELECT 1").execute(pool).await?;
            }
        }
        Ok(())
    }

    pub async fn option(&self, prefix: &str, key: &str) -> Result<Option<String>, sqlx::Error> {
        let sql = match self {
            Self::Sqlite(_) | Self::MySql(_) => {
                format!("SELECT option_value FROM {prefix}options WHERE option_name = ? LIMIT 1")
            }
            Self::Postgres(_) => {
                format!("SELECT option_value FROM {prefix}options WHERE option_name = $1 LIMIT 1")
            }
        };
        match self {
            Self::Sqlite(pool) => Ok(sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(sql))
                .bind(key)
                .fetch_optional(pool)
                .await?),
            Self::MySql(pool) => {
                let sql = sql.replace("$1", "?");
                Ok(sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(sql))
                    .bind(key)
                    .fetch_optional(pool)
                    .await?)
            }
            Self::Postgres(pool) => Ok(sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(sql))
                .bind(key)
                .fetch_optional(pool)
                .await?),
        }
    }

    pub async fn player_profile(
        &self,
        prefix: &str,
        name: &str,
    ) -> Result<Option<PlayerProfile>, sqlx::Error> {
        let sql = match self {
            Self::Sqlite(_) => format!(
                "SELECT p.name, u.permission, s.type AS skin_type, s.hash AS skin_hash, \
                 c.hash AS cape_hash, CAST(p.last_modified AS TEXT) AS last_modified \
                 FROM {prefix}players p \
                 INNER JOIN {prefix}users u ON u.uid = p.uid \
                 LEFT JOIN {prefix}textures s ON s.tid = p.tid_skin \
                 LEFT JOIN {prefix}textures c ON c.tid = p.tid_cape \
                 WHERE p.name = ? LIMIT 1"
            ),
            Self::MySql(_) => format!(
                "SELECT p.name, u.permission, s.type AS skin_type, s.hash AS skin_hash, \
                 c.hash AS cape_hash, DATE_FORMAT(p.last_modified, '%Y-%m-%d %H:%i:%s') AS last_modified \
                 FROM {prefix}players p \
                 INNER JOIN {prefix}users u ON u.uid = p.uid \
                 LEFT JOIN {prefix}textures s ON s.tid = p.tid_skin \
                 LEFT JOIN {prefix}textures c ON c.tid = p.tid_cape \
                 WHERE p.name = ? LIMIT 1"
            ),
            Self::Postgres(_) => format!(
                "SELECT p.name, u.permission, s.type AS skin_type, s.hash AS skin_hash, \
                 c.hash AS cape_hash, to_char(p.last_modified, 'YYYY-MM-DD HH24:MI:SS') AS last_modified \
                 FROM {prefix}players p \
                 INNER JOIN {prefix}users u ON u.uid = p.uid \
                 LEFT JOIN {prefix}textures s ON s.tid = p.tid_skin \
                 LEFT JOIN {prefix}textures c ON c.tid = p.tid_cape \
                 WHERE p.name = $1 LIMIT 1"
            ),
        };
        match self {
            Self::Sqlite(pool) => Ok(sqlx::query_as::<_, PlayerProfile>(sqlx::AssertSqlSafe(sql))
                .bind(name)
                .fetch_optional(pool)
                .await?),
            Self::MySql(pool) => Ok(sqlx::query_as::<_, PlayerProfile>(sqlx::AssertSqlSafe(sql))
                .bind(name)
                .fetch_optional(pool)
                .await?),
            Self::Postgres(pool) => {
                Ok(sqlx::query_as::<_, PlayerProfile>(sqlx::AssertSqlSafe(sql))
                    .bind(name)
                    .fetch_optional(pool)
                    .await?)
            }
        }
    }

    pub async fn texture_hash(
        &self,
        prefix: &str,
        tid: i64,
    ) -> Result<Option<String>, sqlx::Error> {
        let sql = match self {
            Self::Postgres(_) => {
                format!("SELECT hash FROM {prefix}textures WHERE tid = $1 LIMIT 1")
            }
            _ => format!("SELECT hash FROM {prefix}textures WHERE tid = ? LIMIT 1"),
        };
        match self {
            Self::Sqlite(pool) => Ok(sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(sql))
                .bind(tid)
                .fetch_optional(pool)
                .await?),
            Self::MySql(pool) => Ok(sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(sql))
                .bind(tid)
                .fetch_optional(pool)
                .await?),
            Self::Postgres(pool) => Ok(sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(sql))
                .bind(tid)
                .fetch_optional(pool)
                .await?),
        }
    }
    pub async fn access_token(
        &self,
        prefix: &str,
        token_id: &str,
    ) -> Result<Option<AccessTokenRecord>, sqlx::Error> {
        let sql = match self {
            Self::Postgres(_) => format!(
                "SELECT user_id, client_id, revoked FROM {prefix}oauth_access_tokens WHERE id = $1 LIMIT 1"
            ),
            _ => format!(
                "SELECT user_id, client_id, revoked FROM {prefix}oauth_access_tokens WHERE id = ? LIMIT 1"
            ),
        };
        match self {
            Self::Sqlite(pool) => Ok(sqlx::query_as::<_, AccessTokenRecord>(sqlx::AssertSqlSafe(
                sql,
            ))
            .bind(token_id)
            .fetch_optional(pool)
            .await?),
            Self::MySql(pool) => Ok(sqlx::query_as::<_, AccessTokenRecord>(sqlx::AssertSqlSafe(
                sql,
            ))
            .bind(token_id)
            .fetch_optional(pool)
            .await?),
            Self::Postgres(pool) => Ok(sqlx::query_as::<_, AccessTokenRecord>(
                sqlx::AssertSqlSafe(sql),
            )
            .bind(token_id)
            .fetch_optional(pool)
            .await?),
        }
    }

    pub async fn user_profile(
        &self,
        prefix: &str,
        uid: i64,
    ) -> Result<Option<UserProfile>, sqlx::Error> {
        let sql = match self {
            Self::Sqlite(_) => format!(
                "SELECT CAST(uid AS BIGINT) AS uid, email, nickname, locale, CAST(score AS BIGINT) AS score, CAST(avatar AS BIGINT) AS avatar, permission, \
                 CAST(last_sign_at AS TEXT) AS last_sign_at, CAST(register_at AS TEXT) AS register_at, \
                 verified, is_dark_mode FROM {prefix}users WHERE uid = ? LIMIT 1"
            ),
            Self::MySql(_) => format!(
                "SELECT CAST(uid AS BIGINT) AS uid, email, nickname, locale, CAST(score AS BIGINT) AS score, CAST(avatar AS BIGINT) AS avatar, permission, \
                 DATE_FORMAT(last_sign_at, '%Y-%m-%d %H:%i:%s') AS last_sign_at, \
                 DATE_FORMAT(register_at, '%Y-%m-%d %H:%i:%s') AS register_at, \
                 verified, is_dark_mode FROM {prefix}users WHERE uid = ? LIMIT 1"
            ),
            Self::Postgres(_) => format!(
                "SELECT CAST(uid AS BIGINT) AS uid, email, nickname, locale, CAST(score AS BIGINT) AS score, CAST(avatar AS BIGINT) AS avatar, permission, \
                 to_char(last_sign_at, 'YYYY-MM-DD HH24:MI:SS') AS last_sign_at, \
                 to_char(register_at, 'YYYY-MM-DD HH24:MI:SS') AS register_at, \
                 verified, is_dark_mode FROM {prefix}users WHERE uid = $1 LIMIT 1"
            ),
        };
        match self {
            Self::Sqlite(pool) => Ok(sqlx::query_as::<_, UserProfile>(sqlx::AssertSqlSafe(sql))
                .bind(uid)
                .fetch_optional(pool)
                .await?),
            Self::MySql(pool) => Ok(sqlx::query_as::<_, UserProfile>(sqlx::AssertSqlSafe(sql))
                .bind(uid)
                .fetch_optional(pool)
                .await?),
            Self::Postgres(pool) => Ok(sqlx::query_as::<_, UserProfile>(sqlx::AssertSqlSafe(sql))
                .bind(uid)
                .fetch_optional(pool)
                .await?),
        }
    }
    pub async fn players_for_user(
        &self,
        prefix: &str,
        uid: i64,
    ) -> Result<Vec<PlayerRecord>, sqlx::Error> {
        let sql = match self {
            Self::Postgres(_) => format!(
                "SELECT CAST(pid AS BIGINT) AS pid, CAST(uid AS BIGINT) AS uid, name, \
                 CAST(tid_skin AS BIGINT) AS tid_skin, CAST(tid_cape AS BIGINT) AS tid_cape, \
                 to_char(last_modified, 'YYYY-MM-DD HH24:MI:SS') AS last_modified \
                 FROM {prefix}players WHERE CAST(uid AS BIGINT) = $1 ORDER BY pid"
            ),
            Self::MySql(_) => format!(
                "SELECT CAST(pid AS SIGNED) AS pid, CAST(uid AS SIGNED) AS uid, name, \
                 CAST(tid_skin AS SIGNED) AS tid_skin, CAST(tid_cape AS SIGNED) AS tid_cape, \
                 DATE_FORMAT(last_modified, '%Y-%m-%d %H:%i:%s') AS last_modified \
                 FROM {prefix}players WHERE uid = ? ORDER BY pid"
            ),
            Self::Sqlite(_) => format!(
                "SELECT CAST(pid AS BIGINT) AS pid, CAST(uid AS BIGINT) AS uid, name, \
                 CAST(tid_skin AS BIGINT) AS tid_skin, CAST(tid_cape AS BIGINT) AS tid_cape, \
                 CAST(last_modified AS TEXT) AS last_modified \
                 FROM {prefix}players WHERE uid = ? ORDER BY pid"
            ),
        };
        match self {
            Self::Sqlite(pool) => Ok(sqlx::query_as::<_, PlayerRecord>(sqlx::AssertSqlSafe(sql))
                .bind(uid)
                .fetch_all(pool)
                .await?),
            Self::MySql(pool) => Ok(sqlx::query_as::<_, PlayerRecord>(sqlx::AssertSqlSafe(sql))
                .bind(uid)
                .fetch_all(pool)
                .await?),
            Self::Postgres(pool) => Ok(sqlx::query_as::<_, PlayerRecord>(sqlx::AssertSqlSafe(sql))
                .bind(uid)
                .fetch_all(pool)
                .await?),
        }
    }
    pub async fn rename_player(
        &self,
        prefix: &str,
        user_id: i64,
        player_id: i64,
        new_name: &str,
    ) -> Result<PlayerRenameOutcome, sqlx::Error> {
        let select_sql = match self {
            Self::Postgres(_) => format!(
                "SELECT name, CAST(uid AS BIGINT) AS uid FROM {prefix}players WHERE pid = $1 LIMIT 1"
            ),
            _ => format!(
                "SELECT name, CAST(uid AS BIGINT) AS uid FROM {prefix}players WHERE pid = ? LIMIT 1"
            ),
        };
        let player_identity = match self {
            Self::Sqlite(pool) => {
                sqlx::query_as::<_, (String, i64)>(sqlx::AssertSqlSafe(select_sql))
                    .bind(player_id)
                    .fetch_optional(pool)
                    .await?
            }
            Self::MySql(pool) => {
                sqlx::query_as::<_, (String, i64)>(sqlx::AssertSqlSafe(select_sql))
                    .bind(player_id)
                    .fetch_optional(pool)
                    .await?
            }
            Self::Postgres(pool) => {
                sqlx::query_as::<_, (String, i64)>(sqlx::AssertSqlSafe(select_sql))
                    .bind(player_id)
                    .fetch_optional(pool)
                    .await?
            }
        };
        let Some((previous_name, owner_id)) = player_identity else {
            return Ok(PlayerRenameOutcome::NotFound);
        };
        if owner_id != user_id {
            return Ok(PlayerRenameOutcome::Forbidden);
        }

        let duplicate_sql = match self {
            Self::Postgres(_) => {
                format!("SELECT COUNT(*) FROM {prefix}players WHERE name = $1 AND pid <> $2")
            }
            _ => format!("SELECT COUNT(*) FROM {prefix}players WHERE name = ? AND pid <> ?"),
        };
        let duplicate_count = match self {
            Self::Sqlite(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(duplicate_sql))
                    .bind(new_name)
                    .bind(player_id)
                    .fetch_one(pool)
                    .await?
            }
            Self::MySql(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(duplicate_sql))
                    .bind(new_name)
                    .bind(player_id)
                    .fetch_one(pool)
                    .await?
            }
            Self::Postgres(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(duplicate_sql))
                    .bind(new_name)
                    .bind(player_id)
                    .fetch_one(pool)
                    .await?
            }
        };
        if duplicate_count > 0 {
            return Ok(PlayerRenameOutcome::NameExists);
        }

        let update_sql = match self {
            Self::Postgres(_) => format!(
                "UPDATE {prefix}players SET name = $1, last_modified = CURRENT_TIMESTAMP \
                 WHERE pid = $2 AND uid = $3"
            ),
            _ => format!(
                "UPDATE {prefix}players SET name = ?, last_modified = CURRENT_TIMESTAMP \
                 WHERE pid = ? AND uid = ?"
            ),
        };
        let updated_rows = match self {
            Self::Sqlite(pool) => sqlx::query(sqlx::AssertSqlSafe(update_sql))
                .bind(new_name)
                .bind(player_id)
                .bind(user_id)
                .execute(pool)
                .await?
                .rows_affected(),
            Self::MySql(pool) => sqlx::query(sqlx::AssertSqlSafe(update_sql))
                .bind(new_name)
                .bind(player_id)
                .bind(user_id)
                .execute(pool)
                .await?
                .rows_affected(),
            Self::Postgres(pool) => sqlx::query(sqlx::AssertSqlSafe(update_sql))
                .bind(new_name)
                .bind(player_id)
                .bind(user_id)
                .execute(pool)
                .await?
                .rows_affected(),
        };
        if updated_rows == 0 {
            return Ok(PlayerRenameOutcome::NotFound);
        }
        let player = self
            .players_for_user(prefix, user_id)
            .await?
            .into_iter()
            .find(|player| player.pid == player_id);
        Ok(match player {
            Some(player) => PlayerRenameOutcome::Renamed {
                previous_name,
                player,
            },
            None => PlayerRenameOutcome::NotFound,
        })
    }

    pub async fn set_player_textures(
        &self,
        prefix: &str,
        user_id: i64,
        player_id: i64,
        skin: Option<i64>,
        cape: Option<i64>,
    ) -> Result<PlayerTextureOutcome, sqlx::Error> {
        let Some(player) = self
            .players_for_user(prefix, user_id)
            .await?
            .into_iter()
            .find(|player| player.pid == player_id)
        else {
            return Ok(if self.player_exists(prefix, player_id).await? {
                PlayerTextureOutcome::Forbidden
            } else {
                PlayerTextureOutcome::NotFound
            });
        };

        for tid in [skin, cape].into_iter().flatten().filter(|tid| *tid != 0) {
            if !self.texture_exists(prefix, tid).await? {
                return Ok(PlayerTextureOutcome::TextureNotFound);
            }
            if !self.user_has_texture(prefix, user_id, tid).await? {
                return Ok(PlayerTextureOutcome::TextureNotInCloset);
            }
        }
        if let Some(tid) = skin.filter(|tid| *tid != 0) {
            self.update_player_texture(prefix, player_id, user_id, "tid_skin", tid)
                .await?;
        }
        if let Some(tid) = cape.filter(|tid| *tid != 0) {
            self.update_player_texture(prefix, player_id, user_id, "tid_cape", tid)
                .await?;
        }
        let updated = self
            .players_for_user(prefix, user_id)
            .await?
            .into_iter()
            .find(|item| item.pid == player_id)
            .unwrap_or(player);
        Ok(PlayerTextureOutcome::Updated(updated))
    }

    pub async fn clear_player_textures(
        &self,
        prefix: &str,
        user_id: i64,
        player_id: i64,
        skin: bool,
        cape: bool,
    ) -> Result<PlayerTextureOutcome, sqlx::Error> {
        let Some(player) = self
            .players_for_user(prefix, user_id)
            .await?
            .into_iter()
            .find(|player| player.pid == player_id)
        else {
            return Ok(if self.player_exists(prefix, player_id).await? {
                PlayerTextureOutcome::Forbidden
            } else {
                PlayerTextureOutcome::NotFound
            });
        };
        if skin {
            self.update_player_texture(prefix, player_id, user_id, "tid_skin", 0)
                .await?;
        }
        if cape {
            self.update_player_texture(prefix, player_id, user_id, "tid_cape", 0)
                .await?;
        }
        let updated = self
            .players_for_user(prefix, user_id)
            .await?
            .into_iter()
            .find(|item| item.pid == player_id)
            .unwrap_or(player);
        Ok(PlayerTextureOutcome::Updated(updated))
    }

    async fn player_exists(&self, prefix: &str, player_id: i64) -> Result<bool, sqlx::Error> {
        let sql = match self {
            Self::Postgres(_) => format!("SELECT COUNT(*) FROM {prefix}players WHERE pid = $1"),
            _ => format!("SELECT COUNT(*) FROM {prefix}players WHERE pid = ?"),
        };
        match self {
            Self::Sqlite(pool) => Ok(sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                .bind(player_id)
                .fetch_one(pool)
                .await?
                > 0),
            Self::MySql(pool) => Ok(sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                .bind(player_id)
                .fetch_one(pool)
                .await?
                > 0),
            Self::Postgres(pool) => Ok(sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                .bind(player_id)
                .fetch_one(pool)
                .await?
                > 0),
        }
    }

    async fn texture_exists(&self, prefix: &str, tid: i64) -> Result<bool, sqlx::Error> {
        let sql = match self {
            Self::Postgres(_) => format!("SELECT COUNT(*) FROM {prefix}textures WHERE tid = $1"),
            _ => format!("SELECT COUNT(*) FROM {prefix}textures WHERE tid = ?"),
        };
        match self {
            Self::Sqlite(pool) => Ok(sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                .bind(tid)
                .fetch_one(pool)
                .await?
                > 0),
            Self::MySql(pool) => Ok(sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                .bind(tid)
                .fetch_one(pool)
                .await?
                > 0),
            Self::Postgres(pool) => Ok(sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                .bind(tid)
                .fetch_one(pool)
                .await?
                > 0),
        }
    }

    async fn user_has_texture(
        &self,
        prefix: &str,
        user_id: i64,
        tid: i64,
    ) -> Result<bool, sqlx::Error> {
        let sql = match self {
            Self::Postgres(_) => format!(
                "SELECT COUNT(*) FROM {prefix}user_closet WHERE user_uid = $1 AND texture_tid = $2"
            ),
            _ => format!(
                "SELECT COUNT(*) FROM {prefix}user_closet WHERE user_uid = ? AND texture_tid = ?"
            ),
        };
        match self {
            Self::Sqlite(pool) => Ok(sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                .bind(user_id)
                .bind(tid)
                .fetch_one(pool)
                .await?
                > 0),
            Self::MySql(pool) => Ok(sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                .bind(user_id)
                .bind(tid)
                .fetch_one(pool)
                .await?
                > 0),
            Self::Postgres(pool) => Ok(sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                .bind(user_id)
                .bind(tid)
                .fetch_one(pool)
                .await?
                > 0),
        }
    }

    async fn update_player_texture(
        &self,
        prefix: &str,
        player_id: i64,
        user_id: i64,
        column: &str,
        tid: i64,
    ) -> Result<(), sqlx::Error> {
        let sql = match self {
            Self::Postgres(_) => format!(
                "UPDATE {prefix}players SET {column} = $1, last_modified = CURRENT_TIMESTAMP \
                 WHERE pid = $2 AND uid = $3"
            ),
            _ => format!(
                "UPDATE {prefix}players SET {column} = ?, last_modified = CURRENT_TIMESTAMP \
                 WHERE pid = ? AND uid = ?"
            ),
        };
        match self {
            Self::Sqlite(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(tid)
                    .bind(player_id)
                    .bind(user_id)
                    .execute(pool)
                    .await?;
            }
            Self::MySql(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(tid)
                    .bind(player_id)
                    .bind(user_id)
                    .execute(pool)
                    .await?;
            }
            Self::Postgres(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(tid)
                    .bind(player_id)
                    .bind(user_id)
                    .execute(pool)
                    .await?;
            }
        }
        Ok(())
    }

    pub async fn unread_notifications(
        &self,
        prefix: &str,
        user_id: i64,
    ) -> Result<Vec<NotificationRecord>, sqlx::Error> {
        let sql = match self {
            Self::Postgres(_) => format!(
                "SELECT id, data, to_char(created_at, 'YYYY-MM-DD HH24:MI:SS') AS created_at \
                 FROM {prefix}notifications WHERE notifiable_type = $1 AND notifiable_id = $2 \
                 AND read_at IS NULL ORDER BY created_at DESC"
            ),
            Self::MySql(_) => format!(
                "SELECT id, data, DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') AS created_at \
                 FROM {prefix}notifications WHERE notifiable_type = ? AND notifiable_id = ? \
                 AND read_at IS NULL ORDER BY created_at DESC"
            ),
            Self::Sqlite(_) => format!(
                "SELECT id, data, CAST(created_at AS TEXT) AS created_at \
                 FROM {prefix}notifications WHERE notifiable_type = ? AND notifiable_id = ? \
                 AND read_at IS NULL ORDER BY created_at DESC"
            ),
        };
        match self {
            Self::Sqlite(pool) => {
                sqlx::query_as::<_, NotificationRecord>(sqlx::AssertSqlSafe(sql))
                    .bind("App\\Models\\User")
                    .bind(user_id)
                    .fetch_all(pool)
                    .await
            }
            Self::MySql(pool) => {
                sqlx::query_as::<_, NotificationRecord>(sqlx::AssertSqlSafe(sql))
                    .bind("App\\Models\\User")
                    .bind(user_id)
                    .fetch_all(pool)
                    .await
            }
            Self::Postgres(pool) => {
                sqlx::query_as::<_, NotificationRecord>(sqlx::AssertSqlSafe(sql))
                    .bind("App\\Models\\User")
                    .bind(user_id)
                    .fetch_all(pool)
                    .await
            }
        }
    }

    pub async fn read_notification(
        &self,
        prefix: &str,
        user_id: i64,
        id: &str,
    ) -> Result<Option<NotificationRecord>, sqlx::Error> {
        let select_sql = match self {
            Self::Postgres(_) => format!(
                "SELECT id, data, to_char(created_at, 'YYYY-MM-DD HH24:MI:SS') AS created_at \
                 FROM {prefix}notifications WHERE id = $1 AND notifiable_type = $2 \
                 AND notifiable_id = $3 AND read_at IS NULL LIMIT 1"
            ),
            Self::MySql(_) => format!(
                "SELECT id, data, DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') AS created_at \
                 FROM {prefix}notifications WHERE id = ? AND notifiable_type = ? \
                 AND notifiable_id = ? AND read_at IS NULL LIMIT 1"
            ),
            Self::Sqlite(_) => format!(
                "SELECT id, data, CAST(created_at AS TEXT) AS created_at \
                 FROM {prefix}notifications WHERE id = ? AND notifiable_type = ? \
                 AND notifiable_id = ? AND read_at IS NULL LIMIT 1"
            ),
        };
        let notification = match self {
            Self::Sqlite(pool) => {
                sqlx::query_as::<_, NotificationRecord>(sqlx::AssertSqlSafe(select_sql))
                    .bind(id)
                    .bind("App\\Models\\User")
                    .bind(user_id)
                    .fetch_optional(pool)
                    .await?
            }
            Self::MySql(pool) => {
                sqlx::query_as::<_, NotificationRecord>(sqlx::AssertSqlSafe(select_sql))
                    .bind(id)
                    .bind("App\\Models\\User")
                    .bind(user_id)
                    .fetch_optional(pool)
                    .await?
            }
            Self::Postgres(pool) => {
                sqlx::query_as::<_, NotificationRecord>(sqlx::AssertSqlSafe(select_sql))
                    .bind(id)
                    .bind("App\\Models\\User")
                    .bind(user_id)
                    .fetch_optional(pool)
                    .await?
            }
        };
        let Some(notification) = notification else {
            return Ok(None);
        };

        let update_sql = match self {
            Self::Postgres(_) => format!(
                "UPDATE {prefix}notifications SET read_at = CURRENT_TIMESTAMP \
                 WHERE id = $1 AND notifiable_type = $2 AND notifiable_id = $3 AND read_at IS NULL"
            ),
            _ => format!(
                "UPDATE {prefix}notifications SET read_at = CURRENT_TIMESTAMP \
                 WHERE id = ? AND notifiable_type = ? AND notifiable_id = ? AND read_at IS NULL"
            ),
        };
        let updated_rows = match self {
            Self::Sqlite(pool) => sqlx::query(sqlx::AssertSqlSafe(update_sql))
                .bind(id)
                .bind("App\\Models\\User")
                .bind(user_id)
                .execute(pool)
                .await?
                .rows_affected(),
            Self::MySql(pool) => sqlx::query(sqlx::AssertSqlSafe(update_sql))
                .bind(id)
                .bind("App\\Models\\User")
                .bind(user_id)
                .execute(pool)
                .await?
                .rows_affected(),
            Self::Postgres(pool) => sqlx::query(sqlx::AssertSqlSafe(update_sql))
                .bind(id)
                .bind("App\\Models\\User")
                .bind(user_id)
                .execute(pool)
                .await?
                .rows_affected(),
        };
        Ok((updated_rows > 0).then_some(notification))
    }

    pub async fn credentials_by_email(
        &self,
        prefix: &str,
        email: &str,
    ) -> Result<Option<PasswordCredential>, sqlx::Error> {
        self.password_credential(prefix, email, true).await
    }

    pub async fn credentials_by_player_name(
        &self,
        prefix: &str,
        player_name: &str,
    ) -> Result<Option<PasswordCredential>, sqlx::Error> {
        self.password_credential(prefix, player_name, false).await
    }

    async fn password_credential(
        &self,
        prefix: &str,
        identifier: &str,
        is_email: bool,
    ) -> Result<Option<PasswordCredential>, sqlx::Error> {
        let sql = match (self, is_email) {
            (Self::Postgres(_), true) => format!(
                "SELECT CAST(uid AS BIGINT) AS uid, password, permission FROM {prefix}users WHERE email = $1 LIMIT 1"
            ),
            (Self::Postgres(_), false) => format!(
                "SELECT CAST(u.uid AS BIGINT) AS uid, u.password, u.permission FROM {prefix}players p INNER JOIN {prefix}users u ON u.uid = p.uid WHERE p.name = $1 LIMIT 1"
            ),
            (_, true) => format!(
                "SELECT CAST(uid AS BIGINT) AS uid, password, permission FROM {prefix}users WHERE email = ? LIMIT 1"
            ),
            (_, false) => format!(
                "SELECT CAST(u.uid AS BIGINT) AS uid, u.password, u.permission FROM {prefix}players p INNER JOIN {prefix}users u ON u.uid = p.uid WHERE p.name = ? LIMIT 1"
            ),
        };
        match self {
            Self::Sqlite(pool) => Ok(sqlx::query_as::<_, PasswordCredential>(sqlx::AssertSqlSafe(
                sql,
            ))
            .bind(identifier)
            .fetch_optional(pool)
            .await?),
            Self::MySql(pool) => Ok(sqlx::query_as::<_, PasswordCredential>(sqlx::AssertSqlSafe(
                sql,
            ))
            .bind(identifier)
            .fetch_optional(pool)
            .await?),
            Self::Postgres(pool) => Ok(sqlx::query_as::<_, PasswordCredential>(
                sqlx::AssertSqlSafe(sql),
            )
            .bind(identifier)
            .fetch_optional(pool)
            .await?),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::DatabasePool;
    use sqlx::sqlite::SqlitePoolOptions;

    #[tokio::test]
    async fn reads_profiles_and_options_from_legacy_tables() {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query("CREATE TABLE bs_users (uid INTEGER PRIMARY KEY, email TEXT NOT NULL DEFAULT '', nickname TEXT NOT NULL DEFAULT '', locale TEXT, score INTEGER NOT NULL DEFAULT 0, avatar INTEGER NOT NULL DEFAULT 0, password TEXT NOT NULL DEFAULT '', ip TEXT NOT NULL DEFAULT '', permission INTEGER NOT NULL, last_sign_at TEXT NOT NULL DEFAULT '', register_at TEXT NOT NULL DEFAULT '', verified BOOLEAN NOT NULL DEFAULT 0, is_dark_mode BOOLEAN NOT NULL DEFAULT 0)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE bs_players (pid INTEGER PRIMARY KEY, uid INTEGER NOT NULL, name TEXT NOT NULL, tid_skin INTEGER, tid_cape INTEGER, last_modified TEXT)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE bs_textures (tid INTEGER PRIMARY KEY, type TEXT NOT NULL, hash TEXT NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE bs_user_closet (user_uid INTEGER NOT NULL, texture_tid INTEGER NOT NULL, item_name TEXT NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE bs_options (id INTEGER PRIMARY KEY, option_name TEXT NOT NULL, option_value TEXT NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE bs_notifications (id TEXT PRIMARY KEY, type TEXT NOT NULL, notifiable_type TEXT NOT NULL, notifiable_id INTEGER NOT NULL, data TEXT NOT NULL, read_at TEXT, created_at TEXT NOT NULL, updated_at TEXT NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE bs_oauth_access_tokens (id TEXT PRIMARY KEY, user_id INTEGER, client_id INTEGER NOT NULL, scopes TEXT NOT NULL, revoked BOOLEAN NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO bs_oauth_access_tokens (id, user_id, client_id, scopes, revoked) VALUES ('legacy-token-id', 7, 3, 'User.Read', 0)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO bs_users (uid, email, nickname, locale, score, avatar, permission, last_sign_at, register_at, verified, is_dark_mode) VALUES (7, 'alex@example.test', 'Alex User', 'zh_CN', 42, 11, 0, '2026-10-01 10:00:00', '2025-01-02 03:04:05', 1, 0)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO bs_players (pid, uid, name, tid_skin, tid_cape, last_modified) VALUES (3, 7, 'Alex', 11, 12, '2026-10-02 12:00:00'), (4, 8, 'Other', 0, 0, '2026-10-02 13:00:00')")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO bs_textures (tid, type, hash) VALUES (11, 'alex', 'skin-hash'), (12, 'cape', 'cape-hash'), (13, 'alex', 'not-in-closet')")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO bs_user_closet (user_uid, texture_tid, item_name) VALUES (7, 11, 'Alex skin'), (7, 12, 'Alex cape')")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO bs_options (id, option_name, option_value) VALUES (1, 'site_name', 'Legacy Instance')")
            .execute(&pool)
            .await
            .unwrap();

        let notice_type = "App\\Models\\Notifications\\SiteMessage";
        let notifiable_type = "App\\Models\\User";
        for (id, uid, read_at) in [
            ("notice-unread", 7_i64, None),
            ("notice-other-user", 8_i64, None),
            ("notice-read", 7_i64, Some("2026-10-01 11:00:00")),
        ] {
            sqlx::query("INSERT INTO bs_notifications (id,type,notifiable_type,notifiable_id,data,read_at,created_at,updated_at) VALUES (?,?,?, ?, ?, ?, '2026-10-01 10:00:00', '2026-10-01 10:00:00')")
                .bind(id)
                .bind(notice_type)
                .bind(notifiable_type)
                .bind(uid)
                .bind(r#"{"title":"Site notice","content":"Hello **skin**"}"#)
                .bind(read_at)
                .execute(&pool)
                .await
                .unwrap();
        }
        let database = DatabasePool::Sqlite(pool);
        let profile = database
            .player_profile("bs_", "Alex")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(profile.name, "Alex");
        let players = database.players_for_user("bs_", 7).await.unwrap();
        assert_eq!(players.len(), 1);
        assert_eq!(players[0].pid, 3);
        assert_eq!(players[0].uid, 7);
        assert_eq!(players[0].name, "Alex");
        assert_eq!(players[0].tid_skin, 11);
        assert_eq!(players[0].tid_cape, 12);
        assert_eq!(players[0].last_modified, "2026-10-02 12:00:00");
        let unread = database.unread_notifications("bs_", 7).await.unwrap();
        assert_eq!(unread.len(), 1);
        assert_eq!(unread[0].id, "notice-unread");
        let marked_read = database
            .read_notification("bs_", 7, "notice-unread")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            marked_read.data,
            r#"{"title":"Site notice","content":"Hello **skin**"}"#
        );
        assert!(
            database
                .unread_notifications("bs_", 7)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            database
                .read_notification("bs_", 8, "notice-unread")
                .await
                .unwrap()
                .is_none()
        );
        let email_credential = database
            .credentials_by_email("bs_", "alex@example.test")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(email_credential.uid, 7);
        assert_eq!(email_credential.permission, 0);
        let player_credential = database
            .credentials_by_player_name("bs_", "Alex")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(player_credential.uid, 7);
        let renamed = database
            .rename_player("bs_", 7, 3, "Alex_New")
            .await
            .unwrap();
        match renamed {
            super::PlayerRenameOutcome::Renamed {
                previous_name,
                player,
            } => {
                assert_eq!(previous_name, "Alex");
                assert_eq!(player.name, "Alex_New");
                assert_eq!(player.uid, 7);
            }
            result => panic!("expected a rename, got {result:?}"),
        }
        assert!(matches!(
            database.rename_player("bs_", 7, 3, "Other").await.unwrap(),
            super::PlayerRenameOutcome::NameExists
        ));
        assert!(matches!(
            database
                .rename_player("bs_", 8, 3, "NoAccess")
                .await
                .unwrap(),
            super::PlayerRenameOutcome::Forbidden
        ));
        let textures_set = database
            .set_player_textures("bs_", 7, 3, Some(11), Some(12))
            .await
            .unwrap();
        match textures_set {
            super::PlayerTextureOutcome::Updated(player) => {
                assert_eq!(player.tid_skin, 11);
                assert_eq!(player.tid_cape, 12);
            }
            result => panic!("expected texture update, got {result:?}"),
        }
        assert!(matches!(
            database
                .set_player_textures("bs_", 7, 3, Some(99), None)
                .await
                .unwrap(),
            super::PlayerTextureOutcome::TextureNotFound
        ));
        assert!(matches!(
            database
                .set_player_textures("bs_", 7, 3, Some(13), None)
                .await
                .unwrap(),
            super::PlayerTextureOutcome::TextureNotInCloset
        ));
        assert!(matches!(
            database
                .set_player_textures("bs_", 8, 3, Some(11), None)
                .await
                .unwrap(),
            super::PlayerTextureOutcome::Forbidden
        ));
        assert!(matches!(
            database
                .set_player_textures("bs_", 7, 99, Some(11), None)
                .await
                .unwrap(),
            super::PlayerTextureOutcome::NotFound
        ));
        let textures_cleared = database
            .clear_player_textures("bs_", 7, 3, true, false)
            .await
            .unwrap();
        match textures_cleared {
            super::PlayerTextureOutcome::Updated(player) => {
                assert_eq!(player.tid_skin, 0);
                assert_eq!(player.tid_cape, 12);
            }
            result => panic!("expected texture clear, got {result:?}"),
        }
        let user = database.user_profile("bs_", 7).await.unwrap().unwrap();
        assert_eq!(user.email, "alex@example.test");
        assert_eq!(user.nickname, "Alex User");
        assert_eq!(user.locale.as_deref(), Some("zh_CN"));
        assert_eq!(user.score, 42);
        assert_eq!(user.avatar, 11);
        assert!(user.verified);
        assert!(!user.is_dark_mode);
        let token = database
            .access_token("bs_", "legacy-token-id")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(token.user_id, Some(7));
        assert_eq!(token.client_id, 3);
        assert!(!token.revoked);
        assert_eq!(profile.permission, 0);
        assert_eq!(profile.skin_type.as_deref(), Some("alex"));
        assert_eq!(profile.skin_hash.as_deref(), Some("skin-hash"));
        assert_eq!(profile.cape_hash.as_deref(), Some("cape-hash"));
        assert_eq!(
            profile.last_modified.as_deref(),
            Some("2026-10-02 12:00:00")
        );
        assert_eq!(
            database
                .option("bs_", "site_name")
                .await
                .unwrap()
                .as_deref(),
            Some("Legacy Instance")
        );
        assert_eq!(
            database.texture_hash("bs_", 12).await.unwrap().as_deref(),
            Some("cape-hash")
        );
    }
}
