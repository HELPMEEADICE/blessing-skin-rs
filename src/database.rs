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
#[derive(Debug)]
pub enum NotificationAudience {
    All,
    Normal,
    User(i64),
    Email(String),
}
#[derive(Debug, FromRow)]
pub struct NotificationRecord {
    pub id: String,
    pub data: String,
    pub created_at: String,
}
#[derive(Debug, FromRow)]
pub struct SkinLibraryRecord {
    pub tid: i64,
    pub name: String,
    pub texture_type: String,
    pub uploader: i64,
    pub is_public: bool,
    pub likes: i64,
    pub nickname: String,
}
#[derive(Debug, FromRow)]
pub struct TextureInfoRecord {
    pub tid: i64,
    pub name: String,
    pub texture_type: String,
    pub hash: String,
    pub size: i64,
    pub uploader: i64,
    pub is_public: bool,
    pub upload_at: String,
    pub likes: i64,
}
#[derive(Debug, FromRow)]
pub struct ClosetTextureRecord {
    pub tid: i64,
    pub name: String,
    pub texture_type: String,
    pub hash: String,
    pub size: i64,
    pub uploader: i64,
    pub is_public: bool,
    pub upload_at: String,
    pub likes: i64,
    pub user_uid: i64,
    pub texture_tid: i64,
    pub item_name: Option<String>,
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
pub enum ClosetAddOutcome {
    Added,
    NameExists,
    InsufficientScore,
    TextureNotFound,
    PrivateTexture,
}
#[derive(Debug)]
pub enum ClosetRenameOutcome {
    Renamed,
    NotInCloset,
}
#[derive(Debug)]
pub enum ClosetRemoveOutcome {
    Removed,
    NotInCloset,
}
#[derive(Debug)]
pub enum PlayerAddOutcome {
    NameExists,
    InsufficientScore,
    Added(PlayerRecord),
}
#[derive(Debug)]
pub enum PlayerDeleteOutcome {
    NotFound,
    Forbidden,
    Deleted(String),
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
    pub async fn rename_texture(
        &self,
        prefix: &str,
        tid: i64,
        name: &str,
    ) -> Result<(), sqlx::Error> {
        let sql = match self {
            Self::Postgres(_) => {
                format!("UPDATE {prefix}textures SET name = $1 WHERE tid = $2")
            }
            _ => format!("UPDATE {prefix}textures SET name = ? WHERE tid = ?"),
        };
        match self {
            Self::Sqlite(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(name)
                    .bind(tid)
                    .execute(pool)
                    .await?;
            }
            Self::MySql(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(name)
                    .bind(tid)
                    .execute(pool)
                    .await?;
            }
            Self::Postgres(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(name)
                    .bind(tid)
                    .execute(pool)
                    .await?;
            }
        }
        Ok(())
    }
    pub async fn texture_info(
        &self,
        prefix: &str,
        tid: i64,
    ) -> Result<Option<TextureInfoRecord>, sqlx::Error> {
        let sql = match self {
            Self::Postgres(_) => format!(
                "SELECT CAST(tid AS BIGINT) AS tid, name, type AS texture_type, hash, \
                 CAST(size AS BIGINT) AS size, CAST(uploader AS BIGINT) AS uploader, \
                 public AS is_public, TO_CHAR(upload_at, 'YYYY-MM-DD HH24:MI:SS') AS upload_at, \
                 CAST(likes AS BIGINT) AS likes FROM {prefix}textures WHERE tid = $1 LIMIT 1"
            ),
            Self::MySql(_) => format!(
                "SELECT CAST(tid AS SIGNED) AS tid, name, type AS texture_type, hash, \
                 CAST(size AS SIGNED) AS size, CAST(uploader AS SIGNED) AS uploader, \
                 public AS is_public, DATE_FORMAT(upload_at, '%Y-%m-%d %H:%i:%s') AS upload_at, \
                 CAST(likes AS SIGNED) AS likes FROM {prefix}textures WHERE tid = ? LIMIT 1"
            ),
            Self::Sqlite(_) => format!(
                "SELECT CAST(tid AS BIGINT) AS tid, name, type AS texture_type, hash, \
                 CAST(size AS BIGINT) AS size, CAST(uploader AS BIGINT) AS uploader, \
                 public AS is_public, CAST(upload_at AS TEXT) AS upload_at, \
                 CAST(likes AS BIGINT) AS likes FROM {prefix}textures WHERE tid = ? LIMIT 1"
            ),
        };
        match self {
            Self::Sqlite(pool) => Ok(sqlx::query_as::<_, TextureInfoRecord>(sqlx::AssertSqlSafe(
                sql,
            ))
            .bind(tid)
            .fetch_optional(pool)
            .await?),
            Self::MySql(pool) => Ok(sqlx::query_as::<_, TextureInfoRecord>(sqlx::AssertSqlSafe(
                sql,
            ))
            .bind(tid)
            .fetch_optional(pool)
            .await?),
            Self::Postgres(pool) => Ok(sqlx::query_as::<_, TextureInfoRecord>(
                sqlx::AssertSqlSafe(sql),
            )
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

    pub async fn add_closet_item(
        &self,
        prefix: &str,
        user_id: i64,
        tid: i64,
        name: &str,
        score_cost: i64,
        is_admin: bool,
        score_award_per_like: i64,
    ) -> Result<ClosetAddOutcome, sqlx::Error> {
        let score_sql = match self {
            Self::Postgres(_) => {
                format!("SELECT CAST(score AS BIGINT) FROM {prefix}users WHERE uid = $1")
            }
            Self::MySql(_) => {
                format!("SELECT CAST(score AS SIGNED) FROM {prefix}users WHERE uid = ?")
            }
            Self::Sqlite(_) => {
                format!("SELECT CAST(score AS BIGINT) FROM {prefix}users WHERE uid = ?")
            }
        };
        let score = match self {
            Self::Sqlite(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(score_sql))
                    .bind(user_id)
                    .fetch_optional(pool)
                    .await?
            }
            Self::MySql(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(score_sql))
                    .bind(user_id)
                    .fetch_optional(pool)
                    .await?
            }
            Self::Postgres(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(score_sql))
                    .bind(user_id)
                    .fetch_optional(pool)
                    .await?
            }
        };
        if score.is_none_or(|score| score < score_cost) {
            return Ok(ClosetAddOutcome::InsufficientScore);
        }

        let texture_sql = match self {
            Self::Postgres(_) => format!(
                "SELECT public, CAST(uploader AS BIGINT) FROM {prefix}textures WHERE tid = $1"
            ),
            Self::MySql(_) => format!(
                "SELECT public, CAST(uploader AS SIGNED) FROM {prefix}textures WHERE tid = ?"
            ),
            Self::Sqlite(_) => format!(
                "SELECT public, CAST(uploader AS BIGINT) FROM {prefix}textures WHERE tid = ?"
            ),
        };
        let texture = match self {
            Self::Sqlite(pool) => {
                sqlx::query_as::<_, (bool, i64)>(sqlx::AssertSqlSafe(texture_sql))
                    .bind(tid)
                    .fetch_optional(pool)
                    .await?
            }
            Self::MySql(pool) => {
                sqlx::query_as::<_, (bool, i64)>(sqlx::AssertSqlSafe(texture_sql))
                    .bind(tid)
                    .fetch_optional(pool)
                    .await?
            }
            Self::Postgres(pool) => {
                sqlx::query_as::<_, (bool, i64)>(sqlx::AssertSqlSafe(texture_sql))
                    .bind(tid)
                    .fetch_optional(pool)
                    .await?
            }
        };
        let Some((is_public, uploader_id)) = texture else {
            return Ok(ClosetAddOutcome::TextureNotFound);
        };
        if !is_public && uploader_id != user_id && !is_admin {
            return Ok(ClosetAddOutcome::PrivateTexture);
        }

        let duplicate_sql = match self {
            Self::Postgres(_) => format!(
                "SELECT COUNT(*) FROM {prefix}user_closet WHERE user_uid = $1 AND texture_tid = $2"
            ),
            _ => format!(
                "SELECT COUNT(*) FROM {prefix}user_closet WHERE user_uid = ? AND texture_tid = ?"
            ),
        };
        let duplicate_count = match self {
            Self::Sqlite(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(duplicate_sql))
                    .bind(user_id)
                    .bind(tid)
                    .fetch_one(pool)
                    .await?
            }
            Self::MySql(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(duplicate_sql))
                    .bind(user_id)
                    .bind(tid)
                    .fetch_one(pool)
                    .await?
            }
            Self::Postgres(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(duplicate_sql))
                    .bind(user_id)
                    .bind(tid)
                    .fetch_one(pool)
                    .await?
            }
        };
        if duplicate_count > 0 {
            return Ok(ClosetAddOutcome::NameExists);
        }

        let insert_sql = match self {
            Self::Postgres(_) => format!(
                "INSERT INTO {prefix}user_closet (user_uid, texture_tid, item_name) VALUES ($1, $2, $3)"
            ),
            _ => format!(
                "INSERT INTO {prefix}user_closet (user_uid, texture_tid, item_name) VALUES (?, ?, ?)"
            ),
        };
        match self {
            Self::Sqlite(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(insert_sql))
                    .bind(user_id)
                    .bind(tid)
                    .bind(name)
                    .execute(pool)
                    .await?;
            }
            Self::MySql(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(insert_sql))
                    .bind(user_id)
                    .bind(tid)
                    .bind(name)
                    .execute(pool)
                    .await?;
            }
            Self::Postgres(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(insert_sql))
                    .bind(user_id)
                    .bind(tid)
                    .bind(name)
                    .execute(pool)
                    .await?;
            }
        }

        if score_cost != 0 {
            let update_sql = match self {
                Self::Postgres(_) => format!(
                    "UPDATE {prefix}users SET score = score - $1 WHERE uid = $2 AND score >= $3"
                ),
                _ => format!(
                    "UPDATE {prefix}users SET score = score - ? WHERE uid = ? AND score >= ?"
                ),
            };
            let updated = match self {
                Self::Sqlite(pool) => sqlx::query(sqlx::AssertSqlSafe(update_sql))
                    .bind(score_cost)
                    .bind(user_id)
                    .bind(score_cost)
                    .execute(pool)
                    .await?
                    .rows_affected(),
                Self::MySql(pool) => sqlx::query(sqlx::AssertSqlSafe(update_sql))
                    .bind(score_cost)
                    .bind(user_id)
                    .bind(score_cost)
                    .execute(pool)
                    .await?
                    .rows_affected(),
                Self::Postgres(pool) => sqlx::query(sqlx::AssertSqlSafe(update_sql))
                    .bind(score_cost)
                    .bind(user_id)
                    .bind(score_cost)
                    .execute(pool)
                    .await?
                    .rows_affected(),
            };
            if updated == 0 {
                let delete_sql = match self {
                    Self::Postgres(_) => format!(
                        "DELETE FROM {prefix}user_closet WHERE user_uid = $1 AND texture_tid = $2"
                    ),
                    _ => format!(
                        "DELETE FROM {prefix}user_closet WHERE user_uid = ? AND texture_tid = ?"
                    ),
                };
                match self {
                    Self::Sqlite(pool) => {
                        sqlx::query(sqlx::AssertSqlSafe(delete_sql))
                            .bind(user_id)
                            .bind(tid)
                            .execute(pool)
                            .await?;
                    }
                    Self::MySql(pool) => {
                        sqlx::query(sqlx::AssertSqlSafe(delete_sql))
                            .bind(user_id)
                            .bind(tid)
                            .execute(pool)
                            .await?;
                    }
                    Self::Postgres(pool) => {
                        sqlx::query(sqlx::AssertSqlSafe(delete_sql))
                            .bind(user_id)
                            .bind(tid)
                            .execute(pool)
                            .await?;
                    }
                }
                return Ok(ClosetAddOutcome::InsufficientScore);
            }
        }

        let likes_sql = format!(
            "UPDATE {prefix}textures SET likes = likes + 1 WHERE tid = {}",
            if matches!(self, Self::Postgres(_)) {
                "$1"
            } else {
                "?"
            }
        );
        match self {
            Self::Sqlite(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(likes_sql))
                    .bind(tid)
                    .execute(pool)
                    .await?;
            }
            Self::MySql(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(likes_sql))
                    .bind(tid)
                    .execute(pool)
                    .await?;
            }
            Self::Postgres(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(likes_sql))
                    .bind(tid)
                    .execute(pool)
                    .await?;
            }
        }
        if uploader_id != user_id && score_award_per_like != 0 {
            let award_sql = match self {
                Self::Postgres(_) => {
                    format!("UPDATE {prefix}users SET score = score + $1 WHERE uid = $2")
                }
                _ => format!("UPDATE {prefix}users SET score = score + ? WHERE uid = ?"),
            };
            match self {
                Self::Sqlite(pool) => {
                    sqlx::query(sqlx::AssertSqlSafe(award_sql))
                        .bind(score_award_per_like)
                        .bind(uploader_id)
                        .execute(pool)
                        .await?;
                }
                Self::MySql(pool) => {
                    sqlx::query(sqlx::AssertSqlSafe(award_sql))
                        .bind(score_award_per_like)
                        .bind(uploader_id)
                        .execute(pool)
                        .await?;
                }
                Self::Postgres(pool) => {
                    sqlx::query(sqlx::AssertSqlSafe(award_sql))
                        .bind(score_award_per_like)
                        .bind(uploader_id)
                        .execute(pool)
                        .await?;
                }
            }
        }
        Ok(ClosetAddOutcome::Added)
    }

    pub async fn rename_closet_item(
        &self,
        prefix: &str,
        user_id: i64,
        tid: i64,
        name: &str,
    ) -> Result<ClosetRenameOutcome, sqlx::Error> {
        let exists_sql = match self {
            Self::Postgres(_) => format!(
                "SELECT COUNT(*) FROM {prefix}user_closet WHERE user_uid = $1 AND texture_tid = $2"
            ),
            _ => format!(
                "SELECT COUNT(*) FROM {prefix}user_closet WHERE user_uid = ? AND texture_tid = ?"
            ),
        };
        let exists = match self {
            Self::Sqlite(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(exists_sql))
                    .bind(user_id)
                    .bind(tid)
                    .fetch_one(pool)
                    .await?
            }
            Self::MySql(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(exists_sql))
                    .bind(user_id)
                    .bind(tid)
                    .fetch_one(pool)
                    .await?
            }
            Self::Postgres(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(exists_sql))
                    .bind(user_id)
                    .bind(tid)
                    .fetch_one(pool)
                    .await?
            }
        };
        if exists == 0 {
            return Ok(ClosetRenameOutcome::NotInCloset);
        }
        let update_sql = match self {
            Self::Postgres(_) => format!(
                "UPDATE {prefix}user_closet SET item_name = $1 WHERE user_uid = $2 AND texture_tid = $3"
            ),
            _ => format!(
                "UPDATE {prefix}user_closet SET item_name = ? WHERE user_uid = ? AND texture_tid = ?"
            ),
        };
        match self {
            Self::Sqlite(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(update_sql))
                    .bind(name)
                    .bind(user_id)
                    .bind(tid)
                    .execute(pool)
                    .await?;
            }
            Self::MySql(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(update_sql))
                    .bind(name)
                    .bind(user_id)
                    .bind(tid)
                    .execute(pool)
                    .await?;
            }
            Self::Postgres(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(update_sql))
                    .bind(name)
                    .bind(user_id)
                    .bind(tid)
                    .execute(pool)
                    .await?;
            }
        }
        Ok(ClosetRenameOutcome::Renamed)
    }

    pub async fn remove_closet_item(
        &self,
        prefix: &str,
        user_id: i64,
        tid: i64,
        return_score: bool,
        score_refund: i64,
        score_award_per_like: i64,
    ) -> Result<ClosetRemoveOutcome, sqlx::Error> {
        let exists_sql = match self {
            Self::Postgres(_) => format!(
                "SELECT COUNT(*) FROM {prefix}user_closet WHERE user_uid = $1 AND texture_tid = $2"
            ),
            _ => format!(
                "SELECT COUNT(*) FROM {prefix}user_closet WHERE user_uid = ? AND texture_tid = ?"
            ),
        };
        let exists = match self {
            Self::Sqlite(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(exists_sql))
                    .bind(user_id)
                    .bind(tid)
                    .fetch_one(pool)
                    .await?
            }
            Self::MySql(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(exists_sql))
                    .bind(user_id)
                    .bind(tid)
                    .fetch_one(pool)
                    .await?
            }
            Self::Postgres(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(exists_sql))
                    .bind(user_id)
                    .bind(tid)
                    .fetch_one(pool)
                    .await?
            }
        };
        if exists == 0 {
            return Ok(ClosetRemoveOutcome::NotInCloset);
        }
        let texture_sql = match self {
            Self::Postgres(_) => {
                format!("SELECT CAST(uploader AS BIGINT) FROM {prefix}textures WHERE tid = $1")
            }
            Self::MySql(_) => {
                format!("SELECT CAST(uploader AS SIGNED) FROM {prefix}textures WHERE tid = ?")
            }
            Self::Sqlite(_) => {
                format!("SELECT CAST(uploader AS BIGINT) FROM {prefix}textures WHERE tid = ?")
            }
        };
        let uploader_id = match self {
            Self::Sqlite(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(texture_sql))
                    .bind(tid)
                    .fetch_optional(pool)
                    .await?
            }
            Self::MySql(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(texture_sql))
                    .bind(tid)
                    .fetch_optional(pool)
                    .await?
            }
            Self::Postgres(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(texture_sql))
                    .bind(tid)
                    .fetch_optional(pool)
                    .await?
            }
        };
        let Some(uploader_id) = uploader_id else {
            return Ok(ClosetRemoveOutcome::NotInCloset);
        };
        let delete_sql = match self {
            Self::Postgres(_) => {
                format!("DELETE FROM {prefix}user_closet WHERE user_uid = $1 AND texture_tid = $2")
            }
            _ => format!("DELETE FROM {prefix}user_closet WHERE user_uid = ? AND texture_tid = ?"),
        };
        match self {
            Self::Sqlite(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(delete_sql))
                    .bind(user_id)
                    .bind(tid)
                    .execute(pool)
                    .await?;
            }
            Self::MySql(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(delete_sql))
                    .bind(user_id)
                    .bind(tid)
                    .execute(pool)
                    .await?;
            }
            Self::Postgres(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(delete_sql))
                    .bind(user_id)
                    .bind(tid)
                    .execute(pool)
                    .await?;
            }
        }
        if return_score && score_refund != 0 {
            let refund_sql = match self {
                Self::Postgres(_) => {
                    format!("UPDATE {prefix}users SET score = score + $1 WHERE uid = $2")
                }
                _ => format!("UPDATE {prefix}users SET score = score + ? WHERE uid = ?"),
            };
            match self {
                Self::Sqlite(pool) => {
                    sqlx::query(sqlx::AssertSqlSafe(refund_sql))
                        .bind(score_refund)
                        .bind(user_id)
                        .execute(pool)
                        .await?;
                }
                Self::MySql(pool) => {
                    sqlx::query(sqlx::AssertSqlSafe(refund_sql))
                        .bind(score_refund)
                        .bind(user_id)
                        .execute(pool)
                        .await?;
                }
                Self::Postgres(pool) => {
                    sqlx::query(sqlx::AssertSqlSafe(refund_sql))
                        .bind(score_refund)
                        .bind(user_id)
                        .execute(pool)
                        .await?;
                }
            }
        }
        let likes_sql = format!(
            "UPDATE {prefix}textures SET likes = likes - 1 WHERE tid = {}",
            if matches!(self, Self::Postgres(_)) {
                "$1"
            } else {
                "?"
            }
        );
        match self {
            Self::Sqlite(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(likes_sql))
                    .bind(tid)
                    .execute(pool)
                    .await?;
            }
            Self::MySql(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(likes_sql))
                    .bind(tid)
                    .execute(pool)
                    .await?;
            }
            Self::Postgres(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(likes_sql))
                    .bind(tid)
                    .execute(pool)
                    .await?;
            }
        }
        if score_award_per_like != 0 {
            let retract_sql = match self {
                Self::Postgres(_) => {
                    format!("UPDATE {prefix}users SET score = score - $1 WHERE uid = $2")
                }
                _ => format!("UPDATE {prefix}users SET score = score - ? WHERE uid = ?"),
            };
            match self {
                Self::Sqlite(pool) => {
                    sqlx::query(sqlx::AssertSqlSafe(retract_sql))
                        .bind(score_award_per_like)
                        .bind(uploader_id)
                        .execute(pool)
                        .await?;
                }
                Self::MySql(pool) => {
                    sqlx::query(sqlx::AssertSqlSafe(retract_sql))
                        .bind(score_award_per_like)
                        .bind(uploader_id)
                        .execute(pool)
                        .await?;
                }
                Self::Postgres(pool) => {
                    sqlx::query(sqlx::AssertSqlSafe(retract_sql))
                        .bind(score_award_per_like)
                        .bind(uploader_id)
                        .execute(pool)
                        .await?;
                }
            }
        }
        Ok(ClosetRemoveOutcome::Removed)
    }
    pub async fn skinlib_items(
        &self,
        prefix: &str,
        user_id: Option<i64>,
        is_admin: bool,
        filter: &str,
        keyword: Option<&str>,
        uploader: Option<i64>,
        sort: &str,
        page: i64,
        per_page: i64,
    ) -> Result<(Vec<SkinLibraryRecord>, i64), sqlx::Error> {
        let is_postgres = matches!(self, Self::Postgres(_));
        let (keyword_enabled, keyword_pattern, uploader_enabled, uploader_value) = if is_postgres {
            ("$3", "$4", "$5", "$6")
        } else {
            ("?", "?", "?", "?")
        };
        let category = match filter {
            "skin" => "t.type IN ('steve', 'alex')",
            "steve" | "alex" | "cape" => match filter {
                "steve" => "t.type = 'steve'",
                "alex" => "t.type = 'alex'",
                _ => "t.type = 'cape'",
            },
            _ => "t.type = '__no_such_texture_type__'",
        };
        let order_by = match sort {
            "likes" => "t.likes",
            "name" => "t.name",
            _ => "t.upload_at",
        };
        let visibility = if is_postgres {
            "$1 = TRUE OR t.public = TRUE OR t.uploader = $2"
        } else {
            "? = TRUE OR t.public = TRUE OR t.uploader = ?"
        };
        let where_sql = format!(
            "({visibility}) AND {category} \
             AND ({keyword_enabled} = FALSE OR t.name LIKE {keyword_pattern}) \
             AND ({uploader_enabled} = FALSE OR t.uploader = {uploader_value})"
        );
        let count_sql = format!(
            "SELECT COUNT(*) FROM {prefix}textures t \
             INNER JOIN {prefix}users u ON u.uid = t.uploader \
             WHERE {where_sql}"
        );
        let search_pattern = format!("%{}%", keyword.unwrap_or_default());
        let count = match self {
            Self::Sqlite(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(count_sql))
                    .bind(is_admin)
                    .bind(user_id)
                    .bind(keyword.is_some())
                    .bind(&search_pattern)
                    .bind(uploader.is_some())
                    .bind(uploader.unwrap_or_default())
                    .fetch_one(pool)
                    .await?
            }
            Self::MySql(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(count_sql))
                    .bind(is_admin)
                    .bind(user_id)
                    .bind(keyword.is_some())
                    .bind(&search_pattern)
                    .bind(uploader.is_some())
                    .bind(uploader.unwrap_or_default())
                    .fetch_one(pool)
                    .await?
            }
            Self::Postgres(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(count_sql))
                    .bind(is_admin)
                    .bind(user_id)
                    .bind(keyword.is_some())
                    .bind(&search_pattern)
                    .bind(uploader.is_some())
                    .bind(uploader.unwrap_or_default())
                    .fetch_one(pool)
                    .await?
            }
        };
        let (limit_marker, offset_marker) = if is_postgres {
            ("$7".to_owned(), "$8".to_owned())
        } else {
            ("?".to_owned(), "?".to_owned())
        };
        let rows_sql = format!(
            "SELECT CAST(t.tid AS BIGINT) AS tid, t.name, t.type AS texture_type, \
             CAST(t.uploader AS BIGINT) AS uploader, t.public AS is_public, \
             CAST(t.likes AS BIGINT) AS likes, u.nickname \
             FROM {prefix}textures t INNER JOIN {prefix}users u ON u.uid = t.uploader \
             WHERE {where_sql} ORDER BY {order_by} DESC \
             LIMIT {limit_marker} OFFSET {offset_marker}"
        );
        let offset = page.saturating_sub(1).saturating_mul(per_page);
        let rows = match self {
            Self::Sqlite(pool) => {
                sqlx::query_as::<_, SkinLibraryRecord>(sqlx::AssertSqlSafe(rows_sql))
                    .bind(is_admin)
                    .bind(user_id)
                    .bind(keyword.is_some())
                    .bind(&search_pattern)
                    .bind(uploader.is_some())
                    .bind(uploader.unwrap_or_default())
                    .bind(per_page)
                    .bind(offset)
                    .fetch_all(pool)
                    .await?
            }
            Self::MySql(pool) => {
                sqlx::query_as::<_, SkinLibraryRecord>(sqlx::AssertSqlSafe(rows_sql))
                    .bind(is_admin)
                    .bind(user_id)
                    .bind(keyword.is_some())
                    .bind(&search_pattern)
                    .bind(uploader.is_some())
                    .bind(uploader.unwrap_or_default())
                    .bind(per_page)
                    .bind(offset)
                    .fetch_all(pool)
                    .await?
            }
            Self::Postgres(pool) => {
                sqlx::query_as::<_, SkinLibraryRecord>(sqlx::AssertSqlSafe(rows_sql))
                    .bind(is_admin)
                    .bind(user_id)
                    .bind(keyword.is_some())
                    .bind(&search_pattern)
                    .bind(uploader.is_some())
                    .bind(uploader.unwrap_or_default())
                    .bind(per_page)
                    .bind(offset)
                    .fetch_all(pool)
                    .await?
            }
        };
        Ok((rows, count))
    }
    pub async fn closet_items(
        &self,
        prefix: &str,
        user_id: i64,
        category: &str,
        search: Option<&str>,
        page: i64,
        per_page: i64,
    ) -> Result<(Vec<ClosetTextureRecord>, i64), sqlx::Error> {
        let is_postgres = matches!(self, Self::Postgres(_));
        let search_marker = if is_postgres { "$3" } else { "?" };
        let enabled_marker = if is_postgres { "$2" } else { "?" };
        let user_marker = if is_postgres { "$1" } else { "?" };
        let where_sql = if category == "cape" {
            format!(
                "c.user_uid = {user_marker} AND t.type = 'cape' \
                 AND ({enabled_marker} = {} OR c.item_name LIKE {search_marker})",
                if is_postgres { "FALSE" } else { "0" }
            )
        } else {
            format!(
                "c.user_uid = {user_marker} AND t.type IN ('steve', 'alex') \
                 AND ({enabled_marker} = {} OR c.item_name LIKE {search_marker})",
                if is_postgres { "FALSE" } else { "0" }
            )
        };
        let count_sql = format!(
            "SELECT COUNT(*) FROM {prefix}textures t \
             INNER JOIN {prefix}user_closet c ON c.texture_tid = t.tid \
             WHERE {where_sql}"
        );
        let total = match self {
            Self::Sqlite(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(count_sql))
                    .bind(user_id)
                    .bind(search.is_some())
                    .bind(format!("%{}%", search.unwrap_or_default()))
                    .fetch_one(pool)
                    .await?
            }
            Self::MySql(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(count_sql))
                    .bind(user_id)
                    .bind(search.is_some())
                    .bind(format!("%{}%", search.unwrap_or_default()))
                    .fetch_one(pool)
                    .await?
            }
            Self::Postgres(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(count_sql))
                    .bind(user_id)
                    .bind(search.is_some())
                    .bind(format!("%{}%", search.unwrap_or_default()))
                    .fetch_one(pool)
                    .await?
            }
        };

        let mut next_marker = if is_postgres { 4 } else { 0 };
        let limit_marker = if is_postgres {
            let marker = format!("{}{}", "$", next_marker);
            next_marker += 1;
            marker
        } else {
            "?".to_owned()
        };
        let offset_marker = if is_postgres {
            format!("{}{}", "$", next_marker)
        } else {
            "?".to_owned()
        };
        let upload_at = match self {
            Self::MySql(_) => "DATE_FORMAT(t.upload_at, '%Y-%m-%d %H:%i:%s')",
            Self::Postgres(_) => "CAST(t.upload_at AS TEXT)",
            Self::Sqlite(_) => "CAST(t.upload_at AS TEXT)",
        };
        let rows_sql = format!(
            "SELECT CAST(t.tid AS BIGINT) AS tid, t.name, t.type AS texture_type, t.hash, \
             CAST(t.size AS BIGINT) AS size, CAST(t.uploader AS BIGINT) AS uploader, \
             t.public AS is_public, {upload_at} AS upload_at, CAST(t.likes AS BIGINT) AS likes, \
             CAST(c.user_uid AS BIGINT) AS user_uid, CAST(c.texture_tid AS BIGINT) AS texture_tid, \
             c.item_name \
             FROM {prefix}textures t \
             INNER JOIN {prefix}user_closet c ON c.texture_tid = t.tid \
             WHERE {where_sql} ORDER BY c.texture_tid DESC \
             LIMIT {limit_marker} OFFSET {offset_marker}"
        );
        let offset = page.saturating_sub(1).saturating_mul(per_page);
        let rows = match self {
            Self::Sqlite(pool) => {
                sqlx::query_as::<_, ClosetTextureRecord>(sqlx::AssertSqlSafe(rows_sql))
                    .bind(user_id)
                    .bind(search.is_some())
                    .bind(format!("%{}%", search.unwrap_or_default()))
                    .bind(per_page)
                    .bind(offset)
                    .fetch_all(pool)
                    .await?
            }
            Self::MySql(pool) => {
                sqlx::query_as::<_, ClosetTextureRecord>(sqlx::AssertSqlSafe(rows_sql))
                    .bind(user_id)
                    .bind(search.is_some())
                    .bind(format!("%{}%", search.unwrap_or_default()))
                    .bind(per_page)
                    .bind(offset)
                    .fetch_all(pool)
                    .await?
            }
            Self::Postgres(pool) => {
                sqlx::query_as::<_, ClosetTextureRecord>(sqlx::AssertSqlSafe(rows_sql))
                    .bind(user_id)
                    .bind(search.is_some())
                    .bind(format!("%{}%", search.unwrap_or_default()))
                    .bind(per_page)
                    .bind(offset)
                    .fetch_all(pool)
                    .await?
            }
        };
        Ok((rows, total))
    }
    pub async fn add_player(
        &self,
        prefix: &str,
        user_id: i64,
        name: &str,
        score_cost: i64,
    ) -> Result<PlayerAddOutcome, sqlx::Error> {
        let duplicate_sql = match self {
            Self::Postgres(_) => format!("SELECT COUNT(*) FROM {prefix}players WHERE name = $1"),
            _ => format!("SELECT COUNT(*) FROM {prefix}players WHERE name = ?"),
        };
        let duplicate_count = match self {
            Self::Sqlite(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(duplicate_sql))
                    .bind(name)
                    .fetch_one(pool)
                    .await?
            }
            Self::MySql(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(duplicate_sql))
                    .bind(name)
                    .fetch_one(pool)
                    .await?
            }
            Self::Postgres(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(duplicate_sql))
                    .bind(name)
                    .fetch_one(pool)
                    .await?
            }
        };
        if duplicate_count > 0 {
            return Ok(PlayerAddOutcome::NameExists);
        }

        let score_sql = match self {
            Self::Postgres(_) => {
                format!("SELECT CAST(score AS BIGINT) FROM {prefix}users WHERE uid = $1")
            }
            Self::MySql(_) => {
                format!("SELECT CAST(score AS SIGNED) FROM {prefix}users WHERE uid = ?")
            }
            Self::Sqlite(_) => {
                format!("SELECT CAST(score AS BIGINT) FROM {prefix}users WHERE uid = ?")
            }
        };
        let score = match self {
            Self::Sqlite(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(score_sql))
                    .bind(user_id)
                    .fetch_optional(pool)
                    .await?
            }
            Self::MySql(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(score_sql))
                    .bind(user_id)
                    .fetch_optional(pool)
                    .await?
            }
            Self::Postgres(pool) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(score_sql))
                    .bind(user_id)
                    .fetch_optional(pool)
                    .await?
            }
        };
        let Some(score) = score else {
            return Err(sqlx::Error::RowNotFound);
        };
        if score < score_cost {
            return Ok(PlayerAddOutcome::InsufficientScore);
        }

        let player_id = match self {
            Self::Sqlite(pool) => sqlx::query(sqlx::AssertSqlSafe(format!(
                "INSERT INTO {prefix}players (uid, name, tid_skin, tid_cape, last_modified) \
                     VALUES (?, ?, 0, 0, CURRENT_TIMESTAMP)"
            )))
            .bind(user_id)
            .bind(name)
            .execute(pool)
            .await?
            .last_insert_rowid(),
            Self::MySql(pool) => sqlx::query(sqlx::AssertSqlSafe(format!(
                "INSERT INTO {prefix}players (uid, name, tid_skin, tid_cape, last_modified) \
                     VALUES (?, ?, 0, 0, CURRENT_TIMESTAMP)"
            )))
            .bind(user_id)
            .bind(name)
            .execute(pool)
            .await?
            .last_insert_id() as i64,
            Self::Postgres(pool) => {
                let insert_sql = format!(
                    "INSERT INTO {prefix}players (uid, name, tid_skin, tid_cape, last_modified) \
                     VALUES ($1, $2, 0, 0, CURRENT_TIMESTAMP) RETURNING CAST(pid AS BIGINT)"
                );
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(insert_sql))
                    .bind(user_id)
                    .bind(name)
                    .fetch_one(pool)
                    .await?
            }
        };

        if score_cost != 0 {
            let update_sql = match self {
                Self::Postgres(_) => format!(
                    "UPDATE {prefix}users SET score = score - $1 WHERE uid = $2 AND score >= $3"
                ),
                _ => format!(
                    "UPDATE {prefix}users SET score = score - ? WHERE uid = ? AND score >= ?"
                ),
            };
            let updated = match self {
                Self::Sqlite(pool) => sqlx::query(sqlx::AssertSqlSafe(update_sql))
                    .bind(score_cost)
                    .bind(user_id)
                    .bind(score_cost)
                    .execute(pool)
                    .await?
                    .rows_affected(),
                Self::MySql(pool) => sqlx::query(sqlx::AssertSqlSafe(update_sql))
                    .bind(score_cost)
                    .bind(user_id)
                    .bind(score_cost)
                    .execute(pool)
                    .await?
                    .rows_affected(),
                Self::Postgres(pool) => sqlx::query(sqlx::AssertSqlSafe(update_sql))
                    .bind(score_cost)
                    .bind(user_id)
                    .bind(score_cost)
                    .execute(pool)
                    .await?
                    .rows_affected(),
            };
            if updated == 0 {
                let delete_sql = match self {
                    Self::Postgres(_) => {
                        format!("DELETE FROM {prefix}players WHERE pid = $1 AND uid = $2")
                    }
                    _ => format!("DELETE FROM {prefix}players WHERE pid = ? AND uid = ?"),
                };
                match self {
                    Self::Sqlite(pool) => {
                        sqlx::query(sqlx::AssertSqlSafe(delete_sql))
                            .bind(player_id)
                            .bind(user_id)
                            .execute(pool)
                            .await?;
                    }
                    Self::MySql(pool) => {
                        sqlx::query(sqlx::AssertSqlSafe(delete_sql))
                            .bind(player_id)
                            .bind(user_id)
                            .execute(pool)
                            .await?;
                    }
                    Self::Postgres(pool) => {
                        sqlx::query(sqlx::AssertSqlSafe(delete_sql))
                            .bind(player_id)
                            .bind(user_id)
                            .execute(pool)
                            .await?;
                    }
                }
                return Ok(PlayerAddOutcome::InsufficientScore);
            }
        }
        let player = self
            .players_for_user(prefix, user_id)
            .await?
            .into_iter()
            .find(|player| player.pid == player_id)
            .ok_or(sqlx::Error::RowNotFound)?;
        Ok(PlayerAddOutcome::Added(player))
    }

    pub async fn delete_player(
        &self,
        prefix: &str,
        user_id: i64,
        player_id: i64,
        return_score: bool,
        score_reward: i64,
    ) -> Result<PlayerDeleteOutcome, sqlx::Error> {
        let Some(player) = self
            .players_for_user(prefix, user_id)
            .await?
            .into_iter()
            .find(|player| player.pid == player_id)
        else {
            return Ok(if self.player_exists(prefix, player_id).await? {
                PlayerDeleteOutcome::Forbidden
            } else {
                PlayerDeleteOutcome::NotFound
            });
        };
        let delete_sql = match self {
            Self::Postgres(_) => format!("DELETE FROM {prefix}players WHERE pid = $1 AND uid = $2"),
            _ => format!("DELETE FROM {prefix}players WHERE pid = ? AND uid = ?"),
        };
        let deleted = match self {
            Self::Sqlite(pool) => sqlx::query(sqlx::AssertSqlSafe(delete_sql))
                .bind(player_id)
                .bind(user_id)
                .execute(pool)
                .await?
                .rows_affected(),
            Self::MySql(pool) => sqlx::query(sqlx::AssertSqlSafe(delete_sql))
                .bind(player_id)
                .bind(user_id)
                .execute(pool)
                .await?
                .rows_affected(),
            Self::Postgres(pool) => sqlx::query(sqlx::AssertSqlSafe(delete_sql))
                .bind(player_id)
                .bind(user_id)
                .execute(pool)
                .await?
                .rows_affected(),
        };
        if deleted == 0 {
            return Ok(if self.player_exists(prefix, player_id).await? {
                PlayerDeleteOutcome::Forbidden
            } else {
                PlayerDeleteOutcome::NotFound
            });
        }
        if return_score && score_reward != 0 {
            let update_sql = match self {
                Self::Postgres(_) => {
                    format!("UPDATE {prefix}users SET score = score + $1 WHERE uid = $2")
                }
                _ => format!("UPDATE {prefix}users SET score = score + ? WHERE uid = ?"),
            };
            match self {
                Self::Sqlite(pool) => {
                    sqlx::query(sqlx::AssertSqlSafe(update_sql))
                        .bind(score_reward)
                        .bind(user_id)
                        .execute(pool)
                        .await?;
                }
                Self::MySql(pool) => {
                    sqlx::query(sqlx::AssertSqlSafe(update_sql))
                        .bind(score_reward)
                        .bind(user_id)
                        .execute(pool)
                        .await?;
                }
                Self::Postgres(pool) => {
                    sqlx::query(sqlx::AssertSqlSafe(update_sql))
                        .bind(score_reward)
                        .bind(user_id)
                        .execute(pool)
                        .await?;
                }
            }
        }
        Ok(PlayerDeleteOutcome::Deleted(player.name))
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

    pub async fn notification_recipients(
        &self,
        prefix: &str,
        audience: &NotificationAudience,
    ) -> Result<Option<Vec<i64>>, sqlx::Error> {
        let (sql, targeted) = match (self, audience) {
            (Self::Postgres(_), NotificationAudience::All) => (
                format!("SELECT CAST(uid AS BIGINT) FROM {prefix}users ORDER BY uid"),
                false,
            ),
            (Self::Postgres(_), NotificationAudience::Normal) => (
                format!(
                    "SELECT CAST(uid AS BIGINT) FROM {prefix}users WHERE permission = 0 ORDER BY uid"
                ),
                false,
            ),
            (Self::Postgres(_), NotificationAudience::User(_)) => (
                format!("SELECT CAST(uid AS BIGINT) FROM {prefix}users WHERE uid = $1"),
                true,
            ),
            (Self::Postgres(_), NotificationAudience::Email(_)) => (
                format!("SELECT CAST(uid AS BIGINT) FROM {prefix}users WHERE email = $1"),
                true,
            ),
            (_, NotificationAudience::All) => (
                format!("SELECT CAST(uid AS SIGNED) FROM {prefix}users ORDER BY uid"),
                false,
            ),
            (_, NotificationAudience::Normal) => (
                format!(
                    "SELECT CAST(uid AS SIGNED) FROM {prefix}users WHERE permission = 0 ORDER BY uid"
                ),
                false,
            ),
            (_, NotificationAudience::User(_)) => (
                format!("SELECT CAST(uid AS SIGNED) FROM {prefix}users WHERE uid = ?"),
                true,
            ),
            (_, NotificationAudience::Email(_)) => (
                format!("SELECT CAST(uid AS SIGNED) FROM {prefix}users WHERE email = ?"),
                true,
            ),
        };
        let recipients = match (self, audience) {
            (Self::Sqlite(pool), NotificationAudience::User(user_id)) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                    .bind(user_id)
                    .fetch_all(pool)
                    .await?
            }
            (Self::MySql(pool), NotificationAudience::User(user_id)) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                    .bind(user_id)
                    .fetch_all(pool)
                    .await?
            }
            (Self::Postgres(pool), NotificationAudience::User(user_id)) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                    .bind(user_id)
                    .fetch_all(pool)
                    .await?
            }
            (Self::Sqlite(pool), NotificationAudience::Email(email)) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                    .bind(email)
                    .fetch_all(pool)
                    .await?
            }
            (Self::MySql(pool), NotificationAudience::Email(email)) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                    .bind(email)
                    .fetch_all(pool)
                    .await?
            }
            (Self::Postgres(pool), NotificationAudience::Email(email)) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                    .bind(email)
                    .fetch_all(pool)
                    .await?
            }
            (Self::Sqlite(pool), _) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                    .fetch_all(pool)
                    .await?
            }
            (Self::MySql(pool), _) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                    .fetch_all(pool)
                    .await?
            }
            (Self::Postgres(pool), _) => {
                sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
                    .fetch_all(pool)
                    .await?
            }
        };
        if targeted && recipients.is_empty() {
            Ok(None)
        } else {
            Ok(Some(recipients))
        }
    }

    pub async fn create_site_notification(
        &self,
        prefix: &str,
        id: &str,
        user_id: i64,
        data: &str,
    ) -> Result<(), sqlx::Error> {
        let sql = match self {
            Self::Postgres(_) => format!(
                "INSERT INTO {prefix}notifications (id, type, notifiable_type, notifiable_id, data, created_at, updated_at) \
                 VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
            ),
            _ => format!(
                "INSERT INTO {prefix}notifications (id, type, notifiable_type, notifiable_id, data, created_at, updated_at) \
                 VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
            ),
        };
        match self {
            Self::Sqlite(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(id)
                    .bind("App\\Notifications\\SiteMessage")
                    .bind("App\\Models\\User")
                    .bind(user_id)
                    .bind(data)
                    .execute(pool)
                    .await?;
            }
            Self::MySql(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(id)
                    .bind("App\\Notifications\\SiteMessage")
                    .bind("App\\Models\\User")
                    .bind(user_id)
                    .bind(data)
                    .execute(pool)
                    .await?;
            }
            Self::Postgres(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(id)
                    .bind("App\\Notifications\\SiteMessage")
                    .bind("App\\Models\\User")
                    .bind(user_id)
                    .bind(data)
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
        sqlx::query("CREATE TABLE bs_textures (tid INTEGER PRIMARY KEY, name TEXT NOT NULL, type TEXT NOT NULL, hash TEXT NOT NULL, size INTEGER NOT NULL, uploader INTEGER NOT NULL, public BOOLEAN NOT NULL, upload_at TEXT NOT NULL, likes INTEGER NOT NULL)")
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
        sqlx::query("INSERT INTO bs_users (uid, email, nickname, locale, score, avatar, permission, last_sign_at, register_at, verified, is_dark_mode) VALUES (7, 'alex@example.test', 'Alex User', 'zh_CN', 42, 11, 0, '2026-10-01 10:00:00', '2025-01-02 03:04:05', 1, 0), (8, 'admin@example.test', 'Admin', 'en', 50, 0, 1, '', '', 1, 0)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO bs_players (pid, uid, name, tid_skin, tid_cape, last_modified) VALUES (3, 7, 'Alex', 11, 12, '2026-10-02 12:00:00'), (4, 8, 'Other', 0, 0, '2026-10-02 13:00:00')")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO bs_textures (tid, name, type, hash, size, uploader, public, upload_at, likes) VALUES (11, 'Skin', 'alex', 'skin-hash', 8, 7, 1, '2026-10-01 10:00:00', 1), (12, 'Cape', 'cape', 'cape-hash', 9, 7, 1, '2026-10-01 10:01:00', 1), (13, 'Other skin', 'alex', 'not-in-closet', 10, 8, 1, '2026-10-01 10:02:00', 0), (14, 'Private skin', 'steve', 'private-hash', 11, 8, 0, '2026-10-01 10:03:00', 4), (15, 'Private Alex', 'alex', 'owner-private-hash', 12, 7, 0, '2026-10-01 10:04:00', 2)")
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
        let database = DatabasePool::Sqlite(pool.clone());
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
        assert_eq!(
            database
                .notification_recipients("bs_", &super::NotificationAudience::All)
                .await
                .unwrap()
                .unwrap(),
            vec![7, 8]
        );
        assert_eq!(
            database
                .notification_recipients("bs_", &super::NotificationAudience::Normal)
                .await
                .unwrap()
                .unwrap(),
            vec![7]
        );
        assert_eq!(
            database
                .notification_recipients("bs_", &super::NotificationAudience::User(7))
                .await
                .unwrap()
                .unwrap(),
            vec![7]
        );
        assert_eq!(
            database
                .notification_recipients(
                    "bs_",
                    &super::NotificationAudience::Email("alex@example.test".to_owned())
                )
                .await
                .unwrap()
                .unwrap(),
            vec![7]
        );
        assert!(
            database
                .notification_recipients(
                    "bs_",
                    &super::NotificationAudience::Email("missing@example.test".to_owned())
                )
                .await
                .unwrap()
                .is_none()
        );
        database
            .create_site_notification(
                "bs_",
                "00000000-0000-4000-8000-000000000001",
                7,
                r#"{"title":"New notice","content":"Updated **skin**"}"#,
            )
            .await
            .unwrap();
        let sent_notification = database
            .read_notification("bs_", 7, "00000000-0000-4000-8000-000000000001")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&sent_notification.data).unwrap()["title"],
            "New notice"
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
        let added = database
            .add_player("bs_", 7, "NewPlayer", 10)
            .await
            .unwrap();
        let new_player_id = match added {
            super::PlayerAddOutcome::Added(player) => {
                assert_eq!(player.name, "NewPlayer");
                assert_eq!(player.uid, 7);
                assert_eq!(player.tid_skin, 0);
                assert_eq!(player.tid_cape, 0);
                player.pid
            }
            result => panic!("expected a player to be added, got {result:?}"),
        };
        assert!(matches!(
            database.add_player("bs_", 7, "Alex_New", 1).await.unwrap(),
            super::PlayerAddOutcome::NameExists
        ));
        assert!(matches!(
            database
                .add_player("bs_", 7, "TooExpensive", 100)
                .await
                .unwrap(),
            super::PlayerAddOutcome::InsufficientScore
        ));
        let refunded = database
            .delete_player("bs_", 7, new_player_id, true, 10)
            .await
            .unwrap();
        assert!(matches!(
            refunded,
            super::PlayerDeleteOutcome::Deleted(name) if name == "NewPlayer"
        ));
        let added_without_refund = database.add_player("bs_", 7, "NoRefund", 5).await.unwrap();
        let no_refund_id = match added_without_refund {
            super::PlayerAddOutcome::Added(player) => player.pid,
            result => panic!("expected a player to be added, got {result:?}"),
        };
        assert!(matches!(
            database
                .delete_player("bs_", 7, no_refund_id, false, 5)
                .await
                .unwrap(),
            super::PlayerDeleteOutcome::Deleted(name) if name == "NoRefund"
        ));
        assert!(matches!(
            database.delete_player("bs_", 8, 3, false, 0).await.unwrap(),
            super::PlayerDeleteOutcome::Forbidden
        ));
        assert!(matches!(
            database
                .delete_player("bs_", 7, 99, false, 0)
                .await
                .unwrap(),
            super::PlayerDeleteOutcome::NotFound
        ));
        assert!(matches!(
            database
                .add_closet_item("bs_", 7, 99, "Missing", 0, false, 0)
                .await
                .unwrap(),
            super::ClosetAddOutcome::TextureNotFound
        ));
        assert!(matches!(
            database
                .add_closet_item("bs_", 7, 13, "Too costly", 100, false, 0)
                .await
                .unwrap(),
            super::ClosetAddOutcome::InsufficientScore
        ));
        assert!(matches!(
            database
                .add_closet_item("bs_", 7, 11, "Already saved", 0, false, 0)
                .await
                .unwrap(),
            super::ClosetAddOutcome::NameExists
        ));
        assert!(matches!(
            database
                .add_closet_item("bs_", 7, 14, "Private", 0, false, 0)
                .await
                .unwrap(),
            super::ClosetAddOutcome::PrivateTexture
        ));
        assert!(matches!(
            database
                .add_closet_item("bs_", 7, 14, "Admin saved", 0, true, 0)
                .await
                .unwrap(),
            super::ClosetAddOutcome::Added
        ));
        assert!(matches!(
            database
                .remove_closet_item("bs_", 7, 14, false, 0, 0)
                .await
                .unwrap(),
            super::ClosetRemoveOutcome::Removed
        ));
        assert!(matches!(
            database
                .add_closet_item("bs_", 7, 13, "Second skin", 2, false, 0)
                .await
                .unwrap(),
            super::ClosetAddOutcome::Added
        ));
        assert!(matches!(
            database
                .rename_closet_item("bs_", 7, 13, "Second skin renamed")
                .await
                .unwrap(),
            super::ClosetRenameOutcome::Renamed
        ));
        let (skin_page, skin_total) = database
            .closet_items("bs_", 7, "skin", None, 1, 1)
            .await
            .unwrap();
        assert_eq!(skin_total, 2);
        assert_eq!(skin_page.len(), 1);
        assert_eq!(skin_page[0].tid, 13);
        assert_eq!(skin_page[0].user_uid, 7);
        assert_eq!(skin_page[0].texture_tid, 13);
        assert_eq!(
            skin_page[0].item_name.as_deref(),
            Some("Second skin renamed")
        );
        assert!(skin_page[0].is_public);
        let (next_skin_page, next_skin_total) = database
            .closet_items("bs_", 7, "skin", None, 2, 1)
            .await
            .unwrap();
        assert_eq!(next_skin_total, 2);
        assert_eq!(next_skin_page[0].tid, 11);
        let (searched_items, searched_total) = database
            .closet_items("bs_", 7, "skin", Some("Second"), 1, 6)
            .await
            .unwrap();
        assert_eq!(searched_total, 1);
        assert_eq!(searched_items[0].tid, 13);
        assert_eq!(
            searched_items[0].item_name.as_deref(),
            Some("Second skin renamed")
        );
        assert!(matches!(
            database
                .remove_closet_item("bs_", 7, 13, true, 2, 0)
                .await
                .unwrap(),
            super::ClosetRemoveOutcome::Removed
        ));
        assert!(matches!(
            database
                .remove_closet_item("bs_", 7, 99, false, 0, 0)
                .await
                .unwrap(),
            super::ClosetRemoveOutcome::NotInCloset
        ));
        assert!(matches!(
            database
                .rename_closet_item("bs_", 7, 99, "Missing")
                .await
                .unwrap(),
            super::ClosetRenameOutcome::NotInCloset
        ));
        let texture = database.texture_info("bs_", 13).await.unwrap().unwrap();
        assert_eq!(texture.tid, 13);
        assert_eq!(texture.name, "Other skin");
        assert_eq!(texture.texture_type, "alex");
        assert_eq!(texture.hash, "not-in-closet");
        assert_eq!(texture.size, 10);
        assert_eq!(texture.uploader, 8);
        assert!(texture.is_public);
        assert_eq!(texture.upload_at, "2026-10-01 10:02:00");
        assert_eq!(texture.likes, 0);
        assert!(database.texture_info("bs_", 99).await.unwrap().is_none());
        let skin_likes: i64 = sqlx::query_scalar("SELECT likes FROM bs_textures WHERE tid = 13")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(skin_likes, 0);
        let (cape_items, cape_total) = database
            .closet_items("bs_", 7, "cape", None, 1, 6)
            .await
            .unwrap();
        assert_eq!(cape_total, 1);
        assert_eq!(cape_items[0].texture_type, "cape");
        let (public_skins, public_skin_total) = database
            .skinlib_items("bs_", None, false, "skin", None, None, "time", 1, 20)
            .await
            .unwrap();
        assert_eq!(public_skin_total, 2);
        assert_eq!(public_skins.len(), 2);
        assert_eq!(public_skins[0].tid, 13);
        assert_eq!(public_skins[0].nickname, "Admin");
        let (own_skins, own_skin_total) = database
            .skinlib_items("bs_", Some(7), false, "skin", None, None, "time", 1, 20)
            .await
            .unwrap();
        assert_eq!(own_skin_total, 3);
        assert!(
            own_skins
                .iter()
                .any(|item| item.tid == 15 && !item.is_public)
        );
        let (admin_capes, admin_cape_total) = database
            .skinlib_items("bs_", Some(8), true, "cape", None, None, "time", 1, 20)
            .await
            .unwrap();
        assert_eq!(admin_cape_total, 1);
        assert_eq!(admin_capes[0].tid, 12);
        let (admin_skins, admin_skin_total) = database
            .skinlib_items("bs_", Some(8), true, "skin", None, None, "time", 1, 20)
            .await
            .unwrap();
        assert_eq!(admin_skin_total, 4);
        assert!(
            admin_skins
                .iter()
                .any(|item| item.tid == 14 && !item.is_public)
        );
        let (searched_skins, searched_skin_total) = database
            .skinlib_items(
                "bs_",
                None,
                false,
                "skin",
                Some("Other"),
                None,
                "likes",
                1,
                20,
            )
            .await
            .unwrap();
        assert_eq!(searched_skin_total, 1);
        assert_eq!(searched_skins[0].tid, 13);
        let (uploader_skins, uploader_skin_total) = database
            .skinlib_items("bs_", None, false, "skin", None, Some(8), "likes", 1, 20)
            .await
            .unwrap();
        assert_eq!(uploader_skin_total, 1);
        assert_eq!(uploader_skins[0].tid, 13);
        let (first_skin_page, first_skin_page_total) = database
            .skinlib_items("bs_", None, false, "skin", None, None, "time", 1, 1)
            .await
            .unwrap();
        let (second_skin_page, second_skin_page_total) = database
            .skinlib_items("bs_", None, false, "skin", None, None, "time", 2, 1)
            .await
            .unwrap();
        assert_eq!(first_skin_page_total, 2);
        assert_eq!(second_skin_page_total, 2);
        assert_eq!(first_skin_page[0].tid, 13);
        assert_eq!(second_skin_page[0].tid, 11);
        database
            .rename_texture("bs_", 13, "Renamed texture")
            .await
            .unwrap();
        let renamed_texture = database.texture_info("bs_", 13).await.unwrap().unwrap();
        assert_eq!(renamed_texture.name, "Renamed texture");
        let user = database.user_profile("bs_", 7).await.unwrap().unwrap();
        assert_eq!(user.email, "alex@example.test");
        assert_eq!(user.nickname, "Alex User");
        assert_eq!(user.locale.as_deref(), Some("zh_CN"));
        assert_eq!(user.score, 37);
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
