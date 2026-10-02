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
        sqlx::query("CREATE TABLE bs_options (id INTEGER PRIMARY KEY, option_name TEXT NOT NULL, option_value TEXT NOT NULL)")
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
        sqlx::query("INSERT INTO bs_textures (tid, type, hash) VALUES (11, 'alex', 'skin-hash'), (12, 'cape', 'cape-hash')")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO bs_options (id, option_name, option_value) VALUES (1, 'site_name', 'Legacy Instance')")
            .execute(&pool)
            .await
            .unwrap();

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
