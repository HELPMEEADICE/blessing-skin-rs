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
        sqlx::query("CREATE TABLE bs_users (uid INTEGER PRIMARY KEY, permission INTEGER NOT NULL)")
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
        sqlx::query("INSERT INTO bs_users (uid, permission) VALUES (7, 0)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO bs_players (pid, uid, name, tid_skin, tid_cape, last_modified) VALUES (3, 7, 'Alex', 11, 12, '2026-10-02 12:00:00')")
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
