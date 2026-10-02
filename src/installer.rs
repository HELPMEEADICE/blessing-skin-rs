use std::{
    env,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use chrono::Datelike;
use jsonwebtoken::{DecodingKey, EncodingKey};
use rand::{RngCore, rngs::OsRng};
use rsa::{
    RsaPrivateKey,
    pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding},
};
use sqlx::sqlite::SqlitePoolOptions;
use thiserror::Error;

use crate::{auth::hash_legacy_password, config::Config, database::DatabasePool};

#[derive(Debug, Error)]
pub enum InstallError {
    #[error("missing required environment variable {0}")]
    MissingEnvironment(&'static str),
    #[error("invalid installation value: {0}")]
    InvalidInput(&'static str),
    #[error("the site is already installed (storage/install.lock exists)")]
    AlreadyInstalled,
    #[error(
        "the database contains Blessing Skin data; use the existing site instead of installing"
    )]
    DatabaseNotEmpty,
    #[error("Passport public and private keys must both be configured, or both be absent")]
    IncompletePassportKeys,
    #[error("configured Passport keys are invalid")]
    InvalidPassportKeys,
    #[error("configured password method cannot create a compatible password hash")]
    UnsupportedPasswordMethod,
    #[error(transparent)]
    Database(#[from] sqlx::Error),
    #[error(transparent)]
    Pool(#[from] crate::database::DatabaseError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("failed to generate Passport signing keys: {0}")]
    KeyGeneration(String),
}

struct Admin {
    email: String,
    nickname: String,
    password_hash: String,
    site_name: String,
}

struct GeneratedKeys {
    app_key: bool,
    passport_keys: bool,
}

pub async fn run(config: &Config) -> Result<(), InstallError> {
    let storage = PathBuf::from(env::var("STORAGE_PATH").unwrap_or_else(|_| "storage".to_owned()));
    if storage.join("install.lock").exists() {
        return Err(InstallError::AlreadyInstalled);
    }

    let email = required_env("BS_INSTALL_ADMIN_EMAIL")?;
    let nickname = required_env("BS_INSTALL_ADMIN_NICKNAME")?;
    let password = required_env("BS_INSTALL_ADMIN_PASSWORD")?;
    let site_name = required_env("BS_INSTALL_SITE_NAME")?;
    if !email.contains('@') || email.len() > 100 {
        return Err(InstallError::InvalidInput("admin email"));
    }
    if nickname.trim().is_empty() || nickname.len() > 50 {
        return Err(InstallError::InvalidInput("admin nickname"));
    }
    if !(8..=32).contains(&password.chars().count()) {
        return Err(InstallError::InvalidInput(
            "admin password must contain 8 to 32 bytes",
        ));
    }
    if site_name.trim().is_empty() {
        return Err(InstallError::InvalidInput("site name"));
    }
    let password_hash =
        hash_legacy_password(&password, &config.password_method, &config.password_salt)
            .ok_or(InstallError::UnsupportedPasswordMethod)?;
    let admin = Admin {
        email,
        nickname,
        password_hash,
        site_name,
    };

    fs::create_dir_all(&storage)?;
    if env::var("DB_CONNECTION").is_ok_and(|driver| driver.eq_ignore_ascii_case("sqlite")) {
        let filename =
            env::var("DB_DATABASE").unwrap_or_else(|_| "storage/database.sqlite".to_owned());
        if let Some(parent) = Path::new(&filename)
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)?;
        }
    }
    let pool = DatabasePool::connect_for_install(&config.database).await?;
    ensure_database_empty(&pool, &config.database.table_prefix).await?;
    let keys = prepare_keys(config, &storage)?;
    let site_url = config.app_url.trim_end_matches('/');
    initialize_schema(&pool, &config.database.table_prefix).await?;
    seed_options(
        &pool,
        &config.database.table_prefix,
        &admin.site_name,
        site_url,
    )
    .await?;
    let score = initial_score(&pool, &config.database.table_prefix).await?;
    insert_admin(&pool, &config.database.table_prefix, &admin, score).await?;
    fs::write(storage.join("install.lock"), b"")?;
    drop(pool);

    tracing::info!("Blessing Skin installation completed");
    if keys.app_key || keys.passport_keys {
        tracing::info!("Generated Rust session and Passport keys in the storage directory");
    }
    Ok(())
}

fn required_env(name: &'static str) -> Result<String, InstallError> {
    env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or(InstallError::MissingEnvironment(name))
}

fn prepare_keys(config: &Config, storage: &Path) -> Result<GeneratedKeys, InstallError> {
    let mut generated = GeneratedKeys {
        app_key: false,
        passport_keys: false,
    };
    match (&config.passport_private_key, &config.passport_public_key) {
        (Some(private), Some(public)) => {
            EncodingKey::from_rsa_pem(private).map_err(|_| InstallError::InvalidPassportKeys)?;
            DecodingKey::from_rsa_pem(public).map_err(|_| InstallError::InvalidPassportKeys)?;
        }
        (None, None) => {
            let mut rng = OsRng;
            let private = RsaPrivateKey::new(&mut rng, 2048)
                .map_err(|error| InstallError::KeyGeneration(error.to_string()))?;
            let public = private.to_public_key();
            let private_pem = private
                .to_pkcs8_pem(LineEnding::LF)
                .map_err(|error| InstallError::KeyGeneration(error.to_string()))?;
            let public_pem = public
                .to_public_key_pem(LineEnding::LF)
                .map_err(|error| InstallError::KeyGeneration(error.to_string()))?;
            write_private_file(&storage.join("oauth-private.key"), private_pem.as_bytes())?;
            write_private_file(&storage.join("oauth-public.key"), public_pem.as_bytes())?;
            generated.passport_keys = true;
        }
        _ => return Err(InstallError::IncompletePassportKeys),
    }
    if config.app_key.is_none() {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        write_private_file(&storage.join("app.key"), hex::encode(bytes).as_bytes())?;
        generated.app_key = true;
    }
    Ok(generated)
}

fn write_private_file(path: &Path, contents: &[u8]) -> Result<(), std::io::Error> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(contents)
}

async fn ensure_database_empty(pool: &DatabasePool, prefix: &str) -> Result<(), InstallError> {
    let names = table_names(pool).await?;
    for suffix in ["users", "players", "textures", "options"] {
        let expected = format!("{prefix}{suffix}").to_ascii_lowercase();
        if names.iter().any(|name| {
            let name = name.to_ascii_lowercase();
            name.ends_with(suffix) && name != expected
        }) {
            return Err(InstallError::DatabaseNotEmpty);
        }
    }
    for name in ["users", "players", "textures"] {
        let table = format!("{prefix}{name}");
        if table_exists(pool, &table).await? && table_count(pool, &table).await? > 0 {
            return Err(InstallError::DatabaseNotEmpty);
        }
    }
    Ok(())
}

async fn table_names(pool: &DatabasePool) -> Result<Vec<String>, sqlx::Error> {
    match pool {
        DatabasePool::Sqlite(pool) => Ok(sqlx::query_scalar::<_, String>(
            "SELECT name FROM sqlite_master WHERE type = 'table'",
        ).fetch_all(pool).await?),
        DatabasePool::MySql(pool) => Ok(sqlx::query_scalar::<_, String>(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE()",
        ).fetch_all(pool).await?),
        DatabasePool::Postgres(pool) => Ok(sqlx::query_scalar::<_, String>(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = current_schema()",
        ).fetch_all(pool).await?),
    }
}
async fn table_exists(pool: &DatabasePool, name: &str) -> Result<bool, sqlx::Error> {
    match pool {
        DatabasePool::Sqlite(pool) => Ok(sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?",
        ).bind(name).fetch_one(pool).await? > 0),
        DatabasePool::MySql(pool) => Ok(sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = ?",
        ).bind(name).fetch_one(pool).await? > 0),
        DatabasePool::Postgres(pool) => Ok(sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = $1",
        ).bind(name).fetch_one(pool).await? > 0),
    }
}

async fn table_count(pool: &DatabasePool, name: &str) -> Result<i64, sqlx::Error> {
    let sql = format!("SELECT COUNT(*) FROM {name}");
    match pool {
        DatabasePool::Sqlite(pool) => Ok(sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
            .fetch_one(pool)
            .await?),
        DatabasePool::MySql(pool) => Ok(sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
            .fetch_one(pool)
            .await?),
        DatabasePool::Postgres(pool) => Ok(sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
            .fetch_one(pool)
            .await?),
    }
}

async fn initialize_schema(pool: &DatabasePool, prefix: &str) -> Result<(), sqlx::Error> {
    let sqlite = matches!(pool, DatabasePool::Sqlite(_));
    let mysql = matches!(pool, DatabasePool::MySql(_));
    let id = if sqlite {
        "INTEGER PRIMARY KEY AUTOINCREMENT"
    } else if mysql {
        "INTEGER NOT NULL AUTO_INCREMENT PRIMARY KEY"
    } else {
        "SERIAL PRIMARY KEY"
    };
    let big_id = if sqlite {
        "INTEGER PRIMARY KEY AUTOINCREMENT"
    } else if mysql {
        "BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY"
    } else {
        "BIGSERIAL PRIMARY KEY"
    };
    let long_text = if mysql { "LONGTEXT" } else { "TEXT" };
    let datetime = if sqlite || mysql {
        "DATETIME"
    } else {
        "TIMESTAMP"
    };
    let group_column = if mysql {
        format!("{}group{}", char::from(96), char::from(96))
    } else {
        "\"group\"".to_owned()
    };
    let key_column = if mysql {
        format!("{}key{}", char::from(96), char::from(96))
    } else {
        "\"key\"".to_owned()
    };
    let statements = [
        format!(
            "CREATE TABLE IF NOT EXISTS {prefix}users (uid {id}, email VARCHAR(100) NOT NULL, nickname VARCHAR(50) NOT NULL DEFAULT '', locale VARCHAR(255), score INTEGER NOT NULL DEFAULT 0, avatar INTEGER NOT NULL DEFAULT 0, password VARCHAR(255) NOT NULL, ip VARCHAR(45) NOT NULL DEFAULT '', is_dark_mode BOOLEAN NOT NULL DEFAULT FALSE, permission INTEGER NOT NULL DEFAULT 0, last_sign_at {datetime} NOT NULL, register_at {datetime} NOT NULL, verified BOOLEAN NOT NULL DEFAULT FALSE, verification_token VARCHAR(255) NOT NULL DEFAULT '')"
        ),
        format!(
            "CREATE TABLE IF NOT EXISTS {prefix}players (pid {id}, uid INTEGER NOT NULL, name VARCHAR(50) NOT NULL, tid_skin INTEGER NOT NULL DEFAULT -1, tid_cape INTEGER NOT NULL DEFAULT 0, last_modified {datetime} NOT NULL)"
        ),
        format!(
            "CREATE TABLE IF NOT EXISTS {prefix}textures (tid {id}, name VARCHAR(50) NOT NULL, type VARCHAR(10) NOT NULL, hash VARCHAR(64) NOT NULL, size INTEGER NOT NULL, uploader INTEGER NOT NULL, public BOOLEAN NOT NULL DEFAULT FALSE, upload_at {datetime} NOT NULL, likes INTEGER NOT NULL DEFAULT 0)"
        ),
        format!(
            "CREATE TABLE IF NOT EXISTS {prefix}options (id {id}, option_name VARCHAR(50) NOT NULL, option_value {long_text} NOT NULL)"
        ),
        format!(
            "CREATE TABLE IF NOT EXISTS {prefix}user_closet (user_uid INTEGER NOT NULL, texture_tid INTEGER NOT NULL, item_name TEXT)"
        ),
        format!(
            "CREATE TABLE IF NOT EXISTS {prefix}reports (id {id}, tid INTEGER NOT NULL, uploader INTEGER NOT NULL, reporter INTEGER NOT NULL, reason {long_text} NOT NULL, status INTEGER NOT NULL, report_at {datetime} NOT NULL)"
        ),
        format!(
            "CREATE TABLE IF NOT EXISTS {prefix}notifications (id VARCHAR(36) PRIMARY KEY, type VARCHAR(255) NOT NULL, notifiable_type VARCHAR(255) NOT NULL, notifiable_id BIGINT NOT NULL, data {long_text} NOT NULL, read_at {datetime}, created_at {datetime}, updated_at {datetime})"
        ),
        format!(
            "CREATE TABLE IF NOT EXISTS {prefix}scopes (id {id}, name VARCHAR(255) NOT NULL UNIQUE, description VARCHAR(255) NOT NULL)"
        ),
        format!(
            "CREATE TABLE IF NOT EXISTS {prefix}jobs (id {big_id}, queue VARCHAR(255) NOT NULL, payload {long_text} NOT NULL, attempts INTEGER NOT NULL, reserved_at INTEGER, available_at INTEGER NOT NULL, created_at INTEGER NOT NULL)"
        ),
        format!(
            "CREATE TABLE IF NOT EXISTS {prefix}language_lines (id {id}, {group_column} VARCHAR(255) NOT NULL, {key_column} VARCHAR(255) NOT NULL, text TEXT NOT NULL, created_at {datetime}, updated_at {datetime})"
        ),
        format!(
            "CREATE TABLE IF NOT EXISTS {prefix}oauth_clients (id {big_id}, user_id BIGINT, name VARCHAR(255) NOT NULL, secret VARCHAR(100), provider VARCHAR(255), redirect TEXT NOT NULL, personal_access_client BOOLEAN NOT NULL, password_client BOOLEAN NOT NULL, revoked BOOLEAN NOT NULL, created_at {datetime}, updated_at {datetime})"
        ),
        format!(
            "CREATE TABLE IF NOT EXISTS {prefix}oauth_access_tokens (id VARCHAR(100) PRIMARY KEY, user_id BIGINT, client_id BIGINT NOT NULL, name VARCHAR(255), scopes TEXT NOT NULL, revoked BOOLEAN NOT NULL, created_at {datetime}, updated_at {datetime}, expires_at {datetime})"
        ),
        format!(
            "CREATE TABLE IF NOT EXISTS {prefix}oauth_refresh_tokens (id VARCHAR(100) PRIMARY KEY, access_token_id VARCHAR(100) NOT NULL, revoked BOOLEAN NOT NULL, expires_at {datetime})"
        ),
        format!(
            "CREATE TABLE IF NOT EXISTS {prefix}oauth_auth_codes (id VARCHAR(100) PRIMARY KEY, user_id BIGINT, client_id BIGINT NOT NULL, scopes TEXT NOT NULL, revoked BOOLEAN NOT NULL, expires_at {datetime})"
        ),
        format!(
            "CREATE TABLE IF NOT EXISTS {prefix}oauth_personal_access_clients (id {big_id}, client_id BIGINT NOT NULL UNIQUE)"
        ),
    ];
    for statement in statements {
        match pool {
            DatabasePool::Sqlite(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(statement))
                    .execute(pool)
                    .await?;
            }
            DatabasePool::MySql(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(statement))
                    .execute(pool)
                    .await?;
            }
            DatabasePool::Postgres(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(statement))
                    .execute(pool)
                    .await?;
            }
        }
    }
    Ok(())
}

async fn seed_options(
    pool: &DatabasePool,
    prefix: &str,
    site_name: &str,
    site_url: &str,
) -> Result<(), sqlx::Error> {
    let version = env!("CARGO_PKG_VERSION");
    let announcement = format!("Welcome to Blessing Skin {version}!");
    let year = chrono::Utc::now().year();
    let copyright = format!(
        "<b>Copyright &copy; {year} <a href=\"{site_url}\">{site_name}</a>.</b> All rights reserved."
    );
    let options = [
        ("site_url", site_url.to_owned()),
        ("site_name", site_name.to_owned()),
        (
            "site_description",
            "Open-source Minecraft Skin Hosting Service".to_owned(),
        ),
        ("register_with_player_name", "true".to_owned()),
        ("require_verification", "false".to_owned()),
        ("regs_per_ip", "3".to_owned()),
        ("announcement", announcement),
        ("home_pic_url", "./app/bg.webp".to_owned()),
        ("custom_css", "".to_owned()),
        ("custom_js", "".to_owned()),
        ("player_name_rule", "official".to_owned()),
        ("custom_player_name_regexp", "".to_owned()),
        ("player_name_length_min", "3".to_owned()),
        ("player_name_length_max", "16".to_owned()),
        ("user_initial_score", "1000".to_owned()),
        ("sign_gap_time", "24".to_owned()),
        ("sign_score", "10,100".to_owned()),
        ("score_per_storage", "true".to_owned()),
        ("private_score_per_storage", "10".to_owned()),
        ("return_score", "true".to_owned()),
        ("score_per_player", "100".to_owned()),
        ("sign_after_zero", "false".to_owned()),
        ("version", version.to_owned()),
        ("copyright_text", copyright),
        ("auto_del_invalid_texture", "false".to_owned()),
        ("allow_downloading_texture", "true".to_owned()),
        ("texture_name_regexp", "".to_owned()),
        ("cache_expire_time", "31536000".to_owned()),
        ("max_upload_file_size", "1024".to_owned()),
        ("force_ssl", "false".to_owned()),
        ("auto_detect_asset_url", "true".to_owned()),
        ("plugins_enabled", "".to_owned()),
        ("copyright_prefer", "0".to_owned()),
        ("score_per_closet_item", "0".to_owned()),
        ("favicon_url", "app/favicon.ico".to_owned()),
        ("score_award_per_texture", "0".to_owned()),
        ("take_back_scores_after_deletion", "true".to_owned()),
        ("score_award_per_like", "0".to_owned()),
        ("meta_keywords", "".to_owned()),
        ("meta_description", "".to_owned()),
        ("meta_extras", "".to_owned()),
        ("cdn_address", "".to_owned()),
        ("recaptcha_sitekey", "".to_owned()),
        ("recaptcha_secretkey", "".to_owned()),
        ("recaptcha_invisible", "false".to_owned()),
        ("reporter_score_modification", "0".to_owned()),
        ("reporter_reward_score", "0".to_owned()),
        ("content_policy", "".to_owned()),
        ("transparent_navbar", "false".to_owned()),
        ("status_code_for_private", "403".to_owned()),
        ("navbar_color", "cyan".to_owned()),
        ("sidebar_color", "dark-maroon".to_owned()),
        ("max_texture_width", "8192".to_owned()),
    ];
    for (key, value) in options {
        if option_exists(pool, prefix, key).await? {
            continue;
        }
        let sql = match pool {
            DatabasePool::Postgres(_) => {
                format!("INSERT INTO {prefix}options (option_name, option_value) VALUES ($1, $2)")
            }
            _ => format!("INSERT INTO {prefix}options (option_name, option_value) VALUES (?, ?)"),
        };
        match pool {
            DatabasePool::Sqlite(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(key)
                    .bind(value)
                    .execute(pool)
                    .await?;
            }
            DatabasePool::MySql(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(key)
                    .bind(value)
                    .execute(pool)
                    .await?;
            }
            DatabasePool::Postgres(pool) => {
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(key)
                    .bind(value)
                    .execute(pool)
                    .await?;
            }
        }
    }
    Ok(())
}

async fn option_exists(pool: &DatabasePool, prefix: &str, key: &str) -> Result<bool, sqlx::Error> {
    let sql = match pool {
        DatabasePool::Postgres(_) => {
            format!("SELECT COUNT(*) FROM {prefix}options WHERE option_name = $1")
        }
        _ => format!("SELECT COUNT(*) FROM {prefix}options WHERE option_name = ?"),
    };
    match pool {
        DatabasePool::Sqlite(pool) => Ok(sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
            .bind(key)
            .fetch_one(pool)
            .await?
            > 0),
        DatabasePool::MySql(pool) => Ok(sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
            .bind(key)
            .fetch_one(pool)
            .await?
            > 0),
        DatabasePool::Postgres(pool) => Ok(sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(sql))
            .bind(key)
            .fetch_one(pool)
            .await?
            > 0),
    }
}

async fn initial_score(pool: &DatabasePool, prefix: &str) -> Result<i64, sqlx::Error> {
    let sql = format!(
        "SELECT option_value FROM {prefix}options WHERE option_name = 'user_initial_score'"
    );
    let value = match pool {
        DatabasePool::Sqlite(pool) => {
            sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(sql))
                .fetch_optional(pool)
                .await?
        }
        DatabasePool::MySql(pool) => {
            sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(sql))
                .fetch_optional(pool)
                .await?
        }
        DatabasePool::Postgres(pool) => {
            sqlx::query_scalar::<_, String>(sqlx::AssertSqlSafe(sql))
                .fetch_optional(pool)
                .await?
        }
    };
    Ok(value.and_then(|value| value.parse().ok()).unwrap_or(1000))
}

async fn insert_admin(
    pool: &DatabasePool,
    prefix: &str,
    admin: &Admin,
    score: i64,
) -> Result<(), sqlx::Error> {
    let sql = match pool {
        DatabasePool::Postgres(_) => format!(
            "INSERT INTO {prefix}users (email, nickname, score, avatar, password, ip, is_dark_mode, permission, last_sign_at, register_at, verified, verification_token) VALUES ($1, $2, $3, 0, $4, '127.0.0.1', FALSE, 2, TIMESTAMP '1970-01-02 00:00:00', CURRENT_TIMESTAMP, TRUE, '')"
        ),
        DatabasePool::MySql(_) => format!(
            "INSERT INTO {prefix}users (email, nickname, score, avatar, password, ip, is_dark_mode, permission, last_sign_at, register_at, verified, verification_token) VALUES (?, ?, ?, 0, ?, '127.0.0.1', FALSE, 2, '1970-01-02 00:00:00', CURRENT_TIMESTAMP, TRUE, '')"
        ),
        DatabasePool::Sqlite(_) => format!(
            "INSERT INTO {prefix}users (email, nickname, score, avatar, password, ip, is_dark_mode, permission, last_sign_at, register_at, verified, verification_token) VALUES (?, ?, ?, 0, ?, '127.0.0.1', FALSE, 2, '1970-01-01 00:00:00', CURRENT_TIMESTAMP, TRUE, '')"
        ),
    };
    match pool {
        DatabasePool::Sqlite(pool) => {
            sqlx::query(sqlx::AssertSqlSafe(sql))
                .bind(&admin.email)
                .bind(&admin.nickname)
                .bind(score)
                .bind(&admin.password_hash)
                .execute(pool)
                .await?;
        }
        DatabasePool::MySql(pool) => {
            sqlx::query(sqlx::AssertSqlSafe(sql))
                .bind(&admin.email)
                .bind(&admin.nickname)
                .bind(score)
                .bind(&admin.password_hash)
                .execute(pool)
                .await?;
        }
        DatabasePool::Postgres(pool) => {
            sqlx::query(sqlx::AssertSqlSafe(sql))
                .bind(&admin.email)
                .bind(&admin.nickname)
                .bind(score)
                .bind(&admin.password_hash)
                .execute(pool)
                .await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::verify_legacy_password;
    use sqlx::Row;

    #[tokio::test]
    async fn install_connection_creates_a_missing_sqlite_file() {
        let directory =
            std::env::temp_dir().join(format!("blessing-install-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&directory).unwrap();
        let database_file = directory.join("site.sqlite");
        let config = crate::config::DatabaseConfig {
            connection: crate::config::DatabaseConnection::Sqlite(
                sqlx::sqlite::SqliteConnectOptions::new()
                    .filename(&database_file)
                    .create_if_missing(false),
            ),
            table_prefix: String::new(),
        };
        let pool = DatabasePool::connect_for_install(&config).await.unwrap();
        pool.ping().await.unwrap();
        match &pool {
            DatabasePool::Sqlite(pool) => pool.close().await,
            DatabasePool::MySql(pool) => pool.close().await,
            DatabasePool::Postgres(pool) => pool.close().await,
        }
        drop(pool);
        assert!(database_file.exists());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn generated_rsa_pem_is_accepted_by_passport_token_codec() {
        let mut rng = OsRng;
        let private = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let private_pem = private.to_pkcs8_pem(LineEnding::LF).unwrap();
        let public_pem = private
            .to_public_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap();
        assert!(EncodingKey::from_rsa_pem(private_pem.as_bytes()).is_ok());
        assert!(DecodingKey::from_rsa_pem(public_pem.as_bytes()).is_ok());
    }
    #[tokio::test]
    async fn installs_legacy_tables_defaults_and_super_admin() {
        let pool = DatabasePool::Sqlite(
            SqlitePoolOptions::new()
                .connect("sqlite::memory:")
                .await
                .unwrap(),
        );
        ensure_database_empty(&pool, "bs_").await.unwrap();
        initialize_schema(&pool, "bs_").await.unwrap();
        seed_options(&pool, "bs_", "Test Skin", "https://skin.example")
            .await
            .unwrap();
        let password_hash = hash_legacy_password("correct horse", "BCRYPT", "").unwrap();
        let admin = Admin {
            email: "admin@example.test".to_owned(),
            nickname: "Admin".to_owned(),
            password_hash,
            site_name: "Test Skin".to_owned(),
        };
        insert_admin(&pool, "bs_", &admin, 1000).await.unwrap();
        let sqlite = match &pool {
            DatabasePool::Sqlite(pool) => pool,
            _ => unreachable!(),
        };
        let row = sqlx::query(
            "SELECT email, nickname, score, permission, verified, password FROM bs_users",
        )
        .fetch_one(sqlite)
        .await
        .unwrap();
        assert_eq!(row.get::<String, _>("email"), "admin@example.test");
        assert_eq!(row.get::<i64, _>("score"), 1000);
        assert_eq!(row.get::<i64, _>("permission"), 2);
        assert!(row.get::<bool, _>("verified"));
        assert!(verify_legacy_password(
            "correct horse",
            &row.get::<String, _>("password"),
            "BCRYPT",
            ""
        ));
        assert_eq!(
            sqlx::query_scalar::<_, String>(
                "SELECT option_value FROM bs_options WHERE option_name = 'site_url'"
            )
            .fetch_one(sqlite)
            .await
            .unwrap(),
            "https://skin.example"
        );
        assert!(table_exists(&pool, "bs_oauth_auth_codes").await.unwrap());
        assert!(table_exists(&pool, "bs_notifications").await.unwrap());
        let copyright = sqlx::query_scalar::<_, String>(
            "SELECT option_value FROM bs_options WHERE option_name = 'copyright_text'",
        )
        .fetch_one(sqlite)
        .await
        .unwrap();
        assert!(!copyright.contains("{year}"));
    }

    #[tokio::test]
    async fn refuses_to_install_over_existing_users() {
        let sqlite = SqlitePoolOptions::new()
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query("CREATE TABLE users (uid INTEGER PRIMARY KEY)")
            .execute(&sqlite)
            .await
            .unwrap();
        sqlx::query("INSERT INTO users (uid) VALUES (1)")
            .execute(&sqlite)
            .await
            .unwrap();

        let pool = DatabasePool::Sqlite(sqlite);
        assert!(matches!(
            ensure_database_empty(&pool, "").await,
            Err(InstallError::DatabaseNotEmpty)
        ));
    }

    #[tokio::test]
    async fn refuses_to_install_when_a_different_table_prefix_is_present() {
        let sqlite = SqlitePoolOptions::new()
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query("CREATE TABLE legacy_users (uid INTEGER PRIMARY KEY)")
            .execute(&sqlite)
            .await
            .unwrap();
        let pool = DatabasePool::Sqlite(sqlite);
        assert!(matches!(
            ensure_database_empty(&pool, "").await,
            Err(InstallError::DatabaseNotEmpty)
        ));
    }
}
